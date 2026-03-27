//! Session issuance, validation, visibility, and revocation for OSMAP.
//!
//! This module treats browser sessions as first-class security state. Tokens are
//! opaque, high-entropy values; the store keeps only a hash-derived session
//! identifier and bounded metadata under the configured session directory.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use getrandom::getrandom;
use sha2::{Digest, Sha256};

use crate::auth::{AuthenticationContext, RequiredSecondFactor};
use crate::logging::{EventCategory, LogEvent};
use crate::totp::TimeProvider;

/// Conservative token size for opaque browser sessions.
pub const SESSION_TOKEN_BYTES: usize = 32;

/// Exact hex length for the current opaque session token format.
pub const SESSION_TOKEN_HEX_LEN: usize = SESSION_TOKEN_BYTES * 2;

/// Conservative maximum length for presented session tokens.
pub const MAX_SESSION_TOKEN_LEN: usize = 128;

/// Fixed hex length for the SHA-256-derived persisted session identifier.
pub const SESSION_ID_HEX_LEN: usize = 64;

/// Fixed hex length for the persisted CSRF token format.
pub const CSRF_TOKEN_HEX_LEN: usize = 64;

/// Describes the persisted session metadata visible to operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: String,
    pub csrf_token: String,
    pub canonical_username: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub last_seen_at: u64,
    pub revoked_at: Option<u64>,
    pub remote_addr: String,
    pub user_agent: String,
    pub factor: RequiredSecondFactor,
}

/// Holds the opaque browser token without exposing it in debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken {
    value: String,
}

impl SessionToken {
    /// Creates a session token from raw text after bounded validation.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionError> {
        let value = value.into();

        if value.is_empty() {
            return Err(SessionError::InvalidToken {
                reason: "session token must not be empty".to_string(),
            });
        }

        if value.len() > MAX_SESSION_TOKEN_LEN {
            return Err(SessionError::InvalidToken {
                reason: "session token exceeded maximum length".to_string(),
            });
        }

        if value.len() != SESSION_TOKEN_HEX_LEN {
            return Err(SessionError::InvalidToken {
                reason: format!(
                    "session token must be exactly {SESSION_TOKEN_HEX_LEN} hex characters"
                ),
            });
        }

        if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(SessionError::InvalidToken {
                reason: "session token must be hex-encoded".to_string(),
            });
        }

        Ok(Self { value })
    }

    /// Returns the token value for transport to the browser.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken")
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Describes the outcome of issuing a new browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    pub token: SessionToken,
    pub record: SessionRecord,
    pub audit_event: LogEvent,
}

/// Describes the outcome of validating a presented session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSession {
    pub record: SessionRecord,
    pub audit_event: LogEvent,
}

/// Describes the outcome of revoking a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedSession {
    pub record: SessionRecord,
    pub audit_event: LogEvent,
}

/// Errors raised by session issuance or store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    InvalidToken {
        reason: String,
    },
    RandomSourceFailure {
        reason: String,
    },
    StoreFailure {
        reason: String,
    },
    SessionNotFound {
        session_id: String,
    },
}

/// Provides high-entropy bytes for session token generation.
pub trait RandomSource {
    fn fill_bytes(&self, buffer: &mut [u8]) -> Result<(), SessionError>;
}

/// Uses the operating system random source for session tokens.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandomSource;

impl RandomSource for SystemRandomSource {
    fn fill_bytes(&self, buffer: &mut [u8]) -> Result<(), SessionError> {
        getrandom(buffer).map_err(|error| SessionError::RandomSourceFailure {
            reason: format!("failed to read secure randomness: {error}"),
        })
    }
}

/// Persists and retrieves session records.
pub trait SessionStore {
    fn save(&self, record: &SessionRecord) -> Result<(), SessionError>;
    fn load(&self, session_id: &str) -> Result<Option<SessionRecord>, SessionError>;
    fn list_for_user(&self, canonical_username: &str) -> Result<Vec<SessionRecord>, SessionError>;
}

/// File-backed session store rooted at the configured session directory.
pub struct FileSessionStore {
    session_dir: PathBuf,
}

impl FileSessionStore {
    /// Creates a file-backed session store rooted at the supplied directory.
    pub fn new(session_dir: impl Into<PathBuf>) -> Self {
        Self {
            session_dir: session_dir.into(),
        }
    }

    /// Returns the filesystem path for a specific session id.
    pub fn session_path(&self, session_id: &str) -> PathBuf {
        self.session_dir.join(format!("{session_id}.session"))
    }
}

impl SessionStore for FileSessionStore {
    fn save(&self, record: &SessionRecord) -> Result<(), SessionError> {
        fs::create_dir_all(&self.session_dir).map_err(|error| SessionError::StoreFailure {
            reason: format!("failed to create session directory {:?}: {error}", self.session_dir),
        })?;

        let path = self.session_path(&record.session_id);
        let tmp_path = self.session_dir.join(format!("{}.tmp", record.session_id));
        let content = serialize_session_record(record);

        let mut file = fs::File::create(&tmp_path).map_err(|error| SessionError::StoreFailure {
            reason: format!("failed to create session temp file {:?}: {error}", tmp_path),
        })?;
        file.write_all(content.as_bytes())
            .map_err(|error| SessionError::StoreFailure {
                reason: format!("failed to write session temp file {:?}: {error}", tmp_path),
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(
                |error| SessionError::StoreFailure {
                    reason: format!(
                        "failed to set session temp permissions {:?}: {error}",
                        tmp_path
                    ),
                },
            )?;
        }

        fs::rename(&tmp_path, &path).map_err(|error| SessionError::StoreFailure {
            reason: format!("failed to finalize session file {:?}: {error}", path),
        })?;

        Ok(())
    }

    fn load(&self, session_id: &str) -> Result<Option<SessionRecord>, SessionError> {
        let path = self.session_path(session_id);

        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path).map_err(|error| SessionError::StoreFailure {
            reason: format!("failed to read session file {:?}: {error}", path),
        })?;

        parse_session_record(&content)
    }

    fn list_for_user(&self, canonical_username: &str) -> Result<Vec<SessionRecord>, SessionError> {
        let mut records = Vec::new();

        if !self.session_dir.exists() {
            return Ok(records);
        }

        for entry in fs::read_dir(&self.session_dir).map_err(|error| SessionError::StoreFailure {
            reason: format!(
                "failed to read session directory {:?}: {error}",
                self.session_dir
            ),
        })? {
            let entry = entry.map_err(|error| SessionError::StoreFailure {
                reason: format!("failed to read session directory entry: {error}"),
            })?;

            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("session") {
                continue;
            }

            let content =
                fs::read_to_string(entry.path()).map_err(|error| SessionError::StoreFailure {
                    reason: format!("failed to read session record {:?}: {error}", entry.path()),
                })?;
            let record = parse_session_record(&content)?;
            if let Some(record) = record {
                if record.canonical_username == canonical_username {
                    records.push(record);
                }
            }
        }

        records.sort_by(|left, right| right.issued_at.cmp(&left.issued_at));
        Ok(records)
    }
}

/// Issues, validates, and revokes browser sessions.
pub struct SessionService<S, T, R> {
    session_store: S,
    time_provider: T,
    random_source: R,
    lifetime_seconds: u64,
}

impl<S, T, R> SessionService<S, T, R> {
    /// Creates a new session service.
    pub fn new(session_store: S, time_provider: T, random_source: R, lifetime_seconds: u64) -> Self {
        Self {
            session_store,
            time_provider,
            random_source,
            lifetime_seconds,
        }
    }
}

impl<S, T, R> SessionService<S, T, R>
where
    S: SessionStore,
    T: TimeProvider,
    R: RandomSource,
{
    /// Issues a new session after successful multi-factor authentication.
    pub fn issue(
        &self,
        context: &AuthenticationContext,
        canonical_username: &str,
        factor: RequiredSecondFactor,
    ) -> Result<IssuedSession, SessionError> {
        let issued_at = self.time_provider.unix_timestamp();
        let expires_at = issued_at.saturating_add(self.lifetime_seconds);
        let token = generate_session_token(&self.random_source)?;
        let session_id = session_id_from_token(token.as_str());
        let csrf_token = csrf_token_from_session_token(token.as_str());

        let record = SessionRecord {
            session_id: session_id.clone(),
            csrf_token,
            canonical_username: canonical_username.to_string(),
            issued_at,
            expires_at,
            last_seen_at: issued_at,
            revoked_at: None,
            remote_addr: context.remote_addr.clone(),
            user_agent: context.user_agent.clone(),
            factor,
        };

        self.session_store.save(&record)?;

        Ok(IssuedSession {
            token,
            record: record.clone(),
            audit_event: LogEvent::new(
                crate::config::LogLevel::Info,
                EventCategory::Session,
                "session_issued",
                "browser session issued",
            )
            .with_field("session_id", record.session_id.clone())
            .with_field("canonical_username", record.canonical_username.clone())
            .with_field("issued_at", record.issued_at.to_string())
            .with_field("expires_at", record.expires_at.to_string())
            .with_field("factor", factor.as_str())
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
        })
    }

    /// Validates a presented session token and refreshes last-seen metadata.
    pub fn validate(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
    ) -> Result<ValidatedSession, SessionError> {
        let session_id = session_id_from_token(token.as_str());
        let now = self.time_provider.unix_timestamp();
        let Some(mut record) = self.session_store.load(&session_id)? else {
            return Err(SessionError::SessionNotFound { session_id });
        };

        if record.revoked_at.is_some() {
            return Err(SessionError::StoreFailure {
                reason: "session is revoked".to_string(),
            });
        }

        if now > record.expires_at {
            return Err(SessionError::StoreFailure {
                reason: "session is expired".to_string(),
            });
        }

        record.last_seen_at = now;
        self.session_store.save(&record)?;

        Ok(ValidatedSession {
            audit_event: LogEvent::new(
                crate::config::LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            )
            .with_field("session_id", record.session_id.clone())
            .with_field("canonical_username", record.canonical_username.clone())
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone())
            .with_field("expires_at", record.expires_at.to_string()),
            record,
        })
    }

    /// Revokes a session by the presented browser token.
    pub fn revoke_by_token(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
    ) -> Result<RevokedSession, SessionError> {
        self.revoke_by_session_id(context, &session_id_from_token(token.as_str()))
    }

    /// Revokes a session by persisted id and records the revocation time.
    pub fn revoke_by_session_id(
        &self,
        context: &AuthenticationContext,
        session_id: &str,
    ) -> Result<RevokedSession, SessionError> {
        let Some(mut record) = self.session_store.load(session_id)? else {
            return Err(SessionError::SessionNotFound {
                session_id: session_id.to_string(),
            });
        };

        let now = self.time_provider.unix_timestamp();
        record.revoked_at = Some(now);
        self.session_store.save(&record)?;

        Ok(RevokedSession {
            audit_event: LogEvent::new(
                crate::config::LogLevel::Info,
                EventCategory::Session,
                "session_revoked",
                "browser session revoked",
            )
            .with_field("session_id", record.session_id.clone())
            .with_field("canonical_username", record.canonical_username.clone())
            .with_field("revoked_at", now.to_string())
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
            record,
        })
    }

    /// Revokes a session by persisted id.
    ///
    /// This compatibility wrapper keeps existing call sites small while the
    /// codebase grows into more explicit browser and operator session paths.
    pub fn revoke(
        &self,
        context: &AuthenticationContext,
        session_id: &str,
    ) -> Result<RevokedSession, SessionError> {
        self.revoke_by_session_id(context, session_id)
    }

    /// Returns the operator-visible session list for a canonical user.
    pub fn list_for_user(&self, canonical_username: &str) -> Result<Vec<SessionRecord>, SessionError> {
        self.session_store.list_for_user(canonical_username)
    }
}

/// Generates a new high-entropy session token.
fn generate_session_token<R>(random_source: &R) -> Result<SessionToken, SessionError>
where
    R: RandomSource,
{
    let mut bytes = [0_u8; SESSION_TOKEN_BYTES];
    random_source.fill_bytes(&mut bytes)?;
    SessionToken::new(hex_encode(&bytes))
}

/// Derives the persisted session id from an opaque token.
fn session_id_from_token(token: &str) -> String {
    derive_session_hex("session-id", token)
}

/// Derives a stable CSRF token from the issued bearer token.
fn csrf_token_from_session_token(token: &str) -> String {
    derive_session_hex("csrf", token)
}

/// Derives one stable SHA-256-based hex value from a session token.
///
/// The browser token is already high-entropy and opaque. This helper keeps the
/// persisted identifiers deterministic without storing the raw bearer token on
/// disk, and it domain-separates session and CSRF derivations so the values are
/// not interchangeable.
fn derive_session_hex(label: &str, token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(label.as_bytes());
    digest.update(b":");
    digest.update(token.as_bytes());
    hex_encode(&digest.finalize())
}

/// Serializes a session record into a small line-oriented format.
fn serialize_session_record(record: &SessionRecord) -> String {
    let revoked_at = record
        .revoked_at
        .map(|value| value.to_string())
        .unwrap_or_default();

    format!(
        "session_id={}\ncsrf_token={}\ncanonical_username={}\nissued_at={}\nexpires_at={}\nlast_seen_at={}\nrevoked_at={}\nremote_addr={}\nuser_agent={}\nfactor={}\n",
        record.session_id,
        record.csrf_token,
        record.canonical_username,
        record.issued_at,
        record.expires_at,
        record.last_seen_at,
        revoked_at,
        record.remote_addr,
        record.user_agent,
        record.factor.as_str(),
    )
}

/// Parses a serialized session record.
fn parse_session_record(content: &str) -> Result<Option<SessionRecord>, SessionError> {
    let mut session_id = None;
    let mut csrf_token = None;
    let mut canonical_username = None;
    let mut issued_at = None;
    let mut expires_at = None;
    let mut last_seen_at = None;
    let mut revoked_at = None;
    let mut remote_addr = None;
    let mut user_agent = None;
    let mut factor = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(SessionError::StoreFailure {
                reason: format!("invalid session record line {line:?}"),
            });
        };

        match key {
            "session_id" => {
                if value.len() != SESSION_ID_HEX_LEN || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    return Err(SessionError::StoreFailure {
                        reason: "invalid session_id field in session record".to_string(),
                    });
                }
                session_id = Some(value.to_string());
            }
            "csrf_token" => {
                if value.len() != CSRF_TOKEN_HEX_LEN
                    || !value.chars().all(|ch| ch.is_ascii_hexdigit())
                {
                    return Err(SessionError::StoreFailure {
                        reason: "invalid csrf_token field in session record".to_string(),
                    });
                }
                csrf_token = Some(value.to_string());
            }
            "canonical_username" => canonical_username = Some(value.to_string()),
            "issued_at" => issued_at = Some(parse_u64_field("issued_at", value)?),
            "expires_at" => expires_at = Some(parse_u64_field("expires_at", value)?),
            "last_seen_at" => last_seen_at = Some(parse_u64_field("last_seen_at", value)?),
            "revoked_at" => {
                revoked_at = if value.is_empty() {
                    Some(None)
                } else {
                    Some(Some(parse_u64_field("revoked_at", value)?))
                };
            }
            "remote_addr" => remote_addr = Some(value.to_string()),
            "user_agent" => user_agent = Some(value.to_string()),
            "factor" => factor = Some(parse_factor(value)?),
            _ => {
                return Err(SessionError::StoreFailure {
                    reason: format!("unknown session record field {key:?}"),
                })
            }
        }
    }

    let Some(session_id) = session_id else {
        return Ok(None);
    };

    Ok(Some(SessionRecord {
        session_id,
        csrf_token: required_field("csrf_token", csrf_token)?,
        canonical_username: required_field("canonical_username", canonical_username)?,
        issued_at: required_field("issued_at", issued_at)?,
        expires_at: required_field("expires_at", expires_at)?,
        last_seen_at: required_field("last_seen_at", last_seen_at)?,
        revoked_at: revoked_at.unwrap_or(None),
        remote_addr: required_field("remote_addr", remote_addr)?,
        user_agent: required_field("user_agent", user_agent)?,
        factor: required_field("factor", factor)?,
    }))
}

/// Parses a required unsigned integer field from session metadata.
fn parse_u64_field(field: &'static str, value: &str) -> Result<u64, SessionError> {
    value.parse::<u64>().map_err(|error| SessionError::StoreFailure {
        reason: format!("failed parsing {field}: {error}"),
    })
}

/// Parses the factor string stored in session metadata.
fn parse_factor(value: &str) -> Result<RequiredSecondFactor, SessionError> {
    match value {
        "totp" => Ok(RequiredSecondFactor::Totp),
        _ => Err(SessionError::StoreFailure {
            reason: format!("unknown session factor {value:?}"),
        }),
    }
}

/// Returns a required parsed field or raises a structured store error.
fn required_field<T>(field: &'static str, value: Option<T>) -> Result<T, SessionError> {
    value.ok_or_else(|| SessionError::StoreFailure {
        reason: format!("missing required session field {field}"),
    })
}

/// Encodes bytes as lower-case hex.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthenticationDecision, AuthenticationPolicy, AuthenticationService, PrimaryAuthBackendError,
        PrimaryAuthVerdict, PrimaryCredentialBackend, RequiredSecondFactor, SecondFactorService,
    };
    use crate::totp::{FileTotpSecretStore, TotpPolicy, TotpVerifier};
    use crate::totp::TimeProvider;
    use std::cell::Cell;

    #[derive(Debug)]
    struct FixedTimeProvider {
        unix_timestamp: Cell<u64>,
    }

    impl FixedTimeProvider {
        fn new(unix_timestamp: u64) -> Self {
            Self {
                unix_timestamp: Cell::new(unix_timestamp),
            }
        }
    }

    impl TimeProvider for FixedTimeProvider {
        fn unix_timestamp(&self) -> u64 {
            self.unix_timestamp.get()
        }
    }

    #[derive(Debug, Clone)]
    struct StaticRandomSource {
        bytes: Vec<u8>,
    }

    impl RandomSource for StaticRandomSource {
        fn fill_bytes(&self, buffer: &mut [u8]) -> Result<(), SessionError> {
            buffer.copy_from_slice(&self.bytes[..buffer.len()]);
            Ok(())
        }
    }

    struct AcceptingPrimaryBackend;

    impl PrimaryCredentialBackend for AcceptingPrimaryBackend {
        fn verify_primary(
            &self,
            _context: &AuthenticationContext,
            username: &str,
            password: &str,
        ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
            if username == "alice@example.com" && password == "correct horse battery staple" {
                return Ok(PrimaryAuthVerdict::Accept {
                    canonical_username: "alice@example.com".to_string(),
                });
            }

            Ok(PrimaryAuthVerdict::Reject)
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            crate::auth::AuthenticationPolicy::default(),
            "req-session",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            FixedTimeProvider::new(1).unix_timestamp()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn token_debug_output_is_redacted() {
        let token = SessionToken::new("a".repeat(SESSION_TOKEN_HEX_LEN))
            .expect("token should be valid");

        let debug_output = format!("{token:?}");

        assert!(debug_output.contains("<redacted>"));
        assert!(!debug_output.contains(&"a".repeat(SESSION_TOKEN_HEX_LEN)));
    }

    #[test]
    fn issue_session_persists_record_and_returns_token() {
        let session_dir = temp_dir("osmap-session-issue");
        let store = FileSessionStore::new(&session_dir);
        let service = SessionService::new(
            store,
            FixedTimeProvider::new(100),
            StaticRandomSource {
                bytes: vec![0x11; SESSION_TOKEN_BYTES],
            },
            3600,
        );

        let issued = service
            .issue(&test_context(), "alice@example.com", RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");

        assert_eq!(issued.record.canonical_username, "alice@example.com");
        assert_eq!(issued.record.issued_at, 100);
        assert_eq!(issued.record.expires_at, 3700);
        assert_eq!(issued.record.factor, RequiredSecondFactor::Totp);
        assert_eq!(issued.record.csrf_token.len(), CSRF_TOKEN_HEX_LEN);
        assert!(session_dir.join(format!("{}.session", issued.record.session_id)).exists());
    }

    #[test]
    fn validate_session_updates_last_seen() {
        let session_dir = temp_dir("osmap-session-validate");
        let store = FileSessionStore::new(&session_dir);
        let time = FixedTimeProvider::new(100);
        let service = SessionService::new(
            store,
            time,
            StaticRandomSource {
                bytes: vec![0x22; SESSION_TOKEN_BYTES],
            },
            3600,
        );

        let issued = service
            .issue(&test_context(), "alice@example.com", RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");
        service.time_provider.unix_timestamp.set(200);

        let validated = service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        assert_eq!(validated.record.last_seen_at, 200);
    }

    #[test]
    fn revoke_session_marks_record_as_revoked() {
        let session_dir = temp_dir("osmap-session-revoke");
        let store = FileSessionStore::new(&session_dir);
        let time = FixedTimeProvider::new(100);
        let service = SessionService::new(
            store,
            time,
            StaticRandomSource {
                bytes: vec![0x33; SESSION_TOKEN_BYTES],
            },
            3600,
        );

        let issued = service
            .issue(&test_context(), "alice@example.com", RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");
        service.time_provider.unix_timestamp.set(250);

        let revoked = service
            .revoke(&test_context(), &issued.record.session_id)
            .expect("session revocation should succeed");

        assert_eq!(revoked.record.revoked_at, Some(250));
    }

    #[test]
    fn revoke_by_token_supports_logout_style_revocation() {
        let session_dir = temp_dir("osmap-session-logout");
        let store = FileSessionStore::new(&session_dir);
        let time = FixedTimeProvider::new(100);
        let service = SessionService::new(
            store,
            time,
            StaticRandomSource {
                bytes: vec![0x66; SESSION_TOKEN_BYTES],
            },
            3600,
        );

        let issued = service
            .issue(&test_context(), "alice@example.com", RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");
        service.time_provider.unix_timestamp.set(300);

        let revoked = service
            .revoke_by_token(&test_context(), &issued.token)
            .expect("logout revocation should succeed");

        assert_eq!(revoked.record.revoked_at, Some(300));
        assert_eq!(revoked.record.session_id, issued.record.session_id);
    }

    #[test]
    fn list_sessions_returns_records_for_the_user() {
        let session_dir = temp_dir("osmap-session-list");
        let store = FileSessionStore::new(&session_dir);
        let service = SessionService::new(
            store,
            FixedTimeProvider::new(100),
            StaticRandomSource {
                bytes: vec![0x44; SESSION_TOKEN_BYTES],
            },
            3600,
        );

        service
            .issue(&test_context(), "alice@example.com", RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");

        let records = service
            .list_for_user("alice@example.com")
            .expect("listing should succeed");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].canonical_username, "alice@example.com");
    }

    #[test]
    fn validate_session_rejects_expired_records() {
        let session_dir = temp_dir("osmap-session-expired");
        let store = FileSessionStore::new(&session_dir);
        let time = FixedTimeProvider::new(100);
        let service = SessionService::new(
            store,
            time,
            StaticRandomSource {
                bytes: vec![0x55; SESSION_TOKEN_BYTES],
            },
            10,
        );

        let issued = service
            .issue(&test_context(), "alice@example.com", RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");
        service.time_provider.unix_timestamp.set(200);

        let error = service
            .validate(&test_context(), &issued.token)
            .expect_err("expired sessions must fail");

        assert_eq!(
            error,
            SessionError::StoreFailure {
                reason: "session is expired".to_string(),
            }
        );
    }

    #[test]
    fn parses_serialized_session_records() {
        let record = SessionRecord {
            session_id:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            csrf_token:
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
            canonical_username: "alice@example.com".to_string(),
            issued_at: 1,
            expires_at: 2,
            last_seen_at: 3,
            revoked_at: Some(4),
            remote_addr: "127.0.0.1".to_string(),
            user_agent: "Firefox/Test".to_string(),
            factor: RequiredSecondFactor::Totp,
        };

        let parsed = parse_session_record(&serialize_session_record(&record))
            .expect("record should parse")
            .expect("record should exist");

        assert_eq!(parsed, record);
    }

    #[test]
    fn rejects_tokens_with_unexpected_length() {
        let error = SessionToken::new("deadbeef").expect_err("short tokens must fail");

        assert_eq!(
            error,
            SessionError::InvalidToken {
                reason: format!(
                    "session token must be exactly {SESSION_TOKEN_HEX_LEN} hex characters"
                ),
            }
        );
    }

    #[test]
    fn full_auth_to_session_flow_uses_real_totp_and_session_services() {
        let secret_dir = temp_dir("osmap-session-auth-secret");
        let session_dir = temp_dir("osmap-session-auth-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(
            &secret_path,
            "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n",
        )
        .expect("secret file should be written");

        let auth_service = AuthenticationService::new(
            AuthenticationPolicy::default(),
            AcceptingPrimaryBackend,
        );
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );

        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );

        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0x77; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(&test_context(), &canonical_username, RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");

        assert_eq!(issued.record.canonical_username, canonical_username);
        assert_eq!(issued.record.csrf_token.len(), CSRF_TOKEN_HEX_LEN);
        assert_eq!(issued.record.factor, RequiredSecondFactor::Totp);
        assert_eq!(issued.record.issued_at, 59);
        assert_eq!(issued.record.expires_at, 3659);
    }
}
