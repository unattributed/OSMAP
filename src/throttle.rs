//! Bounded login-attempt throttling for the browser authentication path.
//!
//! This module adds a small file-backed abuse-resistance layer without
//! introducing a separate service or framework. The goal is to make repeated
//! login failures more expensive while keeping the implementation explicit,
//! reviewable, and compatible with the existing state boundary.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::auth::{AuthenticationContext, DEFAULT_REMOTE_ADDR_MAX_LEN, DEFAULT_USERNAME_MAX_LEN};
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::totp::TimeProvider;

/// Conservative default threshold for consecutive failed login attempts within
/// one throttle window.
pub const DEFAULT_LOGIN_THROTTLE_MAX_FAILURES: u64 = 5;

/// Conservative default threshold for remote-address-only failures within one
/// throttle window.
pub const DEFAULT_LOGIN_THROTTLE_REMOTE_MAX_FAILURES: u64 = 12;

/// Conservative default window over which failed login attempts are counted.
pub const DEFAULT_LOGIN_THROTTLE_WINDOW_SECONDS: u64 = 300;

/// Conservative default lockout period once the failure threshold is exceeded.
pub const DEFAULT_LOGIN_THROTTLE_LOCKOUT_SECONDS: u64 = 900;

/// Public reason exposed by the browser layer when login throttling is active.
pub const TOO_MANY_ATTEMPTS_PUBLIC_REASON: &str = "too_many_attempts";

/// Policy controlling how the current login-throttle slice behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginThrottlePolicy {
    pub credential_max_failures: u64,
    pub remote_addr_max_failures: u64,
    pub failure_window_seconds: u64,
    pub lockout_seconds: u64,
}

impl Default for LoginThrottlePolicy {
    fn default() -> Self {
        Self {
            credential_max_failures: DEFAULT_LOGIN_THROTTLE_MAX_FAILURES,
            remote_addr_max_failures: DEFAULT_LOGIN_THROTTLE_REMOTE_MAX_FAILURES,
            failure_window_seconds: DEFAULT_LOGIN_THROTTLE_WINDOW_SECONDS,
            lockout_seconds: DEFAULT_LOGIN_THROTTLE_LOCKOUT_SECONDS,
        }
    }
}

/// Distinguishes the current throttle buckets used on the browser login path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginThrottleBucketKind {
    CredentialAndRemoteAddr,
    RemoteAddrOnly,
}

impl LoginThrottleBucketKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::CredentialAndRemoteAddr => "credential_and_remote_addr",
            Self::RemoteAddrOnly => "remote_addr_only",
        }
    }

    fn max_failures(self, policy: LoginThrottlePolicy) -> u64 {
        match self {
            Self::CredentialAndRemoteAddr => policy.credential_max_failures,
            Self::RemoteAddrOnly => policy.remote_addr_max_failures,
        }
    }
}

/// Errors raised while reading or writing throttle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginThrottleError {
    StoreFailure { reason: String },
}

/// One persisted throttle bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginThrottleRecord {
    pub failure_count: u64,
    pub window_started_at: u64,
    pub last_failure_at: u64,
    pub locked_until: Option<u64>,
}

impl LoginThrottleRecord {
    fn empty() -> Self {
        Self {
            failure_count: 0,
            window_started_at: 0,
            last_failure_at: 0,
            locked_until: None,
        }
    }
}

/// The key used for one throttle bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginThrottleKey {
    pub key_id: String,
    pub bucket_kind: LoginThrottleBucketKind,
    pub submitted_username: String,
    pub remote_addr: String,
}

impl LoginThrottleKey {
    /// Builds a stable bucket key from the presented username and remote
    /// address.
    pub fn new(submitted_username: &str, remote_addr: &str) -> Self {
        Self::for_credential_and_remote_addr(submitted_username, remote_addr)
    }

    /// Builds the stable credential-plus-remote bucket key.
    pub fn for_credential_and_remote_addr(submitted_username: &str, remote_addr: &str) -> Self {
        let submitted_username =
            normalize_component(submitted_username, DEFAULT_USERNAME_MAX_LEN, true);
        let remote_addr = normalize_component(remote_addr, DEFAULT_REMOTE_ADDR_MAX_LEN, false);
        let mut digest = Sha256::new();
        digest.update(b"osmap-login-throttle-v2");
        digest.update([0]);
        digest.update(
            LoginThrottleBucketKind::CredentialAndRemoteAddr
                .as_str()
                .as_bytes(),
        );
        digest.update([0]);
        digest.update(submitted_username.as_bytes());
        digest.update([0]);
        digest.update(remote_addr.as_bytes());

        Self {
            key_id: hex_lower(&digest.finalize()),
            bucket_kind: LoginThrottleBucketKind::CredentialAndRemoteAddr,
            submitted_username,
            remote_addr,
        }
    }

    /// Builds the stable remote-only bucket key.
    pub fn for_remote_addr(submitted_username: &str, remote_addr: &str) -> Self {
        let submitted_username =
            normalize_component(submitted_username, DEFAULT_USERNAME_MAX_LEN, true);
        let remote_addr = normalize_component(remote_addr, DEFAULT_REMOTE_ADDR_MAX_LEN, false);
        let mut digest = Sha256::new();
        digest.update(b"osmap-login-throttle-v2");
        digest.update([0]);
        digest.update(LoginThrottleBucketKind::RemoteAddrOnly.as_str().as_bytes());
        digest.update([0]);
        digest.update(remote_addr.as_bytes());

        Self {
            key_id: hex_lower(&digest.finalize()),
            bucket_kind: LoginThrottleBucketKind::RemoteAddrOnly,
            submitted_username,
            remote_addr,
        }
    }
}

/// Persists and retrieves throttle buckets.
pub trait LoginThrottleStore {
    fn load(&self, key_id: &str) -> Result<Option<LoginThrottleRecord>, LoginThrottleError>;
    fn save(&self, key_id: &str, record: &LoginThrottleRecord) -> Result<(), LoginThrottleError>;
    fn remove(&self, key_id: &str) -> Result<(), LoginThrottleError>;
}

/// File-backed throttle store rooted under the configured cache tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLoginThrottleStore {
    throttle_dir: PathBuf,
}

impl FileLoginThrottleStore {
    /// Creates a file-backed throttle store rooted at the supplied directory.
    pub fn new(throttle_dir: impl Into<PathBuf>) -> Self {
        Self {
            throttle_dir: throttle_dir.into(),
        }
    }

    fn record_path(&self, key_id: &str) -> PathBuf {
        self.throttle_dir.join(format!("{key_id}.throttle"))
    }
}

impl LoginThrottleStore for FileLoginThrottleStore {
    fn load(&self, key_id: &str) -> Result<Option<LoginThrottleRecord>, LoginThrottleError> {
        let path = self.record_path(key_id);

        if !path.exists() {
            return Ok(None);
        }

        let content =
            fs::read_to_string(&path).map_err(|error| LoginThrottleError::StoreFailure {
                reason: format!("failed to read login throttle record {:?}: {error}", path),
            })?;

        parse_throttle_record(&content)
    }

    fn save(&self, key_id: &str, record: &LoginThrottleRecord) -> Result<(), LoginThrottleError> {
        fs::create_dir_all(&self.throttle_dir).map_err(|error| {
            LoginThrottleError::StoreFailure {
                reason: format!(
                    "failed to create login throttle directory {:?}: {error}",
                    self.throttle_dir
                ),
            }
        })?;

        let path = self.record_path(key_id);
        let tmp_path = self.throttle_dir.join(format!("{key_id}.tmp"));
        let content = serialize_throttle_record(record);

        let mut file =
            fs::File::create(&tmp_path).map_err(|error| LoginThrottleError::StoreFailure {
                reason: format!(
                    "failed to create login throttle temp file {:?}: {error}",
                    tmp_path
                ),
            })?;
        file.write_all(content.as_bytes())
            .map_err(|error| LoginThrottleError::StoreFailure {
                reason: format!(
                    "failed to write login throttle temp file {:?}: {error}",
                    tmp_path
                ),
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|error| {
                LoginThrottleError::StoreFailure {
                    reason: format!(
                        "failed to set login throttle temp permissions {:?}: {error}",
                        tmp_path
                    ),
                }
            })?;
        }

        fs::rename(&tmp_path, &path).map_err(|error| LoginThrottleError::StoreFailure {
            reason: format!(
                "failed to finalize login throttle record {:?}: {error}",
                path
            ),
        })?;

        Ok(())
    }

    fn remove(&self, key_id: &str) -> Result<(), LoginThrottleError> {
        let path = self.record_path(key_id);

        if !path.exists() {
            return Ok(());
        }

        fs::remove_file(&path).map_err(|error| LoginThrottleError::StoreFailure {
            reason: format!("failed to remove login throttle record {:?}: {error}", path),
        })
    }
}

/// The result of checking whether a login attempt may proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginThrottleDecision {
    Allowed,
    Throttled { retry_after_seconds: u64 },
}

/// The result of one throttle check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginThrottleCheck {
    pub decision: LoginThrottleDecision,
    pub audit_events: Vec<LogEvent>,
}

/// The result of recording a failed login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginThrottleFailureRecord {
    pub lockout_engaged: bool,
    pub audit_events: Vec<LogEvent>,
}

/// A small throttle service over a store and time source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginThrottleService<S, T> {
    store: S,
    time_provider: T,
    policy: LoginThrottlePolicy,
}

impl<S, T> LoginThrottleService<S, T> {
    /// Builds a throttle service from the supplied store, time source, and
    /// policy.
    pub fn new(store: S, time_provider: T, policy: LoginThrottlePolicy) -> Self {
        Self {
            store,
            time_provider,
            policy,
        }
    }
}

impl<S, T> LoginThrottleService<S, T>
where
    S: LoginThrottleStore,
    T: TimeProvider,
{
    /// Checks whether the presented login attempt may proceed.
    pub fn check(
        &self,
        context: &AuthenticationContext,
        submitted_username: &str,
    ) -> Result<LoginThrottleCheck, LoginThrottleError> {
        let keys = [
            LoginThrottleKey::for_credential_and_remote_addr(
                submitted_username,
                &context.remote_addr,
            ),
            LoginThrottleKey::for_remote_addr(submitted_username, &context.remote_addr),
        ];
        let now = self.time_provider.unix_timestamp();
        let mut retry_after_seconds = None;
        let mut audit_events = Vec::new();

        for key in keys {
            let Some(record) = self.store.load(&key.key_id)? else {
                continue;
            };

            if let Some(locked_until) = record.locked_until.filter(|until| *until > now) {
                let current_retry_after = locked_until.saturating_sub(now);
                retry_after_seconds = Some(
                    retry_after_seconds
                        .map(|current: u64| current.max(current_retry_after))
                        .unwrap_or(current_retry_after),
                );
                audit_events.push(build_throttled_event(
                    context,
                    &key,
                    record.failure_count,
                    current_retry_after,
                ));
            }
        }

        if let Some(retry_after_seconds) = retry_after_seconds {
            Ok(LoginThrottleCheck {
                decision: LoginThrottleDecision::Throttled {
                    retry_after_seconds,
                },
                audit_events,
            })
        } else {
            Ok(LoginThrottleCheck {
                decision: LoginThrottleDecision::Allowed,
                audit_events,
            })
        }
    }

    /// Records one failed login attempt for the presented identity bucket.
    pub fn record_failure(
        &self,
        context: &AuthenticationContext,
        submitted_username: &str,
    ) -> Result<LoginThrottleFailureRecord, LoginThrottleError> {
        let keys = [
            LoginThrottleKey::for_credential_and_remote_addr(
                submitted_username,
                &context.remote_addr,
            ),
            LoginThrottleKey::for_remote_addr(submitted_username, &context.remote_addr),
        ];
        let now = self.time_provider.unix_timestamp();
        let mut lockout_engaged = false;
        let mut audit_events = Vec::new();

        for key in keys {
            let mut record = self
                .store
                .load(&key.key_id)?
                .unwrap_or_else(LoginThrottleRecord::empty);

            let lockout_expired = record.locked_until.is_some_and(|until| until <= now);
            let outside_window = record.failure_count == 0
                || now.saturating_sub(record.window_started_at)
                    >= self.policy.failure_window_seconds;

            if lockout_expired || outside_window {
                record.failure_count = 1;
                record.window_started_at = now;
                record.last_failure_at = now;
                record.locked_until = None;
            } else {
                record.failure_count = record.failure_count.saturating_add(1);
                record.last_failure_at = now;
            }

            if record.failure_count >= key.bucket_kind.max_failures(self.policy) {
                lockout_engaged = true;
                record.locked_until = Some(now.saturating_add(self.policy.lockout_seconds));
                audit_events.push(build_lockout_engaged_event(
                    context,
                    &key,
                    record.failure_count,
                    self.policy.lockout_seconds,
                ));
            }

            self.store.save(&key.key_id, &record)?;
        }

        Ok(LoginThrottleFailureRecord {
            lockout_engaged,
            audit_events,
        })
    }

    /// Clears the bucket for a successful login so the next browser entry starts
    /// from a clean state.
    pub fn clear_success(
        &self,
        context: &AuthenticationContext,
        submitted_username: &str,
    ) -> Result<Vec<LogEvent>, LoginThrottleError> {
        let keys = [
            LoginThrottleKey::for_credential_and_remote_addr(
                submitted_username,
                &context.remote_addr,
            ),
            LoginThrottleKey::for_remote_addr(submitted_username, &context.remote_addr),
        ];
        let mut audit_events = Vec::new();

        for key in keys {
            self.store.remove(&key.key_id)?;
            audit_events.push(build_cleared_event(context, &key));
        }

        Ok(audit_events)
    }
}

fn build_throttled_event(
    context: &AuthenticationContext,
    key: &LoginThrottleKey,
    failure_count: u64,
    retry_after_seconds: u64,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Auth,
        "login_throttled",
        "login attempt rejected by throttle policy",
    )
    .with_field("public_reason", TOO_MANY_ATTEMPTS_PUBLIC_REASON)
    .with_field("submitted_username", key.submitted_username.clone())
    .with_field("bucket_kind", key.bucket_kind.as_str())
    .with_field("remote_addr", key.remote_addr.clone())
    .with_field("failure_count", failure_count.to_string())
    .with_field("retry_after_seconds", retry_after_seconds.to_string())
    .with_field("request_id", context.request_id.clone())
    .with_field("user_agent", context.user_agent.clone())
}

fn build_lockout_engaged_event(
    context: &AuthenticationContext,
    key: &LoginThrottleKey,
    failure_count: u64,
    lockout_seconds: u64,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Auth,
        "login_throttle_engaged",
        "login throttle lockout engaged",
    )
    .with_field("public_reason", TOO_MANY_ATTEMPTS_PUBLIC_REASON)
    .with_field("submitted_username", key.submitted_username.clone())
    .with_field("bucket_kind", key.bucket_kind.as_str())
    .with_field("remote_addr", key.remote_addr.clone())
    .with_field("failure_count", failure_count.to_string())
    .with_field("lockout_seconds", lockout_seconds.to_string())
    .with_field("request_id", context.request_id.clone())
    .with_field("user_agent", context.user_agent.clone())
}

fn build_cleared_event(context: &AuthenticationContext, key: &LoginThrottleKey) -> LogEvent {
    LogEvent::new(
        LogLevel::Info,
        EventCategory::Auth,
        "login_throttle_cleared",
        "login throttle bucket cleared after successful authentication",
    )
    .with_field("submitted_username", key.submitted_username.clone())
    .with_field("bucket_kind", key.bucket_kind.as_str())
    .with_field("remote_addr", key.remote_addr.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("user_agent", context.user_agent.clone())
}

fn normalize_component(value: &str, max_len: usize, lowercase: bool) -> String {
    let mut normalized = value.trim().chars().take(max_len).collect::<String>();
    if lowercase {
        normalized = normalized.to_ascii_lowercase();
    }

    if normalized.is_empty() {
        "<empty>".to_string()
    } else {
        normalized
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

fn serialize_throttle_record(record: &LoginThrottleRecord) -> String {
    let locked_until = record
        .locked_until
        .map(|value| value.to_string())
        .unwrap_or_default();

    [
        format!("failure_count={}", record.failure_count),
        format!("window_started_at={}", record.window_started_at),
        format!("last_failure_at={}", record.last_failure_at),
        format!("locked_until={locked_until}"),
    ]
    .join("\n")
}

fn parse_throttle_record(content: &str) -> Result<Option<LoginThrottleRecord>, LoginThrottleError> {
    let mut failure_count = None;
    let mut window_started_at = None;
    let mut last_failure_at = None;
    let mut locked_until = None;

    for raw_line in content.lines() {
        if raw_line.trim().is_empty() {
            continue;
        }

        let Some((key, value)) = raw_line.split_once('=') else {
            return Err(LoginThrottleError::StoreFailure {
                reason: format!("invalid login throttle record line: {raw_line}"),
            });
        };

        match key {
            "failure_count" => {
                failure_count = Some(parse_u64_field("failure_count", value)?);
            }
            "window_started_at" => {
                window_started_at = Some(parse_u64_field("window_started_at", value)?);
            }
            "last_failure_at" => {
                last_failure_at = Some(parse_u64_field("last_failure_at", value)?);
            }
            "locked_until" => {
                if !value.trim().is_empty() {
                    locked_until = Some(parse_u64_field("locked_until", value)?);
                }
            }
            _ => {
                return Err(LoginThrottleError::StoreFailure {
                    reason: format!("unexpected login throttle record field: {key}"),
                });
            }
        }
    }

    match (failure_count, window_started_at, last_failure_at) {
        (Some(failure_count), Some(window_started_at), Some(last_failure_at)) => {
            Ok(Some(LoginThrottleRecord {
                failure_count,
                window_started_at,
                last_failure_at,
                locked_until,
            }))
        }
        (None, None, None) => Ok(None),
        _ => Err(LoginThrottleError::StoreFailure {
            reason: "login throttle record was missing required fields".to_string(),
        }),
    }
}

fn parse_u64_field(field: &'static str, value: &str) -> Result<u64, LoginThrottleError> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| LoginThrottleError::StoreFailure {
            reason: format!("failed to parse login throttle field {field}: {error}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthenticationPolicy;
    use std::path::PathBuf;

    #[derive(Debug, Clone, Copy)]
    struct FixedTimeProvider {
        now: u64,
    }

    impl FixedTimeProvider {
        fn new(now: u64) -> Self {
            Self { now }
        }
    }

    impl TimeProvider for FixedTimeProvider {
        fn unix_timestamp(&self) -> u64 {
            self.now
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-throttle",
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
    fn login_throttle_keys_are_hashed_and_bounded() {
        let key = LoginThrottleKey::new(
            "Alice@Example.com",
            "127.0.0.1:12345.......................................................",
        );

        assert_eq!(key.submitted_username, "alice@example.com");
        assert_eq!(
            key.bucket_kind,
            LoginThrottleBucketKind::CredentialAndRemoteAddr
        );
        assert!(key.key_id.len() == 64);
        assert!(key.key_id.chars().all(|ch| ch.is_ascii_hexdigit()));

        let remote_key = LoginThrottleKey::for_remote_addr("Alice@Example.com", "127.0.0.1");
        assert_eq!(remote_key.submitted_username, "alice@example.com");
        assert_eq!(
            remote_key.bucket_kind,
            LoginThrottleBucketKind::RemoteAddrOnly
        );
        assert_ne!(key.key_id, remote_key.key_id);
    }

    #[test]
    fn file_store_round_trips_throttle_records() {
        let dir = temp_dir("osmap-throttle-store");
        let store = FileLoginThrottleStore::new(&dir);
        let record = LoginThrottleRecord {
            failure_count: 3,
            window_started_at: 100,
            last_failure_at: 120,
            locked_until: Some(400),
        };

        store
            .save("abc123", &record)
            .expect("record should be saved");

        let loaded = store
            .load("abc123")
            .expect("record should load")
            .expect("record should exist");

        assert_eq!(loaded, record);
    }

    #[test]
    fn throttle_engages_after_reaching_failure_threshold() {
        let dir = temp_dir("osmap-throttle-engage");
        let store = FileLoginThrottleStore::new(&dir);
        let service = LoginThrottleService::new(
            store,
            FixedTimeProvider::new(200),
            LoginThrottlePolicy {
                credential_max_failures: 2,
                remote_addr_max_failures: 4,
                failure_window_seconds: 300,
                lockout_seconds: 60,
            },
        );

        let first = service
            .record_failure(&test_context(), "alice@example.com")
            .expect("first failure should record");
        assert!(!first.lockout_engaged);
        assert!(first.audit_events.is_empty());

        let second = service
            .record_failure(&test_context(), "alice@example.com")
            .expect("second failure should record");
        assert!(second.lockout_engaged);
        assert_eq!(
            second
                .audit_events
                .first()
                .expect("lockout should emit an event")
                .action,
            "login_throttle_engaged"
        );

        let check = service
            .check(&test_context(), "alice@example.com")
            .expect("check should succeed");

        assert_eq!(
            check.decision,
            LoginThrottleDecision::Throttled {
                retry_after_seconds: 60
            }
        );
        assert_eq!(
            check
                .audit_events
                .first()
                .expect("throttle hit should be logged")
                .action,
            "login_throttled"
        );
    }

    #[test]
    fn expired_failure_window_resets_throttle_count() {
        let dir = temp_dir("osmap-throttle-window");
        let store = FileLoginThrottleStore::new(&dir);
        let key = LoginThrottleKey::new("alice@example.com", "127.0.0.1");
        store
            .save(
                &key.key_id,
                &LoginThrottleRecord {
                    failure_count: 4,
                    window_started_at: 1,
                    last_failure_at: 2,
                    locked_until: None,
                },
            )
            .expect("seed record should save");

        let service = LoginThrottleService::new(
            store,
            FixedTimeProvider::new(500),
            LoginThrottlePolicy {
                credential_max_failures: 5,
                remote_addr_max_failures: 12,
                failure_window_seconds: 60,
                lockout_seconds: 300,
            },
        );

        let record = service
            .record_failure(&test_context(), "alice@example.com")
            .expect("failure should record");
        assert!(!record.lockout_engaged);

        let loaded = FileLoginThrottleStore::new(&dir)
            .load(&key.key_id)
            .expect("record should load")
            .expect("record should exist");
        assert_eq!(loaded.failure_count, 1);
        assert_eq!(loaded.window_started_at, 500);
    }

    #[test]
    fn successful_login_clears_the_bucket() {
        let dir = temp_dir("osmap-throttle-clear");
        let store = FileLoginThrottleStore::new(&dir);
        let key = LoginThrottleKey::new("alice@example.com", "127.0.0.1");
        store
            .save(
                &key.key_id,
                &LoginThrottleRecord {
                    failure_count: 2,
                    window_started_at: 10,
                    last_failure_at: 20,
                    locked_until: Some(50),
                },
            )
            .expect("seed record should save");

        let service = LoginThrottleService::new(
            store,
            FixedTimeProvider::new(30),
            LoginThrottlePolicy::default(),
        );

        let events = service
            .clear_success(&test_context(), "alice@example.com")
            .expect("clear should succeed");

        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|event| event.action == "login_throttle_cleared"));
        assert!(FileLoginThrottleStore::new(&dir)
            .load(&key.key_id)
            .expect("load should succeed")
            .is_none());
    }

    #[test]
    fn remote_addr_bucket_engages_across_rotating_usernames() {
        let dir = temp_dir("osmap-throttle-remote");
        let store = FileLoginThrottleStore::new(&dir);
        let service = LoginThrottleService::new(
            store,
            FixedTimeProvider::new(200),
            LoginThrottlePolicy {
                credential_max_failures: 5,
                remote_addr_max_failures: 2,
                failure_window_seconds: 300,
                lockout_seconds: 60,
            },
        );

        let first = service
            .record_failure(&test_context(), "alice@example.com")
            .expect("first rotating-username failure should record");
        assert!(!first.lockout_engaged);

        let second = service
            .record_failure(&test_context(), "bob@example.com")
            .expect("second rotating-username failure should record");
        assert!(second.lockout_engaged);
        assert!(second.audit_events.iter().any(|event| {
            event.action == "login_throttle_engaged"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "bucket_kind" && field.value == "remote_addr_only")
        }));

        let check = service
            .check(&test_context(), "charlie@example.com")
            .expect("remote-only throttle check should succeed");
        assert_eq!(
            check.decision,
            LoginThrottleDecision::Throttled {
                retry_after_seconds: 60
            }
        );
        assert!(check.audit_events.iter().any(|event| {
            event.action == "login_throttled"
                && event
                    .fields
                    .iter()
                    .any(|field| field.key == "bucket_kind" && field.value == "remote_addr_only")
        }));
    }
}
