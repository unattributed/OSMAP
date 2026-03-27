//! Authentication primitives for the first WP3 implementation slice.
//!
//! This module intentionally stops at primary credential handling plus an
//! explicit "MFA required" decision. It does not pretend the user is fully
//! authenticated until a later slice implements factor verification and session
//! issuance.

use std::fmt;

use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};

/// Conservative maximum length for submitted mailbox identifiers.
pub const DEFAULT_USERNAME_MAX_LEN: usize = 320;

/// Conservative maximum length for submitted passwords.
pub const DEFAULT_PASSWORD_MAX_LEN: usize = 1024;

/// Conservative maximum length for request identifiers in auth audit events.
pub const DEFAULT_REQUEST_ID_MAX_LEN: usize = 128;

/// Conservative maximum length for remote-address strings in auth audit events.
pub const DEFAULT_REMOTE_ADDR_MAX_LEN: usize = 128;

/// Conservative maximum length for user-agent summaries in auth audit events.
pub const DEFAULT_USER_AGENT_MAX_LEN: usize = 512;

/// Defines the bounds and mandatory second-factor policy for browser auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationPolicy {
    pub username_max_len: usize,
    pub password_max_len: usize,
    pub request_id_max_len: usize,
    pub remote_addr_max_len: usize,
    pub user_agent_max_len: usize,
    pub required_second_factor: RequiredSecondFactor,
}

impl Default for AuthenticationPolicy {
    fn default() -> Self {
        Self {
            username_max_len: DEFAULT_USERNAME_MAX_LEN,
            password_max_len: DEFAULT_PASSWORD_MAX_LEN,
            request_id_max_len: DEFAULT_REQUEST_ID_MAX_LEN,
            remote_addr_max_len: DEFAULT_REMOTE_ADDR_MAX_LEN,
            user_agent_max_len: DEFAULT_USER_AGENT_MAX_LEN,
            required_second_factor: RequiredSecondFactor::Totp,
        }
    }
}

/// The second-factor requirement produced after primary credential acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredSecondFactor {
    Totp,
}

impl RequiredSecondFactor {
    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
        }
    }
}

/// Carries raw user-submitted credentials after bounded validation.
pub struct CredentialInput {
    username: String,
    password: String,
}

impl CredentialInput {
    /// Validates raw credential input against the authentication policy.
    pub fn new(
        policy: AuthenticationPolicy,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, CredentialValidationError> {
        let username = username.into().trim().to_string();
        let password = password.into();

        validate_username(&username, policy.username_max_len)?;
        validate_password(&password, policy.password_max_len)?;

        Ok(Self { username, password })
    }

    /// Returns the validated username for backend verification and logging.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the validated password for backend verification.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for CredentialInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInput")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Context attached to an authentication attempt for audit and investigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationContext {
    pub request_id: String,
    pub remote_addr: String,
    pub user_agent: String,
}

impl AuthenticationContext {
    /// Validates the audit context so later auth logs stay bounded and useful.
    pub fn new(
        policy: AuthenticationPolicy,
        request_id: impl Into<String>,
        remote_addr: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Result<Self, CredentialValidationError> {
        let request_id = request_id.into();
        let remote_addr = remote_addr.into();
        let user_agent = user_agent.into();

        validate_context_field(
            "request_id",
            &request_id,
            policy.request_id_max_len,
            true,
        )?;
        validate_context_field(
            "remote_addr",
            &remote_addr,
            policy.remote_addr_max_len,
            true,
        )?;
        validate_context_field(
            "user_agent",
            &user_agent,
            policy.user_agent_max_len,
            false,
        )?;

        Ok(Self {
            request_id,
            remote_addr,
            user_agent,
        })
    }
}

/// Describes why an auth attempt failed from a user-facing perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicFailureReason {
    InvalidCredentials,
    InvalidRequest,
    TemporarilyUnavailable,
}

impl PublicFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::InvalidRequest => "invalid_request",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Describes the internal reason used in audit-quality auth logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailureReason {
    InputRejected,
    InvalidCredentials,
    BackendUnavailable,
}

impl AuditFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InputRejected => "input_rejected",
            Self::InvalidCredentials => "invalid_credentials",
            Self::BackendUnavailable => "backend_unavailable",
        }
    }
}

/// The result of the primary credential check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryAuthVerdict {
    Reject,
    Accept {
        canonical_username: String,
    },
}

/// Backend failures that should not leak as detailed user-facing auth messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimaryAuthBackendError {
    pub backend: &'static str,
    pub reason: String,
}

/// A backend capable of validating primary mailbox credentials.
pub trait PrimaryCredentialBackend {
    fn verify_primary(
        &self,
        username: &str,
        password: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError>;
}

/// The decision produced by the current authentication slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationDecision {
    Denied {
        public_reason: PublicFailureReason,
    },
    MfaRequired {
        canonical_username: String,
        second_factor: RequiredSecondFactor,
    },
}

/// The combined auth decision and audit event emitted by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationOutcome {
    pub decision: AuthenticationDecision,
    pub audit_event: LogEvent,
}

/// The service responsible for bounded credential handling and primary auth.
pub struct AuthenticationService<B> {
    policy: AuthenticationPolicy,
    backend: B,
}

impl<B> AuthenticationService<B>
where
    B: PrimaryCredentialBackend,
{
    /// Creates a new authentication service around the supplied backend.
    pub fn new(policy: AuthenticationPolicy, backend: B) -> Self {
        Self { policy, backend }
    }

    /// Executes the current auth slice: validate input, verify primary
    /// credentials, and either deny the attempt or require MFA.
    pub fn authenticate(
        &self,
        context: &AuthenticationContext,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> AuthenticationOutcome {
        let credentials = match CredentialInput::new(self.policy, username, password) {
            Ok(credentials) => credentials,
            Err(error) => {
                return AuthenticationOutcome {
                    decision: AuthenticationDecision::Denied {
                        public_reason: PublicFailureReason::InvalidRequest,
                    },
                    audit_event: build_denied_event(
                        context,
                        "<invalid>".to_string(),
                        PublicFailureReason::InvalidRequest,
                        AuditFailureReason::InputRejected,
                        Some(error.as_str().to_string()),
                    ),
                };
            }
        };

        match self
            .backend
            .verify_primary(credentials.username(), credentials.password())
        {
            Ok(PrimaryAuthVerdict::Reject) => AuthenticationOutcome {
                decision: AuthenticationDecision::Denied {
                    public_reason: PublicFailureReason::InvalidCredentials,
                },
                audit_event: build_denied_event(
                    context,
                    credentials.username().to_string(),
                    PublicFailureReason::InvalidCredentials,
                    AuditFailureReason::InvalidCredentials,
                    None,
                ),
            },
            Ok(PrimaryAuthVerdict::Accept { canonical_username }) => {
                AuthenticationOutcome {
                    decision: AuthenticationDecision::MfaRequired {
                        canonical_username: canonical_username.clone(),
                        second_factor: self.policy.required_second_factor,
                    },
                    audit_event: build_mfa_required_event(
                        context,
                        canonical_username,
                        self.policy.required_second_factor,
                    ),
                }
            }
            Err(error) => AuthenticationOutcome {
                decision: AuthenticationDecision::Denied {
                    public_reason: PublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_backend_error_event(
                    context,
                    credentials.username().to_string(),
                    &error,
                ),
            },
        }
    }
}

/// Describes validation failures on bounded auth inputs and audit context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialValidationError {
    EmptyField {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        max_len: usize,
    },
    ControlCharacter {
        field: &'static str,
    },
}

impl CredentialValidationError {
    /// Returns a stable short reason for operator logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyField { .. } => "field must not be empty",
            Self::TooLong { .. } => "field exceeded maximum length",
            Self::ControlCharacter { .. } => "field contains control characters",
        }
    }
}

/// Validates the submitted username.
fn validate_username(value: &str, max_len: usize) -> Result<(), CredentialValidationError> {
    if value.is_empty() {
        return Err(CredentialValidationError::EmptyField { field: "username" });
    }

    if value.len() > max_len {
        return Err(CredentialValidationError::TooLong {
            field: "username",
            max_len,
        });
    }

    if value.chars().any(char::is_control) {
        return Err(CredentialValidationError::ControlCharacter { field: "username" });
    }

    Ok(())
}

/// Validates the submitted password without logging or formatting it.
fn validate_password(value: &str, max_len: usize) -> Result<(), CredentialValidationError> {
    if value.is_empty() {
        return Err(CredentialValidationError::EmptyField { field: "password" });
    }

    if value.len() > max_len {
        return Err(CredentialValidationError::TooLong {
            field: "password",
            max_len,
        });
    }

    if value.contains('\0') {
        return Err(CredentialValidationError::ControlCharacter { field: "password" });
    }

    Ok(())
}

/// Validates audit-context fields so auth events remain bounded and parseable.
fn validate_context_field(
    field: &'static str,
    value: &str,
    max_len: usize,
    required: bool,
) -> Result<(), CredentialValidationError> {
    if required && value.trim().is_empty() {
        return Err(CredentialValidationError::EmptyField { field });
    }

    if value.len() > max_len {
        return Err(CredentialValidationError::TooLong { field, max_len });
    }

    if value.chars().any(char::is_control) {
        return Err(CredentialValidationError::ControlCharacter { field });
    }

    Ok(())
}

/// Builds the audit event for a denied authentication attempt.
fn build_denied_event(
    context: &AuthenticationContext,
    submitted_username: String,
    public_reason: PublicFailureReason,
    audit_reason: AuditFailureReason,
    detail: Option<String>,
) -> LogEvent {
    let mut event = LogEvent::new(
        LogLevel::Warn,
        EventCategory::Auth,
        "login_denied",
        "primary authentication denied",
    )
    .with_field("stage", "primary")
    .with_field("result", "denied")
    .with_field("public_reason", public_reason.as_str())
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("submitted_username", submitted_username)
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone());

    if let Some(detail) = detail {
        event = event.with_field("detail", detail);
    }

    event
}

/// Builds the audit event for a backend failure during authentication.
fn build_backend_error_event(
    context: &AuthenticationContext,
    submitted_username: String,
    error: &PrimaryAuthBackendError,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Error,
        EventCategory::Auth,
        "login_backend_error",
        "primary authentication backend failure",
    )
    .with_field("stage", "primary")
    .with_field("result", "error")
    .with_field("public_reason", PublicFailureReason::TemporarilyUnavailable.as_str())
    .with_field("audit_reason", AuditFailureReason::BackendUnavailable.as_str())
    .with_field("backend", error.backend)
    .with_field("detail", error.reason.clone())
    .with_field("submitted_username", submitted_username)
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Builds the audit event for a successful primary auth that now requires MFA.
fn build_mfa_required_event(
    context: &AuthenticationContext,
    canonical_username: String,
    second_factor: RequiredSecondFactor,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Info,
        EventCategory::Auth,
        "login_mfa_required",
        "primary authentication accepted, second factor required",
    )
    .with_field("stage", "primary")
    .with_field("result", "mfa_required")
    .with_field("canonical_username", canonical_username)
    .with_field("second_factor", second_factor.as_str())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogFormat;
    use crate::logging::Logger;

    struct AcceptingBackend;

    impl PrimaryCredentialBackend for AcceptingBackend {
        fn verify_primary(
            &self,
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

    struct FailingBackend;

    impl PrimaryCredentialBackend for FailingBackend {
        fn verify_primary(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
            Err(PrimaryAuthBackendError {
                backend: "test-backend",
                reason: "backend unavailable".to_string(),
            })
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-123",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("test context should be valid")
    }

    #[test]
    fn redacts_password_in_debug_output() {
        let credentials = CredentialInput::new(
            AuthenticationPolicy::default(),
            "alice@example.com",
            "correct horse battery staple",
        )
        .expect("credentials should be valid");

        let debug_output = format!("{credentials:?}");

        assert!(debug_output.contains("<redacted>"));
        assert!(!debug_output.contains("correct horse battery staple"));
    }

    #[test]
    fn rejects_oversized_usernames() {
        let policy = AuthenticationPolicy {
            username_max_len: 5,
            ..AuthenticationPolicy::default()
        };

        let error =
            CredentialInput::new(policy, "alice@example.com", "password").expect_err("must fail");

        assert_eq!(
            error,
            CredentialValidationError::TooLong {
                field: "username",
                max_len: 5,
            }
        );
    }

    #[test]
    fn denies_invalid_primary_credentials() {
        let service = AuthenticationService::new(AuthenticationPolicy::default(), AcceptingBackend);

        let outcome =
            service.authenticate(&test_context(), "alice@example.com", "wrong password");

        assert_eq!(
            outcome.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::InvalidCredentials,
            }
        );
        assert_eq!(outcome.audit_event.category, EventCategory::Auth);
        assert_eq!(outcome.audit_event.action, "login_denied");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn requires_mfa_after_primary_credential_acceptance() {
        let service = AuthenticationService::new(AuthenticationPolicy::default(), AcceptingBackend);

        let outcome = service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );

        assert_eq!(
            outcome.decision,
            AuthenticationDecision::MfaRequired {
                canonical_username: "alice@example.com".to_string(),
                second_factor: RequiredSecondFactor::Totp,
            }
        );
        assert_eq!(outcome.audit_event.action, "login_mfa_required");
    }

    #[test]
    fn converts_backend_failures_into_operator_visible_auth_events() {
        let service = AuthenticationService::new(AuthenticationPolicy::default(), FailingBackend);

        let outcome =
            service.authenticate(&test_context(), "alice@example.com", "anything");

        assert_eq!(
            outcome.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.level, LogLevel::Error);
        assert_eq!(outcome.audit_event.action, "login_backend_error");
    }

    #[test]
    fn rejects_invalid_auth_context() {
        let error = AuthenticationContext::new(
            AuthenticationPolicy {
                request_id_max_len: 4,
                ..AuthenticationPolicy::default()
            },
            "request-123",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect_err("oversized request ids must fail");

        assert_eq!(
            error,
            CredentialValidationError::TooLong {
                field: "request_id",
                max_len: 4,
            }
        );
    }

    #[test]
    fn produces_audit_quality_log_lines_for_auth_events() {
        let service = AuthenticationService::new(AuthenticationPolicy::default(), AcceptingBackend);
        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);

        let outcome = service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 777);

        assert_eq!(
            rendered,
            "ts=777 level=info category=auth action=login_mfa_required msg=\"primary authentication accepted, second factor required\" stage=\"primary\" result=\"mfa_required\" canonical_username=\"alice@example.com\" second_factor=\"totp\" request_id=\"req-123\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
        );
    }
}
