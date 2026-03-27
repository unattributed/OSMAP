//! Authentication primitives for the first WP3 implementation slice.
//!
//! This module intentionally stops at primary credential handling plus an
//! explicit "MFA required" decision. It does not pretend the user is fully
//! authenticated until a later slice implements factor verification and session
//! issuance.

use std::fmt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::str;

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

/// Conservative maximum length for submitted TOTP codes.
pub const DEFAULT_FACTOR_CODE_MAX_LEN: usize = 16;

/// Defines the bounds and mandatory second-factor policy for browser auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationPolicy {
    pub username_max_len: usize,
    pub password_max_len: usize,
    pub request_id_max_len: usize,
    pub remote_addr_max_len: usize,
    pub user_agent_max_len: usize,
    pub factor_code_max_len: usize,
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
            factor_code_max_len: DEFAULT_FACTOR_CODE_MAX_LEN,
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

        validate_context_field("request_id", &request_id, policy.request_id_max_len, true)?;
        validate_context_field(
            "remote_addr",
            &remote_addr,
            policy.remote_addr_max_len,
            true,
        )?;
        validate_context_field("user_agent", &user_agent, policy.user_agent_max_len, false)?;

        Ok(Self {
            request_id,
            remote_addr,
            user_agent,
        })
    }
}

/// Carries a bounded second-factor code after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactorInput {
    code: String,
}

impl SecondFactorInput {
    /// Validates a second-factor code against the authentication policy.
    pub fn new(
        policy: AuthenticationPolicy,
        code: impl Into<String>,
    ) -> Result<Self, CredentialValidationError> {
        let code = code.into().trim().to_string();

        validate_factor_code(&code, policy.factor_code_max_len)?;

        Ok(Self { code })
    }

    /// Returns the validated second-factor code.
    pub fn code(&self) -> &str {
        &self.code
    }
}

/// Describes why an auth attempt failed from a user-facing perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicFailureReason {
    InvalidCredentials,
    InvalidRequest,
    InvalidSecondFactor,
    TemporarilyUnavailable,
}

impl PublicFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidSecondFactor => "invalid_second_factor",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Describes the internal reason used in audit-quality auth logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFailureReason {
    InputRejected,
    InvalidCredentials,
    InvalidSecondFactor,
    BackendUnavailable,
}

impl AuditFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InputRejected => "input_rejected",
            Self::InvalidCredentials => "invalid_credentials",
            Self::InvalidSecondFactor => "invalid_second_factor",
            Self::BackendUnavailable => "backend_unavailable",
        }
    }
}

/// The result of the primary credential check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimaryAuthVerdict {
    Reject,
    Accept { canonical_username: String },
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
        context: &AuthenticationContext,
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
    AuthenticatedPendingSession {
        canonical_username: String,
    },
}

/// The combined auth decision and audit event emitted by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationOutcome {
    pub decision: AuthenticationDecision,
    pub audit_event: LogEvent,
}

/// Backend failures that should not leak as detailed user-facing factor errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondFactorBackendError {
    pub backend: &'static str,
    pub reason: String,
}

/// The result of checking a second factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondFactorVerdict {
    Reject,
    Accept,
}

/// A backend capable of validating the second factor for a canonical user.
pub trait SecondFactorVerifier {
    fn verify_second_factor(
        &self,
        canonical_username: &str,
        factor: RequiredSecondFactor,
        code: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError>;
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
            .verify_primary(context, credentials.username(), credentials.password())
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
            Ok(PrimaryAuthVerdict::Accept { canonical_username }) => AuthenticationOutcome {
                decision: AuthenticationDecision::MfaRequired {
                    canonical_username: canonical_username.clone(),
                    second_factor: self.policy.required_second_factor,
                },
                audit_event: build_mfa_required_event(
                    context,
                    canonical_username,
                    self.policy.required_second_factor,
                ),
            },
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

/// The service responsible for validating the required second factor.
pub struct SecondFactorService<V> {
    policy: AuthenticationPolicy,
    verifier: V,
}

impl<V> SecondFactorService<V>
where
    V: SecondFactorVerifier,
{
    /// Creates a new second-factor service around the supplied verifier.
    pub fn new(policy: AuthenticationPolicy, verifier: V) -> Self {
        Self { policy, verifier }
    }

    /// Verifies the required second factor for a canonical user.
    pub fn verify(
        &self,
        context: &AuthenticationContext,
        canonical_username: impl Into<String>,
        second_factor: RequiredSecondFactor,
        code: impl Into<String>,
    ) -> AuthenticationOutcome {
        let canonical_username = canonical_username.into();
        let factor_input = match SecondFactorInput::new(self.policy, code) {
            Ok(input) => input,
            Err(error) => {
                return AuthenticationOutcome {
                    decision: AuthenticationDecision::Denied {
                        public_reason: PublicFailureReason::InvalidRequest,
                    },
                    audit_event: build_factor_denied_event(
                        context,
                        canonical_username,
                        second_factor,
                        PublicFailureReason::InvalidRequest,
                        AuditFailureReason::InputRejected,
                        Some(error.as_str().to_string()),
                    ),
                };
            }
        };

        match self.verifier.verify_second_factor(
            &canonical_username,
            second_factor,
            factor_input.code(),
        ) {
            Ok(SecondFactorVerdict::Reject) => AuthenticationOutcome {
                decision: AuthenticationDecision::Denied {
                    public_reason: PublicFailureReason::InvalidSecondFactor,
                },
                audit_event: build_factor_denied_event(
                    context,
                    canonical_username,
                    second_factor,
                    PublicFailureReason::InvalidSecondFactor,
                    AuditFailureReason::InvalidSecondFactor,
                    None,
                ),
            },
            Ok(SecondFactorVerdict::Accept) => AuthenticationOutcome {
                decision: AuthenticationDecision::AuthenticatedPendingSession {
                    canonical_username: canonical_username.clone(),
                },
                audit_event: build_factor_accepted_event(
                    context,
                    canonical_username,
                    second_factor,
                ),
            },
            Err(error) => AuthenticationOutcome {
                decision: AuthenticationDecision::Denied {
                    public_reason: PublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_factor_backend_error_event(
                    context,
                    canonical_username,
                    second_factor,
                    &error,
                ),
            },
        }
    }
}

/// Provides the command result used by external auth backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecution {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Errors that can occur while invoking external auth backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandExecutionError {
    pub reason: String,
}

/// Runs an external command with supplied standard input.
pub trait CommandExecutor {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        stdin_data: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError>;

    fn run_with_stdin(
        &self,
        program: &str,
        args: &[String],
        stdin_data: &str,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes(program, args, stdin_data.as_bytes())
    }
}

/// Executes external commands via the system process API.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        stdin_data: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| CommandExecutionError {
                reason: format!("failed to spawn command: {error}"),
            })?;

        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write as _;
            stdin
                .write_all(stdin_data)
                .map_err(|error| CommandExecutionError {
                    reason: format!("failed to write command stdin: {error}"),
                })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|error| CommandExecutionError {
                reason: format!("failed waiting for command output: {error}"),
            })?;

        Ok(CommandExecution {
            status_code: status_code_or_signal(output.status),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Connects primary credential verification to `doveadm auth test`.
pub struct DoveadmAuthTestBackend<E> {
    command_executor: E,
    doveadm_path: PathBuf,
    auth_socket_path: Option<PathBuf>,
    service: &'static str,
}

impl<E> DoveadmAuthTestBackend<E> {
    /// Builds a backend using the supplied command executor.
    pub fn new(
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
        auth_socket_path: Option<PathBuf>,
        service: &'static str,
    ) -> Self {
        Self {
            command_executor,
            doveadm_path: doveadm_path.into(),
            auth_socket_path,
            service,
        }
    }
}

impl<E> PrimaryCredentialBackend for DoveadmAuthTestBackend<E>
where
    E: CommandExecutor,
{
    fn verify_primary(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        let mut args = vec![
            "-o".to_string(),
            "stats_writer_socket_path=".to_string(),
            "auth".to_string(),
            "test".to_string(),
        ];

        if let Some(auth_socket_path) = &self.auth_socket_path {
            args.push("-a".to_string());
            args.push(auth_socket_path.display().to_string());
        }

        args.push("-x".to_string());
        args.push(format!("service={}", self.service));

        if !context.remote_addr.is_empty() {
            args.push("-x".to_string());
            args.push(format!("rip={}", context.remote_addr));
        }

        args.push(username.to_string());

        let execution = self
            .command_executor
            .run_with_stdin(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                &format!("{password}\n"),
            )
            .map_err(|error| PrimaryAuthBackendError {
                backend: "doveadm-auth-test",
                reason: error.reason,
            })?;

        parse_doveadm_auth_test_output(username, &execution)
    }
}

/// Describes validation failures on bounded auth inputs and audit context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialValidationError {
    EmptyField { field: &'static str },
    TooLong { field: &'static str, max_len: usize },
    ControlCharacter { field: &'static str },
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

/// Validates the submitted second-factor code.
fn validate_factor_code(value: &str, max_len: usize) -> Result<(), CredentialValidationError> {
    if value.is_empty() {
        return Err(CredentialValidationError::EmptyField {
            field: "factor_code",
        });
    }

    if value.len() > max_len {
        return Err(CredentialValidationError::TooLong {
            field: "factor_code",
            max_len,
        });
    }

    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(CredentialValidationError::ControlCharacter {
            field: "factor_code",
        });
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
    .with_field(
        "public_reason",
        PublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field(
        "audit_reason",
        AuditFailureReason::BackendUnavailable.as_str(),
    )
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

/// Builds the audit event for a denied second-factor attempt.
fn build_factor_denied_event(
    context: &AuthenticationContext,
    canonical_username: String,
    second_factor: RequiredSecondFactor,
    public_reason: PublicFailureReason,
    audit_reason: AuditFailureReason,
    detail: Option<String>,
) -> LogEvent {
    let mut event = LogEvent::new(
        LogLevel::Warn,
        EventCategory::Auth,
        "second_factor_denied",
        "second factor denied",
    )
    .with_field("stage", "second_factor")
    .with_field("result", "denied")
    .with_field("public_reason", public_reason.as_str())
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("canonical_username", canonical_username)
    .with_field("second_factor", second_factor.as_str())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone());

    if let Some(detail) = detail {
        event = event.with_field("detail", detail);
    }

    event
}

/// Builds the audit event for a backend failure during second-factor checking.
fn build_factor_backend_error_event(
    context: &AuthenticationContext,
    canonical_username: String,
    second_factor: RequiredSecondFactor,
    error: &SecondFactorBackendError,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Error,
        EventCategory::Auth,
        "second_factor_backend_error",
        "second factor backend failure",
    )
    .with_field("stage", "second_factor")
    .with_field("result", "error")
    .with_field(
        "public_reason",
        PublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field(
        "audit_reason",
        AuditFailureReason::BackendUnavailable.as_str(),
    )
    .with_field("canonical_username", canonical_username)
    .with_field("second_factor", second_factor.as_str())
    .with_field("backend", error.backend)
    .with_field("detail", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Builds the audit event for an accepted second-factor check.
fn build_factor_accepted_event(
    context: &AuthenticationContext,
    canonical_username: String,
    second_factor: RequiredSecondFactor,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Info,
        EventCategory::Auth,
        "second_factor_accepted",
        "second factor accepted, session issuance pending",
    )
    .with_field("stage", "second_factor")
    .with_field("result", "accepted")
    .with_field("canonical_username", canonical_username)
    .with_field("second_factor", second_factor.as_str())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Returns a numeric status code even when the process exited via signal.
fn status_code_or_signal(status: ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

/// Parses the result of `doveadm auth test`.
fn parse_doveadm_auth_test_output(
    submitted_username: &str,
    execution: &CommandExecution,
) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
    let combined_output = format!("{}{}", execution.stdout, execution.stderr);

    if execution.status_code == 0 && combined_output.contains("auth succeeded") {
        return Ok(PrimaryAuthVerdict::Accept {
            canonical_username: extract_doveadm_user_field(&combined_output)
                .unwrap_or_else(|| submitted_username.to_string()),
        });
    }

    if execution.status_code == 77 || combined_output.contains("auth failed") {
        return Ok(PrimaryAuthVerdict::Reject);
    }

    Err(PrimaryAuthBackendError {
        backend: "doveadm-auth-test",
        reason: format!(
            "unexpected doveadm result status={} output={:?}",
            execution.status_code, combined_output
        ),
    })
}

/// Extracts the canonical user value from `doveadm auth test` output.
fn extract_doveadm_user_field(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("user=")
            .map(|user| user.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use std::rc::Rc;

    struct AcceptingBackend;

    impl PrimaryCredentialBackend for AcceptingBackend {
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

    struct FailingBackend;

    impl PrimaryCredentialBackend for FailingBackend {
        fn verify_primary(
            &self,
            _context: &AuthenticationContext,
            _username: &str,
            _password: &str,
        ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
            Err(PrimaryAuthBackendError {
                backend: "test-backend",
                reason: "backend unavailable".to_string(),
            })
        }
    }

    struct AcceptingSecondFactorVerifier;

    impl SecondFactorVerifier for AcceptingSecondFactorVerifier {
        fn verify_second_factor(
            &self,
            canonical_username: &str,
            factor: RequiredSecondFactor,
            code: &str,
        ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
            if canonical_username == "alice@example.com"
                && factor == RequiredSecondFactor::Totp
                && code == "123456"
            {
                return Ok(SecondFactorVerdict::Accept);
            }

            Ok(SecondFactorVerdict::Reject)
        }
    }

    struct FailingSecondFactorVerifier;

    impl SecondFactorVerifier for FailingSecondFactorVerifier {
        fn verify_second_factor(
            &self,
            _canonical_username: &str,
            _factor: RequiredSecondFactor,
            _code: &str,
        ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
            Err(SecondFactorBackendError {
                backend: "test-totp",
                reason: "totp store unavailable".to_string(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct StubCommandExecutor {
        execution: Result<CommandExecution, CommandExecutionError>,
        program: Option<String>,
        args: Option<Vec<String>>,
        stdin_data: Option<String>,
    }

    impl StubCommandExecutor {
        fn success(execution: CommandExecution) -> Self {
            Self {
                execution: Ok(execution),
                program: None,
                args: None,
                stdin_data: None,
            }
        }
    }

    impl CommandExecutor for Rc<std::cell::RefCell<StubCommandExecutor>> {
        fn run_with_stdin_bytes(
            &self,
            program: &str,
            args: &[String],
            stdin_data: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            let mut state = self.borrow_mut();
            state.program = Some(program.to_string());
            state.args = Some(args.to_vec());
            state.stdin_data = Some(
                String::from_utf8(stdin_data.to_vec())
                    .expect("auth test stdin should remain valid utf-8"),
            );
            state.execution.clone()
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
    fn rejects_non_numeric_factor_codes() {
        let error = SecondFactorInput::new(AuthenticationPolicy::default(), "12a456")
            .expect_err("must fail");

        assert_eq!(
            error,
            CredentialValidationError::ControlCharacter {
                field: "factor_code",
            }
        );
    }

    #[test]
    fn denies_invalid_primary_credentials() {
        let service = AuthenticationService::new(AuthenticationPolicy::default(), AcceptingBackend);

        let outcome = service.authenticate(&test_context(), "alice@example.com", "wrong password");

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
    fn second_factor_acceptance_becomes_authenticated_pending_session() {
        let service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            AcceptingSecondFactorVerifier,
        );

        let outcome = service.verify(
            &test_context(),
            "alice@example.com",
            RequiredSecondFactor::Totp,
            "123456",
        );

        assert_eq!(
            outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: "alice@example.com".to_string(),
            }
        );
        assert_eq!(outcome.audit_event.action, "second_factor_accepted");
    }

    #[test]
    fn second_factor_rejection_is_audited_cleanly() {
        let service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            AcceptingSecondFactorVerifier,
        );

        let outcome = service.verify(
            &test_context(),
            "alice@example.com",
            RequiredSecondFactor::Totp,
            "999999",
        );

        assert_eq!(
            outcome.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::InvalidSecondFactor,
            }
        );
        assert_eq!(outcome.audit_event.action, "second_factor_denied");
    }

    #[test]
    fn second_factor_backend_failures_become_operator_visible_events() {
        let service =
            SecondFactorService::new(AuthenticationPolicy::default(), FailingSecondFactorVerifier);

        let outcome = service.verify(
            &test_context(),
            "alice@example.com",
            RequiredSecondFactor::Totp,
            "123456",
        );

        assert_eq!(
            outcome.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "second_factor_backend_error");
    }

    #[test]
    fn doveadm_backend_uses_stdin_and_contextual_auth_info() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout:
                    "passdb: alice@example.com auth succeeded\nextra fields:\n  user=alice@example.com\n"
                        .to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmAuthTestBackend::new(
            executor.clone(),
            "/usr/local/bin/doveadm",
            Some(PathBuf::from("/var/run/dovecot/auth-client")),
            "imap",
        );

        let verdict = backend
            .verify_primary(
                &test_context(),
                "alice@example.com",
                "correct horse battery staple",
            )
            .expect("backend should succeed");

        assert_eq!(
            verdict,
            PrimaryAuthVerdict::Accept {
                canonical_username: "alice@example.com".to_string(),
            }
        );

        let recorded = executor.borrow();
        assert_eq!(recorded.program.as_deref(), Some("/usr/local/bin/doveadm"));
        assert_eq!(
            recorded.stdin_data.as_deref(),
            Some("correct horse battery staple\n")
        );
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "auth".to_string(),
                "test".to_string(),
                "-a".to_string(),
                "/var/run/dovecot/auth-client".to_string(),
                "-x".to_string(),
                "service=imap".to_string(),
                "-x".to_string(),
                "rip=127.0.0.1".to_string(),
                "alice@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn doveadm_failure_exit_is_treated_as_invalid_credentials() {
        let backend = DoveadmAuthTestBackend::new(
            Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
                CommandExecution {
                    status_code: 77,
                    stdout: String::new(),
                    stderr: "passdb: alice@example.com auth failed\n".to_string(),
                },
            ))),
            "/usr/local/bin/doveadm",
            None,
            "imap",
        );

        let verdict = backend
            .verify_primary(&test_context(), "alice@example.com", "wrong password")
            .expect("invalid credentials should not be treated as backend errors");

        assert_eq!(verdict, PrimaryAuthVerdict::Reject);
    }

    #[test]
    fn renders_audit_quality_log_lines_for_second_factor_events() {
        let service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            AcceptingSecondFactorVerifier,
        );
        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);

        let outcome = service.verify(
            &test_context(),
            "alice@example.com",
            RequiredSecondFactor::Totp,
            "123456",
        );
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 888);

        assert_eq!(
            rendered,
            "ts=888 level=info category=auth action=second_factor_accepted msg=\"second factor accepted, session issuance pending\" stage=\"second_factor\" result=\"accepted\" canonical_username=\"alice@example.com\" second_factor=\"totp\" request_id=\"req-123\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
        );
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot auth surface"]
    fn live_doveadm_backend_rejects_invalid_credentials() {
        if !PathBuf::from("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmAuthTestBackend::new(
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
            None,
            "imap",
        );
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "live-invalid-auth",
            "127.0.0.1",
            "osmap-live-test",
        )
        .expect("live test context should be valid");

        let verdict = backend
            .verify_primary(&context, "nosuchuser@example.com", "wrongpassword")
            .expect("invalid credentials should be a normal auth rejection");

        assert_eq!(verdict, PrimaryAuthVerdict::Reject);
    }

    #[test]
    fn converts_backend_failures_into_operator_visible_auth_events() {
        let service = AuthenticationService::new(AuthenticationPolicy::default(), FailingBackend);

        let outcome = service.authenticate(&test_context(), "alice@example.com", "anything");

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
