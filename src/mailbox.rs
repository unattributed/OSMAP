//! Mailbox listing for the first WP5 read-path slice.
//!
//! This module keeps the first mailbox read path intentionally small:
//! - session validation remains a separate gate handled before mailbox access
//! - mailbox listing uses the existing Dovecot surface instead of a new mail
//!   stack
//! - mailbox results and failures are emitted as structured audit events

use std::path::PathBuf;

use crate::auth::{
    AuthenticationContext, CommandExecution, CommandExecutor, SystemCommandExecutor,
};
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::session::ValidatedSession;

/// Conservative maximum length for a mailbox name returned by the backend.
pub const DEFAULT_MAILBOX_NAME_MAX_LEN: usize = 255;

/// Conservative upper bound for the number of mailboxes returned in one listing.
pub const DEFAULT_MAX_MAILBOXES: usize = 1024;

/// Policy controlling mailbox-output bounds for the first read-path slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxListingPolicy {
    pub mailbox_name_max_len: usize,
    pub max_mailboxes: usize,
}

impl Default for MailboxListingPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        }
    }
}

/// A single mailbox visible to the authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    pub name: String,
}

impl MailboxEntry {
    /// Validates a mailbox name so later UI and logging code does not inherit
    /// unbounded or ambiguous backend output.
    pub fn new(
        policy: MailboxListingPolicy,
        name: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        let name = name.into();

        if name.is_empty() {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: "mailbox name must not be empty".to_string(),
            });
        }

        if name.len() > policy.mailbox_name_max_len {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: format!(
                    "mailbox name exceeded maximum length of {} bytes",
                    policy.mailbox_name_max_len
                ),
            });
        }

        if name.chars().any(char::is_control) {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: "mailbox name contains control characters".to_string(),
            });
        }

        Ok(Self { name })
    }
}

/// The user-facing reason returned when mailbox listing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxPublicFailureReason {
    TemporarilyUnavailable,
}

impl MailboxPublicFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Internal audit reason used when mailbox listing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxAuditFailureReason {
    BackendUnavailable,
    OutputRejected,
}

impl MailboxAuditFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackendUnavailable => "backend_unavailable",
            Self::OutputRejected => "output_rejected",
        }
    }
}

/// The outcome of a mailbox-list request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxListingDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailboxes: Vec<MailboxEntry>,
    },
}

/// The decision plus audit event emitted by mailbox listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxListingOutcome {
    pub decision: MailboxListingDecision,
    pub audit_event: LogEvent,
}

/// Backend failures that should not leak detailed internals to mailbox users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBackendError {
    pub backend: &'static str,
    pub reason: String,
}

/// A backend capable of listing mailboxes for a canonical user.
pub trait MailboxBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError>;
}

/// Lists mailboxes for an already validated session.
pub struct MailboxListingService<B> {
    backend: B,
}

impl<B> MailboxListingService<B>
where
    B: MailboxBackend,
{
    /// Creates a mailbox-listing service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Lists mailboxes for the canonical user attached to the validated session.
    pub fn list_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> MailboxListingOutcome {
        let canonical_username = validated_session.record.canonical_username.clone();
        let session_id = validated_session.record.session_id.clone();

        match self.backend.list_mailboxes(&canonical_username) {
            Ok(mailboxes) => MailboxListingOutcome {
                decision: MailboxListingDecision::Listed {
                    canonical_username: canonical_username.clone(),
                    session_id: session_id.clone(),
                    mailboxes: mailboxes.clone(),
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "mailbox_listed",
                    "mailbox listing completed",
                )
                .with_field("canonical_username", canonical_username)
                .with_field("session_id", session_id)
                .with_field("mailbox_count", mailboxes.len().to_string())
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => MailboxListingOutcome {
                decision: MailboxListingDecision::Denied {
                    public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_mailbox_failure_event(
                    context,
                    &validated_session.record.canonical_username,
                    &validated_session.record.session_id,
                    &error,
                ),
            },
        }
    }
}

/// Lists mailboxes through `doveadm mailbox list`.
pub struct DoveadmMailboxListBackend<E> {
    policy: MailboxListingPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
}

impl<E> DoveadmMailboxListBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MailboxListingPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
        }
    }
}

impl Default for DoveadmMailboxListBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MailboxListingPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MailboxBackend for DoveadmMailboxListBackend<E>
where
    E: CommandExecutor,
{
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        let args = vec![
            "mailbox".to_string(),
            "list".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
        ];

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-mailbox-list",
                reason: error.reason,
            })?;

        parse_doveadm_mailbox_list_output(self.policy, &execution)
    }
}

/// Builds a bounded failure event for mailbox-listing problems.
fn build_mailbox_failure_event(
    context: &AuthenticationContext,
    canonical_username: &str,
    session_id: &str,
    error: &MailboxBackendError,
) -> LogEvent {
    let audit_reason = if error.backend == "mailbox-parser" {
        MailboxAuditFailureReason::OutputRejected
    } else {
        MailboxAuditFailureReason::BackendUnavailable
    };

    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "mailbox_list_failed",
        "mailbox listing failed",
    )
    .with_field("canonical_username", canonical_username.to_string())
    .with_field("session_id", session_id.to_string())
    .with_field(
        "public_reason",
        MailboxPublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("backend", error.backend)
    .with_field("backend_reason", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Parses the output of `doveadm mailbox list` into bounded mailbox entries.
fn parse_doveadm_mailbox_list_output(
    policy: MailboxListingPolicy,
    execution: &CommandExecution,
) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
    if execution.status_code != 0 {
        return Err(MailboxBackendError {
            backend: "doveadm-mailbox-list",
            reason: format!(
                "command exited with status {}: {}",
                execution.status_code,
                concise_command_diagnostics(&execution.stdout, &execution.stderr),
            ),
        });
    }

    let mut mailboxes = Vec::new();

    for raw_line in execution.stdout.lines() {
        if raw_line.is_empty() {
            continue;
        }

        mailboxes.push(MailboxEntry::new(policy, raw_line.to_string())?);
        if mailboxes.len() > policy.max_mailboxes {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: format!(
                    "mailbox listing exceeded maximum of {} entries",
                    policy.max_mailboxes
                ),
            });
        }
    }

    Ok(mailboxes)
}

/// Produces a compact single-line diagnostic from command output.
fn concise_command_diagnostics(stdout: &str, stderr: &str) -> String {
    let combined = format!("{} {}", stderr.trim(), stdout.trim()).trim().to_string();
    if combined.is_empty() {
        return "no command diagnostics returned".to_string();
    }

    combined
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthenticationDecision, AuthenticationPolicy, AuthenticationService, CommandExecutionError,
        PrimaryAuthBackendError, PrimaryAuthVerdict, PrimaryCredentialBackend,
        RequiredSecondFactor, SecondFactorService,
    };
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use crate::session::{
        FileSessionStore, RandomSource, SessionError, SessionService, SESSION_TOKEN_BYTES,
    };
    use crate::totp::{FileTotpSecretStore, TimeProvider, TotpPolicy, TotpVerifier};
    use std::cell::Cell;
    use std::fs;
    use std::path::Path;
    use std::rc::Rc;

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

    #[derive(Debug, Clone)]
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

    #[derive(Debug, Clone)]
    struct StubCommandExecutor {
        execution: Result<CommandExecution, CommandExecutionError>,
        program: Option<String>,
        args: Option<Vec<String>>,
    }

    impl StubCommandExecutor {
        fn success(execution: CommandExecution) -> Self {
            Self {
                execution: Ok(execution),
                program: None,
                args: None,
            }
        }
    }

    impl CommandExecutor for Rc<std::cell::RefCell<StubCommandExecutor>> {
        fn run_with_stdin(
            &self,
            program: &str,
            args: &[String],
            _stdin_data: &str,
        ) -> Result<CommandExecution, CommandExecutionError> {
            let mut state = self.borrow_mut();
            state.program = Some(program.to_string());
            state.args = Some(args.to_vec());
            state.execution.clone()
        }
    }

    struct FailingMailboxBackend;

    impl MailboxBackend for FailingMailboxBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-mailbox-backend",
                reason: "imap bridge unavailable".to_string(),
            })
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-mailbox",
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
    fn parses_mailbox_entries_from_doveadm_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "INBOX\nSent\nDrafts\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );

        let mailboxes = backend
            .list_mailboxes("alice@example.com")
            .expect("mailbox list should succeed");

        assert_eq!(
            mailboxes,
            vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent".to_string(),
                },
                MailboxEntry {
                    name: "Drafts".to_string(),
                },
            ]
        );

        let recorded = executor.borrow();
        assert_eq!(
            recorded.program.as_deref(),
            Some("/usr/local/bin/doveadm")
        );
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "mailbox".to_string(),
                "list".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_control_characters_in_mailbox_output() {
        let error = parse_doveadm_mailbox_list_output(
            MailboxListingPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "INBOX\nSent\u{0007}\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("control characters must fail");

        assert_eq!(error.backend, "mailbox-parser");
        assert_eq!(error.reason, "mailbox name contains control characters");
    }

    #[test]
    fn mailbox_service_emits_audit_quality_success_events() {
        let service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Archive".to_string(),
                },
            ],
        });
        let validated_session = validated_session_fixture();

        let outcome = service.list_for_validated_session(&test_context(), &validated_session);

        assert_eq!(
            outcome.decision,
            MailboxListingDecision::Listed {
                canonical_username: "alice@example.com".to_string(),
                session_id: validated_session.record.session_id.clone(),
                mailboxes: vec![
                    MailboxEntry {
                        name: "INBOX".to_string(),
                    },
                    MailboxEntry {
                        name: "Archive".to_string(),
                    },
                ],
            }
        );
        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "mailbox_listed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 4242);
        assert_eq!(
            rendered,
            format!(
                "ts=4242 level=info category=mailbox action=mailbox_listed msg=\"mailbox listing completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn mailbox_service_translates_backend_failures_into_bounded_events() {
        let service = MailboxListingService::new(FailingMailboxBackend);
        let validated_session = validated_session_fixture();

        let outcome = service.list_for_validated_session(&test_context(), &validated_session);

        assert_eq!(
            outcome.decision,
            MailboxListingDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "mailbox_list_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn full_auth_session_and_mailbox_flow_succeeds() {
        let secret_dir = temp_dir("osmap-mailbox-secret");
        let session_dir = temp_dir("osmap-mailbox-session");
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
                bytes: vec![0x88; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(&test_context(), &canonical_username, RequiredSecondFactor::Totp)
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent".to_string(),
                },
            ],
        });
        let outcome = service.list_for_validated_session(&test_context(), &validated);

        match outcome.decision {
            MailboxListingDecision::Listed {
                canonical_username,
                session_id,
                mailboxes,
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(session_id, validated.record.session_id);
                assert_eq!(mailboxes.len(), 2);
                assert_eq!(mailboxes[0].name, "INBOX");
            }
            other => panic!("expected mailbox listing, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_mailbox_list_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMailboxListBackend::default();
        let error = backend
            .list_mailboxes("osmap-no-such-user@example.invalid")
            .expect_err("missing users should not produce mailbox listings");

        assert_eq!(error.backend, "doveadm-mailbox-list");
        assert!(error.reason.contains("status 67"));
    }

    #[derive(Debug, Clone)]
    struct StaticMailboxBackend {
        mailboxes: Vec<MailboxEntry>,
    }

    impl MailboxBackend for StaticMailboxBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Ok(self.mailboxes.clone())
        }
    }

    fn validated_session_fixture() -> ValidatedSession {
        ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef01234567".to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }
}
