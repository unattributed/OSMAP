//! Outbound compose and submission support for the first OSMAP send slice.
//!
//! This module keeps the first send path intentionally narrow:
//! - validate a small compose shape
//! - hand the message to the local submission surface
//! - emit audit-quality submission events
//! - avoid inventing a new SMTP client stack inside the browser runtime

use std::path::PathBuf;

use crate::auth::{
    AuthenticationContext, CommandExecutor, SystemCommandExecutor,
};
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::session::ValidatedSession;

/// Conservative upper bound for one recipient address.
pub const DEFAULT_RECIPIENT_MAX_LEN: usize = 320;

/// Conservative upper bound for the number of recipients in one composed message.
pub const DEFAULT_MAX_RECIPIENTS: usize = 16;

/// Conservative upper bound for one subject line.
pub const DEFAULT_SUBJECT_MAX_LEN: usize = 998;

/// Conservative upper bound for one composed message body.
pub const DEFAULT_BODY_MAX_LEN: usize = 65_536;

/// Policy controlling the first compose-and-send slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComposePolicy {
    pub recipient_max_len: usize,
    pub max_recipients: usize,
    pub subject_max_len: usize,
    pub body_max_len: usize,
}

impl Default for ComposePolicy {
    fn default() -> Self {
        Self {
            recipient_max_len: DEFAULT_RECIPIENT_MAX_LEN,
            max_recipients: DEFAULT_MAX_RECIPIENTS,
            subject_max_len: DEFAULT_SUBJECT_MAX_LEN,
            body_max_len: DEFAULT_BODY_MAX_LEN,
        }
    }
}

/// A bounded compose request for the current outbound message slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeRequest {
    pub recipients: Vec<String>,
    pub subject: String,
    pub body: String,
}

impl ComposeRequest {
    /// Validates the first compose shape before it reaches submission.
    pub fn new(
        policy: ComposePolicy,
        recipients_text: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self, ComposeError> {
        let recipients_text = recipients_text.into();
        let subject = subject.into();
        let body = body.into();

        let recipients = parse_recipients(policy, &recipients_text)?;
        validate_subject(policy, &subject)?;
        validate_body(policy, &body)?;

        Ok(Self {
            recipients,
            subject,
            body,
        })
    }
}

/// Errors raised while validating compose input or talking to submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeError {
    pub reason: String,
}

/// User-facing compose/send failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionPublicFailureReason {
    InvalidRequest,
    TemporarilyUnavailable,
}

impl SubmissionPublicFailureReason {
    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Audit-only compose/send failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionAuditFailureReason {
    InputRejected,
    BackendUnavailable,
}

impl SubmissionAuditFailureReason {
    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InputRejected => "input_rejected",
            Self::BackendUnavailable => "backend_unavailable",
        }
    }
}

/// The send decision visible to later browser and operator code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionDecision {
    Submitted {
        canonical_username: String,
        recipients: Vec<String>,
    },
    Denied {
        public_reason: SubmissionPublicFailureReason,
    },
}

/// The decision plus audit event emitted by the submission layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionOutcome {
    pub decision: SubmissionDecision,
    pub audit_event: LogEvent,
}

/// Errors raised by the submission backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionBackendError {
    pub backend: &'static str,
    pub reason: String,
}

/// A backend capable of handing one composed message to the existing mail path.
pub trait SubmissionBackend {
    fn submit_message(
        &self,
        canonical_username: &str,
        request: &ComposeRequest,
    ) -> Result<(), SubmissionBackendError>;
}

/// Submits composed messages through the local `sendmail` compatibility surface.
pub struct SendmailSubmissionBackend<E> {
    command_executor: E,
    sendmail_path: PathBuf,
}

impl<E> SendmailSubmissionBackend<E> {
    /// Builds a backend using the supplied command executor and sendmail path.
    pub fn new(command_executor: E, sendmail_path: impl Into<PathBuf>) -> Self {
        Self {
            command_executor,
            sendmail_path: sendmail_path.into(),
        }
    }
}

impl Default for SendmailSubmissionBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, "/usr/sbin/sendmail")
    }
}

impl<E> SubmissionBackend for SendmailSubmissionBackend<E>
where
    E: CommandExecutor,
{
    fn submit_message(
        &self,
        canonical_username: &str,
        request: &ComposeRequest,
    ) -> Result<(), SubmissionBackendError> {
        let execution = self
            .command_executor
            .run_with_stdin(
                self.sendmail_path.to_string_lossy().as_ref(),
                &[
                    "-t".to_string(),
                    "-oi".to_string(),
                    "-f".to_string(),
                    canonical_username.to_string(),
                ],
                &build_submission_message(canonical_username, request),
            )
            .map_err(|error| SubmissionBackendError {
                backend: "sendmail-submission",
                reason: error.reason,
            })?;

        if execution.status_code != 0 {
            return Err(SubmissionBackendError {
                backend: "sendmail-submission",
                reason: format!(
                    "sendmail exited with status {}: {}",
                    execution.status_code,
                    execution.stderr.trim()
                ),
            });
        }

        Ok(())
    }
}

/// Submits composed messages for an already validated browser session.
pub struct SubmissionService<B> {
    backend: B,
}

impl<B> SubmissionService<B>
where
    B: SubmissionBackend,
{
    /// Creates a submission service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Submits the composed message for the validated session owner.
    pub fn submit_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &ComposeRequest,
    ) -> SubmissionOutcome {
        match self
            .backend
            .submit_message(&validated_session.record.canonical_username, request)
        {
            Ok(()) => SubmissionOutcome {
                decision: SubmissionDecision::Submitted {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    recipients: request.recipients.clone(),
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Submission,
                    "message_submitted",
                    "outbound message submission completed",
                )
                .with_field(
                    "canonical_username",
                    validated_session.record.canonical_username.clone(),
                )
                .with_field("session_id", validated_session.record.session_id.clone())
                .with_field("recipient_count", request.recipients.len().to_string())
                .with_field(
                    "has_subject",
                    if request.subject.is_empty() { "false" } else { "true" },
                )
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => SubmissionOutcome {
                decision: SubmissionDecision::Denied {
                    public_reason: SubmissionPublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: LogEvent::new(
                    LogLevel::Warn,
                    EventCategory::Submission,
                    "message_submit_failed",
                    "outbound message submission failed",
                )
                .with_field(
                    "canonical_username",
                    validated_session.record.canonical_username.clone(),
                )
                .with_field("session_id", validated_session.record.session_id.clone())
                .with_field(
                    "public_reason",
                    SubmissionPublicFailureReason::TemporarilyUnavailable.as_str(),
                )
                .with_field(
                    "audit_reason",
                    SubmissionAuditFailureReason::BackendUnavailable.as_str(),
                )
                .with_field("backend", error.backend)
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
        }
    }
}

/// Parses the recipient list into a bounded list of plain mailbox addresses.
fn parse_recipients(policy: ComposePolicy, recipients_text: &str) -> Result<Vec<String>, ComposeError> {
    let mut recipients = Vec::new();

    for raw_recipient in recipients_text.split(',') {
        let recipient = raw_recipient.trim();
        if recipient.is_empty() {
            continue;
        }

        if recipients.len() >= policy.max_recipients {
            return Err(ComposeError {
                reason: format!(
                    "recipient count exceeded maximum of {}",
                    policy.max_recipients
                ),
            });
        }

        validate_recipient(policy, recipient)?;
        recipients.push(recipient.to_string());
    }

    if recipients.is_empty() {
        return Err(ComposeError {
            reason: "at least one recipient is required".to_string(),
        });
    }

    Ok(recipients)
}

/// Validates one recipient address for the first narrow send slice.
fn validate_recipient(policy: ComposePolicy, recipient: &str) -> Result<(), ComposeError> {
    if recipient.len() > policy.recipient_max_len {
        return Err(ComposeError {
            reason: format!(
                "recipient exceeded maximum length of {} bytes",
                policy.recipient_max_len
            ),
        });
    }

    if recipient.chars().any(char::is_control) || recipient.contains(char::is_whitespace) {
        return Err(ComposeError {
            reason: "recipient contained control or whitespace characters".to_string(),
        });
    }

    let mut parts = recipient.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() {
        return Err(ComposeError {
            reason: "recipient must be a simple addr-spec style mailbox".to_string(),
        });
    }

    if !local.chars().all(is_allowed_email_local_char)
        || !domain.chars().all(is_allowed_email_domain_char)
        || !domain.contains('.')
    {
        return Err(ComposeError {
            reason: "recipient contained unsupported mailbox characters".to_string(),
        });
    }

    Ok(())
}

/// Validates the subject line against bounded header rules.
fn validate_subject(policy: ComposePolicy, subject: &str) -> Result<(), ComposeError> {
    if subject.len() > policy.subject_max_len {
        return Err(ComposeError {
            reason: format!(
                "subject exceeded maximum length of {} bytes",
                policy.subject_max_len
            ),
        });
    }

    if subject
        .chars()
        .any(|ch| ch.is_control() && ch != '\t')
    {
        return Err(ComposeError {
            reason: "subject contained control characters".to_string(),
        });
    }

    if subject.contains('\r') || subject.contains('\n') {
        return Err(ComposeError {
            reason: "subject must not contain line breaks".to_string(),
        });
    }

    Ok(())
}

/// Validates the body while allowing ordinary text formatting characters.
fn validate_body(policy: ComposePolicy, body: &str) -> Result<(), ComposeError> {
    if body.len() > policy.body_max_len {
        return Err(ComposeError {
            reason: format!(
                "body exceeded maximum length of {} bytes",
                policy.body_max_len
            ),
        });
    }

    if body
        .chars()
        .any(|ch| ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t')
    {
        return Err(ComposeError {
            reason: "body contained unsupported control characters".to_string(),
        });
    }

    Ok(())
}

/// Builds the RFC 5322-ish message handed to the local sendmail surface.
fn build_submission_message(canonical_username: &str, request: &ComposeRequest) -> String {
    let body = normalize_body_line_endings(&request.body);
    format!(
        "From: {canonical_username}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
        request.recipients.join(", "),
        request.subject,
        body,
    )
}

/// Normalizes the body to CRLF so the submission surface sees stable text.
fn normalize_body_line_endings(body: &str) -> String {
    body.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n")
}

/// Allowed characters for the local part in the current narrow mailbox parser.
fn is_allowed_email_local_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
                | '.'
        )
}

/// Allowed characters for the domain part in the current narrow mailbox parser.
fn is_allowed_email_domain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthenticationPolicy, CommandExecution, CommandExecutionError};
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use crate::session::SessionRecord;
    use std::cell::RefCell;
    use std::rc::Rc;

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

    impl CommandExecutor for Rc<RefCell<StubCommandExecutor>> {
        fn run_with_stdin(
            &self,
            program: &str,
            args: &[String],
            stdin_data: &str,
        ) -> Result<CommandExecution, CommandExecutionError> {
            let mut state = self.borrow_mut();
            state.program = Some(program.to_string());
            state.args = Some(args.to_vec());
            state.stdin_data = Some(stdin_data.to_string());
            state.execution.clone()
        }
    }

    #[derive(Debug, Clone)]
    struct FailingSubmissionBackend;

    impl SubmissionBackend for FailingSubmissionBackend {
        fn submit_message(
            &self,
            _canonical_username: &str,
            _request: &ComposeRequest,
        ) -> Result<(), SubmissionBackendError> {
            Err(SubmissionBackendError {
                backend: "test-submission-backend",
                reason: "submission unavailable".to_string(),
            })
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-send",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    fn validated_session_fixture() -> ValidatedSession {
        ValidatedSession {
            record: SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef01234567".to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: crate::auth::RequiredSecondFactor::Totp,
                csrf_token: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }

    #[test]
    fn accepts_simple_compose_requests() {
        let request = ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com, carol@example.net",
            "Test message",
            "Hello world\n",
        )
        .expect("compose request should parse");

        assert_eq!(
            request.recipients,
            vec!["bob@example.com".to_string(), "carol@example.net".to_string()]
        );
        assert_eq!(request.subject, "Test message");
    }

    #[test]
    fn rejects_invalid_recipient_shapes() {
        let error = ComposeRequest::new(
            ComposePolicy::default(),
            "Bob Example <bob@example.com>",
            "Test",
            "Hello",
        )
        .expect_err("display-name recipients are intentionally rejected");

        assert_eq!(
            error,
            ComposeError {
                reason: "recipient contained control or whitespace characters".to_string(),
            }
        );
    }

    #[test]
    fn rejects_subject_line_breaks() {
        let error = ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Bad\nSubject",
            "Hello",
        )
        .expect_err("subject line breaks must fail");

        assert_eq!(
            error,
            ComposeError {
                reason: "subject contained control characters".to_string(),
            }
        );
    }

    #[test]
    fn sendmail_backend_uses_local_submission_surface() {
        let executor = Rc::new(RefCell::new(StubCommandExecutor::success(CommandExecution {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })));
        let backend = SendmailSubmissionBackend::new(executor.clone(), "/usr/sbin/sendmail");
        let request = ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Test message",
            "Hello world\nSecond line\n",
        )
        .expect("request should be valid");

        backend
            .submit_message("alice@example.com", &request)
            .expect("submission should succeed");

        let recorded = executor.borrow();
        assert_eq!(recorded.program.as_deref(), Some("/usr/sbin/sendmail"));
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-t".to_string(),
                "-oi".to_string(),
                "-f".to_string(),
                "alice@example.com".to_string(),
            ]
        );
        let stdin_data = recorded
            .stdin_data
            .as_deref()
            .expect("stdin data should be captured");
        assert!(stdin_data.contains("From: alice@example.com\r\n"));
        assert!(stdin_data.contains("To: bob@example.com\r\n"));
        assert!(stdin_data.contains("Subject: Test message\r\n"));
        assert!(stdin_data.ends_with("Hello world\r\nSecond line\r\n"));
    }

    #[test]
    fn submission_service_emits_audit_quality_success_events() {
        let executor = Rc::new(RefCell::new(StubCommandExecutor::success(CommandExecution {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })));
        let service = SubmissionService::new(SendmailSubmissionBackend::new(
            executor,
            "/usr/sbin/sendmail",
        ));
        let request = ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Test message",
            "Hello world\n",
        )
        .expect("request should be valid");

        let outcome = service.submit_for_validated_session(
            &test_context(),
            &validated_session_fixture(),
            &request,
        );

        assert_eq!(outcome.audit_event.category, EventCategory::Submission);
        assert_eq!(outcome.audit_event.action, "message_submitted");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 8080);
        assert_eq!(
            rendered,
            "ts=8080 level=info category=submission action=message_submitted msg=\"outbound message submission completed\" canonical_username=\"alice@example.com\" session_id=\"0123456789abcdef0123456789abcdef01234567\" recipient_count=\"1\" has_subject=\"true\" request_id=\"req-send\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
        );
    }

    #[test]
    fn submission_service_translates_backend_failures() {
        let service = SubmissionService::new(FailingSubmissionBackend);
        let request = ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Test message",
            "Hello world\n",
        )
        .expect("request should be valid");

        let outcome = service.submit_for_validated_session(
            &test_context(),
            &validated_session_fixture(),
            &request,
        );

        assert_eq!(
            outcome.decision,
            SubmissionDecision::Denied {
                public_reason: SubmissionPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_submit_failed");
    }
}
