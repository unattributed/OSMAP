//! Outbound compose and submission support for the first OSMAP send slice.
//!
//! This module keeps the first send path intentionally narrow:
//! - validate a small compose shape
//! - hand the message to the local submission surface
//! - emit audit-quality submission events
//! - avoid inventing a new SMTP client stack inside the browser runtime

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::auth::{AuthenticationContext, CommandExecutor, SystemCommandExecutor};
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::mime::AttachmentMetadata;
use crate::rendering::RenderedMessageView;
use crate::session::ValidatedSession;

/// Conservative upper bound for one recipient address.
pub const DEFAULT_RECIPIENT_MAX_LEN: usize = 320;

/// Conservative upper bound for the number of recipients in one composed message.
pub const DEFAULT_MAX_RECIPIENTS: usize = 16;

/// Conservative upper bound for one subject line.
pub const DEFAULT_SUBJECT_MAX_LEN: usize = 998;

/// Conservative upper bound for one composed message body.
pub const DEFAULT_BODY_MAX_LEN: usize = 65_536;

/// Conservative upper bound for the number of uploaded attachments.
pub const DEFAULT_MAX_ATTACHMENTS: usize = 3;

/// Conservative upper bound for one uploaded attachment body.
pub const DEFAULT_ATTACHMENT_MAX_BYTES: usize = 256 * 1024;

/// Conservative upper bound for total uploaded attachment bytes.
pub const DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES: usize = 768 * 1024;

/// Conservative upper bound for one uploaded attachment file name.
pub const DEFAULT_ATTACHMENT_FILENAME_MAX_LEN: usize = 128;

/// Conservative upper bound for one uploaded attachment content type.
pub const DEFAULT_ATTACHMENT_CONTENT_TYPE_MAX_LEN: usize = 128;

/// Conservative upper bound for one automatically generated compose notice.
pub const DEFAULT_COMPOSE_NOTICE_MAX_LEN: usize = 512;

/// Policy controlling the first compose-and-send slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComposePolicy {
    pub recipient_max_len: usize,
    pub max_recipients: usize,
    pub subject_max_len: usize,
    pub body_max_len: usize,
    pub max_attachments: usize,
    pub attachment_max_bytes: usize,
    pub total_attachment_max_bytes: usize,
    pub attachment_filename_max_len: usize,
    pub attachment_content_type_max_len: usize,
    pub compose_notice_max_len: usize,
}

impl Default for ComposePolicy {
    fn default() -> Self {
        Self {
            recipient_max_len: DEFAULT_RECIPIENT_MAX_LEN,
            max_recipients: DEFAULT_MAX_RECIPIENTS,
            subject_max_len: DEFAULT_SUBJECT_MAX_LEN,
            body_max_len: DEFAULT_BODY_MAX_LEN,
            max_attachments: DEFAULT_MAX_ATTACHMENTS,
            attachment_max_bytes: DEFAULT_ATTACHMENT_MAX_BYTES,
            total_attachment_max_bytes: DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES,
            attachment_filename_max_len: DEFAULT_ATTACHMENT_FILENAME_MAX_LEN,
            attachment_content_type_max_len: DEFAULT_ATTACHMENT_CONTENT_TYPE_MAX_LEN,
            compose_notice_max_len: DEFAULT_COMPOSE_NOTICE_MAX_LEN,
        }
    }
}

/// The supported browser compose intents built from an existing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeIntent {
    Reply,
    Forward,
}

impl ComposeIntent {
    /// Returns the canonical string representation used in routes and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::Forward => "forward",
        }
    }
}

/// A bounded draft projection used to pre-fill the browser compose form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeDraft {
    pub intent: ComposeIntent,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub context_notice: Option<String>,
}

/// One uploaded attachment accepted by the current bounded compose slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedAttachment {
    pub filename: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl UploadedAttachment {
    /// Validates and stores one uploaded attachment for later submission.
    pub fn new(
        policy: ComposePolicy,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        body: Vec<u8>,
    ) -> Result<Self, ComposeError> {
        let filename = filename.into();
        let content_type = normalize_attachment_content_type(policy, &content_type.into())?;

        validate_attachment_filename(policy, &filename)?;
        validate_attachment_body(policy, &body)?;

        Ok(Self {
            filename,
            content_type,
            body,
        })
    }

    /// Returns the current attachment payload size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.body.len()
    }
}

/// A bounded compose request for the current outbound message slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeRequest {
    pub recipients: Vec<String>,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<UploadedAttachment>,
}

impl ComposeRequest {
    /// Validates the first compose shape before it reaches submission.
    pub fn new(
        policy: ComposePolicy,
        recipients_text: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Result<Self, ComposeError> {
        Self::new_with_attachments(policy, recipients_text, subject, body, Vec::new())
    }

    /// Validates the compose request plus uploaded attachments.
    pub fn new_with_attachments(
        policy: ComposePolicy,
        recipients_text: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
        attachments: Vec<UploadedAttachment>,
    ) -> Result<Self, ComposeError> {
        let recipients_text = recipients_text.into();
        let subject = subject.into();
        let body = body.into();

        let recipients = parse_recipients(policy, &recipients_text)?;
        validate_subject(policy, &subject)?;
        validate_body(policy, &body)?;
        validate_attachment_set(policy, &attachments)?;

        Ok(Self {
            recipients,
            subject,
            body,
            attachments,
        })
    }
}

impl ComposeDraft {
    /// Builds a reply or forward draft from the currently rendered message.
    pub fn from_rendered_message(
        policy: ComposePolicy,
        intent: ComposeIntent,
        rendered: &RenderedMessageView,
    ) -> Result<Self, ComposeError> {
        let attachment_notice = build_attachment_notice(policy, intent, &rendered.attachments)?;

        let (to, subject, body, note) = match intent {
            ComposeIntent::Reply => {
                build_reply_draft(policy, rendered, attachment_notice.as_deref())?
            }
            ComposeIntent::Forward => {
                build_forward_draft(policy, rendered, attachment_notice.as_deref())?
            }
        };

        Ok(Self {
            intent,
            to,
            subject,
            body,
            context_notice: note.or(attachment_notice),
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
        let submission_message = build_submission_message(canonical_username, request);
        let execution = self
            .command_executor
            .run_with_stdin_bytes(
                self.sendmail_path.to_string_lossy().as_ref(),
                &[
                    "-t".to_string(),
                    "-oi".to_string(),
                    "-f".to_string(),
                    canonical_username.to_string(),
                ],
                &submission_message,
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
                .with_field("attachment_count", request.attachments.len().to_string())
                .with_field(
                    "attachment_bytes_total",
                    total_attachment_bytes(&request.attachments).to_string(),
                )
                .with_field(
                    "has_subject",
                    if request.subject.is_empty() {
                        "false"
                    } else {
                        "true"
                    },
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
                .with_field("attachment_count", request.attachments.len().to_string())
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
fn parse_recipients(
    policy: ComposePolicy,
    recipients_text: &str,
) -> Result<Vec<String>, ComposeError> {
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

    if subject.chars().any(|ch| ch.is_control() && ch != '\t') {
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

/// Validates the current uploaded attachment set as one bounded group.
fn validate_attachment_set(
    policy: ComposePolicy,
    attachments: &[UploadedAttachment],
) -> Result<(), ComposeError> {
    if attachments.len() > policy.max_attachments {
        return Err(ComposeError {
            reason: format!(
                "attachment count exceeded maximum of {}",
                policy.max_attachments
            ),
        });
    }

    let total_bytes = total_attachment_bytes(attachments);
    if total_bytes > policy.total_attachment_max_bytes {
        return Err(ComposeError {
            reason: format!(
                "attachment bytes exceeded maximum of {}",
                policy.total_attachment_max_bytes
            ),
        });
    }

    Ok(())
}

/// Validates one uploaded attachment file name for header-safe transport.
fn validate_attachment_filename(policy: ComposePolicy, filename: &str) -> Result<(), ComposeError> {
    if filename.is_empty() {
        return Err(ComposeError {
            reason: "attachment filename must not be empty".to_string(),
        });
    }

    if filename.len() > policy.attachment_filename_max_len {
        return Err(ComposeError {
            reason: format!(
                "attachment filename exceeded maximum length of {} bytes",
                policy.attachment_filename_max_len
            ),
        });
    }

    if filename.chars().any(char::is_control) {
        return Err(ComposeError {
            reason: "attachment filename contained control characters".to_string(),
        });
    }

    if filename.contains('/') || filename.contains('\\') {
        return Err(ComposeError {
            reason: "attachment filename must not contain path separators".to_string(),
        });
    }

    if !filename.chars().all(is_allowed_attachment_filename_char) {
        return Err(ComposeError {
            reason: "attachment filename contained unsupported characters".to_string(),
        });
    }

    Ok(())
}

/// Validates one uploaded attachment body against the configured byte budget.
fn validate_attachment_body(policy: ComposePolicy, body: &[u8]) -> Result<(), ComposeError> {
    if body.len() > policy.attachment_max_bytes {
        return Err(ComposeError {
            reason: format!(
                "attachment body exceeded maximum length of {} bytes",
                policy.attachment_max_bytes
            ),
        });
    }

    Ok(())
}

/// Normalizes and validates one uploaded attachment content type.
fn normalize_attachment_content_type(
    policy: ComposePolicy,
    content_type: &str,
) -> Result<String, ComposeError> {
    let trimmed = content_type.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok("application/octet-stream".to_string());
    }

    if trimmed.len() > policy.attachment_content_type_max_len {
        return Err(ComposeError {
            reason: format!(
                "attachment content type exceeded maximum length of {} bytes",
                policy.attachment_content_type_max_len
            ),
        });
    }

    let mut parts = trimmed.split('/');
    let top_level = parts.next().unwrap_or_default();
    let subtype = parts.next().unwrap_or_default();
    if top_level.is_empty()
        || subtype.is_empty()
        || parts.next().is_some()
        || !top_level.chars().all(is_allowed_content_type_token_char)
        || !subtype.chars().all(is_allowed_content_type_token_char)
    {
        return Ok("application/octet-stream".to_string());
    }

    Ok(trimmed)
}

/// Builds the first reply draft from a rendered message.
fn build_reply_draft(
    policy: ComposePolicy,
    rendered: &RenderedMessageView,
    attachment_notice: Option<&str>,
) -> Result<(String, String, String, Option<String>), ComposeError> {
    let reply_target = extract_reply_recipient(policy, rendered.from.as_deref())?;
    let subject = prefixed_subject(policy, rendered.subject.as_deref(), "Re: ")?;

    let mut body_lines = vec![String::new(), String::new()];
    if let Some(attachment_notice) = attachment_notice {
        body_lines.push(format!("[{attachment_notice}]"));
        body_lines.push(String::new());
    }

    body_lines.push(format!(
        "On {}, {} wrote:",
        rendered.date_received,
        rendered.from.as_deref().unwrap_or("the original sender")
    ));
    body_lines.extend(quote_plain_text(&rendered.body_text_for_compose));

    let body = bounded_generated_body(policy, &body_lines.join("\n"))?;
    let context_notice = if reply_target.is_empty() {
        Some(bounded_notice(
            policy,
            "Original From header could not be converted into a simple reply target; fill the recipient manually.",
        )?)
    } else {
        None
    };

    Ok((reply_target, subject, body, context_notice))
}

/// Builds the first forward draft from a rendered message.
fn build_forward_draft(
    policy: ComposePolicy,
    rendered: &RenderedMessageView,
    attachment_notice: Option<&str>,
) -> Result<(String, String, String, Option<String>), ComposeError> {
    let subject = prefixed_subject(policy, rendered.subject.as_deref(), "Fwd: ")?;

    let mut body_lines = vec![
        String::new(),
        String::new(),
        "---------- Forwarded message ----------".to_string(),
        format!("From: {}", rendered.from.as_deref().unwrap_or("<unknown>")),
        format!("Date: {}", rendered.date_received),
        format!(
            "Subject: {}",
            rendered.subject.as_deref().unwrap_or("<none>")
        ),
        format!("Mailbox: {}", rendered.mailbox_name),
        format!("UID: {}", rendered.uid),
    ];

    if rendered.attachments.is_empty() {
        body_lines.push("Attachments: none surfaced by the current message policy".to_string());
    } else {
        body_lines.push("Attachments:".to_string());
        for attachment in &rendered.attachments {
            body_lines.push(format!("- {}", describe_attachment_for_forward(attachment)));
        }
    }

    body_lines.push(String::new());
    body_lines.push(rendered.body_text_for_compose.clone());

    let body = bounded_generated_body(policy, &body_lines.join("\n"))?;
    let context_notice = attachment_notice
        .map(|notice| bounded_notice(policy, notice))
        .transpose()?;

    Ok((String::new(), subject, body, context_notice))
}

/// Builds the operator-safe notice shown when attachments exist on the source
/// message but the current send slice does not resend them.
fn build_attachment_notice(
    policy: ComposePolicy,
    intent: ComposeIntent,
    attachments: &[AttachmentMetadata],
) -> Result<Option<String>, ComposeError> {
    if attachments.is_empty() {
        return Ok(None);
    }

    let notice = match intent {
        ComposeIntent::Reply => format!(
            "Original message included {} attachment(s); the current reply slice does not resend attachments automatically.",
            attachments.len()
        ),
        ComposeIntent::Forward => format!(
            "Original message included {} attachment(s); the current forward slice preserves attachment metadata in the draft but does not reattach files yet.",
            attachments.len()
        ),
    };

    Ok(Some(bounded_notice(policy, &notice)?))
}

/// Bounds one generated notice string before it reaches the browser form.
fn bounded_notice(policy: ComposePolicy, notice: &str) -> Result<String, ComposeError> {
    if notice.len() > policy.compose_notice_max_len {
        return Err(ComposeError {
            reason: format!(
                "generated compose notice exceeded maximum length of {} bytes",
                policy.compose_notice_max_len
            ),
        });
    }

    Ok(notice.to_string())
}

/// Normalizes and bounds one generated body before it reaches the browser form.
fn bounded_generated_body(policy: ComposePolicy, body: &str) -> Result<String, ComposeError> {
    let mut body = body.trim_end_matches('\n').to_string();
    if body.len() > policy.body_max_len {
        // The current draft builder trims oversized quoted content rather than
        // rejecting reply/forward behavior for a long source message.
        body.truncate(policy.body_max_len.saturating_sub(32));
        body.push_str("\n[quoted content truncated]");
    }

    validate_body(policy, &body)?;
    Ok(body)
}

/// Builds a reply or forward subject line without stacking duplicate prefixes.
fn prefixed_subject(
    policy: ComposePolicy,
    subject: Option<&str>,
    prefix: &str,
) -> Result<String, ComposeError> {
    let subject = subject.unwrap_or("<no subject>").trim();
    let prefixed = if subject
        .to_ascii_lowercase()
        .starts_with(&prefix.trim_end().to_ascii_lowercase())
    {
        subject.to_string()
    } else {
        format!("{prefix}{subject}")
    };

    validate_subject(policy, &prefixed)?;
    Ok(prefixed)
}

/// Extracts a conservative simple reply target from the rendered `From` value.
fn extract_reply_recipient(
    policy: ComposePolicy,
    from_header: Option<&str>,
) -> Result<String, ComposeError> {
    let Some(from_header) = from_header.map(str::trim) else {
        return Ok(String::new());
    };

    if let Some((_, address_and_rest)) = from_header.rsplit_once('<') {
        if let Some((address, _)) = address_and_rest.split_once('>') {
            let address = address.trim();
            validate_recipient(policy, address)?;
            return Ok(address.to_string());
        }
    }

    if validate_recipient(policy, from_header).is_ok() {
        return Ok(from_header.to_string());
    }

    Ok(String::new())
}

/// Quotes one plain-text body block for reply composition.
fn quote_plain_text(body_text: &str) -> Vec<String> {
    if body_text.is_empty() {
        return vec![">".to_string()];
    }

    body_text.lines().map(|line| format!("> {line}")).collect()
}

/// Describes one surfaced attachment for the current forward draft.
fn describe_attachment_for_forward(attachment: &AttachmentMetadata) -> String {
    format!(
        "{} ({}, {}, {} bytes, part {})",
        attachment.filename.as_deref().unwrap_or("<unnamed>"),
        attachment.content_type,
        attachment.disposition.as_str(),
        attachment.size_hint_bytes,
        attachment.part_path,
    )
}

/// Builds the RFC 5322-ish message handed to the local sendmail surface.
fn build_submission_message(canonical_username: &str, request: &ComposeRequest) -> Vec<u8> {
    if request.attachments.is_empty() {
        return build_plain_text_submission_message(canonical_username, request).into_bytes();
    }

    build_multipart_submission_message(canonical_username, request).into_bytes()
}

/// Builds the plain-text-only message handed to the local sendmail surface.
fn build_plain_text_submission_message(
    canonical_username: &str,
    request: &ComposeRequest,
) -> String {
    let body = normalize_body_line_endings(&request.body);
    format!(
        "From: {canonical_username}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
        request.recipients.join(", "),
        request.subject,
        body,
    )
}

/// Builds the multipart/mixed submission body for attachment-bearing requests.
fn build_multipart_submission_message(
    canonical_username: &str,
    request: &ComposeRequest,
) -> String {
    let boundary = build_multipart_boundary(canonical_username, request);
    let mut output = String::new();
    output.push_str(&format!(
        "From: {canonical_username}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n",
        request.recipients.join(", "),
        request.subject,
        boundary,
    ));
    output.push_str(&format!(
        "--{}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}\r\n",
        boundary,
        normalize_body_line_endings(&request.body),
    ));

    for attachment in &request.attachments {
        output.push_str(&format!(
            "--{}\r\nContent-Type: {}; name=\"{}\"\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            boundary,
            attachment.content_type,
            escape_mime_parameter_value(&attachment.filename),
            escape_mime_parameter_value(&attachment.filename),
            base64_encode_wrapped(&attachment.body),
        ));
    }

    output.push_str(&format!("--{}--\r\n", boundary));
    output
}

/// Normalizes the body to CRLF so the submission surface sees stable text.
fn normalize_body_line_endings(body: &str) -> String {
    body.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

/// Builds a deterministic multipart boundary from the current submission.
///
/// The boundary is long and derived from the current message shape so it is
/// unlikely to collide with ordinary message content while staying reviewable.
fn build_multipart_boundary(canonical_username: &str, request: &ComposeRequest) -> String {
    let mut digest = Sha256::new();
    digest.update(canonical_username.as_bytes());
    digest.update(b"\0");
    for recipient in &request.recipients {
        digest.update(recipient.as_bytes());
        digest.update(b"\0");
    }
    digest.update(request.subject.as_bytes());
    digest.update(b"\0");
    digest.update(request.body.as_bytes());
    digest.update(b"\0");
    for attachment in &request.attachments {
        digest.update(attachment.filename.as_bytes());
        digest.update(b"\0");
        digest.update(attachment.content_type.as_bytes());
        digest.update(b"\0");
        digest.update((attachment.body.len() as u64).to_be_bytes());
    }

    let digest = digest.finalize();
    format!("osmap-mixed-{}", hex_encode(&digest[..12]))
}

/// Escapes a MIME parameter value for quoted-string transport.
fn escape_mime_parameter_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\"', "\\\"")
}

/// Encodes one attachment body as MIME base64 wrapped at 76 characters.
fn base64_encode_wrapped(bytes: &[u8]) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    let mut line_len = 0;

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let indices = [
            (b0 >> 2) as usize,
            (((b0 & 0x03) << 4) | (b1 >> 4)) as usize,
            (((b1 & 0x0f) << 2) | (b2 >> 6)) as usize,
            (b2 & 0x3f) as usize,
        ];

        let padding = 3 - chunk.len();
        for (index, value) in indices.into_iter().enumerate() {
            if line_len == 76 {
                output.push_str("\r\n");
                line_len = 0;
            }

            if index >= 4 - padding {
                output.push('=');
            } else {
                output.push(BASE64[value] as char);
            }
            line_len += 1;
        }
    }

    output
}

/// Returns the total attachment size for the current request.
fn total_attachment_bytes(attachments: &[UploadedAttachment]) -> usize {
    attachments.iter().map(UploadedAttachment::size_bytes).sum()
}

/// Encodes bytes as lower-case hex for stable MIME boundary construction.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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

/// Allowed characters for the current narrow uploaded-attachment file names.
fn is_allowed_attachment_filename_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+' | ' ' | '(' | ')')
}

/// Allowed token characters for a narrow MIME content type parser.
fn is_allowed_content_type_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '!' | '#' | '$' | '&' | '^' | '_' | '.' | '+' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthenticationPolicy, CommandExecution, CommandExecutionError};
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use crate::mime::{AttachmentDisposition, MimeBodySource};
    use crate::session::SessionRecord;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Debug, Clone)]
    struct StubCommandExecutor {
        execution: Result<CommandExecution, CommandExecutionError>,
        program: Option<String>,
        args: Option<Vec<String>>,
        stdin_data: Option<Vec<u8>>,
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
        fn run_with_stdin_bytes(
            &self,
            program: &str,
            args: &[String],
            stdin_data: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            let mut state = self.borrow_mut();
            state.program = Some(program.to_string());
            state.args = Some(args.to_vec());
            state.stdin_data = Some(stdin_data.to_vec());
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
                session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: crate::auth::RequiredSecondFactor::Totp,
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }

    fn rendered_message_fixture() -> RenderedMessageView {
        RenderedMessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 42,
            subject: Some("Quarterly report".to_string()),
            from: Some("Alice Example <alice@example.com>".to_string()),
            date_received: "2026-03-27 12:00:00 +0000".to_string(),
            mime_top_level_content_type: "multipart/mixed".to_string(),
            body_source: MimeBodySource::MultipartPlainTextPart,
            contains_html_body: true,
            body_html: "<pre>Hello team</pre>".to_string(),
            body_text_for_compose: "Hello team\nPlease review the report.".to_string(),
            attachments: vec![AttachmentMetadata {
                part_path: "1.2".to_string(),
                filename: Some("report.pdf".to_string()),
                content_type: "application/pdf".to_string(),
                disposition: AttachmentDisposition::Attachment,
                content_id: None,
                size_hint_bytes: 4096,
            }],
            rendering_mode: crate::rendering::RenderingMode::PlainTextPreformatted,
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
            vec![
                "bob@example.com".to_string(),
                "carol@example.net".to_string()
            ]
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
    fn accepts_bounded_uploaded_attachments() {
        let request = ComposeRequest::new_with_attachments(
            ComposePolicy::default(),
            "bob@example.com",
            "Quarterly report",
            "Hello world",
            vec![UploadedAttachment::new(
                ComposePolicy::default(),
                "report.txt",
                "text/plain",
                b"quarterly report body".to_vec(),
            )
            .expect("attachment should be valid")],
        )
        .expect("compose request with attachment should parse");

        assert_eq!(request.attachments.len(), 1);
        assert_eq!(request.attachments[0].filename, "report.txt");
        assert_eq!(request.attachments[0].content_type, "text/plain");
    }

    #[test]
    fn rejects_attachment_filenames_with_path_separators() {
        let error = UploadedAttachment::new(
            ComposePolicy::default(),
            "../report.txt",
            "text/plain",
            b"report".to_vec(),
        )
        .expect_err("path-like attachment names must fail");

        assert_eq!(
            error,
            ComposeError {
                reason: "attachment filename must not contain path separators".to_string(),
            }
        );
    }

    #[test]
    fn builds_reply_draft_from_rendered_message() {
        let draft = ComposeDraft::from_rendered_message(
            ComposePolicy::default(),
            ComposeIntent::Reply,
            &rendered_message_fixture(),
        )
        .expect("reply draft should be built");

        assert_eq!(draft.to, "alice@example.com");
        assert_eq!(draft.subject, "Re: Quarterly report");
        assert!(draft.body.contains("On 2026-03-27 12:00:00 +0000"));
        assert!(draft.body.contains("> Hello team"));
        assert!(draft
            .context_notice
            .as_deref()
            .unwrap_or_default()
            .contains("does not resend attachments automatically"));
    }

    #[test]
    fn builds_forward_draft_with_attachment_summary() {
        let draft = ComposeDraft::from_rendered_message(
            ComposePolicy::default(),
            ComposeIntent::Forward,
            &rendered_message_fixture(),
        )
        .expect("forward draft should be built");

        assert_eq!(draft.to, "");
        assert_eq!(draft.subject, "Fwd: Quarterly report");
        assert!(draft
            .body
            .contains("---------- Forwarded message ----------"));
        assert!(draft.body.contains("report.pdf"));
        assert!(draft.body.contains("part 1.2"));
        assert!(draft
            .context_notice
            .as_deref()
            .unwrap_or_default()
            .contains("does not reattach files yet"));
    }

    #[test]
    fn sendmail_backend_uses_local_submission_surface() {
        let executor = Rc::new(RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        )));
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
            .as_ref()
            .expect("stdin data should be captured");
        let stdin_text =
            String::from_utf8(stdin_data.clone()).expect("plain-text submission should be utf-8");
        assert!(stdin_text.contains("From: alice@example.com\r\n"));
        assert!(stdin_text.contains("To: bob@example.com\r\n"));
        assert!(stdin_text.contains("Subject: Test message\r\n"));
        assert!(stdin_text.ends_with("Hello world\r\nSecond line\r\n"));
    }

    #[test]
    fn sendmail_backend_builds_multipart_message_for_uploaded_attachments() {
        let executor = Rc::new(RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        )));
        let backend = SendmailSubmissionBackend::new(executor.clone(), "/usr/sbin/sendmail");
        let request = ComposeRequest::new_with_attachments(
            ComposePolicy::default(),
            "bob@example.com",
            "Test attachment message",
            "See attached report.",
            vec![UploadedAttachment::new(
                ComposePolicy::default(),
                "report.bin",
                "application/octet-stream",
                vec![0x00, 0xff, 0x10, 0x41],
            )
            .expect("attachment should be valid")],
        )
        .expect("request should be valid");

        backend
            .submit_message("alice@example.com", &request)
            .expect("multipart submission should succeed");

        let stdin_data = executor
            .borrow()
            .stdin_data
            .clone()
            .expect("stdin data should be captured");
        let stdin_text = String::from_utf8(stdin_data).expect("multipart body should be utf-8");

        assert!(stdin_text.contains("Content-Type: multipart/mixed; boundary=\"osmap-mixed-"));
        assert!(stdin_text.contains("filename=\"report.bin\""));
        assert!(stdin_text.contains("Content-Transfer-Encoding: base64"));
        assert!(stdin_text.contains("AP8QQQ=="));
    }

    #[test]
    fn submission_service_emits_audit_quality_success_events() {
        let executor = Rc::new(RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        )));
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
            "ts=8080 level=info category=submission action=message_submitted msg=\"outbound message submission completed\" canonical_username=\"alice@example.com\" session_id=\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" recipient_count=\"1\" attachment_count=\"0\" attachment_bytes_total=\"0\" has_subject=\"true\" request_id=\"req-send\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
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
