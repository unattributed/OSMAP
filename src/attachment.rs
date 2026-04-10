//! Bounded attachment download support for the browser runtime.
//!
//! This module keeps attachment retrieval narrower than a general MIME client:
//! - it consumes an already fetched bounded message view
//! - it resolves only a surfaced attachment part path
//! - it decodes only a small set of common transfer encodings
//! - it returns forced-download metadata for the HTTP layer

use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::mailbox::MessageView;
use crate::mime::{AttachmentPart, MimeAnalysisPolicy, MimeAnalyzer};
use crate::session::ValidatedSession;

/// Conservative upper bound for one attachment part-path selector.
pub const DEFAULT_ATTACHMENT_PART_PATH_MAX_LEN: usize = 32;

/// Conservative upper bound for one decoded attachment payload.
pub const DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES: usize = 256 * 1024;

/// Conservative upper bound for one response download file name.
pub const DEFAULT_ATTACHMENT_DOWNLOAD_FILENAME_MAX_LEN: usize = 128;

/// Conservative upper bound for one response content type.
pub const DEFAULT_ATTACHMENT_DOWNLOAD_CONTENT_TYPE_MAX_LEN: usize = 128;

/// Policy controlling the bounded attachment-download slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentDownloadPolicy {
    pub part_path_max_len: usize,
    pub download_max_bytes: usize,
    pub filename_max_len: usize,
    pub content_type_max_len: usize,
    pub mime_analysis_policy: MimeAnalysisPolicy,
}

impl Default for AttachmentDownloadPolicy {
    fn default() -> Self {
        Self {
            part_path_max_len: DEFAULT_ATTACHMENT_PART_PATH_MAX_LEN,
            download_max_bytes: DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES,
            filename_max_len: DEFAULT_ATTACHMENT_DOWNLOAD_FILENAME_MAX_LEN,
            content_type_max_len: DEFAULT_ATTACHMENT_DOWNLOAD_CONTENT_TYPE_MAX_LEN,
            mime_analysis_policy: MimeAnalysisPolicy::default(),
        }
    }
}

/// A validated attachment part selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentDownloadRequest {
    pub part_path: String,
}

impl AttachmentDownloadRequest {
    /// Validates the requested attachment part path.
    pub fn new(
        policy: AttachmentDownloadPolicy,
        part_path: impl Into<String>,
    ) -> Result<Self, AttachmentDownloadError> {
        let part_path = part_path.into();
        validate_part_path(policy, &part_path)?;
        Ok(Self { part_path })
    }
}

/// A bounded attachment payload prepared for the HTTP layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedAttachment {
    pub mailbox_name: String,
    pub uid: u64,
    pub part_path: String,
    pub filename: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Public failure reasons surfaced through the browser runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentDownloadPublicFailureReason {
    InvalidRequest,
    NotFound,
    TemporarilyUnavailable,
}

impl AttachmentDownloadPublicFailureReason {
    /// Returns the stable string representation used by docs and HTTP code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Audit-only failure reasons used to keep logs explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentDownloadAuditFailureReason {
    InvalidRequest,
    NotFound,
    OutputRejected,
    UnsupportedEncoding,
}

impl AttachmentDownloadAuditFailureReason {
    /// Returns the stable string representation used in audit output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
            Self::OutputRejected => "output_rejected",
            Self::UnsupportedEncoding => "unsupported_encoding",
        }
    }
}

/// Decision emitted by the attachment-download service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentDownloadDecision {
    Downloaded {
        canonical_username: String,
        session_id: String,
        attachment: DownloadedAttachment,
    },
    Denied {
        public_reason: AttachmentDownloadPublicFailureReason,
    },
}

/// The decision plus audit event emitted by the download service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentDownloadOutcome {
    pub decision: AttachmentDownloadDecision,
    pub audit_event: LogEvent,
}

/// Errors raised while validating or extracting one attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentDownloadFailureKind {
    InvalidRequest,
    NotFound,
    OutputRejected,
    UnsupportedEncoding,
}

/// Errors raised while validating or extracting one attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentDownloadError {
    pub kind: AttachmentDownloadFailureKind,
    pub reason: String,
}

impl AttachmentDownloadError {
    pub(crate) fn new(kind: AttachmentDownloadFailureKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: reason.into(),
        }
    }

    pub fn public_reason(&self) -> AttachmentDownloadPublicFailureReason {
        match self.kind {
            AttachmentDownloadFailureKind::InvalidRequest => {
                AttachmentDownloadPublicFailureReason::InvalidRequest
            }
            AttachmentDownloadFailureKind::NotFound => {
                AttachmentDownloadPublicFailureReason::NotFound
            }
            AttachmentDownloadFailureKind::OutputRejected
            | AttachmentDownloadFailureKind::UnsupportedEncoding => {
                AttachmentDownloadPublicFailureReason::TemporarilyUnavailable
            }
        }
    }

    pub fn audit_reason(&self) -> AttachmentDownloadAuditFailureReason {
        match self.kind {
            AttachmentDownloadFailureKind::InvalidRequest => {
                AttachmentDownloadAuditFailureReason::InvalidRequest
            }
            AttachmentDownloadFailureKind::NotFound => {
                AttachmentDownloadAuditFailureReason::NotFound
            }
            AttachmentDownloadFailureKind::OutputRejected => {
                AttachmentDownloadAuditFailureReason::OutputRejected
            }
            AttachmentDownloadFailureKind::UnsupportedEncoding => {
                AttachmentDownloadAuditFailureReason::UnsupportedEncoding
            }
        }
    }

    pub fn helper_backend_label(&self) -> &'static str {
        match self.kind {
            AttachmentDownloadFailureKind::InvalidRequest => "attachment-download-invalid-request",
            AttachmentDownloadFailureKind::NotFound => "attachment-download-not-found",
            AttachmentDownloadFailureKind::OutputRejected => "attachment-download-output-rejected",
            AttachmentDownloadFailureKind::UnsupportedEncoding => {
                "attachment-download-unsupported-encoding"
            }
        }
    }
}

/// Resolves surfaced attachment parts into bounded download payloads.
pub struct AttachmentDownloadService {
    policy: AttachmentDownloadPolicy,
}

impl AttachmentDownloadService {
    /// Creates an attachment-download service from the supplied policy.
    pub fn new(policy: AttachmentDownloadPolicy) -> Self {
        Self { policy }
    }

    pub fn download_from_message(
        &self,
        message: &MessageView,
        part_path: &str,
    ) -> Result<DownloadedAttachment, AttachmentDownloadError> {
        let request = AttachmentDownloadRequest::new(self.policy, part_path)?;

        let part = MimeAnalyzer::new(self.policy.mime_analysis_policy)
            .find_attachment_part(message, &request.part_path)
            .map_err(|error| {
                AttachmentDownloadError::new(
                    AttachmentDownloadFailureKind::OutputRejected,
                    error.reason,
                )
            })?
            .ok_or_else(|| {
                AttachmentDownloadError::new(
                    AttachmentDownloadFailureKind::NotFound,
                    "requested attachment part was not surfaced by the MIME layer",
                )
            })?;

        let body = decode_attachment_body(self.policy, &part)?;

        Ok(DownloadedAttachment {
            mailbox_name: message.mailbox_name.clone(),
            uid: message.uid,
            part_path: request.part_path.clone(),
            filename: sanitize_download_filename(
                self.policy,
                part.metadata.filename.as_deref(),
                message.uid,
                &request.part_path,
            ),
            content_type: normalize_download_content_type(self.policy, &part.metadata.content_type),
            body,
        })
    }

    /// Resolves one attachment part for the already validated session owner.
    pub fn download_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        message: &MessageView,
        part_path: &str,
    ) -> AttachmentDownloadOutcome {
        let attachment = match self.download_from_message(message, part_path) {
            Ok(attachment) => attachment,
            Err(error) => {
                return AttachmentDownloadOutcome {
                    decision: AttachmentDownloadDecision::Denied {
                        public_reason: error.public_reason(),
                    },
                    audit_event: build_failure_event(
                        context,
                        validated_session,
                        message,
                        part_path,
                        error.public_reason(),
                        error.audit_reason(),
                        &error.reason,
                    ),
                };
            }
        };

        AttachmentDownloadOutcome {
            decision: AttachmentDownloadDecision::Downloaded {
                canonical_username: validated_session.record.canonical_username.clone(),
                session_id: validated_session.record.session_id.clone(),
                attachment: attachment.clone(),
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "attachment_downloaded",
                "attachment download completed",
            )
            .with_field(
                "canonical_username",
                validated_session.record.canonical_username.clone(),
            )
            .with_field("session_id", validated_session.record.session_id.clone())
            .with_field("mailbox_name", attachment.mailbox_name.clone())
            .with_field("uid", attachment.uid.to_string())
            .with_field("part_path", attachment.part_path.clone())
            .with_field("download_bytes", attachment.body.len().to_string())
            .with_field("content_type", attachment.content_type.clone())
            .with_field("filename_present", "true")
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
        }
    }
}

/// Builds a bounded failure event for attachment-download problems.
fn build_failure_event(
    context: &AuthenticationContext,
    validated_session: &ValidatedSession,
    message: &MessageView,
    part_path: &str,
    public_reason: AttachmentDownloadPublicFailureReason,
    audit_reason: AttachmentDownloadAuditFailureReason,
    reason: &str,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "attachment_download_failed",
        "attachment download failed",
    )
    .with_field(
        "canonical_username",
        validated_session.record.canonical_username.clone(),
    )
    .with_field("session_id", validated_session.record.session_id.clone())
    .with_field("mailbox_name", message.mailbox_name.clone())
    .with_field("uid", message.uid.to_string())
    .with_field("part_path", part_path.to_string())
    .with_field("public_reason", public_reason.as_str())
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("reason", reason.to_string())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Validates a conservative dotted MIME part-path selector.
fn validate_part_path(
    policy: AttachmentDownloadPolicy,
    part_path: &str,
) -> Result<(), AttachmentDownloadError> {
    if part_path.is_empty() {
        return Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::InvalidRequest,
            "attachment part path must not be empty",
        ));
    }

    if part_path.len() > policy.part_path_max_len {
        return Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::InvalidRequest,
            format!(
                "attachment part path exceeded maximum length of {} bytes",
                policy.part_path_max_len
            ),
        ));
    }

    if part_path.starts_with('.') || part_path.ends_with('.') || part_path.contains("..") {
        return Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::InvalidRequest,
            "attachment part path was not a valid dotted numeric path",
        ));
    }

    let mut segments = 0usize;
    for segment in part_path.split('.') {
        segments += 1;
        if segment.is_empty() || !segment.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(AttachmentDownloadError::new(
                AttachmentDownloadFailureKind::InvalidRequest,
                "attachment part path was not a valid dotted numeric path",
            ));
        }

        if segment.starts_with('0') {
            return Err(AttachmentDownloadError::new(
                AttachmentDownloadFailureKind::InvalidRequest,
                "attachment part path segments must not have leading zeroes",
            ));
        }
    }

    if segments < 2 || !part_path.starts_with("1.") {
        return Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::InvalidRequest,
            "attachment part path must reference a surfaced child part",
        ));
    }

    Ok(())
}

/// Decodes the attachment body according to the surfaced transfer encoding.
fn decode_attachment_body(
    policy: AttachmentDownloadPolicy,
    part: &AttachmentPart,
) -> Result<Vec<u8>, AttachmentDownloadError> {
    match part.transfer_encoding.as_str() {
        "" | "7bit" | "8bit" | "binary" => bounded_bytes(
            policy.download_max_bytes,
            part.body_text.as_bytes().to_vec(),
            "attachment body exceeded maximum decoded length",
        ),
        "base64" => decode_base64_bytes(&part.body_text, policy.download_max_bytes),
        "quoted-printable" => {
            decode_quoted_printable_bytes(&part.body_text, policy.download_max_bytes)
        }
        other => Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::UnsupportedEncoding,
            format!("unsupported content-transfer-encoding {other:?}"),
        )),
    }
}

/// Rejects oversized byte vectors with a stable error string.
fn bounded_bytes(
    max_bytes: usize,
    bytes: Vec<u8>,
    reason: &str,
) -> Result<Vec<u8>, AttachmentDownloadError> {
    if bytes.len() > max_bytes {
        return Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::OutputRejected,
            format!("{reason} of {max_bytes} bytes"),
        ));
    }

    Ok(bytes)
}

/// Decodes base64 attachment content without adding another dependency.
fn decode_base64_bytes(input: &str, max_bytes: usize) -> Result<Vec<u8>, AttachmentDownloadError> {
    let cleaned = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    if cleaned.len() % 4 != 0 {
        return Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::OutputRejected,
            "base64 attachment body length was not a multiple of four",
        ));
    }

    let mut output = Vec::with_capacity((cleaned.len() / 4) * 3);
    for chunk in cleaned.chunks(4) {
        let mut values = [0u8; 4];
        let mut padding = 0usize;

        for (index, byte) in chunk.iter().copied().enumerate() {
            match byte {
                b'A'..=b'Z' => values[index] = byte - b'A',
                b'a'..=b'z' => values[index] = byte - b'a' + 26,
                b'0'..=b'9' => values[index] = byte - b'0' + 52,
                b'+' => values[index] = 62,
                b'/' => values[index] = 63,
                b'=' => {
                    values[index] = 0;
                    padding += 1;
                    if index < 2 {
                        return Err(AttachmentDownloadError::new(
                            AttachmentDownloadFailureKind::OutputRejected,
                            "base64 attachment body used invalid padding",
                        ));
                    }
                }
                _ => {
                    return Err(AttachmentDownloadError::new(
                        AttachmentDownloadFailureKind::OutputRejected,
                        "base64 attachment body contained invalid characters",
                    ))
                }
            }
        }

        if padding == 1 && chunk[3] != b'=' {
            return Err(AttachmentDownloadError::new(
                AttachmentDownloadFailureKind::OutputRejected,
                "base64 attachment body used invalid padding",
            ));
        }
        if padding == 2 && !(chunk[2] == b'=' && chunk[3] == b'=') {
            return Err(AttachmentDownloadError::new(
                AttachmentDownloadFailureKind::OutputRejected,
                "base64 attachment body used invalid padding",
            ));
        }

        let combined = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | (values[3] as u32);
        output.push(((combined >> 16) & 0xff) as u8);
        if padding < 2 {
            output.push(((combined >> 8) & 0xff) as u8);
        }
        if padding < 1 {
            output.push((combined & 0xff) as u8);
        }

        if output.len() > max_bytes {
            return Err(AttachmentDownloadError::new(
                AttachmentDownloadFailureKind::OutputRejected,
                format!("attachment body exceeded maximum decoded length of {max_bytes} bytes"),
            ));
        }
    }

    Ok(output)
}

/// Decodes quoted-printable attachment content with conservative bounds.
fn decode_quoted_printable_bytes(
    input: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, AttachmentDownloadError> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'=' {
            if index + 1 >= bytes.len() {
                return Err(AttachmentDownloadError {
                    kind: AttachmentDownloadFailureKind::OutputRejected,
                    reason: "quoted-printable attachment body ended in a bare escape".to_string(),
                });
            }

            if bytes[index + 1] == b'\n' {
                index += 2;
                continue;
            }

            if bytes[index + 1] == b'\r' && index + 2 < bytes.len() && bytes[index + 2] == b'\n' {
                index += 3;
                continue;
            }

            if index + 2 >= bytes.len() {
                return Err(AttachmentDownloadError {
                    kind: AttachmentDownloadFailureKind::OutputRejected,
                    reason: "quoted-printable attachment body ended in a truncated escape"
                        .to_string(),
                });
            }

            output.push((hex_value(bytes[index + 1])? << 4) | hex_value(bytes[index + 2])?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }

        if output.len() > max_bytes {
            return Err(AttachmentDownloadError {
                kind: AttachmentDownloadFailureKind::OutputRejected,
                reason: format!(
                    "attachment body exceeded maximum decoded length of {max_bytes} bytes"
                ),
            });
        }
    }

    Ok(output)
}

/// Parses one hexadecimal byte from a quoted-printable escape.
fn hex_value(byte: u8) -> Result<u8, AttachmentDownloadError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AttachmentDownloadError::new(
            AttachmentDownloadFailureKind::OutputRejected,
            "quoted-printable attachment body contained invalid hex",
        )),
    }
}

/// Normalizes the surfaced MIME type into a safe HTTP response value.
fn normalize_download_content_type(policy: AttachmentDownloadPolicy, content_type: &str) -> String {
    let trimmed = content_type.trim().to_ascii_lowercase();
    if trimmed.is_empty()
        || trimmed.len() > policy.content_type_max_len
        || !is_safe_media_type(&trimmed)
    {
        return "application/octet-stream".to_string();
    }

    trimmed
}

/// Builds a conservative download file name for `Content-Disposition`.
fn sanitize_download_filename(
    policy: AttachmentDownloadPolicy,
    original: Option<&str>,
    uid: u64,
    part_path: &str,
) -> String {
    let mut sanitized = String::new();

    if let Some(original) = original {
        for ch in original.chars() {
            sanitized.push(
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                    ch
                } else {
                    '_'
                },
            );
            if sanitized.len() >= policy.filename_max_len {
                break;
            }
        }

        while sanitized.starts_with('.') || sanitized.starts_with('_') {
            sanitized.remove(0);
        }
        while sanitized.ends_with('.') || sanitized.ends_with('_') {
            sanitized.pop();
        }
    }

    if sanitized.is_empty() {
        sanitized = format!("attachment-{uid}-{}.bin", part_path.replace('.', "-"));
    }

    if sanitized.len() > policy.filename_max_len {
        sanitized.truncate(policy.filename_max_len);
    }

    sanitized
}

/// Returns true when the media type is a conservative token/token value.
fn is_safe_media_type(value: &str) -> bool {
    let Some((type_name, subtype_name)) = value.split_once('/') else {
        return false;
    };

    !type_name.is_empty()
        && !subtype_name.is_empty()
        && type_name.chars().all(is_safe_media_type_char)
        && subtype_name.chars().all(is_safe_media_type_char)
}

/// Conservative allowed characters for the HTTP media type response header.
fn is_safe_media_type_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '+' | '-' | '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthenticationPolicy, RequiredSecondFactor};
    use crate::mailbox::MessageView;
    use crate::session::SessionRecord;

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-attachment",
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
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
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

    fn multipart_message_view(body_text: &str) -> MessageView {
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 11:00:00 +0000".to_string(),
            size_virtual: 512,
            header_block: "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n"
                .to_string(),
            body_text: body_text.to_string(),
        }
    }

    #[test]
    fn downloads_base64_attachment_parts() {
        let message = multipart_message_view(concat!(
            "--mix-1\n",
            "Content-Type: text/plain; charset=utf-8\n",
            "\n",
            "Body text\n",
            "--mix-1\n",
            "Content-Type: application/pdf\n",
            "Content-Transfer-Encoding: base64\n",
            "Content-Disposition: attachment; filename=\"report.pdf\"\n",
            "\n",
            "SGVsbG8=\n",
            "--mix-1--\n",
        ));

        let outcome = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
            .download_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &message,
                "1.2",
            );

        match outcome.decision {
            AttachmentDownloadDecision::Downloaded { attachment, .. } => {
                assert_eq!(attachment.filename, "report.pdf");
                assert_eq!(attachment.content_type, "application/pdf");
                assert_eq!(attachment.body, b"Hello");
            }
            other => panic!("expected downloaded attachment, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_attachment_part_paths() {
        let message = multipart_message_view(concat!(
            "--mix-1\n",
            "Content-Type: application/octet-stream\n",
            "Content-Disposition: attachment; filename=\"report.bin\"\n",
            "\n",
            "test\n",
            "--mix-1--\n",
        ));

        let outcome = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
            .download_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &message,
                "../bad",
            );

        assert_eq!(
            outcome.decision,
            AttachmentDownloadDecision::Denied {
                public_reason: AttachmentDownloadPublicFailureReason::InvalidRequest
            }
        );
    }

    #[test]
    fn sanitizes_download_filename_and_content_type() {
        let message = multipart_message_view(concat!(
            "--mix-1\n",
            "Content-Type: text/plain\n",
            "\n",
            "Body text\n",
            "--mix-1\n",
            "Content-Type: application/x-custom+data\n",
            "Content-Disposition: attachment; filename=\"../../weird report?.txt\"\n",
            "\n",
            "payload\n",
            "--mix-1--\n",
        ));

        let outcome = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
            .download_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &message,
                "1.2",
            );

        match outcome.decision {
            AttachmentDownloadDecision::Downloaded { attachment, .. } => {
                assert_eq!(attachment.filename, "weird_report_.txt");
                assert_eq!(attachment.content_type, "application/x-custom+data");
            }
            other => panic!("expected downloaded attachment, got {other:?}"),
        }
    }

    #[test]
    fn decodes_quoted_printable_attachment_bodies() {
        let decoded = decode_quoted_printable_bytes("line=0Awith=20space", 64)
            .expect("quoted-printable should decode");

        assert_eq!(decoded, b"line\nwith space");
    }
}
