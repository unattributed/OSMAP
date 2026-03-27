//! Conservative browser-rendering helpers for fetched message content.
//!
//! This renderer intentionally stays smaller than a full mail client:
//! - it consumes an already fetched message view
//! - it asks the MIME layer to classify the message safely
//! - it renders only selected plain text or explicit safe placeholders
//! - it surfaces attachment metadata without attempting download or preview

use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::mailbox::MessageView;
use crate::mime::{
    unfold_headers, AttachmentMetadata, MimeAnalysis, MimeAnalysisPolicy, MimeAnalyzer,
    MimeBodySource,
};
use crate::session::ValidatedSession;

/// Conservative upper bound for one rendered header-summary value.
pub const DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN: usize = 1024;

/// Conservative upper bound for one rendered HTML-safe body fragment.
pub const DEFAULT_RENDERED_BODY_HTML_MAX_LEN: usize = 1_048_576;

/// Policy controlling the browser-rendering slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderingPolicy {
    pub rendered_header_value_max_len: usize,
    pub rendered_body_html_max_len: usize,
    pub mime_analysis_policy: MimeAnalysisPolicy,
}

impl Default for RenderingPolicy {
    fn default() -> Self {
        Self {
            rendered_header_value_max_len: DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN,
            rendered_body_html_max_len: DEFAULT_RENDERED_BODY_HTML_MAX_LEN,
            mime_analysis_policy: MimeAnalysisPolicy::default(),
        }
    }
}

/// The current rendering mode exposed to later UI code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderingMode {
    PlainTextPreformatted,
}

impl RenderingMode {
    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlainTextPreformatted => "plain_text_preformatted",
        }
    }
}

/// A browser-safe rendered message projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedMessageView {
    pub mailbox_name: String,
    pub uid: u64,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub date_received: String,
    pub mime_top_level_content_type: String,
    pub body_source: MimeBodySource,
    pub contains_html_body: bool,
    pub body_html: String,
    pub attachments: Vec<AttachmentMetadata>,
    pub rendering_mode: RenderingMode,
}

/// Errors raised while transforming fetched message content into browser-safe
/// output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError {
    pub reason: String,
}

/// The rendered message plus the audit event emitted by the renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderOutcome {
    pub rendered: RenderedMessageView,
    pub audit_event: LogEvent,
}

/// Renders fetched message payloads into the current browser-safe projection.
pub struct PlainTextMessageRenderer {
    policy: RenderingPolicy,
}

impl PlainTextMessageRenderer {
    /// Creates a renderer from the supplied policy.
    pub fn new(policy: RenderingPolicy) -> Self {
        Self { policy }
    }

    /// Renders a fetched message view for the validated session context.
    pub fn render_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        message: &MessageView,
    ) -> Result<RenderOutcome, RenderError> {
        let unfolded_headers = unfold_headers(&message.header_block);
        let analysis = MimeAnalyzer::new(self.policy.mime_analysis_policy)
            .analyze_message(message)
            .map_err(|error| RenderError {
                reason: error.reason,
            })?;
        let subject = extract_header_value(
            &unfolded_headers,
            "Subject",
            self.policy.rendered_header_value_max_len,
        )?;
        let from = extract_header_value(
            &unfolded_headers,
            "From",
            self.policy.rendered_header_value_max_len,
        )?;
        let body_html = render_body_from_analysis(&analysis, self.policy.rendered_body_html_max_len)?;

        let rendered = RenderedMessageView {
            mailbox_name: message.mailbox_name.clone(),
            uid: message.uid,
            subject,
            from,
            date_received: message.date_received.clone(),
            mime_top_level_content_type: analysis.top_level_content_type.clone(),
            body_source: analysis.body_source,
            contains_html_body: analysis.contains_html_body,
            body_html,
            attachments: analysis.attachments.clone(),
            rendering_mode: RenderingMode::PlainTextPreformatted,
        };

        Ok(RenderOutcome {
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "message_rendered_plain_text",
                "message rendered with plain-text policy",
            )
            .with_field(
                "canonical_username",
                validated_session.record.canonical_username.clone(),
            )
            .with_field("session_id", validated_session.record.session_id.clone())
            .with_field("mailbox_name", rendered.mailbox_name.clone())
            .with_field("uid", rendered.uid.to_string())
            .with_field("mime_top_level_content_type", rendered.mime_top_level_content_type.clone())
            .with_field("body_source", rendered.body_source.as_str())
            .with_field("attachment_count", rendered.attachments.len().to_string())
            .with_field(
                "contains_html_body",
                if rendered.contains_html_body { "true" } else { "false" },
            )
            .with_field("rendering_mode", rendered.rendering_mode.as_str())
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone()),
            rendered,
        })
    }
}

/// Extracts one unfolded header value from a fetched header block.
fn extract_header_value(
    unfolded_headers: &str,
    wanted_name: &str,
    max_len: usize,
) -> Result<Option<String>, RenderError> {
    for line in unfolded_headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(wanted_name) {
                let value = value.trim().to_string();
                if value.len() > max_len {
                    return Err(RenderError {
                        reason: format!(
                            "header {wanted_name} exceeded maximum length of {max_len} bytes"
                        ),
                    });
                }
                return Ok(Some(value));
            }
        }
    }

    Ok(None)
}

/// Renders the selected body or a safe placeholder from MIME analysis.
fn render_body_from_analysis(
    analysis: &MimeAnalysis,
    max_len: usize,
) -> Result<String, RenderError> {
    match analysis.body_source {
        MimeBodySource::SinglePartPlainText | MimeBodySource::MultipartPlainTextPart => {
            render_plain_text_body(
                analysis.selected_plain_text_body.as_deref().unwrap_or_default(),
                max_len,
            )
        }
        MimeBodySource::HtmlWithheld => render_placeholder_body(
            "HTML-only message withheld by current plain-text policy.",
            max_len,
        ),
        MimeBodySource::MultipartHtmlWithheld => render_placeholder_body(
            "Multipart message contains HTML content, but no safe plain-text part was selected.",
            max_len,
        ),
        MimeBodySource::AttachmentOnlyWithheld => render_placeholder_body(
            "Message content is attachment-oriented under the current plain-text policy.",
            max_len,
        ),
        MimeBodySource::BinaryWithheld => render_placeholder_body(
            "Non-text message content withheld by current plain-text policy.",
            max_len,
        ),
        MimeBodySource::MultipartStructureWithheld => render_placeholder_body(
            "Multipart structure detected, but no safe plain-text preview is available.",
            max_len,
        ),
        MimeBodySource::Empty => render_placeholder_body(
            "Message has no renderable body content.",
            max_len,
        ),
    }
}

/// Renders plain text for safe browser display using an escaped `<pre>` block.
fn render_plain_text_body(body_text: &str, max_len: usize) -> Result<String, RenderError> {
    let escaped = escape_html(body_text);
    let rendered = format!("<pre>{escaped}</pre>");

    if rendered.len() > max_len {
        return Err(RenderError {
            reason: format!("rendered body exceeded maximum length of {max_len} bytes"),
        });
    }

    Ok(rendered)
}

/// Renders a bounded safe placeholder into the same preformatted container.
fn render_placeholder_body(message: &str, max_len: usize) -> Result<String, RenderError> {
    render_plain_text_body(&format!("[{message}]"), max_len)
}

/// Escapes HTML-significant characters without adding a dependency.
fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthenticationContext;
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use crate::mailbox::MessageView;
    use crate::session::SessionRecord;
    use crate::{auth::AuthenticationPolicy, mailbox::MailboxPublicFailureReason};

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-render",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    fn validated_session_fixture() -> ValidatedSession {
        ValidatedSession {
            record: SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef01234567".to_string(),
                csrf_token: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: crate::auth::RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }

    fn plain_text_message_view_fixture() -> MessageView {
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 11:00:00 +0000".to_string(),
            size_virtual: 512,
            header_block: concat!(
                "Subject: Test message\n",
                "From: Alice <alice@example.com>\n",
                "Content-Type: text/plain; charset=utf-8\n",
                "X-Long: folded\n",
                " continuation line\n"
            )
            .to_string(),
            body_text: "Hello <world>\nSecond line & more\n".to_string(),
        }
    }

    fn html_only_message_view_fixture() -> MessageView {
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 10,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 11:10:00 +0000".to_string(),
            size_virtual: 1024,
            header_block: concat!(
                "Subject: HTML only\n",
                "From: Alice <alice@example.com>\n",
                "Content-Type: text/html; charset=utf-8\n"
            )
            .to_string(),
            body_text: "<html><body>Hello <b>world</b></body></html>\n".to_string(),
        }
    }

    fn multipart_message_view_fixture() -> MessageView {
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 11,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 11:20:00 +0000".to_string(),
            size_virtual: 2048,
            header_block: concat!(
                "Subject: Mixed message\n",
                "From: Alice <alice@example.com>\n",
                "Content-Type: multipart/mixed; boundary=\"mix-1\"\n"
            )
            .to_string(),
            body_text: concat!(
                "--mix-1\n",
                "Content-Type: multipart/alternative; boundary=\"alt-1\"\n",
                "\n",
                "--alt-1\n",
                "Content-Type: text/plain; charset=utf-8\n",
                "\n",
                "Plain text preview\n",
                "--alt-1\n",
                "Content-Type: text/html; charset=utf-8\n",
                "\n",
                "<html><body>HTML body</body></html>\n",
                "--alt-1--\n",
                "--mix-1\n",
                "Content-Type: application/pdf; name=\"report.pdf\"\n",
                "Content-Disposition: attachment; filename=\"report.pdf\"\n",
                "\n",
                "%PDF-sample%\n",
                "--mix-1--\n",
            )
            .to_string(),
        }
    }

    #[test]
    fn unfolds_headers_and_extracts_values() {
        let unfolded = unfold_headers(&plain_text_message_view_fixture().header_block);
        let subject = extract_header_value(
            &unfolded,
            "Subject",
            DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN,
        )
        .expect("header extraction should succeed");
        let folded = extract_header_value(
            &unfolded,
            "X-Long",
            DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN,
        )
        .expect("header extraction should succeed");

        assert_eq!(subject.as_deref(), Some("Test message"));
        assert_eq!(folded.as_deref(), Some("folded continuation line"));
    }

    #[test]
    fn escapes_plain_text_body_for_browser_display() {
        let rendered = render_plain_text_body(
            "Hello <world> & \"friends\"\n",
            DEFAULT_RENDERED_BODY_HTML_MAX_LEN,
        )
        .expect("rendering should succeed");

        assert_eq!(
            rendered,
            "<pre>Hello &lt;world&gt; &amp; &quot;friends&quot;\n</pre>"
        );
    }

    #[test]
    fn renders_message_view_with_plain_text_policy() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &plain_text_message_view_fixture(),
            )
            .expect("rendering should succeed");

        assert_eq!(outcome.rendered.subject.as_deref(), Some("Test message"));
        assert_eq!(
            outcome.rendered.from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(outcome.rendered.mime_top_level_content_type, "text/plain");
        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::SinglePartPlainText
        );
        assert_eq!(
            outcome.rendered.body_html,
            "<pre>Hello &lt;world&gt;\nSecond line &amp; more\n</pre>"
        );
        assert!(outcome.rendered.attachments.is_empty());
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::PlainTextPreformatted
        );

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 7373);
        assert_eq!(
            rendered,
            "ts=7373 level=info category=mailbox action=message_rendered_plain_text msg=\"message rendered with plain-text policy\" canonical_username=\"alice@example.com\" session_id=\"0123456789abcdef0123456789abcdef01234567\" mailbox_name=\"INBOX\" uid=\"9\" mime_top_level_content_type=\"text/plain\" body_source=\"singlepart_plain_text\" attachment_count=\"0\" contains_html_body=\"false\" rendering_mode=\"plain_text_preformatted\" request_id=\"req-render\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
        );
    }

    #[test]
    fn renders_html_only_messages_as_safe_placeholders() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &html_only_message_view_fixture(),
            )
            .expect("rendering should succeed");

        assert_eq!(outcome.rendered.body_source, MimeBodySource::HtmlWithheld);
        assert!(outcome.rendered.contains_html_body);
        assert_eq!(
            outcome.rendered.body_html,
            "<pre>[HTML-only message withheld by current plain-text policy.]</pre>"
        );
    }

    #[test]
    fn renders_multipart_messages_with_attachment_metadata() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &multipart_message_view_fixture(),
            )
            .expect("rendering should succeed");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartPlainTextPart
        );
        assert!(outcome.rendered.contains_html_body);
        assert_eq!(
            outcome.rendered.body_html,
            "<pre>Plain text preview</pre>"
        );
        assert_eq!(outcome.rendered.attachments.len(), 1);
        assert_eq!(outcome.rendered.attachments[0].part_path, "1.2");
        assert_eq!(
            outcome.rendered.attachments[0].filename.as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            outcome.rendered.attachments[0].content_type,
            "application/pdf"
        );
    }

    #[test]
    fn rejects_oversized_rendered_headers() {
        let error = extract_header_value(
            &format!("Subject: {}\n", "A".repeat(64)),
            "Subject",
            16,
        )
        .expect_err("oversized header values must fail");

        assert_eq!(
            error,
            RenderError {
                reason: "header Subject exceeded maximum length of 16 bytes".to_string(),
            }
        );
    }

    #[test]
    fn keeps_not_found_behavior_out_of_rendering() {
        let not_found = MailboxPublicFailureReason::NotFound;

        assert_eq!(not_found.as_str(), "not_found");
    }
}
