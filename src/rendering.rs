//! Conservative browser-rendering helpers for fetched message content.
//!
//! The first rendering slice is intentionally plain-text-first:
//! - it consumes an already fetched message view
//! - it extracts a small header summary
//! - it escapes message text for browser display
//! - it does not claim to support HTML mail, MIME trees, or attachments

use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::mailbox::MessageView;
use crate::session::ValidatedSession;

/// Conservative upper bound for one rendered header-summary value.
pub const DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN: usize = 1024;

/// Conservative upper bound for one rendered HTML-safe body fragment.
pub const DEFAULT_RENDERED_BODY_HTML_MAX_LEN: usize = 1_048_576;

/// Policy controlling the first browser-rendering slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderingPolicy {
    pub rendered_header_value_max_len: usize,
    pub rendered_body_html_max_len: usize,
}

impl Default for RenderingPolicy {
    fn default() -> Self {
        Self {
            rendered_header_value_max_len: DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN,
            rendered_body_html_max_len: DEFAULT_RENDERED_BODY_HTML_MAX_LEN,
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
    pub body_html: String,
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

/// Renders fetched message payloads into the first browser-safe projection.
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
        let subject = extract_header_value(
            &message.header_block,
            "Subject",
            self.policy.rendered_header_value_max_len,
        )?;
        let from = extract_header_value(
            &message.header_block,
            "From",
            self.policy.rendered_header_value_max_len,
        )?;
        let body_html = render_plain_text_body(
            &message.body_text,
            self.policy.rendered_body_html_max_len,
        )?;

        let rendered = RenderedMessageView {
            mailbox_name: message.mailbox_name.clone(),
            uid: message.uid,
            subject,
            from,
            date_received: message.date_received.clone(),
            body_html,
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
    header_block: &str,
    wanted_name: &str,
    max_len: usize,
) -> Result<Option<String>, RenderError> {
    let normalized_name = wanted_name.to_ascii_lowercase();
    let unfolded = unfold_headers(header_block);

    for line in unfolded.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(&normalized_name) {
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

/// Unfolds RFC 5322-style continuation lines conservatively.
fn unfold_headers(header_block: &str) -> String {
    let mut unfolded = String::new();

    for line in header_block.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            unfolded.push(' ');
            unfolded.push_str(line.trim());
        } else {
            if !unfolded.is_empty() {
                unfolded.push('\n');
            }
            unfolded.push_str(line);
        }
    }

    unfolded
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

    fn message_view_fixture() -> MessageView {
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 11:00:00 +0000".to_string(),
            size_virtual: 512,
            header_block: concat!(
                "Subject: Test message\n",
                "From: Alice <alice@example.com>\n",
                "X-Long: folded\n",
                " continuation line\n"
            )
            .to_string(),
            body_text: "Hello <world>\nSecond line & more\n".to_string(),
        }
    }

    #[test]
    fn unfolds_headers_and_extracts_values() {
        let subject = extract_header_value(
            &message_view_fixture().header_block,
            "Subject",
            DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN,
        )
        .expect("header extraction should succeed");
        let folded = extract_header_value(
            &message_view_fixture().header_block,
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
                &message_view_fixture(),
            )
            .expect("rendering should succeed");

        assert_eq!(outcome.rendered.subject.as_deref(), Some("Test message"));
        assert_eq!(
            outcome.rendered.from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(
            outcome.rendered.body_html,
            "<pre>Hello &lt;world&gt;\nSecond line &amp; more\n</pre>"
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::PlainTextPreformatted
        );

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 7373);
        assert_eq!(
            rendered,
            "ts=7373 level=info category=mailbox action=message_rendered_plain_text msg=\"message rendered with plain-text policy\" canonical_username=\"alice@example.com\" session_id=\"0123456789abcdef0123456789abcdef01234567\" mailbox_name=\"INBOX\" uid=\"9\" rendering_mode=\"plain_text_preformatted\" request_id=\"req-render\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
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
