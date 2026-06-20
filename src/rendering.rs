//! Conservative browser-rendering helpers for fetched message content.
//!
//! This renderer intentionally stays smaller than a full mail client:
//! - it consumes an already fetched message view
//! - it asks the MIME layer to classify the message safely
//! - it renders only selected plain text or explicit safe placeholders
//! - it surfaces attachment metadata without attempting download or preview

use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::html::{EscapedHtml, TrustedHtml};
use crate::logging::audit_session_ref;
use crate::logging::{EventCategory, LogEvent};
use crate::mailbox::MessageView;
use crate::mime::{
    unfold_headers, AttachmentMetadata, MimeAnalysis, MimeAnalysisPolicy, MimeAnalyzer,
    MimeBodySource,
};
use crate::rendering_html::{
    sanitize_html_body, HtmlRenderingPolicy, DEFAULT_HTML_BODY_INPUT_MAX_LEN,
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
    pub html_display_preference: HtmlDisplayPreference,
    pub html_rendering_policy: HtmlRenderingPolicy,
    pub mime_analysis_policy: MimeAnalysisPolicy,
}

impl Default for RenderingPolicy {
    fn default() -> Self {
        Self {
            rendered_header_value_max_len: DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN,
            rendered_body_html_max_len: DEFAULT_RENDERED_BODY_HTML_MAX_LEN,
            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
            html_rendering_policy: HtmlRenderingPolicy {
                html_body_input_max_len: DEFAULT_HTML_BODY_INPUT_MAX_LEN,
            },
            mime_analysis_policy: MimeAnalysisPolicy::default(),
        }
    }
}

/// The current rendering mode exposed to later UI code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderingMode {
    PlainTextPreformatted,
    SanitizedHtml,
}

impl RenderingMode {
    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlainTextPreformatted => "plain_text_preformatted",
            Self::SanitizedHtml => "sanitized_html",
        }
    }
}

/// User-visible preference controlling how HTML-capable messages are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HtmlDisplayPreference {
    #[default]
    PreferSanitizedHtml,
    PreferPlainText,
}

impl HtmlDisplayPreference {
    /// Returns the stable string representation used in settings and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreferSanitizedHtml => "prefer_sanitized_html",
            Self::PreferPlainText => "prefer_plain_text",
        }
    }

    /// Parses the stable string representation used in settings storage.
    pub fn parse(value: &str) -> Result<Self, RenderError> {
        match value {
            "prefer_sanitized_html" => Ok(Self::PreferSanitizedHtml),
            "prefer_plain_text" => Ok(Self::PreferPlainText),
            _ => Err(RenderError {
                reason: "unsupported html display preference".to_string(),
            }),
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
    pub body_html: TrustedHtml,
    pub body_text_for_compose: String,
    pub attachments: Vec<AttachmentMetadata>,
    pub rendering_mode: RenderingMode,
}

/// Errors raised while transforming fetched message content into browser-safe
/// output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError {
    pub reason: String,
}

/// The paired browser-safe HTML and compose-friendly plain-text body output.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedBody {
    body_html: TrustedHtml,
    compose_text: String,
    body_source: MimeBodySource,
    rendering_mode: RenderingMode,
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
        let rendered_body = render_body_from_analysis(
            &analysis,
            self.policy.html_display_preference,
            self.policy.html_rendering_policy,
            self.policy.rendered_body_html_max_len,
        )?;

        let render_action = match rendered_body.rendering_mode {
            RenderingMode::PlainTextPreformatted => "message_rendered_plain_text",
            RenderingMode::SanitizedHtml => "message_rendered_sanitized_html",
        };
        let render_message = match rendered_body.rendering_mode {
            RenderingMode::PlainTextPreformatted => "message rendered with plain-text policy",
            RenderingMode::SanitizedHtml => "message rendered with sanitized-html policy",
        };

        let rendered = RenderedMessageView {
            mailbox_name: message.mailbox_name.clone(),
            uid: message.uid,
            subject,
            from,
            date_received: message.date_received.clone(),
            mime_top_level_content_type: analysis.top_level_content_type.clone(),
            body_source: rendered_body.body_source,
            contains_html_body: analysis.contains_html_body,
            body_html: rendered_body.body_html,
            body_text_for_compose: rendered_body.compose_text,
            attachments: analysis.attachments.clone(),
            rendering_mode: rendered_body.rendering_mode,
        };

        Ok(RenderOutcome {
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                render_action,
                render_message,
            )
            .with_field(
                "canonical_username",
                validated_session.record.canonical_username.clone(),
            )
            .with_field(
                "session_ref",
                audit_session_ref(&validated_session.record.session_id),
            )
            .with_field("mailbox_name", rendered.mailbox_name.clone())
            .with_field("uid", rendered.uid.to_string())
            .with_field(
                "mime_top_level_content_type",
                rendered.mime_top_level_content_type.clone(),
            )
            .with_field("body_source", rendered.body_source.as_str())
            .with_field("attachment_count", rendered.attachments.len().to_string())
            .with_field(
                "contains_html_body",
                if rendered.contains_html_body {
                    "true"
                } else {
                    "false"
                },
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
                let raw_value = value.trim();
                if raw_value.len() > max_len {
                    return Err(RenderError {
                        reason: format!(
                            "header {wanted_name} exceeded maximum length of {max_len} bytes"
                        ),
                    });
                }
                let decoded = decode_encoded_words(raw_value);
                if decoded.len() > max_len {
                    return Err(RenderError {
                        reason: format!(
                            "header {wanted_name} exceeded maximum length of {max_len} bytes"
                        ),
                    });
                }
                return Ok(Some(decoded));
            }
        }
    }

    Ok(None)
}

/// Decodes RFC 2047 encoded words conservatively for the narrow header summary.
fn decode_encoded_words(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;

    while index < value.len() {
        if let Some((consumed, segment)) = parse_encoded_word(&value[index..]) {
            decoded.push_str(&segment);
            index += consumed;

            let whitespace_start = index;
            while let Some(byte) = value.as_bytes().get(index) {
                if *byte == b' ' || *byte == b'\t' {
                    index += 1;
                } else {
                    break;
                }
            }

            if index < value.len() && parse_encoded_word(&value[index..]).is_some() {
                continue;
            }

            if whitespace_start < index {
                decoded.push_str(&value[whitespace_start..index]);
            }
            continue;
        }

        let next_char = value[index..]
            .chars()
            .next()
            .expect("index should remain at a valid char boundary");
        decoded.push(next_char);
        index += next_char.len_utf8();
    }

    decoded
}

/// Parses and decodes one RFC 2047 encoded word from the start of `input`.
fn parse_encoded_word(input: &str) -> Option<(usize, String)> {
    if !input.starts_with("=?") {
        return None;
    }

    let bytes = input.as_bytes();
    let charset_end = input[2..].find('?')? + 2;
    let charset = input[2..charset_end].trim();
    if charset.is_empty() {
        return None;
    }

    let encoding = *bytes.get(charset_end + 1)?;
    if !matches!(encoding, b'B' | b'b' | b'Q' | b'q') {
        return None;
    }
    if *bytes.get(charset_end + 2)? != b'?' {
        return None;
    }

    let encoded_start = charset_end + 3;
    let encoded_end = input[encoded_start..].find("?=")? + encoded_start;
    let encoded_text = &input[encoded_start..encoded_end];

    let decoded_bytes = match encoding {
        b'B' | b'b' => decode_header_base64(encoded_text).ok()?,
        b'Q' | b'q' => decode_header_q_encoding(encoded_text).ok()?,
        _ => return None,
    };
    let decoded_text = crate::charset::decode_text_bytes(charset, &decoded_bytes)?;

    Some((encoded_end + 2, decoded_text))
}

/// Decodes one RFC 2047 Q-encoded word without widening the trust surface.
fn decode_header_q_encoding(input: &str) -> Result<Vec<u8>, ()> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'_' => {
                output.push(b' ');
                index += 1;
            }
            b'=' => {
                let high = *bytes.get(index + 1).ok_or(())?;
                let low = *bytes.get(index + 2).ok_or(())?;
                output.push((hex_value(high)? << 4) | hex_value(low)?);
                index += 3;
            }
            byte if byte.is_ascii() => {
                output.push(byte);
                index += 1;
            }
            _ => return Err(()),
        }
    }

    Ok(output)
}

/// Decodes one RFC 2047 base64-encoded word conservatively.
fn decode_header_base64(input: &str) -> Result<Vec<u8>, ()> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(());
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0;

    while index < bytes.len() {
        let mut values = [0u8; 4];
        let mut padding = 0;
        let mut saw_padding = false;

        for offset in 0..4 {
            let byte = bytes[index + offset];
            if saw_padding && byte != b'=' {
                return Err(());
            }
            values[offset] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    saw_padding = true;
                    0
                }
                _ => return Err(()),
            };
        }

        output.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            output.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding == 0 {
            output.push((values[2] << 6) | values[3]);
        }
        if padding > 2 {
            return Err(());
        }

        index += 4;
    }

    Ok(output)
}

/// Decodes one hexadecimal ASCII nibble used by RFC 2047 Q encoding.
fn hex_value(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

/// Renders the selected body or a safe placeholder from MIME analysis.
fn render_body_from_analysis(
    analysis: &MimeAnalysis,
    html_display_preference: HtmlDisplayPreference,
    html_rendering_policy: HtmlRenderingPolicy,
    max_len: usize,
) -> Result<RenderedBody, RenderError> {
    if html_display_preference == HtmlDisplayPreference::PreferSanitizedHtml {
        if let Some(rendered_html) =
            render_sanitized_html_body(analysis, html_rendering_policy, max_len)?
        {
            return Ok(rendered_html);
        }
    }

    // PreferPlainText means render a safe plain-text part when one exists.
    // It must not mean withhold all HTML forever. If no safe plain-text body
    // exists but the MIME layer selected an HTML body, fall back to sanitized
    // HTML rather than showing the historical regression placeholder.
    if analysis.selected_plain_text_body.is_none() {
        if let Some(rendered_html) =
            render_sanitized_html_body(analysis, html_rendering_policy, max_len)?
        {
            return Ok(rendered_html);
        }
    }

    match analysis.body_source {
        MimeBodySource::SinglePartPlainText | MimeBodySource::MultipartPlainTextPart => {
            let mut rendered = render_plain_text_body(
                analysis
                    .selected_plain_text_body
                    .as_deref()
                    .unwrap_or_default(),
                max_len,
            )?;
            rendered.body_source = analysis.body_source;
            Ok(rendered)
        }
        MimeBodySource::HtmlWithheld => render_placeholder_body(
            "HTML-only message withheld by current plain-text policy.",
            max_len,
            MimeBodySource::HtmlWithheld,
        ),
        MimeBodySource::MultipartHtmlWithheld => render_placeholder_body(
            "Multipart message contains HTML content, but no safe plain-text part was selected.",
            max_len,
            MimeBodySource::MultipartHtmlWithheld,
        ),
        MimeBodySource::AttachmentOnlyWithheld => render_placeholder_body(
            "Message content is attachment-oriented under the current plain-text policy.",
            max_len,
            MimeBodySource::AttachmentOnlyWithheld,
        ),
        MimeBodySource::BinaryWithheld => render_placeholder_body(
            "Non-text message content withheld by current plain-text policy.",
            max_len,
            MimeBodySource::BinaryWithheld,
        ),
        MimeBodySource::MultipartStructureWithheld => render_placeholder_body(
            "Multipart structure detected, but no safe plain-text preview is available.",
            max_len,
            MimeBodySource::MultipartStructureWithheld,
        ),
        MimeBodySource::Empty => render_placeholder_body(
            "Message has no renderable body content.",
            max_len,
            MimeBodySource::Empty,
        ),
        MimeBodySource::HtmlSanitized | MimeBodySource::MultipartHtmlSanitized => {
            unreachable!("sanitized html body sources are introduced by the rendering layer")
        }
    }
}

/// Renders sanitized HTML when the MIME layer selected an HTML body.
fn render_sanitized_html_body(
    analysis: &MimeAnalysis,
    html_rendering_policy: HtmlRenderingPolicy,
    max_len: usize,
) -> Result<Option<RenderedBody>, RenderError> {
    let Some(selected_html_body) = analysis.selected_html_body.as_deref() else {
        return Ok(None);
    };

    let Some(sanitized_html) = sanitize_html_body(
        html_rendering_policy,
        selected_html_body,
        analysis.selected_plain_text_body.as_deref(),
        max_len,
    )?
    else {
        return Ok(None);
    };

    Ok(Some(RenderedBody {
        body_html: sanitized_html.body_html,
        compose_text: sanitized_html.compose_text,
        body_source: if analysis.top_level_content_type.starts_with("multipart/") {
            MimeBodySource::MultipartHtmlSanitized
        } else {
            MimeBodySource::HtmlSanitized
        },
        rendering_mode: RenderingMode::SanitizedHtml,
    }))
}

/// Renders plain text for safe browser display using an escaped `<pre>` block.
fn render_plain_text_body(body_text: &str, max_len: usize) -> Result<RenderedBody, RenderError> {
    let escaped = escape_html(body_text);
    let rendered = format!("<pre>{escaped}</pre>");

    if rendered.len() > max_len {
        return Err(RenderError {
            reason: format!("rendered body exceeded maximum length of {max_len} bytes"),
        });
    }

    Ok(RenderedBody {
        body_html: TrustedHtml::from_template(rendered),
        compose_text: body_text.to_string(),
        body_source: MimeBodySource::SinglePartPlainText,
        rendering_mode: RenderingMode::PlainTextPreformatted,
    })
}

/// Renders a bounded safe placeholder into the same preformatted container.
fn render_placeholder_body(
    message: &str,
    max_len: usize,
    body_source: MimeBodySource,
) -> Result<RenderedBody, RenderError> {
    let mut rendered = render_plain_text_body(&format!("[{message}]"), max_len)?;
    rendered.body_source = body_source;
    Ok(rendered)
}

/// Escapes HTML-significant characters without adding a dependency.
fn escape_html(value: &str) -> EscapedHtml {
    EscapedHtml::new(value)
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

    fn message_view_from_fixture(raw_message: &str) -> MessageView {
        let normalized = raw_message.replace("\r\n", "\n");
        let (header_block, body_text) = normalized
            .split_once("\n\n")
            .expect("fixture should contain a header/body separator");
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 99,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 12:00:00 +0000".to_string(),
            size_virtual: normalized.len() as u64,
            header_block: header_block.to_string(),
            body_text: body_text.to_string(),
        }
    }

    #[test]
    fn unfolds_headers_and_extracts_values() {
        let unfolded = unfold_headers(&plain_text_message_view_fixture().header_block);
        let subject =
            extract_header_value(&unfolded, "Subject", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("header extraction should succeed");
        let folded =
            extract_header_value(&unfolded, "X-Long", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("header extraction should succeed");

        assert_eq!(subject.as_deref(), Some("Test message"));
        assert_eq!(folded.as_deref(), Some("folded continuation line"));
    }

    #[test]
    fn decodes_q_encoded_header_summary_values() {
        let unfolded = unfold_headers(concat!(
            "Subject: =?UTF-8?Q?Ol=C3=A1_do_mundo?=\n",
            "From: =?UTF-8?Q?Andr=C3=A9_Example?= <alice@example.com>\n"
        ));
        let subject =
            extract_header_value(&unfolded, "Subject", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("subject extraction should succeed");
        let from = extract_header_value(&unfolded, "From", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
            .expect("from extraction should succeed");

        assert_eq!(subject.as_deref(), Some("Olá do mundo"));
        assert_eq!(from.as_deref(), Some("André Example <alice@example.com>"));
    }

    #[test]
    fn decodes_base64_encoded_header_summary_values() {
        let unfolded = unfold_headers(concat!(
            "Subject: =?UTF-8?B?VGVzdCDinJM=?=\n",
            "From: =?ISO-8859-1?Q?Andr=E9?= <alice@example.com>\n"
        ));
        let subject =
            extract_header_value(&unfolded, "Subject", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("subject extraction should succeed");
        let from = extract_header_value(&unfolded, "From", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
            .expect("from extraction should succeed");

        assert_eq!(subject.as_deref(), Some("Test ✓"));
        assert_eq!(from.as_deref(), Some("André <alice@example.com>"));
    }

    #[test]
    fn decodes_adjacent_encoded_words_without_preserving_separator_whitespace() {
        let unfolded = unfold_headers("Subject: =?UTF-8?Q?Hello?= =?UTF-8?Q?_world?=\n");
        let subject =
            extract_header_value(&unfolded, "Subject", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("subject extraction should succeed");

        assert_eq!(subject.as_deref(), Some("Hello world"));
    }

    #[test]
    fn escapes_plain_text_body_for_browser_display() {
        let rendered = render_plain_text_body(
            "Hello <world> & \"friends\"\n",
            DEFAULT_RENDERED_BODY_HTML_MAX_LEN,
        )
        .expect("rendering should succeed");

        assert_eq!(
            rendered.body_html,
            "<pre>Hello &lt;world&gt; &amp; &quot;friends&quot;\n</pre>"
        );
        assert_eq!(rendered.compose_text, "Hello <world> & \"friends\"\n");
        assert_eq!(rendered.body_source, MimeBodySource::SinglePartPlainText);
        assert_eq!(
            rendered.rendering_mode,
            RenderingMode::PlainTextPreformatted
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
        assert_eq!(
            outcome.rendered.body_text_for_compose,
            "Hello <world>\nSecond line & more\n"
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
            "ts=\"1970-01-01T02:02:53Z\" ts_unix=7373 level=info category=mailbox action=message_rendered_plain_text msg=\"message rendered with plain-text policy\" canonical_username=\"alice@example.com\" session_ref=\"asr-cc77477e59365048c995e4c7b47f5654\" mailbox_name=\"INBOX\" uid=\"9\" mime_top_level_content_type=\"text/plain\" body_source=\"singlepart_plain_text\" attachment_count=\"0\" contains_html_body=\"false\" rendering_mode=\"plain_text_preformatted\" request_id=\"req-render\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\""
        );
    }

    #[test]
    fn renders_message_view_with_decoded_subject_and_from_summary() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let mut message = plain_text_message_view_fixture();
        message.header_block = concat!(
            "Subject: =?UTF-8?Q?Quarterly_r=C3=A9sum=C3=A9?=\n",
            "From: =?UTF-8?Q?Andr=C3=A9_Example?= <alice@example.com>\n",
            "Content-Type: text/plain; charset=utf-8\n"
        )
        .to_string();

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("rendering should succeed");

        assert_eq!(
            outcome.rendered.subject.as_deref(),
            Some("Quarterly résumé")
        );
        assert_eq!(
            outcome.rendered.from.as_deref(),
            Some("André Example <alice@example.com>")
        );
    }

    #[test]
    fn fixture_encoded_header_matrix_decodes_subject_from_and_date() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/encoded_header_matrix.eml"
        ));
        let unfolded = unfold_headers(&message.header_block);

        let decoded_date =
            extract_header_value(&unfolded, "Date", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("date extraction should succeed");

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("encoded header matrix should render safely");

        assert_eq!(
            outcome.rendered.subject.as_deref(),
            Some("Quarterly ✓ café")
        );
        assert_eq!(
            outcome.rendered.from.as_deref(),
            Some("José Niño <jose@example.com>")
        );
        assert_eq!(
            decoded_date.as_deref(),
            Some("Fri, 27 Mar 2026 12:30:00 +0000")
        );
        assert_eq!(outcome.rendered.date_received, "2026-03-27 12:00:00 +0000");
        assert_eq!(
            outcome.rendered.body_text_for_compose,
            "Header decoding fixture body.\n"
        );
    }

    #[test]
    fn fixture_unsupported_header_charset_preserves_bounded_literal_without_panic() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/unsupported_header_charset.eml"
        ));
        let unfolded = unfold_headers(&message.header_block);

        let subject =
            extract_header_value(&unfolded, "Subject", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
                .expect("subject extraction should not fail for unsupported charset");
        let date = extract_header_value(&unfolded, "Date", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
            .expect("date extraction should succeed");

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("unsupported header charset fixture should render safely");

        assert_eq!(subject.as_deref(), Some("=?KOI8-R?B?8NLJ18XU?="));
        assert_eq!(
            outcome.rendered.subject.as_deref(),
            Some("=?KOI8-R?B?8NLJ18XU?=")
        );
        assert_eq!(
            outcome.rendered.from.as_deref(),
            Some("Safe Sender <safe@example.com>")
        );
        assert_eq!(date.as_deref(), Some("Fri, 27 Mar 2026 12:35:00 +0000"));
        assert_eq!(
            outcome.rendered.body_text_for_compose,
            "Unsupported header charset should not panic or widen decoding.\n"
        );
    }

    #[test]
    fn encoded_date_header_obeys_rendered_header_bound() {
        let unfolded = unfold_headers(&format!(
            "Date: =?US-ASCII?Q?{}?=\n",
            "A".repeat(DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN + 1)
        ));

        let error = extract_header_value(&unfolded, "Date", DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN)
            .expect_err("oversized encoded date header should be rejected");

        assert_eq!(
            error.reason,
            format!(
                "header Date exceeded maximum length of {} bytes",
                DEFAULT_RENDERED_HEADER_VALUE_MAX_LEN
            )
        );
    }

    #[test]
    fn fixture_encoded_headers_render_with_selected_sanitized_html() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/multipart_alternative_encoded_headers.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("fixture rendering should succeed");

        assert_eq!(outcome.rendered.subject.as_deref(), Some("Café update"));
        assert_eq!(
            outcome.rendered.from.as_deref(),
            Some("André Example <andre@example.com>")
        );
        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert!(outcome.rendered.body_html.contains("<strong>team</strong>"));
        assert_eq!(
            outcome.rendered.body_text_for_compose,
            "Olá team\nPlain fixture part"
        );
    }

    #[test]
    fn renders_html_only_messages_with_sanitized_html() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &html_only_message_view_fixture(),
            )
            .expect("rendering should succeed");

        assert_eq!(outcome.rendered.body_source, MimeBodySource::HtmlSanitized);
        assert!(outcome.rendered.contains_html_body);
        assert!(outcome.rendered.body_html.contains("message-html"));
        assert!(outcome.rendered.body_html.contains("Hello"));
        assert!(outcome.rendered.body_html.contains("<b>world</b>"));
        assert!(outcome.rendered.body_text_for_compose.contains("Hello"));
        assert!(outcome.rendered.body_text_for_compose.contains("world"));
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
    }

    #[test]
    fn fixture_windows_1252_html_only_forward_renders_sanitized_content() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/windows_1252_html_only_forward.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("windows-1252 HTML-only forward should render safely");

        assert_eq!(
            outcome.rendered.subject.as_deref(),
            Some("Forwarded café – update")
        );
        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert!(outcome.rendered.body_html.contains(concat!(
            "Forwarded café ",
            "\u{2014}",
            " expected content."
        )));
        assert!(!outcome.rendered.body_html.contains("<script"));
        assert!(!outcome.rendered.body_html.contains("alert(1)"));
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
    }

    #[test]
    fn renders_base64_html_only_messages_after_decoding_and_sanitizing() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let mut message = html_only_message_view_fixture();
        message.header_block = concat!(
            "Subject: Encoded HTML only\n",
            "From: Alice <alice@example.com>\n",
            "Content-Type: text/html; charset=utf-8\n",
            "Content-Transfer-Encoding: base64\n"
        )
        .to_string();
        message.body_text = concat!(
            "PHA+SGVsbG8gPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PjxzdHJvbmc+dGVh",
            "bTwvc3Ryb25nPjwvcD4=\n"
        )
        .to_string();

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("rendering should succeed");

        assert_eq!(outcome.rendered.body_source, MimeBodySource::HtmlSanitized);
        assert!(outcome.rendered.body_html.contains("message-html"));
        assert!(outcome.rendered.body_html.contains("Hello"));
        assert!(outcome.rendered.body_html.contains("<strong>team</strong>"));
        assert!(!outcome.rendered.body_html.contains("<script"));
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
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
            MimeBodySource::MultipartHtmlSanitized
        );
        assert!(outcome.rendered.contains_html_body);
        assert!(outcome.rendered.body_html.contains("message-html"));
        assert!(outcome.rendered.body_html.contains("HTML body"));
        assert_eq!(outcome.rendered.body_text_for_compose, "Plain text preview");
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
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
    }

    #[test]
    fn fixture_hostile_html_strips_active_and_remote_content() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/nested_mixed_hostile_html.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("fixture rendering should succeed");
        let body = &outcome.rendered.body_html;

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert!(body.contains("<strong>reader</strong>"));
        assert!(body.contains("href=\"https://example.com/safe\""));
        assert!(!body.contains("<script"));
        assert!(!body.contains("onclick"));
        assert!(!body.contains("<form"));
        assert!(!body.contains("<iframe"));
        assert!(!body.contains("<img"));
        assert!(!body.contains("<style"));
        assert!(!body.contains("javascript:"));
        assert!(!body.contains("cid:"));
        assert!(!body.contains("data:image"));
        assert!(!body.contains("evil.example"));
        assert_eq!(
            outcome.rendered.body_text_for_compose,
            "Safe plain fallback"
        );
        assert_eq!(outcome.rendered.attachments.len(), 2);
    }

    #[test]
    fn fixture_malformed_boundary_renders_safe_placeholder() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/malformed_boundary.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("malformed fixture should render safely");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartStructureWithheld
        );
        assert!(outcome.rendered.body_html.contains(
            "Multipart structure detected, but no safe plain-text preview is available."
        ));
    }

    #[test]
    fn fixture_newsletter_related_sanitizes_remote_content() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/newsletter_related_remote_content.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("newsletter fixture should render safely");
        let body = &outcome.rendered.body_html;

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert_eq!(
            outcome.rendered.subject.as_deref(),
            Some("Monthly security digest")
        );
        assert!(body.contains("<h1>Monthly digest</h1>"));
        assert!(body.contains("href=\"https://example.com/digest\""));
        assert!(!body.contains("<img"));
        assert!(!body.contains("tracker.example"));
        assert!(!body.contains("cid:"));
        assert!(outcome.rendered.attachments.iter().any(|attachment| {
            attachment.filename.as_deref() == Some("logo.jpg")
                && attachment.content_id.as_deref() == Some("logo@example.com")
        }));
    }

    #[test]
    fn fixture_unsupported_charset_html_renders_placeholder() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/unsupported_charset_html.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("unsupported charset fixture should render safely");

        assert_eq!(outcome.rendered.body_source, MimeBodySource::HtmlWithheld);
        assert!(outcome.rendered.contains_html_body);
        assert!(outcome
            .rendered
            .body_html
            .contains("HTML-only message withheld by current plain-text policy."));
    }

    #[test]
    fn fixture_alternative_html_first_sanitizes_html_and_keeps_plain_compose_fallback() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/alternative_html_first_plain_second.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("html-first alternative fixture should render safely");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert!(outcome
            .rendered
            .body_html
            .contains("<strong>but plain text remains compose-safe</strong>"));
        assert!(!outcome.rendered.body_html.contains("<img"));
        assert!(!outcome.rendered.body_html.contains("tracker.example"));
        assert_eq!(
            outcome.rendered.body_text_for_compose,
            "Plain text arrives second and should remain the compose fallback."
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
    }

    #[test]
    fn fixture_html_link_scheme_probe_strips_unsafe_links_styles_and_forms() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/html_link_scheme_probe.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("html link scheme probe should render safely");
        let body = &outcome.rendered.body_html;

        assert_eq!(outcome.rendered.body_source, MimeBodySource::HtmlSanitized);
        assert!(body.contains("Visible update"));
        assert!(body.contains("href=\"https://example.com/safe\""));
        assert!(body.contains("rel=\"noopener noreferrer nofollow\""));
        assert!(!body.contains("style="));
        assert!(!body.contains("onclick"));
        assert!(!body.contains("<form"));
        assert!(!body.contains("<input"));
        assert!(!body.contains("<img"));
        assert!(!body.contains("<meta"));
        assert!(!body.contains("<style"));
        assert!(!body.contains("href=\"/relative/path\""));
        assert!(!body.contains("href=\"//evil.example/protocol-relative\""));
        assert!(!body.contains("href=\"cid:logo@example.com\""));
        assert!(!body.contains("href=\"data:"));
        assert!(!body.contains("evil.example"));
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
    }

    #[test]
    fn html_only_singlepart_renders_sanitized_html() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &html_only_message_view_fixture(),
            )
            .expect("HTML-only singlepart should render through sanitizer");

        assert_eq!(outcome.rendered.body_source, MimeBodySource::HtmlSanitized);
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
        assert!(outcome.rendered.contains_html_body);
        assert!(outcome.rendered.body_html.contains("message-html"));
        assert!(outcome.rendered.body_html.contains("<b>world</b>"));
        assert!(!outcome.rendered.body_html.contains("<script"));
    }

    #[test]
    fn html_only_multipart_without_plain_text_renders_sanitized_html() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/windows_1252_html_only_forward.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("multipart HTML-only fixture should render through sanitizer");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
        assert!(outcome.rendered.body_html.contains("Forwarded café"));
        assert!(!outcome.rendered.body_html.contains("alert(1)"));
    }

    #[test]
    fn prefer_plain_text_renders_plain_when_plain_exists() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy {
            html_display_preference: HtmlDisplayPreference::PreferPlainText,
            ..RenderingPolicy::default()
        });
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &multipart_message_view_fixture(),
            )
            .expect("plain preference should render selected safe plain text");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartPlainTextPart
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::PlainTextPreformatted
        );
        assert!(outcome
            .rendered
            .body_html
            .contains("<pre>Plain text preview</pre>"));
        assert!(!outcome.rendered.body_html.contains("HTML body"));
    }

    #[test]
    fn prefer_sanitized_html_renders_html_when_html_exists() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy {
            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
            ..RenderingPolicy::default()
        });
        let outcome = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &multipart_message_view_fixture(),
            )
            .expect("sanitized HTML preference should render selected HTML");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
        assert!(outcome.rendered.body_html.contains("HTML body"));
        assert_eq!(outcome.rendered.body_text_for_compose, "Plain text preview");
    }

    #[test]
    fn prefer_plain_text_falls_back_to_sanitized_html_without_plain() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy {
            html_display_preference: HtmlDisplayPreference::PreferPlainText,
            ..RenderingPolicy::default()
        });
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/windows_1252_html_only_forward.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("plain preference should fall back to sanitized HTML without safe plain text");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartHtmlSanitized
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
        assert!(outcome.rendered.body_html.contains("Forwarded café"));
        assert!(!outcome.rendered.body_html.contains(
            "Multipart message contains HTML content, but no safe plain-text part was selected."
        ));
        assert!(!outcome.rendered.body_html.contains("<script"));
    }

    #[test]
    fn windows_1252_html_only_forward_renders_decoded_subject_and_body() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/windows_1252_html_only_forward.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("windows-1252 HTML-only forward should render safely");

        assert_eq!(
            outcome.rendered.subject.as_deref(),
            Some("Forwarded café – update")
        );
        assert!(outcome.rendered.body_html.contains("Forwarded café"));
        assert!(outcome.rendered.body_html.contains("expected content."));
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::SanitizedHtml
        );
    }

    #[test]
    fn hostile_html_sanitization_strips_active_and_remote_content() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let nested_message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/nested_mixed_hostile_html.eml"
        ));
        let link_probe_message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/html_link_scheme_probe.eml"
        ));

        let nested = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &nested_message,
            )
            .expect("hostile nested fixture should render safely");
        let link_probe = renderer
            .render_for_validated_session(
                &test_context(),
                &validated_session_fixture(),
                &link_probe_message,
            )
            .expect("link scheme probe fixture should render safely");

        for body in [&nested.rendered.body_html, &link_probe.rendered.body_html] {
            assert!(!body.contains("<script"));
            assert!(!body.contains("onclick"));
            assert!(!body.contains("<form"));
            assert!(!body.contains("<iframe"));
            assert!(!body.contains("<object"));
            assert!(!body.contains("<embed"));
            assert!(!body.contains("<img"));
            assert!(!body.contains("javascript:"));
            assert!(!body.contains("data:"));
            assert!(!body.contains("cid:"));
            assert!(!body.contains("file:"));
            assert!(!body.contains("blob:"));
            assert!(!body.contains("href=\"/"));
            assert!(!body.contains("href=\"//"));
            assert!(!body.contains("evil.example"));
        }
        assert!(link_probe
            .rendered
            .body_html
            .contains("href=\"https://example.com/safe\""));
    }

    #[test]
    fn malformed_mime_renders_safe_placeholder_or_errors_without_raw_html() {
        let renderer = PlainTextMessageRenderer::new(RenderingPolicy::default());
        let message = message_view_from_fixture(include_str!(
            "../tests/fixtures/mime/malformed_boundary.eml"
        ));

        let outcome = renderer
            .render_for_validated_session(&test_context(), &validated_session_fixture(), &message)
            .expect("malformed fixture should fail closed into a safe placeholder");

        assert_eq!(
            outcome.rendered.body_source,
            MimeBodySource::MultipartStructureWithheld
        );
        assert_eq!(
            outcome.rendered.rendering_mode,
            RenderingMode::PlainTextPreformatted
        );
        assert!(outcome.rendered.body_html.contains(
            "Multipart structure detected, but no safe plain-text preview is available."
        ));
        assert!(!outcome.rendered.body_html.contains("<script"));
        assert!(!outcome.rendered.body_html.contains("<html"));
    }

    #[test]
    fn rejects_oversized_rendered_headers() {
        let error = extract_header_value(&format!("Subject: {}\n", "A".repeat(64)), "Subject", 16)
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
