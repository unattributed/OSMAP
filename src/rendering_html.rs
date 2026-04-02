//! Narrow HTML sanitization helpers for browser-safe message rendering.
//!
//! OSMAP intentionally does not implement its own HTML sanitizer. This module
//! uses a small allowlist policy on top of a dedicated sanitizer crate so the
//! browser-facing trust boundary stays explicit and reviewable.

use std::collections::{HashMap, HashSet};

use ammonia::{clean_text, Builder, UrlRelative};

use crate::rendering::RenderError;

/// Conservative upper bound for one raw HTML body passed into the sanitizer.
pub const DEFAULT_HTML_BODY_INPUT_MAX_LEN: usize = 1_048_576;

/// Policy controlling the safe-HTML rendering slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtmlRenderingPolicy {
    pub html_body_input_max_len: usize,
}

impl Default for HtmlRenderingPolicy {
    fn default() -> Self {
        Self {
            html_body_input_max_len: DEFAULT_HTML_BODY_INPUT_MAX_LEN,
        }
    }
}

/// Safe HTML output plus compose-friendly plain text derived from the same
/// source content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedHtmlBody {
    pub body_html: String,
    pub compose_text: String,
}

/// Sanitizes one HTML message body into the narrow browser-safe subset allowed
/// by the current OSMAP rendering policy.
pub fn sanitize_html_body(
    policy: HtmlRenderingPolicy,
    raw_html: &str,
    plain_text_fallback: Option<&str>,
    rendered_body_html_max_len: usize,
) -> Result<Option<SanitizedHtmlBody>, RenderError> {
    if raw_html.len() > policy.html_body_input_max_len {
        return Err(RenderError {
            reason: format!(
                "html body exceeded maximum length of {} bytes",
                policy.html_body_input_max_len
            ),
        });
    }

    let sanitized_fragment = html_sanitizer().clean(raw_html).to_string();
    if sanitized_fragment.trim().is_empty() {
        return Ok(None);
    }

    let compose_text = match plain_text_fallback {
        Some(plain_text_fallback) => plain_text_fallback.to_string(),
        None => clean_text(raw_html),
    };

    let body_html = format!("<div class=\"message-html\">{sanitized_fragment}</div>");
    if body_html.len() > rendered_body_html_max_len {
        return Err(RenderError {
            reason: format!(
                "rendered body exceeded maximum length of {rendered_body_html_max_len} bytes"
            ),
        });
    }

    Ok(Some(SanitizedHtmlBody {
        body_html,
        compose_text,
    }))
}

/// Builds the current allowlist HTML sanitizer for message rendering.
fn html_sanitizer() -> Builder<'static> {
    let tags = HashSet::from([
        "a",
        "b",
        "blockquote",
        "br",
        "caption",
        "code",
        "dd",
        "div",
        "dl",
        "dt",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "i",
        "li",
        "ol",
        "p",
        "pre",
        "s",
        "span",
        "strong",
        "sub",
        "sup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "u",
        "ul",
    ]);
    let clean_content_tags = HashSet::from([
        "embed", "frame", "head", "iframe", "math", "noscript", "object", "script", "style", "svg",
        "template",
    ]);
    let generic_attributes = HashSet::new();
    let tag_attributes = HashMap::from([
        ("a", HashSet::from(["href", "title"])),
        ("td", HashSet::from(["colspan", "rowspan"])),
        ("th", HashSet::from(["colspan", "rowspan"])),
    ]);
    let url_schemes = HashSet::from(["http", "https", "mailto"]);

    let mut builder = Builder::default();
    builder
        .tags(tags)
        .clean_content_tags(clean_content_tags)
        .generic_attributes(generic_attributes)
        .tag_attributes(tag_attributes)
        .url_schemes(url_schemes)
        .url_relative(UrlRelative::Deny)
        .strip_comments(true)
        .link_rel(Some("noopener noreferrer nofollow"));
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_html_to_a_narrow_safe_subset() {
        let sanitized = sanitize_html_body(
            HtmlRenderingPolicy::default(),
            concat!(
                "<script>alert(1)</script>",
                "<p>Hello <strong>team</strong>.</p>",
                "<img src=\"https://evil.invalid/track.png\">",
                "<a href=\"javascript:alert(1)\">bad</a>",
                "<a href=\"https://example.com/path\">good</a>"
            ),
            None,
            16 * 1024,
        )
        .expect("sanitization should succeed")
        .expect("sanitized html should remain");

        assert!(!sanitized.body_html.contains("<script"));
        assert!(!sanitized.body_html.contains("<img"));
        assert!(!sanitized.body_html.contains("javascript:"));
        assert!(
            sanitized.body_html.contains("<strong>team</strong>")
                || sanitized.body_html.contains("<b>team</b>")
        );
        assert!(sanitized
            .body_html
            .contains("href=\"https://example.com/path\""));
        assert!(sanitized
            .body_html
            .contains("rel=\"noopener noreferrer nofollow\""));
        assert!(sanitized.compose_text.contains("Hello"));
        assert!(sanitized.compose_text.contains("team"));
    }

    #[test]
    fn returns_none_when_html_sanitizes_to_no_visible_output() {
        let sanitized = sanitize_html_body(
            HtmlRenderingPolicy::default(),
            "<script>alert(1)</script><style>body{display:none}</style>",
            None,
            16 * 1024,
        )
        .expect("sanitization should succeed");

        assert!(sanitized.is_none());
    }

    #[test]
    fn rejects_oversized_raw_html_input() {
        let error = sanitize_html_body(
            HtmlRenderingPolicy {
                html_body_input_max_len: 8,
            },
            "<p>0123456789</p>",
            None,
            16 * 1024,
        )
        .expect_err("oversized html should fail");

        assert_eq!(
            error,
            RenderError {
                reason: "html body exceeded maximum length of 8 bytes".to_string(),
            }
        );
    }
}
