//! Bounded source-notation authoring. This module performs no I/O.
//!
//! Emphasis may nest eight levels; unclosed delimiters remain literal. Link
//! labels are literal text, not a second markup language. Incomplete links
//! remain literal. Complete links with unsafe/invalid destinations are errors.
//! Consecutive `- ` or `1. ` lines form a list; numbered output is sequential.
//! CRLF is normalized to LF. Plain-text composition must bypass this renderer.

use std::fmt;

pub const MAX_SOURCE_BYTES: usize = 262_144;
pub const MAX_NESTING: usize = 8;
pub const MAX_OUTPUT_BYTES: usize = MAX_SOURCE_BYTES * 24 + 1024;

/// Explicit interpretation of a message body; existing callers remain plain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BodyFormat {
    #[default]
    Plain,
    Formatted,
}

impl BodyFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Formatted => "formatted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Self::Plain),
            "formatted" => Some(Self::Formatted),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormattedBody {
    pub html: String,
    pub plain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    SourceTooLarge,
    OutputTooLarge,
    NestingTooDeep,
    InvalidLink,
    UnsupportedControl,
    InvalidState,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidState => "Message formatting could not be completed.",
            Self::SourceTooLarge => "Formatted message source exceeds 262144 bytes.",
            Self::OutputTooLarge => "Formatted message output exceeds its limit.",
            Self::NestingTooDeep => "Formatting exceeds eight nested levels.",
            Self::InvalidLink => {
                "Use a valid http, https or mailto link without whitespace or controls."
            }
            Self::UnsupportedControl => {
                "Formatted message contains an unsupported control character."
            }
        })
    }
}

impl std::error::Error for FormatError {}

#[derive(Default)]
struct Fragment {
    html: String,
    plain: String,
}

impl Fragment {
    fn text(&mut self, value: &str) {
        escape_into(&mut self.html, value);
        self.plain.push_str(value);
    }

    fn append(&mut self, other: Self) {
        self.html.push_str(&other.html);
        self.plain.push_str(&other.plain);
    }
}

fn escape_into(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
}

/// Conservative URL grammar: ASCII DNS/IPv4 hosts, optional numeric ports and
/// visible ASCII paths; mailto is one simple mailbox with no query/headers.
/// Percent escapes must be well-formed and cannot encode controls. No userinfo,
/// IPv6 literals, IDNs, address display names, backslashes or browser coercion.
fn safe_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 4096 || !target.is_ascii() {
        return false;
    }
    let bytes = target.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b <= b' ' || b == 127 || matches!(b, b'\\' | b'<' | b'>' | b'"' | b'\'' | b'(' | b')') {
            return false;
        }
        if b == b'%' {
            let Some(pair) = bytes.get(i + 1..i + 3) else {
                return false;
            };
            let Some(a) = (pair[0] as char).to_digit(16) else {
                return false;
            };
            let Some(b) = (pair[1] as char).to_digit(16) else {
                return false;
            };
            let decoded = a * 16 + b;
            if decoded <= 32 || decoded == 127 || decoded == 92 {
                return false;
            }
            i += 2;
        }
        i += 1;
    }
    if let Some(mailbox) = target.strip_prefix("mailto:") {
        let Some((local, host)) = mailbox.split_once('@') else {
            return false;
        };
        return !local.is_empty()
            && local.len() <= 64
            && !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..")
            && local
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".!#$&*+-/=_^`{|}~".contains(&b))
            && valid_host(host);
    }
    let Some(rest) = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_host(host)
        && port.is_none_or(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n > 0)
        })
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn inline(source: &str) -> Result<Fragment, FormatError> {
    let mut frames: Vec<(&str, Fragment)> = vec![("", Fragment::default())];
    let mut i = 0;
    while i < source.len() {
        let rest = &source[i..];
        // Consume each bracket candidate once, including an unfinished one.
        // This prevents repeated scans of a long run of opening brackets.
        if rest.starts_with('[') {
            if let Some(end) = rest.find(']') {
                if rest[end + 1..].starts_with('(') {
                    if let Some(close) = rest[end + 2..].find(')') {
                        let label = &rest[1..end];
                        let target = &rest[end + 2..end + 2 + close];
                        if label.trim().is_empty() || label.contains('[') || !safe_target(target) {
                            return Err(FormatError::InvalidLink);
                        }
                        let output = &mut frames.last_mut().ok_or(FormatError::InvalidState)?.1;
                        output.html.push_str("<a href=\"");
                        escape_into(&mut output.html, target);
                        output.html.push_str("\">");
                        escape_into(&mut output.html, label);
                        output.html.push_str("</a>");
                        output.plain.push_str(label);
                        if label != target {
                            output.plain.push_str(" (");
                            output.plain.push_str(target);
                            output.plain.push(')');
                        }
                        i += end + close + 3;
                        continue;
                    }
                    frames
                        .last_mut()
                        .ok_or(FormatError::InvalidState)?
                        .1
                        .text(rest);
                    break;
                }
                frames
                    .last_mut()
                    .ok_or(FormatError::InvalidState)?
                    .1
                    .text(&rest[..end + 1]);
                i += end + 1;
                continue;
            }
            frames
                .last_mut()
                .ok_or(FormatError::InvalidState)?
                .1
                .text(rest);
            break;
        }
        let top = frames.last().ok_or(FormatError::InvalidState)?.0;
        let marker = if !top.is_empty() && rest.starts_with(top) {
            top
        } else if rest.starts_with("**") {
            "**"
        } else if rest.starts_with("__") {
            "__"
        } else if rest.starts_with('*') {
            "*"
        } else {
            ""
        };
        if marker.is_empty() {
            let width = rest
                .chars()
                .next()
                .ok_or(FormatError::InvalidState)?
                .len_utf8();
            frames
                .last_mut()
                .ok_or(FormatError::InvalidState)?
                .1
                .text(&rest[..width]);
            i += width;
        } else {
            i += marker.len();
            if marker == top {
                let (_, content) = frames.pop().ok_or(FormatError::InvalidState)?;
                let parent = &mut frames.last_mut().ok_or(FormatError::InvalidState)?.1;
                if content.plain.is_empty() {
                    parent.text(marker);
                    parent.text(marker);
                } else {
                    let (open, close) = match marker {
                        "**" => ("<strong>", "</strong>"),
                        "__" => ("<u>", "</u>"),
                        _ => ("<em>", "</em>"),
                    };
                    parent.html.push_str(open);
                    parent.html.push_str(&content.html);
                    parent.html.push_str(close);
                    parent.plain.push_str(&content.plain);
                }
            } else {
                if frames.len() > MAX_NESTING {
                    return Err(FormatError::NestingTooDeep);
                }
                frames.push((marker, Fragment::default()));
            }
        }
    }
    while frames.len() > 1 {
        let (marker, content) = frames.pop().ok_or(FormatError::InvalidState)?;
        let parent = &mut frames.last_mut().ok_or(FormatError::InvalidState)?.1;
        parent.text(marker);
        parent.append(content);
    }
    Ok(frames.pop().ok_or(FormatError::InvalidState)?.1)
}

/// Render both alternatives from the same parse. On any error neither output
/// is returned; callers must retain the user's source and show the error.
pub fn render(source: &str) -> Result<FormattedBody, FormatError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(FormatError::SourceTooLarge);
    }
    let normalized = source.replace("\r\n", "\n");
    if normalized
        .chars()
        .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
    {
        return Err(FormatError::UnsupportedControl);
    }
    let mut result = FormattedBody {
        html: String::new(),
        plain: String::new(),
    };
    let mut list = "";
    let mut number = 0;
    for (line_index, line) in normalized.split('\n').enumerate() {
        let (kind, body) = if let Some(body) = line.strip_prefix("- ") {
            ("ul", body)
        } else if let Some(body) = line.split_once(". ").and_then(|(number, body)| {
            (!number.is_empty()
                && number.len() <= 6
                && number.bytes().all(|byte| byte.is_ascii_digit()))
            .then_some(body)
        }) {
            ("ol", body)
        } else {
            ("", line)
        };
        if kind != list {
            if !list.is_empty() {
                result.html.push_str(&format!("</{list}>"));
            }
            if !kind.is_empty() {
                result.html.push_str(&format!("<{kind}>"));
            }
            list = kind;
            number = 0;
        }
        if line_index > 0 {
            result.plain.push('\n');
        }
        let fragment = inline(body)?;
        if list.is_empty() {
            result.html.push_str("<div>");
            result.html.push_str(if fragment.html.is_empty() {
                "<br>"
            } else {
                &fragment.html
            });
            result.html.push_str("</div>");
        } else {
            result.html.push_str("<li>");
            result.html.push_str(&fragment.html);
            result.html.push_str("</li>");
            if list == "ul" {
                result.plain.push_str("- ");
            } else {
                number += 1;
                result.plain.push_str(&format!("{number}. "));
            }
        }
        result.plain.push_str(&fragment.plain);
        if result.html.len() > MAX_OUTPUT_BYTES || result.plain.len() > MAX_OUTPUT_BYTES {
            return Err(FormatError::OutputTooLarge);
        }
    }
    if !list.is_empty() {
        result.html.push_str(&format!("</{list}>"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_format_requires_explicit_known_mode() {
        assert_eq!(BodyFormat::default(), BodyFormat::Plain);
        for mode in [BodyFormat::Plain, BodyFormat::Formatted] {
            assert_eq!(BodyFormat::parse(mode.as_str()), Some(mode));
        }
        for invalid in ["", "html", "Formatted", " formatted"] {
            assert_eq!(BodyFormat::parse(invalid), None);
        }
    }

    #[test]
    fn nested_formatting_unicode_and_matching_alternatives() {
        let body = render("**bold *italic* __under__** café 🦊").unwrap();
        assert_eq!(
            body.html,
            "<div><strong>bold <em>italic</em> <u>under</u></strong> café 🦊</div>"
        );
        assert_eq!(body.plain, "bold italic under café 🦊");
        assert_eq!(
            render("***both***").unwrap().html,
            "<div><strong><em>both</em></strong></div>"
        );
    }

    #[test]
    fn unclosed_and_empty_notation_remains_literal() {
        for source in [
            "**unfinished",
            "__unfinished",
            "*unfinished",
            "****",
            "[unfinished",
            "[label](unfinished",
        ] {
            assert_eq!(render(source).unwrap().plain, source);
        }
        let body = render("**unfinished *inner*").unwrap();
        assert_eq!(body.plain, "**unfinished inner");
        assert_eq!(body.html, "<div>**unfinished <em>inner</em></div>");
    }

    #[test]
    fn lists_and_line_endings_share_content() {
        let body = render("- **one**\r\n- two\r\n1. first\n1. second\n\nlast\n").unwrap();
        assert_eq!(body.html, "<ul><li><strong>one</strong></li><li>two</li></ul><ol><li>first</li><li>second</li></ol><div><br></div><div>last</div><div><br></div>");
        assert_eq!(body.plain, "- one\n- two\n1. first\n2. second\n\nlast\n");
    }

    #[test]
    fn links_escape_attributes_and_keep_destination_in_plain_text() {
        let body =
            render("[A & B](https://example.test/a?q=1&b=2) [mail](mailto:user+tag@example.test)")
                .unwrap();
        assert!(body
            .html
            .contains("href=\"https://example.test/a?q=1&amp;b=2\">A &amp; B</a>"));
        assert_eq!(
            body.plain,
            "A & B (https://example.test/a?q=1&b=2) mail (mailto:user+tag@example.test)"
        );
        assert!(render("[http://example.test](http://example.test)")
            .unwrap()
            .plain
            .eq("http://example.test"));
    }

    #[test]
    fn unsafe_or_ambiguous_complete_links_are_rejected() {
        for target in [
            "javascript:alert",
            "data:text/html,hi",
            "//example.test",
            "https://",
            "https://user@example.test",
            "https://example.test:99999",
            "https://example.test\\bad",
            "https://example.test/%0aevil",
            "https://example.test/%zz",
            "https://example.test/a b",
            "mailto:a@example.test?subject=x",
            "mailto:a@@example.test",
            "https://-bad.test",
            "HTTPS://example.test",
        ] {
            assert_eq!(
                render(&format!("[x]({target})")),
                Err(FormatError::InvalidLink),
                "{target}"
            );
        }
        assert_eq!(
            render("[](https://example.test)"),
            Err(FormatError::InvalidLink)
        );
    }

    #[test]
    fn html_is_literal_and_links_never_create_images() {
        let body = render("<img src=x onerror='x'>&\"\n![alt](https://example.test/img)").unwrap();
        assert!(body
            .html
            .contains("&lt;img src=x onerror=&#39;x&#39;&gt;&amp;&quot;"));
        assert!(!body.html.contains("<img"));
        assert!(body.plain.starts_with("<img src=x onerror='x'>&\""));
    }

    #[test]
    fn bounded_source_controls_and_pathological_input() {
        assert_eq!(
            render(&"x".repeat(MAX_SOURCE_BYTES + 1)),
            Err(FormatError::SourceTooLarge)
        );
        assert_eq!(render("a\0b"), Err(FormatError::UnsupportedControl));
        assert_eq!(render("a\rb"), Err(FormatError::UnsupportedControl));
        for source in [
            "[".repeat(MAX_SOURCE_BYTES),
            "&".repeat(MAX_SOURCE_BYTES),
            "\n".repeat(MAX_SOURCE_BYTES),
            "*__".repeat(MAX_SOURCE_BYTES / 3),
        ] {
            match render(&source) {
                Ok(body) => {
                    assert!(body.html.len() <= MAX_OUTPUT_BYTES);
                    assert!(body.plain.len() <= MAX_OUTPUT_BYTES);
                }
                Err(error) => assert_eq!(error, FormatError::NestingTooDeep),
            }
        }
    }
}
