//! Bounded parsing helpers for browser form inputs.
//!
//! This module keeps request-form parsing separate from the router so the
//! browser surface remains easier to review as file-upload behavior grows.

use std::collections::BTreeMap;

use crate::send::{ComposePolicy, UploadedAttachment};

/// Errors raised while parsing a browser form body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormParseError {
    pub reason: String,
}

/// Parsed compose input plus any uploaded attachments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedComposeForm {
    pub fields: BTreeMap<String, String>,
    pub attachments: Vec<UploadedAttachment>,
}

/// Parses a URL-encoded query string into a bounded key/value map.
pub fn parse_query_string(
    input: &str,
    max_fields: usize,
) -> Result<BTreeMap<String, String>, FormParseError> {
    parse_urlencoded_map(input, max_fields)
}

/// Parses a URL-encoded form body into a bounded key/value map.
pub fn parse_urlencoded_form(
    body: &[u8],
    max_fields: usize,
    max_bytes: usize,
) -> Result<BTreeMap<String, String>, FormParseError> {
    if body.len() > max_bytes {
        return Err(FormParseError {
            reason: "form body exceeded maximum length".to_string(),
        });
    }

    let body = std::str::from_utf8(body).map_err(|_| FormParseError {
        reason: "form body was not valid utf-8".to_string(),
    })?;

    parse_urlencoded_map(body, max_fields)
}

/// Parses the compose submission body in either URL-encoded or multipart form.
pub fn parse_compose_form(
    body: &[u8],
    content_type: Option<&str>,
    max_fields: usize,
    max_bytes: usize,
    compose_policy: ComposePolicy,
) -> Result<ParsedComposeForm, FormParseError> {
    match content_type.map(str::trim) {
        None | Some("") | Some("application/x-www-form-urlencoded") => Ok(ParsedComposeForm {
            fields: parse_urlencoded_form(body, max_fields, max_bytes)?,
            attachments: Vec::new(),
        }),
        Some(value) if is_multipart_form_data(value) => {
            parse_multipart_compose_form(body, value, max_fields, max_bytes, compose_policy)
        }
        Some(_) => Err(FormParseError {
            reason: "unsupported compose content-type".to_string(),
        }),
    }
}

/// Returns true when the content type names multipart form-data.
pub fn is_multipart_form_data(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .map(|value| value.eq_ignore_ascii_case("multipart/form-data"))
        .unwrap_or(false)
}

/// Parses a URL-encoded string into a key/value map.
fn parse_urlencoded_map(
    input: &str,
    max_fields: usize,
) -> Result<BTreeMap<String, String>, FormParseError> {
    let mut output = BTreeMap::new();

    if input.is_empty() {
        return Ok(output);
    }

    for (index, pair) in input.split('&').enumerate() {
        if index >= max_fields {
            return Err(FormParseError {
                reason: "form field count exceeded maximum".to_string(),
            });
        }

        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        output.insert(percent_decode(key)?, percent_decode(value)?);
    }

    Ok(output)
}

/// Decodes one URL-encoded segment into UTF-8 text.
fn percent_decode(input: &str) -> Result<String, FormParseError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.as_bytes().iter().copied();

    while let Some(byte) = chars.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = chars.next().ok_or_else(|| FormParseError {
                    reason: "truncated percent-encoded sequence".to_string(),
                })?;
                let low = chars.next().ok_or_else(|| FormParseError {
                    reason: "truncated percent-encoded sequence".to_string(),
                })?;
                bytes.push((hex_value(high)? << 4) | hex_value(low)?);
            }
            _ => bytes.push(byte),
        }
    }

    String::from_utf8(bytes).map_err(|_| FormParseError {
        reason: "url-encoded field was not valid utf-8".to_string(),
    })
}

/// Decodes one hexadecimal ASCII byte used in percent encoding.
fn hex_value(byte: u8) -> Result<u8, FormParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FormParseError {
            reason: "invalid percent-encoded byte".to_string(),
        }),
    }
}

/// Parses a bounded multipart form containing compose fields and attachments.
fn parse_multipart_compose_form(
    body: &[u8],
    content_type: &str,
    max_fields: usize,
    max_bytes: usize,
    compose_policy: ComposePolicy,
) -> Result<ParsedComposeForm, FormParseError> {
    if body.len() > max_bytes {
        return Err(FormParseError {
            reason: "form body exceeded maximum length".to_string(),
        });
    }

    let boundary = parse_boundary_parameter(content_type)?;
    let boundary_marker = format!("--{boundary}");
    let part_boundary = boundary_marker.as_bytes();
    let next_boundary = format!("\r\n--{boundary}");
    let next_boundary = next_boundary.as_bytes();

    if !body.starts_with(part_boundary) {
        return Err(FormParseError {
            reason: "multipart body did not begin with the declared boundary".to_string(),
        });
    }

    let mut cursor = 0;
    let mut part_count = 0;
    let mut fields = BTreeMap::new();
    let mut attachments = Vec::new();

    loop {
        if !body[cursor..].starts_with(part_boundary) {
            return Err(FormParseError {
                reason: "multipart body boundary sequence was malformed".to_string(),
            });
        }
        cursor += part_boundary.len();

        if body[cursor..].starts_with(b"--") {
            cursor += 2;
            if !body[cursor..].is_empty() && &body[cursor..] != b"\r\n" {
                return Err(FormParseError {
                    reason: "multipart body had trailing bytes after the closing boundary"
                        .to_string(),
                });
            }
            break;
        }

        if !body[cursor..].starts_with(b"\r\n") {
            return Err(FormParseError {
                reason: "multipart boundary was not followed by CRLF".to_string(),
            });
        }
        cursor += 2;

        part_count += 1;
        if part_count > max_fields {
            return Err(FormParseError {
                reason: "form field count exceeded maximum".to_string(),
            });
        }

        let header_end = find_subslice(&body[cursor..], b"\r\n\r\n").ok_or_else(|| FormParseError {
            reason: "multipart part headers were not terminated correctly".to_string(),
        })?;
        let header_block = std::str::from_utf8(&body[cursor..cursor + header_end]).map_err(|_| {
            FormParseError {
                reason: "multipart part headers were not valid utf-8".to_string(),
            }
        })?;
        cursor += header_end + 4;

        let next_boundary_offset =
            find_subslice(&body[cursor..], next_boundary).ok_or_else(|| FormParseError {
                reason: "multipart part body was not followed by a boundary".to_string(),
            })?;
        let part_body = &body[cursor..cursor + next_boundary_offset];
        cursor += next_boundary_offset + 2;

        let part_headers = parse_header_block(header_block)?;
        let disposition = part_headers
            .get("content-disposition")
            .ok_or_else(|| FormParseError {
                reason: "multipart part was missing content-disposition".to_string(),
            })?;
        let disposition = parse_header_parameters(disposition);
        if !disposition.value.eq_ignore_ascii_case("form-data") {
            return Err(FormParseError {
                reason: "multipart part used an unsupported disposition".to_string(),
            });
        }

        let field_name = disposition
            .params
            .get("name")
            .cloned()
            .ok_or_else(|| FormParseError {
                reason: "multipart part was missing a field name".to_string(),
            })?;
        let filename = disposition.params.get("filename").cloned();

        match filename {
            Some(filename) => {
                if field_name != "attachment" {
                    return Err(FormParseError {
                        reason: "unsupported file field name".to_string(),
                    });
                }

                if filename.is_empty() && part_body.is_empty() {
                    continue;
                }

                let attachment_content_type = part_headers
                    .get("content-type")
                    .map(String::as_str)
                    .unwrap_or("application/octet-stream");
                let attachment = UploadedAttachment::new(
                    compose_policy,
                    filename,
                    attachment_content_type,
                    part_body.to_vec(),
                )
                .map_err(|error| FormParseError {
                    reason: error.reason,
                })?;
                attachments.push(attachment);
            }
            None => {
                let value = String::from_utf8(part_body.to_vec()).map_err(|_| FormParseError {
                    reason: "multipart text field was not valid utf-8".to_string(),
                })?;
                fields.insert(field_name, value);
            }
        }
    }

    Ok(ParsedComposeForm { fields, attachments })
}

/// Parses a multipart boundary parameter from the content-type header.
fn parse_boundary_parameter(content_type: &str) -> Result<String, FormParseError> {
    let parsed = parse_header_parameters(content_type);
    if !parsed.value.eq_ignore_ascii_case("multipart/form-data") {
        return Err(FormParseError {
            reason: "unsupported compose content-type".to_string(),
        });
    }

    let boundary = parsed
        .params
        .get("boundary")
        .cloned()
        .ok_or_else(|| FormParseError {
            reason: "multipart boundary parameter was missing".to_string(),
        })?;

    if boundary.is_empty() || boundary.len() > 200 || boundary.chars().any(char::is_control) {
        return Err(FormParseError {
            reason: "multipart boundary parameter was invalid".to_string(),
        });
    }

    Ok(boundary)
}

/// Parses a small header block into lowercase header names.
fn parse_header_block(header_block: &str) -> Result<BTreeMap<String, String>, FormParseError> {
    let mut headers = BTreeMap::new();
    for line in header_block.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return Err(FormParseError {
                reason: "multipart part header line was malformed".to_string(),
            });
        };
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    Ok(headers)
}

/// One parsed header value with semicolon-separated parameters.
struct HeaderParameters {
    value: String,
    params: BTreeMap<String, String>,
}

/// Parses a header like `multipart/form-data; boundary="abc"` conservatively.
fn parse_header_parameters(header_value: &str) -> HeaderParameters {
    let mut segments = header_value.split(';');
    let value = segments.next().unwrap_or_default().trim().to_string();
    let mut params = BTreeMap::new();

    for segment in segments {
        let Some((name, value)) = segment.trim().split_once('=') else {
            continue;
        };
        params.insert(
            name.trim().to_ascii_lowercase(),
            unquote_header_value(value.trim()),
        );
    }

    HeaderParameters { value, params }
}

/// Removes one layer of surrounding quotes and simple backslash escapes.
fn unquote_header_value(value: &str) -> String {
    let trimmed = value.trim();
    if !(trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2) {
        return trimmed.to_string();
    }

    let mut output = String::new();
    let mut chars = trimmed[1..trimmed.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                output.push(next);
            }
        } else {
            output.push(ch);
        }
    }

    output
}

/// Finds one byte sequence inside another.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urlencoded_forms() {
        let parsed = parse_urlencoded_form(b"name=INBOX&uid=9", 4, 64)
            .expect("form should parse");

        assert_eq!(parsed.get("name").map(String::as_str), Some("INBOX"));
        assert_eq!(parsed.get("uid").map(String::as_str), Some("9"));
    }

    #[test]
    fn parses_multipart_compose_forms_with_attachment() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"attachment\"; filename=\"report.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "quarterly report\r\n",
            "--test-boundary--\r\n"
        );

        let parsed = parse_compose_form(
            body.as_bytes(),
            Some("multipart/form-data; boundary=test-boundary"),
            8,
            1024,
            ComposePolicy::default(),
        )
        .expect("multipart form should parse");

        assert_eq!(parsed.fields.get("to").map(String::as_str), Some("bob@example.com"));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "report.txt");
    }

    #[test]
    fn rejects_unsupported_compose_content_type() {
        let error = parse_compose_form(
            b"{}",
            Some("application/json"),
            4,
            128,
            ComposePolicy::default(),
        )
        .expect_err("unsupported content type must fail");

        assert_eq!(
            error,
            FormParseError {
                reason: "unsupported compose content-type".to_string(),
            }
        );
    }
}
