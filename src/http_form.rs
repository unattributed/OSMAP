//! Bounded parsing helpers for browser form inputs.
//!
//! This module keeps request-form parsing separate from the router so the
//! browser surface remains easier to review as file-upload behavior grows.

use std::collections::BTreeMap;

use crate::send::{ComposePolicy, UploadedAttachment};

/// Maximum bytes accepted in one multipart part header block.
pub const DEFAULT_MULTIPART_PART_HEADER_MAX_BYTES: usize = 8 * 1024;

/// Maximum number of headers accepted in one multipart part.
pub const DEFAULT_MULTIPART_PART_HEADER_MAX_COUNT: usize = 16;

/// Maximum normalized multipart header-name length.
pub const DEFAULT_MULTIPART_PART_HEADER_NAME_MAX_LEN: usize = 64;

/// Maximum normalized multipart header-value length.
pub const DEFAULT_MULTIPART_PART_HEADER_VALUE_MAX_LEN: usize = 4 * 1024;

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
    /// A rejected local image; callers must stop submission and retain fields.
    pub upload_error: Option<String>,
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

/// Returns true when the content type names a URL-encoded form body.
pub fn is_urlencoded_form_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .map(|value| value.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        .unwrap_or(false)
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
        None | Some("") => Ok(ParsedComposeForm {
            fields: parse_urlencoded_form(body, max_fields, max_bytes)?,
            attachments: Vec::new(),
            upload_error: None,
        }),
        Some(value) if is_urlencoded_form_content_type(value) => Ok(ParsedComposeForm {
            fields: parse_urlencoded_form(body, max_fields, max_bytes)?,
            attachments: Vec::new(),
            upload_error: None,
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
        let key = percent_decode(key)?;
        if key.is_empty() {
            return Err(FormParseError {
                reason: "form field name must not be empty".to_string(),
            });
        }
        if output.contains_key(&key) {
            return Err(FormParseError {
                reason: format!("duplicate form field: {key}"),
            });
        }
        output.insert(key, percent_decode(value)?);
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
    let mut upload_error = None;

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

        let header_end =
            find_subslice(&body[cursor..], b"\r\n\r\n").ok_or_else(|| FormParseError {
                reason: "multipart part headers were not terminated correctly".to_string(),
            })?;
        if header_end > DEFAULT_MULTIPART_PART_HEADER_MAX_BYTES {
            return Err(FormParseError {
                reason: "multipart part headers exceeded maximum length".to_string(),
            });
        }
        let header_block =
            std::str::from_utf8(&body[cursor..cursor + header_end]).map_err(|_| {
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
        let disposition =
            part_headers
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
        if field_name.is_empty() {
            return Err(FormParseError {
                reason: "multipart part field name must not be empty".to_string(),
            });
        }
        let filename = disposition.params.get("filename").cloned();

        match filename {
            Some(filename) => {
                if field_name != "attachment" && field_name != "image_attachment" {
                    return Err(FormParseError {
                        reason: "unsupported file field name".to_string(),
                    });
                }

                if filename.is_empty() && part_body.is_empty() {
                    continue;
                }

                let attachment_content_type = if field_name == "image_attachment" {
                    match image_attachment_content_type(part_body) {
                        Ok(content_type) => content_type,
                        Err(error) => {
                            upload_error.get_or_insert(error.reason);
                            continue;
                        }
                    }
                } else {
                    part_headers
                        .get("content-type")
                        .map(String::as_str)
                        .unwrap_or("application/octet-stream")
                };
                let attachment = match UploadedAttachment::new(
                    compose_policy,
                    filename,
                    attachment_content_type,
                    part_body.to_vec(),
                ) {
                    Ok(attachment) => attachment,
                    Err(error)
                        if field_name == "image_attachment"
                            && error.reason.starts_with("attachment filename") =>
                    {
                        upload_error.get_or_insert_with(|| {
                            "image attachment filename is not supported".to_string()
                        });
                        continue;
                    }
                    Err(error) => {
                        return Err(FormParseError {
                            reason: error.reason,
                        })
                    }
                };
                attachments.push(attachment);
            }
            None => {
                let value = String::from_utf8(part_body.to_vec()).map_err(|_| FormParseError {
                    reason: "multipart text field was not valid utf-8".to_string(),
                })?;
                if fields.contains_key(&field_name) {
                    return Err(FormParseError {
                        reason: format!("duplicate form field: {field_name}"),
                    });
                }
                fields.insert(field_name, value);
            }
        }
    }

    Ok(ParsedComposeForm {
        fields,
        attachments,
        upload_error,
    })
}

/// Recognizes the allowed local image signatures, not a full image decoder.
/// Declared MIME types and filename suffixes are not evidence of image format.
fn image_attachment_content_type(body: &[u8]) -> Result<&'static str, FormParseError> {
    if body.len() > 5 * 1024 * 1024 {
        return Err(FormParseError {
            reason: "image attachment exceeded 5 MiB maximum".to_string(),
        });
    }
    if body.starts_with(b"\x89PNG\r\n\x1a\n") {
        Ok("image/png")
    } else if body.starts_with(b"\xff\xd8\xff") {
        Ok("image/jpeg")
    } else if body.starts_with(b"GIF87a") || body.starts_with(b"GIF89a") {
        Ok("image/gif")
    } else {
        Err(FormParseError {
            reason: "image attachment must have a PNG, JPEG or GIF signature".to_string(),
        })
    }
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
    for (index, line) in header_block.split("\r\n").enumerate() {
        if index >= DEFAULT_MULTIPART_PART_HEADER_MAX_COUNT {
            return Err(FormParseError {
                reason: "multipart part contained too many headers".to_string(),
            });
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(FormParseError {
                reason: "multipart part header line was malformed".to_string(),
            });
        };
        let normalized_name = name.trim().to_ascii_lowercase();
        if normalized_name.is_empty()
            || normalized_name.len() > DEFAULT_MULTIPART_PART_HEADER_NAME_MAX_LEN
            || !normalized_name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(FormParseError {
                reason: "multipart part header name was invalid".to_string(),
            });
        }
        if headers.contains_key(&normalized_name) {
            return Err(FormParseError {
                reason: format!("duplicate multipart header: {normalized_name}"),
            });
        }
        let normalized_value = value.trim();
        if normalized_value.len() > DEFAULT_MULTIPART_PART_HEADER_VALUE_MAX_LEN {
            return Err(FormParseError {
                reason: "multipart part header value exceeded maximum length".to_string(),
            });
        }
        if normalized_value.chars().any(char::is_control) {
            return Err(FormParseError {
                reason: "multipart part header value contained control characters".to_string(),
            });
        }
        headers.insert(normalized_name, normalized_value.to_string());
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
        let parsed = parse_urlencoded_form(b"name=INBOX&uid=9", 4, 64).expect("form should parse");

        assert_eq!(parsed.get("name").map(String::as_str), Some("INBOX"));
        assert_eq!(parsed.get("uid").map(String::as_str), Some("9"));
    }

    #[test]
    fn rejects_duplicate_urlencoded_fields() {
        let error = parse_urlencoded_form(b"name=INBOX&name=Archive", 4, 64)
            .expect_err("duplicate fields must be rejected");

        assert_eq!(error.reason, "duplicate form field: name");
    }

    #[test]
    fn rejects_empty_urlencoded_field_names() {
        let error = parse_urlencoded_form(b"=value", 4, 64)
            .expect_err("empty field names must be rejected");

        assert_eq!(error.reason, "form field name must not be empty");
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

        assert_eq!(
            parsed.fields.get("to").map(String::as_str),
            Some("bob@example.com")
        );
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "report.txt");
    }

    fn parse_image_upload(bytes: &[u8]) -> Result<ParsedComposeForm, FormParseError> {
        let mut body = b"--image-test\r\nContent-Disposition: form-data; name=\"image_attachment\"; filename=\"picture.png\"\r\nContent-Type: image/png\r\n\r\n".to_vec();
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n--image-test--\r\n");
        parse_compose_form(
            &body,
            Some("multipart/form-data; boundary=image-test"),
            8,
            6 * 1024 * 1024,
            ComposePolicy::default(),
        )
    }

    #[test]
    fn image_upload_infers_format_from_signature_and_preserves_bytes() {
        // A one-pixel GIF, deliberately sent with a PNG suffix and MIME header.
        let gif = b"GIF89a\x01\0\x01\0\x80\0\0\0\0\0\xff\xff\xff!\xf9\x04\x01\0\0\0\0,\0\0\0\0\x01\0\x01\0\0\x02\x02D\x01\0;";
        let parsed = parse_image_upload(gif).expect("valid GIF upload");
        assert!(parsed.upload_error.is_none());
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename, "picture.png");
        assert_eq!(parsed.attachments[0].content_type, "image/gif");
        assert_eq!(parsed.attachments[0].body, gif);
        for (signature, expected) in [
            (b"\x89PNG\r\n\x1a\n".as_slice(), "image/png"),
            (b"\xff\xd8\xff".as_slice(), "image/jpeg"),
            (b"GIF87a".as_slice(), "image/gif"),
        ] {
            assert_eq!(
                parse_image_upload(signature).unwrap().attachments[0].content_type,
                expected
            );
        }
    }

    #[test]
    fn image_upload_rejects_disguised_and_incomplete_signatures() {
        for bytes in [
            b"<svg xmlns='http://www.w3.org/2000/svg'></svg>".as_slice(),
            b"%PDF-1.7",
            b"GIF89",
            b"\xff\xd8",
            b"\x89PNG\r\n",
            b"",
        ] {
            let parsed = parse_image_upload(bytes).expect("retain fields after image refusal");
            assert!(parsed.attachments.is_empty());
            assert_eq!(
                parsed.upload_error.as_deref(),
                Some("image attachment must have a PNG, JPEG or GIF signature")
            );
        }
    }

    #[test]
    fn image_upload_enforces_five_mib_boundary() {
        let mut bytes = vec![0_u8; 5 * 1024 * 1024];
        bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        assert_eq!(
            parse_image_upload(&bytes).unwrap().attachments[0]
                .body
                .len(),
            bytes.len()
        );
        bytes.push(0);
        let parsed = parse_image_upload(&bytes).unwrap();
        assert!(parsed.attachments.is_empty());
        assert_eq!(
            parsed.upload_error.as_deref(),
            Some("image attachment exceeded 5 MiB maximum")
        );
    }

    #[test]
    fn image_upload_error_retains_surrounding_fields_and_first_reason() {
        let body = concat!(
            "--recover\r\nContent-Disposition: form-data; name=\"subject\"\r\n\r\nPublic subject\r\n",
            "--recover\r\nContent-Disposition: form-data; name=\"image_attachment\"; filename=\"picture.png\"\r\n\r\nnot an image\r\n",
            "--recover\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\nPublic message retained\r\n",
            "--recover\r\nContent-Disposition: form-data; name=\"image_attachment\"; filename=\"../image.gif\"\r\n\r\nGIF89a\r\n",
            "--recover--\r\n"
        );
        let parse = |body: &str| {
            parse_compose_form(
                body.as_bytes(),
                Some("multipart/form-data; boundary=recover"),
                8,
                4096,
                ComposePolicy::default(),
            )
        };
        let parsed = parse(body).unwrap();
        assert_eq!(parsed.fields["subject"], "Public subject");
        assert_eq!(parsed.fields["body"], "Public message retained");
        assert!(parsed.attachments.is_empty());
        assert_eq!(
            parsed.upload_error.as_deref(),
            Some("image attachment must have a PNG, JPEG or GIF signature")
        );
        let name_only = body.replace("not an image", "GIF89a");
        assert_eq!(
            parse(&name_only).unwrap().upload_error.as_deref(),
            Some("image attachment filename is not supported")
        );
        assert!(parse(&body.replace("--recover--\r\n", "--recover--\r\ntrailing")).is_err());
        assert!(parse(&name_only.replace("image_attachment", "attachment")).is_err());
    }

    #[test]
    fn parses_urlencoded_compose_forms_with_charset_parameter() {
        let parsed = parse_compose_form(
            b"to=bob%40example.com&subject=Test",
            Some("application/x-www-form-urlencoded; charset=utf-8"),
            4,
            128,
            ComposePolicy::default(),
        )
        .expect("URL-encoded compose form with charset should parse");

        assert_eq!(
            parsed.fields.get("to").map(String::as_str),
            Some("bob@example.com")
        );
        assert!(parsed.attachments.is_empty());
    }

    #[test]
    fn parses_mixed_case_urlencoded_compose_content_type() {
        let parsed = parse_compose_form(
            b"subject=Test",
            Some("Application/X-WWW-Form-Urlencoded; Charset=UTF-8"),
            4,
            128,
            ComposePolicy::default(),
        )
        .expect("mixed-case URL-encoded compose content type should parse");

        assert_eq!(
            parsed.fields.get("subject").map(String::as_str),
            Some("Test")
        );
    }

    #[test]
    fn rejects_unsupported_compose_content_type() {
        for content_type in ["application/json", "text/plain"] {
            let error =
                parse_compose_form(b"{}", Some(content_type), 4, 128, ComposePolicy::default())
                    .expect_err("unsupported content type must fail");

            assert_eq!(
                error,
                FormParseError {
                    reason: "unsupported compose content-type".to_string(),
                }
            );
        }
    }

    #[test]
    fn rejects_duplicate_multipart_fields() {
        let body = concat!(
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "bob@example.com\r\n",
            "--test-boundary\r\n",
            "Content-Disposition: form-data; name=\"to\"\r\n\r\n",
            "alice@example.com\r\n",
            "--test-boundary--\r\n"
        );

        let error = parse_compose_form(
            body.as_bytes(),
            Some("multipart/form-data; boundary=test-boundary"),
            8,
            1024,
            ComposePolicy::default(),
        )
        .expect_err("duplicate multipart fields must be rejected");

        assert_eq!(error.reason, "duplicate form field: to");
    }

    #[test]
    fn rejects_oversized_multipart_part_header_blocks() {
        let oversized = "a".repeat(DEFAULT_MULTIPART_PART_HEADER_MAX_BYTES);
        let body = format!(
            "--test-boundary\r\nX-Oversized: {oversized}\r\n\r\nvalue\r\n--test-boundary--\r\n"
        );

        let error = parse_compose_form(
            body.as_bytes(),
            Some("multipart/form-data; boundary=test-boundary"),
            32,
            body.len(),
            ComposePolicy::default(),
        )
        .expect_err("oversized multipart headers must fail");

        assert_eq!(
            error.reason,
            "multipart part headers exceeded maximum length"
        );
    }

    #[test]
    fn rejects_excessive_multipart_part_header_counts() {
        let mut headers = String::new();
        for index in 0..=DEFAULT_MULTIPART_PART_HEADER_MAX_COUNT {
            headers.push_str(&format!("X-Test-{index}: value\r\n"));
        }
        let body = format!("--test-boundary\r\n{headers}\r\nvalue\r\n--test-boundary--\r\n");

        let error = parse_compose_form(
            body.as_bytes(),
            Some("multipart/form-data; boundary=test-boundary"),
            32,
            body.len(),
            ComposePolicy::default(),
        )
        .expect_err("excessive multipart headers must fail");

        assert_eq!(error.reason, "multipart part contained too many headers");
    }

    #[test]
    fn rejects_oversized_multipart_header_names_and_values() {
        let oversized_name = "x".repeat(DEFAULT_MULTIPART_PART_HEADER_NAME_MAX_LEN + 1);
        let name_body = format!(
            "--test-boundary\r\n{oversized_name}: value\r\n\r\nvalue\r\n--test-boundary--\r\n"
        );
        let name_error = parse_compose_form(
            name_body.as_bytes(),
            Some("multipart/form-data; boundary=test-boundary"),
            8,
            name_body.len(),
            ComposePolicy::default(),
        )
        .expect_err("oversized multipart header names must fail");

        let oversized_value = "x".repeat(DEFAULT_MULTIPART_PART_HEADER_VALUE_MAX_LEN + 1);
        let value_body = format!(
            "--test-boundary\r\nX-Test: {oversized_value}\r\n\r\nvalue\r\n--test-boundary--\r\n"
        );
        let value_error = parse_compose_form(
            value_body.as_bytes(),
            Some("multipart/form-data; boundary=test-boundary"),
            8,
            value_body.len(),
            ComposePolicy::default(),
        )
        .expect_err("oversized multipart header values must fail");

        assert_eq!(name_error.reason, "multipart part header name was invalid");
        assert_eq!(
            value_error.reason,
            "multipart part header value exceeded maximum length"
        );
    }
}
