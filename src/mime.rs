//! Conservative MIME analysis helpers for browser-safe message rendering.
//!
//! This module does not try to become a full mail client. Its job is smaller:
//! - classify the fetched message at a MIME-aware level
//! - select one safe plain-text body when that is straightforward
//! - surface attachment-like parts as metadata instead of rendering them
//! - keep malformed or hostile structures from silently widening trust

use std::collections::BTreeMap;

use crate::mailbox::MessageView;

/// Conservative upper bound for a parsed MIME header value.
pub const DEFAULT_MIME_HEADER_VALUE_MAX_LEN: usize = 4096;

/// Conservative upper bound for stored MIME media-type values.
pub const DEFAULT_MIME_TYPE_MAX_LEN: usize = 255;

/// Conservative upper bound for stored attachment file names.
pub const DEFAULT_MIME_FILENAME_MAX_LEN: usize = 255;

/// Conservative upper bound for one multipart boundary string.
pub const DEFAULT_MIME_BOUNDARY_MAX_LEN: usize = 200;

/// Conservative upper bound for the number of MIME parts inspected.
pub const DEFAULT_MIME_PARTS_MAX: usize = 64;

/// Conservative upper bound for nested multipart analysis depth.
pub const DEFAULT_MIME_NESTING_MAX_DEPTH: usize = 4;

/// Policy controlling the dependency-light MIME inspection layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MimeAnalysisPolicy {
    pub header_value_max_len: usize,
    pub mime_type_max_len: usize,
    pub filename_max_len: usize,
    pub boundary_max_len: usize,
    pub max_parts: usize,
    pub max_depth: usize,
}

impl Default for MimeAnalysisPolicy {
    fn default() -> Self {
        Self {
            header_value_max_len: DEFAULT_MIME_HEADER_VALUE_MAX_LEN,
            mime_type_max_len: DEFAULT_MIME_TYPE_MAX_LEN,
            filename_max_len: DEFAULT_MIME_FILENAME_MAX_LEN,
            boundary_max_len: DEFAULT_MIME_BOUNDARY_MAX_LEN,
            max_parts: DEFAULT_MIME_PARTS_MAX,
            max_depth: DEFAULT_MIME_NESTING_MAX_DEPTH,
        }
    }
}

/// Canonical attachment disposition used by later UI code and audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentDisposition {
    Attachment,
    Inline,
    Unspecified,
}

impl AttachmentDisposition {
    /// Returns the canonical string representation used in later layers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attachment => "attachment",
            Self::Inline => "inline",
            Self::Unspecified => "unspecified",
        }
    }
}

/// Canonical source used by the renderer to explain what body content is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeBodySource {
    SinglePartPlainText,
    MultipartPlainTextPart,
    HtmlSanitized,
    MultipartHtmlSanitized,
    HtmlWithheld,
    MultipartHtmlWithheld,
    AttachmentOnlyWithheld,
    BinaryWithheld,
    MultipartStructureWithheld,
    Empty,
}

impl MimeBodySource {
    /// Returns the canonical string representation used in logs and docs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SinglePartPlainText => "singlepart_plain_text",
            Self::MultipartPlainTextPart => "multipart_plain_text_part",
            Self::HtmlSanitized => "html_sanitized",
            Self::MultipartHtmlSanitized => "multipart_html_sanitized",
            Self::HtmlWithheld => "html_withheld",
            Self::MultipartHtmlWithheld => "multipart_html_withheld",
            Self::AttachmentOnlyWithheld => "attachment_only_withheld",
            Self::BinaryWithheld => "binary_withheld",
            Self::MultipartStructureWithheld => "multipart_structure_withheld",
            Self::Empty => "empty",
        }
    }
}

/// Attachment metadata surfaced without exposing raw content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMetadata {
    pub part_path: String,
    pub filename: Option<String>,
    pub content_type: String,
    pub disposition: AttachmentDisposition,
    pub content_id: Option<String>,
    pub size_hint_bytes: usize,
}

/// The result of MIME-aware inspection for one fetched message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeAnalysis {
    pub top_level_content_type: String,
    pub body_source: MimeBodySource,
    pub selected_plain_text_body: Option<String>,
    pub selected_html_body: Option<String>,
    pub contains_html_body: bool,
    pub attachments: Vec<AttachmentMetadata>,
}

/// One surfaced attachment part plus the raw body text needed for decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentPart {
    pub metadata: AttachmentMetadata,
    pub transfer_encoding: String,
    pub body_text: String,
}

/// Errors raised while validating MIME metadata into bounded shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeAnalysisError {
    pub reason: String,
}

/// Small analyzer that keeps MIME inspection separate from rendering.
pub struct MimeAnalyzer {
    policy: MimeAnalysisPolicy,
}

impl MimeAnalyzer {
    /// Creates a MIME analyzer from the supplied policy.
    pub fn new(policy: MimeAnalysisPolicy) -> Self {
        Self { policy }
    }

    /// Analyzes a fetched message without attempting browser rendering.
    pub fn analyze_message(
        &self,
        message: &MessageView,
    ) -> Result<MimeAnalysis, MimeAnalysisError> {
        let unfolded_headers = unfold_headers(&message.header_block);
        let content_type = parse_header_value(
            extract_header_value(
                &unfolded_headers,
                "Content-Type",
                self.policy.header_value_max_len,
            )?
            .as_deref()
            .unwrap_or("text/plain"),
            self.policy,
        )?;
        let observation = analyze_entity(
            self.policy,
            EntityAnalyzeInput {
                content_type: &content_type,
                disposition_header: extract_header_value(
                    &unfolded_headers,
                    "Content-Disposition",
                    self.policy.header_value_max_len,
                )?,
                content_id_header: extract_header_value(
                    &unfolded_headers,
                    "Content-ID",
                    self.policy.header_value_max_len,
                )?,
                transfer_encoding_header: extract_header_value(
                    &unfolded_headers,
                    "Content-Transfer-Encoding",
                    self.policy.header_value_max_len,
                )?,
                body_text: &message.body_text,
                part_path: "1",
            },
            0,
        )?;

        Ok(MimeAnalysis {
            top_level_content_type: content_type.value,
            body_source: observation.body_source,
            selected_plain_text_body: observation.selected_plain_text_body,
            selected_html_body: observation.selected_html_body,
            contains_html_body: observation.contains_html_body,
            attachments: observation.attachments,
        })
    }

    /// Finds one surfaced attachment part by dotted part path.
    pub fn find_attachment_part(
        &self,
        message: &MessageView,
        wanted_part_path: &str,
    ) -> Result<Option<AttachmentPart>, MimeAnalysisError> {
        let unfolded_headers = unfold_headers(&message.header_block);
        let content_type = parse_header_value(
            extract_header_value(
                &unfolded_headers,
                "Content-Type",
                self.policy.header_value_max_len,
            )?
            .as_deref()
            .unwrap_or("text/plain"),
            self.policy,
        )?;

        find_attachment_part_in_entity(
            self.policy,
            EntitySearchInput {
                content_type: &content_type,
                disposition_header: extract_header_value(
                    &unfolded_headers,
                    "Content-Disposition",
                    self.policy.header_value_max_len,
                )?,
                content_id_header: extract_header_value(
                    &unfolded_headers,
                    "Content-ID",
                    self.policy.header_value_max_len,
                )?,
                transfer_encoding_header: extract_header_value(
                    &unfolded_headers,
                    "Content-Transfer-Encoding",
                    self.policy.header_value_max_len,
                )?,
                body_text: &message.body_text,
                part_path: "1",
            },
            0,
            wanted_part_path,
        )
    }
}

/// Private normalized representation of one structured MIME header value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHeaderValue {
    value: String,
    params: BTreeMap<String, String>,
}

/// Private recursive observation used while walking MIME entities.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EntityObservation {
    body_source: MimeBodySource,
    selected_plain_text_body: Option<String>,
    selected_html_body: Option<String>,
    contains_html_body: bool,
    attachments: Vec<AttachmentMetadata>,
}

/// Private first-pass representation of one multipart child part.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPart {
    part_path: String,
    header_block: String,
    body_text: String,
}

/// Private recursive view of one MIME entity while analyzing renderable bodies.
struct EntityAnalyzeInput<'a> {
    content_type: &'a ParsedHeaderValue,
    disposition_header: Option<String>,
    content_id_header: Option<String>,
    transfer_encoding_header: Option<String>,
    body_text: &'a str,
    part_path: &'a str,
}

/// Private recursive view of one MIME entity while searching for attachments.
struct EntitySearchInput<'a> {
    content_type: &'a ParsedHeaderValue,
    disposition_header: Option<String>,
    content_id_header: Option<String>,
    transfer_encoding_header: Option<String>,
    body_text: &'a str,
    part_path: &'a str,
}

/// Recursively analyzes one MIME entity while preserving conservative bounds.
fn analyze_entity(
    policy: MimeAnalysisPolicy,
    entity: EntityAnalyzeInput<'_>,
    depth: usize,
) -> Result<EntityObservation, MimeAnalysisError> {
    let disposition =
        parse_header_value(entity.disposition_header.as_deref().unwrap_or(""), policy)?;
    let filename = extract_filename(policy, entity.content_type, &disposition)?;
    let disposition_kind = classify_disposition(&disposition);
    let content_id = normalize_content_id(entity.content_id_header.as_deref(), policy)?;

    // Multipart entities are inspected recursively, but only to a bounded
    // depth and part count so hostile messages cannot create unreviewable work.
    if entity.content_type.value.starts_with("multipart/") {
        if depth >= policy.max_depth {
            return Ok(EntityObservation {
                body_source: MimeBodySource::MultipartStructureWithheld,
                selected_plain_text_body: None,
                selected_html_body: None,
                contains_html_body: false,
                attachments: Vec::new(),
            });
        }

        let Some(boundary) = entity.content_type.params.get("boundary") else {
            return Ok(EntityObservation {
                body_source: MimeBodySource::MultipartStructureWithheld,
                selected_plain_text_body: None,
                selected_html_body: None,
                contains_html_body: false,
                attachments: Vec::new(),
            });
        };

        let parts = parse_multipart_parts(policy, boundary, entity.body_text, entity.part_path)?;
        let mut selected_plain_text_body = None;
        let mut selected_html_body = None;
        let mut contains_html_body = false;
        let mut attachments = Vec::new();

        for part in parts {
            let unfolded_headers = unfold_headers(&part.header_block);
            let part_content_type = parse_header_value(
                extract_header_value(
                    &unfolded_headers,
                    "Content-Type",
                    policy.header_value_max_len,
                )?
                .as_deref()
                .unwrap_or("text/plain"),
                policy,
            )?;
            let part_observation = analyze_entity(
                policy,
                EntityAnalyzeInput {
                    content_type: &part_content_type,
                    disposition_header: extract_header_value(
                        &unfolded_headers,
                        "Content-Disposition",
                        policy.header_value_max_len,
                    )?,
                    content_id_header: extract_header_value(
                        &unfolded_headers,
                        "Content-ID",
                        policy.header_value_max_len,
                    )?,
                    transfer_encoding_header: extract_header_value(
                        &unfolded_headers,
                        "Content-Transfer-Encoding",
                        policy.header_value_max_len,
                    )?,
                    body_text: &part.body_text,
                    part_path: &part.part_path,
                },
                depth + 1,
            )?;

            if selected_plain_text_body.is_none() {
                selected_plain_text_body = part_observation.selected_plain_text_body.clone();
            }
            if selected_html_body.is_none() {
                selected_html_body = part_observation.selected_html_body.clone();
            }

            contains_html_body |= part_observation.contains_html_body;
            attachments.extend(part_observation.attachments);
        }

        let body_source = if selected_plain_text_body.is_some() {
            MimeBodySource::MultipartPlainTextPart
        } else if contains_html_body {
            MimeBodySource::MultipartHtmlWithheld
        } else if !attachments.is_empty() {
            MimeBodySource::AttachmentOnlyWithheld
        } else {
            MimeBodySource::MultipartStructureWithheld
        };

        return Ok(EntityObservation {
            body_source,
            selected_plain_text_body,
            selected_html_body,
            contains_html_body,
            attachments,
        });
    }

    if should_surface_as_attachment(
        &entity.content_type.value,
        disposition_kind,
        filename.as_deref(),
    ) {
        return Ok(EntityObservation {
            body_source: MimeBodySource::AttachmentOnlyWithheld,
            selected_plain_text_body: None,
            selected_html_body: None,
            contains_html_body: false,
            attachments: vec![AttachmentMetadata {
                part_path: entity.part_path.to_string(),
                filename,
                content_type: entity.content_type.value.clone(),
                disposition: disposition_kind,
                content_id,
                size_hint_bytes: entity.body_text.len(),
            }],
        });
    }

    if entity.content_type.value == "text/plain" || entity.content_type.value.is_empty() {
        let Some(decoded_body) = decode_text_body(
            policy,
            entity.content_type,
            entity.transfer_encoding_header.as_deref(),
            entity.body_text,
        )?
        else {
            return Ok(EntityObservation {
                body_source: MimeBodySource::BinaryWithheld,
                selected_plain_text_body: None,
                selected_html_body: None,
                contains_html_body: false,
                attachments: Vec::new(),
            });
        };

        return Ok(EntityObservation {
            body_source: MimeBodySource::SinglePartPlainText,
            selected_plain_text_body: Some(decoded_body),
            selected_html_body: None,
            contains_html_body: false,
            attachments: Vec::new(),
        });
    }

    if entity.content_type.value == "text/html" {
        let Some(decoded_body) = decode_text_body(
            policy,
            entity.content_type,
            entity.transfer_encoding_header.as_deref(),
            entity.body_text,
        )?
        else {
            return Ok(EntityObservation {
                body_source: MimeBodySource::HtmlWithheld,
                selected_plain_text_body: None,
                selected_html_body: None,
                contains_html_body: true,
                attachments: Vec::new(),
            });
        };

        return Ok(EntityObservation {
            body_source: MimeBodySource::HtmlWithheld,
            selected_plain_text_body: None,
            selected_html_body: Some(decoded_body),
            contains_html_body: true,
            attachments: Vec::new(),
        });
    }

    if entity.body_text.trim().is_empty() {
        return Ok(EntityObservation {
            body_source: MimeBodySource::Empty,
            selected_plain_text_body: None,
            selected_html_body: None,
            contains_html_body: false,
            attachments: Vec::new(),
        });
    }

    Ok(EntityObservation {
        body_source: MimeBodySource::BinaryWithheld,
        selected_plain_text_body: None,
        selected_html_body: None,
        contains_html_body: false,
        attachments: Vec::new(),
    })
}

/// Recursively locates one surfaced attachment part by its dotted path.
fn find_attachment_part_in_entity(
    policy: MimeAnalysisPolicy,
    entity: EntitySearchInput<'_>,
    depth: usize,
    wanted_part_path: &str,
) -> Result<Option<AttachmentPart>, MimeAnalysisError> {
    let disposition =
        parse_header_value(entity.disposition_header.as_deref().unwrap_or(""), policy)?;
    let filename = extract_filename(policy, entity.content_type, &disposition)?;
    let disposition_kind = classify_disposition(&disposition);
    let content_id = normalize_content_id(entity.content_id_header.as_deref(), policy)?;

    if entity.content_type.value.starts_with("multipart/") {
        if depth >= policy.max_depth {
            return Ok(None);
        }

        let Some(boundary) = entity.content_type.params.get("boundary") else {
            return Ok(None);
        };

        for part in parse_multipart_parts(policy, boundary, entity.body_text, entity.part_path)? {
            let unfolded_headers = unfold_headers(&part.header_block);
            let part_content_type = parse_header_value(
                extract_header_value(
                    &unfolded_headers,
                    "Content-Type",
                    policy.header_value_max_len,
                )?
                .as_deref()
                .unwrap_or("text/plain"),
                policy,
            )?;

            if let Some(found) = find_attachment_part_in_entity(
                policy,
                EntitySearchInput {
                    content_type: &part_content_type,
                    disposition_header: extract_header_value(
                        &unfolded_headers,
                        "Content-Disposition",
                        policy.header_value_max_len,
                    )?,
                    content_id_header: extract_header_value(
                        &unfolded_headers,
                        "Content-ID",
                        policy.header_value_max_len,
                    )?,
                    transfer_encoding_header: extract_header_value(
                        &unfolded_headers,
                        "Content-Transfer-Encoding",
                        policy.header_value_max_len,
                    )?,
                    body_text: &part.body_text,
                    part_path: &part.part_path,
                },
                depth + 1,
                wanted_part_path,
            )? {
                return Ok(Some(found));
            }
        }

        return Ok(None);
    }

    if entity.part_path == wanted_part_path
        && should_surface_as_attachment(
            &entity.content_type.value,
            disposition_kind,
            filename.as_deref(),
        )
    {
        return Ok(Some(AttachmentPart {
            metadata: AttachmentMetadata {
                part_path: entity.part_path.to_string(),
                filename,
                content_type: entity.content_type.value.clone(),
                disposition: disposition_kind,
                content_id,
                size_hint_bytes: entity.body_text.len(),
            },
            transfer_encoding: normalize_transfer_encoding(
                entity.transfer_encoding_header.as_deref(),
                policy,
            )?,
            body_text: entity.body_text.to_string(),
        }));
    }

    Ok(None)
}

/// Parses one structured MIME header value plus its semicolon parameters.
fn parse_header_value(
    raw_value: &str,
    policy: MimeAnalysisPolicy,
) -> Result<ParsedHeaderValue, MimeAnalysisError> {
    let normalized = raw_value.trim();

    if normalized.len() > policy.header_value_max_len {
        return Err(MimeAnalysisError {
            reason: format!(
                "mime header value exceeded maximum length of {} bytes",
                policy.header_value_max_len
            ),
        });
    }

    if normalized.is_empty() {
        return Ok(ParsedHeaderValue {
            value: String::new(),
            params: BTreeMap::new(),
        });
    }

    let mut segments = normalized.split(';');
    let value = segments
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if value.len() > policy.mime_type_max_len {
        return Err(MimeAnalysisError {
            reason: format!(
                "mime media type exceeded maximum length of {} bytes",
                policy.mime_type_max_len
            ),
        });
    }

    let mut params = BTreeMap::new();
    for raw_param in segments {
        let Some((name, value)) = raw_param.split_once('=') else {
            continue;
        };

        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }

        let value = unquote_header_parameter(value.trim());
        if value.len() > policy.header_value_max_len {
            return Err(MimeAnalysisError {
                reason: format!(
                    "mime parameter value exceeded maximum length of {} bytes",
                    policy.header_value_max_len
                ),
            });
        }

        params.insert(name, value);
    }

    Ok(ParsedHeaderValue { value, params })
}

/// Normalizes one transfer-encoding header to a small lower-case token.
fn normalize_transfer_encoding(
    raw_value: Option<&str>,
    policy: MimeAnalysisPolicy,
) -> Result<String, MimeAnalysisError> {
    let value = raw_value.unwrap_or("").trim().to_ascii_lowercase();
    if value.len() > policy.header_value_max_len {
        return Err(MimeAnalysisError {
            reason: format!(
                "content-transfer-encoding exceeded maximum length of {} bytes",
                policy.header_value_max_len
            ),
        });
    }

    if value
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(MimeAnalysisError {
            reason: "content-transfer-encoding contained unsupported characters".to_string(),
        });
    }

    Ok(value)
}

/// Decodes a text body according to the small transfer-encoding set OSMAP
/// renders in-browser.
fn decode_text_body(
    policy: MimeAnalysisPolicy,
    content_type: &ParsedHeaderValue,
    transfer_encoding_header: Option<&str>,
    body_text: &str,
) -> Result<Option<String>, MimeAnalysisError> {
    let transfer_encoding = normalize_transfer_encoding(transfer_encoding_header, policy)?;
    let decoded_bytes = match transfer_encoding.as_str() {
        "" | "7bit" | "8bit" | "binary" => return Ok(Some(body_text.to_string())),
        "base64" => {
            let Some(decoded) = decode_base64_text_bytes(body_text) else {
                return Ok(None);
            };
            decoded
        }
        "quoted-printable" => {
            let Some(decoded) = decode_quoted_printable_text_bytes(body_text) else {
                return Ok(None);
            };
            decoded
        }
        _ => return Ok(None),
    };

    Ok(decode_text_bytes_with_charset(
        content_type
            .params
            .get("charset")
            .map(String::as_str)
            .unwrap_or("utf-8"),
        &decoded_bytes,
    ))
}

/// Decodes base64 text bodies without accepting invalid padding or characters.
fn decode_base64_text_bytes(input: &str) -> Option<Vec<u8>> {
    let cleaned = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();

    if cleaned.is_empty() {
        return Some(Vec::new());
    }

    if cleaned.len() % 4 != 0 {
        return None;
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
                        return None;
                    }
                }
                _ => return None,
            }
        }

        if padding == 1 && chunk[3] != b'=' {
            return None;
        }
        if padding == 2 && !(chunk[2] == b'=' && chunk[3] == b'=') {
            return None;
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
    }

    Some(output)
}

/// Decodes quoted-printable text bodies for selected renderable parts.
fn decode_quoted_printable_text_bytes(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'=' {
            if index + 1 >= bytes.len() {
                return None;
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
                return None;
            }

            output.push((hex_value(bytes[index + 1])? << 4) | hex_value(bytes[index + 2])?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    Some(output)
}

/// Decodes text body bytes for a narrow set of common charsets.
fn decode_text_bytes_with_charset(charset: &str, bytes: &[u8]) -> Option<String> {
    let charset = charset.trim().to_ascii_lowercase();
    match charset.as_str() {
        "utf-8" | "utf8" => String::from_utf8(bytes.to_vec()).ok(),
        "us-ascii" | "ascii" => {
            if bytes.is_ascii() {
                Some(String::from_utf8_lossy(bytes).into_owned())
            } else {
                None
            }
        }
        "iso-8859-1" | "latin1" | "latin-1" => {
            Some(bytes.iter().map(|byte| char::from(*byte)).collect())
        }
        _ => None,
    }
}

/// Extracts one unfolded header value from a header block by case-insensitive name.
fn extract_header_value(
    unfolded_headers: &str,
    wanted_name: &str,
    max_len: usize,
) -> Result<Option<String>, MimeAnalysisError> {
    for line in unfolded_headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case(wanted_name) {
                let value = value.trim().to_string();
                if value.len() > max_len {
                    return Err(MimeAnalysisError {
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

/// Unfolds RFC 5322 continuation lines conservatively before field lookup.
pub fn unfold_headers(header_block: &str) -> String {
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

/// Removes one layer of simple quoted-string syntax from a parameter value.
fn unquote_header_parameter(raw_value: &str) -> String {
    let trimmed = raw_value.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(trimmed);

    let mut result = String::with_capacity(unquoted.len());
    let mut escaping = false;

    for ch in unquoted.chars() {
        if escaping {
            result.push(ch);
            escaping = false;
        } else if ch == '\\' {
            escaping = true;
        } else {
            result.push(ch);
        }
    }

    result
}

/// Extracts a bounded attachment filename from MIME headers when present.
fn extract_filename(
    policy: MimeAnalysisPolicy,
    content_type: &ParsedHeaderValue,
    disposition: &ParsedHeaderValue,
) -> Result<Option<String>, MimeAnalysisError> {
    let filename = match extract_filename_parameter(policy, &disposition.params, "filename")? {
        Some(filename) => Some(filename),
        None => extract_filename_parameter(policy, &content_type.params, "name")?,
    };

    if let Some(filename) = filename {
        if filename.len() > policy.filename_max_len {
            return Err(MimeAnalysisError {
                reason: format!(
                    "attachment filename exceeded maximum length of {} bytes",
                    policy.filename_max_len
                ),
            });
        }

        if filename.chars().any(char::is_control) {
            return Err(MimeAnalysisError {
                reason: "attachment filename contained control characters".to_string(),
            });
        }

        return Ok(Some(filename));
    }

    Ok(None)
}

/// Extracts a simple or RFC 2231 extended filename-like parameter.
fn extract_filename_parameter(
    policy: MimeAnalysisPolicy,
    params: &BTreeMap<String, String>,
    base_name: &str,
) -> Result<Option<String>, MimeAnalysisError> {
    if let Some(value) = params.get(&format!("{base_name}*")) {
        return decode_rfc2231_extended_parameter(policy, value);
    }

    if let Some(value) = decode_rfc2231_continuation_parameter(policy, params, base_name)? {
        return Ok(Some(value));
    }

    Ok(params.get(base_name).cloned())
}

/// Decodes a bounded RFC 2231 single extended parameter value.
fn decode_rfc2231_extended_parameter(
    policy: MimeAnalysisPolicy,
    value: &str,
) -> Result<Option<String>, MimeAnalysisError> {
    let Some((charset, encoded_value)) = split_rfc2231_extended_parameter(value) else {
        return Ok(None);
    };

    decode_rfc2231_encoded_bytes(policy, &charset, encoded_value)
}

/// Decodes a bounded RFC 2231 continuation parameter set when present.
fn decode_rfc2231_continuation_parameter(
    policy: MimeAnalysisPolicy,
    params: &BTreeMap<String, String>,
    base_name: &str,
) -> Result<Option<String>, MimeAnalysisError> {
    let mut index = 0;
    let mut output = Vec::new();
    let mut charset = None;
    let mut found_any = false;

    loop {
        let encoded_key = format!("{base_name}*{index}*");
        let plain_key = format!("{base_name}*{index}");
        let (value, encoded) = if let Some(value) = params.get(&encoded_key) {
            (value, true)
        } else if let Some(value) = params.get(&plain_key) {
            (value, false)
        } else {
            break;
        };

        found_any = true;
        let segment = if encoded && index == 0 {
            let Some((decoded_charset, encoded_value)) = split_rfc2231_extended_parameter(value)
            else {
                return Ok(None);
            };
            charset = Some(decoded_charset);
            let Some(decoded_bytes) = percent_decode_bytes(encoded_value) else {
                return Ok(None);
            };
            decoded_bytes
        } else if encoded {
            let Some(decoded_bytes) = percent_decode_bytes(value) else {
                return Ok(None);
            };
            decoded_bytes
        } else {
            value.as_bytes().to_vec()
        };

        output.extend(segment);
        if output.len() > policy.filename_max_len {
            return Err(MimeAnalysisError {
                reason: format!(
                    "attachment filename exceeded maximum length of {} bytes",
                    policy.filename_max_len
                ),
            });
        }

        index += 1;
    }

    if !found_any {
        return Ok(None);
    }

    let decoded = match charset {
        Some(charset) => decode_rfc2231_bytes_with_charset(&charset, &output),
        None => String::from_utf8(output).ok(),
    };

    Ok(decoded)
}

/// Splits the `charset'language'value` shape used by RFC 2231 extended values.
fn split_rfc2231_extended_parameter(value: &str) -> Option<(String, &str)> {
    let mut segments = value.splitn(3, '\'');
    let charset = segments.next()?;
    let _language = segments.next()?;
    let encoded_value = segments.next()?;

    Some((charset.to_string(), encoded_value))
}

/// Percent-decodes an RFC 2231 value and converts the supported charset.
fn decode_rfc2231_encoded_bytes(
    policy: MimeAnalysisPolicy,
    charset: &str,
    encoded_value: &str,
) -> Result<Option<String>, MimeAnalysisError> {
    let Some(decoded_bytes) = percent_decode_bytes(encoded_value) else {
        return Ok(None);
    };
    let Some(decoded) = decode_rfc2231_bytes_with_charset(charset, &decoded_bytes) else {
        return Ok(None);
    };

    if decoded.len() > policy.filename_max_len {
        return Err(MimeAnalysisError {
            reason: format!(
                "attachment filename exceeded maximum length of {} bytes",
                policy.filename_max_len
            ),
        });
    }

    Ok(Some(decoded))
}

/// Percent-decodes an ASCII parameter body without accepting malformed escapes.
fn percent_decode_bytes(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            output.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    Some(output)
}

/// Decodes RFC 2231 parameter bytes for the same narrow charset set used by
/// the header-summary renderer.
fn decode_rfc2231_bytes_with_charset(charset: &str, bytes: &[u8]) -> Option<String> {
    let charset = charset.trim().to_ascii_lowercase();
    match charset.as_str() {
        "utf-8" | "utf8" => String::from_utf8(bytes.to_vec()).ok(),
        "us-ascii" | "ascii" => {
            if bytes.is_ascii() {
                Some(String::from_utf8_lossy(bytes).into_owned())
            } else {
                None
            }
        }
        "iso-8859-1" | "latin1" | "latin-1" => {
            Some(bytes.iter().map(|byte| char::from(*byte)).collect())
        }
        _ => None,
    }
}

/// Decodes one hexadecimal ASCII nibble used by RFC 2231 percent encoding.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Extracts one bounded Content-ID value without surrounding angle brackets.
fn normalize_content_id(
    raw_value: Option<&str>,
    policy: MimeAnalysisPolicy,
) -> Result<Option<String>, MimeAnalysisError> {
    let Some(raw_value) = raw_value else {
        return Ok(None);
    };

    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.len() > policy.header_value_max_len {
        return Err(MimeAnalysisError {
            reason: format!(
                "content-id exceeded maximum length of {} bytes",
                policy.header_value_max_len
            ),
        });
    }

    let normalized = trimmed
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(trimmed)
        .trim();

    if normalized.is_empty() {
        return Ok(None);
    }

    if normalized
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(MimeAnalysisError {
            reason: "content-id contained unsupported characters".to_string(),
        });
    }

    Ok(Some(normalized.to_string()))
}

/// Maps the disposition header into a bounded canonical enum.
fn classify_disposition(disposition: &ParsedHeaderValue) -> AttachmentDisposition {
    match disposition.value.as_str() {
        "attachment" => AttachmentDisposition::Attachment,
        "inline" => AttachmentDisposition::Inline,
        _ => AttachmentDisposition::Unspecified,
    }
}

/// Decides whether a part should be surfaced as attachment metadata.
fn should_surface_as_attachment(
    content_type: &str,
    disposition: AttachmentDisposition,
    filename: Option<&str>,
) -> bool {
    if disposition == AttachmentDisposition::Attachment {
        return true;
    }

    if filename.is_some() {
        return true;
    }

    if content_type.starts_with("image/") || content_type.starts_with("application/") {
        return true;
    }

    false
}

/// Parses only the first multipart layer so later code can recurse deliberately.
fn parse_multipart_parts(
    policy: MimeAnalysisPolicy,
    boundary: &str,
    body_text: &str,
    parent_part_path: &str,
) -> Result<Vec<ParsedPart>, MimeAnalysisError> {
    if boundary.is_empty() {
        return Ok(Vec::new());
    }

    if boundary.len() > policy.boundary_max_len {
        return Err(MimeAnalysisError {
            reason: format!(
                "mime boundary exceeded maximum length of {} bytes",
                policy.boundary_max_len
            ),
        });
    }

    let normalized = body_text.replace("\r\n", "\n").replace('\r', "\n");
    let delimiter = format!("--{boundary}");
    let closing_delimiter = format!("--{boundary}--");
    let mut parts = Vec::new();
    let mut current_lines: Vec<String> = Vec::new();
    let mut inside_part = false;

    // Multipart parsing is kept line-oriented and first-layer only so it stays
    // reviewable without pulling in a large MIME dependency this early.
    for line in normalized.split('\n') {
        if line == delimiter {
            if inside_part && !current_lines.is_empty() {
                parts.push(build_parsed_part(
                    policy,
                    parent_part_path,
                    parts.len() + 1,
                    &current_lines,
                )?);
                current_lines.clear();
            }
            inside_part = true;
            continue;
        }

        if line == closing_delimiter {
            if inside_part && !current_lines.is_empty() {
                parts.push(build_parsed_part(
                    policy,
                    parent_part_path,
                    parts.len() + 1,
                    &current_lines,
                )?);
            }
            break;
        }

        if inside_part {
            current_lines.push(line.to_string());
        }
    }

    if parts.len() > policy.max_parts {
        return Err(MimeAnalysisError {
            reason: format!("mime part count exceeded maximum of {}", policy.max_parts),
        });
    }

    Ok(parts)
}

/// Builds one parsed multipart child from the captured line buffer.
fn build_parsed_part(
    policy: MimeAnalysisPolicy,
    parent_part_path: &str,
    part_index: usize,
    lines: &[String],
) -> Result<ParsedPart, MimeAnalysisError> {
    let mut header_lines = Vec::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;

    for line in lines {
        if !in_body && line.is_empty() {
            in_body = true;
            continue;
        }

        if in_body {
            body_lines.push(line.clone());
        } else {
            header_lines.push(line.clone());
        }
    }

    let header_block = header_lines.join("\n");
    if header_block.len() > policy.header_value_max_len * 8 {
        return Err(MimeAnalysisError {
            reason: "mime part header block exceeded conservative bounds".to_string(),
        });
    }

    Ok(ParsedPart {
        part_path: format!("{parent_part_path}.{part_index}"),
        header_block,
        body_text: body_lines.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_view(header_block: &str, body_text: &str) -> MessageView {
        MessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-03-27 11:00:00 +0000".to_string(),
            size_virtual: 512,
            header_block: header_block.to_string(),
            body_text: body_text.to_string(),
        }
    }

    #[test]
    fn analyzes_singlepart_plain_text_messages() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: text/plain; charset=utf-8\n",
                "Hello world\n",
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.top_level_content_type, "text/plain");
        assert_eq!(analysis.body_source, MimeBodySource::SinglePartPlainText);
        assert_eq!(
            analysis.selected_plain_text_body.as_deref(),
            Some("Hello world\n")
        );
        assert!(analysis.selected_html_body.is_none());
        assert!(analysis.attachments.is_empty());
    }

    #[test]
    fn decodes_quoted_printable_plain_text_bodies() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                concat!(
                    "Subject: Test\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "Content-Transfer-Encoding: quoted-printable\n"
                ),
                "Ol=C3=A1=\n team\n",
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.body_source, MimeBodySource::SinglePartPlainText);
        assert_eq!(
            analysis.selected_plain_text_body.as_deref(),
            Some("Olá team\n")
        );
        assert!(analysis.selected_html_body.is_none());
    }

    #[test]
    fn decodes_base64_html_bodies() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                concat!(
                    "Subject: Test\n",
                    "Content-Type: text/html; charset=utf-8\n",
                    "Content-Transfer-Encoding: base64\n"
                ),
                "PHA+SGVsbG8gPHN0cm9uZz50ZWFtPC9zdHJvbmc+PC9wPg==\n",
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.body_source, MimeBodySource::HtmlWithheld);
        assert_eq!(
            analysis.selected_html_body.as_deref(),
            Some("<p>Hello <strong>team</strong></p>")
        );
        assert!(analysis.contains_html_body);
    }

    #[test]
    fn withholds_malformed_encoded_text_bodies_without_error() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                concat!(
                    "Subject: Test\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "Content-Transfer-Encoding: quoted-printable\n"
                ),
                "Hello=\n=",
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.body_source, MimeBodySource::BinaryWithheld);
        assert!(analysis.selected_plain_text_body.is_none());
        assert!(analysis.selected_html_body.is_none());
    }

    #[test]
    fn withholds_singlepart_html_messages() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: text/html; charset=utf-8\n",
                "<html><body>Hello</body></html>\n",
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.body_source, MimeBodySource::HtmlWithheld);
        assert!(analysis.selected_plain_text_body.is_none());
        assert_eq!(
            analysis.selected_html_body.as_deref(),
            Some("<html><body>Hello</body></html>\n")
        );
        assert!(analysis.contains_html_body);
    }

    #[test]
    fn selects_plain_text_from_multipart_alternative() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/alternative; boundary=\"alt-1\"\n",
                concat!(
                    "--alt-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Hello from text part\n",
                    "--alt-1\n",
                    "Content-Type: text/html; charset=utf-8\n",
                    "\n",
                    "<html><body>Hello from html part</body></html>\n",
                    "--alt-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.top_level_content_type, "multipart/alternative");
        assert_eq!(analysis.body_source, MimeBodySource::MultipartPlainTextPart);
        assert_eq!(
            analysis.selected_plain_text_body.as_deref(),
            Some("Hello from text part")
        );
        assert_eq!(
            analysis.selected_html_body.as_deref(),
            Some("<html><body>Hello from html part</body></html>")
        );
        assert!(analysis.contains_html_body);
    }

    #[test]
    fn surfaces_attachment_metadata_from_multipart_mixed_messages() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                concat!(
                    "--mix-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Hello from text part\n",
                    "--mix-1\n",
                    "Content-Type: application/pdf; name=\"report.pdf\"\n",
                    "Content-Disposition: attachment; filename=\"report.pdf\"\n",
                    "\n",
                    "%PDF-sample%\n",
                    "--mix-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.body_source, MimeBodySource::MultipartPlainTextPart);
        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(analysis.attachments[0].part_path, "1.2");
        assert_eq!(
            analysis.attachments[0].filename.as_deref(),
            Some("report.pdf")
        );
        assert_eq!(analysis.attachments[0].content_type, "application/pdf");
        assert_eq!(
            analysis.attachments[0].disposition,
            AttachmentDisposition::Attachment
        );
        assert_eq!(analysis.attachments[0].content_id.as_deref(), None);
    }

    #[test]
    fn decodes_rfc2231_attachment_filename_parameters() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                concat!(
                    "--mix-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Hello from text part\n",
                    "--mix-1\n",
                    "Content-Type: application/pdf\n",
                    "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\n",
                    "\n",
                    "%PDF-sample%\n",
                    "--mix-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(
            analysis.attachments[0].filename.as_deref(),
            Some("résumé.pdf")
        );
    }

    #[test]
    fn decodes_rfc2231_continued_attachment_filename_parameters() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                concat!(
                    "--mix-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Hello from text part\n",
                    "--mix-1\n",
                    "Content-Type: application/pdf\n",
                    "Content-Disposition: attachment; ",
                    "filename*0*=utf-8''quarterly-%E2%9C; ",
                    "filename*1*=%93-report.pdf\n",
                    "\n",
                    "%PDF-sample%\n",
                    "--mix-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(
            analysis.attachments[0].filename.as_deref(),
            Some("quarterly-✓-report.pdf")
        );
    }

    #[test]
    fn decodes_rfc2231_content_type_name_parameters() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                concat!(
                    "--mix-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Hello from text part\n",
                    "--mix-1\n",
                    "Content-Type: application/pdf; name*=iso-8859-1''caf%E9.pdf\n",
                    "Content-Disposition: attachment\n",
                    "\n",
                    "%PDF-sample%\n",
                    "--mix-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(
            analysis.attachments[0].filename.as_deref(),
            Some("café.pdf")
        );
    }

    #[test]
    fn surfaces_nested_attachment_metadata_from_common_multipart_layouts() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                concat!(
                    "--mix-1\n",
                    "Content-Type: multipart/alternative; boundary=\"alt-1\"\n",
                    "\n",
                    "--alt-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Plain text body\n",
                    "--alt-1\n",
                    "Content-Type: text/html; charset=utf-8\n",
                    "\n",
                    "<html><body>HTML body</body></html>\n",
                    "--alt-1--\n",
                    "--mix-1\n",
                    "Content-Type: image/png; name=\"diagram.png\"\n",
                    "Content-Disposition: inline; filename=\"diagram.png\"\n",
                    "\n",
                    "PNGDATA\n",
                    "--mix-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(
            analysis.selected_plain_text_body.as_deref(),
            Some("Plain text body")
        );
        assert_eq!(
            analysis.selected_html_body.as_deref(),
            Some("<html><body>HTML body</body></html>")
        );
        assert!(analysis.contains_html_body);
        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(analysis.attachments[0].part_path, "1.2");
        assert_eq!(
            analysis.attachments[0].disposition,
            AttachmentDisposition::Inline
        );
        assert_eq!(analysis.attachments[0].content_id.as_deref(), None);
    }

    #[test]
    fn surfaces_content_id_metadata_for_inline_image_parts() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let analysis = analyzer
            .analyze_message(&message_view(
                "Subject: Test\nContent-Type: multipart/related; boundary=\"rel-1\"\n",
                concat!(
                    "--rel-1\n",
                    "Content-Type: text/html; charset=utf-8\n",
                    "\n",
                    "<html><body><img src=\"cid:chart@example.com\"></body></html>\n",
                    "--rel-1\n",
                    "Content-Type: image/png; name=\"chart.png\"\n",
                    "Content-Disposition: inline; filename=\"chart.png\"\n",
                    "Content-ID: <chart@example.com>\n",
                    "\n",
                    "PNGDATA\n",
                    "--rel-1--\n",
                ),
            ))
            .expect("analysis should succeed");

        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(
            analysis.attachments[0].content_id.as_deref(),
            Some("chart@example.com")
        );
    }

    #[test]
    fn finds_attachment_part_by_path() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let part = analyzer
            .find_attachment_part(
                &message_view(
                    "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                    concat!(
                        "--mix-1\n",
                        "Content-Type: text/plain\n",
                        "\n",
                        "Hello\n",
                        "--mix-1\n",
                        "Content-Type: application/pdf\n",
                        "Content-Transfer-Encoding: base64\n",
                        "Content-Disposition: attachment; filename=\"report.pdf\"\n",
                        "\n",
                        "SGVsbG8=\n",
                        "--mix-1--\n",
                    ),
                ),
                "1.2",
            )
            .expect("lookup should succeed")
            .expect("attachment should exist");

        assert_eq!(part.metadata.filename.as_deref(), Some("report.pdf"));
        assert_eq!(part.metadata.content_id.as_deref(), None);
        assert_eq!(part.transfer_encoding, "base64");
        assert_eq!(part.body_text, "SGVsbG8=");
    }

    #[test]
    fn resolves_rfc2231_filename_when_finding_attachment_parts() {
        let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
        let part = analyzer
            .find_attachment_part(
                &message_view(
                    "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n",
                    concat!(
                        "--mix-1\n",
                        "Content-Type: text/plain\n",
                        "\n",
                        "Hello\n",
                        "--mix-1\n",
                        "Content-Type: application/pdf\n",
                        "Content-Transfer-Encoding: base64\n",
                        "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\n",
                        "\n",
                        "SGVsbG8=\n",
                        "--mix-1--\n",
                    ),
                ),
                "1.2",
            )
            .expect("lookup should succeed")
            .expect("attachment should exist");

        assert_eq!(part.metadata.filename.as_deref(), Some("résumé.pdf"));
        assert_eq!(part.transfer_encoding, "base64");
    }
}
