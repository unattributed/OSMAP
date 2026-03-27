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
    pub size_hint_bytes: usize,
}

/// The result of MIME-aware inspection for one fetched message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeAnalysis {
    pub top_level_content_type: String,
    pub body_source: MimeBodySource,
    pub selected_plain_text_body: Option<String>,
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
    pub fn analyze_message(&self, message: &MessageView) -> Result<MimeAnalysis, MimeAnalysisError> {
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
            &content_type,
            extract_header_value(
                &unfolded_headers,
                "Content-Disposition",
                self.policy.header_value_max_len,
            )?
            .as_deref(),
            &message.body_text,
            "1",
            0,
        )?;

        Ok(MimeAnalysis {
            top_level_content_type: content_type.value,
            body_source: observation.body_source,
            selected_plain_text_body: observation.selected_plain_text_body,
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
            &content_type,
            extract_header_value(
                &unfolded_headers,
                "Content-Disposition",
                self.policy.header_value_max_len,
            )?
            .as_deref(),
            extract_header_value(
                &unfolded_headers,
                "Content-Transfer-Encoding",
                self.policy.header_value_max_len,
            )?
            .as_deref(),
            &message.body_text,
            "1",
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

/// Recursively analyzes one MIME entity while preserving conservative bounds.
fn analyze_entity(
    policy: MimeAnalysisPolicy,
    content_type: &ParsedHeaderValue,
    disposition_header: Option<&str>,
    body_text: &str,
    part_path: &str,
    depth: usize,
) -> Result<EntityObservation, MimeAnalysisError> {
    let disposition = parse_header_value(
        disposition_header.unwrap_or(""),
        policy,
    )?;
    let filename = extract_filename(policy, content_type, &disposition)?;
    let disposition_kind = classify_disposition(&disposition);

    // Multipart entities are inspected recursively, but only to a bounded
    // depth and part count so hostile messages cannot create unreviewable work.
    if content_type.value.starts_with("multipart/") {
        if depth >= policy.max_depth {
            return Ok(EntityObservation {
                body_source: MimeBodySource::MultipartStructureWithheld,
                selected_plain_text_body: None,
                contains_html_body: false,
                attachments: Vec::new(),
            });
        }

        let Some(boundary) = content_type.params.get("boundary") else {
            return Ok(EntityObservation {
                body_source: MimeBodySource::MultipartStructureWithheld,
                selected_plain_text_body: None,
                contains_html_body: false,
                attachments: Vec::new(),
            });
        };

        let parts = parse_multipart_parts(policy, boundary, body_text, part_path)?;
        let mut selected_plain_text_body = None;
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
                &part_content_type,
                extract_header_value(
                    &unfolded_headers,
                    "Content-Disposition",
                    policy.header_value_max_len,
                )?
                .as_deref(),
                &part.body_text,
                &part.part_path,
                depth + 1,
            )?;

            if selected_plain_text_body.is_none() {
                selected_plain_text_body = part_observation.selected_plain_text_body.clone();
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
            contains_html_body,
            attachments,
        });
    }

    if should_surface_as_attachment(&content_type.value, disposition_kind, filename.as_deref()) {
        return Ok(EntityObservation {
            body_source: MimeBodySource::AttachmentOnlyWithheld,
            selected_plain_text_body: None,
            contains_html_body: false,
            attachments: vec![AttachmentMetadata {
                part_path: part_path.to_string(),
                filename,
                content_type: content_type.value.clone(),
                disposition: disposition_kind,
                size_hint_bytes: body_text.len(),
            }],
        });
    }

    if content_type.value == "text/plain" || content_type.value.is_empty() {
        return Ok(EntityObservation {
            body_source: MimeBodySource::SinglePartPlainText,
            selected_plain_text_body: Some(body_text.to_string()),
            contains_html_body: false,
            attachments: Vec::new(),
        });
    }

    if content_type.value == "text/html" {
        return Ok(EntityObservation {
            body_source: MimeBodySource::HtmlWithheld,
            selected_plain_text_body: None,
            contains_html_body: true,
            attachments: Vec::new(),
        });
    }

    if body_text.trim().is_empty() {
        return Ok(EntityObservation {
            body_source: MimeBodySource::Empty,
            selected_plain_text_body: None,
            contains_html_body: false,
            attachments: Vec::new(),
        });
    }

    Ok(EntityObservation {
        body_source: MimeBodySource::BinaryWithheld,
        selected_plain_text_body: None,
        contains_html_body: false,
        attachments: Vec::new(),
    })
}

/// Recursively locates one surfaced attachment part by its dotted path.
fn find_attachment_part_in_entity(
    policy: MimeAnalysisPolicy,
    content_type: &ParsedHeaderValue,
    disposition_header: Option<&str>,
    transfer_encoding_header: Option<&str>,
    body_text: &str,
    part_path: &str,
    depth: usize,
    wanted_part_path: &str,
) -> Result<Option<AttachmentPart>, MimeAnalysisError> {
    let disposition = parse_header_value(disposition_header.unwrap_or(""), policy)?;
    let filename = extract_filename(policy, content_type, &disposition)?;
    let disposition_kind = classify_disposition(&disposition);

    if content_type.value.starts_with("multipart/") {
        if depth >= policy.max_depth {
            return Ok(None);
        }

        let Some(boundary) = content_type.params.get("boundary") else {
            return Ok(None);
        };

        for part in parse_multipart_parts(policy, boundary, body_text, part_path)? {
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
                &part_content_type,
                extract_header_value(
                    &unfolded_headers,
                    "Content-Disposition",
                    policy.header_value_max_len,
                )?
                .as_deref(),
                extract_header_value(
                    &unfolded_headers,
                    "Content-Transfer-Encoding",
                    policy.header_value_max_len,
                )?
                .as_deref(),
                &part.body_text,
                &part.part_path,
                depth + 1,
                wanted_part_path,
            )? {
                return Ok(Some(found));
            }
        }

        return Ok(None);
    }

    if part_path == wanted_part_path
        && should_surface_as_attachment(&content_type.value, disposition_kind, filename.as_deref())
    {
        return Ok(Some(AttachmentPart {
            metadata: AttachmentMetadata {
                part_path: part_path.to_string(),
                filename,
                content_type: content_type.value.clone(),
                disposition: disposition_kind,
                size_hint_bytes: body_text.len(),
            },
            transfer_encoding: normalize_transfer_encoding(transfer_encoding_header, policy)?,
            body_text: body_text.to_string(),
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

    if value.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(MimeAnalysisError {
            reason: "content-transfer-encoding contained unsupported characters".to_string(),
        });
    }

    Ok(value)
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
    let filename = disposition
        .params
        .get("filename")
        .cloned()
        .or_else(|| content_type.params.get("name").cloned());

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
                parts.push(build_parsed_part(policy, parent_part_path, parts.len() + 1, &current_lines)?);
                current_lines.clear();
            }
            inside_part = true;
            continue;
        }

        if line == closing_delimiter {
            if inside_part && !current_lines.is_empty() {
                parts.push(build_parsed_part(policy, parent_part_path, parts.len() + 1, &current_lines)?);
            }
            break;
        }

        if inside_part {
            current_lines.push(line.to_string());
        }
    }

    if parts.len() > policy.max_parts {
        return Err(MimeAnalysisError {
            reason: format!(
                "mime part count exceeded maximum of {}",
                policy.max_parts
            ),
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
        assert!(analysis.attachments.is_empty());
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
        assert!(analysis.contains_html_body);
        assert_eq!(analysis.attachments.len(), 1);
        assert_eq!(analysis.attachments[0].part_path, "1.2");
        assert_eq!(
            analysis.attachments[0].disposition,
            AttachmentDisposition::Inline
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
        assert_eq!(part.transfer_encoding, "base64");
        assert_eq!(part.body_text, "SGVsbG8=");
    }
}
