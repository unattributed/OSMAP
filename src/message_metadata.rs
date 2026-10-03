//! Bounded message identity and attachment metadata from structured native data.
//!
//! GUIDs identify stored objects, not users or authorization. Every operation
//! must still bind the authenticated account, mailbox and UID on the server.

use crate::mailbox::MailboxBackendError;

pub const MAX_MESSAGE_GUID_BYTES: usize = 256;
pub const MAX_BODYSTRUCTURE_BYTES: usize = 16 * 1024;
pub const MAX_MESSAGE_PREVIEW_CHARS: usize = 160;
pub const MAX_MESSAGE_PREVIEW_BYTES: usize = MAX_MESSAGE_PREVIEW_CHARS * 4;
pub const MAX_PUBLIC_ATTACHMENTS: usize = 8;
pub const MAX_ATTACHMENT_FILENAME_BYTES: usize = 255;
const MAX_STRUCTURE_DEPTH: usize = 16;
const MAX_STRUCTURE_NODES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageVersion {
    pub mailbox_guid: String,
    pub message_guid: String,
}

impl MessageVersion {
    pub fn new(mailbox_guid: String, message_guid: String) -> Result<Self, MailboxBackendError> {
        if mailbox_guid.len() != 32
            || !mailbox_guid.bytes().all(|byte| byte.is_ascii_hexdigit())
            || message_guid.is_empty()
            || message_guid.len() > MAX_MESSAGE_GUID_BYTES
            || !message_guid.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(MailboxBackendError {
                backend: "message-metadata",
                reason: "native message identity is invalid or outside its bounds".into(),
            });
        }
        Ok(Self {
            mailbox_guid: mailbox_guid.to_ascii_lowercase(),
            message_guid,
        })
    }
}

/// Public outer MIME classification, not signature verification or decryption.
/// Plain means no recognized outer OpenPGP MIME envelope; it does not rule out
/// inline OpenPGP or protected content inside another MIME container.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MessageProtection {
    #[default]
    Unknown,
    Plain,
    Signed,
    Encrypted,
}

impl MessageProtection {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "plain" => Some(Self::Plain),
            "signed" => Some(Self::Signed),
            "encrypted" => Some(Self::Encrypted),
            _ => None,
        }
    }

    pub fn value(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Plain => "plain",
            Self::Signed => "signed",
            Self::Encrypted => "encrypted",
        }
    }
}

/// Bounded public MIME part metadata. The size is the transfer-encoded native
/// BODYSTRUCTURE octet count, not the size of a decoded attachment download.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentSummary {
    /// Ordinary supported public name; missing/encoded/ambiguous names stay None.
    pub filename: Option<String>,
    pub encoded_size_bytes: u64,
}

fn valid_attachment_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ATTACHMENT_FILENAME_BYTES
        && !value.contains("=?")
        && !value.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

/// Check an inventory against its independent count before transporting it.
/// None filenames are an explicit unknown name, not an invalid inventory.
pub fn validate_attachment_summaries(
    summaries: &[AttachmentSummary],
    count: Option<usize>,
) -> bool {
    summaries.len() <= MAX_PUBLIC_ATTACHMENTS
        && count == Some(summaries.len())
        && summaries.iter().all(|summary| {
            summary
                .filename
                .as_deref()
                .is_none_or(valid_attachment_filename)
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMetadata {
    pub version: MessageVersion,
    /// None means unsupported/invalid/over-limit BODYSTRUCTURE, never zero.
    pub attachment_count: Option<usize>,
    /// None means unavailable/over-limit details, independently of total count.
    pub attachments: Option<Vec<AttachmentSummary>>,
    /// Classification of the outer public MIME structure only.
    pub protection: MessageProtection,
    /// Bounded native text snippet; absent for unknown or protected content.
    pub preview: Option<String>,
}

/// Read/star operations accept an explicit desired state, never a blind toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageFlag {
    Seen,
    Flagged,
}

impl MessageFlag {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "seen" => Some(Self::Seen),
            "flagged" => Some(Self::Flagged),
            _ => None,
        }
    }

    pub fn value(self) -> &'static str {
        match self {
            Self::Seen => "seen",
            Self::Flagged => "flagged",
        }
    }

    pub fn imap(self) -> &'static str {
        match self {
            Self::Seen => "\\Seen",
            Self::Flagged => "\\Flagged",
        }
    }
}

#[derive(Debug)]
enum Node {
    Value(String),
    List(Vec<Node>),
}

impl Node {
    fn value(&self) -> Option<&str> {
        match self {
            Self::Value(value) => Some(value),
            Self::List(_) => None,
        }
    }
}

struct StructureParser<'a> {
    input: &'a [u8],
    position: usize,
    nodes: usize,
}

impl StructureParser<'_> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn node(&mut self, depth: usize) -> Option<Node> {
        self.nodes += 1;
        if depth > MAX_STRUCTURE_DEPTH || self.nodes > MAX_STRUCTURE_NODES {
            return None;
        }
        self.whitespace();
        let first = *self.input.get(self.position)?;
        self.position += 1;
        match first {
            b'(' => {
                let mut items = Vec::new();
                loop {
                    self.whitespace();
                    if self.input.get(self.position) == Some(&b')') {
                        self.position += 1;
                        return Some(Node::List(items));
                    }
                    items.push(self.node(depth + 1)?);
                }
            }
            b'"' => {
                let mut value = Vec::new();
                loop {
                    let byte = *self.input.get(self.position)?;
                    self.position += 1;
                    match byte {
                        b'"' => return String::from_utf8(value).ok().map(Node::Value),
                        b'\\' => {
                            let escaped = *self.input.get(self.position)?;
                            if !matches!(escaped, b'"' | b'\\') {
                                return None;
                            }
                            self.position += 1;
                            value.push(escaped);
                        }
                        b'\r' | b'\n' | 0 => return None,
                        _ => value.push(byte),
                    }
                }
            }
            b'{' => {
                let start = self.position;
                while self
                    .input
                    .get(self.position)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.position += 1;
                }
                let length = std::str::from_utf8(self.input.get(start..self.position)?)
                    .ok()?
                    .parse::<usize>()
                    .ok()?;
                if self.input.get(self.position..self.position + 3)? != b"}\r\n" {
                    return None;
                }
                self.position += 3;
                let end = self.position.checked_add(length)?;
                let value = std::str::from_utf8(self.input.get(self.position..end)?).ok()?;
                self.position = end;
                Some(Node::Value(value.to_string()))
            }
            b')' => None,
            _ => {
                let start = self.position - 1;
                while self
                    .input
                    .get(self.position)
                    .is_some_and(|byte| !byte.is_ascii_whitespace() && !matches!(byte, b'(' | b')'))
                {
                    self.position += 1;
                }
                let value = std::str::from_utf8(self.input.get(start..self.position)?).ok()?;
                if value
                    .bytes()
                    .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'"' | b'{' | b'}'))
                {
                    return None;
                }
                Some(Node::Value(value.to_string()))
            }
        }
    }
}

fn named_parameter(node: Option<&Node>, name: &str) -> bool {
    let Some(Node::List(parameters)) = node else {
        return false;
    };
    parameters.chunks_exact(2).any(|pair| {
        pair[0].value().is_some_and(|key| {
            key.eq_ignore_ascii_case(name)
                || key.to_ascii_lowercase().starts_with(&format!("{name}*"))
        }) && pair[1]
            .value()
            .is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("nil"))
    })
}

fn mime_token(value: &str) -> bool {
    !value.is_empty()
        && !value.eq_ignore_ascii_case("nil")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&byte))
}

fn parameters_valid(node: &Node) -> bool {
    match node {
        Node::Value(value) => value.eq_ignore_ascii_case("nil"),
        Node::List(parameters) => {
            !parameters.is_empty()
                && parameters.len() % 2 == 0
                && parameters.chunks_exact(2).all(|pair| {
                    pair[0].value().is_some_and(mime_token)
                        && pair[1]
                            .value()
                            .is_some_and(|value| !value.chars().any(char::is_control))
                })
        }
    }
}

fn disposition_valid(node: &Node) -> bool {
    match node {
        Node::Value(value) => value.eq_ignore_ascii_case("nil"),
        Node::List(fields) => {
            fields.len() == 2
                && fields[0].value().is_some_and(mime_token)
                && parameters_valid(&fields[1])
        }
    }
}

fn decimal(node: &Node) -> bool {
    node.value().is_some_and(|value| {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().is_ok()
    })
}

fn count_parts(node: &Node) -> Option<usize> {
    let Node::List(parts) = node else {
        return None;
    };
    if matches!(parts.first(), Some(Node::List(_))) {
        let mut children = parts
            .iter()
            .take_while(|part| matches!(part, Node::List(_)));
        let child_count = children.clone().count();
        if !mime_token(parts.get(child_count)?.value()?)
            || parts
                .get(child_count + 1)
                .is_some_and(|node| !parameters_valid(node))
            || parts
                .get(child_count + 2)
                .is_some_and(|node| !disposition_valid(node))
        {
            return None;
        }
        return children.try_fold(0usize, |total, child| {
            total.checked_add(count_parts(child)?)
        });
    }
    let kind = parts.first()?.value()?;
    let subtype = parts.get(1)?.value()?;
    if !mime_token(kind)
        || !mime_token(subtype)
        || !parameters_valid(parts.get(2)?)
        || parts.get(3)?.value().is_none()
        || parts.get(4)?.value().is_none()
        || !mime_token(parts.get(5)?.value()?)
        || !decimal(parts.get(6)?)
    {
        return None;
    }
    let disposition_index = if kind.eq_ignore_ascii_case("text") {
        if !decimal(parts.get(7)?) {
            return None;
        }
        9
    } else if kind.eq_ignore_ascii_case("message") && subtype.eq_ignore_ascii_case("rfc822") {
        if !matches!(parts.get(7), Some(Node::List(envelope)) if envelope.len() == 10)
            || count_parts(parts.get(8)?).is_none()
            || !decimal(parts.get(9)?)
        {
            return None;
        }
        11
    } else {
        8
    };
    if parts
        .get(disposition_index)
        .is_some_and(|node| !disposition_valid(node))
    {
        return None;
    }
    let disposition = match parts.get(disposition_index) {
        Some(Node::List(value)) => Some(value),
        _ => None,
    };
    // Match the existing reader's downloadable-part policy: explicit attachment,
    // a filename, or an image/application part. Never infer from multipart alone.
    let attachment = kind.eq_ignore_ascii_case("image")
        || kind.eq_ignore_ascii_case("application")
        || named_parameter(parts.get(2), "name")
        || disposition.is_some_and(|value| {
            value
                .first()
                .and_then(Node::value)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("attachment"))
                || named_parameter(value.get(1), "filename")
        });
    Some(usize::from(attachment))
}

fn parse_structure(bodystructure: &str) -> Option<Node> {
    if bodystructure.is_empty() || bodystructure.len() > MAX_BODYSTRUCTURE_BYTES {
        return None;
    }
    let mut parser = StructureParser {
        input: bodystructure.as_bytes(),
        position: 0,
        nodes: 0,
    };
    let mut values = Vec::new();
    loop {
        parser.whitespace();
        if parser.position == parser.input.len() {
            break;
        }
        values.push(parser.node(0)?);
    }
    // Native doveadm emits the BODYSTRUCTURE contents without its outer
    // parentheses. Also accept the fully parenthesized IMAP representation.
    let root = if values.len() == 1 && matches!(values.first(), Some(Node::List(_))) {
        values.pop()?
    } else {
        Node::List(values)
    };
    Some(root)
}

pub fn attachment_count(bodystructure: &str) -> Option<usize> {
    count_parts(&parse_structure(bodystructure)?)
}

fn simple_public_parameter(node: Option<&Node>, name: &str) -> Result<Option<String>, ()> {
    let Some(Node::List(parameters)) = node else {
        return Ok(None);
    };
    let mut found = None;
    for pair in parameters.chunks_exact(2) {
        let key = pair[0].value().ok_or(())?;
        // The existing RFC 2231 decoder belongs to the full MIME reader. This
        // public BODYSTRUCTURE inventory does not claim to decode extended names.
        if key.to_ascii_lowercase().starts_with(&format!("{name}*")) {
            return Err(());
        }
        if key.eq_ignore_ascii_case(name) {
            let value = pair[1].value().ok_or(())?;
            if found.is_some()
                || value.eq_ignore_ascii_case("nil")
                || !valid_attachment_filename(value)
            {
                return Err(());
            }
            found = Some(value.to_owned());
        }
    }
    Ok(found)
}

fn public_part_filename(parts: &[Node], disposition_index: usize) -> Option<String> {
    let disposition_parameters = match parts.get(disposition_index) {
        Some(Node::List(disposition)) => disposition.get(1),
        _ => None,
    };
    match simple_public_parameter(disposition_parameters, "filename") {
        Ok(Some(filename)) => Some(filename),
        // An ambiguous/encoded preferred declaration must not be silently
        // replaced by another name from Content-Type.
        Err(()) => None,
        Ok(None) => simple_public_parameter(parts.get(2), "name").ok().flatten(),
    }
}

fn collect_attachment_summaries(node: &Node, summaries: &mut Vec<AttachmentSummary>) -> Option<()> {
    let Node::List(parts) = node else {
        return None;
    };
    if matches!(parts.first(), Some(Node::List(_))) {
        for child in parts
            .iter()
            .take_while(|part| matches!(part, Node::List(_)))
        {
            collect_attachment_summaries(child, summaries)?;
        }
        return Some(());
    }
    // Preserve count_parts' existing surfaced-part contract. An encapsulated
    // message is considered as its outer part; its private inner parts are not
    // promoted into this summary list.
    if count_parts(node)? == 0 {
        return Some(());
    }
    if summaries.len() >= MAX_PUBLIC_ATTACHMENTS {
        return None;
    }
    let kind = parts.first()?.value()?;
    let subtype = parts.get(1)?.value()?;
    let disposition_index = if kind.eq_ignore_ascii_case("text") {
        9
    } else if kind.eq_ignore_ascii_case("message") && subtype.eq_ignore_ascii_case("rfc822") {
        11
    } else {
        8
    };
    summaries.push(AttachmentSummary {
        filename: public_part_filename(parts, disposition_index),
        encoded_size_bytes: parts.get(6)?.value()?.parse().ok()?,
    });
    Some(())
}

/// Extract only bounded public native part metadata, without reading bodies.
/// The count remains independent when the details inventory exceeds its cap.
pub fn attachment_summaries(bodystructure: Option<&str>) -> Option<Vec<AttachmentSummary>> {
    let structure = parse_structure(bodystructure?)?;
    let count = count_parts(&structure)?;
    if count > MAX_PUBLIC_ATTACHMENTS
        || !structure_values_safe(&structure)
        || !structure_extensions_valid(&structure)
    {
        return None;
    }
    let mut summaries = Vec::with_capacity(count);
    collect_attachment_summaries(&structure, &mut summaries)?;
    validate_attachment_summaries(&summaries, Some(count)).then_some(summaries)
}

fn structure_values_safe(node: &Node) -> bool {
    match node {
        Node::Value(value) => !value.chars().any(char::is_control),
        Node::List(values) => values.iter().all(structure_values_safe),
    }
}

fn structure_language_valid(node: &Node) -> bool {
    match node {
        Node::Value(value) => !value.is_empty(),
        Node::List(values) => {
            !values.is_empty()
                && values.iter().all(|value| {
                    value.value().is_some_and(|value| {
                        !value.is_empty() && !value.eq_ignore_ascii_case("nil")
                    })
                })
        }
    }
}

/// Validate known optional fields only for protection classification. Existing
/// attachment-count compatibility remains independent of this stricter profile.
fn structure_extensions_valid(node: &Node) -> bool {
    let Node::List(parts) = node else {
        return false;
    };
    if matches!(parts.first(), Some(Node::List(_))) {
        let children = parts
            .iter()
            .take_while(|part| matches!(part, Node::List(_)))
            .count();
        return parts[..children].iter().all(structure_extensions_valid)
            && parts.get(children + 3).is_none_or(structure_language_valid)
            && parts
                .get(children + 4)
                .is_none_or(|location| location.value().is_some());
    }
    let body_digest_index = if parts
        .first()
        .and_then(Node::value)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("text"))
    {
        8
    } else if mime_is(node, "message", "rfc822") {
        if !parts.get(8).is_some_and(structure_extensions_valid) {
            return false;
        }
        10
    } else {
        7
    };
    parts
        .get(body_digest_index)
        .is_none_or(|digest| digest.value().is_some())
        && parts
            .get(body_digest_index + 2)
            .is_none_or(structure_language_valid)
        && parts
            .get(body_digest_index + 3)
            .is_none_or(|location| location.value().is_some())
}

fn mime_is(node: &Node, kind: &str, subtype: &str) -> bool {
    let Node::List(parts) = node else {
        return false;
    };
    parts
        .first()
        .and_then(Node::value)
        .is_some_and(|value| value.eq_ignore_ascii_case(kind))
        && parts
            .get(1)
            .and_then(Node::value)
            .is_some_and(|value| value.eq_ignore_ascii_case(subtype))
}

fn protection_parameters(node: Option<&Node>) -> Option<(&str, Option<&str>)> {
    let Node::List(parameters) = node? else {
        return None;
    };
    let mut names = std::collections::HashSet::new();
    let mut protocol = None;
    let mut micalg = None;
    for pair in parameters.chunks_exact(2) {
        let name = pair[0].value()?;
        let value = pair[1].value()?;
        let normalized = name.to_ascii_lowercase();
        // RFC 2231 continuations do not establish an unambiguous protocol or
        // digest declaration in this bounded, supported outer-envelope profile.
        if !names.insert(normalized.clone())
            || normalized.starts_with("protocol*")
            || normalized.starts_with("micalg*")
        {
            return None;
        }
        if normalized == "protocol" {
            protocol = Some(value);
        } else if normalized == "micalg" {
            micalg = Some(value);
        }
    }
    Some((protocol?, micalg))
}

/// Classify bounded public BODYSTRUCTURE without reading bodies or using keys.
/// Only the outer envelope is classified. These values do not confirm valid
/// cryptographic packets, a signature, a decryptable message or plaintext.
pub fn message_protection(bodystructure: Option<&str>) -> MessageProtection {
    let Some(structure) = bodystructure.and_then(parse_structure) else {
        return MessageProtection::Unknown;
    };
    if count_parts(&structure).is_none()
        || !structure_values_safe(&structure)
        || !structure_extensions_valid(&structure)
    {
        return MessageProtection::Unknown;
    }
    let Node::List(parts) = &structure else {
        return MessageProtection::Unknown;
    };
    if matches!(parts.first(), Some(Node::List(_))) {
        let children = parts
            .iter()
            .take_while(|part| matches!(part, Node::List(_)))
            .count();
        let Some(subtype) = parts.get(children).and_then(Node::value) else {
            return MessageProtection::Unknown;
        };
        if subtype.eq_ignore_ascii_case("signed") || subtype.eq_ignore_ascii_case("encrypted") {
            if children != 2 {
                return MessageProtection::Unknown;
            }
            let Some((protocol, micalg)) = protection_parameters(parts.get(children + 1)) else {
                return MessageProtection::Unknown;
            };
            if subtype.eq_ignore_ascii_case("signed")
                && protocol.eq_ignore_ascii_case("application/pgp-signature")
                && micalg.is_some_and(|value| {
                    !value.is_empty() && value.split(',').all(|digest| mime_token(digest.trim()))
                })
                && mime_is(&parts[1], "application", "pgp-signature")
            {
                return MessageProtection::Signed;
            }
            if subtype.eq_ignore_ascii_case("encrypted")
                && protocol.eq_ignore_ascii_case("application/pgp-encrypted")
                && mime_is(&parts[0], "application", "pgp-encrypted")
                && mime_is(&parts[1], "application", "octet-stream")
            {
                return MessageProtection::Encrypted;
            }
            return MessageProtection::Unknown;
        }
        // Unsupported multipart subtypes are unknown; do not reclassify an
        // unfamiliar security envelope or malformed trailing representation.
        return if [
            "mixed",
            "alternative",
            "related",
            "digest",
            "parallel",
            "report",
        ]
        .iter()
        .any(|known| subtype.eq_ignore_ascii_case(known))
        {
            MessageProtection::Plain
        } else {
            MessageProtection::Unknown
        };
    }
    let Some(kind) = parts.first().and_then(Node::value) else {
        return MessageProtection::Unknown;
    };
    let Some(subtype) = parts.get(1).and_then(Node::value) else {
        return MessageProtection::Unknown;
    };
    if !["text", "image", "audio", "video", "application", "message"]
        .iter()
        .any(|supported| kind.eq_ignore_ascii_case(supported))
        || (kind.eq_ignore_ascii_case("message") && !subtype.eq_ignore_ascii_case("rfc822"))
    {
        return MessageProtection::Unknown;
    }
    let normalized = subtype.to_ascii_lowercase();
    if kind.eq_ignore_ascii_case("application")
        && (normalized == "pgp"
            || normalized.starts_with("pgp-")
            || normalized == "x-pgp"
            || normalized.starts_with("x-pgp-")
            || normalized.starts_with("pkcs7-")
            || normalized.starts_with("x-pkcs7-"))
    {
        // Bare or legacy security media types cannot establish the supported
        // outer envelope, and must not be labelled as ordinary MIME.
        return MessageProtection::Unknown;
    }
    MessageProtection::Plain
}

fn encrypted_part(node: &Node) -> bool {
    let Node::List(parts) = node else {
        return true;
    };
    if matches!(parts.first(), Some(Node::List(_))) {
        let mut children = parts
            .iter()
            .take_while(|part| matches!(part, Node::List(_)));
        let count = children.clone().count();
        return parts
            .get(count)
            .and_then(Node::value)
            .is_some_and(|subtype| subtype.eq_ignore_ascii_case("encrypted"))
            || children.any(encrypted_part);
    }
    if parts
        .first()
        .and_then(Node::value)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("message"))
        && parts
            .get(1)
            .and_then(Node::value)
            .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rfc822"))
    {
        return parts.get(8).is_none_or(encrypted_part);
    }
    parts
        .first()
        .and_then(Node::value)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("application"))
        && parts.get(1).and_then(Node::value).is_some_and(|subtype| {
            ["pgp-encrypted", "pkcs7-mime", "x-pkcs7-mime"]
                .iter()
                .any(|value| subtype.eq_ignore_ascii_case(value))
        })
}

pub fn valid_message_preview(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_MESSAGE_PREVIEW_BYTES
        && value.chars().count() <= MAX_MESSAGE_PREVIEW_CHARS
        && !value.chars().any(char::is_control)
        && !value.contains("-----BEGIN PGP")
}

/// Native Dovecot computes the snippet without a per-row body fetch. It is
/// always untrusted text; the UI must escape it and must not infer sender trust.
pub fn message_preview(preview: Option<&str>, bodystructure: Option<&str>) -> Option<String> {
    let raw = preview?;
    if raw.len() > 4096 || raw.chars().any(|ch| ch.is_control() && !ch.is_whitespace()) {
        return None;
    }
    let structure = parse_structure(bodystructure?)?;
    count_parts(&structure)?;
    if encrypted_part(&structure) || raw.contains("-----BEGIN PGP") {
        return None;
    }
    let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let value = if normalized.chars().count() > MAX_MESSAGE_PREVIEW_CHARS {
        let mut value: String = normalized
            .chars()
            .take(MAX_MESSAGE_PREVIEW_CHARS - 1)
            .collect();
        value.push('…');
        value
    } else {
        normalized
    };
    valid_message_preview(&value).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_TEXT: &str =
        r#"("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 12 1 NIL NIL NIL NIL)"#;
    const PUBLIC_SIGNATURE: &str =
        r#"("application" "pgp-signature" NIL NIL NIL "7bit" 20 NIL NIL NIL NIL)"#;
    const PUBLIC_CONTROL: &str =
        r#"("application" "pgp-encrypted" NIL NIL NIL "7bit" 10 NIL NIL NIL NIL)"#;
    const PUBLIC_CIPHERTEXT: &str =
        r#"("application" "octet-stream" NIL NIL NIL "7bit" 28 NIL NIL NIL NIL)"#;

    fn public_signed(parameters: &str) -> String {
        format!("({PUBLIC_TEXT}{PUBLIC_SIGNATURE} \"signed\" {parameters} NIL NIL NIL)")
    }

    fn public_encrypted(parameters: &str) -> String {
        format!("({PUBLIC_CONTROL}{PUBLIC_CIPHERTEXT} \"encrypted\" {parameters} NIL NIL NIL)")
    }

    #[test]
    fn attachment_summaries_report_actual_public_names_and_encoded_octets() {
        let part = r#"("application" "octet-stream" ("name" "type-name.txt") NIL NIL "base64" 20 NIL ("attachment" ("filename" "public.txt")) NIL NIL)"#;
        let mixed = format!("({PUBLIC_TEXT}{part} \"mixed\" NIL NIL NIL NIL)");
        let expected = vec![AttachmentSummary {
            filename: Some("public.txt".into()),
            encoded_size_bytes: 20,
        }];
        assert_eq!(attachment_summaries(Some(&mixed)), Some(expected.clone()));
        assert_eq!(
            attachment_summaries(Some(&mixed[1..mixed.len() - 1])),
            Some(expected.clone())
        );
        assert_eq!(attachment_count(&mixed), Some(1));
        assert!(validate_attachment_summaries(&expected, Some(1)));
        assert_eq!(attachment_summaries(Some(PUBLIC_TEXT)), Some(vec![]));
        let eight = format!(
            "({} \"mixed\" NIL NIL NIL NIL)",
            part.repeat(MAX_PUBLIC_ATTACHMENTS)
        );
        assert_eq!(
            attachment_summaries(Some(&eight)).unwrap().len(),
            MAX_PUBLIC_ATTACHMENTS
        );
        let protected = public_encrypted(r#"("protocol" "application/pgp-encrypted")"#);
        let expected = vec![
            AttachmentSummary {
                filename: None,
                encoded_size_bytes: 10,
            },
            AttachmentSummary {
                filename: None,
                encoded_size_bytes: 28,
            },
        ];
        assert_eq!(attachment_summaries(Some(&protected)), Some(expected));
    }

    #[test]
    fn attachment_summaries_keep_encoded_or_ambiguous_names_unknown() {
        let part = r#"("application" "octet-stream" NIL NIL NIL "base64" 20 NIL ("attachment" ("filename" "NAME")) NIL NIL)"#;
        for name in [
            "",
            "=?utf-8?B?cHVibGlj?=",
            "left\u{202e}right",
            &"x".repeat(MAX_ATTACHMENT_FILENAME_BYTES + 1),
        ] {
            let structure = part.replace("NAME", name);
            assert_eq!(
                attachment_summaries(Some(&structure)),
                Some(vec![AttachmentSummary {
                    filename: None,
                    encoded_size_bytes: 20
                }])
            );
        }
        for parameters in [
            r#"("filename*" "utf-8''r%C3%A9sum%C3%A9.pdf")"#,
            r#"("filename*0*" "utf-8''public" "filename*1*" ".txt")"#,
            r#"("filename" "public.txt" "FILENAME" "other.txt")"#,
        ] {
            let structure = part.replace(r#"("filename" "NAME")"#, parameters);
            assert_eq!(
                attachment_summaries(Some(&structure)),
                Some(vec![AttachmentSummary {
                    filename: None,
                    encoded_size_bytes: 20
                }])
            );
        }
        // Control-bearing native parameter values are structurally invalid under
        // the existing parser profile, so the entire details inventory is unknown.
        assert_eq!(
            attachment_summaries(Some(&part.replace("NAME", "line\tbreak"))),
            None
        );
        let malicious = vec![AttachmentSummary {
            filename: Some("name\nspoof".into()),
            encoded_size_bytes: 20,
        }];
        assert!(!validate_attachment_summaries(&malicious, Some(1)));
        let unnamed = vec![AttachmentSummary {
            filename: None,
            encoded_size_bytes: u64::MAX,
        }];
        assert!(validate_attachment_summaries(&unnamed, Some(1)));
        assert!(!validate_attachment_summaries(&unnamed, None));
        assert!(!validate_attachment_summaries(&unnamed, Some(2)));
        assert!(!validate_attachment_summaries(
            &vec![unnamed[0].clone(); MAX_PUBLIC_ATTACHMENTS + 1],
            Some(MAX_PUBLIC_ATTACHMENTS + 1)
        ));
    }

    #[test]
    fn attachment_summaries_refuse_malformed_or_excessive_inventory_without_changing_count() {
        for structure in ["NIL", "(\"unterminated)", ""] {
            assert_eq!(attachment_summaries(Some(structure)), None);
        }
        assert_eq!(attachment_summaries(None), None);
        let too_many = format!(
            "({} \"mixed\" NIL NIL NIL NIL)",
            PUBLIC_CIPHERTEXT.repeat(MAX_PUBLIC_ATTACHMENTS + 1)
        );
        assert_eq!(
            attachment_count(&too_many),
            Some(MAX_PUBLIC_ATTACHMENTS + 1)
        );
        assert_eq!(attachment_summaries(Some(&too_many)), None);
        let invalid = PUBLIC_TEXT.replace("12 1 NIL NIL", "12 1 (\"invalid-digest\") NIL");
        assert_eq!(attachment_summaries(Some(&invalid)), None);
        assert_eq!(
            attachment_summaries(Some(&"x".repeat(MAX_BODYSTRUCTURE_BYTES + 1))),
            None
        );
    }

    #[test]
    fn protection_metadata_classifies_only_supported_outer_public_mime() {
        let signed =
            public_signed(r#"("protocol" "application/pgp-signature" "micalg" "pgp-sha256")"#);
        let encrypted = public_encrypted(r#"("protocol" "application/pgp-encrypted")"#);
        assert_eq!(message_protection(Some(&signed)), MessageProtection::Signed);
        assert_eq!(
            message_protection(Some(&encrypted)),
            MessageProtection::Encrypted
        );
        for (structure, expected) in [
            (PUBLIC_TEXT, MessageProtection::Plain),
            (&signed[1..signed.len() - 1], MessageProtection::Signed),
            (
                &encrypted[1..encrypted.len() - 1],
                MessageProtection::Encrypted,
            ),
        ] {
            assert_eq!(message_protection(Some(structure)), expected);
        }
        let mixed = format!("({PUBLIC_TEXT}{signed} \"mixed\" NIL NIL NIL NIL)");
        assert_eq!(message_protection(Some(&mixed)), MessageProtection::Plain);
        let signed_encrypted = format!(
            "({encrypted}{PUBLIC_SIGNATURE} \"signed\" (\"protocol\" \"application/pgp-signature\" \"micalg\" \"pgp-sha256\") NIL NIL NIL)"
        );
        assert_eq!(
            message_protection(Some(&signed_encrypted)),
            MessageProtection::Signed
        );
        let upper = signed
            .replace("signed", "SIGNED")
            .replace("protocol", "PROTOCOL")
            .replace("application/pgp-signature", "APPLICATION/PGP-SIGNATURE");
        assert_eq!(message_protection(Some(&upper)), MessageProtection::Signed);
        for value in [
            MessageProtection::Unknown,
            MessageProtection::Plain,
            MessageProtection::Signed,
            MessageProtection::Encrypted,
        ] {
            assert_eq!(MessageProtection::parse(value.value()), Some(value));
        }
        assert_eq!(MessageProtection::parse("verified"), None);
        assert_eq!(MessageProtection::parse("Signed"), None);
    }

    #[test]
    fn protection_metadata_refuses_ambiguous_unsupported_or_malformed_envelopes() {
        let signed_parameters = r#"("protocol" "application/pgp-signature" "micalg" "pgp-sha256")"#;
        let valid_signed = public_signed(signed_parameters);
        let invalid = [
            public_signed("NIL"),
            public_signed(r#"("protocol" "application/pkcs7-signature" "micalg" "sha256")"#),
            public_signed(
                r#"("protocol" "application/pgp-signature" "PROTOCOL" "application/pkcs7-signature" "micalg" "pgp-sha256")"#,
            ),
            public_signed(r#"("protocol*" "application/pgp-signature" "micalg" "pgp-sha256")"#),
            public_signed(r#"("protocol" "application/pgp-signature")"#),
            valid_signed.replace(PUBLIC_SIGNATURE, PUBLIC_TEXT),
            valid_signed.replace("\"signed\"", "\"signed\" NIL"),
            format!(
                "({PUBLIC_TEXT}{PUBLIC_SIGNATURE}{PUBLIC_SIGNATURE} \"signed\" {signed_parameters} NIL NIL NIL)"
            ),
            public_encrypted("NIL"),
            public_encrypted(r#"("protocol" "application/pkcs7-mime")"#),
            public_encrypted(
                r#"("protocol" "application/pgp-encrypted" "protocol" "application/pgp-encrypted")"#,
            ),
            public_encrypted(r#"("protocol" "application/pgp-encrypted")"#)
                .replace(PUBLIC_CONTROL, PUBLIC_TEXT),
            public_encrypted(r#"("protocol" "application/pgp-encrypted")"#)
                .replace(PUBLIC_CIPHERTEXT, PUBLIC_TEXT),
            PUBLIC_CONTROL.to_owned(),
            PUBLIC_SIGNATURE.to_owned(),
            r#"("application" "pgp" NIL NIL NIL "7bit" 10 NIL NIL NIL NIL)"#.to_owned(),
            r#"("application" "x-pgp-message" NIL NIL NIL "7bit" 10 NIL NIL NIL NIL)"#.to_owned(),
            r#"("unknown-kind" "plain" NIL NIL NIL "7bit" 10 NIL NIL NIL NIL)"#.to_owned(),
            format!("({PUBLIC_TEXT} \"unsupported\" NIL NIL NIL NIL)"),
            r#"("application" "pkcs7-mime" NIL NIL NIL "7bit" 10 NIL NIL NIL NIL)"#.to_owned(),
            PUBLIC_TEXT.replace("12 1", "bad 1"),
            PUBLIC_TEXT.replace("NIL NIL \"7bit\"", "NIL \"bad\tvalue\" \"7bit\""),
            "(\"unterminated)".to_owned(),
            "NIL".to_owned(),
        ];
        for structure in invalid {
            assert_eq!(
                message_protection(Some(&structure)),
                MessageProtection::Unknown,
                "{structure}"
            );
        }
        assert_eq!(message_protection(None), MessageProtection::Unknown);
        assert_eq!(message_protection(Some("")), MessageProtection::Unknown);
    }

    #[test]
    fn protection_metadata_rejects_malformed_optional_structure_extensions() {
        let signed =
            public_signed(r#"("protocol" "application/pgp-signature" "micalg" "pgp-sha256")"#);
        let encrypted = public_encrypted(r#"("protocol" "application/pgp-encrypted")"#);
        let invalid_md5 = PUBLIC_TEXT.replace("12 1 NIL NIL", "12 1 (\"invalid-list\") NIL");
        let invalid_control_md5 = PUBLIC_CONTROL.replace("10 NIL NIL", "10 (\"invalid-list\") NIL");
        for structure in [
            invalid_md5.clone(),
            signed.replace(PUBLIC_TEXT, &invalid_md5),
            encrypted.replace(PUBLIC_CONTROL, &invalid_control_md5),
            format!(
                "({PUBLIC_TEXT}{PUBLIC_SIGNATURE} \"signed\" (\"protocol\" \"application/pgp-signature\" \"micalg\" \"pgp-sha256\") NIL ((\"bad\")) NIL)"
            ),
            format!(
                "({PUBLIC_TEXT}{PUBLIC_SIGNATURE} \"signed\" (\"protocol\" \"application/pgp-signature\" \"micalg\" \"pgp-sha256\") NIL NIL (\"bad\"))"
            ),
            format!(
                "({PUBLIC_CONTROL}{PUBLIC_CIPHERTEXT} \"encrypted\" (\"protocol\" \"application/pgp-encrypted\") NIL ((\"bad\")) NIL)"
            ),
            format!(
                "({PUBLIC_CONTROL}{PUBLIC_CIPHERTEXT} \"encrypted\" (\"protocol\" \"application/pgp-encrypted\") NIL NIL (\"bad\"))"
            ),
        ] {
            assert_eq!(
                message_protection(Some(&structure)),
                MessageProtection::Unknown,
                "{structure}"
            );
        }
        let valid_extensions = PUBLIC_TEXT.replace(
            "12 1 NIL NIL NIL NIL",
            "12 1 \"synthetic-digest\" NIL (\"en\" \"fr\") \"public-location\"",
        );
        assert_eq!(
            message_protection(Some(&valid_extensions)),
            MessageProtection::Plain
        );
        let valid_outer_language = format!(
            "({PUBLIC_TEXT}{PUBLIC_SIGNATURE} \"signed\" (\"protocol\" \"application/pgp-signature\" \"micalg\" \"pgp-sha256\") NIL (\"en\" \"fr\") \"public-location\")"
        );
        assert_eq!(
            message_protection(Some(&valid_outer_language)),
            MessageProtection::Signed
        );
        let encapsulated = format!(
            "(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 100 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) {PUBLIC_TEXT} 3 NIL NIL NIL NIL)"
        );
        assert_eq!(
            message_protection(Some(&encapsulated)),
            MessageProtection::Plain
        );
        assert_eq!(
            message_protection(Some(&encapsulated.replace(PUBLIC_TEXT, &invalid_md5))),
            MessageProtection::Unknown
        );
        // Do not change the existing attachment-count compatibility contract.
        assert_eq!(attachment_count(&invalid_md5), Some(0));
    }

    #[test]
    fn protection_metadata_preserves_existing_parser_resource_bounds() {
        let mut deep = PUBLIC_TEXT.to_owned();
        for _ in 0..MAX_STRUCTURE_DEPTH + 1 {
            deep = format!("({deep} \"mixed\" NIL NIL NIL NIL)");
        }
        for structure in [
            deep,
            "x".repeat(MAX_BODYSTRUCTURE_BYTES + 1),
            "(".repeat(MAX_STRUCTURE_DEPTH + 2),
            format!("({})", "NIL ".repeat(MAX_STRUCTURE_NODES + 1)),
            format!(
                "{} extra",
                public_signed(r#"("protocol" "application/pgp-signature" "micalg" "pgp-sha256")"#)
            ),
        ] {
            assert_eq!(
                message_protection(Some(&structure)),
                MessageProtection::Unknown
            );
        }
    }

    #[test]
    fn previews_are_bounded_text_and_protected_content_stays_unknown() {
        let text = r#"("text" "plain" NIL NIL NIL "7bit" 12 1 NIL NIL NIL NIL)"#;
        assert_eq!(
            message_preview(Some("Public\n synthetic\tpreview"), Some(text)),
            Some("Public synthetic preview".into())
        );
        assert_eq!(
            message_preview(Some("<b>Untrusted</b>"), Some(text)),
            Some("<b>Untrusted</b>".into())
        );
        let long = message_preview(Some(&"é".repeat(200)), Some(text)).expect("bounded preview");
        assert_eq!(long.chars().count(), MAX_MESSAGE_PREVIEW_CHARS);
        assert!(long.ends_with('…'));
        for value in [
            "",
            "\0private",
            "-----BEGIN PGP MESSAGE-----",
            "-----BEGIN PGP SIGNED MESSAGE-----",
        ] {
            assert_eq!(message_preview(Some(value), Some(text)), None);
        }
        assert_eq!(
            message_preview(
                Some("untrusted"),
                Some(&format!("({text} \"encrypted\" NIL NIL NIL NIL)"))
            ),
            None
        );
        assert_eq!(message_preview(Some("untrusted"), Some("invalid")), None);
        assert_eq!(message_preview(Some(&"x".repeat(4097)), Some(text)), None);
    }

    #[test]
    fn stored_identity_is_bounded_and_message_guid_is_not_assumed_hex() {
        assert!(MessageVersion::new("a".repeat(32), "fixture.M123P456.obsd1".into()).is_ok());
        for bad in [
            "".into(),
            "x".repeat(257),
            "contains space".into(),
            "line\nbreak".into(),
        ] {
            assert!(MessageVersion::new("a".repeat(32), bad).is_err());
        }
        assert!(MessageVersion::new("g".repeat(32), "valid".into()).is_err());
        assert_eq!(MessageFlag::parse("deleted"), None);
    }

    #[test]
    fn bodystructure_counts_actual_attachment_metadata() {
        let text = r#"("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 12 1 NIL NIL NIL NIL)"#;
        let attachment = r#"("application" "octet-stream" ("name" "fixture.txt") NIL NIL "base64" 28 NIL ("attachment" ("filename" "fixture.txt")) NIL NIL)"#;
        assert_eq!(attachment_count(text), Some(0));
        assert_eq!(attachment_count(&text[1..text.len() - 1]), Some(0));
        assert_eq!(attachment_count(attachment), Some(1));
        assert_eq!(
            attachment_count(&format!("({text}{attachment} \"mixed\" NIL NIL NIL NIL)")),
            Some(1)
        );
        assert_eq!(
            attachment_count(&format!("{text}{attachment} \"mixed\" NIL NIL NIL NIL")),
            Some(1)
        );
        assert_eq!(
            attachment_count(&format!("({text}{text} \"alternative\" NIL NIL NIL NIL)")),
            Some(0)
        );
        let named_text = r#"("text" "plain" NIL NIL NIL "7bit" 10 1 NIL ("inline" ("filename*" "utf-8''note.txt")) NIL NIL)"#;
        assert_eq!(attachment_count(named_text), Some(1));
    }

    #[test]
    fn malformed_and_resource_heavy_structures_are_unknown() {
        for value in [
            "",
            "NIL",
            "()",
            "(\"text\")",
            "(\"unterminated)",
            "({999999999999999999999}\r\nx)",
            r#"("application" "pdf" NIL NIL NIL "base64" bad)"#,
            r#"("text" "plain" NIL NIL NIL "7bit" 10)"#,
            r#"("application" "pdf" ("name") NIL NIL "base64" 10)"#,
            r#"("application" "pdf" NIL NIL NIL "base64" 10 NIL ("attachment"))"#,
        ] {
            assert_eq!(attachment_count(value), None);
        }
        assert_eq!(attachment_count(&"(".repeat(100)), None);
        assert_eq!(
            attachment_count(&"x".repeat(MAX_BODYSTRUCTURE_BYTES + 1)),
            None
        );
        assert_eq!(
            attachment_count(&format!("({})", "NIL ".repeat(MAX_STRUCTURE_NODES + 1))),
            None
        );
    }
}
