//! Bounded message identity and attachment metadata from structured native data.
//!
//! GUIDs identify stored objects, not users or authorization. Every operation
//! must still bind the authenticated account, mailbox and UID on the server.

use crate::mailbox::MailboxBackendError;

pub const MAX_MESSAGE_GUID_BYTES: usize = 256;
pub const MAX_BODYSTRUCTURE_BYTES: usize = 16 * 1024;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMetadata {
    pub version: MessageVersion,
    /// None means unsupported/invalid/over-limit BODYSTRUCTURE, never zero.
    pub attachment_count: Option<usize>,
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

pub fn attachment_count(bodystructure: &str) -> Option<usize> {
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
    count_parts(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

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
