//! Original-header reply metadata. No caller-provided field authorizes a read.
//! HTTP must first bind the original message to its authenticated account and
//! current stored identity; persisted metadata is accepted only from owned drafts.
use std::collections::BTreeMap;

pub const MAX_MESSAGE_ID_BYTES: usize = 254;
pub const MAX_REFERENCES: usize = 20;
pub const MAX_THREAD_INPUT_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyReference {
    pub mailbox_name: String,
    pub uid: u64,
    pub version: crate::message_metadata::MessageVersion,
}

impl ReplyReference {
    pub fn new(
        mailbox_name: String,
        uid: u64,
        version: crate::message_metadata::MessageVersion,
    ) -> Result<Self, &'static str> {
        if uid == 0 || uid > u64::from(u32::MAX) {
            return Err("reply UID is outside its bounds");
        }
        crate::mailbox::MessageViewRequest::new(
            crate::mailbox::MessageViewPolicy::default(),
            &mailbox_name,
            uid,
        )
        .map_err(|_| "reply mailbox is outside its bounds")?;
        let version = crate::message_metadata::MessageVersion::new(
            version.mailbox_guid,
            version.message_guid,
        )
        .map_err(|_| "reply stored identity is invalid")?;
        Ok(Self {
            mailbox_name,
            uid,
            version,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReplyMetadata {
    targets: Vec<String>,
    to: Vec<String>,
    cc: Vec<String>,
    pub thread: Option<ReplyThread>,
}

impl std::fmt::Debug for ReplyMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyMetadata")
            .field("target_count", &self.targets.len())
            .field("to_count", &self.to.len())
            .field("cc_count", &self.cc.len())
            .field("thread", &self.thread)
            .finish()
    }
}

impl ReplyMetadata {
    pub fn from_original(header_block: &str) -> Result<Self, &'static str> {
        let fields = original_fields(header_block)?;
        let addresses = |value: Option<&String>| {
            crate::mail_address::parse_address_list(
                crate::send::ComposePolicy::default(),
                value.map(String::as_str).unwrap_or_default(),
            )
            .map_err(|_| "original reply addresses require manual review")
        };
        Ok(Self {
            targets: addresses(fields.get("reply-to").or_else(|| fields.get("from")))?,
            to: addresses(fields.get("to"))?,
            cc: addresses(fields.get("cc"))?,
            thread: ReplyThread::from_original(header_block).ok(),
        })
    }

    pub fn reply_targets(&self) -> Vec<String> {
        crate::mail_address::deduplicate(&self.targets)
    }

    /// Only the known canonical sender is excluded. Do not invent aliases or
    /// local-part case equivalence that the receiving account authority owns.
    pub fn reply_all_targets(
        &self,
        sender: &str,
    ) -> Result<(Vec<String>, Vec<String>), &'static str> {
        crate::identity::MailboxIdentity::parse(sender)
            .map_err(|_| "reply-all sender identity is unavailable")?;
        let sender_key = crate::mail_address::comparison_key(sender);
        let to: Vec<_> = crate::mail_address::deduplicate(self.targets.iter().chain(&self.to))
            .into_iter()
            .filter(|address| crate::mail_address::comparison_key(address) != sender_key)
            .collect();
        let to_keys: std::collections::BTreeSet<_> = to
            .iter()
            .map(|address| crate::mail_address::comparison_key(address))
            .collect();
        let cc: Vec<_> = crate::mail_address::deduplicate(&self.cc)
            .into_iter()
            .filter(|address| {
                let key = crate::mail_address::comparison_key(address);
                key != sender_key && !to_keys.contains(&key)
            })
            .collect();
        if to.len() + cc.len() > crate::send::DEFAULT_MAX_RECIPIENTS {
            return Err("reply-all exceeds the recipient limit; choose recipients manually");
        }
        Ok((to, cc))
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ReplyThread {
    in_reply_to: Option<String>,
    references: Vec<String>,
    shortened: bool,
}

impl std::fmt::Debug for ReplyThread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplyThread")
            .field("has_parent", &self.in_reply_to.is_some())
            .field("reference_count", &self.references.len())
            .field("shortened", &self.shortened)
            .finish()
    }
}

impl ReplyThread {
    /// RFC 5322 section 3.6.4, bounded to one parent. Unsupported/duplicate
    /// fields refuse instead of selecting one of several possible parents.
    pub fn from_original(header_block: &str) -> Result<Self, &'static str> {
        let fields = original_fields(header_block)?;
        let parent = fields
            .get("message-id")
            .map(|value| message_id(value))
            .transpose()?;
        let mut references = match fields.get("references") {
            Some(value) => reference_ids(value)?,
            None => match fields.get("in-reply-to") {
                Some(value) => {
                    let ids = reference_ids(value)?;
                    if ids.len() == 1 {
                        ids
                    } else {
                        Vec::new()
                    }
                }
                None => Vec::new(),
            },
        };
        if let Some(parent) = &parent {
            references.retain(|id| id != parent);
            references.push(parent.clone());
        }
        let shortened = references.len() > MAX_REFERENCES;
        if shortened {
            let remove = references.len() - MAX_REFERENCES;
            // Retain the root plus the most recent ancestry and parent.
            references.drain(1..1 + remove);
        }
        Ok(Self {
            in_reply_to: parent,
            references,
            shortened,
        })
    }

    /// Restores validated metadata from an account-owned versioned draft.
    pub fn from_stored(
        parent: Option<&str>,
        references: &str,
        shortened: bool,
    ) -> Result<Self, &'static str> {
        let parent = parent.map(message_id).transpose()?;
        let references = reference_ids(references)?;
        if references.len() > MAX_REFERENCES {
            return Err("stored reply references exceeded their count limit");
        }
        Ok(Self {
            in_reply_to: parent,
            references,
            shortened,
        })
    }

    pub fn in_reply_to(&self) -> Option<&str> {
        self.in_reply_to.as_deref()
    }
    pub fn references(&self) -> String {
        self.references.join(" ")
    }
    pub fn shortened(&self) -> bool {
        self.shortened
    }
    pub fn is_empty(&self) -> bool {
        self.in_reply_to.is_none() && self.references.is_empty()
    }

    /// Only validated ID atoms reach headers; folding is generated here.
    pub fn header_lines(&self) -> String {
        let mut output = String::new();
        if let Some(parent) = &self.in_reply_to {
            output.push_str(&format!("In-Reply-To: {parent}\r\n"));
        }
        if !self.references.is_empty() {
            output.push_str("References:");
            let mut column = 11;
            for reference in &self.references {
                if column + 1 + reference.len() > 78 {
                    output.push_str("\r\n");
                    column = 0;
                }
                output.push(' ');
                output.push_str(reference);
                column += 1 + reference.len();
            }
            output.push_str("\r\n");
        }
        output
    }
}

pub fn message_id(value: &str) -> Result<String, &'static str> {
    let value = value.trim_matches([' ', '\t']);
    if value.len() > MAX_MESSAGE_ID_BYTES || !value.starts_with('<') || !value.ends_with('>') {
        return Err("message identifier is outside supported syntax or length");
    }
    let inner = &value[1..value.len() - 1];
    let Some((left, right)) = inner.split_once('@') else {
        return Err("message identifier has no domain separator");
    };
    let atom = |value: &str| {
        !value.is_empty()
            && value.split('.').all(|part| {
                !part.is_empty()
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
                    })
            })
    };
    let literal = right
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| (33..=90).contains(&byte) || (94..=126).contains(&byte))
        });
    if !atom(left) || !(atom(right) || literal) {
        return Err("message identifier contains unsupported characters");
    }
    Ok(value.into())
}

fn reference_ids(value: &str) -> Result<Vec<String>, &'static str> {
    if value.len() > MAX_THREAD_INPUT_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err("reply references contain invalid or excessive input");
    }
    let mut references = Vec::new();
    for value in value.split_ascii_whitespace() {
        if references.len() == 128 {
            return Err("reply references exceeded their parsing limit");
        }
        let id = message_id(value)?;
        if !references.contains(&id) {
            references.push(id);
        }
    }
    Ok(references)
}

/// Header names are case-insensitive. Duplicate origin/destination/threading
/// fields are ambiguous and never silently select a last or first value.
pub fn original_fields(header_block: &str) -> Result<BTreeMap<String, String>, &'static str> {
    if header_block.len() > crate::mailbox::MessageViewPolicy::default().message_header_max_len {
        return Err("original header block exceeded its limit");
    }
    let unfolded = crate::mime::unfold_headers(header_block);
    let mut fields = BTreeMap::new();
    for line in unfolded.lines() {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        if ![
            "from",
            "reply-to",
            "to",
            "cc",
            "message-id",
            "references",
            "in-reply-to",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        let value = value.trim();
        if value.len() > MAX_THREAD_INPUT_BYTES || value.chars().any(char::is_control) {
            return Err("original reply header exceeded its bounds");
        }
        if fields.insert(name, value.to_string()).is_some() {
            return Err("original reply header was duplicated");
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reply_all_honours_reply_to_and_deduplicates_without_guessing_self_aliases() {
        let metadata = ReplyMetadata::from_original("From: Original <original@example.test>\nReply-To: \"Reply, Desk\" <desk@example.test>, desk@EXAMPLE.TEST\nTo: Self <self@example.test>, Desk <desk@example.test>, Other <other@example.test>\nCc: copied@example.test, self@EXAMPLE.TEST, other@example.test, Self@example.test\nBcc: hidden@example.test\nMessage-ID: <parent@example.test>\n").unwrap();
        assert_eq!(metadata.reply_targets(), ["desk@example.test"]);
        let (to, cc) = metadata.reply_all_targets("self@example.test").unwrap();
        assert_eq!(to, ["desk@example.test", "other@example.test"]);
        assert_eq!(cc, ["copied@example.test", "Self@example.test"]);
        assert!(!format!("{metadata:?}").contains("example.test"));
        assert!(metadata.thread.is_some());
        let many = (0..16)
            .map(|i| format!("user{i}@example.test"))
            .collect::<Vec<_>>()
            .join(", ");
        let over =
            ReplyMetadata::from_original(&format!("From: sender@example.test\nTo: {many}\n"))
                .unwrap();
        assert!(over.reply_all_targets("self@example.test").is_err());
        for headers in [
            "From: group: a@example.test;\n",
            "From: a@example.test\nReply-To: bad\n",
            "From: a@example.test\nReply-To: x@example.test\nReply-To: y@example.test\n",
        ] {
            assert!(ReplyMetadata::from_original(headers).is_err());
        }
    }
    #[test]
    fn threading_uses_original_parent_and_references_with_the_rfc_fallback() {
        let thread = ReplyThread::from_original("Message-ID: <parent@example.test>\r\nReferences: <root@example.test>\r\n <previous@example.test>\r\n").unwrap();
        assert_eq!(thread.in_reply_to(), Some("<parent@example.test>"));
        assert_eq!(
            thread.references(),
            "<root@example.test> <previous@example.test> <parent@example.test>"
        );
        assert_eq!(
            ReplyThread::from_stored(
                thread.in_reply_to(),
                &thread.references(),
                thread.shortened()
            )
            .unwrap(),
            thread
        );
        let fallback = ReplyThread::from_original(
            "Message-ID: <p@example.test>\nIn-Reply-To: <root@example.test>\n",
        )
        .unwrap();
        assert_eq!(
            fallback.references(),
            "<root@example.test> <p@example.test>"
        );
        let multiple = ReplyThread::from_original(
            "Message-ID: <p@example.test>\nIn-Reply-To: <a@example.test> <b@example.test>\n",
        )
        .unwrap();
        assert_eq!(multiple.references(), "<p@example.test>");
        assert!(ReplyThread::from_original("Subject: No identifiers\n")
            .unwrap()
            .is_empty());
    }
    #[test]
    fn invalid_or_duplicate_metadata_never_creates_injected_headers() {
        for headers in [
            "Message-ID: <p@example.test>\nmessage-id: <q@example.test>\n",
            "Message-ID: <bad id@example.test>\n",
            "References: <valid@example.test> untrusted\n",
            "Message-ID: <a..b@example.test>\n",
            "To: a@example.test\nTo: b@example.test\n",
        ] {
            assert!(ReplyThread::from_original(headers).is_err());
        }
        for value in [
            "<p@example.test>\r\nBcc: other@example.test",
            "<p@example.test><q@example.test>",
            "<p@>",
            "<> ",
            "<p@(comment)>",
        ] {
            assert!(message_id(value).is_err());
        }
        let thread = ReplyThread::from_original("Message-ID: <p@[IPv6:2001:db8::1]>\n").unwrap();
        assert_eq!(thread.in_reply_to(), Some("<p@[IPv6:2001:db8::1]>"));
        assert!(!format!("{thread:?}").contains("2001"));
    }
    #[test]
    fn long_thread_history_retains_root_and_recent_parent_with_bounded_folding() {
        let references = (0..30)
            .map(|i| format!("<id-{i}@example.test>"))
            .collect::<Vec<_>>()
            .join(" ");
        let thread = ReplyThread::from_original(&format!(
            "Message-ID: <parent@example.test>\nReferences: {references}\n"
        ))
        .unwrap();
        assert!(thread.shortened());
        assert_eq!(
            thread
                .references
                .split_first()
                .map(|(first, _)| first.as_str()),
            Some("<id-0@example.test>")
        );
        assert_eq!(
            thread.references.last().map(String::as_str),
            Some("<parent@example.test>")
        );
        assert_eq!(thread.references.len(), MAX_REFERENCES);
        assert!(thread
            .header_lines()
            .split("\r\n")
            .all(|line| line.len() <= 78));
        assert_eq!(thread.header_lines().matches("References:").count(), 1);
    }
}
