//! Bounded foreground Inbox observations, not an arrival or plaintext monitor.
use crate::notifications::NotificationError;
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_IDENTITIES: usize = 1000;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxIdentity {
    pub uid: u64,
    pub message_guid: String,
}
pub struct InboxSnapshot<'a> {
    pub account: &'a str,
    pub mailbox_guid: &'a str,
    pub messages: &'a [InboxIdentity],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMessage {
    pub uid: u64,
    pub source_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxObservation {
    pub baseline: bool,
    pub messages: Vec<ObservedMessage>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    owner_ref: String,
    generation_ref: String,
    highest_uid: u64,
    highest_message_ref: Option<String>,
    high_water: u64,
}
#[derive(Clone)]
pub struct Store {
    file: PrivateAccountFile,
}
fn hash(domain: &[u8], account: &str, source: &str) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(b"\0");
    h.update(account.as_bytes());
    h.update(b"\0");
    h.update(source.as_bytes());
    format!("{:x}", h.finalize())
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(root.into(), "osmap-notification-observation-v1", 1024),
        }
    }
    /// First observation and a different native mailbox generation establish a
    /// baseline. Higher UIDs are observations, not evidence of delivery time.
    /// Cursor publication precedes return: separate notice publication can fail
    /// and must be reported by its caller, never retried as a mailbox mutation.
    pub fn observe_inbox(
        &self,
        account: &str,
        snapshot: InboxSnapshot<'_>,
        now: u64,
    ) -> Result<InboxObservation, NotificationError> {
        crate::identity::CanonicalUsername::parse(account)
            .map_err(|_| NotificationError::Invalid)?;
        if snapshot.account != account
            || now == 0
            || snapshot.messages.len() > MAX_IDENTITIES
            || snapshot.mailbox_guid.len() != 32
            || !snapshot.mailbox_guid.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(NotificationError::Invalid);
        }
        let mut uids = HashSet::new();
        let mut guids = HashSet::new();
        for message in snapshot.messages {
            if message.uid == 0
                || message.uid > u32::MAX as u64
                || message.message_guid.is_empty()
                || message.message_guid.len() > crate::message_metadata::MAX_MESSAGE_GUID_BYTES
                || !message.message_guid.bytes().all(|b| b.is_ascii_graphic())
                || !uids.insert(message.uid)
                || !guids.insert(&message.message_guid)
            {
                return Err(NotificationError::Invalid);
            }
        }
        let owner = hash(b"observation-owner-v1", account, "");
        let generation = hash(
            b"observation-generation-v1",
            account,
            &snapshot.mailbox_guid.to_ascii_lowercase(),
        );
        let deadline = Instant::now() + Duration::from_millis(500);
        let lock = loop {
            match self.file.lock(account) {
                Ok(lock) => break lock,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(NotificationError::Unavailable),
            }
        };
        let old: Option<Cursor> = lock
            .read()
            .map_err(|_| NotificationError::Unavailable)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| NotificationError::Corrupt))
            .transpose()?;
        if let Some(old) = &old {
            if old.version != 1
                || old.owner_ref != owner
                || !hex(&old.generation_ref)
                || old.highest_uid > u32::MAX as u64
                || old.high_water == 0
                || (old.highest_uid == 0) != old.highest_message_ref.is_none()
                || old
                    .highest_message_ref
                    .as_ref()
                    .is_some_and(|value| !hex(value))
            {
                return Err(NotificationError::Corrupt);
            }
            if now < old.high_water {
                return Err(NotificationError::ClockRollback);
            }
        }
        let baseline = old
            .as_ref()
            .is_none_or(|old| old.generation_ref != generation);
        let previous = old
            .as_ref()
            .filter(|_| !baseline)
            .map_or(0, |old| old.highest_uid);
        let message_ref = |message: &InboxIdentity| {
            hash(
                b"observation-message-v1",
                account,
                &format!("{generation}:{}:{}", message.uid, message.message_guid),
            )
        };
        if !baseline {
            if let Some(at_top) = snapshot
                .messages
                .iter()
                .find(|message| message.uid == previous)
            {
                if old
                    .as_ref()
                    .and_then(|old| old.highest_message_ref.as_ref())
                    != Some(&message_ref(at_top))
                {
                    return Err(NotificationError::Invalid);
                }
            }
        }
        let mut messages: Vec<_> = if baseline {
            Vec::new()
        } else {
            snapshot
                .messages
                .iter()
                .filter(|message| message.uid > previous)
                .map(|message| ObservedMessage {
                    uid: message.uid,
                    source_ref: message_ref(message),
                })
                .collect()
        };
        messages.sort_by_key(|message| message.uid);
        let top = snapshot.messages.iter().max_by_key(|message| message.uid);
        let (highest_uid, highest_message_ref) = match top {
            Some(top) if baseline || top.uid > previous => (top.uid, Some(message_ref(top))),
            _ if !baseline => (
                previous,
                old.as_ref().and_then(|old| old.highest_message_ref.clone()),
            ),
            _ => (0, None),
        };
        let cursor = Cursor {
            version: 1,
            owner_ref: owner,
            generation_ref: generation,
            highest_uid,
            highest_message_ref,
            high_water: now,
        };
        lock.write(&serde_json::to_vec(&cursor).map_err(|_| NotificationError::Corrupt)?)
            .map_err(|_| NotificationError::Unconfirmed)?;
        Ok(InboxObservation { baseline, messages })
    }
}

/// Literal canonical addr-spec, with boundaries that exclude a larger address.
/// Caller supplies already-authorized readable text, never raw MIME/attachments.
pub fn mentions_account(text: &str, account: &str) -> bool {
    if crate::identity::MailboxIdentity::parse(account).is_err() {
        return false;
    }
    fn address_char(c: char) -> bool {
        c.is_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.@".contains(c)
    }
    text.match_indices(account).any(|(at, _)| {
        let end = at + account.len();
        let suffix = &text[end..];
        let after = suffix.chars().next();
        let domain_extension = after == Some('.')
            && suffix
                .chars()
                .nth(1)
                .is_some_and(|c| c.is_alphanumeric() || c == '-');
        !text[..at].chars().next_back().is_some_and(address_char)
            && !after.is_some_and(|c| c.is_alphanumeric() || "_@+-".contains(c))
            && !domain_extension
    })
}

#[cfg(test)]
#[path = "notification_observation_tests.rs"]
mod tests;
