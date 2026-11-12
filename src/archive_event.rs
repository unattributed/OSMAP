//! Known archive events, not received dates or general mailbox history.
//! The caller authenticates the session and selects its current saved Archive
//! folder. Only a confirmed Archive followed by an owned destination identity
//! resolution can construct a recordable event. Unknown moves never do so.
use crate::{
    http::BrowserMessageMoveDecision,
    mailbox::{
        MailboxEntry, MailboxListingPolicy, MessageMovePolicy, MessageMoveRequest, MessageSummary,
    },
    message_metadata::MessageVersion,
    private_account_file::PrivateAccountFile,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

pub const MAX_EVENTS: usize = crate::mailbox::DEFAULT_MAX_MESSAGES;
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
// RFC3339 presentation is bounded to years through 9999.
const MAX_TIMESTAMP: u64 = 253_402_300_799;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Corrupt,
    Capacity,
    Unavailable,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Date {
    Known(u64),
    Unknown,
    Unavailable,
}

/// A failed metadata read is different from a validated record with no known
/// event. Neither state inherits a received date or a partial identity match.
pub fn date_for(
    snapshot: Option<&Snapshot>,
    account: &str,
    folder: &str,
    row: &MessageSummary,
) -> Date {
    let Some(snapshot) = snapshot else {
        return Date::Unavailable;
    };
    let Ok(identity) = Identity::from_summary(account, account, folder, row) else {
        return Date::Unavailable;
    };
    match snapshot.archived_at(&identity) {
        Ok(Some(time)) => Date::Known(time),
        Ok(None) => Date::Unknown,
        Err(_) => Date::Unavailable,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    folder: String,
    uid: u64,
    mailbox_guid: String,
    message_guid: String,
}
impl Key {
    fn valid(&self) -> bool {
        self.uid > 0
            && self.uid <= u32::MAX as u64
            && MailboxEntry::new(MailboxListingPolicy::default(), &self.folder)
                .is_ok_and(|entry| entry.name == self.folder)
            && MessageVersion::new(self.mailbox_guid.clone(), self.message_guid.clone()).is_ok_and(
                |v| v.mailbox_guid == self.mailbox_guid && v.message_guid == self.message_guid,
            )
    }
}

/// A current native summary projection. Validation is not mailbox authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    owner: String,
    key: Key,
}
impl Identity {
    pub fn from_summary(
        account: &str,
        returned_account: &str,
        folder: &str,
        row: &MessageSummary,
    ) -> Result<Self, Error> {
        account_valid(account)?;
        if account != returned_account || row.mailbox_name != folder {
            return Err(Error::Invalid);
        }
        let version = &row.metadata.as_ref().ok_or(Error::Invalid)?.version;
        let key = Key {
            folder: row.mailbox_name.clone(),
            uid: row.uid,
            mailbox_guid: version.mailbox_guid.clone(),
            message_guid: version.message_guid.clone(),
        };
        if !key.valid() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            owner: account.into(),
            key,
        })
    }
}

/// Not constructible from browser fields, an attempted move or Received time.
#[derive(Debug, Clone)]
pub struct ConfirmedArchive {
    owner: String,
    source: Key,
    destination: Key,
}
impl ConfirmedArchive {
    /// Invoke only for the route's explicit Archive action. `saved_archive`
    /// comes from current account settings, and `rows` from the authenticated
    /// post-move native listing. The source UID does not become the destination
    /// UID, and the source mailbox GUID does not become the destination GUID.
    pub fn resolve(
        account: &str,
        saved_archive: &str,
        request: &MessageMoveRequest,
        decision: &BrowserMessageMoveDecision,
        returned_account: &str,
        returned_folder: &str,
        rows: &[MessageSummary],
    ) -> Result<Self, Error> {
        account_valid(account)?;
        let checked = MessageMoveRequest::new(
            MessageMovePolicy::default(),
            request.source_mailbox_name.clone(),
            request.destination_mailbox_name.clone(),
            request.uid,
            request.version.clone(),
        )
        .map_err(|_| Error::Invalid)?;
        if checked != *request
            || account != returned_account
            || saved_archive != request.destination_mailbox_name
            || returned_folder != saved_archive
            || rows.len() > MAX_EVENTS
        {
            return Err(Error::Invalid);
        }
        match decision {
            BrowserMessageMoveDecision::Moved {
                source_mailbox_name,
                destination_mailbox_name,
                uid,
            } if source_mailbox_name == &request.source_mailbox_name
                && destination_mailbox_name == &request.destination_mailbox_name
                && *uid == request.uid => {}
            _ => return Err(Error::Invalid),
        }
        let mut uids = BTreeSet::new();
        let mut guids = BTreeSet::new();
        let mut generation = None;
        let mut destination = None;
        for row in rows {
            let identity = Identity::from_summary(account, returned_account, returned_folder, row)?;
            if !uids.insert(identity.key.uid)
                || !guids.insert(identity.key.message_guid.clone())
                || generation
                    .as_ref()
                    .is_some_and(|g| g != &identity.key.mailbox_guid)
            {
                return Err(Error::Invalid);
            }
            generation = Some(identity.key.mailbox_guid.clone());
            if identity.key.message_guid == request.version.message_guid {
                destination = Some(identity.key);
            }
        }
        let destination = destination.ok_or(Error::Invalid)?;
        let source = Key {
            folder: request.source_mailbox_name.clone(),
            uid: request.uid,
            mailbox_guid: request.version.mailbox_guid.clone(),
            message_guid: request.version.message_guid.clone(),
        };
        if source == destination {
            return Err(Error::Invalid);
        }
        Ok(Self {
            owner: account.into(),
            source,
            destination,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    key: Key,
    archived_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    version: u8,
    account: String,
    revision: u64,
    events: Vec<Event>,
}
impl Snapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Unknown legacy objects, UID reuse, another folder/generation or another
    /// message GUID never inherit an archive date from a partial match.
    pub fn archived_at(&self, identity: &Identity) -> Result<Option<u64>, Error> {
        if self.account != identity.owner {
            return Err(Error::Invalid);
        }
        Ok(self
            .events
            .iter()
            .find(|e| e.key == identity.key)
            .map(|e| e.archived_at))
    }
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Self, Error> {
        account_valid(account)?;
        let Some(bytes) = bytes else {
            return Ok(Self {
                version: 1,
                account: account.into(),
                revision: 0,
                events: vec![],
            });
        };
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Corrupt);
        }
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt)?;
        let mut identities = BTreeSet::new();
        if value.version != 1
            || value.account != account
            || value.revision == 0
            || value.events.len() > MAX_EVENTS
            || value.events.iter().any(|e| {
                !e.key.valid()
                    || e.archived_at == 0
                    || e.archived_at > MAX_TIMESTAMP
                    || !identities.insert(e.key.clone())
            })
        {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    file: PrivateAccountFile,
}
impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(
                directory.into(),
                "osmap-archive-event-v1",
                MAX_RECORD_BYTES,
            ),
        }
    }
    pub fn load(&self, account: &str) -> Result<Snapshot, Error> {
        account_valid(account)?;
        Snapshot::decode(
            account,
            self.file.read(account).map_err(|_| Error::Unavailable)?,
        )
    }
    /// Supply server wall-clock time captured immediately after actual confirmed
    /// Archive, not a request field, Received date or later reconciliation time.
    /// Metadata errors cannot change an already confirmed mail-move result.
    pub fn record_confirmed_archive(
        &self,
        account: &str,
        confirmation: &ConfirmedArchive,
        confirmed_at: u64,
    ) -> Result<Snapshot, Error> {
        account_valid(account)?;
        if account != confirmation.owner {
            return Err(Error::Invalid);
        }
        if confirmed_at == 0 || confirmed_at > MAX_TIMESTAMP {
            return Err(Error::Invalid);
        }
        let locked = self
            .file
            .lock(&confirmation.owner)
            .map_err(|_| Error::Unavailable)?;
        let mut value = Snapshot::decode(
            &confirmation.owner,
            locked.read().map_err(|_| Error::Unavailable)?,
        )?;
        // Repeated reconciliation of the same confirmed object is idempotent;
        // it must not manufacture a later date or spend a revision.
        if value
            .events
            .iter()
            .any(|e| e.key == confirmation.destination)
        {
            return Ok(value);
        }
        value.events.retain(|e| e.key != confirmation.source);
        if value.events.len() == MAX_EVENTS {
            return Err(Error::Capacity);
        }
        value.events.push(Event {
            key: confirmation.destination.clone(),
            archived_at: confirmed_at,
        });
        value.revision = value.revision.checked_add(1).ok_or(Error::Capacity)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?;
        locked.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(value)
    }
}
fn account_valid(account: &str) -> Result<(), Error> {
    crate::identity::CanonicalUsername::parse(account)
        .map(|_| ())
        .map_err(|_| Error::Invalid)
}

#[cfg(test)]
#[cfg(unix)]
#[path = "archive_event_tests.rs"]
mod tests;
