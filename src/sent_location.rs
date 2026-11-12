//! Account-owned Sent destination; a preference never grants mailbox ownership.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_BYTES: usize = 4096;
const LOCK_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub revision: u64,
    pub mailbox_name: String,
    pub mailbox_guid: Option<String>,
}
impl Default for Preference {
    fn default() -> Self {
        Self {
            revision: 0,
            mailbox_name: "Sent".into(),
            mailbox_guid: None,
        }
    }
}
impl Preference {
    pub fn valid(&self) -> bool {
        match self.mailbox_guid.as_deref() {
            Some(guid) => {
                self.revision > 0 && validate_destination(&self.mailbox_name, guid).is_ok()
            }
            None => self.revision == 0 && self.mailbox_name == "Sent",
        }
    }
}
pub fn validate_destination(name: &str, guid: &str) -> Result<(), Error> {
    crate::mailbox_status::MailboxStatus::new(name, guid, 0, 0)
        .map(|_| ())
        .map_err(|_| Error::Invalid)
}
/// Only the authenticated own snapshot can authorize a picker option. Unknown,
/// shared, public, Noselect and NonExistent folders are not eligible.
pub fn selectable(
    snapshot: &crate::folder_metadata::FolderSnapshot,
    account: &str,
    name: &str,
) -> bool {
    if snapshot.validate_for(account).is_err()
        || crate::mailbox_status::validate_name(name).is_err()
    {
        return false;
    }
    let longest = snapshot
        .namespaces()
        .iter()
        .filter(|ns| name.starts_with(ns.prefix()))
        .map(|ns| ns.prefix().len())
        .max();
    let mut matching = snapshot
        .namespaces()
        .iter()
        .filter(|ns| Some(ns.prefix().len()) == longest && name.starts_with(ns.prefix()));
    let private = matching
        .next()
        .is_some_and(|ns| ns.kind() == crate::folder_metadata::NamespaceKind::Private)
        && matching.next().is_none();
    private
        && snapshot.folder(account, name).is_ok_and(|folder| {
            folder.name() == name
                && !folder.has_flag("\\Noselect")
                && !folder.has_flag("\\NonExistent")
        })
}
/// Immutable per-attempt capture. Unavailable is an explicit known target that
/// could not be qualified, never a replacement for corrupt preference data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CapturedLocation {
    Selected {
        mailbox_name: String,
        mailbox_guid: String,
    },
    Unavailable {
        mailbox_name: String,
        mailbox_guid: String,
    },
}
impl CapturedLocation {
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Selected { mailbox_name, .. } | Self::Unavailable { mailbox_name, .. } => {
                mailbox_name
            }
        }
    }
    pub(crate) fn guid(&self) -> &str {
        match self {
            Self::Selected { mailbox_guid, .. } | Self::Unavailable { mailbox_guid, .. } => {
                mailbox_guid
            }
        }
    }
    pub(crate) fn available(&self) -> bool {
        matches!(self, Self::Selected { .. })
    }
    pub(crate) fn valid(&self) -> bool {
        validate_destination(self.name(), self.guid()).is_ok()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SentCopyCapture {
    pub requested: bool,
    pub location: Option<CapturedLocation>,
}
impl SentCopyCapture {
    #[cfg(test)]
    pub(crate) fn legacy(requested: bool) -> Self {
        Self {
            requested,
            location: None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        self.location
            .as_ref()
            .is_none_or(|location| self.requested && location.valid())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Stale,
    Unavailable,
    Unconfirmed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    account: String,
    preference: Preference,
}

#[derive(Debug, Clone)]
pub struct Store {
    file: PrivateAccountFile,
}
impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), "osmap-sent-location-v1", MAX_BYTES),
        }
    }
    fn account(account: &str) -> Result<(), Error> {
        crate::identity::CanonicalUsername::parse(account)
            .map(|_| ())
            .map_err(|_| Error::Invalid)
    }
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Preference, Error> {
        let Some(bytes) = bytes else {
            return Ok(Preference::default());
        };
        if bytes.len() > MAX_BYTES {
            return Err(Error::Unavailable);
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if record.version != 1
            || record.account != account
            || record.preference.revision == 0
            || !record.preference.valid()
        {
            return Err(Error::Unavailable);
        }
        Ok(record.preference)
    }
    pub fn load(&self, account: &str) -> Result<Preference, Error> {
        Self::account(account)?;
        Self::decode(
            account,
            self.file.read(account).map_err(|_| Error::Unavailable)?,
        )
    }
    pub fn save(
        &self,
        account: &str,
        revision: u64,
        mailbox_name: &str,
        mailbox_guid: &str,
    ) -> Result<Preference, Error> {
        Self::account(account)?;
        validate_destination(mailbox_name, mailbox_guid)?;
        let next = revision.checked_add(1).ok_or(Error::Invalid)?;
        let deadline = Instant::now() + LOCK_WAIT;
        let locked = loop {
            match self.file.lock(account) {
                Ok(lock) => break lock,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(Error::Unavailable),
            }
        };
        let old = Self::decode(account, locked.read().map_err(|_| Error::Unavailable)?)?;
        if old.revision != revision {
            return Err(Error::Stale);
        }
        let preference = Preference {
            revision: next,
            mailbox_name: mailbox_name.into(),
            mailbox_guid: Some(mailbox_guid.into()),
        };
        let bytes = serde_json::to_vec(&Record {
            version: 1,
            account: account.into(),
            preference: preference.clone(),
        })
        .map_err(|_| Error::Unavailable)?;
        // Publication failure may occur after rename. Never claim unchanged
        // state or automatically retry when directory sync is unconfirmed.
        locked.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(preference)
    }
}

#[cfg(test)]
#[path = "sent_location_tests.rs"]
mod tests;
