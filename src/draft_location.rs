//! Account-owned choice between two fixed private draft locations.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_BYTES: usize = 512;
const LOCK_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Location {
    Default,
    Working,
}
impl Location {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "working" => Some(Self::Working),
            _ => None,
        }
    }
    pub fn value(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Working => "working",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "Drafts",
            Self::Working => "Working drafts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub revision: u64,
    pub location: Location,
}
impl Default for Preference {
    fn default() -> Self {
        Self {
            revision: 0,
            location: Location::Default,
        }
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
            file: PrivateAccountFile::new(directory.into(), "osmap-draft-location-v1", MAX_BYTES),
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
        if record.version != 1 || record.account != account || record.preference.revision == 0 {
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
        location: Location,
    ) -> Result<Preference, Error> {
        self.save_qualified(account, revision, location, || Ok(()))
    }

    /// Holds the preference CAS lock through fixed-location qualification.
    /// A stale request never initializes storage or publishes a choice.
    pub fn save_qualified(
        &self,
        account: &str,
        revision: u64,
        location: Location,
        qualify: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Preference, Error> {
        Self::account(account)?;
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
        qualify()?;
        let preference = Preference {
            revision: next,
            location,
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
#[path = "draft_location_tests.rs"]
mod tests;
