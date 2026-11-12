//! Account-owned Save Sent preference; fixed Sent destination remains separate.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_BYTES: usize = 512;
const LOCK_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub revision: u64,
    pub save_sent: bool,
}
impl Default for Preference {
    fn default() -> Self {
        Self {
            revision: 0,
            save_sent: true,
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
            file: PrivateAccountFile::new(directory.into(), "osmap-sent-copy-v1", MAX_BYTES),
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
    pub fn save(&self, account: &str, revision: u64, save_sent: bool) -> Result<Preference, Error> {
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
        let preference = Preference {
            revision: next,
            save_sent,
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
#[path = "sent_copy_tests.rs"]
mod tests;
