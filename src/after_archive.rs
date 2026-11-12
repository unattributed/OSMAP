//! Independent account-owned navigation preference; never move authority.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub revision: u64,
    pub choice: Choice,
}
impl Default for Preference {
    fn default() -> Self {
        Self {
            revision: 0,
            choice: Choice::List,
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
struct Stored {
    version: u8,
    account: String,
    preference: Preference,
}
#[derive(Clone, Debug)]
pub struct Store {
    file: PrivateAccountFile,
}
impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(path.into(), "osmap-after-archive-v1", 512),
        }
    }
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Preference, Error> {
        if crate::identity::CanonicalUsername::parse(account).is_err() {
            return Err(Error::Invalid);
        }
        let Some(bytes) = bytes else {
            return Ok(Preference::default());
        };
        let value: Stored = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if value.version != 1 || value.account != account || value.preference.revision == 0 {
            return Err(Error::Unavailable);
        }
        Ok(value.preference)
    }
    pub fn load(&self, account: &str) -> Result<Preference, Error> {
        Self::decode(
            account,
            self.file.read(account).map_err(|_| Error::Unavailable)?,
        )
    }
    pub fn save(&self, account: &str, expected: u64, choice: Choice) -> Result<Preference, Error> {
        if crate::identity::CanonicalUsername::parse(account).is_err() {
            return Err(Error::Invalid);
        }
        let start = Instant::now();
        let lock = loop {
            match self.file.lock(account) {
                Ok(v) => break v,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_millis(500) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(Error::Unavailable),
            }
        };
        let old = Self::decode(account, lock.read().map_err(|_| Error::Unavailable)?)?;
        if old.revision != expected {
            return Err(Error::Stale);
        }
        let value = Preference {
            revision: expected.checked_add(1).ok_or(Error::Unavailable)?,
            choice,
        };
        let bytes = serde_json::to_vec(&Stored {
            version: 1,
            account: account.into(),
            preference: value.clone(),
        })
        .map_err(|_| Error::Unavailable)?;
        lock.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    List,
    Next,
}
impl Choice {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "list" => Some(Self::List),
            "next" => Some(Self::Next),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Next => "next",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn after_archive_private_cas_and_strict_sidecar() {
        let root = std::env::temp_dir().join(format!(
            "after-archive-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = Store::new(&root);
        let a = "alice@example.test";
        assert_eq!(store.load(a).unwrap(), Preference::default());
        let saved = store.save(a, 0, Choice::Next).unwrap();
        assert_eq!(Store::new(&root).load(a).unwrap(), saved);
        assert_eq!(
            store.load("bob@example.test").unwrap(),
            Preference::default()
        );
        assert_eq!(store.save(a, 0, Choice::List), Err(Error::Stale));
        for bytes in [b"bad".as_slice(),br#"{"version":2,"account":"alice@example.test","preference":{"revision":1,"choice":"next"}}"#,br#"{"version":1,"account":"bob@example.test","preference":{"revision":1,"choice":"next"}}"#,br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"choice":"invalid"}}"#,br#"{"version":1,"version":1}"#]{{
                let deadline = Instant::now() + Duration::from_millis(500);
                let lock = loop {
                    match store.file.lock(a) {
                        Ok(lock) => break lock,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                        Err(error) => panic!("fixture lock unavailable: {error}"),
                    }
                };
                lock.write(bytes).unwrap();
            }
            assert_eq!(store.load(a),Err(Error::Unavailable));assert_eq!(store.save(a,1,Choice::List),Err(Error::Unavailable));assert_eq!(store.file.read(a).unwrap().unwrap(),bytes);}
        std::fs::remove_dir_all(root).unwrap();
    }
}
