//! Account-private opt-in automatic draft-save preferences. No dispatch authority.
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
    pub enabled: bool,
    pub interval: u16,
}
impl Default for Preference {
    fn default() -> Self {
        Self {
            revision: 0,
            enabled: false,
            interval: 30,
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
            file: PrivateAccountFile::new(path.into(), "osmap-autosave-v1", 512),
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
        if value.version != 1
            || value.account != account
            || value.preference.revision == 0
            || !matches!(value.preference.interval, 30 | 60 | 120)
        {
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
    pub fn save(
        &self,
        account: &str,
        expected: u64,
        enabled: bool,
        interval: u16,
    ) -> Result<Preference, Error> {
        if crate::identity::CanonicalUsername::parse(account).is_err()
            || !matches!(interval, 30 | 60 | 120)
        {
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
            enabled,
            interval,
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn autosave_private_restart_owner_strict_schema_and_cas() {
        let dir = std::env::temp_dir().join(format!(
            "autosave-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let s = Store::new(&dir);
        let a = "alice@example.test";
        assert_eq!(s.load(a).unwrap(), Preference::default());
        assert!(s.save("local-user", 0, true, 120).is_ok());
        let p = s.save(a, 0, true, 60).unwrap();
        assert_eq!(Store::new(&dir).load(a).unwrap(), p);
        assert_eq!(s.load("bob@example.test").unwrap(), Preference::default());
        let before = s.file.read(a).unwrap();
        assert_eq!(s.save(a, 0, false, 30), Err(Error::Stale));
        assert_eq!(s.save(a, 1, true, 31), Err(Error::Invalid));
        assert_eq!(s.file.read(a).unwrap(), before);
        let s2 = s.clone();
        let t = std::thread::spawn(move || s2.save(a, 1, false, 120));
        let other = s.save(a, 1, true, 30);
        assert_ne!(other.is_ok(), t.join().unwrap().is_ok());
        for bytes in [br#"{"version":1,"account":"bob@example.test","preference":{"revision":1,"enabled":true,"interval":30}}"#.to_vec(),br#"{"version":1,"version":1}"#.to_vec(),b"corrupt".to_vec()]{s.file.lock(a).unwrap().write(&bytes).unwrap();assert_eq!(s.load(a),Err(Error::Unavailable));assert_eq!(s.save(a,2,false,30),Err(Error::Unavailable));assert_eq!(s.file.read(a).unwrap().unwrap(),bytes);}
    }
}
