//! Account-private in-app inbox presentation. No event suppression or delivery authority.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestMode {
    #[default]
    Individual,
    Daily,
}
impl DigestMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "individual" => Some(Self::Individual),
            "daily" => Some(Self::Daily),
            _ => None,
        }
    }
    pub fn value(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Daily => "daily",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub revision: u64,
    pub digest: DigestMode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(root.into(), "osmap-notification-preferences-v1", 512),
        }
    }
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Preference, Error> {
        crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        let Some(bytes) = bytes else {
            return Ok(Preference::default());
        };
        let stored: Stored = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if stored.version != 1 || stored.account != account || stored.preference.revision == 0 {
            return Err(Error::Unavailable);
        }
        Ok(stored.preference)
    }
    pub fn load(&self, account: &str) -> Result<Preference, Error> {
        crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        Self::decode(
            account,
            self.file.read(account).map_err(|_| Error::Unavailable)?,
        )
    }
    pub fn save(
        &self,
        account: &str,
        expected: u64,
        digest: DigestMode,
    ) -> Result<Preference, Error> {
        crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        let lock = loop {
            match self.file.lock(account) {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
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
        let preference = Preference {
            revision: expected.checked_add(1).ok_or(Error::Unavailable)?,
            digest,
        };
        let bytes = serde_json::to_vec(&Stored {
            version: 1,
            account: account.into(),
            preference,
        })
        .map_err(|_| Error::Unavailable)?;
        lock.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "alice@example.test";
    const B: &str = "bob@example.test";
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-notice-preference-{}",
                crate::draft::generate_draft_id().unwrap()
            )))
        }
        fn store(&self) -> Store {
            Store::new(&self.0)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn notification_preference_restart_account_cas_and_unrelated_store_preserved() {
        let root = Scratch::new();
        let store = root.store();
        assert_eq!(store.load(A).unwrap(), Preference::default());
        let other = crate::autosave::Store::new(&root.0)
            .save(A, 0, true, 60)
            .unwrap();
        let daily = store.save(A, 0, DigestMode::Daily).unwrap();
        assert_eq!(root.store().load(A).unwrap(), daily);
        assert_eq!(store.load(B).unwrap(), Preference::default());
        assert_eq!(store.save(A, 0, DigestMode::Individual), Err(Error::Stale));
        assert_eq!(store.load(A).unwrap(), daily);
        assert_eq!(crate::autosave::Store::new(&root.0).load(A).unwrap(), other);
        assert_eq!(
            store
                .save(A, daily.revision, DigestMode::Individual)
                .unwrap()
                .revision,
            2
        );
        assert_eq!(
            store.save("bad\r\naccount", 0, DigestMode::Daily),
            Err(Error::Invalid)
        );
    }
    #[test]
    fn notification_preference_foreign_corrupt_duplicate_version_and_overflow_refuse_without_reset()
    {
        let root = Scratch::new();
        let store = root.store();
        store.save(A, 0, DigestMode::Daily).unwrap();
        let lock = store.file.lock(A).unwrap();
        let original = lock.read().unwrap().unwrap();
        drop(lock);
        let foreign = store.file.lock(B).unwrap();
        foreign.write(&original).unwrap();
        drop(foreign);
        assert_eq!(store.load(B), Err(Error::Unavailable));
        invalid_record_variants(&store, A, &original);
    }
    fn invalid_record_variants(store: &Store, account: &str, original: &[u8]) {
        for bad in [
            "{broken".to_string(),
            String::from_utf8(original.to_vec())
                .unwrap()
                .replace("\"version\":1", "\"version\":2"),
            String::from_utf8(original.to_vec())
                .unwrap()
                .replace("\"version\":1", "\"version\":1,\"version\":1"),
            String::from_utf8(original.to_vec())
                .unwrap()
                .replace("\"daily\"", "\"external_email\""),
            String::from_utf8(original.to_vec())
                .unwrap()
                .replace("\"revision\":1", "\"revision\":18446744073709551615"),
        ] {
            let lock = store.file.lock(account).unwrap();
            lock.write(bad.as_bytes()).unwrap();
            drop(lock);
            assert_eq!(
                store.save(account, u64::MAX, DigestMode::Individual),
                Err(Error::Unavailable)
            );
            let lock = store.file.lock(account).unwrap();
            assert_eq!(lock.read().unwrap().unwrap(), bad.as_bytes());
            lock.write(original).unwrap();
        }
    }
    #[cfg(unix)]
    #[test]
    fn notification_preference_symlink_and_oversize_refuse_without_reset() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = Scratch::new();
        let store = root.store();
        store.save(A, 0, DigestMode::Daily).unwrap();
        let path = std::fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        let original = std::fs::read(&path).unwrap();
        let target = root.0.join("public-sentinel");
        std::fs::write(&target, &original).unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(store.load(A), Err(Error::Unavailable));
        assert_eq!(
            store.save(A, 1, DigestMode::Individual),
            Err(Error::Unavailable)
        );
        assert_eq!(std::fs::read(&target).unwrap(), original);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![b'x'; 513]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(store.load(A), Err(Error::Unavailable));
        assert_eq!(std::fs::read(path).unwrap().len(), 513);
    }
}
