//! Account-owned presentation preferences. These never authorize another From address.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
const NAMESPACE: &str = "osmap-identity-preferences-v1";
const MAX_RECORD: usize = 2048;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct IdentityPreferences {
    display_name: String,
    reply_to: Option<String>,
}
impl std::fmt::Debug for IdentityPreferences {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityPreferences")
            .field("has_display_name", &!self.display_name.is_empty())
            .field("has_reply_to", &self.reply_to.is_some())
            .finish()
    }
}
impl IdentityPreferences {
    pub fn new(
        display_name: &str,
        reply_to: Option<&str>,
    ) -> Result<Self, IdentityPreferencesError> {
        if display_name.len() > 256
            || display_name.chars().count() > 128
            || display_name.trim() != display_name
            || display_name
                .chars()
                .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
        {
            return Err(IdentityPreferencesError::InvalidInput);
        }
        let reply_to = reply_to.filter(|v| !v.is_empty());
        if let Some(value) = reply_to {
            crate::identity::MailboxIdentity::parse(value)
                .map_err(|_| IdentityPreferencesError::InvalidInput)?;
            let (local, domain) = value
                .split_once('@')
                .ok_or(IdentityPreferencesError::InvalidInput)?;
            if value.len() > 254
                || local.len() > 64
                || local.split('.').any(str::is_empty)
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                })
            {
                return Err(IdentityPreferencesError::InvalidInput);
            }
        }
        Ok(Self {
            display_name: display_name.into(),
            reply_to: reply_to.map(str::to_owned),
        })
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub fn reply_to(&self) -> Option<&str> {
        self.reply_to.as_deref()
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityPreferencesRecord {
    pub preferences: IdentityPreferences,
    pub revision: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPreferencesError {
    InvalidInput,
    Corrupt,
    Stale,
    Unavailable,
    Unconfirmed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    revision: u64,
    display_name: String,
    reply_to: String,
}
impl IdentityPreferencesRecord {
    fn parse(bytes: Option<Vec<u8>>) -> Result<Self, IdentityPreferencesError> {
        let Some(bytes) = bytes else {
            return Ok(Self::default());
        };
        let raw: Stored =
            serde_json::from_slice(&bytes).map_err(|_| IdentityPreferencesError::Corrupt)?;
        if raw.version != 1 || raw.revision == 0 {
            return Err(IdentityPreferencesError::Corrupt);
        }
        Ok(Self {
            preferences: IdentityPreferences::new(&raw.display_name, Some(&raw.reply_to))
                .map_err(|_| IdentityPreferencesError::Corrupt)?,
            revision: raw.revision,
        })
    }
    fn bytes(&self) -> Result<Vec<u8>, IdentityPreferencesError> {
        serde_json::to_vec(&Stored {
            version: 1,
            revision: self.revision,
            display_name: self.preferences.display_name.clone(),
            reply_to: self.preferences.reply_to.clone().unwrap_or_default(),
        })
        .map_err(|_| IdentityPreferencesError::Unavailable)
    }
}
#[derive(Debug, Clone)]
pub struct IdentityPreferencesStore {
    file: PrivateAccountFile,
}
impl IdentityPreferencesStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), NAMESPACE, MAX_RECORD),
        }
    }
    fn account(account: &str) -> Result<(), IdentityPreferencesError> {
        crate::identity::CanonicalUsername::parse(account)
            .map(|_| ())
            .map_err(|_| IdentityPreferencesError::InvalidInput)
    }
    pub fn load(
        &self,
        account: &str,
    ) -> Result<IdentityPreferencesRecord, IdentityPreferencesError> {
        Self::account(account)?;
        IdentityPreferencesRecord::parse(
            self.file
                .read(account)
                .map_err(|_| IdentityPreferencesError::Unavailable)?,
        )
    }
    pub fn save(
        &self,
        account: &str,
        expected_revision: u64,
        preferences: &IdentityPreferences,
    ) -> Result<IdentityPreferencesRecord, IdentityPreferencesError> {
        Self::account(account)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        let lock = loop {
            match self.file.lock(account) {
                Ok(lock) => break lock,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(IdentityPreferencesError::Unavailable),
            }
        };
        let old = IdentityPreferencesRecord::parse(
            lock.read()
                .map_err(|_| IdentityPreferencesError::Unavailable)?,
        )?;
        if old.revision != expected_revision {
            return Err(IdentityPreferencesError::Stale);
        }
        let record = IdentityPreferencesRecord {
            preferences: preferences.clone(),
            revision: old
                .revision
                .checked_add(1)
                .ok_or(IdentityPreferencesError::Corrupt)?,
        };
        lock.write(&record.bytes()?)
            .map_err(|_| IdentityPreferencesError::Unconfirmed)?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> (PathBuf, IdentityPreferencesStore) {
        let path = std::env::temp_dir().join(format!(
            "osmap-identity-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        (path.clone(), IdentityPreferencesStore::new(path))
    }
    #[test]
    fn identity_preferences_roundtrip_owner_isolation_and_stale_cas() {
        let (path, s) = store();
        assert_eq!(
            s.load("alice@example.test").unwrap(),
            IdentityPreferencesRecord::default()
        );
        let value =
            IdentityPreferences::new("Zoë 🦊, \"Review\"", Some("replies+work@example.test"))
                .unwrap();
        let saved = s.save("alice@example.test", 0, &value).unwrap();
        assert_eq!(saved.revision, 1);
        assert_eq!(
            IdentityPreferencesStore::new(&path)
                .load("alice@example.test")
                .unwrap(),
            saved
        );
        assert_eq!(s.load("bob@example.test").unwrap().revision, 0);
        assert_eq!(
            s.save("alice@example.test", 0, &IdentityPreferences::default()),
            Err(IdentityPreferencesError::Stale)
        );
        assert_eq!(s.load("alice@example.test").unwrap(), saved);
        assert!(!format!("{saved:?}").contains("Zoë"));
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn identity_preferences_strict_validation_and_corrupt_records() {
        for name in [
            " bad",
            "bad ",
            "line\rbreak",
            "line\nbreak",
            "a\u{2028}b",
            "\0",
        ] {
            assert_eq!(
                IdentityPreferences::new(name, None),
                Err(IdentityPreferencesError::InvalidInput)
            );
        }
        assert!(IdentityPreferences::new(&"a".repeat(129), None).is_err());
        assert!(IdentityPreferences::new(&"🦊".repeat(65), None).is_err());
        for value in [
            "a@example.test\r\nBcc: x@y.test",
            "a@example.test,b@example.test",
            "Name <a@example.test>",
            "a..b@example.test",
            "a@.example.test",
            "a@-x.test",
            "a@example.test ",
            "x@localhost",
        ] {
            assert!(
                IdentityPreferences::new("", Some(value)).is_err(),
                "{value:?}"
            );
        }
        let (path, s) = store();
        let locked = s.file.lock("alice@example.test").unwrap();
        for bytes in [
            br#"{"version":2,"revision":1,"display_name":"","reply_to":""}"#.as_slice(),
            br#"{"version":1,"revision":1,"display_name":""}"#,
            br#"{"version":1,"version":1,"revision":1,"display_name":"","reply_to":""}"#,
        ] {
            locked.write(bytes).unwrap();
            assert_eq!(
                s.load("alice@example.test"),
                Err(IdentityPreferencesError::Corrupt)
            );
        }
        drop(locked);
        assert_eq!(
            s.save("alice@example.test", 0, &IdentityPreferences::default()),
            Err(IdentityPreferencesError::Corrupt)
        );
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn identity_preferences_competing_tabs_publish_one_revision() {
        let (path, s) = store();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = vec![];
        for name in ["First", "Second"] {
            let s = s.clone();
            let b = barrier.clone();
            threads.push(std::thread::spawn(move || {
                b.wait();
                s.save(
                    "alice@example.test",
                    0,
                    &IdentityPreferences::new(name, None).unwrap(),
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(IdentityPreferencesError::Stale))
                .count(),
            1
        );
        assert_eq!(s.load("alice@example.test").unwrap().revision, 1);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn identity_preferences_unsafe_directory_and_busy_write_preserve_bytes() {
        let (path, s) = store();
        s.save("alice@example.test", 0, &IdentityPreferences::default())
            .unwrap();
        let lock = s.file.lock("alice@example.test").unwrap();
        let before = lock.read().unwrap();
        assert_eq!(
            s.save(
                "alice@example.test",
                1,
                &IdentityPreferences::new("Changed", None).unwrap()
            ),
            Err(IdentityPreferencesError::Unavailable)
        );
        assert_eq!(lock.read().unwrap(), before);
        drop(lock);
        #[cfg(unix)]
        {
            let link = path.with_extension("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert_eq!(
                IdentityPreferencesStore::new(&link).load("alice@example.test"),
                Err(IdentityPreferencesError::Unavailable)
            );
            std::fs::remove_file(link).unwrap();
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
