//! Account-owned presentation preferences. These never authorize another From address.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
const NAMESPACE: &str = "osmap-identity-preferences-v1";
const MAX_RECORD: usize = 16 * 2048;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct IdentityPreferences {
    display_name: String,
    reply_to: Option<String>,
    sender: Option<CapturedSender>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedSender {
    id: String,
    address: String,
}
impl CapturedSender {
    pub(crate) fn new(id: &str, address: &str) -> Result<Self, IdentityPreferencesError> {
        if !crate::sender_authority::valid_id(id) || id == crate::sender_authority::CANONICAL_ID {
            return Err(IdentityPreferencesError::InvalidInput);
        }
        IdentityPreferences::new("", Some(address))?;
        Ok(Self {
            id: id.into(),
            address: address.into(),
        })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn address(&self) -> &str {
        &self.address
    }
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
            sender: None,
        })
    }
    pub fn sender(&self) -> Option<&CapturedSender> {
        self.sender.as_ref()
    }
    pub(crate) fn with_sender(
        mut self,
        id: &str,
        address: &str,
    ) -> Result<Self, IdentityPreferencesError> {
        self.sender = Some(CapturedSender::new(id, address)?);
        Ok(self)
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
    pub primary_identity: Option<String>,
    pub sender_profiles: Vec<SenderProfile>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderProfile {
    pub id: String,
    pub preferences: IdentityPreferences,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAction {
    Add,
    Edit,
    Primary,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderIdentityUpdate {
    pub identity_id: String,
    pub action: IdentityAction,
    pub presentation: IdentityPreferences,
    pub use_for_new: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    primary_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sender_profiles: Vec<StoredProfile>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    id: String,
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
        if raw.sender_profiles.len() >= crate::sender_authority::MAX_IDENTITIES {
            return Err(IdentityPreferencesError::Corrupt);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut sender_profiles = Vec::new();
        for profile in raw.sender_profiles {
            if !crate::sender_authority::valid_id(&profile.id)
                || profile.id == crate::sender_authority::CANONICAL_ID
                || !seen.insert(profile.id.clone())
            {
                return Err(IdentityPreferencesError::Corrupt);
            }
            sender_profiles.push(SenderProfile {
                id: profile.id,
                preferences: IdentityPreferences::new(
                    &profile.display_name,
                    Some(&profile.reply_to),
                )
                .map_err(|_| IdentityPreferencesError::Corrupt)?,
            });
        }
        if raw
            .primary_identity
            .as_ref()
            .is_some_and(|id| !seen.contains(id))
        {
            return Err(IdentityPreferencesError::Corrupt);
        }
        Ok(Self {
            primary_identity: raw.primary_identity,
            sender_profiles,
            preferences: IdentityPreferences::new(&raw.display_name, Some(&raw.reply_to))
                .map_err(|_| IdentityPreferencesError::Corrupt)?,
            revision: raw.revision,
        })
    }
    pub fn primary_id(&self) -> &str {
        self.primary_identity
            .as_deref()
            .unwrap_or(crate::sender_authority::CANONICAL_ID)
    }
    pub fn presentation(&self, id: &str) -> Option<&IdentityPreferences> {
        if id == crate::sender_authority::CANONICAL_ID {
            Some(&self.preferences)
        } else {
            self.sender_profiles
                .iter()
                .find(|profile| profile.id == id)
                .map(|profile| &profile.preferences)
        }
    }
    pub fn selected_preferences(
        &self,
        account: &str,
        provider: &crate::sender_authority::Provider,
    ) -> Result<IdentityPreferences, IdentityPreferencesError> {
        let Some(id) = &self.primary_identity else {
            return Ok(self.preferences.clone());
        };
        let snapshot = provider
            .snapshot(account)
            .map_err(|_| IdentityPreferencesError::Unavailable)?;
        let selected = snapshot
            .get(id)
            .map_err(|_| IdentityPreferencesError::Unavailable)?;
        self.presentation(id)
            .ok_or(IdentityPreferencesError::Corrupt)?
            .clone()
            .with_sender(id, &selected.address)
    }
    pub fn preferences_for_id(
        &self,
        account: &str,
        provider: &crate::sender_authority::Provider,
        id: &str,
    ) -> Result<IdentityPreferences, IdentityPreferencesError> {
        if id == crate::sender_authority::CANONICAL_ID {
            return Ok(self.preferences.clone());
        }
        let snapshot = provider
            .snapshot(account)
            .map_err(|_| IdentityPreferencesError::Unavailable)?;
        let identity = snapshot
            .get(id)
            .map_err(|_| IdentityPreferencesError::InvalidInput)?;
        self.presentation(id)
            .cloned()
            .unwrap_or_default()
            .with_sender(id, &identity.address)
    }
    fn bytes(&self) -> Result<Vec<u8>, IdentityPreferencesError> {
        serde_json::to_vec(&Stored {
            version: 1,
            revision: self.revision,
            display_name: self.preferences.display_name.clone(),
            reply_to: self.preferences.reply_to.clone().unwrap_or_default(),
            primary_identity: self.primary_identity.clone(),
            sender_profiles: self
                .sender_profiles
                .iter()
                .map(|profile| StoredProfile {
                    id: profile.id.clone(),
                    display_name: profile.preferences.display_name.clone(),
                    reply_to: profile.preferences.reply_to.clone().unwrap_or_default(),
                })
                .collect(),
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
        if preferences.sender().is_some() {
            return Err(IdentityPreferencesError::InvalidInput);
        }
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
            primary_identity: old.primary_identity,
            sender_profiles: old.sender_profiles,
            revision: old
                .revision
                .checked_add(1)
                .ok_or(IdentityPreferencesError::Corrupt)?,
        };
        lock.write(&record.bytes()?)
            .map_err(|_| IdentityPreferencesError::Unconfirmed)?;
        Ok(record)
    }
    pub fn save_sender(
        &self,
        account: &str,
        expected_revision: u64,
        inventory: &crate::sender_authority::Snapshot,
        update: &SenderIdentityUpdate,
    ) -> Result<IdentityPreferencesRecord, IdentityPreferencesError> {
        Self::account(account)?;
        if inventory.validate(account).is_err()
            || update.presentation.sender().is_some()
            || inventory.get(&update.identity_id).is_err()
        {
            return Err(IdentityPreferencesError::InvalidInput);
        }
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
        let mut record = IdentityPreferencesRecord::parse(
            lock.read()
                .map_err(|_| IdentityPreferencesError::Unavailable)?,
        )?;
        if record.revision != expected_revision {
            return Err(IdentityPreferencesError::Stale);
        }
        let canonical = update.identity_id == crate::sender_authority::CANONICAL_ID;
        if !canonical
            && !record
                .sender_profiles
                .iter()
                .any(|profile| profile.id == update.identity_id)
        {
            if record.sender_profiles.len() >= crate::sender_authority::MAX_IDENTITIES - 1 {
                return Err(IdentityPreferencesError::InvalidInput);
            }
            record.sender_profiles.push(SenderProfile {
                id: update.identity_id.clone(),
                preferences: IdentityPreferences::default(),
            });
        }
        if update.action == IdentityAction::Edit {
            if canonical {
                record.preferences = update.presentation.clone();
            } else {
                record
                    .sender_profiles
                    .iter_mut()
                    .find(|profile| profile.id == update.identity_id)
                    .ok_or(IdentityPreferencesError::Corrupt)?
                    .preferences = update.presentation.clone();
            }
        }
        if update.action == IdentityAction::Primary
            || (update.action == IdentityAction::Edit && update.use_for_new)
        {
            record.primary_identity = (!canonical).then(|| update.identity_id.clone());
        } else if update.action == IdentityAction::Edit
            && record.primary_identity.as_deref() == Some(&update.identity_id)
        {
            record.primary_identity = None;
        }
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(IdentityPreferencesError::Corrupt)?;
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
    include!("sender_preferences_tests.rs");
}
