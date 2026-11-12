//! Account-owned mark-read policy; the store never mutates mailbox flags.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const NAMESPACE: &str = "osmap-mark-read-v1";
const MAX_RECORD_BYTES: usize = 512;
const LOCK_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    #[default]
    Manual,
    OnOpen,
}

impl Policy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "manual" => Some(Self::Manual),
            "on_open" => Some(Self::OnOpen),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::OnOpen => "on_open",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub revision: u64,
    pub policy: Policy,
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

#[derive(Debug, Clone)]
pub struct Store {
    file: PrivateAccountFile,
}

impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), NAMESPACE, MAX_RECORD_BYTES),
        }
    }

    fn validate_account(account: &str) -> Result<(), Error> {
        crate::identity::CanonicalUsername::parse(account)
            .map(|_| ())
            .map_err(|_| Error::Invalid)
    }

    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Preference, Error> {
        let Some(bytes) = bytes else {
            return Ok(Preference::default());
        };
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Unavailable);
        }
        let value: Stored = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if value.version != 1 || value.account != account || value.preference.revision == 0 {
            return Err(Error::Unavailable);
        }
        Ok(value.preference)
    }

    /// Missing state is Manual without creating a directory or record. Invalid
    /// existing state is unavailable, never a default or an automatic reset.
    pub fn load(&self, account: &str) -> Result<Preference, Error> {
        Self::validate_account(account)?;
        Self::decode(
            account,
            self.file.read(account).map_err(|_| Error::Unavailable)?,
        )
    }

    pub fn save(
        &self,
        account: &str,
        expected_revision: u64,
        policy: Policy,
    ) -> Result<Preference, Error> {
        Self::validate_account(account)?;
        // Bound lock admission, while retaining the existing atomic-file I/O
        // contract. This is not a hard timeout on filesystem sync operations.
        let deadline = Instant::now() + LOCK_WAIT;
        let locked = loop {
            match self.file.lock(account) {
                Ok(locked) => break locked,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(Error::Unavailable),
            }
        };
        let current = Self::decode(account, locked.read().map_err(|_| Error::Unavailable)?)?;
        if current.revision != expected_revision {
            return Err(Error::Stale);
        }
        let preference = Preference {
            revision: expected_revision.checked_add(1).ok_or(Error::Unavailable)?,
            policy,
        };
        let bytes = serde_json::to_vec(&Stored {
            version: 1,
            account: account.into(),
            preference: preference.clone(),
        })
        .map_err(|_| Error::Unavailable)?;
        // A failed publication may include a rename followed by failed directory
        // sync. Do not claim unchanged state or automatically retry this error.
        locked.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::sync::{Arc, Barrier};

    const ALICE: &str = "alice@example.test";
    const BOB: &str = "bob@example.test";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-mark-read-{}",
                crate::draft::generate_draft_id().expect("unique fixture directory")
            )))
        }

        fn store(&self) -> Store {
            Store::new(&self.0)
        }

        fn record(&self, account: &str) -> PathBuf {
            let mut hash = Sha256::new();
            hash.update(NAMESPACE.as_bytes());
            hash.update(b"\0");
            hash.update(account.as_bytes());
            self.0.join(format!("{:x}.json", hash.finalize()))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mark_read_policy_persists_across_restart_and_isolated_cas_updates() {
        let root = Scratch::new();
        let store = root.store();
        assert_eq!(store.load(ALICE).unwrap(), Preference::default());
        assert!(!root.0.exists(), "a missing preference load is read-only");
        let first = store.save(ALICE, 0, Policy::OnOpen).unwrap();
        assert_eq!(
            first,
            Preference {
                revision: 1,
                policy: Policy::OnOpen
            }
        );
        let bytes = fs::read(root.record(ALICE)).unwrap();
        assert_eq!(root.store().load(ALICE).unwrap(), first);
        assert_eq!(store.load(BOB).unwrap(), Preference::default());
        assert_eq!(store.save(ALICE, 0, Policy::Manual), Err(Error::Stale));
        assert_eq!(fs::read(root.record(ALICE)).unwrap(), bytes);
        let second = root.store().save(ALICE, 1, Policy::Manual).unwrap();
        assert_eq!(
            second,
            Preference {
                revision: 2,
                policy: Policy::Manual
            }
        );
        let bob = store.save(BOB, 0, Policy::OnOpen).unwrap();
        assert_eq!(store.load(ALICE).unwrap(), second);
        assert_eq!(root.store().load(BOB).unwrap(), bob);
        assert!(fs::read_dir(&root.0).unwrap().all(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            !name.contains("alice") && !name.contains("bob") && !name.ends_with(".tmp")
        }));
    }

    #[test]
    fn mark_read_policy_rejects_invalid_accounts_before_any_file_operation() {
        let root = Scratch::new();
        let store = root.store();
        for account in [
            "",
            " alice@example.test",
            "alice@example.test ",
            "alice@example.test\n",
            "Alice <alice@example.test>",
            "alice@example.test,bob@example.test",
        ] {
            assert_eq!(store.load(account), Err(Error::Invalid));
            assert_eq!(store.save(account, 0, Policy::OnOpen), Err(Error::Invalid));
        }
        assert_eq!(store.load(&"a".repeat(321)), Err(Error::Invalid));
        assert_eq!(
            store.save(&"a".repeat(321), 0, Policy::OnOpen),
            Err(Error::Invalid)
        );
        assert!(!root.0.exists());
    }

    #[test]
    fn mark_read_policy_corrupt_foreign_and_overflow_records_are_preserved() {
        let root = Scratch::new();
        let store = root.store();
        for bad in [
            b"not-json".as_slice(),
            br#"{"version":2,"account":"alice@example.test","preference":{"revision":1,"policy":"manual"}}"#,
            br#"{"version":1,"account":"bob@example.test","preference":{"revision":1,"policy":"manual"}}"#,
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":0,"policy":"manual"}}"#,
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"policy":"timed"}}"#,
            br#"{"version":1,"version":1,"account":"alice@example.test","preference":{"revision":1,"policy":"manual"}}"#,
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"policy":"manual","extra":true}}"#,
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"policy":"manual"},"extra":true}"#,
        ] {
            { let held = store.file.lock(ALICE).unwrap(); held.write(bad).unwrap(); }
            assert_eq!(store.load(ALICE), Err(Error::Unavailable));
            assert_eq!(store.save(ALICE, 1, Policy::OnOpen), Err(Error::Unavailable));
            assert_eq!(fs::read(root.record(ALICE)).unwrap(), bad);
        }
        let exhausted = serde_json::to_vec(&Stored {
            version: 1,
            account: ALICE.into(),
            preference: Preference {
                revision: u64::MAX,
                policy: Policy::Manual,
            },
        })
        .unwrap();
        {
            let held = store.file.lock(ALICE).unwrap();
            held.write(&exhausted).unwrap();
        }
        assert_eq!(store.load(ALICE).unwrap().revision, u64::MAX);
        assert_eq!(
            store.save(ALICE, u64::MAX, Policy::OnOpen),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(root.record(ALICE)).unwrap(), exhausted);
    }

    #[test]
    fn mark_read_policy_concurrent_same_revision_has_only_one_atomic_winner() {
        let root = Scratch::new();
        let store = root.store();
        let barrier = Arc::new(Barrier::new(2));
        let threads: Vec<_> = [Policy::Manual, Policy::OnOpen]
            .into_iter()
            .map(|policy| {
                let barrier = barrier.clone();
                let store = store.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.save(ALICE, 0, policy)
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(Error::Stale))
                .count(),
            1
        );
        let winner = results.into_iter().find_map(Result::ok).unwrap();
        assert_eq!(root.store().load(ALICE).unwrap(), winner);
        assert_eq!(winner.revision, 1);
    }

    #[test]
    fn mark_read_policy_held_account_lock_refuses_without_changing_state() {
        let root = Scratch::new();
        let store = root.store();
        let current = store.save(ALICE, 0, Policy::OnOpen).unwrap();
        let before = fs::read(root.record(ALICE)).unwrap();
        let held = store.file.lock(ALICE).unwrap();
        assert_eq!(
            store.save(ALICE, 1, Policy::Manual),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(root.record(ALICE)).unwrap(), before);
        drop(held);
        assert_eq!(store.load(ALICE).unwrap(), current);
        assert_eq!(store.save(ALICE, 1, Policy::Manual).unwrap().revision, 2);
    }

    #[cfg(unix)]
    #[test]
    fn mark_read_policy_directory_and_lock_symlinks_cannot_redirect_a_write() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = Scratch::new();
        let store = root.store();
        store.save(ALICE, 0, Policy::Manual).unwrap();
        let record_before = fs::read(root.record(ALICE)).unwrap();
        let lock_path = root.record(ALICE).with_extension("lock");
        fs::remove_file(&lock_path).unwrap();
        let target = root.0.join("owned-lock-target");
        fs::write(&target, b"unchanged owned fixture").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &lock_path).unwrap();
        assert_eq!(
            store.save(ALICE, 1, Policy::OnOpen),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(&target).unwrap(), b"unchanged owned fixture");
        assert_eq!(fs::read(root.record(ALICE)).unwrap(), record_before);

        let destination = Scratch::new();
        destination.store().save(BOB, 0, Policy::OnOpen).unwrap();
        let destination_before = fs::read(destination.record(BOB)).unwrap();
        let alias = root.0.join("linked-settings");
        symlink(&destination.0, &alias).unwrap();
        let redirected = Store::new(alias);
        assert_eq!(redirected.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            redirected.save(ALICE, 0, Policy::OnOpen),
            Err(Error::Unavailable)
        );
        assert_eq!(
            fs::read(destination.record(BOB)).unwrap(),
            destination_before
        );
        assert!(!destination.record(ALICE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn mark_read_policy_refuses_unsafe_record_directory_links_and_oversize() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = Scratch::new();
        let store = root.store();
        store.save(ALICE, 0, Policy::OnOpen).unwrap();
        let record = root.record(ALICE);
        let original = fs::read(&record).unwrap();
        assert_eq!(
            fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(store.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            store.save(ALICE, 1, Policy::Manual),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(&record).unwrap(), original);
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.0.join("owned-hardlink");
        fs::hard_link(&record, &alias).unwrap();
        assert_eq!(store.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            store.save(ALICE, 1, Policy::Manual),
            Err(Error::Unavailable)
        );
        fs::remove_file(alias).unwrap();
        let target = root.0.join("owned-target");
        fs::rename(&record, &target).unwrap();
        symlink(&target, &record).unwrap();
        assert_eq!(store.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            store.save(ALICE, 1, Policy::Manual),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(&target).unwrap(), original);
        fs::remove_file(&record).unwrap();
        fs::rename(target, &record).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(store.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            store.save(ALICE, 1, Policy::Manual),
            Err(Error::Unavailable)
        );
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&record, vec![b' '; MAX_RECORD_BYTES + 1]).unwrap();
        assert_eq!(store.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            store.save(ALICE, 1, Policy::Manual),
            Err(Error::Unavailable)
        );
        assert_eq!(
            fs::metadata(record).unwrap().len(),
            (MAX_RECORD_BYTES + 1) as u64
        );
    }
}
