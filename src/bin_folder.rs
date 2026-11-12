//! Account-owned reversible Bin destination; never grants mailbox ownership.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const NAMESPACE: &str = "osmap-bin-folder-v1";
const MAX_RECORD_BYTES: usize = 4096;
const LOCK_WAIT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinPreference {
    pub revision: u64,
    pub mailbox_name: String,
}
impl Default for BinPreference {
    fn default() -> Self {
        Self {
            revision: 0,
            mailbox_name: "Trash".into(),
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
    preference: BinPreference,
}

/// Syntax only. Save and move callers must independently prove this exact
/// folder belongs to the authenticated account and is currently selectable.
pub fn parse_mailbox_name(name: &str) -> Result<String, Error> {
    let entry =
        crate::mailbox::MailboxEntry::new(crate::mailbox::MailboxListingPolicy::default(), name)
            .map_err(|_| Error::Invalid)?;
    // Restore has the existing Inbox destination; Inbox itself cannot be Bin.
    if entry.name.eq_ignore_ascii_case("INBOX") {
        return Err(Error::Invalid);
    }
    Ok(entry.name)
}

/// Native selectable fact, independent of the narrower visible navigation
/// set. The caller additionally checks its exact current owned folder listing.
pub fn selectable(
    snapshot: &crate::folder_metadata::FolderSnapshot,
    account: &str,
    name: &str,
) -> bool {
    let longest = snapshot
        .namespaces()
        .iter()
        .filter(|ns| name.starts_with(ns.prefix()))
        .map(|ns| ns.prefix().len())
        .max();
    let mut matches = snapshot
        .namespaces()
        .iter()
        .filter(|ns| Some(ns.prefix().len()) == longest && name.starts_with(ns.prefix()));
    let private = matches
        .next()
        .is_some_and(|ns| ns.kind() == crate::folder_metadata::NamespaceKind::Private)
        && matches.next().is_none();
    private
        && parse_mailbox_name(name).is_ok()
        && snapshot.folder(account, name).is_ok_and(|folder| {
            folder.name() == name
                && !folder.has_flag("\\Noselect")
                && !folder.has_flag("\\NonExistent")
        })
}

#[derive(Debug, Clone)]
pub struct BinPreferencesStore {
    file: PrivateAccountFile,
}
impl BinPreferencesStore {
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
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<BinPreference, Error> {
        let Some(bytes) = bytes else {
            return Ok(BinPreference::default());
        };
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::Unavailable);
        }
        let stored: Stored = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if stored.version != 1
            || stored.account != account
            || stored.preference.revision == 0
            || parse_mailbox_name(&stored.preference.mailbox_name).is_err()
        {
            return Err(Error::Unavailable);
        }
        Ok(stored.preference)
    }
    /// A genuinely missing record retains Trash without any filesystem write.
    /// Corrupt, inaccessible or foreign-account records never reset to Trash.
    pub fn load(&self, account: &str) -> Result<BinPreference, Error> {
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
        mailbox_name: &str,
    ) -> Result<BinPreference, Error> {
        Self::validate_account(account)?;
        let mailbox_name = parse_mailbox_name(mailbox_name)?;
        // This bounds lock admission, not the existing filesystem sync contract.
        let deadline = Instant::now() + LOCK_WAIT;
        let lock = loop {
            match self.file.lock(account) {
                Ok(lock) => break lock,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(Error::Unavailable),
            }
        };
        let old = Self::decode(account, lock.read().map_err(|_| Error::Unavailable)?)?;
        if old.revision != expected_revision {
            return Err(Error::Stale);
        }
        let preference = BinPreference {
            revision: expected_revision.checked_add(1).ok_or(Error::Unavailable)?,
            mailbox_name,
        };
        let bytes = serde_json::to_vec(&Stored {
            version: 1,
            account: account.into(),
            preference: preference.clone(),
        })
        .map_err(|_| Error::Unavailable)?;
        // Publication may have renamed before a failed directory sync. Never
        // label this unchanged or automatically retry an unconfirmed write.
        lock.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::UserSettingsStore;
    use sha2::{Digest, Sha256};
    use std::fs;
    const ALICE: &str = "alice@example.test";
    const BOB: &str = "bob@example.test";
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-bin-folder-{}",
                crate::draft::generate_draft_id().unwrap()
            )))
        }
        fn store(&self) -> BinPreferencesStore {
            BinPreferencesStore::new(&self.0)
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
    fn bin_folder_native_selectability_accepts_owned_top_level_and_refuses_invalid_projections() {
        let transcript = concat!(
            "* PREAUTH fixture\r\n",
            "* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n",
            "* LIST () \".\" \"INBOX\"\r\n",
            "* LIST () \".\" \"Deleted\"\r\n",
            "* LIST (\\Noselect) \".\" \"Container\"\r\n",
            "* LIST (\\NonExistent) \".\" \"Absent\"\r\n",
            "L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n",
        );
        let snapshot =
            crate::folder_metadata::FolderSnapshot::parse(ALICE, transcript.as_bytes()).unwrap();
        assert!(selectable(&snapshot, ALICE, "Deleted"));
        for name in [
            "INBOX",
            "Container",
            "Absent",
            "Missing",
            "deleted",
            "Deleted\r\n",
        ] {
            assert!(!selectable(&snapshot, ALICE, name));
        }
        assert!(!selectable(&snapshot, BOB, "Deleted"));
        let foreign =
            crate::folder_metadata::FolderSnapshot::parse(BOB, transcript.as_bytes()).unwrap();
        assert!(!selectable(&foreign, ALICE, "Deleted"));
        let root = Scratch::new();
        let saved = root.store().save(ALICE, 0, "Deleted").unwrap();
        assert_eq!(root.store().load(ALICE).unwrap(), saved);
    }
    #[test]
    fn bin_folder_selectable_requires_unambiguous_private_namespace() {
        let transcript = concat!(
            "* PREAUTH fixture\r\n",
            "* NAMESPACE ((\"\" NIL)) ((\"Shared/\" \"/\")) ((\"Public/\" \"/\"))\r\nN1 OK done\r\n",
            "* LIST () NIL \"Deleted\"\r\n",
            "* LIST () \"/\" \"Shared/Team\"\r\n",
            "* LIST () \"/\" \"Public/News\"\r\n",
            "L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n",
        );
        let snapshot =
            crate::folder_metadata::FolderSnapshot::parse(ALICE, transcript.as_bytes()).unwrap();
        assert!(selectable(&snapshot, ALICE, "Deleted"));
        assert!(!selectable(&snapshot, ALICE, "Shared/Team"));
        assert!(!selectable(&snapshot, ALICE, "Public/News"));
        let ambiguous = transcript.replace("((\"Shared/\" \"/\"))", "((\"\" NIL))");
        // The native parser refuses duplicate-prefix transcripts before a
        // selectable snapshot can exist; do not bypass that invariant.
        assert!(
            crate::folder_metadata::FolderSnapshot::parse(ALICE, ambiguous.as_bytes()).is_err()
        );
    }

    #[test]
    fn bin_folder_persists_restart_isolates_accounts_and_refuses_stale_without_write() {
        let root = Scratch::new();
        let store = root.store();
        assert_eq!(store.load(ALICE).unwrap(), BinPreference::default());
        assert!(!root.0.exists());
        let saved = store.save(ALICE, 0, "INBOX.Deleted").unwrap();
        assert_eq!(saved.revision, 1);
        assert_eq!(saved.mailbox_name, "INBOX.Deleted");
        assert_eq!(root.store().load(ALICE).unwrap(), saved);
        let bytes = fs::read(root.record(ALICE)).unwrap();
        assert_eq!(store.save(ALICE, 0, "Trash"), Err(Error::Stale));
        assert_eq!(fs::read(root.record(ALICE)).unwrap(), bytes);
        assert_eq!(store.load(BOB).unwrap(), BinPreference::default());
        let bob = store.save(BOB, 0, "INBOX.OtherBin").unwrap();
        assert_eq!(store.load(ALICE).unwrap(), saved);
        assert_eq!(store.load(BOB).unwrap(), bob);
        assert_eq!(store.save(ALICE, 1, "Trash").unwrap().revision, 2);
    }
    #[test]
    fn bin_folder_interleaved_legacy_archive_content_writes_preserve_independent_records() {
        let root = Scratch::new();
        let legacy = crate::settings::FileUserSettingsStore::new(&root.0);
        legacy.save_archive(ALICE, Some("INBOX.Archive")).unwrap();
        let path = legacy.settings_path_for_username(ALICE);
        let before = fs::read(&path).unwrap();
        let saved = root.store().save(ALICE, 0, "INBOX.Deleted").unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
        let bin_bytes = fs::read(root.record(ALICE)).unwrap();
        legacy
            .save_content(
                ALICE,
                crate::rendering::HtmlDisplayPreference::PreferPlainText,
            )
            .unwrap();
        legacy
            .save_archive(ALICE, Some("INBOX.ArchiveLater"))
            .unwrap();
        assert_eq!(fs::read(root.record(ALICE)).unwrap(), bin_bytes);
        let settings = legacy.load(ALICE).unwrap().unwrap();
        let later = fs::read(&path).unwrap();
        root.store().save(ALICE, saved.revision, "Trash").unwrap();
        assert_eq!(fs::read(&path).unwrap(), later);
        assert_eq!(legacy.load(ALICE).unwrap().unwrap(), settings);
        assert_eq!(root.store().load(BOB).unwrap(), BinPreference::default());
    }
    #[test]
    fn bin_folder_invalid_corrupt_foreign_and_overflow_preserve_existing_bytes() {
        let root = Scratch::new();
        let store = root.store();
        store.save(ALICE, 0, "INBOX.Deleted").unwrap();
        let path = root.record(ALICE);
        let before = fs::read(&path).unwrap();
        for name in [
            "",
            "INBOX",
            "inbox",
            "Trash\r\nOther",
            "Trash\0",
            &"a".repeat(256),
        ] {
            assert_eq!(store.save(ALICE, 1, name), Err(Error::Invalid));
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        assert_eq!(store.save("bad\naccount", 0, "Trash"), Err(Error::Invalid));
        for bytes in [
            b"bad".to_vec(),
            br#"{"version":2,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"Trash"}}"#.to_vec(),
            br#"{"version":1,"account":"bob@example.test","preference":{"revision":1,"mailbox_name":"Trash"}}"#.to_vec(),
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":0,"mailbox_name":"Trash"}}"#.to_vec(),
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"INBOX"}}"#.to_vec(),
            br#"{"version":1,"version":1,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"Trash"}}"#.to_vec(),
            br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"Trash","unknown":1}}"#.to_vec(),
            vec![b' '; MAX_RECORD_BYTES + 1],
        ] {
            fs::write(&path, &bytes).unwrap();
            assert_eq!(store.load(ALICE), Err(Error::Unavailable));
            assert_eq!(store.save(ALICE, 1, "INBOX.Deleted"), Err(Error::Unavailable));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let overflow = serde_json::to_vec(&Stored {
            version: 1,
            account: ALICE.into(),
            preference: BinPreference {
                revision: u64::MAX,
                mailbox_name: "Trash".into(),
            },
        })
        .unwrap();
        fs::write(&path, &overflow).unwrap();
        assert_eq!(
            store.save(ALICE, u64::MAX, "INBOX.Deleted"),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(&path).unwrap(), overflow);
    }
    #[cfg(unix)]
    #[test]
    fn bin_folder_private_files_lock_and_unsafe_record_refuse_without_reset() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = Scratch::new();
        let store = root.store();
        store.save(ALICE, 0, "INBOX.Deleted").unwrap();
        let path = root.record(ALICE);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let lock = store.file.lock(ALICE).unwrap();
        assert_eq!(store.save(ALICE, 1, "Trash"), Err(Error::Unavailable));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(lock);
        assert_eq!(store.save(ALICE, 1, "Trash").unwrap().revision, 2);
        let target = root.0.join("preserved-target");
        fs::write(&target, b"sentinel").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(store.load(ALICE), Err(Error::Unavailable));
        assert_eq!(
            store.save(ALICE, 2, "INBOX.Deleted"),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(&target).unwrap(), b"sentinel");
    }
}
