use super::*;
use sha2::{Digest, Sha256};
use std::fs;

const GUID: &str = "1234567890abcdef1234567890abcdef";
const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "osmap-sent-location-{}",
            crate::draft::generate_draft_id().unwrap()
        )))
    }
    fn store(&self) -> Store {
        Store::new(&self.0)
    }
    fn record(&self, account: &str) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(b"osmap-sent-location-v1\0");
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
fn sent_location_preference_persists_restarts_and_account_cas_isolation() {
    let root = Scratch::new();
    let store = root.store();
    assert_eq!(store.load(ALICE).unwrap(), Preference::default());
    assert!(!root.0.exists());
    let off = store.save(ALICE, 0, "INBOX.CopyA", GUID).unwrap();
    assert_eq!(
        off,
        Preference {
            revision: 1,
            mailbox_name: "INBOX.CopyA".into(),
            mailbox_guid: Some(GUID.into())
        }
    );
    assert_eq!(root.store().load(ALICE).unwrap(), off);
    assert_eq!(root.store().load(BOB).unwrap(), Preference::default());
    let before = fs::read(root.record(ALICE)).unwrap();
    assert_eq!(store.save(ALICE, 0, "INBOX.CopyB", GUID), Err(Error::Stale));
    assert_eq!(fs::read(root.record(ALICE)).unwrap(), before);
    store.save(BOB, 0, "INBOX.CopyB", GUID).unwrap();
    assert_eq!(fs::read(root.record(ALICE)).unwrap(), before);
    assert_eq!(
        store.save(ALICE, 1, "INBOX.CopyB", GUID).unwrap(),
        Preference {
            revision: 2,
            mailbox_name: "INBOX.CopyB".into(),
            mailbox_guid: Some(GUID.into())
        }
    );
}
#[test]
fn sent_location_preference_refuses_foreign_corrupt_version_duplicate_and_oversize() {
    let root = Scratch::new();
    let store = root.store();
    store.save(ALICE, 0, "INBOX.CopyA", GUID).unwrap();
    let path = root.record(ALICE);
    for bytes in [
        br#"{"version":1,"account":"bob@example.test","preference":{"revision":1,"mailbox_name":"INBOX.CopyA","mailbox_guid":"1234567890abcdef1234567890abcdef"}}"#.to_vec(),
        br#"{"version":2,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"INBOX.CopyA","mailbox_guid":"1234567890abcdef1234567890abcdef"}}"#.to_vec(),
        br#"{"version":1,"account":"alice@example.test","preference":{"revision":0,"mailbox_name":"INBOX.CopyA","mailbox_guid":"1234567890abcdef1234567890abcdef"}}"#.to_vec(),
        br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"INBOX.CopyA","mailbox_guid":"1234567890abcdef1234567890abcdef","mailbox_name":"INBOX.CopyB"}}"#.to_vec(),
        br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"mailbox_name":"INBOX.CopyA","mailbox_guid":"1234567890abcdef1234567890abcdef"},"extra":1}"#.to_vec(),
        b"not json".to_vec(), vec![b'x';MAX_BYTES+1],
    ] {
        fs::write(&path,&bytes).unwrap();
        assert_eq!(store.load(ALICE),Err(Error::Unavailable));
        assert_eq!(store.save(ALICE, 1, "INBOX.CopyA", GUID), Err(Error::Unavailable));
        assert_eq!(fs::read(&path).unwrap(),bytes);
    }
}
#[test]
fn sent_location_preference_rejects_invalid_account_and_revision_overflow_without_write() {
    let root = Scratch::new();
    let store = root.store();
    for account in [
        "",
        " alice@example.test",
        "<alice@example.test>",
        "alice@example.test\r\n",
    ] {
        assert_eq!(store.load(account), Err(Error::Invalid));
        assert_eq!(
            store.save(account, 0, "INBOX.CopyA", GUID),
            Err(Error::Invalid)
        );
    }
    assert!(!root.0.exists());
    assert_eq!(
        store.save(ALICE, u64::MAX, "INBOX.CopyA", GUID),
        Err(Error::Invalid)
    );
    assert!(!root.0.exists());
}
#[cfg(unix)]
#[test]
fn sent_location_preference_refuses_unsafe_record_directory_and_links() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = Scratch::new();
    let store = root.store();
    store.save(ALICE, 0, "INBOX.CopyA", GUID).unwrap();
    let path = root.record(ALICE);
    let original = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        store.save(ALICE, 1, "INBOX.CopyB", GUID),
        Err(Error::Unavailable)
    );
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.0.join("unrelated");
    fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
    assert_eq!(
        store.save(ALICE, 1, "INBOX.CopyB", GUID),
        Err(Error::Unavailable)
    );
    assert_eq!(fs::read(&target).unwrap(), original);
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
}
#[test]
fn sent_location_preference_preserves_unrelated_settings_bytes() {
    let root = Scratch::new();
    let store = root.store();
    store.save(ALICE, 0, "INBOX.CopyA", GUID).unwrap();
    let unrelated = root.0.join("legacy.settings");
    fs::write(&unrelated, b"content=plain\narchive=Archive\n").unwrap();
    let bytes = fs::read(&unrelated).unwrap();
    store.save(ALICE, 1, "INBOX.CopyB", GUID).unwrap();
    assert_eq!(fs::read(&unrelated).unwrap(), bytes);
}

#[test]
fn sent_location_syntax_and_inconsistent_default_never_create_records() {
    let root = Scratch::new();
    let store = root.store();
    for (name, guid) in [
        ("", "1234567890abcdef1234567890abcdef"),
        ("INBOX.Copy*", GUID),
        ("INBOX.CopyA", "00000000000000000000000000000000"),
        ("INBOX.CopyA", "123"),
        ("INBOX.CopyA\r\n", GUID),
    ] {
        assert_eq!(store.save(ALICE, 0, name, guid), Err(Error::Invalid));
    }
    assert!(!root.0.exists());
    store.save(ALICE, 0, "INBOX.CopyA", GUID).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(root.record(ALICE)).unwrap()).unwrap();
    value["preference"]["mailbox_guid"] = serde_json::Value::Null;
    fs::write(root.record(ALICE), serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
}
#[test]
fn sent_location_private_owned_selectable_is_distinct_from_visibility_and_shared_folder() {
    let account = "alice@fixture.test";
    let snapshot = crate::folder_metadata::FolderSnapshot::parse(
        account,
        include_bytes!("../maint/ux/fixtures/folder-metadata-alice.imap"),
    )
    .unwrap();
    assert!(selectable(&snapshot, account, "INBOX"));
    assert!(selectable(&snapshot, account, "AliceOnly"));
    assert!(!selectable(&snapshot, "bob@fixture.test", "AliceOnly"));
    assert!(!selectable(&snapshot, account, "BobOnly"));
    assert!(!selectable(&snapshot, account, "Shared/Team"));
}
