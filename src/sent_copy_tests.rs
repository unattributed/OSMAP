use super::*;
use sha2::{Digest, Sha256};
use std::fs;

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "osmap-sent-copy-{}",
            crate::draft::generate_draft_id().unwrap()
        )))
    }
    fn store(&self) -> Store {
        Store::new(&self.0)
    }
    fn record(&self, account: &str) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(b"osmap-sent-copy-v1\0");
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
fn sent_copy_preference_persists_restarts_and_account_cas_isolation() {
    let root = Scratch::new();
    let store = root.store();
    assert_eq!(store.load(ALICE).unwrap(), Preference::default());
    assert!(!root.0.exists());
    let off = store.save(ALICE, 0, false).unwrap();
    assert_eq!(
        off,
        Preference {
            revision: 1,
            save_sent: false
        }
    );
    assert_eq!(root.store().load(ALICE).unwrap(), off);
    assert_eq!(root.store().load(BOB).unwrap(), Preference::default());
    let before = fs::read(root.record(ALICE)).unwrap();
    assert_eq!(store.save(ALICE, 0, true), Err(Error::Stale));
    assert_eq!(fs::read(root.record(ALICE)).unwrap(), before);
    store.save(BOB, 0, true).unwrap();
    assert_eq!(fs::read(root.record(ALICE)).unwrap(), before);
    assert_eq!(
        store.save(ALICE, 1, true).unwrap(),
        Preference {
            revision: 2,
            save_sent: true
        }
    );
}
#[test]
fn sent_copy_preference_refuses_foreign_corrupt_version_duplicate_and_oversize() {
    let root = Scratch::new();
    let store = root.store();
    store.save(ALICE, 0, false).unwrap();
    let path = root.record(ALICE);
    for bytes in [
        br#"{"version":1,"account":"bob@example.test","preference":{"revision":1,"save_sent":false}}"#.to_vec(),
        br#"{"version":2,"account":"alice@example.test","preference":{"revision":1,"save_sent":false}}"#.to_vec(),
        br#"{"version":1,"account":"alice@example.test","preference":{"revision":0,"save_sent":false}}"#.to_vec(),
        br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"save_sent":false,"save_sent":true}}"#.to_vec(),
        br#"{"version":1,"account":"alice@example.test","preference":{"revision":1,"save_sent":false},"extra":1}"#.to_vec(),
        b"not json".to_vec(), vec![b'x';MAX_BYTES+1],
    ] {
        fs::write(&path,&bytes).unwrap();
        assert_eq!(store.load(ALICE),Err(Error::Unavailable));
        assert_eq!(store.save(ALICE,1,true),Err(Error::Unavailable));
        assert_eq!(fs::read(&path).unwrap(),bytes);
    }
}
#[test]
fn sent_copy_preference_rejects_invalid_account_and_revision_overflow_without_write() {
    let root = Scratch::new();
    let store = root.store();
    for account in [
        "",
        " alice@example.test",
        "<alice@example.test>",
        "alice@example.test\r\n",
    ] {
        assert_eq!(store.load(account), Err(Error::Invalid));
        assert_eq!(store.save(account, 0, false), Err(Error::Invalid));
    }
    assert!(!root.0.exists());
    assert_eq!(store.save(ALICE, u64::MAX, false), Err(Error::Invalid));
    assert!(!root.0.exists());
}
#[cfg(unix)]
#[test]
fn sent_copy_preference_refuses_unsafe_record_directory_and_links() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = Scratch::new();
    let store = root.store();
    store.save(ALICE, 0, false).unwrap();
    let path = root.record(ALICE);
    let original = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(store.save(ALICE, 1, true), Err(Error::Unavailable));
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.0.join("unrelated");
    fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
    assert_eq!(store.save(ALICE, 1, true), Err(Error::Unavailable));
    assert_eq!(fs::read(&target).unwrap(), original);
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert_eq!(store.load(ALICE), Err(Error::Unavailable));
}
#[test]
fn sent_copy_preference_preserves_unrelated_settings_bytes() {
    let root = Scratch::new();
    let store = root.store();
    store.save(ALICE, 0, false).unwrap();
    let unrelated = root.0.join("legacy.settings");
    fs::write(&unrelated, b"content=plain\narchive=Archive\n").unwrap();
    let bytes = fs::read(&unrelated).unwrap();
    store.save(ALICE, 1, true).unwrap();
    assert_eq!(fs::read(&unrelated).unwrap(), bytes);
}
