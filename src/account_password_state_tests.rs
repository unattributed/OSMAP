use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

const ALICE: &str = "alice@osmap-password.invalid";
const BOB: &str = "bob@osmap-password.invalid";
const STAMP: &str = "20261018120000";
const INTENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-password-state-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn store(&self) -> Store {
        Store::open(&self.0, crate::openbsd::effective_uid()).unwrap()
    }
    // Explicit fixture initialization, never called from a runtime method.
    fn provision(&self, account: &str, epoch: u64, changed_at: Option<&str>) {
        let name = stem(account).unwrap();
        for (suffix, data) in [
            ("lock", Vec::new()),
            (
                "json",
                serde_json::to_vec(&Record {
                    epoch,
                    state: State::Active,
                    changed_at: changed_at.map(str::to_owned),
                    intent: None,
                    used_intents: vec![],
                })
                .unwrap(),
            ),
        ] {
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.0.join(format!("{name}.{suffix}")))
                .unwrap();
            out.write_all(&data).unwrap();
            out.sync_all().unwrap();
        }
        File::open(&self.0).unwrap().sync_all().unwrap();
    }
    fn record(&self, account: &str) -> PathBuf {
        self.0.join(format!("{}.json", stem(account).unwrap()))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn existing_epoch_v1_schema_completes_once_and_preserves_other_account() {
    let scratch = Scratch::new();
    scratch.provision(ALICE, 3, None);
    scratch.provision(BOB, 7, Some(STAMP));
    let bob = fs::read(scratch.record(BOB)).unwrap();
    let store = scratch.store();
    let mut guard = store.lock_before(ALICE, until()).unwrap();
    assert_eq!(guard.admission(Some(3)).unwrap().epoch, 3);
    guard.begin(3, INTENT, 1000).unwrap();
    assert_eq!(guard.status().unwrap().state, State::Pending);
    assert_eq!(guard.admission(Some(3)), Err(Error::Refused));
    assert_eq!(guard.complete(), Err(Error::Refused));
    guard.record_verified_write(STAMP).unwrap();
    let done = guard.complete().unwrap();
    assert_eq!(
        done,
        Status {
            epoch: 4,
            state: State::Active,
            changed_at: Some(STAMP.into())
        }
    );
    assert_eq!(guard.begin(4, INTENT, 1001), Err(Error::Refused));
    drop(guard);
    drop(store);
    let restarted = scratch.store();
    let mut guard = restarted.lock_before(ALICE, until()).unwrap();
    assert_eq!(guard.admission(Some(3)), Err(Error::Refused));
    assert_eq!(guard.admission(Some(4)).unwrap(), done);
    assert_eq!(guard.begin(4, INTENT, 1001), Err(Error::Replay));
    assert_eq!(fs::read(scratch.record(BOB)).unwrap(), bob);
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(scratch.record(ALICE)).unwrap()).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 5);
    for forbidden in ["current", "password", "confirmation", "hash", "totp"] {
        assert!(!value.as_object().unwrap().contains_key(forbidden));
    }
}

#[test]
fn restart_cannot_clear_pending_or_contained_or_known_verified_write() {
    for contain in [false, true] {
        let scratch = Scratch::new();
        scratch.provision(ALICE, 1, Some("20261017120000"));
        {
            let store = scratch.store();
            let mut guard = store.lock_before(ALICE, until()).unwrap();
            guard.begin(1, INTENT, 1000).unwrap();
            assert_eq!(guard.status().unwrap().changed_at, None);
            guard.record_verified_write(STAMP).unwrap();
            assert_eq!(guard.record_verified_write(STAMP), Err(Error::Refused));
            assert_eq!(guard.known_refused(), Err(Error::Refused));
            if contain {
                guard.contain().unwrap();
            }
        }
        let store = scratch.store();
        let mut guard = store.lock_before(ALICE, until()).unwrap();
        assert_eq!(
            guard.status().unwrap(),
            Status {
                epoch: 1,
                state: if contain {
                    State::Contained
                } else {
                    State::Pending
                },
                changed_at: Some(STAMP.into())
            }
        );
        assert_eq!(guard.admission(Some(1)), Err(Error::Refused));
        assert_eq!(guard.known_refused(), Err(Error::Refused));
        assert_eq!(guard.complete(), Err(Error::Refused));
        assert_eq!(guard.begin(1, INTENT, 2000), Err(Error::Refused));
    }
    let scratch = Scratch::new();
    scratch.provision(ALICE, 1, None);
    let store = scratch.store();
    let mut guard = store.lock_before(ALICE, until()).unwrap();
    guard.begin(1, INTENT, 1000).unwrap();
    guard.original_deadline = Instant::now();
    assert_eq!(guard.record_verified_write(STAMP), Err(Error::Expired));
    assert_eq!(guard.known_refused(), Err(Error::Refused));
}

#[test]
fn exact_zero_write_refusal_preserves_history_and_durable_consumed_intent() {
    let scratch = Scratch::new();
    scratch.provision(ALICE, 5, Some(STAMP));
    {
        let store = scratch.store();
        let mut guard = store.lock_before(ALICE, until()).unwrap();
        guard.begin(5, INTENT, 1000).unwrap();
        guard.known_refused().unwrap();
        assert_eq!(
            guard.admission(Some(5)).unwrap().changed_at.as_deref(),
            Some(STAMP)
        );
    }
    let store = scratch.store();
    let mut guard = store.lock_before(ALICE, until()).unwrap();
    assert_eq!(guard.begin(5, INTENT, 1299), Err(Error::Replay));
    guard.begin(5, INTENT, 1300).unwrap();
    guard.contain().unwrap();
}

#[test]
fn exhausted_epoch_and_expired_budget_refuse_without_state_write() {
    let scratch = Scratch::new();
    scratch.provision(ALICE, crate::account_admission::MAX_EPOCH, None);
    let before = fs::read(scratch.record(ALICE)).unwrap();
    let store = scratch.store();
    assert!(matches!(
        store.lock_before(ALICE, Instant::now()),
        Err(Error::Expired)
    ));
    let mut guard = store.lock_before(ALICE, until()).unwrap();
    assert!(guard
        .admission(Some(crate::account_admission::MAX_EPOCH))
        .is_ok());
    assert_eq!(
        guard.begin(crate::account_admission::MAX_EPOCH, INTENT, 1000),
        Err(Error::Refused)
    );
    assert_eq!(fs::read(scratch.record(ALICE)).unwrap(), before);
}

#[test]
fn lock_wait_uses_original_deadline_and_drop_releases_duplicate_description() {
    let scratch = Scratch::new();
    scratch.provision(ALICE, 0, None);
    let store = scratch.store();
    let guard = store.lock_before(ALICE, until()).unwrap();
    let duplicate = guard.lock.try_clone().unwrap();
    let began = Instant::now();
    assert!(matches!(
        store.lock_before(ALICE, began + Duration::from_millis(25)),
        Err(Error::Expired)
    ));
    assert!(began.elapsed() < Duration::from_secs(1));
    drop(guard);
    assert!(store.lock_before(ALICE, until()).is_ok());
    drop(duplicate);
}

#[test]
fn missing_corrupt_duplicate_keys_permissions_links_and_replacements_refuse() {
    let scratch = Scratch::new();
    let store = scratch.store();
    assert!(store.lock_before(ALICE, until()).is_err());
    assert_eq!(
        fs::read_dir(&scratch.0).unwrap().count(),
        0,
        "runtime recreated missing state"
    );
    scratch.provision(ALICE, 0, None);
    let path = scratch.record(ALICE);
    let original = fs::read(&path).unwrap();
    for data in [
        b"{}".to_vec(),
        b"{\"epoch\":0,\"epoch\":0,\"state\":\"active\",\"changed_at\":null,\"intent\":null,\"used_intents\":[]}".to_vec(),
        b"{\"epoch\":0,\"state\":\"active\",\"intent\":null,\"used_intents\":[]}".to_vec(),
        b"{\"epoch\":0,\"state\":\"pending\",\"changed_at\":null,\"intent\":null,\"used_intents\":[]}".to_vec(),
        vec![b' '; 4097],
    ] {
        fs::write(&path, data).unwrap();
        assert!(store.lock_before(ALICE, until()).is_err());
    }
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(store.lock_before(ALICE, until()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = scratch.0.join("record-link");
    fs::hard_link(&path, &linked).unwrap();
    assert!(store.lock_before(ALICE, until()).is_err());
    fs::remove_file(&linked).unwrap();
    fs::rename(&path, &linked).unwrap();
    symlink(&linked, &path).unwrap();
    assert!(store.lock_before(ALICE, until()).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&linked, &path).unwrap();
    let mut guard = store.lock_before(ALICE, until()).unwrap();
    fs::rename(&path, &linked).unwrap();
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(guard.begin(0, INTENT, 1000), Err(Error::Unavailable));
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn root_replacement_and_symlink_refuse_held_store() {
    let scratch = Scratch::new();
    scratch.provision(ALICE, 0, None);
    let store = scratch.store();
    let moved = scratch.0.with_extension("moved");
    fs::rename(&scratch.0, &moved).unwrap();
    fs::create_dir(&scratch.0).unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(store.lock_before(ALICE, until()).is_err());
    fs::remove_dir(&scratch.0).unwrap();
    symlink(&moved, &scratch.0).unwrap();
    assert!(store.lock_before(ALICE, until()).is_err());
    assert!(Store::open(&scratch.0, crate::openbsd::effective_uid()).is_err());
    fs::remove_file(&scratch.0).unwrap();
    fs::rename(&moved, &scratch.0).unwrap();
}

#[test]
fn preexisting_uncertainty_marker_blocks_active_record_and_is_never_removed() {
    let scratch = Scratch::new();
    scratch.provision(ALICE, 0, Some(STAMP));
    let path = scratch
        .0
        .join(format!("{}.uncertain", stem(ALICE).unwrap()));
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    out.write_all(b"previous interrupted operation").unwrap();
    out.sync_all().unwrap();
    let before = fs::read(&path).unwrap();
    let store = scratch.store();
    let mut guard = store.lock_before(ALICE, until()).unwrap();
    assert_eq!(guard.status().unwrap().state, State::Contained);
    assert_eq!(guard.admission(Some(0)), Err(Error::Refused));
    assert_eq!(guard.begin(0, INTENT, 1000), Err(Error::Refused));
    assert_eq!(guard.known_refused(), Err(Error::Refused));
    assert_eq!(guard.complete(), Err(Error::Refused));
    assert_eq!(fs::read(&path).unwrap(), before);
}
