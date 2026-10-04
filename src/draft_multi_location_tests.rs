use super::*;
use crate::draft_location::Location;
struct Owned(PathBuf);
impl Owned {
    fn new() -> Self {
        Self(temp_dir(&format!(
            "osmap-multi-location-{}",
            generate_draft_id().unwrap()
        )))
    }
    fn store(&self) -> FileDraftStore {
        FileDraftStore::new(&self.0, DraftPolicy::default())
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
const ACCOUNT: &str = "alice@example.com";
#[test]
fn fresh_placement_and_existing_id_cas_restart_and_immutable_read() {
    let owned = Owned::new();
    let legacy = owned.store();
    let working = legacy.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    let a = record(&draft_id(70), ACCOUNT, 100);
    legacy.save(&a, 100).unwrap();
    let mut b = record(&draft_id(71), ACCOUNT, 100);
    b.request
        .attachments
        .push(attachment(b"public working attachment"));
    working.save(&b, 100).unwrap();
    let directory = legacy
        .resolved_draft_dir(ACCOUNT, &b.draft_id)
        .unwrap()
        .unwrap();
    assert!(directory.starts_with(owned.0.join(".locations/working")));
    assert_eq!(
        legacy
            .resolved_draft_dir(ACCOUNT, &a.draft_id)
            .unwrap()
            .unwrap(),
        legacy.draft_dir_for_username_and_id(ACCOUNT, &a.draft_id)
    );
    let mut loaded = owned
        .store()
        .read_immutable(ACCOUNT, &b.draft_id)
        .unwrap()
        .unwrap();
    loaded.starred = true;
    loaded.request.body = "edited public body".into();
    legacy.save(&loaded, 101).unwrap();
    assert_eq!(
        legacy
            .resolved_draft_dir(ACCOUNT, &b.draft_id)
            .unwrap()
            .unwrap(),
        directory
    );
    assert!(legacy
        .save(&loaded, 102)
        .unwrap_err()
        .reason
        .contains("stale"));
    assert_eq!(legacy.list(ACCOUNT, 102).unwrap().len(), 2);
    let current = legacy.load(ACCOUNT, &b.draft_id, 102).unwrap().unwrap();
    assert!(current.starred);
    assert_eq!(
        current.request.attachments[0].body,
        b"public working attachment"
    );
    assert!(legacy
        .delete(ACCOUNT, &b.draft_id, current.revision.unwrap())
        .unwrap());
    assert!(legacy.load(ACCOUNT, &a.draft_id, 102).unwrap().is_some());
}
#[test]
fn combined_count_and_byte_quota_cannot_reset_by_switching_location() {
    let owned = Owned::new();
    let mut policy = DraftPolicy {
        max_drafts_per_user: 2,
        ..DraftPolicy::default()
    };
    let default = FileDraftStore::new(&owned.0, policy);
    let working = default.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    default
        .save(&record(&draft_id(72), ACCOUNT, 100), 100)
        .unwrap();
    working
        .save(&record(&draft_id(73), ACCOUNT, 100), 100)
        .unwrap();
    assert!(default
        .save(&record(&draft_id(74), ACCOUNT, 100), 100)
        .unwrap_err()
        .reason
        .contains("quota"));
    let rows = default.list(ACCOUNT, 100).unwrap();
    let used: u64 = rows.iter().map(|r| r.storage_bytes).sum();
    let mut update = working.load(ACCOUNT, &draft_id(73), 100).unwrap().unwrap();
    update.request.body.push_str("more");
    policy.storage_max_bytes = used;
    let small = FileDraftStore::new(&owned.0, policy);
    assert!(small
        .save(&update, 101)
        .unwrap_err()
        .reason
        .contains("quota"));
    assert_eq!(
        default
            .load(ACCOUNT, &draft_id(73), 100)
            .unwrap()
            .unwrap()
            .request
            .body,
        "Hello from a saved draft."
    );
}
#[test]
fn missing_existing_location_never_recreates_at_latest_choice() {
    let owned = Owned::new();
    let store = owned.store();
    let working = store.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    working
        .save(&record(&draft_id(75), ACCOUNT, 100), 100)
        .unwrap();
    let loaded = store.load(ACCOUNT, &draft_id(75), 100).unwrap().unwrap();
    fs::rename(
        owned.0.join(".locations/working"),
        owned.0.join(".locations/away"),
    )
    .unwrap();
    assert!(store
        .save(&loaded, 101)
        .unwrap_err()
        .reason
        .contains("draft location unavailable"));
    assert!(!store
        .draft_dir_for_username_and_id(ACCOUNT, &loaded.draft_id)
        .exists());
}
#[test]
fn duplicate_id_refuses_before_expiry_cleanup_or_discard_in_either_location() {
    let owned = Owned::new();
    let store = owned.store();
    let working = store.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    let a = record(&draft_id(76), ACCOUNT, 100);
    store.save(&a, 100).unwrap();
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    let first = store.draft_dir_for_username_and_id(ACCOUNT, &a.draft_id);
    let second = owned
        .0
        .join(".locations/working")
        .join(owner_hash(ACCOUNT))
        .join(&a.draft_id);
    create_private_directory(&second).unwrap();
    write_file_atomic(
        &second.join("tmp"),
        &second.join(DRAFT_METADATA_FILE),
        &fs::read(first.join(DRAFT_METADATA_FILE)).unwrap(),
    )
    .unwrap();
    for result in [
        store.list(ACCOUNT, u64::MAX).map(|_| ()),
        store.cleanup_expired(ACCOUNT, u64::MAX).map(|_| ()),
        store.delete(ACCOUNT, &a.draft_id, 1).map(|_| ()),
        store.read_immutable(ACCOUNT, &a.draft_id).map(|_| ()),
    ] {
        assert!(result.unwrap_err().reason.contains("ambiguous"));
    }
    assert!(first.join(DRAFT_METADATA_FILE).exists());
    assert!(second.join(DRAFT_METADATA_FILE).exists());
}
#[cfg(unix)]
#[test]
fn unsafe_other_location_blocks_immutable_load_and_cleanup_without_fallback() {
    use std::os::unix::fs::symlink;
    let owned = Owned::new();
    let store = owned.store();
    let a = record(&draft_id(77), ACCOUNT, 100);
    store.save(&a, 100).unwrap();
    create_private_directory(&owned.0.join(".locations")).unwrap();
    symlink(&owned.0, owned.0.join(".locations/working")).unwrap();
    assert!(store.read_immutable(ACCOUNT, &a.draft_id).is_err());
    assert!(store.cleanup_expired(ACCOUNT, u64::MAX).is_err());
    assert!(store
        .draft_dir_for_username_and_id(ACCOUNT, &a.draft_id)
        .join(DRAFT_METADATA_FILE)
        .exists());
}
#[test]
fn working_publication_fault_preserves_complete_version_and_other_location() {
    let owned = Owned::new();
    let store = owned.store();
    let working = store.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    store
        .save(&record(&draft_id(78), ACCOUNT, 100), 100)
        .unwrap();
    working
        .save(&record(&draft_id(79), ACCOUNT, 100), 100)
        .unwrap();
    let before = fs::read(
        store
            .draft_dir_for_username_and_id(ACCOUNT, &draft_id(78))
            .join(DRAFT_METADATA_FILE),
    )
    .unwrap();
    let mut update = store.load(ACCOUNT, &draft_id(79), 100).unwrap().unwrap();
    update.request.body = "changed".into();
    update.request.attachments.push(attachment(b"public bytes"));
    let mut failing = store.clone();
    failing.save_fault = Some(atomic::SaveFault::BeforePublish);
    assert!(failing.save(&update, 101).is_err());
    assert_ne!(
        store
            .load(ACCOUNT, &draft_id(79), 101)
            .unwrap()
            .unwrap()
            .request
            .body,
        "changed"
    );
    failing.save_fault = Some(atomic::SaveFault::AfterPublish);
    assert!(failing.save(&update, 102).unwrap_err().save_unconfirmed());
    assert_eq!(
        store
            .load(ACCOUNT, &draft_id(79), 102)
            .unwrap()
            .unwrap()
            .request
            .body,
        "changed"
    );
    assert_eq!(
        fs::read(
            store
                .draft_dir_for_username_and_id(ACCOUNT, &draft_id(78))
                .join(DRAFT_METADATA_FILE)
        )
        .unwrap(),
        before
    );
}
#[test]
fn same_id_in_different_accounts_remains_isolated_and_expiry_is_aggregate() {
    let owned = Owned::new();
    let store = owned.store();
    let working = store.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    store
        .save(&record(&draft_id(80), ACCOUNT, 100), 100)
        .unwrap();
    working
        .qualify_location("bob@example.com", Location::Working)
        .unwrap();
    working
        .save(&record(&draft_id(80), "bob@example.com", 100), 100)
        .unwrap();
    working
        .save(&record(&draft_id(81), ACCOUNT, 100), 100)
        .unwrap();
    assert_eq!(store.cleanup_expired(ACCOUNT, u64::MAX).unwrap(), 2);
    assert!(store
        .read_immutable("bob@example.com", &draft_id(80))
        .unwrap()
        .is_some());
}

#[test]
fn disappeared_selected_working_refuses_fresh_save_without_recreation_or_fallback() {
    let owned = Owned::new();
    let default = owned.store();
    let working = default.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    let old = record(&draft_id(82), ACCOUNT, 100);
    working.save(&old, 100).unwrap();
    let current = working.load(ACCOUNT, &old.draft_id, 100).unwrap().unwrap();
    fs::rename(
        owned.0.join(".locations/working"),
        owned.0.join(".locations/away"),
    )
    .unwrap();
    assert!(working
        .save(&record(&draft_id(83), ACCOUNT, 101), 101)
        .is_err());
    assert!(!owned.0.join(".locations/working").exists());
    assert!(!default
        .draft_dir_for_username_and_id(ACCOUNT, &draft_id(83))
        .exists());
    assert!(default
        .save(&current, 101)
        .unwrap_err()
        .reason
        .contains("draft location unavailable"));
    assert!(!default
        .draft_dir_for_username_and_id(ACCOUNT, &old.draft_id)
        .exists());
}

#[test]
fn later_location_ambiguous_backups_refuse_before_any_earlier_recovery_mutation() {
    let owned = Owned::new();
    let default = owned.store();
    let working = default.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    let a = record(&draft_id(95), ACCOUNT, 100);
    let b = record(&draft_id(96), ACCOUNT, 100);
    default.save(&a, 100).unwrap();
    working.save(&b, 100).unwrap();
    let a_path = default
        .resolved_draft_dir(ACCOUNT, &a.draft_id)
        .unwrap()
        .unwrap();
    let b_path = default
        .resolved_draft_dir(ACCOUNT, &b.draft_id)
        .unwrap()
        .unwrap();
    let a_backup = a_path
        .parent()
        .unwrap()
        .join(format!(".{}.1.1.backup", a.draft_id));
    let b_backup1 = b_path
        .parent()
        .unwrap()
        .join(format!(".{}.1.1.backup", b.draft_id));
    let b_backup2 = b_path
        .parent()
        .unwrap()
        .join(format!(".{}.1.2.backup", b.draft_id));
    fs::rename(&a_path, &a_backup).unwrap();
    fs::rename(&b_path, &b_backup1).unwrap();
    create_private_directory(&b_backup2).unwrap();
    let b_bytes = fs::read(b_backup1.join(DRAFT_METADATA_FILE)).unwrap();
    fs::write(b_backup2.join(DRAFT_METADATA_FILE), &b_bytes).unwrap();
    #[cfg(unix)]
    fs::set_permissions(
        b_backup2.join(DRAFT_METADATA_FILE),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let a_bytes = fs::read(a_backup.join(DRAFT_METADATA_FILE)).unwrap();
    assert!(default.resolved_draft_dir(ACCOUNT, &a.draft_id).is_err());
    assert!(default.read_immutable(ACCOUNT, &a.draft_id).is_err());
    assert!(default.list(ACCOUNT, 101).is_err());
    assert!(
        !a_path.exists(),
        "later ambiguity must be detected before earlier rename"
    );
    assert_eq!(
        fs::read(a_backup.join(DRAFT_METADATA_FILE)).unwrap(),
        a_bytes
    );
    assert_eq!(
        fs::read(b_backup1.join(DRAFT_METADATA_FILE)).unwrap(),
        b_bytes
    );
    assert_eq!(
        fs::read(b_backup2.join(DRAFT_METADATA_FILE)).unwrap(),
        b_bytes
    );
}

#[test]
fn missing_registered_working_cannot_reset_aggregate_quota_by_default_fallback() {
    let owned = Owned::new();
    let default = owned.store();
    let working = default.clone().with_new_location(Location::Working);
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    default
        .save(&record(&draft_id(98), ACCOUNT, 100), 100)
        .unwrap();
    working
        .save(&record(&draft_id(99), ACCOUNT, 100), 100)
        .unwrap();
    let root = owned.0.join(".locations/working");
    let parked = owned.0.join("owned-missing-parked");
    fs::rename(&root, &parked).unwrap();
    let before = fs::read(default.metadata_path(ACCOUNT, &draft_id(98))).unwrap();
    assert!(default.list(ACCOUNT, 101).is_err());
    assert!(default.read_immutable(ACCOUNT, &draft_id(98)).is_err());
    assert!(default
        .save(&record(&draft_id(100), ACCOUNT, 101), 101)
        .is_err());
    assert!(default
        .qualify_location(ACCOUNT, Location::Default)
        .is_err());
    assert!(!root.exists());
    assert!(!default
        .draft_dir_for_username_and_id(ACCOUNT, &draft_id(100))
        .exists());
    assert_eq!(
        fs::read(default.metadata_path(ACCOUNT, &draft_id(98))).unwrap(),
        before
    );
    // Only an explicit fixed-location qualification restores availability.
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    assert!(root.is_dir());
    assert!(parked.is_dir());
    assert_eq!(default.list(ACCOUNT, 101).unwrap().len(), 1);
}

#[test]
fn registered_working_parent_disappearance_and_corrupt_marker_never_become_legacy_default() {
    let owned = Owned::new();
    let default = owned.store();
    default
        .save(&record(&draft_id(101), ACCOUNT, 100), 100)
        .unwrap();
    assert!(default
        .working_registration_file()
        .read(ACCOUNT)
        .unwrap()
        .is_none());
    default
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    let marker = default
        .working_registration_file()
        .read(ACCOUNT)
        .unwrap()
        .unwrap();
    let parent = owned.0.join(".locations");
    let parked = owned.0.join("owned-parent-parked");
    fs::rename(&parent, &parked).unwrap();
    assert!(default.list(ACCOUNT, 101).is_err());
    assert!(default
        .save(&record(&draft_id(102), ACCOUNT, 101), 101)
        .is_err());
    assert!(default
        .qualify_location(ACCOUNT, Location::Default)
        .is_err());
    assert!(!parent.exists());
    assert_eq!(
        default
            .working_registration_file()
            .read(ACCOUNT)
            .unwrap()
            .unwrap(),
        marker
    );
    default
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    assert_eq!(default.list(ACCOUNT, 101).unwrap().len(), 1);
    // Invalid/foreign registration is corruption, never first-use Default.
    let file = default.working_registration_file();
    let lock = file.lock(ACCOUNT).unwrap();
    lock.write(b"version=1\naccount=bob@example.com\nworking=1\n")
        .unwrap();
    drop(lock);
    assert!(default.list(ACCOUNT, 101).is_err());
    assert!(default
        .qualify_location(ACCOUNT, Location::Working)
        .is_err());
    let lock = file.lock(ACCOUNT).unwrap();
    lock.write(&marker).unwrap();
    drop(lock);
    assert_eq!(default.list(ACCOUNT, 101).unwrap().len(), 1);
    assert!(parked.is_dir());
}

#[test]
fn registered_account_owner_disappearance_does_not_skip_into_other_location_or_account() {
    let owned = Owned::new();
    let default = owned.store();
    let working = default.clone().with_new_location(Location::Working);
    let bob = "bob@example.com";
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    working.qualify_location(bob, Location::Working).unwrap();
    let a = record(&draft_id(103), ACCOUNT, 100);
    let b = record(&draft_id(104), bob, 100);
    default
        .save(&record(&draft_id(105), ACCOUNT, 100), 100)
        .unwrap();
    working.save(&a, 100).unwrap();
    working.save(&b, 100).unwrap();
    let a_dir = default
        .resolved_draft_dir(ACCOUNT, &a.draft_id)
        .unwrap()
        .unwrap();
    let bob_dir = default
        .resolved_draft_dir(bob, &b.draft_id)
        .unwrap()
        .unwrap();
    let bob_bytes = fs::read(bob_dir.join(DRAFT_METADATA_FILE)).unwrap();
    let a_owner = a_dir.parent().unwrap();
    let parked = owned.0.join("owned-account-parked");
    fs::rename(a_owner, &parked).unwrap();
    assert!(owned.0.join(".locations/working").is_dir());
    assert!(default.list(ACCOUNT, 101).is_err());
    assert!(default.load(ACCOUNT, &draft_id(105), 101).is_err());
    assert!(default.read_immutable(ACCOUNT, &draft_id(105)).is_err());
    assert!(default
        .save(&record(&draft_id(106), ACCOUNT, 101), 101)
        .is_err());
    assert!(!a_owner.exists());
    assert!(!default
        .draft_dir_for_username_and_id(ACCOUNT, &draft_id(106))
        .exists());
    assert_eq!(default.list(bob, 101).unwrap().len(), 1);
    assert_eq!(
        fs::read(bob_dir.join(DRAFT_METADATA_FILE)).unwrap(),
        bob_bytes
    );
    working
        .qualify_location(ACCOUNT, Location::Working)
        .unwrap();
    assert!(a_owner.is_dir());
    assert_eq!(default.list(ACCOUNT, 101).unwrap().len(), 1);
    assert!(parked.join(&a.draft_id).is_dir());
    assert_eq!(
        fs::read(bob_dir.join(DRAFT_METADATA_FILE)).unwrap(),
        bob_bytes
    );
}

#[test]
fn foreign_partial_working_initialization_does_not_disable_unregistered_legacy_account() {
    let owned = Owned::new();
    let store = owned.store();
    let bob = "bob@example.com";
    let a = record(&draft_id(107), ACCOUNT, 100);
    store.save(&a, 100).unwrap();
    store.qualify_location(bob, Location::Working).unwrap();
    let working = owned.0.join(".locations/working");
    // Another account's shared parent is not qualification for Alice.
    let alice_working = store.clone().with_new_location(Location::Working);
    assert!(alice_working
        .save(&record(&draft_id(109), ACCOUNT, 101), 101)
        .is_err());
    assert!(!working.join(owner_hash(ACCOUNT)).exists());
    fs::remove_dir_all(&working).unwrap(); // Controlled interrupted Bob initialization.
    assert!(owned.0.join(".locations").is_dir());
    assert!(store
        .working_registration_file()
        .read(ACCOUNT)
        .unwrap()
        .is_none());
    assert_eq!(store.list(ACCOUNT, 101).unwrap().len(), 1);
    assert!(store.load(ACCOUNT, &a.draft_id, 101).unwrap().is_some());
    store
        .save(&record(&draft_id(108), ACCOUNT, 101), 101)
        .unwrap();
    assert_eq!(store.list(ACCOUNT, 101).unwrap().len(), 2);
    assert!(!working.exists());
    assert!(store
        .working_registration_file()
        .read(ACCOUNT)
        .unwrap()
        .is_none());
    assert!(store.list(bob, 101).is_err());
    assert!(store.qualify_location(bob, Location::Default).is_err());
}
