use super::*;

#[test]
fn settled_usage_preserves_expired_payload_and_counts_exact_private_files() {
    let root = temp_dir("osmap-settled-usage");
    let policy = DraftPolicy {
        max_age_seconds: 1,
        ..DraftPolicy::default()
    };
    let store = FileDraftStore::new(&root, policy);
    assert_eq!(
        store.settle_storage_usage("alice@example.com").unwrap(),
        (0, 0)
    );
    let mut saved = record(&draft_id(70), "alice@example.com", 100);
    saved.request.attachments = vec![attachment(b"same blob"), attachment(b"same blob")];
    store.save(&saved, 100).unwrap();
    let directory = store.draft_dir_for_username_and_id("alice@example.com", &saved.draft_id);
    let metadata = fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap();
    let expected = metadata.len() as u64 + b"same blob".len() as u64;
    // No now argument and no expiry side effect, even with a long-expired payload.
    assert_eq!(
        store.settle_storage_usage("alice@example.com").unwrap(),
        (1, expected)
    );
    assert_eq!(
        fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap(),
        metadata
    );
    assert_eq!(
        store
            .read_immutable("alice@example.com", &saved.draft_id)
            .unwrap()
            .unwrap()
            .expires_at,
        101
    );
    assert!(store.settle_storage_usage("bad account").is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn settled_usage_recovers_interrupted_allocations_without_touching_other_accounts() {
    let root = temp_dir("osmap-settled-orphans");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let mut first = record(&draft_id(71), "alice@example.com", 100);
    first.request.attachments = vec![attachment(b"committed")];
    store.save(&first, 100).unwrap();
    let directory = store.draft_dir_for_username_and_id("alice@example.com", &first.draft_id);
    let expected = fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap().len() as u64
        + b"committed".len() as u64;
    let mut update = store
        .read_immutable("alice@example.com", &first.draft_id)
        .unwrap()
        .unwrap();
    update
        .request
        .attachments
        .push(attachment(b"orphan allocation"));
    let mut interrupted = store.clone();
    interrupted.save_fault = Some(atomic::SaveFault::BeforePublish);
    assert!(interrupted.save(&update, 101).is_err());
    let orphan = directory.join(atomic::blob_name(b"orphan allocation"));
    assert!(orphan.exists());
    let mut staged = record(&draft_id(72), "alice@example.com", 101);
    staged.request.attachments = vec![attachment(b"unpublished")];
    let staged_dir = store.draft_dir_for_username_and_id("alice@example.com", &staged.draft_id);
    // Simulate process interruption before save() can perform its ordinary
    // first-save cleanup. The public save error path correctly removes this.
    assert!(interrupted.publish_atomic_record_in(&staged, None, &staged_dir).is_err());
    assert!(staged_dir.exists());
    let bob = record(&draft_id(73), "bob@example.com", 100);
    store.save(&bob, 100).unwrap();
    let bob_dir = store.draft_dir_for_username_and_id("bob@example.com", &bob.draft_id);
    let bob_orphan = bob_dir.join(atomic::blob_name(b"bob retained orphan"));
    put(&bob_orphan, b"bob retained orphan");
    let bob_metadata = fs::read(bob_dir.join(DRAFT_METADATA_FILE)).unwrap();
    assert_eq!(
        store.settle_storage_usage("alice@example.com").unwrap(),
        (1, expected)
    );
    assert!(!orphan.exists() && !staged_dir.exists());
    assert!(bob_orphan.exists());
    assert_eq!(
        fs::read(bob_dir.join(DRAFT_METADATA_FILE)).unwrap(),
        bob_metadata
    );
    assert_eq!(
        store
            .read_immutable("alice@example.com", &first.draft_id)
            .unwrap()
            .unwrap()
            .revision,
        Some(1)
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn settled_usage_refuses_unknown_unsafe_and_link_residue_without_zero_fabrication() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for kind in ["unknown", "unsafe", "symlink", "owner_unknown"] {
        let root = temp_dir("osmap-settled-refusal");
        let store = FileDraftStore::new(&root, DraftPolicy::default());
        let first = record(&draft_id(74), "alice@example.com", 100);
        store.save(&first, 100).unwrap();
        let directory = store.draft_dir_for_username_and_id("alice@example.com", &first.draft_id);
        let metadata = fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap();
        let outside = root.join("outside-private-file");
        put(&outside, b"unchanged outside");
        let residue = if kind == "owner_unknown" {
            store
                .owner_dir_for_username("alice@example.com")
                .join("unexpected")
        } else if kind == "unknown" {
            directory.join("unexpected")
        } else {
            directory.join(atomic::blob_name(b"unsafe orphan"))
        };
        if kind == "symlink" {
            symlink(&outside, &residue).unwrap();
        } else {
            put(&residue, b"unsafe orphan");
            if kind == "unsafe" {
                fs::set_permissions(&residue, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        assert!(
            store.settle_storage_usage("alice@example.com").is_err(),
            "{kind}"
        );
        assert!(fs::symlink_metadata(&residue).is_ok(), "{kind}");
        assert_eq!(
            fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap(),
            metadata
        );
        assert_eq!(fs::read(&outside).unwrap(), b"unchanged outside");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn settled_usage_reads_complete_unconfirmed_publication_without_retry_or_expiry() {
    let root = temp_dir("osmap-settled-unconfirmed");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let first = record(&draft_id(75), "alice@example.com", 100);
    store.save(&first, 100).unwrap();
    let mut update = store
        .read_immutable("alice@example.com", &first.draft_id)
        .unwrap()
        .unwrap();
    update
        .request
        .attachments
        .push(attachment(b"published body"));
    let mut interrupted = store.clone();
    interrupted.save_fault = Some(atomic::SaveFault::AfterPublish);
    assert!(interrupted
        .save(&update, 101)
        .unwrap_err()
        .save_unconfirmed());
    let directory = store.draft_dir_for_username_and_id("alice@example.com", &first.draft_id);
    let metadata = fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap();
    assert_eq!(
        store.settle_storage_usage("alice@example.com").unwrap(),
        (1, metadata.len() as u64 + b"published body".len() as u64)
    );
    assert_eq!(
        fs::read(directory.join(DRAFT_METADATA_FILE)).unwrap(),
        metadata
    );
    assert_eq!(
        store
            .read_immutable("alice@example.com", &first.draft_id)
            .unwrap()
            .unwrap()
            .revision,
        Some(2)
    );
    fs::remove_dir_all(root).unwrap();
}

fn put(path: &Path, bytes: &[u8]) {
    write_file_atomic(&path.with_extension("test-tmp"), path, bytes).unwrap();
}
