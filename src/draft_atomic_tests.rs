use super::*;

fn put(path: &Path, bytes: &[u8]) {
    write_file_atomic(&path.with_extension("test-tmp"), path, bytes).unwrap();
}

#[test]
fn interrupted_atomic_publication_reopens_one_complete_version_and_refuses_stale_retry() {
    for fault in [atomic::SaveFault::BeforePublish, atomic::SaveFault::AfterPublish] {
        let root = temp_dir("osmap-atomic-interruption");
        let store = FileDraftStore::new(&root, DraftPolicy::default());
        let mut first = record(&draft_id(50), "alice@example.com", 100);
        first.request.attachments = vec![attachment(b"original file")];
        store.save(&first, 100).unwrap();
        let mut update = store.load("alice@example.com", &first.draft_id, 100).unwrap().unwrap();
        update.request.body = "New typed text".into();
        update.request.attachments.push(attachment(b"new file"));
        let mut interrupted = store.clone(); interrupted.save_fault = Some(fault);
        let error = interrupted.save(&update, 101).unwrap_err();
        assert_eq!(error.save_unconfirmed(), fault == atomic::SaveFault::AfterPublish);
        let restarted = FileDraftStore::new(&root, DraftPolicy::default());
        let loaded = restarted.load("alice@example.com", &first.draft_id, 101).unwrap().unwrap();
        assert_eq!(loaded.request.attachments[0].body, b"original file");
        if fault == atomic::SaveFault::BeforePublish {
            assert_eq!(loaded.revision, Some(1));
            assert_eq!(loaded.request.body, first.request.body);
            assert_eq!(loaded.request.attachments.len(), 1);
            restarted.save(&update, 102).unwrap();
        } else {
            assert_eq!(loaded.revision, Some(2));
            assert_eq!(loaded.request.body, "New typed text");
            assert_eq!(loaded.request.attachments.len(), 2);
            assert!(restarted.save(&update, 102).unwrap_err().reason.contains("revision"));
            restarted.save(&loaded, 102).unwrap();
        }
        let directory = store.draft_dir_for_username_and_id("alice@example.com", &first.draft_id);
        assert_eq!(fs::read_dir(directory).unwrap().count(), 3, "only the manifest and two referenced blobs remain");
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn atomic_storage_detects_changed_blob_bytes_and_preserves_legacy_files_until_publication() {
    let root = temp_dir("osmap-atomic-legacy-blob");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let mut first = record(&draft_id(51), "alice@example.com", 100);
    first.request.attachments = vec![attachment(b"original file")];
    store.save(&first, 100).unwrap();
    let directory = store.draft_dir_for_username_and_id("alice@example.com", &first.draft_id);
    let blob = atomic::blob_name(b"original file");
    put(&directory.join(&blob), b"modified file");
    assert!(store.load("alice@example.com", &first.draft_id, 100).unwrap_err().reason.contains("identity mismatch"));
    put(&directory.join(&blob), b"original file");
    fs::rename(directory.join(&blob), directory.join("attachment-0.body")).unwrap();
    let metadata = fs::read_to_string(directory.join(DRAFT_METADATA_FILE)).unwrap().replace("version=9", "version=7").replace("body_format=plain\n", "").replace(&blob, "attachment-0.body");
    put(&directory.join(DRAFT_METADATA_FILE), metadata.as_bytes());
    let legacy = store.load("alice@example.com", &first.draft_id, 100).unwrap().unwrap();
    let mut interrupted = store.clone(); interrupted.save_fault = Some(atomic::SaveFault::BeforePublish);
    assert!(interrupted.save(&legacy, 101).is_err());
    assert_eq!(fs::read_to_string(directory.join(DRAFT_METADATA_FILE)).unwrap(), metadata);
    assert_eq!(store.load("alice@example.com", &first.draft_id, 100).unwrap().unwrap().request.attachments[0].body, b"original file");
    store.save(&legacy, 102).unwrap();
    assert!(directory.join(&blob).exists());
    assert!(!directory.join("attachment-0.body").exists());
    assert!(fs::read_to_string(directory.join(DRAFT_METADATA_FILE)).unwrap().starts_with("version=9\n"));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn unchanged_attachment_blob_is_not_rewritten_by_star_or_text_edits() {
    use std::os::unix::fs::MetadataExt;
    let root = temp_dir("osmap-atomic-immutable-blob");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let mut first = record(&draft_id(52), "alice@example.com", 100);
    first.request.attachments = vec![attachment(b"kept bytes")];
    store.save(&first, 100).unwrap();
    let path = store.draft_dir_for_username_and_id("alice@example.com", &first.draft_id).join(atomic::blob_name(b"kept bytes"));
    let original = fs::metadata(&path).unwrap();
    let mut update = store.load("alice@example.com", &first.draft_id, 100).unwrap().unwrap();
    update.starred = true; update.request.body = "Edited text".into();
    store.save(&update, 101).unwrap();
    let current = fs::metadata(&path).unwrap();
    assert_eq!(current.ino(), original.ino());
    assert_eq!(current.mtime(), original.mtime());
    assert_eq!(current.mode() & 0o777, 0o600);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_legacy_directory_swap_recovers_only_the_owned_previous_record() {
    let root = temp_dir("osmap-atomic-legacy-recovery");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let first = record(&draft_id(53), "alice@example.com", 100);
    store.save(&first, 100).unwrap();
    let owner = store.owner_dir_for_username("alice@example.com");
    let final_dir = owner.join(&first.draft_id);
    let backup = owner.join(format!(".{}.123.0.backup", first.draft_id));
    let staged = owner.join(format!(".{}.123.0.staging", first.draft_id));
    create_private_directory(&staged).unwrap();
    fs::rename(&final_dir, &backup).unwrap();
    let restarted = FileDraftStore::new(&root, DraftPolicy::default());
    let restored = restarted.load("alice@example.com", &first.draft_id, 100).unwrap().unwrap();
    assert_eq!(restored.request, first.request);
    assert_eq!(restored.revision, Some(1));
    assert!(final_dir.exists() && !backup.exists() && staged.exists());
    assert!(restarted.list("bob@example.com", 100).unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_backups_do_not_overwrite_a_newer_version_or_resurrect_after_confirmed_discard() {
    let root = temp_dir("osmap-atomic-prior-backup");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let first = record(&draft_id(54), "alice@example.com", 100);
    store.save(&first, 100).unwrap();
    let metadata = fs::read(store.metadata_path("alice@example.com", &first.draft_id)).unwrap();
    let mut current = store.load("alice@example.com", &first.draft_id, 100).unwrap().unwrap();
    current.request.body = "Latest saved text".into();
    store.save(&current, 101).unwrap();
    let backup = store.owner_dir_for_username("alice@example.com").join(format!(".{}.123.1.backup", first.draft_id));
    create_private_directory(&backup).unwrap(); put(&backup.join(DRAFT_METADATA_FILE), &metadata);
    assert_eq!(store.load("alice@example.com", &first.draft_id, 101).unwrap().unwrap().request.body, "Latest saved text");
    assert!(!backup.exists());
    assert!(store.delete("alice@example.com", &first.draft_id, 2).unwrap());
    assert!(FileDraftStore::new(&root, DraftPolicy::default()).load("alice@example.com", &first.draft_id, 101).unwrap().is_none());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ambiguous_and_foreign_backups_remain_untouched() {
    for foreign in [false, true] {
        let root = temp_dir("osmap-atomic-ambiguous-backup");
        let store = FileDraftStore::new(&root, DraftPolicy::default());
        let first = record(&draft_id(55), "alice@example.com", 100);
        store.save(&first, 100).unwrap();
        let owner = store.owner_dir_for_username("alice@example.com");
        let final_dir = owner.join(&first.draft_id);
        let backup = owner.join(format!(".{}.123.1.backup", first.draft_id));
        fs::rename(&final_dir, &backup).unwrap();
        let mut metadata = fs::read_to_string(backup.join(DRAFT_METADATA_FILE)).unwrap();
        if foreign {
            metadata = metadata.replace(&hex_lower(b"alice@example.com"), &hex_lower(b"bob@example.com"));
            put(&backup.join(DRAFT_METADATA_FILE), metadata.as_bytes());
        } else {
            let other = owner.join(format!(".{}.123.2.backup", first.draft_id));
            create_private_directory(&other).unwrap(); put(&other.join(DRAFT_METADATA_FILE), metadata.as_bytes());
        }
        assert!(store.load("alice@example.com", &first.draft_id, 100).is_err());
        assert!(backup.exists() && !final_dir.exists());
        assert_eq!(fs::read_to_string(backup.join(DRAFT_METADATA_FILE)).unwrap(), metadata);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn incomplete_first_save_cleans_only_generated_private_files() {
    let root = temp_dir("osmap-atomic-unpublished");
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let first = record(&draft_id(56), "alice@example.com", 100);
    store.save(&first, 100).unwrap();
    let orphan = store.owner_dir_for_username("alice@example.com").join(draft_id(57));
    create_private_directory(&orphan).unwrap();
    put(&orphan.join(atomic::blob_name(b"unpublished")), b"unpublished");
    put(&orphan.join(".draft-write-123-1.tmp"), b"partial metadata");
    assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 1);
    assert!(!orphan.exists());
    create_private_directory(&orphan).unwrap(); put(&orphan.join("unrecognized.txt"), b"preserve");
    assert!(store.list("alice@example.com", 100).is_err());
    assert_eq!(fs::read(orphan.join("unrecognized.txt")).unwrap(), b"preserve");
    fs::remove_dir_all(root).unwrap();
}
