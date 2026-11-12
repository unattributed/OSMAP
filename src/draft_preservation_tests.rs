use super::*;

#[test]
fn incomplete_and_maximum_size_text_survive_a_new_store_instance() {
    let directory = temp_dir("osmap-draft-incomplete-restart");
    let policy = DraftPolicy::default();
    let store = FileDraftStore::new(&directory, policy);
    let mut unfinished = record(&draft_id(31), "alice@example.com", 100);
    unfinished.request.recipients_text = "  New colleague <unfinished@".into();
    unfinished.request.cc_text = "".into();
    unfinished.request.bcc_text = "private@example.test".into();
    unfinished.request.subject = "".into();
    unfinished.request.body = "é".repeat(policy.compose_policy.body_max_len / 2);
    store.save(&unfinished, 100).unwrap();
    drop(store);
    let restored = FileDraftStore::new(&directory, policy)
        .load("alice@example.com", &unfinished.draft_id, 101).unwrap().unwrap();
    assert_eq!(restored.revision, Some(1));
    assert_eq!(restored.request, unfinished.request);
    assert!(crate::send::ComposeRequest::new(policy.compose_policy,
        &restored.request.recipients_text, &restored.request.subject, &restored.request.body).is_err());
    assert!(!format!("{restored:?}").contains("private@example.test"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn stale_updates_and_stale_deletes_leave_current_draft_intact() {
    let directory = temp_dir("osmap-draft-revisions");
    let store = FileDraftStore::new(&directory, DraftPolicy::default());
    let original = record(&draft_id(32), "alice@example.com", 100);
    store.save(&original, 100).unwrap();
    let mut first = store.load("alice@example.com", &original.draft_id, 100).unwrap().unwrap();
    let mut stale = first.clone();
    first.request.body = "Saved in the first tab".into();
    store.save(&first, 101).unwrap();
    stale.request.body = "Typed in an older tab".into();
    assert_eq!(store.save(&stale, 102).unwrap_err().reason, "draft revision is stale");
    assert_eq!(store.delete("alice@example.com", &original.draft_id, 1).unwrap_err().reason, "draft revision is stale");
    let current = store.load("alice@example.com", &original.draft_id, 102).unwrap().unwrap();
    assert_eq!(current.request.body, first.request.body);
    assert_eq!(current.revision, Some(2));
    assert!(!store.delete("bob@example.com", &original.draft_id, 2).unwrap());
    assert!(store.delete("alice@example.com", &original.draft_id, 2).unwrap());
    assert!(store.save(&stale, 103).is_err(), "stale save must not recreate a deleted draft");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn storage_quota_counts_metadata_and_attachments_and_preserves_failed_update() {
    let directory = temp_dir("osmap-draft-byte-quota");
    let mut draft = record(&draft_id(33), "alice@example.com", 100);
    draft.request.attachments.push(attachment(b"retained original attachment"));
    let policy = DraftPolicy { storage_max_bytes: draft.summary().storage_bytes + 100, ..DraftPolicy::default() };
    let store = FileDraftStore::new(&directory, policy);
    store.save(&draft, 100).unwrap();
    let saved = store.load("alice@example.com", &draft.draft_id, 100).unwrap().unwrap();
    let mut larger = saved.clone();
    larger.request.body.push_str(&"x".repeat(100));
    assert!(store.save(&larger, 101).unwrap_err().reason.contains("quota"));
    assert_eq!(store.load("alice@example.com", &draft.draft_id, 101).unwrap(), Some(saved.clone()));
    let mut smaller = saved;
    smaller.request.body.clear();
    store.save(&smaller, 102).unwrap();
    assert_eq!(store.list("alice@example.com", 102).unwrap()[0].total_attachment_bytes, 28);
    assert_eq!(DraftPolicy::default().max_drafts_per_user, 50);
    assert_eq!(DraftPolicy::default().storage_max_bytes, 50 * 1024 * 1024);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn source_identity_round_trips_rejects_partial_metadata_and_preserves_legacy_references() {
    let directory = temp_dir("osmap-draft-source-identity");
    let store = FileDraftStore::new(&directory, DraftPolicy::default());
    let mut draft = record(&draft_id(39), "alice@example.com", 100);
    draft.source_attachments = Some(DraftSourceAttachments {
        mailbox_name: "INBOX".into(), uid: 9,
        version: Some(crate::message_metadata::MessageVersion::new("a".repeat(32), "native-message-9".into()).unwrap()),
        part_paths: vec!["1.2".into()],
    });
    store.save(&draft, 100).unwrap();
    let path = store.metadata_path("alice@example.com", &draft.draft_id);
    let current = fs::read_to_string(&path).unwrap();
    assert!(current.starts_with("version=9\n"));
    assert_eq!(store.load("alice@example.com", &draft.draft_id, 100).unwrap().unwrap().source_attachments, draft.source_attachments);
    let without_message = current.lines().filter(|line| !line.starts_with("source_message_guid_hex=")).collect::<Vec<_>>().join("\n") + "\n";
    for invalid in [without_message.clone(), current.replace("version=9", "version=6"), current.replace("source_message_guid_hex=", "source_message_guid_hex=00")] {
        fs::write(&path, &invalid).unwrap();
        assert!(store.load("alice@example.com", &draft.draft_id, 100).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
    }
    let legacy = without_message.lines().filter(|line| !line.starts_with("source_mailbox_guid_hex=") && !line.starts_with("body_format=")).collect::<Vec<_>>().join("\n").replace("version=9", "version=6") + "\n";
    fs::write(&path, &legacy).unwrap();
    let loaded = store.load("alice@example.com", &draft.draft_id, 100).unwrap().unwrap();
    assert!(loaded.source_attachments.as_ref().unwrap().version.is_none());
    assert_eq!(loaded.source_attachments.as_ref().unwrap().part_paths, ["1.2"]);
    assert_eq!(fs::read_to_string(&path).unwrap(), legacy, "reading does not bind a legacy UID to a current message");
    store.save(&loaded, 101).unwrap();
    assert!(store.load("alice@example.com", &draft.draft_id, 101).unwrap().unwrap().source_attachments.unwrap().version.is_none());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn saved_and_source_attachment_counts_share_the_same_bound() {
    let directory = temp_dir("osmap-draft-source-count");
    let store = FileDraftStore::new(&directory, DraftPolicy::default());
    let mut draft = record(&draft_id(40), "alice@example.com", 100);
    draft.request.attachments = (0..3).map(|_| attachment(b"public synthetic attachment")).collect();
    draft.source_attachments = Some(DraftSourceAttachments { mailbox_name: "INBOX".into(), uid: 9, version: None, part_paths: vec!["1.2".into()] });
    assert!(store.save(&draft, 100).is_err());
    draft.request.attachments.pop();
    store.save(&draft, 100).unwrap();
    assert_eq!(store.load("alice@example.com", &draft.draft_id, 100).unwrap().unwrap().summary().attachment_count, 3);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn draft_lock_is_nonblocking_and_scoped_to_one_account() {
    let directory = temp_dir("osmap-draft-account-lock");
    let store = FileDraftStore::new(&directory, DraftPolicy::default());
    let lock = store.acquire_exclusive_lock("alice@example.com").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(store.list("alice@example.com", 100).unwrap_err().reason, "draft store busy");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    store.save(&record(&draft_id(34), "bob@example.com", 100), 100).unwrap();
    drop(lock);
    assert!(store.list("alice@example.com", 100).unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn legacy_record_migrates_only_after_a_revision_zero_save() {
    let directory = temp_dir("osmap-draft-legacy-migration");
    let store = FileDraftStore::new(&directory, DraftPolicy::default());
    let draft = record(&draft_id(35), "alice@example.com", 100);
    store.save(&draft, 100).unwrap();
    let path = store.metadata_path("alice@example.com", &draft.draft_id);
    let current = fs::read_to_string(&path).unwrap();
    for version in ["1", "2", "3", "4"] {
        let legacy = current.replace("version=9", &format!("version={version}")).replace("body_format=plain\n", "").replace("revision=1\n", "").replace("starred=0\n", "");
        fs::write(&path, &legacy).unwrap();
        let mut loaded = store.load("alice@example.com", &draft.draft_id, 100).unwrap().unwrap();
        assert_eq!(loaded.revision, Some(0));
        assert_eq!(fs::read_to_string(&path).unwrap(), legacy, "read does not rewrite legacy state");
        loaded.request.recipients_text.clear();
        store.save(&loaded, 101).unwrap();
        let saved = store.load("alice@example.com", &draft.draft_id, 101).unwrap().unwrap();
        assert_eq!(saved.revision, Some(1));
        assert!(saved.request.recipients_text.is_empty());
    }
    let v5 = fs::read_to_string(&path).unwrap().replace("version=9", "version=5").replace("body_format=plain\n", "").replace("starred=0\n", "");
    fs::write(&path, &v5).unwrap();
    let mut restored = store.load("alice@example.com", &draft.draft_id, 101).unwrap().unwrap();
    assert!(restored.request.recipients_text.is_empty());
    assert!(!restored.starred);
    assert_eq!(restored.revision, Some(1));
    restored.starred = true;
    store.save(&restored, 102).unwrap();
    assert!(store.load("alice@example.com", &draft.draft_id, 102).unwrap().unwrap().starred);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn store_refuses_linked_files_and_unsafe_directories_without_rewriting_them() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    let directory = temp_dir("osmap-draft-private-files");
    let store = FileDraftStore::new(&directory, DraftPolicy::default());
    let draft = record(&draft_id(36), "alice@example.com", 100);
    store.save(&draft, 100).unwrap();
    let path = store.metadata_path("alice@example.com", &draft.draft_id);
    let original = fs::read(&path).unwrap();
    let outside = directory.join("outside.draft");
    fs::rename(&path, &outside).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(store.load("alice@example.com", &draft.draft_id, 100).is_err());
    assert_eq!(fs::read(&outside).unwrap(), original);
    fs::remove_file(&path).unwrap();
    fs::hard_link(&outside, &path).unwrap();
    assert!(store.load("alice@example.com", &draft.draft_id, 100).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&outside, &path).unwrap();
    let owner = store.owner_dir_for_username("alice@example.com");
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.load("alice@example.com", &draft.draft_id, 100).is_err());
    assert_eq!(fs::metadata(&owner).unwrap().permissions().mode() & 0o777, 0o755);
    fs::remove_dir_all(directory).unwrap();
}
