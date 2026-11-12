use super::*;
use crate::message_metadata::{MessageMetadata, MessageProtection};
use std::{
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(PathBuf::from("/tmp").join(format!(
            "osmap-archive-event-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn request() -> MessageMoveRequest {
    MessageMoveRequest::new(
        MessageMovePolicy::default(),
        "INBOX",
        "Archive",
        7,
        MessageVersion::new("a".repeat(32), "native-guid-7".into()).unwrap(),
    )
    .unwrap()
}
fn moved() -> BrowserMessageMoveDecision {
    BrowserMessageMoveDecision::Moved {
        source_mailbox_name: "INBOX".into(),
        destination_mailbox_name: "Archive".into(),
        uid: 7,
    }
}
fn row() -> MessageSummary {
    MessageSummary {
        mailbox_name: "Archive".into(),
        uid: 81,
        flags: vec![],
        date_received: "1999-01-01T00:00:00Z".into(),
        size_virtual: 11,
        subject: None,
        from: None,
        to: None,
        metadata: Some(MessageMetadata {
            version: MessageVersion::new("b".repeat(32), "native-guid-7".into()).unwrap(),
            threading: None,
            attachments: None,
            protection: MessageProtection::Plain,
            attachment_count: None,
            preview: None,
        }),
    }
}
fn confirmation() -> ConfirmedArchive {
    ConfirmedArchive::resolve(
        ALICE,
        "Archive",
        &request(),
        &moved(),
        ALICE,
        "Archive",
        &[row()],
    )
    .unwrap()
}
fn identity(r: &MessageSummary) -> Identity {
    Identity::from_summary(ALICE, ALICE, &r.mailbox_name, r).unwrap()
}

#[test]
fn unavailable_metadata_and_unknown_legacy_events_have_distinct_projection() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    assert_eq!(date_for(None, ALICE, "Archive", &row()), Date::Unavailable);
    let empty = store.load(ALICE).unwrap();
    assert_eq!(
        date_for(Some(&empty), ALICE, "Archive", &row()),
        Date::Unknown
    );
    let known = store
        .record_confirmed_archive(ALICE, &confirmation(), 1234)
        .unwrap();
    assert_eq!(
        date_for(Some(&known), ALICE, "Archive", &row()),
        Date::Known(1234)
    );
    assert_eq!(
        date_for(Some(&known), BOB, "Archive", &row()),
        Date::Unavailable
    );
}

#[test]
fn another_authenticated_account_cannot_record_alices_confirmation() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    assert!(matches!(
        store.record_confirmed_archive(BOB, &confirmation(), 1234),
        Err(Error::Invalid)
    ));
    assert!(!root.0.exists());
}

#[test]
fn missing_legacy_metadata_is_unknown_and_read_only() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    let snapshot = store.load(ALICE).unwrap();
    assert_eq!(snapshot.revision(), 0);
    assert_eq!(snapshot.archived_at(&identity(&row())), Ok(None));
    assert!(!root.0.exists());
}

#[test]
fn confirmed_archive_persists_destination_uid_and_both_guids_not_received_time() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    let event = confirmation();
    assert_eq!(event.destination.uid, 81);
    assert_eq!(event.destination.mailbox_guid, "b".repeat(32));
    assert_eq!(event.source.uid, 7);
    let snapshot = store
        .record_confirmed_archive(ALICE, &event, 1_780_000_000)
        .unwrap();
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(
        Store::new(&root.0)
            .load(ALICE)
            .unwrap()
            .archived_at(&identity(&row())),
        Ok(Some(1_780_000_000))
    );
    let files: Vec<_> = fs::read_dir(&root.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let path = files
        .iter()
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let bytes = fs::read(path).unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("1999"));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn unchanged_confirmed_destination_is_idempotent_without_later_date() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    store
        .record_confirmed_archive(ALICE, &confirmation(), 1234)
        .unwrap();
    let second = store
        .record_confirmed_archive(ALICE, &confirmation(), 9999)
        .unwrap();
    assert_eq!(second.revision(), 1);
    assert_eq!(second.archived_at(&identity(&row())), Ok(Some(1234)));
}

#[test]
fn account_uid_generation_message_and_folder_mismatches_never_inherit_date() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    let snapshot = store
        .record_confirmed_archive(ALICE, &confirmation(), 1234)
        .unwrap();
    for mutation in 0..4 {
        let mut changed = row();
        match mutation {
            0 => changed.uid = 82,
            1 => changed.mailbox_name = "Other".into(),
            2 => changed.metadata.as_mut().unwrap().version.mailbox_guid = "c".repeat(32),
            _ => changed.metadata.as_mut().unwrap().version.message_guid = "another-guid".into(),
        }
        assert_eq!(snapshot.archived_at(&identity(&changed)), Ok(None));
    }
    let bob = Identity::from_summary(BOB, BOB, "Archive", &row()).unwrap();
    assert_eq!(snapshot.archived_at(&bob), Err(Error::Invalid));
    assert_eq!(store.load(BOB).unwrap().archived_at(&bob), Ok(None));
}

#[test]
fn refused_ambiguous_wrong_confirmation_cannot_construct_recordable_event() {
    for decision in [
        BrowserMessageMoveDecision::Denied {
            public_reason: "message_move_unknown".into(),
            retry_after_seconds: None,
        },
        BrowserMessageMoveDecision::Denied {
            public_reason: "message_move_stale".into(),
            retry_after_seconds: None,
        },
        BrowserMessageMoveDecision::Moved {
            source_mailbox_name: "Other".into(),
            destination_mailbox_name: "Archive".into(),
            uid: 7,
        },
        BrowserMessageMoveDecision::Moved {
            source_mailbox_name: "INBOX".into(),
            destination_mailbox_name: "Other".into(),
            uid: 7,
        },
        BrowserMessageMoveDecision::Moved {
            source_mailbox_name: "INBOX".into(),
            destination_mailbox_name: "Archive".into(),
            uid: 81,
        },
    ] {
        assert!(ConfirmedArchive::resolve(
            ALICE,
            "Archive",
            &request(),
            &decision,
            ALICE,
            "Archive",
            &[row()]
        )
        .is_err());
    }
}

#[test]
fn destination_resolution_rejects_foreign_missing_duplicate_wrong_generation_rows() {
    assert!(ConfirmedArchive::resolve(
        ALICE,
        "Archive",
        &request(),
        &moved(),
        BOB,
        "Archive",
        &[row()]
    )
    .is_err());
    assert!(ConfirmedArchive::resolve(
        ALICE,
        "Other",
        &request(),
        &moved(),
        ALICE,
        "Archive",
        &[row()]
    )
    .is_err());
    assert!(ConfirmedArchive::resolve(
        ALICE,
        "Archive",
        &request(),
        &moved(),
        ALICE,
        "Archive",
        &[]
    )
    .is_err());
    for fault in 0..6 {
        let mut rows = vec![row()];
        match fault {
            0 => rows[0].metadata = None,
            1 => rows.push(row()),
            2 => {
                let mut duplicate = row();
                duplicate.uid = 82;
                rows.push(duplicate);
            }
            3 => rows[0].mailbox_name = "Other".into(),
            4 => {
                let mut second = row();
                second.uid = 82;
                let metadata = second.metadata.as_mut().unwrap();
                metadata.version.message_guid = "another".into();
                metadata.version.mailbox_guid = "c".repeat(32);
                rows.push(second);
            }
            _ => rows.resize(MAX_EVENTS + 1, row()),
        }
        assert!(ConfirmedArchive::resolve(
            ALICE,
            "Archive",
            &request(),
            &moved(),
            ALICE,
            "Archive",
            &rows
        )
        .is_err());
    }
}

#[test]
fn malformed_or_tampered_source_is_rejected_before_storage() {
    for fault in 0..4 {
        let mut source = request();
        match fault {
            0 => source.uid = 0,
            1 => source.version.mailbox_guid = "invalid".into(),
            2 => source.version.mailbox_guid = "A".repeat(32),
            _ => source.destination_mailbox_name = "Archive\nOther".into(),
        }
        assert!(ConfirmedArchive::resolve(
            ALICE,
            "Archive",
            &source,
            &moved(),
            ALICE,
            "Archive",
            &[row()]
        )
        .is_err());
    }
    assert!(Identity::from_summary("bad account", "bad account", "Archive", &row()).is_err());
}

#[test]
fn corrupt_records_are_not_replaced_or_projected() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    store
        .record_confirmed_archive(ALICE, &confirmation(), 1234)
        .unwrap();
    let original = store.file.read(ALICE).unwrap().unwrap();
    for fault in 0..7 {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match fault {
            0 => value["account"] = BOB.into(),
            1 => value["version"] = 2.into(),
            2 => value["revision"] = 0.into(),
            3 => value["events"][0]["archived_at"] = 0.into(),
            4 => value["events"][0]["key"]["uid"] = 0.into(),
            5 => value["extra"] = true.into(),
            _ => {
                let item = value["events"][0].clone();
                value["events"].as_array_mut().unwrap().push(item);
            }
        }
        let corrupt = serde_json::to_vec(&value).unwrap();
        store.file.lock(ALICE).unwrap().write(&corrupt).unwrap();
        assert!(matches!(store.load(ALICE), Err(Error::Corrupt)));
        assert!(matches!(
            store.record_confirmed_archive(ALICE, &confirmation(), 9999),
            Err(Error::Corrupt)
        ));
        assert_eq!(store.file.read(ALICE).unwrap().unwrap(), corrupt);
    }
    let duplicate_field = String::from_utf8(original).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    store
        .file
        .lock(ALICE)
        .unwrap()
        .write(duplicate_field.as_bytes())
        .unwrap();
    assert!(matches!(store.load(ALICE), Err(Error::Corrupt)));
}

#[test]
fn clock_bounds_refuse_without_creating_store() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    for time in [0, MAX_TIMESTAMP + 1, u64::MAX] {
        assert!(matches!(
            store.record_confirmed_archive(ALICE, &confirmation(), time),
            Err(Error::Invalid)
        ));
    }
    assert!(!root.0.exists());
}

#[test]
fn lock_contention_preserves_record_and_never_repeats_move() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    store
        .record_confirmed_archive(ALICE, &confirmation(), 1234)
        .unwrap();
    let original = store.file.read(ALICE).unwrap().unwrap();
    let held = store.file.lock(ALICE).unwrap();
    assert!(matches!(
        store.record_confirmed_archive(ALICE, &confirmation(), 9999),
        Err(Error::Unavailable)
    ));
    assert_eq!(held.read().unwrap().unwrap(), original);
}

#[test]
fn full_record_capacity_refuses_new_event_without_pruning_unseen_messages() {
    let root = Scratch::new();
    let store = Store::new(&root.0);
    let mut snapshot = Snapshot {
        version: 1,
        account: ALICE.into(),
        revision: 1,
        events: vec![],
    };
    for i in 0..MAX_EVENTS {
        snapshot.events.push(Event {
            key: Key {
                folder: "Other".into(),
                uid: (i + 1) as u64,
                mailbox_guid: "c".repeat(32),
                message_guid: format!("old-{i}"),
            },
            archived_at: 1234,
        });
    }
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    store.file.lock(ALICE).unwrap().write(&bytes).unwrap();
    assert!(matches!(
        store.record_confirmed_archive(ALICE, &confirmation(), 9999),
        Err(Error::Capacity)
    ));
    assert_eq!(store.file.read(ALICE).unwrap().unwrap(), bytes);
}

#[test]
fn unsafe_record_file_is_refused_and_not_followed() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = Scratch::new();
    let store = Store::new(&root.0);
    store
        .record_confirmed_archive(ALICE, &confirmation(), 1234)
        .unwrap();
    let path = fs::read_dir(&root.0)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(store.load(ALICE), Err(Error::Unavailable)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let target = root.0.join("target");
    fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert!(matches!(
        store.record_confirmed_archive(ALICE, &confirmation(), 9999),
        Err(Error::Unavailable)
    ));
    assert_eq!(fs::read(target).unwrap(), bytes);
}
