use super::*;
const A: &str = "alice@example.test";
const B: &str = "bob@example.test";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "osmap-notice-event-{}",
            crate::draft::generate_draft_id().unwrap()
        )))
    }
    fn store(&self) -> NotificationStore {
        NotificationStore::new(&self.0)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn notification_confirmed_source_replay_preserves_read_revision_owner_and_kind() {
    let root = Scratch::new();
    let store = root.store();
    assert!(store
        .record_once(
            A,
            NotificationKind::PasswordChanged,
            "epoch:3:stamp",
            100,
            100
        )
        .unwrap());
    let one = store.load(A, 100).unwrap();
    let read = store
        .set_read(A, &one.events[0].event_id, one.revision, true, 100)
        .unwrap();
    assert!(!root
        .store()
        .record_once(
            A,
            NotificationKind::PasswordChanged,
            "epoch:3:stamp",
            101,
            101
        )
        .unwrap());
    assert_eq!(root.store().load(A, 101).unwrap(), read);
    assert!(store
        .record_once(
            B,
            NotificationKind::PasswordChanged,
            "epoch:3:stamp",
            100,
            101
        )
        .unwrap());
    assert_ne!(
        store.load(B, 101).unwrap().events[0].event_id,
        read.events[0].event_id
    );
    assert!(store
        .record_once(A, NotificationKind::TotpChanged, "epoch:3:stamp", 101, 101)
        .unwrap());
    let bytes = store.file.read(A).unwrap().unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("epoch:3:stamp"));
}
#[test]
fn notification_retention_capacity_and_evicted_source_cannot_flood_replay() {
    let root = Scratch::new();
    let store = root.store();
    for at in 100..=300 {
        assert!(store
            .record_once(
                A,
                NotificationKind::SubmissionAccepted,
                &format!("intent:{at}"),
                at,
                at
            )
            .unwrap());
    }
    let full = store.load(A, 300).unwrap();
    assert_eq!(full.events.len(), MAX_EVENTS);
    assert!(!store
        .record_once(
            A,
            NotificationKind::SubmissionAccepted,
            "intent:100",
            100,
            300
        )
        .unwrap());
    assert_eq!(store.load(A, 300).unwrap(), full);
    assert!(!store
        .record_once(
            A,
            NotificationKind::NewMail,
            "too-old",
            100,
            100 + RETENTION_SECONDS
        )
        .unwrap());
    assert_eq!(
        store.record_once(A, NotificationKind::NewMail, "future", 400, 399),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.record_once(A, NotificationKind::NewMail, "bad\nsource", 400, 400),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.record_once(A, NotificationKind::NewMail, "ok", 301, 299),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.record_once(A, NotificationKind::NewMail, "ok", 299, 299),
        Err(NotificationError::ClockRollback)
    );
}
#[test]
fn notification_choices_backward_defaults_cas_and_mandatory_security() {
    use crate::notification_preferences::{Choice, DigestMode, Preference, Store};
    let old = br#"{"revision":1,"digest":"daily"}"#;
    let pref: Preference = serde_json::from_slice(old).unwrap();
    assert_eq!(pref.choices, Choice::default());
    let none = Choice {
        new_mail: false,
        mentions: false,
        openpgp: false,
        submission: false,
        sound: false,
        desktop: false,
    };
    for kind in [
        NotificationKind::PasswordChanged,
        NotificationKind::TotpChanged,
        NotificationKind::RecoveryCompleted,
        NotificationKind::PersonalKeyUnlocked,
        NotificationKind::PolicyChanged,
        NotificationKind::SessionRevoked,
    ] {
        assert!(kind.is_mandatory() && none.allows(kind));
        assert!(!kind.title().is_empty());
    }
    for kind in [
        NotificationKind::NewMail,
        NotificationKind::Mention,
        NotificationKind::PublicKeyImported,
        NotificationKind::SubmissionAccepted,
    ] {
        assert!(!kind.is_mandatory() && !none.allows(kind));
    }
    let root = Scratch::new();
    let store = Store::new(&root.0);
    let saved = store.save_choices(A, 0, DigestMode::Daily, none).unwrap();
    assert_eq!(store.load(A).unwrap(), saved);
    assert_eq!(store.load(B).unwrap(), Preference::default());
    assert_eq!(
        store.save_choices(A, 0, DigestMode::Individual, Choice::default()),
        Err(crate::notification_preferences::Error::Stale)
    );
    assert_eq!(
        store.save(A, 1, DigestMode::Individual).unwrap().choices,
        none
    );
}
#[cfg(unix)]
#[test]
fn notification_record_once_publication_failure_keeps_original_state() {
    use std::os::unix::fs::PermissionsExt;
    let root = Scratch::new();
    let store = root.store();
    store
        .record_once(A, NotificationKind::RecoveryCompleted, "case:one", 100, 100)
        .unwrap();
    let before = store.load(A, 100).unwrap();
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    let failed = store.record_once(A, NotificationKind::RecoveryCompleted, "case:two", 101, 101);
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(failed.is_err());
    assert_eq!(store.load(A, 101).unwrap(), before);
}

#[test]
fn notification_delete_all_preserves_sources_other_accounts_and_later_events() {
    let root = Scratch::new();
    let store = root.store();
    let sources = [
        (NotificationKind::PasswordChanged, "password:one"),
        (NotificationKind::NewMail, "mail:one"),
        (NotificationKind::Mention, "mention:one"),
    ];
    for (kind, source) in sources {
        store.record_once(A, kind, source, 100, 100).unwrap();
    }
    store
        .record(B, NotificationKind::SessionIssued, 100)
        .unwrap();
    let foreign = store.load(B, 100).unwrap();
    let initial = store.load(A, 100).unwrap();
    let read = store
        .set_read(A, &initial.events[0].event_id, initial.revision, true, 100)
        .unwrap();
    let partial = store
        .delete(A, &read.events[1].event_id, read.revision, 100)
        .unwrap();
    assert_eq!(
        store.delete_all(A, initial.revision, 100),
        Err(NotificationError::Stale)
    );
    assert_eq!(store.load(A, 100).unwrap(), partial);
    assert_eq!(
        store.delete_all("invalid account", 0, 100),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.delete_all(A, partial.revision, 99),
        Err(NotificationError::ClockRollback)
    );
    let empty = store.delete_all(A, partial.revision, 100).unwrap();
    assert!(empty.events.is_empty());
    assert_eq!(empty.revision, partial.revision + 1);
    assert_eq!(root.store().load(A, 101).unwrap(), empty);
    assert_eq!(store.delete_all(A, empty.revision, 101).unwrap(), empty);
    for (kind, source) in sources {
        assert!(!root.store().record_once(A, kind, source, 100, 101).unwrap());
    }
    assert_eq!(store.load(A, 101).unwrap(), empty);
    assert_eq!(store.load(B, 101).unwrap(), foreign);
    store
        .record_once(A, NotificationKind::NewMail, "mail:new", 102, 102)
        .unwrap();
    let later = store.load(A, 102).unwrap();
    assert_eq!(later.events.len(), 1);
    assert!(!later.events[0].read);
    assert_eq!(
        store.delete_all(A, empty.revision, 102),
        Err(NotificationError::Stale)
    );
    assert_eq!(store.load(A, 102).unwrap(), later);
    let lock = store.lock(A).unwrap();
    let retained = NotificationStore::read(&lock, A, 102).unwrap();
    assert_eq!(retained.events.len(), 4);
    assert_eq!(retained.dismissed.len(), 3);
    drop(lock);
    assert_eq!(store.load(B, 102).unwrap(), foreign);
}

#[test]
fn notification_mark_all_read_is_atomic_owner_bound_and_reopen_stable() {
    let root = Scratch::new();
    let store = root.store();
    for (kind, source) in [
        (NotificationKind::PasswordChanged, "password:one"),
        (NotificationKind::NewMail, "mail:one"),
        (NotificationKind::Mention, "mention:one"),
    ] {
        assert!(store.record_once(A, kind, source, 100, 100).unwrap());
    }
    store
        .record(B, NotificationKind::SessionIssued, 100)
        .unwrap();
    let foreign = store.load(B, 100).unwrap();
    let initial = store.load(A, 100).unwrap();
    assert_eq!(
        store.mark_all_read(A, initial.revision - 1, 100),
        Err(NotificationError::Stale)
    );
    assert_eq!(store.load(A, 100).unwrap(), initial);
    let read = store.mark_all_read(A, initial.revision, 100).unwrap();
    assert_eq!(read.revision, initial.revision + 1);
    assert_eq!(read.events.len(), 3);
    assert!(read.events.iter().all(|event| event.read));
    assert_eq!(root.store().load(A, 101).unwrap(), read);
    assert_eq!(store.mark_all_read(A, read.revision, 101).unwrap(), read);
    assert_eq!(store.load(B, 101).unwrap(), foreign);
    assert_eq!(
        store.mark_all_read("not an account", 0, 101),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.mark_all_read(A, read.revision, 99),
        Err(NotificationError::ClockRollback)
    );
}

#[test]
fn notification_delete_mandatory_notice_persists_without_replayed_resurrection() {
    let root = Scratch::new();
    let store = root.store();
    store
        .record_once(
            A,
            NotificationKind::PasswordChanged,
            "password:one",
            100,
            100,
        )
        .unwrap();
    store
        .record_once(A, NotificationKind::NewMail, "mail:one", 101, 101)
        .unwrap();
    let initial = store.load(A, 101).unwrap();
    let id = initial
        .events
        .iter()
        .find(|event| event.kind.is_mandatory())
        .unwrap()
        .event_id
        .clone();
    assert_eq!(
        store.delete(B, &id, 0, 101),
        Err(NotificationError::Missing)
    );
    assert_eq!(
        store.delete(A, "invalid", initial.revision, 101),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.delete(A, &id, initial.revision - 1, 101),
        Err(NotificationError::Stale)
    );
    assert_eq!(store.load(A, 101).unwrap(), initial);
    let deleted = store.delete(A, &id, initial.revision, 101).unwrap();
    assert_eq!(deleted.revision, initial.revision + 1);
    assert_eq!(deleted.events.len(), 1);
    assert_eq!(deleted.events[0].kind, NotificationKind::NewMail);
    assert_eq!(root.store().load(A, 102).unwrap(), deleted);
    assert!(!root
        .store()
        .record_once(
            A,
            NotificationKind::PasswordChanged,
            "password:one",
            102,
            102
        )
        .unwrap());
    assert_eq!(store.load(A, 102).unwrap(), deleted);
    assert_eq!(
        store.delete(A, &id, deleted.revision, 102).unwrap(),
        deleted
    );
    assert_eq!(
        store.set_read(A, &id, deleted.revision, false, 102),
        Err(NotificationError::Missing)
    );
    let all = store.mark_all_read(A, deleted.revision, 102).unwrap();
    assert_eq!(all.events.len(), 1);
    assert!(all.events[0].read);
    assert!(!store
        .record_once(
            A,
            NotificationKind::PasswordChanged,
            "password:one",
            100,
            102
        )
        .unwrap());
    assert_eq!(store.load(A, 102).unwrap(), all);
}

#[test]
fn notification_dismissal_schema_legacy_and_retention_are_bounded() {
    let root = Scratch::new();
    let store = root.store();
    store
        .record_once(A, NotificationKind::NewMail, "mail:old", 100, 100)
        .unwrap();
    let initial = store.load(A, 100).unwrap();
    let id = initial.events[0].event_id.clone();
    let lock = store.file.lock(A).unwrap();
    let original = lock.read().unwrap().unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&original).unwrap();
    legacy.as_object_mut().unwrap().remove("dismissed");
    lock.write(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    drop(lock);
    assert_eq!(store.load(A, 100).unwrap(), initial);
    for dismissed in [
        serde_json::json!([id.clone(), id.clone()]),
        serde_json::json!(["f".repeat(32)]),
        serde_json::json!(["invalid"]),
        serde_json::json!(vec![id.clone(); 201]),
    ] {
        let mut bad = legacy.clone();
        bad["dismissed"] = dismissed;
        let bytes = serde_json::to_vec(&bad).unwrap();
        let lock = store.file.lock(A).unwrap();
        lock.write(&bytes).unwrap();
        drop(lock);
        assert_eq!(store.load(A, 100), Err(NotificationError::Corrupt));
        assert_eq!(store.file.read(A).unwrap().unwrap(), bytes);
    }
    let lock = store.file.lock(A).unwrap();
    lock.write(&original).unwrap();
    drop(lock);
    let deleted = store.delete(A, &id, initial.revision, 100).unwrap();
    assert!(deleted.events.is_empty());
    let expired = store.load(A, 100 + RETENTION_SECONDS).unwrap();
    assert!(expired.events.is_empty());
    let bytes = store.file.read(A).unwrap().unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["dismissed"], serde_json::json!([]));
    assert!(!store
        .record_once(
            A,
            NotificationKind::NewMail,
            "mail:old",
            100,
            100 + RETENTION_SECONDS
        )
        .unwrap());
    assert_eq!(store.load(A, 100 + RETENTION_SECONDS).unwrap(), expired);
}

#[test]
fn notification_dismissed_capacity_eviction_bounds_stable_and_fresh_observations() {
    let root = Scratch::new();
    let store = root.store();
    for at in 100..300 {
        store
            .record_once(A, NotificationKind::NewMail, &format!("mail:{at}"), at, at)
            .unwrap();
    }
    let full = store.load(A, 300).unwrap();
    let oldest = full.events.last().unwrap().event_id.clone();
    let dismissed = store.delete(A, &oldest, full.revision, 300).unwrap();
    assert_eq!(dismissed.events.len(), MAX_EVENTS - 1);
    store
        .record_once(A, NotificationKind::NewMail, "mail:300", 300, 300)
        .unwrap();
    let current = store.load(A, 300).unwrap();
    assert_eq!(current.events.len(), MAX_EVENTS);
    assert!(!store
        .record_once(A, NotificationKind::NewMail, "mail:100", 100, 300)
        .unwrap());
    assert_eq!(root.store().load(A, 300).unwrap(), current);
    let bytes = store.file.read(A).unwrap().unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["dismissed"], serde_json::json!([]));
    assert!(bytes.len() <= MAX_BYTES);
    // A native message can be observed again with a new observation time after
    // its source identity has left the bounded inbox history. This is not a
    // permanent dismissal ledger: only the stable old timestamp is fenced.
    assert!(store
        .record_once(A, NotificationKind::NewMail, "mail:100", 301, 301)
        .unwrap());
    let fresh = root.store().load(A, 301).unwrap();
    assert_eq!(fresh.events.len(), MAX_EVENTS);
    assert_eq!(fresh.events[0].event_id, oldest);
    assert_eq!(fresh.events[0].occurred_at, 301);
    assert!(!fresh.events[0].read);
}

#[test]
fn notification_maximum_dismissed_metadata_fits_existing_record_bound() {
    let root = Scratch::new();
    let store = root.store();
    let events: Vec<_> = (0..MAX_EVENTS)
        .map(|id| NotificationEvent {
            event_id: format!("{id:032x}"),
            kind: NotificationKind::RecoveryContactRequested,
            occurred_at: u64::MAX,
            read: false,
        })
        .collect();
    let record = Stored {
        owner_ref: owner_ref(A),
        version: 1,
        revision: u64::MAX,
        high_water: u64::MAX,
        discarded_through: u64::MAX,
        dismissed: events.iter().map(|event| event.event_id.clone()).collect(),
        events,
    };
    let bytes = serde_json::to_vec(&record).unwrap();
    assert!(bytes.len() <= MAX_BYTES);
    let lock = store.file.lock(A).unwrap();
    lock.write(&bytes).unwrap();
    drop(lock);
    let inbox = store.load(A, u64::MAX).unwrap();
    assert!(inbox.events.is_empty());
    assert_eq!(inbox.revision, u64::MAX);
}

#[cfg(unix)]
#[test]
fn notification_bulk_and_delete_unsafe_custody_refusal_preserves_inbox() {
    use std::os::unix::fs::PermissionsExt;
    let root = Scratch::new();
    let store = root.store();
    store
        .record_once(
            A,
            NotificationKind::PasswordChanged,
            "password:one",
            100,
            100,
        )
        .unwrap();
    let before = store.load(A, 100).unwrap();
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    let marked = store.mark_all_read(A, before.revision, 100);
    let deleted = store.delete(A, &before.events[0].event_id, before.revision, 100);
    std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(marked.is_err() && deleted.is_err());
    assert_eq!(root.store().load(A, 100).unwrap(), before);
}
