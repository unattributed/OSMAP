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
