use super::*;
const A: &str = "alice@example.test";
const B: &str = "bob@example.test";
const GUID: &str = "0123456789abcdef0123456789abcdef";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "osmap-notice-observe-{}",
            crate::draft::generate_draft_id().unwrap()
        )))
    }
    fn store(&self) -> Store {
        Store::new(&self.0)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn identities(items: &[(u64, &str)]) -> Vec<InboxIdentity> {
    items
        .iter()
        .map(|(uid, guid)| InboxIdentity {
            uid: *uid,
            message_guid: (*guid).into(),
        })
        .collect()
}
fn snapshot<'a>(messages: &'a [InboxIdentity]) -> InboxSnapshot<'a> {
    InboxSnapshot {
        account: A,
        mailbox_guid: GUID,
        messages,
    }
}
#[test]
fn notification_inbox_baseline_new_native_identity_old_page_restart_and_generation() {
    let root = Scratch::new();
    let store = root.store();
    let first = identities(&[(10, "first"), (9, "old")]);
    assert_eq!(
        store.observe_inbox(A, snapshot(&first), 100).unwrap(),
        InboxObservation {
            baseline: true,
            messages: vec![]
        }
    );
    let fresh = identities(&[(12, "new-two"), (11, "new-one"), (10, "first")]);
    let observed = root
        .store()
        .observe_inbox(A, snapshot(&fresh), 101)
        .unwrap();
    assert!(!observed.baseline);
    assert_eq!(
        observed.messages.iter().map(|m| m.uid).collect::<Vec<_>>(),
        vec![11, 12]
    );
    assert!(observed.messages.iter().all(|m| hex(&m.source_ref)));
    assert!(store
        .observe_inbox(A, snapshot(&fresh), 101)
        .unwrap()
        .messages
        .is_empty());
    assert!(store
        .observe_inbox(A, snapshot(&first), 102)
        .unwrap()
        .messages
        .is_empty());
    let replaced = store
        .observe_inbox(
            A,
            InboxSnapshot {
                account: A,
                mailbox_guid: "ffffffffffffffffffffffffffffffff",
                messages: &first,
            },
            103,
        )
        .unwrap();
    assert!(replaced.baseline && replaced.messages.is_empty());
    assert!(
        store
            .observe_inbox(A, snapshot(&fresh), 104)
            .unwrap()
            .baseline
    );
    let raw = String::from_utf8(store.file.read(A).unwrap().unwrap()).unwrap();
    assert!(!raw.contains(A) && !raw.contains(GUID) && !raw.contains("new-two"));
}
#[test]
fn notification_inbox_empty_baseline_missing_foreign_duplicate_reused_uid_clock_refuse() {
    let root = Scratch::new();
    let store = root.store();
    assert!(store.observe_inbox(A, snapshot(&[]), 100).unwrap().baseline);
    let first = identities(&[(1, "actual-one")]);
    assert_eq!(
        store
            .observe_inbox(A, snapshot(&first), 101)
            .unwrap()
            .messages
            .len(),
        1
    );
    let before = store.file.read(A).unwrap();
    for messages in [
        identities(&[(1, "reused")]),
        identities(&[(0, "zero")]),
        identities(&[(2, "")]),
        identities(&[(2, "duplicate"), (3, "duplicate")]),
        identities(&[(2, "two"), (2, "other")]),
        identities(&[(2, &"g".repeat(257))]),
        identities(&[(2, "non-graphic\n")]),
        (1..=1001)
            .map(|uid| InboxIdentity {
                uid,
                message_guid: format!("native-{uid}"),
            })
            .collect(),
    ] {
        assert_eq!(
            store.observe_inbox(A, snapshot(&messages), 102),
            Err(NotificationError::Invalid)
        );
        assert_eq!(store.file.read(A).unwrap(), before);
    }
    for mailbox_guid in [
        "g123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcde\n",
    ] {
        assert_eq!(
            store.observe_inbox(
                A,
                InboxSnapshot {
                    account: A,
                    mailbox_guid,
                    messages: &first
                },
                102
            ),
            Err(NotificationError::Invalid)
        );
        assert_eq!(store.file.read(A).unwrap(), before);
    }
    assert_eq!(
        store.observe_inbox(
            A,
            InboxSnapshot {
                account: B,
                mailbox_guid: GUID,
                messages: &first
            },
            102
        ),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.observe_inbox(
            A,
            InboxSnapshot {
                account: A,
                mailbox_guid: "",
                messages: &first
            },
            102
        ),
        Err(NotificationError::Invalid)
    );
    assert_eq!(
        store.observe_inbox(A, snapshot(&first), 100),
        Err(NotificationError::ClockRollback)
    );
    assert!(
        store
            .observe_inbox(
                B,
                InboxSnapshot {
                    account: B,
                    mailbox_guid: GUID,
                    messages: &first
                },
                102
            )
            .unwrap()
            .baseline
    );
}
#[test]
fn notification_observation_corrupt_foreign_record_is_not_reset() {
    let root = Scratch::new();
    let store = root.store();
    store.observe_inbox(A, snapshot(&[]), 100).unwrap();
    let bytes = store.file.read(A).unwrap().unwrap();
    {
        let lock = store.file.lock(B).unwrap();
        lock.write(&bytes).unwrap();
    }
    assert_eq!(
        store.observe_inbox(
            B,
            InboxSnapshot {
                account: B,
                mailbox_guid: GUID,
                messages: &[]
            },
            100
        ),
        Err(NotificationError::Corrupt)
    );
    let lock = store.file.lock(A).unwrap();
    lock.write(b"{broken").unwrap();
    drop(lock);
    assert_eq!(
        store.observe_inbox(A, snapshot(&[]), 100),
        Err(NotificationError::Corrupt)
    );
    assert_eq!(store.file.read(A).unwrap().unwrap(), b"{broken");
}
#[test]
fn notification_literal_mentions_require_canonical_address_boundaries() {
    for text in [
        "Hello alice@example.test",
        "<alice@example.test>",
        "alice@example.test.",
        "(alice@example.test), thank you",
    ] {
        assert!(mentions_account(text, A), "{text}");
    }
    for text in [
        "malice@example.test",
        "alice@example.test.evil",
        "alice@example.test-other",
        "alice+tag@example.test",
        "bob@example.test",
        "éAlice@example.test",
    ] {
        assert!(!mentions_account(text, A), "{text}");
    }
    assert!(!mentions_account(A, "alice"));
    assert!(!mentions_account(A, ""));
}
