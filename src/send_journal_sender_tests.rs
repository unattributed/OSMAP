#[test]
fn sender_identity_journal_capture_refuses_changed_id_and_replays_without_retargeting() {
    let root = Scratch::new();
    let mut selected = request();
    selected.sender_identity = crate::identity_preferences::IdentityPreferences::default()
        .with_sender("desk", "desk@example.test")
        .unwrap();
    let digest = snapshot_digest(ACCOUNT, &selected);
    assert_ne!(digest, snapshot_digest(ACCOUNT, &request()));
    let mut changed = selected.clone();
    changed.sender_identity = crate::identity_preferences::IdentityPreferences::default()
        .with_sender("other", "desk@example.test")
        .unwrap();
    assert_ne!(digest, snapshot_digest(ACCOUNT, &changed));
    let token = intent(100, 1);
    root.store()
        .execute(ACCOUNT, &token, 100, &selected, || {
            AttemptOutcome::Unconfirmed
        })
        .unwrap();
    let before = record_bytes(&root.store());
    assert_eq!(
        root.store()
            .execute(ACCOUNT, &token, 101, &changed, || panic!(
                "must not dispatch"
            )),
        Err(JournalError::ChangedSnapshot)
    );
    let replay = root
        .store()
        .execute_prepared(
            ACCOUNT,
            &token,
            101,
            |_| Ok::<_, ()>(selected.clone()),
            |_| panic!("must not dispatch"),
        )
        .unwrap();
    assert_eq!(
        replay,
        PreparedResult::Outcome(JournalResult {
            outcome: AttemptOutcome::Unconfirmed,
            replayed: true,
            receipt_persisted: true
        })
    );
    assert_eq!(record_bytes(&root.store()), before);
}
