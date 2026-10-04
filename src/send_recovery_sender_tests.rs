#[test]
fn sender_identity_retained_recovery_reconstructs_exact_sender_and_never_uses_new_default() {
    let f = Fixture::new();
    let token = crate::send_journal::mint_intent(100).unwrap();
    let mut selected = request();
    selected.sender_identity =
        crate::identity_preferences::IdentityPreferences::new("Desk", Some("reply@example.test"))
            .unwrap()
            .with_sender("desk", "desk@example.test")
            .unwrap();
    let calls = std::cell::Cell::new(0);
    dispatch(&f, &token, &selected, None, &calls);
    let reopened = SendRecovery::new(f.root.join("recovery"));
    let RecoveryRead::Available(snapshot) =
        reopened.lookup(&f.journal, ACCOUNT, &token, 101).unwrap()
    else {
        panic!("captured sender must remain available")
    };
    assert_eq!(*snapshot.request, selected);
    assert_eq!(
        snapshot.request.sender_identity.sender().unwrap().address(),
        "desk@example.test"
    );
    dispatch(&f, &token, &selected, None, &calls);
    assert_eq!(calls.get(), 1);
    let mut changed = selected.clone();
    changed.sender_identity = crate::identity_preferences::IdentityPreferences::default();
    assert_eq!(
        f.recovery
            .capture(&f.journal, &f.normal, ACCOUNT, &token, &changed, 101),
        Err(RecoveryError::Changed)
    );
    assert!(matches!(
        reopened
            .lookup(&f.journal, "other@example.test", &token, 101)
            .unwrap(),
        RecoveryRead::Missing
    ));
}
