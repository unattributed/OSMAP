// Included in journal_integration, using real Runtime and durable draft/journal stores.
fn corrupt_location(gateway: &RuntimeBrowserGateway, account: &str) {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"osmap-sent-location-v1\0");
    hash.update(account.as_bytes());
    let path = gateway
        .settings_dir
        .join(format!("{:x}.json", hash.finalize()));
    std::fs::write(path, b"corrupt location fixture").unwrap();
}
#[test]
fn runtime_sent_location_off_skips_corrupt_location_without_append_or_extra_readiness() {
    let f = Fixture::new();
    let g = &f.gateway;
    let session = validated_session();
    let account = &session.record.canonical_username;
    crate::sent_location::Store::new(&g.settings_dir)
        .save(
            account,
            0,
            "INBOX.CopyA",
            "1234567890abcdef1234567890abcdef",
        )
        .unwrap();
    corrupt_location(g, account);
    crate::sent_copy::Store::new(&g.settings_dir)
        .save(account, 0, false)
        .unwrap();
    let (_, draft) = f.save();
    let intent = crate::send_journal::intent_for_draft(
        account,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (submit, append) = probes(false, false);
    let result = g.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &SubmissionService::new(submit.clone()),
        &append,
    );
    assert_eq!(
        result.decision,
        BrowserSendDecision::SubmittedWithoutSentCopy {
            receipt_persisted: true
        }
    );
    assert_eq!(submit.calls.lock().unwrap().len(), 1);
    assert!(append.calls.lock().unwrap().is_empty());
}
#[test]
fn runtime_sent_location_known_unavailable_target_accepts_without_fallback_then_replays_captured_receipt(
) {
    let f = Fixture::new();
    let g = &f.gateway;
    let session = validated_session();
    let account = &session.record.canonical_username;
    let store = crate::sent_location::Store::new(&g.settings_dir);
    store
        .save(
            account,
            0,
            "INBOX.Missing",
            "1234567890abcdef1234567890abcdef",
        )
        .unwrap();
    let (_, draft) = f.save();
    let intent = crate::send_journal::intent_for_draft(
        account,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (submit, append) = probes(false, false);
    let service = SubmissionService::new(submit.clone());
    let result = g.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &service,
        &append,
    );
    let expected = BrowserSendDecision::SubmittedTo {
        mailbox_name: "INBOX.Missing".into(),
        copy_available: false,
        sent_copy_stored: false,
        receipt_persisted: true,
    };
    assert_eq!(result.decision, expected);
    assert_eq!(submit.calls.lock().unwrap().len(), 1);
    assert!(append.calls.lock().unwrap().is_empty());
    assert!(result
        .audit_events
        .iter()
        .any(|event| event.action == "sent_copy_destination_unavailable"));
    assert!(g
        .cleanup_submitted_draft_impl(
            account,
            &draft.draft_id,
            draft.revision.unwrap(),
            &intent,
            g.send_clock()
        )
        .is_err());
    store
        .save(account, 1, "Sent", "abcdef1234567890abcdef1234567890")
        .unwrap();
    corrupt_location(g, account);
    let replay = g.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &service,
        &append,
    );
    assert_eq!(replay.decision, expected);
    assert_eq!(g.send_receipt(&session, &intent).unwrap(), Some(expected));
    assert_eq!(submit.calls.lock().unwrap().len(), 1);
    assert!(append.calls.lock().unwrap().is_empty());
}
#[test]
fn runtime_sent_location_corrupt_fresh_choice_is_refused_before_smtp_and_never_defaults() {
    let f = Fixture::new();
    let g = &f.gateway;
    let session = validated_session();
    let account = &session.record.canonical_username;
    crate::sent_location::Store::new(&g.settings_dir)
        .save(
            account,
            0,
            "INBOX.CopyA",
            "1234567890abcdef1234567890abcdef",
        )
        .unwrap();
    corrupt_location(g, account);
    let (_, draft) = f.save();
    let intent = crate::send_journal::intent_for_draft(
        account,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (submit, append) = probes(false, false);
    let result = g.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &SubmissionService::new(submit.clone()),
        &append,
    );
    assert!(
        matches!(result.decision,BrowserSendDecision::Denied{ref public_reason,..} if public_reason=="sent_location_preference_unavailable")
    );
    assert!(submit.calls.lock().unwrap().is_empty());
    assert!(append.calls.lock().unwrap().is_empty());
    assert!(g.send_receipt(&session, &intent).unwrap().is_none());
}
