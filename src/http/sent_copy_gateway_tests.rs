// Included in journal_integration to reuse its real Runtime/draft/probe seams.
#[test]
fn runtime_sent_copy_off_accepts_without_append_replays_and_cleans_only_exact_draft() {
    let fixture = Fixture::new();
    let gateway = &fixture.gateway;
    let session = validated_session();
    let account = &session.record.canonical_username;
    let preference = crate::sent_copy::Store::new(&gateway.settings_dir);
    preference.save(account, 0, false).unwrap();
    let (_, draft) = fixture.save();
    let (_, sentinel) = fixture.save();
    let intent = crate::send_journal::intent_for_draft(
        account,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (submission, append) = probes(false, false);
    let service = SubmissionService::new(submission.clone());
    let first = gateway.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &service,
        &append,
    );
    assert_eq!(
        first.decision,
        BrowserSendDecision::SubmittedWithoutSentCopy {
            receipt_persisted: true
        }
    );
    assert!(first
        .audit_events
        .iter()
        .any(|e| e.action == "sent_copy_not_requested"));
    assert_eq!(submission.calls.lock().unwrap().len(), 1);
    assert!(append.calls.lock().unwrap().is_empty());
    assert_eq!(
        submission.calls.lock().unwrap()[0].bcc_recipients,
        vec!["hidden@example.test"]
    );
    preference.save(account, 1, true).unwrap();
    let replay = gateway.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &service,
        &append,
    );
    assert_eq!(replay.decision, first.decision);
    assert_eq!(submission.calls.lock().unwrap().len(), 1);
    assert!(append.calls.lock().unwrap().is_empty());
    assert!(gateway
        .cleanup_submitted_draft_impl(
            account,
            &draft.draft_id,
            draft.revision.unwrap() + 1,
            &intent,
            gateway.send_clock()
        )
        .is_err());
    assert!(gateway
        .cleanup_submitted_draft_impl(
            account,
            &draft.draft_id,
            draft.revision.unwrap(),
            &intent,
            gateway.send_clock()
        )
        .unwrap());
    assert!(gateway
        .build_draft_store()
        .load(account, &draft.draft_id, gateway.send_clock())
        .unwrap()
        .is_none());
    assert_eq!(
        gateway
            .build_draft_store()
            .load(account, &sentinel.draft_id, gateway.send_clock())
            .unwrap()
            .unwrap(),
        sentinel
    );
}
#[test]
fn runtime_sent_copy_unavailable_fresh_refuses_before_reservation_but_recorded_replay_survives() {
    let fixture = Fixture::new();
    let gateway = &fixture.gateway;
    let session = validated_session();
    let account = &session.record.canonical_username;
    let preference = crate::sent_copy::Store::new(&gateway.settings_dir);
    preference.save(account, 0, false).unwrap();
    let (_, draft) = fixture.save();
    let (_, fresh) = fixture.save();
    let intent = crate::send_journal::intent_for_draft(
        account,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let fresh_intent = crate::send_journal::intent_for_draft(
        account,
        &fresh.draft_id,
        fresh.revision.unwrap(),
        fresh.updated_at,
    )
    .unwrap();
    let (submission, append) = probes(false, false);
    let service = SubmissionService::new(submission.clone());
    let first = gateway.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &service,
        &append,
    );
    assert_eq!(
        first.decision,
        BrowserSendDecision::SubmittedWithoutSentCopy {
            receipt_persisted: true
        }
    );
    let file = crate::private_account_file::PrivateAccountFile::new(
        gateway.settings_dir.clone(),
        "osmap-sent-copy-v1",
        512,
    );
    file.lock(account)
        .unwrap()
        .write(b"corrupt fixture")
        .unwrap();
    let refused = gateway.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&fresh_intent, &fresh),
        &service,
        &append,
    );
    assert!(
        matches!(refused.decision,BrowserSendDecision::Denied{public_reason,..} if public_reason=="sent_copy_preference_unavailable")
    );
    assert_eq!(
        gateway
            .send_journal()
            .receipt(account, &fresh_intent, gateway.send_clock())
            .unwrap(),
        None
    );
    let replay = gateway.send_message_with_backends(
        &test_context(),
        &session,
        send_request(&intent, &draft),
        &service,
        &append,
    );
    assert_eq!(replay.decision, first.decision);
    assert_eq!(submission.calls.lock().unwrap().len(), 1);
    assert!(append.calls.lock().unwrap().is_empty());
}
#[test]
fn runtime_sent_copy_choice_is_reserved_before_smtp_and_not_changed_by_concurrent_setting() {
    let fixture = Fixture::new();
    let gateway = fixture.gateway.clone();
    let session = validated_session();
    let account = &session.record.canonical_username;
    let preference = crate::sent_copy::Store::new(&gateway.settings_dir);
    preference.save(account, 0, false).unwrap();
    let (_, draft) = fixture.save();
    let intent = crate::send_journal::intent_for_draft(
        account,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (mut submission, append) = probes(false, false);
    let (started, ready) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    submission.started = Some(started);
    submission.block = Some(Arc::new(Mutex::new(wait)));
    let observed_submission = submission.clone();
    let observed_append = append.clone();
    let worker = std::thread::spawn(move || {
        gateway.send_message_with_backends(
            &test_context(),
            &session,
            send_request(&intent, &draft),
            &SubmissionService::new(submission),
            &append,
        )
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    preference
        .save(&validated_session().record.canonical_username, 1, true)
        .unwrap();
    release.send(()).unwrap();
    assert_eq!(
        worker.join().unwrap().decision,
        BrowserSendDecision::SubmittedWithoutSentCopy {
            receipt_persisted: true
        }
    );
    assert_eq!(observed_submission.calls.lock().unwrap().len(), 1);
    assert!(observed_append.calls.lock().unwrap().is_empty());
}
