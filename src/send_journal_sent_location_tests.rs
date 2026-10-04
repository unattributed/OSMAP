#[test]
fn sent_location_journal_reserves_selected_identity_before_dispatch_and_replays_without_retarget() {
    let root = Scratch::new();
    let store = root.store();
    let token = intent(100, 201);
    let request = request();
    let location = crate::sent_location::CapturedLocation::Selected {
        mailbox_name: "INBOX.CopyA".into(),
        mailbox_guid: "1234567890abcdef1234567890abcdef".into(),
    };
    let capture = crate::sent_location::SentCopyCapture {
        requested: true,
        location: Some(location.clone()),
    };
    let first = store
        .execute_prepared_with_sent_location(
            ACCOUNT,
            &token,
            100,
            |old| {
                assert!(old.is_none());
                Ok::<_, ()>((request.clone(), capture.clone()))
            },
            |_, chosen| {
                assert_eq!(chosen, &capture);
                let bytes = record_bytes(&store);
                let disk: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(disk["attempts"][0]["state"], "reserved");
                assert_eq!(
                    disk["attempts"][0]["sent_location"]["mailbox_name"],
                    "INBOX.CopyA"
                );
                ACCEPTED
            },
        )
        .unwrap();
    assert!(matches!(
        first,
        LocatedPreparedResult::Outcome(LocatedResult {
            result: JournalResult {
                replayed: false,
                receipt_persisted: true,
                ..
            },
            ..
        })
    ));
    let replay = root
        .store()
        .execute_prepared_with_sent_location(
            ACCOUNT,
            &token,
            101,
            |old| {
                assert_eq!(old, Some(capture.clone()));
                Ok::<_, ()>((request.clone(), old.unwrap()))
            },
            |_, _| panic!("recorded intent cannot dispatch"),
        )
        .unwrap();
    assert!(
        matches!(replay,LocatedPreparedResult::Outcome(LocatedResult{result:JournalResult{replayed:true,..},location:Some(ref value)}) if value==&location)
    );
    assert_eq!(
        root.store()
            .receipt_with_sent_location(ACCOUNT, &token)
            .unwrap()
            .unwrap()
            .location,
        Some(location)
    );
    assert!(root
        .store()
        .receipt_with_sent_location("bob@example.test", &token)
        .unwrap()
        .is_none());
}
#[test]
fn sent_location_journal_legacy_and_off_bytes_stay_absent_and_choices_are_captured() {
    for requested in [true, false] {
        let a = Scratch::new();
        let b = Scratch::new();
        let token = intent(100, 202);
        let outcome = if requested {
            ACCEPTED
        } else {
            AttemptOutcome::AcceptedWithoutSentCopy
        };
        a.store()
            .execute_prepared_with_sent_copy(
                ACCOUNT,
                &token,
                100,
                |_| Ok::<_, ()>((request(), requested)),
                |_, _| outcome,
            )
            .unwrap();
        b.store()
            .execute_prepared_with_sent_location(
                ACCOUNT,
                &token,
                100,
                |_| {
                    Ok::<_, ()>((
                        request(),
                        crate::sent_location::SentCopyCapture::legacy(requested),
                    ))
                },
                |_, _| outcome,
            )
            .unwrap();
        assert_eq!(record_bytes(&a.store()), record_bytes(&b.store()));
        assert!(!String::from_utf8(record_bytes(&b.store()))
            .unwrap()
            .contains("sent_location"));
        b.store()
            .execute_prepared_with_sent_location(
                ACCOUNT,
                &token,
                101,
                |old| {
                    assert_eq!(
                        old,
                        Some(crate::sent_location::SentCopyCapture::legacy(requested))
                    );
                    Ok::<_, ()>((request(), old.unwrap()))
                },
                |_, _| panic!("legacy replay cannot load current target or dispatch"),
            )
            .unwrap();
    }
}
#[test]
fn sent_location_journal_unavailable_is_accepted_unconfirmed_and_never_claims_stored_or_cleans_draft(
) {
    let root = Scratch::new();
    let store = root.store();
    let token = intent(100, 203);
    let location = crate::sent_location::CapturedLocation::Unavailable {
        mailbox_name: "INBOX.Missing".into(),
        mailbox_guid: "1234567890abcdef1234567890abcdef".into(),
    };
    store
        .execute_prepared_with_sent_location(
            ACCOUNT,
            &token,
            100,
            |_| {
                Ok::<_, ()>((
                    request(),
                    crate::sent_location::SentCopyCapture {
                        requested: true,
                        location: Some(location.clone()),
                    },
                ))
            },
            |_, _| AttemptOutcome::Accepted {
                sent_copy_stored: false,
            },
        )
        .unwrap();
    assert!(
        matches!(store.receipt_with_sent_location(ACCOUNT,&token).unwrap(),Some(LocatedResult{result:JournalResult{outcome:AttemptOutcome::Accepted{sent_copy_stored:false},..},location:Some(ref value)}) if value==&location)
    );
    assert_eq!(
        store
            .account_guard(ACCOUNT, 101)
            .unwrap()
            .require_accepted_for_cleanup(&token),
        Err(JournalError::ConfirmationRequired)
    );
    let mut disk: serde_json::Value = serde_json::from_slice(&record_bytes(&store)).unwrap();
    for state in ["accepted_stored", "accepted_without_sent_copy"] {
        disk["attempts"][0]["state"] = state.into();
        fixture(&store, &serde_json::to_vec(&disk).unwrap());
        assert_eq!(
            store.receipt_with_sent_location(ACCOUNT, &token),
            Err(JournalError::InvalidRecord)
        );
    }
}
#[test]
fn sent_location_journal_invalid_capture_refuses_before_reservation_and_terminal_fault_keeps_no_retry(
) {
    let root = Scratch::new();
    let token = intent(100, 204);
    let location = crate::sent_location::CapturedLocation::Selected {
        mailbox_name: "INBOX.CopyA".into(),
        mailbox_guid: "1234567890abcdef1234567890abcdef".into(),
    };
    let result = root.store().execute_prepared_with_sent_location(
        ACCOUNT,
        &token,
        100,
        |_| {
            Ok::<_, ()>((
                request(),
                crate::sent_location::SentCopyCapture {
                    requested: false,
                    location: Some(location.clone()),
                },
            ))
        },
        |_, _| panic!("invalid capture cannot dispatch"),
    );
    assert_eq!(result, Err(JournalError::InvalidRecord));
    assert!(record_bytes_optional(&root.store()).is_none());
    let mut store = root.store();
    store.fault = Some((true, false));
    let result = store
        .execute_prepared_with_sent_location(
            ACCOUNT,
            &token,
            100,
            |_| {
                Ok::<_, ()>((
                    request(),
                    crate::sent_location::SentCopyCapture {
                        requested: true,
                        location: Some(location.clone()),
                    },
                ))
            },
            |_, _| ACCEPTED,
        )
        .unwrap();
    assert!(matches!(
        result,
        LocatedPreparedResult::Outcome(LocatedResult {
            result: JournalResult {
                receipt_persisted: false,
                ..
            },
            ..
        })
    ));
    root.store()
        .execute_prepared_with_sent_location(
            ACCOUNT,
            &token,
            101,
            |old| Ok::<_, ()>((request(), old.unwrap())),
            |_, _| panic!("durable reservation never redispatches"),
        )
        .unwrap();
}
fn record_bytes_optional(store: &SendJournal) -> Option<Vec<u8>> {
    store.file.read(ACCOUNT).unwrap()
}
