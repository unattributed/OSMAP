#[cfg(unix)]
#[test]
fn sender_identity_runtime_captures_original_draft_and_revalidates_before_preparation() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = std::path::Path::new("/tmp").join(format!(
        "osmap-sender-runtime-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("authority.json");
    fs::write(&path, br#"{"version":1,"accounts":[{"account":"alice@example.com","revision":1,"identities":[{"id":"desk","address":"desk@example.test"}]}]}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let provider = crate::sender_authority::Provider::new(
        Some(path.clone()),
        fs::metadata(&path).unwrap().uid(),
    );
    let gateway = RuntimeBrowserGateway::for_test(&root).with_fixture_sender_authority(provider);
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "sender-runtime",
        "127.0.0.1",
        "Synthetic/Test",
    )
    .unwrap();
    let update = crate::identity_preferences::SenderIdentityUpdate {
        identity_id: "desk".into(),
        action: crate::identity_preferences::IdentityAction::Primary,
        presentation: crate::identity_preferences::IdentityPreferences::default(),
        use_for_new: true,
    };
    let new_intent = crate::send_journal::mint_intent(gateway.send_clock()).unwrap();
    let input = BrowserDraftSaveRequest {
        sender_id: None,
        send_intent: &new_intent,
        draft_id: None,
        expected_revision: None,
        recipients: "receiver@example.test",
        cc_recipients: "",
        bcc_recipients: "",
        subject: "Public identity fixture",
        body: "Public unchanged fixture",
        body_format: crate::compose_format::BodyFormat::Plain,
        attachments: &[],
        removed_attachment_indices: &[],
        source_attachments: None,
        reply_thread: None,
        protection: crate::send::ProtectionIntent::default(),
    };
    let canonical = gateway.save_draft(&context, &session, input);
    let BrowserDraftSaveDecision::Saved {
        draft_id: canonical_id,
    } = canonical.decision
    else {
        panic!("canonical draft");
    };
    gateway
        .update_sender_identity(&session, 0, &update)
        .unwrap();
    let alias_intent = crate::send_journal::mint_intent(gateway.send_clock()).unwrap();
    let alias = gateway.save_draft(
        &context,
        &session,
        BrowserDraftSaveRequest {
            sender_id: None,
            send_intent: &alias_intent,
            ..input
        },
    );
    let BrowserDraftSaveDecision::Saved { draft_id: alias_id } = alias.decision else {
        panic!("alias draft");
    };
    let BrowserDraftLoadDecision::Loaded {
        draft: captured, ..
    } = gateway.load_draft(&context, &session, &alias_id).decision
    else {
        panic!("alias capture");
    };
    assert_eq!(
        captured.request.sender_identity.sender().unwrap().address(),
        "desk@example.test"
    );
    let reset = crate::identity_preferences::SenderIdentityUpdate {
        identity_id: crate::sender_authority::CANONICAL_ID.into(),
        ..update
    };
    gateway.update_sender_identity(&session, 1, &reset).unwrap();
    assert!(gateway
        .load_identity_preferences(&context, &session)
        .unwrap()
        .preferences
        .sender()
        .is_none());
    let per_message_intent = crate::send_journal::mint_intent(gateway.send_clock()).unwrap();
    let selected_once = gateway.save_draft(
        &context,
        &session,
        BrowserDraftSaveRequest {
            sender_id: Some("desk"),
            send_intent: &per_message_intent,
            ..input
        },
    );
    let BrowserDraftSaveDecision::Saved { draft_id: once_id } = selected_once.decision else {
        panic!("actual Runtime per-message choice")
    };
    let BrowserDraftLoadDecision::Loaded { draft: once, .. } =
        gateway.load_draft(&context, &session, &once_id).decision
    else {
        panic!("actual Runtime captured choice")
    };
    assert_eq!(once.request.sender_identity.sender().unwrap().id(), "desk");
    assert!(gateway
        .load_identity_preferences(&context, &session)
        .unwrap()
        .preferences
        .sender()
        .is_none());
    let reopened = RuntimeBrowserGateway::for_test(&root);
    let BrowserDraftLoadDecision::Loaded { draft: after, .. } =
        reopened.load_draft(&context, &session, &alias_id).decision
    else {
        panic!("captured alias reopens without latest authority substitution");
    };
    assert!(after == captured);
    let BrowserDraftLoadDecision::Loaded {
        draft: canonical, ..
    } = reopened
        .load_draft(&context, &session, &canonical_id)
        .decision
    else {
        panic!("canonical draft retained");
    };
    assert!(canonical.request.sender_identity.sender().is_none());
    let mut request = crate::send::ComposeRequest::new(
        crate::send::ComposePolicy::default(),
        "receiver@example.test",
        "Public fixture",
        "Public unchanged fixture",
    )
    .unwrap();
    request.sender_identity = captured.request.sender_identity.clone();
    let prepared = gateway
        .test_prepare_outbound_request("alice@example.com", &request, gateway.send_clock())
        .unwrap()
        .0;
    assert!(std::str::from_utf8(prepared.as_bytes())
        .unwrap()
        .starts_with("From: desk@example.test\r\n"));
    fs::write(&path, br#"{"version":1,"accounts":[{"account":"alice@example.com","revision":2,"identities":[]}]}"#).unwrap();
    assert!(gateway
        .test_prepare_outbound_request("alice@example.com", &request, gateway.send_clock())
        .is_err());
    assert!(gateway
        .test_prepare_outbound_request("bob@example.com", &request, gateway.send_clock())
        .is_err());
    let mut canonical_request = request.clone();
    canonical_request.sender_identity = crate::identity_preferences::IdentityPreferences::default();
    fs::write(&path, b"corrupt").unwrap();
    assert!(gateway
        .test_prepare_outbound_request(
            "alice@example.com",
            &canonical_request,
            gateway.send_clock()
        )
        .is_ok());
    assert!(
        gateway.load_draft(&context, &session, &alias_id).decision
            == BrowserDraftLoadDecision::Loaded {
                canonical_username: session.record.canonical_username.clone(),
                draft: captured
            }
    );
    fs::remove_dir_all(root).unwrap();
}
