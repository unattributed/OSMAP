use super::*;

fn post(app: &BrowserApp<StubGateway>, body: &str, bulk: bool, ua: &str) -> HandledHttpResponse {
    let mut request = request(
        "POST",
        if bulk {
            "/messages/move"
        } else {
            "/message/move"
        },
        &authenticated_same_origin_headers(),
        body,
    );
    request.headers.insert("user-agent".into(), ua.into());
    app.handle_request(&request, "127.0.0.1")
}
fn form(uid: u64, action: &str) -> String {
    move_form(
        &format!(
            "csrf_token={}&mailbox=INBOX&uid={uid}&destination_mailbox=Trash",
            StubGateway::validated_session().record.csrf_token
        ),
        action,
    )
}
fn changed(body: &str, key: &str, value: Option<&str>) -> String {
    let mut fields = parse_urlencoded_form(body.as_bytes(), 20, 16384).unwrap();
    if let Some(value) = value {
        fields.insert(key.into(), value.into());
    } else {
        fields.remove(key);
    }
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[test]
fn reversible_move_replay_and_account_identity_are_bound_to_current_storage() {
    let app = app();
    let original = app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .unwrap();
    let body=changed(&form(9,"bin"),"return_to",Some("/mailbox?name=INBOX&sort=subject&dir=asc&filter=all&page=2&selected_mailbox=INBOX&selected_uid=9&select=move"));
    let response = post(&app, &body, false, "OSMAP/ManyMessages");
    assert_eq!(response.response.status_code, 303);
    assert!(response
        .response
        .headers
        .iter()
        .any(|(name, value)| name == "Location"
            && value == "/mailbox?dir=asc&filter=all&name=INBOX&page=2&sort=subject"));
    assert_eq!(
        post(&app, &body, false, "OSMAP/ManyMessages")
            .response
            .status_code,
        409
    );
    assert!(app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .is_none());
    assert!(app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 10)
        .is_some());
    assert!(app
        .gateway
        .fixture_current_metadata("bob@example.com", "INBOX", 9)
        .is_some());
    let moved = app
        .gateway
        .fixture_reconcile_messages("alice@example.com", "Trash", Vec::new());
    assert_eq!(moved.len(), 1);
    assert_eq!(
        moved[0].metadata.as_ref().unwrap().version.message_guid,
        original.version.message_guid
    );
    let restore = form(moved[0].uid, "restore");
    let restore = changed(&restore, "mailbox", Some("Trash"));
    let restore = changed(
        &restore,
        "mailbox_guid",
        Some(&moved[0].metadata.as_ref().unwrap().version.mailbox_guid),
    );
    let restore = changed(
        &restore,
        "message_guid",
        Some(&original.version.message_guid),
    );
    assert_eq!(
        post(&app, &restore, false, "OSMAP/ManyMessages")
            .response
            .status_code,
        303
    );
    let restored = app
        .gateway
        .fixture_reconcile_messages("alice@example.com", "INBOX", Vec::new());
    assert_eq!(restored.len(), 1);
    assert_ne!(restored[0].uid, 9);
    assert_eq!(
        restored[0].metadata.as_ref().unwrap().version.message_guid,
        original.version.message_guid
    );
    assert_eq!(
        post(&app, &body, false, "OSMAP/ManyMessages")
            .response
            .status_code,
        409
    );
}

#[test]
fn malformed_legacy_cross_account_and_unsupported_move_forms_never_write() {
    let app = app();
    let valid = form(9, "bin");
    let other = StubGateway::fixture_metadata("bob@example.com", "INBOX", 9).version;
    for (key, value, status) in [
        ("csrf_token", Some("invalid"), 403),
        ("uid", Some("0"), 400),
        ("uid", Some("4294967296"), 400),
        ("uid", Some("09"), 400),
        ("mailbox_guid", None, 400),
        ("message_guid", None, 400),
        ("message_guid", Some("stale"), 409),
        ("mailbox_guid", Some(other.mailbox_guid.as_str()), 409),
        ("action", Some("expunge"), 400),
        ("action", Some("restore"), 400),
        ("return_to", Some("https://example.test/"), 400),
        ("unexpected", Some("1"), 400),
    ] {
        let response = post(
            &app,
            &changed(&valid, key, value),
            false,
            "OSMAP/ManyMessages",
        );
        assert_eq!(response.response.status_code, status, "{key}");
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_message_move"));
        assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    }
    assert_eq!(
        post(&app, &format!("{valid}&uid=9"), false, "OSMAP/ManyMessages")
            .response
            .status_code,
        400
    );
    assert!(app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .is_some());
    let request=request("POST","/message/move",&authenticated_same_origin_headers(),"csrf_token=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210&mailbox=INBOX&uid=9&destination_mailbox=Trash");
    assert_eq!(
        app.handle_request(&request, "127.0.0.1")
            .response
            .status_code,
        400
    );
}

#[test]
fn bulk_unknown_stops_without_retry_and_preserves_unattempted_messages() {
    let app = app();
    let body = move_form(
        &format!(
            "csrf_token={}&mailbox=INBOX&uid_9=9&uid_10=10&uid_11=11",
            StubGateway::validated_session().record.csrf_token
        ),
        "bin",
    );
    let response = post(&app, &body, true, "OSMAP/ManyMessages;MoveUnknown");
    assert_eq!(response.response.status_code, 503);
    let text = body_text(&response);
    assert!(
        text.contains("1 confirmed moved; 1 uncertain; 1 remaining messages were not attempted.")
    );
    assert!(text.contains("may have completed"));
    assert!(text.contains("Refresh message list"));
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|event| event.action == "stub_message_move")
            .count(),
        1
    );
    assert!(app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .is_none());
    for uid in [10, 11] {
        assert!(app
            .gateway
            .fixture_current_metadata("alice@example.com", "INBOX", uid)
            .is_some());
    }
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
}

#[test]
fn bulk_identity_key_limit_and_legacy_metadata_controls_are_enforced() {
    let app = app();
    let body = move_form(
        &format!(
            "csrf_token={}&mailbox=INBOX&uid_9=9",
            StubGateway::validated_session().record.csrf_token
        ),
        "bin",
    );
    let malformed = body.replace("message_9=", "message_10=");
    assert_eq!(
        post(&app, &malformed, true, "OSMAP/ManyMessages")
            .response
            .status_code,
        400
    );
    let mut old = String::from("csrf_token=");
    old.push_str(&StubGateway::validated_session().record.csrf_token);
    old.push_str("&mailbox=INBOX");
    for uid in 1..=11 {
        old.push_str(&format!("&uid_{uid}={uid}"));
    }
    assert_eq!(
        post(&app, &move_form(&old, "bin"), true, "OSMAP/ManyMessages")
            .response
            .status_code,
        400
    );
    let mut request = request(
        "GET",
        "/message?mailbox=INBOX&uid=9",
        &authenticated_headers(),
        "",
    );
    request
        .headers
        .insert("user-agent".into(), "OSMAP/LegacyMetadata".into());
    let text = body_text(&app.handle_request(&request, "127.0.0.1"));
    assert!(text.contains("Move actions unavailable"));
    assert!(!text.contains("action=\"/message/move\""));
}

#[test]
fn runtime_move_quota_storage_failure_refuses_before_any_mail_backend() {
    let root = temp_dir("osmap-move-quota-failure");
    fs::create_dir_all(root.join("cache")).unwrap();
    fs::write(
        root.join("cache/message-move-throttle"),
        b"unavailable fixture",
    )
    .unwrap();
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "move-quota",
        "127.0.0.1",
        "Fixture/Test",
    )
    .unwrap();
    let request = MessageMoveRequest::new(
        MessageMovePolicy::default(),
        "INBOX",
        "Trash",
        9,
        StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version,
    )
    .unwrap();
    let outcome = gateway.move_message(&context, &session, &request);
    assert!(
        matches!(outcome.decision,BrowserMessageMoveDecision::Denied{ref public_reason,..} if public_reason=="message_move_unavailable")
    );
    assert!(outcome
        .audit_events
        .iter()
        .any(|event| event.action == "message_move_quota_unavailable"));
    assert!(!outcome
        .audit_events
        .iter()
        .any(|event| event.action == "message_move_result"));
    fs::remove_dir_all(root).unwrap();
}
