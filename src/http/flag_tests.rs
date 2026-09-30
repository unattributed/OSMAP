use super::*;

#[test]
fn runtime_flag_quota_lock_and_store_failure_refuse_before_the_backend() {
    let root = temp_dir("osmap-flag-quota");
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "fixture-quota",
        "127.0.0.1",
        "Fixture/Test",
    )
    .expect("context");
    let session = StubGateway::validated_session();
    let flag = crate::mailbox::MessageFlagRequest::new(
        "INBOX".into(),
        7,
        StubGateway::fixture_metadata(&session.record.canonical_username, "INBOX", 7).version,
        crate::message_metadata::MessageFlag::Seen,
        true,
    )
    .expect("flag");
    let path = root.join("cache").join("message-move-throttle");
    let store = FileLoginThrottleStore::new(path.clone());
    let key = crate::throttle::MessageMoveThrottleKey::for_canonical_user_and_remote_addr(
        &session.record.canonical_username,
        &context.remote_addr,
    );
    store
        .save(
            &key.key_id,
            &crate::throttle::LoginThrottleRecord {
                failure_count: 20,
                window_started_at: 100,
                last_failure_at: 120,
                locked_until: Some(10_000_000_000),
            },
        )
        .expect("fixture quota");
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let outcome = gateway.set_message_flag(&context, &session, &flag);
    assert!(
        matches!(outcome.result, Err(BrowserMessageFlagFailure::RateLimited { retry_after_seconds }) if retry_after_seconds > 0)
    );
    assert!(!outcome
        .audit_events
        .iter()
        .any(|event| event.action == "message_flag_result"));
    fs::remove_dir_all(&path).expect("remove owned fixture quota");
    fs::write(&path, b"synthetic unavailable store").expect("fixture store failure");
    let outcome = gateway.set_message_flag(&context, &session, &flag);
    assert!(matches!(
        outcome.result,
        Err(BrowserMessageFlagFailure::Unavailable)
    ));
    assert!(outcome
        .audit_events
        .iter()
        .any(|event| event.action == "message_flag_quota_unavailable"));
    assert!(!outcome
        .audit_events
        .iter()
        .any(|event| event.action == "message_flag_result"));
    fs::remove_dir_all(root).expect("remove owned fixture root");
}

fn post_flag(
    app: &BrowserApp<StubGateway>,
    changes: &[(&str, &str)],
    ua: &str,
) -> HandledHttpResponse {
    let session = StubGateway::validated_session();
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 7).version;
    let mut form = BTreeMap::from([
        ("csrf_token", session.record.csrf_token),
        ("mailbox", "INBOX".into()),
        ("uid", "7".into()),
        ("mailbox_guid", version.mailbox_guid),
        ("message_guid", version.message_guid),
        ("flag", "seen".into()),
        ("enabled", "1".into()),
        (
            "return_to",
            "/mailbox?name=INBOX&filter=unread&page=2".into(),
        ),
    ]);
    for (name, value) in changes {
        form.insert(*name, (*value).into());
    }
    let body = form
        .iter()
        .map(|(name, value)| format!("{}={}", url_encode(name), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let mut headers = authenticated_same_origin_headers().to_vec();
    headers.push(("Content-Type", "application/x-www-form-urlencoded"));
    let mut request = request("POST", "/message/flag", &headers, &body);
    request.headers.insert("user-agent".into(), ua.into());
    app.handle_request(&request, "127.0.0.1")
}

#[test]
fn flag_form_updates_only_target_state_and_preserves_context() {
    let app = app();
    let response = post_flag(&app, &[], "OSMAP/ManyMessages");
    assert_eq!(response.response.status_code, 303);
    assert!(response.response.headers.iter().any(
        |(key, value)| key == "Location" && value == "/mailbox?filter=unread&name=INBOX&page=2"
    ));
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 7),
        vec!["\\Flagged", "\\Seen"]
    );
    assert_eq!(
        post_flag(&app, &[], "OSMAP/ManyMessages")
            .response
            .status_code,
        303
    );
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 7),
        vec!["\\Flagged", "\\Seen"]
    );
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "Sent", 7),
        vec!["\\Flagged"]
    );
    assert_eq!(
        app.gateway
            .fixture_message_flags("bob@example.com", "INBOX", 7),
        vec!["\\Flagged"]
    );
}

#[test]
fn invalid_stale_and_unconfirmed_flag_requests_cannot_be_successes() {
    let app = app();
    for (name, value, status) in [
        ("csrf_token", "invalid", 403),
        ("flag", "deleted", 400),
        ("enabled", "2", 400),
        ("uid", "0", 400),
        ("return_to", "https://example.test/", 400),
        ("message_guid", "no-longer-current", 409),
        ("unexpected", "1", 400),
    ] {
        assert_eq!(
            post_flag(&app, &[(name, value)], "OSMAP/ManyMessages")
                .response
                .status_code,
            status,
            "{name}"
        );
    }
    let response = post_flag(&app, &[], "OSMAP/ManyMessages;FlagUnknown");
    assert_eq!(response.response.status_code, 503);
    assert!(body_text(&response).contains("may have completed"));
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 7),
        vec!["\\Flagged"]
    );
}

#[test]
fn verified_rows_offer_native_state_controls_and_legacy_rows_do_not() {
    let app = app();
    let mut request = request("GET", "/mailbox?name=INBOX", &authenticated_headers(), "");
    request
        .headers
        .insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let body = body_text(&app.handle_request(&request, "127.0.0.1"));
    assert_eq!(body.matches("action=\"/message/flag\"").count(), 100);
    assert!(body.contains("data-attachment-count=\"1\""));
    request
        .headers
        .insert("user-agent".into(), "OSMAP/LegacyFixture".into());
    let body = body_text(&app.handle_request(&request, "127.0.0.1"));
    assert!(!body.contains("action=\"/message/flag\""));
    assert!(body.contains("State controls unavailable"));
}
