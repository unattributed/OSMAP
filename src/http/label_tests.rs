use super::*;
fn fixture() -> (BrowserApp<StubGateway>, PathBuf, crate::labels::LabelStore) {
    let p = temp_dir(&format!(
        "labels-http-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let store = crate::labels::LabelStore::new(p.join("labels"));
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            labels_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    (app, p, store)
}
fn call(app: &BrowserApp<StubGateway>, body: &str) -> HandledHttpResponse {
    app.handle_request(
        &request(
            "POST",
            "/labels/change",
            &authenticated_same_origin_headers(),
            &format!(
                "csrf_token={}&{body}",
                StubGateway::validated_session().record.csrf_token
            ),
        ),
        "127.0.0.1",
    )
}
fn reference(app: &BrowserApp<StubGateway>) -> String {
    let m = app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .unwrap();
    format!(
        "mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}",
        url_encode(&m.version.mailbox_guid),
        url_encode(&m.version.message_guid)
    )
}
#[test]
fn native_labels_persist_validate_csrf_cas_identity_and_delete_confirmation() {
    let (app, p, s) = fixture();
    let account = "alice@example.com";
    assert_eq!(
        call(&app, "revision=0&action=create&name=Review")
            .response
            .status_code,
        200
    );
    let r = s.load(account).unwrap();
    let id = r.labels()[0].id();
    let context = reference(&app);
    assert_eq!(
        call(
            &app,
            &format!("revision=1&action=attach&label_id={id}&{context}")
        )
        .response
        .status_code,
        200
    );
    assert_eq!(s.load(account).unwrap().assigned_messages(), 1);
    let saved = s.load(account).unwrap();
    for (form, status) in [
        (
            format!("revision=1&action=rename&label_id={id}&name=Keep+my+text"),
            409,
        ),
        (format!("revision=2&action=delete&label_id={id}"), 400),
        (
            format!(
                "revision=2&action=detach&label_id={id}&{}",
                context.replace("uid=9", "uid=10")
            ),
            409,
        ),
    ] {
        let result = call(&app, &form);
        assert_eq!(result.response.status_code, status);
        assert_eq!(s.load(account).unwrap(), saved);
        if form.contains("action=detach") {
            let body = body_text(&result);
            assert!(body.contains("Assignment status unavailable"));
            assert!(body.contains("Assignment unknown"));
            assert!(!body.contains("0 of 8 labels assigned"));
            assert!(!body.contains("Not assigned"));
            assert!(body.contains("<fieldset disabled>"));
        }
    }
    let req = request(
        "POST",
        "/labels/change",
        &authenticated_same_origin_headers(),
        "csrf_token=wrong&revision=2&action=create&name=Denied",
    );
    assert_eq!(
        app.handle_request(&req, "127.0.0.1").response.status_code,
        403
    );
    assert_eq!(s.load(account).unwrap(), saved);
    let headers = authenticated_same_origin_headers();
    let mut req = request(
        "POST",
        "/labels/change",
        &headers,
        &format!(
            "csrf_token={}&revision=2&action=create&name=Denied",
            StubGateway::validated_session().record.csrf_token
        ),
    );
    req.headers
        .insert("origin".into(), "https://foreign.test".into());
    assert_eq!(
        app.handle_request(&req, "127.0.0.1").response.status_code,
        403
    );
    assert!(s.load("bob@example.com").unwrap().labels().is_empty());
    assert_eq!(
        call(
            &app,
            &format!("revision=2&action=delete&label_id={id}&confirm=delete")
        )
        .response
        .status_code,
        200
    );
    assert_eq!(s.load(account).unwrap().assigned_messages(), 0);
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn labels_move_confirmation_reconciles_and_old_uid_cannot_attach() {
    let (app, p, s) = fixture();
    call(&app, "revision=0&action=create&name=Move");
    let r = s.load("alice@example.com").unwrap();
    let id = r.labels()[0].id();
    let context = reference(&app);
    call(
        &app,
        &format!("revision=1&action=attach&label_id={id}&{context}"),
    );
    let body = format!(
        "csrf_token={}&{context}&action=bin&return_to=%2Fmailbox%3Fname%3DINBOX",
        StubGateway::validated_session().record.csrf_token
    );
    let result = app.handle_request(
        &request(
            "POST",
            "/message/move",
            &authenticated_same_origin_headers(),
            &body,
        ),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 303, "{}", body_text(&result));
    let moved = app
        .gateway
        .fixture_reconcile_messages("alice@example.com", "Trash", vec![]);
    assert_eq!(moved.len(), 1);
    let identity = crate::labels::MessageIdentity::from_summary(
        "alice@example.com",
        "alice@example.com",
        "Trash",
        &moved[0],
    )
    .unwrap();
    assert_eq!(
        s.load("alice@example.com")
            .unwrap()
            .labels_for(&identity)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        call(
            &app,
            &format!("revision=3&action=attach&label_id={id}&{context}")
        )
        .response
        .status_code,
        409
    );
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn labels_wrong_owner_and_storage_failure_never_turn_move_into_retry() {
    let (app, p, s) = fixture();
    call(&app, "revision=0&action=create&name=Retain");
    let context = reference(&app);
    let get = format!("/labels?{context}");
    let mut req = request("GET", &get, &authenticated_headers(), "");
    req.headers
        .insert("user-agent".into(), "WelcomeData/wrong-owner".into());
    assert_eq!(
        app.handle_request(&req, "127.0.0.1").response.status_code,
        400
    );
    let body = format!(
        "csrf_token={}&{context}&action=bin&return_to=%2Fmailbox%3Fname%3DINBOX",
        StubGateway::validated_session().record.csrf_token
    );
    let mut req = request(
        "POST",
        "/message/move",
        &authenticated_same_origin_headers(),
        &body,
    );
    req.headers
        .insert("user-agent".into(), "WelcomeWrongAccount".into());
    assert_eq!(
        app.handle_request(&req, "127.0.0.1").response.status_code,
        400
    );
    assert!(app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .is_some());
    let file = fs::read_dir(p.join("labels"))
        .unwrap()
        .map(|v| v.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    fs::write(&file, b"corrupt retained record").unwrap();
    let result = app.handle_request(
        &request(
            "POST",
            "/message/move",
            &authenticated_same_origin_headers(),
            &body,
        ),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 200);
    assert!(
        body_text(&result).contains("mail moves were confirmed")
            && body_text(&result).contains("Label continuity could not be confirmed")
    );
    assert!(app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", 9)
        .is_none());
    assert_eq!(fs::read(&file).unwrap(), b"corrupt retained record");
    assert_eq!(
        s.load("alice@example.com"),
        Err(crate::labels::LabelError::Corrupt)
    );
    fs::remove_dir_all(p).unwrap();
}

fn badge_get(app: &BrowserApp<StubGateway>, path: &str, agent: &str, bob: bool) -> HandledHttpResponse {
    let mut r = request("GET", path, &authenticated_same_origin_headers(), "");
    r.headers.insert("user-agent".into(), agent.into());
    if bob {
        r.headers.insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
    }
    app.handle_request(&r, "127.0.0.1")
}

#[test]
fn assigned_label_badges_owned_list_reader_and_reload_escape_names_without_writes() {
    let (app, root, store) = fixture();
    let account = "alice@example.com";
    let name = "Review <img src=x> & \"quoted\"";
    assert_eq!(call(&app, &format!("revision=0&action=create&name={}", url_encode(name))).response.status_code, 200);
    let id = store.load(account).unwrap().labels()[0].id().to_owned();
    assert_eq!(call(&app, &format!("revision=1&action=attach&label_id={id}&{}", reference(&app))).response.status_code, 200);
    let saved = store.load(account).unwrap();
    let version = app.gateway.fixture_current_metadata(account, "INBOX", 9).unwrap().version;
    let standalone = format!("/message?mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}", url_encode(&version.mailbox_guid), url_encode(&version.message_guid));
    let coordinated = format!("/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9&selected_mailbox_guid={}&selected_message_guid={}", url_encode(&version.mailbox_guid), url_encode(&version.message_guid));
    // A new request and a new application reading the same durable store both
    // project the current assignment, rather than cached form state.
    let reload = BrowserApp::new(HttpPolicy::default(), StubGateway { labels_store: Some(store.clone()), ..StubGateway::default() });
    for current in [&app, &reload] {
        for (path, count) in [("/mailbox?name=INBOX", 1), (standalone.as_str(), 1), (coordinated.as_str(), 2)] {
            let response = badge_get(current, path, "", false);
            assert_eq!(response.response.status_code, 200, "{path}");
            let html = body_text(&response);
            assert_eq!(html.matches(&format!("class=\"badge message-label\" data-label-id=\"{id}\"")).count(), count, "{path}");
            assert!(html.contains("Review &lt;img src=x&gt; &amp; &quot;quoted&quot;"));
            assert!(!html.contains(name));
            assert!(!html.contains("<img src=x>"));
        }
        assert!(current.gateway.submitted.lock().unwrap().is_empty());
        assert_eq!(current.gateway.fixture_current_metadata(account, "INBOX", 9).unwrap().version, version);
    }
    assert_eq!(store.load(account).unwrap(), saved);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn assigned_label_badges_do_not_transfer_to_foreign_or_reused_message_identity() {
    let (app, root, store) = fixture();
    assert_eq!(call(&app, "revision=0&action=create&name=PrivateOwned").response.status_code, 200);
    let id = store.load("alice@example.com").unwrap().labels()[0].id().to_owned();
    assert_eq!(call(&app, &format!("revision=1&action=attach&label_id={id}&{}", reference(&app))).response.status_code, 200);
    let saved = store.load("alice@example.com").unwrap();
    let mut metadata = app.gateway.fixture_current_metadata("alice@example.com", "INBOX", 9).unwrap();
    metadata.version.message_guid = "replacement-current-message".into();
    let replacement = MessageSummary { mailbox_name:"INBOX".into(), uid:9, flags:vec![], date_received:String::new(), size_virtual:1, subject:Some("Replacement".into()), from:None, to:None, metadata:Some(metadata) };
    let changed = BrowserApp::new(HttpPolicy::default(), StubGateway { labels_store:Some(store.clone()), browser_fixture_accounts:true, message_list_override:Some(vec![replacement]), ..StubGateway::default() });
    for (path, bob) in [("/mailbox?name=INBOX", false), ("/message?mailbox=INBOX&uid=9", false), ("/mailbox?name=INBOX", true), ("/message?mailbox=INBOX&uid=9", true)] {
        let response = badge_get(&changed, path, "", bob);
        assert_eq!(response.response.status_code, 200, "{path} bob={bob}");
        assert!(!body_text(&response).contains(&format!("data-label-id=\"{id}\"")));
    }
    *changed.gateway.delete_list_decision.lock().unwrap() = Some(BrowserMessageListDecision::Listed { canonical_username:"bob@example.com".into(), mailbox_name:"INBOX".into(), messages:vec![] });
    let foreign = badge_get(&changed, "/mailbox?name=INBOX", "", false);
    assert_eq!(foreign.response.status_code, 503);
    assert!(!body_text(&foreign).contains("PrivateOwned"));
    assert_eq!(store.load("alice@example.com").unwrap(), saved);
    assert!(changed.gateway.submitted.lock().unwrap().is_empty());
    assert!(changed.gateway.fixture_current_metadata("alice@example.com", "INBOX", 9).is_some());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn assigned_label_badges_metadata_or_private_store_failure_is_unavailable() {
    let (app, root, store) = fixture();
    assert_eq!(call(&app, "revision=0&action=create&name=PrivateOwned").response.status_code, 200);
    let id = store.load("alice@example.com").unwrap().labels()[0].id().to_owned();
    assert_eq!(call(&app, &format!("revision=1&action=attach&label_id={id}&{}", reference(&app))).response.status_code, 200);
    let saved = store.load("alice@example.com").unwrap();
    for path in ["/mailbox?name=INBOX", "/message?mailbox=INBOX&uid=9"] {
        let response = badge_get(&app, path, "OSMAP/LegacyMetadata", false);
        assert_eq!(response.response.status_code, 200);
        let html = body_text(&response);
        assert!(html.contains("message-labels-unavailable\">Labels unavailable"));
        assert!(!html.contains(&format!("data-label-id=\"{id}\"")));
        assert!(!html.contains("message-labels-empty\">No labels"));
    }
    assert_eq!(store.load("alice@example.com").unwrap(), saved);
    let file = fs::read_dir(root.join("labels")).unwrap().map(|item| item.unwrap().path()).find(|path| path.extension().is_some_and(|ext| ext == "json")).unwrap();
    fs::write(&file, b"corrupt retained record").unwrap();
    let unavailable = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
    for current in [&app, &unavailable] {
        for path in ["/mailbox?name=INBOX", "/message?mailbox=INBOX&uid=9"] {
            let response = badge_get(current, path, "", false);
            assert_eq!(response.response.status_code, 200);
            let html = body_text(&response);
            assert!(html.contains("message-labels-unavailable\">Labels unavailable"));
            assert!(!html.contains(&format!("data-label-id=\"{id}\"")));
            assert!(!html.contains("message-labels-empty\">No labels"));
        }
    }
    assert_eq!(fs::read(&file).unwrap(), b"corrupt retained record");
    fs::remove_dir_all(root).unwrap();
}
