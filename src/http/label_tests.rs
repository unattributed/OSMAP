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
