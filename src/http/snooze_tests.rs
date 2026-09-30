use super::*;
fn target() -> String {
    let m = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9);
    format!(
        "mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}",
        url_encode(&m.version.mailbox_guid),
        url_encode(&m.version.message_guid)
    )
}
fn now() -> u64 {
    crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
}
#[test]
fn snooze_native_set_cas_csrf_visibility_cancel_and_corrupt_refusal() {
    let root = temp_dir("snooze-native");
    let store = crate::snooze::SnoozeStore::new(root.join("markers"));
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            snooze_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let get = |url: &str| {
        app.handle_request(
            &request("GET", url, &authenticated_headers(), ""),
            "127.0.0.1",
        )
    };
    let post = |body: &str| {
        app.handle_request(
            &request(
                "POST",
                "/snooze/change",
                &authenticated_same_origin_headers(),
                body,
            ),
            "127.0.0.1",
        )
    };
    let csrf = StubGateway::validated_session().record.csrf_token;
    let until = crate::logging::format_unix_timestamp_utc(now() + 3600)[..16].to_string();
    let body = format!(
        "csrf_token={csrf}&action=set&revision=0&{}&until={until}",
        target()
    );
    let editor = get(&format!("/snooze?{}", target()));
    assert_eq!(editor.response.status_code, 200);
    assert!(!body_text(&editor).contains("name=return_to value=\"\""));
    assert_eq!(
        post(&body.replace(&csrf, "wrong")).response.status_code,
        403
    );
    assert_eq!(
        post(&format!("{body}&unexpected=1")).response.status_code,
        400
    );
    assert_eq!(
        post(&body.replace("uid=9", "uid=0")).response.status_code,
        400
    );
    assert_eq!(
        post(&body.replace(&until, "2026-02-30T01:00"))
            .response
            .status_code,
        400
    );
    let selected=format!("{body}&return_to=%2Fmailbox%3Fname%3DINBOX%26filter%3Dunread%26selected_mailbox%3DINBOX%26selected_uid%3D9");
    let saved = post(&selected);
    assert_eq!(saved.response.status_code, 303);
    let location = saved
        .response
        .headers
        .iter()
        .find(|(k, _)| k == "Location")
        .unwrap()
        .1
        .clone();
    assert!(location.contains("filter=unread") && !location.contains("selected_"));
    let stale = post(&body);
    assert_eq!(stale.response.status_code, 409);
    assert!(body_text(&stale).contains("name=revision value=\"0\""));
    assert!(body_text(&stale).contains(&until));
    assert!(body_text(&stale).contains("disabled"));
    let mailbox = body_text(&get("/mailbox?name=INBOX"));
    assert!(!mailbox.contains("Quarterly report"));
    assert!(mailbox.contains("1 snoozed messages hidden"));
    let welcome = body_text(&get("/mailboxes"));
    assert!(!welcome.contains("Quarterly report"));
    assert!(welcome.contains("1 snoozed messages hidden"));
    let reader = get("/message?mailbox=INBOX&uid=9");
    assert_eq!(reader.response.status_code, 200);
    assert!(body_text(&reader).contains("Example"));
    assert!(body_text(&get("/search?q=Quarterly&scope=all")).contains("Quarterly report"));
    for marker in ["WelcomeData/wrong-owner", "WelcomeData/wrong-mailbox"] {
        let mut req = request("GET", "/mailbox?name=INBOX", &authenticated_headers(), "");
        req.headers.insert("user-agent".into(), marker.into());
        assert_eq!(
            app.handle_request(&req, "127.0.0.1").response.status_code,
            503
        );
    }
    let record = store.load("alice@example.com", now()).unwrap();
    let cancel=format!("csrf_token={csrf}&action=cancel&revision={}&{}&return_to=%2Fmailbox%3Fname%3DINBOX%26filter%3Dunread",record.revision(),target());
    let result = post(&cancel);
    assert_eq!(result.response.status_code, 303);
    assert!(
        result
            .response
            .headers
            .iter()
            .any(|(k, v)| k == "Location" && v == "/mailbox?filter=unread&name=INBOX")
            || result
                .response
                .headers
                .iter()
                .any(|(k, v)| k == "Location" && v == "/mailbox?name=INBOX&filter=unread")
    );
    assert!(body_text(&get("/mailbox?name=INBOX")).contains("Quarterly report"));
    assert!(store
        .load("bob@example.com", now())
        .unwrap()
        .markers()
        .is_empty());
    let file = fs::read_dir(root.join("markers"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|v| v == "json"))
        .unwrap();
    fs::write(&file, b"broken").unwrap();
    let mailbox = body_text(&get("/mailbox?name=INBOX"));
    assert!(mailbox.contains("Quarterly report") && mailbox.contains("Snooze is unavailable"));
    assert_eq!(get("/snoozed").response.status_code, 503);
    assert_eq!(fs::read(file).unwrap(), b"broken");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn snooze_expiry_on_native_load_restores_message_and_utc_is_not_local() {
    let root = temp_dir("snooze-expiry");
    let store = crate::snooze::SnoozeStore::new(root.join("markers"));
    let t = now();
    let row = MessageSummary {
        to: None,
        metadata: Some(StubGateway::fixture_metadata(
            "alice@example.com",
            "INBOX",
            9,
        )),
        mailbox_name: "INBOX".into(),
        uid: 9,
        flags: vec![],
        date_received: String::new(),
        size_virtual: 0,
        subject: None,
        from: None,
    };
    let id = crate::snooze::MessageIdentity::from_summary(
        "alice@example.com",
        "alice@example.com",
        "INBOX",
        &row,
    )
    .unwrap();
    store
        .set("alice@example.com", &id, 0, t - 1, t - 100)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            snooze_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let result = app.handle_request(
        &request("GET", "/mailbox?name=INBOX", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert!(body_text(&result).contains("Quarterly report"));
    assert!(store
        .load("alice@example.com", now())
        .unwrap()
        .markers()
        .is_empty());
    assert_eq!(
        crate::snooze::parse_utc("2026-10-01T00:00", 1790726400).unwrap(),
        1790812800
    );
    for value in [
        "2026-02-30T10:00",
        "2026-10-01T24:00",
        "2026-10-01T01:60",
        "2026-10-01T00:00Z",
        "2026-10-01 00:00",
        "éééééééé",
    ] {
        assert!(crate::snooze::parse_utc(value, 1790726400).is_err())
    }
    fs::remove_dir_all(root).unwrap();
}
