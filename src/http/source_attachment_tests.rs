use super::*;

fn fixture() -> (BrowserApp<StubGateway>, PathBuf, FileDraftStore) {
    let root = std::env::temp_dir().join(format!(
        "osmap-source-ux-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let store = FileDraftStore::new(&root, DraftPolicy::default());
    let gateway = StubGateway {
        draft_store: Some(store.clone()),
        browser_fixture_accounts: true,
        ..StubGateway::default()
    };
    (BrowserApp::new(HttpPolicy::default(), gateway), root, store)
}

fn fields() -> String {
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    format!("source_mailbox=INBOX&source_uid=9&source_mailbox_guid={}&source_message_guid={}&include_original_attachment_1=1.2", version.mailbox_guid, version.message_guid)
}

fn post(app: &BrowserApp<StubGateway>, path: &str, fields: &str, ua: &str) -> HandledHttpResponse {
    let form = format!(
        "csrf_token={}&to=desk%40example.test&body=Retained%20source%20notes&{fields}",
        StubGateway::validated_session().record.csrf_token
    );
    let mut request = request("POST", path, &authenticated_same_origin_headers(), &form);
    request.headers.insert("user-agent".into(), ua.into());
    if request.method == HttpMethod::Post
        && matches!(request.path.as_str(), "/send" | "/drafts/save")
    {
        add_native_compose_intent(app, &mut request);
    }
    app.handle_request(&request, "127.0.0.1")
}

#[test]
fn source_attachment_send_decodes_the_same_owned_snapshot_and_saved_identity_survives_restart() {
    let (app, root, store) = fixture();
    let saved = post(&app, "/drafts/save", &fields(), "normal");
    assert_eq!(saved.response.status_code, 303);
    let path = location_header(&saved);
    let id = path.trim_start_matches("/draft?id=");
    let restored = FileDraftStore::new(&root, DraftPolicy::default())
        .load("alice@example.com", id, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        restored.source_attachments.as_ref().unwrap().version,
        Some(StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version)
    );
    assert!(
        restored.request.attachments.is_empty(),
        "source bytes are not stored in the draft"
    );
    let sent = post(
        &app,
        "/send",
        &format!("draft_id={id}&draft_revision=1&{}", fields()),
        "normal",
    );
    assert_eq!(sent.response.status_code, 303);
    assert_eq!(
        sent.audit_events
            .iter()
            .filter(|event| event.action == "stub_source_read")
            .count(),
        1
    );
    assert!(!sent
        .audit_events
        .iter()
        .any(|event| event.action == "stub_attachment_download"));
    let submitted = app.gateway.submitted.lock().unwrap();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].attachments[0].filename, "report.pdf");
    assert_eq!(submitted[0].attachments[0].body, b"%PDF-stub%");
    assert!(store.load("alice@example.com", id, 100).unwrap().is_none());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_attachment_changed_foreign_and_unavailable_snapshots_preserve_the_form() {
    let (app, root, store) = fixture();
    for path in ["/drafts/save", "/send"] {
        for ua in [
            "SourceStale",
            "SourceWrongMailbox",
            "SourceWrongUid",
            "SourceWrongAccount",
            "SourceWrongSession",
            "SourceOversize",
            "SourceUnavailable",
        ] {
            let failed = post(&app, path, &fields(), ua);
            assert_eq!(
                failed.response.status_code,
                if ua == "SourceUnavailable" { 503 } else { 409 },
                "{path} {ua}"
            );
            let html = body_text(&failed);
            assert!(html.contains("Retained source notes"));
            assert!(html.contains("name=\"include_original_attachment_1\" value=\"1.2\" checked"));
            assert!(html.contains("name=\"source_message_guid\""));
            assert!(!html.contains("inert-source-marker"));
            assert!(!failed
                .audit_events
                .iter()
                .any(|event| event.action == "stub_attachment_download"));
        }
    }
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert!(store.list("alice@example.com", 100).unwrap().is_empty());
    let recovery = post(&app, "/drafts/save", &fields(), "normal");
    assert_eq!(
        recovery.response.status_code, 303,
        "all failed fetches release the budget"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_attachment_identity_is_required_and_legacy_or_changed_drafts_stay_editable() {
    let (app, root, store) = fixture();
    let legacy_fields = "source_mailbox=INBOX&source_uid=9&include_original_attachment_1=1.2";
    for path in ["/drafts/save", "/send"] {
        let denied = post(&app, path, legacy_fields, "normal");
        assert_eq!(denied.response.status_code, 409);
        assert!(body_text(&denied).contains("identity cannot be verified"));
        assert!(!denied
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
        let denied = post(
            &app,
            path,
            &(legacy_fields.to_string() + "&source_mailbox_guid=" + &"a".repeat(32)),
            "normal",
        );
        assert_eq!(denied.response.status_code, 400);
    }
    for variant in ["legacy", "changed", "unavailable"] {
        let saved = post(&app, "/drafts/save", &fields(), "normal");
        assert_eq!(saved.response.status_code, 303);
        let path = location_header(&saved);
        let id = path.trim_start_matches("/draft?id=");
        let mut draft = store.load("alice@example.com", id, 100).unwrap().unwrap();
        let source = draft.source_attachments.as_mut().unwrap();
        match variant {
            "legacy" => source.version = None,
            "changed" => source.version.as_mut().unwrap().message_guid = "changed-original".into(),
            _ => source.uid = 900,
        }
        store.save(&draft, 100).unwrap();
        let resumed = app.handle_request(
            &request("GET", &path, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(resumed.response.status_code, 200, "{variant}");
        let html = body_text(&resumed);
        assert!(html.contains("Retained source notes"));
        assert!(html.contains("Retained source attachments"));
        assert!(
            !html.contains("report.pdf"),
            "do not borrow a newer file's name"
        );
        let removed = post(
            &app,
            "/drafts/save",
            &format!("draft_id={id}&draft_revision=2"),
            "SourceUnavailable",
        );
        assert_eq!(removed.response.status_code, 303);
        assert!(!removed
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
        let loaded = store.load("alice@example.com", id, 100).unwrap().unwrap();
        assert!(loaded.source_attachments.is_none());
        assert_eq!(loaded.request.body, "Retained source notes");
    }
    fs::remove_dir_all(root).unwrap();
}
