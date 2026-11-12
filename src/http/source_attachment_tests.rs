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

#[test]
fn schedule_materializes_verified_source_bytes_into_the_saved_snapshot() {
    let (app, root, store) = fixture();
    let saved = post(
        &app,
        "/drafts/save",
        &format!("{}&compose_action=schedule", fields()),
        "normal",
    );
    assert_eq!(saved.response.status_code, 303);
    let destination = location_header(&saved);
    assert!(destination.starts_with("/scheduled/new?draft="));
    let id = destination
        .strip_prefix("/scheduled/new?draft=")
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let draft = FileDraftStore::new(&root, DraftPolicy::default())
        .load("alice@example.com", id, 100)
        .unwrap()
        .unwrap();
    assert!(draft.source_attachments.is_none());
    assert_eq!(draft.request.attachments.len(), 1);
    assert_eq!(draft.request.attachments[0].filename, "report.pdf");
    assert_eq!(draft.request.attachments[0].body, b"%PDF-stub%");
    assert_eq!(draft.revision, Some(1));
    assert_eq!(
        saved
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_source_read")
            .count(),
        1
    );
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn schedule_source_changes_refuse_before_saving_or_creating_any_job() {
    let (app, root, store) = fixture();
    for ua in [
        "SourceStale",
        "SourceWrongAccount",
        "SourceWrongSession",
        "SourceUnavailable",
    ] {
        let refused = post(
            &app,
            "/drafts/save",
            &format!("{}&compose_action=schedule", fields()),
            ua,
        );
        assert_eq!(
            refused.response.status_code,
            if ua == "SourceUnavailable" { 503 } else { 409 }
        );
        assert!(body_text(&refused).contains("Retained source notes"));
        assert_eq!(
            refused
                .audit_events
                .iter()
                .filter(|event| event.action == "stub_source_read")
                .count(),
            1,
            "{ua}: source resolution must be reached rather than an unrelated early refusal"
        );
        assert!(!refused
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Location" && value.starts_with("/scheduled")));
        assert!(store.list("alice@example.com", 100).unwrap().is_empty());
    }
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn schedule_materialized_source_keeps_saved_attachment_removal_and_combined_caps() {
    let (app, root, store) = fixture();
    let saved = post(&app, "/drafts/save", &fields(), "normal");
    let destination = location_header(&saved);
    let id = destination.trim_start_matches("/draft?id=");
    let mut draft = store.load("alice@example.com", id, 100).unwrap().unwrap();
    // Fill the ordinary saved-file allowance, then select an additional source
    // file in the next compose action. A saved reference already counts toward
    // the same allowance and cannot be used to construct an over-limit fixture.
    draft.source_attachments = None;
    for index in 0..ComposePolicy::default().max_attachments {
        draft.request.attachments.push(
            UploadedAttachment::new(
                ComposePolicy::default(),
                format!("saved-{index}.txt"),
                "text/plain",
                vec![index as u8],
            )
            .unwrap(),
        );
    }
    store.save(&draft, 100).unwrap();
    let saved_revision = store
        .load("alice@example.com", id, 100)
        .unwrap()
        .unwrap()
        .revision
        .unwrap();
    let form = format!(
        "draft_id={id}&draft_revision={saved_revision}&compose_action=schedule&{}",
        fields()
    );
    let refused = post(&app, "/drafts/save", &form, "normal");
    assert_ne!(refused.response.status_code, 303);
    let unchanged = store.load("alice@example.com", id, 100).unwrap().unwrap();
    assert_eq!(unchanged.revision, Some(saved_revision));
    assert!(unchanged.source_attachments.is_none());
    assert_eq!(
        unchanged.request.attachments.len(),
        ComposePolicy::default().max_attachments
    );
    let accepted = post(
        &app,
        "/drafts/save",
        &format!("{form}&remove_saved_attachment_0=1"),
        "normal",
    );
    assert_eq!(accepted.response.status_code, 303);
    let materialized = store.load("alice@example.com", id, 100).unwrap().unwrap();
    assert!(materialized.source_attachments.is_none());
    assert_eq!(
        materialized.request.attachments.len(),
        ComposePolicy::default().max_attachments
    );
    assert!(!materialized
        .request
        .attachments
        .iter()
        .any(|file| file.filename == "saved-0.txt"));
    assert!(materialized
        .request
        .attachments
        .iter()
        .any(|file| file.filename == "report.pdf" && file.body == b"%PDF-stub%"));
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}
