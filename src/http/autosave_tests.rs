use super::*;
#[test]
fn autosave_native_preference_and_receipt_preserve_intent_cas_authority() {
    let root = temp_dir("autosave-native");
    let prefs = crate::autosave::Store::new(root.join("settings"));
    let drafts = FileDraftStore::new(root.join("drafts"), DraftPolicy::default());
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            autosave_store: Some(prefs.clone()),
            draft_store: Some(drafts.clone()),
            ..StubGateway::default()
        },
    );
    let csrf = StubGateway::validated_session().record.csrf_token;
    let account = "alice@example.com";
    let call = |method: &str, path: &str, body: &str| {
        app.handle_request(
            &request(method, path, &authenticated_same_origin_headers(), body),
            "127.0.0.1",
        )
    };
    let body = format!("csrf_token={csrf}&revision=0&enabled=1&interval=30");
    assert_eq!(
        call(
            "POST",
            "/settings/autosave",
            &body.replace(&csrf, "invalid")
        )
        .response
        .status_code,
        403
    );
    assert_eq!(
        prefs.load(account).unwrap(),
        crate::autosave::Preference::default()
    );
    assert_eq!(
        call("POST", "/settings/autosave", &body)
            .response
            .status_code,
        303
    );
    assert_eq!(
        call("POST", "/settings/autosave", &body)
            .response
            .status_code,
        409
    );
    let cfg = call("GET", "/drafts/autosave/config", "");
    assert!(body_text(&cfg).contains("\"enabled\":true"));
    let mut save=request("POST","/drafts/autosave",&authenticated_same_origin_headers(),&format!("csrf_token={csrf}&to=bob%40example.com&subject=Before&body=First%0Aline&body_format=plain"));
    add_native_compose_intent(&app, &mut save);
    let first = app.handle_request(&save, "127.0.0.1");
    assert_eq!(first.response.status_code, 200, "{}", body_text(&first));
    let receipt: serde_json::Value = serde_json::from_slice(&first.response.body).unwrap();
    let id = receipt["draft_id"].as_str().unwrap();
    assert_eq!(receipt["revision"], 1);
    let replay = app.handle_request(&save, "127.0.0.1");
    assert!(!replay.response.headers.iter().any(|(k,v)|k=="Content-Type"&&v=="application/json"),"consumed original intent returns a read-only receipt, never an automatic-save confirmation");
    assert_eq!(drafts.list(account, 100).unwrap().len(), 1);
    let second=format!("csrf_token={csrf}&draft_id={id}&draft_revision=1&send_intent={}&to=bob%40example.com&subject=After&body=Second&body_format=plain",receipt["send_intent"].as_str().unwrap());
    let saved = call("POST", "/drafts/autosave", &second);
    assert_eq!(saved.response.status_code, 200, "{}", body_text(&saved));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&saved.response.body).unwrap()["revision"],
        2
    );
    let stale = call("POST", "/drafts/autosave", &second);
    assert_eq!(stale.response.status_code, 409);
    assert!(
        !stale
            .response
            .headers
            .iter()
            .any(|(key, value)| key.eq_ignore_ascii_case("content-type")
                && value == "application/json"),
        "stale revisions must not become confirmed pre-write refusals"
    );
    assert_eq!(
        drafts.load(account, id, 100).unwrap().unwrap().request.body,
        "Second"
    );
    assert!(drafts.load("bob@example.com", id, 100).unwrap().is_none());
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    let mut foreign = drafts.load(account, id, 100).unwrap().unwrap();
    foreign.draft_id = "b".repeat(32);
    foreign.canonical_username = "bob@example.com".into();
    foreign.revision = None;
    drafts.save(&foreign, 100).unwrap();
    let mut source = drafts.load(account, id, 100).unwrap().unwrap();
    source.draft_id = "c".repeat(32);
    source.revision = None;
    source.source_attachments = Some(crate::draft::DraftSourceAttachments {
        mailbox_name: "INBOX".into(),
        uid: 9,
        version: None,
        part_paths: vec!["1.2".into()],
    });
    drafts.save(&source, 100).unwrap();
    let source_before = drafts
        .load(account, &source.draft_id, 100)
        .unwrap()
        .unwrap();
    let foreign_before = drafts
        .load("bob@example.com", &foreign.draft_id, 100)
        .unwrap()
        .unwrap();
    for refused_id in [
        "d".repeat(32),
        foreign.draft_id.clone(),
        source.draft_id.clone(),
    ] {
        let mut refused = request(
            "POST",
            "/drafts/autosave",
            &authenticated_same_origin_headers(),
            &format!("csrf_token={csrf}&draft_id={refused_id}&draft_revision=1&body=Retained"),
        );
        add_native_compose_intent(&app, &mut refused);
        let response = app.handle_request(&refused, "127.0.0.1");
        assert_eq!(response.response.status_code, 409);
        let value: serde_json::Value = serde_json::from_slice(&response.response.body).unwrap();
        assert_eq!(value, serde_json::json!({"version":1,"state":"paused"}));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "autosave_refused_before_write"));
    }
    assert!(
        drafts
            .load(account, &source.draft_id, 100)
            .unwrap()
            .unwrap()
            == source_before
    );
    assert!(
        drafts
            .load("bob@example.com", &foreign.draft_id, 100)
            .unwrap()
            .unwrap()
            == foreign_before
    );
    let mut unsure = request(
        "POST",
        "/drafts/autosave",
        &authenticated_same_origin_headers(),
        &format!("csrf_token={csrf}&body=Unknown"),
    );
    add_native_compose_intent(&app, &mut unsure);
    unsure
        .headers
        .insert("user-agent".into(), "OSMAP/DraftSaveUnconfirmed".into());
    let result = app.handle_request(&unsure, "127.0.0.1");
    assert_eq!(result.response.status_code, 503);
    assert!(
        !result
            .response
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json"),
        "uncertain native HTML must not become a saved receipt"
    );
}

#[test]
fn autosave_prewrite_refusals_preserve_draft_and_manual_save_intent() {
    for (reason, suffix) in [
        ("protection_invalid", "&pgp_sign=on"),
        ("request_unsupported", "&unexpected=1"),
        ("preference_disabled", ""),
        ("preference_unavailable", ""),
    ] {
        let root = temp_dir("autosave-prewrite");
        let prefs = crate::autosave::Store::new(root.join("settings"));
        if reason != "preference_disabled" {
            prefs.save("alice@example.com", 0, true, 30).unwrap();
        }
        let drafts = FileDraftStore::new(root.join("drafts"), DraftPolicy::default());
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                autosave_store: (reason != "preference_unavailable").then_some(prefs),
                draft_store: Some(drafts.clone()),
                ..StubGateway::default()
            },
        );
        let csrf = StubGateway::validated_session().record.csrf_token;
        let mut attempted = request(
            "POST",
            "/drafts/autosave",
            &authenticated_same_origin_headers(),
            &format!("csrf_token={csrf}&body=Retained%0Apublic+edits{suffix}"),
        );
        add_native_compose_intent(&app, &mut attempted);
        let fields = parse_urlencoded_form(&attempted.body, 32, 4096).unwrap();
        let intent = fields.get("send_intent").unwrap();
        let response = app.handle_request(&attempted, "127.0.0.1");
        assert_eq!(response.response.status_code, 409);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.response.body).unwrap(),
            serde_json::json!({"version":1,"state":"paused","reason":reason})
        );
        let refusal = response
            .audit_events
            .iter()
            .find(|event| event.action == "autosave_refused_before_write")
            .unwrap();
        assert!(refusal
            .fields
            .iter()
            .any(|field| field.key == "reason" && field.value == reason));
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_draft_save"));
        assert!(drafts.list("alice@example.com", 100).unwrap().is_empty());
        assert!(app.gateway.drafts.lock().unwrap().is_empty());
        assert!(matches!(
            app.gateway
                .send_receipt(&StubGateway::validated_session(), intent),
            Ok(None)
        ));
        // The original, unconsumed intent can be used by an explicit corrected
        // manual save, including when automatic preference reads are disabled.
        let manual = request(
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &format!("csrf_token={csrf}&send_intent={intent}&body=Retained%0Apublic+edits"),
        );
        let saved = app.handle_request(&manual, "127.0.0.1");
        assert_eq!(saved.response.status_code, 303);
        let location = location_header(&saved);
        let id = location.trim_start_matches("/draft?id=");
        let stored = drafts.load("alice@example.com", id, 100).unwrap().unwrap();
        assert_eq!(stored.revision, Some(1));
        assert_eq!(stored.request.body, "Retained\npublic edits");
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
    }
}
