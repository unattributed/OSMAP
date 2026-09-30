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
    assert_eq!(
        call("POST", "/drafts/autosave", &second)
            .response
            .status_code,
        409
    );
    assert_eq!(
        drafts.load(account, id, 100).unwrap().unwrap().request.body,
        "Second"
    );
    assert!(drafts.load("bob@example.com", id, 100).unwrap().is_none());
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
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
