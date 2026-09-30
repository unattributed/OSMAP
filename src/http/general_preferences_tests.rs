use super::*;
#[test]
fn general_partial_preferences_preserve_latest_fields_and_refuse_mixed_or_stale() {
    let root = temp_dir("general-partial");
    let reading = crate::reading_preferences::ReadingPreferencesStore::new(root.join("reading"));
    let signature = crate::signature::SignatureStore::new(root.join("signature"));
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            reading_preferences_store: Some(reading.clone()),
            signature_store: Some(signature.clone()),
            ..StubGateway::default()
        },
    );
    let account = "alice@example.com";
    let csrf = StubGateway::validated_session().record.csrf_token;
    let call = |path: &str, body: &str| {
        app.handle_request(
            &request("POST", path, &authenticated_same_origin_headers(), body),
            "127.0.0.1",
        )
    };
    let full = format!("csrf_token={csrf}&start_page=inbox&date_order=oldest");
    assert_eq!(call("/settings/reading", &full).response.status_code, 303);
    let partial = format!("csrf_token={csrf}&reading_action=start_page&start_page=drafts");
    assert_eq!(
        call("/settings/reading", &partial).response.status_code,
        303
    );
    let saved = reading.load(account).unwrap();
    assert_eq!(
        saved.date_order,
        crate::reading_preferences::DateOrder::Oldest
    );
    assert!(!saved.attachment_details && !saved.show_source_shortcut);
    assert_eq!(
        saved.start_page,
        crate::reading_preferences::StartPage::Drafts
    );
    // A later complete save, then an older General page's partial save: retain latest other fields.
    assert_eq!(
        call(
            "/settings/reading",
            &format!("csrf_token={csrf}&start_page=inbox&date_order=newest&show_source_shortcut=1")
        )
        .response
        .status_code,
        303
    );
    assert_eq!(
        call("/settings/reading", &partial).response.status_code,
        303
    );
    let latest = reading.load(account).unwrap();
    assert_eq!(
        latest.date_order,
        crate::reading_preferences::DateOrder::Newest
    );
    assert!(latest.show_source_shortcut && !latest.attachment_details);
    for body in [
        partial.replace(&csrf, "wrong"),
        format!("{partial}&date_order=oldest"),
        partial.replace("drafts", "invalid"),
    ] {
        assert!(call("/settings/reading", &body).response.status_code >= 400);
        assert_eq!(reading.load(account).unwrap(), latest);
    }
    assert_eq!(
        reading.load("bob@example.com").unwrap(),
        crate::reading_preferences::ReadingPreferences::default()
    );
    let sig = signature
        .change(
            account,
            0,
            crate::signature::SignatureChange::Definition {
                selection: crate::signature::SignatureSelection::Default,
                text: "<literal> footer",
            },
        )
        .unwrap();
    let choice=format!("csrf_token={csrf}&signature_revision={}&operation=selection&selection=none&return_section=general",sig.revision);
    let result = call("/settings/signature", &choice);
    assert_eq!(result.response.status_code, 303);
    assert_eq!(location_header(&result), "/settings?section=general");
    assert_eq!(signature.load(account).unwrap().text, "<literal> footer");
    assert_eq!(
        call("/settings/signature", &choice).response.status_code,
        409
    );
    assert_eq!(
        call(
            "/settings/signature",
            &choice.replace("return_section=general", "return_section=evil")
        )
        .response
        .status_code,
        400
    );
    for name in ["reading", "signature"] {
        let file = fs::read_dir(root.join(name))
            .unwrap()
            .filter_map(Result::ok)
            .map(|v| v.path())
            .find(|p| p.extension().is_some_and(|v| v == "json"))
            .unwrap();
        fs::write(&file, b"corrupt").unwrap();
        let response = if name == "reading" {
            call("/settings/reading", &partial)
        } else {
            call(
                "/settings/signature",
                &choice.replace("signature_revision=1", "signature_revision=2"),
            )
        };
        assert_eq!(response.response.status_code, 503);
        assert_eq!(fs::read(&file).unwrap(), b"corrupt");
    }
    let general = app.handle_request(
        &request("GET", "/settings", &authenticated_same_origin_headers(), ""),
        "127.0.0.1",
    );
    let body = body_text(&general);
    assert!(body.contains("Saved Reading preferences unavailable"));
    assert!(body.contains("Saved signature unavailable"));
    assert!(!body.contains("id=\"general-start-form\""));
    assert!(!body.contains("id=\"general-signature-form\""));
    fs::remove_dir_all(root).unwrap();
}
