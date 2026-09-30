use super::*;
use crate::settings::UserSettingsStore;
#[test]
fn partial_settings_runtime_preserves_redacted_success_and_failure_audit() {
    let root = temp_dir("partial-settings-runtime-audit");
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(), "partial-settings-proof", "127.0.0.1", "Settings/Test",
    ).unwrap();
    let store = crate::settings::FileUserSettingsStore::new(root.join("settings"));
    for corrupted in [false, true] {
        if corrupted {
            fs::write(store.settings_path_for_username(&session.record.canonical_username), b"corrupt\n").unwrap();
        }
        for (field, result) in [
            ("content", gateway.update_content_setting(&context, &session, HtmlDisplayPreference::PreferPlainText)),
            ("archive", gateway.update_archive_setting(&context, &session, Some("Private/Archive"))),
        ] {
            assert_eq!(matches!(result.decision, BrowserSettingsUpdateDecision::Updated), !corrupted);
            assert_eq!(result.audit_events.len(), 1);
            let event = &result.audit_events[0];
            assert_eq!(event.action, if corrupted { "user_settings_update_failed" } else { "user_settings_updated" });
            for (key, value) in [("setting", field), ("request_id", "partial-settings-proof"), ("canonical_username", "alice@example.com")] {
                assert!(event.fields.iter().any(|f| f.key == key && f.value == value));
            }
            assert!(event.fields.iter().any(|f| f.key == "session_ref" && f.value.starts_with("asr-")));
            assert!(!event.fields.iter().any(|f| f.value.contains("Private/Archive") || f.value == session.record.session_id || f.value == session.record.csrf_token));
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copies_owned_archive_forms_preserve_content_and_refuse_invalid_owner_csrf_options() {
    let root = temp_dir("copies-owned-route");
    let store = crate::settings::FileUserSettingsStore::new(&root);
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            settings_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let good=format!("csrf_token={}&return_section=copies&html_display_preference=prefer_plain_text&archive_mailbox_name=INBOX.Projects",StubGateway::validated_session().record.csrf_token);
    let perform = |body: &str, ua: &str| {
        let mut r = request(
            "POST",
            "/settings",
            &authenticated_same_origin_headers(),
            body,
        );
        r.headers.insert("user-agent".into(), ua.into());
        app.handle_request(&r, "127.0.0.1")
    };
    assert_eq!(
        location_header(&perform(&good, "Firefox/Test")),
        "/settings?section=copies&updated=1"
    );
    let saved = store.load("alice@example.com").unwrap().unwrap();
    assert_eq!(
        saved.html_display_preference,
        HtmlDisplayPreference::PreferPlainText
    );
    assert_eq!(
        saved.archive_mailbox_name.as_deref(),
        Some("INBOX.Projects")
    );
    for (body, ua, status) in [
        (good.clone(), "CopiesWrongOwner", 503),
        (
            good.replace("INBOX.Projects", "dovecot"),
            "Firefox/Test",
            400,
        ),
        (
            good.replace("INBOX.Projects", "Missing"),
            "Firefox/Test",
            400,
        ),
        (
            good.replace(&StubGateway::validated_session().record.csrf_token, "bad"),
            "Firefox/Test",
            403,
        ),
    ] {
        assert_eq!(perform(&body, ua).response.status_code, status);
        assert_eq!(store.load("alice@example.com").unwrap().unwrap(), saved);
    }
    let mut req = request(
        "GET",
        "/settings?section=copies",
        &authenticated_same_origin_headers(),
        "",
    );
    req.headers
        .insert("user-agent".into(), "CopiesWrongOwner".into());
    let page = app.handle_request(&req, "127.0.0.1");
    assert!(body_text(&page).contains("Archive changes are unavailable"));
    assert!(body_text(&page).contains("name=\"archive_mailbox_name\" disabled"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copies_stale_archive_action_preserves_newer_content_and_refuses_corruption() {
    let root = temp_dir("copies-stale-archive");
    let store = crate::settings::FileUserSettingsStore::new(&root);
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            settings_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let csrf = StubGateway::validated_session().record.csrf_token;
    let post = |body: &str| {
        app.handle_request(
            &request(
                "POST",
                "/settings",
                &authenticated_same_origin_headers(),
                body,
            ),
            "127.0.0.1",
        )
    };
    assert_eq!(
        post(&format!(
            "csrf_token={csrf}&html_display_preference=prefer_plain_text"
        ))
        .response
        .status_code,
        303
    );
    let page = app.handle_request(
        &request(
            "GET",
            "/settings?section=copies",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert!(body_text(&page).contains("name=\"settings_action\" value=\"archive\""));
    assert!(!body_text(&page).contains("name=\"html_display_preference\""));
    assert_eq!(
        post(&format!(
            "csrf_token={csrf}&html_display_preference=prefer_sanitized_html"
        ))
        .response
        .status_code,
        303
    );
    let archive=format!("csrf_token={csrf}&settings_action=archive&return_section=copies&archive_mailbox_name=INBOX.Projects");
    assert_eq!(post(&archive).response.status_code, 303);
    let value = store.load("alice@example.com").unwrap().unwrap();
    assert_eq!(
        value.html_display_preference,
        HtmlDisplayPreference::PreferSanitizedHtml
    );
    assert_eq!(
        value.archive_mailbox_name.as_deref(),
        Some("INBOX.Projects")
    );
    let path = store.settings_path_for_username("alice@example.com");
    let before = fs::read(&path).unwrap();
    for invalid in [
        format!("{archive}&html_display_preference=prefer_plain_text"),
        archive.replace("settings_action=archive", "settings_action=unknown"),
        format!("{archive}&settings_action=archive"),
    ] {
        assert_eq!(post(&invalid).response.status_code, 400);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    fs::write(&path, b"corrupt\n").unwrap();
    assert_eq!(post(&archive).response.status_code, 503);
    assert_eq!(fs::read(&path).unwrap(), b"corrupt\n");
    assert_eq!(
        post(&format!(
            "csrf_token={csrf}&html_display_preference=prefer_plain_text"
        ))
        .response
        .status_code,
        503
    );
    assert_eq!(fs::read(&path).unwrap(), b"corrupt\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn settings_query_notice_describes_loaded_values_without_claiming_a_write() {
    for query in ["updated=1", "appearance_updated=1"] {
        let response = app().handle_request(
            &request(
                "GET",
                &format!("/settings?section=copies&{query}"),
                &authenticated_same_origin_headers(),
                "",
            ),
            "127.0.0.1",
        );
        let html = body_text(&response);
        assert!(html.contains("Current saved settings are shown below. Review your values."));
        assert!(!html.contains("Settings were updated."));
        assert!(!html.contains("Appearance was updated."));
    }
}

#[test]
fn privacy_content_merge_preserves_newer_archive_and_refuses_invalid_or_corrupt_writes() {
    let root = temp_dir("privacy-content-route");
    let store = crate::settings::FileUserSettingsStore::new(&root);
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway { settings_store: Some(store.clone()), ..StubGateway::default() });
    let csrf = StubGateway::validated_session().record.csrf_token;
    let perform = |method, url: &str, body: &str| { let mut r = request(method,url,&authenticated_same_origin_headers(),body); r.headers.insert("user-agent".into(),"PrivacyBrowser".into()); app.handle_request(&r,"127.0.0.1") };
    for section in ["privacy","reading"] {
        let page = perform("GET", &format!("/settings?section={section}"), "");
        assert_eq!(page.response.status_code,200);
        if section == "privacy" {
            assert!(body_text(&page).contains("href=\"/settings?section=reading\""));
            assert!(!body_text(&page).contains("name=\"settings_action\""));
        } else {
            assert!(body_text(&page).contains("name=\"settings_action\" value=\"content\""));
        }
        store.save_archive("alice@example.com", Some("Newer missing archive")).unwrap();
        let form = format!("csrf_token={csrf}&settings_action=content&return_section={section}&html_display_preference=prefer_plain_text");
        assert_eq!(perform("POST","/settings",&form).response.status_code,303);
        assert_eq!(store.load("alice@example.com").unwrap().unwrap().archive_mailbox_name.as_deref(),Some("Newer missing archive"));
        let page = perform("GET","/message?mailbox=INBOX&uid=9","");
        assert!(body_text(&page).contains("Synthetic plain part"));
        assert!(!body_text(&page).contains("<strong>protected part</strong>"));
        let htmlform=form.replace("prefer_plain_text","prefer_sanitized_html");
        assert_eq!(perform("POST","/settings",&htmlform).response.status_code,303);
        let page = perform("GET","/message?mailbox=INBOX&uid=9","");
        assert!(body_text(&page).contains("<strong>protected part</strong>"));
        assert!(!body_text(&page).contains("external.invalid"));
        let path = store.settings_path_for_username("alice@example.com");
        let before = fs::read(&path).unwrap();
        for (invalid, status) in [(form.replace(&csrf,"bad"),403),(form.replace("settings_action=content","settings_action=unknown"),400),(format!("{form}&archive_mailbox_name=Old"),400),(format!("{form}&settings_action=content"),400),(form.replace("prefer_plain_text","raw_html"),400)] {
            assert_eq!(perform("POST","/settings",&invalid).response.status_code,status);
            assert_eq!(fs::read(&path).unwrap(),before);
        }
    }
    assert!(store.load("bob@example.com").unwrap().is_none());
    let path=store.settings_path_for_username("alice@example.com");fs::write(&path,b"corrupt\n").unwrap();
    assert_eq!(perform("GET","/settings?section=privacy","").response.status_code,503);
    assert_eq!(perform("POST","/settings",&format!("csrf_token={csrf}&settings_action=content&html_display_preference=prefer_plain_text")).response.status_code,503);
    assert_eq!(fs::read(path).unwrap(),b"corrupt\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn copies_selection_uses_one_owned_summary_read_and_retains_archive() {
    let root = temp_dir("copies-folder-selection");
    let store = crate::settings::FileUserSettingsStore::new(&root);
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway { settings_store: Some(store.clone()), ..StubGateway::default() });
    let post = format!("csrf_token={}&return_section=copies&settings_action=archive&archive_mailbox_name=INBOX.Projects", StubGateway::validated_session().record.csrf_token);
    assert_eq!(app.handle_request(&request("POST", "/settings", &authenticated_same_origin_headers(), &post), "127.0.0.1").response.status_code, 303);
    let before = store.load("alice@example.com").unwrap();
    for marker in ["valid", "empty", "wrong-owner", "wrong-mailbox", "wrong-row", "zero", "duplicate", "failure"] {
        let mut req = request("GET", "/settings?section=copies&folder=INBOX", &authenticated_same_origin_headers(), "");
        req.headers.insert("user-agent".into(), format!("WelcomeData/{marker}"));
        let result = app.handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, 200);
        assert_eq!(result.audit_events.iter().filter(|v| v.action == "welcome_fixture_summary_list").count(), 1);
        let body = body_text(&result);
        let expected = match marker { "valid" => "8", "empty" => "0", _ => "Unknown" };
        assert!(body.contains(&format!("data-folder-messages>{expected}</dd>")), "{marker}");
        assert!(body.contains("folder=INBOX\" aria-current=\"true\""));
        assert!(body.contains("Counts cover loaded summaries") || body.contains("Verified summary counts are unavailable"));
        assert_eq!(store.load("alice@example.com").unwrap(), before);
    }
    for query in ["section=copies&folder=Foreign", "section=copies&folder=", "section=copies&folder=%0aINBOX", "section=general&folder=INBOX", "section=copies&q=x&folder=INBOX"] {
        assert_eq!(app.handle_request(&request("GET", &format!("/settings?{query}"), &authenticated_same_origin_headers(), ""), "127.0.0.1").response.status_code, 400);
    }
    assert!(super::super::header_theme::safe_return("/settings?section=copies&folder=INBOX.Projects").unwrap().contains("folder=INBOX.Projects"));
    assert!(super::super::header_theme::safe_return("/settings?section=general&folder=INBOX").is_none());
    fs::remove_dir_all(root).unwrap();
}
