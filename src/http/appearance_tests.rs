use super::*;

const CSRF: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

#[test]
fn display_route_persists_one_snapshot_and_rejects_invalid_changes() {
    use crate::appearance::{AppearanceSettings, Density, FontSize, PresentationStyle, ReaderLayout};
    let root = temp_dir("display-preferences-route");
    let store = AppearanceStore::new(root.join("appearance"));
    let browser = BrowserApp::new(HttpPolicy::default(), StubGateway { appearance_store: Some(store.clone()), ..StubGateway::default() });
    let fields = format!("csrf_token={CSRF}&appearance=dark&density=compact&font_size=large&reader_layout=stacked&presentation_style=icons");
    let post = |body: &str| request("POST", "/settings/display", &authenticated_same_origin_headers(), body);
    let result = browser.handle_request(&post(&fields), "127.0.0.1");
    assert_eq!(result.response.status_code, 303);
    let expected = AppearanceSettings { theme: AppearancePreference::Dark, density: Density::Compact, font_size: FontSize::Large, reader_layout: ReaderLayout::Stacked, show_avatars: false, message_preview: false, presentation_style: PresentationStyle::Icons };
    assert_eq!(store.load_settings("alice@example.com").expect("saved presentation"), expected);
    assert!(body_text(&result).contains("data-density=\"compact\""));
    assert!(body_text(&result).contains("data-show-avatars=\"false\""));
    for malformed in [
        fields.replace("compact", "enormous"),
        fields.replace("font_size=large&", ""),
        fields.replace("&presentation_style=icons", ""),
        fields.replace("presentation_style=icons", "presentation_style=unknown"),
        format!("{fields}&presentation_style=text_labels"),
        format!("{fields}&canonical_username=bob%40example.com"),
        format!("{fields}&font_size=small"),
        format!("{fields}&unexpected=1"),
        format!("{fields}&show_avatars=true"),
        fields.replace(CSRF, "wrong"),
    ] {
        let result = browser.handle_request(&post(&malformed), "127.0.0.1");
        assert!(matches!(result.response.status_code, 400 | 403));
        assert_eq!(store.load_settings("alice@example.com").expect("unchanged"), expected);
        assert!(!result.response.headers.iter().any(|(name, _)| name == "Set-Cookie"));
    }
    for origin in [None, Some("https://other.example.test")] {
        let mut req = post(&fields);
        req.headers.remove("origin");
        if let Some(origin) = origin { req.headers.insert("origin".into(), origin.into()); }
        let result = browser.handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, 403);
        assert_eq!(store.load_settings("alice@example.com").expect("origin refusal preserves snapshot"), expected);
    }
    let all_fields = format!("{fields}&show_avatars=1&message_preview=1");
    assert_eq!(browser.handle_request(&post(&all_fields), "127.0.0.1").response.status_code, 303);
    assert_eq!(store.load_settings("alice@example.com").unwrap(), AppearanceSettings { show_avatars: true, message_preview: true, ..expected });
    assert_eq!(browser.handle_request(&post(&fields), "127.0.0.1").response.status_code, 303);
    let themed = browser.handle_request(&theme_request("light"), "127.0.0.1");
    assert_eq!(themed.response.status_code, 303);
    assert_eq!(store.load_settings("alice@example.com").expect("merged theme"), AppearanceSettings { theme: AppearancePreference::Light, ..expected });
    assert_eq!(store.load_settings("bob@example.com").expect("other account"), AppearanceSettings::default());
    let mut download = crate::http_support::plain_text_response(200, "OK", "<!doctype html><html lang=\"en\" data-appearance=\"system\">synthetic source");
    let bytes = download.body.clone();
    crate::http_support::apply_appearance(&mut download, Some("osmap_presentation=v1.compact.large.stacked.0.0"));
    assert_eq!(download.body, bytes);
    fs::remove_dir_all(root).expect("remove owned fixture");
}

#[test]
fn display_runtime_preferences_survive_reopen() {
    use crate::appearance::{AppearanceSettings, Density, PresentationStyle};
    let root = temp_dir("display-runtime");
    let context = AuthenticationContext::new(AuthenticationPolicy::default(), "display-test", "127.0.0.1", "Synthetic/Test").expect("context");
    let session = StubGateway::validated_session();
    let preferences = AppearanceSettings { density: Density::Compact, show_avatars: false, presentation_style: PresentationStyle::Icons, ..AppearanceSettings::default() };
    RuntimeBrowserGateway::for_test(&root).update_display(&context, &session, preferences).expect("persist preferences");
    assert_eq!(RuntimeBrowserGateway::for_test(&root).load_display(&context, &session).expect("reopen preferences"), preferences);
    let mut other = session.clone();
    other.record.canonical_username = "bob@example.test".into();
    let reopened = RuntimeBrowserGateway::for_test(&root);
    assert_eq!(reopened.load_display(&context, &other).expect("other account"), AppearanceSettings::default());
    reopened.update_appearance(&context, &session, AppearancePreference::Light).expect("theme-only merge");
    assert_eq!(reopened.load_display(&context, &session).expect("preserved style"), AppearanceSettings { theme: AppearancePreference::Light, ..preferences });
    reopened.update_display(&context, &other, AppearanceSettings { theme: AppearancePreference::Dark, ..AppearanceSettings::default() }).expect("second account save");
    assert_eq!(reopened.load_display(&context, &session).unwrap().presentation_style, PresentationStyle::Icons);
    fs::remove_dir_all(root).expect("owned fixture cleanup");
}

#[test]
fn display_presentation_form_uses_account_choice_and_labelled_default() {
    use crate::appearance::{AppearanceSettings, PresentationStyle};
    let root = temp_dir("presentation-form");
    let store = AppearanceStore::new(root.join("appearance"));
    let browser = BrowserApp::new(HttpPolicy::default(), StubGateway { appearance_store: Some(store.clone()), ..StubGateway::default() });
    let get = || browser.handle_request(&request("GET", "/settings?section=appearance", &authenticated_headers(), ""), "127.0.0.1");
    let initial = get();
    assert_eq!(initial.response.status_code, 200);
    assert!(body_text(&initial).contains("<label for=\"settings-presentation-style\">Presentation style</label>"));
    assert!(body_text(&initial).contains("<option value=\"text_labels\" selected>Text labels</option>"));
    store.save_settings("alice@example.com", AppearanceSettings { presentation_style: PresentationStyle::Icons, ..AppearanceSettings::default() }).unwrap();
    let saved = get();
    assert!(body_text(&saved).contains("<option value=\"icons\" selected>Icons</option>"));
    assert!(!body_text(&saved).contains("<option value=\"text_labels\" selected>Text labels</option>"));
    assert!(body_text(&saved).contains("<span class=\"presentation-label\">Save changes</span>"));
    let general = browser.handle_request(&request("GET", "/settings?section=general", &authenticated_headers(), ""), "127.0.0.1");
    assert_eq!(general.response.status_code, 200);
    let general_html = body_text(&general);
    let display_form = general_html.split_once("action=\"/settings/display\"").expect("General appearance form").1.split("</form>").next().unwrap();
    assert!(display_form.contains("<input type=\"hidden\" name=\"presentation_style\" value=\"icons\">"));
    fs::remove_dir_all(root).expect("owned fixture cleanup");
}

#[test]
fn presentation_style_projection_uses_current_account_not_cookie_hints() {
    use crate::appearance::{AppearanceSettings, PresentationStyle};
    use crate::reading_preferences::{ReadingPreferences, ReadingPreferencesStore};
    let root = temp_dir("presentation-projection");
    let store = AppearanceStore::new(root.join("appearance"));
    let reading = ReadingPreferencesStore::new(root.join("reading"));
    store.save_settings("alice@example.com", AppearanceSettings { presentation_style: PresentationStyle::Icons, ..AppearanceSettings::default() }).unwrap();
    reading.save("alice@example.com", ReadingPreferences { show_source_shortcut: false, attachment_details: true, ..ReadingPreferences::default() }).unwrap();
    reading.save("bob@example.com", ReadingPreferences { show_source_shortcut: true, attachment_details: false, ..ReadingPreferences::default() }).unwrap();
    let browser = BrowserApp::new(HttpPolicy::default(), StubGateway { appearance_store: Some(store.clone()), reading_preferences_store: Some(reading), browser_fixture_accounts: true, ..StubGateway::default() });
    for (token, expected_style, source, details) in [
        ("a".repeat(64), "icons", false, true),
        ("b".repeat(64), "text_labels", true, false),
        ("a".repeat(64), "icons", false, true),
    ] {
        for hint in ["", "; osmap_presentation=v1.compact.large.stacked.0.0", "; osmap_presentation=v2.icons; presentation_style=icons; osmap_presentation_style=icons"] {
            for path in ["/compose", "/settings?section=appearance"] {
                let mut req = request("GET", path, &authenticated_headers(), "");
                req.headers.insert("cookie".into(), format!("osmap_session={token}{hint}"));
                let response = browser.handle_request(&req, "127.0.0.1");
                assert_eq!(response.response.status_code, 200, "{path}");
                let html = body_text(&response);
                let root_tag = html.split_once("<head>").expect("application root").0;
                assert!(root_tag.contains(&format!(" data-presentation-style=\"{expected_style}\"")), "{path}: {root_tag}");
                assert_eq!(root_tag.matches("data-presentation-style=").count(), 1);
                assert!(html.contains(&format!("<body data-reading-source=\"{source}\" data-reading-attachment-details=\"{details}\">")));
            }
        }
    }
    assert_eq!(store.load_settings("alice@example.com").unwrap().presentation_style, PresentationStyle::Icons);
    assert_eq!(store.load_settings("bob@example.com").unwrap(), AppearanceSettings::default());
    fs::remove_dir_all(root).expect("owned fixture cleanup");
}

#[test]
fn presentation_style_unavailable_defaults_and_prelogin_downloads_are_unchanged() {
    let browser = app();
    let mut authenticated = request("GET", "/compose", &authenticated_headers(), "");
    authenticated.headers.insert("user-agent".into(), "OSMAP/AppearanceUnavailable".into());
    authenticated.headers.get_mut("cookie").unwrap().push_str("; osmap_presentation=v2.icons; presentation_style=icons");
    let response = browser.handle_request(&authenticated, "127.0.0.1");
    assert_eq!(response.response.status_code, 200);
    assert!(body_text(&response).split_once("<head>").unwrap().0.contains(" data-presentation-style=\"text_labels\""));

    for path in ["/login", "/compose"] {
        let req = request("GET", path, &[("Cookie", "osmap_presentation=v2.icons; presentation_style=icons")], "");
        let response = browser.handle_request(&req, "127.0.0.1");
        assert_eq!(response.response.status_code, if path == "/login" { 200 } else { 303 });
        assert!(!body_text(&response).split_once("<head>").unwrap().0.contains("data-presentation-style="));
    }
    let html = "<!doctype html><html lang=\"en\" data-appearance=\"system\"><head></head><body>synthetic download bytes</body></html>";
    for mut response in [
        crate::http_support::plain_text_response(200, "OK", html),
        HttpResponse::text(200, "OK", html).with_header("Content-Type", "text/html; charset=utf-8").with_header("Content-Disposition", "attachment; filename=fixture.html"),
    ] {
        let before = response.body.clone();
        browser.apply_reading_presentation(&mut response, &authenticated);
        assert_eq!(response.body, before);
    }
}

fn theme_request(value: &str) -> HttpRequest {
    request(
        "POST",
        "/settings/appearance",
        &authenticated_same_origin_headers(),
        &format!("csrf_token={CSRF}&appearance={value}"),
    )
}

#[test]
fn settings_search_is_bounded_escaped_and_never_searches_mail() {
    let result = app().handle_request(&request("GET", "/settings?q=font", &authenticated_headers(), ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    assert!(body_text(&result).contains("/settings?section=appearance#settings-font-size"));
    assert!(body_text(&result).contains("action=\"/settings\""));
    assert!(!body_text(&result).contains("action=\"/search\""));
    let result = app().handle_request(&request("GET", "/settings?q=%3Cscript%3E", &authenticated_headers(), ""), "127.0.0.1");
    assert!(body_text(&result).contains("&lt;script&gt;"));
    assert!(!body_text(&result).contains("<script>"));
    let result = app().handle_request(&request("GET", &format!("/settings?q={}", "x".repeat(129)), &authenticated_headers(), ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 400);
}

#[test]
fn settings_search_finds_existing_openpgp_composition_defaults() {
    let app = app();
    for (query, label, anchor, field) in [
        ("sign+outgoing", "Sign outgoing", "composition-signing", "pgp_sign"),
        ("encryption", "Encryption", "composition-encryption", "pgp_encrypt"),
        ("encrypt+to+self", "Encrypt to self", "composition-self", "pgp_self"),
        ("OPENPGP+SIGNING", "Sign outgoing", "composition-signing", "pgp_sign"),
    ] {
        let result = app.handle_request(&request("GET", &format!("/settings?q={query}"), &authenticated_headers(), ""), "127.0.0.1");
        assert_eq!(result.response.status_code, 200);
        let body = body_text(&result);
        assert!(body.contains(&format!("<a href=\"/settings?section=composition#{anchor}\">{label}</a>")), "missing existing control for {query}");
        assert!(!body.contains("No available settings match this search."));
        assert!(body.contains("action=\"/settings\""));
        assert!(!body.contains("action=\"/search\""));
        let destination = app.handle_request(&request("GET", "/settings?section=composition", &authenticated_headers(), ""), "127.0.0.1");
        assert_eq!(destination.response.status_code, 200);
        assert!(body_text(&destination).contains(&format!("id=\"{anchor}\" name=\"{field}\" form=\"composition-settings-form\">")), "search result must target an existing enabled setting");
    }
}

#[test]
fn settings_protection_search_requires_session_and_never_uses_mail_search() {
    let app = app_with_policy(HttpPolicy { search_worker_budget: 1, ..HttpPolicy::default() });
    let _held = app.request_budgets.search_workers.try_acquire().expect("hold the only mail search slot");
    let result = app.handle_request(&request("GET", "/settings?q=encryption", &authenticated_headers(), ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    assert!(body_text(&result).contains("/settings?section=composition#composition-encryption"));
    let mail_control = app.handle_request(&request("GET", "/search?q=encryption", &authenticated_headers(), ""), "127.0.0.1");
    assert_eq!(mail_control.response.status_code, 503);
    assert!(mail_control.audit_events.iter().any(|event| event.action == "request_budget_exhausted"));
    for headers in [vec![("User-Agent", "Firefox/Test")], vec![("User-Agent", "Firefox/Test"), ("Cookie", "osmap_session=invalid")]] {
        let result = app.handle_request(&request("GET", "/settings?q=encryption", &headers, ""), "127.0.0.1");
        assert_eq!(result.response.status_code, 303);
        assert_eq!(location_header(&result), "/login");
        assert!(!body_text(&result).contains("settings-search-results"));
    }
    let unmatched = app.handle_request(&request("GET", "/settings?q=quarterly+report", &authenticated_headers(), ""), "127.0.0.1");
    assert_eq!(unmatched.response.status_code, 200);
    assert!(body_text(&unmatched).contains("No available settings match this search."));
    assert!(!body_text(&unmatched).contains("/message?"));
}

#[test]
fn display_storage_failure_reports_unconfirmed_save_without_setting_cookies() {
    let mut req = request("POST", "/settings/display", &authenticated_same_origin_headers(), &format!("csrf_token={CSRF}&appearance=dark&density=compact&font_size=large&reader_layout=stacked&presentation_style=icons"));
    req.headers.insert("user-agent".into(), "OSMAP/AppearanceUnavailable".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("save could not be confirmed"));
    assert!(result.audit_events.iter().any(|event| event.action == "http_display_save_unconfirmed"));
    assert!(!result.response.headers.iter().any(|(name, _)| name == "Set-Cookie"));
}

fn has_theme_cookie(response: &HandledHttpResponse, choice: &str) -> bool {
    response.response.headers.iter().any(|(name, value)| {
        name == "Set-Cookie" && value.starts_with(&format!("osmap_appearance={choice};"))
    })
}

#[test]
fn appearance_write_uses_session_origin_csrf_and_exact_bounded_form() {
    for choice in ["light", "dark", "system"] {
        let result = app().handle_request(&theme_request(choice), "127.0.0.1");
        assert_eq!(result.response.status_code, 303);
        assert!(has_theme_cookie(&result, choice));
        assert!(body_text(&result).contains(&format!("data-appearance=\"{choice}\"")));
    }
    for (change, expected) in [
        ("no-session", 303),
        ("wrong-csrf", 403),
        ("no-origin", 403),
        ("cross-origin", 403),
        ("bad-content-type", 400),
        ("duplicate", 400),
        ("oversized", 400),
        ("extra-field", 400),
        ("unknown", 400),
    ] {
        let mut req = theme_request("dark");
        match change {
            "no-session" => {
                req.headers.remove("cookie");
            }
            "wrong-csrf" => {
                req.body = b"csrf_token=wrong&appearance=dark".to_vec();
            }
            "no-origin" => {
                req.headers.remove("origin");
            }
            "cross-origin" => {
                req.headers
                    .insert("origin".into(), "https://other.example.test".into());
            }
            "bad-content-type" => {
                req.headers
                    .insert("content-type".into(), "application/json".into());
            }
            "duplicate" => {
                req.body.extend_from_slice(b"&appearance=light");
            }
            "oversized" => {
                req.body = vec![b'x'; 513];
            }
            "extra-field" => {
                req.body.extend_from_slice(b"&unexpected=1");
            }
            "unknown" => {
                req = theme_request("%22%3Einvalid");
            }
            _ => unreachable!("closed test case list"),
        }
        let result = app().handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, expected, "{change}");
        assert!(!has_theme_cookie(&result, "dark"), "{change}");
        assert!(
            !result
                .audit_events
                .iter()
                .any(|event| event.action == "http_appearance_updated"),
            "{change}"
        );
    }
}

#[test]
fn appearance_cookie_covers_navigation_errors_logout_and_login_precedence() {
    for path in [
        "/login",
        "/",
        "/mailboxes",
        "/mailbox?name=INBOX",
        "/search",
        "/message?mailbox=INBOX&uid=9",
        "/compose",
        "/drafts",
        "/sessions",
        "/missing",
    ] {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers
            .get_mut("cookie")
            .expect("fixture cookie")
            .push_str("; osmap_appearance=dark");
        let result = app().handle_request(&req, "127.0.0.1");
        assert!(
            body_text(&result)
                .starts_with("<!doctype html><html lang=\"en\" data-appearance=\"dark\" "),
            "{path}"
        );
    }
    let mut logout = request(
        "POST",
        "/logout",
        &authenticated_same_origin_headers(),
        &format!("csrf_token={CSRF}"),
    );
    logout
        .headers
        .get_mut("cookie")
        .expect("fixture cookie")
        .push_str("; osmap_appearance=dark");
    let result = app().handle_request(&logout, "127.0.0.1");
    assert_eq!(result.response.status_code, 303);
    assert!(body_text(&result).contains("data-appearance=\"dark\""));
    let mut login = request(
        "POST",
        "/login",
        &[("Origin", "http://localhost")],
        "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456",
    );
    login
        .headers
        .insert("cookie".into(), "osmap_appearance=dark".into());
    let result = app().handle_request(&login, "127.0.0.1");
    assert_eq!(result.response.status_code, 303);
    assert!(has_theme_cookie(&result, "system"));
    assert!(body_text(&result).contains("data-appearance=\"system\""));
}

#[test]
fn appearance_settings_restore_saved_account_choice_and_explain_store_failure() {
    let mut req = request("GET", "/settings?section=appearance", &authenticated_headers(), "");
    req.headers
        .get_mut("cookie")
        .expect("fixture cookie")
        .push_str("; osmap_appearance=light");
    req.headers
        .insert("user-agent".into(), "OSMAP/AppearanceDark".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert!(has_theme_cookie(&result, "dark"));
    assert!(body_text(&result).contains("value=\"dark\" aria-label=\"Dark\" checked"));
    assert!(body_text(&result).contains("action=\"/settings/display\""));
    req.headers
        .insert("user-agent".into(), "OSMAP/AppearanceUnavailable".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    assert!(has_theme_cookie(&result, "system"));
    assert!(body_text(&result).contains("saved appearance could not be loaded"));
    let mut req = theme_request("dark");
    req.headers
        .insert("user-agent".into(), "OSMAP/AppearanceUnavailable".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 503);
    assert!(!has_theme_cookie(&result, "dark"));
    assert!(body_text(&result).contains("could not be confirmed"));
}

#[test]
fn appearance_runtime_store_survives_restart_and_isolates_accounts() {
    let root = temp_dir("appearance-runtime");
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "appearance-test",
        "127.0.0.1",
        "Synthetic/Test",
    )
    .expect("context");
    let session = StubGateway::validated_session();
    let runtime = RuntimeBrowserGateway::for_test(&root);
    assert_eq!(
        runtime
            .load_appearance(&context, &session)
            .expect("default"),
        AppearancePreference::System
    );
    runtime
        .update_appearance(&context, &session, AppearancePreference::Dark)
        .expect("persist");
    let reopened = RuntimeBrowserGateway::for_test(&root);
    assert_eq!(
        reopened
            .load_appearance(&context, &session)
            .expect("persisted"),
        AppearancePreference::Dark
    );
    let mut other = session.clone();
    other.record.canonical_username = "bob@example.test".into();
    assert_eq!(
        reopened
            .load_appearance(&context, &other)
            .expect("other account"),
        AppearancePreference::System
    );
    fs::remove_dir_all(root).expect("remove owned fixture");
}

#[test]
fn appearance_never_alters_plain_text_or_download_payloads() {
    use crate::http_support::{apply_appearance, plain_text_response};
    let mut html = html_response(200, "OK", "Synthetic", "<p>Sample</p>");
    let original = html.body.clone();
    let mut plain = plain_text_response(
        200,
        "OK",
        String::from_utf8(original.clone()).expect("fixture utf8"),
    );
    apply_appearance(&mut plain, Some("osmap_appearance=dark"));
    assert_eq!(plain.body, original);
    html = html.with_header("Content-Disposition", "attachment; filename=sample.html");
    apply_appearance(&mut html, Some("osmap_appearance=dark"));
    assert_eq!(html.body, original);
    for cookie in [
        "osmap_appearance=bad",
        "osmap_appearance=light; osmap_appearance=dark",
    ] {
        let mut response = html_response(400, "Bad Request", "Synthetic", "<p>Sample</p>");
        apply_appearance(&mut response, Some(cookie));
        assert!(String::from_utf8(response.body)
            .expect("fixture utf8")
            .contains("data-appearance=\"system\""));
    }
}
