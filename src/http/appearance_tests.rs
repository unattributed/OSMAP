use super::*;

const CSRF: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

#[test]
fn display_route_persists_one_snapshot_and_rejects_invalid_changes() {
    use crate::appearance::{AppearanceSettings, Density, FontSize, ReaderLayout};
    let root = temp_dir("display-preferences-route");
    let store = AppearanceStore::new(root.join("appearance"));
    let browser = BrowserApp::new(HttpPolicy::default(), StubGateway { appearance_store: Some(store.clone()), ..StubGateway::default() });
    let fields = format!("csrf_token={CSRF}&appearance=dark&density=compact&font_size=large&reader_layout=stacked");
    let post = |body: &str| request("POST", "/settings/display", &authenticated_same_origin_headers(), body);
    let result = browser.handle_request(&post(&fields), "127.0.0.1");
    assert_eq!(result.response.status_code, 303);
    let expected = AppearanceSettings { theme: AppearancePreference::Dark, density: Density::Compact, font_size: FontSize::Large, reader_layout: ReaderLayout::Stacked, show_avatars: false, message_preview: false };
    assert_eq!(store.load_settings("alice@example.com").expect("saved presentation"), expected);
    assert!(body_text(&result).contains("data-density=\"compact\""));
    assert!(body_text(&result).contains("data-show-avatars=\"false\""));
    for malformed in [
        fields.replace("compact", "enormous"),
        fields.replace("font_size=large&", ""),
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
    use crate::appearance::{AppearanceSettings, Density};
    let root = temp_dir("display-runtime");
    let context = AuthenticationContext::new(AuthenticationPolicy::default(), "display-test", "127.0.0.1", "Synthetic/Test").expect("context");
    let session = StubGateway::validated_session();
    let preferences = AppearanceSettings { density: Density::Compact, show_avatars: false, ..AppearanceSettings::default() };
    RuntimeBrowserGateway::for_test(&root).update_display(&context, &session, preferences).expect("persist preferences");
    assert_eq!(RuntimeBrowserGateway::for_test(&root).load_display(&context, &session).expect("reopen preferences"), preferences);
    fs::remove_dir_all(root).expect("owned fixture cleanup");
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
    let mut req = request("POST", "/settings/display", &authenticated_same_origin_headers(), &format!("csrf_token={CSRF}&appearance=dark&density=compact&font_size=large&reader_layout=stacked"));
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
        &[],
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
