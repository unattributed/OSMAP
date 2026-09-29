use super::*;

const CSRF: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn theme_request(value: &str) -> HttpRequest {
    request(
        "POST",
        "/settings/appearance",
        &authenticated_same_origin_headers(),
        &format!("csrf_token={CSRF}&appearance={value}"),
    )
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
                .starts_with("<!doctype html><html lang=\"en\" data-appearance=\"dark\">"),
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
    let mut req = request("GET", "/settings", &authenticated_headers(), "");
    req.headers
        .get_mut("cookie")
        .expect("fixture cookie")
        .push_str("; osmap_appearance=light");
    req.headers
        .insert("user-agent".into(), "OSMAP/AppearanceDark".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert!(has_theme_cookie(&result, "dark"));
    assert!(body_text(&result).contains("value=\"dark\" checked"));
    assert!(body_text(&result).contains("action=\"/settings/appearance\""));
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
    assert!(body_text(&result).contains("could not be saved"));
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
