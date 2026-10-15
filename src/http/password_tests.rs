use super::*;

#[test]
fn password_unicode_scalar_boundary_matches_html_utf16_cap_without_secret_reads() {
    let valid = "🦊".repeat(128);
    let invalid = "🦊".repeat(129);
    assert_eq!(valid.len(), 512);
    assert_eq!(valid.chars().count(), 128);
    assert_eq!(valid.encode_utf16().count(), 256);
    assert!(crate::password_change::Request::new(
        "Current-public-password", &valid, &valid, "123456"
    ).is_ok());
    assert!(matches!(crate::password_change::Request::new(
        "Current-public-password", &invalid, &invalid, "123456"
    ), Err(crate::password_change::Error::Invalid)));

    let app = password_app(BrowserPasswordDecision::KnownRefused);
    let page = app.handle_request(&request("GET", "/settings/password",
        &authenticated_same_origin_headers(), ""), "127.0.0.1");
    let html = body_text(&page);
    for name in ["new_password", "confirmation"] {
        assert!(html.contains(&format!("name=\"{name}\" type=\"password\" autocomplete=\"new-password\" maxlength=\"256\"")));
    }
    for (value, expected_status, calls) in [(&valid, 409, 1), (&invalid, 400, 1)] {
        let body = password_form().replace("New-public-password", &url_encode(value));
        let result = app.handle_request(&password_request(&body), "127.0.0.1");
        assert_eq!(result.response.status_code, expected_status);
        assert_eq!(app.gateway.password_calls.lock().unwrap().len(), calls);
        assert!(!body_text(&result).contains("🦊"));
    }
}

fn password_form() -> String {
    format!("csrf_token={}&current_password=Current-public-password&new_password=New-public-password&confirmation=New-public-password&totp_code=123456", url_encode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"))
}
fn password_request(body: &str) -> HttpRequest {
    let mut request = request("POST", "/settings/password", &authenticated_same_origin_headers(), body);
    request.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
    request
}
fn password_app(decision: BrowserPasswordDecision) -> BrowserApp<StubGateway> {
    BrowserApp::new(HttpPolicy::default(), StubGateway { password_result: Some(decision), ..StubGateway::default() })
}
fn assert_no_password_echo(response: &HandledHttpResponse) {
    let output = format!("{} {:?}", body_text(response), response.audit_events);
    for secret in ["Current-public-password", "New-public-password", "123456"] {
        assert!(!output.contains(secret), "secret echoed in response/audit");
    }
}

#[test]
fn password_route_unavailable_and_field_security_refuse_without_dispatch() {
    let unavailable = app();
    let get = unavailable.handle_request(&request("GET", "/settings/password", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(get.response.status_code, 503);
    assert!(body_text(&get).contains("<fieldset disabled>"));
    assert_eq!(unavailable.handle_request(&password_request(&password_form()), "127.0.0.1").response.status_code, 503);
    assert!(unavailable.gateway.password_calls.lock().unwrap().is_empty());

    let enabled = password_app(BrowserPasswordDecision::Changed);
    for body in [
        password_form().replace("fedcba9876543210", "wrong"),
        password_form().replace("confirmation=New-public-password", "confirmation=different"),
        format!("{}&account=bob%40example.com", password_form()),
        format!("{}&current_password=duplicate", password_form()),
    ] {
        let result = enabled.handle_request(&password_request(&body), "127.0.0.1");
        assert!(matches!(result.response.status_code, 400 | 403));
        assert_no_password_echo(&result);
    }
    let mut foreign = password_request(&password_form());
    foreign.headers.insert("origin".into(), "https://foreign.example".into());
    assert_eq!(enabled.handle_request(&foreign, "127.0.0.1").response.status_code, 403);
    let mut absent = password_request(&password_form());
    absent.headers.remove("cookie");
    assert_eq!(enabled.handle_request(&absent, "127.0.0.1").response.status_code, 303);
    assert!(enabled.gateway.password_calls.lock().unwrap().is_empty());
}

#[test]
fn password_route_result_classes_clear_cookie_only_for_changed_or_uncertain() {
    for (decision, status, clear, text) in [
        (BrowserPasswordDecision::Changed, 200, true, "password was changed"),
        (BrowserPasswordDecision::Unconfirmed, 503, true, "Do not repeat"),
        (BrowserPasswordDecision::KnownRefused, 409, false, "No password change was made"),
        (BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Authentication), 403, false, "No change was submitted"),
        (BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Throttled), 429, false, "temporarily limited"),
    ] {
        let app = password_app(decision);
        let result = app.handle_request(&password_request(&password_form()), "127.0.0.1");
        assert_eq!(result.response.status_code, status);
        assert!(body_text(&result).contains(text));
        assert_eq!(result.response.headers.iter().any(|(k,v)| k == "Set-Cookie" && v.contains("Max-Age=0")), clear);
        assert_eq!(app.gateway.password_calls.lock().unwrap().len(), 1);
        assert_no_password_echo(&result);
        if clear { assert!(!body_text(&result).contains("password-change-form")); }
    }
}

#[test]
fn password_page_uses_exact_script_csp_and_independent_empty_fields() {
    let app = password_app(BrowserPasswordDecision::Changed);
    let result = app.handle_request(&request("GET", "/settings/password", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    let html = body_text(&result);
    for name in ["current_password", "new_password", "confirmation"] {
        assert!(html.contains(&format!("id=\"{name}\" name=\"{name}\" type=\"password\"")));
        assert!(html.contains(&format!("aria-controls=\"{name}\"")));
    }
    assert!(html.contains("href=\"/settings?section=security\">Cancel"));
    let csp = result.response.headers.iter().find(|(k,_)| k == "Content-Security-Policy").unwrap().1.clone();
    assert!(csp.contains("script-src 'sha256-"));
    assert!(csp.contains("script-src-attr 'none'; connect-src 'none'"));
    assert!(!csp.contains("script-src 'self'") && !csp.contains("script-src 'unsafe-inline'"));
    let settings = app.handle_request(&request("GET", "/settings?section=security", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert!(body_text(&settings).contains("href=\"/settings/password\""));
    assert!(!body_text(&settings).contains("Password and recovery changes remain unavailable here."));
    // The source gate independently verifies the exact script bytes/hash and
    // rejects changed-hash network/secret-read/CSP broadening controls.
}

#[test]
fn password_runtime_trait_delegates_to_unqualified_owned_capability_without_state_creation() {
    use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
    let root = temp_dir("password-runtime-trait");
    let service = SessionService::new(FileSessionStore::new(root.join("sessions")), crate::totp::SystemTimeProvider, SystemRandomSource, 3600, 1800);
    let context = AuthenticationContext { request_id:"public-password".into(), remote_addr:"127.0.0.1".into(), user_agent:"public fixture".into() };
    let issued = service.issue(&context, "alice@example.test", RequiredSecondFactor::Totp).unwrap();
    let session = service.validate(&context, &issued.token).unwrap();
    let gateway = RuntimeBrowserGateway::for_test(&root);
    assert!(!BrowserGateway::password_change_available(&gateway, &session));
    let action = crate::password_change::Request::new("Current-public-password", "New-public-password", "New-public-password", "123456").unwrap();
    let result = BrowserGateway::change_own_password(&gateway, &context, &session, &issued.token, action, std::time::Instant::now()+std::time::Duration::from_secs(60));
    assert_eq!(result.decision, BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Unavailable));
    assert!(!root.join("settings/password-stepup-rate").exists());
    std::fs::remove_dir_all(root).unwrap();
}
