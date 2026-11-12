// HTTP boundary checks using the existing unavailable-by-default gateway.
use super::*;
fn perform(method: &str, path: &str, body: &str) -> HandledHttpResponse {
    BrowserApp::new(HttpPolicy::default(), StubGateway::default()).handle_request(
        &request(method, path, &authenticated_same_origin_headers(), body),
        "127.0.0.1",
    )
}
fn form() -> String {
    format!(
        "csrf_token={}&draft=0123456789abcdef0123456789abcdef&revision=1&timezone_offset=UTC&due_at={}",
        StubGateway::validated_session().record.csrf_token,
        &crate::logging::format_unix_timestamp_utc(
            crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider) + 3600
        )[..16]
    )
}
#[test]
fn scheduled_unavailable_is_not_an_empty_successful_list() {
    let result = perform("GET", "/scheduled", "");
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("could not be loaded"));
    assert!(!body_text(&result).contains("No scheduled messages."));
}
#[test]
fn scheduled_mutation_requires_current_csrf_and_same_origin() {
    let body = form();
    assert_eq!(
        perform(
            "POST",
            "/scheduled/create",
            &body.replace(&StubGateway::validated_session().record.csrf_token, "wrong")
        )
        .response
        .status_code,
        403
    );
    let mut req = request(
        "POST",
        "/scheduled/create",
        &authenticated_same_origin_headers(),
        &body,
    );
    req.headers
        .insert("origin".into(), "https://other.invalid".into());
    assert_eq!(
        BrowserApp::new(HttpPolicy::default(), StubGateway::default())
            .handle_request(&req, "127.0.0.1")
            .response
            .status_code,
        403
    );
    assert_eq!(
        perform("POST", "/scheduled/create", &body)
            .response
            .status_code,
        503
    );
}
#[test]
fn scheduled_routes_reject_extra_fields_noncanonical_revision_and_unknown_actions() {
    let body = form();
    for bad in [
        format!("{body}&unexpected=1"),
        body.replace("revision=1", "revision=01"),
        body.replace("revision=1", "revision=18446744073709551616"),
        body.replace("draft=0123456789abcdef0123456789abcdef", "draft=../foreign"),
    ] {
        assert_eq!(
            perform("POST", "/scheduled/create", &bad)
                .response
                .status_code,
            400
        );
    }
    assert_eq!(
        perform("GET", "/scheduled?id=../foreign", "")
            .response
            .status_code,
        400
    );
    assert_eq!(
        perform(
            "GET",
            "/scheduled/new?draft=0123456789abcdef0123456789abcdef&revision=01",
            ""
        )
        .response
        .status_code,
        400
    );
    let action = format!(
        "csrf_token={}&id=0123456789abcdef0123456789abcdef&revision=1&action=retry",
        StubGateway::validated_session().record.csrf_token
    );
    assert_eq!(
        perform("POST", "/scheduled/change", &action)
            .response
            .status_code,
        400
    );
}

#[test]
fn scheduled_http_uses_current_owned_timezone_and_rejects_stale_form_without_dispatch() {
    let root = std::env::temp_dir().join(format!("osmap-scheduled-timezone-{}", crate::draft::generate_draft_id().unwrap()));
    let store = crate::timezone::Store::new(&root);
    let account = StubGateway::validated_session().record.canonical_username;
    let east = crate::timezone::FixedOffset::parse("+07:00").unwrap();
    let preference = store.save(&account, 0, east).unwrap();
    let due = ((crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider) + 600) / 60) * 60;
    let capture = Arc::new(Mutex::new(None));
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway { timezone_store: Some(store.clone()), scheduled_due_capture: Some(capture.clone()), ..StubGateway::default() });
    let body = format!("csrf_token={}&draft={}&revision=1&timezone_offset=%2B07%3A00&due_at={}", StubGateway::validated_session().record.csrf_token, "a".repeat(32), east.schedule_input(due).unwrap());
    let submit = |body: &str| app.handle_request(&request("POST", "/scheduled/create", &authenticated_same_origin_headers(), body), "127.0.0.1");
    assert_eq!(submit(&body).response.status_code, 303);
    assert_eq!(*capture.lock().unwrap(), Some(due));
    *capture.lock().unwrap() = None;
    assert_eq!(submit(&body.replace("%2B07%3A00", "UTC")).response.status_code, 409);
    assert_eq!(*capture.lock().unwrap(), None);
    store.save(&account, preference.revision, crate::timezone::FixedOffset::parse("-05:00").unwrap()).unwrap();
    assert_eq!(submit(&body).response.status_code, 409);
    assert_eq!(*capture.lock().unwrap(), None);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn outbox_alias_and_mutations_preserve_http_security_boundaries() {
    let result = perform("GET", "/outbox", "");
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("could not be loaded"));
    for action in ["send_now", "move_to_drafts", "delete"] {
        let body = format!("csrf_token={}&id={}&revision=1&action={action}", StubGateway::validated_session().record.csrf_token, "a".repeat(32));
        assert_eq!(perform("POST", "/scheduled/change", &body).response.status_code, 503);
        assert_eq!(perform("POST", "/scheduled/change", &body.replace("revision=1", "revision=01")).response.status_code, 400);
        assert_eq!(perform("POST", "/scheduled/change", &body.replace(&StubGateway::validated_session().record.csrf_token, "wrong")).response.status_code, 403);
        let mut req = request("POST", "/scheduled/change", &authenticated_same_origin_headers(), &body);
        req.headers.insert("origin".into(), "https://other.invalid".into());
        assert_eq!(BrowserApp::new(HttpPolicy::default(), StubGateway::default()).handle_request(&req, "127.0.0.1").response.status_code, 403);
    }
}
