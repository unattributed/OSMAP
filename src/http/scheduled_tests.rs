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
        "csrf_token={}&draft=0123456789abcdef0123456789abcdef&revision=1&due_at={}",
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
