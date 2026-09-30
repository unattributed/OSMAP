use super::*;
use crate::http::compose_enhancement::{csp, SCRIPT};

#[test]
fn composer_hash_allowance_never_reaches_reader_auth_or_other_pages() {
    for route in [
        "/login",
        "/settings",
        "/sessions",
        "/drafts",
        "/mailbox?name=INBOX",
        "/message?mailbox=INBOX&uid=9",
    ] {
        let result = authenticated_get(route);
        assert!(!body_text(&result).contains("<script"), "{route}");
        assert!(
            result
                .response
                .headers
                .iter()
                .any(|(name, value)| name == "Content-Security-Policy"
                    && value == crate::http_support::browser_csp()),
            "{route}"
        );
    }
    let result = authenticated_get("/compose");
    let body = body_text(&result);
    assert_eq!(body.matches("<script").count(), 1);
    assert!(body.contains(SCRIPT));
    assert!(result
        .response
        .headers
        .iter()
        .any(|(name, value)| name == "Content-Security-Policy" && value == &csp()));
    assert!(!csp().contains("connect-src"));
    assert!(!csp().contains("script-src 'self'"));
}

#[test]
fn retained_author_text_cannot_escape_into_the_allowed_script() {
    let text = "</textarea><script id=unapproved>window.unapproved=true</script><img src=https://invalid.example/test>";
    let form = format!(
        "csrf_token={}&to=invalid&body={}",
        StubGateway::validated_session().record.csrf_token,
        url_encode(text)
    );
    let result = app().handle_request(
        &request("POST", "/send", &authenticated_same_origin_headers(), &form),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 400);
    let body = body_text(&result);
    assert_eq!(body.matches("<script").count(), 1);
    assert!(body.contains(SCRIPT));
    assert!(body.contains(&escape_html(text).to_string()));
    assert!(!body.contains("<script id=unapproved>"));
    assert!(body.contains("data-save-state=\"unsaved\""));
}
