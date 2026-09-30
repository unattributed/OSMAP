// Included only by http.rs's #[cfg(test)] module; these test UI copy, not handlers.
use super::*;

#[test]
fn fragment_errors_have_one_main_heading_and_return_navigation_in_the_active_theme() {
    for (path, status, heading) in [
        ("/missing", 404, "Not Found"),
        ("/search", 400, "Invalid Search Request"),
        (
            "/attachment?mailbox=INBOX&uid=9&part=1.99",
            404,
            "Attachment Not Found",
        ),
    ] {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers
            .get_mut("cookie")
            .expect("fixture cookie")
            .push_str("; osmap_appearance=dark");
        let result = app().handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, status);
        let body = body_text(&result);
        assert_eq!(body.matches("<main ").count(), 1, "{path}");
        assert_eq!(body.matches("<h1").count(), 1, "{path}");
        assert!(body.contains(heading), "{path}");
        if path.starts_with("/attachment") {
            assert!(
                body.contains("Back to message")
                    && body.contains("/message?mailbox=INBOX&amp;uid=9")
            );
        } else {
            assert!(body.contains("Return to mail"));
        }
        assert!(body.contains("data-appearance=\"dark\""));
    }
}

#[test]
fn compact_security_states_do_not_claim_undelivered_capabilities() {
    let reader = body_text(&authenticated_get("/message?mailbox=INBOX&uid=9"));
    assert!(reader.contains("View source") && reader.contains("view=source"));
    let mut legacy = request(
        "GET",
        "/message?mailbox=INBOX&uid=9",
        &authenticated_headers(),
        "",
    );
    legacy
        .headers
        .insert("user-agent".into(), "OSMAP/LegacyMetadata".into());
    assert!(
        body_text(&app().handle_request(&legacy, "127.0.0.1")).contains("Source view unavailable")
    );
    assert!(!reader.contains("Source view escaped"));
    assert!(reader.contains("Decrypted on mail host</dt><dd>not produced"));
    assert!(!reader.contains("Decrypted locally"));
    assert!(reader.contains("<details class=\"openpgp-reader-states\""));
    assert!(reader.contains("data-protected-body-panel=\"true\""));
    let compose = body_text(&authenticated_get("/compose"));
    assert!(compose.contains("This message will be sent without OpenPGP protection."));
    assert!(!compose.contains("name=\"openpgp"));
    assert!(compose.contains("Send Message and Save Draft use unencrypted message content"));
    let settings = body_text(&authenticated_get("/settings"));
    assert!(!settings.contains("action=\"/search\""));
    assert!(settings.contains("aria-label=\"Design principles\""));
    assert!(!settings.to_ascii_lowercase().contains("zero-knowledge"));
    assert!(!settings.contains("name=\"openpgp"));
    assert!(settings.contains("Signing and encryption are currently unavailable"));
}
