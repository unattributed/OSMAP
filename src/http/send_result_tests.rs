use super::*;

#[test]
fn typed_openpgp_denials_keep_message_and_choices_without_dispatch() {
    for (recipient, expected_cause, expected_action) in [
        (
            "pgp-locked@example.test",
            "private OpenPGP key required for this message is locked",
            "ask the mail operator to unlock",
        ),
        (
            "pgp-blocked@example.test",
            "key or policy checks block the selected protection",
            "Review recipient addresses",
        ),
    ] {
        let mut app = app();
        app.gateway.browser_fixture_openpgp = true;
        app.gateway.browser_fixture_openpgp_denials = true;
        let compose = app.handle_request(
            &request("GET", "/compose", &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(compose.response.status_code, 200);
        let compose_html = body_text(&compose);
        let intent = super::send_journal_routes_tests::intent(&compose_html);
        assert!(compose_html.contains("name=\"pgp_binding_revision\" value=\"2\""));
        let csrf = StubGateway::validated_session().record.csrf_token;
        let message = "Protected draft text remains available";
        let fields = format!(
            "csrf_token={csrf}&send_intent={intent}&from=alice%40example.com&to={}&subject=Denied%20protected%20send&body={}&pgp_sign=on&pgp_encrypt=on&pgp_self=on&pgp_binding_revision=2",
            url_encode(recipient),
            url_encode(message),
        );
        let denied = app.handle_request(
            &request("POST", "/send", &authenticated_same_origin_headers(), &fields),
            "127.0.0.1",
        );
        assert_eq!(denied.response.status_code, 503);
        let html = body_text(&denied);
        assert!(html.contains(expected_cause));
        assert!(html.contains(expected_action));
        assert!(html.contains("Nothing was sent."));
        assert!(html.contains(&format!("name=\"to\" value=\"{recipient}\"")));
        assert!(html.contains("Denied protected send"));
        assert!(html.contains(message));
        for selected in ["pgp_sign", "pgp_encrypt", "pgp_self"] {
            assert!(html.contains(&format!("name=\"{selected}\" checked")));
        }
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
        let receipt = app.handle_request(
            &request(
                "GET",
                &format!("/compose?receipt={intent}"),
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(receipt.response.status_code, 404);
    }
}

#[test]
fn submission_receipts_distinguish_acceptance_copy_and_uncertain_dispatch() {
    for (agent, status, retained, wording) in [
        (
            "OSMAP/SendUnconfirmed",
            503,
            true,
            "Submission could not be confirmed",
        ),
        (
            "OSMAP/SentCopyUnconfirmed",
            200,
            true,
            "Sent-copy storage could not be confirmed",
        ),
        (
            "OSMAP/DraftCleanupFailure",
            200,
            true,
            "Removal of the saved draft could not be confirmed",
        ),
        ("Firefox/Test", 303, false, ""),
    ] {
        let mut app = app();
        let get = app.handle_request(
            &request("GET", "/compose", &authenticated_headers(), ""),
            "127.0.0.1",
        );
        let original = super::send_journal_routes_tests::intent(&body_text(&get));
        let csrf = StubGateway::validated_session().record.csrf_token;
        let source = "Synthetic source </textarea><script>never active</script>";
        let fields = format!("csrf_token={csrf}&send_intent={original}&to=bob%40example.com&bcc=hidden%40example.test&subject=Public%20fixture&body={}", url_encode(source));
        let saved = app.handle_request(
            &request(
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                &fields,
            ),
            "127.0.0.1",
        );
        assert_eq!(saved.response.status_code, 303);
        let location = location_header(&saved);
        let id = location
            .strip_prefix("/draft?id=")
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        if agent.contains("DraftCleanupFailure") {
            app.gateway.fail_draft_delete = Some(id.into());
        }
        let resume = app.handle_request(
            &request("GET", &location, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        let saved_intent = super::send_journal_routes_tests::intent(&body_text(&resume));
        let fields = fields.replace(&original, &saved_intent);
        let mut req = request(
            "POST",
            "/send",
            &authenticated_same_origin_headers(),
            &format!("{fields}&draft_id={id}&draft_revision=1"),
        );
        req.headers.insert("user-agent".into(), agent.into());
        let response = app.handle_request(&req, "127.0.0.1");
        assert_eq!(
            response.response.status_code,
            status,
            "{}",
            body_text(&response)
        );
        assert_eq!(app.gateway.submitted.lock().unwrap().len(), 1);
        assert_eq!(
            app.gateway.drafts.lock().unwrap().contains_key(id),
            retained
        );
        if retained {
            let html = body_text(&response);
            assert!(html.contains(wording));
            assert!(html.contains(escape_html(source).as_str()));
            assert!(html.contains("hidden@example.test"));
            assert!(!html.contains("action=\"/send\""));
            assert!(!html.contains("<script"));
            assert!(!html.contains("Nothing was sent"));
            assert!(!response
                .audit_events
                .iter()
                .any(|event| event.action == "stub_draft_delete"));
        } else {
            assert!(location_header(&response).starts_with("/compose?receipt="));
            let result = app.handle_request(
                &request(
                    "GET",
                    &location_header(&response),
                    &authenticated_headers(),
                    "",
                ),
                "127.0.0.1",
            );
            let html = body_text(&result);
            assert!(html.contains("Message submitted"));
            assert!(html.contains("Delivery to the recipient is not yet confirmed"));
            assert!(html.contains("href=\"/mailbox?name=Sent\""));
            assert!(!html.contains("This receipt is read-only"));
            assert!(!html.contains(escape_html(source).as_str()));
            assert!(!html.contains("Exact prepared attempt"));
            assert!(!html.contains("recovery_attachment="));
        }
    }
}
