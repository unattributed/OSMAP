use super::*;

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
            assert!(body_text(&result).contains("accepted for submission"));
            assert!(body_text(&result).contains("Delivery is not confirmed"));
        }
    }
}
