use super::*;
fn home(app: &BrowserApp<StubGateway>, agent: &str) -> HandledHttpResponse {
    let mut req = request("GET", "/mailboxes", &authenticated_headers(), "");
    req.headers.insert("user-agent".into(), agent.into());
    app.handle_request(&req, "127.0.0.1")
}
#[test]
fn welcome_data_projects_only_owned_bounded_summaries_without_mutation() {
    let app = app();
    let result = home(&app, "WelcomeData/rows");
    let html = body_text(&result);
    assert_eq!(result.response.status_code, 200);
    assert_eq!(html.matches("class=\"welcome-recent-link").count(), 5);
    assert!(html.find("Actual 8").unwrap() < html.find("Actual 7").unwrap());
    assert!(!html.contains("Actual 3"));
    assert!(
        html.contains("Actual 8 &lt;inert&gt;")
            && html.contains("Sender &amp; &lt;sender@example.test&gt;")
    );
    assert!(
        html.contains("Unread · loaded Inbox: 4")
            && html.contains("Flagged · loaded Inbox: 4")
            && html.contains("Saved drafts: 0")
    );
    assert!(
        html.contains("/message?mailbox=INBOX&amp;uid=8") && html.contains("Browse your mailboxes")
    );
    assert_eq!(
        result
            .audit_events
            .iter()
            .filter(|event| event.action == "welcome_fixture_summary_list")
            .count(),
        1
    );
    assert_eq!(
        result
            .audit_events
            .iter()
            .filter(|event| event.action == "stub_draft_list")
            .count(),
        1
    );
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert!(app.gateway.message_flags.lock().unwrap().is_empty());
    for marker in [
        "wrong-row",
        "duplicate",
        "wrong-owner",
        "wrong-mailbox",
        "failure",
    ] {
        let failed = home(&app, &format!("WelcomeData/{marker}"));
        assert_eq!(failed.response.status_code, 200);
        let html = body_text(&failed);
        assert!(!html.contains("Actual "));
        assert!(
            html.contains("Inbox summaries are unavailable") && html.contains("Saved drafts: 0")
        );
    }
    assert_eq!(home(&app, "WelcomeWrongAccount").response.status_code, 503);
}
#[test]
fn welcome_data_handles_empty_missing_and_independent_draft_failure() {
    let app = app();
    let empty = body_text(&home(&app, "WelcomeData/empty"));
    assert!(
        empty.contains("Unread · loaded Inbox: 0") && empty.contains("No messages were returned")
    );
    let missing = home(&app, "WelcomeMissing");
    assert!(
        body_text(&missing).contains("Inbox is unavailable")
            && body_text(&missing).contains("Saved drafts: 0")
    );
    assert!(!missing
        .audit_events
        .iter()
        .any(|event| event.action == "stub_messages"));
    for agent in ["WelcomeDraftFailure", "WelcomeDraftWrongOwner"] {
        let html = body_text(&home(&app, agent));
        assert!(
            html.contains("Saved drafts: Unknown") && html.contains("class=\"welcome-recent-link")
        );
    }
}
#[test]
fn welcome_data_counts_actual_saved_drafts_when_inbox_worker_is_busy() {
    let app = app();
    let fields = format!(
        "csrf_token={}&to=bob%40example.com&subject=Saved&body=Public",
        StubGateway::validated_session().record.csrf_token
    );
    let saved = app.handle_request(
        &native_compose_request(
            &app,
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &fields,
        ),
        "127.0.0.1",
    );
    assert_eq!(saved.response.status_code, 303);
    let mut guards = Vec::new();
    while let Some(guard) = app.request_budgets.mailbox_workers.try_acquire() {
        guards.push(guard);
    }
    let result = home(&app, "WelcomeData/rows");
    let html = body_text(&result);
    assert_eq!(result.response.status_code, 200);
    assert!(html.contains("Saved drafts: 1") && html.contains("Inbox summaries are unavailable"));
    assert!(!result
        .audit_events
        .iter()
        .any(|event| event.action == "welcome_fixture_summary_list"));
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert!(app.gateway.message_flags.lock().unwrap().is_empty());
}
