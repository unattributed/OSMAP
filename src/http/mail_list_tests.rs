use super::*;

#[test]
fn compact_rows_keep_untrusted_headers_as_text_and_actions_outside_links() {
    let mut request = request("GET", "/mailbox?name=INBOX", &authenticated_headers(), "");
    request
        .headers
        .insert("user-agent".into(), "OSMAP/ManyMessages;LongHeaders".into());
    let response = app().handle_request(&request, "127.0.0.1");
    assert_eq!(response.response.status_code, 200);
    let body = body_text(&response);
    assert!(body.contains("&lt;b&gt;Synthetic header&lt;/b&gt;"));
    assert!(!body.contains("<b>Synthetic header</b>"));
    assert!(body.contains("&lt;b&gt;Untrusted synthetic preview&lt;/b&gt;"));
    assert!(!body.contains("<b>Untrusted synthetic preview</b>"));
    assert!(body.contains("No preview available"));
    assert!(body.contains("Initials from the sender header"));
    assert!(body.contains("role=\"list\" class=\"message-cards\""));
    assert_eq!(body.matches("class=\"message-row message-card").count(), 50);
    assert!(!body.contains("<table"));
    assert!(body.contains("aria-label=\"More for message #125 in INBOX\""));
}

fn mailbox_page(path: &str) -> HandledHttpResponse {
    let mut request = request("GET", path, &authenticated_headers(), "");
    request
        .headers
        .insert("user-agent".into(), "OSMAP/ManyMessages".into());
    app().handle_request(&request, "127.0.0.1")
}

#[test]
fn coordinated_reader_binds_fresh_filtered_identity_and_releases_its_budget() {
    let app = app_with_policy(HttpPolicy { mailbox_worker_budget: 1, ..HttpPolicy::default() });
    let path = "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=7&filter=starred";
    let mut req = request("GET", path, &authenticated_headers(), "");
    req.headers.insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let response = app.handle_request(&req, "127.0.0.1");
    assert_eq!(response.response.status_code, 200);
    let body = body_text(&response);
    assert!(body.contains("Synthetic message 7 in INBOX for alice@example.com."));
    assert!(body.contains("data-selected=\"true\""));
    assert_eq!(body.matches("<main ").count(), 1);
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    for fault in ["ReaderStale", "ReaderWrongAccount", "ReaderWrongMailbox", "ReaderWrongUid", "ReaderUnavailable"] {
        req.headers.insert("user-agent".into(), format!("OSMAP/ManyMessages;{fault}"));
        let response = app.handle_request(&req, "127.0.0.1");
        let body = body_text(&response);
        assert!(body.contains("Message unavailable"), "{fault}");
        assert!(!body.contains("<pre>Synthetic message"), "{fault}");
        assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    }
    req.headers.insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let occupied = app.request_budgets.mailbox_workers.try_acquire().expect("test budget");
    let response = app.handle_request(&req, "127.0.0.1");
    assert!(body_text(&response).contains("The reading pane is busy"));
    assert!(!body_text(&response).contains("<pre>Synthetic message"));
    drop(occupied);
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    req.headers.remove("cookie");
    let response = app.handle_request(&req, "127.0.0.1");
    assert_eq!(response.response.status_code, 303);
    assert!(!body_text(&response).contains("<pre>Synthetic message"));
}

#[test]
fn coordinated_reader_excludes_other_folders_and_filter_misses_but_keeps_off_page_selection() {
    for path in [
        "/mailbox?name=Sent&selected_mailbox=INBOX&selected_uid=7",
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=8&filter=unread",
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=126",
    ] {
        let response = mailbox_page(path);
        let body = body_text(&response);
        assert!(body.contains("no longer in these results"));
        assert!(!body.contains("<pre>Synthetic message"));
        assert!(!response.audit_events.iter().any(|event| event.action == "stub_message_view"));
    }
    let body = body_text(&mailbox_page("/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=7"));
    assert!(body.contains("Synthetic message 7 in INBOX for alice@example.com."));
    assert!(body.contains("Locate selected message on page 3"));
    assert!(!body.contains("data-selected=\"true\""));
}

#[test]
fn native_list_filters_and_page_links_preserve_sort() {
    let response = mailbox_page("/mailbox?name=INBOX&page=2&filter=unread&sort=subject&dir=asc");
    assert_eq!(response.response.status_code, 200);
    let body = body_text(&response);
    assert_eq!(body.matches("class=\"message-row").count(), 13);
    assert!(body.contains("Message 101"));
    assert!(!body.contains("Message 100"));
    assert!(body.contains("Showing 51–63 of 63 messages · Page 2 of 2"));
    assert!(body.contains("/mailbox?name=INBOX&amp;sort=subject&amp;dir=asc&amp;filter=unread"));
    assert!(body.contains("Sorted by Subject ascending"));
}

#[test]
fn selection_is_a_mailbox_and_uid_pair_and_invalid_state_is_bounded() {
    let selected =
        mailbox_page("/mailbox?name=INBOX&filter=starred&selected_mailbox=INBOX&selected_uid=7");
    let body = body_text(&selected);
    assert!(body.contains("data-selected=\"true\""));
    assert!(body.contains("aria-current=\"true\" dir=\"auto\">Message 007"));
    let other =
        mailbox_page("/mailbox?name=Sent&filter=starred&selected_mailbox=INBOX&selected_uid=7");
    assert!(!body_text(&other).contains("data-selected=\"true\""));
    for bad in [
        "filter=unknown",
        "page=0",
        "page=41",
        "page=-1",
        "selected_uid=1",
        "select=everything",
    ] {
        assert_eq!(
            mailbox_page(&format!("/mailbox?name=INBOX&{bad}"))
                .response
                .status_code,
            400
        );
        assert_eq!(
            authenticated_get(&format!("/search?q=report&{bad}"))
                .response
                .status_code,
            400
        );
    }
}

#[test]
fn bulk_selection_is_bounded_to_the_current_page_and_one_action() {
    for action in ["move", "archive"] {
        let response = mailbox_page(&format!("/mailbox?name=INBOX&page=2&select={action}"));
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert_eq!(body.matches(" checked").count(), crate::mail_list::MAX_BULK_SELECTION);
        assert!(body.contains("Select first 10 on this page"));
        assert!(body.contains("Clear selection"));
    }
    assert!(!body_text(&mailbox_page("/mailbox?name=INBOX&page=2&select=none")).contains(" checked"));
}

#[test]
fn global_search_uses_existing_routes_and_settings_omits_it() {
    let body = body_text(&mailbox_page("/mailbox?name=INBOX"));
    assert!(body.contains("class=\"global-search-menu\""));
    assert!(body.contains("aria-label=\"Mail shortcuts\""));
    assert!(body.contains("accesskey=\"s\""));
    assert!(body.contains("Search all mail"));
    assert!(!body_text(&authenticated_get("/settings")).contains("class=\"global-search-menu\""));
}

#[test]
fn stale_page_is_adjusted_and_search_filter_uses_actual_flags() {
    let adjusted = mailbox_page("/mailbox?name=INBOX&page=40&filter=starred");
    let body = body_text(&adjusted);
    assert!(body.contains("requested page is outside the current results"));
    assert_eq!(body.matches("class=\"message-row").count(), 17);
    let result = authenticated_get("/search?q=searchsort&scope=all&field=from&filter=starred");
    let body = body_text(&result);
    assert!(body.contains("Search Zulu"));
    assert!(!body.contains("Search Middle"));
    assert!(!body.contains("Search Alpha"));
    assert!(body.contains(
        "scope=all&amp;q=searchsort&amp;field=from&amp;sort=subject&amp;dir=asc&amp;filter=starred"
    ));
    assert!(body.contains("aria-label=\"Starred\""));
}

#[test]
fn attachment_filter_http_preserves_search_reader_and_rejects_bad_values() {
    for path in ["/mailbox?name=INBOX&attachment=with&filter=unread&selected_mailbox=INBOX&selected_uid=123", "/search?q=reader-fixture&scope=all&field=subject&attachment=with&filter=unread&selected_mailbox=INBOX&selected_uid=123"] {
        let mut req=request("GET",path,&authenticated_headers(),"");
        req.headers.insert("user-agent".into(),"OSMAP/ManyMessages;AttachmentFilter".into());
        let response=app().handle_request(&req,"127.0.0.1");assert_eq!(response.response.status_code,200);
        let body=body_text(&response);assert!(body.contains("attachment=with"));assert!(body.contains("name=\"attachment\" value=\"with\""));assert!(body.contains("Back to list"));assert!(body.contains("Synthetic message 123"));
        if path.starts_with("/search") { assert!(body.contains("field=subject"));assert!(body.contains("scope=all")); }
    }
    assert_eq!(mailbox_page("/mailbox?name=INBOX&attachment=invalid").response.status_code,400);
}
