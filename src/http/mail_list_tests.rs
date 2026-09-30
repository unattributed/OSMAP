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
    assert!(body.contains("aria-current=\"true\">Message 007"));
    let other =
        mailbox_page("/mailbox?name=Sent&filter=starred&selected_mailbox=INBOX&selected_uid=7");
    assert!(!body_text(&other).contains("data-selected=\"true\""));
    for bad in [
        "filter=unknown",
        "page=0",
        "page=41",
        "page=-1",
        "selected_uid=1",
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
