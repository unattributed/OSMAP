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
    let app = app_with_policy(HttpPolicy {
        mailbox_worker_budget: 1,
        ..HttpPolicy::default()
    });
    let path = "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=7&filter=starred";
    let mut req = request("GET", path, &authenticated_headers(), "");
    req.headers
        .insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let response = app.handle_request(&req, "127.0.0.1");
    assert_eq!(response.response.status_code, 200);
    let body = body_text(&response);
    assert!(body.contains("Synthetic message 7 in INBOX for alice@example.com."));
    assert!(body.contains("data-selected=\"true\""));
    assert_eq!(body.matches("<main ").count(), 1);
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    for fault in [
        "ReaderStale",
        "ReaderWrongAccount",
        "ReaderWrongMailbox",
        "ReaderWrongUid",
        "ReaderUnavailable",
    ] {
        req.headers
            .insert("user-agent".into(), format!("OSMAP/ManyMessages;{fault}"));
        let response = app.handle_request(&req, "127.0.0.1");
        let body = body_text(&response);
        assert!(body.contains("Message unavailable"), "{fault}");
        assert!(!body.contains("<pre>Synthetic message"), "{fault}");
        assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    }
    req.headers
        .insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let occupied = app
        .request_budgets
        .mailbox_workers
        .try_acquire()
        .expect("test budget");
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
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_message_view"));
    }
    let body = body_text(&mailbox_page(
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=7",
    ));
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
        assert_eq!(
            body.matches(" checked").count(),
            crate::mail_list::MAX_BULK_SELECTION
        );
        assert!(body.contains("Select first 10 on this page"));
        assert!(body.contains("Clear selection"));
    }
    assert!(
        !body_text(&mailbox_page("/mailbox?name=INBOX&page=2&select=none")).contains(" checked")
    );
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
    assert_eq!(
        mailbox_page("/mailbox?name=INBOX&attachment=invalid")
            .response
            .status_code,
        400
    );
}

#[test]
fn sent_recipient_rows_escape_headers_and_inbox_search_keep_sender() {
    for (path, sent) in [
        ("/mailbox?name=Sent", true),
        ("/mailbox?name=INBOX", false),
        ("/search?q=reader-fixture&scope=all", false),
    ] {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers.insert(
            "user-agent".into(),
            "OSMAP/ManyMessages;SentRecipients".into(),
        );
        let result = app().handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, 200);
        let html = body_text(&result);
        if sent {
            for text in [
                ">Recipient</span>",
                "To: &lt;img src=x&gt; &amp; recipient@example.test",
                "Recipient unavailable",
                "Initials from the recipient header",
                "Their presence does not confirm delivery",
            ] {
                assert!(html.contains(text), "{text}");
            }
            assert!(!html.contains("<img src=x>"));
        } else {
            assert!(html.contains(">From</span>"));
            if path.starts_with("/search") {
                assert!(html.contains("Synthetic Sender &lt;sender@example.test&gt;"));
                assert!(html.contains("search-result-title"));
            } else {
                assert!(html.contains("Initials from the sender header"));
            }
            assert!(!html.contains("To: &lt;img"));
        }
    }
}

#[test]
fn received_dates_http_refuses_invalid_and_preserves_all_navigation_fields() {
    assert!(crate::http_form::parse_query_string("after=2026-03-28&after=2026-03-29", 16).is_err());
    for query in ["after=2026-02-29", "before=2026-01-01&after=2026-03-28"] {
        assert_eq!(
            mailbox_page(&format!("/mailbox?name=INBOX&{query}"))
                .response
                .status_code,
            400
        );
    }
    let target="/search?q=reader-fixture&field=subject&scope=all&filter=unread&attachment=unknown&sort=received&dir=desc&page=2&selected_mailbox=INBOX&selected_uid=1&select=move&after=2026-09-30&before=2026-09-30";
    let safe = crate::mail_navigation::safe_mail_return(target).unwrap();
    assert!(super::super::header_theme::safe_return(target).is_some());
    let moved = crate::mail_navigation::mail_return_after_move(target, "INBOX").unwrap();
    for value in [
        "after=2026-09-30",
        "before=2026-09-30",
        "field=subject",
        "attachment=unknown",
    ] {
        assert!(safe.contains(value));
        assert!(moved.contains(value));
    }
    assert!(!moved.contains("selected_"));
    let result = mailbox_page("/mailbox?name=INBOX&after=2026-10-01");
    assert_eq!(result.response.status_code, 200);
    assert!(body_text(&result).contains("Showing 0–0 of 0 messages"));
}

#[test]
fn reader_refuses_foreign_secondary_projections_but_keeps_owned_body() {
    let app = app();
    let session = StubGateway::validated_session();
    for agent in ["ReaderSettingsWrongOwner", "ReaderMailboxWrongOwner"] {
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "projection-test",
            "127.0.0.1",
            agent,
        )
        .unwrap();
        assert!(app
            .validated_archive_mailbox_name(&context, &session, &mut Vec::new())
            .is_none());
        let mut req = request(
            "GET",
            "/message?mailbox=Sent&uid=10",
            &authenticated_headers(),
            "",
        );
        req.headers.insert("user-agent".into(), agent.into());
        let result = app.handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, 200);
        let html = body_text(&result);
        assert!(html.contains("id=\"reading-pane\""));
        if agent == "ReaderMailboxWrongOwner" {
            assert!(!html.contains("<option value=\"Archive/2026\""));
        }
    }
}

#[test]
fn reader_neighbours_verify_scope_identity_order_and_refuse_ambiguous_summaries() {
    use crate::reader_neighbours::ReaderNeighbours;
    let gateway = StubGateway::default();
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "neighbour-test",
        "127.0.0.1",
        "Firefox/Test",
    )
    .unwrap();
    let BrowserMessageViewDecision::Rendered { rendered, .. } = gateway
        .view_message(&context, &session, "INBOX", 10)
        .decision
    else {
        panic!("fixture")
    };
    let good = gateway.list_messages(&context, &session, "INBOX").decision;
    let prefs = crate::reading_preferences::ReadingPreferences::default();
    let html = ReaderNeighbours::derive(
        "alice@example.com",
        &rendered,
        Some(prefs),
        &good,
        Some("/mailbox?name=INBOX&filter=unread"),
    )
    .html();
    assert!(html.contains("uid=9&amp;mailbox_guid="));
    assert!(html.contains("aria-label=\"Previous message\" disabled"));
    assert!(html.contains("return_to=%2Fmailbox"));
    assert!(html.contains("do not follow list filters or search results"));
    let oldest = crate::reading_preferences::ReadingPreferences {
        date_order: crate::reading_preferences::DateOrder::Oldest,
        ..prefs
    };
    let html =
        ReaderNeighbours::derive("alice@example.com", &rendered, Some(oldest), &good, None).html();
    assert!(html.contains("aria-label=\"Next message\" disabled"));
    for fault in 0..10 {
        let mut decision = good.clone();
        if let BrowserMessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
        } = &mut decision
        {
            match fault {
                0 => *canonical_username = "bob@example.com".into(),
                1 => *mailbox_name = "Other".into(),
                2 => messages[0].mailbox_name = "Other".into(),
                3 => messages[0].uid = messages[1].uid,
                4 => messages[0].uid = 0,
                5 => messages[1].metadata.as_mut().unwrap().version.message_guid = "changed".into(),
                6 => messages[0].metadata.as_mut().unwrap().version.mailbox_guid = "b".repeat(32),
                7 => messages[0].metadata = None,
                8 => messages.resize(
                    crate::mailbox::DEFAULT_MAX_MESSAGES + 1,
                    messages[0].clone(),
                ),
                _ => messages[0].date_received = "unknown".into(),
            }
        }
        let html =
            ReaderNeighbours::derive("alice@example.com", &rendered, Some(prefs), &decision, None)
                .html();
        assert!(html.contains("Navigation unavailable"), "fault {fault}");
        assert!(!html.contains("href="));
    }
    let failed = BrowserMessageListDecision::Denied {
        public_reason: "unavailable".into(),
    };
    assert!(
        !ReaderNeighbours::derive("alice@example.com", &rendered, Some(prefs), &failed, None)
            .html()
            .contains("href=")
    );
    assert!(!ReaderNeighbours::derive(
        "alice@example.com",
        &rendered,
        None,
        &good,
        Some("https://foreign.test")
    )
    .html()
    .contains("href="));
}

#[test]
fn reader_neighbours_route_checks_link_version_and_fetches_only_current_body() {
    let good = request(
        "GET",
        "/message?mailbox=INBOX&uid=10",
        &authenticated_headers(),
        "",
    );
    let outcome = app().handle_request(&good, "127.0.0.1");
    assert_eq!(outcome.response.status_code, 200);
    assert!(body_text(&outcome).contains("aria-label=\"Next message\" href="));
    assert_eq!(
        outcome
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_view")
            .count(),
        1
    );
    assert_eq!(
        outcome
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_list")
            .count(),
        1
    );
    for suffix in [
        "&mailbox_guid=bad",
        "&mailbox_guid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&message_guid=stale",
    ] {
        let req = request(
            "GET",
            &format!("/message?mailbox=INBOX&uid=10{suffix}"),
            &authenticated_headers(),
            "",
        );
        let outcome = app().handle_request(&req, "127.0.0.1");
        assert_eq!(outcome.response.status_code, 503);
        assert!(!body_text(&outcome).contains("id=\"reading-pane\""));
    }
}

fn empty_search_clear_href(response: &HandledHttpResponse) -> String {
    let body = body_text(response);
    let card = body
        .split_once("<section class=\"mail-state-card\">")
        .expect("empty search card")
        .1;
    let href = card
        .split_once("href=\"")
        .expect("native clear link")
        .1
        .split_once('"')
        .expect("closed native href")
        .0;
    href.replace("&amp;", "&")
}

#[test]
fn empty_search_clear_preserves_validated_query_field_and_scope() {
    let app = app();
    for (path, expected) in [
        ("/search?scope=all&q=ux-empty-fixture&field=subject&filter=unread&attachment=with&after=2026-03-01&before=2026-03-31&page=2&selected_mailbox=INBOX&selected_uid=9&select=move", "/search?scope=all&q=ux-empty-fixture&field=subject"),
        ("/search?mailbox=INBOX&q=ux-empty-fixture&field=from&filter=starred&attachment=with&after=2026-03-01&page=2", "/search?mailbox=INBOX&q=ux-empty-fixture&field=from"),
        ("/search?mailbox=INBOX&scope=all&q=ux-empty-fixture&field=all&attachment=with", "/search?scope=all&q=ux-empty-fixture&field=all"),
        ("/search?mailbox=Archive%2F2026&q=caf%C3%A9+%2B+%3Cdraft%3E+%26+%23%2F%3F&field=subject&attachment=with&sort=subject&dir=asc&page=2", "/search?mailbox=Archive%2F2026&q=caf%C3%A9+%2B+%3Cdraft%3E+%26+%23%2F%3F&field=subject"),
    ] {
        let source = request("GET", path, &authenticated_headers(), "");
        let response = app.handle_request(&source, "127.0.0.1");
        assert_eq!(response.response.status_code, 200);
        assert!(body_text(&response).contains("<h2>Empty search</h2>"));
        let href = empty_search_clear_href(&response);
        assert_eq!(href, expected, "Clear filters must keep the search, not erase keywords");
        let cleared = request("GET", &href, &authenticated_headers(), "");
        assert_eq!(cleared.query_params.get("q"), source.query_params.get("q"));
        assert_eq!(cleared.query_params.get("field"), source.query_params.get("field"));
        for removed in ["filter", "attachment", "after", "before", "page", "selected_mailbox", "selected_uid", "select"] {
            assert!(!cleared.query_params.contains_key(removed), "stale constraint {removed} retained");
        }
        let follow = app.handle_request(&cleared, "127.0.0.1");
        assert_eq!(follow.response.status_code, 200);
        assert!(!body_text(&follow).contains("Enter keywords to search your mail."));
        assert_eq!(app.request_budgets.search_workers.active_count(), 0);
    }
}

#[test]
fn empty_search_clear_is_not_offered_for_unverified_search_context() {
    let app = app();
    for path in [
        "/search?q=ux-empty-fixture&field=unsupported",
        "/search?q=ux-empty-fixture&field=subject&filter=unknown",
        "/search?mailbox=MissingArchive&q=report&field=subject",
    ] {
        let response = app.handle_request(
            &request("GET", path, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 400);
        assert!(!body_text(&response).contains(">Clear filters</a>"));
    }
    for headers in [
        vec![("User-Agent", "Firefox/Test")],
        vec![
            ("User-Agent", "Firefox/Test"),
            ("Cookie", "osmap_session=invalid"),
        ],
    ] {
        let response = app.handle_request(
            &request(
                "GET",
                "/search?q=ux-empty-fixture&scope=all&field=subject",
                &headers,
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 303);
        assert_eq!(location_header(&response), "/login");
        assert!(!body_text(&response).contains(">Clear filters</a>"));
    }
    let mut foreign = request(
        "GET",
        "/search?q=ux-empty-fixture&scope=all&field=subject",
        &authenticated_headers(),
        "",
    );
    foreign
        .headers
        .insert("user-agent".into(), "OSMAP/SearchWrongOwner".into());
    let response = app.handle_request(&foreign, "127.0.0.1");
    assert_eq!(response.response.status_code, 503);
    let body = body_text(&response);
    assert!(!body.contains(">Clear filters</a>"));
    assert!(!body.contains("foreign-secret"));
    assert!(!body.contains("ForeignFolder"));
    assert_eq!(app.request_budgets.search_workers.active_count(), 0);
}
