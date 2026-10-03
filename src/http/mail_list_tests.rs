use super::*;

#[test]
fn public_attachment_names_and_encoded_sizes_are_real_escaped_row_details() {
    for path in ["/mailbox?name=INBOX", "/mailbox?name=Sent", "/search?q=reader-fixture&field=subject&scope=all"] {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers.insert("user-agent".into(), "OSMAP/ManyMessages;AttachmentNames".into());
        let response = app().handle_request(&req, "127.0.0.1");
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("public-&lt;b&gt;.txt"), "{path}");
        assert!(!body.contains("public-<b>.txt"));
        assert!(body.contains("129 encoded MIME bytes"), "{path}");
        assert!(body.contains("decoded download size"));
        assert!(!response.audit_events.iter().any(|event| event.action == "stub_message_view"));
    }
}

#[test]
fn independent_sender_filter_has_an_actual_combined_search_and_navigation_control() {
    let path = "/search?q=reader-fixture&field=subject&scope=all&from=sender%40example.test&pgp=unknown&sort=subject&dir=asc&page=2";
    let response = mailbox_page(path);
    assert_eq!(response.response.status_code, 200);
    let body = body_text(&response);
    assert!(body.contains("aria-label=\"Sender filter\""));
    assert!(body.contains("name=\"from\" value=\"sender@example.test\""));
    assert!(body.contains("from=sender%40example.test"));
    assert!(body.contains("q=reader-fixture"));
    assert!(body.contains("field=subject"));
    assert!(body.contains("pgp=unknown"));
    assert!(body.contains("Showing 51–100"));
    assert_eq!(mailbox_page("/mailbox?name=INBOX&from=not-an-address").response.status_code, 400);
}

#[test]
fn public_mime_protection_filter_is_a_real_preserved_list_and_search_control() {
    for path in [
        "/mailbox?name=INBOX&pgp=unknown&sort=subject&dir=asc&page=2",
        "/search?q=reader-fixture&field=subject&scope=all&pgp=unknown&sort=subject&dir=asc&page=2",
    ] {
        let response = mailbox_page(path);
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains("aria-label=\"OpenPGP filter\""), "{path}");
        assert!(body.contains("name=\"pgp\" value=\"unknown\""), "{path}");
        assert!(body.contains("pgp=unknown&amp;page=3"), "{path}");
        assert!(!body.contains("protection-status filters are unavailable"));
        assert!(body.contains("MIME structure"));
        assert!(!body.contains(">Verified<"));
    }
    let invalid = mailbox_page("/mailbox?name=INBOX&pgp=verified");
    assert_eq!(invalid.response.status_code, 400);
    let absent_session = app().handle_request(
        &request("GET", "/search?q=fixture&scope=all&pgp=encrypted", &[], ""),
        "127.0.0.1",
    );
    assert_eq!(absent_session.response.status_code, 303);
}

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

fn eligible_selection_rendered_page(
    mailbox: &str,
    total: u64,
    eligible: &[u64],
    page: usize,
) -> String {
    let mut messages: Vec<_> = (1..=total)
        .map(|uid| MessageSummary {
            mailbox_name: mailbox.into(),
            uid,
            flags: vec![],
            date_received: "2026-10-03 01:00:00 +0000".into(),
            size_virtual: 100,
            subject: Some(format!("Selection fixture {uid:04}")),
            from: Some("sender@example.test".into()),
            to: Some("recipient@example.test".into()),
            metadata: eligible.contains(&uid).then(|| {
                StubGateway::fixture_metadata("alice@example.com", mailbox, uid)
            }),
        })
        .collect();
    let mut view = crate::mail_list::ListViewState::from_query(&BTreeMap::from([
        ("sort".into(), "subject".into()),
        ("dir".into(), "asc".into()),
        ("page".into(), page.to_string()),
        ("select".into(), "move".into()),
    ]))
    .unwrap();
    view.apply_messages(&mut messages);
    let reader = crate::http_ui::MailReaderContext::default();
    let destinations = vec!["Archive".into(), "Trash".into()];
    crate::http_ui::render_message_list_page(
        "alice@example.com",
        "synthetic-csrf",
        mailbox,
        &messages,
        None,
        crate::http_ui::MessageListBulkActions {
            archive_mailbox_name: Some("Archive"),
            move_destinations: &destinations,
        },
        crate::http_ui::MessageListSortLinks {
            view: &view,
            search_query: None,
            search_scope: None,
            reader: &reader,
        },
    )
    .as_str()
    .to_owned()
}

fn eligible_selection_checkbox_tags(html: &str) -> Vec<&str> {
    html.split("<input")
        .skip(1)
        .filter_map(|tail| tail.split_once('>').map(|(tag, _)| tag))
        .filter(|tag| {
            tag.contains("type=\"checkbox\"") && tag.contains("form=\"bulk-move-form\"")
        })
        .collect()
}

#[test]
fn rendered_inbox_sent_selection_counts_only_current_eligible_identities() {
    for mailbox in ["INBOX", "Sent"] {
        let html = eligible_selection_rendered_page(mailbox, 3, &[2], 1);
        let controls = eligible_selection_checkbox_tags(&html);
        assert_eq!(controls.len(), 1, "only current GUID-bearing row is selectable: {mailbox}");
        assert!(controls[0].contains("name=\"message_2\""));
        assert_eq!(controls.iter().filter(|tag| tag.contains(" checked")).count(), 1);
        assert!(html.contains("1 selected for the next action."),
                "menu count must equal actual checked owned tuples: {mailbox}");
        assert!(!html.contains("3 selected for the next action."));
        assert!(!html.contains("Select all 3 on this page"));
    }
}

#[test]
fn rendered_inbox_sent_missing_identities_offer_no_automatic_selection() {
    for mailbox in ["INBOX", "Sent"] {
        let html = eligible_selection_rendered_page(mailbox, 3, &[], 1);
        assert!(eligible_selection_checkbox_tags(&html).is_empty());
        assert!(!html.contains("Select all 3 on this page"));
        assert!(!html.contains("3 selected for the next action."));
        assert!(!html.contains("name=\"action\" value=\"move\">Move Selected"));
        assert!(!html.contains("name=\"action\" value=\"archive\">Archive Selected"));
        // A zero-count native message or omission is allowed; do not invent
        // a required label. No enabled automatic-selection link may exist.
        for nav in html.split("<nav aria-label=\"Select messages on this page\">").skip(1) {
            let nav = nav.split("</nav>").next().unwrap();
            assert!(!nav.contains("select=move"), "no eligibility, no selection action");
        }
    }
}

#[test]
fn rendered_page_two_selection_preserves_first_ten_boundary_and_eligible_count() {
    for mailbox in ["INBOX", "Sent"] {
        // First page has many eligible rows; they must never contribute.
        // Page2 has 13 rows. Only UID51 lies within its first ten rows;
        // UID61/62 have valid identities but stay unchecked by this mode.
        let eligible: Vec<_> = (1..=50).chain([51, 61, 62]).collect();
        let html = eligible_selection_rendered_page(mailbox, 63, &eligible, 2);
        let controls = eligible_selection_checkbox_tags(&html);
        assert_eq!(controls.len(), 3, "visible current-page controls only");
        let checked: Vec<_> = controls.iter().filter(|tag| tag.contains(" checked")).collect();
        assert_eq!(checked.len(), 1);
        assert!(checked[0].contains("name=\"message_51\""));
        assert!(!controls.iter().any(|tag| tag.contains("name=\"message_50\"")));
        assert!(html.contains("Showing 51–63"));
        assert!(html.contains("1 selected for the next action."));
        assert!(!html.contains("10 selected for the next action."));
    }
}

#[test]
fn rendered_selection_tenth_row_boundary_keeps_later_manual_controls() {
    for mailbox in ["INBOX", "Sent", "Archive", "Trash"] {
        let html = eligible_selection_rendered_page(mailbox, 13, &[10, 11], 1);
        let controls = eligible_selection_checkbox_tags(&html);
        assert_eq!(controls.len(), 2);
        let checked: Vec<_> = controls.iter().filter(|tag| tag.contains(" checked")).collect();
        assert_eq!(checked.len(), 1, "original first-ten window: {mailbox}");
        assert!(checked[0].contains("name=\"message_10\""));
        assert!(html.contains("1 selected for the next action."));

        let html = eligible_selection_rendered_page(mailbox, 13, &[11, 12], 1);
        let controls = eligible_selection_checkbox_tags(&html);
        assert_eq!(controls.len(), 2, "later manual controls stay available: {mailbox}");
        assert!(!controls.iter().any(|tag| tag.contains(" checked")));
        assert!(html.contains("id=\"bulk-move-form\""));
        assert!(html.contains("value=\"move\">Move Selected"));
        assert!(html.contains("No automatic selection."));
        for nav in html.split("<nav aria-label=\"Select messages on this page\">").skip(1) {
            let nav = nav.split("</nav>").next().unwrap();
            assert!(!nav.contains("select=move"), "no automatic identities: {mailbox}");
        }
    }
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
    assert!(!html.contains("uid=9&amp;mailbox_guid="));
    assert!(html.contains("aria-label=\"Previous message\" disabled"));
    assert!(html.contains("aria-label=\"Next message\" disabled"));
    assert!(html.contains("filtered and sorted result snapshot"));
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


fn neighbour_href(html: &str, label: &str) -> String {
    let marker = format!("aria-label=\"{label} message\" href=\"");
    html.split_once(&marker).expect("enabled neighbour").1
        .split_once('"').expect("bounded link").0.replace("&amp;", "&")
}

#[test]
fn reader_neighbours_follow_filtered_order_across_pages_in_mailbox_and_search() {
    for base in [
        "/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc",
        "/search?q=reader-fixture&field=subject&mailbox=INBOX&filter=unread&sort=subject&dir=asc",
    ] {
        let response = mailbox_page(&format!("{base}&selected_mailbox=INBOX&selected_uid=99"));
        assert_eq!(response.response.status_code, 200);
        let html = body_text(&response);
        let previous = neighbour_href(&html, "Previous");
        let next = neighbour_href(&html, "Next");
        assert!(previous.contains("selected_uid=97"));
        assert!(next.contains("selected_uid=101"));
        assert!(next.contains("page=2"));
        assert!(next.contains("selected_mailbox_guid="));
        assert!(next.contains("selected_message_guid="));
        assert!(next.contains("filter=unread"));
        let followed = mailbox_page(next.split('#').next().unwrap());
        assert_eq!(followed.response.status_code, 200);
        assert!(body_text(&followed).contains("Synthetic message 101 in INBOX"));
        assert!(body_text(&followed).contains("data-selected=\"true\""));
        let stale = next.split('#').next().unwrap().split('&')
            .map(|part| if part.starts_with("selected_message_guid=") { "selected_message_guid=changed" } else { part })
            .collect::<Vec<_>>().join("&");
        let refused = mailbox_page(&stale);
        assert!(body_text(&refused).contains("selected message identity changed"));
        assert!(!body_text(&refused).contains("Synthetic message 101 in INBOX"));
        assert!(!refused.audit_events.iter().any(|event| event.action == "stub_message_view"));
    }
}

#[test]
fn standalone_search_neighbours_use_actual_search_and_release_both_budgets() {
    let app = app();
    let return_to = "/search?q=reader-fixture&field=subject&mailbox=INBOX&filter=unread&sort=subject&dir=asc";
    let mut req = request("GET", &format!("/message?mailbox=INBOX&uid=7&return_to={}", url_encode(return_to)), &authenticated_headers(), "");
    req.headers.insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let result = app.handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    let html = body_text(&result);
    assert!(neighbour_href(&html, "Previous").contains("uid=5&"));
    assert!(neighbour_href(&html, "Next").contains("uid=9&"));
    assert!(!result.audit_events.iter().any(|event| event.action == "stub_message_list"));
    assert_eq!(app.request_budgets.search_workers.active_count(), 0);
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    let mut occupied = Vec::new();
    while let Some(guard) = app.request_budgets.search_workers.try_acquire() {
        occupied.push(guard);
    }
    assert!(!occupied.is_empty());
    let blocked = app.handle_request(&req, "127.0.0.1");
    assert_eq!(blocked.response.status_code, 200);
    assert!(!body_text(&blocked).contains("aria-label=\"Next message\" href="));
    assert!(body_text(&blocked).contains("q=reader-fixture"));
    assert!(!blocked.audit_events.iter().any(|event| event.action == "stub_message_list"));
    drop(occupied);
    req.headers.insert("user-agent".into(), "OSMAP/StateFailure".into());
    let denied = app.handle_request(&req, "127.0.0.1");
    assert!(!body_text(&denied).contains("aria-label=\"Next message\" href="));
    assert!(!denied.audit_events.iter().any(|event| event.action == "stub_message_list"));
    req.headers.insert("user-agent".into(), "OSMAP/ManyMessages".into());
    assert!(body_text(&app.handle_request(&req, "127.0.0.1")).contains("aria-label=\"Next message\" href="));
}
