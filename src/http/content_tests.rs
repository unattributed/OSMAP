use super::*;

struct ReaderRetryFixture {
    root: PathBuf,
    contacts: crate::contacts::ContactStore,
    row: MessageSearchResult,
}

impl ReaderRetryFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-reader-retry-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        Self {
            contacts: crate::contacts::ContactStore::new(root.join("contacts")),
            root,
            row: MessageSearchResult {
                metadata: Some(StubGateway::fixture_metadata(
                    "alice@example.com",
                    "INBOX",
                    9,
                )),
                mailbox_name: "INBOX".into(),
                uid: 9,
                flags: Vec::new(),
                date_received: "2026-10-03 12:00:00 +0000".into(),
                size_virtual: 1,
                subject: Some("Public retry target".into()),
                from: Some("Public sender <sender@example.test>".into()),
            },
        }
    }

    fn app(&self, replacement: Option<&str>, override_view: bool) -> BrowserApp<StubGateway> {
        let mut row = self.row.clone();
        if let Some(guid) = replacement {
            row.metadata.as_mut().unwrap().version.message_guid = guid.into();
        }
        let messages = override_view.then(|| {
            vec![MessageSummary {
                metadata: row.metadata.clone(),
                mailbox_name: row.mailbox_name.clone(),
                uid: row.uid,
                flags: row.flags.clone(),
                date_received: row.date_received.clone(),
                size_virtual: row.size_virtual,
                subject: row.subject.clone(),
                from: row.from.clone(),
                to: None,
            }]
        });
        BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                browser_fixture_accounts: true,
                contacts_store: Some(self.contacts.clone()),
                message_list_override: messages,
                all_search_override: Some(BrowserMessageSearchDecision::Listed {
                    canonical_username: "alice@example.com".into(),
                    mailbox_name: Some("INBOX".into()),
                    query: "Public".into(),
                    results: vec![row],
                }),
                ..StubGateway::default()
            },
        )
    }

    fn opening(&self, app: &BrowserApp<StubGateway>) -> String {
        let listing = get(
            app,
            "/search?category=all&q=Public&mailbox=INBOX&filter=unread&from=sender%40example.test&after=2026-10-01&before=2026-10-05&attachment=without&pgp=unknown",
            "OSMAP/ReaderRetry",
        );
        assert_eq!(listing.response.status_code, 200);
        let body = body_text(&listing);
        let opening = body
            .split("<a ")
            .find_map(|anchor| {
                let tag = anchor.split_once('>')?.0;
                (tag.contains("class=\"message-subject-link\"") && tag.contains("href=\"/message?"))
                    .then(|| reader_retry_attribute(tag, "href"))
            })
            .expect("actual All-generated current identity opening");
        let fields = reader_retry_fields(&opening);
        assert_eq!(fields.get("uid").map(String::as_str), Some("9"));
        let version = &self.row.metadata.as_ref().unwrap().version;
        assert_eq!(fields.get("mailbox_guid"), Some(&version.mailbox_guid));
        assert_eq!(fields.get("message_guid"), Some(&version.message_guid));
        assert_eq!(app.request_budgets.search_workers.active_count(), 0);
        opening
    }
}

impl Drop for ReaderRetryFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn reader_retry_attribute(tag: &str, name: &str) -> String {
    tag.split_once(&format!("{name}=\""))
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .replace("&amp;", "&")
}

fn reader_retry_anchor(body: &str, label: &str) -> String {
    body.split("<a ")
        .find_map(|anchor| {
            let (tag, contents) = anchor.split_once('>')?;
            (contents.split_once("</a>")?.0 == label).then(|| reader_retry_attribute(tag, "href"))
        })
        .expect("actual rendered recovery anchor")
}

fn reader_retry_fields(url: &str) -> BTreeMap<String, String> {
    crate::http_form::parse_urlencoded_form(
        url.split_once('?').unwrap().1.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap()
}

fn reader_retry_labelled_anchor(body: &str, label: &str) -> String {
    body.split("<a ")
        .find_map(|anchor| {
            let tag = anchor.split_once('>')?.0;
            tag.contains(&format!("aria-label=\"{label}\""))
                .then(|| reader_retry_attribute(tag, "href"))
        })
        .expect("actual accessible reader control")
}

fn reader_retry_released(app: &BrowserApp<StubGateway>, response: &HandledHttpResponse) {
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_acquired")
            .count(),
        1
    );
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_released")
            .count(),
        1
    );
}

#[test]
fn reader_retry_generated_links_preserve_current_guids_and_nested_all_context() {
    let fixture = ReaderRetryFixture::new();
    // No view override: the existing ReaderUnavailable seam must reach Denied.
    let app = fixture.app(None, false);
    let opening = fixture.opening(&app);
    let flags = app
        .gateway
        .fixture_message_flags("alice@example.com", "INBOX", 9);
    let failed = get(&app, &opening, "OSMAP/ReaderUnavailable");
    assert_eq!(failed.response.status_code, 503);
    reader_retry_released(&app, &failed);
    let body = body_text(&failed);
    let retry = reader_retry_anchor(&body, "Retry loading");
    let back = reader_retry_anchor(&body, "Back to message");
    let expected = reader_retry_fields(&opening);
    let actual = reader_retry_fields(&retry);
    assert_eq!(
        actual, expected,
        "Retry must retain the actual current identity and validated origin"
    );
    assert_eq!(
        reader_retry_fields(&back),
        reader_retry_fields(expected.get("return_to").unwrap()),
        "failed reader Back must retain the actual All filters/page"
    );
    assert!(!body.contains("action=\"/message/") && !body.contains("action=\"/messages/"));
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        flags
    );
}

#[test]
fn reader_retry_actual_link_refuses_same_uid_replacement_after_temporary_failure() {
    let fixture = ReaderRetryFixture::new();
    let failed_app = fixture.app(None, false);
    let opening = fixture.opening(&failed_app);
    let failed = get(&failed_app, &opening, "OSMAP/ReaderUnavailable");
    assert_eq!(failed.response.status_code, 503);
    reader_retry_released(&failed_app, &failed);
    let retry = reader_retry_anchor(&body_text(&failed), "Retry loading");
    let current_app = fixture.app(None, true);
    assert_eq!(
        get(&current_app, &opening, "OSMAP/ReaderRetry")
            .response
            .status_code,
        200,
        "current GUID-bound opening is usable before controlled replacement"
    );
    let replaced_app = fixture.app(Some("controlled-replacement-guid"), true);
    let flags = replaced_app
        .gateway
        .fixture_message_flags("alice@example.com", "INBOX", 9);
    let original_stale = get(&replaced_app, &opening, "OSMAP/ReaderRetry");
    assert_eq!(
        original_stale.response.status_code, 503,
        "unchanged bound opening refuses replaced identity"
    );
    assert!(!body_text(&original_stale).contains("<pre>Synthetic message 9"));
    reader_retry_released(&replaced_app, &original_stale);
    let retried = get(&replaced_app, &retry, "OSMAP/ReaderRetry");
    reader_retry_released(&replaced_app, &retried);
    assert_eq!(
        replaced_app
            .gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        flags
    );
    assert_eq!(
        retried.response.status_code, 503,
        "actual rendered Retry must not downgrade stale identity to current UID"
    );
    assert!(!body_text(&retried).contains("<pre>Synthetic message 9"));
}

#[test]
fn reader_retry_matching_identity_recovers_actual_body_and_all_back_without_mutation() {
    let fixture = ReaderRetryFixture::new();
    let failed_app = fixture.app(None, false);
    let opening = fixture.opening(&failed_app);
    let failed = get(&failed_app, &opening, "OSMAP/ReaderUnavailable");
    assert_eq!(failed.response.status_code, 503);
    let retry = reader_retry_anchor(&body_text(&failed), "Retry loading");
    let current_app = fixture.app(None, true);
    let flags = current_app
        .gateway
        .fixture_message_flags("alice@example.com", "INBOX", 9);
    let recovered = get(&current_app, &retry, "OSMAP/ReaderRetry");
    assert_eq!(recovered.response.status_code, 200);
    let body = body_text(&recovered);
    assert!(body.contains("<pre>Synthetic message 9 in INBOX for alice@example.com.</pre>"));
    let back = reader_retry_labelled_anchor(&body, "Back to list");
    assert_eq!(
        reader_retry_fields(&back),
        reader_retry_fields(reader_retry_fields(&opening).get("return_to").unwrap())
    );
    assert_eq!(
        get(&current_app, &back, "OSMAP/ReaderRetry")
            .response
            .status_code,
        200
    );
    assert_eq!(
        current_app
            .gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        flags
    );
    assert_eq!(
        current_app.request_budgets.mailbox_workers.active_count(),
        0
    );
    assert_eq!(current_app.request_budgets.search_workers.active_count(), 0);
    assert_eq!(
        recovered
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_acquired")
            .count(),
        recovered
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_released")
            .count()
    );
}

fn reader_retry_url(fields: &BTreeMap<String, String>) -> String {
    format!(
        "/message?{}",
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    )
}

#[test]
fn reader_retry_invalid_supplied_identity_or_origin_never_becomes_unbound_retry() {
    let fixture = ReaderRetryFixture::new();
    let app = fixture.app(None, false);
    let opening = fixture.opening(&app);
    let fields = reader_retry_fields(&opening);
    let mut invalid = Vec::new();
    for missing in ["mailbox_guid", "message_guid"] {
        let mut broken = fields.clone();
        broken.remove(missing);
        invalid.push(broken);
    }
    for (name, value) in [
        ("mailbox_guid", "invalid-guid".into()),
        ("message_guid", String::new()),
        (
            "message_guid",
            "x".repeat(crate::message_metadata::MAX_MESSAGE_GUID_BYTES + 1),
        ),
        ("message_guid", "injected\nidentity".into()),
        ("return_to", "https://external.invalid/private".into()),
        (
            "return_to",
            "/search?category=all&q=Public&pgp=verified".into(),
        ),
        ("unexpected_authority", "ignored".into()),
    ] {
        let mut broken = fields.clone();
        broken.insert(name.into(), value);
        invalid.push(broken);
    }
    for broken in invalid {
        let failed = get(&app, &reader_retry_url(&broken), "OSMAP/ReaderUnavailable");
        assert_eq!(
            failed.response.status_code, 503,
            "existing temporary denial classification"
        );
        reader_retry_released(&app, &failed);
        let body = body_text(&failed);
        assert!(
            !body.contains(">Retry loading</a>"),
            "invalid request context must not be dropped into legacy Retry"
        );
        let back = reader_retry_anchor(&body, "Back to message");
        assert!(crate::mail_navigation::safe_mail_return(&back).is_some());
        assert!(!back.starts_with("https:") && !body.contains("action=\"/message/"));
    }
}

#[test]
fn reader_retry_keeps_legacy_unbound_read_and_default_mailbox_back_compatible() {
    let app = app();
    let opening = "/message?mailbox=INBOX&uid=9";
    let flags = app
        .gateway
        .fixture_message_flags("alice@example.com", "INBOX", 9);
    let failed = get(&app, opening, "OSMAP/ReaderUnavailable");
    assert_eq!(failed.response.status_code, 503);
    let body = body_text(&failed);
    let retry = reader_retry_anchor(&body, "Retry loading");
    assert_eq!(reader_retry_fields(&retry), reader_retry_fields(opening));
    assert_eq!(
        reader_retry_fields(&reader_retry_anchor(&body, "Back to message")),
        BTreeMap::from([("name".into(), "INBOX".into())])
    );
    let recovered = get(&app, &retry, "OSMAP/ReaderRetry");
    assert_eq!(recovered.response.status_code, 200);
    assert!(body_text(&recovered).contains("<pre>Hello world</pre>"));
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        flags
    );
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
}

#[test]
fn reader_retry_is_session_owned_and_foreign_or_stale_replies_have_no_retry() {
    let fixture = ReaderRetryFixture::new();
    let app = fixture.app(None, false);
    let opening = fixture.opening(&app);
    let failed = get(&app, &opening, "OSMAP/ReaderUnavailable");
    let retry = reader_retry_anchor(&body_text(&failed), "Retry loading");
    let unauthenticated = app.handle_request(&request("GET", &retry, &[], ""), "127.0.0.1");
    assert_eq!(unauthenticated.response.status_code, 303);
    assert!(!unauthenticated
        .audit_events
        .iter()
        .any(|event| event.action == "request_budget_acquired"));
    for ua in ["OSMAP/ReaderWrongAccount", "OSMAP/ReaderStale"] {
        let denied = get(&app, &retry, ua);
        assert_eq!(denied.response.status_code, 503);
        let body = body_text(&denied);
        assert!(!body.contains("<pre>Hello world</pre>") && !body.contains(">Retry loading</a>"));
        let back = reader_retry_anchor(&body, "Back to message");
        assert_eq!(
            reader_retry_fields(&back),
            reader_retry_fields(reader_retry_fields(&opening).get("return_to").unwrap())
        );
        reader_retry_released(&app, &denied);
    }
    let mut bob = request("GET", &retry, &authenticated_same_origin_headers(), "");
    bob.headers.insert(
        "cookie".into(),
        "osmap_session=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
    );
    let foreign = app.handle_request(&bob, "127.0.0.1");
    assert_eq!(
        foreign.response.status_code, 503,
        "Alice GUID cannot identify Bob's same-UID message"
    );
    assert!(!body_text(&foreign).contains("<pre>Hello world</pre>"));
    reader_retry_released(&app, &foreign);
}

pub(super) fn fixture_source(
    gateway: &StubGateway,
    context: &AuthenticationContext,
    session: &ValidatedSession,
    request: &MessageViewRequest,
) -> crate::mailbox::MessageViewOutcome {
    let ua = &context.user_agent;
    let metadata = gateway.fixture_current_metadata(
        &session.record.canonical_username,
        &request.mailbox_name,
        request.uid,
    );
    let decision = if ua.contains("SourceUnavailable") || request.uid == 900 {
        MessageViewDecision::Denied {
            public_reason: crate::mailbox::MailboxPublicFailureReason::TemporarilyUnavailable,
        }
    } else if metadata.is_none() || request.uid == 999 {
        MessageViewDecision::Denied {
            public_reason: crate::mailbox::MailboxPublicFailureReason::NotFound,
        }
    } else {
        let mut message = MessageView {
            metadata, mailbox_name: request.mailbox_name.clone(), uid: request.uid,
            flags: vec![], date_received: "2026-09-30 00:00:00 +0000".into(), size_virtual: 512,
            header_block: format!("Subject: Synthetic <source> & reader\n{}MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=synthetic-content", super::reply_tests::source_headers(context, session, request.uid)),
            body_text: "--synthetic-content\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Synthetic source for this session.</p><script>inert-source-marker</script><img src=\"https://example.test/blocked\">\r\n--synthetic-content\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi1zdHViJQ==\r\n--synthetic-content--\r\n".into(),
        };
        if ua.contains("SourceStale") {
            message.metadata.as_mut().unwrap().version.message_guid = "changed".into();
        }
        if ua.contains("SourceWrongMailbox") {
            message.mailbox_name = "Sent".into();
        }
        if ua.contains("SourceWrongUid") {
            message.uid += 1;
        }
        if ua.contains("SourceOversize") {
            message.body_text = "x".repeat(MessageViewPolicy::default().message_body_max_len + 1);
        }
        if ua.contains("SourceLong") {
            message.body_text.push_str(&"public-long-line-".repeat(120));
        }
        MessageViewDecision::Retrieved {
            canonical_username: if ua.contains("SourceWrongAccount") {
                "other@example.test".into()
            } else {
                session.record.canonical_username.clone()
            },
            session_id: if ua.contains("SourceWrongSession") {
                "wrong".into()
            } else {
                session.record.session_id.clone()
            },
            message: Box::new(message),
        }
    };
    crate::mailbox::MessageViewOutcome {
        decision,
        audit_event: LogEvent::new(
            LogLevel::Info,
            EventCategory::Mailbox,
            "stub_source_read",
            "synthetic stored content read",
        ),
    }
}

fn content_url(attachment: bool) -> String {
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    format!(
        "{}?mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}&{}&return_to={}",
        if attachment {
            "/attachment"
        } else {
            "/message"
        },
        version.mailbox_guid,
        version.message_guid,
        if attachment {
            "part=1.2"
        } else {
            "view=source"
        },
        url_encode("/mailbox?name=INBOX&filter=unread&selected_mailbox=INBOX&selected_uid=9")
    )
}

fn get(app: &BrowserApp<StubGateway>, url: &str, ua: &str) -> HandledHttpResponse {
    let mut request = request("GET", url, &authenticated_same_origin_headers(), "");
    request.headers.insert("user-agent".into(), ua.into());
    app.handle_request(&request, "127.0.0.1")
}

#[test]
fn source_is_authenticated_escaped_bounded_and_preserves_reader_context() {
    let app = app();
    let url = content_url(false);
    let denied = app.handle_request(&request("GET", &url, &[], ""), "127.0.0.1");
    assert_eq!(denied.response.status_code, 303);
    assert!(!denied
        .audit_events
        .iter()
        .any(|event| event.action == "stub_source_read"));
    let response = get(&app, &url, "OSMAP/SourceLong");
    assert_eq!(response.response.status_code, 200);
    let body = String::from_utf8(response.response.body).unwrap();
    assert!(body.contains("&lt;script&gt;inert-source-marker&lt;/script&gt;"));
    assert!(!body.contains("<script") && !body.contains("<img"));
    assert!(body.contains("filter=unread") && body.contains("selected_uid=9"));
    assert!(body.contains("Stored message source"));
    assert!(response
        .response
        .headers
        .iter()
        .any(|(key, value)| key == "Cache-Control" && value == "no-store"));
    assert!(response
        .response
        .headers
        .iter()
        .any(|(key, value)| key == "Content-Security-Policy"
            && value == crate::http_support::browser_csp()));
    for ua in [
        "SourceWrongAccount",
        "SourceWrongSession",
        "SourceWrongUid",
        "SourceWrongMailbox",
        "SourceOversize",
    ] {
        let denied = get(&app, &url, ua);
        assert_eq!(denied.response.status_code, 503, "{ua}");
        assert!(!String::from_utf8_lossy(&denied.response.body).contains("inert-source-marker"));
    }
    assert_eq!(get(&app, &url, "SourceStale").response.status_code, 409);
    let unavailable = get(&app, &url, "SourceUnavailable");
    let body = String::from_utf8(unavailable.response.body).unwrap();
    assert!(body.contains("Retry loading"));
    assert!(!body.contains("action=\"/message/") && !body.contains("action=\"/messages/"));
    assert_eq!(
        get(&app, &url, "ordinary").response.status_code,
        200,
        "budget released after all errors"
    );
}

#[test]
fn bound_attachment_uses_same_checked_snapshot_and_forces_isolated_download() {
    let app = app();
    let url = content_url(true);
    let response = get(&app, &url, "ordinary");
    assert_eq!(response.response.status_code, 200);
    assert_eq!(response.response.body, b"%PDF-stub%");
    for (name, expected) in [
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    ] {
        assert!(response
            .response
            .headers
            .iter()
            .any(|(key, value)| key == name && value == expected));
    }
    assert!(response
        .response
        .headers
        .iter()
        .any(|(key, value)| key == "Content-Disposition" && value.starts_with("attachment;")));
    assert!(response
        .response
        .headers
        .iter()
        .any(|(key, value)| key == "Content-Security-Policy" && value.starts_with("sandbox;")));
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|event| event.action == "stub_source_read")
            .count(),
        1
    );
    assert_eq!(get(&app, &url, "SourceStale").response.status_code, 409);
    assert_eq!(
        get(&app, &url.replace("part=1.2", "part=1.99"), "ordinary")
            .response
            .status_code,
        404
    );
    for ua in ["SourceWrongAccount", "SourceWrongUid", "SourceOversize"] {
        assert_eq!(get(&app, &url, ua).response.status_code, 503);
    }
}

#[test]
fn content_selectors_reject_ambiguous_or_unbounded_requests_before_reading() {
    let app = app();
    for query in [
        "mailbox=INBOX&uid=0&view=source",
        "mailbox=INBOX&uid=09&view=source",
        "mailbox=INBOX&uid=4294967296&view=source",
        "mailbox=INBOX&uid=9&view=active",
        "mailbox=INBOX&uid=9&view=source&mailbox_guid=bad",
        "mailbox=INBOX&uid=9&view=source&return_to=https%3A%2F%2Fexample.test",
        "mailbox=INBOX&uid=9&view=source&unexpected=1",
    ] {
        let response = get(&app, &format!("/message?{query}"), "ordinary");
        assert_eq!(response.response.status_code, 400, "{query}");
        assert!(!response
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
    }
    assert_eq!(
        get(&app, "/message?mailbox=INBOX&uid=9&view=source", "ordinary")
            .response
            .status_code,
        200
    );
}
