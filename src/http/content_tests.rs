use super::*;

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
