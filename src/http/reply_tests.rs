use super::*;

pub(super) fn source_headers(
    context: &AuthenticationContext,
    session: &ValidatedSession,
    uid: u64,
) -> String {
    if context.user_agent.contains("ReplyRecipients") {
        format!("From: Original <original@example.test>\nReply-To: \"Reply, Desk\" <desk@example.test>\nTo: {}, Desk <desk@EXAMPLE.TEST>, Other <other@example.test>\nCc: copied@example.test, other@example.test, {}\nBcc: private@example.test\nMessage-ID: <fixture-{uid}@example.test>\nReferences: <root@example.test>\n", session.record.canonical_username, session.record.canonical_username)
    } else {
        format!(
            "From: Alice <alice@example.com>\nTo: {}\nMessage-ID: <fixture-{uid}@example.test>\n",
            session.record.canonical_username
        )
    }
}

fn base_form() -> String {
    format!("csrf_token={}&from=alice%40example.com&to=desk%40example.test&cc=copied%40example.test&bcc=private%40example.test&subject=Synthetic%20reply&body=Public%20test%20body", StubGateway::validated_session().record.csrf_token)
}

fn reference_form() -> String {
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    format!(
        "&reply_mailbox=INBOX&reply_uid=9&reply_mailbox_guid={}&reply_message_guid={}",
        url_encode(&version.mailbox_guid),
        url_encode(&version.message_guid)
    )
}

fn perform(
    app: &BrowserApp<StubGateway>,
    method: &str,
    path: &str,
    body: &str,
    ua: &str,
) -> HandledHttpResponse {
    let mut request = request(method, path, &authenticated_same_origin_headers(), body);
    request.headers.insert("user-agent".into(), ua.into());
    if request.method == HttpMethod::Post
        && matches!(request.path.as_str(), "/send" | "/drafts/save")
    {
        add_native_compose_intent(app, &mut request);
    }
    app.handle_request(&request, "127.0.0.1")
}

#[test]
fn compose_reply_all_uses_original_address_roles_and_binds_reader_identity() {
    let app = app();
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    let url = format!(
        "/compose?mode=reply-all&mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}",
        version.mailbox_guid, version.message_guid
    );
    let response = perform(&app, "GET", &url, "", "ReplyRecipients");
    assert_eq!(response.response.status_code, 200);
    let body = body_text(&response);
    assert!(body.contains("<h1>Reply all</h1>"));
    assert!(body.contains("name=\"from\" value=\"alice@example.com\" readonly"));
    assert!(body.contains("name=\"to\" value=\"desk@example.test, other@example.test\""));
    assert!(body.contains("name=\"cc\" value=\"copied@example.test\""));
    assert!(body.contains("name=\"bcc\" value=\"\""));
    assert!(body.contains("name=\"reply_message_guid\""));
    assert!(!body.contains("private@example.test") && !body.contains("fixture-9@example.test"));
    for ua in [
        "ReaderWrongAccount",
        "ReaderWrongMailbox",
        "ReaderWrongUid",
        "ReaderStale",
    ] {
        assert_eq!(
            perform(&app, "GET", &url, "", ua).response.status_code,
            409,
            "{ua}"
        );
    }
    for suffix in ["&mailbox_guid=abc", "&message_guid=missing"] {
        assert_eq!(
            perform(
                &app,
                "GET",
                &format!("/compose?mode=reply&mailbox=INBOX&uid=9{suffix}"),
                "",
                "ordinary"
            )
            .response
            .status_code,
            400
        );
    }
    let forward = perform(
        &app,
        "GET",
        &url.replace("mode=reply-all", "mode=forward"),
        "",
        "ReplyRecipients",
    );
    assert_eq!(forward.response.status_code, 200);
    assert!(!body_text(&forward).contains("name=\"reply_message_guid\""));
}

#[test]
fn reply_submission_derives_threading_from_one_authenticated_original_snapshot() {
    let app = app();
    let form = format!("{}{}", base_form(), reference_form());
    let sent = perform(&app, "POST", "/send", &form, "ReplyRecipients");
    assert_eq!(sent.response.status_code, 303);
    assert_eq!(
        sent.audit_events
            .iter()
            .filter(|event| event.action == "stub_source_read")
            .count(),
        1
    );
    let submitted = app.gateway.submitted.lock().unwrap();
    assert_eq!(submitted.len(), 1);
    let thread = submitted[0].reply_thread.as_ref().unwrap();
    assert_eq!(thread.in_reply_to(), Some("<fixture-9@example.test>"));
    assert_eq!(
        thread.references(),
        "<root@example.test> <fixture-9@example.test>"
    );
    for attachments in [
        vec![],
        vec![UploadedAttachment::new(
            ComposePolicy::default(),
            "public.txt",
            "text/plain",
            b"synthetic attachment".to_vec(),
        )
        .unwrap()],
    ] {
        let mut compose = submitted[0].clone();
        compose.attachments = attachments;
        let wire =
            String::from_utf8(build_submission_message("alice@example.com", &compose).unwrap())
                .unwrap();
        assert_eq!(
            wire.matches("In-Reply-To: <fixture-9@example.test>\r\n")
                .count(),
            1
        );
        assert!(wire.contains("References: <root@example.test> <fixture-9@example.test>\r\n"));
        assert!(!wire.contains("Bcc:") && !wire.contains("private@example.test"));
    }
}

#[test]
fn forged_sender_threading_and_stale_originals_never_save_or_submit() {
    let app = app();
    let base = base_form();
    for path in ["/send", "/drafts/save"] {
        for form in [
            base.replace("from=alice%40example.com", "from=other%40example.test"),
            format!("{base}&in_reply_to=%3Cforged%40example.test%3E"),
            format!("{base}&references=%3Cforged%40example.test%3E"),
            format!("{base}&reply_uid=9"),
            format!(
                "{base}{}",
                reference_form().replace("reply_uid=9", "reply_uid=09")
            ),
        ] {
            let response = perform(&app, "POST", path, &form, "ordinary");
            assert_eq!(response.response.status_code, 400);
            assert!(!response.audit_events.iter().any(|event| [
                "stub_send_ok",
                "stub_draft_save",
                "stub_source_read"
            ]
            .contains(&event.action)));
        }
        let form = format!("{base}{}", reference_form());
        for ua in [
            "SourceStale",
            "SourceWrongAccount",
            "SourceWrongSession",
            "SourceWrongMailbox",
            "SourceWrongUid",
            "SourceUnavailable",
        ] {
            let response = perform(&app, "POST", path, &form, ua);
            assert_eq!(
                response.response.status_code,
                if ua == "SourceUnavailable" { 503 } else { 409 },
                "{ua}"
            );
            assert!(!response
                .audit_events
                .iter()
                .any(|event| ["stub_send_ok", "stub_draft_save"].contains(&event.action)));
        }
        let csrf = perform(
            &app,
            "POST",
            path,
            &form.replace(&StubGateway::validated_session().record.csrf_token, "wrong"),
            "ordinary",
        );
        assert_eq!(csrf.response.status_code, 403);
        assert!(!csrf
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
        let unauthenticated = app.handle_request(&request("POST", path, &[], &form), "127.0.0.1");
        assert_eq!(unauthenticated.response.status_code, 303);
        assert!(!unauthenticated
            .audit_events
            .iter()
            .any(|event| event.action == "stub_source_read"));
    }
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
}

#[test]
fn saved_reply_keeps_its_server_owned_thread_after_source_is_unavailable() {
    let app = app();
    let saved = perform(
        &app,
        "POST",
        "/drafts/save",
        &format!("{}{}", base_form(), reference_form()),
        "ReplyRecipients",
    );
    assert_eq!(saved.response.status_code, 303);
    let location = location_header(&saved);
    let id = location.trim_start_matches("/draft?id=");
    let expected = app
        .gateway
        .drafts
        .lock()
        .unwrap()
        .get(id)
        .unwrap()
        .request
        .reply_thread
        .clone();
    assert!(expected.is_some());
    let resumed = perform(&app, "GET", &location, "", "SourceUnavailable");
    assert_eq!(resumed.response.status_code, 200);
    assert!(!body_text(&resumed).contains("name=\"reply_mailbox\""));
    let form = format!("{}&draft_id={id}&draft_revision=1", base_form());
    assert_eq!(
        perform(
            &app,
            "POST",
            "/drafts/save",
            &format!("{form}{}", reference_form()),
            "ordinary"
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        perform(&app, "POST", "/drafts/save", &form, "SourceUnavailable")
            .response
            .status_code,
        303
    );
    assert_eq!(
        app.gateway
            .drafts
            .lock()
            .unwrap()
            .get(id)
            .unwrap()
            .request
            .reply_thread,
        expected
    );
    let sent = perform(
        &app,
        "POST",
        "/send",
        &form.replace("draft_revision=1", "draft_revision=2"),
        "SourceUnavailable",
    );
    assert_eq!(sent.response.status_code, 303);
    assert!(!sent
        .audit_events
        .iter()
        .any(|event| event.action == "stub_source_read"));
    assert_eq!(
        app.gateway.submitted.lock().unwrap()[0].reply_thread,
        expected
    );
}
