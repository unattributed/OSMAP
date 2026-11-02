// Included only by http.rs's #[cfg(test)] module; these test UI copy, not handlers.
use super::*;

#[test]
fn refused_protected_reader_does_not_report_known_empty_attachments() {
    let fixture = app();
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        crate::auth::AuthenticationPolicy::default(),
        "attachment-refusal-component",
        "127.0.0.1",
        "OSMAP/AttachmentComponent",
    )
    .unwrap();
    let BrowserMessageViewDecision::Rendered { mut rendered, .. } = fixture
        .gateway
        .view_message(&context, &session, "INBOX", 9)
        .decision
    else {
        panic!("existing reader fixture must render")
    };
    rendered.openpgp = Some(crate::openpgp_reader_ui::ReaderState::Refused(
        crate::protected_message::ProtectedError::Locked,
    ));
    rendered.attachments.clear();
    rendered.body_text_for_compose.clear();
    rendered.body_html = TrustedHtml::from_template("<p>Mailbox key locked.</p>".into());
    let standalone = crate::http_ui::render_message_view_page(
        "alice@example.com",
        "synthetic-csrf",
        &rendered,
        None,
        &[],
    );
    let reader = crate::http_ui::MailReaderContext {
        pane: crate::http_ui::SelectedMessagePane::Ready(rendered),
        ..Default::default()
    };
    let view = crate::mail_list::ListViewState::from_query(&BTreeMap::new()).unwrap();
    let coordinated = crate::http_ui::render_message_list_page(
        "alice@example.com",
        "synthetic-csrf",
        "INBOX",
        &[],
        None,
        crate::http_ui::MessageListBulkActions {
            archive_mailbox_name: None,
            move_destinations: &[],
        },
        crate::http_ui::MessageListSortLinks {
            view: &view,
            search_query: None,
            search_scope: None,
            reader: &reader,
        },
    );
    for page in [&standalone, &coordinated] {
        assert!(page.contains("Attachments unavailable"));
        assert!(!page.contains("Attachments (0)"));
        assert!(!page.contains("No attachments."));
        assert!(!page.contains("href=\"/attachment?"));
        assert!(page.contains("data-openpgp-reader-states=\"refused\""));
        assert!(page.contains("View source"));
    }
}

#[test]
fn ordinary_empty_and_decrypted_attachment_counts_remain_distinct() {
    let fixture = app();
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        crate::auth::AuthenticationPolicy::default(),
        "attachment-success-component",
        "127.0.0.1",
        "OSMAP/AttachmentComponent",
    )
    .unwrap();
    let BrowserMessageViewDecision::Rendered { mut rendered, .. } = fixture
        .gateway
        .view_message(&context, &session, "INBOX", 9)
        .decision
    else {
        panic!("existing reader fixture must render")
    };
    let mut decoded = rendered.attachments[0].clone();
    decoded.filename = Some("decoded.bin".into());
    decoded.size_hint_bytes = 4;
    rendered.attachments.clear();
    rendered.metadata.as_mut().unwrap().protection =
        crate::message_metadata::MessageProtection::Plain;
    let ordinary = crate::http_ui::render_message_view_page(
        "alice@example.com",
        "synthetic-csrf",
        &rendered,
        None,
        &[],
    );
    assert!(ordinary.contains("No attachments."));
    assert!(ordinary.contains("Attachments (0)"));
    assert!(!ordinary.contains("Attachments unavailable"));
    rendered.openpgp = Some(crate::openpgp_reader_ui::ReaderState::Assessed(
        crate::protected_message::ProtectionState {
            decrypted_on_mail_host: true,
            signature: crate::protected_message::SignatureValidity::Unsigned,
            signer_identity: crate::protected_message::SignerIdentityState::NotApplicable,
            signer_primary_fingerprint: None,
            key_validity: None,
        },
    ));
    rendered.metadata.as_mut().unwrap().protection =
        crate::message_metadata::MessageProtection::Encrypted;
    rendered.attachments.push(decoded);
    let decrypted = crate::http_ui::render_message_view_page(
        "alice@example.com",
        "synthetic-csrf",
        &rendered,
        None,
        &[],
    );
    assert!(decrypted.contains("Attachments (1)"));
    assert!(decrypted.contains("decoded.bin"));
    assert!(decrypted.contains("href=\"/attachment?") && decrypted.contains("part=1.2"));
    assert!(
        !decrypted.contains("No attachments.") && !decrypted.contains("Attachments unavailable")
    );
    let reader = crate::http_ui::MailReaderContext {
        pane: crate::http_ui::SelectedMessagePane::Ready(rendered),
        ..Default::default()
    };
    let view = crate::mail_list::ListViewState::from_query(&BTreeMap::new()).unwrap();
    let coordinated = crate::http_ui::render_message_list_page(
        "alice@example.com",
        "synthetic-csrf",
        "INBOX",
        &[],
        None,
        crate::http_ui::MessageListBulkActions {
            archive_mailbox_name: None,
            move_destinations: &[],
        },
        crate::http_ui::MessageListSortLinks {
            view: &view,
            search_query: None,
            search_scope: None,
            reader: &reader,
        },
    );
    assert!(coordinated.contains("decoded.bin") && coordinated.contains("href=\"/attachment?"));
    assert!(!coordinated.contains("unknown until decrypted"));
    for page in [&decrypted, &coordinated] {
        assert!(!page.contains("4 bytes · isolated download"));
        assert!(page.contains("Encoded size hint: 4 bytes."));
    }
}

#[test]
fn encrypted_list_does_not_count_outer_parts_as_known_inner_attachments() {
    let mut metadata = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9);
    metadata.attachment_count = Some(2);
    metadata.attachments = None;
    for protection in [
        crate::message_metadata::MessageProtection::Encrypted,
        crate::message_metadata::MessageProtection::Plain,
    ] {
        metadata.protection = protection;
        let mut rows = vec![MessageSummary {
            mailbox_name: "INBOX".into(),
            uid: 9,
            flags: Vec::new(),
            date_received: "2026-11-03 00:00:00 +0000".into(),
            size_virtual: 512,
            subject: Some("Synthetic attachment state".into()),
            from: Some("sender@example.test".into()),
            to: Some("alice@example.com".into()),
            metadata: Some(metadata.clone()),
        }];
        let mut view = crate::mail_list::ListViewState::from_query(&BTreeMap::new()).unwrap();
        view.apply_messages(&mut rows);
        let reader = crate::http_ui::MailReaderContext::default();
        let page = crate::http_ui::render_message_list_page(
            "alice@example.com",
            "synthetic-csrf",
            "INBOX",
            &rows,
            None,
            crate::http_ui::MessageListBulkActions {
                archive_mailbox_name: None,
                move_destinations: &[],
            },
            crate::http_ui::MessageListSortLinks {
                view: &view,
                search_query: None,
                search_scope: None,
                reader: &reader,
            },
        );
        if protection == crate::message_metadata::MessageProtection::Encrypted {
            let copy = page.as_str().to_ascii_lowercase();
            assert!(copy.contains("unknown") && copy.contains("decrypt"));
            assert!(!page.contains("data-attachment-count=\"2\""));
            assert!(!page.contains(">2 attachments</span>"));
        } else {
            assert!(page.contains("data-attachment-count=\"2\""));
            assert!(page.contains(">2 attachments</span>"));
        }
    }
}

#[test]
fn fragment_errors_have_one_main_heading_and_return_navigation_in_the_active_theme() {
    for (path, status, heading) in [
        ("/missing", 404, "Not Found"),
        ("/search?field=invalid", 400, "Invalid Search Request"),
        (
            "/attachment?mailbox=INBOX&uid=9&part=1.99",
            404,
            "Attachment Not Found",
        ),
    ] {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers
            .get_mut("cookie")
            .expect("fixture cookie")
            .push_str("; osmap_appearance=dark");
        let result = app().handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, status);
        let body = body_text(&result);
        assert_eq!(body.matches("<main ").count(), 1, "{path}");
        assert_eq!(body.matches("<h1").count(), 1, "{path}");
        assert!(body.contains(heading), "{path}");
        if path.starts_with("/attachment") {
            assert!(
                body.contains("Back to message")
                    && body.contains("/message?mailbox=INBOX&amp;uid=9")
            );
        } else {
            assert!(body.contains("Return to mail"));
        }
        assert!(body.contains("data-appearance=\"dark\""));
    }
}

#[test]
fn compact_security_states_do_not_claim_undelivered_capabilities() {
    let reader = body_text(&authenticated_get("/message?mailbox=INBOX&uid=9"));
    assert!(reader.contains("View source") && reader.contains("view=source"));
    let mut legacy = request(
        "GET",
        "/message?mailbox=INBOX&uid=9",
        &authenticated_headers(),
        "",
    );
    legacy
        .headers
        .insert("user-agent".into(), "OSMAP/LegacyMetadata".into());
    assert!(
        body_text(&app().handle_request(&legacy, "127.0.0.1")).contains("Source view unavailable")
    );
    assert!(!reader.contains("Source view escaped"));
    assert!(reader.contains("Decryption</dt><dd>not produced"));
    assert!(reader.contains("data-openpgp-reader-states=\"unassessed\""));
    assert!(!reader.contains("Decrypted locally"));
    assert!(reader.contains("<details class=\"openpgp-reader-states\""));
    assert!(reader.contains("data-protected-body-panel=\"true\""));
    let compose = body_text(&authenticated_get("/compose"));
    assert!(compose.contains("This message will be sent without OpenPGP protection."));
    assert!(!compose.contains("name=\"openpgp"));
    assert!(compose.contains("Send Message and Save Draft use unencrypted message content"));
    let settings = body_text(&authenticated_get("/settings"));
    assert!(!settings.contains("action=\"/search\""));
    assert!(settings.contains("aria-labelledby=\"general-privacy-title\""));
    assert!(settings.contains("Blocked by message rendering policy"));
    assert!(settings.contains("Source is never active HTML"));
    assert!(!settings.to_ascii_lowercase().contains("zero-knowledge"));
    assert!(!settings.contains("name=\"openpgp"));
    assert!(settings.contains("id=\"general-signing\" name=\"pgp_sign\""));
    assert!(settings.contains("id=\"general-encryption\" name=\"pgp_encrypt\""));
    assert!(settings.contains("OpenPGP choices apply to newly opened messages"));
    assert!(!settings.contains("OpenPGP signing and encryption are unavailable"));
    let mut unavailable = request("GET", "/settings", &authenticated_headers(), "");
    unavailable
        .headers
        .insert("user-agent".into(), "OSMAP/CompositionUnavailable".into());
    let settings = body_text(&app().handle_request(&unavailable, "127.0.0.1"));
    assert!(settings.contains("disabled aria-label=\"OpenPGP signing, unavailable\""));
    assert!(settings.contains("disabled aria-label=\"Encryption, unavailable\""));
}
