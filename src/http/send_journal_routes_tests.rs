use super::*;
pub(super) fn intent(html: &str) -> String {
    html.split("name=\"send_intent\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string()
}
#[test]
fn native_journal_saved_handoff_and_repeat_posts_dispatch_once() {
    let app = app();
    let get = app.handle_request(
        &request("GET", "/compose", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    let original = intent(&body_text(&get));
    let fields = format!("csrf_token={}&send_intent={original}&to=bob%40example.com&subject=Synthetic&body=Retained%20Unicode%20%F0%9F%A6%8A", StubGateway::validated_session().record.csrf_token);
    let save = app.handle_request(
        &request(
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &fields,
        ),
        "127.0.0.1",
    );
    assert_eq!(save.response.status_code, 303, "{}", body_text(&save));
    let location = location_header(&save);
    let id = location.strip_prefix("/draft?id=").unwrap();
    let resume = app.handle_request(
        &request("GET", &location, &authenticated_headers(), ""),
        "127.0.0.1",
    );
    let saved_intent = intent(&body_text(&resume));
    assert_ne!(original, saved_intent);
    let send_fields = format!(
        "{}&draft_id={id}&draft_revision=1",
        fields.replace(&original, &saved_intent)
    );
    let accepted = app.handle_request(
        &request(
            "POST",
            "/send",
            &authenticated_same_origin_headers(),
            &send_fields,
        ),
        "127.0.0.1",
    );
    assert_eq!(
        accepted.response.status_code,
        303,
        "{}",
        body_text(&accepted)
    );
    assert!(location_header(&accepted).starts_with("/compose?receipt="));
    for (path, posted) in [
        ("/send", &send_fields),
        ("/send", &fields),
        ("/drafts/save", &fields),
    ] {
        let repeated = app.handle_request(
            &request("POST", path, &authenticated_same_origin_headers(), posted),
            "127.0.0.1",
        );
        assert_eq!(repeated.response.status_code, 200);
        assert!(!body_text(&repeated).contains("action=\"/send\""));
    }
    assert_eq!(app.gateway.submitted.lock().unwrap().len(), 1);
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
    let forged = app.handle_request(
        &request("GET", "/compose?sent=1", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert_eq!(forged.response.status_code, 400);
    assert!(!body_text(&forged).contains("accepted for submission"));
    let missing = app.handle_request(
        &request(
            "GET",
            "/compose?receipt=100.ffffffffffffffffffffffffffffffff",
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(missing.response.status_code, 404);
}
#[test]
fn native_validation_retains_intent_without_minting_another() {
    let app = app();
    let get = app.handle_request(
        &request("GET", "/compose", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    let original = intent(&body_text(&get));
    let fields = format!(
        "csrf_token={}&send_intent={original}&to=unfinished&subject=Synthetic&body=Keep%20this",
        StubGateway::validated_session().record.csrf_token
    );
    let rejected = app.handle_request(
        &request(
            "POST",
            "/send",
            &authenticated_same_origin_headers(),
            &fields,
        ),
        "127.0.0.1",
    );
    assert_eq!(
        rejected.response.status_code,
        400,
        "{}",
        body_text(&rejected)
    );
    assert_eq!(intent(&body_text(&rejected)), original);
    assert!(body_text(&rejected).contains("Keep this"));
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
}

#[test]
fn native_authoring_actions_preserve_intent_or_switch_to_confirmed_revision() {
    for (extra, expected) in [
        ("compose_action=preview", 303),
        ("compose_action=preflight", 303),
        ("compose_action=format-bold", 303),
        ("compose_action=theme-dark", 303),
        (
            "compose_action=format-link&format_url=javascript%3Aalert%281%29",
            400,
        ),
        (
            "compose_action=add-contact&contact_id=missing&contact_revision=1&contact_target=to",
            409,
        ),
    ] {
        let app = app();
        let get = app.handle_request(
            &request("GET", "/compose", &authenticated_headers(), ""),
            "127.0.0.1",
        );
        let original = intent(&body_text(&get));
        let fields = format!("csrf_token={}&send_intent={original}&to=bob%40example.com&subject=Synthetic&body=Exact%20text%20%F0%9F%A6%8A&{extra}", StubGateway::validated_session().record.csrf_token);
        let response = app.handle_request(
            &request(
                "POST",
                "/drafts/save",
                &authenticated_same_origin_headers(),
                &fields,
            ),
            "127.0.0.1",
        );
        assert_eq!(
            response.response.status_code,
            expected,
            "{extra}: {}",
            body_text(&response)
        );
        if expected == 303 {
            let get = app.handle_request(
                &request(
                    "GET",
                    &location_header(&response),
                    &authenticated_headers(),
                    "",
                ),
                "127.0.0.1",
            );
            assert_ne!(intent(&body_text(&get)), original);
            let repeat = app.handle_request(
                &request(
                    "POST",
                    "/drafts/save",
                    &authenticated_same_origin_headers(),
                    &fields,
                ),
                "127.0.0.1",
            );
            assert!(body_text(&repeat).contains("This intent already has a recorded action"));
            assert!(!body_text(&repeat).contains("action=\"/send\""));
        } else {
            assert_eq!(intent(&body_text(&response)), original);
            assert!(body_text(&response).contains("Exact text 🦊"));
        }
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
    }
}

#[test]
fn native_paused_save_retains_readonly_text_without_editable_retry() {
    let app = app();
    let get = app.handle_request(
        &request("GET", "/compose", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    let original = intent(&body_text(&get));
    let session = StubGateway::validated_session();
    let _guard = app
        .gateway
        .send_journal
        .account_guard(&session.record.canonical_username, 100)
        .unwrap();
    let fields = format!(
        "csrf_token={}&send_intent={original}&to=bob%40example.com&body=Keep%20this%20text",
        session.record.csrf_token
    );
    let response = app.handle_request(
        &request(
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &fields,
        ),
        "127.0.0.1",
    );
    assert_eq!(response.response.status_code, 503);
    let html = body_text(&response);
    assert!(html.contains("This form is paused") && html.contains("Keep this text"));
    assert!(!html.contains("Nothing was saved or sent") && !html.contains("action=\"/send\""));
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
}

#[test]
fn native_missing_intent_is_refused_without_substitution_or_mutation() {
    let app = app();
    let fields = format!(
        "csrf_token={}&to=bob%40example.com&body=Public",
        StubGateway::validated_session().record.csrf_token
    );
    for path in ["/send", "/drafts/save"] {
        let response = app.handle_request(
            &request("POST", path, &authenticated_same_origin_headers(), &fields),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 400);
        assert!(body_text(&response).contains("No new intent was substituted"));
    }
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
}

#[test]
fn consumed_saved_recovery_is_exact_readonly_and_account_owned() {
    for marker in [
        "SendUnconfirmed",
        "SentCopyUnconfirmed",
        "DraftCleanupFailure",
    ] {
        let mut app = app();
        app.gateway.browser_fixture_accounts = true;
        let session = StubGateway::validated_session();
        let original = "Saved </textarea><script>inert</script> & 🦊\nsecond";
        let fields = format!(
            "csrf_token={}&to=bob%40example.com&body={}",
            session.record.csrf_token,
            url_encode(original)
        );
        let new = native_compose_request(
            &app,
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &fields,
        );
        let parsed = parse_urlencoded_form(&new.body, 128, 100000).unwrap();
        let original_intent = &parsed["send_intent"];
        let saved = app.handle_request(&new, "127.0.0.1");
        let path = location_header(&saved);
        let id = path.strip_prefix("/draft?id=").unwrap();
        {
            let mut drafts = app.gateway.drafts.lock().unwrap();
            drafts.get_mut(id).unwrap().request.attachments.push(
                UploadedAttachment::new(
                    ComposePolicy::default(),
                    "saved.txt",
                    "text/plain",
                    b"first".to_vec(),
                )
                .unwrap(),
            );
        }
        if marker == "DraftCleanupFailure" {
            app.gateway.fail_draft_delete = Some(id.into());
        }
        let mut send = native_compose_request(
            &app,
            "POST",
            "/send",
            &authenticated_same_origin_headers(),
            &format!("{fields}&draft_id={id}&draft_revision=1"),
        );
        send.headers
            .insert("user-agent".into(), format!("OSMAP/{marker}"));
        let result = app.handle_request(&send, "127.0.0.1");
        assert!(matches!(result.response.status_code, 200 | 503));
        for url in [&path, &format!("/compose?receipt={original_intent}")] {
            let response = app.handle_request(
                &request("GET", url, &authenticated_headers(), ""),
                "127.0.0.1",
            );
            assert_eq!(response.response.status_code, 200);
            let html = body_text(&response);
            assert!(
                html.contains(escape_html(original).as_str())
                    && html.contains("saved.txt (5 bytes)")
            );
            assert!(
                html.contains("Saved version for comparison")
                    && html.contains("Drafts expire after 30 days")
            );
            assert_eq!(html.matches(" readonly ").count(), 5);
            assert!(
                !html.contains("action=\"/send\"")
                    && !html.contains("id=\"compose-form\"")
                    && !html.contains("name=\"send_intent\"")
            );
            assert_eq!(
                html.matches("type=\"submit\" disabled data-header-theme")
                    .count(),
                2
            );
        }
        let mut foreign = request("GET", &path, &authenticated_headers(), "");
        foreign
            .headers
            .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        let denied = app.handle_request(&foreign, "127.0.0.1");
        assert_eq!(denied.response.status_code, 404);
        assert!(!body_text(&denied).contains("saved.txt"));
        let guard = app
            .gateway
            .send_journal
            .account_guard(&session.record.canonical_username, 100)
            .unwrap();
        let unavailable = app.handle_request(
            &request("GET", &path, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(unavailable.response.status_code, 503);
        assert!(!body_text(&unavailable).contains("saved.txt"));
        let receipt = app.handle_request(
            &request(
                "GET",
                &format!("/compose?receipt={original_intent}"),
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert!(body_text(&receipt).contains("Recovery availability could not be checked"));
        drop(guard);
        assert_eq!(
            app.gateway.drafts.lock().unwrap()[id].request.body,
            original
        );
        app.gateway.drafts.lock().unwrap().remove(id);
        let absent = app.handle_request(
            &request(
                "GET",
                &format!("/compose?receipt={original_intent}"),
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert!(body_text(&absent).contains("recovery draft is absent"));
        assert_eq!(app.gateway.submitted.lock().unwrap().len(), 1);
    }
}

#[test]
fn native_receipt_read_failure_preserves_readonly_post_without_mutation() {
    use sha2::{Digest, Sha256};
    for unreadable in [false, true] {
        for path in ["/send", "/drafts/save"] {
            let root = std::env::temp_dir().join(format!(
                "osmap-receipt-read-failure-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            let mut app = app();
            app.gateway.send_journal = crate::send_journal::SendJournal::new(root.clone());
            let session = StubGateway::validated_session();
            let account = &session.record.canonical_username;
            let get = app.handle_request(
                &request("GET", "/compose", &authenticated_headers(), ""),
                "127.0.0.1",
            );
            let original = intent(&body_text(&get));
            let private = crate::private_account_file::PrivateAccountFile::new(
                root.clone(), "osmap-send-journal-v1", 1024 * 1024,
            );
            let corrupt = b"{\"version\":99}\n";
            private.lock(account).unwrap().write(corrupt).unwrap();
            let mut hash = Sha256::new();
            hash.update(b"osmap-send-journal-v1\0");
            hash.update(account.as_bytes());
            let record = root.join(format!("{:x}.json", hash.finalize()));
            if unreadable {
                std::fs::remove_file(&record).unwrap();
                std::fs::create_dir(&record).unwrap();
            }
            assert!(app.gateway.send_receipt(&session, &original).is_err());
            let text = "Unsaved </textarea><script>inert</script> & 🦊";
            let mut multipart = String::new();
            for (name, value) in [
                ("csrf_token", session.record.csrf_token.as_str()),
                ("send_intent", original.as_str()),
                ("to", "bob@example.com"),
                ("cc", "copy@example.com"),
                ("bcc", "hidden@example.com"),
                ("subject", "Subject & exact"),
                ("body", text),
                ("body_format", "formatted"),
            ] {
                multipart.push_str(&format!("--read-failure\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
            }
            for filename in ["public-one.txt", "public-two.txt"] {
                multipart.push_str(&format!("--read-failure\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\nfirst\r\n"));
            }
            multipart.push_str("--read-failure--\r\n");
            let mut req = request("POST", path, &authenticated_same_origin_headers(), &multipart);
            req.headers.insert("content-type".into(), "multipart/form-data; boundary=read-failure".into());
            let response = app.handle_request(&req, "127.0.0.1");
            assert_eq!(response.response.status_code, 503);
            let html = body_text(&response);
            assert!(html.contains("This form is paused"));
            assert!(html.contains(&format!("href=\"/compose?receipt={original}\" target=\"_blank\" rel=\"noopener noreferrer\"")));
            assert!(!html.contains("http-equiv=\"refresh\""));
            for value in [text, "bob@example.com", "copy@example.com", "hidden@example.com", "Subject & exact"] {
                assert!(html.contains(escape_html(value).as_str()), "parsed field missing");
            }
            assert!(html.contains("Message format: formatted"));
            for filename in ["public-one.txt", "public-two.txt"] {
                assert!(html.contains(&format!("{filename} (5 bytes)")));
            }
            assert_eq!(html.matches(" readonly>").count(), 5);
            for absent in ["action=\"/send\"", "action=\"/drafts/save\"", "name=\"send_intent\"", "<script>", "Nothing was saved or sent"] {
                assert!(!html.contains(absent));
            }
            assert_eq!(html.matches("type=\"submit\" disabled data-header-theme").count(), 2);
            assert!(app.gateway.submitted.lock().unwrap().is_empty());
            assert!(app.gateway.drafts.lock().unwrap().is_empty());
            if unreadable {
                assert!(record.is_dir());
                assert_eq!(std::fs::read_dir(&record).unwrap().count(), 0);
            } else {
                assert_eq!(std::fs::read(&record).unwrap(), corrupt);
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
