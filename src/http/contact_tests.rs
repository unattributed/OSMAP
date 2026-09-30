use super::*;
use crate::contacts::{ContactChange, ContactStore};

fn fixture() -> (BrowserApp<StubGateway>, std::path::PathBuf, ContactStore) {
    let root = std::env::temp_dir().join(format!(
        "osmap-contact-http-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let store = ContactStore::new(&root);
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            contacts_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        },
    );
    (app, root, store)
}

fn form(extra: &str) -> String {
    format!(
        "csrf_token={}&{extra}",
        StubGateway::validated_session().record.csrf_token
    )
}

fn perform(
    app: &BrowserApp<StubGateway>,
    method: &str,
    path: &str,
    form: &str,
) -> HandledHttpResponse {
    app.handle_request(
        &request(method, path, &authenticated_same_origin_headers(), form),
        "127.0.0.1",
    )
}

fn add(store: &ContactStore) -> crate::contacts::ContactBook {
    store
        .change(
            "alice@example.com",
            0,
            ContactChange::Save {
                id: None,
                display_name: "Desk <Public>".into(),
                address: "desk@example.test".into(),
            },
        )
        .unwrap()
}

#[test]
fn contact_routes_require_session_origin_csrf_and_exact_form_without_mutation() {
    let (app, root, store) = fixture();
    let body = form("revision=0&name=Desk&address=desk%40example.test");
    for (case, status) in [
        ("session", 303),
        ("origin", 403),
        ("csrf", 403),
        ("extra", 400),
        ("duplicate", 400),
        ("revision", 400),
        ("control", 400),
        ("type", 400),
    ] {
        let mut req = request(
            "POST",
            "/contacts/save",
            &authenticated_same_origin_headers(),
            &body,
        );
        match case {
            "session" => {
                req.headers.remove("cookie");
            }
            "origin" => {
                req.headers
                    .insert("origin".into(), "https://outside.example.test".into());
            }
            "csrf" => {
                req.body = body
                    .replace(&StubGateway::validated_session().record.csrf_token, "wrong")
                    .into_bytes();
            }
            "extra" => req.body.extend_from_slice(b"&account=bob"),
            "duplicate" => req.body.extend_from_slice(b"&revision=0"),
            "revision" => req.body = body.replace("revision=0", "revision=00").into_bytes(),
            "control" => req.body = body.replace("name=Desk", "name=bad%0Aname").into_bytes(),
            "type" => {
                req.headers
                    .insert("content-type".into(), "application/json".into());
            }
            _ => unreachable!(),
        }
        let result = app.handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, status, "{case}");
        assert_eq!(store.load("alice@example.com").unwrap().revision, 0);
        assert!(!result
            .audit_events
            .iter()
            .any(|e| e.action == "contact_saved"));
    }
    assert_eq!(
        perform(&app, "POST", "/contacts/save", &body)
            .response
            .status_code,
        303
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn contact_edit_delete_revision_owner_and_confirmation_are_enforced() {
    let (app, root, store) = fixture();
    let book = add(&store);
    let id = &book.contacts[0].id;
    let html = body_text(&perform(&app, "GET", "/contacts", ""));
    assert!(html.contains("Desk &lt;Public&gt;"));
    assert!(!html.contains("Desk <Public>"));
    for (suffix, status) in [("revision=0", 409), ("revision=1&unexpected=1", 400)] {
        assert_eq!(
            perform(&app, "GET", &format!("/contacts?edit={id}&{suffix}"), "")
                .response
                .status_code,
            status
        );
    }
    assert_eq!(
        perform(
            &app,
            "GET",
            &format!("/contacts?delete={id}&revision=1"),
            ""
        )
        .response
        .status_code,
        200
    );
    assert_eq!(store.load("alice@example.com").unwrap(), book);
    let delete = form(&format!("revision=1&id={id}"));
    assert_eq!(
        perform(&app, "POST", "/contacts/delete", &delete)
            .response
            .status_code,
        400
    );
    let mut foreign = request(
        "POST",
        "/contacts/delete",
        &authenticated_same_origin_headers(),
        &format!("csrf_token={}&revision=0&id={id}&confirm=1", "c".repeat(64)),
    );
    foreign
        .headers
        .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
    assert_eq!(
        app.handle_request(&foreign, "127.0.0.1")
            .response
            .status_code,
        404
    );
    assert_eq!(store.load("alice@example.com").unwrap(), book);
    assert_eq!(
        perform(&app, "POST", "/contacts/delete", &(delete + "&confirm=1"))
            .response
            .status_code,
        303
    );
    assert!(store.load("alice@example.com").unwrap().contacts.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn selected_contact_saves_explicit_roles_and_keeps_original_thread_without_sending() {
    let (app, root, store) = fixture();
    let book = add(&store);
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    for target in ["to", "cc", "bcc"] {
        let body=form(&format!("from=alice%40example.com&to=original%40example.test&subject=Synthetic&body=Public&compose_action=add-contact&contact_id={}&contact_revision=1&contact_target={target}&reply_mailbox=INBOX&reply_uid=9&reply_mailbox_guid={}&reply_message_guid={}",book.contacts[0].id,version.mailbox_guid,version.message_guid));
        let saved = perform(&app, "POST", "/drafts/save", &body);
        assert_eq!(saved.response.status_code, 303);
        let drafts = app.gateway.drafts.lock().unwrap();
        let id = location_header(&saved)
            .trim_start_matches("/draft?id=")
            .to_string();
        let draft = drafts.get(&id).unwrap();
        let addresses = match target {
            "to" => &draft.request.recipients,
            "cc" => &draft.request.cc_recipients,
            _ => &draft.request.bcc_recipients,
        };
        assert!(addresses.iter().any(|a| a == "desk@example.test"));
        assert!(draft.request.reply_thread.is_some());
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
        assert_eq!(
            perform(&app, "POST", "/send", &body).response.status_code,
            400
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_or_invalid_contact_selection_retains_escaped_text_and_does_not_save() {
    let (app, root, store) = fixture();
    let book = add(&store);
    let base=form(&format!("to=original%40example.test&subject=Keep%20me&body=%3Cb%3Epublic%3C%2Fb%3E&compose_action=add-contact&contact_id={}&contact_revision=1&contact_target=to",book.contacts[0].id));
    for body in [
        base.replace("contact_revision=1", "contact_revision=0"),
        base.replace("contact_target=to", "contact_target=from"),
        base.replace(&book.contacts[0].id, "00000000000000000000000000000000"),
        base.replace("compose_action=add-contact", "compose_action=unknown"),
    ] {
        let result = perform(&app, "POST", "/drafts/save", &body);
        assert_eq!(result.response.status_code, 409);
        let html = body_text(&result);
        assert!(html.contains("value=\"Keep me\""));
        assert!(html.contains("&lt;b&gt;public&lt;/b&gt;"));
        assert!(!html.contains("<b>public</b>"));
        assert!(app.gateway.drafts.lock().unwrap().is_empty());
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn contact_snapshot_rejects_wrong_owner_and_invalid_initial_state() {
    let book = crate::contacts::ContactBook::empty("alice@example.com");
    assert!(book.ensure_account("alice@example.com").is_ok());
    assert!(book.ensure_account("bob@example.com").is_err());
    let mut invalid = book;
    invalid.contacts.push(crate::contacts::Contact {
        id: "0".repeat(32),
        display_name: "Desk".into(),
        address: "desk@example.test".into(),
    });
    assert!(invalid.ensure_account("alice@example.com").is_err());
}
