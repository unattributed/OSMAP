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
    let mut req = request(method, path, &authenticated_same_origin_headers(), form);
    if method == "POST" && matches!(path, "/send" | "/drafts/save") {
        add_native_compose_intent(app, &mut req);
    }
    app.handle_request(&req, "127.0.0.1")
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
            "to" => &draft.request.recipients_text,
            "cc" => &draft.request.cc_text,
            _ => &draft.request.bcc_text,
        };
        assert!(
            crate::mail_address::parse_address_list(ComposePolicy::default(), addresses)
                .unwrap()
                .iter()
                .any(|a| a == "desk@example.test")
        );
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

fn imported_recipient_fixture(
    account: &str,
    address: &str,
    fingerprints: &[char],
) -> crate::contacts::ImportedRecipientSnapshot {
    let keys = fingerprints.iter().map(|fp| serde_json::json!({
        "primary":{"fingerprint":fp.to_string().repeat(40),"algorithm":1,"bits":3072,
        "created":1,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,
        "can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},
        "subkeys":[],"email_addresses":[address]
    })).collect::<Vec<_>>();
    let inventory = crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&serde_json::json!({
        "version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":keys
    })).unwrap()).unwrap();
    crate::contacts::ImportedRecipientSnapshot::from_inventory(
        account,&crate::openpgp_bindings::BindingRecord::empty(account).unwrap(),&inventory,
    ).unwrap()
}

#[test]
fn imported_key_recipient_is_visible_and_adds_each_role_without_contact_write_or_send() {
    let (mut app, root, store) = fixture();
    let original = store.load("alice@example.com").unwrap();
    let snapshot = imported_recipient_fixture("alice@example.com","cBwZTCpU@protonmail.com",&['A']);
    let id = snapshot.choices[0].id.clone();
    app.gateway.compose_imported_recipients = Some(snapshot);
    let page = body_text(&perform(&app,"GET","/compose",""));
    assert!(page.contains("cBwZTCpU@protonmail.com"));
    assert!(page.contains(&id));
    for target in ["to","cc","bcc"] {
        // No saved-contact revision is supplied: this choice belongs to current
        // certificate metadata, not a fictitious persisted address-book row.
        let body = form(&format!("from=alice%40example.com&to=original%40example.test&subject=Keep&body=Public&compose_action=add-contact&contact_id={id}&contact_target={target}&pgp_encrypt=on&pgp_binding_revision=0"));
        let saved = perform(&app,"POST","/drafts/save",&body);
        assert_eq!(saved.response.status_code,303);
        let drafts = app.gateway.drafts.lock().unwrap();
        let draft_id = location_header(&saved).trim_start_matches("/draft?id=").to_owned();
        let draft = drafts.get(&draft_id).unwrap();
        let selected = match target { "to"=>&draft.request.recipients_text,"cc"=>&draft.request.cc_text,_=>&draft.request.bcc_text };
        assert!(crate::mail_address::parse_address_list(ComposePolicy::default(),selected).unwrap().iter().any(|address|address=="cBwZTCpU@protonmail.com"));
        assert!(draft.request.protection.encrypt);
        assert!(!draft.request.protection.sign);
        assert!(!draft.request.protection.encrypt_to_self);
        assert_eq!(store.load("alice@example.com").unwrap(),original);
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
        drop(drafts);
        assert_eq!(perform(&app,"POST","/send",&body).response.status_code,400);
    }
    assert!(!root.exists(), "read-only picker must not create the contact store");
}

#[test]
fn imported_selection_rechecks_ownership_and_current_membership_before_draft_write() {
    for mode in ["forged","foreign","removed","rebound","ambiguous","unavailable"] {
        let (mut app, root, store) = fixture();
        let original = store.load("alice@example.com").unwrap();
        let snapshot = imported_recipient_fixture("alice@example.com","key@example.test",&['A']);
        let mut id = snapshot.choices[0].id.clone();
        app.gateway.compose_imported_recipients = match mode {
            "foreign"=>Some(imported_recipient_fixture("bob@example.com","key@example.test",&['A'])),
            "removed"=>Some(imported_recipient_fixture("alice@example.com","key@example.test",&[])),
            "rebound"=>Some(imported_recipient_fixture("alice@example.com","key@example.test",&['B'])),
            "ambiguous"=>Some(imported_recipient_fixture("alice@example.com","key@example.test",&['A','B'])),
            "unavailable"=>None,
            _=>Some(snapshot),
        };
        if mode=="forged" {id=format!("key:{}","0".repeat(64));}
        let body=form(&format!("to=original%40example.test&subject=Keep%20me&body=%3Cb%3Epublic%3C%2Fb%3E&compose_action=add-contact&contact_id={id}&contact_target=to"));
        let refused=perform(&app,"POST","/drafts/save",&body);
        assert_eq!(refused.response.status_code,409,"{mode}");
        let html=body_text(&refused);
        assert!(html.contains("Keep me"));
        assert!(html.contains("&lt;b&gt;public&lt;/b&gt;"));
        assert!(app.gateway.drafts.lock().unwrap().is_empty());
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
        assert_eq!(store.load("alice@example.com").unwrap(),original);
        assert!(!root.exists(), "read-only picker must not create the contact store");
    }
}

#[test]
fn unavailable_contact_book_does_not_block_current_imported_recipient() {
    use std::os::unix::fs::PermissionsExt as _;
    let (mut app,root,store)=fixture();
    let snapshot=imported_recipient_fixture("alice@example.com","key@example.test",&['A']);
    let id=snapshot.choices[0].id.clone();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("blocked-contact-store"),b"public fixture, not a directory").unwrap();
    app.gateway.contacts_store=Some(ContactStore::new(root.join("blocked-contact-store")));
    app.gateway.compose_imported_recipients=Some(snapshot);
    let html=body_text(&perform(&app,"GET","/compose",""));
    assert!(html.contains("key@example.test"));
    assert!(html.contains("Saved contacts are unavailable."));
    let saved=perform(&app,"POST","/drafts/save",&form(&format!("subject=Keep&body=Public&compose_action=add-contact&contact_id={id}&contact_target=to")));
    assert_eq!(saved.response.status_code,303);
    let draft_id=location_header(&saved).trim_start_matches("/draft?id=").to_owned();
    let drafts=app.gateway.drafts.lock().unwrap();
    let draft=drafts.get(&draft_id).unwrap();
    assert!(!draft.request.protection.encrypt && !draft.request.protection.sign && !draft.request.protection.encrypt_to_self);
    drop(drafts);
    assert_eq!(store.load("alice@example.com").unwrap().revision,0);
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn imported_picker_mutation_keeps_session_origin_and_csrf_guards() {
    for (mode,status) in [("session",303),("origin",403),("csrf",403),("target",409)] {
        let (mut app,root,store)=fixture();
        let original=store.load("alice@example.com").unwrap();
        let snapshot=imported_recipient_fixture("alice@example.com","key@example.test",&['A']);
        let id=snapshot.choices[0].id.clone();
        app.gateway.compose_imported_recipients=Some(snapshot);
        let body=form(&format!("subject=Keep&body=Public&compose_action=add-contact&contact_id={id}&contact_target=to"));
        let mut req=request("POST","/drafts/save",&authenticated_same_origin_headers(),&body);
        add_native_compose_intent(&app,&mut req);
        match mode {
            "session"=>{req.headers.remove("cookie");},
            "origin"=>{req.headers.insert("origin".into(),"https://outside.example.test".into());},
            "csrf"=>{req.body=String::from_utf8(req.body).unwrap().replace(&StubGateway::validated_session().record.csrf_token,"wrong").into_bytes();},
            "target"=>{req.body=String::from_utf8(req.body).unwrap().replace("contact_target=to","contact_target=from").into_bytes();},
            _=>unreachable!(),
        }
        assert_eq!(app.handle_request(&req,"127.0.0.1").response.status_code,status,"{mode}");
        assert!(app.gateway.drafts.lock().unwrap().is_empty());
        assert!(app.gateway.submitted.lock().unwrap().is_empty());
        assert_eq!(store.load("alice@example.com").unwrap(),original);
        assert!(!root.exists(), "read-only picker must not create the contact store");
    }
}

fn directory_get(app: &BrowserApp<StubGateway>, path: &str, mode: &str) -> HandledHttpResponse {
    let mut req = request("GET", path, &authenticated_same_origin_headers(), "");
    req.headers.insert("user-agent".into(), mode.into());
    app.handle_request(&req, "127.0.0.1")
}

#[test]
fn contacts_directory_lists_searches_and_filters_current_owned_sources_without_writes() {
    let (app, root, store) = fixture();
    let before = add(&store);
    let page = body_text(&directory_get(&app, "/contacts", "KeyInventoryPractical"));
    for expected in ["<table", "Email address", "Encryption policy", "Desk &lt;Public&gt;", "second@example.test", "Off by default", "Require encryption"] {
        assert!(page.contains(expected), "{expected}");
    }
    let search = body_text(&directory_get(&app, "/contacts?q=second", "KeyInventoryPractical"));
    assert!(search.contains("second@example.test"));
    assert!(!search.contains("Desk &lt;Public&gt;"));
    let saved = body_text(&directory_get(&app, "/contacts?filter=saved", "KeyInventoryPractical"));
    assert!(saved.contains("Desk &lt;Public&gt;"));
    assert!(!saved.contains("second@example.test"));
    let imported = body_text(&directory_get(&app, "/contacts?filter=keys", "KeyInventoryPractical"));
    assert!(imported.contains("second@example.test"));
    assert!(!imported.contains("Desk &lt;Public&gt;"));
    let foreign = body_text(&directory_get(&app, "/contacts", "KeyInventoryPracticalForeign"));
    assert!(foreign.contains("Desk &lt;Public&gt;"));
    assert!(!foreign.contains("second@example.test"));
    assert!(!foreign.contains("bob@example.com"));
    assert_eq!(store.load("alice@example.com").unwrap(), before);
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn contacts_directory_rejects_invalid_queries_and_opens_only_explicit_editor() {
    let (app, root, store) = fixture();
    let before = add(&store);
    for query in ["filter=anything".into(), "new=0".into(), "new=1&edit=x&revision=1".into(), "revision=1".into(), "q=%0A".into(), format!("q={}", "x".repeat(201)), "account=bob".into()] {
        assert_eq!(perform(&app, "GET", &format!("/contacts?{query}"), "").response.status_code, 400, "{query}");
    }
    assert_eq!(perform(&app, "GET", "/contacts?new=1", "").response.status_code, 200);
    assert_eq!(store.load("alice@example.com").unwrap(), before);
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn contacts_write_links_revalidate_saved_and_imported_identity_without_get_persistence() {
    let (mut app, root, store) = fixture();
    let before = add(&store);
    let saved = &before.contacts[0].id;
    let page = perform(&app, "GET", &format!("/compose?contact_id={saved}&contact_revision=1"), "");
    assert_eq!(page.response.status_code, 200);
    assert!(body_text(&page).contains("value=\"desk@example.test\""));
    let snapshot = imported_recipient_fixture("alice@example.com", "key@example.test", &['A']);
    let key = snapshot.choices[0].id.clone();
    app.gateway.compose_imported_recipients = Some(snapshot);
    let page = perform(&app, "GET", &format!("/compose?contact_id={key}"), "");
    assert_eq!(page.response.status_code, 200);
    assert!(body_text(&page).contains("value=\"key@example.test\""));
    for path in [format!("/compose?contact_id={saved}&contact_revision=0"), format!("/compose?contact_id={}&contact_revision=1", "f".repeat(32)), format!("/compose?contact_id=key:{}", "0".repeat(64)), "/compose?contact_revision=1".into()] {
        assert_eq!(perform(&app, "GET", &path, "").response.status_code, 409);
    }
    for suffix in ["&to=outside%40example.test", "&mode=reply&mailbox=INBOX&uid=1", "&pgp_encrypt=on"] {
        assert_eq!(perform(&app, "GET", &format!("/compose?contact_id={key}{suffix}"), "").response.status_code, 400);
    }
    for mode in ["foreign", "removed", "rebound", "ambiguous", "unavailable"] {
        app.gateway.compose_imported_recipients = match mode {
            "foreign" => Some(imported_recipient_fixture("bob@example.com", "key@example.test", &['A'])),
            "removed" => Some(imported_recipient_fixture("alice@example.com", "key@example.test", &[])),
            "rebound" => Some(imported_recipient_fixture("alice@example.com", "key@example.test", &['B'])),
            "ambiguous" => Some(imported_recipient_fixture("alice@example.com", "key@example.test", &['A', 'B'])),
            _ => None,
        };
        assert_eq!(perform(&app, "GET", &format!("/compose?contact_id={key}"), "").response.status_code, 409, "{mode}");
    }
    let mut unsigned = request("GET", &format!("/compose?contact_id={saved}&contact_revision=1"), &[], "");
    unsigned.headers.insert("user-agent".into(), "Firefox/Test".into());
    assert_eq!(app.handle_request(&unsigned, "127.0.0.1").response.status_code, 303);
    assert_eq!(store.load("alice@example.com").unwrap(), before);
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn imported_contact_name_editor_prefills_only_a_current_owned_key_address() {
    let (mut app, root, store) = fixture();
    let snapshot = imported_recipient_fixture("alice@example.com", "key@example.test", &['A']);
    let id = snapshot.choices[0].id.clone();
    app.gateway.compose_imported_recipients = Some(snapshot);
    let page = perform(&app, "GET", &format!("/contacts?new=1&from_key={id}"), "");
    assert_eq!(page.response.status_code, 200);
    assert!(body_text(&page).contains("value=\"key@example.test\""));
    assert_eq!(store.load("alice@example.com").unwrap().revision, 0);
    assert!(!root.exists());
    for path in [format!("/contacts?from_key={id}"), "/contacts?new=1&from_key=not-a-key".into()] {
        assert_eq!(perform(&app, "GET", &path, "").response.status_code, 400);
    }
    app.gateway.compose_imported_recipients = None;
    assert_eq!(perform(&app, "GET", &format!("/contacts?new=1&from_key={id}"), "").response.status_code, 503);
    assert!(!root.exists());
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
}

#[test]
fn contacts_directory_keeps_imported_rows_when_the_saved_store_is_unavailable() {
    use std::os::unix::fs::PermissionsExt as _;
    let (mut app, root, _) = fixture();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(root.join("blocked"), b"public fixture").unwrap();
    app.gateway.contacts_store = Some(ContactStore::new(root.join("blocked")));
    let page = directory_get(&app, "/contacts", "KeyInventoryPractical");
    assert_eq!(page.response.status_code, 200);
    let html = body_text(&page);
    assert!(html.contains("second@example.test"));
    assert!(html.contains("unavailable"));
    assert!(!html.contains("No contacts saved yet"));
    assert!(app.gateway.drafts.lock().unwrap().is_empty());
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
