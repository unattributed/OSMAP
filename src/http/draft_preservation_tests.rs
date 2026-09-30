use super::*;

fn fixture(policy: DraftPolicy) -> (BrowserApp<StubGateway>, PathBuf, crate::draft::FileDraftStore) {
    let root = std::env::temp_dir().join(format!("osmap-draft-http-{}", crate::draft::generate_draft_id().unwrap()));
    let store = crate::draft::FileDraftStore::new(&root, policy);
    let gateway = StubGateway { draft_store: Some(store.clone()), browser_fixture_accounts: true, ..StubGateway::default() };
    (BrowserApp::new(HttpPolicy::default(), gateway), root, store)
}

fn perform(app: &BrowserApp<StubGateway>, path: &str, fields: &str) -> HandledHttpResponse {
    let form = format!("csrf_token={}&{fields}", StubGateway::validated_session().record.csrf_token);
    app.handle_request(&request("POST", path, &authenticated_same_origin_headers(), &form), "127.0.0.1")
}

fn save_new(app: &BrowserApp<StubGateway>, fields: &str) -> String {
    let saved = perform(app, "/drafts/save", fields);
    assert_eq!(saved.response.status_code, 303);
    location_header(&saved).trim_start_matches("/draft?id=").into()
}

#[test]
fn blank_and_partial_drafts_are_saveable_but_not_sendable() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let id = save_new(&app, "to=&cc=&bcc=&subject=&body=");
    let updated = perform(&app, "/drafts/save", &format!("draft_id={id}&draft_revision=1&to=unfinished%40&body=Text%20not%20ready"));
    assert_eq!(updated.response.status_code, 303);
    let denied = perform(&app, "/send", &format!("draft_id={id}&draft_revision=2&to=unfinished%40&body=Text%20not%20ready"));
    assert_eq!(denied.response.status_code, 400);
    assert!(String::from_utf8_lossy(&denied.response.body).contains("Text not ready"));
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    let saved = store.load("alice@example.com", &id, 100).unwrap().unwrap();
    assert_eq!(saved.request.recipients_text, "unfinished@");
    assert_eq!(saved.revision, Some(2));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_save_send_and_discard_refuse_without_losing_typed_or_saved_text() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let id = save_new(&app, "to=desk%40example.test&subject=Original&body=Initial");
    let second = perform(&app, "/drafts/save", &format!("draft_id={id}&draft_revision=1&to=desk%40example.test&body=Newer%20saved%20version"));
    assert_eq!(second.response.status_code, 303);
    for path in ["/drafts/save", "/send"] {
        let failed = perform(&app, path, &format!("draft_id={id}&draft_revision=1&to=desk%40example.test&body=Older%20tab%20unsaved%20text"));
        assert_eq!(failed.response.status_code, 409);
        let html = String::from_utf8(failed.response.body).unwrap();
        assert!(html.contains("Older tab unsaved text"));
        assert!(html.contains("Open saved version in a new tab"));
        assert!(html.contains("name=\"draft_revision\" value=\"1\""));
        assert!(!html.contains("Newer saved version"));
    }
    let failed = perform(&app, "/drafts/delete", &format!("draft_id={id}&draft_revision=1&confirm=1"));
    assert_eq!(failed.response.status_code, 409);
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    assert_eq!(store.load("alice@example.com", &id, 100).unwrap().unwrap().request.body, "Newer saved version");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_or_forged_revisions_and_delete_confirmation_do_not_mutate() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let id = save_new(&app, "to=desk%40example.test&body=Keep");
    for tail in ["", "&draft_revision=", "&draft_revision=01", "&draft_revision=-1", "&draft_revision=1&extra=field"] {
        let denied = perform(&app, "/drafts/save", &format!("draft_id={id}{tail}&body=Changed"));
        assert_eq!(denied.response.status_code, 400);
    }
    for tail in ["", "&confirm=0", "&confirm=1&extra=field"] {
        assert_eq!(perform(&app, "/drafts/delete", &format!("draft_id={id}&draft_revision=1{tail}")).response.status_code, 400);
    }
    let page = app.handle_request(&request("GET", "/drafts?deleted=1&saved=1", &authenticated_headers(), ""), "127.0.0.1");
    let html = String::from_utf8(page.response.body).unwrap();
    assert!(!html.contains("Draft deleted."));
    assert!(!html.contains("Draft saved.</"));
    assert_eq!(store.load("alice@example.com", &id, 100).unwrap().unwrap().revision, Some(1));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quota_failure_preserves_form_and_original_draft() {
    let (app, root, store) = fixture(DraftPolicy { storage_max_bytes: 1500, ..DraftPolicy::default() });
    let id = save_new(&app, "to=desk%40example.test&body=Original");
    let body = "Unfinished notes ".repeat(80);
    let failed = perform(&app, "/drafts/save", &format!("draft_id={id}&draft_revision=1&to=desk%40example.test&body={}&source_mailbox=INBOX&source_uid=9&include_original_attachment_1=1.2", url_encode(&body)));
    assert_eq!(failed.response.status_code, 503);
    let html = String::from_utf8(failed.response.body).unwrap();
    assert!(html.contains("draft storage is full"));
    assert!(html.contains(&body));
    assert!(html.contains("Retained source attachments"));
    assert!(html.contains("name=\"include_original_attachment_1\" value=\"1.2\" checked"));
    assert!(html.contains("name=\"source_mailbox\" value=\"INBOX\""));
    assert_eq!(store.load("alice@example.com", &id, 100).unwrap().unwrap().request.body, "Original");
    fs::remove_dir_all(root).unwrap();
}
