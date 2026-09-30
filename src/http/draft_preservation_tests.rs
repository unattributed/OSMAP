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

#[test]
fn draft_stars_persist_keep_content_and_refuse_stale_or_cross_account_forms() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let id = save_new(&app, "to=unfinished%40&subject=One&body=Saved%20text");
    let original = store.load("alice@example.com", &id, 100).unwrap().unwrap();
    let fields = format!("draft_id={id}&draft_revision=1&starred=1&filter=all&sort=subject&q=One");
    let starred = perform(&app, "/drafts/star", &fields);
    assert_eq!(starred.response.status_code, 303);
    assert_eq!(location_header(&starred), "/drafts?filter=all&sort=subject&q=One");
    let current = store.load("alice@example.com", &id, 100).unwrap().unwrap();
    assert!(current.starred);
    assert_eq!(current.request, original.request);
    assert_eq!(current.revision, Some(2));
    assert_eq!(perform(&app, "/drafts/star", &fields).response.status_code, 409);
    let update = perform(&app, "/drafts/save", &format!("draft_id={id}&draft_revision=2&body=Continued%20text"));
    assert_eq!(update.response.status_code, 303);
    assert!(store.load("alice@example.com", &id, 100).unwrap().unwrap().starred);
    let mut req = request("POST", "/drafts/star", &authenticated_same_origin_headers(),
        &format!("csrf_token={}&{}", StubGateway::validated_session().record.csrf_token, fields.replace("draft_revision=1", "draft_revision=3").replace("starred=1", "starred=0")));
    req.headers.insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
    req.body = String::from_utf8(req.body).unwrap().replace(&StubGateway::validated_session().record.csrf_token, &"c".repeat(64)).into_bytes();
    assert_eq!(app.handle_request(&req, "127.0.0.1").response.status_code, 409);
    assert!(store.load("alice@example.com", &id, 100).unwrap().unwrap().starred);
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn draft_star_requires_post_session_csrf_origin_and_exact_fields() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let id = save_new(&app, "subject=Keep&body=Original");
    let fields = format!("csrf_token={}&draft_id={id}&draft_revision=1&starred=1&filter=all&sort=newest&q=", StubGateway::validated_session().record.csrf_token);
    for (case, status) in [("get", 404), ("session", 303), ("csrf", 403), ("origin", 403), ("extra", 400), ("flag", 400), ("missing", 400)] {
        let mut req = request(if case == "get" { "GET" } else { "POST" }, "/drafts/star", &authenticated_same_origin_headers(), if case == "get" { "" } else { &fields });
        match case {
            "session" => { req.headers.remove("cookie"); },
            "csrf" => { req.body = fields.replace("csrf_token=", "csrf_token=x").into_bytes(); },
            "origin" => { req.headers.insert("origin".into(), "https://elsewhere.invalid".into()); },
            "extra" => { req.body.extend_from_slice(b"&account=other"); },
            "flag" => { req.body = fields.replace("starred=1", "starred=yes").into_bytes(); },
            "missing" => { req.body = fields.replace("&draft_revision=1", "").into_bytes(); },
            _ => (),
        }
        assert_eq!(app.handle_request(&req, "127.0.0.1").response.status_code, status, "{case}");
        assert!(!store.load("alice@example.com", &id, 100).unwrap().unwrap().starred);
    }
    fs::remove_dir_all(root).unwrap();
}

fn selection(ids: &[(String, u64)], stage: &str) -> String {
    let mut form = format!("filter=all&sort=subject&q=&stage={stage}");
    for (id, revision) in ids { form.push_str(&format!("&selected_{id}={revision}")); }
    form
}

#[test]
fn selected_drafts_require_review_and_fresh_revisions_without_touching_other_drafts() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let ids: Vec<_> = ["Alpha", "Beta", "Keep"].iter().map(|subject| (save_new(&app, &format!("subject={subject}&body=Private%20body&bcc=private%40example.test")), 1)).collect();
    let reviewed = perform(&app, "/drafts/discard", &selection(&ids[..2], "review"));
    assert_eq!(reviewed.response.status_code, 200);
    let html = body_text(&reviewed);
    assert!(html.contains("Discard selected drafts?"));
    assert!(!html.contains("Private body") && !html.contains("private@example.test"));
    assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 3);
    let mut changed = store.load("alice@example.com", &ids[0].0, 100).unwrap().unwrap();
    changed.request.body = "Changed after review".into();
    store.save(&changed, 100).unwrap();
    let stale = perform(&app, "/drafts/discard", &selection(&ids[..2], "confirm"));
    assert_eq!(stale.response.status_code, 409);
    assert!(body_text(&stale).contains("0 of 2 selected drafts discarded"));
    assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 3);
    let current = vec![(ids[0].0.clone(), 2), ids[1].clone()];
    let deleted = perform(&app, "/drafts/discard", &selection(&current, "confirm"));
    assert_eq!(deleted.response.status_code, 303);
    assert_eq!(location_header(&deleted), "/drafts?filter=all&sort=subject&q=");
    assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 1);
    assert_eq!(store.load("alice@example.com", &ids[2].0, 100).unwrap().unwrap().request.subject, "Keep");
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_selected_discard_stops_and_reports_only_completed_deletions() {
    let (mut app, root, store) = fixture(DraftPolicy::default());
    let mut ids: Vec<_> = (0..3).map(|_| (save_new(&app, "body=Retained"), 1)).collect();
    ids.sort();
    app.gateway.fail_draft_delete = Some(ids[1].0.clone());
    let result = perform(&app, "/drafts/discard", &selection(&ids, "confirm"));
    assert_eq!(result.response.status_code, 409);
    assert!(body_text(&result).contains("1 of 3 selected drafts discarded"));
    assert!(store.load("alice@example.com", &ids[0].0, 100).unwrap().is_none());
    for (id, _) in &ids[1..] { assert!(store.load("alice@example.com", id, 100).unwrap().is_some()); }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn selected_discard_refuses_empty_oversized_tampered_and_foreign_selections() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let ids: Vec<_> = (0..11).map(|_| (save_new(&app, "body=Retained"), 1)).collect();
    for fields in [selection(&[], "review"), selection(&ids, "confirm"), selection(&ids[..1], "unknown"), selection(&ids[..1], "confirm") + "&owner=bob", selection(&[("0".repeat(32), 1)], "confirm")] {
        let denied = perform(&app, "/drafts/discard", &fields);
        assert!(matches!(denied.response.status_code, 400 | 409));
        assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 11);
    }
    let mut foreign = store.load("alice@example.com", &ids[0].0, 100).unwrap().unwrap();
    foreign.canonical_username = "bob@example.com".into(); foreign.revision = None;
    foreign.draft_id = "f".repeat(32);
    store.save(&foreign, 100).unwrap();
    let denied = perform(&app, "/drafts/discard", &selection(&[ids[0].clone(), (foreign.draft_id.clone(), 1)], "confirm"));
    assert_eq!(denied.response.status_code, 409);
    assert_eq!(store.list("alice@example.com", 100).unwrap().len(), 11);
    assert!(store.load("bob@example.com", &foreign.draft_id, 100).unwrap().is_some());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn selected_discard_requires_session_csrf_origin_and_explicit_confirmation() {
    let (app, root, store) = fixture(DraftPolicy::default());
    let id = save_new(&app, "body=Retained");
    let form = format!("csrf_token={}&{}", StubGateway::validated_session().record.csrf_token, selection(&[(id.clone(), 1)], "confirm"));
    for (case, status) in [("session", 303), ("csrf", 403), ("origin", 403), ("stage", 400)] {
        let mut req = request("POST", "/drafts/discard", &authenticated_same_origin_headers(), &form);
        match case {
            "session" => { req.headers.remove("cookie"); },
            "csrf" => { req.body = form.replace("csrf_token=", "csrf_token=x").into_bytes(); },
            "origin" => { req.headers.insert("origin".into(), "https://elsewhere.invalid".into()); },
            "stage" => { req.body = form.replace("&stage=confirm", "").into_bytes(); },
            _ => (),
        }
        assert_eq!(app.handle_request(&req, "127.0.0.1").response.status_code, status);
        assert!(store.load("alice@example.com", &id, 100).unwrap().is_some());
    }
    let result = perform(&app, "/drafts/delete", &format!("draft_id={id}&draft_revision=1&confirm=1&filter=no-attachments&sort=subject&q=Retained"));
    assert_eq!(result.response.status_code, 303);
    assert_eq!(location_header(&result), "/drafts?filter=no-attachments&sort=subject&q=Retained");
    fs::remove_dir_all(root).unwrap();
}
