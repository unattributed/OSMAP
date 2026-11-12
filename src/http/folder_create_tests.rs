use super::*;
#[test]
fn folder_creation_review_csrf_guid_conflict_and_unknown_keep_authority() {
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
    let form=format!("csrf_token={}&parent=INBOX&parent_guid=1234567890abcdef1234567890abcdef&leaf=Reviewed&action=review",StubGateway::validated_session().record.csrf_token);
    let perform = |body: &str, ua: &str| {
        let mut r = request(
            "POST",
            "/settings/folders/create",
            &authenticated_same_origin_headers(),
            body,
        );
        r.headers.insert("user-agent".into(), ua.into());
        app.handle_request(&r, "127.0.0.1")
    };
    let status = |r: &HandledHttpResponse| r.response.status_code;
    assert_eq!(status(&perform(&form, "FolderCreateValid")), 200);
    assert!(app.gateway.created_folders.lock().unwrap().is_empty());
    assert_eq!(
        status(&perform(
            &form.replace("csrf_token=", "csrf_token=wrong"),
            "FolderCreateValid"
        )),
        403
    );
    assert_eq!(
        status(&perform(
            &form.replace(
                "1234567890abcdef1234567890abcdef",
                "abcdef1234567890abcdef1234567890"
            ),
            "FolderCreateValid"
        )),
        409
    );
    let apply = form.replace("action=review", "action=create&confirm=create");
    assert_eq!(status(&perform(&apply, "FolderCreateUnknown")), 503);
    assert!(app.gateway.created_folders.lock().unwrap().is_empty());
    assert_eq!(status(&perform(&apply, "FolderCreateValid")), 303);
    assert_eq!(status(&perform(&apply, "FolderCreateValid")), 409);
    assert_eq!(
        app.gateway
            .created_folders
            .lock()
            .unwrap()
            .get("alice@example.com")
            .unwrap(),
        &vec!["INBOX.Reviewed".to_owned()]
    );
    let unicode = "Élodie & \"Office\"";
    let apply_unicode = apply.replace("leaf=Reviewed", &format!("leaf={}", url_encode(unicode)));
    assert_eq!(status(&perform(&apply_unicode, "FolderCreateValid")), 303);
    let mut r = request("GET", "/settings?section=copies&folder=INBOX", &authenticated_same_origin_headers(), "");
    r.headers.insert("user-agent".into(), "FolderCreateValid".into());
    let result = app.handle_request(&r, "127.0.0.1");
    assert_eq!(status(&result), 200);
    assert!(String::from_utf8_lossy(&result.response.body).contains("INBOX.Élodie &amp; &quot;Office&quot;"));
}
