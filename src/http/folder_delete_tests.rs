use super::*;
struct Fixture {
    root: PathBuf,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "folder-delete-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let gateway = StubGateway {
            sent_location_store: Some(crate::sent_location::Store::new(root.join("sent"))),
            bin_store: Some(crate::bin_folder::BinPreferencesStore::new(
                root.join("bin"),
            )),
            settings_store: Some(crate::settings::FileUserSettingsStore::new(
                root.join("settings"),
            )),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        };
        gateway.created_folders.lock().unwrap().insert(
            "alice@example.com".into(),
            vec!["INBOX.Alpha".into(), "INBOX.Sibling".into()],
        );
        Self {
            root,
            app: BrowserApp::new(HttpPolicy::default(), gateway),
        }
    }
    fn run(
        &self,
        method: &str,
        path: &str,
        body: &str,
        agent: &str,
        bob: bool,
    ) -> HandledHttpResponse {
        let mut r = request(method, path, &authenticated_same_origin_headers(), body);
        r.headers.insert("user-agent".into(), agent.into());
        if bob {
            r.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&r, "127.0.0.1")
    }
    fn form(&self) -> String {
        format!("csrf_token={}&source=INBOX.Alpha&source_guid={}&parent_guid=1234567890abcdef1234567890abcdef&confirm=delete-empty",StubGateway::validated_session().record.csrf_token,self.app.gateway.created_folder_guid("alice@example.com","INBOX.Alpha").unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn folder_disposition_routes_review_csrf_ownership_and_no_get_mutation() {
    let f = Fixture::new();
    let account = "alice@example.com";
    let bin = crate::folder_disposition::Receipt::bin_request(
        account,
        "INBOX.Alpha",
        &f.app
            .gateway
            .created_folder_guid(account, "INBOX.Alpha")
            .unwrap(),
        "1234567890abcdef1234567890abcdef",
        &crate::bin_folder::BinPreference::default(),
        &"d".repeat(32),
    )
    .unwrap();
    let csrf = StubGateway::validated_session().record.csrf_token;
    let form = format!(
        "csrf_token={csrf}&expected_request={}&confirm=review",
        url_encode(&serde_json::to_string(&bin).unwrap())
    );
    let get = f.run(
        "GET",
        "/settings/folders/bin?source=INBOX.Alpha",
        "",
        "FolderCreateValid",
        false,
    );
    assert_eq!(get.response.status_code, 200);
    assert!(body_text(&get).contains("Review move to Bin"));
    let review = f.run(
        "POST",
        "/settings/folders/bin",
        &form,
        "FolderCreateValid",
        false,
    );
    assert_eq!(review.response.status_code, 200);
    assert!(body_text(&review).contains("Confirm move complete folder to Bin"));
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/bin",
            &form.replace(&csrf, "bad"),
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        403
    );
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/bin",
            &form,
            "FolderCreateValid",
            true
        )
        .response
        .status_code,
        403
    );
    let mut stale = serde_json::to_value(&bin).unwrap();
    stale["disposition"]["Bin"]["bin_revision"] = 1.into();
    let stale = format!(
        "csrf_token={csrf}&expected_request={}&confirm=apply",
        url_encode(&stale.to_string())
    );
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/bin",
            &stale,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        409
    );
    assert_eq!(
        f.run(
            "GET",
            "/settings/folders/restore?id=missing",
            "",
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        409
    );
    assert_eq!(
        f.run("GET", "/folders/deleted", "", "FolderCreateValid", false)
            .response
            .status_code,
        200
    );
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    assert!(f.app.gateway.deleted_folders.lock().unwrap().is_empty());
    assert!(f.app.gateway.submitted.lock().unwrap().is_empty());
}
#[test]
fn folder_delete_review_confirm_authority_and_original_result() {
    let f = Fixture::new();
    let form = f.form();
    let csrf = &StubGateway::validated_session().record.csrf_token;
    let review = f.run(
        "GET",
        "/settings/folders/delete?source=INBOX.Alpha",
        "",
        "FolderCreateValid",
        false,
    );
    assert_eq!(review.response.status_code, 200);
    assert!(body_text(&review).contains("Confirm delete empty folder"));
    assert!(f.app.gateway.deleted_folders.lock().unwrap().is_empty());
    for (body, agent, bob) in [
        (form.replace(csrf, "bad"), "FolderCreateValid", false),
        (
            form.replace("confirm=delete-empty", "confirm=no"),
            "FolderCreateValid",
            false,
        ),
        (
            form.replace("parent_guid=123", "parent_guid=bad123"),
            "FolderCreateValid",
            false,
        ),
        (
            form.replace("source_guid=", "source_guid=bad"),
            "FolderCreateValid",
            false,
        ),
        (
            form.replace("INBOX.Alpha", "INBOX.Sent"),
            "FolderCreateValid",
            false,
        ),
        (form.clone(), "FolderTreeWrongOwner", false),
        (form.clone(), "FolderCreateValid", true),
        (form.clone(), "FolderCreateDeletePopulated", false),
    ] {
        assert!(
            f.run("POST", "/settings/folders/delete", &body, agent, bob)
                .response
                .status_code
                >= 400
        );
        assert!(f.app.gateway.deleted_folders.lock().unwrap().is_empty());
    }
    let result = f.run(
        "POST",
        "/settings/folders/delete",
        &form,
        "FolderCreateDeleteUnknownCommitted",
        false,
    );
    assert_eq!(result.response.status_code, 503);
    assert_eq!(f.app.gateway.deleted_folders.lock().unwrap().len(), 1);
    assert!(f
        .app
        .gateway
        .created_folder_guid("alice@example.com", "INBOX.Sibling")
        .is_some());
    assert!(f
        .app
        .gateway
        .created_folder_guid("alice@example.com", "INBOX.Alpha")
        .is_none());
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/delete",
            &form,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        409
    );
    let checked = f.run(
        "POST",
        "/settings/folders/delete/check",
        &format!("csrf_token={csrf}&confirm=check"),
        "FolderCreateValid",
        false,
    );
    assert_eq!(checked.response.status_code, 303);
    assert_eq!(f.app.gateway.deleted_folders.lock().unwrap().len(), 1);
    assert!(f
        .app
        .gateway
        .pending_folder_delete(&StubGateway::validated_session())
        .unwrap()
        .is_none());
}
#[test]
fn folder_delete_unknown_does_not_clear_from_absence_or_retry() {
    let f = Fixture::new();
    let form = f.form();
    let result = f.run(
        "POST",
        "/settings/folders/delete",
        &form,
        "FolderCreateDeleteUnknown",
        false,
    );
    assert_eq!(result.response.status_code, 503);
    // External disappearance alone is not an original-action success witness.
    f.app
        .gateway
        .created_folders
        .lock()
        .unwrap()
        .get_mut("alice@example.com")
        .unwrap()
        .retain(|n| n != "INBOX.Alpha");
    let check = format!(
        "csrf_token={}&confirm=check",
        StubGateway::validated_session().record.csrf_token
    );
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/delete/check",
            &check,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        409
    );
    assert_eq!(f.app.gateway.deleted_folders.lock().unwrap().len(), 1);
    assert!(f
        .app
        .gateway
        .pending_folder_delete(&StubGateway::validated_session())
        .unwrap()
        .is_some());
}
