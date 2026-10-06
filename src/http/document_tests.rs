use super::*;

fn fixture() -> (BrowserApp<StubGateway>, std::path::PathBuf, crate::documents::Store<crate::documents::test_support::FixtureBackend>) {
    let root = std::env::temp_dir().join(format!("osmap-document-http-{}", crate::draft::generate_draft_id().unwrap()));
    let store = crate::documents::Store::new(root.clone(), crate::documents::test_support::FixtureBackend::new(true));
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway {
        document_store: Some(store.clone()),
        browser_fixture_accounts: true,
        ..StubGateway::default()
    });
    (app, root, store)
}

fn upload_request(csrf: &str, revision: u64) -> HttpRequest {
    let body = format!(
        "--doc\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{csrf}\r\n--doc\r\nContent-Disposition: form-data; name=\"revision\"\r\n\r\n{revision}\r\n--doc\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\nExact document body\r\n--doc--\r\n"
    );
    let mut req = request("POST", "/documents/upload", &authenticated_same_origin_headers(), &body);
    req.headers.insert("content-type".into(), "multipart/form-data; boundary=doc".into());
    req
}

fn move_request(route: &str, revision: u64, id: &str, csrf: &str) -> HttpRequest {
    request("POST", route, &authenticated_same_origin_headers(), &format!("csrf_token={csrf}&revision={revision}&id={id}"))
}

#[test]
fn document_browser_upload_list_forced_download_bin_restore_and_owner() {
    let (app, root, store) = fixture();
    let csrf = StubGateway::validated_session().record.csrf_token;
    let initial = app.handle_request(&request("GET", "/documents", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(initial.response.status_code, 200);
    assert!(String::from_utf8_lossy(&initial.response.body).contains("Upload a file"));
    assert_eq!(app.handle_request(&upload_request(&csrf, 0), "127.0.0.1").response.status_code, 303);
    let index = store.load("alice@example.com").unwrap();
    let id = &index.documents[0].id;
    let listed = app.handle_request(&request("GET", "/documents?q=report&sort=name&view=grid", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(listed.response.status_code, 200);
    assert!(String::from_utf8_lossy(&listed.response.body).contains(&format!("/documents/download?id={id}")));
    assert!(String::from_utf8_lossy(&listed.response.body).contains(&format!("selected={id}")));
    let listed_html = String::from_utf8_lossy(&listed.response.body);
    assert!(listed_html.contains("<option value=\"name\" selected>Name</option>"));
    assert!(listed_html.contains("<option value=\"grid\" selected>Grid</option>"));
    assert!(listed_html.contains("q=report&amp;sort=name&amp;view=grid"));
    assert!(listed_html.contains(".document-grid .document-list"));
    assert!(listed_html.contains("grid-template-columns: repeat(auto-fill"));
    let selected = app.handle_request(&request("GET", &format!("/documents?selected={id}"), &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(selected.response.status_code, 200);
    assert!(String::from_utf8_lossy(&selected.response.body).contains("<summary>More actions</summary>"));
    assert_eq!(app.handle_request(&request("GET", "/documents?selected=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &authenticated_same_origin_headers(), ""), "127.0.0.1").response.status_code, 404);
    let download = app.handle_request(&request("GET", &format!("/documents/download?id={id}"), &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(download.response.status_code, 200);
    assert_eq!(download.response.body, b"Exact document body");
    assert!(download.response.headers.iter().any(|(key, value)| key == "Content-Disposition" && value == "attachment; filename=\"report.txt\""));
    assert!(!download.response.headers.iter().any(|(key, value)| key == "Content-Type" && value.starts_with("text/html")));

    let foreign = { let mut req = request("GET", &format!("/documents/download?id={id}"), &authenticated_same_origin_headers(), ""); req.headers.insert("cookie".into(), format!("osmap_session={}", "b".repeat(64))); req };
    assert_eq!(app.handle_request(&foreign, "127.0.0.1").response.status_code, 404);
    assert_eq!(app.handle_request(&move_request("/documents/bin", 0, id, &csrf), "127.0.0.1").response.status_code, 409);
    assert_eq!(app.handle_request(&move_request("/documents/bin", index.revision, id, "wrong"), "127.0.0.1").response.status_code, 403);
    assert_eq!(app.handle_request(&move_request("/documents/bin", index.revision, id, &csrf), "127.0.0.1").response.status_code, 303);
    assert_eq!(app.handle_request(&request("GET", &format!("/documents/download?id={id}"), &authenticated_same_origin_headers(), ""), "127.0.0.1").response.status_code, 404);
    let binned = store.load("alice@example.com").unwrap();
    assert_eq!(binned.used_bytes(), b"Exact document body".len() as u64);
    let selected_bin = app.handle_request(&request("GET", &format!("/documents?bin=1&selected={id}"), &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(selected_bin.response.status_code, 200);
    let selected_bin_html = String::from_utf8_lossy(&selected_bin.response.body);
    assert!(selected_bin_html.contains("Bin retention:"));
    assert!(selected_bin_html.contains(&format!("/documents/delete?id={id}")));
    assert_eq!(app.handle_request(&move_request("/documents/restore", binned.revision, id, &csrf), "127.0.0.1").response.status_code, 303);
    assert_eq!(store.load("alice@example.com").unwrap().documents[0].state, crate::documents::State::Available);
    let restored = store.load("alice@example.com").unwrap();
    assert_eq!(app.handle_request(&move_request("/documents/bin", restored.revision, id, &csrf), "127.0.0.1").response.status_code, 303);
    let in_bin = store.load("alice@example.com").unwrap();
    let review = app.handle_request(&request("GET", &format!("/documents/delete?id={id}"), &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(review.response.status_code, 200);
    assert!(String::from_utf8_lossy(&review.response.body).contains("This cannot be undone"));
    let delete = format!("csrf_token={csrf}&revision={}&id={id}&confirm=delete", in_bin.revision);
    assert_eq!(app.handle_request(&request("POST", "/documents/delete", &authenticated_same_origin_headers(), &delete.replace("confirm=delete", "confirm=no")), "127.0.0.1").response.status_code, 400);
    assert_eq!(app.handle_request(&request("POST", "/documents/delete", &authenticated_same_origin_headers(), &delete.replace(&format!("revision={}", in_bin.revision), "revision=0")), "127.0.0.1").response.status_code, 409);
    assert_eq!(app.handle_request(&request("POST", "/documents/delete", &authenticated_same_origin_headers(), &delete), "127.0.0.1").response.status_code, 303);
    assert!(store.load("alice@example.com").unwrap().documents.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn document_upload_refuses_missing_quota_and_foreign_origin_before_write() {
    let (app, root, store) = fixture();
    let csrf = StubGateway::validated_session().record.csrf_token;
    let mut foreign = upload_request(&csrf, 0);
    foreign.headers.insert("origin".into(), "https://outside.example.test".into());
    assert_eq!(app.handle_request(&foreign, "127.0.0.1").response.status_code, 403);
    assert!(store.load("alice@example.com").unwrap().documents.is_empty());
    let mut bad_csrf = upload_request("wrong", 0);
    assert_eq!(app.handle_request(&bad_csrf, "127.0.0.1").response.status_code, 403);
    bad_csrf.headers.remove("cookie");
    assert_eq!(app.handle_request(&bad_csrf, "127.0.0.1").response.status_code, 303);
    assert!(store.load("alice@example.com").unwrap().documents.is_empty());
    let unavailable_root = std::env::temp_dir().join(format!("osmap-document-http-noquota-{}", crate::draft::generate_draft_id().unwrap()));
    let unavailable_store = crate::documents::Store::new(unavailable_root.clone(), crate::documents::test_support::FixtureBackend::new(false));
    let unavailable_app = BrowserApp::new(HttpPolicy::default(), StubGateway { document_store: Some(unavailable_store.clone()), browser_fixture_accounts: true, ..StubGateway::default() });
    assert_eq!(unavailable_app.handle_request(&upload_request(&csrf, 0), "127.0.0.1").response.status_code, 503);
    assert!(unavailable_store.load("alice@example.com").unwrap().documents.is_empty());
    if unavailable_root.exists() { std::fs::remove_dir_all(unavailable_root).unwrap(); }
    if root.exists() { std::fs::remove_dir_all(root).unwrap(); }
}

#[test]
fn document_folders_are_account_private_revisioned_and_navigable() {
    let (app, root, store) = fixture();
    let csrf = StubGateway::validated_session().record.csrf_token;
    let create = format!("csrf_token={csrf}&revision=0&name=Reports");
    assert_eq!(app.handle_request(&request("POST", "/documents/folders", &authenticated_same_origin_headers(), &create), "127.0.0.1").response.status_code, 303);
    let index = store.load("alice@example.com").unwrap();
    let folder = &index.folders[0].id;
    assert_eq!(index.folders[0].name, "Reports");
    assert_eq!(app.handle_request(&request("POST", "/documents/folders", &authenticated_same_origin_headers(), &create), "127.0.0.1").response.status_code, 409);
    assert_eq!(app.handle_request(&upload_request(&csrf, index.revision), "127.0.0.1").response.status_code, 303);
    let uploaded = store.load("alice@example.com").unwrap();
    let id = &uploaded.documents[0].id;
    let move_form = format!("csrf_token={csrf}&revision={}&id={id}&folder_id={folder}", uploaded.revision);
    let mut foreign = request("POST", "/documents/folder", &authenticated_same_origin_headers(), &move_form);
    foreign.headers.insert("origin".into(), "https://outside.example.test".into());
    assert_eq!(app.handle_request(&foreign, "127.0.0.1").response.status_code, 403);
    assert_eq!(app.handle_request(&request("POST", "/documents/folder", &authenticated_same_origin_headers(), &move_form), "127.0.0.1").response.status_code, 303);
    assert_eq!(store.load("alice@example.com").unwrap().documents[0].folder, *folder);
    let page = app.handle_request(&request("GET", &format!("/documents?folder={folder}"), &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(page.response.status_code, 200);
    assert!(String::from_utf8_lossy(&page.response.body).contains("report.txt"));
    assert_eq!(app.handle_request(&request("GET", "/documents?folder=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &authenticated_same_origin_headers(), ""), "127.0.0.1").response.status_code, 404);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn confirmed_delete_remains_available_after_quota_authority_disappears() {
    let root = std::env::temp_dir().join(format!(
        "osmap-document-delete-noquota-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let backend = crate::documents::test_support::FixtureBackend::new(true);
    let store = crate::documents::Store::new(root.clone(), backend.clone());
    let csrf = StubGateway::validated_session().record.csrf_token;
    let ready_app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            document_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        },
    );
    assert_eq!(
        ready_app
            .handle_request(&upload_request(&csrf, 0), "127.0.0.1")
            .response
            .status_code,
        303
    );
    let uploaded = store.load("alice@example.com").unwrap();
    let id = &uploaded.documents[0].id;
    assert_eq!(
        ready_app
            .handle_request(
                &move_request("/documents/bin", uploaded.revision, id, &csrf),
                "127.0.0.1"
            )
            .response
            .status_code,
        303
    );
    let binned = store.load("alice@example.com").unwrap();
    let unavailable_store = crate::documents::Store::new(root.clone(), backend.with_ready(false));
    let unavailable_app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            document_store: Some(unavailable_store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        },
    );
    let page = unavailable_app.handle_request(
        &request(
            "GET",
            &format!("/documents?bin=1&selected={id}"),
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    let html = String::from_utf8_lossy(&page.response.body);
    assert!(html.contains("shared mailbox quota authority is not ready"));
    assert!(!html.contains("Upload a file"));
    assert!(html.contains(&format!("/documents/delete?id={id}")));
    assert_eq!(
        unavailable_app
            .handle_request(
                &request(
                    "GET",
                    &format!("/documents/delete?id={id}"),
                    &authenticated_same_origin_headers(),
                    ""
                ),
                "127.0.0.1"
            )
            .response
            .status_code,
        200
    );
    let confirm = format!(
        "csrf_token={csrf}&revision={}&id={id}&confirm=delete",
        binned.revision
    );
    assert_eq!(
        unavailable_app
            .handle_request(
                &request(
                    "POST",
                    "/documents/delete",
                    &authenticated_same_origin_headers(),
                    &confirm
                ),
                "127.0.0.1"
            )
            .response
            .status_code,
        303
    );
    assert!(unavailable_store
        .load("alice@example.com")
        .unwrap()
        .documents
        .is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn document_download_quotes_original_name_and_remains_attachment_only() {
    let (app, root, store) = fixture();
    let uploaded = store
        .upload(
            "alice@example.com",
            0,
            "quarter\"final.txt",
            "text/plain",
            b"synthetic",
            100,
        )
        .unwrap();
    let download = app.handle_request(
        &request(
            "GET",
            &format!("/documents/download?id={}", uploaded.documents[0].id),
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(download.response.status_code, 200);
    assert_eq!(download.response.body, b"synthetic");
    assert!(download.response.headers.iter().any(|(key, value)| {
        key == "Content-Disposition" && value == "attachment; filename=\"quarter\\\"final.txt\""
    }));
    assert!(download.response.headers.iter().any(|(key, value)| {
        key == "Content-Type" && value == "application/octet-stream"
    }));
    assert!(download.response.headers.iter().any(|(key, value)| {
        key == "Content-Security-Policy"
            && value == "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    }));
    assert_eq!(download.response.headers.iter().filter(|(key, _)| key == "Content-Security-Policy").count(), 1);
    assert_eq!(download.response.headers.iter().filter(|(key, _)| key == "Cross-Origin-Resource-Policy").count(), 1);
    std::fs::remove_dir_all(root).unwrap();
}
