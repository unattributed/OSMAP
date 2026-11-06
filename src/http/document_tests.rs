// Documents HTTP retirement leaves retained data untouched; ordinary mail
// storage is sourced only from each authenticated account's mail report.
use super::*;

#[test]
fn two_account_mail_reports_reach_dashboard_general_and_rail_without_documents_reads() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!(
        "osmap-retired-documents-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let blocked = root.join("retained-documents");
    fs::write(
        &blocked,
        b"Retained Documents bytes; not a usable index directory",
    )
    .unwrap();
    for (account, token, bytes, limit) in [
        ("alice@example.com", "a", 172_605_611, 102_400_000),
        ("bob@example.com", "b", 4096, 8192),
    ] {
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                browser_fixture_accounts: true,
                document_store: Some(crate::documents::Store::new(
                    blocked.clone(),
                    crate::documents::test_support::FixtureBackend::new(false),
                )),
                mail_storage_report: Some(crate::documents::MailStorageReport {
                    account: account.into(),
                    message_bytes: bytes,
                    configured_limit_bytes: Some(limit),
                }),
                ..StubGateway::default()
            },
        );
        for path in ["/mailboxes", "/settings?section=general"] {
            let mut get = request("GET", path, &authenticated_same_origin_headers(), "");
            get.headers.insert(
                "cookie".into(),
                format!("osmap_session={}", token.repeat(64)),
            );
            let response = app.handle_request(&get, "127.0.0.1");
            assert_eq!(response.response.status_code, 200, "{path}");
            let html = body_text(&response);
            assert!(
                html.contains(&format!("{bytes} bytes"))
                    && html.contains(&format!("{limit} bytes"))
            );
            assert!(html.contains("Enforcement has not been verified"));
            assert!(!html.contains("Documents") && !html.contains("/documents"));
            assert!(html.contains("rail-storage"));
            let foreign = if token == "a" { "b" } else { "a" };
            get.headers.insert(
                "cookie".into(),
                format!("osmap_session={}", foreign.repeat(64)),
            );
            let response = app.handle_request(&get, "127.0.0.1");
            assert_eq!(response.response.status_code, 200);
            assert!(!body_text(&response).contains(&format!("{bytes} bytes")));
            assert!(!body_text(&response).contains(&format!("{limit} bytes")));
            assert_eq!(
                app.handle_request(&request("GET", path, &[], ""), "127.0.0.1")
                    .response
                    .status_code,
                303
            );
        }
        assert_eq!(app.gateway.document_reads.load(Ordering::SeqCst), 0);
    }
    assert!(
        fs::read(&blocked).unwrap() == b"Retained Documents bytes; not a usable index directory"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn retired_documents_paths_refuse_before_any_retained_store_read_or_mutation() {
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
    for path in [
        "/documents",
        "/documents/folders",
        "/documents/folder",
        "/documents/download?id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/documents/upload",
        "/documents/bin",
        "/documents/restore",
        "/documents/delete",
        "/documents/reconcile",
        "/documents/unknown",
        "/search?category=documents&q=private",
    ] {
        for method in ["GET", "POST"] {
            let authenticated = authenticated_same_origin_headers();
            for headers in [&[][..], authenticated.as_slice()] {
                let response = app.handle_request(
                    &request(
                        method,
                        path,
                        headers,
                        if method == "POST" {
                            "csrf_token=irrelevant&revision=0"
                        } else {
                            ""
                        },
                    ),
                    "127.0.0.1",
                );
                assert_eq!(response.response.status_code, 404, "{method} {path}");
                assert!(
                    !body_text(&response).contains("Upload")
                        && !body_text(&response).contains("Download")
                );
            }
        }
    }
    assert_eq!(app.gateway.document_reads.load(Ordering::SeqCst), 0);
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
}
