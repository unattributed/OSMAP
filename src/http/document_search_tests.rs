use super::*;

fn fixture() -> (
    BrowserApp<StubGateway>,
    PathBuf,
    crate::documents::Store<crate::documents::test_support::FixtureBackend>,
) {
    // Let the existing private Store create its own 0700 directory. The shared
    // HTTP temp_dir helper creates a public-mode parent, not a private record root.
    let root = std::env::temp_dir().join(format!(
        "osmap-document-search-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let store = crate::documents::Store::new(
        root.clone(),
        crate::documents::test_support::FixtureBackend::new(true),
    );
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            document_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        },
    );
    (app, root, store)
}

fn get(app: &BrowserApp<StubGateway>, path: &str) -> HandledHttpResponse {
    app.handle_request(
        &request("GET", path, &authenticated_same_origin_headers(), ""),
        "127.0.0.1",
    )
}

#[test]
fn document_search_owned_active_names_pagination_filters_and_forced_download() {
    let (app, root, store) = fixture();
    let mut revision = 0;
    for number in (0..23).rev() {
        revision = store
            .upload(
                "alice@example.com",
                revision,
                &format!("Public {number:02} <file>.txt"),
                "text/plain",
                b"opaque-content",
                100,
            )
            .unwrap()
            .revision;
    }
    let index = store.load("alice@example.com").unwrap();
    let hidden = &index.documents[0].id;
    let binned = store
        .bin("alice@example.com", revision, hidden, 101)
        .unwrap();
    let foreign = store
        .upload(
            "bob@example.com",
            0,
            "Public FOREIGN.txt",
            "text/plain",
            b"foreign-bytes",
            100,
        )
        .unwrap();
    let first = get(
        &app,
        "/search?category=documents&q=PUBLIC&mailbox=INBOX&filter=unread&pgp=encrypted",
    );
    assert_eq!(first.response.status_code, 200);
    let html = body_text(&first);
    assert_eq!(html.matches("class=\"search-result-row\"").count(), 20);
    assert!(html.contains("Documents (22)") && html.contains("Public 00 &lt;file&gt;.txt"));
    assert!(
        !html.contains("Public 22")
            && !html.contains("FOREIGN")
            && !html.contains("opaque-content")
    );
    assert!(html.contains(
        "category=all&amp;filter=unread&amp;mailbox=INBOX&amp;pgp=encrypted&amp;q=PUBLIC"
    ));
    assert!(html.contains("do not filter Documents"));
    assert!(!first
        .audit_events
        .iter()
        .any(|event| event.action == "stub_all_search"));
    let second = get(&app, "/search?category=documents&q=PUBLIC&page=2");
    assert_eq!(
        body_text(&second)
            .matches("class=\"search-result-row\"")
            .count(),
        2
    );
    assert!(body_text(&second).contains("Page 2 of 2"));
    let id = &binned
        .documents
        .iter()
        .find(|document| document.name == "Public 00 <file>.txt")
        .unwrap()
        .id;
    assert!(html.contains(&format!("/documents?selected={id}")));
    let download = get(&app, &format!("/documents/download?id={id}"));
    assert_eq!(download.response.body, b"opaque-content");
    assert!(download
        .response
        .headers
        .iter()
        .any(|(name, value)| name == "Content-Disposition" && value.starts_with("attachment;")));
    assert_eq!(
        get(
            &app,
            &format!("/documents?selected={}", foreign.documents[0].id)
        )
        .response
        .status_code,
        404
    );
    assert_eq!(
        get(&app, "/documents?selected=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .response
            .status_code,
        404
    );
    assert_eq!(store.load("alice@example.com").unwrap(), binned);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn document_search_unavailable_foreign_pending_empty_and_invalid_never_count_as_zero() {
    let (app, root, store) = fixture();
    for path in [
        "/search?category=documents",
        "/search?category=all&q=%20%20",
    ] {
        let response = get(&app, path);
        assert_eq!(response.response.status_code, 200);
        assert!(body_text(&response).contains("Documents not searched"));
    }
    assert_eq!(app.gateway.document_reads.load(Ordering::SeqCst), 0);
    for path in [
        "/search?category=documents&page=6",
        "/search?category=documents&page=0",
        "/search?category=documents&page=01",
        "/search?category=documents&q=%00",
        "/search?category=documents&selected_uid=3",
    ] {
        assert_eq!(get(&app, path).response.status_code, 400, "{path}");
        assert!(crate::mail_navigation::safe_mail_return(path).is_none());
    }
    assert_eq!(app.gateway.document_reads.load(Ordering::SeqCst), 0);
    let empty = get(&app, "/search?category=documents&q=none");
    assert!(
        body_text(&empty).contains("Documents (0)")
            && body_text(&empty).contains("No document file names match")
    );
    let index = store
        .upload(
            "alice@example.com",
            0,
            "Private sentinel.txt",
            "text/plain",
            b"x",
            100,
        )
        .unwrap();
    let path = fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .unwrap();
    for mutation in ["foreign", "pending", "malformed"] {
        let mut value = serde_json::to_value(&index).unwrap();
        match mutation {
            "foreign" => value["account"] = "bob@example.com".into(),
            "pending" => {
                value["documents"][0]["state"] = "uploading".into();
                value["documents"][0]["location"] = serde_json::Value::Null;
            }
            _ => value["documents"][0]["id"] = "malformed".into(),
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let response = get(&app, "/search?category=documents&q=Private");
        assert_eq!(response.response.status_code, 503, "{mutation}");
        let html = body_text(&response);
        assert!(
            html.contains("Documents unavailable")
                && !html.contains("Documents (0)")
                && !html.contains("Private sentinel")
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn all_search_documents_survive_unavailable_mail_and_preserve_category_context() {
    let (app, root, store) = fixture();
    let index = store
        .upload(
            "alice@example.com",
            0,
            "Public <report>.txt",
            "text/plain",
            b"never-preview",
            100,
        )
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            all_search_override: Some(BrowserMessageSearchDecision::Denied {
                public_reason: "Search unavailable".into(),
            }),
            ..app.gateway.clone()
        },
    );
    let response = get(
        &app,
        "/search?category=all&q=Public&filter=unread&mailbox=INBOX&page=28",
    );
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(
        html.contains("Documents (1)")
            && html.contains("All available (1)")
            && html.contains("Messages unavailable")
    );
    assert!(html.contains("Public &lt;report&gt;.txt") && !html.contains("never-preview"));
    assert!(html.contains(&format!("/documents?selected={}", index.documents[0].id)));
    assert!(html.contains("category=documents&amp;filter=unread&amp;mailbox=INBOX&amp;q=Public"));
    assert!(!html.contains("category=documents&amp;page=28"));
    for category in ["documents", "people"] {
        let html = body_text(&get(
            &app,
            &format!("/search?category={category}&q=Public&filter=unread"),
        ));
        assert!(html.contains("category=documents") || category == "documents");
    }
    assert!(
        crate::mail_navigation::safe_mail_return("/search?category=documents&page=5&q=Public")
            .is_some()
    );
    assert!(
        crate::mail_navigation::safe_mail_return("/search?category=all&page=28&q=Public").is_some()
    );
    assert!(
        crate::mail_navigation::safe_mail_return("/search?category=all&page=29&q=Public").is_none()
    );
    fs::remove_dir_all(root).unwrap();
}
