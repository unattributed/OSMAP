use super::*;

#[test]
fn label_filter_current_identity_before_pagination_clear_context_and_neighbours() {
    let root = temp_dir("label-filter-current");
    let store = crate::labels::LabelStore::new(root.join("labels"));
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway {
        labels_store: Some(store.clone()), browser_fixture_accounts: true, ..StubGateway::default()
    });
    let account = "alice@example.com";
    let created = store.change(account, 0, crate::labels::LabelChange::Create("Review <current>")).unwrap();
    let id = created.labels()[0].id().to_owned();
    let mut revision = created.revision();
    for uid in [1, 60, 2] {
        let mut metadata = app.gateway.fixture_current_metadata(account, "INBOX", uid).unwrap();
        if uid == 2 { metadata.version.message_guid = "old-stale-message".into(); }
        let row = crate::mailbox::MessageSummary { to: None, metadata: Some(metadata), mailbox_name: "INBOX".into(), uid, flags: vec![], date_received: String::new(), size_virtual: 0, subject: None, from: None };
        let identity = crate::labels::MessageIdentity::from_summary(account, account, "INBOX", &row).unwrap();
        revision = store.change(account, revision, crate::labels::LabelChange::Attach { id: &id, message: &identity }).unwrap().revision();
    }
    let before = store.load(account).unwrap();
    let get = |path: &str| {
        let mut r = request("GET", path, &authenticated_same_origin_headers(), "");
        r.headers.insert("user-agent".into(), "OSMAP/ManyMessages".into());
        app.handle_request(&r,"127.0.0.1")
    };
    let filtered = get(&format!("/mailbox?name=INBOX&sort=uid&dir=asc&page=2&q=kept&scope=all&label={id}"));
    assert_eq!(filtered.response.status_code, 200);
    let html = body_text(&filtered);
    assert!(html.contains("Message 001"));
    assert!(html.contains("Message 060"));
    assert!(!html.contains("Message 002"));
    assert!(!html.contains("Message 051"));
    assert!(html.contains("Review &lt;current&gt;"));
    assert!(html.contains("Showing 1–2 of 2"));
    let clear = html.split("<a href=\"").find_map(|part| {
        let (href, content) = part.split_once("\"")?;
        content.starts_with(">Clear label filter</a>").then(|| href.replace("&amp;", "&"))
    }).unwrap();
    assert!(!clear.contains("label="));
    for value in ["name=INBOX", "sort=uid", "dir=asc", "q=kept", "scope=all"] { assert!(clear.contains(value),"{clear}"); }
    let cleared = get(&clear);
    assert_eq!(cleared.response.status_code, 200);
    assert!(body_text(&cleared).contains("Message 002"));
    assert!(body_text(&cleared).contains("of 125"));
    let metadata = app.gateway.fixture_current_metadata(account,"INBOX",1).unwrap();
    let origin = format!("/mailbox?name=INBOX&sort=uid&dir=asc&label={id}");
    let reader = get(&format!("/message?mailbox=INBOX&uid=1&mailbox_guid={}&message_guid={}&return_to={}",metadata.version.mailbox_guid,url_encode(&metadata.version.message_guid),url_encode(&origin)));
    assert_eq!(reader.response.status_code, 200);
    assert!(body_text(&reader).contains("uid=60"));
    assert!(!body_text(&reader).contains("uid=2&amp;"));
    assert_eq!(store.load(account).unwrap(),before);
    assert!(app.gateway.submitted.lock().unwrap().is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn label_filter_refuses_foreign_missing_malformed_and_unsupported_scope() {
    let root = temp_dir("label-filter-refusal");
    let store = crate::labels::LabelStore::new(root.join("labels"));
    let created = store.change("alice@example.com",0,crate::labels::LabelChange::Create("Owned")).unwrap();
    let id = created.labels()[0].id().to_owned();
    let app = BrowserApp::new(HttpPolicy::default(),StubGateway { labels_store: Some(store.clone()), browser_fixture_accounts:true, ..StubGateway::default() });
    let call = |path: &str, bob: bool, agent: &str| {
        let mut r = request("GET",path,&authenticated_same_origin_headers(),"");
        if bob { r.headers.insert("cookie".into(),format!("osmap_session={}","b".repeat(64))); }
        r.headers.insert("user-agent".into(),agent.into());
        app.handle_request(&r,"127.0.0.1")
    };
    for (path,bob,agent,code) in [
        (format!("/mailbox?name=INBOX&label={id}"),true,"",409),
        (format!("/mailbox?name=INBOX&label={}","f".repeat(32)),false,"",409),
        ("/mailbox?name=INBOX&label=not-an-id".into(),false,"",400),
        (format!("/mailbox?name=INBOX&label={id}"),false,"OSMAP/LegacyMetadata",409),
        (format!("/search?q=hello&label={id}"),false,"",400),
        (format!("/search?q=hello&category=all&label={id}"),false,"",400),
    ] {
        let response = call(&path,bob,agent);
        assert_eq!(response.response.status_code,code,"{path}");
        assert!(!body_text(&response).contains("Hello world"));
    }
    let labels = call("/labels",false,"");
    assert!(body_text(&labels).contains(&format!("/mailbox?name=INBOX&amp;label={id}")));
    assert_eq!(store.load("alice@example.com").unwrap(),created);
    assert!(store.load("bob@example.com").unwrap().labels().is_empty());
    assert!(crate::mail_navigation::safe_mail_return(&format!("/mailbox?name=INBOX&label={id}")).is_some());
    assert!(crate::mail_navigation::safe_mail_return(&format!("/search?q=hello&label={id}")).is_none());
    let unavailable = BrowserApp::new(HttpPolicy::default(),StubGateway::default());
    assert_eq!(unavailable.handle_request(&request("GET",&format!("/mailbox?name=INBOX&label={id}"),&authenticated_same_origin_headers(),""),"127.0.0.1").response.status_code,409);
    fs::remove_dir_all(root).unwrap();
}
