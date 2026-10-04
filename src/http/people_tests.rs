use super::*;
#[test]
fn people_search_owned_bounded_escaped_paged_and_no_mail_dispatch() {
    let root = temp_dir("people").join("contacts");
    let store = crate::contacts::ContactStore::new(&root);
    let mut revision = 0;
    for n in 0..23 {
        let b = store
            .change(
                "alice@example.com",
                revision,
                crate::contacts::ContactChange::Save {
                    id: None,
                    display_name: format!("Person {n:02} <Public>"),
                    address: format!("person{n:02}@example.test"),
                },
            )
            .unwrap();
        revision = b.revision;
    }
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            contacts_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let call = |path: &str| {
        let mut r = request("GET", path, &authenticated_same_origin_headers(), "");
        r.headers
            .insert("user-agent".into(), "OSMAP/SearchWrongOwner".into());
        app.handle_request(&r, "127.0.0.1")
    };
    let first = call("/search?category=people&q=PERSON");
    assert_eq!(first.response.status_code, 200);
    let body = body_text(&first);
    assert_eq!(body.matches("class=\"people-type\"").count(), 20);
    assert!(body.contains("Person 00 &lt;Public&gt;"));
    assert!(!body.contains("Person 20 &lt;Public&gt;"));
    assert!(!first
        .audit_events
        .iter()
        .any(|e| format!("{e:?}").contains("search_budget")));
    let retained =
        call("/search?category=people&q=PERSON&mailbox=INBOX&filter=unread&pgp=encrypted&page=10");
    assert_eq!(retained.response.status_code, 200);
    assert!(
        body_text(&retained).contains("People (23)")
            && body_text(&retained).contains("do not filter People")
    );
    assert!(
        body_text(&retained).contains("category=all")
            && body_text(&retained).contains("filter=unread")
            && body_text(&retained).contains("pgp=encrypted")
    );
    assert!(!retained.audit_events.iter().any(
        |event| event.action == "request_budget_acquired" || event.action == "stub_all_search"
    ));
    let page = call("/search?category=people&q=person&page=2");
    assert_eq!(body_text(&page).matches("class=\"people-type\"").count(), 3);
    assert!(body_text(&page).contains("revision=23"));
    for p in [
        "/search?category=documents",
        "/search?category=people&page=0",
        "/search?category=people&page=11",
        "/search?category=people&page=01",
        "/search?category=people&scope=all",
        "/search?category=people&q=%00",
    ] {
        assert_eq!(call(p).response.status_code, 400, "{p}");
    }
    assert_eq!(
        call(&format!("/search?category=people&q={}", "x".repeat(257)))
            .response
            .status_code,
        400
    );
    assert!(
        body_text(&call("/search?category=people&q=absent")).contains("No saved contacts match")
    );
    assert_eq!(
        crate::contacts::ContactStore::new(&root)
            .load("alice@example.com")
            .unwrap()
            .contacts
            .len(),
        23
    );
    assert!(store.load("bob@example.com").unwrap().contacts.is_empty());
    // A private record with foreign ownership cannot become a visible result.
    let file = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let mut data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    data["canonical_username"] = "bob@example.com".into();
    std::fs::write(&file, serde_json::to_vec(&data).unwrap()).unwrap();
    let failed = call("/search?category=people&q=Person&page=2");
    assert_eq!(failed.response.status_code, 503);
    assert!(!body_text(&failed).contains("person00@example.test"));
    assert!(!body_text(&failed).contains("No saved contacts match"));
    assert!(body_text(&failed).contains("/search?category=people&amp;page=2&amp;q=Person"));
    std::fs::write(&file, b"corrupt").unwrap();
    assert_eq!(call("/search?category=people").response.status_code, 503);
}
