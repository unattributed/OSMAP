use super::*;

struct AllFixture {
    root: PathBuf,
    contacts: crate::contacts::ContactStore,
}
impl AllFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-all-search-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        Self {
            contacts: crate::contacts::ContactStore::new(root.join("contacts")),
            root,
        }
    }
    fn add(&self, account: &str, name: &str, address: &str) {
        let revision = self.contacts.load(account).unwrap().revision;
        self.contacts
            .change(
                account,
                revision,
                crate::contacts::ContactChange::Save {
                    id: None,
                    display_name: name.into(),
                    address: address.into(),
                },
            )
            .unwrap();
    }
    fn app(&self, decision: Option<BrowserMessageSearchDecision>) -> BrowserApp<StubGateway> {
        BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                contacts_store: Some(self.contacts.clone()),
                all_search_override: decision,
                ..StubGateway::default()
            },
        )
    }
    fn corrupt(&self, foreign: bool) {
        let path = fs::read_dir(self.root.join("contacts"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        if foreign {
            let mut book: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            book["canonical_username"] = "bob@example.com".into();
            fs::write(path, serde_json::to_vec(&book).unwrap()).unwrap();
        } else {
            fs::write(path, b"corrupt").unwrap();
        }
    }
}
impl Drop for AllFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn all_get(app: &BrowserApp<StubGateway>, path: &str) -> HandledHttpResponse {
    app.handle_request(
        &request("GET", path, &authenticated_same_origin_headers(), ""),
        "127.0.0.1",
    )
}
fn all_row(mailbox: &str, uid: u64, subject: &str) -> MessageSearchResult {
    MessageSearchResult {
        metadata: Some(StubGateway::fixture_metadata(
            "alice@example.com",
            mailbox,
            uid,
        )),
        mailbox_name: mailbox.into(),
        uid,
        flags: Vec::new(),
        date_received: "2026-10-03 12:00:00 +0000".into(),
        size_virtual: 1,
        subject: Some(subject.into()),
        from: Some("Public sender <sender@example.test>".into()),
    }
}
fn all_decision(query: &str, results: Vec<MessageSearchResult>) -> BrowserMessageSearchDecision {
    BrowserMessageSearchDecision::Listed {
        canonical_username: "alice@example.com".into(),
        mailbox_name: None,
        query: query.into(),
        results,
    }
}
fn budgets(result: &HandledHttpResponse) {
    assert_eq!(
        result
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_acquired")
            .count(),
        1
    );
    assert_eq!(
        result
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_released")
            .count(),
        1
    );
}

#[test]
fn all_search_dispatches_supported_category_and_projects_owned_people() {
    let fixture = AllFixture::new();
    fixture.add(
        "alice@example.com",
        "ux-empty-fixture <Public>",
        "own-public@example.test",
    );
    fixture.add(
        "bob@example.com",
        "ux-empty-fixture FOREIGN-SENTINEL",
        "foreign-public@example.test",
    );
    let result = all_get(
        &fixture.app(None),
        "/search?category=all&q=ux-empty-fixture",
    );
    assert_eq!(
        result.response.status_code, 200,
        "All is a supported approved category"
    );
    let body = body_text(&result);
    assert!(body.contains("ux-empty-fixture &lt;Public&gt;"));
    assert!(body.contains("own-public@example.test"));
    assert!(body.contains("/contacts?edit="));
    assert!(!body.contains("FOREIGN-SENTINEL") && !body.contains("foreign-public@example.test"));
    assert!(!body.contains("ux-empty-fixture <Public>"));
    assert!(
        body.contains("Messages (0)")
            && body.contains("People (1)")
            && body.contains("All available (1)")
    );
    assert!(body.contains("Documents unavailable") && !body.contains("Documents (0)"));
    budgets(&result);
}

#[test]
fn all_search_distinct_typed_rows_counts_locations_and_exact_owned_opens() {
    let fixture = AllFixture::new();
    fixture.add(
        "alice@example.com",
        "Quarterly <Public>",
        "quarterly@example.test",
    );
    let book = fixture.contacts.load("alice@example.com").unwrap();
    let app = fixture.app(Some(all_decision(
        "quarterly",
        vec![
            all_row("Sent", 1, "Quarterly <Public>"),
            all_row("INBOX", 1, "Quarterly <Public>"),
        ],
    )));
    let result = all_get(&app, "/search?category=all&q=quarterly");
    let body = body_text(&result);
    assert_eq!(result.response.status_code, 200);
    assert_eq!(body.matches("class=\"search-result-row\"").count(), 3);
    assert!(body.contains("Messages (2)") && body.contains("People (1)"));
    assert!(
        body.contains("Saved contacts")
            && body.contains(">Sent</span>")
            && body.contains(">INBOX</span>")
    );
    assert!(body.contains(&format!(
        "/contacts?edit={}&amp;revision=1",
        book.contacts[0].id
    )));
    assert!(
        body.contains("mailbox_guid=")
            && body.contains("message_guid=")
            && body.contains("return_to=")
    );
    assert!(body.contains("category%3Dall") && !body.contains("Quarterly <Public>"));
    assert!(body.find("mailbox=INBOX").unwrap() < body.find("mailbox=Sent").unwrap());
    assert_eq!(
        result
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_all_search")
            .count(),
        1
    );
    let audit = result
        .audit_events
        .iter()
        .find(|e| e.action == "stub_all_search")
        .unwrap();
    assert!(format!("{audit:?}").contains("all_scope") && format!("{audit:?}").contains("true"));
    assert!(format!("{audit:?}").contains("all"));
    budgets(&result);
}

#[test]
fn all_search_combined_paging_is_bounded_and_query_retained() {
    let fixture = AllFixture::new();
    for index in 0..200 {
        fixture.add(
            "alice@example.com",
            &format!("Public {index:03}"),
            &format!("person{index}@example.test"),
        );
    }
    let rows = (1..=250)
        .rev()
        .map(|uid| all_row("INBOX", uid, "Public message"))
        .collect();
    let app = fixture.app(Some(all_decision("Public", rows)));
    let first = all_get(&app, "/search?category=all&q=Public");
    let boundary = all_get(&app, "/search?category=all&q=Public&page=13");
    let last = all_get(&app, "/search?category=all&q=Public&page=23");
    assert!(body_text(&first).contains("450 loaded available results"));
    assert_eq!(
        body_text(&boundary)
            .matches("class=\"search-result-row\"")
            .count(),
        20
    );
    assert_eq!(
        body_text(&boundary).matches("<span>Message</span>").count(),
        10
    );
    assert_eq!(
        body_text(&boundary).matches("<span>Person</span>").count(),
        10
    );
    assert!(body_text(&boundary).contains("category=all&amp;q=Public&amp;page=14"));
    assert_eq!(
        body_text(&last)
            .matches("class=\"search-result-row\"")
            .count(),
        10
    );
    assert!(body_text(&last).contains("Page 23 of 23"));
    assert!(!body_text(&last).contains("Next page"));
    for result in [&first, &boundary, &last] {
        budgets(result);
    }
    assert_eq!(
        fixture.contacts.load("alice@example.com").unwrap().revision,
        200
    );
}

#[test]
fn all_search_partial_and_total_refusals_never_become_fake_empty_categories() {
    let fixture = AllFixture::new();
    fixture.add(
        "alice@example.com",
        "public own contact",
        "public@example.test",
    );
    let app = fixture.app(Some(BrowserMessageSearchDecision::Denied {
        public_reason: "unavailable".into(),
    }));
    let result = all_get(&app, "/search?category=all&q=public");
    assert_eq!(result.response.status_code, 200);
    assert!(
        body_text(&result).contains("Messages unavailable")
            && body_text(&result).contains("People (1)")
    );
    assert!(!body_text(&result).contains("Messages (0)"));
    budgets(&result);
    fixture.corrupt(false);
    let result = all_get(&app, "/search?category=all&q=public");
    assert_eq!(result.response.status_code, 503);
    assert!(
        body_text(&result).contains("Messages unavailable")
            && body_text(&result).contains("People unavailable")
    );
    assert!(!body_text(&result).contains("No messages or saved contacts match"));
    assert!(
        body_text(&result).contains("All unavailable")
            && body_text(&result).contains("Result count unavailable")
    );
    assert!(
        !body_text(&result).contains("All available (0)")
            && !body_text(&result).contains("0 loaded available results")
    );
    assert!(!body_text(&result).contains("Page 1 of 1"));
    assert!(!body_text(&result).contains("aria-label=\"All result pages\""));
    budgets(&result);
    let app = fixture.app(Some(all_decision(
        "public",
        vec![all_row("INBOX", 1, "public native message")],
    )));
    let result = all_get(&app, "/search?category=all&q=public");
    assert_eq!(result.response.status_code, 200);
    assert!(
        body_text(&result).contains("Messages (1)")
            && body_text(&result).contains("People unavailable")
    );
    assert!(body_text(&result).contains("public native message"));
    budgets(&result);
}

#[test]
fn all_search_foreign_corrupt_or_inconsistent_message_snapshots_are_not_projected() {
    let fixture = AllFixture::new();
    fixture.add(
        "alice@example.com",
        "public own contact",
        "public@example.test",
    );
    let valid = all_decision("public", vec![all_row("INBOX", 1, "FOREIGN-SECRET")]);
    let mut snapshots = Vec::new();
    for field in ["account", "query", "scope"] {
        let mut decision = valid.clone();
        if let BrowserMessageSearchDecision::Listed {
            canonical_username,
            mailbox_name,
            query,
            ..
        } = &mut decision
        {
            match field {
                "account" => *canonical_username = "bob@example.com".into(),
                "query" => *query = "wrong".into(),
                _ => *mailbox_name = Some("INBOX".into()),
            }
        }
        snapshots.push(decision);
    }
    let row = all_row("INBOX", 1, "FOREIGN-SECRET");
    snapshots.push(all_decision("public", vec![row.clone(), row.clone()]));
    let mut wrong = all_row("INBOX", 2, "FOREIGN-SECRET");
    wrong.metadata.as_mut().unwrap().version.mailbox_guid = "b".repeat(32);
    snapshots.push(all_decision("public", vec![row.clone(), wrong]));
    let mut invalid = row.clone();
    invalid.uid = 0;
    snapshots.push(all_decision("public", vec![invalid]));
    let mut invalid = row.clone();
    invalid.metadata.as_mut().unwrap().version.message_guid = "invalid space".into();
    snapshots.push(all_decision("public", vec![invalid]));
    snapshots.push(all_decision("public", vec![row; 251]));
    for snapshot in snapshots {
        let result = all_get(
            &fixture.app(Some(snapshot)),
            "/search?category=all&q=public",
        );
        assert_eq!(result.response.status_code, 200);
        assert!(!body_text(&result).contains("FOREIGN-SECRET"));
        assert!(
            body_text(&result).contains("Messages unavailable")
                && body_text(&result).contains("People (1)")
        );
        budgets(&result);
    }
    fixture.corrupt(true);
    let result = all_get(
        &fixture.app(Some(all_decision("public", Vec::new()))),
        "/search?category=all&q=public",
    );
    assert!(body_text(&result).contains("People unavailable"));
    assert!(!body_text(&result).contains("public own contact"));
    budgets(&result);
}

#[test]
fn all_search_invalid_and_landing_requests_dispatch_no_search_worker() {
    let fixture = AllFixture::new();
    let app = fixture.app(None);
    for path in [
        "/search?category=all&scope=all",
        "/search?category=all&pgp=plain",
        "/search?category=all&page=24",
        "/search?category=all&page=0",
        "/search?category=all&page=01",
        "/search?category=all&q=%0D%0A",
        "/search?category=all&field=from",
    ] {
        let result = all_get(&app, path);
        assert_eq!(result.response.status_code, 400, "{path}");
        assert!(!result
            .audit_events
            .iter()
            .any(|event| event.action == "request_budget_acquired"));
    }
    assert_eq!(
        all_get(&app, &format!("/search?category=all&q={}", "x".repeat(257)))
            .response
            .status_code,
        400
    );
    let landing = all_get(&app, "/search?category=all");
    assert_eq!(landing.response.status_code, 200);
    assert!(
        body_text(&landing).contains("Messages not searched")
            && body_text(&landing).contains("People not searched")
    );
    assert!(
        !body_text(&landing).contains("Messages (0)")
            && !landing
                .audit_events
                .iter()
                .any(|event| event.action == "request_budget_acquired")
    );
    let unauthenticated = app.handle_request(
        &request("GET", "/search?category=all&q=public", &[], ""),
        "127.0.0.1",
    );
    assert_eq!(unauthenticated.response.status_code, 303);
}

#[test]
fn all_search_legacy_metadata_has_no_unsafe_open_and_on_open_is_native_post() {
    let fixture = AllFixture::new();
    let mark_read = crate::mark_read::Store::new(fixture.root.join("mark-read"));
    mark_read
        .save("alice@example.com", 0, crate::mark_read::Policy::OnOpen)
        .unwrap();
    let mut legacy = all_row("INBOX", 2, "public legacy");
    legacy.metadata = None;
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            contacts_store: Some(fixture.contacts.clone()),
            mark_read_store: Some(mark_read),
            all_search_override: Some(all_decision(
                "public",
                vec![all_row("Sent", 1, "public native"), legacy],
            )),
            ..StubGateway::default()
        },
    );
    let result = all_get(&app, "/search?category=all&q=public");
    let body = body_text(&result);
    assert_eq!(body.matches("action=\"/message/open\"").count(), 1);
    assert!(body.contains("public legacy") && body.contains("(Open unavailable)"));
    assert!(!body.contains("href=\"/message?mailbox=INBOX"));
    assert!(
        body.contains("name=\"mailbox\" value=\"Sent\"") && body.contains("name=\"mailbox_guid\"")
    );
    assert!(body.contains("name=\"message_guid\"") && body.contains("name=\"csrf_token\""));
    assert!(body.contains("category%3Dall"));
    budgets(&result);
}

#[test]
fn all_search_return_context_is_finite_and_tabs_preserve_keywords() {
    assert_eq!(
        crate::mail_navigation::safe_mail_return(
            "/search?category=all&q=Public+%26+Person&page=23"
        )
        .as_deref(),
        Some("/search?category=all&page=23&q=Public+%26+Person")
    );
    for value in [
        "/search?category=all&page=24",
        "/search?category=all&q=%0A",
        "/search?category=all&q=public&selected_uid=1",
        "/search?category=all&mailbox=INBOX",
        "/search?category=all&field=all",
    ] {
        assert!(
            crate::mail_navigation::safe_mail_return(value).is_none(),
            "{value}"
        );
    }
    let fixture = AllFixture::new();
    let app = fixture.app(Some(all_decision("<Public>&", Vec::new())));
    let result = all_get(&app, "/search?category=all&q=%3CPublic%3E%26");
    let body = body_text(&result);
    assert!(body.contains("value=\"&lt;Public&gt;&amp;\""));
    assert!(body.contains("/search?scope=all&amp;q=%3CPublic%3E%26"));
    assert!(body.contains("/search?category=people&amp;q=%3CPublic%3E%26"));
    assert!(!body.contains("<Public>"));
    assert!(
        body_text(&all_get(&app, "/search?category=people&q=%3CPublic%3E%26"))
            .contains("/search?category=all&amp;q=%3CPublic%3E%26")
    );
    assert!(
        body_text(&all_get(&app, "/search?q=%3CPublic%3E%26&scope=all"))
            .contains("/search?category=all&amp;q=%3CPublic%3E%26")
    );
}

#[test]
fn all_search_measured_empty_partial_category_keeps_its_actual_zero() {
    let fixture = AllFixture::new();
    fixture.add("alice@example.com", "public contact", "public@example.test");
    fixture.corrupt(false);
    let result = all_get(
        &fixture.app(Some(all_decision("public", Vec::new()))),
        "/search?category=all&q=public",
    );
    let body = body_text(&result);
    assert_eq!(result.response.status_code, 200);
    assert!(body.contains("All available (0)") && body.contains("0 loaded available results"));
    assert!(body.contains("Messages (0)") && body.contains("People unavailable"));
    assert!(!body.contains("People (0)") && !body.contains("No messages or saved contacts match"));
    budgets(&result);
}

#[test]
fn all_search_public_snippets_are_bounded_escaped_and_protected_absence_is_preserved() {
    let fixture = AllFixture::new();
    let mut public = all_row("INBOX", 1, "public first");
    public.metadata.as_mut().unwrap().preview =
        Some("Public snippet <b>only text</b> & safe".into());
    let mut invalid = all_row("INBOX", 2, "public second");
    invalid.metadata.as_mut().unwrap().preview = Some(format!(
        "INVALID-PREVIEW{}",
        "x".repeat(crate::message_metadata::MAX_MESSAGE_PREVIEW_CHARS)
    ));
    let mut absent = all_row("INBOX", 3, "public third");
    absent.metadata.as_mut().unwrap().preview = None;
    absent.metadata.as_mut().unwrap().protection =
        crate::message_metadata::MessageProtection::Encrypted;
    let mut protected = all_row("INBOX", 4, "public fourth");
    protected.metadata.as_mut().unwrap().protection =
        crate::message_metadata::MessageProtection::Encrypted;
    protected.metadata.as_mut().unwrap().preview =
        Some("PROTECTED-PREVIEW-MUST-NOT-PROJECT".into());
    let mut injected = all_row("INBOX", 5, "public fifth");
    injected.metadata.as_mut().unwrap().preview = Some("CONTROL-PREVIEW\ninvalid".into());
    let mut armor = all_row("INBOX", 6, "public sixth");
    armor.metadata.as_mut().unwrap().preview = Some("-----BEGIN PGP MESSAGE-----".into());
    let result = all_get(
        &fixture.app(Some(all_decision(
            "public",
            vec![public, invalid, absent, protected, injected, armor],
        ))),
        "/search?category=all&q=public",
    );
    let body = body_text(&result);
    assert_eq!(result.response.status_code, 200);
    assert!(body.contains("Public snippet &lt;b&gt;only text&lt;/b&gt; &amp; safe"));
    assert!(!body.contains("<b>only text</b>") && !body.contains("INVALID-PREVIEW"));
    assert!(
        !body.contains("PROTECTED-PREVIEW")
            && !body.contains("CONTROL-PREVIEW")
            && !body.contains("-----BEGIN PGP")
    );
    assert!(body.contains("Messages (6)"));
    budgets(&result);
}

fn all_html_attribute(tag: &str, name: &str) -> String {
    let delimiter = format!("{name}=\"");
    tag.split_once(delimiter.as_str())
        .and_then(|(_, value)| value.split_once('"'))
        .map(|(value, _)| {
            value
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
        })
        .unwrap()
}

fn all_rendered_open_form(body: &str) -> BTreeMap<String, String> {
    let form = body
        .split("<form ")
        .find(|chunk| {
            chunk
                .split_once('>')
                .is_some_and(|(tag, _)| tag.contains("action=\"/message/open\""))
        })
        .unwrap()
        .split_once("</form>")
        .unwrap()
        .0;
    let fields: BTreeMap<_, _> = form
        .split("<input ")
        .skip(1)
        .map(|input| {
            let tag = input.split_once('>').unwrap().0;
            (
                all_html_attribute(tag, "name"),
                all_html_attribute(tag, "value"),
            )
        })
        .collect();
    assert_eq!(fields.len(), 6);
    fields
}

fn all_post_open(
    app: &BrowserApp<StubGateway>,
    fields: &BTreeMap<String, String>,
    cookie: Option<&str>,
) -> HandledHttpResponse {
    let body = fields
        .iter()
        .map(|(name, value)| format!("{}={}", url_encode(name), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let mut req = request(
        "POST",
        "/message/open",
        &authenticated_same_origin_headers(),
        &body,
    );
    req.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    if let Some(value) = cookie {
        req.headers.insert("cookie".into(), value.into());
    }
    app.handle_request(&req, "127.0.0.1")
}

fn all_rendered_back(body: &str) -> String {
    let tag = body
        .split("<a ")
        .find(|anchor| {
            anchor
                .split_once('>')
                .is_some_and(|(tag, _)| tag.contains("aria-label=\"Back to list\""))
        })
        .unwrap()
        .split_once('>')
        .unwrap()
        .0;
    all_html_attribute(tag, "href")
}

#[test]
fn all_search_follow_manual_generated_identity_link_and_actual_back_is_read_only() {
    let fixture = AllFixture::new();
    let app = fixture.app(Some(all_decision(
        "public",
        vec![all_row("INBOX", 9, "public native message")],
    )));
    let list = all_get(&app, "/search?category=all&q=public");
    let markup = body_text(&list);
    let tag = markup
        .split("<a ")
        .find(|anchor| {
            anchor
                .split_once('>')
                .is_some_and(|(tag, _)| tag.contains("class=\"message-subject-link\""))
        })
        .unwrap()
        .split_once('>')
        .unwrap()
        .0;
    let link = all_html_attribute(tag, "href");
    let flags_before = app
        .gateway
        .fixture_message_flags("alice@example.com", "INBOX", 9);
    let read = all_get(&app, &link);
    assert_eq!(read.response.status_code, 200);
    assert!(body_text(&read).contains("Hello world"));
    let back = all_rendered_back(&body_text(&read));
    assert_eq!(back, "/search?category=all&page=1&q=public");
    assert_eq!(all_get(&app, &back).response.status_code, 200);
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        flags_before
    );
    let stale_link = link.replace("message_guid=synthetic-", "message_guid=stale-synthetic-");
    assert_ne!(stale_link, link);
    let stale = all_get(&app, &stale_link);
    assert_eq!(stale.response.status_code, 503);
    assert!(!body_text(&stale).contains("Hello world"));
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        flags_before
    );
}

#[test]
fn all_search_generated_native_open_post_confirms_only_current_owner_and_returns_to_all() {
    let fixture = AllFixture::new();
    let store = crate::mark_read::Store::new(fixture.root.join("mark-read"));
    store
        .save("alice@example.com", 0, crate::mark_read::Policy::OnOpen)
        .unwrap();
    store
        .save("bob@example.com", 0, crate::mark_read::Policy::OnOpen)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            contacts_store: Some(fixture.contacts.clone()),
            mark_read_store: Some(store),
            browser_fixture_accounts: true,
            all_search_override: Some(all_decision(
                "public",
                vec![all_row("INBOX", 9, "public native message")],
            )),
            ..StubGateway::default()
        },
    );
    let list = all_get(&app, "/search?category=all&q=public");
    let fields = all_rendered_open_form(&body_text(&list));
    let alice_before = app
        .gateway
        .fixture_message_flags("alice@example.com", "INBOX", 9);
    let bob_before = app
        .gateway
        .fixture_message_flags("bob@example.com", "INBOX", 9);
    let mut stale = fields.clone();
    stale.insert("message_guid".into(), "stale-message".into());
    stale.insert(
        "return_to".into(),
        fields["return_to"].replace(&fields["message_guid"], "stale-message"),
    );
    assert_eq!(all_post_open(&app, &stale, None).response.status_code, 409);
    let mut foreign = fields.clone();
    foreign.insert("csrf_token".into(), "c".repeat(64));
    let rejected = all_post_open(
        &app,
        &foreign,
        Some("osmap_session=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );
    assert_eq!(rejected.response.status_code, 409);
    assert_eq!(
        app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        alice_before
    );
    assert_eq!(
        app.gateway
            .fixture_message_flags("bob@example.com", "INBOX", 9),
        bob_before
    );
    let opened = all_post_open(&app, &fields, None);
    assert_eq!(opened.response.status_code, 303, "{}", body_text(&opened));
    assert!(crate::mail_list::has_flag(
        &app.gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9),
        "\\Seen"
    ));
    let read = all_get(&app, &location_header(&opened));
    assert_eq!(read.response.status_code, 200);
    assert!(body_text(&read).contains("Hello world"));
    let back = all_rendered_back(&body_text(&read));
    assert_eq!(back, "/search?category=all&page=1&q=public");
    assert_eq!(all_get(&app, &back).response.status_code, 200);
    assert_eq!(
        app.gateway
            .fixture_message_flags("bob@example.com", "INBOX", 9),
        bob_before
    );
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
    assert_eq!(app.request_budgets.search_workers.active_count(), 0);
}
