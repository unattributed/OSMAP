use super::*;
use crate::mark_read::{Policy, Store};

struct MarkReadFixture {
    root: PathBuf,
    store: Store,
    app: BrowserApp<StubGateway>,
}

impl MarkReadFixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = temp_dir(&format!("mark-read-integrated-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        let store = Store::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                mark_read_store: Some(store.clone()),
                reading_preferences_store: Some(
                    crate::reading_preferences::ReadingPreferencesStore::new(root.join("settings")),
                ),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }

    fn get(&self, path: &str) -> HandledHttpResponse {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers
            .insert("user-agent".into(), "OSMAP/ManyMessages".into());
        self.app.handle_request(&req, "127.0.0.1")
    }

    fn post(&self, path: &str, fields: &BTreeMap<String, String>) -> HandledHttpResponse {
        self.post_with(path, fields, "OSMAP/ManyMessages", None, None)
    }

    fn post_with(
        &self,
        path: &str,
        fields: &BTreeMap<String, String>,
        agent: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> HandledHttpResponse {
        let body = fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = request("POST", path, &authenticated_same_origin_headers(), &body);
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        req.headers.insert("user-agent".into(), agent.into());
        if let Some(cookie) = cookie {
            req.headers.insert("cookie".into(), cookie.into());
        }
        if let Some(origin) = origin {
            req.headers.insert("origin".into(), origin.into());
        }
        self.app.handle_request(&req, "127.0.0.1")
    }

    fn open_form(&self, uid: u64, return_to: &str) -> BTreeMap<String, String> {
        let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", uid).version;
        BTreeMap::from([
            (
                "csrf_token".into(),
                StubGateway::validated_session().record.csrf_token,
            ),
            ("mailbox".into(), "INBOX".into()),
            ("uid".into(), uid.to_string()),
            ("mailbox_guid".into(), version.mailbox_guid),
            ("message_guid".into(), version.message_guid),
            ("return_to".into(), return_to.into()),
        ])
    }

    fn flags(&self, uid: u64) -> Vec<String> {
        self.app
            .gateway
            .fixture_message_flags("alice@example.com", "INBOX", uid)
    }
}

impl Drop for MarkReadFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn mark_read_on_open_post_preserves_exact_reader_and_reconciles_unread_list() {
    let fixture = MarkReadFixture::new();
    fixture
        .store
        .save("alice@example.com", 0, Policy::OnOpen)
        .unwrap();
    assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
    let origin = "/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc&selected_mailbox=INBOX&selected_uid=9";
    let before = fixture.get(origin);
    assert_eq!(before.response.status_code, 200);
    assert!(body_text(&before).contains("Synthetic message 9 in INBOX"));
    assert!(body_text(&before).contains("More for message #9 in INBOX"));
    assert!(
        !crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"),
        "GET must remain read-only even with saved OnOpen"
    );
    let opened = fixture.post("/message/open", &fixture.open_form(9, origin));
    assert_eq!(opened.response.status_code, 303, "{}", body_text(&opened));
    assert!(crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
    let target = location_header(&opened);
    let shown = fixture.get(&target);
    assert_eq!(shown.response.status_code, 200);
    assert!(
        body_text(&shown).contains("Synthetic message 9 in INBOX"),
        "confirmed Seen must not hide the exact reader just opened"
    );
    assert!(
        !body_text(&shown).contains("More for message #9 in INBOX"),
        "actual Unread rows must exclude the now-Seen message"
    );
    let ordinary_unread = fixture.get("/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc&selected_mailbox=INBOX&selected_uid=9");
    assert_eq!(ordinary_unread.response.status_code, 200);
    assert!(!body_text(&ordinary_unread).contains("Synthetic message 9 in INBOX"));
    assert!(body_text(&ordinary_unread).contains("Message unavailable"));
    assert!(!crate::mail_list::has_flag(&fixture.flags(11), "\\Seen"));
    assert!(!crate::mail_list::has_flag(
        &fixture
            .app
            .gateway
            .fixture_message_flags("bob@example.com", "INBOX", 9),
        "\\Seen"
    ));
    assert_eq!(
        fixture.app.request_budgets.mailbox_workers.active_count(),
        0
    );
}

#[test]
fn mark_read_manual_and_get_reload_never_mutate_flags() {
    let fixture = MarkReadFixture::new();
    let origin = "/mailbox?name=INBOX&filter=unread&selected_mailbox=INBOX&selected_uid=9";
    let form = fixture.open_form(9, origin);
    let opened = fixture.post("/message/open", &form);
    assert_eq!(opened.response.status_code, 303);
    assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
    for path in [
        location_header(&opened),
        origin.into(),
        "/message?mailbox=INBOX&uid=9".into(),
    ] {
        assert_eq!(fixture.get(&path).response.status_code, 200);
        assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
    }
    fixture
        .store
        .save("alice@example.com", 0, Policy::OnOpen)
        .unwrap();
    fixture
        .store
        .save("alice@example.com", 1, Policy::Manual)
        .unwrap();
    let changed = fixture.post("/message/open", &form);
    assert_eq!(changed.response.status_code, 303);
    assert!(
        !crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"),
        "an old opening form must use the current server policy"
    );
}

#[test]
fn mark_read_opening_refuses_invalid_csrf_origin_identity_and_destination() {
    let fixture = MarkReadFixture::new();
    fixture
        .store
        .save("alice@example.com", 0, Policy::OnOpen)
        .unwrap();
    let form = fixture.open_form(
        9,
        "/mailbox?name=INBOX&filter=unread&selected_mailbox=INBOX&selected_uid=9",
    );
    for (key, value, status) in [
        ("csrf_token", "wrong", 403),
        ("uid", "0", 400),
        ("message_guid", "absent-owned-guid", 409),
        ("return_to", "https://foreign.test/mailbox", 400),
        (
            "return_to",
            "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=11",
            400,
        ),
        ("unexpected", "1", 400),
    ] {
        let mut changed = form.clone();
        changed.insert(key.into(), value.into());
        let refused = fixture.post("/message/open", &changed);
        assert_eq!(
            refused.response.status_code,
            status,
            "{key}: {}",
            body_text(&refused)
        );
        assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
        assert!(!body_text(&refused).contains("Synthetic message 9 in INBOX"));
    }
    let cross_origin = fixture.post_with(
        "/message/open",
        &form,
        "OSMAP/ManyMessages",
        None,
        Some("https://foreign.test"),
    );
    assert_eq!(cross_origin.response.status_code, 403);
    let absent_session = fixture.post_with(
        "/message/open",
        &form,
        "OSMAP/ManyMessages",
        Some("osmap_session=invalid"),
        None,
    );
    assert_eq!(absent_session.response.status_code, 303);
    assert!(location_header(&absent_session).starts_with("/login"));
    assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
    fixture
        .store
        .save("bob@example.com", 0, Policy::OnOpen)
        .unwrap();
    let mut foreign = form;
    foreign.insert("csrf_token".into(), "c".repeat(64));
    let refused = fixture.post_with(
        "/message/open",
        &foreign,
        "OSMAP/ManyMessages",
        Some("osmap_session=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        None,
    );
    assert_eq!(refused.response.status_code, 409);
    assert!(!crate::mail_list::has_flag(
        &fixture
            .app
            .gateway
            .fixture_message_flags("bob@example.com", "INBOX", 9),
        "\\Seen"
    ));
    assert_eq!(
        fixture.app.request_budgets.mailbox_workers.active_count(),
        0
    );
}

#[test]
fn mark_read_unavailable_or_changed_view_and_unknown_flag_never_claim_open_success() {
    let fixture = MarkReadFixture::new();
    fixture
        .store
        .save("alice@example.com", 0, Policy::OnOpen)
        .unwrap();
    let form = fixture.open_form(
        9,
        "/mailbox?name=INBOX&filter=unread&selected_mailbox=INBOX&selected_uid=9",
    );
    for agent in [
        "OSMAP/ManyMessages;ReaderStale",
        "OSMAP/ManyMessages;ReaderWrongAccount",
        "OSMAP/ManyMessages;ReaderWrongMailbox",
        "OSMAP/ManyMessages;LegacyMetadata",
        "OSMAP/ManyMessages;ReaderUnavailable",
        "OSMAP/ManyMessages;FlagUnknown",
    ] {
        let refused = fixture.post_with("/message/open", &form, agent, None, None);
        assert_ne!(refused.response.status_code, 303, "{agent}");
        assert!(!refused
            .response
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("location")));
        assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
        assert!(!body_text(&refused).contains("Synthetic message 9 in INBOX"));
        assert_eq!(
            fixture.app.request_budgets.mailbox_workers.active_count(),
            0
        );
    }
    let mut unavailable = MarkReadFixture::new();
    unavailable.app.gateway.mark_read_store = None;
    assert_eq!(
        unavailable
            .post("/message/open", &form)
            .response
            .status_code,
        503
    );
    assert!(!crate::mail_list::has_flag(&unavailable.flags(9), "\\Seen"));
    let mut occupied = Vec::new();
    while let Some(guard) = fixture.app.request_budgets.mailbox_workers.try_acquire() {
        occupied.push(guard);
    }
    assert!(!occupied.is_empty());
    let busy = fixture.post("/message/open", &form);
    assert_eq!(busy.response.status_code, 503);
    assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
    drop(occupied);
    assert_eq!(
        fixture.post("/message/open", &form).response.status_code,
        303
    );
}

#[test]
fn mark_read_display_receipt_is_readonly_and_cannot_remove_other_filter_predicates() {
    let fixture = MarkReadFixture::new();
    fixture
        .store
        .save("alice@example.com", 0, Policy::OnOpen)
        .unwrap();
    let origin = "/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc&selected_mailbox=INBOX&selected_uid=9";
    let opened = fixture.post("/message/open", &fixture.open_form(9, origin));
    assert_eq!(opened.response.status_code, 303);
    let target = location_header(&opened);
    let baseline_flags = fixture.flags(9);
    for _ in 0..2 {
        let read = fixture.get(&target);
        assert_eq!(read.response.status_code, 200);
        assert!(body_text(&read).contains("Synthetic message 9 in INBOX"));
        assert_eq!(fixture.flags(9), baseline_flags);
        assert!(!read
            .audit_events
            .iter()
            .any(|event| event.action == "message_flag_result"));
    }
    for exclusion in [
        "&from=other%40example.test",
        "&attachment=with",
        "&pgp=plain",
        "&after=2099-01-01",
    ] {
        let read = fixture.get(&format!("{target}{exclusion}"));
        assert_eq!(read.response.status_code, 200);
        assert!(
            !body_text(&read).contains("Synthetic message 9 in INBOX"),
            "{exclusion}"
        );
        assert_eq!(fixture.flags(9), baseline_flags);
    }
    let starred = fixture.get(&target.replace("filter=unread", "filter=starred"));
    assert!(!body_text(&starred).contains("Synthetic message 9 in INBOX"));
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    let forged = format!(
        "{origin}&selected_mailbox_guid={}&selected_message_guid={}&opened_read=1",
        version.mailbox_guid,
        url_encode(&version.message_guid)
    );
    let readonly = fixture.get(&forged);
    assert_eq!(readonly.response.status_code, 200);
    assert_eq!(fixture.flags(9), baseline_flags);
    assert!(!readonly
        .audit_events
        .iter()
        .any(|event| event.action == "message_flag_result"));
    let stale =
        fixture.get(&forged.replace(&url_encode(&version.message_guid), "absent-owned-guid"));
    assert!(!body_text(&stale).contains("Synthetic message 9 in INBOX"));
}

#[test]
fn mark_read_settings_native_cas_isolated_and_legacy_reading_save_preserves_policy() {
    let fixture = MarkReadFixture::new();
    let form = BTreeMap::from([
        (
            "csrf_token".into(),
            StubGateway::validated_session().record.csrf_token,
        ),
        ("expected_revision".into(), "0".into()),
        ("policy".into(), "on_open".into()),
        ("section".into(), "general".into()),
    ]);
    let mut bad_csrf = form.clone();
    bad_csrf.insert("csrf_token".into(), "wrong".into());
    assert_eq!(
        fixture
            .post("/settings/mark-read", &bad_csrf)
            .response
            .status_code,
        403
    );
    assert_eq!(fixture.store.load("alice@example.com").unwrap().revision, 0);
    let saved = fixture.post("/settings/mark-read", &form);
    assert_eq!(saved.response.status_code, 303);
    assert_eq!(location_header(&saved), "/settings?section=general");
    assert_eq!(
        fixture.store.load("alice@example.com").unwrap().policy,
        Policy::OnOpen
    );
    assert_eq!(
        fixture.store.load("bob@example.com").unwrap().policy,
        Policy::Manual
    );
    assert_eq!(
        fixture
            .post("/settings/mark-read", &form)
            .response
            .status_code,
        409
    );
    let reading = BTreeMap::from([
        (
            "csrf_token".into(),
            StubGateway::validated_session().record.csrf_token,
        ),
        ("start_page".into(), "drafts".into()),
        ("date_order".into(), "oldest".into()),
    ]);
    assert_eq!(
        fixture
            .post("/settings/reading", &reading)
            .response
            .status_code,
        303
    );
    assert_eq!(
        Store::new(fixture.root.join("settings"))
            .load("alice@example.com")
            .unwrap()
            .policy,
        Policy::OnOpen
    );
    for section in ["general", "reading"] {
        let settings = fixture.get(&format!("/settings?section={section}"));
        assert_eq!(settings.response.status_code, 200);
        assert!(body_text(&settings).contains("value=\"on_open\" selected"));
        assert!(body_text(&settings).contains("name=\"expected_revision\" value=\"1\""));
    }
    let mut reset = form;
    reset.insert("expected_revision".into(), "1".into());
    reset.insert("policy".into(), "manual".into());
    reset.insert("section".into(), "reading".into());
    assert_eq!(
        fixture
            .post("/settings/mark-read", &reset)
            .response
            .status_code,
        303
    );
    assert_eq!(
        fixture.store.load("alice@example.com").unwrap().policy,
        Policy::Manual
    );
    assert!(!crate::mail_list::has_flag(&fixture.flags(9), "\\Seen"));
}
