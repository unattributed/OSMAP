use super::*;
use crate::reading_preferences::{
    DateOrder, ReadingPreferences, ReadingPreferencesStore, StartPage,
};

struct Fixture {
    root: PathBuf,
    store: ReadingPreferencesStore,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "reading-http-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = ReadingPreferencesStore::new(root.join("preferences"));
        store
            .save("alice@example.com", ReadingPreferences::default())
            .unwrap();
        Self {
            app: BrowserApp::new(
                HttpPolicy::default(),
                StubGateway {
                    reading_preferences_store: Some(store.clone()),
                    settings_store: Some(crate::settings::FileUserSettingsStore::new(
                        root.join("settings"),
                    )),
                    browser_fixture_accounts: true,
                    ..StubGateway::default()
                },
            ),
            root,
            store,
        }
    }
    fn perform(
        &self,
        method: &str,
        path: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> HandledHttpResponse {
        let mut req = request(method, path, &authenticated_same_origin_headers(), body);
        if let Some(cookie) = cookie {
            req.headers
                .get_mut("cookie")
                .unwrap()
                .push_str(&format!("; {cookie}"));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn save_body(&self) -> String {
        format!(
            "csrf_token={}&start_page=drafts&date_order=oldest",
            StubGateway::validated_session().record.csrf_token
        )
    }
    fn record(&self) -> PathBuf {
        fs::read_dir(self.root.join("preferences"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|v| v == "json"))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn reading_native_save_reopens_account_state_and_login_uses_store_not_cookie() {
    let f = Fixture::new();
    let result = f.perform("POST", "/settings/reading", &f.save_body(), None);
    assert_eq!(result.response.status_code, 303);
    assert_eq!(
        location_header(&result),
        "/settings?section=reading&updated=1"
    );
    let expected = ReadingPreferences {
        start_page: StartPage::Drafts,
        date_order: DateOrder::Oldest,
        show_source_shortcut: false,
        attachment_details: false,
    };
    assert_eq!(
        ReadingPreferencesStore::new(f.root.join("preferences"))
            .load("alice@example.com")
            .unwrap(),
        expected
    );
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        ReadingPreferences::default()
    );
    assert!(result.response.headers.iter().any(
        |(k, v)| k == "Set-Cookie" && v == &expected.cookie(f.app.policy.secure_session_cookie)
    ));
    let page = f.perform("GET", "/settings?section=reading", "", None);
    assert_eq!(page.response.status_code, 200);
    assert!(body_text(&page).contains("value=\"drafts\" selected"));
    let fake = "osmap_reading=v1.sent.newest.1.1";
    let login = f.perform(
        "POST",
        "/login",
        "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456",
        Some(fake),
    );
    assert_eq!(location_header(&login), "/drafts");
    assert!(login.response.headers.iter().any(
        |(k, v)| k == "Set-Cookie" && v == &expected.cookie(f.app.policy.secure_session_cookie)
    ));
    let root = f.perform("GET", "/", "", Some(fake));
    assert_eq!(location_header(&root), "/drafts");
    let bob = f.perform(
        "POST",
        "/login",
        "username=bob%40example.com&password=correct+horse+battery+staple&totp_code=123456",
        Some(fake),
    );
    assert_eq!(location_header(&bob), "/mailboxes");
}

#[test]
fn reading_invalid_forms_and_csrf_never_change_saved_bytes() {
    let f = Fixture::new();
    let before = fs::read(f.record()).unwrap();
    let good = f.save_body();
    for body in [
        good.replace("drafts", "//external.test"),
        good.replace("oldest", "threaded"),
        format!("{good}&show_source_shortcut=false"),
        format!("{good}&attachment_details=2"),
        format!("{good}&start_page=sent"),
        format!("{good}&account=bob"),
        good.replace("&date_order=oldest", ""),
        format!("{good}&{}", "x".repeat(769)),
    ] {
        let response = f.perform("POST", "/settings/reading", &body, None);
        assert_eq!(response.response.status_code, 400);
        assert_eq!(fs::read(f.record()).unwrap(), before);
    }
    let bad_csrf = good.replace(
        &StubGateway::validated_session().record.csrf_token,
        "invalid",
    );
    assert_eq!(
        f.perform("POST", "/settings/reading", &bad_csrf, None)
            .response
            .status_code,
        403
    );
    assert_eq!(fs::read(f.record()).unwrap(), before);
}

#[test]
fn reading_saved_order_overrides_stale_cookie_but_explicit_sort_wins() {
    let f = Fixture::new();
    let check_order = |path: &str, cookie: &str, oldest: bool| {
        let response = f.perform("GET", path, "", Some(cookie));
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert_eq!(
            body.find("Quarterly report").unwrap() < body.find("Follow-up").unwrap(),
            oldest
        );
    };
    let oldest = "osmap_reading=v1.mailbox.oldest.1.1";
    check_order("/mailbox?name=INBOX", oldest, false);
    assert_eq!(
        f.perform("POST", "/settings/reading", &f.save_body(), None)
            .response
            .status_code,
        303
    );
    let stale = "osmap_reading=v1.mailbox.newest.1.1";
    check_order("/mailbox?name=INBOX", stale, true);
    check_order("/mailbox?name=INBOX&sort=received&dir=desc", oldest, false);
    check_order("/mailbox?name=INBOX", "osmap_reading=invalid", true);
    check_order("/mailbox?name=INBOX&sort=subject&dir=asc", oldest, false);
}

#[test]
fn reading_hidden_presentation_does_not_change_reader_content_or_source_authority() {
    let f = Fixture::new();
    // Visibility follows the authenticated account's saved record, never a
    // cookie hint. The source endpoint remains separately authorized.
    let csrf = StubGateway::validated_session().record.csrf_token;
    assert_eq!(
        f.perform(
            "POST",
            "/settings/reading",
            &presentation_save_form(false, false, &csrf),
            None
        )
        .response
        .status_code,
        303
    );
    let cookie = "osmap_reading=v1.mailbox.newest.1.1";
    let page = f.perform("GET", "/message?mailbox=INBOX&uid=9", "", Some(cookie));
    assert_eq!(page.response.status_code, 200);
    let html = body_text(&page);
    assert!(html.contains(
        "<body data-reading-source=\"false\" data-reading-attachment-details=\"false\">"
    ));
    assert!(
        html.contains("class=\"reader-source-shortcut\"")
            && html.contains("Remote content blocked")
    );
    let source = f.perform(
        "GET",
        "/message?mailbox=INBOX&uid=9&view=source",
        "",
        Some(cookie),
    );
    assert_eq!(source.response.status_code, 200);
    let unauth = request(
        "GET",
        "/message?mailbox=INBOX&uid=9&view=source",
        &[("cookie", cookie)],
        "",
    );
    let denied = f.app.handle_request(&unauth, "127.0.0.1");
    assert_eq!(location_header(&denied), "/login");
    let mut download = html_response(200, "OK", "Synthetic", "<p>bytes</p>")
        .with_header("Content-Disposition", "attachment");
    let before = download.body.clone();
    super::super::routes_reading_preferences::apply_presentation(
        &mut download,
        ReadingPreferences {
            show_source_shortcut: false,
            attachment_details: false,
            ..ReadingPreferences::default()
        },
    );
    assert_eq!(download.body, before);
}

#[test]
fn reading_corrupt_store_refuses_load_and_save_without_overwrite_or_success_cookie() {
    let f = Fixture::new();
    fs::write(f.record(), b"corrupt synthetic reading preferences").unwrap();
    let before = fs::read(f.record()).unwrap();
    let load = f.perform("GET", "/settings?section=reading", "", None);
    assert_eq!(load.response.status_code, 503);
    assert!(!body_text(&load).contains("id=\"reading-preferences-form\""));
    let save = f.perform("POST", "/settings/reading", &f.save_body(), None);
    assert_eq!(save.response.status_code, 503);
    assert!(body_text(&save).contains("could not be confirmed"));
    assert!(!save.response.headers.iter().any(|(k, _)| k == "Set-Cookie"));
    assert_eq!(fs::read(f.record()).unwrap(), before);
}

#[test]
fn reading_existing_content_and_archive_saves_return_to_reading_with_finite_destination() {
    let f = Fixture::new();
    let form = format!("csrf_token={}&html_display_preference=prefer_plain_text&archive_mailbox_name=INBOX&return_section=reading", StubGateway::validated_session().record.csrf_token);
    let saved = f.perform("POST", "/settings", &form, None);
    assert_eq!(saved.response.status_code, 303);
    assert_eq!(
        location_header(&saved),
        "/settings?section=reading&updated=1"
    );
    let bad = form
        .replace(
            "return_section=reading",
            "return_section=%2F%2Foutside.test",
        )
        .replace("prefer_plain_text", "prefer_sanitized_html");
    assert_eq!(
        f.perform("POST", "/settings", &bad, None)
            .response
            .status_code,
        400
    );
    let store = crate::settings::FileUserSettingsStore::new(f.root.join("settings"));
    let value = crate::settings::UserSettingsStore::load(&store, "alice@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(
        value.html_display_preference,
        HtmlDisplayPreference::PreferPlainText
    );
    assert_eq!(value.archive_mailbox_name.as_deref(), Some("INBOX"));
}

// Actual ReadingPreferencesStore-backed authenticated route regressions.

fn presentation_save_form(source: bool, attachments: bool, csrf: &str) -> String {
    format!(
        "csrf_token={csrf}&start_page=mailbox&date_order=newest{}{}",
        if source {
            "&show_source_shortcut=1"
        } else {
            ""
        },
        if attachments {
            "&attachment_details=1"
        } else {
            ""
        }
    )
}

fn presentation_as(
    f: &Fixture,
    method: &str,
    path: &str,
    body: &str,
    bob: bool,
    reading_cookie: &str,
) -> HandledHttpResponse {
    let mut req = request(method, path, &authenticated_same_origin_headers(), body);
    let token = if bob { "b".repeat(64) } else { "a".repeat(64) };
    req.headers.insert(
        "cookie".into(),
        format!("osmap_session={token}; {reading_cookie}"),
    );
    f.app.handle_request(&req, "127.0.0.1")
}

fn presentation_body_matches(response: &HandledHttpResponse, source: bool, attachments: bool) {
    assert_eq!(
        response.response.status_code,
        200,
        "{}",
        body_text(response)
    );
    assert!(
        body_text(response).contains(&format!(
        "<body data-reading-source=\"{source}\" data-reading-attachment-details=\"{attachments}\">"
    )),
        "reader presentation must use the current authenticated account's saved choices"
    );
}

fn presentation_switch_matches(html: &str, id: &str, expected: bool) {
    let marker = format!("id=\"{id}\"");
    let start = html.find(&marker).expect("real stored Reading switch");
    let tag = html[start..].split_once('>').unwrap().0;
    assert!(tag.contains("type=\"checkbox\"") && tag.contains("form=\"reading-preferences-form\""));
    assert_eq!(tag.contains(" checked"), expected, "stored switch {id}");
}

#[test]
fn reading_saved_presentation_overrides_stale_cookie_on_reader_and_settings_routes() {
    let f = Fixture::new();
    let csrf = StubGateway::validated_session().record.csrf_token;
    // Independent source/attachment choices catch accidental merging of the two fields.
    for (source, attachments) in [(false, false), (true, true), (false, true), (true, false)] {
        let stale = format!(
            "osmap_reading=v1.sent.oldest.{}.{}",
            u8::from(!source),
            u8::from(!attachments)
        );
        let saved = f.perform(
            "POST",
            "/settings/reading",
            &presentation_save_form(source, attachments, &csrf),
            Some(&stale),
        );
        assert_eq!(saved.response.status_code, 303);
        let expected = ReadingPreferences {
            show_source_shortcut: source,
            attachment_details: attachments,
            ..ReadingPreferences::default()
        };
        assert_eq!(
            ReadingPreferencesStore::new(f.root.join("preferences"))
                .load("alice@example.com")
                .unwrap(),
            expected
        );
        let before = fs::read(f.record()).unwrap();
        let flags = f
            .app
            .gateway
            .fixture_message_flags("alice@example.com", "INBOX", 9);
        for path in [
            "/message?mailbox=INBOX&uid=9",
            "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9",
        ] {
            let reader = f.perform("GET", path, "", Some(&stale));
            presentation_body_matches(&reader, source, attachments);
            assert!(body_text(&reader).contains("Hello world"));
            assert!(body_text(&reader).contains("reader-source-shortcut"));
            assert!(body_text(&reader).contains("Remote content blocked"));
        }
        let settings = f.perform("GET", "/settings?section=reading", "", Some(&stale));
        presentation_body_matches(&settings, source, attachments);
        let html = body_text(&settings);
        presentation_switch_matches(&html, "reading-show-source", source);
        presentation_switch_matches(&html, "reading-attachment-details", attachments);
        assert_eq!(
            fs::read(f.record()).unwrap(),
            before,
            "GET cannot save stale cookies"
        );
        assert_eq!(
            f.app
                .gateway
                .fixture_message_flags("alice@example.com", "INBOX", 9),
            flags
        );
        assert_eq!(f.app.request_budgets.mailbox_workers.active_count(), 0);
    }
}

#[test]
fn reading_saved_presentation_does_not_depend_on_a_present_or_valid_cookie() {
    let f = Fixture::new();
    let saved = f.perform(
        "POST",
        "/settings/reading",
        &presentation_save_form(
            false,
            false,
            &StubGateway::validated_session().record.csrf_token,
        ),
        None,
    );
    assert_eq!(saved.response.status_code, 303);
    for cookie in [
        None,
        Some("osmap_reading=invalid"),
        Some("osmap_reading=v1.mailbox.newest.1.1; osmap_reading=v1.mailbox.newest.0.0"),
    ] {
        let reader = f.perform("GET", "/message?mailbox=INBOX&uid=9", "", cookie);
        presentation_body_matches(&reader, false, false);
        let source = f.perform(
            "GET",
            "/message?mailbox=INBOX&uid=9&view=source",
            "",
            cookie,
        );
        assert_eq!(
            source.response.status_code, 200,
            "presentation never changes source authority"
        );
    }
}

#[test]
fn reading_saved_presentation_is_account_owned_despite_a_foreign_accounts_cookie() {
    let f = Fixture::new();
    let alice_csrf = StubGateway::validated_session().record.csrf_token;
    let alice = f.perform(
        "POST",
        "/settings/reading",
        &presentation_save_form(false, false, &alice_csrf),
        None,
    );
    assert_eq!(alice.response.status_code, 303);
    let alice_cookie = "osmap_reading=v1.mailbox.newest.0.0";
    let bob = presentation_as(
        &f,
        "POST",
        "/settings/reading",
        &presentation_save_form(true, true, &"c".repeat(64)),
        true,
        alice_cookie,
    );
    assert_eq!(bob.response.status_code, 303);
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        ReadingPreferences::default()
    );
    let alice_expected = ReadingPreferences {
        show_source_shortcut: false,
        attachment_details: false,
        ..ReadingPreferences::default()
    };
    assert_eq!(f.store.load("alice@example.com").unwrap(), alice_expected);
    for path in [
        "/message?mailbox=INBOX&uid=9",
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9",
        "/settings?section=reading",
    ] {
        let bob_reader = presentation_as(&f, "GET", path, "", true, alice_cookie);
        presentation_body_matches(&bob_reader, true, true);
        if path.starts_with("/settings") {
            let html = body_text(&bob_reader);
            presentation_switch_matches(&html, "reading-show-source", true);
            presentation_switch_matches(&html, "reading-attachment-details", true);
        }
        let alice_reader = presentation_as(
            &f,
            "GET",
            path,
            "",
            false,
            "osmap_reading=v1.mailbox.newest.1.1",
        );
        presentation_body_matches(&alice_reader, false, false);
    }
    assert_eq!(f.store.load("alice@example.com").unwrap(), alice_expected);
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        ReadingPreferences::default()
    );
    assert_eq!(f.app.request_budgets.mailbox_workers.active_count(), 0);
}

#[test]
fn reading_unavailable_saved_presentation_uses_finite_defaults_without_cookie_or_write() {
    let f = Fixture::new();
    let csrf = StubGateway::validated_session().record.csrf_token;
    assert_eq!(
        f.perform(
            "POST",
            "/settings/reading",
            &presentation_save_form(false, false, &csrf),
            None
        )
        .response
        .status_code,
        303
    );
    let record = f.record();
    fs::write(&record, b"unavailable synthetic reading state").unwrap();
    for cookie in [
        "osmap_reading=v1.mailbox.newest.0.0",
        "osmap_reading=v1.mailbox.newest.1.0",
    ] {
        let reader = f.perform("GET", "/message?mailbox=INBOX&uid=9", "", Some(cookie));
        presentation_body_matches(&reader, true, true);
        assert!(body_text(&reader).contains("Hello world"));
        let settings = f.perform("GET", "/settings?section=reading", "", Some(cookie));
        assert_eq!(settings.response.status_code, 503);
        assert!(!body_text(&settings).contains("id=\"reading-preferences-form\""));
        assert_eq!(
            fs::read(&record).unwrap(),
            b"unavailable synthetic reading state"
        );
    }
    assert_eq!(f.app.request_budgets.mailbox_workers.active_count(), 0);
}

#[test]
fn reading_presentation_scope_cannot_survive_reused_request_or_invalid_session() {
    let f = Fixture::new();
    let csrf = StubGateway::validated_session().record.csrf_token;
    assert_eq!(
        f.perform(
            "POST",
            "/settings/reading",
            &presentation_save_form(false, false, &csrf),
            None
        )
        .response
        .status_code,
        303
    );
    let mut req = request(
        "GET",
        "/message?mailbox=INBOX&uid=9",
        &authenticated_headers(),
        "",
    );
    req.headers
        .get_mut("cookie")
        .unwrap()
        .push_str("; osmap_reading=v1.mailbox.newest.0.0");
    let alice = f.app.handle_request(&req, "127.0.0.1");
    presentation_body_matches(&alice, false, false);
    assert!(req.notification_context.borrow().session.is_none());
    assert!(req
        .notification_context
        .borrow()
        .authentication_context
        .is_none());
    req.headers.insert(
        "cookie".into(),
        format!(
            "osmap_session={}; osmap_reading=v1.mailbox.newest.0.0",
            "b".repeat(64)
        ),
    );
    let bob = f.app.handle_request(&req, "127.0.0.1");
    presentation_body_matches(&bob, true, true);
    assert!(req.notification_context.borrow().session.is_none());
    assert!(req
        .notification_context
        .borrow()
        .authentication_context
        .is_none());
    // Even pre-existing response context must be discarded before a route can
    // validate this reused request. A cookie is not an account identity.
    {
        let mut scope = req.notification_context.borrow_mut();
        scope.session = Some(StubGateway::validated_session());
        scope.authentication_context = Some(
            AuthenticationContext::new(
                AuthenticationPolicy::default(),
                "reading-scope-fixture",
                "127.0.0.1",
                "Firefox/Test",
            )
            .unwrap(),
        );
    }
    req.headers.insert(
        "cookie".into(),
        "osmap_session=invalid; osmap_reading=v1.mailbox.newest.0.0".into(),
    );
    let denied = f.app.handle_request(&req, "127.0.0.1");
    assert_eq!(denied.response.status_code, 303);
    assert_eq!(location_header(&denied), "/login");
    assert!(!denied
        .audit_events
        .iter()
        .any(|event| event.action == "stub_source_read"));
    assert!(req.notification_context.borrow().session.is_none());
    assert!(req
        .notification_context
        .borrow()
        .authentication_context
        .is_none());
    assert!(
        !f.store
            .load("alice@example.com")
            .unwrap()
            .show_source_shortcut
    );
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        ReadingPreferences::default()
    );
}

#[test]
fn reading_saved_presentation_preserves_actual_source_text_and_attachment_bytes() {
    let f = Fixture::new();
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    let attachment_path = format!(
        "/attachment?mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}&part=1.2",
        version.mailbox_guid, version.message_guid
    );
    let source_text = |response: &HandledHttpResponse| {
        let html = body_text(response);
        let (_, content) = html.split_once("<pre class=\"message-source\" aria-label=\"Stored message source\" tabindex=\"0\">").expect("actual escaped source projection");
        content.split_once("</pre>").unwrap().0.to_owned()
    };
    let mut previous_source = None;
    for enabled in [false, true] {
        assert_eq!(
            f.perform(
                "POST",
                "/settings/reading",
                &presentation_save_form(
                    enabled,
                    enabled,
                    &StubGateway::validated_session().record.csrf_token
                ),
                None
            )
            .response
            .status_code,
            303
        );
        let stale = format!(
            "osmap_reading=v1.mailbox.newest.{}.{}",
            u8::from(!enabled),
            u8::from(!enabled)
        );
        let source = f.perform(
            "GET",
            "/message?mailbox=INBOX&uid=9&view=source",
            "",
            Some(&stale),
        );
        assert_eq!(source.response.status_code, 200);
        let actual_source = source_text(&source);
        assert!(actual_source.contains("&lt;script&gt;inert-source-marker&lt;/script&gt;"));
        if let Some(previous) = &previous_source {
            assert_eq!(&actual_source, previous);
        }
        previous_source = Some(actual_source);
        let download = f.perform("GET", &attachment_path, "", Some(&stale));
        assert_eq!(download.response.status_code, 200);
        assert_eq!(download.response.body, b"%PDF-stub%");
        assert!(download
            .response
            .headers
            .iter()
            .any(|(key, value)| key == "Content-Disposition" && value.starts_with("attachment;")));
        assert_eq!(f.app.request_budgets.mailbox_workers.active_count(), 0);
    }
}
