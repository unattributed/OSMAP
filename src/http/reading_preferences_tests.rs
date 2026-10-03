use super::*;
use crate::reading_preferences::{DateOrder, ReadingPreferences, ReadingPreferencesStore, StartPage};

struct Fixture {
    root: PathBuf,
    store: ReadingPreferencesStore,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!("reading-http-{}", crate::draft::generate_draft_id().unwrap()));
        let store = ReadingPreferencesStore::new(root.join("preferences"));
        store.save("alice@example.com", ReadingPreferences::default()).unwrap();
        Self { app: BrowserApp::new(HttpPolicy::default(), StubGateway {
            reading_preferences_store: Some(store.clone()),
            settings_store: Some(crate::settings::FileUserSettingsStore::new(root.join("settings"))),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        }), root, store }
    }
    fn perform(&self, method: &str, path: &str, body: &str, cookie: Option<&str>) -> HandledHttpResponse {
        let mut req = request(method, path, &authenticated_same_origin_headers(), body);
        if let Some(cookie) = cookie {
            req.headers.get_mut("cookie").unwrap().push_str(&format!("; {cookie}"));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn save_body(&self) -> String {
        format!("csrf_token={}&start_page=drafts&date_order=oldest", StubGateway::validated_session().record.csrf_token)
    }
    fn record(&self) -> PathBuf {
        fs::read_dir(self.root.join("preferences")).unwrap().map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|v| v == "json")).unwrap()
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

#[test]
fn reading_native_save_reopens_account_state_and_login_uses_store_not_cookie() {
    let f = Fixture::new();
    let result = f.perform("POST", "/settings/reading", &f.save_body(), None);
    assert_eq!(result.response.status_code, 303);
    assert_eq!(location_header(&result), "/settings?section=reading&updated=1");
    let expected = ReadingPreferences { start_page: StartPage::Drafts, date_order: DateOrder::Oldest, show_source_shortcut: false, attachment_details: false };
    assert_eq!(ReadingPreferencesStore::new(f.root.join("preferences")).load("alice@example.com").unwrap(), expected);
    assert_eq!(f.store.load("bob@example.com").unwrap(), ReadingPreferences::default());
    assert!(result.response.headers.iter().any(|(k,v)| k == "Set-Cookie" && v == &expected.cookie(f.app.policy.secure_session_cookie)));
    let page = f.perform("GET", "/settings?section=reading", "", None);
    assert_eq!(page.response.status_code, 200);
    assert!(body_text(&page).contains("value=\"drafts\" selected"));
    let fake = "osmap_reading=v1.sent.newest.1.1";
    let login = f.perform("POST", "/login", "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456", Some(fake));
    assert_eq!(location_header(&login), "/drafts");
    assert!(login.response.headers.iter().any(|(k,v)| k == "Set-Cookie" && v == &expected.cookie(f.app.policy.secure_session_cookie)));
    let root = f.perform("GET", "/", "", Some(fake));
    assert_eq!(location_header(&root), "/drafts");
    let bob = f.perform("POST", "/login", "username=bob%40example.com&password=correct+horse+battery+staple&totp_code=123456", Some(fake));
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
    let bad_csrf = good.replace(&StubGateway::validated_session().record.csrf_token, "invalid");
    assert_eq!(f.perform("POST", "/settings/reading", &bad_csrf, None).response.status_code, 403);
    assert_eq!(fs::read(f.record()).unwrap(), before);
}

#[test]
fn reading_saved_order_overrides_stale_cookie_but_explicit_sort_wins() {
    let f = Fixture::new();
    let check_order = |path: &str, cookie: &str, oldest: bool| {
        let response = f.perform("GET", path, "", Some(cookie));
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert_eq!(body.find("Quarterly report").unwrap() < body.find("Follow-up").unwrap(), oldest);
    };
    let oldest = "osmap_reading=v1.mailbox.oldest.1.1";
    check_order("/mailbox?name=INBOX", oldest, false);
    assert_eq!(f.perform("POST", "/settings/reading", &f.save_body(), None).response.status_code, 303);
    let stale = "osmap_reading=v1.mailbox.newest.1.1";
    check_order("/mailbox?name=INBOX", stale, true);
    check_order("/mailbox?name=INBOX&sort=received&dir=desc", oldest, false);
    check_order("/mailbox?name=INBOX", "osmap_reading=invalid", true);
    check_order("/mailbox?name=INBOX&sort=subject&dir=asc", oldest, false);
}

#[test]
fn reading_hidden_presentation_does_not_change_reader_content_or_source_authority() {
    let f = Fixture::new();
    let cookie = "osmap_reading=v1.mailbox.newest.0.0";
    let page = f.perform("GET", "/message?mailbox=INBOX&uid=9", "", Some(cookie));
    assert_eq!(page.response.status_code, 200);
    let html = body_text(&page);
    assert!(html.contains("<body data-reading-source=\"false\" data-reading-attachment-details=\"false\">"));
    assert!(html.contains("class=\"reader-source-shortcut\"") && html.contains("Remote content blocked"));
    let source = f.perform("GET", "/message?mailbox=INBOX&uid=9&view=source", "", Some(cookie));
    assert_eq!(source.response.status_code, 200);
    let unauth = request("GET", "/message?mailbox=INBOX&uid=9&view=source", &[("cookie", cookie)], "");
    let denied = f.app.handle_request(&unauth, "127.0.0.1");
    assert_eq!(location_header(&denied), "/login");
    let mut download = html_response(200, "OK", "Synthetic", "<p>bytes</p>").with_header("Content-Disposition", "attachment");
    let before = download.body.clone();
    super::super::routes_reading_preferences::apply_presentation(&mut download, Some(cookie));
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
    assert!(!save.response.headers.iter().any(|(k,_)| k == "Set-Cookie"));
    assert_eq!(fs::read(f.record()).unwrap(), before);
}

#[test]
fn reading_existing_content_and_archive_saves_return_to_reading_with_finite_destination() {
    let f = Fixture::new();
    let form = format!("csrf_token={}&html_display_preference=prefer_plain_text&archive_mailbox_name=INBOX&return_section=reading", StubGateway::validated_session().record.csrf_token);
    let saved = f.perform("POST", "/settings", &form, None);
    assert_eq!(saved.response.status_code, 303);
    assert_eq!(location_header(&saved), "/settings?section=reading&updated=1");
    let bad = form.replace("return_section=reading", "return_section=%2F%2Foutside.test").replace("prefer_plain_text", "prefer_sanitized_html");
    assert_eq!(f.perform("POST", "/settings", &bad, None).response.status_code, 400);
    let store = crate::settings::FileUserSettingsStore::new(f.root.join("settings"));
    let value = crate::settings::UserSettingsStore::load(&store, "alice@example.com").unwrap().unwrap();
    assert_eq!(value.html_display_preference, HtmlDisplayPreference::PreferPlainText);
    assert_eq!(value.archive_mailbox_name.as_deref(), Some("INBOX"));
}
