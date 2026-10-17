use super::*;
use crate::timezone::{FixedOffset, Store};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(temp_dir(&format!(
            "timezone-{}",
            crate::draft::generate_draft_id().unwrap()
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn setting_fields(html: &str, offset: &str) -> BTreeMap<String, String> {
    let form = html
        .split_once("<form id=\"general-timezone-form\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    let mut fields = BTreeMap::new();
    for input in form.split("<input ").skip(1) {
        let attr = |key: &str| {
            input
                .split_once(&format!("{key}=\""))
                .unwrap()
                .1
                .split('"')
                .next()
                .unwrap()
                .to_string()
        };
        assert!(fields.insert(attr("name"), attr("value")).is_none());
    }
    assert_eq!(fields.len(), 2);
    fields.insert("timezone".into(), offset.into());
    fields
}

fn encoded(fields: &BTreeMap<String, String>) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

#[test]
fn timezone_real_runtime_generated_form_persists_reloads_and_isolates_accounts() {
    use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
    use crate::totp::SystemTimeProvider;
    let root = Scratch::new();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "timezone-runtime",
        "127.0.0.1",
        "Firefox/Test",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(root.0.join("sessions")),
        SystemTimeProvider,
        SystemRandomSource,
        3600,
        1800,
    );
    let alice = sessions
        .issue(&context, "alice@example.com", RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, "bob@example.com", RequiredSecondFactor::Totp)
        .unwrap();
    let runtime = || {
        BrowserApp::new(
            HttpPolicy::default(),
            RuntimeBrowserGateway::for_test(&root.0)
                .with_fixture_sendmail_path(root.0.join("owned-nonexistent-sendmail")),
        )
    };
    let call = |app: &BrowserApp<RuntimeBrowserGateway>,
                session: &crate::session::IssuedSession,
                method: &str,
                path: &str,
                fields: &BTreeMap<String, String>| {
        let cookie = format!("osmap_session={}", session.token.as_str());
        let headers = [
            ("Cookie", cookie.as_str()),
            ("User-Agent", "Firefox/Test"),
            ("Origin", "http://localhost"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ];
        app.handle_request(
            &request(method, path, &headers, &encoded(fields)),
            "127.0.0.1",
        )
    };
    let original = crate::mark_read::Store::new(root.0.join("settings"))
        .save("alice@example.com", 0, crate::mark_read::Policy::OnOpen)
        .unwrap();
    let app = runtime();
    let shown = call(
        &app,
        &alice,
        "GET",
        "/settings?section=general",
        &BTreeMap::new(),
    );
    assert_eq!(shown.response.status_code, 200, "{}", body_text(&shown));
    let fields = setting_fields(&body_text(&shown), "+05:45");
    assert_eq!(fields["expected_revision"], "0");
    let saved = call(&app, &alice, "POST", "/settings/timezone", &fields);
    assert_eq!(saved.response.status_code, 303, "{}", body_text(&saved));
    assert_eq!(
        location_header(&saved),
        "/settings?section=general&updated=1"
    );
    drop(app);
    let app = runtime();
    let shown = call(
        &app,
        &alice,
        "GET",
        "/settings?section=general",
        &BTreeMap::new(),
    );
    assert!(body_text(&shown).contains("value=\"+05:45\" selected>UTC+05:45"));
    assert_eq!(
        setting_fields(&body_text(&shown), "UTC")["expected_revision"],
        "1"
    );
    let bob_page = call(
        &app,
        &bob,
        "GET",
        "/settings?section=general",
        &BTreeMap::new(),
    );
    assert!(body_text(&bob_page).contains("value=\"UTC\" selected>UTC"));
    assert_eq!(
        call(&app, &alice, "POST", "/settings/timezone", &fields)
            .response
            .status_code,
        409
    );
    assert_eq!(
        crate::mark_read::Store::new(root.0.join("settings")).load("alice@example.com"),
        Ok(original)
    );
    let store = Store::new(root.0.join("settings"));
    assert_eq!(
        store.load("alice@example.com").unwrap().offset,
        FixedOffset::parse("+05:45").unwrap()
    );
    assert_eq!(store.load("bob@example.com").unwrap().revision, 0);
}

#[test]
fn timezone_mailbox_search_and_both_readers_use_current_store_not_cookies() {
    let root = Scratch::new();
    let store = Store::new(root.0.join("settings"));
    store
        .save(
            "alice@example.com",
            0,
            FixedOffset::parse("-05:00").unwrap(),
        )
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            timezone_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        },
    );
    let get = |path: &str, bob: bool| {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers.insert(
            "cookie".into(),
            format!(
                "osmap_session={}; osmap_timezone=+14:00",
                if bob { "b".repeat(64) } else { "a".repeat(64) }
            ),
        );
        app.handle_request(&req, "127.0.0.1")
    };
    for path in [
        "/mailbox?name=INBOX",
        "/mailbox?name=Archive%2F2026",
        "/search?mailbox=INBOX&q=report",
        "/search?q=report&category=all",
        "/message?mailbox=INBOX&uid=7",
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=7",
    ] {
        let shown = get(path, false);
        assert_eq!(shown.response.status_code, 200, "{path}");
        assert!(
            body_text(&shown).contains("UTC-05:00"),
            "{path}: converted date must be shown"
        );
        assert!(!body_text(&shown).contains("UTC+14:00"));
        assert!(!body_text(&get(path, true)).contains("UTC-05:00"));
    }
    let reader = body_text(&get("/message?mailbox=INBOX&uid=7", false));
    assert!(reader.contains("2026-03-27 06:00:00 UTC-05:00"));
    store
        .save(
            "alice@example.com",
            1,
            FixedOffset::parse("+05:45").unwrap(),
        )
        .unwrap();
    assert!(body_text(&get("/message?mailbox=INBOX&uid=7", false))
        .contains("2026-03-27 16:45:00 UTC+05:45"));
}

#[test]
fn timezone_http_refuses_invalid_duplicate_crossorigin_csrf_and_corrupt_saves() {
    let root = Scratch::new();
    let store = Store::new(root.0.join("settings"));
    let before = store
        .save(
            "alice@example.com",
            0,
            FixedOffset::parse("-05:00").unwrap(),
        )
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            timezone_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let fields = BTreeMap::from([
        (
            "csrf_token".into(),
            StubGateway::validated_session().record.csrf_token,
        ),
        ("expected_revision".into(), "1".into()),
        ("timezone".into(), "UTC".into()),
    ]);
    let good = encoded(&fields);
    for bad in [
        good.replace("timezone=UTC", "timezone=%2B99%3A00"),
        format!("{good}&timezone=UTC"),
        format!("{good}&account=bob%40example.com"),
        good.replace(&fields["csrf_token"], "wrong"),
        good.replace("expected_revision=1", "expected_revision=01"),
    ] {
        let shown = app.handle_request(
            &request(
                "POST",
                "/settings/timezone",
                &authenticated_same_origin_headers(),
                &bad,
            ),
            "127.0.0.1",
        );
        assert!(shown.response.status_code >= 400);
        assert_eq!(store.load("alice@example.com"), Ok(before.clone()));
    }
    let mut foreign = request(
        "POST",
        "/settings/timezone",
        &authenticated_same_origin_headers(),
        &good,
    );
    foreign
        .headers
        .insert("origin".into(), "https://foreign.invalid".into());
    assert_eq!(
        app.handle_request(&foreign, "127.0.0.1")
            .response
            .status_code,
        403
    );
    let record = fs::read_dir(root.0.join("settings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|value| value == "json"))
        .unwrap();
    fs::write(&record, b"corrupt").unwrap();
    let shown = app.handle_request(
        &request(
            "GET",
            "/settings?section=general",
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert!(body_text(&shown).contains("Saved timezone unavailable"));
    assert!(!body_text(&shown).contains("action=\"/settings/timezone\""));
    assert_eq!(
        app.handle_request(
            &request(
                "POST",
                "/settings/timezone",
                &authenticated_same_origin_headers(),
                &good
            ),
            "127.0.0.1"
        )
        .response
        .status_code,
        503
    );
    assert_eq!(fs::read(&record).unwrap(), b"corrupt");
}
