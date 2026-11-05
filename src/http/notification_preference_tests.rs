use super::*;
use crate::notification_preferences::{DigestMode, Preference, Store};

struct Fixture {
    root: PathBuf,
    store: Store,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "notification-preference-route-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = Store::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                notification_preference_store: Some(store.clone()),
                notification_store: Some(crate::notifications::NotificationStore::new(
                    root.join("settings"),
                )),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }
    fn get(&self) -> HandledHttpResponse {
        self.app.handle_request(
            &request(
                "GET",
                "/settings?section=notifications",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        )
    }
    fn fields(&self) -> BTreeMap<String, String> {
        let response = self.get();
        assert_eq!(response.response.status_code, 200);
        let html = body_text(&response);
        let form = html
            .split("id=\"notification-preferences-form\"")
            .nth(1)
            .unwrap()
            .split("</form>")
            .next()
            .unwrap();
        assert!(form.contains("action=\"/settings/notifications\""));
        let mut fields = BTreeMap::new();
        for name in ["csrf_token", "expected_revision"] {
            let value = form
                .split(&format!("name=\"{name}\" value=\""))
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            fields.insert(name.into(), value.into());
        }
        fields.insert("digest".into(), "daily".into());
        fields
    }
    fn encoded(fields: &BTreeMap<String, String>) -> String {
        fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
    fn post(&self, body: &str, bob: bool) -> HandledHttpResponse {
        let mut req = request(
            "POST",
            "/settings/notifications",
            &authenticated_same_origin_headers(),
            body,
        );
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn notification_settings_generated_digest_form_is_editable() {
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
    let response = app.handle_request(
        &request(
            "GET",
            "/settings?section=notifications",
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(html.contains("id=\"notification-preferences-form\""));
    assert!(html.contains("action=\"/settings/notifications\""));
    assert!(html.contains("name=\"expected_revision\" value=\"0\""));
    let control = html
        .split("id=\"notice-digest\"")
        .nth(1)
        .unwrap()
        .split('>')
        .next()
        .unwrap();
    assert!(!control.contains("disabled"));
    assert!(control.contains("name=\"digest\""));
    assert!(html.contains("value=\"individual\" selected"));
    assert!(html.contains("value=\"daily\">Daily (UTC)</option>"));
}

#[test]
fn notification_preference_confirmation_uses_reloaded_owned_revision_and_reports_all_choice_failures(
) {
    let f = Fixture::new();
    let mut fields = f.fields();
    fields.insert("choice_version".into(), "1".into());
    fields.insert("openpgp".into(), "1".into());
    fields.insert("sound".into(), "1".into());
    let saved = f.post(&Fixture::encoded(&fields), false);
    assert_eq!(saved.response.status_code, 303);
    let location = saved
        .response
        .headers
        .iter()
        .find(|(name, _)| name == "Location")
        .unwrap()
        .1
        .clone();
    assert_eq!(location, "/settings?section=notifications&saved_revision=1");
    let get = |path: &str, bob: bool| {
        let mut req = request("GET", path, &authenticated_headers(), "");
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        f.app.handle_request(&req, "127.0.0.1")
    };
    const RELOADED: &str =
        "Saved notification preferences reloaded. These are your current saved choices.";
    assert!(!body_text(&f.get()).contains(RELOADED));
    let loaded = get(&location, false);
    assert_eq!(loaded.response.status_code, 200);
    assert!(body_text(&loaded).contains(RELOADED));
    assert!(body_text(&loaded).contains("name=\"openpgp\" value=\"1\" checked"));
    assert!(body_text(&loaded).contains("name=\"sound\" value=\"1\" checked"));
    assert!(!body_text(&loaded).contains("name=\"mentions\" value=\"1\" checked"));
    assert!(!body_text(&get(&location, true)).contains(RELOADED));
    for revision in ["0", "01", "18446744073709551616", "%3Cscript%3E"] {
        let read = get(
            &format!("/settings?section=notifications&saved_revision={revision}"),
            false,
        );
        assert_eq!(read.response.status_code, 200);
        assert!(body_text(&read).contains("confirmation link was invalid"));
        assert!(!body_text(&read).contains(RELOADED));
        assert!(!body_text(&read).contains("<script>"));
    }
    let changed = f
        .store
        .save("alice@example.com", 1, DigestMode::Individual)
        .unwrap();
    assert_eq!(changed.revision, 2);
    let outdated = get(&location, false);
    assert!(body_text(&outdated).contains("requested preference revision is no longer current"));
    assert!(!body_text(&outdated).contains(RELOADED));
    let mut invalid = f.fields();
    invalid.insert("sound".into(), "on".into());
    invalid.insert("choice_version".into(), "1".into());
    let refused = f.post(&Fixture::encoded(&invalid), false);
    assert_eq!(refused.response.status_code, 400);
    assert!(body_text(&refused).contains("notification preferences request was invalid"));
    let path = fs::read_dir(f.root.join("settings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| fs::read_to_string(path).is_ok_and(|text| text.contains("\"digest\"")))
        .unwrap();
    fs::write(&path, b"{broken").unwrap();
    let unavailable = get("/settings?section=notifications&saved_revision=2", false);
    assert_eq!(unavailable.response.status_code, 503);
    assert!(
        body_text(&unavailable).contains("Saved notification preferences could not be reloaded")
    );
    assert!(!body_text(&unavailable).contains(RELOADED));
    invalid.remove("sound");
    let refused = f.post(&Fixture::encoded(&invalid), false);
    assert_eq!(refused.response.status_code, 503);
    assert!(body_text(&refused).contains("notification preferences save could not be confirmed"));
    assert_eq!(fs::read(path).unwrap(), b"{broken");
}

#[test]
fn notification_preference_generated_save_restart_stale_invalid_csrf_foreign_and_other_section_preservation(
) {
    let f = Fixture::new();
    let before_other = crate::autosave::Store::new(f.root.join("settings"))
        .save("alice@example.com", 0, true, 60)
        .unwrap();
    let fields = f.fields();
    let body = Fixture::encoded(&fields);
    assert_eq!(f.post(&body, false).response.status_code, 303);
    let saved = f.store.load("alice@example.com").unwrap();
    assert_eq!(saved.digest, DigestMode::Daily);
    assert_eq!(
        Store::new(f.root.join("settings"))
            .load("alice@example.com")
            .unwrap(),
        saved
    );
    assert!(body_text(&f.get()).contains("value=\"daily\" selected"));
    assert_eq!(f.post(&body, false).response.status_code, 409);
    let current = f.fields();
    for (field, value, status) in [
        ("digest", "daily-email", 400),
        ("expected_revision", "01", 400),
        ("csrf_token", "invalid", 403),
    ] {
        let mut bad = current.clone();
        bad.insert(field.into(), value.into());
        assert_eq!(
            f.post(&Fixture::encoded(&bad), false).response.status_code,
            status
        );
        assert_eq!(f.store.load("alice@example.com").unwrap(), saved);
    }
    assert_eq!(
        f.post(
            &format!("{}&account=bob%40example.com", Fixture::encoded(&current)),
            false
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        f.post(
            &format!("{}&digest=individual", Fixture::encoded(&current)),
            false
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        f.post(&Fixture::encoded(&current), true)
            .response
            .status_code,
        403
    );
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        Preference::default()
    );
    assert_eq!(f.store.load("alice@example.com").unwrap(), saved);
    assert_eq!(
        crate::autosave::Store::new(f.root.join("settings"))
            .load("alice@example.com")
            .unwrap(),
        before_other
    );
    let unauth = f.app.handle_request(
        &request("POST", "/settings/notifications", &[], &body),
        "127.0.0.1",
    );
    assert_eq!(unauth.response.status_code, 303);
    assert_eq!(f.store.load("alice@example.com").unwrap(), saved);
}

#[test]
fn notification_preference_runtime_effect_does_not_suppress_security_and_corruption_preserves_inbox_badge(
) {
    let root = temp_dir(&format!(
        "notification-preference-runtime-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    assert_eq!(
        gateway.load_notification_preference(&session).unwrap(),
        Preference::default()
    );
    gateway
        .save_notification_preference(&session, 0, DigestMode::Daily)
        .unwrap();
    gateway
        .record_session_notification(
            "alice@example.com",
            crate::notifications::NotificationKind::SessionIssued,
        )
        .unwrap();
    gateway
        .record_session_notification(
            "alice@example.com",
            crate::notifications::NotificationKind::SessionRevoked,
        )
        .unwrap();
    let inbox = gateway.notification_inbox(&session).unwrap();
    assert_eq!(inbox.events.len(), 2);
    let restart = RuntimeBrowserGateway::for_test(&root);
    assert_eq!(
        restart
            .load_notification_preference(&session)
            .unwrap()
            .digest,
        DigestMode::Daily
    );
    let html = crate::http_ui::render_notification_inbox(
        "alice@example.com",
        "csrf",
        Some(&inbox),
        Some(&restart.load_notification_preference(&session).unwrap()),
        None,
    );
    assert_eq!(
        html.as_str()
            .matches("action=\"/notifications/read\"")
            .count(),
        2
    );
    assert!(html.as_str().contains("data-digest=\"daily\""));
    let path = fs::read_dir(root.join("settings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| fs::read_to_string(path).is_ok_and(|value| value.contains("\"digest\"")))
        .unwrap();
    fs::write(&path, b"{broken").unwrap();
    assert!(restart.load_notification_preference(&session).is_err());
    restart
        .record_session_notification(
            "alice@example.com",
            crate::notifications::NotificationKind::SessionIssued,
        )
        .unwrap();
    restart
        .record_session_notification(
            "alice@example.com",
            crate::notifications::NotificationKind::SessionRevoked,
        )
        .unwrap();
    assert_eq!(
        restart.notification_inbox(&session).unwrap().events.len(),
        4
    );
    assert_eq!(fs::read(&path).unwrap(), b"{broken");
    let notices = restart.notification_inbox(&session).unwrap();
    assert_eq!(
        super::super::notification_badge::unread(Some(&notices)),
        Some(4)
    );
    fs::remove_dir_all(root).unwrap();
}
