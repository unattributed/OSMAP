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
