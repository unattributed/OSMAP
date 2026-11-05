use super::*;
use crate::notification_preferences::{Choice, DigestMode, Store};
use crate::notifications::{NotificationKind, NotificationStore};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
struct Fixture {
    root: PathBuf,
    notices: NotificationStore,
    preferences: Store,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "notification-updates-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let notices = NotificationStore::new(root.join("settings"));
        let preferences = Store::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                notification_store: Some(notices.clone()),
                notification_preference_store: Some(preferences.clone()),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self {
            root,
            notices,
            preferences,
            app,
        }
    }
    fn updates(&self, bob: bool) -> HandledHttpResponse {
        let mut req = request(
            "GET",
            "/notifications/updates",
            &authenticated_same_origin_headers(),
            "",
        );
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn post(&self, body: &str) -> HandledHttpResponse {
        self.app.handle_request(
            &request(
                "POST",
                "/settings/notifications",
                &authenticated_same_origin_headers(),
                body,
            ),
            "127.0.0.1",
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn now() -> u64 {
    crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
}
fn json(response: &HandledHttpResponse) -> serde_json::Value {
    serde_json::from_slice(&response.response.body).unwrap()
}
fn no_store(response: &HandledHttpResponse) {
    assert!(response
        .response
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("cache-control") && value == "no-store"));
    assert!(response.response.headers.iter().any(|(name, value)| name
        .eq_ignore_ascii_case("x-content-type-options")
        && value == "nosniff"));
}
fn all_off() -> Choice {
    Choice {
        new_mail: false,
        mentions: false,
        openpgp: false,
        submission: false,
        sound: false,
        desktop: false,
    }
}

#[test]
fn notification_updates_owned_generic_all_read_states_and_optional_filter_keep_security() {
    let f = Fixture::new();
    let at = now();
    for (kind, source) in [
        (NotificationKind::PasswordChanged, "password:3"),
        (NotificationKind::PersonalKeyUnlocked, "grant:one"),
        (NotificationKind::NewMail, "native:one"),
        (NotificationKind::SubmissionAccepted, "intent:one"),
    ] {
        f.notices.record_once(ALICE, kind, source, at, at).unwrap();
    }
    f.notices
        .record_once(BOB, NotificationKind::RecoveryCompleted, "case:bob", at, at)
        .unwrap();
    let inbox = f.notices.load(ALICE, now()).unwrap();
    let read = f
        .notices
        .set_read(
            ALICE,
            &inbox.events[0].event_id,
            inbox.revision,
            true,
            now(),
        )
        .unwrap();
    let response = f.updates(false);
    assert_eq!(response.response.status_code, 200);
    no_store(&response);
    let payload = json(&response);
    let object = payload.as_object().unwrap();
    assert_eq!(
        object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "version",
            "scope",
            "preference_revision",
            "choices",
            "events",
            "sources_available",
            "status"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(payload["version"], 1);
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["sources_available"], true);
    assert_eq!(payload["scope"].as_str().unwrap().len(), 64);
    let events = payload["events"].as_array().unwrap();
    assert_eq!(events.len(), 4);
    for event in events {
        assert_eq!(
            event
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["event_id", "kind", "occurred_at", "read"]
                .into_iter()
                .collect()
        );
        let saved = read
            .events
            .iter()
            .find(|saved| saved.event_id == event["event_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(event["read"], saved.read);
        assert_eq!(event["occurred_at"], saved.occurred_at);
    }
    assert_eq!(
        events.iter().filter(|event| event["read"] == true).count(),
        1
    );
    let text = body_text(&response);
    assert!(!text.contains(ALICE) && !text.contains("password:3") && !text.contains("native:one"));
    f.preferences
        .save_choices(ALICE, 0, DigestMode::Daily, all_off())
        .unwrap();
    let filtered = json(&f.updates(false));
    let visible = filtered["events"].as_array().unwrap();
    assert_eq!(visible.len(), 2);
    assert!(visible.iter().all(|event| matches!(
        event["kind"].as_str(),
        Some("password_changed" | "personal_key_unlocked")
    )));
    assert_eq!(f.notices.load(ALICE, now()).unwrap(), read);
    let bob = f.updates(true);
    assert_eq!(bob.response.status_code, 200);
    let bob = json(&bob);
    assert_ne!(bob["scope"], payload["scope"]);
    assert_eq!(bob["events"].as_array().unwrap().len(), 1);
    assert_eq!(bob["events"][0]["kind"], "recovery_completed");
    assert!(bob["events"].as_array().unwrap().iter().all(|event| !read
        .events
        .iter()
        .any(|saved| saved.event_id == event["event_id"].as_str().unwrap())));
    let offline_sources = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            notification_store: Some(f.notices.clone()),
            notification_preference_store: Some(f.preferences.clone()),
            notification_source_unavailable: true,
            ..StubGateway::default()
        },
    );
    let retained = offline_sources.handle_request(
        &request(
            "GET",
            "/notifications/updates",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(retained.response.status_code, 200);
    no_store(&retained);
    let retained = json(&retained);
    assert_eq!(retained["status"], "ok");
    assert_eq!(retained["sources_available"], false);
    assert_eq!(retained["events"], filtered["events"]);
    assert_eq!(retained["scope"], filtered["scope"]);
    assert_eq!(f.notices.load(ALICE, now()).unwrap(), read);
}

#[test]
fn notification_updates_requires_auth_origin_empty_query_body_and_available_sources() {
    let f = Fixture::new();
    let before = f.notices.load(ALICE, now()).unwrap();
    let unauthorized = f.app.handle_request(
        &request("GET", "/notifications/updates", &[], ""),
        "127.0.0.1",
    );
    assert_eq!(unauthorized.response.status_code, 401);
    no_store(&unauthorized);
    assert_eq!(json(&unauthorized)["status"], "unauthorized");
    let response = f.app.handle_request(
        &request(
            "GET",
            "/notifications/updates?account=bob%40example.com",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(response.response.status_code, 400);
    no_store(&response);
    assert_eq!(json(&response)["status"], "invalid");
    // The real parser rejects a GET body before BrowserApp dispatch; do not
    // use the infallible test-request helper to invent a reachable handler case.
    let body_request = b"GET /notifications/updates HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nunexpected";
    let Err(refusal) = parse_http_request_bytes(body_request, &HttpPolicy::default()) else {
        panic!("GET body reached dispatch")
    };
    assert_eq!(refusal.kind, HttpRequestErrorKind::Parse);
    assert_eq!(refusal.reason, "get requests must not send a request body");
    for origin in [None, Some("https://foreign.example"), Some("null")] {
        let mut req = request(
            "GET",
            "/notifications/updates",
            &authenticated_headers(),
            "",
        );
        if let Some(origin) = origin {
            req.headers.insert("origin".into(), origin.into());
        }
        assert_eq!(
            f.app.handle_request(&req, "127.0.0.1").response.status_code,
            403
        );
    }
    assert_eq!(f.notices.load(ALICE, now()).unwrap(), before);
    let unavailable = BrowserApp::new(HttpPolicy::default(), StubGateway::default())
        .handle_request(
            &request(
                "GET",
                "/notifications/updates",
                &authenticated_same_origin_headers(),
                "",
            ),
            "127.0.0.1",
        );
    assert_eq!(unavailable.response.status_code, 503);
    no_store(&unavailable);
    assert_eq!(json(&unavailable)["status"], "unavailable");
}

#[test]
fn notification_choice_version_all_off_legacy_digest_and_invalid_stale_duplicate_preserve_saved_choices(
) {
    let f = Fixture::new();
    let csrf = StubGateway::validated_session().record.csrf_token;
    let alloff = format!("csrf_token={csrf}&expected_revision=0&digest=daily&choice_version=1");
    assert_eq!(f.post(&alloff).response.status_code, 303);
    let saved = f.preferences.load(ALICE).unwrap();
    assert_eq!(saved.choices, all_off());
    assert_eq!(saved.revision, 1);
    assert_eq!(f.post(&alloff).response.status_code, 409);
    assert_eq!(f.preferences.load(ALICE).unwrap(), saved);
    let legacy = format!("csrf_token={csrf}&expected_revision=1&digest=individual");
    assert_eq!(f.post(&legacy).response.status_code, 303);
    let preserved = f.preferences.load(ALICE).unwrap();
    assert_eq!(preserved.choices, all_off());
    assert_eq!(preserved.digest, DigestMode::Individual);
    let current = format!("csrf_token={csrf}&expected_revision=2&digest=daily");
    for suffix in [
        "&choice_version=2",
        "&new_mail=1",
        "&choice_version=1&new_mail=0",
        "&choice_version=1&desktop=true",
        "&choice_version=1&new_mail=1&new_mail=1",
        "&choice_version=1&account=bob%40example.com",
    ] {
        assert_eq!(
            f.post(&format!("{current}{suffix}")).response.status_code,
            400
        );
        assert_eq!(f.preferences.load(ALICE).unwrap(), preserved);
    }
    let on = format!(
        "{current}&choice_version=1&new_mail=1&mentions=1&openpgp=1&submission=1&sound=1&desktop=1"
    );
    assert_eq!(
        f.post(&on.replace(&csrf, "bad-csrf")).response.status_code,
        403
    );
    assert_eq!(f.preferences.load(ALICE).unwrap(), preserved);
    assert_eq!(f.post(&on).response.status_code, 303);
    let enabled = f.preferences.load(ALICE).unwrap();
    assert!(
        enabled.choices.desktop
            && enabled.choices.sound
            && enabled.choices.new_mail
            && enabled.choices.mentions
            && enabled.choices.openpgp
            && enabled.choices.submission
    );
    assert_eq!(
        f.preferences.load(BOB).unwrap(),
        crate::notification_preferences::Preference::default()
    );
}
