// Generated native forms through real Runtime persistence and event/read projection.
// Synthetic issued sessions are not password/TOTP login or human browser proof.
use super::*;
use crate::notification_preferences::{DigestMode, Store};
use crate::notifications::{NotificationInbox, NotificationKind, NotificationStore};
use crate::session::{FileSessionStore, IssuedSession, SessionService};
use crate::totp::{SystemTimeProvider, TimeProvider};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn app(root: &std::path::Path) -> BrowserApp<RuntimeBrowserGateway> {
    BrowserApp::new(
        HttpPolicy::default(),
        RuntimeBrowserGateway::for_test(root)
            .with_fixture_sendmail_path(root.join("owned-nonexistent-sendmail")),
    )
}
fn http(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    method: &str,
    path: &str,
    fields: &BTreeMap<String, String>,
) -> HandledHttpResponse {
    let cookie = session.map(|s| format!("osmap_session={}", s.token.as_str()));
    let mut headers = vec![
        ("User-Agent", "Firefox/Test"),
        ("Origin", "http://localhost"),
    ];
    if let Some(value) = &cookie {
        headers.push(("Cookie", value.as_str()));
    }
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    if method == "POST" {
        headers.push(("Content-Type", "application/x-www-form-urlencoded"));
    }
    app.handle_request(&request(method, path, &headers, &body), "127.0.0.1")
}
fn get(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    path: &str,
) -> HandledHttpResponse {
    http(app, Some(session), "GET", path, &BTreeMap::new())
}
fn attr(tag: &str, name: &str) -> String {
    tag.split_once(&format!("{name}=\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
        .into()
}
fn fields(form: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split('>').next().unwrap();
        assert!(result
            .insert(attr(tag, "name"), attr(tag, "value"))
            .is_none());
    }
    result
}
fn setting(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    revision: u64,
    mode: &str,
) -> BTreeMap<String, String> {
    let page = get(app, session, "/settings?section=notifications");
    assert_eq!(page.response.status_code, 200);
    let body = body_text(&page);
    let form = body
        .split_once("<form id=\"notification-preferences-form\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains("method=\"post\" action=\"/settings/notifications\""));
    assert!(form.contains("id=\"notice-digest\" name=\"digest\""));
    assert!(form.contains(&format!("value=\"{mode}\"")));
    let mut parsed = fields(form);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed["expected_revision"], revision.to_string());
    parsed.insert("digest".into(), mode.into());
    parsed
}
fn projection(html: &str, inbox: &NotificationInbox, mode: &str, days: usize) {
    assert!(html.contains(&format!("data-digest=\"{mode}\"")));
    assert_eq!(
        html.matches("class=\"notification-event\"").count(),
        inbox.events.len()
    );
    assert_eq!(
        html.matches("action=\"/notifications/read\"").count(),
        inbox.events.len()
    );
    assert_eq!(html.matches("class=\"notification-day\"").count(), days);
    let unread = inbox.events.iter().filter(|e| !e.read).count();
    assert!(html.contains(&format!("data-unread=\"{unread}\"")));
    for event in &inbox.events {
        assert_eq!(
            html.matches(&format!("name=\"event_id\" value=\"{}\"", event.event_id))
                .count(),
            1
        );
        assert!(html.contains(&format!(
            "datetime=\"{}\"",
            crate::logging::format_unix_timestamp_utc(event.occurred_at)
        )));
    }
}
fn json_bytes(root: &std::path::Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| {
            let bytes = fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect()
}
fn run_workflow() {
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-nd-{}-{}",
        std::process::id(),
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let scratch = Scratch(root);
    let root = &scratch.0;
    let settings = root.join("settings");
    let now = SystemTimeProvider.unix_timestamp();
    let midnight = (now / 86400 - 1) * 86400;
    let store = NotificationStore::new(&settings);
    store
        .record(ALICE, NotificationKind::SessionIssued, midnight - 1)
        .unwrap();
    store
        .record(ALICE, NotificationKind::SessionIssued, midnight)
        .unwrap();
    store
        .record(ALICE, NotificationKind::SessionRevoked, midnight + 1)
        .unwrap();
    store
        .record(BOB, NotificationKind::SessionRevoked, midnight)
        .unwrap();
    let original = store.load(ALICE, now).unwrap();
    let bob_inbox = store.load(BOB, now).unwrap();
    let preferences = Store::new(&settings);
    preferences.save(BOB, 0, DigestMode::Individual).unwrap();
    let other = crate::autosave::Store::new(&settings)
        .save(ALICE, 0, true, 60)
        .unwrap();
    let before = json_bytes(&settings);
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "digest-runtime",
        "127.0.0.1",
        "Firefox/Test",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(root.join("sessions")),
        SystemTimeProvider,
        crate::session::SystemRandomSource,
        3600,
        1800,
    );
    let alice = sessions
        .issue(&context, ALICE, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let runtime = app(root);
    let initial = get(&runtime, &alice, "/notifications");
    assert_eq!(initial.response.status_code, 200);
    projection(&body_text(&initial), &original, "individual", 0);
    assert_eq!(json_bytes(&settings), before);
    let daily = setting(&runtime, &alice, 0, "daily");
    assert_eq!(
        http(
            &runtime,
            Some(&alice),
            "POST",
            "/settings/notifications",
            &daily
        )
        .response
        .status_code,
        303
    );
    assert_eq!(preferences.load(ALICE).unwrap().digest, DigestMode::Daily);
    let saved = json_bytes(&settings);
    let added: Vec<_> = saved
        .keys()
        .filter(|p| !before.contains_key(*p))
        .cloned()
        .collect();
    assert_eq!(added.len(), 1);
    let preference_path = added[0].clone();
    for (path, bytes) in &before {
        assert_eq!(fs::read(path).unwrap(), *bytes);
    }
    let restarted = app(root);
    let daily_page = get(&restarted, &alice, "/notifications");
    let html = body_text(&daily_page);
    assert_eq!(daily_page.response.status_code, 200);
    projection(&html, &original, "daily", 2);
    for (day, count) in [(midnight / 86400, 2), (midnight / 86400 - 1, 1)] {
        let group = html
            .split_once(&format!("data-utc-day=\"{day}\""))
            .unwrap()
            .1
            .split_once("</section>")
            .unwrap()
            .0;
        assert!(group.contains(&format!("UTC · {count} notices · {count} unread")));
        assert_eq!(group.matches("class=\"notification-event\"").count(), count);
    }
    assert_eq!(store.load(ALICE, now).unwrap(), original);
    assert_eq!(json_bytes(&settings), saved);
    let read = fields(
        html.split_once("<form method=\"post\" action=\"/notifications/read\"")
            .unwrap()
            .1
            .split_once("</form>")
            .unwrap()
            .0,
    );
    assert_eq!(read.len(), 4);
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/notifications/read",
            &read
        )
        .response
        .status_code,
        303
    );
    let latest = store
        .load(ALICE, SystemTimeProvider.unix_timestamp())
        .unwrap();
    assert_eq!(latest.revision, original.revision + 1);
    for (old, new) in original.events.iter().zip(&latest.events) {
        assert_eq!(old.event_id, new.event_id);
        assert_eq!(old.kind, new.kind);
        assert_eq!(old.occurred_at, new.occurred_at);
        assert_eq!(new.read, new.event_id == read["event_id"]);
    }
    projection(
        &body_text(&get(&restarted, &alice, "/notifications")),
        &latest,
        "daily",
        2,
    );
    let after_read = json_bytes(&settings);
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/notifications/read",
            &read
        )
        .response
        .status_code,
        409
    );
    assert_eq!(json_bytes(&settings), after_read);
    assert_eq!(
        http(
            &restarted,
            Some(&bob),
            "POST",
            "/settings/notifications",
            &daily
        )
        .response
        .status_code,
        403
    );
    let mut invalid = setting(&restarted, &alice, 1, "individual");
    invalid.insert("digest".into(), "external-email".into());
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/notifications",
            &invalid
        )
        .response
        .status_code,
        400
    );
    invalid.insert("digest".into(), "individual".into());
    invalid.remove("csrf_token");
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/notifications",
            &invalid
        )
        .response
        .status_code,
        403
    );
    assert_eq!(
        http(&restarted, None, "POST", "/settings/notifications", &daily)
            .response
            .status_code,
        303
    );
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/notifications",
            &daily
        )
        .response
        .status_code,
        409
    );
    assert_eq!(json_bytes(&settings), after_read);
    let individual = setting(&restarted, &alice, 1, "individual");
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/notifications",
            &individual
        )
        .response
        .status_code,
        303
    );
    projection(
        &body_text(&get(&app(root), &alice, "/notifications")),
        &latest,
        "individual",
        0,
    );
    assert_eq!(
        store
            .load(ALICE, SystemTimeProvider.unix_timestamp())
            .unwrap(),
        latest
    );
    let known = fs::read(&preference_path).unwrap();
    fs::write(&preference_path, b"{broken").unwrap();
    fs::set_permissions(&preference_path, fs::Permissions::from_mode(0o600)).unwrap();
    let unavailable = get(&app(root), &alice, "/settings?section=notifications");
    assert_eq!(unavailable.response.status_code, 503);
    let body = body_text(&unavailable);
    assert!(body.contains("no saved value was reset"));
    assert!(!body.contains("id=\"notification-preferences-form\""));
    let fallback = get(&app(root), &alice, "/notifications");
    assert_eq!(fallback.response.status_code, 200);
    projection(&body_text(&fallback), &latest, "unavailable", 0);
    assert!(body_text(&fallback)
        .contains("Individual notices are shown without hiding or changing any event"));
    assert_eq!(
        http(
            &app(root),
            Some(&alice),
            "POST",
            "/settings/notifications",
            &individual
        )
        .response
        .status_code,
        503
    );
    assert_eq!(fs::read(&preference_path).unwrap(), b"{broken");
    assert_eq!(
        store
            .load(ALICE, SystemTimeProvider.unix_timestamp())
            .unwrap(),
        latest
    );
    fs::write(&preference_path, known).unwrap();
    assert_eq!(preferences.load(ALICE).unwrap().revision, 2);
    assert_eq!(
        store
            .load(BOB, SystemTimeProvider.unix_timestamp())
            .unwrap(),
        bob_inbox
    );
    assert_eq!(
        preferences.load(BOB).unwrap().digest,
        DigestMode::Individual
    );
    assert_eq!(
        crate::autosave::Store::new(&settings).load(ALICE).unwrap(),
        other
    );
    assert!(
        !root.join("drafts").exists()
            && !root.join("cache").exists()
            && !root.join("owned-nonexistent-sendmail").exists()
    );
    println!("native_digest_generated_runtime_default_and_persistence=PASS native_digest_actual_utc_grouping_all_original_rows=PASS native_digest_generated_read_cas_and_badge=PASS native_digest_individual_switch_history_unchanged=PASS native_digest_restart_stale_csrf_foreign_refusal=PASS native_digest_corrupt_honest_fallback_no_reset=PASS native_digest_bob_other_preferences_preserved=PASS native_digest_zero_transport_private_crypto_no_login_claim=PASS");
}
#[cfg(unix)]
#[test]
fn generated_notification_digest_runtime_utc_grouping_readstate_and_refusals() {
    run_workflow();
}
#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "Opt-in owned private Runtime scenario; no SMTP/mailbox/helper or private crypto"]
fn isolated_openbsd_generated_notification_digest_runtime_utc_grouping_readstate_and_refusals() {
    run_workflow();
}
