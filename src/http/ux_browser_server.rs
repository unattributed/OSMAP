// Opt-in test-only browser server. No runtime gateway, mail host, subprocess
// helper, real credential, message source or operator profile is reachable.
use super::*;
use std::time::Instant;

#[test]
#[ignore = "explicit bounded loopback browser fixture, launched by maint/ux/browser_workflows.py"]
fn ux_synthetic_browser_server() {
    let root = PathBuf::from(std::env::var_os("OSMAP_UX_BROWSER_STATE").expect("explicit fixture root"));
    assert!(root.is_absolute());
    // Manual review opts into a longer-lived disposable fixture. Normal browser
    // verification keeps its existing three-minute / 200-connection bounds.
    let preview_minutes = std::env::var("OSMAP_UX_PREVIEW_MINUTES").ok().map(|value| {
        let minutes = value.parse::<u64>().expect("preview duration is an integer");
        assert!((1..=1440).contains(&minutes));
        minutes
    });
    let duration_seconds = preview_minutes.map(|minutes| minutes * 60).unwrap_or(180);
    let max_connections = if preview_minutes.is_some() { 20000 } else { 200 };
    fs::create_dir_all(&root).expect("fixture root");
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture root");
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let address = listener.local_addr().expect("loopback address");
    let policy = HttpPolicy {
        allowed_hosts: vec![address.to_string()],
        secure_session_cookie: false,
        read_timeout_secs: 1,
        write_timeout_secs: 1,
        ..HttpPolicy::default()
    };
    let gateway = StubGateway {
        signature_store: Some(crate::signature::SignatureStore::new(root.join("settings"))),
        labels_store: Some(crate::labels::LabelStore::new(root.join("settings/labels-v1"))),
        recovery_root: root.join("send-recovery"),
        contacts_store: Some(crate::contacts::ContactStore::new(root.join("settings/contacts-v1"))),
        draft_store: Some(crate::draft::FileDraftStore::new(root.join("drafts"), DraftPolicy::default())),
        appearance_store: Some(AppearanceStore::new(root.join("settings"))),
        settings_store: Some(crate::settings::FileUserSettingsStore::new(root.join("settings"))),
        snooze_store: Some(crate::snooze::SnoozeStore::new(root.join("settings"))),
        notification_store: Some(crate::notifications::NotificationStore::new(root.join("settings"))),
        identity_preferences_store: Some(crate::identity_preferences::IdentityPreferencesStore::new(root.join("settings"))),
        composition_preferences_store: Some(crate::composition_preferences::CompositionPreferencesStore::new(root.join("settings"))),
        reading_preferences_store: Some(crate::reading_preferences::ReadingPreferencesStore::new(root.join("settings"))),
        browser_fixture_accounts: true,
        fixture_sessions: Some(fixture_sessions::FixtureSessions::new(root.join("sessions"))),
        ..StubGateway::default()
    };
    let app = BrowserApp::new(policy, gateway);
    let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Error);
    fs::write(root.join("ready.json"), serde_json::to_vec(&serde_json::json!({
        "origin": format!("http://{address}"), "synthetic": true, "deadline_seconds": duration_seconds,
    })).expect("fixture metadata")).expect("write ready marker");
    let deadline = Instant::now() + Duration::from_secs(duration_seconds);
    let mut connections = 0;
    while Instant::now() < deadline && connections < max_connections && !root.join("stop").exists() {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                assert!(peer.ip().is_loopback());
                super::super::http_runtime::handle_client_stream(&app, &logger, &mut stream);
                connections += 1;
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
            Err(error) => panic!("fixture listener failed: {error}"),
        }
    }
}
