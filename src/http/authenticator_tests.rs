use super::*;
use std::os::unix::fs::PermissionsExt;

const ACCOUNT: &str = "alice@example.com";
const CSRF: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-authenticator-http-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn store(&self) -> crate::authenticator::Store {
        crate::authenticator::Store::new(&self.0)
    }
    fn app(&self) -> BrowserApp<StubGateway> {
        BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                authenticator_snapshot: Some(snapshot(ACCOUNT)),
                authenticator_store_root: Some(self.0.clone()),
                ..StubGateway::default()
            },
        )
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn snapshot(account: &str) -> crate::authenticator::Snapshot {
    crate::authenticator::Snapshot {
        account: account.into(),
        enrolled: true,
        last_accepted_counter: Some(56_666_666),
        request: None,
        case: None,
    }
}
fn post(body: &str) -> HttpRequest {
    let mut value = request(
        "POST",
        "/settings/authenticator",
        &authenticated_same_origin_headers(),
        body,
    );
    value.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    value
}
fn form(revision: u64) -> String {
    format!("csrf_token={CSRF}&revision={revision}&action=request")
}

// The request-only operator UI was retired by the Oct30 browser recovery scope.
// Keep native metadata/store delegation below; current route contracts are tested
// in access_recovery_tests, including fresh reauthentication and grant isolation.
#[test]
fn retired_operator_request_action_never_dispatches_or_writes_request() {
    let scratch = Scratch::new();
    let app = scratch.app();
    let mut value = post(&form(0));
    value.headers.insert(
        "cookie".into(),
        format!(
            "osmap_session={}; __Host-osmap_recovery_csrf={CSRF}",
            "a".repeat(64)
        ),
    );
    let result = app.handle_request(&value, "127.0.0.1");
    assert_eq!(result.response.status_code, 400);
    assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
    assert!(app.gateway.access_calls.lock().unwrap().is_empty());
    assert!(scratch.store().read_request(ACCOUNT).unwrap().is_none());
}

#[test]
fn authenticator_metadata_in_both_settings_entries_remains_account_scoped() {
    let scratch = Scratch::new();
    let app = scratch.app();
    for path in [
        "/settings?section=security",
        "/settings?section=authentication",
    ] {
        let response = app.handle_request(
            &request("GET", path, &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 200);
        let html = body_text(&response);
        assert!(html.contains("Enrolled"));
        assert!(html.contains("/settings/authenticator"));
        assert!(html.contains("exact verification time is not recorded"));
        assert!(!html.contains("Last use: just now"));
    }
    assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
    assert!(scratch.store().read_request(ACCOUNT).unwrap().is_none());
}

#[test]
fn anonymous_authenticator_reset_never_reads_account_or_dispatches() {
    let scratch = Scratch::new();
    let app = scratch.app();
    let result = app.handle_request(
        &request("GET", "/settings/authenticator", &[], ""),
        "127.0.0.1",
    );
    assert_ne!(result.response.status_code, 200);
    assert!(app.gateway.authenticator_reads.lock().unwrap().is_empty());
    assert!(app.gateway.access_calls.lock().unwrap().is_empty());
}

#[test]
fn authenticator_runtime_gateway_delegates_to_actual_factor_replay_and_request_stores_without_fallback(
) {
    use std::os::unix::net::UnixListener;
    let scratch = Scratch::new();
    for name in ["totp", "cache", "cache/totp-replay"] {
        fs::create_dir_all(scratch.0.join(name)).unwrap();
        fs::set_permissions(scratch.0.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut listeners = Vec::new();
    for name in ["admission.sock", "mutation.sock"] {
        let listener = UnixListener::bind(scratch.0.join(name)).unwrap();
        fs::set_permissions(scratch.0.join(name), fs::Permissions::from_mode(0o660)).unwrap();
        listeners.push(listener);
    }
    for (name, byte) in [
        ("admission.key", 29u8),
        ("mutation.key", 31),
        ("proof.key", 37),
    ] {
        fs::write(scratch.0.join(name), [byte; 32]).unwrap();
        fs::set_permissions(scratch.0.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let uid = crate::openbsd::effective_uid();
    let admission = crate::account_admission_runtime::Client::paired_fixture_files(
        &scratch.0.join("admission.sock"),
        &scratch.0.join("admission.key"),
        uid,
    )
    .unwrap();
    let mutation = crate::account_mutation_client::Client::stored_fixture_files(
        &scratch.0.join("mutation.sock"),
        &scratch.0.join("mutation.key"),
        &scratch.0.join("proof.key"),
        uid,
    )
    .unwrap();
    let mut gateway = RuntimeBrowserGateway::for_test(&scratch.0)
        .with_account_fixture_clients(admission, mutation);
    let secrets = crate::totp::FileTotpSecretStore::new(scratch.0.join("totp"));
    let factor_path = secrets.secret_path_for_username(ACCOUNT);
    // Public RFC6238 test vector only; no real account factor or credentials.
    fs::write(&factor_path, b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
    fs::set_permissions(&factor_path, fs::Permissions::from_mode(0o600)).unwrap();
    let counter_leaf = format!(
        "{}.counter",
        ACCOUNT
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let counter_path = scratch.0.join("cache/totp-replay").join(counter_leaf);
    fs::write(&counter_path, b"56666666\n").unwrap();
    fs::set_permissions(&counter_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut session = StubGateway::validated_session();
    session.record.account_epoch = Some(3);
    let result = BrowserGateway::authenticator(&gateway, &session).unwrap();
    assert!(result.enrolled);
    assert_eq!(result.last_accepted_counter, Some(56_666_666));
    assert_eq!(result.account, ACCOUNT);
    assert!(result.request.is_none());
    let first = BrowserGateway::request_account_recovery(&gateway, &session, 0).unwrap();
    let store = crate::authenticator::Store::new(scratch.0.join("settings/account-recovery"));
    assert_eq!(store.read_request(ACCOUNT).unwrap(), Some(first.clone()));
    assert!(store.read_case(ACCOUNT).unwrap().is_none());
    assert_eq!(
        BrowserGateway::authenticator(&gateway, &session)
            .unwrap()
            .request,
        Some(first)
    );
    gateway.account_rollout = Some("bob@example.com".into());
    assert_eq!(
        BrowserGateway::authenticator(&gateway, &session),
        Err(crate::authenticator::Error::Unavailable)
    );
    assert_eq!(
        BrowserGateway::request_account_recovery(&gateway, &session, 1),
        Err(crate::authenticator::Error::Unavailable)
    );
    let disabled = RuntimeBrowserGateway::for_test(&scratch.0);
    assert_eq!(
        BrowserGateway::authenticator(&disabled, &session),
        Err(crate::authenticator::Error::Unavailable)
    );
    assert_eq!(
        BrowserGateway::request_account_recovery(&disabled, &session, 1),
        Err(crate::authenticator::Error::Unavailable)
    );
    assert!(store.read_request("bob@example.com").unwrap().is_none());
    assert_eq!(
        fs::read(factor_path).unwrap(),
        b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n"
    );
    assert_eq!(fs::read(counter_path).unwrap(), b"56666666\n");
    drop(listeners);
}
