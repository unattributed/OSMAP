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

#[test]
fn authenticator_navigation_reports_account_metadata_and_real_lifecycle_entry_from_both_settings() {
    let scratch = Scratch::new();
    let app = scratch.app();
    for path in [
        "/settings/authenticator",
        "/settings?section=security",
        "/settings?section=authentication",
    ] {
        let result = app.handle_request(
            &request("GET", path, &authenticated_same_origin_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(result.response.status_code, 200, "{path}");
        let html = body_text(&result);
        assert!(html.contains("Enrolled"), "{path}");
        assert!(html.contains("2023-11-14T22:13:00Z"), "{path}");
        assert!(html.contains("2023-11-14T22:13:29Z"), "{path}");
        assert!(
            html.contains("exact verification time is not recorded"),
            "{path}"
        );
        assert!(html.contains("/settings/authenticator"), "{path}");
        assert!(!html.contains("Last use: just now"));
    }
    assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
    assert!(scratch.store().read_request(ACCOUNT).unwrap().is_none());
    let result = app.handle_request(
        &request(
            "GET",
            "/settings/authenticator",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    let html = body_text(&result);
    for text in [
        "independently verify identity",
        "does not prove identity or bypass MFA",
        "private terminal",
        "preserves your current password",
    ] {
        assert!(html.contains(text), "{text}");
    }
    for secret_field in [
        "name=\"password\"",
        "name=\"current_password\"",
        "name=\"totp_code\"",
        "name=\"token\"",
        "name=\"identity_method\"",
        "name=\"account\"",
    ] {
        assert!(!html.contains(secret_field));
    }
}

#[test]
fn authenticator_post_persists_only_an_untrusted_own_account_request_and_repeated_request_is_idempotent(
) {
    let scratch = Scratch::new();
    let app = scratch.app();
    let result = app.handle_request(&post(&form(0)), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    let first = scratch.store().read_request(ACCOUNT).unwrap().unwrap();
    assert_eq!(first.account, ACCOUNT);
    assert_eq!(first.state, "requested");
    assert!(first.account_epoch.is_none());
    assert!(first.account_state.is_none());
    assert!(scratch.store().read_case(ACCOUNT).unwrap().is_none());
    assert!(scratch
        .store()
        .read_request("bob@example.com")
        .unwrap()
        .is_none());
    assert!(body_text(&result).contains("supplies no recovery authorization"));
    let retry = app.handle_request(&post(&form(1)), "127.0.0.1");
    assert_eq!(retry.response.status_code, 200);
    assert_eq!(
        scratch.store().read_request(ACCOUNT).unwrap(),
        Some(first.clone())
    );
    let stale = app.handle_request(&post(&form(0)), "127.0.0.1");
    assert_eq!(stale.response.status_code, 409);
    assert_eq!(scratch.store().read_request(ACCOUNT).unwrap(), Some(first));
    assert_eq!(
        *app.gateway.authenticator_calls.lock().unwrap(),
        [
            (ACCOUNT.into(), 0),
            (ACCOUNT.into(), 1),
            (ACCOUNT.into(), 0)
        ]
    );
    for event in result
        .audit_events
        .into_iter()
        .chain(retry.audit_events)
        .chain(stale.audit_events)
    {
        let debug = format!("{event:?}");
        assert!(!debug.contains(CSRF));
        assert!(!debug.contains("account_epoch=0"));
    }
}

#[test]
fn authenticator_route_refuses_csrf_origin_query_duplicate_and_extra_account_before_request_dispatch(
) {
    let scratch = Scratch::new();
    let app = scratch.app();
    let good = form(0);
    let mut foreign = post(&good);
    foreign
        .headers
        .insert("origin".into(), "https://foreign.example.test".into());
    let cases = [
        foreign,
        post(&good.replace(CSRF, "wrong")),
        post(&(good.clone() + "&account=bob%40example.com")),
        post(&(good.clone() + "&current_password=synthetic-secret-do-not-echo")),
        post(&(good.clone() + "&identity_method=in_person")),
        post(&(good.clone() + "&action=request")),
        post(&good.replace("revision=0", "revision=invalid")),
        post(&good.replace("action=request", "action=recover")),
        request(
            "GET",
            "/settings/authenticator?account=bob%40example.com",
            &authenticated_same_origin_headers(),
            "",
        ),
    ];
    for value in cases {
        let response = app.handle_request(&value, "127.0.0.1");
        assert_ne!(response.response.status_code, 200);
        assert!(!body_text(&response).contains("synthetic-secret-do-not-echo"));
        assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
    }
    assert!(scratch.store().read_request(ACCOUNT).unwrap().is_none());
    assert!(scratch.store().read_case(ACCOUNT).unwrap().is_none());
}

#[test]
fn authenticator_foreign_or_unavailable_snapshot_is_unknown_and_cannot_save_request() {
    let scratch = Scratch::new();
    for state in [None, Some(snapshot("bob@example.com"))] {
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                authenticator_snapshot: state,
                authenticator_store_root: Some(scratch.0.clone()),
                ..StubGateway::default()
            },
        );
        let result = app.handle_request(
            &request(
                "GET",
                "/settings/authenticator",
                &authenticated_same_origin_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(result.response.status_code, 503);
        let html = body_text(&result);
        assert!(html.contains("Unknown"));
        assert!(html.contains(" disabled"));
        assert!(!html.contains("2023-11-14T22:13:00Z"));
        let result = app.handle_request(&post(&form(0)), "127.0.0.1");
        assert_eq!(result.response.status_code, 503);
        assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
        for path in [
            "/settings?section=security",
            "/settings?section=authentication",
        ] {
            let result = app.handle_request(
                &request("GET", path, &authenticated_same_origin_headers(), ""),
                "127.0.0.1",
            );
            assert_eq!(result.response.status_code, 200);
            assert!(body_text(&result).contains("Unknown"));
            assert!(!body_text(&result).contains("2023-11-14T22:13:00Z"));
        }
    }
}

#[test]
fn authenticator_malformed_foreign_or_unavailable_private_records_fail_closed_through_real_store() {
    for kind in ["invalid-json", "foreign-record", "symlink", "permissive"] {
        let scratch = Scratch::new();
        let store = crate::private_account_file::PrivateAccountFile::new(
            scratch.0.join("cases"),
            crate::authenticator::NAMESPACE,
            4096,
        );
        let guard = store.lock(ACCOUNT).unwrap();
        let mut record = crate::authenticator::RequestRecord {
            account: ACCOUNT.into(),
            case_id: "synthetic-case".into(),
            state: "contained".into(),
            revision: 1,
            requested_at: 100,
            updated_at: 100,
            account_state: Some("contained".into()),
            account_epoch: Some(3),
        };
        if kind == "foreign-record" {
            record.account = "bob@example.com".into();
        }
        guard
            .write(
                if kind == "invalid-json" {
                    b"not-json".to_vec()
                } else {
                    serde_json::to_vec(&record).unwrap()
                }
                .as_slice(),
            )
            .unwrap();
        drop(guard);
        let path = fs::read_dir(scratch.0.join("cases"))
            .unwrap()
            .map(|v| v.unwrap().path())
            .find(|p| p.extension().is_some_and(|v| v == "json"))
            .unwrap();
        if kind == "permissive" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        if kind == "symlink" {
            let real = scratch.0.join("untrusted-record");
            fs::rename(&path, &real).unwrap();
            std::os::unix::fs::symlink(&real, &path).unwrap();
        }
        let app = scratch.app();
        let result = app.handle_request(
            &request(
                "GET",
                "/settings/authenticator",
                &authenticated_same_origin_headers(),
                "",
            ),
            "127.0.0.1",
        );
        assert_eq!(result.response.status_code, 503, "{kind}");
        assert!(!body_text(&result).contains("synthetic-case"));
        let result = app.handle_request(&post(&form(0)), "127.0.0.1");
        assert_eq!(result.response.status_code, 503, "{kind}");
        assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
        assert!(scratch.store().read_request(ACCOUNT).unwrap().is_none());
    }
}

#[test]
fn authenticator_anonymous_navigation_never_reads_account_metadata_or_dispatches_request() {
    let scratch = Scratch::new();
    let app = scratch.app();
    for method in ["GET", "POST"] {
        let body = if method == "POST" {
            form(0)
        } else {
            String::new()
        };
        let mut value = request(method, "/settings/authenticator", &[], &body);
        value.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        let result = app.handle_request(&value, "127.0.0.1");
        assert_ne!(result.response.status_code, 200);
        assert!(!body_text(&result).contains("2023-11-14T22:13:00Z"));
    }
    assert!(app.gateway.authenticator_reads.lock().unwrap().is_empty());
    assert!(app.gateway.authenticator_calls.lock().unwrap().is_empty());
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
