use super::*;

#[test]
fn password_unicode_scalar_boundary_matches_html_utf16_cap_without_secret_reads() {
    let valid = "🦊".repeat(128);
    let invalid = "🦊".repeat(129);
    assert_eq!(valid.len(), 512);
    assert_eq!(valid.chars().count(), 128);
    assert_eq!(valid.encode_utf16().count(), 256);
    assert!(crate::password_change::Request::new(
        "Current-public-password", &valid, &valid, "123456"
    ).is_ok());
    assert!(matches!(crate::password_change::Request::new(
        "Current-public-password", &invalid, &invalid, "123456"
    ), Err(crate::password_change::Error::Invalid)));

    let app = password_app(BrowserPasswordDecision::KnownRefused);
    let page = app.handle_request(&request("GET", "/settings/password",
        &authenticated_same_origin_headers(), ""), "127.0.0.1");
    let html = body_text(&page);
    for name in ["new_password", "confirmation"] {
        assert!(html.contains(&format!("name=\"{name}\" type=\"password\" autocomplete=\"new-password\" maxlength=\"256\"")));
    }
    for (value, expected_status, calls) in [(&valid, 409, 1), (&invalid, 400, 1)] {
        let body = password_form().replace("New-public-password", &url_encode(value));
        let result = app.handle_request(&password_request(&body), "127.0.0.1");
        assert_eq!(result.response.status_code, expected_status);
        assert_eq!(app.gateway.password_calls.lock().unwrap().len(), calls);
        assert!(!body_text(&result).contains("🦊"));
    }
}

fn password_form() -> String {
    format!("csrf_token={}&current_password=Current-public-password&new_password=New-public-password&confirmation=New-public-password&totp_code=123456", url_encode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"))
}
fn password_request(body: &str) -> HttpRequest {
    let mut request = request("POST", "/settings/password", &authenticated_same_origin_headers(), body);
    request.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
    request
}
fn password_app(decision: BrowserPasswordDecision) -> BrowserApp<StubGateway> {
    BrowserApp::new(HttpPolicy::default(), StubGateway { password_result: Some(decision), ..StubGateway::default() })
}
fn assert_no_password_echo(response: &HandledHttpResponse) {
    let output = format!("{} {:?}", body_text(response), response.audit_events);
    for secret in ["Current-public-password", "New-public-password", "123456"] {
        assert!(!output.contains(secret), "secret echoed in response/audit");
    }
}

#[test]
fn password_route_unavailable_and_field_security_refuse_without_dispatch() {
    let unavailable = app();
    let get = unavailable.handle_request(&request("GET", "/settings/password", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(get.response.status_code, 503);
    assert!(body_text(&get).contains("<fieldset disabled>"));
    assert_eq!(unavailable.handle_request(&password_request(&password_form()), "127.0.0.1").response.status_code, 503);
    assert!(unavailable.gateway.password_calls.lock().unwrap().is_empty());

    let enabled = password_app(BrowserPasswordDecision::Changed);
    for body in [
        password_form().replace("fedcba9876543210", "wrong"),
        password_form().replace("confirmation=New-public-password", "confirmation=different"),
        format!("{}&account=bob%40example.com", password_form()),
        format!("{}&current_password=duplicate", password_form()),
    ] {
        let result = enabled.handle_request(&password_request(&body), "127.0.0.1");
        assert!(matches!(result.response.status_code, 400 | 403));
        assert_no_password_echo(&result);
    }
    let mut foreign = password_request(&password_form());
    foreign.headers.insert("origin".into(), "https://foreign.example".into());
    assert_eq!(enabled.handle_request(&foreign, "127.0.0.1").response.status_code, 403);
    let mut absent = password_request(&password_form());
    absent.headers.remove("cookie");
    assert_eq!(enabled.handle_request(&absent, "127.0.0.1").response.status_code, 303);
    assert!(enabled.gateway.password_calls.lock().unwrap().is_empty());
}

#[test]
fn password_route_result_classes_clear_cookie_only_for_changed_or_uncertain() {
    for (decision, status, clear, text) in [
        (BrowserPasswordDecision::Changed, 200, true, "password was changed"),
        (BrowserPasswordDecision::Unconfirmed, 503, true, "Do not repeat"),
        (BrowserPasswordDecision::KnownRefused, 409, false, "No password change was made"),
        (BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Authentication), 403, false, "No change was submitted"),
        (BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Throttled), 429, false, "temporarily limited"),
    ] {
        let app = password_app(decision);
        let result = app.handle_request(&password_request(&password_form()), "127.0.0.1");
        assert_eq!(result.response.status_code, status);
        assert!(body_text(&result).contains(text));
        assert_eq!(result.response.headers.iter().any(|(k,v)| k == "Set-Cookie" && v.contains("Max-Age=0")), clear);
        assert_eq!(app.gateway.password_calls.lock().unwrap().len(), 1);
        assert_no_password_echo(&result);
        if clear { assert!(!body_text(&result).contains("password-change-form")); }
    }
}

#[test]
fn password_page_uses_exact_script_csp_and_independent_empty_fields() {
    let app = password_app(BrowserPasswordDecision::Changed);
    let result = app.handle_request(&request("GET", "/settings/password", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    let html = body_text(&result);
    for name in ["current_password", "new_password", "confirmation"] {
        assert!(html.contains(&format!("id=\"{name}\" name=\"{name}\" type=\"password\"")));
        assert!(html.contains(&format!("aria-controls=\"{name}\"")));
    }
    assert!(html.contains("href=\"/settings?section=security\">Cancel"));
    let csp = result.response.headers.iter().find(|(k,_)| k == "Content-Security-Policy").unwrap().1.clone();
    assert!(csp.contains("script-src 'sha256-"));
    assert!(csp.contains("script-src-attr 'none'; connect-src 'none'"));
    assert!(!csp.contains("script-src 'self'") && !csp.contains("script-src 'unsafe-inline'"));
    let settings = app.handle_request(&request("GET", "/settings?section=security", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert!(body_text(&settings).contains("href=\"/settings/password\""));
    assert!(!body_text(&settings).contains("Password and recovery changes remain unavailable here."));
    // The source gate independently verifies the exact script bytes/hash and
    // rejects changed-hash network/secret-read/CSP broadening controls.
}

#[test]
fn password_runtime_trait_delegates_to_unqualified_owned_capability_without_state_creation() {
    use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
    let root = temp_dir("password-runtime-trait");
    let service = SessionService::new(FileSessionStore::new(root.join("sessions")), crate::totp::SystemTimeProvider, SystemRandomSource, 3600, 1800);
    let context = AuthenticationContext { request_id:"public-password".into(), remote_addr:"127.0.0.1".into(), user_agent:"public fixture".into() };
    let issued = service.issue(&context, "alice@example.test", RequiredSecondFactor::Totp).unwrap();
    let session = service.validate(&context, &issued.token).unwrap();
    let gateway = RuntimeBrowserGateway::for_test(&root);
    assert!(!BrowserGateway::password_change_available(&gateway, &session));
    let action = crate::password_change::Request::new("Current-public-password", "New-public-password", "New-public-password", "123456").unwrap();
    let result = BrowserGateway::change_own_password(&gateway, &context, &session, &issued.token, action, std::time::Instant::now()+std::time::Duration::from_secs(60));
    assert_eq!(result.decision, BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Unavailable));
    assert!(!root.join("settings/password-stepup-rate").exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// Genuine wire-entry fixture. Root owns the actual paired account services,
/// SQL/mail fixture, dropped process, bootstrap socketpair and HTTP consumer.
/// This module does not provision roles or fabricate authentication/sessions.
#[cfg(unix)]
mod genuine_http_pilot {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::net::TcpListener;
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        net::UnixStream,
    };
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const WEB_UID: u32 = 1001;
    const WEB_GID: u32 = 1003;
    const CONNECTIONS: usize = 10;
    const HOST: &str = "password-pilot.osmap.invalid";
    // Public RFC6238 fixture seed. The real file-backed verifier and replay
    // store consume it; the parent computes distinct accepted counter inputs.
    const SEED: &[u8] = b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bootstrap {
        version: u8,
        root: PathBuf,
    }
    fn bootstrap(raw: &[u8]) -> Result<Bootstrap, ()> {
        let value: Bootstrap = serde_json::from_slice(raw).map_err(|_| ())?;
        let runtime = value.root.parent().ok_or(())?;
        let name = runtime.file_name().and_then(|v| v.to_str()).ok_or(())?;
        if value.version != 1
            || runtime.parent() != Some(Path::new("/var/run"))
            || !name.strip_prefix("osmap-pxp-").is_some_and(|suffix| {
                suffix.len() == 16
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || value.root.as_os_str()
                != Path::new("/var/run")
                    .join(name)
                    .join("http-state")
                    .as_os_str()
        {
            return Err(());
        }
        Ok(value)
    }
    struct Control {
        stream: UnixStream,
        identity: (libc::dev_t, libc::ino_t, libc::mode_t),
    }
    impl Control {
        fn owned(stream: UnixStream) -> Result<Self, ()> {
            let identity = crate::openbsd::fixture_http_pilot_root_control_identity(&stream)
                .map_err(|_| ())?;
            Ok(Self { stream, identity })
        }
        fn current(&self) -> Result<(), ()> {
            if crate::openbsd::fixture_http_pilot_root_control_identity(&self.stream)
                .map_err(|_| ())?
                != self.identity
            {
                return Err(());
            }
            Ok(())
        }
        fn read(&mut self, cap: usize, deadline: Instant) -> Result<Vec<u8>, ()> {
            self.current()?;
            let bytes =
                crate::openpgp_inventory_runtime::read_frame(&mut self.stream, cap, deadline)
                    .map_err(|_| ())?;
            self.current()?;
            Ok(bytes)
        }
        fn write(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), ()> {
            self.current()?;
            crate::openpgp_inventory_runtime::write_frame(&mut self.stream, bytes, deadline)
                .map_err(|_| ())?;
            self.current()
        }
    }
    fn directory(path: &Path, owner: u32, mode: u32) -> Result<(), ()> {
        crate::openpgp_inventory_runtime::exact_path(path, WEB_UID).map_err(|_| ())?;
        let info = fs::symlink_metadata(path).map_err(|_| ())?;
        if !info.is_dir()
            || info.uid() != owner
            || info.gid() != WEB_GID
            || info.mode() & 0o7777 != mode
        {
            return Err(());
        }
        Ok(())
    }
    fn config_and_seed(root: &Path) -> Result<crate::config::AppConfig, ()> {
        let runtime = root.parent().ok_or(())?;
        directory(runtime, 0, 0o750)?;
        directory(root, 0, 0o750)?;
        directory(&runtime.join("admission"), 0, 0o750)?;
        directory(&root.join("keys"), 0, 0o750)?;
        directory(&root.join("secrets"), 0, 0o750)?;
        let mut config =
            crate::config::AppConfig::from_env_map(&std::collections::BTreeMap::from([
                ("OSMAP_RUN_MODE".into(), "serve".into()),
            ("OSMAP_ENV".into(), "staging".into()),
                ("OSMAP_STATE_DIR".into(), root.to_str().ok_or(())?.into()),
                ("OSMAP_ALLOWED_HOSTS".into(), HOST.into()),
                ("OSMAP_LISTEN_ADDR".into(), "127.0.0.1:0".into()),
                ("OSMAP_OPENBSD_CONFINEMENT_MODE".into(), "enforce".into()),
            ]))
            .map_err(|_| ())?;
        for path in [
            &config.state_layout.runtime_dir,
            &config.state_layout.session_dir,
            &config.state_layout.settings_dir,
            &config.state_layout.draft_dir,
            &config.state_layout.audit_dir,
            &config.state_layout.cache_dir,
            &config.state_layout.totp_secret_dir,
        ] {
            directory(path, WEB_UID, 0o700)?;
            // Root supplies fresh empty state. Real HTTP login must create the
            // sessions; this entry never installs a session or resets replay.
            if fs::read_dir(path).map_err(|_| ())?.next().is_some() {
                return Err(());
            }
        }
        config.account_runtime = Some(crate::config::AccountRuntimeConfig {
            admission_socket: runtime.join("admission/admission.sock"),
            admission_key_file: root.join("keys/admission.key"),
            admission_helper_uid: 0,
            mutation_socket: runtime.join("rust-mutation.sock"),
            mutation_key_file: root.join("keys/mutation.key"),
            session_proof_key_file: root.join("keys/session-proof.key"),
            mutation_helper_uid: 0,
        });
        let store = crate::totp::FileTotpSecretStore::new(&config.state_layout.totp_secret_dir);
        for account in ["alice@osmap-proxy.invalid", "bob@osmap-proxy.invalid"] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(store.secret_path_for_username(account))
                .map_err(|_| ())?;
            file.write_all(SEED).map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
        }
        Ok(config)
    }

    #[test]
    fn http_pilot_bootstrap_refuses_role_keys_paths_and_duplicate_fields() {
        assert!(bootstrap(
            br#"{"version":1,"root":"/var/run/osmap-pxp-0123456789abcdef/http-state"}"#
        )
        .is_ok());
        for raw in [
            br#"{"version":true,"root":"/var/run/osmap-pxp-0123456789abcdef/http-state"}"#.as_slice(),
            br#"{"version":1,"root":"/var/run/osmap-pxp-0123456789abcdef/http-state","uid":1001}"#,
            br#"{"version":1,"root":"/var/run/osmap-pxp-0123456789abcdef/http-state","request_key":[1]}"#,
            br#"{"version":1,"root":"/var/run/osmap-pxp-0123456789abcdef/http-state","root":"/tmp/elsewhere"}"#,
            br#"{"version":1,"root":"/var/run/osmap-pxp-0123456789ABCDEF/http-state"}"#,
            br#"{"version":1,"root":"/var/run/osmap-pxp-0123456789abcdef/rust-issuer"}"#,
            br#"{"version":1,"root":"/var/run/./osmap-pxp-0123456789abcdef/http-state"}"#,
        ] { assert!(bootstrap(raw).is_err()); }
    }

    /// Root starts this already irreversibly nonroot. Role records/topology,
    /// paired real account services and the complete HTTP consumer must pass
    /// separate frozen review; this entry cannot declare their outcomes.
    #[test]
    #[ignore = "root-reviewed genuine HTTP/password fixture only; no installed activation"]
    fn native_http_password_runtime_entrypoint() {
        assert_eq!(std::env::consts::OS, "openbsd");
        const {
            assert!(!crate::account_admission_runtime::NATIVE_CONFINEMENT_QUALIFIED);
            assert!(!crate::account_mutation_client::NATIVE_CONFINEMENT_QUALIFIED);
        }
        crate::openbsd::disable_core_dumps().expect("HTTP fixture core limit refused");
        let fd = std::env::var("OSMAP_TEST_HTTP_PILOT_FD")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .filter(|v| (3..=1024).contains(v))
            .expect("HTTP fixture descriptor required");
        let mut control = Control::owned(
            crate::openbsd::fixture_owned_http_pilot_control(fd)
                .expect("HTTP fixture descriptor refused"),
        )
        .expect("HTTP fixture fixed role/root peer refused");
        let setup = Instant::now() + Duration::from_secs(20);
        let boot = bootstrap(
            &control
                .read(2048, setup)
                .expect("HTTP fixture bootstrap refused"),
        )
        .expect("HTTP fixture namespace refused");
        let config = config_and_seed(&boot.root).expect("HTTP fixture state refused");
        let account = config
            .account_runtime
            .as_ref()
            .expect("HTTP fixture account config required");
        let admission = crate::account_admission_runtime::Client::paired_fixture_files(
            &account.admission_socket,
            &account.admission_key_file,
            0,
        )
        .expect("HTTP fixture admission custody refused");
        // Same Arc custody is finalized by the actual paired Serve seal below.
        let epoch_probe = admission.clone();
        let mutation = crate::account_mutation_client::Client::stored_fixture_files(
            &account.mutation_socket,
            &account.mutation_key_file,
            &account.session_proof_key_file,
            0,
        )
        .expect("HTTP fixture mutation custody refused");
        let mut gateway = RuntimeBrowserGateway::from_config(&config)
            .with_account_fixture_clients(admission, mutation);
        assert!(gateway.account_runtime.confinement_clients().is_some());
        let listener =
            TcpListener::bind(&config.listen_addr).expect("HTTP fixture listener refused");
        listener
            .set_nonblocking(true)
            .expect("HTTP fixture listener mode refused");
        let port = listener
            .local_addr()
            .expect("HTTP fixture listener identity refused")
            .port();
        let logger = crate::logging::Logger::new(
            crate::config::LogFormat::Text,
            crate::config::LogLevel::Error,
        );
        let seal = crate::openbsd::apply_runtime_confinement_for_accounts(
            &config,
            &logger,
            gateway.account_runtime.confinement_clients(),
        )
        .expect("HTTP fixture actual Serve confinement refused");
        assert!(seal.is_some());
        gateway.account_runtime = gateway
            .account_runtime
            .clone()
            .after_confinement(seal.as_ref());
        assert!(gateway.account_runtime.confinement_clients().is_some());
        let app = BrowserApp::new(HttpPolicy::from_config(&config), gateway);
        use crate::totp::TimeProvider;
        let ready = serde_json::to_vec(&serde_json::json!({"schema":"osmap-http-password-ready-v1",
            "port":port,"connections":CONNECTIONS,"totp_counter":crate::totp::SystemTimeProvider.unix_timestamp()/30})).unwrap();
        control
            .write(&ready, setup)
            .expect("HTTP fixture ready refused");
        assert_eq!(
            control.read(1, setup).ok().as_deref(),
            Some(b"G".as_slice()),
            "HTTP fixture start refused"
        );
        // Each genuine password POST retains the production route's original
        //60s deadline. This90s outer sequence ceiling never renews that budget.
        let began = Instant::now();
        let deadline = began + Duration::from_secs(90);
        let mut handled = 0;
        while handled < CONNECTIONS {
            assert!(
                Instant::now() < deadline,
                "HTTP fixture original outer deadline expired"
            );
            match listener.accept() {
                Ok((mut stream, _)) => {
                    super::super::super::http_runtime::handle_client_stream(
                        &app,
                        &logger,
                        &mut stream,
                    );
                    handled += 1;
                    assert!(
                        Instant::now() < deadline,
                        "HTTP fixture late response refused"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => panic!("HTTP fixture accept refused"),
            }
        }
        // Local cookie revocation must not substitute for a direct stale-epoch
        // negative against the same actual sealed account service. These use
        // the existing sequence deadline and add no HTTP request or actor.
        assert!(matches!(
            epoch_probe.admit_before("alice@osmap-proxy.invalid", 0, deadline),
            Err(crate::account_admission::Error::Refused)
        ));
        epoch_probe
            .admit_before("alice@osmap-proxy.invalid", 1, deadline)
            .expect("HTTP fixture current Alice epoch refused");
        epoch_probe
            .admit_before("bob@osmap-proxy.invalid", 0, deadline)
            .expect("HTTP fixture preserved Bob epoch refused");
        // The authenticated client verifier binds every active epoch to the
        // exact requested epoch before admit_before can return Ok(()).
        let report = serde_json::to_vec(
            &serde_json::json!({"schema":"osmap-http-password-runtime-v1",
            "handled_connections":handled,"elapsed_millis":began.elapsed().as_millis(),
            "alice_epoch0_refused":true,"alice_epoch1_admitted":1,"bob_epoch0_admitted":0}),
        )
        .unwrap();
        control
            .write(&report, deadline)
            .expect("HTTP fixture report refused");
        // Counts attest bounded handling only. Root independently verifies real
        // login/form/CSRF/mutation/revocation/old-new auth/Bob continuity.
    }
}
