use super::*;

#[test]
fn password_unicode_scalar_boundary_matches_html_utf16_cap_without_secret_reads() {
    let valid = "🦊".repeat(128);
    let invalid = "🦊".repeat(129);
    assert_eq!(valid.len(), 512);
    assert_eq!(valid.chars().count(), 128);
    assert_eq!(valid.encode_utf16().count(), 256);
    assert!(crate::password_change::Request::new(
        "Current-public-password",
        &valid,
        &valid,
        "123456"
    )
    .is_ok());
    assert!(matches!(
        crate::password_change::Request::new(
            "Current-public-password",
            &invalid,
            &invalid,
            "123456"
        ),
        Err(crate::password_change::Error::Invalid)
    ));

    let app = password_app(BrowserPasswordDecision::KnownRefused);
    let page = app.handle_request(
        &request(
            "GET",
            "/settings/password",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    let html = body_text(&page);
    for name in ["new_password", "confirmation"] {
        assert!(html.contains(&format!(
            "name=\"{name}\" type=\"password\" autocomplete=\"new-password\" maxlength=\"256\""
        )));
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
    let mut request = request(
        "POST",
        "/settings/password",
        &authenticated_same_origin_headers(),
        body,
    );
    request.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    request
}
fn password_app(decision: BrowserPasswordDecision) -> BrowserApp<StubGateway> {
    BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            password_result: Some(decision),
            password_changed_at: (decision == BrowserPasswordDecision::Changed)
                .then(|| "20261004170001".into()),
            ..StubGateway::default()
        },
    )
}

#[test]
fn password_status_http_routes_keep_time_without_fabricating_completed_effects() {
    for (decision, stamp, code, complete) in [
        (
            BrowserPasswordDecision::Changed,
            Some("20261004170001"),
            200,
            true,
        ),
        (
            BrowserPasswordDecision::Unconfirmed,
            Some("20261004170001"),
            503,
            false,
        ),
        (BrowserPasswordDecision::Changed, None, 503, false),
        (
            BrowserPasswordDecision::Changed,
            Some("20260230010203"),
            503,
            false,
        ),
    ] {
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                password_result: Some(decision),
                password_changed_at: stamp.map(str::to_owned),
                ..StubGateway::default()
            },
        );
        let result = app.handle_request(&password_request(&password_form()), "127.0.0.1");
        assert_eq!(result.response.status_code, code);
        let html = body_text(&result);
        assert_eq!(html.contains("Your password was changed"), complete);
        assert_eq!(
            html.contains("2026-10-04 17:00:01 UTC"),
            stamp == Some("20261004170001")
        );
        assert_eq!(
            html.contains("Required containment remains incomplete"),
            stamp == Some("20261004170001") && !complete
        );
        assert!(result
            .response
            .headers
            .iter()
            .any(|(k, v)| k == "Set-Cookie" && v.contains("Max-Age=0")));
        assert_no_password_echo(&result);
        for section in ["security", "authentication"] {
            let settings = app.handle_request(
                &request(
                    "GET",
                    &format!("/settings?section={section}"),
                    &authenticated_same_origin_headers(),
                    "",
                ),
                "127.0.0.1",
            );
            let settings_html = body_text(&settings);
            assert_eq!(
                settings_html.contains("2026-10-04 17:00:01 UTC"),
                stamp == Some("20261004170001")
            );
            assert_eq!(
                settings_html.contains("Last change unknown"),
                stamp != Some("20261004170001")
            );
        }
    }
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
    let get = unavailable.handle_request(
        &request(
            "GET",
            "/settings/password",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(get.response.status_code, 503);
    assert!(body_text(&get).contains("<fieldset disabled>"));
    assert_eq!(
        unavailable
            .handle_request(&password_request(&password_form()), "127.0.0.1")
            .response
            .status_code,
        503
    );
    assert!(unavailable
        .gateway
        .password_calls
        .lock()
        .unwrap()
        .is_empty());

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
    foreign
        .headers
        .insert("origin".into(), "https://foreign.example".into());
    assert_eq!(
        enabled
            .handle_request(&foreign, "127.0.0.1")
            .response
            .status_code,
        403
    );
    let mut absent = password_request(&password_form());
    absent.headers.remove("cookie");
    assert_eq!(
        enabled
            .handle_request(&absent, "127.0.0.1")
            .response
            .status_code,
        303
    );
    assert!(enabled.gateway.password_calls.lock().unwrap().is_empty());
}

#[test]
fn password_route_result_classes_clear_cookie_only_for_changed_or_uncertain() {
    for (decision, status, clear, text) in [
        (
            BrowserPasswordDecision::Changed,
            200,
            true,
            "password was changed",
        ),
        (
            BrowserPasswordDecision::Unconfirmed,
            503,
            true,
            "Do not repeat",
        ),
        (
            BrowserPasswordDecision::KnownRefused,
            409,
            false,
            "No password change was made",
        ),
        (
            BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Authentication),
            403,
            false,
            "No change was submitted",
        ),
        (
            BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Throttled),
            429,
            false,
            "temporarily limited",
        ),
    ] {
        let app = password_app(decision);
        let result = app.handle_request(&password_request(&password_form()), "127.0.0.1");
        assert_eq!(result.response.status_code, status);
        assert!(body_text(&result).contains(text));
        assert_eq!(
            result
                .response
                .headers
                .iter()
                .any(|(k, v)| k == "Set-Cookie" && v.contains("Max-Age=0")),
            clear
        );
        assert_eq!(app.gateway.password_calls.lock().unwrap().len(), 1);
        assert_no_password_echo(&result);
        if clear {
            assert!(!body_text(&result).contains("password-change-form"));
        }
    }
}

#[test]
fn password_page_uses_exact_script_csp_and_independent_empty_fields() {
    let app = password_app(BrowserPasswordDecision::Changed);
    let result = app.handle_request(
        &request(
            "GET",
            "/settings/password",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 200);
    let html = body_text(&result);
    for name in ["current_password", "new_password", "confirmation"] {
        assert!(html.contains(&format!("id=\"{name}\" name=\"{name}\" type=\"password\"")));
        assert!(html.contains(&format!("aria-controls=\"{name}\"")));
    }
    assert!(html.contains("href=\"/settings?section=security\">Cancel"));
    let csp = result
        .response
        .headers
        .iter()
        .find(|(k, _)| k == "Content-Security-Policy")
        .unwrap()
        .1
        .clone();
    assert!(csp.contains("script-src 'sha256-"));
    assert!(csp.contains("script-src-attr 'none'; connect-src 'none'"));
    assert!(!csp.contains("script-src 'self'") && !csp.contains("script-src 'unsafe-inline'"));
    let settings = app.handle_request(
        &request(
            "GET",
            "/settings?section=security",
            &authenticated_same_origin_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert!(body_text(&settings).contains("href=\"/settings/password\""));
    assert!(
        !body_text(&settings).contains("Password and recovery changes remain unavailable here.")
    );
    // The source gate independently verifies the exact script bytes/hash and
    // rejects changed-hash network/secret-read/CSP broadening controls.
}

#[test]
fn password_runtime_trait_delegates_to_unqualified_owned_capability_without_state_creation() {
    use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
    let root = temp_dir("password-runtime-trait");
    let service = SessionService::new(
        FileSessionStore::new(root.join("sessions")),
        crate::totp::SystemTimeProvider,
        SystemRandomSource,
        3600,
        1800,
    );
    let context = AuthenticationContext {
        request_id: "public-password".into(),
        remote_addr: "127.0.0.1".into(),
        user_agent: "public fixture".into(),
    };
    let issued = service
        .issue(&context, "alice@example.test", RequiredSecondFactor::Totp)
        .unwrap();
    let session = service.validate(&context, &issued.token).unwrap();
    let gateway = RuntimeBrowserGateway::for_test(&root);
    assert!(!BrowserGateway::password_change_available(
        &gateway, &session
    ));
    let action = crate::password_change::Request::new(
        "Current-public-password",
        "New-public-password",
        "New-public-password",
        "123456",
    )
    .unwrap();
    let result = BrowserGateway::change_own_password(
        &gateway,
        &context,
        &session,
        &issued.token,
        action,
        std::time::Instant::now() + std::time::Duration::from_secs(60),
    );
    assert_eq!(
        result.decision,
        BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Unavailable)
    );
    assert!(!root.join("settings/password-stepup-rate").exists());
    std::fs::remove_dir_all(root).unwrap();
}

// Additional T02 source assertions only. StubGateway never proves an actual
// credential update; the revoked-session case uses the production file store.
fn assert_password_source_t02_refusal(response: &HandledHttpResponse) {
    assert_no_password_echo(response);
    let text = format!("{} {:?}", body_text(response), response.audit_events);
    for invented in [
        "Your password was changed",
        "password_changed_at",
        "credential_changed_at",
        "changed_at=",
    ] {
        assert!(
            !text.contains(invented),
            "refusal fabricated a changed-at/result claim"
        );
    }
}

#[test]
fn password_source_t02_exact_minimum_is_admitted_without_claiming_change() {
    let minimum = "a".repeat(15);
    assert!(crate::password_change::Request::new(
        "Current-public-password",
        &minimum,
        &minimum,
        "123456"
    )
    .is_ok());
    let app = password_app(BrowserPasswordDecision::KnownRefused);
    let body = password_form().replace("New-public-password", &minimum);
    let response = app.handle_request(&password_request(&body), "127.0.0.1");
    assert_eq!(response.response.status_code, 409);
    assert_eq!(
        *app.gateway.password_calls.lock().unwrap(),
        vec!["alice@example.com"]
    );
    assert!(body_text(&response).contains("No password change was made"));
    assert_password_source_t02_refusal(&response);
    let too_short = password_form().replace("New-public-password", &"a".repeat(14));
    let refused = app.handle_request(&password_request(&too_short), "127.0.0.1");
    assert_eq!(refused.response.status_code, 400);
    assert_eq!(app.gateway.password_calls.lock().unwrap().len(), 1);
    assert_password_source_t02_refusal(&refused);
}

#[test]
fn password_source_t02_missing_malformed_and_unbound_fields_do_not_dispatch() {
    let app = password_app(BrowserPasswordDecision::Changed);
    let valid = password_form();
    let malformed = [
        valid.replace("current_password=Current-public-password&", ""),
        valid.replace("confirmation=New-public-password&", ""),
        valid.replace("csrf_token=", "csrf_token=%GG"),
        valid.replace(
            "current_password=Current-public-password",
            "current_password=%ff",
        ),
        valid.replace(
            "current_password=Current-public-password",
            "account=bob%40example.com",
        ),
        format!("{valid}&%63urrent_password=duplicate"),
        valid.replace("New-public-password", "Current-public-password"),
    ];
    for body in malformed {
        let response = app.handle_request(&password_request(&body), "127.0.0.1");
        assert_eq!(response.response.status_code, 400);
        assert_password_source_t02_refusal(&response);
    }
    // The production outer parser rejects this body before a password route
    // request can exist; do not weaken its cap just to exercise inner parsing.
    let oversized = format!("{valid}&padding={}", "x".repeat(8192));
    let raw = format!("POST /settings/password HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{oversized}", oversized.len());
    let error = parse_http_request_bytes(raw.as_bytes(), &HttpPolicy::default()).unwrap_err();
    assert_eq!(error.reason, "http body exceeded maximum length");
    let mut wrong_type = password_request(&valid);
    wrong_type
        .headers
        .insert("content-type".into(), "application/json".into());
    let response = app.handle_request(&wrong_type, "127.0.0.1");
    assert_eq!(response.response.status_code, 400);
    assert_password_source_t02_refusal(&response);
    let mut query = password_request(&valid);
    query
        .query_params
        .insert("account".into(), "bob@example.com".into());
    let response = app.handle_request(&query, "127.0.0.1");
    assert_eq!(response.response.status_code, 400);
    assert_password_source_t02_refusal(&response);
    assert!(app.gateway.password_calls.lock().unwrap().is_empty());
}

#[test]
fn password_source_t02_revoked_real_file_session_refuses_without_record_rewrite() {
    use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
    let root = temp_dir("password-source-t02-revoked");
    let session_root = root.join("sessions");
    let service = SessionService::new(
        FileSessionStore::new(&session_root),
        crate::totp::SystemTimeProvider,
        SystemRandomSource,
        3600,
        1800,
    );
    let context = AuthenticationContext {
        request_id: "public-t02".into(),
        remote_addr: "127.0.0.1".into(),
        user_agent: "Firefox/Test".into(),
    };
    let alice = service
        .issue(&context, "alice@example.com", RequiredSecondFactor::Totp)
        .unwrap();
    let bob = service
        .issue(&context, "bob@example.com", RequiredSecondFactor::Totp)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            password_result: Some(BrowserPasswordDecision::Changed),
            fixture_sessions: Some(fixture_sessions::FixtureSessions::new(session_root.clone())),
            ..StubGateway::default()
        },
    );
    let cookie = format!("osmap_session={}", alice.token.as_str());
    let mut get = request(
        "GET",
        "/settings/password",
        &authenticated_same_origin_headers(),
        "",
    );
    get.headers.insert("cookie".into(), cookie.clone());
    assert_eq!(
        app.handle_request(&get, "127.0.0.1").response.status_code,
        200
    );
    assert!(
        service
            .revoke_by_token(&context, &alice.token)
            .unwrap()
            .newly_revoked
    );
    let store = FileSessionStore::new(&session_root);
    let alice_path = store.session_path(&alice.record.session_id);
    let bob_path = store.session_path(&bob.record.session_id);
    let before_alice = fs::read(&alice_path).unwrap();
    let before_bob = fs::read(&bob_path).unwrap();
    let body = password_form().replace(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        &url_encode(&alice.record.csrf_token),
    );
    let mut post = password_request(&body);
    post.headers.insert("cookie".into(), cookie);
    let response = app.handle_request(&post, "127.0.0.1");
    assert_eq!(response.response.status_code, 303);
    assert_password_source_t02_refusal(&response);
    assert!(app.gateway.password_calls.lock().unwrap().is_empty());
    assert!(
        fs::read(&alice_path).unwrap() == before_alice,
        "refused Alice record changed"
    );
    assert!(
        fs::read(&bob_path).unwrap() == before_bob,
        "unrelated Bob record changed"
    );
    assert!(service.validate(&context, &bob.token).is_ok());
    fs::remove_dir_all(root).unwrap();
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
    const WEB_GID: u32 = 1001;
    // Original ten workflow requests plus eight exact T07 history views.
    const CONNECTIONS: usize = 18;
    const HOST: &str = "password-pilot.osmap.invalid";
    // Public RFC6238 fixture seed. The real file-backed verifier and replay
    // store consume it; the parent computes distinct accepted counter inputs.
    const SEED: &[u8] = b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Topology {
        LegacyPrivate,
        PairedRelay,
        NativeLocal,
    }

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
            let identity =
                crate::openbsd::fixture_current_rust_http_pilot_root_control_identity(&stream)
                    .map_err(|_| ())?;
            Ok(Self { stream, identity })
        }
        fn current(&self) -> Result<(), ()> {
            if crate::openbsd::fixture_current_rust_http_pilot_root_control_identity(&self.stream)
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
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PairedRelayProfile {
        version: u8,
        authority: String,
        purpose: String,
        admission_helper_uid: u32,
        mutation_helper_uid: u32,
    }
    fn paired_relay_profile(raw: &[u8]) -> Result<PairedRelayProfile, ()> {
        let profile: PairedRelayProfile = serde_json::from_slice(raw).map_err(|_| ())?;
        if profile.version != 1
            || profile.authority != "mail.blackbagsecurity.com"
            || profile.purpose != "osmap-password-rust-http-fixture"
            || [profile.admission_helper_uid, profile.mutation_helper_uid]
                .iter()
                .any(|uid| *uid == 0 || *uid == u32::MAX)
        {
            return Err(());
        }
        Ok(profile)
    }
    fn paired_profile_file(path: &Path) -> Result<Vec<u8>, ()> {
        let before = fs::symlink_metadata(path).map_err(|_| ())?;
        let identity = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        if !before.is_file()
            || before.uid() != 0
            || before.gid() != WEB_GID
            || before.mode() & 0o7777 != 0o440
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > 2048
        {
            return Err(());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ())?;
        if identity(&file.metadata().map_err(|_| ())?) != identity(&before) {
            return Err(());
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        (&mut file)
            .take(2049)
            .read_to_end(&mut bytes)
            .map_err(|_| ())?;
        if bytes.len() as u64 != before.len()
            || identity(&file.metadata().map_err(|_| ())?) != identity(&before)
            || identity(&fs::symlink_metadata(path).map_err(|_| ())?) != identity(&before)
        {
            return Err(());
        }
        Ok(bytes)
    }
    fn fixture_accounts(topology: Topology) -> [&'static str; 2] {
        if topology != Topology::LegacyPrivate {
            ["alice@osmap-password.invalid", "bob@osmap-password.invalid"]
        } else {
            ["alice@osmap-proxy.invalid", "bob@osmap-proxy.invalid"]
        }
    }
    fn account_config(
        root: &Path,
        runtime: &Path,
        topology: Topology,
    ) -> crate::config::AccountRuntimeConfig {
        let native = topology == Topology::NativeLocal;
        crate::config::AccountRuntimeConfig {
            rollout_account: None,
            admission_socket: if native {
                crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET.into()
            } else {
                runtime.join("admission/admission.sock")
            },
            admission_key_file: root.join("keys/admission.key"),
            admission_helper_uid: 0,
            mutation_socket: if native {
                crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET.into()
            } else {
                runtime.join("rust-mutation.sock")
            },
            mutation_key_file: root.join("keys/mutation.key"),
            session_proof_key_file: root.join("keys/session-proof.key"),
            mutation_helper_uid: 0,
        }
    }
    fn config_and_seed(root: &Path, topology: Topology) -> Result<crate::config::AppConfig, ()> {
        let runtime = root.parent().ok_or(())?;
        directory(runtime, 0, 0o750)?;
        directory(root, 0, 0o750)?;
        if topology == Topology::LegacyPrivate {
            directory(&runtime.join("admission"), 0, 0o750)?;
        }
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
        config.account_runtime = Some(account_config(root, runtime, topology));
        if topology == Topology::PairedRelay {
            // Fixed local purpose relays perform the existing two-host transport.
            // Protected startup selects explicit peers; every real client still
            // checks the socket's kernel peer and purpose-separated private keys.
            // Neither this profile nor test construction grants native readiness.
            let path = root.join("keys/paired-relays.json");
            let profile = paired_relay_profile(&paired_profile_file(&path)?)?;
            let account = config.account_runtime.as_mut().ok_or(())?;
            account.admission_socket = "/var/lib/osmap-bridge/run/admission.sock".into();
            account.mutation_socket = "/var/lib/osmap-bridge/run/mutation.sock".into();
            account.admission_helper_uid = profile.admission_helper_uid;
            account.mutation_helper_uid = profile.mutation_helper_uid;
        }
        let store = crate::totp::FileTotpSecretStore::new(&config.state_layout.totp_secret_dir);
        for account in fixture_accounts(topology) {
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
    fn single_host_http_config_uses_native_pair_without_relay_profile() {
        // Pure construction: no profile file or socket is opened. Native
        // custody is still checked by the actual clients before HTTP startup.
        let runtime = Path::new("/var/run/osmap-pxp-0123456789abcdef");
        let root = runtime.join("http-state");
        let local = account_config(&root, runtime, Topology::NativeLocal);
        assert_eq!(
            local.admission_socket,
            Path::new(crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET)
        );
        assert_eq!(
            local.mutation_socket,
            Path::new(crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET)
        );
        assert_eq!(
            (local.admission_helper_uid, local.mutation_helper_uid),
            (0, 0)
        );
        assert_eq!(local.admission_key_file, root.join("keys/admission.key"));
        assert_eq!(local.mutation_key_file, root.join("keys/mutation.key"));
        assert_eq!(
            local.session_proof_key_file,
            root.join("keys/session-proof.key")
        );
        assert!(local.rollout_account.is_none());
        assert_eq!(
            fixture_accounts(Topology::NativeLocal),
            fixture_accounts(Topology::PairedRelay)
        );
        assert_eq!(
            fixture_accounts(Topology::LegacyPrivate),
            ["alice@osmap-proxy.invalid", "bob@osmap-proxy.invalid"]
        );
        for topology in [Topology::LegacyPrivate, Topology::PairedRelay] {
            let legacy = account_config(&root, runtime, topology);
            assert_eq!(
                legacy.admission_socket,
                runtime.join("admission/admission.sock")
            );
            assert_eq!(legacy.mutation_socket, runtime.join("rust-mutation.sock"));
        }
        const {
            assert!(!crate::account_admission_runtime::NATIVE_CONFINEMENT_QUALIFIED);
            assert!(!crate::account_mutation_client::NATIVE_CONFINEMENT_QUALIFIED);
        }
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

    #[test]
    fn paired_relay_profile_refuses_peer_shortcuts_and_extra_authority() {
        let valid = br#"{"version":1,"authority":"mail.blackbagsecurity.com","purpose":"osmap-password-rust-http-fixture","admission_helper_uid":1004,"mutation_helper_uid":1004}"#;
        assert!(paired_relay_profile(valid).is_ok());
        for raw in [
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("1004", "0"),
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("1004", "4294967295"),
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("1004", "true"),
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("mail.blackbagsecurity.com", "other.invalid"),
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("fixture\"", "other\""),
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("{", "{\"native_ready\":true,"),
            String::from_utf8(valid.to_vec())
                .unwrap()
                .replace("{", "{\"version\":1,"),
        ] {
            assert!(paired_relay_profile(raw.as_bytes()).is_err());
        }
    }

    /// Root starts this already irreversibly nonroot. Role records/topology,
    /// paired real account services and the complete HTTP consumer must pass
    /// separate frozen review; this entry cannot declare their outcomes.
    #[test]
    #[ignore = "root-reviewed genuine HTTP/password fixture only; no installed activation"]
    fn native_http_password_runtime_entrypoint() {
        native_http_password_runtime(Topology::LegacyPrivate);
    }

    #[test]
    #[ignore = "root-reviewed current Rust backend and actual purpose-paired relays required"]
    fn native_current_rust_http_password_runtime_entrypoint() {
        native_http_password_runtime(Topology::PairedRelay);
    }

    #[test]
    #[ignore = "requires reviewed single-host Rust account service and disposable accounts"]
    fn native_single_host_rust_http_password_runtime_entrypoint() {
        native_http_password_runtime(Topology::NativeLocal);
    }

    #[test]
    #[ignore = "requires reviewed native no-write negative consumer and disposable accounts"]
    fn native_single_host_prewrite_runtime_entrypoint() {
        native_http_password_runtime_case(Topology::NativeLocal, false, false, false);
    }

    #[test]
    #[ignore = "requires fixed native postwrite refusal service and independent state witnesses"]
    fn native_single_host_postwrite_runtime_entrypoint() {
        native_http_password_runtime_case(Topology::NativeLocal, true, true, false);
    }

    /// Actual OpenBSD file locks/durable rate records plus live epoch authority.
    /// This does not claim complete wire replay or a concurrent credential write.
    #[test]
    #[ignore = "requires reviewed root bootstrap, fresh state and actual local account service"]
    fn native_single_host_rate_restart_entrypoint() {
        use crate::totp::TimeProvider;
        assert_eq!(std::env::consts::OS, "openbsd");
        crate::openbsd::disable_core_dumps().unwrap();
        let fd: i32 = std::env::var("OSMAP_TEST_HTTP_PILOT_FD")
            .unwrap()
            .parse()
            .unwrap();
        assert!((3..=1024).contains(&fd));
        let mut control = Control::owned(
            crate::openbsd::fixture_current_rust_owned_http_pilot_control(fd).unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let boot = bootstrap(&control.read(2048, deadline).unwrap()).unwrap();
        let config = config_and_seed(&boot.root, Topology::NativeLocal).unwrap();
        let account = config.account_runtime.as_ref().unwrap();
        let client = crate::account_admission_runtime::Client::paired_fixture_files(
            &account.admission_socket,
            &account.admission_key_file,
            0,
        )
        .unwrap();
        for a in fixture_accounts(Topology::NativeLocal) {
            client.admit_before(a, 0, deadline).unwrap();
        }
        let path = config
            .state_layout
            .settings_dir
            .join("password-stepup-rate");
        let store = crate::password_change_rate::Store::new(path.clone());
        let now = crate::totp::SystemTimeProvider.unix_timestamp();
        // Fixed private rate subjects only; no backend account is created.
        let a = "rate-a@osmap-password.invalid";
        for _ in 0..4 {
            assert!(!store
                .admit(a, "192.0.2.11", now)
                .unwrap()
                .failed(now)
                .unwrap());
        }
        store
            .admit(a, "192.0.2.12", now)
            .unwrap()
            .confirm()
            .unwrap();
        assert!(store
            .admit(a, "192.0.2.13", now)
            .unwrap()
            .failed(now)
            .unwrap());
        assert!(crate::password_change_rate::Store::new(path.clone())
            .admit(a, "192.0.2.14", now)
            .is_err());
        let source = "192.0.2.21";
        for a in [
            "rate-b@osmap-password.invalid",
            "rate-c@osmap-password.invalid",
        ] {
            for _ in 0..4 {
                store.admit(a, source, now).unwrap().failed(now).unwrap();
            }
        }
        for _ in 0..2 {
            store
                .admit("rate-d@osmap-password.invalid", source, now)
                .unwrap()
                .failed(now)
                .unwrap();
        }
        assert!(crate::password_change_rate::Store::new(path.clone())
            .admit("rate-e@osmap-password.invalid", source, now)
            .is_err());
        let held = store
            .admit("rate-f@osmap-password.invalid", "192.0.2.31", now)
            .unwrap();
        std::thread::scope(|scope| {
            let path = path.clone();
            assert!(scope
                .spawn(move || crate::password_change_rate::Store::new(path)
                    .admit("rate-f@osmap-password.invalid", "192.0.2.32", now)
                    .is_err())
                .join()
                .unwrap());
        });
        held.confirm().unwrap();
        drop(held);
        store
            .admit("rate-f@osmap-password.invalid", "192.0.2.32", now)
            .unwrap()
            .confirm()
            .unwrap();
        for a in fixture_accounts(Topology::NativeLocal) {
            client.admit_before(a, 0, deadline).unwrap();
        }
        assert!(Instant::now() < deadline);
        control.write(b"{\"schema\":\"osmap-native-rate-restart-v1\",\"account_limit\":5,\"source_limit\":10,\"success_preserved_failures\":true,\"restart_refused\":true,\"concurrent_issuance_refused\":true,\"alice_epoch\":0,\"bob_epoch\":0,\"credential_write\":false}", deadline).unwrap();
    }

    #[test]
    #[ignore = "requires real native mutation replay and independent no-second-write witnesses"]
    fn native_single_host_replay_runtime_entrypoint() {
        native_http_password_runtime_case(Topology::NativeLocal, true, false, true);
    }
    /// Literal second issuer during the native mutation's held Store interval.
    /// Tests the epoch gate after actual primary authentication; factor replay
    /// remains the separate genuine HTTP/TOTP consumer's responsibility.
    #[test]
    #[ignore = "requires root-owned P/G mutation rendezvous and actual native service"]
    fn native_single_host_concurrent_issuance_entrypoint() {
        use crate::account_admission::EpochAuthority;
        use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
        use crate::totp::SystemTimeProvider;
        use std::sync::Arc;
        assert_eq!(std::env::consts::OS, "openbsd");
        crate::openbsd::disable_core_dumps().unwrap();
        let fd: i32 = std::env::var("OSMAP_TEST_HTTP_PILOT_FD")
            .unwrap()
            .parse()
            .unwrap();
        assert!((3..=1024).contains(&fd));
        let mut control = Control::owned(
            crate::openbsd::fixture_current_rust_owned_http_pilot_control(fd).unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(45);
        let boot = bootstrap(&control.read(2048, deadline).unwrap()).unwrap();
        let runtime = boot.root.parent().unwrap();
        directory(runtime, 0, 0o750).unwrap();
        directory(&boot.root, 0, 0o750).unwrap();
        directory(&boot.root.join("keys"), 0, 0o750).unwrap();
        let config = crate::config::AppConfig::from_env_map(&std::collections::BTreeMap::from([
            ("OSMAP_RUN_MODE".into(), "serve".into()),
            ("OSMAP_ENV".into(), "staging".into()),
            ("OSMAP_STATE_DIR".into(), boot.root.to_str().unwrap().into()),
            ("OSMAP_ALLOWED_HOSTS".into(), HOST.into()),
            ("OSMAP_LISTEN_ADDR".into(), "127.0.0.1:0".into()),
            ("OSMAP_OPENBSD_CONFINEMENT_MODE".into(), "enforce".into()),
        ]))
        .unwrap();
        directory(&config.state_layout.runtime_dir, WEB_UID, 0o700).unwrap();
        let account = account_config(&boot.root, runtime, Topology::NativeLocal);
        let client = crate::account_admission_runtime::Client::paired_fixture_files(
            &account.admission_socket,
            &account.admission_key_file,
            0,
        )
        .unwrap();
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Primary {
            alice_password: String,
        }
        let primary: Primary =
            serde_json::from_slice(&control.read(256, deadline).unwrap()).unwrap();
        assert!(
            primary.alice_password.len() == 64
                && primary
                    .alice_password
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
        );
        let captured = client
            .authenticate_before(
                "alice@osmap-password.invalid",
                &primary.alice_password,
                deadline,
            )
            .unwrap()
            .unwrap();
        assert_eq!(captured.account, "alice@osmap-password.invalid");
        assert_eq!(captured.epoch, 0);
        drop(primary);
        let session_root = config.state_layout.runtime_dir.join("t04-issuer-sessions");
        fs::create_dir(&session_root).unwrap();
        fs::set_permissions(
            &session_root,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        control
            .write(
                b"{\"schema\":\"osmap-native-issuance-race-ready-v1\",\"captured_epoch\":0}",
                deadline,
            )
            .unwrap();
        assert_eq!(control.read(1, deadline).unwrap(), b"G");
        struct HeldEpoch {
            client: crate::account_admission_runtime::Client,
            deadline: Instant,
            calls: Arc<std::sync::atomic::AtomicUsize>,
            result: Arc<std::sync::Mutex<Option<crate::account_admission::Error>>>,
        }
        impl EpochAuthority for HeldEpoch {
            fn admit(&self, a: &str, e: u64) -> Result<(), crate::account_admission::Error> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let outcome = self.client.admit_before(a, e, self.deadline);
                *self.result.lock().unwrap() = outcome.as_ref().err().copied();
                outcome
            }
        }
        let probe = Instant::now();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let held_result = Arc::new(std::sync::Mutex::new(None));
        let sessions = SessionService::new(
            FileSessionStore::new(session_root.clone()),
            SystemTimeProvider,
            SystemRandomSource,
            600,
            300,
        )
        .with_epoch_authority(Arc::new(HeldEpoch {
            client: client.clone(),
            deadline: probe + Duration::from_secs(2),
            calls: calls.clone(),
            result: held_result.clone(),
        }));
        let context = crate::auth::AuthenticationContext::new(
            crate::auth::AuthenticationPolicy::default(),
            "native-t04-concurrent-issuer",
            "127.0.0.1",
            "OSMAP/NativeT04",
        )
        .unwrap();
        assert!(sessions
            .issue_with_epoch(
                &context,
                &captured.account,
                crate::auth::RequiredSecondFactor::Totp,
                Some(captured.epoch)
            )
            .is_err());
        assert!(probe.elapsed() < Duration::from_secs(3));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let refusal = match *held_result.lock().unwrap() {
            Some(crate::account_admission::Error::Refused) => "SIGNED_REFUSED",
            Some(crate::account_admission::Error::Unavailable) => "UNAVAILABLE",
            Some(crate::account_admission::Error::Expired) => "EXPIRED",
            _ => panic!("actual bounded native admission refusal not observed"),
        };
        assert!(!fs::read_dir(&session_root).unwrap().any(|entry| entry
            .unwrap()
            .path()
            .extension()
            .and_then(|x| x.to_str())
            == Some("session")));
        let held = serde_json::to_vec(&serde_json::json!({"schema":"osmap-native-issuance-race-held-v1","issuance_denied":true,"new_sessions":0,"native_admission_deadline_ms":2000,"native_admission_calls":1,"native_admission_refusal":refusal})).unwrap();
        control.write(&held, deadline).unwrap();
        assert_eq!(control.read(1, deadline).unwrap(), b"G");
        assert!(matches!(
            client.admit_before(&captured.account, 0, deadline),
            Err(crate::account_admission::Error::Refused)
        ));
        client.admit_before(&captured.account, 1, deadline).unwrap();
        client
            .admit_before("bob@osmap-password.invalid", 0, deadline)
            .unwrap();
        control.write(b"{\"schema\":\"osmap-native-issuance-race-v1\",\"issuance_denied\":true,\"new_sessions\":0,\"stale_epoch_refused\":true,\"current_epoch\":1,\"bob_epoch\":0}", deadline).unwrap();
    }

    fn native_http_password_runtime(topology: Topology) {
        native_http_password_runtime_case(topology, true, false, false);
    }
    fn native_http_password_runtime_case(
        topology: Topology,
        changed: bool,
        incomplete: bool,
        replay: bool,
    ) {
        // Fixed case selectors are cfg(test) callers; bootstrap cannot select one.
        let connections = if changed { CONNECTIONS } else { 32 };
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
            crate::openbsd::fixture_current_rust_owned_http_pilot_control(fd)
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
        let config = config_and_seed(&boot.root, topology).expect("HTTP fixture state refused");
        let account = config
            .account_runtime
            .as_ref()
            .expect("HTTP fixture account config required");
        let admission = crate::account_admission_runtime::Client::paired_fixture_files(
            &account.admission_socket,
            &account.admission_key_file,
            account.admission_helper_uid,
        )
        .expect("HTTP fixture admission custody refused");
        // Same Arc custody is finalized by the actual paired Serve seal below.
        let epoch_probe = admission.clone();
        let mutation = crate::account_mutation_client::Client::stored_fixture_files(
            &account.mutation_socket,
            &account.mutation_key_file,
            &account.session_proof_key_file,
            account.mutation_helper_uid,
        )
        .expect("HTTP fixture mutation custody refused");
        let replay_probe = mutation.clone();
        if replay {
            mutation
                .enable_native_consumed_replay_fixture()
                .expect("native replay fixture refused");
        }
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
            "port":port,"connections":connections,"totp_counter":crate::totp::SystemTimeProvider.unix_timestamp()/30})).unwrap();
        control
            .write(&ready, setup)
            .expect("HTTP fixture ready refused");
        assert_eq!(
            control.read(1, setup).ok().as_deref(),
            Some(b"G".as_slice()),
            "HTTP fixture start refused"
        );
        // Each genuine password POST retains the production route's original
        // 60s deadline. The 300s whole journey allows up to 60s of fresh-counter
        // waiting, the unchanged 60s operation and 180s for the other requests,
        // authority reads and terminal exchange. It never renews an operation.
        let began = Instant::now();
        let deadline = began + Duration::from_secs(300);
        let mut handled = 0;
        while handled < connections {
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
        let [alice, bob] = fixture_accounts(topology);
        if changed {
            assert!(matches!(
                epoch_probe.admit_before(alice, 0, deadline),
                Err(crate::account_admission::Error::Refused)
            ));
            if incomplete {
                assert!(matches!(
                    epoch_probe.admit_before(alice, 1, deadline),
                    Err(crate::account_admission::Error::Refused)
                ));
            } else {
                epoch_probe
                    .admit_before(alice, 1, deadline)
                    .expect("HTTP fixture current Alice epoch refused");
            }
        } else {
            epoch_probe
                .admit_before(alice, 0, deadline)
                .expect("no-write Alice epoch changed");
        }
        epoch_probe
            .admit_before(bob, 0, deadline)
            .expect("HTTP fixture preserved Bob epoch refused");
        // The authenticated client verifier binds every active epoch to the
        // exact requested epoch before admit_before can return Ok(()).
        let mut report = serde_json::json!({"schema":"osmap-http-password-runtime-v1",
            "handled_connections":handled,"elapsed_millis":began.elapsed().as_millis(),
            "alice_epoch0_refused":changed,"alice_epoch1_admitted":if changed && !incomplete { Some(1) } else { None },"bob_epoch0_admitted":0});
        if replay {
            let refusal = replay_probe
                .native_consumed_replay_refusal_fixture()
                .expect("actual consumed native replay not observed");
            assert!(matches!(
                refusal,
                "SIGNED_KNOWN_REFUSED" | "CLOSED_WITHOUT_RECEIPT"
            ));
            report["consumed_mutation_replay_refusal"] = serde_json::json!(refusal);
        }
        let report = serde_json::to_vec(&report).unwrap();
        control
            .write(&report, deadline)
            .expect("HTTP fixture report refused");
        // Counts attest bounded handling only. Root independently verifies real
        // login/form/CSRF/mutation/revocation/old-new auth/Bob continuity.
    }
}
