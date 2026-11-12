use super::*;
use crate::auth::{
    CommandExecution, CommandExecutionError, PrimaryAuthBackendError, PrimaryAuthVerdict,
};
use std::{cell::RefCell, fs, os::unix::fs::PermissionsExt as _, sync::Arc};

const ACCOUNT: &str = "recovery@example.test";
struct Clock;
impl crate::totp::TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        59
    }
}
struct Authority;
impl crate::account_admission::EpochAuthority for Authority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        if account == ACCOUNT && epoch == 3 {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
struct Primary {
    accepted: bool,
    epoch: u64,
}
impl crate::auth::PrimaryCredentialBackend for Primary {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        account: &str,
        _: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        Ok(if self.accepted {
            PrimaryAuthVerdict::Accept {
                canonical_username: account.into(),
            }
        } else {
            PrimaryAuthVerdict::Reject
        })
    }
}
impl EpochPrimaryBackend for Primary {
    fn captured_admission(
        &self,
    ) -> Result<crate::account_admission::Admission, crate::password_change::Error> {
        Ok(crate::account_admission::Admission {
            account: ACCOUNT.into(),
            epoch: self.epoch,
        })
    }
}

struct Fixture {
    root: PathBuf,
    session: ValidatedSession,
    context: AuthenticationContext,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-recovery-runtime-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for child in ["sessions", "totp", "replay"] {
            fs::create_dir(root.join(child)).unwrap();
            fs::set_permissions(root.join(child), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "recovery-runtime",
            "127.0.0.1",
            "PublicFixture",
        )
        .unwrap();
        let service = SessionService::new(
            FileSessionStore::new(root.join("sessions")),
            Clock,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(Arc::new(Authority));
        let issued = service
            .issue_with_epoch(
                &context,
                ACCOUNT,
                crate::auth::RequiredSecondFactor::Totp,
                Some(3),
            )
            .unwrap();
        let secrets = FileTotpSecretStore::new(root.join("totp"));
        let path = secrets.secret_path_for_username(ACCOUNT);
        fs::write(&path, b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            context,
            session: ValidatedSession {
                record: issued.record,
                audit_event: issued.audit_event,
            },
        }
    }
    fn authorize(&self, primary: &Primary, code: &str) -> Result<(), Error> {
        let factor = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                FileTotpSecretStore::new(self.root.join("totp"))
                    .with_replay_dir(self.root.join("replay")),
                Clock,
                TotpPolicy {
                    digits: 6,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        step_up(
            &self.context,
            &self.session,
            primary,
            &factor,
            &Authority,
            &crate::password_change_rate::Store::new(self.root.join("rate")),
            &Clock,
            AuthenticationPolicy::default(),
            "public synthetic passphrase",
            code,
            Instant::now() + Duration::from_secs(10),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn fresh_primary_and_file_totp_replay_are_required_for_recovery_stepup() {
    let f = Fixture::new();
    assert_eq!(
        f.authorize(
            &Primary {
                accepted: true,
                epoch: 2
            },
            "287082"
        ),
        Err(Error::Stale)
    );
    assert_eq!(fs::read_dir(f.root.join("replay")).unwrap().count(), 0);
    assert_eq!(
        f.authorize(
            &Primary {
                accepted: true,
                epoch: 3
            },
            "287082"
        ),
        Ok(())
    );
    assert!(fs::read_dir(f.root.join("replay")).unwrap().count() > 0);
    assert_eq!(
        f.authorize(
            &Primary {
                accepted: true,
                epoch: 3
            },
            "287082"
        ),
        Err(Error::Authentication)
    );
}

#[test]
fn recovery_primary_failures_use_persistent_d04_rate_without_consuming_totp() {
    let f = Fixture::new();
    for _ in 0..5 {
        assert_eq!(
            f.authorize(
                &Primary {
                    accepted: false,
                    epoch: 3
                },
                "287082"
            ),
            Err(Error::Authentication)
        );
    }
    assert_eq!(
        f.authorize(
            &Primary {
                accepted: true,
                epoch: 3
            },
            "287082"
        ),
        Err(Error::Throttled)
    );
    assert_eq!(fs::read_dir(f.root.join("replay")).unwrap().count(), 0);
}

#[derive(Default)]
struct Probe {
    #[allow(clippy::type_complexity)] // Exact fixed transport observations.
    calls: RefCell<Vec<(String, Vec<String>, Vec<u8>, Duration, usize)>>,
    status: i32,
}
impl CommandExecutor for Probe {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("unbounded delivery forbidden")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        cap: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.calls
            .borrow_mut()
            .push((program.into(), args.to_vec(), input.into(), timeout, cap));
        Ok(CommandExecution {
            status_code: self.status,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

#[test]
fn recovery_delivery_has_fixed_bounded_sendmail_shape_and_token_only_on_stdin() {
    let notifier = SendmailNotifier {
        executor: Probe::default(),
        path: std::path::Path::new("/usr/sbin/sendmail"),
        sender: ACCOUNT,
        local_domain: "example.test",
        external_delivery: false,
    };
    let token = "42".repeat(32);
    assert_eq!(
        notifier.deliver(
            RecoveryContactMessage::Verification {
                email: "sink@example.test",
                token: &token,
                expires_at: 1859
            },
            Instant::now() + Duration::from_secs(30)
        ),
        RecoveryContactDelivery::Accepted
    );
    let calls = notifier.executor.calls.borrow();
    let (program, args, wire, timeout, cap) = &calls[0];
    assert_eq!(program, "/usr/sbin/sendmail");
    assert_eq!(
        args,
        &["-oi", "-N", "never", "-f", "<>", "--", "sink@example.test"]
    );
    assert!(String::from_utf8_lossy(wire).contains("Auto-Submitted: auto-generated\r\n"));
    assert!(String::from_utf8_lossy(wire).contains("X-Auto-Response-Suppress: All\r\n"));
    assert!(args.iter().all(|arg| !arg.contains(&token)));
    assert!(String::from_utf8_lossy(wire).contains(&token));
    assert!(*timeout <= Duration::from_secs(10));
    assert_eq!(*cap, 4096);
}

#[test]
fn delivery_refuses_headers_before_dispatch_and_preserves_unknown_acceptance() {
    let notifier = SendmailNotifier {
        executor: Probe {
            status: 75,
            ..Probe::default()
        },
        path: std::path::Path::new("/usr/sbin/sendmail"),
        sender: ACCOUNT,
        local_domain: "example.test",
        external_delivery: false,
    };
    assert_eq!(
        notifier.deliver(
            RecoveryContactMessage::Removed {
                email: "sink@example.test\r\nBcc:other@example.test"
            },
            Instant::now() + Duration::from_secs(1)
        ),
        RecoveryContactDelivery::Refused
    );
    assert!(notifier.executor.calls.borrow().is_empty());
    assert_eq!(
        notifier.deliver(
            RecoveryContactMessage::Removed {
                email: "sink@foreign.test"
            },
            Instant::now() + Duration::from_secs(1)
        ),
        RecoveryContactDelivery::Refused
    );
    assert!(notifier.executor.calls.borrow().is_empty());
    assert_eq!(
        notifier.deliver(
            RecoveryContactMessage::Removed {
                email: "sink@example.test"
            },
            Instant::now() + Duration::from_secs(1)
        ),
        RecoveryContactDelivery::Unconfirmed
    );
    assert_eq!(notifier.executor.calls.borrow().len(), 1);
    assert_eq!(
        notifier.deliver(
            RecoveryContactMessage::Removed {
                email: "sink@example.test"
            },
            Instant::now() - Duration::from_secs(1)
        ),
        RecoveryContactDelivery::Refused
    );
    assert_eq!(notifier.executor.calls.borrow().len(), 1);
}

#[test]
fn explicitly_enabled_external_delivery_uses_account_envelope_and_suppresses_dsns() {
    let notifier = SendmailNotifier {
        executor: Probe::default(),
        path: std::path::Path::new("/usr/sbin/sendmail"),
        sender: ACCOUNT,
        local_domain: "example.test",
        external_delivery: true,
    };
    let token = "42".repeat(32);
    assert_eq!(
        notifier.deliver(
            RecoveryContactMessage::Verification {
                email: "owner@protonmail.com",
                token: &token,
                expires_at: 1859,
            },
            Instant::now() + Duration::from_secs(30),
        ),
        RecoveryContactDelivery::Accepted
    );
    let calls = notifier.executor.calls.borrow();
    let (_, args, wire, _, _) = &calls[0];
    assert_eq!(
        args,
        &[
            "-oi",
            "-N",
            "never",
            "-f",
            ACCOUNT,
            "--",
            "owner@protonmail.com",
        ]
    );
    assert!(String::from_utf8_lossy(wire).contains("To: owner@protonmail.com\r\n"));
    assert!(String::from_utf8_lossy(wire).contains(&token));
    assert!(args.iter().all(|arg| !arg.contains(&token)));

    let invalid_sender = SendmailNotifier {
        executor: Probe::default(),
        path: std::path::Path::new("/usr/sbin/sendmail"),
        sender: "owner@-example.test",
        local_domain: "example.test",
        external_delivery: true,
    };
    assert_eq!(
        invalid_sender.deliver(
            RecoveryContactMessage::Removed {
                email: "owner@protonmail.com",
            },
            Instant::now() + Duration::from_secs(1),
        ),
        RecoveryContactDelivery::Refused
    );
    assert!(invalid_sender.executor.calls.borrow().is_empty());
}

// Exercises the actual BrowserApp -> Runtime gateway -> signed admission
// client -> private session/TOTP/contact stores -> bounded delivery path.
// Only the native account helper and the local mail executable are fixtures.
#[test]
fn ordinary_runtime_http_contact_roundtrip_uses_real_session_and_external_delivery() {
    use hmac::{Hmac, Mac as _};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Owned {
        root: PathBuf,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
        _mutation: UnixListener,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    let root = std::path::Path::new("/tmp").join(format!(
        "osmap-rcontact-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let admission_path = root.join("admission.sock");
    let listener = UnixListener::bind(&admission_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::set_permissions(&admission_path, fs::Permissions::from_mode(0o660)).unwrap();
    let mutation_path = root.join("mutation.sock");
    let mutation = UnixListener::bind(&mutation_path).unwrap();
    fs::set_permissions(&mutation_path, fs::Permissions::from_mode(0o660)).unwrap();
    for (name, byte) in [
        ("admission.key", 29u8),
        ("mutation.key", 31),
        ("proof.key", 37),
    ] {
        fs::write(root.join(name), [byte; 32]).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let guard_observed = Arc::new(AtomicBool::new(false));
    let worker_guard = guard_observed.clone();
    let session_lock = root.join("sessions/.session-store.lock");
    let worker = std::thread::spawn(move || {
        let mut verifier = crate::account_admission::Verifier::default();
        while !worker_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let bytes = crate::openpgp_inventory_runtime::read_frame(
                        &mut stream,
                        crate::account_admission::MAX_FRAME,
                        deadline,
                    )
                    .unwrap();
                    let now = SystemTimeProvider.unix_timestamp();
                    let request = verifier.request(&bytes, &[29; 32], now).unwrap();
                    assert!(request.account() == ACCOUNT);
                    let allowed = match request.operation() {
                        crate::account_admission::Operation::Admit { epoch } => *epoch == 3,
                        crate::account_admission::Operation::Authenticate { password } => {
                            let lock = fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .open(&session_lock)
                                .unwrap();
                            assert!(
                                crate::openbsd::try_advisory_file_lock_exclusive(&lock).is_err()
                            );
                            worker_guard.store(true, Ordering::SeqCst);
                            password == "public synthetic passphrase"
                        }
                    };
                    let reply = request
                        .response(allowed.then_some(3), &[29; 32], now)
                        .unwrap();
                    crate::openpgp_inventory_runtime::write_frame(&mut stream, &reply, deadline)
                        .unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => panic!("owned admission listener failed"),
            }
        }
    });
    let owned = Owned {
        root: root.clone(),
        stop,
        worker: Some(worker),
        _mutation: mutation,
    };
    let uid = crate::openbsd::effective_uid();
    let mut gateway = RuntimeBrowserGateway::for_test(&root).with_account_fixture_clients(
        crate::account_admission_runtime::Client::paired_fixture_files(
            &admission_path,
            &root.join("admission.key"),
            uid,
        )
        .unwrap(),
        crate::account_mutation_client::Client::stored_fixture_files(
            &mutation_path,
            &root.join("mutation.key"),
            &root.join("proof.key"),
            uid,
        )
        .unwrap(),
    );
    gateway.recovery_contact_local_domain = Some("example.test".into());
    gateway.recovery_contact_external_delivery = true;
    for name in ["sessions", "totp", "cache", "cache/totp-replay"] {
        fs::create_dir_all(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let secret = FileTotpSecretStore::new(root.join("totp")).secret_path_for_username(ACCOUNT);
    fs::write(&secret, b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
    fs::set_permissions(secret, fs::Permissions::from_mode(0o600)).unwrap();
    let sink = root.join("recovery-sink");
    let program = root.join("owned-sendmail");
    const SINK_SOURCE: &[u8] = br#"
use std::{fs::OpenOptions, io::{Read,Write}, os::unix::fs::OpenOptionsExt};
fn main() -> std::io::Result<()> {
    let args:Vec<_>=std::env::args().skip(1).collect();
    if args != ["-oi","-N","never","-f","recovery@example.test","--","sink@foreign.test"] {
        std::process::exit(1);
    }
    let mut message=Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut message)?;
    if message.len()>4096 { std::process::exit(1); }
    let executable=std::env::current_exe()?;
    let path=executable.parent().ok_or(std::io::ErrorKind::InvalidInput)?.join("recovery-sink");
    let mut sink=OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    sink.write_all(&message)?;
    sink.sync_all()
}
"#;
    let compiler = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|path| path.join("rustc"))
                .find(|path| path.is_file())
        })
        .expect("test environment requires the existing Rust compiler");
    let compiled = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            compiler.to_str().unwrap(),
            &[
                "--crate-name=osmap_recovery_sink".into(),
                "--edition=2021".into(),
                "-Cdebuginfo=0".into(),
                "-o".into(),
                program.to_str().unwrap().into(),
                "-".into(),
            ],
            SINK_SOURCE,
            Duration::from_secs(30),
            4096,
        )
        .expect("fixed Rust sink compilation unavailable");
    assert_eq!(
        compiled.status_code,
        0,
        "fixed Rust sink refused; diagnostic bytes={}",
        compiled.stderr.len()
    );
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    gateway = gateway.with_fixture_sendmail_path(program);
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "recovery-runtime-http",
        "127.0.0.1",
        "PublicFixture",
    )
    .unwrap();
    let issued = gateway
        .build_session_service()
        .issue_with_epoch(
            &context,
            ACCOUNT,
            crate::auth::RequiredSecondFactor::Totp,
            Some(3),
        )
        .unwrap();
    let cookie = format!("osmap_session={}", issued.token.as_str());
    let csrf = issued.record.csrf_token.clone();
    let now = SystemTimeProvider.unix_timestamp();
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(b"12345678901234567890").unwrap();
    mac.update(&(now / 30).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 15);
    let code = format!(
        "{:06}",
        (u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff)
            % 1_000_000
    );
    let app = BrowserApp::new(HttpPolicy::default(), gateway);
    let request = |method: &str, path: &str, body: &str, cookie: &str| {
        let raw=format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://localhost\r\nCookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",body.len());
        parse_http_request_bytes(raw.as_bytes(), &HttpPolicy::default()).unwrap()
    };
    let perform = |method: &str, path: &str, body: &str, cookie: &str| {
        app.handle_request(&request(method, path, body, cookie), "127.0.0.1")
    };
    let initial = perform("GET", "/settings/recovery", "", &cookie);
    assert_eq!(initial.response.status_code, 200);
    let begin=format!("csrf_token={csrf}&revision=0&action=begin&email=sink%40foreign.test&current_password=public+synthetic+passphrase&totp_code={code}");
    let result = perform("POST", "/settings/recovery", &begin, &cookie);
    assert_eq!(result.response.status_code, 200);
    assert!(guard_observed.load(Ordering::SeqCst));
    let delivered = fs::read_to_string(&sink).unwrap();
    let proof = delivered
        .lines()
        .find(|line| line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap()
        .to_string();
    fs::remove_file(&sink).unwrap();
    let authority = fs::read_dir(root.join("settings/recovery-contact-v1"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.path().extension().is_some_and(|v| v == "json"))
        .unwrap()
        .path();
    assert!(!fs::read_to_string(&authority).unwrap().contains(&proof));
    let pending = app
        .gateway
        .read_recovery_contact(&ValidatedSession {
            record: issued.record.clone(),
            audit_event: issued.audit_event.clone(),
        })
        .unwrap();
    assert!(pending.verified.is_none() && pending.pending.is_some());
    let verify = format!(
        "csrf_token={csrf}&revision={}&action=verify&token={proof}",
        pending.revision
    );
    assert_eq!(
        perform("POST", "/settings/recovery", &verify, &cookie)
            .response
            .status_code,
        200
    );
    let page = perform("GET", "/settings/recovery", "", &cookie);
    assert_eq!(page.response.status_code, 200);
    assert!(String::from_utf8_lossy(&page.response.body).contains("sink@foreign.test"));
    assert!(!String::from_utf8_lossy(&page.response.body).contains(&proof));
    let verified_authority = fs::read(&authority).unwrap();
    let verified = app
        .gateway
        .read_recovery_contact(&ValidatedSession {
            record: issued.record.clone(),
            audit_event: issued.audit_event.clone(),
        })
        .unwrap();
    assert_eq!(
        perform("POST", "/settings/recovery", &verify, &cookie)
            .response
            .status_code,
        409
    );
    let consumed_proof = format!(
        "csrf_token={csrf}&revision={}&action=verify&token={proof}",
        verified.revision
    );
    assert_eq!(
        perform("POST", "/settings/recovery", &consumed_proof, &cookie)
            .response
            .status_code,
        400
    );
    assert_eq!(fs::read(&authority).unwrap(), verified_authority);
    assert_eq!(
        app.gateway
            .read_recovery_contact(&ValidatedSession {
                record: issued.record.clone(),
                audit_event: issued.audit_event.clone(),
            })
            .unwrap(),
        verified
    );
    assert!(!sink.exists());

    // Reconstruct the gateway and purpose-separated clients over the same
    // persisted stores; neither browser metadata nor a cloned View is authority.
    let mut reopened = RuntimeBrowserGateway::for_test(&root)
        .with_account_fixture_clients(
            crate::account_admission_runtime::Client::paired_fixture_files(
                &admission_path,
                &root.join("admission.key"),
                uid,
            )
            .unwrap(),
            crate::account_mutation_client::Client::stored_fixture_files(
                &mutation_path,
                &root.join("mutation.key"),
                &root.join("proof.key"),
                uid,
            )
            .unwrap(),
        )
        .with_fixture_sendmail_path(root.join("owned-sendmail"));
    reopened.recovery_contact_local_domain = Some("example.test".into());
    reopened.recovery_contact_external_delivery = true;
    let reopened = BrowserApp::new(HttpPolicy::default(), reopened);
    for path in [
        "/settings/recovery",
        "/settings?section=security",
        "/settings?section=authentication",
    ] {
        let response = reopened.handle_request(&request("GET", path, "", &cookie), "127.0.0.1");
        assert_eq!(response.response.status_code, 200, "{path}");
        let html = String::from_utf8_lossy(&response.response.body);
        assert!(html.contains("sink@foreign.test"), "{path}");
        assert!(!html.contains(&proof));
    }
    assert_eq!(fs::read(&authority).unwrap(), verified_authority);
    assert!(!sink.exists());
    drop(reopened);
    assert_eq!(
        perform(
            "GET",
            "/settings/recovery",
            "",
            &format!("osmap_session={}", "ab".repeat(32))
        )
        .response
        .status_code,
        303
    );
    assert!(!sink.exists());
    app.gateway
        .build_session_service()
        .revoke_by_token(&context, &issued.token)
        .unwrap();
    assert_eq!(
        perform("POST", "/settings/recovery", &begin, &cookie)
            .response
            .status_code,
        303
    );
    assert!(!sink.exists());
    drop(app);
    drop(owned);
}

#[test]
fn browser_recovery_runtime_delegates_signed_frames_and_refuses_synthetic_success() {
    use crate::access_recovery_protocol::{Action, Authority as WireAuthority, Request, Response};
    use crate::browser_access::{
        AccessAction, AccessAuthority, AccessCookie, AccessError, AccessOutcome, AccessView,
    };
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    // Reuse the existing owned recovery fixture and paired Runtime clients.
    // Only the socket peer is synthetic; Runtime, transport, framing, signing,
    // strict producer/consumer and response stage validation are actual code.
    for mode in ["view", "reset", "wrong-mac", "unsigned"] {
        let fixture = Fixture::new();
        let admission_path = fixture.root.join("admission.sock");
        let mutation_path = fixture.root.join("mutation.sock");
        let _admission_listener = UnixListener::bind(&admission_path).unwrap();
        let listener = UnixListener::bind(&mutation_path).unwrap();
        for path in [&admission_path, &mutation_path] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
        }
        for (name, byte) in [
            ("admission.key", 29u8),
            ("mutation.key", 31),
            ("proof.key", 37),
        ] {
            fs::write(fixture.root.join(name), [byte; 32]).unwrap();
            fs::set_permissions(fixture.root.join(name), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let uid = crate::openbsd::effective_uid();
        let client = crate::account_mutation_client::Client::stored_fixture_files(
            &mutation_path,
            &fixture.root.join("mutation.key"),
            &fixture.root.join("proof.key"),
            uid,
        )
        .unwrap();
        client.enable_access_fixture().unwrap();
        let gateway = RuntimeBrowserGateway::for_test(&fixture.root).with_account_fixture_clients(
            crate::account_admission_runtime::Client::paired_fixture_files(
                &admission_path,
                &fixture.root.join("admission.key"),
                uid,
            )
            .unwrap(),
            client,
        );
        let csrf = fixture.session.record.csrf_token.clone();
        let expected_session_id = fixture.session.record.session_id.clone();
        let expected_csrf = csrf.clone();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => {
                        panic!("bounded recovery fixture accept failed: {:?}", error.kind())
                    }
                }
            };
            let raw = crate::openpgp_inventory_runtime::read_frame(
                &mut stream,
                crate::access_recovery_protocol::MAX_FRAME,
                deadline,
            )
            .unwrap();
            let now = SystemTimeProvider.unix_timestamp();
            let request = Request::parse(&raw, &[31; 32], now).unwrap();
            assert_eq!(request.csrf(), expected_csrf);
            assert_eq!(request.source(), "127.0.0.1");
            match request.authority() {
                WireAuthority::Session {
                    account,
                    epoch,
                    session_id,
                } => {
                    assert_eq!(account, ACCOUNT);
                    assert_eq!(*epoch, 3);
                    assert_eq!(session_id, &expected_session_id);
                }
                _ => panic!("Runtime must preserve actual validated session authority"),
            }
            let view = if mode == "view" {
                assert!(matches!(request.action(), Action::View {}));
                AccessView::TotpResetStart {
                    account: ACCOUNT.into(),
                    csrf: expected_csrf,
                }
            } else {
                match request.action() {
                    Action::BeginReset { password, totp } => {
                        assert_eq!(password, "public synthetic passphrase");
                        assert_eq!(totp, "123456");
                    }
                    _ => panic!("Runtime action mapping changed"),
                }
                AccessView::TotpReplacement {
                    account: ACCOUNT.into(),
                    csrf: expected_csrf,
                    enrollment: crate::totp_enrollment::PendingEnrollment {
                        id: "a".repeat(64),
                        revision: 1,
                        secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                        otpauth_uri:
                            "otpauth://totp/PublicFixture?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                                .into(),
                        expires_at: now + 600,
                    },
                }
            };
            let reply = if mode == "unsigned" {
                br#"{"view":{"kind":"complete"},"grant_cookie":{"kind":"clear"}}"#.to_vec()
            } else {
                let response = Response::issue(
                    &request,
                    Ok(AccessOutcome {
                        view,
                        grant_cookie: AccessCookie::Unchanged,
                    }),
                    &[31; 32],
                    now,
                )
                .unwrap();
                let mut value: serde_json::Value =
                    serde_json::from_slice(&response.bytes().unwrap()).unwrap();
                if mode == "wrong-mac" {
                    value["signature"] = serde_json::Value::String("0".repeat(64));
                }
                serde_json::to_vec(&value).unwrap()
            };
            crate::openpgp_inventory_runtime::write_frame(&mut stream, &reply, deadline).unwrap();
        });
        if mode == "view" {
            let view = BrowserGateway::access_view(
                &gateway,
                &fixture.context,
                AccessAuthority::Session(&fixture.session),
                &csrf,
            )
            .unwrap();
            assert!(matches!(view, AccessView::TotpResetStart { .. }));
        } else {
            let result = BrowserGateway::access_action(
                &gateway,
                &fixture.context,
                AccessAuthority::Session(&fixture.session),
                &csrf,
                AccessAction::BeginTotpReset {
                    current_password: "public synthetic passphrase",
                    current_totp_code: "123456",
                },
                Instant::now() + Duration::from_secs(3),
            );
            if mode == "reset" {
                let result = result.unwrap();
                assert!(matches!(result.view, AccessView::TotpReplacement { .. }));
                assert!(matches!(result.grant_cookie, AccessCookie::Unchanged));
            } else {
                assert!(matches!(result, Err(AccessError::Unconfirmed)));
            }
        }
        server.join().unwrap();
        // The fixture began with one ordinary session. Recovery transport may
        // return setup presentation, never create a new authenticated session.
        let session_files = fs::read_dir(fixture.root.join("sessions"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|v| v.path().extension().is_some_and(|e| e == "session"))
            .count();
        assert_eq!(session_files, 1);
    }
}
