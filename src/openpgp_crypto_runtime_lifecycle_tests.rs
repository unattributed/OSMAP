//! Real authenticated IPC and the existing owned worker fixture; no real keys.
use super::*;
use std::sync::atomic::Ordering;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osmap-crypto-lifecycle-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn service(home: &Path) -> Arc<Service> {
    Arc::new(Service {
        config: Config {
            version: 1,
            worker: "/synthetic/worker".into(),
            engine: "/synthetic/engine".into(),
            socket: home.join("unused.sock"),
            trusted_web_uid: crate::openbsd::effective_uid(),
            accounts: vec![Mapping {
                account: "alice".into(),
                home: home.into(),
                signer_fingerprint: Some("A".repeat(40)),
                decrypt_fingerprints: vec!["A".repeat(40)],
                recipient_fingerprints: vec!["B".repeat(40)],
                allow_imported_recipients: false,
                allow_web_personal_keys: false,
            }],
        },
        key: vec![9; 32],
        verifier: Mutex::new(Verifier::default()),
        admissions: Admissions::default(),
        personal: Mutex::new(personal::Manager::default()),
    })
}
fn sign() -> Operation {
    Operation::Sign {
        signer_fingerprint: "A".repeat(40),
        data: vec![b'X'; 256 * 1024],
    }
}
fn worker_pid(path: &Path) -> Option<u32> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            return text.trim().parse::<u32>().ok().filter(|pid| *pid > 1);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn ordinary_response(service: &Arc<Service>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    let instance = service.clone();
    let thread = std::thread::spawn(move || {
        instance.connection_with_executor(
            server,
            &AtomicBool::new(false),
            |_, _, _, _, _, cancelled| {
                assert!(!cancelled()?);
                Err(CryptoError::Locked)
            },
        )
    });
    let operation = sign();
    let request = Request::issue("alice", &operation, now().unwrap(), &[9; 32]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    write_frame(&mut client, &request.to_bytes().unwrap(), deadline).unwrap();
    let response = read_frame(&mut client, deadline).unwrap();
    assert_eq!(
        Verifier::default()
            .response(&request, &response, &operation, &[9; 32], now().unwrap())
            .unwrap()
            .err(),
        Some(CryptoError::Locked)
    );
    assert!(thread.join().unwrap().is_ok());
}

#[test]
fn ipc_disconnect_cancels_started_worker_and_releases_same_account_admission() {
    let root = Scratch::new();
    let service = service(&root.0);
    let ready = root.0.join("worker.ready");
    let child_ready = ready.clone();
    let (mut client, server) = UnixStream::pair().unwrap();
    let instance = service.clone();
    let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();
    let cancellation_seen = Arc::new(AtomicBool::new(false));
    let worker_cancellation_seen = cancellation_seen.clone();
    let thread = std::thread::spawn(move || {
        instance.connection_with_executor(
            server,
            &AtomicBool::new(false),
            |_, _, _, operation, deadline, cancelled| {
                let result = crate::openpgp_crypto_process::run_cancellable_fixture(
                    "cancellable_hold",
                    &operation.worker_frame()?,
                    deadline,
                    || {
                        let cancelled = cancelled()?;
                        if cancelled {
                            worker_cancellation_seen.store(true, Ordering::SeqCst);
                        }
                        Ok(cancelled)
                    },
                    Some(&child_ready),
                );
                terminal_tx.send(result.as_ref().err().copied()).unwrap();
                match result {
                    Err(error) => Err(error),
                    Ok(_) => Err(CryptoError::Integrity),
                }
            },
        )
    });
    let operation = sign();
    let request = Request::issue("alice", &operation, now().unwrap(), &[9; 32]).unwrap();
    write_frame(
        &mut client,
        &request.to_bytes().unwrap(),
        Instant::now() + Duration::from_secs(3),
    )
    .unwrap();
    let pid = worker_pid(&ready);
    drop(client);
    let connection_result = thread.join().unwrap();
    let terminal = terminal_rx.recv().unwrap();
    let pid = pid.expect("actual worker start was not observed");
    assert!(
        !crate::openbsd::process_group_exists(pid).unwrap(),
        "owned worker group survived"
    );
    assert!(connection_result.is_err());
    assert!(
        cancellation_seen.load(Ordering::SeqCst),
        "service never observed the caller disconnect"
    );
    assert_eq!(
        terminal,
        Some(CryptoError::Unavailable),
        "disconnect must cancel rather than wait for operation expiry"
    );
    assert!(service.admissions.enter("alice").is_ok());
    ordinary_response(&service);
}

#[test]
fn partial_request_disconnect_never_executes_or_leases_a_worker() {
    let root = Scratch::new();
    let service = service(&root.0);
    let (mut client, server) = UnixStream::pair().unwrap();
    let instance = service.clone();
    let executed = Arc::new(AtomicBool::new(false));
    let observed = executed.clone();
    let thread = std::thread::spawn(move || {
        instance.connection_with_executor(server, &AtomicBool::new(false), |_, _, _, _, _, _| {
            observed.store(true, Ordering::SeqCst);
            Err(CryptoError::Unavailable)
        })
    });
    client.write_all(&64u32.to_be_bytes()).unwrap();
    client.write_all(b"partial").unwrap();
    drop(client);
    assert!(thread.join().unwrap().is_err());
    assert!(!executed.load(Ordering::SeqCst));
    assert!(service.admissions.enter("alice").is_ok());
}

#[test]
fn complete_request_with_live_peer_preserves_authenticated_error_response() {
    let root = Scratch::new();
    ordinary_response(&service(&root.0));
}

#[test]
fn stopped_connection_refuses_before_frame_parsing_or_worker_admission() {
    let root = Scratch::new();
    let instance = service(&root.0);
    let (mut client, server) = UnixStream::pair().unwrap();
    // A running connection would parse this as Limit. A stopped connection
    // must refuse before reading it, without an artificial timing assertion.
    client.write_all(&0u32.to_be_bytes()).unwrap();
    assert!(matches!(
        instance.connection_with_executor(
            server,
            &AtomicBool::new(true),
            |_, _, _, _, _, _| panic!("stopped service dispatched a worker")
        ),
        Err(Error::Unavailable)
    ));
    assert!(instance.admissions.enter("alice").is_ok());
}

/// Entered only through the existing ignored, current-executable worker fixture.
pub(crate) fn serve_hold_child() {
    let root = PathBuf::from(std::env::var_os("OSMAP_CRYPTO_SERVICE_FIXTURE_ROOT").unwrap());
    assert!(
        root.parent() == Some(std::env::temp_dir().as_path())
            && root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("osmap-crypto-lifecycle-")
    );
    assert_eq!(root.canonicalize().unwrap(), root);
    assert!(private_dir(&root, crate::openbsd::effective_uid(), false).is_ok());
    crate::openbsd::restore_crypto_termination_signal().unwrap();
    let service = Arc::try_unwrap(service(&root)).ok().unwrap();
    let listener = UnixListener::bind(&service.config.socket).unwrap();
    fs::set_permissions(&service.config.socket, fs::Permissions::from_mode(0o600)).unwrap();
    service
        .serve_loop(listener, |_, _, home, operation, deadline, cancelled| {
            match crate::openpgp_crypto_process::run_cancellable_fixture(
                "cancellable_hold_short",
                &operation.worker_frame()?,
                deadline,
                cancelled,
                Some(&home.join("worker.ready")),
            ) {
                Err(error) => Err(error),
                Ok(_) => Err(CryptoError::Integrity),
            }
        })
        .unwrap();
}

#[test]
fn helper_sigterm_cleans_active_worker_before_helper_exit() {
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    let root = Scratch::new();
    let mut command = crate::auth::crypto_fixture_command("runtime_service_hold");
    command
        .env("OSMAP_CRYPTO_SERVICE_FIXTURE_ROOT", &root.0)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let connect_until = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match UnixStream::connect(root.0.join("unused.sock")) {
            Ok(client) => break Some(client),
            Err(_) if Instant::now() < connect_until => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(_) => break None,
        }
    };
    let request = Request::issue("alice", &sign(), now().unwrap(), &[9; 32]).unwrap();
    let wrote = client.as_mut().is_some_and(|client| {
        write_frame(
            client,
            &request.to_bytes().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .is_ok()
    });
    let pid = if wrote {
        worker_pid(&root.0.join("worker.ready"))
    } else {
        None
    };
    let signal = crate::openbsd::fixture_t04_terminate_owned_group(child.id());
    let exit_until = Instant::now() + Duration::from_secs(5);
    let mut status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < exit_until => std::thread::sleep(Duration::from_millis(2)),
            _ => break None,
        }
    };
    // Observe the actual survivor before waiting for its short natural life.
    // Never signal a historical grandchild/group after its owner has exited.
    let alive_at_exit = status.is_some()
        && pid
            .map(|pid| crate::openbsd::process_group_exists(pid).unwrap())
            .unwrap_or(false);
    if status.is_none() && crate::openbsd::owned_child_exited_without_reap(child.id()).is_ok() {
        let _ = child.kill();
        status = child.wait().ok();
    }
    drop(client);
    let gone_until = Instant::now() + Duration::from_secs(5);
    let absent = loop {
        let absent = pid
            .map(|pid| !crate::openbsd::process_group_exists(pid).unwrap())
            .unwrap_or(true);
        if absent || Instant::now() >= gone_until {
            break absent;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let stdout_bytes = child
        .stdout
        .take()
        .map(|output| std::io::BufReader::new(output).take(4097).bytes().count())
        .unwrap_or(0);
    let stderr_bytes = child
        .stderr
        .take()
        .map(|output| std::io::BufReader::new(output).take(4097).bytes().count())
        .unwrap_or(0);
    println!("helper_exit_observed={} worker_alive_at_helper_exit={} worker_absent_after_natural_wait={} child_stdout_bytes={} child_stderr_bytes={}", status.is_some(), alive_at_exit, absent, stdout_bytes, stderr_bytes);
    if !absent || status.is_none() {
        println!("lifecycle_fixture_retained={}", root.0.display());
        std::mem::forget(root);
    }
    assert!(
        wrote && pid.is_some(),
        "actual service worker start was not observed"
    );
    assert!(signal.is_ok(), "owned helper SIGTERM was not delivered");
    assert!(!alive_at_exit, "worker survived helper SIGTERM");
    assert!(absent, "worker cleanup remains unconfirmed");
    assert!(
        status.is_some_and(|status| status.success()),
        "helper did not stop cleanly"
    );
    assert!(stdout_bytes <= 4096 && stderr_bytes <= 4096);
}

#[test]
#[ignore = "requires disposable OpenBSD GPGME homes and pinned recovery utility"]
fn native_same_service_recovers_stale_private_agent_without_disrupting_public_encrypt() {
    use crate::auth::{CommandExecutor, SystemCommandExecutor};
    use sha2::{Digest, Sha256};
    assert_eq!(std::env::consts::OS, "openbsd");
    let path = |name: &str| PathBuf::from(std::env::var_os(name).unwrap());
    let worker = path("OSMAP_CRYPTO_NATIVE_WORKER");
    let engine = path("OSMAP_CRYPTO_NATIVE_ENGINE");
    let alice = path("OSMAP_CRYPTO_NATIVE_ALICE_HOME");
    let bob = path("OSMAP_CRYPTO_NATIVE_BOB_HOME");
    let alice_fp = std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap();
    let bob_fp = std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap();
    let source = path("OSMAP_CRYPTO_NATIVE_UNLOCK_SOURCE");
    let source_hash = std::env::var("OSMAP_CRYPTO_NATIVE_UNLOCK_SOURCE_SHA256").unwrap();
    let fixture = worker.parent().unwrap();
    assert!(
        fixture.starts_with("/tmp")
            && fixture
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("osmap-crypto-fixture-")
    );
    assert_eq!(worker.canonicalize().unwrap(), worker);
    assert_eq!(engine.parent(), Some(fixture));
    for home in [&alice, &bob] {
        assert!(home.starts_with(fixture));
        assert_eq!(home.canonicalize().unwrap(), *home);
        assert!(private_dir(home, crate::openbsd::effective_uid(), false).is_ok());
    }
    assert!(source.is_absolute());
    assert_eq!(source.canonicalize().unwrap(), source);
    assert_eq!(source_hash.len(), 64);
    assert!(source_hash
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let source_bytes = fs::read(&source).unwrap();
    assert!(source_bytes.len() <= 128 * 1024);
    assert_eq!(format!("{:x}", Sha256::digest(&source_bytes)), source_hash);
    let root = Scratch(fixture.join("same-service-agent-recovery"));
    fs::create_dir(&root.0).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let pinned_source = root.0.join("deployment_unlock.py");
    fs::write(&pinned_source, source_bytes).unwrap();
    fs::set_permissions(&pinned_source, fs::Permissions::from_mode(0o600)).unwrap();
    let config = root.0.join("service.json");
    let grant = root.0.join("service.key");
    let socket = root.0.join("service.sock");
    fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "version":1,"worker":worker,"engine":engine,"socket":socket,
            "trusted_web_uid":crate::openbsd::effective_uid(),
            "accounts":[{"account":"alice","home":alice,"signer_fingerprint":alice_fp,
                "decrypt_fingerprints":[alice_fp],"recipient_fingerprints":[bob_fp]}]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let mut key = [0; 32];
    getrandom::getrandom(&mut key).unwrap();
    fs::write(&grant, key).unwrap();
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o600)).unwrap();
    let service = Service::from_operator_files(&config, &grant).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(90);
        for _ in 0..5 {
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => return Err(Error::Unavailable),
                }
            };
            stream
                .set_nonblocking(false)
                .map_err(|_| Error::Unavailable)?;
            service.connection(stream)?;
        }
        Ok(())
    });
    let client =
        Client::from_operator_files(&socket, &grant, crate::openbsd::effective_uid()).unwrap();
    let data = b"Synthetic same-service agent recovery.\r\n".to_vec();
    let sign = || Operation::Sign {
        signer_fingerprint: alice_fp.clone(),
        data: data.clone(),
    };
    let execute_command = |program: &str, args: &[String]| {
        let result = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
            program,
            args,
            &[],
            Duration::from_secs(20),
            4096,
        );
        let Ok(result) = result else {
            panic!("bounded disposable recovery command unavailable");
        };
        println!(
            "disposable_recovery_command_exit={} stdout_bytes={} stderr_bytes={}",
            result.status_code,
            result.stdout.len(),
            result.stderr.len()
        );
        assert_eq!(
            result.status_code, 0,
            "bounded disposable recovery command refused"
        );
        result.stdout
    };
    let first = client.execute("alice", &sign()).unwrap().unwrap();
    assert!(!first.content.is_empty());
    execute_command(
        "/usr/local/bin/gpgconf",
        &[
            "--homedir".into(),
            alice.to_str().unwrap().into(),
            "--kill".into(),
            "gpg-agent".into(),
        ],
    );
    let agent = alice.join("S.gpg-agent");
    let absent_until = Instant::now() + Duration::from_secs(5);
    while fs::symlink_metadata(&agent).is_ok() && Instant::now() < absent_until {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        fs::symlink_metadata(&agent).is_err(),
        "disposable agent endpoint did not close"
    );
    {
        let stale = UnixListener::bind(&agent).unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o600)).unwrap();
        drop(stale);
    }
    assert_eq!(
        client.execute("alice", &sign()).unwrap().err(),
        Some(CryptoError::Locked)
    );
    let public = client
        .execute(
            "alice",
            &Operation::Encrypt {
                recipient_fingerprints: vec![bob_fp],
                data: data.clone(),
            },
        )
        .unwrap()
        .unwrap();
    assert!(!public.content.is_empty());
    const RECOVER: &str = "import importlib.util,pathlib,sys\np=pathlib.Path(sys.argv[1]);h=pathlib.Path(sys.argv[2])\ns=importlib.util.spec_from_file_location('_osmap_disposable_recovery',p)\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.restart_bounded_agent(h,{'PATH':'/usr/local/bin:/usr/bin:/bin','LC_ALL':'C'},None)\n";
    execute_command(
        "/usr/local/bin/python3",
        &[
            "-I".into(),
            "-B".into(),
            "-c".into(),
            RECOVER.into(),
            pinned_source.to_str().unwrap().into(),
            alice.to_str().unwrap().into(),
        ],
    );
    let agent_info = execute_command(
        "/usr/local/bin/gpg-connect-agent",
        &[
            "--homedir".into(),
            alice.to_str().unwrap().into(),
            "--no-autostart".into(),
            "GETINFO pid".into(),
            "/bye".into(),
        ],
    );
    let mut pid_rows = agent_info
        .lines()
        .filter_map(|line| line.strip_prefix("D "));
    let pid_text = pid_rows.next().expect("disposable agent PID witness");
    assert!(
        pid_rows.next().is_none()
            && pid_text.len() <= 10
            && pid_text.bytes().all(|byte| byte.is_ascii_digit())
    );
    let pid: u32 = pid_text.parse().unwrap();
    assert!(pid > 1 && pid <= i32::MAX as u32);
    let agent_command = execute_command(
        "/bin/ps",
        &[
            "-ww".into(),
            "-p".into(),
            pid.to_string(),
            "-o".into(),
            "args=".into(),
        ],
    );
    let arguments: Vec<&str> = agent_command.split_whitespace().collect();
    for option in ["--default-cache-ttl", "--max-cache-ttl"] {
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| **argument == option)
                .count(),
            1
        );
        let position = arguments
            .iter()
            .position(|argument| *argument == option)
            .unwrap();
        assert_eq!(arguments.get(position + 1), Some(&"28800"));
    }
    assert!(arguments.contains(&"--no-allow-external-cache"));
    let pinentry = arguments
        .iter()
        .position(|argument| *argument == "--pinentry-program")
        .unwrap();
    assert_eq!(
        arguments.get(pinentry + 1),
        Some(&"/usr/local/bin/pinentry-tty")
    );
    assert!(agent_command.contains(alice.to_str().unwrap()));
    let recovered = client.execute("alice", &sign()).unwrap().unwrap();
    let verified = client
        .execute(
            "alice",
            &Operation::Verify {
                data,
                signature: recovered.content,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(verified.primary_fingerprint, Some(alice_fp));
    assert!(server.join().unwrap().is_ok());
    println!("same_service_initial_sign=PASS stale_private_agent_locked=PASS stale_public_encrypt=PASS actual_agent_eight_hour_cache_flags=PASS bounded_recovery_fresh_sign_verify=PASS");
}
