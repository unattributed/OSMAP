use super::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
fn service(uid: u32) -> Service {
    Service {
        active: Mutex::new(BTreeSet::new()),
        cleanup_unconfirmed: std::sync::atomic::AtomicBool::new(false),
        config: Config {
            version: 1,
            socket: "/tmp/unused".into(),
            trusted_web_uid: uid,
            accounts: vec!["alice@example.test".into()],
        },
        key: vec![29; 32],
        verifier: Mutex::new(Verifier::default()),
        engine: None,
    }
}
#[test]
fn unqualified_production_never_constructs_or_dispatches() {
    const {
        assert!(!NATIVE_CONFINEMENT_QUALIFIED);
    }
    assert!(Client::from_operator_files(
        Path::new("/tmp/nonexistent"),
        Path::new("/tmp/nonexistent"),
        0
    )
    .is_err());
    assert!(Service::from_operator_files(
        Path::new("/tmp/nonexistent"),
        Path::new("/tmp/nonexistent")
    )
    .is_err());
    let (stream, _) = UnixStream::pair().unwrap();
    assert_eq!(
        service(crate::openbsd::effective_uid()).connection(stream),
        Err(Error::Unavailable)
    );
    let mut unqualified = service(crate::openbsd::effective_uid());
    let path = std::env::temp_dir().join(format!(
        "osmap-unqualified-admission-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    unqualified.config.socket = path.clone();
    assert_eq!(
        unqualified.serve(&AtomicBool::new(false)),
        Err(Error::Unavailable)
    );
    assert!(fs::symlink_metadata(path).is_err());
}

fn listener_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "adm-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn parent_policy_is_narrow_and_failed_seal_prevents_accept_then_removes_owned_endpoint() {
    let root = listener_root();
    let socket = root.join("admission.sock");
    let plan = crate::openbsd::account_admission_parent_plan(&socket).unwrap();
    let rows: std::collections::BTreeMap<_, _> = plan
        .unveil_rules
        .iter()
        .map(|r| (r.path.as_path(), r.permissions.as_str()))
        .collect();
    assert_eq!(rows.get(socket.as_path()), Some(&"rwc"));
    assert_eq!(rows.get(root.as_path()), Some(&"r"));
    assert_eq!(rows.get(Path::new("/usr/local/bin/python3")), Some(&"rx"));
    assert_eq!(
        rows.get(Path::new("/usr/local/bin/python3.13")),
        Some(&"rx")
    );
    for ancestor in ["/", "/usr", "/usr/local", "/usr/local/bin"] {
        assert_eq!(rows.get(Path::new(ancestor)), Some(&""));
    }
    assert_eq!(
        plan.promises_after_lock,
        "stdio rpath wpath cpath unix proc exec"
    );
    assert_eq!(
        plan.promises_before_lock,
        "stdio rpath wpath cpath unix proc exec unveil"
    );
    assert!(!rows
        .keys()
        .any(|p| p.starts_with("/etc/osmap") || p.starts_with(EPOCH_ROOT)));
    let calls = AtomicUsize::new(0);
    let policy_calls = AtomicUsize::new(0);
    let mut s = service(crate::openbsd::effective_uid());
    s.config.socket = socket.clone();
    let result = s.serve_with_policy(
        &AtomicBool::new(false),
        &|_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        },
        &|endpoint| {
            policy_calls.fetch_add(1, Ordering::SeqCst);
            endpoint.recheck()?;
            assert_eq!(fs::symlink_metadata(&socket).unwrap().mode() & 0o777, 0o660);
            // A queued connection cannot reach peer/frame processing after refusal.
            let _queued = UnixStream::connect(&socket).unwrap();
            Err(Error::Unavailable)
        },
    );
    assert_eq!(result, Err(Error::Unavailable));
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(fs::symlink_metadata(&socket).is_err());
    fs::remove_dir(root).unwrap();
}

#[test]
fn inherited_worker_cwd_refuses_changed_root_in_disposable_process() {
    const CHILD: &str = "OSMAP_TEST_ADMISSION_ROOT_CWD_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        assert_eq!(
            crate::auth::account_admission_inherited_root_command()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::env::set_current_dir("/").unwrap();
        let inherited = crate::auth::account_admission_inherited_root_command().unwrap();
        let ordinary = crate::auth::account_admission_command();
        assert_eq!(inherited.get_program(), ordinary.get_program());
        assert_eq!(
            inherited.get_args().collect::<Vec<_>>(),
            ordinary.get_args().collect::<Vec<_>>()
        );
        assert_eq!(
            inherited.get_envs().collect::<Vec<_>>(),
            ordinary.get_envs().collect::<Vec<_>>()
        );
        assert_eq!(ordinary.get_current_dir(), Some(Path::new("/")));
        assert_eq!(inherited.get_current_dir(), None);
        return;
    }
    let output = crate::openpgp_crypto_process::run_account_admission(
        crate::auth::admission_root_cwd_fixture_command().unwrap(),
        b"",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output).contains("1 passed"));
}

// Existing libtest/subprocess qualification lane; never enables the production
// gate, consumes credentials or authenticates. Root executes this once against
// the exact reviewed native build and installed interpreter custody.
#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "requires root-owned disposable OpenBSD parent confinement qualification"]
fn native_parent_confinement_preserves_metadata_spawn_and_owned_unlink() {
    const CHILD: &str = "OSMAP_TEST_ADMISSION_PARENT_NATIVE_CHILD";
    const OUTSIDE: &str = "OSMAP_TEST_ADMISSION_PARENT_NATIVE_OUTSIDE";
    const MARKER: &str = "admission_parent_metadata_spawn_denial_unlink=PASS";
    assert_eq!(crate::openbsd::effective_uid(), 0);
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let outside = PathBuf::from(std::env::var_os(OUTSIDE).unwrap());
        assert!(root.is_absolute() && outside.is_absolute() && root != outside);
        private_dir(&root, 0, false).unwrap();
        private_dir(&outside, 0, false).unwrap();
        crate::openbsd::disable_core_dumps().unwrap();
        std::env::set_current_dir("/").unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let engine = InstalledEngine::observe(Path::new(ENGINE), 0, deadline).unwrap();
        let mut endpoint = AdmissionEndpoint::bind(&root.join("admission.sock")).unwrap();
        crate::openbsd::apply_account_admission_parent_confinement(&endpoint.path).unwrap();
        endpoint.recheck().unwrap();
        engine.recheck(deadline).unwrap();
        // Only harmless fixture bytes are used for outside-access negatives.
        assert!(fs::read(outside.join("public-fixture")).is_err());
        assert!(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(outside.join("forbidden-create"))
            .is_err());
        let fixed = crate::auth::account_admission_inherited_root_command().unwrap();
        assert_eq!(fixed.get_current_dir(), None);
        // Interpreter-only public control. It deliberately does not invoke the
        // installed private worker or pretend its module closure is qualified.
        let command = crate::auth::admission_parent_interpreter_fixture_command().unwrap();
        let output =
            crate::openpgp_crypto_process::run_account_admission(command, b"", deadline).unwrap();
        assert_eq!(output, b"inherited_root_exec=PASS\n");
        endpoint.remove().unwrap();
        assert!(fs::symlink_metadata(root.join("admission.sock")).is_err());
        println!("{MARKER}");
        return;
    }
    let root = listener_root();
    let outside = listener_root();
    let root_identity = AdmissionEndpoint::identity(&fs::symlink_metadata(&root).unwrap());
    let outside_identity = AdmissionEndpoint::identity(&fs::symlink_metadata(&outside).unwrap());
    fs::write(outside.join("public-fixture"), b"harmless public fixture\n").unwrap();
    let command = crate::auth::admission_parent_native_fixture_command(&root, &outside).unwrap();
    // Existing strict owned-group cleanup is mandatory; on any uncertainty,
    // leave both exact leases retained instead of recursively deleting them.
    let output = crate::openpgp_crypto_process::run_account_admission(
        command,
        b"",
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output).contains(MARKER));
    assert_eq!(
        AdmissionEndpoint::identity(&fs::symlink_metadata(&root).unwrap()),
        root_identity
    );
    assert_eq!(
        AdmissionEndpoint::identity(&fs::symlink_metadata(&outside).unwrap()),
        outside_identity
    );
    assert!(!outside.join("forbidden-create").exists());
    assert_eq!(
        fs::read(outside.join("public-fixture")).unwrap(),
        b"harmless public fixture\n"
    );
    fs::remove_file(outside.join("public-fixture")).unwrap();
    fs::remove_dir(outside).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn fixed_python_alias_admits_only_exact_target_and_refuses_target_replacement() {
    let root = listener_root();
    let alias = root.join("python3");
    let target = root.join("python3.13");
    let owner = crate::openbsd::effective_uid();
    fs::write(&target, b"synthetic executable custody bytes\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink("python3.13", &alias).unwrap();
    // Historical ordinary-file guard refuses this legitimate fixed alias.
    assert!(file(&alias, owner, true, 64 * 1024 * 1024).is_err());
    let deadline = Instant::now() + Duration::from_secs(2);
    let first = InstalledEngine::observe(&alias, owner, deadline).unwrap();
    assert_eq!(first.recheck(deadline), Ok(()));
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink("python3.12", &alias).unwrap();
    assert!(InstalledEngine::observe(&alias, owner, deadline).is_err());
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink("python3.13", &alias).unwrap();
    let current = InstalledEngine::observe(&alias, owner, deadline).unwrap();
    let replacement = root.join("replacement");
    fs::write(&replacement, b"synthetic executable custody bytes\n").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&replacement, &target).unwrap();
    assert_eq!(current.recheck(deadline), Err(Error::Unavailable));
    let parent_alias = root.join("alias-parent");
    std::os::unix::fs::symlink(&root, &parent_alias).unwrap();
    assert!(InstalledEngine::observe(&parent_alias.join("python3"), owner, deadline).is_err());
    fs::remove_file(parent_alias).unwrap();
    fs::remove_file(alias).unwrap();
    fs::remove_file(target).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn expanded_worker_custody_refuses_missing_or_writable_private_primary_module() {
    let root = listener_root();
    let owner = crate::openbsd::effective_uid();
    for name in WORKER_MODULES {
        let path = root.join(name);
        fs::write(&path, b"# synthetic module custody fixture\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(worker_module_custody(&root, owner), Ok(()));
    let primary = root.join("mutation_primary.py");
    fs::remove_file(&primary).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Err(Error::Unavailable));
    fs::write(&primary, b"# synthetic replacement\n").unwrap();
    fs::set_permissions(&primary, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Err(Error::Unavailable));
    fs::set_permissions(&primary, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Ok(()));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Err(Error::Unavailable));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in WORKER_MODULES {
        fs::remove_file(root.join(name)).unwrap();
    }
    fs::remove_dir(root).unwrap();
}
#[test]
fn expired_original_connection_refuses_before_worker_dispatch() {
    let request = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        now().unwrap(),
        &[17; 32],
    )
    .unwrap();
    assert_eq!(
        Service::fixed_worker(&request, Instant::now()),
        Err(Error::Expired)
    );
}
fn wait_listener(path: &Path) {
    assert!(path.as_os_str().len() <= 100);
    let end = Instant::now() + Duration::from_secs(2);
    while !path.exists() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn listener_shutdown_retains_late_worker_cleanup_uncertainty() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let mut s = service(crate::openbsd::effective_uid());
    s.config.socket = path.clone();
    let stop = AtomicBool::new(false);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let execute = |_: &Request, _: Instant| {
        entered.wait();
        release.wait();
        Err(Error::CleanupUnconfirmed)
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| s.serve_with(&stop, &execute));
        wait_listener(&path);
        let request = Request::issue(
            "alice@example.test",
            Operation::Admit { epoch: 0 },
            now().unwrap(),
            &s.key,
        )
        .unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        write_frame(&mut stream, &request.bytes().unwrap(), deadline).unwrap();
        entered.wait();
        stop.store(true, Ordering::SeqCst);
        release.wait();
        assert!(read_frame(&mut stream, MAX_FRAME, deadline).is_err());
        assert_eq!(server.join().unwrap(), Err(Error::CleanupUnconfirmed));
    });
    assert!(s.cleanup_unconfirmed.load(Ordering::SeqCst));
    assert!(!path.exists());
    fs::remove_dir(root).unwrap();
}
#[test]
fn persistent_listener_keeps_replay_state_and_finishes_dispatched_work_before_stop() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let mut s = service(crate::openbsd::effective_uid());
    s.config.socket = path.clone();
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let execute = |_: &Request, deadline: Instant| {
        let index = calls.fetch_add(1, Ordering::SeqCst);
        assert!(deadline > Instant::now());
        assert!(deadline.duration_since(Instant::now()) <= Duration::from_secs(30));
        if index == 1 {
            entered.wait();
            release.wait();
        }
        Ok(Some(3))
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| s.serve_with(&stop, &execute));
        wait_listener(&path);
        let at = now().unwrap();
        let first = Request::issue(
            "alice@example.test",
            Operation::Admit { epoch: 3 },
            at,
            &s.key,
        )
        .unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        write_frame(&mut stream, &first.bytes().unwrap(), deadline).unwrap();
        let reply = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        assert_eq!(
            Verifier::default()
                .response(&first, &reply, &s.key, now().unwrap())
                .unwrap()
                .unwrap()
                .epoch,
            3
        );
        drop(stream);
        // A separately accepted connection still uses the same verifier.
        let mut replay = UnixStream::connect(&path).unwrap();
        write_frame(&mut replay, &first.bytes().unwrap(), deadline).unwrap();
        assert!(read_frame(&mut replay, MAX_FRAME, deadline).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(replay);
        let second = Request::issue(
            "alice@example.test",
            Operation::Admit { epoch: 3 },
            now().unwrap(),
            &s.key,
        )
        .unwrap();
        let mut admitted = UnixStream::connect(&path).unwrap();
        write_frame(&mut admitted, &second.bytes().unwrap(), deadline).unwrap();
        entered.wait();
        stop.store(true, Ordering::SeqCst);
        release.wait();
        let reply = read_frame(&mut admitted, MAX_FRAME, deadline).unwrap();
        assert!(Verifier::default()
            .response(&second, &reply, &s.key, now().unwrap())
            .unwrap()
            .is_some());
        assert_eq!(server.join().unwrap(), Ok(()));
    });
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!path.exists());
    fs::remove_dir(root).unwrap();
}

#[test]
fn listener_rejects_wrong_peer_before_read_and_refuses_foreign_socket_cleanup() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let mut s = service(crate::openbsd::effective_uid().wrapping_add(1));
    s.config.socket = path.clone();
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let execute = |_: &Request, _: Instant| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(0))
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| s.serve_with(&stop, &execute));
        wait_listener(&path);
        let mut peer = UnixStream::connect(&path).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
        stop.store(true, Ordering::SeqCst);
        assert_eq!(server.join().unwrap(), Ok(()));
    });
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!path.exists());
    let mut owned = AdmissionEndpoint::bind(&path).unwrap();
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o660);
    assert!(AdmissionEndpoint::bind(&path).is_err());
    fs::remove_file(&path).unwrap();
    let foreign = UnixListener::bind(&path).unwrap();
    let identity = AdmissionEndpoint::identity(&fs::symlink_metadata(&path).unwrap());
    assert_eq!(owned.remove(), Err(Error::Unavailable));
    drop(owned);
    assert_eq!(
        AdmissionEndpoint::identity(&fs::symlink_metadata(&path).unwrap()),
        identity
    );
    drop(foreign);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn wrong_peer_foreign_account_and_replay_never_dispatch_worker() {
    let (mut stream, _) = UnixStream::pair().unwrap();
    let calls = AtomicUsize::new(0);
    let uid = crate::openbsd::effective_uid();
    assert_eq!(
        service(uid.wrapping_add(1)).connection_with(&mut stream, |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(1))
        }),
        Err(Error::Authentication)
    );
    let s = service(uid);
    let at = now().unwrap();
    let foreign = Request::issue(
        "bob@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert_eq!(
        s.process(&foreign.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .unwrap_err(),
        Error::Refused
    );
    let own = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert!(s
        .process(&own.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .is_ok());
    assert_eq!(
        s.process(&own.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .unwrap_err(),
        Error::Replay
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[test]
fn actual_private_socket_authentication_and_epoch_binding_without_native_credentials() {
    let uid = crate::openbsd::effective_uid();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-account-admission-{}-{}",
        std::process::id(),
        now().unwrap()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("account.sock");
    let key = root.join("grant.key");
    std::fs::write(&key, vec![29; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    let worker = std::thread::spawn(move || {
        let s = service(uid);
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            s.connection_with(&mut stream, |r, _| {
                match r.operation() {
                    Operation::Authenticate { password } => {
                        assert_eq!(password, "synthetic credential")
                    }
                    Operation::Admit { epoch } => assert_eq!(*epoch, 7),
                };
                Ok(Some(7))
            })
            .unwrap();
        }
    });
    let client = Client::qualified_files(&socket, &key, uid).unwrap();
    let a = client
        .authenticate("alice@example.test", "synthetic credential")
        .unwrap()
        .unwrap();
    assert_eq!(
        a,
        Admission {
            account: "alice@example.test".into(),
            epoch: 7
        }
    );
    client.admit(&a.account, a.epoch).unwrap();
    worker.join().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn actual_runtime_login_mfa_session_and_changed_epoch_refusal_no_primary_fallback() {
    use crate::http::{
        BrowserGateway, BrowserLoginDecision, BrowserSessionDecision, RuntimeBrowserGateway,
    };
    use crate::totp::{FileTotpSecretStore, SystemTimeProvider, TimeProvider};
    use hmac::{Hmac, Mac};
    // Public RFC6238 test vector only, never an operator factor or credential.
    let public_vector = b"12345678901234567890";
    for changed_during_mfa in [false, true] {
        let uid = crate::openbsd::effective_uid();
        let root = PathBuf::from("/tmp").join(format!(
            "osmap-account-gateway-{}-{}",
            std::process::id(),
            changed_during_mfa
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("account.sock");
        let key = root.join("grant.key");
        std::fs::write(&key, vec![29; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let epoch = Arc::new(AtomicUsize::new(7));
        let server_epoch = epoch.clone();
        let worker = std::thread::spawn(move || {
            let s = service(uid);
            for _ in 0..if changed_during_mfa { 2 } else { 4 } {
                let (mut stream, _) = listener.accept().unwrap();
                s.connection_with(&mut stream, |request, _| match request.operation() {
                    Operation::Authenticate { password } => {
                        assert_eq!(password, "synthetic primary credential");
                        if changed_during_mfa {
                            server_epoch.store(8, Ordering::SeqCst);
                        }
                        Ok(Some(7))
                    }
                    Operation::Admit { epoch } => {
                        assert_eq!(*epoch, 7, "issuance must not retarget to changed epoch");
                        Ok((server_epoch.load(Ordering::SeqCst) == 7).then_some(7))
                    }
                })
                .unwrap();
            }
        });
        let mutation_socket = root.join("mutation.sock");
        let mutation_key = root.join("mutation.key");
        let proof_key = root.join("session-proof.key");
        let _mutation_listener = UnixListener::bind(&mutation_socket).unwrap();
        std::fs::set_permissions(&mutation_socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        for (path, bytes) in [(&mutation_key, [17_u8; 32]), (&proof_key, [19_u8; 32])] {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let gateway = RuntimeBrowserGateway::for_test(&root).with_account_fixture_clients(
            Client::qualified_files(&socket, &key, uid).unwrap(),
            crate::account_mutation_client::Client::stored_fixture_files(
                &mutation_socket,
                &mutation_key,
                &proof_key,
                uid,
            )
            .unwrap(),
        );
        // for_test has a nonexistent primary backend, so any accidental fallback fails.
        let totp_root = root.join("totp");
        std::fs::create_dir(&totp_root).unwrap();
        std::fs::set_permissions(&totp_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let factor =
            FileTotpSecretStore::new(&totp_root).secret_path_for_username("alice@example.test");
        std::fs::write(&factor, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        std::fs::set_permissions(&factor, std::fs::Permissions::from_mode(0o600)).unwrap();
        let counter = SystemTimeProvider.unix_timestamp() / 30;
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(public_vector).unwrap();
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 15);
        let number =
            u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let code = format!("{:06}", number % 1_000_000);
        let context = crate::auth::AuthenticationContext {
            request_id: "synthetic".into(),
            remote_addr: "127.0.0.1".into(),
            user_agent: "synthetic".into(),
        };
        let result = gateway.login(
            &context,
            "alice@example.test",
            "synthetic primary credential",
            &code,
        );
        if changed_during_mfa {
            assert!(matches!(
                result.decision,
                BrowserLoginDecision::Denied { .. }
            ));
            assert!(std::fs::read_dir(root.join("sessions")).unwrap().all(|e| e
                .unwrap()
                .path()
                .extension()
                .is_none_or(|v| v != "session")));
        } else {
            let BrowserLoginDecision::Authenticated { session_token, .. } = result.decision else {
                panic!("synthetic account helper login refused");
            };
            let valid = gateway.validate_session(&context, session_token.as_str());
            let BrowserSessionDecision::Valid { validated_session } = valid.decision else {
                panic!("bound session refused");
            };
            assert_eq!(validated_session.record.account_epoch, Some(7));
            epoch.store(8, Ordering::SeqCst);
            assert!(matches!(
                gateway
                    .validate_session(&context, session_token.as_str())
                    .decision,
                BrowserSessionDecision::Invalid
            ));
        }
        worker.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unconfirmed_native_cleanup_stops_subsequent_worker_admission() {
    let s = service(crate::openbsd::effective_uid());
    let at = now().unwrap();
    let calls = AtomicUsize::new(0);
    let first = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert_eq!(
        s.process(&first.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::CleanupUnconfirmed)
        })
        .unwrap_err(),
        Error::CleanupUnconfirmed
    );
    let second = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert_eq!(
        s.process(&second.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .unwrap_err(),
        Error::CleanupUnconfirmed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn helper_worker_capacity_is_two_and_one_per_account_without_queue() {
    let mut base = service(crate::openbsd::effective_uid());
    base.config
        .accounts
        .extend(["bob@example.test".into(), "carol@example.test".into()]);
    let service = Arc::new(base);
    let first = service.enter("alice@example.test").unwrap();
    assert!(matches!(
        service.enter("alice@example.test"),
        Err(Error::Capacity)
    ));
    drop(first);
    let entered = Arc::new(std::sync::Barrier::new(3));
    let release = Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for account in ["alice@example.test", "bob@example.test"] {
        let service = service.clone();
        let entered = entered.clone();
        let release = release.clone();
        threads.push(std::thread::spawn(move || {
            let at = now().unwrap();
            let request =
                Request::issue(account, Operation::Admit { epoch: 0 }, at, &service.key).unwrap();
            service
                .process(&request.bytes().unwrap(), at, |_| {
                    entered.wait();
                    release.wait();
                    Ok(Some(0))
                })
                .unwrap();
        }));
    }
    entered.wait();
    for account in ["alice@example.test", "carol@example.test"] {
        let at = now().unwrap();
        let request =
            Request::issue(account, Operation::Admit { epoch: 0 }, at, &service.key).unwrap();
        assert_eq!(
            service
                .process(&request.bytes().unwrap(), at, |_| panic!(
                    "capacity refusal must precede worker"
                ))
                .unwrap_err(),
            Error::Capacity
        );
    }
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    let at = now().unwrap();
    let request = Request::issue(
        "carol@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &service.key,
    )
    .unwrap();
    assert!(service
        .process(&request.bytes().unwrap(), at, |_| Ok(Some(0)))
        .is_ok());
}

#[path = "account_admission_deadline_tests.rs"]
mod original_deadline;
