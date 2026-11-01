use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
const EMPTY: &[u8] = br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]}"#;
#[test]
#[ignore = "requires isolated OpenBSD helper/web service principals"]
fn native_inventory_principal_client() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let setting = |name| std::env::var(name).expect("native principal fixture setting");
    let socket = PathBuf::from(setting("OSMAP_CRYPTO_PRINCIPAL_INVENTORY_SOCKET"));
    let key = PathBuf::from(setting("OSMAP_CRYPTO_PRINCIPAL_KEY"));
    let uid = setting("OSMAP_CRYPTO_PRINCIPAL_HELPER_UID")
        .parse()
        .unwrap();
    let client = Client::from_operator_files(&socket, &key, uid).unwrap();
    if setting("OSMAP_CRYPTO_PRINCIPAL_MODE") == "peer_denied" {
        assert!(client.read("alice").is_err());
        return;
    }
    let inventory = client.read("alice").unwrap();
    let expected = [
        setting("OSMAP_CRYPTO_PRINCIPAL_ALICE_FP"),
        setting("OSMAP_CRYPTO_PRINCIPAL_BOB_FP"),
    ];
    let keys = inventory.keys().expect("available authenticated inventory");
    assert_eq!(keys.len(), 2);
    for key in keys {
        assert!(expected.contains(&key.primary.fingerprint));
        assert_eq!(key.primary.curve.as_deref(), Some("ed25519"));
        assert_eq!(key.subkeys.len(), 1);
        assert_eq!(key.subkeys[0].curve.as_deref(), Some("cv25519"));
    }
    assert!(Client::from_operator_files(&socket, &key, uid.saturating_add(1)).is_err());
    assert!(client.read("unmapped").is_err());
}
fn service() -> Service {
    Service {
        config: Config {
            version: 1,
            worker: "/unused-worker".into(),
            engine: ENGINE.into(),
            socket: "/unused-socket".into(),
            trusted_web_uid: crate::openbsd::effective_uid(),
            accounts: vec![
                Mapping {
                    account: "alice".into(),
                    home: "/alice-public".into(),
                },
                Mapping {
                    account: "bob".into(),
                    home: "/bob-public".into(),
                },
            ],
        },
        key: vec![42; 32],
        verifier: Mutex::new(Verifier::default()),
        admissions: Admissions::default(),
    }
}
#[test]
fn signed_mapping_replay_expiry_and_missing_account_never_fall_back() {
    let s = service();
    let count = AtomicUsize::new(0);
    let request = Request::issue("alice", now().unwrap(), &s.key).unwrap();
    let response = s
        .process(
            &request.to_bytes().unwrap(),
            Instant::now() + Duration::from_secs(1),
            |worker, home, _| {
                assert_eq!(worker, Path::new("/unused-worker"));
                assert_eq!(home, Path::new("/alice-public"));
                count.fetch_add(1, Ordering::SeqCst);
                Inventory::parse(EMPTY)
            },
        )
        .unwrap();
    assert_eq!(
        Verifier::default()
            .response(&request, &response, &s.key, now().unwrap())
            .unwrap()
            .keys()
            .unwrap()
            .len(),
        0
    );
    assert!(matches!(
        s.process(
            &request.to_bytes().unwrap(),
            Instant::now() + Duration::from_secs(1),
            |_, _, _| panic!("replay dispatched")
        ),
        Err(Error::Replay)
    ));
    for req in [
        Request::issue("unknown", now().unwrap(), &s.key).unwrap(),
        Request::issue("alice", now().unwrap() - 11, &s.key).unwrap(),
        Request::issue("bob", now().unwrap(), &[1; 32]).unwrap(),
    ] {
        assert!(s
            .process(
                &req.to_bytes().unwrap(),
                Instant::now() + Duration::from_secs(1),
                |_, _, _| panic!("refused request dispatched")
            )
            .is_err());
    }
    let request = Request::issue("bob", now().unwrap(), &s.key).unwrap();
    s.process(
        &request.to_bytes().unwrap(),
        Instant::now() + Duration::from_secs(1),
        |_, home, _| {
            assert_eq!(home, Path::new("/bob-public"));
            Inventory::parse(EMPTY)
        },
    )
    .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
#[test]
fn actual_competing_admissions_refuse_same_account_and_third_global() {
    let s = Arc::new(service());
    let (tx, rx) = std::sync::mpsc::channel();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for account in ["alice", "bob"] {
        let s = s.clone();
        let tx = tx.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let _p = s.admissions.enter(account).unwrap();
            tx.send(()).unwrap();
            barrier.wait();
        }));
    }
    rx.recv_timeout(Duration::from_secs(1)).unwrap();
    rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(matches!(s.admissions.enter("alice"), Err(Error::Capacity)));
    assert!(matches!(
        s.admissions.enter("charlie"),
        Err(Error::Capacity)
    ));
    barrier.wait();
    for t in threads {
        t.join().unwrap();
    }
    assert!(s.admissions.enter("alice").is_ok());
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut b = [0; 8];
        getrandom::getrandom(&mut b).unwrap();
        // The shared gate TMPDIR may intentionally be writable by other users.
        // These tests require the same protected ancestry as production files;
        // make an owned child of the system sticky-root temporary directory.
        let p = fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-public-runtime-{}-{}",
            std::process::id(),
            u64::from_le_bytes(b)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn write(&self, name: &str, b: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, b).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        p
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn socket_client_has_signed_roundtrip_peer_checks_bounded_frames_and_redacted_debug() {
    let scratch = Scratch::new();
    let socket = scratch.0.join("inventory.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let key = scratch.write("key", &[42; 32]);
    let c = Client::from_operator_files(&socket, &key, crate::openbsd::effective_uid()).unwrap();
    assert_eq!(c, c.clone());
    assert!(!format!("{c:?}").contains("42, 42"));
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let d = Instant::now() + Duration::from_secs(1);
        let bytes = read_frame(&mut stream, 2048, d).unwrap();
        let req = Verifier::default()
            .request(&bytes, "alice", &[42; 32], now().unwrap())
            .unwrap();
        write_frame(
            &mut stream,
            &req.response(&Inventory::parse(EMPTY).unwrap(), &[42; 32], now().unwrap())
                .unwrap(),
            d,
        )
        .unwrap();
    });
    assert!(c.read("alice").unwrap().keys().unwrap().is_empty());
    server.join().unwrap();
    assert!(Client::from_operator_files(
        &socket,
        &key,
        crate::openbsd::effective_uid().wrapping_add(1)
    )
    .is_err());
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(&2049u32.to_be_bytes()).unwrap();
    assert!(matches!(
        read_frame(&mut b, 2048, Instant::now() + Duration::from_secs(1)),
        Err(Error::Limit)
    ));
    let (_a, mut b) = UnixStream::pair().unwrap();
    let start = Instant::now();
    assert!(read_frame(&mut b, 2048, start + Duration::from_millis(50)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}
#[test]
fn config_paths_secrets_and_disabled_activation_are_fail_closed() {
    let scratch = Scratch::new();
    let key = scratch.write("key", &[42; 32]);
    assert_eq!(secret(&key).unwrap().len(), 32);
    let link = scratch.0.join("link");
    std::os::unix::fs::symlink(&key, &link).unwrap();
    assert!(secret(&link).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(secret(&key).is_err());
    assert!(Config::load(&scratch.write("bad", br#"{"version":1,"version":1}"#)).is_err());
    assert!(Config::load(&scratch.write("unknown", br#"{"version":1,"unknown":true}"#)).is_err());
    assert!(service().serve().is_err());
}

#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "private native fixture only; explicit fixture directory required"]
fn native_signed_service_client_and_confined_worker() {
    let root = PathBuf::from(
        std::env::var_os("OSMAP_PUBLIC_INVENTORY_FIXTURE").expect("explicit fixture"),
    );
    let s = Service::from_operator_files(&root.join("config.json"), &root.join("key")).unwrap();
    let listener = UnixListener::bind(&s.config.socket).unwrap();
    fs::set_permissions(&s.config.socket, fs::Permissions::from_mode(0o600)).unwrap();
    let socket = s.config.socket.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..5 {
            let (stream, _) = listener.accept().unwrap();
            let _ = s.connection(stream);
        }
    });
    let c =
        Client::from_operator_files(&socket, &root.join("key"), crate::openbsd::effective_uid())
            .unwrap();
    for account in ["alice", "bob"] {
        let inventory = c.read(account).unwrap();
        let keys = inventory.keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].primary.fingerprint,
            fs::read_to_string(root.join(format!("{account}.fingerprint")))
                .unwrap()
                .trim()
        );
    }
    assert!(c.read("empty").unwrap().keys().unwrap().is_empty());
    assert!(c.read("unknown").is_err());
    let foreign = Client::from_operator_files(
        &socket,
        &root.join("foreign-key"),
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    assert!(foreign.read("alice").is_err());
    server.join().unwrap();
    fs::remove_file(socket).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("config.json")).unwrap()).unwrap();
    value["accounts"][0]["home"] = root.join("missing").to_string_lossy().to_string().into();
    let bad = root.join("missing.json");
    fs::write(&bad, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Service::from_operator_files(&bad, &root.join("key")).is_err());
    fs::remove_file(bad).unwrap();
}

#[test]
fn writable_ancestor_cannot_replace_valid_private_file() {
    let scratch = Scratch::new();
    let parent = scratch.0.join("replaceable");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    let private = parent.join("key");
    fs::write(&private, [7; 32]).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(secret(&private).is_err());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(secret(&private).is_ok());
    assert!(crate::openbsd::disable_core_dumps().is_ok());
}

// Isolated service child: real signed inventory admission and owned process
// fixture only. This does not substitute fixture output for native GPG proof.
pub(crate) fn serve_hold_child() {
    let root = PathBuf::from(std::env::var_os("OSMAP_INVENTORY_SERVICE_FIXTURE_ROOT").unwrap());
    assert!(
        root.starts_with("/tmp")
            && root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("osmap-public-runtime-")
    );
    assert_eq!(root.canonicalize().unwrap(), root);
    assert!(private_dir(&root, crate::openbsd::effective_uid(), false).is_ok());
    crate::openbsd::restore_crypto_termination_signal().unwrap();
    let mut instance = service();
    instance.config.socket = root.join("inventory.sock");
    instance.config.accounts[0].home = root.clone();
    let listener = UnixListener::bind(&instance.config.socket).unwrap();
    fs::set_permissions(&instance.config.socket, fs::Permissions::from_mode(0o600)).unwrap();
    instance
        .serve_loop(listener, |_, home, deadline| {
            match crate::openpgp_crypto_process::run_cancellable_fixture(
                "cancellable_hold_short",
                b"",
                deadline,
                || Ok(false),
                Some(&home.join("worker.ready")),
            ) {
                Ok(_) => Inventory::parse(EMPTY),
                Err(crate::openpgp_crypto::Error::Expired) => Err(Error::Expired),
                Err(crate::openpgp_crypto::Error::Limit) => Err(Error::Limit),
                Err(_) => Err(Error::Unavailable),
            }
        })
        .unwrap();
}
fn inventory_worker_pid(path: &Path) -> Option<u32> {
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

#[test]
fn stopped_inventory_connection_refuses_before_frame_or_worker_admission() {
    let instance = service();
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(&0u32.to_be_bytes()).unwrap();
    assert!(matches!(
        instance.connection_with_executor(
            server,
            &std::sync::atomic::AtomicBool::new(true),
            |_, _, _| panic!("stopped inventory service dispatched a worker"),
        ),
        Err(Error::Unavailable)
    ));
    assert!(instance.admissions.enter("alice").is_ok());
}

#[test]
fn live_inventory_connection_preserves_authenticated_response() {
    let instance = service();
    let (mut client, server) = UnixStream::pair().unwrap();
    let thread = std::thread::spawn(move || {
        instance.connection_with_executor(
            server,
            &std::sync::atomic::AtomicBool::new(false),
            |_, _, _| Inventory::parse(EMPTY),
        )
    });
    let request = Request::issue("alice", now().unwrap(), &[42; 32]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    write_frame(&mut client, &request.to_bytes().unwrap(), deadline).unwrap();
    let response = read_frame(&mut client, FRAME_LIMIT, deadline).unwrap();
    assert!(Verifier::default()
        .response(&request, &response, &[42; 32], now().unwrap())
        .unwrap()
        .keys()
        .unwrap()
        .is_empty());
    assert!(thread.join().unwrap().is_ok());
}

#[test]
fn helper_sigterm_joins_active_inventory_worker_before_helper_exit() {
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    let root = Scratch::new();
    let mut command = crate::auth::inventory_fixture_command("runtime_service_hold");
    command
        .env("OSMAP_INVENTORY_SERVICE_FIXTURE_ROOT", &root.0)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let connect_until = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match UnixStream::connect(root.0.join("inventory.sock")) {
            Ok(client) => break Some(client),
            Err(_) if Instant::now() < connect_until => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(_) => break None,
        }
    };
    let request = Request::issue("alice", now().unwrap(), &[42; 32]).unwrap();
    let wrote = client.as_mut().is_some_and(|client| {
        write_frame(
            client,
            &request.to_bytes().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .is_ok()
    });
    let pid = if wrote {
        inventory_worker_pid(&root.0.join("worker.ready"))
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
