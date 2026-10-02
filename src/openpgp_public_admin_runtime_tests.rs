use super::*;
use crate::openpgp_inventory::Inventory;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
const EMPTY:&[u8]=br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]}"#;
const KEY: &[u8] = &[42; 32];
struct Fixture {
    root: PathBuf,
    config: PathBuf,
    key: PathBuf,
    socket: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-admin-rpc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let home = root.join("home");
        let state = root.join("state");
        for dir in [&home, &state] {
            fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
        }
        fn write(path: &Path, bytes: &[u8], mode: u32) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        write(
            &home.join("pubring.kbx"),
            b"synthetic public fixture",
            0o600,
        );
        write(&home.join("trustdb.gpg"), b"synthetic trust fixture", 0o600);
        let worker = root.join("worker");
        let engine = root.join("engine");
        let script = format!(
            "#!/usr/bin/env python3\nprint({:?})\n",
            std::str::from_utf8(EMPTY).unwrap()
        );
        write(&worker, script.as_bytes(), 0o700);
        write(
            &engine,
            b"#!/usr/bin/env python3\nraise SystemExit(1)\n",
            0o700,
        );
        let config = root.join("config");
        let key = root.join("key");
        let socket = root.join("socket");
        let value = serde_json::json!({"version":1,"worker":worker,"engine":engine,"state_directory":state,"socket":socket,"trusted_web_uid":crate::openbsd::effective_uid(),"accounts":[{"account":"alice","home":home}]});
        write(&config, &serde_json::to_vec(&value).unwrap(), 0o600);
        write(&key, KEY, 0o600);
        Self {
            root,
            config,
            key,
            socket,
        }
    }
    fn service(&self) -> Service {
        Service::from_operator_files(&self.config, &self.key).unwrap()
    }
    fn listener(&self) -> UnixListener {
        let listener = UnixListener::bind(&self.socket).unwrap();
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }
    fn client(&self) -> Client {
        Client::from_operator_files(&self.socket, &self.key, crate::openbsd::effective_uid())
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn snapshot() -> PublicSnapshot {
    PublicSnapshot {
        inventory: Inventory::parse(EMPTY).unwrap(),
        revision: "a".repeat(64),
    }
}
fn request(account: &str, action: Action, time: u64) -> Request {
    Request::issue(
        account,
        action,
        action.mutation().then_some(&"a".repeat(64)),
        action.mutation().then_some(&"A".repeat(40)),
        if action == Action::ImportPublic {
            b"synthetic public certificate"
        } else {
            b""
        },
        time,
        KEY,
    )
    .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
fn authenticated_operations_map_accounts_and_durable_replay_precedes_execution() {
    let f = Fixture::new();
    let service = f.service();
    let count = AtomicUsize::new(0);
    for action in [Action::Snapshot, Action::ImportPublic, Action::RemovePublic] {
        let r = request("alice", action, now().unwrap());
        let reply = service
            .process_with(&r.to_bytes().unwrap(), deadline(), |decoded, _| {
                assert_eq!(decoded.account(), "alice");
                assert_eq!(decoded.action(), action);
                count.fetch_add(1, Ordering::SeqCst);
                Ok(snapshot())
            })
            .unwrap();
        assert!(Verifier::default()
            .response(&r, &reply, KEY, now().unwrap())
            .unwrap()
            .is_ok());
        assert_eq!(
            service
                .process_with(&r.to_bytes().unwrap(), deadline(), |_, _| panic!(
                    "replay must not execute"
                ))
                .err(),
            Some(Error::Replay)
        );
        if action.mutation() {
            let restarted = f.service();
            let reply = restarted
                .process_with(&r.to_bytes().unwrap(), deadline(), |_, _| {
                    panic!("durable replay must not execute")
                })
                .unwrap();
            assert_eq!(
                Verifier::default()
                    .response(&r, &reply, KEY, now().unwrap())
                    .unwrap()
                    .unwrap_err(),
                Error::Replay
            );
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);
    let r = request("bob", Action::ImportPublic, now().unwrap());
    let reply = service
        .process_with(&r.to_bytes().unwrap(), deadline(), |_, _| {
            panic!("foreign account must not execute")
        })
        .unwrap();
    assert_eq!(
        Verifier::default()
            .response(&r, &reply, KEY, now().unwrap())
            .unwrap()
            .unwrap_err(),
        Error::Unavailable
    );
}
#[test]
fn malformed_tampered_expired_and_deadline_requests_never_invoke_native_worker() {
    let f = Fixture::new();
    let s = f.service();
    let r = request("alice", Action::ImportPublic, now().unwrap());
    let mut bytes = r.to_bytes().unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        s.process_with(&bytes, deadline(), |_, _| panic!("tamper must not execute"))
            .err(),
        Some(Error::Authentication)
    );
    let r = request("alice", Action::RemovePublic, now().unwrap() - 11);
    assert_eq!(
        s.process_with(&r.to_bytes().unwrap(), deadline(), |_, _| panic!(
            "expiry must not execute"
        ))
        .err(),
        Some(Error::Expired)
    );
    let r = request("alice", Action::RemovePublic, now().unwrap());
    let reply = s
        .process_with(&r.to_bytes().unwrap(), Instant::now(), |_, _| {
            panic!("deadline must not execute")
        })
        .unwrap();
    assert_eq!(
        Verifier::default()
            .response(&r, &reply, KEY, now().unwrap())
            .unwrap()
            .unwrap_err(),
        Error::Expired
    );
}
#[test]
fn durable_nonce_high_water_refuses_pruned_request_after_clock_rollback_and_restart() {
    // Other parallel tests may fork while this lock is held. CLOEXEC closes
    // their inherited descriptor at exec; assert bounded eventual semantics.
    let consume = |nonces: &Nonces, request: &Request, time| {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let result = nonces.consume(request, time);
            if result != Err(Error::Busy) || Instant::now() >= until {
                break result;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let f = Fixture::new();
    let directory = f.root.join("state/nonces");
    let nonces = Nonces::new(directory.clone());
    let original = request("alice", Action::ImportPublic, 100);
    assert_eq!(consume(&nonces, &original, 99), Err(Error::Expired));
    assert_eq!(consume(&nonces, &original, 110), Err(Error::Expired));
    consume(&nonces, &original, 100).unwrap();
    let next = request("alice", Action::ImportPublic, 111);
    consume(&nonces, &next, 111).unwrap();
    let restarted = Nonces::new(directory);
    assert_eq!(consume(&restarted, &original, 105), Err(Error::Expired));
    // The account high-water is independent; another mapped account has no
    // authority over Alice's journal and cannot consume Alice's nonce.
    let other = request("bob", Action::ImportPublic, 100);
    consume(&restarted, &other, 100).unwrap();
    assert_eq!(consume(&restarted, &original, 105), Err(Error::Expired));
}
#[test]
fn peer_uid_checked_before_input_and_store_execution() {
    let f = Fixture::new();
    let mut s = f.service();
    s.config.trusted_web_uid = crate::openbsd::effective_uid().saturating_add(1);
    let (server, _client) = UnixStream::pair().unwrap();
    assert_eq!(s.connection(server), Err(Error::Authentication));
    assert!(!f.root.join("state/nonces").exists());
}
#[test]
fn admissions_are_one_per_account_two_global_and_release_after_failure() {
    let admissions = Admissions::default();
    let alice = admissions.enter("alice").unwrap();
    assert!(matches!(admissions.enter("alice"), Err(Error::Busy)));
    let bob = admissions.enter("bob").unwrap();
    assert!(matches!(admissions.enter("charlie"), Err(Error::Busy)));
    drop(alice);
    let charlie = admissions.enter("charlie").unwrap();
    drop(bob);
    drop(charlie);
    assert!(admissions.enter("alice").is_ok());
}
#[test]
fn actual_socket_snapshot_and_authenticated_stale_mutation_replies() {
    let f = Fixture::new();
    let listener = f.listener();
    let s = f.service();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            s.connection(stream).unwrap();
        }
    });
    let client = f.client();
    let snapshot = client.snapshot("alice").unwrap();
    assert!(snapshot.inventory.keys().unwrap().is_empty());
    assert_eq!(
        client
            .import_public(
                "alice",
                &"0".repeat(64),
                &"A".repeat(40),
                b"synthetic certificate"
            )
            .unwrap_err(),
        Error::Stale
    );
    server.join().unwrap();
    assert_eq!(
        fs::read(f.root.join("home/pubring.kbx")).unwrap(),
        b"synthetic public fixture"
    );
    assert_eq!(
        fs::read(f.root.join("home/trustdb.gpg")).unwrap(),
        b"synthetic trust fixture"
    );
}
#[test]
fn lost_tampered_and_wrong_nonce_mutation_replies_are_unconfirmed_without_retry() {
    for behavior in 0..3 {
        let f = Fixture::new();
        let listener = f.listener();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let bytes = read_frame(&mut stream, deadline()).unwrap();
            let r = Verifier::default()
                .request(&bytes, KEY, now().unwrap())
                .unwrap();
            if behavior == 0 {
                return;
            }
            let mut reply = if behavior == 1 {
                r.response(Ok(snapshot()), KEY, now().unwrap()).unwrap()
            } else {
                request("alice", Action::ImportPublic, now().unwrap())
                    .response(Ok(snapshot()), KEY, now().unwrap())
                    .unwrap()
            };
            if behavior == 1 {
                *reply.last_mut().unwrap() ^= 1;
            }
            let _ = write_frame(&mut stream, &reply, deadline());
        });
        let client = f.client();
        assert_eq!(
            client
                .import_public("alice", &"a".repeat(64), &"A".repeat(40), b"synthetic")
                .unwrap_err(),
            Error::Unconfirmed
        );
        server.join().unwrap();
    }
}
#[test]
fn absent_helper_wrong_uid_and_unbounded_frames_fail_closed() {
    let f = Fixture::new();
    assert_eq!(
        Client::from_operator_files(&f.socket, &f.key, crate::openbsd::effective_uid())
            .unwrap_err(),
        Error::Unavailable
    );
    let _listener = f.listener();
    assert!(Client::from_operator_files(
        &f.socket,
        &f.key,
        crate::openbsd::effective_uid().saturating_add(1)
    )
    .is_err());
    let client = f.client();
    fs::remove_file(&f.socket).unwrap();
    assert_eq!(client.snapshot("alice").unwrap_err(), Error::Unavailable);
    assert_eq!(
        client
            .import_public("alice", &"a".repeat(64), &"A".repeat(40), b"synthetic")
            .unwrap_err(),
        Error::Unavailable
    );
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
        .unwrap();
    assert_eq!(read_frame(&mut b, deadline()).unwrap_err(), Error::Limit);
}

#[test]
#[ignore = "requires disposable OpenBSD helper/web principals and actual native keyboxes"]
fn native_public_admin_principal_client() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let setting = |name: &str| {
        std::env::var(format!("OSMAP_PUBLIC_ADMIN_PRINCIPAL_{name}"))
            .expect("native public admin fixture setting")
    };
    let socket = PathBuf::from(setting("SOCKET"));
    let key_file = PathBuf::from(setting("KEY"));
    let helper_uid = setting("HELPER_UID").parse::<u32>().unwrap();
    let client = Client::from_operator_files(&socket, &key_file, helper_uid).unwrap();
    let mode = setting("MODE");
    if mode == "peer_denied" {
        assert!(client.snapshot("alice").is_err());
        return;
    }
    let key = secret(&key_file).unwrap();
    if mode == "replay_after_restart" {
        let bytes = fs::read(setting("REPLAY_FILE")).unwrap();
        let request = Verifier::default()
            .request(&bytes, &key, now().unwrap())
            .unwrap();
        let mut stream = crate::openbsd::connect_unix_before(&socket, deadline()).unwrap();
        assert_eq!(
            crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
            helper_uid
        );
        write_frame(&mut stream, &bytes, deadline()).unwrap();
        let reply = read_frame(&mut stream, deadline()).unwrap();
        assert_eq!(
            Verifier::default()
                .response(&request, &reply, &key, now().unwrap())
                .unwrap()
                .unwrap_err(),
            Error::Replay
        );
        return;
    }
    let alice = setting("ALICE_FP");
    let bob = setting("BOB_FP");
    let cert = fs::read(setting("CERTIFICATE")).unwrap();
    if mode == "consume_once" {
        let snapshot = client.snapshot("alice").unwrap();
        let request = Request::issue(
            "alice",
            Action::ImportPublic,
            Some(&snapshot.revision),
            Some(&bob),
            &cert,
            now().unwrap(),
            &key,
        )
        .unwrap();
        let bytes = request.to_bytes().unwrap();
        let mut stream = crate::openbsd::connect_unix_before(&socket, deadline()).unwrap();
        assert_eq!(
            crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
            helper_uid
        );
        write_frame(&mut stream, &bytes, deadline()).unwrap();
        let reply = read_frame(&mut stream, deadline()).unwrap();
        Verifier::default()
            .response(&request, &reply, &key, now().unwrap())
            .unwrap()
            .unwrap();
        // Disposable authenticated request lives only in private fixture scratch.
        // It is not retained as evidence and contains only a synthetic public cert.
        let path = PathBuf::from(setting("REPLAY_FILE"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        return;
    }
    assert_eq!(mode, "authorized");
    for name in ["ALICE_HOME", "BOB_HOME"] {
        assert!(fs::read(PathBuf::from(setting(name)).join("pubring.kbx")).is_err());
    }
    assert!(Client::from_operator_files(&socket, &key_file, helper_uid.saturating_add(1)).is_err());
    assert_eq!(client.snapshot("unmapped").unwrap_err(), Error::Unavailable);
    let first = client.snapshot("alice").unwrap();
    let other = client.snapshot("bob").unwrap();
    assert_eq!(first.inventory.keys().unwrap().len(), 1);
    assert_eq!(
        first.inventory.keys().unwrap()[0].primary.fingerprint,
        alice
    );
    let imported = client
        .import_public("alice", &first.revision, &bob, &cert)
        .unwrap();
    assert_ne!(imported.revision, first.revision);
    assert_eq!(imported.inventory.keys().unwrap().len(), 2);
    assert_eq!(client.snapshot("bob").unwrap().revision, other.revision);
    assert_eq!(
        client
            .import_public("alice", &first.revision, &bob, &cert)
            .unwrap_err(),
        Error::Stale
    );
    let secret_cert = fs::read(setting("SECRET_CERTIFICATE")).unwrap();
    assert!(matches!(
        client.import_public("alice", &imported.revision, &bob, &secret_cert),
        Err(Error::Invalid | Error::Unavailable)
    ));
    assert_eq!(
        client.snapshot("alice").unwrap().revision,
        imported.revision
    );
    assert!(matches!(
        client.remove_public("alice", &imported.revision, &alice),
        Err(Error::Invalid | Error::Unavailable)
    ));
    assert_eq!(
        client.snapshot("alice").unwrap().revision,
        imported.revision
    );
    let removed = client
        .remove_public("alice", &imported.revision, &bob)
        .unwrap();
    assert_eq!(removed.inventory.keys().unwrap().len(), 1);
    assert_ne!(removed.revision, imported.revision);
    assert_eq!(
        client
            .remove_public("alice", &imported.revision, &bob)
            .unwrap_err(),
        Error::Stale
    );
    let restored = client
        .import_public("alice", &removed.revision, &bob, &cert)
        .unwrap();
    assert_eq!(restored.inventory.keys().unwrap().len(), 2);
    assert_eq!(client.snapshot("bob").unwrap().revision, other.revision);
}
