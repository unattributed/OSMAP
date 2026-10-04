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
        let mut gateway = RuntimeBrowserGateway::for_test(&root);
        gateway.account_admission_client =
            Some(Client::qualified_files(&socket, &key, uid).unwrap());
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
