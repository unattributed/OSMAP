//! Local tests qualify session/grant, protection metadata and atomic refusal
//! predicates only; synthetic files and socket are not native crypto evidence.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    listener: Option<UnixListener>,
}
impl Fixture {
    fn new(protected: bool) -> Self {
        let root = fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-personal-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("private-keys-v1.d"))
            .unwrap();
        write_new(
            &root
                .join("private-keys-v1.d")
                .join(format!("{}.key", "A".repeat(40))),
            if protected {
                b"Key: (protected-private-key synthetic)"
            } else {
                b"Key: (private-key synthetic)"
            },
        )
        .unwrap();
        let listener = Some(UnixListener::bind(root.join("S.gpg-agent")).unwrap());
        Self { root, listener }
    }
    fn context(&self) -> Context<'_> {
        Context {
            account: "alice@example.test",
            home: &self.root,
            primary: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            signer: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            worker: Path::new("/unused-worker"),
            engine: Path::new("/unused-engine"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.listener.take();
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn session() -> PrivateSession {
    PrivateSession {
        session_id: "a".repeat(64),
        account_epoch: Some(7),
        expires_at: time().unwrap() + 3600,
    }
}
#[test]
fn personal_private_metadata_distinguishes_protection_without_claiming_readiness() {
    for protected in [false, true] {
        let fixture = Fixture::new(protected);
        let mut manager = Manager::default();
        let state = manager
            .state(
                &fixture.context(),
                &session(),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        assert!(state.installed);
        assert_eq!(state.protected_at_rest, protected);
        assert!(!state.unlocked_for_session);
        assert!(state.valid_until.is_none());
    }
}
#[test]
fn personal_grants_bind_session_epoch_expiry_and_exact_private_revision() {
    let fixture = Fixture::new(true);
    let context = fixture.context();
    let session = session();
    let mut manager = Manager::default();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert!(!manager.permitted(&context, Some(&session), deadline));
    manager.grants.insert(
        (context.account.into(), session.session_id.clone()),
        Grant {
            epoch: session.account_epoch,
            until: time().unwrap() + 60,
            revision: private_files(context.home).unwrap().revision.clone(),
        },
    );
    assert!(manager.permitted(&context, Some(&session), deadline));
    let mut foreign = session.clone();
    foreign.session_id = "b".repeat(64);
    assert!(!manager.permitted(&context, Some(&foreign), deadline));
    foreign = session.clone();
    foreign.account_epoch = Some(8);
    assert!(!manager.permitted(&context, Some(&foreign), deadline));
    foreign = session.clone();
    foreign.expires_at = time().unwrap() + 1;
    assert!(!manager.permitted(&context, Some(&foreign), deadline));
    fs::write(
        fixture
            .root
            .join("private-keys-v1.d")
            .join(format!("{}.key", "A".repeat(40))),
        b"Key: (protected-private-key changed)",
    )
    .unwrap();
    assert!(!manager.permitted(&context, Some(&session), deadline));
    manager
        .grants
        .values_mut()
        .for_each(|grant| grant.until = 0);
    assert!(!manager.permitted(&context, Some(&session), deadline));
    assert!(manager.grants.is_empty());
}
#[test]
fn personal_bad_input_rate_limit_precedes_any_candidate_agent_or_file_write() {
    let fixture = Fixture::new(true);
    let mut manager = Manager::default();
    manager
        .failures
        .insert("alice@example.test".into(), vec![time().unwrap(); 5]);
    let before = fs::read_dir(&fixture.root).unwrap().count();
    assert_eq!(
        manager
            .handle(
                fixture.context(),
                &session(),
                PersonalAction::Unlock {
                    passphrase: b"synthetic wrong"
                },
                Instant::now() + Duration::from_secs(2)
            )
            .err(),
        Some(Error::Locked)
    );
    assert_eq!(before, fs::read_dir(&fixture.root).unwrap().count());
    assert_eq!(manager.failures["alice@example.test"].len(), 5);
}
#[test]
fn personal_partial_link_rollback_retains_unknown_identity_and_continues_known_cleanup() {
    let fixture = Fixture::new(true);
    let original = fixture.root.join("original");
    let created = fixture.root.join("created");
    write_new(&original, b"synthetic").unwrap();
    fs::hard_link(&original, &created).unwrap();
    let unknown = fixture.root.join("unknown");
    write_new(&unknown, b"other").unwrap();
    assert!(!rollback_links(vec![
        (fixture.root.join("missing-original"), unknown.clone()),
        (original.clone(), created.clone())
    ]));
    assert!(unknown.exists());
    assert!(!created.exists());
    assert!(fs::read(original).unwrap() == b"synthetic");
}
#[test]
fn personal_lock_cannot_enter_during_authorized_private_dispatch() {
    use super::super::{Admissions, Config, Mapping, Service};
    use crate::openpgp_crypto::{Error as CryptoError, Operation};
    use crate::openpgp_crypto_protocol::{self as wire, Request, Verifier};
    let fixture = Fixture::new(true);
    let session = session();
    let now = time().unwrap();
    let key = vec![42; 32];
    let mut manager = Manager::default();
    manager.grants.insert(
        ("alice@example.test".into(), session.session_id.clone()),
        Grant {
            epoch: session.account_epoch,
            until: now + 60,
            revision: private_files(&fixture.root).unwrap().revision.clone(),
        },
    );
    let service = Service {
        config: Config {
            version: 1,
            worker: PathBuf::from("/unused-worker"),
            engine: PathBuf::from("/unused-engine"),
            socket: fixture.root.join("rpc"),
            trusted_web_uid: crate::openbsd::effective_uid(),
            accounts: vec![Mapping {
                account: "alice@example.test".into(),
                home: fixture.root.clone(),
                signer_fingerprint: Some("A".repeat(40)),
                decrypt_fingerprints: vec!["A".repeat(40)],
                recipient_fingerprints: vec![],
                allow_imported_recipients: false,
                allow_web_personal_keys: true,
            }],
        },
        key: key.clone(),
        verifier: std::sync::Mutex::new(Verifier::default()),
        admissions: Admissions::default(),
        personal: std::sync::Mutex::new(manager),
    };
    let operation = Operation::Sign {
        signer_fingerprint: "A".repeat(40),
        data: b"synthetic private dispatch".to_vec(),
    };
    let mut request = Request::issue("alice@example.test", &operation, now, &key).unwrap();
    request.bind_session(session.clone(), now, &key).unwrap();
    let response = service
        .process(
            &request.to_bytes().unwrap(),
            Instant::now() + Duration::from_secs(2),
            |_, _, _, _, _| {
                let lock = Request::issue_personal(
                    "alice@example.test",
                    &session,
                    PersonalAction::Lock,
                    now,
                    &key,
                )
                .unwrap();
                assert!(matches!(
                    service.process(
                        &lock.to_bytes().unwrap(),
                        Instant::now() + Duration::from_secs(2),
                        |_, _, _, _, _| panic!("Lock cannot dispatch a crypto worker")
                    ),
                    Err(crate::openpgp_inventory::Error::Capacity)
                ));
                Err(CryptoError::Locked)
            },
        )
        .unwrap();
    assert_eq!(
        wire::Verifier::default()
            .response(&request, &response, &operation, &key, now)
            .unwrap()
            .err(),
        Some(CryptoError::Locked)
    );
}

#[test]
#[ignore = "actual OpenBSD two-cycle personal agent startup discriminator"]
fn native_personal_agent_two_cycle_diagnostic() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let setting = |name| {
        PathBuf::from(std::env::var_os(name).expect("owned native personal fixture setting"))
            .canonicalize()
            .unwrap()
    };
    let home = setting("OSMAP_CRYPTO_NATIVE_PERSONAL_HOME");
    let worker = setting("OSMAP_CRYPTO_NATIVE_WORKER");
    let engine = setting("OSMAP_CRYPTO_NATIVE_ENGINE");
    let root = worker.parent().unwrap();
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    assert!(home.starts_with(root));
    let primary = std::env::var("OSMAP_CRYPTO_NATIVE_PERSONAL_FP").unwrap();
    assert!(primary.len() == 40 && crate::openpgp_crypto::full_fingerprint(&primary));
    let before = private_files(&home).unwrap();
    assert!(before.files.is_empty());
    let public_before = fs::read(home.join("pubring.kbx")).unwrap();
    let trust_before = fs::read(home.join("trustdb.gpg")).unwrap();
    let public_only = fs::read(root.join("personal.public")).unwrap();
    assert!(!public_only.is_empty() && public_only.len() <= 65536);
    let context = Context {
        account: "alice@example.test",
        home: &home,
        primary: &primary,
        signer: &primary,
        worker: &worker,
        engine: &engine,
    };
    let mut all_expected = true;
    for cycle in 0..2 {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stage = Stage::new(&home, None).unwrap();
        let pre = endpoint(&stage.path, deadline);
        let quarantine_before = crate::openpgp_crypto_process::cleanup_unconfirmed_for_test();
        let started = agent(&stage.path, PersonalAgentCommand::Start, deadline);
        let quarantine_after = crate::openpgp_crypto_process::cleanup_unconfirmed_for_test();
        let (start_code, leader_success, stdout_bytes) = match &started {
            Ok(bytes) => ("completed", true, bytes.len()),
            Err(Error::Expired) => ("expired", false, 0),
            Err(Error::Unavailable) => ("unavailable", false, 0),
            Err(_) => ("other_fixed_error", false, 0),
        };
        let immediate = endpoint(&stage.path, deadline);
        // Read only: observe readiness once more without spawning another agent.
        let observe_until = deadline.min(Instant::now() + Duration::from_millis(250));
        let mut later = immediate;
        while matches!(later, Ok(false)) && Instant::now() < observe_until {
            std::thread::sleep(Duration::from_millis(10));
            later = endpoint(&stage.path, deadline);
        }
        let proof = if later == Ok(true) && !quarantine_after {
            Some(prove(
                &context,
                &stage.path,
                &public_only,
                b"synthetic-personal-key-passphrase",
                deadline,
            ))
        } else {
            None
        };
        let cleanup = stage.finish(deadline);
        let candidate_absent = !stage.path.exists();
        let quarantine_final = crate::openpgp_crypto_process::cleanup_unconfirmed_for_test();
        let unchanged = private_files(&home)
            .is_ok_and(|files| files.files.is_empty() && files.revision == before.revision)
            && fs::read(home.join("pubring.kbx")).is_ok_and(|bytes| bytes == public_before)
            && fs::read(home.join("trustdb.gpg")).is_ok_and(|bytes| bytes == trust_before);
        println!("personal_agent_cycle={cycle} production_start=true pre_endpoint={pre:?} start={start_code} leader_success={leader_success} stdout_bytes={stdout_bytes} quarantine_before={quarantine_before} quarantine_after={quarantine_after} immediate_endpoint={immediate:?} later_endpoint={later:?} public_only_proof={proof:?} cleanup={cleanup:?} candidate_absent={candidate_absent} quarantine_final={quarantine_final} target_unchanged={unchanged}");
        all_expected &= pre == Ok(false)
            && leader_success
            && immediate == Ok(true)
            && proof == Some(Err(Error::Invalid))
            && cleanup.is_ok()
            && candidate_absent
            && !quarantine_final
            && unchanged;
        if cleanup.is_err() || quarantine_final {
            break;
        }
    }
    assert!(
        all_expected,
        "two-cycle native startup contract observations above"
    );
}

#[test]
#[ignore = "actual OpenBSD protected personal import/unlock/session/lock fixture"]
fn native_personal_protected_import_unlock_lock_roundtrip() {
    use super::super::{Client, Service};
    use crate::openpgp_crypto::{Error as CryptoError, Operation};
    assert_eq!(std::env::consts::OS, "openbsd");
    let setting = |name| {
        PathBuf::from(std::env::var_os(name).expect("owned native personal fixture setting"))
    };
    let home = setting("OSMAP_CRYPTO_NATIVE_PERSONAL_HOME")
        .canonicalize()
        .unwrap();
    let worker = setting("OSMAP_CRYPTO_NATIVE_WORKER")
        .canonicalize()
        .unwrap();
    let engine = setting("OSMAP_CRYPTO_NATIVE_ENGINE")
        .canonicalize()
        .unwrap();
    let certificate = setting("OSMAP_CRYPTO_NATIVE_PERSONAL_CERTIFICATE")
        .canonicalize()
        .unwrap();
    let primary = std::env::var("OSMAP_CRYPTO_NATIVE_PERSONAL_FP").unwrap();
    assert!(crate::openpgp_crypto::full_fingerprint(&primary) && primary.len() == 40);
    let root = worker.parent().unwrap();
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    assert!(home.starts_with(root) && certificate.starts_with(root));
    assert!(private_files(&home).unwrap().files.is_empty());
    let public_before = fs::read(home.join("pubring.kbx")).unwrap();
    let trust_before = fs::read(home.join("trustdb.gpg")).unwrap();
    const PASSPHRASE: &[u8] = b"synthetic-personal-key-passphrase";
    let mut uploaded = fs::read(certificate).unwrap();
    assert!(uploaded.len() <= 65536);
    let empty_revision = private_files(&home).unwrap().revision.clone();
    // These calls exercise the actual native validation and candidate custody,
    // before the authenticated lifecycle below. They do not reset or bypass a
    // live account's failure limiter and never publish candidate private files.
    let refuse = |case, account, expected_primary: &str, bytes: &[u8]| {
        assert!(!bytes.is_empty() && bytes.len() <= 65536);
        let context = Context {
            account,
            home: &home,
            primary: expected_primary,
            signer: expected_primary,
            worker: &worker,
            engine: &engine,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stage = Stage::new(&home, None).unwrap();
        start_agent(&stage.path, deadline).unwrap();
        let outcome = prove(&context, &stage.path, bytes, PASSPHRASE, deadline);
        let cleaned = stage.finish(deadline).is_ok() && !stage.path.exists();
        let unpublished = private_files(&home)
            .is_ok_and(|files| files.files.is_empty() && files.revision == empty_revision);
        let public_unchanged =
            fs::read(home.join("pubring.kbx")).is_ok_and(|bytes| bytes == public_before);
        let trust_unchanged =
            fs::read(home.join("trustdb.gpg")).is_ok_and(|bytes| bytes == trust_before);
        println!("personal_native_refusal={case} result={outcome:?} candidate_cleanup={cleaned} target_unpublished={unpublished} public_unchanged={public_unchanged} trust_unchanged={trust_unchanged}");
        assert_eq!(outcome, Err(Error::Invalid));
        assert!(cleaned && unpublished && public_unchanged && trust_unchanged);
    };
    let public_only = fs::read(root.join("personal.public")).unwrap();
    refuse("public_only", "alice@example.test", &primary, &public_only);
    let other_primary = std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap();
    assert!(crate::openpgp_crypto::full_fingerprint(&other_primary));
    assert_ne!(other_primary, primary);
    refuse(
        "wrong_primary",
        "alice@example.test",
        &other_primary,
        &uploaded,
    );
    refuse("wrong_account", "bob@example.test", &primary, &uploaded);
    let mut other_certificate = fs::read(root.join("personal-other.asc")).unwrap();
    assert!(other_certificate.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    let mut multiple = uploaded.clone();
    multiple.push(b'\n');
    multiple.extend_from_slice(&other_certificate);
    refuse(
        "multiple_primaries",
        "alice@example.test",
        &primary,
        &multiple,
    );
    crate::openpgp_personal::clear(&mut multiple);
    crate::openpgp_personal::clear(&mut other_certificate);
    let config = home.join("personal-rpc.json");
    let key = home.join("personal-grant");
    let socket = home.join("personal.sock");
    write_new(&config,&serde_json::to_vec(&serde_json::json!({"version":1,"worker":worker,"engine":engine,"socket":socket,"trusted_web_uid":crate::openbsd::effective_uid(),"accounts":[{"account":"alice@example.test","home":home,"signer_fingerprint":primary,"decrypt_fingerprints":[primary],"recipient_fingerprints":[primary],"allow_web_personal_keys":true}]})).unwrap()).unwrap();
    write_new(&key, &[42; 32]).unwrap();
    let start = |count| {
        let service = Service::from_operator_files(&config, &key).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(120);
            for _ in 0..count {
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < until,
                                "bounded personal native RPC acceptance"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => panic!("owned personal listener unavailable"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                service.connection(stream).unwrap();
            }
        })
    };
    let server = start(15);
    let client =
        Client::from_operator_files(&socket, &key, crate::openbsd::effective_uid()).unwrap();
    let session = session();
    let bound = client.for_session(session.clone());
    let sign = || Operation::Sign {
        signer_fingerprint: primary.clone(),
        data: b"synthetic personal signed control".to_vec(),
    };
    let state = client
        .personal("alice@example.test", &session, PersonalAction::Status)
        .unwrap();
    assert!(!state.installed && !state.unlocked_for_session);
    assert_eq!(
        client.execute("alice@example.test", &sign()).unwrap().err(),
        Some(CryptoError::Locked)
    );
    let imported = client
        .personal(
            "alice@example.test",
            &session,
            PersonalAction::Import {
                certificate: &uploaded,
                passphrase: PASSPHRASE,
            },
        )
        .unwrap();
    crate::openpgp_personal::clear(&mut uploaded);
    assert!(imported.installed && imported.protected_at_rest && imported.unlocked_for_session);
    assert_eq!(imported.primary_fingerprint, primary);
    let signed = bound
        .execute("alice@example.test", &sign())
        .unwrap()
        .unwrap();
    let verified = client
        .execute(
            "alice@example.test",
            &Operation::Verify {
                data: b"synthetic personal signed control".to_vec(),
                signature: signed.content,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        verified.primary_fingerprint.as_deref(),
        Some(primary.as_str())
    );
    assert_eq!(
        client
            .personal(
                "alice@example.test",
                &session,
                PersonalAction::Unlock {
                    passphrase: b"synthetic wrong passphrase"
                }
            )
            .err(),
        Some(Error::Locked)
    );
    assert!(bound
        .execute("alice@example.test", &sign())
        .unwrap()
        .is_ok());
    let mut foreign = session.clone();
    foreign.session_id = "b".repeat(64);
    assert_eq!(
        client
            .for_session(foreign)
            .execute("alice@example.test", &sign())
            .unwrap()
            .err(),
        Some(CryptoError::Locked)
    );
    let mut stale = session.clone();
    stale.account_epoch = Some(8);
    assert_eq!(
        client
            .for_session(stale)
            .execute("alice@example.test", &sign())
            .unwrap()
            .err(),
        Some(CryptoError::Locked)
    );
    let locked = client
        .personal("alice@example.test", &session, PersonalAction::Lock)
        .unwrap();
    assert!(!locked.unlocked_for_session);
    assert_eq!(
        bound.execute("alice@example.test", &sign()).unwrap().err(),
        Some(CryptoError::Locked)
    );
    let unlocked = client
        .personal(
            "alice@example.test",
            &session,
            PersonalAction::Unlock {
                passphrase: PASSPHRASE,
            },
        )
        .unwrap();
    assert!(unlocked.unlocked_for_session);
    let encrypted = client
        .execute(
            "alice@example.test",
            &Operation::Encrypt {
                recipient_fingerprints: vec![primary.clone()],
                data: b"synthetic personal decrypted control".to_vec(),
            },
        )
        .unwrap()
        .unwrap();
    let decrypted = bound
        .execute(
            "alice@example.test",
            &Operation::Decrypt {
                allowed_primary_fingerprints: vec![primary.clone()],
                ciphertext: encrypted.content,
            },
        )
        .unwrap()
        .unwrap();
    assert!(decrypted.content == b"synthetic personal decrypted control");
    assert_eq!(
        client
            .personal(
                "alice@example.test",
                &session,
                PersonalAction::Import {
                    certificate: b"not used when installed",
                    passphrase: PASSPHRASE
                }
            )
            .err(),
        Some(Error::Conflict)
    );
    server.join().unwrap();
    assert!(endpoint(&home, Instant::now() + Duration::from_secs(2)).unwrap());
    fs::remove_file(&socket).unwrap();
    let restarted = start(2);
    assert_eq!(
        bound.execute("alice@example.test", &sign()).unwrap().err(),
        Some(CryptoError::Locked)
    );
    assert!(
        !client
            .personal("alice@example.test", &session, PersonalAction::Lock)
            .unwrap()
            .unlocked_for_session
    );
    restarted.join().unwrap();
    fs::remove_file(&socket).unwrap();
    assert!(!endpoint(&home, Instant::now() + Duration::from_secs(2)).unwrap());
    assert!(fs::read(home.join("pubring.kbx")).unwrap() == public_before);
    assert!(fs::read(home.join("trustdb.gpg")).unwrap() == trust_before);
    assert!(!fs::read_dir(&home).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".p-")));
    println!("personal_protected_import=PASS cold_wrong_passphrase_while_warm=PASS prior_grant_preserved=PASS session_epoch_refusals=PASS native_sign_verify_self_decrypt=PASS no_replace_conflict=PASS explicit_lock=PASS helper_restart_locks=PASS public_trust_unchanged=PASS candidate_cleanup=PASS");
}
