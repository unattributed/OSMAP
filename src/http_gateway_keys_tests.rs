use super::*;
use crate::session::SessionToken;
use crate::totp::TimeProvider as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const ACCOUNT: &str = "alice@example.test";
const PASSWORD: &str = "public synthetic +&= café key fixture password";
const RFC_SECRET: &[u8] = b"12345678901234567890";

struct Fixture {
    root: PathBuf,
    gateway: RuntimeBrowserGateway,
    context: AuthenticationContext,
    session: ValidatedSession,
    token: SessionToken,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-keys-runtime-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        Self::at(root)
    }
    fn at(root: PathBuf) -> Self {
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["sessions", "totp", "cache", "settings"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut gateway = RuntimeBrowserGateway::for_test(&root);
        let marker = root.join("primary-called");
        let script = root.join("primary-fixture");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf called > '{}'; IFS= read -r password\n[ \"$password\" = '{PASSWORD}' ] || exit 1\nif [ -f '{}/hold-auth' ]; then\ni=0; while [ ! -f '{}/release-auth' ] && [ \"$i\" -lt 500 ]; do sleep 0.01; i=$((i+1)); done\n[ -f '{}/release-auth' ] || exit 1\nfi\nprintf 'passdb: {ACCOUNT} auth succeeded\\n'\n",
                marker.display(),root.display(),root.display(),root.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        // Establish that the detector actually executes before using absence.
        let control = std::process::Command::new(&script)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(!control.status.success());
        assert_eq!(fs::read(&marker).unwrap(), b"called");
        fs::remove_file(marker).unwrap();
        gateway.doveadm_path = script;
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "keys-runtime-fixture",
            "127.0.0.1",
            "Synthetic/Keys",
        )
        .unwrap();
        let issued = gateway
            .build_session_service()
            .issue(&context, ACCOUNT, RequiredSecondFactor::Totp)
            .unwrap();
        let secret =
            FileTotpSecretStore::new(&gateway.totp_secret_dir).secret_path_for_username(ACCOUNT);
        fs::write(&secret, b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        fs::set_permissions(secret, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            gateway,
            context,
            session: ValidatedSession {
                record: issued.record,
                audit_event: issued.audit_event,
            },
            token: issued.token,
        }
    }
    fn code(&self) -> String {
        crate::totp::generate_totp_code(
            RFC_SECRET,
            SystemTimeProvider.unix_timestamp() / 30,
            TotpPolicy::default(),
        )
        .unwrap()
    }
    fn request<'a>(&self, code: &'a str) -> MutationRequest<'a> {
        MutationRequest {
            action: key_management::Action::ClearAccount,
            expected_revision: 0,
            expected_public_revision: None,
            password: PASSWORD,
            totp: code,
        }
    }
}

struct NativeService(std::process::Child);
impl Drop for NativeService {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Selected admission over actual MAC-bound Unix RPC and real factor/session/
/// admin stores. Primary authority is a same-UID synthetic responder, not live
/// Dovecot or the root-owned native-local account service.
#[test]
#[ignore = "requires disposable OpenBSD keyboxes and real public-admin worker"]
fn native_runtime_key_management_journey() {
    use crate::openpgp_bindings::{Recipients, Requirement, Selections};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const TEST: &str =
        "http::http_gateway::http_gateway_keys::tests::native_runtime_key_management_journey";
    assert_eq!(std::env::consts::OS, "openbsd");
    if let Ok(service) = std::env::var("OSMAP_KEYS_NATIVE_SERVICE") {
        let config = PathBuf::from(std::env::var_os("OSMAP_KEYS_NATIVE_CONFIG").unwrap());
        let key = PathBuf::from(std::env::var_os("OSMAP_KEYS_NATIVE_KEY").unwrap());
        match service.as_str() {
            "admin" => {
                crate::openpgp_public_admin_runtime::Service::from_operator_files(&config, &key)
                    .unwrap()
                    .serve()
                    .unwrap()
            }
            "crypto" => crate::openpgp_crypto_runtime::Service::from_operator_files(&config, &key)
                .unwrap()
                .serve()
                .unwrap(),
            "inventory" => {
                crate::openpgp_inventory_runtime::Service::from_operator_files(&config, &key)
                    .unwrap()
                    .serve()
                    .unwrap()
            }
            _ => panic!("unknown native fixture service"),
        }
        return;
    }
    let setting = |name| PathBuf::from(std::env::var_os(name).unwrap());
    let worker = setting("OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER");
    let crypto_worker = setting("OSMAP_CRYPTO_NATIVE_WORKER");
    let engine = setting("OSMAP_CRYPTO_NATIVE_ENGINE");
    let alice = setting("OSMAP_CRYPTO_NATIVE_ALICE_HOME");
    let bob = setting("OSMAP_CRYPTO_NATIVE_BOB_HOME");
    let bob_fp = std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap();
    let fixture = worker.parent().unwrap();
    assert!(fixture.starts_with("/tmp"));
    assert!(fixture
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    assert!(alice.starts_with(fixture) && bob.starts_with(fixture));
    assert!(crypto_worker.starts_with(fixture));
    let mut f = Fixture::at(fixture.join("runtime-keys"));
    // Keep the established legacy process marker as a forbidden-route detector.
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    struct SelectedPrimary {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for SelectedPrimary {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let result = thread.join();
                if !std::thread::panicking() {
                    assert!(
                        result.is_ok(),
                        "synthetic selected admission responder failed"
                    );
                }
            }
        }
    }
    let admission_socket = f.root.join("admission.sock");
    let mutation_socket = f.root.join("mutation.sock");
    let admission_listener = std::os::unix::net::UnixListener::bind(&admission_socket).unwrap();
    let mutation_listener = std::os::unix::net::UnixListener::bind(&mutation_socket).unwrap();
    for path in [&admission_socket, &mutation_socket] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
    }
    admission_listener.set_nonblocking(true).unwrap();
    mutation_listener.set_nonblocking(true).unwrap();
    for (name, byte) in [
        ("admission.key", 29),
        ("mutation.key", 17),
        ("proof.key", 19),
    ] {
        let path = f.root.join(name);
        fs::write(&path, [byte; 32]).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let uid = crate::openbsd::effective_uid();
    f.gateway = f.gateway.clone().with_account_fixture_clients(
        crate::account_admission_runtime::Client::paired_fixture_files(
            &admission_socket,
            &f.root.join("admission.key"),
            uid,
        )
        .unwrap(),
        crate::account_mutation_client::Client::stored_fixture_files(
            &mutation_socket,
            &f.root.join("mutation.key"),
            &f.root.join("proof.key"),
            uid,
        )
        .unwrap(),
    );
    f.gateway.account_rollout = Some(ACCOUNT.into());
    fs::write(
        &f.gateway.doveadm_path,
        format!(
            "#!/bin/sh\nprintf called > '{}'\nexit 1\n",
            f.root.join("primary-called").display()
        ),
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let authenticate_count = Arc::new(AtomicUsize::new(0));
    let admit_count = Arc::new(AtomicUsize::new(0));
    let selected_primary = SelectedPrimary {
        stop: stop.clone(),
        thread: Some(std::thread::spawn({
            let authenticate_count = authenticate_count.clone();
            let admit_count = admit_count.clone();
            move || {
                use crate::openpgp_inventory_runtime::{now, read_frame, write_frame};
                let end = Instant::now() + Duration::from_secs(240);
                let mut verifier = crate::account_admission::Verifier::default();
                while !stop.load(Ordering::SeqCst) {
                    assert!(Instant::now() < end, "synthetic admission fixture deadline");
                    let mut stream = match admission_listener.accept() {
                        Ok((stream, _)) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => panic!("synthetic admission fixture accept failed"),
                    };
                    assert_eq!(crate::openbsd::unix_stream_peer_uid(&stream).unwrap(), uid);
                    let deadline = Instant::now() + Duration::from_secs(3);
                    let bytes =
                        read_frame(&mut stream, crate::account_admission::MAX_FRAME, deadline)
                            .unwrap();
                    let request = verifier.request(&bytes, &[29; 32], now().unwrap()).unwrap();
                    assert_eq!(request.account(), ACCOUNT);
                    match request.operation() {
                        crate::account_admission::Operation::Authenticate { password } => {
                            assert!(
                                password == PASSWORD,
                                "unexpected synthetic primary credential"
                            );
                            authenticate_count.fetch_add(1, Ordering::SeqCst);
                        }
                        crate::account_admission::Operation::Admit { epoch } => {
                            assert_eq!(*epoch, 7);
                            admit_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    let response = request
                        .response(Some(7), &[29; 32], now().unwrap())
                        .unwrap();
                    write_frame(&mut stream, &response, deadline).unwrap();
                }
            }
        })),
    };
    let issued = f
        .gateway
        .build_session_service()
        .issue_with_epoch(&f.context, ACCOUNT, RequiredSecondFactor::Totp, Some(7))
        .unwrap();
    f.session = ValidatedSession {
        record: issued.record,
        audit_event: issued.audit_event,
    };
    f.token = issued.token;
    assert_eq!(f.session.record.account_epoch, Some(7));
    let state_dir = f.root.join("admin-state");
    fs::create_dir(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let key = f.root.join("admin-grant");
    let mut grant = [0; 32];
    getrandom::getrandom(&mut grant).unwrap();
    fs::write(&key, grant).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let socket = f.root.join("admin.sock");
    let config = f.root.join("admin.json");
    fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "version":1,"worker":worker,"engine":engine,"state_directory":state_dir,
            "socket":socket,"trusted_web_uid":crate::openbsd::effective_uid(),
            "accounts":[{"account":ACCOUNT,"home":alice}]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let mut service = NativeService(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--ignored"])
            .env("OSMAP_KEYS_NATIVE_SERVICE", "admin")
            .env("OSMAP_KEYS_NATIVE_CONFIG", &config)
            .env("OSMAP_KEYS_NATIVE_KEY", &key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(service.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    f.gateway.public_admin_client = Some(
        crate::openpgp_public_admin_runtime::Client::from_operator_files(
            &socket,
            &key,
            crate::openbsd::effective_uid(),
        )
        .unwrap(),
    );
    let trustdb = fs::read(alice.join("trustdb.gpg")).unwrap();
    let private = fs::read_dir(alice.join("private-keys-v1.d"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect::<Vec<_>>();
    let certificate = Command::new("/usr/local/bin/gpg")
        .args(["--no-options", "--homedir"])
        .arg(&bob)
        .args(["--batch", "--no-autostart", "--armor", "--export", &bob_fp])
        .output()
        .unwrap();
    assert!(certificate.status.success());
    let mut counter = SystemTimeProvider.unix_timestamp() / 30;
    let began = Instant::now();
    let mut next_code = || {
        counter = counter.max(SystemTimeProvider.unix_timestamp() / 30);
        while counter > SystemTimeProvider.unix_timestamp() / 30 + 1 {
            // Additional fresh MFA logins consume real 30-second TOTP steps.
            // Keep their finite wait inside the existing 300-second native bound.
            assert!(began.elapsed() < Duration::from_secs(210));
            std::thread::sleep(Duration::from_millis(100));
        }
        let code =
            crate::totp::generate_totp_code(RFC_SECRET, counter, TotpPolicy::default()).unwrap();
        counter += 1;
        code
    };
    let change = |action, revision, public_revision, code: &str| {
        f.gateway.change_keys_impl(
            &f.context,
            &f.session,
            &f.token,
            MutationRequest {
                action,
                expected_revision: revision,
                expected_public_revision: public_revision,
                password: PASSWORD,
                totp: code,
            },
        )
    };
    let initial = f.gateway.key_management_state(&f.context, &f.session).state;
    assert!(initial.binding_changes_available && initial.public_key_changes_available);
    assert_eq!(
        initial.bindings.as_ref().unwrap().policy.encryption,
        Requirement::Optional
    );
    let code = next_code();
    assert_eq!(
        change(
            key_management::Action::SetRecipient {
                address: "bob@example.test",
                primary_fingerprint: &bob_fp,
                encryption: Requirement::Optional,
            },
            0,
            None,
            &code
        )
        .result,
        Ok(())
    );
    let first = f.gateway.key_management_state(&f.context, &f.session).state;
    let binding = first.bindings.as_ref().unwrap();
    assert_eq!(binding.revision, 1);
    let recipients = vec!["bob@example.test".into()];
    let preflight = crate::openpgp_bindings::evaluate(
        ACCOUNT,
        binding,
        first.inventory.as_ref().unwrap(),
        Recipients {
            to: &recipients,
            cc: &[],
            bcc: &[],
        },
        Selections::default(),
        SystemTimeProvider.unix_timestamp(),
    )
    .unwrap();
    assert!(preflight.reasons.is_empty());
    assert_eq!(
        change(
            key_management::Action::SetPolicy {
                signing: Requirement::Optional,
                encryption: Requirement::Required,
            },
            1,
            None,
            &code
        )
        .result,
        Err(Error::Authentication)
    );
    assert_eq!(
        change(
            key_management::Action::SetPolicy {
                signing: Requirement::Optional,
                encryption: Requirement::Required,
            },
            1,
            None,
            &next_code()
        )
        .result,
        Ok(())
    );
    let required = f.gateway.key_management_state(&f.context, &f.session).state;
    let preflight = crate::openpgp_bindings::evaluate(
        ACCOUNT,
        required.bindings.as_ref().unwrap(),
        required.inventory.as_ref().unwrap(),
        Recipients {
            to: &recipients,
            cc: &[],
            bcc: &[],
        },
        Selections::default(),
        SystemTimeProvider.unix_timestamp(),
    )
    .unwrap();
    assert!(preflight
        .reasons
        .contains(&crate::openpgp_bindings::BlockReason::EncryptionRequired));
    assert_eq!(
        change(
            key_management::Action::RemoveRecipient {
                address: "bob@example.test"
            },
            2,
            None,
            &next_code()
        )
        .result,
        Ok(())
    );
    let before = f.gateway.key_management_state(&f.context, &f.session).state;
    assert_eq!(
        change(
            key_management::Action::RemovePublic {
                primary_fingerprint: &bob_fp
            },
            3,
            before.public_inventory_revision.as_deref(),
            &next_code()
        )
        .result,
        Ok(())
    );
    let removed = f.gateway.key_management_state(&f.context, &f.session).state;
    assert!(!removed
        .inventory
        .as_ref()
        .unwrap()
        .keys()
        .unwrap()
        .iter()
        .any(|k| k.primary.fingerprint == bob_fp));
    // A fresh authenticated crypto helper opts in to local imported recipients
    // with an EMPTY static recipient list. It grants no signing/decryption.
    let crypto_socket = f.root.join("crypto.sock");
    let crypto_config = f.root.join("crypto.json");
    let crypto_key = f.root.join("crypto-grant");
    let mut crypto_grant = [0; 32];
    getrandom::getrandom(&mut crypto_grant).unwrap();
    fs::write(&crypto_key, crypto_grant).unwrap();
    fs::set_permissions(&crypto_key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&crypto_config, serde_json::to_vec(&serde_json::json!({
        "version":1,"worker":crypto_worker,"engine":engine,"socket":crypto_socket,"trusted_web_uid":uid,
        "accounts":[{"account":ACCOUNT,"home":alice,"signer_fingerprint":null,"decrypt_fingerprints":[],"recipient_fingerprints":[],"allow_imported_recipients":true}],
    })).unwrap()).unwrap();
    fs::set_permissions(&crypto_config, fs::Permissions::from_mode(0o600)).unwrap();
    let mut crypto_service = NativeService(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--ignored"])
            .env("OSMAP_KEYS_NATIVE_SERVICE", "crypto")
            .env("OSMAP_KEYS_NATIVE_CONFIG", &crypto_config)
            .env("OSMAP_KEYS_NATIVE_KEY", &crypto_key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !crypto_socket.exists() {
        assert!(crypto_service.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let crypto_client = crate::openpgp_crypto_runtime::Client::from_operator_files(
        &crypto_socket,
        &crypto_key,
        uid,
    )
    .unwrap();
    let plaintext = b"Synthetic imported-recipient encryption proof; no mail delivery.";
    let encrypt = |fingerprint: String| crate::openpgp_crypto::Operation::Encrypt {
        recipient_fingerprints: vec![fingerprint],
        data: plaintext.to_vec(),
    };
    let absent = "D".repeat(40);
    assert!(!removed
        .inventory
        .as_ref()
        .unwrap()
        .keys()
        .unwrap()
        .iter()
        .any(|key| key.primary.fingerprint == absent));
    assert!(crypto_client
        .execute(ACCOUNT, &encrypt(absent))
        .unwrap()
        .is_err());
    // Bob exists in the OTHER fixture home, but was removed from mapped Alice.
    assert!(crypto_client
        .execute(ACCOUNT, &encrypt(bob_fp.clone()))
        .unwrap()
        .is_err());
    // Exercise an actual multipart .asc upload through parsed HTTP -> selected
    // Runtime -> factor -> native RPC. Text parts retain '+', '&', '=' and UTF-8
    // literally; they must never receive URL-form decoding.
    let uploaded_certificate = std::str::from_utf8(&certificate.stdout).unwrap();
    let boundary = "osmap-native-key-upload";
    let fresh_code = next_code();
    let mut body = String::new();
    for (name, value) in [
        ("key_action", "import_public"),
        ("binding_revision", "3"),
        (
            "public_inventory_revision",
            removed.public_inventory_revision.as_deref().unwrap(),
        ),
        ("expected_primary_fingerprint", bob_fp.as_str()),
        ("current_password", PASSWORD),
        ("totp_code", fresh_code.as_str()),
        ("csrf_token", f.session.record.csrf_token.as_str()),
    ] {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"publickey.cBwZTCpU@protonmail.com-02b34119c22074fc68b10e23e3294df8de68c834.asc\"\r\nContent-Type: application/pgp-keys\r\n\r\n{uploaded_certificate}\r\n--{boundary}--\r\n"));
    let policy = crate::http::HttpPolicy::default();
    let raw = format!(
        "POST /settings/keys/change HTTP/1.1\r\nHost: localhost\r\nOrigin: https://localhost\r\nUser-Agent: Synthetic/Keys-HTTP\r\nCookie: osmap_session={}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n{}",
        f.token.as_str(), body.len(), body,
    );
    let parsed = crate::http_parse::parse_http_request(&raw, &policy).unwrap();
    let response = crate::http::BrowserApp::new(policy, f.gateway.clone())
        .handle_request(&parsed, "127.0.0.1");
    assert_eq!(response.response.status_code, 303);
    let diagnostic = response
        .audit_events
        .iter()
        .find(|event| event.action == "openpgp_key_change_confirmed")
        .unwrap();
    for (name, value) in [
        ("result", "Ok(())".to_string()),
        ("native_operation", "import_public".to_string()),
        ("native_result", "Ok(())".to_string()),
        (
            "public_certificate_bytes",
            uploaded_certificate.trim().len().to_string(),
        ),
    ] {
        assert!(diagnostic
            .fields
            .iter()
            .any(|field| field.key == name && field.value == value));
    }
    let diagnostic_text = format!("{diagnostic:?}");
    assert!(!diagnostic_text.contains(PASSWORD));
    assert!(!diagnostic_text.contains("BEGIN PGP"));
    let restored = f.gateway.key_management_state(&f.context, &f.session).state;
    assert!(restored
        .inventory
        .as_ref()
        .unwrap()
        .keys()
        .unwrap()
        .iter()
        .any(|k| k.primary.fingerprint == bob_fp));
    assert!(restored
        .bindings
        .as_ref()
        .unwrap()
        .recipient_bindings
        .is_empty());
    assert_eq!(
        restored.bindings.as_ref().unwrap().policy.encryption,
        Requirement::Required
    );
    // A successful file import exposes the engine-parsed UID addr-spec. The
    // recipient resolves without another SetRecipient/persisted binding step.
    let inventory = restored.inventory.as_ref().unwrap();
    let imported = inventory
        .keys()
        .unwrap()
        .iter()
        .find(|key| key.primary.fingerprint == bob_fp)
        .unwrap();
    assert_eq!(
        imported
            .email_addresses
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["bob@example.test", "bob.alias@example.test"]),
    );
    let record = restored.bindings.as_ref().unwrap();
    assert!(record.recipient_bindings.is_empty());
    let automatic_recipients: Vec<String> =
        vec!["bob@example.test".into(), "bob.alias@example.test".into()];
    for address in &automatic_recipients {
        assert_eq!(
            record
                .resolve_recipient(inventory, address)
                .unwrap()
                .primary_fingerprint,
            bob_fp
        );
    }
    assert!(matches!(
        record.resolve_recipient(inventory, "revoked@example.test"),
        Err(crate::openpgp_bindings::KeyStatus::MissingBinding)
    ));
    let automatic = crate::openpgp_bindings::evaluate(
        ACCOUNT,
        record,
        inventory,
        Recipients {
            to: &automatic_recipients,
            cc: &[],
            bcc: &[],
        },
        Selections {
            encrypt: true,
            ..Selections::default()
        },
        SystemTimeProvider.unix_timestamp(),
    )
    .unwrap();
    let plan = automatic
        .plan
        .expect("imported UID recipient must produce an encryption plan");
    assert_eq!(
        plan.recipient_fingerprints.as_slice(),
        std::slice::from_ref(&bob_fp)
    );
    let encrypted = crypto_client
        .execute(
            ACCOUNT,
            &crate::openpgp_crypto::Operation::Encrypt {
                recipient_fingerprints: plan.recipient_fingerprints,
                data: plaintext.to_vec(),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(encrypted.operation, "encrypt");
    assert!(encrypted
        .content
        .starts_with(b"-----BEGIN PGP MESSAGE-----"));
    assert!(encrypted.content != plaintext);
    let encryption_subkey = imported.subkeys.iter().find(|key| key.can_encrypt).unwrap();
    assert!(matches!(
        crypto_client
            .execute(ACCOUNT, &encrypt(encryption_subkey.fingerprint.clone()))
            .unwrap(),
        Err(crate::openpgp_crypto::Error::Unsupported)
    ));
    assert!(crypto_client
        .execute(
            ACCOUNT,
            &crate::openpgp_crypto::Operation::Sign {
                signer_fingerprint: bob_fp.clone(),
                data: plaintext.to_vec()
            }
        )
        .is_err());
    assert!(crypto_client
        .execute(
            ACCOUNT,
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![bob_fp.clone()],
                ciphertext: encrypted.content
            }
        )
        .is_err());
    assert!(crate::openpgp_bindings::BindingStore::new(
        f.gateway.settings_dir.join("openpgp-bindings")
    )
    .load(ACCOUNT)
    .unwrap()
    .recipient_bindings
    .is_empty());
    assert!(fs::read(alice.join("trustdb.gpg")).unwrap() == trustdb);
    for (path, bytes) in private {
        assert!(fs::read(path).unwrap() == bytes);
    }
    let personal_code = next_code();
    native_personal_key_journey(
        &f,
        (&worker, &crypto_worker, &engine, &alice),
        &personal_code,
        &mut next_code,
    );
    f.gateway
        .build_session_service()
        .revoke(&f.context, &f.session.record.session_id)
        .unwrap();
    assert_eq!(
        change(key_management::Action::ClearAllBindings, 3, None, "000000").result,
        Err(Error::Authentication)
    );
    assert!(authenticate_count.load(Ordering::SeqCst) > 0);
    assert!(admit_count.load(Ordering::SeqCst) > 0);
    assert!(
        !f.root.join("primary-called").exists(),
        "selected step-up used legacy primary route"
    );
    assert_eq!(
        mutation_listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(selected_primary);
    drop(crypto_service);
    drop(service);
}

// Same real HTTP/session/factor/native-helper fixture, with no preinstalled
// private material in the target. Transport is an explicit Rust capture only.
fn native_personal_key_journey(
    f: &Fixture,
    paths: (
        &std::path::Path,
        &std::path::Path,
        &std::path::Path,
        &std::path::Path,
    ),
    totp: &str,
    next_code: &mut dyn FnMut() -> String,
) {
    use crate::auth::CommandExecutor;
    use crate::openpgp_personal::{PersonalAction, PrivateSession};
    use std::os::unix::fs::DirBuilderExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const TEST: &str =
        "http::http_gateway::http_gateway_keys::tests::native_runtime_key_management_journey";
    let (inventory_worker, crypto_worker, engine, source) = paths;
    let primary = std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap();
    let home = f.root.join("personal-home");
    fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
    struct PersonalAgent(std::path::PathBuf);
    impl Drop for PersonalAgent {
        fn drop(&mut self) {
            let stopped = crate::auth::SystemCommandExecutor
                .run_with_stdin_bytes_timeout_and_output_limit(
                    "/usr/local/bin/gpgconf",
                    &[
                        "--homedir".into(),
                        self.0.to_string_lossy().into_owned(),
                        "--kill".into(),
                        "gpg-agent".into(),
                    ],
                    &[],
                    Duration::from_secs(5),
                    4096,
                );
            let deadline = Instant::now() + Duration::from_secs(1);
            while self.0.join("S.gpg-agent").exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                stopped.is_ok_and(|result| result.status_code == 0)
                    && !self.0.join("S.gpg-agent").exists(),
                "owned personal fixture agent cleanup unconfirmed"
            );
        }
    }
    let _agent = PersonalAgent(home.clone());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(home.join("private-keys-v1.d"))
        .unwrap();
    for name in ["pubring.kbx", "trustdb.gpg"] {
        fs::copy(source.join(name), home.join(name)).unwrap();
        fs::set_permissions(home.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(fs::read_dir(home.join("private-keys-v1.d"))
        .unwrap()
        .next()
        .is_none());
    let grant = f.root.join("personal-grant");
    fs::write(&grant, [59; 32]).unwrap();
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o600)).unwrap();
    let start = |kind: &str, body: serde_json::Value, socket: &std::path::Path| {
        let config = f.root.join(format!("personal-{kind}.json"));
        fs::write(&config, serde_json::to_vec(&body).unwrap()).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let mut service = NativeService(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--ignored"])
                .env("OSMAP_KEYS_NATIVE_SERVICE", kind)
                .env("OSMAP_KEYS_NATIVE_CONFIG", &config)
                .env("OSMAP_KEYS_NATIVE_KEY", &grant)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(service.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        service
    };
    let uid = crate::openbsd::effective_uid();
    let crypto_socket = f.root.join("pc.sock");
    let crypto_service = start(
        "crypto",
        serde_json::json!({
            "version":1,"worker":crypto_worker,"engine":engine,"socket":crypto_socket,"trusted_web_uid":uid,
            "accounts":[{"account":ACCOUNT,"home":home,"signer_fingerprint":primary,"decrypt_fingerprints":[primary],"recipient_fingerprints":[primary],"allow_web_personal_keys":true}]
        }),
        &crypto_socket,
    );
    let inventory_socket = f.root.join("pi.sock");
    let inventory_service = start(
        "inventory",
        serde_json::json!({
            "version":1,"worker":inventory_worker,"engine":"/usr/local/bin/gpg","socket":inventory_socket,"trusted_web_uid":uid,
            "accounts":[{"account":ACCOUNT,"home":home}]
        }),
        &inventory_socket,
    );
    let admin_socket = f.root.join("pa.sock");
    let admin_state = f.root.join("personal-admin-state");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&admin_state)
        .unwrap();
    let admin_service = start(
        "admin",
        serde_json::json!({
            "version":1,"worker":inventory_worker,"engine":engine,"socket":admin_socket,"trusted_web_uid":uid,"state_directory":admin_state,
            "accounts":[{"account":ACCOUNT,"home":home}]
        }),
        &admin_socket,
    );
    let client =
        crate::openpgp_crypto_runtime::Client::from_operator_files(&crypto_socket, &grant, uid)
            .unwrap();
    let mut gateway = f.gateway.clone();
    gateway.crypto_client = Some(client.clone());
    gateway.public_inventory_client = Some(
        crate::openpgp_inventory_runtime::Client::from_operator_files(
            &inventory_socket,
            &grant,
            uid,
        )
        .unwrap(),
    );
    gateway.public_admin_client = Some(
        crate::openpgp_public_admin_runtime::Client::from_operator_files(
            &admin_socket,
            &grant,
            uid,
        )
        .unwrap(),
    );
    let inventory = gateway.inventory_client().unwrap().read(ACCOUNT).unwrap();
    let store =
        crate::openpgp_bindings::BindingStore::new(gateway.settings_dir.join("openpgp-bindings"));
    let old = store.load(ACCOUNT).unwrap();
    let bound = store
        .replace_operator(
            ACCOUNT,
            old.revision,
            crate::openpgp_bindings::Update {
                account_binding: Some(crate::openpgp_bindings::AccountBinding {
                    primary_fingerprint: primary.clone(),
                    signing_fingerprint: Some(primary.clone()),
                    decrypt_primary_fingerprints: vec![primary.clone()],
                }),
                recipient_bindings: vec![],
                policy: crate::openpgp_bindings::ProtectionPolicy::default(),
            },
            &inventory,
            SystemTimeProvider.unix_timestamp(),
        )
        .unwrap();
    let private_session = PrivateSession {
        session_id: f.session.record.session_id.clone(),
        account_epoch: f.session.record.account_epoch,
        expires_at: f.session.record.expires_at,
    };
    assert!(
        !client
            .personal(ACCOUNT, &private_session, PersonalAction::Status)
            .unwrap()
            .installed
    );
    let exported = crate::auth::SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/gpg",
            &[
                "--no-options".into(),
                "--homedir".into(),
                source.to_string_lossy().into_owned(),
                "--batch".into(),
                "--no-autostart".into(),
                "--armor".into(),
                "--export-secret-keys".into(),
                primary.clone(),
            ],
            &[],
            Duration::from_secs(10),
            crate::openpgp_personal::MAX_CERTIFICATE,
        )
        .unwrap();
    assert_eq!(exported.status_code, 0);
    let mut certificate = exported.stdout.into_bytes();
    assert!(certificate.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    let app = crate::http::BrowserApp::new(
        crate::http::HttpPolicy {
            secure_session_cookie: true,
            ..Default::default()
        },
        gateway,
    );
    let fields = format!("--personal-native\r\nContent-Disposition: form-data; name=\"key_action\"\r\n\r\nimport_personal\r\n--personal-native\r\nContent-Disposition: form-data; name=\"binding_revision\"\r\n\r\n{}\r\n--personal-native\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{}\r\n--personal-native\r\nContent-Disposition: form-data; name=\"current_password\"\r\n\r\n{PASSWORD}\r\n--personal-native\r\nContent-Disposition: form-data; name=\"totp_code\"\r\n\r\n{totp}\r\n--personal-native\r\nContent-Disposition: form-data; name=\"key_passphrase\"\r\n\r\n\r\n--personal-native\r\nContent-Disposition: form-data; name=\"personal_certificate\"; filename=\"own.ASC\"\r\nContent-Type: application/pgp-keys\r\n\r\n", bound.revision, f.session.record.csrf_token);
    let mut upload = fields.into_bytes();
    upload.extend_from_slice(&certificate);
    upload.extend_from_slice(b"\r\n--personal-native--\r\n");
    let raw = format!("POST /settings/keys/change HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nUser-Agent: {}\r\nCookie: osmap_session={}\r\nContent-Type: multipart/form-data; boundary=personal-native\r\nContent-Length: {}\r\n\r\n", f.context.user_agent, f.token.as_str(), upload.len());
    let mut raw = raw.into_bytes();
    raw.extend_from_slice(&upload);
    let mut request = crate::http::parse_http_request_bytes(&raw, app.policy()).unwrap();
    let imported = app.handle_request(&request, "127.0.0.1");
    crate::openpgp_personal::clear(&mut request.body);
    crate::openpgp_personal::clear(&mut certificate);
    crate::openpgp_personal::clear(&mut upload);
    crate::openpgp_personal::clear(&mut raw);
    assert_eq!(imported.response.status_code, 303);
    let state = client
        .personal(ACCOUNT, &private_session, PersonalAction::Status)
        .unwrap();
    assert!(state.installed && !state.protected_at_rest);
    let post = |action: &str| {
        let body = format!(
            "key_action={action}&binding_revision={}&csrf_token={}&key_passphrase=",
            bound.revision, f.session.record.csrf_token
        );
        let body = if action == "lock_personal" {
            body.trim_end_matches("&key_passphrase=").to_owned()
        } else {
            body
        };
        let raw = format!("POST /settings/keys/change HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nUser-Agent: {}\r\nCookie: osmap_session={}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", f.context.user_agent, f.token.as_str(), body.len());
        let request = crate::http::parse_http_request(&raw, app.policy()).unwrap();
        app.handle_request(&request, "127.0.0.1")
    };
    assert_eq!(post("unlock_personal").response.status_code, 303);
    assert!(
        client
            .personal(ACCOUNT, &private_session, PersonalAction::Status)
            .unwrap()
            .unlocked_for_session
    );
    let other = app
        .gateway
        .build_session_service()
        .issue_with_epoch(
            &f.context,
            ACCOUNT,
            RequiredSecondFactor::Totp,
            f.session.record.account_epoch,
        )
        .unwrap();
    let foreign = PrivateSession {
        session_id: other.record.session_id,
        account_epoch: other.record.account_epoch,
        expires_at: other.record.expires_at,
    };
    let sign = crate::openpgp_crypto::Operation::Sign {
        signer_fingerprint: primary.clone(),
        data: b"personal private operation".to_vec(),
    };
    assert!(!matches!(
        client.for_session(foreign).execute(ACCOUNT, &sign),
        Ok(Ok(_))
    ));
    #[derive(Default)]
    struct Capture(std::cell::RefCell<Vec<Vec<u8>>>);
    impl crate::send::SubmissionBackend for &Capture {
        fn submit_message(
            &self,
            _: &str,
            _: &crate::send::ComposeRequest,
        ) -> Result<(), crate::send::SubmissionBackendError> {
            panic!("personal selected signing must use prepared bytes")
        }
        fn submit_prepared_message(
            &self,
            account: &str,
            request: &crate::send::ComposeRequest,
            prepared: &crate::protected_submission::PreparedSubmission,
        ) -> Result<(), crate::send::SubmissionBackendError> {
            assert_eq!(account, ACCOUNT);
            prepared
                .validate_for(
                    &crate::identity::CanonicalUsername::parse(account).unwrap(),
                    request,
                )
                .unwrap();
            assert!(prepared.as_bytes().len() <= crate::pgp_mime::MAX_PGP_MIME_BYTES);
            self.0.borrow_mut().push(prepared.as_bytes().to_vec());
            Ok(())
        }
    }
    let capture = Capture::default();
    let submission = crate::send::SubmissionService::new(&capture);
    let append = crate::mailbox::DoveadmMessageAppendBackend::new(
        crate::auth::SystemCommandExecutor,
        "/usr/bin/false",
    );
    let intent = crate::send_journal::mint_intent(SystemTimeProvider.unix_timestamp()).unwrap();
    let send = || BrowserSendRequest {
        sender_id: None,
        send_intent: &intent,
        draft_id: None,
        draft_revision: None,
        recipients: "unregistered@example.test",
        cc_recipients: "",
        bcc_recipients: "",
        subject: "Personal native sign",
        body: "Personal native clear body",
        body_format: crate::compose_format::BodyFormat::Plain,
        attachments: &[],
        reply_thread: None,
        protection: crate::send::ProtectionIntent {
            sign: true,
            binding_revision: Some(bound.revision),
            ..Default::default()
        },
    };
    let sent = app.gateway.send_message_with_backends(
        &f.context,
        &f.session,
        send(),
        &submission,
        &append,
    );
    assert!(matches!(
        sent.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: false,
            receipt_persisted: true
        }
    ));
    assert_eq!(capture.0.borrow().len(), 1);
    let wire = capture.0.borrow()[0].clone();
    let crate::pgp_mime::PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = crate::pgp_mime::classify(&wire, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("personal gateway must emit signed MIME")
    };
    assert!(std::str::from_utf8(&canonical_entity)
        .unwrap()
        .contains("openpgp-public-key.asc"));
    let raw_entity = std::str::from_utf8(&canonical_entity).unwrap();
    let (headers, body) = raw_entity.split_once("\r\n\r\n").unwrap();
    let signed_message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "Sent".into(),
        uid: 1,
        flags: vec![],
        date_received: String::new(),
        size_virtual: canonical_entity.len() as u64,
        header_block: headers.into(),
        body_text: body.into(),
    };
    let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&signed_message)
        .unwrap();
    let attached = analysis
        .attachments
        .iter()
        .find(|attachment| attachment.filename.as_deref() == Some("openpgp-public-key.asc"))
        .unwrap();
    let public_certificate = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(&signed_message, &attached.part_path)
    .unwrap();
    crate::protected_submission::native_tests::verify_with_only_attached_certificate(
        &f.root,
        &public_certificate.body,
        &canonical_entity,
        &signature,
        &primary,
    );
    assert_eq!(
        client
            .execute(
                ACCOUNT,
                &crate::openpgp_crypto::Operation::Verify {
                    data: canonical_entity,
                    signature
                }
            )
            .unwrap()
            .unwrap()
            .signature,
        crate::openpgp_crypto::SignatureState::Valid
    );
    let plaintext =
        b"Content-Type: text/plain; charset=UTF-8\r\n\r\nPersonal encrypted reader body\r\n";
    let encrypted = client
        .execute(
            ACCOUNT,
            &crate::openpgp_crypto::Operation::Encrypt {
                recipient_fingerprints: vec![primary.clone()],
                data: plaintext.to_vec(),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .for_session(private_session.clone())
            .execute(
                ACCOUNT,
                &crate::openpgp_crypto::Operation::Decrypt {
                    allowed_primary_fingerprints: vec![primary.clone()],
                    ciphertext: encrypted.content.clone()
                }
            )
            .unwrap()
            .unwrap()
            .content,
        plaintext
    );
    let mime = crate::pgp_mime::build_encrypted(
        &encrypted.content,
        "personal-native-reader",
        crate::pgp_mime::PgpMimePolicy::default(),
    )
    .unwrap();
    let raw = std::str::from_utf8(&mime).unwrap();
    let (header, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "INBOX".into(),
        uid: 1,
        flags: vec![],
        date_received: String::new(),
        size_virtual: mime.len() as u64,
        header_block: header.into(),
        body_text: body.into(),
    };
    let rendered = app
        .gateway
        .render_protected_snapshot(
            &f.context,
            &f.session,
            &message,
            crate::rendering::RenderingPolicy::default(),
        )
        .unwrap();
    assert!(rendered
        .body_html
        .as_str()
        .contains("Personal encrypted reader body"));
    assert!(
        rendered.body_text_for_compose.is_empty(),
        "reader plaintext must not enter the compose projection"
    );
    assert!(matches!(rendered.openpgp,
        Some(crate::openpgp_reader_ui::ReaderState::Assessed(ref protection))
            if protection.decrypted_on_mail_host
                && protection.signature == crate::protected_message::SignatureValidity::Unsigned
    ));
    assert_eq!(post("lock_personal").response.status_code, 303);
    assert!(
        !client
            .personal(ACCOUNT, &private_session, PersonalAction::Status)
            .unwrap()
            .unlocked_for_session
    );
    assert!(!matches!(
        client
            .for_session(private_session.clone())
            .execute(ACCOUNT, &sign),
        Ok(Ok(_))
    ));
    assert!(!matches!(
        client.for_session(private_session.clone()).execute(
            ACCOUNT,
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![primary],
                ciphertext: encrypted.content
            }
        ),
        Ok(Ok(_))
    ));
    app.gateway
        .send_message_with_backends(&f.context, &f.session, send(), &submission, &append);
    assert_eq!(
        capture.0.borrow().len(),
        1,
        "recorded send never duplicates after lock"
    );
    // Real route -> password/TOTP admission -> newly issued session -> native
    // helper restoration. No password or TOTP is bypassed by the key cookie.
    let remembered = post("unlock_personal&remember_key=1");
    assert_eq!(remembered.response.status_code, 303);
    let key_cookie = remembered
        .response
        .headers
        .iter()
        .find(|(name, value)| name == "Set-Cookie" && value.starts_with("__Host-osmap_key_access="))
        .unwrap()
        .1
        .clone();
    assert!(
        key_cookie.contains("Secure")
            && key_cookie.contains("HttpOnly")
            && key_cookie.contains("SameSite=Strict")
    );
    let key_cookie = key_cookie.split(';').next().unwrap();
    let original_until = client
        .personal(ACCOUNT, &private_session, PersonalAction::Status)
        .unwrap()
        .remembered_until
        .unwrap();
    let login = |code: &str| {
        let password: String = PASSWORD.bytes().map(|b| format!("%{b:02X}")).collect();
        let body = format!("username={ACCOUNT}&password={password}&totp_code={code}");
        let raw = format!("POST /login HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nUser-Agent: {}\r\nCookie: {key_cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", f.context.user_agent, body.len());
        app.handle_request(
            &crate::http::parse_http_request(&raw, app.policy()).unwrap(),
            "127.0.0.1",
        )
    };
    assert_eq!(
        login("").response.status_code,
        401,
        "remembered key never bypasses TOTP"
    );
    let signed_in = login(&next_code());
    assert_eq!(signed_in.response.status_code, 303);
    let auth_cookie = signed_in
        .response
        .headers
        .iter()
        .find(|(name, value)| name == "Set-Cookie" && value.starts_with("osmap_session="))
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap();
    let auth_token = auth_cookie.split_once('=').unwrap().1;
    let validated = app.gateway.validate_session(&f.context, auth_token);
    let BrowserSessionDecision::Valid {
        validated_session: restored,
    } = validated.decision
    else {
        panic!("fresh login must validate")
    };
    let restored_private = RuntimeBrowserGateway::private_key_session(&restored);
    let restored_state = client
        .personal(ACCOUNT, &restored_private, PersonalAction::Status)
        .unwrap();
    assert!(restored_state.unlocked_for_session);
    assert_eq!(restored_state.remembered_until, Some(original_until));
    assert!(matches!(
        client
            .for_session(restored_private.clone())
            .execute(ACCOUNT, &sign),
        Ok(Ok(_))
    ));
    // Logout without a live authentication cookie still removes remembered
    // authority; replay plus another correct MFA login cannot restore it.
    let raw = format!("POST /logout HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nCookie: {key_cookie}\r\nContent-Length: 0\r\n\r\n");
    let logged_out = app.handle_request(
        &crate::http::parse_http_request(&raw, app.policy()).unwrap(),
        "127.0.0.1",
    );
    assert!(logged_out
        .response
        .headers
        .iter()
        .any(|(name, value)| name == "Set-Cookie"
            && value.starts_with("__Host-osmap_key_access=;")
            && value.contains("Max-Age=0")));
    assert!(!matches!(
        client.for_session(restored_private).execute(ACCOUNT, &sign),
        Ok(Ok(_))
    ));
    let replay = login(&next_code());
    assert_eq!(
        replay.response.status_code, 303,
        "ordinary MFA login still succeeds"
    );
    let replay_token = replay
        .response
        .headers
        .iter()
        .find(|(name, value)| name == "Set-Cookie" && value.starts_with("osmap_session="))
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1;
    let BrowserSessionDecision::Valid {
        validated_session: replay_session,
    } = app
        .gateway
        .validate_session(&f.context, replay_token)
        .decision
    else {
        panic!("MFA login")
    };
    assert!(
        !client
            .personal(
                ACCOUNT,
                &RuntimeBrowserGateway::private_key_session(&replay_session),
                PersonalAction::Status
            )
            .unwrap()
            .unlocked_for_session
    );
    assert_eq!(post("lock_personal").response.status_code, 303);
    drop(app);
    drop(admin_service);
    drop(inventory_service);
    drop(crypto_service);
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("RETAINED_PRIVATE_KEYS_FIXTURE={}", self.root.display());
            return;
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn revoked_stored_session_refuses_key_mutation_before_primary_or_key_effect() {
    let f = Fixture::new();
    f.gateway
        .build_session_service()
        .revoke(&f.context, &f.session.record.session_id)
        .unwrap();
    let result = f
        .gateway
        .change_keys_impl(&f.context, &f.session, &f.token, f.request(&f.code()));
    assert_eq!(result.result, Err(Error::Authentication));
    assert!(!f.root.join("primary-called").exists());
    assert!(!f.gateway.settings_dir.join("openpgp-bindings").exists());
}

#[test]
fn current_stored_session_reaches_fresh_auth_without_claiming_missing_key_backend_success() {
    let f = Fixture::new();
    let result = f
        .gateway
        .change_keys_impl(&f.context, &f.session, &f.token, f.request(&f.code()));
    assert_eq!(result.result, Err(Error::Unavailable));
    let diagnostic = result
        .audit_events
        .iter()
        .find(|event| event.action == "openpgp_key_change_refused")
        .unwrap();
    assert!(diagnostic
        .fields
        .iter()
        .any(|field| field.key == "result" && field.value == "Err(Unavailable)"));
    assert!(!diagnostic
        .fields
        .iter()
        .any(|field| field.key == "native_operation"));
    assert_eq!(fs::read(f.root.join("primary-called")).unwrap(), b"called");
}

#[test]
fn key_change_keeps_the_actual_session_lock_during_fresh_authentication() {
    use std::time::{Duration, Instant};
    let f = Fixture::new();
    fs::write(f.root.join("hold-auth"), b"hold").unwrap();
    let gateway = f.gateway.clone();
    let context = f.context.clone();
    let session = f.session.clone();
    let token = f.token.clone();
    let code = f.code();
    let mutation = std::thread::spawn(move || {
        gateway.change_keys_impl(
            &context,
            &session,
            &token,
            MutationRequest {
                action: key_management::Action::ClearAccount,
                expected_revision: 0,
                expected_public_revision: None,
                password: PASSWORD,
                totp: &code,
            },
        )
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !f.root.join("primary-called").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(FileSessionStore::new(&f.gateway.session_dir).lock_path())
        .unwrap();
    assert!(crate::openbsd::try_advisory_file_lock_exclusive(&lock).is_err());
    fs::write(f.root.join("release-auth"), b"continue").unwrap();
    assert_eq!(mutation.join().unwrap().result, Err(Error::Unavailable));
    assert!(crate::openbsd::try_advisory_file_lock_exclusive(&lock).is_ok());
}

#[test]
fn a_different_genuine_session_token_cannot_authorize_the_captured_account() {
    let f = Fixture::new();
    let other = f
        .gateway
        .build_session_service()
        .issue(&f.context, "bob@example.test", RequiredSecondFactor::Totp)
        .unwrap();
    let result =
        f.gateway
            .change_keys_impl(&f.context, &f.session, &other.token, f.request(&f.code()));
    assert_eq!(result.result, Err(Error::Stale));
    assert!(!f.root.join("primary-called").exists());
}

#[test]
fn failed_cached_admin_can_use_independently_authenticated_read_only_inventory() {
    use crate::openpgp_inventory_runtime::{read_frame, write_frame};
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};
    // This read-only RPC test needs only private paths, not password/TOTP or
    // a freshly written authentication executable. Keep failures in this owned
    // directory for inspection; successful cleanup follows the joined server.
    use std::os::unix::fs::DirBuilderExt;
    let root = std::env::temp_dir().join(format!(
        "osmap-inventory-read-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let grant = root.join("inventory-grant");
    fs::write(&grant, [43; 32]).unwrap();
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o600)).unwrap();
    let stale_socket = root.join("admin.sock");
    let stale_listener = UnixListener::bind(&stale_socket).unwrap();
    fs::set_permissions(&stale_socket, fs::Permissions::from_mode(0o600)).unwrap();
    let admin = crate::openpgp_public_admin_runtime::Client::from_operator_files(
        &stale_socket,
        &grant,
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    drop(stale_listener);
    let socket = root.join("inventory.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let inventory = crate::openpgp_inventory_runtime::Client::from_operator_files(
        &socket,
        &grant,
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let bytes = read_frame(&mut stream, 2048, deadline).unwrap();
                    let now = SystemTimeProvider.unix_timestamp();
                    let request = crate::openpgp_inventory_protocol::Verifier::default()
                        .request(&bytes, ACCOUNT, &[43; 32], now)
                        .unwrap();
                    let empty = crate::openpgp_inventory::Inventory::parse(
                        br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]}"#,
                    ).unwrap();
                    let response = request.response(&empty, &[43; 32], now).unwrap();
                    write_frame(&mut stream, &response, deadline).unwrap();
                    return true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return false,
            }
        }
        false
    });
    let diagnostic = std::cell::Cell::new(None);
    let backend = KeyBackend {
        inventory: Some(&inventory),
        admin: Some(&admin),
        diagnostic: &diagnostic,
    };
    let result = backend.read(ACCOUNT);
    let served = server.join().unwrap();
    assert!(result.is_ok());
    assert!(served);
    assert!(result.unwrap().keys().unwrap().is_empty());
    fs::remove_dir_all(&root).unwrap();
    assert!(!root.exists());
}
