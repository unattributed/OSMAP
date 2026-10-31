use super::*;
use crate::session::SessionToken;
use crate::totp::TimeProvider as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const ACCOUNT: &str = "alice@example.test";
const PASSWORD: &str = "public synthetic key fixture password";
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

/// Current application adapter and real factor/session/admin stores. The
/// primary-credential process is deliberately synthetic, not live Dovecot.
#[test]
#[ignore = "requires disposable OpenBSD keyboxes and real public-admin worker"]
fn native_runtime_key_management_journey() {
    use crate::openpgp_bindings::{Recipients, Requirement, Selections};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    const TEST: &str =
        "http::http_gateway::http_gateway_keys::tests::native_runtime_key_management_journey";
    assert_eq!(std::env::consts::OS, "openbsd");
    if std::env::var_os("OSMAP_KEYS_NATIVE_SERVICE").is_some() {
        crate::openpgp_public_admin_runtime::Service::from_operator_files(
            &PathBuf::from(std::env::var_os("OSMAP_KEYS_NATIVE_CONFIG").unwrap()),
            &PathBuf::from(std::env::var_os("OSMAP_KEYS_NATIVE_KEY").unwrap()),
        )
        .unwrap()
        .serve()
        .unwrap();
        return;
    }
    let setting = |name| PathBuf::from(std::env::var_os(name).unwrap());
    let worker = setting("OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER");
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
    let mut f = Fixture::at(fixture.join("runtime-keys"));
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
            assert!(began.elapsed() < Duration::from_secs(120));
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
    assert_eq!(
        change(
            key_management::Action::ImportPublic {
                certificate: &certificate.stdout,
                expected_primary_fingerprint: &bob_fp,
            },
            3,
            removed.public_inventory_revision.as_deref(),
            &next_code()
        )
        .result,
        Ok(())
    );
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
    assert!(fs::read(alice.join("trustdb.gpg")).unwrap() == trustdb);
    for (path, bytes) in private {
        assert!(fs::read(path).unwrap() == bytes);
    }
    f.gateway
        .build_session_service()
        .revoke(&f.context, &f.session.record.session_id)
        .unwrap();
    assert_eq!(
        change(key_management::Action::ClearAllBindings, 3, None, "000000").result,
        Err(Error::Authentication)
    );
    drop(service);
}
impl Drop for Fixture {
    fn drop(&mut self) {
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
    let f = Fixture::new();
    let grant = f.root.join("inventory-grant");
    fs::write(&grant, [43; 32]).unwrap();
    fs::set_permissions(&grant, fs::Permissions::from_mode(0o600)).unwrap();
    let stale_socket = f.root.join("admin.sock");
    let stale_listener = UnixListener::bind(&stale_socket).unwrap();
    fs::set_permissions(&stale_socket, fs::Permissions::from_mode(0o600)).unwrap();
    let admin = crate::openpgp_public_admin_runtime::Client::from_operator_files(
        &stale_socket,
        &grant,
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    drop(stale_listener);
    let socket = f.root.join("inventory.sock");
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
    let backend = KeyBackend {
        inventory: Some(&inventory),
        admin: Some(&admin),
    };
    let result = backend.read(ACCOUNT);
    let served = server.join().unwrap();
    assert!(result.is_ok());
    assert!(served);
    assert!(result.unwrap().keys().unwrap().is_empty());
}
