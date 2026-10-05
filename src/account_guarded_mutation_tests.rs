use super::*;
use crate::account_admission::{Admission, EpochAuthority};
use crate::auth::*;
use crate::password_change::{self, EpochPrimaryBackend};
use crate::session::{
    FileSessionStore, SessionService, SessionStore, SessionToken, SystemRandomSource,
    ValidatedSession,
};
use crate::totp::TimeProvider;
use std::sync::Arc;
const KEY: [u8; 32] = [17; 32];
const SESSION_KEY: [u8; 32] = [19; 32];
const ACCOUNT: &str = "alice@example.test";
struct Clock;
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        100
    }
}
struct Epoch;
impl EpochAuthority for Epoch {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        if account == ACCOUNT && epoch == 3 {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
impl PrimaryCredentialBackend for Epoch {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        account: &str,
        _: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        Ok(PrimaryAuthVerdict::Accept {
            canonical_username: account.into(),
        })
    }
}
impl EpochPrimaryBackend for Epoch {
    fn captured_admission(&self) -> Result<Admission, password_change::Error> {
        Ok(Admission {
            account: ACCOUNT.into(),
            epoch: 3,
        })
    }
}
struct Factor;
impl SecondFactorVerifier for Factor {
    fn verify_second_factor(
        &self,
        _: &str,
        _: RequiredSecondFactor,
        _: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        Ok(SecondFactorVerdict::Accept)
    }
}
struct Fixture {
    root: std::path::PathBuf,
    context: AuthenticationContext,
    token: SessionToken,
    session: ValidatedSession,
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::path::Path::new("/tmp").join(format!("osmap-guarded-proof-{}", hex(&nonce)));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "public-guarded-request",
            "127.0.0.1",
            "Fixture/Test",
        )
        .unwrap();
        let service = SessionService::new(
            FileSessionStore::new(&root),
            Clock,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(Arc::new(Epoch));
        let issued = service
            .issue_with_epoch(&context, ACCOUNT, RequiredSecondFactor::Totp, Some(3))
            .unwrap();
        Self {
            root,
            context,
            token: issued.token,
            session: ValidatedSession {
                record: issued.record,
                audit_event: issued.audit_event,
            },
        }
    }
    fn service(&self) -> SessionService<FileSessionStore, Clock, SystemRandomSource> {
        SessionService::new(
            FileSessionStore::new(&self.root),
            Clock,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(Arc::new(Epoch))
    }
    fn request(&self) -> Request {
        let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor);
        let rate = crate::password_change_rate::Store::new(self.root.join("rate"));
        let prepared = password_change::prepare(
            password_change::Services {
                primary: &Epoch,
                factor: &factor,
                epoch: &Epoch,
                rate: &rate,
                clock: &Clock,
                policy: AuthenticationPolicy::default(),
            },
            password_change::Attempt {
                context: &self.context,
                session: &self.session,
                request: password_change::Request::new(
                    "public-old-value",
                    "public-new-passphrase",
                    "public-new-passphrase",
                    "123456",
                )
                .unwrap(),
            },
        )
        .authorization
        .unwrap();
        Request::issue(
            prepared
                .into_dispatch(&self.context, &self.session, &Epoch, &Clock)
                .unwrap(),
            &KEY,
            100,
        )
        .unwrap()
    }
    fn frame(&self) -> Vec<u8> {
        let request = self.request();
        self.service()
            .with_guarded_session_lease(&self.context, &self.token, |_, lease| {
                let original = Instant::now() + std::time::Duration::from_secs(1);
                let guarded = lease
                    .authorize_at(request, &KEY, &SESSION_KEY, original, 100000)
                    .unwrap();
                assert_eq!(guarded.deadline(), original);
                assert_eq!(
                    guarded.request().session_id(),
                    self.session.record.session_id
                );
                assert!(self
                    .service()
                    .with_guarded_validated_session(&self.context, &self.token, |_| ())
                    .is_err());
                assert!(!format!("{guarded:?}").contains("public-old-value"));
                guarded.bytes().to_vec()
            })
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn python(raw: &[u8], at: u64) -> serde_json::Value {
    let input =
        serde_json::to_vec(&serde_json::json!({"raw_hex":hex(raw),"now_millis":at})).unwrap();
    serde_json::from_slice(&crate::auth::guarded_mutation_fixture(&input).unwrap()).unwrap()
}
#[test]
fn actual_stored_locked_session_assertion_authenticates_exact_python_action() {
    let f = Fixture::new();
    let bytes = f.frame();
    let result = python(&bytes, 100001);
    assert_eq!(result["accepted"], true);
    assert_eq!(result["current_action"], true);
    assert_eq!(result["copied_action"], false);
    assert_eq!(result["epoch"], 3);
}
#[test]
fn actual_guarded_client_exchange_retains_current_store_lock_until_sealed_receipt() {
    use crate::openpgp_inventory_runtime::{read_frame, write_frame};
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let f = Fixture::new();
    let socket = f.root.join("mutation.sock");
    let key = f.root.join("mutation.key");
    std::fs::write(&key, KEY).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    let client = crate::account_mutation_client::Client::guarded_fixture_files(
        &socket,
        &key,
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    let root = f.root.clone();
    let context = f.context.clone();
    let token = f.token.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(
            crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
            crate::openbsd::effective_uid()
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        assert_eq!(python(&raw, 100001)["accepted"], true);
        let contending = SessionService::new(
            FileSessionStore::new(root),
            Clock,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(Arc::new(Epoch));
        assert!(contending
            .with_guarded_validated_session(&context, &token, |_| ())
            .is_err());
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let input=serde_json::to_vec(&serde_json::json!({"raw_hex":v["budget"]["request_hex"],"now":100,"mode":"response","outcome":{"status":"known_refused"}})).unwrap();
        // Exact compatibility codec only; no coordinator or synthetic True
        // authorization substitutes for the independently verified session proof.
        let output = crate::auth::mutation_compatibility_fixture(&input).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(v["accepted"], true);
        let hex = v["response_hex"].as_str().unwrap();
        let reply: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        write_frame(&mut stream, &reply, deadline).unwrap();
    });
    let request = f.request();
    let receipt = f
        .service()
        .with_guarded_session_lease(&f.context, &f.token, |_, lease| {
            let action = lease
                .authorize_at(
                    request,
                    &KEY,
                    &SESSION_KEY,
                    Instant::now() + std::time::Duration::from_secs(1),
                    100000,
                )
                .unwrap();
            client.guarded_fixture_exchange(action, &Clock)
        })
        .unwrap()
        .unwrap();
    assert!(matches!(
        receipt.outcome(),
        crate::account_mutation::Outcome::KnownRefused
    ));
    server.join().unwrap();
    f.service()
        .with_guarded_validated_session(&f.context, &f.token, |_| ())
        .unwrap();
}
#[test]
fn ordinary_request_mac_cannot_replace_independent_session_assertion() {
    let f = Fixture::new();
    let raw = f.frame();
    for (field, value) in [
        ("account", serde_json::json!("bob@example.test")),
        ("epoch", serde_json::json!(4)),
        ("session_id", serde_json::json!("0".repeat(64))),
        ("source", serde_json::json!("127.0.0.2")),
        ("request_id", serde_json::json!("other")),
        ("intent_reference", serde_json::json!("0".repeat(64))),
        ("request_sha256", serde_json::json!("0".repeat(64))),
        ("budget_sha256", serde_json::json!("0".repeat(64))),
        ("deadline_millis", serde_json::json!(102000)),
        ("signature", serde_json::json!("0".repeat(64))),
        ("checked_millis", serde_json::json!(true)),
        ("extra", serde_json::json!(true)),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        v["session_proof"][field] = value;
        assert_eq!(
            python(&serde_json::to_vec(&v).unwrap(), 100001)["accepted"],
            false,
            "{field}"
        );
    }
    let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v.as_object_mut().unwrap().remove("session_proof");
    assert_eq!(
        python(&serde_json::to_vec(&v).unwrap(), 100001)["accepted"],
        false
    );
    assert_eq!(python(&raw, 99999)["accepted"], false);
    assert_eq!(python(&raw, 101000)["accepted"], false);
    for malformed in [
        b"{}".to_vec(),
        b"{\"budget\":{},\"budget\":{}}".to_vec(),
        vec![b'x'; MAX_FRAME + 1],
    ] {
        assert_eq!(python(&malformed, 100001)["accepted"], false);
    }
}
#[test]
fn revoked_or_changed_stored_authority_cannot_mint_session_proof() {
    for variant in 0..3 {
        let f = Fixture::new();
        let request = f.request();
        let store = FileSessionStore::new(&f.root);
        let mut record = store.load(&f.session.record.session_id).unwrap().unwrap();
        match variant {
            0 => record.revoked_at = Some(100),
            1 => record.account_epoch = Some(4),
            _ => record.canonical_username = "bob@example.test".into(),
        };
        store.save(&record).unwrap();
        let result = f
            .service()
            .with_guarded_session_lease(&f.context, &f.token, |_, lease| {
                let _ = lease.authorize_at(
                    request,
                    &KEY,
                    &SESSION_KEY,
                    Instant::now() + std::time::Duration::from_secs(1),
                    100000,
                );
                panic!("stored authority refusal must happen before proof issuer")
            });
        assert!(result.is_err());
    }
}
#[test]
fn expired_deadline_other_request_or_same_key_cannot_mint_proof() {
    for variant in 0..4 {
        let f = Fixture::new();
        let request = if variant == 0 {
            crate::account_mutation::tests::issue(
                "public-old-value",
                "public-new-passphrase",
                3,
                100,
            )
            .unwrap()
        } else {
            f.request()
        };
        let result = f
            .service()
            .with_guarded_session_lease(&f.context, &f.token, |_, lease| {
                let deadline = if variant == 1 {
                    Instant::now()
                } else {
                    Instant::now() + std::time::Duration::from_secs(1)
                };
                let at = if variant == 2 { 2000000 } else { 100000 };
                lease
                    .authorize_at(
                        request,
                        &KEY,
                        if variant == 3 { &KEY } else { &SESSION_KEY },
                        deadline,
                        at,
                    )
                    .is_err()
            })
            .unwrap();
        assert!(result);
    }
}
