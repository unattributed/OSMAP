use super::*;
use crate::auth::{
    PrimaryAuthBackendError, PrimaryAuthVerdict, SecondFactorBackendError, SecondFactorVerdict,
};
use crate::config::LogLevel;
use crate::logging::EventCategory;
use crate::session::SessionRecord;
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osmap-key-management-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "keys-test",
        "127.0.0.1",
        "test",
    )
    .unwrap()
}
use crate::auth::AuthenticationPolicy;
fn session() -> ValidatedSession {
    ValidatedSession {
        record: SessionRecord {
            session_id: "A".repeat(64),
            csrf_token: "B".repeat(64),
            canonical_username: "alice@example.test".into(),
            issued_at: 10,
            expires_at: 100,
            last_seen_at: 20,
            revoked_at: None,
            remote_addr: "127.0.0.1".into(),
            user_agent: "test".into(),
            factor: RequiredSecondFactor::Totp,
        },
        audit_event: LogEvent::new(LogLevel::Info, EventCategory::Session, "test", "test"),
    }
}
struct Primary {
    verdict: Result<PrimaryAuthVerdict, PrimaryAuthBackendError>,
}
impl PrimaryCredentialBackend for Primary {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        username: &str,
        password: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        assert_eq!(username, "alice@example.test");
        assert_eq!(password, "fixture-password");
        self.verdict.clone()
    }
}
struct Factor(Cell<usize>);
impl SecondFactorVerifier for Factor {
    fn verify_second_factor(
        &self,
        account: &str,
        _: RequiredSecondFactor,
        code: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        self.0.set(self.0.get() + 1);
        assert_eq!(account, "alice@example.test");
        Ok(if code == "123456" {
            SecondFactorVerdict::Accept
        } else {
            SecondFactorVerdict::Reject
        })
    }
}
fn primary(account: &str) -> AuthenticationService<Primary> {
    AuthenticationService::new(
        AuthenticationPolicy::default(),
        Primary {
            verdict: Ok(PrimaryAuthVerdict::Accept {
                canonical_username: account.into(),
            }),
        },
    )
}
fn proof(c: &AuthenticationContext, s: &ValidatedSession) -> FreshAuthorization {
    verify_fresh(
        &primary("alice@example.test"),
        &SecondFactorService::new(AuthenticationPolicy::default(), Factor(Cell::new(0))),
        c,
        s,
        ("fixture-password", "123456"),
        59,
    )
    .authorization
    .ok()
    .unwrap()
}
struct InventoryBackend {
    reads: Cell<usize>,
    unavailable: bool,
}
impl PublicKeyBackend for InventoryBackend {
    fn read(&self, account: &str) -> Result<Inventory, Error> {
        self.reads.set(self.reads.get() + 1);
        assert_eq!(account, "alice@example.test");
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        let k = |fp: char| serde_json::json!({"primary":{"fingerprint":fp.to_string().repeat(40),"algorithm":1,"bits":3072,"created":1,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,"can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},"subkeys":[]});
        Inventory::parse(&serde_json::to_vec(&serde_json::json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[k('A'),k('B')]})).unwrap()).map_err(|_|Error::Unavailable)
    }
}
fn backend() -> InventoryBackend {
    InventoryBackend {
        reads: Cell::new(0),
        unavailable: false,
    }
}
fn request(action: Action<'_>, revision: u64) -> MutationRequest<'_> {
    MutationRequest {
        action,
        expected_revision: revision,
        password: "fixture-password",
        totp: "123456",
    }
}

#[test]
fn key_management_fresh_verification_is_account_bound_and_backend_outage_distinct() {
    let c = context();
    let s = session();
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor(Cell::new(0)));
    assert!(matches!(
        verify_fresh(
            &primary("bob@example.test"),
            &factor,
            &c,
            &s,
            ("fixture-password", "123456"),
            59
        )
        .authorization,
        Err(Error::Authentication)
    ));
    let unavailable = AuthenticationService::new(
        AuthenticationPolicy::default(),
        Primary {
            verdict: Err(PrimaryAuthBackendError {
                backend: "fixture",
                reason: "unavailable".into(),
            }),
        },
    );
    assert!(matches!(
        verify_fresh(
            &unavailable,
            &factor,
            &c,
            &s,
            ("fixture-password", "123456"),
            59
        )
        .authorization,
        Err(Error::Unavailable)
    ));
    let out = verify_fresh(
        &primary("alice@example.test"),
        &factor,
        &c,
        &s,
        ("fixture-password", "654321"),
        59,
    );
    assert!(matches!(out.authorization, Err(Error::Authentication)));
    let audit = format!("{:?}", out.audit_events);
    assert!(!audit.contains("fixture-password"));
    assert!(!audit.contains("654321"));
}
#[test]
fn key_management_binding_changes_require_fresh_same_request_and_cas() {
    let root = Scratch::new();
    let store = BindingStore::new(root.0.join("bindings"));
    let b = backend();
    let c = context();
    let s = session();
    let fp = "A".repeat(40);
    let r = request(
        Action::SetAccount {
            primary_fingerprint: &fp,
            signing_fingerprint: Some(&fp),
            decrypt_fingerprints: &fp,
        },
        0,
    );
    assert_eq!(mutate(&b, &store, proof(&c, &s), &c, &s, &r, 59), Ok(()));
    let record = store.load("alice@example.test").unwrap();
    assert_eq!(record.revision, 1);
    assert_eq!(record.account_binding.unwrap().primary_fingerprint, fp);
    assert_eq!(
        mutate(&b, &store, proof(&c, &s), &c, &s, &r, 59),
        Err(Error::Stale)
    );
    assert_eq!(b.reads.get(), 1);
    let mut foreign = s.clone();
    foreign.record.canonical_username = "bob@example.test".into();
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &foreign,
            &request(Action::ClearAccount, 1),
            59
        ),
        Err(Error::Authentication)
    );
    let mut other = c.clone();
    other.request_id = "other".into();
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &other,
            &s,
            &request(Action::ClearAccount, 1),
            59
        ),
        Err(Error::Authentication)
    );
    assert_eq!(b.reads.get(), 1);
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(Action::ClearAccount, 1),
            121
        ),
        Err(Error::Authentication)
    );
    assert_eq!(b.reads.get(), 1);
}
#[test]
fn key_management_explicit_recipient_binding_and_policy_roundtrip_no_uid_guessing() {
    let root = Scratch::new();
    let store = BindingStore::new(root.0.join("bindings"));
    let b = backend();
    let c = context();
    let s = session();
    let fp = "B".repeat(40);
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::SetRecipient {
                    address: "recipient@example.test",
                    primary_fingerprint: &fp,
                    encryption: Requirement::Required
                },
                0
            ),
            59
        ),
        Ok(())
    );
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::SetPolicy {
                    signing: Requirement::Optional,
                    encryption: Requirement::Required
                },
                1
            ),
            59
        ),
        Ok(())
    );
    let record = store.load("alice@example.test").unwrap();
    assert_eq!(record.revision, 2);
    assert_eq!(
        record.recipient_bindings[0].address,
        "recipient@example.test"
    );
    assert_eq!(record.policy.encryption, Requirement::Required);
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::RemoveRecipient {
                    address: "recipient@example.test"
                },
                2
            ),
            59
        ),
        Ok(())
    );
    assert!(store
        .load("alice@example.test")
        .unwrap()
        .recipient_bindings
        .is_empty());
}
#[test]
fn key_management_public_writes_unavailable_and_invalid_key_never_committed() {
    let root = Scratch::new();
    let store = BindingStore::new(root.0.join("bindings"));
    let b = backend();
    let c = context();
    let s = session();
    let fp = "A".repeat(40);
    let missing = "C".repeat(40);
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::SetAccount {
                    primary_fingerprint: &missing,
                    signing_fingerprint: None,
                    decrypt_fingerprints: ""
                },
                0
            ),
            59
        ),
        Err(Error::InvalidKey)
    );
    let public =
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----";
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::ImportPublic {
                    certificate: public,
                    expected_primary_fingerprint: &fp
                },
                0
            ),
            59
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::RemovePublic {
                    primary_fingerprint: &fp
                },
                0
            ),
            59
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(store.load("alice@example.test").unwrap().revision, 0);
    assert_eq!(
        validate_public_certificate(b"-----BEGIN PGP PRIVATE KEY BLOCK-----", &fp),
        Err(Error::Invalid)
    );
    assert_eq!(
        validate_public_certificate(&vec![b'A'; MAX_PUBLIC_CERTIFICATE + 1], &fp),
        Err(Error::Invalid)
    );
}
#[derive(Clone, Copy)]
struct FixedTime;
impl crate::totp::TimeProvider for FixedTime {
    fn unix_timestamp(&self) -> u64 {
        59
    }
}
#[test]
fn key_management_real_persistent_totp_replay_cannot_authorize_twice() {
    use crate::totp::{FileTotpSecretStore, TotpPolicy, TotpVerifier};
    let root = Scratch::new();
    let secret_dir = root.0.join("secrets");
    fs::create_dir(&secret_dir).unwrap();
    fs::set_permissions(&secret_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let store = FileTotpSecretStore::new(&secret_dir).with_replay_dir(root.0.join("replay"));
    let path = store.secret_path_for_username("alice@example.test");
    fs::write(&path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let policy = TotpPolicy {
        digits: 6,
        period_seconds: 30,
        allowed_skew_steps: 0,
    };
    let c = context();
    let s = session();
    let factor = SecondFactorService::new(
        AuthenticationPolicy::default(),
        TotpVerifier::new(store, FixedTime, policy),
    );
    assert!(verify_fresh(
        &primary("alice@example.test"),
        &factor,
        &c,
        &s,
        ("fixture-password", "287082"),
        59
    )
    .authorization
    .is_ok());
    let reopened = FileTotpSecretStore::new(&secret_dir).with_replay_dir(root.0.join("replay"));
    let factor = SecondFactorService::new(
        AuthenticationPolicy::default(),
        TotpVerifier::new(reopened, FixedTime, policy),
    );
    assert!(matches!(
        verify_fresh(
            &primary("alice@example.test"),
            &factor,
            &c,
            &s,
            ("fixture-password", "287082"),
            59
        )
        .authorization,
        Err(Error::Authentication)
    ));
}

struct EmptyInventory;
impl PublicKeyBackend for EmptyInventory {
    fn read(&self, _: &str) -> Result<Inventory, Error> {
        Inventory::parse(br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[]}"#).map_err(|_|Error::Unavailable)
    }
}
#[test]
fn key_management_atomic_cleanup_recovers_multiple_unavailable_bound_keys() {
    let root = Scratch::new();
    let store = BindingStore::new(root.0.join("bindings"));
    let b = backend();
    let c = context();
    let s = session();
    let account = "A".repeat(40);
    let recipient = "B".repeat(40);
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::SetAccount {
                    primary_fingerprint: &account,
                    signing_fingerprint: Some(&account),
                    decrypt_fingerprints: &account
                },
                0
            ),
            59
        ),
        Ok(())
    );
    assert_eq!(
        mutate(
            &b,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::SetRecipient {
                    address: "recipient@example.test",
                    primary_fingerprint: &recipient,
                    encryption: Requirement::Required
                },
                1
            ),
            59
        ),
        Ok(())
    );
    assert_eq!(
        mutate(
            &EmptyInventory,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(Action::ClearAccount, 2),
            59
        ),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        mutate(
            &EmptyInventory,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(
                Action::RemoveRecipient {
                    address: "recipient@example.test"
                },
                2
            ),
            59
        ),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        mutate(
            &EmptyInventory,
            &store,
            proof(&c, &s),
            &c,
            &s,
            &request(Action::ClearAllBindings, 2),
            59
        ),
        Ok(())
    );
    let record = store.load("alice@example.test").unwrap();
    assert_eq!(record.revision, 3);
    assert!(record.account_binding.is_none());
    assert!(record.recipient_bindings.is_empty());
}
