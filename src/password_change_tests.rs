use crate::account_admission::{Admission, EpochAuthority};
use crate::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use crate::auth::{
    PrimaryAuthBackendError, PrimaryAuthVerdict, PrimaryCredentialBackend,
    SecondFactorBackendError, SecondFactorService, SecondFactorVerdict, SecondFactorVerifier,
};
use crate::http::RuntimeBrowserGateway;
use crate::password_change::{self, Attempt, EpochPrimaryBackend, Error, Request, Services};
use crate::session::{SessionRecord, ValidatedSession};
use crate::totp::{FileTotpSecretStore, TimeProvider, TotpPolicy, TotpVerifier};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
#[path = "password_preparation_deadline_tests.rs"]
mod preparation_deadline_tests;
#[cfg(unix)]
#[path = "password_session_action_tests.rs"]
mod session_action_tests;

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "osmap-stepup-{}",
            nonce.iter().map(|v| format!("{v:02x}")).collect::<String>()
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Clock(AtomicU64);
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Epoch {
    value: AtomicU64,
    active: AtomicBool,
    calls: AtomicUsize,
}
impl Epoch {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(3),
            active: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        }
    }
}
impl EpochAuthority for Epoch {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.active.load(Ordering::SeqCst)
            && self.value.load(Ordering::SeqCst) == epoch
            && account == "alice@example.test"
        {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
struct Primary<'a> {
    epoch: &'a Epoch,
    capture: Mutex<Option<Admission>>,
    calls: AtomicUsize,
    account: &'static str,
}
impl<'a> Primary<'a> {
    fn new(epoch: &'a Epoch) -> Self {
        Self {
            epoch,
            capture: Mutex::new(None),
            calls: AtomicUsize::new(0),
            account: "alice@example.test",
        }
    }
}
impl PrimaryCredentialBackend for Primary<'_> {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        account: &str,
        password: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(account, "alice@example.test");
        if password != "public-old-value" {
            return Ok(PrimaryAuthVerdict::Reject);
        }
        *self.capture.lock().unwrap() = Some(Admission {
            account: self.account.into(),
            epoch: self.epoch.value.load(Ordering::SeqCst),
        });
        Ok(PrimaryAuthVerdict::Accept {
            canonical_username: self.account.into(),
        })
    }
}
impl EpochPrimaryBackend for Primary<'_> {
    fn captured_admission(&self) -> Result<Admission, Error> {
        self.capture
            .lock()
            .unwrap()
            .clone()
            .ok_or(Error::Unavailable)
    }
}
struct Factor<'a> {
    calls: Arc<AtomicUsize>,
    epoch_change: Option<&'a Epoch>,
    accept: bool,
}
impl Factor<'_> {
    fn accepted() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            epoch_change: None,
            accept: true,
        }
    }
}
impl SecondFactorVerifier for Factor<'_> {
    fn verify_second_factor(
        &self,
        account: &str,
        factor: RequiredSecondFactor,
        _: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(account, "alice@example.test");
        assert_eq!(factor, RequiredSecondFactor::Totp);
        if let Some(epoch) = self.epoch_change {
            epoch.value.store(4, Ordering::SeqCst);
        }
        Ok(if self.accept {
            SecondFactorVerdict::Accept
        } else {
            SecondFactorVerdict::Reject
        })
    }
}
fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "public-stepup",
        "127.0.0.1",
        "Firefox/Test",
    )
    .unwrap()
}
fn session() -> ValidatedSession {
    ValidatedSession {
        record: SessionRecord {
            account_epoch: Some(3),
            session_id: "a".repeat(64),
            csrf_token: "b".repeat(64),
            canonical_username: "alice@example.test".into(),
            issued_at: 1,
            expires_at: 10000,
            last_seen_at: 1,
            revoked_at: None,
            remote_addr: "127.0.0.1".into(),
            user_agent: "Firefox/Test".into(),
            factor: RequiredSecondFactor::Totp,
        },
        audit_event: crate::logging::LogEvent::new(
            crate::config::LogLevel::Info,
            crate::logging::EventCategory::Session,
            "session_validated",
            "public fixture",
        ),
    }
}
fn request() -> Request<'static> {
    Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "123456",
    )
    .unwrap()
}
fn prepare<'a, F: SecondFactorVerifier>(
    primary: &Primary<'_>,
    factor: &SecondFactorService<F>,
    epoch: &Epoch,
    rate: &crate::password_change_rate::Store,
    clock: &Clock,
    attempt: (&'a AuthenticationContext, &'a ValidatedSession, Request<'a>),
) -> password_change::Outcome<'a> {
    password_change::prepare(
        Services {
            primary,
            factor,
            epoch,
            rate,
            clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: attempt.0,
            session: attempt.1,
            request: attempt.2,
        },
    )
}

#[test]
fn exact_request_moves_from_fresh_verification_to_dispatch_without_writer_or_retarget() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let outcome = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    );
    assert_eq!(outcome.audit_events.len(), 2);
    let dispatch = outcome
        .authorization
        .unwrap()
        .into_dispatch(&c, &s, &epoch, &clock)
        .unwrap();
    assert_eq!(dispatch.account(), "alice@example.test");
    assert_eq!(dispatch.epoch(), 3);
    assert_eq!(dispatch.intent_reference().len(), 64);
    assert_eq!(dispatch.session_id(), s.record.session_id);
    assert_eq!(dispatch.request_id(), c.request_id);
    assert_eq!(dispatch.source(), c.remote_addr);
    assert_eq!(dispatch.issued(), 100);
    assert_eq!(dispatch.expires(), 400);
    assert_eq!(dispatch.current(), "public-old-value");
    assert_eq!(dispatch.new_password(), "public-new-passphrase");
    assert_eq!(dispatch.confirmation(), dispatch.new_password());
    assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn independent_password_policy_boundaries_unicode_confirmation_controls_and_unchanged() {
    for new in [
        "a".repeat(14),
        "a".repeat(129),
        "x\n".repeat(8),
        "public-old-value".into(),
    ] {
        assert!(Request::new("public-old-value", &new, &new, "123456").is_err());
    }
    let maximal = "🦀".repeat(128);
    assert!(Request::new("public-old-value", &maximal, &maximal, "123456").is_ok());
    assert!(Request::new(
        "public-old-value",
        "public-new-passphrase",
        "different-confirmation",
        "123456"
    )
    .is_err());
    assert!(Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "notOTP"
    )
    .is_err());
}
#[test]
fn wrong_primary_and_foreign_canonical_never_run_factor_or_issue_permit() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let mut primary = Primary::new(&epoch);
    let backend = Factor::accepted();
    let factor_calls = backend.calls.clone();
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), backend);
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let wrong = Request::new(
        "wrong-public-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "123456",
    )
    .unwrap();
    assert!(matches!(
        prepare(&primary, &factor, &epoch, &rate, &clock, (&c, &s, wrong)).authorization,
        Err(Error::Authentication)
    ));
    primary.account = "bob@example.test";
    assert!(matches!(
        prepare(
            &primary,
            &factor,
            &epoch,
            &rate,
            &clock,
            (&c, &s, request())
        )
        .authorization,
        Err(Error::Authentication)
    ));
    assert_eq!(primary.calls.load(Ordering::SeqCst), 2);
    assert_eq!(factor_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn credential_epoch_change_during_factor_and_contained_account_refuse_permit() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(
        AuthenticationPolicy::default(),
        Factor {
            calls: Arc::new(AtomicUsize::new(0)),
            epoch_change: Some(&epoch),
            accept: true,
        },
    );
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    assert!(matches!(
        prepare(
            &primary,
            &factor,
            &epoch,
            &rate,
            &clock,
            (&c, &s, request())
        )
        .authorization,
        Err(Error::Stale)
    ));
    epoch.active.store(false, Ordering::SeqCst);
    assert!(matches!(
        prepare(
            &primary,
            &factor,
            &epoch,
            &rate,
            &clock,
            (&c, &s, request())
        )
        .authorization,
        Err(Error::Stale)
    ));
    assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn verification_elapsed_at_exact_freshness_boundary_never_issues_late_permit() {
    struct DelayedFactor<'a>(&'a Clock);
    impl SecondFactorVerifier for DelayedFactor<'_> {
        fn verify_second_factor(
            &self,
            _: &str,
            _: RequiredSecondFactor,
            _: &str,
        ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
            self.0 .0.store(400, Ordering::SeqCst);
            Ok(SecondFactorVerdict::Accept)
        }
    }
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let clock = Clock(AtomicU64::new(100));
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), DelayedFactor(&clock));
    let c = context();
    let s = session();
    let result = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    );
    assert!(matches!(result.authorization, Err(Error::Expired)));
    assert_eq!(result.audit_events.len(), 2);
    assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
}
#[test]
fn permit_rejects_exact_300_second_boundary_clock_rollback_and_changed_bindings() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let permit = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    )
    .authorization
    .unwrap();
    clock.0.store(400, Ordering::SeqCst);
    assert!(matches!(
        permit.into_dispatch(&c, &s, &epoch, &clock),
        Err(Error::Expired)
    ));
    clock.0.store(100, Ordering::SeqCst);
    let permit = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    )
    .authorization
    .unwrap();
    clock.0.store(99, Ordering::SeqCst);
    assert!(matches!(
        permit.into_dispatch(&c, &s, &epoch, &clock),
        Err(Error::Expired)
    ));
    clock.0.store(100, Ordering::SeqCst);
    for field in 0..5 {
        let permit = prepare(
            &primary,
            &factor,
            &epoch,
            &rate,
            &clock,
            (&c, &s, request()),
        )
        .authorization
        .unwrap();
        let mut different_c = c.clone();
        let mut different_s = s.clone();
        match field {
            0 => different_c.request_id = "other-request".into(),
            1 => different_c.remote_addr = "127.0.0.2".into(),
            2 => different_s.record.session_id = "c".repeat(64),
            3 => different_s.record.canonical_username = "bob@example.test".into(),
            _ => different_s.record.account_epoch = Some(4),
        }
        assert!(matches!(
            permit.into_dispatch(&different_c, &different_s, &epoch, &clock),
            Err(Error::Stale)
        ));
    }
}
#[test]
fn permit_consumption_rechecks_authoritative_epoch_and_revocation() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let permit = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    )
    .authorization
    .unwrap();
    epoch.value.store(4, Ordering::SeqCst);
    assert!(matches!(
        permit.into_dispatch(&c, &s, &epoch, &clock),
        Err(Error::Stale)
    ));
    epoch.value.store(3, Ordering::SeqCst);
    let permit = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    )
    .authorization
    .unwrap();
    let mut revoked = s.clone();
    revoked.record.revoked_at = Some(100);
    assert!(matches!(
        permit.into_dispatch(&c, &revoked, &epoch, &clock),
        Err(Error::Authentication)
    ));
}

#[test]
fn permit_expiring_during_final_authority_check_refuses_after_callback() {
    struct DelayedAuthority<'a>(&'a Epoch, &'a Clock);
    impl EpochAuthority for DelayedAuthority<'_> {
        fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
            self.0.admit(account, epoch)?;
            self.1 .0.store(400, Ordering::SeqCst);
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let permit = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    )
    .authorization
    .unwrap();
    assert!(matches!(
        permit.into_dispatch(&c, &s, &DelayedAuthority(&epoch, &clock), &clock),
        Err(Error::Expired)
    ));
}

#[test]
fn session_expiring_during_final_authority_check_refuses_before_permit_deadline() {
    struct DelayedAuthority<'a>(&'a Epoch, &'a Clock);
    impl EpochAuthority for DelayedAuthority<'_> {
        fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
            self.0.admit(account, epoch)?;
            self.1 .0.store(250, Ordering::SeqCst);
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let mut s = session();
    s.record.expires_at = 200;
    let permit = prepare(
        &primary,
        &factor,
        &epoch,
        &rate,
        &clock,
        (&c, &s, request()),
    )
    .authorization
    .unwrap();
    assert!(matches!(
        permit.into_dispatch(&c, &s, &DelayedAuthority(&epoch, &clock), &clock),
        Err(Error::Authentication)
    ));
}

#[test]
fn preparation_final_authority_delay_cannot_issue_already_expired_authorization() {
    struct DelayedAuthority<'a> {
        epoch: &'a Epoch,
        clock: &'a Clock,
        calls: AtomicUsize,
    }
    impl EpochAuthority for DelayedAuthority<'_> {
        fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
            self.epoch.admit(account, epoch)?;
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                self.clock.0.store(400, Ordering::SeqCst);
            }
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let delayed = DelayedAuthority {
        epoch: &epoch,
        clock: &clock,
        calls: AtomicUsize::new(0),
    };
    let outcome = password_change::prepare(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &delayed,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
    );
    assert!(matches!(outcome.authorization, Err(Error::Expired)));
}

#[test]
fn preparation_delay_preserves_original_deadline_instead_of_extending_freshness() {
    struct DelayedAuthority<'a> {
        epoch: &'a Epoch,
        clock: &'a Clock,
        calls: AtomicUsize,
    }
    impl EpochAuthority for DelayedAuthority<'_> {
        fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
            self.epoch.admit(account, epoch)?;
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                self.clock.0.store(399, Ordering::SeqCst);
            }
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    let s = session();
    let delayed = DelayedAuthority {
        epoch: &epoch,
        clock: &clock,
        calls: AtomicUsize::new(0),
    };
    let outcome = password_change::prepare(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &delayed,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
    );
    let dispatch = outcome
        .authorization
        .unwrap()
        .into_dispatch(&c, &s, &epoch, &clock)
        .unwrap();
    assert_eq!(dispatch.issued(), 100);
    assert_eq!(dispatch.expires(), 400);
}
#[test]
fn unbound_and_terminal_epoch_refuse_before_primary_and_private_rate_state() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let clock = Clock(AtomicU64::new(100));
    let c = context();
    for value in [
        None,
        Some(crate::account_admission::MAX_EPOCH),
        Some(u64::MAX),
    ] {
        let mut s = session();
        s.record.account_epoch = value;
        assert!(matches!(
            prepare(
                &primary,
                &factor,
                &epoch,
                &rate,
                &clock,
                (&c, &s, request())
            )
            .authorization,
            Err(Error::Stale)
        ));
    }
    assert_eq!(primary.calls.load(Ordering::SeqCst), 0);
    assert!(!scratch.0.join("rate").exists());
}
#[test]
fn real_file_backed_totp_counter_from_login_cannot_authorize_fresh_password_stepup() {
    let scratch = Scratch::new();
    let root = scratch.0.join("factor");
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = FileTotpSecretStore::new(&root).with_replay_dir(scratch.0.join("replay"));
    let path = store.secret_path_for_username("alice@example.test");
    std::fs::write(&path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let factor = SecondFactorService::new(
        AuthenticationPolicy::default(),
        TotpVerifier::new(store, Clock(AtomicU64::new(59)), TotpPolicy::default()),
    );
    let c = context();
    let login = factor.verify(
        &c,
        "alice@example.test",
        RequiredSecondFactor::Totp,
        "287082",
    );
    assert!(matches!(
        login.decision,
        crate::auth::AuthenticationDecision::AuthenticatedPendingSession { .. }
    ));
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let clock = Clock(AtomicU64::new(59));
    let s = session();
    let reused = Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "287082",
    )
    .unwrap();
    assert!(matches!(
        prepare(&primary, &factor, &epoch, &rate, &clock, (&c, &s, reused)).authorization,
        Err(Error::Authentication)
    ));
    // Fresh request cannot reset replay history merely by using a new Runtime/service.
    let restarted = SecondFactorService::new(
        AuthenticationPolicy::default(),
        TotpVerifier::new(
            FileTotpSecretStore::new(&root).with_replay_dir(scratch.0.join("replay")),
            Clock(AtomicU64::new(59)),
            TotpPolicy::default(),
        ),
    );
    let reused = Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "287082",
    )
    .unwrap();
    assert!(matches!(
        prepare(
            &primary,
            &restarted,
            &epoch,
            &rate,
            &clock,
            (&c, &s, reused)
        )
        .authorization,
        Err(Error::Authentication)
    ));
}

#[test]
fn actual_file_factor_fresh_stepup_succeeds_once_and_restart_preserves_consumed_counter() {
    let scratch = Scratch::new();
    let root = scratch.0.join("factor");
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = FileTotpSecretStore::new(&root).with_replay_dir(scratch.0.join("replay"));
    let path = store.secret_path_for_username("alice@example.test");
    std::fs::write(&path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let factor = SecondFactorService::new(
        AuthenticationPolicy::default(),
        TotpVerifier::new(store, Clock(AtomicU64::new(59)), TotpPolicy::default()),
    );
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let clock = Clock(AtomicU64::new(59));
    let s = session();
    let c = context();
    let fresh = Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "287082",
    )
    .unwrap();
    let permit = prepare(&primary, &factor, &epoch, &rate, &clock, (&c, &s, fresh))
        .authorization
        .unwrap();
    assert_eq!(
        permit
            .into_dispatch(&c, &s, &epoch, &clock)
            .unwrap()
            .account(),
        "alice@example.test"
    );
    let restarted = SecondFactorService::new(
        AuthenticationPolicy::default(),
        TotpVerifier::new(
            FileTotpSecretStore::new(&root).with_replay_dir(scratch.0.join("replay")),
            Clock(AtomicU64::new(59)),
            TotpPolicy::default(),
        ),
    );
    let reused = Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "287082",
    )
    .unwrap();
    assert!(matches!(
        prepare(
            &primary,
            &restarted,
            &epoch,
            &rate,
            &clock,
            (&c, &s, reused)
        )
        .authorization,
        Err(Error::Authentication)
    ));
}

#[test]
fn password_runtime_without_qualified_helper_refuses_before_private_state_creation() {
    let scratch = Scratch::new();
    let root = scratch.0.join("uncreated-runtime");
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "public-stepup",
        "127.0.0.1",
        "Firefox/Test",
    )
    .unwrap();
    let session = ValidatedSession {
        record: SessionRecord {
            account_epoch: Some(3),
            session_id: "a".repeat(64),
            csrf_token: "b".repeat(64),
            canonical_username: "alice@example.test".into(),
            issued_at: 1,
            expires_at: u64::MAX - 1,
            last_seen_at: 1,
            revoked_at: None,
            remote_addr: "127.0.0.1".into(),
            user_agent: "Firefox/Test".into(),
            factor: RequiredSecondFactor::Totp,
        },
        audit_event: crate::logging::LogEvent::new(
            crate::config::LogLevel::Info,
            crate::logging::EventCategory::Session,
            "session_validated",
            "public fixture",
        ),
    };
    let request = crate::password_change::Request::new(
        "public-old-value",
        "public-new-passphrase",
        "public-new-passphrase",
        "123456",
    )
    .unwrap();
    let result =
        RuntimeBrowserGateway::for_test(&root).prepare_password_change(&context, &session, request);
    assert!(matches!(
        result.authorization,
        Err(crate::password_change::Error::Unavailable)
    ));
    assert!(!root.exists());
}
