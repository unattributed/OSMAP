use super::*;
use std::time::{Duration, Instant};
struct DelayedClock {
    calls: AtomicUsize,
    delay_on: usize,
}
impl TimeProvider for DelayedClock {
    fn unix_timestamp(&self) -> u64 {
        if self.calls.fetch_add(1, Ordering::SeqCst) == self.delay_on {
            std::thread::sleep(Duration::from_millis(70));
        }
        100
    }
}
#[test]
fn initial_clock_elapsed_original_budget_cannot_issue_prepared_authority() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let s = session();
    let clock = DelayedClock {
        calls: AtomicUsize::new(0),
        delay_on: 0,
    };
    let original = Instant::now() + Duration::from_millis(20);
    let result = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    );
    assert!(Instant::now() >= original);
    assert!(
        matches!(result.authorization, Err(Error::Expired)),
        "old preparation ignored caller original elapsed budget"
    );
}

struct BoundedPrimary<'a> {
    inner: Primary<'a>,
    delay: Duration,
    seen: Mutex<Vec<Instant>>,
}
impl PrimaryCredentialBackend for BoundedPrimary<'_> {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        _: &str,
        _: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        panic!("bounded preparation must not use the unbounded primary entry")
    }
}
impl EpochPrimaryBackend for BoundedPrimary<'_> {
    fn captured_admission(&self) -> Result<Admission, Error> {
        self.inner.captured_admission()
    }
    fn verify_primary_before(
        &self,
        c: &AuthenticationContext,
        a: &str,
        p: &str,
        d: Instant,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        self.seen.lock().unwrap().push(d);
        std::thread::sleep(self.delay);
        self.inner.verify_primary(c, a, p)
    }
}
struct BoundedEpoch<'a> {
    inner: &'a Epoch,
    delay_on: usize,
    calls: AtomicUsize,
    seen: Mutex<Vec<Instant>>,
}
impl EpochAuthority for BoundedEpoch<'_> {
    fn admit(&self, _: &str, _: u64) -> Result<(), crate::account_admission::Error> {
        panic!("bounded preparation must not use renewed admission")
    }
    fn admit_before(
        &self,
        a: &str,
        e: u64,
        d: Instant,
    ) -> Result<(), crate::account_admission::Error> {
        self.seen.lock().unwrap().push(d);
        if self.calls.fetch_add(1, Ordering::SeqCst) == self.delay_on {
            std::thread::sleep(Duration::from_millis(70));
        }
        self.inner.admit(a, e)
    }
}
struct DelayedFactor {
    calls: Arc<AtomicUsize>,
    accept: bool,
}
impl SecondFactorVerifier for DelayedFactor {
    fn verify_second_factor(
        &self,
        _: &str,
        _: RequiredSecondFactor,
        _: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(70));
        Ok(if self.accept {
            SecondFactorVerdict::Accept
        } else {
            SecondFactorVerdict::Reject
        })
    }
}
#[test]
fn primary_elapsed_original_deadline_refuses_before_factor() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = BoundedPrimary {
        inner: Primary::new(&epoch),
        delay: Duration::from_millis(70),
        seen: Mutex::new(vec![]),
    };
    let verifier = Factor::accepted();
    let calls = verifier.calls.clone();
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), verifier);
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    let original = Instant::now() + Duration::from_millis(20);
    let outcome = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    );
    assert!(matches!(outcome.authorization, Err(Error::Expired)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(*primary.seen.lock().unwrap(), vec![original]);
}
#[test]
fn factor_elapsed_original_deadline_cannot_issue_authority() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let calls = Arc::new(AtomicUsize::new(0));
    let factor = SecondFactorService::new(
        AuthenticationPolicy::default(),
        DelayedFactor {
            calls: calls.clone(),
            accept: true,
        },
    );
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    let original = Instant::now() + Duration::from_millis(20);
    let outcome = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    );
    assert!(matches!(outcome.authorization, Err(Error::Expired)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[test]
fn final_clock_elapsed_budget_cannot_issue_late_authority() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let s = session();
    let clock = DelayedClock {
        calls: AtomicUsize::new(0),
        delay_on: 2,
    };
    let original = Instant::now() + Duration::from_millis(20);
    let outcome = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    );
    assert!(matches!(outcome.authorization, Err(Error::Expired)));
    assert_eq!(clock.calls.load(Ordering::SeqCst), 3);
}
#[test]
fn final_epoch_callback_uses_original_budget_and_refuses_late_return() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let authority = BoundedEpoch {
        inner: &epoch,
        delay_on: 1,
        calls: AtomicUsize::new(0),
        seen: Mutex::new(vec![]),
    };
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    let original = Instant::now() + Duration::from_millis(20);
    let outcome = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &authority,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    );
    assert!(matches!(outcome.authorization, Err(Error::Expired)));
    assert_eq!(*authority.seen.lock().unwrap(), vec![original, original]);
}
#[test]
fn successful_preparation_preserves_exact_original_deadline_into_signed_request() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let authority = BoundedEpoch {
        inner: &epoch,
        delay_on: usize::MAX,
        calls: AtomicUsize::new(0),
        seen: Mutex::new(vec![]),
    };
    let primary = BoundedPrimary {
        inner: Primary::new(&epoch),
        delay: Duration::ZERO,
        seen: Mutex::new(vec![]),
    };
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    let original = Instant::now() + Duration::from_secs(1);
    let prepared = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &authority,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    )
    .authorization
    .unwrap();
    let dispatch = prepared.into_dispatch(&c, &s, &authority, &clock).unwrap();
    assert_eq!(dispatch.workflow_deadline(), Some(original));
    let signed = crate::account_mutation::Request::issue(dispatch, &[0x72; 32], 100).unwrap();
    assert_eq!(signed.workflow_deadline(), Some(original));
    assert_eq!(
        *authority.seen.lock().unwrap(),
        vec![original, original, original]
    );
    assert_eq!(*primary.seen.lock().unwrap(), vec![original]);
}
#[test]
fn prepared_action_cannot_renew_original_deadline_on_consumption() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    let original = Instant::now() + Duration::from_millis(40);
    let prepared = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    )
    .authorization
    .unwrap();
    std::thread::sleep(Duration::from_millis(70));
    let calls = epoch.calls.load(Ordering::SeqCst);
    assert!(matches!(
        prepared.into_dispatch(&c, &s, &epoch, &clock),
        Err(Error::Expired)
    ));
    assert_eq!(epoch.calls.load(Ordering::SeqCst), calls);
}
#[test]
fn invalid_initial_budgets_admit_no_factor_or_rate_files() {
    let scratch = Scratch::new();
    let path = scratch.0.join("rate");
    let rate = crate::password_change_rate::Store::new(path.clone());
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let verifier = Factor::accepted();
    let calls = verifier.calls.clone();
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), verifier);
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    for deadline in [
        Instant::now() - Duration::from_secs(1),
        Instant::now() + Duration::from_secs(61),
    ] {
        let outcome = password_change::prepare_before(
            Services {
                primary: &primary,
                factor: &factor,
                epoch: &epoch,
                rate: &rate,
                clock: &clock,
                policy: AuthenticationPolicy::default(),
            },
            Attempt {
                context: &c,
                session: &s,
                request: request(),
            },
            deadline,
        );
        assert!(matches!(outcome.authorization, Err(Error::Expired)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(primary.calls.load(Ordering::SeqCst), 0);
    assert_eq!(epoch.calls.load(Ordering::SeqCst), 0);
    assert!(!path.exists());
}
#[test]
fn bounded_success_does_not_reset_durable_failed_authentication_history() {
    let scratch = Scratch::new();
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    for n in 0..6 {
        let req = if n == 4 {
            request()
        } else {
            Request::new(
                "wrong-public-old",
                "public-new-passphrase",
                "public-new-passphrase",
                "123456",
            )
            .unwrap()
        };
        let outcome = password_change::prepare_before(
            Services {
                primary: &primary,
                factor: &factor,
                epoch: &epoch,
                rate: &rate,
                clock: &clock,
                policy: AuthenticationPolicy::default(),
            },
            Attempt {
                context: &c,
                session: &s,
                request: req,
            },
            Instant::now() + Duration::from_secs(1),
        );
        if n == 4 {
            assert!(outcome.authorization.is_ok());
        } else if n == 5 {
            assert!(matches!(outcome.authorization, Err(Error::Throttled)));
        } else {
            assert!(matches!(outcome.authorization, Err(Error::Authentication)));
        }
    }
}
#[test]
fn known_factor_rejection_remains_durable_when_original_budget_expires() {
    let scratch = Scratch::new();
    let path = scratch.0.join("rate");
    let rate = crate::password_change_rate::Store::new(path.clone());
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let delayed = SecondFactorService::new(
        AuthenticationPolicy::default(),
        DelayedFactor {
            calls: Arc::new(AtomicUsize::new(0)),
            accept: false,
        },
    );
    let c = context();
    let s = session();
    let clock = Clock(AtomicU64::new(100));
    let outcome = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &delayed,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        Instant::now() + Duration::from_millis(20),
    );
    assert!(matches!(outcome.authorization, Err(Error::Expired)));
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let restarted = crate::password_change_rate::Store::new(path);
    for n in 0..4 {
        let outcome = password_change::prepare_before(
            Services {
                primary: &primary,
                factor: &factor,
                epoch: &epoch,
                rate: &restarted,
                clock: &clock,
                policy: AuthenticationPolicy::default(),
            },
            Attempt {
                context: &c,
                session: &s,
                request: Request::new(
                    "wrong-public-old",
                    "public-new-passphrase",
                    "public-new-passphrase",
                    "123456",
                )
                .unwrap(),
            },
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            matches!(outcome.authorization, Err(Error::Authentication))
                || (n == 3 && matches!(outcome.authorization, Err(Error::Throttled)))
        );
        if n == 3 {
            assert!(matches!(outcome.authorization, Err(Error::Throttled)));
        }
    }
}

#[test]
fn default_runtime_before_remains_unavailable_without_creating_private_stores() {
    let scratch = Scratch::new();
    let root = scratch.0.join("unconfigured");
    let runtime = RuntimeBrowserGateway::for_test(&root);
    let c = context();
    let s = session();
    let outcome = runtime.prepare_password_change_before(
        &c,
        &s,
        request(),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(matches!(outcome.authorization, Err(Error::Unavailable)));
    assert!(!root.exists());
}
#[cfg(unix)]
#[test]
fn mutation_client_cannot_replace_preparation_deadline_with_later_budget() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    // The production socket client rejects writable non-sticky ancestors. This
    // disposable fixture uses canonical sticky /tmp, independent of gate TMPDIR.
    let scratch = {
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::path::Path::new("/tmp")
            .canonicalize()
            .unwrap()
            .join(format!(
                "osmap-preparation-socket-{}",
                nonce.iter().map(|v| format!("{v:02x}")).collect::<String>()
            ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Scratch(path)
    };
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let epoch = Epoch::new();
    let primary = Primary::new(&epoch);
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor::accepted());
    let c = context();
    let mut s = session();
    let wall = crate::totp::SystemTimeProvider.unix_timestamp();
    s.record.issued_at = wall;
    s.record.last_seen_at = wall;
    s.record.expires_at = wall + 1000;
    let clock = Clock(AtomicU64::new(wall));
    let original = Instant::now() + Duration::from_secs(1);
    let prepared = password_change::prepare_before(
        Services {
            primary: &primary,
            factor: &factor,
            epoch: &epoch,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &c,
            session: &s,
            request: request(),
        },
        original,
    )
    .authorization
    .unwrap();
    let dispatch = prepared.into_dispatch(&c, &s, &epoch, &clock).unwrap();
    let signed = crate::account_mutation::Request::issue(dispatch, &[0x72; 32], wall).unwrap();
    // Independent wire verifier proves wall freshness still valid: refusal
    // below must come from the preserved monotonic preparation budget.
    crate::account_mutation::Verifier::default()
        .request(&signed.bytes().unwrap(), &[0x72; 32], wall)
        .unwrap();
    let socket = scratch.0.join("test.sock");
    let key = scratch.0.join("test.key");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    std::fs::write(&key, [0x72; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let client = crate::account_mutation_client::Client::guarded_fixture_files(
        &socket,
        &key,
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    std::thread::sleep(
        original.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    );
    assert_eq!(
        client
            .execute_budget(signed, Instant::now() + Duration::from_secs(1))
            .unwrap_err(),
        crate::account_mutation_client::Error::Expired
    );
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
