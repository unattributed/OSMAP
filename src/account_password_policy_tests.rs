use super::*;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const ALICE: &str = "alice@osmap-policy.invalid";
const BOB: &str = "bob@osmap-policy.invalid";
#[derive(Clone)]
struct TestClock {
    base: Instant,
    millis: Arc<AtomicU64>,
}
impl TestClock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            millis: Arc::new(AtomicU64::new(0)),
        }
    }
    fn set(&self, millis: u64) {
        self.millis.store(millis, Ordering::SeqCst);
    }
    fn deadline(&self) -> Instant {
        self.now() + CALLBACK
    }
}
impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}
struct Fixture {
    root: PathBuf,
    store: Arc<Store>,
    clock: TestClock,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-password-policy-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        // Explicit test-only provisioning, not a runtime operation.
        for account in [ALICE, BOB] {
            let stem = format!(
                "{:x}",
                Sha256::digest(
                    [b"osmap-account-epoch-v1\0".as_slice(), account.as_bytes()].concat()
                )
            );
            for (suffix, body) in [("lock", b"".as_slice()), ("json", b"{\"epoch\":0,\"state\":\"active\",\"changed_at\":null,\"intent\":null,\"used_intents\":[]}".as_slice())] {
                let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join(format!("{stem}.{suffix}"))).unwrap();
                file.write_all(body).unwrap(); file.sync_all().unwrap();
            }
        }
        let store = Arc::new(Store::open(&root, crate::openbsd::effective_uid()).unwrap());
        Self {
            root,
            store,
            clock: TestClock::new(),
        }
    }
    fn fence(&self) -> Fence<TestClock> {
        Fence::new(
            self.store.clone(),
            [ALICE.into(), BOB.into()].into(),
            self.clock.clone(),
        )
        .unwrap()
    }
    fn change(&self, pending: bool) {
        let mut guard = self
            .store
            .lock_before(ALICE, Instant::now() + Duration::from_secs(1))
            .unwrap();
        guard.begin(0, &"a".repeat(64), 1000).unwrap();
        if !pending {
            guard.record_verified_write("20261018120000").unwrap();
            guard.complete().unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn body(phase: &str, session: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"login":ALICE,"protocol":"imap","session_id":session,"phase":phase,"tls":true})).unwrap()
}
struct Observer<'a> {
    fixture: &'a Fixture,
    calls: AtomicUsize,
    wrong_anvil: bool,
    advance: Option<u64>,
}
impl RegistrationObserver for Observer<'_> {
    fn observe_registration(
        &self,
        guard: &Guard<'_>,
        account: &str,
        session: &str,
        _deadline: Instant,
    ) -> Result<RegistrationEvidence, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let epoch = guard.admission(None).map_err(|_| Error::Refused)?.epoch;
        // The writer lock remains held across the actual observation seam.
        assert!(self
            .fixture
            .store
            .lock_before(account, Instant::now() + Duration::from_millis(2))
            .is_err());
        if let Some(now) = self.advance {
            self.fixture.clock.set(now);
        }
        Ok(RegistrationEvidence {
            account: account.into(),
            session: session.into(),
            epoch,
            kernel_pid: 1234,
            anvil_pid: if self.wrong_anvil { 4321 } else { 1234 },
            kernel_uid: 518,
            expected_uid: 518,
            process_birth: 99,
            observed: self.fixture.clock.now(),
        })
    }
}

#[test]
fn real_guard_pair_publishes_once_preserves_other_account_and_needs_native_evidence() {
    let f = Fixture::new();
    let fence = f.fence();
    let observer = Observer {
        fixture: &f,
        calls: AtomicUsize::new(0),
        wrong_anvil: false,
        advance: None,
    };
    assert!(fence
        .publish_imap(&body("after", "session01"), &observer, f.clock.deadline())
        .is_err());
    assert_eq!(
        fence.allow(&body("before", "session01"), f.clock.deadline()),
        Decision::Allow
    );
    assert!(fence
        .publish_imap(&body("after", "session01"), &observer, f.clock.deadline())
        .is_err());
    assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fence.allow(&body("after", "session01"), f.clock.deadline()),
        Decision::Allow
    );
    let result = fence
        .publish_imap(&body("after", "session01"), &observer, f.clock.deadline())
        .unwrap();
    assert_eq!(
        (
            result.account(),
            result.session(),
            result.epoch(),
            result.pid()
        ),
        (ALICE, "session01", 0, 1234)
    );
    assert!(fence
        .publish_imap(&body("after", "session01"), &observer, f.clock.deadline())
        .is_err());
    assert_eq!(
        fence.allow(&body("after", "session01"), f.clock.deadline()),
        Decision::Deny
    );
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.store
            .lock_before(BOB, Instant::now() + CALLBACK)
            .unwrap()
            .admission(Some(0))
            .unwrap()
            .epoch,
        0
    );
    assert_eq!(Decision::Allow.body(), b"{\"status\":0}");
    assert_eq!(Decision::Deny.body(), b"{\"status\":-1}");
}

#[test]
fn changed_or_pending_epoch_refuses_after_and_cannot_refresh_or_publish() {
    for pending in [false, true] {
        let f = Fixture::new();
        let fence = f.fence();
        assert_eq!(
            fence.allow(&body("before", "epoch01"), f.clock.deadline()),
            Decision::Allow
        );
        f.change(pending);
        assert_eq!(
            fence.allow(&body("before", "epoch01"), f.clock.deadline()),
            Decision::Deny
        );
        assert_eq!(
            fence.allow(&body("after", "epoch01"), f.clock.deadline()),
            Decision::Deny
        );
        assert_eq!(
            fence.allow(&body("after", "epoch01"), f.clock.deadline()),
            Decision::Deny
        );
        let observer = Observer {
            fixture: &f,
            calls: AtomicUsize::new(0),
            wrong_anvil: false,
            advance: None,
        };
        assert!(fence
            .publish_imap(&body("after", "epoch01"), &observer, f.clock.deadline())
            .is_err());
        assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn failed_publication_is_consumed_and_rechecks_actual_epoch_after_policy() {
    for changed in [false, true] {
        let f = Fixture::new();
        let fence = f.fence();
        for phase in ["before", "after"] {
            assert_eq!(
                fence.allow(&body(phase, "publish01"), f.clock.deadline()),
                Decision::Allow
            );
        }
        if changed {
            f.change(false);
        }
        let observer = Observer {
            fixture: &f,
            calls: AtomicUsize::new(0),
            wrong_anvil: true,
            advance: None,
        };
        assert!(fence
            .publish_imap(&body("after", "publish01"), &observer, f.clock.deadline())
            .is_err());
        assert!(fence
            .publish_imap(&body("after", "publish01"), &observer, f.clock.deadline())
            .is_err());
        assert_eq!(
            observer.calls.load(Ordering::SeqCst),
            if changed { 0 } else { 1 }
        );
    }
}

#[test]
fn exact_request_scope_rejects_foreign_fields_pid_reports_identity_and_tls_changes() {
    let f = Fixture::new();
    let fence = f.fence();
    let valid: serde_json::Value = serde_json::from_slice(&body("before", "strict01")).unwrap();
    for extra in ["pid", "password", "success", "policy_reject", "request_id"] {
        let mut request = valid.clone();
        request[extra] = serde_json::json!(1234);
        assert_eq!(
            fence.allow(&serde_json::to_vec(&request).unwrap(), f.clock.deadline()),
            Decision::Deny
        );
    }
    for key in ["login", "protocol", "session_id", "phase", "tls"] {
        let mut request = valid.clone();
        request.as_object_mut().unwrap().remove(key);
        assert_eq!(
            fence.allow(&serde_json::to_vec(&request).unwrap(), f.clock.deadline()),
            Decision::Deny
        );
    }
    assert_eq!(
        fence.allow(br#"{"login":"x","login":"y"}"#, f.clock.deadline()),
        Decision::Deny
    );
    assert_eq!(
        fence.allow(&vec![b' '; 4097], f.clock.deadline()),
        Decision::Deny
    );
    assert_eq!(
        fence.allow(&body("before", "strict01"), f.clock.deadline()),
        Decision::Allow
    );
    for (key, value) in [
        ("login", serde_json::json!(BOB)),
        ("protocol", serde_json::json!("smtp")),
        ("session_id", serde_json::json!("other01")),
        ("tls", serde_json::json!(false)),
    ] {
        let mut request: serde_json::Value =
            serde_json::from_slice(&body("after", "strict01")).unwrap();
        request[key] = value;
        assert_eq!(
            fence.allow(&serde_json::to_vec(&request).unwrap(), f.clock.deadline()),
            Decision::Deny
        );
    }
    assert_eq!(
        fence.allow(&body("after", "strict01"), f.clock.deadline()),
        Decision::Allow
    );
}

#[test]
fn expiration_restart_rollback_and_callback_deadline_never_reissue_ticket() {
    let f = Fixture::new();
    let fence = f.fence();
    assert_eq!(
        fence.allow(&body("before", "expiry01"), f.clock.deadline()),
        Decision::Allow
    );
    assert_eq!(
        f.fence()
            .allow(&body("after", "expiry01"), f.clock.deadline()),
        Decision::Deny
    );
    f.clock.set(30_000);
    assert_eq!(
        fence.allow(&body("after", "expiry01"), f.clock.deadline()),
        Decision::Deny
    );
    assert_eq!(
        fence.allow(&body("before", "expiry01"), f.clock.deadline()),
        Decision::Allow
    );
    f.clock.set(29_999);
    assert_eq!(
        fence.allow(&body("after", "expiry01"), f.clock.deadline()),
        Decision::Deny
    );
    f.clock.set(31_000);
    assert_eq!(
        fence.allow(&body("before", "other01"), f.clock.deadline()),
        Decision::Deny
    );
    let fresh = f.fence();
    assert_eq!(
        fresh.allow(&body("before", "late01"), f.clock.now()),
        Decision::Deny
    );
    assert_eq!(
        fresh.allow(&body("before", "late01"), f.clock.deadline()),
        Decision::Deny
    );
    assert_eq!(
        fresh.allow(
            &body("before", "overlong01"),
            f.clock.now() + Duration::from_secs(1)
        ),
        Decision::Deny
    );
}

#[test]
fn native_observer_crossing_original_deadline_cannot_publish_or_retry() {
    let f = Fixture::new();
    let fence = f.fence();
    for phase in ["before", "after"] {
        assert_eq!(
            fence.allow(&body(phase, "late-native01"), f.clock.deadline()),
            Decision::Allow
        );
    }
    let observer = Observer {
        fixture: &f,
        calls: AtomicUsize::new(0),
        wrong_anvil: false,
        advance: Some(500),
    };
    let original = f.clock.deadline();
    assert!(fence
        .publish_imap(&body("after", "late-native01"), &observer, original)
        .is_err());
    assert!(fence
        .publish_imap(
            &body("after", "late-native01"),
            &observer,
            f.clock.deadline()
        )
        .is_err());
    assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn finite_capture_capacity_never_evicts_live_connection_or_expands_managed_scope() {
    let f = Fixture::new();
    let fence = f.fence();
    for index in 0..MAX_ENTRIES {
        assert_eq!(
            fence.allow(
                &body("before", &format!("bounded{index}")),
                f.clock.deadline()
            ),
            Decision::Allow
        );
    }
    assert_eq!(
        fence.allow(&body("before", "overflow"), f.clock.deadline()),
        Decision::Deny
    );
    assert_eq!(
        fence.allow(&body("after", "bounded0"), f.clock.deadline()),
        Decision::Allow
    );
    assert!(Fence::new(f.store.clone(), BTreeSet::new(), f.clock.clone()).is_err());
    assert!(Fence::new(f.store.clone(), ["invalid".into()].into(), f.clock.clone()).is_err());
}
