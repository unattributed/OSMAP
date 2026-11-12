use super::*;
use crate::session::{FileSessionStore, SessionRecord, SessionStore};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::time::Duration;

const ALICE: &str = "alice@recovery.invalid";
const BOB: &str = "bob@recovery.invalid";
const PASSWORD_TIME: &str = "20261027120000";
const OLD: &[u8] = b"# public RFC 6238 test vector\nsecret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
const NEW: &[u8] = b"# synthetic replacement factor\nsecret=KRUGS4ZANFZSAYJA\n";
const STAMP: &str = "20261029T120000Z";

struct Scratch {
    root: PathBuf,
}
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-recovery-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["epoch", "cases", "sessions", "factors", "revoked"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let value = Self { root };
        value.provision(ALICE, 3);
        value.provision(BOB, 7);
        value.write(&value.coordinator().factor_path(ALICE), OLD);
        value.write(&value.coordinator().factor_path(BOB), OLD);
        value.write(&value.root.join("sessions/.session-store.lock"), b"");
        let sessions = FileSessionStore::new(value.root.join("sessions"));
        for (letter, account, epoch) in [
            ('a', ALICE, Some(3)),
            ('b', ALICE, None),
            ('c', BOB, Some(7)),
        ] {
            sessions
                .save(&SessionRecord {
                    account_epoch: epoch,
                    session_id: letter.to_string().repeat(64),
                    csrf_token: "f".repeat(64),
                    canonical_username: account.into(),
                    issued_at: 100,
                    expires_at: 99999,
                    last_seen_at: 500,
                    revoked_at: None,
                    remote_addr: "127.0.0.1".into(),
                    user_agent: "Synthetic".into(),
                    factor: crate::auth::RequiredSecondFactor::Totp,
                })
                .unwrap();
        }
        value
    }
    fn coordinator(&self) -> Coordinator {
        Coordinator::new(Paths {
            epoch: self.root.join("epoch"),
            cases: self.root.join("cases"),
            sessions: self.root.join("sessions"),
            factors: self.root.join("factors"),
            revoked: self.root.join("revoked"),
            operator_uid: crate::openbsd::effective_uid(),
            runtime_uid: crate::openbsd::effective_uid(),
            runtime_gid: crate::openbsd::effective_gid(),
        })
    }
    fn write(&self, path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn epoch_stem(&self, account: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(b"osmap-account-epoch-v1\0");
        hash.update(account.as_bytes());
        format!("{:x}", hash.finalize())
    }
    fn provision(&self, account: &str, epoch: u64) {
        let stem = self.epoch_stem(account);
        self.write(&self.root.join(format!("epoch/{stem}.lock")), b"");
        self.write(&self.root.join(format!("epoch/{stem}.json")), &serde_json::to_vec(&serde_json::json!({
            "epoch": epoch, "state":"active", "changed_at": PASSWORD_TIME, "intent":null, "used_intents":[],
        })).unwrap());
    }
    fn epoch_record(&self, account: &str) -> Vec<u8> {
        fs::read(
            self.root
                .join(format!("epoch/{}.json", self.epoch_stem(account))),
        )
        .unwrap()
    }
    fn marker(&self) -> PathBuf {
        self.root
            .join(format!("epoch/{}.uncertain", self.epoch_stem(ALICE)))
    }
    fn replace_factor(&self) {
        let c = self.coordinator();
        fs::rename(c.factor_path(ALICE), c.archived_path(ALICE, STAMP)).unwrap();
        self.write(&c.factor_path(ALICE), NEW);
    }
    fn request(&self) -> Request {
        Request {
            schema: SCHEMA.into(),
            account: ALICE.into(),
            case_id: "synthetic-case-1".into(),
            expected_epoch: 3,
            previous_factor_sha256: format!("{:x}", Sha256::digest(OLD)),
            approval_sha256: "a".repeat(64),
            identity_method: IdentityMethod::InPerson,
            identity_case: "identity-1".into(),
            issued_at: 900,
            expires_at: 1800,
            replacement_factor_sha256: None,
            revoke_stamp: None,
        }
    }
    fn prepared_request(&self) -> Request {
        let mut request = self.request();
        request.replacement_factor_sha256 = Some(format!("{:x}", Sha256::digest(NEW)));
        request.revoke_stamp = Some(STAMP.into());
        request
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn actual_stores_recovery_preserves_password_and_foreign_account_and_advances_epoch_once() {
    let s = Scratch::new();
    let c = s.coordinator();
    let request = s.request();
    let bob_epoch = s.epoch_record(BOB);
    let bob_session =
        fs::read(s.root.join(format!("sessions/{}.session", "c".repeat(64)))).unwrap();
    let bob_factor = fs::read(c.factor_path(BOB)).unwrap();
    let result = c.begin(&request, 1000, until()).unwrap();
    assert_eq!(result.state, "pending");
    assert_eq!(result.case_state, Some(CaseState::SessionsRevoked));
    assert_eq!(
        c.epoch()
            .unwrap()
            .lock_before(ALICE, until())
            .unwrap()
            .admission(Some(3)),
        Err(crate::account_password_state::Error::Refused)
    );
    let prepared = s.prepared_request();
    assert_eq!(
        c.prepare_factor(&prepared, 1001, until())
            .unwrap()
            .case_state,
        Some(CaseState::FactorReplacement)
    );
    s.replace_factor();
    let done = s.coordinator().reconcile(&prepared, 1002, until()).unwrap();
    assert_eq!(done.state, "active");
    assert_eq!(done.epoch, 4);
    assert_eq!(done.case_state, Some(CaseState::Reconciled));
    assert_eq!(
        c.reconcile(&prepared, 1003, until()).err(),
        Some(Error::ReconciliationRequired)
    );
    assert_eq!(c.begin(&request, 1003, until()).err(), Some(Error::Replay));
    assert!(!s.marker().exists());
    let record: serde_json::Value = serde_json::from_slice(&s.epoch_record(ALICE)).unwrap();
    assert_eq!(record["changed_at"], PASSWORD_TIME);
    assert_eq!(s.epoch_record(BOB), bob_epoch);
    assert_eq!(fs::read(c.factor_path(BOB)).unwrap(), bob_factor);
    assert_eq!(
        fs::read(s.root.join(format!("sessions/{}.session", "c".repeat(64)))).unwrap(),
        bob_session
    );
    for letter in ['a', 'b'] {
        assert!(FileSessionStore::new(s.root.join("sessions"))
            .load(&letter.to_string().repeat(64))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
    }
    assert_eq!(
        c.epoch()
            .unwrap()
            .lock_before(ALICE, until())
            .unwrap()
            .admission(Some(3)),
        Err(crate::account_password_state::Error::Refused)
    );
}

#[test]
fn invalid_identity_scope_freshness_factor_and_epoch_refuse_before_account_effects() {
    for variant in 0..7 {
        let s = Scratch::new();
        let c = s.coordinator();
        let mut request = s.request();
        let epoch = s.epoch_record(ALICE);
        let factor = fs::read(c.factor_path(ALICE)).unwrap();
        let session =
            fs::read(s.root.join(format!("sessions/{}.session", "a".repeat(64)))).unwrap();
        match variant {
            0 => request.identity_method = IdentityMethod::ControlledTestCustody,
            1 => request.approval_sha256 = "not-a-digest".into(),
            2 => request.identity_case.clear(),
            3 => request.expires_at = 999,
            4 => request.previous_factor_sha256 = "0".repeat(64),
            5 => request.expected_epoch = 4,
            _ => request.account = "alice@recovery.invalid;bad".into(),
        }
        assert!(
            c.begin(&request, 1000, until()).is_err(),
            "variant {variant}"
        );
        assert_eq!(s.epoch_record(ALICE), epoch);
        assert_eq!(fs::read(c.factor_path(ALICE)).unwrap(), factor);
        assert_eq!(
            fs::read(s.root.join(format!("sessions/{}.session", "a".repeat(64)))).unwrap(),
            session
        );
        assert!(!s.marker().exists());
    }
}

#[test]
fn case_and_factor_admission_cannot_be_replayed_or_switched() {
    let s = Scratch::new();
    let c = s.coordinator();
    c.begin(&s.request(), 1000, until()).unwrap();
    let baseline = s.epoch_record(ALICE);
    for variant in 0..5 {
        let mut request = s.prepared_request();
        match variant {
            0 => request.case_id = "foreign-case".into(),
            1 => request.approval_sha256 = "b".repeat(64),
            2 => request.expected_epoch = 2,
            3 => request.previous_factor_sha256 = "c".repeat(64),
            _ => request.account = BOB.into(),
        }
        assert!(c.prepare_factor(&request, 1001, until()).is_err());
        assert_eq!(s.epoch_record(ALICE), baseline);
    }
    c.prepare_factor(&s.prepared_request(), 1001, until())
        .unwrap();
    assert_eq!(
        c.prepare_factor(&s.prepared_request(), 1002, until()).err(),
        Some(Error::ReconciliationRequired)
    );
}

#[test]
fn restart_after_dispatch_admission_never_repeats_or_automatically_releases() {
    let s = Scratch::new();
    s.coordinator().begin(&s.request(), 1000, until()).unwrap();
    s.coordinator()
        .prepare_factor(&s.prepared_request(), 1001, until())
        .unwrap();
    let restarted = s.coordinator();
    assert_eq!(
        restarted.status(ALICE, until()).unwrap().case_state,
        Some(CaseState::FactorReplacement)
    );
    assert_eq!(
        restarted
            .prepare_factor(&s.prepared_request(), 1002, until())
            .err(),
        Some(Error::ReconciliationRequired)
    );
    assert_eq!(
        restarted
            .reconcile(&s.prepared_request(), 1002, until())
            .err(),
        Some(Error::FactorMismatch)
    );
    assert_eq!(restarted.status(ALICE, until()).unwrap().state, "pending");
    s.replace_factor();
    assert_eq!(
        restarted
            .reconcile(&s.prepared_request(), 1003, until())
            .err(),
        Some(Error::ReconciliationRequired)
    );
    assert!(s.marker().exists());
}

#[test]
fn wrong_marker_inode_and_password_marker_cannot_be_adopted() {
    for password_marker in [false, true] {
        let s = Scratch::new();
        let c = s.coordinator();
        c.begin(&s.request(), 1000, until()).unwrap();
        c.prepare_factor(&s.prepared_request(), 1001, until())
            .unwrap();
        s.replace_factor();
        let existing = fs::read(s.marker()).unwrap();
        let held = OpenOptions::new().read(true).open(s.marker()).unwrap();
        fs::remove_file(s.marker()).unwrap();
        let replacement = if password_marker {
            b"osmap-password-uncertain-v1\nforeign\n".as_slice()
        } else {
            &existing
        };
        s.write(&s.marker(), replacement);
        assert_eq!(
            c.reconcile(&s.prepared_request(), 1002, until()).err(),
            Some(Error::ContainmentIncomplete)
        );
        assert_eq!(c.status(ALICE, until()).unwrap().state, "pending");
        drop(held);
    }
}

#[test]
fn missing_durable_marker_custody_requires_manual_reconciliation() {
    let s = Scratch::new();
    let c = s.coordinator();
    c.begin(&s.request(), 1000, until()).unwrap();
    let locked = c.files().lock(ALICE).unwrap();
    let mut case = c.load(&locked).unwrap().unwrap();
    case.marker = None;
    c.save(&locked, &case).unwrap();
    drop(locked);
    assert_eq!(
        c.prepare_factor(&s.prepared_request(), 1001, until()).err(),
        Some(Error::ContainmentIncomplete)
    );
    assert_eq!(c.status(ALICE, until()).unwrap().state, "pending");
}

#[test]
fn symlinked_factor_and_unrelated_password_pending_are_refused() {
    let s = Scratch::new();
    let c = s.coordinator();
    fs::remove_file(c.factor_path(ALICE)).unwrap();
    symlink(c.factor_path(BOB), c.factor_path(ALICE)).unwrap();
    assert!(c.begin(&s.request(), 1000, until()).is_err());
    fs::remove_file(c.factor_path(ALICE)).unwrap();
    s.write(&c.factor_path(ALICE), OLD);
    let epoch = c.epoch().unwrap();
    let mut guard = epoch.lock_before(ALICE, until()).unwrap();
    guard.begin(3, &"f".repeat(64), 1000).unwrap();
    drop(guard);
    let before = s.epoch_record(ALICE);
    assert_eq!(
        c.begin(&s.request(), 1000, until()).err(),
        Some(Error::EpochMismatch)
    );
    assert_eq!(s.epoch_record(ALICE), before);
}

#[test]
fn bounded_case_record_contains_no_factor_material_and_status_is_read_only() {
    let s = Scratch::new();
    let c = s.coordinator();
    assert_eq!(c.status(ALICE, until()).unwrap().case_state, None);
    c.begin(&s.request(), 1000, until()).unwrap();
    let bytes = c.files().read(ALICE).unwrap().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("secret="));
    assert!(!text.contains("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    assert!(!text.contains("KRUGS4ZANFZSAYJA"));
    assert!(bytes.len() < MAX_CASE_BYTES);
    c.status(ALICE, until()).unwrap();
    assert_eq!(c.files().read(ALICE).unwrap().unwrap(), bytes);
}

#[test]
fn actual_session_snapshot_failure_retains_first_diagnostic_and_containment() {
    let s = Scratch::new();
    let c = s.coordinator();
    let path = s.root.join(format!("sessions/{}.session", "a".repeat(64)));
    let original = fs::read(&path).unwrap();
    s.write(&path, b"malformed-session\n");
    assert_eq!(
        c.begin(&s.request(), 1000, until()).err(),
        Some(Error::SessionsIncomplete)
    );
    let status = c.status(ALICE, until()).unwrap();
    assert_eq!(status.state, "pending");
    assert_eq!(status.case_state, Some(CaseState::Contained));
    assert_eq!(status.failure, Some(Error::SessionsIncomplete));
    assert_eq!(
        status.session_failure,
        Some(SessionFailure {
            stage: SessionFailureStage::Snapshot,
            attempted_writes: 0,
            completed_writes: 0
        })
    );
    s.write(&path, &original);
    assert_eq!(
        c.prepare_factor(&s.prepared_request(), 1001, until()).err(),
        Some(Error::ReconciliationRequired)
    );
    assert_eq!(
        c.status(ALICE, until()).unwrap().session_failure,
        status.session_failure
    );
    assert_eq!(fs::read(c.factor_path(ALICE)).unwrap(), OLD);
}

#[test]
fn interruption_after_actual_release_retains_truthful_uncertainty_and_refuses_replay() {
    let s = Scratch::new();
    let c = s.coordinator();
    c.begin(&s.request(), 1000, until()).unwrap();
    c.prepare_factor(&s.prepared_request(), 1001, until())
        .unwrap();
    s.replace_factor();
    INTERRUPT_AFTER_RELEASE.with(|value| value.set(true));
    assert_eq!(
        c.reconcile(&s.prepared_request(), 1002, until()).err(),
        Some(Error::CaseWrite)
    );
    let restarted = s.coordinator();
    let status = restarted.status(ALICE, until()).unwrap();
    assert_eq!(status.state, "active");
    assert_eq!(status.epoch, 4);
    assert_eq!(status.case_state, Some(CaseState::ReleasePending));
    assert_eq!(
        restarted
            .reconcile(&s.prepared_request(), 1003, until())
            .err(),
        Some(Error::ReconciliationRequired)
    );
    assert_eq!(
        restarted
            .prepare_factor(&s.prepared_request(), 1003, until())
            .err(),
        Some(Error::ReconciliationRequired)
    );
    assert_eq!(
        restarted.begin(&s.request(), 1003, until()).err(),
        Some(Error::Replay)
    );
    assert_eq!(restarted.status(ALICE, until()).unwrap().epoch, 4);
    assert!(!s.marker().exists());
}

#[test]
fn same_marker_inode_with_changed_domain_or_intent_is_not_release_authority() {
    let s = Scratch::new();
    let c = s.coordinator();
    c.begin(&s.request(), 1000, until()).unwrap();
    c.prepare_factor(&s.prepared_request(), 1001, until())
        .unwrap();
    s.replace_factor();
    let inode = fs::metadata(s.marker()).unwrap().ino();
    s.write(&s.marker(), b"osmap-password-uncertain-v1\nwrong-case\n");
    assert_eq!(fs::metadata(s.marker()).unwrap().ino(), inode);
    assert_eq!(
        c.reconcile(&s.prepared_request(), 1002, until()).err(),
        Some(Error::ContainmentIncomplete)
    );
    assert_eq!(c.status(ALICE, until()).unwrap().epoch, 3);
}

#[test]
fn exact_serialized_native_status_fixture() {
    let s = Scratch::new();
    let c = s.coordinator();
    println!(
        "RECOVERY_STATUS_FIXTURE={}",
        serde_json::to_string(&c.status(ALICE, until()).unwrap()).unwrap()
    );
    println!(
        "RECOVERY_STATUS_FIXTURE={}",
        serde_json::to_string(&c.begin(&s.request(), 1000, until()).unwrap()).unwrap()
    );
    println!(
        "RECOVERY_STATUS_FIXTURE={}",
        serde_json::to_string(
            &c.prepare_factor(&s.prepared_request(), 1001, until())
                .unwrap()
        )
        .unwrap()
    );
    s.replace_factor();
    println!(
        "RECOVERY_STATUS_FIXTURE={}",
        serde_json::to_string(&c.reconcile(&s.prepared_request(), 1002, until()).unwrap()).unwrap()
    );
}

#[test]
fn signed_expiry_bounds_real_lock_wait_without_account_or_factor_effects() {
    let s = Scratch::new();
    let c = s.coordinator();
    let mut request = s.request();
    request.expires_at = 1001;
    // Establish the actual factor/epoch/case read path before holding the lock.
    // A fixture ownership or I/O refusal must not masquerade as lock expiry.
    let preflight = c.status(ALICE, until()).unwrap();
    assert_eq!(preflight.state, "active");
    assert_eq!(preflight.epoch, request.expected_epoch);
    assert_eq!(
        preflight.existing_factor_sha256.as_deref(),
        Some(request.previous_factor_sha256.as_str())
    );
    assert_eq!(preflight.case_state, None);
    let epoch_bytes = s.epoch_record(ALICE);
    let epoch = c.epoch().unwrap();
    let _held = epoch.lock_before(ALICE, until()).unwrap();
    let began = Instant::now();
    assert_eq!(
        c.begin(&request, 1000, began + Duration::from_secs(4))
            .err(),
        Some(Error::StateUnavailable)
    );
    let elapsed = began.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "the held epoch lock must be the refusal boundary"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "signed one-second remainder must bound the four-second operation"
    );
    assert_eq!(s.epoch_record(ALICE), epoch_bytes);
    assert_eq!(fs::read(c.factor_path(ALICE)).unwrap(), OLD);
    assert!(!s.marker().exists());
    assert!(c.files().read(ALICE).unwrap().is_none());
}
