use super::*;
use crate::openpgp_crypto::{Operation, Outcome, SignatureState};
use crate::protected_message::{CryptoExecutor, CryptoFailure};
use crate::protected_submission::{PreparedSubmission, SubmissionProtection};
use crate::scheduled_send::{ClaimedJob, ScheduleInput, ScheduledStore};
use std::cell::Cell;

struct ClaimFixture {
    root: PathBuf,
}
impl ClaimFixture {
    fn new() -> Self {
        Self {
            root: std::env::temp_dir().join(format!(
                "osmap-send-job-{}",
                crate::draft::generate_draft_id().unwrap()
            )),
        }
    }
    fn claim(&self, account: &str, request: &ComposeRequest) -> ClaimedJob {
        let store = ScheduledStore::new(self.root.join("jobs"));
        let journal = crate::send_journal::SendJournal::new(self.root.join("journal"));
        {
            let mut guard = journal.account_guard(account, 100).unwrap();
            let staged = store
                .create_staged(
                    &guard,
                    0,
                    ScheduleInput {
                        due_at: 200,
                        account_epoch: 2,
                        private_session: crate::openpgp_personal::PrivateSession {
                            session_id: "a".repeat(64),
                            account_epoch: Some(2),
                            expires_at: 28800,
                        },
                        request,
                    },
                    100,
                )
                .unwrap();
            let source = crate::send_journal::mint_intent(100).unwrap();
            guard
                .begin_schedule(&source, &staged.id, &staged.digest)
                .unwrap();
            store
                .publish_pending(&guard, staged.revision, &staged.id, &staged.digest, 100)
                .unwrap();
            guard
                .finish_schedule(&source, &staged.id, &staged.digest)
                .unwrap();
        }
        let guard = journal.account_guard(account, 200).unwrap();
        store.claim_next(&guard, 200).unwrap().unwrap()
    }
}
impl Drop for ClaimFixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

struct SyntheticSigner;
impl CryptoExecutor for SyntheticSigner {
    fn execute(
        &self,
        _: &crate::identity::CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        let Operation::Sign {
            signer_fingerprint, ..
        } = operation
        else {
            panic!("scheduled submission unit control signs only");
        };
        Ok(Outcome {
            operation: "sign".into(),
            content:
                b"-----BEGIN PGP SIGNATURE-----\n\nZml4dHVyZQ==\n-----END PGP SIGNATURE-----\n"
                    .to_vec(),
            signer_fingerprint: Some(signer_fingerprint.clone()),
            primary_fingerprint: Some(signer_fingerprint.clone()),
            signature: SignatureState::Valid,
            hash_algorithm: Some(8),
        })
    }
}
fn request(sign: bool) -> ComposeRequest {
    let mut request = ComposeRequest::new(
        ComposePolicy::default(),
        "recipient@example.test",
        "Private scheduled subject",
        "Private scheduled body",
    )
    .unwrap();
    if sign {
        request.protection = ProtectionIntent {
            sign: true,
            encrypt: false,
            encrypt_to_self: false,
            binding_revision: Some(7),
        };
    }
    request
}
fn prepared(account: &str, request: &ComposeRequest) -> PreparedSubmission {
    crate::protected_submission::prepare(
        &SyntheticSigner,
        &crate::identity::CanonicalUsername::parse(account).unwrap(),
        request,
        &crate::openpgp_bindings::OperationPlan {
            signer_fingerprint: request.protection.sign.then(|| "A".repeat(40)),
            recipient_fingerprints: Vec::new(),
            encrypt_to_self: false,
        },
    )
    .unwrap()
}
struct CountingPrepared {
    calls: Cell<usize>,
    bytes: RefCell<Vec<u8>>,
    fail: bool,
}
impl CountingPrepared {
    fn new(fail: bool) -> Self {
        Self {
            calls: Cell::new(0),
            bytes: RefCell::new(Vec::new()),
            fail,
        }
    }
}
impl SubmissionBackend for CountingPrepared {
    fn submit_message(&self, _: &str, _: &ComposeRequest) -> Result<(), SubmissionBackendError> {
        panic!("scheduled prepared path must not invoke raw composer");
    }
    fn submit_prepared_message(
        &self,
        account: &str,
        request: &ComposeRequest,
        prepared: &PreparedSubmission,
    ) -> Result<(), SubmissionBackendError> {
        prepared
            .validate_for(
                &crate::identity::CanonicalUsername::parse(account).unwrap(),
                request,
            )
            .unwrap();
        self.calls.set(self.calls.get() + 1);
        *self.bytes.borrow_mut() = prepared.as_bytes().to_vec();
        if self.fail {
            Err(SubmissionBackendError {
                backend: "synthetic-prepared",
                reason: "private failure detail".into(),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn scheduled_prepared_dispatch_uses_real_claim_and_exact_ordinary_or_protected_bytes() {
    for sign in [false, true] {
        let fixture = ClaimFixture::new();
        let request = request(sign);
        let claim = fixture.claim("alice@example.com", &request);
        let prepared = prepared("alice@example.com", &request);
        assert_eq!(
            prepared.protection(),
            if sign {
                SubmissionProtection::Signed
            } else {
                SubmissionProtection::Ordinary
            }
        );
        let service = SubmissionService::new(CountingPrepared::new(false));
        let outcome = service.submit_prepared_for_scheduled_job(&claim, &prepared);
        assert!(matches!(
            outcome.decision,
            SubmissionDecision::Submitted { .. }
        ));
        assert_eq!(service.backend.calls.get(), 1);
        assert_eq!(*service.backend.bytes.borrow(), prepared.as_bytes());
        let audit = Logger::new(LogFormat::Text, LogLevel::Debug)
            .render_with_timestamp(&outcome.audit_event, 200);
        assert!(audit.contains("submission_origin=\"scheduled\""));
        assert!(audit.contains(&format!("scheduled_job_ref=\"{}\"", claim.id())));
        for forbidden in [
            "session_ref=",
            "remote_addr=",
            "user_agent=",
            "request_id=",
            "Private scheduled",
            "private failure detail",
        ] {
            assert!(
                !audit.contains(forbidden),
                "scheduled audit leaked {forbidden}"
            );
        }
    }
}

#[test]
fn scheduled_prepared_dispatch_refuses_wrong_account_or_changed_snapshot_before_callback() {
    let fixture = ClaimFixture::new();
    let request = request(true);
    let claim = fixture.claim("alice@example.com", &request);
    let service = SubmissionService::new(CountingPrepared::new(false));
    let foreign = prepared("bob@example.com", &request);
    assert!(matches!(
        service
            .submit_prepared_for_scheduled_job(&claim, &foreign)
            .decision,
        SubmissionDecision::Denied { .. }
    ));
    let mut changed = request.clone();
    changed.body.push_str(" changed after claim");
    let changed = prepared("alice@example.com", &changed);
    assert!(matches!(
        service
            .submit_prepared_for_scheduled_job(&claim, &changed)
            .decision,
        SubmissionDecision::Denied { .. }
    ));
    assert_eq!(service.backend.calls.get(), 0);
    assert!(service.backend.bytes.borrow().is_empty());
}

#[test]
fn scheduled_prepared_failure_is_unconfirmed_and_never_retried_inside_service() {
    let fixture = ClaimFixture::new();
    let request = request(false);
    let claim = fixture.claim("alice@example.com", &request);
    let prepared = prepared("alice@example.com", &request);
    let service = SubmissionService::new(CountingPrepared::new(true));
    let outcome = service.submit_prepared_for_scheduled_job(&claim, &prepared);
    assert!(matches!(
        outcome.decision,
        SubmissionDecision::Unconfirmed { .. }
    ));
    assert_eq!(service.backend.calls.get(), 1);
    let audit = Logger::new(LogFormat::Text, LogLevel::Debug)
        .render_with_timestamp(&outcome.audit_event, 200);
    assert!(audit.contains("message_submit_unconfirmed") && audit.contains("scheduled_job_ref="));
    assert!(!audit.contains("private failure detail") && !audit.contains("session_ref="));
}

#[test]
fn browser_prepared_delegation_preserves_browser_audit_and_account_refusal() {
    let request = request(false);
    let prepared = prepared("alice@example.com", &request);
    let service = SubmissionService::new(CountingPrepared::new(false));
    let context = test_context();
    let session = validated_session_fixture();
    let outcome =
        service.submit_prepared_for_validated_session(&context, &session, &request, &prepared);
    assert!(matches!(
        outcome.decision,
        SubmissionDecision::Submitted { .. }
    ));
    assert_eq!(service.backend.calls.get(), 1);
    let audit = Logger::new(LogFormat::Text, LogLevel::Debug)
        .render_with_timestamp(&outcome.audit_event, 200);
    assert!(audit.contains("session_ref=") && audit.contains("request_id=\"req-send\""));
    assert!(
        audit.contains("remote_addr=\"127.0.0.1\"")
            && audit.contains("user_agent=\"Firefox/Test\"")
    );
    assert!(!audit.contains("scheduled_job_ref=") && !audit.contains("submission_origin="));
    let mut foreign = session;
    foreign.record.canonical_username = "bob@example.com".into();
    assert!(matches!(
        service
            .submit_prepared_for_validated_session(&context, &foreign, &request, &prepared)
            .decision,
        SubmissionDecision::Denied { .. }
    ));
    assert_eq!(service.backend.calls.get(), 1);
}
