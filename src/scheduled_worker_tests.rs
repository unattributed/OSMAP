use super::*;
use crate::openpgp_personal::PrivateSession;
use crate::scheduled_send::{JobView, ScheduleInput};
use crate::send::{ComposePolicy, ComposeRequest};
use std::path::PathBuf;

const ALICE: &str = "alice@example.test";
struct Fixture {
    root: PathBuf,
    store: ScheduledStore,
    journal: SendJournal,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-scheduled-worker-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        Self {
            store: ScheduledStore::new(root.join("scheduled-send")),
            journal: SendJournal::new(root.join("send-journal")),
            root,
        }
    }
    fn pending(&self, account: &str, now: u64, due: u64) -> String {
        let mut guard = self.journal.account_guard(account, now).unwrap();
        let revision = self.store.list(&guard, now).unwrap().revision;
        let request = request();
        let job = self
            .store
            .create_staged(
                &guard,
                revision,
                ScheduleInput {
                    due_at: due,
                    account_epoch: 2,
                    private_session: PrivateSession {
                        session_id: "a".repeat(64),
                        account_epoch: Some(2),
                        expires_at: now + 28800,
                    },
                    request: &request,
                },
                now,
            )
            .unwrap();
        let source = crate::send_journal::mint_intent(now).unwrap();
        guard.begin_schedule(&source, &job.id, &job.digest).unwrap();
        self.store
            .publish_pending(&guard, job.revision, &job.id, &job.digest, now)
            .unwrap();
        guard
            .finish_schedule(&source, &job.id, &job.digest)
            .unwrap();
        job.id
    }
    fn claim(&self, account: &str, now: u64) -> ClaimedJob {
        let guard = self.journal.account_guard(account, now).unwrap();
        self.store.claim_next(&guard, now).unwrap().unwrap()
    }
    fn view(&self, account: &str, id: &str, now: u64) -> JobView {
        let guard = self.journal.account_guard(account, now).unwrap();
        self.store
            .list(&guard, now)
            .unwrap()
            .jobs
            .into_iter()
            .find(|job| job.id == id)
            .unwrap()
    }
    fn receipt(
        &self,
        claim: &ClaimedJob,
        request: ComposeRequest,
        outcome: AttemptOutcome,
        now: u64,
    ) {
        let result = self
            .journal
            .execute_prepared::<()>(
                claim.account(),
                claim.intent(),
                now,
                |_| Ok(request),
                |_| outcome,
            )
            .unwrap();
        assert!(matches!(
            result,
            crate::send_journal::PreparedResult::Outcome(_)
        ));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() && self.root.exists() {
            std::fs::remove_dir_all(&self.root).unwrap();
            assert!(!self.root.exists());
        }
    }
}
fn request() -> ComposeRequest {
    ComposeRequest::new(
        ComposePolicy::default(),
        "recipient@example.test",
        "scheduled",
        "private captured body",
    )
    .unwrap()
}
fn accepted_outcome() -> AttemptOutcome {
    AttemptOutcome::Accepted {
        sent_copy_stored: true,
    }
}

#[test]
fn restart_without_journal_attempt_resumes_exact_claim_once_and_drops_guard() {
    let f = Fixture::new();
    let id = f.pending(ALICE, 100, 200);
    let interrupted = f.claim(ALICE, 200);
    let intent = interrupted.intent().to_owned();
    let digest = interrupted.digest().to_owned();
    let mut calls = 0;
    run_account(&f.store, &f.journal, ALICE, &|| 201, &mut |claim| {
        calls += 1;
        assert_eq!(claim.intent(), intent);
        assert_eq!(claim.digest(), digest);
        // This real journal acquisition would fail if the worker kept its guard.
        f.receipt(claim, claim.request().clone(), accepted_outcome(), 201);
        DispatchDecision::Submitted
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(f.view(ALICE, &id, 202).state, State::Submitted);
    run_account(&f.store, &f.journal, ALICE, &|| 203, &mut |_| {
        panic!("submitted job rearmed")
    })
    .unwrap();
}

#[test]
fn restart_with_matching_accepted_receipt_settles_without_dispatch() {
    let f = Fixture::new();
    let id = f.pending(ALICE, 100, 200);
    let claim = f.claim(ALICE, 200);
    f.receipt(&claim, claim.request().clone(), accepted_outcome(), 200);
    run_account(&f.store, &f.journal, ALICE, &|| 201, &mut |_| {
        panic!("accepted attempt resubmitted")
    })
    .unwrap();
    assert_eq!(f.view(ALICE, &id, 201).state, State::Submitted);
}

#[test]
fn uncertain_attempt_becomes_unknown_never_rearms_and_does_not_starve_pending() {
    let f = Fixture::new();
    let unknown = f.pending(ALICE, 100, 200);
    let claim = f.claim(ALICE, 200);
    f.receipt(
        &claim,
        claim.request().clone(),
        AttemptOutcome::Unconfirmed,
        200,
    );
    run_account(&f.store, &f.journal, ALICE, &|| 201, &mut |_| {
        panic!("uncertain attempt resubmitted")
    })
    .unwrap();
    assert_eq!(f.view(ALICE, &unknown, 201).state, State::Unknown);
    let next = f.pending(ALICE, 201, 202);
    let mut calls = 0;
    run_account(&f.store, &f.journal, ALICE, &|| 202, &mut |claim| {
        calls += 1;
        assert_eq!(claim.id(), next);
        f.receipt(claim, claim.request().clone(), accepted_outcome(), 202);
        DispatchDecision::Submitted
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(f.view(ALICE, &unknown, 202).state, State::Unknown);
    assert_eq!(f.view(ALICE, &next, 202).state, State::Submitted);
}

#[test]
fn accepted_receipt_for_wrong_snapshot_cannot_settle_or_dispatch_claim() {
    let f = Fixture::new();
    let id = f.pending(ALICE, 100, 200);
    let claim = f.claim(ALICE, 200);
    let mut other = claim.request().clone();
    other.subject = "a different captured message".into();
    f.receipt(&claim, other, accepted_outcome(), 200);
    run_account(&f.store, &f.journal, ALICE, &|| 201, &mut |_| {
        panic!("mismatched receipt dispatched")
    })
    .unwrap();
    assert_eq!(f.view(ALICE, &id, 201).state, State::Unknown);
}

#[test]
fn corrupt_account_receipt_refuses_before_dispatch_and_preserves_other_account() {
    let f = Fixture::new();
    let id = f.pending(ALICE, 100, 200);
    let _claim = f.claim(ALICE, 200);
    let bob = f.pending("bob@example.test", 100, 200);
    let bytes = f
        .journal
        .receipt(
            "bob@example.test",
            "100.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            200,
        )
        .unwrap();
    assert_eq!(bytes, None);
    let journal_file = PrivateAccountFile::new(
        f.root.join("send-journal"),
        "osmap-send-journal-v1",
        1024 * 1024,
    );
    journal_file.lock(ALICE).unwrap().write(b"{broken").unwrap();
    assert!(
        run_account(&f.store, &f.journal, ALICE, &|| 201, &mut |_| panic!(
            "corrupt journal dispatched"
        ))
        .is_err()
    );
    assert_eq!(f.view("bob@example.test", &bob, 201).state, State::Pending);
    assert_eq!(
        f.journal
            .receipt(ALICE, "100.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 201),
        Err(crate::send_journal::JournalError::InvalidRecord)
    );
    assert!(!id.is_empty());
}

#[test]
fn foreign_account_index_refuses_without_dispatch() {
    let f = Fixture::new();
    f.pending(ALICE, 100, 200);
    f.pending("bob@example.test", 100, 200);
    let file = PrivateAccountFile::new(
        f.root.join("scheduled-send/index"),
        "scheduled-send-v1",
        1024 * 1024,
    );
    let foreign = file.read("bob@example.test").unwrap().unwrap();
    file.lock(ALICE).unwrap().write(&foreign).unwrap();
    assert!(
        run_account(&f.store, &f.journal, ALICE, &|| 200, &mut |_| panic!(
            "foreign job dispatched"
        ))
        .is_err()
    );
}

#[test]
fn one_global_lease_excludes_a_competing_worker_during_real_dispatch() {
    let f = Fixture::new();
    let id = f.pending(ALICE, 100, 200);
    let mut calls = 0;
    let result = run_once(
        &f.root,
        || 200,
        |claim| {
            calls += 1;
            assert!(matches!(
                run_once(&f.root, || 200, |_| panic!("competing worker dispatched")),
                Err(Error::Unavailable)
            ));
            f.receipt(claim, claim.request().clone(), accepted_outcome(), 200);
            DispatchDecision::Submitted
        },
    )
    .unwrap();
    assert_eq!(result.accounts_checked, 1);
    assert_eq!(result.accounts_unavailable, 0);
    assert_eq!(calls, 1);
    assert_eq!(f.view(ALICE, &id, 201).state, State::Submitted);
}

#[test]
fn persisted_rotation_reaches_more_than_eight_accounts_and_refuses_clock_rollback() {
    let f = Fixture::new();
    let accounts: Vec<_> = (0..10)
        .map(|n| format!("user{n:02}@example.test"))
        .collect();
    for account in &accounts {
        f.pending(account, 100, 200);
    }
    let mut calls = Vec::new();
    for now in [200, 201] {
        let result = run_once(
            &f.root,
            || now,
            |claim| {
                calls.push(claim.account().to_owned());
                f.receipt(claim, claim.request().clone(), accepted_outcome(), now);
                DispatchDecision::Submitted
            },
        )
        .unwrap();
        assert_eq!(result.accounts_checked, 8);
        assert_eq!(result.accounts_unavailable, 0);
    }
    assert_eq!(calls, accounts);
    assert!(matches!(
        run_once(&f.root, || 199, |_| panic!("clock rollback dispatched")),
        Err(Error::ClockRollback)
    ));
    run_once(&f.root, || 202, |_| panic!("completed jobs rearmed")).unwrap();
}
