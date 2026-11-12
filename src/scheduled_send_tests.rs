use super::*;
const ACCOUNT: &str = "alice@example.test";
#[test]
fn return_to_draft_is_durable_non_dispatchable_and_exact_revision_owned() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    let original = request();
    let staged = f.pending(&mut guard, 0, &original, 200, 100);
    let list = f.store.list(&guard, 101).unwrap();
    let (prepared, captured) = f.store.prepare_return_to_draft(&guard, list.revision, &staged.id, 101).unwrap();
    assert_eq!(captured, original);
    assert_eq!(prepared.jobs[0].state, State::ReturningToDraft);
    let reopened = ScheduledStore::new(f.root.join("jobs"));
    assert!(reopened.claim_next(&guard, 201).unwrap().is_none());
    assert!(matches!(reopened.cancel(&guard, prepared.revision, &staged.id, 201), Err(Error::Invalid)));
    let (resumed, captured) = reopened.prepare_return_to_draft(&guard, prepared.revision, &staged.id, 201).unwrap();
    assert_eq!(captured, original);
    let foreign = f.guard("bob@example.test", 201);
    assert!(matches!(reopened.finish_return_to_draft(&foreign, 0, &staged.id, 201), Err(Error::NotFound)));
    assert!(matches!(reopened.finish_return_to_draft(&guard, 0, &staged.id, 201), Err(Error::Stale)));
    let finished = reopened.finish_return_to_draft(&guard, resumed.revision, &staged.id, 201).unwrap();
    assert_eq!(finished.jobs[0].state, State::Cancelled);
    assert!(reopened.claim_next(&guard, 202).unwrap().is_none());
    assert!(reopened.read(&guard, &staged.id, 202).is_err());
}
struct Fixture {
    root: PathBuf,
    store: ScheduledStore,
    journal: crate::send_journal::SendJournal,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-scheduled-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        Self {
            store: ScheduledStore::new(root.join("jobs")),
            journal: crate::send_journal::SendJournal::new(root.join("journal")),
            root,
        }
    }
    fn guard(&self, account: &str, now: u64) -> AccountGuard {
        self.journal.account_guard(account, now).unwrap()
    }
    fn pending(
        &self,
        guard: &mut AccountGuard,
        revision: u64,
        request: &ComposeRequest,
        due: u64,
        now: u64,
    ) -> StagedJob {
        let staged = self
            .store
            .create_staged(guard, revision, input(request, due, now), now)
            .unwrap();
        let source = crate::send_journal::mint_intent(now).unwrap();
        guard
            .begin_schedule(&source, &staged.id, &staged.digest)
            .unwrap();
        self.store
            .publish_pending(guard, staged.revision, &staged.id, &staged.digest, now)
            .unwrap();
        guard
            .finish_schedule(&source, &staged.id, &staged.digest)
            .unwrap();
        staged
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
fn request() -> ComposeRequest {
    ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        "one@example.test",
        "cc@example.test",
        "bcc@example.test",
        "Captured subject",
        "private body",
        Vec::new(),
    )
    .unwrap()
}
fn session(now: u64) -> PrivateSession {
    PrivateSession {
        session_id: "a".repeat(64),
        account_epoch: Some(2),
        expires_at: now + 28800,
    }
}
fn input(request: &ComposeRequest, due: u64, now: u64) -> ScheduleInput<'_> {
    ScheduleInput {
        due_at: due,
        account_epoch: 2,
        private_session: session(now),
        request,
    }
}

#[test]
fn staging_is_non_dispatchable_until_exact_journal_retirement_and_snapshot_survives_reopen() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    let mut original = request();
    let staged = f
        .store
        .create_staged(&guard, 0, input(&original, 200, 100), 100)
        .unwrap();
    assert!(f.store.claim_next(&guard, 100).unwrap().is_none());
    assert!(matches!(
        f.store
            .publish_pending(&guard, staged.revision, &staged.id, &staged.digest, 100),
        Err(Error::Invalid)
    ));
    let intent = crate::send_journal::mint_intent(100).unwrap();
    guard
        .begin_schedule(&intent, &staged.id, &staged.digest)
        .unwrap();
    assert!(matches!(
        guard.require_unconsumed(&intent),
        Err(crate::send_journal::JournalError::Consumed)
    ));
    let published = f
        .store
        .publish_pending(&guard, staged.revision, &staged.id, &staged.digest, 100)
        .unwrap();
    assert_eq!(published.jobs[0].subject, "Captured subject");
    guard
        .finish_schedule(&intent, &staged.id, &staged.digest)
        .unwrap();
    original.body = "later draft edit".into();
    assert_ne!(original, request());
    let reopened = ScheduledStore::new(f.root.join("jobs"));
    assert_eq!(reopened.read(&guard, &staged.id, 101).unwrap(), request());
    assert_eq!(published.jobs[0].state, State::Pending);
    assert!(matches!(
        reopened.cancel(&guard, 0, &staged.id, 101),
        Err(Error::Stale)
    ));
    assert_eq!(
        reopened.list(&guard, 101).unwrap().revision,
        published.revision
    );
    assert_eq!(
        reopened.list(&guard, 102).unwrap().revision,
        published.revision
    );
    let foreign = f.guard("bob@example.test", 101);
    assert!(matches!(
        reopened.read(&foreign, &staged.id, 101),
        Err(Error::NotFound)
    ));
    assert!(!format!("{:?}", published).contains("private body"));
}

#[test]
fn due_claim_is_stable_restart_recovery_and_completion_never_rearm() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    let staged = f.pending(&mut guard, 0, &request(), 200, 100);
    assert!(f.store.claim_next(&guard, 199).unwrap().is_none());
    let claim = f.store.claim_next(&guard, 200).unwrap().unwrap();
    let intent = claim.intent().to_string();
    assert_eq!(claim.request(), &request());
    assert_eq!(claim.account_epoch(), 2);
    assert!(f.store.claim_next(&guard, 201).unwrap().is_none());
    assert!(matches!(
        f.store.cancel(
            &guard,
            f.store.list(&guard, 201).unwrap().revision,
            &staged.id,
            201
        ),
        Err(Error::Invalid)
    ));
    let reopened = ScheduledStore::new(f.root.join("jobs"));
    let resumed = reopened
        .recover_claimed(&guard, &staged.id, &intent, ClaimRecovery::NoAttempt, 202)
        .unwrap()
        .unwrap();
    assert_eq!(resumed.intent(), intent);
    assert_eq!(resumed.digest(), claim.digest());
    reopened.submitted(&guard, &resumed, 203).unwrap();
    assert!(reopened.claim_next(&guard, 204).unwrap().is_none());
    assert!(matches!(
        reopened.read(&guard, &staged.id, 204),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        reopened.claim_next(&guard, 202),
        Err(Error::ClockRollback)
    ));
    let rows = reopened.list(&guard, 203 + TERMINAL_LIFETIME).unwrap();
    assert!(rows.jobs.is_empty());
}

#[test]
fn blocked_requires_explicit_reauthorization_and_unknown_never_dispatches() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    let staged = f.pending(&mut guard, 0, &request(), 200, 100);
    let claim = f.store.claim_next(&guard, 200).unwrap().unwrap();
    let intent = claim.intent().to_string();
    f.store
        .block_unsubmitted(&guard, &claim, BlockReason::KeyLocked, 201)
        .unwrap();
    assert!(f.store.claim_next(&guard, 202).unwrap().is_none());
    let rows = f.store.list(&guard, 202).unwrap();
    f.store
        .reauthorize(
            &guard,
            rows.revision,
            &staged.id,
            Reauthorization {
                due_at: 300,
                account_epoch: 2,
                private_session: session(203),
            },
            203,
        )
        .unwrap();
    let next = f.store.claim_next(&guard, 300).unwrap().unwrap();
    assert_eq!(next.intent(), intent);
    f.store.unknown(&guard, &next, 301).unwrap();
    let rows = f.store.list(&guard, 301).unwrap();
    assert_eq!(rows.jobs[0].state, State::Unknown);
    assert!(matches!(
        f.store.reauthorize(
            &guard,
            rows.revision,
            &staged.id,
            Reauthorization {
                due_at: 400,
                account_epoch: 2,
                private_session: session(302)
            },
            302
        ),
        Err(Error::Invalid)
    ));
    assert!(f.store.claim_next(&guard, 400).unwrap().is_none());
    let expired = f.store.list(&guard, 100 + PAYLOAD_LIFETIME).unwrap();
    assert_eq!(expired.jobs[0].state, State::Unknown);
    assert_eq!(
        f.store.payloads().settle_storage_usage(ACCOUNT).unwrap(),
        (0, 0)
    );
    assert!(matches!(
        f.store.recover_claimed(
            &guard,
            &staged.id,
            &intent,
            ClaimRecovery::NoAttempt,
            100 + PAYLOAD_LIFETIME
        ),
        Err(Error::Invalid)
    ));
    assert!(f
        .store
        .recover_claimed(
            &guard,
            &staged.id,
            &intent,
            ClaimRecovery::Submitted,
            101 + PAYLOAD_LIFETIME
        )
        .unwrap()
        .is_none());
    assert_eq!(
        f.store.list(&guard, 101 + PAYLOAD_LIFETIME).unwrap().jobs[0].state,
        State::Submitted
    );
}

#[test]
fn content_edit_stages_before_rebinding_and_claimed_jobs_are_immutable() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    let staged = f.pending(&mut guard, 0, &request(), 200, 100);
    let rows = f.store.list(&guard, 101).unwrap();
    let mut changed = request();
    changed.subject = "explicit change".into();
    let replacement = f
        .store
        .replace_staged(
            &guard,
            rows.revision,
            &staged.id,
            input(&changed, 250, 102),
            102,
        )
        .unwrap();
    assert_ne!(replacement.digest, staged.digest);
    assert!(matches!(
        f.store.publish_pending(
            &guard,
            replacement.revision,
            &staged.id,
            &replacement.digest,
            102
        ),
        Err(Error::Invalid)
    ));
    guard
        .replace_schedule_binding(&staged.id, &staged.digest, &replacement.digest)
        .unwrap();
    f.store
        .publish_pending(
            &guard,
            replacement.revision,
            &staged.id,
            &replacement.digest,
            102,
        )
        .unwrap();
    let claim = f.store.claim_next(&guard, 250).unwrap().unwrap();
    assert_eq!(claim.request().subject, "explicit change");
    let rows = f.store.list(&guard, 251).unwrap();
    assert_eq!(rows.jobs[0].subject, "explicit change");
    assert!(matches!(
        f.store.replace_staged(
            &guard,
            rows.revision,
            &staged.id,
            input(&request(), 400, 252),
            252
        ),
        Err(Error::Invalid)
    ));
}

#[test]
fn bounds_clock_expiry_and_sorted_account_discovery_are_durable() {
    let f = Fixture::new();
    let guard = f.guard(ACCOUNT, 100);
    for due in [100, 100 + HORIZON + 1] {
        assert!(matches!(
            f.store
                .create_staged(&guard, 0, input(&request(), due, 100), 100),
            Err(Error::Invalid)
        ));
    }
    let mut revision = 0;
    for _ in 0..MAX_JOBS {
        let staged = f
            .store
            .create_staged(&guard, revision, input(&request(), 200, 100), 100)
            .unwrap();
        revision = staged.revision;
    }
    assert!(matches!(
        f.store
            .create_staged(&guard, revision, input(&request(), 200, 100), 100),
        Err(Error::Capacity)
    ));
    let rows = f.store.list(&guard, 100 + PAYLOAD_LIFETIME).unwrap();
    assert!(rows.jobs.iter().all(|job| job.state == State::Failed));
    assert_eq!(
        f.store.payloads().settle_storage_usage(ACCOUNT).unwrap(),
        (0, 0)
    );
    assert!(matches!(
        f.store.list(&guard, 100),
        Err(Error::ClockRollback)
    ));
    let bob = f.guard("bob@example.test", 100 + PAYLOAD_LIFETIME);
    f.store.list(&bob, 100 + PAYLOAD_LIFETIME).unwrap();
    assert_eq!(
        f.store.discover_accounts().unwrap(),
        vec![ACCOUNT.to_string(), "bob@example.test".into()]
    );
    let index = f.root.join("jobs/index");
    let path = std::fs::read_dir(index)
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["account"] = "foreign@example.test".into();
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(f.store.discover_accounts(), Err(Error::Invalid)));
}

#[test]
fn persisted_horizon_and_identity_mutations_refuse_before_claim() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    f.pending(&mut guard, 0, &request(), 200, 100);
    let original = f.store.index.read(ACCOUNT).unwrap().unwrap();
    for field in ["horizon", "epoch", "duplicate", "owner"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match field {
            "horizon" => value["entries"][0]["due_at"] = (100 + HORIZON + 1).into(),
            "epoch" => {
                value["entries"][0]["private_session"]["account_epoch"] = serde_json::Value::Null
            }
            "duplicate" => {
                let entry = value["entries"][0].clone();
                value["entries"].as_array_mut().unwrap().push(entry);
            }
            _ => value["account"] = "bob@example.test".into(),
        }
        assert!(
            matches!(
                ScheduledStore::decode(ACCOUNT, Some(serde_json::to_vec(&value).unwrap())),
                Err(Error::Invalid)
            ),
            "{field}"
        );
    }
}

#[test]
fn overview_subject_uses_compose_bounds_and_refuses_malformed_persisted_copy() {
    let f = Fixture::new();
    let mut guard = f.guard(ACCOUNT, 100);
    let mut bad = request();
    bad.subject = "bad\r\nsubject".into();
    assert!(matches!(
        f.store.create_staged(&guard, 0, input(&bad, 200, 100), 100),
        Err(Error::Invalid)
    ));
    assert!(f.store.index.read(ACCOUNT).unwrap().is_none());
    f.pending(&mut guard, 0, &request(), 200, 100);
    let original = f.store.index.read(ACCOUNT).unwrap().unwrap();
    for subject in [
        "x".repeat(crate::send::DEFAULT_SUBJECT_MAX_LEN + 1),
        "injected\r\nBcc: other@example.test".into(),
        "nul\0subject".into(),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["entries"][0]["subject"] = subject.into();
        assert!(matches!(
            ScheduledStore::decode(ACCOUNT, Some(serde_json::to_vec(&value).unwrap())),
            Err(Error::Invalid)
        ));
    }
    for subject in [
        "".to_owned(),
        "x".repeat(crate::send::DEFAULT_SUBJECT_MAX_LEN),
        "UTF-8 café\tsubject".into(),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["entries"][0]["subject"] = subject.clone().into();
        let index =
            ScheduledStore::decode(ACCOUNT, Some(serde_json::to_vec(&value).unwrap())).unwrap();
        assert_eq!(view(&index.entries[0]).subject, subject);
    }
}

#[test]
fn valid_unindexed_snapshots_still_consume_the_account_byte_limit() {
    let f = Fixture::new();
    let guard = f.guard(ACCOUNT, 100);
    let heavy = |byte: u8| {
        let files = (0..2)
            .map(|number| {
                crate::send::UploadedAttachment::new(
                    ComposePolicy::default(),
                    format!("file{number}.bin"),
                    "application/octet-stream",
                    vec![byte + number as u8; 10 * 1024 * 1024],
                )
                .unwrap()
            })
            .collect();
        ComposeRequest::new_with_attachments(
            ComposePolicy::default(),
            "one@example.test",
            "Captured",
            "private",
            files,
        )
        .unwrap()
    };
    for byte in [1, 3] {
        f.store
            .capture(
                ACCOUNT,
                &crate::draft::generate_draft_id().unwrap(),
                &heavy(byte),
                100,
            )
            .unwrap();
    }
    let (count, bytes) = f.store.payloads().settle_storage_usage(ACCOUNT).unwrap();
    assert_eq!(count, 2);
    assert!(bytes > 20 * 1024 * 1024);
    assert!(matches!(
        f.store
            .create_staged(&guard, 0, input(&heavy(5), 200, 100), 100),
        Err(Error::Capacity)
    ));
    assert_eq!(
        f.store.payloads().settle_storage_usage(ACCOUNT).unwrap(),
        (count, bytes)
    );
    assert!(f.store.claim_next(&guard, 200).unwrap().is_none());
}
