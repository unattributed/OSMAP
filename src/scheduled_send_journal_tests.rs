use super::*;

const ACCOUNT: &str = "alice@example.test";
const OTHER: &str = "other@example.test";
const ID: &str = "0123456789abcdef0123456789abcdef";
const OTHER_ID: &str = "fedcba9876543210fedcba9876543210";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        Self(std::env::temp_dir().join(format!("osmap-schedule-journal-{}", hex(&nonce))))
    }
    fn journal(&self) -> SendJournal {
        SendJournal::new(self.0.clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() && self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
fn intent(issued: u64, nonce: u128) -> String {
    format!("{issued}.{nonce:032x}")
}
fn scheduled(confirmed: bool) -> AttemptOutcome {
    AttemptOutcome::Scheduled {
        job_id: parse_draft_id(ID).unwrap(),
        schedule_confirmed: confirmed,
    }
}
fn assert_no_dispatch(journal: &SendJournal, source: &str, now: u64, confirmed: bool) {
    assert_eq!(
        journal.execute_prepared::<()>(
            ACCOUNT,
            source,
            now,
            |_| panic!("a retired schedule must not prepare content"),
            |_| panic!("a retired schedule must not invoke SMTP"),
        ),
        Ok(PreparedResult::Outcome(JournalResult {
            outcome: scheduled(confirmed),
            replayed: true,
            receipt_persisted: true,
        }))
    );
}

#[test]
fn schedule_reservation_and_publication_survive_reopen_without_smtp() {
    let fixture = Fixture::new();
    let source = intent(100, 1);
    {
        let mut guard = fixture.journal().account_guard(ACCOUNT, 100).unwrap();
        assert_eq!(guard.account(), ACCOUNT);
        guard.begin_schedule(&source, ID, DIGEST).unwrap();
        assert_eq!(
            guard.require_schedule_binding(ID, DIGEST),
            Ok(source.as_str())
        );
        assert_eq!(
            guard.require_unconsumed(&source),
            Err(JournalError::Consumed)
        );
        assert_eq!(
            guard.begin_draft_save(&source, OTHER_ID),
            Err(JournalError::Consumed)
        );
    }
    assert_eq!(
        fixture.journal().receipt(ACCOUNT, &source, 101).unwrap(),
        Some(scheduled(false))
    );
    assert_no_dispatch(&fixture.journal(), &source, 101, false);
    {
        let mut guard = fixture.journal().account_guard(ACCOUNT, 102).unwrap();
        guard.finish_schedule(&source, ID, DIGEST).unwrap();
        guard.finish_schedule(&source, ID, DIGEST).unwrap();
    }
    assert_eq!(
        fixture.journal().receipt(ACCOUNT, &source, 103).unwrap(),
        Some(scheduled(true))
    );
    assert_no_dispatch(&fixture.journal(), &source, 103, true);
    // Historical metadata remains available; expiry cannot renew send authority.
    let after_intent_expiry = 100 + INTENT_LIFETIME;
    let guard = fixture
        .journal()
        .account_guard(ACCOUNT, after_intent_expiry)
        .unwrap();
    assert_eq!(
        guard.require_schedule_binding(ID, DIGEST),
        Ok(source.as_str())
    );
    assert_eq!(
        guard.require_unconsumed(&source),
        Err(JournalError::ExpiredIntent)
    );
}

#[test]
fn schedule_binding_refuses_foreign_missing_malformed_and_changed_inputs() {
    let fixture = Fixture::new();
    let source = intent(100, 1);
    {
        let mut guard = fixture.journal().account_guard(ACCOUNT, 100).unwrap();
        for bad in ["", "0123", "0123456789ABCDEF0123456789ABCDEF"] {
            assert!(guard.begin_schedule(&source, bad, DIGEST).is_err());
        }
        for bad in [
            "",
            "Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "00",
        ] {
            assert_eq!(
                guard.begin_schedule(&source, ID, bad),
                Err(JournalError::ChangedSnapshot)
            );
        }
        guard.begin_schedule(&source, ID, DIGEST).unwrap();
        assert_eq!(
            guard.require_schedule_binding(OTHER_ID, DIGEST),
            Err(JournalError::InvalidRecord)
        );
        assert_eq!(
            guard.require_schedule_binding(ID, NEXT_DIGEST),
            Err(JournalError::ChangedSnapshot)
        );
        assert_eq!(
            guard.finish_schedule(&source, OTHER_ID, DIGEST),
            Err(JournalError::ChangedSnapshot)
        );
        assert_eq!(
            guard.finish_schedule(&source, ID, NEXT_DIGEST),
            Err(JournalError::ChangedSnapshot)
        );
        assert_eq!(
            guard.begin_schedule(&intent(100, 2), ID, DIGEST),
            Err(JournalError::Consumed)
        );
    }
    let guard = fixture.journal().account_guard(OTHER, 100).unwrap();
    assert_eq!(guard.account(), OTHER);
    assert_eq!(
        guard.require_schedule_binding(ID, DIGEST),
        Err(JournalError::InvalidRecord)
    );
    assert_eq!(
        fixture.journal().receipt(OTHER, &source, 100).unwrap(),
        None
    );
}

#[test]
fn explicit_edit_rebinds_only_exact_old_snapshot_and_preserves_source_retirement() {
    let fixture = Fixture::new();
    let source = intent(100, 1);
    {
        let mut guard = fixture.journal().account_guard(ACCOUNT, 100).unwrap();
        guard.begin_schedule(&source, ID, DIGEST).unwrap();
        guard.finish_schedule(&source, ID, DIGEST).unwrap();
    }
    {
        let mut guard = fixture.journal().account_guard(ACCOUNT, 101).unwrap();
        assert_eq!(
            guard.replace_schedule_binding(OTHER_ID, DIGEST, NEXT_DIGEST),
            Err(JournalError::InvalidRecord)
        );
        assert_eq!(
            guard.replace_schedule_binding(ID, NEXT_DIGEST, DIGEST),
            Err(JournalError::ChangedSnapshot)
        );
        guard
            .replace_schedule_binding(ID, DIGEST, NEXT_DIGEST)
            .unwrap();
        assert_eq!(
            guard.require_schedule_binding(ID, DIGEST),
            Err(JournalError::ChangedSnapshot)
        );
        assert_eq!(
            guard.require_schedule_binding(ID, NEXT_DIGEST),
            Ok(source.as_str())
        );
        assert_eq!(
            guard.replace_schedule_binding(ID, DIGEST, NEXT_DIGEST),
            Err(JournalError::ChangedSnapshot)
        );
    }
    assert_no_dispatch(&fixture.journal(), &source, 102, false);
    {
        let mut guard = fixture.journal().account_guard(ACCOUNT, 103).unwrap();
        guard.finish_schedule(&source, ID, NEXT_DIGEST).unwrap();
    }
    assert_no_dispatch(&fixture.journal(), &source, 104, true);
}

#[test]
fn uncertain_schedule_writes_preserve_durable_retirement_without_callbacks() {
    for after_publication in [false, true] {
        let fixture = Fixture::new();
        let source = intent(100, 1);
        let mut faulty = fixture.journal();
        faulty.fault = Some((true, after_publication));
        {
            let mut guard = faulty.account_guard(ACCOUNT, 100).unwrap();
            guard.begin_schedule(&source, ID, DIGEST).unwrap();
            assert_eq!(
                guard.finish_schedule(&source, ID, DIGEST),
                Err(JournalError::StoreUnavailable)
            );
        }
        assert_eq!(
            fixture.journal().receipt(ACCOUNT, &source, 101).unwrap(),
            Some(scheduled(after_publication))
        );
        assert_no_dispatch(&fixture.journal(), &source, 101, after_publication);
    }
    // A failed initial reservation must not be treated as permission to publish
    // a staged job. After-publication uncertainty is still a consumed intent.
    for after_publication in [false, true] {
        let fixture = Fixture::new();
        let source = intent(100, 1);
        let mut faulty = fixture.journal();
        faulty.fault = Some((false, after_publication));
        {
            let mut guard = faulty.account_guard(ACCOUNT, 100).unwrap();
            assert_eq!(
                guard.begin_schedule(&source, ID, DIGEST),
                Err(JournalError::StoreUnavailable)
            );
        }
        let guard = fixture.journal().account_guard(ACCOUNT, 101).unwrap();
        assert_eq!(
            guard.require_schedule_binding(ID, DIGEST).is_ok(),
            after_publication
        );
        drop(guard);
        if after_publication {
            assert_no_dispatch(&fixture.journal(), &source, 101, false);
        }
    }
}

#[test]
fn interrupted_edit_rebind_reopens_exactly_one_binding_without_rearming_source() {
    for after_publication in [false, true] {
        let fixture = Fixture::new();
        let source = intent(100, 1);
        {
            let mut guard = fixture.journal().account_guard(ACCOUNT, 100).unwrap();
            guard.begin_schedule(&source, ID, DIGEST).unwrap();
            guard.finish_schedule(&source, ID, DIGEST).unwrap();
        }
        let mut faulty = fixture.journal();
        faulty.fault = Some((false, after_publication));
        {
            let mut guard = faulty.account_guard(ACCOUNT, 101).unwrap();
            assert_eq!(
                guard.replace_schedule_binding(ID, DIGEST, NEXT_DIGEST),
                Err(JournalError::StoreUnavailable)
            );
            // An ambiguous write ends this operation: drop and reopen rather
            // than authorizing from the guard's tentative in-memory state.
        }
        let guard = fixture.journal().account_guard(ACCOUNT, 102).unwrap();
        let (live, refused) = if after_publication {
            (NEXT_DIGEST, DIGEST)
        } else {
            (DIGEST, NEXT_DIGEST)
        };
        assert_eq!(
            guard.require_schedule_binding(ID, live),
            Ok(source.as_str())
        );
        assert_eq!(
            guard.require_schedule_binding(ID, refused),
            Err(JournalError::ChangedSnapshot)
        );
        drop(guard);
        assert_no_dispatch(&fixture.journal(), &source, 102, !after_publication);
    }
}

fn entry(issued: u64, nonce: u128, digest: &str, state: State) -> Entry {
    Entry {
        intent: intent(issued, nonce),
        snapshot: digest.into(),
        state,
        sent_copy_requested: None,
        sent_location: None,
    }
}

#[test]
fn pruning_preserves_ninety_day_bindings_and_unresolved_same_snapshot() {
    let issued = 100;
    let job_id = parse_draft_id(ID).unwrap();
    let mut record = Record {
        version: 1,
        high_water: issued,
        attempts: vec![
            entry(issued, 1, DIGEST, State::Scheduled { job_id }),
            entry(
                issued,
                2,
                NEXT_DIGEST,
                State::ScheduleReserved {
                    job_id: parse_draft_id(OTHER_ID).unwrap(),
                },
            ),
            entry(issued, 3, NEXT_DIGEST, State::AcceptedStored),
        ],
    };
    prune_accepted(&mut record, issued + SCHEDULE_BINDING_LIFETIME - 1).unwrap();
    assert_eq!(record.attempts.len(), 2);
    prune_accepted(&mut record, issued + SCHEDULE_BINDING_LIFETIME).unwrap();
    assert_eq!(record.attempts.len(), 1);
    assert!(matches!(
        record.attempts[0].state,
        State::ScheduleReserved { .. }
    ));
    for unresolved in [State::Reserved, State::Unconfirmed] {
        let mut record = Record {
            version: 1,
            high_water: issued,
            attempts: vec![
                entry(issued, 1, DIGEST, State::Scheduled { job_id }),
                entry(issued + 1, 2, DIGEST, unresolved),
            ],
        };
        prune_accepted(&mut record, issued + 10 * SCHEDULE_BINDING_LIFETIME).unwrap();
        assert_eq!(record.attempts.len(), 2);
        assert!(matches!(record.attempts[0].state, State::Scheduled { .. }));
    }
}

#[test]
fn strict_journal_decode_refuses_duplicate_job_or_conflicting_send_facts() {
    let job_id = parse_draft_id(ID).unwrap();
    let mut record = Record {
        version: 1,
        high_water: 100,
        attempts: vec![
            entry(100, 1, DIGEST, State::Scheduled { job_id }),
            entry(100, 2, NEXT_DIGEST, State::ScheduleReserved { job_id }),
        ],
    };
    assert!(matches!(
        Record::read(Some(serde_json::to_vec(&record).unwrap())),
        Err(JournalError::InvalidRecord)
    ));
    record.attempts.pop();
    record.attempts[0].sent_copy_requested = Some(false);
    assert!(matches!(
        Record::read(Some(serde_json::to_vec(&record).unwrap())),
        Err(JournalError::InvalidRecord)
    ));
    record.attempts[0].sent_copy_requested = None;
    assert!(Record::read(Some(serde_json::to_vec(&record).unwrap())).is_ok());
    let mut json = serde_json::to_value(&record).unwrap();
    json["attempts"][0]["state"]["scheduled"]["retry"] = serde_json::json!(true);
    assert!(matches!(
        Record::read(Some(serde_json::to_vec(&json).unwrap())),
        Err(JournalError::InvalidRecord)
    ));
}

#[test]
fn schedule_retirement_obeys_existing_journal_capacity_and_clock_guard() {
    let fixture = Fixture::new();
    let journal = fixture.journal();
    let record = Record {
        version: 1,
        high_water: 100,
        attempts: (1..=MAX_ATTEMPTS)
            .map(|nonce| entry(100, nonce as u128, DIGEST, State::Unconfirmed))
            .collect(),
    };
    journal
        .file
        .lock(ACCOUNT)
        .unwrap()
        .write(&serde_json::to_vec(&record).unwrap())
        .unwrap();
    {
        let mut guard = journal.account_guard(ACCOUNT, 101).unwrap();
        assert_eq!(
            guard.begin_schedule(&intent(101, 1), ID, DIGEST),
            Err(JournalError::Capacity)
        );
        assert_eq!(
            guard.require_schedule_binding(ID, DIGEST),
            Err(JournalError::InvalidRecord)
        );
    }
    assert!(matches!(
        journal.account_guard(ACCOUNT, 99),
        Err(JournalError::ClockRollback)
    ));
    let restored = Record::read(journal.file.read(ACCOUNT).unwrap()).unwrap();
    assert_eq!(restored.attempts.len(), MAX_ATTEMPTS);
    assert_eq!(restored.high_water, 100);
}
