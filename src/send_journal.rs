//! Durable suppression for one authenticated account's explicit send intent.
//! Reserved/unknown attempts are never retried or automatically discarded.
//! This stores metadata only, not a recoverable message or delivery guarantee.
use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use crate::send::ComposeRequest;

pub(crate) const INTENT_LIFETIME: u64 = 30 * 24 * 60 * 60;
const MAX_ATTEMPTS: usize = 4096;
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalError {
    InvalidAccount,
    InvalidIntent,
    ExpiredIntent,
    ClockRollback,
    InvalidRecord,
    Capacity,
    ChangedSnapshot,
    Consumed,
    ConfirmationRequired,
    StoreUnavailable,
    RandomUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptOutcome {
    RecoveryRefused {
        capacity: bool,
    },
    Accepted {
        sent_copy_stored: bool,
    },
    Unconfirmed,
    /// The intent was retired into a draft, never submitted under this intent.
    DraftSaved {
        draft_id: [u8; 16],
        save_confirmed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalResult {
    pub outcome: AttemptOutcome,
    pub replayed: bool,
    pub receipt_persisted: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreparedResult<E> {
    /// Validation/throttling refused while the intent was unconsumed and locked.
    NotDispatched(E),
    Outcome(JournalResult),
}

/// Generated on the server and carried unchanged by the native compose form.
/// The intent is not an authentication credential or permission to send.
pub(crate) fn mint_intent(now: u64) -> Result<String, JournalError> {
    if now == 0 {
        return Err(JournalError::InvalidIntent);
    }
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| JournalError::RandomUnavailable)?;
    Ok(format!("{now}.{}", hex(&nonce)))
}

pub(crate) fn intent_for_draft(
    account: &str,
    id: &str,
    revision: u64,
    updated_at: u64,
) -> Result<String, JournalError> {
    crate::identity::MailboxIdentity::parse(account).map_err(|_| JournalError::InvalidAccount)?;
    crate::draft::validate_draft_id(id).map_err(|_| JournalError::InvalidIntent)?;
    if updated_at == 0 {
        return Err(JournalError::InvalidIntent);
    }
    let mut hash = Sha256::new();
    hash.update(b"osmap-draft-send-intent-v1\0");
    for value in [account, id] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(revision.to_be_bytes());
    Ok(format!("{updated_at}.{}", hex(&hash.finalize()[..16])))
}

pub(crate) struct AccountGuard {
    lock: LockedAccountFile,
    record: Record,
    account: String,
    now: u64,
    journal: SendJournal,
}

impl AccountGuard {
    fn validate_intent(&self, intent: &str) -> Result<(), JournalError> {
        let issued = intent_time(intent)?;
        if issued > self.now {
            return Err(JournalError::InvalidIntent);
        }
        if self.now - issued >= INTENT_LIFETIME {
            return Err(JournalError::ExpiredIntent);
        }
        Ok(())
    }
    pub(crate) fn require_unconsumed(&self, intent: &str) -> Result<(), JournalError> {
        self.validate_intent(intent)?;
        if self
            .record
            .attempts
            .iter()
            .any(|entry| entry.intent == intent)
        {
            return Err(JournalError::Consumed);
        }
        Ok(())
    }
    /// Inspect the current summary revision while holding the account coordination lock.
    pub(crate) fn draft_attempt(
        &self,
        summary: &crate::draft::DraftSummary,
    ) -> Result<(String, Option<AttemptOutcome>), JournalError> {
        let intent = intent_for_draft(
            &self.account,
            &summary.draft_id,
            summary.revision,
            summary.updated_at,
        )?;
        self.validate_intent(&intent)?;
        Ok((
            intent.clone(),
            self.record
                .attempts
                .iter()
                .find(|entry| entry.intent == intent)
                .map(|entry| entry.state.outcome()),
        ))
    }

    /// Retire an unsaved intent before publishing the first draft revision.
    pub(crate) fn begin_draft_save(&mut self, intent: &str, id: &str) -> Result<(), JournalError> {
        self.require_unconsumed(intent)?;
        let draft_id = parse_draft_id(id)?;
        prune_accepted(&mut self.record, self.now)?;
        if self.record.attempts.len() >= MAX_ATTEMPTS {
            return Err(JournalError::Capacity);
        }
        self.record.high_water = self.now;
        self.record.attempts.push(Entry {
            intent: intent.into(),
            snapshot: "0".repeat(64),
            state: State::SaveReserved { draft_id },
        });
        self.journal.write(&self.lock, &self.record, false)
    }
    pub(crate) fn finish_draft_save(&mut self, intent: &str, id: &str) -> Result<(), JournalError> {
        let draft_id = parse_draft_id(id)?;
        let entry = self
            .record
            .attempts
            .iter_mut()
            .find(|entry| entry.intent == intent)
            .ok_or(JournalError::InvalidRecord)?;
        if !matches!(entry.state, State::SaveReserved { draft_id: bound } if bound == draft_id) {
            return Err(JournalError::InvalidRecord);
        }
        entry.state = State::DraftSaved { draft_id };
        self.journal.write(&self.lock, &self.record, true)
    }
    pub(crate) fn draft_intent(
        &self,
        draft: &crate::draft::DraftRecord,
    ) -> Result<String, JournalError> {
        if draft.canonical_username != self.account {
            return Err(JournalError::InvalidAccount);
        }
        intent_for_draft(
            &self.account,
            &draft.draft_id,
            draft.revision.ok_or(JournalError::InvalidIntent)?,
            draft.updated_at,
        )
    }
    pub(crate) fn require_accepted_with_sent(&self, intent: &str) -> Result<(), JournalError> {
        self.validate_intent(intent)?;
        if self
            .record
            .attempts
            .iter()
            .any(|entry| entry.intent == intent && matches!(entry.state, State::AcceptedStored))
        {
            Ok(())
        } else {
            Err(JournalError::ConfirmationRequired)
        }
    }
}

fn parse_draft_id(id: &str) -> Result<[u8; 16], JournalError> {
    crate::draft::validate_draft_id(id).map_err(|_| JournalError::InvalidIntent)?;
    let mut bytes = [0_u8; 16];
    for (slot, pair) in bytes.iter_mut().zip(id.as_bytes().chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| JournalError::InvalidIntent)?;
        *slot = u8::from_str_radix(text, 16).map_err(|_| JournalError::InvalidIntent)?;
    }
    Ok(bytes)
}
pub(crate) fn draft_id_text(id: &[u8; 16]) -> String {
    hex(id)
}

/// Syntax-only validation for a read-only receipt destination. Account authority
/// and recorded outcome are still checked by the authenticated receipt route.
pub(crate) fn receipt_intent_valid(value: &str) -> bool {
    intent_time(value).is_ok()
}

pub(crate) fn intent_time(value: &str) -> Result<u64, JournalError> {
    let (issued, nonce) = value.split_once('.').ok_or(JournalError::InvalidIntent)?;
    if issued.is_empty()
        || issued.len() > 20
        || issued.starts_with('0')
        || !issued.bytes().all(|b| b.is_ascii_digit())
        || !lower_hex(nonce, 32)
    {
        return Err(JournalError::InvalidIntent);
    }
    issued.parse().map_err(|_| JournalError::InvalidIntent)
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Length-prefix every field and list, including Bcc and attachment bytes.
/// Call only after validation; the callback must use this exact snapshot.
pub(crate) fn snapshot_digest(account: &str, request: &ComposeRequest) -> String {
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    hash.update(b"osmap-send-snapshot-v1\0");
    field(&mut hash, account.as_bytes());
    for recipients in [
        &request.recipients,
        &request.cc_recipients,
        &request.bcc_recipients,
    ] {
        hash.update((recipients.len() as u64).to_be_bytes());
        for recipient in recipients {
            field(&mut hash, recipient.as_bytes());
        }
    }
    for value in [&request.subject, &request.body] {
        field(&mut hash, value.as_bytes());
    }
    field(&mut hash, request.body_format.as_str().as_bytes());
    match &request.reply_thread {
        Some(thread) => {
            hash.update([1]);
            // Include the validated stored metadata, not just rendered headers.
            field(
                &mut hash,
                thread.in_reply_to().unwrap_or_default().as_bytes(),
            );
            field(&mut hash, thread.references().as_bytes());
            hash.update([u8::from(thread.shortened())]);
        }
        None => hash.update([0]),
    }
    hash.update((request.attachments.len() as u64).to_be_bytes());
    for attachment in &request.attachments {
        field(&mut hash, attachment.filename.as_bytes());
        field(&mut hash, attachment.content_type.as_bytes());
        field(&mut hash, &attachment.body);
    }
    hex(&hash.finalize())
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum State {
    RecoveryRefused { capacity: bool },
    Reserved,
    AcceptedStored,
    AcceptedUnconfirmed,
    Unconfirmed,
    SaveReserved { draft_id: [u8; 16] },
    DraftSaved { draft_id: [u8; 16] },
}

impl State {
    fn outcome(self) -> AttemptOutcome {
        match self {
            Self::RecoveryRefused { capacity } => AttemptOutcome::RecoveryRefused { capacity },
            Self::AcceptedStored => AttemptOutcome::Accepted {
                sent_copy_stored: true,
            },
            Self::AcceptedUnconfirmed => AttemptOutcome::Accepted {
                sent_copy_stored: false,
            },
            Self::Reserved | Self::Unconfirmed => AttemptOutcome::Unconfirmed,
            Self::SaveReserved { draft_id } => AttemptOutcome::DraftSaved {
                draft_id,
                save_confirmed: false,
            },
            Self::DraftSaved { draft_id } => AttemptOutcome::DraftSaved {
                draft_id,
                save_confirmed: true,
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    intent: String,
    snapshot: String,
    state: State,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    high_water: u64,
    attempts: Vec<Entry>,
}

impl Record {
    fn read(bytes: Option<Vec<u8>>) -> Result<Self, JournalError> {
        let Some(bytes) = bytes else {
            return Ok(Self {
                version: 1,
                high_water: 0,
                attempts: vec![],
            });
        };
        if bytes.len() > MAX_BYTES {
            return Err(JournalError::InvalidRecord);
        }
        let record: Self =
            serde_json::from_slice(&bytes).map_err(|_| JournalError::InvalidRecord)?;
        if record.version != 1 || record.high_water == 0 || record.attempts.len() > MAX_ATTEMPTS {
            return Err(JournalError::InvalidRecord);
        }
        let mut seen = HashSet::new();
        for entry in &record.attempts {
            let issued = intent_time(&entry.intent).map_err(|_| JournalError::InvalidRecord)?;
            if issued > record.high_water
                || !lower_hex(&entry.snapshot, 64)
                || !seen.insert(&entry.intent)
            {
                return Err(JournalError::InvalidRecord);
            }
        }
        Ok(record)
    }
}

fn prune_accepted(record: &mut Record, now: u64) -> Result<(), JournalError> {
    let mut retained = Vec::with_capacity(record.attempts.len());
    for entry in record.attempts.drain(..) {
        let issued = intent_time(&entry.intent).map_err(|_| JournalError::InvalidRecord)?;
        let age = now.checked_sub(issued).ok_or(JournalError::InvalidRecord)?;
        if matches!(
            entry.state,
            State::Reserved | State::Unconfirmed | State::SaveReserved { .. }
        ) || age < INTENT_LIFETIME
        {
            retained.push(entry);
        }
    }
    record.attempts = retained;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct SendJournal {
    file: PrivateAccountFile,
    #[cfg(test)]
    fault: Option<(bool, bool)>, // terminal write, after publication
}

impl SendJournal {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            file: PrivateAccountFile::new(directory, "osmap-send-journal-v1", MAX_BYTES),
            #[cfg(test)]
            fault: None,
        }
    }

    fn write(
        &self,
        lock: &LockedAccountFile,
        record: &Record,
        terminal: bool,
    ) -> Result<(), JournalError> {
        #[cfg(not(test))]
        let _ = terminal;
        #[cfg(test)]
        if self.fault == Some((terminal, false)) {
            return Err(JournalError::StoreUnavailable);
        }
        let bytes = serde_json::to_vec(record).map_err(|_| JournalError::InvalidRecord)?;
        lock.write(&bytes)
            .map_err(|_| JournalError::StoreUnavailable)?;
        #[cfg(test)]
        if self.fault == Some((terminal, true)) {
            return Err(JournalError::StoreUnavailable);
        }
        Ok(())
    }

    /// Hold this guard across draft load, revision check and CAS mutation.
    /// All callers acquire journal before draft locks, never the reverse.
    pub(crate) fn account_guard(
        &self,
        account: &str,
        now: u64,
    ) -> Result<AccountGuard, JournalError> {
        crate::identity::MailboxIdentity::parse(account)
            .map_err(|_| JournalError::InvalidAccount)?;
        if now == 0 {
            return Err(JournalError::InvalidIntent);
        }
        let lock = self
            .file
            .lock(account)
            .map_err(|_| JournalError::StoreUnavailable)?;
        let record = Record::read(lock.read().map_err(|_| JournalError::StoreUnavailable)?)?;
        if now < record.high_water {
            return Err(JournalError::ClockRollback);
        }
        Ok(AccountGuard {
            lock,
            record,
            account: account.into(),
            now,
            journal: self.clone(),
        })
    }

    fn read_for(
        &self,
        account: &str,
        intent: &str,
        now: u64,
    ) -> Result<(LockedAccountFile, Record), JournalError> {
        // Refuse malformed/future/expired intents before creating state paths.
        let issued = intent_time(intent)?;
        if issued > now {
            return Err(JournalError::InvalidIntent);
        }
        if now - issued >= INTENT_LIFETIME {
            return Err(JournalError::ExpiredIntent);
        }
        let guard = self.account_guard(account, now)?;
        Ok((guard.lock, guard.record))
    }

    /// Account-owned receipt; query text alone never proves a send outcome.
    pub(crate) fn receipt(
        &self,
        account: &str,
        intent: &str,
        _now: u64,
    ) -> Result<Option<AttemptOutcome>, JournalError> {
        // Receipts never grant mutation permission. Historical unknown records
        // stay readable after expiry and clock changes. Atomic replacement plus
        // bounded descriptor reads yield one complete owned metadata record.
        crate::identity::MailboxIdentity::parse(account)
            .map_err(|_| JournalError::InvalidAccount)?;
        intent_time(intent)?;
        let record = Record::read(
            self.file
                .read(account)
                .map_err(|_| JournalError::StoreUnavailable)?,
        )?;
        Ok(record
            .attempts
            .iter()
            .find(|entry| entry.intent == intent)
            .map(|entry| entry.state.outcome()))
    }

    /// Read-only presence check for route guards, not dispatch permission.
    #[cfg(test)]
    pub(crate) fn consumed(
        &self,
        account: &str,
        intent: &str,
        now: u64,
    ) -> Result<bool, JournalError> {
        Ok(self.receipt(account, intent, now)?.is_some())
    }

    #[cfg(test)]
    fn replay(
        &self,
        account: &str,
        intent: &str,
        now: u64,
        request: &ComposeRequest,
    ) -> Result<Option<JournalResult>, JournalError> {
        let (_lock, record) = self.read_for(account, intent, now)?;
        let snapshot = snapshot_digest(account, request);
        match record.attempts.iter().find(|entry| entry.intent == intent) {
            Some(entry) if entry.snapshot != snapshot => Err(JournalError::ChangedSnapshot),
            Some(entry) => Ok(Some(JournalResult {
                outcome: entry.state.outcome(),
                replayed: true,
                receipt_persisted: true,
            })),
            None => Ok(None),
        }
    }

    #[cfg(test)]
    fn execute(
        &self,
        account: &str,
        intent: &str,
        now: u64,
        request: &ComposeRequest,
        dispatch: impl FnOnce() -> AttemptOutcome,
    ) -> Result<JournalResult, JournalError> {
        match self.execute_prepared(
            account,
            intent,
            now,
            |_| Ok::<_, std::convert::Infallible>(request.clone()),
            |_| dispatch(),
        )? {
            PreparedResult::Outcome(result) => Ok(result),
            PreparedResult::NotDispatched(never) => match never {},
        }
    }

    /// Consumed-state lookup, validation and throttle decisions share the same
    /// lock as reservation. Only an unconsumed intent may return NotDispatched.
    /// All journal errors pause sending; never substitute a fresh intent.
    pub(crate) fn execute_prepared<E>(
        &self,
        account: &str,
        intent: &str,
        now: u64,
        prepare: impl FnOnce(bool) -> Result<ComposeRequest, E>,
        dispatch: impl FnOnce(&ComposeRequest) -> AttemptOutcome,
    ) -> Result<PreparedResult<E>, JournalError> {
        let (lock, mut record) = self.read_for(account, intent, now)?;
        let existing = record.attempts.iter().find(|entry| entry.intent == intent);
        if let Some(entry) = existing {
            if matches!(
                entry.state,
                State::SaveReserved { .. } | State::DraftSaved { .. }
            ) {
                return Ok(PreparedResult::Outcome(JournalResult {
                    outcome: entry.state.outcome(),
                    replayed: true,
                    receipt_persisted: true,
                }));
            }
        }
        let request = match prepare(existing.is_some()) {
            Ok(request) => request,
            Err(_) if existing.is_some() => return Err(JournalError::ChangedSnapshot),
            Err(reason) => return Ok(PreparedResult::NotDispatched(reason)),
        };
        let snapshot = snapshot_digest(account, &request);
        if let Some(entry) = existing {
            if entry.snapshot != snapshot {
                return Err(JournalError::ChangedSnapshot);
            }
            return Ok(PreparedResult::Outcome(JournalResult {
                outcome: entry.state.outcome(),
                replayed: true,
                receipt_persisted: true,
            }));
        }
        // Unknown/reserved entries stay forever, even after intent expiry.
        // Atomic high-water persistence prevents pruned accepted intents from
        // becoming valid again when the wall clock moves backwards.
        prune_accepted(&mut record, now)?;
        if record.attempts.len() >= MAX_ATTEMPTS {
            return Err(JournalError::Capacity);
        }
        record.high_water = now;
        record.attempts.push(Entry {
            intent: intent.into(),
            snapshot,
            state: State::Reserved,
        });
        self.write(&lock, &record, false)?;
        let outcome = dispatch(&request);
        record
            .attempts
            .last_mut()
            .ok_or(JournalError::InvalidRecord)?
            .state = match outcome {
            AttemptOutcome::Accepted {
                sent_copy_stored: true,
            } => State::AcceptedStored,
            AttemptOutcome::Accepted {
                sent_copy_stored: false,
            } => State::AcceptedUnconfirmed,
            AttemptOutcome::Unconfirmed => State::Unconfirmed,
            AttemptOutcome::RecoveryRefused { capacity } => State::RecoveryRefused { capacity },
            AttemptOutcome::DraftSaved { .. } => return Err(JournalError::InvalidRecord),
        };
        let receipt_persisted = self.write(&lock, &record, true).is_ok();
        Ok(PreparedResult::Outcome(JournalResult {
            outcome,
            replayed: false,
            receipt_persisted,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-send-journal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn store(&self) -> SendJournal {
            SendJournal::new(self.0.clone())
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn request() -> ComposeRequest {
        ComposeRequest::new(
            crate::send::ComposePolicy::default(),
            "bob@example.test",
            "Synthetic subject",
            "Synthetic body",
        )
        .unwrap()
    }
    fn intent(now: u64, n: u128) -> String {
        format!("{now}.{n:032x}")
    }
    const ACCOUNT: &str = "alice@example.test";
    const ACCEPTED: AttemptOutcome = AttemptOutcome::Accepted {
        sent_copy_stored: true,
    };
    fn fixture(store: &SendJournal, bytes: &[u8]) {
        store.file.lock(ACCOUNT).unwrap().write(bytes).unwrap();
    }
    fn record_bytes(store: &SendJournal) -> Vec<u8> {
        store.file.read(ACCOUNT).unwrap().unwrap()
    }

    #[test]
    fn reopened_store_replays_each_outcome_without_another_callback() {
        for outcome in [
            AttemptOutcome::RecoveryRefused { capacity: false },
            AttemptOutcome::RecoveryRefused { capacity: true },
            ACCEPTED,
            AttemptOutcome::Accepted {
                sent_copy_stored: false,
            },
            AttemptOutcome::Unconfirmed,
        ] {
            let root = Scratch::new();
            let calls = AtomicUsize::new(0);
            let token = intent(100, 1);
            let result = root
                .store()
                .execute(ACCOUNT, &token, 100, &request(), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    outcome
                })
                .unwrap();
            assert!(!result.replayed);
            assert_eq!(result.outcome, outcome);
            let replay = root
                .store()
                .execute(ACCOUNT, &token, 101, &request(), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ACCEPTED
                })
                .unwrap();
            assert!(replay.replayed);
            assert_eq!(replay.outcome, outcome);
            assert_eq!(
                root.store()
                    .replay(ACCOUNT, &token, 101, &request())
                    .unwrap(),
                Some(replay)
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                root.store().receipt(ACCOUNT, &token, 101).unwrap(),
                Some(outcome)
            );
            assert_eq!(
                root.store()
                    .receipt("foreign@example.test", &token, 101)
                    .unwrap(),
                None
            );
            assert_eq!(
                root.store()
                    .receipt(ACCOUNT, &intent(100, 99), 101)
                    .unwrap(),
                None
            );
            let bytes = record_bytes(&root.store());
            let text = String::from_utf8(bytes).unwrap();
            for private in [
                ACCOUNT,
                "bob@example.test",
                "Synthetic subject",
                "Synthetic body",
            ] {
                assert!(!text.contains(private));
            }
        }
    }

    #[test]
    fn changed_snapshot_is_refused_across_all_dispatch_fields() {
        let root = Scratch::new();
        let original = request();
        let token = intent(100, 1);
        root.store()
            .execute(ACCOUNT, &token, 100, &original, || ACCEPTED)
            .unwrap();
        let mut changed = Vec::new();
        let mut value = original.clone();
        value.recipients.push("other@example.test".into());
        changed.push(value);
        let mut value = original.clone();
        value.cc_recipients.push("other@example.test".into());
        changed.push(value);
        let mut value = original.clone();
        value.bcc_recipients.push("other@example.test".into());
        changed.push(value);
        let mut value = original.clone();
        value.subject.push('!');
        changed.push(value);
        let mut value = original.clone();
        value.body.push('\n');
        changed.push(value);
        let mut value = original.clone();
        value.body_format = crate::compose_format::BodyFormat::Formatted;
        changed.push(value);
        let mut value = original.clone();
        value.reply_thread = Some(
            crate::reply_thread::ReplyThread::from_original(
                "Message-ID: <parent@example.test>\r\n",
            )
            .unwrap(),
        );
        changed.push(value);
        let mut value = original.clone();
        value.attachments.push(
            crate::send::UploadedAttachment::new(
                crate::send::ComposePolicy::default(),
                "file.txt",
                "text/plain",
                b"synthetic bytes".to_vec(),
            )
            .unwrap(),
        );
        changed.push(value);
        let before = record_bytes(&root.store());
        for changed in changed {
            assert_eq!(
                root.store()
                    .execute(ACCOUNT, &token, 101, &changed, || panic!(
                        "must not dispatch"
                    )),
                Err(JournalError::ChangedSnapshot)
            );
        }
        assert_eq!(record_bytes(&root.store()), before);
        // The same intent belongs independently to another authenticated account.
        assert!(
            !root
                .store()
                .execute("other@example.test", &token, 101, &original, || ACCEPTED)
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn attachment_content_metadata_order_and_field_boundaries_are_bound() {
        let mut original = request();
        for name in ["a.txt", "b.txt"] {
            original.attachments.push(
                crate::send::UploadedAttachment::new(
                    crate::send::ComposePolicy::default(),
                    name,
                    "text/plain",
                    b"ab".to_vec(),
                )
                .unwrap(),
            );
        }
        let original_hash = snapshot_digest(ACCOUNT, &original);
        let mut changed = original.clone();
        changed.attachments[0].filename = "c.txt".into();
        assert_ne!(original_hash, snapshot_digest(ACCOUNT, &changed));
        let mut changed = original.clone();
        changed.attachments[0].content_type = "application/octet-stream".into();
        assert_ne!(original_hash, snapshot_digest(ACCOUNT, &changed));
        let mut changed = original.clone();
        changed.attachments[0].body = b"ac".to_vec();
        assert_ne!(original_hash, snapshot_digest(ACCOUNT, &changed));
        let mut changed = original.clone();
        changed.attachments.swap(0, 1);
        assert_ne!(original_hash, snapshot_digest(ACCOUNT, &changed));
        let mut a = request();
        a.subject = "a".into();
        a.body = "bc".into();
        let mut b = request();
        b.subject = "ab".into();
        b.body = "c".into();
        assert_ne!(snapshot_digest(ACCOUNT, &a), snapshot_digest(ACCOUNT, &b));
    }

    #[test]
    fn uncertain_publication_and_callback_interruption_never_redispatch() {
        for terminal in [false, true] {
            for after in [false, true] {
                let root = Scratch::new();
                let mut store = root.store();
                store.fault = Some((terminal, after));
                let calls = AtomicUsize::new(0);
                let token = intent(100, 1);
                let result = store.execute(ACCOUNT, &token, 100, &request(), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ACCEPTED
                });
                if terminal {
                    assert_eq!(
                        result,
                        Ok(JournalResult {
                            outcome: ACCEPTED,
                            replayed: false,
                            receipt_persisted: false
                        })
                    );
                } else {
                    assert_eq!(result, Err(JournalError::StoreUnavailable));
                }
                assert_eq!(calls.load(Ordering::SeqCst), usize::from(terminal));
                let replay = root
                    .store()
                    .execute(ACCOUNT, &token, 101, &request(), || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        ACCEPTED
                    })
                    .unwrap();
                if terminal || after {
                    assert!(replay.replayed);
                    assert_eq!(
                        replay.outcome,
                        if terminal && after {
                            ACCEPTED
                        } else {
                            AttemptOutcome::Unconfirmed
                        }
                    );
                    assert_eq!(calls.load(Ordering::SeqCst), usize::from(terminal));
                } else {
                    assert!(!replay.replayed);
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                }
            }
        }
        let root = Scratch::new();
        let token = intent(100, 2);
        let interrupted = std::panic::catch_unwind(|| {
            root.store().execute(ACCOUNT, &token, 100, &request(), || {
                panic!("synthetic interruption")
            })
        });
        assert!(interrupted.is_err());
        let replay = root
            .store()
            .execute(ACCOUNT, &token, 101, &request(), || {
                panic!("must not redispatch")
            })
            .unwrap();
        assert_eq!(replay.outcome, AttemptOutcome::Unconfirmed);
    }

    #[test]
    fn competing_file_store_callers_cannot_dispatch_twice() {
        let root = Scratch::new();
        let token = intent(100, 1);
        let first = root.store();
        let first_token = token.clone();
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = calls.clone();
        let thread = std::thread::spawn(move || {
            first.execute(ACCOUNT, &first_token, 100, &request(), || {
                first_calls.fetch_add(1, Ordering::SeqCst);
                started.send(()).unwrap();
                wait.recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                ACCEPTED
            })
        });
        ready
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            root.store()
                .execute(ACCOUNT, &token, 100, &request(), || panic!(
                    "concurrent dispatch"
                )),
            Err(JournalError::StoreUnavailable)
        );
        assert!(root
            .store()
            .execute("other@example.test", &token, 100, &request(), || ACCEPTED)
            .is_ok());
        release.send(()).unwrap();
        assert!(thread.join().unwrap().is_ok());
        assert!(
            root.store()
                .execute(ACCOUNT, &token, 100, &request(), || panic!(
                    "repeat dispatch"
                ))
                .unwrap()
                .replayed
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pruning_retains_unknowns_and_high_water_blocks_clock_resurrection() {
        let root = Scratch::new();
        let store = root.store();
        store
            .execute(ACCOUNT, &intent(100, 1), 100, &request(), || ACCEPTED)
            .unwrap();
        store
            .execute(ACCOUNT, &intent(100, 2), 100, &request(), || {
                AttemptOutcome::Unconfirmed
            })
            .unwrap();
        let later = 100 + INTENT_LIFETIME;
        store
            .execute(ACCOUNT, &intent(later, 3), later, &request(), || ACCEPTED)
            .unwrap();
        let record = Record::read(Some(record_bytes(&store))).unwrap();
        assert_eq!(record.attempts.len(), 2);
        assert_eq!(record.high_water, later);
        assert!(record
            .attempts
            .iter()
            .any(|entry| entry.intent == intent(100, 2)));
        assert_eq!(
            store.execute(ACCOUNT, &intent(100, 1), 100, &request(), || panic!(
                "resurrected"
            )),
            Err(JournalError::ClockRollback)
        );
        assert_eq!(
            store.execute(ACCOUNT, &intent(100, 1), later, &request(), || panic!(
                "expired"
            )),
            Err(JournalError::ExpiredIntent)
        );
    }

    #[test]
    fn strict_schema_and_capacity_refuse_without_mutation() {
        let root = Scratch::new();
        let store = root.store();
        for bytes in [
            br#"{"version":2,"high_water":100,"attempts":[]}"#.as_slice(),
            br#"{"version":1,"version":1,"high_water":100,"attempts":[]}"#,
            br#"{"version":1,"high_water":100,"attempts":[],"extra":0}"#,
            br#"{"version":1,"high_water":100,"attempts":[{"intent":"bad","snapshot":"bad","state":"future"}]}"#,
        ] {
            fixture(&store, bytes);
            assert_eq!(store.execute(ACCOUNT, &intent(100, 1), 100, &request(), || panic!("invalid record")), Err(JournalError::InvalidRecord));
            assert_eq!(record_bytes(&store), bytes);
        }
        let record = Record {
            version: 1,
            high_water: 100,
            attempts: (0..MAX_ATTEMPTS)
                .map(|n| Entry {
                    intent: intent(100, n as u128),
                    snapshot: snapshot_digest(ACCOUNT, &request()),
                    state: State::Unconfirmed,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(bytes.len() < MAX_BYTES);
        fixture(&store, &bytes);
        assert_eq!(
            store.execute(
                ACCOUNT,
                &intent(100, MAX_ATTEMPTS as u128),
                100,
                &request(),
                || panic!("full")
            ),
            Err(JournalError::Capacity)
        );
        assert_eq!(record_bytes(&store), bytes);
        assert!(
            store
                .execute(ACCOUNT, &intent(100, 1), 100, &request(), || panic!(
                    "full replay"
                ))
                .unwrap()
                .replayed
        );
        let mut duplicate = record;
        duplicate.attempts[1].intent = duplicate.attempts[0].intent.clone();
        fixture(&store, &serde_json::to_vec(&duplicate).unwrap());
        assert_eq!(
            store.execute(ACCOUNT, &intent(100, 1), 100, &request(), || panic!(
                "duplicate record"
            )),
            Err(JournalError::InvalidRecord)
        );
        assert!(Record::read(Some(vec![b' '; MAX_BYTES + 1])).is_err());
    }

    #[test]
    fn preparation_is_locked_and_consumed_malformed_inputs_cannot_be_denied() {
        let root = Scratch::new();
        let store = root.store();
        let token = intent(100, 1);
        assert!(!store.consumed(ACCOUNT, &token, 100).unwrap());
        for refusal in ["invalid_request", "throttled"] {
            let result = store
                .execute_prepared(
                    ACCOUNT,
                    &token,
                    100,
                    |consumed| {
                        assert!(!consumed);
                        assert!(matches!(
                            root.store().account_guard(ACCOUNT, 100),
                            Err(JournalError::StoreUnavailable)
                        ));
                        Err::<ComposeRequest, _>(refusal)
                    },
                    |_| panic!("refused preparation must not dispatch"),
                )
                .unwrap();
            assert_eq!(result, PreparedResult::NotDispatched(refusal));
            assert!(!store.consumed(ACCOUNT, &token, 100).unwrap());
        }
        store
            .execute(ACCOUNT, &token, 100, &request(), || ACCEPTED)
            .unwrap();
        assert!(store.consumed(ACCOUNT, &token, 100).unwrap());
        assert_eq!(
            store.execute_prepared(
                ACCOUNT,
                &token,
                100,
                |consumed| {
                    assert!(consumed);
                    Err::<ComposeRequest, _>("malformed changed text")
                },
                |_| panic!("consumed malformed request")
            ),
            Err(JournalError::ChangedSnapshot)
        );
        let replay = store
            .execute_prepared(
                ACCOUNT,
                &token,
                100,
                |consumed| {
                    if !consumed {
                        return Err("synthetic current throttle");
                    }
                    Ok(request())
                },
                |_| panic!("accepted replay must skip dispatch"),
            )
            .unwrap();
        assert_eq!(
            replay,
            PreparedResult::Outcome(JournalResult {
                outcome: ACCEPTED,
                replayed: true,
                receipt_persisted: true
            })
        );
    }

    fn stored_draft(root: &Scratch) -> (crate::draft::FileDraftStore, crate::draft::DraftRecord) {
        use crate::draft::DraftStore;
        let store = crate::draft::FileDraftStore::new(
            root.0.join("drafts"),
            crate::draft::DraftPolicy::default(),
        );
        let draft = crate::draft::DraftRecord::new(
            crate::draft::DraftPolicy::default(),
            crate::draft::DraftRecordInput {
                draft_id: "abababababababababababababababab".into(),
                canonical_username: ACCOUNT.into(),
                now: 100,
                recipients_text: "bob@example.test".into(),
                cc_text: "".into(),
                bcc_text: "".into(),
                subject: "Synthetic subject".into(),
                body: "Synthetic body".into(),
                attachments: vec![],
                source_attachments: None,
            },
        )
        .unwrap();
        store.save(&draft, 100).unwrap();
        let loaded = store.load(ACCOUNT, &draft.draft_id, 100).unwrap().unwrap();
        (store, loaded)
    }

    #[test]
    fn actual_draft_save_wins_race_and_stale_send_cannot_dispatch() {
        use crate::draft::DraftStore;
        let root = Scratch::new();
        let (drafts, saved) = stored_draft(&root);
        let journal = SendJournal::new(root.0.join("journal"));
        let old = intent_for_draft(ACCOUNT, &saved.draft_id, 1, saved.updated_at).unwrap();
        assert_eq!(
            old,
            intent_for_draft(ACCOUNT, &saved.draft_id, 1, saved.updated_at).unwrap()
        );
        let guard = journal.account_guard(ACCOUNT, 100).unwrap();
        guard.require_unconsumed(&old).unwrap();
        let contender = journal.clone();
        let token = old.clone();
        let thread = std::thread::spawn(move || {
            contender.execute(ACCOUNT, &token, 100, &request(), || {
                panic!("save holds account lock")
            })
        });
        assert_eq!(thread.join().unwrap(), Err(JournalError::StoreUnavailable));
        let mut edited = saved.clone();
        edited.request.body = "Edited synthetic body".into();
        drafts.save(&edited, 101).unwrap();
        drop(guard);
        let result = journal
            .execute_prepared(
                ACCOUNT,
                &old,
                101,
                |_| {
                    let current = drafts.load(ACCOUNT, &saved.draft_id, 101).unwrap().unwrap();
                    if current.revision != saved.revision {
                        return Err("stale revision");
                    }
                    Ok(request())
                },
                |_| panic!("stale revision must not dispatch"),
            )
            .unwrap();
        assert_eq!(result, PreparedResult::NotDispatched("stale revision"));
        let current = drafts.load(ACCOUNT, &saved.draft_id, 101).unwrap().unwrap();
        assert_eq!(current.revision, Some(2));
        assert_ne!(
            old,
            intent_for_draft(ACCOUNT, &current.draft_id, 2, current.updated_at).unwrap()
        );
    }

    #[test]
    fn actual_send_wins_race_and_consumed_draft_or_unsaved_intent_cannot_save() {
        use crate::draft::DraftStore;
        let root = Scratch::new();
        let (drafts, saved) = stored_draft(&root);
        let journal = SendJournal::new(root.0.join("journal"));
        let token = intent_for_draft(ACCOUNT, &saved.draft_id, 1, saved.updated_at).unwrap();
        let calls = AtomicUsize::new(0);
        journal
            .execute(ACCOUNT, &token, 100, &request(), || {
                calls.fetch_add(1, Ordering::SeqCst);
                let contender = journal.clone();
                assert!(
                    std::thread::spawn(move || contender.account_guard(ACCOUNT, 100).is_err())
                        .join()
                        .unwrap()
                );
                ACCEPTED
            })
            .unwrap();
        let guard = journal.account_guard(ACCOUNT, 100).unwrap();
        assert_eq!(
            guard.require_unconsumed(&guard.draft_intent(&saved).unwrap()),
            Err(JournalError::Consumed)
        );
        assert!(guard.require_accepted_with_sent(&token).is_ok());
        drop(guard);
        assert_eq!(
            drafts
                .load(ACCOUNT, &saved.draft_id, 100)
                .unwrap()
                .unwrap()
                .revision,
            Some(1)
        );
        let unsaved = intent(100, 99);
        journal
            .execute(ACCOUNT, &unsaved, 100, &request(), || {
                calls.fetch_add(1, Ordering::SeqCst);
                AttemptOutcome::Unconfirmed
            })
            .unwrap();
        let guard = journal.account_guard(ACCOUNT, 100).unwrap();
        assert_eq!(
            guard.require_unconsumed(&unsaved),
            Err(JournalError::Consumed)
        );
        assert_eq!(
            guard.require_accepted_with_sent(&unsaved),
            Err(JournalError::ConfirmationRequired)
        );
        assert_eq!(drafts.list(ACCOUNT, 100).unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn historical_unknown_receipts_remain_readable_without_permitting_dispatch() {
        for reserved in [false, true] {
            let root = Scratch::new();
            let mut store = root.store();
            let token = intent(100, 1);
            if reserved {
                store.fault = Some((false, true));
            }
            let result = store.execute(ACCOUNT, &token, 100, &request(), || {
                AttemptOutcome::Unconfirmed
            });
            if reserved {
                assert_eq!(result, Err(JournalError::StoreUnavailable));
            } else {
                assert!(result.is_ok());
            }
            let later = 100 + INTENT_LIFETIME;
            let store = root.store();
            store
                .execute(ACCOUNT, &intent(later, 2), later, &request(), || ACCEPTED)
                .unwrap();
            let before = record_bytes(&store);
            assert_eq!(
                store.receipt(ACCOUNT, &token, later).unwrap(),
                Some(AttemptOutcome::Unconfirmed)
            );
            assert_eq!(
                store.receipt(ACCOUNT, &token, 1).unwrap(),
                Some(AttemptOutcome::Unconfirmed)
            );
            assert_eq!(
                store
                    .receipt("foreign@example.test", &token, later)
                    .unwrap(),
                None
            );
            assert_eq!(
                store.receipt(ACCOUNT, &intent(100, 99), later).unwrap(),
                None
            );
            assert_eq!(
                store.execute(ACCOUNT, &token, later, &request(), || panic!(
                    "expired dispatch"
                )),
                Err(JournalError::ExpiredIntent)
            );
            assert_eq!(
                store.execute(ACCOUNT, &token, 100, &request(), || panic!(
                    "backward dispatch"
                )),
                Err(JournalError::ClockRollback)
            );
            assert!(matches!(
                store.account_guard(ACCOUNT, 100),
                Err(JournalError::ClockRollback)
            ));
            assert_eq!(
                store
                    .account_guard(ACCOUNT, later)
                    .unwrap()
                    .require_unconsumed(&token),
                Err(JournalError::ExpiredIntent)
            );
            assert_eq!(record_bytes(&store), before);
        }
    }

    #[test]
    fn unsaved_save_wins_and_retires_original_form_before_draft_dispatch() {
        use crate::draft::DraftStore;
        let template = Scratch::new();
        let (_, mut draft) = stored_draft(&template);
        draft.revision = None;
        let root = Scratch::new();
        let journal = SendJournal::new(root.0.join("journal"));
        let drafts = crate::draft::FileDraftStore::new(
            root.0.join("drafts"),
            crate::draft::DraftPolicy::default(),
        );
        let original = intent(100, 55);
        let mut guard = journal.account_guard(ACCOUNT, 100).unwrap();
        guard.begin_draft_save(&original, &draft.draft_id).unwrap();
        let contender = journal.clone();
        let old_form = original.clone();
        assert_eq!(
            std::thread::spawn(move || contender.execute(
                ACCOUNT,
                &old_form,
                100,
                &request(),
                || panic!("save in progress")
            ))
            .join()
            .unwrap(),
            Err(JournalError::StoreUnavailable)
        );
        drafts.save(&draft, 100).unwrap();
        guard.finish_draft_save(&original, &draft.draft_id).unwrap();
        drop(guard);
        let saved = drafts.load(ACCOUNT, &draft.draft_id, 100).unwrap().unwrap();
        let saved_intent = intent_for_draft(
            ACCOUNT,
            &saved.draft_id,
            saved.revision.unwrap(),
            saved.updated_at,
        )
        .unwrap();
        let calls = AtomicUsize::new(0);
        journal
            .execute(ACCOUNT, &saved_intent, 100, &request(), || {
                calls.fetch_add(1, Ordering::SeqCst);
                ACCEPTED
            })
            .unwrap();
        let replay = journal
            .execute_prepared(
                ACCOUNT,
                &original,
                100,
                |_| -> Result<ComposeRequest, ()> { panic!("retired form must not prepare") },
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ACCEPTED
                },
            )
            .unwrap();
        assert_eq!(
            replay,
            PreparedResult::Outcome(JournalResult {
                outcome: AttemptOutcome::DraftSaved {
                    draft_id: parse_draft_id(&saved.draft_id).unwrap(),
                    save_confirmed: true,
                },
                replayed: true,
                receipt_persisted: true
            })
        );
        let mut guard = journal.account_guard(ACCOUNT, 100).unwrap();
        assert_eq!(
            guard.begin_draft_save(&original, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
            Err(JournalError::Consumed)
        );
        assert_eq!(drafts.list(ACCOUNT, 100).unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn interrupted_unsaved_handoffs_never_become_submission_unknown_or_retry() {
        use crate::draft::DraftStore;
        for phase in 0..3 {
            let template = Scratch::new();
            let (_, mut draft) = stored_draft(&template);
            draft.revision = None;
            let root = Scratch::new();
            let mut journal = SendJournal::new(root.0.join("journal"));
            if phase > 0 {
                journal.fault = Some((true, phase == 2));
            }
            let drafts = crate::draft::FileDraftStore::new(
                root.0.join("drafts"),
                crate::draft::DraftPolicy::default(),
            );
            let token = intent(100, 77);
            let mut guard = journal.account_guard(ACCOUNT, 100).unwrap();
            guard.begin_draft_save(&token, &draft.draft_id).unwrap();
            if phase > 0 {
                drafts.save(&draft, 100).unwrap();
                assert_eq!(
                    guard.finish_draft_save(&token, &draft.draft_id),
                    Err(JournalError::StoreUnavailable)
                );
            }
            drop(guard); // phase0 models interruption before draft publication.
            let journal = SendJournal::new(root.0.join("journal"));
            let expected = AttemptOutcome::DraftSaved {
                draft_id: parse_draft_id(&draft.draft_id).unwrap(),
                save_confirmed: phase == 2,
            };
            assert_eq!(
                journal.receipt(ACCOUNT, &token, 100).unwrap(),
                Some(expected)
            );
            assert_eq!(
                journal
                    .execute(ACCOUNT, &token, 100, &request(), || panic!(
                        "retired handoff"
                    ))
                    .unwrap()
                    .outcome,
                expected
            );
            let mut guard = journal.account_guard(ACCOUNT, 100).unwrap();
            assert_eq!(
                guard.begin_draft_save(&token, &draft.draft_id),
                Err(JournalError::Consumed)
            );
            assert_eq!(
                drafts
                    .load(ACCOUNT, &draft.draft_id, 100)
                    .unwrap()
                    .is_some(),
                phase > 0
            );
        }
    }

    #[test]
    fn expiry_waits_for_dispatch_then_obeys_the_existing_thirty_day_policy() {
        use crate::draft::DraftStore;
        let root = Scratch::new();
        let (drafts, saved) = stored_draft(&root);
        let journal = SendJournal::new(root.0.join("journal"));
        let token = intent_for_draft(
            ACCOUNT,
            &saved.draft_id,
            saved.revision.unwrap(),
            saved.updated_at,
        )
        .unwrap();
        let expires = saved.expires_at;
        journal
            .execute(ACCOUNT, &token, expires - 1, &request(), || {
                let contender = journal.clone();
                let competing_store = drafts.clone();
                let blocked = std::thread::spawn(move || {
                    let guard = contender.account_guard(ACCOUNT, expires);
                    if guard.is_err() {
                        return true;
                    }
                    competing_store.list(ACCOUNT, expires).unwrap();
                    false
                })
                .join()
                .unwrap();
                assert!(blocked);
                AttemptOutcome::Unconfirmed
            })
            .unwrap();
        assert!(drafts
            .load(ACCOUNT, &saved.draft_id, expires - 1)
            .unwrap()
            .is_some());
        let guard = journal.account_guard(ACCOUNT, expires).unwrap();
        assert!(drafts.list(ACCOUNT, expires).unwrap().is_empty());
        drop(guard);
        assert_eq!(
            journal.receipt(ACCOUNT, &token, expires).unwrap(),
            Some(AttemptOutcome::Unconfirmed)
        );
        assert!(!drafts
            .draft_dir_for_username_and_id(ACCOUNT, &saved.draft_id)
            .exists());
    }

    #[test]
    fn intents_are_finite_and_future_or_expired_forms_do_not_dispatch() {
        let root = Scratch::new();
        let store = root.store();
        let minted = mint_intent(100).unwrap();
        assert_eq!(intent_time(&minted).unwrap(), 100);
        assert_ne!(minted, mint_intent(100).unwrap());
        for invalid in [
            "0.00000000000000000000000000000000",
            "0100.00000000000000000000000000000000",
            "100.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "100.a",
            "18446744073709551616.00000000000000000000000000000000",
        ] {
            assert_eq!(
                store.execute(ACCOUNT, invalid, 100, &request(), || panic!("invalid")),
                Err(JournalError::InvalidIntent)
            );
        }
        assert_eq!(
            store.execute(ACCOUNT, &intent(101, 1), 100, &request(), || panic!(
                "future"
            )),
            Err(JournalError::InvalidIntent)
        );
        assert_eq!(
            store.execute(
                ACCOUNT,
                &intent(100, 1),
                100 + INTENT_LIFETIME,
                &request(),
                || panic!("expired")
            ),
            Err(JournalError::ExpiredIntent)
        );
        assert!(!root.0.exists());
    }
}
