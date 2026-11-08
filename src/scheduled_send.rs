//! Durable, bounded scheduled authoring snapshots. SMTP authority stays in the
//! existing send pipeline. Lock order is journal account -> job index -> codec.
use crate::draft::{DraftPolicy, DraftRecord, DraftRecordInput, DraftStore, FileDraftStore};
use crate::openpgp_personal::PrivateSession;
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use crate::send::{ComposePolicy, ComposeRequest};
use crate::send_journal::{snapshot_digest, AccountGuard};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub(crate) const MAX_JOBS: usize = 20;
pub(crate) const MAX_BYTES: u64 = 50 * 1024 * 1024;
pub(crate) const HORIZON: u64 = 30 * 86400;
pub(crate) const PAYLOAD_LIFETIME: u64 = 60 * 86400;
const TERMINAL_LIFETIME: u64 = 30 * 86400;
const MAX_RECORD: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;
const MAX_GLOBAL_ENTRIES: usize = 65536;
const NAMESPACE: &str = "scheduled-send-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NotFound,
    Stale,
    Capacity,
    ClockRollback,
    Unavailable,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Staged,
    Pending,
    Blocked,
    ReturningToDraft,
    Claimed,
    Unknown,
    Submitted,
    Cancelled,
    Failed,
}
impl State {
    fn terminal(self) -> bool {
        matches!(self, Self::Submitted | Self::Cancelled | Self::Failed)
    }
    fn editable(self) -> bool {
        matches!(self, Self::Pending | Self::Blocked)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    KeyLocked,
    SessionExpired,
    AccountChanged,
    ServiceUnavailable,
    PolicyChanged,
    InvalidContent,
    PayloadExpired,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    subject: String,
    payload: Option<String>,
    retired_payload: Option<String>,
    digest: String,
    created_at: u64,
    updated_at: u64,
    due_at: u64,
    payload_expires_at: u64,
    authorized_at: u64,
    account_epoch: u64,
    private_session: PrivateSession,
    state: State,
    ready: bool,
    intent: Option<String>,
    reason: Option<BlockReason>,
    terminal_at: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    account: String,
    revision: u64,
    high_water: u64,
    entries: Vec<Entry>,
}

/// No body, Bcc, attachments or private-session descriptor enters this projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobView {
    pub id: String,
    pub subject: String,
    pub digest: String,
    pub state: State,
    pub due_at: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub payload_expires_at: u64,
    pub reason: Option<BlockReason>,
    pub intent: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobList {
    pub revision: u64,
    pub jobs: Vec<JobView>,
}
pub(crate) struct ScheduleInput<'a> {
    pub due_at: u64,
    pub account_epoch: u64,
    pub private_session: PrivateSession,
    pub request: &'a ComposeRequest,
}
pub(crate) struct Reauthorization {
    pub due_at: u64,
    pub account_epoch: u64,
    pub private_session: PrivateSession,
}
#[derive(Clone, Copy)]
pub(crate) enum ClaimRecovery {
    NoAttempt,
    Submitted,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedJob {
    pub id: String,
    pub digest: String,
    pub revision: u64,
}

/// Constructed only after a persisted claim. The caller cannot manufacture a
/// claimed snapshot or replace its stable delivery identity.
pub(crate) struct ClaimedJob {
    account: String,
    id: String,
    digest: String,
    intent: String,
    epoch: u64,
    private_session: PrivateSession,
    request: ComposeRequest,
}
impl ClaimedJob {
    pub(crate) fn account(&self) -> &str {
        &self.account
    }
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn intent(&self) -> &str {
        &self.intent
    }
    pub(crate) fn account_epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn private_session(&self) -> &PrivateSession {
        &self.private_session
    }
    pub(crate) fn request(&self) -> &ComposeRequest {
        &self.request
    }
}

#[derive(Clone)]
pub(crate) struct ScheduledStore {
    root: PathBuf,
    index: PrivateAccountFile,
}
impl ScheduledStore {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            index: PrivateAccountFile::new(root.join("index"), NAMESPACE, MAX_RECORD),
            root,
        }
    }
    fn payloads(&self) -> FileDraftStore {
        FileDraftStore::new(
            self.root.join("payloads"),
            DraftPolicy {
                max_age_seconds: PAYLOAD_LIFETIME,
                max_drafts_per_user: MAX_JOBS * 2,
                max_summary_rows: MAX_JOBS * 2,
                storage_max_bytes: MAX_BYTES,
                ..DraftPolicy::default()
            },
        )
    }
    fn canonical(account: &str) -> bool {
        crate::identity::MailboxIdentity::parse(account)
            .is_ok_and(|value| value.as_str() == account)
    }
    fn hex(value: &str, len: usize) -> bool {
        value.len() == len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Index, Error> {
        if !Self::canonical(account) {
            return Err(Error::Invalid);
        }
        let Some(bytes) = bytes else {
            return Ok(Index {
                version: 1,
                account: account.into(),
                revision: 0,
                high_water: 0,
                entries: Vec::new(),
            });
        };
        let index: Index = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if index.version != 1 || index.account != account || index.entries.len() > MAX_ENTRIES {
            return Err(Error::Invalid);
        }
        let mut ids = BTreeSet::new();
        let mut payloads = BTreeSet::new();
        let mut intents = BTreeSet::new();
        let mut active = 0;
        for entry in &index.entries {
            if !Self::hex(&entry.id, 32)
                || crate::send::validate_subject(ComposePolicy::default(), &entry.subject).is_err()
                || !ids.insert(&entry.id)
                || !Self::hex(&entry.digest, 64)
                || entry.created_at == 0
                || entry.created_at > entry.updated_at
                || entry.updated_at > index.high_water
                || entry.payload_expires_at.checked_sub(entry.created_at) != Some(PAYLOAD_LIFETIME)
                || entry.authorized_at < entry.created_at
                || entry.authorized_at > entry.updated_at
                || !crate::account_admission::valid_epoch(entry.account_epoch)
                || entry.private_session.account_epoch != Some(entry.account_epoch)
                || !entry.private_session.valid(entry.authorized_at)
                || entry.due_at < entry.created_at
                || entry
                    .due_at
                    .checked_sub(entry.authorized_at)
                    .is_none_or(|age| age == 0 || age > HORIZON)
                || entry.due_at >= entry.payload_expires_at
                || entry
                    .payload
                    .as_ref()
                    .is_some_and(|id| !Self::hex(id, 32) || !payloads.insert(id))
                || entry
                    .retired_payload
                    .as_ref()
                    .is_some_and(|id| !Self::hex(id, 32) || !payloads.insert(id))
                || entry.intent.as_ref().is_some_and(|intent| {
                    crate::send_journal::intent_time(intent).is_err() || !intents.insert(intent)
                })
                || (matches!(
                    entry.state,
                    State::Claimed | State::Unknown | State::Submitted
                ) && entry.intent.is_none())
                || entry.state.terminal() != entry.terminal_at.is_some()
                || entry
                    .terminal_at
                    .is_some_and(|time| time < entry.created_at || time > entry.updated_at)
                || (matches!(entry.state, State::Pending | State::ReturningToDraft)
                    && (!entry.ready || entry.payload.is_none() || entry.reason.is_some()))
                || (entry.state == State::Blocked && entry.reason.is_none())
            {
                return Err(Error::Invalid);
            }
            if !entry.state.terminal() {
                active += 1;
            }
        }
        if active > MAX_JOBS {
            return Err(Error::Invalid);
        }
        Ok(index)
    }
    fn lock(&self, guard: &AccountGuard, now: u64) -> Result<(LockedAccountFile, Index), Error> {
        let lock = self
            .index
            .lock(guard.account())
            .map_err(|_| Error::Unavailable)?;
        let index = Self::decode(
            guard.account(),
            lock.read().map_err(|_| Error::Unavailable)?,
        )?;
        if now == 0 || now < index.high_water {
            return Err(Error::ClockRollback);
        }
        Ok((lock, index))
    }
    fn write(lock: &LockedAccountFile, index: &mut Index, now: u64) -> Result<(), Error> {
        index.revision = index.revision.checked_add(1).ok_or(Error::Capacity)?;
        index.high_water = now;
        Self::persist(lock, index)
    }
    fn persist(lock: &LockedAccountFile, index: &Index) -> Result<(), Error> {
        let bytes = serde_json::to_vec(index).map_err(|_| Error::Invalid)?;
        if bytes.len() > MAX_RECORD {
            return Err(Error::Capacity);
        }
        lock.write(&bytes).map_err(|_| Error::Unconfirmed)
    }
    fn cas(index: &Index, revision: u64) -> Result<(), Error> {
        if index.revision == revision {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    fn validate_input(input: &ScheduleInput<'_>, now: u64) -> Result<(), Error> {
        if crate::send::validate_subject(ComposePolicy::default(), &input.request.subject).is_err()
            || input.due_at <= now
            || input
                .due_at
                .checked_sub(now)
                .is_none_or(|age| age > HORIZON)
            || !crate::account_admission::valid_epoch(input.account_epoch)
            || !input.private_session.valid(now)
            || input.private_session.account_epoch != Some(input.account_epoch)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn capture(
        &self,
        account: &str,
        id: &str,
        request: &ComposeRequest,
        now: u64,
    ) -> Result<(), Error> {
        let store = self.payloads();
        // Job expiry was reconciled before allocation. This also removes
        // finite expired orphan snapshots through the existing codec.
        store
            .cleanup_expired(account, now)
            .map_err(|_| Error::Unavailable)?;
        let (_, used) = store
            .settle_storage_usage(account)
            .map_err(|_| Error::Unavailable)?;
        let mut record = DraftRecord::new(
            DraftPolicy {
                max_age_seconds: PAYLOAD_LIFETIME,
                ..DraftPolicy::default()
            },
            DraftRecordInput {
                draft_id: id.into(),
                canonical_username: account.into(),
                now,
                recipients_text: request.recipients.join(", "),
                cc_text: request.cc_recipients.join(", "),
                bcc_text: request.bcc_recipients.join(", "),
                subject: request.subject.clone(),
                body: request.body.clone(),
                attachments: request.attachments.clone(),
                source_attachments: None,
            },
        )
        .map_err(|_| Error::Invalid)?;
        record.request.sender_identity = request.sender_identity.clone();
        record.request.body_format = request.body_format;
        record.request.reply_thread = request.reply_thread.clone();
        record.request.protection = request.protection;
        if restore(&record)? != *request
            || used
                .checked_add(record.summary().storage_bytes)
                .is_none_or(|total| total > MAX_BYTES)
        {
            return Err(Error::Capacity);
        }
        store.save(&record, now).map_err(|_| Error::Unconfirmed)?;
        let reopened = store
            .read_immutable(account, id)
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unconfirmed)?;
        if restore(&reopened)? != *request {
            return Err(Error::Unconfirmed);
        }
        Ok(())
    }
    fn read_payload(
        &self,
        account: &str,
        entry: &Entry,
        now: u64,
    ) -> Result<ComposeRequest, Error> {
        if now >= entry.payload_expires_at || !entry.ready {
            return Err(Error::Unavailable);
        }
        let record = self
            .payloads()
            .read_immutable(account, entry.payload.as_deref().ok_or(Error::NotFound)?)
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::Unavailable)?;
        let request = restore(&record)?;
        if record.revision != Some(1) || snapshot_digest(account, &request) != entry.digest {
            return Err(Error::Invalid);
        }
        Ok(request)
    }
    fn delete_payload(&self, account: &str, id: &str) -> Result<(), Error> {
        let store = self.payloads();
        // Reuse atomic first-save recovery before reading a possibly
        // interrupted staged snapshot; never traverse or unlink ad hoc paths.
        store
            .settle_storage_usage(account)
            .map_err(|_| Error::Unavailable)?;
        if let Some(record) = store
            .read_immutable(account, id)
            .map_err(|_| Error::Unavailable)?
        {
            store
                .delete(account, id, record.revision.ok_or(Error::Invalid)?)
                .map_err(|_| Error::Unconfirmed)?;
        }
        if store
            .read_immutable(account, id)
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::Unconfirmed);
        }
        Ok(())
    }
    /// Mark non-dispatchable first, then remove expired/terminal plaintext. A
    /// failed deletion remains indexed and charged; Unknown is never rearmed.
    fn expire(
        &self,
        guard: &AccountGuard,
        lock: &LockedAccountFile,
        index: &mut Index,
        now: u64,
    ) -> Result<(), Error> {
        let mut changed = false;
        for entry in &mut index.entries {
            if now >= entry.payload_expires_at && !entry.state.terminal() {
                entry.state = if matches!(entry.state, State::Claimed | State::Unknown) {
                    State::Unknown
                } else {
                    State::Failed
                };
                entry.terminal_at = entry.state.terminal().then_some(now);
                entry.ready = false;
                entry.reason = Some(BlockReason::PayloadExpired);
                entry.updated_at = now;
                changed = true;
            }
        }
        if changed {
            Self::write(lock, index, now)?;
        }
        let mut removed = false;
        for entry in &mut index.entries {
            if entry.state.terminal() || now >= entry.payload_expires_at {
                if let Some(id) = &entry.retired_payload {
                    self.delete_payload(guard.account(), id)?;
                    entry.retired_payload = None;
                    removed = true;
                }
                if let Some(id) = &entry.payload {
                    self.delete_payload(guard.account(), id)?;
                    entry.payload = None;
                    removed = true;
                }
            }
        }
        let before = index.entries.len();
        index.entries.retain(|entry| {
            !(entry.payload.is_none()
                && entry.retired_payload.is_none()
                && entry
                    .terminal_at
                    .is_some_and(|time| now.saturating_sub(time) >= TERMINAL_LIFETIME))
        });
        if removed || index.entries.len() != before {
            Self::write(lock, index, now)?;
        }
        Ok(())
    }
    pub(crate) fn list(&self, guard: &AccountGuard, now: u64) -> Result<JobList, Error> {
        let (lock, mut index) = self.lock(guard, now)?;
        self.expire(guard, &lock, &mut index, now)?;
        if now > index.high_water {
            index.high_water = now;
            Self::persist(&lock, &index)?;
        }
        let mut jobs: Vec<_> = index.entries.iter().map(view).collect();
        jobs.sort_by_key(|job| (job.due_at, job.id.clone()));
        Ok(JobList {
            revision: index.revision,
            jobs,
        })
    }
    pub(crate) fn create_staged(
        &self,
        guard: &AccountGuard,
        expected_revision: u64,
        input: ScheduleInput<'_>,
        now: u64,
    ) -> Result<StagedJob, Error> {
        Self::validate_input(&input, now)?;
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, expected_revision)?;
        self.expire(guard, &lock, &mut index, now)?;
        if index.entries.len() >= MAX_ENTRIES
            || index
                .entries
                .iter()
                .filter(|entry| !entry.state.terminal())
                .count()
                >= MAX_JOBS
        {
            return Err(Error::Capacity);
        }
        let id = crate::draft::generate_draft_id().map_err(|_| Error::Unavailable)?;
        let payload = crate::draft::generate_draft_id().map_err(|_| Error::Unavailable)?;
        if index.entries.iter().any(|entry| {
            entry.id == id
                || entry.payload.as_ref() == Some(&payload)
                || entry.retired_payload.as_ref() == Some(&payload)
        }) || self
            .payloads()
            .read_immutable(guard.account(), &payload)
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::Unavailable);
        }
        let digest = snapshot_digest(guard.account(), input.request);
        index.entries.push(Entry {
            id: id.clone(),
            subject: input.request.subject.clone(),
            payload: Some(payload.clone()),
            retired_payload: None,
            digest: digest.clone(),
            created_at: now,
            updated_at: now,
            due_at: input.due_at,
            payload_expires_at: now.checked_add(PAYLOAD_LIFETIME).ok_or(Error::Invalid)?,
            authorized_at: now,
            account_epoch: input.account_epoch,
            private_session: input.private_session,
            state: State::Staged,
            ready: false,
            intent: None,
            reason: None,
            terminal_at: None,
        });
        Self::write(&lock, &mut index, now)?;
        self.capture(guard.account(), &payload, input.request, now)?;
        index.entries.last_mut().ok_or(Error::Invalid)?.ready = true;
        Self::write(&lock, &mut index, now)?;
        Ok(StagedJob {
            id,
            digest,
            revision: index.revision,
        })
    }
    pub(crate) fn publish_pending(
        &self,
        guard: &AccountGuard,
        expected_revision: u64,
        id: &str,
        digest: &str,
        now: u64,
    ) -> Result<JobList, Error> {
        guard
            .require_schedule_binding(id, digest)
            .map_err(|_| Error::Invalid)?;
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, expected_revision)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        if entry.state != State::Staged
            || entry.digest != digest
            || entry.due_at <= now
            || entry.retired_payload.is_some()
        {
            return Err(Error::Invalid);
        }
        self.read_payload(guard.account(), entry, now)?;
        entry.state = State::Pending;
        entry.updated_at = now;
        Self::write(&lock, &mut index, now)?;
        Ok(JobList {
            revision: index.revision,
            jobs: index.entries.iter().map(view).collect(),
        })
    }
    /// Full content edits become non-dispatchable before either payload file or
    /// journal binding changes. Caller replaces the journal binding, then publishes.
    pub(crate) fn replace_staged(
        &self,
        guard: &AccountGuard,
        expected_revision: u64,
        id: &str,
        input: ScheduleInput<'_>,
        now: u64,
    ) -> Result<StagedJob, Error> {
        Self::validate_input(&input, now)?;
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, expected_revision)?;
        self.expire(guard, &lock, &mut index, now)?;
        let payload = crate::draft::generate_draft_id().map_err(|_| Error::Unavailable)?;
        if index.entries.iter().any(|entry| {
            entry.payload.as_ref() == Some(&payload)
                || entry.retired_payload.as_ref() == Some(&payload)
        }) || self
            .payloads()
            .read_immutable(guard.account(), &payload)
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::Unavailable);
        }
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        if !entry.state.editable() || input.due_at >= entry.payload_expires_at {
            return Err(Error::Invalid);
        }
        entry.state = State::Staged;
        entry.intent = None;
        entry.ready = false;
        entry.updated_at = now;
        entry.retired_payload = entry.payload.replace(payload.clone());
        entry.digest = snapshot_digest(guard.account(), input.request);
        entry.subject = input.request.subject.clone();
        entry.due_at = input.due_at;
        entry.account_epoch = input.account_epoch;
        entry.private_session = input.private_session;
        entry.authorized_at = now;
        entry.reason = None;
        let digest = entry.digest.clone();
        Self::write(&lock, &mut index, now)?;
        self.capture(guard.account(), &payload, input.request, now)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        entry.ready = true;
        Self::write(&lock, &mut index, now)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        if let Some(old) = &entry.retired_payload {
            self.delete_payload(guard.account(), old)?;
            entry.retired_payload = None;
        }
        Self::write(&lock, &mut index, now)?;
        Ok(StagedJob {
            id: id.into(),
            digest,
            revision: index.revision,
        })
    }
    pub(crate) fn cancel(
        &self,
        guard: &AccountGuard,
        expected_revision: u64,
        id: &str,
        now: u64,
    ) -> Result<JobList, Error> {
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, expected_revision)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        if !(entry.state.editable() || entry.state == State::Staged) {
            return Err(Error::Invalid);
        }
        entry.state = State::Cancelled;
        entry.terminal_at = Some(now);
        entry.updated_at = now;
        entry.ready = false;
        Self::write(&lock, &mut index, now)?;
        self.expire(guard, &lock, &mut index, now)?;
        Ok(JobList {
            revision: index.revision,
            jobs: index.entries.iter().map(view).collect(),
        })
    }
    /// Stop dispatch durably before an editable destination can be published.
    pub(crate) fn prepare_return_to_draft(
        &self,
        guard: &AccountGuard,
        revision: u64,
        id: &str,
        now: u64,
    ) -> Result<(JobList, ComposeRequest), Error> {
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, revision)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        if !(entry.state.editable() || entry.state == State::ReturningToDraft) {
            return Err(Error::Invalid);
        }
        let request = self.read_payload(guard.account(), entry, now)?;
        if entry.state != State::ReturningToDraft {
            entry.state = State::ReturningToDraft;
            entry.reason = None;
            entry.updated_at = now;
            Self::write(&lock, &mut index, now)?;
        }
        Ok((
            JobList {
                revision: index.revision,
                jobs: index.entries.iter().map(view).collect(),
            },
            request,
        ))
    }
    /// Caller has confirmed the owned destination by readback. Retire only the
    /// scheduler payload; its original consumed source intent remains consumed.
    pub(crate) fn finish_return_to_draft(
        &self,
        guard: &AccountGuard,
        revision: u64,
        id: &str,
        now: u64,
    ) -> Result<JobList, Error> {
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, revision)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::NotFound)?;
        if entry.state != State::ReturningToDraft {
            return Err(Error::Invalid);
        }
        entry.state = State::Cancelled;
        entry.terminal_at = Some(now);
        entry.updated_at = now;
        entry.ready = false;
        Self::write(&lock, &mut index, now)?;
        self.expire(guard, &lock, &mut index, now)?;
        Ok(JobList {
            revision: index.revision,
            jobs: index.entries.iter().map(view).collect(),
        })
    }
    pub(crate) fn claim_next(
        &self,
        guard: &AccountGuard,
        now: u64,
    ) -> Result<Option<ClaimedJob>, Error> {
        let (lock, mut index) = self.lock(guard, now)?;
        self.expire(guard, &lock, &mut index, now)?;
        let selected = index
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.state == State::Pending && entry.due_at <= now)
            .min_by_key(|(_, entry)| (entry.due_at, &entry.id))
            .map(|(position, _)| position);
        let Some(position) = selected else {
            if now > index.high_water {
                index.high_water = now;
                Self::persist(&lock, &index)?;
            }
            return Ok(None);
        };
        let entry = &index.entries[position];
        guard
            .require_schedule_binding(&entry.id, &entry.digest)
            .map_err(|_| Error::Invalid)?;
        let request = self.read_payload(guard.account(), entry, now)?;
        let entry = &mut index.entries[position];
        let intent = match &entry.intent {
            Some(intent) => intent.clone(),
            None => crate::send_journal::mint_intent(now).map_err(|_| Error::Unavailable)?,
        };
        entry.intent = Some(intent.clone());
        entry.state = State::Claimed;
        entry.updated_at = now;
        let claim = ClaimedJob {
            account: guard.account().into(),
            id: entry.id.clone(),
            digest: entry.digest.clone(),
            intent,
            epoch: entry.account_epoch,
            private_session: entry.private_session.clone(),
            request,
        };
        Self::write(&lock, &mut index, now)?;
        Ok(Some(claim))
    }
    /// Called only when the shared send pipeline proves no SMTP dispatch. A new
    /// explicit authorization is required; the worker cannot pick Blocked jobs.
    pub(crate) fn block_unsubmitted(
        &self,
        guard: &AccountGuard,
        claim: &ClaimedJob,
        reason: BlockReason,
        now: u64,
    ) -> Result<(), Error> {
        self.finish(guard, claim, State::Blocked, Some(reason), now)
    }
    pub(crate) fn submitted(
        &self,
        guard: &AccountGuard,
        claim: &ClaimedJob,
        now: u64,
    ) -> Result<(), Error> {
        self.finish(guard, claim, State::Submitted, None, now)
    }
    pub(crate) fn unknown(
        &self,
        guard: &AccountGuard,
        claim: &ClaimedJob,
        now: u64,
    ) -> Result<(), Error> {
        self.finish(guard, claim, State::Unknown, None, now)
    }
    fn finish(
        &self,
        guard: &AccountGuard,
        claim: &ClaimedJob,
        state: State,
        reason: Option<BlockReason>,
        now: u64,
    ) -> Result<(), Error> {
        if claim.account != guard.account() {
            return Err(Error::Invalid);
        }
        let (lock, mut index) = self.lock(guard, now)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == claim.id)
            .ok_or(Error::NotFound)?;
        if entry.state != State::Claimed
            || entry.digest != claim.digest
            || entry.intent.as_deref() != Some(&claim.intent)
        {
            return Err(Error::Stale);
        }
        entry.state = state;
        entry.reason = reason;
        entry.updated_at = now;
        entry.terminal_at = state.terminal().then_some(now);
        Self::write(&lock, &mut index, now)?;
        self.expire(guard, &lock, &mut index, now)
    }
    pub(crate) fn reauthorize(
        &self,
        guard: &AccountGuard,
        expected_revision: u64,
        id: &str,
        authorization: Reauthorization,
        now: u64,
    ) -> Result<JobList, Error> {
        let Reauthorization {
            private_session,
            account_epoch: epoch,
            due_at,
        } = authorization;
        if !private_session.valid(now)
            || private_session.account_epoch != Some(epoch)
            || !crate::account_admission::valid_epoch(epoch)
            || due_at <= now
            || due_at.saturating_sub(now) > HORIZON
        {
            return Err(Error::Invalid);
        }
        let (lock, mut index) = self.lock(guard, now)?;
        Self::cas(&index, expected_revision)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        if !entry.state.editable() || due_at >= entry.payload_expires_at {
            return Err(Error::Invalid);
        }
        if entry.intent.as_ref().is_some_and(|intent| {
            !crate::send_journal::intent_time(intent).is_ok_and(|issued| {
                due_at.saturating_sub(issued) < crate::send_journal::INTENT_LIFETIME
            })
        }) {
            return Err(Error::Invalid);
        }
        self.read_payload(guard.account(), entry, now)?;
        entry.account_epoch = epoch;
        entry.private_session = private_session;
        entry.authorized_at = now;
        entry.due_at = due_at;
        entry.state = State::Pending;
        entry.reason = None;
        entry.updated_at = now;
        Self::write(&lock, &mut index, now)?;
        Ok(JobList {
            revision: index.revision,
            jobs: index.entries.iter().map(view).collect(),
        })
    }
    /// Caller holds the exclusive run-once worker lock and has inspected the
    /// existing journal receipt. NoAttempt continues only the same intent.
    pub(crate) fn recover_claimed(
        &self,
        guard: &AccountGuard,
        id: &str,
        intent: &str,
        outcome: ClaimRecovery,
        now: u64,
    ) -> Result<Option<ClaimedJob>, Error> {
        let (lock, mut index) = self.lock(guard, now)?;
        let entry = index
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        if !matches!(entry.state, State::Claimed | State::Unknown)
            || entry.intent.as_deref() != Some(intent)
        {
            return Err(Error::Stale);
        }
        guard
            .require_schedule_binding(&entry.id, &entry.digest)
            .map_err(|_| Error::Invalid)?;
        match outcome {
            ClaimRecovery::NoAttempt => {
                if entry.state != State::Claimed {
                    return Err(Error::Invalid);
                }
                let request = self.read_payload(guard.account(), entry, now)?;
                return Ok(Some(ClaimedJob {
                    account: guard.account().into(),
                    id: entry.id.clone(),
                    digest: entry.digest.clone(),
                    intent: intent.into(),
                    epoch: entry.account_epoch,
                    private_session: entry.private_session.clone(),
                    request,
                }));
            }
            ClaimRecovery::Submitted => {
                entry.state = State::Submitted;
                entry.reason = None;
                entry.terminal_at = Some(now);
            }
            ClaimRecovery::Unknown => {
                entry.state = State::Unknown;
            }
        }
        entry.updated_at = now;
        Self::write(&lock, &mut index, now)?;
        self.expire(guard, &lock, &mut index, now)?;
        Ok(None)
    }
    pub(crate) fn read(
        &self,
        guard: &AccountGuard,
        id: &str,
        now: u64,
    ) -> Result<ComposeRequest, Error> {
        let (_lock, index) = self.lock(guard, now)?;
        let entry = index
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(Error::NotFound)?;
        self.read_payload(guard.account(), entry, now)
    }
    #[cfg(test)]
    pub(crate) fn discover_accounts(&self) -> Result<Vec<String>, Error> {
        self.discover_accounts_before(
            std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(90))
                .ok_or(Error::Unavailable)?,
        )
    }
    pub(crate) fn discover_accounts_before(
        &self,
        deadline: std::time::Instant,
    ) -> Result<Vec<String>, Error> {
        let within_budget = || {
            if std::time::Instant::now() < deadline {
                Ok(())
            } else {
                Err(Error::Unavailable)
            }
        };
        within_budget()?;
        let directory = self.root.join("index");
        match crate::private_account_file::check_directory(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(Error::Unavailable),
            Ok(()) => {}
        }
        let mut accounts = BTreeSet::new();
        for (number, entry) in std::fs::read_dir(&directory)
            .map_err(|_| Error::Unavailable)?
            .enumerate()
        {
            within_budget()?;
            if number >= MAX_GLOBAL_ENTRIES {
                return Err(Error::Capacity);
            }
            let entry = entry.map_err(|_| Error::Unavailable)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::Invalid)?;
            let known_lock = name
                .strip_suffix(".lock")
                .is_some_and(|stem| Self::hex(stem, 64));
            let known_temporary = name
                .strip_prefix('.')
                .and_then(|value| value.strip_suffix(".tmp"))
                .is_some_and(|value| {
                    let parts: Vec<_> = value.split('-').collect();
                    parts.len() == 3
                        && Self::hex(parts[0], 64)
                        && parts[1..].iter().all(|part| {
                            part.parse::<u64>()
                                .is_ok_and(|number| number.to_string() == *part)
                        })
                });
            if known_lock || known_temporary {
                crate::private_account_file::read_record(&entry.path(), MAX_RECORD)
                    .map_err(|_| Error::Unavailable)?
                    .ok_or(Error::Unavailable)?;
                continue;
            }
            let stem = name
                .strip_suffix(".json")
                .filter(|stem| Self::hex(stem, 64))
                .ok_or(Error::Invalid)?;
            let bytes = crate::private_account_file::read_record(&entry.path(), MAX_RECORD)
                .map_err(|_| Error::Unavailable)?
                .ok_or(Error::Unavailable)?;
            within_budget()?;
            let header: Index = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
            let account = header.account.clone();
            Self::decode(&account, Some(bytes))?;
            let mut hash = Sha256::new();
            hash.update(NAMESPACE.as_bytes());
            hash.update(b"\0");
            hash.update(account.as_bytes());
            if format!("{:x}", hash.finalize()) != stem || !accounts.insert(account) {
                return Err(Error::Invalid);
            }
        }
        within_budget()?;
        Ok(accounts.into_iter().collect())
    }
}
fn view(entry: &Entry) -> JobView {
    JobView {
        id: entry.id.clone(),
        subject: entry.subject.clone(),
        digest: entry.digest.clone(),
        state: entry.state,
        due_at: entry.due_at,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        payload_expires_at: entry.payload_expires_at,
        reason: entry.reason,
        intent: entry.intent.clone(),
    }
}

#[cfg(test)]
mod discovery_deadline_tests {
    use super::*;
    #[test]
    fn expired_discovery_budget_is_unavailable_even_for_an_absent_directory() {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let name = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let store = ScheduledStore::new(
            std::env::temp_dir().join(format!("osmap-discovery-deadline-{name}")),
        );
        assert_eq!(
            store.discover_accounts_before(std::time::Instant::now()),
            Err(Error::Unavailable)
        );
        assert_eq!(
            store.discover_accounts_before(
                std::time::Instant::now() + std::time::Duration::from_secs(1)
            ),
            Ok(Vec::new())
        );
    }
}
fn restore(record: &DraftRecord) -> Result<ComposeRequest, Error> {
    let content = &record.request;
    let mut request = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        &content.recipients_text,
        &content.cc_text,
        &content.bcc_text,
        &content.subject,
        &content.body,
        content.attachments.clone(),
    )
    .and_then(|request| request.with_body_format(content.body_format))
    .map_err(|_| Error::Invalid)?;
    request.sender_identity = content.sender_identity.clone();
    request.reply_thread = content.reply_thread.clone();
    request.protection = content.protection;
    Ok(request)
}

#[cfg(test)]
mod tests {
    include!("scheduled_send_tests.rs");
}
