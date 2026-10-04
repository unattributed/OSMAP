//! Immutable exact prepared attempts, kept outside editable draft namespaces.
//! Caller holds the journal account guard during capture and quota operations.
use crate::draft::{DraftPolicy, DraftRecord, DraftRecordInput, DraftStore, FileDraftStore};
use crate::private_account_file::PrivateAccountFile;
use crate::send::{ComposePolicy, ComposeRequest};
use crate::send_journal::{snapshot_digest, SendJournal};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_INDEX: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryError {
    Unavailable,
    Invalid,
    Changed,
    Capacity,
    ClockRollback,
    Unconfirmed,
}
#[derive(PartialEq, Eq)]
pub(crate) enum RecoveryRead {
    Available(RecoverySnapshot),
    Missing,
    Expired,
    Unconfirmed,
}
#[derive(PartialEq, Eq)]
pub(crate) struct RecoverySnapshot {
    pub request: Box<ComposeRequest>,
    pub created_at: u64,
    pub expires_at: u64,
}
#[derive(Clone)]
pub(crate) struct SendRecovery {
    root: PathBuf,
    index: PrivateAccountFile,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u8,
    high_water: u64,
    entries: Vec<Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    intent: String,
    id: String,
    digest: String,
    created: u64,
    expires: u64,
    confirmed: bool,
    #[serde(default, skip_serializing_if = "is_default_protection")]
    protection: crate::send::ProtectionIntent,
}
fn is_default_protection(value: &crate::send::ProtectionIntent) -> bool {
    *value == crate::send::ProtectionIntent::default()
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturePoint {
    BeforeIndex,
    AfterIndex,
    AfterSnapshot,
    AfterConfirmation,
}
struct CaptureInput<'a> {
    account: &'a str,
    intent: &'a str,
    request: &'a ComposeRequest,
    now: u64,
}
impl SendRecovery {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            index: PrivateAccountFile::new(root.join("index"), "send-recovery-v1", MAX_INDEX),
            root,
        }
    }
    fn store(&self, policy: DraftPolicy) -> FileDraftStore {
        FileDraftStore::new(self.root.join("snapshots"), policy)
    }
    fn cleanup_index_temps(&self, account: &str) -> Result<(), RecoveryError> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"send-recovery-v1\0");
        hash.update(account.as_bytes());
        let prefix = format!(".{:x}-", hash.finalize());
        let directory = self.root.join("index");
        for (count, entry) in std::fs::read_dir(&directory)
            .map_err(|_| RecoveryError::Unavailable)?
            .enumerate()
        {
            if count > 16384 {
                return Err(RecoveryError::Unavailable);
            }
            let entry = entry.map_err(|_| RecoveryError::Unavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(rest) = name
                .strip_prefix(&prefix)
                .and_then(|v| v.strip_suffix(".tmp"))
            {
                let parts: Vec<_> = rest.split('-').collect();
                if parts.len() != 2
                    || !parts
                        .iter()
                        .all(|part| part.parse::<u64>().is_ok_and(|n| n.to_string() == *part))
                {
                    return Err(RecoveryError::Invalid);
                }
                crate::private_account_file::read_record(&entry.path(), MAX_INDEX)
                    .map_err(|_| RecoveryError::Unavailable)?
                    .ok_or(RecoveryError::Unavailable)?;
                std::fs::remove_file(entry.path()).map_err(|_| RecoveryError::Unavailable)?;
            }
        }
        std::fs::File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| RecoveryError::Unavailable)
    }
    fn decode(bytes: Option<Vec<u8>>) -> Result<Index, RecoveryError> {
        let Some(bytes) = bytes else {
            return Ok(Index {
                version: 1,
                ..Index::default()
            });
        };
        let value: Index = serde_json::from_slice(&bytes).map_err(|_| RecoveryError::Invalid)?;
        if value.version != 1 || value.entries.len() > MAX_ENTRIES {
            return Err(RecoveryError::Invalid);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for entry in &value.entries {
            if crate::send_journal::intent_time(&entry.intent).is_err()
                || crate::draft::validate_draft_id(&entry.id).is_err()
                || entry.digest.len() != 64
                || !entry
                    .digest
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || entry.created == 0
                || entry.expires.checked_sub(entry.created)
                    != Some(crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS)
                || entry.created > value.high_water
                || !seen.insert(&entry.intent)
                || !ids.insert(&entry.id)
            {
                return Err(RecoveryError::Invalid);
            }
        }
        Ok(value)
    }
    fn write(
        lock: &crate::private_account_file::LockedAccountFile,
        index: &Index,
    ) -> Result<(), RecoveryError> {
        let bytes = serde_json::to_vec(index).map_err(|_| RecoveryError::Invalid)?;
        lock.write(&bytes).map_err(|_| RecoveryError::Unconfirmed)
    }
    /// Verified live metadata usage; caller holds the journal account guard.
    /// No message reconstruction or body fetch beyond the store's existing summary listing.
    pub(crate) fn storage_usage(
        &self,
        account: &str,
        now: u64,
    ) -> Result<(usize, u64), RecoveryError> {
        let lock = self
            .index
            .lock(account)
            .map_err(|_| RecoveryError::Unavailable)?;
        let index = Self::decode(lock.read().map_err(|_| RecoveryError::Unavailable)?)?;
        if now < index.high_water {
            return Err(RecoveryError::ClockRollback);
        }
        let rows = self
            .store(DraftPolicy::default())
            .list(account, now)
            .map_err(|_| RecoveryError::Unavailable)?;
        for row in &rows {
            if !index.entries.iter().any(|entry| {
                entry.id == row.draft_id
                    && entry.created == row.created_at
                    && entry.expires == row.expires_at
                    && row.revision == 1
            }) {
                return Err(RecoveryError::Invalid);
            }
        }
        if index.entries.iter().any(|entry| {
            entry.confirmed
                && entry.expires > now
                && !rows.iter().any(|row| row.draft_id == entry.id)
        }) {
            return Err(RecoveryError::Unavailable);
        }
        let bytes = rows
            .iter()
            .try_fold(0_u64, |sum, row| sum.checked_add(row.storage_bytes))
            .ok_or(RecoveryError::Capacity)?;
        Ok((rows.len(), bytes))
    }

    /// These records count against the same count and logical-byte allowance as drafts.
    pub(crate) fn draft_policy(
        &self,
        account: &str,
        now: u64,
    ) -> Result<DraftPolicy, RecoveryError> {
        let summaries = self
            .store(DraftPolicy::default())
            .list(account, now)
            .map_err(|_| RecoveryError::Unavailable)?;
        let used = summaries
            .iter()
            .try_fold(0_u64, |sum, row| sum.checked_add(row.storage_bytes))
            .ok_or(RecoveryError::Capacity)?;
        let mut policy = DraftPolicy::default();
        policy.max_drafts_per_user = policy
            .max_drafts_per_user
            .checked_sub(summaries.len())
            .ok_or(RecoveryError::Capacity)?;
        policy.storage_max_bytes = policy
            .storage_max_bytes
            .checked_sub(used)
            .ok_or(RecoveryError::Capacity)?;
        Ok(policy)
    }
    pub(crate) fn capture(
        &self,
        journal: &SendJournal,
        normal: &FileDraftStore,
        account: &str,
        intent: &str,
        request: &ComposeRequest,
        now: u64,
    ) -> Result<ComposeRequest, RecoveryError> {
        self.capture_with(
            journal,
            normal,
            CaptureInput {
                account,
                intent,
                request,
                now,
            },
            |_| Ok(()),
        )
    }
    fn capture_with(
        &self,
        journal: &SendJournal,
        normal: &FileDraftStore,
        input: CaptureInput<'_>,
        hook: impl Fn(CapturePoint) -> Result<(), RecoveryError>,
    ) -> Result<ComposeRequest, RecoveryError> {
        let CaptureInput {
            account,
            intent,
            request,
            now,
        } = input;
        if journal
            .receipt(account, intent, now)
            .map_err(|_| RecoveryError::Unavailable)?
            .is_none()
        {
            return Err(RecoveryError::Invalid);
        }
        let lock = self
            .index
            .lock(account)
            .map_err(|_| RecoveryError::Unavailable)?;
        self.cleanup_index_temps(account)?;
        let mut index = Self::decode(lock.read().map_err(|_| RecoveryError::Unavailable)?)?;
        if now < index.high_water {
            return Err(RecoveryError::ClockRollback);
        }
        let digest = snapshot_digest(account, request);
        if let Some(entry) = index.entries.iter().find(|e| e.intent == intent) {
            if entry.digest != digest {
                return Err(RecoveryError::Changed);
            }
            return match self.read_entry(account, entry, now)? {
                RecoveryRead::Available(value) if *value.request == *request => Ok(*value.request),
                _ => Err(RecoveryError::Unconfirmed),
            };
        }
        index
            .entries
            .retain(|entry| !entry.confirmed || entry.expires > now);
        if index.entries.len() >= MAX_ENTRIES {
            return Err(RecoveryError::Capacity);
        }
        let normal_rows = normal
            .list(account, now)
            .map_err(|_| RecoveryError::Unavailable)?;
        let used = normal_rows
            .iter()
            .try_fold(0_u64, |sum, row| sum.checked_add(row.storage_bytes))
            .ok_or(RecoveryError::Capacity)?;
        let mut policy = DraftPolicy::default();
        policy.max_drafts_per_user = policy
            .max_drafts_per_user
            .checked_sub(normal_rows.len())
            .ok_or(RecoveryError::Capacity)?;
        policy.storage_max_bytes = policy
            .storage_max_bytes
            .checked_sub(used)
            .ok_or(RecoveryError::Capacity)?;
        let id = crate::draft::generate_draft_id().map_err(|_| RecoveryError::Unavailable)?;
        let mut record = DraftRecord::new(
            policy,
            DraftRecordInput {
                draft_id: id.clone(),
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
        .map_err(|_| RecoveryError::Invalid)?;
        record.request.sender_identity = request.sender_identity.clone();
        record.request.body_format = request.body_format;
        record.request.reply_thread = request.reply_thread.clone();
        record.request.protection = request.protection;
        if restore(&record)? != *request {
            return Err(RecoveryError::Invalid);
        }
        let existing = self
            .store(DraftPolicy::default())
            .list(account, now)
            .map_err(|_| RecoveryError::Unavailable)?;
        let total = existing
            .iter()
            .try_fold(record.summary().storage_bytes, |sum, row| {
                sum.checked_add(row.storage_bytes)
            })
            .ok_or(RecoveryError::Capacity)?;
        if existing.len() >= policy.max_drafts_per_user || total > policy.storage_max_bytes {
            return Err(RecoveryError::Capacity);
        }

        index.high_water = now;
        index.entries.push(Entry {
            intent: intent.into(),
            id,
            digest,
            created: now,
            expires: record.expires_at,
            confirmed: false,
            protection: request.protection,
        });
        hook(CapturePoint::BeforeIndex)?;
        Self::write(&lock, &index)?;
        hook(CapturePoint::AfterIndex)?;
        self.store(policy)
            .save(&record, now)
            .map_err(|_| RecoveryError::Unconfirmed)?;
        hook(CapturePoint::AfterSnapshot)?;
        let entry = index.entries.last_mut().ok_or(RecoveryError::Invalid)?;
        let saved = self
            .store(DraftPolicy::default())
            .read_immutable(account, &entry.id)
            .map_err(|_| RecoveryError::Unavailable)?
            .ok_or(RecoveryError::Unconfirmed)?;
        let prepared = restore(&saved)?;
        if prepared.protection != entry.protection {
            return Err(RecoveryError::Changed);
        }
        if prepared != *request || snapshot_digest(account, &prepared) != entry.digest {
            return Err(RecoveryError::Changed);
        }
        entry.confirmed = true;
        Self::write(&lock, &index)?;
        hook(CapturePoint::AfterConfirmation)?;
        // Confirm the final index and immutable bytes through fresh descriptors.
        let reopened = Self::decode(
            self.index
                .read(account)
                .map_err(|_| RecoveryError::Unavailable)?,
        )?;
        let entry = reopened
            .entries
            .iter()
            .find(|e| e.intent == intent)
            .ok_or(RecoveryError::Unconfirmed)?;
        match self.read_entry(account, entry, now)? {
            RecoveryRead::Available(value) if *value.request == *request => Ok(*value.request),
            _ => Err(RecoveryError::Unconfirmed),
        }
    }
    fn read_entry(
        &self,
        account: &str,
        entry: &Entry,
        now: u64,
    ) -> Result<RecoveryRead, RecoveryError> {
        let record = self
            .store(DraftPolicy::default())
            .read_immutable(account, &entry.id)
            .map_err(|_| RecoveryError::Unavailable)?;
        if now >= entry.expires {
            return Ok(RecoveryRead::Expired);
        }
        if !entry.confirmed {
            return Ok(RecoveryRead::Unconfirmed);
        }
        let Some(record) = record else {
            return Ok(RecoveryRead::Missing);
        };
        if record.created_at != entry.created
            || record.expires_at != entry.expires
            || record.revision != Some(1)
            || record.source_attachments.is_some()
        {
            return Err(RecoveryError::Invalid);
        }
        let request = restore(&record)?;
        if request.protection != entry.protection {
            return Err(RecoveryError::Changed);
        }
        if snapshot_digest(account, &request) != entry.digest {
            return Err(RecoveryError::Changed);
        }
        Ok(RecoveryRead::Available(RecoverySnapshot {
            request: Box::new(request),
            created_at: entry.created,
            expires_at: entry.expires,
        }))
    }
    /// Authenticated account and exact private index binding authorize read-only recovery.
    /// Missing/pruned/corrupt outcome receipts do not grant or remove snapshot authority.
    pub(crate) fn lookup(
        &self,
        _journal: &SendJournal,
        account: &str,
        intent: &str,
        now: u64,
    ) -> Result<RecoveryRead, RecoveryError> {
        crate::identity::MailboxIdentity::parse(account).map_err(|_| RecoveryError::Invalid)?;
        crate::send_journal::intent_time(intent).map_err(|_| RecoveryError::Invalid)?;
        let lock = self
            .index
            .lock(account)
            .map_err(|_| RecoveryError::Unavailable)?;
        self.cleanup_index_temps(account)?;
        let mut index = Self::decode(lock.read().map_err(|_| RecoveryError::Unavailable)?)?;
        if now < index.high_water {
            return Err(RecoveryError::ClockRollback);
        }
        index.high_water = now;
        Self::write(&lock, &index)?;
        match index.entries.iter().find(|entry| entry.intent == intent) {
            Some(entry) => self.read_entry(account, entry, now),
            None => Ok(RecoveryRead::Missing),
        }
    }
}
fn restore(record: &DraftRecord) -> Result<ComposeRequest, RecoveryError> {
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
    .and_then(|value| value.with_body_format(content.body_format))
    .map_err(|_| RecoveryError::Invalid)?;
    request.reply_thread = content.reply_thread.clone();
    request.sender_identity = content.sender_identity.clone();
    request.protection = content.protection;
    Ok(request)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::send_journal::AttemptOutcome;
    use std::sync::atomic::{AtomicU64, Ordering};
    const ACCOUNT: &str = "alice@example.test";
    struct Fixture {
        root: PathBuf,
        journal: SendJournal,
        recovery: SendRecovery,
        normal: FileDraftStore,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "osmap-send-recovery-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            Self {
                journal: SendJournal::new(root.join("journal")),
                recovery: SendRecovery::new(root.join("recovery")),
                normal: FileDraftStore::new(root.join("drafts"), DraftPolicy::default()),
                root,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn request() -> ComposeRequest {
        let files = vec![crate::send::UploadedAttachment::new(
            ComposePolicy::default(),
            "resolved.bin",
            "application/octet-stream",
            vec![0, 255, 10, 99],
        )
        .unwrap()];
        let mut r = ComposeRequest::new_with_routing(
            ComposePolicy::default(),
            "bob@example.test",
            "copy@example.test",
            "hidden@example.test",
            "Exact 🦊",
            "**Saved** source\n",
            files,
        )
        .unwrap()
        .with_body_format(crate::compose_format::BodyFormat::Formatted)
        .unwrap();
        r.reply_thread = Some(
            crate::reply_thread::ReplyThread::from_original(
                "Message-ID: <parent@example.test>\nReferences: <root@example.test>\n",
            )
            .unwrap(),
        );
        r
    }
    fn dispatch(
        f: &Fixture,
        token: &str,
        r: &ComposeRequest,
        point: Option<CapturePoint>,
        calls: &std::cell::Cell<usize>,
    ) {
        f.journal
            .execute_prepared(
                ACCOUNT,
                token,
                100,
                |_| Ok::<_, ()>(r.clone()),
                |prepared| match f.recovery.capture_with(
                    &f.journal,
                    &f.normal,
                    CaptureInput {
                        account: ACCOUNT,
                        intent: token,
                        request: prepared,
                        now: 100,
                    },
                    |at| {
                        if Some(at) == point {
                            Err(RecoveryError::Unconfirmed)
                        } else {
                            Ok(())
                        }
                    },
                ) {
                    Ok(reopened) => {
                        assert_eq!(reopened, *r);
                        calls.set(calls.get() + 1);
                        AttemptOutcome::Accepted {
                            sent_copy_stored: false,
                        }
                    }
                    Err(_) => AttemptOutcome::Unconfirmed,
                },
            )
            .unwrap();
    }
    #[test]
    fn exact_reopen_and_replay_keep_every_field_and_never_edit_normal_drafts() {
        let f = Fixture::new();
        let token = crate::send_journal::mint_intent(100).unwrap();
        let r = request();
        let calls = std::cell::Cell::new(0);
        dispatch(&f, &token, &r, None, &calls);
        dispatch(&f, &token, &r, None, &calls);
        assert_eq!(calls.get(), 1);
        let reopened = SendRecovery::new(f.root.join("recovery"));
        assert!(
            matches!(reopened.lookup(&f.journal,ACCOUNT,&token,101).unwrap(),RecoveryRead::Available(value) if *value.request==r)
        );
        assert!(f.normal.list(ACCOUNT, 101).unwrap().is_empty());
        assert!(matches!(
            reopened
                .lookup(&f.journal, "foreign@example.test", &token, 101)
                .unwrap(),
            RecoveryRead::Missing
        ));
        let mut changed = r.clone();
        changed.attachments[0].body[0] = 1;
        assert_eq!(
            f.recovery
                .capture(&f.journal, &f.normal, ACCOUNT, &token, &changed, 101),
            Err(RecoveryError::Changed)
        );
    }
    #[test]
    fn protected_attempt_recovery_preserves_intent_and_refuses_changed_replay() {
        let f = Fixture::new();
        let token = crate::send_journal::mint_intent(100).unwrap();
        let mut request = request();
        request.protection = crate::send::ProtectionIntent {
            sign: true,
            encrypt: true,
            encrypt_to_self: true,
            binding_revision: Some(7),
        };
        let calls = std::cell::Cell::new(0);
        dispatch(&f, &token, &request, None, &calls);
        dispatch(&f, &token, &request, None, &calls);
        assert_eq!(calls.get(), 1);
        let RecoveryRead::Available(snapshot) =
            f.recovery.lookup(&f.journal, ACCOUNT, &token, 101).unwrap()
        else {
            panic!("protected immutable snapshot")
        };
        assert_eq!(snapshot.request.protection, request.protection);
        for changed in [
            {
                let mut value = request.clone();
                value.protection.sign = false;
                value
            },
            {
                let mut value = request.clone();
                value.protection.encrypt = false;
                value
            },
            {
                let mut value = request.clone();
                value.protection.encrypt_to_self = false;
                value
            },
            {
                let mut value = request.clone();
                value.protection.binding_revision = Some(8);
                value
            },
        ] {
            assert_ne!(
                snapshot_digest(ACCOUNT, &request),
                snapshot_digest(ACCOUNT, &changed)
            );
            assert_eq!(
                f.journal.execute_prepared(
                    ACCOUNT,
                    &token,
                    101,
                    |_| Ok::<_, ()>(changed),
                    |_| panic!("changed intent must never redispatch")
                ),
                Err(crate::send_journal::JournalError::ChangedSnapshot)
            );
        }
    }
    #[test]
    fn publication_faults_and_interrupted_reservation_never_invoke_backend() {
        for point in [
            CapturePoint::BeforeIndex,
            CapturePoint::AfterIndex,
            CapturePoint::AfterSnapshot,
            CapturePoint::AfterConfirmation,
        ] {
            let f = Fixture::new();
            let token = crate::send_journal::mint_intent(100).unwrap();
            let calls = std::cell::Cell::new(0);
            dispatch(&f, &token, &request(), Some(point), &calls);
            dispatch(&f, &token, &request(), None, &calls);
            assert_eq!(calls.get(), 0);
            let result = f.recovery.lookup(&f.journal, ACCOUNT, &token, 101).unwrap();
            assert!(match point {
                CapturePoint::BeforeIndex => matches!(result, RecoveryRead::Missing),
                CapturePoint::AfterConfirmation => matches!(result, RecoveryRead::Available(_)),
                _ => matches!(result, RecoveryRead::Unconfirmed),
            });
        }
    }
    #[test]
    fn expiry_is_distinct_and_clock_rollback_cannot_restore_expired_bytes() {
        let f = Fixture::new();
        let token = crate::send_journal::mint_intent(100).unwrap();
        let calls = std::cell::Cell::new(0);
        dispatch(&f, &token, &request(), None, &calls);
        let later = 100 + crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS;
        assert!(matches!(
            f.recovery
                .lookup(&f.journal, ACCOUNT, &token, later)
                .unwrap(),
            RecoveryRead::Expired
        ));
        assert!(matches!(
            f.recovery.lookup(&f.journal, ACCOUNT, &token, 101),
            Err(RecoveryError::ClockRollback)
        ));
    }
    #[test]
    fn near_expiry_intent_snapshot_remains_readable_without_its_receipt() {
        let f = Fixture::new();
        let token = crate::send_journal::mint_intent(1).unwrap();
        let now = crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS;
        let r = request();
        f.journal
            .execute_prepared(
                ACCOUNT,
                &token,
                now,
                |_| Ok::<_, ()>(r.clone()),
                |prepared| {
                    f.recovery
                        .capture(&f.journal, &f.normal, ACCOUNT, &token, prepared, now)
                        .unwrap();
                    AttemptOutcome::Accepted {
                        sent_copy_stored: true,
                    }
                },
            )
            .unwrap();
        std::fs::remove_dir_all(f.root.join("journal")).unwrap();
        assert!(
            matches!(f.recovery.lookup(&f.journal,ACCOUNT,&token,now+100).unwrap(),RecoveryRead::Available(value) if *value.request==r)
        );
        assert!(matches!(
            f.recovery
                .lookup(
                    &f.journal,
                    ACCOUNT,
                    &token,
                    now + crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS
                )
                .unwrap(),
            RecoveryRead::Expired
        ));
    }
    #[test]
    fn competing_attempts_publish_one_snapshot_and_invoke_one_backend() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        };
        let f = Fixture::new();
        let token = crate::send_journal::mint_intent(100).unwrap();
        let barrier = Barrier::new(2);
        let calls = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    barrier.wait();
                    let _ = f.journal.execute_prepared(
                        ACCOUNT,
                        &token,
                        100,
                        |_| Ok::<_, ()>(request()),
                        |r| {
                            f.recovery
                                .capture(&f.journal, &f.normal, ACCOUNT, &token, r, 100)
                                .unwrap();
                            calls.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(25));
                            AttemptOutcome::Accepted {
                                sent_copy_stored: true,
                            }
                        },
                    );
                });
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.recovery
                .store(DraftPolicy::default())
                .list(ACCOUNT, 100)
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn expired_confirmed_index_capacity_is_reclaimed() {
        let f = Fixture::new();
        let now = crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS + 2;
        let entries = (1..=MAX_ENTRIES)
            .map(|n| Entry {
                intent: format!("1.{n:032x}"),
                id: format!("{n:032x}"),
                digest: "a".repeat(64),
                created: 1,
                expires: 1 + crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS,
                confirmed: true,
                protection: crate::send::ProtectionIntent::default(),
            })
            .collect();
        {
            let lock = f.recovery.index.lock(ACCOUNT).unwrap();
            SendRecovery::write(
                &lock,
                &Index {
                    version: 1,
                    high_water: 1,
                    entries,
                },
            )
            .unwrap();
        }
        let token = crate::send_journal::mint_intent(now).unwrap();
        f.journal
            .execute_prepared(
                ACCOUNT,
                &token,
                now,
                |_| Ok::<_, ()>(request()),
                |r| {
                    f.recovery
                        .capture(&f.journal, &f.normal, ACCOUNT, &token, r, now)
                        .unwrap();
                    AttemptOutcome::Accepted {
                        sent_copy_stored: true,
                    }
                },
            )
            .unwrap();
        assert_eq!(
            SendRecovery::decode(f.recovery.index.read(ACCOUNT).unwrap())
                .unwrap()
                .entries
                .len(),
            1
        );
    }
    #[test]
    fn recovery_and_both_draft_locations_share_the_same_account_quota() {
        let f = Fixture::new();
        f.normal
            .qualify_location(ACCOUNT, crate::draft_location::Location::Working)
            .unwrap();
        let token = crate::send_journal::mint_intent(100).unwrap();
        dispatch(&f, &token, &request(), None, &std::cell::Cell::new(0));
        let policy = f.recovery.draft_policy(ACCOUNT, 100).unwrap();
        for index in 0..49 {
            let record = DraftRecord::new(
                policy,
                DraftRecordInput {
                    draft_id: format!("{:032x}", index + 1),
                    canonical_username: ACCOUNT.into(),
                    now: 100,
                    recipients_text: "bob@example.test".into(),
                    cc_text: String::new(),
                    bcc_text: String::new(),
                    subject: "Public quota fixture".into(),
                    body: "Public body".into(),
                    attachments: vec![],
                    source_attachments: None,
                },
            )
            .unwrap();
            let location = if index % 2 == 0 {
                crate::draft_location::Location::Default
            } else {
                crate::draft_location::Location::Working
            };
            FileDraftStore::new(f.root.join("drafts"), policy)
                .with_new_location(location)
                .save(&record, 100)
                .unwrap();
        }
        let record = DraftRecord::new(
            policy,
            DraftRecordInput {
                draft_id: format!("{:032x}", 100),
                canonical_username: ACCOUNT.into(),
                now: 100,
                recipients_text: "bob@example.test".into(),
                cc_text: String::new(),
                bcc_text: String::new(),
                subject: "Public excess fixture".into(),
                body: "Public body".into(),
                attachments: vec![],
                source_attachments: None,
            },
        )
        .unwrap();
        for location in [
            crate::draft_location::Location::Default,
            crate::draft_location::Location::Working,
        ] {
            assert!(FileDraftStore::new(f.root.join("drafts"), policy)
                .with_new_location(location)
                .save(&record, 100)
                .unwrap_err()
                .reason
                .contains("quota"));
        }
        assert_eq!(f.normal.list(ACCOUNT, 100).unwrap().len(), 49);
        assert_eq!(f.recovery.storage_usage(ACCOUNT, 100).unwrap().0, 1);
        assert!(f
            .normal
            .load(ACCOUNT, &record.draft_id, 100)
            .unwrap()
            .is_none());
    }
    #[test]
    fn recovery_usage_reduces_ordinary_draft_budget() {
        let f = Fixture::new();
        let token = crate::send_journal::mint_intent(100).unwrap();
        dispatch(&f, &token, &request(), None, &std::cell::Cell::new(0));
        let policy = f.recovery.draft_policy(ACCOUNT, 100).unwrap();
        let guard = f.journal.account_guard(ACCOUNT, 100).unwrap();
        let (count, bytes) = f.recovery.storage_usage(ACCOUNT, 100).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            bytes,
            crate::draft::DEFAULT_DRAFT_STORAGE_MAX_BYTES - policy.storage_max_bytes
        );
        drop(guard);
        assert_eq!(policy.max_drafts_per_user, 49);
        assert!(policy.storage_max_bytes < crate::draft::DEFAULT_DRAFT_STORAGE_MAX_BYTES);
    }
}
#[cfg(test)]
mod correction_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn index_is_strict_and_symlinks_fail_closed() {
        for bytes in [
            br#"{"version":2,"high_water":0,"entries":[]}"#.as_slice(),
            br#"{"version":1,"version":1,"high_water":0,"entries":[]}"#,
            br#"{"version":1,"high_water":0,"entries":[],"extra":true}"#,
        ] {
            assert!(SendRecovery::decode(Some(bytes.to_vec())).is_err());
        }
        let root = std::env::temp_dir().join(format!(
            "osmap-recovery-links-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o700)).unwrap();
        let recovery = SendRecovery::new(root.join("recovery"));
        std::fs::create_dir_all(root.join("recovery")).unwrap();
        symlink(&outside, root.join("recovery/index")).unwrap();
        let journal = SendJournal::new(root.join("journal"));
        let token = crate::send_journal::mint_intent(100).unwrap();
        assert!(recovery
            .lookup(&journal, "alice@example.test", &token, 100)
            .is_err());
        assert!(std::fs::read_dir(outside).unwrap().next().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn orphan_blobs_without_manifest_are_removed_before_quota_allocation() {
        let root = std::env::temp_dir().join(format!(
            "osmap-recovery-orphan-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let recovery = SendRecovery::new(root.clone());
        let store = recovery.store(DraftPolicy::default());
        let dir = store.draft_dir_for_username_and_id(
            "alice@example.test",
            "11111111111111111111111111111111",
        );
        std::fs::create_dir_all(&dir).unwrap();
        for path in [
            &root,
            &root.join("snapshots"),
            &store.owner_dir_for_username("alice@example.test"),
            &dir,
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let blob = dir.join(format!("attachment-{}.body", "a".repeat(64)));
        std::fs::write(&blob, b"unpublished").unwrap();
        std::fs::set_permissions(blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            recovery
                .draft_policy("alice@example.test", 100)
                .unwrap()
                .max_drafts_per_user,
            50
        );
        assert!(!dir.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
