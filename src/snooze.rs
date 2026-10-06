//! Private hide-until metadata only. No mail moves, deletion, or dispatch.
//! Callers must authenticate and obtain current native summaries before set/project.
use crate::{
    mailbox::{MailboxEntry, MailboxListingPolicy, MessageSummary},
    private_account_file::PrivateAccountFile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

pub const MAX_MARKERS: usize = 100;
pub const MAX_DURATION: u64 = 30 * 86400;
const MAX_BYTES: usize = 512 * 1024;
const NAMESPACE: &str = "osmap-snooze-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnoozeError {
    Invalid,
    Corrupt,
    Stale,
    Missing,
    Capacity,
    ClockRollback,
    Unavailable,
    Unconfirmed,
}

/// Construction validates identity, not authorization. GUIDs are native identities,
/// not a claim that the backend exposes UIDVALIDITY.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageIdentity {
    account: String,
    folder: String,
    uid: u64,
    mailbox_guid: String,
    message_guid: String,
}

impl MessageIdentity {
    pub fn from_summary(
        account: &str,
        returned_account: &str,
        folder: &str,
        row: &MessageSummary,
    ) -> Result<Self, SnoozeError> {
        if account != returned_account || folder != row.mailbox_name {
            return Err(SnoozeError::Invalid);
        }
        let version = &row.metadata.as_ref().ok_or(SnoozeError::Invalid)?.version;
        let value = Self {
            account: account.into(),
            folder: folder.into(),
            uid: row.uid,
            mailbox_guid: version.mailbox_guid.clone(),
            message_guid: version.message_guid.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), SnoozeError> {
        account_valid(&self.account)?;
        if self.uid == 0
            || self.uid > u32::MAX as u64
            || MailboxEntry::new(MailboxListingPolicy::default(), &self.folder).is_err()
            || !crate::message_metadata::MessageVersion::new(
                self.mailbox_guid.clone(),
                self.message_guid.clone(),
            )
            .is_ok_and(|v| v.mailbox_guid == self.mailbox_guid)
        {
            return Err(SnoozeError::Invalid);
        }
        Ok(())
    }
    pub fn folder(&self) -> &str {
        &self.folder
    }
    pub fn uid(&self) -> u64 {
        self.uid
    }
    pub fn mailbox_guid(&self) -> &str {
        &self.mailbox_guid
    }
    pub fn message_guid(&self) -> &str {
        &self.message_guid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnoozeMarker {
    identity: MessageIdentity,
    created_at: u64,
    until: u64,
}
impl SnoozeMarker {
    pub fn identity(&self) -> &MessageIdentity {
        &self.identity
    }
    pub fn until(&self) -> u64 {
        self.until
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnoozeRecord {
    version: u8,
    account: String,
    revision: u64,
    high_water: u64,
    markers: Vec<SnoozeMarker>,
}
impl SnoozeRecord {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn markers(&self) -> &[SnoozeMarker] {
        &self.markers
    }
    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Self, SnoozeError> {
        let Some(bytes) = bytes else {
            return Ok(Self {
                version: 1,
                account: account.into(),
                revision: 0,
                high_water: 0,
                markers: vec![],
            });
        };
        let r: Self = serde_json::from_slice(&bytes).map_err(|_| SnoozeError::Corrupt)?;
        if r.version != 1
            || r.account != account
            || r.revision == 0
            || r.high_water == 0
            || r.markers.len() > MAX_MARKERS
        {
            return Err(SnoozeError::Corrupt);
        }
        let mut slots = BTreeSet::new();
        for m in &r.markers {
            if m.identity.validate().is_err()
                || m.identity.account != account
                || m.created_at == 0
                || m.created_at > r.high_water
                || validate_until(m.until, m.created_at).is_err()
                || !slots.insert((&m.identity.folder, m.identity.uid))
            {
                return Err(SnoozeError::Corrupt);
            }
        }
        Ok(r)
    }
}

/// Canonical UTC Unix seconds only; local-time/DST interpretation belongs outside this core.
pub fn parse_until(value: &str, now: u64) -> Result<u64, SnoozeError> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|v| v.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(SnoozeError::Invalid);
    }
    let until = value.parse().map_err(|_| SnoozeError::Invalid)?;
    validate_until(until, now)?;
    Ok(until)
}
/// Exact four-digit UTC civil date and minute. Never interprets browser-local time.
pub fn parse_utc(value: &str, now: u64) -> Result<u64, SnoozeError> {
    let b = value.as_bytes();
    if !value.is_ascii()
        || b.len() != 16
        || b[10] != b'T'
        || b[13] != b':'
        || !b[11..13].iter().chain(&b[14..16]).all(u8::is_ascii_digit)
    {
        return Err(SnoozeError::Invalid);
    }
    let day = crate::mailbox::parse_calendar_date(&value[..10]).ok_or(SnoozeError::Invalid)?;
    let hour: i64 = value[11..13].parse().map_err(|_| SnoozeError::Invalid)?;
    let minute: i64 = value[14..].parse().map_err(|_| SnoozeError::Invalid)?;
    if hour > 23 || minute > 59 {
        return Err(SnoozeError::Invalid);
    }
    let until = u64::try_from(day + hour * 3600 + minute * 60).map_err(|_| SnoozeError::Invalid)?;
    validate_until(until, now)?;
    Ok(until)
}
fn validate_until(until: u64, now: u64) -> Result<(), SnoozeError> {
    if now == 0 || until <= now || until.checked_sub(now).is_none_or(|d| d > MAX_DURATION) {
        return Err(SnoozeError::Invalid);
    }
    Ok(())
}
fn account_valid(account: &str) -> Result<(), SnoozeError> {
    crate::identity::CanonicalUsername::parse(account)
        .map(|_| ())
        .map_err(|_| SnoozeError::Invalid)
}

/// On failure hidden is always empty: show all loaded messages and an unavailable notice.
#[derive(Debug, Clone)]
pub struct SnoozeProjection {
    pub hidden: Vec<MessageIdentity>,
    pub revision: Option<u64>,
    pub unavailable: Option<SnoozeError>,
}

#[derive(Debug, Clone)]
pub struct SnoozeStore {
    file: PrivateAccountFile,
}
impl SnoozeStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), NAMESPACE, MAX_BYTES),
        }
    }
    fn lock(
        &self,
        account: &str,
    ) -> Result<crate::private_account_file::LockedAccountFile, SnoozeError> {
        account_valid(account)?;
        let start = Instant::now();
        loop {
            match self.file.lock(account) {
                Ok(lock) => return Ok(lock),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_millis(500) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(SnoozeError::Unavailable),
            }
        }
    }
    fn transact(
        &self,
        account: &str,
        now: u64,
        revision: Option<u64>,
        action: impl FnOnce(&mut SnoozeRecord) -> Result<(), SnoozeError>,
    ) -> Result<SnoozeRecord, SnoozeError> {
        if now == 0 {
            return Err(SnoozeError::Invalid);
        }
        let lock = self.lock(account)?;
        let mut r =
            SnoozeRecord::decode(account, lock.read().map_err(|_| SnoozeError::Unavailable)?)?;
        if now < r.high_water {
            return Err(SnoozeError::ClockRollback);
        }
        if revision.is_some_and(|v| v != r.revision) {
            return Err(SnoozeError::Stale);
        }
        let before = r.markers.clone();
        r.markers.retain(|m| m.until > now);
        action(&mut r)?;
        let changed = r.markers != before;
        if changed {
            r.revision = r.revision.checked_add(1).ok_or(SnoozeError::Capacity)?;
        }
        if changed || (r.revision > 0 && now > r.high_water) {
            r.high_water = now;
            let bytes = serde_json::to_vec(&r).map_err(|_| SnoozeError::Corrupt)?;
            lock.write(&bytes).map_err(|_| SnoozeError::Unconfirmed)?;
        }
        Ok(r)
    }
    /// Only after authoritative folder-GUID continuity. Keeps all marker times intact.
    pub(crate) fn reconcile_folder_rename(
        &self,
        request: &crate::folder_rename::RenameFolderRequest,
    ) -> Result<(), SnoozeError> {
        request.validate().map_err(|_| SnoozeError::Invalid)?;
        let account = request.account();
        let lock = self
            .file
            .lock(account)
            .map_err(|_| SnoozeError::Unavailable)?;
        let mut record =
            SnoozeRecord::decode(account, lock.read().map_err(|_| SnoozeError::Unavailable)?)?;
        let mut changed = false;
        for marker in &mut record.markers {
            if marker.identity.folder == request.source()
                && marker.identity.mailbox_guid == request.source_guid()
            {
                marker.identity.folder = request.destination();
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(SnoozeError::Capacity)?;
        let bytes = serde_json::to_vec(&record).map_err(|_| SnoozeError::Corrupt)?;
        SnoozeRecord::decode(account, Some(bytes.clone()))?;
        lock.write(&bytes).map_err(|_| SnoozeError::Unconfirmed)
    }
    pub fn load(&self, account: &str, now: u64) -> Result<SnoozeRecord, SnoozeError> {
        self.transact(account, now, None, |_| Ok(()))
    }
    /// Identity must come from a freshly authorized native response, never browser assertions.
    pub fn set(
        &self,
        account: &str,
        identity: &MessageIdentity,
        revision: u64,
        until: u64,
        now: u64,
    ) -> Result<SnoozeRecord, SnoozeError> {
        identity.validate()?;
        if account != identity.account {
            return Err(SnoozeError::Invalid);
        }
        validate_until(until, now)?;
        self.transact(account, now, Some(revision), |r| {
            r.markers.retain(|m| {
                !(m.identity.folder == identity.folder && m.identity.uid == identity.uid)
            });
            if r.markers.len() >= MAX_MARKERS {
                return Err(SnoozeError::Capacity);
            }
            r.markers.push(SnoozeMarker {
                identity: identity.clone(),
                created_at: now,
                until,
            });
            Ok(())
        })
    }
    pub fn cancel(
        &self,
        account: &str,
        identity: &MessageIdentity,
        revision: u64,
        now: u64,
    ) -> Result<SnoozeRecord, SnoozeError> {
        if account != identity.account {
            return Err(SnoozeError::Invalid);
        }
        self.transact(account, now, Some(revision), |r| {
            let index = r
                .markers
                .iter()
                .position(|m| &m.identity == identity)
                .ok_or(SnoozeError::Missing)?;
            r.markers.remove(index);
            Ok(())
        })
    }
    pub fn project(
        &self,
        account: &str,
        returned_account: &str,
        folder: &str,
        rows: &[MessageSummary],
        now: u64,
    ) -> SnoozeProjection {
        let result = (|| {
            account_valid(account)?;
            if account != returned_account
                || rows.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
                || MailboxEntry::new(MailboxListingPolicy::default(), folder).is_err()
            {
                return Err(SnoozeError::Invalid);
            }
            let identities = rows
                .iter()
                .map(|r| MessageIdentity::from_summary(account, returned_account, folder, r))
                .collect::<Result<Vec<_>, _>>()?;
            let mut uids = BTreeSet::new();
            let mut messages = BTreeSet::new();
            if identities.iter().any(|i| {
                !uids.insert(i.uid)
                    || !messages.insert(&i.message_guid)
                    || identities
                        .first()
                        .is_some_and(|first| first.mailbox_guid != i.mailbox_guid)
            }) {
                return Err(SnoozeError::Invalid);
            }
            let r = self.transact(account, now, None, |r| {
                // Only positive same-slot identity evidence removes a stale marker.
                r.markers.retain(|m| {
                    !identities.iter().any(|i| {
                        i.folder == m.identity.folder && i.uid == m.identity.uid && i != &m.identity
                    })
                });
                Ok(())
            })?;
            let hidden = identities
                .into_iter()
                .filter(|i| r.markers.iter().any(|m| &m.identity == i))
                .collect();
            Ok((hidden, r.revision))
        })();
        match result {
            Ok((hidden, revision)) => SnoozeProjection {
                hidden,
                revision: Some(revision),
                unavailable: None,
            },
            Err(e) => SnoozeProjection {
                hidden: vec![],
                revision: None,
                unavailable: Some(e),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-snooze-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn store(&self) -> SnoozeStore {
            SnoozeStore::new(&self.0)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn row(uid: u64) -> MessageSummary {
        MessageSummary {
            uid,
            mailbox_name: "INBOX".into(),
            metadata: Some(crate::message_metadata::MessageMetadata {
                threading: None,
                attachments: None,
                protection: crate::message_metadata::MessageProtection::Unknown,
                version: crate::message_metadata::MessageVersion::new(
                    "a".repeat(32),
                    format!("message-{uid}"),
                )
                .unwrap(),
                attachment_count: Some(0),
                preview: None,
            }),
            to: None,
            flags: vec![],
            date_received: String::new(),
            size_virtual: 0,
            subject: None,
            from: None,
        }
    }
    fn identity(uid: u64) -> MessageIdentity {
        MessageIdentity::from_summary("alice", "alice", "INBOX", &row(uid)).unwrap()
    }
    #[test]
    fn reopen_expiry_capacity_cancel_and_cas() {
        let f = Fixture::new();
        let s = f.store();
        let mut revision = 0;
        for uid in 1..=100 {
            revision = s
                .set("alice", &identity(uid), revision, 200, 100)
                .unwrap()
                .revision();
        }
        assert_eq!(
            s.set("alice", &identity(101), revision, 200, 100),
            Err(SnoozeError::Capacity)
        );
        assert_eq!(
            s.cancel("alice", &identity(1), 0, 100),
            Err(SnoozeError::Stale)
        );
        assert_eq!(f.store().load("alice", 100).unwrap().markers().len(), 100);
        let r = s.cancel("alice", &identity(1), revision, 100).unwrap();
        assert_eq!(r.markers().len(), 99);
        assert!(s.load("alice", 200).unwrap().markers().is_empty());
        assert_eq!(
            f.store().load("alice", 199),
            Err(SnoozeError::ClockRollback)
        );
        assert!(s
            .project("alice", "alice", "INBOX", &[row(2)], 200)
            .hidden
            .is_empty());
    }
    #[test]
    fn utc_validation_is_explicit_and_bounded() {
        assert_eq!(
            parse_until(&(100 + MAX_DURATION).to_string(), 100),
            Ok(100 + MAX_DURATION)
        );
        for bad in [
            "",
            "+101",
            "0101",
            "101 ",
            "2026-10-01T00:00:00",
            "0",
            "100",
            "18446744073709551616",
        ] {
            assert!(parse_until(bad, 100).is_err());
        }
        assert!(parse_until(&(101 + MAX_DURATION).to_string(), 100).is_err());
        assert!(parse_until("1", 0).is_err());
    }
    #[test]
    fn absence_never_retargets_and_verified_uid_reuse_removes_only_marker() {
        let f = Fixture::new();
        let s = f.store();
        s.set("alice", &identity(1), 0, 200, 100).unwrap();
        let p = s.project("alice", "alice", "INBOX", &[row(2)], 101);
        assert!(p.hidden.is_empty());
        assert!(p.unavailable.is_none());
        assert_eq!(s.load("alice", 101).unwrap().markers().len(), 1);
        assert_eq!(
            s.project("alice", "alice", "INBOX", &[row(1)], 102).hidden,
            vec![identity(1)]
        );
        let mut reused = row(1);
        reused.metadata.as_mut().unwrap().version.message_guid = "replacement".into();
        assert!(s
            .project("alice", "alice", "INBOX", &[reused], 103)
            .hidden
            .is_empty());
        assert!(f.store().load("alice", 103).unwrap().markers().is_empty());
    }
    #[test]
    fn uncertain_projections_hide_nothing_and_do_not_cleanup() {
        let f = Fixture::new();
        let s = f.store();
        s.set("alice", &identity(1), 0, 200, 100).unwrap();
        let mut missing = row(1);
        missing.metadata = None;
        let mut zero = row(1);
        zero.uid = 0;
        let mut generation = row(2);
        generation.metadata.as_mut().unwrap().version.mailbox_guid = "b".repeat(32);
        let mut duplicate_guid = row(2);
        duplicate_guid.metadata = row(1).metadata;
        for rows in [
            vec![row(1), row(1)],
            vec![missing],
            vec![zero],
            vec![row(1), generation],
            vec![row(1), duplicate_guid],
            vec![row(1); crate::mailbox::DEFAULT_MAX_MESSAGES + 1],
        ] {
            let p = s.project("alice", "alice", "INBOX", &rows, 100);
            assert!(p.hidden.is_empty());
            assert!(p.unavailable.is_some());
        }
        for (owner, folder) in [("bob", "INBOX"), ("alice", "Other")] {
            let p = s.project("alice", owner, folder, &[row(1)], 100);
            assert!(p.hidden.is_empty());
            assert!(p.unavailable.is_some());
        }
        assert_eq!(s.load("alice", 100).unwrap().markers().len(), 1);
        assert!(s.load("bob", 100).unwrap().markers().is_empty());
        assert_eq!(
            s.set("bob", &identity(1), 0, 200, 100),
            Err(SnoozeError::Invalid)
        );
    }
    #[test]
    fn corrupt_foreign_future_duplicate_and_oversized_records_are_never_hidden() {
        let f = Fixture::new();
        let s = f.store();
        s.set("alice", &identity(1), 0, 200, 100).unwrap();
        let bytes = s.file.read("alice").unwrap().unwrap();
        let original = String::from_utf8(bytes.clone()).unwrap();
        let mut overcount: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        overcount["markers"] =
            serde_json::json!(vec![overcount["markers"][0].clone(); MAX_MARKERS + 1]);
        for bad in [
            original.replace("\"version\":1", "\"version\":2"),
            original.replace("\"version\":1", "\"version\":1,\"version\":1"),
            original.replace("alice", "bob"),
            original.replace(
                "\"until\":200",
                &format!("\"until\":{}", MAX_DURATION + 101),
            ),
            overcount.to_string(),
            "{".into(),
        ] {
            s.file.lock("alice").unwrap().write(bad.as_bytes()).unwrap();
            let p = s.project("alice", "alice", "INBOX", &[row(1)], 100);
            assert!(p.hidden.is_empty());
            assert!(p.unavailable.is_some());
            assert_eq!(s.file.read("alice").unwrap().unwrap(), bad.as_bytes());
        }
        s.file.lock("alice").unwrap().write(&bytes).unwrap();
        s.file.lock("bob").unwrap().write(&bytes).unwrap();
        assert_eq!(s.load("bob", 100), Err(SnoozeError::Corrupt));
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(NAMESPACE);
        hash.update(b"\0alice");
        let file = f.0.join(format!("{:x}.json", hash.finalize()));
        let oversized = vec![b' '; MAX_BYTES + 1];
        std::fs::write(&file, &oversized).unwrap();
        let p = s.project("alice", "alice", "INBOX", &[row(1)], 100);
        assert!(p.hidden.is_empty());
        assert!(p.unavailable.is_some());
        assert_eq!(std::fs::read(file).unwrap(), oversized);
    }
    #[test]
    fn simultaneous_cas_writers_have_one_winner() {
        let f = Fixture::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = (1..=2)
            .map(|uid| {
                let s = f.store();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    s.set("alice", &identity(uid), 0, 200, 100)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(SnoozeError::Stale))
                .count(),
            1
        );
        assert_eq!(f.store().load("alice", 100).unwrap().markers().len(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_or_unavailable_state_keeps_expired_messages_visible() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = Fixture::new();
        let s = f.store();
        s.set("alice", &identity(1), 0, 200, 100).unwrap();
        std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o500)).unwrap();
        let p = s.project("alice", "alice", "INBOX", &[row(1)], 200);
        assert!(p.hidden.is_empty());
        assert!(p.unavailable.is_some());
        std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let other = Fixture::new();
        symlink(&f.0, &other.0).unwrap();
        assert!(other.store().load("alice", 100).is_err());
        std::fs::remove_file(&other.0).unwrap();
        assert_eq!(s.load("alice", 100).unwrap().markers().len(), 1);
    }
}
