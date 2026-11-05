//! Bounded recorded session events, not a complete authentication audit.
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
pub const MAX_EVENTS: usize = 200;
pub const RETENTION_SECONDS: u64 = 90 * 86400;
const MAX_BYTES: usize = 40 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    SessionIssued,
    SessionRevoked,
    PasswordChanged,
    TotpChanged,
    RecoveryRequested,
    RecoveryCompleted,
    RecoveryContactRequested,
    RecoveryContactChanged,
    PublicKeyImported,
    PublicKeyRemoved,
    PersonalKeyImported,
    PersonalKeyUnlocked,
    PersonalKeyLocked,
    PolicyChanged,
    NewMail,
    Mention,
    SubmissionAccepted,
    SubmissionUnknown,
    ScheduledBlocked,
    ScheduledSaved,
    ScheduledCancelled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationCategory {
    NewMail,
    Mentions,
    OpenPgp,
    Submission,
}
impl NotificationKind {
    pub fn title(self) -> &'static str {
        match self {
            Self::SessionIssued => "Browser session started",
            Self::SessionRevoked => "Browser session revoked",
            Self::PasswordChanged => "Account password changed",
            Self::TotpChanged => "Authenticator changed",
            Self::RecoveryRequested => "Account recovery requested",
            Self::RecoveryCompleted => "Account recovery reconciled",
            Self::RecoveryContactRequested => "Recovery contact verification requested",
            Self::RecoveryContactChanged => "Recovery contact changed",
            Self::PublicKeyImported => "Public key imported",
            Self::PublicKeyRemoved => "Public key removed",
            Self::PersonalKeyImported => "Personal key imported",
            Self::PersonalKeyUnlocked => "Personal key unlocked",
            Self::PersonalKeyLocked => "Personal key locked",
            Self::PolicyChanged => "OpenPGP policy or binding changed",
            Self::NewMail => "New Inbox message observed",
            Self::Mention => "Your address was mentioned in a message you read",
            Self::SubmissionAccepted => "Message accepted for submission",
            Self::SubmissionUnknown => "Message submission outcome is uncertain",
            Self::ScheduledBlocked => "Scheduled message blocked",
            Self::ScheduledSaved => "Scheduled message saved",
            Self::ScheduledCancelled => "Scheduled message cancelled",
        }
    }
    pub fn optional_category(self) -> Option<NotificationCategory> {
        match self {
            Self::NewMail => Some(NotificationCategory::NewMail),
            Self::Mention => Some(NotificationCategory::Mentions),
            Self::PublicKeyImported | Self::PublicKeyRemoved => Some(NotificationCategory::OpenPgp),
            Self::SubmissionAccepted | Self::SubmissionUnknown | Self::ScheduledBlocked => {
                Some(NotificationCategory::Submission)
            }
            Self::ScheduledSaved | Self::ScheduledCancelled => {
                Some(NotificationCategory::Submission)
            }
            _ => None,
        }
    }
    pub fn is_mandatory(self) -> bool {
        self.optional_category().is_none()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationEvent {
    pub event_id: String,
    pub kind: NotificationKind,
    pub occurred_at: u64,
    pub read: bool,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotificationInbox {
    pub revision: u64,
    pub events: Vec<NotificationEvent>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationError {
    Invalid,
    Corrupt,
    Stale,
    Missing,
    ClockRollback,
    Unavailable,
    Unconfirmed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    owner_ref: String,
    version: u8,
    revision: u64,
    high_water: u64,
    /// A capacity-evicted timestamp cannot be replayed into a fresh event.
    #[serde(default)]
    discarded_through: u64,
    events: Vec<NotificationEvent>,
}
#[derive(Debug, Clone)]
pub struct NotificationStore {
    file: PrivateAccountFile,
}
impl NotificationStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(root.into(), "osmap-notifications-v1", MAX_BYTES),
        }
    }
    fn lock(&self, account: &str) -> Result<LockedAccountFile, NotificationError> {
        crate::identity::CanonicalUsername::parse(account)
            .map_err(|_| NotificationError::Invalid)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match self.file.lock(account) {
                Ok(lock) => return Ok(lock),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(NotificationError::Unavailable),
            }
        }
    }
    fn read(
        lock: &LockedAccountFile,
        account: &str,
        now: u64,
    ) -> Result<Stored, NotificationError> {
        if now == 0 {
            return Err(NotificationError::Invalid);
        }
        let Some(bytes) = lock.read().map_err(|_| NotificationError::Unavailable)? else {
            return Ok(Stored {
                owner_ref: owner_ref(account),
                version: 1,
                revision: 0,
                high_water: now,
                discarded_through: 0,
                events: vec![],
            });
        };
        let record: Stored =
            serde_json::from_slice(&bytes).map_err(|_| NotificationError::Corrupt)?;
        if record.owner_ref != owner_ref(account)
            || record.version != 1
            || record.revision == 0
            || record.high_water == 0
            || record.discarded_through > record.high_water
            || record.events.len() > MAX_EVENTS
        {
            return Err(NotificationError::Corrupt);
        }
        let mut ids = HashSet::new();
        let mut previous = u64::MAX;
        for event in &record.events {
            if !valid_id(&event.event_id)
                || !ids.insert(&event.event_id)
                || event.occurred_at == 0
                || event.occurred_at > record.high_water
                || event.occurred_at > previous
            {
                return Err(NotificationError::Corrupt);
            }
            previous = event.occurred_at;
        }
        if now < record.high_water {
            return Err(NotificationError::ClockRollback);
        }
        Ok(record)
    }
    fn write(
        lock: &LockedAccountFile,
        record: &mut Stored,
        now: u64,
    ) -> Result<(), NotificationError> {
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(NotificationError::Corrupt)?;
        record.high_water = now;
        let bytes = serde_json::to_vec(record).map_err(|_| NotificationError::Corrupt)?;
        if bytes.len() > MAX_BYTES {
            return Err(NotificationError::Corrupt);
        }
        lock.write(&bytes)
            .map_err(|_| NotificationError::Unconfirmed)
    }
    fn prune(record: &mut Stored, now: u64) -> bool {
        let old = record.events.len();
        record
            .events
            .retain(|event| now - event.occurred_at < RETENTION_SECONDS);
        old != record.events.len()
    }
    fn inbox(record: Stored) -> NotificationInbox {
        NotificationInbox {
            revision: record.revision,
            events: record.events,
        }
    }
    pub fn load(&self, account: &str, now: u64) -> Result<NotificationInbox, NotificationError> {
        let lock = self.lock(account)?;
        let mut record = Self::read(&lock, account, now)?;
        if Self::prune(&mut record, now) {
            Self::write(&lock, &mut record, now)?;
        }
        Ok(Self::inbox(record))
    }
    pub fn record(
        &self,
        account: &str,
        kind: NotificationKind,
        now: u64,
    ) -> Result<(), NotificationError> {
        let lock = self.lock(account)?;
        let mut record = Self::read(&lock, account, now)?;
        Self::prune(&mut record, now);
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| NotificationError::Unavailable)?;
        let event_id: String = random.iter().map(|b| format!("{b:02x}")).collect();
        if record.events.iter().any(|event| event.event_id == event_id) {
            return Err(NotificationError::Unavailable);
        }
        record.events.insert(
            0,
            NotificationEvent {
                event_id,
                kind,
                occurred_at: now,
                read: false,
            },
        );
        if record.events.len() > MAX_EVENTS {
            record.discarded_through = record.discarded_through.max(
                record.events[MAX_EVENTS..]
                    .iter()
                    .map(|event| event.occurred_at)
                    .max()
                    .unwrap_or(0),
            );
            record.events.truncate(MAX_EVENTS);
        }
        Self::write(&lock, &mut record, now)
    }
    /// One confirmed source operation, with no source identifier persisted.
    /// A full inbox conservatively rejects replay at an evicted timestamp;
    /// same-second capacity overflow may therefore omit optional new notices.
    pub fn record_once(
        &self,
        account: &str,
        kind: NotificationKind,
        source_ref: &str,
        occurred_at: u64,
        now: u64,
    ) -> Result<bool, NotificationError> {
        if source_ref.is_empty()
            || source_ref.len() > 512
            || !source_ref.bytes().all(|b| b.is_ascii_graphic())
            || occurred_at == 0
            || occurred_at > now
        {
            return Err(NotificationError::Invalid);
        }
        let lock = self.lock(account)?;
        let mut record = Self::read(&lock, account, now)?;
        let mut hash = Sha256::new();
        hash.update(b"osmap-notification-source-v1\0");
        hash.update(account.as_bytes());
        hash.update(b"\0");
        hash.update(serde_json::to_vec(&kind).map_err(|_| NotificationError::Invalid)?);
        hash.update(b"\0");
        hash.update(source_ref.as_bytes());
        let event_id = hash.finalize()[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if record.events.iter().any(|event| event.event_id == event_id)
            || now - occurred_at >= RETENTION_SECONDS
            || occurred_at <= record.discarded_through
        {
            return Ok(false);
        }
        Self::prune(&mut record, now);
        if record.events.len() == MAX_EVENTS
            && record
                .events
                .last()
                .is_some_and(|event| occurred_at <= event.occurred_at)
        {
            return Ok(false);
        }
        record.events.push(NotificationEvent {
            event_id,
            kind,
            occurred_at,
            read: false,
        });
        record.events.sort_by(|a, b| {
            b.occurred_at
                .cmp(&a.occurred_at)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        if record.events.len() > MAX_EVENTS {
            let removed = record.events.pop().ok_or(NotificationError::Corrupt)?;
            record.discarded_through = record.discarded_through.max(removed.occurred_at);
        }
        Self::write(&lock, &mut record, now)?;
        Ok(true)
    }
    pub fn set_read(
        &self,
        account: &str,
        event_id: &str,
        revision: u64,
        read: bool,
        now: u64,
    ) -> Result<NotificationInbox, NotificationError> {
        if !valid_id(event_id) {
            return Err(NotificationError::Invalid);
        }
        let lock = self.lock(account)?;
        let mut record = Self::read(&lock, account, now)?;
        if Self::prune(&mut record, now) {
            Self::write(&lock, &mut record, now)?;
        }
        if record.revision != revision {
            return Err(NotificationError::Stale);
        }
        let event = record
            .events
            .iter_mut()
            .find(|event| event.event_id == event_id)
            .ok_or(NotificationError::Missing)?;
        if event.read != read {
            event.read = read;
            Self::write(&lock, &mut record, now)?;
        }
        Ok(Self::inbox(record))
    }
}

#[cfg(test)]
#[path = "notification_event_tests.rs"]
mod event_tests;
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn owner_ref(account: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"osmap-notification-owner-v1\0");
    h.update(account.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-notifications-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn store(&self) -> NotificationStore {
            NotificationStore::new(&self.0)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    const A: &str = "alice@example.test";
    const B: &str = "bob@example.test";
    #[test]
    fn notification_roundtrip_owner_cas_capacity_and_retention() {
        let root = Scratch::new();
        let store = root.store();
        assert!(store.load(A, 100).unwrap().events.is_empty());
        for now in 100..305 {
            store
                .record(A, NotificationKind::SessionIssued, now)
                .unwrap();
        }
        let inbox = root.store().load(A, 305).unwrap();
        assert_eq!(inbox.events.len(), 200);
        assert_eq!(inbox.events[0].occurred_at, 304);
        assert!(store.load(B, 305).unwrap().events.is_empty());
        assert_eq!(
            store.set_read(B, &inbox.events[0].event_id, 0, true, 305),
            Err(NotificationError::Missing)
        );
        let read = store
            .set_read(A, &inbox.events[0].event_id, inbox.revision, true, 305)
            .unwrap();
        assert!(read.events[0].read);
        assert_eq!(
            store.set_read(A, &inbox.events[1].event_id, inbox.revision, true, 305),
            Err(NotificationError::Stale)
        );
        let expired = store.load(A, 304 + RETENTION_SECONDS).unwrap();
        assert!(expired.events.is_empty());
        assert!(expired.revision > read.revision);
        assert_eq!(store.load(A, 306), Err(NotificationError::ClockRollback));
        assert!(root
            .store()
            .load(A, 304 + RETENTION_SECONDS)
            .unwrap()
            .events
            .is_empty());
    }
    #[test]
    fn notification_strict_schema_refuses_without_reset() {
        let root = Scratch::new();
        let store = root.store();
        store
            .record(A, NotificationKind::SessionIssued, 100)
            .unwrap();
        let lock = store.file.lock(A).unwrap();
        let good = lock.read().unwrap().unwrap();
        let foreign = store.file.lock(B).unwrap();
        foreign.write(&lock.read().unwrap().unwrap()).unwrap();
        assert!(matches!(
            NotificationStore::read(&foreign, B, 100),
            Err(NotificationError::Corrupt)
        ));
        drop(foreign);

        for bad in [
            String::from_utf8(good.clone())
                .unwrap()
                .replace("\"version\":1", "\"version\":2"),
            String::from_utf8(good.clone())
                .unwrap()
                .replace("\"version\":1", "\"version\":1,\"version\":1"),
            String::from_utf8(good.clone())
                .unwrap()
                .replace("session_issued", "untrusted_kind"),
            "{".into(),
        ] {
            lock.write(bad.as_bytes()).unwrap();
            drop(store.file.read(A));
            assert!(NotificationStore::read(&lock, A, 100).is_err());
            assert_eq!(lock.read().unwrap().unwrap(), bad.as_bytes());
        }
    }
    #[test]
    fn notification_competing_writers_preserve_bounded_actual_events() {
        let root = Scratch::new();
        root.store().load(A, 100).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..3 {
                let store = root.store();
                scope.spawn(move || {
                    for _ in 0..10 {
                        store
                            .record(A, NotificationKind::SessionRevoked, 100)
                            .unwrap();
                    }
                });
            }
        });
        let inbox = root.store().load(A, 100).unwrap();
        assert_eq!(inbox.events.len(), 30);
        assert_eq!(inbox.revision, 30);
    }
    #[cfg(unix)]
    #[test]
    fn notification_symlink_and_publication_refusal_are_not_success() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = Scratch::new();
        let store = root.store();
        store
            .record(A, NotificationKind::SessionIssued, 100)
            .unwrap();
        let before = store.load(A, 100).unwrap();
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = store.record(A, NotificationKind::SessionIssued, 100);
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert_eq!(store.load(A, 100).unwrap(), before);
        let path = std::fs::read_dir(&root.0)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .unwrap();
        let original = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let target = root.0.join("synthetic-target");
        std::fs::write(&target, &original).unwrap();
        symlink(&target, &path).unwrap();
        assert!(store.load(A, 100).is_err());
        assert_eq!(std::fs::read(target).unwrap(), original);
    }
}
