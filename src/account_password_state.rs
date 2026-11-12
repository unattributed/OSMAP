//! Durable account admission state for the Rust password service.
//!
//! The epoch-v1 filename and five-field JSON schema match the existing operator
//! store. Runtime opens existing state only. A crash after `begin` leaves the
//! account pending; a new guard cannot clear pending/contained state. These
//! methods are trusted service operations, not browser-request capabilities.
//! Rust readers also honor the narrowly owned `.uncertain` sibling marker.
//! Legacy Python readers do not: admission and mutation must cut over together,
//! rather than running mixed readers against this store.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const LIMIT: usize = 4096;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Unavailable,
    Refused,
    Expired,
    Replay,
    Capacity,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    Active,
    Pending,
    Contained,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    epoch: u64,
    state: State,
    changed_at: Option<String>,
    intent: Option<String>,
    used_intents: Vec<(String, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    pub epoch: u64,
    pub state: State,
    pub changed_at: Option<String>,
}

/// Durable custody of the marker created for one operator recovery case.
/// It is never an authentication or completion claim by itself.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryMarker {
    pub device: u64,
    pub inode: u64,
}

type Identity = (u64, u64, u32, u32, u32);
fn identity(m: &fs::Metadata) -> Identity {
    (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
}
fn available<T>(_: T) -> Error {
    Error::Unavailable
}
fn deadline(value: Instant) -> Result<(), Error> {
    if Instant::now() >= value {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn reference(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn leaf(value: &str) -> Result<std::ffi::CString, Error> {
    std::ffi::CString::new(value).map_err(available)
}
fn stem(account: &str) -> Result<String, Error> {
    crate::account_admission::valid_account(account).map_err(|_| Error::Refused)?;
    let mut hash = Sha256::new();
    hash.update(b"osmap-account-epoch-v1\0");
    hash.update(account.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}
fn record_valid(record: &Record) -> bool {
    crate::account_admission::valid_epoch(record.epoch)
        && record
            .changed_at
            .as_deref()
            .is_none_or(crate::account_mutation::changed_at_valid)
        && record.intent.as_deref().is_none_or(reference)
        && (record.state == State::Active) == record.intent.is_none()
        && record.used_intents.len() <= 32
        && record
            .used_intents
            .iter()
            .all(|(id, expiry)| reference(id) && *expiry > 0)
}

pub(crate) struct Store {
    root: PathBuf,
    directory: File,
    owner: u32,
    identity: Identity,
}
impl Store {
    /// `root`/owner come only from fixed operator service configuration. The
    /// directory and every runtime lock/record must already exist.
    pub(crate) fn open(root: &Path, owner: u32) -> Result<Self, Error> {
        if !root.is_absolute() || root.canonicalize().map_err(available)? != root {
            return Err(Error::Unavailable);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)
            .map_err(available)?;
        let metadata = directory.metadata().map_err(available)?;
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(Error::Unavailable);
        }
        let store = Self {
            root: root.into(),
            directory,
            owner,
            identity: identity(&metadata),
        };
        store.check_root()?;
        Ok(store)
    }
    fn check_root(&self) -> Result<(), Error> {
        let current = fs::symlink_metadata(&self.root).map_err(available)?;
        if current.file_type().is_symlink()
            || identity(&current) != self.identity
            || identity(&self.directory.metadata().map_err(available)?) != self.identity
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn open_leaf(&self, name: &str, flags: i32) -> Result<File, Error> {
        self.check_root()?;
        let name = leaf(name)?;
        let file =
            crate::openbsd::private_leaf_open(&self.directory, &name, flags).map_err(available)?;
        self.check_file(&file)?;
        Ok(file)
    }
    fn check_file(&self, file: &File) -> Result<(), Error> {
        let m = file.metadata().map_err(available)?;
        if !m.is_file()
            || m.uid() != self.owner
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() > LIMIT as u64
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn current_identity(&self, name: &str) -> Result<Identity, Error> {
        let file = self.open_leaf(name, libc::O_RDONLY)?;
        Ok(identity(&file.metadata().map_err(available)?))
    }
    fn read(&self, name: &str) -> Result<(Record, Identity), Error> {
        let mut file = self.open_leaf(name, libc::O_RDONLY)?;
        let before = identity(&file.metadata().map_err(available)?);
        let mut bytes = Vec::new();
        (&mut file)
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(available)?;
        self.check_file(&file)?;
        if bytes.len() > LIMIT
            || identity(&file.metadata().map_err(available)?) != before
            || self.current_identity(name)? != before
        {
            return Err(Error::Unavailable);
        }
        let record: Record = serde_json::from_slice(&bytes).map_err(available)?;
        let shape: serde_json::Value = serde_json::from_slice(&bytes).map_err(available)?;
        if shape.as_object().is_none_or(|fields| fields.len() != 5) || !record_valid(&record) {
            return Err(Error::Unavailable);
        }
        Ok((record, before))
    }
    pub(crate) fn lock_before(
        &self,
        account: &str,
        original_deadline: Instant,
    ) -> Result<Guard<'_>, Error> {
        deadline(original_deadline)?;
        let stem = stem(account)?;
        let lock_name = format!("{stem}.lock");
        let record_name = format!("{stem}.json");
        let lock = self.open_leaf(&lock_name, libc::O_RDWR)?;
        if lock.metadata().map_err(available)?.len() != 0 {
            return Err(Error::Unavailable);
        }
        let lock_identity = identity(&lock.metadata().map_err(available)?);
        loop {
            deadline(original_deadline)?;
            let error = match crate::openbsd::private_file_try_lock(&lock) {
                Ok(()) => break,
                Err(error) => error,
            };
            if !matches!(
                error.raw_os_error(),
                Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
            ) {
                return Err(Error::Unavailable);
            }
            std::thread::sleep(
                Duration::from_millis(2)
                    .min(original_deadline.saturating_duration_since(Instant::now())),
            );
        }
        let result = (|| {
            self.check_root()?;
            if self.current_identity(&lock_name)? != lock_identity {
                return Err(Error::Unavailable);
            }
            let (record, record_identity) = self.read(&record_name)?;
            deadline(original_deadline)?;
            Ok((record, record_identity))
        })();
        match result {
            Ok((record, record_identity)) => Ok(Guard {
                store: self,
                lock,
                lock_name,
                lock_identity,
                marker_name: format!("{stem}.uncertain"),
                marker: None,
                record_name,
                record_identity,
                record,
                original_deadline,
                operation: None,
                finished: false,
            }),
            Err(error) => {
                let _ = crate::openbsd::private_file_unlock(&lock);
                Err(error)
            }
        }
    }
}

struct Operation {
    original: Record,
    verified_write: bool,
}
/// Held flock serializes admission and mutation in every cooperating process.
/// No Clone or serialization; dropping it never clears durable safety state.
pub(crate) struct Guard<'a> {
    store: &'a Store,
    lock: File,
    lock_name: String,
    lock_identity: Identity,
    record_name: String,
    record_identity: Identity,
    marker_name: String,
    marker: Option<(File, Identity)>,
    record: Record,
    original_deadline: Instant,
    operation: Option<Operation>,
    finished: bool,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // Explicit unlock also covers inherited duplicate descriptors.
        let _ = crate::openbsd::private_file_unlock(&self.lock);
    }
}
impl Guard<'_> {
    fn check(&self) -> Result<(), Error> {
        deadline(self.original_deadline)?;
        self.store.check_root()?;
        self.store.check_file(&self.lock)?;
        if self.store.current_identity(&self.lock_name)? != self.lock_identity
            || self.store.current_identity(&self.record_name)? != self.record_identity
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub(crate) fn status(&self) -> Result<Status, Error> {
        self.check()?;
        // An uncertainty marker predating this guard is never cleared by
        // runtime. It also covers a crash between final rename and fsync.
        let uncertain = self.marker_exists()? && self.record.state == State::Active;
        Ok(Status {
            epoch: self.record.epoch,
            state: if uncertain {
                State::Contained
            } else {
                self.record.state
            },
            changed_at: self.record.changed_at.clone(),
        })
    }
    pub(crate) fn admission(&self, expected_epoch: Option<u64>) -> Result<Status, Error> {
        let status = self.status()?;
        if status.state != State::Active
            || expected_epoch.is_some_and(|value| value != status.epoch)
        {
            return Err(Error::Refused);
        }
        Ok(status)
    }
    /// Caller supplies the sealed request-bound intent after fresh verification
    /// and required authority preflight. Pending is durable before SQL dispatch.
    pub(crate) fn begin(
        &mut self,
        expected_epoch: u64,
        intent: &str,
        now: u64,
    ) -> Result<(), Error> {
        self.admission(Some(expected_epoch))?;
        if self.operation.is_some()
            || self.finished
            || !reference(intent)
            || now == 0
            || expected_epoch >= crate::account_admission::MAX_EPOCH
        {
            return Err(Error::Refused);
        }
        let expires = now.checked_add(300).ok_or(Error::Refused)?;
        let mut pending = self.record.clone();
        pending.used_intents.retain(|(_, expiry)| *expiry > now);
        if pending.used_intents.iter().any(|(id, _)| id == intent) {
            return Err(Error::Replay);
        }
        if pending.used_intents.len() >= 32 {
            return Err(Error::Capacity);
        }
        pending.used_intents.push((intent.into(), expires));
        pending.state = State::Pending;
        pending.intent = Some(intent.into());
        pending.changed_at = None;
        let original = self.record.clone();
        self.create_marker(intent)?;
        self.write(pending)?;
        self.operation = Some(Operation {
            original,
            verified_write: false,
        });
        Ok(())
    }
    /// Operator-only factor recovery. Unlike a password transaction, this
    /// preserves the authoritative password-change timestamp. The domain-
    /// separated marker can be completed only by this exact recovery case.
    pub(crate) fn begin_recovery(
        &mut self,
        expected_epoch: u64,
        intent: &str,
        now: u64,
    ) -> Result<RecoveryMarker, Error> {
        self.admission(Some(expected_epoch))?;
        if self.operation.is_some()
            || self.finished
            || !reference(intent)
            || now == 0
            || expected_epoch >= crate::account_admission::MAX_EPOCH
        {
            return Err(Error::Refused);
        }
        let expires = now.checked_add(300).ok_or(Error::Refused)?;
        let mut next = self.record.clone();
        next.used_intents.retain(|(_, expiry)| *expiry > now);
        if next.used_intents.iter().any(|(id, _)| id == intent) {
            return Err(Error::Replay);
        }
        if next.used_intents.len() >= 32 {
            return Err(Error::Capacity);
        }
        next.used_intents.push((intent.into(), expires));
        next.state = State::Pending;
        next.intent = Some(intent.into());
        self.check()?;
        if self.marker_exists()? || self.marker.is_some() {
            return Err(Error::Refused);
        }
        let mut marker = self.store.open_leaf(
            &self.marker_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let owned = identity(&marker.metadata().map_err(available)?);
        self.marker = Some((marker.try_clone().map_err(available)?, owned));
        marker
            .write_all(format!("osmap-recovery-uncertain-v1\n{intent}\n").as_bytes())
            .map_err(available)?;
        marker.sync_all().map_err(available)?;
        self.store.directory.sync_all().map_err(available)?;
        self.write(next)?;
        Ok(RecoveryMarker {
            device: owned.0,
            inode: owned.1,
        })
    }
    /// Check only the exact case-owned recovery containment. A password marker,
    /// foreign case, changed epoch or replacement inode can never be adopted.
    pub(crate) fn check_recovery(
        &self,
        expected_epoch: u64,
        intent: &str,
        owned: RecoveryMarker,
    ) -> Result<(), Error> {
        self.check()?;
        if !reference(intent)
            || self.record.epoch != expected_epoch
            || !matches!(self.record.state, State::Pending | State::Contained)
            || self.record.intent.as_deref() != Some(intent)
        {
            return Err(Error::Refused);
        }
        let mut marker = self.store.open_leaf(&self.marker_name, libc::O_RDONLY)?;
        let metadata = marker.metadata().map_err(available)?;
        if metadata.dev() != owned.device || metadata.ino() != owned.inode {
            return Err(Error::Refused);
        }
        let mut bytes = Vec::new();
        marker.read_to_end(&mut bytes).map_err(available)?;
        if bytes != format!("osmap-recovery-uncertain-v1\n{intent}\n").as_bytes() {
            return Err(Error::Refused);
        }
        Ok(())
    }
    /// The operator coordinator calls this only after actual session, factor
    /// and durable case readbacks pass. No password write is invented. This
    /// trusted store operation does not itself attest those external effects.
    pub(crate) fn complete_recovery(
        &mut self,
        expected_epoch: u64,
        intent: &str,
        owned: RecoveryMarker,
    ) -> Result<Status, Error> {
        self.check_recovery(expected_epoch, intent, owned)?;
        let marker = self.store.open_leaf(&self.marker_name, libc::O_RDONLY)?;
        let marker_identity = identity(&marker.metadata().map_err(available)?);
        self.marker = Some((marker, marker_identity));
        let mut active = self.record.clone();
        active.epoch = active
            .epoch
            .checked_add(1)
            .filter(|v| crate::account_admission::valid_epoch(*v))
            .ok_or(Error::Refused)?;
        active.state = State::Active;
        active.intent = None;
        self.write(active)?;
        self.remove_own_marker()?;
        self.finished = true;
        self.operation = None;
        self.status()
    }
    /// Native recovery calls this only with the timestamp of its actual
    /// conditional password write and readback, while the same case is fenced.
    pub(crate) fn record_recovery_password_write(
        &mut self,
        expected_epoch: u64,
        intent: &str,
        owned: RecoveryMarker,
        changed_at: &str,
    ) -> Result<(), Error> {
        self.check_recovery(expected_epoch, intent, owned)?;
        if self.finished
            || self.record.state != State::Pending
            || !crate::account_mutation::changed_at_valid(changed_at)
        {
            return Err(Error::Refused);
        }
        let mut pending = self.record.clone();
        pending.changed_at = Some(changed_at.into());
        self.write(pending)
    }
    /// Allowed only for this guard's own independently verified zero-write
    /// refusal. Never use for a transport error or ambiguous dispatch.
    pub(crate) fn known_refused(&mut self) -> Result<(), Error> {
        let operation = self.operation.as_ref().ok_or(Error::Refused)?;
        if operation.verified_write || self.finished {
            return Err(Error::Refused);
        }
        let mut previous = operation.original.clone();
        previous.used_intents = self.record.used_intents.clone();
        self.write(previous)?;
        self.remove_own_marker()?;
        self.finished = true;
        self.operation = None;
        Ok(())
    }
    /// Timestamp must come from the actual conditional SQL write/readback,
    /// never a generic mailbox timestamp or a request-supplied value.
    pub(crate) fn record_verified_write(&mut self, changed_at: &str) -> Result<(), Error> {
        if self
            .operation
            .as_ref()
            .is_none_or(|value| value.verified_write)
            || self.finished
            || self.record.state != State::Pending
            || !crate::account_mutation::changed_at_valid(changed_at)
        {
            return Err(Error::Refused);
        }
        let mut pending = self.record.clone();
        pending.changed_at = Some(changed_at.into());
        // A known SQL write is irreversible even when persisting its timing
        // fails. It must never re-enable the zero-write restoration branch.
        self.operation
            .as_mut()
            .ok_or(Error::Refused)?
            .verified_write = true;
        self.write(pending)
    }
    /// Sticky containment is a durable admission refusal; it does not claim
    /// that any external connection has actually been terminated.
    pub(crate) fn contain(&mut self) -> Result<(), Error> {
        if self.operation.is_none() || self.finished {
            return Err(Error::Refused);
        }
        let mut contained = self.record.clone();
        contained.state = State::Contained;
        self.write(contained)?;
        self.finished = true;
        self.operation = None;
        Ok(())
    }
    /// Call only after required authentication/cache/mail effects actually
    /// pass. This store itself neither executes nor attests those effects.
    pub(crate) fn complete(&mut self) -> Result<Status, Error> {
        if !self
            .operation
            .as_ref()
            .is_some_and(|value| value.verified_write)
            || self.finished
            || self.record.state != State::Pending
            || self.record.changed_at.is_none()
        {
            return Err(Error::Refused);
        }
        let mut active = self.record.clone();
        active.epoch = active
            .epoch
            .checked_add(1)
            .filter(|v| crate::account_admission::valid_epoch(*v))
            .ok_or(Error::Refused)?;
        active.state = State::Active;
        active.intent = None;
        self.write(active)?;
        self.remove_own_marker()?;
        self.finished = true;
        self.operation = None;
        self.status()
    }
    fn write(&mut self, next: Record) -> Result<(), Error> {
        self.check()?;
        if !record_valid(&next) {
            return Err(Error::Refused);
        }
        let bytes = serde_json::to_vec(&next).map_err(available)?;
        if bytes.len() > LIMIT {
            return Err(Error::Capacity);
        }
        let temporary = format!(
            ".epoch-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        );
        let mut output = self
            .store
            .open_leaf(&temporary, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        let own_identity = identity(&output.metadata().map_err(available)?);
        let result = (|| {
            output.write_all(&bytes).map_err(available)?;
            output.sync_all().map_err(available)?;
            self.check()?;
            if self.store.current_identity(&temporary)? != own_identity {
                return Err(Error::Unavailable);
            }
            let from = leaf(&temporary)?;
            let to = leaf(&self.record_name)?;
            crate::openbsd::private_leaf_rename(&self.store.directory, &from, &to)
                .map_err(available)?;
            // Once renamed, the in-memory snapshot tracks the actual record
            // even if directory fsync fails; caller must classify uncertainty.
            self.record = next;
            self.record_identity = own_identity;
            self.store.directory.sync_all().map_err(available)?;
            self.store.check_root()?;
            // Commit acknowledgement does not renew the caller's deadline.
            // A late return after successful fsync is a safely committed
            // record, not a reason to invent durable containment failure.
            Ok(())
        })();
        if self.store.current_identity(&temporary).ok() == Some(own_identity) {
            if let Ok(name) = leaf(&temporary) {
                // Remove only our exact still-owned temporary inode.
                let _ = crate::openbsd::private_leaf_unlink(&self.store.directory, &name);
            }
        }
        result
    }
    fn marker_exists(&self) -> Result<bool, Error> {
        self.store.check_root()?;
        let name = leaf(&self.marker_name)?;
        if crate::openbsd::private_leaf_exists(&self.store.directory, &name).map_err(available)? {
            self.store.open_leaf(&self.marker_name, libc::O_RDONLY)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn create_marker(&mut self, intent: &str) -> Result<(), Error> {
        self.check()?;
        if self.marker_exists()? || self.marker.is_some() {
            return Err(Error::Refused);
        }
        let mut marker = self.store.open_leaf(
            &self.marker_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let marker_identity = identity(&marker.metadata().map_err(available)?);
        self.marker = Some((marker.try_clone().map_err(available)?, marker_identity));
        marker
            .write_all(format!("osmap-password-uncertain-v1\n{intent}\n").as_bytes())
            .map_err(available)?;
        marker.sync_all().map_err(available)?;
        self.store.directory.sync_all().map_err(available)?;
        self.check()
    }
    fn remove_own_marker(&mut self) -> Result<(), Error> {
        let (marker, owned) = self.marker.as_ref().ok_or(Error::Refused)?;
        self.store.check_root()?;
        self.store.check_file(marker)?;
        if identity(&marker.metadata().map_err(available)?) != *owned
            || self.store.current_identity(&self.marker_name)? != *owned
        {
            return Err(Error::Unavailable);
        }
        let name = leaf(&self.marker_name)?;
        // Exact own marker identity checked under the account lock.
        crate::openbsd::private_leaf_unlink(&self.store.directory, &name).map_err(available)?;
        self.store.directory.sync_all().map_err(available)?;
        self.marker = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "account_password_state_tests.rs"]
mod tests;
