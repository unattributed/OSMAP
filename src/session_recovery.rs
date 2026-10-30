//! Operator-only browser-session recovery. The account coordinator must make
//! admission durably refuse before calling, and keep it contained on any error.
//! This module revokes stored sessions; it cannot attest identity or mail access.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 8192;
const MAX_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryRevocationStage {
    Input,
    Lock,
    Snapshot,
    Write,
    Readback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRevocationFailure {
    pub stage: RecoveryRevocationStage,
    /// A write that failed after rename may have taken effect. This is a lower
    /// bound, never proof that the next attempted record remained unchanged.
    pub completed_writes: usize,
    pub attempted_writes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRevocation {
    pub matched: usize,
    pub newly_revoked: usize,
    pub verified: usize,
}

type Identity = (u64, u64, u32, u32, u32);
fn identity(metadata: &fs::Metadata) -> Identity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}

struct RecoveryLock {
    _guard: SessionFileLock,
    directory: File,
    directory_identity: Identity,
    lock_identity: Identity,
}

/// Move-only custody of the physical session-store lock after validating the
/// exact session. Keep it through epoch containment; drop before revocation.
pub(crate) struct RecoverySessionLease {
    _locked: RecoveryLock,
}

struct Entry {
    record: SessionRecord,
    bytes: Vec<u8>,
}

struct Operation<'a> {
    store: FileSessionStore,
    owner: u32,
    group: u32,
    account: &'a str,
    epoch: u64,
    now: u64,
    deadline: Instant,
    attempted: usize,
    completed: usize,
}

impl Operation<'_> {
    fn failure(&self, stage: RecoveryRevocationStage) -> RecoveryRevocationFailure {
        RecoveryRevocationFailure {
            stage,
            completed_writes: self.completed,
            attempted_writes: self.attempted,
        }
    }

    fn within(&self) -> Result<(), ()> {
        if Instant::now() >= self.deadline {
            return Err(());
        }
        Ok(())
    }

    fn lock(&self) -> Result<RecoveryLock, ()> {
        self.within()?;
        // No creation or chmod here: root must never replace the runtime's
        // lock with a root-owned file or repair unknown state as a side effect.
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        let directory = options.open(&self.store.session_dir).map_err(|_| ())?;
        let metadata = directory.metadata().map_err(|_| ())?;
        if metadata.uid() != self.owner
            || metadata.gid() != self.group
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(());
        }
        for parent in self.store.session_dir.ancestors().skip(1) {
            let metadata =
                crate::account_password_custody::ancestor_metadata(parent).map_err(|_| ())?;
            let root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !metadata.is_dir()
                || (metadata.uid() != 0 && metadata.uid() != self.owner)
                || (metadata.mode() & 0o022 != 0 && !root_sticky)
            {
                return Err(());
            }
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(self.store.lock_path()).map_err(|_| ())?;
        let lock_metadata = file.metadata().map_err(|_| ())?;
        if !lock_metadata.is_file()
            || lock_metadata.uid() != self.owner
            || lock_metadata.gid() != self.group
            || lock_metadata.mode() & 0o7777 != 0o600
            || lock_metadata.nlink() != 1
            || lock_metadata.len() != 0
        {
            return Err(());
        }
        crate::openbsd::try_advisory_file_lock_exclusive(&file).map_err(|_| ())?;
        let locked = RecoveryLock {
            _guard: SessionFileLock { file },
            directory,
            directory_identity: identity(&metadata),
            lock_identity: identity(&lock_metadata),
        };
        self.custody(&locked)?;
        Ok(locked)
    }

    fn custody(&self, locked: &RecoveryLock) -> Result<(), ()> {
        self.within()?;
        let metadata = fs::symlink_metadata(&self.store.session_dir).map_err(|_| ())?;
        let lock_metadata = fs::symlink_metadata(self.store.lock_path()).map_err(|_| ())?;
        if !metadata.is_dir()
            || identity(&metadata) != locked.directory_identity
            || identity(&lock_metadata) != locked.lock_identity
            || identity(&locked.directory.metadata().map_err(|_| ())?) != locked.directory_identity
        {
            return Err(());
        }
        Ok(())
    }

    fn read(&self, id: &str) -> Result<Vec<u8>, ()> {
        self.within()?;
        let path = self.store.session_path(id);
        let bytes =
            crate::private_account_file::read_record_owned(&path, MAX_RECORD_BYTES, self.owner)
                .map_err(|_| ())?
                .ok_or(())?;
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if !metadata.is_file() || metadata.gid() != self.group || metadata.mode() & 0o7777 != 0o600
        {
            return Err(());
        }
        Ok(bytes)
    }

    fn snapshot(&self, locked: &RecoveryLock) -> Result<BTreeMap<String, Entry>, ()> {
        self.custody(locked)?;
        let mut records = BTreeMap::new();
        for (index, entry) in fs::read_dir(&self.store.session_dir)
            .map_err(|_| ())?
            .enumerate()
        {
            if index >= MAX_ENTRIES {
                return Err(());
            }
            self.within()?;
            let entry = entry.map_err(|_| ())?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("session") {
                continue;
            }
            if records.len() >= MAX_RECORDS {
                return Err(());
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or(())?;
            if id.len() != SESSION_ID_HEX_LEN || !id.bytes().all(|value| value.is_ascii_hexdigit())
            {
                return Err(());
            }
            let bytes = self.read(id)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
            let mut keys = BTreeSet::new();
            for line in text.lines().filter(|value| !value.is_empty()) {
                let (key, _) = line.split_once('=').ok_or(())?;
                if !keys.insert(key) {
                    return Err(());
                }
            }
            let record = parse_session_record(text).map_err(|_| ())?.ok_or(())?;
            if record.session_id != id
                || !keys.contains("revoked_at")
                || record.issued_at == 0
                || record.expires_at <= record.issued_at
                || record.last_seen_at < record.issued_at
                || record.last_seen_at > record.expires_at
                || record.revoked_at.is_some_and(|at| at < record.issued_at)
                || (record.canonical_username == self.account
                    && record.account_epoch.is_some_and(|epoch| epoch > self.epoch))
            {
                return Err(());
            }
            if records.insert(id.into(), Entry { record, bytes }).is_some() {
                return Err(());
            }
        }
        self.custody(locked)?;
        Ok(records)
    }

    fn save(&self, locked: &RecoveryLock, record: &SessionRecord) -> Result<(), ()> {
        self.custody(locked)?;
        let temporary = std::ffi::CString::new(format!(
            ".recovery-revocation-{}-{}.tmp",
            std::process::id(),
            SESSION_TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .map_err(|_| ())?;
        let destination =
            std::ffi::CString::new(format!("{}.session", record.session_id)).map_err(|_| ())?;
        // The runtime owns the active directory. Pin all privileged namespace
        // writes to the already inspected directory descriptor, so a replaced
        // ancestor cannot redirect root's create/rename/cleanup operations.
        let mut file = crate::openbsd::private_leaf_open(
            &locked.directory,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| ())?;
        let created = file.metadata().map_err(|_| ())?;
        let result = (|| {
            // Reuse the original owner and group rather than replacing a
            // runtime-owned session with a root-owned atomic temporary.
            if crate::openbsd::effective_uid() == 0 {
                crate::openbsd::private_file_set_owner(&file, self.owner, self.group)
                    .map_err(|_| ())?;
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| ())?;
            let metadata = file.metadata().map_err(|_| ())?;
            if !metadata.is_file()
                || metadata.uid() != self.owner
                || metadata.gid() != self.group
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o600
            {
                return Err(());
            }
            file.write_all(serialize_session_record(record).as_bytes())
                .map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
            self.custody(locked)?;
            if !same_temporary(&locked.directory, &temporary, &created) {
                return Err(());
            }
            crate::openbsd::private_leaf_rename(&locked.directory, &temporary, &destination)
                .map_err(|_| ())?;
            locked.directory.sync_all().map_err(|_| ())?;
            Ok(())
        })();
        if result.is_err() {
            // Remove only the exact temporary inode created by this call. A
            // replaced leaf is retained as uncertain rather than adopted.
            if same_temporary(&locked.directory, &temporary, &created) {
                let _ = crate::openbsd::private_leaf_unlink(&locked.directory, &temporary);
            }
        }
        result
    }
}

fn same_temporary(directory: &File, leaf: &std::ffi::CStr, created: &fs::Metadata) -> bool {
    let Ok(current) = crate::openbsd::private_leaf_open(directory, leaf, libc::O_RDONLY) else {
        return false;
    };
    current.metadata().is_ok_and(|metadata| {
        metadata.is_file()
            && metadata.dev() == created.dev()
            && metadata.ino() == created.ino()
            && metadata.nlink() == 1
    })
}

fn operation<'a>(
    session_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    account: &'a str,
    expected_epoch: u64,
    now: u64,
    deadline: Instant,
) -> Result<Operation<'a>, RecoveryRevocationFailure> {
    let began = Instant::now();
    if !session_dir.is_absolute()
        || session_dir.components().count() > 128
        || runtime_uid == u32::MAX
        || runtime_gid == u32::MAX
        || (crate::openbsd::effective_uid() != 0 && crate::openbsd::effective_uid() != runtime_uid)
        || CanonicalUsername::parse(account).is_err()
        || !crate::account_admission::valid_epoch(expected_epoch)
        || now == 0
        || deadline <= began
        || deadline > began + Duration::from_secs(60)
    {
        return Err(RecoveryRevocationFailure {
            stage: RecoveryRevocationStage::Input,
            attempted_writes: 0,
            completed_writes: 0,
        });
    }
    Ok(Operation {
        store: FileSessionStore::new(session_dir),
        owner: runtime_uid,
        group: runtime_gid,
        account,
        epoch: expected_epoch,
        now,
        deadline,
        attempted: 0,
        completed: 0,
    })
}

/// Trusted operator construction supplies the fixed session root and runtime
/// principal. Existing/late authenticated sessions must remain unusable through
/// the coordinator's durable admission containment and final epoch advance.
#[allow(clippy::too_many_arguments)]
pub(crate) fn revoke_recovery_sessions(
    session_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    account: &str,
    expected_epoch: u64,
    now: u64,
    deadline: Instant,
) -> Result<RecoveryRevocation, RecoveryRevocationFailure> {
    revoke_with_clock(
        session_dir,
        runtime_uid,
        runtime_gid,
        account,
        expected_epoch,
        now,
        deadline,
        &crate::totp::SystemTimeProvider,
    )
}

#[allow(clippy::too_many_arguments)]
fn revoke_with_clock(
    session_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    account: &str,
    expected_epoch: u64,
    now: u64,
    deadline: Instant,
    clock: &impl TimeProvider,
) -> Result<RecoveryRevocation, RecoveryRevocationFailure> {
    let mut operation = operation(
        session_dir,
        runtime_uid,
        runtime_gid,
        account,
        expected_epoch,
        now,
        deadline,
    )?;
    let locked = operation
        .lock()
        .map_err(|_| operation.failure(RecoveryRevocationStage::Lock))?;
    // The CLI's initial clock can precede a legitimate session issued before
    // containment. Sample while holding the store lock, after that race closes.
    let sampled = clock.unix_timestamp();
    if sampled < now || sampled == 0 {
        return Err(operation.failure(RecoveryRevocationStage::Snapshot));
    }
    operation.now = sampled;
    let before = operation
        .snapshot(&locked)
        .map_err(|_| operation.failure(RecoveryRevocationStage::Snapshot))?;
    if before.values().any(|entry| {
        entry.record.canonical_username == account
            && entry.record.revoked_at.is_none()
            && entry.record.issued_at > sampled
    }) {
        return Err(operation.failure(RecoveryRevocationStage::Snapshot));
    }
    let matched = before
        .values()
        .filter(|entry| entry.record.canonical_username == account)
        .count();
    for (id, entry) in &before {
        if entry.record.canonical_username != account || entry.record.revoked_at.is_some() {
            continue;
        }
        operation
            .custody(&locked)
            .and_then(|_| operation.read(id))
            .and_then(|bytes| {
                if bytes == entry.bytes {
                    Ok(())
                } else {
                    Err(())
                }
            })
            .map_err(|_| operation.failure(RecoveryRevocationStage::Write))?;
        let mut record = entry.record.clone();
        record.revoked_at = Some(sampled);
        operation.attempted += 1;
        operation
            .save(&locked, &record)
            .map_err(|_| operation.failure(RecoveryRevocationStage::Write))?;
        operation.completed += 1;
    }
    let after = operation
        .snapshot(&locked)
        .map_err(|_| operation.failure(RecoveryRevocationStage::Readback))?;
    if before.len() != after.len()
        || before.iter().any(|(id, entry)| {
            let Some(current) = after.get(id) else {
                return true;
            };
            let mut expected = entry.record.clone();
            if expected.canonical_username == account && expected.revoked_at.is_none() {
                expected.revoked_at = Some(sampled);
                current.record != expected
            } else {
                current.bytes != entry.bytes
            }
        })
    {
        return Err(operation.failure(RecoveryRevocationStage::Readback));
    }
    Ok(RecoveryRevocation {
        matched,
        newly_revoked: operation.completed,
        verified: matched,
    })
}

/// Read-only reconciliation checks physical revocation records under the same
/// owned session lock. It never clears containment or claims mail revocation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_recovery_sessions(
    session_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    account: &str,
    expected_epoch: u64,
    now: u64,
    deadline: Instant,
) -> Result<RecoveryRevocation, RecoveryRevocationFailure> {
    let operation = operation(
        session_dir,
        runtime_uid,
        runtime_gid,
        account,
        expected_epoch,
        now,
        deadline,
    )?;
    let locked = operation
        .lock()
        .map_err(|_| operation.failure(RecoveryRevocationStage::Lock))?;
    let snapshot = operation
        .snapshot(&locked)
        .map_err(|_| operation.failure(RecoveryRevocationStage::Snapshot))?;
    let mut matched = 0;
    for entry in snapshot
        .values()
        .filter(|entry| entry.record.canonical_username == account)
    {
        matched += 1;
        if entry.record.revoked_at.is_none() {
            return Err(operation.failure(RecoveryRevocationStage::Readback));
        }
    }
    Ok(RecoveryRevocation {
        matched,
        newly_revoked: 0,
        verified: matched,
    })
}

/// Read the exact stored session through the same descriptor/custody checks
/// used by native revocation. This creates no session and changes no metadata.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_recovery_session(
    session_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    account: &str,
    expected_epoch: u64,
    session_id: &str,
    csrf: &str,
    now: u64,
    idle_seconds: u64,
    deadline: Instant,
) -> Result<RecoverySessionLease, RecoveryRevocationFailure> {
    let operation = operation(
        session_dir,
        runtime_uid,
        runtime_gid,
        account,
        expected_epoch,
        now,
        deadline,
    )?;
    let failure = || operation.failure(RecoveryRevocationStage::Snapshot);
    if session_id.len() != SESSION_ID_HEX_LEN || !session_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(failure());
    }
    let locked = operation
        .lock()
        .map_err(|_| operation.failure(RecoveryRevocationStage::Lock))?;
    let records = operation.snapshot(&locked).map_err(|_| failure())?;
    let record = &records.get(session_id).ok_or_else(failure)?.record;
    if record.session_id != session_id
        || record.canonical_username != account
        || record.account_epoch != Some(expected_epoch)
        || record.revoked_at.is_some()
        || record.factor != RequiredSecondFactor::Totp
        || record.csrf_token != csrf
        || now < record.issued_at
        || now < record.last_seen_at
        || now > record.expires_at
        || now.saturating_sub(record.last_seen_at) > idle_seconds
    {
        return Err(failure());
    }
    operation.custody(&locked).map_err(|_| failure())?;
    Ok(RecoverySessionLease { _locked: locked })
}

#[cfg(test)]
#[path = "session_recovery_tests.rs"]
mod tests;
