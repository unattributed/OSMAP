//! Native factor activation. Paths and verified identity/grant authority belong
//! to the native dispatcher; browser input can never construct filesystem roots.
//! Any interruption after dispatch retains Pending and requires reconciliation.
use crate::account_password_state::{RecoveryMarker, Store};
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use crate::totp::{enrollment_counter, parse_secret_file};
use crate::totp_enrollment::{EnrollmentBinding, VerifiedEnrollment};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SCHEMA: &str = "osmap-native-factor-replacement-v1";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Error {
    Refused,
    Expired,
    Replay,
    StateUnavailable,
    FactorChanged,
    FactorWrite,
    SessionsIncomplete,
    PasswordReset,
    ReleaseUncertain,
}
pub(crate) struct Paths {
    pub epoch: PathBuf,
    pub cases: PathBuf,
    pub sessions: PathBuf,
    pub factors: PathBuf,
    pub archive: PathBuf,
    pub operator_uid: u32,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
}
pub(crate) struct Coordinator {
    paths: Paths,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub account: String,
    pub enrollment_id: String,
    pub epoch: u64,
    pub factor_sha256: String,
    pub revoked_sessions: usize,
    pub password_changed_at: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    DispatchPending,
    Contained,
    FactorReplaced,
    ReleasePending,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    schema: String,
    binding: EnrollmentBinding,
    enrollment_id: String,
    intent: String,
    replacement_sha256: String,
    phase: Phase,
    marker: Option<RecoveryMarker>,
    failure: Option<Error>,
    password_changed_at: Option<String>,
    revoked_sessions: usize,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn leaf(account: &str) -> Result<String, Error> {
    crate::account_admission::valid_account(account).map_err(|_| Error::Refused)?;
    Ok(format!(
        "{}.totp",
        account
            .as_bytes()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>()
    ))
}
fn within(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn save(lock: &LockedAccountFile, case: &Case) -> Result<(), Error> {
    let bytes = serde_json::to_vec(case).map_err(|_| Error::StateUnavailable)?;
    lock.write(&bytes).map_err(|_| Error::StateUnavailable)?;
    if lock.read().map_err(|_| Error::StateUnavailable)?.as_deref() != Some(bytes.as_slice()) {
        return Err(Error::StateUnavailable);
    }
    Ok(())
}
fn fail(lock: &LockedAccountFile, case: &mut Case, error: Error) -> Error {
    case.failure = Some(error);
    let _ = save(lock, case);
    error
}
impl Coordinator {
    pub(crate) fn new(paths: Paths) -> Self {
        Self { paths }
    }
    fn check_owner(&self) -> Result<(), Error> {
        if crate::openbsd::effective_uid() != self.paths.operator_uid {
            return Err(Error::Refused);
        }
        Ok(())
    }
    fn epoch(&self) -> Result<Store, Error> {
        Store::open(&self.paths.epoch, self.paths.operator_uid).map_err(|_| Error::StateUnavailable)
    }
    fn files(&self) -> PrivateAccountFile {
        PrivateAccountFile::new(self.paths.cases.clone(), SCHEMA, 16_384)
    }
    fn factors(&self) -> Result<Directory, Error> {
        Directory::open(
            &self.paths.factors,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )
    }
    pub(crate) fn snapshot(
        &self,
        account: &str,
        deadline: Instant,
    ) -> Result<(u64, String), Error> {
        self.check_owner()?;
        within(deadline)?;
        let epoch = self.epoch()?;
        let guard = epoch
            .lock_before(account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        let admitted = guard.admission(None).map_err(|_| Error::Refused)?;
        let (bytes, _) = self.factors()?.read(&leaf(account)?)?;
        parse_secret_file(std::str::from_utf8(&bytes).map_err(|_| Error::StateUnavailable)?)
            .map_err(|_| Error::StateUnavailable)?
            .ok_or(Error::Refused)?;
        within(deadline)?;
        Ok((admitted.epoch, hash(&bytes)))
    }
    /// Pure check of the current descriptor-validated factor. This does not
    /// consume or claim to consume the browser login replay counter.
    pub(crate) fn verify_current_code(
        &self,
        account: &str,
        code: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<bool, Error> {
        self.check_owner()?;
        within(deadline)?;
        let epoch = self.epoch()?;
        let guard = epoch
            .lock_before(account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        guard.admission(None).map_err(|_| Error::Refused)?;
        let (bytes, _) = self.factors()?.read(&leaf(account)?)?;
        let secret =
            parse_secret_file(std::str::from_utf8(&bytes).map_err(|_| Error::StateUnavailable)?)
                .map_err(|_| Error::StateUnavailable)?
                .ok_or(Error::Refused)?;
        within(deadline)?;
        Ok(enrollment_counter(&secret.secret_bytes, code, now).is_some())
    }
    /// Caller is the native credential/recovery-grant service. Candidate proof
    /// alone is NOT authorization: the dispatcher must bind actual native
    /// password+current-factor reauthentication or a consumed email grant first.
    pub(crate) fn replace<F>(
        &self,
        verified: VerifiedEnrollment,
        now: u64,
        deadline: Instant,
        before_release: F,
    ) -> Result<Receipt, Error>
    where
        F: FnOnce() -> Result<Option<String>, Error>,
    {
        self.replace_inner(verified, None, now, deadline, before_release)
    }
    /// Signed-in activation must revalidate and hold the actual stored session
    /// until Pending is durable, so a logout that wins the lock prevents it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn replace_session<F>(
        &self,
        verified: VerifiedEnrollment,
        csrf: &str,
        idle_seconds: u64,
        now: u64,
        deadline: Instant,
        before_release: F,
    ) -> Result<Receipt, Error>
    where
        F: FnOnce() -> Result<Option<String>, Error>,
    {
        self.replace_inner(
            verified,
            Some((csrf, idle_seconds)),
            now,
            deadline,
            before_release,
        )
    }
    fn replace_inner<F>(
        &self,
        verified: VerifiedEnrollment,
        session: Option<(&str, u64)>,
        now: u64,
        deadline: Instant,
        before_release: F,
    ) -> Result<Receipt, Error>
    where
        F: FnOnce() -> Result<Option<String>, Error>,
    {
        self.check_owner()?;
        if now == 0 || now >= verified.expires_at() {
            return Err(Error::Expired);
        }
        let deadline = deadline.min(
            Instant::now()
                .checked_add(Duration::from_secs(verified.expires_at() - now))
                .ok_or(Error::Expired)?,
        );
        within(deadline)?;
        let binding = verified.binding().clone();
        let active_name = leaf(&binding.account)?;
        let new_bytes = format!(
            "# {}\nsecret={}\n",
            binding.account,
            verified.secret_base32()
        )
        .into_bytes();
        let replacement = hash(&new_bytes);
        if replacement == binding.expected_factor_sha256 {
            return Err(Error::Refused);
        }
        let files = self.files();
        let locked = files
            .lock(&binding.account)
            .map_err(|_| Error::StateUnavailable)?;
        if let Some(bytes) = locked.read().map_err(|_| Error::StateUnavailable)? {
            let prior: Case =
                serde_json::from_slice(&bytes).map_err(|_| Error::StateUnavailable)?;
            if prior.schema != SCHEMA
                || prior.binding.account != binding.account
                || prior.phase != Phase::Complete
                || prior.enrollment_id == verified.id()
            {
                return Err(Error::Replay);
            }
        }
        let factors = self.factors()?;
        let (old_bytes, old_identity) = factors.read(&active_name)?;
        if hash(&old_bytes) != binding.expected_factor_sha256 {
            return Err(Error::FactorChanged);
        }
        let old_secret = parse_secret_file(
            std::str::from_utf8(&old_bytes).map_err(|_| Error::StateUnavailable)?,
        )
        .map_err(|_| Error::StateUnavailable)?
        .ok_or(Error::Refused)?;
        let new_secret = parse_secret_file(
            std::str::from_utf8(&new_bytes).map_err(|_| Error::StateUnavailable)?,
        )
        .map_err(|_| Error::StateUnavailable)?
        .ok_or(Error::Refused)?;
        if old_secret == new_secret {
            return Err(Error::Refused);
        }
        // Case -> session -> epoch. The grant path already holds its consumed
        // native grant lock; it must not substitute a session assertion here.
        let session_lease: Option<crate::session::RecoverySessionLease> = session
            .map(|(csrf, idle_seconds)| {
                crate::session::validate_recovery_session(
                    &self.paths.sessions,
                    self.paths.runtime_uid,
                    self.paths.runtime_gid,
                    &binding.account,
                    binding.epoch,
                    &binding.session_id,
                    csrf,
                    now,
                    idle_seconds,
                    deadline,
                )
                .map_err(|_| Error::Refused)
            })
            .transpose()?;
        let epoch = self.epoch()?;
        let mut guard = epoch
            .lock_before(&binding.account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        let original = guard
            .admission(Some(binding.epoch))
            .map_err(|_| Error::Refused)?;
        let mut intent = Sha256::new();
        intent.update(b"osmap-browser-factor-replacement-v1\0");
        intent.update(binding.account.as_bytes());
        intent.update(verified.id().as_bytes());
        intent.update(binding.session_id.as_bytes());
        intent.update(binding.epoch.to_be_bytes());
        intent.update(binding.expected_factor_sha256.as_bytes());
        let intent = format!("{:x}", intent.finalize());
        let mut case = Case {
            schema: SCHEMA.into(),
            binding: binding.clone(),
            enrollment_id: verified.id().into(),
            intent,
            replacement_sha256: replacement.clone(),
            phase: Phase::DispatchPending,
            marker: None,
            failure: None,
            password_changed_at: original.changed_at,
            revoked_sessions: 0,
        };
        save(&locked, &case)?;
        let marker = guard
            .begin_recovery(binding.epoch, &case.intent, now)
            .map_err(|_| fail(&locked, &mut case, Error::StateUnavailable))?;
        case.marker = Some(marker);
        case.phase = Phase::Contained;
        save(&locked, &case)?;
        // Preserve session -> epoch lock order. Pending itself remains durable.
        drop(guard);
        drop(session_lease);
        let revoked = crate::session::revoke_recovery_sessions(
            &self.paths.sessions,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
            &binding.account,
            binding.epoch,
            now,
            deadline,
        )
        .map_err(|_| fail(&locked, &mut case, Error::SessionsIncomplete))?;
        case.revoked_sessions = revoked.verified;
        within(deadline)?;
        let archive = Directory::ensure(
            &self.paths.archive,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )
        .map_err(|_| fail(&locked, &mut case, Error::FactorWrite))?;
        let (current, identity) = factors
            .read(&active_name)
            .map_err(|_| fail(&locked, &mut case, Error::StateUnavailable))?;
        if identity != old_identity || current != old_bytes {
            return Err(fail(&locked, &mut case, Error::FactorChanged));
        }
        let archive_name = format!(
            "{}.{}.revoked.totp",
            active_name.trim_end_matches(".totp"),
            verified.id()
        );
        archive
            .write_new(&archive_name, &old_bytes)
            .map_err(|_| fail(&locked, &mut case, Error::FactorWrite))?;
        let temporary = format!(".replacement-{}.tmp", verified.id());
        factors
            .write_new(&temporary, &new_bytes)
            .map_err(|_| fail(&locked, &mut case, Error::FactorWrite))?;
        let (current, identity) = factors
            .read(&active_name)
            .map_err(|_| fail(&locked, &mut case, Error::StateUnavailable))?;
        if identity != old_identity || current != old_bytes {
            return Err(fail(&locked, &mut case, Error::FactorChanged));
        }
        factors
            .rename(&temporary, &active_name)
            .map_err(|_| fail(&locked, &mut case, Error::FactorWrite))?;
        if factors.read(&active_name)?.0 != new_bytes || archive.read(&archive_name)?.0 != old_bytes
        {
            return Err(fail(&locked, &mut case, Error::FactorChanged));
        }
        case.phase = Phase::FactorReplaced;
        save(&locked, &case)?;
        // Real password reset/readback/cache cleanup, if requested, occurs under
        // this same durable fence; no success Boolean or fake SQL write exists.
        case.password_changed_at = before_release()
            .map_err(|error| fail(&locked, &mut case, error))?
            .or(case.password_changed_at);
        save(&locked, &case)?;
        within(deadline)?;
        crate::session::verify_recovery_sessions(
            &self.paths.sessions,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
            &binding.account,
            binding.epoch,
            now,
            deadline,
        )
        .map_err(|_| fail(&locked, &mut case, Error::SessionsIncomplete))?;
        if hash(&factors.read(&active_name)?.0) != replacement
            || hash(&archive.read(&archive_name)?.0) != binding.expected_factor_sha256
        {
            return Err(fail(&locked, &mut case, Error::FactorChanged));
        }
        let mut guard = epoch
            .lock_before(&binding.account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        guard
            .check_recovery(binding.epoch, &case.intent, marker)
            .map_err(|_| Error::StateUnavailable)?;
        if case.password_changed_at
            != guard
                .status()
                .map_err(|_| Error::StateUnavailable)?
                .changed_at
        {
            let stamp = case
                .password_changed_at
                .as_deref()
                .ok_or(Error::PasswordReset)?;
            guard
                .record_recovery_password_write(binding.epoch, &case.intent, marker, stamp)
                .map_err(|_| fail(&locked, &mut case, Error::PasswordReset))?;
        }
        case.phase = Phase::ReleasePending;
        save(&locked, &case)?;
        let status = guard
            .complete_recovery(binding.epoch, &case.intent, marker)
            .map_err(|_| fail(&locked, &mut case, Error::ReleaseUncertain))?;
        case.phase = Phase::Complete;
        save(&locked, &case).map_err(|_| Error::ReleaseUncertain)?;
        Ok(Receipt {
            account: binding.account,
            enrollment_id: case.enrollment_id,
            epoch: status.epoch,
            factor_sha256: replacement,
            revoked_sessions: case.revoked_sessions,
            password_changed_at: status.changed_at,
        })
    }
}

type Identity = (u64, u64, u64, i64, i64);
struct Directory {
    path: PathBuf,
    fd: File,
    owner: u32,
    group: u32,
}
impl Directory {
    fn open(path: &Path, owner: u32, group: u32) -> Result<Self, Error> {
        for parent in path.ancestors() {
            let m = fs::symlink_metadata(parent).map_err(|_| Error::StateUnavailable)?;
            let sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
            if !m.is_dir()
                || m.file_type().is_symlink()
                || (m.uid() != 0 && m.uid() != owner)
                || (m.mode() & 0o022 != 0 && !sticky)
            {
                return Err(Error::StateUnavailable);
            }
        }
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error::StateUnavailable)?;
        let m = fd.metadata().map_err(|_| Error::StateUnavailable)?;
        if m.uid() != owner || m.gid() != group || m.mode() & 0o7777 != 0o700 {
            return Err(Error::StateUnavailable);
        }
        let value = Self {
            path: path.into(),
            fd,
            owner,
            group,
        };
        value.check()?;
        Ok(value)
    }
    fn ensure(path: &Path, owner: u32, group: u32) -> Result<Self, Error> {
        if fs::symlink_metadata(path).is_ok() {
            return Self::open(path, owner, group);
        }
        let parent = path.parent().ok_or(Error::StateUnavailable)?;
        let parent = Self::open(parent, owner, group)?;
        let name = CString::new(
            path.file_name()
                .ok_or(Error::StateUnavailable)?
                .as_encoded_bytes(),
        )
        .map_err(|_| Error::StateUnavailable)?;
        let created = crate::openbsd::private_directory_create(&parent.fd, &name)
            .map_err(|_| Error::StateUnavailable)?;
        let fd = crate::openbsd::private_leaf_open(
            &parent.fd,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .map_err(|_| Error::StateUnavailable)?;
        if created {
            let m = fd.metadata().map_err(|_| Error::StateUnavailable)?;
            if m.uid() != crate::openbsd::effective_uid() || m.mode() & 0o7777 != 0o700 {
                return Err(Error::StateUnavailable);
            }
            crate::openbsd::private_file_set_owner(&fd, owner, group)
                .map_err(|_| Error::StateUnavailable)?;
            fd.sync_all().map_err(|_| Error::StateUnavailable)?;
            parent.fd.sync_all().map_err(|_| Error::StateUnavailable)?;
        }
        Self::open(path, owner, group)
    }
    fn check(&self) -> Result<(), Error> {
        let m = fs::symlink_metadata(&self.path).map_err(|_| Error::StateUnavailable)?;
        let fd = self.fd.metadata().map_err(|_| Error::StateUnavailable)?;
        if !m.is_dir()
            || (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())
                != (fd.dev(), fd.ino(), self.owner, self.group, fd.mode())
            || m.mode() & 0o7777 != 0o700
        {
            return Err(Error::StateUnavailable);
        }
        Ok(())
    }
    fn read(&self, name: &str) -> Result<(Vec<u8>, Identity), Error> {
        self.check()?;
        let name = CString::new(name).map_err(|_| Error::Refused)?;
        let mut file = crate::openbsd::private_leaf_open(&self.fd, &name, libc::O_RDONLY)
            .map_err(|_| Error::StateUnavailable)?;
        let m = file.metadata().map_err(|_| Error::StateUnavailable)?;
        if !m.is_file()
            || m.uid() != self.owner
            || m.gid() != self.group
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() == 0
            || m.len() > 4096
        {
            return Err(Error::StateUnavailable);
        }
        let identity = (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec());
        let mut bytes = Vec::new();
        (&mut file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::StateUnavailable)?;
        let after = file.metadata().map_err(|_| Error::StateUnavailable)?;
        if identity
            != (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
            )
            || bytes.len() > 4096
        {
            return Err(Error::StateUnavailable);
        }
        self.check()?;
        Ok((bytes, identity))
    }
    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        self.check()?;
        let name = CString::new(name).map_err(|_| Error::Refused)?;
        let mut file = crate::openbsd::private_leaf_open(
            &self.fd,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| Error::FactorWrite)?;
        crate::openbsd::private_file_set_owner(&file, self.owner, self.group)
            .map_err(|_| Error::FactorWrite)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::FactorWrite)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| self.fd.sync_all())
            .map_err(|_| Error::FactorWrite)?;
        if self.read(name.to_str().map_err(|_| Error::FactorWrite)?)?.0 != bytes {
            return Err(Error::FactorWrite);
        }
        Ok(())
    }
    fn rename(&self, from: &str, to: &str) -> Result<(), Error> {
        self.check()?;
        let from = CString::new(from).map_err(|_| Error::Refused)?;
        let to = CString::new(to).map_err(|_| Error::Refused)?;
        crate::openbsd::private_leaf_rename(&self.fd, &from, &to)
            .and_then(|_| self.fd.sync_all())
            .map_err(|_| Error::FactorWrite)?;
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_password_state::State;
    use crate::session::{FileSessionStore, SessionRecord, SessionStore};
    use crate::totp::{
        decode_base32, generate_totp_code, FileTotpSecretStore, TimeProvider, TotpPolicy,
        TotpSecretStore,
    };
    use crate::totp_enrollment::EnrollmentStore;
    use std::cell::Cell;
    const ACCOUNT: &str = "alice@factor.invalid";
    const OTHER: &str = "bob@factor.invalid";
    const OLD: &[u8] = b"# public RFC fixture\nsecret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n";
    const OLD_TIME: &str = "20261018000000";
    struct Fixture {
        root: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    impl Fixture {
        fn new() -> Self {
            Self::new_in(&std::env::temp_dir())
        }
        fn new_in(parent: &Path) -> Self {
            let root = parent.join(format!(
                "osmap-factor-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            for name in ["epoch", "sessions", "factors", "cases"] {
                fs::create_dir(root.join(name)).unwrap();
                fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
            }
            let value = Self { root };
            for (account, epoch) in [(ACCOUNT, 3), (OTHER, 8)] {
                let stem =
                    hash(&[b"osmap-account-epoch-v1\0".as_slice(), account.as_bytes()].concat());
                value.write(&value.root.join(format!("epoch/{stem}.lock")), b"");
                value.write(&value.root.join(format!("epoch/{stem}.json")), &serde_json::to_vec(&serde_json::json!({"epoch":epoch,"state":"active","changed_at":OLD_TIME,"intent":null,"used_intents":[]})).unwrap());
                value.write(
                    &value.root.join("factors").join(leaf(account).unwrap()),
                    OLD,
                );
            }
            value.write(&value.root.join("sessions/.session-store.lock"), b"");
            let sessions = value.sessions();
            for (letter, account, epoch) in [
                ('a', ACCOUNT, Some(3)),
                ('b', ACCOUNT, None),
                ('c', OTHER, Some(8)),
            ] {
                sessions
                    .save(&SessionRecord {
                        session_id: letter.to_string().repeat(64),
                        csrf_token: "f".repeat(64),
                        canonical_username: account.into(),
                        issued_at: 1,
                        expires_at: u64::MAX,
                        last_seen_at: 1,
                        revoked_at: None,
                        remote_addr: "127.0.0.1".into(),
                        user_agent: "Synthetic".into(),
                        factor: crate::auth::RequiredSecondFactor::Totp,
                        account_epoch: epoch,
                    })
                    .unwrap();
            }
            value
        }
        fn write(&self, path: &Path, bytes: &[u8]) {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn coordinator(&self) -> Coordinator {
            let group = fs::metadata(&self.root).unwrap().gid();
            Coordinator::new(Paths {
                epoch: self.root.join("epoch"),
                cases: self.root.join("cases"),
                sessions: self.root.join("sessions"),
                factors: self.root.join("factors"),
                archive: self.root.join("archive"),
                operator_uid: crate::openbsd::effective_uid(),
                runtime_uid: crate::openbsd::effective_uid(),
                runtime_gid: group,
            })
        }
        fn sessions(&self) -> FileSessionStore {
            FileSessionStore::new(self.root.join("sessions"))
        }
        fn factor(&self) -> PathBuf {
            self.root.join("factors").join(leaf(ACCOUNT).unwrap())
        }
        fn status(&self) -> crate::account_password_state::Status {
            let store =
                Store::open(&self.root.join("epoch"), crate::openbsd::effective_uid()).unwrap();
            let guard = store.lock_before(ACCOUNT, deadline()).unwrap();
            guard.status().unwrap()
        }
        fn proof(&self) -> VerifiedEnrollment {
            let enroll = EnrollmentStore::new(self.root.join("enrollment"));
            let pending = enroll
                .begin(
                    EnrollmentBinding {
                        account: ACCOUNT.into(),
                        session_id: "a".repeat(64),
                        epoch: 3,
                        expected_factor_sha256: hash(OLD),
                    },
                    0,
                    100,
                    deadline(),
                )
                .unwrap();
            let secret = decode_base32(&pending.secret_base32).unwrap();
            let code = generate_totp_code(&secret, 4, TotpPolicy::default()).unwrap();
            enroll
                .verify(
                    &EnrollmentBinding {
                        account: ACCOUNT.into(),
                        session_id: "a".repeat(64),
                        epoch: 3,
                        expected_factor_sha256: hash(OLD),
                    },
                    &pending.id,
                    pending.revision,
                    &code,
                    120,
                    deadline(),
                )
                .unwrap()
        }
    }
    #[test]
    fn descriptor_snapshot_and_current_code_are_pure() {
        let f = Fixture::new();
        let coordinator = f.coordinator();
        assert_eq!(
            coordinator.snapshot(ACCOUNT, deadline()).unwrap(),
            (3, hash(OLD))
        );
        assert!(coordinator
            .verify_current_code(ACCOUNT, "287082", 59, deadline())
            .unwrap());
        assert!(!coordinator
            .verify_current_code(ACCOUNT, "not-six", 59, deadline())
            .unwrap());
        assert_eq!(fs::read(f.factor()).unwrap(), OLD);
        assert_eq!(f.status().state, State::Active);
        assert!(f
            .sessions()
            .load(&"a".repeat(64))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none());
    }
    #[test]
    fn logout_or_wrong_session_proof_before_containment_has_zero_effects() {
        for reason in ["logout", "csrf", "idle", "epoch"] {
            let f = Fixture::new();
            let proof = f.proof();
            let mut record = f.sessions().load(&"a".repeat(64)).unwrap().unwrap();
            match reason {
                "logout" => record.revoked_at = Some(119),
                "epoch" => record.account_epoch = Some(2),
                _ => {}
            }
            f.sessions().save(&record).unwrap();
            let called = Cell::new(false);
            let csrf = if reason == "csrf" {
                "e".repeat(64)
            } else {
                "f".repeat(64)
            };
            assert_eq!(
                f.coordinator().replace_session(
                    proof,
                    &csrf,
                    if reason == "idle" { 60 } else { 1800 },
                    120,
                    deadline(),
                    || {
                        called.set(true);
                        Ok(None)
                    },
                ),
                Err(Error::Refused),
                "{reason}",
            );
            assert!(!called.get());
            assert_eq!(f.status().state, State::Active);
            assert_eq!(f.status().epoch, 3);
            assert_eq!(fs::read(f.factor()).unwrap(), OLD);
            assert!(!f.root.join("archive").exists());
            assert!(f.coordinator().files().read(ACCOUNT).unwrap().is_none());
        }
    }
    #[test]
    fn signed_in_lease_drops_after_pending_before_revocation_relocks() {
        let f = Fixture::new();
        let receipt = f
            .coordinator()
            .replace_session(f.proof(), &"f".repeat(64), 1800, 120, deadline(), || {
                assert_eq!(f.status().state, State::Pending);
                assert!(f
                    .sessions()
                    .load(&"a".repeat(64))
                    .unwrap()
                    .unwrap()
                    .revoked_at
                    .is_some());
                Ok(None)
            })
            .unwrap();
        assert_eq!(receipt.epoch, 4);
        assert_eq!(receipt.revoked_sessions, 2);
    }
    #[test]
    fn actual_factor_session_and_epoch_effects_complete_before_release() {
        let f = Fixture::new();
        let proof = f.proof();
        let id = proof.id().to_string();
        let secret = decode_base32(proof.secret_base32()).unwrap();
        let foreign = fs::read(
            f.root
                .join("sessions")
                .join(format!("{}.session", "c".repeat(64))),
        )
        .unwrap();
        let receipt = f
            .coordinator()
            .replace(proof, 120, deadline(), || {
                assert_eq!(f.status().state, State::Pending);
                assert_eq!(f.status().epoch, 3);
                assert!(f
                    .sessions()
                    .load(&"a".repeat(64))
                    .unwrap()
                    .unwrap()
                    .revoked_at
                    .is_some());
                assert_ne!(fs::read(f.factor()).unwrap(), OLD);
                Ok(None)
            })
            .unwrap();
        assert_eq!(receipt.epoch, 4);
        assert_eq!(receipt.revoked_sessions, 2);
        assert_eq!(receipt.password_changed_at.as_deref(), Some(OLD_TIME));
        assert_eq!(f.status().state, State::Active);
        assert_eq!(
            FileTotpSecretStore::new(f.root.join("factors"))
                .load_secret(ACCOUNT)
                .unwrap()
                .unwrap()
                .secret_bytes,
            secret
        );
        let archived = f.root.join("archive").join(format!(
            "{}.{}.revoked.totp",
            leaf(ACCOUNT).unwrap().trim_end_matches(".totp"),
            id
        ));
        assert_eq!(fs::read(archived).unwrap(), OLD);
        assert_eq!(
            fs::read(
                f.root
                    .join("sessions")
                    .join(format!("{}.session", "c".repeat(64)))
            )
            .unwrap(),
            foreign
        );
        assert_eq!(f.coordinator().snapshot(ACCOUNT, deadline()).unwrap().0, 4);
    }
    #[test]
    fn password_receipt_timestamp_changes_inside_same_fence() {
        let f = Fixture::new();
        let proof = f.proof();
        let receipt = f
            .coordinator()
            .replace(proof, 120, deadline(), || {
                assert_eq!(f.status().state, State::Pending);
                Ok(Some("20261030090000".into()))
            })
            .unwrap();
        assert_eq!(receipt.epoch, 4);
        assert_eq!(
            receipt.password_changed_at.as_deref(),
            Some("20261030090000")
        );
        assert_eq!(f.status().changed_at, receipt.password_changed_at);
    }
    #[test]
    fn failed_password_callback_never_releases_or_restores_old_factor() {
        let f = Fixture::new();
        let proof = f.proof();
        assert_eq!(
            f.coordinator()
                .replace(proof, 120, deadline(), || Err(Error::PasswordReset)),
            Err(Error::PasswordReset)
        );
        assert_eq!(f.status().state, State::Pending);
        assert_eq!(f.status().epoch, 3);
        assert_ne!(fs::read(f.factor()).unwrap(), OLD);
        assert!(f
            .sessions()
            .load(&"a".repeat(64))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
        assert_eq!(
            f.coordinator().snapshot(ACCOUNT, deadline()),
            Err(Error::Refused)
        );
    }
    #[test]
    fn factor_race_or_expired_proof_has_no_active_effects() {
        let f = Fixture::new();
        let proof = f.proof();
        let called = Cell::new(false);
        f.write(
            &f.factor(),
            b"# concurrent public fixture\nsecret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n",
        );
        assert_eq!(
            f.coordinator().replace(proof, 120, deadline(), || {
                called.set(true);
                Ok(None)
            }),
            Err(Error::FactorChanged)
        );
        assert!(!called.get());
        assert_eq!(f.status().state, State::Active);
        let g = Fixture::new();
        let proof = g.proof();
        let expires = proof.expires_at();
        assert_eq!(
            g.coordinator()
                .replace(proof, expires, deadline(), || Ok(None)),
            Err(Error::Expired)
        );
        assert_eq!(fs::read(g.factor()).unwrap(), OLD);
        assert_eq!(g.status().state, State::Active);
    }
    #[test]
    fn symlinked_archive_is_never_followed_and_failure_stays_fenced() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let proof = f.proof();
        let target = f.root.join("unrelated");
        fs::create_dir(&target).unwrap();
        symlink(&target, f.root.join("archive")).unwrap();
        assert_eq!(
            f.coordinator().replace(proof, 120, deadline(), || Ok(None)),
            Err(Error::FactorWrite)
        );
        assert_eq!(fs::read(f.factor()).unwrap(), OLD);
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
        assert_eq!(f.status().state, State::Pending);
    }

    /// Qualifies root/runtime custody using only freshly created synthetic
    /// files. Ordinary local suites neither need root nor dispatch this test.
    #[test]
    #[ignore = "OpenBSD root-only disposable mixed-owner factor/session replacement"]
    fn native_mixed_owner_replacement() {
        assert!(
            crate::openbsd::password_native_authority(),
            "NATIVE_PLATFORM_REQUIRED"
        );
        assert_eq!(crate::openbsd::effective_uid(), 0, "NATIVE_ROOT_REQUIRED");
        let (uid, gid) =
            crate::openbsd::osmap_runtime_identity().expect("NATIVE_RUNTIME_IDENTITY_UNAVAILABLE");
        assert_ne!(uid, 0, "NATIVE_DISTINCT_RUNTIME_REQUIRED");
        // Never invoke Fixture's ordinary recursive cleanup on native failure.
        // The root fixture must not inherit an unprivileged build actor's
        // TMPDIR ancestry: production custody correctly refuses that owner.
        let f = std::mem::ManuallyDrop::new(Fixture::new_in(Path::new("/tmp")));
        let root_identity = fs::symlink_metadata(&f.root).unwrap();
        let phase = Cell::new("fixture_ownership");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = |path: &Path, user: u32, group: u32| {
                let metadata = fs::symlink_metadata(path).expect("NATIVE_METADATA_UNAVAILABLE");
                assert!(!metadata.file_type().is_symlink(), "NATIVE_UNEXPECTED_LINK");
                let fd = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(path)
                    .expect("NATIVE_OWNERSHIP_OPEN_FAILED");
                crate::openbsd::private_file_set_owner(&fd, user, group)
                    .expect("NATIVE_OWNERSHIP_CHANGE_FAILED");
            };
            owner(&f.root, 0, 0);
            for name in ["epoch", "cases"] {
                owner(&f.root.join(name), 0, 0);
                for entry in fs::read_dir(f.root.join(name)).unwrap() {
                    owner(&entry.unwrap().path(), 0, 0);
                }
            }
            let now = crate::totp::SystemTimeProvider.unix_timestamp();
            for letter in ['a', 'b', 'c'] {
                let mut record = f
                    .sessions()
                    .load(&letter.to_string().repeat(64))
                    .unwrap()
                    .unwrap();
                record.issued_at = now - 10;
                record.last_seen_at = now;
                record.expires_at = now + 3600;
                f.sessions().save(&record).unwrap();
            }
            let runtime = f.root.join("runtime");
            fs::create_dir(&runtime).unwrap();
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
            owner(&runtime, uid, gid);
            for name in ["sessions", "factors"] {
                let destination = runtime.join(name);
                fs::rename(f.root.join(name), &destination).unwrap();
                owner(&destination, uid, gid);
                for entry in fs::read_dir(&destination).unwrap() {
                    owner(&entry.unwrap().path(), uid, gid);
                }
            }
            let coordinator = Coordinator::new(Paths {
                epoch: f.root.join("epoch"),
                cases: f.root.join("cases"),
                sessions: runtime.join("sessions"),
                factors: runtime.join("factors"),
                archive: runtime.join("revoked"),
                operator_uid: 0,
                runtime_uid: uid,
                runtime_gid: gid,
            });
            phase.set("parent_seal");
            let mut parent = crate::account_password_confinement::ParentPlan::access_fixture(
                &f.root,
                deadline(),
            )
            .expect("NATIVE_PARENT_PLAN_REFUSED");
            let seal =
                crate::openbsd::seal_password_parent(&parent).expect("NATIVE_PARENT_SEAL_REFUSED");
            parent
                .activate(seal)
                .expect("NATIVE_PARENT_ACTIVATION_REFUSED");
            parent
                .recheck(deadline())
                .expect("NATIVE_PARENT_CUSTODY_REFUSED");
            phase.set("snapshot_current_code");
            assert_eq!(
                coordinator.snapshot(ACCOUNT, deadline()).unwrap(),
                (3, hash(OLD))
            );
            let current_code = generate_totp_code(
                &decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
                now / 30,
                TotpPolicy::default(),
            )
            .unwrap();
            assert!(coordinator
                .verify_current_code(ACCOUNT, &current_code, now, deadline())
                .unwrap());
            let foreign_session = runtime
                .join("sessions")
                .join(format!("{}.session", "c".repeat(64)));
            let foreign_before = fs::read(&foreign_session).unwrap();
            let foreign_epoch = f.root.join("epoch").join(format!(
                "{}.json",
                hash(&[b"osmap-account-epoch-v1\0".as_slice(), OTHER.as_bytes()].concat())
            ));
            let epoch_before = fs::read(&foreign_epoch).unwrap();
            phase.set("candidate_proof");
            let binding = EnrollmentBinding {
                account: ACCOUNT.into(),
                session_id: "a".repeat(64),
                epoch: 3,
                expected_factor_sha256: hash(OLD),
            };
            let enroll = EnrollmentStore::new(f.root.join("enrollment"));
            let pending = enroll.begin(binding.clone(), 0, now, deadline()).unwrap();
            let replacement_secret = decode_base32(&pending.secret_base32).unwrap();
            let code =
                generate_totp_code(&replacement_secret, now / 30, TotpPolicy::default()).unwrap();
            let verified = enroll
                .verify(
                    &binding,
                    &pending.id,
                    pending.revision,
                    &code,
                    now,
                    deadline(),
                )
                .unwrap();
            owner(&f.root.join("enrollment"), 0, 0);
            for entry in fs::read_dir(f.root.join("enrollment")).unwrap() {
                owner(&entry.unwrap().path(), 0, 0);
            }
            phase.set("native_activation");
            let callback_seen = Cell::new(false);
            let receipt = coordinator
                .replace_session(verified, &"f".repeat(64), 1800, now, deadline(), || {
                    phase.set("pending_callback");
                    assert_eq!(f.status().state, State::Pending);
                    assert_eq!(f.status().epoch, 3);
                    assert_eq!(
                        crate::session::verify_recovery_sessions(
                            &runtime.join("sessions"),
                            uid,
                            gid,
                            ACCOUNT,
                            3,
                            now,
                            deadline(),
                        )
                        .unwrap()
                        .verified,
                        2
                    );
                    callback_seen.set(true);
                    Ok(None)
                })
                .unwrap();
            phase.set("final_readback");
            assert!(callback_seen.get());
            assert_eq!(receipt.epoch, 4);
            assert_eq!(receipt.revoked_sessions, 2);
            assert_eq!(receipt.password_changed_at.as_deref(), Some(OLD_TIME));
            assert_eq!(f.status().state, State::Active);
            let (epoch, digest) = coordinator.snapshot(ACCOUNT, deadline()).unwrap();
            assert_eq!(epoch, 4);
            assert_eq!(digest, receipt.factor_sha256);
            let active = coordinator
                .factors()
                .unwrap()
                .read(&leaf(ACCOUNT).unwrap())
                .unwrap()
                .0;
            assert!(
                parse_secret_file(std::str::from_utf8(&active).unwrap())
                    .unwrap()
                    .unwrap()
                    .secret_bytes
                    == replacement_secret
            );
            let archive = Directory::open(&runtime.join("revoked"), uid, gid).unwrap();
            assert!(
                archive
                    .read(&format!(
                        "{}.{}.revoked.totp",
                        leaf(ACCOUNT).unwrap().trim_end_matches(".totp"),
                        pending.id
                    ))
                    .unwrap()
                    .0
                    == OLD
            );
            assert!(fs::read(&foreign_session).unwrap() == foreign_before);
            assert!(fs::read(&foreign_epoch).unwrap() == epoch_before);
            assert!(
                coordinator
                    .factors()
                    .unwrap()
                    .read(&leaf(OTHER).unwrap())
                    .unwrap()
                    .0
                    == OLD
            );
            for (path, owner, group) in [(&f.root, 0, 0), (&runtime, uid, gid)] {
                let m = fs::symlink_metadata(path).unwrap();
                assert!(m.is_dir());
                assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (owner, group, 0o700));
            }
            for directory in ["sessions", "factors", "revoked"] {
                let directory = runtime.join(directory);
                let m = fs::symlink_metadata(&directory).unwrap();
                assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (uid, gid, 0o700));
                for entry in fs::read_dir(directory).unwrap() {
                    let m = fs::symlink_metadata(entry.unwrap().path()).unwrap();
                    assert!(m.is_file());
                    assert_eq!(
                        (m.uid(), m.gid(), m.mode() & 0o7777, m.nlink()),
                        (uid, gid, 0o600, 1)
                    );
                }
            }
            for directory in ["epoch", "cases", "enrollment"] {
                let directory = f.root.join(directory);
                let m = fs::symlink_metadata(&directory).unwrap();
                assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (0, 0, 0o700));
                for entry in fs::read_dir(directory).unwrap() {
                    let m = fs::symlink_metadata(entry.unwrap().path()).unwrap();
                    assert_eq!(
                        (m.uid(), m.gid(), m.mode() & 0o7777, m.nlink()),
                        (0, 0, 0o600, 1)
                    );
                }
            }
        }));
        if let Err(panic) = outcome {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "test":"native_mixed_owner_replacement", "outcome":"FAIL",
                "phase":phase.get(), "cleanup":"RETAINED_UNCERTAIN"
            }))
            .unwrap();
            let path = f.root.join("native-failure.json");
            let receipt_confirmed = if let Ok(mut file) = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .and_then(|_| File::open(&f.root)?.sync_all())
                    .and_then(|_| fs::read(f.root.join("native-failure.json")))
                    .is_ok_and(|observed| observed == bytes)
            } else {
                false
            };
            eprintln!(
                "native_mixed_owner_replacement phase={} cleanup=RETAINED_UNCERTAIN receipt_confirmed={receipt_confirmed} fixture_root={}",
                phase.get(),
                f.root.display(),
            );
            std::panic::resume_unwind(panic);
        }
        let current = fs::symlink_metadata(&f.root).unwrap();
        assert_eq!(
            (current.dev(), current.ino(), current.uid()),
            (root_identity.dev(), root_identity.ino(), 0),
            "NATIVE_CLEANUP_IDENTITY_REFUSED"
        );
        fs::remove_dir_all(&f.root).expect("NATIVE_EXACT_FIXTURE_CLEANUP_FAILED");
    }
}
