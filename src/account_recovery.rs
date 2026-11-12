//! Operator-side recovery coordination over actual account, session and factor
//! stores. The SSH/private-terminal adapter verifies independent human approval;
//! this module never authenticates a claimant or grants browser administration.
use crate::account_password_state::{RecoveryMarker, State, Store};
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const SCHEMA: &str = "osmap-account-recovery-v1";
pub const VALIDATION_ACCOUNT: &str = "osmap-helper-validation@blackbagsecurity.com";
const MAX_CASE_BYTES: usize = 16384;
#[cfg(test)]
std::thread_local! {
    static INTERRUPT_AFTER_RELEASE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMethod {
    InPerson,
    EstablishedOutOfBand,
    ControlledTestCustody,
}

/// Contains opaque authorization references and digests only, never passwords,
/// factor seeds, verification codes or private identity evidence.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub account: String,
    pub case_id: String,
    pub expected_epoch: u64,
    pub previous_factor_sha256: String,
    pub approval_sha256: String,
    pub identity_method: IdentityMethod,
    pub identity_case: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub replacement_factor_sha256: Option<String>,
    #[serde(default)]
    pub revoke_stamp: Option<String>,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryRequest(<private>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseState {
    Requested,
    IdentityReviewed,
    Contained,
    SessionsRevoked,
    FactorReplacement,
    ReleasePending,
    Reconciled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidRequest,
    Unauthorized,
    Expired,
    Busy,
    StateUnavailable,
    CaseWrite,
    CaseMismatch,
    Replay,
    FactorMismatch,
    EpochMismatch,
    ContainmentIncomplete,
    SessionsIncomplete,
    ReconciliationRequired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionFailureStage {
    Input,
    Lock,
    Snapshot,
    Write,
    Readback,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionFailure {
    pub stage: SessionFailureStage,
    pub attempted_writes: usize,
    pub completed_writes: usize,
}
impl From<crate::session::RecoveryRevocationFailure> for SessionFailure {
    fn from(value: crate::session::RecoveryRevocationFailure) -> Self {
        use crate::session::RecoveryRevocationStage as Stage;
        Self {
            stage: match value.stage {
                Stage::Input => SessionFailureStage::Input,
                Stage::Lock => SessionFailureStage::Lock,
                Stage::Snapshot => SessionFailureStage::Snapshot,
                Stage::Write => SessionFailureStage::Write,
                Stage::Readback => SessionFailureStage::Readback,
            },
            attempted_writes: value.attempted_writes,
            completed_writes: value.completed_writes,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        if value.kind() == std::io::ErrorKind::WouldBlock {
            Self::Busy
        } else {
            Self::StateUnavailable
        }
    }
}
#[derive(Serialize)]
pub struct Status {
    pub schema: &'static str,
    pub account: String,
    pub state: &'static str,
    pub epoch: u64,
    pub existing_factor_sha256: Option<String>,
    pub case_id: Option<String>,
    pub case_state: Option<CaseState>,
    pub failure: Option<Error>,
    pub session_failure: Option<SessionFailure>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    schema: String,
    account: String,
    case_id: String,
    expected_epoch: u64,
    previous_factor_sha256: String,
    approval_sha256: String,
    identity_method: IdentityMethod,
    identity_case: String,
    issued_at: u64,
    expires_at: u64,
    intent: String,
    marker: Option<RecoveryMarker>,
    state: CaseState,
    replacement_factor_sha256: Option<String>,
    revoke_stamp: Option<String>,
    revoked_sessions: Option<usize>,
    password_changed_at: Option<String>,
    failure: Option<Error>,
    session_failure: Option<SessionFailure>,
}

pub(crate) struct Paths {
    pub epoch: PathBuf,
    pub cases: PathBuf,
    pub sessions: PathBuf,
    pub factors: PathBuf,
    pub revoked: PathBuf,
    pub operator_uid: u32,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
}
pub(crate) struct Coordinator {
    paths: Paths,
}

fn reference(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._-".contains(&v))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn stamp(value: &str) -> bool {
    value.len() == 16
        && value.as_bytes()[8] == b'T'
        && value.as_bytes()[15] == b'Z'
        && value
            .bytes()
            .enumerate()
            .all(|(i, v)| matches!(i, 8 | 15) || v.is_ascii_digit())
}
fn before(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn authorized_deadline(request: &Request, now: u64, original: Instant) -> Result<Instant, Error> {
    request.validate(now, true)?;
    Instant::now()
        .checked_add(Duration::from_secs(request.expires_at - now))
        .map(|expiry| original.min(expiry))
        .ok_or(Error::Expired)
}
impl Request {
    fn validate(&self, now: u64, fresh: bool) -> Result<(), Error> {
        crate::account_admission::valid_account(&self.account)
            .map_err(|_| Error::InvalidRequest)?;
        if self.schema != SCHEMA
            || !reference(&self.case_id)
            || !reference(&self.identity_case)
            || !digest(&self.previous_factor_sha256)
            || !digest(&self.approval_sha256)
            || self.expected_epoch >= crate::account_admission::MAX_EPOCH
            || self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 900
            || self
                .replacement_factor_sha256
                .as_deref()
                .is_some_and(|v| !digest(v) || v == self.previous_factor_sha256)
            || self.revoke_stamp.as_deref().is_some_and(|v| !stamp(v))
        {
            return Err(Error::InvalidRequest);
        }
        if self.identity_method == IdentityMethod::ControlledTestCustody
            && self.account != VALIDATION_ACCOUNT
        {
            return Err(Error::Unauthorized);
        }
        if fresh && !(self.issued_at <= now && now < self.expires_at) {
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn intent(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"osmap-governed-factor-recovery-v1\0");
        for part in [&self.account, &self.case_id, &self.approval_sha256] {
            hash.update(part.as_bytes());
            hash.update(b"\0");
        }
        hash.update(self.expected_epoch.to_be_bytes());
        format!("{:x}", hash.finalize())
    }
}
impl Case {
    fn matches(&self, request: &Request) -> bool {
        self.schema == SCHEMA
            && self.account == request.account
            && self.case_id == request.case_id
            && self.expected_epoch == request.expected_epoch
            && self.previous_factor_sha256 == request.previous_factor_sha256
            && self.approval_sha256 == request.approval_sha256
            && self.identity_method == request.identity_method
            && self.identity_case == request.identity_case
            && self.issued_at == request.issued_at
            && self.expires_at == request.expires_at
            && self.intent == request.intent()
    }
}
impl Coordinator {
    pub(crate) fn new(paths: Paths) -> Self {
        Self { paths }
    }
    fn files(&self) -> PrivateAccountFile {
        PrivateAccountFile::new(self.paths.cases.clone(), SCHEMA, MAX_CASE_BYTES)
    }
    fn epoch(&self) -> Result<Store, Error> {
        Store::open(&self.paths.epoch, self.paths.operator_uid).map_err(|_| Error::StateUnavailable)
    }
    fn load(&self, locked: &LockedAccountFile) -> Result<Option<Case>, Error> {
        locked
            .read()?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| Error::StateUnavailable))
            .transpose()
    }
    fn save(&self, locked: &LockedAccountFile, case: &Case) -> Result<(), Error> {
        let bytes = serde_json::to_vec(case).map_err(|_| Error::CaseWrite)?;
        locked.write(&bytes).map_err(|_| Error::CaseWrite)?;
        if locked.read().map_err(|_| Error::CaseWrite)?.as_deref() != Some(&bytes) {
            return Err(Error::CaseWrite);
        }
        Ok(())
    }
    fn failed(&self, locked: &LockedAccountFile, case: &mut Case, error: Error) -> Error {
        if case.failure.is_none() {
            case.failure = Some(error);
        }
        let _ = self.save(locked, case);
        error
    }
    fn session_failed(
        &self,
        locked: &LockedAccountFile,
        case: &mut Case,
        failure: crate::session::RecoveryRevocationFailure,
    ) -> Error {
        if case.session_failure.is_none() {
            case.session_failure = Some(failure.into());
        }
        self.failed(locked, case, Error::SessionsIncomplete)
    }
    fn factor_path(&self, account: &str) -> PathBuf {
        let name: String = account
            .as_bytes()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect();
        self.paths.factors.join(format!("{name}.totp"))
    }
    fn archived_path(&self, account: &str, value: &str) -> PathBuf {
        let name: String = account
            .as_bytes()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect();
        self.paths
            .revoked
            .join(format!("{name}.{value}.revoked.totp"))
    }
    fn factor_digest(&self, path: &Path) -> Result<Option<String>, Error> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let mut file = match options.open(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.paths.runtime_uid
            || metadata.gid() != self.paths.runtime_gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() == 0
            || metadata.len() > 16384
        {
            return Err(Error::StateUnavailable);
        }
        let mut bytes = Vec::new();
        (&mut file).take(16385).read_to_end(&mut bytes)?;
        let after = fs::symlink_metadata(path)?;
        if bytes.len() > 16384
            || (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
            ) != (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            )
        {
            return Err(Error::StateUnavailable);
        }
        Ok(Some(format!("{:x}", Sha256::digest(&bytes))))
    }
    pub(crate) fn status(&self, account: &str, deadline: Instant) -> Result<Status, Error> {
        crate::account_admission::valid_account(account).map_err(|_| Error::InvalidRequest)?;
        before(deadline)?;
        let store = self.epoch()?;
        let status = store
            .lock_before(account, deadline)
            .map_err(|_| Error::StateUnavailable)?
            .status()
            .map_err(|_| Error::StateUnavailable)?;
        let case: Option<Case> = self
            .files()
            .read(account)?
            .map(|v| serde_json::from_slice(&v).map_err(|_| Error::StateUnavailable))
            .transpose()?;
        if case
            .as_ref()
            .is_some_and(|v| v.schema != SCHEMA || v.account != account)
        {
            return Err(Error::CaseMismatch);
        }
        let factor = self.factor_digest(&self.factor_path(account))?;
        before(deadline)?;
        Ok(Status {
            schema: SCHEMA,
            account: account.into(),
            state: match status.state {
                State::Active => "active",
                State::Pending => "pending",
                State::Contained => "contained",
            },
            epoch: status.epoch,
            existing_factor_sha256: factor,
            case_id: case.as_ref().map(|v| v.case_id.clone()),
            case_state: case.as_ref().map(|v| v.state),
            failure: case.as_ref().and_then(|v| v.failure),
            session_failure: case.and_then(|v| v.session_failure),
        })
    }
    pub(crate) fn begin(
        &self,
        request: &Request,
        now: u64,
        deadline: Instant,
    ) -> Result<Status, Error> {
        let deadline = authorized_deadline(request, now, deadline)?;
        if request.replacement_factor_sha256.is_some() || request.revoke_stamp.is_some() {
            return Err(Error::InvalidRequest);
        }
        before(deadline)?;
        let locked = self.files().lock(&request.account)?;
        if let Some(previous) = self.load(&locked)? {
            if previous.state != CaseState::Reconciled
                || previous.case_id == request.case_id
                || previous.intent == request.intent()
            {
                return Err(Error::Replay);
            }
        }
        if self
            .factor_digest(&self.factor_path(&request.account))?
            .as_deref()
            != Some(&request.previous_factor_sha256)
        {
            return Err(Error::FactorMismatch);
        }
        let epoch = self.epoch()?;
        let mut guard = epoch
            .lock_before(&request.account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        let original = guard
            .admission(Some(request.expected_epoch))
            .map_err(|_| Error::EpochMismatch)?;
        let mut case = Case {
            schema: SCHEMA.into(),
            account: request.account.clone(),
            case_id: request.case_id.clone(),
            expected_epoch: request.expected_epoch,
            previous_factor_sha256: request.previous_factor_sha256.clone(),
            approval_sha256: request.approval_sha256.clone(),
            identity_method: request.identity_method,
            identity_case: request.identity_case.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            intent: request.intent(),
            marker: None,
            state: CaseState::Requested,
            replacement_factor_sha256: None,
            revoke_stamp: None,
            revoked_sessions: None,
            password_changed_at: original.changed_at,
            failure: None,
            session_failure: None,
        };
        self.save(&locked, &case)?;
        case.state = CaseState::IdentityReviewed;
        self.save(&locked, &case)?;
        let marker = guard
            .begin_recovery(request.expected_epoch, &case.intent, now)
            .map_err(|_| self.failed(&locked, &mut case, Error::ContainmentIncomplete))?;
        case.marker = Some(marker);
        case.state = CaseState::Contained;
        self.save(&locked, &case)?;
        // Login uses session -> epoch lock order. Release the epoch lock before
        // taking the session lock; durable Pending already denies new admission.
        drop(guard);
        let sessions: crate::session::RecoveryRevocation =
            crate::session::revoke_recovery_sessions(
                &self.paths.sessions,
                self.paths.runtime_uid,
                self.paths.runtime_gid,
                &request.account,
                request.expected_epoch,
                now,
                deadline,
            )
            .map_err(|failure| self.session_failed(&locked, &mut case, failure))?;
        let guard = epoch
            .lock_before(&request.account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        guard
            .check_recovery(request.expected_epoch, &case.intent, marker)
            .map_err(|_| Error::ContainmentIncomplete)?;
        case.revoked_sessions = Some(sessions.verified);
        case.state = CaseState::SessionsRevoked;
        self.save(&locked, &case)?;
        drop(guard);
        drop(locked);
        self.status(&request.account, deadline)
    }
    pub(crate) fn prepare_factor(
        &self,
        request: &Request,
        now: u64,
        deadline: Instant,
    ) -> Result<Status, Error> {
        let deadline = authorized_deadline(request, now, deadline)?;
        let replacement = request
            .replacement_factor_sha256
            .as_deref()
            .ok_or(Error::InvalidRequest)?;
        let revoke_stamp = request
            .revoke_stamp
            .as_deref()
            .ok_or(Error::InvalidRequest)?;
        before(deadline)?;
        let locked = self.files().lock(&request.account)?;
        let mut case = self.load(&locked)?.ok_or(Error::CaseMismatch)?;
        if !case.matches(request) {
            return Err(Error::CaseMismatch);
        }
        if case.state != CaseState::SessionsRevoked || case.failure.is_some() {
            return Err(Error::ReconciliationRequired);
        }
        let epoch = self.epoch()?;
        let guard = epoch
            .lock_before(&request.account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        guard
            .check_recovery(
                request.expected_epoch,
                &case.intent,
                case.marker.ok_or(Error::ContainmentIncomplete)?,
            )
            .map_err(|_| Error::ContainmentIncomplete)?;
        drop(guard);
        crate::session::verify_recovery_sessions(
            &self.paths.sessions,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
            &request.account,
            request.expected_epoch,
            now,
            deadline,
        )
        .map_err(|failure| self.session_failed(&locked, &mut case, failure))?;
        if self
            .factor_digest(&self.factor_path(&request.account))?
            .as_deref()
            != Some(&case.previous_factor_sha256)
            || self
                .factor_digest(&self.archived_path(&request.account, revoke_stamp))?
                .is_some()
        {
            return Err(Error::FactorMismatch);
        }
        case.replacement_factor_sha256 = Some(replacement.into());
        case.revoke_stamp = Some(revoke_stamp.into());
        // This durable state is the one-shot admission to the irreversible
        // legacy factor operation. No subsequent invocation can prepare again.
        case.state = CaseState::FactorReplacement;
        self.save(&locked, &case)?;
        drop(locked);
        self.status(&request.account, deadline)
    }
    pub(crate) fn reconcile(
        &self,
        request: &Request,
        now: u64,
        deadline: Instant,
    ) -> Result<Status, Error> {
        let deadline = authorized_deadline(request, now, deadline)?;
        before(deadline)?;
        let locked = self.files().lock(&request.account)?;
        let mut case = self.load(&locked)?.ok_or(Error::CaseMismatch)?;
        if !case.matches(request)
            || case.replacement_factor_sha256 != request.replacement_factor_sha256
            || case.revoke_stamp != request.revoke_stamp
        {
            return Err(Error::CaseMismatch);
        }
        if case.state != CaseState::FactorReplacement || case.failure.is_some() {
            return Err(Error::ReconciliationRequired);
        }
        crate::session::verify_recovery_sessions(
            &self.paths.sessions,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
            &request.account,
            request.expected_epoch,
            now,
            deadline,
        )
        .map_err(|failure| self.session_failed(&locked, &mut case, failure))?;
        let expected = case
            .replacement_factor_sha256
            .as_deref()
            .ok_or(Error::ReconciliationRequired)?;
        let revoke_stamp = case
            .revoke_stamp
            .as_deref()
            .ok_or(Error::ReconciliationRequired)?;
        if self
            .factor_digest(&self.factor_path(&request.account))?
            .as_deref()
            != Some(expected)
            || self
                .factor_digest(&self.archived_path(&request.account, revoke_stamp))?
                .as_deref()
                != Some(&case.previous_factor_sha256)
        {
            return Err(self.failed(&locked, &mut case, Error::FactorMismatch));
        }
        let epoch = self.epoch()?;
        let mut guard = epoch
            .lock_before(&request.account, deadline)
            .map_err(|_| Error::StateUnavailable)?;
        let marker = case.marker.ok_or(Error::ContainmentIncomplete)?;
        guard
            .check_recovery(request.expected_epoch, &case.intent, marker)
            .map_err(|_| Error::ContainmentIncomplete)?;
        if guard
            .status()
            .map_err(|_| Error::StateUnavailable)?
            .changed_at
            != case.password_changed_at
        {
            return Err(Error::EpochMismatch);
        }
        // Persist release admission before its effect. A crash or lost response
        // can then truthfully report Pending OR Active/epoch+1 without replaying
        // factor mutation or automatically repeating the release operation.
        case.state = CaseState::ReleasePending;
        self.save(&locked, &case)?;
        guard
            .complete_recovery(request.expected_epoch, &case.intent, marker)
            .map_err(|_| self.failed(&locked, &mut case, Error::ContainmentIncomplete))?;
        #[cfg(test)]
        if INTERRUPT_AFTER_RELEASE.with(|value| value.replace(false)) {
            return Err(Error::CaseWrite);
        }
        case.state = CaseState::Reconciled;
        self.save(&locked, &case)?;
        drop(guard);
        drop(locked);
        self.status(&request.account, deadline)
    }
}

#[cfg(test)]
#[path = "account_recovery_tests.rs"]
mod tests;
