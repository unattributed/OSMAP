//! Account-private recovery proof lifecycle; contact possession grants no login
//! or factor-reset authority. The caller supplies session/CSRF and fresh step-up.
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use crate::session::{RandomSource, SystemRandomSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const PENDING_SECONDS: u64 = 86400;
const TOKEN_SECONDS: u64 = 1800;
const MAX_BYTES: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryContactDelivery {
    Accepted,
    Refused,
    Unconfirmed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryContactNoticeKind {
    Replaced,
    Removed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryContactEffect {
    Pending,
    Verified,
    Removed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryContactError {
    Invalid,
    Authentication,
    Throttled,
    Stale,
    Busy,
    Unavailable,
    Expired,
    InvalidToken,
    NoPending,
    RateLimited { retry_at: u64 },
    DeliveryUnconfirmed,
}
impl RecoveryContactError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid => "Use one supported email address or verification code.",
            Self::Authentication => "Current password and a fresh verification code are required.",
            Self::Throttled | Self::RateLimited { .. } => "Wait before trying again.",
            Self::Stale => "Recovery contact changed. Reload before submitting again.",
            Self::Busy => "Another recovery contact change is in progress.",
            Self::Unavailable => "Recovery contact state could not be confirmed. Reload to check it.",
            Self::Expired => "This verification has expired.",
            Self::InvalidToken => "This verification code was not accepted.",
            Self::NoPending => "There is no pending recovery contact verification.",
            Self::DeliveryUnconfirmed => "Delivery is unconfirmed. Check the message or remove the pending request before starting again.",
        }
    }
}
impl From<std::io::Error> for RecoveryContactError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            Self::Busy
        } else {
            Self::Unavailable
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRecoveryContact {
    pub email: String,
    pub verified_at: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct PendingRecoveryContact {
    pub email: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub token_expires_at: u64,
    pub attempts_remaining: u8,
    pub delivery: RecoveryContactDelivery,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContactNotice {
    pub kind: RecoveryContactNoticeKind,
    pub attempted_at: u64,
    pub delivery: RecoveryContactDelivery,
    /// A later operation cannot erase a previous ambiguous old-contact notice.
    pub earlier_unconfirmed: bool,
}
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryContactSnapshot {
    pub revision: u64,
    pub verified: Option<VerifiedRecoveryContact>,
    pub pending: Option<PendingRecoveryContact>,
    pub notice: Option<RecoveryContactNotice>,
    pub resend_at: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryContactResult {
    pub snapshot: RecoveryContactSnapshot,
    pub effect: RecoveryContactEffect,
    pub delivery: Option<RecoveryContactDelivery>,
}
macro_rules! redacted_debug {
    ($($t:ty),+) => { $(impl std::fmt::Debug for $t {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($t), "(<private>)"))
        }
    })+ };
}
redacted_debug!(
    VerifiedRecoveryContact,
    PendingRecoveryContact,
    RecoveryContactSnapshot
);

pub enum RecoveryContactAction {
    Begin { email: String },
    Resend,
    Verify { token: String },
    Remove,
}
pub struct RecoveryContactMutation<'a> {
    pub account: &'a str,
    pub expected_revision: u64,
    pub now: u64,
    pub deadline: Instant,
    pub action: RecoveryContactAction,
}
pub enum RecoveryContactMessage<'a> {
    Verification {
        email: &'a str,
        token: &'a str,
        expires_at: u64,
    },
    Replaced {
        email: &'a str,
    },
    Removed {
        email: &'a str,
    },
}
redacted_debug!(
    RecoveryContactAction,
    RecoveryContactMutation<'_>,
    RecoveryContactMessage<'_>
);
/// Implementations must honor the supplied absolute deadline, never retry an
/// ambiguous send, and keep borrowed addresses/tokens out of logs and artifacts.
pub trait RecoveryContactNotifier {
    fn deliver(
        &self,
        message: RecoveryContactMessage<'_>,
        deadline: Instant,
    ) -> RecoveryContactDelivery;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    email: String,
    created_at: u64,
    expires_at: u64,
    token_issued_at: u64,
    token_expires_at: u64,
    token_digest: Option<String>,
    attempts: u8,
    delivery: RecoveryContactDelivery,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    account: String,
    revision: u64,
    updated_at: u64,
    verified: Option<VerifiedRecoveryContact>,
    pending: Option<Pending>,
    notice: Option<RecoveryContactNotice>,
    sends: Vec<u64>,
}
impl Record {
    fn empty(account: &str) -> Self {
        Self {
            version: 1,
            account: account.into(),
            revision: 0,
            updated_at: 0,
            verified: None,
            pending: None,
            notice: None,
            sends: Vec::new(),
        }
    }
    fn validate(&self, account: &str, now: u64) -> Result<(), RecoveryContactError> {
        let invalid = || RecoveryContactError::Unavailable;
        if self.version != 1
            || self.account != account
            || self.revision == 0
            || self.updated_at > now
            || self.sends.len() > 10
            || self.sends.iter().any(|t| *t > self.updated_at)
            || self
                .sends
                .windows(2)
                .any(|p| p[1].saturating_sub(p[0]) < 60)
            || self
                .sends
                .windows(4)
                .any(|p| p[3].saturating_sub(p[0]) < 3600)
        {
            return Err(invalid());
        }
        if let Some(v) = &self.verified {
            email(&v.email).map_err(|_| invalid())?;
            if v.verified_at > self.updated_at {
                return Err(invalid());
            }
        }
        if let Some(p) = &self.pending {
            email(&p.email).map_err(|_| invalid())?;
            if p.created_at > p.token_issued_at
                || p.token_issued_at > self.updated_at
                || p.created_at.checked_add(PENDING_SECONDS) != Some(p.expires_at)
                || p.token_issued_at
                    .checked_add(TOKEN_SECONDS)
                    .map(|v| v.min(p.expires_at))
                    != Some(p.token_expires_at)
                || p.token_expires_at <= p.token_issued_at
                || p.attempts > 5
                || p.token_digest.as_ref().is_some_and(|d| !hex64(d))
                || p.token_digest.is_some()
                    && (p.attempts == 5 || p.delivery == RecoveryContactDelivery::Refused)
                || p.token_digest.is_none()
                    && p.attempts < 5
                    && p.delivery != RecoveryContactDelivery::Refused
                || self.sends.last() != Some(&p.token_issued_at)
                || self.verified.as_ref().is_some_and(|v| {
                    crate::mail_address::comparison_key(&v.email)
                        == crate::mail_address::comparison_key(&p.email)
                })
            {
                return Err(invalid());
            }
        }
        if self
            .notice
            .as_ref()
            .is_some_and(|n| n.attempted_at > self.updated_at)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn snapshot(&self, now: u64) -> RecoveryContactSnapshot {
        let pending = self.pending.as_ref().filter(|p| now < p.expires_at);
        RecoveryContactSnapshot {
            revision: self.revision,
            verified: self.verified.clone(),
            pending: pending.map(|p| PendingRecoveryContact {
                email: p.email.clone(),
                created_at: p.created_at,
                expires_at: p.expires_at,
                token_expires_at: p.token_expires_at,
                attempts_remaining: 5 - p.attempts,
                delivery: p.delivery,
            }),
            notice: self.notice.clone(),
            resend_at: pending
                .filter(|p| p.delivery != RecoveryContactDelivery::Unconfirmed)
                .map(|_| self.retry_at(now)),
        }
    }
    fn retry_at(&self, now: u64) -> u64 {
        let mut at = self.sends.last().map_or(now, |t| t.saturating_add(60));
        let hour: Vec<_> = self
            .sends
            .iter()
            .filter(|t| now.saturating_sub(**t) < 3600)
            .collect();
        if hour.len() >= 3 {
            at = at.max(hour[hour.len() - 3].saturating_add(3600));
        }
        if self.sends.len() >= 10 {
            at = at.max(self.sends[0].saturating_add(86400));
        }
        at.max(now)
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryContactStore {
    file: PrivateAccountFile,
    directory: PathBuf,
}
impl RecoveryContactStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            file: PrivateAccountFile::new(
                directory.clone(),
                "osmap-recovery-contact-v1",
                MAX_BYTES,
            ),
            directory,
        }
    }
    /// Native recovery uses this read-only observation solely as a veto against
    /// an obsolete independently registered address. It never promotes a Web
    /// record into recovery authority and never creates a lock or directory.
    #[cfg(unix)]
    pub(crate) fn registered_consistency(
        &self,
        account: &str,
        now: u64,
        expected_email: &str,
        owner: u32,
        group: u32,
    ) -> Result<bool, RecoveryContactError> {
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        canonical(account)?;
        email(expected_email)?;
        if !self.directory.is_absolute() {
            return Err(RecoveryContactError::Unavailable);
        }
        for path in self.directory.ancestors().skip(1) {
            let metadata = match fs::symlink_metadata(path) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error.into()),
            };
            let root_sticky = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || (metadata.uid() != 0 && metadata.uid() != owner)
                || (metadata.mode() & 0o022 != 0 && !root_sticky)
            {
                return Err(RecoveryContactError::Unavailable);
            }
        }
        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.directory)
        {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let held = directory.metadata()?;
        if (held.uid(), held.gid(), held.mode() & 0o7777) != (owner, group, 0o700) {
            return Err(RecoveryContactError::Unavailable);
        }
        let mut hash = Sha256::new();
        hash.update(b"osmap-recovery-contact-v1\0");
        hash.update(account.as_bytes());
        let path = self.directory.join(format!("{:x}.json", hash.finalize()));
        let Some(raw) = crate::private_account_file::read_record_owned(&path, MAX_BYTES, owner)?
        else {
            return Ok(false);
        };
        let record_metadata = fs::symlink_metadata(&path)?;
        let current = fs::symlink_metadata(&self.directory)?;
        if record_metadata.gid() != group
            || (
                current.dev(),
                current.ino(),
                current.uid(),
                current.gid(),
                current.mode(),
            ) != (held.dev(), held.ino(), held.uid(), held.gid(), held.mode())
        {
            return Err(RecoveryContactError::Unavailable);
        }
        Ok(decode(account, Some(raw), now)?
            .verified
            .is_some_and(|v| v.email == expected_email))
    }
    pub fn snapshot(
        &self,
        account: &str,
        now: u64,
    ) -> Result<RecoveryContactSnapshot, RecoveryContactError> {
        canonical(account)?;
        let locked = self.file.lock(account)?;
        Ok(decode(account, locked.read()?, now)?.snapshot(now))
    }
    pub fn mutate<N, F>(
        &self,
        request: RecoveryContactMutation<'_>,
        authorize: F,
        notifier: &N,
    ) -> Result<RecoveryContactResult, RecoveryContactError>
    where
        N: RecoveryContactNotifier,
        F: FnOnce() -> Result<(), RecoveryContactError>,
    {
        self.mutate_with_random(request, authorize, notifier, &SystemRandomSource)
    }
    fn mutate_with_random<N, F, R>(
        &self,
        request: RecoveryContactMutation<'_>,
        authorize: F,
        notifier: &N,
        random: &R,
    ) -> Result<RecoveryContactResult, RecoveryContactError>
    where
        N: RecoveryContactNotifier,
        F: FnOnce() -> Result<(), RecoveryContactError>,
        R: RandomSource,
    {
        let began = Instant::now();
        canonical(request.account)?;
        if request.now.checked_add(PENDING_SECONDS).is_none() {
            return Err(RecoveryContactError::Invalid);
        }
        if began >= request.deadline {
            return Err(RecoveryContactError::Expired);
        }
        let locked = self.file.lock(request.account)?;
        let mut record = decode(request.account, locked.read()?, request.now)?;
        if record.revision != request.expected_revision {
            return Err(RecoveryContactError::Stale);
        }
        if let RecoveryContactAction::Begin { email: address } = &request.action {
            email(address)?;
        }
        let deadline = match (&request.action, &record.pending) {
            (RecoveryContactAction::Verify { .. }, Some(p)) => request.deadline.min(
                began
                    .checked_add(Duration::from_secs(
                        p.token_expires_at.saturating_sub(request.now),
                    ))
                    .ok_or(RecoveryContactError::Expired)?,
            ),
            (RecoveryContactAction::Resend, Some(p)) => request.deadline.min(
                began
                    .checked_add(Duration::from_secs(
                        p.expires_at.saturating_sub(request.now),
                    ))
                    .ok_or(RecoveryContactError::Expired)?,
            ),
            _ => request.deadline,
        };
        authorize()?;
        if Instant::now() >= deadline {
            return Err(RecoveryContactError::Expired);
        }
        let now = request
            .now
            .checked_add(began.elapsed().as_secs())
            .ok_or(RecoveryContactError::Expired)?;
        if now.checked_add(PENDING_SECONDS).is_none() {
            return Err(RecoveryContactError::Expired);
        }
        if record.pending.as_ref().is_some_and(|p| now >= p.expires_at) {
            record.pending = None;
        }
        record.sends.retain(|t| now.saturating_sub(*t) < 86400);
        record.revision = record
            .revision
            .checked_add(1)
            .ok_or(RecoveryContactError::Unavailable)?;
        record.updated_at = now;
        let (effect, delivery) = match request.action {
            RecoveryContactAction::Begin { email: address } => {
                email(&address)?;
                if record.verified.as_ref().is_some_and(|v| {
                    crate::mail_address::comparison_key(&v.email)
                        == crate::mail_address::comparison_key(&address)
                }) {
                    return Err(RecoveryContactError::Invalid);
                }
                if record
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.delivery == RecoveryContactDelivery::Unconfirmed)
                {
                    return Err(RecoveryContactError::DeliveryUnconfirmed);
                }
                let delivery = issue(
                    &locked,
                    &mut record,
                    address,
                    now,
                    now + PENDING_SECONDS,
                    deadline,
                    notifier,
                    random,
                )?;
                (RecoveryContactEffect::Pending, Some(delivery))
            }
            RecoveryContactAction::Resend => {
                let p = record
                    .pending
                    .as_ref()
                    .ok_or(RecoveryContactError::NoPending)?;
                if p.delivery == RecoveryContactDelivery::Unconfirmed {
                    return Err(RecoveryContactError::DeliveryUnconfirmed);
                }
                let (address, created, expiry) = (p.email.clone(), p.created_at, p.expires_at);
                let delivery = issue(
                    &locked,
                    &mut record,
                    address,
                    created,
                    expiry,
                    deadline,
                    notifier,
                    random,
                )?;
                (RecoveryContactEffect::Pending, Some(delivery))
            }
            RecoveryContactAction::Verify { token } => {
                let p = record
                    .pending
                    .as_mut()
                    .ok_or(RecoveryContactError::NoPending)?;
                if now >= p.token_expires_at {
                    return Err(RecoveryContactError::Expired);
                }
                if p.attempts == 5 {
                    return Err(RecoveryContactError::InvalidToken);
                }
                let valid = p.token_digest.as_ref().is_some_and(|d| {
                    hex64(&token)
                        && crate::http_support::constant_time_eq(
                            d.as_bytes(),
                            digest(request.account, &token).as_bytes(),
                        )
                });
                if !valid {
                    if p.attempts < 5 {
                        p.attempts += 1;
                    }
                    if p.attempts == 5 {
                        p.token_digest = None;
                    }
                    save(&locked, &record)?;
                    return Err(RecoveryContactError::InvalidToken);
                }
                let address = p.email.clone();
                let old = record.verified.replace(VerifiedRecoveryContact {
                    email: address,
                    verified_at: now,
                });
                record.pending = None;
                let delivery = if let Some(old) = old {
                    Some(notice(
                        &locked,
                        &mut record,
                        RecoveryContactNoticeKind::Replaced,
                        &old.email,
                        deadline,
                        notifier,
                    )?)
                } else {
                    save(&locked, &record)?;
                    None
                };
                (RecoveryContactEffect::Verified, delivery)
            }
            RecoveryContactAction::Remove => {
                let old = record.verified.take();
                record.pending = None;
                let delivery = if let Some(old) = old {
                    Some(notice(
                        &locked,
                        &mut record,
                        RecoveryContactNoticeKind::Removed,
                        &old.email,
                        deadline,
                        notifier,
                    )?)
                } else {
                    save(&locked, &record)?;
                    None
                };
                (RecoveryContactEffect::Removed, delivery)
            }
        };
        Ok(RecoveryContactResult {
            snapshot: record.snapshot(now),
            effect,
            delivery,
        })
    }
}

#[allow(clippy::too_many_arguments)] // One held account lock and one original bounded send.
fn issue<N: RecoveryContactNotifier, R: RandomSource>(
    locked: &LockedAccountFile,
    record: &mut Record,
    address: String,
    created: u64,
    expiry: u64,
    deadline: Instant,
    notifier: &N,
    random: &R,
) -> Result<RecoveryContactDelivery, RecoveryContactError> {
    let now = record.updated_at;
    let retry_at = record.retry_at(now);
    if retry_at > now {
        return Err(RecoveryContactError::RateLimited { retry_at });
    }
    let mut bytes = [0u8; 32];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| RecoveryContactError::Unavailable)?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let token_digest = digest(&record.account, &token);
    if record
        .pending
        .as_ref()
        .and_then(|p| p.token_digest.as_ref())
        == Some(&token_digest)
    {
        return Err(RecoveryContactError::Unavailable);
    }
    record.sends.push(now);
    record.pending = Some(Pending {
        email: address,
        created_at: created,
        expires_at: expiry,
        token_issued_at: now,
        token_expires_at: (now + TOKEN_SECONDS).min(expiry),
        token_digest: Some(token_digest),
        attempts: 0,
        delivery: RecoveryContactDelivery::Unconfirmed,
    });
    save(locked, record)?;
    let p = record
        .pending
        .as_ref()
        .ok_or(RecoveryContactError::Unavailable)?;
    let result = deliver(
        notifier,
        RecoveryContactMessage::Verification {
            email: &p.email,
            token: &token,
            expires_at: p.token_expires_at,
        },
        deadline,
    );
    let p = record
        .pending
        .as_mut()
        .ok_or(RecoveryContactError::Unavailable)?;
    p.delivery = result;
    if result == RecoveryContactDelivery::Refused {
        p.token_digest = None;
    }
    save(locked, record)?;
    Ok(result)
}
fn notice<N: RecoveryContactNotifier>(
    locked: &LockedAccountFile,
    record: &mut Record,
    kind: RecoveryContactNoticeKind,
    address: &str,
    deadline: Instant,
    notifier: &N,
) -> Result<RecoveryContactDelivery, RecoveryContactError> {
    let earlier_unconfirmed = record.notice.as_ref().is_some_and(|n| {
        n.earlier_unconfirmed || n.delivery == RecoveryContactDelivery::Unconfirmed
    });
    record.notice = Some(RecoveryContactNotice {
        kind,
        attempted_at: record.updated_at,
        delivery: RecoveryContactDelivery::Unconfirmed,
        earlier_unconfirmed,
    });
    save(locked, record)?;
    let message = match kind {
        RecoveryContactNoticeKind::Replaced => RecoveryContactMessage::Replaced { email: address },
        RecoveryContactNoticeKind::Removed => RecoveryContactMessage::Removed { email: address },
    };
    let result = deliver(notifier, message, deadline);
    record
        .notice
        .as_mut()
        .ok_or(RecoveryContactError::Unavailable)?
        .delivery = result;
    save(locked, record)?;
    Ok(result)
}
fn deliver<N: RecoveryContactNotifier>(
    notifier: &N,
    message: RecoveryContactMessage<'_>,
    deadline: Instant,
) -> RecoveryContactDelivery {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(10));
    if Instant::now() >= deadline {
        return RecoveryContactDelivery::Refused;
    }
    let result = notifier.deliver(message, deadline);
    if Instant::now() >= deadline {
        RecoveryContactDelivery::Unconfirmed
    } else {
        result
    }
}
fn canonical(account: &str) -> Result<(), RecoveryContactError> {
    crate::identity::CanonicalUsername::parse(account.to_string())
        .map(|_| ())
        .map_err(|_| RecoveryContactError::Invalid)
}
fn email(address: &str) -> Result<(), RecoveryContactError> {
    crate::mail_address::validate_address(
        crate::send::ComposePolicy {
            recipient_max_len: 254,
            ..Default::default()
        },
        address,
    )
    .map_err(|_| RecoveryContactError::Invalid)
}
fn digest(account: &str, token: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"osmap-recovery-contact-proof-v1\0");
    hash.update(account.as_bytes());
    hash.update(b"\0");
    hash.update(token.as_bytes());
    format!("{:x}", hash.finalize())
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(account: &str, bytes: Option<Vec<u8>>, now: u64) -> Result<Record, RecoveryContactError> {
    let Some(bytes) = bytes else {
        return Ok(Record::empty(account));
    };
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|_| RecoveryContactError::Unavailable)?;
    record.validate(account, now)?;
    Ok(record)
}
fn save(locked: &LockedAccountFile, record: &Record) -> Result<(), RecoveryContactError> {
    record.validate(&record.account, record.updated_at)?;
    locked.write(&serde_json::to_vec(record).map_err(|_| RecoveryContactError::Unavailable)?)?;
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "recovery_contact_tests.rs"]
mod tests;
