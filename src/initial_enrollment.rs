//! First-time owner setup, separate from registered-account recovery.
//!
//! The trusted caller first establishes a pending native account and authorizes
//! its approved independent contact. This store supplies only restricted setup
//! authority. It neither creates a mailbox nor installs an active factor. The
//! native caller must refuse existing factors, contain incomplete activation,
//! install without overwrite, and read back password/factor state before finish.
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use crate::session::{RandomSource, SystemRandomSource};
use crate::totp::{decode_base32, encode_base32, enrollment_counter, MIN_TOTP_SECRET_BYTES};
use crate::totp_enrollment::{PendingEnrollment, MAX_CONFIRMATION_ATTEMPTS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

const SCHEMA: &str = "osmap-initial-enrollment-v1";
pub const LIFETIME_SECONDS: u64 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Refused,
    Expired,
    InvalidCode,
    AttemptsExhausted,
    Unavailable,
}

/// Fixed source-owned diagnostics only. Never persist utility output, exception
/// text, credentials or bearer values in the retained activation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    PasswordHash,
    FactorInstall,
    SqlActivation,
    SqlReadback,
    CompletionReceipt,
}

/// Deliver privately to the approved contact; never return to the administrator
/// as evidence of recipient verification or put the bearer in a logged URL.
pub struct Invitation {
    pub token: String,
    pub expires_at: u64,
}
/// This bearer permits setup only. It is never an ordinary login/session token.
pub struct Grant {
    pub token: String,
    pub expires_at: u64,
}
/// Consumed first-factor proof, not a claim that native activation succeeded.
pub struct VerifiedInitial {
    account: String,
    operation_id: String,
    secret_base32: String,
    counter: u64,
}
macro_rules! redacted {
    ($($name:ty),+ $(,)?) => {$ (impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($name),"([REDACTED])"))
        }
    })+};
}
redacted!(Invitation, Grant, VerifiedInitial);
impl VerifiedInitial {
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn secret_base32(&self) -> &str {
        &self.secret_base32
    }
    pub fn accepted_counter(&self) -> u64 {
        self.counter
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Invited,
    Setup,
    Activating,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    account: String,
    contact: String,
    operation_id: String,
    phase: Phase,
    created_at: u64,
    expires_at: u64,
    invitation_digest: Option<String>,
    grant_digest: Option<String>,
    setup_started: Option<u64>,
    enrollment_id: Option<String>,
    secret_base32: Option<String>,
    revision: u64,
    attempts: u8,
    counter: Option<u64>,
    installed_digest: Option<String>,
    #[serde(default)]
    failure_stage: Option<FailureStage>,
}

#[derive(Clone, Debug)]
pub struct Store {
    files: PrivateAccountFile,
}
impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            files: PrivateAccountFile::new(directory.into(), SCHEMA, 16_384),
        }
    }
    /// Only the native administrator operation may call this after checking
    /// current TOTP, scope, pending-account authority and factor absence.
    pub fn provision(
        &self,
        account: &str,
        contact: &str,
        operation_id: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<Invitation, Error> {
        valid_account(account)?;
        if !valid_contact(contact) || contact.eq_ignore_ascii_case(account) || !hex_id(operation_id)
        {
            return Err(Error::Refused);
        }
        let expires_at = expires(now)?;
        before(deadline)?;
        let held = self.files.lock(account).map_err(unavailable)?;
        if held.read().map_err(unavailable)?.is_some() {
            // Expiry never makes an existing account eligible for reprovisioning.
            return Err(Error::Refused);
        }
        let token = random_token()?;
        let value = Record {
            schema: SCHEMA.into(),
            account: account.into(),
            contact: contact.into(),
            operation_id: operation_id.into(),
            phase: Phase::Invited,
            created_at: now,
            expires_at,
            invitation_digest: Some(digest("invitation", &token)),
            grant_digest: None,
            setup_started: None,
            enrollment_id: None,
            secret_base32: None,
            revision: 1,
            attempts: 0,
            counter: None,
            installed_digest: None,
            failure_stage: None,
        };
        save(&held, &value, deadline)?;
        Ok(Invitation { token, expires_at })
    }
    /// The independent recipient presents the privately delivered bearer.
    /// Account selection cannot redirect it or select another contact.
    pub fn redeem(
        &self,
        account: &str,
        invitation: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<Grant, Error> {
        let (held, mut value) = self.locked(account, deadline)?;
        if value.phase != Phase::Invited
            || !matches_digest(&value.invitation_digest, "invitation", invitation)
        {
            return Err(Error::Refused);
        }
        live(value.created_at, value.expires_at, now)?;
        let expires_at = expires(now)?;
        let token = random_token()?;
        let mut secret = [0; MIN_TOTP_SECRET_BYTES];
        SystemRandomSource
            .fill_bytes(&mut secret)
            .map_err(unavailable)?;
        value.phase = Phase::Setup;
        value.invitation_digest = None;
        value.grant_digest = Some(digest("grant", &token));
        value.setup_started = Some(now);
        value.expires_at = expires_at;
        value.enrollment_id = Some(random_token()?);
        value.secret_base32 = Some(encode_base32(&secret));
        value.revision = value.revision.checked_add(1).ok_or(Error::Unavailable)?;
        save(&held, &value, deadline)?;
        Ok(Grant { token, expires_at })
    }
    pub fn pending(
        &self,
        account: &str,
        grant: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<PendingEnrollment, Error> {
        let (_, value) = self.locked(account, deadline)?;
        authorized(&value, grant, now)?;
        let secret = value.secret_base32.ok_or(Error::Unavailable)?;
        Ok(PendingEnrollment {
            id: value.enrollment_id.ok_or(Error::Unavailable)?,
            revision: value.revision,
            otpauth_uri: format!(
                "otpauth://totp/{}?secret={secret}&issuer=OSMAP&algorithm=SHA1&digits=6&period=30",
                crate::http_support::url_encode(&format!("OSMAP:{account}"))
            ),
            secret_base32: secret,
            expires_at: value.expires_at,
        })
    }
    /// Persist activation intent and consume the setup grant BEFORE native
    /// writes. Interrupted activation must be reconciled, never replayed as a
    /// new enrollment. Ordinary login remains the native caller's responsibility.
    #[allow(clippy::too_many_arguments)]
    pub fn confirm(
        &self,
        account: &str,
        grant: &str,
        enrollment_id: &str,
        revision: u64,
        code: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<VerifiedInitial, Error> {
        let (held, mut value) = self.locked(account, deadline)?;
        authorized(&value, grant, now)?;
        if value.enrollment_id.as_deref() != Some(enrollment_id) || value.revision != revision {
            return Err(Error::Refused);
        }
        let secret_base32 = value.secret_base32.clone().ok_or(Error::Unavailable)?;
        let secret = decode_base32(&secret_base32).map_err(unavailable)?;
        let counter = enrollment_counter(&secret, code, now);
        value.attempts += 1;
        value.revision = value.revision.checked_add(1).ok_or(Error::Unavailable)?;
        if let Some(counter) = counter {
            value.phase = Phase::Activating;
            value.grant_digest = None;
            value.counter = Some(counter);
        }
        save(&held, &value, deadline)?;
        let counter = counter.ok_or(if value.attempts == MAX_CONFIRMATION_ATTEMPTS {
            Error::AttemptsExhausted
        } else {
            Error::InvalidCode
        })?;
        Ok(VerifiedInitial {
            account: value.account,
            operation_id: value.operation_id,
            secret_base32,
            counter,
        })
    }
    /// Called only after native no-overwrite installation, counter consumption,
    /// password activation and independent readback succeed. This receipt is
    /// not itself a native activation mechanism or login authority.
    pub fn finish(
        &self,
        account: &str,
        operation_id: &str,
        factor_sha256: &str,
        deadline: Instant,
    ) -> Result<(), Error> {
        let (held, mut value) = self.locked(account, deadline)?;
        if value.phase != Phase::Activating
            || value.operation_id != operation_id
            || !hex_id(factor_sha256)
        {
            return Err(Error::Refused);
        }
        let secret = value.secret_base32.as_deref().ok_or(Error::Unavailable)?;
        let expected = format!(
            "{:x}",
            Sha256::digest(format!("# {account}\nsecret={secret}\n").as_bytes())
        );
        if !crate::http_support::constant_time_eq(expected.as_bytes(), factor_sha256.as_bytes()) {
            return Err(Error::Refused);
        }
        value.phase = Phase::Complete;
        value.secret_base32 = None;
        value.installed_digest = Some(factor_sha256.into());
        save(&held, &value, deadline)
    }
    /// Preserve the earliest activation failure in the existing private record.
    /// A visible Complete record may still have had an uncertain final write;
    /// only that completion-receipt failure can be recorded after Complete.
    pub fn record_failure(
        &self,
        account: &str,
        operation_id: &str,
        stage: FailureStage,
        deadline: Instant,
    ) -> Result<(), Error> {
        let (held, mut value) = self.locked(account, deadline)?;
        if value.operation_id != operation_id
            || !(value.phase == Phase::Activating
                || (value.phase == Phase::Complete && stage == FailureStage::CompletionReceipt))
        {
            return Err(Error::Refused);
        }
        if value.failure_stage.is_none() {
            value.failure_stage = Some(stage);
            save(&held, &value, deadline)?;
        }
        Ok(())
    }
    fn locked(
        &self,
        account: &str,
        deadline: Instant,
    ) -> Result<(LockedAccountFile, Record), Error> {
        valid_account(account)?;
        before(deadline)?;
        let held = self.files.lock(account).map_err(unavailable)?;
        let bytes = held.read().map_err(unavailable)?.ok_or(Error::Refused)?;
        let value: Record = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if !valid_record(&value, account) {
            return Err(Error::Unavailable);
        }
        before(deadline)?;
        Ok((held, value))
    }
}

fn valid_record(v: &Record, account: &str) -> bool {
    v.schema == SCHEMA
        && v.account == account
        && valid_contact(&v.contact)
        && !v.contact.eq_ignore_ascii_case(account)
        && hex_id(&v.operation_id)
        && v.created_at > 0
        && v.revision > 0
        && v.attempts <= MAX_CONFIRMATION_ATTEMPTS
        && (v.failure_stage.is_none() || matches!(v.phase, Phase::Activating | Phase::Complete))
        && match v.phase {
            Phase::Invited => {
                v.expires_at.checked_sub(v.created_at) == Some(LIFETIME_SECONDS)
                    && v.invitation_digest.as_deref().is_some_and(hex_id)
                    && v.grant_digest.is_none()
                    && v.setup_started.is_none()
                    && v.enrollment_id.is_none()
                    && v.secret_base32.is_none()
                    && v.counter.is_none()
                    && v.installed_digest.is_none()
                    && v.attempts == 0
            }
            _ => {
                v.setup_started.is_some_and(|start| {
                    start >= v.created_at
                        && start < v.created_at.saturating_add(LIFETIME_SECONDS)
                        && v.expires_at.checked_sub(start) == Some(LIFETIME_SECONDS)
                }) && v.invitation_digest.is_none()
                    && v.enrollment_id.as_deref().is_some_and(hex_id)
                    && match v.phase {
                        Phase::Setup => {
                            v.grant_digest.as_deref().is_some_and(hex_id)
                                && valid_secret(v.secret_base32.as_deref())
                                && v.counter.is_none()
                                && v.installed_digest.is_none()
                        }
                        Phase::Activating => {
                            v.grant_digest.is_none()
                                && valid_secret(v.secret_base32.as_deref())
                                && v.counter.is_some()
                                && v.installed_digest.is_none()
                        }
                        Phase::Complete => {
                            v.grant_digest.is_none()
                                && v.secret_base32.is_none()
                                && v.counter.is_some()
                                && v.installed_digest.as_deref().is_some_and(hex_id)
                        }
                        Phase::Invited => false,
                    }
            }
        }
}
fn valid_secret(value: Option<&str>) -> bool {
    value.is_some_and(|text| {
        decode_base32(text).is_ok_and(|bytes| {
            bytes.len() == MIN_TOTP_SECRET_BYTES && encode_base32(&bytes) == text
        })
    })
}
fn authorized(value: &Record, grant: &str, now: u64) -> Result<(), Error> {
    if value.phase != Phase::Setup || !matches_digest(&value.grant_digest, "grant", grant) {
        return Err(Error::Refused);
    }
    live(
        value.setup_started.ok_or(Error::Unavailable)?,
        value.expires_at,
        now,
    )?;
    if value.attempts >= MAX_CONFIRMATION_ATTEMPTS {
        return Err(Error::AttemptsExhausted);
    }
    Ok(())
}
fn save(held: &LockedAccountFile, value: &Record, deadline: Instant) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(unavailable)?;
    before(deadline)?;
    held.write(&bytes).map_err(unavailable)?;
    if held.read().map_err(unavailable)?.as_deref() != Some(bytes.as_slice()) {
        return Err(Error::Unavailable);
    }
    before(deadline)
}
fn random_token() -> Result<String, Error> {
    let mut bytes = [0; 32];
    SystemRandomSource
        .fill_bytes(&mut bytes)
        .map_err(unavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn digest(purpose: &str, token: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(SCHEMA);
    hash.update([0]);
    hash.update(purpose);
    hash.update([0]);
    hash.update(token);
    format!("{:x}", hash.finalize())
}
fn matches_digest(stored: &Option<String>, purpose: &str, presented: &str) -> bool {
    hex_id(presented)
        && stored.as_ref().is_some_and(|expected| {
            crate::http_support::constant_time_eq(
                expected.as_bytes(),
                digest(purpose, presented).as_bytes(),
            )
        })
}
fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_account(value: &str) -> Result<(), Error> {
    crate::account_admission::valid_account(value).map_err(|_| Error::Refused)
}
pub(crate) fn valid_contact(value: &str) -> bool {
    value.is_ascii()
        && !value.chars().any(char::is_control)
        && crate::mail_address::validate_address(crate::send::ComposePolicy::default(), value)
            .is_ok()
}
/// Invitations use the installation's ordinary HTTPS origin. A separate test
/// listener must never become an onboarding URL sent to a user.
pub(crate) fn valid_setup_origin(origin: &str) -> bool {
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn expires(now: u64) -> Result<u64, Error> {
    if now == 0 {
        return Err(Error::Refused);
    }
    now.checked_add(LIFETIME_SECONDS).ok_or(Error::Refused)
}
fn live(created: u64, expires: u64, now: u64) -> Result<(), Error> {
    if now < created || now >= expires {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn before(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Unavailable)
    } else {
        Ok(())
    }
}
fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;
    const ACCOUNT: &str = "new-owner@example.test";
    const CONTACT: &str = "owner@independent.test";
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Scratch, Store) {
        let root = std::env::temp_dir().join(format!("osmap-initial-{}", random_token().unwrap()));
        (Scratch(root.clone()), Store::new(root))
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn provision(store: &Store) -> Invitation {
        store
            .provision(ACCOUNT, CONTACT, &"a".repeat(64), 30, deadline())
            .unwrap()
    }
    fn setup(store: &Store) -> (Grant, PendingEnrollment) {
        let invitation = provision(store);
        let grant = store
            .redeem(ACCOUNT, &invitation.token, 31, deadline())
            .unwrap();
        let candidate = store
            .pending(ACCOUNT, &grant.token, 32, deadline())
            .unwrap();
        (grant, candidate)
    }
    fn code(candidate: &PendingEnrollment, now: u64) -> String {
        crate::totp::generate_totp_code(
            &decode_base32(&candidate.secret_base32).unwrap(),
            now / 30,
            crate::totp::TotpPolicy::default(),
        )
        .unwrap()
    }

    #[test]
    fn recipient_proof_is_single_use_account_bound_and_digest_only() {
        let (_scratch, store) = fixture();
        let invitation = provision(&store);
        let original = store.files.read(ACCOUNT).unwrap().unwrap();
        assert!(!String::from_utf8(original.clone())
            .unwrap()
            .contains(&invitation.token));
        assert_eq!(
            store
                .redeem("other@example.test", &invitation.token, 31, deadline())
                .unwrap_err(),
            Error::Refused
        );
        assert_eq!(
            store
                .redeem(ACCOUNT, &"b".repeat(64), 31, deadline())
                .unwrap_err(),
            Error::Refused
        );
        assert_eq!(store.files.read(ACCOUNT).unwrap().unwrap(), original);
        let grant = store
            .redeem(ACCOUNT, &invitation.token, 31, deadline())
            .unwrap();
        assert_eq!(
            store
                .redeem(ACCOUNT, &invitation.token, 32, deadline())
                .unwrap_err(),
            Error::Refused
        );
        assert_eq!(
            store
                .pending("other@example.test", &grant.token, 32, deadline())
                .unwrap_err(),
            Error::Refused
        );
        assert!(
            !String::from_utf8(store.files.read(ACCOUNT).unwrap().unwrap())
                .unwrap()
                .contains(&grant.token)
        );
        assert!(!format!("{invitation:?} {grant:?}").contains(&grant.token));
    }

    #[test]
    fn expired_invitation_and_grant_cannot_restart_existing_setup() {
        let (_scratch, store) = fixture();
        let invitation = provision(&store);
        assert_eq!(
            store
                .redeem(ACCOUNT, &invitation.token, 630, deadline())
                .unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            store
                .provision(ACCOUNT, CONTACT, &"a".repeat(64), 631, deadline())
                .unwrap_err(),
            Error::Refused
        );
        let (_scratch, store) = fixture();
        let (grant, _) = setup(&store);
        assert_eq!(
            store
                .pending(ACCOUNT, &grant.token, 631, deadline())
                .unwrap_err(),
            Error::Expired
        );
    }

    #[test]
    fn proved_initial_factor_consumes_authority_before_native_activation() {
        let (_scratch, store) = fixture();
        let (grant, candidate) = setup(&store);
        let proof = store
            .confirm(
                ACCOUNT,
                &grant.token,
                &candidate.id,
                candidate.revision,
                &code(&candidate, 60),
                60,
                deadline(),
            )
            .unwrap();
        assert_eq!(proof.account(), ACCOUNT);
        assert_eq!(proof.operation_id(), "a".repeat(64));
        assert_eq!(proof.accepted_counter(), 2);
        assert_eq!(proof.secret_base32(), candidate.secret_base32);
        assert!(!format!("{proof:?}").contains(&candidate.secret_base32));
        assert_eq!(
            store
                .pending(ACCOUNT, &grant.token, 61, deadline())
                .unwrap_err(),
            Error::Refused
        );
        assert_eq!(
            store
                .confirm(
                    ACCOUNT,
                    &grant.token,
                    &candidate.id,
                    candidate.revision,
                    &code(&candidate, 60),
                    61,
                    deadline()
                )
                .unwrap_err(),
            Error::Refused
        );
        // An interrupted native operation leaves its candidate available only
        // in the private activation record, never through the consumed grant.
        assert!(
            String::from_utf8(store.files.read(ACCOUNT).unwrap().unwrap())
                .unwrap()
                .contains(&candidate.secret_base32)
        );
        assert_eq!(
            store.finish(ACCOUNT, &"b".repeat(64), &"c".repeat(64), deadline()),
            Err(Error::Refused)
        );
        assert_eq!(
            store.finish(ACCOUNT, &"a".repeat(64), &"c".repeat(64), deadline()),
            Err(Error::Refused)
        );
        let (_, unchanged) = store.locked(ACCOUNT, deadline()).unwrap();
        assert!(unchanged.phase == Phase::Activating);
        assert_eq!(
            unchanged.secret_base32.as_deref(),
            Some(candidate.secret_base32.as_str())
        );
        let factor_digest = format!(
            "{:x}",
            Sha256::digest(format!("# {ACCOUNT}\nsecret={}\n", candidate.secret_base32).as_bytes())
        );
        store
            .finish(ACCOUNT, &"a".repeat(64), &factor_digest, deadline())
            .unwrap();
        assert!(
            !String::from_utf8(store.files.read(ACCOUNT).unwrap().unwrap())
                .unwrap()
                .contains(&candidate.secret_base32)
        );
        assert_eq!(
            store
                .provision(ACCOUNT, CONTACT, &"b".repeat(64), 62, deadline())
                .unwrap_err(),
            Error::Refused
        );
    }

    #[test]
    fn wrong_totp_is_bounded_without_changing_candidate_or_grant() {
        let (_scratch, store) = fixture();
        let (grant, first) = setup(&store);
        for attempt in 0..MAX_CONFIRMATION_ATTEMPTS {
            let candidate = store
                .pending(ACCOUNT, &grant.token, 60, deadline())
                .unwrap();
            assert_eq!(candidate.secret_base32, first.secret_base32);
            let result = store
                .confirm(
                    ACCOUNT,
                    &grant.token,
                    &candidate.id,
                    candidate.revision,
                    "invalid",
                    60,
                    deadline(),
                )
                .unwrap_err();
            assert_eq!(
                result,
                if attempt + 1 == MAX_CONFIRMATION_ATTEMPTS {
                    Error::AttemptsExhausted
                } else {
                    Error::InvalidCode
                }
            );
        }
        assert_eq!(
            store
                .pending(ACCOUNT, &grant.token, 61, deadline())
                .unwrap_err(),
            Error::AttemptsExhausted
        );
    }

    #[test]
    fn durable_failure_preserves_earliest_stage_only_after_activation_begins() {
        let (_scratch, store) = fixture();
        let (grant, candidate) = setup(&store);
        let operation = "a".repeat(64);
        assert_eq!(
            store.record_failure(ACCOUNT, &operation, FailureStage::PasswordHash, deadline()),
            Err(Error::Refused)
        );
        // A record produced before diagnostic support remains readable.
        let bytes = store.files.read(ACCOUNT).unwrap().unwrap();
        let mut old: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        old.as_object_mut().unwrap().remove("failure_stage");
        let previous: Record = serde_json::from_value(old).unwrap();
        assert!(previous.failure_stage.is_none());
        assert!(valid_record(&previous, ACCOUNT));
        store
            .confirm(
                ACCOUNT,
                &grant.token,
                &candidate.id,
                candidate.revision,
                &code(&candidate, 60),
                60,
                deadline(),
            )
            .unwrap();
        store
            .record_failure(ACCOUNT, &operation, FailureStage::FactorInstall, deadline())
            .unwrap();
        store
            .record_failure(ACCOUNT, &operation, FailureStage::SqlActivation, deadline())
            .unwrap();
        let (_, retained) = store.locked(ACCOUNT, deadline()).unwrap();
        assert_eq!(retained.failure_stage, Some(FailureStage::FactorInstall));
        let factor_digest = format!(
            "{:x}",
            Sha256::digest(format!("# {ACCOUNT}\nsecret={}\n", candidate.secret_base32).as_bytes())
        );
        store
            .finish(ACCOUNT, &operation, &factor_digest, deadline())
            .unwrap();
        store
            .record_failure(
                ACCOUNT,
                &operation,
                FailureStage::CompletionReceipt,
                deadline(),
            )
            .unwrap();
        let (_, retained) = store.locked(ACCOUNT, deadline()).unwrap();
        assert_eq!(retained.failure_stage, Some(FailureStage::FactorInstall));
        assert!(retained.secret_base32.is_none());
    }
}
