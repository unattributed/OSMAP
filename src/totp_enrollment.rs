//! Account-bound replacement TOTP candidates for already-enrolled accounts.
//!
//! This store never changes the active factor, account epoch or browser sessions.
//! Native activation must consume the verified enrollment ID under the real
//! account fence, compare the prior factor/epoch, install the factor,
//! revoke old sessions and independently read back before releasing it.
use crate::identity::CanonicalUsername;
use crate::private_account_file::PrivateAccountFile;
use crate::session::{RandomSource, SystemRandomSource};
use crate::totp::{decode_base32, encode_base32, enrollment_counter, MIN_TOTP_SECRET_BYTES};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

const CANDIDATE_SCHEMA: &str = "osmap-totp-enrollment-v1";
const MAX_BYTES: usize = 16_384;
pub const ENROLLMENT_LIFETIME_SECONDS: u64 = 600;
pub const MAX_CONFIRMATION_ATTEMPTS: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    Refused,
    Expired,
    InvalidCode,
    AttemptsExhausted,
    Unavailable,
}

/// Constructed from authenticated native context, never posted account fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBinding {
    pub account: String,
    pub session_id: String,
    pub epoch: u64,
    pub expected_factor_sha256: String,
}
impl fmt::Debug for EnrollmentBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentBinding")
            .field("epoch", &self.epoch)
            .field("identity", &"[REDACTED]")
            .finish()
    }
}
impl EnrollmentBinding {
    fn valid(&self) -> bool {
        CanonicalUsername::parse(self.account.clone()).is_ok()
            && hex_id(&self.session_id)
            && hex_id(&self.expected_factor_sha256)
    }
}

/// Sensitive response for the authenticated enrollment page only. Never log,
/// serialize into audit data, cache, or expose outside its bound session.
pub struct PendingEnrollment {
    pub id: String,
    pub revision: u64,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub expires_at: u64,
}
impl fmt::Debug for PendingEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingEnrollment")
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("enrollment", &"[REDACTED]")
            .finish()
    }
}

/// A consumed candidate proof. This is not evidence of native activation.
/// The native authority must enforce the same ID's one-use activation/CAS.
pub struct VerifiedEnrollment {
    binding: EnrollmentBinding,
    id: String,
    revision: u64,
    secret_base32: String,
    counter: u64,
    expires_at: u64,
}
impl fmt::Debug for VerifiedEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedEnrollment([REDACTED])")
    }
}
impl VerifiedEnrollment {
    pub fn binding(&self) -> &EnrollmentBinding {
        &self.binding
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn accepted_counter(&self) -> u64 {
        self.counter
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub(crate) fn secret_base32(&self) -> &str {
        &self.secret_base32
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    schema: String,
    binding: EnrollmentBinding,
    id: String,
    revision: u64,
    secret_base32: String,
    created_at: u64,
    expires_at: u64,
    attempts: u8,
    verified_counter: Option<u64>,
}
fn decode_candidate(
    bytes: Option<Vec<u8>>,
    account: &str,
) -> Result<Option<Candidate>, EnrollmentError> {
    bytes
        .map(|bytes| {
            let v: Candidate =
                serde_json::from_slice(&bytes).map_err(|_| EnrollmentError::Unavailable)?;
            let secret =
                decode_base32(&v.secret_base32).map_err(|_| EnrollmentError::Unavailable)?;
            if v.schema != CANDIDATE_SCHEMA
                || !v.binding.valid()
                || v.binding.account != account
                || !hex_id(&v.id)
                || v.revision == 0
                || v.created_at == 0
                || v.expires_at.checked_sub(v.created_at) != Some(ENROLLMENT_LIFETIME_SECONDS)
                || v.attempts > MAX_CONFIRMATION_ATTEMPTS
                || secret.len() != MIN_TOTP_SECRET_BYTES
                || encode_base32(&secret) != v.secret_base32
            {
                return Err(EnrollmentError::Unavailable);
            }
            Ok(v)
        })
        .transpose()
}

#[derive(Clone, Debug)]
pub struct EnrollmentStore {
    files: PrivateAccountFile,
}
impl EnrollmentStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            files: PrivateAccountFile::new(directory.into(), CANDIDATE_SCHEMA, MAX_BYTES),
        }
    }
    pub fn revision(&self, account: &str, deadline: Instant) -> Result<u64, EnrollmentError> {
        valid_account(account)?;
        before(deadline)?;
        let v = decode_candidate(
            self.files
                .read(account)
                .map_err(|_| EnrollmentError::Unavailable)?,
            account,
        )?;
        before(deadline)?;
        Ok(v.map_or(0, |v| v.revision))
    }
    /// Resume only this exact session/grant's unconsumed candidate. Reading
    /// never rotates its secret or grants authority to begin an enrollment.
    pub fn pending(
        &self,
        binding: &EnrollmentBinding,
        now: u64,
        deadline: Instant,
    ) -> Result<Option<PendingEnrollment>, EnrollmentError> {
        if !binding.valid() {
            return Err(EnrollmentError::Refused);
        }
        before(deadline)?;
        let value = decode_candidate(
            self.files
                .read(&binding.account)
                .map_err(|_| EnrollmentError::Unavailable)?,
            &binding.account,
        )?;
        before(deadline)?;
        let Some(v) = value else {
            return Ok(None);
        };
        if v.binding != *binding
            || v.verified_counter.is_some()
            || v.attempts >= MAX_CONFIRMATION_ATTEMPTS
            || now < v.created_at
            || now >= v.expires_at
        {
            return Ok(None);
        }
        let uri = format!(
            "otpauth://totp/{}?secret={}&issuer=OSMAP&algorithm=SHA1&digits=6&period=30",
            crate::http_support::url_encode(&format!("OSMAP:{}", binding.account)),
            v.secret_base32
        );
        Ok(Some(PendingEnrollment {
            id: v.id,
            revision: v.revision,
            secret_base32: v.secret_base32,
            otpauth_uri: uri,
            expires_at: v.expires_at,
        }))
    }
    /// Root must first verify current credentials or a genuine restricted grant.
    pub fn begin(
        &self,
        binding: EnrollmentBinding,
        revision: u64,
        now: u64,
        deadline: Instant,
    ) -> Result<PendingEnrollment, EnrollmentError> {
        self.begin_with_random(binding, revision, now, deadline, &SystemRandomSource)
    }
    fn begin_with_random<R: RandomSource>(
        &self,
        binding: EnrollmentBinding,
        revision: u64,
        now: u64,
        deadline: Instant,
        random: &R,
    ) -> Result<PendingEnrollment, EnrollmentError> {
        if !binding.valid() || now == 0 {
            return Err(EnrollmentError::Refused);
        }
        let expires_at = now
            .checked_add(ENROLLMENT_LIFETIME_SECONDS)
            .ok_or(EnrollmentError::Refused)?;
        before(deadline)?;
        let lock = self
            .files
            .lock(&binding.account)
            .map_err(|_| EnrollmentError::Unavailable)?;
        let current = decode_candidate(
            lock.read().map_err(|_| EnrollmentError::Unavailable)?,
            &binding.account,
        )?;
        if current.as_ref().map_or(0, |v| v.revision) != revision
            || current.as_ref().is_some_and(|v| {
                v.verified_counter.is_some()
                    && v.binding.epoch == binding.epoch
                    && now < v.expires_at
            })
        {
            return Err(EnrollmentError::Refused);
        }
        let mut nonce = [0; 32];
        let mut secret = [0; MIN_TOTP_SECRET_BYTES];
        random
            .fill_bytes(&mut nonce)
            .map_err(|_| EnrollmentError::Unavailable)?;
        random
            .fill_bytes(&mut secret)
            .map_err(|_| EnrollmentError::Unavailable)?;
        let id = hex(&nonce);
        let secret_base32 = encode_base32(&secret);
        let revision = revision
            .checked_add(1)
            .ok_or(EnrollmentError::Unavailable)?;
        let uri = format!("otpauth://totp/{}?secret={secret_base32}&issuer=OSMAP&algorithm=SHA1&digits=6&period=30", crate::http_support::url_encode(&format!("OSMAP:{}", binding.account)));
        let v = Candidate {
            schema: CANDIDATE_SCHEMA.into(),
            binding,
            id: id.clone(),
            revision,
            secret_base32: secret_base32.clone(),
            created_at: now,
            expires_at,
            attempts: 0,
            verified_counter: None,
        };
        let bytes = serde_json::to_vec(&v).map_err(|_| EnrollmentError::Unavailable)?;
        before(deadline)?;
        lock.write(&bytes)
            .map_err(|_| EnrollmentError::Unavailable)?;
        if lock
            .read()
            .map_err(|_| EnrollmentError::Unavailable)?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(EnrollmentError::Unavailable);
        }
        Ok(PendingEnrollment {
            id,
            revision,
            secret_base32,
            otpauth_uri: uri,
            expires_at,
        })
    }
    /// Verifies only the candidate; active-factor replay state is untouched.
    /// The revision is returned by begin; wrong codes increment it, so callers
    /// obtain the current revision before a subsequent intentional attempt.
    pub fn verify(
        &self,
        binding: &EnrollmentBinding,
        id: &str,
        revision: u64,
        code: &str,
        now: u64,
        deadline: Instant,
    ) -> Result<VerifiedEnrollment, EnrollmentError> {
        if !binding.valid() || !hex_id(id) || now == 0 {
            return Err(EnrollmentError::Refused);
        }
        before(deadline)?;
        let lock = self
            .files
            .lock(&binding.account)
            .map_err(|_| EnrollmentError::Unavailable)?;
        let mut v = decode_candidate(
            lock.read().map_err(|_| EnrollmentError::Unavailable)?,
            &binding.account,
        )?
        .ok_or(EnrollmentError::Refused)?;
        if v.binding != *binding
            || v.id != id
            || v.revision != revision
            || v.verified_counter.is_some()
        {
            return Err(EnrollmentError::Refused);
        }
        if now < v.created_at || now >= v.expires_at {
            return Err(EnrollmentError::Expired);
        }
        if v.attempts >= MAX_CONFIRMATION_ATTEMPTS {
            return Err(EnrollmentError::AttemptsExhausted);
        }
        let secret = decode_base32(&v.secret_base32).map_err(|_| EnrollmentError::Unavailable)?;
        let counter = enrollment_counter(&secret, code, now);
        v.attempts += 1;
        v.revision = v
            .revision
            .checked_add(1)
            .ok_or(EnrollmentError::Unavailable)?;
        v.verified_counter = counter;
        let bytes = serde_json::to_vec(&v).map_err(|_| EnrollmentError::Unavailable)?;
        before(deadline)?;
        lock.write(&bytes)
            .map_err(|_| EnrollmentError::Unavailable)?;
        if lock
            .read()
            .map_err(|_| EnrollmentError::Unavailable)?
            .as_deref()
            != Some(bytes.as_slice())
        {
            return Err(EnrollmentError::Unavailable);
        }
        let counter = counter.ok_or(if v.attempts == MAX_CONFIRMATION_ATTEMPTS {
            EnrollmentError::AttemptsExhausted
        } else {
            EnrollmentError::InvalidCode
        })?;
        Ok(VerifiedEnrollment {
            binding: v.binding,
            id: v.id,
            revision: v.revision,
            secret_base32: v.secret_base32,
            counter,
            expires_at: v.expires_at,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn before(deadline: Instant) -> Result<(), EnrollmentError> {
    if Instant::now() >= deadline {
        Err(EnrollmentError::Unavailable)
    } else {
        Ok(())
    }
}
fn valid_account(account: &str) -> Result<(), EnrollmentError> {
    CanonicalUsername::parse(account.to_owned())
        .map(|_| ())
        .map_err(|_| EnrollmentError::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct ReferenceRandom(Cell<u8>);
    impl RandomSource for ReferenceRandom {
        fn fill_bytes(&self, bytes: &mut [u8]) -> Result<(), crate::session::SessionError> {
            if bytes.len() == MIN_TOTP_SECRET_BYTES {
                bytes.copy_from_slice(b"12345678901234567890");
            } else {
                bytes.fill(self.0.get());
                self.0.set(self.0.get().wrapping_add(1));
            }
            Ok(())
        }
    }
    struct BrokenRandom;
    impl RandomSource for BrokenRandom {
        fn fill_bytes(&self, _: &mut [u8]) -> Result<(), crate::session::SessionError> {
            Err(crate::session::SessionError::RandomSourceFailure {
                reason: "synthetic unavailable source".into(),
            })
        }
    }
    fn fixture() -> (Scratch, EnrollmentStore) {
        let root = std::env::temp_dir().join(format!(
            "osmap-enrollment-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        (Scratch(root.clone()), EnrollmentStore::new(root))
    }
    fn binding() -> EnrollmentBinding {
        EnrollmentBinding {
            account: "alice@example.test".into(),
            session_id: "1".repeat(64),
            epoch: 4,
            expected_factor_sha256: "a".repeat(64),
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn begin(store: &EnrollmentStore) -> PendingEnrollment {
        store
            .begin_with_random(binding(), 0, 30, deadline(), &ReferenceRandom(Cell::new(1)))
            .unwrap()
    }
    fn bytes(store: &EnrollmentStore) -> Vec<u8> {
        store.files.read(&binding().account).unwrap().unwrap()
    }

    #[test]
    fn replacement_candidate_uses_existing_rfc_verifier_and_redacts_presentation() {
        let (_scratch, store) = fixture();
        let pending = begin(&store);
        assert_eq!(pending.secret_base32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert!(pending
            .otpauth_uri
            .starts_with("otpauth://totp/OSMAP%3Aalice%40example.test?secret="));
        assert!(!format!("{pending:?}").contains(&pending.secret_base32));
        let proof = store
            .verify(
                &binding(),
                &pending.id,
                pending.revision,
                "287082",
                59,
                deadline(),
            )
            .unwrap();
        assert_eq!(proof.accepted_counter(), 1);
        assert_eq!(proof.binding(), &binding());
        assert_eq!(proof.secret_base32(), pending.secret_base32);
        assert!(!format!("{proof:?}").contains(&pending.secret_base32));
        assert_eq!(proof.expires_at(), 630);
    }

    #[test]
    fn wrong_session_epoch_factor_id_and_revision_never_consume_candidate() {
        let (_scratch, store) = fixture();
        let pending = begin(&store);
        let original = bytes(&store);
        let mut changes = Vec::new();
        let mut v = binding();
        v.session_id = "2".repeat(64);
        changes.push(v);
        let mut v = binding();
        v.epoch += 1;
        changes.push(v);
        let mut v = binding();
        v.expected_factor_sha256 = "b".repeat(64);
        changes.push(v);
        for value in changes {
            assert_eq!(
                store
                    .verify(
                        &value,
                        &pending.id,
                        pending.revision,
                        "287082",
                        59,
                        deadline()
                    )
                    .unwrap_err(),
                EnrollmentError::Refused
            );
            assert_eq!(bytes(&store), original);
        }
        for (id, revision) in [
            ("f".repeat(64), pending.revision),
            (pending.id.clone(), pending.revision + 1),
        ] {
            assert_eq!(
                store
                    .verify(&binding(), &id, revision, "287082", 59, deadline())
                    .unwrap_err(),
                EnrollmentError::Refused
            );
            assert_eq!(bytes(&store), original);
        }
        let mut other = binding();
        other.account = "bob@example.test".into();
        assert_eq!(
            store
                .verify(
                    &other,
                    &pending.id,
                    pending.revision,
                    "287082",
                    59,
                    deadline()
                )
                .unwrap_err(),
            EnrollmentError::Refused
        );
        assert_eq!(bytes(&store), original);
    }

    #[test]
    fn invalid_new_code_preserves_existing_factor_and_limits_attempts() {
        let (scratch, store) = fixture();
        let pending = begin(&store);
        let active = scratch.0.with_extension("active-test-factor");
        fs::write(
            &active,
            b"synthetic existing factor; never an account secret",
        )
        .unwrap();
        for attempt in 0..MAX_CONFIRMATION_ATTEMPTS {
            let revision = store.revision(&binding().account, deadline()).unwrap();
            let error = store
                .verify(
                    &binding(),
                    &pending.id,
                    revision,
                    "not-a-code",
                    59,
                    deadline(),
                )
                .unwrap_err();
            assert_eq!(
                error,
                if attempt + 1 == MAX_CONFIRMATION_ATTEMPTS {
                    EnrollmentError::AttemptsExhausted
                } else {
                    EnrollmentError::InvalidCode
                }
            );
            assert_eq!(
                fs::read(&active).unwrap(),
                b"synthetic existing factor; never an account secret"
            );
        }
        let revision = store.revision(&binding().account, deadline()).unwrap();
        let before = bytes(&store);
        assert_eq!(
            store
                .verify(&binding(), &pending.id, revision, "287082", 59, deadline())
                .unwrap_err(),
            EnrollmentError::AttemptsExhausted
        );
        assert_eq!(bytes(&store), before);
        fs::remove_file(active).unwrap();
    }

    #[test]
    fn expired_or_replayed_proof_has_no_additional_effect() {
        let (_scratch, store) = fixture();
        let pending = begin(&store);
        let before = bytes(&store);
        for now in [29, 630, 631] {
            assert_eq!(
                store
                    .verify(
                        &binding(),
                        &pending.id,
                        pending.revision,
                        "287082",
                        now,
                        deadline()
                    )
                    .unwrap_err(),
                EnrollmentError::Expired
            );
            assert_eq!(bytes(&store), before);
        }
        let proof = store
            .verify(
                &binding(),
                &pending.id,
                pending.revision,
                "287082",
                59,
                deadline(),
            )
            .unwrap();
        let consumed = bytes(&store);
        assert_eq!(
            store
                .verify(
                    &binding(),
                    &pending.id,
                    proof.revision(),
                    "287082",
                    59,
                    deadline()
                )
                .unwrap_err(),
            EnrollmentError::Refused
        );
        assert_eq!(bytes(&store), consumed);
        assert_eq!(
            store
                .begin(binding(), proof.revision(), 60, deadline())
                .unwrap_err(),
            EnrollmentError::Refused
        );
    }

    #[test]
    fn restart_and_parallel_confirmation_preserve_one_use() {
        let (scratch, store) = fixture();
        let pending = begin(&store);
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let restarted = EnrollmentStore::new(scratch.0.clone());
            let barrier = barrier.clone();
            let id = pending.id.clone();
            let revision = pending.revision;
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                restarted
                    .verify(&binding(), &id, revision, "287082", 59, deadline())
                    .is_ok()
            }));
        }
        assert_eq!(
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert!(decode_candidate(Some(bytes(&store)), &binding().account)
            .unwrap()
            .unwrap()
            .verified_counter
            .is_some());
    }

    #[test]
    fn pending_read_resumes_same_secret_and_new_revision_after_invalid_code() {
        let (_scratch, store) = fixture();
        let pending = begin(&store);
        let original = bytes(&store);
        let resumed = store.pending(&binding(), 59, deadline()).unwrap().unwrap();
        assert_eq!(resumed.id, pending.id);
        assert_eq!(resumed.secret_base32, pending.secret_base32);
        assert_eq!(bytes(&store), original);
        let mut foreign = binding();
        foreign.session_id = "f".repeat(64);
        assert!(store.pending(&foreign, 59, deadline()).unwrap().is_none());
        assert!(store
            .pending(&binding(), 630, deadline())
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .verify(
                    &binding(),
                    &pending.id,
                    pending.revision,
                    "not-code",
                    59,
                    deadline()
                )
                .unwrap_err(),
            EnrollmentError::InvalidCode
        );
        let resumed = store.pending(&binding(), 59, deadline()).unwrap().unwrap();
        assert_eq!(resumed.revision, pending.revision + 1);
        assert_eq!(resumed.secret_base32, pending.secret_base32);
        store
            .verify(
                &binding(),
                &resumed.id,
                resumed.revision,
                "287082",
                59,
                deadline(),
            )
            .unwrap();
        assert!(store.pending(&binding(), 59, deadline()).unwrap().is_none());
    }

    #[test]
    fn stale_begin_rng_failure_and_deadline_leave_original_unchanged() {
        let (_scratch, store) = fixture();
        let pending = begin(&store);
        let before = bytes(&store);
        assert_eq!(
            store.begin(binding(), 0, 59, deadline()).unwrap_err(),
            EnrollmentError::Refused
        );
        assert_eq!(
            store
                .begin_with_random(binding(), pending.revision, 59, deadline(), &BrokenRandom)
                .unwrap_err(),
            EnrollmentError::Unavailable
        );
        assert_eq!(
            store
                .verify(
                    &binding(),
                    &pending.id,
                    pending.revision,
                    "287082",
                    59,
                    Instant::now()
                )
                .unwrap_err(),
            EnrollmentError::Unavailable
        );
        assert_eq!(bytes(&store), before);
        let mut absent = binding();
        absent.expected_factor_sha256.clear();
        assert_eq!(
            store
                .begin(absent, pending.revision, 59, deadline())
                .unwrap_err(),
            EnrollmentError::Refused
        );
    }

    #[cfg(unix)]
    #[test]
    fn records_are_owner_private_and_symlinks_are_refused() {
        use std::os::unix::fs::{symlink, MetadataExt};
        let (scratch, store) = fixture();
        let _pending = begin(&store);
        assert_eq!(fs::metadata(&scratch.0).unwrap().mode() & 0o777, 0o700);
        let record = fs::read_dir(&scratch.0)
            .unwrap()
            .map(|v| v.unwrap().path())
            .find(|p| p.extension().is_some_and(|v| v == "json"))
            .unwrap();
        assert_eq!(fs::metadata(&record).unwrap().mode() & 0o777, 0o600);
        let target = scratch.0.join("original.json");
        fs::rename(&record, &target).unwrap();
        symlink(&target, &record).unwrap();
        assert_eq!(
            store.revision(&binding().account, deadline()).unwrap_err(),
            EnrollmentError::Unavailable
        );
    }
}
