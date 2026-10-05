//! A separate current-file-session assertion, issued only while its lock is held.
//! This authenticates the exact guarded snapshot, not distributed lease liveness
//! after issuer failure. Native routing, confinement and worker startup stay off.
use crate::account_mutation::{Error, Request, Verifier};
use crate::session::GuardedSessionLease;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "osmap-guarded-session-proof-v1";
pub(crate) const MAX_FRAME: usize = 12288;

#[derive(Serialize)]
struct Proof<'a> {
    schema: &'static str,
    account: &'a str,
    epoch: u64,
    session_id: &'a str,
    request_id: &'a str,
    source: &'a str,
    intent_reference: &'a str,
    request_sha256: String,
    budget_sha256: String,
    checked_millis: u64,
    session_expires: u64,
    idle_expires: u64,
    issued: u64,
    expires: u64,
    deadline_millis: u64,
    signature: String,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn payload(proof: &Proof<'_>) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
        SCHEMA,
        "guarded_file_session",
        proof.account,
        proof.epoch,
        proof.session_id,
        proof.request_id,
        proof.source,
        proof.intent_reference,
        proof.request_sha256,
        proof.budget_sha256,
        proof.checked_millis,
        proof.session_expires,
        proof.idle_expires,
        proof.issued,
        proof.expires,
        proof.deadline_millis
    ]))
    .map_err(|_| Error::Invalid)
}

/// Move-only request that borrows the actual still-held FileSessionStore lock.
/// It cannot escape the higher-ranked guarded callback or be deserialized.
pub struct GuardedMutation<'guard> {
    request: Request,
    frame: Vec<u8>,
    deadline: Instant,
    _lease: GuardedSessionLease<'guard>,
}
impl std::fmt::Debug for GuardedMutation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardedMutation(<redacted>)")
    }
}
impl GuardedMutation<'_> {
    pub fn request(&self) -> &Request {
        &self.request
    }
    /// Exact original caller deadline; it is never renewed by the proof issuer.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.frame
    }
    pub(crate) fn consume<O>(self, execute: impl FnOnce(Request, Vec<u8>, Instant) -> O) -> O {
        let result = execute(self.request, self.frame, self.deadline);
        // Retain the actual borrowed lock through the complete finite exchange.
        drop(self._lease);
        result
    }
}

impl<'guard> GuardedSessionLease<'guard> {
    /// The proof key is a separate protected helper authority key, not a browser
    /// field or the ordinary mutation/grant key. No caller Boolean is accepted.
    pub fn authorize_mutation(
        self,
        request: Request,
        mutation_key: &[u8],
        proof_key: &[u8],
        original_deadline: Instant,
    ) -> Result<GuardedMutation<'guard>, Error> {
        let millis = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Expired)?
                .as_millis(),
        )
        .map_err(|_| Error::Expired)?;
        self.authorize_at(request, mutation_key, proof_key, original_deadline, millis)
    }
    fn authorize_at(
        self,
        request: Request,
        mutation_key: &[u8],
        proof_key: &[u8],
        original_deadline: Instant,
        checked_millis: u64,
    ) -> Result<GuardedMutation<'guard>, Error> {
        let original_deadline = request
            .workflow_deadline()
            .map(|original| original_deadline.min(original))
            .unwrap_or(original_deadline);
        if !(32..=1024).contains(&proof_key.len()) || proof_key == mutation_key {
            return Err(Error::Authentication);
        }
        let remaining = original_deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(Error::Expired)?;
        let delta = u64::try_from(remaining.as_millis()).map_err(|_| Error::Expired)?;
        if !(1..=60000).contains(&delta) {
            return Err(Error::Expired);
        }
        let deadline_millis = checked_millis.checked_add(delta).ok_or(Error::Expired)?;
        let record = self.record();
        let idle_expires = record
            .last_seen_at
            .checked_add(self.idle_timeout())
            .ok_or(Error::Expired)?
            .min(record.expires_at);
        let seconds = checked_millis / 1000;
        if checked_millis == 0
            || seconds < self.checked_at()
            || seconds >= idle_expires
            || record.revoked_at.is_some()
            || record.factor != crate::auth::RequiredSecondFactor::Totp
            || record.canonical_username != request.account()
            || record.session_id != request.session_id()
            || record.account_epoch != Some(request.epoch())
            || self.request_id() != request.request_id()
            || self.source() != request.source()
            || deadline_millis > idle_expires.checked_mul(1000).ok_or(Error::Expired)?
        {
            return Err(Error::Authentication);
        }
        let raw = request.bytes()?;
        Verifier::default().request(&raw, mutation_key, seconds)?;
        let budget = crate::account_mutation_budget::issue(
            &request,
            mutation_key,
            checked_millis,
            deadline_millis,
        )?;
        let budget: serde_json::Value =
            serde_json::from_slice(&budget).map_err(|_| Error::Invalid)?;
        let canonical_budget = serde_json::to_vec(&budget).map_err(|_| Error::Invalid)?;
        let mut proof = Proof {
            schema: SCHEMA,
            account: request.account(),
            epoch: request.epoch(),
            session_id: request.session_id(),
            request_id: request.request_id(),
            source: request.source(),
            intent_reference: request.intent_reference(),
            request_sha256: hex(&Sha256::digest(&raw)),
            budget_sha256: hex(&Sha256::digest(&canonical_budget)),
            checked_millis,
            session_expires: record.expires_at,
            idle_expires,
            issued: request.issued(),
            expires: request.expires(),
            deadline_millis,
            signature: String::new(),
        };
        let mut mac =
            Hmac::<Sha256>::new_from_slice(proof_key).map_err(|_| Error::Authentication)?;
        mac.update(&payload(&proof)?);
        proof.signature = hex(&mac.finalize().into_bytes());
        let frame = serde_json::to_vec(&serde_json::json!({"budget":budget,"session_proof":proof}))
            .map_err(|_| Error::Invalid)?;
        if frame.len() > MAX_FRAME || Instant::now() >= original_deadline {
            return Err(Error::Expired);
        }
        Ok(GuardedMutation {
            request,
            frame,
            deadline: original_deadline,
            _lease: self,
        })
    }
}

#[cfg(test)]
#[path = "account_guarded_mutation_tests.rs"]
mod tests;
