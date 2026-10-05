//! Typed own-password action codec only; no socket, writer or activation.
//! A request consumes the sealed fresh-action dispatch, never a Boolean factor
//! claim. Secrets have no public Deserialize/Clone/Debug representation. Worker
//! integration must still revalidate stored session authority and durably consume
//! the action intent under the account lock; this replay cache is process-local.
use crate::account_admission::{valid_account, MAX_EPOCH};
use crate::password_change::Dispatch;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

pub const MAX_FRAME: usize = crate::account_admission::MAX_FRAME;
const SCHEMA: &str = "osmap-account-mutation-v1";
const ACTION: &str = "change_password";
const WINDOW: u64 = 300;
type HmacSha256 = Hmac<Sha256>;

/// None of these errors proves that a dispatched credential write did not occur.
/// Only an authenticated Outcome::KnownRefused makes that claim. A transport
/// timeout or malformed reply must remain uncertain at the future caller.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Authentication,
    Expired,
    Replay,
    Capacity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    schema: String,
    action: String,
    account: String,
    epoch: u64,
    intent_reference: String,
    session_id: String,
    request_id: String,
    source: String,
    issued: u64,
    expires: u64,
    current: String,
    new: String,
    confirmation: String,
    signature: String,
}

pub struct Request(RequestWire, Option<std::time::Instant>);
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountMutationRequest(<redacted>)")
    }
}

/// Sanitized semantic outcomes, never credentials or an arbitrary backend error.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    KnownRefused,
    Changed { epoch: u64, changed_at: String },
    Contained,
}

/// A matching authenticated terminal reply, consumed once by the caller.
/// This proves wire authenticity and exact action binding, not database effects.
/// Credentials and a reusable request are deliberately absent.
pub struct TerminalReceipt {
    account: String,
    old_epoch: u64,
    session_id: String,
    request_id: String,
    intent_reference: String,
    source: String,
    issued: u64,
    expires: u64,
    responded_at: u64,
    outcome: Outcome,
}
impl std::fmt::Debug for TerminalReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountMutationTerminalReceipt(<redacted>)")
    }
}
impl TerminalReceipt {
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn old_epoch(&self) -> u64 {
        self.old_epoch
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn intent_reference(&self) -> &str {
        &self.intent_reference
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn responded_at(&self) -> u64 {
        self.responded_at
    }
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
}
// Empty struct variants enforce unknown-field refusal; serde's internally
// tagged unit variants otherwise ignore extra fields despite the enum setting.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum StrictOutcome {
    KnownRefused {},
    Changed { epoch: u64, changed_at: String },
    Contained {},
}
impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match StrictOutcome::deserialize(deserializer)? {
            StrictOutcome::KnownRefused {} => Self::KnownRefused,
            StrictOutcome::Changed { epoch, changed_at } => Self::Changed { epoch, changed_at },
            StrictOutcome::Contained {} => Self::Contained,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    schema: String,
    action: String,
    account: String,
    intent_reference: String,
    request_id: String,
    request_signature: String,
    responded_at: u64,
    outcome: Outcome,
    signature: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}
fn mac(key: &[u8], bytes: &[u8]) -> Result<HmacSha256, Error> {
    if !(32..=1024).contains(&key.len()) {
        return Err(Error::Authentication);
    }
    let mut result = HmacSha256::new_from_slice(key).map_err(|_| Error::Authentication)?;
    result.update(bytes);
    Ok(result)
}
fn verify(key: &[u8], bytes: &[u8], signature: &str) -> Result<(), Error> {
    if !lower_hex(signature, 64) {
        return Err(Error::Authentication);
    }
    let decoded: Result<Vec<_>, _> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&signature[i..i + 2], 16))
        .collect();
    mac(key, bytes)?
        .verify_slice(&decoded.map_err(|_| Error::Authentication)?)
        .map_err(|_| Error::Authentication)
}
fn frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
fn changed_at_valid(value: &str) -> bool {
    if value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let number = |start, end| value[start..end].parse::<u32>().unwrap_or(0);
    let year = number(0, 4);
    let month = number(4, 6);
    let day = number(6, 8);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return false,
    };
    year > 0
        && day > 0
        && day <= days
        && number(8, 10) < 24
        && number(10, 12) < 60
        && number(12, 14) < 60
}

impl Request {
    /// The only request issuer consumes an actual sealed fresh-action dispatch.
    /// Signing retains its original deadline rather than granting a new window.
    pub fn issue(dispatch: Dispatch<'_>, key: &[u8], now: u64) -> Result<Self, Error> {
        let workflow_deadline = dispatch.workflow_deadline();
        if workflow_deadline.is_some_and(|value| std::time::Instant::now() >= value) {
            return Err(Error::Expired);
        }
        let mut request = Self(
            RequestWire {
                schema: SCHEMA.into(),
                action: ACTION.into(),
                account: dispatch.account().into(),
                epoch: dispatch.epoch(),
                intent_reference: dispatch.intent_reference().into(),
                session_id: dispatch.session_id().into(),
                request_id: dispatch.request_id().into(),
                source: dispatch.source().into(),
                issued: dispatch.issued(),
                expires: dispatch.expires(),
                current: dispatch.current().into(),
                new: dispatch.new_password().into(),
                confirmation: dispatch.confirmation().into(),
                signature: String::new(),
            },
            workflow_deadline,
        );
        request.shape()?;
        request.time(now)?;
        request.0.signature = hex(&mac(key, &request.payload()?)?.finalize().into_bytes());
        request.bytes()?;
        if workflow_deadline.is_some_and(|value| std::time::Instant::now() >= value) {
            return Err(Error::Expired);
        }
        Ok(request)
    }
    pub(crate) fn workflow_deadline(&self) -> Option<std::time::Instant> {
        self.1
    }
    fn shape(&self) -> Result<(), Error> {
        let r = &self.0;
        valid_account(&r.account).map_err(|_| Error::Invalid)?;
        if r.schema != SCHEMA
            || r.action != ACTION
            || r.epoch >= MAX_EPOCH
            || !lower_hex(&r.intent_reference, 64)
            || !lower_hex(&r.session_id, 64)
            || !bounded(&r.request_id, crate::auth::DEFAULT_REQUEST_ID_MAX_LEN)
            || r.request_id.trim().is_empty()
            || !bounded(&r.source, crate::auth::DEFAULT_REMOTE_ADDR_MAX_LEN)
            || r.source.parse::<std::net::IpAddr>().is_err()
            || !bounded(&r.current, 1024)
            || !bounded(&r.new, 512)
            || !(15..=128).contains(&r.new.chars().count())
            || r.new != r.confirmation
            || r.current == r.new
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn time(&self, now: u64) -> Result<(), Error> {
        let r = &self.0;
        if r.issued == 0
            || r.expires.checked_sub(r.issued) != Some(WINDOW)
            || now < r.issued
            || now >= r.expires
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn payload(&self) -> Result<Vec<u8>, Error> {
        let r = &self.0;
        serde_json::to_vec(&(
            SCHEMA,
            ACTION,
            "request",
            &r.account,
            r.epoch,
            &r.intent_reference,
            &r.session_id,
            &r.request_id,
            &r.source,
            r.issued,
            r.expires,
            &r.current,
            &r.new,
            &r.confirmation,
        ))
        .map_err(|_| Error::Invalid)
    }
    fn valid(&self, key: &[u8], now: u64) -> Result<(), Error> {
        self.shape()?;
        self.time(now)?;
        verify(key, &self.payload()?, &self.0.signature)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        frame(&self.0)
    }
    pub fn account(&self) -> &str {
        &self.0.account
    }
    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }
    pub fn intent_reference(&self) -> &str {
        &self.0.intent_reference
    }
    pub fn session_id(&self) -> &str {
        &self.0.session_id
    }
    pub fn request_id(&self) -> &str {
        &self.0.request_id
    }
    pub fn source(&self) -> &str {
        &self.0.source
    }
    pub fn issued(&self) -> u64 {
        self.0.issued
    }
    pub fn expires(&self) -> u64 {
        self.0.expires
    }
    pub fn current(&self) -> &str {
        &self.0.current
    }
    pub fn new_password(&self) -> &str {
        &self.0.new
    }
    pub fn confirmation(&self) -> &str {
        &self.0.confirmation
    }
    fn outcome_valid(&self, outcome: &Outcome) -> Result<(), Error> {
        match outcome {
            Outcome::Changed { epoch, changed_at }
                if self.0.epoch.checked_add(1) != Some(*epoch)
                    || *epoch > MAX_EPOCH
                    || !changed_at_valid(changed_at) =>
            {
                Err(Error::Invalid)
            }
            _ => Ok(()),
        }
    }
    /// Future helper integration must supply only measured coordinator outcomes.
    /// The codec authenticates this claim; it cannot establish database effects.
    pub fn response(&self, outcome: Outcome, key: &[u8], now: u64) -> Result<Vec<u8>, Error> {
        self.valid(key, now)?;
        self.outcome_valid(&outcome)?;
        let mut r = ResponseWire {
            schema: SCHEMA.into(),
            action: ACTION.into(),
            account: self.0.account.clone(),
            intent_reference: self.0.intent_reference.clone(),
            request_id: self.0.request_id.clone(),
            request_signature: self.0.signature.clone(),
            responded_at: now,
            outcome,
            signature: String::new(),
        };
        r.signature = hex(&mac(key, &r.payload()?)?.finalize().into_bytes());
        frame(&r)
    }
}
impl ResponseWire {
    fn payload(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&(
            SCHEMA,
            ACTION,
            "response",
            &self.account,
            &self.intent_reference,
            &self.request_id,
            &self.request_signature,
            self.responded_at,
            &self.outcome,
        ))
        .map_err(|_| Error::Invalid)
    }
}

#[derive(Default)]
pub struct Verifier {
    seen: BTreeMap<(bool, String, String), u64>,
    high_water: u64,
}
impl Verifier {
    fn consume(&mut self, r: &Request, response: bool, now: u64) -> Result<(), Error> {
        if now < self.high_water {
            return Err(Error::Expired);
        }
        self.high_water = now;
        self.seen.retain(|_, expires| *expires > now);
        let id = (response, r.0.account.clone(), r.0.intent_reference.clone());
        if self.seen.contains_key(&id) {
            return Err(Error::Replay);
        }
        if self.seen.len() >= 128 {
            return Err(Error::Capacity);
        }
        self.seen.insert(id, r.0.expires);
        Ok(())
    }
    pub fn request(&mut self, bytes: &[u8], key: &[u8], now: u64) -> Result<Request, Error> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        let r = Request(
            serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?,
            None,
        );
        r.valid(key, now)?;
        self.consume(&r, false, now)?;
        Ok(r)
    }
    /// Errors, including expiry and invalid replies, are not KnownRefused.
    pub fn response(
        &mut self,
        request: &Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<Outcome, Error> {
        self.verified_response(request, bytes, key, now)
            .map(|r| r.outcome)
    }

    /// Consume the original request and seal only its authenticated reply.
    pub fn terminal_response(
        &mut self,
        request: Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<TerminalReceipt, Error> {
        let reply = self.verified_response(&request, bytes, key, now)?;
        Ok(TerminalReceipt {
            account: request.0.account,
            old_epoch: request.0.epoch,
            session_id: request.0.session_id,
            request_id: request.0.request_id,
            intent_reference: request.0.intent_reference,
            source: request.0.source,
            issued: request.0.issued,
            expires: request.0.expires,
            responded_at: reply.responded_at,
            outcome: reply.outcome,
        })
    }

    fn verified_response(
        &mut self,
        request: &Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<ResponseWire, Error> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        request.valid(key, now)?;
        let r: ResponseWire = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if r.schema != SCHEMA
            || r.action != ACTION
            || r.account != request.0.account
            || r.intent_reference != request.0.intent_reference
            || r.request_id != request.0.request_id
            || r.request_signature != request.0.signature
        {
            return Err(Error::Authentication);
        }
        if r.responded_at < request.0.issued
            || r.responded_at > now
            || r.responded_at >= request.0.expires
        {
            return Err(Error::Expired);
        }
        verify(key, &r.payload()?, &r.signature)?;
        request.outcome_valid(&r.outcome)?;
        self.consume(request, true, now)?;
        Ok(r)
    }
}

#[cfg(test)]
#[path = "account_mutation_tests.rs"]
pub(crate) mod tests;
