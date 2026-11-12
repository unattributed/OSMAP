//! Additive authenticated original-budget envelope; inner v1 bytes stay exact.
use crate::account_mutation::{Error, Request, Verifier};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
const SCHEMA: &str = "osmap-account-mutation-budget-v1";
pub(crate) const MAX_FRAME: usize = 12288;
#[derive(Serialize)]
struct Wire<'a> {
    schema: &'static str,
    request_hex: String,
    raw_sha256: String,
    account: &'a str,
    intent_reference: &'a str,
    request_signature: String,
    sent_millis: u64,
    deadline_millis: u64,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    schema: String,
    request_hex: String,
    raw_sha256: String,
    account: String,
    intent_reference: String,
    request_signature: String,
    sent_millis: u64,
    deadline_millis: u64,
    signature: String,
}

/// Exact authenticated envelope, with one monotonic deadline captured from the
/// receiver's original wall/monotonic sample. No Clone or serialization.
pub(crate) struct VerifiedBudget {
    request: Request,
    raw: Vec<u8>,
    sent_millis: u64,
    deadline_millis: u64,
    deadline: Instant,
}
impl VerifiedBudget {
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn sent_millis(&self) -> u64 {
        self.sent_millis
    }
    pub(crate) fn deadline_millis(&self) -> u64 {
        self.deadline_millis
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn into_request(self) -> Request {
        self.request
    }
}

#[cfg(test)]
pub(crate) fn verify(
    raw: &[u8],
    key: &[u8],
    received_millis: u64,
    received: Instant,
) -> Result<VerifiedBudget, Error> {
    if raw.is_empty() || raw.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    let wire: Envelope = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
    verify_envelope(&wire, key, received_millis, received)
}

pub(crate) fn verify_envelope(
    wire: &Envelope,
    key: &[u8],
    received_millis: u64,
    received: Instant,
) -> Result<VerifiedBudget, Error> {
    if !(32..=1024).contains(&key.len())
        || wire.schema != SCHEMA
        || received > Instant::now()
        || wire.sent_millis == 0
        || !matches!(
            wire.deadline_millis.checked_sub(wire.sent_millis),
            Some(1..=60000)
        )
        || received_millis < wire.sent_millis
        || received_millis >= wire.deadline_millis
    {
        return Err(Error::Expired);
    }
    let signature = decode_hex(&wire.signature, 64)?;
    for value in [
        &wire.raw_sha256,
        &wire.intent_reference,
        &wire.request_signature,
    ] {
        decode_hex(value, 64)?;
    }
    let payload = serde_json::to_vec(&(
        SCHEMA,
        "remaining_budget",
        &wire.raw_sha256,
        &wire.account,
        &wire.intent_reference,
        &wire.request_signature,
        wire.sent_millis,
        wire.deadline_millis,
    ))
    .map_err(|_| Error::Invalid)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Authentication)?;
    mac.update(&payload);
    mac.verify_slice(&signature)
        .map_err(|_| Error::Authentication)?;
    if wire.request_hex.is_empty() || wire.request_hex.len() > 8192 {
        return Err(Error::Invalid);
    }
    let raw = decode_hex(&wire.request_hex, wire.request_hex.len())?;
    if hex(&Sha256::digest(&raw)) != wire.raw_sha256 {
        return Err(Error::Authentication);
    }
    let request = Verifier::default().request(&raw, key, received_millis / 1000)?;
    let inner: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| Error::Invalid)?;
    if request.account() != wire.account
        || request.intent_reference() != wire.intent_reference
        || inner.get("signature").and_then(|v| v.as_str()) != Some(wire.request_signature.as_str())
        || wire.deadline_millis > request.expires().checked_mul(1000).ok_or(Error::Expired)?
    {
        return Err(Error::Authentication);
    }
    let deadline = received
        .checked_add(Duration::from_millis(
            wire.deadline_millis - received_millis,
        ))
        .ok_or(Error::Expired)?;
    if Instant::now() >= deadline {
        return Err(Error::Expired);
    }
    Ok(VerifiedBudget {
        request,
        raw,
        sent_millis: wire.sent_millis,
        deadline_millis: wire.deadline_millis,
        deadline,
    })
}

pub(crate) fn decode_hex(value: &str, length: usize) -> Result<Vec<u8>, Error> {
    if value.len() != length
        || length == 0
        || length % 2 != 0
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| Error::Invalid)?;
            u8::from_str_radix(text, 16).map_err(|_| Error::Invalid)
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn issue(
    request: &Request,
    key: &[u8],
    sent_millis: u64,
    deadline_millis: u64,
) -> Result<Vec<u8>, Error> {
    if sent_millis == 0
        || !matches!(deadline_millis.checked_sub(sent_millis), Some(1..=60000))
        || deadline_millis > request.expires().checked_mul(1000).ok_or(Error::Invalid)?
    {
        return Err(Error::Expired);
    }
    let raw = request.bytes()?;
    Verifier::default().request(&raw, key, sent_millis / 1000)?;
    // The unchanged v1 signature is bound by both exact raw digest and MAC.
    let inner: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| Error::Invalid)?;
    let request_signature = inner["signature"]
        .as_str()
        .ok_or(Error::Invalid)?
        .to_owned();
    let mut wire = Wire {
        schema: SCHEMA,
        request_hex: hex(&raw),
        raw_sha256: hex(&Sha256::digest(&raw)),
        account: request.account(),
        intent_reference: request.intent_reference(),
        request_signature,
        sent_millis,
        deadline_millis,
        signature: String::new(),
    };
    let payload = serde_json::to_vec(&(
        SCHEMA,
        "remaining_budget",
        &wire.raw_sha256,
        wire.account,
        wire.intent_reference,
        &wire.request_signature,
        sent_millis,
        deadline_millis,
    ))
    .map_err(|_| Error::Invalid)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Invalid)?;
    mac.update(&payload);
    wire.signature = hex(&mac.finalize().into_bytes());
    let raw = serde_json::to_vec(&wire).map_err(|_| Error::Invalid)?;
    if raw.len() > MAX_FRAME {
        return Err(Error::Invalid);
    }
    Ok(raw)
}
#[cfg(test)]
#[path = "account_mutation_budget_tests.rs"]
mod tests;
