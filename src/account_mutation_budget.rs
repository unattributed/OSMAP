//! Additive authenticated original-budget envelope; inner v1 bytes stay exact.
use crate::account_mutation::{Error, Request, Verifier};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
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
