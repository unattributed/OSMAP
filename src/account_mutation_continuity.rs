//! Guarded-only authenticated pending-before-write ACK, never a browser action.
use crate::account_mutation::Request;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const SCHEMA: &str = "osmap-account-mutation-continuity-v1";
pub(crate) const LIMIT: usize = 2048;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    schema: String,
    phase: String,
    account: String,
    epoch: u64,
    intent_reference: String,
    request_signature: String,
    frame_sha256: String,
    nonce: String,
    deadline_millis: u64,
    challenged_millis: u64,
    signature: String,
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn lower(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn payload(v: &Challenge) -> Result<Vec<u8>, ()> {
    serde_json::to_vec(&(
        SCHEMA,
        &v.phase,
        &v.account,
        v.epoch,
        &v.intent_reference,
        &v.request_signature,
        &v.frame_sha256,
        &v.nonce,
        v.deadline_millis,
        v.challenged_millis,
    ))
    .map_err(|_| ())
}
/// Called exclusively during GuardedMutation's borrowed actual stored-session
/// lock. ACK is a proof of that response, while helper durable pending contains
/// loss after it; it does not assert continued cross-host lock ownership.
pub(crate) fn acknowledge(
    request: &Request,
    frame: &[u8],
    raw: &[u8],
    key: &[u8],
    now_millis: u64,
) -> Result<Vec<u8>, ()> {
    if raw.is_empty() || raw.len() > LIMIT || !(32..=1024).contains(&key.len()) {
        return Err(());
    }
    let mut value: Challenge = serde_json::from_slice(raw).map_err(|_| ())?;
    let inner: serde_json::Value =
        serde_json::from_slice(&request.bytes().map_err(|_| ())?).map_err(|_| ())?;
    let guarded: serde_json::Value = serde_json::from_slice(frame).map_err(|_| ())?;
    let original = guarded
        .get("budget")
        .and_then(|v| v.get("deadline_millis"))
        .and_then(|v| v.as_u64())
        .ok_or(())?;
    if value.schema != SCHEMA
        || value.phase != "challenge"
        || value.account != request.account()
        || value.epoch != request.epoch()
        || value.intent_reference != request.intent_reference()
        || Some(value.request_signature.as_str()) != inner.get("signature").and_then(|v| v.as_str())
        || value.frame_sha256 != hex(&Sha256::digest(frame))
        || !lower(&value.nonce)
        || !lower(&value.signature)
        || value.deadline_millis != original
        || value.challenged_millis == 0
        || now_millis < value.challenged_millis
        || now_millis >= value.deadline_millis
        || value.deadline_millis <= value.challenged_millis
        || value.deadline_millis - value.challenged_millis > 60000
    {
        return Err(());
    }
    let signature = (0..64)
        .step_by(2)
        .map(|n| u8::from_str_radix(&value.signature[n..n + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ())?;
    mac.update(&payload(&value)?);
    mac.verify_slice(&signature).map_err(|_| ())?;
    value.phase = "ack".into();
    value.signature = String::new();
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| ())?;
    mac.update(&payload(&value)?);
    value.signature = hex(&mac.finalize().into_bytes());
    let result = serde_json::to_vec(&value).map_err(|_| ())?;
    if result.len() > LIMIT {
        return Err(());
    }
    Ok(result)
}

#[cfg(all(test, unix))]
#[path = "account_mutation_continuity_tests.rs"]
pub(crate) mod tests;
