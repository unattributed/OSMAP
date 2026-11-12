//! Separately versioned authenticated public-inventory transport. No executable or home paths.
use crate::{
    identity::CanonicalUsername,
    openpgp_inventory::{Error, Inventory, MAX_METADATA},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
type HmacSha256 = Hmac<Sha256>;
const SCHEMA: &str = "osmap-public-inventory-wire-v1";
const OP: &str = "public_inventory";
const MAX_WIRE: usize = MAX_METADATA * 2 + 4096;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    schema: String,
    operation: String,
    account: String,
    issued: u64,
    expires: u64,
    nonce: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema: String,
    operation: String,
    account: String,
    nonce: String,
    inventory: String,
    signature: String,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Authentication);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::Authentication))
        .collect()
}
fn mac(key: &[u8], data: &[u8]) -> Result<HmacSha256, Error> {
    if !(32..=1024).contains(&key.len()) {
        return Err(Error::Authentication);
    }
    let mut m = HmacSha256::new_from_slice(key).map_err(|_| Error::Authentication)?;
    m.update(data);
    Ok(m)
}
fn check(key: &[u8], data: &[u8], signature: &str) -> Result<(), Error> {
    mac(key, data)?
        .verify_slice(&unhex(signature)?)
        .map_err(|_| Error::Authentication)
}
impl Request {
    pub fn issue(account: &str, now: u64, key: &[u8]) -> Result<Self, Error> {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
        Self::issue_nonce(account, now, hex(&random), key)
    }
    fn issue_nonce(account: &str, now: u64, nonce: String, key: &[u8]) -> Result<Self, Error> {
        CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        let mut r = Self {
            schema: SCHEMA.into(),
            operation: OP.into(),
            account: account.into(),
            issued: now,
            expires: now.checked_add(10).ok_or(Error::Invalid)?,
            nonce,
            signature: String::new(),
        };
        r.signature = hex(&mac(key, &r.payload()?)?.finalize().into_bytes());
        Ok(r)
    }
    fn payload(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&(
            SCHEMA,
            "request",
            &self.operation,
            &self.account,
            self.issued,
            self.expires,
            &self.nonce,
        ))
        .map_err(|_| Error::Invalid)
    }
    fn validate(&self, account: &str, now: u64, key: &[u8]) -> Result<(), Error> {
        CanonicalUsername::parse(&self.account).map_err(|_| Error::Invalid)?;
        if self.schema != SCHEMA
            || self.operation != OP
            || self.account != account
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Authentication);
        }
        if self.expires.checked_sub(self.issued) != Some(10)
            || now < self.issued
            || now >= self.expires
        {
            return Err(Error::Expired);
        }
        check(key, &self.payload()?, &self.signature)
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Invalid)
    }
    pub fn response(&self, inventory: &Inventory, key: &[u8], now: u64) -> Result<Vec<u8>, Error> {
        self.validate(&self.account, now, key)?;
        let mut r = Response {
            schema: SCHEMA.into(),
            operation: OP.into(),
            account: self.account.clone(),
            nonce: self.nonce.clone(),
            inventory: String::from_utf8(inventory.to_bytes()?).map_err(|_| Error::Invalid)?,
            signature: String::new(),
        };
        r.signature = hex(&mac(key, &r.payload()?)?.finalize().into_bytes());
        let bytes = serde_json::to_vec(&r).map_err(|_| Error::Invalid)?;
        if bytes.len() > MAX_WIRE {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
}
impl Response {
    fn payload(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&(
            SCHEMA,
            "response",
            &self.operation,
            &self.account,
            &self.nonce,
            &self.inventory,
        ))
        .map_err(|_| Error::Invalid)
    }
}
/// Keep one verifier per receiving endpoint; serialize access around verification and dispatch.
#[derive(Default)]
pub struct Verifier {
    seen: BTreeMap<(bool, String, String), u64>,
    high_water: u64,
}
impl Verifier {
    fn consume(&mut self, r: &Request, response: bool, now: u64) -> Result<(), Error> {
        if now < self.high_water {
            return Err(Error::Clock);
        }
        self.high_water = now;
        self.seen.retain(|_, expires| *expires > now);
        let id = (response, r.account.clone(), r.nonce.clone());
        if self.seen.contains_key(&id) {
            return Err(Error::Replay);
        }
        if self.seen.len() >= 1024 {
            return Err(Error::Capacity);
        }
        self.seen.insert(id, r.expires);
        Ok(())
    }
    pub fn request(
        &mut self,
        bytes: &[u8],
        account: &str,
        key: &[u8],
        now: u64,
    ) -> Result<Request, Error> {
        if bytes.len() > 2048 {
            return Err(Error::Limit);
        }
        let r: Request = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        r.validate(account, now, key)?;
        self.consume(&r, false, now)?;
        Ok(r)
    }
    pub fn response(
        &mut self,
        request: &Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<Inventory, Error> {
        if bytes.len() > MAX_WIRE {
            return Err(Error::Limit);
        }
        request.validate(request.account(), now, key)?;
        let r: Response = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if r.schema != SCHEMA
            || r.operation != OP
            || r.account != request.account
            || r.nonce != request.nonce
        {
            return Err(Error::Authentication);
        }
        check(key, &r.payload()?, &r.signature)?;
        let inventory = Inventory::parse(r.inventory.as_bytes())?;
        self.consume(request, true, now)?;
        Ok(inventory)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_bind_account_request_response_and_replay() {
        let key = [7; 32];
        let r = Request::issue_nonce("alice", 100, "a".repeat(32), &key).unwrap();
        let bytes = r.to_bytes().unwrap();
        let mut v = Verifier::default();
        assert!(v.request(&bytes, "bob", &key, 101).is_err());
        assert!(v.request(&bytes, "alice", &[8; 32], 101).is_err());
        assert!(v.request(&bytes, "alice", &key, 99).is_err());
        assert!(v.request(&bytes, "alice", &key, 110).is_err());
        let verified = v.request(&bytes, "alice", &key, 101).unwrap();
        assert!(matches!(
            v.request(&bytes, "alice", &key, 101),
            Err(Error::Replay)
        ));
        let inv = Inventory::parse(br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#)
            .unwrap();
        let response = verified.response(&inv, &key, 102).unwrap();
        let mut client = Verifier::default();
        let other = Request::issue_nonce("alice", 100, "b".repeat(32), &key).unwrap();
        assert!(client.response(&other, &response, &key, 102).is_err());
        let mut tampered: serde_json::Value = serde_json::from_slice(&response).unwrap();
        tampered["inventory"] = serde_json::json!("{}");
        assert!(client
            .response(&r, &serde_json::to_vec(&tampered).unwrap(), &key, 102)
            .is_err());
        assert!(client
            .response(&r, &response, &key, 102)
            .unwrap()
            .keys()
            .is_none());
        assert!(matches!(
            client.response(&r, &response, &key, 102),
            Err(Error::Replay)
        ));
        let mut raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for field in ["keyhome", "path", "pattern"] {
            raw[field] = serde_json::json!("test");
            assert!(Verifier::default()
                .request(&serde_json::to_vec(&raw).unwrap(), "alice", &key, 101)
                .is_err());
            raw.as_object_mut().unwrap().remove(field);
        }
        raw["signature"] = serde_json::json!("");
        assert!(Verifier::default()
            .request(&serde_json::to_vec(&raw).unwrap(), "alice", &key, 101)
            .is_err());
        let duplicate = String::from_utf8(bytes).unwrap().replace(
            "\"operation\":",
            "\"operation\":\"public_inventory\",\"operation\":",
        );
        assert!(Verifier::default()
            .request(duplicate.as_bytes(), "alice", &key, 101)
            .is_err());
    }
    #[test]
    fn replay_capacity_clock_and_expiry_are_bounded() {
        let key = [9; 32];
        let mut v = Verifier::default();
        for n in 0..1024 {
            let r = Request::issue_nonce("alice", 100, format!("{n:032x}"), &key).unwrap();
            v.request(&r.to_bytes().unwrap(), "alice", &key, 101)
                .unwrap();
        }
        let next = Request::issue_nonce("alice", 100, format!("{:032x}", 1024), &key).unwrap();
        assert!(matches!(
            v.request(&next.to_bytes().unwrap(), "alice", &key, 101),
            Err(Error::Capacity)
        ));
        assert!(matches!(
            v.request(&next.to_bytes().unwrap(), "alice", &key, 100),
            Err(Error::Clock)
        ));
        let fresh = Request::issue_nonce("alice", 110, "f".repeat(32), &key).unwrap();
        v.request(&fresh.to_bytes().unwrap(), "alice", &key, 110)
            .unwrap();
        assert_eq!(v.seen.len(), 1);
    }
}
