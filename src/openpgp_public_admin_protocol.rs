//! Authenticated public-key administration. Paths and native commands are absent
//! from the wire; certificate bytes have a fixed bound and are never Debug data.
use crate::identity::CanonicalUsername;
use crate::openpgp_inventory::Inventory;
use crate::openpgp_public_admin::{AdminError, PublicSnapshot};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

const SCHEMA: &str = "osmap-public-admin-wire-v1";
pub const MAX_CERTIFICATE: usize = 65536;
const MAX_HEADER: usize = 2048;
pub const MAX_FRAME: usize = MAX_CERTIFICATE + MAX_HEADER + 4;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    Invalid,
    Unavailable,
    Stale,
    Busy,
    Expired,
    Unconfirmed,
    Authentication,
    Replay,
    Limit,
}
impl From<AdminError> for Error {
    fn from(value: AdminError) -> Self {
        match value {
            AdminError::Invalid => Self::Invalid,
            AdminError::Unavailable => Self::Unavailable,
            AdminError::Stale => Self::Stale,
            AdminError::Busy => Self::Busy,
            AdminError::Expired => Self::Expired,
            AdminError::Unconfirmed => Self::Unconfirmed,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Snapshot,
    ImportPublic,
    RemovePublic,
}
impl Action {
    pub(crate) fn mutation(self) -> bool {
        self != Self::Snapshot
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    account: String,
    issued: u64,
    expires: u64,
    nonce: String,
    action: Action,
    revision: Option<String>,
    fingerprint: Option<String>,
    body_len: usize,
    error: Option<Error>,
    reply: bool,
    mac: String,
}
pub(crate) struct Request {
    header: Header,
    body: Vec<u8>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
pub(crate) fn revision(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn fingerprint(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
}
impl Header {
    fn payload(&self) -> Result<Vec<u8>, Error> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        serde_json::to_vec(&unsigned).map_err(|_| Error::Invalid)
    }
    fn validate(&self, now: u64) -> Result<(), Error> {
        let account = CanonicalUsername::parse(&self.account).map_err(|_| Error::Invalid)?;
        if account.as_str() != self.account
            || self.schema != SCHEMA
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::Invalid);
        }
        if self.expires.checked_sub(self.issued) != Some(10)
            || now < self.issued
            || now >= self.expires
        {
            return Err(Error::Expired);
        }
        if self.body_len > MAX_CERTIFICATE {
            return Err(Error::Limit);
        }
        if self.reply {
            if self.fingerprint.is_some()
                || self.error.is_some() && (self.body_len != 0 || self.revision.is_some())
                || self.error.is_none()
                    && (!self.revision.as_deref().is_some_and(revision) || self.body_len == 0)
            {
                return Err(Error::Invalid);
            }
        } else {
            if self.error.is_some() {
                return Err(Error::Invalid);
            }
            match self.action {
                Action::Snapshot
                    if self.revision.is_none()
                        && self.fingerprint.is_none()
                        && self.body_len == 0 => {}
                Action::ImportPublic
                    if self.revision.as_deref().is_some_and(revision)
                        && self.fingerprint.as_deref().is_some_and(fingerprint)
                        && self.body_len != 0 => {}
                Action::RemovePublic
                    if self.revision.as_deref().is_some_and(revision)
                        && self.fingerprint.as_deref().is_some_and(fingerprint)
                        && self.body_len == 0 => {}
                _ => return Err(Error::Invalid),
            }
        }
        Ok(())
    }
}
fn authenticate(key: &[u8], header: &Header, body: &[u8]) -> Result<HmacSha256, Error> {
    if !(32..=1024).contains(&key.len()) {
        return Err(Error::Authentication);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::Authentication)?;
    mac.update(&header.payload()?);
    mac.update(body);
    Ok(mac)
}
fn verify(key: &[u8], header: &Header, body: &[u8]) -> Result<(), Error> {
    if !revision(&header.mac) {
        return Err(Error::Authentication);
    }
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&header.mac[i..i + 2], 16).map_err(|_| Error::Authentication))
        .collect::<Result<Vec<_>, _>>()?;
    authenticate(key, header, body)?
        .verify_slice(&bytes)
        .map_err(|_| Error::Authentication)
}
fn frame(header: &Header, body: &[u8]) -> Result<Vec<u8>, Error> {
    let meta = serde_json::to_vec(header).map_err(|_| Error::Invalid)?;
    if meta.len() > MAX_HEADER || body.len() > MAX_CERTIFICATE {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::with_capacity(4 + meta.len() + body.len());
    bytes.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&meta);
    bytes.extend_from_slice(body);
    Ok(bytes)
}
fn parse(bytes: &[u8]) -> Result<(Header, &[u8]), Error> {
    if bytes.len() < 4 || bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
    if n == 0 || n > MAX_HEADER || n > bytes.len() - 4 {
        return Err(Error::Invalid);
    }
    let header: Header = serde_json::from_slice(&bytes[4..4 + n]).map_err(|_| Error::Invalid)?;
    let body = &bytes[4 + n..];
    if body.len() != header.body_len {
        return Err(Error::Invalid);
    }
    Ok((header, body))
}
impl Request {
    pub(crate) fn issue(
        account: &str,
        action: Action,
        revision: Option<&str>,
        fingerprint: Option<&str>,
        body: &[u8],
        now: u64,
        key: &[u8],
    ) -> Result<Self, Error> {
        if body.len() > MAX_CERTIFICATE {
            return Err(Error::Limit);
        }
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        let mut header = Header {
            schema: SCHEMA.into(),
            account: account.into(),
            issued: now,
            expires: now.checked_add(10).ok_or(Error::Invalid)?,
            nonce: hex(&nonce),
            action,
            revision: revision.map(str::to_owned),
            fingerprint: fingerprint.map(str::to_owned),
            body_len: body.len(),
            error: None,
            reply: false,
            mac: String::new(),
        };
        header.validate(now)?;
        header.mac = hex(&authenticate(key, &header, body)?.finalize().into_bytes());
        Ok(Self {
            header,
            body: body.to_vec(),
        })
    }
    pub(crate) fn account(&self) -> &str {
        &self.header.account
    }
    pub(crate) fn nonce(&self) -> &str {
        &self.header.nonce
    }
    pub(crate) fn issued(&self) -> u64 {
        self.header.issued
    }
    pub(crate) fn expires(&self) -> u64 {
        self.header.expires
    }
    pub(crate) fn action(&self) -> Action {
        self.header.action
    }
    pub(crate) fn revision(&self) -> Option<&str> {
        self.header.revision.as_deref()
    }
    pub(crate) fn fingerprint(&self) -> Option<&str> {
        self.header.fingerprint.as_deref()
    }
    pub(crate) fn certificate(&self) -> &[u8] {
        &self.body
    }
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        frame(&self.header, &self.body)
    }
    pub(crate) fn response(
        &self,
        result: Result<PublicSnapshot, Error>,
        key: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let mut header = self.header.clone();
        header.reply = true;
        header.fingerprint = None;
        let body = match result {
            Ok(snapshot) => {
                header.revision = Some(snapshot.revision);
                header.error = None;
                snapshot.inventory.to_bytes().map_err(|_| Error::Invalid)?
            }
            Err(error) => {
                header.revision = None;
                header.error = Some(error);
                Vec::new()
            }
        };
        header.body_len = body.len();
        header.validate(now)?;
        header.mac = hex(&authenticate(key, &header, &body)?.finalize().into_bytes());
        frame(&header, &body)
    }
}
#[derive(Default)]
pub(crate) struct Verifier {
    requests: BTreeMap<String, u64>,
    responses: BTreeMap<String, u64>,
    high_water: u64,
}
fn admit(
    cache: &mut BTreeMap<String, u64>,
    nonce: &str,
    expires: u64,
    now: u64,
) -> Result<(), Error> {
    cache.retain(|_, expiry| *expiry > now);
    if cache.contains_key(nonce) {
        return Err(Error::Replay);
    }
    if cache.len() >= 4096 {
        return Err(Error::Busy);
    }
    cache.insert(nonce.to_owned(), expires);
    Ok(())
}
impl Verifier {
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.high_water {
            return Err(Error::Expired);
        }
        self.high_water = now;
        Ok(())
    }
    pub(crate) fn request(&mut self, bytes: &[u8], key: &[u8], now: u64) -> Result<Request, Error> {
        self.clock(now)?;
        let (header, body) = parse(bytes)?;
        header.validate(now)?;
        if header.reply {
            return Err(Error::Invalid);
        }
        verify(key, &header, body)?;
        admit(&mut self.requests, &header.nonce, header.expires, now)?;
        Ok(Request {
            header,
            body: body.to_vec(),
        })
    }
    pub(crate) fn response(
        &mut self,
        request: &Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<Result<PublicSnapshot, Error>, Error> {
        self.clock(now)?;
        let (header, body) = parse(bytes)?;
        header.validate(now)?;
        if !header.reply
            || header.account != request.header.account
            || header.nonce != request.header.nonce
            || header.action != request.header.action
            || header.issued != request.header.issued
            || header.expires != request.header.expires
        {
            return Err(Error::Authentication);
        }
        verify(key, &header, body)?;
        admit(&mut self.responses, &header.nonce, header.expires, now)?;
        if let Some(error) = header.error {
            return Ok(Err(error));
        }
        let inventory = Inventory::parse(body).map_err(|_| Error::Invalid)?;
        if inventory.keys().is_none() {
            return Err(Error::Invalid);
        }
        Ok(Ok(PublicSnapshot {
            inventory,
            revision: header.revision.ok_or(Error::Invalid)?,
        }))
    }
}
#[cfg(test)]
#[path = "openpgp_public_admin_protocol_tests.rs"]
mod tests;
