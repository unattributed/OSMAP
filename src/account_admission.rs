//! Own-account helper admission. No password change or administrative operation.
use crate::identity::CanonicalUsername;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

pub const MAX_FRAME: usize = 4096;
/// Last durable readable epoch. It may admit sessions but cannot advance again.
pub const MAX_EPOCH: u64 = u64::MAX - 1;
pub(crate) fn valid_epoch(epoch: u64) -> bool {
    epoch <= MAX_EPOCH
}
const SCHEMA: &str = "osmap-account-admission-v1";
const WINDOW: u64 = 35;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Refused,
    Unavailable,
    Authentication,
    Replay,
    Expired,
    Capacity,
    CleanupUnconfirmed,
}

/// Session issuance must use the exact epoch captured by successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub account: String,
    pub epoch: u64,
}

pub trait EpochAuthority: Send + Sync {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), Error>;
    /// Default bounded callback contract; native transports override the I/O
    /// cap with the caller's exact original deadline instead of a fresh timeout.
    fn admit_before(
        &self,
        account: &str,
        epoch: u64,
        deadline: std::time::Instant,
    ) -> Result<(), Error> {
        if std::time::Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        let result = self.admit(account, epoch);
        if std::time::Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        result
    }
}

/// Exact existing authoritative adapter profile; never a Dovecot option/name glob.
pub(crate) fn valid_account(account: &str) -> Result<(), Error> {
    CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
    let Some((local, domain)) = account.split_once('@') else {
        return Err(Error::Invalid);
    };
    if account.len() > 255
        || local.is_empty()
        || local.len() > 191
        || domain.is_empty()
        || domain.len() > 64
        || !local.as_bytes()[0].is_ascii_alphanumeric()
        || !domain.as_bytes()[0].is_ascii_alphanumeric()
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Authenticate { password: String },
    Admit { epoch: u64 },
}
impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticate { .. } => f.write_str("Authenticate(<redacted>)"),
            Self::Admit { epoch } => f.debug_tuple("Admit").field(epoch).finish(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    schema: String,
    account: String,
    operation: Operation,
    issued: u64,
    expires: u64,
    nonce: String,
    signature: String,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountAdmissionRequest(<redacted>)")
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema: String,
    account: String,
    nonce: String,
    status: String,
    epoch: Option<u64>,
    signature: String,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
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
impl Request {
    pub fn issue(account: &str, operation: Operation, now: u64, key: &[u8]) -> Result<Self, Error> {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        let mut r = Self {
            schema: SCHEMA.into(),
            account: account.into(),
            operation,
            issued: now,
            expires: now.checked_add(WINDOW).ok_or(Error::Invalid)?,
            nonce: hex(&nonce),
            signature: String::new(),
        };
        r.shape()?;
        r.signature = hex(&mac(key, &r.payload()?)?.finalize().into_bytes());
        Ok(r)
    }
    fn shape(&self) -> Result<(), Error> {
        valid_account(&self.account)?;
        if self.schema != SCHEMA
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        match &self.operation {
            Operation::Authenticate { password }
                if password.is_empty()
                    || password.len() > 1024
                    || password.chars().any(char::is_control) =>
            {
                return Err(Error::Invalid)
            }
            Operation::Admit { epoch } if !valid_epoch(*epoch) => return Err(Error::Invalid),
            _ => {}
        }
        Ok(())
    }
    fn payload(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&(
            SCHEMA,
            "request",
            &self.account,
            &self.operation,
            self.issued,
            self.expires,
            &self.nonce,
        ))
        .map_err(|_| Error::Invalid)
    }
    pub(crate) fn valid(&self, key: &[u8], now: u64) -> Result<(), Error> {
        self.shape()?;
        if self.expires.checked_sub(self.issued) != Some(WINDOW)
            || now < self.issued
            || now >= self.expires
        {
            return Err(Error::Expired);
        }
        verify(key, &self.payload()?, &self.signature)
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn operation(&self) -> &Operation {
        &self.operation
    }
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let b = serde_json::to_vec(self).map_err(|_| Error::Invalid)?;
        if b.len() > MAX_FRAME {
            Err(Error::Invalid)
        } else {
            Ok(b)
        }
    }
    pub(crate) fn worker_bytes(&self) -> Result<Vec<u8>, Error> {
        let v = match &self.operation {
            Operation::Authenticate { password } => {
                serde_json::json!({"schema":"osmap-account-admission-worker-v1","operation":"authenticate","account":self.account,"password":password})
            }
            Operation::Admit { epoch } => {
                serde_json::json!({"schema":"osmap-account-admission-worker-v1","operation":"admit","account":self.account,"epoch":epoch})
            }
        };
        serde_json::to_vec(&v).map_err(|_| Error::Invalid)
    }
    pub(crate) fn response(
        &self,
        admission: Option<u64>,
        key: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        if admission.is_some_and(|epoch| !valid_epoch(epoch)) {
            return Err(Error::Invalid);
        }
        self.valid(key, now)?;
        let mut r = Response {
            schema: SCHEMA.into(),
            account: self.account.clone(),
            nonce: self.nonce.clone(),
            status: if admission.is_some() {
                "active"
            } else {
                "rejected"
            }
            .into(),
            epoch: admission,
            signature: String::new(),
        };
        r.signature = hex(&mac(key, &r.payload()?)?.finalize().into_bytes());
        serde_json::to_vec(&r).map_err(|_| Error::Invalid)
    }
}
impl Response {
    fn payload(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&(
            SCHEMA,
            "response",
            &self.account,
            &self.nonce,
            &self.status,
            self.epoch,
        ))
        .map_err(|_| Error::Invalid)
    }
}
#[derive(Default)]
pub struct Verifier {
    seen: BTreeMap<(bool, String), u64>,
    high_water: u64,
}
impl Verifier {
    fn consume(&mut self, r: &Request, response: bool, now: u64) -> Result<(), Error> {
        if now < self.high_water {
            return Err(Error::Expired);
        }
        self.high_water = now;
        self.seen.retain(|_, v| *v > now);
        let id = (response, r.nonce.clone());
        if self.seen.contains_key(&id) {
            return Err(Error::Replay);
        }
        if self.seen.len() >= 128 {
            return Err(Error::Capacity);
        }
        self.seen.insert(id, r.expires);
        Ok(())
    }
    pub(crate) fn request(&mut self, bytes: &[u8], key: &[u8], now: u64) -> Result<Request, Error> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        let r: Request = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        r.valid(key, now)?;
        self.consume(&r, false, now)?;
        Ok(r)
    }
    pub(crate) fn response(
        &mut self,
        request: &Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<Option<Admission>, Error> {
        if bytes.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        request.valid(key, now)?;
        let r: Response = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if r.schema != SCHEMA || r.account != request.account || r.nonce != request.nonce {
            return Err(Error::Authentication);
        }
        verify(key, &r.payload()?, &r.signature)?;
        let value = match (&request.operation, r.status.as_str(), r.epoch) {
            (Operation::Authenticate { .. }, "rejected", None) => None,
            (Operation::Authenticate { .. }, "active", Some(epoch)) if valid_epoch(epoch) => {
                Some(Admission {
                    account: r.account,
                    epoch,
                })
            }
            (Operation::Admit { epoch: expected }, "active", Some(epoch)) if epoch == *expected => {
                Some(Admission {
                    account: r.account,
                    epoch,
                })
            }
            _ => return Err(Error::Refused),
        };
        self.consume(request, true, now)?;
        Ok(value)
    }
}
#[cfg(test)]
#[path = "account_admission_tests.rs"]
mod tests;
