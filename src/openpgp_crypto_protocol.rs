//! Authenticated crypto transport. Bodies use length-delimited binary bytes,
//! never JSON byte arrays, filesystem paths, commands or diagnostic strings.
use crate::identity::CanonicalUsername;
use crate::openpgp_crypto::{Error as CryptoError, Operation, Outcome, SignatureState};
use crate::openpgp_inventory::Error;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

const SCHEMA: &str = "osmap-crypto-wire-v1";
pub const MAX_CONTENT: usize = 16 * 1024 * 1024;
pub const MAX_HEADER: usize = 65536;
pub const MAX_FRAME: usize = MAX_CONTENT + MAX_HEADER + 4;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    account: String,
    issued: u64,
    expires: u64,
    nonce: String,
    operation: String,
    signer: Option<String>,
    recipients: Vec<String>,
    data_len: usize,
    signature_len: usize,
    mac: String,
}

/// No Debug implementation: operation content must not appear in diagnostics.
pub struct Request {
    header: Header,
    data: Vec<u8>,
    signature: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn authenticate(
    key: &[u8],
    header: &[u8],
    body: &[u8],
    signature: &[u8],
) -> Result<HmacSha256, Error> {
    if !(32..=1024).contains(&key.len()) {
        return Err(Error::Authentication);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::Authentication)?;
    for bytes in [header, body, signature] {
        mac.update(bytes);
    }
    Ok(mac)
}
fn verify(mac: HmacSha256, value: &str) -> Result<(), Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Authentication);
    }
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| Error::Authentication))
        .collect::<Result<Vec<_>, _>>()?;
    mac.verify_slice(&bytes).map_err(|_| Error::Authentication)
}
fn frame<T: Serialize>(header: &T, body: &[u8], signature: &[u8]) -> Result<Vec<u8>, Error> {
    let meta = serde_json::to_vec(header).map_err(|_| Error::Invalid)?;
    if meta.len() > MAX_HEADER || body.len().saturating_add(signature.len()) > MAX_CONTENT {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::with_capacity(4 + meta.len() + body.len() + signature.len());
    bytes.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&meta);
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(signature);
    Ok(bytes)
}
fn split(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < 4 || bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
    if n == 0 || n > MAX_HEADER || n > bytes.len() - 4 {
        return Err(Error::Invalid);
    }
    Ok((&bytes[4..4 + n], &bytes[4 + n..]))
}
impl Header {
    fn payload(&self) -> Result<Vec<u8>, Error> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        serde_json::to_vec(&unsigned).map_err(|_| Error::Invalid)
    }
    fn validate(&self, now: u64) -> Result<(), Error> {
        CanonicalUsername::parse(&self.account).map_err(|_| Error::Invalid)?;
        if self.schema != SCHEMA
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
        if self.recipients.len() > 50
            || self.data_len.saturating_add(self.signature_len) > MAX_CONTENT
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
impl Request {
    /// The caller supplies a previously validated session account.
    pub fn issue(
        account: &str,
        operation: &Operation,
        now: u64,
        key: &[u8],
    ) -> Result<Self, Error> {
        CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        let (name, signer, recipients, data, signature) = match operation {
            Operation::Decrypt { ciphertext, .. } => {
                ("decrypt", None, Vec::new(), ciphertext.clone(), Vec::new())
            }
            Operation::Verify { data, signature } => {
                ("verify", None, Vec::new(), data.clone(), signature.clone())
            }
            Operation::Sign {
                signer_fingerprint,
                data,
            } => (
                "sign",
                Some(signer_fingerprint.clone()),
                Vec::new(),
                data.clone(),
                Vec::new(),
            ),
            Operation::Encrypt {
                recipient_fingerprints,
                data,
            } => (
                "encrypt",
                None,
                recipient_fingerprints.clone(),
                data.clone(),
                Vec::new(),
            ),
        };
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        let mut request = Self {
            header: Header {
                schema: SCHEMA.into(),
                account: account.into(),
                issued: now,
                expires: now.checked_add(10).ok_or(Error::Invalid)?,
                nonce: hex(&nonce),
                operation: name.into(),
                signer,
                recipients,
                data_len: data.len(),
                signature_len: signature.len(),
                mac: String::new(),
            },
            data,
            signature,
        };
        request.header.validate(now)?;
        // Decryption key authority is deliberately absent from client requests.
        request
            .operation(&["A".repeat(40)])?
            .validate()
            .map_err(|_| Error::Invalid)?;
        request.header.mac = hex(&authenticate(
            key,
            &request.header.payload()?,
            &request.data,
            &request.signature,
        )?
        .finalize()
        .into_bytes());
        Ok(request)
    }
    pub fn account(&self) -> &str {
        &self.header.account
    }
    pub fn expires(&self) -> u64 {
        self.header.expires
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        frame(&self.header, &self.data, &self.signature)
    }
    pub(crate) fn operation(&self, decrypt_keys: &[String]) -> Result<Operation, Error> {
        let h = &self.header;
        let op = match h.operation.as_str() {
            "decrypt"
                if h.signer.is_none() && h.recipients.is_empty() && self.signature.is_empty() =>
            {
                Operation::Decrypt {
                    allowed_primary_fingerprints: decrypt_keys.to_vec(),
                    ciphertext: self.data.clone(),
                }
            }
            "verify" if h.signer.is_none() && h.recipients.is_empty() => Operation::Verify {
                data: self.data.clone(),
                signature: self.signature.clone(),
            },
            "sign" if h.recipients.is_empty() && self.signature.is_empty() => Operation::Sign {
                signer_fingerprint: h.signer.clone().ok_or(Error::Invalid)?,
                data: self.data.clone(),
            },
            "encrypt" if h.signer.is_none() && self.signature.is_empty() => Operation::Encrypt {
                recipient_fingerprints: h.recipients.clone(),
                data: self.data.clone(),
            },
            _ => return Err(Error::Invalid),
        };
        op.validate().map_err(|_| Error::Invalid)?;
        Ok(op)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseHeader {
    schema: String,
    account: String,
    nonce: String,
    operation: String,
    error: Option<String>,
    content_len: usize,
    signer_fingerprint: Option<String>,
    primary_fingerprint: Option<String>,
    signature: SignatureState,
    hash_algorithm: Option<u32>,
    mac: String,
}
impl ResponseHeader {
    fn payload(&self) -> Result<Vec<u8>, Error> {
        let mut h = self.clone();
        h.mac.clear();
        serde_json::to_vec(&h).map_err(|_| Error::Invalid)
    }
}
pub(crate) fn response(
    request: &Request,
    result: Result<Outcome, CryptoError>,
    key: &[u8],
    now: u64,
) -> Result<Vec<u8>, Error> {
    request.header.validate(now)?;
    let (content, signer, primary, signature, hash, error) = match result {
        Ok(v) if v.operation == request.header.operation => (
            v.content,
            v.signer_fingerprint,
            v.primary_fingerprint,
            v.signature,
            v.hash_algorithm,
            None,
        ),
        Ok(_) => return Err(Error::Invalid),
        Err(e) => (
            Vec::new(),
            None,
            None,
            SignatureState::None,
            None,
            Some(error_name(e).into()),
        ),
    };
    let mut h = ResponseHeader {
        schema: SCHEMA.into(),
        account: request.account().into(),
        nonce: request.header.nonce.clone(),
        operation: request.header.operation.clone(),
        error,
        content_len: content.len(),
        signer_fingerprint: signer,
        primary_fingerprint: primary,
        signature,
        hash_algorithm: hash,
        mac: String::new(),
    };
    h.mac = hex(&authenticate(key, &h.payload()?, &content, &[])?
        .finalize()
        .into_bytes());
    frame(&h, &content, &[])
}
fn error_name(e: CryptoError) -> &'static str {
    match e {
        CryptoError::Invalid => "invalid",
        CryptoError::Limit => "limit",
        CryptoError::Expired => "expired",
        CryptoError::Unavailable => "unavailable",
        CryptoError::Locked => "locked",
        CryptoError::MissingKey => "missing_key",
        CryptoError::Unsupported => "unsupported",
        CryptoError::Integrity => "integrity",
        CryptoError::Signature => "signature",
    }
}
fn crypto_error(s: &str) -> Result<CryptoError, Error> {
    Ok(match s {
        "invalid" => CryptoError::Invalid,
        "limit" => CryptoError::Limit,
        "expired" => CryptoError::Expired,
        "unavailable" => CryptoError::Unavailable,
        "locked" => CryptoError::Locked,
        "missing_key" => CryptoError::MissingKey,
        "unsupported" => CryptoError::Unsupported,
        "integrity" => CryptoError::Integrity,
        "signature" => CryptoError::Signature,
        _ => return Err(Error::Invalid),
    })
}
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
        self.seen.retain(|_, expiry| *expiry > now);
        let id = (response, r.account().into(), r.header.nonce.clone());
        if self.seen.contains_key(&id) {
            return Err(Error::Replay);
        }
        if self.seen.len() >= 1024 {
            return Err(Error::Capacity);
        }
        self.seen.insert(id, r.expires());
        Ok(())
    }
    pub fn request(&mut self, bytes: &[u8], key: &[u8], now: u64) -> Result<Request, Error> {
        let (meta, body) = split(bytes)?;
        let header: Header = serde_json::from_slice(meta).map_err(|_| Error::Invalid)?;
        header.validate(now)?;
        if body.len() != header.data_len.saturating_add(header.signature_len) {
            return Err(Error::Invalid);
        }
        let (data, signature) = body.split_at(header.data_len);
        verify(
            authenticate(key, &header.payload()?, data, signature)?,
            &header.mac,
        )?;
        let r = Request {
            header,
            data: data.to_vec(),
            signature: signature.to_vec(),
        };
        r.operation(&["A".repeat(40)])?;
        self.consume(&r, false, now)?;
        Ok(r)
    }
    pub fn response(
        &mut self,
        r: &Request,
        bytes: &[u8],
        operation: &Operation,
        key: &[u8],
        now: u64,
    ) -> Result<Result<Outcome, CryptoError>, Error> {
        r.header.validate(now)?;
        let (meta, body) = split(bytes)?;
        let h: ResponseHeader = serde_json::from_slice(meta).map_err(|_| Error::Invalid)?;
        if h.schema != SCHEMA
            || h.account != r.account()
            || h.nonce != r.header.nonce
            || h.operation != r.header.operation
            || h.content_len != body.len()
        {
            return Err(Error::Authentication);
        }
        verify(authenticate(key, &h.payload()?, body, &[])?, &h.mac)?;
        let result = if let Some(e) = h.error {
            if !body.is_empty()
                || h.signer_fingerprint.is_some()
                || h.primary_fingerprint.is_some()
                || h.hash_algorithm.is_some()
                || h.signature != SignatureState::None
            {
                return Err(Error::Invalid);
            }
            Err(crypto_error(&e)?)
        } else {
            let v = Outcome {
                operation: h.operation,
                content: body.to_vec(),
                signer_fingerprint: h.signer_fingerprint,
                primary_fingerprint: h.primary_fingerprint,
                signature: h.signature,
                hash_algorithm: h.hash_algorithm,
            };
            v.validate_for(operation).map_err(|_| Error::Invalid)?;
            Ok(v)
        };
        self.consume(r, true, now)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn op() -> Operation {
        Operation::Sign {
            signer_fingerprint: "A".repeat(40),
            data: b"MIME bytes\r\n".to_vec(),
        }
    }
    #[test]
    fn authenticated_binary_body_rejects_tamper_wrong_key_expiry_replay_and_paths() {
        let key = [7; 32];
        let r = Request::issue("alice", &op(), 100, &key).unwrap();
        let bytes = r.to_bytes().unwrap();
        assert!(Verifier::default().request(&bytes, &[8; 32], 101).is_err());
        assert!(Verifier::default().request(&bytes, &key, 110).is_err());
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(Verifier::default().request(&altered, &key, 101).is_err());
        let mut verifier = Verifier::default();
        let parsed = verifier.request(&bytes, &key, 101).unwrap();
        assert_eq!(parsed.account(), "alice");
        assert!(matches!(
            verifier.request(&bytes, &key, 101),
            Err(Error::Replay)
        ));
        let (meta, body) = split(&bytes).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(meta).unwrap();
        json["home"] = serde_json::json!("/tmp/untrusted");
        assert!(Verifier::default()
            .request(&frame(&json, body, &[]).unwrap(), &key, 101)
            .is_err());
        assert!(Verifier::default()
            .request(&bytes[..bytes.len() - 1], &key, 101)
            .is_err());
        assert!(Verifier::default().request(&[0; 4], &key, 101).is_err());
    }
    #[test]
    fn authenticated_errors_and_response_account_nonce_are_bound() {
        let key = [9; 32];
        let operation = op();
        let r = Request::issue("alice", &operation, 100, &key).unwrap();
        let bytes = response(&r, Err(CryptoError::Locked), &key, 101).unwrap();
        let other = Request::issue("bob", &operation, 100, &key).unwrap();
        let mut v = Verifier::default();
        assert!(v.response(&other, &bytes, &operation, &key, 102).is_err());
        assert_eq!(
            v.response(&r, &bytes, &operation, &key, 102).unwrap().err(),
            Some(CryptoError::Locked)
        );
        assert!(matches!(
            v.response(&r, &bytes, &operation, &key, 102),
            Err(Error::Replay)
        ));
    }
    #[test]
    fn clock_rollback_expired_response_and_truncated_content_refuse() {
        let key = [3; 32];
        let operation = op();
        let r = Request::issue("alice", &operation, 100, &key).unwrap();
        let response = response(&r, Err(CryptoError::MissingKey), &key, 101).unwrap();
        assert!(Verifier::default()
            .response(&r, &response, &operation, &key, 110)
            .is_err());
        assert!(Verifier::default()
            .response(&r, &response[..response.len() - 1], &operation, &key, 102)
            .is_err());
        let mut verifier = Verifier::default();
        verifier.request(&r.to_bytes().unwrap(), &key, 102).unwrap();
        let different = Request::issue("alice", &operation, 100, &key).unwrap();
        assert!(matches!(
            verifier.request(&different.to_bytes().unwrap(), &key, 101),
            Err(Error::Clock)
        ));
        let decrypt = Operation::Decrypt {
            allowed_primary_fingerprints: vec!["A".repeat(40)],
            ciphertext: b"synthetic ciphertext".to_vec(),
        };
        let request = Request::issue("alice", &decrypt, 100, &key).unwrap();
        let result = Outcome {
            operation: "decrypt".into(),
            content: b"synthetic transient body".to_vec(),
            signer_fingerprint: None,
            primary_fingerprint: Some("B".repeat(40)),
            signature: SignatureState::None,
            hash_algorithm: None,
        };
        let response = super::response(&request, Ok(result), &key, 101).unwrap();
        assert!(Verifier::default()
            .response(&request, &response, &decrypt, &key, 102)
            .is_err());
    }
}
