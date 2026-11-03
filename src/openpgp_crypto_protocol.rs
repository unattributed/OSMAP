//! Authenticated crypto transport. Bodies use length-delimited binary bytes,
//! never JSON byte arrays, filesystem paths, commands or diagnostic strings.
use crate::identity::CanonicalUsername;
use crate::openpgp_crypto::{Error as CryptoError, Operation, Outcome, SignatureState};
use crate::openpgp_inventory::Error;
use crate::openpgp_personal::{PersonalAction, PersonalError, PersonalState, PrivateSession};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<PrivateSession>,
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
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.valid(now))
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
        // Refuse oversized or malformed operations before cloning their content.
        operation.validate().map_err(|error| match error {
            CryptoError::Limit => Error::Limit,
            _ => Error::Invalid,
        })?;
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
                session: None,
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
    pub(crate) fn session(&self) -> Option<&PrivateSession> {
        self.header.session.as_ref()
    }
    pub(crate) fn bind_session(
        &mut self,
        session: PrivateSession,
        now: u64,
        key: &[u8],
    ) -> Result<(), Error> {
        self.header.session = Some(session);
        self.header.validate(now)?;
        self.header.mac =
            hex(
                &authenticate(key, &self.header.payload()?, &self.data, &self.signature)?
                    .finalize()
                    .into_bytes(),
            );
        Ok(())
    }
    pub(crate) fn personal_name(&self) -> Option<&str> {
        matches!(
            self.header.operation.as_str(),
            "personal_status" | "personal_import" | "personal_unlock" | "personal_lock"
        )
        .then_some(self.header.operation.as_str())
    }
    pub(crate) fn personal_parts(&self) -> Result<(&[u8], &[u8]), Error> {
        if self.personal_name().is_none()
            || self.header.session.is_none()
            || self.header.signer.is_some()
            || !self.header.recipients.is_empty()
            || !self.signature.is_empty()
        {
            return Err(Error::Invalid);
        }
        if matches!(
            self.personal_name(),
            Some("personal_status" | "personal_lock")
        ) {
            return if self.data.is_empty() {
                Ok((&[], &[]))
            } else {
                Err(Error::Invalid)
            };
        }
        if self.data.len() < 8 {
            return Err(Error::Invalid);
        }
        let certificate =
            u32::from_be_bytes(self.data[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
        let passphrase =
            u32::from_be_bytes(self.data[4..8].try_into().map_err(|_| Error::Invalid)?) as usize;
        if certificate > crate::openpgp_personal::MAX_CERTIFICATE
            || passphrase > crate::openpgp_personal::MAX_PASSPHRASE
            || self.data.len() != 8 + certificate + passphrase
            || (self.personal_name() == Some("personal_import")) != (certificate > 0)
        {
            return Err(Error::Invalid);
        }
        let (cert, pass) = self.data[8..].split_at(certificate);
        if pass
            .iter()
            .any(|byte| matches!(*byte, b'\0' | b'\r' | b'\n'))
        {
            return Err(Error::Invalid);
        }
        Ok((cert, pass))
    }
    pub(crate) fn issue_personal(
        account: &str,
        session: &PrivateSession,
        action: PersonalAction<'_>,
        now: u64,
        key: &[u8],
    ) -> Result<Self, Error> {
        let (name, certificate, passphrase) = match action {
            PersonalAction::Status => ("personal_status", &[][..], &[][..]),
            PersonalAction::Import {
                certificate,
                passphrase,
            } => ("personal_import", certificate, passphrase),
            PersonalAction::Unlock { passphrase } => ("personal_unlock", &[][..], passphrase),
            PersonalAction::Lock => ("personal_lock", &[][..], &[][..]),
        };
        if certificate.len() > crate::openpgp_personal::MAX_CERTIFICATE
            || passphrase.len() > crate::openpgp_personal::MAX_PASSPHRASE
        {
            return Err(Error::Limit);
        }
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        let mut data = Vec::new();
        if matches!(name, "personal_import" | "personal_unlock") {
            data.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
            data.extend_from_slice(&(passphrase.len() as u32).to_be_bytes());
            data.extend_from_slice(certificate);
            data.extend_from_slice(passphrase);
        }
        let mut request = Self {
            header: Header {
                schema: SCHEMA.into(),
                account: account.into(),
                issued: now,
                expires: now.checked_add(10).ok_or(Error::Invalid)?,
                nonce: hex(&nonce),
                operation: name.into(),
                signer: None,
                recipients: vec![],
                data_len: data.len(),
                signature_len: 0,
                mac: String::new(),
                session: Some(session.clone()),
            },
            data,
            signature: vec![],
        };
        request.header.validate(now)?;
        request.personal_parts()?;
        request.header.mac =
            hex(
                &authenticate(key, &request.header.payload()?, &request.data, &[])?
                    .finalize()
                    .into_bytes(),
            );
        Ok(request)
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
        if r.personal_name().is_some() {
            r.personal_parts()?;
        } else {
            r.operation(&["A".repeat(40)])?;
        }
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
impl Drop for Request {
    fn drop(&mut self) {
        crate::openpgp_personal::clear(&mut self.data);
        crate::openpgp_personal::clear(&mut self.signature);
    }
}

pub(crate) fn personal_response(
    request: &Request,
    result: Result<PersonalState, PersonalError>,
    key: &[u8],
    now: u64,
) -> Result<Vec<u8>, Error> {
    request.header.validate(now)?;
    if request.personal_name().is_none() {
        return Err(Error::Invalid);
    }
    let body = serde_json::to_vec(&result).map_err(|_| Error::Invalid)?;
    let mut header = ResponseHeader {
        schema: SCHEMA.into(),
        account: request.account().into(),
        nonce: request.header.nonce.clone(),
        operation: request.header.operation.clone(),
        error: None,
        content_len: body.len(),
        signer_fingerprint: None,
        primary_fingerprint: None,
        signature: SignatureState::None,
        hash_algorithm: None,
        mac: String::new(),
    };
    header.mac = hex(&authenticate(key, &header.payload()?, &body, &[])?
        .finalize()
        .into_bytes());
    frame(&header, &body, &[])
}
impl Verifier {
    pub(crate) fn personal_response(
        &mut self,
        request: &Request,
        bytes: &[u8],
        key: &[u8],
        now: u64,
    ) -> Result<Result<PersonalState, PersonalError>, Error> {
        request.header.validate(now)?;
        let (meta, body) = split(bytes)?;
        let header: ResponseHeader = serde_json::from_slice(meta).map_err(|_| Error::Invalid)?;
        if request.personal_name().is_none()
            || header.schema != SCHEMA
            || header.account != request.account()
            || header.nonce != request.header.nonce
            || header.operation != request.header.operation
            || header.content_len != body.len()
            || body.len() > 4096
            || header.error.is_some()
            || header.signer_fingerprint.is_some()
            || header.primary_fingerprint.is_some()
            || header.signature != SignatureState::None
            || header.hash_algorithm.is_some()
        {
            return Err(Error::Authentication);
        }
        verify(
            authenticate(key, &header.payload()?, body, &[])?,
            &header.mac,
        )?;
        self.consume(request, true, now)?;
        let result: Result<PersonalState, PersonalError> =
            serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        let session = request.session().ok_or(Error::Invalid)?;
        if result
            .as_ref()
            .is_ok_and(|state| !state.valid_for(session, now))
        {
            return Err(Error::Invalid);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn private_session() -> PrivateSession {
        PrivateSession {
            session_id: "a".repeat(64),
            account_epoch: Some(7),
            expires_at: 1000,
        }
    }
    #[test]
    fn personal_wire_authenticates_session_and_private_binary_body_without_header_secrets() {
        let session = private_session();
        let key = [42; 32];
        let request = Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Import {
                certificate: b"synthetic private certificate",
                passphrase: b"synthetic passphrase",
            },
            100,
            &key,
        )
        .unwrap();
        let bytes = request.to_bytes().unwrap();
        let (header, body) = split(&bytes).unwrap();
        assert!(!header
            .windows(b"synthetic".len())
            .any(|part| part == b"synthetic"));
        assert!(body
            .windows(b"synthetic passphrase".len())
            .any(|part| part == b"synthetic passphrase"));
        let decoded = Verifier::default().request(&bytes, &key, 101).unwrap();
        assert!(decoded.session() == Some(&session));
        let (certificate, passphrase) = decoded.personal_parts().unwrap();
        assert!(certificate == b"synthetic private certificate");
        assert!(passphrase == b"synthetic passphrase");
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            Verifier::default().request(&changed, &key, 101).err(),
            Some(Error::Authentication)
        );
        let mut altered = request.header.clone();
        altered.session.as_mut().unwrap().account_epoch = Some(8);
        assert_eq!(
            Verifier::default()
                .request(&frame(&altered, &request.data, &[]).unwrap(), &key, 101)
                .err(),
            Some(Error::Authentication)
        );
        assert!(Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Import {
                certificate: &[],
                passphrase: b"x"
            },
            100,
            &key
        )
        .is_err());
        assert!(Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Unlock {
                passphrase: b"line\nbreak"
            },
            100,
            &key
        )
        .is_err());
        assert!(Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Unlock {
                passphrase: &vec![b'x'; 1025]
            },
            100,
            &key
        )
        .is_err());
    }
    #[test]
    fn personal_reply_is_nonce_bound_and_requests_expire_with_session() {
        let mut session = private_session();
        let key = [42; 32];
        let request = Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Status,
            100,
            &key,
        )
        .unwrap();
        let state = PersonalState {
            primary_fingerprint: "A".repeat(40),
            private_revision: "b".repeat(64),
            installed: true,
            protected_at_rest: true,
            unlocked_for_session: true,
            valid_until: Some(500),
            cache_seconds: 28800,
        };
        let bytes = personal_response(&request, Ok(state), &key, 101).unwrap();
        let result = Verifier::default()
            .personal_response(&request, &bytes, &key, 101)
            .unwrap()
            .unwrap();
        assert!(result.unlocked_for_session);
        let other = Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Status,
            100,
            &key,
        )
        .unwrap();
        assert_eq!(
            Verifier::default()
                .personal_response(&other, &bytes, &key, 101)
                .err(),
            Some(Error::Authentication)
        );
        session.expires_at = 105;
        let request = Request::issue_personal(
            "alice@example.test",
            &session,
            PersonalAction::Status,
            100,
            &key,
        )
        .unwrap();
        assert_eq!(
            Verifier::default()
                .request(&request.to_bytes().unwrap(), &key, 105)
                .err(),
            Some(Error::Expired)
        );
    }
    fn op() -> Operation {
        Operation::Sign {
            signer_fingerprint: "A".repeat(40),
            data: b"MIME bytes\r\n".to_vec(),
        }
    }
    #[test]
    fn invalid_local_decryption_selection_is_refused_before_request_issuance() {
        for fingerprints in [Vec::new(), vec!["not-a-fingerprint".into()]] {
            let operation = Operation::Decrypt {
                allowed_primary_fingerprints: fingerprints,
                ciphertext: b"synthetic ciphertext".to_vec(),
            };
            assert!(matches!(
                Request::issue("alice", &operation, 100, &[7; 32]),
                Err(Error::Invalid)
            ));
        }
    }

    #[test]
    fn request_issuance_preserves_content_and_recipient_limit_errors() {
        let oversized = Operation::Encrypt {
            recipient_fingerprints: vec!["A".repeat(40)],
            data: vec![0; MAX_CONTENT + 1],
        };
        assert!(matches!(
            Request::issue("alice", &oversized, 100, &[7; 32]),
            Err(Error::Limit)
        ));
        let too_many = Operation::Encrypt {
            recipient_fingerprints: (0..51).map(|n| format!("{n:040X}")).collect(),
            data: b"synthetic".to_vec(),
        };
        assert!(matches!(
            Request::issue("alice", &too_many, 100, &[7; 32]),
            Err(Error::Limit)
        ));
    }

    #[test]
    fn supported_operations_preserve_binary_content_and_separate_signature() {
        let data = vec![0, 255, b'\r', b'\n', 128];
        let signature = vec![255, 0, 1];
        let fingerprint = "A".repeat(40);
        let operations = [
            Operation::Encrypt {
                recipient_fingerprints: vec![fingerprint.clone()],
                data: data.clone(),
            },
            Operation::Decrypt {
                allowed_primary_fingerprints: vec![fingerprint.clone()],
                ciphertext: data.clone(),
            },
            Operation::Sign {
                signer_fingerprint: fingerprint,
                data: data.clone(),
            },
            Operation::Verify {
                data: data.clone(),
                signature: signature.clone(),
            },
        ];
        for operation in operations {
            let request = Request::issue("alice", &operation, 100, &[7; 32]).unwrap();
            let parsed = Verifier::default()
                .request(&request.to_bytes().unwrap(), &[7; 32], 101)
                .unwrap();
            assert!(parsed.data == data);
            assert!(parsed.signature == operation.signature());
            assert_eq!(parsed.header.operation, operation.name());
        }
    }

    #[test]
    fn authenticated_unknown_errors_and_error_content_are_refused() {
        let key = [7; 32];
        let operation = op();
        let request = Request::issue("alice", &operation, 100, &key).unwrap();
        let bytes = response(&request, Err(CryptoError::Locked), &key, 101).unwrap();
        let (metadata, _) = split(&bytes).unwrap();
        let original: ResponseHeader = serde_json::from_slice(metadata).unwrap();
        for (error, content) in [
            ("unknown_result", Vec::new()),
            ("locked", b"must not escape an error".to_vec()),
        ] {
            let mut header = original.clone();
            header.error = Some(error.into());
            header.content_len = content.len();
            header.mac = hex(
                &authenticate(&key, &header.payload().unwrap(), &content, &[])
                    .unwrap()
                    .finalize()
                    .into_bytes(),
            );
            let invalid = frame(&header, &content, &[]).unwrap();
            assert!(matches!(
                Verifier::default().response(&request, &invalid, &operation, &key, 102),
                Err(Error::Invalid)
            ));
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
