//! Typed transient OpenPGP operations. No paths, passphrases or private key data
//! are protocol fields. Account authority belongs to the authenticated runtime.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_CONTENT: usize = 16 * 1024 * 1024;
pub const MAX_METADATA: usize = 64 * 1024;
pub const MAX_RECIPIENTS: usize = 50;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Decrypt {
        allowed_primary_fingerprints: Vec<String>,
        ciphertext: Vec<u8>,
    },
    Verify {
        data: Vec<u8>,
        signature: Vec<u8>,
    },
    Sign {
        signer_fingerprint: String,
        data: Vec<u8>,
    },
    Encrypt {
        recipient_fingerprints: Vec<String>,
        data: Vec<u8>,
    },
}
// Deliberately no Debug implementation: request/response content is sensitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Limit,
    Expired,
    Unavailable,
    Locked,
    MissingKey,
    Unsupported,
    Integrity,
    Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    None,
    Valid,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub operation: String,
    pub content: Vec<u8>,
    pub signer_fingerprint: Option<String>,
    pub primary_fingerprint: Option<String>,
    pub signature: SignatureState,
    pub hash_algorithm: Option<u32>,
}

pub fn full_fingerprint(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Decrypt { .. } => "decrypt",
            Self::Verify { .. } => "verify",
            Self::Sign { .. } => "sign",
            Self::Encrypt { .. } => "encrypt",
        }
    }
    pub fn content(&self) -> &[u8] {
        match self {
            Self::Decrypt { ciphertext, .. } => ciphertext,
            Self::Verify { data, .. } | Self::Sign { data, .. } | Self::Encrypt { data, .. } => {
                data
            }
        }
    }
    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Verify { signature, .. } => signature,
            _ => &[],
        }
    }
    fn fingerprints(&self) -> Vec<&str> {
        match self {
            Self::Decrypt {
                allowed_primary_fingerprints,
                ..
            } => allowed_primary_fingerprints
                .iter()
                .map(String::as_str)
                .collect(),
            Self::Encrypt {
                recipient_fingerprints,
                ..
            } => recipient_fingerprints.iter().map(String::as_str).collect(),
            Self::Sign {
                signer_fingerprint, ..
            } => vec![signer_fingerprint],
            Self::Verify { .. } => Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        let size = self
            .content()
            .len()
            .checked_add(self.signature().len())
            .ok_or(Error::Limit)?;
        if self.content().is_empty()
            || matches!(self, Self::Verify { .. }) && self.signature().is_empty()
        {
            return Err(Error::Invalid);
        }
        if size > MAX_CONTENT {
            return Err(Error::Limit);
        }
        let keys = self.fingerprints();
        if keys.len() > MAX_RECIPIENTS {
            return Err(Error::Limit);
        }
        if (!matches!(self, Self::Verify { .. }) && keys.is_empty())
            || keys.iter().any(|f| !full_fingerprint(f))
            || keys.iter().collect::<BTreeSet<_>>().len() != keys.len()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Internal worker framing; trusted dispatcher has already authorized keys.
    pub(crate) fn worker_frame(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let fingerprints = self.fingerprints();
        let code = match self {
            Self::Decrypt { .. } => 1,
            Self::Verify { .. } => 2,
            Self::Sign { .. } => 3,
            Self::Encrypt { .. } => 4,
        };
        let mut frame = Vec::with_capacity(
            16 + fingerprints.len() * 64 + self.content().len() + self.signature().len(),
        );
        frame.extend_from_slice(b"OSMC");
        frame.extend_from_slice(&[code, fingerprints.len() as u8, 0, 0]);
        frame.extend_from_slice(&(self.content().len() as u32).to_be_bytes());
        frame.extend_from_slice(&(self.signature().len() as u32).to_be_bytes());
        for fp in fingerprints {
            frame.extend_from_slice(fp.as_bytes());
            frame.resize(frame.len() + 64 - fp.len(), 0);
        }
        frame.extend_from_slice(self.content());
        frame.extend_from_slice(self.signature());
        Ok(frame)
    }
}
impl Outcome {
    pub fn validate_for(&self, operation: &Operation) -> Result<(), Error> {
        operation.validate()?;
        if self.operation != operation.name()
            || self.content.len() > MAX_CONTENT
            || self
                .signer_fingerprint
                .as_deref()
                .is_some_and(|fp| !full_fingerprint(fp))
            || self
                .primary_fingerprint
                .as_deref()
                .is_some_and(|fp| !full_fingerprint(fp))
        {
            return Err(Error::Invalid);
        }
        let signed = self.signature == SignatureState::Valid
            && matches!(self.hash_algorithm, Some(8 | 10))
            && self.signer_fingerprint.is_some()
            && self.primary_fingerprint.is_some();
        let unsigned = self.signature == SignatureState::None
            && self.hash_algorithm.is_none()
            && self.signer_fingerprint.is_none();
        let valid = match operation {
            Operation::Decrypt {
                allowed_primary_fingerprints,
                ..
            } => {
                unsigned
                    && !self.content.is_empty()
                    && self
                        .primary_fingerprint
                        .as_ref()
                        .is_some_and(|f| allowed_primary_fingerprints.contains(f))
            }
            Operation::Verify { .. } => signed && self.content.is_empty(),
            Operation::Sign {
                signer_fingerprint, ..
            } => {
                signed
                    && !self.content.is_empty()
                    && self.signer_fingerprint.as_ref() == Some(signer_fingerprint)
            }
            Operation::Encrypt { .. } => {
                unsigned && !self.content.is_empty() && self.primary_fingerprint.is_none()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
    pub(crate) fn worker_result(
        operation: &Operation,
        output: &[u8],
        success: bool,
    ) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Metadata {
            version: u8,
            ok: bool,
            operation: String,
            #[serde(default)]
            error: Option<String>,
            #[serde(default)]
            signer_fingerprint: Option<String>,
            #[serde(default)]
            primary_fingerprint: Option<String>,
            #[serde(default)]
            signature: Option<SignatureState>,
            #[serde(default)]
            hash_algorithm: Option<u32>,
        }
        if output.len() < 8 {
            return Err(Error::Invalid);
        }
        let metadata_size =
            u32::from_be_bytes(output[..4].try_into().map_err(|_| Error::Invalid)?) as usize;
        let body_size =
            u32::from_be_bytes(output[4..8].try_into().map_err(|_| Error::Invalid)?) as usize;
        if metadata_size == 0 || metadata_size > MAX_METADATA || body_size > MAX_CONTENT {
            return Err(Error::Limit);
        }
        if output.len() != 8 + metadata_size + body_size {
            return Err(Error::Invalid);
        }
        let m: Metadata =
            serde_json::from_slice(&output[8..8 + metadata_size]).map_err(|_| Error::Invalid)?;
        if m.version != 1 || m.operation != operation.name() || m.ok != success {
            return Err(Error::Invalid);
        }
        if !m.ok {
            if body_size != 0
                || m.signer_fingerprint.is_some()
                || m.primary_fingerprint.is_some()
                || m.signature.is_some()
                || m.hash_algorithm.is_some()
            {
                return Err(Error::Invalid);
            }
            return Err(match m.error.as_deref() {
                Some("invalid") => Error::Invalid,
                Some("limit") => Error::Limit,
                Some("locked") => Error::Locked,
                Some("missing_key") => Error::MissingKey,
                Some("unsupported") => Error::Unsupported,
                Some("integrity") => Error::Integrity,
                Some("signature") => Error::Signature,
                Some("unavailable") => Error::Unavailable,
                _ => Error::Invalid,
            });
        }
        if m.error.is_some() {
            return Err(Error::Invalid);
        }
        let outcome = Self {
            operation: m.operation,
            content: output[8 + metadata_size..].to_vec(),
            signer_fingerprint: m.signer_fingerprint,
            primary_fingerprint: m.primary_fingerprint,
            signature: m.signature.ok_or(Error::Invalid)?,
            hash_algorithm: m.hash_algorithm,
        };
        outcome.validate_for(operation)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_keys_payload_and_unknown_operation_fields() {
        let valid = Operation::Encrypt {
            recipient_fingerprints: vec!["A".repeat(40)],
            data: vec![1],
        };
        assert!(valid.validate().is_ok());
        for keys in [
            vec![],
            vec!["ABC".into()],
            vec!["A".repeat(40), "A".repeat(40)],
            vec!["a".repeat(40)],
            vec!["A".repeat(40); 51],
        ] {
            assert!(Operation::Encrypt {
                recipient_fingerprints: keys,
                data: vec![1]
            }
            .validate()
            .is_err());
        }
        assert!(Operation::Verify {
            data: vec![1; MAX_CONTENT],
            signature: vec![1]
        }
        .validate()
        .is_err());
        for raw in [
            r#"{"operation":"sign","signer_fingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","data":[1],"home":"/tmp"}"#,
            r#"{"operation":"decrypt","operation":"verify","data":[1],"signature":[1]}"#,
        ] {
            assert!(serde_json::from_str::<Operation>(raw).is_err());
        }
        assert_eq!(valid.worker_frame().unwrap().len(), 81);
    }
    #[test]
    fn response_cannot_lie_about_signer_or_release_partial_content() {
        let op = Operation::Sign {
            signer_fingerprint: "A".repeat(40),
            data: vec![1],
        };
        let mut outcome = Outcome {
            operation: "sign".into(),
            content: vec![2],
            signer_fingerprint: Some("A".repeat(40)),
            primary_fingerprint: Some("B".repeat(40)),
            signature: SignatureState::Valid,
            hash_algorithm: Some(8),
        };
        assert!(outcome.validate_for(&op).is_ok());
        outcome.signer_fingerprint = Some("C".repeat(40));
        assert!(outcome.validate_for(&op).is_err());
        let metadata = br#"{"version":1,"ok":false,"operation":"sign","error":"locked"}"#;
        let mut wire = (metadata.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(metadata);
        assert!(matches!(
            Outcome::worker_result(&op, &wire, false),
            Err(Error::Locked)
        ));
        wire[7] = 1;
        wire.push(1);
        assert!(matches!(
            Outcome::worker_result(&op, &wire, false),
            Err(Error::Invalid)
        ));
    }
}
