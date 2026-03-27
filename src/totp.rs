//! TOTP verification and secret-store support for OSMAP.
//!
//! This module implements a small RFC 6238-compatible verifier using a
//! file-backed secret-store boundary under the configured state root. The goal
//! is to add a real second-factor backend without introducing a large auth
//! framework.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::auth::{
    RequiredSecondFactor, SecondFactorBackendError, SecondFactorVerdict, SecondFactorVerifier,
};

type HmacSha1 = Hmac<Sha1>;

/// The current fixed TOTP secret file extension.
pub const TOTP_SECRET_FILE_EXTENSION: &str = "totp";

/// Policy controlling TOTP code shape and clock skew tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpPolicy {
    pub digits: u32,
    pub period_seconds: u64,
    pub allowed_skew_steps: i64,
}

impl Default for TotpPolicy {
    fn default() -> Self {
        Self {
            digits: 6,
            period_seconds: 30,
            allowed_skew_steps: 1,
        }
    }
}

/// Carries the raw shared secret bytes for TOTP verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSecret {
    pub secret_bytes: Vec<u8>,
}

/// A source of current Unix time for TOTP verification.
pub trait TimeProvider {
    fn unix_timestamp(&self) -> u64;
}

/// Uses the system clock as the TOTP time source.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn unix_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Returns TOTP secrets for canonical users.
pub trait TotpSecretStore {
    fn load_secret(
        &self,
        canonical_username: &str,
    ) -> Result<Option<TotpSecret>, TotpSecretStoreError>;
}

/// Errors raised while reading or parsing TOTP secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSecretStoreError {
    pub reason: String,
}

/// Verifies TOTP codes using a secret store and time provider.
pub struct TotpVerifier<S, T> {
    secret_store: S,
    time_provider: T,
    policy: TotpPolicy,
}

impl<S, T> TotpVerifier<S, T> {
    /// Creates a verifier from the supplied store, time source, and policy.
    pub fn new(secret_store: S, time_provider: T, policy: TotpPolicy) -> Self {
        Self {
            secret_store,
            time_provider,
            policy,
        }
    }
}

impl<S, T> SecondFactorVerifier for TotpVerifier<S, T>
where
    S: TotpSecretStore,
    T: TimeProvider,
{
    fn verify_second_factor(
        &self,
        canonical_username: &str,
        factor: RequiredSecondFactor,
        code: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        if factor != RequiredSecondFactor::Totp {
            return Err(SecondFactorBackendError {
                backend: "totp",
                reason: "unsupported second factor for TOTP verifier".to_string(),
            });
        }

        let secret = self
            .secret_store
            .load_secret(canonical_username)
            .map_err(|error| SecondFactorBackendError {
                backend: "totp-secret-store",
                reason: error.reason,
            })?;

        let Some(secret) = secret else {
            return Ok(SecondFactorVerdict::Reject);
        };

        if code.len() != self.policy.digits as usize {
            return Ok(SecondFactorVerdict::Reject);
        }

        let timestamp = self.time_provider.unix_timestamp();
        for counter in counters_for_time(timestamp, self.policy) {
            let expected = generate_totp_code(&secret.secret_bytes, counter, self.policy).map_err(
                |error| SecondFactorBackendError {
                    backend: "totp",
                    reason: error,
                },
            )?;

            if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
                return Ok(SecondFactorVerdict::Accept);
            }
        }

        Ok(SecondFactorVerdict::Reject)
    }
}

/// Loads per-user TOTP secrets from files rooted under a configured directory.
pub struct FileTotpSecretStore {
    secret_dir: PathBuf,
}

impl FileTotpSecretStore {
    /// Creates a file-backed secret store rooted at the supplied directory.
    pub fn new(secret_dir: impl Into<PathBuf>) -> Self {
        Self {
            secret_dir: secret_dir.into(),
        }
    }

    /// Returns the on-disk path for a user's secret file.
    pub fn secret_path_for_username(&self, canonical_username: &str) -> PathBuf {
        self.secret_dir.join(format!(
            "{}.{}",
            hex_encode(canonical_username.as_bytes()),
            TOTP_SECRET_FILE_EXTENSION
        ))
    }
}

impl TotpSecretStore for FileTotpSecretStore {
    fn load_secret(
        &self,
        canonical_username: &str,
    ) -> Result<Option<TotpSecret>, TotpSecretStoreError> {
        let path = self.secret_path_for_username(canonical_username);

        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path).map_err(|error| TotpSecretStoreError {
            reason: format!("failed reading TOTP secret file {:?}: {error}", path),
        })?;

        parse_secret_file(&content)
    }
}

/// Parses the counters that should be accepted for the current time and policy.
fn counters_for_time(timestamp: u64, policy: TotpPolicy) -> Vec<u64> {
    let current_counter = timestamp / policy.period_seconds;
    let mut counters = Vec::new();

    for skew in -policy.allowed_skew_steps..=policy.allowed_skew_steps {
        let adjusted = current_counter as i128 + skew as i128;
        if adjusted >= 0 {
            counters.push(adjusted as u64);
        }
    }

    counters
}

/// Generates a TOTP code from the secret bytes and counter.
fn generate_totp_code(
    secret_bytes: &[u8],
    counter: u64,
    policy: TotpPolicy,
) -> Result<String, String> {
    let counter_bytes = counter.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret_bytes)
        .map_err(|error| format!("failed to create HMAC state: {error}"))?;
    mac.update(&counter_bytes);
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(policy.digits);
    let value = binary % modulus;

    Ok(format!("{value:0width$}", width = policy.digits as usize))
}

/// Parses the contents of a TOTP secret file.
fn parse_secret_file(content: &str) -> Result<Option<TotpSecret>, TotpSecretStoreError> {
    let mut secret_value = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(value) = line.strip_prefix("secret=") {
            secret_value = Some(value.trim().to_string());
            continue;
        }

        return Err(TotpSecretStoreError {
            reason: format!("unrecognized secret file line {line:?}"),
        });
    }

    let Some(secret_value) = secret_value else {
        return Ok(None);
    };

    let secret_bytes =
        decode_base32(&secret_value).map_err(|error| TotpSecretStoreError { reason: error })?;

    Ok(Some(TotpSecret { secret_bytes }))
}

/// Decodes RFC 4648 base32 text while tolerating spaces and hyphens.
fn decode_base32(value: &str) -> Result<Vec<u8>, String> {
    let mut bits = 0_u32;
    let mut bit_count = 0_u32;
    let mut output = Vec::new();

    for ch in value.chars() {
        if matches!(ch, ' ' | '\t' | '\n' | '\r' | '-') {
            continue;
        }

        if ch == '=' {
            break;
        }

        let upper = ch.to_ascii_uppercase();
        let symbol = match upper {
            'A'..='Z' => upper as u8 - b'A',
            '2'..='7' => upper as u8 - b'2' + 26,
            _ => return Err(format!("invalid base32 character {ch:?}")),
        };

        bits = (bits << 5) | u32::from(symbol);
        bit_count += 5;

        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xff) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Ok(output)
}

/// Encodes bytes as lower-case hex without additional dependencies.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Performs a constant-time equality comparison for two byte slices.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::RequiredSecondFactor;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Copy)]
    struct FixedTimeProvider {
        unix_timestamp: u64,
    }

    impl TimeProvider for FixedTimeProvider {
        fn unix_timestamp(&self) -> u64 {
            self.unix_timestamp
        }
    }

    #[derive(Debug, Clone)]
    struct StaticSecretStore {
        secrets: BTreeMap<String, TotpSecret>,
    }

    impl TotpSecretStore for StaticSecretStore {
        fn load_secret(
            &self,
            canonical_username: &str,
        ) -> Result<Option<TotpSecret>, TotpSecretStoreError> {
            Ok(self.secrets.get(canonical_username).cloned())
        }
    }

    fn rfc_secret() -> TotpSecret {
        TotpSecret {
            secret_bytes: b"12345678901234567890".to_vec(),
        }
    }

    #[test]
    fn decodes_base32_secrets() {
        let decoded =
            decode_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("secret should decode");

        assert_eq!(decoded, b"12345678901234567890");
    }

    #[test]
    fn generates_rfc6238_reference_code() {
        let code = generate_totp_code(
            &rfc_secret().secret_bytes,
            1,
            TotpPolicy {
                digits: 8,
                period_seconds: 30,
                allowed_skew_steps: 0,
            },
        )
        .expect("code generation should succeed");

        assert_eq!(code, "94287082");
    }

    #[test]
    fn file_secret_store_uses_hex_encoded_usernames() {
        let store = FileTotpSecretStore::new("/var/lib/osmap/secrets/totp");
        let path = store.secret_path_for_username("alice@example.com");

        assert_eq!(
            path,
            std::path::Path::new(
                "/var/lib/osmap/secrets/totp/616c696365406578616d706c652e636f6d.totp"
            )
        );
    }

    #[test]
    fn parses_secret_files() {
        let secret = parse_secret_file("# comment\nsecret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should parse")
            .expect("secret should exist");

        assert_eq!(secret.secret_bytes, b"12345678901234567890");
    }

    #[test]
    fn totp_verifier_accepts_current_code() {
        let verifier = TotpVerifier::new(
            StaticSecretStore {
                secrets: BTreeMap::from([("alice@example.com".to_string(), rfc_secret())]),
            },
            FixedTimeProvider { unix_timestamp: 59 },
            TotpPolicy {
                digits: 8,
                period_seconds: 30,
                allowed_skew_steps: 0,
            },
        );

        let verdict = verifier
            .verify_second_factor("alice@example.com", RequiredSecondFactor::Totp, "94287082")
            .expect("verification should succeed");

        assert_eq!(verdict, SecondFactorVerdict::Accept);
    }

    #[test]
    fn totp_verifier_rejects_invalid_codes() {
        let verifier = TotpVerifier::new(
            StaticSecretStore {
                secrets: BTreeMap::from([("alice@example.com".to_string(), rfc_secret())]),
            },
            FixedTimeProvider { unix_timestamp: 59 },
            TotpPolicy {
                digits: 8,
                period_seconds: 30,
                allowed_skew_steps: 0,
            },
        );

        let verdict = verifier
            .verify_second_factor("alice@example.com", RequiredSecondFactor::Totp, "00000000")
            .expect("verification should succeed");

        assert_eq!(verdict, SecondFactorVerdict::Reject);
    }

    #[test]
    fn totp_verifier_honors_allowed_clock_skew() {
        let verifier = TotpVerifier::new(
            StaticSecretStore {
                secrets: BTreeMap::from([("alice@example.com".to_string(), rfc_secret())]),
            },
            FixedTimeProvider { unix_timestamp: 89 },
            TotpPolicy {
                digits: 8,
                period_seconds: 30,
                allowed_skew_steps: 1,
            },
        );

        let verdict = verifier
            .verify_second_factor("alice@example.com", RequiredSecondFactor::Totp, "94287082")
            .expect("verification should succeed");

        assert_eq!(verdict, SecondFactorVerdict::Accept);
    }

    #[test]
    fn constant_time_compare_rejects_different_lengths() {
        assert!(!constant_time_eq(b"123456", b"1234567"));
    }
}
