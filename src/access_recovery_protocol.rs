//! Strict recovery RPC over the existing authenticated native mutation socket.
//! MACs authenticate the relay/frame; they do not prove a password, TOTP, stored
//! session or email challenge. The native dispatcher independently checks those.
use crate::browser_access::{
    AccessAction, AccessAuthority, AccessCookie, AccessError, AccessOutcome, AccessView,
};
use crate::private_account_file::PrivateAccountFile;
use crate::totp_enrollment::PendingEnrollment;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;

pub const SCHEMA: &str = "osmap-access-recovery-v1";
pub const MAX_FRAME: usize = crate::account_admission::MAX_FRAME;
const WINDOW: u64 = 30;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Authentication,
    Expired,
    Replay,
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    Unauthenticated {},
    Grant {
        token: String,
    },
    Session {
        account: String,
        epoch: u64,
        session_id: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    View {},
    Start {
        email: String,
    },
    Verify {
        challenge_id: String,
        code: String,
    },
    BeginReset {
        password: String,
        totp: String,
    },
    Confirm {
        enrollment_id: String,
        revision: u64,
        code: String,
        password: Option<String>,
        confirmation: Option<String>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    schema: String,
    authority: Authority,
    action: Action,
    csrf: String,
    source: String,
    issued: u64,
    expires: u64,
    nonce: String,
    signature: String,
}
macro_rules! redacted {
    ($($name:ty),+ $(,)?) => {$ (impl std::fmt::Debug for $name {
        fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result { f.write_str(concat!(stringify!($name),"([REDACTED])")) }
    })+};
}
redacted!(Authority, Action, Request);

impl Authority {
    pub fn from_browser(value: &AccessAuthority<'_>) -> Result<Self, Error> {
        Ok(match value {
            AccessAuthority::Unauthenticated => Self::Unauthenticated {},
            AccessAuthority::Grant(token) => Self::Grant {
                token: (*token).into(),
            },
            AccessAuthority::Session(session) => Self::Session {
                account: session.record.canonical_username.clone(),
                epoch: session.record.account_epoch.ok_or(Error::Authentication)?,
                session_id: session.record.session_id.clone(),
            },
        })
    }
}
impl Action {
    pub fn from_browser(value: Option<&AccessAction<'_>>) -> Self {
        match value {
            None => Self::View {},
            Some(AccessAction::SendRecoveryCode { email }) => Self::Start {
                email: (*email).into(),
            },
            Some(AccessAction::VerifyRecoveryCode { challenge_id, code }) => Self::Verify {
                challenge_id: (*challenge_id).into(),
                code: (*code).into(),
            },
            Some(AccessAction::BeginTotpReset {
                current_password,
                current_totp_code,
            }) => Self::BeginReset {
                password: (*current_password).into(),
                totp: (*current_totp_code).into(),
            },
            Some(AccessAction::ConfirmRecovery {
                enrollment_id,
                revision,
                new_password,
                confirmation,
                new_totp_code,
            }) => Self::Confirm {
                enrollment_id: (*enrollment_id).into(),
                revision: *revision,
                code: (*new_totp_code).into(),
                password: Some((*new_password).into()),
                confirmation: Some((*confirmation).into()),
            },
            Some(AccessAction::ConfirmTotpReset {
                enrollment_id,
                revision,
                new_totp_code,
            }) => Self::Confirm {
                enrollment_id: (*enrollment_id).into(),
                revision: *revision,
                code: (*new_totp_code).into(),
                password: None,
                confirmation: None,
            },
        }
    }
}
impl Request {
    pub fn from_browser(
        authority: &AccessAuthority<'_>,
        action: Option<&AccessAction<'_>>,
        csrf: &str,
        source: &str,
        now: u64,
        key: &[u8],
    ) -> Result<Self, Error> {
        Self::issue(
            Authority::from_browser(authority)?,
            Action::from_browser(action),
            csrf,
            source,
            now,
            key,
        )
    }
    pub fn issue(
        authority: Authority,
        action: Action,
        csrf: &str,
        source: &str,
        now: u64,
        key: &[u8],
    ) -> Result<Self, Error> {
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        let mut value = Self {
            schema: SCHEMA.into(),
            authority,
            action,
            csrf: csrf.into(),
            source: source.into(),
            issued: now,
            expires: now.checked_add(WINDOW).ok_or(Error::Invalid)?,
            nonce: hex(&nonce),
            signature: String::new(),
        };
        value.shape()?;
        value.signature = sign(key, b"request", &value.payload()?)?;
        Ok(value)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        frame(self)
    }
    /// Conservatively bind the frame to the caller's remaining workflow
    /// budget. This can shorten an existing signed window, never renew it.
    pub fn bound_expiry(mut self, expires_at: u64, key: &[u8]) -> Result<Self, Error> {
        self.valid(key, self.issued)?;
        if expires_at <= self.issued || expires_at > self.expires {
            return Err(Error::Expired);
        }
        self.expires = expires_at;
        self.signature = sign(key, b"request", &self.payload()?)?;
        Ok(self)
    }
    pub fn parse(raw: &[u8], key: &[u8], now: u64) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        let value: Self = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
        value.valid(key, now)?;
        Ok(value)
    }
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
    pub fn action(&self) -> &Action {
        &self.action
    }
    pub fn csrf(&self) -> &str {
        &self.csrf
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    fn payload(&self) -> Result<Vec<u8>, Error> {
        frame(&(
            SCHEMA,
            &self.authority,
            &self.action,
            &self.csrf,
            &self.source,
            self.issued,
            self.expires,
            &self.nonce,
        ))
    }
    fn valid(&self, key: &[u8], now: u64) -> Result<(), Error> {
        self.shape()?;
        if now < self.issued
            || now >= self.expires
            || !self
                .expires
                .checked_sub(self.issued)
                .is_some_and(|seconds| (1..=WINDOW).contains(&seconds))
        {
            return Err(Error::Expired);
        }
        verify(key, b"request", &self.payload()?, &self.signature)
    }
    fn shape(&self) -> Result<(), Error> {
        if self.schema != SCHEMA
            || !id(&self.csrf)
            || !id(&self.nonce)
            || !bounded(&self.source, 128)
            || self.issued == 0
        {
            return Err(Error::Invalid);
        }
        match &self.authority {
            Authority::Unauthenticated {} => {}
            Authority::Grant { token } if id(token) => {}
            Authority::Session {
                account,
                epoch,
                session_id,
            } if crate::account_admission::valid_account(account).is_ok()
                && crate::account_admission::valid_epoch(*epoch)
                && id(session_id) => {}
            _ => return Err(Error::Invalid),
        }
        let valid = match (&self.authority, &self.action) {
            (_, Action::View {}) => true,
            (Authority::Unauthenticated {}, Action::Start { email }) => {
                crate::account_admission::valid_account(email).is_ok()
            }
            (Authority::Unauthenticated {}, Action::Verify { challenge_id, code }) => {
                id(challenge_id) && otp(code)
            }
            (Authority::Session { .. }, Action::BeginReset { password, totp }) => {
                bounded(password, 1024) && otp(totp)
            }
            (
                Authority::Grant { .. },
                Action::Confirm {
                    enrollment_id,
                    revision,
                    code,
                    password: Some(password),
                    confirmation: Some(confirmation),
                },
            ) => {
                id(enrollment_id)
                    && *revision > 0
                    && otp(code)
                    && bounded(password, 1024)
                    && bounded(confirmation, 1024)
            }
            (
                Authority::Session { .. },
                Action::Confirm {
                    enrollment_id,
                    revision,
                    code,
                    password: None,
                    confirmation: None,
                },
            ) => id(enrollment_id) && *revision > 0 && otp(code),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
}

/// Native durable nonce admission. Caller must invoke this before all service
/// effects, including mail. Request MAC alone supplies no replay protection.
pub struct ReplayStore(PrivateAccountFile);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsedNonce {
    version: u8,
    nonce: String,
    request_signature: String,
    issued: u64,
    expires: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecord {
    version: u8,
    updated_at: u64,
    entries: Vec<UsedNonce>,
}
impl ReplayStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self(PrivateAccountFile::new(
            directory.into(),
            "osmap-access-rpc-replay-v1",
            262144,
        ))
    }
    pub fn verify_and_consume(&self, raw: &[u8], key: &[u8], now: u64) -> Result<Request, Error> {
        let value = Request::parse(raw, key, now)?;
        let locked = self.0.lock("current").map_err(|_| Error::Unavailable)?;
        let mut record = match locked.read().map_err(|_| Error::Unavailable)? {
            Some(raw) => {
                serde_json::from_slice::<ReplayRecord>(&raw).map_err(|_| Error::Unavailable)?
            }
            None => ReplayRecord {
                version: 1,
                updated_at: now,
                entries: Vec::new(),
            },
        };
        let mut unique = std::collections::BTreeSet::new();
        if record.version != 1
            || record.updated_at > now
            || record.entries.len() > 512
            || record.entries.iter().any(|entry| {
                entry.version != 1
                    || !id(&entry.nonce)
                    || !id(&entry.request_signature)
                    || entry.issued == 0
                    || entry.issued > record.updated_at
                    || !entry
                        .expires
                        .checked_sub(entry.issued)
                        .is_some_and(|seconds| (1..=WINDOW).contains(&seconds))
                    || !unique.insert(entry.nonce.clone())
            })
        {
            return Err(Error::Unavailable);
        }
        record.entries.retain(|entry| entry.expires > now);
        if record
            .entries
            .iter()
            .any(|entry| entry.nonce == value.nonce)
        {
            return Err(Error::Replay);
        }
        if record.entries.len() >= 512 {
            return Err(Error::Unavailable);
        }
        let used = UsedNonce {
            version: 1,
            nonce: value.nonce.clone(),
            request_signature: value.signature.clone(),
            issued: value.issued,
            expires: value.expires,
        };
        record.entries.push(used);
        record.updated_at = now;
        locked
            .write(&serde_json::to_vec(&record).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?;
        Ok(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub id: String,
    pub revision: u64,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub expires_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum View {
    RecoveryEmail {
        csrf: String,
    },
    RecoveryCode {
        csrf: String,
        challenge_id: String,
    },
    RecoverySetup {
        csrf: String,
        enrollment: Enrollment,
    },
    TotpResetStart {
        account: String,
        csrf: String,
    },
    TotpReplacement {
        account: String,
        csrf: String,
        enrollment: Enrollment,
    },
    Complete {},
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Cookie {
    Unchanged {},
    Set { token: String },
    Clear {},
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub view: View,
    pub grant_cookie: Cookie,
}
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Refused,
    Expired,
    Conflict,
    Throttled,
    Unavailable,
    Unconfirmed,
}
redacted!(Enrollment, View, Cookie, Outcome);
impl From<PendingEnrollment> for Enrollment {
    fn from(v: PendingEnrollment) -> Self {
        Self {
            id: v.id,
            revision: v.revision,
            secret_base32: v.secret_base32,
            otpauth_uri: v.otpauth_uri,
            expires_at: v.expires_at,
        }
    }
}
impl From<Enrollment> for PendingEnrollment {
    fn from(v: Enrollment) -> Self {
        Self {
            id: v.id,
            revision: v.revision,
            secret_base32: v.secret_base32,
            otpauth_uri: v.otpauth_uri,
            expires_at: v.expires_at,
        }
    }
}
impl From<AccessView> for View {
    fn from(v: AccessView) -> Self {
        match v {
            AccessView::RecoveryEmail { csrf } => Self::RecoveryEmail { csrf },
            AccessView::RecoveryCode { csrf, challenge_id } => {
                Self::RecoveryCode { csrf, challenge_id }
            }
            AccessView::RecoverySetup { csrf, enrollment } => Self::RecoverySetup {
                csrf,
                enrollment: enrollment.into(),
            },
            AccessView::TotpResetStart { account, csrf } => Self::TotpResetStart { account, csrf },
            AccessView::TotpReplacement {
                account,
                csrf,
                enrollment,
            } => Self::TotpReplacement {
                account,
                csrf,
                enrollment: enrollment.into(),
            },
            AccessView::Complete => Self::Complete {},
        }
    }
}
impl From<View> for AccessView {
    fn from(v: View) -> Self {
        match v {
            View::RecoveryEmail { csrf } => Self::RecoveryEmail { csrf },
            View::RecoveryCode { csrf, challenge_id } => Self::RecoveryCode { csrf, challenge_id },
            View::RecoverySetup { csrf, enrollment } => Self::RecoverySetup {
                csrf,
                enrollment: enrollment.into(),
            },
            View::TotpResetStart { account, csrf } => Self::TotpResetStart { account, csrf },
            View::TotpReplacement {
                account,
                csrf,
                enrollment,
            } => Self::TotpReplacement {
                account,
                csrf,
                enrollment: enrollment.into(),
            },
            View::Complete {} => Self::Complete,
        }
    }
}
impl From<AccessOutcome> for Outcome {
    fn from(v: AccessOutcome) -> Self {
        Self {
            view: v.view.into(),
            grant_cookie: match v.grant_cookie {
                AccessCookie::Unchanged => Cookie::Unchanged {},
                AccessCookie::Set(token) => Cookie::Set { token },
                AccessCookie::Clear => Cookie::Clear {},
            },
        }
    }
}
impl From<Outcome> for AccessOutcome {
    fn from(v: Outcome) -> Self {
        Self {
            view: v.view.into(),
            grant_cookie: match v.grant_cookie {
                Cookie::Unchanged {} => AccessCookie::Unchanged,
                Cookie::Set { token } => AccessCookie::Set(token),
                Cookie::Clear {} => AccessCookie::Clear,
            },
        }
    }
}
impl From<AccessError> for Failure {
    fn from(v: AccessError) -> Self {
        match v {
            AccessError::Refused => Self::Refused,
            AccessError::Expired => Self::Expired,
            AccessError::Conflict => Self::Conflict,
            AccessError::Throttled => Self::Throttled,
            AccessError::Unavailable => Self::Unavailable,
            AccessError::Unconfirmed => Self::Unconfirmed,
        }
    }
}
impl From<Failure> for AccessError {
    fn from(v: Failure) -> Self {
        match v {
            Failure::Refused => Self::Refused,
            Failure::Expired => Self::Expired,
            Failure::Conflict => Self::Conflict,
            Failure::Throttled => Self::Throttled,
            Failure::Unavailable => Self::Unavailable,
            Failure::Unconfirmed => Self::Unconfirmed,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    schema: String,
    nonce: String,
    request_signature: String,
    responded_at: u64,
    result: Result<Outcome, Failure>,
    signature: String,
}
redacted!(Response);
impl Response {
    pub fn issue(
        request: &Request,
        result: Result<AccessOutcome, AccessError>,
        key: &[u8],
        now: u64,
    ) -> Result<Self, Error> {
        request.valid(key, now)?;
        let mut value = Self {
            schema: SCHEMA.into(),
            nonce: request.nonce.clone(),
            request_signature: request.signature.clone(),
            responded_at: now,
            result: result.map(Into::into).map_err(Into::into),
            signature: String::new(),
        };
        value.signature = sign(key, b"response", &value.payload()?)?;
        Ok(value)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        frame(self)
    }
    pub fn verify(
        raw: &[u8],
        request: &Request,
        key: &[u8],
        now: u64,
    ) -> Result<Result<AccessOutcome, AccessError>, Error> {
        if raw.is_empty() || raw.len() > MAX_FRAME {
            return Err(Error::Invalid);
        }
        let value: Self = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
        request.valid(key, now)?;
        if value.schema != SCHEMA
            || value.nonce != request.nonce
            || value.request_signature != request.signature
            || value.responded_at < request.issued
            || value.responded_at >= request.expires
        {
            return Err(Error::Authentication);
        }
        verify(key, b"response", &value.payload()?, &value.signature)?;
        value.shape(request)?;
        Ok(value.result.map(Into::into).map_err(Into::into))
    }
    fn payload(&self) -> Result<Vec<u8>, Error> {
        frame(&(
            SCHEMA,
            &self.nonce,
            &self.request_signature,
            self.responded_at,
            &self.result,
        ))
    }
    fn shape(&self, request: &Request) -> Result<(), Error> {
        let Ok(value) = &self.result else {
            return Ok(());
        };
        if let Cookie::Set { token } = &value.grant_cookie {
            if !id(token) {
                return Err(Error::Invalid);
            }
        }
        let (csrf, enrollment) = match &value.view {
            View::RecoveryEmail { csrf } => (Some(csrf), None),
            View::RecoveryCode { csrf, challenge_id } => {
                if !id(challenge_id) {
                    return Err(Error::Invalid);
                }
                (Some(csrf), None)
            }
            View::RecoverySetup { csrf, enrollment } => (Some(csrf), Some(enrollment)),
            View::TotpResetStart { account, csrf } => {
                if crate::account_admission::valid_account(account).is_err() {
                    return Err(Error::Invalid);
                }
                (Some(csrf), None)
            }
            View::TotpReplacement {
                account,
                csrf,
                enrollment,
            } => {
                if crate::account_admission::valid_account(account).is_err() {
                    return Err(Error::Invalid);
                }
                (Some(csrf), Some(enrollment))
            }
            View::Complete {} => (None, None),
        };
        if csrf.is_some_and(|value| value != &request.csrf) {
            return Err(Error::Authentication);
        }
        let stage_matches = match (
            &request.authority,
            &request.action,
            &value.view,
            &value.grant_cookie,
        ) {
            (
                Authority::Unauthenticated {},
                Action::View {} | Action::Start { .. },
                View::RecoveryEmail { .. } | View::RecoveryCode { .. },
                Cookie::Unchanged {},
            ) => true,
            (
                Authority::Unauthenticated {},
                Action::Verify { .. },
                View::RecoverySetup { .. },
                Cookie::Set { .. },
            ) => true,
            (
                Authority::Grant { .. },
                Action::View {},
                View::RecoverySetup { .. },
                Cookie::Unchanged {},
            ) => true,
            (
                Authority::Grant { .. },
                Action::Confirm { .. },
                View::Complete {},
                Cookie::Clear {},
            ) => true,
            (
                Authority::Session { account, .. },
                Action::View {} | Action::BeginReset { .. },
                View::TotpResetStart {
                    account: returned, ..
                }
                | View::TotpReplacement {
                    account: returned, ..
                },
                Cookie::Unchanged {},
            ) => account == returned,
            (
                Authority::Session { .. },
                Action::Confirm { .. },
                View::Complete {},
                Cookie::Clear {} | Cookie::Unchanged {},
            ) => true,
            _ => false,
        };
        if !stage_matches {
            return Err(Error::Authentication);
        }
        if let Some(value) = enrollment {
            if !id(&value.id)
                || value.revision == 0
                || !bounded(&value.secret_base32, 128)
                || !value
                    .secret_base32
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
                || !bounded(&value.otpauth_uri, 4096)
                || !value.otpauth_uri.starts_with("otpauth://totp/")
                || value.expires_at <= self.responded_at
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
fn bounded(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn otp(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|b| b.is_ascii_digit())
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let raw = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if raw.len() > MAX_FRAME {
        Err(Error::Invalid)
    } else {
        Ok(raw)
    }
}
fn mac(key: &[u8], domain: &[u8], payload: &[u8]) -> Result<HmacSha256, Error> {
    if !(32..=1024).contains(&key.len()) {
        return Err(Error::Authentication);
    }
    let mut value = HmacSha256::new_from_slice(key).map_err(|_| Error::Authentication)?;
    value.update(SCHEMA.as_bytes());
    value.update(b"\0");
    value.update(domain);
    value.update(b"\0");
    value.update(payload);
    Ok(value)
}
fn sign(key: &[u8], domain: &[u8], payload: &[u8]) -> Result<String, Error> {
    Ok(hex(&mac(key, domain, payload)?.finalize().into_bytes()))
}
fn verify(key: &[u8], domain: &[u8], payload: &[u8], signature: &str) -> Result<(), Error> {
    if !id(signature) {
        return Err(Error::Authentication);
    }
    let raw: Result<Vec<_>, _> = (0..64)
        .step_by(2)
        .map(|at| u8::from_str_radix(&signature[at..at + 2], 16))
        .collect();
    mac(key, domain, payload)?
        .verify_slice(&raw.map_err(|_| Error::Authentication)?)
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
#[path = "access_recovery_protocol_tests.rs"]
mod tests;
