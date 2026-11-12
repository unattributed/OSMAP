//! Native-owned registered-email account recovery. Web-owned contact records
//! and browser assertions are not authorities for this store. Native composition
//! supplies the verified contact, active epoch, existing factor and mailer.
//! An opaque restricted grant has no conversion to a normal mail session.
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use crate::recovery_contact::RecoveryContactDelivery;
use crate::session::{RandomSource, SystemRandomSource};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Instant;

const CODE_SECONDS: u64 = 600;
const GRANT_SECONDS: u64 = 600;
const MAX_ATTEMPTS: u8 = 5;
const MAX_BYTES: usize = 16384;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Denied,
    Expired,
    Busy,
    Unavailable,
    /// A one-use proof/effect was dispatched. It must not be retried blindly.
    Unconfirmed,
}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        if value.kind() == std::io::ErrorKind::WouldBlock {
            Self::Busy
        } else {
            Self::Unavailable
        }
    }
}

/// Construct only from independently native-owned verified-contact state.
/// This is deliberately not a wire/deserializable proof object.
pub struct EligibleAccount {
    pub epoch: u64,
    pub verified_email: String,
    pub contact_revision: u64,
    pub verified_at: u64,
    pub existing_factor_sha256: String,
}
impl std::fmt::Debug for EligibleAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EligibleAccount(<private>)")
    }
}

/// The actual native service implements this lookup. A Web-produced Boolean,
/// session, or settings-file verified flag cannot implement their authority.
pub trait Authority {
    fn eligible(&self, account: &str, deadline: Instant) -> Result<Option<EligibleAccount>, Error>;
}

pub trait Notifier {
    /// One bounded send. Never log borrowed private values or retry ambiguity.
    fn deliver(
        &self,
        account: &str,
        email: &str,
        code: &str,
        expires_at: u64,
        deadline: Instant,
    ) -> RecoveryContactDelivery;
}

pub struct Start<'a> {
    pub account: &'a str,
    pub source: &'a str,
    pub flow: &'a str,
    pub now: u64,
    pub deadline: Instant,
}
pub struct Verify<'a> {
    pub account: &'a str,
    pub source: &'a str,
    pub flow: &'a str,
    pub challenge_id: &'a str,
    pub email_code: &'a str,
    pub now: u64,
    pub deadline: Instant,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Started {
    /// Same public shape for eligible, unknown and throttled accounts.
    pub challenge_id: String,
    pub expires_at: u64,
    /// Native-only source admission disposition; never serialize as account
    /// information. It is decided before any account/contact lookup.
    pub source_limited: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    /// Replacement authenticator setup and the explicitly staged password
    /// step only. This does not authorize mail, Settings or another account.
    AccountRecoverySetup,
}
pub struct GrantBinding {
    pub account: String,
    pub epoch: u64,
    pub purpose: Purpose,
    pub expires_at: u64,
    pub flow_sha256: String,
    pub existing_factor_sha256: String,
}
impl std::fmt::Debug for GrantBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantBinding(<private>)")
    }
}
pub struct RestrictedGrant {
    token: String,
    pub binding: GrantBinding,
}
impl RestrictedGrant {
    /// Transport only in an HttpOnly/Secure/SameSite restricted cookie.
    pub fn token(&self) -> &str {
        &self.token
    }
}
impl std::fmt::Debug for RestrictedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RestrictedGrant(<private>)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rate {
    version: u8,
    key: String,
    updated_at: u64,
    attempts: Vec<u64>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    Open,
    Verifying,
    GrantIssued,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    id: String,
    flow_sha256: String,
    epoch: Option<u64>,
    contact_digest: Option<String>,
    code_digest: Option<String>,
    created_at: u64,
    expires_at: u64,
    attempts: u8,
    phase: Phase,
    delivery: RecoveryContactDelivery,
    grant_key: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    version: u8,
    account: String,
    updated_at: u64,
    sends: Vec<u64>,
    challenge: Option<Challenge>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum GrantState {
    Pending,
    Processing,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRecord {
    version: u8,
    key: String,
    account: String,
    epoch: u64,
    contact_digest: String,
    flow_sha256: String,
    existing_factor_sha256: String,
    purpose: Purpose,
    issued_at: u64,
    expires_at: u64,
    state: GrantState,
}
impl GrantRecord {
    fn binding(&self) -> GrantBinding {
        GrantBinding {
            account: self.account.clone(),
            epoch: self.epoch,
            purpose: self.purpose,
            expires_at: self.expires_at,
            flow_sha256: self.flow_sha256.clone(),
            existing_factor_sha256: self.existing_factor_sha256.clone(),
        }
    }
}

/// Instantiate under a native-owned root. PrivateAccountFile enforces effective
/// process ownership, mode0700/0600 and account-hashed path components.
pub struct Store {
    accounts: PrivateAccountFile,
    sources: PrivateAccountFile,
    grants: PrivateAccountFile,
    challenges: PrivateAccountFile,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeIndex {
    version: u8,
    id: String,
    account: String,
    flow_sha256: String,
    expires_at: u64,
}
impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            accounts: PrivateAccountFile::new(
                root.join("accounts"),
                "osmap-access-recovery-v1",
                MAX_BYTES,
            ),
            sources: PrivateAccountFile::new(
                root.join("sources"),
                "osmap-access-recovery-source-v1",
                MAX_BYTES,
            ),
            grants: PrivateAccountFile::new(
                root.join("grants"),
                "osmap-access-recovery-grant-v1",
                MAX_BYTES,
            ),
            challenges: PrivateAccountFile::new(
                root.join("challenges"),
                "osmap-access-challenge-v1",
                MAX_BYTES,
            ),
        }
    }

    pub fn start<A: Authority, N: Notifier>(
        &self,
        request: Start<'_>,
        authority: &A,
        notifier: &N,
    ) -> Result<Started, Error> {
        self.start_random(request, authority, notifier, &SystemRandomSource)
    }

    fn start_random<A: Authority, N: Notifier, R: RandomSource>(
        &self,
        request: Start<'_>,
        authority: &A,
        notifier: &N,
        random: &R,
    ) -> Result<Started, Error> {
        inputs(
            request.account,
            request.source,
            request.now,
            request.deadline,
        )?;
        let flow_sha256 = flow_key(request.flow)?;
        let response = Started {
            challenge_id: random_hex(random)?,
            expires_at: request
                .now
                .checked_add(CODE_SECONDS)
                .ok_or(Error::Invalid)?,
            source_limited: false,
        };
        if !self.source_attempt(request.source, request.now)? {
            return Ok(Started {
                source_limited: true,
                ..response
            });
        }
        before(request.deadline)?;
        let eligible = match authority.eligible(request.account, request.deadline) {
            Ok(Some(value)) => value,
            Ok(None) | Err(Error::Denied) => return Ok(response),
            Err(error) => return Err(error),
        };
        let contact = contact_digest(&eligible, request.now)?;
        let locked = self.accounts.lock(request.account)?;
        let mut account = account_record(request.account, locked.read()?, request.now)?;
        if let Some(c) = &account.challenge {
            if c.phase == Phase::Verifying {
                return Ok(response);
            }
            if c.phase == Phase::GrantIssued {
                if let Some(key) = &c.grant_key {
                    if let Some(raw) = self.grants.read(slot(key))? {
                        let grant = parse_grant(raw, request.now)?;
                        if grant.key == *key
                            && (grant.state == GrantState::Processing
                                || (grant.state == GrantState::Pending
                                    && request.now < grant.expires_at))
                        {
                            return Ok(response);
                        }
                    }
                }
            }
            if c.phase == Phase::Open
                && request.now < c.expires_at
                && account
                    .sends
                    .last()
                    .is_some_and(|at| request.now.saturating_sub(*at) < 60)
            {
                if c.flow_sha256 != flow_sha256 {
                    return Ok(response);
                }
                return Ok(Started {
                    challenge_id: c.id.clone(),
                    expires_at: c.expires_at,
                    source_limited: false,
                });
            }
        }
        account
            .sends
            .retain(|at| request.now.saturating_sub(*at) < 3600);
        if account.sends.len() >= 3 {
            return Ok(response);
        }
        before(request.deadline)?;
        let index = self.challenges.lock(slot(&response.challenge_id))?;
        if let Some(raw) = index.read()? {
            let previous: ChallengeIndex =
                serde_json::from_slice(&raw).map_err(|_| Error::Unavailable)?;
            if previous.version != 1
                || !lower_hex(&previous.id)
                || !lower_hex(&previous.flow_sha256)
                || crate::account_admission::valid_account(&previous.account).is_err()
            {
                return Err(Error::Unavailable);
            }
            if request.now < previous.expires_at
                || self.account_uncertain(&previous.account, request.now)?
            {
                return Ok(response);
            }
        }
        let code = random_code(random)?;
        account.updated_at = request.now;
        account.sends.push(request.now);
        account.challenge = Some(Challenge {
            id: response.challenge_id.clone(),
            flow_sha256: flow_sha256.clone(),
            epoch: Some(eligible.epoch),
            contact_digest: Some(contact),
            code_digest: Some(code_digest(&response.challenge_id, &code)?),
            created_at: request.now,
            expires_at: response.expires_at,
            attempts: 0,
            phase: Phase::Open,
            // Persist dispatch uncertainty BEFORE calling the sender.
            delivery: RecoveryContactDelivery::Unconfirmed,
            grant_key: None,
        });
        save(&locked, &account)?;
        save(
            &index,
            &ChallengeIndex {
                version: 1,
                id: response.challenge_id.clone(),
                account: request.account.into(),
                flow_sha256,
                expires_at: response.expires_at,
            },
        )?;
        before(request.deadline)?;
        {
            let delivery = notifier.deliver(
                request.account,
                &eligible.verified_email,
                &code,
                response.expires_at,
                request.deadline,
            );
            account
                .challenge
                .as_mut()
                .ok_or(Error::Unavailable)?
                .delivery = delivery;
            save(&locked, &account)?;
        }
        before(request.deadline)?;
        Ok(response)
    }

    pub fn verify<A: Authority>(
        &self,
        request: Verify<'_>,
        authority: &A,
    ) -> Result<RestrictedGrant, Error> {
        self.verify_random(request, authority, &SystemRandomSource)
    }

    /// Resolve the account from a native-only, expiring challenge index. The
    /// browser supplies only the challenge and its bound double-submit flow.
    #[allow(clippy::too_many_arguments)] // Exact proof/flow/source and original native deadline.
    pub fn verify_challenge<A: Authority>(
        &self,
        challenge_id: &str,
        flow: &str,
        source: &str,
        email_code: &str,
        now: u64,
        deadline: Instant,
        authority: &A,
    ) -> Result<RestrictedGrant, Error> {
        before(deadline)?;
        if !lower_hex(challenge_id) {
            return Err(Error::Denied);
        }
        let flow_sha256 = flow_key(flow)?;
        let index_lock = self.challenges.lock(slot(challenge_id))?;
        let raw = index_lock.read()?.ok_or(Error::Denied)?;
        let index: ChallengeIndex = serde_json::from_slice(&raw).map_err(|_| Error::Unavailable)?;
        if index.version != 1
            || index.id != challenge_id
            || index.flow_sha256 != flow_sha256
            || crate::account_admission::valid_account(&index.account).is_err()
            || now >= index.expires_at
            || index.expires_at.saturating_sub(now) > CODE_SECONDS
        {
            return Err(Error::Denied);
        }
        self.verify(
            Verify {
                account: &index.account,
                source,
                flow,
                challenge_id,
                email_code,
                now,
                deadline,
            },
            authority,
        )
    }

    fn verify_random<A: Authority, R: RandomSource>(
        &self,
        request: Verify<'_>,
        authority: &A,
        random: &R,
    ) -> Result<RestrictedGrant, Error> {
        inputs(
            request.account,
            request.source,
            request.now,
            request.deadline,
        )?;
        let flow_sha256 = flow_key(request.flow)?;
        if !self.source_attempt(request.source, request.now)? {
            return Err(Error::Denied);
        }
        let eligible = authority
            .eligible(request.account, request.deadline)?
            .ok_or(Error::Denied)?;
        let locked = self.accounts.lock(request.account)?;
        let mut account = account_record(request.account, locked.read()?, request.now)?;
        let c = account.challenge.as_mut().ok_or(Error::Denied)?;
        if c.phase != Phase::Open {
            return Err(if c.phase == Phase::Verifying {
                Error::Unconfirmed
            } else {
                Error::Denied
            });
        }
        if request.now >= c.expires_at || c.attempts >= MAX_ATTEMPTS {
            return Err(Error::Denied);
        }
        c.attempts += 1;
        account.updated_at = request.now;
        let proof_matches = c.id == request.challenge_id
            && c.flow_sha256 == flow_sha256
            && request.email_code.len() == 6
            && request.email_code.bytes().all(|b| b.is_ascii_digit())
            && c.code_digest
                .as_deref()
                .is_some_and(|digest| matches_code(&c.id, request.email_code, digest));
        save(&locked, &account)?;
        if !proof_matches {
            return Err(Error::Denied);
        }
        let c = account.challenge.as_mut().ok_or(Error::Unavailable)?;
        if c.epoch != Some(eligible.epoch)
            || c.contact_digest.as_ref() != Some(&contact_digest(&eligible, request.now)?)
            || c.delivery == RecoveryContactDelivery::Refused
        {
            return Err(Error::Denied);
        }
        before(request.deadline)?;
        let mut allocation = None;
        // Bounded ID allocation is not a credential/effect retry. Allocate a
        // free slot before consuming proof so a collision cannot burn a code.
        for _ in 0..8 {
            let token = random_hex(random)?;
            if token == request.challenge_id {
                continue;
            }
            let key = token_key(&token)?;
            let grant_lock = self.grants.lock(slot(&key))?;
            if let Some(raw) = grant_lock.read()? {
                let prior = parse_grant(raw, request.now)?;
                if prior.state == GrantState::Processing
                    || (prior.state == GrantState::Pending && request.now < prior.expires_at)
                {
                    continue;
                }
            }
            allocation = Some((token, key, grant_lock));
            break;
        }
        let (token, key, grant_lock) = allocation.ok_or(Error::Unavailable)?;
        let c = account.challenge.as_mut().ok_or(Error::Unavailable)?;
        c.phase = Phase::Verifying;
        save(&locked, &account)?;
        // Consume the proof durably before minting the restricted grant. On
        // uncertain storage outcome, keep Verifying and never mint it twice.
        before(request.deadline).map_err(|_| Error::Unconfirmed)?;
        let grant = GrantRecord {
            version: 1,
            key: key.clone(),
            account: request.account.into(),
            epoch: eligible.epoch,
            contact_digest: contact_digest(&eligible, request.now)?,
            flow_sha256,
            existing_factor_sha256: eligible.existing_factor_sha256.clone(),
            purpose: Purpose::AccountRecoverySetup,
            issued_at: request.now,
            expires_at: request
                .now
                .checked_add(GRANT_SECONDS)
                .ok_or(Error::Unconfirmed)?,
            state: GrantState::Pending,
        };
        save(&grant_lock, &grant).map_err(|_| Error::Unconfirmed)?;
        let c = account.challenge.as_mut().ok_or(Error::Unconfirmed)?;
        c.phase = Phase::GrantIssued;
        c.code_digest = None;
        c.grant_key = Some(key);
        save(&locked, &account).map_err(|_| Error::Unconfirmed)?;
        before(request.deadline).map_err(|_| Error::Unconfirmed)?;
        Ok(RestrictedGrant {
            token,
            binding: grant.binding(),
        })
    }

    pub fn lookup_grant<A: Authority>(
        &self,
        token: &str,
        flow: &str,
        now: u64,
        deadline: Instant,
        authority: &A,
    ) -> Result<GrantBinding, Error> {
        before(deadline)?;
        let key = token_key(token)?;
        let raw = self.grants.read(slot(&key))?.ok_or(Error::Denied)?;
        let grant = decode_grant(raw, &key, now)?;
        if grant.flow_sha256 != flow_key(flow)? {
            return Err(Error::Denied);
        }
        validate_grant(&grant, now, deadline, authority)?;
        Ok(grant.binding())
    }

    /// The native stage machine calls this only after all setup/password inputs
    /// are independently validated. Persist Processing before the first effect;
    /// all closure failures remain Unconfirmed and cannot repeat that effect.
    pub fn consume_grant<A: Authority, F>(
        &self,
        token: &str,
        flow: &str,
        now: u64,
        deadline: Instant,
        authority: &A,
        effect: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&GrantBinding) -> Result<(), Error>,
    {
        before(deadline)?;
        let key = token_key(token)?;
        let locked = self.grants.lock(slot(&key))?;
        let mut grant = decode_grant(locked.read()?.ok_or(Error::Denied)?, &key, now)?;
        if grant.flow_sha256 != flow_key(flow)? {
            return Err(Error::Denied);
        }
        validate_grant(&grant, now, deadline, authority)?;
        grant.state = GrantState::Processing;
        save(&locked, &grant)?;
        effect(&grant.binding()).map_err(|_| Error::Unconfirmed)?;
        before(deadline).map_err(|_| Error::Unconfirmed)?;
        grant.state = GrantState::Complete;
        save(&locked, &grant).map_err(|_| Error::Unconfirmed)
    }

    fn source_attempt(&self, source: &str, now: u64) -> Result<bool, Error> {
        let source: std::net::IpAddr = source.parse().map_err(|_| Error::Invalid)?;
        let source_digest = digest("osmap-access-source-v1", source.to_string().as_bytes());
        let key = slot(&source_digest).to_owned();
        let locked = self.sources.lock(&key)?;
        let mut rate = match locked.read()? {
            Some(raw) => serde_json::from_slice::<Rate>(&raw).map_err(|_| Error::Unavailable)?,
            None => Rate {
                version: 1,
                key: key.clone(),
                updated_at: now,
                attempts: Vec::new(),
            },
        };
        if rate.version != 1
            || rate.key != key
            || rate.updated_at > now
            || rate.attempts.len() > 30
            || rate.attempts.iter().any(|at| *at > rate.updated_at)
            || rate.attempts.windows(2).any(|p| p[0] > p[1])
        {
            return Err(Error::Unavailable);
        }
        rate.attempts.retain(|at| now.saturating_sub(*at) < 900);
        if rate.attempts.len() >= 30 {
            return Ok(false);
        }
        rate.attempts.push(now);
        rate.updated_at = now;
        save(&locked, &rate)?;
        Ok(true)
    }

    fn account_uncertain(&self, account: &str, now: u64) -> Result<bool, Error> {
        let record = account_record(account, self.accounts.read(account)?, now)?;
        let Some(challenge) = record.challenge else {
            return Ok(false);
        };
        if challenge.phase == Phase::Verifying {
            return Ok(true);
        }
        if let Some(key) = challenge.grant_key {
            if let Some(raw) = self.grants.read(slot(&key))? {
                let grant = parse_grant(raw, now)?;
                return Ok(grant.key == key
                    && (grant.state == GrantState::Processing
                        || (grant.state == GrantState::Pending && now < grant.expires_at)));
            }
        }
        Ok(false)
    }
}

fn before(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn inputs(account: &str, source: &str, now: u64, deadline: Instant) -> Result<(), Error> {
    before(deadline)?;
    crate::account_admission::valid_account(account).map_err(|_| Error::Invalid)?;
    if source.is_empty() || source.len() > 128 || source.chars().any(char::is_control) || now == 0 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn save<T: Serialize>(locked: &LockedAccountFile, value: &T) -> Result<(), Error> {
    locked.write(&serde_json::to_vec(value).map_err(|_| Error::Unavailable)?)?;
    Ok(())
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn lower_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Exactly4096 physical slots; full IDs remain checked inside each record.
fn slot(value: &str) -> &str {
    &value[..3]
}
fn digest(domain: &str, raw: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update(b"\0");
    hash.update(raw);
    hex(&hash.finalize())
}
fn random_hex<R: RandomSource>(random: &R) -> Result<String, Error> {
    let mut raw = [0; 32];
    random
        .fill_bytes(&mut raw)
        .map_err(|_| Error::Unavailable)?;
    Ok(hex(&raw))
}
fn random_code<R: RandomSource>(random: &R) -> Result<String, Error> {
    for _ in 0..128 {
        let mut raw = [0; 4];
        random
            .fill_bytes(&mut raw)
            .map_err(|_| Error::Unavailable)?;
        let n = u32::from_be_bytes(raw);
        if n < 4_294_000_000 {
            return Ok(format!("{:06}", n % 1_000_000));
        }
    }
    Err(Error::Unavailable)
}
fn token_key(token: &str) -> Result<String, Error> {
    if !lower_hex(token) {
        return Err(Error::Denied);
    }
    Ok(digest("osmap-access-grant-token-v1", token.as_bytes()))
}
fn flow_key(flow: &str) -> Result<String, Error> {
    if !lower_hex(flow) {
        return Err(Error::Denied);
    }
    Ok(digest("osmap-access-flow-v1", flow.as_bytes()))
}
fn contact_digest(value: &EligibleAccount, now: u64) -> Result<String, Error> {
    if !crate::account_admission::valid_epoch(value.epoch)
        || value.contact_revision == 0
        || value.verified_at == 0
        || value.verified_at > now
        || value.verified_email.len() > 254
        || value.verified_email.chars().any(char::is_control)
        || value.verified_email.split('@').count() != 2
        || !lower_hex(&value.existing_factor_sha256)
    {
        return Err(Error::Unavailable);
    }
    Ok(digest(
        "osmap-access-contact-v1",
        &serde_json::to_vec(&(
            &value.verified_email,
            value.contact_revision,
            value.verified_at,
            &value.existing_factor_sha256,
        ))
        .map_err(|_| Error::Unavailable)?,
    ))
}
fn code_digest(challenge: &str, code: &str) -> Result<String, Error> {
    let mut mac =
        HmacSha256::new_from_slice(challenge.as_bytes()).map_err(|_| Error::Unavailable)?;
    mac.update(b"osmap-access-email-otp-v1\0");
    mac.update(code.as_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}
fn matches_code(challenge: &str, code: &str, expected: &str) -> bool {
    if !lower_hex(expected) {
        return false;
    }
    let raw: Result<Vec<_>, _> = (0..64)
        .step_by(2)
        .map(|at| u8::from_str_radix(&expected[at..at + 2], 16))
        .collect();
    let Ok(raw) = raw else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(challenge.as_bytes()) else {
        return false;
    };
    mac.update(b"osmap-access-email-otp-v1\0");
    mac.update(code.as_bytes());
    mac.verify_slice(&raw).is_ok()
}
fn account_record(account: &str, raw: Option<Vec<u8>>, now: u64) -> Result<Account, Error> {
    let value = match raw {
        Some(raw) => serde_json::from_slice::<Account>(&raw).map_err(|_| Error::Unavailable)?,
        None => Account {
            version: 1,
            account: account.into(),
            updated_at: now,
            sends: Vec::new(),
            challenge: None,
        },
    };
    if value.version != 1
        || value.account != account
        || value.updated_at > now
        || value.sends.len() > 3
        || value.sends.iter().any(|at| *at > value.updated_at)
        || value.sends.windows(2).any(|p| p[0] > p[1])
    {
        return Err(Error::Unavailable);
    }
    if let Some(c) = &value.challenge {
        if !lower_hex(&c.id)
            || !lower_hex(&c.flow_sha256)
            || c.created_at > value.updated_at
            || c.created_at.checked_add(CODE_SECONDS) != Some(c.expires_at)
            || c.attempts > MAX_ATTEMPTS
            || c.epoch
                .is_some_and(|e| !crate::account_admission::valid_epoch(e))
            || c.epoch.is_some() != c.contact_digest.is_some()
            || c.contact_digest.as_ref().is_some_and(|d| !lower_hex(d))
            || c.code_digest.as_ref().is_some_and(|d| !lower_hex(d))
            || c.grant_key.as_ref().is_some_and(|d| !lower_hex(d))
            || (c.phase == Phase::GrantIssued && (c.grant_key.is_none() || c.code_digest.is_some()))
        {
            return Err(Error::Unavailable);
        }
    }
    Ok(value)
}
fn decode_grant(raw: Vec<u8>, key: &str, now: u64) -> Result<GrantRecord, Error> {
    let value = parse_grant(raw, now)?;
    if value.key != key {
        return Err(Error::Denied);
    }
    Ok(value)
}
fn parse_grant(raw: Vec<u8>, now: u64) -> Result<GrantRecord, Error> {
    let value: GrantRecord = serde_json::from_slice(&raw).map_err(|_| Error::Unavailable)?;
    if value.version != 1
        || !lower_hex(&value.key)
        || crate::account_admission::valid_account(&value.account).is_err()
        || !crate::account_admission::valid_epoch(value.epoch)
        || !lower_hex(&value.contact_digest)
        || !lower_hex(&value.flow_sha256)
        || !lower_hex(&value.existing_factor_sha256)
        || value.issued_at > now
        || value.issued_at.checked_add(GRANT_SECONDS) != Some(value.expires_at)
    {
        return Err(Error::Unavailable);
    }
    Ok(value)
}
fn validate_grant<A: Authority>(
    grant: &GrantRecord,
    now: u64,
    deadline: Instant,
    authority: &A,
) -> Result<(), Error> {
    before(deadline)?;
    match grant.state {
        GrantState::Processing => return Err(Error::Unconfirmed),
        GrantState::Complete => return Err(Error::Denied),
        GrantState::Pending => {}
    }
    if now >= grant.expires_at {
        return Err(Error::Expired);
    }
    let eligible = authority
        .eligible(&grant.account, deadline)?
        .ok_or(Error::Denied)?;
    if eligible.epoch != grant.epoch || contact_digest(&eligible, now)? != grant.contact_digest {
        return Err(Error::Denied);
    }
    before(deadline)
}

#[cfg(test)]
#[path = "access_recovery_tests.rs"]
mod tests;
