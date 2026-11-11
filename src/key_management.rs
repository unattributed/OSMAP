//! Fresh authenticated, account-bound public binding changes. Passwords and
//! factor codes have no Debug/serialization/persistence representation here.
use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationOutcome, AuthenticationService,
    PrimaryCredentialBackend, PublicFailureReason, RequiredSecondFactor, SecondFactorService,
    SecondFactorVerifier,
};
use crate::identity::CanonicalUsername;
use crate::logging::LogEvent;
use crate::openpgp_bindings::{
    AccountBinding, BindingError, BindingRecord, BindingStore, ProtectionPolicy, RecipientBinding,
    Requirement, Update,
};
use crate::openpgp_inventory::Inventory;
use crate::session::ValidatedSession;
use sha1::{Digest, Sha1};
use std::borrow::Cow;

pub const MAX_PUBLIC_CERTIFICATE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Invalid,
    Authentication,
    Throttled,
    Stale,
    InvalidKey,
    KeyInUse,
    Unconfirmed,
    PersonalLocked,
    PersonalConflict,
    PersonalInvalid,
}
impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "Key management is unavailable. No change was confirmed.",
            Self::Invalid => "Review the full fingerprints, address and current revision.",
            Self::Authentication => "Fresh password and authenticator verification failed. No change was made.",
            Self::Throttled => "Wait before trying fresh verification again. No change was made.",
            Self::Stale => "The key inventory or bindings changed. Reload this page before changing them.",
            Self::InvalidKey => "The selected public key is missing, expired, revoked, ambiguous or unsupported.",
            Self::KeyInUse => "Remove this key’s account and recipient bindings before changing its public certificate.",
            Self::Unconfirmed => "The change could not be confirmed. Reload and inspect the current state before retrying.",
            Self::PersonalLocked => "The personal key could not be unlocked. Check its key passphrase. Nothing was sent.",
            Self::PersonalConflict => "A personal private key is already stored for this account. Use Unlock; importing will not replace it.",
            Self::PersonalInvalid => "The personal key or passphrase could not be accepted. Choose the matching private .asc file for your configured account key; other keys and key replacement are not accepted here.",
        }
    }
}

pub struct State {
    pub canonical_username: String,
    pub inventory: Option<Inventory>,
    pub bindings: Option<BindingRecord>,
    pub binding_changes_available: bool,
    pub public_key_changes_available: bool,
    /// Revision of the same native public-keybox snapshot shown on this page.
    /// Public import/removal must compare it inside the helper transaction.
    pub public_inventory_revision: Option<String>,
}
impl State {
    pub fn unavailable(account: &str) -> Self {
        Self {
            canonical_username: account.into(),
            inventory: None,
            bindings: None,
            binding_changes_available: false,
            public_key_changes_available: false,
            public_inventory_revision: None,
        }
    }
}
pub struct StateOutcome {
    pub state: State,
    pub audit_events: Vec<LogEvent>,
}

pub enum Action<'a> {
    ImportPersonal {
        certificate: &'a [u8],
        passphrase: &'a [u8],
    },
    UnlockPersonal {
        passphrase: &'a [u8],
    },
    LockPersonal,
    ImportPublic {
        certificate: &'a [u8],
        expected_primary_fingerprint: &'a str,
    },
    RemovePublic {
        primary_fingerprint: &'a str,
    },
    SetAccount {
        primary_fingerprint: &'a str,
        signing_fingerprint: Option<&'a str>,
        decrypt_fingerprints: &'a str,
    },
    ClearAccount,
    ClearAllBindings,
    SetRecipient {
        address: &'a str,
        primary_fingerprint: &'a str,
        encryption: Requirement,
    },
    RemoveRecipient {
        address: &'a str,
    },
    SetPolicy {
        signing: Requirement,
        encryption: Requirement,
    },
}
pub struct MutationRequest<'a> {
    pub action: Action<'a>,
    pub expected_revision: u64,
    pub expected_public_revision: Option<&'a str>,
    pub password: &'a str,
    pub totp: &'a str,
}
pub struct MutationOutcome {
    pub result: Result<(), Error>,
    pub audit_events: Vec<LogEvent>,
}

/// Constructed only by actual primary and replay-protected second-factor
/// verification. Owned and not Clone, Debug or serializable; consumed once.
pub struct FreshAuthorization {
    account: CanonicalUsername,
    session_id: String,
    request_id: String,
    verified_at: u64,
}
pub struct StepUpOutcome {
    pub authorization: Result<FreshAuthorization, Error>,
    pub audit_events: Vec<LogEvent>,
}
pub fn verify_fresh<P: PrimaryCredentialBackend, F: SecondFactorVerifier>(
    primary: &AuthenticationService<P>,
    factor: &SecondFactorService<F>,
    context: &AuthenticationContext,
    session: &ValidatedSession,
    credentials: (&str, &str),
    now: u64,
) -> StepUpOutcome {
    verify_fresh_with_primary(
        |context, account, password| (primary.authenticate(context, account, password), Ok(())),
        factor,
        context,
        session,
        credentials,
        now,
    )
}

/// Reuses the caller's actual primary-credential route while retaining the
/// account/session checks and fresh second-factor verification here. The
/// additional constraint binds selected primary admission to the session epoch.
pub(crate) fn verify_fresh_with_primary<F: SecondFactorVerifier>(
    primary: impl FnOnce(
        &AuthenticationContext,
        &str,
        &str,
    ) -> (AuthenticationOutcome, Result<(), Error>),
    factor: &SecondFactorService<F>,
    context: &AuthenticationContext,
    session: &ValidatedSession,
    credentials: (&str, &str),
    now: u64,
) -> StepUpOutcome {
    let mut events = Vec::new();
    let result = (|| {
        let account = CanonicalUsername::parse(&session.record.canonical_username)
            .map_err(|_| Error::Invalid)?;
        if now == 0
            || now >= session.record.expires_at
            || now < session.record.issued_at
            || session.record.revoked_at.is_some()
            || session.record.factor != RequiredSecondFactor::Totp
        {
            return Err(Error::Authentication);
        }
        let (outcome, constraint) = primary(context, account.as_str(), credentials.0);
        events.push(outcome.audit_event);
        if matches!(
            outcome.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::TemporarilyUnavailable
            }
        ) {
            return Err(Error::Unavailable);
        }
        let AuthenticationDecision::MfaRequired {
            canonical_username,
            second_factor: RequiredSecondFactor::Totp,
        } = outcome.decision
        else {
            return Err(Error::Authentication);
        };
        if canonical_username != account.as_str() {
            return Err(Error::Authentication);
        }
        constraint?;
        let outcome = factor.verify(
            context,
            account.as_str(),
            RequiredSecondFactor::Totp,
            credentials.1,
        );
        events.push(outcome.audit_event);
        if matches!(
            outcome.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::TemporarilyUnavailable
            }
        ) {
            return Err(Error::Unavailable);
        }
        if !matches!(outcome.decision, AuthenticationDecision::AuthenticatedPendingSession { ref canonical_username }
            if canonical_username == account.as_str())
        {
            return Err(Error::Authentication);
        }
        Ok(FreshAuthorization {
            account,
            session_id: session.record.session_id.clone(),
            request_id: context.request_id.clone(),
            verified_at: now,
        })
    })();
    StepUpOutcome {
        authorization: result,
        audit_events: events,
    }
}

pub trait PublicKeyBackend {
    fn read(&self, account: &str) -> Result<Inventory, Error>;
    fn import_public(
        &self,
        _account: &str,
        _expected_public_revision: &str,
        _primary_fingerprint: &str,
        _certificate: &[u8],
    ) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
    fn remove_public(
        &self,
        _account: &str,
        _expected_public_revision: &str,
        _primary_fingerprint: &str,
    ) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
}

pub fn mutate<B: PublicKeyBackend>(
    backend: &B,
    store: &BindingStore,
    auth: FreshAuthorization,
    context: &AuthenticationContext,
    session: &ValidatedSession,
    request: &MutationRequest<'_>,
    now: u64,
) -> Result<(), Error> {
    if auth.account.as_str() != session.record.canonical_username
        || auth.session_id != session.record.session_id
        || auth.request_id != context.request_id
        || now < auth.verified_at
        || now - auth.verified_at > 60
        || now >= session.record.expires_at
        || session.record.revoked_at.is_some()
    {
        return Err(Error::Authentication);
    }
    let account = auth.account.as_str();
    // Public keybox writes use a second, page-load CAS token and hold the same
    // account lock as binding writers through the native helper RPC. The helper
    // independently CAS-checks the actual keybox and confirms its result.
    match &request.action {
        Action::ImportPublic {
            certificate,
            expected_primary_fingerprint,
        } => {
            let (certificate, primary_fingerprint) =
                normalized_public_certificate(certificate, expected_primary_fingerprint)?;
            let public_revision = public_revision(request.expected_public_revision)?;
            return store
                .with_locked_revision(account, request.expected_revision, |record| {
                    Ok(if key_in_use(record, primary_fingerprint.as_ref()) {
                        Err(Error::KeyInUse)
                    } else {
                        backend.import_public(
                            account,
                            public_revision,
                            primary_fingerprint.as_ref(),
                            certificate,
                        )
                    })
                })
                .map_err(binding_error)?;
        }
        Action::RemovePublic {
            primary_fingerprint,
        } => {
            fingerprint(primary_fingerprint)?;
            let public_revision = public_revision(request.expected_public_revision)?;
            return store
                .with_locked_revision(account, request.expected_revision, |record| {
                    Ok(if key_in_use(record, primary_fingerprint) {
                        Err(Error::KeyInUse)
                    } else {
                        backend.remove_public(account, public_revision, primary_fingerprint)
                    })
                })
                .map_err(binding_error)?;
        }
        _ => {}
    }
    let old = store.load(account).map_err(binding_error)?;
    if old.revision != request.expected_revision {
        return Err(Error::Stale);
    }
    let mut update = Update {
        account_binding: old.account_binding.clone(),
        recipient_bindings: old.recipient_bindings.clone(),
        policy: old.policy,
    };
    match &request.action {
        Action::ImportPublic { .. } | Action::RemovePublic { .. } => unreachable!(),
        Action::ImportPersonal { .. } | Action::UnlockPersonal { .. } | Action::LockPersonal => {
            return Err(Error::Invalid);
        }
        Action::SetAccount {
            primary_fingerprint,
            signing_fingerprint,
            decrypt_fingerprints,
        } => {
            fingerprint(primary_fingerprint)?;
            let signing = signing_fingerprint
                .map(|f| fingerprint(f).map(|()| f.to_owned()))
                .transpose()?;
            let decrypt = decrypt_fingerprints
                .split(',')
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(|f| fingerprint(f).map(|()| f.to_owned()))
                .collect::<Result<Vec<_>, _>>()?;
            if decrypt.len() > 8 {
                return Err(Error::Invalid);
            }
            update.account_binding = Some(AccountBinding {
                primary_fingerprint: (*primary_fingerprint).into(),
                signing_fingerprint: signing,
                decrypt_primary_fingerprints: decrypt,
            });
        }
        Action::ClearAccount => update.account_binding = None,
        Action::ClearAllBindings => {
            update.account_binding = None;
            update.recipient_bindings.clear();
        }
        Action::SetRecipient {
            address,
            primary_fingerprint,
            encryption,
        } => {
            crate::identity::MailboxIdentity::parse(*address).map_err(|_| Error::Invalid)?;
            fingerprint(primary_fingerprint)?;
            let compare = crate::mail_address::comparison_key(address);
            update
                .recipient_bindings
                .retain(|b| crate::mail_address::comparison_key(&b.address) != compare);
            update.recipient_bindings.push(RecipientBinding {
                address: (*address).into(),
                primary_fingerprint: (*primary_fingerprint).into(),
                encryption: *encryption,
            });
        }
        Action::RemoveRecipient { address } => {
            crate::identity::MailboxIdentity::parse(*address).map_err(|_| Error::Invalid)?;
            let compare = crate::mail_address::comparison_key(address);
            let original = update.recipient_bindings.len();
            update
                .recipient_bindings
                .retain(|b| crate::mail_address::comparison_key(&b.address) != compare);
            if original == update.recipient_bindings.len() {
                return Err(Error::Invalid);
            }
        }
        Action::SetPolicy {
            signing,
            encryption,
        } => {
            update.policy = ProtectionPolicy {
                signing: *signing,
                encryption: *encryption,
            }
        }
    }
    store
        .replace_operator_with_inventory(
            account,
            request.expected_revision,
            update,
            || {
                let inventory = backend.read(account).map_err(|error| match error {
                    Error::Stale => BindingError::Stale,
                    Error::Unconfirmed => BindingError::Unconfirmed,
                    _ => BindingError::Unavailable,
                })?;
                if let Action::SetRecipient {
                    address,
                    primary_fingerprint,
                    ..
                } = &request.action
                {
                    let compare = crate::mail_address::comparison_key(address);
                    let saved_pair = old.recipient_bindings.iter().any(|binding| {
                        crate::mail_address::comparison_key(&binding.address) == compare
                            && binding.primary_fingerprint == *primary_fingerprint
                    });
                    let certificate_pair = inventory.keys().is_some_and(|keys| {
                        keys.iter().any(|key| {
                            key.primary.fingerprint == *primary_fingerprint
                                && key.email_addresses.iter().any(|email| {
                                    crate::mail_address::comparison_key(email) == compare
                                })
                        })
                    });
                    if !saved_pair && !certificate_pair {
                        return Err(BindingError::InvalidKey);
                    }
                }
                Ok(inventory)
            },
            now,
        )
        .map_err(binding_error)?;
    Ok(())
}

fn fingerprint(value: &str) -> Result<(), Error> {
    crate::openpgp_crypto::full_fingerprint(value)
        .then_some(())
        .ok_or(Error::Invalid)
}
fn public_revision(value: Option<&str>) -> Result<&str, Error> {
    let value = value.ok_or(Error::Invalid)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Invalid);
    }
    Ok(value)
}
pub fn validate_public_certificate(bytes: &[u8], expected: &str) -> Result<(), Error> {
    normalized_public_certificate(bytes, expected).map(|_| ())
}
fn normalized_public_certificate<'a>(
    bytes: &'a [u8],
    expected: &'a str,
) -> Result<(&'a [u8], Cow<'a, str>), Error> {
    if !expected.is_empty() {
        fingerprint(expected)?;
    }
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC_CERTIFICATE || !bytes.is_ascii() {
        return Err(Error::Invalid);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Invalid)?
        .trim();
    if !text.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        || !text.ends_with("-----END PGP PUBLIC KEY BLOCK-----")
        || text.contains("PRIVATE KEY")
        || text.contains("SECRET KEY")
    {
        return Err(Error::Invalid);
    }
    let primary = if expected.is_empty() {
        Cow::Owned(derived_public_fingerprint(text)?)
    } else {
        Cow::Borrowed(expected)
    };
    // Native before-write inspection remains the authority for the complete
    // certificate and exact fingerprint. Derivation supplies an identifier,
    // never key validity, trust or permission to bypass that inspection.
    // Forward the same armor representation that passed these checks. The
    // native helper requires BEGIN at byte zero; preserve all interior bytes.
    Ok((text.as_bytes(), primary))
}

/// Extract a bounded v4 public-key identity, without replacing native certificate
/// validation. Only the blank expected-fingerprint path uses this parser.
fn derived_public_fingerprint(armor: &str) -> Result<String, Error> {
    let mut lines = armor.lines();
    if lines.next().map(str::trim_end) != Some("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        return Err(Error::Invalid);
    }
    let mut separated = false;
    for line in lines.by_ref() {
        if line.trim().is_empty() {
            separated = true;
            break;
        }
        let Some((name, value)) = line.split_once(": ") else {
            return Err(Error::Invalid);
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(Error::Invalid);
        }
    }
    if !separated {
        return Err(Error::Invalid);
    }
    let mut encoded = String::new();
    let mut checksum = false;
    let mut ended = false;
    for line in lines.by_ref() {
        let line = line.trim();
        if line == "-----END PGP PUBLIC KEY BLOCK-----" {
            ended = true;
            break;
        }
        if line.is_empty() {
            continue;
        }
        if checksum {
            return Err(Error::Invalid);
        }
        // RFC 9580 §6.1 makes the CRC24 footer optional and forbids rejecting
        // solely for a malformed/mismatched CRC. It supplies no key authority.
        if line.starts_with('=') && encoded.len() % 4 == 0 {
            checksum = true;
            continue;
        }
        encoded.extend(
            line.bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .map(char::from),
        );
    }
    if !ended || lines.any(|line| !line.trim().is_empty()) || encoded.is_empty() {
        return Err(Error::Invalid);
    }
    let value = |byte| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    // The attachment decoder is reused only after canonical padding admission:
    // no interior padding and no non-zero unused bits in the final quantum.
    if encoded.len() % 4 != 0 {
        return Err(Error::Invalid);
    }
    for (index, chunk) in encoded.as_bytes().chunks_exact(4).enumerate() {
        let second = value(chunk[1]).ok_or(Error::Invalid)?;
        value(chunk[0]).ok_or(Error::Invalid)?;
        let last = (index + 1) * 4 == encoded.len();
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || second & 15 != 0 {
                return Err(Error::Invalid);
            }
        } else {
            let third = value(chunk[2]).ok_or(Error::Invalid)?;
            if chunk[3] == b'=' {
                if !last || third & 3 != 0 {
                    return Err(Error::Invalid);
                }
            } else {
                value(chunk[3]).ok_or(Error::Invalid)?;
            }
        }
    }
    let mut decoded = crate::attachment::decode_base64_bytes(&encoded, MAX_PUBLIC_CERTIFICATE)
        .map_err(|_| Error::Invalid)?;
    let result = public_packet_fingerprint(&decoded);
    // A falsely labelled public upload can contain a secret-key packet. Clear
    // every decoded request-local byte on success and all packet refusals.
    crate::openpgp_personal::clear(&mut decoded);
    result
}

fn public_packet_fingerprint(packets: &[u8]) -> Result<String, Error> {
    fn take<'a>(bytes: &'a [u8], cursor: &mut usize, count: usize) -> Result<&'a [u8], Error> {
        let end = cursor.checked_add(count).ok_or(Error::Invalid)?;
        let value = bytes.get(*cursor..end).ok_or(Error::Invalid)?;
        *cursor = end;
        Ok(value)
    }
    fn scalar(bytes: &[u8]) -> Result<usize, Error> {
        bytes.iter().try_fold(0usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(Error::Invalid)
        })
    }
    let mut cursor = 0;
    let mut primary = None;
    while cursor < packets.len() {
        let header = take(packets, &mut cursor, 1)?[0];
        if header & 0x80 == 0 {
            return Err(Error::Invalid);
        }
        let tag = if header & 0x40 != 0 {
            header & 0x3f
        } else {
            (header >> 2) & 0x0f
        };
        if matches!(tag, 5 | 7) {
            return Err(Error::Invalid);
        }
        let length = if header & 0x40 != 0 {
            match take(packets, &mut cursor, 1)?[0] {
                first @ 0..=191 => usize::from(first),
                first @ 192..=223 => {
                    ((usize::from(first) - 192) << 8)
                        + usize::from(take(packets, &mut cursor, 1)?[0])
                        + 192
                }
                255 => scalar(take(packets, &mut cursor, 4)?)?,
                _ => return Err(Error::Invalid),
            }
        } else {
            let count = match header & 3 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(Error::Invalid),
            };
            scalar(take(packets, &mut cursor, count)?)?
        };
        let body = take(packets, &mut cursor, length)?;
        if tag == 6 {
            if primary.is_some() || body.len() < 6 || body[0] != 4 {
                return Err(Error::Invalid);
            }
            primary = Some(body);
        }
    }
    let primary = primary.ok_or(Error::Invalid)?;
    let length = u16::try_from(primary.len()).map_err(|_| Error::Invalid)?;
    // RFC 9580 §5.5.4.2: v4 identity hashes the entire Public-Key body,
    // prefixed by 0x99 and its two-byte big-endian length.
    let mut digest = Sha1::new();
    digest.update([0x99]);
    digest.update(length.to_be_bytes());
    digest.update(primary);
    Ok(format!("{:X}", digest.finalize()))
}
fn key_in_use(record: &BindingRecord, primary: &str) -> bool {
    record.account_binding.as_ref().is_some_and(|b| {
        b.primary_fingerprint == primary
            || b.signing_fingerprint.as_deref() == Some(primary)
            || b.decrypt_primary_fingerprints
                .iter()
                .any(|fp| fp == primary)
    }) || record
        .recipient_bindings
        .iter()
        .any(|b| b.primary_fingerprint == primary)
}
pub(crate) fn binding_error(error: BindingError) -> Error {
    match error {
        BindingError::Stale => Error::Stale,
        BindingError::InvalidKey => Error::InvalidKey,
        BindingError::Unconfirmed => Error::Unconfirmed,
        BindingError::Invalid
        | BindingError::Duplicate
        | BindingError::ForeignAccount
        | BindingError::Quota => Error::Invalid,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
#[path = "key_management_tests.rs"]
mod tests;
