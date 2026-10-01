//! Fresh authenticated, account-bound public binding changes. Passwords and
//! factor codes have no Debug/serialization/persistence representation here.
use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationService, PrimaryCredentialBackend,
    PublicFailureReason, RequiredSecondFactor, SecondFactorService, SecondFactorVerifier,
};
use crate::identity::CanonicalUsername;
use crate::logging::LogEvent;
use crate::openpgp_bindings::{
    AccountBinding, BindingError, BindingRecord, BindingStore, ProtectionPolicy, RecipientBinding,
    Requirement, Update,
};
use crate::openpgp_inventory::Inventory;
use crate::session::ValidatedSession;

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
}
impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "Key management is unavailable. No change was confirmed.",
            Self::Invalid => "Review the full fingerprints, address and current revision.",
            Self::Authentication => "Fresh password and authenticator verification failed. No change was made.",
            Self::Throttled => "Wait before trying fresh verification again. No change was made.",
            Self::Stale => "The key bindings changed. Reload this page before changing them.",
            Self::InvalidKey => "The selected public key is missing, expired, revoked, ambiguous or unsupported.",
            Self::KeyInUse => "Remove this key’s account and recipient bindings before removing its public certificate.",
            Self::Unconfirmed => "The change could not be confirmed. Reload and inspect the current state before retrying.",
        }
    }
}

pub struct State {
    pub canonical_username: String,
    pub inventory: Option<Inventory>,
    pub bindings: Option<BindingRecord>,
    pub binding_changes_available: bool,
    pub public_key_changes_available: bool,
}
impl State {
    pub fn unavailable(account: &str) -> Self {
        Self {
            canonical_username: account.into(),
            inventory: None,
            bindings: None,
            binding_changes_available: false,
            public_key_changes_available: false,
        }
    }
}
pub struct StateOutcome {
    pub state: State,
    pub audit_events: Vec<LogEvent>,
}

pub enum Action<'a> {
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
        let outcome = primary.authenticate(context, account.as_str(), credentials.0);
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
    let old = store.load(account).map_err(binding_error)?;
    if old.revision != request.expected_revision {
        return Err(Error::Stale);
    }
    let inventory = backend.read(account)?;
    if inventory.keys().is_none() {
        return Err(Error::Unavailable);
    }
    let mut update = Update {
        account_binding: old.account_binding.clone(),
        recipient_bindings: old.recipient_bindings.clone(),
        policy: old.policy,
    };
    match &request.action {
        Action::ImportPublic {
            certificate,
            expected_primary_fingerprint,
        } => {
            validate_public_certificate(certificate, expected_primary_fingerprint)?;
            // A qualified public-admin protocol must serialize the binding
            // in-use check and inventory mutation before enabling this action.
            return Err(Error::Unavailable);
        }
        Action::RemovePublic {
            primary_fingerprint,
        } => {
            fingerprint(primary_fingerprint)?;
            if key_in_use(&old, primary_fingerprint) {
                return Err(Error::KeyInUse);
            }
            return Err(Error::Unavailable);
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
        .replace_operator(account, request.expected_revision, update, &inventory, now)
        .map_err(binding_error)?;
    Ok(())
}

fn fingerprint(value: &str) -> Result<(), Error> {
    crate::openpgp_crypto::full_fingerprint(value)
        .then_some(())
        .ok_or(Error::Invalid)
}
pub fn validate_public_certificate(bytes: &[u8], expected: &str) -> Result<(), Error> {
    fingerprint(expected)?;
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
    // Native before-write inspection still establishes packet/key contents and
    // exact full fingerprint. Armor labels alone grant no import authority.
    Ok(())
}
fn key_in_use(record: &BindingRecord, primary: &str) -> bool {
    record.account_binding.as_ref().is_some_and(|b| {
        b.primary_fingerprint == primary
            || b.decrypt_primary_fingerprints
                .iter()
                .any(|fp| fp == primary)
    }) || record
        .recipient_bindings
        .iter()
        .any(|b| b.primary_fingerprint == primary)
}
fn binding_error(error: BindingError) -> Error {
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
