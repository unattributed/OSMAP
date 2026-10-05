//! Own-account fresh password-change authorization. No writer, route or activation.
//! Borrowed secrets are carried by one immutable action-bound, move-only permit;
//! they have no Debug, Clone, serialization or persisted representation.
use crate::account_admission::{Admission, EpochAuthority};
use crate::auth::{
    AuthenticationContext, AuthenticationDecision, AuthenticationPolicy, AuthenticationService,
    PrimaryAuthBackendError, PrimaryAuthVerdict, PrimaryCredentialBackend, PublicFailureReason,
    RequiredSecondFactor, SecondFactorService, SecondFactorVerifier,
};
use crate::logging::LogEvent;
use crate::password_change_rate::{Admission as RateAdmission, Store};
use crate::session::ValidatedSession;
use crate::totp::TimeProvider;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Invalid,
    Authentication,
    Throttled,
    Stale,
    Expired,
}
pub struct Request<'a> {
    current: &'a str,
    new: &'a str,
    confirmation: &'a str,
    totp: &'a str,
}
impl<'a> Request<'a> {
    pub fn new(
        current: &'a str,
        new: &'a str,
        confirmation: &'a str,
        totp: &'a str,
    ) -> Result<Self, Error> {
        if current.is_empty()
            || current.len() > 1024
            || current.chars().any(char::is_control)
            || !(15..=128).contains(&new.chars().count())
            || new.len() > 512
            || new.chars().any(char::is_control)
            || new != confirmation
            || current == new
            || totp.len() != 6
            || !totp.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            current,
            new,
            confirmation,
            totp,
        })
    }
}
pub trait EpochPrimaryBackend: PrimaryCredentialBackend {
    fn captured_admission(&self) -> Result<Admission, Error>;
    fn verify_primary_before(
        &self,
        context: &AuthenticationContext,
        account: &str,
        password: &str,
        deadline: std::time::Instant,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        let expired = || PrimaryAuthBackendError {
            backend: "account-helper",
            reason: "account authentication deadline unavailable".into(),
        };
        if std::time::Instant::now() >= deadline {
            return Err(expired());
        }
        let result = self.verify_primary(context, account, password);
        if std::time::Instant::now() >= deadline {
            return Err(expired());
        }
        result
    }
}
struct BorrowedBackend<'a, B>(&'a B, Option<std::time::Instant>);
impl<B: EpochPrimaryBackend> PrimaryCredentialBackend for BorrowedBackend<'_, B> {
    fn verify_primary(
        &self,
        c: &AuthenticationContext,
        account: &str,
        password: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        match self.1 {
            Some(deadline) => self.0.verify_primary_before(c, account, password, deadline),
            None => self.0.verify_primary(c, account, password),
        }
    }
}
pub struct Services<'a, B, F> {
    pub primary: &'a B,
    pub factor: &'a SecondFactorService<F>,
    pub epoch: &'a dyn EpochAuthority,
    pub rate: &'a Store,
    pub clock: &'a dyn TimeProvider,
    pub policy: AuthenticationPolicy,
}
pub struct Attempt<'a> {
    pub context: &'a AuthenticationContext,
    pub session: &'a ValidatedSession,
    pub request: Request<'a>,
}
pub struct Outcome<'a> {
    pub authorization: Result<Prepared<'a>, Error>,
    pub audit_events: Vec<LogEvent>,
}
pub struct Prepared<'a> {
    workflow_deadline: Option<std::time::Instant>,
    request: Request<'a>,
    account: String,
    epoch: u64,
    session_id: String,
    request_id: String,
    source: String,
    issued: u64,
    expires: u64,
    intent_reference: String,
    rate: Store,
}
/// Typed input for a future qualified own-account mutation transport. This is
/// not a database receipt, mutation success or permission to enable a helper.
pub struct Dispatch<'a> {
    workflow_deadline: Option<std::time::Instant>,
    account: String,
    epoch: u64,
    intent_reference: String,
    session_id: String,
    request_id: String,
    source: String,
    issued: u64,
    expires: u64,
    current: &'a str,
    new: &'a str,
    confirmation: &'a str,
}
impl Dispatch<'_> {
    pub(crate) fn workflow_deadline(&self) -> Option<std::time::Instant> {
        self.workflow_deadline
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn intent_reference(&self) -> &str {
        &self.intent_reference
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn current(&self) -> &str {
        self.current
    }
    pub fn new_password(&self) -> &str {
        self.new
    }
    pub fn confirmation(&self) -> &str {
        self.confirmation
    }
}
fn session_epoch(session: &ValidatedSession, now: u64) -> Result<u64, Error> {
    let r = &session.record;
    let epoch = r.account_epoch.ok_or(Error::Stale)?;
    crate::account_admission::valid_account(&r.canonical_username).map_err(|_| Error::Invalid)?;
    if !crate::account_admission::valid_epoch(epoch) || epoch == crate::account_admission::MAX_EPOCH
    {
        return Err(Error::Stale);
    }
    if now == 0
        || now < r.issued_at
        || now >= r.expires_at
        || r.revoked_at.is_some()
        || r.factor != RequiredSecondFactor::Totp
    {
        return Err(Error::Authentication);
    }
    Ok(epoch)
}
fn admit(authority: &dyn EpochAuthority, account: &str, epoch: u64) -> Result<(), Error> {
    authority
        .admit(account, epoch)
        .map_err(|error| match error {
            crate::account_admission::Error::Refused => Error::Stale,
            _ => Error::Unavailable,
        })
}
fn deadline_check(deadline: Option<std::time::Instant>) -> Result<(), Error> {
    if deadline.is_some_and(|value| std::time::Instant::now() >= value) {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn admit_with_deadline(
    authority: &dyn EpochAuthority,
    account: &str,
    epoch: u64,
    deadline: Option<std::time::Instant>,
) -> Result<(), Error> {
    deadline_check(deadline)?;
    match deadline {
        Some(value) => {
            authority
                .admit_before(account, epoch, value)
                .map_err(|error| match error {
                    crate::account_admission::Error::Expired => Error::Expired,
                    crate::account_admission::Error::Refused => Error::Stale,
                    _ => Error::Unavailable,
                })?
        }
        None => admit(authority, account, epoch)?,
    }
    deadline_check(deadline)
}
pub fn prepare<'a, B: EpochPrimaryBackend, F: SecondFactorVerifier>(
    services: Services<'_, B, F>,
    attempt: Attempt<'a>,
) -> Outcome<'a> {
    prepare_internal(services, attempt, None)
}
/// One original workflow budget starts before password/factor preparation. The
/// 300-second wall freshness rule remains a separate unextended constraint.
pub fn prepare_before<'a, B: EpochPrimaryBackend, F: SecondFactorVerifier>(
    services: Services<'_, B, F>,
    attempt: Attempt<'a>,
    original_deadline: std::time::Instant,
) -> Outcome<'a> {
    let now = std::time::Instant::now();
    if original_deadline <= now || original_deadline > now + std::time::Duration::from_secs(60) {
        return Outcome {
            authorization: Err(Error::Expired),
            audit_events: vec![],
        };
    }
    prepare_internal(services, attempt, Some(original_deadline))
}
fn prepare_internal<'a, B: EpochPrimaryBackend, F: SecondFactorVerifier>(
    services: Services<'_, B, F>,
    attempt: Attempt<'a>,
    deadline: Option<std::time::Instant>,
) -> Outcome<'a> {
    let mut events = Vec::new();
    let result = (|| {
        deadline_check(deadline)?;
        let began = services.clock.unix_timestamp();
        deadline_check(deadline)?;
        let epoch = session_epoch(attempt.session, began)?;
        let account = &attempt.session.record.canonical_username;
        admit_with_deadline(services.epoch, account, epoch, deadline)?;
        deadline_check(deadline)?;
        let guard = services
            .rate
            .admit(account, &attempt.context.remote_addr, began)?;
        deadline_check(deadline)?;
        let primary = AuthenticationService::new(
            services.policy,
            BorrowedBackend(services.primary, deadline),
        )
        .authenticate(attempt.context, account, attempt.request.current);
        events.push(primary.audit_event);
        let primary_result = match primary.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor: RequiredSecondFactor::Totp,
            } if canonical_username == *account => Ok(()),
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::TemporarilyUnavailable,
            } => Err(Error::Unavailable),
            _ => Err(Error::Authentication),
        };
        if let Err(error) = primary_result {
            return failed(guard, error, services.clock, deadline);
        }
        deadline_check(deadline)?;
        let captured = services.primary.captured_admission()?;
        deadline_check(deadline)?;
        if captured.account != *account || captured.epoch != epoch {
            return Err(Error::Stale);
        }
        let factor = services.factor.verify(
            attempt.context,
            account,
            RequiredSecondFactor::Totp,
            attempt.request.totp,
        );
        events.push(factor.audit_event);
        match factor.decision {
            AuthenticationDecision::AuthenticatedPendingSession { canonical_username }
                if canonical_username == *account => {}
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::TemporarilyUnavailable,
            } => return Err(Error::Unavailable),
            _ => return failed(guard, Error::Authentication, services.clock, deadline),
        }
        deadline_check(deadline)?;
        let now = services.clock.unix_timestamp();
        deadline_check(deadline)?;
        if now < began
            || began.checked_add(300).is_none_or(|expires| now >= expires)
            || session_epoch(attempt.session, now)? != epoch
        {
            return Err(Error::Expired);
        }
        admit_with_deadline(services.epoch, account, epoch, deadline)?;
        deadline_check(deadline)?;
        guard.confirm()?;
        deadline_check(deadline)?;
        let final_now = services.clock.unix_timestamp();
        deadline_check(deadline)?;
        if final_now < now
            || began
                .checked_add(300)
                .is_none_or(|expires| final_now >= expires)
            || session_epoch(attempt.session, final_now)? != epoch
        {
            return Err(Error::Expired);
        }
        // Verification time belongs to the original freshness budget; a slow
        // authority or private publication check never starts a second window.
        let expires = began.checked_add(300).ok_or(Error::Unavailable)?;
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        deadline_check(deadline)?;
        let prepared = Prepared {
            workflow_deadline: deadline,
            request: attempt.request,
            account: account.clone(),
            epoch,
            session_id: attempt.session.record.session_id.clone(),
            request_id: attempt.context.request_id.clone(),
            source: attempt.context.remote_addr.clone(),
            issued: began,
            expires,
            intent_reference: nonce.iter().map(|b| format!("{b:02x}")).collect(),
            rate: services.rate.clone(),
        };
        deadline_check(deadline)?;
        Ok(prepared)
    })();
    Outcome {
        authorization: result,
        audit_events: events,
    }
}
fn failed<'a>(
    guard: RateAdmission,
    error: Error,
    clock: &dyn TimeProvider,
    deadline: Option<std::time::Instant>,
) -> Result<Prepared<'a>, Error> {
    if error != Error::Authentication {
        deadline_check(deadline)?;
        return Err(error);
    }
    // A confirmed authentication rejection remains a durable failure even if
    // a callback exhausted the workflow. Deadline expiry never resets history.
    let now = clock.unix_timestamp();
    let exhausted = deadline_check(deadline).is_err();
    let throttled = guard.failed(now)?;
    deadline_check(deadline)?;
    if exhausted {
        return Err(Error::Expired);
    }
    Err(if throttled {
        Error::Throttled
    } else {
        Error::Authentication
    })
}
impl<'a> Prepared<'a> {
    pub(crate) fn bound_workflow_deadline(
        &self,
        supplied: std::time::Instant,
    ) -> std::time::Instant {
        self.workflow_deadline
            .map(|original| supplied.min(original))
            .unwrap_or(supplied)
    }
    /// Rechecks the authoritative account epoch and the supplied session record.
    /// A future mutation caller MUST revalidate the session from its durable
    /// SessionStore immediately before consumption; this borrowed snapshot does
    /// not detect an independent stored-session revocation. No current route or
    /// writer consumes this prerequisite.
    pub fn into_dispatch(
        self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        epoch: &dyn EpochAuthority,
        clock: &dyn TimeProvider,
    ) -> Result<Dispatch<'a>, Error> {
        deadline_check(self.workflow_deadline)?;
        let now = clock.unix_timestamp();
        deadline_check(self.workflow_deadline)?;
        if now < self.issued || now >= self.expires {
            return Err(Error::Expired);
        }
        if self.account != session.record.canonical_username
            || self.session_id != session.record.session_id
            || self.request_id != context.request_id
            || self.source != context.remote_addr
            || session_epoch(session, now)? != self.epoch
        {
            return Err(Error::Stale);
        }
        admit_with_deadline(epoch, &self.account, self.epoch, self.workflow_deadline)?;
        self.rate.healthy()?;
        deadline_check(self.workflow_deadline)?;
        let final_now = clock.unix_timestamp();
        deadline_check(self.workflow_deadline)?;
        if final_now < now || final_now >= self.expires {
            return Err(Error::Expired);
        }
        if session_epoch(session, final_now)? != self.epoch {
            return Err(Error::Stale);
        }
        Ok(Dispatch {
            workflow_deadline: self.workflow_deadline,
            account: self.account,
            epoch: self.epoch,
            intent_reference: self.intent_reference,
            session_id: self.session_id,
            request_id: self.request_id,
            source: self.source,
            issued: self.issued,
            expires: self.expires,
            current: self.request.current,
            new: self.request.new,
            confirmation: self.request.confirmation,
        })
    }
}
