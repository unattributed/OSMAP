use super::*;
use crate::password_change::{self, Attempt, EpochPrimaryBackend, Outcome, Request, Services};
use crate::totp::TimeProvider as _;

pub(crate) type PasswordCompletion = (crate::session::BrowserRevocation, Option<String>);

impl EpochPrimaryBackend for crate::account_admission_runtime::CredentialBackend {
    fn captured_admission(
        &self,
    ) -> Result<crate::account_admission::Admission, password_change::Error> {
        self.captured
            .try_lock()
            .ok()
            .and_then(|v| v.clone())
            .ok_or(password_change::Error::Unavailable)
    }
    fn verify_primary_before(
        &self,
        _: &AuthenticationContext,
        account: &str,
        password: &str,
        deadline: std::time::Instant,
    ) -> Result<crate::auth::PrimaryAuthVerdict, crate::auth::PrimaryAuthBackendError> {
        let denied = || crate::auth::PrimaryAuthBackendError {
            backend: "account-helper",
            reason: "account authentication unavailable".into(),
        };
        let admission = self
            .client
            .authenticate_before(account, password, deadline)
            .map_err(|_| denied())?;
        if std::time::Instant::now() >= deadline {
            return Err(denied());
        }
        let verdict = match &admission {
            Some(value) => crate::auth::PrimaryAuthVerdict::Accept {
                canonical_username: value.account.clone(),
            },
            None => crate::auth::PrimaryAuthVerdict::Reject,
        };
        *self.captured.try_lock().map_err(|_| denied())? = admission;
        if std::time::Instant::now() >= deadline {
            return Err(denied());
        }
        Ok(verdict)
    }
}
const PASSWORD_RESULT_TTL: u64 = 900;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordResultRecord {
    version: u8,
    account: String,
    session: String,
    created: u64,
    expires: u64,
    confirmed: bool,
    changed_at: Option<String>,
}
fn valid_result_capability(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl PasswordResultRecord {
    fn valid(&self, now: u64) -> bool {
        self.version == 1
            && !self.account.is_empty()
            && !self.session.is_empty()
            && self.expires.checked_sub(self.created) == Some(PASSWORD_RESULT_TTL)
            && self.created <= now
            && now < self.expires
            && self
                .changed_at
                .as_deref()
                .is_none_or(crate::account_mutation::changed_at_valid)
            && (!self.confirmed || self.changed_at.is_some())
    }
    fn matches(&self, session: &ValidatedSession) -> bool {
        self.account == session.record.canonical_username
            && self.session == session.record.session_id
    }
}

impl RuntimeBrowserGateway {
    fn password_result_store(&self) -> crate::private_account_file::PrivateAccountFile {
        crate::private_account_file::PrivateAccountFile::new(
            self.settings_dir.join("password-results"),
            "osmap-password-result-v1",
            2048,
        )
    }
    pub(super) fn begin_password_result_record(
        &self,
        session: &ValidatedSession,
        existing: Option<&str>,
    ) -> Result<Option<String>, BrowserPasswordResultError> {
        let now = SystemTimeProvider.unix_timestamp();
        let store = self.password_result_store();
        if let Some(capability) = existing.filter(|v| valid_result_capability(v)) {
            let prior = store
                .read(capability)
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_slice::<PasswordResultRecord>(&b).ok());
            if prior.is_some_and(|record| record.valid(now) && record.matches(session)) {
                return Ok(Some(capability.into()));
            }
        }
        // One purpose-separated result capability per existing session. Repeated
        // form loads cannot allocate unbounded records. The CSRF secret never
        // enters the record, URL, logs or the result body.
        use hmac::{Hmac, Mac as _};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(session.record.csrf_token.as_bytes())
            .map_err(|_| BrowserPasswordResultError::Unavailable)?;
        mac.update(b"osmap-password-result-v1\0");
        mac.update(session.record.canonical_username.as_bytes());
        mac.update(b"\0");
        mac.update(session.record.session_id.as_bytes());
        let capability: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let record = PasswordResultRecord {
            version: 1,
            account: session.record.canonical_username.clone(),
            session: session.record.session_id.clone(),
            created: now,
            expires: now
                .checked_add(PASSWORD_RESULT_TTL)
                .ok_or(BrowserPasswordResultError::Unavailable)?,
            confirmed: false,
            changed_at: None,
        };
        let locked = store
            .lock(&capability)
            .map_err(|_| BrowserPasswordResultError::Unavailable)?;
        if let Some(bytes) = locked
            .read()
            .map_err(|_| BrowserPasswordResultError::Unavailable)?
        {
            let prior: PasswordResultRecord = serde_json::from_slice(&bytes)
                .map_err(|_| BrowserPasswordResultError::Unavailable)?;
            if !prior.matches(session) {
                return Err(BrowserPasswordResultError::Unavailable);
            }
            if prior.valid(now) {
                return Ok(Some(capability));
            }
            if prior.expires > now {
                return Err(BrowserPasswordResultError::Unavailable);
            }
        }
        let bytes =
            serde_json::to_vec(&record).map_err(|_| BrowserPasswordResultError::Unavailable)?;
        locked
            .write(&bytes)
            .map_err(|_| BrowserPasswordResultError::Unavailable)?;
        Ok(Some(capability))
    }
    pub(super) fn finish_password_result_record(
        &self,
        session: &ValidatedSession,
        capability: &str,
        outcome: &BrowserPasswordOutcome,
    ) -> bool {
        if !valid_result_capability(capability)
            || !matches!(
                outcome.decision,
                BrowserPasswordDecision::Changed | BrowserPasswordDecision::Unconfirmed
            )
        {
            return false;
        }
        let store = self.password_result_store();
        let Ok(locked) = store.lock(capability) else {
            return false;
        };
        let Some(mut record) = locked
            .read()
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<PasswordResultRecord>(&b).ok())
        else {
            return false;
        };
        if !record.valid(SystemTimeProvider.unix_timestamp()) || !record.matches(session) {
            return false;
        }
        // One credential operation can complete for this session epoch. A late
        // uncertain response from another in-flight request cannot erase or
        // downgrade already verified timing/effects for that operation.
        if let Some(known) = &record.changed_at {
            return outcome
                .changed_at
                .as_ref()
                .is_none_or(|later| later == known);
        }
        record.changed_at = outcome
            .changed_at
            .as_deref()
            .filter(|v| crate::account_mutation::changed_at_valid(v))
            .map(str::to_owned);
        record.confirmed =
            outcome.decision == BrowserPasswordDecision::Changed && record.changed_at.is_some();
        serde_json::to_vec(&record)
            .ok()
            .is_some_and(|bytes| locked.write(&bytes).is_ok())
    }
    pub(super) fn read_password_result_record(
        &self,
        capability: &str,
    ) -> Option<BrowserPasswordResult> {
        if !valid_result_capability(capability) {
            return None;
        }
        let bytes = self.password_result_store().read(capability).ok()??;
        let record: PasswordResultRecord = serde_json::from_slice(&bytes).ok()?;
        record
            .valid(SystemTimeProvider.unix_timestamp())
            .then_some(BrowserPasswordResult {
                confirmed: record.confirmed,
                changed_at: record.changed_at,
            })
    }

    pub(super) fn change_own_password_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        token: &SessionToken,
        request: Request<'_>,
        deadline: std::time::Instant,
    ) -> BrowserPasswordOutcome {
        let prepared = self.prepare_password_change_before(context, session, request, deadline);
        let (decision, changed_at) = match prepared.authorization {
            Err(error) => (BrowserPasswordDecision::PrewriteRefused(error), None),
            Ok(permit) => {
                let completion =
                    self.with_password_change_completion_status(context, token, permit, deadline);
                self.finish_password_change_completion(session, completion, deadline)
            }
        };
        BrowserPasswordOutcome {
            decision,
            changed_at,
            audit_events: prepared.audit_events,
        }
    }
    /// Classify the actual cleanup result without discarding verified write
    /// timing. Success still requires matching persisted timing at the new
    /// epoch, read through the paired authority under the original deadline.
    pub(crate) fn finish_password_change_completion(
        &self,
        session: &ValidatedSession,
        completion: Result<PasswordCompletion, password_change::Error>,
        deadline: std::time::Instant,
    ) -> (BrowserPasswordDecision, Option<String>) {
        use crate::session::BrowserRevocation;
        match completion {
            Ok((BrowserRevocation::OldSessionsRevoked { .. }, known_at)) => {
                let ready = self.ready_account_runtime(&session.record.canonical_username);
                let readback = session
                    .record
                    .account_epoch
                    .and_then(|epoch| epoch.checked_add(1))
                    .and_then(|epoch| {
                        ready.and_then(|paired| {
                            paired
                                .admission()
                                .password_changed_at_before(
                                    &session.record.canonical_username,
                                    epoch,
                                    deadline,
                                )
                                .ok()
                                .flatten()
                        })
                    });
                if known_at.is_some() && readback == known_at {
                    (BrowserPasswordDecision::Changed, known_at)
                } else {
                    if let Some(paired) = ready {
                        paired
                            .mutation()
                            .quarantine_account(&session.record.canonical_username);
                    }
                    (BrowserPasswordDecision::Unconfirmed, known_at)
                }
            }
            Ok((BrowserRevocation::KnownRefused, _)) => {
                (BrowserPasswordDecision::KnownRefused, None)
            }
            Ok((BrowserRevocation::ChangedIncomplete { changed_at, .. }, _)) => {
                (BrowserPasswordDecision::Unconfirmed, Some(changed_at))
            }
            Ok((BrowserRevocation::Contained { .. }, known_at)) => {
                (BrowserPasswordDecision::Unconfirmed, known_at)
            }
            Err(_) => (BrowserPasswordDecision::Unconfirmed, None),
        }
    }
    /// The trusted caller's eventual mutation RPC must run in this callback.
    /// Ordinary session validation/revocation may run only after it returns;
    /// reentering the held global session lock from the callback would deadlock.
    /// No current browser route, writer or helper activation uses this method.
    pub fn with_password_change_dispatch<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        dispatch: impl FnOnce(password_change::Dispatch<'a>) -> Result<(), password_change::Error>,
    ) -> Result<(), password_change::Error> {
        let Some(ready) = self.account_runtime.ready() else {
            return Err(password_change::Error::Unavailable);
        };
        let client = ready.admission();
        self.password_dispatch_guarded(
            context,
            token,
            prepared,
            (std::sync::Arc::new(client.clone()), &SystemTimeProvider),
            dispatch,
        )
    }
    /// Backend completion seam only: no route/form activates this workflow.
    /// The same original deadline must begin before preparation. A verified
    /// mutation receipt establishes only its stated outcome; this return type
    /// describes browser cleanup, not full native mail containment acceptance.
    pub fn with_password_change_completion<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        original_deadline: std::time::Instant,
    ) -> Result<crate::session::BrowserRevocation, password_change::Error> {
        self.with_password_change_completion_status(context, token, prepared, original_deadline)
            .map(|value| value.0)
    }
    fn with_password_change_completion_status<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        original_deadline: std::time::Instant,
    ) -> Result<PasswordCompletion, password_change::Error> {
        let original_deadline = prepared.bound_workflow_deadline(original_deadline);
        let Some(ready) = self.account_runtime.ready() else {
            return Err(password_change::Error::Unavailable);
        };
        let client = ready.admission();
        let authority = std::sync::Arc::new(DeadlineAuthority {
            client: client.clone(),
            deadline: original_deadline,
        });
        self.password_completion_with_client(
            context,
            token,
            prepared,
            (authority, &SystemTimeProvider),
            ready.mutation(),
            original_deadline,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn password_completion_with_client<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        mutation: &crate::account_mutation_client::Client,
        original_deadline: std::time::Instant,
    ) -> Result<PasswordCompletion, password_change::Error> {
        let original_deadline = prepared.bound_workflow_deadline(original_deadline);
        self.password_completion_guarded(
            context,
            token,
            prepared,
            services,
            original_deadline,
            |dispatch, lease| {
                mutation
                    .execute_stored_continuous(dispatch, lease, original_deadline)
                    .map_err(|_| password_change::Error::Unavailable)
            },
            |account| mutation.quarantine_account(account),
        )
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stored_completion_fixture<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        mutation: &crate::account_mutation_client::Client,
        original_deadline: std::time::Instant,
    ) -> Result<crate::session::BrowserRevocation, password_change::Error> {
        self.password_completion_with_client(
            context,
            token,
            prepared,
            services,
            mutation,
            original_deadline,
        )
        .map(|value| value.0)
    }
    #[allow(clippy::too_many_arguments)]
    fn password_completion_guarded<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        deadline: std::time::Instant,
        dispatch: impl for<'guard> FnOnce(
            password_change::Dispatch<'a>,
            crate::session::GuardedSessionLease<'guard>,
        ) -> Result<
            crate::account_mutation::TerminalReceipt,
            password_change::Error,
        >,
        mut quarantine: impl FnMut(&str),
    ) -> Result<PasswordCompletion, password_change::Error> {
        use crate::account_mutation::Outcome as MutationOutcome;
        use crate::session::BrowserRevocation;
        use std::time::{Duration, Instant};
        // A later caller budget cannot renew preparation at receipt, admission
        // or browser cleanup. Legacy preparation without a captured budget
        // retains the caller's original deadline.
        let deadline = prepared.bound_workflow_deadline(deadline);
        let now = Instant::now();
        if deadline <= now || deadline > now + Duration::from_secs(60) {
            return Err(password_change::Error::Expired);
        }
        let (authority, clock) = services;
        let mut binding = None;
        let receipt = self.password_dispatch_with_lease(
            context,
            token,
            prepared,
            (authority.clone(), clock),
            |action, lease| {
                if Instant::now() >= deadline {
                    return Err(password_change::Error::Expired);
                }
                binding = Some(CompletionBinding::capture(&action));
                dispatch(action, lease)
            },
        );
        // The guarded call has returned: its store lock has dropped on all paths.
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(binding) = &binding {
                    quarantine(&binding.account);
                }
                return Err(error);
            }
        };
        let binding = binding.ok_or(password_change::Error::Unavailable)?;
        if !binding.matches(&receipt) {
            quarantine(&binding.account);
            return Ok((BrowserRevocation::Contained { count: 0 }, None));
        }
        let performed_at = match receipt.outcome() {
            MutationOutcome::Changed { changed_at, .. }
            | MutationOutcome::ChangedIncomplete { changed_at } => Some(changed_at.clone()),
            _ => None,
        };
        // Even an authentic refusal cannot become a known terminal result once
        // the original operation budget or action validity has elapsed. Sample
        // the wall clock before the final Instant check so a slow clock cannot
        // renew the budget at this boundary.
        let wall_now = clock.unix_timestamp();
        if wall_now < receipt.issued()
            || wall_now < receipt.responded_at()
            || wall_now >= receipt.expires()
            || Instant::now() >= deadline
        {
            quarantine(&binding.account);
            return Ok((
                match performed_at.clone() {
                    Some(changed_at) => BrowserRevocation::ChangedIncomplete {
                        count: 0,
                        changed_at,
                    },
                    None => BrowserRevocation::Contained { count: 0 },
                },
                performed_at,
            ));
        }
        if matches!(receipt.outcome(), MutationOutcome::KnownRefused) {
            return Ok((BrowserRevocation::KnownRefused, None));
        }
        let epoch_ready = match receipt.outcome() {
            MutationOutcome::Changed { epoch, .. } => {
                Instant::now() < deadline
                    && authority.admit(&binding.account, *epoch).is_ok()
                    && Instant::now() < deadline
            }
            _ => false,
        };
        let service = SessionService::new(
            FileSessionStore::new(self.session_dir.clone()),
            ActionClock(clock),
            SystemRandomSource,
            self.session_lifetime_seconds,
            self.session_idle_timeout_seconds,
        );
        let result = service.revoke_password_change_sessions(receipt, deadline);
        match result {
            BrowserRevocation::OldSessionsRevoked { count } if epoch_ready => Ok((
                BrowserRevocation::OldSessionsRevoked { count },
                performed_at,
            )),
            BrowserRevocation::OldSessionsRevoked { count }
            | BrowserRevocation::Contained { count } => {
                quarantine(&binding.account);
                Ok((
                    match performed_at.clone() {
                        Some(changed_at) => {
                            BrowserRevocation::ChangedIncomplete { count, changed_at }
                        }
                        None => BrowserRevocation::Contained { count },
                    },
                    performed_at,
                ))
            }
            BrowserRevocation::ChangedIncomplete { count, changed_at } => {
                quarantine(&binding.account);
                Ok((
                    BrowserRevocation::ChangedIncomplete { count, changed_at },
                    performed_at,
                ))
            }
            BrowserRevocation::KnownRefused => {
                quarantine(&binding.account);
                Ok((BrowserRevocation::Contained { count: 0 }, None))
            }
        }
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn password_completion_for_test<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        deadline: std::time::Instant,
        dispatch: impl FnOnce(
            password_change::Dispatch<'a>,
        ) -> Result<
            crate::account_mutation::TerminalReceipt,
            password_change::Error,
        >,
        quarantine: impl FnMut(&str),
    ) -> Result<crate::session::BrowserRevocation, password_change::Error> {
        self.password_completion_status_for_test(
            context, token, prepared, services, deadline, dispatch, quarantine,
        )
        .map(|value| value.0)
    }
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn password_completion_status_for_test<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        deadline: std::time::Instant,
        dispatch: impl FnOnce(
            password_change::Dispatch<'a>,
        ) -> Result<
            crate::account_mutation::TerminalReceipt,
            password_change::Error,
        >,
        quarantine: impl FnMut(&str),
    ) -> Result<PasswordCompletion, password_change::Error> {
        self.password_completion_guarded(
            context,
            token,
            prepared,
            services,
            deadline,
            |action, _lease| dispatch(action),
            quarantine,
        )
    }
    fn password_dispatch_guarded<'a, O>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        dispatch: impl FnOnce(password_change::Dispatch<'a>) -> Result<O, password_change::Error>,
    ) -> Result<O, password_change::Error> {
        self.password_dispatch_with_lease(context, token, prepared, services, |action, _lease| {
            dispatch(action)
        })
    }
    fn password_dispatch_with_lease<'a, O>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        dispatch: impl for<'guard> FnOnce(
            password_change::Dispatch<'a>,
            crate::session::GuardedSessionLease<'guard>,
        ) -> Result<O, password_change::Error>,
    ) -> Result<O, password_change::Error> {
        let (authority, clock) = services;
        let service = SessionService::new(
            FileSessionStore::new(self.session_dir.clone()),
            ActionClock(clock),
            SystemRandomSource,
            self.session_lifetime_seconds,
            self.session_idle_timeout_seconds,
        );
        let service = match &self.account_rollout {
            Some(account) => {
                service.with_account_epoch_authority(account.clone(), authority.clone())
            }
            None => service.with_epoch_authority(authority.clone()),
        };
        service
            .with_guarded_session_lease(context, token, |current, lease| {
                if !self.uses_account_runtime(&current.record.canonical_username) {
                    return Err(password_change::Error::Unavailable);
                }
                let action =
                    prepared.into_dispatch(context, &current, authority.as_ref(), clock)?;
                service
                    .recheck_guarded_session(&current)
                    .map_err(guarded_error)?;
                dispatch(action, lease)
            })
            .map_err(guarded_error)?
    }
    /// Synthetic authority injection exists only in unit-test compilation.
    #[cfg(test)]
    pub(crate) fn password_dispatch_for_test<'a, O>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        dispatch: impl FnOnce(password_change::Dispatch<'a>) -> Result<O, password_change::Error>,
    ) -> Result<O, password_change::Error> {
        self.password_dispatch_guarded(context, token, prepared, services, dispatch)
    }
    /// Backend prerequisite only. No browser route/form or configuration opt-in
    /// enables an unqualified helper or dispatches a password write.
    pub fn prepare_password_change<'a>(
        &self,
        context: &'a AuthenticationContext,
        session: &'a ValidatedSession,
        request: Request<'a>,
    ) -> Outcome<'a> {
        self.prepare_password_action(context, session, request, None)
    }
    /// Source-only preparation on the exact budget later consumed by guarded
    /// mutation/epoch checks and post-lock browser cleanup; no route enables it.
    pub fn prepare_password_change_before<'a>(
        &self,
        context: &'a AuthenticationContext,
        session: &'a ValidatedSession,
        request: Request<'a>,
        original_deadline: std::time::Instant,
    ) -> Outcome<'a> {
        self.prepare_password_action(context, session, request, Some(original_deadline))
    }
    fn prepare_password_action<'a>(
        &self,
        context: &'a AuthenticationContext,
        session: &'a ValidatedSession,
        request: Request<'a>,
        deadline: Option<std::time::Instant>,
    ) -> Outcome<'a> {
        let Some(ready) = self.ready_account_runtime(&session.record.canonical_username) else {
            return Outcome {
                authorization: Err(password_change::Error::Unavailable),
                audit_events: vec![],
            };
        };
        let client = ready.admission();
        let backend = crate::account_admission_runtime::CredentialBackend {
            client: client.clone(),
            captured: Default::default(),
        };
        let rate =
            crate::password_change_rate::Store::new(self.settings_dir.join("password-stepup-rate"));
        let factor = self.build_factor_service();
        let services = Services {
            primary: &backend,
            factor: &factor,
            epoch: client,
            rate: &rate,
            clock: &SystemTimeProvider,
            policy: self.authentication_policy,
        };
        let attempt = Attempt {
            context,
            session,
            request,
        };
        match deadline {
            Some(value) => password_change::prepare_before(services, attempt, value),
            None => password_change::prepare(services, attempt),
        }
    }
}
struct ActionClock<'a>(&'a dyn crate::totp::TimeProvider);
impl crate::totp::TimeProvider for ActionClock<'_> {
    fn unix_timestamp(&self) -> u64 {
        self.0.unix_timestamp()
    }
}
fn guarded_error(error: crate::session::GuardedSessionError) -> password_change::Error {
    match error {
        crate::session::GuardedSessionError::Inactive => password_change::Error::Authentication,
        crate::session::GuardedSessionError::Unavailable => password_change::Error::Unavailable,
    }
}

struct DeadlineAuthority {
    client: crate::account_admission_runtime::Client,
    deadline: std::time::Instant,
}
impl crate::account_admission::EpochAuthority for DeadlineAuthority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        self.client.admit_before(account, epoch, self.deadline)
    }
}
struct CompletionBinding {
    account: String,
    epoch: u64,
    session: String,
    request: String,
    intent: String,
    source: String,
    issued: u64,
    expires: u64,
}
impl CompletionBinding {
    fn capture(action: &password_change::Dispatch<'_>) -> Self {
        Self {
            account: action.account().into(),
            epoch: action.epoch(),
            session: action.session_id().into(),
            request: action.request_id().into(),
            intent: action.intent_reference().into(),
            source: action.source().into(),
            issued: action.issued(),
            expires: action.expires(),
        }
    }
    fn matches(&self, receipt: &crate::account_mutation::TerminalReceipt) -> bool {
        receipt.account() == self.account
            && receipt.old_epoch() == self.epoch
            && receipt.session_id() == self.session
            && receipt.request_id() == self.request
            && receipt.intent_reference() == self.intent
            && receipt.source() == self.source
            && receipt.issued() == self.issued
            && receipt.expires() == self.expires
    }
}

#[cfg(test)]
mod password_result_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    struct Fixture {
        root: std::path::PathBuf,
        gateway: RuntimeBrowserGateway,
        session: ValidatedSession,
        token: SessionToken,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "osmap-password-result-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let gateway = RuntimeBrowserGateway::for_test(&root);
            let context = AuthenticationContext::new(
                AuthenticationPolicy::default(),
                "result-test",
                "127.0.0.1",
                "ResultTest",
            )
            .unwrap();
            let issued = gateway
                .build_session_service()
                .issue(
                    &context,
                    "alice@example.test",
                    crate::auth::RequiredSecondFactor::Totp,
                )
                .unwrap();
            Self {
                root,
                gateway,
                token: issued.token,
                session: ValidatedSession {
                    record: issued.record,
                    audit_event: issued.audit_event,
                },
            }
        }
        fn outcome(confirmed: bool, stamp: Option<&str>) -> BrowserPasswordOutcome {
            BrowserPasswordOutcome {
                decision: if confirmed {
                    BrowserPasswordDecision::Changed
                } else {
                    BrowserPasswordDecision::Unconfirmed
                },
                changed_at: stamp.map(str::to_owned),
                audit_events: vec![],
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn verified_password_result_survives_late_unknown_publication() {
        for confirmed in [true, false] {
            let f = Fixture::new();
            let cap = f
                .gateway
                .begin_password_result_record(&f.session, None)
                .unwrap()
                .unwrap();
            assert!(f.gateway.finish_password_result_record(
                &f.session,
                &cap,
                &Fixture::outcome(confirmed, Some("20261025062139"))
            ));
            assert!(f.gateway.finish_password_result_record(
                &f.session,
                &cap,
                &Fixture::outcome(false, None)
            ));
            assert_eq!(
                f.gateway.read_password_result_record(&cap),
                Some(BrowserPasswordResult {
                    confirmed,
                    changed_at: Some("20261025062139".into())
                })
            );
        }
    }

    #[test]
    fn password_result_reopen_retains_time_without_admitting_revoked_session() {
        let f = Fixture::new();
        let cap = f
            .gateway
            .begin_password_result_record(&f.session, None)
            .unwrap()
            .unwrap();
        // Repeated form loads, with or without the cookie, reuse one record.
        assert_eq!(
            f.gateway
                .begin_password_result_record(&f.session, None)
                .unwrap(),
            Some(cap.clone())
        );
        assert_eq!(
            f.gateway
                .begin_password_result_record(&f.session, Some(&cap))
                .unwrap(),
            Some(cap.clone())
        );
        assert!(f.gateway.finish_password_result_record(
            &f.session,
            &cap,
            &Fixture::outcome(false, Some("20261025062139"))
        ));
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "result-reopen",
            "127.0.0.1",
            "ResultTest",
        )
        .unwrap();
        assert!(
            f.gateway
                .build_session_service()
                .revoke_by_token(&context, &f.token)
                .unwrap()
                .newly_revoked
        );
        let gateway = RuntimeBrowserGateway::for_test(&f.root);
        assert!(gateway
            .build_session_service()
            .validate(&context, &f.token)
            .is_err());
        assert_eq!(
            gateway.read_password_result_record(&cap),
            Some(BrowserPasswordResult {
                confirmed: false,
                changed_at: Some("20261025062139".into())
            })
        );
        let mut bob = f.session.clone();
        bob.record.canonical_username = "bob@example.test".into();
        assert!(!gateway.finish_password_result_record(
            &bob,
            &cap,
            &Fixture::outcome(true, Some("20261025062139"))
        ));
        let bob_cap = gateway
            .begin_password_result_record(&bob, Some(&cap))
            .unwrap()
            .unwrap();
        assert_ne!(bob_cap, cap);
        assert_eq!(
            gateway.read_password_result_record(&bob_cap),
            Some(BrowserPasswordResult {
                confirmed: false,
                changed_at: None
            })
        );
        assert!(gateway
            .read_password_result_record(&"f".repeat(64))
            .is_none());
        for invalid in ["", "../record", "000", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
            assert!(gateway.read_password_result_record(invalid).is_none());
        }
        let app = BrowserApp::new(HttpPolicy::default(), gateway.clone());
        let get = |path: &str, cookie: &str| {
            let bytes =
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nCookie: {cookie}\r\n\r\n");
            let request = crate::http_parse::parse_http_request_bytes(
                bytes.as_bytes(),
                &HttpPolicy::default(),
            )
            .unwrap();
            app.handle_request(&request, "127.0.0.1")
        };
        for section in ["security", "authentication"] {
            let denied = get(
                &format!("/settings?section={section}"),
                &format!("osmap_session={}", f.token.as_str()),
            );
            assert_eq!(denied.response.status_code, 303);
            assert!(
                !String::from_utf8_lossy(&denied.response.body).contains("2026-10-25 06:21:39 UTC")
            );
        }
        let view = get(
            "/settings/password/result",
            &format!("osmap_password_result={cap}"),
        );
        assert_eq!(view.response.status_code, 200);
        let html = String::from_utf8_lossy(&view.response.body);
        assert!(html.contains("2026-10-25 06:21:39 UTC"));
        assert!(html.contains("Required containment remains incomplete"));
        assert!(!html.contains("alice@example.test"));
        assert!(!html.contains("csrf_token"));
        assert!(!html.contains("password-change-form"));
        for cookie in [
            String::new(),
            format!("osmap_password_result={}", "f".repeat(64)),
        ] {
            let missing = get("/settings/password/result", &cookie);
            assert_eq!(missing.response.status_code, 404);
            assert!(!String::from_utf8_lossy(&missing.response.body)
                .contains("2026-10-25 06:21:39 UTC"));
        }
        assert!(view.audit_events.is_empty());
        let store = gateway.password_result_store();
        let locked = store.lock(&cap).unwrap();
        let mut record: PasswordResultRecord =
            serde_json::from_slice(&locked.read().unwrap().unwrap()).unwrap();
        record.created = 1;
        record.expires = 1 + PASSWORD_RESULT_TTL;
        locked.write(&serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(gateway.read_password_result_record(&cap).is_none());
    }
}
