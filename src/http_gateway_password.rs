use super::*;
use crate::password_change::{self, Attempt, EpochPrimaryBackend, Outcome, Request, Services};

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
impl RuntimeBrowserGateway {
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
        let Some(client) = &self.account_admission_client else {
            return Err(password_change::Error::Unavailable);
        };
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
        mutation: &crate::account_mutation_client::Client,
        original_deadline: std::time::Instant,
    ) -> Result<crate::session::BrowserRevocation, password_change::Error> {
        let original_deadline = prepared.bound_workflow_deadline(original_deadline);
        let Some(client) = &self.account_admission_client else {
            return Err(password_change::Error::Unavailable);
        };
        let authority = std::sync::Arc::new(DeadlineAuthority {
            client: client.clone(),
            deadline: original_deadline,
        });
        self.password_completion_with_client(
            context,
            token,
            prepared,
            (authority, &SystemTimeProvider),
            mutation,
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
    ) -> Result<crate::session::BrowserRevocation, password_change::Error> {
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
    ) -> Result<crate::session::BrowserRevocation, password_change::Error> {
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
            return Ok(BrowserRevocation::Contained { count: 0 });
        }
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
            return Ok(BrowserRevocation::Contained { count: 0 });
        }
        if matches!(receipt.outcome(), MutationOutcome::KnownRefused) {
            return Ok(BrowserRevocation::KnownRefused);
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
            BrowserRevocation::OldSessionsRevoked { count } if epoch_ready => {
                Ok(BrowserRevocation::OldSessionsRevoked { count })
            }
            BrowserRevocation::OldSessionsRevoked { count }
            | BrowserRevocation::Contained { count } => {
                quarantine(&binding.account);
                Ok(BrowserRevocation::Contained { count })
            }
            BrowserRevocation::KnownRefused => {
                quarantine(&binding.account);
                Ok(BrowserRevocation::Contained { count: 0 })
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
        )
        .with_epoch_authority(authority.clone());
        service
            .with_guarded_session_lease(context, token, |current, lease| {
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
        let Some(client) = &self.account_admission_client else {
            return Outcome {
                authorization: Err(password_change::Error::Unavailable),
                audit_events: vec![],
            };
        };
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
