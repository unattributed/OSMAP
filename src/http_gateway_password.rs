use super::*;
use crate::password_change::{self, Attempt, EpochPrimaryBackend, Outcome, Request, Services};

impl EpochPrimaryBackend for crate::account_admission_runtime::CredentialBackend {
    fn captured_admission(
        &self,
    ) -> Result<crate::account_admission::Admission, password_change::Error> {
        self.captured
            .lock()
            .ok()
            .and_then(|v| v.clone())
            .ok_or(password_change::Error::Unavailable)
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
    fn password_dispatch_guarded<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        dispatch: impl FnOnce(password_change::Dispatch<'a>) -> Result<(), password_change::Error>,
    ) -> Result<(), password_change::Error> {
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
            .with_guarded_validated_session(context, token, |current| {
                let action =
                    prepared.into_dispatch(context, &current, authority.as_ref(), clock)?;
                service
                    .recheck_guarded_session(&current)
                    .map_err(guarded_error)?;
                dispatch(action)
            })
            .map_err(guarded_error)?
    }
    /// Synthetic authority injection exists only in unit-test compilation.
    #[cfg(test)]
    pub(crate) fn password_dispatch_for_test<'a>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        prepared: password_change::Prepared<'a>,
        services: (
            std::sync::Arc<dyn crate::account_admission::EpochAuthority>,
            &dyn crate::totp::TimeProvider,
        ),
        dispatch: impl FnOnce(password_change::Dispatch<'a>) -> Result<(), password_change::Error>,
    ) -> Result<(), password_change::Error> {
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
        password_change::prepare(
            Services {
                primary: &backend,
                factor: &self.build_factor_service(),
                epoch: client,
                rate: &crate::password_change_rate::Store::new(
                    self.settings_dir.join("password-stepup-rate"),
                ),
                clock: &SystemTimeProvider,
                policy: self.authentication_policy,
            },
            Attempt {
                context,
                session,
                request,
            },
        )
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
