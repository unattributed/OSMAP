//! Recovery-contact actions use current stored session authority and fresh
//! own-account authentication. They never issue a login, write credentials or
//! grant authority to replace a factor.
use super::*;
use crate::auth::CommandExecutor;
use crate::password_change::EpochPrimaryBackend;
use crate::recovery_contact::{
    RecoveryContactAction, RecoveryContactDelivery, RecoveryContactError as Error,
    RecoveryContactMessage, RecoveryContactMutation, RecoveryContactNotifier,
    RecoveryContactResult, RecoveryContactSnapshot, RecoveryContactStore,
};
use crate::totp::TimeProvider as _;
use std::time::{Duration, Instant};

fn before(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}

fn rate_error(error: crate::password_change::Error) -> Error {
    match error {
        crate::password_change::Error::Invalid => Error::Invalid,
        crate::password_change::Error::Authentication => Error::Authentication,
        crate::password_change::Error::Throttled => Error::Throttled,
        crate::password_change::Error::Stale => Error::Stale,
        crate::password_change::Error::Expired => Error::Expired,
        crate::password_change::Error::Unavailable => Error::Unavailable,
    }
}

fn epoch_before(
    authority: &dyn crate::account_admission::EpochAuthority,
    account: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<(), Error> {
    before(deadline)?;
    authority
        .admit_before(account, epoch, deadline)
        .map_err(|error| match error {
            crate::account_admission::Error::Refused => Error::Stale,
            crate::account_admission::Error::Expired => Error::Expired,
            _ => Error::Unavailable,
        })?;
    before(deadline)
}

#[allow(clippy::too_many_arguments)] // Separate current authority and private factors.
fn step_up<B: EpochPrimaryBackend, F: crate::auth::SecondFactorVerifier>(
    context: &AuthenticationContext,
    session: &ValidatedSession,
    primary: &B,
    factor: &SecondFactorService<F>,
    authority: &dyn crate::account_admission::EpochAuthority,
    rate: &crate::password_change_rate::Store,
    clock: &dyn crate::totp::TimeProvider,
    policy: AuthenticationPolicy,
    current_password: &str,
    code: &str,
    deadline: Instant,
) -> Result<(), Error> {
    before(deadline)?;
    if current_password.is_empty()
        || current_password.len() > 1024
        || current_password.chars().any(char::is_control)
        || code.len() != 6
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Invalid);
    }
    let began = clock.unix_timestamp();
    let epoch = session.record.account_epoch.ok_or(Error::Unavailable)?;
    let account = &session.record.canonical_username;
    epoch_before(authority, account, epoch, deadline)?;
    let admission = rate
        .admit(account, &context.remote_addr, began)
        .map_err(rate_error)?;
    let verdict = primary
        .verify_primary_before(context, account, current_password, deadline)
        .map_err(|_| Error::Unavailable)?;
    before(deadline)?;
    if !matches!(verdict, crate::auth::PrimaryAuthVerdict::Accept { canonical_username } if canonical_username == *account)
    {
        admission
            .failed(clock.unix_timestamp())
            .map_err(rate_error)?;
        return Err(Error::Authentication);
    }
    let captured = primary.captured_admission().map_err(rate_error)?;
    if captured.account != *account || captured.epoch != epoch {
        return Err(Error::Stale);
    }
    before(deadline)?;
    let verified = factor.verify(context, account, policy.required_second_factor, code);
    match verified.decision {
        AuthenticationDecision::AuthenticatedPendingSession { canonical_username }
            if canonical_username == *account => {}
        AuthenticationDecision::Denied {
            public_reason: crate::auth::PublicFailureReason::TemporarilyUnavailable,
        } => return Err(Error::Unavailable),
        _ => {
            admission
                .failed(clock.unix_timestamp())
                .map_err(rate_error)?;
            return Err(Error::Authentication);
        }
    }
    before(deadline)?;
    let now = clock.unix_timestamp();
    if now < began || began.checked_add(300).is_none_or(|until| now >= until) {
        return Err(Error::Expired);
    }
    epoch_before(authority, account, epoch, deadline)?;
    admission.confirm().map_err(rate_error)?;
    before(deadline)
}

impl RuntimeBrowserGateway {
    pub(super) fn read_recovery_contact(
        &self,
        session: &ValidatedSession,
    ) -> Result<RecoveryContactSnapshot, Error> {
        self.recovery_contact_local_domain
            .as_ref()
            .ok_or(Error::Unavailable)?;
        self.ready_account_runtime(&session.record.canonical_username)
            .ok_or(Error::Unavailable)?;
        RecoveryContactStore::new(self.settings_dir.join("recovery-contact-v1")).snapshot(
            &session.record.canonical_username,
            SystemTimeProvider.unix_timestamp(),
        )
    }

    #[allow(clippy::too_many_arguments)] // Exact HTTP action and independent factors.
    pub(super) fn mutate_recovery_contact(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        token: &SessionToken,
        expected_revision: u64,
        action: RecoveryContactAction,
        current_password: &str,
        totp_code: &str,
        deadline: Instant,
    ) -> Result<RecoveryContactResult, Error> {
        before(deadline)?;
        let local_domain = self
            .recovery_contact_local_domain
            .as_deref()
            .ok_or(Error::Unavailable)?;
        if deadline > Instant::now() + Duration::from_secs(60) {
            return Err(Error::Invalid);
        }
        let ready = self
            .ready_account_runtime(&session.record.canonical_username)
            .ok_or(Error::Unavailable)?;
        let client = ready.admission().clone();
        let primary = crate::account_admission_runtime::CredentialBackend {
            client: client.clone(),
            captured: Default::default(),
        };
        let authority: std::sync::Arc<dyn crate::account_admission::EpochAuthority> =
            std::sync::Arc::new(client);
        let sessions = self.build_session_service();
        let requires_step_up = !matches!(&action, RecoveryContactAction::Verify { .. });
        let notifier = SendmailNotifier {
            executor: SystemCommandExecutor,
            path: &self.sendmail_path,
            sender: &session.record.canonical_username,
            local_domain,
        };
        sessions
            .with_guarded_session_lease(context, token, |current, _lease| {
                if current.record.session_id != session.record.session_id
                    || current.record.canonical_username != session.record.canonical_username
                    || current.record.account_epoch != session.record.account_epoch
                {
                    return Err(Error::Stale);
                }
                let epoch = current.record.account_epoch.ok_or(Error::Unavailable)?;
                let store =
                    RecoveryContactStore::new(self.settings_dir.join("recovery-contact-v1"));
                store.mutate(
                    RecoveryContactMutation {
                        account: &current.record.canonical_username,
                        expected_revision,
                        now: SystemTimeProvider.unix_timestamp(),
                        deadline,
                        action,
                    },
                    || {
                        if requires_step_up {
                            step_up(
                                context,
                                &current,
                                &primary,
                                &self.build_factor_service(),
                                authority.as_ref(),
                                &crate::password_change_rate::Store::new(
                                    self.settings_dir.join("password-stepup-rate"),
                                ),
                                &SystemTimeProvider,
                                self.authentication_policy,
                                current_password,
                                totp_code,
                                deadline,
                            )?;
                        }
                        epoch_before(
                            authority.as_ref(),
                            &current.record.canonical_username,
                            epoch,
                            deadline,
                        )?;
                        sessions
                            .recheck_guarded_session(&current)
                            .map_err(|_| Error::Authentication)?;
                        before(deadline)
                    },
                    &notifier,
                )
            })
            .map_err(|error| match error {
                crate::session::GuardedSessionError::Inactive => Error::Authentication,
                crate::session::GuardedSessionError::Unavailable => Error::Unavailable,
            })?
    }
}

struct SendmailNotifier<'a, E> {
    executor: E,
    path: &'a std::path::Path,
    sender: &'a str,
    local_domain: &'a str,
}

impl<E: CommandExecutor> RecoveryContactNotifier for SendmailNotifier<'_, E> {
    fn deliver(
        &self,
        message: RecoveryContactMessage<'_>,
        deadline: Instant,
    ) -> RecoveryContactDelivery {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return RecoveryContactDelivery::Refused;
        };
        let (recipient, subject, body) = match message {
            RecoveryContactMessage::Verification { email, token, expires_at } => (email,
                "Verify your OSMAP recovery contact",
                format!("Use this one-use code in the authenticated OSMAP recovery-contact form:\n\n{token}\n\nExpires at Unix time {expires_at}. Contact possession does not grant sign-in or factor-reset permission.\n")),
            RecoveryContactMessage::Replaced { email } => (email,
                "OSMAP recovery contact replaced",
                "Your previous OSMAP recovery contact was replaced after verification. This message contains no account credentials or mail contents.\n".into()),
            RecoveryContactMessage::Removed { email } => (email,
                "OSMAP recovery contact removed",
                "Your OSMAP recovery contact was removed. This message contains no account credentials or mail contents.\n".into()),
        };
        if crate::identity::MailboxIdentity::parse(recipient).is_err()
            || crate::identity::MailboxIdentity::parse(self.sender).is_err()
            || !recipient
                .rsplit_once('@')
                .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(self.local_domain))
        {
            return RecoveryContactDelivery::Refused;
        }
        let wire = format!("From: {}\r\nTo: {}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{body}", self.sender, recipient);
        let result = self.executor.run_with_stdin_bytes_timeout_and_output_limit(
            self.path.to_string_lossy().as_ref(),
            &[
                "-oi".into(),
                "-f".into(),
                self.sender.into(),
                "--".into(),
                recipient.into(),
            ],
            wire.as_bytes(),
            remaining.min(Duration::from_secs(10)),
            4096,
        );
        match result {
            Ok(output) if output.status_code == 0 && Instant::now() < deadline => {
                RecoveryContactDelivery::Accepted
            }
            // A nonzero/timeout/process error does not prove queue nonacceptance.
            // Core persists uncertainty and withholds any automatic resend.
            _ => RecoveryContactDelivery::Unconfirmed,
        }
    }
}

#[cfg(test)]
#[path = "http_gateway_recovery_tests.rs"]
mod tests;
