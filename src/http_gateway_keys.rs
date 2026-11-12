//! Browser key mutations reuse real password/TOTP services, never session-only approval.
use super::*;
use crate::identity::CanonicalUsername;
use crate::key_management::{
    self, Error, MutationOutcome, MutationRequest, PublicKeyBackend, State, StateOutcome,
};
use crate::openpgp_bindings::BindingStore;
#[cfg(test)]
#[path = "http_gateway_keys_tests.rs"]
mod tests;
struct KeyBackend<'a> {
    inventory: Option<&'a crate::openpgp_inventory_runtime::Client>,
    admin: Option<&'a crate::openpgp_public_admin_runtime::Client>,
    diagnostic: &'a std::cell::Cell<Option<NativeDiagnostic>>,
}
type NativeDiagnostic = (
    &'static str,
    Result<(), crate::openpgp_public_admin_protocol::Error>,
    Option<usize>,
);
fn admin_error(error: crate::openpgp_public_admin_protocol::Error) -> Error {
    use crate::openpgp_public_admin_protocol::Error as Native;
    match error {
        Native::Stale => Error::Stale,
        Native::Unconfirmed => Error::Unconfirmed,
        Native::Invalid | Native::Limit => Error::Invalid,
        Native::Busy
        | Native::Unavailable
        | Native::Authentication
        | Native::Replay
        | Native::Expired => Error::Unavailable,
    }
}
impl PublicKeyBackend for KeyBackend<'_> {
    fn read(&self, account: &str) -> Result<crate::openpgp_inventory::Inventory, Error> {
        if let Some(admin) = self.admin {
            let snapshot = admin.snapshot(account).map_err(admin_error);
            match snapshot {
                Ok(snapshot) if snapshot.inventory.keys().is_some() => {
                    return Ok(snapshot.inventory);
                }
                Err(error) if self.inventory.is_none() => return Err(error),
                _ => {}
            }
        }
        // Match the page's read-only fallback. Mutations never retry through it.
        self.inventory
            .ok_or(Error::Unavailable)?
            .read(account)
            .map_err(|_| Error::Unavailable)
    }
    fn import_public(
        &self,
        account: &str,
        expected_public_revision: &str,
        primary_fingerprint: &str,
        certificate: &[u8],
    ) -> Result<(), Error> {
        let result = self
            .admin
            .ok_or(Error::Unavailable)?
            .import_public(
                account,
                expected_public_revision,
                primary_fingerprint,
                certificate,
            )
            .map(|_| ());
        self.diagnostic
            .set(Some(("import_public", result, Some(certificate.len()))));
        result.map_err(admin_error)
    }
    fn remove_public(
        &self,
        account: &str,
        expected_public_revision: &str,
        primary_fingerprint: &str,
    ) -> Result<(), Error> {
        let result = self
            .admin
            .ok_or(Error::Unavailable)?
            .remove_public(account, expected_public_revision, primary_fingerprint)
            .map(|_| ());
        self.diagnostic.set(Some(("remove_public", result, None)));
        result.map_err(admin_error)
    }
}
impl RuntimeBrowserGateway {
    pub(super) fn private_key_session(
        session: &ValidatedSession,
    ) -> crate::openpgp_personal::PrivateSession {
        crate::openpgp_personal::PrivateSession {
            session_id: session.record.session_id.clone(),
            account_epoch: session.record.account_epoch,
            expires_at: session.record.expires_at,
        }
    }

    fn personal_key_change(
        &self,
        session: &ValidatedSession,
        request: &MutationRequest<'_>,
    ) -> Result<(), Error> {
        use crate::openpgp_personal::{PersonalAction, PersonalError};
        let native_error = |error| match error {
            PersonalError::Locked => Error::PersonalLocked,
            PersonalError::Conflict => Error::PersonalConflict,
            PersonalError::Expired => Error::Authentication,
            PersonalError::Invalid | PersonalError::Unsupported => Error::PersonalInvalid,
            PersonalError::Unavailable => Error::Unavailable,
            PersonalError::Unconfirmed => Error::Unconfirmed,
        };
        let client = self.crypto_client().ok_or(Error::Unavailable)?;
        let account = &session.record.canonical_username;
        let private_session = Self::private_key_session(session);
        // Lock is deliberately available even when the public binding store
        // cannot be read. It can only reduce this mapped account's authority.
        if matches!(request.action, key_management::Action::LockPersonal) {
            return client
                .personal(account, &private_session, PersonalAction::Lock)
                .map(|_| ())
                .map_err(native_error);
        }
        BindingStore::new(self.settings_dir.join("openpgp-bindings"))
            .with_locked_revision(account, request.expected_revision, |record| {
                let state = client
                    .personal(account, &private_session, PersonalAction::Status)
                    .map_err(native_error);
                let result = (|| {
                    let state = state?;
                    if record.account_binding.as_ref().is_none_or(|binding| {
                        binding.primary_fingerprint != state.primary_fingerprint
                    }) {
                        return Err(Error::InvalidKey);
                    }
                    let action = match &request.action {
                        key_management::Action::ImportPersonal {
                            certificate,
                            passphrase,
                        } => PersonalAction::Import {
                            certificate,
                            passphrase,
                        },
                        key_management::Action::UnlockPersonal { passphrase } => {
                            PersonalAction::Unlock { passphrase }
                        }
                        _ => return Err(Error::Invalid),
                    };
                    client
                        .personal(account, &private_session, action)
                        .map(|_| ())
                        .map_err(native_error)
                })();
                Ok(result)
            })
            .map_err(key_management::binding_error)?
    }

    pub(super) fn key_management_state(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> StateOutcome {
        let mut state = State::unavailable(&session.record.canonical_username);
        if let Ok(account) = CanonicalUsername::parse(&session.record.canonical_username) {
            let admin = self.admin_client();
            let inventory = self.inventory_client();
            state.bindings = BindingStore::new(self.settings_dir.join("openpgp-bindings"))
                .load(account.as_str())
                .ok();
            if let Some(snapshot) = admin
                .as_ref()
                .and_then(|c| c.snapshot(account.as_str()).ok())
                .filter(|s| s.inventory.keys().is_some())
            {
                state.inventory = Some(snapshot.inventory);
                state.public_inventory_revision = Some(snapshot.revision);
            } else {
                state.inventory = inventory
                    .as_ref()
                    .and_then(|c| c.read(account.as_str()).ok())
                    .filter(|i| i.keys().is_some());
            }
            state.binding_changes_available = state.bindings.is_some() && state.inventory.is_some();
            state.public_key_changes_available = state.binding_changes_available
                && state.public_inventory_revision.is_some()
                && admin.is_some();
        }
        StateOutcome {
            state,
            audit_events: vec![],
        }
    }
    pub(super) fn change_keys_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        token: &SessionToken,
        request: MutationRequest<'_>,
    ) -> MutationOutcome {
        let mut audit_events = Vec::new();
        let native_diagnostic = std::cell::Cell::new(None);
        let sessions = self.build_session_service();
        let result = sessions
            .with_guarded_session_lease(context, token, |current, _lease| {
                if current.record.session_id != session.record.session_id
                    || current.record.canonical_username != session.record.canonical_username
                    || current.record.account_epoch != session.record.account_epoch
                {
                    return Err(Error::Stale);
                }
                let account = CanonicalUsername::parse(&current.record.canonical_username)
                    .map_err(|_| Error::Invalid)?;
                if matches!(
                    request.action,
                    key_management::Action::UnlockPersonal { .. }
                        | key_management::Action::LockPersonal
                ) {
                    sessions
                        .recheck_guarded_session(&current)
                        .map_err(guarded_error)?;
                    return self.personal_key_change(&current, &request);
                }
                let inventory = self.inventory_client();
                let admin = self.admin_client();
                let backend = KeyBackend {
                    inventory: inventory.as_ref(),
                    admin: admin.as_ref(),
                    diagnostic: &native_diagnostic,
                };
                let throttle = self.build_login_throttle_service();
                let check = throttle
                    .check(context, account.as_str())
                    .map_err(|_| Error::Unavailable)?;
                audit_events.extend(check.audit_events);
                if matches!(check.decision, LoginThrottleDecision::Throttled { .. }) {
                    return Err(Error::Throttled);
                }
                let stepup = key_management::verify_fresh_with_primary(
                    |context, username, password| {
                        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
                        let outcome = self.authenticate_account_primary(
                            context,
                            username,
                            password,
                            captured.clone(),
                        );
                        let constraint = if self.ready_account_runtime(username).is_some()
                            && matches!(
                                outcome.decision,
                                AuthenticationDecision::MfaRequired { .. }
                            ) {
                            match captured.lock() {
                                Ok(admission)
                                    if admission.as_ref().is_some_and(|admission| {
                                        admission.account == current.record.canonical_username
                                            && Some(admission.epoch) == current.record.account_epoch
                                    }) =>
                                {
                                    Ok(())
                                }
                                Ok(_) => Err(Error::Stale),
                                Err(_) => Err(Error::Unavailable),
                            }
                        } else {
                            Ok(())
                        };
                        (outcome, constraint)
                    },
                    &self.build_factor_service(),
                    context,
                    &current,
                    (request.password, request.totp),
                    crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
                );
                audit_events.extend(stepup.audit_events);
                let authorization = match stepup.authorization {
                    Ok(a) => a,
                    Err(Error::Authentication) => {
                        let failure = throttle
                            .record_failure(context, account.as_str())
                            .map_err(|_| Error::Unavailable)?;
                        audit_events.extend(failure.audit_events);
                        return Err(if failure.lockout_engaged {
                            Error::Throttled
                        } else {
                            Error::Authentication
                        });
                    }
                    Err(e) => return Err(e),
                };
                audit_events.extend(
                    throttle
                        .clear_success(context, account.as_str())
                        .map_err(|_| Error::Unavailable)?,
                );
                sessions
                    .recheck_guarded_session(&current)
                    .map_err(guarded_error)?;
                if matches!(
                    request.action,
                    key_management::Action::ImportPersonal { .. }
                ) {
                    // Reaching this branch requires the same actual primary
                    // and replay-protected factor verification as public writes.
                    drop(authorization);
                    return self.personal_key_change(&current, &request);
                }
                key_management::mutate(
                    &backend,
                    &BindingStore::new(self.settings_dir.join("openpgp-bindings")),
                    authorization,
                    context,
                    &current,
                    &request,
                    crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
                )
            })
            .map_err(guarded_error)
            .and_then(std::convert::identity);
        let mut event = build_http_info_event(
            if result.is_ok() {
                "openpgp_key_change_confirmed"
            } else {
                "openpgp_key_change_refused"
            },
            "OpenPGP key management evaluated",
            context,
        )
        .with_field("result", format!("{result:?}"));
        if let Some((operation, native_result, certificate_bytes)) = native_diagnostic.get() {
            // Only source-owned enums and bounded byte accounting. Never log
            // certificate bodies, credentials, factors, grants or native text.
            event = event
                .with_field("native_operation", operation)
                .with_field("native_result", format!("{native_result:?}"));
            if let Some(bytes) = certificate_bytes {
                event = event.with_field("public_certificate_bytes", bytes.to_string());
            }
        }
        audit_events.push(event);
        if result.is_ok() {
            use crate::notifications::NotificationKind as K;
            let kind = match &request.action {
                key_management::Action::ImportPublic { .. } => K::PublicKeyImported,
                key_management::Action::RemovePublic { .. } => K::PublicKeyRemoved,
                key_management::Action::ImportPersonal { .. } => K::PersonalKeyImported,
                key_management::Action::UnlockPersonal { .. } => K::PersonalKeyUnlocked,
                key_management::Action::LockPersonal => K::PersonalKeyLocked,
                _ => K::PolicyChanged,
            };
            // Each fresh authorization acknowledges one operation. Request IDs
            // restart with Web and cannot serve as durable operation identities.
            if crate::notifications::NotificationStore::new(&self.settings_dir)
                .record(
                    &session.record.canonical_username,
                    kind,
                    crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
                )
                .is_err()
            {
                audit_events.push(build_http_warning_event(
                    "notification_recording_unconfirmed",
                    "the key operation result is unchanged; its notice could not be confirmed",
                    context,
                ));
            }
        }
        MutationOutcome {
            result,
            audit_events,
        }
    }
}

fn guarded_error(error: crate::session::GuardedSessionError) -> Error {
    match error {
        crate::session::GuardedSessionError::Inactive => Error::Authentication,
        crate::session::GuardedSessionError::Unavailable => Error::Unavailable,
    }
}
