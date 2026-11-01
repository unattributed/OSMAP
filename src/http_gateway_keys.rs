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
