//! Browser key mutations reuse real password/TOTP services, never session-only approval.
use super::*;
use crate::identity::CanonicalUsername;
use crate::key_management::{
    self, Error, MutationOutcome, MutationRequest, PublicKeyBackend, State, StateOutcome,
};
use crate::openpgp_bindings::BindingStore;
impl PublicKeyBackend for crate::openpgp_inventory_runtime::Client {
    fn read(&self, account: &str) -> Result<crate::openpgp_inventory::Inventory, Error> {
        self.read(account).map_err(|_| Error::Unavailable)
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
            state.bindings = BindingStore::new(self.settings_dir.join("openpgp-bindings"))
                .load(account.as_str())
                .ok();
            state.inventory = self
                .public_inventory_client
                .as_ref()
                .and_then(|c| c.read(account.as_str()).ok())
                .filter(|i| i.keys().is_some());
            state.binding_changes_available = state.bindings.is_some() && state.inventory.is_some();
            // Public inventory writes await the separate native admin protocol
            // and account-serialized binding/CAS transaction.
            state.public_key_changes_available = false;
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
        request: MutationRequest<'_>,
    ) -> MutationOutcome {
        let mut audit_events = Vec::new();
        let result = (|| {
            let account = CanonicalUsername::parse(&session.record.canonical_username)
                .map_err(|_| Error::Invalid)?;
            let backend = self
                .public_inventory_client
                .as_ref()
                .ok_or(Error::Unavailable)?;
            let throttle = self.build_login_throttle_service();
            let check = throttle
                .check(context, account.as_str())
                .map_err(|_| Error::Unavailable)?;
            audit_events.extend(check.audit_events);
            if matches!(check.decision, LoginThrottleDecision::Throttled { .. }) {
                return Err(Error::Throttled);
            }
            let stepup = key_management::verify_fresh(
                &self.build_auth_service(),
                &self.build_factor_service(),
                context,
                session,
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
            key_management::mutate(
                backend,
                &BindingStore::new(self.settings_dir.join("openpgp-bindings")),
                authorization,
                context,
                session,
                &request,
                crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
            )
        })();
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "openpgp_binding_changed"
            } else {
                "openpgp_key_change_refused"
            },
            "OpenPGP key management evaluated",
            context,
        ));
        MutationOutcome {
            result,
            audit_events,
        }
    }
}
