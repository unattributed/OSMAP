//! Browser key mutations reuse real password/TOTP services, never session-only approval.
use super::*;
use crate::identity::CanonicalUsername;
use crate::key_management::{
    self, Error, MutationOutcome, MutationRequest, PublicKeyBackend, State, StateOutcome,
};
use crate::openpgp_bindings::BindingStore;
struct KeyBackend<'a> {
    inventory: Option<&'a crate::openpgp_inventory_runtime::Client>,
    admin: Option<&'a crate::openpgp_public_admin_runtime::Client>,
}
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
            return admin
                .snapshot(account)
                .map(|snapshot| snapshot.inventory)
                .map_err(admin_error);
        }
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
        self.admin
            .ok_or(Error::Unavailable)?
            .import_public(
                account,
                expected_public_revision,
                primary_fingerprint,
                certificate,
            )
            .map(|_| ())
            .map_err(admin_error)
    }
    fn remove_public(
        &self,
        account: &str,
        expected_public_revision: &str,
        primary_fingerprint: &str,
    ) -> Result<(), Error> {
        self.admin
            .ok_or(Error::Unavailable)?
            .remove_public(account, expected_public_revision, primary_fingerprint)
            .map(|_| ())
            .map_err(admin_error)
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
            if let Some(snapshot) = self
                .public_admin_client
                .as_ref()
                .and_then(|c| c.snapshot(account.as_str()).ok())
                .filter(|s| s.inventory.keys().is_some())
            {
                state.inventory = Some(snapshot.inventory);
                state.public_inventory_revision = Some(snapshot.revision);
            } else {
                state.inventory = self
                    .public_inventory_client
                    .as_ref()
                    .and_then(|c| c.read(account.as_str()).ok())
                    .filter(|i| i.keys().is_some());
            }
            state.binding_changes_available = state.bindings.is_some() && state.inventory.is_some();
            state.public_key_changes_available = state.binding_changes_available
                && state.public_inventory_revision.is_some()
                && self.public_admin_client.is_some();
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
            let backend = KeyBackend {
                inventory: self.public_inventory_client.as_ref(),
                admin: self.public_admin_client.as_ref(),
            };
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
                &backend,
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
                "openpgp_key_change_confirmed"
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
