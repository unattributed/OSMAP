//! Rust replacement for the private Python admission worker's semantics.
//!
//! This primitive uses the existing authenticated admission wire and durable
//! epoch store. Fixed native command custody, listener/peer confinement and
//! rollout installation remain separate; construction enables no client/form.
#[cfg(test)]
use crate::account_admission::Verifier;
use crate::account_admission::{Error, Operation, Request};
use crate::account_password_state::{Error as StateError, Store};
use crate::auth::CommandExecutor;
use crate::totp::TimeProvider;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

pub(crate) type AdmissionStatus = (u64, Option<String>);
pub(crate) struct Service<'a, E, C> {
    store: &'a Store,
    executor: &'a E,
    clock: &'a C,
    key: Vec<u8>,
    accounts: BTreeSet<String>,
    #[cfg(test)]
    verifier: Verifier,
}
impl<'a, E: CommandExecutor, C: TimeProvider> Service<'a, E, C> {
    /// Accounts/key/root are fixed operator service authority, never fields
    /// supplied by an incoming browser or authentication request.
    pub(crate) fn new(
        store: &'a Store,
        executor: &'a E,
        clock: &'a C,
        key: &[u8],
        accounts: BTreeSet<String>,
    ) -> Result<Self, Error> {
        if !(32..=1024).contains(&key.len())
            || accounts.is_empty()
            || accounts.len() > 64
            || accounts
                .iter()
                .any(|account| crate::account_admission::valid_account(account).is_err())
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            executor,
            clock,
            key: key.into(),
            accounts,
            #[cfg(test)]
            verifier: Verifier::default(),
        })
    }
    /// Consume the same signed request/nonce and produce the unchanged client's
    /// authenticated epoch+optional password-write-time response.
    #[cfg(test)]
    pub(crate) fn process(
        &mut self,
        frame: &[u8],
        original_deadline: Instant,
    ) -> Result<Vec<u8>, Error> {
        valid_deadline(original_deadline)?;
        let now = self.clock.unix_timestamp();
        let request = self.verifier.request(frame, &self.key, now)?;
        let status = self.execute_verified(&request, original_deadline)?;
        let at = self.clock.unix_timestamp();
        if at < now || Instant::now() >= original_deadline {
            return Err(Error::Expired);
        }
        let (epoch, changed_at) =
            status.map_or((None, None), |(epoch, stamp)| (Some(epoch), stamp));
        request.response_with_status(epoch, changed_at, &self.key, at)
    }
    /// Callback seam for the existing root-owned authenticated listener. Even
    /// that trusted caller cannot bypass request signature, scope or expiry.
    /// Its listener retains responsibility for consuming the wire nonce once.
    pub(crate) fn execute_verified(
        &self,
        request: &Request,
        original_deadline: Instant,
    ) -> Result<Option<AdmissionStatus>, Error> {
        valid_deadline(original_deadline)?;
        let mut sampled = self.clock.unix_timestamp();
        self.fresh(request, original_deadline, &mut sampled)?;
        if !self.accounts.contains(request.account()) {
            return Err(Error::Refused);
        }
        let status = {
            let guard = self
                .store
                .lock_before(request.account(), original_deadline)
                .map_err(state_error)?;
            let expected = match request.operation() {
                Operation::Admit { epoch } => Some(*epoch),
                Operation::Authenticate { .. } => None,
            };
            let before = match guard.admission(expected) {
                Ok(value) => value,
                Err(StateError::Refused) => return Ok(None),
                Err(error) => return Err(state_error(error)),
            };
            self.fresh(request, original_deadline, &mut sampled)?;
            if let Operation::Authenticate { password } = request.operation() {
                // Held shared epoch flock spans actual current-password
                // authentication; a writer cannot change the credential/epoch
                // between acceptance and the session epoch returned here.
                let accepted = crate::account_password_mail::primary(
                    self.executor,
                    request.account(),
                    password,
                    original_deadline,
                )
                .map_err(|_| Error::Unavailable)?;
                self.fresh(request, original_deadline, &mut sampled)?;
                if !accepted {
                    return Ok(None);
                }
            }
            let after = guard.admission(Some(before.epoch)).map_err(state_error)?;
            self.fresh(request, original_deadline, &mut sampled)?;
            (after.epoch, after.changed_at)
        };
        // Include lock cleanup in the original bound; no renewed phase clock.
        self.fresh(request, original_deadline, &mut sampled)?;
        Ok(Some(status))
    }
    fn fresh(&self, request: &Request, deadline: Instant, sampled: &mut u64) -> Result<(), Error> {
        let now = self.clock.unix_timestamp();
        if now < *sampled || Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        request.valid(&self.key, now)?;
        *sampled = now;
        Ok(())
    }
}
fn valid_deadline(deadline: Instant) -> Result<(), Error> {
    let now = Instant::now();
    if deadline <= now || deadline > now + Duration::from_secs(35) {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn state_error(error: StateError) -> Error {
    match error {
        StateError::Expired => Error::Expired,
        StateError::Refused => Error::Refused,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
#[path = "account_password_admission_tests.rs"]
mod tests;
