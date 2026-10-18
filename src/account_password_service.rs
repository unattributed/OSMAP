//! Rust-owned password transaction orchestration. No listener or native
//! activation is provided here. Concrete dependencies are trusted helper code;
//! request fields cannot supply an authorization or containment result.
use crate::account_mutation::{Outcome, Request, Verifier};
use crate::account_password_backend::{Backend, Error as BackendError};
use crate::account_password_state::{Guard, State, Store};
use crate::auth::CommandExecutor;
use crate::totp::TimeProvider;
use std::cell::Cell;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DependencyError {
    /// A measured refusal with no uncertain dependency side effect.
    Refused,
    Unavailable,
}

/// Fixed helper implementations must perform the named operation and validate
/// its exact result. None of these methods is populated from a wire Boolean.
pub(crate) trait Dependencies {
    fn authorize(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError>;
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        deadline: Instant,
    ) -> Result<bool, DependencyError>;
    fn preflight(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError>;
    /// Durable account pending must precede the independent issuer ACK.
    fn confirm_pending(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError>;
    fn before_write(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError>;
    fn invalidate_cache(&self, account: &str, deadline: Instant) -> Result<(), DependencyError>;
    fn finish_mail(&self, account: &str, deadline: Instant) -> Result<(), DependencyError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Authentication,
    Expired,
    Unavailable,
}

pub(crate) struct Service<'a, E, D, C> {
    store: &'a Store,
    backend: &'a Backend<E>,
    dependencies: &'a D,
    clock: &'a C,
    key: Vec<u8>,
    verifier: Verifier,
}
impl<'a, E: CommandExecutor, D: Dependencies, C: TimeProvider> Service<'a, E, D, C> {
    pub(crate) fn new(
        store: &'a Store,
        backend: &'a Backend<E>,
        dependencies: &'a D,
        clock: &'a C,
        key: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            store,
            backend,
            dependencies,
            clock,
            key: if (32..=1024).contains(&key.as_ref().len()) {
                key.as_ref().to_vec()
            } else {
                Vec::new()
            },
            verifier: Verifier::default(),
        }
    }

    /// Returns the authenticated consumed request solely so the fixed server
    /// can issue its matching signed response. An error has no success meaning.
    pub(crate) fn execute(
        &mut self,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(Request, Outcome), Error> {
        let began = Instant::now();
        if !(32..=1024).contains(&self.key.len()) {
            return Err(Error::Authentication);
        }
        if deadline <= began || deadline > began + Duration::from_secs(60) {
            return Err(Error::Expired);
        }
        let now = self.clock.unix_timestamp();
        let request =
            self.verifier
                .request(frame, &self.key, now)
                .map_err(|error| match error {
                    crate::account_mutation::Error::Expired => Error::Expired,
                    _ => Error::Authentication,
                })?;
        let mut sampled = now;
        self.fresh(&request, deadline, &mut sampled)?;
        let outcome = self.change(&request, deadline, &mut sampled)?;
        Ok((request, outcome))
    }

    fn fresh(&self, request: &Request, deadline: Instant, sampled: &mut u64) -> Result<(), Error> {
        let now = self.clock.unix_timestamp();
        if Instant::now() >= deadline
            || now < *sampled
            || now < request.issued()
            || now >= request.expires()
        {
            return Err(Error::Expired);
        }
        *sampled = now;
        Ok(())
    }

    fn change(
        &self,
        request: &Request,
        deadline: Instant,
        sampled: &mut u64,
    ) -> Result<Outcome, Error> {
        let mut guard = self
            .store
            .lock_before(request.account(), deadline)
            .map_err(|_| Error::Unavailable)?;
        if guard.admission(Some(request.epoch())).is_err() {
            return match guard.status().map_err(|_| Error::Unavailable)?.state {
                State::Active => Ok(Outcome::KnownRefused),
                State::Pending | State::Contained => Ok(Outcome::Contained),
            };
        }
        self.fresh(request, deadline, sampled)?;
        match self.dependencies.authorize(request, deadline) {
            Ok(()) => {}
            Err(DependencyError::Refused) => return Ok(Outcome::KnownRefused),
            Err(DependencyError::Unavailable) => return Err(Error::Unavailable),
        }
        self.fresh(request, deadline, sampled)?;
        // No separate journal is necessary: this durable pending transition
        // consumes the action before any primary/read/preflight dispatch. A
        // settled no-write refusal restores active while retaining the intent.
        if guard
            .begin(request.epoch(), request.intent_reference(), *sampled)
            .is_err()
        {
            return match guard.status().map_err(|_| Error::Unavailable)?.state {
                State::Active => Ok(Outcome::KnownRefused),
                _ => Ok(Outcome::Contained),
            };
        }
        let prepare = (|| {
            self.fresh(request, deadline, sampled)
                .map_err(|_| DependencyError::Unavailable)?;
            match self
                .dependencies
                .authenticate(request.account(), request.current(), deadline)?
            {
                true => {}
                false => return Err(DependencyError::Refused),
            }
            self.fresh(request, deadline, sampled)
                .map_err(|_| DependencyError::Unavailable)?;
            let snapshot = self
                .backend
                .read(request.account(), deadline)
                .map_err(|_| DependencyError::Refused)?;
            self.fresh(request, deadline, sampled)
                .map_err(|_| DependencyError::Unavailable)?;
            self.dependencies.preflight(request, deadline)?;
            self.fresh(request, deadline, sampled)
                .map_err(|_| DependencyError::Unavailable)?;
            Ok(snapshot)
        })();
        let snapshot = match prepare {
            Ok(snapshot) => snapshot,
            Err(DependencyError::Refused) => return Ok(no_write(&mut guard)),
            Err(DependencyError::Unavailable) => return Ok(contained(&mut guard, None)),
        };
        // Losing the pending/issuer handshake never reopens the old authority,
        // even though the credential SQL has not yet been dispatched.
        if self
            .dependencies
            .confirm_pending(request, deadline)
            .is_err()
            || self.fresh(request, deadline, sampled).is_err()
        {
            return Ok(contained(&mut guard, None));
        }
        let callback_uncertain = Cell::new(false);
        let replaced = self.backend.replace(snapshot, request, deadline, || {
            if self.fresh(request, deadline, sampled).is_err() {
                callback_uncertain.set(true);
                return Err(BackendError::Refused);
            }
            match self.dependencies.before_write(request, deadline) {
                Ok(()) => {}
                Err(error) => {
                    callback_uncertain.set(error == DependencyError::Unavailable);
                    return Err(BackendError::Refused);
                }
            }
            if self.fresh(request, deadline, sampled).is_err() {
                callback_uncertain.set(true);
                return Err(BackendError::Refused);
            }
            Ok(())
        });
        let receipt = match replaced {
            Ok(receipt) => receipt,
            Err(BackendError::Refused) if !callback_uncertain.get() => {
                return Ok(no_write(&mut guard))
            }
            Err(BackendError::Refused) => return Ok(contained(&mut guard, None)),
            Err(BackendError::Unconfirmed { changed_at }) => {
                if let Some(stamp) = &changed_at {
                    let _ = guard.record_verified_write(stamp);
                }
                return Ok(contained(&mut guard, changed_at));
            }
        };
        let stamp = receipt.changed_at().to_owned();
        // Persist verified write timing BEFORE cache/auth/mail operations.
        if guard.record_verified_write(&stamp).is_err() {
            return Ok(contained(&mut guard, Some(stamp)));
        }
        let finish = (|| {
            self.fresh(request, deadline, sampled)?;
            self.dependencies
                .invalidate_cache(request.account(), deadline)
                .map_err(|_| Error::Unavailable)?;
            self.fresh(request, deadline, sampled)?;
            if self
                .dependencies
                .authenticate(request.account(), request.current(), deadline)
                .map_err(|_| Error::Unavailable)?
            {
                return Err(Error::Unavailable);
            }
            self.fresh(request, deadline, sampled)?;
            if !self
                .dependencies
                .authenticate(request.account(), request.new_password(), deadline)
                .map_err(|_| Error::Unavailable)?
            {
                return Err(Error::Unavailable);
            }
            self.fresh(request, deadline, sampled)?;
            self.dependencies
                .finish_mail(request.account(), deadline)
                .map_err(|_| Error::Unavailable)?;
            self.fresh(request, deadline, sampled)?;
            let status = guard.complete().map_err(|_| Error::Unavailable)?;
            if status.state != State::Active
                || status.epoch != request.epoch() + 1
                || status.changed_at.as_deref() != Some(stamp.as_str())
            {
                return Err(Error::Unavailable);
            }
            Ok(status)
        })();
        match finish {
            Ok(status) => Ok(Outcome::Changed {
                epoch: status.epoch,
                changed_at: stamp,
            }),
            Err(_) => Ok(contained(&mut guard, Some(stamp))),
        }
    }
}

fn no_write(guard: &mut Guard<'_>) -> Outcome {
    if guard.known_refused().is_ok() {
        Outcome::KnownRefused
    } else {
        contained(guard, None)
    }
}
fn contained(guard: &mut Guard<'_>, stamp: Option<String>) -> Outcome {
    // A failed final persistence leaves the already-created safety marker or
    // pending state intact; never restore credentials or repeat the SQL.
    let _ = guard.contain();
    match stamp {
        Some(changed_at) => Outcome::ChangedIncomplete { changed_at },
        None => Outcome::Contained,
    }
}

#[cfg(test)]
#[path = "account_password_service_tests.rs"]
mod tests;
