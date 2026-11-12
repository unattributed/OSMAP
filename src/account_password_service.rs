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

// Fixed per-request phases share the existing service stderr channel. No
// request field, exception text or native stream is formatted into this record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionPhase {
    Input,
    Freshness,
    Admission,
    Authorize,
    Begin,
    SnapshotRead,
    Authenticate,
    Preflight,
    PendingAck,
    Hash,
    BeforeWrite,
    Cas,
    WriteTime,
    Cache,
    OldVerifier,
    NewVerifier,
    Mail,
    EpochComplete,
}
impl TransactionPhase {
    fn tag(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Freshness => "freshness",
            Self::Admission => "admission",
            Self::Authorize => "authorize",
            Self::Begin => "begin",
            Self::SnapshotRead => "snapshot_read",
            Self::Authenticate => "authenticate",
            Self::Preflight => "preflight",
            Self::PendingAck => "pending_ack",
            Self::Hash => "hash",
            Self::BeforeWrite => "before_write",
            Self::Cas => "cas",
            Self::WriteTime => "write_time",
            Self::Cache => "cache",
            Self::OldVerifier => "old_verifier",
            Self::NewVerifier => "new_verifier",
            Self::Mail => "mail",
            Self::EpochComplete => "epoch_complete",
        }
    }
    fn backend(self) -> bool {
        matches!(
            self,
            Self::SnapshotRead | Self::Hash | Self::BeforeWrite | Self::Cas
        )
    }
}
fn write_transaction_diagnostic(
    output: &mut impl std::io::Write,
    phase: TransactionPhase,
    result: &Result<(Request, Outcome), Error>,
) -> std::io::Result<()> {
    let outcome = match result {
        Ok((_, Outcome::Changed { .. })) => return Ok(()),
        Ok((_, Outcome::KnownRefused)) => "known_refused",
        Ok((_, Outcome::Contained)) => "contained",
        Ok((_, Outcome::ChangedIncomplete { .. })) => "changed_incomplete",
        Err(Error::Authentication) => "authentication",
        Err(Error::Expired) => "expired",
        Err(Error::Unavailable) => "unavailable",
    };
    // The old native scalars are progress observations, not inferred causes.
    // Omit irrelevant/stale command observations on non-backend phases.
    let [stage, errno, status, stdout, stderr, sql_code] = if phase.backend() {
        crate::account_password_process::native_sql_read_diagnostic()
    } else {
        [0, -1, -1, -1, -1, 0]
    };
    let [child_pid, term_signal] = if phase.backend() {
        crate::account_password_process::native_sql_child_diagnostic()
    } else {
        [0, -1]
    };
    let bounded = |value, low, high, unknown| {
        if (low..=high).contains(&value) {
            value
        } else {
            unknown
        }
    };
    let parser = if phase == TransactionPhase::SnapshotRead {
        let value = crate::account_password_backend::native_read_diagnostic();
        if value <= 11 {
            value
        } else {
            0
        }
    } else {
        0
    };
    writeln!(output,
        "account_password_service stage=transaction_{} outcome={} process_stage={} errno={} status={} stdout_bytes={} stderr_bytes={} sql_code={} parser_phase={} child_pid={} term_signal={}",
        phase.tag(), outcome, bounded(stage,0,9,0), bounded(errno,0,4095,-1),
        bounded(status,0,255,-1), bounded(stdout,0,65537,-1), bounded(stderr,0,65537,-1),
        bounded(sql_code,1000,9999,0), parser, bounded(child_pid,2,i64::from(i32::MAX),0), bounded(term_signal,0,127,-1))
}

pub(crate) struct Service<'a, E, D, C> {
    store: &'a Store,
    backend: &'a Backend<E>,
    dependencies: &'a D,
    clock: &'a C,
    key: Vec<u8>,
    verifier: Verifier,
    diagnostic_phase: Cell<TransactionPhase>,
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
            diagnostic_phase: Cell::new(TransactionPhase::Input),
        }
    }

    /// Returns the authenticated consumed request solely so the fixed server
    /// can issue its matching signed response. An error has no success meaning.
    pub(crate) fn execute(
        &mut self,
        frame: &[u8],
        deadline: Instant,
    ) -> Result<(Request, Outcome), Error> {
        self.diagnostic_phase.set(TransactionPhase::Input);
        crate::account_password_backend::reset_native_read_diagnostic();
        crate::account_password_process::reset_native_sql_read_diagnostic();
        let result = self.execute_inner(frame, deadline);
        // Exactly one diagnostic precedes the terminal reply. Settlement and
        // containment never overwrite the phase of the first failed operation.
        let _ = write_transaction_diagnostic(
            &mut std::io::stderr().lock(),
            self.diagnostic_phase.get(),
            &result,
        );
        result
    }
    fn execute_inner(
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
        self.diagnostic_phase.set(TransactionPhase::Freshness);
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
            self.diagnostic_phase.set(TransactionPhase::Freshness);
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
        self.diagnostic_phase.set(TransactionPhase::Admission);
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
        self.diagnostic_phase.set(TransactionPhase::Authorize);
        match self.dependencies.authorize(request, deadline) {
            Ok(()) => {}
            Err(DependencyError::Refused) => return Ok(Outcome::KnownRefused),
            Err(DependencyError::Unavailable) => return Err(Error::Unavailable),
        }
        self.fresh(request, deadline, sampled)?;
        // No separate journal is necessary: this durable pending transition
        // consumes the action before any primary/read/preflight dispatch. A
        // settled no-write refusal restores active while retaining the intent.
        self.diagnostic_phase.set(TransactionPhase::Begin);
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
            // Keep the comparison row from before authoritative authentication.
            // A concurrent external credential change must conflict with this
            // snapshot at the existing CAS, rather than become its new baseline.
            self.diagnostic_phase.set(TransactionPhase::SnapshotRead);
            let snapshot = self
                .backend
                .read(request.account(), deadline)
                .map_err(|_| DependencyError::Refused)?;
            self.fresh(request, deadline, sampled)
                .map_err(|_| DependencyError::Unavailable)?;
            self.diagnostic_phase.set(TransactionPhase::Authenticate);
            match self
                .dependencies
                .authenticate(request.account(), request.current(), deadline)?
            {
                true => {}
                false => return Err(DependencyError::Refused),
            }
            self.fresh(request, deadline, sampled)
                .map_err(|_| DependencyError::Unavailable)?;
            self.diagnostic_phase.set(TransactionPhase::Preflight);
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
        self.diagnostic_phase.set(TransactionPhase::PendingAck);
        if self
            .dependencies
            .confirm_pending(request, deadline)
            .is_err()
            || self.fresh(request, deadline, sampled).is_err()
        {
            return Ok(contained(&mut guard, None));
        }
        let callback_uncertain = Cell::new(false);
        self.diagnostic_phase.set(TransactionPhase::Hash);
        let replaced = self.backend.replace(snapshot, request, deadline, || {
            self.diagnostic_phase.set(TransactionPhase::BeforeWrite);
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
            self.diagnostic_phase.set(TransactionPhase::Cas);
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
        self.diagnostic_phase.set(TransactionPhase::WriteTime);
        if guard.record_verified_write(&stamp).is_err() {
            return Ok(contained(&mut guard, Some(stamp)));
        }
        let finish = (|| {
            self.fresh(request, deadline, sampled)?;
            self.diagnostic_phase.set(TransactionPhase::Cache);
            self.dependencies
                .invalidate_cache(request.account(), deadline)
                .map_err(|_| Error::Unavailable)?;
            self.fresh(request, deadline, sampled)?;
            self.diagnostic_phase.set(TransactionPhase::OldVerifier);
            if self
                .dependencies
                .authenticate(request.account(), request.current(), deadline)
                .map_err(|_| Error::Unavailable)?
            {
                return Err(Error::Unavailable);
            }
            self.fresh(request, deadline, sampled)?;
            self.diagnostic_phase.set(TransactionPhase::NewVerifier);
            if !self
                .dependencies
                .authenticate(request.account(), request.new_password(), deadline)
                .map_err(|_| Error::Unavailable)?
            {
                return Err(Error::Unavailable);
            }
            self.fresh(request, deadline, sampled)?;
            self.diagnostic_phase.set(TransactionPhase::Mail);
            self.dependencies
                .finish_mail(request.account(), deadline)
                .map_err(|_| Error::Unavailable)?;
            self.fresh(request, deadline, sampled)?;
            self.diagnostic_phase.set(TransactionPhase::EpochComplete);
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
