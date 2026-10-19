//! Concrete password runtime composition. Fixed startup supplies the existing
//! epoch store, private keys, connector identity and a native-produced submission
//! namespace. This module neither provisions those authorities nor qualifies an
//! absent producer. No Python worker or caller success flag is used.
use crate::account_password_backend::Backend;
use crate::account_password_connection::{self, Effects, Keys};
use crate::account_password_imap::Registry;
use crate::account_password_mail::{self as mail, SubmissionControl, SubmissionNamespace};
use crate::account_password_policy::{Fence, MonotonicClock};
use crate::account_password_service::DependencyError;
use crate::account_password_state::Store;
use crate::auth::CommandExecutor;
use crate::totp::SystemTimeProvider;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Unavailable;

/// Policy callbacks and mutations necessarily share this same Store instance.
/// Namespace construction/recheck remains the concrete root-owned topology and
/// daemon custody producer; a proxy-list response alone cannot construct it.
#[allow(dead_code)] // Historical private-ingress adapter retained for scoped tests.
pub(crate) struct Runtime {
    store: Arc<Store>,
    accounts: BTreeSet<String>,
    policy: Arc<Fence<MonotonicClock>>,
    namespace: SubmissionNamespace,
    keys: Keys,
    admission_key: Vec<u8>,
    connector_uid: u32,
    imap: Arc<Registry>,
}
#[allow(dead_code)]
impl Runtime {
    #[allow(clippy::too_many_arguments)] // Explicit independent authority/lifetime inputs.
    pub(crate) fn from_authorities(
        store: Arc<Store>,
        accounts: BTreeSet<String>,
        policy: Arc<Fence<MonotonicClock>>,
        namespace: SubmissionNamespace,
        keys: Keys,
        admission_key: &[u8],
        connector_uid: u32,
        imap: Arc<Registry>,
    ) -> Result<Self, Unavailable> {
        if !(32..=1024).contains(&admission_key.len())
            || connector_uid == 0
            || connector_uid == u32::MAX
            || !policy.bound_to(&store, &accounts)
        {
            return Err(Unavailable);
        }
        Ok(Self {
            store,
            accounts,
            policy,
            namespace,
            keys,
            admission_key: admission_key.into(),
            connector_uid,
            imap,
        })
    }

    /// Called by the existing root admission listener AFTER its persistent
    /// Verifier consumed the exact authenticated request/nonce. This preserves
    /// the existing listener replay boundary rather than resetting it per call.
    pub(crate) fn admission<E: CommandExecutor>(
        &self,
        request: &crate::account_admission::Request,
        primary: &E,
        original_deadline: Instant,
    ) -> Result<
        Option<crate::account_password_admission::AdmissionStatus>,
        crate::account_admission::Error,
    > {
        crate::account_password_admission::execute_current(
            self.store.as_ref(),
            primary,
            &SystemTimeProvider,
            &self.admission_key,
            self.accounts.clone(),
            request,
            original_deadline,
        )
    }

    /// The root process supplies independently confined SQL/hash, private
    /// primary and control executors, all bound to this operation's original
    /// deadline. No command/profile path is selected by an incoming frame.
    pub(crate) fn mutation<E: CommandExecutor, P: CommandExecutor, A: CommandExecutor>(
        &self,
        stream: UnixStream,
        backend: &Backend<E>,
        primary: &P,
        control: &A,
        original_deadline: Instant,
    ) -> Result<(), account_password_connection::Error> {
        let effects = NativeEffects {
            primary,
            control,
            namespace: &self.namespace,
            policy: &self.policy,
            imap: &self.imap,
            account: RefCell::new(None),
            submission: RefCell::new(None),
            phase: Cell::new(Phase::New),
            epoch: Cell::new(None),
        };
        account_password_connection::serve_once(
            stream,
            self.connector_uid,
            self.store.as_ref(),
            backend,
            &effects,
            &SystemTimeProvider,
            &self.keys,
            original_deadline,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Ready,
    WriteAdmitted,
    FlushDispatched,
    Flushed,
    #[allow(dead_code)] // Only the historical adapter terminates external mail.
    Terminating,
    Finished,
}
#[allow(dead_code)]
struct NativeEffects<'a, P, A> {
    primary: &'a P,
    control: &'a A,
    namespace: &'a SubmissionNamespace,
    policy: &'a Fence<MonotonicClock>,
    imap: &'a Registry,
    account: RefCell<Option<String>>,
    submission: RefCell<Option<SubmissionControl<'a, A>>>,
    phase: Cell<Phase>,
    epoch: Cell<Option<u64>>,
}
#[allow(dead_code)]
impl<P: CommandExecutor, A: CommandExecutor> NativeEffects<'_, P, A> {
    fn owns(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        if Instant::now() >= deadline || !self.policy.manages(account) {
            return Err(DependencyError::Refused);
        }
        let mut selected = self
            .account
            .try_borrow_mut()
            .map_err(|_| DependencyError::Unavailable)?;
        match selected.as_deref() {
            None if self.phase.get() == Phase::New => {
                *selected = Some(account.into());
                Ok(())
            }
            Some(own) if own == account => Ok(()),
            _ => Err(DependencyError::Refused),
        }
    }
    fn topology(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        self.owns(account, deadline)?;
        self.namespace
            .recheck(account, deadline)
            .map_err(|_| DependencyError::Unavailable)
    }
}
impl<P: CommandExecutor, A: CommandExecutor> Effects for NativeEffects<'_, P, A> {
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        deadline: Instant,
    ) -> Result<bool, DependencyError> {
        self.owns(account, deadline)?;
        // Fixed private auth service bypasses recursive policy/cache only;
        // its passdb remains the authoritative Dovecot credential backend.
        mail::primary(self.primary, account, password, deadline)
            .map_err(|_| DependencyError::Unavailable)
    }
    fn preflight(
        &self,
        request: &crate::account_mutation::Request,
        deadline: Instant,
    ) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::New {
            return Err(DependencyError::Refused);
        }
        self.topology(request.account(), deadline)?;
        self.imap
            .preflight(self.control, request.account(), request.epoch(), deadline)
            .map_err(|_| DependencyError::Refused)?;
        self.epoch.set(Some(request.epoch()));
        let mut submission =
            SubmissionControl::new(self.control, self.namespace, request.account())
                .map_err(|_| DependencyError::Unavailable)?;
        submission
            .preflight(deadline)
            .map_err(|_| DependencyError::Unavailable)?;
        self.topology(request.account(), deadline)?;
        *self
            .submission
            .try_borrow_mut()
            .map_err(|_| DependencyError::Unavailable)? = Some(submission);
        self.phase.set(Phase::Ready);
        Ok(())
    }
    fn before_write(
        &self,
        request: &crate::account_mutation::Request,
        deadline: Instant,
    ) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::Ready {
            return Err(DependencyError::Refused);
        }
        self.topology(request.account(), deadline)?;
        self.imap
            .preflight(self.control, request.account(), request.epoch(), deadline)
            .map_err(|_| DependencyError::Refused)?;
        self.phase.set(Phase::WriteAdmitted);
        Ok(())
    }
    fn invalidate_cache(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::WriteAdmitted {
            return Err(DependencyError::Unavailable);
        }
        self.topology(account, deadline)?;
        self.phase.set(Phase::FlushDispatched);
        mail::flush(self.control, account, deadline).map_err(|_| DependencyError::Unavailable)?;
        self.topology(account, deadline)?;
        self.phase.set(Phase::Flushed);
        Ok(())
    }
    fn finish_mail(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::Flushed {
            return Err(DependencyError::Unavailable);
        }
        self.topology(account, deadline)?;
        self.phase.set(Phase::Terminating);
        self.submission
            .try_borrow_mut()
            .map_err(|_| DependencyError::Unavailable)?
            .as_mut()
            .ok_or(DependencyError::Unavailable)?
            .terminate(deadline)
            .map_err(|_| DependencyError::Unavailable)?;
        self.topology(account, deadline)?;
        self.imap
            .terminate(
                self.control,
                account,
                self.epoch.get().ok_or(DependencyError::Unavailable)?,
                deadline,
            )
            .map_err(|_| DependencyError::Unavailable)?;
        self.topology(account, deadline)?;
        self.phase.set(Phase::Finished);
        Ok(())
    }
}

/// Scoped existing-backend adapter. The same Store and exact operator allowlist
/// govern login and mutation; existing external mail sessions are not revoked.
pub(crate) struct StockRuntime {
    store: Arc<Store>,
    accounts: BTreeSet<String>,
    keys: Keys,
    admission_key: Vec<u8>,
    connector_uid: u32,
    peer: Arc<crate::account_password_peer::StockPeer>,
}
impl StockRuntime {
    pub(crate) fn new(
        store: Arc<Store>,
        accounts: BTreeSet<String>,
        keys: Keys,
        admission_key: &[u8],
        connector_uid: u32,
        peer: Arc<crate::account_password_peer::StockPeer>,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        if !(32..=1024).contains(&admission_key.len())
            || connector_uid == 0
            || connector_uid == u32::MAX
            || accounts.is_empty()
            || accounts.len() > 64
            || accounts
                .iter()
                .any(|a| crate::account_admission::valid_account(a).is_err())
        {
            return Err(Unavailable);
        }
        peer.recheck(deadline).map_err(|_| Unavailable)?;
        Ok(Self {
            store,
            accounts,
            keys,
            admission_key: admission_key.into(),
            connector_uid,
            peer,
        })
    }
    pub(crate) fn admission<E: CommandExecutor>(
        &self,
        request: &crate::account_admission::Request,
        executor: &E,
        deadline: Instant,
    ) -> Result<
        Option<crate::account_password_admission::AdmissionStatus>,
        crate::account_admission::Error,
    > {
        self.peer
            .recheck(deadline)
            .map_err(|_| crate::account_admission::Error::Unavailable)?;
        crate::account_password_admission::execute_current(
            self.store.as_ref(),
            executor,
            &SystemTimeProvider,
            &self.admission_key,
            self.accounts.clone(),
            request,
            deadline,
        )
    }
    pub(crate) fn mutation<E: CommandExecutor, P: CommandExecutor>(
        &self,
        stream: UnixStream,
        backend: &Backend<E>,
        primary: &P,
        deadline: Instant,
    ) -> Result<(), account_password_connection::Error> {
        let effects = StockEffects {
            primary,
            peer: &self.peer,
            accounts: &self.accounts,
            account: RefCell::new(None),
            phase: Cell::new(Phase::New),
        };
        account_password_connection::serve_once(
            stream,
            self.connector_uid,
            self.store.as_ref(),
            backend,
            &effects,
            &SystemTimeProvider,
            &self.keys,
            deadline,
        )
    }
}
struct StockEffects<'a, P> {
    primary: &'a P,
    peer: &'a crate::account_password_peer::StockPeer,
    accounts: &'a BTreeSet<String>,
    account: RefCell<Option<String>>,
    phase: Cell<Phase>,
}
impl<P: CommandExecutor> StockEffects<'_, P> {
    fn current(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        if Instant::now() >= deadline || !self.accounts.contains(account) {
            return Err(DependencyError::Refused);
        }
        let mut selected = self
            .account
            .try_borrow_mut()
            .map_err(|_| DependencyError::Unavailable)?;
        match selected.as_deref() {
            None if self.phase.get() == Phase::New => *selected = Some(account.into()),
            Some(own) if own == account => {}
            _ => return Err(DependencyError::Refused),
        }
        self.peer
            .recheck(deadline)
            .map_err(|_| DependencyError::Unavailable)
    }
}
impl<P: CommandExecutor> Effects for StockEffects<'_, P> {
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        deadline: Instant,
    ) -> Result<bool, DependencyError> {
        self.current(account, deadline)?;
        mail::primary(self.primary, account, password, deadline)
            .map_err(|_| DependencyError::Unavailable)
    }
    fn preflight(
        &self,
        request: &crate::account_mutation::Request,
        deadline: Instant,
    ) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::New {
            return Err(DependencyError::Refused);
        }
        self.current(request.account(), deadline)?;
        self.phase.set(Phase::Ready);
        Ok(())
    }
    fn before_write(
        &self,
        request: &crate::account_mutation::Request,
        deadline: Instant,
    ) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::Ready {
            return Err(DependencyError::Refused);
        }
        self.current(request.account(), deadline)?;
        self.phase.set(Phase::WriteAdmitted);
        Ok(())
    }
    fn invalidate_cache(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        if self.phase.get() != Phase::WriteAdmitted {
            return Err(DependencyError::Unavailable);
        }
        self.current(account, deadline)?;
        self.phase.set(Phase::FlushDispatched);
        // Source-bound actual public daemon cache_size=0; no fictitious flush.
        self.peer
            .recheck(deadline)
            .map_err(|_| DependencyError::Unavailable)?;
        self.current(account, deadline)?;
        self.phase.set(Phase::Flushed);
        Ok(())
    }
    fn finish_mail(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        // Existing service invokes this only after verified cache0 + old-password
        // rejection + new-password acceptance. It conveys no external lifetime claim.
        if self.phase.get() != Phase::Flushed {
            return Err(DependencyError::Unavailable);
        }
        self.current(account, deadline)?;
        self.phase.set(Phase::Finished);
        Ok(())
    }
}
