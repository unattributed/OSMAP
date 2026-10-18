//! Before/after epoch fences and a one-use IMAP publication ticket.
//!
//! This is a service primitive, not a native policy endpoint or plugin. Managed
//! account scope and the registration observer come only from trusted service
//! construction. No JSON PID, success boolean or report grants publication.
use crate::account_password_state::{Guard, Store};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CAPTURE: Duration = Duration::from_secs(30);
const CALLBACK: Duration = Duration::from_millis(500);
const MAX_ENTRIES: usize = 256;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    Refused,
    Unavailable,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Allow,
    Deny,
}
impl Decision {
    pub(crate) fn body(self) -> &'static [u8] {
        match self {
            Self::Allow => b"{\"status\":0}",
            Self::Deny => b"{\"status\":-1}",
        }
    }
}
pub(crate) trait Clock {
    fn now(&self) -> Instant;
}
pub(crate) struct MonotonicClock;
impl Clock for MonotonicClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Before,
    After,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    login: String,
    protocol: String,
    session_id: String,
    phase: Phase,
    tls: bool,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    account: String,
    protocol: String,
    session: String,
    tls: bool,
}
struct Capture {
    epoch: Option<u64>,
    expires: Instant,
    used: bool,
    verified: bool,
}
struct Inner {
    captures: BTreeMap<Key, Capture>,
    last: Option<Instant>,
    clock_failed: bool,
    after_observations: u64,
}

/// Evidence is opaque outside this module. The sole production conversion
/// consumes an opaque observation produced by the native peer inspector after
/// kernel/process custody and actual anvil registration pass under the guard.
pub(crate) struct RegistrationEvidence {
    account: String,
    session: String,
    epoch: u64,
    kernel_pid: u32,
    anvil_pid: u32,
    kernel_uid: u32,
    expected_uid: u32,
    process_birth: u64,
    observed: Instant,
}
impl RegistrationEvidence {
    pub(crate) fn from_native_observation(
        value: crate::account_password_peer::NativeRegistration,
    ) -> Self {
        Self {
            account: value.account().into(),
            session: value.session().into(),
            epoch: value.epoch(),
            kernel_pid: value.pid(),
            anvil_pid: value.pid(),
            kernel_uid: value.uid(),
            expected_uid: value.uid(),
            process_birth: value.birth(),
            observed: value.observed(),
        }
    }
}
#[cfg(test)]
impl RegistrationEvidence {
    pub(crate) fn fixture(
        account: &str,
        session: &str,
        epoch: u64,
        pid: u32,
        observed: Instant,
    ) -> Self {
        Self {
            account: account.into(),
            session: session.into(),
            epoch,
            kernel_pid: pid,
            anvil_pid: pid,
            kernel_uid: 518,
            expected_uid: 518,
            process_birth: 1,
            observed,
        }
    }
}
pub(crate) trait RegistrationObserver {
    fn observe_registration(
        &self,
        guard: &Guard<'_>,
        account: &str,
        session: &str,
        deadline: Instant,
    ) -> Result<RegistrationEvidence, Error>;
}
/// One move-only publication result. Native publication must still consume it
/// in the managed single-client process before tagged IMAP success.
pub(crate) struct Publication {
    account: String,
    session: String,
    epoch: u64,
    pid: u32,
}
impl Publication {
    pub(crate) fn account(&self) -> &str {
        &self.account
    }
    pub(crate) fn session(&self) -> &str {
        &self.session
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

pub(crate) struct Fence<C> {
    store: Arc<Store>,
    accounts: BTreeSet<String>,
    clock: C,
    inner: Mutex<Inner>,
}
impl<C: Clock> Fence<C> {
    /// A cold-start policy and the later mutation runtime must retain the
    /// identical Store and capture map, rather than recreating authorization.
    pub(crate) fn bound_to(&self, store: &Arc<Store>, accounts: &BTreeSet<String>) -> bool {
        Arc::ptr_eq(&self.store, store) && &self.accounts == accounts
    }
    /// Scheduling hint only: never admission or namespace authority.
    pub(crate) fn after_observations(&self) -> Result<u64, Error> {
        Ok(self
            .inner
            .try_lock()
            .map_err(|_| Error::Unavailable)?
            .after_observations)
    }
    pub(crate) fn manages(&self, account: &str) -> bool {
        self.accounts.contains(account)
    }
    pub(crate) fn new(
        store: Arc<Store>,
        accounts: BTreeSet<String>,
        clock: C,
    ) -> Result<Self, Error> {
        if accounts.is_empty()
            || accounts.len() > 64
            || accounts
                .iter()
                .any(|a| crate::account_admission::valid_account(a).is_err())
        {
            return Err(Error::Refused);
        }
        Ok(Self {
            store,
            accounts,
            clock,
            inner: Mutex::new(Inner {
                captures: BTreeMap::new(),
                last: None,
                clock_failed: false,
                after_observations: 0,
            }),
        })
    }
    fn request(&self, body: &[u8]) -> Result<(Key, Phase), Error> {
        if body.is_empty() || body.len() > 4096 {
            return Err(Error::Refused);
        }
        let request: Request = serde_json::from_slice(body).map_err(|_| Error::Refused)?;
        if !self.accounts.contains(&request.login)
            || !matches!(
                request.protocol.as_str(),
                "imap" | "pop3" | "smtp" | "submission"
            )
            || request.session_id.is_empty()
            || request.session_id.len() > 128
            || !request
                .session_id
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"/+_=.-".contains(&v))
        {
            return Err(Error::Refused);
        }
        Ok((
            Key {
                account: request.login,
                protocol: request.protocol,
                session: request.session_id,
                tls: request.tls,
            },
            request.phase,
        ))
    }
    fn now(&self, inner: &mut Inner) -> Result<Instant, Error> {
        let now = self.clock.now();
        if inner.clock_failed || inner.last.is_some_and(|value| now < value) {
            inner.clock_failed = true;
            return Err(Error::Unavailable);
        }
        inner.last = Some(now);
        Ok(now)
    }
    fn callback_deadline(
        &self,
        began: Instant,
        expires: Instant,
        original: Instant,
    ) -> Result<Instant, Error> {
        if original <= began || original > began + CALLBACK {
            return Err(Error::Refused);
        }
        Ok(original.min(expires))
    }
    pub(crate) fn allow(&self, body: &[u8], original_deadline: Instant) -> Decision {
        match self.allow_inner(body, original_deadline) {
            Ok(()) => Decision::Allow,
            Err(_) => Decision::Deny,
        }
    }
    fn allow_inner(&self, body: &[u8], original_deadline: Instant) -> Result<(), Error> {
        let mut inner = self.inner.try_lock().map_err(|_| Error::Unavailable)?;
        let began = self.now(&mut inner)?;
        let (key, phase) = self.request(body)?;
        inner.captures.retain(|_, value| value.expires > began);
        let (epoch, expires) = if phase == Phase::Before {
            if inner.captures.contains_key(&key) || inner.captures.len() >= MAX_ENTRIES {
                return Err(Error::Refused);
            }
            let expires = began + CAPTURE;
            // Reserve a used tombstone before any durable lookup, even when
            // lookup refuses; duplicate before cannot capture a later epoch.
            inner.captures.insert(
                key.clone(),
                Capture {
                    epoch: None,
                    expires,
                    used: true,
                    verified: false,
                },
            );
            (None, expires)
        } else {
            let capture = inner.captures.get_mut(&key).ok_or(Error::Refused)?;
            if capture.used {
                return Err(Error::Refused);
            }
            capture.used = true;
            capture.verified = false;
            (capture.epoch, capture.expires)
        };
        let deadline = self.callback_deadline(began, expires, original_deadline)?;
        let admitted = {
            let guard = self
                .store
                .lock_before(&key.account, deadline)
                .map_err(|_| Error::Unavailable)?;
            let status = guard.admission(epoch).map_err(|_| Error::Refused)?;
            if self.now(&mut inner)? >= deadline {
                return Err(Error::Refused);
            }
            status.epoch
        };
        if self.now(&mut inner)? >= deadline {
            return Err(Error::Refused);
        }
        let capture = inner.captures.get_mut(&key).ok_or(Error::Refused)?;
        if phase == Phase::Before {
            capture.epoch = Some(admitted);
            capture.used = false;
        } else {
            capture.verified = true;
            inner.after_observations = inner
                .after_observations
                .checked_add(1)
                .ok_or(Error::Unavailable)?;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn publish_imap(
        &self,
        body: &[u8],
        observer: &impl RegistrationObserver,
        original_deadline: Instant,
    ) -> Result<Publication, Error> {
        self.publish_imap_inner(body, observer, original_deadline, |_, _| Ok(()))
    }
    pub(crate) fn publish_imap_registered(
        &self,
        body: &[u8],
        observer: &impl RegistrationObserver,
        registry: &crate::account_password_imap::Registry,
        io: crate::account_password_imap::AttestedIo,
        control: std::os::unix::net::UnixStream,
        original_deadline: Instant,
    ) -> Result<Publication, Error> {
        self.publish_imap_inner(body, observer, original_deadline, |guard, publication| {
            registry
                .register(guard, publication, io, control, original_deadline)
                .map_err(|_| Error::Unavailable)
        })
    }
    fn publish_imap_inner(
        &self,
        body: &[u8],
        observer: &impl RegistrationObserver,
        original_deadline: Instant,
        register: impl FnOnce(&Guard<'_>, &Publication) -> Result<(), Error>,
    ) -> Result<Publication, Error> {
        let mut inner = self.inner.try_lock().map_err(|_| Error::Unavailable)?;
        let began = self.now(&mut inner)?;
        let (key, phase) = self.request(body)?;
        if phase != Phase::After || key.protocol != "imap" {
            return Err(Error::Refused);
        }
        let capture = inner.captures.get_mut(&key).ok_or(Error::Refused)?;
        if !capture.used || !capture.verified {
            return Err(Error::Refused);
        }
        // Consume before lookup/observer; an expired/failed publication cannot
        // be retried for this connection or reconstruct the verified ticket.
        capture.verified = false;
        let epoch = capture.epoch.ok_or(Error::Refused)?;
        let deadline = self.callback_deadline(began, capture.expires, original_deadline)?;
        if began >= deadline {
            return Err(Error::Refused);
        }
        let publication = {
            let guard = self
                .store
                .lock_before(&key.account, deadline)
                .map_err(|_| Error::Unavailable)?;
            guard.admission(Some(epoch)).map_err(|_| Error::Refused)?;
            if self.now(&mut inner)? >= deadline {
                return Err(Error::Refused);
            }
            let evidence =
                observer.observe_registration(&guard, &key.account, &key.session, deadline)?;
            let now = self.now(&mut inner)?;
            if now >= deadline
                || evidence.observed < began
                || evidence.observed > now
                || evidence.account != key.account
                || evidence.session != key.session
                || evidence.epoch != epoch
                || evidence.kernel_pid <= 1
                || evidence.kernel_pid >= i32::MAX as u32
                || evidence.kernel_pid != evidence.anvil_pid
                || evidence.kernel_uid != evidence.expected_uid
                || evidence.process_birth == 0
            {
                return Err(Error::Refused);
            }
            // Recheck the exact store root/record under the held account lock
            // after native observation, rather than trusting a cached epoch.
            guard.admission(Some(epoch)).map_err(|_| Error::Refused)?;
            let publication = Publication {
                account: key.account,
                session: key.session,
                epoch,
                pid: evidence.kernel_pid,
            };
            register(&guard, &publication)?;
            guard.admission(Some(epoch)).map_err(|_| Error::Refused)?;
            publication
        };
        if self.now(&mut inner)? >= deadline {
            return Err(Error::Refused);
        }
        Ok(publication)
    }
}

#[cfg(test)]
#[path = "account_password_policy_tests.rs"]
mod tests;
