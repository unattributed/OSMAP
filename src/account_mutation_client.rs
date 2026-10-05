//! Single-attempt private mutation transport; native production remains off.
//!
//! A caller supplies the same absolute monotonic workflow deadline used by its
//! authentication and later browser cleanup. This module never renews it. Only
//! a sealed verified terminal receipt can leave a completed exchange; an I/O or
//! verifier error after frame submission remains uncertain and quarantines the
//! account. There is no reconnect, automatic retry or quarantine reset API.
use crate::account_mutation::{Request, TerminalReceipt, Verifier, MAX_FRAME};
use crate::openpgp_inventory_runtime::{file, read_frame, validate_socket, write_frame};
use crate::password_change::Dispatch;
use crate::totp::{SystemTimeProvider, TimeProvider};
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const NATIVE_CONFINEMENT_QUALIFIED: bool = false;
const MAXIMUM: Duration = Duration::from_secs(60);
const MAX_QUARANTINE: usize = 128;

/// No transport error is an authenticated KnownRefused outcome or proof that
/// an earlier dispatched credential update did not occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Invalid,
    Expired,
    Replay,
    Capacity,
    Uncertain,
}

struct State {
    active: BTreeSet<String>,
    quarantine: BTreeSet<String>,
}
struct ClientState {
    socket: PathBuf,
    helper_uid: u32,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
    state: Mutex<State>,
    cleanup_unconfirmed: AtomicBool,
}
#[derive(Clone)]
pub struct Client(Arc<ClientState>);
impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccountMutationClient(<private configuration>)")
    }
}

impl Client {
    pub fn from_operator_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        if !NATIVE_CONFINEMENT_QUALIFIED {
            return Err(Error::Unavailable);
        }
        Self::qualified_files(socket, key, helper_uid)
    }
    fn qualified_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(|_| Error::Unavailable)?;
        validate_socket(socket, helper_uid).map_err(|_| Error::Unavailable)?;
        Ok(Self(Arc::new(ClientState {
            socket: socket.into(),
            helper_uid,
            key: private_key(key)?,
            verifier: Mutex::new(Verifier::default()),
            state: Mutex::new(State {
                active: BTreeSet::new(),
                quarantine: BTreeSet::new(),
            }),
            cleanup_unconfirmed: AtomicBool::new(false),
        })))
    }

    pub fn issue(&self, dispatch: Dispatch<'_>) -> Result<Request, Error> {
        Request::issue(dispatch, &self.0.key, SystemTimeProvider.unix_timestamp())
            .map_err(|_| Error::Invalid)
    }

    pub fn execute(
        &self,
        request: Request,
        workflow_deadline: Instant,
    ) -> Result<TerminalReceipt, Error> {
        self.execute_with(request, workflow_deadline, &SystemTimeProvider)
    }

    /// Additive budget-envelope transport. Only this entry may be integrated
    /// with the future supervised native mutation listener; defaults stay off.
    pub fn execute_budget(
        &self,
        request: Request,
        workflow_deadline: Instant,
    ) -> Result<TerminalReceipt, Error> {
        self.execute_mode(request, workflow_deadline, &SystemTimeProvider, true)
    }

    /// Source-only guarded path: the borrowed current-session lease stays alive
    /// through peer authentication, exact frame exchange and verified receipt.
    /// This does not qualify a remote distributed lease or activate a helper.
    pub fn execute_guarded(
        &self,
        action: crate::account_guarded_mutation::GuardedMutation<'_>,
    ) -> Result<TerminalReceipt, Error> {
        self.execute_guarded_with(action, &SystemTimeProvider)
    }
    fn execute_guarded_with(
        &self,
        action: crate::account_guarded_mutation::GuardedMutation<'_>,
        clock: &dyn TimeProvider,
    ) -> Result<TerminalReceipt, Error> {
        action.consume(|request, frame, deadline| {
            let mut at = clock.unix_timestamp();
            let deadline = bound_deadline(&request, deadline, at)?;
            let _permit = self.enter(request.account())?;
            let request = self
                .0
                .verifier
                .try_lock()
                .map_err(|_| Error::Unavailable)?
                .request(
                    &request.bytes().map_err(|_| Error::Invalid)?,
                    &self.0.key,
                    at,
                )
                .map_err(codec_error)?;
            validate_socket(&self.0.socket, self.0.helper_uid).map_err(|_| Error::Unavailable)?;
            check_time(&request, deadline, clock, &mut at)?;
            let stream = crate::openbsd::connect_unix_before(&self.0.socket, deadline)
                .map_err(|_| Error::Unavailable)?;
            self.exchange(request, frame, stream, deadline, clock, at)
        })
    }
    #[cfg(test)]
    pub(crate) fn guarded_fixture_files(
        socket: &Path,
        key: &Path,
        uid: u32,
    ) -> Result<Self, Error> {
        Self::qualified_files(socket, key, uid)
    }
    #[cfg(test)]
    pub(crate) fn guarded_fixture_exchange(
        &self,
        action: crate::account_guarded_mutation::GuardedMutation<'_>,
        clock: &dyn TimeProvider,
    ) -> Result<TerminalReceipt, Error> {
        self.execute_guarded_with(action, clock)
    }

    fn execute_with(
        &self,
        request: Request,
        workflow_deadline: Instant,
        clock: &dyn TimeProvider,
    ) -> Result<TerminalReceipt, Error> {
        self.execute_mode(request, workflow_deadline, clock, false)
    }
    fn execute_mode(
        &self,
        request: Request,
        workflow_deadline: Instant,
        clock: &dyn TimeProvider,
        budget_envelope: bool,
    ) -> Result<TerminalReceipt, Error> {
        let mut at = clock.unix_timestamp();
        let deadline = bound_deadline(&request, workflow_deadline, at)?;
        let _permit = self.enter(request.account())?;
        // Record this exact signed intent before attempting any connection.
        // Request replay capacity/clock checks are separate from response replay.
        let request = self
            .0
            .verifier
            .try_lock()
            .map_err(|_| Error::Unavailable)?
            .request(
                &request.bytes().map_err(|_| Error::Invalid)?,
                &self.0.key,
                at,
            )
            .map_err(codec_error)?;
        validate_socket(&self.0.socket, self.0.helper_uid).map_err(|_| Error::Unavailable)?;
        check_time(&request, deadline, clock, &mut at)?;
        let stream = crate::openbsd::connect_unix_before(&self.0.socket, deadline)
            .map_err(|_| Error::Unavailable)?;
        let frame = if budget_envelope {
            let sent = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::Expired)?
                .as_millis();
            let left = remaining(deadline)?.as_millis();
            let sent = u64::try_from(sent).map_err(|_| Error::Expired)?;
            let left = u64::try_from(left).map_err(|_| Error::Expired)?;
            crate::account_mutation_budget::issue(
                &request,
                &self.0.key,
                sent,
                sent.checked_add(left).ok_or(Error::Expired)?,
            )
            .map_err(|_| Error::Invalid)?
        } else {
            request.bytes().map_err(|_| Error::Invalid)?
        };
        self.exchange(request, frame, stream, deadline, clock, at)
    }

    fn exchange(
        &self,
        request: Request,
        frame: Vec<u8>,
        mut stream: UnixStream,
        deadline: Instant,
        clock: &dyn TimeProvider,
        mut at: u64,
    ) -> Result<TerminalReceipt, Error> {
        // Socket path metadata alone cannot establish the connected peer.
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Unavailable)?
            != self.0.helper_uid
        {
            return Err(Error::Unavailable);
        }
        check_time(&request, deadline, clock, &mut at)?;
        let account = request.account().to_owned();
        let original_issued = request.issued();
        let original_expires = request.expires();
        let result = (|| {
            // Once frame submission starts, even a failed partial write is
            // ambiguous. Never reconnect or convert any error below to refusal.
            write_frame(&mut stream, &frame, deadline).map_err(|_| Error::Uncertain)?;
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|_| Error::Uncertain)?;
            check_time(&request, deadline, clock, &mut at).map_err(|_| Error::Uncertain)?;
            let bytes =
                read_frame(&mut stream, MAX_FRAME, deadline).map_err(|_| Error::Uncertain)?;
            // One response and EOF is the connection contract; no trailing
            // bytes, persistent connection or second response is accepted.
            stream
                .set_read_timeout(Some(remaining(deadline).map_err(|_| Error::Uncertain)?))
                .map_err(|_| Error::Uncertain)?;
            let mut extra = [0; 1];
            if stream.read(&mut extra).map_err(|_| Error::Uncertain)? != 0 {
                return Err(Error::Uncertain);
            }
            check_time(&request, deadline, clock, &mut at).map_err(|_| Error::Uncertain)?;
            let receipt = self
                .0
                .verifier
                .try_lock()
                .map_err(|_| Error::Uncertain)?
                .terminal_response(request, &bytes, &self.0.key, at)
                .map_err(|_| Error::Uncertain)?;
            // Root's later cleanup keeps the caller's original deadline and
            // receipt expiry. A late verification never authorizes that cleanup.
            let final_at = clock.unix_timestamp();
            if remaining(deadline).is_err()
                || final_at < at
                || final_at < original_issued
                || final_at >= original_expires
            {
                return Err(Error::Uncertain);
            }
            Ok(receipt)
        })();
        if result.is_err() {
            self.quarantine_account(&account);
        }
        result
    }

    fn enter(&self, account: &str) -> Result<Permit<'_>, Error> {
        if self.0.cleanup_unconfirmed.load(Ordering::SeqCst) {
            return Err(Error::Uncertain);
        }
        let mut state = self.0.state.try_lock().map_err(|_| Error::Unavailable)?;
        if state.quarantine.contains(account) {
            return Err(Error::Uncertain);
        }
        if state.active.len() >= 2 || !state.active.insert(account.to_owned()) {
            return Err(Error::Capacity);
        }
        Ok(Permit {
            client: self,
            account: account.to_owned(),
        })
    }

    /// The parent workflow captures the exact bound account before consuming
    /// its terminal receipt. A later cleanup failure uses this same client.
    /// This is local mutation quarantine, not durable shared login containment.
    pub(crate) fn quarantine_account(&self, account: &str) {
        if crate::account_admission::valid_account(account).is_err() {
            self.0.cleanup_unconfirmed.store(true, Ordering::SeqCst);
            return;
        }
        match self.0.state.try_lock() {
            Ok(mut state) if state.quarantine.len() < MAX_QUARANTINE => {
                state.quarantine.insert(account.to_owned());
            }
            _ => self.0.cleanup_unconfirmed.store(true, Ordering::SeqCst),
        }
    }
}
struct Permit<'a> {
    client: &'a Client,
    account: String,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        match self.client.0.state.try_lock() {
            Ok(mut state) => {
                state.active.remove(&self.account);
            }
            Err(_) => self
                .client
                .0
                .cleanup_unconfirmed
                .store(true, Ordering::SeqCst),
        }
    }
}
fn codec_error(error: crate::account_mutation::Error) -> Error {
    match error {
        crate::account_mutation::Error::Expired => Error::Expired,
        crate::account_mutation::Error::Replay => Error::Replay,
        crate::account_mutation::Error::Capacity => Error::Capacity,
        _ => Error::Invalid,
    }
}
fn private_key(path: &Path) -> Result<Vec<u8>, Error> {
    let handle =
        file(path, crate::openbsd::effective_uid(), false, 1024).map_err(|_| Error::Unavailable)?;
    if handle.metadata().map_err(|_| Error::Unavailable)?.nlink() != 1 {
        return Err(Error::Unavailable);
    }
    let mut bytes = Vec::new();
    handle
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if !(32..=1024).contains(&bytes.len()) {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(Error::Expired)
}
fn bound_deadline(request: &Request, supplied: Instant, at: u64) -> Result<Instant, Error> {
    let supplied = request
        .workflow_deadline()
        .map(|original| supplied.min(original))
        .unwrap_or(supplied);
    let duration = remaining(supplied)?;
    if duration > MAXIMUM || at < request.issued() || at >= request.expires() {
        return Err(Error::Expired);
    }
    let expires = Instant::now()
        .checked_add(Duration::from_secs(request.expires() - at))
        .ok_or(Error::Expired)?;
    Ok(supplied.min(expires))
}
fn check_time(
    request: &Request,
    deadline: Instant,
    clock: &dyn TimeProvider,
    at: &mut u64,
) -> Result<(), Error> {
    remaining(deadline)?;
    let next = clock.unix_timestamp();
    if next < *at || next < request.issued() || next >= request.expires() {
        return Err(Error::Expired);
    }
    *at = next;
    Ok(())
}

#[cfg(test)]
#[path = "account_mutation_client_tests.rs"]
mod tests;
