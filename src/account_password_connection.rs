//! One owned authenticated Unix connection. Listener publication, connector
//! grants and installed service topology are separate root-owned composition.
use crate::account_guarded_mutation::{verify_guarded, GuardedAuthority};
use crate::account_mutation::Request;
use crate::account_password_backend::Backend;
use crate::account_password_service::{Dependencies, DependencyError, Service};
use crate::account_password_state::Store;
use crate::auth::CommandExecutor;
use crate::totp::TimeProvider;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Peer,
    Input,
    Authentication,
    Expired,
    Unavailable,
    Transport,
}

/// Constructed only from the helper's private purpose-key material. No Debug,
/// serialization or wire-selected key is exposed.
pub(crate) struct Keys {
    mutation: Vec<u8>,
    session: Vec<u8>,
}
impl Keys {
    pub(crate) fn new(
        mutation: impl AsRef<[u8]>,
        session: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        let mutation = mutation.as_ref();
        let session = session.as_ref();
        if !(32..=1024).contains(&mutation.len())
            || !(32..=1024).contains(&session.len())
            || mutation == session
        {
            return Err(Error::Authentication);
        }
        // Existing installed files contain raw ASCII key bytes. Preserve those
        // bytes exactly; interpreting them as encoded hex changes every MAC.
        Ok(Self {
            mutation: mutation.to_vec(),
            session: session.to_vec(),
        })
    }
}

/// Concrete native effects own their fixed profiles and trusted mail topology.
/// Session-proof authority and pending confirmation are implemented here, not
/// supplied by these dependencies or any incoming Boolean.
pub(crate) trait Effects {
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        deadline: Instant,
    ) -> Result<bool, DependencyError>;
    fn preflight(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError>;
    fn before_write(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError>;
    fn invalidate_cache(&self, account: &str, deadline: Instant) -> Result<(), DependencyError>;
    fn finish_mail(&self, account: &str, deadline: Instant) -> Result<(), DependencyError>;
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Error::Expired)
}
fn wall_millis() -> Result<u64, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Expired)?;
    let floor = u64::try_from(now.as_millis()).map_err(|_| Error::Expired)?;
    floor
        .checked_add(u64::from(now.subsec_nanos() % 1_000_000 != 0))
        .filter(|v| *v > 0)
        .ok_or(Error::Expired)
}
fn read_exact(
    stream: &mut UnixStream,
    mut output: &mut [u8],
    deadline: Instant,
) -> Result<(), Error> {
    while !output.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| Error::Transport)?;
        match stream.read(output) {
            Ok(0) => return Err(Error::Transport),
            Ok(n) => output = &mut output[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Transport),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read_frame(stream: &mut UnixStream, limit: usize, deadline: Instant) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > limit {
        return Err(Error::Input);
    }
    let mut output = vec![0u8; length];
    read_exact(stream, &mut output, deadline)?;
    Ok(output)
}
fn write_frame(
    stream: &mut UnixStream,
    raw: &[u8],
    limit: usize,
    deadline: Instant,
) -> Result<(), Error> {
    if raw.is_empty() || raw.len() > limit {
        return Err(Error::Input);
    }
    let header = (raw.len() as u32).to_be_bytes();
    for part in [&header[..], raw] {
        let mut input = part;
        while !input.is_empty() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| Error::Transport)?;
            match stream.write(input) {
                Ok(0) => return Err(Error::Transport),
                Ok(n) => input = &input[n..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::Transport),
            }
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn require_eof(stream: &mut UnixStream, deadline: Instant) -> Result<(), Error> {
    let mut extra = [0u8; 1];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| Error::Transport)?;
        match stream.read(&mut extra) {
            Ok(0) => {
                remaining(deadline)?;
                return Ok(());
            }
            Ok(_) => return Err(Error::Input),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Transport),
        }
    }
}

struct Connected<'a, F> {
    stream: &'a RefCell<UnixStream>,
    authority: GuardedAuthority,
    effects: &'a F,
    key: &'a [u8],
    deadline: Instant,
}
impl<F: Effects> Connected<'_, F> {
    fn admitted(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError> {
        if deadline > self.deadline {
            return Err(DependencyError::Unavailable);
        }
        self.authority
            .authorize(
                request,
                wall_millis().map_err(|_| DependencyError::Unavailable)?,
            )
            .map_err(|_| DependencyError::Unavailable)
    }
}
impl<F: Effects> Dependencies for Connected<'_, F> {
    fn authorize(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError> {
        self.admitted(request, deadline)
    }
    fn authenticate(
        &self,
        account: &str,
        password: &str,
        deadline: Instant,
    ) -> Result<bool, DependencyError> {
        self.effects.authenticate(account, password, deadline)
    }
    fn preflight(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError> {
        self.admitted(request, deadline)?;
        self.effects.preflight(request, deadline)
    }
    fn confirm_pending(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError> {
        let result = (|| {
            self.admitted(request, deadline)
                .map_err(|_| Error::Authentication)?;
            let pending = crate::account_mutation_continuity::PendingChallenge::new(
                request,
                &self.authority,
                self.key,
                wall_millis()?,
            )
            .map_err(|_| Error::Authentication)?;
            let challenge = pending.bytes().map_err(|_| Error::Expired)?;
            let mut stream = self
                .stream
                .try_borrow_mut()
                .map_err(|_| Error::Unavailable)?;
            write_frame(
                &mut stream,
                &challenge,
                crate::account_mutation_continuity::LIMIT,
                deadline,
            )?;
            let ack = read_frame(
                &mut stream,
                crate::account_mutation_continuity::LIMIT,
                deadline,
            )?;
            pending
                .verify_ack(&ack, self.key, wall_millis()?)
                .map_err(|_| Error::Authentication)?;
            // The client ACK writer half-closes exactly once while its actual
            // stored-session lease remains held. No following request is read.
            require_eof(&mut stream, deadline)?;
            self.admitted(request, deadline)
                .map_err(|_| Error::Authentication)
        })();
        result.map_err(|_| DependencyError::Unavailable)
    }
    fn before_write(&self, request: &Request, deadline: Instant) -> Result<(), DependencyError> {
        self.admitted(request, deadline)?;
        self.effects.before_write(request, deadline)
    }
    fn invalidate_cache(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        self.effects.invalidate_cache(account, deadline)
    }
    fn finish_mail(&self, account: &str, deadline: Instant) -> Result<(), DependencyError> {
        self.effects.finish_mail(account, deadline)
    }
}

/// The peer UID is selected by fixed protected connector configuration, never
/// by the frame. The caller owns listener/custody admission before this entry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_once<E: CommandExecutor, F: Effects, C: TimeProvider>(
    stream: UnixStream,
    trusted_peer_uid: u32,
    store: &Store,
    backend: &Backend<E>,
    effects: &F,
    clock: &C,
    keys: &Keys,
    original_outer_deadline: Instant,
) -> Result<(), Error> {
    serve_once_with_access(
        stream,
        trusted_peer_uid,
        store,
        backend,
        effects,
        clock,
        keys,
        original_outer_deadline,
        None,
    )
}

type AccessHandler<'a> = &'a dyn Fn(&[u8], &[u8], Instant) -> Result<Vec<u8>, Error>;
#[allow(clippy::too_many_arguments)] // Existing authorities plus narrowly typed recovery dispatcher.
pub(crate) fn serve_once_with_access<E: CommandExecutor, F: Effects, C: TimeProvider>(
    mut stream: UnixStream,
    trusted_peer_uid: u32,
    store: &Store,
    backend: &Backend<E>,
    effects: &F,
    clock: &C,
    keys: &Keys,
    original_outer_deadline: Instant,
    access: Option<AccessHandler<'_>>,
) -> Result<(), Error> {
    let deadline = original_outer_deadline.min(Instant::now() + Duration::from_secs(60));
    remaining(deadline)?;
    // No byte is read before the kernel principal matches trusted configuration.
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Peer)? != trusted_peer_uid {
        return Err(Error::Peer);
    }
    stream
        .set_nonblocking(false)
        .map_err(|_| Error::Transport)?;
    let raw = read_frame(
        &mut stream,
        crate::account_guarded_mutation::MAX_FRAME,
        deadline,
    )?;
    // Recovery is a separate strict MAC domain, never a password-change proof.
    // The same kernel peer/capacity/closed frame/deadline checks apply first.
    let is_access = serde_json::from_slice::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("schema").and_then(|s| s.as_str()).map(str::to_owned))
        .as_deref()
        == Some(crate::access_recovery_protocol::SCHEMA);
    if is_access {
        require_eof(&mut stream, deadline)?;
        let response = access.ok_or(Error::Authentication)?(&raw, &keys.mutation, deadline)?;
        remaining(deadline)?;
        return write_frame(
            &mut stream,
            &response,
            crate::access_recovery_protocol::MAX_FRAME,
            deadline,
        );
    }
    // Reading consumes the outer budget. These two samples define only the
    // conversion of the already-signed absolute deadline, never a fresh lease.
    let received = Instant::now();
    let received_millis = wall_millis()?;
    let verified = verify_guarded(
        &raw,
        &keys.mutation,
        &keys.session,
        received_millis,
        received,
    )
    .map_err(|_| Error::Authentication)?;
    let (request, authority) = verified.consume();
    let deadline = deadline.min(authority.deadline());
    remaining(deadline)?;
    let stream = RefCell::new(stream);
    let connected = Connected {
        stream: &stream,
        authority,
        effects,
        key: &keys.mutation,
        deadline,
    };
    let mut service = Service::new(store, backend, &connected, clock, &keys.mutation);
    // Service verifies the existing v1 MAC again and durably consumes the exact
    // intent under Store. A new connection cannot reset persisted replay state.
    let (request, outcome) = service
        .execute(&request.bytes().map_err(|_| Error::Input)?, deadline)
        .map_err(|_| Error::Unavailable)?;
    remaining(deadline)?;
    let response = request
        .response(outcome, &keys.mutation, clock.unix_timestamp())
        .map_err(|_| Error::Expired)?;
    write_frame(
        &mut stream.borrow_mut(),
        &response,
        crate::account_mutation::MAX_FRAME,
        deadline,
    )?;
    // Owned stream drops on every return, producing the client's required EOF.
    Ok(())
}

#[cfg(test)]
#[path = "account_password_connection_tests.rs"]
mod tests;
