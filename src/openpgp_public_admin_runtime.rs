//! Operator-configured public administration RPC. The helper principal owns all
//! keybox paths. Web callers supply an authenticated account, never a home/command.
use crate::identity::CanonicalUsername;
use crate::openpgp_inventory_runtime::{file, private_dir, secret, validate_socket};
pub use crate::openpgp_public_admin::PublicSnapshot;
use crate::openpgp_public_admin::{AccountHome, PublicAdminStore};
use crate::openpgp_public_admin_protocol::{Action, Error, Request, Verifier, MAX_FRAME};
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Activation requires independent native RPC/principal transaction proof.
pub const NATIVE_CONFINEMENT_QUALIFIED: bool = true;

fn now() -> Result<u64, Error> {
    crate::openpgp_inventory_runtime::now().map_err(|_| Error::Unavailable)
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Error::Expired)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    account: String,
    home: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    worker: PathBuf,
    engine: PathBuf,
    state_directory: PathBuf,
    socket: PathBuf,
    trusted_web_uid: u32,
    accounts: Vec<Mapping>,
}
impl Config {
    fn load(path: &Path) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        file(path, crate::openbsd::effective_uid(), false, 65536)
            .map_err(|_| Error::Unavailable)?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let c: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if c.version != 1
            || c.accounts.is_empty()
            || c.accounts.len() > 128
            || !c.socket.is_absolute()
            || c.socket.as_os_str().len() > 100
            || c.socket.file_name().is_none()
        {
            return Err(Error::Invalid);
        }
        private_dir(
            c.socket.parent().ok_or(Error::Invalid)?,
            crate::openbsd::effective_uid(),
            true,
        )
        .map_err(|_| Error::Invalid)?;
        // State, home and executable checks belong to the store constructor.
        for mapping in &c.accounts {
            if CanonicalUsername::parse(&mapping.account)
                .map_err(|_| Error::Invalid)?
                .as_str()
                != mapping.account
            {
                return Err(Error::Invalid);
            }
        }
        Ok(c)
    }
}
#[derive(Default)]
struct Admissions(Mutex<BTreeSet<String>>);
struct Permit<'a> {
    admissions: &'a Admissions,
    account: String,
}
impl Admissions {
    fn enter(&self, account: &str) -> Result<Permit<'_>, Error> {
        let mut active = self.0.lock().map_err(|_| Error::Unavailable)?;
        if active.len() >= 2 || !active.insert(account.into()) {
            return Err(Error::Busy);
        }
        Ok(Permit {
            admissions: self,
            account: account.into(),
        })
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.admissions.0.lock() {
            active.remove(&self.account);
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nonce {
    nonce: String,
    expires: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceRecord {
    version: u8,
    account: String,
    high_water: u64,
    entries: Vec<Nonce>,
}
/// Mutating nonces are durably consumed before dispatch. Helper restart cannot
/// re-apply a captured request while its ten-second authentication window lasts.
struct Nonces(PrivateAccountFile);
impl Nonces {
    fn new(directory: PathBuf) -> Self {
        Self(PrivateAccountFile::new(
            directory,
            "osmap-public-admin-nonce-v1",
            32768,
        ))
    }
    fn consume(&self, request: &Request, now: u64) -> Result<(), Error> {
        if now < request.issued() || now >= request.expires() {
            return Err(Error::Expired);
        }
        let locked = self.0.lock(request.account()).map_err(|_| Error::Busy)?;
        let mut record = match locked.read().map_err(|_| Error::Unavailable)? {
            Some(bytes) => {
                serde_json::from_slice::<NonceRecord>(&bytes).map_err(|_| Error::Unavailable)?
            }
            None => NonceRecord {
                version: 1,
                account: request.account().into(),
                high_water: now,
                entries: Vec::new(),
            },
        };
        if record.version != 1 || record.account != request.account() || record.entries.len() > 256
        {
            return Err(Error::Unavailable);
        }
        if now < record.high_water {
            return Err(Error::Expired);
        }
        record.high_water = now;
        let mut unique = BTreeSet::new();
        for entry in &record.entries {
            if entry.nonce.len() != 32
                || !entry
                    .nonce
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || !unique.insert(&entry.nonce)
            {
                return Err(Error::Unavailable);
            }
        }
        record.entries.retain(|entry| entry.expires > now);
        if record
            .entries
            .iter()
            .any(|entry| entry.nonce == request.nonce())
        {
            return Err(Error::Replay);
        }
        if record.entries.len() >= 256 {
            return Err(Error::Busy);
        }
        record.entries.push(Nonce {
            nonce: request.nonce().into(),
            expires: request.expires(),
        });
        locked
            .write(&serde_json::to_vec(&record).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)
    }
}
/// Construct only as the helper principal from owner-private operator files.
pub struct Service {
    config: Config,
    store: PublicAdminStore,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
    admissions: Admissions,
    nonces: Nonces,
}
impl Service {
    pub fn from_operator_files(config: &Path, key: &Path) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(|_| Error::Unavailable)?;
        let config = Config::load(config)?;
        let accounts = config
            .accounts
            .iter()
            .map(|m| {
                Ok(AccountHome {
                    account: CanonicalUsername::parse(&m.account).map_err(|_| Error::Invalid)?,
                    home: m.home.clone(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let store = PublicAdminStore::from_operator_mappings(
            config.state_directory.clone(),
            config.worker.clone(),
            config.engine.clone(),
            accounts,
        )
        .map_err(Error::from)?;
        let nonces = Nonces::new(config.state_directory.join("nonces"));
        Ok(Self {
            config,
            store,
            nonces,
            key: secret(key).map_err(|_| Error::Unavailable)?,
            verifier: Mutex::new(Verifier::default()),
            admissions: Admissions::default(),
        })
    }
    fn process(&self, bytes: &[u8], deadline: Instant) -> Result<Vec<u8>, Error> {
        self.process_with(bytes, deadline, |request, deadline| {
            let account =
                CanonicalUsername::parse(request.account()).map_err(|_| Error::Invalid)?;
            match request.action() {
                Action::Snapshot => self.store.snapshot(&account, deadline),
                Action::ImportPublic => self.store.import_public(
                    &account,
                    request.revision().ok_or(Error::Invalid)?,
                    request.fingerprint().ok_or(Error::Invalid)?,
                    request.certificate(),
                    deadline,
                ),
                Action::RemovePublic => self.store.remove_public(
                    &account,
                    request.revision().ok_or(Error::Invalid)?,
                    request.fingerprint().ok_or(Error::Invalid)?,
                    deadline,
                ),
            }
            .map_err(Error::from)
        })
    }
    fn process_with(
        &self,
        bytes: &[u8],
        deadline: Instant,
        execute: impl FnOnce(&Request, Instant) -> Result<PublicSnapshot, Error>,
    ) -> Result<Vec<u8>, Error> {
        let accepted_at = now()?;
        let request = self
            .verifier
            .lock()
            .map_err(|_| Error::Unavailable)?
            .request(bytes, &self.key, accepted_at)?;
        let result = (|| {
            if !self
                .config
                .accounts
                .iter()
                .any(|mapping| mapping.account == request.account())
            {
                return Err(Error::Unavailable);
            }
            let _permit = self.admissions.enter(request.account())?;
            let timestamp = now()?;
            if timestamp < accepted_at {
                return Err(Error::Expired);
            }
            let deadline = deadline.min(
                Instant::now() + Duration::from_secs(request.expires().saturating_sub(timestamp)),
            );
            remaining(deadline)?;
            if request.action().mutation() {
                self.nonces.consume(&request, timestamp)?;
            }
            remaining(deadline)?;
            execute(&request, deadline)
        })();
        request.response(result, &self.key, now()?)
    }
    fn connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.config.trusted_web_uid
        {
            return Err(Error::Authentication);
        }
        let bytes = read_frame(&mut stream, deadline)?;
        write_frame(&mut stream, &self.process(&bytes, deadline)?, deadline)
    }
    pub fn serve(self) -> Result<(), Error> {
        if !cfg!(target_os = "openbsd")
            || !NATIVE_CONFINEMENT_QUALIFIED
            || !crate::openpgp_inventory_runtime::NATIVE_CONFINEMENT_QUALIFIED
            || !crate::openpgp_crypto_runtime::NATIVE_CONFINEMENT_QUALIFIED
        {
            return Err(Error::Unavailable);
        }
        if fs::symlink_metadata(&self.config.socket).is_ok() {
            return Err(Error::Unavailable);
        }
        let listener = UnixListener::bind(&self.config.socket).map_err(|_| Error::Unavailable)?;
        fs::set_permissions(
            &self.config.socket,
            fs::Permissions::from_mode(
                if self.config.trusted_web_uid == crate::openbsd::effective_uid() {
                    0o600
                } else {
                    0o660
                },
            ),
        )
        .map_err(|_| Error::Unavailable)?;
        let service = Arc::new(self);
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for incoming in listener.incoming() {
            let stream = incoming.map_err(|_| Error::Unavailable)?;
            if active
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |n| (n < 2).then_some(n + 1),
                )
                .is_err()
            {
                continue;
            }
            let service = service.clone();
            let active = active.clone();
            std::thread::spawn(move || {
                let _ = service.connection(stream);
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
        Err(Error::Unavailable)
    }
}
struct ClientState {
    socket: PathBuf,
    key_file: PathBuf,
    helper_uid: u32,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
}
#[derive(Clone)]
pub struct Client(Arc<ClientState>);
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicAdminClient")
            .field("socket", &self.0.socket)
            .field("key_file", &self.0.key_file)
            .field("helper_uid", &self.0.helper_uid)
            .finish_non_exhaustive()
    }
}
impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.0.socket == other.0.socket
            && self.0.key_file == other.0.key_file
            && self.0.helper_uid == other.0.helper_uid
            && self.0.key == other.0.key
    }
}
impl Eq for Client {}
impl Client {
    pub fn from_operator_files(
        socket: &Path,
        key_file: &Path,
        expected_helper_uid: u32,
    ) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(|_| Error::Unavailable)?;
        validate_socket(socket, expected_helper_uid).map_err(|_| Error::Unavailable)?;
        Ok(Self(Arc::new(ClientState {
            socket: socket.into(),
            key_file: key_file.into(),
            helper_uid: expected_helper_uid,
            key: secret(key_file).map_err(|_| Error::Unavailable)?,
            verifier: Mutex::new(Verifier::default()),
        })))
    }
    /// Account comes exclusively from the caller's authenticated canonical session.
    pub fn snapshot(&self, account: &str) -> Result<PublicSnapshot, Error> {
        self.call(account, Action::Snapshot, None, None, &[])
    }
    pub fn import_public(
        &self,
        account: &str,
        expected_revision: &str,
        primary_fingerprint: &str,
        certificate: &[u8],
    ) -> Result<PublicSnapshot, Error> {
        self.call(
            account,
            Action::ImportPublic,
            Some(expected_revision),
            Some(primary_fingerprint),
            certificate,
        )
    }
    pub fn remove_public(
        &self,
        account: &str,
        expected_revision: &str,
        primary_fingerprint: &str,
    ) -> Result<PublicSnapshot, Error> {
        self.call(
            account,
            Action::RemovePublic,
            Some(expected_revision),
            Some(primary_fingerprint),
            &[],
        )
    }
    fn call(
        &self,
        account: &str,
        action: Action,
        revision: Option<&str>,
        fingerprint: Option<&str>,
        body: &[u8],
    ) -> Result<PublicSnapshot, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let request = Request::issue(
            account,
            action,
            revision,
            fingerprint,
            body,
            now()?,
            &self.0.key,
        )?;
        let bytes = request.to_bytes()?;
        validate_socket(&self.0.socket, self.0.helper_uid).map_err(|_| Error::Unavailable)?;
        let mut stream = crate::openbsd::connect_unix_before(&self.0.socket, deadline)
            .map_err(|_| Error::Unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.0.helper_uid
        {
            return Err(Error::Authentication);
        }
        // From the first attempted write onward the helper might have committed.
        // Preserve authenticated negative replies; transport/auth uncertainty is
        // a distinct outcome and must never trigger an automatic mutation retry.
        let uncertain = |error| {
            if action.mutation() {
                Error::Unconfirmed
            } else {
                error
            }
        };
        write_frame(&mut stream, &bytes, deadline).map_err(uncertain)?;
        let response = read_frame(&mut stream, deadline).map_err(uncertain)?;
        self.0
            .verifier
            .lock()
            .map_err(|_| uncertain(Error::Unavailable))?
            .response(&request, &response, &self.0.key, now().map_err(uncertain)?)
            .map_err(uncertain)?
    }
}
fn read_exact(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| Error::Unavailable)?;
        match stream.read(bytes) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}
fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, Error> {
    let mut size = [0; 4];
    read_exact(stream, &mut size, deadline)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut bytes = vec![0; size];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
fn write_frame(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    let mut rest = &frame[..];
    while !rest.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| Error::Unavailable)?;
        match stream.write(rest) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => rest = &rest[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "openpgp_public_admin_runtime_tests.rs"]
mod tests;
