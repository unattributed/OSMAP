//! Authenticated, bounded public inventory adapter. No browser-selected paths or operations.
//! Replay state persists for this process lifetime; restarting loses the ten-second replay window.
use crate::identity::CanonicalUsername;
use crate::openpgp_inventory::{Error, Inventory, MAX_METADATA};
use crate::openpgp_inventory_protocol::{Request, Verifier};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FRAME_LIMIT: usize = MAX_METADATA * 2 + 4096;
const ENGINE: &str = "/usr/local/bin/gpg";
// Deliberate release gate. A configuration value cannot bypass native qualification.
pub const NATIVE_CONFINEMENT_QUALIFIED: bool = true;
pub(crate) fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Clock)
}
pub(crate) fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Expired)
}
fn protected_ancestors(path: &Path, owner: u32) -> Result<(), Error> {
    for ancestor in path.ancestors().skip(1) {
        // The filesystem root is an OS-owned trust anchor. Under OpenBSD
        // unveil, specific descendants remain visible but metadata for `/`
        // itself is hidden; requiring its stat would disable every client.
        if ancestor == Path::new("/") {
            break;
        }
        let m = fs::symlink_metadata(ancestor).map_err(|_| Error::Unavailable)?;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || (m.uid() != 0 && m.uid() != owner)
            || (m.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}
pub(crate) fn exact_path(path: &Path, owner: u32) -> Result<(), Error> {
    protected_ancestors(path, owner)?;
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || fs::canonicalize(path).map_err(|_| Error::Unavailable)? != path
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(crate) fn private_dir(path: &Path, owner: u32, shared: bool) -> Result<(), Error> {
    exact_path(path, owner)?;
    let m = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !m.is_dir() || m.uid() != owner || m.mode() & (if shared { 0o027 } else { 0o077 }) != 0 {
        return Err(Error::Unavailable);
    }
    Ok(())
}
pub(crate) fn file(path: &Path, owner: u32, executable: bool, max: u64) -> Result<File, Error> {
    exact_path(path, owner)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    let m = f.metadata().map_err(|_| Error::Unavailable)?;
    if !m.is_file()
        || m.uid() != owner
        || m.len() > max
        || m.mode() & (if executable { 0o022 } else { 0o077 }) != 0
        || (executable && m.mode() & 0o111 == 0)
    {
        return Err(Error::Unavailable);
    }
    Ok(f)
}
pub(crate) fn secret(path: &Path) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    file(path, crate::openbsd::effective_uid(), false, 1024)?
        .take(1025)
        .read_to_end(&mut b)
        .map_err(|_| Error::Unavailable)?;
    if !(32..=1024).contains(&b.len()) {
        return Err(Error::Invalid);
    }
    Ok(b)
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
    socket: PathBuf,
    trusted_web_uid: u32,
    accounts: Vec<Mapping>,
}
impl Config {
    fn load(path: &Path) -> Result<Self, Error> {
        let owner = crate::openbsd::effective_uid();
        let mut bytes = Vec::new();
        file(path, owner, false, 65536)?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let c: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if c.version != 1
            || c.engine != Path::new(ENGINE)
            || c.accounts.is_empty()
            || c.accounts.len() > 128
            || c.socket.file_name().is_none()
            || !c.socket.is_absolute()
            || c.socket.as_os_str().len() > 100
        {
            return Err(Error::Invalid);
        }
        file(&c.worker, owner, true, 64 * 1024 * 1024)?;
        // The system engine is operator installed, never replaceable by the web account.
        file(&c.engine, 0, true, 64 * 1024 * 1024)?;
        private_dir(c.socket.parent().ok_or(Error::Invalid)?, owner, true)?;
        let mut accounts = BTreeSet::new();
        let mut homes = BTreeSet::new();
        for m in &c.accounts {
            CanonicalUsername::parse(&m.account).map_err(|_| Error::Invalid)?;
            if !accounts.insert(&m.account)
                || homes
                    .iter()
                    .any(|other: &&PathBuf| m.home.starts_with(other) || other.starts_with(&m.home))
                || !homes.insert(&m.home)
            {
                return Err(Error::Invalid);
            }
            private_dir(&m.home, owner, false)?;
            for name in ["pubring.kbx", "trustdb.gpg"] {
                file(&m.home.join(name), owner, false, 64 * 1024 * 1024)?;
            }
            for name in ["gpg.conf", "common.conf", "gpg-agent.conf"] {
                if fs::symlink_metadata(m.home.join(name)).is_ok() {
                    return Err(Error::Invalid);
                }
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
            return Err(Error::Capacity);
        }
        Ok(Permit {
            admissions: self,
            account: account.into(),
        })
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut a) = self.admissions.0.lock() {
            a.remove(&self.account);
        }
    }
}
/// Operator-created service; authentication is checked before any worker dispatch.
pub struct Service {
    config: Config,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
    admissions: Admissions,
}
impl Service {
    pub fn from_operator_files(config: &Path, key: &Path) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            config: Config::load(config)?,
            key: secret(key)?,
            verifier: Mutex::new(Verifier::default()),
            admissions: Admissions::default(),
        })
    }
    fn process(
        &self,
        bytes: &[u8],
        deadline: Instant,
        execute: impl FnOnce(&Path, &Path, Instant) -> Result<Inventory, Error>,
    ) -> Result<Vec<u8>, Error> {
        if bytes.len() > 2048 {
            return Err(Error::Limit);
        }
        let candidate: Request = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        let request = self
            .verifier
            .lock()
            .map_err(|_| Error::Unavailable)?
            .request(bytes, candidate.account(), &self.key, now()?)?;
        let _permit = self.admissions.enter(request.account())?;
        let mapping = self
            .config
            .accounts
            .iter()
            .find(|m| m.account == request.account())
            .ok_or(Error::Unavailable)?;
        let until_expiry = Duration::from_secs(request.expires().saturating_sub(now()?));
        let deadline = deadline.min(Instant::now() + until_expiry);
        remaining(deadline)?;
        let inventory = execute(&self.config.worker, &mapping.home, deadline)?;
        request.response(&inventory, &self.key, now()?)
    }
    fn connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.config.trusted_web_uid
        {
            return Err(Error::Authentication);
        }
        let bytes = read_frame(&mut stream, 2048, deadline)?;
        let response = self.process(&bytes, deadline, crate::openpgp_inventory_process::execute)?;
        write_frame(&mut stream, &response, deadline)
    }
    /// Refuses activation until the separately reviewed native confinement gate is qualified.
    pub fn serve(self) -> Result<(), Error> {
        if !cfg!(target_os = "openbsd") || !NATIVE_CONFINEMENT_QUALIFIED {
            return Err(Error::Unavailable);
        }
        // Never remove or replace an existing socket, even after a previous service crash.
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
                    |v| (v < 2).then_some(v + 1),
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
        f.debug_struct("PublicInventoryClient")
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
        validate_socket(socket, expected_helper_uid)?;
        Ok(Self(Arc::new(ClientState {
            socket: socket.into(),
            key_file: key_file.into(),
            helper_uid: expected_helper_uid,
            key: secret(key_file)?,
            verifier: Mutex::new(Verifier::default()),
        })))
    }
    /// Account must come from the browser's already validated canonical session.
    pub fn read(&self, account: &str) -> Result<Inventory, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let request = Request::issue(account, now()?, &self.0.key)?;
        validate_socket(&self.0.socket, self.0.helper_uid)?;
        let mut stream = crate::openbsd::connect_unix_before(&self.0.socket, deadline)
            .map_err(|_| Error::Unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.0.helper_uid
        {
            return Err(Error::Authentication);
        }
        write_frame(&mut stream, &request.to_bytes()?, deadline)?;
        let response = read_frame(&mut stream, FRAME_LIMIT, deadline)?;
        self.0
            .verifier
            .lock()
            .map_err(|_| Error::Unavailable)?
            .response(&request, &response, &self.0.key, now()?)
    }
}
pub(crate) fn validate_socket(path: &Path, owner: u32) -> Result<(), Error> {
    exact_path(path, owner)?;
    private_dir(path.parent().ok_or(Error::Invalid)?, owner, true)?;
    let m = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !m.file_type().is_socket() || m.uid() != owner || m.mode() & 0o117 != 0 {
        return Err(Error::Unavailable);
    }
    Ok(())
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
        let n = stream.read(bytes).map_err(|_| Error::Unavailable)?;
        if n == 0 {
            return Err(Error::Unavailable);
        }
        bytes = &mut bytes[n..];
    }
    Ok(())
}
pub(crate) fn read_frame(
    stream: &mut UnixStream,
    max: usize,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let mut size = [0; 4];
    read_exact(stream, &mut size, deadline)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > max {
        return Err(Error::Limit);
    }
    let mut bytes = vec![0; size];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
pub(crate) fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
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
        let n = stream.write(rest).map_err(|_| Error::Unavailable)?;
        if n == 0 {
            return Err(Error::Unavailable);
        }
        rest = &rest[n..];
    }
    Ok(())
}
#[cfg(test)]
#[path = "openpgp_inventory_runtime_tests.rs"]
mod tests;
