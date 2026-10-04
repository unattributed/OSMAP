//! Peer-authenticated private account-helper transport; production remains off.
use crate::account_admission::{
    valid_epoch, Admission, EpochAuthority, Error, Operation, Request, Verifier, MAX_FRAME,
};
use crate::openpgp_inventory_runtime::{
    file, now, private_dir, read_frame, secret, validate_socket, write_frame,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Source construction cannot opt out of actual native/helper confinement qualification.
pub const NATIVE_CONFINEMENT_QUALIFIED: bool = false;
const WORKER: &str = "/usr/local/libexec/osmap/account-runtime/account_admission_worker.py";
const ENGINE: &str = "/usr/local/bin/python3";
const EPOCH_ROOT: &str = "/var/db/osmap-account/epoch";
fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    socket: PathBuf,
    trusted_web_uid: u32,
    accounts: Vec<String>,
}
pub struct Service {
    active: Mutex<BTreeSet<String>>,
    cleanup_unconfirmed: std::sync::atomic::AtomicBool,
    config: Config,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
}
impl Service {
    pub fn from_operator_files(config: &Path, key: &Path) -> Result<Self, Error> {
        if !NATIVE_CONFINEMENT_QUALIFIED {
            return Err(Error::Unavailable);
        }
        crate::openbsd::disable_core_dumps().map_err(unavailable)?;
        let owner = crate::openbsd::effective_uid();
        if owner != 0 {
            return Err(Error::Unavailable);
        }
        let mut bytes = Vec::new();
        file(config, 0, false, 65536)
            .map_err(unavailable)?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        let c: Config = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if c.version != 1
            || c.trusted_web_uid == 0
            || c.accounts.is_empty()
            || c.accounts.len() > 128
            || !c.socket.is_absolute()
            || c.socket.as_os_str().len() > 100
        {
            return Err(Error::Invalid);
        }
        let mut accounts = BTreeSet::new();
        for account in &c.accounts {
            crate::account_admission::valid_account(account)?;
            if !accounts.insert(account) {
                return Err(Error::Invalid);
            }
        }
        private_dir(c.socket.parent().ok_or(Error::Invalid)?, 0, true).map_err(unavailable)?;
        private_dir(Path::new(EPOCH_ROOT), 0, false).map_err(unavailable)?;
        file(Path::new(ENGINE), 0, true, 64 * 1024 * 1024).map_err(unavailable)?;
        for name in [
            "account_admission_worker.py",
            "account_epoch.py",
            "authoritative_password.py",
        ] {
            file(
                &Path::new(WORKER).parent().ok_or(Error::Invalid)?.join(name),
                0,
                false,
                128 * 1024,
            )
            .map_err(unavailable)?;
        }
        Ok(Self {
            active: Mutex::new(BTreeSet::new()),
            cleanup_unconfirmed: std::sync::atomic::AtomicBool::new(false),
            config: c,
            key: secret(key).map_err(unavailable)?,
            verifier: Mutex::new(Verifier::default()),
        })
    }
    fn process(
        &self,
        bytes: &[u8],
        at: u64,
        execute: impl FnOnce(&Request) -> Result<Option<u64>, Error>,
    ) -> Result<Vec<u8>, Error> {
        if self
            .cleanup_unconfirmed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::CleanupUnconfirmed);
        }
        let request = self
            .verifier
            .lock()
            .map_err(unavailable)?
            .request(bytes, &self.key, at)?;
        if !self.config.accounts.iter().any(|a| a == request.account()) {
            return Err(Error::Refused);
        }
        let _permit = self.enter(request.account())?;
        let result = match execute(&request) {
            Err(Error::CleanupUnconfirmed) => {
                self.cleanup_unconfirmed
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(Error::CleanupUnconfirmed);
            }
            value => value?,
        };
        request.response(result, &self.key, now().map_err(unavailable)?)
    }
    fn enter(&self, account: &str) -> Result<Permit<'_>, Error> {
        let mut active = self.active.lock().map_err(unavailable)?;
        if active.len() >= 2 || !active.insert(account.into()) {
            return Err(Error::Capacity);
        }
        Ok(Permit {
            service: self,
            account: account.into(),
        })
    }
    fn fixed_worker(request: &Request, deadline: Instant) -> Result<Option<u64>, Error> {
        // Interpreter, script and module roots are fixed and operator-owned.
        // Credential JSON is exclusively stdin under the existing private,
        // nonblocking process-group transport and quarantine-on-cleanup policy.
        let command = crate::auth::account_admission_command();
        let bytes = crate::openpgp_crypto_process::run_account_admission(
            command,
            &request.worker_bytes()?,
            deadline,
        )
        .map_err(unavailable)?;
        if bytes.len() > MAX_FRAME {
            return Err(Error::Unavailable);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WorkerResponse {
            schema: String,
            account: Option<String>,
            status: String,
            epoch: Option<u64>,
        }
        let r: WorkerResponse = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if r.schema == "osmap-account-admission-worker-v1"
            && r.status == "cleanup_unconfirmed"
            && r.account.is_none()
            && r.epoch.is_none()
        {
            return Err(Error::CleanupUnconfirmed);
        }
        if r.schema != "osmap-account-admission-worker-v1"
            || r.account.as_deref() != Some(request.account())
        {
            return Err(Error::Unavailable);
        }
        match (&request.operation(), r.status.as_str(), r.epoch) {
            (Operation::Authenticate { .. }, "rejected", None) => Ok(None),
            (Operation::Authenticate { .. }, "active", Some(epoch)) if valid_epoch(epoch) => {
                Ok(Some(epoch))
            }
            (Operation::Admit { epoch: expected }, "active", Some(epoch)) if epoch == *expected => {
                Ok(Some(epoch))
            }
            _ => Err(Error::Refused),
        }
    }
    /// Caller accepts one finite connection only after a reviewed supervisor
    /// has applied the actual account-helper native confinement policy.
    pub fn connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        if !NATIVE_CONFINEMENT_QUALIFIED {
            return Err(Error::Unavailable);
        }
        self.connection_with(&mut stream, Self::fixed_worker)
    }
    fn connection_with(
        &self,
        stream: &mut UnixStream,
        execute: impl FnOnce(&Request, Instant) -> Result<Option<u64>, Error>,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(30);
        if crate::openbsd::unix_stream_peer_uid(stream).map_err(unavailable)?
            != self.config.trusted_web_uid
        {
            return Err(Error::Authentication);
        }
        let bytes = read_frame(stream, MAX_FRAME, deadline).map_err(unavailable)?;
        let response = self.process(&bytes, now().map_err(unavailable)?, |r| {
            execute(r, deadline)
        })?;
        write_frame(stream, &response, deadline).map_err(unavailable)
    }
}
struct Permit<'a> {
    service: &'a Service,
    account: String,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.service.active.lock() {
            active.remove(&self.account);
        }
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
        f.write_str("AccountAdmissionClient(<private configuration>)")
    }
}
impl PartialEq for Client {
    fn eq(&self, o: &Self) -> bool {
        self.0.socket == o.0.socket
            && self.0.key_file == o.0.key_file
            && self.0.helper_uid == o.0.helper_uid
            && self.0.key == o.0.key
    }
}
impl Eq for Client {}
impl Client {
    pub fn from_operator_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        if !NATIVE_CONFINEMENT_QUALIFIED {
            return Err(Error::Unavailable);
        }
        Self::qualified_files(socket, key, helper_uid)
    }
    fn qualified_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(unavailable)?;
        validate_socket(socket, helper_uid).map_err(unavailable)?;
        Ok(Self(Arc::new(ClientState {
            socket: socket.into(),
            key_file: key.into(),
            helper_uid,
            key: secret(key).map_err(unavailable)?,
            verifier: Mutex::new(Verifier::default()),
        })))
    }
    fn execute(&self, account: &str, operation: Operation) -> Result<Option<Admission>, Error> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let request = Request::issue(account, operation, now().map_err(unavailable)?, &self.0.key)?;
        validate_socket(&self.0.socket, self.0.helper_uid).map_err(unavailable)?;
        let mut stream =
            crate::openbsd::connect_unix_before(&self.0.socket, deadline).map_err(unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)? != self.0.helper_uid
        {
            return Err(Error::Authentication);
        }
        write_frame(&mut stream, &request.bytes()?, deadline).map_err(unavailable)?;
        let bytes = read_frame(&mut stream, MAX_FRAME, deadline).map_err(unavailable)?;
        self.0.verifier.lock().map_err(unavailable)?.response(
            &request,
            &bytes,
            &self.0.key,
            now().map_err(unavailable)?,
        )
    }
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Option<Admission>, Error> {
        self.execute(
            username,
            Operation::Authenticate {
                password: password.into(),
            },
        )
    }
}
impl EpochAuthority for Client {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), Error> {
        self.execute(account, Operation::Admit { epoch })?
            .map(|_| ())
            .ok_or(Error::Refused)
    }
}

/// Primary credential adapter preserves the exact authenticated epoch alongside
/// the existing MFA-required decision. It does not turn primary auth into a session.
pub struct CredentialBackend {
    pub client: Client,
    pub captured: Arc<Mutex<Option<Admission>>>,
}
impl crate::auth::PrimaryCredentialBackend for CredentialBackend {
    fn verify_primary(
        &self,
        _: &crate::auth::AuthenticationContext,
        username: &str,
        password: &str,
    ) -> Result<crate::auth::PrimaryAuthVerdict, crate::auth::PrimaryAuthBackendError> {
        let denied = || crate::auth::PrimaryAuthBackendError {
            backend: "account-helper",
            reason: "account authentication unavailable".into(),
        };
        let admission = self
            .client
            .authenticate(username, password)
            .map_err(|_| denied())?;
        let verdict = match &admission {
            Some(a) => crate::auth::PrimaryAuthVerdict::Accept {
                canonical_username: a.account.clone(),
            },
            None => crate::auth::PrimaryAuthVerdict::Reject,
        };
        *self.captured.lock().map_err(|_| denied())? = admission;
        Ok(verdict)
    }
}
#[cfg(test)]
#[path = "account_admission_runtime_tests.rs"]
mod tests;
