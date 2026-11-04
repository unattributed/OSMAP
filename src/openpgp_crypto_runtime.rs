//! Account-mapped crypto dispatcher and client. Web requests carry typed bytes
//! and full fingerprint selections; only operator configuration supplies homes.
use crate::identity::CanonicalUsername;
use crate::openpgp_crypto::{Error as CryptoError, Operation, Outcome};
use crate::openpgp_crypto_protocol::{self as wire, Request, Verifier, MAX_FRAME};
use crate::openpgp_inventory::Error;
use crate::openpgp_inventory_runtime::{
    file, now, private_dir, remaining, secret, validate_socket,
};
use crate::openpgp_personal::{PersonalAction, PersonalError, PersonalState, PrivateSession};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Native primitive tests alone do not qualify service principals/key custody.
pub const NATIVE_CONFINEMENT_QUALIFIED: bool = true;
#[path = "openpgp_crypto_personal.rs"]
mod personal;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    account: String,
    home: PathBuf,
    signer_fingerprint: Option<String>,
    decrypt_fingerprints: Vec<String>,
    recipient_fingerprints: Vec<String>,
    /// Trusted operator opt-in: encryption may use suitable primary keys already
    /// in this mapped account home. Native validation remains authoritative.
    #[serde(default)]
    allow_imported_recipients: bool,
    #[serde(default)]
    allow_web_personal_keys: bool,
}
fn valid_fingerprint(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
impl Mapping {
    fn validate(&self) -> Result<(), Error> {
        CanonicalUsername::parse(&self.account).map_err(|_| Error::Invalid)?;
        if self.allow_web_personal_keys
            && (self.decrypt_fingerprints.len() != 1
                || self.signer_fingerprint.is_none()
                || !self.account.contains('@'))
        {
            return Err(Error::Invalid);
        }
        if self
            .signer_fingerprint
            .as_ref()
            .is_some_and(|s| !valid_fingerprint(s))
            || self.decrypt_fingerprints.len() > 32
            || self.recipient_fingerprints.len() > 200
        {
            return Err(Error::Invalid);
        }
        for values in [&self.decrypt_fingerprints, &self.recipient_fingerprints] {
            let mut seen = BTreeSet::new();
            if values
                .iter()
                .any(|v| !valid_fingerprint(v) || !seen.insert(v))
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    fn authorize(&self, request: &Request) -> Result<Operation, Error> {
        if request.account() != self.account {
            return Err(Error::Authentication);
        }
        let operation = request.operation(&self.decrypt_fingerprints)?;
        match &operation {
            Operation::Sign {
                signer_fingerprint, ..
            } if self.signer_fingerprint.as_ref() != Some(signer_fingerprint) => {
                return Err(Error::Authentication)
            }
            Operation::Encrypt {
                recipient_fingerprints,
                ..
            } if !self.allow_imported_recipients
                && recipient_fingerprints
                    .iter()
                    .any(|fp| !self.recipient_fingerprints.contains(fp)) =>
            {
                return Err(Error::Authentication)
            }
            Operation::Decrypt { .. } if self.decrypt_fingerprints.is_empty() => {
                return Err(Error::Authentication)
            }
            _ => (),
        }
        Ok(operation)
    }
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
            || c.accounts.is_empty()
            || c.accounts.len() > 128
            || !c.socket.is_absolute()
            || c.socket.as_os_str().len() > 100
            || c.socket.file_name().is_none()
        {
            return Err(Error::Invalid);
        }
        file(&c.worker, owner, true, 64 * 1024 * 1024)?;
        // This engine is the reviewed shim, which confines its fixed system GPG invocation.
        file(&c.engine, owner, true, 64 * 1024 * 1024)?;
        private_dir(c.socket.parent().ok_or(Error::Invalid)?, owner, true)?;
        let mut accounts = BTreeSet::new();
        let mut homes: BTreeSet<&PathBuf> = BTreeSet::new();
        for m in &c.accounts {
            m.validate()?;
            if !accounts.insert(&m.account)
                || homes
                    .iter()
                    .any(|other| m.home.starts_with(other) || other.starts_with(&m.home))
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
struct Permit<'a>(&'a Admissions, String);
impl Admissions {
    fn enter(&self, account: &str) -> Result<Permit<'_>, Error> {
        let mut a = self.0.lock().map_err(|_| Error::Unavailable)?;
        if a.len() >= 2 || !a.insert(account.into()) {
            return Err(Error::Capacity);
        }
        Ok(Permit(self, account.into()))
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut a) = self.0 .0.lock() {
            a.remove(&self.1);
        }
    }
}
pub struct Service {
    config: Config,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
    admissions: Admissions,
    personal: Mutex<personal::Manager>,
}
impl Service {
    pub fn from_operator_files(config: &Path, key: &Path) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            config: Config::load(config)?,
            key: secret(key)?,
            verifier: Mutex::new(Verifier::default()),
            admissions: Admissions::default(),
            personal: Mutex::new(personal::Manager::default()),
        })
    }
    fn process(
        &self,
        bytes: &[u8],
        deadline: Instant,
        execute: impl FnOnce(&Path, &Path, &Path, &Operation, Instant) -> Result<Outcome, CryptoError>,
    ) -> Result<Vec<u8>, Error> {
        let request = self
            .verifier
            .lock()
            .map_err(|_| Error::Unavailable)?
            .request(bytes, &self.key, now()?)?;
        let mapping = self
            .config
            .accounts
            .iter()
            .find(|m| m.account == request.account())
            .ok_or(Error::Authentication)?;
        let _permit = self.admissions.enter(request.account())?;
        let deadline = deadline
            .min(Instant::now() + Duration::from_secs(request.expires().saturating_sub(now()?)));
        remaining(deadline)?;
        if let Some(action) = request.personal_name() {
            let result = (|| {
                let context = self.personal_context(mapping)?;
                let (certificate, passphrase) = request
                    .personal_parts()
                    .map_err(|_| PersonalError::Invalid)?;
                if action == "personal_forget" && request.session().is_none() {
                    let mut manager = self
                        .personal
                        .lock()
                        .map_err(|_| PersonalError::Unavailable)?;
                    manager.forget(request.account(), passphrase)?;
                    return Ok(PersonalState {
                        primary_fingerprint: context.primary.into(),
                        private_revision: "0".repeat(64),
                        installed: false,
                        protected_at_rest: false,
                        unlocked_for_session: false,
                        valid_until: None,
                        remembered_until: None,
                        cache_seconds: crate::openpgp_personal::CACHE_SECONDS,
                    });
                }
                let session = request.session().ok_or(PersonalError::Invalid)?;
                let action = match action {
                    "personal_status" => PersonalAction::Status,
                    "personal_import" => PersonalAction::Import {
                        certificate,
                        passphrase,
                    },
                    "personal_unlock" => PersonalAction::Unlock { passphrase },
                    "personal_lock" => PersonalAction::Lock,
                    "personal_remember" => PersonalAction::Remember { token: passphrase },
                    "personal_resume" => PersonalAction::Resume { token: passphrase },
                    "personal_forget" => PersonalAction::Forget { token: passphrase },
                    _ => return Err(PersonalError::Invalid),
                };
                self.personal
                    .lock()
                    .map_err(|_| PersonalError::Unavailable)?
                    .handle(context, session, action, deadline)
            })();
            return wire::personal_response(&request, result, &self.key, now()?);
        }
        let operation = mapping.authorize(&request)?;
        if mapping.allow_web_personal_keys
            && matches!(
                operation,
                Operation::Sign { .. } | Operation::Decrypt { .. }
            )
        {
            let permitted = self.personal_context(mapping).ok().is_some_and(|context| {
                self.personal.lock().is_ok_and(|mut manager| {
                    manager.permitted(&context, request.session(), deadline)
                })
            });
            if !permitted {
                return wire::response(&request, Err(CryptoError::Locked), &self.key, now()?);
            }
        }
        let outcome = execute(
            &self.config.worker,
            &self.config.engine,
            &mapping.home,
            &operation,
            deadline,
        )
        .and_then(|v| {
            v.validate_for(&operation)?;
            Ok(v)
        });
        wire::response(&request, outcome, &self.key, now()?)
    }
    fn personal_context<'a>(
        &'a self,
        mapping: &'a Mapping,
    ) -> Result<personal::Context<'a>, PersonalError> {
        if !mapping.allow_web_personal_keys || mapping.decrypt_fingerprints.len() != 1 {
            return Err(PersonalError::Unavailable);
        }
        Ok(personal::Context {
            account: &mapping.account,
            home: &mapping.home,
            primary: &mapping.decrypt_fingerprints[0],
            signer: mapping
                .signer_fingerprint
                .as_deref()
                .ok_or(PersonalError::Unavailable)?,
            worker: &self.config.worker,
            engine: &self.config.engine,
        })
    }
    #[cfg(test)]
    fn connection(&self, stream: UnixStream) -> Result<(), Error> {
        self.connection_with_executor(
            stream,
            &AtomicBool::new(false),
            |worker, engine, home, operation, deadline, cancelled| {
                crate::openpgp_crypto_process::execute_cancellable(
                    worker, engine, home, operation, deadline, cancelled,
                )
            },
        )
    }
    fn connection_with_executor(
        &self,
        mut stream: UnixStream,
        stopped: &AtomicBool,
        execute: impl FnOnce(
            &Path,
            &Path,
            &Path,
            &Operation,
            Instant,
            &mut dyn FnMut() -> Result<bool, CryptoError>,
        ) -> Result<Outcome, CryptoError>,
    ) -> Result<(), Error> {
        if stopped.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.config.trusted_web_uid
        {
            return Err(Error::Authentication);
        }
        let bytes = read_frame(&mut stream, deadline)?;
        // After the sole complete request, this connection carries no further
        // input. EOF or unexpected input cancels owned work without a new frame.
        let mut cancelled = || {
            if stopped.load(Ordering::SeqCst) {
                return Ok(true);
            }
            crate::openbsd::completed_request_peer_closed(&stream)
                .map_err(|_| CryptoError::Unavailable)
        };
        let result = self.process(
            &bytes,
            deadline,
            |worker, engine, home, operation, deadline| {
                execute(worker, engine, home, operation, deadline, &mut cancelled)
            },
        )?;
        if cancelled().unwrap_or(true) {
            return Err(Error::Unavailable);
        }
        write_frame(&mut stream, &result, deadline)
    }
    pub fn serve(self) -> Result<(), Error> {
        if !cfg!(target_os = "openbsd") || !NATIVE_CONFINEMENT_QUALIFIED {
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
        self.serve_loop(
            listener,
            |worker, engine, home, operation, deadline, cancelled| {
                crate::openpgp_crypto_process::execute_cancellable(
                    worker, engine, home, operation, deadline, cancelled,
                )
            },
        )
    }
    fn serve_loop<E>(self, listener: UnixListener, execute: E) -> Result<(), Error>
    where
        E: Fn(
                &Path,
                &Path,
                &Path,
                &Operation,
                Instant,
                &mut dyn FnMut() -> Result<bool, CryptoError>,
            ) -> Result<Outcome, CryptoError>
            + Send
            + Sync
            + 'static,
    {
        let signals =
            crate::openbsd::CryptoTerminationSignals::install().map_err(|_| Error::Unavailable)?;
        let stopped = signals.stop_flag();
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::Unavailable)?;
        let service = Arc::new(self);
        let execute = Arc::new(execute);
        let mut active: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut failed = false;
        while !stopped.load(Ordering::SeqCst) {
            let mut index = 0;
            while index < active.len() {
                if active[index].is_finished() {
                    if active.swap_remove(index).join().is_err() {
                        failed = true;
                        stopped.store(true, Ordering::SeqCst);
                    }
                } else {
                    index += 1;
                }
            }
            if stopped.load(Ordering::SeqCst) {
                break;
            }
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    failed = true;
                    break;
                }
            };
            if active.len() >= 2 {
                continue;
            }
            // OpenBSD may inherit the listener's nonblocking flag on accept.
            if stream.set_nonblocking(false).is_err() {
                failed = true;
                break;
            }
            let service = service.clone();
            let execute = execute.clone();
            let thread = std::thread::Builder::new().spawn(move || {
                let _ = service.connection_with_executor(
                    stream,
                    stopped,
                    |worker, engine, home, operation, deadline, cancelled| {
                        execute(worker, engine, home, operation, deadline, cancelled)
                    },
                );
            });
            match thread {
                Ok(thread) => active.push(thread),
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        // Stop admission first, then cancel and join the existing two bounded
        // connections. Partial frames retain their original ten-second budget;
        // active workers observe this flag through the same owned cleanup path.
        stopped.store(true, Ordering::SeqCst);
        drop(listener);
        for thread in active {
            if thread.join().is_err() {
                failed = true;
            }
        }
        drop(signals);
        if failed {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "openpgp_crypto_runtime_lifecycle_tests.rs"]
pub(crate) mod lifecycle_tests;
struct ClientState {
    socket: PathBuf,
    helper_uid: u32,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
}
#[derive(Clone)]
pub struct Client(Arc<ClientState>, Option<PrivateSession>);
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoClient")
            .field("socket", &self.0.socket)
            .field("helper_uid", &self.0.helper_uid)
            .finish_non_exhaustive()
    }
}
impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        self.0.socket == other.0.socket
            && self.0.helper_uid == other.0.helper_uid
            && self.0.key == other.0.key
    }
}
impl Eq for Client {}
impl Client {
    pub fn from_operator_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(|_| Error::Unavailable)?;
        validate_socket(socket, helper_uid)?;
        Ok(Self(
            Arc::new(ClientState {
                socket: socket.into(),
                helper_uid,
                key: secret(key)?,
                verifier: Mutex::new(Verifier::default()),
            }),
            None,
        ))
    }
    pub fn for_session(&self, session: PrivateSession) -> Self {
        Self(self.0.clone(), Some(session))
    }
    pub fn personal(
        &self,
        account: &str,
        session: &PrivateSession,
        action: PersonalAction<'_>,
    ) -> Result<PersonalState, PersonalError> {
        let convert = |error| match error {
            Error::Expired => PersonalError::Expired,
            Error::Invalid => PersonalError::Invalid,
            _ => PersonalError::Unavailable,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let request = Request::issue_personal(
            account,
            session,
            action,
            now().map_err(convert)?,
            &self.0.key,
        )
        .map_err(convert)?;
        let bytes = self.exchange(&request, deadline).map_err(convert)?;
        self.0
            .verifier
            .lock()
            .map_err(|_| PersonalError::Unavailable)?
            .personal_response(&request, &bytes, &self.0.key, now().map_err(convert)?)
            .map_err(convert)?
    }
    /// Revoke a remembered capability even after its browser session expired.
    /// This authenticated transport action cannot grant private-key access.
    pub fn forget_remembered(&self, account: &str, token: &[u8]) -> Result<(), PersonalError> {
        let convert = |_| PersonalError::Unavailable;
        let request = Request::issue_forget(account, token, now().map_err(convert)?, &self.0.key)
            .map_err(convert)?;
        let bytes = self
            .exchange(&request, Instant::now() + Duration::from_secs(10))
            .map_err(convert)?;
        self.0
            .verifier
            .lock()
            .map_err(|_| PersonalError::Unavailable)?
            .personal_response(&request, &bytes, &self.0.key, now().map_err(convert)?)
            .map_err(convert)?
            .map(|_| ())
    }
    pub fn execute(
        &self,
        account: &str,
        operation: &Operation,
    ) -> Result<Result<Outcome, CryptoError>, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut request = Request::issue(account, operation, now()?, &self.0.key)?;
        if let Some(session) = &self.1 {
            request.bind_session(session.clone(), now()?, &self.0.key)?;
        }
        let bytes = self.exchange(&request, deadline)?;
        self.0
            .verifier
            .lock()
            .map_err(|_| Error::Unavailable)?
            .response(&request, &bytes, operation, &self.0.key, now()?)
    }
    fn exchange(&self, request: &Request, deadline: Instant) -> Result<Vec<u8>, Error> {
        validate_socket(&self.0.socket, self.0.helper_uid)?;
        let mut stream = crate::openbsd::connect_unix_before(&self.0.socket, deadline)
            .map_err(|_| Error::Unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.0.helper_uid
        {
            return Err(Error::Authentication);
        }
        write_frame(&mut stream, &request.to_bytes()?, deadline)?;
        read_frame(&mut stream, deadline)
    }
}
fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, Error> {
    fn read(
        stream: &mut UnixStream,
        mut output: &mut [u8],
        deadline: Instant,
    ) -> Result<(), Error> {
        while !output.is_empty() {
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|_| Error::Unavailable)?;
            let n = stream.read(output).map_err(|_| Error::Unavailable)?;
            if n == 0 {
                return Err(Error::Unavailable);
            }
            output = &mut output[n..];
        }
        Ok(())
    }
    let mut size = [0; 4];
    read(stream, &mut size, deadline)?;
    let n = u32::from_be_bytes(size) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut body = vec![0; n];
    read(stream, &mut body, deadline)?;
    Ok(body)
}
fn write_frame(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    for mut part in [&(bytes.len() as u32).to_be_bytes()[..], bytes] {
        while !part.is_empty() {
            stream
                .set_write_timeout(Some(remaining(deadline)?))
                .map_err(|_| Error::Unavailable)?;
            let n = stream.write(part).map_err(|_| Error::Unavailable)?;
            if n == 0 {
                return Err(Error::Unavailable);
            }
            part = &part[n..];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Run under a disposable web or unauthorized UID against the production
    /// service in an isolated native qualification deployment. Values are only
    /// paths, public fingerprints and expected outcomes; no credential output.
    #[test]
    #[ignore = "requires isolated OpenBSD helper/web service principals"]
    fn native_crypto_principal_client() {
        assert_eq!(std::env::consts::OS, "openbsd");
        let env = |name| std::env::var(name).expect("native principal fixture setting");
        let socket = PathBuf::from(env("OSMAP_CRYPTO_PRINCIPAL_SOCKET"));
        let key = PathBuf::from(env("OSMAP_CRYPTO_PRINCIPAL_KEY"));
        let uid: u32 = env("OSMAP_CRYPTO_PRINCIPAL_HELPER_UID").parse().unwrap();
        let mode = env("OSMAP_CRYPTO_PRINCIPAL_MODE");
        let afp = env("OSMAP_CRYPTO_PRINCIPAL_ALICE_FP");
        let bfp = env("OSMAP_CRYPTO_PRINCIPAL_BOB_FP");
        let client = Client::from_operator_files(&socket, &key, uid).unwrap();
        let sign = Operation::Sign {
            signer_fingerprint: afp.clone(),
            data: b"disposable principal fixture\r\n".to_vec(),
        };
        if mode == "peer_denied" {
            assert!(client.execute("alice", &sign).is_err());
            return;
        }
        assert_eq!(mode, "authorized");
        let signed = client.execute("alice", &sign).unwrap().unwrap();
        let verified = client
            .execute(
                "bob",
                &Operation::Verify {
                    data: b"disposable principal fixture\r\n".to_vec(),
                    signature: signed.content,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(verified.primary_fingerprint.as_deref(), Some(afp.as_str()));
        assert!(client
            .execute(
                "alice",
                &Operation::Sign {
                    signer_fingerprint: bfp.clone(),
                    data: b"foreign signer".to_vec(),
                }
            )
            .is_err());
        assert!(Client::from_operator_files(&socket, &key, uid.saturating_add(1)).is_err());
        for name in [
            "OSMAP_CRYPTO_PRINCIPAL_ALICE_HOME",
            "OSMAP_CRYPTO_PRINCIPAL_BOB_HOME",
        ] {
            let home = PathBuf::from(env(name));
            assert!(fs::read(home.join("pubring.kbx")).is_err());
            assert!(fs::read_dir(home.join("private-keys-v1.d")).is_err());
        }
        crate::protected_message::native_tests::run_client_fixture(&client, &afp, &bfp);
    }
    fn mapping() -> Mapping {
        Mapping {
            account: "alice".into(),
            home: "/operator/only".into(),
            signer_fingerprint: Some("A".repeat(40)),
            decrypt_fingerprints: vec!["B".repeat(40)],
            recipient_fingerprints: vec!["C".repeat(40)],
            allow_imported_recipients: false,
            allow_web_personal_keys: false,
        }
    }
    #[test]
    fn imported_recipient_opt_in_is_default_off_and_never_changes_private_authority() {
        let raw = serde_json::json!({"account":"alice","home":"/operator/only",
            "signer_fingerprint":"A".repeat(40),"decrypt_fingerprints":["B".repeat(40)],"recipient_fingerprints":[]});
        let mut mapping: Mapping = serde_json::from_value(raw).unwrap();
        assert!(!mapping.allow_imported_recipients);
        let key = [7; 32];
        let encrypt = Operation::Encrypt {
            recipient_fingerprints: vec!["D".repeat(40)],
            data: b"public fixture".to_vec(),
        };
        let request = Request::issue("alice", &encrypt, 100, &key).unwrap();
        assert!(mapping.authorize(&request).is_err());
        mapping.allow_imported_recipients = true;
        assert!(mapping.authorize(&request).is_ok()); // Native local-key checks still run after this boundary.
        assert!(mapping
            .authorize(&Request::issue("bob", &encrypt, 100, &key).unwrap())
            .is_err());
        let sign = Operation::Sign {
            signer_fingerprint: "D".repeat(40),
            data: b"fixture".to_vec(),
        };
        assert!(mapping
            .authorize(&Request::issue("alice", &sign, 100, &key).unwrap())
            .is_err());
        let decrypt = Operation::Decrypt {
            allowed_primary_fingerprints: vec!["D".repeat(40)],
            ciphertext: b"fixture".to_vec(),
        };
        assert!(
            matches!(mapping.authorize(&Request::issue("alice",&decrypt,100,&key).unwrap()).unwrap(),
            Operation::Decrypt{allowed_primary_fingerprints,..} if allowed_primary_fingerprints==vec!["B".repeat(40)])
        );
        mapping.decrypt_fingerprints.clear();
        assert!(mapping
            .authorize(&Request::issue("alice", &decrypt, 100, &key).unwrap())
            .is_err());
    }

    #[test]
    fn authority_is_account_and_exact_fingerprint_bound() {
        let m = mapping();
        m.validate().unwrap();
        let key = [7; 32];
        let sign = |fp: String| Operation::Sign {
            signer_fingerprint: fp,
            data: b"data".to_vec(),
        };
        assert!(m
            .authorize(&Request::issue("alice", &sign("A".repeat(40)), 100, &key).unwrap())
            .is_ok());
        assert!(m
            .authorize(&Request::issue("bob", &sign("A".repeat(40)), 100, &key).unwrap())
            .is_err());
        assert!(m
            .authorize(&Request::issue("alice", &sign("D".repeat(40)), 100, &key).unwrap())
            .is_err());
        let encrypt = Operation::Encrypt {
            recipient_fingerprints: vec!["D".repeat(40)],
            data: b"data".to_vec(),
        };
        assert!(m
            .authorize(&Request::issue("alice", &encrypt, 100, &key).unwrap())
            .is_err());
        let decrypt = Operation::Decrypt {
            allowed_primary_fingerprints: vec!["D".repeat(40)],
            ciphertext: b"encrypted".to_vec(),
        };
        match m
            .authorize(&Request::issue("alice", &decrypt, 100, &key).unwrap())
            .unwrap()
        {
            Operation::Decrypt {
                allowed_primary_fingerprints,
                ..
            } => assert_eq!(allowed_primary_fingerprints, m.decrypt_fingerprints),
            _ => panic!("wrong operation"),
        }
    }
    #[test]
    fn admissions_refuse_same_account_and_global_third_worker() {
        let a = Admissions::default();
        let first = a.enter("alice").unwrap();
        assert!(matches!(a.enter("alice"), Err(Error::Capacity)));
        let _second = a.enter("bob").unwrap();
        assert!(matches!(a.enter("carol"), Err(Error::Capacity)));
        drop(first);
        assert!(a.enter("carol").is_ok());
    }
    #[test]
    fn authenticated_dispatch_rejects_unknown_accounts_fingerprints_and_replays_before_execution() {
        let key = [9; 32];
        let now = now().unwrap();
        let service = Service {
            config: Config {
                version: 1,
                worker: "/operator/worker".into(),
                engine: "/operator/engine".into(),
                socket: "/operator/socket".into(),
                trusted_web_uid: 0,
                accounts: vec![mapping()],
            },
            key: key.to_vec(),
            verifier: Mutex::new(Verifier::default()),
            admissions: Admissions::default(),
            personal: Mutex::new(personal::Manager::default()),
        };
        let sign = |fp: String| Operation::Sign {
            signer_fingerprint: fp,
            data: b"canonical MIME bytes\r\n".to_vec(),
        };
        for (account, fp) in [("bob", "A"), ("alice", "D")] {
            let r = Request::issue(account, &sign(fp.repeat(40)), now, &key).unwrap();
            assert!(service
                .process(
                    &r.to_bytes().unwrap(),
                    Instant::now() + Duration::from_secs(10),
                    |_, _, _, _, _| panic!("unauthorized worker dispatch")
                )
                .is_err());
        }
        let operation = sign("A".repeat(40));
        let request = Request::issue("alice", &operation, now, &key).unwrap();
        let bytes = request.to_bytes().unwrap();
        let response=service.process(&bytes,Instant::now()+Duration::from_secs(10),|worker,engine,home,op,_| {
            assert_eq!(worker,Path::new("/operator/worker"));assert_eq!(engine,Path::new("/operator/engine"));assert_eq!(home,Path::new("/operator/only"));
            assert!(matches!(op,Operation::Sign {signer_fingerprint,..} if signer_fingerprint==&"A".repeat(40)));
            Err(CryptoError::Locked)
        }).unwrap();
        assert_eq!(
            Verifier::default()
                .response(&request, &response, &operation, &key, now)
                .unwrap()
                .err(),
            Some(CryptoError::Locked)
        );
        assert!(matches!(
            service.process(
                &bytes,
                Instant::now() + Duration::from_secs(10),
                |_, _, _, _, _| panic!("replayed worker dispatch")
            ),
            Err(Error::Replay)
        ));
    }
    #[test]
    #[ignore = "native disposable GPGME service/client fixture; invoked by crypto native harness"]
    fn native_crypto_authenticated_service_client() {
        assert_eq!(std::env::consts::OS, "openbsd");
        let path = |name: &str| PathBuf::from(std::env::var(name).unwrap());
        let worker = path("OSMAP_CRYPTO_NATIVE_WORKER");
        let engine = path("OSMAP_CRYPTO_NATIVE_ENGINE");
        let alice = path("OSMAP_CRYPTO_NATIVE_ALICE_HOME");
        let bob = path("OSMAP_CRYPTO_NATIVE_BOB_HOME");
        let afp = std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap();
        let bfp = std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap();
        let scratch = worker.parent().unwrap();
        assert!(scratch.starts_with("/tmp"));
        assert!(scratch
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("osmap-crypto-fixture-"));
        let socket = scratch.join("rust-service.sock");
        let config = scratch.join("rust-service.json");
        let key_file = scratch.join("rust-service.key");
        let mut key = [0; 32];
        getrandom::getrandom(&mut key).unwrap();
        let raw = serde_json::json!({"version":1,"worker":worker,"engine":engine,"socket":socket,"trusted_web_uid":crate::openbsd::effective_uid(),"accounts":[
            {"account":"alice","home":alice,"signer_fingerprint":afp,"decrypt_fingerprints":[afp],"recipient_fingerprints":[bfp]},
            {"account":"bob","home":bob,"signer_fingerprint":bfp,"decrypt_fingerprints":[bfp],"recipient_fingerprints":[afp]}
        ]});
        fs::write(&config, serde_json::to_vec(&raw).unwrap()).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&key_file, key).unwrap();
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        let service = Service::from_operator_files(&config, &key_file).unwrap();
        // Direct fixture listener exercises production connection/peer/frame/dispatch
        // code. It deliberately does not bypass or qualify the activation gate.
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..5 + crate::protected_message::native_tests::CLIENT_REQUESTS {
                let (stream, _) = listener.accept().unwrap();
                let _ = service.connection(stream);
            }
        });
        let client =
            Client::from_operator_files(&socket, &key_file, crate::openbsd::effective_uid())
                .unwrap();
        let data =
            b"Content-Type: text/plain\r\n\r\nSynthetic authenticated crypto fixture.\r\n".to_vec();
        let signed = client
            .execute(
                "alice",
                &Operation::Sign {
                    signer_fingerprint: afp.clone(),
                    data: data.clone(),
                },
            )
            .unwrap()
            .unwrap();
        let verified = client
            .clone()
            .execute(
                "bob",
                &Operation::Verify {
                    data: data.clone(),
                    signature: signed.content,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(verified.primary_fingerprint, Some(afp.clone()));
        let encrypted = client
            .execute(
                "alice",
                &Operation::Encrypt {
                    recipient_fingerprints: vec![bfp.clone()],
                    data: data.clone(),
                },
            )
            .unwrap()
            .unwrap();
        let decrypted = client
            .execute(
                "bob",
                &Operation::Decrypt {
                    allowed_primary_fingerprints: vec![bfp.clone()],
                    ciphertext: encrypted.content,
                },
            )
            .unwrap()
            .unwrap();
        assert!(decrypted.content == data);
        assert!(client
            .execute(
                "alice",
                &Operation::Sign {
                    signer_fingerprint: bfp.clone(),
                    data
                }
            )
            .is_err());
        crate::protected_message::native_tests::run_client_fixture(&client, &afp, &bfp);
        server.join().unwrap();
        for f in [&socket, &config, &key_file] {
            fs::remove_file(f).unwrap();
        }
    }
}
