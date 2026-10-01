//! Account-mapped crypto dispatcher and client. Web requests carry typed bytes
//! and full fingerprint selections; only operator configuration supplies homes.
use crate::identity::CanonicalUsername;
use crate::openpgp_crypto::{Error as CryptoError, Operation, Outcome};
use crate::openpgp_crypto_protocol::{self as wire, Request, Verifier, MAX_FRAME};
use crate::openpgp_inventory::Error;
use crate::openpgp_inventory_runtime::{
    file, now, private_dir, remaining, secret, validate_socket,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Native primitive tests alone do not qualify service principals/key custody.
pub const NATIVE_CONFINEMENT_QUALIFIED: bool = true;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    account: String,
    home: PathBuf,
    signer_fingerprint: Option<String>,
    decrypt_fingerprints: Vec<String>,
    recipient_fingerprints: Vec<String>,
}
fn valid_fingerprint(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
impl Mapping {
    fn validate(&self) -> Result<(), Error> {
        CanonicalUsername::parse(&self.account).map_err(|_| Error::Invalid)?;
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
            } if recipient_fingerprints
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
        let operation = mapping.authorize(&request)?;
        let _permit = self.admissions.enter(request.account())?;
        let deadline = deadline
            .min(Instant::now() + Duration::from_secs(request.expires().saturating_sub(now()?)));
        remaining(deadline)?;
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
    fn connection(&self, mut stream: UnixStream) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.config.trusted_web_uid
        {
            return Err(Error::Authentication);
        }
        let bytes = read_frame(&mut stream, deadline)?;
        let result = self.process(&bytes, deadline, crate::openpgp_crypto_process::execute)?;
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
    helper_uid: u32,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
}
#[derive(Clone)]
pub struct Client(Arc<ClientState>);
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
        Ok(Self(Arc::new(ClientState {
            socket: socket.into(),
            helper_uid,
            key: secret(key)?,
            verifier: Mutex::new(Verifier::default()),
        })))
    }
    pub fn execute(
        &self,
        account: &str,
        operation: &Operation,
    ) -> Result<Result<Outcome, CryptoError>, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let request = Request::issue(account, operation, now()?, &self.0.key)?;
        validate_socket(&self.0.socket, self.0.helper_uid)?;
        let mut stream = crate::openbsd::connect_unix_before(&self.0.socket, deadline)
            .map_err(|_| Error::Unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| Error::Authentication)?
            != self.0.helper_uid
        {
            return Err(Error::Authentication);
        }
        write_frame(&mut stream, &request.to_bytes()?, deadline)?;
        let bytes = read_frame(&mut stream, deadline)?;
        self.0
            .verifier
            .lock()
            .map_err(|_| Error::Unavailable)?
            .response(&request, &bytes, operation, &self.0.key, now()?)
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
        }
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
