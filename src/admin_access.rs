//! Authenticated, scoped reads in the trusted admin backend. Construction and
//! private state paths belong to the backend, never to a browser/request.
use crate::admin_directory::{Adapter, Domain, Scope};
use crate::auth::{
    AuthenticationContext, CommandExecutor, RequiredSecondFactor, SecondFactorVerdict,
    SecondFactorVerifier,
};
use crate::session::{FileSessionStore, SessionService, SessionToken, SystemRandomSource};
use crate::throttle::{
    FileLoginThrottleStore, LoginThrottleDecision, LoginThrottlePolicy, LoginThrottleService,
};
use crate::totp::{FileTotpSecretStore, TimeProvider, TotpPolicy, TotpVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROGRAM: &str = "/usr/local/bin/mariadb";
const ARGS: &[&str] = &[
    "--defaults-file=/etc/osmap/admin-read-mariadb.cnf",
    "--database=postfixadmin",
    "--batch",
    "--skip-column-names",
    "--raw",
];
const PREFIX: &str = "osmap-admin1.";
const MAX_LOGIN: usize = 96;
const ADMIN_QUERY: &str = "SELECT HEX(a.username),HEX(a.password),a.active,HEX(CAST(a.modified AS CHAR)),a.superadmin,HEX(d.domain) FROM admin a LEFT JOIN domain_admins d ON BINARY d.username=BINARY a.username AND d.active=1 WHERE BINARY a.username=BINARY ? ORDER BY BINARY d.domain LIMIT 17";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Denied,
    Unavailable,
    Invalid,
    Unsupported,
}

/// Raw passwords/hashes and bearer tokens deliberately have no Debug/Serialize.
pub(crate) struct Token(String);
impl Token {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn presented(value: &str) -> Result<Self, Error> {
        let raw = value.strip_prefix(PREFIX).ok_or(Error::Denied)?;
        if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Denied);
        }
        Ok(Self(value.into()))
    }
    fn session(&self) -> Result<SessionToken, Error> {
        SessionToken::new(self.0.strip_prefix(PREFIX).ok_or(Error::Denied)?)
            .map_err(|_| Error::Denied)
    }
}
struct Admin {
    login: String,
    hash: String,
    epoch: u64,
    generation: String,
    domains: Vec<String>,
    system: bool,
    active: bool,
}
impl Admin {
    fn subject(&self) -> String {
        format!(
            "admin.{}.{}",
            upper_hex(self.login.as_bytes()),
            self.generation
        )
    }
}
fn valid_login(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LOGIN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
}
fn upper_hex(s: &[u8]) -> String {
    s.iter().map(|b| format!("{b:02X}")).collect()
}
fn unhex(s: &str) -> Result<String, Error> {
    if s.len() > 2048 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Unavailable);
    }
    let bytes = s
        .as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let text = std::str::from_utf8(p).map_err(|_| Error::Unavailable)?;
            u8::from_str_radix(text, 16).map_err(|_| Error::Unavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| Error::Unavailable)
}
fn factor_subject(login: &str) -> String {
    format!("admin-{:x}", Sha256::digest(login.as_bytes()))
}

#[derive(Clone)]
struct Authority<E> {
    executor: E,
    root: PathBuf,
}
impl<E: CommandExecutor> Authority<E> {
    fn lookup(&self, login: &str, initialize: bool) -> Result<Option<Admin>, Error> {
        if !valid_login(login) {
            return Err(Error::Invalid);
        }
        private_root(&self.root)?;
        let input = format!("SET @admin_login=CONVERT(0x{} USING utf8mb4); PREPARE admin_read FROM '{}'; EXECUTE admin_read USING @admin_login;\n", upper_hex(login.as_bytes()), ADMIN_QUERY);
        let args = ARGS.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let output = self
            .executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                PROGRAM,
                &args,
                input.as_bytes(),
                Duration::from_secs(10),
                16384,
            )
            .map_err(|_| Error::Unavailable)?;
        if output.status_code != 0
            || !output.stderr.is_empty()
            || output.stdout.len() > 16384
            || !output.stdout.is_ascii()
        {
            return Err(Error::Unavailable);
        }
        use crate::totp::TotpSecretStore as _;
        let secret = self.factors().load_secret(&factor_subject(login));
        let mut fingerprint = Sha256::new();
        fingerprint.update(b"osmap-admin-authority-v1\0");
        fingerprint.update(output.stdout.as_bytes());
        match &secret {
            Ok(Some(value)) => fingerprint.update(&value.secret_bytes),
            Ok(None) => fingerprint.update(b"factor-absent"),
            Err(_) => fingerprint.update(b"factor-unavailable"),
        }
        let fingerprint = format!("{:x}", fingerprint.finalize());
        let epoch = self.observe(login, &fingerprint, initialize && !output.stdout.is_empty())?;
        let secret = secret.map_err(|_| Error::Unavailable)?;
        let rows = output.stdout.lines().collect::<Vec<_>>();
        if rows.len() > 16 {
            return Err(Error::Unavailable);
        }
        if rows.is_empty() {
            return Ok(None);
        }
        let mut identity: Option<Vec<String>> = None;
        let mut domains = Vec::new();
        let mut has_all = false;
        for line in &rows {
            let parts = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
            if parts.len() != 6
                || !matches!(parts[2].as_str(), "0" | "1")
                || !matches!(parts[4].as_str(), "0" | "1")
            {
                return Err(Error::Unavailable);
            }
            if identity
                .as_ref()
                .is_some_and(|first| first[..5] != parts[..5])
            {
                return Err(Error::Unavailable);
            }
            if parts[5] != "NULL" {
                let domain = unhex(&parts[5])?;
                if domain == "ALL" {
                    if has_all {
                        return Err(Error::Unavailable);
                    }
                    has_all = true;
                } else {
                    Scope::domains(&[&domain]).map_err(|_| Error::Denied)?;
                    if domains.contains(&domain) {
                        return Err(Error::Unavailable);
                    }
                    domains.push(domain);
                }
            }
            identity = Some(parts);
        }
        let identity = identity.ok_or(Error::Unavailable)?;
        if unhex(&identity[0])? != login {
            return Err(Error::Unavailable);
        }
        // Compatibility requires the current flag and active legacy grant to
        // agree. Neither indicator alone can grant installation-wide reads.
        let system = identity[4] == "1";
        if system != has_all {
            return Err(Error::Denied);
        }
        let hash = unhex(&identity[1])?;
        if !bcrypt(&hash) {
            return Err(Error::Unsupported);
        }
        if secret.is_none() {
            return Ok(None);
        }
        let (epoch, generation) = epoch.ok_or(Error::Unavailable)?;
        Ok(Some(Admin {
            login: login.into(),
            hash,
            epoch,
            generation,
            domains,
            system,
            active: identity[2] == "1",
        }))
    }
    fn factors(&self) -> FileTotpSecretStore {
        FileTotpSecretStore::new(self.root.join("factors"))
            .with_replay_dir(self.root.join("replay"))
    }
    fn bound(&self, subject: &str, epoch: u64) -> Result<Admin, Error> {
        let rest = subject.strip_prefix("admin.").ok_or(Error::Denied)?;
        let (encoded, _) = rest.split_once('.').ok_or(Error::Denied)?;
        let login = unhex(encoded).map_err(|_| Error::Denied)?;
        let admin = self.lookup(&login, false)?.ok_or(Error::Denied)?;
        if !admin.active || admin.subject() != subject || admin.epoch != epoch {
            return Err(Error::Denied);
        }
        Ok(admin)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    fingerprint: String,
    epoch: u64,
    generation: String,
}
impl<E> Authority<E> {
    fn observe(
        &self,
        login: &str,
        fingerprint: &str,
        create: bool,
    ) -> Result<Option<(u64, String)>, Error> {
        let store = crate::private_account_file::PrivateAccountFile::new(
            self.root.join("epochs"),
            "osmap-admin-generation-v1",
            1024,
        );
        // Unknown submitted names do not create unbounded per-name state.
        if !create && store.read(login).map_err(|_| Error::Unavailable)?.is_none() {
            return Ok(None);
        }
        let held = store.lock(login).map_err(|_| Error::Unavailable)?;
        let previous = held.read().map_err(|_| Error::Unavailable)?;
        let mut record = match previous {
            Some(bytes) => {
                serde_json::from_slice::<Generation>(&bytes).map_err(|_| Error::Unavailable)?
            }
            None => {
                let mut random = [0u8; 16];
                getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
                Generation {
                    fingerprint: fingerprint.into(),
                    epoch: 1,
                    generation: upper_hex(&random),
                }
            }
        };
        if record.epoch == 0
            || record.epoch > crate::account_admission::MAX_EPOCH
            || record.fingerprint.len() != 64
            || record.generation.len() != 32
            || !record.generation.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Unavailable);
        }
        if record.fingerprint != fingerprint {
            record.epoch = record
                .epoch
                .checked_add(1)
                .filter(|e| *e <= crate::account_admission::MAX_EPOCH)
                .ok_or(Error::Unavailable)?;
            record.fingerprint = fingerprint.into();
        }
        held.write(&serde_json::to_vec(&record).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?;
        Ok(Some((record.epoch, record.generation)))
    }
}
type AdmissionFailure = Arc<Mutex<Option<Error>>>;
type Sessions<T> = SessionService<FileSessionStore, T, SystemRandomSource>;
struct Admission<E> {
    authority: Arc<Authority<E>>,
    failure: AdmissionFailure,
}
impl<E: CommandExecutor + Send + Sync> crate::account_admission::EpochAuthority for Admission<E> {
    fn admit(&self, subject: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        let result = self.authority.bound(subject, epoch).map(|_| ());
        *self
            .failure
            .lock()
            .map_err(|_| crate::account_admission::Error::Unavailable)? =
            result.as_ref().err().copied();
        result.map_err(|e| match e {
            Error::Unavailable => crate::account_admission::Error::Unavailable,
            _ => crate::account_admission::Error::Refused,
        })
    }
}
fn admission_failure(failure: &AdmissionFailure) -> Error {
    failure
        .lock()
        .ok()
        .and_then(|f| *f)
        .unwrap_or(Error::Denied)
}

fn bcrypt(hash: &str) -> bool {
    crate::openbsd::admin_bcrypt_hash_supported(hash)
}
pub(crate) trait PasswordVerifier {
    fn verify(&self, password: &str, hash: &str) -> Result<bool, Error>;
}
pub(crate) struct NativePassword;
impl PasswordVerifier for NativePassword {
    fn verify(&self, password: &str, hash: &str) -> Result<bool, Error> {
        crate::openbsd::admin_password_matches(password, hash).map_err(|_| Error::Unavailable)
    }
}
pub(crate) struct Service<E, T, P = NativePassword> {
    authority: Arc<Authority<E>>,
    clock: T,
    password: P,
}
impl<
        E: CommandExecutor + Clone + Send + Sync + 'static,
        T: TimeProvider + Clone,
        P: PasswordVerifier,
    > Service<E, T, P>
{
    /// Trusted composition only. No request chooses executor, verifier or path.
    pub(crate) fn new(executor: E, clock: T, password: P, root: PathBuf) -> Result<Self, Error> {
        private_root(&root)?;
        for child in ["factors", "replay", "sessions", "throttle", "epochs"] {
            let path = root.join(child);
            if !path.exists() {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .map_err(|_| Error::Unavailable)?;
            }
            private_root(&path)?;
        }
        Ok(Self {
            authority: Arc::new(Authority { executor, root }),
            clock,
            password,
        })
    }
    fn sessions(&self) -> (Sessions<T>, AdmissionFailure) {
        let failure = Arc::new(Mutex::new(None));
        let sessions = SessionService::new(
            FileSessionStore::new(self.authority.root.join("sessions")),
            self.clock.clone(),
            SystemRandomSource,
            900,
            300,
        )
        .with_epoch_authority(Arc::new(Admission {
            authority: self.authority.clone(),
            failure: failure.clone(),
        }));
        (sessions, failure)
    }
    fn context() -> AuthenticationContext {
        // Internal/local backend for this slice. A future authenticated transport
        // must supply its own verified peer binding, not an HTTP forwarded field.
        AuthenticationContext {
            request_id: "admin-local".into(),
            remote_addr: format!("local-uid-{}", crate::openbsd::real_uid()),
            user_agent: "admin-backend".into(),
        }
    }
    pub(crate) fn login(&self, login: &str, password: &str, code: &str) -> Result<Token, Error> {
        if !valid_login(login)
            || password.is_empty()
            || password.len() > 72
            || password.bytes().any(|b| b == 0)
            || code.len() != 6
            || !code.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Invalid);
        }
        let throttle = LoginThrottleService::new(
            FileLoginThrottleStore::new(self.authority.root.join("throttle")),
            self.clock.clone(),
            LoginThrottlePolicy::default(),
        );
        let context = Self::context();
        if throttle
            .check(&context, login)
            .map_err(|_| Error::Unavailable)?
            .decision
            != LoginThrottleDecision::Allowed
        {
            return Err(Error::Denied);
        }
        let admin = self.authority.lookup(login, true)?;
        let dummy = "$2b$12$.....................................................";
        let hash = admin.as_ref().map_or(dummy, |a| a.hash.as_str());
        let matched = self.password.verify(password, hash)?;
        let Some(admin) = admin.filter(|a| a.active && matched) else {
            throttle
                .record_failure(&context, login)
                .map_err(|_| Error::Unavailable)?;
            return Err(Error::Denied);
        };
        let factor = TotpVerifier::new(
            self.authority.factors(),
            self.clock.clone(),
            TotpPolicy::default(),
        )
        .verify_second_factor(
            &factor_subject(&admin.login),
            RequiredSecondFactor::Totp,
            code,
        )
        .map_err(|_| Error::Unavailable)?;
        if factor != SecondFactorVerdict::Accept {
            throttle
                .record_failure(&context, login)
                .map_err(|_| Error::Unavailable)?;
            return Err(Error::Denied);
        }
        throttle
            .clear_success(&context, login)
            .map_err(|_| Error::Unavailable)?;
        let (sessions, failure) = self.sessions();
        let session = sessions
            .issue_with_epoch(
                &context,
                &admin.subject(),
                RequiredSecondFactor::Totp,
                Some(admin.epoch),
            )
            .map_err(|_| match admission_failure(&failure) {
                Error::Denied => Error::Unavailable,
                e => e,
            })?;
        Ok(Token(format!("{PREFIX}{}", session.token.as_str())))
    }
    pub(crate) fn domain(&self, token: &Token, domain: &str) -> Result<Option<Domain>, Error> {
        let (sessions, failure) = self.sessions();
        let session = sessions
            .validate(&Self::context(), &token.session()?)
            .map_err(|_| admission_failure(&failure))?;
        let epoch = session.record.account_epoch.ok_or(Error::Denied)?;
        let admin = self
            .authority
            .bound(&session.record.canonical_username, epoch)?;
        let names = if admin.system {
            vec![domain]
        } else {
            admin.domains.iter().map(String::as_str).collect::<Vec<_>>()
        };
        let scope = Scope::domains(&names).map_err(|_| {
            if admin.system {
                Error::Invalid
            } else {
                Error::Denied
            }
        })?;
        // Validate before dispatching any directory query, including existence.
        Adapter::new(self.authority.executor.clone())
            .domain(&scope, domain)
            .map_err(|e| match e {
                crate::admin_directory::Error::Unauthorized => Error::Denied,
                crate::admin_directory::Error::Invalid => Error::Invalid,
                _ => Error::Unavailable,
            })
    }
    pub(crate) fn logout(&self, token: &Token) -> Result<(), Error> {
        self.sessions()
            .0
            .revoke_by_token(&Self::context(), &token.session()?)
            .map(|_| ())
            .map_err(|_| Error::Denied)
    }
}
fn private_root(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt as _;
    let m = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !path.is_absolute()
        || path.canonicalize().map_err(|_| Error::Unavailable)? != path
        || !m.is_dir()
        || m.uid() != crate::openbsd::effective_uid()
        || m.mode() & 0o7777 != 0o700
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
#[path = "admin_access_tests.rs"]
mod tests;
