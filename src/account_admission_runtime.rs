//! Peer-authenticated private account-helper transport; production remains off.
use crate::account_admission::{
    valid_epoch, Admission, EpochAuthority, Error, Operation, Request, Verifier, MAX_FRAME,
};
use crate::openpgp_inventory_runtime::{
    file, now, private_dir, read_frame, secret, validate_socket, write_frame,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Source construction cannot opt out of actual native/helper confinement qualification.
pub const NATIVE_CONFINEMENT_QUALIFIED: bool = false;
const WORKER: &str = "/usr/local/libexec/osmap/account-runtime/account_admission_worker.py";
// Closed sibling source closure of the private worker, including the material
// and command factory's function-local imports. No request/config can add one.
const WORKER_MODULES: [&str; 33] = [
    "account_admission_worker.py",
    "account_command_kernel.py",
    "account_epoch.py",
    "account_guarded_mutation.py",
    "account_hash_graph.py",
    "account_hash_graph_pins.py",
    "account_hash_identity.py",
    "account_mutation_budget.py",
    "account_mutation_codec.py",
    "account_mutation_continuity.py",
    "account_mutation_grant.py",
    "account_mutation_native.py",
    "account_mutation_supervisor.py",
    "account_mutation_worker.py",
    "account_native_material.py",
    "account_primary_graph.py",
    "account_primary_identity.py",
    "account_sql_graph.py",
    "account_sql_graph_pins.py",
    "authoritative_password.py",
    "mail_session_containment.py",
    "mutation_primary.py",
    "operation_budget.py",
    "prepared_password.py",
    "smtp_auth_control.py",
    "smtp_auth_control_service.py",
    "smtp_auth_lifecycle.py",
    "smtp_control_authorization.py",
    "smtp_control_startup.py",
    "smtp_guarded_builder.py",
    "smtp_mutation_containment.py",
    "smtp_native_peer.py",
    "smtp_topology.py",
];
const ENGINE: &str = "/usr/local/bin/python3";
const ENGINE_TARGET: &str = "python3.13";
const EPOCH_ROOT: &str = "/var/db/osmap-account/epoch";
type AdmissionStatus = (u64, Option<String>);
fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}
fn worker_module_custody(root: &Path, owner: u32) -> Result<(), Error> {
    // Root and all ancestors use the existing guarded directory/file readers.
    // Only native startup selects the fixed installed root and owner0.
    private_dir(root, owner, true).map_err(unavailable)?;
    let root_before =
        AdmissionEndpoint::identity(&fs::symlink_metadata(root).map_err(unavailable)?);
    for name in WORKER_MODULES {
        let path = root.join(name);
        let before = installed_identity(&fs::symlink_metadata(&path).map_err(unavailable)?);
        let descriptor = file(&path, owner, false, 128 * 1024).map_err(unavailable)?;
        if before.5 != 1
            || before != installed_identity(&descriptor.metadata().map_err(unavailable)?)
            || before != installed_identity(&fs::symlink_metadata(&path).map_err(unavailable)?)
        {
            return Err(Error::Unavailable);
        }
    }
    if root_before != AdmissionEndpoint::identity(&fs::symlink_metadata(root).map_err(unavailable)?)
    {
        return Err(Error::Unavailable);
    }
    Ok(())
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
    engine: Option<InstalledEngine>,
}
impl Service {
    /// Fixed helper entry only. The existing native gate must qualify the
    /// private-primary worker and its supervisor before listener activation;
    /// source construction never authorizes the ordinary auth-test fallback.
    pub fn serve(self, stop: &AtomicBool) -> Result<(), Error> {
        if !cfg!(target_os = "openbsd")
            || !NATIVE_CONFINEMENT_QUALIFIED
            || crate::openbsd::effective_uid() != 0
        {
            return Err(Error::Unavailable);
        }
        // Process-global setup precedes both confinement and connection threads.
        std::env::set_current_dir("/").map_err(unavailable)?;
        self.serve_with_status_policy(
            stop,
            &|request, deadline| self.native_worker(request, deadline),
            &|endpoint| {
                self.engine
                    .as_ref()
                    .ok_or(Error::Unavailable)?
                    .confine_parent(endpoint)
            },
        )
    }

    #[cfg(test)]
    fn serve_with<F>(&self, stop: &AtomicBool, execute: &F) -> Result<(), Error>
    where
        F: Fn(&Request, Instant) -> Result<Option<u64>, Error> + Sync,
    {
        self.serve_with_policy(stop, execute, &|_| Ok(()))
    }

    #[cfg(test)]
    fn serve_with_policy<F, P>(
        &self,
        stop: &AtomicBool,
        execute: &F,
        confine: &P,
    ) -> Result<(), Error>
    where
        F: Fn(&Request, Instant) -> Result<Option<u64>, Error> + Sync,
        P: Fn(&AdmissionEndpoint) -> Result<(), Error>,
    {
        self.serve_with_status_policy(
            stop,
            &|r, d| execute(r, d).map(|v| v.map(|epoch| (epoch, None))),
            confine,
        )
    }

    fn serve_with_status_policy<F, P>(
        &self,
        stop: &AtomicBool,
        execute: &F,
        confine: &P,
    ) -> Result<(), Error>
    where
        F: Fn(&Request, Instant) -> Result<Option<AdmissionStatus>, Error> + Sync,
        P: Fn(&AdmissionEndpoint) -> Result<(), Error>,
    {
        let mut endpoint = AdmissionEndpoint::bind(&self.config.socket)?;
        // Publication is complete, so the steady-state policy needs neither
        // chown nor fattr. Failure drops only this exact owned endpoint; no
        // accept or credential frame is permitted before successful sealing.
        confine(&endpoint)?;
        let result = std::thread::scope(|scope| {
            let mut active: Vec<std::thread::ScopedJoinHandle<'_, ()>> = Vec::new();
            loop {
                endpoint.recheck()?;
                if self.cleanup_unconfirmed.load(Ordering::SeqCst) {
                    return Err(Error::CleanupUnconfirmed);
                }
                // Admission stops; dispatched connections retain their one
                // existing deadline. Scoped joins complete before unlink.
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                let mut pending = Vec::new();
                for handle in active.drain(..) {
                    if handle.is_finished() {
                        handle.join().map_err(unavailable)?;
                    } else {
                        pending.push(handle);
                    }
                }
                active = pending;
                if active.len() == 2 {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                match endpoint.listener.accept() {
                    Ok((mut stream, _)) => {
                        endpoint.recheck()?;
                        if stop.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                        if self.cleanup_unconfirmed.load(Ordering::SeqCst) {
                            return Err(Error::CleanupUnconfirmed);
                        }
                        active.push(scope.spawn(move || {
                            // Existing exact kernel-peer admission precedes
                            // reading any frame; MAC/replay/account checks and
                            // quarantine remain on the persistent Service.
                            let _ = self.connection_with_status(&mut stream, execute);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return Err(Error::Unavailable),
                }
            }
        });
        let result = result.and_then(|()| {
            if self.cleanup_unconfirmed.load(Ordering::SeqCst) {
                Err(Error::CleanupUnconfirmed)
            } else {
                Ok(())
            }
        });
        let cleanup = endpoint.remove();
        result.and(cleanup)
    }

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
        // Match NativeMaterial's one observed package alias; no general
        // following or caller-selected interpreter target is admitted.
        let engine = InstalledEngine::observe(
            Path::new(ENGINE),
            0,
            Instant::now() + Duration::from_secs(5),
        )?;
        worker_module_custody(Path::new(WORKER).parent().ok_or(Error::Invalid)?, 0)?;
        Ok(Self {
            active: Mutex::new(BTreeSet::new()),
            cleanup_unconfirmed: std::sync::atomic::AtomicBool::new(false),
            config: c,
            key: secret(key).map_err(unavailable)?,
            verifier: Mutex::new(Verifier::default()),
            engine: Some(engine),
        })
    }
    #[cfg(test)]
    fn process(
        &self,
        bytes: &[u8],
        at: u64,
        execute: impl FnOnce(&Request) -> Result<Option<u64>, Error>,
    ) -> Result<Vec<u8>, Error> {
        self.process_with_status(bytes, at, |request| {
            execute(request).map(|v| v.map(|epoch| (epoch, None)))
        })
    }
    fn process_with_status(
        &self,
        bytes: &[u8],
        at: u64,
        execute: impl FnOnce(&Request) -> Result<Option<AdmissionStatus>, Error>,
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
        let (epoch, stamp) = match result {
            Some((epoch, stamp)) => (Some(epoch), stamp),
            None => (None, None),
        };
        request.response_with_status(epoch, stamp, &self.key, now().map_err(unavailable)?)
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
    #[cfg(test)]
    fn fixed_worker(request: &Request, deadline: Instant) -> Result<Option<u64>, Error> {
        Self::fixed_worker_command(request, deadline, crate::auth::account_admission_command())
    }
    #[cfg(test)]
    fn fixed_worker_command(
        request: &Request,
        deadline: Instant,
        command: std::process::Command,
    ) -> Result<Option<u64>, Error> {
        Self::fixed_worker_status_command(request, deadline, command)
            .map(|v| v.map(|(epoch, _)| epoch))
    }
    fn fixed_worker_status_command(
        request: &Request,
        deadline: Instant,
        command: std::process::Command,
    ) -> Result<Option<AdmissionStatus>, Error> {
        // Interpreter, script and module roots are fixed and operator-owned.
        // Credential JSON is exclusively stdin under the existing private,
        // nonblocking process-group transport and quarantine-on-cleanup policy.
        // Translate only the remaining original connection allowance, rounding
        // down. Sample wall time first so elapsed sampling/serialization time
        // cannot enlarge the monotonic budget. The parent still enforces this
        // exact original Instant through spawn, transfer, cleanup and response.
        let wall_millis = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(unavailable)?
                .as_millis(),
        )
        .map_err(unavailable)?;
        let left_millis = u64::try_from(
            deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Expired)?
                .as_millis(),
        )
        .map_err(unavailable)?;
        if left_millis == 0 {
            return Err(Error::Expired);
        }
        let worker_deadline = wall_millis.checked_add(left_millis).ok_or(Error::Expired)?;
        let frame = request.worker_bytes(worker_deadline)?;
        let bytes = crate::openpgp_crypto_process::run_account_admission(command, &frame, deadline)
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
            #[serde(default)]
            changed_at: Option<String>,
        }
        let r: WorkerResponse = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if r.schema == "osmap-account-admission-worker-v1"
            && r.status == "cleanup_unconfirmed"
            && r.account.is_none()
            && r.epoch.is_none()
            && r.changed_at.is_none()
        {
            return Err(Error::CleanupUnconfirmed);
        }
        if r.schema != "osmap-account-admission-worker-v1"
            || r.account.as_deref() != Some(request.account())
            || r.changed_at
                .as_deref()
                .is_some_and(|v| !crate::account_mutation::changed_at_valid(v))
            || (r.status != "active" && r.changed_at.is_some())
        {
            return Err(Error::Unavailable);
        }
        match (&request.operation(), r.status.as_str(), r.epoch) {
            (Operation::Authenticate { .. }, "rejected", None) => Ok(None),
            (Operation::Authenticate { .. }, "active", Some(epoch)) if valid_epoch(epoch) => {
                Ok(Some((epoch, r.changed_at)))
            }
            (Operation::Admit { epoch: expected }, "active", Some(epoch)) if epoch == *expected => {
                Ok(Some((epoch, r.changed_at)))
            }
            _ => Err(Error::Refused),
        }
    }
    fn native_worker(
        &self,
        request: &Request,
        deadline: Instant,
    ) -> Result<Option<AdmissionStatus>, Error> {
        // The fixed command inherits startup's `/`; a pre-exec chdir would
        // require a broad root read grant. No connection changes process cwd.
        if std::env::current_dir().map_err(unavailable)? != Path::new("/") {
            return Err(Error::Unavailable);
        }
        self.engine
            .as_ref()
            .ok_or(Error::Unavailable)?
            .recheck(deadline)?;
        Self::fixed_worker_status_command(
            request,
            deadline,
            crate::auth::account_admission_inherited_root_command().map_err(unavailable)?,
        )
    }
    /// Retained closed finite-connection API. Only `serve` owns mandatory
    /// parent sealing before reaching the private connection implementation;
    /// later qualification must never open a caller-supervised bypass.
    pub fn connection(&self, _stream: UnixStream) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
    #[cfg(test)]
    fn connection_with(
        &self,
        stream: &mut UnixStream,
        execute: impl FnOnce(&Request, Instant) -> Result<Option<u64>, Error>,
    ) -> Result<(), Error> {
        self.connection_with_status(stream, |r, d| {
            execute(r, d).map(|v| v.map(|epoch| (epoch, None)))
        })
    }
    fn connection_with_status(
        &self,
        stream: &mut UnixStream,
        execute: impl FnOnce(&Request, Instant) -> Result<Option<AdmissionStatus>, Error>,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_secs(30);
        if crate::openbsd::unix_stream_peer_uid(stream).map_err(unavailable)?
            != self.config.trusted_web_uid
        {
            return Err(Error::Authentication);
        }
        let bytes = read_frame(stream, MAX_FRAME, deadline).map_err(unavailable)?;
        let response = self.process_with_status(&bytes, now().map_err(unavailable)?, |r| {
            execute(r, deadline)
        })?;
        write_frame(stream, &response, deadline).map_err(unavailable)
    }
}

type InstalledIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
type InstalledAncestors = Vec<(PathBuf, (u64, u64, u32, u32, u32))>;
fn installed_identity(info: &fs::Metadata) -> InstalledIdentity {
    (
        info.dev(),
        info.ino(),
        info.uid(),
        info.gid(),
        info.mode(),
        info.nlink(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}
struct InstalledEngine {
    target: PathBuf,
    descriptor: File,
    ancestors: InstalledAncestors,
    target_identity: InstalledIdentity,
    target_sha256: [u8; 32],
    sealed: std::sync::OnceLock<crate::openbsd::AccountAdmissionParentSeal>,
    startup_deadline: Instant,
}
impl InstalledEngine {
    fn ancestors(target: &Path, owner: u32) -> Result<InstalledAncestors, Error> {
        let mut rows = Vec::new();
        for path in target.ancestors().skip(1) {
            // Match the existing guarded reader's OS-root trust boundary.
            // Other ancestors retain stable identity/ownership/fullmode,
            // without coupling authority to unrelated contents/timestamps.
            if path == Path::new("/") {
                break;
            }
            let m = fs::symlink_metadata(path).map_err(unavailable)?;
            let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
            if !m.is_dir()
                || (m.uid() != 0 && m.uid() != owner)
                || (m.mode() & 0o022 != 0 && !sticky_root)
            {
                return Err(Error::Unavailable);
            }
            rows.push((path.into(), (m.dev(), m.ino(), m.uid(), m.gid(), m.mode())));
        }
        Ok(rows)
    }
    fn observe(alias: &Path, owner: u32, deadline: Instant) -> Result<Self, Error> {
        if alias.file_name() != Some(std::ffi::OsStr::new("python3")) || Instant::now() >= deadline
        {
            return Err(Error::Unavailable);
        }
        let before = fs::symlink_metadata(alias).map_err(unavailable)?;
        if !before.file_type().is_symlink()
            || before.uid() != owner
            || before.nlink() != 1
            || fs::read_link(alias).map_err(unavailable)? != Path::new(ENGINE_TARGET)
        {
            return Err(Error::Unavailable);
        }
        let target = alias.parent().ok_or(Error::Invalid)?.join(ENGINE_TARGET);
        let ancestors = Self::ancestors(&target, owner)?;
        let target_before =
            installed_identity(&fs::symlink_metadata(&target).map_err(unavailable)?);
        let mut descriptor = file(&target, owner, true, 64 * 1024 * 1024).map_err(unavailable)?;
        if target_before.5 != 1
            || target_before.6 == 0
            || !crate::openbsd::descriptor_is_cloexec(descriptor.as_raw_fd())
                .map_err(unavailable)?
            || installed_identity(&descriptor.metadata().map_err(unavailable)?) != target_before
        {
            return Err(Error::Unavailable);
        }
        let mut digest = Sha256::new();
        let mut count = 0u64;
        let mut bytes = [0; 4096];
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Expired);
            }
            let read = descriptor.read(&mut bytes).map_err(unavailable)?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > 64 * 1024 * 1024 {
                return Err(Error::Unavailable);
            }
            digest.update(&bytes[..read]);
        }
        let alias_identity = installed_identity(&before);
        if count != target_before.6
            || installed_identity(&descriptor.metadata().map_err(unavailable)?) != target_before
            || installed_identity(&fs::symlink_metadata(&target).map_err(unavailable)?)
                != target_before
            || installed_identity(&fs::symlink_metadata(alias).map_err(unavailable)?)
                != alias_identity
            || fs::read_link(alias).map_err(unavailable)? != Path::new(ENGINE_TARGET)
            || Self::ancestors(&target, owner)? != ancestors
            || Instant::now() >= deadline
        {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            target,
            descriptor,
            ancestors,
            target_identity: target_before,
            target_sha256: digest.finalize().into(),
            sealed: std::sync::OnceLock::new(),
            startup_deadline: deadline,
        })
    }
    fn confine_parent(&self, endpoint: &AdmissionEndpoint) -> Result<(), Error> {
        // Same original installed-engine startup deadline, never a new cap.
        let deadline = self.startup_deadline;
        if self.sealed.get().is_some() {
            return Err(Error::Unavailable);
        }
        // Full protected pathname ancestry is mandatory immediately before the
        // real lock. Afterward unveil binds directory inodes; it does not keep
        // checking ancestor ownership/mode. Trusted administration preserves it.
        self.recheck(deadline)?;
        endpoint.recheck()?;
        let seal = crate::openbsd::apply_account_admission_parent_confinement(&endpoint.path)
            .map_err(unavailable)?;
        self.sealed.set(seal).map_err(unavailable)?;
        self.recheck(deadline)
    }
    fn recheck(&self, deadline: Instant) -> Result<(), Error> {
        // The startup alias is never dispatched after sealing. Its verified
        // fixed target keeps the original FD and full identity/hash. Before
        // actual sealing it also rechecks protected pathname ancestry. Only the
        // native token selects postseal inode binding instead of hidden lstat.
        // No readlink/canonicalize requires recursive bin/ancestor read grants.
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        let owner = self.target_identity.2;
        if (self.sealed.get().is_none() && Self::ancestors(&self.target, owner)? != self.ancestors)
            || !crate::openbsd::descriptor_is_cloexec(self.descriptor.as_raw_fd())
                .map_err(unavailable)?
            || installed_identity(&self.descriptor.metadata().map_err(unavailable)?)
                != self.target_identity
            || installed_identity(&fs::symlink_metadata(&self.target).map_err(unavailable)?)
                != self.target_identity
        {
            return Err(Error::Unavailable);
        }
        let mut digest = Sha256::new();
        let mut count = 0u64;
        let mut bytes = [0; 4096];
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Expired);
            }
            // Positional reads do not share mutable seek state between the
            // service's two bounded concurrent connection threads.
            let read = self
                .descriptor
                .read_at(&mut bytes, count)
                .map_err(unavailable)?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > 64 * 1024 * 1024 {
                return Err(Error::Unavailable);
            }
            digest.update(&bytes[..read]);
        }
        let hash: [u8; 32] = digest.finalize().into();
        if count != self.target_identity.6
            || hash != self.target_sha256
            || installed_identity(&self.descriptor.metadata().map_err(unavailable)?)
                != self.target_identity
            || installed_identity(&fs::symlink_metadata(&self.target).map_err(unavailable)?)
                != self.target_identity
            || (self.sealed.get().is_none()
                && Self::ancestors(&self.target, owner)? != self.ancestors)
        {
            return Err(Error::Unavailable);
        }
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

type EndpointIdentity = (u64, u64, u32, u32, u32, u64);
struct AdmissionEndpoint {
    listener: UnixListener,
    path: PathBuf,
    parent: File,
    parent_identity: EndpointIdentity,
    socket_identity: EndpointIdentity,
    removed: bool,
}
impl AdmissionEndpoint {
    fn identity(info: &fs::Metadata) -> EndpointIdentity {
        (
            info.dev(),
            info.ino(),
            info.uid(),
            info.gid(),
            info.mode(),
            info.nlink(),
        )
    }
    fn bind(path: &Path) -> Result<Self, Error> {
        let owner = crate::openbsd::effective_uid();
        let parent_path = path.parent().ok_or(Error::Invalid)?;
        private_dir(parent_path, owner, true).map_err(unavailable)?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(parent_path)
            .map_err(unavailable)?;
        let parent_identity = Self::identity(&parent.metadata().map_err(unavailable)?);
        if Self::identity(&fs::symlink_metadata(parent_path).map_err(unavailable)?)
            != parent_identity
        {
            return Err(Error::Unavailable);
        }
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::Unavailable),
        }
        let listener = UnixListener::bind(path).map_err(unavailable)?;
        let info = fs::symlink_metadata(path).map_err(unavailable)?;
        if !info.file_type().is_socket() || info.uid() != owner || info.nlink() != 1 {
            return Err(Error::Unavailable);
        }
        let mut endpoint = Self {
            listener,
            path: path.into(),
            parent,
            parent_identity,
            socket_identity: Self::identity(&info),
            removed: false,
        };
        endpoint.recheck()?;
        // The source-owned namespace's group grants only reachability. It
        // never substitutes for the independently checked exact kernel UID.
        std::os::unix::fs::chown(path, Some(owner), Some(parent_identity.3))
            .map_err(unavailable)?;
        let group_info = fs::symlink_metadata(path).map_err(unavailable)?;
        if (
            group_info.dev(),
            group_info.ino(),
            group_info.uid(),
            group_info.gid(),
            group_info.mode(),
            group_info.nlink(),
        ) != (
            info.dev(),
            info.ino(),
            owner,
            parent_identity.3,
            info.mode(),
            1,
        ) {
            return Err(Error::Unavailable);
        }
        endpoint.socket_identity = Self::identity(&group_info);
        fs::set_permissions(path, fs::Permissions::from_mode(0o660)).map_err(unavailable)?;
        let published = fs::symlink_metadata(path).map_err(unavailable)?;
        if (
            published.dev(),
            published.ino(),
            published.uid(),
            published.gid(),
            published.mode(),
            published.nlink(),
        ) != (
            info.dev(),
            info.ino(),
            owner,
            parent_identity.3,
            libc::S_IFSOCK | 0o660,
            1,
        ) {
            return Err(Error::Unavailable);
        }
        endpoint.socket_identity = Self::identity(&published);
        endpoint.recheck()?;
        endpoint
            .listener
            .set_nonblocking(true)
            .map_err(unavailable)?;
        Ok(endpoint)
    }
    fn recheck(&self) -> Result<(), Error> {
        let parent_path = self.path.parent().ok_or(Error::Invalid)?;
        if Self::identity(&self.parent.metadata().map_err(unavailable)?) != self.parent_identity
            || Self::identity(&fs::symlink_metadata(parent_path).map_err(unavailable)?)
                != self.parent_identity
            || Self::identity(&fs::symlink_metadata(&self.path).map_err(unavailable)?)
                != self.socket_identity
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn remove(&mut self) -> Result<(), Error> {
        self.recheck()?;
        fs::remove_file(&self.path).map_err(unavailable)?;
        self.removed = true;
        Ok(())
    }
}
impl Drop for AdmissionEndpoint {
    fn drop(&mut self) {
        if !self.removed {
            // Never delete a stale, replaced or foreign inode on an error path.
            let _ = self.remove();
        }
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
/// Account-only custody captured with full protected pathname checks before
/// confinement. After an actual Serve seal, unveil pins the admitted leaves;
/// retained exact key descriptors and current socket identity avoid hidden
/// ancestor pathname reads. No directory read capability survives startup.
/// Parent/ancestor custody after locked unveil is administrative trust, not
/// continuous postseal ownership/mode observation.
pub(crate) struct AccountClientPaths {
    socket: PathBuf,
    helper_uid: u32,
    socket_identity: EndpointIdentity,
    parent_identity: (u64, u64, u32, u32, u32),
    keys: Vec<(PathBuf, File, EndpointIdentity, Vec<u8>)>,
    seal: std::sync::OnceLock<Arc<crate::openbsd::ServeAccountSeal>>,
}
impl AccountClientPaths {
    // Child directory creation changes nlink without changing this protected
    // parent's identity or authority. Socket/key single-link checks stay exact.
    fn parent_identity(info: &fs::Metadata) -> (u64, u64, u32, u32, u32) {
        (info.dev(), info.ino(), info.uid(), info.gid(), info.mode())
    }
    pub(crate) fn observe(
        socket: &Path,
        helper_uid: u32,
        keys: &[(&Path, &[u8])],
    ) -> Result<Self, Error> {
        validate_socket(socket, helper_uid).map_err(unavailable)?;
        let socket_identity =
            AdmissionEndpoint::identity(&fs::symlink_metadata(socket).map_err(unavailable)?);
        if socket_identity.5 != 1 {
            return Err(Error::Unavailable);
        }
        let parent_path = socket.parent().ok_or(Error::Invalid)?;
        let parent_identity =
            Self::parent_identity(&fs::symlink_metadata(parent_path).map_err(unavailable)?);
        let mut retained_keys = Vec::new();
        for (path, bytes) in keys {
            let handle =
                file(path, crate::openbsd::effective_uid(), false, 1024).map_err(unavailable)?;
            let identity = AdmissionEndpoint::identity(&handle.metadata().map_err(unavailable)?);
            if identity.5 != 1
                || !crate::openbsd::descriptor_is_cloexec(handle.as_raw_fd())
                    .map_err(unavailable)?
            {
                return Err(Error::Unavailable);
            }
            retained_keys.push(((*path).into(), handle, identity, bytes.to_vec()));
        }
        let value = Self {
            socket: socket.into(),
            helper_uid,
            socket_identity,
            parent_identity,
            keys: retained_keys,
            seal: std::sync::OnceLock::new(),
        };
        value.recheck()?;
        Ok(value)
    }
    pub(crate) fn finalize(
        &self,
        seal: Arc<crate::openbsd::ServeAccountSeal>,
    ) -> Result<(), Error> {
        let paths: Vec<_> = self
            .keys
            .iter()
            .map(|(path, _, _, _)| path.clone())
            .collect();
        if !seal.permits(&self.socket, &paths, self.helper_uid) {
            return Err(Error::Unavailable);
        }
        // Enforcement has already hidden ancestor metadata. No weakened phase
        // is reachable until the exact native capability has been verified.
        self.recheck_leaves()?;
        self.seal.set(seal).map_err(unavailable)?;
        Ok(())
    }
    pub(crate) fn recheck(&self) -> Result<(), Error> {
        if self.seal.get().is_none() {
            validate_socket(&self.socket, self.helper_uid).map_err(unavailable)?;
            if Self::parent_identity(
                &fs::symlink_metadata(self.socket.parent().ok_or(Error::Invalid)?)
                    .map_err(unavailable)?,
            ) != self.parent_identity
            {
                return Err(Error::Unavailable);
            }
            for (path, _, _, _) in &self.keys {
                crate::openpgp_inventory_runtime::exact_path(path, crate::openbsd::effective_uid())
                    .map_err(unavailable)?;
            }
        }
        self.recheck_leaves()
    }
    fn recheck_leaves(&self) -> Result<(), Error> {
        if AdmissionEndpoint::identity(&fs::symlink_metadata(&self.socket).map_err(unavailable)?)
            != self.socket_identity
        {
            return Err(Error::Unavailable);
        }
        for (path, handle, identity, expected) in &self.keys {
            if AdmissionEndpoint::identity(&handle.metadata().map_err(unavailable)?) != *identity
                || AdmissionEndpoint::identity(&fs::symlink_metadata(path).map_err(unavailable)?)
                    != *identity
            {
                return Err(Error::Unavailable);
            }
            // Positioned reads preserve the retained descriptor's shared
            // offset across concurrent clients; a changed key is never adopted.
            let mut bytes = [0; 1025];
            let mut length = 0;
            while length < bytes.len() {
                let count = handle
                    .read_at(&mut bytes[length..], length as u64)
                    .map_err(unavailable)?;
                if count == 0 {
                    break;
                }
                length += count;
            }
            if &bytes[..length] != expected
                || AdmissionEndpoint::identity(&handle.metadata().map_err(unavailable)?)
                    != *identity
                || AdmissionEndpoint::identity(&fs::symlink_metadata(path).map_err(unavailable)?)
                    != *identity
            {
                return Err(Error::Unavailable);
            }
        }
        Ok(())
    }
    pub(crate) fn preflight_serve(
        &self,
        socket: &Path,
        keys: &[&Path],
        helper_uid: u32,
    ) -> Result<(), Error> {
        if self.seal.get().is_some()
            || self.socket != socket
            || self.helper_uid != helper_uid
            || self.keys.len() != keys.len()
            || self
                .keys
                .iter()
                .zip(keys)
                .any(|((actual, _, _, _), expected)| actual.as_path() != *expected)
        {
            return Err(Error::Unavailable);
        }
        self.recheck()
    }
}

struct ClientState {
    socket: PathBuf,
    key_file: PathBuf,
    helper_uid: u32,
    key: Vec<u8>,
    verifier: Mutex<Verifier>,
    paths: AccountClientPaths,
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
    pub(crate) fn preflight_serve(
        &self,
        config: &crate::config::AccountRuntimeConfig,
    ) -> Result<(), Error> {
        self.0.paths.preflight_serve(
            &config.admission_socket,
            &[&config.admission_key_file],
            config.admission_helper_uid,
        )
    }
    pub(crate) fn has_purpose_key(&self, key: &[u8]) -> bool {
        self.0.key == key
    }
    pub(crate) fn finalize_serve(
        &self,
        seal: Arc<crate::openbsd::ServeAccountSeal>,
    ) -> Result<(), Error> {
        self.0.paths.finalize(seal)
    }
    #[cfg(test)]
    pub(crate) fn paired_fixture_files(socket: &Path, key: &Path, uid: u32) -> Result<Self, Error> {
        Self::qualified_files(socket, key, uid)
    }
    pub fn from_operator_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        if !NATIVE_CONFINEMENT_QUALIFIED {
            return Err(Error::Unavailable);
        }
        Self::qualified_files(socket, key, helper_uid)
    }
    fn qualified_files(socket: &Path, key: &Path, helper_uid: u32) -> Result<Self, Error> {
        crate::openbsd::disable_core_dumps().map_err(unavailable)?;
        validate_socket(socket, helper_uid).map_err(unavailable)?;
        let bytes = secret(key).map_err(unavailable)?;
        let paths = AccountClientPaths::observe(socket, helper_uid, &[(key, &bytes)])?;
        Ok(Self(Arc::new(ClientState {
            socket: socket.into(),
            key_file: key.into(),
            helper_uid,
            key: bytes,
            verifier: Mutex::new(Verifier::default()),
            paths,
        })))
    }
    fn execute(&self, account: &str, operation: Operation) -> Result<Option<Admission>, Error> {
        self.execute_before(account, operation, Instant::now() + Duration::from_secs(30))
    }
    fn execute_before(
        &self,
        account: &str,
        operation: Operation,
        original_deadline: Instant,
    ) -> Result<Option<Admission>, Error> {
        self.execute_before_with_clock(account, operation, original_deadline, || {
            now().map_err(unavailable)
        })
    }
    fn execute_before_with_clock(
        &self,
        account: &str,
        operation: Operation,
        original_deadline: Instant,
        clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<Option<Admission>, Error> {
        self.execute_status_before_with_clock(account, operation, original_deadline, clock)
            .map(|v| v.0)
    }
    fn execute_status_before_with_clock(
        &self,
        account: &str,
        operation: Operation,
        original_deadline: Instant,
        mut clock: impl FnMut() -> Result<u64, Error>,
    ) -> Result<(Option<Admission>, Option<String>), Error> {
        // Preserve the caller's one workflow budget and this adapter's existing
        // maximum; neither connection nor verification starts a new deadline.
        let deadline = original_deadline.min(Instant::now() + Duration::from_secs(30));
        crate::openpgp_inventory_runtime::remaining(deadline).map_err(|_| Error::Expired)?;
        let mut previous = clock()?;
        let request = Request::issue(account, operation, previous, &self.0.key)?;
        let mut check = || -> Result<u64, Error> {
            crate::openpgp_inventory_runtime::remaining(deadline).map_err(|_| Error::Expired)?;
            let at = clock()?;
            if at < previous {
                return Err(Error::Expired);
            }
            request.valid(&self.0.key, at)?;
            // A clock callback or validation cannot consume the remaining
            // original budget and still return a late authorization.
            crate::openpgp_inventory_runtime::remaining(deadline).map_err(|_| Error::Expired)?;
            previous = at;
            Ok(at)
        };
        self.0.paths.recheck()?;
        check()?;
        let mut stream =
            crate::openbsd::connect_unix_before(&self.0.socket, deadline).map_err(unavailable)?;
        if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)? != self.0.helper_uid
        {
            return Err(Error::Authentication);
        }
        self.0.paths.recheck()?;
        check()?;
        write_frame(&mut stream, &request.bytes()?, deadline).map_err(unavailable)?;
        check()?;
        let bytes = read_frame(&mut stream, MAX_FRAME, deadline).map_err(unavailable)?;
        let at = check()?;
        // A held verifier must not turn a bounded operation into a blocking
        // lock wait. The authenticated result is withheld until the final check.
        let result = self
            .0
            .verifier
            .try_lock()
            .map_err(unavailable)?
            .response_with_status(&request, &bytes, &self.0.key, at)?;
        check()?;
        Ok(result)
    }
    /// Read only the active own-account record for this exact session epoch.
    /// Pending/contained/stale authority is refused by the unchanged worker.
    pub fn password_changed_at_before(
        &self,
        account: &str,
        epoch: u64,
        deadline: Instant,
    ) -> Result<Option<String>, Error> {
        let (admission, stamp) = self.execute_status_before_with_clock(
            account,
            Operation::Admit { epoch },
            deadline,
            || now().map_err(unavailable),
        )?;
        let admitted = admission.ok_or(Error::Refused)?;
        if admitted.account != account || admitted.epoch != epoch {
            return Err(Error::Refused);
        }
        Ok(stamp)
    }
    /// Revalidate the exact epoch within the original workflow deadline.
    /// This does not renew preparation freshness or prove native confinement.
    pub fn admit_before(
        &self,
        account: &str,
        epoch: u64,
        original_deadline: Instant,
    ) -> Result<(), Error> {
        self.execute_before(account, Operation::Admit { epoch }, original_deadline)?
            .map(|_| ())
            .ok_or(Error::Refused)
    }
    pub fn authenticate_before(
        &self,
        username: &str,
        password: &str,
        original_deadline: Instant,
    ) -> Result<Option<Admission>, Error> {
        self.execute_before(
            username,
            Operation::Authenticate {
                password: password.into(),
            },
            original_deadline,
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
    fn admit_before(&self, account: &str, epoch: u64, deadline: Instant) -> Result<(), Error> {
        Client::admit_before(self, account, epoch, deadline)
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
