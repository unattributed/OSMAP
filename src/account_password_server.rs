//! Fixed Rust account service. Listener lifetime/custody and admission replay
//! reuse the existing account transport; no Python application is dispatched.
//! Native qualification remains closed. Fixed live submission authority and
//! the owning Rust parent seal precede all accepted connection handling.
use crate::account_admission::Error;
use crate::account_admission_runtime::{AdmissionEndpoint, Service as AdmissionService};
use crate::account_password_backend::Backend;
use crate::account_password_connection::Keys;
use crate::account_password_imap::Registry;
use crate::account_password_mail::SubmissionNamespace;
use crate::account_password_native::{NativeProfile, Role};
use crate::account_password_peer::{NativeInspector, Startup};
use crate::account_password_policy::{Fence, MonotonicClock};
use crate::account_password_policy_endpoint::Endpoint;
use crate::account_password_process::FixedExecutor;
use crate::account_password_process::MetadataExecutor;
use crate::account_password_runtime::Runtime;
use crate::account_password_state::Store;
use crate::auth::CommandExecutor;
use crate::openpgp_inventory_runtime::{file, private_dir, secret};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROOT: &str = "/etc/osmap/account-runtime";
const EPOCH: &str = "/var/db/osmap-account/epoch";
const ADMISSION: &str = "/var/run/osmap-account-admission/admission.sock";
const MUTATION: &str = "/var/run/osmap-account-mutation/mutation.sock";
const PUBLICATION: &str = "/var/run/osmap-account/imap-publication.sock";
const FILES: [&str; 5] = [
    "config.json",
    "mutation.key",
    "session-proof.key",
    "imap-publication.json",
    "imap-policy.key",
];
type Identity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
fn identity(m: &fs::Metadata) -> Identity {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationConfig {
    version: u8,
    authority: String,
    purpose: String,
    accounts: Vec<String>,
    trusted_relay_uid: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationConfig {
    version: u8,
    authority: String,
    purpose: String,
    master_pid: u32,
    connector_gid: u32,
}
struct OperatorFiles {
    accounts: BTreeSet<String>,
    relay_uid: u32,
    master_pid: u32,
    connector_gid: u32,
    mutation: Vec<u8>,
    session: Vec<u8>,
    policy: [u8; 64],
    captured: Vec<Identity>,
    root: Identity,
}
impl OperatorFiles {
    fn read(deadline: Instant) -> Result<Self, Error> {
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        let root = Path::new(ROOT);
        private_dir(root, 0, false).map_err(unavailable)?;
        let root_identity = identity(&fs::symlink_metadata(root).map_err(unavailable)?);
        if root_identity.4 & 0o077 != 0 {
            return Err(Error::Unavailable);
        }
        let captured = FILES
            .iter()
            .map(|name| {
                fs::symlink_metadata(root.join(name))
                    .map(|m| identity(&m))
                    .map_err(unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let read = |name: &str| -> Result<Vec<u8>, Error> {
            let mut bytes = Vec::new();
            file(&root.join(name), 0, false, 16384)
                .map_err(unavailable)?
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(unavailable)?;
            Ok(bytes)
        };
        let mutation_config: MutationConfig =
            serde_json::from_slice(&read("config.json")?).map_err(unavailable)?;
        let publication: PublicationConfig =
            serde_json::from_slice(&read("imap-publication.json")?).map_err(unavailable)?;
        let mutation = secret(&root.join("mutation.key")).map_err(unavailable)?;
        let session = secret(&root.join("session-proof.key")).map_err(unavailable)?;
        let policy = read("imap-policy.key")?;
        let accounts = mutation_config
            .accounts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if mutation_config.version != 1
            || mutation_config.authority != "mail.blackbagsecurity.com"
            || mutation_config.purpose != "osmap-account-mutation"
            || mutation_config.trusted_relay_uid == 0
            || mutation_config.trusted_relay_uid == u32::MAX
            || accounts.is_empty()
            || accounts.len() > 64
            || accounts.len() != mutation_config.accounts.len()
            || accounts
                .iter()
                .any(|a| crate::account_admission::valid_account(a).is_err())
            || publication.version != 1
            || publication.authority != "mail.blackbagsecurity.com"
            || publication.purpose != "osmap-imap-publication"
            || publication.master_pid <= 1
            || publication.master_pid >= i32::MAX as u32
            || publication.connector_gid == 0
            || publication.connector_gid == u32::MAX
            || policy.len() != 64
            || !policy
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || mutation == session
            || policy == mutation
            || policy == session
        {
            return Err(Error::Unavailable);
        }
        let value = Self {
            accounts,
            relay_uid: mutation_config.trusted_relay_uid,
            master_pid: publication.master_pid,
            connector_gid: publication.connector_gid,
            mutation,
            session,
            policy: policy.try_into().map_err(unavailable)?,
            captured,
            root: root_identity,
        };
        value.recheck(deadline)?;
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        Ok(value)
    }
    fn recheck(&self, deadline: Instant) -> Result<(), Error> {
        crate::account_password_custody::ancestors(ROOT, None, deadline).map_err(unavailable)?;
        let root = crate::account_password_custody::directory_metadata(ROOT, 0, deadline)
            .map_err(unavailable)?;
        if root.mode() & 0o077 != 0 || identity(&root) != self.root {
            return Err(Error::Unavailable);
        }
        for (name, expected) in FILES.iter().zip(&self.captured) {
            if identity(&fs::symlink_metadata(Path::new(ROOT).join(name)).map_err(unavailable)?)
                != *expected
            {
                return Err(Error::Unavailable);
            }
        }
        Ok(())
    }
}

/// Fixed operator entry: no caller-selected account/config/utility paths or
/// namespace/sealing success flags. All production gates remain false.
pub fn run_operator_service(stop: &AtomicBool) -> Result<(), Error> {
    if !crate::account_password_native::NATIVE_QUALIFIED
        || !crate::openbsd::password_native_authority()
    {
        return Err(Error::Unavailable);
    }
    let startup_deadline = Instant::now() + Duration::from_secs(5);
    crate::openbsd::disable_core_dumps().map_err(unavailable)?;
    std::env::set_current_dir("/").map_err(unavailable)?;
    let files = OperatorFiles::read(startup_deadline)?;
    let admission = AdmissionService::from_password_operator_files()?;
    if admission.password_accounts() != files.accounts {
        return Err(Error::Unavailable);
    }
    let metadata = Arc::new(MetadataExecutor);
    let startup = Startup::native(metadata.as_ref(), files.master_pid, startup_deadline)
        .map_err(unavailable)?;
    let startup = Arc::new(startup);
    let store = Arc::new(Store::open(Path::new(EPOCH), 0).map_err(unavailable)?);
    let fence = Arc::new(
        Fence::new(store.clone(), files.accounts.clone(), MonotonicClock).map_err(unavailable)?,
    );
    let registry = Arc::new(Registry::new());
    if Instant::now() >= startup_deadline {
        return Err(Error::Expired);
    }
    serve(
        stop,
        &files,
        &admission,
        store,
        fence,
        registry,
        startup,
        metadata,
        startup_deadline,
    )
}

#[allow(clippy::too_many_arguments)] // Explicit independent authority/lifetime inputs.
fn serve(
    stop: &AtomicBool,
    files: &OperatorFiles,
    admission: &AdmissionService,
    store: Arc<Store>,
    fence: Arc<Fence<MonotonicClock>>,
    registry: Arc<Registry>,
    startup: Arc<Startup>,
    metadata: Arc<MetadataExecutor>,
    startup_deadline: Instant,
) -> Result<(), Error> {
    let mut admission_socket = AdmissionEndpoint::bind(Path::new(ADMISSION))?;
    let mut mutation_socket = AdmissionEndpoint::bind(Path::new(MUTATION))?;
    let mut publication_socket = AdmissionEndpoint::bind(Path::new(PUBLICATION))?;
    if fs::symlink_metadata(Path::new(PUBLICATION).parent().ok_or(Error::Unavailable)?)
        .map_err(unavailable)?
        .gid()
        != files.connector_gid
    {
        return Err(Error::Unavailable);
    }
    let policy =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10058)).map_err(unavailable)?;
    policy.set_nonblocking(true).map_err(unavailable)?;
    if Instant::now() >= startup_deadline {
        return Err(Error::Expired);
    }
    let registration_refresh = Arc::new(
        crate::account_password_topology::RegistrationRefresh::capture(startup_deadline)
            .map_err(unavailable)?,
    );
    let mut parent_plan =
        crate::account_password_confinement::ParentPlan::prepare(startup_deadline)
            .map_err(unavailable)?;
    let seal = crate::openbsd::seal_password_parent(&parent_plan).map_err(unavailable)?;
    parent_plan.activate(seal).map_err(unavailable)?;
    if Instant::now() >= startup_deadline {
        return Err(Error::Expired);
    }
    let outcome = std::thread::scope(|scope| {
        let mut active: Vec<std::thread::ScopedJoinHandle<'_, ()>> = Vec::new();
        let mut observing: Option<
            std::thread::ScopedJoinHandle<'_, Result<SubmissionNamespace, Error>>,
        > = None;
        let mut attempted_record: Option<(Identity, u64)> = None;
        let mut runtime: Option<Arc<Runtime>> = None;
        while !stop.load(Ordering::SeqCst) {
            if crate::account_password_process::execution_quarantined() {
                return Err(Error::CleanupUnconfirmed);
            }
            let custody_deadline = Instant::now() + Duration::from_millis(500);
            parent_plan.recheck(custody_deadline).map_err(unavailable)?;
            files.recheck(custody_deadline)?;
            admission_socket.recheck()?;
            mutation_socket.recheck()?;
            publication_socket.recheck()?;
            let mut pending = Vec::new();
            for thread in active.drain(..) {
                if thread.is_finished() {
                    thread.join().map_err(unavailable)?;
                } else {
                    pending.push(thread);
                }
            }
            active = pending;
            if observing
                .as_ref()
                .is_some_and(|thread| thread.is_finished())
            {
                let namespace = observing
                    .take()
                    .ok_or(Error::Unavailable)?
                    .join()
                    .map_err(unavailable)?;
                if let Ok(namespace) = namespace {
                    // Only an actual live namespace observation creates this
                    // capability. The cold policy's SAME Store/Fence/registry
                    // survive activation, including captured epoch tickets.
                    runtime = Some(Arc::new(
                        Runtime::from_authorities(
                            store.clone(),
                            files.accounts.clone(),
                            fence.clone(),
                            namespace,
                            Keys::new(&files.mutation, &files.session).map_err(unavailable)?,
                            admission.password_key(),
                            files.relay_uid,
                            registry.clone(),
                        )
                        .map_err(unavailable)?,
                    ));
                }
            }
            if runtime.is_none() && observing.is_none() && active.len() < 4 {
                // Absence/invalid data never becomes a readiness Boolean. A
                // changed root record or actual successful after-callback only
                // triggers one bounded observation. Neither grants readiness.
                // Unchanged failures do not spin/retry.
                // A busy policy lock only postpones scheduling; it must not
                // stop the service or manufacture a new observed event.
                let after_observations = fence
                    .after_observations()
                    .unwrap_or_else(|_| attempted_record.as_ref().map_or(0, |value| value.1));
                match fs::symlink_metadata(crate::account_password_topology::REGISTRATION) {
                    Ok(info)
                        if info.is_file()
                            && info.len() > 0
                            && attempted_record != Some((identity(&info), after_observations)) =>
                    {
                        attempted_record = Some((identity(&info), after_observations));
                        let registration_refresh = registration_refresh.clone();
                        let metadata = metadata.clone();
                        let startup = startup.clone();
                        let observation_deadline = Instant::now() + Duration::from_secs(5);
                        observing = Some(scope.spawn(move || {
                            fixed_submission_namespace(
                                metadata,
                                startup,
                                files,
                                registration_refresh.as_ref(),
                                observation_deadline,
                            )
                        }));
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(Error::Unavailable),
                }
            }
            let capacity = 4 - usize::from(observing.is_some());
            if active.len() < capacity {
                for (role, endpoint) in [
                    (0, &admission_socket),
                    (1, &mutation_socket),
                    (2, &publication_socket),
                ] {
                    if active.len() >= capacity {
                        break;
                    }
                    // Authentication/admission and SQL mutation stay disabled
                    // throughout cold policy bootstrap: zero frame intake.
                    if role != 2 && runtime.is_none() {
                        continue;
                    }
                    match endpoint.accept() {
                        Ok((stream, _)) => {
                            let accepted = Instant::now();
                            if stop.load(Ordering::SeqCst) {
                                drop(stream);
                                return Ok(());
                            }
                            if crate::account_password_process::execution_quarantined() {
                                drop(stream);
                                return Err(Error::CleanupUnconfirmed);
                            }
                            endpoint.recheck()?;
                            let runtime = runtime.clone();
                            let fence = fence.clone();
                            let registry = registry.clone();
                            let metadata = metadata.clone();
                            let startup = startup.clone();
                            active.push(scope.spawn(move || {
                                let _ = match role {
                                    0 | 1 => match runtime {
                                        Some(runtime) => operation(
                                            stream,
                                            runtime.as_ref(),
                                            admission,
                                            accepted,
                                            role == 0,
                                            files.relay_uid,
                                        ),
                                        None => Err(Error::Unavailable),
                                    },
                                    _ => {
                                        let inspector = NativeInspector::from_startup(
                                            metadata.as_ref(),
                                            startup.as_ref(),
                                            files.accounts.clone(),
                                        )
                                        .map_err(unavailable);
                                        inspector.and_then(|inspector| {
                                            Endpoint::new(fence.as_ref(), files.policy)
                                                .map_err(unavailable)?
                                                .final_connection(
                                                    stream,
                                                    &inspector,
                                                    registry.as_ref(),
                                                    accepted + Duration::from_millis(500),
                                                )
                                                .map_err(unavailable)
                                        })
                                    }
                                };
                            }));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => return Err(Error::Unavailable),
                    }
                }
                if active.len() < capacity {
                    match policy.accept() {
                        Ok((stream, address)) => {
                            let accepted = Instant::now();
                            if stop.load(Ordering::SeqCst) {
                                drop(stream);
                                return Ok(());
                            }
                            if crate::account_password_process::execution_quarantined() {
                                drop(stream);
                                return Err(Error::CleanupUnconfirmed);
                            }
                            if address.ip() != Ipv4Addr::LOCALHOST {
                                return Err(Error::Authentication);
                            }
                            let fence = fence.clone();
                            active.push(scope.spawn(move || {
                                let _ = Endpoint::new(fence.as_ref(), files.policy).and_then(
                                    |endpoint| {
                                        endpoint.policy_connection(
                                            stream,
                                            accepted + Duration::from_millis(500),
                                        )
                                    },
                                );
                            }));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => return Err(Error::Unavailable),
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Scoped joins retain the already-dispatched original deadlines on
        // stop; no observation/credential operation is restarted or extended.
        Ok(())
    });
    let cleanup = admission_socket
        .remove()
        .and(mutation_socket.remove())
        .and(publication_socket.remove());
    outcome.and(cleanup)
}

fn operation(
    mut stream: UnixStream,
    runtime: &Runtime,
    admission: &AdmissionService,
    accepted: Instant,
    is_admission: bool,
    relay_uid: u32,
) -> Result<(), Error> {
    if crate::account_password_process::execution_quarantined() {
        return Err(Error::CleanupUnconfirmed);
    }
    let deadline = accepted + Duration::from_secs(if is_admission { 30 } else { 60 });
    let expected = if is_admission {
        admission.password_peer_uid()
    } else {
        relay_uid
    };
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)? != expected {
        return Err(Error::Authentication);
    }
    let sql = NativeProfile::fixed(Role::Sql, deadline).map_err(unavailable)?;
    let hash = NativeProfile::fixed(Role::Hash, deadline).map_err(unavailable)?;
    let primary = NativeProfile::fixed(Role::Primary, deadline).map_err(unavailable)?;
    let control = NativeProfile::fixed(Role::Control, deadline).map_err(unavailable)?;
    let executor = FixedExecutor::from_profiles(deadline, &sql, &hash, &primary, &control);
    if is_admission {
        admission.password_connection(&mut stream, deadline, |request, inherited| {
            runtime.admission(request, &executor, deadline.min(inherited))
        })
    } else {
        let backend = Backend::new(FixedExecutor::from_profiles(
            deadline, &sql, &hash, &primary, &control,
        ));
        runtime
            .mutation(stream, &backend, &executor, &executor, deadline)
            .map_err(unavailable)
    }
}

fn fixed_submission_namespace(
    metadata: Arc<dyn CommandExecutor + Send + Sync>,
    startup: Arc<Startup>,
    files: &OperatorFiles,
    refresh: &crate::account_password_topology::RegistrationRefresh,
    deadline: Instant,
) -> Result<SubmissionNamespace, Error> {
    let profile = NativeProfile::fixed(Role::Control, deadline).map_err(unavailable)?;
    let control_gid = profile.selected_control_gid().map_err(unavailable)?;
    refresh
        .refresh_stale(metadata.as_ref(), startup.as_ref(), control_gid, deadline)
        .map_err(unavailable)?;
    let registration = crate::account_password_topology::RegisteredSubmission::observe_current(
        metadata.as_ref(),
        startup.as_ref(),
        control_gid,
        deadline,
    )
    .map_err(unavailable)?;
    let topology = crate::account_password_topology::Topology::fixed(
        metadata,
        startup,
        registration,
        control_gid,
        files.accounts.clone(),
        deadline,
    )
    .map_err(unavailable)?;
    Ok(SubmissionNamespace::from_topology(topology))
}
