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
use crate::account_password_process::MetadataExecutor;
use crate::account_password_process::{FixedExecutor, PrimaryExecutor};
use crate::account_password_runtime::Runtime;
use crate::account_password_state::Store;
use crate::openpgp_inventory_runtime::{file, private_dir, secret};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
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
/// namespace/sealing success flags. Native authority is observed, not toggled.
pub fn run_operator_service(stop: &AtomicBool) -> Result<(), Error> {
    let mut trace = crate::account_password_fstat::StartupTrace::new(
        crate::account_password_fstat::StartupOperation::ServiceNative,
    );
    let result = run_operator_service_with_trace(stop, &mut trace);
    if let Err(error) = &result {
        trace.emit(error);
    }
    result
}
fn run_operator_service_with_trace(
    stop: &AtomicBool,
    trace: &mut crate::account_password_fstat::StartupTrace,
) -> Result<(), Error> {
    use crate::account_password_fstat::{StartupCategory as Cat, StartupOperation as Op};
    if !crate::openbsd::password_native_authority() {
        return Err(Error::Unavailable);
    }
    let startup_deadline = Instant::now() + Duration::from_secs(5);
    trace.set(Op::ServiceDumps);
    crate::openbsd::disable_core_dumps().map_err(|e| {
        trace.io(&e);
        unavailable(e)
    })?;
    trace.set(Op::ServiceCwd);
    std::env::set_current_dir("/").map_err(|e| {
        trace.io(&e);
        unavailable(e)
    })?;
    trace.set(Op::ServiceFiles);
    let files = OperatorFiles::read(startup_deadline)?;
    trace.set(Op::ServiceAdmission);
    let admission = AdmissionService::from_password_operator_files()?;
    trace.set(Op::ServiceAccounts);
    if admission.password_accounts() != files.accounts {
        trace.category(Cat::Invalid);
        return Err(Error::Unavailable);
    }
    let metadata = Arc::new(MetadataExecutor::readonly());
    trace.set(Op::ServiceStartup);
    let startup = Startup::native(metadata.as_ref(), files.master_pid, startup_deadline)
        .map_err(unavailable)?;
    let startup = Arc::new(startup);
    let observer = Arc::new(
        crate::account_password_fstat::Observer::start(
            startup.as_ref(),
            metadata.as_ref(),
            startup_deadline,
            trace,
        )
        .map_err(unavailable)?,
    );
    let metadata = Arc::new(MetadataExecutor::with_fstat(observer.clone()));
    let outcome = (|| {
        trace.set(Op::ServiceStore);
        let store = Arc::new(Store::open(Path::new(EPOCH), 0).map_err(unavailable)?);
        trace.set(Op::ServiceFence);
        let fence = Arc::new(
            Fence::new(store.clone(), files.accounts.clone(), MonotonicClock)
                .map_err(unavailable)?,
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
            trace,
        )
    })();
    // Native child custody is part of service exit, including failed setup.
    let cleanup = observer
        .shutdown(Instant::now() + Duration::from_millis(500))
        .map_err(unavailable);
    if cleanup.is_err() {
        trace.cleanup_failed();
    }
    if outcome.is_ok() {
        if let Err(error) = &cleanup {
            let _ = writeln!(
                std::io::stderr().lock(),
                "account_password_service stage=service_observer_cleanup error={error:?}"
            );
        }
    }
    outcome.and(cleanup)
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
    trace: &mut crate::account_password_fstat::StartupTrace,
) -> Result<(), Error> {
    use crate::account_password_fstat::{StartupCategory as Cat, StartupOperation as Op};
    trace.set(Op::AdmissionBind);
    let mut admission_socket = AdmissionEndpoint::bind(Path::new(ADMISSION))?;
    trace.set(Op::MutationBind);
    let mut mutation_socket = AdmissionEndpoint::bind(Path::new(MUTATION))?;
    trace.set(Op::PublicationBind);
    let mut publication_socket = AdmissionEndpoint::bind(Path::new(PUBLICATION))?;
    trace.set(Op::PublicationGroup);
    if fs::symlink_metadata(Path::new(PUBLICATION).parent().ok_or(Error::Unavailable)?)
        .map_err(unavailable)?
        .gid()
        != files.connector_gid
    {
        trace.category(Cat::Invalid);
        return Err(Error::Unavailable);
    }
    trace.set(Op::PolicyBind);
    let policy = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10058)).map_err(|e| {
        trace.io(&e);
        unavailable(e)
    })?;
    trace.set(Op::PolicyNonblocking);
    policy.set_nonblocking(true).map_err(|e| {
        trace.io(&e);
        unavailable(e)
    })?;
    trace.set(Op::SetupDeadline);
    if Instant::now() >= startup_deadline {
        trace.category(Cat::Deadline);
        return Err(Error::Expired);
    }
    trace.set(Op::RegistrationRefresh);
    let registration_refresh = Arc::new(
        crate::account_password_topology::RegistrationRefresh::capture(startup_deadline)
            .map_err(unavailable)?,
    );
    let mut primary_stage = "primary_startup";
    let primary = crate::account_password_peer::PrimaryPeer::observe(
        metadata.clone(),
        startup.as_ref(),
        startup_deadline,
        &mut primary_stage,
    );
    match &primary {
        Ok(_) => eprintln!("account_password_service stage=primary_ready result=ok"),
        Err(error) => eprintln!("account_password_service stage={primary_stage} error={error:?}"),
    }
    let primary = primary.ok().map(Arc::new);
    trace.set(Op::ParentPrepare);
    let mut parent_plan =
        crate::account_password_confinement::ParentPlan::prepare(startup_deadline)
            .map_err(unavailable)?;
    trace.set(Op::ParentSeal);
    let seal = crate::openbsd::seal_password_parent(&parent_plan).map_err(|e| {
        trace.io(&e);
        unavailable(e)
    })?;
    trace.set(Op::ParentActivate);
    parent_plan.activate(seal).map_err(unavailable)?;
    trace.set(Op::SetupDeadline);
    if Instant::now() >= startup_deadline {
        trace.category(Cat::Deadline);
        return Err(Error::Expired);
    }
    trace.finish();
    let admission_failure_reported = AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        let mut active: Vec<std::thread::ScopedJoinHandle<'_, ()>> = Vec::new();
        let mut observing: Option<
            std::thread::ScopedJoinHandle<'_, Result<ReadyRuntimeAuthority, Error>>,
        > = None;
        let mut attempted_record: Option<(Identity, u64)> = None;
        let mut runtime: Option<Arc<ReadyRuntime>> = None;
        while !stop.load(Ordering::SeqCst) {
            if crate::account_password_process::execution_quarantined() {
                return Err(Error::CleanupUnconfirmed);
            }
            let custody_deadline = Instant::now() + Duration::from_millis(500);
            let metadata_check = metadata.recheck_fstat(custody_deadline);
            let metadata_reason = metadata_check
                .as_ref()
                .err()
                .map(|error| error.reason.as_str());
            if loop_custody(
                metadata_check.as_ref().copied().map_err(unavailable),
                Op::BeforeRecheck,
                stop,
                metadata_reason,
            )? == crate::account_password_fstat::Recheck::Busy
            {
                // No accept, observation scheduling or credential action is
                // reachable while the existing metadata operation owns custody.
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            loop_custody(
                parent_plan.recheck(custody_deadline).map_err(unavailable),
                Op::ParentActivate,
                stop,
                None,
            )?;
            loop_custody(
                files.recheck(custody_deadline),
                Op::ServiceFiles,
                stop,
                None,
            )?;
            loop_custody(admission_socket.recheck(), Op::AdmissionBind, stop, None)?;
            loop_custody(mutation_socket.recheck(), Op::MutationBind, stop, None)?;
            loop_custody(
                publication_socket.recheck(),
                Op::PublicationBind,
                stop,
                None,
            )?;
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
                if let Ok(authority) = namespace {
                    // Only an actual live namespace observation creates this
                    // capability. The cold policy's SAME Store/Fence/registry
                    // survive activation, including captured epoch tickets.
                    runtime = Some(Arc::new(ReadyRuntime {
                        runtime: Runtime::from_authorities(
                            store.clone(),
                            files.accounts.clone(),
                            fence.clone(),
                            authority.namespace,
                            Keys::new(&files.mutation, &files.session).map_err(unavailable)?,
                            admission.password_key(),
                            files.relay_uid,
                            registry.clone(),
                        )
                        .map_err(unavailable)?,
                        control: authority.control,
                        metadata: authority.metadata,
                    }));
                }
            }
            if runtime.is_none() && primary.is_some() && observing.is_none() && active.len() < 4 {
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
                        let primary = primary.as_ref().ok_or(Error::Unavailable)?.clone();
                        let metadata = metadata.clone();
                        let startup = startup.clone();
                        let observation_deadline = Instant::now() + Duration::from_secs(5);
                        observing = Some(scope.spawn(move || {
                            fixed_submission_namespace(
                                metadata,
                                startup,
                                files,
                                registration_refresh.as_ref(),
                                primary,
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
                    // Admission requires measured private primary; mutation
                    // additionally requires measured Control plus namespace.
                    if (role == 0 && primary.is_none()) || (role == 1 && runtime.is_none()) {
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
                            let metadata = runtime
                                .as_ref()
                                .map_or_else(|| metadata.clone(), |ready| ready.metadata.clone());
                            let startup = startup.clone();
                            let primary = primary.clone();
                            let store = store.clone();
                            let admission_failure_reported = &admission_failure_reported;
                            active.push(scope.spawn(move || {
                                let _ = match role {
                                    0 => {
                                        let mut stage = "admission_primary";
                                        let result = primary.ok_or(Error::Unavailable).and_then(|primary| {
                                        admission_operation(
                                            stream,
                                            admission,
                                            accepted,
                                            store.as_ref(),
                                            files.accounts.clone(),
                                            primary,
                                            runtime.as_ref().map(|ready| &ready.runtime),
                                            &mut stage,
                                        )
                                        });
                                        if let Err(error) = result {
                                            if first_admission_failure(admission_failure_reported) {
                                                eprintln!("account_password_service stage={stage} error={error:?}");
                                            }
                                        }
                                        result
                                    },
                                    1 => match (runtime, primary) {
                                        (Some(ready), Some(primary)) => operation(
                                            stream,
                                            ready.as_ref(),
                                            accepted,
                                            files.relay_uid,
                                            startup,
                                            metadata,
                                            primary,
                                        ),
                                        _ => Err(Error::Unavailable),
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
    if let Err(error) = &outcome {
        let _ = writeln!(
            std::io::stderr().lock(),
            "account_password_service stage=service_loop error={error:?}"
        );
    } else if let Err(error) = &cleanup {
        let _ = writeln!(
            std::io::stderr().lock(),
            "account_password_service stage=service_endpoint_cleanup error={error:?}"
        );
    }
    outcome.and(cleanup)
}

struct ReadyRuntimeAuthority {
    namespace: SubmissionNamespace,
    control: Arc<crate::account_password_peer::ControlPeer>,
    metadata: Arc<MetadataExecutor>,
}
struct ReadyRuntime {
    runtime: Runtime,
    control: Arc<crate::account_password_peer::ControlPeer>,
    metadata: Arc<MetadataExecutor>,
}
#[allow(clippy::too_many_arguments)] // Independent existing authority plus closed diagnostic stage.
fn admission_operation(
    mut stream: UnixStream,
    admission: &AdmissionService,
    accepted: Instant,
    store: &Store,
    accounts: BTreeSet<String>,
    peer: Arc<crate::account_password_peer::PrimaryPeer>,
    ready: Option<&Runtime>,
    stage: &mut &'static str,
) -> Result<(), Error> {
    if crate::account_password_process::execution_quarantined() {
        return Err(Error::CleanupUnconfirmed);
    }
    let deadline = accepted + Duration::from_secs(30);
    *stage = "admission_peer";
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)?
        != admission.password_peer_uid()
    {
        return Err(Error::Authentication);
    }
    *stage = "admission_profile";
    let profile =
        NativeProfile::from_primary_with_stage(peer, deadline, stage).map_err(unavailable)?;
    let executor = PrimaryExecutor::new(&profile, deadline);
    *stage = "admission_password_connection";
    admission.password_connection(&mut stream, deadline, |request, inherited| {
        if let Some(runtime) = ready {
            return runtime.admission(request, &executor, deadline.min(inherited));
        }
        crate::account_password_admission::execute_current(
            store,
            &executor,
            &crate::totp::SystemTimeProvider,
            admission.password_key(),
            accounts.clone(),
            request,
            deadline.min(inherited),
        )
    })
}
#[allow(clippy::too_many_arguments)] // Independent native authority and original request budget.
fn operation(
    stream: UnixStream,
    ready: &ReadyRuntime,
    accepted: Instant,
    relay_uid: u32,
    startup: Arc<Startup>,
    metadata: Arc<MetadataExecutor>,
    primary_peer: Arc<crate::account_password_peer::PrimaryPeer>,
) -> Result<(), Error> {
    if crate::account_password_process::execution_quarantined() {
        return Err(Error::CleanupUnconfirmed);
    }
    let deadline = accepted + Duration::from_secs(60);
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)? != relay_uid {
        return Err(Error::Authentication);
    }
    let sql = NativeProfile::from_startup(Role::Sql, startup.clone(), metadata.clone(), deadline)
        .map_err(unavailable)?;
    let hash = NativeProfile::from_startup(Role::Hash, startup, metadata, deadline)
        .map_err(unavailable)?;
    let primary = NativeProfile::from_primary(primary_peer, deadline).map_err(unavailable)?;
    let control =
        NativeProfile::from_control(ready.control.clone(), deadline).map_err(unavailable)?;
    let executor = FixedExecutor::from_profiles(deadline, &sql, &hash, &primary, &control);
    let backend = Backend::new(FixedExecutor::from_profiles(
        deadline, &sql, &hash, &primary, &control,
    ));
    ready
        .runtime
        .mutation(stream, &backend, &executor, &executor, deadline)
        .map_err(unavailable)
}

fn fixed_submission_namespace(
    _metadata: Arc<MetadataExecutor>,
    startup: Arc<Startup>,
    files: &OperatorFiles,
    refresh: &crate::account_password_topology::RegistrationRefresh,
    primary: Arc<crate::account_password_peer::PrimaryPeer>,
    deadline: Instant,
) -> Result<ReadyRuntimeAuthority, Error> {
    let control = Arc::new(
        crate::account_password_peer::ControlPeer::observe(primary, deadline)
            .map_err(unavailable)?,
    );
    let metadata = Arc::new(_metadata.with_control(control.clone()));
    let profile = NativeProfile::from_control(control.clone(), deadline).map_err(unavailable)?;
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
        metadata.clone(),
        startup,
        registration,
        control_gid,
        files.accounts.clone(),
        deadline,
    )
    .map_err(unavailable)?;
    Ok(ReadyRuntimeAuthority {
        namespace: SubmissionNamespace::from_topology(topology),
        control,
        metadata,
    })
}

// Only the first failing loop guard reaches this error-only diagnostic: the
// unchanged Err immediately leaves the loop. The stop snapshot distinguishes
// a guard failure observed during requested shutdown from a pre-stop failure.
// The existing closed trace vocabulary carries no native payload or identity.
fn loop_custody<T>(
    result: Result<T, Error>,
    operation: crate::account_password_fstat::StartupOperation,
    stop: &AtomicBool,
    metadata_reason: Option<&str>,
) -> Result<T, Error> {
    if let Err(error) = &result {
        use crate::account_password_fstat::{StartupCategory as Cat, StartupOperation as Op};
        let mut trace = crate::account_password_fstat::StartupTrace::new(operation);
        if operation == Op::BeforeRecheck {
            match metadata_reason {
                Some(
                    "metadata_child_deadline"
                    | "metadata_fstat_rpc_deadline"
                    | "metadata_child_budget",
                ) => trace.category(Cat::Deadline),
                Some("metadata_fstat_worker_exit" | "metadata_query_exit") => {
                    trace.category(Cat::Exit)
                }
                Some("metadata_child_cleanup") => trace.cleanup_failed(),
                _ => {}
            }
        }
        let requested = stop.load(Ordering::SeqCst);
        eprintln!("account_password_service stage=service_loop_guard stop_requested={requested}");
        trace.emit(error);
    }
    result
}

fn first_admission_failure(reported: &AtomicBool) -> bool {
    !reported.swap(true, Ordering::SeqCst)
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn first_failure_is_bounded_across_concurrent_connections() {
        let reported = AtomicBool::new(false);
        let winners = std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|_| scope.spawn(|| first_admission_failure(&reported)))
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|first| *first)
                .count()
        });
        assert_eq!(winners, 1);
        assert!(!first_admission_failure(&reported));
    }
}
