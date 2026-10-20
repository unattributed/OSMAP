//! Fixed Rust account service. Listener lifetime/custody and admission replay
//! reuse the existing account transport; no Python application is dispatched.
//! Existing authoritative authentication/cache sockets and the owning Rust
//! parent seal precede all accepted connection handling. Public mail services
//! and configurations are never activated or changed by this service.
use crate::account_admission::Error;
use crate::account_admission_runtime::{AdmissionEndpoint, Service as AdmissionService};
use crate::account_password_backend::Backend;
use crate::account_password_connection::Keys;
use crate::account_password_native::{NativeProfile, Role};
use crate::account_password_peer::StockPeer;
use crate::account_password_process::MetadataExecutor;
use crate::account_password_process::{FixedExecutor, PrimaryExecutor};
use crate::account_password_runtime::StockRuntime;
use crate::account_password_state::Store;
use crate::openpgp_inventory_runtime::{file, private_dir, secret};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
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
const FILES: [&str; 3] = ["config.json", "mutation.key", "session-proof.key"];
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
struct OperatorFiles {
    accounts: BTreeSet<String>,
    relay_uid: u32,
    master_pid: u32,
    mutation: Vec<u8>,
    session: Vec<u8>,
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
        let mutation = secret(&root.join("mutation.key")).map_err(unavailable)?;
        let session = secret(&root.join("session-proof.key")).map_err(unavailable)?;
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
            || mutation == session
        {
            return Err(Error::Unavailable);
        }
        let value = Self {
            accounts,
            relay_uid: mutation_config.trusted_relay_uid,
            master_pid: crate::account_password_peer::stock_master_pid(deadline)
                .map_err(unavailable)?,
            mutation,
            session,
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
    let metadata = Arc::new(MetadataExecutor::readonly());
    trace.set(Op::ServiceStartup);
    let stock =
        Arc::new(StockPeer::observe(metadata, startup_deadline, trace).map_err(unavailable)?);
    trace.set(Op::ServiceFiles);
    let files = OperatorFiles::read(startup_deadline)?;
    trace.set(Op::ServiceAdmission);
    let admission = AdmissionService::from_password_operator_files()?;
    trace.set(Op::ServiceAccounts);
    if admission.password_accounts() != files.accounts
        || admission.password_key() == files.mutation
        || admission.password_key() == files.session
    {
        trace.category(Cat::Invalid);
        return Err(Error::Unavailable);
    }
    if files.master_pid != stock.master_pid() {
        return Err(Error::Unavailable);
    }
    trace.set(Op::ServiceStore);
    let store = Arc::new(Store::open(Path::new(EPOCH), 0).map_err(unavailable)?);
    if Instant::now() >= startup_deadline {
        return Err(Error::Expired);
    }
    serve(
        stop,
        &files,
        &admission,
        store,
        stock,
        startup_deadline,
        trace,
    )
}

#[allow(clippy::too_many_arguments)] // Fixed independent custody and original startup budget.
fn serve(
    stop: &AtomicBool,
    files: &OperatorFiles,
    admission: &AdmissionService,
    store: Arc<Store>,
    stock: Arc<StockPeer>,
    startup_deadline: Instant,
    trace: &mut crate::account_password_fstat::StartupTrace,
) -> Result<(), Error> {
    use crate::account_password_fstat::StartupOperation as Op;
    trace.set(Op::AdmissionBind);
    let mut admission_socket = AdmissionEndpoint::bind(Path::new(ADMISSION))?;
    trace.set(Op::MutationBind);
    let mut mutation_socket = AdmissionEndpoint::bind(Path::new(MUTATION))?;
    // All actual stock mail authority is established before accepting requests.
    // There is no policy listener, publication endpoint, Generation or activation.
    let runtime = Arc::new(
        StockRuntime::new(
            store,
            files.accounts.clone(),
            Keys::new(&files.mutation, &files.session).map_err(unavailable)?,
            admission.password_key(),
            files.relay_uid,
            stock.clone(),
            startup_deadline,
        )
        .map_err(unavailable)?,
    );
    trace.set(Op::ParentPrepare);
    let mut parent_plan =
        crate::account_password_confinement::ParentPlan::prepare_stock(startup_deadline)
            .map_err(unavailable)?;
    trace.set(Op::ParentSeal);
    let seal = crate::openbsd::seal_password_parent(&parent_plan).map_err(unavailable)?;
    parent_plan.activate(seal).map_err(unavailable)?;
    if Instant::now() >= startup_deadline {
        return Err(Error::Expired);
    }
    trace.finish();
    let admission_failure_reported = AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        let mut active: Vec<std::thread::ScopedJoinHandle<'_, ()>> = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            if crate::account_password_process::execution_quarantined() {
                return Err(Error::CleanupUnconfirmed);
            }
            let custody_deadline = Instant::now() + Duration::from_millis(500);
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
            let mut pending = Vec::new();
            for thread in active.drain(..) {
                if thread.is_finished() {
                    thread.join().map_err(unavailable)?;
                } else {
                    pending.push(thread);
                }
            }
            active = pending;
            for (mutation, endpoint) in [(false, &admission_socket), (true, &mutation_socket)] {
                if active.len() >= 4 {
                    break;
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
                        let stock = stock.clone();
                        let reported = &admission_failure_reported;
                        active.push(scope.spawn(move || {
                            let result = if mutation {
                                stock_operation(stream, runtime.as_ref(), accepted, files.relay_uid, stock)
                            } else { stock_admission(stream, admission, runtime.as_ref(), stock, accepted) };
                            if let Err(error) = result {
                                if first_admission_failure(reported) { eprintln!("account_password_service stage=stock_operation error={error:?}"); }
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Error::Unavailable),
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });
    let cleanup = admission_socket.remove().and(mutation_socket.remove());
    outcome.and(cleanup)
}
fn stock_admission(
    mut stream: UnixStream,
    admission: &AdmissionService,
    runtime: &StockRuntime,
    stock: Arc<StockPeer>,
    accepted: Instant,
) -> Result<(), Error> {
    let deadline = accepted + Duration::from_secs(30);
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)?
        != admission.password_peer_uid()
    {
        return Err(Error::Authentication);
    }
    admission.password_connection(&mut stream, deadline, |request, inherited| {
        let deadline = deadline.min(inherited);
        match request.operation() {
            crate::account_admission::Operation::Admit { .. } => {
                // Epoch/status admission performs no primary command. Keep the
                // runtime's peer/account/Store checks without an unused auth graph.
                runtime.admission(request, &MetadataExecutor::readonly(), deadline)
            }
            crate::account_admission::Operation::Authenticate { .. } => {
                let profile =
                    NativeProfile::from_stock(Role::StockPrimary, stock.clone(), deadline)
                        .map_err(unavailable)?;
                let executor = PrimaryExecutor::new(&profile, deadline);
                runtime.admission(request, &executor, deadline)
            }
        }
    })
}
#[allow(clippy::too_many_arguments)] // Independent source-owned native authorities.
fn stock_operation(
    stream: UnixStream,
    runtime: &StockRuntime,
    accepted: Instant,
    relay_uid: u32,
    stock: Arc<StockPeer>,
) -> Result<(), Error> {
    let deadline = accepted + Duration::from_secs(60);
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)? != relay_uid {
        return Err(Error::Authentication);
    }
    let sql = NativeProfile::from_stock_backend(Role::Sql, stock.clone(), deadline)
        .map_err(unavailable)?;
    let hash = NativeProfile::from_stock_backend(Role::Hash, stock.clone(), deadline)
        .map_err(unavailable)?;
    let primary = NativeProfile::from_stock(Role::StockPrimary, stock.clone(), deadline)
        .map_err(unavailable)?;
    let executor = FixedExecutor::from_profiles(deadline, &sql, &hash, &primary, &primary);
    let backend = Backend::new(FixedExecutor::from_profiles(
        deadline, &sql, &hash, &primary, &primary,
    ));
    runtime
        .mutation(stream, &backend, &executor, deadline)
        .map_err(unavailable)
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
