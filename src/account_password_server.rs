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
use std::fmt::Debug;
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
const ADMISSION: &str = crate::config::LOCAL_ACCOUNT_ADMISSION_SOCKET;
const MUTATION: &str = crate::config::LOCAL_ACCOUNT_MUTATION_SOCKET;
const FILES: [&str; 3] = ["config.json", "mutation.key", "session-proof.key"];
const MAX_ACTIVE_WORKERS: usize = 4;
type Identity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

// This ignored native fixture can only remove dispatch authority in its own
// process. Production has no flag or argument that changes these decisions.
#[cfg(test)]
static READONLY_ADMISSION_FIXTURE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static AUTHENTICATION_READONLY_FIXTURE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(crate) const FRESHNESS_FIXTURE_ACCOUNT: &str =
    "s04-02-freshness-20261024-01@osmap-password.invalid";
fn readonly_admission_fixture() -> bool {
    #[cfg(test)]
    {
        READONLY_ADMISSION_FIXTURE.load(Ordering::SeqCst)
    }
    #[cfg(not(test))]
    {
        false
    }
}
fn authentication_readonly_fixture() -> bool {
    #[cfg(test)]
    {
        readonly_admission_fixture() && AUTHENTICATION_READONLY_FIXTURE.load(Ordering::SeqCst)
    }
    #[cfg(not(test))]
    {
        false
    }
}
fn admission_operation_allowed(
    readonly: bool,
    authentication_readonly: bool,
    account: &str,
    operation: &crate::account_admission::Operation,
) -> bool {
    if !readonly {
        return true;
    }
    match operation {
        crate::account_admission::Operation::Admit { .. } => true,
        crate::account_admission::Operation::Authenticate { .. } => {
            #[cfg(test)]
            {
                authentication_readonly && account == FRESHNESS_FIXTURE_ACCOUNT
            }
            #[cfg(not(test))]
            {
                let _ = (authentication_readonly, account);
                false
            }
        }
    }
}
fn mutation_operation_allowed(readonly: bool) -> bool {
    !readonly
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointKind {
    Admission,
    Mutation,
}
impl EndpointKind {
    fn other(self) -> Self {
        match self {
            Self::Admission => Self::Mutation,
            Self::Mutation => Self::Admission,
        }
    }
    fn stage(self) -> &'static str {
        match self {
            Self::Admission => "stock_admission",
            Self::Mutation => "stock_mutation",
        }
    }
}
fn endpoint_order(preferred: EndpointKind) -> [EndpointKind; 2] {
    [preferred, preferred.other()]
}
fn worker_slot_available(active: usize) -> bool {
    active < MAX_ACTIVE_WORKERS
}
fn record_accepted_endpoint(preferred: &mut EndpointKind, accepted: EndpointKind) {
    *preferred = accepted.other();
}

enum StockOperationError {
    Service(Error),
    Connection(crate::account_password_connection::Error),
}
impl Debug for StockOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Service(error) => formatter.debug_tuple("Service").field(error).finish(),
            Self::Connection(error) => formatter.debug_tuple("Connection").field(error).finish(),
        }
    }
}

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
    run_operator_service_diagnostic(stop, false)
}
/// Explicit operator-only diagnostic invocation of the identical service path.
/// The extra fixed trace line is not accepted by legacy strict stderr consumers.
pub fn run_operator_service_with_metadata_diagnostics(stop: &AtomicBool) -> Result<(), Error> {
    run_operator_service_diagnostic(stop, true)
}
fn run_operator_service_diagnostic(stop: &AtomicBool, metadata: bool) -> Result<(), Error> {
    let mut trace = crate::account_password_fstat::StartupTrace::new(
        crate::account_password_fstat::StartupOperation::ServiceNative,
    );
    let result = run_operator_service_with_trace(stop, &mut trace);
    if let Err(error) = &result {
        if metadata {
            trace.emit_metadata(error);
        } else {
            trace.emit(error);
        }
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
    // Only the isolated native authentication test projects its one fresh
    // account. Original protected files, keys and account equality were checked
    // above; both runtime account sets retain every originally configured entry.
    #[cfg(test)]
    let (files, admission) = if authentication_readonly_fixture() {
        let mut files = files;
        let admission = admission.with_freshness_fixture_account()?;
        if files.accounts.len() >= 64
            || !files.accounts.insert(FRESHNESS_FIXTURE_ACCOUNT.into())
            || admission.password_accounts() != files.accounts
        {
            trace.category(Cat::Invalid);
            return Err(Error::Invalid);
        }
        (files, admission)
    } else {
        (files, admission)
    };
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
    let mut mutation_socket = match AdmissionEndpoint::bind(Path::new(MUTATION)) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let admission_cleanup = admission_socket.remove();
            return finish_service(Err(error), admission_cleanup, Ok(()));
        }
    };
    let outcome = (|| {
        // All actual stock mail authority is established before accepting requests.
        // There is no policy listener, publication endpoint, Generation or activation.
        trace.set(Op::ServiceStartup);
        let keys = Keys::new(&files.mutation, &files.session).map_err(|error| {
            trace.category(crate::account_password_fstat::StartupCategory::Invalid);
            unavailable(error)
        })?;
        let runtime = Arc::new(
            StockRuntime::new(
                store,
                files.accounts.clone(),
                keys,
                admission.password_key(),
                files.relay_uid,
                stock.clone(),
                startup_deadline,
                trace,
            )
            .map_err(unavailable)?,
        );
        trace.set(Op::ParentPrepare);
        let mut parent_plan =
            crate::account_password_confinement::ParentPlan::prepare_stock_with_trace(
                startup_deadline,
                trace,
            )
            .map_err(unavailable)?;
        trace.set(Op::ParentSeal);
        let seal = crate::openbsd::seal_password_parent(&parent_plan).map_err(unavailable)?;
        parent_plan.activate(seal).map_err(unavailable)?;
        if Instant::now() >= startup_deadline {
            return Err(Error::Expired);
        }
        trace.finish();
        let admission_failure_reported = AtomicBool::new(false);
        let mutation_failure_reported = AtomicBool::new(false);
        let mut preferred = EndpointKind::Admission;
        std::thread::scope(|scope| {
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
                for kind in endpoint_order(preferred) {
                    if !worker_slot_available(active.len()) {
                        break;
                    }
                    let endpoint = match kind {
                        EndpointKind::Admission => &admission_socket,
                        EndpointKind::Mutation => &mutation_socket,
                    };
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
                            record_accepted_endpoint(&mut preferred, kind);
                            let runtime = runtime.clone();
                            let stock = stock.clone();
                            let reported = match kind {
                                EndpointKind::Admission => &admission_failure_reported,
                                EndpointKind::Mutation => &mutation_failure_reported,
                            };
                            active.push(scope.spawn(move || match kind {
                                EndpointKind::Admission => {
                                    if let Err(error) = stock_admission(
                                        stream,
                                        admission,
                                        runtime.as_ref(),
                                        stock,
                                        accepted,
                                    ) {
                                        report_first_failure(kind, reported, error);
                                    }
                                }
                                EndpointKind::Mutation => {
                                    if let Err(error) = stock_operation(
                                        stream,
                                        runtime.as_ref(),
                                        accepted,
                                        files.relay_uid,
                                        stock,
                                    ) {
                                        report_first_failure(kind, reported, error);
                                    }
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
        })
    })();
    // Both removals are always attempted. Any uncertain endpoint disposition
    // takes precedence over an ordinary startup, loop or shutdown error.
    finish_service_with_cleanup(
        outcome,
        || admission_socket.remove(),
        || mutation_socket.remove(),
    )
}

fn finish_service_with_cleanup(
    outcome: Result<(), Error>,
    admission_cleanup: impl FnOnce() -> Result<(), Error>,
    mutation_cleanup: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    let admission_cleanup = admission_cleanup();
    let mutation_cleanup = mutation_cleanup();
    finish_service(outcome, admission_cleanup, mutation_cleanup)
}

fn finish_service(
    outcome: Result<(), Error>,
    admission_cleanup: Result<(), Error>,
    mutation_cleanup: Result<(), Error>,
) -> Result<(), Error> {
    if admission_cleanup.is_err() || mutation_cleanup.is_err() {
        Err(Error::CleanupUnconfirmed)
    } else {
        outcome
    }
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
        if !admission_operation_allowed(
            readonly_admission_fixture(),
            authentication_readonly_fixture(),
            request.account(),
            request.operation(),
        ) {
            return Err(Error::Refused);
        }
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
) -> Result<(), StockOperationError> {
    if !mutation_operation_allowed(readonly_admission_fixture()) {
        return Err(StockOperationError::Service(Error::Refused));
    }
    let deadline = accepted + Duration::from_secs(60);
    if crate::openbsd::unix_stream_peer_uid(&stream)
        .map_err(|error| StockOperationError::Service(unavailable(error)))?
        != relay_uid
    {
        return Err(StockOperationError::Service(Error::Authentication));
    }
    let sql = NativeProfile::from_stock_backend(Role::Sql, stock.clone(), deadline)
        .map_err(|error| StockOperationError::Service(unavailable(error)))?;
    let hash = NativeProfile::from_stock_backend(Role::Hash, stock.clone(), deadline)
        .map_err(|error| StockOperationError::Service(unavailable(error)))?;
    let primary = NativeProfile::from_stock(Role::StockPrimary, stock.clone(), deadline)
        .map_err(|error| StockOperationError::Service(unavailable(error)))?;
    let executor = FixedExecutor::from_profiles(deadline, &sql, &hash, &primary, &primary);
    let backend = Backend::new(FixedExecutor::from_profiles(
        deadline, &sql, &hash, &primary, &primary,
    ));
    runtime
        .mutation(stream, &backend, &executor, deadline)
        .map_err(StockOperationError::Connection)
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

fn report_first_failure(kind: EndpointKind, reported: &AtomicBool, error: impl Debug) {
    if first_endpoint_failure(reported) {
        eprintln!(
            "account_password_service stage={} error={error:?}",
            kind.stage()
        );
    }
}

fn first_endpoint_failure(reported: &AtomicBool) -> bool {
    !reported.swap(true, Ordering::SeqCst)
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn readonly_fixture_restricts_authenticate_and_mutation_dispatch() {
        use crate::account_admission::Operation;
        let admit = Operation::Admit { epoch: 0 };
        let authenticate = Operation::Authenticate {
            password: "fixed nonsecret test credential".into(),
        };
        let original = "alice@osmap-password.invalid";
        assert!(admission_operation_allowed(false, false, original, &admit));
        assert!(admission_operation_allowed(
            false,
            false,
            original,
            &authenticate
        ));
        assert!(mutation_operation_allowed(false));
        for authentication_readonly in [false, true] {
            assert!(!mutation_operation_allowed(true));
            assert!(admission_operation_allowed(
                true,
                authentication_readonly,
                original,
                &admit
            ));
            assert!(admission_operation_allowed(
                true,
                authentication_readonly,
                FRESHNESS_FIXTURE_ACCOUNT,
                &admit
            ));
            assert!(!admission_operation_allowed(
                true,
                authentication_readonly,
                original,
                &authenticate
            ));
        }
        assert!(!admission_operation_allowed(
            true,
            false,
            FRESHNESS_FIXTURE_ACCOUNT,
            &authenticate
        ));
        assert!(admission_operation_allowed(
            true,
            true,
            FRESHNESS_FIXTURE_ACCOUNT,
            &authenticate
        ));
    }

    /// The normal startup, seal and accept loop run against the current fixed
    /// protected configuration. Only authenticated epoch reads may dispatch.
    #[test]
    #[ignore = "operator-run root-only stock helper and independent nonroot epoch client"]
    fn native_stock_readonly_admission_service_entrypoint() -> Result<(), &'static str> {
        if !crate::openbsd::password_native_authority() {
            return Err("root OpenBSD authority required");
        }
        READONLY_ADMISSION_FIXTURE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "readonly fixture already armed")?;
        let signals = crate::openbsd::AccountAdmissionSignals::install().map_err(|error| {
            crate::account_password_fstat::report_signal_setup_failure(&error);
            "readonly fixture signal setup unavailable"
        })?;
        run_operator_service_with_metadata_diagnostics(signals.stop_flag())
            .map_err(|_| "readonly stock service lifecycle unavailable")
    }

    /// The same native service admits primary authentication only for the
    /// source-owned fresh account; all credential mutation remains refused.
    #[test]
    #[ignore = "operator-run root-only stock helper and independent fresh-account primary client"]
    fn native_stock_authentication_readonly_service_entrypoint() -> Result<(), &'static str> {
        if !crate::openbsd::password_native_authority() {
            return Err("root OpenBSD authority required");
        }
        READONLY_ADMISSION_FIXTURE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "readonly fixture already armed")?;
        AUTHENTICATION_READONLY_FIXTURE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "authentication readonly fixture already armed")?;
        let signals = crate::openbsd::AccountAdmissionSignals::install().map_err(|error| {
            crate::account_password_fstat::report_signal_setup_failure(&error);
            "readonly fixture signal setup unavailable"
        })?;
        let stop = signals.stop_flag();
        std::thread::scope(|scope| {
            let control = std::thread::Builder::new()
                .spawn_scoped(scope, move || {
                    let mut byte = [0u8; 1];
                    let result = match std::io::stdin().read_exact(&mut byte) {
                        Ok(()) if byte == [b'S'] => Ok(()),
                        Ok(()) => Err("readonly fixture stop byte invalid"),
                        Err(_) => Err("readonly fixture stop input unavailable"),
                    };
                    stop.store(true, Ordering::SeqCst);
                    result
                })
                .map_err(|_| "readonly fixture control thread unavailable")?;
            let service = run_operator_service_with_metadata_diagnostics(stop)
                .map_err(|_| "readonly stock service lifecycle unavailable");
            let control = control
                .join()
                .map_err(|_| "readonly fixture control thread failed")
                .and_then(|value| value);
            if control.is_err() {
                eprintln!("account_password_service fixture_stop_control=refused");
            }
            // The service diagnostic is emitted before joining; a secondary
            // control failure never replaces the original service failure.
            service.and(control)
        })
    }

    #[test]
    fn endpoint_cleanup_failure_retains_original_metadata_in_rich_trace() {
        use crate::account_password_fstat::{StartupOperation as Op, StartupTrace};
        let mut trace = StartupTrace::new(Op::StockWorkerArgv);
        trace.metadata("metadata_spawn_denied");
        trace.metadata_error(Error::Unavailable);
        let result = finish_service_with_cleanup(
            Err(Error::Unavailable),
            || Err(Error::Unavailable),
            || Ok(()),
        );
        assert_eq!(result, Err(Error::CleanupUnconfirmed));
        let mut output = Vec::new();
        trace
            .write_diagnostic(&mut output, &result.unwrap_err(), true)
            .unwrap();
        assert_eq!(String::from_utf8(output).unwrap(),
            "account_password_service stage=primary_fstat_stock_worker_argv_denied error=CleanupUnconfirmed\naccount_password_service metadata=metadata_spawn_denied error=Unavailable cleanup=unconfirmed\n");
    }
    /// Own process only: root has provisioned the existing fixed configuration,
    /// keys and fresh Alice/Bob accounts. Public mail stays untouched.
    #[test]
    #[ignore = "requires root-reviewed native postwrite fixture and independent owned cleanup"]
    fn native_stock_postwrite_refusal_service_entrypoint() {
        assert!(crate::openbsd::password_native_authority());
        let files = OperatorFiles::read(Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(
            files.accounts,
            BTreeSet::from([
                "alice@osmap-password.invalid".to_owned(),
                "bob@osmap-password.invalid".to_owned(),
            ])
        );
        assert!(
            !crate::account_password_runtime::STOCK_POSTWRITE_REFUSAL.swap(true, Ordering::SeqCst)
        );
        let signals = crate::openbsd::AccountAdmissionSignals::install()
            .expect("native postwrite signal handlers refused");
        run_operator_service(signals.stop_flag())
            .expect("native postwrite service lifecycle refused");
    }

    #[test]
    #[ignore = "requires root-reviewed before-write rendezvous and independent admission actor"]
    fn native_stock_concurrent_mutation_service_entrypoint() {
        assert!(crate::openbsd::password_native_authority());
        let files = OperatorFiles::read(Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(
            files.accounts,
            BTreeSet::from([
                "alice@osmap-password.invalid".to_owned(),
                "bob@osmap-password.invalid".to_owned(),
            ])
        );
        let fd: i32 = std::env::var("OSMAP_TEST_NATIVE_MUTATION_GATE_FD")
            .unwrap()
            .parse()
            .unwrap();
        assert!((3..=1024).contains(&fd));
        let control = crate::openbsd::fixture_owned_unix_stream(fd).unwrap();
        crate::account_password_runtime::arm_native_mutation_gate_fixture(control).unwrap();
        let signals = crate::openbsd::AccountAdmissionSignals::install()
            .expect("native concurrent signal handlers refused");
        run_operator_service(signals.stop_flag())
            .expect("native concurrent service lifecycle refused");
    }

    #[test]
    fn first_failure_is_bounded_independently_per_endpoint() {
        let admission = AtomicBool::new(false);
        let mutation = AtomicBool::new(false);
        for reported in [&admission, &mutation] {
            let winners = std::thread::scope(|scope| {
                let handles = (0..8)
                    .map(|_| scope.spawn(|| first_endpoint_failure(reported)))
                    .collect::<Vec<_>>();
                handles
                    .into_iter()
                    .map(|handle| handle.join().unwrap())
                    .filter(|first| *first)
                    .count()
            });
            assert_eq!(winners, 1);
            assert!(!first_endpoint_failure(reported));
        }
        assert_eq!(EndpointKind::Admission.stage(), "stock_admission");
        assert_eq!(EndpointKind::Mutation.stage(), "stock_mutation");
    }

    #[test]
    fn a_single_free_worker_alternates_between_busy_endpoints() {
        let mut preferred = EndpointKind::Admission;
        let mut active = MAX_ACTIVE_WORKERS - 1;
        let served = (0..8)
            .map(|_| {
                assert!(worker_slot_available(active));
                let current = endpoint_order(preferred)[0];
                active += 1;
                assert_eq!(active, MAX_ACTIVE_WORKERS);
                record_accepted_endpoint(&mut preferred, current);
                // One worker completes before both endpoints are ready again.
                active -= 1;
                current
            })
            .collect::<Vec<_>>();
        assert_eq!(
            served,
            vec![
                EndpointKind::Admission,
                EndpointKind::Mutation,
                EndpointKind::Admission,
                EndpointKind::Mutation,
                EndpointKind::Admission,
                EndpointKind::Mutation,
                EndpointKind::Admission,
                EndpointKind::Mutation,
            ]
        );
    }

    #[test]
    fn cleanup_uncertainty_has_precedence_over_service_outcome() {
        assert_eq!(
            finish_service(Err(Error::Expired), Err(Error::Unavailable), Ok(())),
            Err(Error::CleanupUnconfirmed)
        );
        assert_eq!(
            finish_service(Ok(()), Ok(()), Err(Error::Unavailable)),
            Err(Error::CleanupUnconfirmed)
        );
        assert_eq!(
            finish_service(Err(Error::Expired), Ok(()), Ok(())),
            Err(Error::Expired)
        );
    }

    #[test]
    fn mutation_cleanup_runs_after_admission_cleanup_failure() {
        let admission_calls = std::sync::atomic::AtomicUsize::new(0);
        let mutation_calls = std::sync::atomic::AtomicUsize::new(0);
        assert_eq!(
            finish_service_with_cleanup(
                Err(Error::Expired),
                || {
                    admission_calls.fetch_add(1, Ordering::SeqCst);
                    Err(Error::Unavailable)
                },
                || {
                    mutation_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            ),
            Err(Error::CleanupUnconfirmed)
        );
        assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
        assert_eq!(mutation_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mutation_diagnostics_preserve_safe_closed_error_categories() {
        assert_eq!(
            format!(
                "{:?}",
                StockOperationError::Connection(crate::account_password_connection::Error::Expired)
            ),
            "Connection(Expired)"
        );
        assert_eq!(
            format!(
                "{:?}",
                StockOperationError::Connection(
                    crate::account_password_connection::Error::Authentication
                )
            ),
            "Connection(Authentication)"
        );
        assert_eq!(
            format!("{:?}", StockOperationError::Service(Error::Authentication)),
            "Service(Authentication)"
        );
        assert_eq!(EndpointKind::Admission.stage(), "stock_admission");
        assert_eq!(EndpointKind::Mutation.stage(), "stock_mutation");
    }
}
