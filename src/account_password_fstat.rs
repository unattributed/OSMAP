//! One pre-seal-born, private fstat execution domain. No named endpoint, caller
//! program, credential or general command execution protocol is accepted.
use crate::auth::{CommandExecution, CommandExecutionError};
use std::io::Read;
#[cfg(test)]
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const WORKER_ARGUMENT: &str = "--fixed-fstat-observer";
const RESERVE: Duration = Duration::from_millis(100);
const MAX: usize = 65536;
const REQUEST: usize = 25;
const PREFIX: usize = 10;

// Fixed startup diagnostics share the existing static service channel. They
// carry no paths, PIDs, arguments, frames, native stderr or credential material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)] // Preserve stable historical phase IDs for retained evidence.
pub(crate) enum StartupOperation {
    ServiceNative = 0,
    ServiceDumps = 1,
    ServiceCwd = 2,
    ServiceFiles = 3,
    ServiceAdmission = 4,
    ServiceAccounts = 5,
    ServiceStartup = 6,
    ServiceStore = 7,
    ServiceFence = 8,
    BeforeRecheck = 9,
    GraphFstat = 10,
    GraphKvm = 11,
    GraphLibc = 12,
    GraphLoader = 13,
    GraphHints = 14,
    Pair = 15,
    Command = 16,
    Budget = 17,
    Spawn = 18,
    Hello = 19,
    HelloEof = 20,
    HelloFrame = 21,
    AfterRecheck = 22,
    WorkerPeer = 23,
    CustodyCapture = 24,
    Seal = 25,
    Activate = 26,
    WorkerHello = 27,
    AdmissionBind = 28,
    MutationBind = 29,
    PublicationBind = 30,
    PublicationGroup = 31,
    PolicyBind = 32,
    PolicyNonblocking = 33,
    RegistrationRefresh = 34,
    ParentPrepare = 35,
    ParentSeal = 36,
    ParentActivate = 37,
    SetupDeadline = 38,
    ServiceSignals = 39,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum StartupCategory {
    Unknown = 0,
    Denied = 1,
    Invalid = 2,
    Absent = 3,
    Busy = 4,
    Capacity = 5,
    Deadline = 6,
    Eof = 7,
    Exit = 8,
    Signal = 9,
    Protocol = 10,
    Output = 11,
}
macro_rules! startup_tags {
    ($prefix:literal) => {
        [
            concat!($prefix, "_unknown"),
            concat!($prefix, "_denied"),
            concat!($prefix, "_invalid"),
            concat!($prefix, "_absent"),
            concat!($prefix, "_busy"),
            concat!($prefix, "_capacity"),
            concat!($prefix, "_deadline"),
            concat!($prefix, "_eof"),
            concat!($prefix, "_exit"),
            concat!($prefix, "_signal"),
            concat!($prefix, "_protocol"),
            concat!($prefix, "_output"),
        ]
    };
}
const STARTUP_TAGS: [[&str; 12]; 40] = [
    startup_tags!("primary_fstat_service_native"),
    startup_tags!("primary_fstat_service_dumps"),
    startup_tags!("primary_fstat_service_cwd"),
    startup_tags!("primary_fstat_service_files"),
    startup_tags!("primary_fstat_service_admission"),
    startup_tags!("primary_fstat_service_accounts"),
    startup_tags!("primary_fstat_service_startup"),
    startup_tags!("primary_fstat_service_store"),
    startup_tags!("primary_fstat_service_fence"),
    startup_tags!("primary_fstat_before_recheck"),
    startup_tags!("primary_fstat_graph_fstat"),
    startup_tags!("primary_fstat_graph_kvm"),
    startup_tags!("primary_fstat_graph_libc"),
    startup_tags!("primary_fstat_graph_loader"),
    startup_tags!("primary_fstat_graph_hints"),
    startup_tags!("primary_fstat_pair"),
    startup_tags!("primary_fstat_command"),
    startup_tags!("primary_fstat_budget"),
    startup_tags!("primary_fstat_spawn"),
    startup_tags!("primary_fstat_hello"),
    startup_tags!("primary_fstat_hello_eof"),
    startup_tags!("primary_fstat_hello_frame"),
    startup_tags!("primary_fstat_after_recheck"),
    startup_tags!("primary_fstat_worker_peer"),
    startup_tags!("primary_fstat_custody_capture"),
    startup_tags!("primary_fstat_seal"),
    startup_tags!("primary_fstat_activate"),
    startup_tags!("primary_fstat_worker_hello"),
    startup_tags!("primary_fstat_admission_bind"),
    startup_tags!("primary_fstat_mutation_bind"),
    startup_tags!("primary_fstat_publication_bind"),
    startup_tags!("primary_fstat_publication_group"),
    startup_tags!("primary_fstat_policy_bind"),
    startup_tags!("primary_fstat_policy_nonblocking"),
    startup_tags!("primary_fstat_registration_refresh"),
    startup_tags!("primary_fstat_parent_prepare"),
    startup_tags!("primary_fstat_parent_seal"),
    startup_tags!("primary_fstat_parent_activate"),
    startup_tags!("primary_fstat_setup_deadline"),
    startup_tags!("primary_fstat_service_signals"),
];
const WORKER_STARTUP_TAGS: [[&str; 12]; 40] = [
    startup_tags!("primary_fstat_bootstrap_service_native"),
    startup_tags!("primary_fstat_bootstrap_service_dumps"),
    startup_tags!("primary_fstat_bootstrap_service_cwd"),
    startup_tags!("primary_fstat_bootstrap_service_files"),
    startup_tags!("primary_fstat_bootstrap_service_admission"),
    startup_tags!("primary_fstat_bootstrap_service_accounts"),
    startup_tags!("primary_fstat_bootstrap_service_startup"),
    startup_tags!("primary_fstat_bootstrap_service_store"),
    startup_tags!("primary_fstat_bootstrap_service_fence"),
    startup_tags!("primary_fstat_bootstrap_before_recheck"),
    startup_tags!("primary_fstat_bootstrap_graph_fstat"),
    startup_tags!("primary_fstat_bootstrap_graph_kvm"),
    startup_tags!("primary_fstat_bootstrap_graph_libc"),
    startup_tags!("primary_fstat_bootstrap_graph_loader"),
    startup_tags!("primary_fstat_bootstrap_graph_hints"),
    startup_tags!("primary_fstat_bootstrap_pair"),
    startup_tags!("primary_fstat_bootstrap_command"),
    startup_tags!("primary_fstat_bootstrap_budget"),
    startup_tags!("primary_fstat_bootstrap_spawn"),
    startup_tags!("primary_fstat_bootstrap_hello"),
    startup_tags!("primary_fstat_bootstrap_hello_eof"),
    startup_tags!("primary_fstat_bootstrap_hello_frame"),
    startup_tags!("primary_fstat_bootstrap_after_recheck"),
    startup_tags!("primary_fstat_bootstrap_worker_peer"),
    startup_tags!("primary_fstat_bootstrap_custody_capture"),
    startup_tags!("primary_fstat_bootstrap_seal"),
    startup_tags!("primary_fstat_bootstrap_activate"),
    startup_tags!("primary_fstat_bootstrap_worker_hello"),
    startup_tags!("primary_fstat_bootstrap_admission_bind"),
    startup_tags!("primary_fstat_bootstrap_mutation_bind"),
    startup_tags!("primary_fstat_bootstrap_publication_bind"),
    startup_tags!("primary_fstat_bootstrap_publication_group"),
    startup_tags!("primary_fstat_bootstrap_policy_bind"),
    startup_tags!("primary_fstat_bootstrap_policy_nonblocking"),
    startup_tags!("primary_fstat_bootstrap_registration_refresh"),
    startup_tags!("primary_fstat_bootstrap_parent_prepare"),
    startup_tags!("primary_fstat_bootstrap_parent_seal"),
    startup_tags!("primary_fstat_bootstrap_parent_activate"),
    startup_tags!("primary_fstat_bootstrap_setup_deadline"),
    startup_tags!("primary_fstat_bootstrap_service_signals"),
];
pub(crate) struct StartupTrace {
    operation: StartupOperation,
    category: StartupCategory,
    worker: bool,
    cleanup_unknown: bool,
    enabled: bool,
}
impl StartupTrace {
    pub(crate) fn new(operation: StartupOperation) -> Self {
        Self {
            operation,
            category: StartupCategory::Unknown,
            worker: false,
            cleanup_unknown: false,
            enabled: true,
        }
    }
    pub(crate) fn set(&mut self, operation: StartupOperation) {
        self.operation = operation;
        self.category = StartupCategory::Unknown;
    }
    pub(crate) fn category(&mut self, category: StartupCategory) {
        self.category = category;
    }
    pub(crate) fn io(&mut self, error: &std::io::Error) {
        use std::io::ErrorKind;
        self.category = match crate::account_password_process::metadata_errno_tag("builder", error)
        {
            "metadata_builder_denied" => StartupCategory::Denied,
            "metadata_builder_invalid" => StartupCategory::Invalid,
            "metadata_builder_absent" => StartupCategory::Absent,
            "metadata_builder_busy" => StartupCategory::Busy,
            "metadata_builder_capacity" => StartupCategory::Capacity,
            _ => match error.kind() {
                ErrorKind::PermissionDenied => StartupCategory::Denied,
                ErrorKind::InvalidInput | ErrorKind::InvalidData => StartupCategory::Invalid,
                ErrorKind::NotFound => StartupCategory::Absent,
                ErrorKind::WouldBlock => StartupCategory::Busy,
                ErrorKind::OutOfMemory => StartupCategory::Capacity,
                ErrorKind::TimedOut => StartupCategory::Deadline,
                ErrorKind::UnexpectedEof => StartupCategory::Eof,
                _ => StartupCategory::Unknown,
            },
        };
    }
    fn failure(&mut self, failure: Failure) {
        self.category = match failure {
            Failure::Deadline => StartupCategory::Deadline,
            Failure::Output => StartupCategory::Output,
            Failure::Protocol => StartupCategory::Protocol,
            Failure::Signal => StartupCategory::Signal,
            Failure::Exit | Failure::WorkerExit => StartupCategory::Exit,
            Failure::Cleanup => {
                self.cleanup_unknown = true;
                StartupCategory::Unknown
            }
            _ => StartupCategory::Unknown,
        };
    }
    fn tag(&self) -> &'static str {
        if self.worker {
            WORKER_STARTUP_TAGS[self.operation as usize][self.category as usize]
        } else {
            STARTUP_TAGS[self.operation as usize][self.category as usize]
        }
    }
    pub(crate) fn cleanup_failed(&mut self) {
        self.cleanup_unknown = true;
    }
    pub(crate) fn finish(&mut self) {
        self.enabled = false;
    }
    pub(crate) fn emit(&self, error: &crate::account_admission::Error) {
        if self.enabled {
            if self.cleanup_unknown {
                eprintln!(
                    "account_password_service stage={} error=CleanupUnconfirmed",
                    self.tag()
                );
            } else {
                eprintln!(
                    "account_password_service stage={} error={error:?}",
                    self.tag()
                );
            }
        }
    }
    fn after_stop(&mut self, exited: bool, clean: &Result<i32, Failure>) {
        if self.operation == StartupOperation::HelloEof && exited {
            match clean {
                Ok(code) if *code < 0 => self.category(StartupCategory::Signal),
                Ok(_) => self.category(StartupCategory::Exit),
                Err(_) => {}
            }
        }
        if clean.is_err() {
            self.cleanup_unknown = true;
        }
    }
    fn bootstrap_frame(&self) -> [u8; 4] {
        [1, 1, self.operation as u8, self.category as u8]
    }
    fn accept_bootstrap(&mut self, raw: &[u8]) -> Result<(), Failure> {
        if raw.len() != 4 || raw[0..2] != [1, 1] {
            return Err(Failure::Protocol);
        }
        let operation = match raw[2] {
            23 => StartupOperation::WorkerPeer,
            10 => StartupOperation::GraphFstat,
            11 => StartupOperation::GraphKvm,
            12 => StartupOperation::GraphLibc,
            13 => StartupOperation::GraphLoader,
            14 => StartupOperation::GraphHints,
            24 => StartupOperation::CustodyCapture,
            25 => StartupOperation::Seal,
            26 => StartupOperation::Activate,
            27 => StartupOperation::WorkerHello,
            _ => return Err(Failure::Protocol),
        };
        let category = match raw[3] {
            0 => StartupCategory::Unknown,
            1 => StartupCategory::Denied,
            2 => StartupCategory::Invalid,
            3 => StartupCategory::Absent,
            4 => StartupCategory::Busy,
            5 => StartupCategory::Capacity,
            6 => StartupCategory::Deadline,
            7 => StartupCategory::Eof,
            8 => StartupCategory::Exit,
            9 => StartupCategory::Signal,
            10 => StartupCategory::Protocol,
            11 => StartupCategory::Output,
            _ => return Err(Failure::Protocol),
        };
        self.operation = operation;
        self.category = category;
        self.worker = true;
        Ok(())
    }
}
/// Fixed no-argument service signal setup failure; no caller-selected stage.
pub fn report_signal_setup_failure(error: &std::io::Error) {
    let mut trace = StartupTrace::new(StartupOperation::ServiceSignals);
    trace.io(error);
    trace.emit(&crate::account_admission::Error::Unavailable);
}
fn startup_receive(
    stream: &mut UnixStream,
    end: Instant,
    trace: &mut StartupTrace,
) -> Result<Vec<u8>, Failure> {
    fn exact(
        stream: &mut UnixStream,
        mut bytes: &mut [u8],
        end: Instant,
        trace: &mut StartupTrace,
    ) -> Result<(), Failure> {
        while !bytes.is_empty() {
            let left = remaining(end).inspect_err(|&e| {
                trace.failure(e);
            })?;
            stream.set_read_timeout(Some(left)).map_err(|e| {
                trace.io(&e);
                Failure::Protocol
            })?;
            let count = stream.read(bytes).map_err(|e| {
                trace.io(&e);
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    trace.category(StartupCategory::Deadline);
                    Failure::Deadline
                } else {
                    Failure::Protocol
                }
            })?;
            if count == 0 {
                trace.set(StartupOperation::HelloEof);
                trace.category(StartupCategory::Eof);
                return Err(Failure::Protocol);
            }
            bytes = &mut bytes[count..];
        }
        remaining(end).inspect_err(|&e| {
            trace.failure(e);
        })?;
        Ok(())
    }
    let mut header = [0; 4];
    exact(stream, &mut header, end, trace)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > 4 {
        trace.set(StartupOperation::HelloFrame);
        trace.category(StartupCategory::Output);
        return Err(Failure::Output);
    }
    let mut raw = vec![0; len];
    exact(stream, &mut raw, end, trace)?;
    Ok(raw)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Spawn,
    Exit,
    Signal,
    Deadline,
    Output,
    Cleanup,
    Protocol,
    Stderr,
    Loader,
    KernFile,
    WorkerExit,
    RpcDeadline,
    PreSpawnDeadline,
    Graph,
}
impl Failure {
    fn reason(self) -> &'static str {
        match self {
            Self::Spawn => "metadata_spawn_unknown",
            Self::Exit => "metadata_query_exit",
            Self::Signal => "metadata_fstat_signal",
            Self::Deadline => "metadata_child_deadline",
            Self::Output => "metadata_child_output",
            Self::Cleanup => "metadata_child_cleanup",
            Self::Protocol => "metadata_fstat_protocol",
            Self::Stderr => "metadata_query_stderr",
            Self::Loader => "metadata_fstat_loader",
            Self::KernFile => "metadata_fstat_kernfile",
            Self::WorkerExit => "metadata_fstat_worker_exit",
            Self::RpcDeadline => "metadata_fstat_rpc_deadline",
            Self::PreSpawnDeadline => "metadata_child_budget",
            Self::Graph => "metadata_fstat_graph",
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::Spawn => 1,
            Self::Exit => 2,
            Self::Signal => 3,
            Self::Deadline => 4,
            Self::Output => 5,
            Self::Cleanup => 6,
            Self::Protocol => 7,
            Self::Stderr => 8,
            Self::Loader => 9,
            Self::KernFile => 10,
            Self::WorkerExit => 11,
            Self::PreSpawnDeadline => 12,
            Self::Graph => 13,
            // Parent-only category is never accepted as worker authority.
            Self::RpcDeadline => 14,
        }
    }
    fn decode(byte: u8) -> Result<Self, Self> {
        match byte {
            1 => Ok(Self::Spawn),
            2 => Ok(Self::Exit),
            3 => Ok(Self::Signal),
            4 => Ok(Self::Deadline),
            5 => Ok(Self::Output),
            6 => Ok(Self::Cleanup),
            7 => Ok(Self::Protocol),
            8 => Ok(Self::Stderr),
            9 => Ok(Self::Loader),
            10 => Ok(Self::KernFile),
            11 => Ok(Self::WorkerExit),
            12 => Ok(Self::PreSpawnDeadline),
            13 => Ok(Self::Graph),
            _ => Err(Self::Protocol),
        }
    }
}
fn error(failure: Failure) -> CommandExecutionError {
    CommandExecutionError {
        reason: failure.reason().into(),
    }
}
fn rpc_failure(failure: Failure) -> Failure {
    if failure == Failure::Deadline {
        Failure::RpcDeadline
    } else {
        failure
    }
}
fn operation_end(caller: Instant, began: Instant) -> Instant {
    caller.min(began + Duration::from_millis(500))
}
fn remaining(deadline: Instant) -> Result<Duration, Failure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Failure::Deadline)
}
fn absolute(deadline: Instant) -> Result<u64, Failure> {
    let clock = crate::openbsd::password_monotonic_ns().map_err(|_| Failure::Deadline)?;
    let left = u64::try_from(remaining(deadline)?.as_nanos()).map_err(|_| Failure::Deadline)?;
    clock.checked_add(left).ok_or(Failure::Deadline)
}
fn deadline(stamp: u64) -> Result<Instant, Failure> {
    let began = Instant::now();
    let clock = crate::openbsd::password_monotonic_ns().map_err(|_| Failure::Deadline)?;
    let left = stamp
        .checked_sub(clock)
        .filter(|v| *v > 0 && *v <= 500_000_000)
        .ok_or(Failure::Deadline)?;
    Ok(began + Duration::from_nanos(left))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    Pid(u32),
    All,
}
impl Selection {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        if args.len() == 1 && args[0] == "-n" {
            return Ok(Self::All);
        }
        if args.len() != 3 || args[0] != "-n" || args[1] != "-p" {
            return Err(Failure::Protocol);
        }
        let value = args[2].parse::<u32>().map_err(|_| Failure::Protocol)?;
        if value.to_string() != args[2] {
            return Err(Failure::Protocol);
        }
        match Self::decode(value)? {
            Self::Pid(pid) => Ok(Self::Pid(pid)),
            Self::All => Err(Failure::Protocol),
        }
    }
    fn decode(value: u32) -> Result<Self, Failure> {
        match value {
            0 => Ok(Self::All),
            n if n > 1 && n < i32::MAX as u32 => Ok(Self::Pid(n)),
            _ => Err(Failure::Protocol),
        }
    }
    fn args(self) -> Vec<String> {
        match self {
            Self::Pid(pid) => vec!["-n".into(), "-p".into(), pid.to_string()],
            Self::All => vec!["-n".into()],
        }
    }
    fn wire(self) -> Result<u32, Failure> {
        match self {
            Self::All => Ok(0),
            Self::Pid(pid) if pid > 1 && pid < i32::MAX as u32 => Ok(pid),
            _ => Err(Failure::Protocol),
        }
    }
}
fn request(
    sequence: u64,
    selection: Selection,
    cap: usize,
    end: Instant,
) -> Result<Vec<u8>, Failure> {
    if sequence == 0 || !matches!(cap, 4096 | 16384 | 65536) {
        return Err(Failure::Protocol);
    }
    let mut out = vec![1];
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&selection.wire()?.to_be_bytes());
    out.extend_from_slice(&(cap as u32).to_be_bytes());
    out.extend_from_slice(&absolute(end)?.to_be_bytes());
    Ok(out)
}
fn parse_request(raw: &[u8], sequence: u64) -> Result<(Selection, usize, Instant), Failure> {
    if raw.len() != REQUEST
        || raw[0] != 1
        || u64::from_be_bytes(raw[1..9].try_into().map_err(|_| Failure::Protocol)?) != sequence
    {
        return Err(Failure::Protocol);
    }
    let selection = Selection::decode(u32::from_be_bytes(
        raw[9..13].try_into().map_err(|_| Failure::Protocol)?,
    ))?;
    let cap = u32::from_be_bytes(raw[13..17].try_into().map_err(|_| Failure::Protocol)?) as usize;
    if !matches!(cap, 4096 | 16384 | 65536) {
        return Err(Failure::Protocol);
    }
    Ok((
        selection,
        cap,
        deadline(u64::from_be_bytes(
            raw[17..25].try_into().map_err(|_| Failure::Protocol)?,
        ))?,
    ))
}
fn frame_failure(error: crate::openpgp_inventory::Error, end: Instant) -> Failure {
    if Instant::now() >= end {
        Failure::Deadline
    } else if matches!(error, crate::openpgp_inventory::Error::Limit) {
        Failure::Output
    } else {
        Failure::Protocol
    }
}
fn send(stream: &mut UnixStream, raw: &[u8], end: Instant) -> Result<(), Failure> {
    if raw.is_empty() || raw.len() > MAX + PREFIX {
        return Err(Failure::Output);
    }
    crate::openpgp_inventory_runtime::write_frame(stream, raw, end)
        .map_err(|e| frame_failure(e, end))
}
fn receive(stream: &mut UnixStream, max: usize, end: Instant) -> Result<Vec<u8>, Failure> {
    crate::openpgp_inventory_runtime::read_frame(stream, max, end)
        .map_err(|e| frame_failure(e, end))
}
fn read_exact(stream: &mut UnixStream, mut raw: &mut [u8], end: Instant) -> Result<(), Failure> {
    while !raw.is_empty() {
        stream
            .set_read_timeout(Some(remaining(end)?))
            .map_err(|_| Failure::Protocol)?;
        let n = stream.read(raw).map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                Failure::Deadline
            } else {
                Failure::Protocol
            }
        })?;
        if n == 0 {
            return Err(Failure::Protocol);
        }
        raw = &mut raw[n..];
    }
    remaining(end)?;
    Ok(())
}
fn parse_reply(raw: &[u8], sequence: u64, cap: usize) -> Result<String, Failure> {
    if raw.len() < PREFIX
        || raw[0] != 1
        || u64::from_be_bytes(raw[2..10].try_into().map_err(|_| Failure::Protocol)?) != sequence
    {
        return Err(Failure::Protocol);
    }
    if raw[1] != 0 {
        if raw.len() != PREFIX {
            return Err(Failure::Protocol);
        }
        return Err(Failure::decode(raw[1])?);
    }
    let body = &raw[PREFIX..];
    if body.len() > cap || !body.is_ascii() || body.contains(&0) {
        return Err(Failure::Output);
    }
    String::from_utf8(body.to_vec()).map_err(|_| Failure::Output)
}
fn reply(sequence: u64, result: Result<String, Failure>) -> Vec<u8> {
    let mut out = vec![1, 0];
    out.extend_from_slice(&sequence.to_be_bytes());
    match result {
        Ok(text) => out.extend_from_slice(text.as_bytes()),
        Err(f) => out[1] = f.byte(),
    }
    out
}

struct State {
    child: Option<Child>,
    stream: UnixStream,
    sequence: u64,
    failed: bool,
}
/// Current permits the server to continue custody checks; Busy grants no
/// authority and postpones the iteration before any accepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recheck {
    Current,
    Busy,
}

pub(crate) struct Observer {
    state: Mutex<State>,
}
impl Observer {
    #[allow(dead_code)] // Retained private observer lifecycle, unselected by stock.
    pub(crate) fn start(
        startup: &crate::account_password_peer::Startup,
        metadata: &crate::account_password_process::MetadataExecutor,
        end: Instant,
        trace: &mut StartupTrace,
    ) -> Result<Self, CommandExecutionError> {
        if !crate::openbsd::password_native_authority() {
            return Err(error(Failure::Protocol));
        }
        trace.set(StartupOperation::BeforeRecheck);
        startup.recheck(metadata, end).map_err(|e| {
            if e == crate::account_password_policy_endpoint::Error::Expired || Instant::now() >= end
            {
                trace.category(StartupCategory::Deadline);
            }
            error(Failure::Protocol)
        })?;
        crate::account_password_native::verify_fstat_worker_graph_with_trace(end, trace).map_err(
            |_| {
                if Instant::now() >= end {
                    trace.category(StartupCategory::Deadline);
                }
                error(Failure::Protocol)
            },
        )?;
        trace.set(StartupOperation::Pair);
        let (stream, child_stream) = UnixStream::pair().map_err(|e| {
            trace.io(&e);
            error(Failure::Spawn)
        })?;
        trace.set(StartupOperation::Command);
        let mut command = crate::auth::password_fstat_worker_command().map_err(|e| {
            trace.io(&e);
            error(Failure::Spawn)
        })?;
        command
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_stream)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        trace.set(StartupOperation::Budget);
        let io_end = end
            .checked_sub(RESERVE)
            .filter(|v| *v > Instant::now())
            .ok_or_else(|| {
                trace.category(StartupCategory::Deadline);
                error(Failure::Deadline)
            })?;
        trace.set(StartupOperation::Spawn);
        let child = command.spawn().map_err(|e| {
            trace.io(&e);
            error(Failure::Spawn)
        })?;
        let mut state = State {
            child: Some(child),
            stream,
            sequence: 0,
            failed: false,
        };
        // Command is reusable and retains its owned stdin peer. Release that
        // parent copy before waiting so an exited child can produce EOF.
        drop(command);
        trace.set(StartupOperation::Hello);
        let ready = startup_receive(&mut state.stream, io_end, trace).and_then(|raw| {
            if raw == [1, 0] {
                Ok(())
            } else if raw.len() == 4 {
                if let Err(error) = trace.accept_bootstrap(&raw) {
                    trace.set(StartupOperation::HelloFrame);
                    trace.category(StartupCategory::Protocol);
                    return Err(error);
                }
                Err(Failure::Protocol)
            } else {
                trace.set(StartupOperation::HelloFrame);
                trace.category(StartupCategory::Protocol);
                Err(Failure::Protocol)
            }
        });
        if let Err(failure) = ready {
            state.failed = true;
            // Inspect without reaping. Only a pre-cleanup exit may supply the
            // child's own status; our later SIGKILL is never its failure cause.
            let exited = worker_exited(&state).unwrap_or(false);
            let clean = stop_state(&mut state, end);
            trace.after_stop(exited, &clean);
            return Err(error(if clean.is_ok() {
                failure
            } else {
                Failure::Cleanup
            }));
        }
        trace.set(StartupOperation::AfterRecheck);
        if let Err(e) = startup.recheck(metadata, end) {
            if e == crate::account_password_policy_endpoint::Error::Expired || Instant::now() >= end
            {
                trace.category(StartupCategory::Deadline);
            }
            let clean = stop_state(&mut state, end);
            if clean.is_err() {
                trace.cleanup_unknown = true;
            }
            return Err(error(if clean.is_ok() {
                Failure::Protocol
            } else {
                Failure::Cleanup
            }));
        }
        Ok(Self {
            state: Mutex::new(state),
        })
    }
    pub(crate) fn observe(
        &self,
        args: &[String],
        end: Instant,
        cap: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        // Bound the whole queued operation once, even if an outer topology
        // caller carries a longer budget. Neither lock nor child renews it.
        let end = operation_end(end, Instant::now());
        let selection = Selection::parse(args).map_err(error)?;
        let mut state = loop {
            match self.state.try_lock() {
                Ok(s) => break s,
                Err(std::sync::TryLockError::Poisoned(p)) => {
                    let mut state = p.into_inner();
                    state.failed = true;
                    crate::account_password_process::metadata_stopped();
                    let _ = stop_state(&mut state, end);
                    return Err(error(Failure::Cleanup));
                }
                Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(
                    remaining(end)
                        .map_err(|f| error(rpc_failure(f)))?
                        .min(Duration::from_millis(1)),
                ),
            }
        };
        if state.failed || state.child.is_none() {
            return Err(error(Failure::Protocol));
        }
        let io_end = end
            .checked_sub(RESERVE)
            .filter(|v| *v > Instant::now())
            .ok_or_else(|| error(Failure::RpcDeadline))?;
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| error(Failure::Protocol))?;
        let seq = state.sequence;
        let result = (|| {
            let raw = request(seq, selection, cap, io_end).map_err(rpc_failure)?;
            send(&mut state.stream, &raw, io_end).map_err(rpc_failure)?;
            let raw = receive(&mut state.stream, cap + PREFIX, io_end).map_err(rpc_failure)?;
            let data = parse_reply(&raw, seq, cap)?;
            remaining(io_end).map_err(rpc_failure)?;
            Ok(data)
        })();
        match result {
            Ok(stdout) => Ok(CommandExecution {
                status_code: 0,
                stdout,
                stderr: String::new(),
            }),
            Err(f) => {
                let f = if f == Failure::Protocol
                    && state.child.as_ref().is_some_and(|child| {
                        crate::openbsd::owned_child_exited_without_reap(child.id()).unwrap_or(false)
                    }) {
                    Failure::WorkerExit
                } else {
                    f
                };
                state.failed = true;
                crate::account_password_process::metadata_stopped();
                let clean = stop_state(&mut state, end);
                Err(error(if clean.is_ok() { f } else { Failure::Cleanup }))
            }
        }
    }
    pub(crate) fn recheck(&self, end: Instant) -> Result<Recheck, CommandExecutionError> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                let mut state = poisoned.into_inner();
                state.failed = true;
                state
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                // A finite in-flight observation owns this lock. Busy is not
                // a liveness attestation and never permits new admission.
                remaining(end).map_err(error)?;
                return Ok(Recheck::Busy);
            }
        };
        if !state.failed && worker_exited(&state).is_ok_and(|exited| !exited) {
            remaining(end).map_err(error)?;
            return Ok(Recheck::Current);
        }
        state.failed = true;
        crate::account_password_process::metadata_stopped();
        let clean = stop_state(&mut state, end);
        Err(error(if clean.is_ok() {
            Failure::WorkerExit
        } else {
            Failure::Cleanup
        }))
    }
    #[allow(dead_code)] // Retained private observer lifecycle, unselected by stock.
    pub(crate) fn shutdown(&self, end: Instant) -> Result<(), CommandExecutionError> {
        let mut state = loop {
            match self.state.try_lock() {
                Ok(s) => break s,
                Err(std::sync::TryLockError::Poisoned(p)) => {
                    let mut state = p.into_inner();
                    state.failed = true;
                    let _ = stop_state(&mut state, end);
                    return Err(error(Failure::Cleanup));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(remaining(end).map_err(error)?.min(Duration::from_millis(1)))
                }
            }
        };
        if state.child.is_none() {
            return if state.failed {
                Err(error(Failure::Protocol))
            } else {
                Ok(())
            };
        }
        let io_end = end
            .checked_sub(RESERVE)
            .ok_or_else(|| error(Failure::Deadline))?;
        let graceful = send(&mut state.stream, &[1, 255], io_end)
            .and_then(|_| receive(&mut state.stream, 2, io_end))
            .is_ok_and(|r| r == [1, 255]);
        while graceful && Instant::now() < io_end {
            let pid = state
                .child
                .as_ref()
                .ok_or_else(|| error(Failure::Cleanup))?
                .id();
            if crate::openbsd::owned_child_exited_without_reap(pid).unwrap_or(false) {
                break;
            }
            std::thread::sleep(
                io_end
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(1)),
            );
        }
        let result = stop_state(&mut state, end);
        if !graceful || !result.is_ok_and(|code| code == 0) {
            return Err(error(Failure::Cleanup));
        }
        Ok(())
    }
}
fn worker_exited(state: &State) -> Result<bool, Failure> {
    let child = state.child.as_ref().ok_or(Failure::Protocol)?;
    crate::openbsd::owned_child_exited_without_reap(child.id()).map_err(|_| Failure::Cleanup)
}
fn stop_state(state: &mut State, end: Instant) -> Result<i32, Failure> {
    let Some(mut child) = state.child.take() else {
        return Ok(0);
    };
    let pid = child.id();
    let _ = state.stream.shutdown(std::net::Shutdown::Both);
    let signal = crate::openbsd::kill_process_group(pid);
    let signaled = signal.is_ok()
        || signal
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(libc::ESRCH));
    while signaled && Instant::now() < end {
        if let Ok(Some(status)) = child.try_wait() {
            if crate::openbsd::process_group_exists(pid).is_ok_and(|v| !v) {
                return Ok(status.code().unwrap_or(-1));
            }
            break;
        }
        std::thread::sleep(
            end.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(1)),
        );
    }
    crate::account_password_process::retain_uncertain_metadata_child(child);
    Err(Failure::Cleanup)
}
impl Drop for Observer {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.child.is_some() {
            let _ = stop_state(state, Instant::now() + RESERVE);
        }
    }
}

/// Exact internal executable mode; a terminal, pipe or unprivileged caller
/// cannot create its private root-only peer authority.
pub fn run_worker() -> Result<(), crate::account_admission::Error> {
    worker().map_err(|_| crate::account_admission::Error::Unavailable)
}
fn worker() -> Result<(), Failure> {
    if !crate::openbsd::password_native_authority() {
        return Err(Failure::Protocol);
    }
    crate::openbsd::password_close_fstat_inherited_descriptors().map_err(|_| Failure::Protocol)?;
    crate::openbsd::disable_core_dumps().map_err(|_| Failure::Protocol)?;
    std::env::set_current_dir("/").map_err(|_| Failure::Protocol)?;
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| Failure::Protocol)?;
    let mut stream = UnixStream::from(fd);
    let end = Instant::now() + Duration::from_secs(5);
    let mut trace = StartupTrace::new(StartupOperation::WorkerPeer);
    trace.worker = true;
    let bootstrap = (|| {
        let peer = crate::openbsd::password_kernel_peer(&stream).map_err(|e| {
            trace.io(&e);
            Failure::Protocol
        })?;
        if peer.uid() != 0 || peer.gid() != 0 || peer.pid() == std::process::id() {
            trace.category(StartupCategory::Denied);
            return Err(Failure::Protocol);
        }
        let plan = crate::account_password_native::FstatWorkerPlan::capture(end, &mut trace)
            .map_err(|_| {
                if Instant::now() >= end {
                    trace.category(StartupCategory::Deadline);
                }
                Failure::Protocol
            })?;
        trace.set(StartupOperation::Seal);
        let seal = crate::openbsd::seal_password_fstat_worker(&plan).map_err(|e| {
            trace.io(&e);
            Failure::Protocol
        })?;
        trace.set(StartupOperation::Activate);
        plan.activate(&seal).map_err(|_| Failure::Protocol)?;
        trace.set(StartupOperation::WorkerHello);
        send(&mut stream, &[1, 0], end).inspect_err(|&e| {
            trace.failure(e);
        })?;
        Ok((plan, seal))
    })();
    let (plan, seal) = match bootstrap {
        Ok(value) => value,
        Err(failure) => {
            if trace.operation != StartupOperation::WorkerHello {
                let _ = send(&mut stream, &trace.bootstrap_frame(), end);
            }
            return Err(failure);
        }
    };
    let mut sequence = 0u64;
    loop {
        // Idle waiting has no operation. Once a header arrives, the original
        // parent's absolute request deadline bounds all utility/response work.
        stream
            .set_read_timeout(None)
            .map_err(|_| Failure::Protocol)?;
        let mut header = [0; 4];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(_) => return Err(Failure::Protocol),
        }
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > REQUEST {
            return Err(Failure::Protocol);
        }
        let mut raw = vec![0; len];
        read_exact(
            &mut stream,
            &mut raw,
            Instant::now() + Duration::from_millis(500),
        )?;
        if raw == [1, 255] {
            send(&mut stream, &[1, 255], Instant::now() + RESERVE)?;
            return Ok(());
        }
        sequence = sequence.checked_add(1).ok_or(Failure::Protocol)?;
        let (selection, cap, end) = parse_request(&raw, sequence)?;
        let graph_failed = plan.recheck(end).is_err();
        let result = if graph_failed {
            // An expired original stamp cannot publish a late assertion. The
            // parent then reports RPC expiry with the inner stage unknown.
            Err(Failure::Graph)
        } else {
            let args = selection.args();
            let result =
                crate::account_password_process::run_fstat_in_worker(&seal, &args, end, cap);
            match result {
                Err(e) => Err(match e.reason.as_str() {
                    "metadata_child_deadline" => Failure::Deadline,
                    "metadata_child_budget" => Failure::PreSpawnDeadline,
                    "metadata_child_output" => Failure::Output,
                    "metadata_child_cleanup" => Failure::Cleanup,
                    _ => Failure::Spawn,
                }),
                Ok(value) => {
                    if value.status_code < 0 {
                        Err(Failure::Signal)
                    } else if value.status_code != 0 {
                        if value.stderr.starts_with("ld.so:") {
                            Err(Failure::Loader)
                        } else if value.stderr.contains("kvm_getfiles:") {
                            Err(Failure::KernFile)
                        } else {
                            Err(Failure::Exit)
                        }
                    } else if !value.stderr.is_empty() {
                        Err(Failure::Stderr)
                    } else if value.stdout.len() > cap
                        || !value.stdout.is_ascii()
                        || value.stdout.contains('\0')
                    {
                        Err(Failure::Output)
                    } else {
                        Ok(value.stdout)
                    }
                }
            }
        };
        send(&mut stream, &reply(sequence, result), end)?;
        if graph_failed {
            return Err(Failure::Graph);
        }
        if crate::account_password_process::execution_quarantined() {
            return Err(Failure::Cleanup);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_released_command_peer_exposes_actual_child_exit_as_eof() {
        let (own, child_peer) = UnixStream::pair().unwrap();
        let output = child_peer.try_clone().unwrap();
        let mut command = crate::auth::password_fstat_echo_fixture();
        command
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_peer)))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(output)))
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().unwrap();
        let pid = child.id();
        let mut state = State {
            child: Some(child),
            stream: own,
            sequence: 0,
            failed: false,
        };
        let end = Instant::now() + Duration::from_millis(400);
        state.stream.shutdown(std::net::Shutdown::Write).unwrap();
        while !worker_exited(&state).unwrap() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(worker_exited(&state).unwrap());
        let mut old = StartupTrace::new(StartupOperation::Hello);
        assert_eq!(
            startup_receive(
                &mut state.stream,
                Instant::now() + Duration::from_millis(20),
                &mut old
            )
            .unwrap_err(),
            Failure::Deadline
        );
        // The same real exited, unreaped child and held stream now show EOF
        // after only the Command-owned duplicate peer is released.
        drop(command);
        let mut fixed = StartupTrace::new(StartupOperation::Hello);
        assert_eq!(
            startup_receive(&mut state.stream, end, &mut fixed).unwrap_err(),
            Failure::Protocol
        );
        assert_eq!(fixed.operation, StartupOperation::HelloEof);
        let clean = stop_state(&mut state, end);
        assert_eq!(clean, Ok(0));
        fixed.after_stop(true, &clean);
        assert_eq!(fixed.category, StartupCategory::Exit);
        assert!(!fixed.cleanup_unknown);
        assert!(!crate::openbsd::process_group_exists(pid).unwrap());
    }
    #[test]
    fn startup_bootstrap_closed_leaf_and_errno_tuple_survives_parent() {
        for operation in [
            StartupOperation::WorkerPeer,
            StartupOperation::GraphFstat,
            StartupOperation::GraphKvm,
            StartupOperation::GraphLibc,
            StartupOperation::GraphLoader,
            StartupOperation::GraphHints,
            StartupOperation::CustodyCapture,
            StartupOperation::Seal,
            StartupOperation::Activate,
            StartupOperation::WorkerHello,
        ] {
            let mut worker = StartupTrace::new(operation);
            worker.worker = true;
            worker.io(&std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            let mut parent = StartupTrace::new(StartupOperation::Hello);
            parent.accept_bootstrap(&worker.bootstrap_frame()).unwrap();
            assert_eq!(parent.tag(), worker.tag());
            assert!(parent.tag().ends_with("_denied"));
        }
        let mut parent = StartupTrace::new(StartupOperation::Hello);
        let original = parent.tag();
        for raw in [
            vec![1, 1],
            vec![2, 1, 0, 0],
            vec![1, 1, 255, 0],
            vec![1, 1, StartupOperation::ServiceFiles as u8, 0],
            vec![1, 1, StartupOperation::Seal as u8, 255],
            vec![1, 1, 0, 0, 0],
        ] {
            assert!(parent.accept_bootstrap(&raw).is_err());
            assert_eq!(parent.tag(), original);
        }
    }
    #[test]
    fn startup_eof_deadline_exit_signal_and_cleanup_stay_distinct() {
        let (mut own, other) = UnixStream::pair().unwrap();
        drop(other);
        let mut trace = StartupTrace::new(StartupOperation::Hello);
        assert_eq!(
            startup_receive(
                &mut own,
                Instant::now() + Duration::from_millis(50),
                &mut trace
            )
            .unwrap_err(),
            Failure::Protocol
        );
        let eof = trace.tag();
        assert!(eof.ends_with("hello_eof_eof"));
        trace.after_stop(false, &Ok(-1));
        assert_eq!(trace.tag(), eof);
        trace.after_stop(true, &Ok(1));
        let exited = trace.tag();
        assert_ne!(exited, eof);
        trace.after_stop(true, &Ok(-1));
        assert_ne!(trace.tag(), exited);
        trace.after_stop(false, &Err(Failure::Cleanup));
        assert!(trace.cleanup_unknown);
        let (mut own, other) = UnixStream::pair().unwrap();
        let mut trace = StartupTrace::new(StartupOperation::Hello);
        assert_eq!(
            startup_receive(
                &mut own,
                Instant::now() + Duration::from_millis(20),
                &mut trace
            )
            .unwrap_err(),
            Failure::Deadline
        );
        assert!(trace.tag().ends_with("_deadline"));
        drop(other);
    }
    #[test]
    fn service_recheck_defers_live_contention_and_refuses_expired_budget() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let observer = Observer {
            state: Mutex::new(State {
                child: None,
                stream,
                sequence: 0,
                failed: false,
            }),
        };
        let held = observer.state.lock().unwrap();
        let result = observer.recheck(Instant::now() + Duration::from_millis(500));
        assert_eq!(format!("{:?}", result.unwrap()), "Busy");
        assert_eq!(
            observer
                .recheck(Instant::now() - Duration::from_millis(1))
                .unwrap_err()
                .reason,
            "metadata_child_deadline"
        );
        assert!(!held.failed);
        drop(held);
    }

    #[test]
    fn closed_pid_frames_and_closed_failures_keep_their_exact_stage() {
        let now = Instant::now();
        let short = now + Duration::from_millis(100);
        assert_eq!(operation_end(short, now), short);
        let capped = operation_end(now + Duration::from_secs(2), now);
        assert_eq!(capped, now + Duration::from_millis(500));
        let end = Instant::now() + Duration::from_millis(400);
        let raw = request(7, Selection::Pid(42), 65536, end).unwrap();
        let (pid, cap, parsed) = parse_request(&raw, 7).unwrap();
        assert_eq!((pid, cap), (Selection::Pid(42), 65536));
        assert!(parsed <= end);
        let mut changed = raw.clone();
        changed[0] = 2;
        assert_eq!(parse_request(&changed, 7).unwrap_err(), Failure::Protocol);
        let mut changed = raw.clone();
        changed[9..13].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(parse_request(&changed, 7).unwrap_err(), Failure::Protocol);
        let mut changed = raw.clone();
        changed[13..17].copy_from_slice(&65537u32.to_be_bytes());
        assert_eq!(parse_request(&changed, 7).unwrap_err(), Failure::Protocol);
        assert!(request(1, Selection::Pid(0), 65536, end).is_err());
        assert!(request(1, Selection::Pid(42), 65537, end).is_err());
        assert!(parse_request(&raw, 8).is_err());
        assert!(deadline(0).is_err());
        assert!(deadline(crate::openbsd::password_monotonic_ns().unwrap() + 600_000_000).is_err());
        let all = request(1, Selection::All, 65536, end).unwrap();
        assert_eq!(parse_request(&all, 1).unwrap().0, Selection::All);
        assert_eq!(Selection::All.args(), vec!["-n"]);
        assert_eq!(Selection::parse(&["-n".into()]).unwrap(), Selection::All);
        for args in [
            vec!["-n".into(), "-p".into(), "0".into()],
            vec!["-n".into(), "-u".into(), "0".into()],
            vec!["-n".into(), "-p".into(), "01".into()],
        ] {
            assert!(Selection::parse(&args).is_err());
        }
        let mut stages = std::collections::BTreeSet::new();
        for failure in [
            Failure::Exit,
            Failure::Signal,
            Failure::Deadline,
            Failure::Output,
            Failure::Cleanup,
            Failure::Protocol,
            Failure::Loader,
            Failure::KernFile,
            Failure::WorkerExit,
        ] {
            assert_eq!(
                parse_reply(&reply(7, Err(failure)), 7, 65536).unwrap_err(),
                failure
            );
            let detail =
                crate::account_password_process::metadata_failure_tag(failure.reason()).unwrap();
            for phase in ["primary_startup_master_fstat", "primary_startup_own_fstat"] {
                let stage =
                    crate::account_password_process::metadata_phase_failure(phase, detail).unwrap();
                assert!(stages.insert(stage));
            }
        }
    }
    #[test]
    fn parent_rpc_expiry_is_not_a_worker_deadline_reply() {
        assert_eq!(rpc_failure(Failure::Deadline), Failure::RpcDeadline);
        assert_eq!(rpc_failure(Failure::Protocol), Failure::Protocol);
        let mut stages = std::collections::BTreeSet::new();
        for failure in [Failure::Deadline, Failure::PreSpawnDeadline, Failure::Graph] {
            assert_eq!(
                parse_reply(&reply(7, Err(failure)), 7, 65536).unwrap_err(),
                failure
            );
            for phase in ["primary_startup_master_fstat", "primary_startup_own_fstat"] {
                assert!(stages.insert(
                    crate::account_password_process::metadata_phase_failure(
                        phase,
                        failure.reason()
                    )
                    .unwrap()
                ));
            }
        }
        assert!(Failure::decode(Failure::RpcDeadline.byte()).is_err());
        for phase in ["primary_startup_master_fstat", "primary_startup_own_fstat"] {
            assert!(stages.insert(
                crate::account_password_process::metadata_phase_failure(
                    phase,
                    Failure::RpcDeadline.reason()
                )
                .unwrap()
            ));
        }
    }
    #[test]
    fn private_reply_deadline_and_limits_refuse_without_retry() {
        let (mut own, mut other) = UnixStream::pair().unwrap();
        let guard = std::thread::spawn(move || {
            let mut one = [0];
            other.read(&mut one).unwrap()
        });
        assert_eq!(
            receive(&mut own, 16, Instant::now() + Duration::from_millis(20)).unwrap_err(),
            Failure::Deadline
        );
        own.shutdown(std::net::Shutdown::Both).unwrap();
        assert_eq!(guard.join().unwrap(), 0);
        assert!(parse_reply(&reply(2, Ok("ok".into())), 1, 16).is_err());
        assert_eq!(
            parse_reply(&reply(1, Ok("long".into())), 1, 2).unwrap_err(),
            Failure::Output
        );
        let (mut own, mut other) = UnixStream::pair().unwrap();
        other
            .write_all(&((MAX + PREFIX + 1) as u32).to_be_bytes())
            .unwrap();
        assert_eq!(
            receive(
                &mut own,
                MAX + PREFIX,
                Instant::now() + Duration::from_millis(20)
            )
            .unwrap_err(),
            Failure::Output
        );
    }
    #[test]
    fn owned_purpose_group_stops_its_actual_child_and_reaps() {
        let (own, child_stream) = UnixStream::pair().unwrap();
        let output = child_stream.try_clone().unwrap();
        let mut command = crate::auth::password_fstat_echo_fixture();
        command
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_stream)))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(output)))
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().unwrap();
        let pid = child.id();
        let mut state = State {
            child: Some(child),
            stream: own,
            sequence: 0,
            failed: false,
        };
        // One actually executed fixed local child exercises private I/O and
        // owned group disposal; it is not native worker/confinement proof.
        let end = Instant::now() + Duration::from_millis(400);
        send(&mut state.stream, b"not-a-worker-reply", end).unwrap();
        let echoed = receive(&mut state.stream, 32, end).unwrap();
        assert!(parse_reply(&echoed, 1, 32).is_err());
        assert!(!worker_exited(&state).unwrap());
        state.stream.shutdown(std::net::Shutdown::Write).unwrap();
        while !worker_exited(&state).unwrap() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(worker_exited(&state).unwrap());
        stop_state(&mut state, end).unwrap();
        assert!(state.child.is_none());
        assert!(!crate::openbsd::process_group_exists(pid).unwrap());
    }
}
