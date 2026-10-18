//! Fixed SQL/hash process transport. Native identity/loader/confinement admission
//! remains a separate service-construction obligation; this module cannot enable
//! the ordinary password form or qualify the installed workflow by itself.
use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

static UNCERTAIN: AtomicBool = AtomicBool::new(false);
static METADATA_STOPPED: AtomicBool = AtomicBool::new(false);
static OWNED_UNREAPED: Mutex<Vec<Child>> = Mutex::new(Vec::new());
const LIMIT: usize = 4096;
const INPUT_LIMIT: usize = 16384;
const RESERVE: Duration = Duration::from_millis(100);

// Scalars for the existing ignored native SQL read failure only. No raw
// utility, SQL, password or verifier bytes leave this test-only observation.
#[cfg(test)]
mod native_trace {
    use std::cell::Cell;
    std::thread_local! { static VALUE: Cell<[i64; 6]> = const { Cell::new([0,-1,-1,-1,-1,0]) }; }
    pub(super) fn reset() {
        VALUE.with(|value| value.set([1, -1, -1, -1, -1, 0]));
    }
    pub(super) fn stage(stage: u8) {
        VALUE.with(|value| {
            let mut row = value.get();
            row[0] = stage.into();
            value.set(row);
        });
    }
    pub(super) fn errno(error: &std::io::Error) {
        VALUE.with(|value| {
            let mut row = value.get();
            row[1] = error.raw_os_error().map_or(-1, i64::from);
            value.set(row);
        });
    }
    pub(super) fn status(code: Option<i32>) {
        VALUE.with(|value| {
            let mut row = value.get();
            row[2] = code.map_or(-1, i64::from);
            value.set(row);
        });
    }
    pub(super) fn output(stdout: &[u8], stderr: &[u8]) {
        VALUE.with(|value| {
            let mut row = value.get();
            row[3] = stdout.len() as i64;
            row[4] = stderr.len() as i64;
            if stderr.len() >= 11
                && stderr.starts_with(b"ERROR ")
                && stderr[6..10].iter().all(u8::is_ascii_digit)
                && stderr[10] == b' '
            {
                let code = stderr[6..10]
                    .iter()
                    .fold(0i64, |sum, value| sum * 10 + i64::from(value - b'0'));
                if (1000..=9999).contains(&code) {
                    row[5] = code;
                }
            }
            value.set(row);
        });
    }
    #[cfg(target_os = "openbsd")]
    pub(super) fn snapshot() -> [i64; 6] {
        VALUE.with(Cell::get)
    }
}
#[cfg(all(test, target_os = "openbsd"))]
pub(crate) fn native_sql_read_diagnostic() -> [i64; 6] {
    native_trace::snapshot()
}

/// Original operation deadline is held by the trusted helper, not renewed per
/// utility. A cleanup uncertainty latches this process unavailable.
pub(crate) struct FixedExecutor<'a> {
    deadline: Instant,
    sql: &'a crate::account_password_native::NativeProfile,
    hash: &'a crate::account_password_native::NativeProfile,
    primary: &'a crate::account_password_native::NativeProfile,
    control: &'a crate::account_password_native::NativeProfile,
}
impl<'a> FixedExecutor<'a> {
    pub(crate) fn from_profiles(
        deadline: Instant,
        sql: &'a crate::account_password_native::NativeProfile,
        hash: &'a crate::account_password_native::NativeProfile,
        primary: &'a crate::account_password_native::NativeProfile,
        control: &'a crate::account_password_native::NativeProfile,
    ) -> Self {
        Self {
            deadline,
            sql,
            hash,
            primary,
            control,
        }
    }
}

/// A retained child or uncertain cleanup closes ALL service admission,
/// including epoch-only requests which would otherwise spawn no utility.
pub(crate) fn execution_quarantined() -> bool {
    UNCERTAIN.load(Ordering::SeqCst)
        || METADATA_STOPPED.load(Ordering::SeqCst)
        || OWNED_UNREAPED
            .lock()
            .map_or(true, |children| !children.is_empty())
}
pub(crate) fn metadata_stopped() {
    METADATA_STOPPED.store(true, Ordering::SeqCst);
}
pub(crate) fn retain_uncertain_metadata_child(child: Child) {
    UNCERTAIN.store(true, Ordering::SeqCst);
    OWNED_UNREAPED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(child);
}

pub(crate) struct MetadataExecutor {
    control: Option<std::sync::Arc<crate::account_password_peer::ControlPeer>>,
    fstat: Option<std::sync::Arc<crate::account_password_fstat::Observer>>,
}
impl MetadataExecutor {
    pub(crate) fn readonly() -> Self {
        Self {
            control: None,
            fstat: None,
        }
    }
    pub(crate) fn with_fstat(
        fstat: std::sync::Arc<crate::account_password_fstat::Observer>,
    ) -> Self {
        Self {
            control: None,
            fstat: Some(fstat),
        }
    }
    pub(crate) fn recheck_fstat(&self, end: Instant) -> Result<(), CommandExecutionError> {
        self.fstat.as_ref().ok_or_else(unavailable)?.recheck(end)
    }
    pub(crate) fn with_control(
        &self,
        control: std::sync::Arc<crate::account_password_peer::ControlPeer>,
    ) -> Self {
        Self {
            control: Some(control),
            fstat: self.fstat.clone(),
        }
    }
}
/// Closed source-owned metadata commands. PIDs are accepted only from the
/// native inspector's current kernel/process producer, never a request frame.
pub(crate) fn fixed_metadata_args(program: &str, args: &[String]) -> bool {
    let equal = |expected: &[&str]| args.iter().map(String::as_str).eq(expected.iter().copied());
    let pid = |value: &str| {
        value
            .parse::<u32>()
            .is_ok_and(|pid| pid > 1 && pid < i32::MAX as u32 && pid.to_string() == value)
    };
    match program {
        "/bin/ps" => {
            equal(&["-ax", "-o", crate::account_password_peer::PS_FIELDS])
                || (args.len() == 4
                    && args[0] == "-p"
                    && pid(&args[1])
                    && args[2] == "-o"
                    && matches!(
                        args[3].as_str(),
                        crate::account_password_peer::PS_FIELDS | "args="
                    ))
        }
        "/usr/bin/fstat" => {
            equal(&["-n"])
                || (args.len() == 3 && args[0] == "-n" && args[1] == "-p" && pid(&args[2]))
        }
        "/usr/local/sbin/postconf" => {
            equal(&["-M"]) || equal(&["-P"]) || equal(&["-h", "smtpd_sasl_auth_enable"])
        }
        "/usr/local/bin/doveconf" => equal(&["-c", crate::account_password_topology::CONFIG, "-n"]),
        "/sbin/pfctl" => {
            equal(&["-sr"])
                || equal(&["-s", "info"])
                || equal(&["-a", "osmap/account-submission", "-sr"])
                || equal(&["-i", "lo0", "-v", "-s", "Interfaces"])
        }
        "/usr/local/bin/doveadm" => {
            let who = crate::account_password_mail::WHO;
            equal(who)
                || (args.len() == who.len() + 1
                    && args[..who.len()]
                        .iter()
                        .map(String::as_str)
                        .eq(who.iter().copied())
                    && crate::account_admission::valid_account(&args[who.len()]).is_ok())
                || equal(&[
                    "-O",
                    "-o",
                    "stats_writer_socket_path=",
                    "proxy",
                    "list",
                    "-a",
                    crate::account_password_topology::IPC,
                ])
        }
        _ => false,
    }
}
impl CommandExecutor for MetadataExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        Err(unavailable())
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        cap: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        if !crate::openbsd::password_native_authority()
            || execution_quarantined()
            || !input.is_empty()
            || timeout.is_zero()
            || timeout > Duration::from_secs(10)
            || !matches!(cap, 4096 | 16384 | 65536)
            || !fixed_metadata_args(program, args)
        {
            return Err(unavailable());
        }
        let deadline = Instant::now() + timeout;
        if program == crate::account_password_peer::FSTAT
            && crate::openbsd::password_parent_is_sealed()
        {
            return self
                .fstat
                .as_ref()
                .ok_or_else(|| metadata_failure("metadata_fstat_protocol", true))?
                .observe(args, deadline, cap);
        }
        #[cfg(target_os = "openbsd")]
        if program == crate::account_password_peer::PS
            && crate::openbsd::password_parent_is_sealed()
        {
            // PS calls unveil itself and cannot run under our inherited locked
            // table. Keep the pre-seal external captures; after the real seal,
            // observe only these same fixed process fields through the kernel.
            let stdout = crate::openbsd::password_process_observation(args, deadline, cap)
                .map_err(|error| {
                    metadata_failure(
                        metadata_failure_tag(&error.to_string()).unwrap_or("metadata_ps_unknown"),
                        true,
                    )
                })?;
            return Ok(CommandExecution {
                status_code: 0,
                stdout,
                stderr: String::new(),
            });
        }
        if program == crate::account_password_mail::PROGRAM {
            // Administrative reads retain the fixed unprivileged control
            // identity/loader/socket profile; metadata never gains root WHO.
            let profile = crate::account_password_native::NativeProfile::from_control(
                self.control.as_ref().ok_or_else(unavailable)?.clone(),
                deadline,
            )
            .map_err(|_| unavailable())?;
            let plan = profile
                .prepare(program, args, deadline)
                .map_err(|_| unavailable())?;
            let mut command =
                crate::auth::password_backend_command(program, args).map_err(|_| unavailable())?;
            crate::openbsd::install_password_child_profile(&mut command, plan)
                .map_err(|_| unavailable())?;
            run_with_cap(command, b"", deadline, cap)
        } else {
            let command = crate::auth::password_metadata_command(program, args)
                .map_err(|error| metadata_failure(metadata_errno_tag("builder", &error), true))?;
            run_with_cap_labeled(command, b"", deadline, cap, true)
        }
    }
}

const META_PS_ROW: [&str; 6] = [
    "metadata_ps_row_denied",
    "metadata_ps_row_invalid",
    "metadata_ps_row_absent",
    "metadata_ps_row_busy",
    "metadata_ps_row_capacity",
    "metadata_ps_row_unknown",
];
const META_PS_ARGV: [&str; 6] = [
    "metadata_ps_argv_denied",
    "metadata_ps_argv_invalid",
    "metadata_ps_argv_absent",
    "metadata_ps_argv_busy",
    "metadata_ps_argv_capacity",
    "metadata_ps_argv_unknown",
];
const META_BUILDER: [&str; 6] = [
    "metadata_builder_denied",
    "metadata_builder_invalid",
    "metadata_builder_absent",
    "metadata_builder_busy",
    "metadata_builder_capacity",
    "metadata_builder_unknown",
];
const META_SPAWN: [&str; 6] = [
    "metadata_spawn_denied",
    "metadata_spawn_invalid",
    "metadata_spawn_absent",
    "metadata_spawn_busy",
    "metadata_spawn_capacity",
    "metadata_spawn_unknown",
];
const META_CHILD_IO: [&str; 6] = [
    "metadata_child_io_denied",
    "metadata_child_io_invalid",
    "metadata_child_io_absent",
    "metadata_child_io_busy",
    "metadata_child_io_capacity",
    "metadata_child_io_unknown",
];
const META_FIXED: &[&str] = &[
    "metadata_ps_request",
    "metadata_ps_row_count",
    "metadata_ps_row_render",
    "metadata_ps_argv_frame",
    "metadata_ps_unknown",
    "metadata_child_preflight",
    "metadata_child_deadline",
    "metadata_child_pipe",
    "metadata_child_output",
    "metadata_child_read",
    "metadata_child_cleanup",
    "metadata_child_encoding",
    "metadata_query_deadline",
    "metadata_query_exit",
    "metadata_query_stderr",
    "metadata_query_output",
    "metadata_fstat_signal",
    "metadata_fstat_protocol",
    "metadata_fstat_loader",
    "metadata_fstat_kernfile",
    "metadata_fstat_worker_exit",
];

/// Fixed diagnostics contain no dynamic command, output, account or path data.
pub(crate) fn metadata_failure_tag(reason: &str) -> Option<&'static str> {
    [
        META_PS_ROW.as_slice(),
        META_PS_ARGV.as_slice(),
        META_BUILDER.as_slice(),
        META_SPAWN.as_slice(),
        META_CHILD_IO.as_slice(),
        META_FIXED,
    ]
    .into_iter()
    .flatten()
    .copied()
    .find(|tag| *tag == reason)
}
pub(crate) fn metadata_errno_tag(operation: &str, error: &std::io::Error) -> &'static str {
    let class = match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => 0,
        Some(libc::EINVAL | libc::ENOTDIR | libc::EOPNOTSUPP) => 1,
        Some(libc::ENOENT | libc::ESRCH) => 2,
        Some(libc::EBUSY | libc::EAGAIN) => 3,
        Some(libc::ENOMEM | libc::E2BIG | libc::ENOBUFS) => 4,
        _ => 5,
    };
    match operation {
        "ps_row" => META_PS_ROW[class],
        "ps_argv" => META_PS_ARGV[class],
        "builder" => META_BUILDER[class],
        "spawn" => META_SPAWN[class],
        "child_io" => META_CHILD_IO[class],
        _ => "metadata_ps_unknown",
    }
}
/// Preserve both exact fixed observation and fixed closed failure category.
pub(crate) fn metadata_phase_failure(phase: &str, detail: &str) -> Option<&'static str> {
    match (phase, detail) {
        ("primary_startup_master_fstat", "metadata_fstat_worker_exit") => {
            Some("primary_startup_master_fstat_worker_exit")
        }
        ("primary_startup_own_fstat", "metadata_fstat_worker_exit") => {
            Some("primary_startup_own_fstat_worker_exit")
        }
        ("primary_startup_master_fstat", "metadata_fstat_signal") => {
            Some("primary_startup_master_fstat_worker_signal")
        }
        ("primary_startup_master_fstat", "metadata_fstat_protocol") => {
            Some("primary_startup_master_fstat_worker_protocol")
        }
        ("primary_startup_master_fstat", "metadata_fstat_loader") => {
            Some("primary_startup_master_fstat_worker_loader")
        }
        ("primary_startup_master_fstat", "metadata_fstat_kernfile") => {
            Some("primary_startup_master_fstat_worker_kernfile")
        }
        ("primary_startup_own_fstat", "metadata_fstat_signal") => {
            Some("primary_startup_own_fstat_worker_signal")
        }
        ("primary_startup_own_fstat", "metadata_fstat_protocol") => {
            Some("primary_startup_own_fstat_worker_protocol")
        }
        ("primary_startup_own_fstat", "metadata_fstat_loader") => {
            Some("primary_startup_own_fstat_worker_loader")
        }
        ("primary_startup_own_fstat", "metadata_fstat_kernfile") => {
            Some("primary_startup_own_fstat_worker_kernfile")
        }
        ("primary_startup_master_row", "metadata_ps_row_denied") => {
            Some("primary_startup_master_row_denied")
        }
        ("primary_startup_master_row", "metadata_ps_row_invalid") => {
            Some("primary_startup_master_row_invalid")
        }
        ("primary_startup_master_row", "metadata_ps_row_absent") => {
            Some("primary_startup_master_row_absent")
        }
        ("primary_startup_master_row", "metadata_ps_row_busy") => {
            Some("primary_startup_master_row_busy")
        }
        ("primary_startup_master_row", "metadata_ps_row_capacity") => {
            Some("primary_startup_master_row_capacity")
        }
        ("primary_startup_master_row", "metadata_ps_row_unknown") => {
            Some("primary_startup_master_row_unknown")
        }
        ("primary_startup_master_row", "metadata_ps_row_count") => {
            Some("primary_startup_master_row_count")
        }
        ("primary_startup_master_row", "metadata_ps_row_render") => {
            Some("primary_startup_master_row_render")
        }
        ("primary_startup_master_row", "metadata_ps_request") => {
            Some("primary_startup_master_row_ps_request")
        }
        ("primary_startup_master_row", "metadata_ps_unknown") => {
            Some("primary_startup_master_row_ps_unknown")
        }
        ("primary_startup_master_row", "metadata_query_deadline") => {
            Some("primary_startup_master_row_query_deadline")
        }
        ("primary_startup_master_row", "metadata_query_exit") => {
            Some("primary_startup_master_row_query_exit")
        }
        ("primary_startup_master_row", "metadata_query_stderr") => {
            Some("primary_startup_master_row_query_stderr")
        }
        ("primary_startup_master_row", "metadata_query_output") => {
            Some("primary_startup_master_row_query_output")
        }
        ("primary_startup_own_row", "metadata_ps_row_denied") => {
            Some("primary_startup_own_row_denied")
        }
        ("primary_startup_own_row", "metadata_ps_row_invalid") => {
            Some("primary_startup_own_row_invalid")
        }
        ("primary_startup_own_row", "metadata_ps_row_absent") => {
            Some("primary_startup_own_row_absent")
        }
        ("primary_startup_own_row", "metadata_ps_row_busy") => Some("primary_startup_own_row_busy"),
        ("primary_startup_own_row", "metadata_ps_row_capacity") => {
            Some("primary_startup_own_row_capacity")
        }
        ("primary_startup_own_row", "metadata_ps_row_unknown") => {
            Some("primary_startup_own_row_unknown")
        }
        ("primary_startup_own_row", "metadata_ps_row_count") => {
            Some("primary_startup_own_row_count")
        }
        ("primary_startup_own_row", "metadata_ps_row_render") => {
            Some("primary_startup_own_row_render")
        }
        ("primary_startup_own_row", "metadata_ps_request") => {
            Some("primary_startup_own_row_ps_request")
        }
        ("primary_startup_own_row", "metadata_ps_unknown") => {
            Some("primary_startup_own_row_ps_unknown")
        }
        ("primary_startup_own_row", "metadata_query_deadline") => {
            Some("primary_startup_own_row_query_deadline")
        }
        ("primary_startup_own_row", "metadata_query_exit") => {
            Some("primary_startup_own_row_query_exit")
        }
        ("primary_startup_own_row", "metadata_query_stderr") => {
            Some("primary_startup_own_row_query_stderr")
        }
        ("primary_startup_own_row", "metadata_query_output") => {
            Some("primary_startup_own_row_query_output")
        }
        ("primary_main_argv", "metadata_ps_argv_denied") => Some("primary_main_argv_denied"),
        ("primary_main_argv", "metadata_ps_argv_invalid") => Some("primary_main_argv_invalid"),
        ("primary_main_argv", "metadata_ps_argv_absent") => Some("primary_main_argv_absent"),
        ("primary_main_argv", "metadata_ps_argv_busy") => Some("primary_main_argv_busy"),
        ("primary_main_argv", "metadata_ps_argv_capacity") => Some("primary_main_argv_capacity"),
        ("primary_main_argv", "metadata_ps_argv_unknown") => Some("primary_main_argv_unknown"),
        ("primary_main_argv", "metadata_ps_argv_frame") => Some("primary_main_argv_frame"),
        ("primary_main_argv", "metadata_ps_request") => Some("primary_main_argv_ps_request"),
        ("primary_main_argv", "metadata_ps_unknown") => Some("primary_main_argv_ps_unknown"),
        ("primary_main_argv", "metadata_query_deadline") => {
            Some("primary_main_argv_query_deadline")
        }
        ("primary_main_argv", "metadata_query_exit") => Some("primary_main_argv_query_exit"),
        ("primary_main_argv", "metadata_query_stderr") => Some("primary_main_argv_query_stderr"),
        ("primary_main_argv", "metadata_query_output") => Some("primary_main_argv_query_output"),
        ("primary_startup_master_fstat", "metadata_builder_denied") => {
            Some("primary_startup_master_fstat_builder_denied")
        }
        ("primary_startup_master_fstat", "metadata_builder_invalid") => {
            Some("primary_startup_master_fstat_builder_invalid")
        }
        ("primary_startup_master_fstat", "metadata_builder_absent") => {
            Some("primary_startup_master_fstat_builder_absent")
        }
        ("primary_startup_master_fstat", "metadata_builder_busy") => {
            Some("primary_startup_master_fstat_builder_busy")
        }
        ("primary_startup_master_fstat", "metadata_builder_capacity") => {
            Some("primary_startup_master_fstat_builder_capacity")
        }
        ("primary_startup_master_fstat", "metadata_builder_unknown") => {
            Some("primary_startup_master_fstat_builder_unknown")
        }
        ("primary_startup_master_fstat", "metadata_spawn_denied") => {
            Some("primary_startup_master_fstat_spawn_denied")
        }
        ("primary_startup_master_fstat", "metadata_spawn_invalid") => {
            Some("primary_startup_master_fstat_spawn_invalid")
        }
        ("primary_startup_master_fstat", "metadata_spawn_absent") => {
            Some("primary_startup_master_fstat_spawn_absent")
        }
        ("primary_startup_master_fstat", "metadata_spawn_busy") => {
            Some("primary_startup_master_fstat_spawn_busy")
        }
        ("primary_startup_master_fstat", "metadata_spawn_capacity") => {
            Some("primary_startup_master_fstat_spawn_capacity")
        }
        ("primary_startup_master_fstat", "metadata_spawn_unknown") => {
            Some("primary_startup_master_fstat_spawn_unknown")
        }
        ("primary_startup_master_fstat", "metadata_child_io_denied") => {
            Some("primary_startup_master_fstat_child_io_denied")
        }
        ("primary_startup_master_fstat", "metadata_child_io_invalid") => {
            Some("primary_startup_master_fstat_child_io_invalid")
        }
        ("primary_startup_master_fstat", "metadata_child_io_absent") => {
            Some("primary_startup_master_fstat_child_io_absent")
        }
        ("primary_startup_master_fstat", "metadata_child_io_busy") => {
            Some("primary_startup_master_fstat_child_io_busy")
        }
        ("primary_startup_master_fstat", "metadata_child_io_capacity") => {
            Some("primary_startup_master_fstat_child_io_capacity")
        }
        ("primary_startup_master_fstat", "metadata_child_io_unknown") => {
            Some("primary_startup_master_fstat_child_io_unknown")
        }
        ("primary_startup_master_fstat", "metadata_child_preflight") => {
            Some("primary_startup_master_fstat_child_preflight")
        }
        ("primary_startup_master_fstat", "metadata_child_deadline") => {
            Some("primary_startup_master_fstat_child_deadline")
        }
        ("primary_startup_master_fstat", "metadata_child_pipe") => {
            Some("primary_startup_master_fstat_child_pipe")
        }
        ("primary_startup_master_fstat", "metadata_child_output") => {
            Some("primary_startup_master_fstat_child_output")
        }
        ("primary_startup_master_fstat", "metadata_child_read") => {
            Some("primary_startup_master_fstat_child_read")
        }
        ("primary_startup_master_fstat", "metadata_child_cleanup") => {
            Some("primary_startup_master_fstat_child_cleanup")
        }
        ("primary_startup_master_fstat", "metadata_child_encoding") => {
            Some("primary_startup_master_fstat_child_encoding")
        }
        ("primary_startup_master_fstat", "metadata_query_deadline") => {
            Some("primary_startup_master_fstat_query_deadline")
        }
        ("primary_startup_master_fstat", "metadata_query_exit") => {
            Some("primary_startup_master_fstat_query_exit")
        }
        ("primary_startup_master_fstat", "metadata_query_stderr") => {
            Some("primary_startup_master_fstat_query_stderr")
        }
        ("primary_startup_master_fstat", "metadata_query_output") => {
            Some("primary_startup_master_fstat_query_output")
        }
        ("primary_startup_own_fstat", "metadata_builder_denied") => {
            Some("primary_startup_own_fstat_builder_denied")
        }
        ("primary_startup_own_fstat", "metadata_builder_invalid") => {
            Some("primary_startup_own_fstat_builder_invalid")
        }
        ("primary_startup_own_fstat", "metadata_builder_absent") => {
            Some("primary_startup_own_fstat_builder_absent")
        }
        ("primary_startup_own_fstat", "metadata_builder_busy") => {
            Some("primary_startup_own_fstat_builder_busy")
        }
        ("primary_startup_own_fstat", "metadata_builder_capacity") => {
            Some("primary_startup_own_fstat_builder_capacity")
        }
        ("primary_startup_own_fstat", "metadata_builder_unknown") => {
            Some("primary_startup_own_fstat_builder_unknown")
        }
        ("primary_startup_own_fstat", "metadata_spawn_denied") => {
            Some("primary_startup_own_fstat_spawn_denied")
        }
        ("primary_startup_own_fstat", "metadata_spawn_invalid") => {
            Some("primary_startup_own_fstat_spawn_invalid")
        }
        ("primary_startup_own_fstat", "metadata_spawn_absent") => {
            Some("primary_startup_own_fstat_spawn_absent")
        }
        ("primary_startup_own_fstat", "metadata_spawn_busy") => {
            Some("primary_startup_own_fstat_spawn_busy")
        }
        ("primary_startup_own_fstat", "metadata_spawn_capacity") => {
            Some("primary_startup_own_fstat_spawn_capacity")
        }
        ("primary_startup_own_fstat", "metadata_spawn_unknown") => {
            Some("primary_startup_own_fstat_spawn_unknown")
        }
        ("primary_startup_own_fstat", "metadata_child_io_denied") => {
            Some("primary_startup_own_fstat_child_io_denied")
        }
        ("primary_startup_own_fstat", "metadata_child_io_invalid") => {
            Some("primary_startup_own_fstat_child_io_invalid")
        }
        ("primary_startup_own_fstat", "metadata_child_io_absent") => {
            Some("primary_startup_own_fstat_child_io_absent")
        }
        ("primary_startup_own_fstat", "metadata_child_io_busy") => {
            Some("primary_startup_own_fstat_child_io_busy")
        }
        ("primary_startup_own_fstat", "metadata_child_io_capacity") => {
            Some("primary_startup_own_fstat_child_io_capacity")
        }
        ("primary_startup_own_fstat", "metadata_child_io_unknown") => {
            Some("primary_startup_own_fstat_child_io_unknown")
        }
        ("primary_startup_own_fstat", "metadata_child_preflight") => {
            Some("primary_startup_own_fstat_child_preflight")
        }
        ("primary_startup_own_fstat", "metadata_child_deadline") => {
            Some("primary_startup_own_fstat_child_deadline")
        }
        ("primary_startup_own_fstat", "metadata_child_pipe") => {
            Some("primary_startup_own_fstat_child_pipe")
        }
        ("primary_startup_own_fstat", "metadata_child_output") => {
            Some("primary_startup_own_fstat_child_output")
        }
        ("primary_startup_own_fstat", "metadata_child_read") => {
            Some("primary_startup_own_fstat_child_read")
        }
        ("primary_startup_own_fstat", "metadata_child_cleanup") => {
            Some("primary_startup_own_fstat_child_cleanup")
        }
        ("primary_startup_own_fstat", "metadata_child_encoding") => {
            Some("primary_startup_own_fstat_child_encoding")
        }
        ("primary_startup_own_fstat", "metadata_query_deadline") => {
            Some("primary_startup_own_fstat_query_deadline")
        }
        ("primary_startup_own_fstat", "metadata_query_exit") => {
            Some("primary_startup_own_fstat_query_exit")
        }
        ("primary_startup_own_fstat", "metadata_query_stderr") => {
            Some("primary_startup_own_fstat_query_stderr")
        }
        ("primary_startup_own_fstat", "metadata_query_output") => {
            Some("primary_startup_own_fstat_query_output")
        }
        _ => None,
    }
}
fn metadata_failure(tag: &'static str, labeled: bool) -> CommandExecutionError {
    if labeled {
        CommandExecutionError {
            reason: metadata_failure_tag(tag)
                .unwrap_or("metadata_ps_unknown")
                .into(),
        }
    } else {
        unavailable()
    }
}
fn unavailable() -> CommandExecutionError {
    CommandExecutionError {
        reason: "password utility unavailable".into(),
    }
}
impl CommandExecutor for FixedExecutor<'_> {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(
            program,
            args,
            input,
            Duration::from_secs(10),
            LIMIT,
        )
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        #[cfg(test)]
        native_trace::reset();
        let primary = args.len() == crate::account_password_mail::PRIMARY.len() + 1
            && args
                .iter()
                .take(crate::account_password_mail::PRIMARY.len())
                .map(String::as_str)
                .eq(crate::account_password_mail::PRIMARY.iter().copied());
        let phase_limit = Duration::from_secs(if primary { 25 } else { 10 });
        if input.len() > INPUT_LIMIT || limit != LIMIT || timeout.is_zero() || timeout > phase_limit
        {
            return Err(unavailable());
        }
        let deadline = self.deadline.min(Instant::now() + timeout);
        let profile = if program == crate::account_password_backend::SQL_PROGRAM {
            self.sql
        } else if primary {
            self.primary
        } else if crate::account_password_mail::fixed_control_args(args) {
            self.control
        } else {
            self.hash
        };
        #[cfg(test)]
        native_trace::stage(2);
        let plan = profile
            .prepare(program, args, deadline)
            .map_err(|_| unavailable())?;
        #[cfg(test)]
        native_trace::stage(3);
        let mut command =
            crate::auth::password_backend_command(program, args).map_err(|_error| {
                #[cfg(test)]
                native_trace::errno(&_error);
                unavailable()
            })?;
        #[cfg(test)]
        native_trace::stage(4);
        crate::openbsd::install_password_child_profile(&mut command, plan).map_err(|_error| {
            #[cfg(test)]
            native_trace::errno(&_error);
            unavailable()
        })?;
        let result = run(command, input, deadline);
        #[cfg(test)]
        if result.is_ok() {
            native_trace::stage(9);
        }
        result
    }
}

fn drain_labeled(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    cap: usize,
    labeled: bool,
) -> Result<bool, CommandExecutionError> {
    let mut buffer = [0u8; LIMIT];
    // Bound each drain as well as total output, so a hot producer cannot hide
    // the original deadline from the duplex loop.
    for _ in 0..3 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) if bytes.len() + n <= cap => bytes.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Ok(_) => return Err(metadata_failure("metadata_child_output", labeled)),
            Err(_) => return Err(metadata_failure("metadata_child_read", labeled)),
        }
    }
    Ok(false)
}

fn run(
    command: Command,
    input: &[u8],
    deadline: Instant,
) -> Result<CommandExecution, CommandExecutionError> {
    run_with_cap(command, input, deadline, LIMIT)
}
fn run_with_cap(
    command: Command,
    input: &[u8],
    deadline: Instant,
    cap: usize,
) -> Result<CommandExecution, CommandExecutionError> {
    run_with_cap_labeled(command, input, deadline, cap, false)
}
fn run_with_cap_labeled(
    command: Command,
    input: &[u8],
    deadline: Instant,
    cap: usize,
    labeled: bool,
) -> Result<CommandExecution, CommandExecutionError> {
    run_with_group(command, input, deadline, cap, labeled, None)
}
pub(crate) fn run_fstat_in_worker(
    seal: &crate::openbsd::PasswordFstatSeal,
    args: &[String],
    deadline: Instant,
    cap: usize,
) -> Result<CommandExecution, CommandExecutionError> {
    if !seal.is_current_process() || !fixed_metadata_args(crate::account_password_peer::FSTAT, args)
    {
        return Err(metadata_failure("metadata_fstat_protocol", true));
    }
    let command = crate::auth::password_metadata_command(crate::account_password_peer::FSTAT, args)
        .map_err(|e| metadata_failure(metadata_errno_tag("builder", &e), true))?;
    run_with_group(command, b"", deadline, cap, true, Some(seal))
}
fn run_with_group(
    mut command: Command,
    input: &[u8],
    deadline: Instant,
    cap: usize,
    labeled: bool,
    fstat_seal: Option<&crate::openbsd::PasswordFstatSeal>,
) -> Result<CommandExecution, CommandExecutionError> {
    if !matches!(cap, 4096 | 16384 | 65536)
        || execution_quarantined()
        || deadline.saturating_duration_since(Instant::now()) <= RESERVE
    {
        return Err(metadata_failure("metadata_child_preflight", labeled));
    }
    let io_deadline = deadline - RESERVE;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if fstat_seal.is_none() {
        command.process_group(0);
    }
    #[cfg(test)]
    native_trace::stage(5);
    let mut child = command.spawn().map_err(|_error| {
        #[cfg(test)]
        native_trace::errno(&_error);
        metadata_failure(metadata_errno_tag("spawn", &_error), labeled)
    })?;
    #[cfg(test)]
    native_trace::stage(6);
    // Keep the born leader unreaped until signalling its exclusively owned
    // group. No historical/reusable PID is used as cleanup authority.
    let pid = child.id();
    let result = (|| {
        let mut input_pipe = Some(
            child
                .stdin
                .take()
                .ok_or_else(|| metadata_failure("metadata_child_pipe", labeled))?,
        );
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| metadata_failure("metadata_child_pipe", labeled))?;
        let mut error = child
            .stderr
            .take()
            .ok_or_else(|| metadata_failure("metadata_child_pipe", labeled))?;
        for fd in [
            input_pipe
                .as_ref()
                .ok_or_else(|| metadata_failure("metadata_child_pipe", labeled))?
                .as_raw_fd(),
            output.as_raw_fd(),
            error.as_raw_fd(),
        ] {
            crate::openbsd::set_descriptor_nonblocking(fd).map_err(|error| {
                metadata_failure(metadata_errno_tag("child_io", &error), labeled)
            })?;
        }
        if input.is_empty() {
            input_pipe.take();
        }
        let mut written = 0;
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if Instant::now() >= io_deadline {
                return Err(metadata_failure("metadata_child_deadline", labeled));
            }
            if let Some(pipe) = input_pipe.as_mut() {
                match pipe.write(&input[written..]) {
                    Ok(0) => return Err(metadata_failure("metadata_child_pipe", labeled)),
                    Ok(n) => written += n,
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    _ => return Err(metadata_failure("metadata_child_pipe", labeled)),
                }
                if written == input.len() {
                    input_pipe.take();
                }
            }
            if !out_eof {
                out_eof = drain_labeled(&mut output, &mut stdout, cap, labeled)?;
            }
            if !err_eof {
                err_eof = drain_labeled(&mut error, &mut stderr, cap, labeled)?;
            }
            if out_eof
                && err_eof
                && written == input.len()
                && crate::openbsd::owned_child_exited_without_reap(pid).map_err(|error| {
                    metadata_failure(metadata_errno_tag("child_io", &error), labeled)
                })?
            {
                return Ok((stdout, stderr));
            }
            crate::openbsd::wait_worker_pipes(
                input_pipe.as_ref().map(AsRawFd::as_raw_fd),
                (!out_eof).then(|| output.as_raw_fd()),
                (!err_eof).then(|| error.as_raw_fd()),
                io_deadline,
            )
            .map_err(|error| metadata_failure(metadata_errno_tag("child_io", &error), labeled))?;
        }
    })();
    // Kill while this unreaped Popen leader still leases the PGID; then reap
    // and prove absence. Descendants holding pipes cannot prolong a reader join.
    #[cfg(test)]
    native_trace::stage(7);
    // The fixed no-fork fstat retains its purpose worker's PGID. Its direct
    // unreaped Child is cleaned here; the parent owns the whole worker group.
    // All ordinary password roles preserve their existing separate groups.
    let signal = if fstat_seal.is_some() {
        child.kill()
    } else {
        crate::openbsd::kill_process_group(pid)
    };
    let signal_ok = signal.is_ok()
        || signal
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(libc::ESRCH));
    while signal_ok && Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            let gone = fstat_seal.is_some()
                || crate::openbsd::process_group_exists(pid).is_ok_and(|exists| !exists);
            if gone && Instant::now() < deadline {
                #[cfg(test)]
                {
                    native_trace::status(status.code());
                    native_trace::stage(8);
                }
                let (stdout, stderr) = result?;
                #[cfg(test)]
                {
                    native_trace::output(&stdout, &stderr);
                }
                return Ok(CommandExecution {
                    status_code: status.code().unwrap_or(-1),
                    stdout: String::from_utf8(stdout)
                        .map_err(|_| metadata_failure("metadata_child_encoding", labeled))?,
                    stderr: String::from_utf8(stderr)
                        .map_err(|_| metadata_failure("metadata_child_encoding", labeled))?,
                });
            }
            break;
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(2)),
        );
    }
    UNCERTAIN.store(true, Ordering::SeqCst);
    if let Ok(mut children) = OWNED_UNREAPED.lock() {
        children.push(child);
    }
    Err(metadata_failure("metadata_child_cleanup", labeled))
}

#[cfg(test)]
#[path = "account_password_process_tests.rs"]
mod tests;

/// One-role adapter for admission before a submission namespace exists. The
/// sealed profile only prepares PRIMARY commands; no SQL/hash/control fallback.
pub(crate) struct PrimaryExecutor<'a> {
    profile: &'a crate::account_password_native::NativeProfile,
    deadline: Instant,
}
impl<'a> PrimaryExecutor<'a> {
    pub(crate) fn new(
        profile: &'a crate::account_password_native::NativeProfile,
        deadline: Instant,
    ) -> Self {
        Self { profile, deadline }
    }
}
impl CommandExecutor for PrimaryExecutor<'_> {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(
            program,
            args,
            input,
            Duration::from_secs(25),
            LIMIT,
        )
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        if execution_quarantined()
            || input.len() > INPUT_LIMIT
            || limit != LIMIT
            || timeout.is_zero()
            || timeout > Duration::from_secs(25)
        {
            return Err(unavailable());
        }
        let deadline = self.deadline.min(Instant::now() + timeout);
        let plan = self
            .profile
            .prepare(program, args, deadline)
            .map_err(|_| unavailable())?;
        let mut command =
            crate::auth::password_backend_command(program, args).map_err(|_| unavailable())?;
        crate::openbsd::install_password_child_profile(&mut command, plan)
            .map_err(|_| unavailable())?;
        run(command, input, deadline)
    }
}
