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
        || OWNED_UNREAPED
            .lock()
            .map_or(true, |children| !children.is_empty())
}

pub(crate) struct MetadataExecutor;
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
                    && args[3] == crate::account_password_peer::PS_FIELDS)
        }
        "/usr/bin/fstat" => args.len() == 3 && args[0] == "-n" && args[1] == "-p" && pid(&args[2]),
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
        if program == crate::account_password_mail::PROGRAM {
            // Administrative reads retain the fixed unprivileged control
            // identity/loader/socket profile; metadata never gains root WHO.
            let profile = crate::account_password_native::NativeProfile::fixed(
                crate::account_password_native::Role::Control,
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
            let command =
                crate::auth::password_metadata_command(program, args).map_err(|_| unavailable())?;
            run_with_cap(command, b"", deadline, cap)
        }
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

fn drain(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    cap: usize,
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
            _ => return Err(unavailable()),
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
    mut command: Command,
    input: &[u8],
    deadline: Instant,
    cap: usize,
) -> Result<CommandExecution, CommandExecutionError> {
    if !matches!(cap, 4096 | 16384 | 65536)
        || execution_quarantined()
        || deadline.saturating_duration_since(Instant::now()) <= RESERVE
    {
        return Err(unavailable());
    }
    let io_deadline = deadline - RESERVE;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    #[cfg(test)]
    native_trace::stage(5);
    let mut child = command.spawn().map_err(|_error| {
        #[cfg(test)]
        native_trace::errno(&_error);
        unavailable()
    })?;
    #[cfg(test)]
    native_trace::stage(6);
    // Keep the born leader unreaped until signalling its exclusively owned
    // group. No historical/reusable PID is used as cleanup authority.
    let pid = child.id();
    let result = (|| {
        let mut input_pipe = Some(child.stdin.take().ok_or_else(unavailable)?);
        let mut output = child.stdout.take().ok_or_else(unavailable)?;
        let mut error = child.stderr.take().ok_or_else(unavailable)?;
        for fd in [
            input_pipe.as_ref().ok_or_else(unavailable)?.as_raw_fd(),
            output.as_raw_fd(),
            error.as_raw_fd(),
        ] {
            crate::openbsd::set_descriptor_nonblocking(fd).map_err(|_| unavailable())?;
        }
        if input.is_empty() {
            input_pipe.take();
        }
        let mut written = 0;
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if Instant::now() >= io_deadline {
                return Err(unavailable());
            }
            if let Some(pipe) = input_pipe.as_mut() {
                match pipe.write(&input[written..]) {
                    Ok(0) => return Err(unavailable()),
                    Ok(n) => written += n,
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    _ => return Err(unavailable()),
                }
                if written == input.len() {
                    input_pipe.take();
                }
            }
            if !out_eof {
                out_eof = drain(&mut output, &mut stdout, cap)?;
            }
            if !err_eof {
                err_eof = drain(&mut error, &mut stderr, cap)?;
            }
            if out_eof
                && err_eof
                && written == input.len()
                && crate::openbsd::owned_child_exited_without_reap(pid)
                    .map_err(|_| unavailable())?
            {
                return Ok((stdout, stderr));
            }
            crate::openbsd::wait_worker_pipes(
                input_pipe.as_ref().map(AsRawFd::as_raw_fd),
                (!out_eof).then(|| output.as_raw_fd()),
                (!err_eof).then(|| error.as_raw_fd()),
                io_deadline,
            )
            .map_err(|_| unavailable())?;
        }
    })();
    // Kill while this unreaped Popen leader still leases the PGID; then reap
    // and prove absence. Descendants holding pipes cannot prolong a reader join.
    #[cfg(test)]
    native_trace::stage(7);
    let signal = crate::openbsd::kill_process_group(pid);
    let signal_ok = signal.is_ok()
        || signal
            .err()
            .is_some_and(|e| e.raw_os_error() == Some(libc::ESRCH));
    while signal_ok && Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            let gone = crate::openbsd::process_group_exists(pid).is_ok_and(|exists| !exists);
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
                    stdout: String::from_utf8(stdout).map_err(|_| unavailable())?,
                    stderr: String::from_utf8(stderr).map_err(|_| unavailable())?,
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
    Err(unavailable())
}

#[cfg(test)]
#[path = "account_password_process_tests.rs"]
mod tests;
