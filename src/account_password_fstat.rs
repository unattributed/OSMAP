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
            _ => Err(Self::Protocol),
        }
    }
}
fn error(failure: Failure) -> CommandExecutionError {
    CommandExecutionError {
        reason: failure.reason().into(),
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
pub(crate) struct Observer {
    state: Mutex<State>,
}
impl Observer {
    pub(crate) fn start(
        startup: &crate::account_password_peer::Startup,
        metadata: &crate::account_password_process::MetadataExecutor,
        end: Instant,
    ) -> Result<Self, CommandExecutionError> {
        if !crate::openbsd::password_native_authority() {
            return Err(error(Failure::Protocol));
        }
        startup
            .recheck(metadata, end)
            .map_err(|_| error(Failure::Protocol))?;
        crate::account_password_native::verify_fstat_worker_graph(end)
            .map_err(|_| error(Failure::Protocol))?;
        let (stream, child_stream) = UnixStream::pair().map_err(|_| error(Failure::Spawn))?;
        let mut command =
            crate::auth::password_fstat_worker_command().map_err(|_| error(Failure::Spawn))?;
        command
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_stream)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let io_end = end
            .checked_sub(RESERVE)
            .filter(|v| *v > Instant::now())
            .ok_or_else(|| error(Failure::Deadline))?;
        let child = command.spawn().map_err(|_| error(Failure::Spawn))?;
        let mut state = State {
            child: Some(child),
            stream,
            sequence: 0,
            failed: false,
        };
        let ready = receive(&mut state.stream, 2, io_end).and_then(|r| {
            if r == [1, 0] {
                Ok(())
            } else {
                Err(Failure::Protocol)
            }
        });
        if let Err(f) = ready {
            state.failed = true;
            let clean = stop_state(&mut state, end);
            return Err(error(if clean.is_ok() { f } else { Failure::Cleanup }));
        }
        if startup.recheck(metadata, end).is_err() {
            let clean = stop_state(&mut state, end);
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
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(remaining(end).map_err(error)?.min(Duration::from_millis(1)))
                }
            }
        };
        if state.failed || state.child.is_none() {
            return Err(error(Failure::Protocol));
        }
        let io_end = end
            .checked_sub(RESERVE)
            .filter(|v| *v > Instant::now())
            .ok_or_else(|| error(Failure::Deadline))?;
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| error(Failure::Protocol))?;
        let seq = state.sequence;
        let result = (|| {
            let raw = request(seq, selection, cap, io_end)?;
            send(&mut state.stream, &raw, io_end)?;
            let raw = receive(&mut state.stream, cap + PREFIX, io_end)?;
            let data = parse_reply(&raw, seq, cap)?;
            remaining(io_end)?;
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
    pub(crate) fn recheck(&self, end: Instant) -> Result<(), CommandExecutionError> {
        let mut state = loop {
            match self.state.try_lock() {
                Ok(s) => break s,
                Err(std::sync::TryLockError::Poisoned(p)) => {
                    let mut state = p.into_inner();
                    state.failed = true;
                    break state;
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(remaining(end).map_err(error)?.min(Duration::from_millis(1)))
                }
            }
        };
        if !state.failed && worker_exited(&state).is_ok_and(|exited| !exited) {
            remaining(end).map_err(error)?;
            return Ok(());
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
    let peer = crate::openbsd::password_kernel_peer(&stream).map_err(|_| Failure::Protocol)?;
    if peer.uid() != 0 || peer.gid() != 0 || peer.pid() == std::process::id() {
        return Err(Failure::Protocol);
    }
    let end = Instant::now() + Duration::from_secs(5);
    let plan = crate::account_password_native::FstatWorkerPlan::capture(end)
        .map_err(|_| Failure::Protocol)?;
    let seal = crate::openbsd::seal_password_fstat_worker(&plan).map_err(|_| Failure::Protocol)?;
    plan.activate(&seal).map_err(|_| Failure::Protocol)?;
    send(&mut stream, &[1, 0], end)?;
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
        plan.recheck(end).map_err(|_| Failure::Protocol)?;
        let args = selection.args();
        let result = crate::account_password_process::run_fstat_in_worker(&seal, &args, end, cap);
        let result = match result {
            Err(e) => Err(match e.reason.as_str() {
                "metadata_child_deadline" => Failure::Deadline,
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
        };
        send(&mut stream, &reply(sequence, result), end)?;
        if crate::account_password_process::execution_quarantined() {
            return Err(Failure::Cleanup);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
