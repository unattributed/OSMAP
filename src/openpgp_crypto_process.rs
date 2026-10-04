//! Nonblocking duplex worker pipes share a single deadline and bounded buffers.
use crate::openpgp_crypto::{Error, Operation, Outcome, MAX_CONTENT, MAX_METADATA};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};
static CLEANUP_UNCONFIRMED: AtomicBool = AtomicBool::new(false);
static UNREAPED: Mutex<Vec<Child>> = Mutex::new(Vec::new());

pub(crate) fn execute(
    worker: &Path,
    engine: &Path,
    home: &Path,
    operation: &Operation,
    deadline: Instant,
) -> Result<Outcome, Error> {
    let frame = operation.worker_frame()?;
    let command = crate::auth::crypto_worker_command(worker, engine, home);
    let (bytes, success) = run(command, &frame, deadline)?;
    Outcome::worker_result(operation, &bytes, success)
}
fn run(command: Command, input: &[u8], deadline: Instant) -> Result<(Vec<u8>, bool), Error> {
    run_bounded(command, input, deadline, MAX_CONTENT + MAX_METADATA + 8)
}
pub(crate) fn run_public_admin(
    command: Command,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_METADATA {
        return Err(Error::Limit);
    }
    let (output, success) = run_bounded(command, input, deadline, MAX_METADATA)?;
    if !success {
        return Err(Error::Unavailable);
    }
    Ok(output)
}
/// Separate primary-auth profile: Dovecot may delay a failed credential by15s.
/// Existing crypto/admin callers retain their original ten-second cap.
pub(crate) fn run_account_admission(
    command: Command,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    if input.len() > 4096 {
        return Err(Error::Limit);
    }
    let (output, success) = run_limited(
        command,
        input,
        deadline,
        4096,
        Duration::from_secs(30),
        false,
    )?;
    if !success {
        return Err(Error::Unavailable);
    }
    Ok(output)
}
/// Mutation-only whole-worker profile; production bootstrap remains disabled.
/// Existing authentication and crypto/admin profiles retain their prior limits.
#[allow(dead_code)] // Not wired until fixed native mutation bootstrap is qualified.
pub(crate) fn run_account_mutation(
    command: Command,
    input: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    if input.len() > 12288 {
        return Err(Error::Limit);
    }
    let (output, success) = run_limited(
        command,
        input,
        deadline,
        4096,
        Duration::from_secs(60),
        true,
    )?;
    if !success {
        return Err(Error::Unavailable);
    }
    Ok(output)
}

fn cleanup_owned_group_before(child: &mut Child, deadline: Instant) -> Result<(), Error> {
    cleanup_owned_group_with(
        child,
        deadline,
        crate::openbsd::kill_process_group,
        crate::openbsd::process_group_exists,
    )
}
fn cleanup_owned_group_with(
    child: &mut Child,
    deadline: Instant,
    kill: impl Fn(u32) -> std::io::Result<()>,
    exists: impl Fn(u32) -> std::io::Result<bool>,
) -> Result<(), Error> {
    let pid = child.id();
    match kill(pid) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
        Err(_) => return Err(Error::Unavailable),
    }
    while Instant::now() < deadline {
        let reaped = child.try_wait().map_err(|_| Error::Unavailable)?.is_some();
        let absent = !exists(pid).map_err(|_| Error::Unavailable)?;
        if reaped && absent && Instant::now() < deadline {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(Duration::from_millis(2)));
    }
    Err(Error::Unavailable)
}

fn run_bounded(
    command: Command,
    input: &[u8],
    deadline: Instant,
    output_limit: usize,
) -> Result<(Vec<u8>, bool), Error> {
    run_limited(
        command,
        input,
        deadline,
        output_limit,
        Duration::from_secs(10),
        false,
    )
}
fn run_limited(
    mut command: Command,
    input: &[u8],
    deadline: Instant,
    output_limit: usize,
    operation_limit: Duration,
    strict_group: bool,
) -> Result<(Vec<u8>, bool), Error> {
    if CLEANUP_UNCONFIRMED.load(Ordering::SeqCst) {
        return Err(Error::Unavailable);
    }
    let deadline = deadline.min(Instant::now() + operation_limit);
    if deadline.saturating_duration_since(Instant::now()) <= Duration::from_millis(100) {
        return Err(Error::Expired);
    }
    let command_deadline = deadline - Duration::from_millis(100);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| Error::Unavailable)?;
    let pid = child.id();
    let result = (|| {
        let input_pipe = child.stdin.take().ok_or(Error::Unavailable)?;
        let mut stdout = child.stdout.take().ok_or(Error::Unavailable)?;
        let mut stderr = child.stderr.take().ok_or(Error::Unavailable)?;
        for fd in [
            input_pipe.as_raw_fd(),
            stdout.as_raw_fd(),
            stderr.as_raw_fd(),
        ] {
            crate::openbsd::set_descriptor_nonblocking(fd).map_err(|_| Error::Unavailable)?;
        }
        let mut stdin = Some(input_pipe);
        if input.is_empty() {
            stdin.take();
        }
        let mut output = Vec::new();
        let mut discarded = 0usize;
        let mut written = 0usize;
        let mut out_done = false;
        let mut err_done = false;
        let mut status = None;
        loop {
            if Instant::now() >= command_deadline {
                return Err(Error::Expired);
            }
            if let Some(pipe) = stdin.as_mut() {
                match pipe.write(&input[written..input.len().min(written + 65536)]) {
                    Ok(0) => return Err(Error::Unavailable),
                    Ok(n) => written += n,
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    Err(_) => return Err(Error::Unavailable),
                }
                if written == input.len() {
                    stdin.take();
                }
            }
            if !out_done {
                out_done = drain(&mut stdout, &mut output, output_limit, false)?;
            }
            if !err_done {
                let mut bytes = Vec::new();
                err_done = drain(
                    &mut stderr,
                    &mut bytes,
                    8192usize.saturating_sub(discarded),
                    true,
                )?;
                discarded += bytes.len();
            }
            if strict_group && out_done && err_done {
                // Do not reap/release the leader PID before the owned group
                // kill. The true exit status is reconciled after strict cleanup.
                return if written == input.len() {
                    Ok((output, true))
                } else {
                    Err(Error::Unavailable)
                };
            }
            if !strict_group && status.is_none() {
                status = child.try_wait().map_err(|_| Error::Unavailable)?;
            }
            if let Some(status) = status {
                if !strict_group {
                    let _ = crate::openbsd::kill_process_group(pid);
                }
                if out_done && err_done {
                    return if written == input.len() {
                        Ok((output, status.success()))
                    } else {
                        Err(Error::Unavailable)
                    };
                }
            }
            crate::openbsd::wait_worker_pipes(
                stdin.as_ref().map(AsRawFd::as_raw_fd),
                (!out_done).then(|| stdout.as_raw_fd()),
                (!err_done).then(|| stderr.as_raw_fd()),
                command_deadline,
            )
            .map_err(|error| {
                if error.kind() == ErrorKind::TimedOut {
                    Error::Expired
                } else {
                    Error::Unavailable
                }
            })?;
        }
    })();
    if strict_group {
        if cleanup_owned_group_before(&mut child, deadline).is_ok() {
            let confirmed_status = child.try_wait().ok().flatten();
            if let Some(status) = confirmed_status {
                if Instant::now() < deadline {
                    return result.map(|(output, _)| (output, status.success()));
                }
            }
        }
        CLEANUP_UNCONFIRMED.store(true, Ordering::SeqCst);
        if let Ok(mut children) = UNREAPED.try_lock() {
            children.push(child);
        }
        return Err(Error::Unavailable);
    }
    let _ = crate::openbsd::kill_process_group(pid);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return result,
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => break,
        }
    }
    CLEANUP_UNCONFIRMED.store(true, Ordering::SeqCst);
    if let Ok(mut children) = UNREAPED.lock() {
        children.push(child);
    }
    Err(Error::Unavailable)
}
fn drain(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    max: usize,
    discard: bool,
) -> Result<bool, Error> {
    let mut buffer = [0u8; 4096];
    for _ in 0..17 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if output.len().saturating_add(n) > max {
                    return Err(Error::Limit);
                }
                if discard {
                    output.resize(output.len() + n, 0);
                } else {
                    output.extend_from_slice(&buffer[..n]);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(false)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::crypto_fixture_command as fixture;
    #[test]
    #[ignore = "child process fixture; invoked by duplex process test"]
    fn worker_fixture() {
        match std::env::var("OSMAP_CRYPTO_PROCESS_FIXTURE")
            .unwrap()
            .as_str()
        {
            "blocked_stdin" => std::thread::sleep(Duration::from_secs(5)),
            "account_auth_delay" => {
                std::thread::sleep(Duration::from_secs(11));
                std::io::stdout()
                    .write_all(b"bounded-account-auth-delay")
                    .unwrap();
            }
            "duplex" => {
                std::io::stdout().write_all(&vec![1; 256 * 1024]).unwrap();
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input).unwrap();
                assert_eq!(input.len(), 256 * 1024);
            }
            "descendant" => {
                let _child = fixture("blocked_stdin").spawn().unwrap();
                std::io::stdout().write_all(b"complete").unwrap();
                std::io::stdout().flush().unwrap();
                std::process::exit(0);
            }
            "stdout_limit" => std::io::stdout()
                .write_all(&vec![0; MAX_CONTENT + MAX_METADATA + 9])
                .unwrap(),
            "stderr_limit" => std::io::stderr().write_all(&[0; 8193]).unwrap(),
            "failure" => std::process::exit(1),
            "success" => (),
            _ => panic!("unknown fixture"),
        }
    }

    #[test]
    fn account_auth_delay_profile_preserves_crypto_admin_ten_second_cap() {
        // Synthetic current-executable children only; no native authentication,
        // credentials, cryptography or provider operations are performed.
        let ordinary = std::thread::spawn(|| {
            run_public_admin(
                fixture("account_auth_delay"),
                b"",
                Instant::now() + Duration::from_secs(14),
            )
        });
        let account = std::thread::spawn(|| {
            run_account_admission(
                fixture("account_auth_delay"),
                b"",
                Instant::now() + Duration::from_secs(14),
            )
        });
        assert!(ordinary.join().unwrap().is_err());
        let output = account.join().unwrap().unwrap();
        assert!(output
            .windows(b"bounded-account-auth-delay".len())
            .any(|w| w == b"bounded-account-auth-delay"));
    }
    #[test]
    fn duplex_stdin_deadlines_limits_and_descendant_cleanup() {
        let start = Instant::now();
        assert!(matches!(
            run(
                fixture("blocked_stdin"),
                &vec![1; 256 * 1024],
                Instant::now() + Duration::from_millis(250)
            ),
            Err(Error::Expired)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        let (output, success) = run(
            fixture("duplex"),
            &vec![1; 256 * 1024],
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert!(success && output.len() >= 256 * 1024);
        let start = Instant::now();
        let (output, success) = run(
            fixture("descendant"),
            &[1],
            Instant::now() + Duration::from_millis(500),
        )
        .unwrap();
        assert!(success && output.windows(8).any(|s| s == b"complete"));
        assert!(start.elapsed() < Duration::from_secs(1));
        let limited = run(
            fixture("stdout_limit"),
            &[1],
            // OpenBSD pipe capacity is smaller than Linux's; this fixture must
            // reach the actual 16 MiB limit within the production deadline.
            Instant::now() + Duration::from_secs(10),
        );
        assert!(
            matches!(limited, Err(Error::Limit)),
            "stdout limit error: {:?}",
            limited.as_ref().err()
        );
        assert!(matches!(
            run(
                fixture("stderr_limit"),
                &[1],
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Limit)
        ));
        assert!(
            !run(
                fixture("failure"),
                &[1],
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
            .1
        );
        // Failure to confirm reaping disables future admission in this process.
        let child = fixture("success")
            .process_group(0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        CLEANUP_UNCONFIRMED.store(true, Ordering::SeqCst);
        UNREAPED.lock().unwrap().push(child);
        assert!(matches!(
            run(
                fixture("success"),
                &[1],
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Unavailable)
        ));
        for mut child in UNREAPED.lock().unwrap().drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
        CLEANUP_UNCONFIRMED.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[path = "account_mutation_supervisor_tests.rs"]
mod mutation_supervisor_tests;
