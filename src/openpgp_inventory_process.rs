//! One bounded process group; nonblocking drains share the command deadline.
use crate::openpgp_inventory::{Error, Inventory, MAX_METADATA};
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
static CLEANUP_UNCONFIRMED: AtomicBool = AtomicBool::new(false);
static UNREAPED: Mutex<Vec<Child>> = Mutex::new(Vec::new());
use std::time::{Duration, Instant};

pub(crate) fn execute(worker: &Path, home: &Path, deadline: Instant) -> Result<Inventory, Error> {
    let command = crate::auth::public_inventory_command(worker, home);
    Inventory::parse(&run(command, deadline)?)
}
fn run(mut command: Command, deadline: Instant) -> Result<Vec<u8>, Error> {
    if CLEANUP_UNCONFIRMED.load(Ordering::SeqCst) {
        return Err(Error::Unavailable);
    }
    let deadline = deadline.min(Instant::now() + Duration::from_secs(10));
    if deadline.saturating_duration_since(Instant::now()) <= Duration::from_millis(100) {
        return Err(Error::Expired);
    }
    let command_deadline = deadline - Duration::from_millis(100);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| Error::Unavailable)?;
    let pid = child.id();
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or(Error::Unavailable)?;
        let mut stderr = child.stderr.take().ok_or(Error::Unavailable)?;
        crate::openbsd::set_descriptor_nonblocking(stdout.as_raw_fd())
            .map_err(|_| Error::Unavailable)?;
        crate::openbsd::set_descriptor_nonblocking(stderr.as_raw_fd())
            .map_err(|_| Error::Unavailable)?;
        let mut output = Vec::new();
        let mut discarded = 0usize;
        let mut out_done = false;
        let mut err_done = false;
        let mut status = None;
        loop {
            if Instant::now() >= command_deadline {
                return Err(Error::Expired);
            }
            if !out_done {
                out_done = drain(&mut stdout, &mut output, MAX_METADATA, false)?;
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
            if status.is_none() {
                status = child.try_wait().map_err(|_| Error::Unavailable)?;
            }
            if let Some(status) = status {
                // Also stop descendants retaining stdout/stderr after the leader exits.
                let _ = crate::openbsd::kill_process_group(pid);
                if out_done && err_done {
                    return if status.success() {
                        Ok(output)
                    } else {
                        Err(Error::Unavailable)
                    };
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    let _ = crate::openbsd::kill_process_group(pid);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return result,
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => break,
        }
    }
    quarantine(child);
    Err(Error::Unavailable)
}
fn quarantine(child: Child) {
    // A group kill does not prove reaping. Stop all future worker admission in
    // this service process and retain the child handle for operator recovery.
    CLEANUP_UNCONFIRMED.store(true, Ordering::SeqCst);
    if let Ok(mut pending) = UNREAPED.lock() {
        pending.push(child);
    }
}
fn drain(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    max: usize,
    discard: bool,
) -> Result<bool, Error> {
    let mut buffer = [0u8; 4096];
    // Bound each turn so an endless writer cannot prevent deadline checks.
    for _ in 0..17 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if output.len().saturating_add(n) > max {
                    return Err(Error::Limit);
                }
                // Preserve only a byte count for stderr, never diagnostic contents.
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
    use crate::auth::inventory_fixture_command as fixture;
    use std::io::Write;

    #[test]
    #[ignore = "child process fixture; invoked by bounded process test"]
    fn worker_fixture() {
        match std::env::var("OSMAP_INVENTORY_PROCESS_FIXTURE")
            .unwrap()
            .as_str()
        {
            "sleep" => std::thread::sleep(Duration::from_secs(5)),
            "descendant" => {
                // Inherit this test child's process group and output descriptors.
                let _child = fixture("sleep").spawn().unwrap();
                print!("complete");
                std::io::stdout().flush().unwrap();
                std::process::exit(0);
            }
            "stdout_limit" => std::io::stdout()
                .write_all(&vec![0; MAX_METADATA + 1])
                .unwrap(),
            "stderr_limit" => std::io::stderr().write_all(&[0; 8193]).unwrap(),
            "failure" => std::process::exit(1),
            "success" => (),
            _ => panic!("unknown test fixture"),
        }
    }
    #[test]
    fn bounds_failures_and_descendant_pipes_are_bounded() {
        let start = Instant::now();
        assert!(matches!(
            run(
                fixture("sleep"),
                Instant::now() + Duration::from_millis(250)
            ),
            Err(Error::Expired)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        let start = Instant::now();
        assert!(String::from_utf8(
            run(
                fixture("descendant"),
                Instant::now() + Duration::from_millis(500)
            )
            .unwrap()
        )
        .unwrap()
        .contains("complete"));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            run(
                fixture("stdout_limit"),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Limit)
        ));
        assert!(matches!(
            run(
                fixture("stderr_limit"),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Limit)
        ));
        assert!(run(fixture("failure"), Instant::now() + Duration::from_secs(1)).is_err());
        // Inject an uncertain-reap disposition: no subsequent command can run.
        let child = fixture("success")
            .process_group(0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        quarantine(child);
        assert!(run(fixture("success"), Instant::now() + Duration::from_secs(1)).is_err());
        assert!(CLEANUP_UNCONFIRMED.load(Ordering::SeqCst));
        for mut child in UNREAPED.lock().unwrap().drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
        CLEANUP_UNCONFIRMED.store(false, Ordering::SeqCst); // Test-only cleanup.
    }
}
