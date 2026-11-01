//! One bounded process group; nonblocking drains share the command deadline.
use crate::openpgp_inventory::{Error, Inventory};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub(crate) fn execute(worker: &Path, home: &Path, deadline: Instant) -> Result<Inventory, Error> {
    let command = crate::auth::public_inventory_command(worker, home);
    Inventory::parse(&run(command, deadline)?)
}
fn run(command: Command, deadline: Instant) -> Result<Vec<u8>, Error> {
    // The existing public-admin profile has the same ten-second cap and64KiB
    // output bound. Reuse its owned cleanup instead of a second supervisor.
    inventory_result(crate::openpgp_crypto_process::run_public_admin(
        command, b"", deadline,
    ))
}
fn inventory_result(
    result: Result<Vec<u8>, crate::openpgp_crypto::Error>,
) -> Result<Vec<u8>, Error> {
    result.map_err(|error| match error {
        crate::openpgp_crypto::Error::Limit => Error::Limit,
        crate::openpgp_crypto::Error::Expired => Error::Expired,
        _ => Error::Unavailable,
    })
}
#[cfg(test)]
fn run_with_group_ops(
    command: Command,
    deadline: Instant,
    kill: &dyn Fn(u32) -> std::io::Result<()>,
    exists: &dyn Fn(u32) -> std::io::Result<bool>,
) -> Result<Vec<u8>, Error> {
    inventory_result(
        crate::openpgp_crypto_process::run_inventory_fixture_with_group_ops(
            command, deadline, kill, exists,
        ),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::inventory_fixture_command as fixture;
    use crate::openpgp_inventory::MAX_METADATA;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn inventory_signals_only_while_the_direct_child_still_leases_its_group() {
        let unowned_signals = AtomicUsize::new(0);
        let signals = AtomicUsize::new(0);
        let kill = |pid| {
            signals.fetch_add(1, Ordering::SeqCst);
            // Refuse any real signal after direct-child ownership is gone.
            if let Err(error) = crate::openbsd::owned_child_exited_without_reap(pid) {
                unowned_signals.fetch_add(1, Ordering::SeqCst);
                return Err(error);
            }
            crate::openbsd::kill_process_group(pid)
        };
        let result = run_with_group_ops(
            fixture("success"),
            Instant::now() + Duration::from_secs(2),
            &kill,
            &crate::openbsd::process_group_exists,
        );
        assert!(result.is_ok(), "known zero-exit inventory fixture failed");
        assert!(signals.load(Ordering::SeqCst) > 0);
        assert_eq!(
            unowned_signals.load(Ordering::SeqCst),
            0,
            "inventory cleanup released its leader identity before signalling"
        );
    }

    #[test]
    #[ignore = "child process fixture; invoked by bounded process test"]
    fn worker_fixture() {
        match std::env::var("OSMAP_INVENTORY_PROCESS_FIXTURE")
            .unwrap()
            .as_str()
        {
            "runtime_service_hold" => {
                crate::openpgp_inventory_runtime::tests::serve_hold_child();
            }
            "descendant_disposition" => descendant_disposition(),
            "absence_uncertain" => uncertain_group_absence(),
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
        let output = run(
            fixture("descendant_disposition"),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(output
            .windows(b"DESCENDANT_ABSENCE=".len())
            .any(|bytes| bytes == b"DESCENDANT_ABSENCE="));
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
    }

    #[test]
    fn uncertain_group_absence_refuses_output_and_next_inventory_worker() {
        let output = run(
            fixture("absence_uncertain"),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(output
            .windows(b"UNCONFIRMED_CLEANUP=REFUSED".len())
            .any(|bytes| bytes == b"UNCONFIRMED_CLEANUP=REFUSED"));
    }

    fn uncertain_group_absence() {
        let pid = AtomicU32::new(0);
        let exists = |group| {
            pid.store(group, Ordering::SeqCst);
            Ok(true)
        };
        assert!(matches!(
            run_with_group_ops(
                fixture("success"),
                Instant::now() + Duration::from_millis(200),
                &crate::openbsd::kill_process_group,
                &exists,
            ),
            Err(Error::Unavailable)
        ));
        let pid = pid.load(Ordering::SeqCst);
        assert!(pid > 1);
        assert!(!crate::openbsd::process_group_exists(pid).unwrap());
        assert!(matches!(
            run(fixture("success"), Instant::now() + Duration::from_secs(1)),
            Err(Error::Unavailable)
        ));
        println!("UNCONFIRMED_CLEANUP=REFUSED");
    }

    fn descendant_disposition() {
        let pid = AtomicU32::new(0);
        let present = AtomicBool::new(false);
        let exists = |group| {
            pid.store(group, Ordering::SeqCst);
            let value = crate::openbsd::process_group_exists(group)?;
            if value {
                present.store(true, Ordering::SeqCst);
            }
            Ok(value)
        };
        let began = Instant::now();
        let result = run_with_group_ops(
            fixture("descendant"),
            began + Duration::from_millis(500),
            &crate::openbsd::kill_process_group,
            &exists,
        );
        assert!(began.elapsed() < Duration::from_secs(1));
        let pid = pid.load(Ordering::SeqCst);
        assert!(pid > 1);
        match result {
            Ok(output) => {
                assert!(output.windows(8).any(|bytes| bytes == b"complete"));
                assert!(!crate::openbsd::process_group_exists(pid).unwrap());
                println!("DESCENDANT_ABSENCE=CONFIRMED");
            }
            Err(Error::Unavailable) => {
                assert!(present.load(Ordering::SeqCst));
                assert!(matches!(
                    run(fixture("success"), Instant::now() + Duration::from_secs(1)),
                    Err(Error::Unavailable)
                ));
                println!("DESCENDANT_ABSENCE=UNCONFIRMED_FAIL_CLOSED");
                #[cfg(target_os = "openbsd")]
                panic!("native inventory qualification requires descendant group absence");
            }
            _ => panic!("unexpected inventory descendant disposition"),
        }
    }
}
