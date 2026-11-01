use super::*;
use std::sync::atomic::{AtomicU32, AtomicUsize};

#[test]
fn crypto_signals_only_while_the_direct_child_still_leases_its_group() {
    let unowned_signals = AtomicUsize::new(0);
    let signals = AtomicUsize::new(0);
    let kill = |pid| {
        signals.fetch_add(1, Ordering::SeqCst);
        // Refuse the unsafe signal in this discriminator; never target a
        // historical PID after waitid says direct-child ownership is gone.
        if let Err(error) = crate::openbsd::owned_child_exited_without_reap(pid) {
            unowned_signals.fetch_add(1, Ordering::SeqCst);
            return Err(error);
        }
        crate::openbsd::kill_process_group(pid)
    };
    let result = run_limited_with_group_ops(
        crate::auth::crypto_fixture_command("success"),
        b"",
        Instant::now() + Duration::from_secs(2),
        RunProfile {
            output_limit: 4096,
            operation_limit: Duration::from_secs(10),
            strict_group: false,
        },
        GroupOps {
            kill: &kill,
            exists: &crate::openbsd::process_group_exists,
        },
        || Ok(false),
    );
    assert!(result.is_ok(), "the known zero-exit fixture must complete");
    assert!(signals.load(Ordering::SeqCst) > 0);
    assert_eq!(
        unowned_signals.load(Ordering::SeqCst),
        0,
        "crypto cleanup released its leader identity before signalling"
    );
}

#[test]
fn an_already_reaped_child_is_never_group_signal_authority() {
    let mut child = crate::auth::crypto_fixture_command("success")
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(child.try_wait().unwrap().is_some());
    let signals = AtomicUsize::new(0);
    assert!(cleanup_owned_group_with(
        &mut child,
        Instant::now() + Duration::from_millis(100),
        |_| {
            signals.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_| Ok(false)
    )
    .is_err());
    assert_eq!(signals.load(Ordering::SeqCst), 0);
}

pub(super) fn assert_isolated_descendant_cleanup() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "openpgp_crypto_process::lifecycle_tests::descendant_disposition_fixture",
        "--ignored",
        "--nocapture",
    ]);
    let (output, success) = run(command, b"", Instant::now() + Duration::from_secs(3)).unwrap();
    assert!(success, "isolated descendant disposition checks failed");
    if output
        .windows(b"DESCENDANT_ABSENCE=CONFIRMED".len())
        .any(|bytes| bytes == b"DESCENDANT_ABSENCE=CONFIRMED")
    {
        println!("DESCENDANT_ABSENCE=CONFIRMED");
    } else {
        assert!(output
            .windows(b"DESCENDANT_ABSENCE=UNCONFIRMED_FAIL_CLOSED".len())
            .any(|bytes| bytes == b"DESCENDANT_ABSENCE=UNCONFIRMED_FAIL_CLOSED"));
        println!("DESCENDANT_ABSENCE=UNCONFIRMED_FAIL_CLOSED");
    }
}

#[test]
#[ignore = "isolated current-executable descendant cleanup discriminator"]
fn descendant_disposition_fixture() {
    let group_id = AtomicU32::new(0);
    let remaining_group = AtomicBool::new(false);
    let exists = |pid| {
        group_id.store(pid, Ordering::SeqCst);
        let present = crate::openbsd::process_group_exists(pid)?;
        if present {
            remaining_group.store(true, Ordering::SeqCst);
        }
        Ok(present)
    };
    let began = Instant::now();
    let result = run_limited_with_group_ops(
        crate::auth::crypto_fixture_command("descendant"),
        &[1],
        began + Duration::from_millis(500),
        RunProfile {
            output_limit: 4096,
            operation_limit: Duration::from_secs(10),
            strict_group: false,
        },
        GroupOps {
            kill: &crate::openbsd::kill_process_group,
            exists: &exists,
        },
        || Ok(false),
    );
    assert!(began.elapsed() < Duration::from_secs(1));
    match result {
        Ok((output, success)) => {
            assert!(success && output.windows(8).any(|bytes| bytes == b"complete"));
            assert!(!CLEANUP_UNCONFIRMED.load(Ordering::SeqCst));
            assert!(
                !crate::openbsd::process_group_exists(group_id.load(Ordering::SeqCst)).unwrap()
            );
            println!("DESCENDANT_ABSENCE=CONFIRMED");
        }
        Err(Error::Unavailable) => {
            // A killed orphan can remain a kernel-visible zombie where init
            // does not reap promptly. That is NOT an absence or success proof.
            assert!(remaining_group.load(Ordering::SeqCst));
            assert!(CLEANUP_UNCONFIRMED.load(Ordering::SeqCst));
            assert!(matches!(
                run(
                    crate::auth::crypto_fixture_command("success"),
                    b"",
                    Instant::now() + Duration::from_secs(1)
                ),
                Err(Error::Unavailable)
            ));
            println!("DESCENDANT_ABSENCE=UNCONFIRMED_FAIL_CLOSED");
            #[cfg(target_os = "openbsd")]
            panic!("native qualification requires actual descendant group absence");
        }
        _ => panic!("unexpected descendant operation result"),
    }
}
