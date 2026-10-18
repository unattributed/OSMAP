use super::*;

#[test]
fn fixed_commands_have_hash_only_isolation_and_no_caller_program() {
    if std::env::current_dir().unwrap() != std::path::Path::new("/") {
        let result = run(
            crate::auth::password_command_shape_fixture().unwrap(),
            b"",
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(result.status_code, 0);
        assert!(result.stdout.contains("1 passed; 0 failed"));
        return;
    }
    use crate::account_password_backend::{HASH_ARGS, HASH_PROGRAM, SQL_ARGS, SQL_PROGRAM};
    let strings = |args: &[&str]| args.iter().map(|s| (*s).into()).collect::<Vec<String>>();
    assert!(fixed_metadata_args(
        "/bin/ps",
        &strings(&["-p", "123", "-o", "args="])
    ));
    assert!(!fixed_metadata_args(
        "/bin/ps",
        &strings(&["-p", "123", "-o", "env="])
    ));
    assert!(!fixed_metadata_args(
        "/bin/ps",
        &strings(&["-p", "0123", "-o", "args="])
    ));
    let hash = crate::auth::password_backend_command(HASH_PROGRAM, &strings(HASH_ARGS)).unwrap();
    let env = hash.get_envs().collect::<Vec<_>>();
    assert!(env.contains(&(
        std::ffi::OsStr::new("CONFIG_FILE"),
        Some(std::ffi::OsStr::new("/dev/null"))
    )));
    assert!(env.contains(&(
        std::ffi::OsStr::new("STATS_WRITER_SOCKET_PATH"),
        Some(std::ffi::OsStr::new(""))
    )));
    assert!(fixed_metadata_args(
        "/sbin/pfctl",
        &strings(&["-i", "lo0", "-v", "-s", "Interfaces"])
    ));
    assert!(!fixed_metadata_args(
        "/sbin/pfctl",
        &strings(&["-i", "em0", "-v", "-s", "Interfaces"])
    ));
    assert!(!fixed_metadata_args(
        "/sbin/pfctl",
        &strings(&["-i", "lo0", "-vv", "-s", "Interfaces"])
    ));
    let filtered = crate::account_password_topology::loopback_filtered;
    assert!(filtered("lo0\n").is_ok());
    assert!(filtered("lo0 (skip)\n").is_err());
    assert!(filtered("lo0\nem0\n").is_err());
    let sql = crate::auth::password_backend_command(SQL_PROGRAM, &strings(SQL_ARGS)).unwrap();
    assert!(!sql.get_envs().any(|(name, _)| name == "CONFIG_FILE"));
    assert!(crate::auth::password_backend_command("/usr/bin/id", &[]).is_err());
    assert!(crate::auth::password_backend_command(HASH_PROGRAM, &["pw".into()]).is_err());
    assert!(fixed_metadata_args(
        "/sbin/pfctl",
        &strings(&["-a", "osmap/account-submission", "-sr"])
    ));
    assert!(!fixed_metadata_args(
        "/sbin/pfctl",
        &strings(&["-a", "*", "-sr"])
    ));
    assert!(!fixed_metadata_args(
        "/sbin/pfctl",
        &strings(&["-a", "osmap/account-submission", "-f", "/tmp/rules"])
    ));
}

#[test]
fn actual_duplex_retains_natural_exit_status_and_bounds_owned_cleanup() {
    let result = run(
        crate::auth::password_process_fixture_command("result"),
        b"",
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(result.status_code, 7);
    assert_eq!(result.stdout, "fixed-result\n");
    assert_eq!(result.stderr, "fixed-error\n");
    let early = run(
        crate::auth::password_process_fixture_command("early_eof"),
        b"",
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(early.status_code, 7);
    let started = Instant::now();
    assert!(run(
        crate::auth::password_process_fixture_command("blocked"),
        b"",
        started + Duration::from_millis(300)
    )
    .is_err());
    assert!(started.elapsed() < Duration::from_millis(700));
    // Deadline refusal with measured group cleanup does not latch uncertainty.
    assert!(!UNCERTAIN.load(Ordering::SeqCst));
}

#[test]
fn sealed_recheck_diagnostic_errno_classes_are_closed_and_payload_free() {
    for (errno, class) in [
        (libc::EACCES, "denied"),
        (libc::EINVAL, "invalid"),
        (libc::ESRCH, "absent"),
        (libc::EBUSY, "busy"),
        (libc::ENOMEM, "capacity"),
        (libc::EIO, "unknown"),
    ] {
        for operation in ["ps_row", "ps_argv", "builder", "spawn", "child_io"] {
            let tag = metadata_errno_tag(operation, &std::io::Error::from_raw_os_error(errno));
            assert!(tag.ends_with(class));
            assert_eq!(metadata_failure_tag(tag), Some(tag));
            assert_eq!(
                metadata_failure(tag, false).reason,
                "password utility unavailable"
            );
            assert_eq!(metadata_failure(tag, true).reason, tag);
        }
    }
    for bad in [
        "metadata_ps_row_denied password=secret",
        "/private/path",
        "metadata_ps_row_123",
        "metadata_ps_row_denied\n",
    ] {
        assert!(metadata_failure_tag(bad).is_none());
    }
}
