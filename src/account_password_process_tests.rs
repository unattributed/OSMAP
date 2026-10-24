use super::*;

#[test]
fn fixed_commands_have_hash_only_isolation_and_no_caller_program() {
    let ps_args = ["-p", "123", "-o", "args="].map(str::to_owned).to_vec();
    if std::env::current_dir().unwrap() != std::path::Path::new("/") {
        assert_eq!(
            metadata_command("/bin/ps", &ps_args).unwrap_err().reason,
            "metadata_builder_denied"
        );
        assert_eq!(
            crate::auth::password_metadata_command("/bin/ps", &ps_args)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
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
    let metadata = metadata_command("/bin/ps", &ps_args).unwrap();
    assert_eq!(metadata.get_program(), std::ffi::OsStr::new("/bin/ps"));
    assert_eq!(
        metadata.get_args().collect::<Vec<_>>(),
        ps_args.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>()
    );
    assert!(metadata.get_current_dir().is_none());
    assert_eq!(
        metadata_command("/bin/ps", &strings(&["-p", "123", "-o", "env="]))
            .unwrap_err()
            .reason,
        "metadata_builder_denied"
    );
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
    let denied = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "private reader token=0123456789abcdef0123456789abcdef",
    );
    for (operation, expected) in [
        ("ps_row", "metadata_ps_row_denied"),
        ("ps_argv", "metadata_ps_argv_denied"),
        ("builder", "metadata_builder_denied"),
        ("spawn", "metadata_spawn_denied"),
        ("child_io", "metadata_child_io_denied"),
    ] {
        assert_eq!(metadata_errno_tag(operation, &denied), expected);
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

#[test]
fn metadata_actual_runner_preserves_echo_and_fixed_spawn_denial() {
    let output = run_with_cap_labeled(
        crate::auth::password_fstat_echo_fixture(),
        b"public-metadata-fixture\n",
        Instant::now() + Duration::from_secs(2),
        4096,
        true,
    )
    .unwrap();
    assert_eq!(output.status_code, 0);
    assert_eq!(output.stdout, "public-metadata-fixture\n");
    assert!(output.stderr.is_empty());

    for (labeled, expected) in [
        (true, "metadata_spawn_denied"),
        (false, "password utility unavailable"),
    ] {
        let error = run_with_cap_labeled(
            crate::auth::password_metadata_spawn_denied_fixture(),
            b"",
            Instant::now() + Duration::from_secs(2),
            4096,
            labeled,
        )
        .unwrap_err();
        assert_eq!(error.reason, expected);
    }
    assert!(!execution_quarantined());
}

#[test]
fn metadata_actual_drain_denial_excludes_private_error_payload() {
    struct DeniedReader;
    impl std::io::Read for DeniedReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private reader token=0123456789abcdef0123456789abcdef",
            ))
        }
    }
    for (labeled, expected) in [
        (true, "metadata_child_io_denied"),
        (false, "password utility unavailable"),
    ] {
        let mut bytes = Vec::new();
        let error = drain_labeled(&mut DeniedReader, &mut bytes, 4096, labeled).unwrap_err();
        assert_eq!(error.reason, expected);
        assert!(bytes.is_empty());
    }
}

#[test]
fn metadata_cleanup_failure_preserves_the_original_error() {
    for labeled in [true, false] {
        let original = metadata_failure("metadata_child_io_denied", labeled);
        let expected = original.reason.clone();
        let error = metadata_cleanup_result::<()>(Err(original), labeled).unwrap_err();
        assert_eq!(error.reason, expected);
        let cleanup = metadata_cleanup_result(Ok(()), labeled).unwrap_err();
        assert_eq!(
            cleanup.reason,
            if labeled {
                "metadata_child_cleanup"
            } else {
                "password utility unavailable"
            }
        );
    }
}

#[test]
fn metadata_budget_expiry_is_distinct_before_any_spawn() {
    let command = || crate::auth::password_process_fixture_command("result");
    let end = Instant::now();
    let invalid_cap = run_with_cap_labeled(command(), b"", end, 1, true).unwrap_err();
    assert_eq!(invalid_cap.reason, "metadata_child_preflight");
    let insufficient = run_with_cap_labeled(command(), b"", end, 4096, true).unwrap_err();
    assert_eq!(insufficient.reason, "metadata_child_budget");
    assert!(!execution_quarantined());
}

#[test]
fn fixed_stock_configuration_queries_are_admitted_without_arbitrary_options() {
    let strings = |args: &[&str]| args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    for args in [
        vec!["-c", "/etc/dovecot/dovecot.conf", "-n"],
        vec!["-c", "/etc/dovecot/dovecot.conf", "-h", "auth_cache_size"],
        vec![
            "-c",
            "/etc/dovecot/dovecot.conf",
            "-h",
            "auth_username_format",
        ],
    ] {
        assert!(fixed_metadata_args(
            "/usr/local/bin/doveconf",
            &strings(&args)
        ));
    }
    for args in [
        vec!["-c", "/tmp/dovecot.conf", "-n"],
        vec!["-c", "/etc/dovecot/dovecot.conf", "-h", "ssl_key"],
        vec!["-c", "/etc/dovecot/dovecot.conf", "-n", "extra"],
    ] {
        assert!(!fixed_metadata_args(
            "/usr/local/bin/doveconf",
            &strings(&args)
        ));
    }
}
