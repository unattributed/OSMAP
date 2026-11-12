use super::*;
fn sleeper() -> Child {
    crate::auth::mutation_sleeper_fixture()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap()
}
#[test]
fn actual_owned_group_killed_direct_child_reaped_and_group_absent_within_original_budget() {
    let mut child = sleeper();
    let pid = child.id();
    let began = Instant::now();
    cleanup_owned_group_before(&mut child, began + Duration::from_millis(100)).unwrap();
    assert!(child.try_wait().unwrap().is_some());
    assert!(!crate::openbsd::process_group_exists(pid).unwrap());
    assert!(began.elapsed() < Duration::from_millis(100));
}
#[test]
fn kill_permission_unknown_group_and_late_cleanup_are_never_success_proofs() {
    let mut denied = sleeper();
    let deadline = Instant::now() + Duration::from_millis(100);
    assert!(cleanup_owned_group_with(
        &mut denied,
        deadline,
        |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        |_| Ok(false)
    )
    .is_err());
    cleanup_owned_group_before(&mut denied, Instant::now() + Duration::from_millis(100)).unwrap();
    let mut unknown = sleeper();
    assert!(cleanup_owned_group_with(
        &mut unknown,
        Instant::now() + Duration::from_millis(100),
        crate::openbsd::kill_process_group,
        |_| Err(std::io::Error::from_raw_os_error(libc::EPERM))
    )
    .is_err());
    // The injected existence error may follow successful leader reaping. Only
    // reconcile after its already-issued kill; never signal that PID again.
    let deadline = Instant::now() + Duration::from_millis(100);
    while unknown.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(unknown.try_wait().unwrap().is_some());
    assert!(!crate::openbsd::process_group_exists(unknown.id()).unwrap());
    let mut late = sleeper();
    assert!(
        cleanup_owned_group_before(&mut late, Instant::now() - Duration::from_millis(1)).is_err()
    );
    let deadline = Instant::now() + Duration::from_millis(100);
    while late.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(late.try_wait().unwrap().is_some());
    assert!(!crate::openbsd::process_group_exists(late.id()).unwrap());
}
#[test]
fn mutation_profile_never_renews_original_deadline_and_enforces_frame_limits() {
    let began = Instant::now();
    let command = crate::auth::mutation_sleeper_fixture();
    assert!(matches!(
        run_account_mutation(command, &[0; 12289], began + Duration::from_secs(1)),
        Err(Error::Limit)
    ));
    let command = crate::auth::mutation_sleeper_fixture();
    assert!(matches!(
        run_account_mutation(command, b"", Instant::now() + Duration::from_millis(250)),
        Err(Error::Expired)
    ));
    assert!(began.elapsed() < Duration::from_secs(1));
}

#[test]
fn eof_requires_actual_exit_status_and_nonzero_worker_cannot_be_success() {
    assert_eq!(
        run_account_mutation(
            crate::auth::mutation_immediate_fixture(),
            b"",
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap(),
        Vec::<u8>::new()
    );
    assert!(matches!(
        run_account_mutation(
            crate::auth::crypto_fixture_command("failure"),
            b"",
            Instant::now() + Duration::from_secs(1)
        ),
        Err(Error::Unavailable)
    ));
}
