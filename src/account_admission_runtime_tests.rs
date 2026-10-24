use super::*;
use crate::openpgp_inventory_runtime::validate_socket;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
fn service(uid: u32) -> Service {
    Service {
        active: Mutex::new(BTreeSet::new()),
        cleanup_unconfirmed: std::sync::atomic::AtomicBool::new(false),
        config: Config {
            version: 1,
            socket: "/tmp/unused".into(),
            trusted_web_uid: uid,
            accounts: vec!["alice@example.test".into()],
        },
        key: vec![29; 32],
        verifier: Mutex::new(Verifier::default()),
        engine: None,
    }
}
#[test]
fn freshness_fixture_projects_only_fixed_account_and_preserves_service_authority() {
    let original = service(51);
    let original_accounts = original.password_accounts();
    let projected = original.with_freshness_fixture_account().unwrap();
    let mut expected = original_accounts;
    expected.insert(crate::account_password_server::FRESHNESS_FIXTURE_ACCOUNT.into());
    assert_eq!(projected.password_accounts(), expected);
    assert_eq!(projected.config.version, 1);
    assert_eq!(projected.config.socket, Path::new("/tmp/unused"));
    assert_eq!(projected.password_peer_uid(), 51);
    assert_eq!(projected.password_key(), &[29; 32]);
    assert!(projected.engine.is_none());
    assert!(projected.active.lock().unwrap().is_empty());
    assert!(!projected.cleanup_unconfirmed.load(Ordering::SeqCst));
    let at = now().unwrap();
    for account in [
        "alice@example.test",
        crate::account_password_server::FRESHNESS_FIXTURE_ACCOUNT,
    ] {
        let request =
            Request::issue(account, Operation::Admit { epoch: 0 }, at, &projected.key).unwrap();
        assert!(projected
            .process(&request.bytes().unwrap(), at, |observed| {
                assert_eq!(observed.account(), account);
                Ok(Some(0))
            })
            .is_ok());
    }
    let foreign = Request::issue(
        "unrelated@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &projected.key,
    )
    .unwrap();
    assert_eq!(
        projected.process(&foreign.bytes().unwrap(), at, |_| {
            panic!("unconfigured account reached dispatch")
        }),
        Err(Error::Refused)
    );
    assert!(matches!(
        projected.with_freshness_fixture_account(),
        Err(Error::Invalid)
    ));
    let mut full = service(51);
    full.config.accounts = (0..64).map(|i| format!("user{i}@example.test")).collect();
    assert!(matches!(
        full.with_freshness_fixture_account(),
        Err(Error::Invalid)
    ));
}
#[test]
fn unqualified_production_never_constructs_or_dispatches() {
    const {
        assert!(!NATIVE_CONFINEMENT_QUALIFIED);
    }
    assert!(Client::from_operator_files(
        Path::new("/tmp/nonexistent"),
        Path::new("/tmp/nonexistent"),
        0
    )
    .is_err());
    assert!(Service::from_operator_files(
        Path::new("/tmp/nonexistent"),
        Path::new("/tmp/nonexistent")
    )
    .is_err());
    let (stream, _) = UnixStream::pair().unwrap();
    assert_eq!(
        service(crate::openbsd::effective_uid()).connection(stream),
        Err(Error::Unavailable)
    );
    let mut unqualified = service(crate::openbsd::effective_uid());
    let path = std::env::temp_dir().join(format!(
        "osmap-unqualified-admission-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    unqualified.config.socket = path.clone();
    assert_eq!(
        unqualified.serve(&AtomicBool::new(false)),
        Err(Error::Unavailable)
    );
    assert!(fs::symlink_metadata(path).is_err());
}

fn listener_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "adm-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn account_client_custody_refuses_key_content_replacement_links_endpoint_and_parent_drift() {
    let root = fs::canonicalize("/tmp").unwrap().join(format!(
        "osmap-client-custody-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("account.sock");
    let key = root.join("purpose.key");
    fs::write(&key, [29; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    let uid = crate::openbsd::effective_uid();
    let paths = AccountClientPaths::observe(&socket, uid, &[(&key, &[29; 32])]).unwrap();
    assert_eq!(paths.recheck(), Ok(()));
    assert!(paths.seal.get().is_none());
    fs::write(&key, [30; 32]).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    fs::write(&key, [29; 32]).unwrap();
    assert_eq!(paths.recheck(), Ok(()));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::hard_link(&key, root.join("linked.key")).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    assert!(AccountClientPaths::observe(&socket, uid, &[(&key, &[29; 32])]).is_err());
    fs::remove_file(root.join("linked.key")).unwrap();
    let replacement = root.join("replacement.key");
    fs::write(&replacement, [29; 32]).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &key).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    let paths = AccountClientPaths::observe(&socket, uid, &[(&key, &[29; 32])]).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    fs::remove_file(&socket).unwrap();
    let replacement_listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    drop((listener, replacement_listener, paths));
    fs::remove_file(socket).unwrap();
    fs::remove_file(key).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn account_client_preseal_ancestry_remains_enforced() {
    let root = fs::canonicalize("/tmp").unwrap().join(format!(
        "osmap-client-ancestry-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = root.join("private");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = parent.join("account.sock");
    let key = parent.join("purpose.key");
    fs::write(&key, [29; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    let paths = AccountClientPaths::observe(
        &socket,
        crate::openbsd::effective_uid(),
        &[(&key, &[29; 32])],
    )
    .unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(paths.recheck(), Err(Error::Unavailable));
    assert!(AccountClientPaths::observe(
        &socket,
        crate::openbsd::effective_uid(),
        &[(&key, &[29; 32])]
    )
    .is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(paths.recheck(), Ok(()));
    drop((paths, listener));
    fs::remove_file(socket).unwrap();
    fs::remove_file(key).unwrap();
    fs::remove_dir(parent).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn account_client_final_preseal_refuses_relocated_same_leaves_in_replaced_parent() {
    let root = fs::canonicalize("/tmp").unwrap().join(format!(
        "osmap-parent-custody-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let parent = root.join("private");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = parent.join("account.sock");
    let key = parent.join("purpose.key");
    fs::write(&key, [29; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    let uid = crate::openbsd::effective_uid();
    let paths = AccountClientPaths::observe(&socket, uid, &[(&key, &[29; 32])]).unwrap();
    assert_eq!(paths.preflight_serve(&socket, &[&key], uid), Ok(()));
    assert_eq!(
        paths.preflight_serve(&socket, &[&key], uid.wrapping_add(1)),
        Err(Error::Unavailable)
    );
    assert_eq!(
        paths.preflight_serve(&socket, &[&socket], uid),
        Err(Error::Unavailable)
    );
    let old_parent = root.join("old-private");
    fs::rename(&parent, &old_parent).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(old_parent.join("account.sock"), &socket).unwrap();
    fs::rename(old_parent.join("purpose.key"), &key).unwrap();
    // Same allowed leaf inodes/content and fully protected new pathname are
    // insufficient: the final preseal parent identity must still match.
    validate_socket(&socket, uid).unwrap();
    assert_eq!(paths.recheck_leaves(), Ok(()));
    assert_eq!(
        paths.preflight_serve(&socket, &[&key], uid),
        Err(Error::Unavailable)
    );
    assert!(AccountClientPaths::observe(&socket, uid, &[(&key, &[29; 32])]).is_ok());
    drop((paths, listener));
    fs::remove_file(socket).unwrap();
    fs::remove_file(key).unwrap();
    fs::remove_dir(parent).unwrap();
    fs::remove_dir(old_parent).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn account_client_parent_allows_new_private_sibling_without_custody_change() {
    let root = fs::canonicalize("/tmp").unwrap().join(format!(
        "osmap-parent-sibling-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("account.sock");
    let key = root.join("purpose.key");
    fs::write(&key, [29; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    let uid = crate::openbsd::effective_uid();
    let paths = AccountClientPaths::observe(&socket, uid, &[(&key, &[29; 32])]).unwrap();
    let before = fs::symlink_metadata(&root).unwrap();
    let sibling = root.join("late-runtime-private-state");
    fs::create_dir(&sibling).unwrap();
    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o700)).unwrap();
    let after = fs::symlink_metadata(&root).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.uid(),
            before.gid(),
            before.mode()
        ),
        (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.mode()
        )
    );
    assert!(
        after.nlink() > before.nlink(),
        "fixture must demonstrate the directory-link-count change"
    );
    assert_eq!(paths.recheck_leaves(), Ok(()));
    let result = paths.preflight_serve(&socket, &[&key], uid);
    drop((paths, listener));
    fs::remove_file(socket).unwrap();
    fs::remove_file(key).unwrap();
    fs::remove_dir(sibling).unwrap();
    fs::remove_dir(root).unwrap();
    // Bounded RED witness: no server accept thread or private frame is needed.
    assert_eq!(
        result,
        Ok(()),
        "a new private sibling is not parent identity or custody drift"
    );
}

#[test]
fn parent_policy_is_narrow_and_failed_seal_prevents_accept_then_removes_owned_endpoint() {
    let root = listener_root();
    let socket = root.join("admission.sock");
    let plan = crate::openbsd::account_admission_parent_plan(
        &socket,
        Path::new("/usr/local/bin/python3.14"),
    )
    .unwrap();
    let rows: std::collections::BTreeMap<_, _> = plan
        .unveil_rules
        .iter()
        .map(|r| (r.path.as_path(), r.permissions.as_str()))
        .collect();
    assert_eq!(rows.get(socket.as_path()), Some(&"rwc"));
    assert_eq!(rows.get(root.as_path()), Some(&"r"));
    assert_eq!(rows.get(Path::new("/usr/local/bin/python3")), None);
    assert_eq!(
        rows.get(Path::new("/usr/local/bin/python3.14")),
        Some(&"rx")
    );
    for ancestor in ["/", "/usr", "/usr/local", "/usr/local/bin"] {
        assert_eq!(rows.get(Path::new(ancestor)), Some(&""));
    }
    assert_eq!(
        plan.promises_after_lock,
        "stdio rpath wpath cpath unix proc exec"
    );
    assert_eq!(
        plan.promises_before_lock,
        "stdio rpath wpath cpath unix proc exec unveil"
    );
    assert!(!rows
        .keys()
        .any(|p| p.starts_with("/etc/osmap") || p.starts_with(EPOCH_ROOT)));
    let calls = AtomicUsize::new(0);
    let policy_calls = AtomicUsize::new(0);
    let mut s = service(crate::openbsd::effective_uid());
    s.config.socket = socket.clone();
    let result = s.serve_with_policy(
        &AtomicBool::new(false),
        &|_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        },
        &|endpoint| {
            policy_calls.fetch_add(1, Ordering::SeqCst);
            endpoint.recheck()?;
            assert_eq!(fs::symlink_metadata(&socket).unwrap().mode() & 0o777, 0o660);
            // A queued connection cannot reach peer/frame processing after refusal.
            let _queued = UnixStream::connect(&socket).unwrap();
            Err(Error::Unavailable)
        },
    );
    assert_eq!(result, Err(Error::Unavailable));
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(fs::symlink_metadata(&socket).is_err());
    fs::remove_dir(root).unwrap();
}

#[test]
fn inherited_worker_cwd_refuses_changed_root_in_disposable_process() {
    const CHILD: &str = "OSMAP_TEST_ADMISSION_ROOT_CWD_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::env::set_current_dir(std::env::temp_dir()).unwrap();
        assert_eq!(
            crate::auth::account_admission_inherited_root_command(Path::new(
                "/usr/local/bin/python3.13"
            ))
            .unwrap_err()
            .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::env::set_current_dir("/").unwrap();
        let inherited = crate::auth::account_admission_inherited_root_command(Path::new(
            "/usr/local/bin/python3.13",
        ))
        .unwrap();
        let ordinary = crate::auth::account_admission_command();
        assert_eq!(inherited.get_program(), "/usr/local/bin/python3.13");
        assert_eq!(ordinary.get_program(), "/usr/local/bin/python3");
        assert_eq!(
            inherited.get_args().collect::<Vec<_>>(),
            ordinary.get_args().collect::<Vec<_>>()
        );
        assert_eq!(
            inherited.get_envs().collect::<Vec<_>>(),
            ordinary.get_envs().collect::<Vec<_>>()
        );
        assert_eq!(ordinary.get_current_dir(), Some(Path::new("/")));
        assert_eq!(inherited.get_current_dir(), None);
        return;
    }
    let output = crate::openpgp_crypto_process::run_account_admission(
        crate::auth::admission_root_cwd_fixture_command().unwrap(),
        b"",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output).contains("1 passed"));
}

// Existing libtest/subprocess qualification lane; never enables the production
// gate, consumes credentials or authenticates. Root executes this once against
// the exact reviewed native build and installed interpreter custody.
#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "requires root-owned disposable OpenBSD parent confinement qualification"]
fn native_parent_confinement_preserves_metadata_spawn_and_owned_unlink() {
    const CHILD: &str = "OSMAP_TEST_ADMISSION_PARENT_NATIVE_CHILD";
    const OUTSIDE: &str = "OSMAP_TEST_ADMISSION_PARENT_NATIVE_OUTSIDE";
    const MARKER: &str = "admission_parent_metadata_spawn_denial_unlink=PASS";
    assert_eq!(crate::openbsd::effective_uid(), 0);
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let outside = PathBuf::from(std::env::var_os(OUTSIDE).unwrap());
        assert!(root.is_absolute() && outside.is_absolute() && root != outside);
        private_dir(&root, 0, false).unwrap();
        private_dir(&outside, 0, false).unwrap();
        crate::openbsd::disable_core_dumps().unwrap();
        std::env::set_current_dir("/").unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let engine = InstalledEngine::observe(Path::new(ENGINE), 0, deadline).unwrap();
        let mut endpoint = AdmissionEndpoint::bind(&root.join("admission.sock")).unwrap();
        assert!(engine.sealed.get().is_none());
        engine.confine_parent(&endpoint).unwrap();
        assert!(engine.sealed.get().is_some());
        endpoint.recheck().unwrap();
        engine.recheck(deadline).unwrap();
        // Only harmless fixture bytes are used for outside-access negatives.
        assert!(fs::read(outside.join("public-fixture")).is_err());
        assert!(OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(outside.join("forbidden-create"))
            .is_err());
        let fixed = crate::auth::account_admission_inherited_root_command(&engine.target).unwrap();
        assert_eq!(fixed.get_current_dir(), None);
        // Interpreter-only public control. It deliberately does not invoke the
        // installed private worker or pretend its module closure is qualified.
        let command = crate::auth::admission_parent_interpreter_fixture_command().unwrap();
        let output =
            crate::openpgp_crypto_process::run_account_admission(command, b"", deadline).unwrap();
        assert_eq!(output, b"inherited_root_exec=PASS\n");
        endpoint.remove().unwrap();
        assert!(fs::symlink_metadata(root.join("admission.sock")).is_err());
        println!("{MARKER}");
        return;
    }
    let root = listener_root();
    let outside = listener_root();
    let root_identity = AdmissionEndpoint::identity(&fs::symlink_metadata(&root).unwrap());
    let outside_identity = AdmissionEndpoint::identity(&fs::symlink_metadata(&outside).unwrap());
    fs::write(outside.join("public-fixture"), b"harmless public fixture\n").unwrap();
    let command = crate::auth::admission_parent_native_fixture_command(&root, &outside).unwrap();
    // Existing strict owned-group cleanup is mandatory; on any uncertainty,
    // leave both exact leases retained instead of recursively deleting them.
    let output = crate::openpgp_crypto_process::run_account_admission(
        command,
        b"",
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&output).contains(MARKER));
    assert_eq!(
        AdmissionEndpoint::identity(&fs::symlink_metadata(&root).unwrap()),
        root_identity
    );
    assert_eq!(
        AdmissionEndpoint::identity(&fs::symlink_metadata(&outside).unwrap()),
        outside_identity
    );
    assert!(!outside.join("forbidden-create").exists());
    assert_eq!(
        fs::read(outside.join("public-fixture")).unwrap(),
        b"harmless public fixture\n"
    );
    fs::remove_file(outside.join("public-fixture")).unwrap();
    fs::remove_dir(outside).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn fixed_python_alias_admits_only_exact_target_and_refuses_target_replacement() {
    let root = listener_root();
    let alias = root.join("python3");
    let target = root.join("python3.13");
    let owner = crate::openbsd::effective_uid();
    fs::write(&target, b"synthetic executable custody bytes\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink("python3.13", &alias).unwrap();
    // Historical ordinary-file guard refuses this legitimate fixed alias.
    assert!(file(&alias, owner, true, 64 * 1024 * 1024).is_err());
    let deadline = Instant::now() + Duration::from_secs(2);
    let first = InstalledEngine::observe(&alias, owner, deadline).unwrap();
    assert_eq!(first.recheck(deadline), Ok(()));
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink("python3.12", &alias).unwrap();
    assert!(InstalledEngine::observe(&alias, owner, deadline).is_err());
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink("python3.13", &alias).unwrap();
    let current = InstalledEngine::observe(&alias, owner, deadline).unwrap();
    let replacement = root.join("replacement");
    fs::write(&replacement, b"synthetic executable custody bytes\n").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&replacement, &target).unwrap();
    assert_eq!(current.recheck(deadline), Err(Error::Unavailable));
    let parent_alias = root.join("alias-parent");
    std::os::unix::fs::symlink(&root, &parent_alias).unwrap();
    assert!(InstalledEngine::observe(&parent_alias.join("python3"), owner, deadline).is_err());
    fs::remove_file(parent_alias).unwrap();
    fs::remove_file(alias).unwrap();
    fs::remove_file(target).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn installed_python_accepts_minor_upgrade_but_refuses_target_escape() {
    let root = listener_root();
    let alias = root.join("python3");
    let owner = crate::openbsd::effective_uid();
    for name in ["python3.13", "python3.14"] {
        let path = root.join(name);
        fs::write(&path, b"synthetic interpreter").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(name, &alias).unwrap();
        let engine =
            InstalledEngine::observe(&alias, owner, Instant::now() + Duration::from_secs(2))
                .unwrap();
        assert_eq!(engine.target, path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4700)).unwrap();
        assert!(
            InstalledEngine::observe(&alias, owner, Instant::now() + Duration::from_secs(2))
                .is_err()
        );
        fs::remove_file(&alias).unwrap();
        fs::remove_file(path).unwrap();
    }
    for bad in [
        "../python3.14",
        "/usr/local/bin/python3.14",
        "python3.14/",
        "python3.14x",
        "python2.7",
        "sh",
    ] {
        assert!(!python_target_name(Path::new(bad)), "{bad}");
    }
    fs::remove_dir(root).unwrap();
}

#[test]
fn bound_target_recheck_ignores_unused_alias_and_refuses_target_or_ancestor_drift() {
    let root = listener_root();
    let alias = root.join("python3");
    let target = root.join("python3.13");
    fs::write(&target, b"synthetic fixed target bytes\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink("python3.13", &alias).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let engine =
        InstalledEngine::observe(&alias, crate::openbsd::effective_uid(), deadline).unwrap();
    assert!(engine.sealed.get().is_none());
    fs::remove_file(&alias).unwrap();
    // No alias remains to readlink/canonicalize or accidentally dispatch.
    assert!(InstalledEngine::observe(&alias, crate::openbsd::effective_uid(), deadline).is_err());
    assert_eq!(engine.recheck(deadline), Ok(()));
    std::thread::scope(|scope| {
        let a = scope.spawn(|| engine.recheck(deadline));
        let b = scope.spawn(|| engine.recheck(deadline));
        assert_eq!(a.join().unwrap(), Ok(()));
        assert_eq!(b.join().unwrap(), Ok(()));
    });
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(engine.recheck(deadline), Err(Error::Unavailable));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = root.join("replacement");
    fs::write(&replacement, b"synthetic fixed target bytes\n").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&replacement, &target).unwrap();
    assert_eq!(engine.recheck(deadline), Err(Error::Unavailable));
    fs::remove_file(&target).unwrap();
    fs::remove_dir(root).unwrap();
}
#[test]
fn expanded_worker_custody_refuses_missing_or_writable_private_primary_module() {
    let root = listener_root();
    let owner = crate::openbsd::effective_uid();
    for name in WORKER_MODULES {
        let path = root.join(name);
        fs::write(&path, b"# synthetic module custody fixture\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(worker_module_custody(&root, owner), Ok(()));
    let primary = root.join("mutation_primary.py");
    fs::remove_file(&primary).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Err(Error::Unavailable));
    fs::write(&primary, b"# synthetic replacement\n").unwrap();
    fs::set_permissions(&primary, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Err(Error::Unavailable));
    fs::set_permissions(&primary, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Ok(()));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(worker_module_custody(&root, owner), Err(Error::Unavailable));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in WORKER_MODULES {
        fs::remove_file(root.join(name)).unwrap();
    }
    fs::remove_dir(root).unwrap();
}
#[test]
fn expired_original_connection_refuses_before_worker_dispatch() {
    let request = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        now().unwrap(),
        &[17; 32],
    )
    .unwrap();
    assert_eq!(
        Service::fixed_worker(&request, Instant::now()),
        Err(Error::Expired)
    );
}
fn wait_listener(path: &Path) {
    assert!(path.as_os_str().len() <= 100);
    let end = Instant::now() + Duration::from_secs(2);
    while !path.exists() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn listener_shutdown_retains_late_worker_cleanup_uncertainty() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let mut s = service(crate::openbsd::effective_uid());
    s.config.socket = path.clone();
    let stop = AtomicBool::new(false);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let execute = |_: &Request, _: Instant| {
        entered.wait();
        release.wait();
        Err(Error::CleanupUnconfirmed)
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| s.serve_with(&stop, &execute));
        wait_listener(&path);
        let request = Request::issue(
            "alice@example.test",
            Operation::Admit { epoch: 0 },
            now().unwrap(),
            &s.key,
        )
        .unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        write_frame(&mut stream, &request.bytes().unwrap(), deadline).unwrap();
        entered.wait();
        stop.store(true, Ordering::SeqCst);
        release.wait();
        assert!(read_frame(&mut stream, MAX_FRAME, deadline).is_err());
        assert_eq!(server.join().unwrap(), Err(Error::CleanupUnconfirmed));
    });
    assert!(s.cleanup_unconfirmed.load(Ordering::SeqCst));
    assert!(!path.exists());
    fs::remove_dir(root).unwrap();
}
#[test]
fn persistent_listener_keeps_replay_state_and_finishes_dispatched_work_before_stop() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let mut s = service(crate::openbsd::effective_uid());
    s.config.socket = path.clone();
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let execute = |_: &Request, deadline: Instant| {
        let index = calls.fetch_add(1, Ordering::SeqCst);
        assert!(deadline > Instant::now());
        assert!(deadline.duration_since(Instant::now()) <= Duration::from_secs(30));
        if index == 1 {
            entered.wait();
            release.wait();
        }
        Ok(Some(3))
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| s.serve_with(&stop, &execute));
        wait_listener(&path);
        let at = now().unwrap();
        let first = Request::issue(
            "alice@example.test",
            Operation::Admit { epoch: 3 },
            at,
            &s.key,
        )
        .unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        write_frame(&mut stream, &first.bytes().unwrap(), deadline).unwrap();
        let reply = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        assert_eq!(
            Verifier::default()
                .response(&first, &reply, &s.key, now().unwrap())
                .unwrap()
                .unwrap()
                .epoch,
            3
        );
        drop(stream);
        // A separately accepted connection still uses the same verifier.
        let mut replay = UnixStream::connect(&path).unwrap();
        write_frame(&mut replay, &first.bytes().unwrap(), deadline).unwrap();
        assert!(read_frame(&mut replay, MAX_FRAME, deadline).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(replay);
        let second = Request::issue(
            "alice@example.test",
            Operation::Admit { epoch: 3 },
            now().unwrap(),
            &s.key,
        )
        .unwrap();
        let mut admitted = UnixStream::connect(&path).unwrap();
        write_frame(&mut admitted, &second.bytes().unwrap(), deadline).unwrap();
        entered.wait();
        stop.store(true, Ordering::SeqCst);
        release.wait();
        let reply = read_frame(&mut admitted, MAX_FRAME, deadline).unwrap();
        assert!(Verifier::default()
            .response(&second, &reply, &s.key, now().unwrap())
            .unwrap()
            .is_some());
        assert_eq!(server.join().unwrap(), Ok(()));
    });
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!path.exists());
    fs::remove_dir(root).unwrap();
}

#[test]
fn listener_rejects_wrong_peer_before_read_and_refuses_foreign_socket_cleanup() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let mut s = service(crate::openbsd::effective_uid().wrapping_add(1));
    s.config.socket = path.clone();
    let stop = AtomicBool::new(false);
    let calls = AtomicUsize::new(0);
    let execute = |_: &Request, _: Instant| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(0))
    };
    std::thread::scope(|scope| {
        let server = scope.spawn(|| s.serve_with(&stop, &execute));
        wait_listener(&path);
        let mut peer = UnixStream::connect(&path).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
        stop.store(true, Ordering::SeqCst);
        assert_eq!(server.join().unwrap(), Ok(()));
    });
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!path.exists());
    let mut owned = AdmissionEndpoint::bind(&path).unwrap();
    assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o660);
    assert!(AdmissionEndpoint::bind(&path).is_err());
    fs::remove_file(&path).unwrap();
    let foreign = UnixListener::bind(&path).unwrap();
    let identity = AdmissionEndpoint::identity(&fs::symlink_metadata(&path).unwrap());
    assert_eq!(owned.remove(), Err(Error::Unavailable));
    drop(owned);
    assert_eq!(
        AdmissionEndpoint::identity(&fs::symlink_metadata(&path).unwrap()),
        identity
    );
    drop(foreign);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn endpoint_bind_reports_unknown_cleanup_and_preserves_post_bind_replacement() {
    let root = listener_root();
    let path = root.join("admission.sock");
    let result = AdmissionEndpoint::bind_after_create(&path, |created| {
        assert!(fs::symlink_metadata(created)
            .unwrap()
            .file_type()
            .is_socket());
        fs::remove_file(created).unwrap();
        fs::write(created, b"foreign replacement\n").unwrap();
    });
    assert!(matches!(result, Err(Error::CleanupUnconfirmed)));
    assert_eq!(fs::read(&path).unwrap(), b"foreign replacement\n");
    assert!(fs::symlink_metadata(&path).unwrap().is_file());
    fs::remove_file(path).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn wrong_peer_foreign_account_and_replay_never_dispatch_worker() {
    let (mut stream, _) = UnixStream::pair().unwrap();
    let calls = AtomicUsize::new(0);
    let uid = crate::openbsd::effective_uid();
    assert_eq!(
        service(uid.wrapping_add(1)).connection_with(&mut stream, |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(1))
        }),
        Err(Error::Authentication)
    );
    let s = service(uid);
    let at = now().unwrap();
    let foreign = Request::issue(
        "bob@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert_eq!(
        s.process(&foreign.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .unwrap_err(),
        Error::Refused
    );
    let own = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert!(s
        .process(&own.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .is_ok());
    assert_eq!(
        s.process(&own.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .unwrap_err(),
        Error::Replay
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
#[test]
fn actual_private_socket_authentication_and_epoch_binding_without_native_credentials() {
    let uid = crate::openbsd::effective_uid();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-account-admission-{}-{}",
        std::process::id(),
        now().unwrap()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("account.sock");
    let key = root.join("grant.key");
    std::fs::write(&key, vec![29; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    let worker = std::thread::spawn(move || {
        let s = service(uid);
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            s.connection_with(&mut stream, |r, _| {
                match r.operation() {
                    Operation::Authenticate { password } => {
                        assert_eq!(password, "synthetic credential")
                    }
                    Operation::Admit { epoch } => assert_eq!(*epoch, 7),
                };
                Ok(Some(7))
            })
            .unwrap();
        }
    });
    let client = Client::qualified_files(&socket, &key, uid).unwrap();
    let a = client
        .authenticate("alice@example.test", "synthetic credential")
        .unwrap()
        .unwrap();
    assert_eq!(
        a,
        Admission {
            account: "alice@example.test".into(),
            epoch: 7
        }
    );
    client.admit(&a.account, a.epoch).unwrap();
    worker.join().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn typed_worker_stale_denial_is_signed_and_refused_while_current_epoch_still_admits() {
    let uid = crate::openbsd::effective_uid();
    let root = listener_root();
    let socket = root.join("account.sock");
    let key = root.join("grant.key");
    fs::write(&key, [29; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    let worker = std::thread::spawn(move || {
        let s = service(uid);
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            s.connection_with_status(&mut stream, |request, deadline| {
                // Exact worker protocol on real bounded stdin/stdout. The
                // paired Python main test proves production denial generation.
                let command = crate::auth::admission_stale_denial_fixture_command();
                Service::fixed_worker_status_command(request, deadline, command)
            })
            .unwrap();
        }
    });
    let client = Client::qualified_files(&socket, &key, uid).unwrap();
    assert_eq!(
        client.admit_before(
            "alice@example.test",
            0,
            Instant::now() + Duration::from_secs(5)
        ),
        Err(Error::Refused)
    );
    assert_eq!(
        client.password_changed_at_before(
            "alice@example.test",
            1,
            Instant::now() + Duration::from_secs(5)
        ),
        Ok(Some("20261016140432".into()))
    );
    worker.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn actual_runtime_login_mfa_session_and_changed_epoch_refusal_no_primary_fallback() {
    use crate::http::{
        BrowserGateway, BrowserLoginDecision, BrowserSessionDecision, RuntimeBrowserGateway,
    };
    use crate::totp::{FileTotpSecretStore, SystemTimeProvider, TimeProvider};
    use hmac::{Hmac, Mac};
    // Public RFC6238 test vector only, never an operator factor or credential.
    let public_vector = b"12345678901234567890";
    for changed_during_mfa in [false, true] {
        let uid = crate::openbsd::effective_uid();
        let root = PathBuf::from("/tmp").join(format!(
            "osmap-account-gateway-{}-{}",
            std::process::id(),
            changed_during_mfa
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("account.sock");
        let key = root.join("grant.key");
        std::fs::write(&key, vec![29; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let epoch = Arc::new(AtomicUsize::new(7));
        let server_epoch = epoch.clone();
        let worker = std::thread::spawn(move || {
            let s = service(uid);
            for _ in 0..if changed_during_mfa { 2 } else { 4 } {
                let (mut stream, _) = listener.accept().unwrap();
                s.connection_with(&mut stream, |request, _| match request.operation() {
                    Operation::Authenticate { password } => {
                        assert_eq!(password, "synthetic primary credential");
                        if changed_during_mfa {
                            server_epoch.store(8, Ordering::SeqCst);
                        }
                        Ok(Some(7))
                    }
                    Operation::Admit { epoch } => {
                        assert_eq!(*epoch, 7, "issuance must not retarget to changed epoch");
                        Ok((server_epoch.load(Ordering::SeqCst) == 7).then_some(7))
                    }
                })
                .unwrap();
            }
        });
        let mutation_socket = root.join("mutation.sock");
        let mutation_key = root.join("mutation.key");
        let proof_key = root.join("session-proof.key");
        let _mutation_listener = UnixListener::bind(&mutation_socket).unwrap();
        std::fs::set_permissions(&mutation_socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        for (path, bytes) in [(&mutation_key, [17_u8; 32]), (&proof_key, [19_u8; 32])] {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let gateway = RuntimeBrowserGateway::for_test(&root).with_account_fixture_clients(
            Client::qualified_files(&socket, &key, uid).unwrap(),
            crate::account_mutation_client::Client::stored_fixture_files(
                &mutation_socket,
                &mutation_key,
                &proof_key,
                uid,
            )
            .unwrap(),
        );
        // for_test has a nonexistent primary backend, so any accidental fallback fails.
        let totp_root = root.join("totp");
        std::fs::create_dir(&totp_root).unwrap();
        std::fs::set_permissions(&totp_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let factor =
            FileTotpSecretStore::new(&totp_root).secret_path_for_username("alice@example.test");
        std::fs::write(&factor, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        std::fs::set_permissions(&factor, std::fs::Permissions::from_mode(0o600)).unwrap();
        let counter = SystemTimeProvider.unix_timestamp() / 30;
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(public_vector).unwrap();
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 15);
        let number =
            u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let code = format!("{:06}", number % 1_000_000);
        let context = crate::auth::AuthenticationContext {
            request_id: "synthetic".into(),
            remote_addr: "127.0.0.1".into(),
            user_agent: "synthetic".into(),
        };
        let result = gateway.login(
            &context,
            "alice@example.test",
            "synthetic primary credential",
            &code,
        );
        if changed_during_mfa {
            assert!(matches!(
                result.decision,
                BrowserLoginDecision::Denied { .. }
            ));
            assert!(std::fs::read_dir(root.join("sessions")).unwrap().all(|e| e
                .unwrap()
                .path()
                .extension()
                .is_none_or(|v| v != "session")));
        } else {
            let BrowserLoginDecision::Authenticated { session_token, .. } = result.decision else {
                panic!("synthetic account helper login refused");
            };
            let valid = gateway.validate_session(&context, session_token.as_str());
            let BrowserSessionDecision::Valid { validated_session } = valid.decision else {
                panic!("bound session refused");
            };
            assert_eq!(validated_session.record.account_epoch, Some(7));
            epoch.store(8, Ordering::SeqCst);
            assert!(matches!(
                gateway
                    .validate_session(&context, session_token.as_str())
                    .decision,
                BrowserSessionDecision::Invalid
            ));
        }
        worker.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unconfirmed_native_cleanup_stops_subsequent_worker_admission() {
    let s = service(crate::openbsd::effective_uid());
    let at = now().unwrap();
    let calls = AtomicUsize::new(0);
    let first = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert_eq!(
        s.process(&first.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::CleanupUnconfirmed)
        })
        .unwrap_err(),
        Error::CleanupUnconfirmed
    );
    let second = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &s.key,
    )
    .unwrap();
    assert_eq!(
        s.process(&second.bytes().unwrap(), at, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(0))
        })
        .unwrap_err(),
        Error::CleanupUnconfirmed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn helper_worker_capacity_is_two_and_one_per_account_without_queue() {
    let mut base = service(crate::openbsd::effective_uid());
    base.config
        .accounts
        .extend(["bob@example.test".into(), "carol@example.test".into()]);
    let service = Arc::new(base);
    let first = service.enter("alice@example.test").unwrap();
    assert!(matches!(
        service.enter("alice@example.test"),
        Err(Error::Capacity)
    ));
    drop(first);
    let entered = Arc::new(std::sync::Barrier::new(3));
    let release = Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for account in ["alice@example.test", "bob@example.test"] {
        let service = service.clone();
        let entered = entered.clone();
        let release = release.clone();
        threads.push(std::thread::spawn(move || {
            let at = now().unwrap();
            let request =
                Request::issue(account, Operation::Admit { epoch: 0 }, at, &service.key).unwrap();
            service
                .process(&request.bytes().unwrap(), at, |_| {
                    entered.wait();
                    release.wait();
                    Ok(Some(0))
                })
                .unwrap();
        }));
    }
    entered.wait();
    for account in ["alice@example.test", "carol@example.test"] {
        let at = now().unwrap();
        let request =
            Request::issue(account, Operation::Admit { epoch: 0 }, at, &service.key).unwrap();
        assert_eq!(
            service
                .process(&request.bytes().unwrap(), at, |_| panic!(
                    "capacity refusal must precede worker"
                ))
                .unwrap_err(),
            Error::Capacity
        );
    }
    release.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    let at = now().unwrap();
    let request = Request::issue(
        "carol@example.test",
        Operation::Admit { epoch: 0 },
        at,
        &service.key,
    )
    .unwrap();
    assert!(service
        .process(&request.bytes().unwrap(), at, |_| Ok(Some(0)))
        .is_ok());
}

#[path = "account_admission_deadline_tests.rs"]
mod original_deadline;

// Append only to account_admission_runtime_tests.rs in the isolated candidate.
// Real Service/Engine/parent seal/frame/MAC/replay/worker receipt/quarantine.
// Only root fixture socket/key/module/worker paths and trusted root issuer UID
// are projected; the production activation gate remains false.
#[cfg(unix)]
#[test]
#[ignore = "root-reviewed single full-factory composition only"]
fn native_full_factory_admission_entrypoint() {
    full_factory_admission_fixture(0, "OSMAP_TEST_FULL_FACTORY_ADMISSION_FD");
}

/// Separate fixed web role; the original root issuer fixture remains UID0.
/// Root must freshly verify the proposed _osmap1001/GID1003 public identity.
#[cfg(unix)]
#[test]
#[ignore = "root-reviewed genuine nonroot HTTP pilot admission only"]
fn native_http_pilot_admission_entrypoint() {
    full_factory_admission_fixture(1001, "OSMAP_TEST_HTTP_ADMISSION_FD");
}

#[cfg(unix)]
fn full_factory_admission_fixture(trusted_web_uid: u32, descriptor_variable: &str) {
    assert_eq!(std::env::consts::OS, "openbsd");
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureBootstrap {
        version: u8,
        root: PathBuf,
        stage: PathBuf,
    }
    assert_eq!(crate::openbsd::effective_uid(), 0);
    const {
        assert!(!NATIVE_CONFINEMENT_QUALIFIED);
    }
    crate::openbsd::disable_core_dumps().unwrap();
    std::env::set_current_dir("/").unwrap();
    let fd = std::env::var(descriptor_variable)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| (3..=1024).contains(v))
        .expect("fixed born bootstrap required");
    let mut control =
        crate::openbsd::fixture_owned_unix_stream(fd).expect("fixed born bootstrap refused");
    let setup = Instant::now() + Duration::from_secs(20);
    let raw = read_frame(&mut control, 2048, setup).expect("fixed bootstrap refused");
    let boot: FixtureBootstrap = serde_json::from_slice(&raw).expect("fixed shape refused");
    let fixed_name = |path: &Path, prefix: &str| {
        path.parent() == Some(Path::new("/var/run"))
            && path
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|name| {
                    name.strip_prefix(prefix).is_some_and(|suffix| {
                        suffix.len() == 16
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                })
    };
    assert!(
        boot.version == 1
            && fixed_name(&boot.root, "osmap-pxp-")
            && fixed_name(&boot.stage, "osmap-primary-root-")
    );
    private_dir(&boot.root.join("admission"), 0, true).unwrap();
    private_dir(&boot.stage, 0, false).unwrap();
    worker_module_custody(&boot.stage, 0).unwrap();
    let worker = boot.stage.join("native_factory_admission_worker.py");
    let adapter = boot.stage.join("native_factory_worker.py");
    file(&worker, 0, false, 65536).unwrap();
    file(&adapter, 0, false, 65536).unwrap();
    let key = secret(&boot.root.join("bootstrap/account-admission.key")).unwrap();
    let engine = InstalledEngine::observe(
        Path::new(ENGINE),
        0,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let service = Service {
        active: Mutex::new(BTreeSet::new()),
        cleanup_unconfirmed: std::sync::atomic::AtomicBool::new(false),
        config: Config {
            version: 1,
            socket: boot.root.join("admission/admission.sock"),
            trusted_web_uid,
            accounts: vec![
                "alice@osmap-proxy.invalid".into(),
                "bob@osmap-proxy.invalid".into(),
            ],
        },
        key,
        verifier: Mutex::new(Verifier::default()),
        engine: Some(engine),
    };
    let signals = crate::openbsd::AccountAdmissionSignals::install().unwrap();
    let execute = |request: &Request, deadline: Instant| {
        if std::env::current_dir().map_err(unavailable)? != Path::new("/") {
            return Err(Error::Unavailable);
        }
        service
            .engine
            .as_ref()
            .ok_or(Error::Unavailable)?
            .recheck(deadline)?;
        // Same strict status worker command, changing only the reviewed private
        // wrapper pathname. No credentials/options/UIDs from a request enter argv.
        let command = crate::auth::full_factory_admission_fixture_command(&boot.stage)
            .map_err(unavailable)?;
        // Preserve the authoritative timestamp through the production status
        // path. Epoch-only test adapters intentionally discard that history
        // and cannot qualify the Runtime's required changed-at readback.
        Service::fixed_worker_status_command(request, deadline, command)
    };
    let result = service.serve_with_status_policy(signals.stop_flag(), &execute, &|endpoint| {
        service
            .engine
            .as_ref()
            .ok_or(Error::Unavailable)?
            .confine_parent(endpoint)?;
        // READY follows actual native sealing, not mere pathname publication.
        write_frame(
            &mut control.try_clone().map_err(unavailable)?,
            b"READY",
            setup,
        )
        .map_err(unavailable)
    });
    assert_eq!(result, Ok(()), "full-factory admission disposition refused");
    assert!(!service.cleanup_unconfirmed.load(Ordering::SeqCst));
    println!("full_factory_admission_stopped=PASS");
}

/// Only the existing Rust client drives the actual fixed production helper.
/// Root owns the bounded fixture/provisioning and supplies bootstrap bytes via
/// private stdin after dropping this process to its dedicated nonroot UID.
#[cfg(unix)]
#[test]
#[ignore = "requires reviewed OpenBSD actual Rust service and fresh owned private-primary fixture"]
fn native_rust_private_primary_admission() -> Result<(), &'static str> {
    native_rust_private_primary_admission_for("alice@osmap-password.invalid")
}

#[cfg(unix)]
#[test]
#[ignore = "requires reviewed OpenBSD authentication-readonly service and fresh fixed account"]
fn native_rust_freshness_primary_admission() -> Result<(), &'static str> {
    native_rust_private_primary_admission_for(
        crate::account_password_server::FRESHNESS_FIXTURE_ACCOUNT,
    )
}

#[cfg(unix)]
fn native_rust_private_primary_admission_for(account: &'static str) -> Result<(), &'static str> {
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bootstrap {
        version: u8,
        client_root: PathBuf,
        alice_password: String,
        wrong_password: String,
    }
    if !cfg!(target_os = "openbsd") || crate::openbsd::effective_uid() == 0 {
        return Err("fixed nonroot OpenBSD client required");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "client core limit refused")?;
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "private bootstrap read refused")?;
    if bytes.len() > 4096 {
        return Err("private bootstrap bound refused");
    }
    let boot: Bootstrap =
        serde_json::from_slice(&bytes).map_err(|_| "private bootstrap shape refused")?;
    let root = &boot.client_root;
    let fixed_name = root.parent() == Some(Path::new("/var/run"))
        && root
            .file_name()
            .and_then(|x| x.to_str())
            .is_some_and(|name| {
                name.strip_prefix("osmap-service-admission-client-")
                    .is_some_and(|suffix| {
                        suffix.len() == 16
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
            });
    let password = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if boot.version != 1
        || !fixed_name
        || !password(&boot.alice_password)
        || !password(&boot.wrong_password)
        || boot.alice_password == boot.wrong_password
    {
        return Err("private bootstrap authority refused");
    }
    let directory = std::fs::symlink_metadata(root).map_err(|_| "client directory unavailable")?;
    if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o7777 != 0o750 {
        return Err("client directory custody refused");
    }
    let client = Client::paired_fixture_files(
        Path::new("/var/run/osmap-account-admission/admission.sock"),
        &root.join("admission.key"),
        0,
    )
    .map_err(|_| "existing Rust client custody refused")?;
    let wrong = client
        .authenticate_before(account, &boot.wrong_password, deadline)
        .map_err(|_| "wrong password reply unavailable")?;
    if wrong.is_some() {
        return Err("wrong password admitted");
    }
    let good = client
        .authenticate_before(account, &boot.alice_password, deadline)
        .map_err(|error| {
            // Error contains only the existing eight payload-free variants.
            let _ = writeln!(
                std::io::stderr().lock(),
                "native_private_primary_admission error={error:?}"
            );
            "correct password reply unavailable"
        })?
        .ok_or("correct password refused")?;
    if good.account != account || good.epoch != 0 {
        return Err("signed epoch binding mismatch");
    }
    client
        .admit_before(&good.account, good.epoch, deadline)
        .map_err(|_| "signed epoch revalidation refused")?;
    if Instant::now() >= deadline {
        return Err("original client deadline expired");
    }
    println!("\nnative_private_primary_admission result=PASS wrong_password_rejected=true correct_password_admitted=true signed_epoch=0 epoch_revalidated=true credential_write=false full_workflow_qualified=false");
    Ok(())
}

/// One real authenticated epoch read; requires separately authorized native
/// fixture custody. No password, mutation, HTTP or readiness flags are supplied.
#[cfg(unix)]
#[test]
#[ignore = "requires explicit one-shot OpenBSD R1/R2 authority and fresh exact-owned fixture"]
fn native_rust_stock_epoch_admission() -> Result<(), &'static str> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bootstrap {
        version: u8,
        client_root: PathBuf,
    }
    if !cfg!(target_os = "openbsd") || crate::openbsd::effective_uid() == 0 {
        return Err("fixed nonroot OpenBSD client required");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "client core limit refused")?;
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "private bootstrap read refused")?;
    if bytes.len() > 4096 {
        return Err("private bootstrap bound refused");
    }
    let boot: Bootstrap =
        serde_json::from_slice(&bytes).map_err(|_| "private bootstrap shape refused")?;
    let root = &boot.client_root;
    if boot.version != 1
        || root.parent() != Some(Path::new("/var/run"))
        || !root
            .file_name()
            .and_then(|x| x.to_str())
            .is_some_and(|name| {
                name.strip_prefix("osmap-service-admission-client-")
                    .is_some_and(|suffix| {
                        suffix.len() == 16
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
            })
    {
        return Err("private bootstrap authority refused");
    }
    let directory = std::fs::symlink_metadata(root).map_err(|_| "client directory unavailable")?;
    if !directory.is_dir() || directory.uid() != 0 || directory.mode() & 0o7777 != 0o750 {
        return Err("client directory custody refused");
    }
    let client = Client::paired_fixture_files(
        Path::new("/var/run/osmap-account-admission/admission.sock"),
        &root.join("admission.key"),
        0,
    )
    .map_err(|_| "existing Rust client custody refused")?;
    client
        .admit_before("alice@osmap-password.invalid", 0, deadline)
        .map_err(|_| "authenticated epoch exchange refused")?;
    if client.admit_before("alice@osmap-password.invalid", 1, deadline) != Err(Error::Refused) {
        return Err("noncurrent epoch refusal mismatch");
    }
    if Instant::now() >= deadline {
        return Err("original client deadline expired");
    }
    println!("native_stock_epoch_admission result=PASS authenticated_exchange=true epoch=0 noncurrent_epoch_refused=true credential_write=false full_workflow_qualified=false");
    Ok(())
}

/// Exercise the real constructor against local filesystem objects. Diagnostics
/// discriminate the rejected invariant without disclosing the object or key.
#[test]
#[ignore = "explicit subprocess fixture for actual constructor diagnostic and fixed HTTP panic"]
fn account_construction_diagnostic_emitter() {
    let root = fs::canonicalize(listener_root()).unwrap();
    let result = Client::qualified_files(
        &root.join("missing.sock"),
        &root.join("unused.key"),
        crate::openbsd::effective_uid(),
    );
    // Dispose of this empty, uniquely created directory before the deliberate
    // caller panic; no backend socket or credential file was created or read.
    fs::remove_dir(root).unwrap();
    result.expect("HTTP fixture admission custody refused");
}

#[test]
fn admission_construction_reports_precise_custody_failure() {
    use custody::Category;
    use ConstructionOperation as Op;
    let root = fs::canonicalize(listener_root()).unwrap();
    let socket = root.join("socket");
    let key = root.join("private-key-name");
    let uid = crate::openbsd::effective_uid();
    let check = |operation, invariant, category| {
        let failure = Client::qualified_files_detailed(&socket, &key, uid).unwrap_err();
        assert_eq!(failure.operation, operation);
        assert_eq!(failure.failure.check, invariant);
        assert_eq!(failure.failure.category, category);
        let mut output = Vec::new();
        failure.write_diagnostic(&mut output).unwrap();
        let line = String::from_utf8(output).unwrap();
        assert!(line.len() < 256);
        assert!(!line.contains(root.to_str().unwrap()));
        assert!(!line.contains("private-key-name"));
        assert!(!line.contains("SECRET_CUSTODY_TEST_MATERIAL"));
        let json: serde_json::Value = serde_json::from_str(
            line.strip_prefix("OSMAP_ACCOUNT_CONSTRUCTION_V1 ")
                .unwrap()
                .trim_end(),
        )
        .unwrap();
        assert_eq!(json.as_object().unwrap().len(), 4);
        assert_eq!(json["schema"], "osmap-account-construction-v1");
    };
    check(Op::SocketValidation, Check::Canonicalize, Category::Absent);
    fs::write(&socket, b"not a socket").unwrap();
    check(Op::SocketValidation, Check::SocketType, Category::Invariant);
    fs::remove_file(&socket).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    check(
        Op::SocketValidation,
        Check::SocketPermissions,
        Category::Invariant,
    );
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    check(Op::KeyLoad, Check::Canonicalize, Category::Absent);
    fs::write(&key, b"short").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    check(Op::KeyLoad, Check::KeyLength, Category::Invariant);
    fs::write(&key, b"SECRET_CUSTODY_TEST_MATERIAL_123456789").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
    check(Op::KeyLoad, Check::FilePermissions, Category::Invariant);
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&key, root.join("linked")).unwrap();
    check(Op::CustodyCapture, Check::KeyLinks, Category::Invariant);
    fs::remove_file(root.join("linked")).unwrap();
    let client = Client::qualified_files_detailed(&socket, &key, uid).unwrap();
    assert_eq!(client.0.paths.recheck(), Ok(()));
    drop(client);
    drop(listener);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn admission_custody_recheck_preserves_identity_and_content_reason() {
    let root = fs::canonicalize(listener_root()).unwrap();
    let socket = root.join("socket");
    let key = root.join("key");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    fs::write(&key, [29; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let client =
        Client::qualified_files_detailed(&socket, &key, crate::openbsd::effective_uid()).unwrap();
    fs::write(&key, [30; 32]).unwrap();
    assert_eq!(
        client.0.paths.recheck_detailed().unwrap_err().check,
        Check::KeyContent
    );
    fs::write(&key, [29; 32]).unwrap();
    let replacement = root.join("replacement");
    fs::write(&replacement, [29; 32]).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &key).unwrap();
    assert_eq!(
        client.0.paths.recheck_detailed().unwrap_err().check,
        Check::KeyDescriptorIdentity
    );
    drop(client);
    drop(listener);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn admission_diagnostic_sanitizes_io_errors_and_tolerates_broken_output() {
    use custody::Category;
    use std::io::{Error as IoError, ErrorKind};
    for (kind, category) in [
        (ErrorKind::NotFound, Category::Absent),
        (ErrorKind::PermissionDenied, Category::Denied),
        (ErrorKind::InvalidInput, Category::Invalid),
        (ErrorKind::TimedOut, Category::Deadline),
        (ErrorKind::Interrupted, Category::Interrupted),
        (ErrorKind::Other, Category::OtherIo),
    ] {
        let failure = ConstructionFailure::at(
            ConstructionOperation::KeyLoad,
            CustodyFailure::io(
                Check::FileOpen,
                IoError::new(kind, "/private/SECRET_IO_PAYLOAD"),
            ),
        );
        assert_eq!(failure.failure.category, category);
        assert!(!format!("{failure:?}").contains("SECRET_IO_PAYLOAD"));
        let mut output = Vec::new();
        failure.write_diagnostic(&mut output).unwrap();
        assert!(!String::from_utf8(output)
            .unwrap()
            .contains("SECRET_IO_PAYLOAD"));
        let mut full = &mut [][..];
        assert!(failure.write_diagnostic(&mut full).is_err());
        assert_eq!(failure.failure.category, category);
    }
}

#[test]
fn detailed_custody_preserves_legacy_inventory_errors_and_owner_rules() {
    let root = fs::canonicalize(listener_root()).unwrap();
    let key = root.join("key");
    fs::write(&key, b"short").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let uid = crate::openbsd::effective_uid();
    assert_eq!(secret(&key), Err(crate::openpgp_inventory::Error::Invalid));
    let error = custody::file(&key, uid.wrapping_add(1), false, 1024).unwrap_err();
    assert_eq!(
        error.check,
        if uid == 0 {
            Check::FileOwner
        } else {
            Check::AncestorOwner
        }
    );
    assert_eq!(
        error.into_original(),
        crate::openpgp_inventory::Error::Unavailable
    );
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&key, &alias).unwrap();
    assert_eq!(
        custody::exact_path(&alias, uid).unwrap_err().check,
        Check::CanonicalPath
    );
    assert_eq!(
        crate::openpgp_inventory_runtime::exact_path(&alias, uid),
        Err(crate::openpgp_inventory::Error::Invalid)
    );
    fs::remove_dir_all(root).unwrap();
}
