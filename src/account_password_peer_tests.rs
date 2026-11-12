use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
const ACCOUNT: &str = "alice@osmap-peer.invalid";
fn process(pid: u32, parent: u32, uid: u32, command: &str) -> Row {
    row(
        &format!("{pid} {parent} 10 {uid} {uid} Sun Oct 18 01:02:03 2026 {command}\n"),
        pid,
    )
    .unwrap()
}
fn pin() -> FilePin {
    FilePin {
        path: IMAP,
        dev: 0,
        inode: 42,
        mode: 0o100555,
        size: 100,
        modified: (0, 0),
        changed: (0, 0),
    }
}
fn header() -> &'static str {
    "USER CMD PID FD DEV INUM MODE R/W SZ|DV\n"
}

#[test]
fn exact_process_birth_parent_principal_and_executable_are_bound() {
    let master = process(10, 1, 0, "dovecot");
    assert!(main_master_argv("dovecot\n").is_ok());
    assert!(main_master_argv("/usr/local/sbin/dovecot -c /etc/dovecot/dovecot.conf\n").is_ok());
    for wrong in [
        "dovecot -c /tmp/other.conf\n",
        "dovecot -o passdb=other\n",
        "dovecot -c /etc/dovecot/dovecot.conf -o auth_cache_size=1\n",
    ] {
        assert!(main_master_argv(wrong).is_err());
    }

    assert!(private_primary_argv("auth -o auth_policy_server_url= -o auth_cache_size=0\n").is_ok());
    assert!(
        private_primary_argv("dovecot/auth -o auth_policy_server_url= -o auth_cache_size=0\n")
            .is_ok()
    );
    for wrong in [
        "auth\n",
        "auth -o auth_policy_server_url=http://bad -o auth_cache_size=0\n",
        "auth -o auth_policy_server_url= -o auth_cache_size=1\n",
    ] {
        assert!(private_primary_argv(wrong).is_err());
    }

    let own = process(30, 1, 0, "password-helper");
    let child = process(20, 10, 518, "imap");
    let rows = vec![master.clone(), child.clone(), own.clone()];
    assert_eq!(roles(&rows, &master, &own, (20, 518, 518)), Ok(()));
    for changed in [
        process(20, 11, 518, "imap"),
        process(20, 10, 519, "imap"),
        process(20, 10, 518, "sh"),
    ] {
        assert_eq!(
            roles(
                &[master.clone(), changed, own.clone()],
                &master,
                &own,
                (20, 518, 518)
            ),
            Err(Error::Refused)
        );
    }
    let private = process(21, 10, 519, "auth");
    assert_eq!(primary_worker(&private, &master, 519), Ok(()));
    assert!(primary_worker(&private, &master, 518).is_err());
    assert!(primary_worker(&process(21, 11, 519, "auth"), &master, 519).is_err());
    assert!(primary_worker(&process(21, 10, 519, "imap"), &master, 519).is_err());
    for raw in ["020 10 10 518 518 Sun Oct 18 01:02:03 2026 imap\n","20 10 10 518 518 Sun Oct 18 25:02:03 2026 imap\n","20 10 10 518 518 Sun Oct 18 01:02:03 2026 imap\n20 10 10 518 518 Sun Oct 18 01:02:03 2026 imap\n"]{assert!(row(raw,20).is_err());}
    let mut changed = rows.clone();
    changed[0].birth = "Sun Oct 18 01:02:04 2026".into();
    assert_eq!(
        roles(&changed, &master, &own, (20, 518, 518)),
        Err(Error::Refused)
    );
}

#[test]
fn exact_text_inode_and_reciprocal_accepted_descriptor_are_required() {
    let target = process(20, 10, 518, "imap");
    let raw = format!(
        "{}mail imap 20 text 0, 0 42 100555 r 100\nmail imap 20 7* unix stream 0x11 <-> 0x22\n",
        header()
    );
    let peer = descriptors(&raw, &target, &pin()).unwrap();
    let own = [(8, (0x22, 0x11))].into();
    assert_eq!(reciprocal(&own, &peer, 8), Ok((0x22, 0x11)));
    assert!(reciprocal(&own, &peer, 9).is_err());
    let master = process(10, 1, 0, "dovecot");
    let listening = format!("{}root dovecot 10 text 0, 0 42 100555 r 100\nroot dovecot 10 9* unix stream 0x55 {PRIMARY_SOCKET}\n", header());
    assert_eq!(primary_listener(&listening, &master, &pin()), Ok(0x55));
    assert!(primary_listener(&listening.replace("0x55", "0x00"), &master, &pin()).is_err());
    assert!(primary_listener(
        &listening.replace(PRIMARY_SOCKET, "/other"),
        &master,
        &pin()
    )
    .is_err());
    let mut wrong = peer.clone();
    wrong.insert(9, (0x11, 0x22));
    assert!(reciprocal(&own, &wrong, 8).is_err());
    for invalid in [
        raw.replace("42 100555", "43 100555"),
        raw.replace("0x11 <-> 0x22", "0x11 <-> 0x00"),
        raw.replace("7* unix", "7 unix"),
        raw.replace("imap 20 text", "sh 20 text"),
    ] {
        assert!(descriptors(&invalid, &target, &pin()).is_err());
    }
}

#[test]
fn actual_anvil_row_requires_single_exact_account_pid_and_count() {
    let row = format!("{WHO_HEADER}{ACCOUNT}\t1\timap\t(1234)\t(127.0.0.1)\n");
    assert_eq!(registered(&row, ACCOUNT, 1234), Ok(()));
    for invalid in [
        row.replace(ACCOUNT, "bob@osmap-peer.invalid"),
        row.replace("(1234)", "(1235)"),
        row.replace("(1234)", "(1234 1234)"),
        row.replace("\t1\timap", "\t2\timap"),
        row.replace("\timap\t", "\tsubmission\t"),
        format!("{row}{ACCOUNT}\t1\timap\t(1234)\t(127.0.0.1)\n"),
    ] {
        assert!(registered(&invalid, ACCOUNT, 1234).is_err());
    }
}

struct Never;
impl CommandExecutor for Never {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("foreign native factory dispatched command")
    }
}

#[test]
fn stock_leaf_witness_detects_real_file_socket_and_link_changes() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;
    let root = std::env::temp_dir().join(format!(
        "osmap-stock-leaf-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let config = root.join("config");
    fs::write(&config, b"original configuration").unwrap();
    let original = stock_leaf_identity(&fs::symlink_metadata(&config).unwrap());
    assert!(stock_leaf_unchanged(&config, &original, deadline).unwrap());
    fs::write(&config, b"changed configuration with different length").unwrap();
    assert!(!stock_leaf_unchanged(&config, &original, deadline).unwrap());
    assert!(stock_leaf_unchanged(&config, &original, Instant::now()).is_err());

    let link = root.join("runtime-config");
    symlink(&config, &link).unwrap();
    assert!(configuration_link_target(&link, &config, deadline).unwrap());
    assert!(!configuration_link_target(&link, &root.join("foreign"), deadline).unwrap());
    assert!(configuration_link_target(&link, &config, Instant::now()).is_err());
    let captured = stock_leaf_identity(&fs::symlink_metadata(&link).unwrap());
    fs::remove_file(&link).unwrap();
    symlink(root.join("foreign"), &link).unwrap();
    assert!(!stock_leaf_unchanged(&link, &captured, deadline).unwrap());

    let socket = root.join("auth");
    let listener = UnixListener::bind(&socket).unwrap();
    let captured = stock_leaf_identity(&fs::symlink_metadata(&socket).unwrap());
    assert!(stock_leaf_unchanged(&socket, &captured, deadline).unwrap());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let captured = stock_leaf_identity(&fs::symlink_metadata(&socket).unwrap());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(!stock_leaf_unchanged(&socket, &captured, deadline).unwrap());
    drop(listener);
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, b"not a socket").unwrap();
    assert!(!stock_leaf_unchanged(&socket, &captured, deadline).unwrap());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stock_kernel_peer_requires_root_user_and_group() {
    assert!(stock_root_peer((42, 0, 0)));
    assert!(!stock_root_peer((42, 518, 0)));
    assert!(!stock_root_peer((42, 0, 518)));
}

#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "operator-run root-only fixed stock constructor and recheck; no authentication"]
fn native_stock_constructor_and_recheck_use_no_process_metadata() -> Result<(), &'static str> {
    use std::sync::Arc;
    struct NoProcessMetadata(crate::account_password_process::MetadataExecutor);
    impl CommandExecutor for NoProcessMetadata {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            Err(CommandExecutionError {
                reason: "bounded metadata method required".into(),
            })
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            limit: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            if matches!(program, PS | FSTAT) {
                return Err(CommandExecutionError {
                    reason: "process metadata forbidden".into(),
                });
            }
            self.0
                .run_with_stdin_bytes_timeout_and_output_limit(program, args, input, timeout, limit)
        }
    }
    if !crate::openbsd::password_native_authority() {
        return Err("root OpenBSD authority required");
    }
    std::env::set_current_dir("/").map_err(|_| "fixed working directory unavailable")?;
    let executor = Arc::new(NoProcessMetadata(
        crate::account_password_process::MetadataExecutor::readonly(),
    ));
    let mut trace = crate::account_password_fstat::StartupTrace::new(
        crate::account_password_fstat::StartupOperation::ServiceStartup,
    );
    let admission_error = |error| match error {
        Error::Refused => crate::account_admission::Error::Refused,
        Error::Expired => crate::account_admission::Error::Expired,
        Error::Unavailable => crate::account_admission::Error::Unavailable,
    };
    let peer = StockPeer::observe(
        executor,
        Instant::now() + Duration::from_secs(10),
        &mut trace,
    )
    .map_err(|error| {
        trace.emit_metadata(&admission_error(error));
        "stock construction unavailable"
    })?;
    peer.recheck_with_trace(Instant::now() + Duration::from_secs(3), &mut trace)
        .map_err(|error| {
            trace.emit_metadata(&admission_error(error));
            "stock recheck unavailable"
        })?;
    if !matches!(peer.recheck(Instant::now()), Err(Error::Expired)) {
        return Err("expired recheck category refused");
    }
    Ok(())
}
#[test]
fn stock_runtime_constructor_retains_runtime_and_nested_recheck_failures() {
    use crate::account_password_connection::Keys;
    use crate::account_password_fstat::{StartupOperation as Op, StartupTrace};
    use crate::account_password_runtime::{StockRuntime, Unavailable};
    use crate::account_password_state::Store;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    // Deliberately incapable of native observation: both exercised guards must
    // refuse before any command, backend configuration or socket is accessed.
    let peer = Arc::new(StockPeer {
        master_pid: 10,
        auth: pin(),
        files: Vec::new(),
        server_uid: 518,
        server_gid: 518,
        selection: [0; 11],
        auth_snapshot: StockSocketSnapshot {
            endpoint: [0; 11],
            binder: (10, 0, 0),
        },
    });
    let root = std::env::temp_dir().join(format!(
        "osmap-runtime-trace-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let root = root.canonicalize().unwrap();
    let store = Arc::new(Store::open(&root, crate::openbsd::effective_uid()).unwrap());
    let valid_accounts = BTreeSet::from([ACCOUNT.to_owned()]);
    for (accounts, admission, connector) in [
        (valid_accounts.clone(), vec![b'a'; 31], 518),
        (valid_accounts.clone(), vec![b'a'; 32], 0),
        (valid_accounts.clone(), vec![b'a'; 32], u32::MAX),
        (BTreeSet::new(), vec![b'a'; 32], 518),
        (BTreeSet::from(["invalid".into()]), vec![b'a'; 32], 518),
    ] {
        let mut trace = StartupTrace::new(Op::MutationBind);
        assert!(matches!(
            StockRuntime::new(
                store.clone(),
                accounts,
                Keys::new([b'm'; 32], [b's'; 32]).unwrap(),
                &admission,
                connector,
                peer.clone(),
                Instant::now(),
                &mut trace,
            ),
            Err(Unavailable)
        ));
        assert_eq!(trace.tag(), "primary_fstat_service_startup_invalid");
    }
    for (deadline, expected) in [
        (Instant::now(), "primary_fstat_before_recheck_deadline"),
        (
            Instant::now() + Duration::from_secs(5),
            "primary_fstat_before_recheck_invalid",
        ),
    ] {
        let mut trace = StartupTrace::new(Op::MutationBind);
        assert!(matches!(
            StockRuntime::new(
                store.clone(),
                valid_accounts.clone(),
                Keys::new([b'm'; 32], [b's'; 32]).unwrap(),
                &[b'a'; 32],
                518,
                peer.clone(),
                deadline,
                &mut trace,
            ),
            Err(Unavailable)
        ));
        assert_eq!(trace.tag(), expected);
    }
    drop(store);
    fs::remove_dir(root).unwrap();
}
#[test]
fn unknown_native_authority_never_creates_peer_or_dispatches_metadata() {
    if !crate::openbsd::password_native_authority() {
        assert!(Startup::native(&Never, 10, Instant::now() + Duration::from_millis(500)).is_err());
    }
    assert_eq!(ps_args(1234), vec!["-p", "1234", "-o", PS_FIELDS]);
    assert_eq!(fstat_args(1234), vec!["-n", "-p", "1234"]);
}

#[test]
fn stock_configuration_optional_presence_is_closed_and_membership_changes_refuse() {
    use std::io::ErrorKind;
    let deadline = Instant::now() + Duration::from_secs(2);
    let selected = stock_configuration_paths_with(deadline, |path| {
        stock_configuration_presence(
            path,
            if STOCK_OPTIONAL_CONFIGURATION_PATHS.contains(&path) {
                Err(ErrorKind::NotFound)
            } else {
                Ok(true)
            },
        )
    })
    .unwrap();
    assert_eq!(selected.len(), 23);
    let files = selected
        .iter()
        .map(|&path| PrimaryFile {
            path,
            identity: [0; 11],
            digest: [0; 32],
        })
        .collect::<Vec<_>>();
    let names = selected
        .iter()
        .filter(|path| path.starts_with("/etc/dovecot/conf.d/") && path.ends_with(".conf"))
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    assert!(primary_include_names_match(&names, &files).is_ok());
    for path in STOCK_OPTIONAL_CONFIGURATION_PATHS {
        assert_eq!(stock_configuration_presence(path, Ok(true)), Ok(true));
        assert!(stock_configuration_presence(path, Ok(false)).is_err()); // symlink/nonfile
        assert!(stock_configuration_presence(path, Err(ErrorKind::PermissionDenied)).is_err());
        let mut appeared = names.clone();
        appeared.insert((*path).to_owned()); // also represents a broken symlink name
        assert!(primary_include_names_match(&appeared, &files).is_err());
    }
    for path in [
        "/etc/dovecot/dovecot.conf",
        "/etc/dovecot/conf.d/99-unapproved.conf",
    ] {
        assert!(stock_configuration_presence(path, Err(ErrorKind::NotFound)).is_err());
    }
    let mut disappeared = names.clone();
    disappeared.remove("/etc/dovecot/conf.d/10-auth.conf");
    assert!(primary_include_names_match(&disappeared, &files).is_err());
    assert!(stock_configuration_paths_with(Instant::now(), |_| panic!(
        "expired before observation"
    ))
    .is_err());
}

#[test]
fn primary_configuration_membership_is_fixed_and_control_is_separately_required() {
    // These are graph-policy inputs, not native file or loaded-config witnesses.
    let files = |control: bool| {
        PRIMARY_CONFIGURATION_PATHS
            .iter()
            .copied()
            .filter(|path| control || *path != CONTROL_FRAGMENT)
            .map(|path| PrimaryFile {
                path,
                identity: [0; 11],
                digest: [0; 32],
            })
            .collect::<Vec<_>>()
    };
    let names = |files: &[PrimaryFile]| {
        files
            .iter()
            .map(|file| file.path)
            .filter(|path| path.starts_with("/etc/dovecot/conf.d/") && path.ends_with(".conf"))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    };
    let primary = files(false);
    let control = files(true);
    assert_eq!(primary.len(), 26);
    assert_eq!(control.len(), 27);
    assert!(primary_include_names_match(&names(&primary), &primary).is_ok());
    assert!(primary_include_names_match(&names(&control), &control).is_ok());
    // The same captured graph rejects either subsequent membership transition.
    assert!(primary_include_names_match(&names(&control), &primary).is_err());
    assert!(primary_include_names_match(&names(&primary), &control).is_err());
    let mut extra = names(&primary);
    extra.insert("/etc/dovecot/conf.d/99-unobserved.conf".to_owned());
    assert!(primary_include_names_match(&extra, &primary).is_err());
    assert!(captured_control_configuration(&primary).is_err());
    assert!(captured_control_configuration(&control).is_ok());
}

#[test]
fn diagnostic_stages_preserve_original_startup_refusal_without_metadata_dispatch() {
    let startup = Startup {
        master: process(10, 1, 0, "dovecot"),
        // Deliberately foreign current process identity; refusal precedes all I/O.
        own: process(std::process::id().saturating_add(1), 1, 0, "account-passwd"),
        pins: Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut stage = "not_observed";
    let result = PrimaryPeer::observe(std::sync::Arc::new(Never), &startup, deadline, &mut stage);
    assert!(matches!(result, Err(Error::Refused)));
    assert_eq!(stage, "primary_startup_recheck");
    stage = "not_observed";
    let result = socket_probe_with_stage(
        &Never,
        &startup,
        &pin(),
        PRIMARY_SOCKET,
        "auth",
        518,
        518,
        deadline,
        &mut stage,
    );
    assert!(matches!(result, Err(Error::Refused)));
    assert_eq!(stage, "primary_probe_startup");
    // The existing untagged consumer retains precisely the same closed refusal.
    assert!(matches!(
        socket_probe(
            &Never,
            &startup,
            &pin(),
            PRIMARY_SOCKET,
            "auth",
            518,
            518,
            deadline
        ),
        Err(Error::Refused)
    ));
}

#[test]
fn cold_primary_zero_then_one_keeps_the_same_held_stream_and_deadline() {
    let (held, _other) = UnixStream::pair().unwrap();
    let fd = held.as_raw_fd();
    let deadline = Instant::now() + Duration::from_secs(1);
    let expected = process(20, 10, 518, "auth");
    let mut calls = 0;
    let mut stage = "initial";
    let worker = ready_socket_worker(PRIMARY_SOCKET, deadline, &mut stage, |end, _| {
        assert_eq!(end, deadline);
        assert_eq!(held.as_raw_fd(), fd);
        calls += 1;
        Ok(if calls == 1 {
            vec![]
        } else {
            vec![expected.clone()]
        })
    })
    .unwrap();
    assert_eq!(worker.pid, expected.pid);
    assert_eq!(calls, 2);
    assert_eq!(held.as_raw_fd(), fd);
    assert_eq!(stage, "primary_probe_unique_worker");
}

#[test]
fn cold_primary_permanent_zero_expires_without_renewing_deadline() {
    let deadline = Instant::now() + Duration::from_millis(4);
    let mut stage = "initial";
    assert!(matches!(
        ready_socket_worker(PRIMARY_SOCKET, deadline, &mut stage, |end, _| {
            assert_eq!(end, deadline);
            Ok(vec![])
        }),
        Err(Error::Expired)
    ));
}

#[test]
fn cold_primary_ambiguity_and_observer_error_never_retry() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut stage = "initial";
    let mut calls = 0;
    let worker = process(20, 10, 518, "auth");
    assert!(matches!(
        ready_socket_worker(PRIMARY_SOCKET, deadline, &mut stage, |_, _| {
            calls += 1;
            Ok(vec![worker.clone(), worker.clone()])
        }),
        Err(Error::Refused)
    ));
    assert_eq!(calls, 1);
    calls = 0;
    assert!(matches!(
        ready_socket_worker(PRIMARY_SOCKET, deadline, &mut stage, |_, stage| {
            calls += 1;
            *stage = "primary_probe_worker_descriptors";
            Err(Error::Refused)
        }),
        Err(Error::Refused)
    ));
    assert_eq!(calls, 1);
    assert_eq!(stage, "primary_probe_worker_descriptors");
}

#[test]
fn cold_primary_late_sole_worker_is_not_accepted_and_other_roles_do_not_wait() {
    let deadline = Instant::now() + Duration::from_millis(4);
    let mut stage = "initial";
    assert!(matches!(
        ready_socket_worker(PRIMARY_SOCKET, deadline, &mut stage, |end, _| {
            std::thread::sleep(end.saturating_duration_since(Instant::now()));
            Ok(vec![process(20, 10, 518, "auth")])
        }),
        Err(Error::Expired)
    ));
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut calls = 0;
    assert!(matches!(
        ready_socket_worker(
            "/var/dovecot/osmap-account-auth-master",
            deadline,
            &mut stage,
            |end, _| {
                assert_eq!(end, deadline);
                calls += 1;
                Ok(vec![])
            }
        ),
        Err(Error::Refused)
    ));
    assert_eq!(calls, 1);
}

#[test]
fn sealed_recheck_diagnostic_query_discriminates_only_fixed_failed_guard() {
    struct Reply {
        code: i32,
        out: String,
        err: String,
        failure: Option<String>,
    }
    impl CommandExecutor for Reply {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            Err(CommandExecutionError {
                reason: "unexpected unbounded dispatch".into(),
            })
        }

        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
            _: Duration,
            _: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            if let Some(reason) = &self.failure {
                return Err(CommandExecutionError {
                    reason: reason.clone(),
                });
            }
            Ok(CommandExecution {
                status_code: self.code,
                stdout: self.out.clone(),
                stderr: self.err.clone(),
            })
        }
    }
    let mut reply = Reply {
        code: 0,
        out: "fixed public metadata\n".into(),
        err: String::new(),
        failure: None,
    };
    let mut stage = "primary_startup_master_fstat";
    let deadline = || Instant::now() + Duration::from_millis(500);
    assert!(query_with_stage(&reply, FSTAT, &fstat_args(10), deadline(), &mut stage).is_ok());
    assert_eq!(stage, "primary_startup_master_fstat");
    use crate::account_password_fstat::{
        StartupCategory as Cat, StartupOperation as Op, StartupTrace,
    };
    let mut trace = StartupTrace::new(Op::StockMasterRow);
    assert_eq!(
        stock_query(&reply, PS, &ps_args(10), deadline(), &mut trace).unwrap(),
        reply.out
    );
    assert_eq!(trace.tag(), "primary_fstat_stock_master_row_unknown");
    for (code, out, err, expected) in [
        (1, "fixed\n", "", "metadata_query_exit"),
        (0, "fixed\n", "not retained", "metadata_query_stderr"),
        (0, "", "", "metadata_query_output"),
        (0, "\0", "", "metadata_query_output"),
    ] {
        reply.code = code;
        reply.out = out.into();
        reply.err = err.into();
        stage = "primary_startup_master_fstat";
        assert_eq!(
            query_with_stage(&reply, FSTAT, &fstat_args(10), deadline(), &mut stage),
            Err(Error::Unavailable)
        );
        assert_eq!(
            stage,
            crate::account_password_process::metadata_phase_failure(
                "primary_startup_master_fstat",
                expected
            )
            .unwrap()
        );
        let mut trace = StartupTrace::new(Op::StockWorkerArgv);
        assert_eq!(
            stock_query(&reply, PS, &ps_args(10), deadline(), &mut trace),
            Err(Error::Unavailable)
        );
        assert_eq!(trace.metadata_detail(), Some(expected));
    }
    reply.failure = Some("metadata_ps_row_denied".into());
    assert!(stock_query(&reply, PS, &ps_args(10), deadline(), &mut trace).is_err());
    trace.category_if_unknown(Cat::Invalid);
    assert_eq!(trace.tag(), "primary_fstat_stock_master_row_denied");
    stage = "primary_startup_master_row";
    assert!(query_with_stage(&reply, PS, &ps_args(10), deadline(), &mut stage).is_err());
    assert_eq!(stage, "primary_startup_master_row_denied");
    stage = "primary_startup_own_row";
    assert!(query_with_stage(&reply, PS, &ps_args(10), deadline(), &mut stage).is_err());
    assert_eq!(stage, "primary_startup_own_row_denied");
    reply.failure = Some("untrusted private text".into());
    let mut trace = StartupTrace::new(Op::StockMasterRow);
    assert!(stock_query(&reply, PS, &ps_args(10), deadline(), &mut trace).is_err());
    assert_eq!(trace.tag(), "primary_fstat_stock_master_row_unknown");
    stage = "primary_startup_master_fstat";
    assert!(query_with_stage(&reply, FSTAT, &fstat_args(10), deadline(), &mut stage).is_err());
    assert_eq!(stage, "primary_startup_master_fstat");

    for detail in [
        "metadata_builder_denied",
        "metadata_spawn_denied",
        "metadata_child_io_denied",
        "metadata_child_deadline",
        "metadata_child_cleanup",
    ] {
        reply.failure = Some(detail.into());
        let mut trace = StartupTrace::new(Op::StockWorkerArgv);
        assert_eq!(
            stock_query(&reply, PS, &ps_args(10), deadline(), &mut trace),
            Err(Error::Unavailable)
        );
        assert_eq!(trace.metadata_detail(), Some(detail));
    }
    let mut trace = StartupTrace::new(Op::StockWorkerArgv);
    assert_eq!(
        stock_query(&reply, PS, &ps_args(10), Instant::now(), &mut trace),
        Err(Error::Expired)
    );
    assert_eq!(trace.metadata_detail(), Some("metadata_query_deadline"));
}

#[test]
fn stock_worker_argv_validation_preserves_identity_and_classifies_value_refusal() {
    use crate::account_password_fstat::{StartupOperation as Op, StartupTrace};
    for raw in [
        "auth\n",
        "dovecot/auth\n",
        "/usr/local/libexec/dovecot/auth\n",
    ] {
        let mut trace = StartupTrace::new(Op::StockWorkerArgv);
        assert!(stock_auth_argv(raw, &mut trace).is_ok());
        assert_eq!(trace.metadata_detail(), None);
    }
    for raw in [
        "",
        "auth --arbitrary-option\n",
        "auth\nauth\n",
        "untrusted-auth\n",
    ] {
        let mut trace = StartupTrace::new(Op::StockWorkerArgv);
        assert_eq!(stock_auth_argv(raw, &mut trace), Err(Error::Refused));
        assert_eq!(trace.tag(), "primary_fstat_stock_worker_argv_invalid");
        assert_eq!(trace.metadata_detail(), None);
    }
}
