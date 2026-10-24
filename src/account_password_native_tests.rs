use super::*;

#[test]
fn installed_cache_admission_skips_only_cold_callers_duplicate_verification() {
    let cache = std::sync::OnceLock::new();
    let stage = Cell::new("metadata_parent_graph_unknown");
    let deadline = Instant::now() + Duration::from_secs(5);
    let captured = Cell::new(0);
    let rechecked = Cell::new(0);
    let first = cached_graph(
        &cache,
        deadline,
        &stage,
        || {
            captured.set(captured.get() + 1);
            Ok(7u8)
        },
        |_, _| {
            rechecked.set(rechecked.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(*first, 7);
    assert_eq!(captured.get(), 1);
    assert_eq!(rechecked.get(), 0);
    let second = cached_graph(
        &cache,
        deadline,
        &stage,
        || panic!("admitted cache must not be captured again"),
        |value, inherited| {
            assert_eq!(*value, 7);
            assert_eq!(inherited, deadline);
            rechecked.set(rechecked.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert!(std::ptr::eq(first, second));
    assert_eq!(rechecked.get(), 1);
    assert!(cached_graph(
        &cache,
        deadline,
        &stage,
        || panic!("changed cache must not be recaptured"),
        |_, _| Err(Unavailable),
    )
    .is_err());
}

#[test]
fn installed_cache_admission_concurrent_consumer_rechecks_after_initializer() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let cache = std::sync::OnceLock::new();
    let rechecks = AtomicUsize::new(0);
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let (consumer_tx, consumer_rx) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|scope| {
        let cache = &cache;
        let first = scope.spawn(move || {
            cached_graph(
                cache,
                Instant::now() + Duration::from_secs(5),
                &Cell::new("metadata_parent_graph_unknown"),
                || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    Ok(7u8)
                },
                |_, _| panic!("initializing caller already verified in capture"),
            )
            .copied()
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let count = &rechecks;
        let consumer = scope.spawn(move || {
            consumer_tx.send(()).unwrap();
            cached_graph(
                cache,
                Instant::now() + Duration::from_secs(5),
                &Cell::new("metadata_parent_graph_unknown"),
                || panic!("other initializer owns the capture"),
                |value, _| {
                    assert_eq!(*value, 7);
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .copied()
        });
        consumer_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(7));
        assert_eq!(consumer.join().unwrap(), Ok(7));
    });
    assert_eq!(rechecks.load(Ordering::SeqCst), 1);
}

#[test]
fn installed_cache_admission_preserves_failed_capture_and_deadline_refusal() {
    let failed = std::sync::OnceLock::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let stage = Cell::new("metadata_parent_graph_unknown");
    assert!(cached_graph(
        &failed,
        deadline,
        &stage,
        || Err::<u8, _>(Unavailable),
        |_, _| panic!("failed graph must never be rechecked or used"),
    )
    .is_err());
    assert!(cached_graph(
        &failed,
        deadline,
        &stage,
        || panic!("failed capture must not be silently retried"),
        |_, _| panic!("failed graph must never be used"),
    )
    .is_err());
    let empty: std::sync::OnceLock<Result<u8, Unavailable>> = std::sync::OnceLock::new();
    assert!(cached_graph(
        &empty,
        Instant::now(),
        &stage,
        || panic!("expired deadline must precede capture"),
        |_, _| panic!("expired deadline must precede recheck"),
    )
    .is_err());
    assert!(empty.get().is_none());
    assert_eq!(stage.get(), "metadata_parent_graph_deadline");
    let finished_late = std::sync::OnceLock::new();
    let deadline = Instant::now() + Duration::from_millis(1);
    assert!(cached_graph(
        &finished_late,
        deadline,
        &stage,
        || {
            while Instant::now() < deadline {
                std::thread::yield_now();
            }
            Ok(7u8)
        },
        |_, _| panic!("late cold caller must not add a renewed verification"),
    )
    .is_err());
}

#[test]
fn parent_graph_trace_retains_parent_identity_fixed_phase_and_actual_deadline() {
    use crate::account_password_fstat::{StartupOperation as Op, StartupTrace};
    let mut trace = StartupTrace::new(Op::ParentPrepare);
    assert_eq!(Op::ParentPrepare as u8, 35);
    assert!(stock_parent_rules_with_trace(Instant::now(), &mut trace).is_err());
    assert_eq!(trace.tag(), "primary_fstat_parent_prepare_deadline");
    assert_eq!(
        trace.metadata_detail(),
        Some("metadata_parent_graph_deadline")
    );
    for program in [
        crate::account_password_backend::SQL_PROGRAM,
        crate::account_password_backend::HASH_PROGRAM,
    ] {
        for phase in [
            GraphPhase::Sources,
            GraphPhase::Resolve,
            GraphPhase::Closure,
            GraphPhase::Files,
            GraphPhase::Directories,
        ] {
            let stage = Cell::new("metadata_parent_graph_unknown");
            graph_stage(program, phase, &stage);
            assert_eq!(
                crate::account_password_process::metadata_failure_tag(stage.get()),
                Some(stage.get())
            );
            let mut unknown = StartupTrace::new(Op::ParentPrepare);
            unknown.metadata(stage.get());
            unknown.metadata_error(crate::account_admission::Error::Unavailable);
            unknown.metadata("metadata_parent_graph_deadline");
            unknown.cleanup_failed();
            let mut bytes = Vec::new();
            unknown
                .write_diagnostic(
                    &mut bytes,
                    &crate::account_admission::Error::CleanupUnconfirmed,
                    true,
                )
                .unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains("stage=primary_fstat_parent_prepare_unknown"));
            assert!(text.contains(stage.get()));
            assert!(text.contains("error=Unavailable cleanup=unconfirmed"));
            assert_eq!(unknown.metadata_detail(), Some(stage.get()));
        }
    }
}

#[test]
fn selected_parent_resolves_sql_hash_only_and_legacy_keeps_fstat() {
    use crate::account_password_backend::{HASH_PROGRAM, SQL_PROGRAM};
    for (selection, expected) in [
        (ParentGraphs::Stock, vec![SQL_PROGRAM, HASH_PROGRAM]),
        (
            ParentGraphs::Legacy,
            vec![SQL_PROGRAM, HASH_PROGRAM, "/usr/bin/fstat"],
        ),
    ] {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut observed = Vec::new();
        // Exercise the actual rule producer's graph selection/union. Native
        // installed graph discovery and OpenBSD sealing are separate proofs.
        let rules = parent_rules_with(selection, deadline, |program, inherited| {
            assert_eq!(inherited, deadline);
            observed.push(program);
            Ok(vec![
                (program.to_owned(), "rx"),
                ("/usr/lib/libc.so.current".to_owned(), "r"),
            ])
        })
        .unwrap();
        assert_eq!(observed, expected);
        for required in [SQL_PROGRAM, HASH_PROGRAM] {
            assert!(rules
                .iter()
                .any(|(path, access)| path == required && *access == "rx"));
        }
        for required in [
            SQL_CONFIG,
            SQL_PLAN,
            SQL_SOCKET,
            pins::MODULE_DIRECTORY,
            pins::SEARCH_DIRECTORY,
        ] {
            assert!(rules.iter().any(|(path, _)| path == required));
        }
        let stock = matches!(selection, ParentGraphs::Stock);
        assert_eq!(
            rules.iter().any(|(path, _)| path == "/usr/bin/fstat"),
            !stock
        );
        assert!(!rules.iter().any(|(path, _)| path == "/bin/ps"));
        assert_eq!(
            rules.iter().any(
                |(path, access)| path == crate::account_password_mail::STOCK_AUTH
                    && *access == "rw"
            ),
            stock
        );
        for private in [
            PRIMARY_SOCKET,
            CONTROL_AUTH,
            CONTROL_ANVIL,
            crate::account_password_topology::IPC,
        ] {
            assert_eq!(rules.iter().any(|(path, _)| path == private), !stock);
        }
        assert!(!rules
            .iter()
            .any(|(path, _)| matches!(path.as_str(), "/" | "/usr/lib" | "/usr/local/lib")));
    }
}

#[test]
fn selected_parent_refuses_failed_backend_graph_and_original_deadline() {
    use crate::account_password_backend::{HASH_PROGRAM, SQL_PROGRAM};
    for failed in [SQL_PROGRAM, HASH_PROGRAM] {
        let mut observed = Vec::new();
        let result = parent_rules_with(
            ParentGraphs::Stock,
            Instant::now() + Duration::from_secs(1),
            |program, _| {
                observed.push(program);
                if program == failed {
                    Err(Unavailable)
                } else {
                    Ok(vec![(program.to_owned(), "rx")])
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(observed.last(), Some(&failed));
        assert!(!observed.contains(&"/usr/bin/fstat"));
    }
    assert!(
        parent_rules_with(ParentGraphs::Stock, Instant::now(), |_, _| {
            panic!("expired parent deadline must refuse before graph discovery")
        })
        .is_err()
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut calls = 0;
    assert!(
        parent_rules_with(ParentGraphs::Legacy, deadline, |program, inherited| {
            calls += 1;
            assert_eq!(inherited, deadline);
            if program == "/usr/bin/fstat" {
                Err(Unavailable)
            } else {
                Ok(vec![(program.to_owned(), "rx")])
            }
        })
        .is_err()
    );
    assert_eq!(calls, 3, "legacy parent must still require its fstat graph");
}

#[test]
fn stock_primary_role_keeps_fixed_socket_command_and_separate_material() {
    use crate::account_password_backend::{HASH_PROGRAM, SQL_PROGRAM};
    let mut original = crate::account_password_mail::PRIMARY
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<_>>();
    original.push("alice@example.test".into());
    let actual = crate::account_password_mail::stock_args(&original, true).unwrap();
    assert!(matches_command(Role::StockPrimary, HASH_PROGRAM, &actual));
    assert!(!matches_command(Role::StockPrimary, SQL_PROGRAM, &actual));
    assert!(!matches_command(
        Role::StockPrimary,
        HASH_PROGRAM,
        &original
    ));
    let mut foreign = actual.clone();
    *foreign.last_mut().unwrap() = "alice@example.test;whoami".into();
    assert!(!matches_command(Role::StockPrimary, HASH_PROGRAM, &foreign));
    let mut extra = actual;
    extra.push("-o".into());
    assert!(!matches_command(Role::StockPrimary, HASH_PROGRAM, &extra));
    let plan = prepared_paths(
        Role::StockPrimary,
        (518, 518),
        Instant::now() + Duration::from_secs(1),
        &[HASH_PROGRAM, "/usr/lib/libc.so.current"],
    )
    .unwrap();
    assert_eq!(plan.ids(), (518, 518));
    assert!(plan.rules().iter().any(|(path, access)| path.to_bytes()
        == crate::account_password_mail::STOCK_AUTH.as_bytes()
        && access.to_bytes() == b"rw"));
    for (path, access) in plan.rules() {
        assert_ne!(path.to_bytes(), SQL_CONFIG.as_bytes());
        assert_ne!(path.to_bytes(), b"/etc/passwd");
        assert_ne!(path.to_bytes(), b"/bin/ps");
        assert_ne!(path.to_bytes(), b"/usr/bin/fstat");
        if access.to_bytes().contains(&b'x') {
            assert_eq!(path.to_bytes(), HASH_PROGRAM.as_bytes());
        }
        if access.to_bytes().contains(&b'c') {
            assert_eq!(path.to_bytes(), b"/dev/null");
        }
    }
}

#[test]
fn fixed_authority_never_exposes_system_library_directories() {
    let rules = fixed_parent_rules();
    assert!(!rules
        .iter()
        .any(|(path, _)| matches!(path.as_str(), "/usr/lib" | "/usr/local/lib" | "/dev" | "/")));
}

#[test]
fn parent_main_selection_link_has_only_fixed_directory_read_authority() {
    // Exercise the actual fixed union consumed by ParentPlan::prepare.
    let rules = fixed_parent_rules();
    assert_eq!(
        rules
            .iter()
            .filter(|(path, _)| *path == "/var/dovecot")
            .cloned()
            .collect::<Vec<_>>(),
        vec![("/var/dovecot".to_owned(), "r")]
    );
    assert!(!rules
        .iter()
        .any(|(path, _)| matches!(path.as_str(), "/var" | "/")));
}

#[test]
fn native_roles_keep_exact_separate_commands_and_existing_permission_boundaries() {
    use crate::account_password_backend::{HASH_ARGS, HASH_PROGRAM, SQL_ARGS, SQL_PROGRAM};
    let strings = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(matches_command(Role::Sql, SQL_PROGRAM, &strings(SQL_ARGS)));
    assert!(!matches_command(
        Role::Sql,
        HASH_PROGRAM,
        &strings(HASH_ARGS)
    ));
    assert!(matches_command(
        Role::Hash,
        HASH_PROGRAM,
        &strings(HASH_ARGS)
    ));
    assert!(!matches_command(
        Role::Hash,
        "/usr/bin/id",
        &strings(&["-u"])
    ));
    let mut primary = strings(crate::account_password_mail::PRIMARY);
    primary.push("alice@example.test".into());
    assert!(matches_command(Role::Primary, HASH_PROGRAM, &primary));
    *primary.last_mut().unwrap() = "alice@example.test;whoami".into();
    assert!(!matches_command(Role::Primary, HASH_PROGRAM, &primary));
    let deadline = Instant::now() + Duration::from_secs(1);
    let sql = prepared_paths(
        Role::Sql,
        (1008, 1008),
        deadline,
        &[SQL_PROGRAM, "/usr/lib/libc.so.current"],
    )
    .unwrap();
    assert_eq!(sql.ids(), (1008, 1008));
    assert!(!sql.promises().to_bytes().windows(5).any(|v| v == b"wpath"));
    for (path, access) in sql.rules() {
        if access.to_bytes().contains(&b'w') {
            assert_eq!(path.to_bytes(), SQL_SOCKET.as_bytes());
        }
        assert!(!access.to_bytes().contains(&b'c'));
    }
    for role in [Role::Hash, Role::Primary, Role::Control] {
        let plan = prepared_paths(
            role,
            (1005, 1005),
            deadline,
            &[HASH_PROGRAM, "/usr/lib/libc.so.current"],
        )
        .unwrap();
        for (path, access) in plan.rules() {
            if access.to_bytes().contains(&b'c') {
                assert_eq!(path.to_bytes(), b"/dev/null");
                assert_eq!(access.to_bytes(), b"rwc");
            }
            if path.to_bytes() == pins::SEARCH_DIRECTORY.as_bytes()
                || path.to_bytes() == pins::MODULE_DIRECTORY.as_bytes()
            {
                assert_eq!(access.to_bytes(), b"r");
            }
            assert_ne!(path.to_bytes(), SQL_CONFIG.as_bytes());
            assert_ne!(path.to_bytes(), b"/etc/passwd");
        }
    }
}

#[test]
fn purpose_identity_refuses_alias_supplemental_and_shared_numeric_authority() {
    let passwd =
        b"root:*:0:0:root:/root:/bin/ksh\n_osmaphash:*:1005:1005:Hash:/var/empty:/sbin/nologin\n";
    let group = b"wheel:*:0:root\n_osmaphash:*:1005:\n";
    assert_eq!(selected(passwd, group, b"_osmaphash"), Ok((1005, 1005)));
    for bad in [
        [group.as_slice(), b"other:*:2000: _osmaphash \n"].concat(),
        [group.as_slice(), b"alias:*:1005:\n"].concat(),
    ] {
        assert!(selected(passwd, &bad, b"_osmaphash").is_err());
    }
    assert!(selected(
        &[
            passwd.as_slice(),
            b"alias:*:1005:2000:alias:/var/empty:/sbin/nologin\n"
        ]
        .concat(),
        group,
        b"_osmaphash"
    )
    .is_err());
    assert!(selected(
        &[
            passwd.as_slice(),
            b"other:*:invalid:2000:alias:/var/empty:/sbin/nologin\n"
        ]
        .concat(),
        group,
        b"_osmaphash"
    )
    .is_err());
}

#[test]
fn sql_material_language_refuses_include_remote_extra_or_duplicate_options() {
    let plan=br#"{"version":1,"authority":"mail.blackbagsecurity.com","purpose":"osmap-account-mutation","server":"_mysql","socket":"/var/run/mysql/mysql.sock","database_user":"osmap_account_mutation"}"#;
    valid_plan(plan).unwrap();
    let config=b"[client]\nuser=osmap_account_mutation\npassword=public_synthetic_0123456789\nprotocol=SOCKET\nsocket=/var/run/mysql/mysql.sock\n";
    valid_config(config).unwrap();
    for bad in [
        [config.as_slice(), b"!include=/etc/master.passwd\n"].concat(),
        String::from_utf8(config.to_vec())
            .unwrap()
            .replace("protocol=SOCKET", "protocol=TCP")
            .into_bytes(),
        String::from_utf8(config.to_vec())
            .unwrap()
            .replace("socket=/var/run/mysql/mysql.sock", "user=other")
            .into_bytes(),
    ] {
        assert!(valid_config(&bad).is_err());
    }
    let duplicate = std::str::from_utf8(plan)
        .unwrap()
        .replacen("{", "{\"version\":1,", 1);
    assert!(valid_plan(duplicate.as_bytes()).is_err());
}

#[test]
fn production_factory_remains_off_and_primary_peer_is_not_inferred() {
    const { assert!(!NATIVE_QUALIFIED) };
    assert!(PRIMARY_PEER_UID.is_none());
    for role in [Role::Sql, Role::Hash, Role::Primary, Role::Control] {
        assert!(NativeProfile::fixed(role, Instant::now() + Duration::from_secs(1)).is_err());
    }
}

#[test]
fn sql_role_requires_unique_locked_identity_and_exact_readonly_private_grant() {
    let passwd = b"root:*:0:0:root:/root:/bin/ksh\n_mysql:*:502:502:Database:/var/empty:/sbin/nologin\n_osmapsql:*:1008:1008:SQL:/var/empty:/sbin/nologin\n";
    let group = b"wheel:*:0:root\n_mysql:*:502:\n_osmapsql:*:1008:\n";
    assert_eq!(selected(passwd, group, b"_osmapsql"), Ok((1008, 1008)));
    for bad in [
        [
            passwd.as_slice(),
            b"alias:*:1008:2000:Alias:/var/empty:/sbin/nologin\n",
        ]
        .concat(),
        String::from_utf8(passwd.to_vec())
            .unwrap()
            .replace("SQL:/var/empty:/sbin/nologin", "SQL:/root:/bin/ksh")
            .into_bytes(),
    ] {
        assert!(selected(&bad, group, b"_osmapsql").is_err());
    }
    for bad in [
        [group.as_slice(), b"extra:*:2000:_osmapsql\n"].concat(),
        [group.as_slice(), b"alias:*:1008:\n"].concat(),
    ] {
        assert!(selected(passwd, &bad, b"_osmapsql").is_err());
    }
    assert!(sql_config_metadata(0, 1008, 0o100440, 1, 1008));
    for (uid, gid, mode, links) in [
        (1008, 1008, 0o100440, 1),
        (0, 1009, 0o100440, 1),
        (0, 1008, 0o100640, 1),
        (0, 1008, 0o100444, 1),
        (0, 1008, 0o100440, 2),
        (0, 1008, 0o104440, 1),
        (0, 1008, 0o100600, 1),
    ] {
        assert!(!sql_config_metadata(uid, gid, mode, links, 1008));
    }
    let ids = (1008, 1008);
    assert!(role_permission(0, 1008, 0o100440, ids, 4));
    assert!(!role_permission(0, 0, 0o100600, ids, 4));
    assert!(!role_permission(0, 1008, 0o100440, ids, 2));
    assert!(!role_permission(0, 1009, 0o140660, ids, 2));
    assert!(role_permission(502, 502, 0o140666, ids, 2));
    let traversable = vec![("/etc/osmap".into(), [1, 2, 0, 1008, 0o040710])];
    assert!(role_traverses(&traversable, ids));
    assert!(!role_traverses(
        &[("/etc/osmap".into(), [1, 2, 0, 0, 0o040700])],
        ids
    ));
}

#[cfg(target_os = "openbsd")]
#[test]
#[ignore = "operator-run root-only installed dependency admission; no credentials or service mutation"]
fn installed_dependency_graphs_admit_current_trusted_system() {
    assert!(crate::openbsd::password_native_authority());
    let started = Instant::now();
    let deadline = started + Duration::from_secs(5);
    for program in [
        "/usr/bin/fstat",
        crate::account_password_backend::HASH_PROGRAM,
        crate::account_password_backend::SQL_PROGRAM,
    ] {
        eprintln!("DEPENDENCY_ADMISSION_PROGRAM={program}");
        let admitted =
            installed_graph(program, deadline).expect("trusted installed dependency admission");
        assert!(!admitted.files.is_empty());
        admitted
            .recheck(deadline)
            .expect("installed graph continuity");
    }
    eprintln!(
        "DEPENDENCY_GRAPH_ADMISSION=PASS; ELAPSED_MS={}",
        started.elapsed().as_millis()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn installed_graph_uses_fresh_trusted_bytes_and_rejects_stale_operation_snapshots() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let path = "/usr/bin/true";
    let (identity, digest, _) = public_file(path, false, FILE_CAP, deadline).unwrap();
    let mut graph = InstalledGraph {
        files: vec![(path.into(), identity, digest)],
        directories: vec![],
    };
    graph.recheck(deadline).unwrap();
    graph.files[0].1[1] ^= 1;
    assert!(graph.recheck(deadline).is_err());
    graph.files[0].1 = identity;
    graph.files[0].2[0] ^= 1;
    assert!(graph.recheck(deadline).is_err());
    graph.files[0].2 = digest;
    graph.recheck(deadline).unwrap();
    assert!(public_file("/tmp/", false, FILE_CAP, deadline).is_err());
}

#[test]
fn named_private_role_uses_unique_current_identity_without_historical_uid() {
    for uid in [518, 1700] {
        let passwd = format!("root:*:0:0:root:/root:/bin/ksh\n_dovecot:*:519:519:mail:/var/empty:/sbin/nologin\n_osmapprimary:*:{uid}:{uid}:role:/var/empty:/sbin/nologin\n");
        let group = format!("wheel:*:0:root\n_dovecot:*:519:\n_osmapprimary:*:{uid}:\n");
        assert_eq!(
            selected(passwd.as_bytes(), group.as_bytes(), b"_osmapprimary"),
            Ok((uid, uid))
        );
        let shared = passwd.replace("_dovecot:*:519:519", &format!("_dovecot:*:{uid}:519"));
        assert!(selected(shared.as_bytes(), group.as_bytes(), b"_osmapprimary").is_err());
    }
}
