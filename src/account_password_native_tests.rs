use super::*;

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
