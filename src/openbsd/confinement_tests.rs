use super::*;
use std::cell::RefCell;

const PRIVATE: &str = "/private/secret-token-canary-7adf";

#[derive(Default)]
struct InjectedSyscalls {
    calls: Vec<&'static str>,
    fail_at: Option<usize>,
    errno: i32,
}
impl InjectedSyscalls {
    fn call(&mut self, category: &'static str) -> io::Result<()> {
        self.calls.push(category);
        if self.fail_at == Some(self.calls.len()) {
            Err(io::Error::from_raw_os_error(self.errno))
        } else {
            Ok(())
        }
    }
}
impl ConfinementSyscalls for InjectedSyscalls {
    fn pledge(&mut self, _: &std::ffi::CStr) -> io::Result<()> {
        self.call("pledge")
    }
    fn unveil(&mut self, rule: Option<(&std::ffi::CStr, &std::ffi::CStr)>) -> io::Result<()> {
        self.call(if rule.is_some() { "rule" } else { "lock" })
    }
}
fn plan() -> OpenbsdConfinementPlan {
    OpenbsdConfinementPlan {
        promises_before_lock: "stdio rpath unveil",
        promises_after_lock: "stdio rpath",
        dependency_error: None,
        unveil_rules: vec![
            OpenbsdUnveilRule {
                path: PRIVATE.into(),
                permissions: "r".into(),
            },
            OpenbsdUnveilRule {
                path: format!("{PRIVATE}/second").into(),
                permissions: "rw".into(),
            },
        ],
    }
}
fn decoded(failure: &ConfinementFailure) -> serde_json::Value {
    let line = failure.diagnostic_line();
    assert!(line.len() < 320);
    assert!(line.ends_with('\n'));
    assert_eq!(line.lines().count(), 1);
    assert!(!line.contains(PRIVATE));
    assert!(!format!("{failure:?}").contains(PRIVATE));
    let value: serde_json::Value = serde_json::from_str(
        line.trim()
            .strip_prefix("OSMAP_SERVE_CONFINEMENT_V1 ")
            .unwrap(),
    )
    .unwrap();
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "errno",
            "reason",
            "rule_ordinal",
            "schema",
            "stage",
            "syscall"
        ]
    );
    assert_eq!(value["schema"], "osmap-serve-confinement-v1");
    value
}

#[test]
fn successful_sequence_preserves_order_and_drops_unveil_last() {
    let mut calls = InjectedSyscalls::default();
    apply_plan_with_syscalls(&plan(), &mut calls).unwrap();
    assert_eq!(calls.calls, ["pledge", "rule", "rule", "lock", "pledge"]);
}

#[test]
fn every_syscall_failure_preserves_errno_ordinal_and_first_failure_without_retry() {
    for (index, stage, syscall, ordinal) in [
        (1, "initial_pledge", "pledge", None),
        (2, "unveil_rule", "unveil", Some(1)),
        (3, "unveil_rule", "unveil", Some(2)),
        (4, "unveil_lock", "unveil", None),
        (5, "final_pledge", "pledge", None),
    ] {
        for errno in [libc::EPERM, libc::ENOENT, libc::EINVAL, libc::EINTR, 4095] {
            let mut calls = InjectedSyscalls {
                fail_at: Some(index),
                errno,
                ..Default::default()
            };
            let error = apply_plan_with_syscalls(&plan(), &mut calls).unwrap_err();
            let value = decoded(&error);
            assert_eq!(value["stage"], stage);
            assert_eq!(value["reason"], "syscall_failed");
            assert_eq!(value["syscall"], syscall);
            assert_eq!(value["errno"], errno);
            assert_eq!(value["rule_ordinal"], serde_json::json!(ordinal));
            assert_eq!(calls.calls.len(), index);
            let original = error.into_original();
            assert!(original.contains(&io::Error::from_raw_os_error(errno).to_string()));
            if ordinal.is_some() {
                assert!(original.contains(PRIVATE));
            }
        }
    }
}

#[test]
fn missing_or_unbounded_errno_remains_unknown() {
    for error in [
        io::Error::other(PRIVATE),
        io::Error::from_raw_os_error(0),
        io::Error::from_raw_os_error(4096),
        io::Error::from_raw_os_error(-1),
    ] {
        let error = ConfinementFailure::syscall(
            ConfinementStage::InitialPledge,
            ConfinementSyscall::Pledge,
            None,
            &error,
            PRIVATE.into(),
        );
        assert!(decoded(&error)["errno"].is_null());
    }
}

#[test]
fn dependency_refusal_precedes_every_syscall_and_preserves_original() {
    let mut p = plan();
    p.dependency_error = Some(PRIVATE.into());
    let mut calls = InjectedSyscalls::default();
    let failure = apply_plan_with_syscalls(&p, &mut calls).unwrap_err();
    let value = decoded(&failure);
    assert_eq!(value["stage"], "dependency_plan");
    assert_eq!(value["reason"], "boundary_refused");
    assert!(value["syscall"].is_null() && value["errno"].is_null());
    assert!(calls.calls.is_empty());
    assert_eq!(failure.into_original(), PRIVATE);
}

#[test]
fn account_preflight_boundaries_short_circuit_in_original_order() {
    for (separated, admission_ok, mutation_ok, expected, call_count) in [
        (false, true, true, "purpose_separation", 0),
        (true, false, true, "admission_preflight", 1),
        (true, true, false, "mutation_preflight", 2),
    ] {
        let calls = RefCell::new(Vec::new());
        let failure = check_account_preflight(
            separated,
            || {
                calls.borrow_mut().push("admission");
                if admission_ok {
                    Ok(())
                } else {
                    Err(())
                }
            },
            || {
                calls.borrow_mut().push("mutation");
                if mutation_ok {
                    Ok(())
                } else {
                    Err(())
                }
            },
        )
        .unwrap_err();
        let value = decoded(&failure);
        assert_eq!(value["stage"], expected);
        assert_eq!(value["reason"], "boundary_refused");
        assert!(
            value["syscall"].is_null()
                && value["errno"].is_null()
                && value["rule_ordinal"].is_null()
        );
        assert_eq!(*calls.borrow(), ["admission", "mutation"][..call_count]);
        assert_eq!(failure.into_original(), "account Serve custody unavailable");
    }
    let calls = RefCell::new(Vec::new());
    check_account_preflight(
        true,
        || {
            calls.borrow_mut().push("admission");
            Ok(())
        },
        || {
            calls.borrow_mut().push("mutation");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(*calls.borrow(), ["admission", "mutation"]);
}

#[test]
fn nul_arguments_are_not_misreported_as_failed_syscalls() {
    for (field, stage, ordinal, call_count) in [
        (0, "initial_pledge", None, 0),
        (1, "unveil_rule", Some(2), 2),
        (2, "unveil_rule", Some(2), 2),
        (3, "final_pledge", None, 4),
    ] {
        let mut p = plan();
        match field {
            0 => p.promises_before_lock = "stdio\0private",
            1 => p.unveil_rules[1].path = format!("{PRIVATE}\0hidden").into(),
            2 => p.unveil_rules[1].permissions = "r\0private".into(),
            3 => p.promises_after_lock = "stdio\0private",
            _ => unreachable!(),
        }
        let mut calls = InjectedSyscalls::default();
        let failure = apply_plan_with_syscalls(&p, &mut calls).unwrap_err();
        let value = decoded(&failure);
        assert_eq!(value["stage"], stage);
        assert_eq!(value["reason"], "invalid_argument");
        assert!(value["syscall"].is_null() && value["errno"].is_null());
        assert_eq!(value["rule_ordinal"], serde_json::json!(ordinal));
        assert_eq!(calls.calls.len(), call_count);
        assert!(failure.into_original().contains("contained interior NUL"));
    }
}

#[cfg(not(target_os = "openbsd"))]
#[test]
fn actual_top_level_platform_refusal_and_disabled_modes_cannot_mint_seal() {
    let mut config = AppConfig::from_env_map(&BTreeMap::new()).unwrap();
    config.run_mode = crate::config::AppRunMode::Bootstrap;
    let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Error);
    for mode in [
        OpenbsdConfinementMode::Disabled,
        OpenbsdConfinementMode::LogOnly,
    ] {
        config.openbsd_confinement_mode = mode;
        assert!(
            apply_runtime_confinement_for_accounts_detailed(&config, &logger, None)
                .unwrap()
                .is_none()
        );
    }
    config.openbsd_confinement_mode = OpenbsdConfinementMode::Enforce;
    let error = apply_runtime_confinement_for_accounts_detailed(&config, &logger, None)
        .err()
        .unwrap();
    assert_eq!(decoded(&error)["stage"], "unsupported_platform");
    assert_eq!(
        apply_runtime_confinement_for_accounts(&config, &logger, None)
            .err()
            .unwrap(),
        error.into_original()
    );
}

#[cfg(unix)]
#[test]
fn concrete_account_clients_keep_key_separation_peer_uid_and_leaf_custody_checks() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    let root = fs::canonicalize("/tmp").unwrap().join(format!(
        "osmap-confinement-preflight-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let uid = effective_uid();
    let account = crate::config::AccountRuntimeConfig {
        rollout_account: None,
        admission_socket: root.join("admission.sock"),
        admission_key_file: root.join("admission.key"),
        admission_helper_uid: uid,
        mutation_socket: root.join("mutation.sock"),
        mutation_key_file: root.join("mutation.key"),
        session_proof_key_file: root.join("proof.key"),
        mutation_helper_uid: uid,
    };
    for (path, byte) in [
        (&account.admission_key_file, 29),
        (&account.mutation_key_file, 37),
        (&account.session_proof_key_file, 41),
    ] {
        fs::write(path, [byte; 32]).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let listeners = [&account.admission_socket, &account.mutation_socket].map(|path| {
        let listener = UnixListener::bind(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
        listener
    });
    let admission = crate::account_admission_runtime::Client::paired_fixture_files(
        &account.admission_socket,
        &account.admission_key_file,
        uid,
    )
    .unwrap();
    let mutation = crate::account_mutation_client::Client::stored_fixture_files(
        &account.mutation_socket,
        &account.mutation_key_file,
        &account.session_proof_key_file,
        uid,
    )
    .unwrap();
    preflight_concrete_account_clients(&account, &admission, &mutation).unwrap();
    let mut changed = account.clone();
    changed.admission_helper_uid = uid.wrapping_add(1);
    assert_eq!(
        decoded(&preflight_concrete_account_clients(&changed, &admission, &mutation).unwrap_err())
            ["stage"],
        "admission_preflight"
    );
    changed = account.clone();
    changed.mutation_helper_uid = uid.wrapping_add(1);
    assert_eq!(
        decoded(&preflight_concrete_account_clients(&changed, &admission, &mutation).unwrap_err())
            ["stage"],
        "mutation_preflight"
    );
    // Distinct pathnames cannot legitimize shared purpose-key bytes.
    let wrong_purpose = crate::account_mutation_client::Client::stored_fixture_files(
        &account.mutation_socket,
        &account.admission_key_file,
        &account.session_proof_key_file,
        uid,
    )
    .unwrap();
    assert_eq!(
        decoded(
            &preflight_concrete_account_clients(&account, &admission, &wrong_purpose).unwrap_err()
        )["stage"],
        "purpose_separation"
    );
    // Constructor success does not replace the final live custody observation.
    fs::set_permissions(
        &account.mutation_key_file,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(
        decoded(&preflight_concrete_account_clients(&account, &admission, &mutation).unwrap_err())
            ["stage"],
        "mutation_preflight"
    );
    fs::set_permissions(
        &account.mutation_key_file,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    preflight_concrete_account_clients(&account, &admission, &mutation).unwrap();
    drop((admission, mutation, wrong_purpose, listeners));
    for path in [
        &account.admission_socket,
        &account.mutation_socket,
        &account.admission_key_file,
        &account.mutation_key_file,
        &account.session_proof_key_file,
    ] {
        fs::remove_file(path).unwrap();
    }
    fs::remove_dir(root).unwrap();
}

// Local subprocess adapter only. The same private sequence and serializer used
// by the native fixture feed the real Issue #79 guardian/consumer regression.
#[test]
#[ignore = "invoked by local diagnostic-pipeline integration with exact variant"]
fn serve_confinement_diagnostic_emitter() {
    let variant = std::env::var("OSMAP_TEST_CONFINEMENT_VARIANT").expect("test variant required");
    let mut p = plan();
    let mut calls = InjectedSyscalls::default();
    let failure = match variant.as_str() {
        "dependency_plan:boundary_refused" => {
            p.dependency_error = Some(PRIVATE.into());
            apply_plan_with_syscalls(&p, &mut calls).unwrap_err()
        }
        "purpose_separation:boundary_refused" => {
            check_account_preflight(false, || Ok(()), || Ok(())).unwrap_err()
        }
        "admission_preflight:boundary_refused" => {
            check_account_preflight(true, || Err(()), || Ok(())).unwrap_err()
        }
        "mutation_preflight:boundary_refused" => {
            check_account_preflight(true, || Ok(()), || Err(())).unwrap_err()
        }
        "unsupported_platform:boundary_refused" => {
            ConfinementFailure::boundary(ConfinementStage::UnsupportedPlatform, PRIVATE.into())
        }
        "initial_pledge:syscall_failed"
        | "unveil_rule:syscall_failed:1"
        | "unveil_rule:syscall_failed:2"
        | "unveil_lock:syscall_failed"
        | "final_pledge:syscall_failed" => {
            let (index, errno) = match variant.as_str() {
                "initial_pledge:syscall_failed" => (1, 1),
                "unveil_rule:syscall_failed:1" => (2, 2),
                "unveil_rule:syscall_failed:2" => (3, 2),
                "unveil_lock:syscall_failed" => (4, 22),
                "final_pledge:syscall_failed" => (5, 1),
                _ => unreachable!(),
            };
            calls.fail_at = Some(index);
            calls.errno = errno;
            apply_plan_with_syscalls(&p, &mut calls).unwrap_err()
        }
        "initial_pledge:invalid_argument"
        | "unveil_rule:invalid_argument:1"
        | "unveil_rule:invalid_argument:2"
        | "final_pledge:invalid_argument" => {
            match variant.as_str() {
                "initial_pledge:invalid_argument" => p.promises_before_lock = "stdio\0private",
                "unveil_rule:invalid_argument:1" => {
                    p.unveil_rules[0].path = format!("{PRIVATE}\0hidden").into()
                }
                "unveil_rule:invalid_argument:2" => {
                    p.unveil_rules[1].permissions = "r\0private".into()
                }
                "final_pledge:invalid_argument" => p.promises_after_lock = "stdio\0private",
                _ => unreachable!(),
            }
            apply_plan_with_syscalls(&p, &mut calls).unwrap_err()
        }
        _ => panic!("unknown fixed test variant"),
    };
    failure.emit_native_fixture_diagnostic();
    panic!("HTTP fixture actual Serve confinement refused");
}
