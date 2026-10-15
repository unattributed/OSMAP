use super::TEST_GATE as BACKEND_CASES;
use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use std::sync::Mutex;
struct Exec {
    mode: u8,
    writes: Mutex<usize>,
    calls: Mutex<Vec<Vec<String>>>,
}
impl CommandExecutor for Exec {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded execution required")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.calls.lock().unwrap().push(args.to_vec());
        assert_eq!(program, "/fixed/doveadm");
        assert!(timeout <= Duration::from_secs(10));
        let mut writes = self.writes.lock().unwrap();
        let mut code = 0;
        let stdout = if args[0] == "exec" {
            assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
            let namespace = if self.mode == 37 {
                "((\"\" \".\")) ((\"INBOX.Alpha.Child.\" \".\")) NIL"
            } else if self.mode == 14 {
                "((\"\" \".\")) ((\"INBOX.Alpha.\" \".\")) NIL"
            } else if self.mode == 11 {
                "NIL ((\"\" \".\")) NIL"
            } else {
                "((\"\" \".\")) NIL NIL"
            };
            let mut rows = "* LIST (\\HasChildren) \".\" INBOX\r\n".to_owned();
            if (20..30).contains(&self.mode) || self.mode == 38 {
                rows.push_str(&format!(
                    "* LIST ({}) \".\" INBOX.Target\r\n",
                    if self.mode == 23 {
                        "\\Sent"
                    } else {
                        "\\HasChildren"
                    }
                ));
            }
            if *writes == 0 || self.mode == 8 {
                let flags = if self.mode == 4 {
                    "\\Sent"
                } else if self.mode >= 30 {
                    "\\HasChildren"
                } else {
                    "\\HasNoChildren"
                };
                rows.push_str(&format!("* LIST ({flags}) \".\" INBOX.Alpha\r\n"));
            }
            if self.mode == 3 {
                rows.push_str("* LIST () \".\" INBOX.Alpha.Child\r\n");
            }
            if self.mode >= 30 {
                let root = if *writes == 0 || self.mode == 32 {
                    "INBOX.Alpha"
                } else if self.mode == 38 {
                    "INBOX.Target.Alpha"
                } else {
                    "INBOX.Beta"
                };
                if self.mode == 38 {
                    rows.push_str(&format!(
                        "* LIST (\\HasNoChildren) \".\" {root}.Child.Grand\r\n"
                    ));
                }
                rows.push_str(&format!(
                    "* LIST ({}) \".\" {root}.Child\r\n",
                    if self.mode == 36 {
                        "\\Sent"
                    } else if self.mode == 38 {
                        "\\HasChildren"
                    } else {
                        "\\HasNoChildren"
                    }
                ));
                if self.mode == 37 {
                    rows.push_str("* LIST (\\HasNoChildren) \".\" INBOX.Alpha.Child.Shared\r\n");
                }
                if self.mode == 35 || self.mode == 34 && *writes > 0 {
                    rows.push_str("* LIST (\\HasNoChildren) \".\" INBOX.Beta.Orphan\r\n");
                }
            }
            if *writes > 0 || self.mode == 5 || self.mode == 24 {
                let flags = if self.mode == 12 {
                    "\\UnknownRole"
                } else {
                    "\\HasNoChildren"
                };
                rows.push_str(&format!(
                    "* LIST ({flags}) \".\" {}\r\n",
                    if (20..30).contains(&self.mode) || self.mode == 38 {
                        "INBOX.Target.Alpha"
                    } else {
                        "INBOX.Beta"
                    }
                ));
            }
            format!("* PREAUTH ready\r\n* NAMESPACE {namespace}\r\nN1 OK done\r\n{rows}L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n")
        } else if args.iter().any(|arg| arg == "rename") {
            assert_eq!(
                args,
                [
                    "-o",
                    "stats_writer_socket_path=",
                    "-o",
                    "auth_socket_path=/private/userdb",
                    "mailbox",
                    "rename",
                    "-u",
                    "alice@fixture.test",
                    "INBOX.Alpha",
                    if (20..30).contains(&self.mode) || self.mode == 38 {
                        "INBOX.Target.Alpha"
                    } else {
                        "INBOX.Beta"
                    }
                ]
            );
            assert!(input.is_empty());
            assert_eq!(limit, 4096);
            *writes += 1;
            if self.mode == 6 || self.mode == 25 {
                return Err(CommandExecutionError {
                    reason: "injected timeout after dispatch".into(),
                });
            }
            if self.mode == 9 {
                code = 65;
            }
            String::new()
        } else {
            let pos = args
                .iter()
                .position(|arg| arg == "guid messages vsize")
                .unwrap();
            let rows = args[pos+1..].iter().map(|name| {
            let guid = if name.ends_with(".Grand") { "f" } else if name.ends_with(".Child") {
                if self.mode == 31 || self.mode == 33 && *writes > 0 {
                    "f"
                } else {
                    "e"
                }
            } else if name == "INBOX.Target" {
                if self.mode == 22 {
                    "c"
                } else {
                    "d"
                }
            } else if name == "INBOX" {
                if self.mode == 10 || self.mode == 21 || (*writes > 0 && self.mode == 13) {
                    "c"
                } else {
                    "b"
                }
            } else if self.mode == 1 || (*writes > 0 && matches!(self.mode, 7 | 26)) {
                "c"
            } else {
                "a"
            }
            .repeat(32);
            let count = if self.mode == 2 || self.mode >= 20 {
                1
            } else if self.mode == 15 && *writes > 0 {
                7
            } else {
                0
            };

                serde_json::json!({"mailbox": name, "guid":guid,"messages":count.to_string(),"vsize":"0"})
            }).collect::<Vec<_>>();
            serde_json::to_string(&rows).unwrap()
        };
        Ok(CommandExecution {
            status_code: code,
            stdout,
            stderr: String::new(),
        })
    }
}

#[test]
fn folder_subtree_backend_exact_children_preflight_and_partial_result_boundaries() {
    let _case = BACKEND_CASES.lock().unwrap();
    let leaf = RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let mut fields = serde_json::to_value(&leaf).unwrap();
    fields["descendants"] = serde_json::json!([{"suffix":".Child","guid":"e".repeat(32)}]);
    let request: RenameFolderRequest = serde_json::from_value(fields).unwrap();
    for (mode, expected, writes) in [
        (30, Outcome::Renamed, 1),
        (31, Outcome::Refused(Refusal::Stale), 0),
        (32, Outcome::Unknown, 1),
        (33, Outcome::Unknown, 1),
        (34, Outcome::Unknown, 1),
        (35, Outcome::Conflict, 0),
        (36, Outcome::Refused(Refusal::Invalid), 0),
        (37, Outcome::Refused(Refusal::Invalid), 0),
    ] {
        let executor = Exec {
            mode,
            writes: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            rename(
                &executor,
                Path::new("/fixed/doveadm"),
                Some(Path::new("/private/userdb")),
                &request
            ),
            expected,
            "mode{mode}"
        );
        assert_eq!(*executor.writes.lock().unwrap(), writes, "mode{mode}");
    }
    let executor = Exec {
        mode: 30,
        writes: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };
    assert_eq!(
        rename(
            &executor,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            &leaf
        ),
        Outcome::Refused(Refusal::Invalid)
    );
    assert_eq!(*executor.writes.lock().unwrap(), 0);
}

#[test]
fn folder_move_pins_both_parents_preserves_leaf_and_refuses_before_dispatch() {
    let _case = BACKEND_CASES.lock().unwrap();
    let request = RenameFolderRequest::for_move(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "INBOX.Target",
        &"d".repeat(32),
    )
    .unwrap();
    assert_eq!(request.destination(), "INBOX.Target.Alpha");
    assert_eq!(request.source_parent(), "INBOX");
    assert_eq!(request.source_parent_guid(), "b".repeat(32));
    let mut altered = serde_json::to_value(&request).unwrap();
    altered["leaf"] = "Sent".into();
    assert_eq!(
        serde_json::from_value::<RenameFolderRequest>(altered)
            .unwrap()
            .validate(),
        Err(Refusal::Invalid)
    );
    for (mode, expected, writes) in [
        (20, Outcome::Renamed, 1),
        (21, Outcome::Refused(Refusal::Stale), 0),
        (22, Outcome::Refused(Refusal::Stale), 0),
        (23, Outcome::Refused(Refusal::Invalid), 0),
        (24, Outcome::Conflict, 0),
        (25, Outcome::Unknown, 1),
        (26, Outcome::Unknown, 1),
    ] {
        let executor = Exec {
            mode,
            writes: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            rename(
                &executor,
                Path::new("/fixed/doveadm"),
                Some(Path::new("/private/userdb")),
                &request
            ),
            expected,
            "mode{mode}"
        );
        assert_eq!(*executor.writes.lock().unwrap(), writes, "mode{mode}");
    }
    for parent in [
        "INBOX",
        "INBOX.Alpha",
        "INBOX.Alpha.Child",
        "INBOX.Sent",
        "INBOX.Trash.Child",
        "Shared.Other",
        "Public.Other",
    ] {
        assert!(
            RenameFolderRequest::for_move(
                "alice@fixture.test",
                "INBOX.Alpha",
                &"a".repeat(32),
                &"b".repeat(32),
                parent,
                &"d".repeat(32)
            )
            .is_err(),
            "{parent}"
        );
    }
    let old = RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let wire = serde_json::to_value(&old).unwrap();
    assert!(wire.get("destination_parent").is_none() && wire.get("source_parent_guid").is_none());
    let reloaded: RenameFolderRequest = serde_json::from_value(wire).unwrap();
    assert_eq!(reloaded, old);
    reloaded.validate().unwrap();
}
#[test]
fn folder_rename_backend_confirmed_and_refusal_boundaries() {
    let _case = BACKEND_CASES.lock().unwrap();
    let request = RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    for (mode, expected, writes) in [
        (0, Outcome::Renamed, 1),
        (1, Outcome::Refused(Refusal::Stale), 0),
        (2, Outcome::Renamed, 1),
        (3, Outcome::Refused(Refusal::Invalid), 0),
        (4, Outcome::Refused(Refusal::Invalid), 0),
        (5, Outcome::Conflict, 0),
        (6, Outcome::Unknown, 1),
        (7, Outcome::Unknown, 1),
        (8, Outcome::Unknown, 1),
        (9, Outcome::Unknown, 1),
        (10, Outcome::Refused(Refusal::Stale), 0),
        (11, Outcome::Refused(Refusal::Invalid), 0),
        (12, Outcome::Unknown, 1),
        (13, Outcome::Unknown, 1),
        (14, Outcome::Refused(Refusal::Invalid), 0),
        (15, Outcome::Renamed, 1),
    ] {
        let executor = Exec {
            mode,
            writes: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            rename(
                &executor,
                Path::new("/fixed/doveadm"),
                Some(Path::new("/private/userdb")),
                &request
            ),
            expected,
            "mode{mode}"
        );
        assert_eq!(*executor.writes.lock().unwrap(), writes, "mode{mode}");
    }
    let executor = Exec {
        mode: 0,
        writes: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };
    let snapshot = crate::folder_metadata::FolderSnapshot::parse("bob@fixture.test", b"* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST () \".\" INBOX\r\n* LIST () \".\" INBOX.Alpha\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n").unwrap();
    let source =
        crate::mailbox_status::MailboxStatus::new("INBOX.Alpha", &"a".repeat(32), 0, 0).unwrap();
    let parent = crate::mailbox_status::MailboxStatus::new("INBOX", &"b".repeat(32), 0, 0).unwrap();
    assert_eq!(
        request.validate_before(&snapshot, &source, &parent),
        Err(Refusal::Unavailable)
    );
    assert_eq!(*executor.writes.lock().unwrap(), 0);
}
#[test]
fn folder_rename_names_roles_and_settings_admission() {
    for source in [
        "INBOX",
        "INBOX.",
        "INBOX..User",
        "INBOX.Sent",
        "INBOX.Sent.Child",
        "OSMAP.Documents",
        "Shared.User",
    ] {
        assert!(
            RenameFolderRequest::new(
                "alice@fixture.test",
                source,
                &"a".repeat(32),
                &"b".repeat(32),
                "Beta"
            )
            .is_err(),
            "{source}"
        );
    }
    for leaf in [
        "",
        "Alpha",
        "Sent",
        "Documents",
        "A.B",
        "A/B",
        "*",
        "-x",
        " A",
        "A\n",
    ] {
        assert!(
            RenameFolderRequest::new(
                "alice@fixture.test",
                "INBOX.Alpha",
                &"a".repeat(32),
                &"b".repeat(32),
                leaf
            )
            .is_err(),
            "{leaf:?}"
        );
    }
    let unicode = RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Élodie & Office",
    )
    .unwrap();
    assert_eq!(unicode.destination(), "INBOX.Élodie & Office");
    assert!(crate::folder_rename::role_conflict(
        &["INBOX.Alpha".into()],
        "INBOX.Alpha",
        "INBOX.Beta"
    ));
    assert!(crate::folder_rename::role_conflict(
        &["INBOX.Beta".into()],
        "INBOX.Alpha",
        "INBOX.Beta"
    ));
}

#[test]
fn folder_rename_native_two_descendants_share_each_fresh_phase_batch() {
    let _case = BACKEND_CASES.lock().unwrap();
    let request = RenameFolderRequest::for_move(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "INBOX.Target",
        &"d".repeat(32),
    )
    .unwrap();
    let mut fields = serde_json::to_value(request).unwrap();
    fields["descendants"] = serde_json::json!([{"suffix":".Child","guid":"e".repeat(32)},{"suffix":".Child.Grand","guid":"f".repeat(32)}]);
    let request: RenameFolderRequest = serde_json::from_value(fields).unwrap();
    let executor = Exec {
        mode: 38,
        writes: Mutex::new(0),
        calls: Mutex::new(Vec::new()),
    };
    assert_eq!(
        rename(
            &executor,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            &request
        ),
        Outcome::Renamed
    );
    assert_eq!(*executor.writes.lock().unwrap(), 1);
    let calls = executor.calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        5,
        "metadata+batch STATUS before, one rename, independent metadata+batch STATUS after"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|args| args.first().is_some_and(|arg| arg == "exec"))
            .count(),
        2
    );
    let batches = calls
        .iter()
        .filter_map(|args| {
            args.iter()
                .position(|arg| arg == "guid messages vsize")
                .map(|pos| &args[pos + 1..])
        })
        .collect::<Vec<_>>();
    assert_eq!(
        batches,
        vec![
            &[
                "INBOX".to_owned(),
                "INBOX.Alpha".to_owned(),
                "INBOX.Alpha.Child".to_owned(),
                "INBOX.Alpha.Child.Grand".to_owned(),
                "INBOX.Target".to_owned()
            ][..],
            &[
                "INBOX.Target".to_owned(),
                "INBOX.Target.Alpha".to_owned(),
                "INBOX.Target.Alpha.Child".to_owned(),
                "INBOX.Target.Alpha.Child.Grand".to_owned()
            ][..]
        ]
    );
}
