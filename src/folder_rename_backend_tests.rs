use super::*;
use crate::auth::{CommandExecution, CommandExecutionError};
use std::sync::Mutex;
struct Exec {
    mode: u8,
    writes: Mutex<usize>,
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
        assert_eq!(program, "/fixed/doveadm");
        assert!(timeout <= Duration::from_secs(10));
        let mut writes = self.writes.lock().unwrap();
        let mut code = 0;
        let stdout = if args[0] == "exec" {
            assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
            let namespace = if self.mode == 14 {
                "((\"\" \".\")) ((\"INBOX.Alpha.\" \".\")) NIL"
            } else if self.mode == 11 {
                "NIL ((\"\" \".\")) NIL"
            } else {
                "((\"\" \".\")) NIL NIL"
            };
            let mut rows = "* LIST (\\HasChildren) \".\" INBOX\r\n".to_owned();
            if *writes == 0 || self.mode == 8 {
                let flags = if self.mode == 4 {
                    "\\Sent"
                } else {
                    "\\HasNoChildren"
                };
                rows.push_str(&format!("* LIST ({flags}) \".\" INBOX.Alpha\r\n"));
            }
            if self.mode == 3 {
                rows.push_str("* LIST () \".\" INBOX.Alpha.Child\r\n");
            }
            if *writes > 0 || self.mode == 5 {
                let flags = if self.mode == 12 {
                    "\\UnknownRole"
                } else {
                    "\\HasNoChildren"
                };
                rows.push_str(&format!("* LIST ({flags}) \".\" INBOX.Beta\r\n"));
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
                    "INBOX.Beta"
                ]
            );
            assert!(input.is_empty());
            assert_eq!(limit, 4096);
            *writes += 1;
            if self.mode == 6 {
                return Err(CommandExecutionError {
                    reason: "injected timeout after dispatch".into(),
                });
            }
            if self.mode == 9 {
                code = 65;
            }
            String::new()
        } else {
            let name = args.last().unwrap();
            let guid = if name == "INBOX" {
                if self.mode == 10 || (*writes > 0 && self.mode == 13) {
                    "c"
                } else {
                    "b"
                }
            } else if self.mode == 1 || (*writes > 0 && self.mode == 7) {
                "c"
            } else {
                "a"
            }
            .repeat(32);
            let count = if self.mode == 2 {
                1
            } else if self.mode == 15 && *writes > 0 {
                7
            } else {
                0
            };
            format!("[{{\"mailbox\":\"{name}\",\"guid\":\"{guid}\",\"messages\":\"{count}\",\"vsize\":\"0\"}}]")
        };
        Ok(CommandExecution {
            status_code: code,
            stdout,
            stderr: String::new(),
        })
    }
}
#[test]
fn folder_rename_backend_confirmed_and_refusal_boundaries() {
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
