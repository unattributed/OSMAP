use crate::{
    auth::{CommandExecution, CommandExecutionError, CommandExecutor},
    folder_create::{CreateFolderRequest, Outcome, Refusal},
    mailbox::{DoveadmMailboxListBackend, MailboxBackend, MailboxListingPolicy},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};
struct Deadline<'a, E> {
    inner: &'a E,
    until: Instant,
}
impl<E: CommandExecutor> CommandExecutor for Deadline<'_, E> {
    fn run_with_stdin_bytes(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(
            p,
            a,
            input,
            Duration::from_secs(10),
            512 * 1024,
        )
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        let remaining = self
            .until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| CommandExecutionError {
                reason: "folder operation deadline exceeded".into(),
            })?;
        self.inner.run_with_stdin_bytes_timeout_and_output_limit(
            p,
            a,
            input,
            timeout.min(remaining),
            limit,
        )
    }
}
pub(crate) fn create<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    request: &CreateFolderRequest,
) -> Outcome {
    if let Err(e) = request.validate() {
        return Outcome::Refused(e);
    }
    let limited = Deadline {
        inner: executor,
        until: Instant::now() + Duration::from_secs(10),
    };
    let backend = DoveadmMailboxListBackend::new(MailboxListingPolicy::default(), &limited, path)
        .with_userdb_socket_path(socket.map(Path::to_path_buf));
    let (Ok(before), Ok(parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), request.parent()),
    ) else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    if let Err(e) = request.validate_parent(&before, &parent) {
        return Outcome::Refused(e);
    }
    if before.folder(request.account(), &request.child()).is_ok() {
        return Outcome::Conflict;
    }
    let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
    if let Some(s) = socket {
        args.extend(["-o".into(), format!("auth_socket_path={}", s.display())]);
    }
    args.extend([
        "mailbox".into(),
        "create".into(),
        "-u".into(),
        request.account().into(),
        request.child(),
    ]);
    let execution = limited.run_with_stdin_bytes_timeout_and_output_limit(
        &path.to_string_lossy(),
        &args,
        b"",
        Duration::from_secs(10),
        4096,
    );
    let Ok(result) = execution else {
        return Outcome::Unknown;
    };
    if result.status_code != 0 && result.status_code != 65 {
        return Outcome::Unknown;
    }
    let (Ok(after), Ok(parent), Ok(child)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), request.parent()),
        backend.mailbox_status(request.account(), &request.child()),
    ) else {
        return Outcome::Unknown;
    };
    // Capacity can now be exactly1024 after this single creation.
    if !matches!(
        request.validate_parent(&after, &parent),
        Ok(()) | Err(Refusal::Capacity)
    ) || child.guid() == parent.guid()
        || after.validate_for(request.account()).is_err()
        || parent.guid() != request.parent_guid()
        || parent.validate(request.parent()).is_err()
        || child.validate(&request.child()).is_err()
    {
        return Outcome::Unknown;
    }
    let Ok(folder) = after.folder(request.account(), &request.child()) else {
        return Outcome::Unknown;
    };
    if folder.delimiter() != Some('.')
        || folder.has_flag("\\Noselect")
        || folder.has_flag("\\NonExistent")
    {
        return Outcome::Unknown;
    }
    if result.status_code == 65 {
        Outcome::Conflict
    } else {
        Outcome::Created {
            guid: child.guid().into(),
        }
    }
}
impl<E: CommandExecutor> CommandExecutor for &Deadline<'_, E> {
    fn run_with_stdin_bytes(
        &self,
        p: &str,
        a: &[String],
        i: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        (**self).run_with_stdin_bytes(p, a, i)
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        p: &str,
        a: &[String],
        i: &[u8],
        t: Duration,
        l: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        (**self).run_with_stdin_bytes_timeout_and_output_limit(p, a, i, t, l)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Exec {
        mode: u8,
        creates: Mutex<usize>,
    }
    impl CommandExecutor for Exec {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("bounded only")
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            _: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            limit: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert!(timeout <= Duration::from_secs(10));
            let mut count = self.creates.lock().unwrap();
            let mut code = 0;
            let stdout = if args[0] == "exec" {
                assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
                let child = if (*count > 0 && self.mode != 6) || self.mode == 1 {
                    "* LIST (\\HasNoChildren) \".\" INBOX.Child\r\n"
                } else {
                    ""
                };
                format!("* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\HasChildren) \".\" INBOX\r\n{child}L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n")
            } else if args.iter().any(|a| a == "create") {
                assert_eq!(
                    args,
                    [
                        "-o",
                        "stats_writer_socket_path=",
                        "-o",
                        "auth_socket_path=/private/userdb",
                        "mailbox",
                        "create",
                        "-u",
                        "alice@fixture.test",
                        "INBOX.Child"
                    ]
                );
                assert!(input.is_empty());
                assert_eq!(limit, 4096);
                *count += 1;
                if self.mode == 3 {
                    return Err(CommandExecutionError {
                        reason: "injected timeout after dispatch".into(),
                    });
                }
                if self.mode == 4 || self.mode == 6 {
                    code = 65
                }
                String::new()
            } else {
                let name = args.last().unwrap();
                let guid =
                    if name == "INBOX.Child" || self.mode == 2 || (*count > 0 && self.mode == 5) {
                        "b".repeat(32)
                    } else {
                        "a".repeat(32)
                    };
                format!("[{{\"mailbox\":\"{name}\",\"guid\":\"{guid}\",\"messages\":\"0\",\"vsize\":\"0\"}}]")
            };
            Ok(CommandExecution {
                status_code: code,
                stdout,
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn folder_create_dispatch_failure_boundaries() {
        let request =
            CreateFolderRequest::new("alice@fixture.test", "INBOX", &"a".repeat(32), "Child")
                .unwrap();
        for (mode, expected, count) in [
            (
                0,
                Outcome::Created {
                    guid: "b".repeat(32),
                },
                1,
            ),
            (1, Outcome::Conflict, 0),
            (2, Outcome::Refused(Refusal::Stale), 0),
            (3, Outcome::Unknown, 1),
            (4, Outcome::Conflict, 1),
            (5, Outcome::Unknown, 1),
            (6, Outcome::Unknown, 1),
        ] {
            let e = Exec {
                mode,
                creates: Mutex::new(0),
            };
            assert_eq!(
                create(
                    &e,
                    Path::new("/fixed/doveadm"),
                    Some(Path::new("/private/userdb")),
                    &request
                ),
                expected
            );
            assert_eq!(*e.creates.lock().unwrap(), count);
        }
        for leaf in ["", ".", "A.B", "A/B", "*", "-s", "A%", "A\\B", "x\n", " x"] {
            assert!(
                CreateFolderRequest::new("alice@fixture.test", "INBOX", &"a".repeat(32), leaf)
                    .is_err()
            );
        }
        assert!(
            CreateFolderRequest::new("alice@fixture.test", "Other", &"a".repeat(32), "Child")
                .is_err()
        );
        assert!(CreateFolderRequest::new(
            "alice@fixture.test",
            "INBOX",
            &"a".repeat(32),
            &"é".repeat(128)
        )
        .is_err());
        let e = Exec {
            mode: 0,
            creates: Mutex::new(0),
        };
        let expired = Deadline {
            inner: &e,
            until: Instant::now() - Duration::from_secs(1),
        };
        assert!(expired.run_with_stdin_bytes("", &[], b"").is_err());
        assert_eq!(*e.creates.lock().unwrap(), 0);
    }
    struct BoundaryExec {
        namespaces: &'static str,
        delimiter: &'static str,
        flags: &'static str,
        initial_count: usize,
        creates: Mutex<usize>,
    }
    impl BoundaryExec {
        fn transcript(&self, created: bool) -> String {
            let mut rows = format!("* LIST ({}) {} INBOX\r\n", self.flags, self.delimiter);
            for n in 1..self.initial_count {
                rows.push_str(&format!(
                    "* LIST () {} INBOX.Existing{n}\r\n",
                    self.delimiter
                ));
            }
            if created {
                rows.push_str("* LIST () \".\" INBOX.Child\r\n");
            }
            format!("* PREAUTH ready\r\n* NAMESPACE {}\r\nN1 OK done\r\n{rows}L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n", self.namespaces)
        }
    }
    impl CommandExecutor for BoundaryExec {
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
            _: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            limit: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert!(timeout <= Duration::from_secs(10));
            let mut creates = self.creates.lock().unwrap();
            let stdout = if args[0] == "exec" {
                assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
                self.transcript(*creates != 0)
            } else if args.iter().any(|a| a == "create") {
                assert_eq!(args.last().unwrap(), "INBOX.Child");
                assert!(input.is_empty());
                assert_eq!(limit, 4096);
                *creates += 1;
                String::new()
            } else {
                let name = args.last().unwrap();
                let guid = if name == "INBOX" { "a" } else { "b" }.repeat(32);
                format!("[{{\"mailbox\":\"{name}\",\"guid\":\"{guid}\",\"messages\":\"0\",\"vsize\":\"0\"}}]")
            };
            Ok(CommandExecution {
                status_code: 0,
                stdout,
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn folder_create_namespace_and_capacity_boundaries() {
        let request =
            CreateFolderRequest::new("alice@fixture.test", "INBOX", &"a".repeat(32), "Child")
                .unwrap();
        for (name, namespaces, delimiter, flags, count, refusal) in [
            (
                "slash",
                "((\"\" \"/\")) NIL NIL",
                "\"/\"",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "nil",
                "((\"\" NIL)) NIL NIL",
                "NIL",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "shared",
                "NIL ((\"\" \".\")) NIL",
                "\".\"",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "public",
                "NIL NIL ((\"\" \".\"))",
                "\".\"",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "ambiguous",
                "((\"\" \".\")(\"INBOX.\" \".\")) NIL NIL",
                "\".\"",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "noinferiors",
                "((\"\" \".\")) NIL NIL",
                "\".\"",
                "\\Noinferiors",
                1,
                Refusal::Invalid,
            ),
            (
                "child-is-shared-namespace-root",
                "((\"\" \".\")) ((\"INBOX.Child.\" \".\")) NIL",
                "\".\"",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "child-is-public-namespace-root",
                "((\"\" \".\")) NIL ((\"INBOX.Child.\" \".\"))",
                "\".\"",
                "",
                1,
                Refusal::Invalid,
            ),
            (
                "capacity",
                "((\"\" \".\")) NIL NIL",
                "\".\"",
                "",
                1024,
                Refusal::Capacity,
            ),
        ] {
            let exec = BoundaryExec {
                namespaces,
                delimiter,
                flags,
                initial_count: count,
                creates: Mutex::new(0),
            };
            // Prove each input is valid metadata, so parser rejection cannot mask the authority check.
            let snapshot = crate::folder_metadata::FolderSnapshot::parse(
                request.account(),
                exec.transcript(false).as_bytes(),
            )
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(snapshot.folders().len(), count, "{name}");
            assert_eq!(
                create(&exec, Path::new("/fixed/doveadm"), None, &request),
                Outcome::Refused(refusal),
                "{name}"
            );
            assert_eq!(*exec.creates.lock().unwrap(), 0, "{name}");
        }
        let exec = BoundaryExec {
            namespaces: "((\"\" \".\")) NIL NIL",
            delimiter: "\".\"",
            flags: "",
            initial_count: 1023,
            creates: Mutex::new(0),
        };
        assert_eq!(
            create(&exec, Path::new("/fixed/doveadm"), None, &request),
            Outcome::Created {
                guid: "b".repeat(32)
            }
        );
        assert_eq!(*exec.creates.lock().unwrap(), 1);
        let after = crate::folder_metadata::FolderSnapshot::parse(
            request.account(),
            exec.transcript(true).as_bytes(),
        )
        .unwrap();
        assert_eq!(after.folders().len(), 1024);
        assert!(after.folder(request.account(), "INBOX.Child").is_ok());
    }
}
