//! One bounded require-empty native command; unknown outcomes never retry.
use crate::{
    auth::CommandExecutor,
    folder_create::Refusal,
    folder_delete::{DeleteFolderRequest, Outcome},
    mailbox::{DoveadmMailboxListBackend, MailboxBackend, MailboxListingPolicy},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};
pub(crate) fn delete<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    request: &DeleteFolderRequest,
) -> Outcome {
    if let Err(e) = request.validate() {
        return Outcome::Refused(e);
    }
    let limited = crate::folder_create_backend::Deadline {
        inner: executor,
        until: Instant::now() + Duration::from_secs(10),
    };
    let backend = DoveadmMailboxListBackend::new(MailboxListingPolicy::default(), &limited, path)
        .with_userdb_socket_path(socket.map(Path::to_path_buf));
    let (Ok(snapshot), Ok(source), Ok(parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), request.source()),
        backend.mailbox_status(request.account(), request.parent()),
    ) else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    if let Err(e) = request.validate_before(&snapshot, &source, &parent) {
        return Outcome::Refused(e);
    }
    let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
    if let Some(socket) = socket {
        args.extend([
            "-o".into(),
            format!("auth_socket_path={}", socket.display()),
        ]);
    }
    args.extend([
        "mailbox".into(),
        "delete".into(),
        "-e".into(),
        "-u".into(),
        request.account().into(),
        request.source().into(),
    ]);
    let Ok(result) = limited.run_with_stdin_bytes_timeout_and_output_limit(
        &path.to_string_lossy(),
        &args,
        b"",
        Duration::from_secs(10),
        4096,
    ) else {
        return Outcome::Unknown;
    };
    // A nonzero code may follow partial native work. Never classify it as a
    // pre-dispatch refusal or automatically retry, even if the leaf still exists.
    if result.status_code != 0 {
        return Outcome::Unknown;
    }
    let (Ok(after), Ok(parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), request.parent()),
    ) else {
        return Outcome::Unknown;
    };
    if request.confirmed_absent(&after, &parent) {
        Outcome::Deleted
    } else {
        Outcome::Unknown
    }
}

#[cfg(test)]
mod tests {
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
            panic!("bounded only")
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            p: &str,
            a: &[String],
            input: &[u8],
            time: Duration,
            limit: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert_eq!(p, "/fixed/doveadm");
            assert!(time <= Duration::from_secs(10));
            let mut writes = self.writes.lock().unwrap();
            let (code, out) = if a.first().map(String::as_str) == Some("exec") {
                assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
                (0,format!("* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\HasChildren) \".\" INBOX\r\n{}L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n",if *writes==0||self.mode==2{"* LIST (\\HasNoChildren) \".\" INBOX.Alpha\r\n"}else{""}))
            } else if a.iter().any(|v| v == "delete") {
                assert_eq!(
                    a,
                    [
                        "-o",
                        "stats_writer_socket_path=",
                        "-o",
                        "auth_socket_path=/private/userdb",
                        "mailbox",
                        "delete",
                        "-e",
                        "-u",
                        "alice@fixture.test",
                        "INBOX.Alpha"
                    ]
                );
                assert!(input.is_empty());
                assert_eq!(limit, 4096);
                *writes += 1;
                (if self.mode == 2 { 75 } else { 0 }, String::new())
            } else {
                let name = a.last().unwrap();
                let guid = if name == "INBOX" { "b" } else { "a" }.repeat(32);
                (0,format!("[{{\"mailbox\":\"{name}\",\"guid\":\"{guid}\",\"messages\":\"{}\",\"vsize\":\"0\"}}]",if self.mode==1 && name=="INBOX.Alpha"{1}else{0}))
            };
            Ok(CommandExecution {
                status_code: code,
                stdout: out,
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn folder_delete_fixed_empty_dispatch_and_uncertain_native_refusal() {
        let r = DeleteFolderRequest::new(
            "alice@fixture.test",
            "INBOX.Alpha",
            &"a".repeat(32),
            &"b".repeat(32),
        )
        .unwrap();
        for (mode, expected, writes) in [
            (0, Outcome::Deleted, 1),
            (1, Outcome::Refused(Refusal::Invalid), 0),
            (2, Outcome::Unknown, 1),
        ] {
            let e = Exec {
                mode,
                writes: Mutex::new(0),
            };
            assert_eq!(
                delete(
                    &e,
                    Path::new("/fixed/doveadm"),
                    Some(Path::new("/private/userdb")),
                    &r
                ),
                expected
            );
            assert_eq!(*e.writes.lock().unwrap(), writes);
        }
    }
}
