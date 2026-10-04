//! Fixed read-only stdio IMAP operation, bound to the validated account.
use crate::auth::{CommandExecutor, DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS};
use crate::folder_metadata::FolderSnapshot;
use crate::mailbox::MailboxBackendError;
use std::{
    path::Path,
    time::{Duration, Instant},
};
pub(crate) const TRANSCRIPT: &[u8] =
    b"N1 NAMESPACE\r\nL1 LIST \"\" \"*\" RETURN (CHILDREN SPECIAL-USE)\r\nZ1 LOGOUT\r\n";
pub(crate) fn unavailable() -> MailboxBackendError {
    MailboxBackendError {
        backend: "folder-metadata",
        reason: "folder metadata unavailable".into(),
    }
}
pub(crate) fn read<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    account: &str,
) -> Result<FolderSnapshot, MailboxBackendError> {
    read_before(
        executor,
        path,
        socket,
        account,
        Instant::now() + Duration::from_secs(DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS),
    )
}
pub(crate) fn read_before<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    account: &str,
    deadline: Instant,
) -> Result<FolderSnapshot, MailboxBackendError> {
    crate::identity::CanonicalUsername::parse(account).map_err(|_| unavailable())?;
    crate::mailbox_status::validate_account(account)?;
    // exec passes these options to imap; global doveadm -o does not propagate.
    let mut args = vec![
        "exec".into(),
        "imap".into(),
        "-o".into(),
        "stats_writer_socket_path=".into(),
    ];
    if let Some(socket) = socket {
        args.extend([
            "-o".into(),
            format!("auth_socket_path={}", socket.display()),
        ]);
    }
    args.extend(["-u".into(), account.into()]);
    let result = executor
        .run_with_stdin_bytes_timeout_and_output_limit(
            &path.to_string_lossy(),
            &args,
            TRANSCRIPT,
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(unavailable)?,
            512 * 1024,
        )
        .map_err(|_| unavailable())?;
    if Instant::now() >= deadline
        || result.status_code != 0
        || result.stdout.len() > 512 * 1024
        || result.stderr.len() > 512 * 1024
    {
        return Err(unavailable());
    }
    FolderSnapshot::parse(account, result.stdout.as_bytes()).map_err(|_| unavailable())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CommandExecution, CommandExecutionError};
    use std::sync::Mutex;
    struct Executor {
        calls: Mutex<usize>,
        fail: bool,
    }
    impl CommandExecutor for Executor {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("unbounded command forbidden")
        }
        fn run_with_stdin_bytes_timeout_and_output_limit(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
            limit: usize,
        ) -> Result<CommandExecution, CommandExecutionError> {
            *self.calls.lock().unwrap() += 1;
            assert_eq!(program, "/fixed/doveadm");
            assert_eq!(
                args,
                [
                    "exec",
                    "imap",
                    "-o",
                    "stats_writer_socket_path=",
                    "-o",
                    "auth_socket_path=/private/userdb",
                    "-u",
                    "alice@fixture.test"
                ]
            );
            assert_eq!(input, TRANSCRIPT);
            assert!(!timeout.is_zero() && timeout <= Duration::from_secs(10));
            assert_eq!(limit, 512 * 1024);
            Ok(CommandExecution {status_code:if self.fail{89}else{0},stdout:"* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\HasNoChildren) \".\" INBOX\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n".into(),stderr:"native informational logout; never metadata".into()})
        }
    }
    #[test]
    fn folder_metadata_native_account_transcripts() {
        let alice = FolderSnapshot::parse(
            "alice@fixture.test",
            include_bytes!("../maint/ux/fixtures/folder-metadata-alice.imap"),
        )
        .unwrap();
        let bob = FolderSnapshot::parse(
            "bob@fixture.test",
            include_bytes!("../maint/ux/fixtures/folder-metadata-bob.imap"),
        )
        .unwrap();
        assert!(alice.folder("alice@fixture.test", "AliceOnly").is_ok());
        assert!(alice.folder("alice@fixture.test", "BobOnly").is_err());
        assert!(alice.validate_for("bob@fixture.test").is_err());
        assert!(bob.folder("bob@fixture.test", "BobOnly").is_ok());
        assert!(bob.folder("bob@fixture.test", "AliceOnly").is_err());
    }
    #[test]
    fn folder_metadata_fixed_driver_bounds_and_refusals() {
        let e = Executor {
            calls: Mutex::new(0),
            fail: false,
        };
        let run = |account| {
            read(
                &e,
                Path::new("/fixed/doveadm"),
                Some(Path::new("/private/userdb")),
                account,
            )
        };
        assert!(run("alice@fixture.test")
            .unwrap()
            .folder("alice@fixture.test", "INBOX")
            .is_ok());
        for account in [
            "-A",
            "*",
            "alice%",
            "alice\nuser",
            "alice user",
            "alice<fixture>",
            "alice,fixture",
        ] {
            assert!(run(account).is_err());
        }
        assert_eq!(*e.calls.lock().unwrap(), 1);
        let failed = Executor {
            calls: Mutex::new(0),
            fail: true,
        };
        assert!(read(
            &failed,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            "alice@fixture.test"
        )
        .is_err());
    }
}
