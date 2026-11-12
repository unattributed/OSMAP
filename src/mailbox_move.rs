//! Identity-bound moves with bounded, read-only post-write reconciliation.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::mailbox_json::parse_json_summaries;
use super::{
    MailboxBackendError, MessageListPolicy, MessageMoveBackend, MessageMovePolicy,
    MessageMoveRequest, MessageSummary,
};
use crate::auth::{CommandExecutor, SystemCommandExecutor};

const FIELDS: &str = "uid flags date.received size.virtual mailbox mailbox-guid guid";
pub const MOVE_OPERATION_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone)]
pub struct DoveadmMessageMoveBackend<E> {
    executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
    command_timeout_secs: u64,
    operation_gate: Arc<Mutex<()>>,
}

fn failure(backend: &'static str, reason: &str) -> MailboxBackendError {
    MailboxBackendError {
        backend,
        reason: reason.into(),
    }
}

impl<E> DoveadmMessageMoveBackend<E> {
    pub fn new(executor: E, doveadm_path: impl Into<PathBuf>) -> Self {
        Self {
            executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
            command_timeout_secs: MOVE_OPERATION_TIMEOUT_SECS,
            operation_gate: Arc::new(Mutex::new(())),
        }
    }
    pub fn with_userdb_socket_path(mut self, path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = path;
        self
    }
    pub fn with_command_timeout_secs(mut self, seconds: u64) -> Self {
        self.command_timeout_secs = seconds.clamp(1, MOVE_OPERATION_TIMEOUT_SECS);
        self
    }
    pub fn with_operation_gate(mut self, gate: Arc<Mutex<()>>) -> Self {
        self.operation_gate = gate;
        self
    }
    fn base_args(&self) -> Vec<String> {
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        if let Some(path) = &self.userdb_socket_path {
            args.extend(["-o".into(), format!("auth_socket_path={}", path.display())]);
        }
        args
    }
    fn source_query(request: &MessageMoveRequest) -> Vec<String> {
        vec![
            "mailbox".into(),
            request.source_mailbox_name.clone(),
            "mailbox-guid".into(),
            request.version.mailbox_guid.clone(),
            "uid".into(),
            request.uid.to_string(),
            "guid".into(),
            request.version.message_guid.clone(),
        ]
    }
    fn destination_query(request: &MessageMoveRequest) -> Vec<String> {
        vec![
            "mailbox".into(),
            request.destination_mailbox_name.clone(),
            "guid".into(),
            request.version.message_guid.clone(),
        ]
    }
}

impl Default for DoveadmMessageMoveBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
    }
}

impl<E: CommandExecutor> DoveadmMessageMoveBackend<E> {
    fn read_summary(
        &self,
        username: &str,
        query: Vec<String>,
        deadline: Instant,
    ) -> Result<Option<MessageSummary>, MailboxBackendError> {
        let mut args = self.base_args();
        args.extend([
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "-u".into(),
            username.into(),
            FIELDS.into(),
        ]);
        args.extend(query);
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| failure("message-move-unavailable", "move read deadline reached"))?;
        let execution = self
            .executor
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                remaining,
            )
            .map_err(|_| {
                failure(
                    "message-move-unavailable",
                    "native move-state read did not complete",
                )
            })?;
        let mut rows = parse_json_summaries(
            MessageListPolicy {
                max_messages: 1,
                ..MessageListPolicy::default()
            },
            &execution,
        )
        .map_err(|_| {
            failure(
                "message-move-unavailable",
                "native move-state response was unavailable or ambiguous",
            )
        })?;
        Ok(rows.pop())
    }
}

impl<E: CommandExecutor> MessageMoveBackend for DoveadmMessageMoveBackend<E> {
    fn move_message(
        &self,
        username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| failure("message-move-busy", "another mail mutation is active"))?;
        let request = MessageMoveRequest::new(
            MessageMovePolicy::default(),
            request.source_mailbox_name.clone(),
            request.destination_mailbox_name.clone(),
            request.uid,
            request.version.clone(),
        )?;
        if username.is_empty()
            || username.len() > crate::auth::DEFAULT_USERNAME_MAX_LEN
            || username.chars().any(char::is_control)
            || username.contains(['*', '?'])
        {
            return Err(failure(
                "message-move-parser",
                "account identity is invalid",
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(self.command_timeout_secs);
        let source = self
            .read_summary(username, Self::source_query(&request), deadline)?
            .ok_or_else(|| {
                failure(
                    "message-move-stale",
                    "message identity is no longer current",
                )
            })?;
        if source.mailbox_name != request.source_mailbox_name
            || source.uid != request.uid
            || source.metadata.as_ref().map(|m| &m.version) != Some(&request.version)
        {
            return Err(failure(
                "message-move-stale",
                "source identity did not match",
            ));
        }
        if self
            .read_summary(username, Self::destination_query(&request), deadline)?
            .is_some()
        {
            return Err(failure("message-move-stale", "destination already contains this message identity; refresh before choosing another action"));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                failure(
                    "message-move-unavailable",
                    "move deadline reached before mutation",
                )
            })?;
        let mut args = self.base_args();
        args.extend([
            "move".into(),
            "-u".into(),
            username.into(),
            request.destination_mailbox_name.clone(),
        ]);
        args.extend(Self::source_query(&request));
        let execution = self.executor.run_with_stdin_timeout(
            self.doveadm_path.to_string_lossy().as_ref(),
            &args,
            "",
            remaining,
        );
        let unknown = || {
            failure("message-move-unknown", "the move may have completed; refresh both mailboxes before choosing another action")
        };
        if !matches!(execution, Ok(ref result) if result.status_code == 0) {
            return Err(unknown());
        }
        if self
            .read_summary(username, Self::source_query(&request), deadline)
            .map_err(|_| unknown())?
            .is_some()
        {
            return Err(unknown());
        }
        let destination = self
            .read_summary(username, Self::destination_query(&request), deadline)
            .map_err(|_| unknown())?
            .ok_or_else(unknown)?;
        if destination.mailbox_name != request.destination_mailbox_name
            || destination
                .metadata
                .as_ref()
                .map(|m| &m.version.message_guid)
                != Some(&request.version.message_guid)
        {
            return Err(unknown());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::auth::{CommandExecution, CommandExecutionError};
    use crate::message_metadata::MessageVersion;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct Executor {
        outputs: RefCell<VecDeque<CommandExecution>>,
        calls: RefCell<Vec<Vec<String>>>,
        deadlines: RefCell<Vec<Duration>>,
    }
    impl CommandExecutor for &Executor {
        fn run_with_stdin_bytes(
            &self,
            _program: &str,
            args: &[String],
            input: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert!(input.is_empty());
            self.calls.borrow_mut().push(args.to_vec());
            self.outputs
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| CommandExecutionError {
                    reason: "fixture queue exhausted".into(),
                })
        }
        fn run_with_stdin_bytes_timeout(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
        ) -> Result<CommandExecution, CommandExecutionError> {
            self.deadlines.borrow_mut().push(timeout);
            self.run_with_stdin_bytes(program, args, input)
        }
    }
    fn ok(text: &str) -> CommandExecution {
        CommandExecution {
            status_code: 0,
            stdout: text.into(),
            stderr: String::new(),
        }
    }
    fn row(mailbox: &str, uid: u64, mailbox_guid: &str) -> CommandExecution {
        ok(&serde_json::json!([{"uid":uid.to_string(),"flags":"\\Seen \\Flagged","date.received":"2026-09-30 00:00:00","size.virtual":"32","mailbox":mailbox,"mailbox-guid":mailbox_guid,"guid":"fixture-9"}]).to_string())
    }
    fn request() -> MessageMoveRequest {
        MessageMoveRequest::new(
            MessageMovePolicy::default(),
            "INBOX",
            "Archive",
            9,
            MessageVersion::new("a".repeat(32), "fixture-9".into()).unwrap(),
        )
        .unwrap()
    }
    fn executor(outputs: Vec<CommandExecution>) -> Executor {
        Executor {
            outputs: RefCell::new(outputs.into()),
            calls: RefCell::new(Vec::new()),
            deadlines: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn assert_identity_bound_move(shell_shaped: bool) {
        let mut request = request();
        if shell_shaped {
            request.source_mailbox_name = "INBOX; id".into();
            request.destination_mailbox_name = "Archive$(id) 2>&1".into();
        }
        let executor = executor(vec![
            row(&request.source_mailbox_name, 9, &"a".repeat(32)),
            ok("[]"),
            ok(""),
            ok("[]"),
            row(&request.destination_mailbox_name, 17, &"b".repeat(32)),
        ]);
        let backend = DoveadmMessageMoveBackend::new(&executor, "/fixture/doveadm")
            .with_userdb_socket_path(Some(PathBuf::from("/var/run/osmap-userdb")))
            .with_command_timeout_secs(3);
        assert_eq!(backend.move_message("alice@example.test", &request), Ok(()));
        let calls = executor.calls.borrow();
        assert_eq!(calls.len(), 5);
        let mut expected: Vec<String> = [
            "-o",
            "stats_writer_socket_path=",
            "-o",
            "auth_socket_path=/var/run/osmap-userdb",
            "move",
            "-u",
            "alice@example.test",
            &request.destination_mailbox_name,
        ]
        .into_iter()
        .map(String::from)
        .collect();
        expected.extend(DoveadmMessageMoveBackend::<&Executor>::source_query(
            &request,
        ));
        assert_eq!(calls[2], expected);
        assert!(calls.iter().all(|args| !args
            .iter()
            .any(|arg| matches!(arg.as_str(), "expunge" | "id" | "$(id)" | "2>&1"))));
        let deadlines = executor.deadlines.borrow();
        assert_eq!(deadlines.len(), 5);
        assert!(deadlines
            .iter()
            .all(|value| *value <= Duration::from_secs(3)));
        assert!(deadlines.windows(2).all(|pair| pair[1] <= pair[0]));
    }

    #[test]
    fn stale_duplicate_mismatched_and_busy_moves_never_write() {
        for outputs in [
            vec![ok("[]")],
            vec![row("INBOX", 10, &"a".repeat(32))],
            vec![row("INBOX", 9, &"b".repeat(32))],
            vec![
                row("INBOX", 9, &"a".repeat(32)),
                row("Archive", 17, &"b".repeat(32)),
            ],
        ] {
            let executor = executor(outputs);
            let backend = DoveadmMessageMoveBackend::new(&executor, "/fixture/doveadm");
            assert_eq!(
                backend
                    .move_message("alice@example.test", &request())
                    .unwrap_err()
                    .backend,
                "message-move-stale"
            );
            assert!(executor
                .calls
                .borrow()
                .iter()
                .all(|args| !args.iter().any(|arg| arg == "move")));
            let _guard = backend.operation_gate.lock().unwrap();
            assert_eq!(
                backend
                    .move_message("alice@example.test", &request())
                    .unwrap_err()
                    .backend,
                "message-move-busy"
            );
        }
    }

    #[test]
    fn failed_write_or_confirmation_is_unknown_and_is_never_retried() {
        for tail in [
            vec![CommandExecution {
                status_code: 1,
                stdout: "private body".into(),
                stderr: "private body".into(),
            }],
            vec![ok(""), row("INBOX", 9, &"a".repeat(32))],
            vec![ok(""), ok("[]"), ok("[]")],
            vec![ok(""), ok("[]"), row("Wrong", 17, &"b".repeat(32))],
        ] {
            let mut outputs = vec![row("INBOX", 9, &"a".repeat(32)), ok("[]")];
            outputs.extend(tail);
            let executor = executor(outputs);
            let backend = DoveadmMessageMoveBackend::new(&executor, "/fixture/doveadm");
            let error = backend
                .move_message("alice@example.test", &request())
                .unwrap_err();
            assert_eq!(error.backend, "message-move-unknown");
            assert!(!error.reason.contains("private body"));
            assert_eq!(
                executor
                    .calls
                    .borrow()
                    .iter()
                    .filter(|args| args.iter().any(|arg| arg == "move"))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn invalid_or_unavailable_move_state_refuses_before_write() {
        let executor = executor(vec![ok("malformed private body")]);
        let backend = DoveadmMessageMoveBackend::new(&executor, "/fixture/doveadm");
        let error = backend
            .move_message("alice@example.test", &request())
            .unwrap_err();
        assert_eq!(error.backend, "message-move-unavailable");
        assert!(!error.reason.contains("private body"));
        for uid in [0, u64::from(u32::MAX) + 1] {
            let mut request = request();
            request.uid = uid;
            assert!(backend
                .move_message("alice@example.test", &request)
                .is_err());
        }
        assert!(backend.move_message("*", &request()).is_err());
        assert_eq!(executor.calls.borrow().len(), 1);
    }
}
