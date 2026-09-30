//! Identity-bound, idempotent Seen/Flagged updates with bounded confirmation.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth::CommandExecutor;
use crate::message_metadata::{MessageFlag, MessageVersion};

use super::mailbox_json::parse_json_summaries;
use super::{MailboxBackendError, MailboxEntry, MailboxListingPolicy, MessageListPolicy};

const FLAG_FIELDS: &str = "uid flags date.received size.virtual mailbox mailbox-guid guid";
pub const FLAG_OPERATION_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFlagRequest {
    pub mailbox_name: String,
    pub uid: u64,
    pub version: MessageVersion,
    pub flag: MessageFlag,
    pub enabled: bool,
}

impl MessageFlagRequest {
    pub fn new(
        mailbox_name: String,
        uid: u64,
        version: MessageVersion,
        flag: MessageFlag,
        enabled: bool,
    ) -> Result<Self, MailboxBackendError> {
        MailboxEntry::new(MailboxListingPolicy::default(), &mailbox_name)?;
        if uid == 0 || uid > u64::from(u32::MAX) {
            return Err(failure(
                "message-flag-invalid",
                "message UID is outside its bound",
            ));
        }
        let version = MessageVersion::new(version.mailbox_guid, version.message_guid)?;
        Ok(Self {
            mailbox_name,
            uid,
            version,
            flag,
            enabled,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageFlagResult {
    Updated,
    AlreadySet,
}

pub trait MessageFlagBackend {
    fn set_message_flag(
        &self,
        canonical_username: &str,
        request: &MessageFlagRequest,
    ) -> Result<MessageFlagResult, MailboxBackendError>;
}

#[derive(Debug, Clone)]
pub struct DoveadmMessageFlagBackend<E> {
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

impl<E> DoveadmMessageFlagBackend<E> {
    pub fn new(executor: E, doveadm_path: impl Into<PathBuf>) -> Self {
        Self {
            executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
            command_timeout_secs: FLAG_OPERATION_TIMEOUT_SECS,
            operation_gate: Arc::new(Mutex::new(())),
        }
    }

    pub fn with_userdb_socket_path(mut self, path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = path;
        self
    }

    pub fn with_command_timeout_secs(mut self, seconds: u64) -> Self {
        self.command_timeout_secs = seconds.clamp(1, FLAG_OPERATION_TIMEOUT_SECS);
        self
    }

    /// Runtime construction shares one gate across request-scoped backends.
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

    fn identity_args(request: &MessageFlagRequest) -> Vec<String> {
        vec![
            "mailbox".into(),
            request.mailbox_name.clone(),
            "mailbox-guid".into(),
            request.version.mailbox_guid.clone(),
            "uid".into(),
            request.uid.to_string(),
            "guid".into(),
            request.version.message_guid.clone(),
        ]
    }
}

impl<E: CommandExecutor> DoveadmMessageFlagBackend<E> {
    fn current_state(
        &self,
        username: &str,
        request: &MessageFlagRequest,
        deadline: Instant,
    ) -> Result<bool, MailboxBackendError> {
        let mut args = self.base_args();
        args.extend([
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "-u".into(),
            username.into(),
            FLAG_FIELDS.into(),
        ]);
        args.extend(Self::identity_args(request));
        let execution = self
            .executor
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| {
                        failure(
                            "message-flag-unavailable",
                            "flag operation deadline reached",
                        )
                    })?,
            )
            .map_err(|_| {
                failure(
                    "message-flag-unavailable",
                    "native flag-state read did not complete",
                )
            })?;
        let mut rows = parse_json_summaries(
            MessageListPolicy {
                max_messages: 1,
                ..MessageListPolicy::default()
            },
            &execution,
        )?;
        let row = rows.pop().ok_or_else(|| {
            failure(
                "message-flag-stale",
                "message identity is no longer current",
            )
        })?;
        if row.mailbox_name != request.mailbox_name
            || row.uid != request.uid
            || row.metadata.as_ref().map(|metadata| &metadata.version) != Some(&request.version)
        {
            return Err(failure(
                "message-flag-stale",
                "native response does not match the requested identity",
            ));
        }
        Ok(crate::mail_list::has_flag(&row.flags, request.flag.imap()))
    }
}

impl<E: CommandExecutor> MessageFlagBackend for DoveadmMessageFlagBackend<E> {
    fn set_message_flag(
        &self,
        canonical_username: &str,
        request: &MessageFlagRequest,
    ) -> Result<MessageFlagResult, MailboxBackendError> {
        // Never queue an unbounded series of stale mutations. The same gate is
        // shared by the helper's workers and by direct-runtime request builders.
        let _guard = self.operation_gate.try_lock().map_err(|_| {
            failure(
                "message-flag-busy",
                "another flag update is active or the operation gate is unavailable",
            )
        })?;
        let request = MessageFlagRequest::new(
            request.mailbox_name.clone(),
            request.uid,
            request.version.clone(),
            request.flag,
            request.enabled,
        )?;
        if canonical_username.is_empty()
            || canonical_username.len() > crate::auth::DEFAULT_USERNAME_MAX_LEN
            || canonical_username.chars().any(char::is_control)
            || canonical_username.contains(['*', '?'])
        {
            return Err(failure(
                "message-flag-invalid",
                "account identity is invalid",
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(self.command_timeout_secs);
        if self.current_state(canonical_username, &request, deadline)? == request.enabled {
            return Ok(MessageFlagResult::AlreadySet);
        }
        let mut args = self.base_args();
        args.extend([
            "flags".into(),
            if request.enabled {
                "add".into()
            } else {
                "remove".into()
            },
            "-u".into(),
            canonical_username.into(),
            request.flag.imap().into(),
        ]);
        args.extend(Self::identity_args(&request));
        let result = self.executor.run_with_stdin_timeout(
            self.doveadm_path.to_string_lossy().as_ref(),
            &args,
            "",
            deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    failure(
                        "message-flag-unavailable",
                        "flag operation deadline reached before mutation",
                    )
                })?,
        );
        if !matches!(result, Ok(ref execution) if execution.status_code == 0) {
            return Err(failure(
                "message-flag-unknown",
                "flag update could not be confirmed; refresh before choosing another action",
            ));
        }
        match self.current_state(canonical_username, &request, deadline) {
            Ok(enabled) if enabled == request.enabled => Ok(MessageFlagResult::Updated),
            _ => Err(failure(
                "message-flag-unknown",
                "flag state changed or confirmation failed; refresh before choosing another action",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CommandExecution, CommandExecutionError};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct Executor {
        outputs: RefCell<VecDeque<CommandExecution>>,
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl CommandExecutor for &Executor {
        fn run_with_stdin_bytes(
            &self,
            _program: &str,
            args: &[String],
            stdin: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert!(stdin.is_empty());
            self.calls.borrow_mut().push(args.to_vec());
            self.outputs
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| CommandExecutionError {
                    reason: "fixture queue exhausted".into(),
                })
        }
    }

    fn response(flags: &str) -> CommandExecution {
        CommandExecution { status_code: 0, stderr: String::new(), stdout: serde_json::json!([{
            "uid":"7", "flags":flags, "date.received":"2026-09-30 00:00:00", "size.virtual":"12",
            "mailbox":"INBOX", "mailbox-guid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "guid":"fixture-7"
        }]).to_string() }
    }
    fn request() -> MessageFlagRequest {
        MessageFlagRequest::new(
            "INBOX".into(),
            7,
            MessageVersion::new("a".repeat(32), "fixture-7".into()).expect("fixture"),
            MessageFlag::Flagged,
            true,
        )
        .expect("fixture")
    }

    #[test]
    fn mutation_is_identity_bound_and_confirmed_without_replacing_other_flags() {
        let executor = Executor {
            outputs: RefCell::new(VecDeque::from([
                response("\\Seen"),
                CommandExecution {
                    status_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
                response("\\Seen \\Flagged"),
            ])),
            calls: RefCell::new(Vec::new()),
        };
        let backend = DoveadmMessageFlagBackend::new(&executor, "/fixture/doveadm");
        assert_eq!(
            backend.set_message_flag("alice@example.test", &request()),
            Ok(MessageFlagResult::Updated)
        );
        let calls = executor.calls.borrow();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            &calls[1][2..7],
            &["flags", "add", "-u", "alice@example.test", "\\Flagged"]
        );
        assert_eq!(
            &calls[1][7..],
            &DoveadmMessageFlagBackend::<&Executor>::identity_args(&request())
        );
        assert!(!calls[1].iter().any(|arg| arg == "replace"));
    }

    #[test]
    fn duplicate_and_stale_requests_do_not_issue_writes() {
        let executor = Executor {
            outputs: RefCell::new(VecDeque::from([response("\\Flagged")])),
            calls: RefCell::new(Vec::new()),
        };
        let backend = DoveadmMessageFlagBackend::new(&executor, "/fixture/doveadm");
        assert_eq!(
            backend.set_message_flag("alice@example.test", &request()),
            Ok(MessageFlagResult::AlreadySet)
        );
        assert_eq!(executor.calls.borrow().len(), 1);
        executor.outputs.borrow_mut().push_back(CommandExecution {
            status_code: 0,
            stdout: "[]".into(),
            stderr: String::new(),
        });
        assert_eq!(
            backend
                .set_message_flag("alice@example.test", &request())
                .expect_err("stale")
                .backend,
            "message-flag-stale"
        );
        assert_eq!(executor.calls.borrow().len(), 2);
        let _guard = backend.operation_gate.lock().expect("fixture lock");
        assert_eq!(
            backend
                .set_message_flag("alice@example.test", &request())
                .expect_err("busy")
                .backend,
            "message-flag-busy"
        );
        assert_eq!(executor.calls.borrow().len(), 2);
    }

    #[test]
    fn uncertain_mutation_is_never_retried_or_reported_successful() {
        let executor = Executor {
            outputs: RefCell::new(VecDeque::from([
                response(""),
                CommandExecution {
                    status_code: 1,
                    stdout: "private fixture".into(),
                    stderr: "private fixture".into(),
                },
            ])),
            calls: RefCell::new(Vec::new()),
        };
        let backend = DoveadmMessageFlagBackend::new(&executor, "/fixture/doveadm");
        let error = backend
            .set_message_flag("alice@example.test", &request())
            .expect_err("unconfirmed");
        assert_eq!(error.backend, "message-flag-unknown");
        assert!(!error.reason.contains("private fixture"));
        assert_eq!(executor.calls.borrow().len(), 2);
    }
}
