//! Mailbox listing for the first WP5 read-path slice.
//!
//! This module keeps the first mailbox read path intentionally small:
//! - session validation remains a separate gate handled before mailbox access
//! - mailbox listing uses the existing Dovecot surface instead of a new mail
//!   stack
//! - mailbox, message-list, and message-view results/failures are emitted as
//!   structured audit events

#[path = "mailbox_backend.rs"]
mod mailbox_backend;
#[path = "mailbox_model.rs"]
mod mailbox_model;
#[path = "mailbox_parse.rs"]
mod mailbox_parse;
#[path = "mailbox_service.rs"]
mod mailbox_service;

pub use self::mailbox_backend::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageMoveBackend,
    DoveadmMessageSearchBackend, DoveadmMessageViewBackend,
};
pub use self::mailbox_model::{
    MailboxAuditFailureReason, MailboxBackend, MailboxBackendError, MailboxEntry,
    MailboxListingDecision, MailboxListingOutcome, MailboxListingPolicy,
    MailboxPublicFailureReason, MessageListBackend, MessageListDecision, MessageListOutcome,
    MessageListPolicy, MessageListRequest, MessageMoveBackend, MessageMoveDecision,
    MessageMoveOutcome, MessageMovePolicy, MessageMoveRequest, MessageSearchBackend,
    MessageSearchDecision, MessageSearchOutcome, MessageSearchPolicy, MessageSearchRequest,
    MessageSearchResult, MessageSummary, MessageView, MessageViewBackend, MessageViewDecision,
    MessageViewOutcome, MessageViewPolicy, MessageViewRequest, DEFAULT_MAILBOX_NAME_MAX_LEN,
    DEFAULT_MAX_MAILBOXES, DEFAULT_MAX_MESSAGES, DEFAULT_MAX_SEARCH_RESULTS,
    DEFAULT_MESSAGE_BODY_MAX_LEN, DEFAULT_MESSAGE_DATE_MAX_LEN,
    DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN, DEFAULT_MESSAGE_HEADER_MAX_LEN,
    DEFAULT_SEARCH_HEADER_VALUE_MAX_LEN, DEFAULT_SEARCH_QUERY_MAX_LEN,
};
use self::mailbox_parse::{
    parse_doveadm_mailbox_list_output, parse_doveadm_message_list_output,
    parse_doveadm_message_search_output, parse_doveadm_message_view_output,
};
pub use self::mailbox_service::{
    MailboxListingService, MessageListService, MessageMoveService, MessageSearchService,
    MessageViewService,
};
#[cfg(test)]
use crate::auth::CommandExecutor;
use crate::auth::{AuthenticationContext, CommandExecution};
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::session::ValidatedSession;

/// Produces a compact single-line diagnostic from command output.
pub(super) fn concise_command_diagnostics(stdout: &str, stderr: &str) -> String {
    let combined = format!("{} {}", stderr.trim(), stdout.trim())
        .trim()
        .to_string();
    if combined.is_empty() {
        return "no command diagnostics returned".to_string();
    }

    combined.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthenticationDecision, AuthenticationPolicy, AuthenticationService, CommandExecutionError,
        PrimaryAuthBackendError, PrimaryAuthVerdict, PrimaryCredentialBackend,
        RequiredSecondFactor, SecondFactorService,
    };
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use crate::session::{
        FileSessionStore, RandomSource, SessionError, SessionService, SESSION_TOKEN_BYTES,
    };
    use crate::totp::{FileTotpSecretStore, TimeProvider, TotpPolicy, TotpVerifier};
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    struct AcceptingPrimaryBackend;

    impl PrimaryCredentialBackend for AcceptingPrimaryBackend {
        fn verify_primary(
            &self,
            _context: &AuthenticationContext,
            username: &str,
            password: &str,
        ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
            if username == "alice@example.com" && password == "correct horse battery staple" {
                return Ok(PrimaryAuthVerdict::Accept {
                    canonical_username: "alice@example.com".to_string(),
                });
            }

            Ok(PrimaryAuthVerdict::Reject)
        }
    }

    #[derive(Debug, Clone)]
    struct FixedTimeProvider {
        unix_timestamp: Cell<u64>,
    }

    impl FixedTimeProvider {
        fn new(unix_timestamp: u64) -> Self {
            Self {
                unix_timestamp: Cell::new(unix_timestamp),
            }
        }
    }

    impl TimeProvider for FixedTimeProvider {
        fn unix_timestamp(&self) -> u64 {
            self.unix_timestamp.get()
        }
    }

    #[derive(Debug, Clone)]
    struct StaticRandomSource {
        bytes: Vec<u8>,
    }

    impl RandomSource for StaticRandomSource {
        fn fill_bytes(&self, buffer: &mut [u8]) -> Result<(), SessionError> {
            buffer.copy_from_slice(&self.bytes[..buffer.len()]);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct StubCommandExecutor {
        execution: Result<CommandExecution, CommandExecutionError>,
        program: Option<String>,
        args: Option<Vec<String>>,
    }

    impl StubCommandExecutor {
        fn success(execution: CommandExecution) -> Self {
            Self {
                execution: Ok(execution),
                program: None,
                args: None,
            }
        }
    }

    impl CommandExecutor for Rc<std::cell::RefCell<StubCommandExecutor>> {
        fn run_with_stdin_bytes(
            &self,
            program: &str,
            args: &[String],
            _stdin_data: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            let mut state = self.borrow_mut();
            state.program = Some(program.to_string());
            state.args = Some(args.to_vec());
            state.execution.clone()
        }
    }

    struct FailingMailboxBackend;

    impl MailboxBackend for FailingMailboxBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-mailbox-backend",
                reason: "imap bridge unavailable".to_string(),
            })
        }
    }

    struct FailingMessageListBackend;

    impl MessageListBackend for FailingMessageListBackend {
        fn list_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageListRequest,
        ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-message-backend",
                reason: "message index unavailable".to_string(),
            })
        }
    }

    struct FailingMessageSearchBackend;

    impl MessageSearchBackend for FailingMessageSearchBackend {
        fn search_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageSearchRequest,
        ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-message-search-backend",
                reason: "message search unavailable".to_string(),
            })
        }
    }

    struct MissingMessageViewBackend;

    impl MessageViewBackend for MissingMessageViewBackend {
        fn fetch_message(
            &self,
            _canonical_username: &str,
            _request: &MessageViewRequest,
        ) -> Result<MessageView, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "message-view-not-found",
                reason: "no message matched the request".to_string(),
            })
        }
    }

    struct FailingMessageMoveBackend;

    impl MessageMoveBackend for FailingMessageMoveBackend {
        fn move_message(
            &self,
            _canonical_username: &str,
            _request: &MessageMoveRequest,
        ) -> Result<(), MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-message-move-backend",
                reason: "move operation unavailable".to_string(),
            })
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-mailbox",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            FixedTimeProvider::new(1).unix_timestamp()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn parses_mailbox_entries_from_doveadm_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "INBOX\nSent\nDrafts\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );

        let mailboxes = backend
            .list_mailboxes("alice@example.com")
            .expect("mailbox list should succeed");

        assert_eq!(
            mailboxes,
            vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent".to_string(),
                },
                MailboxEntry {
                    name: "Drafts".to_string(),
                },
            ]
        );

        let recorded = executor.borrow();
        assert_eq!(recorded.program.as_deref(), Some("/usr/local/bin/doveadm"));
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "mailbox".to_string(),
                "list".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn mailbox_list_uses_explicit_userdb_socket_when_configured() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "INBOX\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(PathBuf::from("/var/run/osmap-userdb")));

        let _ = backend
            .list_mailboxes("alice@example.com")
            .expect("mailbox list should succeed");

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-o".to_string(),
                "auth_socket_path=/var/run/osmap-userdb".to_string(),
                "mailbox".to_string(),
                "list".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn parses_message_summaries_from_doveadm_flow_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: concat!(
                    "uid=4 flags=\"\\\\Seen\" date.received=2026-03-27 09:00:00 +0000 size.virtual=2048 mailbox=INBOX\n",
                    "uid=5 flags=\"\\\\Seen \\\\Answered\" date.received=2026-03-27 10:15:00 +0000 size.virtual=4096 mailbox=INBOX\n"
                )
                .to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");

        let messages = backend
            .list_messages("alice@example.com", &request)
            .expect("message list should succeed");

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].uid, 4);
        assert_eq!(messages[0].mailbox_name, "INBOX");
        assert_eq!(messages[0].flags, vec!["\\Seen".to_string()]);
        assert_eq!(
            messages[1].flags,
            vec!["\\Seen".to_string(), "\\Answered".to_string()]
        );

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-f".to_string(),
                "flow".to_string(),
                "fetch".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "uid flags date.received size.virtual mailbox".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "all".to_string(),
            ]
        );
    }

    #[test]
    fn parses_message_view_from_doveadm_flow_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "uid=9 flags=\"\\\\Seen\" date.received=2026-03-27 11:00:00 +0000 size.virtual=512 mailbox=INBOX hdr=\"Subject: Test message\\nFrom: Alice <alice@example.com>\\n\" body=\"Hello world\\nSecond line\\n\"\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageViewBackend::new(
            MessageViewPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");

        let message = backend
            .fetch_message("alice@example.com", &request)
            .expect("message retrieval should succeed");

        assert_eq!(message.uid, 9);
        assert_eq!(message.mailbox_name, "INBOX");
        assert_eq!(message.flags, vec!["\\Seen".to_string()]);
        assert_eq!(
            message.header_block,
            "Subject: Test message\nFrom: Alice <alice@example.com>\n"
        );
        assert_eq!(message.body_text, "Hello world\nSecond line\n");

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-f".to_string(),
                "flow".to_string(),
                "fetch".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "uid flags date.received size.virtual mailbox hdr body".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "uid".to_string(),
                "9".to_string(),
            ]
        );
    }

    #[test]
    fn parses_message_search_results_from_doveadm_flow_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: concat!(
                    "uid=14 flags=\"\\\\Seen\" date.received=2026-03-27 15:00:00 +0000 size.virtual=2048 mailbox=INBOX hdr.subject=\"Quarterly report\" hdr.from=\"Alice <alice@example.com>\"\n",
                    "uid=15 flags=\"\" date.received=2026-03-27 16:00:00 +0000 size.virtual=1024 mailbox=INBOX hdr.subject=\"Follow-up\" hdr.from=\"Bob <bob@example.com>\"\n"
                )
                .to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should be valid");

        let results = backend
            .search_messages("alice@example.com", &request)
            .expect("message search should succeed");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].uid, 14);
        assert_eq!(results[0].subject.as_deref(), Some("Quarterly report"));
        assert_eq!(
            results[0].from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(results[1].uid, 15);

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-f".to_string(),
                "flow".to_string(),
                "fetch".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "uid flags date.received size.virtual mailbox hdr.subject hdr.from".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "TEXT".to_string(),
                "quarterly report".to_string(),
            ]
        );
    }

    #[test]
    fn message_move_uses_doveadm_move_command_shape() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageMoveBackend::new(executor.clone(), "/usr/local/bin/doveadm")
            .with_userdb_socket_path(Some(PathBuf::from("/var/run/osmap-userdb")));
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should be valid");

        backend
            .move_message("alice@example.com", &request)
            .expect("message move should succeed");

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-o".to_string(),
                "auth_socket_path=/var/run/osmap-userdb".to_string(),
                "move".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "Archive/2026".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "uid".to_string(),
                "9".to_string(),
            ]
        );
    }

    #[test]
    fn parses_multiline_message_view_from_live_style_flow_output() {
        let message = parse_doveadm_message_view_output(
            MessageViewPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: concat!(
                    "uid=1 flags=\\Recent date.received=2026-03-28 01:00:32 size.virtual=606 mailbox=INBOX hdr=From: OSMAP Validation <osmap-helper-validation@blackbagsecurity.com>\n",
                    "To: OSMAP Validation <osmap-helper-validation@blackbagsecurity.com>\n",
                    "Subject: OSMAP helper attachment validation\n",
                    "MIME-Version: 1.0\n",
                    "Content-Type: multipart/mixed; boundary=\"osmap-boundary\"\n",
                    "\n",
                    " body=--osmap-boundary\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "This is the helper validation message body.\n",
                    "\n",
                    "--osmap-boundary--\n",
                )
                .to_string(),
                stderr: String::new(),
            },
        )
        .expect("multiline flow output should parse");

        assert_eq!(message.uid, 1);
        assert_eq!(message.mailbox_name, "INBOX");
        assert_eq!(message.size_virtual, 606);
        assert!(message
            .header_block
            .contains("Subject: OSMAP helper attachment validation"));
        assert!(message
            .body_text
            .contains("This is the helper validation message body."));
    }

    #[test]
    fn rejects_message_list_output_missing_required_fields() {
        let error = parse_doveadm_message_list_output(
            MessageListPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "uid=4 flags=\"\" size.virtual=2048 mailbox=INBOX\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("missing fields must fail");

        assert_eq!(error.backend, "message-list-parser");
        assert_eq!(
            error.reason,
            "missing required message-list field date.received"
        );
    }

    #[test]
    fn rejects_message_view_output_missing_required_fields() {
        let error = parse_doveadm_message_view_output(
            MessageViewPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "uid=9 flags=\"\\\\Seen\" date.received=\"2026-03-27 11:00:00 +0000\" size.virtual=512 mailbox=INBOX hdr=\"Subject: test\\n\"\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("missing body field must fail");

        assert_eq!(error.backend, "message-view-parser");
        assert_eq!(error.reason, "missing required message-view field body");
    }

    #[test]
    fn rejects_message_search_with_empty_query() {
        let error = MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "   ")
            .expect_err("empty query must fail");

        assert_eq!(error.backend, "message-search-parser");
        assert_eq!(error.reason, "search query must not be empty");
    }

    #[test]
    fn rejects_message_search_output_missing_required_fields() {
        let error = parse_doveadm_message_search_output(
            MessageSearchPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "uid=4 flags=\"\" size.virtual=2048 mailbox=INBOX hdr.subject=\"Test\"\n"
                    .to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("missing fields must fail");

        assert_eq!(error.backend, "message-search-parser");
        assert_eq!(
            error.reason,
            "missing required message-search field date.received"
        );
    }

    #[test]
    fn rejects_message_move_with_same_source_and_destination() {
        let error = MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "INBOX", 9)
            .expect_err("identical source and destination must fail");

        assert_eq!(error.backend, "message-move-parser");
        assert_eq!(
            error.reason,
            "destination mailbox must differ from source mailbox"
        );
    }

    #[test]
    fn rejects_control_characters_in_mailbox_output() {
        let error = parse_doveadm_mailbox_list_output(
            MailboxListingPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "INBOX\nSent\u{0007}\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("control characters must fail");

        assert_eq!(error.backend, "mailbox-parser");
        assert_eq!(error.reason, "mailbox name contains control characters");
    }

    #[test]
    fn message_view_service_emits_audit_quality_success_events() {
        let service = MessageViewService::new(StaticMessageViewBackend {
            message: MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            },
        });
        let validated_session = validated_session_fixture();
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");

        let outcome =
            service.fetch_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_viewed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 6262);
        assert_eq!(
            rendered,
            format!(
                "ts=6262 level=info category=mailbox action=message_viewed msg=\"message retrieval completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_name=\"INBOX\" uid=\"9\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_view_service_maps_missing_messages_to_not_found() {
        let service = MessageViewService::new(MissingMessageViewBackend);
        let validated_session = validated_session_fixture();
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");

        let outcome =
            service.fetch_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageViewDecision::Denied {
                public_reason: MailboxPublicFailureReason::NotFound,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_view_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn mailbox_service_emits_audit_quality_success_events() {
        let service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Archive".to_string(),
                },
            ],
        });
        let validated_session = validated_session_fixture();

        let outcome = service.list_for_validated_session(&test_context(), &validated_session);

        assert_eq!(
            outcome.decision,
            MailboxListingDecision::Listed {
                canonical_username: "alice@example.com".to_string(),
                session_id: validated_session.record.session_id.clone(),
                mailboxes: vec![
                    MailboxEntry {
                        name: "INBOX".to_string(),
                    },
                    MailboxEntry {
                        name: "Archive".to_string(),
                    },
                ],
            }
        );
        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "mailbox_listed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 4242);
        assert_eq!(
            rendered,
            format!(
                "ts=4242 level=info category=mailbox action=mailbox_listed msg=\"mailbox listing completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn mailbox_service_translates_backend_failures_into_bounded_events() {
        let service = MailboxListingService::new(FailingMailboxBackend);
        let validated_session = validated_session_fixture();

        let outcome = service.list_for_validated_session(&test_context(), &validated_session);

        assert_eq!(
            outcome.decision,
            MailboxListingDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "mailbox_list_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn message_list_service_emits_audit_quality_success_events() {
        let service = MessageListService::new(StaticMessageListBackend {
            messages: vec![
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 4,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 09:00:00 +0000".to_string(),
                    size_virtual: 2048,
                },
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 5,
                    flags: vec![],
                    date_received: "2026-03-27 09:30:00 +0000".to_string(),
                    size_virtual: 1024,
                },
            ],
        });
        let validated_session = validated_session_fixture();
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");

        let outcome =
            service.list_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_listed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 5252);
        assert_eq!(
            rendered,
            format!(
                "ts=5252 level=info category=mailbox action=message_listed msg=\"message list retrieval completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_name=\"INBOX\" message_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_list_service_translates_backend_failures_into_bounded_events() {
        let service = MessageListService::new(FailingMessageListBackend);
        let validated_session = validated_session_fixture();
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");

        let outcome =
            service.list_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageListDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_list_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn message_search_service_emits_audit_quality_success_events() {
        let service = MessageSearchService::new(StaticMessageSearchBackend {
            results: vec![
                MessageSearchResult {
                    mailbox_name: "INBOX".to_string(),
                    uid: 14,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 15:00:00 +0000".to_string(),
                    size_virtual: 2048,
                    subject: Some("Quarterly report".to_string()),
                    from: Some("Alice <alice@example.com>".to_string()),
                },
                MessageSearchResult {
                    mailbox_name: "INBOX".to_string(),
                    uid: 15,
                    flags: Vec::new(),
                    date_received: "2026-03-27 16:00:00 +0000".to_string(),
                    size_virtual: 1024,
                    subject: Some("Follow-up".to_string()),
                    from: Some("Bob <bob@example.com>".to_string()),
                },
            ],
        });
        let validated_session = validated_session_fixture();
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should be valid");

        let outcome =
            service.search_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_searched");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 5353);
        assert_eq!(
            rendered,
            format!(
                "ts=5353 level=info category=mailbox action=message_searched msg=\"message search completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_name=\"INBOX\" query=\"quarterly report\" result_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_search_service_translates_backend_failures_into_bounded_events() {
        let service = MessageSearchService::new(FailingMessageSearchBackend);
        let validated_session = validated_session_fixture();
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should be valid");

        let outcome =
            service.search_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageSearchDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_search_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn message_move_service_emits_audit_quality_success_events() {
        let service = MessageMoveService::new(StaticMessageMoveBackend);
        let validated_session = validated_session_fixture();
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should be valid");

        let outcome =
            service.move_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_moved");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 5454);
        assert_eq!(
            rendered,
            format!(
                "ts=5454 level=info category=mailbox action=message_moved msg=\"message move completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" source_mailbox_name=\"INBOX\" destination_mailbox_name=\"Archive/2026\" uid=\"9\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_move_service_translates_backend_failures_into_bounded_events() {
        let service = MessageMoveService::new(FailingMessageMoveBackend);
        let validated_session = validated_session_fixture();
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should be valid");

        let outcome =
            service.move_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageMoveDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_move_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn full_auth_session_and_mailbox_flow_succeeds() {
        let secret_dir = temp_dir("osmap-mailbox-secret");
        let session_dir = temp_dir("osmap-mailbox-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(&secret_path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should be written");

        let auth_service =
            AuthenticationService::new(AuthenticationPolicy::default(), AcceptingPrimaryBackend);
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );
        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0x88; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(
                &test_context(),
                &canonical_username,
                RequiredSecondFactor::Totp,
            )
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent".to_string(),
                },
            ],
        });
        let outcome = service.list_for_validated_session(&test_context(), &validated);

        match outcome.decision {
            MailboxListingDecision::Listed {
                canonical_username,
                session_id,
                mailboxes,
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(session_id, validated.record.session_id);
                assert_eq!(mailboxes.len(), 2);
                assert_eq!(mailboxes[0].name, "INBOX");
            }
            other => panic!("expected mailbox listing, got {other:?}"),
        }
    }

    #[test]
    fn full_auth_session_mailbox_and_message_list_flow_succeeds() {
        let secret_dir = temp_dir("osmap-message-secret");
        let session_dir = temp_dir("osmap-message-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(&secret_path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should be written");

        let auth_service =
            AuthenticationService::new(AuthenticationPolicy::default(), AcceptingPrimaryBackend);
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );
        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0x99; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(
                &test_context(),
                &canonical_username,
                RequiredSecondFactor::Totp,
            )
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let mailbox_service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![MailboxEntry {
                name: "INBOX".to_string(),
            }],
        });
        let mailbox_outcome =
            mailbox_service.list_for_validated_session(&test_context(), &validated);
        match mailbox_outcome.decision {
            MailboxListingDecision::Listed { mailboxes, .. } => {
                assert_eq!(mailboxes.len(), 1);
                assert_eq!(mailboxes[0].name, "INBOX");
            }
            other => panic!("expected mailbox listing, got {other:?}"),
        }

        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");
        let message_service = MessageListService::new(StaticMessageListBackend {
            messages: vec![MessageSummary {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
            }],
        });
        let outcome =
            message_service.list_for_validated_session(&test_context(), &validated, &request);

        match outcome.decision {
            MessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
                ..
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(mailbox_name, "INBOX");
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].uid, 9);
            }
            other => panic!("expected message list, got {other:?}"),
        }
    }

    #[test]
    fn full_auth_session_message_view_flow_succeeds() {
        let secret_dir = temp_dir("osmap-view-secret");
        let session_dir = temp_dir("osmap-view-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(&secret_path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should be written");

        let auth_service =
            AuthenticationService::new(AuthenticationPolicy::default(), AcceptingPrimaryBackend);
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );
        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0xaa; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(
                &test_context(),
                &canonical_username,
                RequiredSecondFactor::Totp,
            )
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");
        let service = MessageViewService::new(StaticMessageViewBackend {
            message: MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            },
        });
        let outcome = service.fetch_for_validated_session(&test_context(), &validated, &request);

        match outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                message,
                ..
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(message.uid, 9);
                assert_eq!(message.mailbox_name, "INBOX");
                assert_eq!(message.body_text, "Hello world\n");
            }
            other => panic!("expected message view, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_mailbox_list_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMailboxListBackend::default();
        let error = backend
            .list_mailboxes("osmap-no-such-user@example.invalid")
            .expect_err("missing users should not produce mailbox listings");

        assert_eq!(error.backend, "doveadm-mailbox-list");
        assert!(error.reason.contains("status 67"));
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_message_list_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMessageListBackend::default();
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");
        let error = backend
            .list_messages("osmap-no-such-user@example.invalid", &request)
            .expect_err("missing users should not produce message listings");

        assert_eq!(error.backend, "doveadm-message-list");
        assert!(error.reason.contains("status 67"));
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_message_view_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMessageViewBackend::default();
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 1)
            .expect("request should be valid");
        let error = backend
            .fetch_message("osmap-no-such-user@example.invalid", &request)
            .expect_err("missing users should not produce message retrieval");

        assert_eq!(error.backend, "doveadm-message-view");
        assert!(error.reason.contains("status 67"));
    }

    #[derive(Debug, Clone)]
    struct StaticMailboxBackend {
        mailboxes: Vec<MailboxEntry>,
    }

    impl MailboxBackend for StaticMailboxBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Ok(self.mailboxes.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageListBackend {
        messages: Vec<MessageSummary>,
    }

    impl MessageListBackend for StaticMessageListBackend {
        fn list_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageListRequest,
        ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
            Ok(self.messages.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageSearchBackend {
        results: Vec<MessageSearchResult>,
    }

    impl MessageSearchBackend for StaticMessageSearchBackend {
        fn search_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageSearchRequest,
        ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
            Ok(self.results.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageViewBackend {
        message: MessageView,
    }

    impl MessageViewBackend for StaticMessageViewBackend {
        fn fetch_message(
            &self,
            _canonical_username: &str,
            _request: &MessageViewRequest,
        ) -> Result<MessageView, MailboxBackendError> {
            Ok(self.message.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageMoveBackend;

    impl MessageMoveBackend for StaticMessageMoveBackend {
        fn move_message(
            &self,
            _canonical_username: &str,
            _request: &MessageMoveRequest,
        ) -> Result<(), MailboxBackendError> {
            Ok(())
        }
    }

    fn validated_session_fixture() -> ValidatedSession {
        ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }
}
