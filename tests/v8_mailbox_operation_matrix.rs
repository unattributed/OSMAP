use std::path::{Path, PathBuf};

use osmap::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use osmap::config::LogLevel;
use osmap::logging::{EventCategory, LogEvent};
use osmap::mailbox::{
    sort_message_search_results, sort_message_summaries, MailboxBackend, MailboxBackendError,
    MailboxEntry, MailboxListingDecision, MailboxListingPolicy, MailboxListingService,
    MailboxPublicFailureReason, MessageListBackend, MessageListDecision, MessageListPolicy,
    MessageListRequest, MessageListService, MessageMoveBackend, MessageMoveDecision,
    MessageMovePolicy, MessageMoveRequest, MessageMoveService, MessageSearchBackend,
    MessageSearchDecision, MessageSearchField, MessageSearchPolicy, MessageSearchRequest,
    MessageSearchResult, MessageSearchService, MessageSort, MessageSortColumn,
    MessageSortDirection, MessageSummary, MessageView, MessageViewBackend, MessageViewDecision,
    MessageViewPolicy, MessageViewRequest, MessageViewService,
};
use osmap::session::{SessionRecord, ValidatedSession};

const SESSION_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct StaticMailboxBackend {
    mailboxes: Vec<MailboxEntry>,
}

impl MailboxBackend for StaticMailboxBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        assert_eq!(canonical_username, "alice@example.com");
        Ok(self.mailboxes.clone())
    }
}

#[derive(Clone)]
struct StaticMessageListBackend {
    messages: Vec<MessageSummary>,
}

impl MessageListBackend for StaticMessageListBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
        assert_eq!(canonical_username, "alice@example.com");
        assert_eq!(request.mailbox_name, "INBOX");
        Ok(self.messages.clone())
    }
}

#[derive(Clone)]
struct StaticMessageSearchBackend {
    results: Vec<MessageSearchResult>,
}

impl MessageSearchBackend for StaticMessageSearchBackend {
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        assert_eq!(canonical_username, "alice@example.com");
        assert_eq!(request.mailbox_name, "INBOX");
        assert_eq!(request.query, "Alpha");
        assert_eq!(request.field, MessageSearchField::Subject);
        Ok(self.results.clone())
    }
}

#[derive(Clone)]
struct StaticMessageViewBackend {
    message: MessageView,
}

impl MessageViewBackend for StaticMessageViewBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        assert_eq!(canonical_username, "alice@example.com");
        assert_eq!(request.mailbox_name, "INBOX");
        assert_eq!(request.uid, 303);
        Ok(self.message.clone())
    }
}

#[derive(Clone)]
struct StaticMessageMoveBackend;

impl MessageMoveBackend for StaticMessageMoveBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        assert_eq!(canonical_username, "alice@example.com");
        assert_eq!(request.source_mailbox_name, "INBOX");
        assert_eq!(request.destination_mailbox_name, "Archive");
        assert_eq!(request.uid, 303);
        Ok(())
    }
}

#[derive(Clone)]
struct FailingMailboxBackend {
    backend: &'static str,
    reason: &'static str,
}

impl MailboxBackend for FailingMailboxBackend {
    fn list_mailboxes(
        &self,
        _canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        Err(MailboxBackendError {
            backend: self.backend,
            reason: self.reason.to_string(),
        })
    }
}

#[derive(Clone)]
struct FailingMessageListBackend {
    backend: &'static str,
    reason: &'static str,
}

impl MessageListBackend for FailingMessageListBackend {
    fn list_messages(
        &self,
        _canonical_username: &str,
        _request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
        Err(MailboxBackendError {
            backend: self.backend,
            reason: self.reason.to_string(),
        })
    }
}

#[derive(Clone)]
struct FailingMessageSearchBackend {
    backend: &'static str,
    reason: &'static str,
}

impl MessageSearchBackend for FailingMessageSearchBackend {
    fn search_messages(
        &self,
        _canonical_username: &str,
        _request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        Err(MailboxBackendError {
            backend: self.backend,
            reason: self.reason.to_string(),
        })
    }
}

#[derive(Clone)]
struct FailingMessageViewBackend {
    backend: &'static str,
    reason: &'static str,
}

impl MessageViewBackend for FailingMessageViewBackend {
    fn fetch_message(
        &self,
        _canonical_username: &str,
        _request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        Err(MailboxBackendError {
            backend: self.backend,
            reason: self.reason.to_string(),
        })
    }
}

#[derive(Clone)]
struct FailingMessageMoveBackend {
    backend: &'static str,
    reason: &'static str,
}

impl MessageMoveBackend for FailingMessageMoveBackend {
    fn move_message(
        &self,
        _canonical_username: &str,
        _request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        Err(MailboxBackendError {
            backend: self.backend,
            reason: self.reason.to_string(),
        })
    }
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn test_context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-v8-mailbox-operation",
        "127.0.0.1",
        "Firefox/V8-Mailbox-Operation",
    )
    .expect("authentication context should be valid")
}

fn validated_session_fixture() -> ValidatedSession {
    ValidatedSession {
        record: SessionRecord {
            session_id: SESSION_ID.to_string(),
            csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                .to_string(),
            canonical_username: "alice@example.com".to_string(),
            issued_at: 10,
            expires_at: 100,
            last_seen_at: 20,
            revoked_at: None,
            remote_addr: "127.0.0.1".to_string(),
            user_agent: "Firefox/V8-Mailbox-Operation".to_string(),
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

fn event_field<'a>(event: &'a LogEvent, key: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.as_str())
}

fn assert_audit_redacts_raw_session_id(event: &LogEvent) {
    assert!(
        event_field(event, "session_id").is_none(),
        "raw session_id field must not appear in mailbox audit events"
    );
    let session_ref = event_field(event, "session_ref").expect("session_ref should be present");
    assert_ne!(
        session_ref, SESSION_ID,
        "session_ref must not equal the raw session id"
    );
    assert!(
        session_ref.starts_with("asr-"),
        "session_ref should use the audit-session-ref prefix"
    );
}

fn mailbox_entries() -> Vec<MailboxEntry> {
    ["INBOX", "Archive", "Sent", "Projects/OSMAP", "Trash"]
        .into_iter()
        .map(|name| MailboxEntry::new(MailboxListingPolicy::default(), name).unwrap())
        .collect()
}

fn message_summaries() -> Vec<MessageSummary> {
    vec![
        MessageSummary {
            mailbox_name: "INBOX".to_string(),
            uid: 303,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-06-20 11:00:00 +0000".to_string(),
            size_virtual: 4096,
            subject: Some("Zeta Release".to_string()),
            from: Some("alice@example.com".to_string()),
        },
        MessageSummary {
            mailbox_name: "INBOX".to_string(),
            uid: 101,
            flags: vec!["\\Answered".to_string()],
            date_received: "2026-06-18 09:10:00 +0000".to_string(),
            size_virtual: 2048,
            subject: Some("Alpha Plan".to_string()),
            from: Some("bob@example.com".to_string()),
        },
        MessageSummary {
            mailbox_name: "INBOX".to_string(),
            uid: 202,
            flags: vec!["\\Flagged".to_string(), "\\Seen".to_string()],
            date_received: "2026-06-19 10:15:00 +0000".to_string(),
            size_virtual: 8192,
            subject: Some("Beta Review".to_string()),
            from: Some("carol@example.com".to_string()),
        },
    ]
}

fn search_results() -> Vec<MessageSearchResult> {
    vec![
        MessageSearchResult {
            mailbox_name: "Archive".to_string(),
            uid: 77,
            flags: vec!["\\Seen".to_string()],
            date_received: "2026-06-17 08:00:00 +0000".to_string(),
            size_virtual: 1500,
            subject: Some("Archived Alpha".to_string()),
            from: Some("archive@example.com".to_string()),
        },
        MessageSearchResult {
            mailbox_name: "INBOX".to_string(),
            uid: 88,
            flags: vec!["\\Flagged".to_string()],
            date_received: "2026-06-20 12:00:00 +0000".to_string(),
            size_virtual: 2500,
            subject: Some("Current Beta".to_string()),
            from: Some("current@example.com".to_string()),
        },
        MessageSearchResult {
            mailbox_name: "Projects/OSMAP".to_string(),
            uid: 99,
            flags: vec!["\\Answered".to_string()],
            date_received: "2026-06-19 06:30:00 +0000".to_string(),
            size_virtual: 3500,
            subject: Some("Project Gamma".to_string()),
            from: Some("project@example.com".to_string()),
        },
    ]
}

fn message_view_fixture() -> MessageView {
    let raw_message = include_str!("fixtures/mailbox_operations/message_view.eml");
    let (header_block, body_text) = raw_message
        .split_once("\n\n")
        .expect("message view fixture should contain a header/body separator");
    MessageView {
        mailbox_name: "INBOX".to_string(),
        uid: 303,
        flags: vec!["\\Seen".to_string()],
        date_received: "2026-06-20 04:50:00 +0000".to_string(),
        size_virtual: raw_message.len() as u64,
        header_block: header_block.to_string(),
        body_text: body_text.to_string(),
    }
}

fn sort(column: MessageSortColumn, direction: MessageSortDirection) -> MessageSort {
    MessageSort { column, direction }
}

fn summary_uids(messages: &[MessageSummary]) -> Vec<u64> {
    messages.iter().map(|message| message.uid).collect()
}

fn search_uids(results: &[MessageSearchResult]) -> Vec<u64> {
    results.iter().map(|result| result.uid).collect()
}

#[test]
fn v8_mailbox_operation_fixture_inventory_is_complete() {
    for relative in [
        "tests/fixtures/mailbox_operations/MANIFEST.md",
        "tests/fixtures/mailbox_operations/mailboxes.txt",
        "tests/fixtures/mailbox_operations/messages.tsv",
        "tests/fixtures/mailbox_operations/search_results.tsv",
        "tests/fixtures/mailbox_operations/message_view.eml",
        "tests/fixtures/mailbox_operations/move_operations.tsv",
        "docs/V8_MAILBOX_OPERATION_MATRIX.md",
        "maint/security/osmap-v8-mailbox-operation-gate.sh",
    ] {
        assert!(repo_path(relative).is_file(), "missing {relative}");
    }

    assert!(include_str!("fixtures/mailbox_operations/mailboxes.txt").contains("Projects/OSMAP"));
    assert!(include_str!("fixtures/mailbox_operations/messages.tsv").contains("Zeta Release"));
    assert!(
        include_str!("fixtures/mailbox_operations/search_results.tsv").contains("Project Gamma")
    );
    assert!(
        include_str!("fixtures/mailbox_operations/move_operations.tsv")
            .contains("rejected_zero_uid")
    );
}

#[test]
fn v8_mailbox_operation_matrix_validates_requests_and_sort_controls() {
    assert!(MailboxEntry::new(MailboxListingPolicy::default(), "").is_err());
    assert!(MailboxEntry::new(MailboxListingPolicy::default(), "INBOX\nInjected").is_err());
    assert!(MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: 4,
            max_mailboxes: 10,
        },
        "Archive"
    )
    .is_err());

    assert_eq!(
        MessageSort::from_query_values(Some("received"), None),
        Some(sort(
            MessageSortColumn::Received,
            MessageSortDirection::Desc
        ))
    );
    assert_eq!(
        MessageSort::from_query_values(Some("subject"), None),
        Some(sort(MessageSortColumn::Subject, MessageSortDirection::Asc))
    );
    assert_eq!(
        MessageSort::from_query_values(Some("uid"), Some("desc")),
        Some(sort(MessageSortColumn::Uid, MessageSortDirection::Desc))
    );
    assert_eq!(
        MessageSort::from_query_values(Some("unknown"), Some("asc")),
        None
    );
    assert_eq!(
        MessageSearchField::from_query_value("subject"),
        Some(MessageSearchField::Subject)
    );
    assert_eq!(MessageSearchField::from_query_value("body"), None);

    let search_request = MessageSearchRequest::new_with_field(
        MessageSearchPolicy::default(),
        "INBOX",
        "  Alpha  ",
        MessageSearchField::Subject,
    )
    .expect("valid search request should be accepted");
    assert_eq!(search_request.query, "Alpha");
    assert_eq!(search_request.field, MessageSearchField::Subject);

    assert!(MessageListRequest::new(MessageListPolicy::default(), "INBOX\rInjected").is_err());
    assert!(MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "   ").is_err());
    assert!(
        MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "bad\nquery").is_err()
    );
    assert!(MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 0).is_err());
    assert!(MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "INBOX", 303).is_err());
    assert!(MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive", 0).is_err());
}

#[test]
fn v8_mailbox_operation_matrix_preserves_list_and_search_sorting() {
    let mut by_received = message_summaries();
    sort_message_summaries(
        &mut by_received,
        Some(sort(
            MessageSortColumn::Received,
            MessageSortDirection::Desc,
        )),
    );
    assert_eq!(summary_uids(&by_received), vec![303, 202, 101]);

    let mut by_subject = message_summaries();
    sort_message_summaries(
        &mut by_subject,
        Some(sort(MessageSortColumn::Subject, MessageSortDirection::Asc)),
    );
    assert_eq!(summary_uids(&by_subject), vec![101, 202, 303]);

    let mut by_size = message_summaries();
    sort_message_summaries(
        &mut by_size,
        Some(sort(MessageSortColumn::Size, MessageSortDirection::Asc)),
    );
    assert_eq!(summary_uids(&by_size), vec![101, 303, 202]);

    let mut search_by_from = search_results();
    sort_message_search_results(
        &mut search_by_from,
        Some(sort(MessageSortColumn::From, MessageSortDirection::Desc)),
    );
    assert_eq!(search_uids(&search_by_from), vec![99, 88, 77]);

    let mut search_by_received = search_results();
    sort_message_search_results(
        &mut search_by_received,
        Some(sort(
            MessageSortColumn::Received,
            MessageSortDirection::Desc,
        )),
    );
    assert_eq!(search_uids(&search_by_received), vec![88, 99, 77]);
}

#[test]
fn v8_mailbox_operation_matrix_exercises_success_paths_and_audit_redaction() {
    let context = test_context();
    let session = validated_session_fixture();

    let mailbox_outcome = MailboxListingService::new(StaticMailboxBackend {
        mailboxes: mailbox_entries(),
    })
    .list_for_validated_session(&context, &session);
    match mailbox_outcome.decision {
        MailboxListingDecision::Listed {
            canonical_username,
            session_id,
            mailboxes,
        } => {
            assert_eq!(canonical_username, "alice@example.com");
            assert_eq!(session_id, SESSION_ID);
            assert_eq!(mailboxes.len(), 5);
        }
        other => panic!("expected mailbox listing success, got {other:?}"),
    }
    assert_eq!(mailbox_outcome.audit_event.action, "mailbox_listed");
    assert_eq!(
        event_field(&mailbox_outcome.audit_event, "mailbox_count"),
        Some("5")
    );
    assert_audit_redacts_raw_session_id(&mailbox_outcome.audit_event);

    let list_request =
        MessageListRequest::new(MessageListPolicy::default(), "INBOX").expect("valid list request");
    let message_list_outcome = MessageListService::new(StaticMessageListBackend {
        messages: message_summaries(),
    })
    .list_for_validated_session(&context, &session, &list_request);
    match message_list_outcome.decision {
        MessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
            ..
        } => {
            assert_eq!(canonical_username, "alice@example.com");
            assert_eq!(mailbox_name, "INBOX");
            assert_eq!(messages.len(), 3);
        }
        other => panic!("expected message list success, got {other:?}"),
    }
    assert_eq!(message_list_outcome.audit_event.action, "message_listed");
    assert_eq!(
        event_field(&message_list_outcome.audit_event, "message_count"),
        Some("3")
    );
    assert_audit_redacts_raw_session_id(&message_list_outcome.audit_event);

    let search_request = MessageSearchRequest::new_with_field(
        MessageSearchPolicy::default(),
        "INBOX",
        "Alpha",
        MessageSearchField::Subject,
    )
    .expect("valid search request");
    let search_outcome = MessageSearchService::new(StaticMessageSearchBackend {
        results: search_results(),
    })
    .search_for_validated_session(&context, &session, &search_request);
    match search_outcome.decision {
        MessageSearchDecision::Listed {
            canonical_username,
            mailbox_name,
            query,
            results,
            ..
        } => {
            assert_eq!(canonical_username, "alice@example.com");
            assert_eq!(mailbox_name, "INBOX");
            assert_eq!(query, "Alpha");
            assert_eq!(results.len(), 3);
        }
        other => panic!("expected search success, got {other:?}"),
    }
    assert_eq!(search_outcome.audit_event.action, "message_searched");
    assert_eq!(
        event_field(&search_outcome.audit_event, "result_count"),
        Some("3")
    );
    assert_audit_redacts_raw_session_id(&search_outcome.audit_event);

    let view_request =
        MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 303).expect("valid view");
    let view_outcome = MessageViewService::new(StaticMessageViewBackend {
        message: message_view_fixture(),
    })
    .fetch_for_validated_session(&context, &session, &view_request);
    match view_outcome.decision {
        MessageViewDecision::Retrieved {
            canonical_username,
            message,
            ..
        } => {
            assert_eq!(canonical_username, "alice@example.com");
            assert_eq!(message.uid, 303);
            assert!(message
                .body_text
                .contains("Mailbox operation message body."));
        }
        other => panic!("expected message view success, got {other:?}"),
    }
    assert_eq!(view_outcome.audit_event.action, "message_viewed");
    assert_audit_redacts_raw_session_id(&view_outcome.audit_event);

    let move_request =
        MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive", 303)
            .expect("valid move request");
    let move_outcome = MessageMoveService::new(StaticMessageMoveBackend)
        .move_for_validated_session(&context, &session, &move_request);
    match move_outcome.decision {
        MessageMoveDecision::Moved {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
            ..
        } => {
            assert_eq!(canonical_username, "alice@example.com");
            assert_eq!(source_mailbox_name, "INBOX");
            assert_eq!(destination_mailbox_name, "Archive");
            assert_eq!(uid, 303);
        }
        other => panic!("expected message move success, got {other:?}"),
    }
    assert_eq!(move_outcome.audit_event.action, "message_moved");
    assert_audit_redacts_raw_session_id(&move_outcome.audit_event);
}

#[test]
fn v8_mailbox_operation_matrix_exercises_fail_closed_paths() {
    let context = test_context();
    let session = validated_session_fixture();

    let mailbox_failure = MailboxListingService::new(FailingMailboxBackend {
        backend: "mailbox-helper",
        reason: "helper unavailable",
    })
    .list_for_validated_session(&context, &session);
    assert_eq!(
        mailbox_failure.decision,
        MailboxListingDecision::Denied {
            public_reason: MailboxPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(mailbox_failure.audit_event.action, "mailbox_list_failed");
    assert_eq!(
        event_field(&mailbox_failure.audit_event, "audit_reason"),
        Some("backend_unavailable")
    );
    assert_audit_redacts_raw_session_id(&mailbox_failure.audit_event);

    let list_request =
        MessageListRequest::new(MessageListPolicy::default(), "INBOX").expect("valid list request");
    let list_failure = MessageListService::new(FailingMessageListBackend {
        backend: "message-list-parser",
        reason: "message list output rejected",
    })
    .list_for_validated_session(&context, &session, &list_request);
    assert_eq!(
        list_failure.decision,
        MessageListDecision::Denied {
            public_reason: MailboxPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(list_failure.audit_event.action, "message_list_failed");
    assert_eq!(
        event_field(&list_failure.audit_event, "audit_reason"),
        Some("output_rejected")
    );
    assert_audit_redacts_raw_session_id(&list_failure.audit_event);

    let search_request = MessageSearchRequest::new_with_field(
        MessageSearchPolicy::default(),
        "INBOX",
        "Alpha",
        MessageSearchField::Subject,
    )
    .expect("valid search request");
    let search_failure = MessageSearchService::new(FailingMessageSearchBackend {
        backend: "message-search-parser",
        reason: "search output rejected",
    })
    .search_for_validated_session(&context, &session, &search_request);
    assert_eq!(
        search_failure.decision,
        MessageSearchDecision::Denied {
            public_reason: MailboxPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(search_failure.audit_event.action, "message_search_failed");
    assert_eq!(
        event_field(&search_failure.audit_event, "audit_reason"),
        Some("output_rejected")
    );
    assert_audit_redacts_raw_session_id(&search_failure.audit_event);

    let view_request =
        MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 303).expect("valid view");
    let view_not_found = MessageViewService::new(FailingMessageViewBackend {
        backend: "message-view-not-found",
        reason: "no message matched",
    })
    .fetch_for_validated_session(&context, &session, &view_request);
    assert_eq!(
        view_not_found.decision,
        MessageViewDecision::Denied {
            public_reason: MailboxPublicFailureReason::NotFound
        }
    );
    assert_eq!(view_not_found.audit_event.action, "message_view_failed");
    assert_eq!(
        event_field(&view_not_found.audit_event, "public_reason"),
        Some("not_found")
    );
    assert_eq!(
        event_field(&view_not_found.audit_event, "audit_reason"),
        Some("not_found")
    );
    assert_audit_redacts_raw_session_id(&view_not_found.audit_event);

    let move_request =
        MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive", 303)
            .expect("valid move request");
    let move_failure = MessageMoveService::new(FailingMessageMoveBackend {
        backend: "message-move-helper",
        reason: "move backend unavailable",
    })
    .move_for_validated_session(&context, &session, &move_request);
    assert_eq!(
        move_failure.decision,
        MessageMoveDecision::Denied {
            public_reason: MailboxPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(move_failure.audit_event.action, "message_move_failed");
    assert_eq!(
        event_field(&move_failure.audit_event, "audit_reason"),
        Some("backend_unavailable")
    );
    assert_audit_redacts_raw_session_id(&move_failure.audit_event);
}
