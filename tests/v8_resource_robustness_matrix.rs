use std::path::{Path, PathBuf};

use osmap::attachment::{
    AttachmentDownloadDecision, AttachmentDownloadPolicy, AttachmentDownloadPublicFailureReason,
    AttachmentDownloadService,
};
use osmap::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use osmap::config::LogLevel;
use osmap::logging::{EventCategory, LogEvent};
use osmap::mailbox::{
    sort_message_search_results, sort_message_summaries, MailboxEntry, MailboxListingPolicy,
    MessageMovePolicy, MessageMoveRequest, MessageSearchResult, MessageSort, MessageSortColumn,
    MessageSortDirection, MessageSummary, MessageView, MessageViewPolicy, MessageViewRequest,
};
use osmap::session::{SessionRecord, SessionToken, ValidatedSession, SESSION_TOKEN_HEX_LEN};

const SESSION_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn test_context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-v8-resource-robustness",
        "127.0.0.1",
        "Firefox/V8-Resource-Robustness",
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
            user_agent: "Firefox/V8-Resource-Robustness".to_string(),
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

fn message_view_from_fixture(raw_message: &str) -> MessageView {
    let normalized = raw_message.replace("\r\n", "\n");
    let (header_block, body_text) = normalized
        .split_once("\n\n")
        .expect("fixture should contain a header/body separator");
    MessageView {
        mailbox_name: "INBOX".to_string(),
        uid: 909,
        flags: vec!["\\Seen".to_string()],
        date_received: "2026-06-20 06:00:00 +0000".to_string(),
        size_virtual: normalized.len() as u64,
        header_block: header_block.to_string(),
        body_text: body_text.to_string(),
    }
}

fn event_field<'a>(event: &'a LogEvent, key: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.as_str())
}

fn sort(column: MessageSortColumn, direction: MessageSortDirection) -> MessageSort {
    MessageSort { column, direction }
}

fn synthetic_summaries(count: u64) -> Vec<MessageSummary> {
    (1..=count)
        .rev()
        .map(|uid| MessageSummary {
            mailbox_name: "INBOX".to_string(),
            uid,
            flags: if uid % 2 == 0 {
                vec!["\\Seen".to_string()]
            } else {
                vec!["\\Flagged".to_string()]
            },
            date_received: format!("2026-06-20 {:02}:00:00 +0000", uid % 24),
            size_virtual: uid * 10,
            subject: Some(format!("subject-{uid:03}")),
            from: Some(format!("sender-{uid:03}@example.com")),
        })
        .collect()
}

fn synthetic_search_results(count: u64) -> Vec<MessageSearchResult> {
    (1..=count)
        .map(|uid| MessageSearchResult {
            mailbox_name: if uid % 2 == 0 {
                "INBOX".to_string()
            } else {
                "Archive".to_string()
            },
            uid,
            flags: vec!["\\Seen".to_string()],
            date_received: format!("2026-06-20 {:02}:30:00 +0000", uid % 24),
            size_virtual: uid * 100,
            subject: Some(format!("result-{uid:03}")),
            from: Some(format!("result-{uid:03}@example.com")),
        })
        .collect()
}

fn summary_uids(messages: &[MessageSummary]) -> Vec<u64> {
    messages.iter().map(|message| message.uid).collect()
}

fn search_uids(results: &[MessageSearchResult]) -> Vec<u64> {
    results.iter().map(|result| result.uid).collect()
}

#[test]
fn v8_resource_robustness_fixture_inventory_is_complete() {
    for relative in [
        "tests/fixtures/resource_robustness/MANIFEST.md",
        "tests/fixtures/resource_robustness/limits.env",
        "tests/fixtures/resource_robustness/sort_matrix.tsv",
        "tests/fixtures/resource_robustness/rejection_matrix.tsv",
        "docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md",
        "maint/security/osmap-v8-resource-robustness-gate.sh",
    ] {
        assert!(repo_path(relative).is_file(), "missing {relative}");
    }

    assert!(include_str!("fixtures/resource_robustness/limits.env")
        .contains("synthetic_message_count=256"));
    assert!(
        include_str!("fixtures/resource_robustness/sort_matrix.tsv").contains("message_uid_asc")
    );
    assert!(
        include_str!("fixtures/resource_robustness/rejection_matrix.tsv")
            .contains("attachment_download_max_bytes")
    );
}

#[test]
fn v8_resource_robustness_matrix_rejects_bounded_invalid_inputs() {
    assert!(
        SessionToken::new("a".repeat(SESSION_TOKEN_HEX_LEN * 2)).is_err(),
        "overlength session tokens must be rejected"
    );

    assert!(
        MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: 8,
                max_mailboxes: 4,
            },
            "Projects/OSMAP",
        )
        .is_err(),
        "mailbox names beyond the configured bound must be rejected"
    );

    assert!(
        MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 0).is_err(),
        "zero UID message view requests must be rejected"
    );

    assert!(
        MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "INBOX", 42).is_err(),
        "same-mailbox move requests must be rejected"
    );
}

#[test]
fn v8_resource_robustness_matrix_fails_closed_for_oversized_attachment_output() {
    let policy = AttachmentDownloadPolicy {
        download_max_bytes: 3,
        ..AttachmentDownloadPolicy::default()
    };
    let outcome = AttachmentDownloadService::new(policy).download_for_validated_session(
        &test_context(),
        &validated_session_fixture(),
        &message_view_from_fixture(include_str!("fixtures/attachments/safe_pdf_base64.eml")),
        "1.2",
    );

    assert_eq!(
        outcome.decision,
        AttachmentDownloadDecision::Denied {
            public_reason: AttachmentDownloadPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(outcome.audit_event.action, "attachment_download_failed");
    assert_eq!(
        event_field(&outcome.audit_event, "public_reason"),
        Some("temporarily_unavailable")
    );
    assert_eq!(
        event_field(&outcome.audit_event, "audit_reason"),
        Some("output_rejected")
    );
    assert!(
        event_field(&outcome.audit_event, "session_ref").is_some(),
        "bounded rejection should still include a redacted session reference"
    );
    assert!(
        event_field(&outcome.audit_event, "session_id").is_none(),
        "bounded rejection must not log raw session_id"
    );
}

#[test]
fn v8_resource_robustness_matrix_sorts_larger_synthetic_message_sets_deterministically() {
    let mut by_uid = synthetic_summaries(256);
    sort_message_summaries(
        &mut by_uid,
        Some(sort(MessageSortColumn::Uid, MessageSortDirection::Asc)),
    );
    let by_uid_order = summary_uids(&by_uid);
    assert_eq!(by_uid_order.first(), Some(&1));
    assert_eq!(by_uid_order.last(), Some(&256));
    assert_eq!(by_uid_order.len(), 256);

    let mut by_subject = synthetic_summaries(256);
    sort_message_summaries(
        &mut by_subject,
        Some(sort(MessageSortColumn::Subject, MessageSortDirection::Asc)),
    );
    let by_subject_order = summary_uids(&by_subject);
    assert_eq!(by_subject_order.first(), Some(&1));
    assert_eq!(by_subject_order.last(), Some(&256));
    assert_eq!(by_subject_order.len(), 256);

    let mut search_by_size = synthetic_search_results(256);
    sort_message_search_results(
        &mut search_by_size,
        Some(sort(MessageSortColumn::Size, MessageSortDirection::Desc)),
    );
    let search_order = search_uids(&search_by_size);
    assert_eq!(search_order.first(), Some(&256));
    assert_eq!(search_order.last(), Some(&1));
    assert_eq!(search_order.len(), 256);
}
