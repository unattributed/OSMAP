use std::path::{Path, PathBuf};

use osmap::attachment::{
    AttachmentDownloadDecision, AttachmentDownloadPolicy, AttachmentDownloadPublicFailureReason,
    AttachmentDownloadService, DownloadedAttachment,
};
use osmap::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use osmap::config::LogLevel;
use osmap::http::HttpResponse;
use osmap::http_support::attachment_download_response;
use osmap::logging::{EventCategory, LogEvent};
use osmap::mailbox::MessageView;
use osmap::session::{SessionRecord, ValidatedSession};

#[derive(Debug, Clone, Copy)]
struct AttachmentCase {
    fixture_name: &'static str,
    raw_message: &'static str,
    expected_filename: &'static str,
    expected_content_type: &'static str,
    expected_body_marker: &'static [u8],
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn message_view_from_fixture(raw_message: &str) -> MessageView {
    let normalized = raw_message.replace("\r\n", "\n");
    let (header_block, body_text) = normalized
        .split_once("\n\n")
        .expect("fixture should contain a header/body separator");
    MessageView {
        mailbox_name: "INBOX".to_string(),
        uid: 808,
        flags: vec!["\\Seen".to_string()],
        date_received: "2026-06-20 04:30:00 +0000".to_string(),
        size_virtual: normalized.len() as u64,
        header_block: header_block.to_string(),
        body_text: body_text.to_string(),
    }
}

fn test_context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-v8-attachment-safety",
        "127.0.0.1",
        "Firefox/V8-Attachment-Safety",
    )
    .expect("authentication context should be valid")
}

fn validated_session_fixture() -> ValidatedSession {
    ValidatedSession {
        record: SessionRecord {
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
            user_agent: "Firefox/V8-Attachment-Safety".to_string(),
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

fn download_attachment_with_policy(
    raw_message: &str,
    part_path: &str,
    policy: AttachmentDownloadPolicy,
) -> (AttachmentDownloadDecision, LogEvent) {
    let outcome = AttachmentDownloadService::new(policy).download_for_validated_session(
        &test_context(),
        &validated_session_fixture(),
        &message_view_from_fixture(raw_message),
        part_path,
    );
    (outcome.decision, outcome.audit_event)
}

fn downloaded_attachment(raw_message: &str) -> (DownloadedAttachment, LogEvent) {
    let (decision, audit_event) =
        download_attachment_with_policy(raw_message, "1.2", AttachmentDownloadPolicy::default());
    match decision {
        AttachmentDownloadDecision::Downloaded { attachment, .. } => (attachment, audit_event),
        other => panic!("expected downloaded attachment, got {other:?}"),
    }
}

fn response_header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn event_field<'a>(event: &'a LogEvent, key: &str) -> Option<&'a str> {
    event
        .fields
        .iter()
        .find(|field| field.key == key)
        .map(|field| field.value.as_str())
}

fn assert_forced_download_response(attachment: &DownloadedAttachment) {
    let response = attachment_download_response(attachment);
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, attachment.body);

    assert_eq!(
        response_header(&response, "Content-Type"),
        Some(attachment.content_type.as_str())
    );
    assert_eq!(
        response_header(&response, "Content-Disposition"),
        Some(format!("attachment; filename=\"{}\"", attachment.filename).as_str())
    );
    assert_eq!(
        response_header(&response, "Cache-Control"),
        Some("no-store")
    );
    assert_eq!(
        response_header(&response, "Cross-Origin-Resource-Policy"),
        Some("same-origin")
    );
    assert_eq!(
        response_header(&response, "Referrer-Policy"),
        Some("no-referrer")
    );
    assert_eq!(
        response_header(&response, "X-Content-Type-Options"),
        Some("nosniff")
    );
    assert_eq!(response_header(&response, "X-Frame-Options"), Some("DENY"));
}

#[test]
fn v8_attachment_safety_fixture_inventory_is_complete() {
    for relative in [
        "tests/fixtures/attachments/MANIFEST.md",
        "tests/fixtures/attachments/safe_pdf_base64.eml",
        "tests/fixtures/attachments/quoted_printable_text.eml",
        "tests/fixtures/attachments/suspicious_html_attachment.eml",
        "tests/fixtures/attachments/svg_active_attachment.eml",
        "tests/fixtures/attachments/generated_filename_fallback.eml",
        "tests/fixtures/attachments/unsupported_encoding.eml",
        "docs/V8_ATTACHMENT_SAFETY_MATRIX.md",
        "maint/security/osmap-v8-attachment-safety-gate.sh",
    ] {
        assert!(repo_path(relative).is_file(), "missing {relative}");
    }
}

#[test]
fn v8_attachment_safety_matrix_enforces_download_metadata_and_headers() {
    let cases = [
        AttachmentCase {
            fixture_name: "safe_pdf_base64",
            raw_message: include_str!("fixtures/attachments/safe_pdf_base64.eml"),
            expected_filename: "report.pdf",
            expected_content_type: "application/pdf",
            expected_body_marker: b"%PDF-v8\n",
        },
        AttachmentCase {
            fixture_name: "quoted_printable_text",
            raw_message: include_str!("fixtures/attachments/quoted_printable_text.eml"),
            expected_filename: "notes.txt",
            expected_content_type: "text/plain",
            expected_body_marker: b"hello quoted-printable\n",
        },
        AttachmentCase {
            fixture_name: "suspicious_html_attachment",
            raw_message: include_str!("fixtures/attachments/suspicious_html_attachment.eml"),
            expected_filename: "invoice_script_.html",
            expected_content_type: "application/octet-stream",
            expected_body_marker: b"download me",
        },
        AttachmentCase {
            fixture_name: "svg_active_attachment",
            raw_message: include_str!("fixtures/attachments/svg_active_attachment.eml"),
            expected_filename: "chart.svg",
            expected_content_type: "application/octet-stream",
            expected_body_marker: b"<svg",
        },
        AttachmentCase {
            fixture_name: "generated_filename_fallback",
            raw_message: include_str!("fixtures/attachments/generated_filename_fallback.eml"),
            expected_filename: "attachment-808-1-2.bin",
            expected_content_type: "application/octet-stream",
            expected_body_marker: b"payload",
        },
    ];

    for case in cases {
        let (attachment, audit_event) = downloaded_attachment(case.raw_message);
        assert_eq!(
            attachment.filename, case.expected_filename,
            "{} filename changed",
            case.fixture_name
        );
        assert_eq!(
            attachment.content_type, case.expected_content_type,
            "{} content type changed",
            case.fixture_name
        );
        assert!(
            attachment
                .body
                .windows(case.expected_body_marker.len())
                .any(|window| window == case.expected_body_marker),
            "{} body marker was not found in downloaded attachment",
            case.fixture_name
        );
        assert_eq!(attachment.mailbox_name, "INBOX");
        assert_eq!(attachment.uid, 808);
        assert_eq!(attachment.part_path, "1.2");

        assert_forced_download_response(&attachment);

        assert_eq!(audit_event.action, "attachment_downloaded");
        assert_eq!(
            event_field(&audit_event, "canonical_username"),
            Some("alice@example.com")
        );
        assert_eq!(event_field(&audit_event, "mailbox_name"), Some("INBOX"));
        assert_eq!(event_field(&audit_event, "uid"), Some("808"));
        assert_eq!(event_field(&audit_event, "part_path"), Some("1.2"));
        assert_eq!(
            event_field(&audit_event, "content_type"),
            Some(attachment.content_type.as_str())
        );
        assert_eq!(event_field(&audit_event, "filename_present"), Some("true"));
        assert!(event_field(&audit_event, "session_ref").is_some());
        assert!(
            event_field(&audit_event, "session_id").is_none(),
            "raw session id must not be present in attachment audit fields"
        );
    }
}

#[test]
fn v8_attachment_safety_matrix_rejects_unsurfaced_and_invalid_part_paths() {
    for part_path in ["", "1", "2.1", "1.02", "1..2", ".1.2", "1.2.", "../bad"] {
        let (decision, audit_event) = download_attachment_with_policy(
            include_str!("fixtures/attachments/safe_pdf_base64.eml"),
            part_path,
            AttachmentDownloadPolicy::default(),
        );

        assert_eq!(
            decision,
            AttachmentDownloadDecision::Denied {
                public_reason: AttachmentDownloadPublicFailureReason::InvalidRequest
            },
            "part path {part_path:?} should be rejected"
        );
        assert_eq!(audit_event.action, "attachment_download_failed");
        assert_eq!(
            event_field(&audit_event, "public_reason"),
            Some("invalid_request")
        );
        assert_eq!(
            event_field(&audit_event, "audit_reason"),
            Some("invalid_request")
        );
        assert_eq!(event_field(&audit_event, "part_path"), Some(part_path));
    }

    let (decision, audit_event) = download_attachment_with_policy(
        include_str!("fixtures/attachments/safe_pdf_base64.eml"),
        "1.9",
        AttachmentDownloadPolicy::default(),
    );
    assert_eq!(
        decision,
        AttachmentDownloadDecision::Denied {
            public_reason: AttachmentDownloadPublicFailureReason::NotFound
        }
    );
    assert_eq!(
        event_field(&audit_event, "public_reason"),
        Some("not_found")
    );
    assert_eq!(event_field(&audit_event, "audit_reason"), Some("not_found"));
}

#[test]
fn v8_attachment_safety_matrix_fails_closed_for_unsafe_decoding() {
    let (unsupported_decision, unsupported_event) = download_attachment_with_policy(
        include_str!("fixtures/attachments/unsupported_encoding.eml"),
        "1.2",
        AttachmentDownloadPolicy::default(),
    );
    assert_eq!(
        unsupported_decision,
        AttachmentDownloadDecision::Denied {
            public_reason: AttachmentDownloadPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(
        event_field(&unsupported_event, "public_reason"),
        Some("temporarily_unavailable")
    );
    assert_eq!(
        event_field(&unsupported_event, "audit_reason"),
        Some("unsupported_encoding")
    );

    let restrictive_policy = AttachmentDownloadPolicy {
        download_max_bytes: 3,
        ..AttachmentDownloadPolicy::default()
    };
    let (oversized_decision, oversized_event) = download_attachment_with_policy(
        include_str!("fixtures/attachments/safe_pdf_base64.eml"),
        "1.2",
        restrictive_policy,
    );
    assert_eq!(
        oversized_decision,
        AttachmentDownloadDecision::Denied {
            public_reason: AttachmentDownloadPublicFailureReason::TemporarilyUnavailable
        }
    );
    assert_eq!(
        event_field(&oversized_event, "public_reason"),
        Some("temporarily_unavailable")
    );
    assert_eq!(
        event_field(&oversized_event, "audit_reason"),
        Some("output_rejected")
    );
}
