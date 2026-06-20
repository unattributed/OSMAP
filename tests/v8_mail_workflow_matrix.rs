use std::path::{Path, PathBuf};

use osmap::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use osmap::config::LogLevel;
use osmap::http_ui::render_message_view_page;
use osmap::logging::{EventCategory, LogEvent};
use osmap::mailbox::{MailboxEntry, MessageView};
use osmap::mime::{MimeAnalysisPolicy, MimeAnalyzer, MimeBodySource};
use osmap::rendering::{
    HtmlDisplayPreference, PlainTextMessageRenderer, RenderedMessageView, RenderingMode,
    RenderingPolicy,
};
use osmap::session::{SessionRecord, ValidatedSession};

#[derive(Debug, Clone, Copy)]
struct WorkflowCase {
    fixture_name: &'static str,
    raw_message: &'static str,
    expected_body_source: MimeBodySource,
    expected_rendering_mode: RenderingMode,
    expected_html_present: bool,
    expected_attachment_count: usize,
    expected_visible_text: &'static str,
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
        date_received: "2026-06-20 03:30:00 +0000".to_string(),
        size_virtual: normalized.len() as u64,
        header_block: header_block.to_string(),
        body_text: body_text.to_string(),
    }
}

fn test_context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-v8-mail-workflow",
        "127.0.0.1",
        "Firefox/V8-Mail-Workflow",
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
            user_agent: "Firefox/V8-Mail-Workflow".to_string(),
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

fn render_fixture(
    raw_message: &str,
    html_display_preference: HtmlDisplayPreference,
) -> RenderedMessageView {
    let renderer = PlainTextMessageRenderer::new(RenderingPolicy {
        html_display_preference,
        ..RenderingPolicy::default()
    });
    renderer
        .render_for_validated_session(
            &test_context(),
            &validated_session_fixture(),
            &message_view_from_fixture(raw_message),
        )
        .expect("workflow fixture should render safely")
        .rendered
}

fn message_page_html(rendered: &RenderedMessageView) -> String {
    let mailboxes = vec![
        MailboxEntry {
            name: "INBOX".to_string(),
        },
        MailboxEntry {
            name: "Archive".to_string(),
        },
        MailboxEntry {
            name: "Trash".to_string(),
        },
    ];
    render_message_view_page(
        "alice@example.com",
        "csrf-v8-mail-workflow",
        rendered,
        Some("Archive"),
        &mailboxes,
    )
    .to_string()
}

fn assert_body_source_and_rendering_labels(rendered: &RenderedMessageView, page_html: &str) {
    let expected_body_source = format!(
        "<dt>Body Source</dt><dd>{}</dd>",
        rendered.body_source.as_str()
    );
    let expected_rendering_mode = format!(
        "<dt>Rendering Mode</dt><dd>{}</dd>",
        rendered.rendering_mode.as_str()
    );
    let expected_html_present = format!(
        "<dt>HTML Present</dt><dd>{}</dd>",
        if rendered.contains_html_body {
            "yes"
        } else {
            "no"
        }
    );

    assert!(
        page_html.contains(&expected_body_source),
        "message view page did not expose body source label {expected_body_source}"
    );
    assert!(
        page_html.contains(&expected_rendering_mode),
        "message view page did not expose rendering mode label {expected_rendering_mode}"
    );
    assert!(
        page_html.contains(&expected_html_present),
        "message view page did not expose HTML-present label {expected_html_present}"
    );
}

fn assert_no_raw_active_html(rendered: &RenderedMessageView) {
    let body_html = rendered.body_html.as_str();
    for forbidden in [
        "<script",
        "</script>",
        "javascript:",
        "onerror",
        "tracker.example",
        "alert('must not render')",
        "Malformed raw HTML body must not render.",
    ] {
        assert!(
            !body_html.contains(forbidden),
            "rendered body retained forbidden active or unsafe HTML marker {forbidden}: {body_html}"
        );
    }
}

#[test]
fn v8_mail_workflow_fixture_inventory_is_complete() {
    for relative in [
        "tests/fixtures/mail_workflows/MANIFEST.md",
        "tests/fixtures/mail_workflows/text_plain.eml",
        "tests/fixtures/mail_workflows/text_html.eml",
        "tests/fixtures/mail_workflows/multipart_alternative.eml",
        "tests/fixtures/mail_workflows/multipart_mixed.eml",
        "tests/fixtures/mail_workflows/nested_multipart.eml",
        "tests/fixtures/mail_workflows/attachment_heavy.eml",
        "tests/fixtures/mail_workflows/malformed_mime.eml",
        "docs/V8_MAIL_WORKFLOW_MATRIX.md",
        "maint/security/osmap-v8-mail-workflow-gate.sh",
    ] {
        assert!(repo_path(relative).is_file(), "missing {relative}");
    }
}

#[test]
fn v8_mail_workflow_matrix_verifies_body_selection_and_labels() {
    let cases = [
        WorkflowCase {
            fixture_name: "text_plain",
            raw_message: include_str!("fixtures/mail_workflows/text_plain.eml"),
            expected_body_source: MimeBodySource::SinglePartPlainText,
            expected_rendering_mode: RenderingMode::PlainTextPreformatted,
            expected_html_present: false,
            expected_attachment_count: 0,
            expected_visible_text: "Plain workflow body",
        },
        WorkflowCase {
            fixture_name: "text_html",
            raw_message: include_str!("fixtures/mail_workflows/text_html.eml"),
            expected_body_source: MimeBodySource::HtmlSanitized,
            expected_rendering_mode: RenderingMode::SanitizedHtml,
            expected_html_present: true,
            expected_attachment_count: 0,
            expected_visible_text: "HTML workflow body",
        },
        WorkflowCase {
            fixture_name: "multipart_alternative",
            raw_message: include_str!("fixtures/mail_workflows/multipart_alternative.eml"),
            expected_body_source: MimeBodySource::MultipartHtmlSanitized,
            expected_rendering_mode: RenderingMode::SanitizedHtml,
            expected_html_present: true,
            expected_attachment_count: 0,
            expected_visible_text: "Alternative HTML body visible.",
        },
        WorkflowCase {
            fixture_name: "multipart_mixed",
            raw_message: include_str!("fixtures/mail_workflows/multipart_mixed.eml"),
            expected_body_source: MimeBodySource::MultipartPlainTextPart,
            expected_rendering_mode: RenderingMode::PlainTextPreformatted,
            expected_html_present: false,
            expected_attachment_count: 1,
            expected_visible_text: "Mixed workflow plain body",
        },
        WorkflowCase {
            fixture_name: "nested_multipart",
            raw_message: include_str!("fixtures/mail_workflows/nested_multipart.eml"),
            expected_body_source: MimeBodySource::MultipartHtmlSanitized,
            expected_rendering_mode: RenderingMode::SanitizedHtml,
            expected_html_present: true,
            expected_attachment_count: 1,
            expected_visible_text: "Nested HTML workflow body visible.",
        },
        WorkflowCase {
            fixture_name: "attachment_heavy",
            raw_message: include_str!("fixtures/mail_workflows/attachment_heavy.eml"),
            expected_body_source: MimeBodySource::MultipartPlainTextPart,
            expected_rendering_mode: RenderingMode::PlainTextPreformatted,
            expected_html_present: false,
            expected_attachment_count: 5,
            expected_visible_text: "Attachment-heavy workflow body remains selected",
        },
    ];

    for case in cases {
        let rendered = render_fixture(case.raw_message, HtmlDisplayPreference::PreferSanitizedHtml);
        assert_eq!(
            rendered.body_source, case.expected_body_source,
            "{} body source changed",
            case.fixture_name
        );
        assert_eq!(
            rendered.rendering_mode, case.expected_rendering_mode,
            "{} rendering mode changed",
            case.fixture_name
        );
        assert_eq!(
            rendered.contains_html_body, case.expected_html_present,
            "{} HTML-present status changed",
            case.fixture_name
        );
        assert_eq!(
            rendered.attachments.len(),
            case.expected_attachment_count,
            "{} attachment metadata count changed",
            case.fixture_name
        );
        assert!(
            rendered
                .body_html
                .as_str()
                .contains(case.expected_visible_text),
            "{} selected body text was not rendered: {}",
            case.fixture_name,
            rendered.body_html.as_str()
        );

        let page_html = message_page_html(&rendered);
        assert_body_source_and_rendering_labels(&rendered, &page_html);

        if case.expected_html_present {
            assert!(
                page_html.contains("remote content blocked"),
                "{} page did not surface remote-content status",
                case.fixture_name
            );
        } else {
            assert!(
                page_html.contains("safe text render"),
                "{} page did not surface safe text status",
                case.fixture_name
            );
        }

        if case.expected_rendering_mode == RenderingMode::SanitizedHtml {
            assert!(
                page_html.contains("Sanitized HTML:"),
                "{} page did not surface sanitized HTML notice",
                case.fixture_name
            );
        }

        assert_no_raw_active_html(&rendered);
    }
}

#[test]
fn v8_mail_workflow_matrix_preserves_prefer_plain_text_behavior() {
    let rendered = render_fixture(
        include_str!("fixtures/mail_workflows/multipart_alternative.eml"),
        HtmlDisplayPreference::PreferPlainText,
    );
    assert_eq!(rendered.body_source, MimeBodySource::MultipartPlainTextPart);
    assert_eq!(
        rendered.rendering_mode,
        RenderingMode::PlainTextPreformatted
    );
    assert!(rendered.contains_html_body);
    assert!(rendered
        .body_html
        .as_str()
        .contains("Alternative plain body for compose and plain preference."));
    assert!(!rendered
        .body_html
        .as_str()
        .contains("Alternative HTML body visible."));

    let page_html = message_page_html(&rendered);
    assert_body_source_and_rendering_labels(&rendered, &page_html);
    assert!(page_html.contains("remote content blocked"));
    assert!(!page_html.contains("Sanitized HTML:"));
}

#[test]
fn v8_mail_workflow_matrix_surfaces_inline_content_without_rendering_it_inline() {
    let rendered = render_fixture(
        include_str!("fixtures/mail_workflows/nested_multipart.eml"),
        HtmlDisplayPreference::PreferSanitizedHtml,
    );
    assert_eq!(rendered.attachments.len(), 1);
    assert_eq!(
        rendered.attachments[0].filename.as_deref(),
        Some("logo.png")
    );
    assert_eq!(
        rendered.attachments[0].content_id.as_deref(),
        Some("v8-logo")
    );
    assert_eq!(rendered.attachments[0].disposition.as_str(), "inline");

    let page_html = message_page_html(&rendered);
    assert!(page_html.contains("Remote content blocked by policy:"));
    assert!(page_html.contains("Content-ID <strong>cid:v8-logo</strong>"));
    assert!(page_html.contains("Download"));
    assert_no_raw_active_html(&rendered);
}

#[test]
fn v8_mail_workflow_matrix_malformed_mime_falls_back_safely() {
    let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());
    let analysis = analyzer
        .analyze_message(&message_view_from_fixture(include_str!(
            "fixtures/mail_workflows/malformed_mime.eml"
        )))
        .expect("malformed MIME should fail closed without panic");
    assert_eq!(
        analysis.body_source,
        MimeBodySource::MultipartStructureWithheld
    );
    assert!(analysis.attachments.is_empty());

    let rendered = render_fixture(
        include_str!("fixtures/mail_workflows/malformed_mime.eml"),
        HtmlDisplayPreference::PreferSanitizedHtml,
    );
    assert_eq!(
        rendered.body_source,
        MimeBodySource::MultipartStructureWithheld
    );
    assert_eq!(
        rendered.rendering_mode,
        RenderingMode::PlainTextPreformatted
    );
    assert!(rendered
        .body_html
        .as_str()
        .contains("Multipart structure detected, but no safe plain-text preview is available."));
    assert_no_raw_active_html(&rendered);

    let page_html = message_page_html(&rendered);
    assert_body_source_and_rendering_labels(&rendered, &page_html);
    assert!(page_html.contains("safe text render"));
}
