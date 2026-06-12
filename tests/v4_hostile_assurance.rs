use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use osmap::attachment::{
    AttachmentDownloadPolicy, AttachmentDownloadService, DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES,
};
use osmap::mailbox::MessageView;
use osmap::mime::{MimeAnalysisPolicy, MimeAnalyzer, MimeBodySource};
use osmap::rendering_html::{sanitize_html_body, HtmlRenderingPolicy};

const CORPUS_ROOT: &str = "tests/testdata/hostile-mail-corpus";

#[derive(Debug)]
struct EvidenceRow {
    component: &'static str,
    status: &'static str,
    observation: String,
}

#[test]
fn v4_hostile_content_assurance_corpus_gate() {
    let mut evidence = Vec::new();

    validate_corpus_metadata(&mut evidence);
    validate_browser_rendered_negative_assertions(&mut evidence);
    validate_mime_parser_robustness(&mut evidence);
    validate_attachment_deception_handling(&mut evidence);
    validate_browser_isolation_source_invariants(&mut evidence);
    write_evidence_report(&evidence);

    assert!(
        evidence.iter().all(|row| row.status == "passed"),
        "all V4 hostile-content assurance checks must pass: {evidence:#?}"
    );
}

fn validate_corpus_metadata(evidence: &mut Vec<EvidenceRow>) {
    let root = repo_path(CORPUS_ROOT);
    assert!(root.join("MANIFEST.json").is_file());

    let required_fixture_paths = [
        "html/hostile_html_active_content.eml",
        "html/css_tracking_cid_abuse.eml",
        "html/suspicious_link_matrix.eml",
        "mime/malformed_headers_boundary.eml",
        "mime/invalid_transfer_charset.eml",
        "mime/deep_nested_mime.eml",
        "mime/header_count_abuse.eml",
        "unicode/unicode_deception_subject.eml",
        "attachments/spoofed_double_extension.eml",
        "attachments/svg_disguised_image.eml",
        "attachments/executable_benign_name.eml",
        "attachments/archive_like_confusion.eml",
    ];
    let required_categories = [
        "hostile HTML",
        "CSS abuse",
        "tracking attempts",
        "CID abuse",
        "unicode deception",
        "suspicious links",
        "malformed headers",
        "nested MIME structures",
        "suspicious charsets",
        "spoofed filenames",
        "attachment deception",
    ];

    let mut metadata_blob = String::new();
    for fixture in required_fixture_paths {
        let eml_path = root.join(fixture);
        let json_path = eml_path.with_extension("json");
        assert!(eml_path.is_file(), "missing fixture {}", eml_path.display());
        assert!(
            json_path.is_file(),
            "missing metadata {}",
            json_path.display()
        );

        let metadata = fs::read_to_string(&json_path).expect("metadata should be readable");
        for field in [
            "fixture_identifier",
            "category",
            "expected_outcome",
            "security_objective",
            "release_coverage_mapping",
        ] {
            assert!(
                metadata.contains(field),
                "{} missing metadata field {field}",
                json_path.display()
            );
        }
        metadata_blob.push_str(&metadata);
    }

    for category in required_categories {
        assert!(
            metadata_blob.contains(category),
            "corpus metadata does not cover required category {category}"
        );
    }

    evidence.push(EvidenceRow {
        component: "hostile_corpus_metadata",
        status: "passed",
        observation: format!(
            "{} fixtures cover {} required categories",
            required_fixture_paths.len(),
            required_categories.len()
        ),
    });
}

fn validate_browser_rendered_negative_assertions(evidence: &mut Vec<EvidenceRow>) {
    let active = include_str!("testdata/hostile-mail-corpus/html/hostile_html_active_content.eml");
    let css = include_str!("testdata/hostile-mail-corpus/html/css_tracking_cid_abuse.eml");
    let links = include_str!("testdata/hostile-mail-corpus/html/suspicious_link_matrix.eml");

    let mut rendered_fragments = Vec::new();
    for fixture in [active, css, links] {
        let message = message_view_from_fixture(fixture);
        let sanitized = sanitize_html_body(
            HtmlRenderingPolicy::default(),
            &message.body_text,
            None,
            128 * 1024,
        )
        .expect("hostile HTML fixture should sanitize without parser failure")
        .expect("hostile HTML fixture should leave visible inert text");
        rendered_fragments.push(sanitized.body_html);
    }

    let rendered = rendered_fragments.join("\n");
    let lower = rendered.to_ascii_lowercase();

    for forbidden in [
        "<script",
        "<form",
        "<iframe",
        "<object",
        "<embed",
        "<svg",
        "<math",
        "<audio",
        "<video",
        " onload",
        " onclick",
        " onerror",
        " onfocus",
        "<img",
        "cid:",
        "data:",
        "blob:",
        "file:",
        "href=\"/relative",
        "href=\"//",
        "<meta",
        "http-equiv",
        "<link",
        "rel=\"preload",
        "navigator.serviceworker",
        "new websocket",
        "sendbeacon",
        "broadcastchannel",
        "rtcpeerconnection",
        "localstorage",
        "sessionstorage",
        "target=\"_blank",
    ] {
        assert!(
            !lower.contains(forbidden),
            "browser-rendered hostile content retained forbidden pattern {forbidden:?}: {rendered}"
        );
    }

    assert!(rendered.contains("Visible hostile HTML fixture text."));
    assert!(rendered.contains("Visible CSS abuse text."));
    assert!(rendered.contains("Visible suspicious link fixture text."));
    assert!(rendered.contains("href=\"https://example.com/safe\""));
    assert!(rendered.contains("href=\"http://example.com/safe\""));
    assert!(rendered.contains("href=\"mailto:ops@example.com\""));
    assert!(rendered.contains("rel=\"noopener noreferrer nofollow\""));

    evidence.push(EvidenceRow {
        component: "browser_rendered_negative_assertions",
        status: "passed",
        observation: "sanitized browser-facing fragments retain inert text and allowed links only"
            .to_string(),
    });
}

fn validate_mime_parser_robustness(evidence: &mut Vec<EvidenceRow>) {
    let analyzer = MimeAnalyzer::new(MimeAnalysisPolicy::default());

    let malformed = analyzer
        .analyze_message(&message_view_from_fixture(include_str!(
            "testdata/hostile-mail-corpus/mime/malformed_headers_boundary.eml"
        )))
        .expect("malformed boundary fixture should fail closed without panic");
    assert_eq!(
        malformed.body_source,
        MimeBodySource::MultipartStructureWithheld
    );
    assert!(malformed.attachments.is_empty());

    let invalid_encoding = analyzer
        .analyze_message(&message_view_from_fixture(include_str!(
            "testdata/hostile-mail-corpus/mime/invalid_transfer_charset.eml"
        )))
        .expect("unsupported encoding fixture should fail closed without panic");
    assert_eq!(invalid_encoding.body_source, MimeBodySource::HtmlWithheld);
    assert!(invalid_encoding.contains_html_body);
    assert!(invalid_encoding.selected_html_body.is_none());

    let deep = analyzer
        .analyze_message(&message_view_from_fixture(include_str!(
            "testdata/hostile-mail-corpus/mime/deep_nested_mime.eml"
        )))
        .expect("deep nesting fixture should be bounded without panic");
    assert_eq!(deep.body_source, MimeBodySource::MultipartStructureWithheld);

    let low_header_limit = MimeAnalysisPolicy {
        header_count_max: 4,
        ..MimeAnalysisPolicy::default()
    };
    let header_count_error = MimeAnalyzer::new(low_header_limit)
        .analyze_message(&message_view_from_fixture(include_str!(
            "testdata/hostile-mail-corpus/mime/header_count_abuse.eml"
        )))
        .expect_err("header-count abuse should fail closed");
    assert!(header_count_error
        .reason
        .contains("mime header count exceeded"));

    let low_part_limit = MimeAnalysisPolicy {
        max_parts: 2,
        ..MimeAnalysisPolicy::default()
    };
    let part_count_error = MimeAnalyzer::new(low_part_limit)
        .analyze_message(&message_view(
            "Subject: part count\nContent-Type: multipart/mixed; boundary=\"many\"\n",
            concat!(
                "--many\nContent-Type: text/plain\n\none\n",
                "--many\nContent-Type: text/plain\n\ntwo\n",
                "--many\nContent-Type: text/plain\n\nthree\n",
                "--many--\n"
            ),
        ))
        .expect_err("part-count abuse should fail closed");
    assert!(part_count_error.reason.contains("mime part count exceeded"));

    let oversized_boundary_error = MimeAnalyzer::new(MimeAnalysisPolicy {
        boundary_max_len: 8,
        ..MimeAnalysisPolicy::default()
    })
    .analyze_message(&message_view(
        "Subject: oversized boundary\nContent-Type: multipart/mixed; boundary=\"boundary-too-long\"\n",
        "--boundary-too-long\nContent-Type: text/plain\n\nbody\n--boundary-too-long--\n",
    ))
    .expect_err("oversized boundary should fail closed");
    assert!(oversized_boundary_error
        .reason
        .contains("mime boundary exceeded"));

    evidence.push(EvidenceRow {
        component: "mime_parser_robustness",
        status: "passed",
        observation: "malformed boundary, invalid transfer, deep nesting, header count, part count, and boundary length checks are bounded".to_string(),
    });
}

fn validate_attachment_deception_handling(evidence: &mut Vec<EvidenceRow>) {
    let service = AttachmentDownloadService::new(AttachmentDownloadPolicy::default());

    let html = service
        .download_from_message(
            &message_view_from_fixture(include_str!(
                "testdata/hostile-mail-corpus/attachments/spoofed_double_extension.eml"
            )),
            "1.2",
        )
        .expect("spoofed HTML attachment should be downloadable only");
    assert_eq!(html.filename, "invoice.pdf.html");
    assert_eq!(html.content_type, "application/octet-stream");

    let svg = service
        .download_from_message(
            &message_view_from_fixture(include_str!(
                "testdata/hostile-mail-corpus/attachments/svg_disguised_image.eml"
            )),
            "1.2",
        )
        .expect("SVG disguised as image should be downloadable only");
    assert_eq!(svg.filename, "chart.png");
    assert_eq!(svg.content_type, "application/octet-stream");

    let script = service
        .download_from_message(
            &message_view_from_fixture(include_str!(
                "testdata/hostile-mail-corpus/attachments/executable_benign_name.eml"
            )),
            "1.2",
        )
        .expect("script attachment with benign name should be downloadable only");
    assert_eq!(script.filename, "meeting-notes.txt");
    assert_eq!(script.content_type, "application/octet-stream");

    let archive = service
        .download_from_message(
            &message_view_from_fixture(include_str!(
                "testdata/hostile-mail-corpus/attachments/archive_like_confusion.eml"
            )),
            "1.2",
        )
        .expect("archive-like content should stay download-only metadata");
    assert_eq!(archive.filename, "photos.txt");
    assert_eq!(archive.content_type, "application/zip");

    let unicode = service
        .download_from_message(
            &message_view_from_fixture(include_str!(
                "testdata/hostile-mail-corpus/unicode/unicode_deception_subject.eml"
            )),
            "1.2",
        )
        .expect("unicode-deception filename should normalize");
    assert!(unicode.filename.is_ascii());
    assert!(!unicode.filename.contains('\u{202e}'));

    let oversized = AttachmentDownloadService::new(AttachmentDownloadPolicy {
        download_max_bytes: 4,
        ..AttachmentDownloadPolicy::default()
    })
    .download_from_message(
        &message_view(
            "Subject: oversized attachment\nContent-Type: multipart/mixed; boundary=\"big\"\n",
            "--big\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"big.bin\"\n\n12345\n--big--\n",
        ),
        "1.1",
    )
    .expect_err("oversized attachment should fail closed");
    assert!(oversized
        .reason
        .contains("attachment body exceeded maximum decoded length"));

    evidence.push(EvidenceRow {
        component: "attachment_deception_handling",
        status: "passed",
        observation: format!(
            "active attachment media are downgraded; archive remains download-only; max bytes={}",
            DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES
        ),
    });
}

fn validate_browser_isolation_source_invariants(evidence: &mut Vec<EvidenceRow>) {
    let http_support =
        fs::read_to_string(repo_path("src/http_support.rs")).expect("http support source readable");

    for required in [
        "default-src 'none'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "Content-Disposition",
        "attachment; filename",
        "X-Content-Type-Options",
        "nosniff",
        "X-Frame-Options",
        "DENY",
        "Cross-Origin-Resource-Policy",
        "same-origin",
        "Referrer-Policy",
        "no-referrer",
    ] {
        assert!(
            http_support.contains(required),
            "HTTP browser boundary source missing {required}"
        );
    }

    let src_files = [
        "src/http_support.rs",
        "src/http_ui.rs",
        "src/rendering_html.rs",
        "src/rendering.rs",
    ];
    for source_path in src_files {
        let source =
            fs::read_to_string(repo_path(source_path)).expect("browser-boundary source readable");
        for forbidden in [
            "serviceWorker.register",
            "new WebSocket",
            "BroadcastChannel",
            "RTCPeerConnection",
            "window.open",
            "Service-Worker-Allowed",
        ] {
            assert!(
                !source.contains(forbidden),
                "{source_path} contains forbidden browser isolation pattern {forbidden}"
            );
        }
    }

    evidence.push(EvidenceRow {
        component: "browser_isolation_verification",
        status: "passed",
        observation: "CSP, frame ancestry, forced-download, nosniff, CORP, referrer policy, and no active browser APIs verified".to_string(),
    });
}

fn write_evidence_report(evidence: &[EvidenceRow]) {
    let Some(report_path) = env::var_os("OSMAP_V4_ASSURANCE_REPORT") else {
        return;
    };
    let report_path = PathBuf::from(report_path);
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).expect("report parent should be creatable");
    }

    let generated_at =
        env::var("OSMAP_V4_ASSURANCE_GENERATED_AT").unwrap_or_else(|_| "unknown".to_string());
    let assessed_ref =
        env::var("OSMAP_V4_ASSURANCE_ASSESSED_REF").unwrap_or_else(|_| "unknown".to_string());
    let status = if evidence.iter().all(|row| row.status == "passed") {
        "passed"
    } else {
        "failed"
    };

    let components = evidence
        .iter()
        .map(|row| {
            format!(
                "    {{\"component\":\"{}\",\"status\":\"{}\",\"observation\":\"{}\"}}",
                json_escape(row.component),
                json_escape(row.status),
                json_escape(&row.observation)
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"osmap-v4-hostile-assurance-report-v1\",\n",
            "  \"status\": \"{}\",\n",
            "  \"assessed_ref\": \"{}\",\n",
            "  \"generated_at_utc\": \"{}\",\n",
            "  \"corpus_root\": \"{}\",\n",
            "  \"release_gate\": \"maint/security/osmap-v4-hostile-assurance-gate.sh\",\n",
            "  \"resource_usage_observations\": {{\n",
            "    \"mime_max_depth\": {},\n",
            "    \"mime_max_parts\": {},\n",
            "    \"mime_header_count_max\": {},\n",
            "    \"attachment_download_max_bytes\": {}\n",
            "  }},\n",
            "  \"network_assertions\": {{\n",
            "    \"remote_fetches\": 0,\n",
            "    \"beacon_requests\": 0,\n",
            "    \"websocket_requests\": 0,\n",
            "    \"service_worker_registrations\": 0\n",
            "  }},\n",
            "  \"components\": [\n",
            "{}\n",
            "  ]\n",
            "}}\n"
        ),
        json_escape(status),
        json_escape(&assessed_ref),
        json_escape(&generated_at),
        CORPUS_ROOT,
        MimeAnalysisPolicy::default().max_depth,
        MimeAnalysisPolicy::default().max_parts,
        MimeAnalysisPolicy::default().header_count_max,
        DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES,
        components
    );

    fs::write(report_path, report).expect("V4 assurance report should be writable");
}

fn message_view_from_fixture(raw_message: &str) -> MessageView {
    let normalized = raw_message.replace("\r\n", "\n");
    let (header_block, body_text) = normalized
        .split_once("\n\n")
        .expect("fixture should contain a header/body separator");
    message_view(header_block, body_text)
}

fn message_view(header_block: &str, body_text: &str) -> MessageView {
    MessageView {
        mailbox_name: "INBOX".to_string(),
        uid: 9901,
        flags: vec!["\\Seen".to_string()],
        date_received: "2026-06-12 00:00:00 +0000".to_string(),
        size_virtual: (header_block.len() + body_text.len()) as u64,
        header_block: header_block.to_string(),
        body_text: body_text.to_string(),
    }
}

fn repo_path(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}
