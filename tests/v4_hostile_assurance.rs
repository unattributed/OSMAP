use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use osmap::attachment::{
    AttachmentDownloadPolicy, AttachmentDownloadService, DownloadedAttachment,
    DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES,
};
use osmap::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use osmap::config::LogLevel;
use osmap::http::HttpResponse;
use osmap::http_support::{attachment_download_response, html_response};
use osmap::http_ui::render_message_view_page;
use osmap::logging::{EventCategory, LogEvent};
use osmap::mailbox::MailboxEntry;
use osmap::mailbox::MessageView;
use osmap::mime::{MimeAnalysisPolicy, MimeAnalyzer, MimeBodySource};
use osmap::rendering::{PlainTextMessageRenderer, RenderingPolicy};
use osmap::session::{SessionRecord, ValidatedSession};

const CORPUS_ROOT: &str = "tests/testdata/hostile-mail-corpus";

#[derive(Debug)]
struct EvidenceRow {
    component: &'static str,
    status: &'static str,
    observation: String,
}

#[derive(Debug, Default)]
struct BrowserBoundaryObservations {
    rendered_message_routes: usize,
    attachment_download_routes: usize,
    dom_assertions: usize,
    auto_fetch_surfaces: usize,
    beacon_requests: usize,
    websocket_requests: usize,
    service_worker_registrations: usize,
    unsafe_browser_api_references: usize,
}

impl BrowserBoundaryObservations {
    fn merge_network(&mut self, other: BrowserBoundaryObservations) {
        self.auto_fetch_surfaces += other.auto_fetch_surfaces;
        self.beacon_requests += other.beacon_requests;
        self.websocket_requests += other.websocket_requests;
        self.service_worker_registrations += other.service_worker_registrations;
        self.unsafe_browser_api_references += other.unsafe_browser_api_references;
    }
}

#[test]
fn v4_hostile_content_assurance_corpus_gate() {
    let mut evidence = Vec::new();
    let mut browser_observations = BrowserBoundaryObservations::default();

    validate_corpus_metadata(&mut evidence);
    validate_browser_rendered_negative_assertions(&mut evidence, &mut browser_observations);
    validate_mime_parser_robustness(&mut evidence);
    validate_attachment_deception_handling(&mut evidence, &mut browser_observations);
    validate_browser_isolation_source_invariants(&mut evidence, &browser_observations);
    write_evidence_report(&evidence, &browser_observations);

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

fn validate_browser_rendered_negative_assertions(
    evidence: &mut Vec<EvidenceRow>,
    observations: &mut BrowserBoundaryObservations,
) {
    let active = include_str!("testdata/hostile-mail-corpus/html/hostile_html_active_content.eml");
    let css = include_str!("testdata/hostile-mail-corpus/html/css_tracking_cid_abuse.eml");
    let links = include_str!("testdata/hostile-mail-corpus/html/suspicious_link_matrix.eml");

    for (fixture, expected_text) in [
        (active, "Visible hostile HTML fixture text."),
        (css, "Visible CSS abuse text."),
        (links, "Visible suspicious link fixture text."),
    ] {
        let response = render_hostile_message_route_response(fixture);
        assert_eq!(response.status_code, 200);
        assert_header_contains(
            &response.headers,
            "Content-Security-Policy",
            "default-src 'none'",
        );
        assert_header(&response.headers, "X-Content-Type-Options", "nosniff");
        assert_header(&response.headers, "X-Frame-Options", "DENY");

        let route_html = String::from_utf8(response.body.clone())
            .expect("route-backed HTML response should be UTF-8");
        let body_panel = message_body_panel(&route_html);
        assert!(
            body_panel.contains(expected_text),
            "route-backed body panel missing expected inert text {expected_text:?}: {body_panel}"
        );
        assert_message_body_dom_is_inert(body_panel);
        observations.dom_assertions += 1;

        let route_observations = observe_browser_boundary(&route_html);
        assert_eq!(
            route_observations.auto_fetch_surfaces, 0,
            "route-backed response retained auto-fetch surface: {route_html}"
        );
        assert_eq!(route_observations.beacon_requests, 0);
        assert_eq!(route_observations.websocket_requests, 0);
        assert_eq!(route_observations.service_worker_registrations, 0);
        assert_eq!(route_observations.unsafe_browser_api_references, 0);

        observations.rendered_message_routes += 1;
        observations.merge_network(route_observations);
    }

    evidence.push(EvidenceRow {
        component: "browser_rendered_negative_assertions",
        status: "passed",
        observation: format!(
            "route-backed message responses={} had inert body DOM and zero observed auto-fetch surfaces",
            observations.rendered_message_routes
        ),
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

fn validate_attachment_deception_handling(
    evidence: &mut Vec<EvidenceRow>,
    observations: &mut BrowserBoundaryObservations,
) {
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
    assert_forced_download_route(&html, observations);

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
    assert_forced_download_route(&svg, observations);

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
    assert_forced_download_route(&script, observations);

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
    assert_forced_download_route(&archive, observations);

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
    assert_forced_download_route(&unicode, observations);

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
            "active attachment media are downgraded; {} attachment routes force download with nosniff; max bytes={}",
            observations.attachment_download_routes,
            DEFAULT_ATTACHMENT_DOWNLOAD_MAX_BYTES
        ),
    });
}

fn validate_browser_isolation_source_invariants(
    evidence: &mut Vec<EvidenceRow>,
    observations: &BrowserBoundaryObservations,
) {
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
        observation: format!(
            "CSP/frame headers, forced-download headers, source invariants, and route-backed browser observations verified; rendered_routes={}, attachment_routes={}",
            observations.rendered_message_routes,
            observations.attachment_download_routes
        ),
    });
}

fn write_evidence_report(evidence: &[EvidenceRow], observations: &BrowserBoundaryObservations) {
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
            "    \"remote_fetches\": {},\n",
            "    \"beacon_requests\": {},\n",
            "    \"websocket_requests\": {},\n",
            "    \"service_worker_registrations\": {}\n",
            "  }},\n",
            "  \"route_backed_observations\": {{\n",
            "    \"rendered_message_routes\": {},\n",
            "    \"attachment_download_routes\": {},\n",
            "    \"dom_assertions\": {},\n",
            "    \"auto_fetch_surfaces\": {},\n",
            "    \"unsafe_browser_api_references\": {}\n",
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
        observations.auto_fetch_surfaces,
        observations.beacon_requests,
        observations.websocket_requests,
        observations.service_worker_registrations,
        observations.rendered_message_routes,
        observations.attachment_download_routes,
        observations.dom_assertions,
        observations.auto_fetch_surfaces,
        observations.unsafe_browser_api_references,
        components
    );

    fs::write(report_path, report).expect("V4 assurance report should be writable");
}

fn render_hostile_message_route_response(raw_message: &str) -> HttpResponse {
    let message = message_view_from_fixture(raw_message);
    let session = validated_session_fixture();
    let outcome = PlainTextMessageRenderer::new(RenderingPolicy::default())
        .render_for_validated_session(&test_context(), &session, &message)
        .expect("hostile fixture should render through the browser-facing renderer");
    let page = render_message_view_page(
        &session.record.canonical_username,
        &session.record.csrf_token,
        &outcome.rendered,
        Some("Archive"),
        &[
            MailboxEntry {
                name: "INBOX".to_string(),
            },
            MailboxEntry {
                name: "Archive".to_string(),
            },
            MailboxEntry {
                name: "Trash".to_string(),
            },
        ],
    );
    html_response(200, "OK", "OSMAP Message", &page)
}

fn assert_forced_download_route(
    attachment: &DownloadedAttachment,
    observations: &mut BrowserBoundaryObservations,
) {
    let response = attachment_download_response(attachment);
    assert_eq!(response.status_code, 200);
    assert_header(
        &response.headers,
        "Content-Disposition",
        &format!("attachment; filename=\"{}\"", attachment.filename),
    );
    assert_header(&response.headers, "Content-Type", &attachment.content_type);
    assert_header(&response.headers, "X-Content-Type-Options", "nosniff");
    assert_header(
        &response.headers,
        "Cross-Origin-Resource-Policy",
        "same-origin",
    );
    assert_header(&response.headers, "X-Frame-Options", "DENY");
    observations.attachment_download_routes += 1;
}

fn message_body_panel(route_html: &str) -> &str {
    let marker = "<section class=\"body-panel\"><h2>Body</h2>";
    let start = route_html
        .find(marker)
        .expect("route-backed message page should contain the body panel")
        + marker.len();
    let end = route_html[start..]
        .find("</section>")
        .expect("route-backed message body panel should close")
        + start;
    &route_html[start..end]
}

fn assert_message_body_dom_is_inert(body_panel: &str) {
    let lower = body_panel.to_ascii_lowercase();
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
        "<source",
        "<template",
        "<meta",
        "<link",
        "<style",
        "<img",
        " onload=",
        " onclick=",
        " onerror=",
        " onfocus=",
        " autofocus",
        "cid:",
        "data:",
        "blob:",
        "file:",
        "javascript:",
        "vbscript:",
        "href=\"/relative",
        "href=\"//",
        "src=\"//",
        "http-equiv",
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
            "route-backed hostile body retained forbidden DOM pattern {forbidden:?}: {body_panel}"
        );
    }
}

fn observe_browser_boundary(route_html: &str) -> BrowserBoundaryObservations {
    let lower = route_html.to_ascii_lowercase();
    BrowserBoundaryObservations {
        auto_fetch_surfaces: count_patterns(
            &lower,
            &[
                "<script",
                "<img",
                "<iframe",
                "<object",
                "<embed",
                "<svg",
                "<math",
                "<audio",
                "<video",
                "<source",
                "<track",
                "<meta http-equiv=\"refresh",
                "<meta http-equiv='refresh",
                "rel=\"preload",
                "rel='preload",
                "rel=\"modulepreload",
                "rel='modulepreload",
                "rel=\"stylesheet",
                "rel='stylesheet",
                "@import",
                "url(http:",
                "url(https:",
                "url(//",
            ],
        ),
        beacon_requests: count_patterns(&lower, &["sendbeacon"]),
        websocket_requests: count_patterns(&lower, &["websocket", "new websocket"]),
        service_worker_registrations: count_patterns(
            &lower,
            &["serviceworker.register", "service-worker-allowed"],
        ),
        unsafe_browser_api_references: count_patterns(
            &lower,
            &[
                "broadcastchannel",
                "rtcpeerconnection",
                "window.open",
                "localstorage",
                "sessionstorage",
            ],
        ),
        ..BrowserBoundaryObservations::default()
    }
}

fn count_patterns(haystack: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .map(|needle| haystack.matches(needle).count())
        .sum()
}

fn assert_header(headers: &[(String, String)], wanted_name: &str, wanted_value: &str) {
    assert!(
        headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case(wanted_name) && value == wanted_value),
        "response headers missing {wanted_name}: {wanted_value}; got {headers:?}"
    );
}

fn assert_header_contains(headers: &[(String, String)], wanted_name: &str, wanted_value: &str) {
    assert!(
        headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(wanted_name) && value.contains(wanted_value)
        }),
        "response headers missing {wanted_name} containing {wanted_value}; got {headers:?}"
    );
}

fn test_context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-v4-assurance",
        "127.0.0.1",
        "OSMAP-V4-Assurance",
    )
    .expect("test authentication context should be valid")
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
            user_agent: "OSMAP-V4-Assurance".to_string(),
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
