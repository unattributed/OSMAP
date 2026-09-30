// Test-only route snapshots. Uses the existing in-memory gateway and never
// constructs a runtime gateway, opens a socket, or contacts a mail host.
use super::*;
use sha2::{Digest, Sha256};

fn redact_fixture_tokens(html: &str) -> String {
    let mut output = String::with_capacity(html.len());
    let mut hex_run = String::new();
    for character in html.chars().chain(std::iter::once('\0')) {
        if character.is_ascii_hexdigit() {
            hex_run.push(character);
            continue;
        }
        if hex_run.len() >= 32 {
            output.push_str("SYNTHETIC-REDACTED");
        } else {
            output.push_str(&hex_run);
        }
        hex_run.clear();
        if character != '\0' {
            output.push(character);
        }
    }
    output.replace("@example.com", "@example.test")
}

#[test]
fn ux_synthetic_route_baselines() {
    let output_dir = std::env::var_os("OSMAP_UX_FIXTURE_DIR").map(PathBuf::from);
    let appearance = std::env::var("OSMAP_UX_FIXTURE_APPEARANCE")
        .map(|value| AppearancePreference::parse(&value).expect("valid fixture appearance"))
        .unwrap_or_default();
    if let Some(path) = &output_dir {
        assert!(path.is_absolute(), "fixture directory must be absolute");
        fs::create_dir_all(path).expect("create fixture directory");
    }
    let cases = [
        ("login", "/login", false, 200),
        ("login-error", "/login", false, 401),
        ("host-rejected", "/login", false, 421),
        ("redirect", "/", false, 303),
        ("mailboxes", "/mailboxes", true, 200),
        ("inbox", "/mailbox?name=INBOX", true, 200),
        ("mailbox-empty", "/mailbox?name=INBOX", true, 200),
        (
            "inbox-unread",
            "/mailbox?name=INBOX&filter=unread",
            true,
            200,
        ),
        (
            "inbox-starred-empty",
            "/mailbox?name=INBOX&filter=starred",
            true,
            200,
        ),
        ("inbox-many", "/mailbox?name=INBOX", true, 200),
        ("inbox-long-headers", "/mailbox?name=INBOX", true, 200),
        (
            "inbox-long-reader",
            "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125",
            true,
            200,
        ),
        (
            "reader-off-page",
            "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=7",
            true,
            200,
        ),
        (
            "reader-filter-miss",
            "/mailbox?name=INBOX&filter=unread&selected_mailbox=INBOX&selected_uid=8",
            true,
            200,
        ),
        (
            "reader-stale-selection",
            "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125",
            true,
            200,
        ),
        (
            "search-reader",
            "/search?q=reader-fixture&scope=all&selected_mailbox=Sent&selected_uid=125&page=3",
            true,
            200,
        ),
        ("inbox-page-two", "/mailbox?name=INBOX&page=2", true, 200),
        (
            "inbox-bulk-selection",
            "/mailbox?name=INBOX&select=move",
            true,
            200,
        ),
        (
            "bin-reader",
            "/mailbox?name=Trash&selected_mailbox=Trash&selected_uid=125",
            true,
            200,
        ),
        ("reader-legacy", "/message?mailbox=INBOX&uid=9", true, 200),
        ("move-partial", "/messages/move", true, 503),
        ("move-stale", "/message/move", true, 409),
        ("move-invalid", "/message/move", true, 400),
        (
            "inbox-selected",
            "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125",
            true,
            200,
        ),
        ("search", "/search?mailbox=INBOX&q=report", true, 200),
        (
            "search-starred",
            "/search?q=searchsort&filter=starred",
            true,
            200,
        ),
        ("search-page-two", "/search?q=manyresults&page=2", true, 200),
        ("invalid-list-page", "/mailbox?name=INBOX&page=0", true, 400),
        (
            "search-empty",
            "/search?mailbox=INBOX&q=ux-empty-fixture",
            true,
            200,
        ),
        (
            "attachment-unavailable",
            "/attachment?mailbox=INBOX&uid=9&part=1.99",
            true,
            404,
        ),
        ("reader", "/message?mailbox=INBOX&uid=9", true, 200),
        (
            "reader-unavailable",
            "/message?mailbox=INBOX&uid=900",
            true,
            503,
        ),
        (
            "source-long",
            "/message?mailbox=INBOX&uid=9&view=source",
            true,
            200,
        ),
        (
            "source-unavailable",
            "/message?mailbox=INBOX&uid=9&view=source",
            true,
            503,
        ),
        (
            "source-not-found",
            "/message?mailbox=INBOX&uid=999&view=source",
            true,
            404,
        ),
        (
            "reader-state-controls",
            "/message?mailbox=INBOX&uid=10",
            true,
            200,
        ),
        (
            "source",
            "/message?mailbox=INBOX&uid=9&view=source",
            true,
            200,
        ),
        ("compose", "/compose", true, 200),
        (
            "compose-saved-attachments",
            "/draft?id=00000000000000000000000000000001",
            true,
            200,
        ),
        (
            "compose-source-changed",
            "/draft?id=00000000000000000000000000000001",
            true,
            200,
        ),
        (
            "compose-source-unverified",
            "/draft?id=00000000000000000000000000000001",
            true,
            200,
        ),
        (
            "compose-source-unavailable",
            "/draft?id=00000000000000000000000000000001",
            true,
            200,
        ),
        ("draft-save-unconfirmed", "/drafts/save", true, 503),
        (
            "reply-all",
            "/compose?mode=reply-all&mailbox=INBOX&uid=9",
            true,
            200,
        ),
        (
            "forward",
            "/compose?mode=forward&mailbox=INBOX&uid=9",
            true,
            200,
        ),
        (
            "reply",
            "/compose?mode=reply&mailbox=INBOX&uid=9",
            true,
            200,
        ),
        ("drafts-empty", "/drafts", true, 200),
        ("drafts-populated", "/drafts", true, 200),
        ("drafts-filtered-empty", "/drafts?filter=starred&q=NoMatch", true, 200),
        ("drafts-review", "/drafts/discard", true, 200),
        ("settings", "/settings", true, 200),
        ("settings-appearance", "/settings?section=appearance", true, 200),
        ("settings-reading", "/settings?section=reading", true, 200),
        ("settings-long-identity", "/settings", true, 200),
        (
            "archive-shortcut",
            "/mailbox/shortcut?kind=archive",
            true,
            303,
        ),
        (
            "archive-unconfigured",
            "/mailbox/shortcut?kind=archive",
            true,
            200,
        ),
        (
            "archive-missing",
            "/mailbox/shortcut?kind=archive",
            true,
            404,
        ),
        (
            "archive-unavailable",
            "/mailbox/shortcut?kind=archive",
            true,
            503,
        ),
        ("sessions", "/sessions", true, 200),
        ("not-found", "/not-a-route", false, 404),
        ("invalid-search", "/search", true, 400),
        (
            "reader-unavailable",
            "/message?mailbox=INBOX&uid=900",
            true,
            503,
        ),
    ];
    let mut manifest = Vec::new();
    for (name, path, authenticated, expected_status) in cases {
        let mut headers = if authenticated {
            authenticated_headers().to_vec()
        } else {
            vec![("User-Agent", "OSMAP/SyntheticUX")]
        };
        if name == "mailbox-empty" {
            headers[0] = ("User-Agent", "OSMAP/EmptyMailbox");
        }
        if matches!(
            name,
            "inbox-many"
                | "inbox-page-two"
                | "inbox-selected"
                | "reader-state-controls"
                | "reader-off-page"
                | "reader-filter-miss"
                | "search-reader"
                | "inbox-bulk-selection"
                | "bin-reader"
        ) {
            headers[0] = ("User-Agent", "OSMAP/ManyMessages");
        }
        match name {
            "reply-all" => headers[0] = ("User-Agent", "OSMAP/ReplyRecipients"),
            "reader-legacy" => headers[0] = ("User-Agent", "OSMAP/LegacyMetadata"),
            "source-long" => headers[0] = ("User-Agent", "OSMAP/SourceLong"),
            "source-unavailable" => headers[0] = ("User-Agent", "OSMAP/SourceUnavailable"),
            "move-partial" => headers[0] = ("User-Agent", "OSMAP/ManyMessages;MoveUnknown"),
            "move-stale" | "move-invalid" => headers[0] = ("User-Agent", "OSMAP/ManyMessages"),
            "reader-stale-selection" => {
                headers[0] = ("User-Agent", "OSMAP/ManyMessages;ReaderStale")
            }
            "inbox-long-headers" | "inbox-long-reader" => {
                headers[0] = ("User-Agent", "OSMAP/ManyMessages;LongHeaders")
            }
            "settings-long-identity" => headers[0] = ("User-Agent", "OSMAP/LongIdentity"),
            "archive-unconfigured" => headers[0] = ("User-Agent", "OSMAP/NoArchiveTest"),
            "archive-missing" => headers[0] = ("User-Agent", "OSMAP/InvalidArchiveTest"),
            "archive-unavailable" => headers[0] = ("User-Agent", "OSMAP/SettingsUnavailable"),
            "draft-save-unconfirmed" => headers[0] = ("User-Agent", "OSMAP/DraftSaveUnconfirmed"),
            _ => {}
        }
        let method = if name == "login-error"
            || name.starts_with("move-")
            || matches!(name, "drafts-review" | "draft-save-unconfirmed")
        {
            "POST"
        } else {
            "GET"
        };
        let body = if name == "draft-save-unconfirmed" {
            headers.push(("Origin", "https://localhost"));
            format!("csrf_token={}&to=still%20choosing&subject=Public%20project%20notes&body=Unconfirmed%20save%20-%20public%20synthetic%20text", StubGateway::validated_session().record.csrf_token)
        } else if name == "drafts-review" {
            headers.push(("Origin", "https://localhost"));
            format!("csrf_token={}&stage=review&filter=all&sort=newest&q=&selected_{:032x}=1&selected_{:032x}=1", StubGateway::validated_session().record.csrf_token, 1, 2)
        } else if name.starts_with("move-") {
            headers.push(("Origin", "https://localhost"));
            let selection = if name == "move-partial" {
                "uid_9=9&uid_10=10&uid_11=11"
            } else {
                "uid=9"
            };
            let mut body = move_form(
                &format!(
                    "csrf_token={}&mailbox=INBOX&{selection}",
                    StubGateway::validated_session().record.csrf_token
                ),
                "bin",
            );
            if name == "move-stale" {
                let original = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9)
                    .version
                    .message_guid;
                body = body.replace(&url_encode(&original), "absent-synthetic-message");
            }
            if name == "move-invalid" {
                body.push_str("&unexpected=1");
            }
            body
        } else {
            String::new()
        };
        let mut fixture_request = request(method, path, &headers, &body);
        fixture_request
            .headers
            .entry("cookie".into())
            .or_default()
            .push_str(&format!("; osmap_appearance={}", appearance.as_str()));
        let marker = match appearance {
            AppearancePreference::Light => ";AppearanceLight",
            AppearancePreference::Dark => ";AppearanceDark",
            AppearancePreference::System => ";AppearanceSystem",
        };
        fixture_request
            .headers
            .entry("user-agent".into())
            .or_default()
            .push_str(marker);
        if name == "host-rejected" {
            fixture_request
                .headers
                .insert("host".to_string(), "unaccepted.example.test".to_string());
        }
        let fixture_app = app();
        if matches!(
            name,
            "drafts-populated"
                | "drafts-filtered-empty"
                | "drafts-review"
                | "compose-saved-attachments"
                | "compose-source-changed"
                | "compose-source-unverified"
                | "compose-source-unavailable"
        ) {
            let mut drafts = fixture_app.gateway.drafts.lock().unwrap();
            for (index, subject) in [
                "Project notes",
                "Security outline",
                "Meeting notes",
                "Vendor assessment",
                "Policy draft",
                "Quarterly update",
                "Personal notes",
                "Release checklist",
            ]
            .iter()
            .enumerate()
            {
                let id = format!("{:032x}", index + 1);
                let mut draft = DraftRecord::new(
                    DraftPolicy::default(),
                    DraftRecordInput {
                        draft_id: id.clone(),
                        canonical_username: "alice@example.com".into(),
                        now: 1_790_000_000 - index as u64 * 86_400,
                        recipients_text: format!(
                            "Synthetic Recipient {} <recipient{}@example.test>",
                            index + 1,
                            index + 1
                        ),
                        cc_text: String::new(),
                        bcc_text: String::new(),
                        subject: subject.to_string(),
                        body: "Public synthetic fixture text".into(),
                        attachments: if index % 3 == 0 {
                            vec![UploadedAttachment::new(
                                ComposePolicy::default(),
                                "synthetic.txt",
                                "text/plain",
                                b"public synthetic file".to_vec(),
                            )
                            .unwrap()]
                        } else {
                            vec![]
                        },
                        source_attachments: None,
                    },
                )
                .unwrap();
                draft.revision = Some(1);
                if name.starts_with("compose-source-") && index == 0 {
                    let mut version =
                        StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
                    if name == "compose-source-changed" {
                        version.message_guid = "old-original".into();
                    }
                    draft.source_attachments = Some(DraftSourceAttachments {
                        mailbox_name: "INBOX".into(),
                        uid: if name == "compose-source-unavailable" {
                            900
                        } else {
                            9
                        },
                        version: (name != "compose-source-unverified").then_some(version),
                        part_paths: vec!["1.2".into()],
                    });
                }
                if name == "compose-saved-attachments" && index == 0 {
                    draft.request.attachments = ["Project_review_notes.txt", "Risk_assessment.pdf"]
                        .into_iter()
                        .map(|filename| {
                            UploadedAttachment::new(
                                ComposePolicy::default(),
                                filename,
                                "application/octet-stream",
                                b"public synthetic fixture".to_vec(),
                            )
                            .unwrap()
                        })
                        .collect();
                }
                draft.starred = index == 1;
                drafts.insert(id, draft);
            }
        }
        if fixture_request.method == HttpMethod::Post
            && matches!(fixture_request.path.as_str(), "/send" | "/drafts/save")
        {
            add_native_compose_intent(&fixture_app, &mut fixture_request);
        }
        let response = fixture_app.handle_request(&fixture_request, "127.0.0.1");
        assert_eq!(response.response.status_code, expected_status, "{name}");
        let csp = response
            .response
            .headers
            .iter()
            .find(|(header, _)| header == "Content-Security-Policy")
            .map(|(_, value)| value.as_str())
            .expect("HTML has CSP");
        let html = redact_fixture_tokens(&body_text(&response));
        let compose_enhanced = html.contains("id=\"compose-form\"");
        if compose_enhanced {
            assert_eq!(csp, super::super::compose_enhancement::csp());
            assert!(html.contains(super::super::compose_enhancement::SCRIPT));
            assert_eq!(
                html.matches("<script").count(),
                1,
                "bounded script fixture {name}"
            );
        } else {
            assert_eq!(csp, crate::http_support::browser_csp());
            assert!(!html.contains("<script"), "script-free fixture {name}");
        }
        if let Some(directory) = &output_dir {
            fs::write(directory.join(format!("{name}.html")), &html).expect("write fixture");
        }
        manifest.push(serde_json::json!({
            "name": name, "method": method, "route": path,
            "status": expected_status, "authenticated_fixture": authenticated,
            "html_sha256": format!("{:x}", Sha256::digest(html.as_bytes())),
            "csp": csp, "synthetic": true, "tokens_redacted": true,
            "appearance": appearance.as_str(),
            "script_count": usize::from(compose_enhanced),
        }));
    }
    if let Some(directory) = &output_dir {
        fs::write(
            directory.join("routes.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
    }
}
