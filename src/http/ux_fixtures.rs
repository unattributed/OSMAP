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
        (
            "drafts-filtered-empty",
            "/drafts?filter=starred&q=NoMatch",
            true,
            200,
        ),
        ("drafts-review", "/drafts/discard", true, 200),
        ("settings", "/settings", true, 200),
        (
            "settings-appearance",
            "/settings?section=appearance",
            true,
            200,
        ),
        ("settings-reading", "/settings?section=reading", true, 200),
        ("sent", "/mailbox?name=Sent", true, 200),
        ("bin", "/mailbox?name=Trash", true, 200),
        ("documents-missing", "/documents", true, 503),
        ("settings-security", "/settings?section=security", true, 200),
        ("settings-identity", "/settings?section=identity", true, 503),
        (
            "settings-composition",
            "/settings?section=composition",
            true,
            200,
        ),
        ("settings-copies", "/settings?section=copies", true, 200),
        (
            "settings-notifications",
            "/settings?section=notifications",
            true,
            200,
        ),
        ("settings-privacy", "/settings?section=privacy", true, 200),
        ("settings-openpgp", "/settings?section=openpgp", true, 200),
        (
            "settings-authentication",
            "/settings?section=authentication",
            true,
            200,
        ),
        ("key-management-unavailable", "/settings/keys", true, 200),
        ("key-management-inventory", "/settings/keys", true, 200),
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
        ("invalid-search", "/search?field=invalid", true, 400),
    ];
    // A design page is not necessarily a distinct implemented route. Keep
    // absent screens, combined authentication and state references explicit.
    let approved_page_cases: [(&str, &[&str], &str, &str); 27] = [
        ("PAGE-01", &["mailboxes"], "route_rendered", "Synthetic welcome; no live mailbox qualification."),
        ("PAGE-02", &["inbox", "mailbox-empty"], "route_rendered", "Synthetic list and empty state."),
        ("PAGE-03", &["reader", "reader-unavailable"], "route_rendered", "Synthetic reader and unavailable state."),
        ("PAGE-04", &["compose"], "route_rendered", "Rendering only; no Send exercised."),
        ("PAGE-05", &["sent"], "route_rendered", "Synthetic Sent list; no authoritative storage or delivery proof."),
        ("PAGE-06", &["drafts-populated"], "route_rendered", "Synthetic drafts; no live persisted draft proof."),
        ("PAGE-07", &["documents-missing"], "unavailable_fixture", "Authenticated Documents route returns503 without configured synthetic storage/quota; no native storage or PAGE07 acceptance."),
        ("PAGE-08", &["bin", "archive-unconfigured", "archive-missing"], "partial_route_rendered", "Current Bin and archive failures; no complete archive/bin acceptance."),
        ("PAGE-09", &["search", "search-empty"], "route_rendered", "Synthetic message search; ancillary search is not qualified."),
        ("PAGE-10", &["settings-security"], "route_rendered", "Current overview includes unavailable controls."),
        ("PAGE-11", &["settings"], "route_rendered", "Current General settings; persistence not exercised."),
        ("PAGE-12", &["settings-appearance"], "route_rendered", "Current Appearance settings; persistence not exercised."),
        ("PAGE-13", &["settings-identity"], "unavailable_fixture", "Actual identity route with unavailable synthetic preferences returns503; no live capability conclusion."),
        ("PAGE-14", &["settings-reading"], "route_rendered", "Current Reading settings; persistence not exercised."),
        ("PAGE-15", &["settings-composition"], "route_rendered", "Current Composition settings; persistence and Send not exercised."),
        ("PAGE-16", &["settings-copies"], "route_rendered", "Current Copies settings; folder mutations not exercised."),
        ("PAGE-17", &["settings-notifications"], "route_rendered", "Current notification preferences; event delivery not exercised."),
        ("PAGE-18", &["settings-privacy"], "route_rendered", "Current Privacy settings; preference mutations not exercised."),
        ("PAGE-19", &["settings-openpgp"], "route_rendered", "Unavailable public inventory fixture; no private-key readiness proof."),
        ("PAGE-20", &["settings-authentication"], "route_rendered", "Current overview includes disabled password and recovery controls."),
        ("PAGE-21", &["key-management-unavailable", "key-management-inventory"], "route_rendered", "Unavailable and synthetic public inventory; no mutation or cryptography exercised."),
        ("PAGE-22", &["settings-authentication"], "missing_dedicated_page", "Password change is disabled in the current authentication overview; no dedicated screen exists."),
        ("PAGE-23", &["settings-authentication"], "missing_dedicated_page", "Recovery contact management is disabled in the current authentication overview; no dedicated screen exists."),
        ("PAGE-24", &["sessions"], "route_rendered", "Current synthetic sessions; revocation not exercised."),
        ("PAGE-25", &["login", "login-error"], "retained_authentication", "Current combined password/TOTP login and generic failure; layout unchanged."),
        ("PAGE-26", &["login", "login-error"], "combined_authentication", "TOTP remains in the current login form; no standalone challenge route exists."),
        ("PAGE-27", &["mailbox-empty", "reader-unavailable", "key-management-unavailable", "host-rejected"], "state_reference", "Representative actual states, not a fabricated State Matrix runtime page or complete state acceptance."),
    ];
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../../maint/ux/approved_pages.json"))
            .expect("approved page inventory");
    let pages = inventory["pages"].as_array().expect("approved pages array");
    assert_eq!(pages.len(), approved_page_cases.len());
    let approved_ids: std::collections::BTreeSet<_> = pages
        .iter()
        .map(|page| page["id"].as_str().expect("approved page id"))
        .collect();
    let mapped_ids: std::collections::BTreeSet<_> =
        approved_page_cases.iter().map(|case| case.0).collect();
    assert_eq!(
        mapped_ids.len(),
        approved_page_cases.len(),
        "page ids must be unique"
    );
    assert_eq!(
        mapped_ids, approved_ids,
        "every approved page must be mapped"
    );
    let names: std::collections::BTreeSet<_> = cases.iter().map(|case| case.0).collect();
    assert_eq!(names.len(), cases.len(), "fixture names must be unique");
    let mut page_manifest = Vec::new();
    for (page_id, fixtures, observation, limit) in &approved_page_cases {
        let page = pages
            .iter()
            .find(|page| page["id"] == *page_id)
            .expect("mapping references an approved page");
        for name in *fixtures {
            assert!(
                names.contains(name),
                "{page_id} references absent fixture {name}"
            );
        }
        page_manifest.push(serde_json::json!({
            "page_id": page_id, "title": page["title"], "reference": page["reference"],
            "fixture_names": fixtures, "observation": observation, "limit": limit,
            "functional_acceptance": false, "synthetic": true,
        }));
    }
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
            "key-management-inventory" => headers[0] = ("User-Agent", "KeyInventoryAvailable"),
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
        if name == "documents-missing" {
            assert!(html.contains("Document storage or its shared quota authority is unavailable."));
            assert!(!html.contains("action=\"/documents/upload\""));
            assert!(!html.contains("type=\"file\""));
        }
        if matches!(name, "login" | "login-error") {
            assert!(html.contains("name=\"totp_code\""), "retained TOTP control");
            assert!(
                html.contains("name=\"password\""),
                "retained password control"
            );
        }
        if name == "settings-authentication" {
            assert!(html.contains("disabled>Change</button>"));
            assert!(html.contains("disabled>Manage contact</button>"));
            assert!(html.contains("Recovery-contact management is unavailable."));
        }
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
            "approved_page_ids": approved_page_cases.iter()
                .filter(|(_, names, _, _)| names.contains(&name))
                .map(|(id, _, _, _)| *id).collect::<Vec<_>>(),
            "fixture_source_sha256": format!("{:x}", Sha256::digest(include_bytes!("ux_fixtures.rs"))),
            "approved_inventory_sha256": format!("{:x}", Sha256::digest(include_bytes!("../../maint/ux/approved_pages.json"))),
        }));
    }
    if let Some(directory) = &output_dir {
        fs::write(
            directory.join("routes.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
        fs::write(
            directory.join("approved-page-baselines.json"),
            serde_json::to_vec_pretty(&page_manifest).expect("serialize page mappings"),
        )
        .expect("write approved page mapping");
    }
}
