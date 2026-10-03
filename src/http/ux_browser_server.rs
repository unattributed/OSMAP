// Opt-in test-only browser server. No runtime gateway, mail host, subprocess
// helper, real credential, message source or operator profile is reachable.
use super::*;
use std::time::Instant;

#[test]
#[ignore = "explicit bounded loopback browser fixture, launched by maint/ux/browser_workflows.py"]
fn ux_synthetic_browser_server() {
    let root =
        PathBuf::from(std::env::var_os("OSMAP_UX_BROWSER_STATE").expect("explicit fixture root"));
    assert!(root.is_absolute());
    // Manual review opts into a longer-lived disposable fixture. Normal browser
    // verification keeps its existing three-minute / 200-connection bounds.
    let preview_minutes = std::env::var("OSMAP_UX_PREVIEW_MINUTES").ok().map(|value| {
        let minutes = value
            .parse::<u64>()
            .expect("preview duration is an integer");
        assert!((1..=1440).contains(&minutes));
        minutes
    });
    let duration_seconds = preview_minutes.map(|minutes| minutes * 60).unwrap_or(180);
    let max_connections = if preview_minutes.is_some() {
        20000
    } else {
        200
    };
    fs::create_dir_all(&root).expect("fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("bounded accept");
    let address = listener.local_addr().expect("loopback address");
    let policy = HttpPolicy {
        allowed_hosts: vec![address.to_string()],
        secure_session_cookie: false,
        read_timeout_secs: 1,
        write_timeout_secs: 1,
        ..HttpPolicy::default()
    };
    let gateway = StubGateway {
        after_archive_store: Some(crate::after_archive::Store::new(root.join("settings"))),
        mark_read_store: Some(crate::mark_read::Store::new(root.join("settings"))),
        autosave_store: Some(crate::autosave::Store::new(root.join("settings"))),
        signature_store: Some(crate::signature::SignatureStore::new(root.join("settings"))),
        labels_store: Some(crate::labels::LabelStore::new(
            root.join("settings/labels-v1"),
        )),
        recovery_root: root.join("send-recovery"),
        contacts_store: Some(crate::contacts::ContactStore::new(
            root.join("settings/contacts-v1"),
        )),
        draft_store: Some(crate::draft::FileDraftStore::new(
            root.join("drafts"),
            DraftPolicy::default(),
        )),
        appearance_store: Some(AppearanceStore::new(root.join("settings"))),
        settings_store: Some(crate::settings::FileUserSettingsStore::new(
            root.join("settings"),
        )),
        snooze_store: Some(crate::snooze::SnoozeStore::new(root.join("settings"))),
        notification_store: Some(crate::notifications::NotificationStore::new(
            root.join("settings"),
        )),
        identity_preferences_store: Some(
            crate::identity_preferences::IdentityPreferencesStore::new(root.join("settings")),
        ),
        composition_preferences_store: Some(
            crate::composition_preferences::CompositionPreferencesStore::new(root.join("settings")),
        ),
        reading_preferences_store: Some(crate::reading_preferences::ReadingPreferencesStore::new(
            root.join("settings"),
        )),
        browser_fixture_accounts: true,
        message_list_override: (std::env::var("OSMAP_UX_FIXTURE_CONVERSATION")
            .ok()
            .as_deref()
            == Some("1"))
        .then(super::conversation_tests::conversation_rows),
        browser_fixture_openpgp: std::env::var("OSMAP_UX_FIXTURE_OPENPGP").ok().as_deref()
            == Some("1"),
        preview_mailbox_tree: preview_minutes.is_some(),
        fixture_sessions: Some(fixture_sessions::FixtureSessions::new(
            root.join("sessions"),
        )),
        ..StubGateway::default()
    };
    let app = BrowserApp::new(policy, gateway);
    let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Error);
    fs::write(root.join("ready.json"), serde_json::to_vec(&serde_json::json!({
        "origin": format!("http://{address}"), "synthetic": true, "deadline_seconds": duration_seconds,
        "back_focus_fixture": back_focus_enabled(),
    })).expect("fixture metadata")).expect("write ready marker");
    let deadline = Instant::now() + Duration::from_secs(duration_seconds);
    let mut connections = 0;
    while Instant::now() < deadline && connections < max_connections && !root.join("stop").exists()
    {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                assert!(peer.ip().is_loopback());
                super::super::http_runtime::handle_client_stream(&app, &logger, &mut stream);
                connections += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => panic!("fixture listener failed: {error}"),
        }
    }
}

// Opt-in public fixtures for actual page-two/folder-scoped browser focus. These
// hooks do not replace the existing conversation rows in other browser runs.
fn back_focus_enabled() -> bool {
    std::env::var("OSMAP_UX_FIXTURE_BACK_FOCUS").ok().as_deref() == Some("1")
}

fn back_focus_rows(mailbox: &str) -> Vec<MessageSummary> {
    if mailbox == "INBOX" {
        let mut rows = super::conversation_tests::conversation_rows();
        rows.extend((4..=53).map(|uid| MessageSummary {
            mailbox_name: "INBOX".into(),
            uid,
            flags: vec![],
            date_received: format!("2026-10-03 04:{:02}:00 +0000", uid),
            size_virtual: 100,
            subject: Some("Shared public subject".into()),
            from: Some("filler@example.test".into()),
            to: None,
            metadata: Some(StubGateway::fixture_metadata(
                "alice@example.com",
                "INBOX",
                uid,
            )),
        }));
        rows
    } else if mailbox == "Sent" {
        vec![MessageSummary {
            mailbox_name: "Sent".into(),
            uid: 3,
            flags: vec![],
            date_received: "2026-10-03 03:00:00 +0000".into(),
            size_virtual: 100,
            subject: Some("Shared public subject".into()),
            from: Some("sender@example.test".into()),
            to: Some("recipient@example.test".into()),
            metadata: Some(StubGateway::fixture_metadata(
                "alice@example.com",
                "Sent",
                3,
            )),
        }]
    } else {
        vec![]
    }
}

pub(super) fn back_focus_list(
    session: &ValidatedSession,
    mailbox: &str,
) -> Option<BrowserMessageListOutcome> {
    if !back_focus_enabled()
        || session.record.canonical_username != "alice@example.com"
        || !matches!(mailbox, "INBOX" | "Sent")
    {
        return None;
    }
    Some(BrowserMessageListOutcome {
        decision: BrowserMessageListDecision::Listed {
            canonical_username: session.record.canonical_username.clone(),
            mailbox_name: mailbox.into(),
            messages: back_focus_rows(mailbox),
        },
        audit_events: vec![],
    })
}

pub(super) fn back_focus_search(
    session: &ValidatedSession,
    mailbox: Option<&str>,
    query: &str,
    field: MessageSearchField,
) -> Option<BrowserMessageSearchOutcome> {
    if !back_focus_enabled()
        || session.record.canonical_username != "alice@example.com"
        || !mailbox.is_none_or(|name| matches!(name, "INBOX" | "Sent"))
        || query != "Shared public subject"
        || field != MessageSearchField::Subject
    {
        return None;
    }
    let names = mailbox.map_or_else(|| vec!["INBOX", "Sent"], |name| vec![name]);
    let results = names
        .into_iter()
        .flat_map(back_focus_rows)
        .map(|message| MessageSearchResult {
            mailbox_name: message.mailbox_name,
            uid: message.uid,
            flags: message.flags,
            date_received: message.date_received,
            size_virtual: message.size_virtual,
            subject: message.subject,
            from: message.from,
            metadata: message.metadata,
        })
        .collect();
    Some(BrowserMessageSearchOutcome {
        decision: BrowserMessageSearchDecision::Listed {
            canonical_username: session.record.canonical_username.clone(),
            mailbox_name: mailbox.map(str::to_string),
            query: query.into(),
            results,
        },
        audit_events: vec![],
    })
}

pub(super) fn back_focus_view(
    session: &ValidatedSession,
    mailbox: &str,
    uid: u64,
) -> Option<BrowserMessageViewOutcome> {
    if !back_focus_enabled()
        || session.record.canonical_username != "alice@example.com"
        || !matches!(mailbox, "INBOX" | "Sent")
    {
        return None;
    }
    let Some(message) = back_focus_rows(mailbox)
        .into_iter()
        .find(|row| row.uid == uid)
    else {
        return Some(BrowserMessageViewOutcome {
            decision: BrowserMessageViewDecision::Denied {
                public_reason: "not_found".into(),
            },
            audit_events: vec![],
        });
    };
    let body = format!("Synthetic message {uid} in {mailbox} for alice@example.com.");
    Some(BrowserMessageViewOutcome {
        decision: BrowserMessageViewDecision::Rendered {
            canonical_username: session.record.canonical_username.clone(),
            rendered: Box::new(RenderedMessageView {
                openpgp: None,
                metadata: message.metadata,
                to: Some(session.record.canonical_username.clone()),
                cc: None,
                reply_metadata: None,
                flags: message.flags,
                mailbox_name: message.mailbox_name,
                uid,
                subject: message.subject,
                from: message.from,
                date_received: message.date_received,
                mime_top_level_content_type: "text/plain".into(),
                body_source: MimeBodySource::SinglePartPlainText,
                contains_html_body: false,
                body_html: TrustedHtml::from_template(format!("<pre>{}</pre>", escape_html(&body))),
                body_text_for_compose: body,
                attachments: vec![],
                rendering_mode: RenderingMode::PlainTextPreformatted,
            }),
        },
        audit_events: vec![],
    })
}

#[test]
fn back_focus_rows_are_bounded_and_equal_uids_have_distinct_current_folder_versions() {
    let inbox = back_focus_rows("INBOX");
    let sent = back_focus_rows("Sent");
    assert_eq!(inbox.len(), 53);
    assert_eq!(sent.len(), 1);
    assert!(inbox.iter().all(|row| row.mailbox_name == "INBOX"
        && crate::mailbox::parse_received_timestamp(&row.date_received).is_some()));
    assert_eq!(sent[0].uid, 3);
    let inbox_three = inbox.iter().find(|row| row.uid == 3).unwrap();
    assert_ne!(
        inbox_three.metadata.as_ref().unwrap().version,
        sent[0].metadata.as_ref().unwrap().version
    );
    assert!(back_focus_rows("Foreign").is_empty());
    // The existing conversation fixture remains its original three-row shape.
    assert_eq!(super::conversation_tests::conversation_rows().len(), 3);
}
