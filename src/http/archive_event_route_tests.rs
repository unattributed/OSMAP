use super::*;
use crate::archive_event::{ConfirmedArchive, Date, Error as ArchiveError, Identity, Store};
use std::sync::atomic::Ordering;

pub(super) const CONFIRMED_AT: u64 = 1_800_000_123;
const ACCOUNT: &str = "alice@example.com";
const ARCHIVE: &str = "INBOX.Projects";

#[derive(Debug, Clone, Copy)]
pub(super) enum PostListFault {
    Missing,
    Foreign,
    Duplicate,
    WrongGeneration,
}

struct ArchiveFixture {
    root: PathBuf,
    store: Store,
    app: BrowserApp<StubGateway>,
}
impl ArchiveFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "archive-event-route-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let settings = crate::settings::FileUserSettingsStore::new(root.join("settings"));
        settings.save_archive(ACCOUNT, Some(ARCHIVE)).unwrap();
        let store = Store::new(root.join("archive-events"));
        let app = BrowserApp::new(
            HttpPolicy {
                mailbox_worker_budget: 1,
                ..HttpPolicy::default()
            },
            StubGateway {
                settings_store: Some(settings),
                snooze_store: Some(crate::snooze::SnoozeStore::new(root.join("settings"))),
                archive_event_store: Some(store.clone()),
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }
    fn form(&self, uid: u64, action: &str) -> String {
        move_form(
            &format!(
                "csrf_token={}&mailbox=INBOX&uid={uid}&destination_mailbox=INBOX.Projects",
                StubGateway::validated_session().record.csrf_token
            ),
            action,
        )
    }
    fn post(&self, body: &str, bulk: bool, agent: &str) -> HandledHttpResponse {
        let mut req = request(
            "POST",
            if bulk {
                "/messages/move"
            } else {
                "/message/move"
            },
            &authenticated_same_origin_headers(),
            body,
        );
        req.headers.insert("user-agent".into(), agent.into());
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn calls(&self) -> usize {
        self.app
            .gateway
            .archive_event_records
            .load(Ordering::SeqCst)
    }
    fn destination(&self) -> MessageSummary {
        let rows = self
            .app
            .gateway
            .fixture_reconcile_messages(ACCOUNT, ARCHIVE, vec![]);
        assert_eq!(rows.len(), 1);
        rows[0].clone()
    }
    fn check_idle(&self) {
        assert_eq!(self.app.request_budgets.mailbox_workers.active_count(), 0);
    }
}
impl Drop for ArchiveFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn archive_success_records_once_after_confirmation_at_actual_destination_identity() {
    let fixture = ArchiveFixture::new();
    let form = fixture.form(9, "archive");
    let old = fixture
        .app
        .gateway
        .fixture_current_metadata(ACCOUNT, "INBOX", 9)
        .unwrap();
    let response = fixture.post(&form, false, "OSMAP/ManyMessages");
    assert_eq!(
        response.response.status_code,
        303,
        "{}",
        body_text(&response)
    );
    assert_eq!(fixture.calls(), 1);
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_move")
            .count(),
        1
    );
    let destination = fixture.destination();
    let version = &destination.metadata.as_ref().unwrap().version;
    assert_ne!(destination.uid, 9);
    assert_ne!(version.mailbox_guid, old.version.mailbox_guid);
    assert_eq!(version.message_guid, old.version.message_guid);
    let snapshot = fixture.store.load(ACCOUNT).unwrap();
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(
        snapshot
            .archived_at(&Identity::from_summary(ACCOUNT, ACCOUNT, ARCHIVE, &destination).unwrap()),
        Ok(Some(CONFIRMED_AT))
    );
    assert_eq!(
        fixture
            .post(&form, false, "OSMAP/ManyMessages")
            .response
            .status_code,
        409
    );
    assert_eq!(fixture.calls(), 1);
    fixture.check_idle();
    let mut req = request(
        "GET",
        "/mailbox?name=INBOX.Projects",
        &authenticated_headers(),
        "",
    );
    req.headers
        .insert("user-agent".into(), "OSMAP/ManyMessages".into());
    let page = fixture.app.handle_request(&req, "127.0.0.1");
    assert_eq!(page.response.status_code, 200);
    let expected = crate::logging::format_unix_timestamp_utc(CONFIRMED_AT);
    assert!(body_text(&page).contains(&format!("data-label=\"Archived\">{expected}")));
    assert!(body_text(&page).contains("data-label=\"Received\">"));
}

#[test]
fn archive_refusal_ambiguity_csrf_stale_and_foreign_never_record_events() {
    for (agent, uid, mutate, expected) in [
        ("OSMAP/ManyMessages;MoveUnknown", 10, "none", 503),
        ("OSMAP/ManyMessages;MoveBusy", 9, "none", 409),
        ("OSMAP/ManyMessages;MoveUnavailable", 9, "none", 503),
        ("OSMAP/ManyMessages", 9, "csrf", 403),
        ("OSMAP/ManyMessages", 9, "stale", 409),
        ("OSMAP/ManyMessages", 9, "foreign", 409),
    ] {
        let fixture = ArchiveFixture::new();
        let mut fields =
            parse_urlencoded_form(fixture.form(uid, "archive").as_bytes(), 20, 16384).unwrap();
        match mutate {
            "csrf" => {
                fields.insert("csrf_token".into(), "invalid".into());
            }
            "stale" => {
                fields.insert("message_guid".into(), "stale".into());
            }
            "foreign" => {
                fields.insert(
                    "mailbox_guid".into(),
                    StubGateway::fixture_metadata("bob@example.com", "INBOX", uid)
                        .version
                        .mailbox_guid,
                );
            }
            _ => {}
        }
        let form = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let response = fixture.post(&form, false, agent);
        assert_eq!(
            response.response.status_code,
            expected,
            "{agent}/{mutate}: {}",
            body_text(&response)
        );
        assert_eq!(fixture.calls(), 0);
        assert_eq!(fixture.store.load(ACCOUNT).unwrap().revision(), 0);
        assert!(fixture
            .app
            .gateway
            .fixture_current_metadata(ACCOUNT, "INBOX", uid)
            .is_some());
        fixture.check_idle();
    }
}

#[test]
fn archive_destination_metadata_faults_preserve_confirmed_move_without_retry() {
    for fault in [
        PostListFault::Missing,
        PostListFault::Foreign,
        PostListFault::Duplicate,
        PostListFault::WrongGeneration,
    ] {
        let fixture = ArchiveFixture::new();
        *fixture
            .app
            .gateway
            .archive_event_post_list_fault
            .lock()
            .unwrap() = Some(fault);
        let response = fixture.post(&fixture.form(9, "archive"), false, "OSMAP/ManyMessages");
        assert_eq!(
            response.response.status_code,
            200,
            "{fault:?}: {}",
            body_text(&response)
        );
        assert!(body_text(&response).contains("All selected mail moves were confirmed"));
        assert!(body_text(&response).contains("Archive-date recording could not be confirmed"));
        assert!(body_text(&response).contains("do not repeat"));
        assert_eq!(fixture.calls(), 0);
        assert_eq!(
            response
                .audit_events
                .iter()
                .filter(|e| e.action == "stub_message_move")
                .count(),
            1
        );
        assert!(fixture
            .app
            .gateway
            .fixture_current_metadata(ACCOUNT, "INBOX", 9)
            .is_none());
        assert_eq!(fixture.store.load(ACCOUNT).unwrap().revision(), 0);
        fixture.check_idle();
    }
}

#[test]
fn archive_store_failure_preserves_confirmed_move_and_reports_metadata_only_failure() {
    let fixture = ArchiveFixture::new();
    fs::write(
        fixture.root.join("archive-events"),
        b"blocked fixture directory",
    )
    .unwrap();
    let response = fixture.post(&fixture.form(9, "archive"), false, "OSMAP/ManyMessages");
    assert_eq!(response.response.status_code, 200);
    assert!(body_text(&response).contains("do not repeat the mail move"));
    assert_eq!(fixture.calls(), 1);
    assert!(matches!(
        fixture.store.load(ACCOUNT),
        Err(ArchiveError::Unavailable)
    ));
    assert!(fixture
        .app
        .gateway
        .fixture_current_metadata(ACCOUNT, "INBOX", 9)
        .is_none());
    assert_eq!(fixture.destination().uid, 1001);
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_move")
            .count(),
        1
    );
    fixture.check_idle();
}

#[test]
fn bulk_archive_records_only_confirmed_members_before_uncertain_stop() {
    let fixture = ArchiveFixture::new();
    let form = move_form(
        &format!(
            "csrf_token={}&mailbox=INBOX&uid_9=9&uid_10=10&uid_11=11",
            StubGateway::validated_session().record.csrf_token
        ),
        "archive",
    );
    let response = fixture.post(&form, true, "OSMAP/ManyMessages;MoveUnknown");
    assert_eq!(response.response.status_code, 503);
    assert!(body_text(&response)
        .contains("1 confirmed moved; 1 uncertain; 1 remaining messages were not attempted."));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.store.load(ACCOUNT).unwrap().revision(), 1);
    let identity =
        Identity::from_summary(ACCOUNT, ACCOUNT, ARCHIVE, &fixture.destination()).unwrap();
    assert_eq!(
        fixture.store.load(ACCOUNT).unwrap().archived_at(&identity),
        Ok(Some(CONFIRMED_AT))
    );
    for uid in [10, 11] {
        assert!(fixture
            .app
            .gateway
            .fixture_current_metadata(ACCOUNT, "INBOX", uid)
            .is_some());
    }
    fixture.check_idle();
}

#[test]
fn ordinary_move_bin_and_restore_do_not_generate_archive_events() {
    for action in ["move", "bin"] {
        let fixture = ArchiveFixture::new();
        let response = fixture.post(&fixture.form(9, action), false, "OSMAP/ManyMessages");
        assert_eq!(
            response.response.status_code,
            303,
            "{action}: {}",
            body_text(&response)
        );
        assert_eq!(fixture.calls(), 0);
        assert_eq!(fixture.store.load(ACCOUNT).unwrap().revision(), 0);
        if action == "bin" {
            let moved = fixture
                .app
                .gateway
                .fixture_reconcile_messages(ACCOUNT, "Trash", vec![]);
            assert_eq!(moved.len(), 1);
            let version = &moved[0].metadata.as_ref().unwrap().version;
            let body = format!("csrf_token={}&mailbox=Trash&uid={}&mailbox_guid={}&message_guid={}&action=restore&return_to=%2Fmailbox%3Fname%3DTrash",
                StubGateway::validated_session().record.csrf_token, moved[0].uid,
                url_encode(&version.mailbox_guid), url_encode(&version.message_guid));
            assert_eq!(
                fixture
                    .post(&body, false, "OSMAP/ManyMessages")
                    .response
                    .status_code,
                303
            );
            assert_eq!(fixture.calls(), 0);
        }
        fixture.check_idle();
    }
}

#[test]
fn bulk_confirmed_metadata_refusal_then_unknown_move_keeps_both_outcomes_distinct() {
    let fixture = ArchiveFixture::new();
    fs::write(
        fixture.root.join("archive-events"),
        b"blocked metadata directory",
    )
    .unwrap();
    let form = move_form(
        &format!(
            "csrf_token={}&mailbox=INBOX&uid_9=9&uid_10=10&uid_11=11",
            StubGateway::validated_session().record.csrf_token
        ),
        "archive",
    );
    let response = fixture.post(&form, true, "OSMAP/ManyMessages;MoveUnknown");
    assert_eq!(response.response.status_code, 503);
    let html = body_text(&response);
    assert!(
        html.contains("1 confirmed moved; 1 uncertain; 1 remaining messages were not attempted.")
    );
    assert!(html
        .contains("Archive-date recording for an earlier confirmed move could not be confirmed"));
    assert!(html.contains("do not repeat those mail moves"));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_move")
            .count(),
        1
    );
    assert!(fixture
        .app
        .gateway
        .fixture_current_metadata(ACCOUNT, "INBOX", 9)
        .is_none());
    for uid in [10, 11] {
        assert!(fixture
            .app
            .gateway
            .fixture_current_metadata(ACCOUNT, "INBOX", uid)
            .is_some());
    }
    fixture.check_idle();
}

#[test]
fn confirmed_archive_event_does_not_replace_saved_next_message_navigation() {
    let mut fixture = ArchiveFixture::new();
    let next = crate::after_archive::Store::new(fixture.root.join("navigation"));
    next.save(ACCOUNT, 0, crate::after_archive::Choice::Next)
        .unwrap();
    fixture.app.gateway.after_archive_store = Some(next);
    let response = fixture.post(&fixture.form(10, "archive"), false, "Firefox/Test");
    assert_eq!(
        response.response.status_code,
        303,
        "{}",
        body_text(&response)
    );
    assert!(location_header(&response).starts_with("/message?"));
    assert!(location_header(&response).contains("uid=9&mailbox_guid="));
    assert_eq!(fixture.calls(), 1);
    assert_eq!(fixture.store.load(ACCOUNT).unwrap().revision(), 1);
    fixture.check_idle();
}

fn runtime_confirmation() -> (ConfirmedArchive, MessageSummary) {
    let source = StubGateway::fixture_metadata(ACCOUNT, "INBOX", 9).version;
    let mut destination = MessageSummary {
        mailbox_name: ARCHIVE.into(),
        uid: 1001,
        flags: vec![],
        date_received: "1999-01-01".into(),
        size_virtual: 11,
        subject: None,
        from: None,
        to: None,
        metadata: Some(StubGateway::fixture_metadata(ACCOUNT, ARCHIVE, 9)),
    };
    destination.metadata.as_mut().unwrap().version.message_guid = source.message_guid.clone();
    let request =
        MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", ARCHIVE, 9, source).unwrap();
    let decision = BrowserMessageMoveDecision::Moved {
        source_mailbox_name: "INBOX".into(),
        destination_mailbox_name: ARCHIVE.into(),
        uid: 9,
    };
    (
        ConfirmedArchive::resolve(
            ACCOUNT,
            ARCHIVE,
            &request,
            &decision,
            ACCOUNT,
            ARCHIVE,
            std::slice::from_ref(&destination),
        )
        .unwrap(),
        destination,
    )
}

#[test]
fn runtime_archive_store_uses_validated_session_owner_and_persists_across_restart() {
    let root = temp_dir(&format!(
        "archive-runtime-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let alice = StubGateway::validated_session();
    let mut bob = alice.clone();
    bob.record.canonical_username = "bob@example.com".into();
    let (event, destination) = runtime_confirmation();
    assert!(gateway.archive_events_available());
    assert!(matches!(
        gateway.record_archive_event(&bob, &event, CONFIRMED_AT),
        Err(ArchiveError::Invalid)
    ));
    assert_eq!(gateway.load_archive_events(&alice).unwrap().revision(), 0);
    gateway
        .record_archive_event(&alice, &event, CONFIRMED_AT)
        .unwrap();
    let restarted = RuntimeBrowserGateway::for_test(&root);
    assert_eq!(
        crate::archive_event::date_for(
            Some(&restarted.load_archive_events(&alice).unwrap()),
            ACCOUNT,
            ARCHIVE,
            &destination
        ),
        Date::Known(CONFIRMED_AT)
    );
    let unknown = restarted.load_archive_events(&bob).unwrap();
    assert_eq!(unknown.revision(), 0);
    assert!(unknown
        .archived_at(
            &Identity::from_summary("bob@example.com", "bob@example.com", ARCHIVE, &destination)
                .unwrap()
        )
        .unwrap()
        .is_none());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn runtime_archive_metadata_unavailable_is_not_an_empty_successful_snapshot() {
    let root = temp_dir(&format!(
        "archive-runtime-blocked-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir_all(root.join("settings")).unwrap();
    fs::write(
        root.join("settings/archive-events-v1"),
        b"blocked fixture directory",
    )
    .unwrap();
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    assert!(matches!(
        gateway.load_archive_events(&session),
        Err(ArchiveError::Unavailable)
    ));
    assert!(matches!(
        gateway.record_archive_event(&session, &runtime_confirmation().0, CONFIRMED_AT),
        Err(ArchiveError::Unavailable)
    ));
    fs::remove_dir_all(root).unwrap();
}
