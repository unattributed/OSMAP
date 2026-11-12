//! Real Runtime adapters/private persistence; synthetic issued sessions do not
//! claim password/TOTP authentication or installed helper qualification.
use super::*;
use crate::auth::{AuthenticationPolicy, RequiredSecondFactor};
use crate::config::AppConfig;
use crate::message_metadata::{MessageMetadata, MessageProtection, MessageVersion};
use crate::notifications::{NotificationInbox, NotificationKind, NotificationStore};
use crate::rendering::{PlainTextMessageRenderer, RenderingPolicy};
use crate::totp::SystemTimeProvider;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
struct Fixture {
    root: PathBuf,
    config: AppConfig,
    runtime: RuntimeBrowserGateway,
    context: AuthenticationContext,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-notice-producer-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let config = AppConfig::from_env_map(&BTreeMap::from([
            ("OSMAP_ENV".into(), "development".into()),
            (
                "OSMAP_STATE_DIR".into(),
                root.join("state").to_string_lossy().into_owned(),
            ),
        ]))
        .unwrap();
        let runtime = RuntimeBrowserGateway::from_config(&config);
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "notice-producer",
            "127.0.0.1",
            "Synthetic/Notice",
        )
        .unwrap();
        Self {
            root,
            config,
            runtime,
            context,
        }
    }
    fn store(&self) -> NotificationStore {
        NotificationStore::new(&self.config.state_layout.settings_dir)
    }
    fn inbox(&self, account: &str) -> NotificationInbox {
        self.store().load(account, now()).unwrap()
    }
    fn session(&self, account: &str) -> ValidatedSession {
        let issued = self
            .runtime
            .build_session_service()
            .issue(&self.context, account, RequiredSecondFactor::Totp)
            .unwrap();
        ValidatedSession {
            record: issued.record,
            audit_event: issued.audit_event,
        }
    }
    fn render(&self, session: &ValidatedSession, text: &str) -> RenderedMessageView {
        let message = crate::mailbox::MessageView {
            metadata: Some(MessageMetadata {
                threading: None,
                version: MessageVersion::new("0123456789abcdef0123456789abcdef".into(), "native-message-one".into()).unwrap(),
                attachment_count: Some(0), attachments: Some(Vec::new()), protection: MessageProtection::Plain, preview: None,
            }),
            mailbox_name: "INBOX".into(), uid: 10, flags: Vec::new(), date_received: "2026-11-05 00:00:00 +0000".into(), size_virtual: text.len() as u64,
            header_block: "From: sender@example.test\r\nSubject: Synthetic readable fixture\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit".into(),
            body_text: text.into(),
        };
        PlainTextMessageRenderer::new(RenderingPolicy::default())
            .render_for_validated_session(&self.context, session, &message)
            .unwrap()
            .rendered
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn now() -> u64 {
    SystemTimeProvider.unix_timestamp()
}

#[test]
fn notification_acknowledgements_do_not_use_restartable_request_ids_as_durable_identity() {
    let fixture = Fixture::new();
    let at = now();
    for _ in 0..2 {
        let runtime = RuntimeBrowserGateway::from_config(&fixture.config);
        // Same store/clock/account/kind across reopened Runtime. This is the
        // existing random-ID path used after actual acknowledged key outcomes.
        runtime
            .record_session_notification(ALICE, NotificationKind::PublicKeyImported)
            .unwrap();
    }
    let inbox = fixture.store().load(ALICE, at.max(now())).unwrap();
    assert_eq!(inbox.events.len(), 2);
    assert_ne!(inbox.events[0].event_id, inbox.events[1].event_id);
    assert!(inbox
        .events
        .iter()
        .all(|e| e.kind == NotificationKind::PublicKeyImported));
}
fn json_records(root: &Path) -> Vec<Vec<u8>> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| fs::read(path).unwrap())
        .collect()
}

#[test]
fn notification_runtime_confirmed_notice_replay_preserves_read_owner_and_source_identity() {
    let fixture = Fixture::new();
    let at = now();
    let mut events = Vec::new();
    assert!(fixture.runtime.record_notice(
        ALICE,
        NotificationKind::PasswordChanged,
        "confirmed-epoch:3",
        at,
        &mut events
    ));
    assert!(events.is_empty());
    let first = fixture.inbox(ALICE);
    assert_eq!(first.events.len(), 1);
    let read = fixture
        .store()
        .set_read(
            ALICE,
            &first.events[0].event_id,
            first.revision,
            true,
            now(),
        )
        .unwrap();
    let restarted = RuntimeBrowserGateway::from_config(&fixture.config);
    assert!(restarted.record_notice(
        ALICE,
        NotificationKind::PasswordChanged,
        "confirmed-epoch:3",
        at,
        &mut events
    ));
    assert_eq!(fixture.inbox(ALICE), read);
    assert!(restarted.record_notice(
        BOB,
        NotificationKind::PasswordChanged,
        "confirmed-epoch:3",
        at,
        &mut events
    ));
    assert_ne!(
        fixture.inbox(BOB).events[0].event_id,
        read.events[0].event_id
    );
    assert!(restarted.record_notice(
        ALICE,
        NotificationKind::PasswordChanged,
        "confirmed-epoch:4",
        at,
        &mut events
    ));
    assert_eq!(fixture.inbox(ALICE).events.len(), 2);
    assert!(events.is_empty());
    for bytes in json_records(&fixture.config.state_layout.settings_dir) {
        let json = String::from_utf8(bytes).unwrap();
        assert!(!json.contains("confirmed-epoch:"));
    }
}

#[test]
fn notification_runtime_notice_publication_failure_warns_without_altering_confirmed_state() {
    let fixture = Fixture::new();
    let mut events = Vec::new();
    assert!(fixture.runtime.record_notice(
        ALICE,
        NotificationKind::SessionIssued,
        "confirmed-session",
        now(),
        &mut events
    ));
    let before = fixture.inbox(ALICE);
    let preference = crate::autosave::Store::new(&fixture.config.state_layout.settings_dir)
        .save(ALICE, 0, true, 60)
        .unwrap();
    fs::set_permissions(
        &fixture.config.state_layout.settings_dir,
        fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let recorded = fixture.runtime.record_notice(
        ALICE,
        NotificationKind::TotpChanged,
        "confirmed-enrollment",
        now(),
        &mut events,
    );
    fs::set_permissions(
        &fixture.config.state_layout.settings_dir,
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(!recorded);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "notification_recording_unconfirmed");
    assert_eq!(events[0].level, LogLevel::Warn);
    assert_eq!(fixture.inbox(ALICE), before);
    assert_eq!(
        crate::autosave::Store::new(&fixture.config.state_layout.settings_dir)
            .load(ALICE)
            .unwrap(),
        preference
    );
    assert!(!format!("{events:?}").contains("confirmed-enrollment"));
}

#[test]
fn notification_runtime_readable_mentions_use_native_identity_and_never_persist_content() {
    let fixture = Fixture::new();
    let alice = fixture.session(ALICE);
    let bob = fixture.session(BOB);
    let rendered = fixture.render(
        &alice,
        "Hello alice@example.test. private-readable-marker café",
    );
    assert!(rendered.body_text_for_compose.contains(ALICE));
    let mut events = Vec::new();
    fixture
        .runtime
        .observe_read_notice(&alice, &rendered, &mut events);
    let first = fixture.inbox(ALICE);
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.events[0].kind, NotificationKind::Mention);
    fixture
        .runtime
        .observe_read_notice(&alice, &rendered, &mut events);
    assert_eq!(fixture.inbox(ALICE), first);
    fixture
        .runtime
        .observe_read_notice(&bob, &rendered, &mut events);
    assert!(fixture.inbox(BOB).events.is_empty());
    let mut another = rendered.clone();
    another.metadata.as_mut().unwrap().version.message_guid = "native-message-two".into();
    fixture
        .runtime
        .observe_read_notice(&alice, &another, &mut events);
    assert_eq!(fixture.inbox(ALICE).events.len(), 2);
    assert!(events.is_empty());
    for bytes in json_records(&fixture.config.state_layout.settings_dir) {
        let json = String::from_utf8(bytes).unwrap();
        assert!(
            !json.contains("private-readable-marker")
                && !json.contains(ALICE)
                && !json.contains("native-message-")
        );
    }
}

#[test]
fn notification_runtime_read_refusal_missing_invalid_identity_and_nonmatching_text_emit_nothing() {
    let fixture = Fixture::new();
    let alice = fixture.session(ALICE);
    let mut events = Vec::new();
    let rendered = fixture.render(&alice, "alice@example.test");
    let mut refused = rendered.clone();
    refused.openpgp = Some(crate::openpgp_reader_ui::ReaderState::Refused(
        crate::protected_message::ProtectedError::Locked,
    ));
    let mut missing = rendered.clone();
    missing.metadata = None;
    let mut invalid = rendered.clone();
    invalid.metadata.as_mut().unwrap().version.mailbox_guid = "not-native-guid".into();
    let nonmatching = fixture.render(&alice, "Address belongs to bob@example.test");
    for view in [refused, missing, invalid, nonmatching] {
        fixture
            .runtime
            .observe_read_notice(&alice, &view, &mut events);
    }
    assert!(fixture.inbox(ALICE).events.is_empty());
    assert!(events.is_empty());
}

#[test]
fn notification_runtime_persisted_attempt_outcomes_replay_without_dispatch_or_false_success_notices(
) {
    use crate::send_journal::{AttemptOutcome, PreparedResult, SendJournal};
    use std::cell::Cell;
    let fixture = Fixture::new();
    let journal = SendJournal::new(
        fixture
            .config
            .state_layout
            .settings_dir
            .join("send-journal"),
    );
    let request = crate::send::ComposeRequest::new(
        crate::send::ComposePolicy::default(),
        "recipient@example.test",
        "Synthetic journal outcome",
        "Never sent by this test",
    )
    .unwrap();
    let dispatches = Cell::new(0usize);
    let mut events = Vec::new();
    let mut expected_notices = 0;
    for outcome in [
        AttemptOutcome::Accepted {
            sent_copy_stored: true,
        },
        AttemptOutcome::Accepted {
            sent_copy_stored: false,
        },
        AttemptOutcome::AcceptedWithoutSentCopy,
        AttemptOutcome::Unconfirmed,
        AttemptOutcome::RecoveryRefused { capacity: false },
        AttemptOutcome::RecoveryRefused { capacity: true },
    ] {
        let at = now();
        let intent = crate::send_journal::mint_intent(at).unwrap();
        let requested = !matches!(outcome, AttemptOutcome::AcceptedWithoutSentCopy);
        let actual = journal
            .execute_prepared_with_sent_copy(
                ALICE,
                &intent,
                at,
                |_| Ok::<_, ()>((request.clone(), requested)),
                |_, captured| {
                    assert_eq!(captured, requested);
                    dispatches.set(dispatches.get() + 1);
                    outcome
                },
            )
            .unwrap();
        let PreparedResult::Outcome(actual) = actual else {
            panic!("fixture journal did not dispatch typed outcome")
        };
        assert!(!actual.replayed && actual.receipt_persisted);
        assert_eq!(
            journal.receipt(ALICE, &intent, now()).unwrap(),
            Some(outcome)
        );
        fixture
            .runtime
            .record_attempt_notice(ALICE, &intent, actual.outcome, at, &mut events);
        let expected_kind = match outcome {
            AttemptOutcome::Accepted { .. } | AttemptOutcome::AcceptedWithoutSentCopy => {
                Some(NotificationKind::SubmissionAccepted)
            }
            AttemptOutcome::Unconfirmed => Some(NotificationKind::SubmissionUnknown),
            _ => None,
        };
        if let Some(kind) = expected_kind {
            expected_notices += 1;
            assert!(fixture
                .inbox(ALICE)
                .events
                .iter()
                .any(|event| event.kind == kind));
        }
        let recorded = fixture.inbox(ALICE);
        assert_eq!(recorded.events.len(), expected_notices);
        let before = dispatches.get();
        let replay = journal
            .execute_prepared_with_sent_copy(
                ALICE,
                &intent,
                now(),
                |captured| {
                    assert_eq!(captured, Some(requested));
                    Ok::<_, ()>((request.clone(), requested))
                },
                |_, _| panic!("persisted replay must not invoke dispatch"),
            )
            .unwrap();
        let PreparedResult::Outcome(replay) = replay else {
            panic!("fixture replay disappeared")
        };
        assert!(replay.replayed && replay.receipt_persisted);
        assert_eq!(dispatches.get(), before);
        fixture
            .runtime
            .record_attempt_notice(ALICE, &intent, replay.outcome, at, &mut events);
        assert_eq!(fixture.inbox(ALICE), recorded);
        assert!(fixture.inbox(BOB).events.is_empty());
    }
    assert_eq!(dispatches.get(), 6);
    assert_eq!(expected_notices, 4);
    assert!(events.is_empty());
    // These are actual persisted journal result projections. No SMTP backend
    // or remote-recipient delivery is exercised by the controlled callback.
}
