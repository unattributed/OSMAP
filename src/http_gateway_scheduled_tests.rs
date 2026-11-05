use super::*;
use crate::draft::{DraftPolicy, DraftRecord, DraftRecordInput, DraftStore};
use crate::mailbox::{MailboxBackendError, MessageAppendBackend, MessageAppendRequest};
use crate::send::{SubmissionBackend, SubmissionBackendError};
const ACCOUNT: &str = "alice@example.com";
struct Fixture {
    root: std::path::PathBuf,
    gateway: RuntimeBrowserGateway,
    session: ValidatedSession,
    context: AuthenticationContext,
    now: u64,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-runtime-scheduled-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let now = SystemTimeProvider.unix_timestamp();
        let session = ValidatedSession {
            record: crate::session::SessionRecord {
                account_epoch: Some(2),
                session_id: "a".repeat(64),
                csrf_token: "b".repeat(64),
                canonical_username: ACCOUNT.into(),
                issued_at: now,
                expires_at: now + 3600,
                last_seen_at: now,
                revoked_at: None,
                remote_addr: "127.0.0.1".into(),
                user_agent: "Synthetic/Test".into(),
                factor: crate::auth::RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "synthetic_session",
                "synthetic session",
            ),
        };
        Self {
            gateway: RuntimeBrowserGateway::for_test(&root),
            root,
            session,
            context: AuthenticationContext::new(
                AuthenticationPolicy::default(),
                "scheduled-runtime-test",
                "127.0.0.1",
                "Synthetic/Test",
            )
            .unwrap(),
            now,
        }
    }
    fn draft(&self) -> DraftRecord {
        let draft = DraftRecord::new(
            DraftPolicy::default(),
            DraftRecordInput {
                draft_id: crate::draft::generate_draft_id().unwrap(),
                canonical_username: ACCOUNT.into(),
                now: self.now,
                recipients_text: "bob@example.com".into(),
                cc_text: "cc@example.com".into(),
                bcc_text: "private@example.com".into(),
                subject: "Original scheduled subject".into(),
                body: "Exact captured source".into(),
                attachments: vec![],
                source_attachments: None,
            },
        )
        .unwrap();
        let store = self.gateway.build_draft_store();
        store.save(&draft, self.now).unwrap();
        store
            .load(ACCOUNT, &draft.draft_id, self.now)
            .unwrap()
            .unwrap()
    }
    fn source(&self, draft: &DraftRecord) -> String {
        crate::send_journal::intent_for_draft(
            ACCOUNT,
            &draft.draft_id,
            draft.revision.unwrap(),
            draft.updated_at,
        )
        .unwrap()
    }
    fn schedule(&self, draft: &DraftRecord) -> String {
        self.gateway
            .scheduled_from_draft_impl(
                &self.session,
                &draft.draft_id,
                draft.revision.unwrap(),
                self.now + 3600,
            )
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !std::thread::panicking() && self.root.exists() {
            std::fs::remove_dir_all(&self.root).unwrap();
            assert!(!self.root.exists());
        }
    }
}
struct NoNative;
fn composed(draft: &DraftRecord) -> ComposeRequest {
    let content = &draft.request;
    let mut request = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        &content.recipients_text,
        &content.cc_text,
        &content.bcc_text,
        &content.subject,
        &content.body,
        content.attachments.clone(),
    )
    .and_then(|request| request.with_body_format(content.body_format))
    .unwrap();
    request.sender_identity = content.sender_identity.clone();
    request.reply_thread = content.reply_thread.clone();
    request.protection = content.protection;
    request
}
impl SubmissionBackend for NoNative {
    fn submit_message(&self, _: &str, _: &ComposeRequest) -> Result<(), SubmissionBackendError> {
        panic!("retired scheduled source reached SMTP");
    }
}
impl MessageAppendBackend for NoNative {
    fn append_message(&self, _: &str, _: &MessageAppendRequest) -> Result<(), MailboxBackendError> {
        panic!("retired scheduled source reached Sent append");
    }
}

#[test]
fn runtime_schedule_edit_cancel_uses_captured_payload_exact_revision_and_account() {
    let f = Fixture::new();
    let draft = f.draft();
    assert!(matches!(
        f.gateway.scheduled_from_draft_impl(
            &f.session,
            &draft.draft_id,
            draft.revision.unwrap() + 1,
            f.now + 3600
        ),
        Err(Error::Stale)
    ));
    let id = f.schedule(&draft);
    assert_eq!(
        f.gateway.scheduled_payload_impl(&f.session, &id).unwrap(),
        composed(&draft)
    );
    let mut foreign = f.session.clone();
    foreign.record.canonical_username = "other@example.com".into();
    assert!(matches!(
        f.gateway.scheduled_payload_impl(&foreign, &id),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        f.gateway.scheduled_from_draft_impl(
            &foreign,
            &draft.draft_id,
            draft.revision.unwrap(),
            f.now + 3600
        ),
        Err(Error::NotFound)
    ));
    assert!(f
        .gateway
        .scheduled_list_impl(&foreign)
        .unwrap()
        .jobs
        .is_empty());
    let before = f.gateway.scheduled_list_impl(&f.session).unwrap();
    assert!(matches!(
        f.gateway.scheduled_edit_impl(
            &f.session,
            &id,
            before.revision + 1,
            f.now + 7200,
            "next@example.com",
            "",
            "",
            "Edited",
            "Edited body"
        ),
        Err(Error::Stale)
    ));
    let edited = f
        .gateway
        .scheduled_edit_impl(
            &f.session,
            &id,
            before.revision,
            f.now + 7200,
            "next@example.com",
            "newcc@example.com",
            "newprivate@example.com",
            "Edited",
            "Edited body",
        )
        .unwrap();
    let captured = f.gateway.scheduled_payload_impl(&f.session, &id).unwrap();
    assert_eq!(captured.subject, "Edited");
    assert_eq!(captured.body, "Edited body");
    assert_eq!(captured.recipients, ["next@example.com"]);
    assert_eq!(captured.cc_recipients, ["newcc@example.com"]);
    assert_eq!(captured.bcc_recipients, ["newprivate@example.com"]);
    assert!(f
        .gateway
        .build_draft_store()
        .load(ACCOUNT, &draft.draft_id, f.now)
        .unwrap()
        .is_none());
    assert!(matches!(
        f.gateway
            .scheduled_change_impl(&f.session, &id, before.revision, "cancel", None),
        Err(Error::Stale)
    ));
    let cancelled = f
        .gateway
        .scheduled_change_impl(&f.session, &id, edited.revision, "cancel", None)
        .unwrap();
    assert_eq!(
        cancelled
            .jobs
            .iter()
            .find(|job| job.id == id)
            .unwrap()
            .state,
        State::Cancelled
    );
    let journal = f.gateway.send_journal();
    let guard = journal.account_guard(ACCOUNT, f.now + 7201).unwrap();
    assert!(f
        .gateway
        .scheduled_store()
        .claim_next(&guard, f.now + 7201)
        .unwrap()
        .is_none());
}

#[test]
fn runtime_scheduling_retires_original_draft_send_and_save_without_native_callbacks() {
    let f = Fixture::new();
    let draft = f.draft();
    let source = f.source(&draft);
    let id = f.schedule(&draft);
    let result = f.gateway.send_message_with_backends(
        &f.context,
        &f.session,
        BrowserSendRequest {
            sender_id: None,
            protection: draft.request.protection,
            send_intent: &source,
            draft_id: Some(&draft.draft_id),
            draft_revision: draft.revision,
            recipients: &draft.request.recipients_text,
            cc_recipients: &draft.request.cc_text,
            bcc_recipients: &draft.request.bcc_text,
            subject: &draft.request.subject,
            body: &draft.request.body,
            body_format: draft.request.body_format,
            attachments: &[],
            reply_thread: None,
        },
        &SubmissionService::new(NoNative),
        &NoNative,
    );
    assert!(matches!(
        result.decision,
        BrowserSendDecision::Scheduled { ref job_id, schedule_confirmed: true } if job_id == &id
    ));
    let saved = f.gateway.save_draft_impl(
        &f.context,
        &f.session,
        BrowserDraftSaveRequest {
            sender_id: None,
            protection: draft.request.protection,
            send_intent: &source,
            draft_id: Some(&draft.draft_id),
            expected_revision: draft.revision,
            recipients: "changed@example.com",
            cc_recipients: "",
            bcc_recipients: "",
            subject: "stale save",
            body: "stale save",
            body_format: draft.request.body_format,
            attachments: &[],
            removed_attachment_indices: &[],
            source_attachments: None,
            reply_thread: None,
        },
    );
    assert!(matches!(
        saved.decision,
        BrowserDraftSaveDecision::Denied { .. }
    ));
    assert!(f
        .gateway
        .build_draft_store()
        .load(ACCOUNT, &draft.draft_id, f.now)
        .unwrap()
        .is_none());
    assert_eq!(
        f.gateway.scheduled_payload_impl(&f.session, &id).unwrap(),
        composed(&draft)
    );
    assert!(matches!(
        f.gateway.scheduled_from_draft_impl(
            &f.session,
            &draft.draft_id,
            draft.revision.unwrap(),
            f.now + 3600
        ),
        Err(Error::NotFound)
    ));
    assert_eq!(
        f.gateway
            .scheduled_list_impl(&f.session)
            .unwrap()
            .jobs
            .len(),
        1
    );
}

#[test]
fn runtime_scheduled_draft_projection_stays_readonly_after_cancel_and_reopen() {
    let f = Fixture::new();
    let draft = f.draft();
    let id = f.schedule(&draft);
    // Recreate a pre-correction source copy without changing the captured job.
    let mut legacy = draft.clone();
    legacy.revision = None;
    f.gateway.build_draft_store().save(&legacy, f.now).unwrap();
    let projected = || match f.gateway.list_drafts_impl(&f.context, &f.session).decision {
        BrowserDraftListDecision::Listed { states, .. } => states[0].state.clone(),
        other => panic!("unexpected draft projection: {other:?}"),
    };
    assert_eq!(
        projected(),
        BrowserDraftEditState::Scheduled { job_id: id.clone() }
    );
    let list = f.gateway.scheduled_list_impl(&f.session).unwrap();
    f.gateway
        .scheduled_change_impl(&f.session, &id, list.revision, "cancel", None)
        .unwrap();
    assert_eq!(
        projected(),
        BrowserDraftEditState::Scheduled { job_id: id.clone() }
    );
    let journal = f.gateway.send_journal();
    let guard = journal.account_guard(ACCOUNT, f.now).unwrap();
    assert!(guard.require_unconsumed(&f.source(&draft)).is_err());
    drop(guard);
    assert!(matches!(
        f.gateway
            .delete_draft_impl(&f.context, &f.session, &draft.draft_id, 99)
            .decision,
        BrowserDraftDeleteDecision::Denied { .. }
    ));
    let mut foreign = f.session.clone();
    foreign.record.canonical_username = "other@example.com".into();
    assert!(matches!(
        f.gateway
            .delete_draft_impl(&f.context, &foreign, &draft.draft_id, 1)
            .decision,
        BrowserDraftDeleteDecision::NotFound
    ));
    assert!(matches!(
        f.gateway
            .delete_draft_impl(&f.context, &f.session, &draft.draft_id, 1)
            .decision,
        BrowserDraftDeleteDecision::Deleted
    ));
    let BrowserDraftListDecision::Listed { drafts, usage, .. } =
        f.gateway.list_drafts_impl(&f.context, &f.session).decision
    else {
        panic!("listing refused")
    };
    assert!(drafts.is_empty());
    assert!(matches!(
        usage,
        BrowserDraftStorageUsage::Verified {
            ordinary_count: 0,
            ordinary_bytes: 0,
            ..
        }
    ));
    let reopened = RuntimeBrowserGateway::for_test(&f.root);
    let journal = reopened.send_journal();
    let guard = journal.account_guard(ACCOUNT, f.now).unwrap();
    assert!(guard.require_unconsumed(&f.source(&draft)).is_err());
    drop(guard);
    assert_eq!(
        reopened.scheduled_list_impl(&f.session).unwrap().jobs[0].state,
        State::Cancelled
    );
    let reserved = f.draft();
    let journal = f.gateway.send_journal();
    let mut guard = journal.account_guard(ACCOUNT, f.now).unwrap();
    let reserved_id = "c".repeat(32);
    guard
        .begin_schedule(&f.source(&reserved), &reserved_id, &"d".repeat(64))
        .unwrap();
    f.gateway
        .cleanup_confirmed_scheduled_source(&guard, &reserved);
    drop(guard);
    assert!(matches!(
        f.gateway
            .delete_draft_impl(&f.context, &f.session, &reserved.draft_id, 1)
            .decision,
        BrowserDraftDeleteDecision::Denied { .. }
    ));
    let BrowserDraftListDecision::Listed { states, .. } =
        f.gateway.list_drafts_impl(&f.context, &f.session).decision
    else {
        panic!("draft listing refused");
    };
    assert!(states
        .iter()
        .any(|state| state.draft_id == reserved.draft_id
            && matches!(state.state, BrowserDraftEditState::Paused { .. })));
}

#[test]
fn runtime_already_submitted_source_and_missing_epoch_never_create_jobs() {
    let f = Fixture::new();
    let draft = f.draft();
    let source = f.source(&draft);
    f.gateway
        .send_journal()
        .execute_prepared::<()>(
            ACCOUNT,
            &source,
            f.now,
            |_| Ok(composed(&draft)),
            |_| crate::send_journal::AttemptOutcome::Accepted {
                sent_copy_stored: true,
            },
        )
        .unwrap();
    assert!(matches!(
        f.gateway.scheduled_from_draft_impl(
            &f.session,
            &draft.draft_id,
            draft.revision.unwrap(),
            f.now + 3600
        ),
        Err(Error::Stale)
    ));
    assert!(f
        .gateway
        .scheduled_list_impl(&f.session)
        .unwrap()
        .jobs
        .is_empty());
    let second = f.draft();
    let mut legacy = f.session.clone();
    legacy.record.account_epoch = None;
    assert!(matches!(
        f.gateway.scheduled_from_draft_impl(
            &legacy,
            &second.draft_id,
            second.revision.unwrap(),
            f.now + 3600
        ),
        Err(Error::Unavailable)
    ));
    assert!(f
        .gateway
        .scheduled_list_impl(&f.session)
        .unwrap()
        .jobs
        .is_empty());
}

#[test]
fn runtime_direct_source_reference_refuses_without_jobs_or_intent_retirement() {
    let f = Fixture::new();
    let mut draft = f.draft();
    draft.source_attachments = Some(crate::draft::DraftSourceAttachments {
        mailbox_name: "INBOX".into(),
        uid: 9,
        version: Some(
            crate::message_metadata::MessageVersion::new(
                "a".repeat(32),
                "owned-source-message".into(),
            )
            .unwrap(),
        ),
        part_paths: vec!["1.2".into()],
    });
    let store = f.gateway.build_draft_store();
    store.save(&draft, f.now).unwrap();
    let current = store
        .load(ACCOUNT, &draft.draft_id, f.now)
        .unwrap()
        .unwrap();
    let source = f.source(&current);
    assert!(matches!(
        f.gateway.scheduled_from_draft_impl(
            &f.session,
            &current.draft_id,
            current.revision.unwrap(),
            f.now + 3600,
        ),
        Err(Error::Invalid)
    ));
    assert!(f
        .gateway
        .scheduled_list_impl(&f.session)
        .unwrap()
        .jobs
        .is_empty());
    assert_eq!(
        f.gateway
            .send_journal()
            .receipt(ACCOUNT, &source, f.now)
            .unwrap(),
        None
    );
    assert!(
        store
            .load(ACCOUNT, &current.draft_id, f.now)
            .unwrap()
            .unwrap()
            == current
    );
}

#[test]
fn runtime_schedule_cleanup_failure_keeps_confirmed_job_and_changed_source() {
    let f = Fixture::new();
    let draft = f.draft();
    let id = f.schedule(&draft);
    let BrowserDraftListDecision::Listed { drafts, usage, .. } =
        f.gateway.list_drafts_impl(&f.context, &f.session).decision
    else {
        panic!("listing refused")
    };
    assert!(drafts.is_empty());
    assert!(matches!(
        usage,
        BrowserDraftStorageUsage::Verified {
            ordinary_count: 0,
            ordinary_bytes: 0,
            ..
        }
    ));
    // A stale exact-revision cleanup must leave a later physical record intact.
    let store = f.gateway.build_draft_store();
    let mut legacy = draft.clone();
    legacy.revision = None;
    store.save(&legacy, f.now).unwrap();
    let mut changed = store
        .load(ACCOUNT, &draft.draft_id, f.now)
        .unwrap()
        .unwrap();
    changed.starred = true;
    store.save(&changed, f.now).unwrap();
    let before = store
        .load(ACCOUNT, &draft.draft_id, f.now)
        .unwrap()
        .unwrap();
    let journal = f.gateway.send_journal();
    let guard = journal.account_guard(ACCOUNT, f.now).unwrap();
    f.gateway.cleanup_confirmed_scheduled_source(&guard, &draft);
    assert!(guard.require_unconsumed(&f.source(&draft)).is_err());
    drop(guard);
    assert_eq!(
        store
            .load(ACCOUNT, &draft.draft_id, f.now)
            .unwrap()
            .unwrap(),
        before
    );
    let jobs = f.gateway.scheduled_list_impl(&f.session).unwrap();
    assert_eq!(jobs.jobs.len(), 1);
    assert_eq!(jobs.jobs[0].id, id);
    assert_eq!(jobs.jobs[0].state, State::Pending);
    assert_eq!(
        f.gateway.scheduled_payload_impl(&f.session, &id).unwrap(),
        composed(&draft)
    );
}

#[test]
fn runtime_legacy_scheduled_source_discard_preserves_pending_payload_and_retirement() {
    let f = Fixture::new();
    let draft = f.draft();
    let id = f.schedule(&draft);
    let mut legacy = draft.clone();
    legacy.revision = None;
    f.gateway.build_draft_store().save(&legacy, f.now).unwrap();
    assert!(matches!(
        f.gateway
            .delete_draft_impl(&f.context, &f.session, &draft.draft_id, 1)
            .decision,
        BrowserDraftDeleteDecision::Deleted
    ));
    let reopened = RuntimeBrowserGateway::for_test(&f.root);
    assert_eq!(
        reopened.scheduled_payload_impl(&f.session, &id).unwrap(),
        composed(&draft)
    );
    let jobs = reopened.scheduled_list_impl(&f.session).unwrap();
    assert_eq!(jobs.jobs.len(), 1);
    assert_eq!(jobs.jobs[0].state, State::Pending);
    let journal = reopened.send_journal();
    let guard = journal.account_guard(ACCOUNT, f.now).unwrap();
    assert!(guard.require_unconsumed(&f.source(&draft)).is_err());
}
