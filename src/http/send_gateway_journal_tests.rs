use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct Fixture {
    root: std::path::PathBuf,
    gateway: RuntimeBrowserGateway,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "osmap-runtime-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let gateway = RuntimeBrowserGateway::for_test(&root);
        Self { root, gateway }
    }
    fn save(&self) -> (String, DraftRecord) {
        let session = validated_session();
        let token = crate::send_journal::mint_intent(self.gateway.send_clock()).unwrap();
        let outcome = self.gateway.save_draft_impl(
            &test_context(),
            &session,
            save_request(&token, None, None),
        );
        let BrowserDraftSaveDecision::Saved { draft_id } = outcome.decision else {
            panic!("save must confirm")
        };
        let draft = self
            .gateway
            .build_draft_store()
            .load(
                &session.record.canonical_username,
                &draft_id,
                self.gateway.send_clock(),
            )
            .unwrap()
            .unwrap();
        (token, draft)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn save_request<'a>(
    intent: &'a str,
    id: Option<&'a str>,
    revision: Option<u64>,
) -> BrowserDraftSaveRequest<'a> {
    BrowserDraftSaveRequest {
 sender_id: None,
            protection: crate::send::ProtectionIntent::default(),
        send_intent: intent,
        draft_id: id,
        expected_revision: revision,
        recipients: "bob@example.test",
        cc_recipients: "",
        bcc_recipients: "hidden@example.test",
        subject: "Synthetic subject",
        body: "Synthetic body 🦊",
        body_format: crate::compose_format::BodyFormat::Plain,
        attachments: &[],
        removed_attachment_indices: &[],
        source_attachments: None,
        reply_thread: None,
    }
}
fn send_request<'a>(intent: &'a str, draft: &'a DraftRecord) -> BrowserSendRequest<'a> {
    BrowserSendRequest {
 sender_id: None,
            protection: crate::send::ProtectionIntent::default(),
        send_intent: intent,
        draft_id: Some(&draft.draft_id),
        draft_revision: draft.revision,
        recipients: &draft.request.recipients_text,
        cc_recipients: &draft.request.cc_text,
        bcc_recipients: &draft.request.bcc_text,
        subject: &draft.request.subject,
        body: &draft.request.body,
        body_format: draft.request.body_format,
        attachments: &draft.request.attachments,
        reply_thread: draft.request.reply_thread.as_ref(),
    }
}
#[derive(Clone)]
struct SubmissionProbe {
    calls: Arc<Mutex<Vec<ComposeRequest>>>,
    fail: bool,
    block: Option<Arc<Mutex<std::sync::mpsc::Receiver<()>>>>,
    started: Option<std::sync::mpsc::Sender<()>>,
}
impl crate::send::SubmissionBackend for SubmissionProbe {
    fn submit_message(
        &self,
        _: &str,
        request: &ComposeRequest,
    ) -> Result<(), crate::send::SubmissionBackendError> {
        self.calls.lock().unwrap().push(request.clone());
        if let Some(started) = &self.started {
            started.send(()).unwrap();
        }
        if let Some(block) = &self.block {
            block
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
        }
        if self.fail {
            Err(crate::send::SubmissionBackendError {
                backend: "synthetic",
                reason: "unconfirmed".into(),
            })
        } else {
            Ok(())
        }
    }
}
#[derive(Clone)]
struct AppendProbe {
    calls: Arc<Mutex<Vec<MessageAppendRequest>>>,
    fail: bool,
}
impl MessageAppendBackend for AppendProbe {
    fn append_message(
        &self,
        _: &str,
        request: &MessageAppendRequest,
    ) -> Result<(), crate::mailbox::MailboxBackendError> {
        self.calls.lock().unwrap().push(request.clone());
        if self.fail {
            Err(crate::mailbox::MailboxBackendError {
                backend: "synthetic",
                reason: "unconfirmed".into(),
            })
        } else {
            Ok(())
        }
    }
}
fn probes(fail_submission: bool, fail_append: bool) -> (SubmissionProbe, AppendProbe) {
    (
        SubmissionProbe {
            calls: Arc::default(),
            fail: fail_submission,
            block: None,
            started: None,
        },
        AppendProbe {
            calls: Arc::default(),
            fail: fail_append,
        },
    )
}

#[test]
fn runtime_preparation_refusal_audits_only_finite_stage_and_never_dispatches() {
    let fixture = Fixture::new();
    let session = validated_session();
    let (_, draft) = fixture.save();
    let intent = crate::send_journal::intent_for_draft(
        &session.record.canonical_username,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (submission, append) = probes(false, false);
    let service = SubmissionService::new(submission.clone());
    let mut selected = send_request(&intent, &draft);
    selected.protection.sign = true;
    selected.protection.binding_revision = Some(0);
    let context = test_context();
    let result = fixture.gateway.send_message_with_backends(
        &context, &session, selected, &service, &append,
    );
    assert!(matches!(result.decision,
        BrowserSendDecision::Denied { ref public_reason, .. }
            if public_reason == "openpgp_inventory_unavailable"));
    assert!(submission.calls.lock().unwrap().is_empty());
    assert!(append.calls.lock().unwrap().is_empty());
    let events = result.audit_events.iter()
        .filter(|event| event.action == "send_preparation_refused")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    let event = events[0];
    assert_eq!(event.category, EventCategory::Submission);
    assert!(event.fields.iter().any(|field| field.key == "stage" && field.value == "pre_dispatch"));
    assert!(event.fields.iter().any(|field| field.key == "reason" && field.value == "openpgp_inventory_unavailable"));
    assert!(event.fields.iter().any(|field| field.key == "request_id" && field.value == context.request_id));
    assert!(event.fields.iter().any(|field| field.key == "session_ref"));
    assert!(!event.fields.iter().any(|field| matches!(field.key, "session_id" | "to" | "subject" | "body")));
    assert_eq!(send_preparation_audit_reason("untrusted future value"), "other");
}
#[test]
fn runtime_saved_handoff_replays_without_backend_or_append_and_cleanup_is_qualified() {
    for (fail_submission, fail_append) in [(false, false), (false, true), (true, false)] {
        let fixture = Fixture::new();
        let gateway = &fixture.gateway;
        let session = validated_session();
        let (original, draft) = fixture.save();
        let intent = crate::send_journal::intent_for_draft(
            &session.record.canonical_username,
            &draft.draft_id,
            draft.revision.unwrap(),
            draft.updated_at,
        )
        .unwrap();
        let (submission, append) = probes(fail_submission, fail_append);
        let service = SubmissionService::new(submission.clone());
        let first = gateway.send_message_with_backends(
            &test_context(),
            &session,
            send_request(&intent, &draft),
            &service,
            &append,
        );
        let repeated = gateway.send_message_with_backends(
            &test_context(),
            &session,
            send_request(&intent, &draft),
            &service,
            &append,
        );
        assert_eq!(first.decision, repeated.decision);
        let BrowserSendRecoveryDecision::Available(snapshot) =
            gateway.read_send_recovery(&session, &intent)
        else {
            panic!("owned exact snapshot")
        };
        assert_eq!(
            snapshot.expires_at - snapshot.created_at,
            crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS
        );
        assert_eq!(*snapshot.request, submission.calls.lock().unwrap()[0]);
        let mut foreign = session.clone();
        foreign.record.canonical_username = "foreign@example.test".into();
        assert!(matches!(
            gateway.read_send_recovery(&foreign, &intent),
            BrowserSendRecoveryDecision::Missing
        ));

        assert_eq!(submission.calls.lock().unwrap().len(), 1);
        assert_eq!(
            append.calls.lock().unwrap().len(),
            usize::from(!fail_submission)
        );
        if !fail_submission {
            let expected = build_submission_message(
                &session.record.canonical_username,
                &submission.calls.lock().unwrap()[0],
            )
            .unwrap();
            assert_eq!(append.calls.lock().unwrap()[0].message, expected);
            assert!(!String::from_utf8_lossy(&expected).contains("Bcc:"));
        }
        let mut old = send_request(&original, &draft);
        old.draft_id = None;
        old.draft_revision = None;
        assert!(matches!(
            gateway
                .send_message_with_backends(&test_context(), &session, old, &service, &append)
                .decision,
            BrowserSendDecision::DraftSaved {
                save_confirmed: true,
                ..
            }
        ));
        assert!(matches!(
            gateway
                .save_draft_impl(
                    &test_context(),
                    &session,
                    save_request(&original, None, None)
                )
                .decision,
            BrowserDraftSaveDecision::Denied { .. }
        ));
        assert!(matches!(
            gateway
                .set_draft_star_impl(
                    &test_context(),
                    &session,
                    &draft.draft_id,
                    draft.revision.unwrap(),
                    true
                )
                .decision,
            BrowserDraftSaveDecision::Denied { .. }
        ));
        assert!(matches!(
            gateway
                .delete_draft_impl(
                    &test_context(),
                    &session,
                    &draft.draft_id,
                    draft.revision.unwrap()
                )
                .decision,
            BrowserDraftDeleteDecision::Denied { .. }
        ));
        assert!(gateway
            .cleanup_submitted_draft_impl(
                &session.record.canonical_username,
                &draft.draft_id,
                draft.revision.unwrap(),
                &original,
                gateway.send_clock()
            )
            .is_err());
        let cleanup = gateway.cleanup_submitted_draft_impl(
            &session.record.canonical_username,
            &draft.draft_id,
            draft.revision.unwrap(),
            &intent,
            gateway.send_clock(),
        );
        if fail_submission || fail_append {
            assert!(cleanup.is_err());
        } else {
            assert!(cleanup.unwrap());
        }
        assert_eq!(
            gateway
                .build_draft_store()
                .load(
                    &session.record.canonical_username,
                    &draft.draft_id,
                    gateway.send_clock()
                )
                .unwrap()
                .is_some(),
            fail_submission || fail_append
        );
        assert_eq!(submission.calls.lock().unwrap().len(), 1);
    }
}
#[test]
fn runtime_dispatch_blocks_save_star_list_load_and_public_delete() {
    let fixture = Fixture::new();
    let (original, draft) = fixture.save();
    let gateway = fixture.gateway.clone();
    let session = validated_session();
    let intent = crate::send_journal::intent_for_draft(
        &session.record.canonical_username,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let (mut submission, append) = probes(false, false);
    let (started, ready) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    submission.started = Some(started);
    submission.block = Some(Arc::new(Mutex::new(wait)));
    let sender = gateway.clone();
    let owned_draft = draft.clone();
    let owned_intent = intent.clone();
    let thread = std::thread::spawn(move || {
        sender.send_message_with_backends(
            &test_context(),
            &validated_session(),
            send_request(&owned_intent, &owned_draft),
            &SubmissionService::new(submission),
            &append,
        )
    });
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        gateway
            .save_draft_impl(
                &test_context(),
                &session,
                save_request(&intent, Some(&draft.draft_id), draft.revision)
            )
            .decision,
        BrowserDraftSaveDecision::Denied { .. }
    ));
    assert!(matches!(
        gateway
            .save_draft_impl(
                &test_context(),
                &session,
                save_request(&original, None, None)
            )
            .decision,
        BrowserDraftSaveDecision::Denied { .. }
    ));
    assert!(matches!(
        gateway.list_drafts_impl(&test_context(), &session).decision,
        BrowserDraftListDecision::Denied { .. }
    ));
    assert!(matches!(
        gateway
            .load_draft_impl(&test_context(), &session, &draft.draft_id)
            .decision,
        BrowserDraftLoadDecision::Denied { .. }
    ));
    assert!(matches!(
        gateway
            .delete_draft_impl(
                &test_context(),
                &session,
                &draft.draft_id,
                draft.revision.unwrap()
            )
            .decision,
        BrowserDraftDeleteDecision::Denied { .. }
    ));
    release.send(()).unwrap();
    assert!(matches!(
        thread.join().unwrap().decision,
        BrowserSendDecision::Submitted { .. }
    ));
    assert_eq!(
        gateway
            .build_draft_store()
            .load(
                &session.record.canonical_username,
                &draft.draft_id,
                gateway.send_clock()
            )
            .unwrap()
            .unwrap()
            .revision,
        draft.revision
    );
}

#[test]
fn runtime_recovery_storage_failure_consumes_intent_without_submit_or_sent() {
    let fixture = Fixture::new();
    let gateway = &fixture.gateway;
    let session = validated_session();
    let (original, draft) = fixture.save();
    let intent = crate::send_journal::intent_for_draft(
        &session.record.canonical_username,
        &draft.draft_id,
        draft.revision.unwrap(),
        draft.updated_at,
    )
    .unwrap();
    let recovery = gateway.settings_dir.join("send-recovery");
    std::fs::create_dir_all(&recovery).unwrap();
    std::fs::write(recovery.join("index"), b"synthetic refusal").unwrap();
    let (submission, append) = probes(false, false);
    let service = SubmissionService::new(submission.clone());
    for changed in [false, true] {
        let mut request = send_request(&intent, &draft);
        if changed {
            request.body = "Different attempted body";
            request.recipients = "unfinished recipient <";
        }
        let result = gateway.send_message_with_backends(
            &test_context(),
            &session,
            request,
            &service,
            &append,
        );
        assert_eq!(
            result.decision,
            BrowserSendDecision::RecoveryRefused { capacity: false }
        );
    }
    assert!(submission.calls.lock().unwrap().is_empty());
    assert!(append.calls.lock().unwrap().is_empty());
    assert!(matches!(
        gateway
            .save_draft_impl(
                &test_context(),
                &session,
                save_request(&original, None, None)
            )
            .decision,
        BrowserDraftSaveDecision::Denied { .. }
    ));
}

fn quota_record(gateway: &RuntimeBrowserGateway, number: u64, sizes: &[usize]) {
    let now = gateway.send_clock();
    let session = validated_session();
    let mut record = DraftRecord::new(
        DraftPolicy::default(),
        crate::draft::DraftRecordInput {
            draft_id: format!("{number:032x}"),
            canonical_username: session.record.canonical_username,
            now,
            recipients_text: "bob@example.test".into(),
            cc_text: "".into(),
            bcc_text: "".into(),
            subject: "Quota fixture".into(),
            body: "Exact".into(),
            attachments: vec![],
            source_attachments: None,
        },
    )
    .unwrap();
    for (index, size) in sizes.iter().enumerate() {
        record.request.attachments.push(
            UploadedAttachment::new(
                ComposePolicy::default(),
                format!("file{index}.bin"),
                "application/octet-stream",
                vec![42; *size],
            )
            .unwrap(),
        );
    }
    gateway.build_draft_store().save(&record, now).unwrap();
}
#[test]
fn runtime_combined_count_and_byte_limits_cover_capture_and_normal_save() {
    for count_limit in [true, false] {
        let fixture = Fixture::new();
        let gateway = &fixture.gateway;
        let session = validated_session();
        if count_limit {
            for n in 1..50 {
                quota_record(gateway, n, &[]);
            }
        } else {
            quota_record(
                gateway,
                1,
                &[10 * 1024 * 1024, 10 * 1024 * 1024, 9 * 1024 * 1024],
            );
        }
        let files = if count_limit {
            vec![]
        } else {
            (0..2)
                .map(|n| {
                    UploadedAttachment::new(
                        ComposePolicy::default(),
                        format!("recover{n}.bin"),
                        "application/octet-stream",
                        vec![7; 10 * 1024 * 1024],
                    )
                    .unwrap()
                })
                .collect()
        };
        let intent = crate::send_journal::mint_intent(gateway.send_clock()).unwrap();
        let (submission, append) = probes(false, false);
        let service = SubmissionService::new(submission.clone());
        let mut draft = DraftRecord::new(
            DraftPolicy::default(),
            crate::draft::DraftRecordInput {
                draft_id: "ffffffffffffffffffffffffffffffff".into(),
                canonical_username: session.record.canonical_username.clone(),
                now: gateway.send_clock(),
                recipients_text: "bob@example.test".into(),
                cc_text: "".into(),
                bcc_text: "".into(),
                subject: "Quota attempt".into(),
                body: "Exact".into(),
                attachments: files,
                source_attachments: None,
            },
        )
        .unwrap();
        let mut request = send_request(&intent, &draft);
        request.draft_id = None;
        request.draft_revision = None;
        assert!(matches!(
            gateway
                .send_message_with_backends(&test_context(), &session, request, &service, &append)
                .decision,
            BrowserSendDecision::Submitted { .. }
        ));
        match gateway.list_drafts_impl(&test_context(), &session).decision {
            BrowserDraftListDecision::Listed {
                usage:
                    BrowserDraftStorageUsage::Verified {
                        ordinary_count,
                        ordinary_bytes,
                        recovery_count,
                        recovery_bytes,
                        max_count,
                        max_bytes,
                    },
                ..
            } => {
                assert_eq!(
                    (ordinary_count, recovery_count, max_count, max_bytes),
                    (if count_limit { 49 } else { 1 }, 1, 50, 50 * 1024 * 1024)
                );
                assert!(ordinary_bytes > 0 && recovery_bytes > 0);
                if !count_limit {
                    assert!(ordinary_bytes + recovery_bytes > 49 * 1024 * 1024);
                }
                assert!(ordinary_bytes + recovery_bytes <= max_bytes);
            }
            other => panic!("verified combined projection required: {other:?}"),
        }
        let extra = if count_limit {
            vec![]
        } else {
            vec![UploadedAttachment::new(
                ComposePolicy::default(),
                "extra.bin",
                "application/octet-stream",
                vec![4; 1024 * 1024],
            )
            .unwrap()]
        };
        let next = crate::send_journal::mint_intent(gateway.send_clock()).unwrap();
        let mut save = save_request(&next, None, None);
        save.attachments = &extra;
        let refused = gateway
            .save_draft_impl(&test_context(), &session, save)
            .decision;
        assert!(matches!(
            refused,
            BrowserDraftSaveDecision::Denied { .. } | BrowserDraftSaveDecision::Unconfirmed { .. }
        ));
        assert_eq!(
            gateway
                .build_draft_store()
                .list(&session.record.canonical_username, gateway.send_clock())
                .unwrap()
                .len(),
            if count_limit { 49 } else { 1 }
        );
        draft.request.attachments = extra;
        let next = crate::send_journal::mint_intent(gateway.send_clock()).unwrap();
        let mut request = send_request(&next, &draft);
        request.draft_id = None;
        request.draft_revision = None;
        assert_eq!(
            gateway
                .send_message_with_backends(&test_context(), &session, request, &service, &append)
                .decision,
            BrowserSendDecision::RecoveryRefused { capacity: true }
        );
        assert_eq!(submission.calls.lock().unwrap().len(), 1);
        assert_eq!(append.calls.lock().unwrap().len(), 1);
    }
}

#[test]
fn identity_capture_survives_profile_change_reopen_replay_and_sent_mime_is_identical() {
    use crate::identity_preferences::{IdentityPreferences, IdentityPreferencesStore};
    let f = Fixture::new();
    let account = validated_session().record.canonical_username;
    let profiles = IdentityPreferencesStore::new(&f.gateway.settings_dir);
    let (_, legacy) = f.save();
    let original =
        IdentityPreferences::new("Zoë 🦊, \"Review\"", Some("reply@example.test")).unwrap();
    profiles.save(&account, 0, &original).unwrap();
    let (_, captured) = f.save();
    assert_eq!(captured.request.sender_identity, original);
    assert_eq!(
        legacy.request.sender_identity,
        IdentityPreferences::default()
    );
    let newer = IdentityPreferences::new("Different profile", Some("new@example.test")).unwrap();
    profiles.save(&account, 1, &newer).unwrap();
    let (_, fresh) = f.save();
    assert_eq!(fresh.request.sender_identity, newer);
    let resave = |record: &DraftRecord| {
        let intent = crate::send_journal::intent_for_draft(
            &account,
            &record.draft_id,
            record.revision.unwrap(),
            record.updated_at,
        )
        .unwrap();
        let result = f.gateway.save_draft_impl(
            &test_context(),
            &validated_session(),
            save_request(&intent, Some(&record.draft_id), record.revision),
        );
        assert!(matches!(
            result.decision,
            BrowserDraftSaveDecision::Saved { .. }
        ));
        f.gateway
            .build_draft_store()
            .load(&account, &record.draft_id, f.gateway.send_clock())
            .unwrap()
            .unwrap()
    };
    let captured = resave(&captured);
    let legacy = resave(&legacy);
    assert_eq!(captured.request.sender_identity, original);
    assert_eq!(
        legacy.request.sender_identity,
        IdentityPreferences::default()
    );
    let unsaved_intent = crate::send_journal::mint_intent(f.gateway.send_clock()).unwrap();
    let mut unsaved = send_request(&unsaved_intent, &fresh);
    unsaved.draft_id = None;
    unsaved.draft_revision = None;
    let (direct, append) = probes(false, false);
    assert!(matches!(
        f.gateway
            .send_message_with_backends(
                &test_context(),
                &validated_session(),
                unsaved,
                &SubmissionService::new(direct.clone()),
                &append
            )
            .decision,
        BrowserSendDecision::Submitted { .. }
    ));
    assert_eq!(direct.calls.lock().unwrap()[0].sender_identity, newer);
    for (draft, expected) in [
        (&captured, original.clone()),
        (&legacy, IdentityPreferences::default()),
    ] {
        let intent = crate::send_journal::intent_for_draft(
            &account,
            &draft.draft_id,
            draft.revision.unwrap(),
            draft.updated_at,
        )
        .unwrap();
        let (submission, append) = probes(false, true);
        let service = SubmissionService::new(submission.clone());
        let result = f.gateway.send_message_with_backends(
            &test_context(),
            &validated_session(),
            send_request(&intent, draft),
            &service,
            &append,
        );
        assert!(matches!(
            result.decision,
            BrowserSendDecision::Submitted {
                sent_copy_stored: false,
                receipt_persisted: true
            }
        ));
        let sent = submission.calls.lock().unwrap()[0].clone();
        assert_eq!(sent.sender_identity, expected);
        let smtp = build_submission_message(&account, &sent).unwrap();
        assert_eq!(append.calls.lock().unwrap()[0].message, smtp);
        assert!(!String::from_utf8_lossy(&smtp).contains("Bcc:"));
        let reopened = RuntimeBrowserGateway::for_test(&f.root);
        let BrowserSendRecoveryDecision::Available(snapshot) =
            reopened.read_send_recovery(&validated_session(), &intent)
        else {
            panic!("verified snapshot required")
        };
        assert_eq!(snapshot.request.sender_identity, expected);
        assert_eq!(
            build_submission_message(&account, &snapshot.request).unwrap(),
            smtp
        );
        let retry = reopened.send_message_with_backends(
            &test_context(),
            &validated_session(),
            send_request(&intent, draft),
            &service,
            &append,
        );
        assert!(matches!(
            retry.decision,
            BrowserSendDecision::Submitted { .. }
        ));
        assert_eq!(submission.calls.lock().unwrap().len(), 1);
        assert_eq!(append.calls.lock().unwrap().len(), 1);
    }
}
