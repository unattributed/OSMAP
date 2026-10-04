use super::*;
use crate::logging::audit_session_ref;
use crate::totp::TimeProvider;

impl RuntimeBrowserGateway {
    pub(super) fn set_draft_star_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
        starred: bool,
    ) -> BrowserDraftSaveOutcome {
        let now = SystemTimeProvider.unix_timestamp();
        let result = (|| {
            let journal = self.send_journal();
            let guard = journal
                .account_guard(&session.record.canonical_username, now)
                .map_err(journal_draft_error)?;
            let policy =
                crate::send_recovery::SendRecovery::new(self.settings_dir.join("send-recovery"))
                    .draft_policy(&session.record.canonical_username, now)
                    .map_err(|_| crate::draft::DraftError {
                        reason: "send_attempt_paused".into(),
                    })?;
            let store = FileDraftStore::new(self.draft_dir.clone(), policy);
            let mut draft = store
                .load(&session.record.canonical_username, draft_id, now)?
                .ok_or_else(|| crate::draft::DraftError {
                    reason: "draft revision is stale".into(),
                })?;
            if draft.revision != Some(expected_revision) {
                return Err(crate::draft::DraftError {
                    reason: "draft revision is stale".into(),
                });
            }
            let intent = guard.draft_intent(&draft).map_err(journal_draft_error)?;
            guard
                .require_unconsumed(&intent)
                .map_err(journal_draft_error)?;
            draft.starred = starred;
            store.save(&draft, now)
        })();
        match result {
            Ok(()) => BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Saved {
                    draft_id: draft_id.into(),
                },
                audit_events: vec![draft_info_event(
                    "draft_star_updated",
                    "draft star updated",
                    context,
                    session,
                )],
            },
            Err(error) if error.save_unconfirmed() => BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Unconfirmed {
                    draft_id: draft_id.into(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_star_unconfirmed",
                    "draft star outcome unconfirmed",
                    context,
                    session,
                )],
            },
            Err(error) => BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Denied {
                    public_reason: draft_public_reason(&error).into(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_star_refused",
                    "draft star change refused",
                    context,
                    session,
                )
                .with_field("reason", draft_error_label(&error))],
            },
        }
    }

    pub(super) fn send_journal(&self) -> crate::send_journal::SendJournal {
        crate::send_journal::SendJournal::new(self.settings_dir.join("send-journal"))
    }

    pub(super) fn build_draft_store(&self) -> FileDraftStore {
        FileDraftStore::new(self.draft_dir.clone(), DraftPolicy::default())
    }

    pub(super) fn list_drafts_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserDraftListOutcome {
        let store = self.build_draft_store();
        let now = SystemTimeProvider.unix_timestamp();
        let result = (|| {
            let journal = self.send_journal();
            let guard = journal
                .account_guard(&validated_session.record.canonical_username, now)
                .map_err(journal_draft_error)?;
            let drafts = store.list(&validated_session.record.canonical_username, now)?;
            let recovery =
                crate::send_recovery::SendRecovery::new(self.settings_dir.join("send-recovery"))
                    .storage_usage(&validated_session.record.canonical_username, now);
            let (states, usage) =
                super::super::http_browser::project_drafts(&guard, &drafts, recovery);
            Ok((drafts, states, usage))
        })();
        match result {
            Ok((drafts, states, usage)) => BrowserDraftListOutcome {
                decision: BrowserDraftListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    drafts,
                    states,
                    usage,
                },
                audit_events: vec![draft_info_event(
                    "drafts_listed",
                    "drafts listed",
                    context,
                    validated_session,
                )],
            },
            Err(error) => BrowserDraftListOutcome {
                decision: BrowserDraftListDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_list_failed",
                    "draft list failed",
                    context,
                    validated_session,
                )
                .with_field("reason", draft_error_label(&error))],
            },
        }
    }

    pub(super) fn load_draft_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
    ) -> BrowserDraftLoadOutcome {
        let store = self.build_draft_store();
        let now = SystemTimeProvider.unix_timestamp();
        let result = (|| {
            let journal = self.send_journal();
            let _guard = journal
                .account_guard(&validated_session.record.canonical_username, now)
                .map_err(journal_draft_error)?;
            store.load(&validated_session.record.canonical_username, draft_id, now)
        })();
        match result {
            Ok(Some(draft)) => BrowserDraftLoadOutcome {
                decision: BrowserDraftLoadDecision::Loaded {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    draft: Box::new(draft.clone()),
                },
                audit_events: vec![draft_info_event(
                    "draft_loaded",
                    "draft loaded",
                    context,
                    validated_session,
                )
                .with_field("draft_ref", audit_session_ref(&draft.draft_id))
                .with_field(
                    "attachment_count",
                    draft.request.attachments.len().to_string(),
                )],
            },
            Ok(None) => BrowserDraftLoadOutcome {
                decision: BrowserDraftLoadDecision::NotFound,
                audit_events: vec![draft_warn_event(
                    "draft_not_found",
                    "draft not found",
                    context,
                    validated_session,
                )],
            },
            Err(error) => BrowserDraftLoadOutcome {
                decision: BrowserDraftLoadDecision::Denied {
                    public_reason: draft_public_reason(&error).to_string(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_load_failed",
                    "draft load failed",
                    context,
                    validated_session,
                )
                .with_field("reason", draft_error_label(&error))],
            },
        }
    }

    pub(super) fn save_draft_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserDraftSaveRequest<'_>,
    ) -> BrowserDraftSaveOutcome {
        let now = SystemTimeProvider.unix_timestamp();
        let canonical_username = validated_session.record.canonical_username.clone();
        let draft_id = match request.draft_id {
            Some(value) if !value.trim().is_empty() => value.to_string(),
            _ => match crate::draft::generate_draft_id() {
                Ok(generated) => generated,
                Err(error) => {
                    return BrowserDraftSaveOutcome {
                        decision: BrowserDraftSaveDecision::Denied {
                            public_reason: "temporarily_unavailable".to_string(),
                        },
                        audit_events: vec![draft_warn_event(
                            "draft_id_generation_failed",
                            "draft id generation failed",
                            context,
                            validated_session,
                        )
                        .with_field("reason", draft_error_label(&error))],
                    };
                }
            },
        };

        let journal = self.send_journal();
        let mut guard = match journal.account_guard(&canonical_username, now) {
            Ok(guard) => guard,
            Err(_) => return paused_draft_save(),
        };
        if guard.require_unconsumed(request.send_intent).is_err() {
            return paused_draft_save();
        }
        let policy =
            match crate::send_recovery::SendRecovery::new(self.settings_dir.join("send-recovery"))
                .draft_policy(&validated_session.record.canonical_username, now)
            {
                Ok(value) => value,
                Err(_) => return paused_draft_save(),
            };
        let store = FileDraftStore::new(self.draft_dir.clone(), policy);
        // Existing IDs never depend on a preference or migrate on a save.
        let store = if request.draft_id.is_none() {
            match crate::draft_location::Store::new(&self.settings_dir).load(&canonical_username) {
                Ok(saved) => store.with_new_location(saved.location),
                Err(_) => {
                    return BrowserDraftSaveOutcome {
                        decision: BrowserDraftSaveDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        },
                        audit_events: vec![draft_warn_event(
                            "draft_save_denied",
                            "draft save denied",
                            context,
                            validated_session,
                        )],
                    }
                }
            }
        } else {
            store
        };
        if request.draft_id.is_none() && store.require_new_location(&canonical_username).is_err() {
            return BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Denied {
                    public_reason: "temporarily_unavailable".into(),
                },
                audit_events: vec![],
            };
        }
        let existing = match store.load(&canonical_username, &draft_id, now) {
            Ok(existing) => existing,
            Err(error) => {
                return BrowserDraftSaveOutcome {
                    decision: BrowserDraftSaveDecision::Denied {
                        public_reason: draft_public_reason(&error).to_string(),
                    },
                    audit_events: vec![draft_warn_event(
                        "draft_save_existing_load_failed",
                        "draft save failed while loading existing draft",
                        context,
                        validated_session,
                    )
                    .with_field("reason", draft_error_label(&error))],
                };
            }
        };

        if existing.as_ref().and_then(|draft| draft.revision) != request.expected_revision
            || request.draft_id.is_some() != existing.is_some()
        {
            return BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Denied {
                    public_reason: "draft_conflict".into(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_stale_save",
                    "stale draft save refused",
                    context,
                    validated_session,
                )],
            };
        }

        if let Some(draft) = &existing {
            let Ok(intent) = guard.draft_intent(draft) else {
                return paused_draft_save();
            };
            if intent != request.send_intent || guard.require_unconsumed(&intent).is_err() {
                return paused_draft_save();
            }
        }

        let mut persisted_attachments = match crate::draft_content::retain_saved_attachments(
            existing
                .as_ref()
                .map(|draft| draft.request.attachments.as_slice())
                .unwrap_or_default(),
            request.removed_attachment_indices,
        ) {
            Ok(attachments) => attachments,
            Err(_) => {
                return BrowserDraftSaveOutcome {
                    decision: BrowserDraftSaveDecision::Denied {
                        public_reason: "invalid_request".into(),
                    },
                    audit_events: vec![draft_warn_event(
                        "draft_attachment_selection_refused",
                        "saved attachment selection refused",
                        context,
                        validated_session,
                    )],
                }
            }
        };
        persisted_attachments.extend_from_slice(request.attachments);

        let mut record = match DraftRecord::new(
            DraftPolicy::default(),
            DraftRecordInput {
                draft_id: draft_id.clone(),
                canonical_username: canonical_username.clone(),
                now,
                recipients_text: request.recipients.to_string(),
                cc_text: request.cc_recipients.to_string(),
                bcc_text: request.bcc_recipients.to_string(),
                subject: request.subject.to_string(),
                body: request.body.to_string(),
                attachments: persisted_attachments,
                source_attachments: request.source_attachments.cloned(),
            },
        ) {
            Ok(record) => record,
            Err(error) => {
                return BrowserDraftSaveOutcome {
                    decision: BrowserDraftSaveDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![draft_warn_event(
                        "draft_save_request_rejected",
                        "draft save request validation failed",
                        context,
                        validated_session,
                    )
                    .with_field("reason", draft_error_label(&error))],
                };
            }
        };
        record.request.sender_identity = match existing.as_ref() {
            Some(saved) => saved.request.sender_identity.clone(),
            None => match self.load_identity_preferences(context, validated_session) {
                Ok(profile) => profile.preferences,
                Err(_) => {
                    return BrowserDraftSaveOutcome {
                        decision: BrowserDraftSaveDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        },
                        audit_events: vec![],
                    }
                }
            },
        };
        record.request.body_format = request.body_format;
        record.request.protection = request.protection;
        record.request.reply_thread = request.reply_thread.cloned();
        if let Some(existing) = existing {
            record.created_at = existing.created_at;
            record.revision = existing.revision;
            record.starred = existing.starred;
            record.request.reply_thread = existing.request.reply_thread;
        }

        let new_draft = request.draft_id.is_none();
        if new_draft
            && guard
                .begin_draft_save(request.send_intent, &draft_id)
                .is_err()
        {
            return paused_draft_save();
        }
        let save_result = store.save(&record, now);
        if new_draft
            && (save_result.is_err()
                || guard
                    .finish_draft_save(request.send_intent, &draft_id)
                    .is_err())
        {
            return BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Unconfirmed { draft_id },
                audit_events: vec![draft_warn_event(
                    "draft_handoff_unconfirmed",
                    "draft handoff save unconfirmed; no submission performed",
                    context,
                    validated_session,
                )],
            };
        }
        match save_result {
            Ok(()) => BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Saved {
                    draft_id: record.draft_id.clone(),
                },
                audit_events: vec![draft_info_event(
                    "draft_saved",
                    "draft saved",
                    context,
                    validated_session,
                )
                .with_field("draft_ref", audit_session_ref(&record.draft_id))
                .with_field(
                    "recipient_count",
                    record.request.total_recipient_count().to_string(),
                )
                .with_field(
                    "attachment_count",
                    record.request.attachments.len().to_string(),
                )],
            },
            Err(error) if error.save_unconfirmed() => BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Unconfirmed {
                    draft_id: record.draft_id.clone(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_save_unconfirmed",
                    "draft save outcome unconfirmed",
                    context,
                    validated_session,
                )],
            },
            Err(error) => BrowserDraftSaveOutcome {
                decision: BrowserDraftSaveDecision::Denied {
                    public_reason: draft_public_reason(&error).to_string(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_save_failed",
                    "draft save failed",
                    context,
                    validated_session,
                )
                .with_field("reason", draft_error_label(&error))],
            },
        }
    }

    pub(super) fn delete_draft_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
    ) -> BrowserDraftDeleteOutcome {
        let store = self.build_draft_store();
        let now = SystemTimeProvider.unix_timestamp();
        let result = (|| {
            let journal = self.send_journal();
            let guard = journal
                .account_guard(&validated_session.record.canonical_username, now)
                .map_err(journal_draft_error)?;
            let Some(draft) =
                store.load(&validated_session.record.canonical_username, draft_id, now)?
            else {
                return Ok(false);
            };
            let intent = guard.draft_intent(&draft).map_err(journal_draft_error)?;
            guard
                .require_unconsumed(&intent)
                .map_err(journal_draft_error)?;
            store.delete(
                &validated_session.record.canonical_username,
                draft_id,
                expected_revision,
            )
        })();
        match result {
            Ok(true) => BrowserDraftDeleteOutcome {
                decision: BrowserDraftDeleteDecision::Deleted,
                audit_events: vec![draft_info_event(
                    "draft_deleted",
                    "draft deleted",
                    context,
                    validated_session,
                )
                .with_field("draft_ref", audit_session_ref(draft_id))],
            },
            Ok(false) => BrowserDraftDeleteOutcome {
                decision: BrowserDraftDeleteDecision::NotFound,
                audit_events: vec![draft_warn_event(
                    "draft_delete_not_found",
                    "draft delete target not found",
                    context,
                    validated_session,
                )],
            },
            Err(error) => BrowserDraftDeleteOutcome {
                decision: BrowserDraftDeleteDecision::Denied {
                    public_reason: draft_public_reason(&error).to_string(),
                },
                audit_events: vec![draft_warn_event(
                    "draft_delete_failed",
                    "draft delete failed",
                    context,
                    validated_session,
                )
                .with_field("reason", draft_error_label(&error))],
            },
        }
    }
    /// Internal receipt-qualified cleanup; never exposed as public discard.
    pub(super) fn cleanup_submitted_draft_impl(
        &self,
        account: &str,
        draft_id: &str,
        revision: u64,
        intent: &str,
        now: u64,
    ) -> Result<bool, crate::draft::DraftError> {
        let journal = self.send_journal();
        let guard = journal
            .account_guard(account, now)
            .map_err(journal_draft_error)?;
        guard
            .require_accepted_for_cleanup(intent)
            .map_err(journal_draft_error)?;
        let store = self.build_draft_store();
        let Some(draft) = store.load(account, draft_id, now)? else {
            return Ok(false);
        };
        if draft.revision != Some(revision)
            || guard.draft_intent(&draft).map_err(journal_draft_error)? != intent
        {
            return Err(crate::draft::DraftError {
                reason: "draft revision is stale".into(),
            });
        }
        store.delete(account, draft_id, revision)
    }
}

fn draft_info_event(
    action: &'static str,
    message: &'static str,
    context: &AuthenticationContext,
    validated_session: &ValidatedSession,
) -> LogEvent {
    build_http_info_event(action, message, context)
        .with_field(
            "canonical_username",
            validated_session.record.canonical_username.clone(),
        )
        .with_field(
            "session_ref",
            audit_session_ref(&validated_session.record.session_id),
        )
}

fn draft_warn_event(
    action: &'static str,
    message: &'static str,
    context: &AuthenticationContext,
    validated_session: &ValidatedSession,
) -> LogEvent {
    build_http_warning_event(action, message, context)
        .with_field(
            "canonical_username",
            validated_session.record.canonical_username.clone(),
        )
        .with_field(
            "session_ref",
            audit_session_ref(&validated_session.record.session_id),
        )
}

fn draft_public_reason(error: &crate::draft::DraftError) -> &'static str {
    if error.reason == "send_attempt_paused" {
        "send_attempt_paused"
    } else if error.reason.contains("revision") {
        "draft_conflict"
    } else if error.reason.contains("quota") {
        "draft_quota_exceeded"
    } else if error.reason == "draft store busy" {
        "draft_busy"
    } else if error.reason.contains("maximum")
        || error.reason.contains("invalid")
        || error.reason.contains("must")
        || error.reason.contains("exceeded")
    {
        "invalid_request"
    } else {
        "temporarily_unavailable"
    }
}

fn draft_error_label(error: &crate::draft::DraftError) -> &'static str {
    if error.reason == "send_attempt_paused" {
        "send_attempt_paused"
    } else if error.reason.contains("revision") {
        "stale_revision"
    } else if error.reason.contains("quota") {
        "quota_exceeded"
    } else if error.reason.contains("maximum") || error.reason.contains("exceeded") {
        "limit_exceeded"
    } else if error.reason.contains("invalid") || error.reason.contains("must") {
        "invalid_request"
    } else {
        "store_failure"
    }
}

fn journal_draft_error(_: crate::send_journal::JournalError) -> crate::draft::DraftError {
    crate::draft::DraftError {
        reason: "send_attempt_paused".into(),
    }
}
fn paused_draft_save() -> BrowserDraftSaveOutcome {
    BrowserDraftSaveOutcome {
        decision: BrowserDraftSaveDecision::Denied {
            public_reason: "send_attempt_paused".into(),
        },
        audit_events: vec![],
    }
}

#[cfg(test)]
mod draft_state_tests {
    use super::*;
    use crate::draft::{DraftRecord, DraftRecordInput};
    use crate::send_journal::{intent_for_draft, AttemptOutcome};
    use std::sync::{Arc, Barrier};
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
                "osmap-draft-state-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            let context = AuthenticationContext::new(
                AuthenticationPolicy::default(),
                "draft-state-test",
                "127.0.0.1",
                "Synthetic/Test",
            )
            .unwrap();
            let session = ValidatedSession {
                record: crate::session::SessionRecord {
                    session_id: "synthetic-session".into(),
                    csrf_token: "synthetic-csrf".into(),
                    canonical_username: "alice@example.com".into(),
                    issued_at: 1,
                    expires_at: u64::MAX,
                    last_seen_at: 1,
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
                context,
                now: SystemTimeProvider.unix_timestamp(),
            }
        }
        fn draft(&self) -> DraftRecord {
            let store = self.gateway.build_draft_store();
            let record = DraftRecord::new(
                DraftPolicy::default(),
                DraftRecordInput {
                    draft_id: crate::draft::generate_draft_id().unwrap(),
                    canonical_username: self.session.record.canonical_username.clone(),
                    now: self.now,
                    recipients_text: "bob@example.com".into(),
                    cc_text: String::new(),
                    bcc_text: String::new(),
                    subject: "Synthetic draft".into(),
                    body: "Exact draft source".into(),
                    attachments: vec![],
                    source_attachments: None,
                },
            )
            .unwrap();
            store.save(&record, self.now).unwrap();
            store
                .load(&record.canonical_username, &record.draft_id, self.now)
                .unwrap()
                .unwrap()
        }
        fn list(
            &self,
        ) -> (
            Vec<DraftSummary>,
            Vec<BrowserDraftState>,
            BrowserDraftStorageUsage,
        ) {
            match self
                .gateway
                .list_drafts_impl(&self.context, &self.session)
                .decision
            {
                BrowserDraftListDecision::Listed {
                    drafts,
                    states,
                    usage,
                    ..
                } => (drafts, states, usage),
                other => panic!("unexpected list: {other:?}"),
            }
        }
        fn intent(&self, draft: &DraftRecord) -> String {
            intent_for_draft(
                &draft.canonical_username,
                &draft.draft_id,
                draft.revision.unwrap(),
                draft.updated_at,
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn runtime_projection_reports_exact_revision_attempt_and_combined_usage_without_body_reload() {
        let f = Fixture::new();
        let draft = f.draft();
        let intent = f.intent(&draft);
        let (rows, states, usage) = f.list();
        assert_eq!(states[0].state, BrowserDraftEditState::Editable);
        assert_eq!(states[0].revision, draft.revision.unwrap());
        assert!(matches!(
            usage,
            BrowserDraftStorageUsage::Verified {
                ordinary_count: 1,
                recovery_count: 0,
                ..
            }
        ));
        let request = crate::send::ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Attempt subject",
            "Prepared source differs",
        )
        .unwrap();
        let journal = f.gateway.send_journal();
        journal
            .execute_prepared(
                &draft.canonical_username,
                &intent,
                f.now,
                |_| Ok::<_, ()>(request.clone()),
                |prepared| {
                    crate::send_recovery::SendRecovery::new(
                        f.gateway.settings_dir.join("send-recovery"),
                    )
                    .capture(
                        &journal,
                        &f.gateway.build_draft_store(),
                        &draft.canonical_username,
                        &intent,
                        prepared,
                        f.now,
                    )
                    .unwrap();
                    AttemptOutcome::Accepted {
                        sent_copy_stored: false,
                    }
                },
            )
            .unwrap();
        let (after, states, usage) = f.list();
        assert_eq!(rows, after);
        assert_eq!(
            states[0].state,
            BrowserDraftEditState::Attempted {
                receipt_intent: intent.clone()
            }
        );
        match usage {
            BrowserDraftStorageUsage::Verified {
                ordinary_count,
                ordinary_bytes,
                recovery_count,
                recovery_bytes,
                max_count,
                max_bytes,
            } => {
                assert_eq!(
                    (ordinary_count, recovery_count, max_count, max_bytes),
                    (1, 1, 50, 50 * 1024 * 1024)
                );
                assert_eq!(ordinary_bytes, rows[0].storage_bytes);
                assert!(recovery_bytes > 0);
            }
            _ => panic!("usage unknown"),
        }
        assert!(matches!(
            f.gateway
                .set_draft_star_impl(
                    &f.context,
                    &f.session,
                    &draft.draft_id,
                    draft.revision.unwrap(),
                    true
                )
                .decision,
            BrowserDraftSaveDecision::Denied { .. }
        ));
        let mut foreign = f.session.clone();
        foreign.record.canonical_username = "bob@example.com".into();
        assert!(
            matches!(f.gateway.list_drafts_impl(&f.context,&foreign).decision,BrowserDraftListDecision::Listed{drafts,usage:BrowserDraftStorageUsage::Verified{ordinary_count:0,recovery_count:0,..},..} if drafts.is_empty())
        );
    }

    #[test]
    fn runtime_projection_serializes_with_attempt_and_rechecks_new_revision() {
        let f = Fixture::new();
        let mut draft = f.draft();
        let old_intent = f.intent(&draft);
        draft.request.body = "new revision".into();
        f.gateway.build_draft_store().save(&draft, f.now).unwrap();
        let current = f
            .gateway
            .build_draft_store()
            .load(&draft.canonical_username, &draft.draft_id, f.now)
            .unwrap()
            .unwrap();
        let request = crate::send::ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Synthetic",
            "Body",
        )
        .unwrap();
        f.gateway
            .send_journal()
            .execute_prepared(
                &draft.canonical_username,
                &old_intent,
                f.now,
                |_| Ok::<_, ()>(request.clone()),
                |_| AttemptOutcome::Unconfirmed,
            )
            .unwrap();
        assert_eq!(f.list().1[0].state, BrowserDraftEditState::Editable);
        assert_eq!(f.list().1[0].revision, current.revision.unwrap());
        let entered = Arc::new(Barrier::new(2));
        let finish = Arc::new(Barrier::new(2));
        let j = f.gateway.send_journal();
        let intent = f.intent(&current);
        let now = f.now;
        let e = entered.clone();
        let end = finish.clone();
        let thread = std::thread::spawn(move || {
            j.execute_prepared(
                "alice@example.com",
                &intent,
                now,
                |_| Ok::<_, ()>(request),
                |_| {
                    e.wait();
                    end.wait();
                    AttemptOutcome::Unconfirmed
                },
            )
        });
        entered.wait();
        let blocked = f.gateway.list_drafts_impl(&f.context, &f.session);
        finish.wait();
        thread.join().unwrap().unwrap();
        assert!(matches!(
            blocked.decision,
            BrowserDraftListDecision::Denied { .. }
        ));
        assert_eq!(
            f.list().1[0].state,
            BrowserDraftEditState::Paused {
                receipt_intent: f.intent(&current)
            }
        );
    }

    #[test]
    fn runtime_projection_refuses_corrupt_recovery_usage_and_corrupt_journal() {
        let f = Fixture::new();
        f.draft();
        let index = crate::private_account_file::PrivateAccountFile::new(
            f.gateway.settings_dir.join("send-recovery/index"),
            "send-recovery-v1",
            1024 * 1024,
        );
        index
            .lock("alice@example.com")
            .unwrap()
            .write(b"corrupt")
            .unwrap();
        let (_, states, usage) = f.list();
        assert_eq!(usage, BrowserDraftStorageUsage::Unknown);
        assert_eq!(states[0].state, BrowserDraftEditState::Unknown);
        let j = f.gateway.send_journal();
        let guard = j.account_guard("alice@example.com", f.now).unwrap();
        assert!(matches!(
            f.gateway.list_drafts_impl(&f.context, &f.session).decision,
            BrowserDraftListDecision::Denied { .. }
        ));
        drop(guard);
        let journal_file = crate::private_account_file::PrivateAccountFile::new(
            f.gateway.settings_dir.join("send-journal"),
            "osmap-send-journal-v1",
            1024 * 1024,
        );
        journal_file
            .lock("alice@example.com")
            .unwrap()
            .write(b"corrupt")
            .unwrap();
        assert!(matches!(
            f.gateway.list_drafts_impl(&f.context, &f.session).decision,
            BrowserDraftListDecision::Denied { .. }
        ));
    }
}
