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
        let store = self.build_draft_store();
        let now = SystemTimeProvider.unix_timestamp();
        let result = (|| {
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
        match store.list(&validated_session.record.canonical_username, now) {
            Ok(drafts) => BrowserDraftListOutcome {
                decision: BrowserDraftListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    drafts,
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
        match store.load(&validated_session.record.canonical_username, draft_id, now) {
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
        let store = self.build_draft_store();
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
        record.request.reply_thread = request.reply_thread.cloned();
        if let Some(existing) = existing {
            record.created_at = existing.created_at;
            record.revision = existing.revision;
            record.starred = existing.starred;
            record.request.reply_thread = existing.request.reply_thread;
        }

        match store.save(&record, now) {
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
        match store.delete(
            &validated_session.record.canonical_username,
            draft_id,
            expected_revision,
        ) {
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
    if error.reason.contains("revision") {
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
    if error.reason.contains("revision") {
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
