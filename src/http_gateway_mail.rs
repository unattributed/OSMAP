use super::*;
use crate::totp::TimeProvider;

use crate::config::LogLevel;
use crate::logging::EventCategory;
use crate::mailbox::{validate_message_search_query, MessageSearchBackend};
use std::time::{Duration, Instant};

fn mailbox_is_browser_visible(mailbox_name: &str) -> bool {
    matches!(
        mailbox_name,
        "INBOX" | "Archive" | "Drafts" | "Junk" | "Sent" | "Trash"
    ) || mailbox_name.starts_with("INBOX.")
}

fn batch_search_failure_code(error: &crate::mailbox::MailboxBackendError) -> &'static str {
    match error.backend {
        "message-search-parser" | "mailbox-parser" => "scope_request_invalid",
        "message-json-parser" => "native_output_rejected",
        "doveadm-message-search" => "native_operation_unavailable",
        "mailbox-helper-config" => "helper_configuration_unavailable",
        "mailbox-helper-client" => "helper_transport_or_response_rejected",
        _ => "backend_operation_refused",
    }
}

fn mailbox_list_contains(mailboxes: &[MailboxEntry], mailbox_name: &str) -> bool {
    mailboxes.iter().any(|mailbox| mailbox.name == mailbox_name)
}

// Called only after submission acceptance. An append error cannot establish
// whether the backend stored the copy, and must never cause another dispatch.
fn store_prepared_sent_copy(
    context: &AuthenticationContext,
    canonical_username: &str,
    request: &ComposeRequest,
    prepared: &crate::protected_submission::PreparedSubmission,
    backend: &impl MessageAppendBackend,
) -> (bool, LogEvent) {
    let append_result = crate::identity::CanonicalUsername::parse(canonical_username)
        .map_err(|_| crate::mailbox::MailboxBackendError {
            backend: "sent-copy-formatter",
            reason: "invalid prepared account".into(),
        })
        .and_then(|account| {
            prepared.validate_for(&account, request).map_err(|_| {
                crate::mailbox::MailboxBackendError {
                    backend: "sent-copy-formatter",
                    reason: "prepared identity mismatch".into(),
                }
            })
        })
        .and_then(|()| MessageAppendRequest::new("Sent", prepared.as_bytes().to_vec()))
        .and_then(|append_request| {
            backend.append_message(canonical_username, &append_request)?;
            Ok(append_request.message.len())
        });
    let (stored, event) = match append_result {
        Ok(message_bytes) => (
            true,
            LogEvent::new(
                LogLevel::Info,
                EventCategory::Submission,
                "sent_copy_stored",
                "outbound message accepted for submission; copy stored in Sent",
            )
            .with_field("message_bytes", message_bytes.to_string()),
        ),
        Err(error) => (
            false,
            LogEvent::new(
                LogLevel::Warn,
                EventCategory::Submission,
                "sent_copy_store_failed",
                "outbound message accepted for submission; Sent copy storage not confirmed",
            )
            .with_field("backend", error.backend),
        ),
    };
    (
        stored,
        event
            .with_field("canonical_username", canonical_username)
            .with_field("mailbox_name", "Sent")
            .with_field("request_id", context.request_id.clone()),
    )
}

#[cfg(test)]
fn store_sent_copy(
    context: &AuthenticationContext,
    canonical_username: &str,
    request: &ComposeRequest,
    backend: &impl MessageAppendBackend,
) -> (bool, LogEvent) {
    let account = crate::identity::CanonicalUsername::parse(canonical_username).unwrap();
    let prepared = crate::protected_submission::prepare(
        &crate::protected_submission::UnavailableCrypto,
        &account,
        request,
        &crate::openpgp_bindings::OperationPlan {
            signer_fingerprint: None,
            recipient_fingerprints: Vec::new(),
            encrypt_to_self: false,
        },
    );
    match prepared {
        Ok(prepared) => {
            store_prepared_sent_copy(context, canonical_username, request, &prepared, backend)
        }
        Err(_) => (
            false,
            LogEvent::new(
                LogLevel::Warn,
                EventCategory::Submission,
                "sent_copy_store_failed",
                "outbound message accepted for submission; Sent copy storage not confirmed",
            )
            .with_field("backend", "sent-copy-formatter")
            .with_field("canonical_username", canonical_username)
            .with_field("request_id", &context.request_id),
        ),
    }
}

pub(super) fn journal_send_decision(
    result: Result<crate::send_journal::JournalResult, crate::send_journal::JournalError>,
) -> BrowserSendDecision {
    match result {
        Ok(crate::send_journal::JournalResult {
            outcome: crate::send_journal::AttemptOutcome::RecoveryRefused { capacity },
            ..
        }) => BrowserSendDecision::RecoveryRefused { capacity },
        Ok(crate::send_journal::JournalResult {
            outcome: crate::send_journal::AttemptOutcome::Accepted { sent_copy_stored },
            receipt_persisted,
            ..
        }) => BrowserSendDecision::Submitted {
            sent_copy_stored,
            receipt_persisted,
        },
        Ok(crate::send_journal::JournalResult {
            outcome:
                crate::send_journal::AttemptOutcome::DraftSaved {
                    draft_id,
                    save_confirmed,
                },
            ..
        }) => BrowserSendDecision::DraftSaved {
            draft_id: crate::send_journal::draft_id_text(&draft_id),
            save_confirmed,
        },
        _ => BrowserSendDecision::Unconfirmed {
            public_reason: "send_attempt_unconfirmed".into(),
        },
    }
}

impl RuntimeBrowserGateway {
    fn expensive_route_deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(self.expensive_request_timeout_secs)
    }

    fn expensive_route_deadline_exceeded(deadline: Instant) -> bool {
        Instant::now() >= deadline
    }

    fn expensive_route_remaining_timeout_secs(deadline: Instant) -> Option<u64> {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining < Duration::from_secs(1) {
            None
        } else {
            Some(remaining.as_secs())
        }
    }

    fn build_message_search_fanout_deadline_event(
        &self,
        context: &AuthenticationContext,
        visible_mailbox_count: usize,
        searched_mailboxes: usize,
    ) -> LogEvent {
        build_http_warning_event(
            "message_search_fanout_deadline_exceeded",
            "all-mailbox search fanout exceeded route deadline",
            context,
        )
        .with_field("route_class", "message_search")
        .with_field(
            "deadline_seconds",
            self.expensive_request_timeout_secs.to_string(),
        )
        .with_field("visible_mailbox_count", visible_mailbox_count.to_string())
        .with_field("searched_mailboxes", searched_mailboxes.to_string())
    }

    /// Builds the current file-backed submission-throttle service.
    pub(super) fn build_submission_throttle_service(
        &self,
    ) -> SubmissionThrottleService<FileLoginThrottleStore, SystemTimeProvider> {
        SubmissionThrottleService::new(
            FileLoginThrottleStore::new(self.submission_throttle_dir.clone()),
            SystemTimeProvider,
            self.submission_throttle_policy,
        )
    }

    /// Builds the current file-backed message-move throttle service.
    pub(super) fn build_message_move_throttle_service(
        &self,
    ) -> MessageMoveThrottleService<FileLoginThrottleStore, SystemTimeProvider> {
        MessageMoveThrottleService::new(
            FileLoginThrottleStore::new(self.message_move_throttle_dir.clone()),
            SystemTimeProvider,
            self.message_move_throttle_policy,
        )
    }

    /// Builds the current send-path service around the local sendmail surface.
    pub(super) fn build_submission_service(
        &self,
    ) -> SubmissionService<SendmailSubmissionBackend<SystemCommandExecutor>> {
        SubmissionService::new(
            SendmailSubmissionBackend::new(SystemCommandExecutor, self.sendmail_path.clone())
                .with_command_timeout_secs(
                    self.expensive_request_timeout_secs
                        .min(crate::auth::DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS),
                ),
        )
    }

    /// Records a non-fatal throttle-store failure so operators can diagnose
    /// missing submission-abuse resistance without crashing the send path.
    pub(super) fn build_submission_throttle_store_error_event(
        &self,
        action: &'static str,
        message: &'static str,
        context: &AuthenticationContext,
        error: &LoginThrottleError,
    ) -> LogEvent {
        LogEvent::new(LogLevel::Warn, EventCategory::Submission, action, message)
            .with_field("reason", throttle_store_error_label(error))
            .with_field("request_id", context.request_id.clone())
            .with_field("remote_addr", context.remote_addr.clone())
            .with_field("user_agent", context.user_agent.clone())
    }

    pub(super) fn list_mailboxes_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome {
        let outcome = MailboxListingService::new(self.build_mailbox_list_backend())
            .list_for_validated_session(context, validated_session);

        match outcome.decision {
            MailboxListingDecision::Listed {
                canonical_username,
                mailboxes,
                ..
            } => BrowserMailboxOutcome {
                decision: BrowserMailboxDecision::Listed {
                    canonical_username,
                    mailboxes,
                },
                audit_events: vec![outcome.audit_event],
            },
            MailboxListingDecision::Denied { public_reason } => BrowserMailboxOutcome {
                decision: BrowserMailboxDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    pub(super) fn list_messages_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
    ) -> BrowserMessageListOutcome {
        let request = match MessageListRequest::new(MessageListPolicy::default(), mailbox_name) {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageListOutcome {
                    decision: BrowserMessageListDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_list_request_rejected",
                        "message list request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let outcome = MessageListService::new(self.build_message_list_backend())
            .list_for_validated_session(context, validated_session, &request);

        match outcome.decision {
            MessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
                ..
            } => BrowserMessageListOutcome {
                decision: BrowserMessageListDecision::Listed {
                    canonical_username,
                    mailbox_name,
                    messages,
                },
                audit_events: vec![outcome.audit_event],
            },
            MessageListDecision::Denied { public_reason } => BrowserMessageListOutcome {
                decision: BrowserMessageListDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    pub(super) fn search_messages_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: Option<&str>,
        query: &str,
        field: MessageSearchField,
    ) -> BrowserMessageSearchOutcome {
        let search_policy = MessageSearchPolicy::default();
        let query = match validate_message_search_query(search_policy, query) {
            Ok(query) => query,
            Err(error) => {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_search_request_rejected",
                        "message search request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let Some(mailbox_name) = mailbox_name else {
            let deadline = self.expensive_route_deadline();
            let Some(list_timeout) = Self::expensive_route_remaining_timeout_secs(deadline) else {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events: vec![
                        self.build_message_search_fanout_deadline_event(context, 0, 0)
                    ],
                };
            };
            let mailbox_outcome = MailboxListingService::new(
                self.build_mailbox_list_backend_with_timeout(list_timeout),
            )
            .list_for_validated_session(context, validated_session);
            let mut audit_events = vec![mailbox_outcome.audit_event];
            let (canonical_username, mailboxes) = match mailbox_outcome.decision {
                MailboxListingDecision::Listed {
                    canonical_username,
                    mailboxes,
                    ..
                } => (canonical_username, mailboxes),
                MailboxListingDecision::Denied { public_reason } => {
                    return BrowserMessageSearchOutcome {
                        decision: BrowserMessageSearchDecision::Denied {
                            public_reason: public_reason.as_str().into(),
                        },
                        audit_events,
                    }
                }
            };
            let names = mailboxes
                .into_iter()
                .filter(|mailbox| mailbox_is_browser_visible(&mailbox.name))
                .map(|mailbox| mailbox.name)
                .collect::<Vec<_>>();
            let count = names.len();
            let Some(remaining_timeout) = Self::expensive_route_remaining_timeout_secs(deadline)
            else {
                audit_events
                    .push(self.build_message_search_fanout_deadline_event(context, count, 0));
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events,
                };
            };
            let results = if names.is_empty() {
                Ok(Vec::new())
            } else {
                crate::mailbox::MessageSearchBatchRequest::new(search_policy, names, &query, field)
                    .and_then(|request| {
                        self.build_message_search_backend_with_timeout(remaining_timeout)
                            .search_messages_batch(&canonical_username, &request)
                    })
            };
            if Self::expensive_route_deadline_exceeded(deadline) {
                audit_events
                    .push(self.build_message_search_fanout_deadline_event(context, count, 0));
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events,
                };
            }
            return match results {
                Ok(results) => {
                    audit_events.push(
                        LogEvent::new(
                            LogLevel::Info,
                            EventCategory::Mailbox,
                            "message_search_batch_completed",
                            "bounded visible-mailbox search completed",
                        )
                        .with_field("canonical_username", canonical_username.clone())
                        .with_field("visible_mailbox_count", count.to_string())
                        .with_field("result_count", results.len().to_string())
                        .with_field("request_id", context.request_id.clone()),
                    );
                    BrowserMessageSearchOutcome {
                        decision: BrowserMessageSearchDecision::Listed {
                            canonical_username,
                            mailbox_name: None,
                            query,
                            results,
                        },
                        audit_events,
                    }
                }
                Err(error) => {
                    audit_events.push(
                        build_http_warning_event(
                            "message_search_batch_failed",
                            "bounded visible-mailbox search refused",
                            context,
                        )
                        .with_field("failure_code", batch_search_failure_code(&error))
                        .with_field("backend", error.backend),
                    );
                    BrowserMessageSearchOutcome {
                        decision: BrowserMessageSearchDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        },
                        audit_events,
                    }
                }
            };
        };

        let mailbox_outcome = MailboxListingService::new(self.build_mailbox_list_backend())
            .list_for_validated_session(context, validated_session);
        let mut audit_events = vec![mailbox_outcome.audit_event];
        let mailboxes = match mailbox_outcome.decision {
            MailboxListingDecision::Listed { mailboxes, .. } => mailboxes,
            MailboxListingDecision::Denied { public_reason } => {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: public_reason.as_str().to_string(),
                    },
                    audit_events,
                };
            }
        };
        if !mailbox_list_contains(&mailboxes, mailbox_name) {
            audit_events.push(
                build_http_warning_event(
                    "message_search_mailbox_rejected",
                    "message search mailbox did not match mailbox listing",
                    context,
                )
                .with_field("mailbox_name", mailbox_name.to_string()),
            );
            return BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Denied {
                    public_reason: "invalid_mailbox".to_string(),
                },
                audit_events,
            };
        }

        let request = match MessageSearchRequest::new_with_field(
            search_policy,
            mailbox_name,
            &query,
            field,
        ) {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageSearchOutcome {
                    decision: BrowserMessageSearchDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: {
                        audit_events.push(
                            build_http_warning_event(
                                "message_search_request_rejected",
                                "message search request validation failed",
                                context,
                            )
                            .with_field("reason", error.reason),
                        );
                        audit_events
                    },
                };
            }
        };

        let outcome = MessageSearchService::new(self.build_message_search_backend())
            .search_for_validated_session(context, validated_session, &request);

        match outcome.decision {
            MessageSearchDecision::Listed {
                canonical_username,
                mailbox_name,
                query,
                results,
                ..
            } => BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Listed {
                    canonical_username,
                    mailbox_name: Some(mailbox_name),
                    query,
                    results,
                },
                audit_events: {
                    audit_events.push(outcome.audit_event);
                    audit_events
                },
            },
            MessageSearchDecision::Denied { public_reason } => BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: {
                    audit_events.push(outcome.audit_event);
                    audit_events
                },
            },
        }
    }

    pub(super) fn view_message_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
    ) -> BrowserMessageViewOutcome {
        let request = match MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name, uid)
        {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageViewOutcome {
                    decision: BrowserMessageViewDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_view_request_rejected",
                        "message view request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let message_outcome = MessageViewService::new(self.build_message_view_backend())
            .fetch_for_validated_session(context, validated_session, &request);
        let mut audit_events = vec![message_outcome.audit_event.clone()];
        if let MessageViewDecision::Retrieved {
            canonical_username,
            session_id,
            message,
        } = &message_outcome.decision
        {
            if canonical_username != &validated_session.record.canonical_username
                || session_id != &validated_session.record.session_id
                || message.mailbox_name != request.mailbox_name
                || message.uid != request.uid
            {
                return BrowserMessageViewOutcome {
                    decision: BrowserMessageViewDecision::Denied {
                        public_reason: "temporarily_unavailable".into(),
                    },
                    audit_events,
                };
            }
        }

        match message_outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                message,
                ..
            } => {
                let html_display_preference = match self
                    .build_user_settings_service()
                    .load_for_validated_session(context, validated_session)
                {
                    Ok(loaded_settings) => {
                        audit_events.push(loaded_settings.audit_event);
                        loaded_settings.settings.html_display_preference
                    }
                    Err(error) => {
                        audit_events.push(self.build_user_settings_store_error_event(
                            "user_settings_load_failed_for_rendering",
                            "user settings load failed during message rendering",
                            context,
                            &error,
                        ));
                        HtmlDisplayPreference::PreferPlainText
                    }
                };

                let policy = self.render_policy_for_html_preference(html_display_preference);
                if super::http_gateway_protected::has_protection_envelope(&message) {
                    let rendered = match self.render_protected_snapshot(
                        context,
                        validated_session,
                        &message,
                        policy,
                    ) {
                        Ok(rendered) => rendered,
                        Err(error) => {
                            audit_events.push(build_http_warning_event(
                                "protected_message_refused",
                                "protected content was not released",
                                context,
                            ));
                            // Keep only the outer envelope and a refusal notice. Neither
                            // ciphertext parts nor partial plaintext become attachments
                            // or automatic reply/forward content on a failed operation.
                            let Ok(mut fallback) = PlainTextMessageRenderer::new(policy)
                                .render_for_validated_session(context, validated_session, &message)
                            else {
                                return BrowserMessageViewOutcome {
                                    decision: BrowserMessageViewDecision::Denied {
                                        public_reason: "temporarily_unavailable".into(),
                                    },
                                    audit_events,
                                };
                            };
                            fallback.rendered.body_html = TrustedHtml::from_template(format!(
                                "<p>{}</p>",
                                escape_html(crate::openpgp_reader_ui::refusal_description(error))
                            ));
                            fallback.rendered.body_text_for_compose.clear();
                            fallback.rendered.attachments.clear();
                            fallback.rendered.openpgp =
                                Some(crate::openpgp_reader_ui::ReaderState::Refused(error));
                            fallback.rendered
                        }
                    };
                    return BrowserMessageViewOutcome {
                        decision: BrowserMessageViewDecision::Rendered {
                            canonical_username,
                            rendered: Box::new(rendered),
                        },
                        audit_events,
                    };
                }

                match PlainTextMessageRenderer::new(
                    self.render_policy_for_html_preference(html_display_preference),
                )
                .render_for_validated_session(context, validated_session, &message)
                {
                    Ok(rendered_outcome) => {
                        audit_events.push(rendered_outcome.audit_event.clone());
                        BrowserMessageViewOutcome {
                            decision: BrowserMessageViewDecision::Rendered {
                                canonical_username,
                                rendered: Box::new(rendered_outcome.rendered),
                            },
                            audit_events,
                        }
                    }
                    Err(error) => {
                        audit_events.push(
                            build_http_warning_event(
                                "message_render_failed",
                                "message rendering failed",
                                context,
                            )
                            .with_field("reason", error.reason),
                        );
                        BrowserMessageViewOutcome {
                            decision: BrowserMessageViewDecision::Denied {
                                public_reason: "temporarily_unavailable".to_string(),
                            },
                            audit_events,
                        }
                    }
                }
            }
            MessageViewDecision::Denied { public_reason } => BrowserMessageViewOutcome {
                decision: BrowserMessageViewDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events,
            },
        }
    }

    pub(super) fn download_attachment_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> BrowserAttachmentDownloadOutcome {
        let request = match MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name, uid)
        {
            Ok(request) => request,
            Err(error) => {
                return BrowserAttachmentDownloadOutcome {
                    decision: BrowserAttachmentDownloadDecision::Denied {
                        public_reason: AttachmentDownloadPublicFailureReason::InvalidRequest
                            .as_str()
                            .to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "attachment_download_request_rejected",
                        "attachment download request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        // Legacy links carry no stable GUID. Fetch exactly once through the
        // configured mailbox boundary, and refuse protected legacy selectors.
        let outcome = MessageViewService::new(self.build_message_view_backend())
            .fetch_for_validated_session(context, validated_session, &request);
        let mut audit_events = vec![outcome.audit_event];
        match outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                session_id,
                message,
            } if canonical_username == validated_session.record.canonical_username
                && session_id == validated_session.record.session_id
                && message.mailbox_name == request.mailbox_name
                && message.uid == request.uid =>
            {
                if super::http_gateway_protected::has_protection_envelope(&message) {
                    return BrowserAttachmentDownloadOutcome {
                        decision: BrowserAttachmentDownloadDecision::Denied {
                            public_reason: "invalid_request".into(),
                        },
                        audit_events,
                    };
                }
                let mut result = self.download_stored_attachment(
                    context,
                    validated_session,
                    &message,
                    part_path,
                );
                audit_events.append(&mut result.audit_events);
                result.audit_events = audit_events;
                result
            }
            MessageViewDecision::Denied { public_reason } => BrowserAttachmentDownloadOutcome {
                decision: BrowserAttachmentDownloadDecision::Denied {
                    public_reason: public_reason.as_str().into(),
                },
                audit_events,
            },
            _ => BrowserAttachmentDownloadOutcome {
                decision: BrowserAttachmentDownloadDecision::Denied {
                    public_reason: "temporarily_unavailable".into(),
                },
                audit_events,
            },
        }
    }

    pub(super) fn send_message_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: BrowserSendRequest<'_>,
    ) -> BrowserSendOutcome {
        self.send_message_with_backends(
            context,
            session,
            request,
            &self.build_submission_service(),
            &self.build_message_append_backend(),
        )
    }

    pub(super) fn send_message_with_backends<
        S: crate::send::SubmissionBackend,
        A: MessageAppendBackend,
    >(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        send_request: BrowserSendRequest<'_>,
        submission: &SubmissionService<S>,
        append: &A,
    ) -> BrowserSendOutcome {
        use crate::send_journal::PreparedResult;
        let throttle_service = self.build_submission_throttle_service();
        let account = &validated_session.record.canonical_username;
        let now = SystemTimeProvider.unix_timestamp();
        let journal = crate::send_journal::SendJournal::new(self.settings_dir.join("send-journal"));
        let mut preparation_events = Vec::new();
        let mut dispatch_events = Vec::new();
        let prepared_wire = std::cell::RefCell::new(None);
        let result = journal.execute_prepared(
            account,
            send_request.send_intent,
            now,
            |consumed| {
                // The journal account lock is already held. Recheck persisted
                // revision here, after any concurrent save has completed.
                let mut sender_identity = None;
                if !consumed {
                    match (send_request.draft_id, send_request.draft_revision) {
                        (Some(id), Some(revision)) => {
                            let draft = self
                                .build_draft_store()
                                .load(account, id, now)
                                .ok()
                                .flatten()
                                .ok_or_else(|| BrowserSendDecision::Unconfirmed {
                                    public_reason: "send_attempt_paused".into(),
                                })?;
                            sender_identity = Some(draft.request.sender_identity.clone());
                            let expected = crate::send_journal::intent_for_draft(
                                account,
                                id,
                                revision,
                                draft.updated_at,
                            );
                            if draft.revision != Some(revision)
                                || expected.as_deref() != Ok(send_request.send_intent)
                            {
                                return Err(BrowserSendDecision::Unconfirmed {
                                    public_reason: "send_attempt_paused".into(),
                                });
                            }
                        }
                        (None, None) => {}
                        _ => {
                            return Err(BrowserSendDecision::Unconfirmed {
                                public_reason: "send_attempt_paused".into(),
                            })
                        }
                    }
                }
                let mut request = ComposeRequest::new_with_routing(
                    ComposePolicy::default(),
                    send_request.recipients,
                    send_request.cc_recipients,
                    send_request.bcc_recipients,
                    send_request.subject,
                    send_request.body,
                    send_request.attachments.to_vec(),
                )
                .and_then(|request| request.with_body_format(send_request.body_format))
                .map_err(|error| {
                    preparation_events.push(
                        build_http_warning_event(
                            "compose_request_rejected",
                            "compose request validation failed",
                            context,
                        )
                        .with_field("reason", error.reason),
                    );
                    BrowserSendDecision::Denied {
                        public_reason: SubmissionPublicFailureReason::InvalidRequest
                            .as_str()
                            .into(),
                        retry_after_seconds: None,
                    }
                })?;
                request.sender_identity = if consumed {
                    match crate::send_recovery::SendRecovery::new(
                        self.settings_dir.join("send-recovery"),
                    )
                    .lookup(&journal, account, send_request.send_intent, now)
                    {
                        Ok(crate::send_recovery::RecoveryRead::Available(snapshot)) => {
                            if snapshot.request.protection != send_request.protection {
                                return Err(BrowserSendDecision::Unconfirmed {
                                    public_reason: "send_attempt_paused".into(),
                                });
                            }
                            snapshot.request.sender_identity.clone()
                        }
                        _ => {
                            return Err(BrowserSendDecision::Unconfirmed {
                                public_reason: "send_attempt_paused".into(),
                            })
                        }
                    }
                } else if let Some(identity) = sender_identity {
                    identity
                } else {
                    self.load_identity_preferences(context, validated_session)
                        .map_err(|_| BrowserSendDecision::Unconfirmed {
                            public_reason: "send_attempt_paused".into(),
                        })?
                        .preferences
                };
                request.reply_thread = send_request.reply_thread.cloned();
                request.protection = send_request.protection;
                // Replay skips current throttle state. For fresh attempts the check
                // and its NotDispatched disposition are protected by the journal lock.
                if !consumed {
                    match throttle_service.check(context, account) {
                        Ok(check) => {
                            preparation_events.extend(check.audit_events);
                            if let SubmissionThrottleDecision::Throttled {
                                retry_after_seconds,
                            } = check.decision
                            {
                                return Err(BrowserSendDecision::Denied {
                                    public_reason: TOO_MANY_SUBMISSIONS_PUBLIC_REASON.into(),
                                    retry_after_seconds: Some(retry_after_seconds),
                                });
                            }
                        }
                        Err(error) => preparation_events.push(
                            self.build_submission_throttle_store_error_event(
                                "submission_throttle_check_failed",
                                "submission throttle check failed",
                                context,
                                &error,
                            ),
                        ),
                    }
                    let prepared = self
                        .prepare_outbound_request(account, &request, now)
                        .map_err(|reason| BrowserSendDecision::Denied {
                            public_reason: reason.into(),
                            retry_after_seconds: None,
                        })?;
                    *prepared_wire.borrow_mut() = Some(prepared);
                }
                Ok(request)
            },
            |request| {
                let recovery = crate::send_recovery::SendRecovery::new(
                    self.settings_dir.join("send-recovery"),
                );
                let request = match recovery.capture(
                    &journal,
                    &self.build_draft_store(),
                    account,
                    send_request.send_intent,
                    request,
                    now,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        dispatch_events.push(build_http_warning_event(
                            "send_recovery_unconfirmed",
                            "attempt recovery was not confirmed; submission was not invoked",
                            context,
                        ));
                        return crate::send_journal::AttemptOutcome::RecoveryRefused {
                            capacity: error == crate::send_recovery::RecoveryError::Capacity,
                        };
                    }
                };
                let Some((prepared, binding_revision)) = prepared_wire.borrow_mut().take() else {
                    return crate::send_journal::AttemptOutcome::Unconfirmed;
                };
                // Serialize the final revision check and SMTP dispatch with
                // PAGE21 policy/binding writers. The journal lock is acquired
                // first by both fresh and replayed attempts; no writer can
                // change required protection between this check and dispatch.
                let outcome = match crate::openpgp_bindings::BindingStore::new(
                    self.settings_dir.join("openpgp-bindings"),
                )
                .with_locked_revision(account, binding_revision, |_| {
                    Ok(submission.submit_prepared_for_validated_session(
                        context,
                        validated_session,
                        &request,
                        &prepared,
                    ))
                }) {
                    Ok(outcome) => outcome,
                    Err(_) => return crate::send_journal::AttemptOutcome::Unconfirmed,
                };
                let SubmissionOutcome {
                    decision,
                    audit_event,
                } = outcome;
                dispatch_events.push(audit_event);

                match decision {
                    SubmissionDecision::Submitted { .. } => {
                        let (sent_copy_stored, sent_copy_event) = store_prepared_sent_copy(
                            context,
                            &validated_session.record.canonical_username,
                            &request,
                            &prepared,
                            append,
                        );
                        dispatch_events.push(sent_copy_event);

                        match throttle_service.record_submission(
                            context,
                            &validated_session.record.canonical_username,
                        ) {
                            Ok(record) => dispatch_events.extend(record.audit_events),
                            Err(error) => dispatch_events.push(
                                self.build_submission_throttle_store_error_event(
                                    "submission_throttle_record_failed",
                                    "submission throttle recording failed",
                                    context,
                                    &error,
                                ),
                            ),
                        }

                        crate::send_journal::AttemptOutcome::Accepted { sent_copy_stored }
                    }
                    SubmissionDecision::Unconfirmed { .. } | SubmissionDecision::Denied { .. } => {
                        crate::send_journal::AttemptOutcome::Unconfirmed
                    }
                }
            },
        );
        preparation_events.extend(dispatch_events);
        let decision = match result {
            Ok(PreparedResult::NotDispatched(decision)) => decision,
            Ok(PreparedResult::Outcome(recorded)) => journal_send_decision(Ok(recorded)),
            Err(error) => journal_send_decision(Err(error)),
        };
        BrowserSendOutcome {
            decision,
            audit_events: preparation_events,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_prepare_outbound_request(
        &self,
        account: &str,
        request: &ComposeRequest,
        now: u64,
    ) -> Result<(crate::protected_submission::PreparedSubmission, u64), &'static str> {
        self.prepare_outbound_request(account, request, now)
    }

    fn prepare_outbound_request(
        &self,
        account: &str,
        request: &ComposeRequest,
        now: u64,
    ) -> Result<(crate::protected_submission::PreparedSubmission, u64), &'static str> {
        let account =
            crate::identity::CanonicalUsername::parse(account).map_err(|_| "invalid_request")?;
        let record =
            crate::openpgp_bindings::BindingStore::new(self.settings_dir.join("openpgp-bindings"))
                .load(account.as_str())
                .map_err(|_| "openpgp_binding_unavailable")?;
        let inventory = self
            .inventory_client()
            .as_ref()
            .and_then(|client| client.read(account.as_str()).ok());
        let result = match &self.crypto_client() {
            Some(client) => crate::protected_submission::prepare_for_delivery(
                client,
                &account,
                request,
                &record,
                inventory.as_ref(),
                now,
            ),
            None => crate::protected_submission::prepare_for_delivery(
                &crate::protected_submission::UnavailableCrypto,
                &account,
                request,
                &record,
                inventory.as_ref(),
                now,
            ),
        };
        result
            .map(|prepared| (prepared, record.revision))
            .map_err(|error| match error {
                crate::protected_submission::SubmissionError::StaleBinding => {
                    "openpgp_binding_changed"
                }
                crate::protected_submission::SubmissionError::ProtectionBlocked(reason) => {
                    use crate::openpgp_bindings::BlockReason;
                    match reason {
                        Some(BlockReason::RecipientRequiresEncryption) => {
                            "openpgp_recipient_encryption_required"
                        }
                        Some(BlockReason::RecipientForbidsEncryption) => {
                            "openpgp_recipient_encryption_disabled"
                        }
                        Some(BlockReason::RecipientKeyUnavailable) => {
                            "openpgp_recipient_key_unavailable"
                        }
                        Some(BlockReason::SigningRequired) => "openpgp_signing_required",
                        Some(BlockReason::SigningDisabled) => "openpgp_signing_disabled",
                        Some(BlockReason::EncryptionRequired) => "openpgp_encryption_required",
                        Some(BlockReason::EncryptionDisabled) => "openpgp_encryption_disabled",
                        Some(BlockReason::SigningUnavailable) => "openpgp_signing_key_unavailable",
                        Some(BlockReason::EncryptedBccUnqualified) => {
                            "openpgp_encrypted_bcc_unavailable"
                        }
                        Some(BlockReason::SelfRequiresEncryption) => {
                            "openpgp_self_requires_encryption"
                        }
                        Some(BlockReason::SelfKeyUnavailable) => "openpgp_self_key_unavailable",
                        None => "openpgp_protection_blocked",
                    }
                }
                crate::protected_submission::SubmissionError::InventoryUnavailable => {
                    "openpgp_inventory_unavailable"
                }
                crate::protected_submission::SubmissionError::Crypto(
                    crate::protected_message::CryptoFailure::Engine(
                        crate::openpgp_crypto::Error::Locked,
                    ),
                ) => "openpgp_key_locked",
                crate::protected_submission::SubmissionError::SizeLimit => {
                    "openpgp_message_too_large"
                }
                _ => "openpgp_submission_unavailable",
            })
    }

    pub(super) fn move_message_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> BrowserMessageMoveOutcome {
        use crate::mailbox::MessageMoveBackend;
        let mut audit_events = Vec::new();
        let denied = |reason: &str, retry_after_seconds, audit_events| BrowserMessageMoveOutcome {
            decision: BrowserMessageMoveDecision::Denied {
                public_reason: reason.into(),
                retry_after_seconds,
            },
            audit_events,
        };
        if MessageMoveRequest::new(
            MessageMovePolicy::default(),
            request.source_mailbox_name.clone(),
            request.destination_mailbox_name.clone(),
            request.uid,
            request.version.clone(),
        )
        .is_err()
        {
            return denied("invalid_request", None, audit_events);
        }
        match self
            .build_message_move_throttle_service()
            .reserve_mail_action(context, &session.record.canonical_username)
        {
            Ok(check) => {
                audit_events.extend(check.audit_events);
                if let MessageMoveThrottleDecision::Throttled {
                    retry_after_seconds,
                } = check.decision
                {
                    return denied(
                        TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON,
                        Some(retry_after_seconds),
                        audit_events,
                    );
                }
            }
            Err(_) => {
                audit_events.push(build_http_warning_event(
                    "message_move_quota_unavailable",
                    "move refused because its quota could not be reserved",
                    context,
                ));
                return denied("message_move_unavailable", None, audit_events);
            }
        }
        let listing = MailboxListingService::new(self.build_mailbox_list_backend())
            .list_for_validated_session(context, session);
        audit_events.push(listing.audit_event);
        let MailboxListingDecision::Listed { mailboxes, .. } = listing.decision else {
            return denied("message_move_unavailable", None, audit_events);
        };
        if !mailbox_list_contains(&mailboxes, &request.source_mailbox_name)
            || !mailbox_list_contains(&mailboxes, &request.destination_mailbox_name)
        {
            return denied("invalid_mailbox", None, audit_events);
        }
        let result = self
            .build_message_move_backend()
            .move_message(&session.record.canonical_username, request);
        audit_events.push(
            build_http_info_event(
                "message_move_result",
                "bounded identity-bound move completed",
                context,
            )
            .with_field(
                "session_ref",
                crate::logging::audit_session_ref(&session.record.session_id),
            )
            .with_field(
                "outcome",
                match &result {
                    Ok(()) => "confirmed",
                    Err(error) => error.backend,
                },
            ),
        );
        match result {
            Ok(()) => BrowserMessageMoveOutcome {
                decision: BrowserMessageMoveDecision::Moved {
                    source_mailbox_name: request.source_mailbox_name.clone(),
                    destination_mailbox_name: request.destination_mailbox_name.clone(),
                    uid: request.uid,
                },
                audit_events,
            },
            Err(error) => denied(
                match error.backend {
                    "message-move-stale" => "message_move_stale",
                    "message-move-busy" => "message_move_busy",
                    "message-move-unknown" => "message_move_unknown",
                    "message-move-parser" | "message-metadata" => "invalid_request",
                    _ => "message_move_unavailable",
                },
                None,
                audit_events,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_folder_participates_in_account_mailbox_search() {
        assert!(mailbox_is_browser_visible("Archive"));
        assert!(!mailbox_is_browser_visible("Shared/Other"));
        assert!(!mailbox_is_browser_visible("OtherAccount/Archive"));
    }
    mod journal_integration {
        use super::*;
        include!("http/send_gateway_journal_tests.rs");
    }
    mod protected_send {
        use super::*;
        include!("http/protected_send_gateway_tests.rs");
    }
    mod protected_send_native {
        use super::*;
        include!("http/protected_send_gateway_native_tests.rs");
    }

    #[derive(Default)]
    struct StubSentAppendBackend {
        fail: bool,
        calls: std::cell::RefCell<Vec<(String, MessageAppendRequest)>>,
    }

    impl MessageAppendBackend for StubSentAppendBackend {
        fn append_message(
            &self,
            canonical_username: &str,
            request: &MessageAppendRequest,
        ) -> Result<(), crate::mailbox::MailboxBackendError> {
            self.calls
                .borrow_mut()
                .push((canonical_username.into(), request.clone()));
            if self.fail {
                Err(crate::mailbox::MailboxBackendError {
                    backend: "synthetic-append",
                    reason: "private backend error detail".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn sent_copy_reports_confirmation_and_never_retries_append() {
        let request = ComposeRequest::new_with_routing(
            ComposePolicy::default(),
            "bob@example.com",
            "",
            "hidden@example.com",
            "Synthetic subject",
            "Synthetic body",
            vec![],
        )
        .unwrap();
        for fail in [false, true] {
            let backend = StubSentAppendBackend {
                fail,
                ..Default::default()
            };
            let (stored, event) =
                store_sent_copy(&test_context(), "alice@example.com", &request, &backend);
            assert_eq!(stored, !fail);
            let calls = backend.calls.borrow();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "alice@example.com");
            assert_eq!(calls[0].1.mailbox_name, "Sent");
            assert_eq!(
                calls[0].1.message,
                build_submission_message("alice@example.com", &request).unwrap()
            );
            assert!(!String::from_utf8_lossy(&calls[0].1.message).contains("Bcc:"));
            assert_eq!(
                event.action,
                if fail {
                    "sent_copy_store_failed"
                } else {
                    "sent_copy_stored"
                }
            );
            let rendered =
                crate::logging::Logger::new(crate::config::LogFormat::Text, LogLevel::Debug)
                    .render_with_timestamp(&event, 8080);
            assert!(rendered.contains("accepted for submission"));
            for private in [
                "private backend error detail",
                "Synthetic subject",
                "Synthetic body",
                "hidden@example.com",
            ] {
                assert!(!rendered.contains(private));
            }
        }
    }

    #[test]
    fn sent_copy_format_failure_does_not_append_or_claim_storage() {
        let mut request = ComposeRequest::new(
            ComposePolicy::default(),
            "bob@example.com",
            "Synthetic subject",
            "**valid**",
        )
        .unwrap()
        .with_body_format(crate::compose_format::BodyFormat::Formatted)
        .unwrap();
        request.body = "[bad](javascript:x)".into();
        let backend = StubSentAppendBackend::default();
        let (stored, event) =
            store_sent_copy(&test_context(), "alice@example.com", &request, &backend);
        assert!(!stored);
        assert!(backend.calls.borrow().is_empty());
        assert_eq!(event.action, "sent_copy_store_failed");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "backend" && field.value == "sent-copy-formatter"));
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-fanout-deadline",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    fn validated_session() -> ValidatedSession {
        ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "session-id".to_string(),
                csrf_token: "csrf-token".to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 1,
                expires_at: 3600,
                last_seen_at: 1,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: crate::auth::RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "session validated",
            ),
        }
    }

    #[cfg(unix)]
    #[test]
    fn all_mailbox_search_uses_one_batch_fetch_for_39_folders() {
        use crate::auth::CommandExecutor;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let root = std::env::temp_dir().join(format!(
            "osmap-search-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let interpreter = if cfg!(target_os = "openbsd") {
            "/usr/local/bin/python3"
        } else {
            "/usr/bin/python3"
        };
        assert!(
            std::path::Path::new(interpreter).is_file(),
            "qualified direct Python interpreter required"
        );
        let script = root.join("doveadm-fixture");
        let calls = root.join("calls");
        let mode_file = root.join("mode");
        let names = (0..39)
            .map(|n| format!("INBOX.fixture{n:02}"))
            .collect::<Vec<_>>();
        std::fs::write(
            root.join("names.json"),
            serde_json::to_string(&names).unwrap(),
        )
        .unwrap();
        std::fs::write(&mode_file, "normal").unwrap();
        std::fs::write(&calls, "").unwrap();
        // Direct exec preserves argv boundaries and has no interpreter child to
        // outlive SystemCommandExecutor's timeout/kill/wait boundary.
        const FIXTURE: &str = r#"import json
import os
from pathlib import Path
import sys
import time
root = Path(__file__).resolve().parent
args = sys.argv[1:]
if len(args) == 2 and args[0] == "--assert-process-gone":
    try:
        os.kill(int(args[1]), 0)
    except ProcessLookupError:
        sys.exit(0)
    sys.exit(42)
if "-u" not in args or args.index("-u") + 1 >= len(args) or args[args.index("-u") + 1] != "alice@example.com":
    sys.exit(1)
with (root / "calls").open("a") as recorded:
    recorded.write(json.dumps(args) + "\n")
(root / "pid").write_text(str(os.getpid()))
mode = (root / "mode").read_text()
is_listing = any(args[index:index + 2] == ["mailbox", "list"] for index in range(len(args) - 1))
if is_listing:
    if mode == "listing_timeout":
        time.sleep(2)
    names = json.loads((root / "names.json").read_text()) if mode == "normal" else ["INBOX"]
    sys.stdout.write("".join(name + "\n" for name in names))
elif "fetch" in args:
    if mode == "fetch_timeout":
        time.sleep(2)
    sys.stdout.write("[]" if mode in ["normal", "fetch_timeout"] else "[invalid-json]")
else:
    sys.exit(1)
"#;
        std::fs::write(&script, format!("#!{interpreter}\n{FIXTURE}")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let read_calls = || -> Vec<Vec<String>> {
            std::fs::read_to_string(&calls)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        let is_listing =
            |args: &Vec<String>| args.windows(2).any(|pair| pair == ["mailbox", "list"]);
        let is_fetch = |args: &Vec<String>| args.iter().any(|arg| arg == "fetch");
        let mut gateway = RuntimeBrowserGateway::for_test(&root);
        gateway.doveadm_path = script;
        gateway.mailbox_helper_socket_path = None;
        gateway.doveadm_userdb_socket_path = None;
        gateway.expensive_request_timeout_secs = 5;
        let result = gateway.search_messages_impl(
            &test_context(),
            &validated_session(),
            None,
            "needle",
            MessageSearchField::Subject,
        );
        assert!(
            matches!(result.decision, BrowserMessageSearchDecision::Listed {results, ..} if results.is_empty())
        );
        let recorded = read_calls();
        assert_eq!(recorded.iter().filter(|args| is_listing(args)).count(), 1);
        assert_eq!(
            recorded.iter().filter(|args| is_fetch(args)).count(),
            1,
            "39-folder all-scope search must not start 39 separate native fetches"
        );
        assert!(recorded
            .iter()
            .any(|args| args.iter().any(|arg| arg == "INBOX.fixture38")));
        assert!(recorded.iter().all(|args| args
            .windows(2)
            .any(|pair| pair == ["-u", "alice@example.com"])));
        for mode in [
            "malformed_fetch",
            "listing_timeout",
            "fetch_timeout",
            "expired",
        ] {
            std::fs::write(&calls, "").unwrap();
            std::fs::write(&mode_file, mode).unwrap();
            gateway.expensive_request_timeout_secs = if mode == "expired" { 1 } else { 2 };
            let started = Instant::now();
            let denied = gateway.search_messages_impl(
                &test_context(),
                &validated_session(),
                None,
                "private-needle",
                MessageSearchField::Subject,
            );
            assert!(
                matches!(denied.decision, BrowserMessageSearchDecision::Denied { .. }),
                "{mode}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "{mode} must keep bounded total deadline"
            );
            let observed = read_calls();
            if matches!(mode, "listing_timeout" | "expired") {
                assert!(
                    !observed.iter().any(is_fetch),
                    "{mode} must not dispatch search"
                );
            }
            if matches!(mode, "listing_timeout" | "fetch_timeout") {
                let pid = std::fs::read_to_string(root.join("pid"))
                    .unwrap()
                    .parse::<u32>()
                    .unwrap();
                assert!(pid > 0);
                let child_gone = crate::auth::SystemCommandExecutor
                    .run_with_stdin_timeout(
                        gateway.doveadm_path.to_str().unwrap(),
                        &["--assert-process-gone".into(), pid.to_string()],
                        "",
                        Duration::from_secs(1),
                    )
                    .unwrap();
                assert_eq!(
                    child_gone.status_code, 0,
                    "{mode} timed-out fixture process must be reaped"
                );
            }
            if mode == "malformed_fetch" {
                assert!(denied
                    .audit_events
                    .iter()
                    .any(|event| event.action == "message_search_batch_failed"
                        && event.fields.iter().any(|field| field.key == "failure_code"
                            && field.value == "native_output_rejected")));
            }
            assert!(!format!("{:?}", denied.audit_events).contains("private-needle"));
            std::fs::write(&mode_file, "cheap_listing").unwrap();
            assert!(
                matches!(
                    gateway
                        .list_mailboxes_impl(&test_context(), &validated_session())
                        .decision,
                    BrowserMailboxDecision::Listed { .. }
                ),
                "{mode} must not prevent cheap subsequent listing"
            );
        }
    }

    #[test]
    fn batch_search_refusal_audit_codes_are_finite_and_ignore_private_diagnostics() {
        for (backend, expected) in [
            ("message-search-parser", "scope_request_invalid"),
            ("message-json-parser", "native_output_rejected"),
            ("doveadm-message-search", "native_operation_unavailable"),
            (
                "mailbox-helper-client",
                "helper_transport_or_response_rejected",
            ),
        ] {
            let error = crate::mailbox::MailboxBackendError {
                backend,
                reason: "private-query and backend output must not reach audit".into(),
            };
            assert_eq!(batch_search_failure_code(&error), expected);
        }
    }

    #[test]
    fn all_mailbox_search_deadline_detects_expired_budget() {
        let expired = Instant::now() - Duration::from_secs(1);

        assert!(RuntimeBrowserGateway::expensive_route_deadline_exceeded(
            expired
        ));
        assert_eq!(
            RuntimeBrowserGateway::expensive_route_remaining_timeout_secs(expired),
            None
        );
    }

    #[test]
    fn all_mailbox_search_deadline_reports_remaining_whole_seconds() {
        let deadline = Instant::now() + Duration::from_secs(3);

        assert_eq!(
            RuntimeBrowserGateway::expensive_route_remaining_timeout_secs(deadline),
            Some(2)
        );
    }

    #[test]
    fn all_mailbox_search_deadline_event_omits_private_search_inputs() {
        let temp_root = std::env::temp_dir().join(format!(
            "osmap-search-fanout-deadline-{}",
            std::process::id()
        ));
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.expensive_request_timeout_secs = 3;

        let event = gateway.build_message_search_fanout_deadline_event(&test_context(), 7, 2);

        assert_eq!(event.action, "message_search_fanout_deadline_exceeded");
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "route_class" && field.value == "message_search"));
        assert!(event
            .fields
            .iter()
            .any(|field| field.key == "deadline_seconds" && field.value == "3"));
        assert!(!event.fields.iter().any(|field| {
            matches!(
                field.key,
                "query" | "mailbox_name" | "session_id" | "csrf_token"
            )
        }));
    }

    #[test]
    fn attachment_download_fails_closed_when_helper_grant_key_path_is_missing() {
        let temp_root = std::env::temp_dir().join(format!(
            "osmap-attachment-missing-helper-grant-{}",
            std::process::id()
        ));
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.mailbox_helper_socket_path = Some(temp_root.join("mailbox-helper.sock"));
        gateway.mailbox_helper_grant_key_path = None;

        let outcome = gateway.download_attachment_impl(
            &test_context(),
            &validated_session(),
            "INBOX",
            1,
            "1",
        );

        assert_eq!(
            outcome.decision,
            BrowserAttachmentDownloadDecision::Denied {
                public_reason: "temporarily_unavailable".to_string()
            }
        );
        assert!(outcome.audit_events.iter().any(|event| {
            event.action == "message_view_failed"
                && event.fields.iter().any(|field| {
                    field.key == "backend_reason"
                        && field.value == "mailbox helper socket configured without grant key path"
                })
        }));
        let source = gateway.read_message_source(
            &test_context(),
            &validated_session(),
            &MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 1)
                .expect("valid request"),
        );
        assert!(matches!(
            source.decision,
            MessageViewDecision::Denied {
                public_reason: crate::mailbox::MailboxPublicFailureReason::TemporarilyUnavailable
            }
        ));
    }
}
