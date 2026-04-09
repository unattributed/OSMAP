use super::*;

use crate::config::LogLevel;
use crate::logging::EventCategory;
use crate::mailbox::validate_message_search_query;

impl RuntimeBrowserGateway {
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
        SubmissionService::new(SendmailSubmissionBackend::new(
            SystemCommandExecutor,
            self.sendmail_path.clone(),
        ))
    }

    /// Builds the current attachment-download service from the MIME policy.
    pub(super) fn build_attachment_download_service(&self) -> AttachmentDownloadService {
        AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
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

    /// Records a non-fatal throttle-store failure so operators can diagnose
    /// missing mailbox-mutation abuse resistance without crashing the move path.
    pub(super) fn build_message_move_throttle_store_error_event(
        &self,
        action: &'static str,
        message: &'static str,
        context: &AuthenticationContext,
        error: &LoginThrottleError,
    ) -> LogEvent {
        LogEvent::new(LogLevel::Warn, EventCategory::Mailbox, action, message)
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
            let mailbox_outcome = MailboxListingService::new(self.build_mailbox_list_backend())
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
                            public_reason: public_reason.as_str().to_string(),
                        },
                        audit_events,
                    };
                }
            };

            let search_service = MessageSearchService::new(self.build_message_search_backend());
            let mut aggregated_results = Vec::new();
            for mailbox in mailboxes {
                let request =
                    match MessageSearchRequest::new(search_policy, mailbox.name.clone(), &query) {
                        Ok(request) => request,
                        Err(error) => {
                            audit_events.push(
                                build_http_warning_event(
                                    "message_search_request_rejected",
                                    "message search request validation failed",
                                    context,
                                )
                                .with_field("reason", error.reason),
                            );
                            return BrowserMessageSearchOutcome {
                                decision: BrowserMessageSearchDecision::Denied {
                                    public_reason: "invalid_request".to_string(),
                                },
                                audit_events,
                            };
                        }
                    };
                let outcome = search_service.search_for_validated_session(
                    context,
                    validated_session,
                    &request,
                );
                audit_events.push(outcome.audit_event);

                match outcome.decision {
                    MessageSearchDecision::Listed { results, .. } => {
                        let remaining = search_policy
                            .max_results
                            .saturating_sub(aggregated_results.len());
                        if remaining == 0 {
                            break;
                        }
                        aggregated_results.extend(results.into_iter().take(remaining));
                        if aggregated_results.len() >= search_policy.max_results {
                            break;
                        }
                    }
                    MessageSearchDecision::Denied { public_reason } => {
                        return BrowserMessageSearchOutcome {
                            decision: BrowserMessageSearchDecision::Denied {
                                public_reason: public_reason.as_str().to_string(),
                            },
                            audit_events,
                        };
                    }
                }
            }

            return BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Listed {
                    canonical_username,
                    mailbox_name: None,
                    query,
                    results: aggregated_results,
                },
                audit_events,
            };
        };

        let request = match MessageSearchRequest::new(search_policy, mailbox_name, &query) {
            Ok(request) => request,
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
                audit_events: vec![outcome.audit_event],
            },
            MessageSearchDecision::Denied { public_reason } => BrowserMessageSearchOutcome {
                decision: BrowserMessageSearchDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
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

        let message_outcome = MessageViewService::new(self.build_message_view_backend())
            .fetch_for_validated_session(context, validated_session, &request);
        let mut audit_events = vec![message_outcome.audit_event.clone()];

        match message_outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                message,
                ..
            } => {
                let attachment_outcome = self
                    .build_attachment_download_service()
                    .download_for_validated_session(
                        context,
                        validated_session,
                        &message,
                        part_path,
                    );
                audit_events.push(attachment_outcome.audit_event.clone());

                match attachment_outcome.decision {
                    AttachmentDownloadDecision::Downloaded { attachment, .. } => {
                        BrowserAttachmentDownloadOutcome {
                            decision: BrowserAttachmentDownloadDecision::Downloaded {
                                canonical_username,
                                attachment,
                            },
                            audit_events,
                        }
                    }
                    AttachmentDownloadDecision::Denied { public_reason } => {
                        BrowserAttachmentDownloadOutcome {
                            decision: BrowserAttachmentDownloadDecision::Denied {
                                public_reason: public_reason.as_str().to_string(),
                            },
                            audit_events,
                        }
                    }
                }
            }
            MessageViewDecision::Denied { public_reason } => BrowserAttachmentDownloadOutcome {
                decision: BrowserAttachmentDownloadDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events,
            },
        }
    }

    pub(super) fn send_message_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
        attachments: &[UploadedAttachment],
    ) -> BrowserSendOutcome {
        let throttle_service = self.build_submission_throttle_service();
        let mut audit_events = Vec::new();
        let request = match ComposeRequest::new_with_attachments(
            ComposePolicy::default(),
            recipients,
            subject,
            body,
            attachments.to_vec(),
        ) {
            Ok(request) => request,
            Err(error) => {
                return BrowserSendOutcome {
                    decision: BrowserSendDecision::Denied {
                        public_reason: SubmissionPublicFailureReason::InvalidRequest
                            .as_str()
                            .to_string(),
                        retry_after_seconds: None,
                    },
                    audit_events: vec![build_http_warning_event(
                        "compose_request_rejected",
                        "compose request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        match throttle_service.check(context, &validated_session.record.canonical_username) {
            Ok(check) => {
                audit_events.extend(check.audit_events);

                if let SubmissionThrottleDecision::Throttled {
                    retry_after_seconds,
                } = check.decision
                {
                    return BrowserSendOutcome {
                        decision: BrowserSendDecision::Denied {
                            public_reason: TOO_MANY_SUBMISSIONS_PUBLIC_REASON.to_string(),
                            retry_after_seconds: Some(retry_after_seconds),
                        },
                        audit_events,
                    };
                }
            }
            Err(error) => audit_events.push(self.build_submission_throttle_store_error_event(
                "submission_throttle_check_failed",
                "submission throttle check failed",
                context,
                &error,
            )),
        }

        let outcome = self
            .build_submission_service()
            .submit_for_validated_session(context, validated_session, &request);
        let SubmissionOutcome {
            decision,
            audit_event,
        } = outcome;
        audit_events.push(audit_event);

        match decision {
            SubmissionDecision::Submitted { .. } => {
                match throttle_service
                    .record_submission(context, &validated_session.record.canonical_username)
                {
                    Ok(record) => audit_events.extend(record.audit_events),
                    Err(error) => {
                        audit_events.push(self.build_submission_throttle_store_error_event(
                            "submission_throttle_record_failed",
                            "submission throttle recording failed",
                            context,
                            &error,
                        ))
                    }
                }

                BrowserSendOutcome {
                    decision: BrowserSendDecision::Submitted,
                    audit_events,
                }
            }
            SubmissionDecision::Denied { public_reason } => BrowserSendOutcome {
                decision: BrowserSendDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                    retry_after_seconds: None,
                },
                audit_events,
            },
        }
    }

    pub(super) fn move_message_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        source_mailbox_name: &str,
        uid: u64,
        destination_mailbox_name: &str,
    ) -> BrowserMessageMoveOutcome {
        let throttle_service = self.build_message_move_throttle_service();
        let request = match MessageMoveRequest::new(
            MessageMovePolicy::default(),
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        ) {
            Ok(request) => request,
            Err(error) => {
                return BrowserMessageMoveOutcome {
                    decision: BrowserMessageMoveDecision::Denied {
                        public_reason: "invalid_request".to_string(),
                        retry_after_seconds: None,
                    },
                    audit_events: vec![build_http_warning_event(
                        "message_move_request_rejected",
                        "message move request validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };
        let mut audit_events = Vec::new();

        match throttle_service.check(context, &validated_session.record.canonical_username) {
            Ok(check) => {
                audit_events.extend(check.audit_events);

                if let MessageMoveThrottleDecision::Throttled {
                    retry_after_seconds,
                } = check.decision
                {
                    return BrowserMessageMoveOutcome {
                        decision: BrowserMessageMoveDecision::Denied {
                            public_reason: TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON.to_string(),
                            retry_after_seconds: Some(retry_after_seconds),
                        },
                        audit_events,
                    };
                }
            }
            Err(error) => audit_events.push(self.build_message_move_throttle_store_error_event(
                "message_move_throttle_check_failed",
                "message move throttle check failed",
                context,
                &error,
            )),
        }

        let outcome = MessageMoveService::new(self.build_message_move_backend())
            .move_for_validated_session(context, validated_session, &request);
        let MessageMoveOutcome {
            decision,
            audit_event,
        } = outcome;
        audit_events.push(audit_event);

        match decision {
            MessageMoveDecision::Moved {
                source_mailbox_name,
                destination_mailbox_name,
                uid,
                ..
            } => BrowserMessageMoveOutcome {
                decision: BrowserMessageMoveDecision::Moved {
                    source_mailbox_name,
                    destination_mailbox_name,
                    uid,
                },
                audit_events: {
                    match throttle_service
                        .record_move(context, &validated_session.record.canonical_username)
                    {
                        Ok(record) => audit_events.extend(record.audit_events),
                        Err(error) => {
                            audit_events.push(self.build_message_move_throttle_store_error_event(
                                "message_move_throttle_record_failed",
                                "message move throttle recording failed",
                                context,
                                &error,
                            ))
                        }
                    }
                    audit_events
                },
            },
            MessageMoveDecision::Denied { public_reason } => BrowserMessageMoveOutcome {
                decision: BrowserMessageMoveDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                    retry_after_seconds: None,
                },
                audit_events,
            },
        }
    }
}
