use super::*;

#[path = "http_gateway_auth.rs"]
mod http_gateway_auth;
#[path = "http_mailbox_backends.rs"]
mod http_mailbox_backends;

/// The concrete runtime gateway built from the existing OSMAP services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBrowserGateway {
    authentication_policy: AuthenticationPolicy,
    totp_policy: TotpPolicy,
    login_throttle_policy: LoginThrottlePolicy,
    session_lifetime_seconds: u64,
    session_dir: PathBuf,
    login_throttle_dir: PathBuf,
    totp_secret_dir: PathBuf,
    doveadm_path: PathBuf,
    doveadm_auth_socket_path: Option<PathBuf>,
    doveadm_userdb_socket_path: Option<PathBuf>,
    mailbox_helper_socket_path: Option<PathBuf>,
    sendmail_path: PathBuf,
    render_policy: RenderingPolicy,
}

impl RuntimeBrowserGateway {
    /// Builds the runtime gateway from validated configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            authentication_policy: AuthenticationPolicy::default(),
            totp_policy: TotpPolicy {
                allowed_skew_steps: config.totp_allowed_skew_steps,
                ..TotpPolicy::default()
            },
            login_throttle_policy: LoginThrottlePolicy {
                max_failures: config.login_throttle_max_failures,
                failure_window_seconds: config.login_throttle_window_seconds,
                lockout_seconds: config.login_throttle_lockout_seconds,
            },
            session_lifetime_seconds: config.session_lifetime_seconds,
            session_dir: config.state_layout.session_dir.clone(),
            login_throttle_dir: config.state_layout.cache_dir.join("login-throttle"),
            totp_secret_dir: config.state_layout.totp_secret_dir.clone(),
            doveadm_path: PathBuf::from("/usr/local/bin/doveadm"),
            doveadm_auth_socket_path: config.doveadm_auth_socket_path.clone(),
            doveadm_userdb_socket_path: config.doveadm_userdb_socket_path.clone(),
            mailbox_helper_socket_path: config.mailbox_helper_socket_path.clone(),
            sendmail_path: PathBuf::from("/usr/sbin/sendmail"),
            render_policy: RenderingPolicy::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(temp_root: &std::path::Path) -> Self {
        Self {
            authentication_policy: AuthenticationPolicy::default(),
            totp_policy: TotpPolicy::default(),
            login_throttle_policy: LoginThrottlePolicy {
                max_failures: 5,
                failure_window_seconds: 300,
                lockout_seconds: 600,
            },
            session_lifetime_seconds: 3600,
            session_dir: temp_root.join("sessions"),
            login_throttle_dir: temp_root.join("cache").join("login-throttle"),
            totp_secret_dir: temp_root.join("totp"),
            doveadm_path: PathBuf::from("/nonexistent/doveadm"),
            doveadm_auth_socket_path: None,
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: None,
            sendmail_path: PathBuf::from("/usr/sbin/sendmail"),
            render_policy: RenderingPolicy::default(),
        }
    }

    /// Builds the current send-path service around the local sendmail surface.
    fn build_submission_service(
        &self,
    ) -> SubmissionService<SendmailSubmissionBackend<SystemCommandExecutor>> {
        SubmissionService::new(SendmailSubmissionBackend::new(
            SystemCommandExecutor,
            self.sendmail_path.clone(),
        ))
    }

    /// Builds the current attachment-download service from the MIME policy.
    fn build_attachment_download_service(&self) -> AttachmentDownloadService {
        AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
    }
}

impl BrowserGateway for RuntimeBrowserGateway {
    fn login(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> BrowserLoginOutcome {
        self.login_impl(context, username, password, totp_code)
    }

    fn validate_session(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome {
        self.validate_session_impl(context, presented_token)
    }

    fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome {
        self.logout_impl(context, presented_token)
    }

    fn list_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSessionListOutcome {
        self.list_sessions_impl(context, validated_session)
    }

    fn revoke_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        session_id: &str,
    ) -> BrowserSessionRevokeOutcome {
        self.revoke_session_impl(context, validated_session, session_id)
    }

    fn list_mailboxes(
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

    fn list_messages(
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

    fn search_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        query: &str,
    ) -> BrowserMessageSearchOutcome {
        let request =
            match MessageSearchRequest::new(MessageSearchPolicy::default(), mailbox_name, query) {
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
                    mailbox_name,
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

    fn view_message(
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
            } => match PlainTextMessageRenderer::new(self.render_policy)
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
            },
            MessageViewDecision::Denied { public_reason } => BrowserMessageViewOutcome {
                decision: BrowserMessageViewDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events,
            },
        }
    }

    fn download_attachment(
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

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
        attachments: &[UploadedAttachment],
    ) -> BrowserSendOutcome {
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

        let outcome = self
            .build_submission_service()
            .submit_for_validated_session(context, validated_session, &request);

        match outcome.decision {
            SubmissionDecision::Submitted { .. } => BrowserSendOutcome {
                decision: BrowserSendDecision::Submitted,
                audit_events: vec![outcome.audit_event],
            },
            SubmissionDecision::Denied { public_reason } => BrowserSendOutcome {
                decision: BrowserSendDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        source_mailbox_name: &str,
        uid: u64,
        destination_mailbox_name: &str,
    ) -> BrowserMessageMoveOutcome {
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

        let outcome = MessageMoveService::new(self.build_message_move_backend())
            .move_for_validated_session(context, validated_session, &request);

        match outcome.decision {
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
                audit_events: vec![outcome.audit_event],
            },
            MessageMoveDecision::Denied { public_reason } => BrowserMessageMoveOutcome {
                decision: BrowserMessageMoveDecision::Denied {
                    public_reason: public_reason.as_str().to_string(),
                },
                audit_events: vec![outcome.audit_event],
            },
        }
    }
}
