use super::*;

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

    /// Builds the current auth service around `doveadm auth test`.
    fn build_auth_service(
        &self,
    ) -> AuthenticationService<DoveadmAuthTestBackend<SystemCommandExecutor>> {
        AuthenticationService::new(
            self.authentication_policy,
            DoveadmAuthTestBackend::new(
                SystemCommandExecutor,
                self.doveadm_path.clone(),
                self.doveadm_auth_socket_path.clone(),
                "imap",
            ),
        )
    }

    /// Builds the current second-factor service around the file-backed TOTP store.
    fn build_factor_service(
        &self,
    ) -> SecondFactorService<TotpVerifier<FileTotpSecretStore, SystemTimeProvider>> {
        SecondFactorService::new(
            self.authentication_policy,
            TotpVerifier::new(
                FileTotpSecretStore::new(self.totp_secret_dir.clone()),
                SystemTimeProvider,
                self.totp_policy,
            ),
        )
    }

    /// Builds the current file-backed session service.
    fn build_session_service(
        &self,
    ) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
        SessionService::new(
            FileSessionStore::new(self.session_dir.clone()),
            SystemTimeProvider,
            SystemRandomSource,
            self.session_lifetime_seconds,
        )
    }

    /// Builds the current file-backed login-throttle service.
    fn build_login_throttle_service(
        &self,
    ) -> LoginThrottleService<FileLoginThrottleStore, SystemTimeProvider> {
        LoginThrottleService::new(
            FileLoginThrottleStore::new(self.login_throttle_dir.clone()),
            SystemTimeProvider,
            self.login_throttle_policy,
        )
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

    /// Projects persisted session metadata into a browser-safe summary.
    fn visible_session(record: crate::session::SessionRecord) -> BrowserVisibleSession {
        BrowserVisibleSession {
            session_id: record.session_id,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            last_seen_at: record.last_seen_at,
            revoked_at: record.revoked_at,
            remote_addr: record.remote_addr,
            user_agent: record.user_agent,
            factor: record.factor,
        }
    }

    /// Selects the current message-search backend based on whether the local
    /// mailbox helper is configured for read-path proxying.
    fn build_message_search_backend(&self) -> MessageSearchRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => {
                MessageSearchRuntimeBackend::Helper(MailboxHelperMessageSearchBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageSearchPolicy::default(),
                ))
            }
            None => MessageSearchRuntimeBackend::Direct(
                DoveadmMessageSearchBackend::new(
                    MessageSearchPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Selects the current message-view backend based on whether the local
    /// mailbox helper is configured for read-path proxying.
    fn build_message_view_backend(&self) -> MessageViewRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => {
                MessageViewRuntimeBackend::Helper(MailboxHelperMessageViewBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageViewPolicy::default(),
                ))
            }
            None => MessageViewRuntimeBackend::Direct(
                DoveadmMessageViewBackend::new(
                    MessageViewPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Selects the current message-move backend based on whether the local
    /// mailbox helper is configured for mailbox-authoritative operations.
    fn build_message_move_backend(&self) -> MessageMoveRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => MessageMoveRuntimeBackend::Helper(
                MailboxHelperMessageMoveBackend::new(socket_path, MailboxHelperPolicy::default()),
            ),
            None => MessageMoveRuntimeBackend::Direct(
                DoveadmMessageMoveBackend::new(SystemCommandExecutor, self.doveadm_path.clone())
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Records a non-fatal throttle-store failure so operators can diagnose
    /// missing abuse resistance without crashing the login path.
    fn build_login_throttle_store_error_event(
        &self,
        action: &'static str,
        message: &'static str,
        context: &AuthenticationContext,
        error: &LoginThrottleError,
    ) -> LogEvent {
        build_auth_warning_event(action, message, context)
            .with_field("reason", login_throttle_error_label(error))
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
        let mut audit_events = Vec::new();
        let throttle_service = self.build_login_throttle_service();

        match throttle_service.check(context, username) {
            Ok(check) => {
                if let Some(audit_event) = check.audit_event {
                    audit_events.push(audit_event);
                }

                if let LoginThrottleDecision::Throttled { .. } = check.decision {
                    return BrowserLoginOutcome {
                        decision: BrowserLoginDecision::Denied {
                            public_reason: TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string(),
                        },
                        audit_events,
                    };
                }
            }
            Err(error) => audit_events.push(self.build_login_throttle_store_error_event(
                "login_throttle_check_failed",
                "login throttle check failed",
                context,
                &error,
            )),
        }

        let auth_outcome = self
            .build_auth_service()
            .authenticate(context, username, password);
        audit_events.push(auth_outcome.audit_event.clone());

        match auth_outcome.decision {
            AuthenticationDecision::Denied { public_reason } => {
                let mut effective_public_reason = public_reason.as_str().to_string();
                if public_reason == PublicFailureReason::InvalidCredentials {
                    match throttle_service.record_failure(context, username) {
                        Ok(record) => {
                            if let Some(audit_event) = record.audit_event {
                                audit_events.push(audit_event);
                            }
                            if record.lockout_engaged {
                                effective_public_reason =
                                    TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string();
                            }
                        }
                        Err(error) => {
                            audit_events.push(self.build_login_throttle_store_error_event(
                                "login_throttle_record_failed",
                                "login throttle failure recording failed",
                                context,
                                &error,
                            ))
                        }
                    }
                }

                BrowserLoginOutcome {
                    decision: BrowserLoginDecision::Denied {
                        public_reason: effective_public_reason,
                    },
                    audit_events,
                }
            }
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                let factor_outcome = self.build_factor_service().verify(
                    context,
                    canonical_username.clone(),
                    second_factor,
                    totp_code,
                );
                audit_events.push(factor_outcome.audit_event.clone());

                match factor_outcome.decision {
                    AuthenticationDecision::Denied { public_reason } => {
                        let mut effective_public_reason = public_reason.as_str().to_string();
                        if public_reason == PublicFailureReason::InvalidSecondFactor {
                            match throttle_service.record_failure(context, username) {
                                Ok(record) => {
                                    if let Some(audit_event) = record.audit_event {
                                        audit_events.push(audit_event);
                                    }
                                    if record.lockout_engaged {
                                        effective_public_reason =
                                            TOO_MANY_ATTEMPTS_PUBLIC_REASON.to_string();
                                    }
                                }
                                Err(error) => {
                                    audit_events.push(self.build_login_throttle_store_error_event(
                                        "login_throttle_record_failed",
                                        "login throttle failure recording failed",
                                        context,
                                        &error,
                                    ))
                                }
                            }
                        }

                        BrowserLoginOutcome {
                            decision: BrowserLoginDecision::Denied {
                                public_reason: effective_public_reason,
                            },
                            audit_events,
                        }
                    }
                    AuthenticationDecision::AuthenticatedPendingSession { canonical_username } => {
                        match self.build_session_service().issue(
                            context,
                            &canonical_username,
                            second_factor,
                        ) {
                            Ok(issued_session) => {
                                audit_events.push(issued_session.audit_event.clone());
                                match throttle_service.clear_success(context, username) {
                                    Ok(Some(audit_event)) => audit_events.push(audit_event),
                                    Ok(None) => {}
                                    Err(error) => audit_events.push(
                                        self.build_login_throttle_store_error_event(
                                            "login_throttle_clear_failed",
                                            "login throttle clear failed after successful authentication",
                                            context,
                                            &error,
                                        ),
                                    ),
                                }
                                BrowserLoginOutcome {
                                    decision: BrowserLoginDecision::Authenticated {
                                        canonical_username,
                                        session_token: issued_session.token,
                                    },
                                    audit_events,
                                }
                            }
                            Err(error) => {
                                audit_events.push(
                                    build_http_warning_event(
                                        "session_issue_failed",
                                        "session issuance failed during browser login",
                                        context,
                                    )
                                    .with_field("reason", session_error_label(&error)),
                                );
                                BrowserLoginOutcome {
                                    decision: BrowserLoginDecision::Denied {
                                        public_reason: PublicFailureReason::TemporarilyUnavailable
                                            .as_str()
                                            .to_string(),
                                    },
                                    audit_events,
                                }
                            }
                        }
                    }
                    AuthenticationDecision::MfaRequired { .. } => BrowserLoginOutcome {
                        decision: BrowserLoginDecision::Denied {
                            public_reason: PublicFailureReason::TemporarilyUnavailable
                                .as_str()
                                .to_string(),
                        },
                        audit_events,
                    },
                }
            }
            AuthenticationDecision::AuthenticatedPendingSession { .. } => BrowserLoginOutcome {
                decision: BrowserLoginDecision::Denied {
                    public_reason: PublicFailureReason::TemporarilyUnavailable
                        .as_str()
                        .to_string(),
                },
                audit_events,
            },
        }
    }

    fn validate_session(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome {
        let token = match SessionToken::new(presented_token.to_string()) {
            Ok(token) => token,
            Err(_) => {
                return BrowserSessionValidationOutcome {
                    decision: BrowserSessionDecision::Invalid,
                    audit_events: Vec::new(),
                };
            }
        };

        match self.build_session_service().validate(context, &token) {
            Ok(validated_session) => BrowserSessionValidationOutcome {
                decision: BrowserSessionDecision::Valid {
                    validated_session: Box::new(validated_session.clone()),
                },
                audit_events: vec![validated_session.audit_event],
            },
            Err(error) => BrowserSessionValidationOutcome {
                decision: BrowserSessionDecision::Invalid,
                audit_events: vec![build_http_warning_event(
                    "session_validation_failed",
                    "browser session validation failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome {
        let token = match SessionToken::new(presented_token.to_string()) {
            Ok(token) => token,
            Err(_) => {
                return BrowserLogoutOutcome {
                    session_was_revoked: false,
                    audit_events: Vec::new(),
                };
            }
        };

        match self
            .build_session_service()
            .revoke_by_token(context, &token)
        {
            Ok(revoked_session) => BrowserLogoutOutcome {
                session_was_revoked: true,
                audit_events: vec![revoked_session.audit_event],
            },
            Err(error) => BrowserLogoutOutcome {
                session_was_revoked: false,
                audit_events: vec![build_http_warning_event(
                    "session_revoke_failed",
                    "browser session revocation failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn list_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSessionListOutcome {
        match self
            .build_session_service()
            .list_for_user(&validated_session.record.canonical_username)
        {
            Ok(records) => BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Listed {
                    canonical_username: validated_session.record.canonical_username.clone(),
                    sessions: records.into_iter().map(Self::visible_session).collect(),
                },
                audit_events: vec![build_http_info_event(
                    "session_listed",
                    "browser session list returned",
                    context,
                )
                .with_field(
                    "canonical_username",
                    validated_session.record.canonical_username.clone(),
                )],
            },
            Err(error) => BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_list_failed",
                    "browser session listing failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn revoke_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        session_id: &str,
    ) -> BrowserSessionRevokeOutcome {
        if session_id.len() != SESSION_ID_HEX_LEN
            || !session_id.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "invalid_request".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_revoke_request_rejected",
                    "browser session revoke request validation failed",
                    context,
                )
                .with_field("reason", "invalid_session_id")],
            };
        }

        let owned_session = match self
            .build_session_service()
            .list_for_user(&validated_session.record.canonical_username)
        {
            Ok(records) => records
                .into_iter()
                .any(|record| record.session_id == session_id),
            Err(error) => {
                return BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::Denied {
                        public_reason: "temporarily_unavailable".to_string(),
                    },
                    audit_events: vec![build_http_warning_event(
                        "session_revoke_lookup_failed",
                        "browser session ownership lookup failed",
                        context,
                    )
                    .with_field("reason", session_error_label(&error))],
                };
            }
        };

        if !owned_session {
            return BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "not_found".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_revoke_denied",
                    "browser session revoke target not found for user",
                    context,
                )
                .with_field(
                    "canonical_username",
                    validated_session.record.canonical_username.clone(),
                )
                .with_field("session_id", session_id.to_string())],
            };
        }

        match self.build_session_service().revoke(context, session_id) {
            Ok(revoked_session) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Revoked {
                    revoked_session_id: revoked_session.record.session_id.clone(),
                    revoked_current_session: revoked_session.record.session_id
                        == validated_session.record.session_id,
                },
                audit_events: vec![revoked_session.audit_event],
            },
            Err(error) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_revoke_failed",
                    "browser session revoke failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }

    fn list_mailboxes(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome {
        let backend = match &self.mailbox_helper_socket_path {
            Some(socket_path) => MailboxListRuntimeBackend::Helper(
                MailboxHelperMailboxListBackend::new(socket_path, MailboxHelperPolicy::default()),
            ),
            None => MailboxListRuntimeBackend::Direct(
                DoveadmMailboxListBackend::new(
                    MailboxListingPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        };
        let outcome = MailboxListingService::new(backend)
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

        let backend = match &self.mailbox_helper_socket_path {
            Some(socket_path) => {
                MessageListRuntimeBackend::Helper(MailboxHelperMessageListBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageListPolicy::default(),
                ))
            }
            None => MessageListRuntimeBackend::Direct(
                DoveadmMessageListBackend::new(
                    MessageListPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        };
        let outcome = MessageListService::new(backend).list_for_validated_session(
            context,
            validated_session,
            &request,
        );

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

/// Selects the current mailbox-list backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MailboxListRuntimeBackend {
    Direct(DoveadmMailboxListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMailboxListBackend),
}

impl crate::mailbox::MailboxBackend for MailboxListRuntimeBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_mailboxes(canonical_username),
            Self::Helper(backend) => backend.list_mailboxes(canonical_username),
        }
    }
}

/// Selects the current message-list backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageListRuntimeBackend {
    Direct(DoveadmMessageListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageListBackend),
}

impl crate::mailbox::MessageListBackend for MessageListRuntimeBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_messages(canonical_username, request),
            Self::Helper(backend) => backend.list_messages(canonical_username, request),
        }
    }
}

/// Selects the current message-search backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageSearchRuntimeBackend {
    Direct(DoveadmMessageSearchBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageSearchBackend),
}

impl crate::mailbox::MessageSearchBackend for MessageSearchRuntimeBackend {
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.search_messages(canonical_username, request),
            Self::Helper(backend) => backend.search_messages(canonical_username, request),
        }
    }
}

/// Selects the current message-move backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageMoveRuntimeBackend {
    Direct(DoveadmMessageMoveBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageMoveBackend),
}

impl crate::mailbox::MessageMoveBackend for MessageMoveRuntimeBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.move_message(canonical_username, request),
            Self::Helper(backend) => backend.move_message(canonical_username, request),
        }
    }
}

/// Selects the current message-view backend without widening the browser
/// runtime's authority when a local helper is configured.
enum MessageViewRuntimeBackend {
    Direct(DoveadmMessageViewBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageViewBackend),
}

impl crate::mailbox::MessageViewBackend for MessageViewRuntimeBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<crate::mailbox::MessageView, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.fetch_message(canonical_username, request),
            Self::Helper(backend) => backend.fetch_message(canonical_username, request),
        }
    }
}
