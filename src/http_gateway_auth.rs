use super::*;

impl RuntimeBrowserGateway {
    /// Builds the current auth service around `doveadm auth test`.
    pub(super) fn build_auth_service(
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
    pub(super) fn build_factor_service(
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
    pub(super) fn build_session_service(
        &self,
    ) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
        SessionService::new(
            FileSessionStore::new(self.session_dir.clone()),
            SystemTimeProvider,
            SystemRandomSource,
            self.session_lifetime_seconds,
            self.session_idle_timeout_seconds,
        )
    }

    /// Builds the current file-backed login-throttle service.
    pub(super) fn build_login_throttle_service(
        &self,
    ) -> LoginThrottleService<FileLoginThrottleStore, SystemTimeProvider> {
        LoginThrottleService::new(
            FileLoginThrottleStore::new(self.login_throttle_dir.clone()),
            SystemTimeProvider,
            self.login_throttle_policy,
        )
    }

    /// Projects persisted session metadata into a browser-safe summary.
    pub(super) fn visible_session(record: crate::session::SessionRecord) -> BrowserVisibleSession {
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

    /// Records a non-fatal throttle-store failure so operators can diagnose
    /// missing abuse resistance without crashing the login path.
    pub(super) fn build_login_throttle_store_error_event(
        &self,
        action: &'static str,
        message: &'static str,
        context: &AuthenticationContext,
        error: &LoginThrottleError,
    ) -> LogEvent {
        build_auth_warning_event(action, message, context)
            .with_field("reason", throttle_store_error_label(error))
    }

    pub(super) fn login_impl(
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
                audit_events.extend(check.audit_events);

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
                let mut effective_public_reason =
                    normalized_login_public_reason(public_reason).to_string();
                if public_reason == PublicFailureReason::InvalidCredentials {
                    match throttle_service.record_failure(context, username) {
                        Ok(record) => {
                            audit_events.extend(record.audit_events);
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
                        let mut effective_public_reason =
                            normalized_login_public_reason(public_reason).to_string();
                        if public_reason == PublicFailureReason::InvalidSecondFactor {
                            match throttle_service.record_failure(context, username) {
                                Ok(record) => {
                                    audit_events.extend(record.audit_events);
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
                                    Ok(throttle_audit_events) => {
                                        audit_events.extend(throttle_audit_events)
                                    }
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

    pub(super) fn validate_session_impl(
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

    pub(super) fn logout_impl(
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

    pub(super) fn list_sessions_impl(
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
                    session_lifetime_seconds: self.session_lifetime_seconds,
                    session_idle_timeout_seconds: self.session_idle_timeout_seconds,
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

    pub(super) fn revoke_session_impl(
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

    pub(super) fn revoke_sessions_impl(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        scope: BrowserSessionRevokeScope,
    ) -> BrowserSessionRevokeOutcome {
        let service = self.build_session_service();
        let result = match scope {
            BrowserSessionRevokeScope::OtherSessions => service.revoke_all_for_user_except(
                context,
                &validated_session.record.canonical_username,
                &validated_session.record.session_id,
            ),
            BrowserSessionRevokeScope::AllSessions => {
                service.revoke_all_for_user(context, &validated_session.record.canonical_username)
            }
        };

        match result {
            Ok(revoked_sessions) => {
                let revoked_current_session = revoked_sessions.iter().any(|revoked| {
                    revoked.record.session_id == validated_session.record.session_id
                });
                let mut audit_events = revoked_sessions
                    .iter()
                    .map(|revoked| revoked.audit_event.clone())
                    .collect::<Vec<_>>();
                audit_events.push(
                    build_http_info_event(
                        "session_bulk_revoked",
                        "browser session bulk revocation completed",
                        context,
                    )
                    .with_field(
                        "canonical_username",
                        validated_session.record.canonical_username.clone(),
                    )
                    .with_field(
                        "scope",
                        match scope {
                            BrowserSessionRevokeScope::OtherSessions => "other_sessions",
                            BrowserSessionRevokeScope::AllSessions => "all_sessions",
                        },
                    )
                    .with_field("revoked_count", revoked_sessions.len().to_string())
                    .with_field(
                        "revoked_current_session",
                        revoked_current_session.to_string(),
                    ),
                );

                BrowserSessionRevokeOutcome {
                    decision: BrowserSessionRevokeDecision::RevokedMany {
                        revoked_count: revoked_sessions.len(),
                        revoked_current_session,
                    },
                    audit_events,
                }
            }
            Err(error) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Denied {
                    public_reason: "temporarily_unavailable".to_string(),
                },
                audit_events: vec![build_http_warning_event(
                    "session_bulk_revoke_failed",
                    "browser session bulk revoke failed",
                    context,
                )
                .with_field("reason", session_error_label(&error))],
            },
        }
    }
}

fn normalized_login_public_reason(public_reason: PublicFailureReason) -> &'static str {
    match public_reason {
        PublicFailureReason::InvalidSecondFactor => {
            PublicFailureReason::InvalidCredentials.as_str()
        }
        _ => public_reason.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_second_factor_rejection_to_generic_login_failure_reason() {
        assert_eq!(
            normalized_login_public_reason(PublicFailureReason::InvalidSecondFactor),
            PublicFailureReason::InvalidCredentials.as_str()
        );
    }

    #[test]
    fn preserves_non_second_factor_login_failure_reasons() {
        assert_eq!(
            normalized_login_public_reason(PublicFailureReason::InvalidCredentials),
            PublicFailureReason::InvalidCredentials.as_str()
        );
        assert_eq!(
            normalized_login_public_reason(PublicFailureReason::InvalidRequest),
            PublicFailureReason::InvalidRequest.as_str()
        );
        assert_eq!(
            normalized_login_public_reason(PublicFailureReason::TemporarilyUnavailable),
            PublicFailureReason::TemporarilyUnavailable.as_str()
        );
    }
}
