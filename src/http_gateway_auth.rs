use super::*;
use crate::logging::audit_session_ref;

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
            )
            // Dovecot intentionally delays repeated failures for as long as
            // 15 seconds. Authentication therefore has a distinct bounded
            // deadline instead of inheriting the shorter mailbox-work cap.
            .with_command_timeout_secs(self.auth_backend_timeout_secs),
        )
    }

    /// Builds the current second-factor service around the file-backed TOTP store.
    pub(super) fn build_factor_service(
        &self,
    ) -> SecondFactorService<TotpVerifier<FileTotpSecretStore, SystemTimeProvider>> {
        SecondFactorService::new(
            self.authentication_policy,
            TotpVerifier::new(
                FileTotpSecretStore::new(self.totp_secret_dir.clone())
                    .with_replay_dir(self.totp_replay_dir.clone()),
                SystemTimeProvider,
                self.totp_policy,
            ),
        )
    }

    /// Builds the current file-backed session service.
    pub(super) fn build_session_service(
        &self,
    ) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
        let service = SessionService::new(
            FileSessionStore::new(self.session_dir.clone()),
            SystemTimeProvider,
            SystemRandomSource,
            self.session_lifetime_seconds,
            self.session_idle_timeout_seconds,
        );
        let authority: std::sync::Arc<dyn crate::account_admission::EpochAuthority> = match &self
            .account_runtime
        {
            AccountRuntimeCapability::Ready(ready) => {
                std::sync::Arc::new(ready.admission().clone())
            }
            AccountRuntimeCapability::Disabled if self.account_rollout.is_none() => return service,
            _ => std::sync::Arc::new(super::http_gateway_account::UnavailableAccountAuthority),
        };
        match &self.account_rollout {
            Some(account) => service.with_account_epoch_authority(account.clone(), authority),
            None => service.with_epoch_authority(authority),
        }
    }

    fn authenticate_account_primary(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
        captured: std::sync::Arc<std::sync::Mutex<Option<crate::account_admission::Admission>>>,
    ) -> crate::auth::AuthenticationOutcome {
        let selected = self.uses_account_runtime(username);
        let unavailable = || {
            AuthenticationService::new(
                self.authentication_policy,
                super::http_gateway_account::UnavailableAccountAuthority,
            )
            .authenticate(context, username, password)
        };
        let outcome = if selected {
            match &self.account_runtime {
                AccountRuntimeCapability::Ready(ready) => AuthenticationService::new(
                    self.authentication_policy,
                    crate::account_admission_runtime::CredentialBackend {
                        client: ready.admission().clone(),
                        captured,
                    },
                )
                .authenticate(context, username, password),
                AccountRuntimeCapability::ConfiguredUnavailable => unavailable(),
                AccountRuntimeCapability::Disabled if self.account_rollout.is_some() => {
                    unavailable()
                }
                AccountRuntimeCapability::Disabled => self
                    .build_auth_service()
                    .authenticate(context, username, password),
            }
        } else {
            self.build_auth_service()
                .authenticate(context, username, password)
        };
        if let AuthenticationDecision::MfaRequired {
            canonical_username, ..
        } = &outcome.decision
        {
            // A legacy alias cannot admit the selected canonical identity, and
            // selected authority cannot issue a session for an unrelated identity.
            if self.account_rollout.is_some()
                && selected != self.uses_account_runtime(canonical_username)
            {
                return unavailable();
            }
        }
        outcome
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
    pub(in crate::http) fn visible_session(
        record: crate::session::SessionRecord,
    ) -> BrowserVisibleSession {
        BrowserVisibleSession {
            session_id: record.session_id,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            last_seen_at: record.last_seen_at,
            revoked_at: record.revoked_at,
            device_label: session_device_label(&record.user_agent),
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

        let captured_admission = std::sync::Arc::new(std::sync::Mutex::new(None));
        let auth_outcome = self.authenticate_account_primary(
            context,
            username,
            password,
            captured_admission.clone(),
        );
        audit_events.push(auth_outcome.audit_event.clone());

        match auth_outcome.decision {
            AuthenticationDecision::Denied { public_reason } => {
                let mut effective_public_reason =
                    normalized_login_public_reason(public_reason).to_string();
                if records_login_throttle_failure(public_reason) {
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
                        if records_login_throttle_failure(public_reason) {
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
                        let authenticated_epoch = captured_admission.lock().ok().and_then(|v| {
                            v.as_ref()
                                .filter(|a| a.account == canonical_username)
                                .map(|a| a.epoch)
                        });
                        match self.build_session_service().issue_with_epoch(
                            context,
                            &canonical_username,
                            second_factor,
                            authenticated_epoch,
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
                                let presentation = AppearanceStore::new(&self.settings_dir)
                                    .load_settings(&canonical_username)
                                    .unwrap_or_else(|_| {
                                        audit_events.push(build_http_warning_event(
                                            "appearance_load_failed",
                                            "appearance preference unavailable at login",
                                            context,
                                        ));
                                        AppearanceSettings::default()
                                    });
                                let reading =
                                    crate::reading_preferences::ReadingPreferencesStore::new(
                                        &self.settings_dir,
                                    )
                                    .load(&canonical_username)
                                    .unwrap_or_else(|_| {
                                        audit_events.push(build_http_warning_event(
                                            "reading_preferences_load_failed",
                                            "reading preferences unavailable at login",
                                            context,
                                        ));
                                        crate::reading_preferences::ReadingPreferences::default()
                                    });
                                BrowserLoginOutcome {
                                    decision: BrowserLoginDecision::Authenticated {
                                        appearance: presentation.theme,
                                        presentation,
                                        reading,
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
                                        public_reason: normalized_login_public_reason(
                                            PublicFailureReason::TemporarilyUnavailable,
                                        )
                                        .to_string(),
                                    },
                                    audit_events,
                                }
                            }
                        }
                    }
                    AuthenticationDecision::MfaRequired { .. } => BrowserLoginOutcome {
                        decision: BrowserLoginDecision::Denied {
                            public_reason: normalized_login_public_reason(
                                PublicFailureReason::TemporarilyUnavailable,
                            )
                            .to_string(),
                        },
                        audit_events,
                    },
                }
            }
            AuthenticationDecision::AuthenticatedPendingSession { .. } => BrowserLoginOutcome {
                decision: BrowserLoginDecision::Denied {
                    public_reason: normalized_login_public_reason(
                        PublicFailureReason::TemporarilyUnavailable,
                    )
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
                .with_field("session_ref", audit_session_ref(session_id))],
            };
        }

        match self.build_session_service().revoke(context, session_id) {
            Ok(revoked_session) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Revoked {
                    newly_revoked: revoked_session.newly_revoked,
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
        PublicFailureReason::InvalidSecondFactor | PublicFailureReason::TemporarilyUnavailable => {
            PublicFailureReason::InvalidCredentials.as_str()
        }
        _ => public_reason.as_str(),
    }
}

fn records_login_throttle_failure(public_reason: PublicFailureReason) -> bool {
    matches!(
        public_reason,
        PublicFailureReason::InvalidCredentials | PublicFailureReason::InvalidSecondFactor
    )
}

fn session_device_label(user_agent: &str) -> String {
    let user_agent = user_agent.trim();
    if user_agent.is_empty() {
        return "Unknown device".to_string();
    }

    let browser = if user_agent.contains("Edg/") || user_agent.contains("EdgiOS/") {
        "Edge"
    } else if user_agent.contains("Firefox/") || user_agent.contains("FxiOS/") {
        "Firefox"
    } else if user_agent.contains("Chrome/") || user_agent.contains("CriOS/") {
        "Chrome"
    } else if user_agent.contains("Safari/") {
        "Safari"
    } else if user_agent.contains("OSMAP") || user_agent.contains("osmap") {
        "OSMAP validation client"
    } else {
        "Other browser"
    };

    let platform = if user_agent.contains("iPhone") || user_agent.contains("iPad") {
        Some("iOS")
    } else if user_agent.contains("Android") {
        Some("Android")
    } else if user_agent.contains("OpenBSD") {
        Some("OpenBSD")
    } else if user_agent.contains("FreeBSD") {
        Some("FreeBSD")
    } else if user_agent.contains("Windows") {
        Some("Windows")
    } else if user_agent.contains("Mac OS X") || user_agent.contains("Macintosh") {
        Some("macOS")
    } else if user_agent.contains("Linux") || user_agent.contains("X11") {
        Some("Linux")
    } else {
        None
    };

    match platform {
        Some(platform) => format!("{browser} on {platform}"),
        None => browser.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn accepted_legacy_primary_fixture(
        root: &std::path::Path,
        submitted: &str,
        canonical: &str,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let marker = root.join("accepted-primary");
        let executable = root.join("doveadm");
        let interpreter = if cfg!(target_os = "openbsd") {
            "/usr/local/bin/python3"
        } else {
            "/usr/bin/python3"
        };
        let marker_literal = serde_json::to_string(&marker).unwrap();
        std::fs::write(
            &executable,
            format!(
                "#!{interpreter}\nimport sys\nfrom pathlib import Path\nsys.stdin.read()\nPath({marker_literal}).write_bytes(b'called\\n')\nprint('passdb: {submitted} auth succeeded')\nprint('extra fields:')\nprint('  user={canonical}')\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        executable
    }

    #[cfg(unix)]
    #[test]
    fn disabled_password_runtime_preserves_ordinary_login_totp_and_session() {
        use crate::totp::TimeProvider;
        use hmac::{Hmac, Mac};
        use std::os::unix::fs::PermissionsExt;

        // Compare all owned paths and file bytes without rendering session tokens
        // in assertion output. This detects password-side state creation as well
        // as mutation of the existing session or factor/replay files.
        fn snapshot(
            root: &std::path::Path,
        ) -> std::collections::BTreeMap<PathBuf, Option<Vec<u8>>> {
            let mut entries = std::collections::BTreeMap::new();
            for entry in std::fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    entries.insert(path.clone(), None);
                    entries.extend(snapshot(&path));
                } else {
                    entries.insert(path.clone(), Some(std::fs::read(&path).unwrap()));
                }
            }
            entries
        }

        let root = std::env::temp_dir().join(format!(
            "osmap-disabled-password-login-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable =
            accepted_legacy_primary_fixture(&root, "alice@example.test", "alice@example.test");
        let mut env = std::collections::BTreeMap::new();
        env.insert("OSMAP_STATE_DIR".into(), root.to_str().unwrap().into());
        let config = AppConfig::from_env_map(&env).unwrap();
        assert!(config.account_runtime.is_none());
        let mut gateway = RuntimeBrowserGateway::from_config(&config);
        assert!(matches!(
            gateway.account_runtime,
            AccountRuntimeCapability::Disabled
        ));
        assert!(gateway.account_rollout.is_none());
        gateway.doveadm_path = executable;

        // The same public RFC6238 vector and real file-backed verifier used by
        // the paired-runtime regression; no accepting factor stub is involved.
        std::fs::create_dir_all(&gateway.totp_secret_dir).unwrap();
        std::fs::set_permissions(
            &gateway.totp_secret_dir,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let factor = FileTotpSecretStore::new(&gateway.totp_secret_dir)
            .secret_path_for_username("alice@example.test");
        std::fs::write(&factor, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        std::fs::set_permissions(&factor, std::fs::Permissions::from_mode(0o600)).unwrap();
        let counter = SystemTimeProvider.unix_timestamp() / 30;
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(b"12345678901234567890").unwrap();
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 15);
        let number =
            u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let code = format!("{:06}", number % 1_000_000);
        let context = AuthenticationContext {
            request_id: "disabled-password-login".into(),
            remote_addr: "127.0.0.1".into(),
            user_agent: "public fixture".into(),
        };
        let outcome = gateway.login(
            &context,
            "alice@example.test",
            "public synthetic credential",
            &code,
        );
        let BrowserLoginDecision::Authenticated {
            canonical_username,
            session_token,
            ..
        } = outcome.decision
        else {
            panic!("ordinary Runtime login refused with password mutation disabled");
        };
        assert_eq!(canonical_username, "alice@example.test");
        assert!(root.join("accepted-primary").exists());
        let BrowserSessionDecision::Valid { validated_session } = gateway
            .validate_session(&context, session_token.as_str())
            .decision
        else {
            panic!("ordinary Runtime session refused");
        };
        assert_eq!(validated_session.record.account_epoch, None);
        assert!(!gateway.password_change_available(&validated_session));
        let before = snapshot(&root);
        let request = crate::password_change::Request::new(
            "public synthetic credential",
            "New-public-passphrase",
            "New-public-passphrase",
            &code,
        )
        .unwrap();
        let password = gateway.change_own_password(
            &context,
            &validated_session,
            &session_token,
            request,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(
            password.decision,
            BrowserPasswordDecision::PrewriteRefused(crate::password_change::Error::Unavailable)
        );
        assert!(password.changed_at.is_none());
        assert!(
            snapshot(&root) == before,
            "unavailable password operation changed owned state"
        );
        assert!(!gateway.settings_dir.join("password-stepup-rate").exists());
        assert!(matches!(
            gateway
                .validate_session(&context, session_token.as_str())
                .decision,
            BrowserSessionDecision::Valid { .. }
        ));

        // Reconstructing the real verifier must retain the login's consumed
        // counter, including after the unavailable password action.
        let replay = gateway.build_factor_service().verify(
            &context,
            "alice@example.test",
            RequiredSecondFactor::Totp,
            &code,
        );
        assert!(matches!(
            replay.decision,
            AuthenticationDecision::Denied {
                public_reason: PublicFailureReason::InvalidSecondFactor
            }
        ));
        let sessions_before = std::fs::read_dir(&gateway.session_dir).unwrap().count();
        assert!(matches!(
            gateway
                .login(
                    &context,
                    "alice@example.test",
                    "public synthetic credential",
                    &code
                )
                .decision,
            BrowserLoginDecision::Denied { .. }
        ));
        assert_eq!(
            std::fs::read_dir(&gateway.session_dir).unwrap().count(),
            sessions_before
        );
        assert!(matches!(
            gateway
                .validate_session(&context, session_token.as_str())
                .decision,
            BrowserSessionDecision::Valid { .. }
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn configured_account_failure_never_uses_accepted_legacy_doveadm() {
        use std::os::unix::fs::PermissionsExt;
        for (configured, scope, submitted, canonical, expected_called, expected_accepted) in [
            (
                false,
                None,
                "alice@example.test",
                "alice@example.test",
                true,
                true,
            ),
            (
                true,
                None,
                "alice@example.test",
                "alice@example.test",
                false,
                false,
            ),
            (
                true,
                Some("alice@example.test"),
                "alice@example.test",
                "alice@example.test",
                false,
                false,
            ),
            (
                true,
                Some("alice@example.test"),
                "bob@example.test",
                "bob@example.test",
                true,
                true,
            ),
            (
                true,
                Some("alice@example.test"),
                "alice-alias",
                "alice@example.test",
                true,
                false,
            ),
        ] {
            let root = std::env::temp_dir().join(format!(
                "osmap-account-fallback-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = root.join("accepted-primary");
            let executable = accepted_legacy_primary_fixture(&root, submitted, canonical);
            let mut env = std::collections::BTreeMap::new();
            env.insert("OSMAP_STATE_DIR".into(), root.to_str().unwrap().into());
            if configured {
                for (name, file) in [
                    ("OSMAP_ACCOUNT_ADMISSION_SOCKET", "admission.sock"),
                    ("OSMAP_ACCOUNT_ADMISSION_KEY_FILE", "admission.key"),
                    ("OSMAP_ACCOUNT_MUTATION_SOCKET", "mutation.sock"),
                    ("OSMAP_ACCOUNT_MUTATION_KEY_FILE", "mutation.key"),
                    ("OSMAP_ACCOUNT_MUTATION_SESSION_PROOF_KEY_FILE", "proof.key"),
                ] {
                    env.insert(name.into(), root.join(file).to_str().unwrap().into());
                }
                env.insert("OSMAP_ACCOUNT_ADMISSION_HELPER_UID".into(), "1003".into());
                env.insert("OSMAP_ACCOUNT_MUTATION_HELPER_UID".into(), "1004".into());
            }
            if let Some(account) = scope {
                env.insert("OSMAP_ACCOUNT_ROLLOUT_ACCOUNT".into(), account.into());
            }
            let config = AppConfig::from_env_map(&env).unwrap();
            let mut gateway = RuntimeBrowserGateway::from_config(&config);
            gateway.doveadm_path = executable;
            let context = AuthenticationContext {
                request_id: "account-fallback".into(),
                remote_addr: "127.0.0.1".into(),
                user_agent: "public fixture".into(),
            };
            let outcome =
                gateway.login(&context, submitted, "public synthetic credential", "123456");
            let called = marker.exists();
            let accepted = outcome
                .audit_events
                .iter()
                .any(|event| event.action == "login_mfa_required");
            std::fs::remove_dir_all(&root).unwrap();
            assert_eq!(
                called, expected_called,
                "configured failure invoked legacy primary"
            );
            assert_eq!(
                accepted, expected_accepted,
                "the Disabled control must accept actual legacy primary"
            );
        }
    }

    #[test]
    fn normalizes_second_factor_rejection_to_generic_login_failure_reason() {
        assert_eq!(
            normalized_login_public_reason(PublicFailureReason::InvalidSecondFactor),
            PublicFailureReason::InvalidCredentials.as_str()
        );
    }

    #[test]
    fn normalizes_login_backend_failures_to_generic_login_failure_reason() {
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
            PublicFailureReason::InvalidCredentials.as_str()
        );
    }

    #[test]
    fn records_generic_login_failures_into_throttle_buckets() {
        assert!(records_login_throttle_failure(
            PublicFailureReason::InvalidCredentials
        ));
        assert!(records_login_throttle_failure(
            PublicFailureReason::InvalidSecondFactor
        ));
        assert!(!records_login_throttle_failure(
            PublicFailureReason::TemporarilyUnavailable
        ));
        assert!(!records_login_throttle_failure(
            PublicFailureReason::InvalidRequest
        ));
    }

    #[test]
    fn derives_stable_browser_visible_device_labels() {
        assert_eq!(
            session_device_label(
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
            ),
            "Firefox on Linux"
        );
        assert_eq!(
            session_device_label(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15"
            ),
            "Safari on macOS"
        );
        assert_eq!(
            session_device_label("osmap-live-v3-mime-html-proof"),
            "OSMAP validation client"
        );
        assert_eq!(session_device_label("   "), "Unknown device");
        assert_eq!(
            session_device_label("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Mobile/15E148 Safari/604.1"),
            "Safari on iOS"
        );
        assert_eq!(
            session_device_label("Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) FxiOS/140.0 Mobile/15E148 Safari/605.1.15"),
            "Firefox on iOS"
        );
        assert_eq!(
            session_device_label(
                "Mozilla/5.0 (Linux; Android 15) Chrome/140.0 Mobile Safari/537.36"
            ),
            "Chrome on Android"
        );
    }
}
