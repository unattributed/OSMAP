// Opt-in browser fixture adapter over the production session service/store.
// Synthetic password/TOTP checks remain in StubGateway. This module must only
// be registered beneath the HTTP test module and rooted in temporary storage.
use super::*;
use crate::session::{FileSessionStore, SessionService, SystemRandomSource};
use crate::totp::SystemTimeProvider;

#[derive(Debug, Clone)]
pub(super) struct FixtureSessions {
    root: PathBuf,
}

impl FixtureSessions {
    pub(super) fn new(root: PathBuf) -> Self {
        assert!(root.is_absolute(), "fixture session root must be absolute");
        Self { root }
    }

    fn service(&self) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
        SessionService::new(
            FileSessionStore::new(&self.root),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
    }

    pub(super) fn login(
        &self,
        context: &AuthenticationContext,
        username: &str,
        appearance: AppearancePreference,
    ) -> BrowserLoginOutcome {
        match self
            .service()
            .issue(context, username, RequiredSecondFactor::Totp)
        {
            Ok(issued) => BrowserLoginOutcome {
                decision: BrowserLoginDecision::Authenticated {
                    canonical_username: issued.record.canonical_username,
                    appearance,
                    presentation: AppearanceSettings { theme: appearance, ..AppearanceSettings::default() },
                    reading: crate::reading_preferences::ReadingPreferences::default(),
                    session_token: issued.token,
                },
                audit_events: vec![issued.audit_event],
            },
            Err(_) => BrowserLoginOutcome {
                decision: BrowserLoginDecision::Denied {
                    public_reason: "temporarily_unavailable".into(),
                },
                audit_events: Vec::new(),
            },
        }
    }

    pub(super) fn validate(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome {
        let result = SessionToken::new(presented_token)
            .and_then(|token| self.service().validate(context, &token));
        match result {
            Ok(session) => BrowserSessionValidationOutcome {
                audit_events: vec![session.audit_event.clone()],
                decision: BrowserSessionDecision::Valid {
                    validated_session: Box::new(session),
                },
            },
            Err(_) => BrowserSessionValidationOutcome {
                decision: BrowserSessionDecision::Invalid,
                audit_events: Vec::new(),
            },
        }
    }

    pub(super) fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome {
        let result = SessionToken::new(presented_token)
            .and_then(|token| self.service().revoke_by_token(context, &token));
        match result {
            Ok(revoked) => BrowserLogoutOutcome {
                session_was_revoked: true,
                audit_events: vec![revoked.audit_event],
            },
            Err(_) => BrowserLogoutOutcome {
                session_was_revoked: false,
                audit_events: Vec::new(),
            },
        }
    }

    pub(super) fn list(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> BrowserSessionListOutcome {
        match self
            .service()
            .list_for_user(&session.record.canonical_username)
        {
            Ok(records) => BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Listed {
                    canonical_username: session.record.canonical_username.clone(),
                    session_lifetime_seconds: 3600,
                    session_idle_timeout_seconds: 1800,
                    sessions: records.into_iter().map(visible_session).collect(),
                },
                audit_events: Vec::new(),
            },
            Err(_) => BrowserSessionListOutcome {
                decision: BrowserSessionListDecision::Denied {
                    public_reason: "temporarily_unavailable".into(),
                },
                audit_events: Vec::new(),
            },
        }
    }

    fn denied(reason: &str) -> BrowserSessionRevokeOutcome {
        BrowserSessionRevokeOutcome {
            decision: BrowserSessionRevokeDecision::Denied {
                public_reason: reason.into(),
            },
            audit_events: Vec::new(),
        }
    }

    pub(super) fn revoke(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        target: &str,
    ) -> BrowserSessionRevokeOutcome {
        if target.len() != crate::session::SESSION_ID_HEX_LEN
            || !target.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Self::denied("invalid_request");
        }
        let service = self.service();
        // Preserve the production gateway's owner check before using the real
        // service's ID-based revoke. Never let a fixture bypass account scope.
        match service.list_for_user(&session.record.canonical_username) {
            Ok(records) if records.iter().any(|record| record.session_id == target) => (),
            Ok(_) => return Self::denied("not_found"),
            Err(_) => return Self::denied("temporarily_unavailable"),
        }
        match service.revoke(context, target) {
            Ok(revoked) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::Revoked {
                    revoked_current_session: revoked.record.session_id == session.record.session_id,
                    revoked_session_id: revoked.record.session_id,
                },
                audit_events: vec![revoked.audit_event],
            },
            Err(_) => Self::denied("temporarily_unavailable"),
        }
    }

    pub(super) fn revoke_many(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        scope: BrowserSessionRevokeScope,
    ) -> BrowserSessionRevokeOutcome {
        let service = self.service();
        let result = match scope {
            BrowserSessionRevokeScope::OtherSessions => service.revoke_all_for_user_except(
                context,
                &session.record.canonical_username,
                &session.record.session_id,
            ),
            BrowserSessionRevokeScope::AllSessions => {
                service.revoke_all_for_user(context, &session.record.canonical_username)
            }
        };
        match result {
            Ok(revoked) => BrowserSessionRevokeOutcome {
                decision: BrowserSessionRevokeDecision::RevokedMany {
                    revoked_count: revoked.len(),
                    revoked_current_session: revoked
                        .iter()
                        .any(|entry| entry.record.session_id == session.record.session_id),
                },
                audit_events: revoked.into_iter().map(|entry| entry.audit_event).collect(),
            },
            Err(_) => Self::denied("temporarily_unavailable"),
        }
    }
}

fn visible_session(record: crate::session::SessionRecord) -> BrowserVisibleSession {
    let agent = record.user_agent.as_str();
    let label = if agent.contains("Edg/") {
        "Edge"
    } else if agent.contains("Firefox/") {
        "Firefox"
    } else if agent.contains("Chrome/") {
        "Chrome"
    } else if agent.contains("Safari/") {
        "Safari"
    } else {
        "Unknown browser"
    };
    BrowserVisibleSession {
        session_id: record.session_id,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        last_seen_at: record.last_seen_at,
        revoked_at: record.revoked_at,
        device_label: label.into(),
        remote_addr: record.remote_addr,
        user_agent: record.user_agent,
        factor: record.factor,
    }
}

#[test]
fn fixture_uses_persistent_sessions_and_account_scoped_revocation() {
    let root = std::env::temp_dir().join(format!(
        "osmap-session-fixture-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let fixture = FixtureSessions::new(root.join("sessions"));
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "session-fixture",
        "127.0.0.1",
        "Firefox/Synthetic",
    )
    .unwrap();
    let issue = |username| match fixture
        .login(&context, username, AppearancePreference::System)
        .decision
    {
        BrowserLoginDecision::Authenticated { session_token, .. } => session_token,
        _ => panic!("synthetic session issuance failed"),
    };
    let current = issue("alice@example.com");
    let other = issue("alice@example.com");
    let foreign = issue("bob@example.com");
    let validated = |token: &SessionToken| match fixture.validate(&context, token.as_str()).decision
    {
        BrowserSessionDecision::Valid { validated_session } => *validated_session,
        _ => panic!("synthetic session validation failed"),
    };
    let current_session = validated(&current);
    let foreign_session = validated(&foreign);
    assert!(matches!(
        fixture
            .revoke(
                &context,
                &current_session,
                &foreign_session.record.session_id
            )
            .decision,
        BrowserSessionRevokeDecision::Denied { .. }
    ));
    assert!(matches!(
        fixture
            .revoke_many(
                &context,
                &current_session,
                BrowserSessionRevokeScope::OtherSessions
            )
            .decision,
        BrowserSessionRevokeDecision::RevokedMany {
            revoked_count: 1,
            revoked_current_session: false
        }
    ));
    assert!(matches!(
        fixture.validate(&context, other.as_str()).decision,
        BrowserSessionDecision::Invalid
    ));
    assert!(matches!(
        fixture.validate(&context, current.as_str()).decision,
        BrowserSessionDecision::Valid { .. }
    ));
    assert!(matches!(
        fixture.validate(&context, foreign.as_str()).decision,
        BrowserSessionDecision::Valid { .. }
    ));
    let reopened = FixtureSessions::new(root.join("sessions"));
    assert!(matches!(
        reopened.validate(&context, other.as_str()).decision,
        BrowserSessionDecision::Invalid
    ));
    assert!(matches!(
        reopened
            .revoke_many(
                &context,
                &current_session,
                BrowserSessionRevokeScope::AllSessions
            )
            .decision,
        BrowserSessionRevokeDecision::RevokedMany {
            revoked_count: 1,
            revoked_current_session: true
        }
    ));
    assert!(matches!(
        reopened.validate(&context, current.as_str()).decision,
        BrowserSessionDecision::Invalid
    ));
    assert!(
        reopened
            .logout(&context, foreign.as_str())
            .session_was_revoked
    );
    fs::remove_dir_all(root).unwrap();
}
