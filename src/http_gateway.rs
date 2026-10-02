use super::*;

#[path = "http_gateway_auth.rs"]
mod http_gateway_auth;
#[path = "http_gateway_draft.rs"]
mod http_gateway_draft;
#[path = "http_gateway_flags.rs"]
mod http_gateway_flags;
#[path = "http_gateway_keys.rs"]
mod http_gateway_keys;
#[path = "http_gateway_mail.rs"]
mod http_gateway_mail;
#[path = "http_gateway_protected.rs"]
pub(super) mod http_gateway_protected;
#[path = "http_gateway_settings.rs"]
mod http_gateway_settings;
#[path = "http_mailbox_backends.rs"]
mod http_mailbox_backends;

/// The concrete runtime gateway built from the existing OSMAP services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBrowserGateway {
    pub(crate) public_inventory_client: Option<crate::openpgp_inventory_runtime::Client>,
    pub(crate) crypto_client: Option<crate::openpgp_crypto_runtime::Client>,
    pub(crate) public_admin_client: Option<crate::openpgp_public_admin_runtime::Client>,
    inventory_recovery:
        std::sync::Arc<std::sync::OnceLock<crate::openpgp_inventory_runtime::Client>>,
    crypto_recovery: std::sync::Arc<std::sync::OnceLock<crate::openpgp_crypto_runtime::Client>>,
    admin_recovery:
        std::sync::Arc<std::sync::OnceLock<crate::openpgp_public_admin_runtime::Client>>,
    inventory_config: Option<crate::config::OpenPgpInventoryConfig>,
    crypto_config: Option<crate::config::OpenPgpCryptoConfig>,
    admin_config: Option<crate::config::OpenPgpAdminConfig>,
    authentication_policy: AuthenticationPolicy,
    totp_policy: TotpPolicy,
    login_throttle_policy: LoginThrottlePolicy,
    submission_throttle_policy: SubmissionThrottlePolicy,
    message_move_throttle_policy: MessageMoveThrottlePolicy,
    session_lifetime_seconds: u64,
    session_idle_timeout_seconds: u64,
    expensive_request_timeout_secs: u64,
    auth_backend_timeout_secs: u64,
    session_dir: PathBuf,
    pub(crate) settings_dir: PathBuf,
    draft_dir: PathBuf,
    login_throttle_dir: PathBuf,
    submission_throttle_dir: PathBuf,
    message_move_throttle_dir: PathBuf,
    totp_secret_dir: PathBuf,
    totp_replay_dir: PathBuf,
    doveadm_path: PathBuf,
    doveadm_auth_socket_path: Option<PathBuf>,
    doveadm_userdb_socket_path: Option<PathBuf>,
    mailbox_helper_socket_path: Option<PathBuf>,
    mailbox_helper_grant_key_path: Option<PathBuf>,
    sendmail_path: PathBuf,
    render_policy: RenderingPolicy,
}

impl RuntimeBrowserGateway {
    /// Builds the runtime gateway from validated configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            public_admin_client: config.openpgp_public_admin.as_ref().and_then(|c| {
                crate::openpgp_public_admin_runtime::Client::from_operator_files(
                    &c.socket,
                    &c.key_file,
                    c.helper_uid,
                )
                .ok()
            }),
            crypto_client: config.openpgp_crypto.as_ref().and_then(|c| {
                if !crate::openpgp_crypto_runtime::NATIVE_CONFINEMENT_QUALIFIED {
                    return None;
                }
                crate::openpgp_crypto_runtime::Client::from_operator_files(
                    &c.socket,
                    &c.key_file,
                    c.helper_uid,
                )
                .ok()
            }),
            public_inventory_client: config.openpgp_inventory.as_ref().and_then(|c| {
                crate::openpgp_inventory_runtime::Client::from_operator_files(
                    &c.socket,
                    &c.key_file,
                    c.helper_uid,
                )
                .ok()
            }),
            inventory_recovery: std::sync::Arc::new(std::sync::OnceLock::new()),
            crypto_recovery: std::sync::Arc::new(std::sync::OnceLock::new()),
            admin_recovery: std::sync::Arc::new(std::sync::OnceLock::new()),
            inventory_config: config.openpgp_inventory.clone(),
            crypto_config: config.openpgp_crypto.clone(),
            admin_config: config.openpgp_public_admin.clone(),
            authentication_policy: AuthenticationPolicy::default(),
            totp_policy: TotpPolicy {
                allowed_skew_steps: config.totp_allowed_skew_steps,
                ..TotpPolicy::default()
            },
            login_throttle_policy: LoginThrottlePolicy {
                credential_max_failures: config.login_throttle_max_failures,
                remote_addr_max_failures: config.login_throttle_remote_max_failures,
                failure_window_seconds: config.login_throttle_window_seconds,
                lockout_seconds: config.login_throttle_lockout_seconds,
            },
            submission_throttle_policy: SubmissionThrottlePolicy {
                canonical_user_max_submissions: config.submission_throttle_max_submissions,
                remote_addr_max_submissions: config.submission_throttle_remote_max_submissions,
                submission_window_seconds: config.submission_throttle_window_seconds,
                lockout_seconds: config.submission_throttle_lockout_seconds,
            },
            message_move_throttle_policy: MessageMoveThrottlePolicy {
                canonical_user_max_moves: config.message_move_throttle_max_moves,
                remote_addr_max_moves: config.message_move_throttle_remote_max_moves,
                move_window_seconds: config.message_move_throttle_window_seconds,
                lockout_seconds: config.message_move_throttle_lockout_seconds,
            },
            session_lifetime_seconds: config.session_lifetime_seconds,
            session_idle_timeout_seconds: config.session_idle_timeout_seconds,
            expensive_request_timeout_secs: config.expensive_request_timeout_seconds,
            auth_backend_timeout_secs: config.auth_backend_timeout_seconds,
            session_dir: config.state_layout.session_dir.clone(),
            settings_dir: config.state_layout.settings_dir.clone(),
            draft_dir: config.state_layout.draft_dir.clone(),
            login_throttle_dir: config.state_layout.cache_dir.join("login-throttle"),
            submission_throttle_dir: config.state_layout.cache_dir.join("submission-throttle"),
            message_move_throttle_dir: config.state_layout.cache_dir.join("message-move-throttle"),
            totp_secret_dir: config.state_layout.totp_secret_dir.clone(),
            totp_replay_dir: config.state_layout.cache_dir.join("totp-replay"),
            doveadm_path: PathBuf::from("/usr/local/bin/doveadm"),
            doveadm_auth_socket_path: config.doveadm_auth_socket_path.clone(),
            doveadm_userdb_socket_path: config.doveadm_userdb_socket_path.clone(),
            mailbox_helper_socket_path: config.mailbox_helper_socket_path.clone(),
            mailbox_helper_grant_key_path: config.mailbox_helper_grant_key_path.clone(),
            sendmail_path: PathBuf::from("/usr/sbin/sendmail"),
            render_policy: RenderingPolicy::default(),
        }
    }

    // A helper may start after the web service. Failures remain retryable;
    // success is cached across gateway clones so the client's response verifier
    // preserves its replay and clock high-water state.
    pub(crate) fn inventory_client(&self) -> Option<crate::openpgp_inventory_runtime::Client> {
        if let Some(client) = &self.public_inventory_client {
            return Some(client.clone());
        }
        if let Some(client) = self.inventory_recovery.get() {
            return Some(client.clone());
        }
        let c = self.inventory_config.as_ref()?;
        let client = crate::openpgp_inventory_runtime::Client::from_operator_files(
            &c.socket,
            &c.key_file,
            c.helper_uid,
        )
        .ok()?;
        let _ = self.inventory_recovery.set(client);
        self.inventory_recovery.get().cloned()
    }

    pub(crate) fn crypto_client(&self) -> Option<crate::openpgp_crypto_runtime::Client> {
        if let Some(client) = &self.crypto_client {
            return Some(client.clone());
        }
        if let Some(client) = self.crypto_recovery.get() {
            return Some(client.clone());
        }
        if !crate::openpgp_crypto_runtime::NATIVE_CONFINEMENT_QUALIFIED {
            return None;
        }
        let c = self.crypto_config.as_ref()?;
        let client = crate::openpgp_crypto_runtime::Client::from_operator_files(
            &c.socket,
            &c.key_file,
            c.helper_uid,
        )
        .ok()?;
        let _ = self.crypto_recovery.set(client);
        self.crypto_recovery.get().cloned()
    }

    pub(crate) fn admin_client(&self) -> Option<crate::openpgp_public_admin_runtime::Client> {
        if let Some(client) = &self.public_admin_client {
            return Some(client.clone());
        }
        if let Some(client) = self.admin_recovery.get() {
            return Some(client.clone());
        }
        let c = self.admin_config.as_ref()?;
        let client = crate::openpgp_public_admin_runtime::Client::from_operator_files(
            &c.socket,
            &c.key_file,
            c.helper_uid,
        )
        .ok()?;
        let _ = self.admin_recovery.set(client);
        self.admin_recovery.get().cloned()
    }

    /// Construction checks the local socket and grant; it does not prove an
    /// authenticated RPC or that a helper is accepting requests.
    pub(crate) fn helper_client_status_events(&self) -> [LogEvent; 3] {
        let status = |configured: bool, constructed: bool, helper: &'static str| {
            LogEvent::new(
                if configured && !constructed {
                    LogLevel::Warn
                } else {
                    LogLevel::Info
                },
                crate::logging::EventCategory::Bootstrap,
                "openpgp_helper_client_status",
                "OpenPGP helper client construction checked",
            )
            .with_field("helper", helper)
            .with_field(
                "status",
                if !configured {
                    "not_configured"
                } else if constructed {
                    "client_constructed"
                } else {
                    "configured_client_unavailable"
                },
            )
        };
        [
            status(
                self.inventory_config.is_some(),
                self.public_inventory_client.is_some(),
                "public_inventory",
            ),
            status(
                self.admin_config.is_some(),
                self.public_admin_client.is_some(),
                "public_admin",
            ),
            status(
                self.crypto_config.is_some(),
                self.crypto_client.is_some(),
                "crypto",
            ),
        ]
    }

    #[cfg(test)]
    pub(crate) fn for_test(temp_root: &std::path::Path) -> Self {
        Self {
            public_inventory_client: None,
            crypto_client: None,
            public_admin_client: None,
            inventory_recovery: std::sync::Arc::new(std::sync::OnceLock::new()),
            crypto_recovery: std::sync::Arc::new(std::sync::OnceLock::new()),
            admin_recovery: std::sync::Arc::new(std::sync::OnceLock::new()),
            inventory_config: None,
            crypto_config: None,
            admin_config: None,
            authentication_policy: AuthenticationPolicy::default(),
            totp_policy: TotpPolicy::default(),
            login_throttle_policy: LoginThrottlePolicy {
                credential_max_failures: 5,
                remote_addr_max_failures: 12,
                failure_window_seconds: 300,
                lockout_seconds: 600,
            },
            submission_throttle_policy: SubmissionThrottlePolicy {
                canonical_user_max_submissions: 10,
                remote_addr_max_submissions: 25,
                submission_window_seconds: 300,
                lockout_seconds: 900,
            },
            message_move_throttle_policy: MessageMoveThrottlePolicy {
                canonical_user_max_moves: 20,
                remote_addr_max_moves: 60,
                move_window_seconds: 300,
                lockout_seconds: 900,
            },
            session_lifetime_seconds: 3600,
            session_idle_timeout_seconds: 1800,
            expensive_request_timeout_secs: DEFAULT_EXPENSIVE_REQUEST_TIMEOUT_SECS,
            auth_backend_timeout_secs: crate::config::DEFAULT_AUTH_BACKEND_TIMEOUT_SECONDS,
            session_dir: temp_root.join("sessions"),
            settings_dir: temp_root.join("settings"),
            draft_dir: temp_root.join("drafts"),
            login_throttle_dir: temp_root.join("cache").join("login-throttle"),
            submission_throttle_dir: temp_root.join("cache").join("submission-throttle"),
            message_move_throttle_dir: temp_root.join("cache").join("message-move-throttle"),
            totp_secret_dir: temp_root.join("totp"),
            totp_replay_dir: temp_root.join("cache").join("totp-replay"),
            doveadm_path: PathBuf::from("/nonexistent/doveadm"),
            doveadm_auth_socket_path: None,
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: None,
            mailbox_helper_grant_key_path: None,
            sendmail_path: PathBuf::from("/usr/sbin/sendmail"),
            render_policy: RenderingPolicy::default(),
        }
    }
}

impl BrowserGateway for RuntimeBrowserGateway {
    fn key_management(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> crate::key_management::StateOutcome {
        self.key_management_state(context, session)
    }
    fn change_keys(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: crate::key_management::MutationRequest<'_>,
    ) -> crate::key_management::MutationOutcome {
        self.change_keys_impl(context, session, request)
    }
    fn compose_protection(
        &self,
        session: &ValidatedSession,
        to: &str,
        cc: &str,
        bcc: &str,
        intent: crate::send::ProtectionIntent,
    ) -> Option<crate::http::ComposeProtectionView> {
        self.compose_protection_view(session, to, cc, bcc, intent)
    }

    fn public_key_inventory(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> BrowserPublicInventoryOutcome {
        let inventory = self
            .inventory_client()
            .as_ref()
            .and_then(|client| client.read(&session.record.canonical_username).ok());
        let audit_events = if inventory
            .as_ref()
            .and_then(crate::openpgp_inventory::Inventory::keys)
            .is_none()
        {
            vec![build_http_warning_event(
                "public_inventory_unavailable",
                "public key inventory unavailable",
                context,
            )]
        } else {
            vec![]
        };
        BrowserPublicInventoryOutcome {
            canonical_username: session.record.canonical_username.clone(),
            inventory,
            audit_events,
        }
    }

    fn load_after_archive(
        &self,
        s: &ValidatedSession,
    ) -> Result<crate::after_archive::Preference, crate::after_archive::Error> {
        crate::after_archive::Store::new(&self.settings_dir).load(&s.record.canonical_username)
    }
    fn save_after_archive(
        &self,
        s: &ValidatedSession,
        revision: u64,
        choice: crate::after_archive::Choice,
    ) -> Result<crate::after_archive::Preference, crate::after_archive::Error> {
        crate::after_archive::Store::new(&self.settings_dir).save(
            &s.record.canonical_username,
            revision,
            choice,
        )
    }

    fn load_autosave(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::autosave::Preference, crate::autosave::Error> {
        crate::autosave::Store::new(&self.settings_dir).load(&session.record.canonical_username)
    }
    fn save_autosave(
        &self,
        session: &ValidatedSession,
        revision: u64,
        enabled: bool,
        interval: u16,
    ) -> Result<crate::autosave::Preference, crate::autosave::Error> {
        crate::autosave::Store::new(&self.settings_dir).save(
            &session.record.canonical_username,
            revision,
            enabled,
            interval,
        )
    }
    fn load_signature(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::signature::SignatureRecord, crate::signature::SignatureError> {
        crate::signature::SignatureStore::new(&self.settings_dir)
            .load(&session.record.canonical_username)
    }
    fn change_signature(
        &self,
        session: &ValidatedSession,
        revision: u64,
        change: crate::signature::SignatureChange<'_>,
    ) -> Result<crate::signature::SignatureRecord, crate::signature::SignatureError> {
        crate::signature::SignatureStore::new(&self.settings_dir).change(
            &session.record.canonical_username,
            revision,
            change,
        )
    }

    fn snooze_load(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::snooze::SnoozeRecord, crate::snooze::SnoozeError> {
        crate::snooze::SnoozeStore::new(&self.settings_dir)
            .load(&session.record.canonical_username, self.snooze_clock())
    }
    fn snooze_change(
        &self,
        session: &ValidatedSession,
        identity: &crate::snooze::MessageIdentity,
        revision: u64,
        until: Option<u64>,
    ) -> Result<crate::snooze::SnoozeRecord, crate::snooze::SnoozeError> {
        let store = crate::snooze::SnoozeStore::new(&self.settings_dir);
        match until {
            Some(until) => store.set(
                &session.record.canonical_username,
                identity,
                revision,
                until,
                self.snooze_clock(),
            ),
            None => store.cancel(
                &session.record.canonical_username,
                identity,
                revision,
                self.snooze_clock(),
            ),
        }
    }
    fn snooze_project(
        &self,
        session: &ValidatedSession,
        owner: &str,
        folder: &str,
        rows: &[MessageSummary],
    ) -> crate::snooze::SnoozeProjection {
        let store = crate::snooze::SnoozeStore::new(&self.settings_dir);
        store.project(
            &session.record.canonical_username,
            owner,
            folder,
            rows,
            self.snooze_clock(),
        )
    }

    fn read_send_recovery(
        &self,
        session: &ValidatedSession,
        intent: &str,
    ) -> BrowserSendRecoveryDecision {
        use crate::send_recovery::{RecoveryRead, SendRecovery};
        match SendRecovery::new(self.settings_dir.join("send-recovery")).lookup(
            &self.send_journal(),
            &session.record.canonical_username,
            intent,
            self.send_clock(),
        ) {
            Ok(RecoveryRead::Available(value)) => {
                BrowserSendRecoveryDecision::Available(BrowserSendRecoverySnapshot {
                    request: value.request,
                    created_at: value.created_at,
                    expires_at: value.expires_at,
                })
            }
            Ok(RecoveryRead::Missing) => BrowserSendRecoveryDecision::Missing,
            Ok(RecoveryRead::Expired) => BrowserSendRecoveryDecision::Expired,
            Ok(RecoveryRead::Unconfirmed) => BrowserSendRecoveryDecision::Unconfirmed,
            Err(_) => BrowserSendRecoveryDecision::Unavailable,
        }
    }

    fn send_receipt(
        &self,
        session: &ValidatedSession,
        intent: &str,
    ) -> Result<Option<BrowserSendDecision>, String> {
        self.send_journal()
            .receipt(
                &session.record.canonical_username,
                intent,
                self.send_clock(),
            )
            .map(|value| {
                value.map(|outcome| {
                    http_gateway_mail::journal_send_decision(Ok(
                        crate::send_journal::JournalResult {
                            outcome,
                            replayed: true,
                            receipt_persisted: true,
                        },
                    ))
                })
            })
            .map_err(|_| "send_attempt_paused".into())
    }
    fn cleanup_sent_draft(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        intent: &str,
    ) -> Result<bool, String> {
        self.cleanup_submitted_draft_impl(
            &session.record.canonical_username,
            id,
            revision,
            intent,
            self.send_clock(),
        )
        .map_err(|_| "send_attempt_paused".into())
    }

    fn labels_available(&self) -> bool {
        true
    }
    fn load_labels(
        &self,
        s: &ValidatedSession,
    ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
        crate::labels::LabelStore::new(self.settings_dir.join("labels-v1"))
            .load(&s.record.canonical_username)
    }
    fn change_labels(
        &self,
        s: &ValidatedSession,
        r: u64,
        c: crate::labels::LabelChange<'_>,
    ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
        crate::labels::LabelStore::new(self.settings_dir.join("labels-v1")).change(
            &s.record.canonical_username,
            r,
            c,
        )
    }
    fn reconcile_labels(
        &self,
        s: &ValidatedSession,
        r: u64,
        a: &crate::labels::MessageIdentity,
        b: &crate::labels::MessageIdentity,
    ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
        crate::labels::LabelStore::new(self.settings_dir.join("labels-v1"))
            .reconcile_confirmed_move(&s.record.canonical_username, r, a, b)
    }
    fn load_contacts(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError> {
        crate::contacts::ContactStore::new(self.settings_dir.join("contacts-v1"))
            .load(&session.record.canonical_username)
    }

    fn change_contact(
        &self,
        session: &ValidatedSession,
        expected_revision: u64,
        change: crate::contacts::ContactChange,
    ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError> {
        crate::contacts::ContactStore::new(self.settings_dir.join("contacts-v1")).change(
            &session.record.canonical_username,
            expected_revision,
            change,
        )
    }

    fn set_message_flag(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &crate::mailbox::MessageFlagRequest,
    ) -> BrowserMessageFlagOutcome {
        self.set_message_flag_impl(context, validated_session, request)
    }

    fn record_session_notification(
        &self,
        account: &str,
        kind: crate::notifications::NotificationKind,
    ) -> Result<(), crate::notifications::NotificationError> {
        crate::notifications::NotificationStore::new(&self.settings_dir).record(
            account,
            kind,
            crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
        )
    }
    fn notification_inbox(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::notifications::NotificationInbox, crate::notifications::NotificationError>
    {
        crate::notifications::NotificationStore::new(&self.settings_dir).load(
            &session.record.canonical_username,
            crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
        )
    }
    fn set_notification_read(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        read: bool,
    ) -> Result<crate::notifications::NotificationInbox, crate::notifications::NotificationError>
    {
        crate::notifications::NotificationStore::new(&self.settings_dir).set_read(
            &session.record.canonical_username,
            id,
            revision,
            read,
            crate::totp::TimeProvider::unix_timestamp(&SystemTimeProvider),
        )
    }
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

    fn revoke_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        scope: BrowserSessionRevokeScope,
    ) -> BrowserSessionRevokeOutcome {
        self.revoke_sessions_impl(context, validated_session, scope)
    }

    fn load_reading_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> std::io::Result<crate::reading_preferences::ReadingPreferences> {
        crate::reading_preferences::ReadingPreferencesStore::new(&self.settings_dir)
            .load(&session.record.canonical_username)
    }

    fn update_reading_start_page(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        start_page: crate::reading_preferences::StartPage,
    ) -> std::io::Result<crate::reading_preferences::ReadingPreferences> {
        crate::reading_preferences::ReadingPreferencesStore::new(&self.settings_dir)
            .save_start_page(&session.record.canonical_username, start_page)
    }

    fn update_reading_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        value: crate::reading_preferences::ReadingPreferences,
    ) -> std::io::Result<()> {
        crate::reading_preferences::ReadingPreferencesStore::new(&self.settings_dir)
            .save(&session.record.canonical_username, value)
    }

    fn load_identity_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> Result<
        crate::identity_preferences::IdentityPreferencesRecord,
        crate::identity_preferences::IdentityPreferencesError,
    > {
        crate::identity_preferences::IdentityPreferencesStore::new(&self.settings_dir)
            .load(&session.record.canonical_username)
    }
    fn update_identity_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        expected_revision: u64,
        value: &crate::identity_preferences::IdentityPreferences,
    ) -> Result<
        crate::identity_preferences::IdentityPreferencesRecord,
        crate::identity_preferences::IdentityPreferencesError,
    > {
        crate::identity_preferences::IdentityPreferencesStore::new(&self.settings_dir).save(
            &session.record.canonical_username,
            expected_revision,
            value,
        )
    }

    fn load_composition_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> std::io::Result<crate::composition_preferences::CompositionPreferences> {
        crate::composition_preferences::CompositionPreferencesStore::new(&self.settings_dir)
            .load(&session.record.canonical_username)
    }
    fn update_composition_format(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        value: crate::compose_format::BodyFormat,
    ) -> std::io::Result<()> {
        crate::composition_preferences::CompositionPreferencesStore::new(&self.settings_dir)
            .save_format(&session.record.canonical_username, value)
    }

    fn update_composition_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        value: crate::composition_preferences::CompositionPreferences,
    ) -> std::io::Result<()> {
        crate::composition_preferences::CompositionPreferencesStore::new(&self.settings_dir)
            .save(&session.record.canonical_username, value)
    }

    fn load_appearance(
        &self,
        _context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> std::io::Result<AppearancePreference> {
        AppearanceStore::new(&self.settings_dir).load(&validated_session.record.canonical_username)
    }

    fn update_appearance(
        &self,
        _context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        appearance: AppearancePreference,
    ) -> std::io::Result<()> {
        AppearanceStore::new(&self.settings_dir)
            .save(&validated_session.record.canonical_username, appearance)
    }

    fn load_display(
        &self,
        _context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> std::io::Result<AppearanceSettings> {
        AppearanceStore::new(&self.settings_dir)
            .load_settings(&validated_session.record.canonical_username)
    }

    fn update_display(
        &self,
        _context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        preferences: AppearanceSettings,
    ) -> std::io::Result<()> {
        AppearanceStore::new(&self.settings_dir)
            .save_settings(&validated_session.record.canonical_username, preferences)
    }

    fn load_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSettingsOutcome {
        self.load_settings_impl(context, validated_session)
    }

    fn update_content_setting(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        content: HtmlDisplayPreference,
    ) -> BrowserSettingsUpdateOutcome {
        let result = crate::settings::FileUserSettingsStore::new(&self.settings_dir)
            .save_content(&session.record.canonical_username, content);
        self.partial_settings_outcome(context, session, "content", result)
    }

    fn update_archive_setting(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        archive: Option<&str>,
    ) -> BrowserSettingsUpdateOutcome {
        let result = crate::settings::FileUserSettingsStore::new(&self.settings_dir)
            .save_archive(&session.record.canonical_username, archive);
        self.partial_settings_outcome(context, session, "archive", result)
    }

    fn update_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
        archive_mailbox_name: Option<&str>,
    ) -> BrowserSettingsUpdateOutcome {
        self.update_settings_impl(
            context,
            validated_session,
            html_display_preference,
            archive_mailbox_name,
        )
    }

    fn create_folder(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &crate::folder_create::CreateFolderRequest,
    ) -> BrowserFolderCreateOutcome {
        let outcome = if request.account() != session.record.canonical_username {
            crate::folder_create::Outcome::Refused(crate::folder_create::Refusal::Invalid)
        } else {
            crate::mailbox::MailboxBackend::create_folder(
                &self.build_mailbox_list_backend(),
                request,
            )
        };
        let event = LogEvent::new(
            LogLevel::Info,
            crate::logging::EventCategory::Mailbox,
            "folder_create_result",
            "folder create completed with bounded result",
        )
        .with_field("request_id", context.request_id.clone())
        .with_field(
            "confirmed",
            matches!(outcome, crate::folder_create::Outcome::Created { .. }).to_string(),
        );
        BrowserFolderCreateOutcome {
            outcome,
            audit_events: vec![event],
        }
    }
    fn folder_metadata(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> BrowserFolderMetadataOutcome {
        let account = &session.record.canonical_username;
        let snapshot = crate::mailbox::MailboxBackend::folder_metadata(
            &self.build_mailbox_list_backend(),
            account,
        )
        .ok()
        .filter(|v| v.validate_for(account).is_ok());
        let event = LogEvent::new(
            if snapshot.is_some() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            crate::logging::EventCategory::Mailbox,
            "folder_metadata_read",
            "folder metadata lookup completed",
        )
        .with_field("request_id", context.request_id.clone())
        .with_field("available", snapshot.is_some().to_string());
        BrowserFolderMetadataOutcome {
            canonical_username: account.clone(),
            snapshot,
            audit_events: vec![event],
        }
    }
    fn mailbox_status(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        folder: &str,
    ) -> BrowserMailboxStatusOutcome {
        let status = crate::mailbox::MailboxBackend::mailbox_status(
            &self.build_mailbox_list_backend(),
            &session.record.canonical_username,
            folder,
        )
        .ok();
        let event = LogEvent::new(
            if status.is_some() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            crate::logging::EventCategory::Mailbox,
            "mailbox_status_read",
            "folder status lookup completed",
        )
        .with_field("request_id", context.request_id.clone())
        .with_field(
            "canonical_username",
            session.record.canonical_username.clone(),
        )
        .with_field("available", status.is_some().to_string());
        BrowserMailboxStatusOutcome {
            canonical_username: session.record.canonical_username.clone(),
            status,
            audit_events: vec![event],
        }
    }
    fn list_mailboxes(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome {
        self.list_mailboxes_impl(context, validated_session)
    }

    fn list_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
    ) -> BrowserMessageListOutcome {
        self.list_messages_impl(context, validated_session, mailbox_name)
    }

    fn search_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: Option<&str>,
        query: &str,
        field: MessageSearchField,
    ) -> BrowserMessageSearchOutcome {
        self.search_messages_impl(context, validated_session, mailbox_name, query, field)
    }

    fn view_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
    ) -> BrowserMessageViewOutcome {
        self.view_message_impl(context, validated_session, mailbox_name, uid)
    }

    fn download_attachment(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> BrowserAttachmentDownloadOutcome {
        self.download_attachment_impl(context, validated_session, mailbox_name, uid, part_path)
    }

    fn download_stored_attachment(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        message: &MessageView,
        part: &str,
    ) -> BrowserAttachmentDownloadOutcome {
        if !http_gateway_protected::has_protection_envelope(message) {
            let result = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
                .download_for_validated_session(context, session, message, part);
            return BrowserAttachmentDownloadOutcome {
                decision: match result.decision {
                    AttachmentDownloadDecision::Downloaded {
                        canonical_username,
                        attachment,
                        ..
                    } => BrowserAttachmentDownloadDecision::Downloaded {
                        canonical_username,
                        attachment,
                    },
                    AttachmentDownloadDecision::Denied { public_reason } => {
                        BrowserAttachmentDownloadDecision::Denied {
                            public_reason: public_reason.as_str().into(),
                        }
                    }
                },
                audit_events: vec![result.audit_event],
            };
        }
        let result = self.protected_attachment_snapshot(context, session, message, part);
        BrowserAttachmentDownloadOutcome {
            decision: match result {
                Ok(attachment) => BrowserAttachmentDownloadDecision::Downloaded {
                    canonical_username: session.record.canonical_username.clone(),
                    attachment,
                },
                Err(crate::protected_message::ProtectedError::Attachment(reason)) => {
                    BrowserAttachmentDownloadDecision::Denied {
                        public_reason: reason.as_str().into(),
                    }
                }
                Err(_) => BrowserAttachmentDownloadDecision::Denied {
                    public_reason: "temporarily_unavailable".into(),
                },
            },
            audit_events: vec![build_http_info_event(
                "protected_attachment_processed",
                "protected attachment request completed",
                context,
            )],
        }
    }

    fn read_message_source(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageViewRequest,
    ) -> crate::mailbox::MessageViewOutcome {
        MessageViewService::new(self.build_message_view_backend()).fetch_for_validated_session(
            context,
            validated_session,
            request,
        )
    }

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserSendRequest<'_>,
    ) -> BrowserSendOutcome {
        self.send_message_impl(context, validated_session, request)
    }

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> BrowserMessageMoveOutcome {
        self.move_message_impl(context, validated_session, request)
    }

    fn list_drafts(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserDraftListOutcome {
        self.list_drafts_impl(context, validated_session)
    }

    fn load_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
    ) -> BrowserDraftLoadOutcome {
        self.load_draft_impl(context, validated_session, draft_id)
    }

    fn save_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserDraftSaveRequest<'_>,
    ) -> BrowserDraftSaveOutcome {
        self.save_draft_impl(context, validated_session, request)
    }

    fn delete_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
    ) -> BrowserDraftDeleteOutcome {
        self.delete_draft_impl(context, validated_session, draft_id, expected_revision)
    }

    fn set_draft_star(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
        starred: bool,
    ) -> BrowserDraftSaveOutcome {
        self.set_draft_star_impl(
            context,
            validated_session,
            draft_id,
            expected_revision,
            starred,
        )
    }
}

#[cfg(test)]
mod public_inventory_gateway_tests {
    use super::*;
    #[test]
    fn runtime_inventory_defaults_to_disabled() {
        let config = AppConfig::from_env_map(&std::collections::BTreeMap::new()).unwrap();
        let gateway = RuntimeBrowserGateway::from_config(&config);
        assert!(gateway.inventory_client().is_none());
        assert!(gateway.admin_client().is_none());
        assert!(gateway.crypto_client().is_none());
        assert_eq!(gateway, gateway.clone());
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "inventory-test",
            "127.0.0.1",
            "Test",
        )
        .unwrap();
        let session = ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "synthetic".into(),
                csrf_token: "synthetic".into(),
                canonical_username: "alice@example.com".into(),
                issued_at: 1,
                expires_at: 100,
                last_seen_at: 1,
                revoked_at: None,
                remote_addr: "127.0.0.1".into(),
                user_agent: "Test".into(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(LogLevel::Info, EventCategory::Session, "test", "test"),
        };
        let result = gateway.public_key_inventory(&context, &session);
        assert_eq!(result.canonical_username, "alice@example.com");
        assert!(result.inventory.is_none());
        assert_eq!(result.audit_events.len(), 1);
        assert!(!format!("{:?}", result.audit_events).contains("alice@example.com"));
    }

    #[test]
    fn configured_helpers_recover_after_socket_appears_without_rebuilding_gateway() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        // The security gate exports TMPDIR=/tmp/osmap-tmp, which may be
        // group-writable. Client path validation intentionally rejects that
        // ancestor, so this protected fixture uses the canonical sticky /tmp.
        let root = std::fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-gateway-helper-retry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("helper.sock");
        let grant = root.join("grant");
        std::fs::write(&grant, [17_u8; 32]).unwrap();
        std::fs::set_permissions(&grant, std::fs::Permissions::from_mode(0o600)).unwrap();
        let binding = crate::config::OpenPgpInventoryConfig {
            socket: socket.clone(),
            key_file: grant.clone(),
            helper_uid: crate::openbsd::effective_uid(),
        };
        let mut gateway = RuntimeBrowserGateway::for_test(&root);
        gateway.inventory_config = Some(binding.clone());
        gateway.admin_config = Some(binding.clone());
        gateway.crypto_config = Some(binding);

        assert!(gateway.inventory_client().is_none());
        assert!(gateway.admin_client().is_none());
        assert!(gateway.crypto_client().is_none());
        let unavailable = gateway.helper_client_status_events();
        assert!(unavailable.iter().all(|event| {
            event.action == "openpgp_helper_client_status"
                && event.level == LogLevel::Warn
                && event.fields.iter().any(|field| {
                    field.key == "status" && field.value == "configured_client_unavailable"
                })
        }));
        let logged = format!("{unavailable:?}");
        assert!(!logged.contains(root.to_str().unwrap()));
        assert!(!logged.contains("grant"));

        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid = crate::openbsd::effective_uid();
        assert!(
            gateway.inventory_client().is_some(),
            "configured inventory client failed after socket appeared: {:?}",
            crate::openpgp_inventory_runtime::Client::from_operator_files(&socket, &grant, uid)
                .err()
        );
        assert!(
            gateway.admin_client().is_some(),
            "configured admin client failed after socket appeared: {:?}",
            crate::openpgp_public_admin_runtime::Client::from_operator_files(&socket, &grant, uid)
                .err()
        );
        assert!(
            gateway.crypto_client().is_some(),
            "configured crypto client failed after socket appeared: {:?}",
            crate::openpgp_crypto_runtime::Client::from_operator_files(&socket, &grant, uid).err()
        );
        let cloned_gateway = gateway.clone();
        assert!(cloned_gateway.inventory_client().is_some());
        assert!(cloned_gateway.admin_client().is_some());
        assert!(cloned_gateway.crypto_client().is_some());
        assert!(std::ptr::eq(
            gateway.inventory_recovery.get().unwrap(),
            cloned_gateway.inventory_recovery.get().unwrap()
        ));
        assert!(std::ptr::eq(
            gateway.admin_recovery.get().unwrap(),
            cloned_gateway.admin_recovery.get().unwrap()
        ));
        assert!(std::ptr::eq(
            gateway.crypto_recovery.get().unwrap(),
            cloned_gateway.crypto_recovery.get().unwrap()
        ));
        drop(listener);
        std::fs::remove_file(&socket).unwrap();
        // Construction success remains cached, but each RPC still validates
        // the live socket and fails closed if the helper stops.
        assert!(gateway.inventory_client().is_some());
        assert!(gateway.admin_client().is_some());
        assert!(gateway.crypto_client().is_some());
        std::fs::remove_dir_all(root).unwrap();
    }
}
