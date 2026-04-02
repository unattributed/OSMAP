use super::*;

#[path = "http_gateway_auth.rs"]
mod http_gateway_auth;
#[path = "http_gateway_mail.rs"]
mod http_gateway_mail;
#[path = "http_gateway_settings.rs"]
mod http_gateway_settings;
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
    settings_dir: PathBuf,
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
            settings_dir: config.state_layout.settings_dir.clone(),
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
            settings_dir: temp_root.join("settings"),
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

    fn load_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSettingsOutcome {
        self.load_settings_impl(context, validated_session)
    }

    fn update_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
    ) -> BrowserSettingsUpdateOutcome {
        self.update_settings_impl(context, validated_session, html_display_preference)
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
        mailbox_name: &str,
        query: &str,
    ) -> BrowserMessageSearchOutcome {
        self.search_messages_impl(context, validated_session, mailbox_name, query)
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

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
        attachments: &[UploadedAttachment],
    ) -> BrowserSendOutcome {
        self.send_message_impl(
            context,
            validated_session,
            recipients,
            subject,
            body,
            attachments,
        )
    }

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        source_mailbox_name: &str,
        uid: u64,
        destination_mailbox_name: &str,
    ) -> BrowserMessageMoveOutcome {
        self.move_message_impl(
            context,
            validated_session,
            source_mailbox_name,
            uid,
            destination_mailbox_name,
        )
    }
}
