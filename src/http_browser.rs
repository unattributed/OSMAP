use super::*;

/// A runtime-facing gateway for browser operations.
pub trait BrowserGateway {
    fn login(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> BrowserLoginOutcome;

    fn validate_session(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome;

    fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome;

    fn list_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSessionListOutcome;

    fn revoke_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        session_id: &str,
    ) -> BrowserSessionRevokeOutcome;

    fn load_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSettingsOutcome;

    fn update_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
        archive_mailbox_name: Option<&str>,
    ) -> BrowserSettingsUpdateOutcome;

    fn list_mailboxes(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome;

    fn list_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
    ) -> BrowserMessageListOutcome;

    fn search_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        query: &str,
    ) -> BrowserMessageSearchOutcome;

    fn view_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
    ) -> BrowserMessageViewOutcome;

    fn download_attachment(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> BrowserAttachmentDownloadOutcome;

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        source_mailbox_name: &str,
        uid: u64,
        destination_mailbox_name: &str,
    ) -> BrowserMessageMoveOutcome;

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        recipients: &str,
        subject: &str,
        body: &str,
        attachments: &[UploadedAttachment],
    ) -> BrowserSendOutcome;
}

/// The result of a browser login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLoginOutcome {
    pub decision: BrowserLoginDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Login decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserLoginDecision {
    Authenticated {
        canonical_username: String,
        session_token: SessionToken,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of validating a presented browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionValidationOutcome {
    pub decision: BrowserSessionDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Session validation decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSessionDecision {
    Valid {
        validated_session: Box<ValidatedSession>,
    },
    Invalid,
}

/// The result of a browser logout attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLogoutOutcome {
    pub session_was_revoked: bool,
    pub audit_events: Vec<LogEvent>,
}

/// Safe browser-visible session metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVisibleSession {
    pub session_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub last_seen_at: u64,
    pub revoked_at: Option<u64>,
    pub remote_addr: String,
    pub user_agent: String,
    pub factor: RequiredSecondFactor,
}

/// Safe browser-visible end-user settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVisibleSettings {
    pub html_display_preference: HtmlDisplayPreference,
    pub archive_mailbox_name: Option<String>,
}

/// The result of a browser-visible session listing operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionListOutcome {
    pub decision: BrowserSessionListDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Session-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSessionListDecision {
    Listed {
        canonical_username: String,
        sessions: Vec<BrowserVisibleSession>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser-driven session revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionRevokeOutcome {
    pub decision: BrowserSessionRevokeDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Session-revocation decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSessionRevokeDecision {
    Revoked {
        revoked_session_id: String,
        revoked_current_session: bool,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of loading the browser-visible settings page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSettingsOutcome {
    pub decision: BrowserSettingsDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Settings-page decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSettingsDecision {
    Loaded {
        canonical_username: String,
        settings: BrowserVisibleSettings,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of one browser-driven settings update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSettingsUpdateOutcome {
    pub decision: BrowserSettingsUpdateDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Settings-update decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSettingsUpdateDecision {
    Updated,
    Denied { public_reason: String },
}

/// The result of a mailbox-listing browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMailboxOutcome {
    pub decision: BrowserMailboxDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Mailbox-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMailboxDecision {
    Listed {
        canonical_username: String,
        mailboxes: Vec<MailboxEntry>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a message-list browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageListOutcome {
    pub decision: BrowserMessageListDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageListDecision {
    Listed {
        canonical_username: String,
        mailbox_name: String,
        messages: Vec<MessageSummary>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a message-search browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageSearchOutcome {
    pub decision: BrowserMessageSearchDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-search decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageSearchDecision {
    Listed {
        canonical_username: String,
        mailbox_name: String,
        query: String,
        results: Vec<MessageSearchResult>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a rendered message-view browser operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageViewOutcome {
    pub decision: BrowserMessageViewDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-view decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageViewDecision {
    Rendered {
        canonical_username: String,
        rendered: Box<RenderedMessageView>,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser attachment-download operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAttachmentDownloadOutcome {
    pub decision: BrowserAttachmentDownloadDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Attachment-download decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserAttachmentDownloadDecision {
    Downloaded {
        canonical_username: String,
        attachment: DownloadedAttachment,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of a browser message-move operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageMoveOutcome {
    pub decision: BrowserMessageMoveDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Message-move decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageMoveDecision {
    Moved {
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
    },
    Denied {
        public_reason: String,
        retry_after_seconds: Option<u64>,
    },
}

/// The result of a browser send operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSendOutcome {
    pub decision: BrowserSendDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Send decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSendDecision {
    Submitted,
    Denied {
        public_reason: String,
        retry_after_seconds: Option<u64>,
    },
}
