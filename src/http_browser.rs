use super::*;

/// A runtime-facing gateway for browser operations.
/// Verified exact attempted content and finite retention; no editable draft id.
pub struct BrowserSendRecoverySnapshot {
    pub request: Box<ComposeRequest>,
    pub created_at: u64,
    pub expires_at: u64,
}

pub enum BrowserSendRecoveryDecision {
    Available(BrowserSendRecoverySnapshot),
    Missing,
    Expired,
    Unconfirmed,
    Unavailable,
}

pub trait BrowserGateway {
    fn retention_status(
        &self,
        _session: &ValidatedSession,
        _mailbox: &str,
    ) -> crate::mailbox::RetentionDecision {
        crate::mailbox::RetentionDecision::Unavailable
    }
    fn delete_message(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _request: &crate::mailbox::MessageDeleteRequest,
    ) -> BrowserMessageDeleteOutcome {
        BrowserMessageDeleteOutcome {
            result: Err(crate::mailbox::MessageDeleteError::Unavailable),
            retry_after_seconds: None,
            audit_events: Vec::new(),
        }
    }
    fn key_management(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> crate::key_management::StateOutcome {
        crate::key_management::StateOutcome {
            state: crate::key_management::State::unavailable(&session.record.canonical_username),
            audit_events: vec![],
        }
    }
    fn change_keys(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _request: crate::key_management::MutationRequest<'_>,
    ) -> crate::key_management::MutationOutcome {
        crate::key_management::MutationOutcome {
            result: Err(crate::key_management::Error::Unavailable),
            audit_events: vec![],
        }
    }
    fn load_bin_preference(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::bin_folder::BinPreference, crate::bin_folder::Error> {
        Err(crate::bin_folder::Error::Unavailable)
    }
    fn update_bin_preference(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _mailbox_name: &str,
    ) -> Result<crate::bin_folder::BinPreference, crate::bin_folder::Error> {
        Err(crate::bin_folder::Error::Unavailable)
    }

    fn load_after_archive(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::after_archive::Preference, crate::after_archive::Error> {
        Err(crate::after_archive::Error::Unavailable)
    }
    fn save_after_archive(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _choice: crate::after_archive::Choice,
    ) -> Result<crate::after_archive::Preference, crate::after_archive::Error> {
        Err(crate::after_archive::Error::Unavailable)
    }

    fn load_mark_read_policy(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::mark_read::Preference, crate::mark_read::Error> {
        Err(crate::mark_read::Error::Unavailable)
    }
    fn load_sent_location_preference(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::sent_location::Preference, crate::sent_location::Error> {
        let _ = session;
        Err(crate::sent_location::Error::Unavailable)
    }
    fn save_sent_location_preference(
        &self,
        session: &ValidatedSession,
        revision: u64,
        name: &str,
        guid: &str,
    ) -> Result<crate::sent_location::Preference, crate::sent_location::Error> {
        let _ = (session, revision, name, guid);
        Err(crate::sent_location::Error::Unavailable)
    }
    fn load_sent_copy_preference(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::sent_copy::Preference, crate::sent_copy::Error> {
        Err(crate::sent_copy::Error::Unavailable)
    }
    fn save_sent_copy_preference(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _save_sent: bool,
    ) -> Result<crate::sent_copy::Preference, crate::sent_copy::Error> {
        Err(crate::sent_copy::Error::Unavailable)
    }
    fn save_mark_read_policy(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _policy: crate::mark_read::Policy,
    ) -> Result<crate::mark_read::Preference, crate::mark_read::Error> {
        Err(crate::mark_read::Error::Unavailable)
    }

    fn load_autosave(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::autosave::Preference, crate::autosave::Error> {
        Err(crate::autosave::Error::Unavailable)
    }
    fn save_autosave(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _enabled: bool,
        _interval: u16,
    ) -> Result<crate::autosave::Preference, crate::autosave::Error> {
        Err(crate::autosave::Error::Unavailable)
    }

    fn load_signature(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::signature::SignatureRecord, crate::signature::SignatureError> {
        Err(crate::signature::SignatureError::Unavailable)
    }
    fn change_signature(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _change: crate::signature::SignatureChange<'_>,
    ) -> Result<crate::signature::SignatureRecord, crate::signature::SignatureError> {
        Err(crate::signature::SignatureError::Unavailable)
    }

    fn snooze_clock(&self) -> u64 {
        crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
    }
    fn snooze_load(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::snooze::SnoozeRecord, crate::snooze::SnoozeError> {
        Err(crate::snooze::SnoozeError::Unavailable)
    }
    fn snooze_change(
        &self,
        _session: &ValidatedSession,
        _identity: &crate::snooze::MessageIdentity,
        _revision: u64,
        _until: Option<u64>,
    ) -> Result<crate::snooze::SnoozeRecord, crate::snooze::SnoozeError> {
        Err(crate::snooze::SnoozeError::Unavailable)
    }
    fn snooze_project(
        &self,
        _session: &ValidatedSession,
        _owner: &str,
        _folder: &str,
        _rows: &[MessageSummary],
    ) -> crate::snooze::SnoozeProjection {
        crate::snooze::SnoozeProjection {
            hidden: vec![],
            revision: None,
            unavailable: Some(crate::snooze::SnoozeError::Unavailable),
        }
    }

    /// Authenticated read-only exact snapshot; never grants a mutation or retry.
    fn read_send_recovery(
        &self,
        _session: &ValidatedSession,
        _intent: &str,
    ) -> BrowserSendRecoveryDecision {
        BrowserSendRecoveryDecision::Unavailable
    }

    fn send_clock(&self) -> u64 {
        crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
    }
    fn send_receipt(
        &self,
        session: &ValidatedSession,
        intent: &str,
    ) -> Result<Option<BrowserSendDecision>, String>;
    fn cleanup_sent_draft(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        intent: &str,
    ) -> Result<bool, String>;

    fn archive_events_available(&self) -> bool {
        false
    }
    fn archive_event_clock(&self) -> u64 {
        crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
    }
    fn load_archive_events(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::archive_event::Snapshot, crate::archive_event::Error> {
        Err(crate::archive_event::Error::Unavailable)
    }
    fn record_archive_event(
        &self,
        _session: &ValidatedSession,
        _confirmation: &crate::archive_event::ConfirmedArchive,
        _confirmed_at: u64,
    ) -> Result<crate::archive_event::Snapshot, crate::archive_event::Error> {
        Err(crate::archive_event::Error::Unavailable)
    }

    fn labels_available(&self) -> bool {
        false
    }
    fn load_labels(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
        Err(crate::labels::LabelError::Unavailable)
    }
    fn change_labels(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _change: crate::labels::LabelChange<'_>,
    ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
        Err(crate::labels::LabelError::Unavailable)
    }
    fn reconcile_labels(
        &self,
        _session: &ValidatedSession,
        _revision: u64,
        _source: &crate::labels::MessageIdentity,
        _destination: &crate::labels::MessageIdentity,
    ) -> Result<crate::labels::LabelRecord, crate::labels::LabelError> {
        Err(crate::labels::LabelError::Unavailable)
    }
    fn load_contacts(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError>;
    fn change_contact(
        &self,
        session: &ValidatedSession,
        expected_revision: u64,
        change: crate::contacts::ContactChange,
    ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError>;

    fn set_message_flag(
        &self,
        _context: &AuthenticationContext,
        _validated_session: &ValidatedSession,
        _request: &crate::mailbox::MessageFlagRequest,
    ) -> BrowserMessageFlagOutcome {
        BrowserMessageFlagOutcome {
            result: Err(BrowserMessageFlagFailure::Unavailable),
            audit_events: Vec::new(),
        }
    }

    fn record_session_notification(
        &self,
        _account: &str,
        _kind: crate::notifications::NotificationKind,
    ) -> Result<(), crate::notifications::NotificationError> {
        Err(crate::notifications::NotificationError::Unavailable)
    }
    fn notification_inbox(
        &self,
        _session: &ValidatedSession,
    ) -> Result<crate::notifications::NotificationInbox, crate::notifications::NotificationError>
    {
        Err(crate::notifications::NotificationError::Unavailable)
    }
    fn set_notification_read(
        &self,
        _session: &ValidatedSession,
        _id: &str,
        _revision: u64,
        _read: bool,
    ) -> Result<crate::notifications::NotificationInbox, crate::notifications::NotificationError>
    {
        Err(crate::notifications::NotificationError::Unavailable)
    }

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

    fn revoke_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        scope: BrowserSessionRevokeScope,
    ) -> BrowserSessionRevokeOutcome;

    fn load_reading_preferences(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
    ) -> std::io::Result<crate::reading_preferences::ReadingPreferences> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "reading preferences unavailable",
        ))
    }

    fn update_reading_start_page(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        start_page: crate::reading_preferences::StartPage,
    ) -> std::io::Result<crate::reading_preferences::ReadingPreferences> {
        let _ = (session, start_page);
        Err(std::io::Error::other("reading preferences unavailable"))
    }

    fn update_reading_preferences(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _value: crate::reading_preferences::ReadingPreferences,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "reading preferences unavailable",
        ))
    }

    fn load_identity_preferences(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> Result<
        crate::identity_preferences::IdentityPreferencesRecord,
        crate::identity_preferences::IdentityPreferencesError,
    > {
        {
            let _ = session;
            Err(crate::identity_preferences::IdentityPreferencesError::Unavailable)
        }
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
        {
            let _ = (session, expected_revision, value);
            Err(crate::identity_preferences::IdentityPreferencesError::Unavailable)
        }
    }

    fn load_composition_preferences(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
    ) -> std::io::Result<crate::composition_preferences::CompositionPreferences> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "composition preferences unavailable",
        ))
    }
    fn update_composition_format(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _value: crate::compose_format::BodyFormat,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "composition preferences unavailable",
        ))
    }

    fn update_composition_preferences(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _value: crate::composition_preferences::CompositionPreferencesUpdate,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "composition preferences unavailable",
        ))
    }

    fn load_appearance(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> std::io::Result<AppearancePreference>;

    fn update_appearance(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        appearance: AppearancePreference,
    ) -> std::io::Result<()>;

    fn load_display(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> std::io::Result<AppearanceSettings> {
        self.load_appearance(context, validated_session)
            .map(|theme| AppearanceSettings {
                theme,
                ..AppearanceSettings::default()
            })
    }

    fn update_display(
        &self,
        _context: &AuthenticationContext,
        _validated_session: &ValidatedSession,
        _preferences: AppearanceSettings,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "display preferences unavailable",
        ))
    }

    fn load_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSettingsOutcome;

    fn update_content_setting(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _content: HtmlDisplayPreference,
    ) -> BrowserSettingsUpdateOutcome {
        BrowserSettingsUpdateOutcome {
            decision: BrowserSettingsUpdateDecision::Denied {
                public_reason: "temporarily_unavailable".into(),
            },
            audit_events: vec![],
        }
    }

    fn update_archive_setting(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _archive: Option<&str>,
    ) -> BrowserSettingsUpdateOutcome {
        BrowserSettingsUpdateOutcome {
            decision: BrowserSettingsUpdateDecision::Denied {
                public_reason: "temporarily_unavailable".into(),
            },
            audit_events: vec![],
        }
    }

    fn update_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
        archive_mailbox_name: Option<&str>,
    ) -> BrowserSettingsUpdateOutcome;

    fn create_folder(
        &self,
        _: &AuthenticationContext,
        _: &ValidatedSession,
        _: &crate::folder_create::CreateFolderRequest,
    ) -> BrowserFolderCreateOutcome {
        BrowserFolderCreateOutcome {
            outcome: crate::folder_create::Outcome::Refused(
                crate::folder_create::Refusal::Unavailable,
            ),
            audit_events: vec![],
        }
    }
    fn compose_protection(
        &self,
        _session: &ValidatedSession,
        _to: &str,
        _cc: &str,
        _bcc: &str,
        _intent: crate::send::ProtectionIntent,
    ) -> Option<crate::http::ComposeProtectionView> {
        None
    }

    fn public_key_inventory(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> BrowserPublicInventoryOutcome {
        BrowserPublicInventoryOutcome {
            canonical_username: session.record.canonical_username.clone(),
            inventory: None,
            audit_events: vec![],
        }
    }
    fn folder_metadata(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> BrowserFolderMetadataOutcome {
        BrowserFolderMetadataOutcome {
            canonical_username: session.record.canonical_username.clone(),
            snapshot: None,
            audit_events: vec![],
        }
    }
    fn mailbox_status(
        &self,
        _context: &AuthenticationContext,
        session: &ValidatedSession,
        _folder: &str,
    ) -> BrowserMailboxStatusOutcome {
        BrowserMailboxStatusOutcome {
            canonical_username: session.record.canonical_username.clone(),
            status: None,
            audit_events: vec![],
        }
    }
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
        mailbox_name: Option<&str>,
        query: &str,
        field: MessageSearchField,
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

    /// Decode a freshly fetched, already ownership-checked stored snapshot.
    /// A runtime override processes protected content through its authenticated
    /// crypto client; the default refuses protected envelopes.
    fn download_stored_attachment(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        message: &MessageView,
        part: &str,
    ) -> BrowserAttachmentDownloadOutcome {
        let result =
            if super::http_gateway::http_gateway_protected::has_protection_envelope(message) {
                None
            } else {
                Some(
                    AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
                        .download_for_validated_session(context, session, message, part),
                )
            };
        let mut audit_events = vec![];
        let decision = if let Some(outcome) = result {
            audit_events.push(outcome.audit_event);
            match outcome.decision {
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
            }
        } else {
            BrowserAttachmentDownloadDecision::Denied {
                public_reason: "temporarily_unavailable".into(),
            }
        };
        BrowserAttachmentDownloadOutcome {
            decision,
            audit_events,
        }
    }

    /// Read bounded stored text through the configured mailbox boundary.
    /// Callers must check account, mailbox, UID and any expected version.
    fn read_message_source(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageViewRequest,
    ) -> crate::mailbox::MessageViewOutcome;

    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> BrowserMessageMoveOutcome;

    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserSendRequest<'_>,
    ) -> BrowserSendOutcome;

    fn list_drafts(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserDraftListOutcome;

    fn load_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
    ) -> BrowserDraftLoadOutcome;

    fn save_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserDraftSaveRequest<'_>,
    ) -> BrowserDraftSaveOutcome;

    fn delete_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
    ) -> BrowserDraftDeleteOutcome;

    fn set_draft_star(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
        starred: bool,
    ) -> BrowserDraftSaveOutcome;
}

/// Draft save fields parsed by the browser route layer.
#[derive(Debug, Clone, Copy)]
pub struct BrowserDraftSaveRequest<'a> {
    pub protection: crate::send::ProtectionIntent,
    pub send_intent: &'a str,
    pub draft_id: Option<&'a str>,
    pub expected_revision: Option<u64>,
    pub recipients: &'a str,
    pub cc_recipients: &'a str,
    pub bcc_recipients: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub body_format: crate::compose_format::BodyFormat,
    pub attachments: &'a [UploadedAttachment],
    pub removed_attachment_indices: &'a [usize],
    pub source_attachments: Option<&'a DraftSourceAttachments>,
    pub reply_thread: Option<&'a crate::reply_thread::ReplyThread>,
}

/// Send fields parsed by the browser route layer.
#[derive(Debug, Clone, Copy)]
pub struct BrowserSendRequest<'a> {
    pub protection: crate::send::ProtectionIntent,
    pub send_intent: &'a str,
    pub draft_id: Option<&'a str>,
    pub draft_revision: Option<u64>,
    pub recipients: &'a str,
    pub cc_recipients: &'a str,
    pub bcc_recipients: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub body_format: crate::compose_format::BodyFormat,
    pub attachments: &'a [UploadedAttachment],
    pub reply_thread: Option<&'a crate::reply_thread::ReplyThread>,
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
        appearance: AppearancePreference,
        presentation: AppearanceSettings,
        reading: crate::reading_preferences::ReadingPreferences,
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
    pub device_label: String,
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
        session_lifetime_seconds: u64,
        session_idle_timeout_seconds: u64,
        sessions: Vec<BrowserVisibleSession>,
    },
    Denied {
        public_reason: String,
    },
}

impl BrowserSessionListDecision {
    /// Verified retained metadata for an authenticated account overview.
    pub(crate) fn verified_sessions(&self, account: &str) -> Option<&[BrowserVisibleSession]> {
        let Self::Listed {
            canonical_username,
            sessions,
            ..
        } = self
        else {
            return None;
        };
        if canonical_username != account || sessions.len() > 256 {
            return None;
        }
        let mut seen = std::collections::BTreeSet::new();
        if sessions
            .iter()
            .any(|session| !seen.insert(session.session_id.as_str()))
        {
            return None;
        }
        Some(sessions)
    }
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
        newly_revoked: bool,
        revoked_session_id: String,
        revoked_current_session: bool,
    },
    RevokedMany {
        revoked_count: usize,
        revoked_current_session: bool,
    },
    Denied {
        public_reason: String,
    },
}

/// Bulk session-revocation scopes supported by the browser sessions page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSessionRevokeScope {
    OtherSessions,
    AllSessions,
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
        mailbox_name: Option<String>,
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

/// A permanent-delete outcome; a quota refusal is distinct from dispatched uncertainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageDeleteOutcome {
    pub result: Result<crate::mailbox::MessageDeleteResult, crate::mailbox::MessageDeleteError>,
    pub retry_after_seconds: Option<u64>,
    pub audit_events: Vec<LogEvent>,
}

/// The result of a browser message-move operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMessageFlagOutcome {
    pub result: Result<crate::mailbox::MessageFlagResult, BrowserMessageFlagFailure>,
    pub audit_events: Vec<LogEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserMessageFlagFailure {
    Invalid,
    Stale,
    Busy,
    RateLimited { retry_after_seconds: u64 },
    Unavailable,
    Unknown,
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
    RecoveryRefused {
        capacity: bool,
    },
    DraftSaved {
        draft_id: String,
        save_confirmed: bool,
    },
    /// Accepted by the submission backend; this does not confirm delivery.
    Submitted {
        sent_copy_stored: bool,
        receipt_persisted: bool,
    },
    /// SMTP acceptance with a captured explicit destination, not a delivery guarantee.
    SubmittedTo {
        mailbox_name: String,
        copy_available: bool,
        sent_copy_stored: bool,
        receipt_persisted: bool,
    },
    /// Acceptance is known; no copy was requested by captured account choice.
    SubmittedWithoutSentCopy {
        receipt_persisted: bool,
    },
    /// Dispatch may have occurred; this outcome must not trigger a retry.
    Unconfirmed {
        public_reason: String,
    },
    Denied {
        public_reason: String,
        retry_after_seconds: Option<u64>,
    },
}

/// The result of listing browser-visible drafts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDraftListOutcome {
    pub decision: BrowserDraftListDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Account/revision-bound list state; an absent/mismatched row must remain unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDraftState {
    pub draft_id: String,
    pub revision: u64,
    pub state: BrowserDraftEditState,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserDraftEditState {
    Editable,
    Attempted { receipt_intent: String },
    Paused { receipt_intent: String },
    Unknown,
}
/// Logical stored bytes use the same metadata + attachment basis as the shared quota.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserDraftStorageUsage {
    Verified {
        ordinary_count: usize,
        ordinary_bytes: u64,
        recovery_count: usize,
        recovery_bytes: u64,
        max_count: usize,
        max_bytes: u64,
    },
    Unknown,
}

pub(crate) fn project_drafts(
    guard: &crate::send_journal::AccountGuard,
    drafts: &[DraftSummary],
    recovery: Result<(usize, u64), crate::send_recovery::RecoveryError>,
) -> (Vec<BrowserDraftState>, BrowserDraftStorageUsage) {
    let policy = crate::draft::DraftPolicy::default();
    let usage = match (
        drafts
            .iter()
            .try_fold(0_u64, |total, row| total.checked_add(row.storage_bytes)),
        recovery,
    ) {
        (Some(ordinary_bytes), Ok((recovery_count, recovery_bytes)))
            if drafts
                .len()
                .checked_add(recovery_count)
                .is_some_and(|n| n <= policy.max_drafts_per_user)
                && ordinary_bytes
                    .checked_add(recovery_bytes)
                    .is_some_and(|n| n <= policy.storage_max_bytes) =>
        {
            BrowserDraftStorageUsage::Verified {
                ordinary_count: drafts.len(),
                ordinary_bytes,
                recovery_count,
                recovery_bytes,
                max_count: policy.max_drafts_per_user,
                max_bytes: policy.storage_max_bytes,
            }
        }
        _ => BrowserDraftStorageUsage::Unknown,
    };
    let states = drafts
        .iter()
        .map(|draft| {
            let state = match guard.draft_attempt(draft) {
                Ok((_, None)) if usage != BrowserDraftStorageUsage::Unknown => {
                    BrowserDraftEditState::Editable
                }
                Ok((
                    receipt_intent,
                    Some(crate::send_journal::AttemptOutcome::Accepted { .. }),
                )) => BrowserDraftEditState::Attempted { receipt_intent },
                Ok((receipt_intent, Some(_))) => BrowserDraftEditState::Paused { receipt_intent },
                _ => BrowserDraftEditState::Unknown,
            };
            BrowserDraftState {
                draft_id: draft.draft_id.clone(),
                revision: draft.revision,
                state,
            }
        })
        .collect();
    (states, usage)
}

/// Draft-list decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserDraftListDecision {
    Listed {
        canonical_username: String,
        drafts: Vec<DraftSummary>,
        states: Vec<BrowserDraftState>,
        usage: BrowserDraftStorageUsage,
    },
    Denied {
        public_reason: String,
    },
}

/// The result of loading one draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDraftLoadOutcome {
    pub decision: BrowserDraftLoadDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Draft-load decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserDraftLoadDecision {
    Loaded {
        canonical_username: String,
        draft: Box<DraftRecord>,
    },
    NotFound,
    Denied {
        public_reason: String,
    },
}

/// The result of saving one browser draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDraftSaveOutcome {
    pub decision: BrowserDraftSaveDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Draft-save decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserDraftSaveDecision {
    Saved { draft_id: String },
    Unconfirmed { draft_id: String },
    Denied { public_reason: String },
}

/// The result of deleting one browser draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserDraftDeleteOutcome {
    pub decision: BrowserDraftDeleteDecision,
    pub audit_events: Vec<LogEvent>,
}

/// Draft-delete decisions visible to the browser layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserDraftDeleteDecision {
    Deleted,
    NotFound,
    Denied { public_reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMailboxStatusOutcome {
    pub canonical_username: String,
    pub status: Option<crate::mailbox_status::MailboxStatus>,
    pub audit_events: Vec<LogEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserFolderMetadataOutcome {
    pub canonical_username: String,
    pub snapshot: Option<crate::folder_metadata::FolderSnapshot>,
    pub audit_events: Vec<LogEvent>,
}

pub struct BrowserPublicInventoryOutcome {
    pub canonical_username: String,
    pub inventory: Option<crate::openpgp_inventory::Inventory>,
    pub audit_events: Vec<LogEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserFolderCreateOutcome {
    pub outcome: crate::folder_create::Outcome,
    pub audit_events: Vec<LogEvent>,
}
