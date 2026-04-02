//! Mailbox listing for the first WP5 read-path slice.
//!
//! This module keeps the first mailbox read path intentionally small:
//! - session validation remains a separate gate handled before mailbox access
//! - mailbox listing uses the existing Dovecot surface instead of a new mail
//!   stack
//! - mailbox, message-list, and message-view results/failures are emitted as
//!   structured audit events

use std::path::PathBuf;

#[path = "mailbox_parse.rs"]
mod mailbox_parse;

use crate::auth::{
    AuthenticationContext, CommandExecution, CommandExecutor, SystemCommandExecutor,
};
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::session::ValidatedSession;
use self::mailbox_parse::{
    parse_doveadm_mailbox_list_output, parse_doveadm_message_list_output,
    parse_doveadm_message_search_output, parse_doveadm_message_view_output,
};

/// Conservative maximum length for a mailbox name returned by the backend.
pub const DEFAULT_MAILBOX_NAME_MAX_LEN: usize = 255;

/// Conservative upper bound for the number of mailboxes returned in one listing.
pub const DEFAULT_MAX_MAILBOXES: usize = 1024;

/// Conservative upper bound for the number of messages returned in one listing.
pub const DEFAULT_MAX_MESSAGES: usize = 2000;

/// Conservative upper bound for the number of messages returned in one search.
pub const DEFAULT_MAX_SEARCH_RESULTS: usize = 250;

/// Conservative maximum length for rendered date strings returned by the backend.
pub const DEFAULT_MESSAGE_DATE_MAX_LEN: usize = 128;

/// Conservative maximum length for rendered flag strings returned by the backend.
pub const DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN: usize = 256;

/// Conservative maximum length for one free-text mailbox search query.
pub const DEFAULT_SEARCH_QUERY_MAX_LEN: usize = 256;

/// Conservative maximum length for a surfaced header field in search results.
pub const DEFAULT_SEARCH_HEADER_VALUE_MAX_LEN: usize = 512;

/// Conservative maximum length for fetched message headers.
pub const DEFAULT_MESSAGE_HEADER_MAX_LEN: usize = 65_536;

/// Conservative maximum length for fetched message bodies in the first view slice.
pub const DEFAULT_MESSAGE_BODY_MAX_LEN: usize = 262_144;

/// Policy controlling mailbox-output bounds for the first read-path slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxListingPolicy {
    pub mailbox_name_max_len: usize,
    pub max_mailboxes: usize,
}

impl Default for MailboxListingPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        }
    }
}

/// Policy controlling message-list request and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageListPolicy {
    pub mailbox_name_max_len: usize,
    pub max_messages: usize,
    pub message_date_max_len: usize,
    pub message_flag_string_max_len: usize,
}

impl Default for MessageListPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_messages: DEFAULT_MAX_MESSAGES,
            message_date_max_len: DEFAULT_MESSAGE_DATE_MAX_LEN,
            message_flag_string_max_len: DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN,
        }
    }
}

/// Policy controlling single-message retrieval request and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageViewPolicy {
    pub mailbox_name_max_len: usize,
    pub message_date_max_len: usize,
    pub message_flag_string_max_len: usize,
    pub message_header_max_len: usize,
    pub message_body_max_len: usize,
}

impl Default for MessageViewPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            message_date_max_len: DEFAULT_MESSAGE_DATE_MAX_LEN,
            message_flag_string_max_len: DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN,
            message_header_max_len: DEFAULT_MESSAGE_HEADER_MAX_LEN,
            message_body_max_len: DEFAULT_MESSAGE_BODY_MAX_LEN,
        }
    }
}

/// Policy controlling mailbox-scoped search request and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSearchPolicy {
    pub mailbox_name_max_len: usize,
    pub max_results: usize,
    pub query_max_len: usize,
    pub message_date_max_len: usize,
    pub message_flag_string_max_len: usize,
    pub header_value_max_len: usize,
}

impl Default for MessageSearchPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_results: DEFAULT_MAX_SEARCH_RESULTS,
            query_max_len: DEFAULT_SEARCH_QUERY_MAX_LEN,
            message_date_max_len: DEFAULT_MESSAGE_DATE_MAX_LEN,
            message_flag_string_max_len: DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN,
            header_value_max_len: DEFAULT_SEARCH_HEADER_VALUE_MAX_LEN,
        }
    }
}

/// A single mailbox visible to the authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    pub name: String,
}

/// A validated request for listing messages from a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageListRequest {
    pub mailbox_name: String,
}

impl MessageListRequest {
    /// Validates the mailbox name used for message-list retrieval.
    pub fn new(
        policy: MessageListPolicy,
        mailbox_name: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_name = mailbox_name.into();
        let _ = MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: policy.mailbox_name_max_len,
                max_mailboxes: DEFAULT_MAX_MAILBOXES,
            },
            mailbox_name.clone(),
        )?;

        Ok(Self { mailbox_name })
    }
}

/// A single summary row in a message list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    pub mailbox_name: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub date_received: String,
    pub size_virtual: u64,
}

/// A validated mailbox-scoped search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSearchRequest {
    pub mailbox_name: String,
    pub query: String,
}

impl MessageSearchRequest {
    /// Validates the mailbox name and free-text query used for message search.
    pub fn new(
        policy: MessageSearchPolicy,
        mailbox_name: impl Into<String>,
        query: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_name = mailbox_name.into();
        let _ = MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: policy.mailbox_name_max_len,
                max_mailboxes: DEFAULT_MAX_MAILBOXES,
            },
            mailbox_name.clone(),
        )?;

        let query = query.into().trim().to_string();
        if query.is_empty() {
            return Err(MailboxBackendError {
                backend: "message-search-parser",
                reason: "search query must not be empty".to_string(),
            });
        }
        if query.len() > policy.query_max_len {
            return Err(MailboxBackendError {
                backend: "message-search-parser",
                reason: format!(
                    "search query exceeded maximum length of {} bytes",
                    policy.query_max_len
                ),
            });
        }
        if query.chars().any(char::is_control) {
            return Err(MailboxBackendError {
                backend: "message-search-parser",
                reason: "search query contains control characters".to_string(),
            });
        }

        Ok(Self {
            mailbox_name,
            query,
        })
    }
}

/// A single summary row returned from a mailbox-scoped search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSearchResult {
    pub mailbox_name: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub date_received: String,
    pub size_virtual: u64,
    pub subject: Option<String>,
    pub from: Option<String>,
}

/// A validated request for retrieving one message from a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageViewRequest {
    pub mailbox_name: String,
    pub uid: u64,
}

impl MessageViewRequest {
    /// Validates the mailbox name and UID used for message retrieval.
    pub fn new(
        policy: MessageViewPolicy,
        mailbox_name: impl Into<String>,
        uid: u64,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_name = mailbox_name.into();
        let _ = MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: policy.mailbox_name_max_len,
                max_mailboxes: DEFAULT_MAX_MAILBOXES,
            },
            mailbox_name.clone(),
        )?;

        if uid == 0 {
            return Err(MailboxBackendError {
                backend: "message-view-parser",
                reason: "uid must be greater than zero".to_string(),
            });
        }

        Ok(Self { mailbox_name, uid })
    }
}

/// Policy controlling one-message move request validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageMovePolicy {
    pub mailbox_name_max_len: usize,
}

impl Default for MessageMovePolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
        }
    }
}

/// A validated request for moving one message between existing mailboxes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMoveRequest {
    pub source_mailbox_name: String,
    pub destination_mailbox_name: String,
    pub uid: u64,
}

impl MessageMoveRequest {
    /// Validates the source mailbox, destination mailbox, and UID for a
    /// one-message move operation.
    pub fn new(
        policy: MessageMovePolicy,
        source_mailbox_name: impl Into<String>,
        destination_mailbox_name: impl Into<String>,
        uid: u64,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_policy = MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        };
        let source_mailbox_name =
            MailboxEntry::new(mailbox_policy, source_mailbox_name.into())?.name;
        let destination_mailbox_name =
            MailboxEntry::new(mailbox_policy, destination_mailbox_name.into())?.name;

        if source_mailbox_name == destination_mailbox_name {
            return Err(MailboxBackendError {
                backend: "message-move-parser",
                reason: "destination mailbox must differ from source mailbox".to_string(),
            });
        }

        if uid == 0 {
            return Err(MailboxBackendError {
                backend: "message-move-parser",
                reason: "uid must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        })
    }
}

/// A bounded per-message payload for the first message-view slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageView {
    pub mailbox_name: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub date_received: String,
    pub size_virtual: u64,
    pub header_block: String,
    pub body_text: String,
}

impl MailboxEntry {
    /// Validates a mailbox name so later UI and logging code does not inherit
    /// unbounded or ambiguous backend output.
    pub fn new(
        policy: MailboxListingPolicy,
        name: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        let name = name.into();

        if name.is_empty() {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: "mailbox name must not be empty".to_string(),
            });
        }

        if name.len() > policy.mailbox_name_max_len {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: format!(
                    "mailbox name exceeded maximum length of {} bytes",
                    policy.mailbox_name_max_len
                ),
            });
        }

        if name.chars().any(char::is_control) {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: "mailbox name contains control characters".to_string(),
            });
        }

        Ok(Self { name })
    }
}

/// The user-facing reason returned when mailbox listing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxPublicFailureReason {
    NotFound,
    TemporarilyUnavailable,
}

impl MailboxPublicFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Internal audit reason used when mailbox listing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxAuditFailureReason {
    NotFound,
    BackendUnavailable,
    OutputRejected,
}

impl MailboxAuditFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::BackendUnavailable => "backend_unavailable",
            Self::OutputRejected => "output_rejected",
        }
    }
}

/// The outcome of a mailbox-list request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxListingDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailboxes: Vec<MailboxEntry>,
    },
}

/// The outcome of a message-list request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageListDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailbox_name: String,
        messages: Vec<MessageSummary>,
    },
}

/// The outcome of a message-view request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageViewDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Retrieved {
        canonical_username: String,
        session_id: String,
        message: MessageView,
    },
}

/// The outcome of a message-search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageSearchDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailbox_name: String,
        query: String,
        results: Vec<MessageSearchResult>,
    },
}

/// The outcome of a one-message move request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageMoveDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Moved {
        canonical_username: String,
        session_id: String,
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
    },
}

/// The decision plus audit event emitted by mailbox listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxListingOutcome {
    pub decision: MailboxListingDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by message-list retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageListOutcome {
    pub decision: MessageListDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by message retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageViewOutcome {
    pub decision: MessageViewDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by message search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSearchOutcome {
    pub decision: MessageSearchDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by one-message move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMoveOutcome {
    pub decision: MessageMoveDecision,
    pub audit_event: LogEvent,
}

/// Backend failures that should not leak detailed internals to mailbox users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBackendError {
    pub backend: &'static str,
    pub reason: String,
}

/// A backend capable of listing mailboxes for a canonical user.
pub trait MailboxBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError>;
}

/// A backend capable of listing message summaries for a mailbox.
pub trait MessageListBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError>;
}

/// A backend capable of retrieving one message view for a mailbox and UID.
pub trait MessageViewBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError>;
}

/// A backend capable of searching for messages within one mailbox.
pub trait MessageSearchBackend {
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError>;
}

/// A backend capable of moving one message between existing mailboxes.
pub trait MessageMoveBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError>;
}

/// Lists mailboxes for an already validated session.
pub struct MailboxListingService<B> {
    backend: B,
}

impl<B> MailboxListingService<B>
where
    B: MailboxBackend,
{
    /// Creates a mailbox-listing service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Lists mailboxes for the canonical user attached to the validated session.
    pub fn list_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> MailboxListingOutcome {
        let canonical_username = validated_session.record.canonical_username.clone();
        let session_id = validated_session.record.session_id.clone();

        match self.backend.list_mailboxes(&canonical_username) {
            Ok(mailboxes) => MailboxListingOutcome {
                decision: MailboxListingDecision::Listed {
                    canonical_username: canonical_username.clone(),
                    session_id: session_id.clone(),
                    mailboxes: mailboxes.clone(),
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "mailbox_listed",
                    "mailbox listing completed",
                )
                .with_field("canonical_username", canonical_username)
                .with_field("session_id", session_id)
                .with_field("mailbox_count", mailboxes.len().to_string())
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => MailboxListingOutcome {
                decision: MailboxListingDecision::Denied {
                    public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_mailbox_failure_event(
                    context,
                    &validated_session.record.canonical_username,
                    &validated_session.record.session_id,
                    &error,
                ),
            },
        }
    }
}

/// Lists message summaries for an already validated session.
pub struct MessageListService<B> {
    backend: B,
}

impl<B> MessageListService<B>
where
    B: MessageListBackend,
{
    /// Creates a message-list service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Lists message summaries for the canonical user attached to the
    /// validated session.
    pub fn list_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageListRequest,
    ) -> MessageListOutcome {
        let canonical_username = validated_session.record.canonical_username.clone();
        let session_id = validated_session.record.session_id.clone();

        match self.backend.list_messages(&canonical_username, request) {
            Ok(messages) => MessageListOutcome {
                decision: MessageListDecision::Listed {
                    canonical_username: canonical_username.clone(),
                    session_id: session_id.clone(),
                    mailbox_name: request.mailbox_name.clone(),
                    messages: messages.clone(),
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "message_listed",
                    "message list retrieval completed",
                )
                .with_field("canonical_username", canonical_username)
                .with_field("session_id", session_id)
                .with_field("mailbox_name", request.mailbox_name.clone())
                .with_field("message_count", messages.len().to_string())
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => MessageListOutcome {
                decision: MessageListDecision::Denied {
                    public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_message_list_failure_event(
                    context,
                    &validated_session.record.canonical_username,
                    &validated_session.record.session_id,
                    &request.mailbox_name,
                    &error,
                ),
            },
        }
    }
}

/// Retrieves one message view for an already validated session.
pub struct MessageViewService<B> {
    backend: B,
}

impl<B> MessageViewService<B>
where
    B: MessageViewBackend,
{
    /// Creates a message-view service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Retrieves a single bounded message payload for the canonical user
    /// attached to the validated session.
    pub fn fetch_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageViewRequest,
    ) -> MessageViewOutcome {
        let canonical_username = validated_session.record.canonical_username.clone();
        let session_id = validated_session.record.session_id.clone();

        match self.backend.fetch_message(&canonical_username, request) {
            Ok(message) => MessageViewOutcome {
                decision: MessageViewDecision::Retrieved {
                    canonical_username: canonical_username.clone(),
                    session_id: session_id.clone(),
                    message: message.clone(),
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "message_viewed",
                    "message retrieval completed",
                )
                .with_field("canonical_username", canonical_username)
                .with_field("session_id", session_id)
                .with_field("mailbox_name", message.mailbox_name.clone())
                .with_field("uid", message.uid.to_string())
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => {
                let public_reason = if error.backend == "message-view-not-found" {
                    MailboxPublicFailureReason::NotFound
                } else {
                    MailboxPublicFailureReason::TemporarilyUnavailable
                };

                MessageViewOutcome {
                    decision: MessageViewDecision::Denied { public_reason },
                    audit_event: build_message_view_failure_event(
                        context,
                        &validated_session.record.canonical_username,
                        &validated_session.record.session_id,
                        &request.mailbox_name,
                        request.uid,
                        public_reason,
                        &error,
                    ),
                }
            }
        }
    }
}

/// Searches messages for an already validated session.
pub struct MessageSearchService<B> {
    backend: B,
}

impl<B> MessageSearchService<B>
where
    B: MessageSearchBackend,
{
    /// Creates a message-search service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Searches message summaries for the canonical user attached to the
    /// validated session.
    pub fn search_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageSearchRequest,
    ) -> MessageSearchOutcome {
        let canonical_username = validated_session.record.canonical_username.clone();
        let session_id = validated_session.record.session_id.clone();

        match self.backend.search_messages(&canonical_username, request) {
            Ok(results) => MessageSearchOutcome {
                decision: MessageSearchDecision::Listed {
                    canonical_username: canonical_username.clone(),
                    session_id: session_id.clone(),
                    mailbox_name: request.mailbox_name.clone(),
                    query: request.query.clone(),
                    results: results.clone(),
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "message_searched",
                    "message search completed",
                )
                .with_field("canonical_username", canonical_username)
                .with_field("session_id", session_id)
                .with_field("mailbox_name", request.mailbox_name.clone())
                .with_field("query", request.query.clone())
                .with_field("result_count", results.len().to_string())
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => MessageSearchOutcome {
                decision: MessageSearchDecision::Denied {
                    public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_message_search_failure_event(
                    context,
                    &validated_session.record.canonical_username,
                    &validated_session.record.session_id,
                    &request.mailbox_name,
                    &request.query,
                    &error,
                ),
            },
        }
    }
}

/// Moves one message for an already validated session.
pub struct MessageMoveService<B> {
    backend: B,
}

impl<B> MessageMoveService<B>
where
    B: MessageMoveBackend,
{
    /// Creates a message-move service around the supplied backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Moves one message for the canonical user attached to the validated
    /// session.
    pub fn move_for_validated_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> MessageMoveOutcome {
        let canonical_username = validated_session.record.canonical_username.clone();
        let session_id = validated_session.record.session_id.clone();

        match self.backend.move_message(&canonical_username, request) {
            Ok(()) => MessageMoveOutcome {
                decision: MessageMoveDecision::Moved {
                    canonical_username: canonical_username.clone(),
                    session_id: session_id.clone(),
                    source_mailbox_name: request.source_mailbox_name.clone(),
                    destination_mailbox_name: request.destination_mailbox_name.clone(),
                    uid: request.uid,
                },
                audit_event: LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Mailbox,
                    "message_moved",
                    "message move completed",
                )
                .with_field("canonical_username", canonical_username)
                .with_field("session_id", session_id)
                .with_field("source_mailbox_name", request.source_mailbox_name.clone())
                .with_field(
                    "destination_mailbox_name",
                    request.destination_mailbox_name.clone(),
                )
                .with_field("uid", request.uid.to_string())
                .with_field("request_id", context.request_id.clone())
                .with_field("remote_addr", context.remote_addr.clone())
                .with_field("user_agent", context.user_agent.clone()),
            },
            Err(error) => MessageMoveOutcome {
                decision: MessageMoveDecision::Denied {
                    public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
                },
                audit_event: build_message_move_failure_event(
                    context,
                    &validated_session.record.canonical_username,
                    &validated_session.record.session_id,
                    &request.source_mailbox_name,
                    &request.destination_mailbox_name,
                    request.uid,
                    &error,
                ),
            },
        }
    }
}

/// Lists mailboxes through `doveadm mailbox list`.
pub struct DoveadmMailboxListBackend<E> {
    policy: MailboxListingPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMailboxListBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MailboxListingPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points mailbox lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMailboxListBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MailboxListingPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MailboxBackend for DoveadmMailboxListBackend<E>
where
    E: CommandExecutor,
{
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "mailbox".to_string(),
            "list".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-mailbox-list",
                reason: error.reason,
            })?;

        parse_doveadm_mailbox_list_output(self.policy, &execution)
    }
}

/// Lists message summaries through `doveadm fetch`.
pub struct DoveadmMessageListBackend<E> {
    policy: MessageListPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageListBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MessageListPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-list lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageListBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MessageListPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MessageListBackend for DoveadmMessageListBackend<E>
where
    E: CommandExecutor,
{
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".to_string(),
            "flow".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "uid flags date.received size.virtual mailbox".to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "all".to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-list",
                reason: error.reason,
            })?;

        parse_doveadm_message_list_output(self.policy, &execution)
    }
}

/// Retrieves a bounded single-message payload through `doveadm fetch`.
pub struct DoveadmMessageViewBackend<E> {
    policy: MessageViewPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageViewBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MessageViewPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-view lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

/// Searches message summaries through `doveadm fetch` using a mailbox-scoped
/// Dovecot `TEXT` search term.
pub struct DoveadmMessageSearchBackend<E> {
    policy: MessageSearchPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageSearchBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MessageSearchPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-search lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageSearchBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MessageSearchPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MessageSearchBackend for DoveadmMessageSearchBackend<E>
where
    E: CommandExecutor,
{
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".to_string(),
            "flow".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "uid flags date.received size.virtual mailbox hdr.subject hdr.from".to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "TEXT".to_string(),
            request.query.clone(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-search",
                reason: error.reason,
            })?;

        parse_doveadm_message_search_output(self.policy, &execution)
    }
}

impl Default for DoveadmMessageViewBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MessageViewPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MessageViewBackend for DoveadmMessageViewBackend<E>
where
    E: CommandExecutor,
{
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".to_string(),
            "flow".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "uid flags date.received size.virtual mailbox hdr body".to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "uid".to_string(),
            request.uid.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-view",
                reason: error.reason,
            })?;

        parse_doveadm_message_view_output(self.policy, &execution)
    }
}

/// Moves one message through `doveadm move`.
pub struct DoveadmMessageMoveBackend<E> {
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageMoveBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(command_executor: E, doveadm_path: impl Into<PathBuf>) -> Self {
        Self {
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-move operations at an explicit Dovecot userdb-capable
    /// socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageMoveBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
    }
}

impl<E> MessageMoveBackend for DoveadmMessageMoveBackend<E>
where
    E: CommandExecutor,
{
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "move".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            request.destination_mailbox_name.clone(),
            "mailbox".to_string(),
            request.source_mailbox_name.clone(),
            "uid".to_string(),
            request.uid.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-move",
                reason: error.reason,
            })?;

        if execution.status_code != 0 {
            return Err(MailboxBackendError {
                backend: "doveadm-message-move",
                reason: format!(
                    "command exited with status {}: {}",
                    execution.status_code,
                    concise_command_diagnostics(&execution.stdout, &execution.stderr),
                ),
            });
        }

        Ok(())
    }
}

/// Builds a bounded failure event for mailbox-listing problems.
fn build_mailbox_failure_event(
    context: &AuthenticationContext,
    canonical_username: &str,
    session_id: &str,
    error: &MailboxBackendError,
) -> LogEvent {
    let audit_reason = if error.backend == "mailbox-parser" {
        MailboxAuditFailureReason::OutputRejected
    } else {
        MailboxAuditFailureReason::BackendUnavailable
    };

    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "mailbox_list_failed",
        "mailbox listing failed",
    )
    .with_field("canonical_username", canonical_username.to_string())
    .with_field("session_id", session_id.to_string())
    .with_field(
        "public_reason",
        MailboxPublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("backend", error.backend)
    .with_field("backend_reason", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Builds a bounded failure event for message-list problems.
fn build_message_list_failure_event(
    context: &AuthenticationContext,
    canonical_username: &str,
    session_id: &str,
    mailbox_name: &str,
    error: &MailboxBackendError,
) -> LogEvent {
    let audit_reason = if error.backend == "message-list-parser" {
        MailboxAuditFailureReason::OutputRejected
    } else {
        MailboxAuditFailureReason::BackendUnavailable
    };

    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "message_list_failed",
        "message list retrieval failed",
    )
    .with_field("canonical_username", canonical_username.to_string())
    .with_field("session_id", session_id.to_string())
    .with_field("mailbox_name", mailbox_name.to_string())
    .with_field(
        "public_reason",
        MailboxPublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("backend", error.backend)
    .with_field("backend_reason", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Builds a bounded failure event for single-message retrieval problems.
fn build_message_view_failure_event(
    context: &AuthenticationContext,
    canonical_username: &str,
    session_id: &str,
    mailbox_name: &str,
    uid: u64,
    public_reason: MailboxPublicFailureReason,
    error: &MailboxBackendError,
) -> LogEvent {
    let audit_reason = match error.backend {
        "message-view-not-found" => MailboxAuditFailureReason::NotFound,
        "message-view-parser" => MailboxAuditFailureReason::OutputRejected,
        _ => MailboxAuditFailureReason::BackendUnavailable,
    };

    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "message_view_failed",
        "message retrieval failed",
    )
    .with_field("canonical_username", canonical_username.to_string())
    .with_field("session_id", session_id.to_string())
    .with_field("mailbox_name", mailbox_name.to_string())
    .with_field("uid", uid.to_string())
    .with_field("public_reason", public_reason.as_str())
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("backend", error.backend)
    .with_field("backend_reason", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Builds a bounded failure event for message-search problems.
fn build_message_search_failure_event(
    context: &AuthenticationContext,
    canonical_username: &str,
    session_id: &str,
    mailbox_name: &str,
    query: &str,
    error: &MailboxBackendError,
) -> LogEvent {
    let audit_reason = if error.backend == "message-search-parser" {
        MailboxAuditFailureReason::OutputRejected
    } else {
        MailboxAuditFailureReason::BackendUnavailable
    };

    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "message_search_failed",
        "message search failed",
    )
    .with_field("canonical_username", canonical_username.to_string())
    .with_field("session_id", session_id.to_string())
    .with_field("mailbox_name", mailbox_name.to_string())
    .with_field("query", query.to_string())
    .with_field(
        "public_reason",
        MailboxPublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field("audit_reason", audit_reason.as_str())
    .with_field("backend", error.backend)
    .with_field("backend_reason", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Builds a bounded failure event for one-message move problems.
fn build_message_move_failure_event(
    context: &AuthenticationContext,
    canonical_username: &str,
    session_id: &str,
    source_mailbox_name: &str,
    destination_mailbox_name: &str,
    uid: u64,
    error: &MailboxBackendError,
) -> LogEvent {
    LogEvent::new(
        LogLevel::Warn,
        EventCategory::Mailbox,
        "message_move_failed",
        "message move failed",
    )
    .with_field("canonical_username", canonical_username.to_string())
    .with_field("session_id", session_id.to_string())
    .with_field("source_mailbox_name", source_mailbox_name.to_string())
    .with_field(
        "destination_mailbox_name",
        destination_mailbox_name.to_string(),
    )
    .with_field("uid", uid.to_string())
    .with_field(
        "public_reason",
        MailboxPublicFailureReason::TemporarilyUnavailable.as_str(),
    )
    .with_field(
        "audit_reason",
        MailboxAuditFailureReason::BackendUnavailable.as_str(),
    )
    .with_field("backend", error.backend)
    .with_field("backend_reason", error.reason.clone())
    .with_field("request_id", context.request_id.clone())
    .with_field("remote_addr", context.remote_addr.clone())
    .with_field("user_agent", context.user_agent.clone())
}

/// Adds an explicit Dovecot auth socket override for userdb-capable helper work
/// when the deployment provides one.
fn append_doveadm_auth_socket_override(args: &mut Vec<String>, auth_socket_path: Option<&PathBuf>) {
    if let Some(auth_socket_path) = auth_socket_path {
        args.push("-o".to_string());
        args.push(format!("auth_socket_path={}", auth_socket_path.display()));
    }
}

/// Produces a compact single-line diagnostic from command output.
fn concise_command_diagnostics(stdout: &str, stderr: &str) -> String {
    let combined = format!("{} {}", stderr.trim(), stdout.trim())
        .trim()
        .to_string();
    if combined.is_empty() {
        return "no command diagnostics returned".to_string();
    }

    combined.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{
        AuthenticationDecision, AuthenticationPolicy, AuthenticationService, CommandExecutionError,
        PrimaryAuthBackendError, PrimaryAuthVerdict, PrimaryCredentialBackend,
        RequiredSecondFactor, SecondFactorService,
    };
    use crate::config::LogFormat;
    use crate::logging::Logger;
    use crate::session::{
        FileSessionStore, RandomSource, SessionError, SessionService, SESSION_TOKEN_BYTES,
    };
    use crate::totp::{FileTotpSecretStore, TimeProvider, TotpPolicy, TotpVerifier};
    use std::cell::Cell;
    use std::fs;
    use std::path::Path;
    use std::rc::Rc;

    struct AcceptingPrimaryBackend;

    impl PrimaryCredentialBackend for AcceptingPrimaryBackend {
        fn verify_primary(
            &self,
            _context: &AuthenticationContext,
            username: &str,
            password: &str,
        ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
            if username == "alice@example.com" && password == "correct horse battery staple" {
                return Ok(PrimaryAuthVerdict::Accept {
                    canonical_username: "alice@example.com".to_string(),
                });
            }

            Ok(PrimaryAuthVerdict::Reject)
        }
    }

    #[derive(Debug, Clone)]
    struct FixedTimeProvider {
        unix_timestamp: Cell<u64>,
    }

    impl FixedTimeProvider {
        fn new(unix_timestamp: u64) -> Self {
            Self {
                unix_timestamp: Cell::new(unix_timestamp),
            }
        }
    }

    impl TimeProvider for FixedTimeProvider {
        fn unix_timestamp(&self) -> u64 {
            self.unix_timestamp.get()
        }
    }

    #[derive(Debug, Clone)]
    struct StaticRandomSource {
        bytes: Vec<u8>,
    }

    impl RandomSource for StaticRandomSource {
        fn fill_bytes(&self, buffer: &mut [u8]) -> Result<(), SessionError> {
            buffer.copy_from_slice(&self.bytes[..buffer.len()]);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct StubCommandExecutor {
        execution: Result<CommandExecution, CommandExecutionError>,
        program: Option<String>,
        args: Option<Vec<String>>,
    }

    impl StubCommandExecutor {
        fn success(execution: CommandExecution) -> Self {
            Self {
                execution: Ok(execution),
                program: None,
                args: None,
            }
        }
    }

    impl CommandExecutor for Rc<std::cell::RefCell<StubCommandExecutor>> {
        fn run_with_stdin_bytes(
            &self,
            program: &str,
            args: &[String],
            _stdin_data: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            let mut state = self.borrow_mut();
            state.program = Some(program.to_string());
            state.args = Some(args.to_vec());
            state.execution.clone()
        }
    }

    struct FailingMailboxBackend;

    impl MailboxBackend for FailingMailboxBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-mailbox-backend",
                reason: "imap bridge unavailable".to_string(),
            })
        }
    }

    struct FailingMessageListBackend;

    impl MessageListBackend for FailingMessageListBackend {
        fn list_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageListRequest,
        ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-message-backend",
                reason: "message index unavailable".to_string(),
            })
        }
    }

    struct FailingMessageSearchBackend;

    impl MessageSearchBackend for FailingMessageSearchBackend {
        fn search_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageSearchRequest,
        ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-message-search-backend",
                reason: "message search unavailable".to_string(),
            })
        }
    }

    struct MissingMessageViewBackend;

    impl MessageViewBackend for MissingMessageViewBackend {
        fn fetch_message(
            &self,
            _canonical_username: &str,
            _request: &MessageViewRequest,
        ) -> Result<MessageView, MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "message-view-not-found",
                reason: "no message matched the request".to_string(),
            })
        }
    }

    struct FailingMessageMoveBackend;

    impl MessageMoveBackend for FailingMessageMoveBackend {
        fn move_message(
            &self,
            _canonical_username: &str,
            _request: &MessageMoveRequest,
        ) -> Result<(), MailboxBackendError> {
            Err(MailboxBackendError {
                backend: "test-message-move-backend",
                reason: "move operation unavailable".to_string(),
            })
        }
    }

    fn test_context() -> AuthenticationContext {
        AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "req-mailbox",
            "127.0.0.1",
            "Firefox/Test",
        )
        .expect("context should be valid")
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            FixedTimeProvider::new(1).unix_timestamp()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn parses_mailbox_entries_from_doveadm_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "INBOX\nSent\nDrafts\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );

        let mailboxes = backend
            .list_mailboxes("alice@example.com")
            .expect("mailbox list should succeed");

        assert_eq!(
            mailboxes,
            vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent".to_string(),
                },
                MailboxEntry {
                    name: "Drafts".to_string(),
                },
            ]
        );

        let recorded = executor.borrow();
        assert_eq!(recorded.program.as_deref(), Some("/usr/local/bin/doveadm"));
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "mailbox".to_string(),
                "list".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn mailbox_list_uses_explicit_userdb_socket_when_configured() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "INBOX\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(PathBuf::from("/var/run/osmap-userdb")));

        let _ = backend
            .list_mailboxes("alice@example.com")
            .expect("mailbox list should succeed");

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-o".to_string(),
                "auth_socket_path=/var/run/osmap-userdb".to_string(),
                "mailbox".to_string(),
                "list".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
            ]
        );
    }

    #[test]
    fn parses_message_summaries_from_doveadm_flow_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: concat!(
                    "uid=4 flags=\"\\\\Seen\" date.received=2026-03-27 09:00:00 +0000 size.virtual=2048 mailbox=INBOX\n",
                    "uid=5 flags=\"\\\\Seen \\\\Answered\" date.received=2026-03-27 10:15:00 +0000 size.virtual=4096 mailbox=INBOX\n"
                )
                .to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");

        let messages = backend
            .list_messages("alice@example.com", &request)
            .expect("message list should succeed");

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].uid, 4);
        assert_eq!(messages[0].mailbox_name, "INBOX");
        assert_eq!(messages[0].flags, vec!["\\Seen".to_string()]);
        assert_eq!(
            messages[1].flags,
            vec!["\\Seen".to_string(), "\\Answered".to_string()]
        );

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-f".to_string(),
                "flow".to_string(),
                "fetch".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "uid flags date.received size.virtual mailbox".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "all".to_string(),
            ]
        );
    }

    #[test]
    fn parses_message_view_from_doveadm_flow_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: "uid=9 flags=\"\\\\Seen\" date.received=2026-03-27 11:00:00 +0000 size.virtual=512 mailbox=INBOX hdr=\"Subject: Test message\\nFrom: Alice <alice@example.com>\\n\" body=\"Hello world\\nSecond line\\n\"\n".to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageViewBackend::new(
            MessageViewPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");

        let message = backend
            .fetch_message("alice@example.com", &request)
            .expect("message retrieval should succeed");

        assert_eq!(message.uid, 9);
        assert_eq!(message.mailbox_name, "INBOX");
        assert_eq!(message.flags, vec!["\\Seen".to_string()]);
        assert_eq!(
            message.header_block,
            "Subject: Test message\nFrom: Alice <alice@example.com>\n"
        );
        assert_eq!(message.body_text, "Hello world\nSecond line\n");

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-f".to_string(),
                "flow".to_string(),
                "fetch".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "uid flags date.received size.virtual mailbox hdr body".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "uid".to_string(),
                "9".to_string(),
            ]
        );
    }

    #[test]
    fn parses_message_search_results_from_doveadm_flow_output() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: concat!(
                    "uid=14 flags=\"\\\\Seen\" date.received=2026-03-27 15:00:00 +0000 size.virtual=2048 mailbox=INBOX hdr.subject=\"Quarterly report\" hdr.from=\"Alice <alice@example.com>\"\n",
                    "uid=15 flags=\"\" date.received=2026-03-27 16:00:00 +0000 size.virtual=1024 mailbox=INBOX hdr.subject=\"Follow-up\" hdr.from=\"Bob <bob@example.com>\"\n"
                )
                .to_string(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        );
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should be valid");

        let results = backend
            .search_messages("alice@example.com", &request)
            .expect("message search should succeed");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].uid, 14);
        assert_eq!(results[0].subject.as_deref(), Some("Quarterly report"));
        assert_eq!(
            results[0].from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(results[1].uid, 15);

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-f".to_string(),
                "flow".to_string(),
                "fetch".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "uid flags date.received size.virtual mailbox hdr.subject hdr.from".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "TEXT".to_string(),
                "quarterly report".to_string(),
            ]
        );
    }

    #[test]
    fn message_move_uses_doveadm_move_command_shape() {
        let executor = Rc::new(std::cell::RefCell::new(StubCommandExecutor::success(
            CommandExecution {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        )));
        let backend = DoveadmMessageMoveBackend::new(executor.clone(), "/usr/local/bin/doveadm")
            .with_userdb_socket_path(Some(PathBuf::from("/var/run/osmap-userdb")));
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should be valid");

        backend
            .move_message("alice@example.com", &request)
            .expect("message move should succeed");

        let recorded = executor.borrow();
        assert_eq!(
            recorded.args.as_ref().expect("args should be captured"),
            &vec![
                "-o".to_string(),
                "stats_writer_socket_path=".to_string(),
                "-o".to_string(),
                "auth_socket_path=/var/run/osmap-userdb".to_string(),
                "move".to_string(),
                "-u".to_string(),
                "alice@example.com".to_string(),
                "Archive/2026".to_string(),
                "mailbox".to_string(),
                "INBOX".to_string(),
                "uid".to_string(),
                "9".to_string(),
            ]
        );
    }

    #[test]
    fn parses_multiline_message_view_from_live_style_flow_output() {
        let message = parse_doveadm_message_view_output(
            MessageViewPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: concat!(
                    "uid=1 flags=\\Recent date.received=2026-03-28 01:00:32 size.virtual=606 mailbox=INBOX hdr=From: OSMAP Validation <osmap-helper-validation@blackbagsecurity.com>\n",
                    "To: OSMAP Validation <osmap-helper-validation@blackbagsecurity.com>\n",
                    "Subject: OSMAP helper attachment validation\n",
                    "MIME-Version: 1.0\n",
                    "Content-Type: multipart/mixed; boundary=\"osmap-boundary\"\n",
                    "\n",
                    " body=--osmap-boundary\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "This is the helper validation message body.\n",
                    "\n",
                    "--osmap-boundary--\n",
                )
                .to_string(),
                stderr: String::new(),
            },
        )
        .expect("multiline flow output should parse");

        assert_eq!(message.uid, 1);
        assert_eq!(message.mailbox_name, "INBOX");
        assert_eq!(message.size_virtual, 606);
        assert!(message
            .header_block
            .contains("Subject: OSMAP helper attachment validation"));
        assert!(message
            .body_text
            .contains("This is the helper validation message body."));
    }

    #[test]
    fn rejects_message_list_output_missing_required_fields() {
        let error = parse_doveadm_message_list_output(
            MessageListPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "uid=4 flags=\"\" size.virtual=2048 mailbox=INBOX\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("missing fields must fail");

        assert_eq!(error.backend, "message-list-parser");
        assert_eq!(
            error.reason,
            "missing required message-list field date.received"
        );
    }

    #[test]
    fn rejects_message_view_output_missing_required_fields() {
        let error = parse_doveadm_message_view_output(
            MessageViewPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "uid=9 flags=\"\\\\Seen\" date.received=\"2026-03-27 11:00:00 +0000\" size.virtual=512 mailbox=INBOX hdr=\"Subject: test\\n\"\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("missing body field must fail");

        assert_eq!(error.backend, "message-view-parser");
        assert_eq!(error.reason, "missing required message-view field body");
    }

    #[test]
    fn rejects_message_search_with_empty_query() {
        let error = MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "   ")
            .expect_err("empty query must fail");

        assert_eq!(error.backend, "message-search-parser");
        assert_eq!(error.reason, "search query must not be empty");
    }

    #[test]
    fn rejects_message_search_output_missing_required_fields() {
        let error = parse_doveadm_message_search_output(
            MessageSearchPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "uid=4 flags=\"\" size.virtual=2048 mailbox=INBOX hdr.subject=\"Test\"\n"
                    .to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("missing fields must fail");

        assert_eq!(error.backend, "message-search-parser");
        assert_eq!(
            error.reason,
            "missing required message-search field date.received"
        );
    }

    #[test]
    fn rejects_message_move_with_same_source_and_destination() {
        let error = MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "INBOX", 9)
            .expect_err("identical source and destination must fail");

        assert_eq!(error.backend, "message-move-parser");
        assert_eq!(
            error.reason,
            "destination mailbox must differ from source mailbox"
        );
    }

    #[test]
    fn rejects_control_characters_in_mailbox_output() {
        let error = parse_doveadm_mailbox_list_output(
            MailboxListingPolicy::default(),
            &CommandExecution {
                status_code: 0,
                stdout: "INBOX\nSent\u{0007}\n".to_string(),
                stderr: String::new(),
            },
        )
        .expect_err("control characters must fail");

        assert_eq!(error.backend, "mailbox-parser");
        assert_eq!(error.reason, "mailbox name contains control characters");
    }

    #[test]
    fn message_view_service_emits_audit_quality_success_events() {
        let service = MessageViewService::new(StaticMessageViewBackend {
            message: MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            },
        });
        let validated_session = validated_session_fixture();
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");

        let outcome =
            service.fetch_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_viewed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 6262);
        assert_eq!(
            rendered,
            format!(
                "ts=6262 level=info category=mailbox action=message_viewed msg=\"message retrieval completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_name=\"INBOX\" uid=\"9\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_view_service_maps_missing_messages_to_not_found() {
        let service = MessageViewService::new(MissingMessageViewBackend);
        let validated_session = validated_session_fixture();
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");

        let outcome =
            service.fetch_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageViewDecision::Denied {
                public_reason: MailboxPublicFailureReason::NotFound,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_view_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn mailbox_service_emits_audit_quality_success_events() {
        let service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Archive".to_string(),
                },
            ],
        });
        let validated_session = validated_session_fixture();

        let outcome = service.list_for_validated_session(&test_context(), &validated_session);

        assert_eq!(
            outcome.decision,
            MailboxListingDecision::Listed {
                canonical_username: "alice@example.com".to_string(),
                session_id: validated_session.record.session_id.clone(),
                mailboxes: vec![
                    MailboxEntry {
                        name: "INBOX".to_string(),
                    },
                    MailboxEntry {
                        name: "Archive".to_string(),
                    },
                ],
            }
        );
        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "mailbox_listed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 4242);
        assert_eq!(
            rendered,
            format!(
                "ts=4242 level=info category=mailbox action=mailbox_listed msg=\"mailbox listing completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn mailbox_service_translates_backend_failures_into_bounded_events() {
        let service = MailboxListingService::new(FailingMailboxBackend);
        let validated_session = validated_session_fixture();

        let outcome = service.list_for_validated_session(&test_context(), &validated_session);

        assert_eq!(
            outcome.decision,
            MailboxListingDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "mailbox_list_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn message_list_service_emits_audit_quality_success_events() {
        let service = MessageListService::new(StaticMessageListBackend {
            messages: vec![
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 4,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 09:00:00 +0000".to_string(),
                    size_virtual: 2048,
                },
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 5,
                    flags: vec![],
                    date_received: "2026-03-27 09:30:00 +0000".to_string(),
                    size_virtual: 1024,
                },
            ],
        });
        let validated_session = validated_session_fixture();
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");

        let outcome =
            service.list_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_listed");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 5252);
        assert_eq!(
            rendered,
            format!(
                "ts=5252 level=info category=mailbox action=message_listed msg=\"message list retrieval completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_name=\"INBOX\" message_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_list_service_translates_backend_failures_into_bounded_events() {
        let service = MessageListService::new(FailingMessageListBackend);
        let validated_session = validated_session_fixture();
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");

        let outcome =
            service.list_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageListDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_list_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn message_search_service_emits_audit_quality_success_events() {
        let service = MessageSearchService::new(StaticMessageSearchBackend {
            results: vec![
                MessageSearchResult {
                    mailbox_name: "INBOX".to_string(),
                    uid: 14,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 15:00:00 +0000".to_string(),
                    size_virtual: 2048,
                    subject: Some("Quarterly report".to_string()),
                    from: Some("Alice <alice@example.com>".to_string()),
                },
                MessageSearchResult {
                    mailbox_name: "INBOX".to_string(),
                    uid: 15,
                    flags: Vec::new(),
                    date_received: "2026-03-27 16:00:00 +0000".to_string(),
                    size_virtual: 1024,
                    subject: Some("Follow-up".to_string()),
                    from: Some("Bob <bob@example.com>".to_string()),
                },
            ],
        });
        let validated_session = validated_session_fixture();
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should be valid");

        let outcome =
            service.search_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_searched");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 5353);
        assert_eq!(
            rendered,
            format!(
                "ts=5353 level=info category=mailbox action=message_searched msg=\"message search completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" mailbox_name=\"INBOX\" query=\"quarterly report\" result_count=\"2\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_search_service_translates_backend_failures_into_bounded_events() {
        let service = MessageSearchService::new(FailingMessageSearchBackend);
        let validated_session = validated_session_fixture();
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should be valid");

        let outcome =
            service.search_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageSearchDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_search_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn message_move_service_emits_audit_quality_success_events() {
        let service = MessageMoveService::new(StaticMessageMoveBackend);
        let validated_session = validated_session_fixture();
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should be valid");

        let outcome =
            service.move_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(outcome.audit_event.category, EventCategory::Mailbox);
        assert_eq!(outcome.audit_event.action, "message_moved");

        let logger = Logger::new(LogFormat::Text, LogLevel::Debug);
        let rendered = logger.render_with_timestamp(&outcome.audit_event, 5454);
        assert_eq!(
            rendered,
            format!(
                "ts=5454 level=info category=mailbox action=message_moved msg=\"message move completed\" canonical_username=\"alice@example.com\" session_id=\"{}\" source_mailbox_name=\"INBOX\" destination_mailbox_name=\"Archive/2026\" uid=\"9\" request_id=\"req-mailbox\" remote_addr=\"127.0.0.1\" user_agent=\"Firefox/Test\"",
                validated_session.record.session_id
            )
        );
    }

    #[test]
    fn message_move_service_translates_backend_failures_into_bounded_events() {
        let service = MessageMoveService::new(FailingMessageMoveBackend);
        let validated_session = validated_session_fixture();
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should be valid");

        let outcome =
            service.move_for_validated_session(&test_context(), &validated_session, &request);

        assert_eq!(
            outcome.decision,
            MessageMoveDecision::Denied {
                public_reason: MailboxPublicFailureReason::TemporarilyUnavailable,
            }
        );
        assert_eq!(outcome.audit_event.action, "message_move_failed");
        assert_eq!(outcome.audit_event.level, LogLevel::Warn);
    }

    #[test]
    fn full_auth_session_and_mailbox_flow_succeeds() {
        let secret_dir = temp_dir("osmap-mailbox-secret");
        let session_dir = temp_dir("osmap-mailbox-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(&secret_path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should be written");

        let auth_service =
            AuthenticationService::new(AuthenticationPolicy::default(), AcceptingPrimaryBackend);
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );
        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0x88; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(
                &test_context(),
                &canonical_username,
                RequiredSecondFactor::Totp,
            )
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent".to_string(),
                },
            ],
        });
        let outcome = service.list_for_validated_session(&test_context(), &validated);

        match outcome.decision {
            MailboxListingDecision::Listed {
                canonical_username,
                session_id,
                mailboxes,
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(session_id, validated.record.session_id);
                assert_eq!(mailboxes.len(), 2);
                assert_eq!(mailboxes[0].name, "INBOX");
            }
            other => panic!("expected mailbox listing, got {other:?}"),
        }
    }

    #[test]
    fn full_auth_session_mailbox_and_message_list_flow_succeeds() {
        let secret_dir = temp_dir("osmap-message-secret");
        let session_dir = temp_dir("osmap-message-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(&secret_path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should be written");

        let auth_service =
            AuthenticationService::new(AuthenticationPolicy::default(), AcceptingPrimaryBackend);
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );
        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0x99; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(
                &test_context(),
                &canonical_username,
                RequiredSecondFactor::Totp,
            )
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let mailbox_service = MailboxListingService::new(StaticMailboxBackend {
            mailboxes: vec![MailboxEntry {
                name: "INBOX".to_string(),
            }],
        });
        let mailbox_outcome =
            mailbox_service.list_for_validated_session(&test_context(), &validated);
        match mailbox_outcome.decision {
            MailboxListingDecision::Listed { mailboxes, .. } => {
                assert_eq!(mailboxes.len(), 1);
                assert_eq!(mailboxes[0].name, "INBOX");
            }
            other => panic!("expected mailbox listing, got {other:?}"),
        }

        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");
        let message_service = MessageListService::new(StaticMessageListBackend {
            messages: vec![MessageSummary {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
            }],
        });
        let outcome =
            message_service.list_for_validated_session(&test_context(), &validated, &request);

        match outcome.decision {
            MessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
                ..
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(mailbox_name, "INBOX");
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].uid, 9);
            }
            other => panic!("expected message list, got {other:?}"),
        }
    }

    #[test]
    fn full_auth_session_message_view_flow_succeeds() {
        let secret_dir = temp_dir("osmap-view-secret");
        let session_dir = temp_dir("osmap-view-session");
        let secret_store = FileTotpSecretStore::new(&secret_dir);
        let secret_path = secret_store.secret_path_for_username("alice@example.com");
        fs::write(&secret_path, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n")
            .expect("secret file should be written");

        let auth_service =
            AuthenticationService::new(AuthenticationPolicy::default(), AcceptingPrimaryBackend);
        let auth_outcome = auth_service.authenticate(
            &test_context(),
            "alice@example.com",
            "correct horse battery staple",
        );
        let canonical_username = match auth_outcome.decision {
            AuthenticationDecision::MfaRequired {
                canonical_username,
                second_factor,
            } => {
                assert_eq!(second_factor, RequiredSecondFactor::Totp);
                canonical_username
            }
            other => panic!("expected MFA-required decision, got {other:?}"),
        };

        let factor_service = SecondFactorService::new(
            AuthenticationPolicy::default(),
            TotpVerifier::new(
                secret_store,
                FixedTimeProvider::new(59),
                TotpPolicy {
                    digits: 8,
                    period_seconds: 30,
                    allowed_skew_steps: 0,
                },
            ),
        );
        let factor_outcome = factor_service.verify(
            &test_context(),
            canonical_username.clone(),
            RequiredSecondFactor::Totp,
            "94287082",
        );
        assert_eq!(
            factor_outcome.decision,
            AuthenticationDecision::AuthenticatedPendingSession {
                canonical_username: canonical_username.clone(),
            }
        );

        let session_service = SessionService::new(
            FileSessionStore::new(&session_dir),
            FixedTimeProvider::new(59),
            StaticRandomSource {
                bytes: vec![0xaa; SESSION_TOKEN_BYTES],
            },
            3600,
        );
        let issued = session_service
            .issue(
                &test_context(),
                &canonical_username,
                RequiredSecondFactor::Totp,
            )
            .expect("session issuance should succeed");
        let validated = session_service
            .validate(&test_context(), &issued.token)
            .expect("session validation should succeed");

        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 9)
            .expect("request should be valid");
        let service = MessageViewService::new(StaticMessageViewBackend {
            message: MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 11:00:00 +0000".to_string(),
                size_virtual: 512,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            },
        });
        let outcome = service.fetch_for_validated_session(&test_context(), &validated, &request);

        match outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                message,
                ..
            } => {
                assert_eq!(canonical_username, "alice@example.com");
                assert_eq!(message.uid, 9);
                assert_eq!(message.mailbox_name, "INBOX");
                assert_eq!(message.body_text, "Hello world\n");
            }
            other => panic!("expected message view, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_mailbox_list_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMailboxListBackend::default();
        let error = backend
            .list_mailboxes("osmap-no-such-user@example.invalid")
            .expect_err("missing users should not produce mailbox listings");

        assert_eq!(error.backend, "doveadm-mailbox-list");
        assert!(error.reason.contains("status 67"));
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_message_list_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMessageListBackend::default();
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should be valid");
        let error = backend
            .list_messages("osmap-no-such-user@example.invalid", &request)
            .expect_err("missing users should not produce message listings");

        assert_eq!(error.backend, "doveadm-message-list");
        assert!(error.reason.contains("status 67"));
    }

    #[test]
    #[ignore = "requires a host with doveadm configured against a live Dovecot mailbox surface"]
    fn live_doveadm_message_view_rejects_missing_user() {
        if !Path::new("/usr/local/bin/doveadm").exists() {
            return;
        }

        let backend = DoveadmMessageViewBackend::default();
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 1)
            .expect("request should be valid");
        let error = backend
            .fetch_message("osmap-no-such-user@example.invalid", &request)
            .expect_err("missing users should not produce message retrieval");

        assert_eq!(error.backend, "doveadm-message-view");
        assert!(error.reason.contains("status 67"));
    }

    #[derive(Debug, Clone)]
    struct StaticMailboxBackend {
        mailboxes: Vec<MailboxEntry>,
    }

    impl MailboxBackend for StaticMailboxBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Ok(self.mailboxes.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageListBackend {
        messages: Vec<MessageSummary>,
    }

    impl MessageListBackend for StaticMessageListBackend {
        fn list_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageListRequest,
        ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
            Ok(self.messages.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageSearchBackend {
        results: Vec<MessageSearchResult>,
    }

    impl MessageSearchBackend for StaticMessageSearchBackend {
        fn search_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageSearchRequest,
        ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
            Ok(self.results.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageViewBackend {
        message: MessageView,
    }

    impl MessageViewBackend for StaticMessageViewBackend {
        fn fetch_message(
            &self,
            _canonical_username: &str,
            _request: &MessageViewRequest,
        ) -> Result<MessageView, MailboxBackendError> {
            Ok(self.message.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct StaticMessageMoveBackend;

    impl MessageMoveBackend for StaticMessageMoveBackend {
        fn move_message(
            &self,
            _canonical_username: &str,
            _request: &MessageMoveRequest,
        ) -> Result<(), MailboxBackendError> {
            Ok(())
        }
    }

    fn validated_session_fixture() -> ValidatedSession {
        ValidatedSession {
            record: crate::session::SessionRecord {
                session_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
                csrf_token: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .to_string(),
                canonical_username: "alice@example.com".to_string(),
                issued_at: 10,
                expires_at: 100,
                last_seen_at: 20,
                revoked_at: None,
                remote_addr: "127.0.0.1".to_string(),
                user_agent: "Firefox/Test".to_string(),
                factor: RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "session_validated",
                "browser session validated",
            ),
        }
    }
}
