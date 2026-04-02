//! Mailbox service layer and audit-event helpers.
//!
//! Keeping the validated-session service layer separate from backend command
//! wiring reduces how much application logic is concentrated in `mailbox.rs`
//! while preserving the existing public mailbox API.

use super::*;

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
