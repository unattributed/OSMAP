#[cfg(unix)]
use crate::config::LogLevel;
#[cfg(unix)]
use crate::logging::{EventCategory, LogEvent, Logger};
#[cfg(unix)]
use crate::mailbox::{
    MailboxBackend, MessageListBackend, MessageListPolicy, MessageListRequest, MessageMoveBackend,
    MessageMovePolicy, MessageMoveRequest, MessageSearchBackend, MessageSearchPolicy,
    MessageSearchRequest, MessageViewBackend, MessageViewPolicy, MessageViewRequest,
};

#[cfg(unix)]
use super::{MailboxHelperRequest, MailboxHelperResponse};

#[cfg(unix)]
pub(super) struct HelperBackends<'a, MB, MLB, MSB, MVB, MMB> {
    pub(super) mailbox_backend: &'a MB,
    pub(super) message_list_backend: &'a MLB,
    pub(super) message_search_backend: &'a MSB,
    pub(super) message_view_backend: &'a MVB,
    pub(super) message_move_backend: &'a MMB,
}

#[cfg(unix)]
pub(super) fn dispatch_helper_request<MB, MLB, MSB, MVB, MMB>(
    backends: HelperBackends<'_, MB, MLB, MSB, MVB, MMB>,
    request: &MailboxHelperRequest,
) -> MailboxHelperResponse
where
    MB: MailboxBackend,
    MLB: MessageListBackend,
    MSB: MessageSearchBackend,
    MVB: MessageViewBackend,
    MMB: MessageMoveBackend,
{
    match request {
        MailboxHelperRequest::MailboxList { canonical_username } => {
            match backends.mailbox_backend.list_mailboxes(canonical_username) {
                Ok(mailboxes) => MailboxHelperResponse::MailboxListOk { mailboxes },
                Err(error) => MailboxHelperResponse::Error {
                    backend: error.backend.to_string(),
                    reason: error.reason,
                },
            }
        }
        MailboxHelperRequest::MessageList {
            canonical_username,
            mailbox_name,
        } => {
            match MessageListRequest::new(MessageListPolicy::default(), mailbox_name.clone())
                .map_err(|error| MailboxHelperResponse::Error {
                    backend: error.backend.to_string(),
                    reason: error.reason,
                })
                .and_then(|request| {
                    backends
                        .message_list_backend
                        .list_messages(canonical_username, &request)
                        .map_err(|error| MailboxHelperResponse::Error {
                            backend: error.backend.to_string(),
                            reason: error.reason,
                        })
                }) {
                Ok(messages) => MailboxHelperResponse::MessageListOk {
                    mailbox_name: mailbox_name.clone(),
                    messages,
                },
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageSearch {
            canonical_username,
            mailbox_name,
            query,
        } => {
            match MessageSearchRequest::new(
                MessageSearchPolicy::default(),
                mailbox_name.clone(),
                query.clone(),
            )
            .map_err(|error| MailboxHelperResponse::Error {
                backend: error.backend.to_string(),
                reason: error.reason,
            })
            .and_then(|request| {
                backends
                    .message_search_backend
                    .search_messages(canonical_username, &request)
                    .map_err(|error| MailboxHelperResponse::Error {
                        backend: error.backend.to_string(),
                        reason: error.reason,
                    })
            }) {
                Ok(results) => MailboxHelperResponse::MessageSearchOk {
                    mailbox_name: mailbox_name.clone(),
                    query: query.clone(),
                    results,
                },
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageView {
            canonical_username,
            mailbox_name,
            uid,
        } => {
            match MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name.clone(), *uid)
                .map_err(|error| MailboxHelperResponse::Error {
                    backend: error.backend.to_string(),
                    reason: error.reason,
                })
                .and_then(|request| {
                    backends
                        .message_view_backend
                        .fetch_message(canonical_username, &request)
                        .map_err(|error| MailboxHelperResponse::Error {
                            backend: error.backend.to_string(),
                            reason: error.reason,
                        })
                }) {
                Ok(message) => MailboxHelperResponse::MessageViewOk {
                    message: Box::new(message),
                },
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageMove {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        } => {
            match MessageMoveRequest::new(
                MessageMovePolicy::default(),
                source_mailbox_name.clone(),
                destination_mailbox_name.clone(),
                *uid,
            )
            .map_err(|error| MailboxHelperResponse::Error {
                backend: error.backend.to_string(),
                reason: error.reason,
            })
            .and_then(|request| {
                backends
                    .message_move_backend
                    .move_message(canonical_username, &request)
                    .map_err(|error| MailboxHelperResponse::Error {
                        backend: error.backend.to_string(),
                        reason: error.reason,
                    })
            }) {
                Ok(()) => MailboxHelperResponse::MessageMoveOk {
                    source_mailbox_name: source_mailbox_name.clone(),
                    destination_mailbox_name: destination_mailbox_name.clone(),
                    uid: *uid,
                },
                Err(error_response) => error_response,
            }
        }
    }
}

#[cfg(unix)]
pub(super) fn log_helper_response(
    logger: &Logger,
    response: &MailboxHelperResponse,
    request: Option<&MailboxHelperRequest>,
) {
    match (response, request) {
        (
            MailboxHelperResponse::MailboxListOk { mailboxes },
            Some(MailboxHelperRequest::MailboxList { canonical_username }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_listed",
                "mailbox helper listed mailboxes",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_count", mailboxes.len().to_string()),
        ),
        (
            MailboxHelperResponse::MessageListOk {
                mailbox_name,
                messages,
            },
            Some(MailboxHelperRequest::MessageList {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_listed",
                "mailbox helper listed messages",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_name", mailbox_name.clone())
            .with_field("message_count", messages.len().to_string()),
        ),
        (
            MailboxHelperResponse::MessageSearchOk {
                mailbox_name,
                query,
                results,
            },
            Some(MailboxHelperRequest::MessageSearch {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_searched",
                "mailbox helper searched messages",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_name", mailbox_name.clone())
            .with_field("query", query.clone())
            .with_field("result_count", results.len().to_string()),
        ),
        (
            MailboxHelperResponse::MessageViewOk { message },
            Some(MailboxHelperRequest::MessageView {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_viewed",
                "mailbox helper retrieved one message",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_name", message.mailbox_name.clone())
            .with_field("uid", message.uid.to_string()),
        ),
        (
            MailboxHelperResponse::MessageMoveOk {
                source_mailbox_name,
                destination_mailbox_name,
                uid,
            },
            Some(MailboxHelperRequest::MessageMove {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_moved",
                "mailbox helper moved one message",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("source_mailbox_name", source_mailbox_name.clone())
            .with_field("destination_mailbox_name", destination_mailbox_name.clone())
            .with_field("uid", uid.to_string()),
        ),
        (MailboxHelperResponse::Error { backend, reason }, Some(request)) => logger.emit(
            &LogEvent::new(
                LogLevel::Warn,
                EventCategory::Mailbox,
                "mailbox_helper_request_failed",
                "mailbox helper request failed",
            )
            .with_field("operation", helper_operation_label(request))
            .with_field("backend", backend.clone())
            .with_field("reason", reason.clone()),
        ),
        (MailboxHelperResponse::Error { backend, reason }, None) => logger.emit(
            &LogEvent::new(
                LogLevel::Warn,
                EventCategory::Mailbox,
                "mailbox_helper_request_rejected",
                "mailbox helper rejected request",
            )
            .with_field("backend", backend.clone())
            .with_field("reason", reason.clone()),
        ),
        _ => {}
    }
}

#[cfg(unix)]
fn helper_operation_label(request: &MailboxHelperRequest) -> &'static str {
    match request {
        MailboxHelperRequest::MailboxList { .. } => "mailbox_list",
        MailboxHelperRequest::MessageList { .. } => "message_list",
        MailboxHelperRequest::MessageSearch { .. } => "message_search",
        MailboxHelperRequest::MessageView { .. } => "message_view",
        MailboxHelperRequest::MessageMove { .. } => "message_move",
    }
}
