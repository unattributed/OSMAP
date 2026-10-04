#[cfg(unix)]
use crate::attachment::{AttachmentDownloadPolicy, AttachmentDownloadService};
#[cfg(unix)]
use crate::config::LogLevel;
#[cfg(unix)]
use crate::logging::{EventCategory, LogEvent, Logger};
#[cfg(unix)]
use crate::mailbox::{
    MailboxBackend, MessageAppendBackend, MessageAppendRequest, MessageListBackend,
    MessageListPolicy, MessageListRequest, MessageMoveBackend, MessageMovePolicy,
    MessageMoveRequest, MessageSearchBackend, MessageSearchBatchRequest, MessageSearchPolicy,
    MessageSearchRequest, MessageViewBackend, MessageViewPolicy, MessageViewRequest,
};

#[cfg(unix)]
use super::{MailboxHelperRequest, MailboxHelperResponse};
#[cfg(unix)]
use crate::mailbox::MessageFlagBackend;

#[cfg(unix)]
pub(super) struct HelperBackends<'a, MB, MLB, MSB, MVB, MMB, MAB, MFB> {
    pub(super) mailbox_backend: &'a MB,
    pub(super) message_list_backend: &'a MLB,
    pub(super) message_search_backend: &'a MSB,
    pub(super) message_view_backend: &'a MVB,
    pub(super) message_move_backend: &'a MMB,
    pub(super) message_append_backend: &'a MAB,
    pub(super) message_flag_backend: &'a MFB,
}

#[cfg(unix)]
pub(super) fn dispatch_helper_request_with_delete<MB, MLB, MSB, MVB, MMB, MAB, MFB>(
    backends: HelperBackends<'_, MB, MLB, MSB, MVB, MMB, MAB, MFB>,
    delete_backend: Option<&dyn crate::mailbox::MessageDeleteBackend>,
    request: &MailboxHelperRequest,
) -> MailboxHelperResponse
where
    MB: MailboxBackend,
    MLB: MessageListBackend,
    MSB: MessageSearchBackend,
    MVB: MessageViewBackend,
    MMB: MessageMoveBackend,
    MAB: MessageAppendBackend,
    MFB: MessageFlagBackend,
{
    match request {
        MailboxHelperRequest::RetentionStatus {
            canonical_username,
            mailbox_name,
            grant,
        } => MailboxHelperResponse::RetentionStatus {
            canonical_username: canonical_username.clone(),
            mailbox_name: mailbox_name.clone(),
            decision: delete_backend
                .map(|backend| backend.retention_status(canonical_username, mailbox_name))
                .unwrap_or(crate::mailbox::RetentionDecision::Unavailable),
            nonce: grant.nonce.clone(),
        },
        MailboxHelperRequest::MessageDelete { request, grant } => {
            MailboxHelperResponse::MessageDelete {
                request: Box::new(request.clone()),
                result: delete_backend
                    .map(|backend| backend.delete_message(&request.canonical_username, request))
                    .unwrap_or(Err(crate::mailbox::MessageDeleteError::PolicyUnavailable)),
                nonce: grant.nonce.clone(),
            }
        }
        MailboxHelperRequest::FolderCreate { request, .. } => {
            MailboxHelperResponse::FolderCreateOk {
                request: request.clone(),
                outcome: backends.mailbox_backend.create_folder(request),
            }
        }
        MailboxHelperRequest::FolderMetadata {
            canonical_username, ..
        } => match backends.mailbox_backend.folder_metadata(canonical_username) {
            Ok(snapshot) if snapshot.validate_for(canonical_username).is_ok() => {
                MailboxHelperResponse::FolderMetadataOk { snapshot }
            }
            _ => MailboxHelperResponse::Error {
                backend: "folder-metadata".into(),
                reason: "folder metadata unavailable".into(),
            },
        },
        MailboxHelperRequest::MailboxStatus {
            canonical_username,
            mailbox_name,
            ..
        } => match backends
            .mailbox_backend
            .mailbox_status(canonical_username, mailbox_name)
        {
            Ok(status) if status.validate(mailbox_name).is_ok() => {
                MailboxHelperResponse::MailboxStatusOk { status }
            }
            _ => MailboxHelperResponse::Error {
                backend: "mailbox-status".into(),
                reason: "exact folder status is unavailable".into(),
            },
        },
        MailboxHelperRequest::MessageFlag {
            canonical_username,
            request,
            ..
        } => match backends
            .message_flag_backend
            .set_message_flag(canonical_username, request)
        {
            Ok(result) => MailboxHelperResponse::MessageFlagOk {
                request: request.clone(),
                result,
            },
            Err(error) => MailboxHelperResponse::Error {
                backend: error.backend.into(),
                reason: error.reason,
            },
        },
        MailboxHelperRequest::MailboxList {
            canonical_username, ..
        } => match backends.mailbox_backend.list_mailboxes(canonical_username) {
            Ok(mailboxes) => MailboxHelperResponse::MailboxListOk { mailboxes },
            Err(error) => MailboxHelperResponse::Error {
                backend: error.backend.to_string(),
                reason: error.reason,
            },
        },
        MailboxHelperRequest::MessageList {
            canonical_username,
            mailbox_name,
            ..
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
            field,
            ..
        } => {
            match MessageSearchRequest::new_with_field(
                MessageSearchPolicy::default(),
                mailbox_name.clone(),
                query.clone(),
                *field,
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
                    field: *field,
                    results,
                },
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageSearchBatch {
            canonical_username,
            mailbox_names,
            query,
            field,
            ..
        } => {
            match MessageSearchBatchRequest::new(
                MessageSearchPolicy::default(),
                mailbox_names.clone(),
                query.clone(),
                *field,
            )
            .map_err(|error| MailboxHelperResponse::Error {
                backend: error.backend.to_string(),
                reason: error.reason,
            })
            .and_then(|request| {
                backends
                    .message_search_backend
                    .search_messages_batch(canonical_username, &request)
                    .map_err(|error| MailboxHelperResponse::Error {
                        backend: error.backend.to_string(),
                        reason: error.reason,
                    })
            }) {
                Ok(results) => MailboxHelperResponse::MessageSearchBatchOk {
                    mailbox_names: mailbox_names.clone(),
                    query: query.clone(),
                    field: *field,
                    results,
                },
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageView {
            canonical_username,
            mailbox_name,
            uid,
            ..
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
        MailboxHelperRequest::AttachmentDownload {
            canonical_username,
            mailbox_name,
            uid,
            part_path,
            ..
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
                })
                .and_then(|message| {
                    AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
                        .download_from_message(&message, part_path)
                        .map(|attachment| MailboxHelperResponse::AttachmentDownloadOk {
                            attachment: Box::new(attachment),
                        })
                        .map_err(|error| MailboxHelperResponse::Error {
                            backend: error.helper_backend_label().to_string(),
                            reason: error.reason,
                        })
                }) {
                Ok(response) => response,
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageMove {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
            version,
            ..
        } => {
            match MessageMoveRequest::new(
                MessageMovePolicy::default(),
                source_mailbox_name.clone(),
                destination_mailbox_name.clone(),
                *uid,
                version.clone(),
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
                    version: version.clone(),
                },
                Err(error_response) => error_response,
            }
        }
        MailboxHelperRequest::MessageAppend {
            canonical_username,
            mailbox_name,
            message,
            destination_mailbox_guid,
            ..
        } => {
            match MessageAppendRequest::new(mailbox_name.clone(), message.clone())
                .and_then(|request| match destination_mailbox_guid {
                    Some(guid) => request.with_destination_mailbox_guid(guid),
                    None => Ok(request),
                })
                .map_err(|error| MailboxHelperResponse::Error {
                    backend: error.backend.to_string(),
                    reason: error.reason,
                })
                .and_then(|request| {
                    backends
                        .message_append_backend
                        .append_message(canonical_username, &request)
                        .map_err(|error| MailboxHelperResponse::Error {
                            backend: error.backend.to_string(),
                            reason: error.reason,
                        })
                }) {
                Ok(()) => MailboxHelperResponse::MessageAppendOk {
                    destination_mailbox_guid: destination_mailbox_guid.clone(),
                    mailbox_name: mailbox_name.clone(),
                    message_bytes: message.len(),
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
            MailboxHelperResponse::RetentionStatus { decision, .. },
            Some(MailboxHelperRequest::RetentionStatus { .. }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_retention_status",
                "mailbox helper checked retention authority",
            )
            .with_field(
                "result",
                match decision {
                    crate::mailbox::RetentionDecision::Allowed { .. } => "allowed",
                    crate::mailbox::RetentionDecision::Denied => "denied",
                    crate::mailbox::RetentionDecision::Unavailable => "unavailable",
                },
            ),
        ),
        (
            MailboxHelperResponse::MessageDelete { result, .. },
            Some(MailboxHelperRequest::MessageDelete { .. }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_delete_result",
                "mailbox helper returned exact deletion outcome",
            )
            .with_field(
                "result",
                match result {
                    Ok(_) => "deleted",
                    Err(crate::mailbox::MessageDeleteError::Invalid) => "invalid",
                    Err(crate::mailbox::MessageDeleteError::Stale) => "stale",
                    Err(crate::mailbox::MessageDeleteError::PolicyDenied) => "policy_denied",
                    Err(crate::mailbox::MessageDeleteError::PolicyUnavailable) => {
                        "policy_unavailable"
                    }
                    Err(crate::mailbox::MessageDeleteError::Busy) => "busy",
                    Err(crate::mailbox::MessageDeleteError::Unavailable) => "unavailable",
                    Err(crate::mailbox::MessageDeleteError::Unknown) => "unknown",
                },
            ),
        ),
        (
            MailboxHelperResponse::MessageFlagOk { request, result },
            Some(MailboxHelperRequest::MessageFlag { .. }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_flagged",
                "mailbox helper confirmed message flag state",
            )
            .with_field("flag", request.flag.value())
            .with_field("enabled", request.enabled.to_string())
            .with_field(
                "result",
                match result {
                    crate::mailbox::MessageFlagResult::Updated => "updated",
                    crate::mailbox::MessageFlagResult::AlreadySet => "already_set",
                },
            ),
        ),
        (
            MailboxHelperResponse::MailboxListOk { mailboxes },
            Some(MailboxHelperRequest::MailboxList {
                canonical_username, ..
            }),
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
                field,
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
            .with_field("search_field", field.query_value())
            .with_field("result_count", results.len().to_string()),
        ),
        (
            MailboxHelperResponse::MessageSearchBatchOk {
                mailbox_names,
                results,
                ..
            },
            Some(MailboxHelperRequest::MessageSearchBatch {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_batch_searched",
                "mailbox helper searched ordered mailbox scope",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_count", mailbox_names.len().to_string())
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
                ..
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
        (
            MailboxHelperResponse::AttachmentDownloadOk { attachment },
            Some(MailboxHelperRequest::AttachmentDownload {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_attachment_downloaded",
                "mailbox helper downloaded one attachment",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_name", attachment.mailbox_name.clone())
            .with_field("uid", attachment.uid.to_string())
            .with_field("part_path", attachment.part_path.clone())
            .with_field("download_bytes", attachment.body.len().to_string()),
        ),
        (
            MailboxHelperResponse::MessageAppendOk {
                mailbox_name,
                message_bytes,
                ..
            },
            Some(MailboxHelperRequest::MessageAppend {
                canonical_username, ..
            }),
        ) => logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_message_appended",
                "mailbox helper appended one message",
            )
            .with_field("canonical_username", canonical_username.clone())
            .with_field("mailbox_name", mailbox_name.clone())
            .with_field("message_bytes", message_bytes.to_string()),
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
        MailboxHelperRequest::RetentionStatus { .. } => "retention_status",
        MailboxHelperRequest::MessageDelete { .. } => "message_delete",
        MailboxHelperRequest::MessageFlag { .. } => "message_flag",
        MailboxHelperRequest::FolderCreate { .. } => "folder_create",
        MailboxHelperRequest::FolderMetadata { .. } => "folder_metadata",
        MailboxHelperRequest::MailboxStatus { .. } => "mailbox_status",
        MailboxHelperRequest::MailboxList { .. } => "mailbox_list",
        MailboxHelperRequest::MessageList { .. } => "message_list",
        MailboxHelperRequest::MessageSearch { .. } => "message_search",
        MailboxHelperRequest::MessageSearchBatch { .. } => "message_search_batch",
        MailboxHelperRequest::MessageView { .. } => "message_view",
        MailboxHelperRequest::AttachmentDownload { .. } => "attachment_download",
        MailboxHelperRequest::MessageMove { .. } => "message_move",
        MailboxHelperRequest::MessageAppend { .. } => "message_append",
    }
}
