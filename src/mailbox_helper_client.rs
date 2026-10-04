use super::*;
use crate::attachment::{
    AttachmentDownloadError, AttachmentDownloadFailureKind, DownloadedAttachment,
};
use crate::mailbox::MessageSearchBatchRequest;
#[cfg(unix)]
use std::time::Instant;

/// Client backend that proxies mailbox listing through the local helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMailboxListBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
}

impl MailboxHelperMailboxListBackend {
    /// Creates a mailbox-list client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
        }
    }
}

impl MailboxBackend for MailboxHelperMailboxListBackend {
    fn create_folder(
        &self,
        value: &crate::folder_create::CreateFolderRequest,
    ) -> crate::folder_create::Outcome {
        let execute = || -> Result<crate::folder_create::Outcome, MailboxBackendError> {
            value
                .validate()
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            let mut request = MailboxHelperRequest::FolderCreate {
                request: value.clone(),
                grant: MailboxHelperGrant::unsigned(),
            };
            let bytes = encode_authorized_request(&self.grant_key_path, &mut request)
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            #[cfg(not(unix))]
            {
                let _ = bytes;
                Err(crate::folder_metadata_backend::unavailable())
            }
            #[cfg(unix)]
            {
                let mut stream = UnixStream::connect(&self.socket_path)
                    .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(
                        self.policy.read_timeout_secs.max(1),
                    )))
                    .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(
                        self.policy.write_timeout_secs.max(1),
                    )))
                    .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                stream
                    .write_all(&bytes)
                    .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                let bytes =
                    read_bounded_from_stream(&mut stream, self.policy.max_response_bytes.min(4096))
                        .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                let response = parse_response(
                    MailboxListingPolicy::default(),
                    MessageListPolicy::default(),
                    MessageSearchPolicy::default(),
                    MessageViewPolicy::default(),
                    std::str::from_utf8(&bytes)
                        .map_err(|_| crate::folder_metadata_backend::unavailable())?,
                )
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                match response {
                    MailboxHelperResponse::FolderCreateOk { request, outcome }
                        if value.accepts_response(&request, &outcome) =>
                    {
                        Ok(outcome)
                    }
                    _ => Err(crate::folder_metadata_backend::unavailable()),
                }
            }
        };
        execute().unwrap_or(crate::folder_create::Outcome::Unknown)
    }

    fn folder_metadata(
        &self,
        account: &str,
    ) -> Result<crate::folder_metadata::FolderSnapshot, MailboxBackendError> {
        crate::mailbox_status::validate_account(account)?;
        let mut request = MailboxHelperRequest::FolderMetadata {
            canonical_username: account.into(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes = encode_authorized_request(&self.grant_key_path, &mut request)
            .map_err(|_| crate::folder_metadata_backend::unavailable())?;
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(crate::folder_metadata_backend::unavailable())
        }
        #[cfg(unix)]
        {
            let mut stream = UnixStream::connect(&self.socket_path)
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(
                    self.policy.read_timeout_secs.max(1),
                )))
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(
                    self.policy.write_timeout_secs.max(1),
                )))
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            stream
                .write_all(&bytes)
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            let bytes = read_bounded_from_stream(
                &mut stream,
                self.policy.max_response_bytes.min(704 * 1024),
            )
            .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&bytes)
                    .map_err(|_| crate::folder_metadata_backend::unavailable())?,
            )
            .map_err(|_| crate::folder_metadata_backend::unavailable())?;
            match response {
                MailboxHelperResponse::FolderMetadataOk { snapshot } => {
                    snapshot
                        .validate_for(account)
                        .map_err(|_| crate::folder_metadata_backend::unavailable())?;
                    Ok(snapshot)
                }
                _ => Err(crate::folder_metadata_backend::unavailable()),
            }
        }
    }

    fn mailbox_status(
        &self,
        account: &str,
        folder: &str,
    ) -> Result<crate::mailbox_status::MailboxStatus, MailboxBackendError> {
        crate::mailbox_status::validate_name(folder)?;
        let mut request = MailboxHelperRequest::MailboxStatus {
            canonical_username: account.into(),
            mailbox_name: folder.into(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes = encode_authorized_request(&self.grant_key_path, &mut request)
            .map_err(|_| crate::mailbox_status::unavailable())?;
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(crate::mailbox_status::unavailable())
        }
        #[cfg(unix)]
        {
            let mut stream = UnixStream::connect(&self.socket_path)
                .map_err(|_| crate::mailbox_status::unavailable())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(
                    self.policy.read_timeout_secs.max(1),
                )))
                .map_err(|_| crate::mailbox_status::unavailable())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(
                    self.policy.write_timeout_secs.max(1),
                )))
                .map_err(|_| crate::mailbox_status::unavailable())?;
            stream
                .write_all(&bytes)
                .map_err(|_| crate::mailbox_status::unavailable())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| crate::mailbox_status::unavailable())?;
            let bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes.min(4096))
                    .map_err(|_| crate::mailbox_status::unavailable())?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&bytes).map_err(|_| crate::mailbox_status::unavailable())?,
            )
            .map_err(|_| crate::mailbox_status::unavailable())?;
            match response {
                MailboxHelperResponse::MailboxStatusOk { status } => {
                    status.validate(folder)?;
                    Ok(status)
                }
                _ => Err(crate::mailbox_status::unavailable()),
            }
        }
    }

    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        #[cfg(unix)]
        let deadline = helper_request_deadline(self.policy);
        let mut request = MailboxHelperRequest::MailboxList {
            canonical_username: canonical_username.to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: "mailbox helper requires a Unix-domain socket platform".to_string(),
            });
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;
            let response_bytes =
                helper_exchange_before(&self.socket_path, &request_bytes, self.policy, deadline)
                    .map_err(|reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    })?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&response_bytes).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("helper response was not valid UTF-8: {error}"),
                })?,
            )
            .map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;

            match response {
                MailboxHelperResponse::RetentionStatus { .. }
                | MailboxHelperResponse::MessageDelete { .. }
                | MailboxHelperResponse::FolderCreateOk { .. }
                | MailboxHelperResponse::FolderMetadataOk { .. }
                | MailboxHelperResponse::MailboxStatusOk { .. }
                | MailboxHelperResponse::MessageFlagOk { .. }
                | MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned a flag response for a different operation".into(),
                }),
                MailboxHelperResponse::MailboxListOk { mailboxes } => {
                    helper_deadline_remaining(deadline).map_err(|reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    })?;
                    Ok(mailboxes)
                }
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                MailboxHelperResponse::MessageListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-list response for mailbox-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageSearchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-search response for mailbox-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageViewOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-view response for mailbox-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::AttachmentDownloadOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned attachment-download response for mailbox-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageMoveOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-move response for mailbox-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageAppendOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-append response for mailbox-list request"
                        .to_string(),
                }),
            }
        }
    }
}

/// Client backend that proxies message-list retrieval through the local helper
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageListBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
    message_policy: MessageListPolicy,
}

impl MailboxHelperMessageListBackend {
    /// Creates a message-list client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
        message_policy: MessageListPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
            message_policy,
        }
    }
}

impl MessageListBackend for MailboxHelperMessageListBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
        let mut helper_request = MailboxHelperRequest::MessageList {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut helper_request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: "mailbox helper requires a Unix-domain socket platform".to_string(),
            });
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;
            let mut stream =
                UnixStream::connect(&self.socket_path).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!(
                        "failed to connect to mailbox helper {}: {error}",
                        self.socket_path.display()
                    ),
                })?;

            configure_stream_timeouts(&stream, self.policy);
            stream
                .write_all(&request_bytes)
                .map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("failed to write helper request: {error}"),
                })?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("failed to finish helper request: {error}"),
                })?;

            let response_bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes).map_err(
                    |reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    },
                )?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                self.message_policy,
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&response_bytes).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("helper response was not valid UTF-8: {error}"),
                })?,
            )
            .map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;

            match response {
                MailboxHelperResponse::RetentionStatus { .. }
                | MailboxHelperResponse::MessageDelete { .. }
                | MailboxHelperResponse::FolderCreateOk { .. }
                | MailboxHelperResponse::FolderMetadataOk { .. }
                | MailboxHelperResponse::MailboxStatusOk { .. }
                | MailboxHelperResponse::MessageFlagOk { .. }
                | MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned a flag response for a different operation".into(),
                }),
                MailboxHelperResponse::MessageListOk {
                    mailbox_name,
                    messages,
                } => {
                    if mailbox_name != request.mailbox_name {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response mailbox mismatch: expected {:?}, got {:?}",
                                request.mailbox_name, mailbox_name
                            ),
                        });
                    }
                    Ok(messages)
                }
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                MailboxHelperResponse::MailboxListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned mailbox-list response for message-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageSearchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-search response for message-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageViewOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-view response for message-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::AttachmentDownloadOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned attachment-download response for message-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageMoveOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-move response for message-list request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageAppendOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-append response for message-list request"
                        .to_string(),
                }),
            }
        }
    }
}

/// Client backend that proxies mailbox-scoped message search through the local
/// helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageSearchBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
    search_policy: MessageSearchPolicy,
}

impl MailboxHelperMessageSearchBackend {
    /// Creates a message-search client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
        search_policy: MessageSearchPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
            search_policy,
        }
    }
}

impl MessageSearchBackend for MailboxHelperMessageSearchBackend {
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        let mut helper_request = MailboxHelperRequest::MessageSearch {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
            query: request.query.clone(),
            field: request.field,
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut helper_request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: "mailbox helper requires a Unix-domain socket platform".to_string(),
            });
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;
            let mut stream =
                UnixStream::connect(&self.socket_path).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!(
                        "failed to connect to mailbox helper {}: {error}",
                        self.socket_path.display()
                    ),
                })?;

            configure_stream_timeouts(&stream, self.policy);
            stream
                .write_all(&request_bytes)
                .map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("failed to write helper request: {error}"),
                })?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("failed to finish helper request: {error}"),
                })?;

            let response_bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes).map_err(
                    |reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    },
                )?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                self.search_policy,
                MessageViewPolicy::default(),
                std::str::from_utf8(&response_bytes).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("helper response was not valid UTF-8: {error}"),
                })?,
            )
            .map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;

            match response {
                MailboxHelperResponse::RetentionStatus { .. }
                | MailboxHelperResponse::MessageDelete { .. }
                | MailboxHelperResponse::FolderCreateOk { .. }
                | MailboxHelperResponse::FolderMetadataOk { .. }
                | MailboxHelperResponse::MailboxStatusOk { .. }
                | MailboxHelperResponse::MessageFlagOk { .. }
                | MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned a flag response for a different operation".into(),
                }),
                MailboxHelperResponse::MessageSearchOk {
                    mailbox_name,
                    query,
                    field,
                    results,
                } => {
                    if mailbox_name != request.mailbox_name {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response mailbox mismatch: expected {:?}, got {:?}",
                                request.mailbox_name, mailbox_name
                            ),
                        });
                    }
                    if query != request.query {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response query mismatch: expected {:?}, got {:?}",
                                request.query, query
                            ),
                        });
                    }
                    if field != request.field {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response search field mismatch: expected {:?}, got {:?}",
                                request.field, field
                            ),
                        });
                    }
                    Ok(results)
                }
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                MailboxHelperResponse::MailboxListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned mailbox-list response for message-search request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-list response for message-search request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageViewOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-view response for message-search request"
                        .to_string(),
                }),
                MailboxHelperResponse::AttachmentDownloadOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason:
                        "helper returned attachment-download response for message-search request"
                            .to_string(),
                }),
                MailboxHelperResponse::MessageMoveOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-move response for message-search request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageAppendOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-append response for message-search request"
                        .to_string(),
                }),
            }
        }
    }
    fn search_messages_batch(
        &self,
        canonical_username: &str,
        request: &MessageSearchBatchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        #[cfg(unix)]
        let deadline = helper_request_deadline(self.policy);
        request
            .validate(self.search_policy)
            .map_err(|error| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: error.reason,
            })?;
        let mut helper_request = MailboxHelperRequest::MessageSearchBatch {
            canonical_username: canonical_username.to_string(),
            mailbox_names: request.mailbox_names.clone(),
            query: request.query.clone(),
            field: request.field,
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut helper_request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: "mailbox helper requires a Unix-domain socket platform".to_string(),
            });
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;
            if request_bytes.len() > self.policy.max_request_bytes {
                return Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper batch request exceeded byte limit".into(),
                });
            }
            let response_bytes =
                helper_exchange_before(&self.socket_path, &request_bytes, self.policy, deadline)
                    .map_err(|reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    })?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                self.search_policy,
                MessageViewPolicy::default(),
                std::str::from_utf8(&response_bytes).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("helper response was not valid UTF-8: {error}"),
                })?,
            )
            .map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;

            match response {
                MailboxHelperResponse::MessageSearchBatchOk {
                    mailbox_names,
                    query,
                    field,
                    results,
                } if mailbox_names == request.mailbox_names
                    && query == request.query
                    && field == request.field =>
                {
                    helper_deadline_remaining(deadline).map_err(|reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    })?;
                    Ok(results)
                }
                MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper batch response scope, query or field mismatch".into(),
                }),
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                _ => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned wrong operation for batch search".into(),
                }),
            }
        }
    }
}

/// Client backend that proxies single-message retrieval through the local
/// helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageViewBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
    message_view_policy: MessageViewPolicy,
}

impl MailboxHelperMessageViewBackend {
    /// Creates a message-view client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
        message_view_policy: MessageViewPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
            message_view_policy,
        }
    }
}

impl MessageViewBackend for MailboxHelperMessageViewBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        let mut helper_request = MailboxHelperRequest::MessageView {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
            uid: request.uid,
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut helper_request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: "mailbox helper requires a Unix-domain socket platform".to_string(),
            });
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;
            let mut stream =
                UnixStream::connect(&self.socket_path).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!(
                        "failed to connect to mailbox helper {}: {error}",
                        self.socket_path.display()
                    ),
                })?;

            configure_stream_timeouts(&stream, self.policy);
            stream
                .write_all(&request_bytes)
                .map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("failed to write helper request: {error}"),
                })?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("failed to finish helper request: {error}"),
                })?;

            let response_bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes).map_err(
                    |reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    },
                )?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                self.message_view_policy,
                std::str::from_utf8(&response_bytes).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("helper response was not valid UTF-8: {error}"),
                })?,
            )
            .map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;

            match response {
                MailboxHelperResponse::RetentionStatus { .. }
                | MailboxHelperResponse::MessageDelete { .. }
                | MailboxHelperResponse::FolderCreateOk { .. }
                | MailboxHelperResponse::FolderMetadataOk { .. }
                | MailboxHelperResponse::MailboxStatusOk { .. }
                | MailboxHelperResponse::MessageFlagOk { .. }
                | MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned a flag response for a different operation".into(),
                }),
                MailboxHelperResponse::MessageViewOk { message } => {
                    if message.mailbox_name != request.mailbox_name {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response mailbox mismatch: expected {:?}, got {:?}",
                                request.mailbox_name, message.mailbox_name
                            ),
                        });
                    }
                    if message.uid != request.uid {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response uid mismatch: expected {}, got {}",
                                request.uid, message.uid
                            ),
                        });
                    }
                    Ok(*message)
                }
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                MailboxHelperResponse::MailboxListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned mailbox-list response for message-view request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-list response for message-view request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageSearchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-search response for message-view request"
                        .to_string(),
                }),
                MailboxHelperResponse::AttachmentDownloadOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned attachment-download response for message-view request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageMoveOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-move response for message-view request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageAppendOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-append response for message-view request"
                        .to_string(),
                }),
            }
        }
    }
}

/// Client backend that proxies one attachment download through the local helper
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperAttachmentDownloadBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
}

impl MailboxHelperAttachmentDownloadBackend {
    /// Creates an attachment-download client backend for the supplied helper
    /// socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
        }
    }

    pub fn download_attachment(
        &self,
        canonical_username: &str,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> Result<DownloadedAttachment, AttachmentDownloadError> {
        let mut helper_request = MailboxHelperRequest::AttachmentDownload {
            canonical_username: canonical_username.to_string(),
            mailbox_name: mailbox_name.to_string(),
            uid,
            part_path: part_path.to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut helper_request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(AttachmentDownloadError::new(
                AttachmentDownloadFailureKind::OutputRejected,
                "mailbox helper requires a Unix-domain socket platform",
            ));
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(transport_error)?;
            let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
                transport_error(format!(
                    "failed to connect to mailbox helper {}: {error}",
                    self.socket_path.display()
                ))
            })?;

            configure_stream_timeouts(&stream, self.policy);
            stream.write_all(&request_bytes).map_err(|error| {
                transport_error(format!("failed to write helper request: {error}"))
            })?;
            stream.shutdown(Shutdown::Write).map_err(|error| {
                transport_error(format!("failed to finish helper request: {error}"))
            })?;

            let response_bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes)
                    .map_err(transport_error)?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&response_bytes).map_err(|error| {
                    transport_error(format!("helper response was not valid UTF-8: {error}"))
                })?,
            )
            .map_err(transport_error)?;

            match response {
                MailboxHelperResponse::RetentionStatus { .. }
                | MailboxHelperResponse::MessageDelete { .. }
                | MailboxHelperResponse::FolderCreateOk { .. }
                | MailboxHelperResponse::FolderMetadataOk { .. }
                | MailboxHelperResponse::MailboxStatusOk { .. }
                | MailboxHelperResponse::MessageFlagOk { .. }
                | MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(transport_error(
                    "helper returned a flag response for a different operation",
                )),
                MailboxHelperResponse::AttachmentDownloadOk { attachment } => {
                    if attachment.mailbox_name != mailbox_name {
                        return Err(transport_error(format!(
                            "helper response mailbox mismatch: expected {:?}, got {:?}",
                            mailbox_name, attachment.mailbox_name
                        )));
                    }
                    if attachment.uid != uid {
                        return Err(transport_error(format!(
                            "helper response uid mismatch: expected {}, got {}",
                            uid, attachment.uid
                        )));
                    }
                    if attachment.part_path != part_path {
                        return Err(transport_error(format!(
                            "helper response part path mismatch: expected {:?}, got {:?}",
                            part_path, attachment.part_path
                        )));
                    }
                    Ok(*attachment)
                }
                MailboxHelperResponse::Error { backend, reason } => {
                    Err(map_attachment_helper_error(&backend, reason))
                }
                MailboxHelperResponse::MailboxListOk { .. } => Err(transport_error(
                    "helper returned mailbox-list response for attachment-download request"
                        .to_string(),
                )),
                MailboxHelperResponse::MessageListOk { .. } => Err(transport_error(
                    "helper returned message-list response for attachment-download request"
                        .to_string(),
                )),
                MailboxHelperResponse::MessageSearchOk { .. } => Err(transport_error(
                    "helper returned message-search response for attachment-download request"
                        .to_string(),
                )),
                MailboxHelperResponse::MessageViewOk { .. } => Err(transport_error(
                    "helper returned message-view response for attachment-download request"
                        .to_string(),
                )),
                MailboxHelperResponse::MessageMoveOk { .. } => Err(transport_error(
                    "helper returned message-move response for attachment-download request"
                        .to_string(),
                )),
                MailboxHelperResponse::MessageAppendOk { .. } => Err(transport_error(
                    "helper returned message-append response for attachment-download request"
                        .to_string(),
                )),
            }
        }
    }
}

/// Client backend that proxies one-message move through the local helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageMoveBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
}

impl MailboxHelperMessageMoveBackend {
    /// Creates a message-move client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
        }
    }
}

fn move_unknown() -> MailboxBackendError {
    MailboxBackendError {
        backend: "message-move-unknown",
        reason:
            "move update response could not be confirmed; refresh before choosing another action"
                .into(),
    }
}

impl MessageMoveBackend for MailboxHelperMessageMoveBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        let mut helper_request = MailboxHelperRequest::MessageMove {
            canonical_username: canonical_username.into(),
            source_mailbox_name: request.source_mailbox_name.clone(),
            destination_mailbox_name: request.destination_mailbox_name.clone(),
            uid: request.uid,
            version: request.version.clone(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes =
            encode_authorized_request(&self.grant_key_path, &mut helper_request).map_err(|_| {
                MailboxBackendError {
                    backend: "message-move-unavailable",
                    reason: "move helper authority is unavailable".into(),
                }
            })?;
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(MailboxBackendError {
                backend: "message-move-unavailable",
                reason: "move helper requires Unix-domain sockets".into(),
            })
        }
        #[cfg(unix)]
        {
            let mut stream =
                UnixStream::connect(&self.socket_path).map_err(|_| MailboxBackendError {
                    backend: "message-move-unavailable",
                    reason: "move helper is unavailable".into(),
                })?;
            let unavailable = |_| MailboxBackendError {
                backend: "message-move-unavailable",
                reason: "move helper transport deadline is unavailable".into(),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(
                    self.policy.read_timeout_secs.max(1),
                )))
                .map_err(unavailable)?;
            stream
                .set_write_timeout(Some(Duration::from_secs(
                    self.policy.write_timeout_secs.max(1),
                )))
                .map_err(unavailable)?;
            stream.write_all(&bytes).map_err(|_| move_unknown())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| move_unknown())?;
            // The move response contains only identity, state and outcome.
            let bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes.min(4096))
                    .map_err(|_| move_unknown())?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&bytes).map_err(|_| move_unknown())?,
            )
            .map_err(|_| move_unknown())?;
            match response {
                MailboxHelperResponse::MessageMoveOk {
                    source_mailbox_name,
                    destination_mailbox_name,
                    uid,
                    version,
                } if source_mailbox_name == request.source_mailbox_name
                    && destination_mailbox_name == request.destination_mailbox_name
                    && uid == request.uid
                    && version == request.version =>
                {
                    Ok(())
                }
                MailboxHelperResponse::Error { backend, .. } => match backend.as_str() {
                    "message-move-stale" => Err(MailboxBackendError {
                        backend: "message-move-stale",
                        reason: "message identity is no longer current".into(),
                    }),
                    "message-move-busy" => Err(MailboxBackendError {
                        backend: "message-move-busy",
                        reason: "another move update is active".into(),
                    }),
                    "message-move-parser" => Err(MailboxBackendError {
                        backend: "message-move-parser",
                        reason: "move update was invalid".into(),
                    }),
                    "message-move-unavailable" | "message-json-parser" => {
                        Err(MailboxBackendError {
                            backend: "message-move-unavailable",
                            reason: "move state could not be read".into(),
                        })
                    }
                    _ => Err(move_unknown()),
                },
                _ => Err(move_unknown()),
            }
        }
    }
}

/// Client backend that proxies one-message append through the local helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageAppendBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
    helper_uid: Option<u32>,
}

impl MailboxHelperMessageAppendBackend {
    /// Creates a message-append client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
            helper_uid: None,
        }
    }
}

impl MailboxHelperMessageAppendBackend {
    pub fn with_helper_uid(mut self, uid: Option<u32>) -> Self {
        self.helper_uid = uid;
        self
    }
}

impl MessageAppendBackend for MailboxHelperMessageAppendBackend {
    fn append_message(
        &self,
        canonical_username: &str,
        request: &MessageAppendRequest,
    ) -> Result<(), MailboxBackendError> {
        #[cfg(unix)]
        let deadline = helper_request_deadline(self.policy);
        if let Some(guid) = request.destination_mailbox_guid.as_deref() {
            crate::sent_location::validate_destination(&request.mailbox_name, guid).map_err(
                |_| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "invalid captured copy identity".into(),
                },
            )?;
        }
        let mut helper_request = MailboxHelperRequest::MessageAppend {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
            destination_mailbox_guid: request.destination_mailbox_guid.clone(),
            message: request.message.clone(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let request_bytes = encode_authorized_request(&self.grant_key_path, &mut helper_request);

        #[cfg(not(unix))]
        {
            let _ = request_bytes;
            return Err(MailboxBackendError {
                backend: "mailbox-helper-client",
                reason: "mailbox helper requires a Unix-domain socket platform".to_string(),
            });
        }

        #[cfg(unix)]
        {
            let request_bytes = request_bytes.map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;
            let response_bytes = if request.destination_mailbox_guid.is_some() {
                let uid = self.helper_uid.ok_or_else(|| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "trusted helper UID unavailable".into(),
                })?;
                helper_exchange_before_with_peer(
                    &self.socket_path,
                    &request_bytes,
                    self.policy,
                    deadline,
                    Some(uid),
                )
                .map_err(|_| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "selected copy append unconfirmed".into(),
                })?
            } else {
                let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
                    MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason: format!(
                            "failed to connect to mailbox helper {}: {error}",
                            self.socket_path.display()
                        ),
                    }
                })?;

                configure_stream_timeouts(&stream, self.policy);
                stream
                    .write_all(&request_bytes)
                    .map_err(|error| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason: format!("failed to write helper request: {error}"),
                    })?;
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|error| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason: format!("failed to finish helper request: {error}"),
                    })?;

                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes).map_err(
                    |reason| MailboxBackendError {
                        backend: "mailbox-helper-client",
                        reason,
                    },
                )?
            };
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&response_bytes).map_err(|error| MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("helper response was not valid UTF-8: {error}"),
                })?,
            )
            .map_err(|reason| MailboxBackendError {
                backend: "mailbox-helper-client",
                reason,
            })?;

            if request.destination_mailbox_guid.is_some() && Instant::now() >= deadline {
                return Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "selected copy response expired".into(),
                });
            }
            match response {
                MailboxHelperResponse::RetentionStatus { .. }
                | MailboxHelperResponse::MessageDelete { .. }
                | MailboxHelperResponse::FolderCreateOk { .. }
                | MailboxHelperResponse::FolderMetadataOk { .. }
                | MailboxHelperResponse::MailboxStatusOk { .. }
                | MailboxHelperResponse::MessageFlagOk { .. }
                | MailboxHelperResponse::MessageSearchBatchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned a flag response for a different operation".into(),
                }),
                MailboxHelperResponse::MessageAppendOk {
                    mailbox_name,
                    message_bytes,
                    destination_mailbox_guid,
                } if destination_mailbox_guid == request.destination_mailbox_guid
                    && mailbox_name == request.mailbox_name
                    && message_bytes == request.message.len() =>
                {
                    Ok(())
                }
                MailboxHelperResponse::MessageAppendOk {
                    mailbox_name,
                    message_bytes,
                    ..
                } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!(
                        "helper append response mismatch: mailbox {:?}, bytes {}",
                        mailbox_name, message_bytes
                    ),
                }),
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                _ => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned the wrong response for message-append request"
                        .to_string(),
                }),
            }
        }
    }
}

#[cfg(unix)]
fn helper_request_deadline(policy: MailboxHelperPolicy) -> Instant {
    Instant::now()
        + Duration::from_secs(
            policy
                .read_timeout_secs
                .min(policy.write_timeout_secs)
                .min(DEFAULT_MAILBOX_HELPER_READ_TIMEOUT_SECS),
        )
}

#[cfg(unix)]
fn helper_deadline_remaining(deadline: Instant) -> Result<Duration, String> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| "helper transport deadline expired".into())
}

// Listing and batch search share one transport budget across preparation,
// bounded connect, every partial write/read and final response qualification.
// The legacy single-folder operations retain their existing transport path.
#[cfg(unix)]
fn helper_exchange_before(
    socket: &Path,
    request: &[u8],
    policy: MailboxHelperPolicy,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    helper_exchange_before_with_peer(socket, request, policy, deadline, None)
}
#[cfg(unix)]
fn helper_exchange_before_with_peer(
    socket: &Path,
    request: &[u8],
    policy: MailboxHelperPolicy,
    deadline: Instant,
    peer: Option<u32>,
) -> Result<Vec<u8>, String> {
    if request.len() > policy.max_request_bytes {
        return Err("helper request exceeded byte limit".into());
    }
    helper_deadline_remaining(deadline)?;
    let mut stream = crate::openbsd::connect_unix_before(socket, deadline).map_err(|error| {
        format!(
            "failed to connect to mailbox helper {}: {error}",
            socket.display()
        )
    })?;
    if let Some(uid) = peer {
        if crate::openbsd::unix_stream_peer_uid(&stream).ok() != Some(uid) {
            return Err("helper peer refused".into());
        }
    }
    helper_deadline_remaining(deadline)?;
    let mut unwritten = request;
    while !unwritten.is_empty() {
        stream
            .set_write_timeout(Some(
                helper_deadline_remaining(deadline)
                    .map_err(|reason| format!("failed to write helper request: {reason}"))?,
            ))
            .map_err(|error| format!("failed to configure helper write timeout: {error}"))?;
        match stream.write(unwritten) {
            Ok(0) => return Err("failed to write helper request: zero write".into()),
            Ok(written) => unwritten = &unwritten[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("failed to write helper request: {error}")),
        }
        helper_deadline_remaining(deadline)
            .map_err(|reason| format!("failed to write helper request: {reason}"))?;
    }
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| format!("failed to finish helper request: {error}"))?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        stream
            .set_read_timeout(Some(
                helper_deadline_remaining(deadline)
                    .map_err(|reason| format!("failed to read helper payload: {reason}"))?,
            ))
            .map_err(|error| format!("failed to configure helper read timeout: {error}"))?;
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("failed to read helper payload: {error}")),
        };
        helper_deadline_remaining(deadline)
            .map_err(|reason| format!("failed to read helper payload: {reason}"))?;
        if read == 0 {
            return Ok(response);
        }
        if read > policy.max_response_bytes.saturating_sub(response.len()) {
            return Err(format!(
                "helper payload exceeded maximum size of {} bytes",
                policy.max_response_bytes
            ));
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

fn transport_error(reason: impl Into<String>) -> AttachmentDownloadError {
    AttachmentDownloadError::new(AttachmentDownloadFailureKind::OutputRejected, reason)
}

pub(super) fn encode_authorized_request(
    grant_key_path: &Path,
    request: &mut MailboxHelperRequest,
) -> Result<Vec<u8>, String> {
    let key = load_helper_grant_key(grant_key_path)?;
    issue_request_grant(request, &key, current_unix_time_secs()?)?;
    Ok(encode_request(request).into_bytes())
}

fn map_attachment_helper_error(backend: &str, reason: String) -> AttachmentDownloadError {
    let kind = match backend {
        "attachment-download-invalid-request" => AttachmentDownloadFailureKind::InvalidRequest,
        "attachment-download-not-found" | "message-view-not-found" => {
            AttachmentDownloadFailureKind::NotFound
        }
        "attachment-download-unsupported-encoding" => {
            AttachmentDownloadFailureKind::UnsupportedEncoding
        }
        _ => AttachmentDownloadFailureKind::OutputRejected,
    };

    AttachmentDownloadError::new(kind, format!("{backend}: {reason}"))
}

#[cfg(test)]
#[cfg(unix)]
mod batch_client_tests {
    use super::*;
    use crate::mailbox_helper::mailbox_helper_protocol::encode_response;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const KEY: &[u8] = b"batch-client-fixture-grant-key-32-bytes";
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct FixtureRoot(PathBuf);
    impl FixtureRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "osmap-batch-client-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn key(&self) -> PathBuf {
            let path = self.0.join("fixture.key");
            fs::write(&path, KEY).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }
    impl Drop for FixtureRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn request() -> MessageSearchBatchRequest {
        MessageSearchBatchRequest::new(
            MessageSearchPolicy::default(),
            (0..39).map(|n| format!("Folder/{n:02}")).collect(),
            "literal É $(query)",
            MessageSearchField::Subject,
        )
        .unwrap()
    }

    fn response(request: &MessageSearchBatchRequest) -> MailboxHelperResponse {
        MailboxHelperResponse::MessageSearchBatchOk {
            mailbox_names: request.mailbox_names.clone(),
            query: request.query.clone(),
            field: request.field,
            results: vec![MessageSearchResult {
                mailbox_name: request.mailbox_names[38].clone(),
                uid: 1,
                flags: vec![],
                date_received: "2026-10-03 10:00:00 +0000".into(),
                size_virtual: 42,
                subject: Some("fixture".into()),
                from: Some("fixture@example.com".into()),
                metadata: None,
            }],
        }
    }

    // This is an owned Unix transport fixture. It applies the actual request
    // codec and grant/replay verifier; native dispatcher proof is separate.
    fn transport(
        response: String,
        policy: MailboxHelperPolicy,
        single: bool,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        let root = FixtureRoot::new();
        let socket = root.0.join("helper.sock");
        let key = root.key();
        let listener = UnixListener::bind(&socket).unwrap();
        let expected = request();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
            let bytes =
                read_bounded_from_stream(&mut stream, DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES)
                    .unwrap();
            let parsed = parse_request(std::str::from_utf8(&bytes).unwrap()).unwrap();
            let cache = Mutex::new(BTreeMap::new());
            verify_helper_request_authority(&parsed, KEY, &cache).unwrap();
            if single {
                assert!(matches!(parsed, MailboxHelperRequest::MessageSearch { .. }));
            } else {
                assert!(matches!(parsed, MailboxHelperRequest::MessageSearchBatch {
                    canonical_username, mailbox_names, query, field, ..
                } if canonical_username == "alice@example.com" && mailbox_names == expected.mailbox_names
                    && query == expected.query && field == expected.field));
            }
            // The client may close as soon as it observes a bounded refusal.
            let _ = stream.write_all(response.as_bytes());
        });
        let client = MailboxHelperMessageSearchBackend::new(
            &socket,
            &key,
            policy,
            MessageSearchPolicy::default(),
        );
        let result = if single {
            client.search_messages(
                "alice@example.com",
                &MessageSearchRequest::new_with_field(
                    MessageSearchPolicy::default(),
                    "Folder/00",
                    "literal É $(query)",
                    MessageSearchField::Subject,
                )
                .unwrap(),
            )
        } else {
            client.search_messages_batch("alice@example.com", &request())
        };
        server.join().unwrap();
        result
    }

    #[test]
    fn batch_client_transports_one_authenticated_exact_39_folder_scope() {
        let expected = response(&request());
        let results = transport(
            encode_response(&expected),
            MailboxHelperPolicy::default(),
            false,
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mailbox_name, "Folder/38");
        let policy = MailboxHelperPolicy::default();
        assert_eq!(policy.max_response_bytes, 1024 * 1024);
        assert_eq!(policy.read_timeout_secs, 5);
        assert_eq!(policy.max_concurrent_connections, 4);
    }

    #[test]
    fn batch_client_refuses_mismatched_wrong_operation_and_hostile_replies() {
        let original = response(&request());
        let mut bad_responses = Vec::new();
        for selector in 0..6 {
            let mut bad = original.clone();
            if let MailboxHelperResponse::MessageSearchBatchOk {
                mailbox_names,
                query,
                field,
                results,
            } = &mut bad
            {
                match selector {
                    0 => mailbox_names.reverse(),
                    1 => mailbox_names[0] = "Foreign".into(),
                    2 => *query = "different query".into(),
                    3 => *field = MessageSearchField::From,
                    4 => results[0].mailbox_name = "Foreign".into(),
                    _ => results.push(results[0].clone()),
                }
            }
            bad_responses.push(encode_response(&bad));
        }
        bad_responses.push(encode_response(&MailboxHelperResponse::MessageSearchOk {
            mailbox_name: "Folder/00".into(),
            query: request().query,
            field: request().field,
            results: vec![],
        }));
        bad_responses.push(encode_response(&MailboxHelperResponse::MailboxListOk {
            mailboxes: vec![],
        }));
        bad_responses.push(encode_response(&MailboxHelperResponse::Error {
            backend: "fixture-refusal".into(),
            reason: "refused".into(),
        }));
        let good = encode_response(&original);
        bad_responses.push(good.replace("search_field=subject", "search_field=invalid"));
        bad_responses
            .push(good.replace("message_end=1", "message_mailbox_guid=bad\nmessage_end=1"));
        bad_responses.push(format!("{good}unexpected=1\n"));
        bad_responses.push(format!(
            "{good}{}",
            "x".repeat(DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES)
        ));
        for bad in bad_responses {
            assert!(transport(bad, MailboxHelperPolicy::default(), false).is_err());
        }
        // A new batch reply cannot satisfy a legacy single-folder operation.
        assert!(transport(good, MailboxHelperPolicy::default(), true).is_err());
    }

    #[test]
    fn batch_client_refuses_invalid_scope_before_connecting() {
        let client = MailboxHelperMessageSearchBackend::new(
            "/nonexistent-osmap-batch.sock",
            "/nonexistent-osmap-batch.key",
            MailboxHelperPolicy::default(),
            MessageSearchPolicy::default(),
        );
        let invalid = MessageSearchBatchRequest {
            mailbox_names: vec![],
            query: "fixture".into(),
            field: MessageSearchField::All,
        };
        assert_eq!(
            client
                .search_messages_batch("alice@example.com", &invalid)
                .unwrap_err()
                .reason,
            "invalid batch mailbox count"
        );
    }

    #[test]
    fn batch_client_refuses_request_byte_overflow_before_connecting() {
        let root = FixtureRoot::new();
        let key = root.key();
        let client = MailboxHelperMessageSearchBackend::new(
            root.0.join("unbound.sock"),
            key,
            MailboxHelperPolicy {
                max_request_bytes: 64,
                ..MailboxHelperPolicy::default()
            },
            MessageSearchPolicy::default(),
        );
        assert_eq!(
            client
                .search_messages_batch("alice@example.com", &request())
                .unwrap_err()
                .reason,
            "helper batch request exceeded byte limit"
        );
    }

    #[test]
    fn batch_client_refuses_transport_timeout_without_results() {
        let root = FixtureRoot::new();
        let socket = root.0.join("timeout.sock");
        let key = root.key();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
            let input =
                read_bounded_from_stream(&mut stream, DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES)
                    .unwrap();
            let parsed = parse_request(std::str::from_utf8(&input).unwrap()).unwrap();
            verify_helper_request_authority(&parsed, KEY, &Mutex::new(BTreeMap::new())).unwrap();
            std::thread::sleep(Duration::from_millis(1500));
        });
        let client = MailboxHelperMessageSearchBackend::new(
            &socket,
            key,
            MailboxHelperPolicy {
                read_timeout_secs: 1,
                ..MailboxHelperPolicy::default()
            },
            MessageSearchPolicy::default(),
        );
        let error = client
            .search_messages_batch("alice@example.com", &request())
            .unwrap_err();
        assert!(
            error.reason.contains("failed to read helper payload"),
            "{}",
            error.reason
        );
        server.join().unwrap();
    }

    fn qualify_slow_trickle_deadline(batch: bool) {
        let root = FixtureRoot::new();
        let socket = root.0.join("trickle.sock");
        let key = root.key();
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = if batch {
            response(&request())
        } else {
            MailboxHelperResponse::MailboxListOk {
                mailboxes: request()
                    .mailbox_names
                    .into_iter()
                    .map(|name| MailboxEntry::new(MailboxListingPolicy::default(), name).unwrap())
                    .collect(),
            }
        };
        let reply = encode_response(&reply);
        let server = std::thread::spawn(move || {
            let cache = Mutex::new(BTreeMap::new());
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
                let input =
                    read_bounded_from_stream(&mut stream, DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES)
                        .unwrap();
                let parsed = parse_request(std::str::from_utf8(&input).unwrap()).unwrap();
                verify_helper_request_authority(&parsed, KEY, &cache).unwrap();
                assert!(if batch {
                    matches!(parsed, MailboxHelperRequest::MessageSearchBatch { .. })
                } else {
                    matches!(parsed, MailboxHelperRequest::MailboxList { .. })
                });
                if attempt == 0 {
                    // Each read succeeds before the old one-second per-read
                    // timeout, but the complete valid reply takes 1.5 seconds.
                    for chunk in reply.as_bytes().chunks(reply.len().div_ceil(6)) {
                        std::thread::sleep(Duration::from_millis(250));
                        if stream.write_all(chunk).is_err() {
                            break;
                        }
                    }
                } else {
                    stream.write_all(reply.as_bytes()).unwrap();
                }
            }
        });
        let policy = MailboxHelperPolicy {
            read_timeout_secs: 1,
            write_timeout_secs: 1,
            ..MailboxHelperPolicy::default()
        };
        let batch_client = MailboxHelperMessageSearchBackend::new(
            &socket,
            &key,
            policy,
            MessageSearchPolicy::default(),
        );
        let listing_client = MailboxHelperMailboxListBackend::new(&socket, &key, policy);
        let execute = || {
            if batch {
                batch_client
                    .search_messages_batch("alice@example.com", &request())
                    .map(|rows| rows.len())
            } else {
                listing_client
                    .list_mailboxes("alice@example.com")
                    .map(|rows| rows.len())
            }
        };
        let started = std::time::Instant::now();
        let slow_result = execute();
        let elapsed = started.elapsed();
        let next_result = execute();
        server.join().unwrap();
        assert!(
            slow_result.is_err(),
            "complete trickled reply escaped total deadline at {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(800) && elapsed < Duration::from_millis(1400),
            "total deadline was not enforced: {elapsed:?}"
        );
        assert_eq!(next_result.unwrap(), if batch { 1 } else { 39 });
    }

    #[test]
    fn batch_total_deadline_refuses_slow_trickle_and_accepts_next_request() {
        qualify_slow_trickle_deadline(true);
    }

    #[test]
    fn listing_total_deadline_refuses_slow_trickle_and_accepts_next_request() {
        qualify_slow_trickle_deadline(false);
    }

    #[test]
    fn batch_total_deadline_refuses_partial_write_backpressure_and_recovers() {
        let root = FixtureRoot::new();
        let socket = root.0.join("backpressure.sock");
        let key = root.key();
        let large = MessageSearchBatchRequest::new(
            MessageSearchPolicy::default(),
            (0..1024)
                .map(|n| format!("{n:04}{}", "\\".repeat(251)))
                .collect(),
            "fixture",
            MessageSearchField::All,
        )
        .unwrap();
        let mut signed = MailboxHelperRequest::MessageSearchBatch {
            canonical_username: "alice@example.com".into(),
            mailbox_names: large.mailbox_names.clone(),
            query: large.query.clone(),
            field: large.field,
            grant: MailboxHelperGrant::unsigned(),
        };
        let complete = encode_authorized_request(&key, &mut signed).unwrap();
        let parsed = parse_request(std::str::from_utf8(&complete).unwrap()).unwrap();
        verify_helper_request_authority(&parsed, KEY, &Mutex::new(BTreeMap::new())).unwrap();
        let complete_len = complete.len();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stalled, _) = listener.accept().unwrap();
            configure_stream_timeouts(&stalled, MailboxHelperPolicy::default());
            // A valid signed request is larger than the socket's send buffer.
            // The peer accepts, but supplies no receive progress for 1.5s.
            std::thread::sleep(Duration::from_millis(1500));
            let partial =
                read_bounded_from_stream(&mut stalled, DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES)
                    .unwrap();
            drop(stalled);
            let (mut healthy, _) = listener.accept().unwrap();
            configure_stream_timeouts(&healthy, MailboxHelperPolicy::default());
            let input =
                read_bounded_from_stream(&mut healthy, DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES)
                    .unwrap();
            let parsed = parse_request(std::str::from_utf8(&input).unwrap()).unwrap();
            verify_helper_request_authority(&parsed, KEY, &Mutex::new(BTreeMap::new())).unwrap();
            healthy
                .write_all(encode_response(&response(&request())).as_bytes())
                .unwrap();
            partial.len()
        });
        let client = MailboxHelperMessageSearchBackend::new(
            &socket,
            key,
            MailboxHelperPolicy {
                read_timeout_secs: 1,
                write_timeout_secs: 1,
                ..MailboxHelperPolicy::default()
            },
            MessageSearchPolicy::default(),
        );
        let started = Instant::now();
        let blocked = client.search_messages_batch("alice@example.com", &large);
        let elapsed = started.elapsed();
        let recovered = client.search_messages_batch("alice@example.com", &request());
        let partial_len = server.join().unwrap();
        let error = blocked.unwrap_err();
        assert!(
            error.reason.contains("failed to write helper request"),
            "{}",
            error.reason
        );
        assert!(
            partial_len > 0 && partial_len < complete_len,
            "fixture did not exercise a partial request write: {partial_len}/{complete_len}"
        );
        assert!(
            elapsed >= Duration::from_millis(800) && elapsed < Duration::from_millis(1400),
            "partial write escaped total deadline: {elapsed:?}"
        );
        assert_eq!(recovered.unwrap().len(), 1);
    }

    #[test]
    fn batch_transport_rejects_replayed_signed_request() {
        let root = FixtureRoot::new();
        let socket = root.0.join("replay.sock");
        let key = root.key();
        let mut request = MailboxHelperRequest::MessageSearchBatch {
            canonical_username: "alice@example.com".into(),
            mailbox_names: request().mailbox_names,
            query: request().query,
            field: request().field,
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes = encode_authorized_request(&key, &mut request).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let cache = Mutex::new(BTreeMap::new());
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
                let input =
                    read_bounded_from_stream(&mut stream, DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES)
                        .unwrap();
                let parsed = parse_request(std::str::from_utf8(&input).unwrap()).unwrap();
                let result = verify_helper_request_authority(&parsed, KEY, &cache);
                if attempt == 0 {
                    result.unwrap();
                    stream.write_all(b"accepted").unwrap();
                } else {
                    assert!(result.unwrap_err().contains("replay"));
                    stream.write_all(b"rejected").unwrap();
                }
            }
        });
        for expected in [b"accepted".as_slice(), b"rejected".as_slice()] {
            let mut stream = UnixStream::connect(&socket).unwrap();
            configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
            stream.write_all(&bytes).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            assert_eq!(
                read_bounded_from_stream(&mut stream, 128).unwrap(),
                expected
            );
        }
        server.join().unwrap();
    }
}

#[cfg(test)]
#[cfg(unix)]
#[path = "mailbox_helper_append_location_client_tests.rs"]
mod append_location_client_tests;
