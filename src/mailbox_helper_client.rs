use super::*;
use crate::attachment::{
    AttachmentDownloadError, AttachmentDownloadFailureKind, DownloadedAttachment,
};

/// Client backend that proxies mailbox listing through the local helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMailboxListBackend {
    socket_path: PathBuf,
    policy: MailboxHelperPolicy,
}

impl MailboxHelperMailboxListBackend {
    /// Creates a mailbox-list client backend for the supplied helper socket.
    pub fn new(socket_path: impl Into<PathBuf>, policy: MailboxHelperPolicy) -> Self {
        Self {
            socket_path: socket_path.into(),
            policy,
        }
    }
}

impl MailboxBackend for MailboxHelperMailboxListBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        let request = MailboxHelperRequest::MailboxList {
            canonical_username: canonical_username.to_string(),
        };
        let request_bytes = encode_request(&request).into_bytes();

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
                MailboxHelperResponse::MailboxListOk { mailboxes } => Ok(mailboxes),
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
            }
        }
    }
}

/// Client backend that proxies message-list retrieval through the local helper
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageListBackend {
    socket_path: PathBuf,
    policy: MailboxHelperPolicy,
    message_policy: MessageListPolicy,
}

impl MailboxHelperMessageListBackend {
    /// Creates a message-list client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
        message_policy: MessageListPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
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
        let helper_request = MailboxHelperRequest::MessageList {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
        };
        let request_bytes = encode_request(&helper_request).into_bytes();

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
            }
        }
    }
}

/// Client backend that proxies mailbox-scoped message search through the local
/// helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageSearchBackend {
    socket_path: PathBuf,
    policy: MailboxHelperPolicy,
    search_policy: MessageSearchPolicy,
}

impl MailboxHelperMessageSearchBackend {
    /// Creates a message-search client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
        search_policy: MessageSearchPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
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
        let helper_request = MailboxHelperRequest::MessageSearch {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
            query: request.query.clone(),
        };
        let request_bytes = encode_request(&helper_request).into_bytes();

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
                MailboxHelperResponse::MessageSearchOk {
                    mailbox_name,
                    query,
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
            }
        }
    }
}

/// Client backend that proxies single-message retrieval through the local
/// helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageViewBackend {
    socket_path: PathBuf,
    policy: MailboxHelperPolicy,
    message_view_policy: MessageViewPolicy,
}

impl MailboxHelperMessageViewBackend {
    /// Creates a message-view client backend for the supplied helper socket.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
        message_view_policy: MessageViewPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
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
        let helper_request = MailboxHelperRequest::MessageView {
            canonical_username: canonical_username.to_string(),
            mailbox_name: request.mailbox_name.clone(),
            uid: request.uid,
        };
        let request_bytes = encode_request(&helper_request).into_bytes();

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
            }
        }
    }
}

/// Client backend that proxies one attachment download through the local helper
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperAttachmentDownloadBackend {
    socket_path: PathBuf,
    policy: MailboxHelperPolicy,
}

impl MailboxHelperAttachmentDownloadBackend {
    /// Creates an attachment-download client backend for the supplied helper
    /// socket.
    pub fn new(socket_path: impl Into<PathBuf>, policy: MailboxHelperPolicy) -> Self {
        Self {
            socket_path: socket_path.into(),
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
        let helper_request = MailboxHelperRequest::AttachmentDownload {
            canonical_username: canonical_username.to_string(),
            mailbox_name: mailbox_name.to_string(),
            uid,
            part_path: part_path.to_string(),
        };
        let request_bytes = encode_request(&helper_request).into_bytes();

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
            }
        }
    }
}

/// Client backend that proxies one-message move through the local helper socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageMoveBackend {
    socket_path: PathBuf,
    policy: MailboxHelperPolicy,
}

impl MailboxHelperMessageMoveBackend {
    /// Creates a message-move client backend for the supplied helper socket.
    pub fn new(socket_path: impl Into<PathBuf>, policy: MailboxHelperPolicy) -> Self {
        Self {
            socket_path: socket_path.into(),
            policy,
        }
    }
}

impl MessageMoveBackend for MailboxHelperMessageMoveBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        let helper_request = MailboxHelperRequest::MessageMove {
            canonical_username: canonical_username.to_string(),
            source_mailbox_name: request.source_mailbox_name.clone(),
            destination_mailbox_name: request.destination_mailbox_name.clone(),
            uid: request.uid,
        };
        let request_bytes = encode_request(&helper_request).into_bytes();

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
                MailboxHelperResponse::MessageMoveOk {
                    source_mailbox_name,
                    destination_mailbox_name,
                    uid,
                } => {
                    if source_mailbox_name != request.source_mailbox_name {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response source mailbox mismatch: expected {:?}, got {:?}",
                                request.source_mailbox_name, source_mailbox_name
                            ),
                        });
                    }
                    if destination_mailbox_name != request.destination_mailbox_name {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response destination mailbox mismatch: expected {:?}, got {:?}",
                                request.destination_mailbox_name, destination_mailbox_name
                            ),
                        });
                    }
                    if uid != request.uid {
                        return Err(MailboxBackendError {
                            backend: "mailbox-helper-client",
                            reason: format!(
                                "helper response uid mismatch: expected {}, got {}",
                                request.uid, uid
                            ),
                        });
                    }
                    Ok(())
                }
                MailboxHelperResponse::Error { backend, reason } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: format!("{backend}: {reason}"),
                }),
                MailboxHelperResponse::MailboxListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned mailbox-list response for message-move request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageListOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-list response for message-move request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageSearchOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-search response for message-move request"
                        .to_string(),
                }),
                MailboxHelperResponse::MessageViewOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-view response for message-move request"
                        .to_string(),
                }),
                MailboxHelperResponse::AttachmentDownloadOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned attachment-download response for message-move request"
                        .to_string(),
                }),
            }
        }
    }
}

fn transport_error(reason: impl Into<String>) -> AttachmentDownloadError {
    AttachmentDownloadError::new(AttachmentDownloadFailureKind::OutputRejected, reason)
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
