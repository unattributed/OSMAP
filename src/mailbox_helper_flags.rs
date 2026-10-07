//! Narrow flag-update client. A configured helper never falls back to direct IO.
use super::mailbox_helper_client::encode_authorized_request;
use super::*;
use crate::mailbox::{MessageFlagBackend, MessageFlagRequest, MessageFlagResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageFlagBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
    helper_uid: Option<u32>,
}

impl MailboxHelperMessageFlagBackend {
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

    pub fn with_helper_uid(mut self, uid: Option<u32>) -> Self {
        self.helper_uid = uid;
        self
    }
}

fn unknown() -> MailboxBackendError {
    MailboxBackendError {
        backend: "message-flag-unknown",
        reason:
            "flag update response could not be confirmed; refresh before choosing another action"
                .into(),
    }
}

impl MessageFlagBackend for MailboxHelperMessageFlagBackend {
    fn set_message_flag(
        &self,
        canonical_username: &str,
        request: &MessageFlagRequest,
    ) -> Result<MessageFlagResult, MailboxBackendError> {
        let mut helper_request = MailboxHelperRequest::MessageFlag {
            canonical_username: canonical_username.into(),
            request: request.clone(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes =
            encode_authorized_request(&self.grant_key_path, &mut helper_request).map_err(|_| {
                MailboxBackendError {
                    backend: "message-flag-unavailable",
                    reason: "flag helper authority is unavailable".into(),
                }
            })?;
        #[cfg(not(unix))]
        {
            let _ = bytes;
            Err(MailboxBackendError {
                backend: "message-flag-unavailable",
                reason: "flag helper requires Unix-domain sockets".into(),
            })
        }
        #[cfg(unix)]
        {
            let mut stream =
                UnixStream::connect(&self.socket_path).map_err(|_| MailboxBackendError {
                    backend: "message-flag-unavailable",
                    reason: "flag helper is unavailable".into(),
                })?;
            if let Some(uid) = self.helper_uid {
                if crate::openbsd::unix_stream_peer_uid(&stream).ok() != Some(uid) {
                    return Err(MailboxBackendError {
                        backend: "message-flag-unavailable",
                        reason: "flag helper peer refused".into(),
                    });
                }
            }
            let unavailable = |_| MailboxBackendError {
                backend: "message-flag-unavailable",
                reason: "flag helper transport deadline is unavailable".into(),
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
            stream.write_all(&bytes).map_err(|_| unknown())?;
            stream.shutdown(Shutdown::Write).map_err(|_| unknown())?;
            // The flag response contains only identity, state and outcome.
            let bytes =
                read_bounded_from_stream(&mut stream, self.policy.max_response_bytes.min(4096))
                    .map_err(|_| unknown())?;
            let response = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&bytes).map_err(|_| unknown())?,
            )
            .map_err(|_| unknown())?;
            match response {
                MailboxHelperResponse::MessageFlagOk {
                    request: confirmed,
                    result,
                } if &confirmed == request => Ok(result),
                MailboxHelperResponse::Error { backend, .. } => match backend.as_str() {
                    "message-flag-stale" => Err(MailboxBackendError {
                        backend: "message-flag-stale",
                        reason: "message identity is no longer current".into(),
                    }),
                    "message-flag-busy" => Err(MailboxBackendError {
                        backend: "message-flag-busy",
                        reason: "another flag update is active".into(),
                    }),
                    "message-flag-invalid" => Err(MailboxBackendError {
                        backend: "message-flag-invalid",
                        reason: "flag update was invalid".into(),
                    }),
                    "message-flag-unavailable" | "message-json-parser" => {
                        Err(MailboxBackendError {
                            backend: "message-flag-unavailable",
                            reason: "flag state could not be read".into(),
                        })
                    }
                    _ => Err(unknown()),
                },
                _ => Err(unknown()),
            }
        }
    }
}
