//! Local mailbox-helper boundary for least-privilege mailbox reads.
//!
//! The first helper slice stays intentionally narrow:
//! - one local Unix-domain socket listener
//! - one small set of read-only mailbox operations
//! - one small line-oriented protocol that is easy to review
//! - no new RPC framework or mailbox mutation behavior

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::auth::SystemCommandExecutor;
use crate::config::{AppConfig, AppRunMode, LogLevel};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageViewBackend,
    MailboxBackend, MailboxBackendError, MailboxEntry, MailboxListingPolicy, MessageListBackend,
    MessageListPolicy, MessageListRequest, MessageSummary, MessageView, MessageViewBackend,
    MessageViewPolicy, MessageViewRequest,
};
use crate::openbsd::apply_runtime_confinement;

/// Conservative upper bound for one helper request payload.
pub const DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES: usize = 4096;

/// Conservative upper bound for one helper response payload.
pub const DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Conservative per-connection read timeout for the helper socket.
pub const DEFAULT_MAILBOX_HELPER_READ_TIMEOUT_SECS: u64 = 5;

/// Conservative per-connection write timeout for the helper socket.
pub const DEFAULT_MAILBOX_HELPER_WRITE_TIMEOUT_SECS: u64 = 5;

/// Policy controlling the first mailbox-helper boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxHelperPolicy {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
}

impl Default for MailboxHelperPolicy {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES,
            read_timeout_secs: DEFAULT_MAILBOX_HELPER_READ_TIMEOUT_SECS,
            write_timeout_secs: DEFAULT_MAILBOX_HELPER_WRITE_TIMEOUT_SECS,
        }
    }
}

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
                MailboxHelperResponse::MessageViewOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-view response for mailbox-list request"
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
                MailboxHelperResponse::MessageViewOk { .. } => Err(MailboxBackendError {
                    backend: "mailbox-helper-client",
                    reason: "helper returned message-view response for message-list request"
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
                    Ok(message)
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
            }
        }
    }
}

/// Runs the first local mailbox-helper service.
pub fn run_mailbox_helper_server(config: &AppConfig, logger: &Logger) -> Result<(), String> {
    if config.run_mode != AppRunMode::MailboxHelper {
        return Ok(());
    }

    let socket_path = config.mailbox_helper_socket_path.as_ref().ok_or_else(|| {
        "mailbox helper run mode requires OSMAP_MAILBOX_HELPER_SOCKET_PATH".to_string()
    })?;

    #[cfg(not(unix))]
    {
        let _ = socket_path;
        let _ = logger;
        return Err("mailbox helper requires a Unix-domain socket platform".to_string());
    }

    #[cfg(unix)]
    {
        apply_runtime_confinement(config, logger)?;
        remove_stale_socket_if_needed(socket_path)?;

        let listener = UnixListener::bind(socket_path).map_err(|error| {
            format!(
                "failed to bind helper socket {}: {error}",
                socket_path.display()
            )
        })?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660)).map_err(|error| {
            format!(
                "failed to set helper socket permissions on {}: {error}",
                socket_path.display()
            )
        })?;

        let mailbox_backend = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone());
        let message_list_backend = DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone());
        let message_view_backend = DoveadmMessageViewBackend::new(
            MessageViewPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone());
        let policy = MailboxHelperPolicy::default();

        logger.emit(
            &LogEvent::new(
                LogLevel::Info,
                EventCategory::Mailbox,
                "mailbox_helper_started",
                "mailbox helper started",
            )
            .with_field("socket_path", socket_path.display().to_string())
            .with_field("run_mode", config.run_mode.as_str()),
        );

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => handle_helper_client(
                    &mailbox_backend,
                    &message_list_backend,
                    &message_view_backend,
                    logger,
                    &mut stream,
                    policy,
                ),
                Err(error) => logger.emit(
                    &LogEvent::new(
                        LogLevel::Warn,
                        EventCategory::Mailbox,
                        "mailbox_helper_accept_failed",
                        "mailbox helper accept failed",
                    )
                    .with_field("reason", error.to_string()),
                ),
            }
        }

        Ok(())
    }
}

/// Supported helper requests for the first mailbox-read slice.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MailboxHelperRequest {
    MailboxList {
        canonical_username: String,
    },
    MessageList {
        canonical_username: String,
        mailbox_name: String,
    },
    MessageView {
        canonical_username: String,
        mailbox_name: String,
        uid: u64,
    },
}

/// Supported helper responses for the first mailbox-read slice.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MailboxHelperResponse {
    MailboxListOk {
        mailboxes: Vec<MailboxEntry>,
    },
    MessageListOk {
        mailbox_name: String,
        messages: Vec<MessageSummary>,
    },
    MessageViewOk {
        message: MessageView,
    },
    Error {
        backend: String,
        reason: String,
    },
}

#[cfg(unix)]
fn handle_helper_client<MB, MLB, MVB>(
    mailbox_backend: &MB,
    message_list_backend: &MLB,
    message_view_backend: &MVB,
    logger: &Logger,
    stream: &mut UnixStream,
    policy: MailboxHelperPolicy,
) where
    MB: MailboxBackend,
    MLB: MessageListBackend,
    MVB: MessageViewBackend,
{
    configure_stream_timeouts(stream, policy);

    let request = match read_bounded_from_stream(stream, policy.max_request_bytes)
        .map_err(|reason| MailboxHelperResponse::Error {
            backend: "mailbox-helper-request".to_string(),
            reason,
        })
        .and_then(|bytes| {
            std::str::from_utf8(&bytes)
                .map_err(|error| MailboxHelperResponse::Error {
                    backend: "mailbox-helper-request".to_string(),
                    reason: format!("helper request was not valid UTF-8: {error}"),
                })
                .and_then(|text| {
                    parse_request(text).map_err(|reason| MailboxHelperResponse::Error {
                        backend: "mailbox-helper-request".to_string(),
                        reason,
                    })
                })
        }) {
        Ok(request) => request,
        Err(response) => {
            let _ = write_response(stream, &response);
            log_helper_response(logger, &response, None);
            return;
        }
    };

    let response = match &request {
        MailboxHelperRequest::MailboxList { canonical_username } => {
            match mailbox_backend.list_mailboxes(canonical_username) {
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
                    message_list_backend
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
                    message_view_backend
                        .fetch_message(canonical_username, &request)
                        .map_err(|error| MailboxHelperResponse::Error {
                            backend: error.backend.to_string(),
                            reason: error.reason,
                        })
                }) {
                Ok(message) => MailboxHelperResponse::MessageViewOk { message },
                Err(error_response) => error_response,
            }
        }
    };

    let _ = write_response(stream, &response);
    log_helper_response(logger, &response, Some(&request));
}

#[cfg(unix)]
fn configure_stream_timeouts<T>(stream: &T, policy: MailboxHelperPolicy)
where
    T: UnixStreamTimeouts,
{
    let _ = stream.set_read_timeout(Some(Duration::from_secs(policy.read_timeout_secs)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(policy.write_timeout_secs)));
}

#[cfg(unix)]
trait UnixStreamTimeouts {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

#[cfg(unix)]
impl UnixStreamTimeouts for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

fn encode_request(request: &MailboxHelperRequest) -> String {
    match request {
        MailboxHelperRequest::MailboxList { canonical_username } => format!(
            "operation=mailbox_list\ncanonical_username={canonical_username}\n"
        ),
        MailboxHelperRequest::MessageList {
            canonical_username,
            mailbox_name,
        } => format!(
            "operation=message_list\ncanonical_username={canonical_username}\nmailbox_name={mailbox_name}\n"
        ),
        MailboxHelperRequest::MessageView {
            canonical_username,
            mailbox_name,
            uid,
        } => format!(
            "operation=message_view\ncanonical_username={canonical_username}\nmailbox_name={mailbox_name}\nuid={uid}\n"
        ),
    }
}

fn parse_request(input: &str) -> Result<MailboxHelperRequest, String> {
    let fields = parse_kv_lines(input)?;
    let operation = require_field(&fields, "operation")?;
    let canonical_username = require_field(&fields, "canonical_username")?.to_string();
    validate_canonical_username(&canonical_username)?;

    match operation {
        "mailbox_list" => Ok(MailboxHelperRequest::MailboxList { canonical_username }),
        "message_list" => {
            let mailbox_name = require_field(&fields, "mailbox_name")?.to_string();
            let _ = MessageListRequest::new(MessageListPolicy::default(), mailbox_name.clone())
                .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageList {
                canonical_username,
                mailbox_name,
            })
        }
        "message_view" => {
            let mailbox_name = require_field(&fields, "mailbox_name")?.to_string();
            let uid = require_field(&fields, "uid")?
                .parse::<u64>()
                .map_err(|error| format!("invalid helper uid: {error}"))?;
            let request =
                MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name.clone(), uid)
                    .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageView {
                canonical_username,
                mailbox_name: request.mailbox_name,
                uid: request.uid,
            })
        }
        _ => Err(format!("unsupported helper operation: {operation}")),
    }
}

fn encode_response(response: &MailboxHelperResponse) -> String {
    match response {
        MailboxHelperResponse::MailboxListOk { mailboxes } => {
            let mut output = format!("status=ok\noperation=mailbox_list\nmailbox_count={}\n", mailboxes.len());
            for mailbox in mailboxes {
                output.push_str("mailbox=");
                output.push_str(&mailbox.name);
                output.push('\n');
            }
            output
        }
        MailboxHelperResponse::MessageListOk {
            mailbox_name,
            messages,
        } => {
            let mut output = format!(
                "status=ok\noperation=message_list\nmailbox_name={mailbox_name}\nmessage_count={}\n",
                messages.len()
            );
            for message in messages {
                output.push_str("message_uid=");
                output.push_str(&message.uid.to_string());
                output.push('\n');
                output.push_str("message_flags=");
                output.push_str(&message.flags.join(","));
                output.push('\n');
                output.push_str("message_date_received=");
                output.push_str(&message.date_received);
                output.push('\n');
                output.push_str("message_size_virtual=");
                output.push_str(&message.size_virtual.to_string());
                output.push('\n');
                output.push_str("message_mailbox=");
                output.push_str(&message.mailbox_name);
                output.push('\n');
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageViewOk { message } => format!(
            "status=ok\noperation=message_view\nmessage_uid={}\nmessage_flags={}\nmessage_date_received={}\nmessage_size_virtual={}\nmessage_mailbox={}\nmessage_header_block_b64={}\nmessage_body_text_b64={}\n",
            message.uid,
            message.flags.join(","),
            message.date_received,
            message.size_virtual,
            message.mailbox_name,
            encode_base64(message.header_block.as_bytes()),
            encode_base64(message.body_text.as_bytes()),
        ),
        MailboxHelperResponse::Error { backend, reason } => {
            format!("status=error\nbackend={backend}\nreason={reason}\n")
        }
    }
}

fn parse_response(
    mailbox_policy: MailboxListingPolicy,
    message_policy: MessageListPolicy,
    message_view_policy: MessageViewPolicy,
    input: &str,
) -> Result<MailboxHelperResponse, String> {
    let mut status = None::<String>;
    let mut operation = None::<String>;
    let mut backend = None::<String>;
    let mut reason = None::<String>;
    let mut mailboxes = Vec::<MailboxEntry>::new();
    let mut mailbox_name = None::<String>;
    let mut messages = Vec::<MessageSummary>::new();
    let mut current_message_fields = BTreeMap::<String, String>::new();

    for raw_line in input.lines() {
        if raw_line.is_empty() {
            continue;
        }
        let (key, value) = raw_line
            .split_once('=')
            .ok_or_else(|| format!("malformed helper response line: {raw_line:?}"))?;
        match key {
            "status" => status = Some(value.to_string()),
            "operation" => operation = Some(value.to_string()),
            "backend" => backend = Some(value.to_string()),
            "reason" => reason = Some(value.to_string()),
            "mailbox_name" => mailbox_name = Some(value.to_string()),
            "mailbox" => {
                mailboxes.push(
                    MailboxEntry::new(mailbox_policy, value.to_string()).map_err(|error| {
                        format!("invalid helper mailbox entry: {}", error.reason)
                    })?,
                );
            }
            "mailbox_count" => {}
            "message_count" => {}
            "message_uid"
            | "message_flags"
            | "message_date_received"
            | "message_size_virtual"
            | "message_mailbox"
            | "message_header_block_b64"
            | "message_body_text_b64" => {
                if current_message_fields
                    .insert(key.to_string(), value.to_string())
                    .is_some()
                {
                    return Err(format!("duplicate message field in helper response: {key}"));
                }
            }
            "message_end" => {
                if value != "1" {
                    return Err(format!("unexpected helper message_end marker: {value}"));
                }
                messages.push(parse_message_summary_fields(
                    message_policy,
                    &current_message_fields,
                )?);
                current_message_fields.clear();
            }
            _ => return Err(format!("unexpected helper response field: {key}")),
        }
    }

    if matches!(operation.as_deref(), Some("message_list")) && !current_message_fields.is_empty() {
        return Err("helper response ended before message_end marker".to_string());
    }

    match status.as_deref() {
        Some("ok") => match operation.as_deref() {
            Some("mailbox_list") => Ok(MailboxHelperResponse::MailboxListOk { mailboxes }),
            Some("message_list") => Ok(MailboxHelperResponse::MessageListOk {
                mailbox_name: mailbox_name.unwrap_or_else(|| "unknown".to_string()),
                messages,
            }),
            Some("message_view") => Ok(MailboxHelperResponse::MessageViewOk {
                message: parse_message_view_fields(message_view_policy, &current_message_fields)?,
            }),
            Some(other) => Err(format!("unsupported helper response operation: {other}")),
            None => Err("helper response did not include an operation".to_string()),
        },
        Some("error") => Ok(MailboxHelperResponse::Error {
            backend: backend.unwrap_or_else(|| "mailbox-helper".to_string()),
            reason: reason.unwrap_or_else(|| "helper returned an unspecified error".to_string()),
        }),
        Some(other) => Err(format!("unsupported helper response status: {other}")),
        None => Err("helper response did not include a status".to_string()),
    }
}

fn parse_kv_lines(input: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();

    for raw_line in input.lines() {
        if raw_line.is_empty() {
            continue;
        }
        let (key, value) = raw_line
            .split_once('=')
            .ok_or_else(|| format!("malformed helper line: {raw_line:?}"))?;
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate helper field: {key}"));
        }
    }

    Ok(fields)
}

fn require_field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing helper field: {key}"))
}

fn validate_canonical_username(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("canonical_username must not be empty".to_string());
    }
    if value.len() > crate::auth::DEFAULT_USERNAME_MAX_LEN {
        return Err(format!(
            "canonical_username exceeded maximum length of {} bytes",
            crate::auth::DEFAULT_USERNAME_MAX_LEN
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("canonical_username contains control characters".to_string());
    }

    Ok(())
}

fn parse_message_summary_fields(
    policy: MessageListPolicy,
    fields: &BTreeMap<String, String>,
) -> Result<MessageSummary, String> {
    let mailbox_name = require_field(fields, "message_mailbox")?.to_string();
    let _ = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: 1,
        },
        mailbox_name.clone(),
    )
    .map_err(|error| error.reason)?;

    let uid = require_field(fields, "message_uid")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message uid: {error}"))?;
    if uid == 0 {
        return Err("helper message uid must be greater than zero".to_string());
    }

    let date_received = require_field(fields, "message_date_received")?.to_string();
    if date_received.is_empty() {
        return Err("helper message date_received must not be empty".to_string());
    }
    if date_received.len() > policy.message_date_max_len {
        return Err(format!(
            "helper message date_received exceeded maximum length of {} bytes",
            policy.message_date_max_len
        ));
    }
    if date_received.chars().any(char::is_control) {
        return Err("helper message date_received contains control characters".to_string());
    }

    let size_virtual = require_field(fields, "message_size_virtual")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message size_virtual: {error}"))?;

    let flags_string = require_field(fields, "message_flags")?.to_string();
    if flags_string.len() > policy.message_flag_string_max_len {
        return Err(format!(
            "helper message flags exceeded maximum length of {} bytes",
            policy.message_flag_string_max_len
        ));
    }
    if flags_string.chars().any(char::is_control) {
        return Err("helper message flags contain control characters".to_string());
    }
    let flags = if flags_string.is_empty() {
        Vec::new()
    } else {
        flags_string
            .split(',')
            .map(|value| value.to_string())
            .collect()
    };

    Ok(MessageSummary {
        mailbox_name,
        uid,
        flags,
        date_received,
        size_virtual,
    })
}

fn parse_message_view_fields(
    policy: MessageViewPolicy,
    fields: &BTreeMap<String, String>,
) -> Result<MessageView, String> {
    let mailbox_name = require_field(fields, "message_mailbox")?.to_string();
    let _ = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: 1,
        },
        mailbox_name.clone(),
    )
    .map_err(|error| error.reason)?;

    let uid = require_field(fields, "message_uid")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message uid: {error}"))?;
    if uid == 0 {
        return Err("helper message uid must be greater than zero".to_string());
    }

    let date_received = require_field(fields, "message_date_received")?.to_string();
    validate_helper_string(
        "message date_received",
        &date_received,
        policy.message_date_max_len,
        false,
        false,
    )?;

    let size_virtual = require_field(fields, "message_size_virtual")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message size_virtual: {error}"))?;

    let flags_text = require_field(fields, "message_flags")?.to_string();
    validate_helper_string(
        "message flags",
        &flags_text,
        policy.message_flag_string_max_len,
        true,
        false,
    )?;
    let flags = if flags_text.is_empty() {
        Vec::new()
    } else {
        flags_text
            .split(',')
            .map(|value| value.to_string())
            .collect()
    };

    let header_block = decode_base64_text(
        require_field(fields, "message_header_block_b64")?,
        policy.message_header_max_len,
        "message header_block",
    )?;
    validate_helper_string(
        "message header_block",
        &header_block,
        policy.message_header_max_len,
        false,
        true,
    )?;

    let body_text = decode_base64_text(
        require_field(fields, "message_body_text_b64")?,
        policy.message_body_max_len,
        "message body_text",
    )?;
    validate_helper_string(
        "message body_text",
        &body_text,
        policy.message_body_max_len,
        true,
        true,
    )?;

    Ok(MessageView {
        mailbox_name,
        uid,
        flags,
        date_received,
        size_virtual,
        header_block,
        body_text,
    })
}

fn validate_helper_string(
    field: &str,
    value: &str,
    max_len: usize,
    allow_empty: bool,
    allow_text_whitespace_controls: bool,
) -> Result<(), String> {
    if value.is_empty() && !allow_empty {
        return Err(format!("{field} must not be empty"));
    }

    if value.len() > max_len {
        return Err(format!(
            "{field} exceeded maximum length of {max_len} bytes"
        ));
    }

    if value.chars().any(|ch| {
        ch.is_control() && !(allow_text_whitespace_controls && matches!(ch, '\n' | '\r' | '\t'))
    }) {
        return Err(format!("{field} contains control characters"));
    }

    Ok(())
}

fn encode_base64(bytes: &[u8]) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if bytes.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte0 = chunk[0];
        let byte1 = chunk.get(1).copied().unwrap_or(0);
        let byte2 = chunk.get(2).copied().unwrap_or(0);
        let combined = ((byte0 as u32) << 16) | ((byte1 as u32) << 8) | (byte2 as u32);

        output.push(BASE64[((combined >> 18) & 0x3f) as usize] as char);
        output.push(BASE64[((combined >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(BASE64[((combined >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(BASE64[(combined & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn decode_base64_text(input: &str, max_len: usize, field: &str) -> Result<String, String> {
    let bytes = decode_base64_bytes(input, max_len, field)?;
    String::from_utf8(bytes).map_err(|error| format!("{field} was not valid UTF-8: {error}"))
}

fn decode_base64_bytes(input: &str, max_len: usize, field: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let sanitized: Vec<char> = input
        .chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect();
    if sanitized.len() % 4 != 0 {
        return Err(format!("{field} base64 length was not a multiple of four"));
    }

    let mut output = Vec::with_capacity((sanitized.len() / 4) * 3);
    for chunk in sanitized.chunks(4) {
        let mut values = [0_u8; 4];
        let mut padding = 0usize;

        for (index, ch) in chunk.iter().enumerate() {
            values[index] = match *ch {
                'A'..='Z' => (*ch as u8) - b'A',
                'a'..='z' => (*ch as u8) - b'a' + 26,
                '0'..='9' => (*ch as u8) - b'0' + 52,
                '+' => 62,
                '/' => 63,
                '=' => {
                    padding += 1;
                    0
                }
                _ => return Err(format!("{field} base64 contained invalid characters")),
            };

            if *ch == '=' && index < 2 {
                return Err(format!("{field} base64 used invalid padding"));
            }
        }

        let combined = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;

        output.push(((combined >> 16) & 0xff) as u8);
        if padding < 2 {
            output.push(((combined >> 8) & 0xff) as u8);
        }
        if padding < 1 {
            output.push((combined & 0xff) as u8);
        }

        if output.len() > max_len {
            return Err(format!(
                "{field} exceeded maximum length of {max_len} bytes"
            ));
        }
    }

    Ok(output)
}

#[cfg(unix)]
fn write_response(stream: &mut UnixStream, response: &MailboxHelperResponse) -> Result<(), String> {
    stream
        .write_all(encode_response(response).as_bytes())
        .map_err(|error| format!("failed to write helper response: {error}"))
}

#[cfg(unix)]
fn read_bounded_from_stream<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 4096];

    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| format!("failed to read helper payload: {error}"))?;
        if read == 0 {
            break;
        }
        output.extend_from_slice(&chunk[..read]);
        if output.len() > max_bytes {
            return Err(format!(
                "helper payload exceeded maximum size of {max_bytes} bytes"
            ));
        }
    }

    Ok(output)
}

#[cfg(unix)]
fn remove_stale_socket_if_needed(socket_path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(format!(
                    "refusing to remove existing non-socket path {}",
                    socket_path.display()
                ));
            }
            fs::remove_file(socket_path).map_err(|error| {
                format!(
                    "failed to remove stale helper socket {}: {error}",
                    socket_path.display()
                )
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect helper socket {}: {error}",
            socket_path.display()
        )),
    }
}

#[cfg(unix)]
fn log_helper_response(
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
        MailboxHelperRequest::MessageView { .. } => "message_view",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::MailboxBackendError;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct StaticHelperBackend {
        mailbox_result: Arc<Result<Vec<MailboxEntry>, MailboxBackendError>>,
        message_list_result: Arc<Result<Vec<MessageSummary>, MailboxBackendError>>,
        message_view_result: Arc<Result<MessageView, MailboxBackendError>>,
    }

    impl MailboxBackend for StaticHelperBackend {
        fn list_mailboxes(
            &self,
            _canonical_username: &str,
        ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            (*self.mailbox_result).clone()
        }
    }

    impl MessageListBackend for StaticHelperBackend {
        fn list_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageListRequest,
        ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
            (*self.message_list_result).clone()
        }
    }

    impl MessageViewBackend for StaticHelperBackend {
        fn fetch_message(
            &self,
            _canonical_username: &str,
            _request: &MessageViewRequest,
        ) -> Result<MessageView, MailboxBackendError> {
            (*self.message_view_result).clone()
        }
    }

    #[test]
    fn parses_mailbox_list_request() {
        let request =
            parse_request("operation=mailbox_list\ncanonical_username=alice@example.com\n")
                .expect("request should parse");

        assert_eq!(
            request,
            MailboxHelperRequest::MailboxList {
                canonical_username: "alice@example.com".to_string(),
            }
        );
    }

    #[test]
    fn rejects_duplicate_request_fields() {
        let error = parse_request(
            "operation=mailbox_list\ncanonical_username=alice@example.com\ncanonical_username=bob@example.com\n",
        )
        .expect_err("duplicate fields must fail");

        assert!(error.contains("duplicate helper field"));
    }

    #[test]
    fn parses_message_list_request() {
        let request = parse_request(
            "operation=message_list\ncanonical_username=alice@example.com\nmailbox_name=INBOX\n",
        )
        .expect("message-list request should parse");

        assert_eq!(
            request,
            MailboxHelperRequest::MessageList {
                canonical_username: "alice@example.com".to_string(),
                mailbox_name: "INBOX".to_string(),
            }
        );
    }

    #[test]
    fn parses_message_view_request() {
        let request = parse_request(
            "operation=message_view\ncanonical_username=alice@example.com\nmailbox_name=INBOX\nuid=9\n",
        )
        .expect("message-view request should parse");

        assert_eq!(
            request,
            MailboxHelperRequest::MessageView {
                canonical_username: "alice@example.com".to_string(),
                mailbox_name: "INBOX".to_string(),
                uid: 9,
            }
        );
    }

    #[test]
    fn parses_success_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=mailbox_list\nmailbox_count=2\nmailbox=INBOX\nmailbox=Sent Items\n",
        )
        .expect("response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::MailboxListOk {
                mailboxes: vec![
                    MailboxEntry {
                        name: "INBOX".to_string(),
                    },
                    MailboxEntry {
                        name: "Sent Items".to_string(),
                    },
                ],
            }
        );
    }

    #[test]
    fn parses_error_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageViewPolicy::default(),
            "status=error\nbackend=doveadm-mailbox-list\nreason=temporarily unavailable\n",
        )
        .expect("error response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::Error {
                backend: "doveadm-mailbox-list".to_string(),
                reason: "temporarily unavailable".to_string(),
            }
        );
    }

    #[test]
    fn parses_message_list_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=message_list\nmailbox_name=INBOX\nmessage_count=2\nmessage_uid=7\nmessage_flags=\\Seen\nmessage_date_received=2026-03-27 12:00:00 +0000\nmessage_size_virtual=42\nmessage_mailbox=INBOX\nmessage_end=1\nmessage_uid=8\nmessage_flags=\nmessage_date_received=2026-03-27 13:00:00 +0000\nmessage_size_virtual=43\nmessage_mailbox=INBOX\nmessage_end=1\n",
        )
        .expect("message-list response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::MessageListOk {
                mailbox_name: "INBOX".to_string(),
                messages: vec![
                    MessageSummary {
                        mailbox_name: "INBOX".to_string(),
                        uid: 7,
                        flags: vec!["\\Seen".to_string()],
                        date_received: "2026-03-27 12:00:00 +0000".to_string(),
                        size_virtual: 42,
                    },
                    MessageSummary {
                        mailbox_name: "INBOX".to_string(),
                        uid: 8,
                        flags: Vec::new(),
                        date_received: "2026-03-27 13:00:00 +0000".to_string(),
                        size_virtual: 43,
                    },
                ],
            }
        );
    }

    #[test]
    fn parses_message_view_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=message_view\nmessage_uid=9\nmessage_flags=\\Seen\nmessage_date_received=2026-03-27 14:00:00 +0000\nmessage_size_virtual=44\nmessage_mailbox=INBOX\nmessage_header_block_b64=U3ViamVjdDogVGVzdCBtZXNzYWdlCg==\nmessage_body_text_b64=SGVsbG8gd29ybGQK\n",
        )
        .expect("message-view response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::MessageViewOk {
                message: MessageView {
                    mailbox_name: "INBOX".to_string(),
                    uid: 9,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 14:00:00 +0000".to_string(),
                    size_virtual: 44,
                    header_block: "Subject: Test message\n".to_string(),
                    body_text: "Hello world\n".to_string(),
                },
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_lists_mailboxes_over_helper_socket() {
        let socket_path = temp_socket_path("mailbox-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Archive".to_string(),
                },
            ])),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client =
            MailboxHelperMailboxListBackend::new(&socket_path, MailboxHelperPolicy::default());

        let mailboxes = client
            .list_mailboxes("alice@example.com")
            .expect("helper-backed mailbox list should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(
            mailboxes,
            vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Archive".to_string(),
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_surfaces_helper_failures() {
        let socket_path = temp_socket_path("mailbox-helper-error");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Err(MailboxBackendError {
                backend: "doveadm-mailbox-list",
                reason: "userdb denied lookup".to_string(),
            })),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client =
            MailboxHelperMailboxListBackend::new(&socket_path, MailboxHelperPolicy::default());

        let error = client
            .list_mailboxes("alice@example.com")
            .expect_err("helper-backed mailbox list should surface error");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(error.backend, "mailbox-helper-client");
        assert!(error.reason.contains("doveadm-mailbox-list"));
    }

    #[cfg(unix)]
    #[test]
    fn client_lists_messages_over_helper_socket() {
        let socket_path = temp_socket_path("message-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(vec![
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 10,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 12:00:00 +0000".to_string(),
                    size_virtual: 99,
                },
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 11,
                    flags: Vec::new(),
                    date_received: "2026-03-27 13:00:00 +0000".to_string(),
                    size_virtual: 100,
                },
            ])),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client = MailboxHelperMessageListBackend::new(
            &socket_path,
            MailboxHelperPolicy::default(),
            MessageListPolicy::default(),
        );
        let request = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("request should parse");

        let messages = client
            .list_messages("alice@example.com", &request)
            .expect("helper-backed message list should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].uid, 10);
        assert_eq!(messages[1].uid, 11);
    }

    #[cfg(unix)]
    #[test]
    fn client_fetches_message_view_over_helper_socket() {
        let socket_path = temp_socket_path("message-view-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Ok(MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 12,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 14:00:00 +0000".to_string(),
                size_virtual: 101,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            })),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client = MailboxHelperMessageViewBackend::new(
            &socket_path,
            MailboxHelperPolicy::default(),
            MessageViewPolicy::default(),
        );
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 12)
            .expect("request should parse");

        let message = client
            .fetch_message("alice@example.com", &request)
            .expect("helper-backed message view should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(message.uid, 12);
        assert_eq!(message.header_block, "Subject: Test message\n");
        assert_eq!(message.body_text, "Hello world\n");
    }

    #[cfg(unix)]
    fn spawn_test_helper<B>(socket_path: PathBuf, backend: B) -> thread::JoinHandle<()>
    where
        B: MailboxBackend + MessageListBackend + MessageViewBackend + Send + 'static,
    {
        thread::spawn(move || {
            let _ = remove_stale_socket_if_needed(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("test helper should bind");
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Info);
            let (mut stream, _) = listener.accept().expect("test helper should accept");
            handle_helper_client(
                &backend,
                &backend,
                &backend,
                &logger,
                &mut stream,
                MailboxHelperPolicy::default(),
            );
        })
    }

    #[cfg(unix)]
    fn temp_socket_path(prefix: &str) -> PathBuf {
        let unique = format!(
            "{prefix}-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[cfg(unix)]
    fn wait_for_socket(socket_path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if socket_path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }

        panic!(
            "timed out waiting for helper socket {}",
            socket_path.display()
        );
    }
}
