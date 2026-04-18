//! Local mailbox-helper boundary for least-privilege mailbox reads.
//!
//! The first helper slice stays intentionally narrow:
//! - one local Unix-domain socket listener
//! - one small set of mailbox operations
//! - one small line-oriented protocol that is easy to review
//! - no new RPC framework and only one bounded mailbox mutation behavior

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "mailbox_helper_client.rs"]
mod mailbox_helper_client;
#[path = "mailbox_helper_dispatch.rs"]
mod mailbox_helper_dispatch;
#[path = "mailbox_helper_protocol.rs"]
mod mailbox_helper_protocol;

pub use self::mailbox_helper_client::{
    MailboxHelperAttachmentDownloadBackend, MailboxHelperMailboxListBackend,
    MailboxHelperMessageListBackend, MailboxHelperMessageMoveBackend,
    MailboxHelperMessageSearchBackend, MailboxHelperMessageViewBackend,
};
use self::mailbox_helper_dispatch::{dispatch_helper_request, log_helper_response, HelperBackends};
use self::mailbox_helper_protocol::{
    encode_request, encode_response, parse_request, parse_response, MailboxHelperRequest,
    MailboxHelperResponse,
};
use crate::auth::SystemCommandExecutor;
use crate::config::{AppConfig, AppRunMode, LogLevel};
use crate::logging::{EventCategory, LogEvent, Logger};
#[cfg(test)]
use crate::mailbox::MessageMovePolicy;
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageListBackend, DoveadmMessageMoveBackend,
    DoveadmMessageSearchBackend, DoveadmMessageViewBackend, MailboxBackend, MailboxBackendError,
    MailboxEntry, MailboxListingPolicy, MessageListBackend, MessageListPolicy, MessageListRequest,
    MessageMoveBackend, MessageMoveRequest, MessageSearchBackend, MessageSearchPolicy,
    MessageSearchRequest, MessageSearchResult, MessageSummary, MessageView, MessageViewBackend,
    MessageViewPolicy, MessageViewRequest,
};
use crate::openbsd::{apply_runtime_confinement, unix_stream_peer_uid};

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

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MailboxHelperTrustedCallerPolicy {
    trusted_peer_uid: u32,
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
        let trusted_caller_policy = trusted_caller_policy_from_config(config)?;
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
        let message_search_backend = DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
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
        let message_move_backend =
            DoveadmMessageMoveBackend::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
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
                    HelperBackends {
                        mailbox_backend: &mailbox_backend,
                        message_list_backend: &message_list_backend,
                        message_search_backend: &message_search_backend,
                        message_view_backend: &message_view_backend,
                        message_move_backend: &message_move_backend,
                    },
                    logger,
                    &mut stream,
                    policy,
                    trusted_caller_policy,
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

#[cfg(unix)]
fn handle_helper_client<MB, MLB, MSB, MVB, MMB>(
    backends: HelperBackends<'_, MB, MLB, MSB, MVB, MMB>,
    logger: &Logger,
    stream: &mut UnixStream,
    policy: MailboxHelperPolicy,
    trusted_caller_policy: MailboxHelperTrustedCallerPolicy,
) where
    MB: MailboxBackend,
    MLB: MessageListBackend,
    MSB: MessageSearchBackend,
    MVB: MessageViewBackend,
    MMB: MessageMoveBackend,
{
    configure_stream_timeouts(stream, policy);

    match helper_stream_peer_uid(stream)
        .and_then(|peer_uid| authorize_helper_peer_uid(peer_uid, trusted_caller_policy))
    {
        Ok(()) => {}
        Err(reason) => {
            logger.emit(
                &LogEvent::new(
                    LogLevel::Warn,
                    EventCategory::Mailbox,
                    "mailbox_helper_peer_not_authorized",
                    "mailbox helper peer was not authorized",
                )
                .with_field("reason", reason),
            );
            let response = MailboxHelperResponse::Error {
                backend: "mailbox-helper-authz".to_string(),
                reason: "helper peer credentials were not authorized".to_string(),
            };
            let _ = write_response(stream, &response);
            log_helper_response(logger, &response, None);
            return;
        }
    }

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

    let response = dispatch_helper_request(backends, &request);

    let _ = write_response(stream, &response);
    log_helper_response(logger, &response, Some(&request));
}

#[cfg(unix)]
fn trusted_caller_policy_from_config(
    config: &AppConfig,
) -> Result<MailboxHelperTrustedCallerPolicy, String> {
    let auth_socket_path = config.doveadm_auth_socket_path.as_ref().ok_or_else(|| {
        "mailbox helper run mode requires OSMAP_DOVEADM_AUTH_SOCKET_PATH".to_string()
    })?;
    let expected_web_runtime_uid = config.trusted_web_runtime_uid.ok_or_else(|| {
        "mailbox helper run mode requires OSMAP_TRUSTED_WEB_RUNTIME_UID".to_string()
    })?;
    let metadata = fs::symlink_metadata(auth_socket_path).map_err(|error| {
        format!(
            "failed to inspect trusted auth socket {}: {error}",
            auth_socket_path.display()
        )
    })?;

    if !metadata.file_type().is_socket() {
        return Err(format!(
            "trusted auth socket path {} must point to a Unix-domain socket",
            auth_socket_path.display()
        ));
    }

    let derived_trusted_peer_uid = metadata.uid();
    if derived_trusted_peer_uid != expected_web_runtime_uid {
        return Err(format!(
            "trusted auth socket owner uid {derived_trusted_peer_uid} did not match configured OSMAP_TRUSTED_WEB_RUNTIME_UID {expected_web_runtime_uid}"
        ));
    }

    Ok(MailboxHelperTrustedCallerPolicy {
        trusted_peer_uid: derived_trusted_peer_uid,
    })
}

#[cfg(unix)]
fn authorize_helper_peer_uid(
    peer_uid: u32,
    trusted_caller_policy: MailboxHelperTrustedCallerPolicy,
) -> Result<(), String> {
    if peer_uid == trusted_caller_policy.trusted_peer_uid {
        return Ok(());
    }

    Err(format!(
        "helper peer uid {peer_uid} did not match trusted uid {}",
        trusted_caller_policy.trusted_peer_uid
    ))
}

#[cfg(unix)]
fn helper_stream_peer_uid(stream: &UnixStream) -> Result<u32, String> {
    unix_stream_peer_uid(stream)
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

#[cfg(unix)]
fn write_response(stream: &mut UnixStream, response: &MailboxHelperResponse) -> Result<(), String> {
    stream
        .write_all(encode_response(response).as_bytes())
        .map_err(|error| format!("failed to write helper response: {error}"))?;
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::MailboxBackendError;
    use std::env;
    use std::fs;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct StaticHelperBackend {
        mailbox_result: Arc<Result<Vec<MailboxEntry>, MailboxBackendError>>,
        message_list_result: Arc<Result<Vec<MessageSummary>, MailboxBackendError>>,
        message_search_result: Arc<Result<Vec<MessageSearchResult>, MailboxBackendError>>,
        message_view_result: Arc<Result<MessageView, MailboxBackendError>>,
        message_move_result: Arc<Result<(), MailboxBackendError>>,
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

    impl MessageSearchBackend for StaticHelperBackend {
        fn search_messages(
            &self,
            _canonical_username: &str,
            _request: &MessageSearchRequest,
        ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
            (*self.message_search_result).clone()
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

    impl MessageMoveBackend for StaticHelperBackend {
        fn move_message(
            &self,
            _canonical_username: &str,
            _request: &MessageMoveRequest,
        ) -> Result<(), MailboxBackendError> {
            (*self.message_move_result).clone()
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
    fn parses_attachment_download_request() {
        let request = parse_request(
            "operation=attachment_download\ncanonical_username=alice@example.com\nmailbox_name=INBOX\nuid=9\npart_path=1.2\n",
        )
        .expect("attachment-download request should parse");

        assert_eq!(
            request,
            MailboxHelperRequest::AttachmentDownload {
                canonical_username: "alice@example.com".to_string(),
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                part_path: "1.2".to_string(),
            }
        );
    }

    #[test]
    fn parses_message_search_request() {
        let request = parse_request(
            "operation=message_search\ncanonical_username=alice@example.com\nmailbox_name=INBOX\nquery=quarterly report\n",
        )
        .expect("message-search request should parse");

        assert_eq!(
            request,
            MailboxHelperRequest::MessageSearch {
                canonical_username: "alice@example.com".to_string(),
                mailbox_name: "INBOX".to_string(),
                query: "quarterly report".to_string(),
            }
        );
    }

    #[test]
    fn parses_message_move_request() {
        let request = parse_request(
            "operation=message_move\ncanonical_username=alice@example.com\nsource_mailbox_name=INBOX\ndestination_mailbox_name=Archive/2026\nuid=9\n",
        )
        .expect("message-move request should parse");

        assert_eq!(
            request,
            MailboxHelperRequest::MessageMove {
                canonical_username: "alice@example.com".to_string(),
                source_mailbox_name: "INBOX".to_string(),
                destination_mailbox_name: "Archive/2026".to_string(),
                uid: 9,
            }
        );
    }

    fn helper_test_backends() -> StaticHelperBackend {
        StaticHelperBackend {
            mailbox_result: Arc::new(Ok(vec![MailboxEntry {
                name: "INBOX".to_string(),
            }])),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Ok(MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 1,
                flags: Vec::new(),
                date_received: "2026-04-13 00:00:00 +0000".to_string(),
                size_virtual: 1,
                header_block: "Subject: test\n".to_string(),
                body_text: "hello\n".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
        }
    }

    fn run_helper_round_trip(trusted_peer_uid: u32, request: &str) -> MailboxHelperResponse {
        let socket_path = temp_socket_path("mailbox-helper-authz");
        let backends = helper_test_backends();
        let server =
            spawn_test_helper_with_trusted_uid(socket_path.clone(), backends, trusted_peer_uid);

        wait_for_socket(&socket_path);
        let mut client_stream =
            UnixStream::connect(&socket_path).expect("test client should connect to helper");

        client_stream
            .write_all(request.as_bytes())
            .expect("request write should succeed");
        client_stream
            .shutdown(Shutdown::Write)
            .expect("client shutdown should succeed");
        let response_bytes = read_helper_test_response(&mut client_stream);
        server.join().expect("helper thread should complete");
        let _ = fs::remove_file(&socket_path);

        let response_text = String::from_utf8(response_bytes).expect("response should be utf-8");
        parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &response_text,
        )
        .expect("response should parse")
    }

    #[test]
    fn helper_rejects_untrusted_peer_uid() {
        let current_uid = test_runtime_uid();
        let response = run_helper_round_trip(
            current_uid.saturating_add(1),
            "operation=mailbox_list\ncanonical_username=alice@example.com\n",
        );

        assert_eq!(
            response,
            MailboxHelperResponse::Error {
                backend: "mailbox-helper-authz".to_string(),
                reason: "helper peer credentials were not authorized".to_string(),
            }
        );
    }

    #[test]
    fn helper_accepts_trusted_peer_uid() {
        let current_uid = test_runtime_uid();
        let response = run_helper_round_trip(
            current_uid,
            "operation=mailbox_list\ncanonical_username=alice@example.com\n",
        );

        assert_eq!(
            response,
            MailboxHelperResponse::MailboxListOk {
                mailboxes: vec![MailboxEntry {
                    name: "INBOX".to_string(),
                }],
            }
        );
    }

    #[test]
    fn trusted_caller_policy_uses_auth_socket_owner_uid() {
        let temp_root = env::temp_dir().join(format!(
            "osmap-mailbox-helper-authz-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_root).expect("temp root should be created");
        let socket_path = temp_socket_path("trusted-auth");
        let _listener = UnixListener::bind(&socket_path).expect("test auth socket should bind");
        let config = AppConfig {
            run_mode: AppRunMode::MailboxHelper,
            environment: crate::config::RuntimeEnvironment::Development,
            listen_addr: "127.0.0.1:8080".to_string(),
            doveadm_auth_socket_path: Some(socket_path.clone()),
            trusted_web_runtime_uid: Some(test_runtime_uid()),
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: Some(temp_root.join("mailbox-helper.sock")),
            state_root: temp_root.clone(),
            log_level: LogLevel::Info,
            log_format: crate::config::LogFormat::Text,
            state_layout: crate::state::StateLayout::new(
                temp_root.clone(),
                temp_root.join("run"),
                temp_root.join("sessions"),
                temp_root.join("settings"),
                temp_root.join("audit"),
                temp_root.join("cache"),
                temp_root.join("totp"),
            )
            .expect("layout should be valid"),
            http_max_concurrent_connections: 16,
            session_lifetime_seconds: 43200,
            totp_allowed_skew_steps: 1,
            login_throttle_max_failures: 5,
            login_throttle_remote_max_failures: 12,
            login_throttle_window_seconds: 300,
            login_throttle_lockout_seconds: 900,
            submission_throttle_max_submissions: 10,
            submission_throttle_remote_max_submissions: 25,
            submission_throttle_window_seconds: 300,
            submission_throttle_lockout_seconds: 900,
            message_move_throttle_max_moves: 20,
            message_move_throttle_remote_max_moves: 60,
            message_move_throttle_window_seconds: 300,
            message_move_throttle_lockout_seconds: 900,
            openbsd_confinement_mode: crate::config::OpenbsdConfinementMode::Disabled,
        };

        let policy =
            trusted_caller_policy_from_config(&config).expect("auth socket owner should resolve");

        let expected_uid = fs::metadata(&socket_path)
            .expect("auth socket metadata should be readable")
            .uid();
        assert_eq!(policy.trusted_peer_uid, expected_uid);

        fs::remove_file(&socket_path).expect("socket should be removed");
        fs::remove_dir_all(&temp_root).expect("temp root should be removed");
    }

    #[test]
    fn trusted_caller_policy_rejects_mismatched_expected_web_runtime_uid() {
        let temp_root = env::temp_dir().join(format!(
            "osmap-mailbox-helper-authz-mismatch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_root).expect("temp root should be created");
        let socket_path = temp_socket_path("trusted-auth");
        let _listener = UnixListener::bind(&socket_path).expect("test auth socket should bind");
        let actual_uid = fs::metadata(&socket_path)
            .expect("auth socket metadata should be readable")
            .uid();
        let mismatched_uid = actual_uid.saturating_add(1);
        let config = AppConfig {
            run_mode: AppRunMode::MailboxHelper,
            environment: crate::config::RuntimeEnvironment::Development,
            listen_addr: "127.0.0.1:8080".to_string(),
            doveadm_auth_socket_path: Some(socket_path.clone()),
            trusted_web_runtime_uid: Some(mismatched_uid),
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: Some(temp_root.join("mailbox-helper.sock")),
            state_root: temp_root.clone(),
            log_level: LogLevel::Info,
            log_format: crate::config::LogFormat::Text,
            state_layout: crate::state::StateLayout::new(
                temp_root.clone(),
                temp_root.join("run"),
                temp_root.join("sessions"),
                temp_root.join("settings"),
                temp_root.join("audit"),
                temp_root.join("cache"),
                temp_root.join("totp"),
            )
            .expect("layout should be valid"),
            http_max_concurrent_connections: 16,
            session_lifetime_seconds: 43200,
            totp_allowed_skew_steps: 1,
            login_throttle_max_failures: 5,
            login_throttle_remote_max_failures: 12,
            login_throttle_window_seconds: 300,
            login_throttle_lockout_seconds: 900,
            submission_throttle_max_submissions: 10,
            submission_throttle_remote_max_submissions: 25,
            submission_throttle_window_seconds: 300,
            submission_throttle_lockout_seconds: 900,
            message_move_throttle_max_moves: 20,
            message_move_throttle_remote_max_moves: 60,
            message_move_throttle_window_seconds: 300,
            message_move_throttle_lockout_seconds: 900,
            openbsd_confinement_mode: crate::config::OpenbsdConfinementMode::Disabled,
        };

        let error = trusted_caller_policy_from_config(&config)
            .expect_err("mismatched configured runtime uid must fail closed");
        assert_eq!(
            error,
            format!(
                "trusted auth socket owner uid {actual_uid} did not match configured OSMAP_TRUSTED_WEB_RUNTIME_UID {mismatched_uid}"
            )
        );

        fs::remove_file(&socket_path).expect("socket should be removed");
        fs::remove_dir_all(&temp_root).expect("temp root should be removed");
    }

    #[test]
    fn parses_success_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
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
            MessageSearchPolicy::default(),
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
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=message_list\nmailbox_name=INBOX\nmessage_count=2\nmessage_uid=7\nmessage_flags=\\Seen\nmessage_date_received=2026-03-27 12:00:00 +0000\nmessage_size_virtual=42\nmessage_mailbox=INBOX\nmessage_subject=Quarterly report\nmessage_from=Alice <alice@example.com>\nmessage_end=1\nmessage_uid=8\nmessage_flags=\nmessage_date_received=2026-03-27 13:00:00 +0000\nmessage_size_virtual=43\nmessage_mailbox=INBOX\nmessage_subject=Follow-up\nmessage_from=Bob <bob@example.com>\nmessage_end=1\n",
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
                        subject: Some("Quarterly report".to_string()),
                        from: Some("Alice <alice@example.com>".to_string()),
                    },
                    MessageSummary {
                        mailbox_name: "INBOX".to_string(),
                        uid: 8,
                        flags: Vec::new(),
                        date_received: "2026-03-27 13:00:00 +0000".to_string(),
                        size_virtual: 43,
                        subject: Some("Follow-up".to_string()),
                        from: Some("Bob <bob@example.com>".to_string()),
                    },
                ],
            }
        );
    }

    #[test]
    fn parses_message_search_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=message_search\nmailbox_name=INBOX\nquery=quarterly report\nmessage_count=1\nmessage_uid=9\nmessage_flags=\\Seen\nmessage_date_received=2026-03-27 14:00:00 +0000\nmessage_size_virtual=44\nmessage_mailbox=INBOX\nmessage_subject=Quarterly report\nmessage_from=Alice <alice@example.com>\nmessage_end=1\n",
        )
        .expect("message-search response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::MessageSearchOk {
                mailbox_name: "INBOX".to_string(),
                query: "quarterly report".to_string(),
                results: vec![MessageSearchResult {
                    mailbox_name: "INBOX".to_string(),
                    uid: 9,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 14:00:00 +0000".to_string(),
                    size_virtual: 44,
                    subject: Some("Quarterly report".to_string()),
                    from: Some("Alice <alice@example.com>".to_string()),
                }],
            }
        );
    }

    #[test]
    fn parses_message_view_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=message_view\nmessage_uid=9\nmessage_flags=\\Seen\nmessage_date_received=2026-03-27 14:00:00 +0000\nmessage_size_virtual=44\nmessage_mailbox=INBOX\nmessage_header_block_b64=U3ViamVjdDogVGVzdCBtZXNzYWdlCg==\nmessage_body_text_b64=SGVsbG8gd29ybGQK\n",
        )
        .expect("message-view response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::MessageViewOk {
                message: Box::new(MessageView {
                    mailbox_name: "INBOX".to_string(),
                    uid: 9,
                    flags: vec!["\\Seen".to_string()],
                    date_received: "2026-03-27 14:00:00 +0000".to_string(),
                    size_virtual: 44,
                    header_block: "Subject: Test message\n".to_string(),
                    body_text: "Hello world\n".to_string(),
                }),
            }
        );
    }

    #[test]
    fn parses_attachment_download_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=attachment_download\nattachment_mailbox_name=INBOX\nattachment_uid=9\nattachment_part_path=1.2\nattachment_filename=report.pdf\nattachment_content_type=application/pdf\nattachment_body_b64=SGVsbG8=\n",
        )
        .expect("attachment-download response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::AttachmentDownloadOk {
                attachment: Box::new(crate::attachment::DownloadedAttachment {
                    mailbox_name: "INBOX".to_string(),
                    uid: 9,
                    part_path: "1.2".to_string(),
                    filename: "report.pdf".to_string(),
                    content_type: "application/pdf".to_string(),
                    body: b"Hello".to_vec(),
                }),
            }
        );
    }

    #[test]
    fn parses_message_move_response() {
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            "status=ok\noperation=message_move\nsource_mailbox_name=INBOX\ndestination_mailbox_name=Archive/2026\nuid=9\n",
        )
        .expect("message-move response should parse");

        assert_eq!(
            response,
            MailboxHelperResponse::MessageMoveOk {
                source_mailbox_name: "INBOX".to_string(),
                destination_mailbox_name: "Archive/2026".to_string(),
                uid: 9,
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
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
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
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
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
                    subject: Some("Quarterly report".to_string()),
                    from: Some("Alice <alice@example.com>".to_string()),
                },
                MessageSummary {
                    mailbox_name: "INBOX".to_string(),
                    uid: 11,
                    flags: Vec::new(),
                    date_received: "2026-03-27 13:00:00 +0000".to_string(),
                    size_virtual: 100,
                    subject: Some("Follow-up".to_string()),
                    from: Some("Bob <bob@example.com>".to_string()),
                },
            ])),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
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
        assert_eq!(messages[0].subject.as_deref(), Some("Quarterly report"));
        assert_eq!(
            messages[0].from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(messages[1].uid, 11);
        assert_eq!(messages[1].subject.as_deref(), Some("Follow-up"));
        assert_eq!(messages[1].from.as_deref(), Some("Bob <bob@example.com>"));
    }

    #[cfg(unix)]
    #[test]
    fn client_searches_messages_over_helper_socket() {
        let socket_path = temp_socket_path("message-search-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(vec![MessageSearchResult {
                mailbox_name: "INBOX".to_string(),
                uid: 18,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 17:00:00 +0000".to_string(),
                size_virtual: 222,
                subject: Some("Quarterly report".to_string()),
                from: Some("Alice <alice@example.com>".to_string()),
            }])),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client = MailboxHelperMessageSearchBackend::new(
            &socket_path,
            MailboxHelperPolicy::default(),
            MessageSearchPolicy::default(),
        );
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should parse");

        let results = client
            .search_messages("alice@example.com", &request)
            .expect("helper-backed message search should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].uid, 18);
        assert_eq!(results[0].subject.as_deref(), Some("Quarterly report"));
    }

    #[cfg(unix)]
    #[test]
    fn client_fetches_message_view_over_helper_socket() {
        let socket_path = temp_socket_path("message-view-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Ok(MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 12,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 14:00:00 +0000".to_string(),
                size_virtual: 101,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
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
    #[test]
    fn client_downloads_attachment_over_helper_socket() {
        let socket_path = temp_socket_path("attachment-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Ok(MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 12,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 14:00:00 +0000".to_string(),
                size_virtual: 101,
                header_block: "Subject: Test\nContent-Type: multipart/mixed; boundary=\"mix-1\"\n"
                    .to_string(),
                body_text: concat!(
                    "--mix-1\n",
                    "Content-Type: text/plain; charset=utf-8\n",
                    "\n",
                    "Body text\n",
                    "--mix-1\n",
                    "Content-Type: application/pdf\n",
                    "Content-Transfer-Encoding: base64\n",
                    "Content-Disposition: attachment; filename=\"report.pdf\"\n",
                    "\n",
                    "SGVsbG8=\n",
                    "--mix-1--\n",
                )
                .to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client = MailboxHelperAttachmentDownloadBackend::new(
            &socket_path,
            MailboxHelperPolicy::default(),
        );

        let attachment = client
            .download_attachment("alice@example.com", "INBOX", 12, "1.2")
            .expect("helper-backed attachment download should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(attachment.mailbox_name, "INBOX");
        assert_eq!(attachment.uid, 12);
        assert_eq!(attachment.part_path, "1.2");
        assert_eq!(attachment.filename, "report.pdf");
        assert_eq!(attachment.content_type, "application/pdf");
        assert_eq!(attachment.body, b"Hello");
    }

    #[cfg(unix)]
    #[test]
    fn client_maps_missing_attachment_to_not_found() {
        let socket_path = temp_socket_path("attachment-helper-missing");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-found",
                reason: "message was not found".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client = MailboxHelperAttachmentDownloadBackend::new(
            &socket_path,
            MailboxHelperPolicy::default(),
        );

        let error = client
            .download_attachment("alice@example.com", "INBOX", 12, "1.2")
            .expect_err("missing helper attachment should surface as an error");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(
            error.kind,
            crate::attachment::AttachmentDownloadFailureKind::NotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_moves_message_over_helper_socket() {
        let socket_path = temp_socket_path("message-move-helper-ok");
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "message-view-not-used",
                reason: "unexpected message-view request".to_string(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let client =
            MailboxHelperMessageMoveBackend::new(&socket_path, MailboxHelperPolicy::default());
        let request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive/2026", 9)
                .expect("request should parse");

        client
            .move_message("alice@example.com", &request)
            .expect("helper-backed message move should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);
    }

    #[cfg(unix)]
    fn spawn_test_helper<B>(socket_path: PathBuf, backend: B) -> thread::JoinHandle<()>
    where
        B: MailboxBackend
            + MessageListBackend
            + MessageSearchBackend
            + MessageViewBackend
            + MessageMoveBackend
            + Send
            + 'static,
    {
        spawn_test_helper_with_trusted_uid(socket_path, backend, test_runtime_uid())
    }

    #[cfg(unix)]
    fn spawn_test_helper_with_trusted_uid<B>(
        socket_path: PathBuf,
        backend: B,
        trusted_peer_uid: u32,
    ) -> thread::JoinHandle<()>
    where
        B: MailboxBackend
            + MessageListBackend
            + MessageSearchBackend
            + MessageViewBackend
            + MessageMoveBackend
            + Send
            + 'static,
    {
        thread::spawn(move || {
            let _ = remove_stale_socket_if_needed(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("test helper should bind");
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Info);
            let (mut stream, _) = listener.accept().expect("test helper should accept");
            handle_helper_client(
                HelperBackends {
                    mailbox_backend: &backend,
                    message_list_backend: &backend,
                    message_search_backend: &backend,
                    message_view_backend: &backend,
                    message_move_backend: &backend,
                },
                &logger,
                &mut stream,
                MailboxHelperPolicy::default(),
                MailboxHelperTrustedCallerPolicy { trusted_peer_uid },
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
    fn test_runtime_uid() -> u32 {
        let temp_root = env::temp_dir().join(format!(
            "osmap-mailbox-helper-test-uid-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_root).expect("temp root should be created");
        let uid = fs::metadata(&temp_root)
            .expect("temp root metadata should be readable")
            .uid();
        fs::remove_dir(&temp_root).expect("temp root should be removed");
        uid
    }

    #[cfg(unix)]
    fn read_helper_test_response(stream: &mut UnixStream) -> Vec<u8> {
        let mut output = Vec::new();
        let mut chunk = [0_u8; 4096];

        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    output.extend_from_slice(&chunk[..read]);
                    if output.len() > DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES {
                        panic!("test helper response exceeded maximum size");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("response read should succeed: {error}"),
            }
        }

        output
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
