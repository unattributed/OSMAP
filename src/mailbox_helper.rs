//! Local mailbox-helper boundary for least-privilege mailbox reads.
//!
//! The first helper slice stays intentionally narrow:
//! - one local Unix-domain socket listener
//! - one small set of mailbox operations
//! - one small line-oriented protocol that is easy to review
//! - no new RPC framework and only one bounded mailbox mutation behavior

use std::collections::BTreeMap;
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "mailbox_helper_client.rs"]
mod mailbox_helper_client;
#[path = "mailbox_helper_dispatch.rs"]
mod mailbox_helper_dispatch;
#[path = "mailbox_helper_protocol.rs"]
mod mailbox_helper_protocol;

pub use self::mailbox_helper_client::{
    MailboxHelperAttachmentDownloadBackend, MailboxHelperMailboxListBackend,
    MailboxHelperMessageAppendBackend, MailboxHelperMessageListBackend,
    MailboxHelperMessageMoveBackend, MailboxHelperMessageSearchBackend,
    MailboxHelperMessageViewBackend,
};
use self::mailbox_helper_dispatch::{dispatch_helper_request, log_helper_response, HelperBackends};
#[cfg(test)]
use self::mailbox_helper_protocol::issue_request_grant_with_nonce;
use self::mailbox_helper_protocol::{
    encode_request, encode_response, issue_request_grant, parse_request, parse_response,
    request_grant, verify_request_grant, MailboxHelperGrant, MailboxHelperRequest,
    MailboxHelperResponse,
};
use crate::auth::SystemCommandExecutor;
use crate::config::{AppConfig, AppRunMode, LogLevel};
use crate::logging::{EventCategory, LogEvent, Logger};
use crate::mailbox::{
    DoveadmMailboxListBackend, DoveadmMessageAppendBackend, DoveadmMessageListBackend,
    DoveadmMessageMoveBackend, DoveadmMessageSearchBackend, DoveadmMessageViewBackend,
    MailboxBackend, MailboxBackendError, MailboxEntry, MailboxListingPolicy, MessageAppendBackend,
    MessageAppendRequest, MessageListBackend, MessageListPolicy, MessageListRequest,
    MessageMoveBackend, MessageMoveRequest, MessageSearchBackend, MessageSearchPolicy,
    MessageSearchRequest, MessageSearchResult, MessageSummary, MessageView, MessageViewBackend,
    MessageViewPolicy, MessageViewRequest, DEFAULT_MESSAGE_APPEND_MAX_BYTES,
};
#[cfg(test)]
use crate::mailbox::{MessageMovePolicy, MessageSearchField};
use crate::openbsd::{apply_runtime_confinement, unix_stream_peer_uid};

/// Conservative upper bound for one helper request payload.
pub const DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES: usize =
    (DEFAULT_MESSAGE_APPEND_MAX_BYTES / 3 * 4) + 8192;

/// Conservative upper bound for one helper response payload.
///
/// This includes base64 expansion of a maximum-size message-view body.
pub const DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Conservative per-connection read timeout for the helper socket.
pub const DEFAULT_MAILBOX_HELPER_READ_TIMEOUT_SECS: u64 = 5;

/// Conservative per-connection write timeout for the helper socket.
pub const DEFAULT_MAILBOX_HELPER_WRITE_TIMEOUT_SECS: u64 = 5;

/// Conservative cap for concurrently active helper connections.
pub const DEFAULT_MAILBOX_HELPER_MAX_CONCURRENT_CONNECTIONS: usize = 4;

/// Policy controlling the first mailbox-helper boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxHelperPolicy {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
    pub max_concurrent_connections: usize,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MailboxHelperTrustedCallerPolicy {
    trusted_peer_uid: u32,
    grant_key: Vec<u8>,
}

impl Default for MailboxHelperPolicy {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAILBOX_HELPER_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES,
            read_timeout_secs: DEFAULT_MAILBOX_HELPER_READ_TIMEOUT_SECS,
            write_timeout_secs: DEFAULT_MAILBOX_HELPER_WRITE_TIMEOUT_SECS,
            max_concurrent_connections: DEFAULT_MAILBOX_HELPER_MAX_CONCURRENT_CONNECTIONS,
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

        let mailbox_backend = Arc::new(
            DoveadmMailboxListBackend::new(
                MailboxListingPolicy::default(),
                SystemCommandExecutor,
                "/usr/local/bin/doveadm",
            )
            .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone()),
        );
        let message_list_backend = Arc::new(
            DoveadmMessageListBackend::new(
                MessageListPolicy::default(),
                SystemCommandExecutor,
                "/usr/local/bin/doveadm",
            )
            .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone()),
        );
        let message_search_backend = Arc::new(
            DoveadmMessageSearchBackend::new(
                MessageSearchPolicy::default(),
                SystemCommandExecutor,
                "/usr/local/bin/doveadm",
            )
            .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone()),
        );
        let message_view_backend = Arc::new(
            DoveadmMessageViewBackend::new(
                MessageViewPolicy::default(),
                SystemCommandExecutor,
                "/usr/local/bin/doveadm",
            )
            .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone()),
        );
        let message_move_backend = Arc::new(
            DoveadmMessageMoveBackend::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
                .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone()),
        );
        let message_append_backend = Arc::new(
            DoveadmMessageAppendBackend::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
                .with_userdb_socket_path(config.doveadm_userdb_socket_path.clone()),
        );
        let policy = MailboxHelperPolicy::default();
        let replay_cache = Arc::new(Mutex::new(BTreeMap::<String, u64>::new()));
        let active_connections = Arc::new(AtomicUsize::new(0));

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
                Ok(mut stream) => {
                    let Some(slot) = try_acquire_helper_slot(
                        Arc::clone(&active_connections),
                        policy.max_concurrent_connections,
                    ) else {
                        logger.emit(
                            &LogEvent::new(
                                LogLevel::Warn,
                                EventCategory::Mailbox,
                                "mailbox_helper_capacity_reached",
                                "mailbox helper connection capacity reached",
                            )
                            .with_field(
                                "max_concurrent_connections",
                                policy.max_concurrent_connections.to_string(),
                            ),
                        );
                        let _ = write_response(
                            &mut stream,
                            &MailboxHelperResponse::Error {
                                backend: "mailbox-helper-capacity".to_string(),
                                reason: "mailbox helper is at connection capacity".to_string(),
                            },
                        );
                        continue;
                    };

                    let mailbox_backend = Arc::clone(&mailbox_backend);
                    let message_list_backend = Arc::clone(&message_list_backend);
                    let message_search_backend = Arc::clone(&message_search_backend);
                    let message_view_backend = Arc::clone(&message_view_backend);
                    let message_move_backend = Arc::clone(&message_move_backend);
                    let message_append_backend = Arc::clone(&message_append_backend);
                    let replay_cache = Arc::clone(&replay_cache);
                    let trusted_caller_policy = trusted_caller_policy.clone();
                    let worker_logger = logger.clone();
                    if let Err(error) = thread::Builder::new()
                        .name("osmap-mailbox-helper".to_string())
                        .spawn(move || {
                            let _slot = slot;
                            handle_helper_client(
                                HelperBackends {
                                    mailbox_backend: mailbox_backend.as_ref(),
                                    message_list_backend: message_list_backend.as_ref(),
                                    message_search_backend: message_search_backend.as_ref(),
                                    message_view_backend: message_view_backend.as_ref(),
                                    message_move_backend: message_move_backend.as_ref(),
                                    message_append_backend: message_append_backend.as_ref(),
                                },
                                &worker_logger,
                                &mut stream,
                                policy,
                                trusted_caller_policy,
                                replay_cache.as_ref(),
                            );
                        })
                    {
                        logger.emit(
                            &LogEvent::new(
                                LogLevel::Error,
                                EventCategory::Mailbox,
                                "mailbox_helper_worker_spawn_failed",
                                "mailbox helper worker could not start",
                            )
                            .with_field("reason", error.to_string()),
                        );
                    }
                }
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
fn handle_helper_client<MB, MLB, MSB, MVB, MMB, MAB>(
    backends: HelperBackends<'_, MB, MLB, MSB, MVB, MMB, MAB>,
    logger: &Logger,
    stream: &mut UnixStream,
    policy: MailboxHelperPolicy,
    trusted_caller_policy: MailboxHelperTrustedCallerPolicy,
    replay_cache: &Mutex<BTreeMap<String, u64>>,
) where
    MB: MailboxBackend,
    MLB: MessageListBackend,
    MSB: MessageSearchBackend,
    MVB: MessageViewBackend,
    MMB: MessageMoveBackend,
    MAB: MessageAppendBackend,
{
    configure_stream_timeouts(stream, policy);

    match helper_stream_peer_uid(stream)
        .and_then(|peer_uid| authorize_helper_peer_uid(peer_uid, &trusted_caller_policy))
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

    if let Err(reason) =
        verify_helper_request_authority(&request, &trusted_caller_policy.grant_key, replay_cache)
    {
        let response = MailboxHelperResponse::Error {
            backend: "mailbox-helper-grant".to_string(),
            reason,
        };
        let _ = write_response(stream, &response);
        log_helper_response(logger, &response, None);
        return;
    }

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
        grant_key: load_helper_grant_key_from_config(config)?,
    })
}

fn load_helper_grant_key_from_config(config: &AppConfig) -> Result<Vec<u8>, String> {
    let grant_key_path = config
        .mailbox_helper_grant_key_path
        .as_ref()
        .ok_or_else(|| "mailbox helper requires OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH".to_string())?;
    load_helper_grant_key(grant_key_path)
}

pub(crate) fn load_helper_grant_key(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect helper grant key {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "helper grant key {} must be a regular file",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "helper grant key {} must not grant group or other access",
                path.display()
            ));
        }
    }

    let mut key = fs::read(path).map_err(|error| {
        format!(
            "failed to read helper grant key {}: {error}",
            path.display()
        )
    })?;
    while matches!(key.last(), Some(b'\n' | b'\r')) {
        key.pop();
    }
    if key.len() < 32 {
        return Err("helper grant key must contain at least 32 bytes".to_string());
    }
    Ok(key)
}

#[cfg(unix)]
fn verify_helper_request_authority(
    request: &MailboxHelperRequest,
    grant_key: &[u8],
    replay_cache: &Mutex<BTreeMap<String, u64>>,
) -> Result<(), String> {
    let now = current_unix_time_secs()?;
    verify_request_grant(request, grant_key, now)?;
    let mut replay_cache = replay_cache
        .lock()
        .map_err(|_| "helper replay cache lock was poisoned".to_string())?;
    replay_cache.retain(|_, expires_at| *expires_at >= now);
    let grant = request_grant(request);
    let replay_key = grant.signature.clone();
    if replay_cache.contains_key(&replay_key) {
        return Err("helper request grant replay was rejected".to_string());
    }
    replay_cache.insert(replay_key, grant.expires_at);
    Ok(())
}

struct HelperWorkerSlot {
    active_connections: Arc<AtomicUsize>,
}

impl Drop for HelperWorkerSlot {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_helper_slot(
    active_connections: Arc<AtomicUsize>,
    max_concurrent_connections: usize,
) -> Option<HelperWorkerSlot> {
    if max_concurrent_connections == 0 {
        return None;
    }

    let mut active = active_connections.load(Ordering::Acquire);
    loop {
        if active >= max_concurrent_connections {
            return None;
        }
        match active_connections.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(HelperWorkerSlot { active_connections }),
            Err(observed) => active = observed,
        }
    }
}

fn current_unix_time_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock was before Unix epoch: {error}"))
}

#[cfg(unix)]
fn authorize_helper_peer_uid(
    peer_uid: u32,
    trusted_caller_policy: &MailboxHelperTrustedCallerPolicy,
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

    fn test_helper_grant_key() -> Vec<u8> {
        (0..64).map(|index| b'a' + (index % 26) as u8).collect()
    }

    fn test_grant_nonce(seed: u8) -> String {
        let mut nonce = String::new();
        for offset in 0..16 {
            nonce.push_str(&format!("{:02x}", seed.wrapping_add(offset)));
        }
        nonce
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

    impl MessageAppendBackend for StaticHelperBackend {
        fn append_message(
            &self,
            _canonical_username: &str,
            _request: &MessageAppendRequest,
        ) -> Result<(), MailboxBackendError> {
            Ok(())
        }
    }

    fn sign_test_request(request: &mut MailboxHelperRequest) -> String {
        let key = test_helper_grant_key();
        let nonce = test_grant_nonce(0);
        issue_request_grant_with_nonce(request, &key, 100, &nonce)
            .expect("test request grant should sign");
        encode_request(request)
    }

    fn signed_mailbox_list_request_text(username: &str) -> String {
        let mut request = MailboxHelperRequest::MailboxList {
            canonical_username: username.to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let key = test_helper_grant_key();
        let nonce = test_grant_nonce(16);
        issue_request_grant_with_nonce(
            &mut request,
            &key,
            current_unix_time_secs().expect("test clock should be valid"),
            &nonce,
        )
        .expect("test request grant should sign");
        encode_request(&request)
    }

    #[test]
    fn message_append_grant_binds_mailbox_and_message_digest() {
        let mut request = MailboxHelperRequest::MessageAppend {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "Sent".to_string(),
            message: b"Subject: original\r\n\r\nBody\r\n".to_vec(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let key = test_helper_grant_key();
        issue_request_grant_with_nonce(&mut request, &key, 100, &test_grant_nonce(32))
            .expect("append request should sign");

        verify_request_grant(&request, &key, 100).expect("original append request should verify");

        if let MailboxHelperRequest::MessageAppend { message, .. } = &mut request {
            message.extend_from_slice(b"tampered");
        }
        let error = verify_request_grant(&request, &key, 100)
            .expect_err("message mutation must invalidate the grant");
        assert_eq!(error, "helper request grant signature was invalid");
    }

    #[test]
    fn parses_mailbox_list_request() {
        let mut expected = MailboxHelperRequest::MailboxList {
            canonical_username: "alice@example.com".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let text = sign_test_request(&mut expected);
        let request = parse_request(&text).expect("request should parse");

        assert_eq!(request, expected);
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
    fn rejects_legacy_raw_request_fields() {
        let mut request = MailboxHelperRequest::MailboxList {
            canonical_username: "alice@example.com".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let mut text = sign_test_request(&mut request);
        text.push_str("canonical_username=alice@example.com\n");

        let error = parse_request(&text).expect_err("legacy raw fields must fail");

        assert_eq!(error, "unexpected helper request field: canonical_username");
    }

    #[test]
    fn rejects_unknown_request_fields() {
        let mut request = MailboxHelperRequest::MessageList {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let mut text = sign_test_request(&mut request);
        text.push_str("surprise_b64=dmFsdWU=\n");

        let error = parse_request(&text).expect_err("unknown fields must fail");

        assert_eq!(error, "unexpected helper request field: surprise_b64");
    }

    #[test]
    fn rejects_malformed_control_character_request_fields() {
        let error = parse_request("operation=mailbox_list\ncanonical_username_b64=YWxpY2U=\u{1}\n")
            .expect_err("control characters must fail");

        assert!(error.contains("control characters"));
    }

    #[test]
    fn parses_message_list_request() {
        let mut expected = MailboxHelperRequest::MessageList {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let text = sign_test_request(&mut expected);
        let request = parse_request(&text).expect("message-list request should parse");

        assert_eq!(request, expected);
    }

    #[test]
    fn parses_message_view_request() {
        let mut expected = MailboxHelperRequest::MessageView {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            grant: MailboxHelperGrant::unsigned(),
        };
        let text = sign_test_request(&mut expected);
        let request = parse_request(&text).expect("message-view request should parse");

        assert_eq!(request, expected);
    }

    #[test]
    fn parses_attachment_download_request() {
        let mut expected = MailboxHelperRequest::AttachmentDownload {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            part_path: "1.2".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let text = sign_test_request(&mut expected);
        let request = parse_request(&text).expect("attachment-download request should parse");

        assert_eq!(request, expected);
    }

    #[test]
    fn parses_message_search_request() {
        let mut expected = MailboxHelperRequest::MessageSearch {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            query: "quarterly report".to_string(),
            field: MessageSearchField::Subject,
            grant: MailboxHelperGrant::unsigned(),
        };
        let text = sign_test_request(&mut expected);
        let request = parse_request(&text).expect("message-search request should parse");

        assert_eq!(request, expected);
    }

    #[test]
    fn rejects_invalid_message_search_request_field() {
        let mut request = MailboxHelperRequest::MessageSearch {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            query: "quarterly report".to_string(),
            field: MessageSearchField::Subject,
            grant: MailboxHelperGrant::unsigned(),
        };
        let text =
            sign_test_request(&mut request).replace("search_field=subject", "search_field=to");

        let error = parse_request(&text).expect_err("invalid search field should fail");

        assert!(error.contains("invalid helper search_field"));
    }

    #[test]
    fn parses_message_move_request() {
        let mut expected = MailboxHelperRequest::MessageMove {
            canonical_username: "alice@example.com".to_string(),
            source_mailbox_name: "INBOX".to_string(),
            destination_mailbox_name: "Archive/2026".to_string(),
            uid: 9,
            grant: MailboxHelperGrant::unsigned(),
        };
        let text = sign_test_request(&mut expected);
        let request = parse_request(&text).expect("message-move request should parse");

        assert_eq!(request, expected);
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

    fn parse_helper_test_response(response_bytes: Vec<u8>) -> MailboxHelperResponse {
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

        parse_helper_test_response(response_bytes)
    }

    fn run_untrusted_helper_round_trip(trusted_peer_uid: u32) -> MailboxHelperResponse {
        let socket_path = temp_socket_path("mailbox-helper-authz");
        let backends = helper_test_backends();
        let server =
            spawn_test_helper_with_trusted_uid(socket_path.clone(), backends, trusted_peer_uid);

        wait_for_socket(&socket_path);
        let mut client_stream =
            UnixStream::connect(&socket_path).expect("test client should connect to helper");
        client_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("test client read timeout should be configured");

        let response_bytes = read_helper_test_response(&mut client_stream);
        server.join().expect("helper thread should complete");
        let _ = fs::remove_file(&socket_path);

        parse_helper_test_response(response_bytes)
    }

    #[test]
    fn helper_rejects_untrusted_peer_uid() {
        let current_uid = test_runtime_uid();
        let response = run_untrusted_helper_round_trip(current_uid.saturating_add(1));

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
            &signed_mailbox_list_request_text("alice@example.com"),
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
    fn helper_worker_slots_enforce_and_release_the_connection_cap() {
        let active = Arc::new(AtomicUsize::new(0));
        let first = try_acquire_helper_slot(Arc::clone(&active), 2)
            .expect("first helper slot should be available");
        let second = try_acquire_helper_slot(Arc::clone(&active), 2)
            .expect("second helper slot should be available");

        assert!(try_acquire_helper_slot(Arc::clone(&active), 2).is_none());
        assert_eq!(active.load(Ordering::Acquire), 2);

        drop(first);
        let replacement = try_acquire_helper_slot(Arc::clone(&active), 2)
            .expect("released helper slot should become available");
        assert_eq!(active.load(Ordering::Acquire), 2);

        drop(second);
        drop(replacement);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn helper_worker_slots_reject_a_zero_capacity_policy() {
        let active = Arc::new(AtomicUsize::new(0));

        assert!(try_acquire_helper_slot(Arc::clone(&active), 0).is_none());
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn helper_rejects_missing_request_grant() {
        let current_uid = test_runtime_uid();
        let response = run_helper_round_trip(
            current_uid,
            "operation=mailbox_list\ncanonical_username_b64=YWxpY2VAZXhhbXBsZS5jb20=\n",
        );

        assert_eq!(
            response,
            MailboxHelperResponse::Error {
                backend: "mailbox-helper-request".to_string(),
                reason: "missing helper field: grant_issued_at".to_string(),
            }
        );
    }

    #[test]
    fn helper_rejects_altered_grant_username() {
        let current_uid = test_runtime_uid();
        let tampered = signed_mailbox_list_request_text("alice@example.com")
            .replace("YWxpY2VAZXhhbXBsZS5jb20=", "Ym9iQGV4YW1wbGUuY29t");
        let response = run_helper_round_trip(current_uid, &tampered);

        assert_eq!(
            response,
            MailboxHelperResponse::Error {
                backend: "mailbox-helper-grant".to_string(),
                reason: "helper request grant signature was invalid".to_string(),
            }
        );
    }

    #[test]
    fn helper_rejects_expired_request_grant() {
        let current_uid = test_runtime_uid();
        let mut request = MailboxHelperRequest::MailboxList {
            canonical_username: "alice@example.com".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let now = current_unix_time_secs().expect("test clock should be valid");
        let key = test_helper_grant_key();
        let nonce = test_grant_nonce(32);
        issue_request_grant_with_nonce(&mut request, &key, now.saturating_sub(120), &nonce)
            .expect("expired test grant should sign");
        let response = run_helper_round_trip(current_uid, &encode_request(&request));

        assert_eq!(
            response,
            MailboxHelperResponse::Error {
                backend: "mailbox-helper-grant".to_string(),
                reason: "helper request grant expired".to_string(),
            }
        );
    }

    #[test]
    fn helper_rejects_read_grant_reused_for_mutation() {
        let current_uid = test_runtime_uid();
        let mut read_request = MailboxHelperRequest::MessageList {
            canonical_username: "alice@example.com".to_string(),
            mailbox_name: "INBOX".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let key = test_helper_grant_key();
        let nonce = test_grant_nonce(48);
        issue_request_grant_with_nonce(
            &mut read_request,
            &key,
            current_unix_time_secs().expect("test clock should be valid"),
            &nonce,
        )
        .expect("read grant should sign");
        let read_grant = request_grant(&read_request).clone();
        let move_request = MailboxHelperRequest::MessageMove {
            canonical_username: "alice@example.com".to_string(),
            source_mailbox_name: "INBOX".to_string(),
            destination_mailbox_name: "Archive".to_string(),
            uid: 9,
            grant: read_grant,
        };
        let response = run_helper_round_trip(current_uid, &encode_request(&move_request));

        assert_eq!(
            response,
            MailboxHelperResponse::Error {
                backend: "mailbox-helper-grant".to_string(),
                reason: "helper request grant signature was invalid".to_string(),
            }
        );
    }

    #[test]
    fn helper_rejects_replayed_request_grant() {
        let mut request = MailboxHelperRequest::MailboxList {
            canonical_username: "alice@example.com".to_string(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let key = test_helper_grant_key();
        let nonce = test_grant_nonce(64);
        issue_request_grant_with_nonce(
            &mut request,
            &key,
            current_unix_time_secs().expect("test clock should be valid"),
            &nonce,
        )
        .expect("test grant should sign");
        let replay_cache = Mutex::new(BTreeMap::<String, u64>::new());

        verify_helper_request_authority(&request, &key, &replay_cache)
            .expect("first grant use should pass");
        let error = verify_helper_request_authority(&request, &key, &replay_cache)
            .expect_err("second grant use must fail");

        assert_eq!(error, "helper request grant replay was rejected");
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
        let grant_key_path = temp_root.join("mailbox-helper-grant.key");
        fs::write(&grant_key_path, test_helper_grant_key()).expect("grant key should be written");
        fs::set_permissions(&grant_key_path, fs::Permissions::from_mode(0o600))
            .expect("grant key permissions should be restricted");
        let config = AppConfig {
            run_mode: AppRunMode::MailboxHelper,
            environment: crate::config::RuntimeEnvironment::Development,
            listen_addr: "127.0.0.1:8080".to_string(),
            allowed_hosts: vec!["localhost".to_string()],
            doveadm_auth_socket_path: Some(socket_path.clone()),
            trusted_web_runtime_uid: Some(test_runtime_uid()),
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: Some(temp_root.join("mailbox-helper.sock")),
            mailbox_helper_grant_key_path: Some(grant_key_path),
            state_root: temp_root.clone(),
            log_level: LogLevel::Info,
            log_format: crate::config::LogFormat::Text,
            state_layout: crate::state::StateLayout::new(crate::state::StateLayoutPaths {
                root_dir: temp_root.clone(),
                runtime_dir: temp_root.join("run"),
                session_dir: temp_root.join("sessions"),
                settings_dir: temp_root.join("settings"),
                draft_dir: temp_root.join("drafts"),
                audit_dir: temp_root.join("audit"),
                cache_dir: temp_root.join("cache"),
                totp_secret_dir: temp_root.join("totp"),
            })
            .expect("layout should be valid"),
            http_max_concurrent_connections: 16,
            mailbox_worker_budget: 8,
            search_worker_budget: 4,
            send_worker_budget: 2,
            auth_worker_budget: 4,
            expensive_request_timeout_seconds: 5,
            auth_backend_timeout_seconds: 20,
            session_lifetime_seconds: 43200,
            session_idle_timeout_seconds: 1800,
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
            allowed_hosts: vec!["localhost".to_string()],
            doveadm_auth_socket_path: Some(socket_path.clone()),
            trusted_web_runtime_uid: Some(mismatched_uid),
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: Some(temp_root.join("mailbox-helper.sock")),
            mailbox_helper_grant_key_path: Some(temp_root.join("mailbox-helper-grant.key")),
            state_root: temp_root.clone(),
            log_level: LogLevel::Info,
            log_format: crate::config::LogFormat::Text,
            state_layout: crate::state::StateLayout::new(crate::state::StateLayoutPaths {
                root_dir: temp_root.clone(),
                runtime_dir: temp_root.join("run"),
                session_dir: temp_root.join("sessions"),
                settings_dir: temp_root.join("settings"),
                draft_dir: temp_root.join("drafts"),
                audit_dir: temp_root.join("audit"),
                cache_dir: temp_root.join("cache"),
                totp_secret_dir: temp_root.join("totp"),
            })
            .expect("layout should be valid"),
            http_max_concurrent_connections: 16,
            mailbox_worker_budget: 8,
            search_worker_budget: 4,
            send_worker_budget: 2,
            auth_worker_budget: 4,
            expensive_request_timeout_seconds: 5,
            auth_backend_timeout_seconds: 20,
            session_lifetime_seconds: 43200,
            session_idle_timeout_seconds: 1800,
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
        let expected = MailboxHelperResponse::MailboxListOk {
            mailboxes: vec![
                MailboxEntry {
                    name: "INBOX".to_string(),
                },
                MailboxEntry {
                    name: "Sent Items".to_string(),
                },
            ],
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("response should parse");

        assert_eq!(response, expected);
    }

    #[test]
    fn parses_error_response() {
        let expected = MailboxHelperResponse::Error {
            backend: "doveadm-mailbox-list".to_string(),
            reason: "temporarily unavailable".to_string(),
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("error response should parse");

        assert_eq!(response, expected);
    }

    #[test]
    fn parses_message_list_response() {
        let expected = MailboxHelperResponse::MessageListOk {
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
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("message-list response should parse");

        assert_eq!(response, expected);
    }

    #[test]
    fn parses_message_search_response() {
        let expected = MailboxHelperResponse::MessageSearchOk {
            mailbox_name: "INBOX".to_string(),
            query: "quarterly report".to_string(),
            field: MessageSearchField::Subject,
            results: vec![MessageSearchResult {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 14:00:00 +0000".to_string(),
                size_virtual: 44,
                subject: Some("Quarterly report".to_string()),
                from: Some("Alice <alice@example.com>".to_string()),
            }],
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("message-search response should parse");

        assert_eq!(response, expected);
    }

    #[test]
    fn rejects_invalid_message_search_response_field() {
        let response_text = concat!(
            "status=ok\n",
            "operation=message_search\n",
            "mailbox_name_b64=SU5CT1g=\n",
            "query_b64=cXVhcnRlcmx5IHJlcG9ydA==\n",
            "search_field=to\n",
            "message_count=0\n",
        );

        let error = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            response_text,
        )
        .expect_err("invalid response search field should fail");

        assert!(error.contains("invalid helper response search_field"));
    }

    #[test]
    fn parses_message_view_response() {
        let expected = MailboxHelperResponse::MessageViewOk {
            message: Box::new(MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                flags: vec!["\\Seen".to_string()],
                date_received: "2026-03-27 14:00:00 +0000".to_string(),
                size_virtual: 44,
                header_block: "Subject: Test message\n".to_string(),
                body_text: "Hello world\n".to_string(),
            }),
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("message-view response should parse");

        assert_eq!(response, expected);
    }

    #[test]
    fn parses_attachment_download_response() {
        let expected = MailboxHelperResponse::AttachmentDownloadOk {
            attachment: Box::new(crate::attachment::DownloadedAttachment {
                mailbox_name: "INBOX".to_string(),
                uid: 9,
                part_path: "1.2".to_string(),
                filename: "report.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                body: b"Hello".to_vec(),
            }),
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("attachment-download response should parse");

        assert_eq!(response, expected);
    }

    #[test]
    fn parses_message_move_response() {
        let expected = MailboxHelperResponse::MessageMoveOk {
            source_mailbox_name: "INBOX".to_string(),
            destination_mailbox_name: "Archive/2026".to_string(),
            uid: 9,
        };
        let text = encode_response(&expected);
        let response = parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &text,
        )
        .expect("message-move response should parse");

        assert_eq!(response, expected);
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
        let grant_key_path = temp_grant_key_path("mailbox-helper-ok");
        let client = MailboxHelperMailboxListBackend::new(
            &socket_path,
            &grant_key_path,
            MailboxHelperPolicy::default(),
        );

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
        let grant_key_path = temp_grant_key_path("mailbox-helper-error");
        let client = MailboxHelperMailboxListBackend::new(
            &socket_path,
            &grant_key_path,
            MailboxHelperPolicy::default(),
        );

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
    fn client_mailbox_list_times_out_when_helper_does_not_respond() {
        let socket_path = temp_socket_path("mailbox-helper-timeout");
        let server = spawn_unresponsive_helper(socket_path.clone());
        wait_for_socket(&socket_path);
        let grant_key_path = temp_grant_key_path("mailbox-helper-timeout");
        let client = MailboxHelperMailboxListBackend::new(
            &socket_path,
            &grant_key_path,
            one_second_helper_timeout_policy(),
        );
        let started_at = Instant::now();

        let error = client
            .list_mailboxes("alice@example.com")
            .expect_err("unresponsive helper must time out");
        let elapsed = started_at.elapsed();

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(error.backend, "mailbox-helper-client");
        assert!(error.reason.contains("failed to read helper payload"));
        assert!(
            elapsed < Duration::from_secs(2),
            "helper read timeout should fire before the silent helper closes"
        );
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
        let grant_key_path = temp_grant_key_path("message-helper-ok");
        let client = MailboxHelperMessageListBackend::new(
            &socket_path,
            &grant_key_path,
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
        let grant_key_path = temp_grant_key_path("message-search-helper-ok");
        let client = MailboxHelperMessageSearchBackend::new(
            &socket_path,
            &grant_key_path,
            MailboxHelperPolicy::default(),
            MessageSearchPolicy::default(),
        );
        let request = MessageSearchRequest::new_with_field(
            MessageSearchPolicy::default(),
            "INBOX",
            "quarterly report",
            MessageSearchField::Subject,
        )
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
    fn client_message_search_times_out_when_helper_does_not_respond() {
        let socket_path = temp_socket_path("message-search-helper-timeout");
        let server = spawn_unresponsive_helper(socket_path.clone());
        wait_for_socket(&socket_path);
        let grant_key_path = temp_grant_key_path("message-search-helper-timeout");
        let client = MailboxHelperMessageSearchBackend::new(
            &socket_path,
            &grant_key_path,
            one_second_helper_timeout_policy(),
            MessageSearchPolicy::default(),
        );
        let request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "quarterly report")
                .expect("request should parse");
        let started_at = Instant::now();

        let error = client
            .search_messages("alice@example.com", &request)
            .expect_err("unresponsive helper must time out");
        let elapsed = started_at.elapsed();

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(error.backend, "mailbox-helper-client");
        assert!(error.reason.contains("failed to read helper payload"));
        assert!(
            elapsed < Duration::from_secs(2),
            "helper read timeout should fire before the silent helper closes"
        );
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
        let grant_key_path = temp_grant_key_path("message-view-helper-ok");
        let client = MailboxHelperMessageViewBackend::new(
            &socket_path,
            &grant_key_path,
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
    fn client_fetches_maximum_bounded_message_view_over_helper_socket() {
        let socket_path = temp_socket_path("message-view-helper-max-body");
        let body_text = "x".repeat(crate::mailbox::DEFAULT_MESSAGE_BODY_MAX_LEN);
        let backend = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Ok(MessageView {
                mailbox_name: "INBOX".to_string(),
                uid: 12,
                flags: Vec::new(),
                date_received: "2026-06-20 00:00:00 +0000".to_string(),
                size_virtual: body_text.len() as u64,
                header_block: "Subject: Bounded message\n".to_string(),
                body_text: body_text.clone(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let server = spawn_test_helper(socket_path.clone(), backend);
        wait_for_socket(&socket_path);
        let grant_key_path = temp_grant_key_path("message-view-helper-max-body");
        let client = MailboxHelperMessageViewBackend::new(
            &socket_path,
            &grant_key_path,
            MailboxHelperPolicy::default(),
            MessageViewPolicy::default(),
        );
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 12)
            .expect("request should parse");

        let message = client
            .fetch_message("alice@example.com", &request)
            .expect("maximum bounded message view should cross helper protocol");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&grant_key_path);

        assert_eq!(
            message.body_text.len(),
            crate::mailbox::DEFAULT_MESSAGE_BODY_MAX_LEN
        );
        assert_eq!(
            MailboxHelperPolicy::default().max_response_bytes,
            DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES
        );
    }

    #[cfg(unix)]
    #[test]
    fn client_message_view_times_out_when_helper_does_not_respond() {
        let socket_path = temp_socket_path("message-view-helper-timeout");
        let server = spawn_unresponsive_helper(socket_path.clone());
        wait_for_socket(&socket_path);
        let grant_key_path = temp_grant_key_path("message-view-helper-timeout");
        let client = MailboxHelperMessageViewBackend::new(
            &socket_path,
            &grant_key_path,
            one_second_helper_timeout_policy(),
            MessageViewPolicy::default(),
        );
        let request = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 12)
            .expect("request should parse");
        let started_at = Instant::now();

        let error = client
            .fetch_message("alice@example.com", &request)
            .expect_err("unresponsive helper must time out");
        let elapsed = started_at.elapsed();

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);

        assert_eq!(error.backend, "mailbox-helper-client");
        assert!(error.reason.contains("failed to read helper payload"));
        assert!(
            elapsed < Duration::from_secs(2),
            "helper read timeout should fire before the silent helper closes"
        );
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
        let grant_key_path = temp_grant_key_path("attachment-helper-ok");
        let client = MailboxHelperAttachmentDownloadBackend::new(
            &socket_path,
            &grant_key_path,
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
        let grant_key_path = temp_grant_key_path("attachment-helper-missing");
        let client = MailboxHelperAttachmentDownloadBackend::new(
            &socket_path,
            &grant_key_path,
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
        let grant_key_path = temp_grant_key_path("message-move-helper-ok");
        let client = MailboxHelperMessageMoveBackend::new(
            &socket_path,
            &grant_key_path,
            MailboxHelperPolicy::default(),
        );
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
    #[test]
    fn client_appends_message_over_helper_socket() {
        let socket_path = temp_socket_path("message-append-helper-ok");
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
        let grant_key_path = temp_grant_key_path("message-append-helper-ok");
        let client = MailboxHelperMessageAppendBackend::new(
            &socket_path,
            &grant_key_path,
            MailboxHelperPolicy::default(),
        );
        let request = MessageAppendRequest::new(
            "Sent",
            b"From: alice@example.com\r\nTo: bob@example.com\r\n\r\nHello\r\n".to_vec(),
        )
        .expect("request should parse");

        client
            .append_message("alice@example.com", &request)
            .expect("helper-backed message append should succeed");

        server.join().expect("helper thread should finish");
        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&grant_key_path);
    }

    #[cfg(unix)]
    fn spawn_test_helper<B>(socket_path: PathBuf, backend: B) -> thread::JoinHandle<()>
    where
        B: MailboxBackend
            + MessageListBackend
            + MessageSearchBackend
            + MessageViewBackend
            + MessageMoveBackend
            + MessageAppendBackend
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
            + MessageAppendBackend
            + Send
            + 'static,
    {
        thread::spawn(move || {
            let _ = remove_stale_socket_if_needed(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("test helper should bind");
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Info);
            let (mut stream, _) = listener.accept().expect("test helper should accept");
            let replay_cache = Mutex::new(BTreeMap::<String, u64>::new());
            handle_helper_client(
                HelperBackends {
                    mailbox_backend: &backend,
                    message_list_backend: &backend,
                    message_search_backend: &backend,
                    message_view_backend: &backend,
                    message_move_backend: &backend,
                    message_append_backend: &backend,
                },
                &logger,
                &mut stream,
                MailboxHelperPolicy::default(),
                MailboxHelperTrustedCallerPolicy {
                    trusted_peer_uid,
                    grant_key: test_helper_grant_key(),
                },
                &replay_cache,
            );
        })
    }

    #[cfg(unix)]
    fn spawn_unresponsive_helper(socket_path: PathBuf) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let _ = remove_stale_socket_if_needed(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("test helper should bind");
            let (mut stream, _) = listener.accept().expect("test helper should accept");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .expect("test helper should read request");
            thread::sleep(Duration::from_secs(3));
        })
    }

    fn one_second_helper_timeout_policy() -> MailboxHelperPolicy {
        MailboxHelperPolicy {
            read_timeout_secs: 1,
            write_timeout_secs: 1,
            ..MailboxHelperPolicy::default()
        }
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
    fn temp_grant_key_path(prefix: &str) -> PathBuf {
        let path = temp_socket_path(prefix).with_extension("key");
        fs::write(&path, test_helper_grant_key()).expect("test grant key should be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test grant key permissions should be restricted");
        path
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
