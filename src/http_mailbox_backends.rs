use super::*;
use crate::mailbox::{
    DoveadmMessageFlagBackend, MessageFlagBackend, MessageFlagRequest, MessageFlagResult,
};
use crate::mailbox_helper::MailboxHelperMessageFlagBackend;
use std::path::Path;

const MISSING_HELPER_GRANT_BACKEND: &str = "mailbox-helper-config";
const MISSING_HELPER_GRANT_REASON: &str = "mailbox helper socket configured without grant key path";

impl RuntimeBrowserGateway {
    pub(super) fn build_message_flag_backend(&self) -> MessageFlagRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(key) => {
                    MessageFlagRuntimeBackend::Helper(MailboxHelperMessageFlagBackend::new(
                        socket_path,
                        key,
                        self.expensive_route_helper_policy(),
                    ))
                }
                None => MessageFlagRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => {
                let gate = direct_mail_mutation_gate();
                MessageFlagRuntimeBackend::Direct(
                    DoveadmMessageFlagBackend::new(
                        SystemCommandExecutor,
                        self.doveadm_path.clone(),
                    )
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                    .with_operation_gate(gate)
                    .with_command_timeout_secs(self.expensive_request_timeout_secs),
                )
            }
        }
    }

    /// Caps helper-backed expensive route work to the browser route deadline.
    pub(super) fn expensive_route_helper_policy(&self) -> MailboxHelperPolicy {
        self.expensive_route_helper_policy_with_timeout(self.expensive_request_timeout_secs)
    }

    /// Caps helper-backed expensive route work to the supplied route deadline.
    pub(super) fn expensive_route_helper_policy_with_timeout(
        &self,
        timeout_secs: u64,
    ) -> MailboxHelperPolicy {
        let mut policy = MailboxHelperPolicy::default();
        policy.read_timeout_secs = policy.read_timeout_secs.min(timeout_secs.max(1));
        policy.write_timeout_secs = policy.write_timeout_secs.min(timeout_secs.max(1));
        policy
    }

    /// Caps direct external mailbox commands to the browser route deadline.
    fn expensive_route_command_timeout_secs(&self) -> u64 {
        self.expensive_route_command_timeout_secs_with_timeout(self.expensive_request_timeout_secs)
    }

    /// Caps direct external mailbox commands to the supplied route deadline.
    fn expensive_route_command_timeout_secs_with_timeout(&self, timeout_secs: u64) -> u64 {
        timeout_secs.clamp(1, crate::auth::DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS)
    }

    /// Selects the current mailbox-list backend without widening the browser
    /// runtime's authority when a local helper is configured.
    pub(super) fn build_mailbox_list_backend(&self) -> MailboxListRuntimeBackend {
        self.build_mailbox_list_backend_with_timeout(
            crate::auth::DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS,
        )
    }

    /// A listing bounded by the remaining all-mailbox search deadline.
    pub(super) fn build_mailbox_list_backend_with_timeout(
        &self,
        timeout_secs: u64,
    ) -> MailboxListRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => MailboxListRuntimeBackend::Helper(
                    MailboxHelperMailboxListBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy_with_timeout(timeout_secs),
                    )
                    .with_helper_uid(self.mailbox_helper_peer_uid),
                ),
                None => MailboxListRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => MailboxListRuntimeBackend::Direct(
                DoveadmMailboxListBackend::new(
                    MailboxListingPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                .with_command_timeout_secs(
                    self.expensive_route_command_timeout_secs_with_timeout(timeout_secs),
                ),
            ),
        }
    }

    /// Selects the current message-list backend without widening the browser
    /// runtime's authority when a local helper is configured.
    pub(super) fn build_message_list_backend(&self) -> MessageListRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match (self.helper_grant_key_path(), self.mailbox_helper_peer_uid)
            {
                (Some(grant_key_path), Some(helper_uid)) => MessageListRuntimeBackend::Helper(
                    MailboxHelperMessageListBackend::new(
                        socket_path,
                        grant_key_path,
                        MailboxHelperPolicy::default(),
                        MessageListPolicy::default(),
                    )
                    .with_helper_uid(Some(helper_uid)),
                ),
                (None, _) => MessageListRuntimeBackend::Unavailable(missing_helper_grant_error()),
                (_, None) => MessageListRuntimeBackend::Unavailable(missing_helper_peer_error()),
            },
            None => MessageListRuntimeBackend::Direct(
                DoveadmMessageListBackend::new(
                    MessageListPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Selects the current message-search backend based on whether the local
    /// mailbox helper is configured for read-path proxying.
    pub(super) fn build_message_search_backend(&self) -> MessageSearchRuntimeBackend {
        self.build_message_search_backend_with_timeout(self.expensive_request_timeout_secs)
    }

    pub(super) fn build_message_search_backend_with_timeout(
        &self,
        timeout_secs: u64,
    ) -> MessageSearchRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => {
                    MessageSearchRuntimeBackend::Helper(MailboxHelperMessageSearchBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy_with_timeout(timeout_secs),
                        MessageSearchPolicy::default(),
                    ))
                }
                None => MessageSearchRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => MessageSearchRuntimeBackend::Direct(
                DoveadmMessageSearchBackend::new(
                    MessageSearchPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                .with_command_timeout_secs(
                    self.expensive_route_command_timeout_secs_with_timeout(timeout_secs),
                ),
            ),
        }
    }

    /// Selects the current message-view backend based on whether the local
    /// mailbox helper is configured for read-path proxying.
    pub(super) fn build_message_view_backend(&self) -> MessageViewRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match (self.helper_grant_key_path(), self.mailbox_helper_peer_uid)
            {
                (Some(grant_key_path), Some(helper_uid)) => MessageViewRuntimeBackend::Helper(
                    MailboxHelperMessageViewBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy(),
                        MessageViewPolicy::default(),
                    )
                    .with_helper_uid(Some(helper_uid)),
                ),
                (None, _) => MessageViewRuntimeBackend::Unavailable(missing_helper_grant_error()),
                (_, None) => MessageViewRuntimeBackend::Unavailable(missing_helper_peer_error()),
            },
            None => MessageViewRuntimeBackend::Direct(
                DoveadmMessageViewBackend::new(
                    MessageViewPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                .with_command_timeout_secs(self.expensive_route_command_timeout_secs()),
            ),
        }
    }

    /// Selects the current message-move backend based on whether the local
    /// mailbox helper is configured for mailbox-authoritative operations.
    pub(super) fn build_message_move_backend(&self) -> MessageMoveRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => {
                    MessageMoveRuntimeBackend::Helper(MailboxHelperMessageMoveBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy(),
                    ))
                }
                None => MessageMoveRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => MessageMoveRuntimeBackend::Direct(
                DoveadmMessageMoveBackend::new(SystemCommandExecutor, self.doveadm_path.clone())
                    .with_operation_gate(direct_mail_mutation_gate())
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                    .with_command_timeout_secs(self.expensive_route_command_timeout_secs()),
            ),
        }
    }

    /// Selects the backend used to file a delivered message into Sent.
    pub(super) fn build_message_append_backend(&self) -> MessageAppendRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => MessageAppendRuntimeBackend::Helper(
                    MailboxHelperMessageAppendBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy(),
                    )
                    .with_helper_uid(self.mailbox_helper_peer_uid),
                ),
                None => MessageAppendRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => MessageAppendRuntimeBackend::Direct(
                DoveadmMessageAppendBackend::new(SystemCommandExecutor, self.doveadm_path.clone())
                    .with_operation_gate(direct_mail_mutation_gate())
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                    .with_command_timeout_secs(self.expensive_route_command_timeout_secs()),
            ),
        }
    }

    fn helper_grant_key_path(&self) -> Option<&Path> {
        self.mailbox_helper_grant_key_path.as_deref()
    }
}

fn missing_helper_grant_error() -> crate::mailbox::MailboxBackendError {
    crate::mailbox::MailboxBackendError {
        backend: MISSING_HELPER_GRANT_BACKEND,
        reason: MISSING_HELPER_GRANT_REASON.to_string(),
    }
}

fn missing_helper_peer_error() -> crate::mailbox::MailboxBackendError {
    crate::mailbox::MailboxBackendError {
        backend: "mailbox-helper-client",
        reason: "helper peer uid missing".into(),
    }
}

pub(super) enum MessageFlagRuntimeBackend {
    Direct(DoveadmMessageFlagBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageFlagBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl MessageFlagBackend for MessageFlagRuntimeBackend {
    fn set_message_flag(
        &self,
        username: &str,
        request: &MessageFlagRequest,
    ) -> Result<MessageFlagResult, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.set_message_flag(username, request),
            Self::Helper(backend) => backend.set_message_flag(username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

fn direct_mail_mutation_gate() -> std::sync::Arc<std::sync::Mutex<()>> {
    static GATE: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<()>>> =
        std::sync::OnceLock::new();
    GATE.get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(())))
        .clone()
}

/// Selects the current mailbox-list backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MailboxListRuntimeBackend {
    Direct(DoveadmMailboxListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMailboxListBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MailboxBackend for MailboxListRuntimeBackend {
    fn folder_rename_completion(
        &self,
        r: &crate::folder_rename::RenameFolderRequest,
    ) -> crate::folder_rename::Completion {
        match self {
            Self::Helper(b) => b.folder_rename_completion(r),
            _ => crate::folder_rename::Completion::Unconfirmed,
        }
    }
    fn rename_folder(
        &self,
        r: &crate::folder_rename::RenameFolderRequest,
    ) -> crate::folder_rename::Outcome {
        match self {
            Self::Direct(b) => b.rename_folder(r),
            Self::Helper(b) => b.rename_folder(r),
            Self::Unavailable(_) => {
                crate::folder_rename::Outcome::Refused(crate::folder_create::Refusal::Unavailable)
            }
        }
    }

    fn create_folder(
        &self,
        r: &crate::folder_create::CreateFolderRequest,
    ) -> crate::folder_create::Outcome {
        match self {
            Self::Direct(b) => b.create_folder(r),
            Self::Helper(b) => b.create_folder(r),
            Self::Unavailable(_) => {
                crate::folder_create::Outcome::Refused(crate::folder_create::Refusal::Unavailable)
            }
        }
    }
    fn folder_metadata(
        &self,
        account: &str,
    ) -> Result<crate::folder_metadata::FolderSnapshot, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(v) => v.folder_metadata(account),
            Self::Helper(v) => v.folder_metadata(account),
            Self::Unavailable(e) => Err(e.clone()),
        }
    }

    fn mailbox_status(
        &self,
        account: &str,
        folder: &str,
    ) -> Result<crate::mailbox_status::MailboxStatus, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(v) => v.mailbox_status(account, folder),
            Self::Helper(v) => v.mailbox_status(account, folder),
            Self::Unavailable(e) => Err(e.clone()),
        }
    }

    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_mailboxes(canonical_username),
            Self::Helper(backend) => backend.list_mailboxes(canonical_username),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

/// Selects the current message-list backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageListRuntimeBackend {
    Direct(DoveadmMessageListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageListBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MessageListBackend for MessageListRuntimeBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_messages(canonical_username, request),
            Self::Helper(backend) => backend.list_messages(canonical_username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

/// Selects the current message-search backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageSearchRuntimeBackend {
    Direct(DoveadmMessageSearchBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageSearchBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MessageSearchBackend for MessageSearchRuntimeBackend {
    fn search_messages_batch(
        &self,
        canonical_username: &str,
        request: &crate::mailbox::MessageSearchBatchRequest,
    ) -> Result<Vec<MessageSearchResult>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.search_messages_batch(canonical_username, request),
            Self::Helper(backend) => backend.search_messages_batch(canonical_username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.search_messages(canonical_username, request),
            Self::Helper(backend) => backend.search_messages(canonical_username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

/// Selects the current message-move backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageMoveRuntimeBackend {
    Direct(DoveadmMessageMoveBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageMoveBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MessageMoveBackend for MessageMoveRuntimeBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.move_message(canonical_username, request),
            Self::Helper(backend) => backend.move_message(canonical_username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

/// Selects the current message-append backend without giving the browser
/// runtime direct mailbox authority when a local helper is configured.
pub(super) enum MessageAppendRuntimeBackend {
    Direct(DoveadmMessageAppendBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageAppendBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MessageAppendBackend for MessageAppendRuntimeBackend {
    fn append_message(
        &self,
        canonical_username: &str,
        request: &MessageAppendRequest,
    ) -> Result<(), crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.append_message(canonical_username, request),
            Self::Helper(backend) => backend.append_message(canonical_username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

/// Selects the current message-view backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageViewRuntimeBackend {
    Direct(DoveadmMessageViewBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageViewBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MessageViewBackend for MessageViewRuntimeBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<crate::mailbox::MessageView, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.fetch_message(canonical_username, request),
            Self::Helper(backend) => backend.fetch_message(canonical_username, request),
            Self::Unavailable(error) => Err(error.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::{
        MailboxBackend, MessageAppendBackend, MessageListBackend, MessageMoveBackend,
        MessageSearchBackend, MessageViewBackend,
    };

    #[cfg(unix)]
    #[test]
    fn runtime_message_reads_refuse_configured_wrong_peer_before_wire() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        use std::thread;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let temp_root = std::env::temp_dir().join(format!(
            "osmap-message-read-peer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should follow epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&temp_root).expect("test root should be created");
        std::fs::set_permissions(&temp_root, std::fs::Permissions::from_mode(0o700))
            .expect("test root should be private");
        let socket_path = temp_root.join("helper.sock");
        let key_path = temp_root.join("grant.key");
        std::fs::write(&key_path, vec![b'k'; 64]).expect("test key should be written");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("test key should be private");
        let listener = UnixListener::bind(&socket_path).expect("test helper should bind");
        let server = thread::spawn(move || {
            let mut observed = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("test helper should accept");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("test read should be bounded");
                let mut first_byte = [0_u8; 1];
                observed.push(
                    stream
                        .read(&mut first_byte)
                        .expect("test read should finish"),
                );
            }
            observed
        });
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.mailbox_helper_socket_path = Some(socket_path.clone());
        gateway.mailbox_helper_grant_key_path = Some(key_path.clone());
        gateway.mailbox_helper_peer_uid = Some(crate::openbsd::effective_uid().wrapping_add(1));
        let list = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("list request should parse");
        let view = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 1)
            .expect("view request should parse");

        let list_error = gateway
            .build_message_list_backend()
            .list_messages("alice@example.com", &list)
            .expect_err("configured wrong peer must refuse list");
        let view_error = gateway
            .build_message_view_backend()
            .fetch_message("alice@example.com", &view)
            .expect_err("configured wrong peer must refuse view");
        let observed = server.join().expect("test helper should finish");
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_dir(&temp_root);

        assert_eq!(observed, vec![0, 0], "wrong peer received request bytes");
        assert_eq!(list_error.reason, "helper peer refused");
        assert_eq!(view_error.reason, "helper peer refused");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_message_reads_without_configured_peer_never_connect() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        use std::time::{SystemTime, UNIX_EPOCH};

        let temp_root = std::env::temp_dir().join(format!(
            "osmap-message-read-missing-peer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should follow epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&temp_root).expect("test root should be created");
        std::fs::set_permissions(&temp_root, std::fs::Permissions::from_mode(0o700))
            .expect("test root should be private");
        let socket_path = temp_root.join("helper.sock");
        let key_path = temp_root.join("grant.key");
        std::fs::write(&key_path, vec![b'k'; 64]).expect("test key should be written");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("test key should be private");
        let listener = UnixListener::bind(&socket_path).expect("test helper should bind");
        listener
            .set_nonblocking(true)
            .expect("test accept should not block");
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.mailbox_helper_socket_path = Some(socket_path.clone());
        gateway.mailbox_helper_grant_key_path = Some(key_path.clone());
        gateway.mailbox_helper_peer_uid = None;
        let list = MessageListRequest::new(MessageListPolicy::default(), "INBOX")
            .expect("list request should parse");
        let view = MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 1)
            .expect("view request should parse");

        let list_error = gateway
            .build_message_list_backend()
            .list_messages("alice@example.com", &list)
            .expect_err("missing expected peer must refuse list");
        let view_error = gateway
            .build_message_view_backend()
            .fetch_message("alice@example.com", &view)
            .expect_err("missing expected peer must refuse view");
        let connection = listener.accept();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_dir(&temp_root);

        assert_eq!(list_error.reason, "helper peer uid missing");
        assert_eq!(view_error.reason, "helper peer uid missing");
        assert_eq!(
            connection
                .expect_err("missing peer must not connect")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn expensive_route_helper_policy_never_exceeds_route_timeout() {
        let temp_root = std::env::temp_dir().join(format!(
            "osmap-expensive-helper-policy-{}",
            std::process::id()
        ));
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.expensive_request_timeout_secs = 2;

        let policy = gateway.expensive_route_helper_policy();

        assert_eq!(policy.read_timeout_secs, 2);
        assert_eq!(policy.write_timeout_secs, 2);
    }

    #[test]
    fn expensive_route_helper_policy_keeps_tighter_helper_defaults() {
        let temp_root = std::env::temp_dir().join(format!(
            "osmap-expensive-helper-policy-default-{}",
            std::process::id()
        ));
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.expensive_request_timeout_secs = 30;

        let policy = gateway.expensive_route_helper_policy();

        assert_eq!(
            policy.read_timeout_secs,
            crate::mailbox_helper::DEFAULT_MAILBOX_HELPER_READ_TIMEOUT_SECS
        );
        assert_eq!(
            policy.write_timeout_secs,
            crate::mailbox_helper::DEFAULT_MAILBOX_HELPER_WRITE_TIMEOUT_SECS
        );
    }

    #[test]
    fn helper_backends_fail_closed_when_grant_key_path_is_missing() {
        let temp_root =
            std::env::temp_dir().join(format!("osmap-missing-helper-grant-{}", std::process::id()));
        let mut gateway = RuntimeBrowserGateway::for_test(&temp_root);
        gateway.mailbox_helper_socket_path = Some(temp_root.join("mailbox-helper.sock"));
        gateway.mailbox_helper_grant_key_path = None;

        let message_list_request =
            MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
        let message_search_request =
            MessageSearchRequest::new(MessageSearchPolicy::default(), "INBOX", "needle").unwrap();
        let message_view_request =
            MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 1).unwrap();
        let message_move_request = MessageMoveRequest::new(
            MessageMovePolicy::default(),
            "INBOX",
            "Archive",
            1,
            crate::message_metadata::MessageVersion::new("a".repeat(32), "fixture-9".into())
                .unwrap(),
        )
        .unwrap();
        let message_append_request =
            MessageAppendRequest::new("Sent", b"Subject: saved\r\n\r\nbody".to_vec()).unwrap();

        let errors = [
            gateway
                .build_message_flag_backend()
                .set_message_flag(
                    "alice@example.com",
                    &MessageFlagRequest::new(
                        "INBOX".into(),
                        1,
                        crate::message_metadata::MessageVersion::new(
                            "a".repeat(32),
                            "fixture".into(),
                        )
                        .unwrap(),
                        crate::message_metadata::MessageFlag::Seen,
                        true,
                    )
                    .unwrap(),
                )
                .unwrap_err(),
            gateway
                .build_mailbox_list_backend()
                .list_mailboxes("alice@example.com")
                .unwrap_err(),
            gateway
                .build_message_list_backend()
                .list_messages("alice@example.com", &message_list_request)
                .unwrap_err(),
            gateway
                .build_message_search_backend()
                .search_messages("alice@example.com", &message_search_request)
                .unwrap_err(),
            gateway
                .build_message_view_backend()
                .fetch_message("alice@example.com", &message_view_request)
                .unwrap_err(),
            gateway
                .build_message_move_backend()
                .move_message("alice@example.com", &message_move_request)
                .unwrap_err(),
            gateway
                .build_message_append_backend()
                .append_message("alice@example.com", &message_append_request)
                .unwrap_err(),
        ];

        for error in errors {
            assert_eq!(error.backend, MISSING_HELPER_GRANT_BACKEND);
            assert_eq!(error.reason, MISSING_HELPER_GRANT_REASON);
        }
    }
}
