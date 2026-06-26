use super::*;
use std::path::Path;

const MISSING_HELPER_GRANT_BACKEND: &str = "mailbox-helper-config";
const MISSING_HELPER_GRANT_REASON: &str = "mailbox helper socket configured without grant key path";

impl RuntimeBrowserGateway {
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
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => {
                    MailboxListRuntimeBackend::Helper(MailboxHelperMailboxListBackend::new(
                        socket_path,
                        grant_key_path,
                        MailboxHelperPolicy::default(),
                    ))
                }
                None => MailboxListRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => MailboxListRuntimeBackend::Direct(
                DoveadmMailboxListBackend::new(
                    MailboxListingPolicy::default(),
                    SystemCommandExecutor,
                    self.doveadm_path.clone(),
                )
                .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone()),
            ),
        }
    }

    /// Selects the current message-list backend without widening the browser
    /// runtime's authority when a local helper is configured.
    pub(super) fn build_message_list_backend(&self) -> MessageListRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => {
                    MessageListRuntimeBackend::Helper(MailboxHelperMessageListBackend::new(
                        socket_path,
                        grant_key_path,
                        MailboxHelperPolicy::default(),
                        MessageListPolicy::default(),
                    ))
                }
                None => MessageListRuntimeBackend::Unavailable(missing_helper_grant_error()),
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
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => {
                    MessageViewRuntimeBackend::Helper(MailboxHelperMessageViewBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy(),
                        MessageViewPolicy::default(),
                    ))
                }
                None => MessageViewRuntimeBackend::Unavailable(missing_helper_grant_error()),
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
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                    .with_command_timeout_secs(self.expensive_route_command_timeout_secs()),
            ),
        }
    }

    /// Selects the backend used to file a delivered message into Sent.
    pub(super) fn build_message_append_backend(&self) -> MessageAppendRuntimeBackend {
        match &self.mailbox_helper_socket_path {
            Some(socket_path) => match self.helper_grant_key_path() {
                Some(grant_key_path) => {
                    MessageAppendRuntimeBackend::Helper(MailboxHelperMessageAppendBackend::new(
                        socket_path,
                        grant_key_path,
                        self.expensive_route_helper_policy(),
                    ))
                }
                None => MessageAppendRuntimeBackend::Unavailable(missing_helper_grant_error()),
            },
            None => MessageAppendRuntimeBackend::Direct(
                DoveadmMessageAppendBackend::new(SystemCommandExecutor, self.doveadm_path.clone())
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

/// Selects the current mailbox-list backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MailboxListRuntimeBackend {
    Direct(DoveadmMailboxListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMailboxListBackend),
    Unavailable(crate::mailbox::MailboxBackendError),
}

impl crate::mailbox::MailboxBackend for MailboxListRuntimeBackend {
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
        let message_move_request =
            MessageMoveRequest::new(MessageMovePolicy::default(), "INBOX", "Archive", 1).unwrap();
        let message_append_request =
            MessageAppendRequest::new("Sent", b"Subject: saved\r\n\r\nbody".to_vec()).unwrap();

        let errors = [
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
