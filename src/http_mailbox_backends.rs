use super::*;

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
            Some(socket_path) => MailboxListRuntimeBackend::Helper(
                MailboxHelperMailboxListBackend::new(socket_path, MailboxHelperPolicy::default()),
            ),
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
            Some(socket_path) => {
                MessageListRuntimeBackend::Helper(MailboxHelperMessageListBackend::new(
                    socket_path,
                    MailboxHelperPolicy::default(),
                    MessageListPolicy::default(),
                ))
            }
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
            Some(socket_path) => {
                MessageSearchRuntimeBackend::Helper(MailboxHelperMessageSearchBackend::new(
                    socket_path,
                    self.expensive_route_helper_policy_with_timeout(timeout_secs),
                    MessageSearchPolicy::default(),
                ))
            }
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
            Some(socket_path) => {
                MessageViewRuntimeBackend::Helper(MailboxHelperMessageViewBackend::new(
                    socket_path,
                    self.expensive_route_helper_policy(),
                    MessageViewPolicy::default(),
                ))
            }
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
            Some(socket_path) => {
                MessageMoveRuntimeBackend::Helper(MailboxHelperMessageMoveBackend::new(
                    socket_path,
                    self.expensive_route_helper_policy(),
                ))
            }
            None => MessageMoveRuntimeBackend::Direct(
                DoveadmMessageMoveBackend::new(SystemCommandExecutor, self.doveadm_path.clone())
                    .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
                    .with_command_timeout_secs(self.expensive_route_command_timeout_secs()),
            ),
        }
    }
}

/// Selects the current mailbox-list backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MailboxListRuntimeBackend {
    Direct(DoveadmMailboxListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMailboxListBackend),
}

impl crate::mailbox::MailboxBackend for MailboxListRuntimeBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, crate::mailbox::MailboxBackendError> {
        match self {
            Self::Direct(backend) => backend.list_mailboxes(canonical_username),
            Self::Helper(backend) => backend.list_mailboxes(canonical_username),
        }
    }
}

/// Selects the current message-list backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageListRuntimeBackend {
    Direct(DoveadmMessageListBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageListBackend),
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
        }
    }
}

/// Selects the current message-search backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageSearchRuntimeBackend {
    Direct(DoveadmMessageSearchBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageSearchBackend),
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
        }
    }
}

/// Selects the current message-move backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageMoveRuntimeBackend {
    Direct(DoveadmMessageMoveBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageMoveBackend),
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
        }
    }
}

/// Selects the current message-view backend without widening the browser
/// runtime's authority when a local helper is configured.
pub(super) enum MessageViewRuntimeBackend {
    Direct(DoveadmMessageViewBackend<SystemCommandExecutor>),
    Helper(MailboxHelperMessageViewBackend),
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
