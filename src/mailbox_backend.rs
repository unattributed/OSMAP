use std::path::PathBuf;

use crate::auth::{CommandExecutor, SystemCommandExecutor};

use super::{
    concise_command_diagnostics, parse_doveadm_mailbox_list_output,
    parse_doveadm_message_list_output, parse_doveadm_message_search_output,
    parse_doveadm_message_view_output, MailboxBackend, MailboxBackendError, MailboxEntry,
    MailboxListingPolicy, MessageListBackend, MessageListPolicy, MessageListRequest,
    MessageMoveBackend, MessageMoveRequest, MessageSearchBackend, MessageSearchPolicy,
    MessageSearchRequest, MessageSearchResult, MessageSummary, MessageView, MessageViewBackend,
    MessageViewPolicy, MessageViewRequest,
};

/// Lists mailboxes through `doveadm mailbox list`.
pub struct DoveadmMailboxListBackend<E> {
    policy: MailboxListingPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMailboxListBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MailboxListingPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points mailbox lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMailboxListBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MailboxListingPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MailboxBackend for DoveadmMailboxListBackend<E>
where
    E: CommandExecutor,
{
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "mailbox".to_string(),
            "list".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-mailbox-list",
                reason: error.reason,
            })?;

        parse_doveadm_mailbox_list_output(self.policy, &execution)
    }
}

/// Lists message summaries through `doveadm fetch`.
pub struct DoveadmMessageListBackend<E> {
    policy: MessageListPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageListBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MessageListPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-list lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageListBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MessageListPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MessageListBackend for DoveadmMessageListBackend<E>
where
    E: CommandExecutor,
{
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".to_string(),
            "flow".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "uid flags date.received size.virtual mailbox hdr.subject hdr.from".to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "all".to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-list",
                reason: error.reason,
            })?;

        parse_doveadm_message_list_output(self.policy, &execution)
    }
}

/// Retrieves a bounded single-message payload through `doveadm fetch`.
pub struct DoveadmMessageViewBackend<E> {
    policy: MessageViewPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageViewBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MessageViewPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-view lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageViewBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MessageViewPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MessageViewBackend for DoveadmMessageViewBackend<E>
where
    E: CommandExecutor,
{
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".to_string(),
            "flow".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "uid flags date.received size.virtual mailbox hdr body".to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "uid".to_string(),
            request.uid.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-view",
                reason: error.reason,
            })?;

        parse_doveadm_message_view_output(self.policy, &execution)
    }
}

/// Searches message summaries through `doveadm fetch` using a mailbox-scoped
/// Dovecot `TEXT` search term.
pub struct DoveadmMessageSearchBackend<E> {
    policy: MessageSearchPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageSearchBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(
        policy: MessageSearchPolicy,
        command_executor: E,
        doveadm_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-search lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageSearchBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(
            MessageSearchPolicy::default(),
            SystemCommandExecutor,
            "/usr/local/bin/doveadm",
        )
    }
}

impl<E> MessageSearchBackend for DoveadmMessageSearchBackend<E>
where
    E: CommandExecutor,
{
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".to_string(),
            "flow".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "uid flags date.received size.virtual mailbox hdr.subject hdr.from".to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "TEXT".to_string(),
            request.query.clone(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-search",
                reason: error.reason,
            })?;

        parse_doveadm_message_search_output(self.policy, &execution)
    }
}

/// Moves one message through `doveadm move`.
pub struct DoveadmMessageMoveBackend<E> {
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
}

impl<E> DoveadmMessageMoveBackend<E> {
    /// Builds a backend using the supplied command executor and `doveadm` path.
    pub fn new(command_executor: E, doveadm_path: impl Into<PathBuf>) -> Self {
        Self {
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
        }
    }

    /// Points message-move operations at an explicit Dovecot userdb-capable
    /// socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }
}

impl Default for DoveadmMessageMoveBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
    }
}

impl<E> MessageMoveBackend for DoveadmMessageMoveBackend<E>
where
    E: CommandExecutor,
{
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        let args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        let mut args = args;
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "move".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            request.destination_mailbox_name.clone(),
            "mailbox".to_string(),
            request.source_mailbox_name.clone(),
            "uid".to_string(),
            request.uid.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin(self.doveadm_path.to_string_lossy().as_ref(), &args, "")
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-move",
                reason: error.reason,
            })?;

        if execution.status_code != 0 {
            return Err(MailboxBackendError {
                backend: "doveadm-message-move",
                reason: format!(
                    "command exited with status {}: {}",
                    execution.status_code,
                    concise_command_diagnostics(&execution.stdout, &execution.stderr),
                ),
            });
        }

        Ok(())
    }
}

/// Adds an explicit Dovecot auth socket override for userdb-capable helper work
/// when the deployment provides one.
fn append_doveadm_auth_socket_override(args: &mut Vec<String>, auth_socket_path: Option<&PathBuf>) {
    if let Some(auth_socket_path) = auth_socket_path {
        args.push("-o".to_string());
        args.push(format!("auth_socket_path={}", auth_socket_path.display()));
    }
}
