use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::auth::{CommandExecutor, SystemCommandExecutor, DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS};

use super::mailbox_json::{
    parse_json_batch_guids, parse_json_search, parse_json_search_batch,
    parse_json_search_batch_with_guids, parse_json_summaries, parse_json_view, SUMMARY_FIELDS,
    VIEW_FIELDS,
};

use super::{
    concise_command_diagnostics, parse_doveadm_mailbox_list_output, MailboxBackend,
    MailboxBackendError, MailboxEntry, MailboxListingPolicy, MessageAppendBackend,
    MessageAppendRequest, MessageListBackend, MessageListPolicy, MessageListRequest,
    MessageSearchBackend, MessageSearchBatchRequest, MessageSearchPolicy, MessageSearchRequest,
    MessageSearchResult, MessageSummary, MessageView, MessageViewBackend, MessageViewPolicy,
    MessageViewRequest,
};

/// Lists mailboxes through `doveadm mailbox list`.
#[derive(Debug, Clone)]
pub struct DoveadmMailboxListBackend<E> {
    policy: MailboxListingPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
    command_timeout_secs: u64,
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
            command_timeout_secs: DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS,
        }
    }
    pub fn with_command_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.command_timeout_secs = timeout_secs.max(1);
        self
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
    fn rename_folder(
        &self,
        request: &crate::folder_rename::RenameFolderRequest,
    ) -> crate::folder_rename::Outcome {
        crate::folder_rename_backend::rename(
            &self.command_executor,
            &self.doveadm_path,
            self.userdb_socket_path.as_deref(),
            request,
        )
    }
    fn create_folder(
        &self,
        request: &crate::folder_create::CreateFolderRequest,
    ) -> crate::folder_create::Outcome {
        crate::folder_create_backend::create(
            &self.command_executor,
            &self.doveadm_path,
            self.userdb_socket_path.as_deref(),
            request,
        )
    }
    fn folder_metadata(
        &self,
        account: &str,
    ) -> Result<crate::folder_metadata::FolderSnapshot, MailboxBackendError> {
        crate::folder_metadata_backend::read(
            &self.command_executor,
            &self.doveadm_path,
            self.userdb_socket_path.as_deref(),
            account,
        )
    }
    fn mailbox_status(
        &self,
        canonical_username: &str,
        mailbox: &str,
    ) -> Result<crate::mailbox_status::MailboxStatus, MailboxBackendError> {
        crate::mailbox_status::validate_account(canonical_username)?;
        crate::mailbox_status::validate_name(mailbox)?;
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".into(),
            "json".into(),
            "mailbox".into(),
            "status".into(),
            "-u".into(),
            canonical_username.into(),
            "guid messages vsize".into(),
            mailbox.into(),
        ]);
        let execution = self
            .command_executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                b"",
                Duration::from_secs(DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS),
                4096,
            )
            .map_err(|_| crate::mailbox_status::unavailable())?;
        crate::mailbox_status::parse_native(mailbox, &execution)
    }
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
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                Duration::from_secs(self.command_timeout_secs),
            )
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-mailbox-list",
                reason: error.reason,
            })?;

        parse_doveadm_mailbox_list_output(self.policy, &execution)
    }
}

/// Lists message summaries through `doveadm fetch`.
#[derive(Debug, Clone)]
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
            "json".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            SUMMARY_FIELDS.to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "all".to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                Duration::from_secs(DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS),
            )
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-list",
                reason: error.reason,
            })?;

        let messages = parse_json_summaries(self.policy, &execution)?;
        if messages
            .iter()
            .any(|message| message.mailbox_name != request.mailbox_name)
        {
            return Err(MailboxBackendError {
                backend: "message-json-parser",
                reason: "native list returned a different mailbox".into(),
            });
        }
        Ok(messages)
    }
}

/// Retrieves a bounded single-message payload through `doveadm fetch`.
#[derive(Debug, Clone)]
pub struct DoveadmMessageViewBackend<E> {
    policy: MessageViewPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
    command_timeout_secs: u64,
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
            command_timeout_secs: DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS,
        }
    }

    /// Points message-view lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }

    /// Caps the external `doveadm fetch` execution used for one message view.
    pub fn with_command_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.command_timeout_secs = timeout_secs.max(1);
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
            "json".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            VIEW_FIELDS.to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            "uid".to_string(),
            request.uid.to_string(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                Duration::from_secs(self.command_timeout_secs),
            )
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-view",
                reason: error.reason,
            })?;

        let message = parse_json_view(self.policy, &execution)?;
        if message.mailbox_name != request.mailbox_name || message.uid != request.uid {
            return Err(MailboxBackendError {
                backend: "message-json-parser",
                reason: "native view returned a different message".into(),
            });
        }
        Ok(message)
    }
}

/// Searches message summaries through `doveadm fetch` using a mailbox-scoped
/// whitelisted Dovecot search term.
#[derive(Debug, Clone)]
pub struct DoveadmMessageSearchBackend<E> {
    policy: MessageSearchPolicy,
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
    command_timeout_secs: u64,
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
            command_timeout_secs: DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS,
        }
    }

    /// Points message-search lookups at an explicit Dovecot userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }

    /// Caps each mailbox-scoped external search command.
    pub fn with_command_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.command_timeout_secs = timeout_secs.max(1);
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
    fn search_messages_batch(
        &self,
        canonical_username: &str,
        request: &MessageSearchBatchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        request.validate(self.policy)?;
        crate::mailbox_status::validate_account(canonical_username)?;
        // Discovery and fetch share the caller's remaining budget. Native helpers
        // never extend the browser's five-second all-scope search boundary.
        let deadline = Instant::now() + Duration::from_secs(self.command_timeout_secs.min(5));
        let remaining = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| MailboxBackendError {
                    backend: "doveadm-message-search",
                    reason: "native batch search deadline expired".into(),
                })
        };
        let expected_guids = if request
            .mailbox_names
            .iter()
            .any(|name| name.contains(['*', '%', '?', '[', ']', '\\']))
        {
            let mut discovery = vec!["-o".into(), "stats_writer_socket_path=".into()];
            append_doveadm_auth_socket_override(&mut discovery, self.userdb_socket_path.as_ref());
            discovery.extend([
                "-f".into(),
                "json".into(),
                "mailbox".into(),
                "status".into(),
                "-u".into(),
                canonical_username.into(),
                "guid".into(),
                "*".into(),
            ]);
            let execution = self
                .command_executor
                .run_with_stdin_timeout(
                    self.doveadm_path.to_string_lossy().as_ref(),
                    &discovery,
                    "",
                    remaining()?,
                )
                .map_err(|error| MailboxBackendError {
                    backend: "doveadm-message-search",
                    reason: error.reason,
                })?;
            Some(parse_json_batch_guids(self.policy, request, &execution)?)
        } else {
            None
        };
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "-u".into(),
            canonical_username.into(),
            SUMMARY_FIELDS.into(),
            "(".into(),
        ]);
        for (index, name) in request.mailbox_names.iter().enumerate() {
            if index > 0 {
                args.push("OR".into());
            }
            args.extend(match &expected_guids {
                Some(guids) => [
                    "mailbox-guid".into(),
                    guids
                        .get(name)
                        .cloned()
                        .ok_or_else(|| MailboxBackendError {
                            backend: "message-json-parser",
                            reason: "resolved native GUID scope is incomplete".into(),
                        })?,
                ],
                None => ["mailbox".into(), name.clone()],
            });
        }
        args.extend([
            ")".into(),
            request.field.doveadm_search_key().into(),
            request.query.clone(),
        ]);
        let execution = self
            .command_executor
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                remaining()?,
            )
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-search",
                reason: error.reason,
            })?;
        let results = match expected_guids.as_ref() {
            Some(guids) => {
                parse_json_search_batch_with_guids(self.policy, request, &execution, Some(guids))
            }
            None => parse_json_search_batch(self.policy, request, &execution),
        }?;
        remaining()?;
        Ok(results)
    }
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
            "json".to_string(),
            "fetch".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            SUMMARY_FIELDS.to_string(),
            "mailbox".to_string(),
            request.mailbox_name.clone(),
            request.field.doveadm_search_key().to_string(),
            request.query.clone(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                "",
                Duration::from_secs(self.command_timeout_secs),
            )
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-search",
                reason: error.reason,
            })?;

        let results = parse_json_search(self.policy, &execution)?;
        if results
            .iter()
            .any(|message| message.mailbox_name != request.mailbox_name)
        {
            return Err(MailboxBackendError {
                backend: "message-json-parser",
                reason: "native search returned a different mailbox".into(),
            });
        }
        Ok(results)
    }
}

/// Appends one complete message through `doveadm save`.
#[derive(Debug, Clone)]
pub struct DoveadmMessageAppendBackend<E> {
    command_executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
    command_timeout_secs: u64,
    operation_gate: std::sync::Arc<std::sync::Mutex<()>>,
}

impl<E> DoveadmMessageAppendBackend<E> {
    /// Builds a backend using the supplied command executor and doveadm path.
    pub fn new(command_executor: E, doveadm_path: impl Into<PathBuf>) -> Self {
        Self {
            command_executor,
            doveadm_path: doveadm_path.into(),
            userdb_socket_path: None,
            command_timeout_secs: DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS,
            operation_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
        }
    }

    /// Points message append operations at an explicit userdb-capable socket.
    pub fn with_userdb_socket_path(mut self, userdb_socket_path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = userdb_socket_path;
        self
    }

    pub fn with_operation_gate(mut self, gate: std::sync::Arc<std::sync::Mutex<()>>) -> Self {
        self.operation_gate = gate;
        self
    }

    /// Caps the external doveadm save execution.
    pub fn with_command_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.command_timeout_secs = timeout_secs.max(1);
        self
    }
}

impl Default for DoveadmMessageAppendBackend<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, "/usr/local/bin/doveadm")
    }
}

impl<E> MessageAppendBackend for DoveadmMessageAppendBackend<E>
where
    E: CommandExecutor,
{
    fn append_message(
        &self,
        canonical_username: &str,
        request: &MessageAppendRequest,
    ) -> Result<(), MailboxBackendError> {
        if request.destination_mailbox_guid.is_some() {
            return self.append_bound(canonical_username, request);
        }
        let mut args = vec!["-o".to_string(), "stats_writer_socket_path=".to_string()];
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "save".to_string(),
            "-u".to_string(),
            canonical_username.to_string(),
            "-m".to_string(),
            request.mailbox_name.clone(),
        ]);

        let execution = self
            .command_executor
            .run_with_stdin_bytes_timeout(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                &request.message,
                Duration::from_secs(self.command_timeout_secs),
            )
            .map_err(|error| MailboxBackendError {
                backend: "doveadm-message-append",
                reason: error.reason,
            })?;

        if execution.status_code != 0 {
            return Err(MailboxBackendError {
                backend: "doveadm-message-append",
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

impl<E: CommandExecutor> DoveadmMessageAppendBackend<E> {
    fn append_bound(
        &self,
        account: &str,
        request: &MessageAppendRequest,
    ) -> Result<(), MailboxBackendError> {
        let unavailable = || MailboxBackendError {
            backend: "sent-location-append",
            reason: "captured copy destination could not be confirmed".into(),
        };
        crate::identity::CanonicalUsername::parse(account).map_err(|_| unavailable())?;
        crate::mailbox_status::validate_account(account)?;
        let guid = request
            .destination_mailbox_guid
            .as_deref()
            .ok_or_else(unavailable)?;
        let validated = MessageAppendRequest::new(&request.mailbox_name, request.message.clone())?
            .with_destination_mailbox_guid(guid)?;
        if &validated != request {
            return Err(unavailable());
        }
        let deadline = Instant::now()
            + Duration::from_secs(
                self.command_timeout_secs
                    .clamp(1, DEFAULT_EXTERNAL_COMMAND_TIMEOUT_SECS),
            );
        let _gate = self.operation_gate.try_lock().map_err(|_| unavailable())?;
        let snapshot = crate::folder_metadata_backend::read_before(
            &self.command_executor,
            &self.doveadm_path,
            self.userdb_socket_path.as_deref(),
            account,
            deadline,
        )?;
        if !crate::sent_location::selectable(&snapshot, account, &request.mailbox_name) {
            return Err(unavailable());
        }
        self.bound_status(account, &request.mailbox_name, guid, deadline)?;
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "save".into(),
            "-u".into(),
            account.into(),
            "-m".into(),
            request.mailbox_name.clone(),
        ]);
        let execution = self
            .command_executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                &self.doveadm_path.to_string_lossy(),
                &args,
                &request.message,
                deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(unavailable)?,
                1024 * 1024,
            )
            .map_err(|_| unavailable())?;
        if execution.status_code != 0
            || Instant::now() >= deadline
            || execution.stdout.len() > 1024 * 1024
            || execution.stderr.len() > 1024 * 1024
        {
            return Err(unavailable());
        }
        // The CLI addresses a name, not a mailbox GUID. Concurrent external IMAP
        // replacement between the final check and save is not atomic. A failed
        // post-check means unconfirmed copy, never a retry or a storage claim.
        self.bound_status(account, &request.mailbox_name, guid, deadline)
    }
    fn bound_status(
        &self,
        account: &str,
        name: &str,
        guid: &str,
        deadline: Instant,
    ) -> Result<(), MailboxBackendError> {
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        append_doveadm_auth_socket_override(&mut args, self.userdb_socket_path.as_ref());
        args.extend([
            "-f".into(),
            "json".into(),
            "mailbox".into(),
            "status".into(),
            "-u".into(),
            account.into(),
            "guid messages vsize".into(),
            name.into(),
        ]);
        let execution = self
            .command_executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                &self.doveadm_path.to_string_lossy(),
                &args,
                b"",
                deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or_else(crate::mailbox_status::unavailable)?,
                4096,
            )
            .map_err(|_| crate::mailbox_status::unavailable())?;
        if execution.stdout.len() > 4096 || execution.stderr.len() > 4096 {
            return Err(crate::mailbox_status::unavailable());
        }
        let status = crate::mailbox_status::parse_native(name, &execution)?;
        if Instant::now() >= deadline || status.guid() != guid {
            return Err(crate::mailbox_status::unavailable());
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

#[cfg(test)]
mod batch_tests {
    use super::*;
    use crate::auth::{CommandExecution, CommandExecutionError};
    use crate::mailbox::MessageSearchField;
    use std::sync::{Arc, Mutex};
    type RecordedGuidCalls = Arc<Mutex<Vec<(Vec<String>, Duration)>>>;
    #[derive(Clone)]
    struct GuidExecutor {
        calls: RecordedGuidCalls,
        delay: Duration,
    }
    impl CommandExecutor for GuidExecutor {
        fn run_with_stdin_bytes(
            &self,
            _: &str,
            _: &[String],
            _: &[u8],
        ) -> Result<CommandExecution, CommandExecutionError> {
            panic!("batch must use bounded native execution")
        }
        fn run_with_stdin_bytes_timeout(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
            timeout: Duration,
        ) -> Result<CommandExecution, CommandExecutionError> {
            assert_eq!(program, "/fixture/doveadm");
            assert!(input.is_empty());
            self.calls.lock().unwrap().push((args.to_vec(), timeout));
            let stdout = if args.iter().any(|arg| arg == "status") {
                std::thread::sleep(self.delay);
                r#"[{"mailbox":"INBOX.literal*folder","guid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#
            } else {
                "[]"
            };
            Ok(CommandExecution {
                status_code: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn batch_guid_resolution_and_fetch_share_one_deadline_and_literal_scope() {
        for (delay, succeeds) in [
            (Duration::from_millis(250), true),
            (Duration::from_millis(1100), false),
        ] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let backend = DoveadmMessageSearchBackend::new(
                MessageSearchPolicy::default(),
                GuidExecutor {
                    calls: calls.clone(),
                    delay,
                },
                "/fixture/doveadm",
            )
            .with_command_timeout_secs(1);
            let request = MessageSearchBatchRequest::new(
                MessageSearchPolicy::default(),
                vec!["INBOX.literal*folder".into()],
                "literal OR (subject)",
                MessageSearchField::Subject,
            )
            .unwrap();
            assert_eq!(
                backend
                    .search_messages_batch("alice@example.com", &request)
                    .is_ok(),
                succeeds
            );
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), if succeeds { 2 } else { 1 });
            assert!(calls[0].0.windows(2).any(|pair| pair == ["guid", "*"]));
            assert!(calls[0]
                .0
                .windows(2)
                .any(|pair| pair == ["-u", "alice@example.com"]));
            if succeeds {
                assert!(
                    calls[1].1 < calls[0].1.saturating_sub(Duration::from_millis(200)),
                    "GUID lookup time must reduce fetch's remaining timeout"
                );
                assert!(calls[1]
                    .0
                    .windows(2)
                    .any(|pair| pair == ["mailbox-guid", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]));
                assert!(!calls[1].0.iter().any(|arg| arg == "INBOX.literal*folder"));
                assert_eq!(calls[1].0.last().unwrap(), "literal OR (subject)");
            }
        }
    }
}

#[cfg(test)]
#[path = "mailbox_append_location_tests.rs"]
mod append_location_tests;
