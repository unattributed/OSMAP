//! One explicitly permitted stored tuple, never a mailbox-wide expunge.
//! Browser confirmation and saved-Bin ownership are additional route guards;
//! they cannot create the helper's separate retention permission.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::mailbox_json::parse_json_summaries;
use super::mailbox_retention::{valid_account, FileMailboxRetentionPolicy, RetentionDecision};
use super::{MessageListPolicy, MessageSummary};
use crate::auth::CommandExecutor;
use crate::message_metadata::MessageVersion;

pub const DELETE_OPERATION_TIMEOUT_SECS: u64 = 3;
pub const DELETE_STATE_OUTPUT_MAX_BYTES: usize = 64 * 1024;
const FIELDS: &str = "uid flags date.received size.virtual mailbox mailbox-guid guid";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDeleteError {
    Invalid,
    Stale,
    PolicyDenied,
    PolicyUnavailable,
    Busy,
    /// Refused before the mutation was dispatched.
    Unavailable,
    /// The mutation was dispatched; completion could not be confirmed.
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDeleteResult {
    Deleted,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeleteRequest {
    pub canonical_username: String,
    pub mailbox_name: String,
    pub uid: u64,
    pub version: MessageVersion,
    pub policy_revision: u64,
}
impl MessageDeleteRequest {
    pub fn new(
        account: impl Into<String>,
        mailbox: impl Into<String>,
        uid: u64,
        version: MessageVersion,
        policy_revision: u64,
    ) -> Result<Self, MessageDeleteError> {
        let canonical_username = account.into();
        let mailbox_name = mailbox.into();
        if !valid_account(&canonical_username)
            || crate::bin_folder::parse_mailbox_name(&mailbox_name).is_err()
            || uid == 0
            || uid > u64::from(u32::MAX)
            || policy_revision == 0
        {
            return Err(MessageDeleteError::Invalid);
        }
        let version = MessageVersion::new(version.mailbox_guid, version.message_guid)
            .map_err(|_| MessageDeleteError::Invalid)?;
        Ok(Self {
            canonical_username,
            mailbox_name,
            uid,
            version,
            policy_revision,
        })
    }
}

pub trait MessageDeleteBackend {
    /// Helper-owned authority, never inferred from the browser's Bin preference.
    fn retention_status(&self, _account: &str, _mailbox: &str) -> RetentionDecision {
        RetentionDecision::Unavailable
    }

    fn delete_message(
        &self,
        authenticated_account: &str,
        request: &MessageDeleteRequest,
    ) -> Result<MessageDeleteResult, MessageDeleteError>;
}

#[derive(Debug, Clone)]
pub struct DoveadmMessageDeleteBackend<E> {
    executor: E,
    doveadm_path: PathBuf,
    userdb_socket_path: Option<PathBuf>,
    authority: FileMailboxRetentionPolicy,
    command_timeout_secs: u64,
    operation_gate: Arc<Mutex<()>>,
}
impl<E> DoveadmMessageDeleteBackend<E> {
    pub fn new(
        executor: E,
        path: impl Into<PathBuf>,
        authority: FileMailboxRetentionPolicy,
    ) -> Self {
        Self {
            executor,
            doveadm_path: path.into(),
            userdb_socket_path: None,
            authority,
            command_timeout_secs: DELETE_OPERATION_TIMEOUT_SECS,
            operation_gate: Arc::new(Mutex::new(())),
        }
    }
    pub fn with_userdb_socket_path(mut self, path: Option<PathBuf>) -> Self {
        self.userdb_socket_path = path;
        self
    }
    pub fn with_command_timeout_secs(mut self, seconds: u64) -> Self {
        self.command_timeout_secs = seconds.clamp(1, DELETE_OPERATION_TIMEOUT_SECS);
        self
    }
    /// Helper construction must share this gate with its move/flag backends.
    pub fn with_operation_gate(mut self, gate: Arc<Mutex<()>>) -> Self {
        self.operation_gate = gate;
        self
    }
    pub fn retention_status(&self, account: &str, mailbox: &str) -> RetentionDecision {
        self.authority.decision(
            account,
            mailbox,
            Instant::now() + Duration::from_secs(self.command_timeout_secs),
        )
    }
    fn base_args(&self) -> Vec<String> {
        let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
        if let Some(path) = &self.userdb_socket_path {
            args.extend(["-o".into(), format!("auth_socket_path={}", path.display())]);
        }
        args
    }
    fn identity_args(request: &MessageDeleteRequest) -> Vec<String> {
        // Mailbox names may contain wildcard characters in Dovecot search.
        // The conjoined mailbox GUID is mandatory; the name alone is never
        // an identity selector, and no OR/ALL/Deleted search is constructed.
        vec![
            "mailbox".into(),
            request.mailbox_name.clone(),
            "mailbox-guid".into(),
            request.version.mailbox_guid.clone(),
            "uid".into(),
            request.uid.to_string(),
            "guid".into(),
            request.version.message_guid.clone(),
        ]
    }
    fn check_policy(
        &self,
        request: &MessageDeleteRequest,
        deadline: Instant,
    ) -> Result<(), MessageDeleteError> {
        match self
            .authority
            .decision(&request.canonical_username, &request.mailbox_name, deadline)
        {
            RetentionDecision::Allowed { revision } if revision == request.policy_revision => {
                Ok(())
            }
            RetentionDecision::Allowed { .. } => Err(MessageDeleteError::Stale),
            RetentionDecision::Denied => Err(MessageDeleteError::PolicyDenied),
            RetentionDecision::Unavailable => Err(MessageDeleteError::PolicyUnavailable),
        }
    }
}
impl<E: CommandExecutor> DoveadmMessageDeleteBackend<E> {
    fn read_state(
        &self,
        request: &MessageDeleteRequest,
        deadline: Instant,
    ) -> Result<Option<MessageSummary>, MessageDeleteError> {
        let mut args = self.base_args();
        args.extend([
            "-f".into(),
            "json".into(),
            "fetch".into(),
            "-u".into(),
            request.canonical_username.clone(),
            FIELDS.into(),
        ]);
        args.extend(Self::identity_args(request));
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(MessageDeleteError::Unavailable)?;
        let execution = self
            .executor
            .run_with_stdin_bytes_timeout_and_output_limit(
                self.doveadm_path.to_string_lossy().as_ref(),
                &args,
                b"",
                remaining,
                DELETE_STATE_OUTPUT_MAX_BYTES,
            )
            .map_err(|_| MessageDeleteError::Unavailable)?;
        if Instant::now() >= deadline
            || execution.stdout.len() > DELETE_STATE_OUTPUT_MAX_BYTES
            || execution.stderr.len() > DELETE_STATE_OUTPUT_MAX_BYTES
        {
            return Err(MessageDeleteError::Unavailable);
        }
        let mut rows = parse_json_summaries(
            MessageListPolicy {
                max_messages: 1,
                ..MessageListPolicy::default()
            },
            &execution,
        )
        .map_err(|_| MessageDeleteError::Unavailable)?;
        let row = rows.pop();
        if row.as_ref().is_some_and(|row| {
            row.mailbox_name != request.mailbox_name
                || row.uid != request.uid
                || row.metadata.as_ref().map(|m| &m.version) != Some(&request.version)
        }) {
            return Err(MessageDeleteError::Stale);
        }
        Ok(row)
    }
}
impl<E: CommandExecutor> MessageDeleteBackend for DoveadmMessageDeleteBackend<E> {
    fn retention_status(&self, account: &str, mailbox: &str) -> RetentionDecision {
        DoveadmMessageDeleteBackend::retention_status(self, account, mailbox)
    }

    fn delete_message(
        &self,
        authenticated_account: &str,
        request: &MessageDeleteRequest,
    ) -> Result<MessageDeleteResult, MessageDeleteError> {
        let deadline = Instant::now() + Duration::from_secs(self.command_timeout_secs);
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| MessageDeleteError::Busy)?;
        let request = MessageDeleteRequest::new(
            request.canonical_username.clone(),
            request.mailbox_name.clone(),
            request.uid,
            request.version.clone(),
            request.policy_revision,
        )?;
        if !valid_account(authenticated_account)
            || authenticated_account != request.canonical_username
        {
            return Err(MessageDeleteError::Invalid);
        }
        self.check_policy(&request, deadline)?;
        if self.read_state(&request, deadline)?.is_none() {
            return Err(MessageDeleteError::Stale);
        }
        // A trusted policy change while fetching current state must refuse
        // before expunge. Confirmation/revision from the browser is no permit.
        self.check_policy(&request, deadline)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(MessageDeleteError::Unavailable)?;
        let mut args = self.base_args();
        args.extend([
            "expunge".into(),
            "-u".into(),
            request.canonical_username.clone(),
        ]);
        args.extend(Self::identity_args(&request));
        let execution = self.executor.run_with_stdin_bytes_timeout_and_output_limit(
            self.doveadm_path.to_string_lossy().as_ref(),
            &args,
            b"",
            remaining,
            DELETE_STATE_OUTPUT_MAX_BYTES,
        );
        // Never retry after dispatch; command diagnostics may contain private
        // content and are not propagated through the typed public error.
        if !matches!(execution, Ok(ref output) if output.status_code == 0
            && output.stdout.len() <= DELETE_STATE_OUTPUT_MAX_BYTES
            && output.stderr.len() <= DELETE_STATE_OUTPUT_MAX_BYTES)
            || Instant::now() >= deadline
        {
            return Err(MessageDeleteError::Unknown);
        }
        match self.read_state(&request, deadline) {
            Ok(None) => Ok(MessageDeleteResult::Deleted),
            _ => Err(MessageDeleteError::Unknown),
        }
    }
}

#[cfg(test)]
#[path = "mailbox_delete_tests.rs"]
mod tests;
