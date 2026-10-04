//! Narrow guarded action validation; existing browser session APIs are unchanged.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardedSessionError {
    Unavailable,
    Inactive,
}

impl FileSessionStore {
    pub(super) fn guarded_lock(&self) -> Result<SessionFileLock, GuardedSessionError> {
        let unavailable = |_| GuardedSessionError::Unavailable;
        crate::private_account_file::check_directory(&self.session_dir).map_err(unavailable)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(not(unix))]
        return Err(GuardedSessionError::Unavailable);
        let file = options.open(self.lock_path()).map_err(unavailable)?;
        let metadata = file.metadata().map_err(unavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_file()
                || metadata.len() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.uid() != crate::openbsd::effective_uid()
            {
                return Err(GuardedSessionError::Unavailable);
            }
            // Finite lock admission: contention refuses immediately, never queues.
            crate::openbsd::try_advisory_file_lock_exclusive(&file).map_err(unavailable)?;
        }
        Ok(SessionFileLock { file })
    }
    fn with_guarded_record<O>(
        &self,
        id: &str,
        callback: impl FnOnce(SessionRecord) -> Result<O, GuardedSessionError>,
    ) -> Result<O, GuardedSessionError> {
        let unavailable = |_| GuardedSessionError::Unavailable;
        crate::private_account_file::check_directory(&self.session_dir).map_err(unavailable)?;
        if id.len() != SESSION_ID_HEX_LEN || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GuardedSessionError::Inactive);
        }
        let _guard = self.guarded_lock()?;
        let bytes = crate::private_account_file::read_record(&self.session_path(id), 4096)
            .map_err(unavailable)?
            .ok_or(GuardedSessionError::Inactive)?;
        let content = std::str::from_utf8(&bytes).map_err(|_| GuardedSessionError::Unavailable)?;
        let mut keys = std::collections::BTreeSet::new();
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            let (key, _) = line
                .split_once('=')
                .ok_or(GuardedSessionError::Unavailable)?;
            if !keys.insert(key) {
                return Err(GuardedSessionError::Unavailable);
            }
        }
        let record = parse_session_record(content)
            .map_err(|_| GuardedSessionError::Unavailable)?
            .ok_or(GuardedSessionError::Inactive)?;
        if record.session_id != id {
            return Err(GuardedSessionError::Inactive);
        }
        callback(record)
    }
}
impl<T: TimeProvider, R: RandomSource> SessionService<FileSessionStore, T, R> {
    /// Runs a trusted action callback while holding the actual owned session lock.
    /// The callback must dispatch its RPC here, not retain unlocked authorization.
    /// It must not call ordinary SessionStore/SessionService operations, which
    /// reacquire this same lock. Browser-record cleanup belongs after callback
    /// release or in a separately reviewed already-held-lock implementation.
    /// This read-only action check preserves bytes on every refusal and success.
    pub fn with_guarded_validated_session<O>(
        &self,
        context: &AuthenticationContext,
        token: &SessionToken,
        callback: impl FnOnce(ValidatedSession) -> O,
    ) -> Result<O, GuardedSessionError> {
        let id = session_id_from_token(token.as_str());
        self.session_store.with_guarded_record(&id, |record| {
            let began = self.time_provider.unix_timestamp();
            self.action_current(&record, began)?;
            self.check_epoch(&record.canonical_username, record.account_epoch)
                .map_err(|_| GuardedSessionError::Unavailable)?;
            let now = self.time_provider.unix_timestamp();
            if now < began {
                return Err(GuardedSessionError::Inactive);
            }
            self.action_current(&record, now)?;
            let audit_event = LogEvent::new(
                crate::config::LogLevel::Info,
                EventCategory::Session,
                "session_action_revalidated",
                "browser session action revalidated",
            )
            .with_field("session_ref", audit_session_ref(&record.session_id))
            .with_field("request_id", context.request_id.clone());
            Ok(callback(ValidatedSession {
                record,
                audit_event,
            }))
        })
    }
    fn action_current(&self, record: &SessionRecord, now: u64) -> Result<(), GuardedSessionError> {
        if now == 0
            || record.issued_at == 0
            || record.expires_at <= record.issued_at
            || record.last_seen_at < record.issued_at
            || record.last_seen_at >= record.expires_at
            || now < record.last_seen_at
            || now < record.issued_at
            || now >= record.expires_at
            || now - record.last_seen_at >= self.idle_timeout_seconds
            || record.revoked_at.is_some()
        {
            return Err(GuardedSessionError::Inactive);
        }
        Ok(())
    }
    /// Final temporal check after bounded authority work, before the trusted
    /// callback dispatches within the same held session lock.
    pub(crate) fn recheck_guarded_session(
        &self,
        session: &ValidatedSession,
    ) -> Result<(), GuardedSessionError> {
        self.action_current(&session.record, self.time_provider.unix_timestamp())
    }
}
