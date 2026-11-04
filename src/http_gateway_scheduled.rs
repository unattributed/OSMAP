//! Account-owned scheduler mutations and one sequential, restart-safe worker pass.
use super::*;
use crate::logging::{EventCategory, Logger};
use crate::scheduled_send::{
    Error, JobList, Reauthorization, ScheduleInput, ScheduledStore, State,
};
use crate::totp::TimeProvider;
impl RuntimeBrowserGateway {
    pub(super) fn scheduled_store(&self) -> ScheduledStore {
        ScheduledStore::new(self.settings_dir.join("scheduled-send"))
    }
    fn schedule_epoch(session: &ValidatedSession) -> Result<u64, Error> {
        session
            .record
            .account_epoch
            .filter(|epoch| crate::account_admission::valid_epoch(*epoch))
            .ok_or(Error::Unavailable)
    }
    pub(super) fn scheduled_list_impl(&self, session: &ValidatedSession) -> Result<JobList, Error> {
        let now = SystemTimeProvider.unix_timestamp();
        let journal = self.send_journal();
        let guard = journal
            .account_guard(&session.record.canonical_username, now)
            .map_err(|_| Error::Unavailable)?;
        self.scheduled_store().list(&guard, now)
    }
    pub(super) fn scheduled_payload_impl(
        &self,
        session: &ValidatedSession,
        id: &str,
    ) -> Result<ComposeRequest, Error> {
        let now = SystemTimeProvider.unix_timestamp();
        let journal = self.send_journal();
        let guard = journal
            .account_guard(&session.record.canonical_username, now)
            .map_err(|_| Error::Unavailable)?;
        self.scheduled_store().read(&guard, id, now)
    }
    pub(super) fn scheduled_from_draft_impl(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        due: u64,
    ) -> Result<String, Error> {
        let now = SystemTimeProvider.unix_timestamp();
        let epoch = Self::schedule_epoch(session)?;
        let account = &session.record.canonical_username;
        let journal = self.send_journal();
        let mut guard = journal
            .account_guard(account, now)
            .map_err(|_| Error::Unavailable)?;
        let draft = self
            .build_draft_store()
            .load(account, id, now)
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::NotFound)?;
        if draft.revision != Some(revision) {
            return Err(Error::Stale);
        }
        // A saved forward may still refer to selected parts of another owned
        // message. Compose's Schedule action materializes those checked bytes
        // first. Direct links must never silently omit unresolved selections.
        if draft.source_attachments.is_some() {
            return Err(Error::Invalid);
        }
        let intent = guard.draft_intent(&draft).map_err(|_| Error::Stale)?;
        guard
            .require_unconsumed(&intent)
            .map_err(|_| Error::Stale)?;
        self.sender_authority
            .authorize(account, draft.request.sender_identity.sender())
            .map_err(|_| Error::Invalid)?;
        let store = self.scheduled_store();
        let list = store.list(&guard, now)?;
        let content = &draft.request;
        let mut request = ComposeRequest::new_with_routing(
            ComposePolicy::default(),
            &content.recipients_text,
            &content.cc_text,
            &content.bcc_text,
            &content.subject,
            &content.body,
            content.attachments.clone(),
        )
        .and_then(|value| value.with_body_format(content.body_format))
        .map_err(|_| Error::Invalid)?;
        request.sender_identity = content.sender_identity.clone();
        request.reply_thread = content.reply_thread.clone();
        request.protection = content.protection;
        let staged = store.create_staged(
            &guard,
            list.revision,
            ScheduleInput {
                due_at: due,
                account_epoch: epoch,
                private_session: Self::private_key_session(session),
                request: &request,
            },
            now,
        )?;
        // On any write error abort this guard. Never infer that a retirement
        // was rolled back merely because its confirmation was unavailable.
        guard
            .begin_schedule(&intent, &staged.id, &staged.digest)
            .map_err(|_| Error::Unconfirmed)?;
        store.publish_pending(&guard, staged.revision, &staged.id, &staged.digest, now)?;
        guard
            .finish_schedule(&intent, &staged.id, &staged.digest)
            .map_err(|_| Error::Unconfirmed)?;
        Ok(staged.id)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn scheduled_edit_impl(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        due: u64,
        to: &str,
        cc: &str,
        bcc: &str,
        subject: &str,
        body: &str,
    ) -> Result<JobList, Error> {
        let now = SystemTimeProvider.unix_timestamp();
        let epoch = Self::schedule_epoch(session)?;
        let account = &session.record.canonical_username;
        let journal = self.send_journal();
        let mut guard = journal
            .account_guard(account, now)
            .map_err(|_| Error::Unavailable)?;
        let store = self.scheduled_store();
        let list = store.list(&guard, now)?;
        if list.revision != revision {
            return Err(Error::Stale);
        }
        let job = list
            .jobs
            .iter()
            .find(|job| job.id == id)
            .ok_or(Error::NotFound)?;
        if !matches!(job.state, State::Pending | State::Blocked) {
            return Err(Error::Invalid);
        }
        let original = store.read(&guard, id, now)?;
        let mut request = ComposeRequest::new_with_routing(
            ComposePolicy::default(),
            to,
            cc,
            bcc,
            subject,
            body,
            original.attachments.clone(),
        )
        .and_then(|value| value.with_body_format(original.body_format))
        .map_err(|_| Error::Invalid)?;
        request.sender_identity = original.sender_identity;
        request.reply_thread = original.reply_thread;
        request.protection = original.protection;
        self.sender_authority
            .authorize(account, request.sender_identity.sender())
            .map_err(|_| Error::Invalid)?;
        let source_intent = guard
            .require_schedule_binding(id, &job.digest)
            .map_err(|_| Error::Invalid)?
            .to_owned();
        let staged = store.replace_staged(
            &guard,
            revision,
            id,
            ScheduleInput {
                due_at: due,
                account_epoch: epoch,
                private_session: Self::private_key_session(session),
                request: &request,
            },
            now,
        )?;
        guard
            .replace_schedule_binding(id, &job.digest, &staged.digest)
            .map_err(|_| Error::Unconfirmed)?;
        let result = store.publish_pending(&guard, staged.revision, id, &staged.digest, now)?;
        guard
            .finish_schedule(&source_intent, id, &staged.digest)
            .map_err(|_| Error::Unconfirmed)?;
        Ok(result)
    }
    pub(super) fn scheduled_change_impl(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        action: &str,
        due: Option<u64>,
    ) -> Result<JobList, Error> {
        let now = SystemTimeProvider.unix_timestamp();
        let journal = self.send_journal();
        let guard = journal
            .account_guard(&session.record.canonical_username, now)
            .map_err(|_| Error::Unavailable)?;
        let store = self.scheduled_store();
        match (action, due) {
            ("cancel", None) => store.cancel(&guard, revision, id, now),
            ("reauthorize", Some(due_at)) => store.reauthorize(
                &guard,
                revision,
                id,
                Reauthorization {
                    due_at,
                    account_epoch: Self::schedule_epoch(session)?,
                    private_session: Self::private_key_session(session),
                },
                now,
            ),
            _ => Err(Error::Invalid),
        }
    }
    pub(crate) fn run_scheduled_once(&self, logger: &Logger) -> Result<usize, Error> {
        let result = crate::scheduled_worker::run_once(
            &self.settings_dir,
            || SystemTimeProvider.unix_timestamp(),
            |claim| {
                let outcome = self.dispatch_scheduled(claim);
                for event in outcome.audit_events {
                    logger.emit(&event);
                }
                match outcome.decision {
                    super::http_gateway_scheduled_send::ScheduledDispatch::Submitted => {
                        crate::scheduled_worker::DispatchDecision::Submitted
                    }
                    super::http_gateway_scheduled_send::ScheduledDispatch::Blocked(reason) => {
                        crate::scheduled_worker::DispatchDecision::Blocked(reason)
                    }
                    super::http_gateway_scheduled_send::ScheduledDispatch::Unknown => {
                        crate::scheduled_worker::DispatchDecision::Unknown
                    }
                }
            },
        )?;
        if result.accounts_unavailable > 0 {
            logger.emit(&LogEvent::new(LogLevel::Warn, EventCategory::Submission,
                "scheduled_accounts_unavailable", "scheduled account state could not be confirmed; uncertain submissions were not retried")
                .with_field("account_count", result.accounts_unavailable.to_string()));
        }
        Ok(result.accounts_checked)
    }
}

#[cfg(test)]
#[path = "http_gateway_scheduled_tests.rs"]
mod tests;
