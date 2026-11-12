//! Account-owned scheduler mutations and one sequential, restart-safe worker pass.
use super::*;
use crate::config::LogFormat;
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
        self.cleanup_confirmed_scheduled_source(&guard, &draft);
        Ok(staged.id)
    }
    /// Best-effort removal after durable capture. Failure must never turn a
    /// confirmed schedule into a retryable scheduling error.
    pub(super) fn cleanup_confirmed_scheduled_source(
        &self,
        guard: &crate::send_journal::AccountGuard,
        draft: &crate::draft::DraftRecord,
    ) {
        let cleanup = (|| {
            let (intent, attempt) = guard.draft_attempt(&draft.summary()).map_err(|_| ())?;
            if !matches!(
                attempt,
                Some(crate::send_journal::AttemptOutcome::Scheduled {
                    schedule_confirmed: true,
                    ..
                })
            ) || guard.draft_intent(draft).map_err(|_| ())? != intent
            {
                return Err(());
            }
            self.build_draft_store()
                .delete(
                    &draft.canonical_username,
                    &draft.draft_id,
                    draft.revision.ok_or(())?,
                )
                .map_err(|_| ())?;
            Ok(())
        })();
        if cleanup.is_err() {
            Logger::new(LogFormat::Text, LogLevel::Warn).emit(&LogEvent::new(
                LogLevel::Warn,
                EventCategory::Submission,
                "scheduled_source_cleanup_unconfirmed",
                "schedule confirmed; source draft cleanup unconfirmed; retained copy requires explicit discard",
            ));
        }
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
            ("cancel" | "delete", None) => store.cancel(&guard, revision, id, now),
            ("send_now", None) => store.reauthorize(
                &guard,
                revision,
                id,
                Reauthorization {
                    due_at: now.checked_add(1).ok_or(Error::Invalid)?,
                    account_epoch: Self::schedule_epoch(session)?,
                    private_session: Self::private_key_session(session),
                },
                now,
            ),
            ("move_to_drafts", None) => {
                let (list, request) = store.prepare_return_to_draft(&guard, revision, id, now)?;
                let account = &session.record.canonical_username;
                let policy = crate::send_recovery::SendRecovery::new(
                    self.settings_dir.join("send-recovery"),
                )
                .draft_policy(account, now)
                .map_err(|_| Error::Capacity)?;
                let location = crate::draft_location::Store::new(&self.settings_dir)
                    .load(account)
                    .map_err(|_| Error::Unavailable)?
                    .location;
                let drafts =
                    FileDraftStore::new(self.draft_dir.clone(), policy).with_new_location(location);
                // A deterministic destination makes interrupted transfers resumable.
                // Never overwrite an existing (possibly subsequently edited) draft.
                let existing = drafts
                    .load(account, id, now)
                    .map_err(|_| Error::Unavailable)?;
                if existing.is_none() {
                    let mut draft = crate::draft::DraftRecord::new(
                        DraftPolicy::default(),
                        crate::draft::DraftRecordInput {
                            draft_id: id.into(),
                            canonical_username: account.clone(),
                            now,
                            recipients_text: request.recipients.join(", "),
                            cc_text: request.cc_recipients.join(", "),
                            bcc_text: request.bcc_recipients.join(", "),
                            subject: request.subject.clone(),
                            body: request.body.clone(),
                            attachments: request.attachments.clone(),
                            source_attachments: None,
                        },
                    )
                    .map_err(|_| Error::Invalid)?;
                    draft.request.sender_identity = request.sender_identity.clone();
                    draft.request.body_format = request.body_format;
                    draft.request.reply_thread = request.reply_thread.clone();
                    draft.request.protection = request.protection;
                    drafts.save(&draft, now).map_err(|e| {
                        if e.save_unconfirmed() {
                            Error::Unconfirmed
                        } else {
                            Error::Capacity
                        }
                    })?;
                }
                let saved = drafts
                    .load(account, id, now)
                    .map_err(|_| Error::Unavailable)?
                    .ok_or(Error::Unconfirmed)?;
                // A colliding or changed destination is preserved, never overwritten
                // and never mistaken for successful transfer of this snapshot.
                let d = &saved.request;
                let mut restored = ComposeRequest::new_with_routing(
                    ComposePolicy::default(),
                    &d.recipients_text,
                    &d.cc_text,
                    &d.bcc_text,
                    &d.subject,
                    &d.body,
                    d.attachments.clone(),
                )
                .and_then(|r| r.with_body_format(d.body_format))
                .map_err(|_| Error::Invalid)?;
                restored.sender_identity = d.sender_identity.clone();
                restored.reply_thread = d.reply_thread.clone();
                restored.protection = d.protection;
                if saved.source_attachments.is_some() || restored != request {
                    return Err(Error::Stale);
                }
                let intent = guard.draft_intent(&saved).map_err(|_| Error::Stale)?;
                guard
                    .require_unconsumed(&intent)
                    .map_err(|_| Error::Stale)?;
                store.finish_return_to_draft(&guard, list.revision, id, now)
            }
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
