//! Small adapters from confirmed product facts to the existing private inbox.
use super::*;
use crate::notifications::{NotificationError, NotificationKind, NotificationStore};
use crate::totp::TimeProvider as _;

impl RuntimeBrowserGateway {
    pub(super) fn record_notice(
        &self,
        account: &str,
        kind: NotificationKind,
        source: &str,
        occurred_at: u64,
        events: &mut Vec<LogEvent>,
    ) -> bool {
        let now = SystemTimeProvider.unix_timestamp();
        let result = NotificationStore::new(&self.settings_dir).record_once(
            account,
            kind,
            source,
            occurred_at,
            now,
        );
        if result.is_err() {
            events.push(LogEvent::new(
                LogLevel::Warn,
                crate::logging::EventCategory::Session,
                "notification_recording_unconfirmed",
                "the product outcome is unchanged; its notice could not be confirmed",
            ));
        }
        result.is_ok()
    }

    pub(super) fn observe_read_notice(
        &self,
        session: &ValidatedSession,
        rendered: &RenderedMessageView,
        events: &mut Vec<LogEvent>,
    ) {
        if matches!(
            rendered.openpgp,
            Some(crate::openpgp_reader_ui::ReaderState::Refused(_))
        ) || !crate::notification_observations::mentions_account(
            &rendered.body_text_for_compose,
            &session.record.canonical_username,
        ) {
            return;
        }
        self.record_mention_version(session, rendered.metadata.as_ref(), events);
    }

    pub(super) fn record_mention_version(
        &self,
        session: &ValidatedSession,
        metadata: Option<&crate::message_metadata::MessageMetadata>,
        events: &mut Vec<LogEvent>,
    ) {
        let Some(metadata) = metadata else { return };
        let Ok(version) = crate::message_metadata::MessageVersion::new(
            metadata.version.mailbox_guid.clone(),
            metadata.version.message_guid.clone(),
        ) else {
            return;
        };
        // Only a hash reaches persistence; no readable body or raw native GUID.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"osmap-mention-observation-v1\0");
        h.update(version.mailbox_guid.as_bytes());
        h.update([0]);
        h.update(version.message_guid.as_bytes());
        self.record_notice(
            &session.record.canonical_username,
            NotificationKind::Mention,
            &format!("{:x}", h.finalize()),
            SystemTimeProvider.unix_timestamp(),
            events,
        );
    }

    pub(super) fn refresh_account_notice_facts(
        &self,
        session: &ValidatedSession,
    ) -> Result<(), NotificationError> {
        let account = &session.record.canonical_username;
        let now = SystemTimeProvider.unix_timestamp();
        let inbox = NotificationStore::new(&self.settings_dir);
        let recovery = crate::authenticator::Store::new(self.settings_dir.join("account-recovery"));
        if let Some(request) = recovery
            .read_request(account)
            .map_err(|_| NotificationError::Unavailable)?
        {
            inbox.record_once(
                account,
                NotificationKind::RecoveryRequested,
                &request.case_id,
                request.requested_at,
                now,
            )?;
        }
        if let Some(case) = recovery
            .read_case(account)
            .map_err(|_| NotificationError::Unavailable)?
        {
            if case.account == *account
                && case.state == "reconciled"
                && case.account_state.as_deref() == Some("active")
                && case.account_epoch == session.record.account_epoch
            {
                inbox.record_once(
                    account,
                    NotificationKind::RecoveryCompleted,
                    &format!("{}:{}", case.case_id, case.account_epoch.unwrap_or(0)),
                    case.updated_at,
                    now,
                )?;
            }
        }
        let jobs = self
            .scheduled_list_impl(session)
            .map_err(|_| NotificationError::Unavailable)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        let mut recent: Vec<_> = jobs.jobs.iter().collect();
        recent.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        for job in recent.into_iter().take(crate::notifications::MAX_EVENTS) {
            if std::time::Instant::now() >= deadline {
                return Err(NotificationError::Unavailable);
            }
            use crate::scheduled_send::State;
            let kind = match job.state {
                State::Pending => NotificationKind::ScheduledSaved,
                State::Cancelled => NotificationKind::ScheduledCancelled,
                State::Blocked => NotificationKind::ScheduledBlocked,
                State::Unknown => NotificationKind::SubmissionUnknown,
                State::Submitted => NotificationKind::SubmissionAccepted,
                _ => continue,
            };
            let source = if matches!(job.state, State::Submitted | State::Unknown) {
                job.intent.clone().ok_or(NotificationError::Corrupt)?
            } else {
                format!(
                    "{}:{}:{}:{:?}:{:?}",
                    job.id, job.digest, job.updated_at, job.state, job.reason
                )
            };
            inbox.record_once(account, kind, &source, job.updated_at, now)?;
        }
        Ok(())
    }

    pub(super) fn record_attempt_notice(
        &self,
        account: &str,
        intent: &str,
        outcome: crate::send_journal::AttemptOutcome,
        now: u64,
        events: &mut Vec<LogEvent>,
    ) {
        use crate::send_journal::AttemptOutcome;
        let kind = match outcome {
            AttemptOutcome::Accepted { .. } | AttemptOutcome::AcceptedWithoutSentCopy => {
                NotificationKind::SubmissionAccepted
            }
            AttemptOutcome::Unconfirmed => NotificationKind::SubmissionUnknown,
            _ => return,
        };
        self.record_notice(account, kind, intent, now, events);
    }

    pub(super) fn refresh_notices_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> Result<(), NotificationError> {
        use crate::notification_observations::{InboxIdentity, InboxSnapshot, Store};
        self.refresh_account_notice_facts(session)?;
        let account = &session.record.canonical_username;
        let outcome = self.list_messages_impl(context, session, "INBOX");
        let BrowserMessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
        } = outcome.decision
        else {
            return Err(NotificationError::Unavailable);
        };
        if canonical_username != *account || mailbox_name != "INBOX" || messages.len() > 1000 {
            return Err(NotificationError::Invalid);
        }
        let mut generation = None;
        let mut identities = Vec::with_capacity(messages.len());
        for message in &messages {
            if message.mailbox_name != "INBOX" {
                return Err(NotificationError::Invalid);
            }
            let metadata = message
                .metadata
                .as_ref()
                .ok_or(NotificationError::Unavailable)?;
            let version = crate::message_metadata::MessageVersion::new(
                metadata.version.mailbox_guid.clone(),
                metadata.version.message_guid.clone(),
            )
            .map_err(|_| NotificationError::Invalid)?;
            if generation
                .as_ref()
                .is_some_and(|g| g != &version.mailbox_guid)
            {
                return Err(NotificationError::Invalid);
            }
            generation = Some(version.mailbox_guid);
            identities.push(InboxIdentity {
                uid: message.uid,
                message_guid: version.message_guid,
            });
        }
        let generation = match generation {
            Some(g) => g,
            None => {
                let status = self.mailbox_status(context, session, "INBOX");
                if status.canonical_username != *account {
                    return Err(NotificationError::Invalid);
                }
                let status = status.status.ok_or(NotificationError::Unavailable)?;
                if status.mailbox() != "INBOX" || status.messages() != 0 {
                    return Err(NotificationError::Unavailable);
                }
                status.guid().to_string()
            }
        };
        let now = SystemTimeProvider.unix_timestamp();
        let observed = Store::new(&self.settings_dir).observe_inbox(
            account,
            InboxSnapshot {
                account: &canonical_username,
                mailbox_guid: &generation,
                messages: &identities,
            },
            now,
        )?;
        let store = NotificationStore::new(&self.settings_dir);
        // One generic activity event per successful observation, not1000 fsyncs
        // or a promise of one notice for every delivered message.
        if let Some(message) = observed.messages.iter().max_by_key(|message| message.uid) {
            store.record_once(
                account,
                NotificationKind::NewMail,
                &message.source_ref,
                now,
                now,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "http/notification_producer_tests.rs"]
mod tests;
