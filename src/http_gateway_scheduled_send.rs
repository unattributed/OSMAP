//! Scheduled authority adapter. Submission, recovery and Sent share one callback
//! with interactive sends; no browser session or network origin is fabricated.
use super::*;
use crate::config::LogLevel;
use crate::logging::EventCategory;
use crate::scheduled_send::{BlockReason, ClaimedJob};
use crate::session::{FileSessionStore, SessionStore};
use crate::totp::TimeProvider;
use std::time::{Duration, Instant};

pub(crate) enum ScheduledDispatch {
    Submitted,
    Blocked(BlockReason),
    Unknown,
}
pub(crate) struct ScheduledSendOutcome {
    pub decision: ScheduledDispatch,
    pub audit_events: Vec<LogEvent>,
}
pub(super) type PreparedWire = (
    crate::protected_submission::PreparedSubmission,
    u64,
    Option<[u8; 32]>,
);

#[derive(Clone, Copy)]
pub(super) enum SendAuditOrigin<'a> {
    Browser(&'a AuthenticationContext),
    Scheduled(&'a ClaimedJob),
}
impl SendAuditOrigin<'_> {
    pub(super) fn request(self, event: LogEvent) -> LogEvent {
        match self {
            Self::Browser(context) => event.with_field("request_id", &context.request_id),
            Self::Scheduled(claim) => event
                .with_field("submission_origin", "scheduled")
                .with_field("scheduled_job_ref", claim.id()),
        }
    }
    fn warning(self, action: &'static str, message: &'static str) -> LogEvent {
        match self {
            Self::Browser(context) => build_http_warning_event(action, message, context),
            Self::Scheduled(_) => self.request(LogEvent::new(
                LogLevel::Warn,
                EventCategory::Submission,
                action,
                message,
            )),
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum DispatchAuthority<'a> {
    Browser {
        context: &'a AuthenticationContext,
        session: &'a ValidatedSession,
    },
    Scheduled(&'a ClaimedJob),
}
impl<'a> DispatchAuthority<'a> {
    fn account(self) -> &'a str {
        match self {
            Self::Browser { session, .. } => &session.record.canonical_username,
            Self::Scheduled(claim) => claim.account(),
        }
    }
    fn audit(self) -> SendAuditOrigin<'a> {
        match self {
            Self::Browser { context, .. } => SendAuditOrigin::Browser(context),
            Self::Scheduled(claim) => SendAuditOrigin::Scheduled(claim),
        }
    }
}
pub(super) struct PreparedDispatchInput<'a> {
    pub authority: DispatchAuthority<'a>,
    pub journal: &'a crate::send_journal::SendJournal,
    pub intent: &'a str,
    pub now: u64,
    pub request: &'a ComposeRequest,
    pub capture: &'a crate::sent_location::SentCopyCapture,
    pub prepared: Option<PreparedWire>,
    pub throttle: &'a SubmissionThrottleService<FileLoginThrottleStore, SystemTimeProvider>,
    pub deadline: Option<Instant>,
}

impl RuntimeBrowserGateway {
    /// Read-only authority check. It never refreshes session last_seen or grants.
    fn scheduled_authority(
        &self,
        claim: &ClaimedJob,
        deadline: Instant,
    ) -> Result<(), BlockReason> {
        if self
            .account_rollout
            .as_deref()
            .is_some_and(|a| a != claim.account())
        {
            return Err(BlockReason::AccountChanged);
        }
        let runtime = self
            .ready_account_runtime(claim.account())
            .ok_or(BlockReason::ServiceUnavailable)?;
        runtime
            .admission()
            .admit_before(claim.account(), claim.account_epoch(), deadline)
            .map_err(|error| match error {
                crate::account_admission::Error::Invalid
                | crate::account_admission::Error::Refused
                | crate::account_admission::Error::Authentication => BlockReason::AccountChanged,
                _ => BlockReason::ServiceUnavailable,
            })?;
        if claim.request().protection.sign {
            self.scheduled_private_session(claim, SystemTimeProvider.unix_timestamp())?;
        }
        if Instant::now() >= deadline {
            return Err(BlockReason::ServiceUnavailable);
        }
        Ok(())
    }
    fn scheduled_private_session(&self, claim: &ClaimedJob, now: u64) -> Result<(), BlockReason> {
        let descriptor = claim.private_session();
        if !descriptor.valid(now) || descriptor.account_epoch != Some(claim.account_epoch()) {
            return Err(BlockReason::SessionExpired);
        }
        let record = FileSessionStore::new(self.session_dir.clone())
            .load(&descriptor.session_id)
            .map_err(|_| BlockReason::ServiceUnavailable)?
            .ok_or(BlockReason::SessionExpired)?;
        if record.session_id != descriptor.session_id
            || record.canonical_username != claim.account()
            || record.account_epoch != Some(claim.account_epoch())
            || record.revoked_at.is_some()
            || record.expires_at != descriptor.expires_at
            || record.expires_at <= now
            || record.issued_at > now
            || record.last_seen_at > now
            || record.last_seen_at < record.issued_at
            || now.saturating_sub(record.last_seen_at) > self.session_idle_timeout_seconds
        {
            return Err(BlockReason::SessionExpired);
        }
        Ok(())
    }

    pub(crate) fn dispatch_scheduled(&self, claim: &ClaimedJob) -> ScheduledSendOutcome {
        self.dispatch_scheduled_with_backends(
            claim,
            &self.build_submission_service(),
            &self.build_message_append_backend(),
        )
    }
    pub(super) fn dispatch_scheduled_with_backends<
        S: crate::send::SubmissionBackend,
        A: MessageAppendBackend,
    >(
        &self,
        claim: &ClaimedJob,
        submission: &SubmissionService<S>,
        append: &A,
    ) -> ScheduledSendOutcome {
        use crate::send_journal::{AttemptOutcome, LocatedPreparedResult};
        let now = SystemTimeProvider.unix_timestamp();
        let deadline = Instant::now() + Duration::from_secs(self.expensive_request_timeout_secs);
        let journal = crate::send_journal::SendJournal::new(self.settings_dir.join("send-journal"));
        let throttle = self.build_submission_throttle_service();
        let prepared = std::cell::RefCell::new(None);
        let mut events = Vec::new();
        let mut dispatch_events = Vec::new();
        let result = journal.execute_prepared_with_sent_location(
            claim.account(),
            claim.intent(),
            now,
            |captured| {
                if let Some(captured) = captured {
                    return Ok((claim.request().clone(), captured));
                }
                self.scheduled_authority(claim, deadline)?;
                let check = throttle
                    .check_scheduled(claim.account(), claim.id())
                    .map_err(|_| BlockReason::ServiceUnavailable)?;
                events.extend(check.audit_events);
                if matches!(check.decision, SubmissionThrottleDecision::Throttled { .. }) {
                    return Err(BlockReason::ServiceUnavailable);
                }
                let wire = self
                    .prepare_outbound_request(
                        claim.account(),
                        claim.request(),
                        now,
                        Some(claim.private_session().clone()),
                    )
                    .map_err(|reason| {
                        events.push(
                            SendAuditOrigin::Scheduled(claim)
                                .warning(
                                    "send_preparation_refused",
                                    "scheduled outbound preparation refused before submission",
                                )
                                .with_field("reason", reason),
                        );
                        match reason {
                            "openpgp_key_locked" => BlockReason::KeyLocked,
                            "invalid_request" | "openpgp_message_too_large" => {
                                BlockReason::InvalidContent
                            }
                            "openpgp_binding_changed"
                            | "openpgp_recipient_encryption_required"
                            | "openpgp_recipient_encryption_disabled"
                            | "openpgp_recipient_key_unavailable"
                            | "openpgp_signing_required"
                            | "openpgp_signing_disabled"
                            | "openpgp_encryption_required"
                            | "openpgp_encryption_disabled"
                            | "openpgp_signing_key_unavailable"
                            | "openpgp_encrypted_bcc_unavailable"
                            | "openpgp_self_requires_encryption"
                            | "openpgp_self_key_unavailable"
                            | "openpgp_protection_blocked" => BlockReason::PolicyChanged,
                            _ => BlockReason::ServiceUnavailable,
                        }
                    })?;
                if Instant::now() >= deadline {
                    return Err(BlockReason::ServiceUnavailable);
                }
                *prepared.borrow_mut() = Some(wire);
                let save_sent = crate::sent_copy::Store::new(&self.settings_dir)
                    .load(claim.account())
                    .map_err(|_| BlockReason::ServiceUnavailable)?
                    .save_sent;
                let location = if save_sent {
                    self.capture_sent_location(claim.account())
                        .map_err(|_| BlockReason::ServiceUnavailable)?
                } else {
                    None
                };
                Ok((
                    claim.request().clone(),
                    crate::sent_location::SentCopyCapture {
                        requested: save_sent,
                        location,
                    },
                ))
            },
            |request, capture| {
                self.dispatch_prepared_attempt(
                    PreparedDispatchInput {
                        authority: DispatchAuthority::Scheduled(claim),
                        journal: &journal,
                        intent: claim.intent(),
                        now,
                        request,
                        capture,
                        prepared: prepared.borrow_mut().take(),
                        throttle: &throttle,
                        deadline: Some(deadline),
                    },
                    submission,
                    append,
                    &mut dispatch_events,
                )
            },
        );
        events.extend(dispatch_events);
        let decision = match result {
            Ok(LocatedPreparedResult::NotDispatched(reason)) => ScheduledDispatch::Blocked(reason),
            Ok(LocatedPreparedResult::Outcome(recorded)) => match recorded.result.outcome {
                AttemptOutcome::Accepted { .. } | AttemptOutcome::AcceptedWithoutSentCopy => {
                    ScheduledDispatch::Submitted
                }
                _ => ScheduledDispatch::Unknown,
            },
            Err(_) => ScheduledDispatch::Unknown,
        };
        ScheduledSendOutcome {
            decision,
            audit_events: events,
        }
    }

    /// Journal reservation precedes this callback. Every refusal from here is
    /// conservatively Unknown; none authorizes another SMTP invocation.
    pub(super) fn dispatch_prepared_attempt<
        S: crate::send::SubmissionBackend,
        A: MessageAppendBackend,
    >(
        &self,
        input: PreparedDispatchInput<'_>,
        submission: &SubmissionService<S>,
        append: &A,
        events: &mut Vec<LogEvent>,
    ) -> crate::send_journal::AttemptOutcome {
        use crate::send_journal::AttemptOutcome;
        let PreparedDispatchInput {
            authority,
            journal,
            intent,
            now,
            request,
            capture,
            prepared,
            throttle,
            deadline,
        } = input;
        let account = authority.account();
        let audit = authority.audit();
        if let DispatchAuthority::Scheduled(claim) = authority {
            if claim.intent() != intent || claim.request() != request {
                return AttemptOutcome::Unconfirmed;
            }
        }
        let recovery =
            crate::send_recovery::SendRecovery::new(self.settings_dir.join("send-recovery"));
        let request = match recovery.capture(
            journal,
            &self.build_draft_store(),
            account,
            intent,
            request,
            now,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                events.push(audit.warning(
                    "send_recovery_unconfirmed",
                    "attempt recovery was not confirmed; submission was not invoked",
                ));
                return AttemptOutcome::RecoveryRefused {
                    capacity: error == crate::send_recovery::RecoveryError::Capacity,
                };
            }
        };
        let Some((prepared, binding_revision, inventory_revision)) = prepared else {
            return AttemptOutcome::Unconfirmed;
        };
        let outcome =
            crate::openpgp_bindings::BindingStore::new(self.settings_dir.join("openpgp-bindings"))
                .with_locked_inventory_revision(
                    account,
                    binding_revision,
                    inventory_revision,
                    || {
                        self.inventory_client()
                            .as_ref()
                            .ok_or(crate::openpgp_bindings::BindingError::Unavailable)?
                            .read(account)
                            .map_err(|_| crate::openpgp_bindings::BindingError::Unavailable)
                    },
                    || match authority {
                        DispatchAuthority::Browser { context, session } => {
                            Some(submission.submit_prepared_for_validated_session(
                                context, session, &request, &prepared,
                            ))
                        }
                        DispatchAuthority::Scheduled(claim) => {
                            let deadline = deadline?;
                            self.scheduled_authority(claim, deadline).ok()?;
                            Some(submission.submit_prepared_for_scheduled_job(claim, &prepared))
                        }
                    },
                );
        let Ok(Some(SubmissionOutcome {
            decision,
            audit_event,
        })) = outcome
        else {
            return AttemptOutcome::Unconfirmed;
        };
        events.push(audit_event);
        if !matches!(decision, SubmissionDecision::Submitted { .. }) {
            return AttemptOutcome::Unconfirmed;
        }
        let (stored, event) = if capture.requested
            && capture
                .location
                .as_ref()
                .is_some_and(|location| !location.available())
        {
            (false, audit.request(LogEvent::new(LogLevel::Warn, EventCategory::Submission,
                "sent_copy_destination_unavailable", "submission accepted; captured copy destination unavailable; append not invoked")
                .with_field("mailbox_name", capture.location.as_ref().map_or("", |location| location.name()))))
        } else if capture.requested {
            super::http_gateway_mail::store_prepared_sent_copy_for(
                audit,
                account,
                &request,
                &prepared,
                append,
                capture.location.as_ref(),
            )
        } else {
            (
                false,
                audit.request(LogEvent::new(
                    LogLevel::Info,
                    EventCategory::Submission,
                    "sent_copy_not_requested",
                    "outbound message accepted; no Sent copy requested",
                )),
            )
        };
        events.push(event);
        let recorded = match authority {
            DispatchAuthority::Browser { context, .. } => {
                throttle.record_submission(context, account)
            }
            DispatchAuthority::Scheduled(claim) => {
                throttle.record_scheduled_submission(account, claim.id())
            }
        };
        match recorded {
            Ok(recorded) => events.extend(recorded.audit_events),
            Err(error) => events.push(match authority {
                DispatchAuthority::Browser { context, .. } => self
                    .build_submission_throttle_store_error_event(
                        "submission_throttle_record_failed",
                        "submission throttle recording failed",
                        context,
                        &error,
                    ),
                DispatchAuthority::Scheduled(_) => audit.warning(
                    "submission_throttle_record_failed",
                    "scheduled submission throttle recording failed",
                ),
            }),
        }
        if capture.requested {
            AttemptOutcome::Accepted {
                sent_copy_stored: stored,
            }
        } else {
            AttemptOutcome::AcceptedWithoutSentCopy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("http_gateway_scheduled_send_tests.rs");
}
