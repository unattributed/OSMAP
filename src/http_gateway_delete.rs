//! Permanent deletion uses only the configured authenticated helper and existing quota.
use super::*;
use crate::mailbox::{
    MessageDeleteBackend, MessageDeleteError, MessageDeleteRequest, MessageDeleteResult,
};

impl RuntimeBrowserGateway {
    pub(super) fn build_message_delete_backend(
        &self,
    ) -> Option<crate::mailbox_helper::MailboxHelperMessageDeleteBackend> {
        Some(
            crate::mailbox_helper::MailboxHelperMessageDeleteBackend::new(
                self.mailbox_helper_socket_path.as_ref()?,
                self.mailbox_helper_grant_key_path.as_ref()?,
                crate::mailbox_helper::MailboxHelperPolicy::default(),
            )
            .with_helper_uid(self.mailbox_helper_peer_uid?),
        )
    }

    pub(super) fn delete_message_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &MessageDeleteRequest,
    ) -> BrowserMessageDeleteOutcome {
        let mut outcome = BrowserMessageDeleteOutcome {
            result: Err(MessageDeleteError::Unavailable),
            retry_after_seconds: None,
            audit_events: Vec::new(),
        };
        if request.canonical_username != session.record.canonical_username
            || MessageDeleteRequest::new(
                request.canonical_username.clone(),
                request.mailbox_name.clone(),
                request.uid,
                request.version.clone(),
                request.policy_revision,
            )
            .is_err()
        {
            outcome.result = Err(MessageDeleteError::Invalid);
            return outcome;
        }
        let Some(backend) = self.build_message_delete_backend() else {
            return outcome;
        };
        match self
            .build_message_move_throttle_service()
            .reserve_mail_action(context, &session.record.canonical_username)
        {
            Ok(check) => {
                outcome.audit_events.extend(check.audit_events);
                if let MessageMoveThrottleDecision::Throttled {
                    retry_after_seconds,
                } = check.decision
                {
                    outcome.result = Err(MessageDeleteError::Busy);
                    outcome.retry_after_seconds = Some(retry_after_seconds);
                    return outcome;
                }
            }
            Err(_) => {
                outcome.audit_events.push(build_http_warning_event(
                    "message_delete_quota_unavailable",
                    "delete refused because its mutation quota could not be reserved",
                    context,
                ));
                return outcome;
            }
        }
        outcome.result = backend.delete_message(&session.record.canonical_username, request);
        let label = match outcome.result {
            Ok(MessageDeleteResult::Deleted) => "deleted",
            Err(MessageDeleteError::Invalid) => "invalid",
            Err(MessageDeleteError::Stale) => "stale",
            Err(MessageDeleteError::PolicyDenied) => "policy_denied",
            Err(MessageDeleteError::PolicyUnavailable) => "policy_unavailable",
            Err(MessageDeleteError::Busy) => "busy",
            Err(MessageDeleteError::Unavailable) => "unavailable",
            Err(MessageDeleteError::Unknown) => "unknown",
        };
        outcome.audit_events.push(
            build_http_info_event(
                "message_delete_result",
                "single-message delete result observed",
                context,
            )
            .with_field(
                "session_ref",
                crate::logging::audit_session_ref(&session.record.session_id),
            )
            .with_field("outcome", label),
        );
        outcome
    }
}

#[cfg(all(test, unix))]
#[path = "http_gateway_delete_tests.rs"]
mod tests;
