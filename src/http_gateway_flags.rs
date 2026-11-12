//! Flag mutations use the authenticated account and a fail-closed quota reserve.
use super::*;
use crate::mailbox::{MessageFlagBackend, MessageFlagRequest};

impl RuntimeBrowserGateway {
    pub(super) fn set_message_flag_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &MessageFlagRequest,
    ) -> BrowserMessageFlagOutcome {
        let mut audit_events = Vec::new();
        if MessageFlagRequest::new(
            request.mailbox_name.clone(),
            request.uid,
            request.version.clone(),
            request.flag,
            request.enabled,
        )
        .is_err()
        {
            return BrowserMessageFlagOutcome {
                result: Err(BrowserMessageFlagFailure::Invalid),
                audit_events,
            };
        }
        let reserve = self
            .build_message_move_throttle_service()
            .reserve_mail_action(context, &session.record.canonical_username);
        match reserve {
            Ok(check) => {
                audit_events.extend(check.audit_events);
                if let MessageMoveThrottleDecision::Throttled {
                    retry_after_seconds,
                } = check.decision
                {
                    return BrowserMessageFlagOutcome {
                        result: Err(BrowserMessageFlagFailure::RateLimited {
                            retry_after_seconds,
                        }),
                        audit_events,
                    };
                }
            }
            Err(_) => {
                audit_events.push(build_http_warning_event(
                    "message_flag_quota_unavailable",
                    "flag update refused because the mutation quota could not be reserved",
                    context,
                ));
                return BrowserMessageFlagOutcome {
                    result: Err(BrowserMessageFlagFailure::Unavailable),
                    audit_events,
                };
            }
        }
        let result = self
            .build_message_flag_backend()
            .set_message_flag(&session.record.canonical_username, request);
        let outcome_label = match &result {
            Ok(crate::mailbox::MessageFlagResult::Updated) => "updated",
            Ok(crate::mailbox::MessageFlagResult::AlreadySet) => "already_set",
            Err(error) => error.backend,
        };
        audit_events.push(
            build_http_info_event(
                "message_flag_result",
                "bounded flag update completed",
                context,
            )
            .with_field(
                "session_ref",
                crate::logging::audit_session_ref(&session.record.session_id),
            )
            .with_field("flag", request.flag.value())
            .with_field("enabled", request.enabled.to_string())
            .with_field("outcome", outcome_label),
        );
        let result = result.map_err(|error| match error.backend {
            "message-flag-invalid" | "message-metadata" => BrowserMessageFlagFailure::Invalid,
            "message-flag-stale" => BrowserMessageFlagFailure::Stale,
            "message-flag-busy" => BrowserMessageFlagFailure::Busy,
            "message-flag-unknown" => BrowserMessageFlagFailure::Unknown,
            _ => BrowserMessageFlagFailure::Unavailable,
        });
        BrowserMessageFlagOutcome {
            result,
            audit_events,
        }
    }
}
