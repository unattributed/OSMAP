//! Rspamd spam feedback uses one fixed doas command after exact stored-message
//! retrieval through the configured mailbox boundary.

use super::*;
use crate::auth::CommandExecutor;
use crate::mailbox::RawMessageBackend;

impl RuntimeBrowserGateway {
    pub(super) fn record_spam_feedback_impl(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> BrowserSpamFeedbackOutcome {
        let mut audit_events = Vec::new();
        let failed = |failure, events| BrowserSpamFeedbackOutcome {
            result: Err(failure),
            audit_events: events,
        };
        if MessageMoveRequest::new(
            MessageMovePolicy::default(),
            request.source_mailbox_name.clone(),
            request.destination_mailbox_name.clone(),
            request.uid,
            request.version.clone(),
        )
        .is_err()
            || request.destination_mailbox_name != "Junk"
        {
            return failed(BrowserSpamFeedbackFailure::Invalid, audit_events);
        }
        match self
            .build_message_move_throttle_service()
            .reserve_mail_action(context, &session.record.canonical_username)
        {
            Ok(check) => {
                audit_events.extend(check.audit_events);
                if let MessageMoveThrottleDecision::Throttled {
                    retry_after_seconds,
                } = check.decision
                {
                    return failed(
                        BrowserSpamFeedbackFailure::RateLimited {
                            retry_after_seconds,
                        },
                        audit_events,
                    );
                }
            }
            Err(_) => return failed(BrowserSpamFeedbackFailure::Unavailable, audit_events),
        }

        let raw_request = match crate::mailbox::RawMessageRequest::new(
            request.source_mailbox_name.clone(),
            request.uid,
            request.version.clone(),
        ) {
            Ok(request) => request,
            Err(_) => return failed(BrowserSpamFeedbackFailure::Invalid, audit_events),
        };
        let fetched = match &self.mailbox_helper_socket_path {
            Some(socket_path) => match (self.helper_grant_key_path(), self.mailbox_helper_peer_uid)
            {
                (Some(key), Some(uid)) => {
                    crate::mailbox_helper::MailboxHelperRawMessageBackend::new(
                        socket_path,
                        key,
                        self.expensive_route_helper_policy(),
                    )
                    .with_helper_uid(Some(uid))
                    .fetch_raw_message(&session.record.canonical_username, &raw_request)
                }
                _ => Err(crate::mailbox::MailboxBackendError {
                    backend: "mailbox-helper-config",
                    reason: "raw message helper identity unavailable".into(),
                }),
            },
            None => crate::mailbox::DoveadmRawMessageBackend::new(
                SystemCommandExecutor,
                self.doveadm_path.clone(),
            )
            .with_userdb_socket_path(self.doveadm_userdb_socket_path.clone())
            .fetch_raw_message(&session.record.canonical_username, &raw_request),
        };
        let stored_message = match fetched {
            Ok(message) if message.version == request.version => message.bytes,
            Ok(_) => return failed(BrowserSpamFeedbackFailure::Stale, audit_events),
            Err(_) => return failed(BrowserSpamFeedbackFailure::Unavailable, audit_events),
        };

        let result = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/bin/doas",
            &[
                "-n".into(),
                "/usr/local/bin/osmap".into(),
                "rspamd-learn-spam".into(),
            ],
            &stored_message,
            std::time::Duration::from_secs(self.expensive_request_timeout_secs.clamp(1, 12)),
            4096,
        );
        let public_result = match result {
            Ok(execution) if execution.status_code == 0 && execution.stdout.trim() == "learned" => {
                Ok(())
            }
            Ok(execution) if execution.status_code == 10 => {
                Err(BrowserSpamFeedbackFailure::Refused)
            }
            Ok(execution) if execution.status_code == 11 => {
                Err(BrowserSpamFeedbackFailure::Unknown)
            }
            Ok(_) => Err(BrowserSpamFeedbackFailure::Unavailable),
            Err(_) => Err(BrowserSpamFeedbackFailure::Unknown),
        };
        audit_events.push(
            build_http_info_event(
                "rspamd_spam_feedback_result",
                "bounded exact-message spam feedback completed",
                context,
            )
            .with_field(
                "session_ref",
                crate::logging::audit_session_ref(&session.record.session_id),
            )
            .with_field(
                "outcome",
                match &public_result {
                    Ok(()) => "confirmed",
                    Err(BrowserSpamFeedbackFailure::Refused) => "refused",
                    Err(BrowserSpamFeedbackFailure::Unknown) => "unknown",
                    _ => "unavailable",
                },
            ),
        );
        BrowserSpamFeedbackOutcome {
            result: public_result,
            audit_events,
        }
    }
}
