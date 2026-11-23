//! Bulk Junk is a two-observation workflow: Rspamd must first confirm spam
//! learning for the exact stored message, then the same identity is moved to
//! the account-owned literal Junk folder. Partial outcomes never auto-retry.

use super::*;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_bulk_message_junk(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let notice = |status, reason, title, message: &str, events| HandledHttpResponse {
            response: html_response(
                status,
                reason,
                title,
                render_navigation_notice(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    title,
                    message,
                ),
            ),
            audit_events: events,
        };
        let invalid = |events| {
            notice(
                400,
                "Bad Request",
                "Invalid Junk Request",
                "Select between one and ten current messages outside Junk, then choose Mark as Junk.",
                events,
            )
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return invalid(audit_events);
        }
        let form = match parse_urlencoded_form(
            &request.body,
            // The visible toolbar shares its form with Move Selected, so a
            // successful destination_mailbox control is serialized even when
            // the submit button overrides the endpoint to this Junk route.
            crate::mail_list::MAX_BULK_SELECTION + 5,
            16_384,
        ) {
            Ok(form) => form,
            Err(_) => return invalid(audit_events),
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let common = [
            "csrf_token",
            "mailbox",
            "action",
            "return_to",
            "destination_mailbox",
        ];
        if form
            .keys()
            .any(|key| !common.contains(&key.as_str()) && !key.starts_with("message_"))
        {
            return invalid(audit_events);
        }
        if form.get("action").map(String::as_str) != Some("junk") {
            return invalid(audit_events);
        }
        let Some(source) = form.get("mailbox") else {
            return invalid(audit_events);
        };
        if source == "Junk" {
            return invalid(audit_events);
        }
        let Some(return_to) = form
            .get("return_to")
            .and_then(|value| crate::mail_navigation::safe_mail_return(value))
        else {
            return invalid(audit_events);
        };
        let Some(selected) = super::routes_moves::selected_moves(&form, source, "Junk", true)
        else {
            return invalid(audit_events);
        };
        let (guard, event) =
            match self.acquire_mailbox_budget(context, &session, "bulk_message_junk") {
                Ok(value) => value,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
        audit_events.push(event);

        let listing = self.gateway.list_mailboxes(context, &session);
        audit_events.extend(listing.audit_events);
        let BrowserMailboxDecision::Listed {
            canonical_username,
            mailboxes,
        } = listing.decision
        else {
            return notice(
                503,
                "Service Unavailable",
                "Junk Unavailable",
                "Your mailboxes could not be checked. No feedback or move was attempted.",
                audit_events,
            );
        };
        if canonical_username != session.record.canonical_username
            || !mailboxes.iter().any(|mailbox| mailbox.name == *source)
            || !mailboxes.iter().any(|mailbox| mailbox.name == "Junk")
        {
            return invalid(audit_events);
        }

        let total = selected.len();
        for (confirmed, selected) in selected.iter().enumerate() {
            let feedback = self
                .gateway
                .record_spam_feedback(context, &session, selected);
            audit_events.extend(feedback.audit_events);
            if let Err(error) = feedback.result {
                let (status, reason, detail, uncertain, retry_after) = match error {
                    BrowserSpamFeedbackFailure::Invalid => (400, "Bad Request", "The selected message reference was invalid. Rspamd feedback was not attempted.", 0, None),
                    BrowserSpamFeedbackFailure::Stale => (409, "Conflict", "The selected message was moved, removed or replaced. Rspamd feedback was not attempted.", 0, None),
                    BrowserSpamFeedbackFailure::RateLimited { retry_after_seconds } => (429, "Too Many Requests", "The mail action limit was reached. Rspamd feedback was not attempted.", 0, Some(retry_after_seconds)),
                    BrowserSpamFeedbackFailure::Refused => (503, "Service Unavailable", "Rspamd refused the spam-learning event. The message was not moved.", 0, None),
                    BrowserSpamFeedbackFailure::Unavailable => (503, "Service Unavailable", "Rspamd spam learning is unavailable. The message was not moved.", 0, None),
                    BrowserSpamFeedbackFailure::Unknown => (503, "Service Unavailable", "Rspamd may have recorded the spam-learning event, but confirmation failed. The message was not moved; do not repeat Mark as Junk.", 1, None),
                };
                let remaining = total - confirmed - 1;
                let message = format!(
                    "{detail} {confirmed} earlier messages were trained and moved; {uncertain} feedback event is uncertain; {remaining} remaining messages were not attempted."
                );
                let mut response = notice(
                    status,
                    reason,
                    "Mark as Junk Stopped",
                    &message,
                    audit_events,
                );
                if let Some(seconds) = retry_after {
                    response.response = response
                        .response
                        .with_header("Retry-After", seconds.to_string());
                }
                drop(guard);
                return response;
            }

            let moved = self.gateway.move_message(context, &session, selected);
            audit_events.extend(moved.audit_events);
            if !matches!(
                moved.decision,
                BrowserMessageMoveDecision::Moved {
                    ref source_mailbox_name,
                    ref destination_mailbox_name,
                    uid,
                } if source_mailbox_name == source
                    && destination_mailbox_name == "Junk"
                    && uid == selected.uid
            ) {
                let uncertain = matches!(
                    moved.decision,
                    BrowserMessageMoveDecision::Denied {
                        ref public_reason,
                        ..
                    } if public_reason == "message_move_unknown"
                );
                let remaining = total - confirmed - 1;
                let message = format!(
                    "Rspamd confirmed spam learning for the current message, but its move to Junk {}. Do not repeat Mark as Junk; use the ordinary Move control after checking both folders. {confirmed} earlier messages were trained and moved; 1 current message was trained; {remaining} remaining messages were not attempted.",
                    if uncertain { "is unconfirmed" } else { "was refused" }
                );
                drop(guard);
                return notice(
                    if uncertain { 503 } else { 409 },
                    if uncertain {
                        "Service Unavailable"
                    } else {
                        "Conflict"
                    },
                    "Spam Learned; Move Incomplete",
                    &message,
                    audit_events,
                );
            }
        }
        drop(guard);
        HandledHttpResponse {
            response: redirect_response(303, "See Other", &return_to),
            audit_events,
        }
    }
}
