//! Authenticated native forms for identity-bound read/star updates.
use super::*;
use crate::mailbox::{MessageFlagRequest, MessageFlagResult};
use crate::message_metadata::{MessageFlag, MessageVersion};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_message_flag(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(result) => result,
            Err(response) => return response,
        };
        let failure = |status, reason, title, message: &str, audit_events| HandledHttpResponse {
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
            audit_events,
        };
        let invalid = |events| {
            failure(
                400,
                "Bad Request",
                "Invalid Message State Request",
                "Return to the message list and choose a current read or star control.",
                events,
            )
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return invalid(audit_events);
        }
        let form = match parse_urlencoded_form(&request.body, 8, 8192) {
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
        let allowed = [
            "csrf_token",
            "mailbox",
            "uid",
            "mailbox_guid",
            "message_guid",
            "flag",
            "enabled",
            "return_to",
        ];
        if form.len() != allowed.len() || form.keys().any(|key| !allowed.contains(&key.as_str())) {
            return invalid(audit_events);
        }
        let flag_request = (|| {
            let flag = MessageFlag::parse(form.get("flag")?)?;
            let enabled = match form.get("enabled")?.as_str() {
                "1" => true,
                "0" => false,
                _ => return None,
            };
            let uid = form.get("uid")?.parse::<u64>().ok()?;
            let version = MessageVersion::new(
                form.get("mailbox_guid")?.clone(),
                form.get("message_guid")?.clone(),
            )
            .ok()?;
            MessageFlagRequest::new(form.get("mailbox")?.clone(), uid, version, flag, enabled).ok()
        })();
        let Some(flag_request) = flag_request else {
            return invalid(audit_events);
        };
        let Some(return_to) = form
            .get("return_to")
            .and_then(|value| crate::mail_navigation::safe_mail_return(value))
        else {
            return invalid(audit_events);
        };
        let (guard, event) = match self.acquire_mailbox_budget(context, &session, "message_flag") {
            Ok(value) => value,
            Err(mut response) => {
                audit_events.extend(response.audit_events);
                response.audit_events = audit_events;
                return response;
            }
        };
        audit_events.push(event);
        let outcome = self
            .gateway
            .set_message_flag(context, &session, &flag_request);
        drop(guard);
        audit_events.extend(outcome.audit_events);
        match outcome.result {
            Ok(MessageFlagResult::Updated | MessageFlagResult::AlreadySet) => HandledHttpResponse {
                response: redirect_response(303, "See Other", &return_to),
                audit_events,
            },
            Err(error) => {
                let (status, reason, title, message) = match error {
                    BrowserMessageFlagFailure::Invalid => (400, "Bad Request", "Invalid Message State Request", "Return to the message list and choose a current read or star control."),
                    BrowserMessageFlagFailure::Stale => (409, "Conflict", "Message Has Changed", "This message was moved, removed or replaced. Refresh the list before choosing another action."),
                    BrowserMessageFlagFailure::Busy => (409, "Conflict", "Message Update In Progress", "Another message state update is in progress. Refresh the list when it finishes."),
                    BrowserMessageFlagFailure::RateLimited { .. } => (429, "Too Many Requests", "Message Updates Temporarily Limited", "The mail action limit has been reached. Wait before choosing another action."),
                    BrowserMessageFlagFailure::Unknown => (503, "Service Unavailable", "Message State Not Confirmed", "The update may have completed, but its result could not be confirmed. Refresh the list to check the current state before choosing another action."),
                    BrowserMessageFlagFailure::Unavailable => (503, "Service Unavailable", "Message Update Unavailable", "Message state could not be checked. Refresh the list before choosing another action."),
                };
                let mut response = failure(status, reason, title, message, audit_events);
                if let BrowserMessageFlagFailure::RateLimited {
                    retry_after_seconds,
                } = error
                {
                    response.response = response
                        .response
                        .with_header("Retry-After", retry_after_seconds.to_string());
                }
                response
            }
        }
    }
}
