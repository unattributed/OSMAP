//! Authenticated native forms for identity-bound read/star updates.
use super::*;
use crate::mailbox::{MessageFlagRequest, MessageFlagResult};
use crate::message_metadata::{MessageFlag, MessageVersion};

fn selected_flag_requests(
    form: &BTreeMap<String, String>,
    mailbox_name: &str,
    enabled: bool,
) -> Option<Vec<MessageFlagRequest>> {
    let mut selected = Vec::new();
    for (key, value) in form.iter().filter(|(key, _)| key.starts_with("message_")) {
        if selected.len() == crate::mail_list::MAX_BULK_SELECTION {
            return None;
        }
        let mut parts = value.splitn(3, '|');
        let uid_text = parts.next()?;
        let uid = uid_text.parse::<u32>().ok()?;
        if uid == 0 || uid.to_string() != uid_text || key != &format!("message_{uid}") {
            return None;
        }
        let version = MessageVersion::new(parts.next()?.into(), parts.next()?.into()).ok()?;
        selected.push(
            MessageFlagRequest::new(
                mailbox_name.into(),
                u64::from(uid),
                version,
                MessageFlag::Seen,
                enabled,
            )
            .ok()?,
        );
    }
    selected.sort_by_key(|request| request.uid);
    (!selected.is_empty()).then_some(selected)
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_bulk_message_flag(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(result) => result,
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
                "Invalid Message State Request",
                "Select between one and ten current messages, then choose Mark Read or Mark Unread.",
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
            // the submit button overrides the endpoint to this flag route.
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
        let Some(mailbox_name) = form.get("mailbox") else {
            return invalid(audit_events);
        };
        let enabled = match form.get("action").map(String::as_str) {
            Some("read") => true,
            Some("unread") => false,
            _ => return invalid(audit_events),
        };
        let Some(return_to) = form
            .get("return_to")
            .and_then(|value| crate::mail_navigation::safe_mail_return(value))
        else {
            return invalid(audit_events);
        };
        let Some(selected) = selected_flag_requests(&form, mailbox_name, enabled) else {
            return invalid(audit_events);
        };
        let (guard, event) =
            match self.acquire_mailbox_budget(context, &session, "bulk_message_flag") {
                Ok(value) => value,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
        audit_events.push(event);
        let total = selected.len();
        for (confirmed, flag_request) in selected.iter().enumerate() {
            let outcome = self
                .gateway
                .set_message_flag(context, &session, flag_request);
            audit_events.extend(outcome.audit_events);
            match outcome.result {
                Ok(MessageFlagResult::Updated | MessageFlagResult::AlreadySet) => {}
                Err(error) => {
                    let (status, reason, detail, uncertain, retry_after) = match error {
                        BrowserMessageFlagFailure::Invalid => (400, "Bad Request", "The selected message reference was invalid. Its read state was not changed.", 0, None),
                        BrowserMessageFlagFailure::Stale => (409, "Conflict", "The selected message was moved, removed or replaced. Its read state was not changed.", 0, None),
                        BrowserMessageFlagFailure::Busy => (409, "Conflict", "Another mail action is active. This read-state update was refused.", 0, None),
                        BrowserMessageFlagFailure::RateLimited { retry_after_seconds } => (429, "Too Many Requests", "The mail action limit was reached. This read-state update was refused.", 0, Some(retry_after_seconds)),
                        BrowserMessageFlagFailure::Unavailable => (503, "Service Unavailable", "The current message could not be checked. Its read-state update was not attempted.", 0, None),
                        BrowserMessageFlagFailure::Unknown => (503, "Service Unavailable", "The current read-state update may have completed, but confirmation failed. Refresh before trying again.", 1, None),
                    };
                    let remaining = total - confirmed - 1;
                    let message = format!(
                        "{detail} {confirmed} confirmed; {uncertain} uncertain; {remaining} remaining messages were not attempted."
                    );
                    let mut response = notice(
                        status,
                        reason,
                        "Read-State Update Stopped",
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
            }
        }
        drop(guard);
        HandledHttpResponse {
            response: redirect_response(303, "See Other", &return_to),
            audit_events,
        }
    }

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
