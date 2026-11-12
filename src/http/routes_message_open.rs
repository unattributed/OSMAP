//! Explicit authenticated opening. GET never changes Seen, including refresh/Back.
use super::*;
use crate::mailbox::MessageFlagRequest;
use crate::message_metadata::{MessageFlag, MessageVersion};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_message_open(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let refuse = |status, title, message, audit_events| HandledHttpResponse {
            response: html_response(
                status,
                "Opening Not Confirmed",
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
        let form =
            allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
                .then(|| parse_urlencoded_form(&request.body, 6, 8192).ok())
                .flatten();
        let Some(form) = form else {
            return refuse(
                400,
                "Invalid Message Opening",
                "Choose a current message from the list.",
                audit_events,
            );
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let identity = (|| {
            if form.len() != 6
                || form.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "csrf_token"
                            | "mailbox"
                            | "uid"
                            | "mailbox_guid"
                            | "message_guid"
                            | "return_to"
                    )
                })
            {
                return None;
            }
            let uid = form.get("uid")?.parse::<u32>().ok()?;
            if uid == 0 || uid.to_string() != *form.get("uid")? {
                return None;
            }
            let version = MessageVersion::new(
                form.get("mailbox_guid")?.clone(),
                form.get("message_guid")?.clone(),
            )
            .ok()?;
            MessageFlagRequest::new(
                form.get("mailbox")?.clone(),
                u64::from(uid),
                version,
                MessageFlag::Seen,
                true,
            )
            .ok()
        })();
        let Some(identity) = identity else {
            return refuse(
                400,
                "Invalid Message Opening",
                "Choose a current message from the list.",
                audit_events,
            );
        };
        let Some(destination) = opening_destination(
            form.get("return_to").map(String::as_str).unwrap_or(""),
            &identity,
        ) else {
            return refuse(
                400,
                "Invalid Message Opening",
                "The opening destination does not match this message.",
                audit_events,
            );
        };
        let policy = match self.gateway.load_mark_read_policy(&session) {
            Ok(preference) => preference.policy,
            Err(_) => return refuse(503, "Reading Preference Unavailable", "Your saved mark-read choice could not be checked. Reload Reading settings before opening this message.", audit_events),
        };
        let (guard, event) = match self.acquire_mailbox_budget(context, &session, "message_open") {
            Ok(value) => value,
            Err(response) => return response,
        };
        audit_events.push(event);
        let outcome =
            self.gateway
                .view_message(context, &session, &identity.mailbox_name, identity.uid);
        audit_events.extend(outcome.audit_events);
        audit_events.push(self.release_request_budget(guard, "message_open", context, &session));
        let verified = matches!(outcome.decision, BrowserMessageViewDecision::Rendered { canonical_username, rendered }
            if canonical_username == session.record.canonical_username && rendered.mailbox_name == identity.mailbox_name
                && rendered.uid == identity.uid && rendered.metadata.as_ref().is_some_and(|metadata| metadata.version == identity.version));
        if !verified {
            return refuse(
                409,
                "Message Has Changed",
                "Refresh the list before opening this message. No read-state update was requested.",
                audit_events,
            );
        }
        if policy == crate::mark_read::Policy::Manual {
            return HandledHttpResponse {
                response: redirect_response(303, "See Other", &destination),
                audit_events,
            };
        }
        // Existing flag route retains quota, native CAS and ambiguous outcomes.
        // No retry or claim of unchanged flags on an unconfirmed native result.
        let mut flag_request = request.clone();
        flag_request.path = "/message/flag".into();
        flag_request.body = [
            ("csrf_token", session.record.csrf_token.clone()),
            ("mailbox", identity.mailbox_name),
            ("uid", identity.uid.to_string()),
            ("mailbox_guid", identity.version.mailbox_guid),
            ("message_guid", identity.version.message_guid),
            ("flag", "seen".into()),
            ("enabled", "1".into()),
            ("return_to", destination),
        ]
        .iter()
        .map(|(key, value)| format!("{key}={}", url_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes();
        let mut response = self.handle_message_flag(&flag_request, context);
        audit_events.append(&mut response.audit_events);
        response.audit_events = audit_events;
        response
    }
}

fn opening_destination(value: &str, identity: &MessageFlagRequest) -> Option<String> {
    let safe = crate::mail_navigation::safe_mail_return(value)?;
    let (path, query) = safe.split_once('?')?;
    let mut fields = parse_urlencoded_form(
        query.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .ok()?;
    let (mailbox_key, uid_key, mailbox_guid_key, message_guid_key) = match path {
        "/message" => ("mailbox", "uid", "mailbox_guid", "message_guid"),
        "/mailbox" | "/search" if !fields.contains_key("category") => (
            "selected_mailbox",
            "selected_uid",
            "selected_mailbox_guid",
            "selected_message_guid",
        ),
        _ => return None,
    };
    if fields.get(mailbox_key)? != &identity.mailbox_name
        || fields.get(uid_key)? != &identity.uid.to_string()
        || fields
            .get(mailbox_guid_key)
            .is_some_and(|guid| guid != &identity.version.mailbox_guid)
        || fields
            .get(message_guid_key)
            .is_some_and(|guid| guid != &identity.version.message_guid)
    {
        return None;
    }
    fields.insert(
        mailbox_guid_key.into(),
        identity.version.mailbox_guid.clone(),
    );
    fields.insert(
        message_guid_key.into(),
        identity.version.message_guid.clone(),
    );
    fields.remove("select");
    if path != "/message" && fields.get("filter").map(String::as_str) == Some("unread") {
        fields.insert("opened_read".into(), "1".into());
    }
    crate::mail_navigation::safe_mail_return(&format!(
        "{path}?{}",
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    ))
}
