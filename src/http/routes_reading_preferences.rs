//! Native account reading defaults; no effect on authentication or mail policy.
use super::*;
use crate::reading_preferences::{DateOrder, ReadingPreferences, StartPage};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn reading_mailbox_choices(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        audit: &mut Vec<LogEvent>,
    ) -> Option<Vec<MailboxEntry>> {
        let (guard, event) =
            match self.acquire_mailbox_budget(context, session, "settings_mailboxes") {
                Ok(value) => value,
                Err(response) => {
                    audit.extend(response.audit_events);
                    return None;
                }
            };
        audit.push(event);
        let outcome = self.gateway.list_mailboxes(context, session);
        audit.extend(outcome.audit_events);
        audit.push(self.release_request_budget(guard, "settings_mailboxes", context, session));
        match outcome.decision {
            BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } if canonical_username == session.record.canonical_username => Some(mailboxes),
            _ => None,
        }
    }

    pub(super) fn handle_reading_preferences_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let rejected = |status, reason, message| HandledHttpResponse {
            response: html_response(status, reason, "Reading Preferences Not Saved", message),
            audit_events: vec![build_http_warning_event(
                "reading_preferences_rejected",
                "reading preference update was not confirmed",
                context,
            )],
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return rejected(
                400,
                "Bad Request",
                "<p>The form content type was not supported.</p>",
            );
        }
        let form = match parse_urlencoded_form(&request.body, 5, 768) {
            Ok(value) => value,
            Err(_) => {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>The reading preference form was invalid.</p>",
                )
            }
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        if form.keys().any(|key| {
            ![
                "csrf_token",
                "start_page",
                "date_order",
                "show_source_shortcut",
                "attachment_details",
            ]
            .contains(&key.as_str())
        }) {
            return rejected(
                400,
                "Bad Request",
                "<p>The form contained an unsupported preference.</p>",
            );
        }
        let checkbox = |name: &str| match form.get(name).map(String::as_str) {
            None => Some(false),
            Some("1") => Some(true),
            _ => None,
        };
        let (
            Some(start_page),
            Some(date_order),
            Some(show_source_shortcut),
            Some(attachment_details),
        ) = (
            form.get("start_page").and_then(|v| StartPage::parse(v)),
            form.get("date_order").and_then(|v| DateOrder::parse(v)),
            checkbox("show_source_shortcut"),
            checkbox("attachment_details"),
        )
        else {
            return rejected(400, "Bad Request", "<p>Choose the supported reading preferences. Your saved preferences were not changed.</p>");
        };
        let preferences = ReadingPreferences {
            start_page,
            date_order,
            show_source_shortcut,
            attachment_details,
        };
        if self
            .gateway
            .update_reading_preferences(context, &session, preferences)
            .is_err()
        {
            return rejected(503, "Service Unavailable", "<p>The reading preference save could not be confirmed. <a href=\"/settings?section=reading\">Review your saved Reading settings</a> before trying again.</p>");
        }
        audit_events.push(build_http_info_event(
            "reading_preferences_saved",
            "account reading defaults saved",
            context,
        ));
        HandledHttpResponse {
            response: redirect_response(303, "See Other", "/settings?section=reading&updated=1")
                .with_header(
                    "Set-Cookie",
                    preferences.cookie(self.policy.secure_session_cookie),
                ),
            audit_events,
        }
    }
}

/// Finite display hints only. Stored preferences, not this cookie, select login
/// destinations. Downloaded/source content is never modified by presentation.
pub(super) fn apply_presentation(response: &mut HttpResponse, cookie: Option<&str>) {
    if !response
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Content-Type") && v == "text/html; charset=utf-8")
        || response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Content-Disposition"))
    {
        return;
    }
    let Ok(html) = std::str::from_utf8(&response.body) else {
        return;
    };
    if !html.starts_with("<!doctype html><html lang=\"en\" data-appearance=\"") {
        return;
    }
    let preferences = ReadingPreferences::from_cookie_header(cookie);
    response.body = html
        .replacen(
            "<body>",
            &format!(
                "<body data-reading-source=\"{}\" data-reading-attachment-details=\"{}\">",
                preferences.show_source_shortcut, preferences.attachment_details
            ),
            1,
        )
        .into_bytes();
}
