//! Independent, account-owned mark-read preference. No mailbox mutation here.
use super::*;
use crate::mark_read::{Error, Policy};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_mark_read_settings(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let form =
            allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
                .then(|| parse_urlencoded_form(&request.body, 4, 1024).ok())
                .flatten();
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Mark-read Preference",
                    "<p>Reload General or Reading settings before saving the mark-read choice.</p>",
                ),
                audit_events,
            };
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let revision = form.get("expected_revision").and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|revision| revision.to_string() == *value)
        });
        let policy = form.get("policy").and_then(|value| Policy::parse(value));
        let section = form
            .get("section")
            .map(String::as_str)
            .filter(|value| matches!(*value, "general" | "reading"));
        let result = if form.keys().any(|key| {
            !matches!(
                key.as_str(),
                "csrf_token" | "expected_revision" | "policy" | "section"
            )
        }) {
            Err(Error::Invalid)
        } else {
            match (revision, policy, section) {
                (Some(revision), Some(policy), Some(_)) => match revision.checked_add(1) {
                    Some(next_revision) => self
                        .gateway
                        .save_mark_read_policy(&session, revision, policy)
                        .and_then(|saved| {
                            if saved.revision == next_revision && saved.policy == policy {
                                Ok(saved)
                            } else {
                                Err(Error::Unconfirmed)
                            }
                        }),
                    None => Err(Error::Invalid),
                },
                _ => Err(Error::Invalid),
            }
        };
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "mark_read_preference_saved"
            } else {
                "mark_read_preference_unconfirmed"
            },
            "mark-read preference evaluated",
            context,
        ));
        let section = section.unwrap_or("reading");
        let destination = format!("/settings?section={section}");
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", &destination),
            Err(error) => html_response(
                match error {
                    Error::Invalid => 400,
                    Error::Stale => 409,
                    Error::Unavailable | Error::Unconfirmed => 503,
                },
                "Preference Not Confirmed",
                "Mark-read Choice Not Confirmed",
                TrustedHtml::from_template(format!(
                    concat!(
                        "{}<main id=\"main-content\" class=\"page-shell standalone-notice\" tabindex=\"-1\"><section class=\"panel\">",
                        "<h1>Mark-read choice not confirmed</h1><p>Your submitted choice is shown below. Reload saved settings before another change.</p>",
                        "<fieldset disabled><label>Mark read<input value=\"{}\"></label><label>Revision<input value=\"{}\"></label></fieldset>",
                        "<a href=\"{}\">Load saved settings</a></section></main>"
                    ),
                    crate::http_ui::app_header(
                        &session.record.canonical_username,
                        &session.record.csrf_token,
                        if section == "general" { "settings-general" } else { "settings-reading" },
                    ),
                    escape_html(form.get("policy").map(String::as_str).unwrap_or("")),
                    escape_html(form.get("expected_revision").map(String::as_str).unwrap_or("")),
                    destination,
                )),
            ),
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
