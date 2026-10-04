//! Save Sent is an account setting, never a browser-supplied send override.
use super::*;
use crate::sent_copy::Error;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_sent_copy_settings(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let invalid = || {
            html_response(
                400,
                "Bad Request",
                "Save Sent Preference Invalid",
                "<p>Reload Copies &amp; Folders before saving the choice.</p>",
            )
        };
        let form =
            allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
                .then(|| parse_urlencoded_form(&request.body, 3, 512).ok())
                .flatten();
        let Some(form) = form else {
            return HandledHttpResponse {
                response: invalid(),
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
        let choice = form
            .get("save_sent")
            .and_then(|value| match value.as_str() {
                "on" => Some(true),
                "off" => Some(false),
                _ => None,
            });
        if form.keys().any(|key| {
            !matches!(
                key.as_str(),
                "csrf_token" | "expected_revision" | "save_sent"
            )
        }) {
            return HandledHttpResponse {
                response: invalid(),
                audit_events,
            };
        }
        let (Some(revision), Some(choice)) = (revision, choice) else {
            return HandledHttpResponse {
                response: invalid(),
                audit_events,
            };
        };
        let result = revision
            .checked_add(1)
            .ok_or(Error::Invalid)
            .and_then(|next| {
                self.gateway
                    .save_sent_copy_preference(&session, revision, choice)
                    .and_then(|saved| {
                        if saved.revision == next && saved.save_sent == choice {
                            Ok(saved)
                        } else {
                            Err(Error::Unconfirmed)
                        }
                    })
            });
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "sent_copy_preference_saved"
            } else {
                "sent_copy_preference_unconfirmed"
            },
            "Save Sent preference evaluated",
            context,
        ));
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", "/settings?section=copies&updated=1"),
            Err(error) => html_response(match error { Error::Invalid => 400, Error::Stale => 409, Error::Unavailable | Error::Unconfirmed => 503 }, "Preference Not Confirmed", "Save Sent Preference Not Confirmed", TrustedHtml::from_template(format!("<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Save Sent choice not confirmed</h1><p>Your submitted choice: {}. Reload the saved preference before another change; no mail was submitted.</p><a href=\"/settings?section=copies\">Load saved Copies &amp; Folders</a></main>", if choice { "On" } else { "Off" }))),
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
