//! Account-owned timezone preference; changes presentation, never message bytes.
use super::*;
use crate::timezone::{Error, FixedOffset};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_timezone_update(
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
                .then(|| parse_urlencoded_form(&request.body, 3, 512).ok())
                .flatten();
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Timezone Not Saved",
                    "<p>Reload General settings before saving a timezone.</p>",
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
        let offset = form
            .get("timezone")
            .and_then(|value| FixedOffset::parse(value));
        let result = if form.keys().any(|key| {
            !matches!(
                key.as_str(),
                "csrf_token" | "expected_revision" | "timezone"
            )
        }) {
            Err(Error::Invalid)
        } else {
            match (revision, offset) {
                (Some(revision), Some(offset)) => self
                    .gateway
                    .save_timezone(&session, revision, offset)
                    .and_then(|saved| {
                        if revision.checked_add(1) == Some(saved.revision) && saved.offset == offset
                        {
                            Ok(saved)
                        } else {
                            Err(Error::Unconfirmed)
                        }
                    }),
                _ => Err(Error::Invalid),
            }
        };
        audit_events.push(build_http_info_event(
            if result.is_ok() {
                "timezone_saved"
            } else {
                "timezone_unconfirmed"
            },
            "account timezone preference evaluated",
            context,
        ));
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", "/settings?section=general&updated=1"),
            Err(error) => html_response(match error { Error::Invalid => 400, Error::Stale => 409, Error::Unavailable | Error::Unconfirmed => 503 }, "Timezone Not Confirmed", "Timezone Not Confirmed", "<p>The save could not be confirmed. <a href=\"/settings?section=general\">Reload saved General settings</a> before another change.</p>"),
        };
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}
