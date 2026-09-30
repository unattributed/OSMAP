//! Presentation preference writes retain the authenticated form boundary.

use super::*;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_appearance_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let failure = |status, reason, message| HandledHttpResponse {
            response: html_response(status, reason, "Appearance Not Saved", message),
            audit_events: vec![build_http_warning_event(
                "http_appearance_update_rejected",
                "appearance update was not saved",
                context,
            )],
        };
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return failure(
                400,
                "Bad Request",
                "<p>The appearance form content type was not supported.</p>",
            );
        }
        let form = match parse_urlencoded_form(&request.body, 2, 512) {
            Ok(form) => form,
            Err(_) => return failure(
                400,
                "Bad Request",
                "<p>The appearance form could not be read. Return to Settings and try again.</p>",
            ),
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }
        let Some(appearance) = form
            .get("appearance")
            .and_then(|value| AppearancePreference::parse(value))
        else {
            return failure(
                400,
                "Bad Request",
                "<p>Choose Light, Dark or System in Settings.</p>",
            );
        };
        if self
            .gateway
            .update_appearance(context, &validated_session, appearance)
            .is_err()
        {
            audit_events.push(build_http_warning_event(
                "http_appearance_save_unconfirmed",
                "appearance preference save could not be confirmed",
                context,
            ));
            return HandledHttpResponse { response: html_response(503, "Service Unavailable", "Appearance Save Unconfirmed", "<p>Your appearance preference could not be confirmed. <a href=\"/settings?section=appearance\">Review your saved preference</a> before trying again.</p>"), audit_events };
        }
        audit_events.push(build_http_info_event(
            "http_appearance_updated",
            "appearance preference saved",
            context,
        ));
        HandledHttpResponse {
            response: redirect_response(303, "See Other", "/settings?appearance_updated=1")
                .with_header(
                    "Set-Cookie",
                    appearance.cookie(self.policy.secure_session_cookie),
                ),
            audit_events,
        }
    }
}
