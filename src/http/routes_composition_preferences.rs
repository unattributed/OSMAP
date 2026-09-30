use super::*;
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_composition_preferences_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let rejected = |status, reason, message| HandledHttpResponse {
            response: html_response(status, reason, "Composition Preference Not Saved", message),
            audit_events: vec![build_http_warning_event(
                "composition_preference_rejected",
                "composition preference was not confirmed",
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
        let form = match parse_urlencoded_form(&request.body, 2, 512) {
            Ok(value) => value,
            Err(_) => {
                return rejected(
                    400,
                    "Bad Request",
                    "<p>The preference form was invalid.</p>",
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
        if form
            .keys()
            .any(|key| !["csrf_token", "default_body_format"].contains(&key.as_str()))
        {
            return rejected(
                400,
                "Bad Request",
                "<p>The preference form contained an unsupported field.</p>",
            );
        }
        let Some(value) = form.get("default_body_format").and_then(|value| {
            crate::composition_preferences::CompositionPreferences::parse_default_format(value)
        }) else {
            return rejected(
                400,
                "Bad Request",
                "<p>Choose Plain text or Formatted text.</p>",
            );
        };
        if self
            .gateway
            .update_composition_preferences(context, &session, value)
            .is_err()
        {
            return rejected(503, "Service Unavailable", "<p>The preference save could not be confirmed. Review your saved setting before retrying.</p>");
        }
        audit_events.push(build_http_info_event(
            "composition_preference_saved",
            "default composition format saved",
            context,
        ));
        HandledHttpResponse {
            response: redirect_response(303, "See Other", "/settings?section=general&updated=1"),
            audit_events,
        }
    }
}
