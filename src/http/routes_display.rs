//! Account-scoped presentation preferences; never a mail/security policy.
use super::*;
use crate::appearance::{AppearanceSettings, Density, FontSize, ReaderLayout};

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_display_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(result) => result,
            Err(response) => return response,
        };
        let rejected = |status, reason, message| HandledHttpResponse {
            response: html_response(status, reason, "Appearance Not Saved", message),
            audit_events: vec![build_http_warning_event(
                "http_display_update_rejected",
                "display preferences were not saved",
                context,
            )],
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return rejected(
                400,
                "Bad Request",
                "<p>The appearance form content type was not supported.</p>",
            );
        }
        let form = match parse_urlencoded_form(&request.body, 7, 1024) {
            Ok(form) => form,
            Err(_) => return rejected(
                400,
                "Bad Request",
                "<p>The appearance form could not be read. Return to Appearance and try again.</p>",
            ),
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
            "appearance",
            "density",
            "font_size",
            "reader_layout",
            "show_avatars",
            "message_preview",
        ];
        if form.keys().any(|key| !allowed.contains(&key.as_str())) {
            return rejected(
                400,
                "Bad Request",
                "<p>The appearance form contained an unsupported field.</p>",
            );
        }
        let checkbox = |name: &str| match form.get(name).map(String::as_str) {
            None => Some(false),
            Some("1") => Some(true),
            _ => None,
        };
        let (
            Some(theme),
            Some(density),
            Some(font_size),
            Some(reader_layout),
            Some(show_avatars),
            Some(message_preview),
        ) = (
            form.get("appearance")
                .and_then(|value| AppearancePreference::parse(value)),
            form.get("density").and_then(|value| Density::parse(value)),
            form.get("font_size")
                .and_then(|value| FontSize::parse(value)),
            form.get("reader_layout")
                .and_then(|value| ReaderLayout::parse(value)),
            checkbox("show_avatars"),
            checkbox("message_preview"),
        )
        else {
            return rejected(400, "Bad Request", "<p>Choose the supported appearance options. Your saved preferences were not changed.</p>");
        };
        let preferences = AppearanceSettings {
            theme,
            density,
            font_size,
            reader_layout,
            show_avatars,
            message_preview,
        };
        if self
            .gateway
            .update_display(context, &session, preferences)
            .is_err()
        {
            audit_events.push(build_http_warning_event(
                "http_display_save_unconfirmed",
                "display preference save could not be confirmed",
                context,
            ));
            return HandledHttpResponse { response: html_response(503, "Service Unavailable", "Appearance Save Unconfirmed", "<p>Your appearance preference save could not be confirmed. <a href=\"/settings?section=appearance\">Review your stored Appearance settings</a> before trying again.</p>"), audit_events };
        }
        audit_events.push(build_http_info_event(
            "http_display_updated",
            "display preferences saved",
            context,
        ));
        HandledHttpResponse {
            response: redirect_response(
                303,
                "See Other",
                "/settings?section=appearance&appearance_updated=1",
            )
            .with_header(
                "Set-Cookie",
                theme.cookie(self.policy.secure_session_cookie),
            )
            .with_header(
                "Set-Cookie",
                preferences.cookie(self.policy.secure_session_cookie),
            ),
            audit_events,
        }
    }
}
