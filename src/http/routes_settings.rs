//! End-user settings route handlers for the bounded browser runtime.
//!
//! This first settings slice stays intentionally small and CSRF-bound so OSMAP
//! can expose one useful preference without becoming a broad preference UI.

use super::*;

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// Serves the current bounded settings page.
    pub(super) fn handle_settings_page(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let success_message =
            if request.query_params.get("updated").map(String::as_str) == Some("1") {
                Some("Settings were updated.")
            } else {
                None
            };

        let outcome = self.gateway.load_settings(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSettingsDecision::Loaded {
                canonical_username,
                settings,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Settings",
                    &render_settings_page(&SettingsPageModel {
                        canonical_username: &canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message,
                        error_message: None,
                        html_display_preference: settings.html_display_preference,
                    }),
                ),
                audit_events,
            },
            BrowserSettingsDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Settings Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles CSRF-bound end-user settings updates.
    pub(super) fn handle_settings_update(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Settings Request",
                    "<p>The settings form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_settings_content_type_rejected",
                    "settings form content type was not supported",
                    context,
                )],
            };
        }

        let form = match parse_urlencoded_form(
            &request.body,
            self.policy.max_form_fields,
            self.policy.max_body_bytes,
        ) {
            Ok(form) => form,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>The settings form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_settings_parse_failed",
                        "settings form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        if let Some(response) = self.require_valid_csrf(
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }

        let Some(html_display_preference) = form.get("html_display_preference") else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Settings Request",
                    "<p>An HTML display preference is required.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_settings_missing_preference",
                    "settings update missing html display preference",
                    context,
                )],
            };
        };

        let html_display_preference = match HtmlDisplayPreference::parse(html_display_preference) {
            Ok(html_display_preference) => html_display_preference,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>The submitted HTML display preference was not valid.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_settings_preference_rejected",
                        "settings update preference validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        let outcome =
            self.gateway
                .update_settings(context, &validated_session, html_display_preference);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSettingsUpdateDecision::Updated => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/settings?updated=1"),
                audit_events,
            },
            BrowserSettingsUpdateDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Settings Update Failed",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }
}
