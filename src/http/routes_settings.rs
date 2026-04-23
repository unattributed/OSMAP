//! End-user settings route handlers for the bounded browser runtime.
//!
//! This settings slice stays intentionally small and CSRF-bound so OSMAP can
//! expose a few useful preferences without becoming a broad preference UI.

use super::*;
use crate::settings::parse_archive_mailbox_name;

fn mailbox_name_exists(mailboxes: &[MailboxEntry], mailbox_name: &str) -> bool {
    mailboxes.iter().any(|mailbox| mailbox.name == mailbox_name)
}

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
                        archive_mailbox_name: settings.archive_mailbox_name.as_deref(),
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
            request,
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
        let archive_mailbox_name = match parse_archive_mailbox_name(
            form.get("archive_mailbox_name").map(String::as_str),
        ) {
            Ok(archive_mailbox_name) => archive_mailbox_name,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Settings Request",
                        "<p>The submitted archive mailbox name was not valid.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_settings_archive_mailbox_rejected",
                        "settings update archive mailbox validation failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };

        if let Some(archive_mailbox_name) = archive_mailbox_name.as_deref() {
            let mailbox_outcome = self.gateway.list_mailboxes(context, &validated_session);
            audit_events.extend(mailbox_outcome.audit_events);

            match mailbox_outcome.decision {
                BrowserMailboxDecision::Listed { mailboxes, .. } => {
                    if !mailbox_name_exists(&mailboxes, archive_mailbox_name) {
                        return HandledHttpResponse {
                            response: html_response(
                                400,
                                "Bad Request",
                                "Invalid Settings Request",
                                "<p>The selected archive mailbox does not exist for this account.</p>",
                            ),
                            audit_events: {
                                audit_events.push(
                                    build_http_warning_event(
                                        "http_settings_archive_mailbox_missing",
                                        "settings update archive mailbox did not match mailbox listing",
                                        context,
                                    )
                                    .with_field(
                                        "archive_mailbox_name",
                                        archive_mailbox_name.to_string(),
                                    ),
                                );
                                audit_events
                            },
                        };
                    }
                }
                BrowserMailboxDecision::Denied { public_reason } => {
                    return HandledHttpResponse {
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
                    };
                }
            }
        }

        let outcome = self.gateway.update_settings(
            context,
            &validated_session,
            html_display_preference,
            archive_mailbox_name.as_deref(),
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSettingsUpdateDecision::Updated => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/settings?updated=1"),
                audit_events,
            },
            BrowserSettingsUpdateDecision::Denied { public_reason } => {
                let (status_code, reason_phrase, title) = if public_reason == "invalid_request" {
                    (400, "Bad Request", "Invalid Settings Request")
                } else {
                    (503, "Service Unavailable", "Settings Update Failed")
                };
                HandledHttpResponse {
                    response: html_response(
                        status_code,
                        reason_phrase,
                        title,
                        &format!(
                            "<p>{}</p>",
                            escape_html(public_reason_message(&public_reason))
                        ),
                    ),
                    audit_events,
                }
            }
        }
    }
}
