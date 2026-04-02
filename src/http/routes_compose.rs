//! Compose and send route handlers for the bounded browser runtime.
//!
//! Keeping compose and submission flows separate from auth/session, mailbox,
//! and transport code reduces how much browser-side mutation logic remains in
//! `http.rs` without changing the current route surface.

use super::*;

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// Handles the compose form for the validated browser session.
    pub(super) fn handle_compose_form(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let success_message = if request.query_params.get("sent").map(String::as_str) == Some("1") {
            Some("Message submission completed.")
        } else {
            None
        };
        let mut compose_heading = "Compose";
        let mut context_notice: Option<String> = None;
        let mut to_value = String::new();
        let mut subject_value = String::new();
        let mut body_value = String::new();

        match compose_source_from_request(request) {
            Ok(Some((intent, mailbox_name, uid))) => {
                let outcome =
                    self.gateway
                        .view_message(context, &validated_session, &mailbox_name, uid);
                audit_events.extend(outcome.audit_events);

                match outcome.decision {
                    BrowserMessageViewDecision::Rendered { rendered, .. } => {
                        let draft = match ComposeDraft::from_rendered_message(
                            ComposePolicy::default(),
                            intent,
                            &rendered,
                        ) {
                            Ok(draft) => draft,
                            Err(error) => {
                                return HandledHttpResponse {
                                    response: html_response(
                                        503,
                                        "Service Unavailable",
                                        "Compose Unavailable",
                                        "<p>The compose draft could not be prepared safely.</p>",
                                    ),
                                    audit_events: vec![build_http_warning_event(
                                        "compose_draft_failed",
                                        "compose draft generation failed",
                                        context,
                                    )
                                    .with_field("reason", error.reason)],
                                };
                            }
                        };

                        compose_heading = match draft.intent {
                            ComposeIntent::Reply => "Reply",
                            ComposeIntent::Forward => "Forward",
                        };
                        context_notice = draft.context_notice;
                        to_value = draft.to;
                        subject_value = draft.subject;
                        body_value = draft.body;
                    }
                    BrowserMessageViewDecision::Denied { public_reason } => {
                        return HandledHttpResponse {
                            response: html_response(
                                503,
                                "Service Unavailable",
                                "Compose Unavailable",
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
            Ok(None) => {}
            Err(reason) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>The compose reference was not valid.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "compose_reference_rejected",
                        "compose reference validation failed",
                        context,
                    )
                    .with_field("reason", reason)],
                };
            }
        }

        HandledHttpResponse {
            response: html_response(
                200,
                "OK",
                compose_heading,
                &render_compose_page(&ComposePageModel {
                    heading: compose_heading,
                    canonical_username: &validated_session.record.canonical_username,
                    csrf_token: &validated_session.record.csrf_token,
                    success_message,
                    error_message: None,
                    context_notice: context_notice.as_deref(),
                    to_value: &to_value,
                    subject_value: &subject_value,
                    body_value: &body_value,
                }),
            ),
            audit_events,
        }
    }

    /// Handles the current compose/send form submission.
    pub(super) fn handle_send(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let parsed_form = match parse_compose_form(
            &request.body,
            request.headers.get("content-type").map(String::as_str),
            self.policy.max_form_fields,
            self.policy.max_upload_body_bytes,
            ComposePolicy::default(),
        ) {
            Ok(form) => form,
            Err(error) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>The compose form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_send_parse_failed",
                        "compose form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };
        let form = parsed_form.fields;
        let attachments = parsed_form.attachments;

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

        let recipients = form.get("to").cloned().unwrap_or_default();
        let subject = form.get("subject").cloned().unwrap_or_default();
        let body = form.get("body").cloned().unwrap_or_default();
        let outcome = self.gateway.send_message(
            context,
            &validated_session,
            &recipients,
            &subject,
            &body,
            &attachments,
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserSendDecision::Submitted => HandledHttpResponse {
                response: redirect_response(303, "See Other", "/compose?sent=1"),
                audit_events,
            },
            BrowserSendDecision::Denied {
                public_reason,
                retry_after_seconds,
            } => {
                let (status_code, reason_phrase) = if public_reason == "invalid_request" {
                    (400, "Bad Request")
                } else if public_reason == TOO_MANY_SUBMISSIONS_PUBLIC_REASON {
                    (429, "Too Many Requests")
                } else {
                    (503, "Service Unavailable")
                };
                let mut response = html_response(
                    status_code,
                    reason_phrase,
                    "Compose",
                    &render_compose_page(&ComposePageModel {
                        heading: "Compose",
                        canonical_username: &validated_session.record.canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message: None,
                        error_message: Some(public_reason_message(&public_reason)),
                        context_notice: None,
                        to_value: &recipients,
                        subject_value: &subject,
                        body_value: &body,
                    }),
                );
                if let Some(retry_after_seconds) = retry_after_seconds {
                    response = response.with_header("Retry-After", retry_after_seconds.to_string());
                }
                HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
        }
    }
}
