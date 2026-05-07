//! Draft route handlers for the bounded browser runtime.

use super::*;

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// Serves the authenticated user's draft list.
    pub(super) fn handle_draft_list(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let success_message = match request.query_params.get("saved").map(String::as_str) {
            Some("1") => Some("Draft saved."),
            _ if request.query_params.get("deleted").map(String::as_str) == Some("1") => {
                Some("Draft deleted.")
            }
            _ => None,
        };

        let outcome = self.gateway.list_drafts(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftListDecision::Listed {
                canonical_username,
                drafts,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Drafts",
                    &render_draft_list_page(&DraftListPageModel {
                        canonical_username: &canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message,
                        error_message: None,
                        drafts: &drafts,
                    }),
                ),
                audit_events,
            },
            BrowserDraftListDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Drafts Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Resumes one authenticated draft into the compose form.
    pub(super) fn handle_draft_resume(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let Some(draft_id) = request.query_params.get("id").map(String::as_str) else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Draft Request",
                    "<p>A draft id is required.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_draft_resume_missing_id",
                    "draft resume request missing id",
                    context,
                )],
            };
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let outcome = self
            .gateway
            .load_draft(context, &validated_session, draft_id);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftLoadDecision::Loaded { draft, .. } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Resume Draft",
                    &render_compose_page(&ComposePageModel {
                        heading: "Resume Draft",
                        canonical_username: &validated_session.record.canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message: None,
                        error_message: None,
                        context_notice: None,
                        to_value: &draft.request.recipients.join(", "),
                        subject_value: &draft.request.subject,
                        body_value: &draft.request.body,
                        draft_id: Some(&draft.draft_id),
                        draft_attachment_count: draft.request.attachments.len(),
                    }),
                ),
                audit_events,
            },
            BrowserDraftLoadDecision::NotFound => HandledHttpResponse {
                response: html_response(
                    404,
                    "Not Found",
                    "Draft Not Found",
                    "<p>The requested draft was not found.</p>",
                ),
                audit_events,
            },
            BrowserDraftLoadDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Draft Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles CSRF-bound draft saves from the compose form.
    pub(super) fn handle_draft_save(
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
                        "Invalid Draft Request",
                        "<p>The draft form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_draft_save_parse_failed",
                        "draft save form parsing failed",
                        context,
                    )
                    .with_field("reason", error.reason)],
                };
            }
        };
        let form = parsed_form.fields;

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

        let recipients = form.get("to").cloned().unwrap_or_default();
        let subject = form.get("subject").cloned().unwrap_or_default();
        let body = form.get("body").cloned().unwrap_or_default();
        let draft_id = form.get("draft_id").map(String::as_str);
        let outcome = self.gateway.save_draft(
            context,
            &validated_session,
            BrowserDraftSaveRequest {
                draft_id,
                recipients: &recipients,
                subject: &subject,
                body: &body,
                attachments: &parsed_form.attachments,
            },
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftSaveDecision::Saved { draft_id } => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    &format!("/draft?id={}", url_encode(&draft_id)),
                ),
                audit_events,
            },
            BrowserDraftSaveDecision::Denied { public_reason } => {
                let (status_code, reason_phrase) = if public_reason == "invalid_request" {
                    (400, "Bad Request")
                } else {
                    (503, "Service Unavailable")
                };
                HandledHttpResponse {
                    response: html_response(
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
                            draft_id,
                            draft_attachment_count: 0,
                        }),
                    ),
                    audit_events,
                }
            }
        }
    }

    /// Handles CSRF-bound draft deletion.
    pub(super) fn handle_draft_delete(
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
                    "Invalid Draft Request",
                    "<p>The draft delete form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_draft_delete_content_type_rejected",
                    "draft delete form content type was not supported",
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
                        "Invalid Draft Request",
                        "<p>The draft delete form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_draft_delete_parse_failed",
                        "draft delete form parsing failed",
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
        let Some(draft_id) = form.get("draft_id").map(String::as_str) else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Draft Request",
                    "<p>A draft id is required.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_draft_delete_missing_id",
                    "draft delete request missing id",
                    context,
                )],
            };
        };

        let outcome = self
            .gateway
            .delete_draft(context, &validated_session, draft_id);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftDeleteDecision::Deleted | BrowserDraftDeleteDecision::NotFound => {
                HandledHttpResponse {
                    response: redirect_response(303, "See Other", "/drafts?deleted=1"),
                    audit_events,
                }
            }
            BrowserDraftDeleteDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Draft Delete Failed",
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
