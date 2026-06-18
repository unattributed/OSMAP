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
                    render_draft_list_page(&DraftListPageModel {
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
                    TrustedHtml::from_template(format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    )),
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
            BrowserDraftLoadDecision::Loaded { draft, .. } => {
                let mut source_attachments = Vec::new();
                if let Some(source) = &draft.source_attachments {
                    let source_outcome = self.gateway.view_message(
                        context,
                        &validated_session,
                        &source.mailbox_name,
                        source.uid,
                    );
                    audit_events.extend(source_outcome.audit_events);
                    match source_outcome.decision {
                        BrowserMessageViewDecision::Rendered { rendered, .. } => {
                            if source.part_paths.iter().any(|selected| {
                                !rendered
                                    .attachments
                                    .iter()
                                    .any(|attachment| &attachment.part_path == selected)
                            }) {
                                return HandledHttpResponse {
                                    response: html_response(
                                        409,
                                        "Conflict",
                                        "Draft Source Changed",
                                        "<p>One or more selected source attachments are no longer available. The draft was not changed or sent.</p>",
                                    ),
                                    audit_events,
                                };
                            }
                            source_attachments = rendered.attachments;
                        }
                        BrowserMessageViewDecision::Denied { .. } => {
                            return HandledHttpResponse {
                                response: html_response(
                                    503,
                                    "Service Unavailable",
                                    "Draft Source Unavailable",
                                    "<p>The source message for this draft could not be revalidated safely. The draft was not changed or sent.</p>",
                                ),
                                audit_events,
                            };
                        }
                    }
                }
                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Resume Draft",
                        render_compose_page(&ComposePageModel {
                            heading: "Resume Draft",
                            canonical_username: &validated_session.record.canonical_username,
                            csrf_token: &validated_session.record.csrf_token,
                            success_message: None,
                            error_message: None,
                            context_notice: draft.source_attachments.as_ref().map(|_| {
                                "Only the source attachments explicitly selected when this draft was saved remain selected."
                            }),
                            to_value: &draft.request.recipients.join(", "),
                            subject_value: &draft.request.subject,
                            body_value: &draft.request.body,
                            draft_id: Some(&draft.draft_id),
                            draft_attachment_count: draft.request.attachments.len(),
                            source_mailbox_name: draft
                                .source_attachments
                                .as_ref()
                                .map(|source| source.mailbox_name.as_str()),
                            source_uid: draft
                                .source_attachments
                                .as_ref()
                                .map(|source| source.uid),
                            source_attachments: &source_attachments,
                            selected_source_part_paths: draft
                                .source_attachments
                                .as_ref()
                                .map(|source| source.part_paths.as_slice())
                                .unwrap_or_default(),
                        }),
                    ),
                    audit_events,
                }
            }
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
                    TrustedHtml::from_template(format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    )),
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
        let selected_source_parts =
            match super::routes_compose::selected_original_attachment_parts(&form) {
                Ok(parts) => parts,
                Err(reason) => {
                    return HandledHttpResponse {
                        response: html_response(
                            400,
                            "Bad Request",
                            "Invalid Draft Request",
                            "<p>The selected source attachments were not valid.</p>",
                        ),
                        audit_events: vec![build_http_warning_event(
                            "http_draft_source_selection_rejected",
                            "draft source attachment selection validation failed",
                            context,
                        )
                        .with_field("reason", reason)],
                    };
                }
            };
        let source_attachments = if selected_source_parts.is_empty() {
            None
        } else {
            let Some(source_mailbox) = form
                .get("source_mailbox")
                .filter(|mailbox| !mailbox.is_empty())
                .cloned()
            else {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Draft Request",
                        "<p>The selected source attachments were missing a source mailbox.</p>",
                    ),
                    audit_events,
                };
            };
            let Some(source_uid) = form
                .get("source_uid")
                .and_then(|uid| uid.parse::<u64>().ok())
            else {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Draft Request",
                        "<p>The selected source attachments were missing a valid source UID.</p>",
                    ),
                    audit_events,
                };
            };
            let source_outcome =
                self.gateway
                    .view_message(context, &validated_session, &source_mailbox, source_uid);
            audit_events.extend(source_outcome.audit_events);
            match source_outcome.decision {
                BrowserMessageViewDecision::Rendered { rendered, .. }
                    if selected_source_parts.iter().all(|selected| {
                        rendered
                            .attachments
                            .iter()
                            .any(|attachment| &attachment.part_path == selected)
                    }) =>
                {
                    Some(DraftSourceAttachments {
                        mailbox_name: source_mailbox,
                        uid: source_uid,
                        part_paths: selected_source_parts,
                    })
                }
                BrowserMessageViewDecision::Rendered { .. } => {
                    return HandledHttpResponse {
                        response: html_response(
                            409,
                            "Conflict",
                            "Draft Source Changed",
                            "<p>One or more selected source attachments could not be revalidated. The draft was not saved.</p>",
                        ),
                        audit_events,
                    };
                }
                BrowserMessageViewDecision::Denied { .. } => {
                    return HandledHttpResponse {
                        response: html_response(
                            503,
                            "Service Unavailable",
                            "Draft Source Unavailable",
                            "<p>The source message could not be revalidated safely. The draft was not saved.</p>",
                        ),
                        audit_events,
                    };
                }
            }
        };
        let outcome = self.gateway.save_draft(
            context,
            &validated_session,
            BrowserDraftSaveRequest {
                draft_id,
                recipients: &recipients,
                subject: &subject,
                body: &body,
                attachments: &parsed_form.attachments,
                source_attachments: source_attachments.as_ref(),
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
                        render_compose_page(&ComposePageModel {
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
                            source_mailbox_name: None,
                            source_uid: None,
                            source_attachments: &[],
                            selected_source_part_paths: &[],
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
                    TrustedHtml::from_template(format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    )),
                ),
                audit_events,
            },
        }
    }
}
