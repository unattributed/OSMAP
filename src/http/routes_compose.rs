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
        let mut source_mailbox_name: Option<String> = None;
        let mut source_uid: Option<u64> = None;
        let mut source_attachments = Vec::new();

        match compose_source_from_request(request) {
            Ok(Some((intent, mailbox_name, uid))) => {
                let (budget_guard, budget_event) = match self.acquire_mailbox_budget(
                    context,
                    &validated_session,
                    "compose_source",
                ) {
                    Ok(result) => result,
                    Err(mut response) => {
                        audit_events.extend(response.audit_events);
                        response.audit_events = audit_events;
                        return response;
                    }
                };
                audit_events.push(budget_event);

                let outcome =
                    self.gateway
                        .view_message(context, &validated_session, &mailbox_name, uid);
                audit_events.extend(outcome.audit_events);
                audit_events.push(self.release_request_budget(
                    budget_guard,
                    "compose_source",
                    context,
                    &validated_session,
                ));

                match outcome.decision {
                    BrowserMessageViewDecision::Rendered { rendered, .. } => {
                        let draft = match ComposeDraft::from_rendered_message(
                            ComposePolicy::default(),
                            intent,
                            &rendered,
                        ) {
                            Ok(draft) => draft,
                            Err(error) => {
                                audit_events.push(
                                    build_http_warning_event(
                                        "compose_draft_failed",
                                        "compose draft generation failed",
                                        context,
                                    )
                                    .with_field("reason", error.reason),
                                );
                                return HandledHttpResponse {
                                    response: html_response(
                                        503,
                                        "Service Unavailable",
                                        "Compose Unavailable",
                                        "<p>The compose draft could not be prepared safely.</p>",
                                    ),
                                    audit_events,
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
                        if !rendered.attachments.is_empty() {
                            source_mailbox_name = Some(mailbox_name);
                            source_uid = Some(uid);
                            source_attachments = rendered.attachments;
                        }
                    }
                    BrowserMessageViewDecision::Denied { public_reason } => {
                        return HandledHttpResponse {
                            response: html_response(
                                503,
                                "Service Unavailable",
                                "Compose Unavailable",
                                TrustedHtml::from_template(format!(
                                    "<p>{}</p>",
                                    escape_html(public_reason_message(&public_reason))
                                )),
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
                render_compose_page(&ComposePageModel {
                    heading: compose_heading,
                    canonical_username: &validated_session.record.canonical_username,
                    csrf_token: &validated_session.record.csrf_token,
                    success_message,
                    error_message: None,
                    context_notice: context_notice.as_deref(),
                    to_value: &to_value,
                    subject_value: &subject_value,
                    body_value: &body_value,
                    draft_id: None,
                    draft_attachment_count: 0,
                    source_mailbox_name: source_mailbox_name.as_deref(),
                    source_uid,
                    source_attachments: &source_attachments,
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
                let public_body =
                    TrustedHtml::from_template(compose_form_parse_failure_body(&error.reason));
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        public_body,
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
        let original_attachment_parts = match selected_original_attachment_parts(&form) {
            Ok(parts) => parts,
            Err(reason) => {
                audit_events.push(
                    build_http_warning_event(
                        "http_send_original_attachment_selection_rejected",
                        "original attachment selection validation failed",
                        context,
                    )
                    .with_field("reason", reason),
                );
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>The selected source attachments were not valid.</p>",
                    ),
                    audit_events,
                };
            }
        };
        let draft_id = form
            .get("draft_id")
            .filter(|value| !value.trim().is_empty())
            .cloned();
        let mut send_attachments = attachments;
        if !original_attachment_parts.is_empty() {
            if send_attachments.len() + original_attachment_parts.len()
                > ComposePolicy::default().max_attachments
            {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>The selected attachments exceeded the compose attachment count limit.</p>",
                    ),
                    audit_events,
                };
            }

            let source_mailbox = match form.get("source_mailbox").filter(|value| !value.is_empty())
            {
                Some(source_mailbox) => source_mailbox.clone(),
                None => {
                    return HandledHttpResponse {
                        response: html_response(
                            400,
                            "Bad Request",
                            "Invalid Compose Request",
                            "<p>The selected source attachments were missing a source mailbox.</p>",
                        ),
                        audit_events,
                    };
                }
            };
            let source_uid = match form.get("source_uid").and_then(|value| value.parse().ok()) {
                Some(source_uid) => source_uid,
                None => {
                    return HandledHttpResponse {
                        response: html_response(
                            400,
                            "Bad Request",
                            "Invalid Compose Request",
                            "<p>The selected source attachments were missing a valid source UID.</p>",
                        ),
                        audit_events,
                    };
                }
            };

            let (budget_guard, budget_event) = match self.acquire_mailbox_budget(
                context,
                &validated_session,
                "original_attachment_send",
            ) {
                Ok(result) => result,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
            audit_events.push(budget_event);

            for part_path in &original_attachment_parts {
                let download_outcome = self.gateway.download_attachment(
                    context,
                    &validated_session,
                    &source_mailbox,
                    source_uid,
                    part_path,
                );
                audit_events.extend(download_outcome.audit_events);
                match download_outcome.decision {
                    BrowserAttachmentDownloadDecision::Downloaded { attachment, .. } => {
                        match UploadedAttachment::new(
                            ComposePolicy::default(),
                            attachment.filename,
                            attachment.content_type,
                            attachment.body,
                        ) {
                            Ok(attachment) => send_attachments.push(attachment),
                            Err(error) => {
                                audit_events.push(self.release_request_budget(
                                    budget_guard,
                                    "original_attachment_send",
                                    context,
                                    &validated_session,
                                ));
                                return HandledHttpResponse {
                                    response: html_response(
                                        400,
                                        "Bad Request",
                                        "Invalid Compose Request",
                                        "<p>A selected source attachment exceeded the compose limits.</p>",
                                    ),
                                    audit_events: {
                                        audit_events.push(
                                            build_http_warning_event(
                                                "http_send_original_attachment_rejected",
                                                "original attachment rejected before send",
                                                context,
                                            )
                                            .with_field("reason", error.reason),
                                        );
                                        audit_events
                                    },
                                };
                            }
                        }
                    }
                    BrowserAttachmentDownloadDecision::Denied { public_reason } => {
                        audit_events.push(self.release_request_budget(
                            budget_guard,
                            "original_attachment_send",
                            context,
                            &validated_session,
                        ));
                        return HandledHttpResponse {
                            response: html_response(
                                503,
                                "Service Unavailable",
                                "Compose Unavailable",
                                "<p>A selected source attachment could not be fetched safely.</p>",
                            ),
                            audit_events: {
                                audit_events.push(
                                    build_http_warning_event(
                                        "http_send_original_attachment_fetch_failed",
                                        "original attachment fetch failed before send",
                                        context,
                                    )
                                    .with_field("public_reason", public_reason),
                                );
                                audit_events
                            },
                        };
                    }
                }
            }
            audit_events.push(self.release_request_budget(
                budget_guard,
                "original_attachment_send",
                context,
                &validated_session,
            ));
        }
        let mut persisted_draft_attachment_count = 0;
        if let Some(draft_id) = draft_id.as_deref() {
            let draft_outcome = self
                .gateway
                .load_draft(context, &validated_session, draft_id);
            audit_events.extend(draft_outcome.audit_events);
            match draft_outcome.decision {
                BrowserDraftLoadDecision::Loaded { draft, .. } => {
                    let mut persisted = draft.request.attachments.clone();
                    persisted_draft_attachment_count = persisted.len();
                    persisted.extend(send_attachments);
                    send_attachments = persisted;
                }
                BrowserDraftLoadDecision::NotFound => {
                    return HandledHttpResponse {
                        response: html_response(
                            404,
                            "Not Found",
                            "Draft Not Found",
                            "<p>The draft selected for sending was not found.</p>",
                        ),
                        audit_events,
                    };
                }
                BrowserDraftLoadDecision::Denied { public_reason } => {
                    return HandledHttpResponse {
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
                    };
                }
            }
        }
        let (budget_guard, budget_event) =
            match self.acquire_send_budget(context, &validated_session) {
                Ok(result) => result,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
        audit_events.push(budget_event);

        let outcome = self.gateway.send_message(
            context,
            &validated_session,
            &recipients,
            &subject,
            &body,
            &send_attachments,
        );
        audit_events.extend(outcome.audit_events);

        let mut handled = match outcome.decision {
            BrowserSendDecision::Submitted => {
                if let Some(draft_id) = draft_id.as_deref() {
                    let delete_outcome =
                        self.gateway
                            .delete_draft(context, &validated_session, draft_id);
                    audit_events.extend(delete_outcome.audit_events);
                }
                HandledHttpResponse {
                    response: redirect_response(303, "See Other", "/compose?sent=1"),
                    audit_events,
                }
            }
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
                        draft_id: draft_id.as_deref(),
                        draft_attachment_count: persisted_draft_attachment_count,
                        source_mailbox_name: None,
                        source_uid: None,
                        source_attachments: &[],
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
        };
        handled.audit_events.push(self.release_request_budget(
            budget_guard,
            "message_send",
            context,
            &validated_session,
        ));
        handled
    }
}

fn compose_form_parse_failure_body(reason: &str) -> String {
    if reason.starts_with("attachment body exceeded maximum length") {
        return format!(
            "<p>One attachment exceeded the {} MiB per-file compose limit.</p>",
            bytes_to_mib(DEFAULT_ATTACHMENT_MAX_BYTES)
        );
    }
    if reason == "form body exceeded maximum length" {
        return "<p>The uploaded compose form exceeded the request size limit.</p>".to_string();
    }
    if reason.starts_with("attachment bytes exceeded maximum") {
        return format!(
            "<p>The selected attachments exceeded the {} MiB total compose limit.</p>",
            bytes_to_mib(DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES)
        );
    }

    "<p>The compose form could not be parsed.</p>".to_string()
}

fn bytes_to_mib(bytes: usize) -> usize {
    bytes / (1024 * 1024)
}

fn selected_original_attachment_parts(
    form: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    for (key, value) in form {
        if !key.starts_with("include_original_attachment_") {
            continue;
        }
        if value.is_empty() {
            return Err("selected original attachment part path was empty".to_string());
        }
        if parts.iter().any(|existing| existing == value) {
            return Err("duplicate original attachment selection".to_string());
        }
        parts.push(value.clone());
    }
    Ok(parts)
}
