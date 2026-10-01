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

        if let Some(intent) = request.query_params.get("receipt") {
            let response = if !crate::send_journal::receipt_intent_valid(intent)
                || request.query_params.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "receipt" | "recovery_attachment" | "recovery_body"
                    )
                })
                || request
                    .query_params
                    .get("recovery_body")
                    .is_some_and(|value| value != "1")
                || request.query_params.contains_key("recovery_body")
                    && request.query_params.contains_key("recovery_attachment")
            {
                html_response(
                    400,
                    "Bad Request",
                    "Invalid recovery request",
                    "<p>Use the existing attempt receipt link.</p>",
                )
            } else if request.query_params.contains_key("recovery_body") {
                self.recovery_body_response(&validated_session, intent)
            } else if let Some(index) = request.query_params.get("recovery_attachment") {
                self.recovery_attachment_response(&validated_session, intent, index)
            } else {
                self.send_receipt_response(context, &validated_session, intent)
            };
            return HandledHttpResponse {
                response,
                audit_events,
            };
        }
        if request.query_params.contains_key("recovery_attachment")
            || request.query_params.contains_key("recovery_body")
        {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Receipt required",
                    "<p>An owned attempt receipt is required.</p>",
                ),
                audit_events,
            };
        }
        if request.query_params.contains_key("sent") {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Receipt required",
                    "<p>A query flag is not a submission receipt.</p>",
                ),
                audit_events,
            };
        }
        let send_intent = match crate::send_journal::mint_intent(self.gateway.send_clock()) {
            Ok(value) => value,
            Err(_) => {
                return HandledHttpResponse {
                    response: html_response(
                        503,
                        "Service Unavailable",
                        "Compose unavailable",
                        "<p>A send intent could not be created.</p>",
                    ),
                    audit_events,
                }
            }
        };
        let success_message = None;
        let mut compose_heading = "Compose";
        let mut context_notice: Option<String> = None;
        let mut to_value = String::new();
        let mut cc_value = String::new();
        let bcc_value = String::new();
        let mut subject_value = String::new();
        let mut body_value = String::new();
        let mut signature_placement = crate::signature::InitialPlacement::Blank;
        let mut body_format = crate::compose_format::BodyFormat::Plain;
        let mut source_mailbox_name: Option<String> = None;
        let mut source_uid: Option<u64> = None;
        let mut source_version = None;
        let mut source_attachments = Vec::new();
        let mut reply_reference = None;
        let expected_version = match super::routes_reply::query_version(&request.query_params) {
            Ok(value) => value,
            Err(_) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Compose Request",
                        "<p>Open a current reply or forward link from the reader.</p>",
                    ),
                    audit_events,
                }
            }
        };

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
                    BrowserMessageViewDecision::Rendered { canonical_username, rendered }
                        if canonical_username == validated_session.record.canonical_username && rendered.mailbox_name == mailbox_name && rendered.uid == uid
                            && expected_version.as_ref().is_none_or(|expected| rendered.metadata.as_ref().is_some_and(|metadata| &metadata.version == expected)) => {
                        let draft = match ComposeDraft::for_sender(
                            ComposePolicy::default(),
                            intent,
                            &rendered,
                            &validated_session.record.canonical_username,
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
                            ComposeIntent::ReplyAll => "Reply all",
                            ComposeIntent::Forward => "Forward",
                        };
                        context_notice = Some(match draft.context_notice {
                            Some(notice) if !notice.is_empty() => format!("{notice} Replies and forwards start in Plain text to preserve quoted message text. Choosing Formatted text can interpret formatting marks in the quote."),
                            _ => "Replies and forwards start in Plain text to preserve quoted message text. Choosing Formatted text can interpret formatting marks in the quote.".to_owned(),
                        });
                        to_value = draft.to;
                        cc_value = draft.cc;
                        subject_value = draft.subject;
                        body_value = draft.body;
                        signature_placement = crate::signature::InitialPlacement::AboveQuote;
                        if intent != ComposeIntent::Forward {
                            match self.gateway.load_composition_preferences(context, &validated_session) {
                                Ok(preferences) => {
                                    let Some(placed) = preferences.reply_placement.initial_reply_body(&body_value) else {
                                        return HandledHttpResponse { response: html_response(503, "Service Unavailable", "Reply Placement Unavailable", "<p>The reply layout could not be prepared safely.</p>"), audit_events };
                                    };
                                    body_value = placed;
                                    if preferences.reply_placement == crate::composition_preferences::ReplyPlacement::Below {
                                        signature_placement = crate::signature::InitialPlacement::BelowQuote;
                                        context_notice.get_or_insert_with(String::new).push_str(" Reply space is below the quoted text. Move to the end of the message before typing; the cursor is not moved automatically.");
                                    }
                                }
                                Err(_) => context_notice.get_or_insert_with(String::new).push_str(" Your saved reply placement could not be loaded. Reply space is above the quoted text."),
                            }
                        }
                        if intent != ComposeIntent::Forward {
                            reply_reference = rendered.metadata.as_ref().and_then(|metadata|
                                crate::reply_thread::ReplyReference::new(mailbox_name.clone(), uid, metadata.version.clone()).ok());
                        }
                        if !rendered.attachments.is_empty() && rendered.metadata.is_some() {
                            source_version = rendered.metadata.as_ref().map(|metadata| metadata.version.clone());
                            source_mailbox_name = Some(mailbox_name);
                            source_uid = Some(uid);
                            source_attachments = rendered.attachments;
                        }
                    }
                    BrowserMessageViewDecision::Rendered { .. } => return HandledHttpResponse {
                        response: html_response(409, "Conflict", "Compose Source Changed", "<p>The original message changed. Open a fresh reply or forward from the reader.</p>"), audit_events,
                    },
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
            Ok(None) => {
                body_format = match self.gateway.load_composition_preferences(context, &validated_session) {
                    Ok(value) => value.default_body_format,
                    Err(_) => return HandledHttpResponse { response: html_response(503, "Service Unavailable", "Composition Preferences Unavailable", "<p>Your default composition format could not be loaded. No draft was changed.</p>"), audit_events },
                };
            }
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

        let signature_notice = match self.gateway.load_signature(&validated_session) {
            Ok(record) => match crate::signature::initial_body(&record,&body_value,body_format,signature_placement) { Ok(Some(body)) => {body_value=body;None},Ok(None)=>None,Err(notice)=>Some(notice) },
            Err(_) => Some("Your saved signature is unavailable. No signature was inserted; the prepared message text is unchanged."),
        };
        if let Some(notice) = signature_notice {
            context_notice
                .get_or_insert_with(String::new)
                .push_str(&format!(" {notice}"));
        }
        HandledHttpResponse {
            response: super::compose_enhancement::response(
                200,
                "OK",
                compose_heading,
                self.render_protected_compose_page(
                    &validated_session,
                    ComposePageModel {
                        protection: crate::send::ProtectionIntent::default(),
                        openpgp: None,
                        sender_identity: self
                            .gateway
                            .load_identity_preferences(context, &validated_session)
                            .ok()
                            .as_ref()
                            .map(|profile| &profile.preferences),
                        send_intent: &send_intent,
                        contacts: self.contact_snapshot(&validated_session).ok().as_ref(),
                        reply_reference: reply_reference.as_ref(),
                        heading: compose_heading,
                        canonical_username: &validated_session.record.canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message,
                        error_message: None,
                        context_notice: context_notice.as_deref(),
                        to_value: &to_value,
                        cc_value: &cc_value,
                        bcc_value: &bcc_value,
                        subject_value: &subject_value,
                        body_value: &body_value,
                        body_format,
                        preview: false,
                        preflight: false,
                        draft_id: None,
                        draft_revision: None,
                        draft_attachments: &[],
                        removed_attachment_indices: &[],
                        source_mailbox_name: source_mailbox_name.as_deref(),
                        source_uid,
                        source_version: source_version.as_ref(),
                        source_attachments: &source_attachments,
                        selected_source_part_paths: &[],
                    },
                ),
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
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let parsed_form = match parse_compose_form(
            &request.body,
            request.headers.get("content-type").map(String::as_str),
            self.policy.max_form_fields.saturating_add(17),
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

        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }

        let protection = match super::compose_protection::intent_from_form(&form) {
            Ok(intent) => intent,
            Err(message) => {
                return HandledHttpResponse {
                    response: self.retained_compose_input_error(
                        &validated_session,
                        &form,
                        None,
                        message,
                    ),
                    audit_events,
                }
            }
        };

        if let Some(response) =
            self.intent_guard_response(context, &validated_session, &form, &attachments)
        {
            return HandledHttpResponse {
                response,
                audit_events,
            };
        }
        let recipients = form.get("to").cloned().unwrap_or_default();
        if form.contains_key("compose_action")
            || !super::routes_reply::compose_metadata_valid(
                &form,
                &validated_session.record.canonical_username,
            )
        {
            return HandledHttpResponse {
                response: invalid_compose_metadata(),
                audit_events,
            };
        }
        let reply_reference = match super::routes_reply::reply_reference(&form) {
            Ok(reference) => reference,
            Err(_) => {
                return HandledHttpResponse {
                    response: invalid_compose_metadata(),
                    audit_events,
                }
            }
        };
        if let Some(message) = parsed_form.upload_error.as_deref() {
            return HandledHttpResponse {
                response: self.retained_compose_input_error(
                    &validated_session,
                    &form,
                    reply_reference.as_ref(),
                    message,
                ),
                audit_events,
            };
        }
        let mut reply_thread = match reply_reference.as_ref() {
            Some(reference) => match self.resolve_reply_thread(
                context,
                &validated_session,
                reference,
                &mut audit_events,
            ) {
                Ok(thread) => thread,
                Err(response) => {
                    return HandledHttpResponse {
                        response,
                        audit_events,
                    }
                }
            },
            None => None,
        };
        let cc_recipients = form.get("cc").cloned().unwrap_or_default();
        let bcc_recipients = form.get("bcc").cloned().unwrap_or_default();
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
        let draft_revision = match super::routes_draft::submitted_draft_revision(&form) {
            Ok(revision) => revision,
            Err(()) => {
                return HandledHttpResponse {
                    response: invalid_compose_metadata(),
                    audit_events,
                }
            }
        };
        let mut send_attachments = attachments;
        if send_attachments.len() + original_attachment_parts.len()
            > ComposePolicy::default().max_attachments
        {
            let (status, reason, public_reason) =
                super::routes_source_attachments::SourceFailure::Count.response();
            return HandledHttpResponse {
                response: self.retained_compose_failure(
                    &validated_session,
                    &form,
                    reply_reference.as_ref(),
                    public_reason,
                    status,
                    reason,
                ),
                audit_events,
            };
        }
        match self.resolve_source_attachments(
            context,
            &validated_session,
            &form,
            &original_attachment_parts,
            &mut audit_events,
            "original_attachment_send",
        ) {
            Ok(Some((_, attachments))) => send_attachments.extend(attachments),
            Ok(None) => {}
            Err(error) => {
                let (status, reason, public_reason) = error.response();
                return HandledHttpResponse {
                    response: self.retained_compose_failure(
                        &validated_session,
                        &form,
                        reply_reference.as_ref(),
                        public_reason,
                        status,
                        reason,
                    ),
                    audit_events,
                };
            }
        }
        let removed_attachment_indices =
            super::routes_draft::removed_attachment_indices(&form).unwrap_or_default();
        let mut persisted_draft_attachments = Vec::new();
        if let Some(draft_id) = draft_id.as_deref() {
            let draft_outcome = self
                .gateway
                .load_draft(context, &validated_session, draft_id);
            audit_events.extend(draft_outcome.audit_events);
            match draft_outcome.decision {
                BrowserDraftLoadDecision::Loaded {
                    canonical_username,
                    draft,
                } if canonical_username == validated_session.record.canonical_username
                    && draft.canonical_username == canonical_username
                    && draft.draft_id == draft_id
                    && draft.revision == draft_revision =>
                {
                    reply_thread = draft.request.reply_thread.clone();
                    let mut persisted = match crate::draft_content::retain_saved_attachments(
                        &draft.request.attachments,
                        &removed_attachment_indices,
                    ) {
                        Ok(attachments) => attachments,
                        Err(_) => {
                            return HandledHttpResponse {
                                response: self.retained_compose_failure(
                                    &validated_session,
                                    &form,
                                    reply_reference.as_ref(),
                                    "invalid_request",
                                    400,
                                    "Bad Request",
                                ),
                                audit_events,
                            }
                        }
                    };
                    persisted_draft_attachments = draft.request.attachments.clone();
                    persisted.extend(send_attachments);
                    send_attachments = persisted;
                }
                BrowserDraftLoadDecision::Loaded {
                    canonical_username,
                    draft,
                } if canonical_username == validated_session.record.canonical_username
                    && draft.canonical_username == canonical_username
                    && draft.draft_id == draft_id =>
                {
                    return HandledHttpResponse {
                        response: self.retained_compose_failure(
                            &validated_session,
                            &form,
                            reply_reference.as_ref(),
                            "draft_conflict",
                            409,
                            "Conflict",
                        ),
                        audit_events,
                    }
                }
                BrowserDraftLoadDecision::Loaded { .. } => {
                    return HandledHttpResponse {
                        response: invalid_compose_metadata(),
                        audit_events,
                    }
                }
                BrowserDraftLoadDecision::NotFound => {
                    return HandledHttpResponse {
                        response: self.retained_compose_failure(
                            &validated_session,
                            &form,
                            reply_reference.as_ref(),
                            "draft_conflict",
                            409,
                            "Conflict",
                        ),
                        audit_events,
                    };
                }
                BrowserDraftLoadDecision::Denied { public_reason } => {
                    return HandledHttpResponse {
                        response: self.retained_compose_failure(
                            &validated_session,
                            &form,
                            reply_reference.as_ref(),
                            &public_reason,
                            503,
                            "Service Unavailable",
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
            BrowserSendRequest {
                protection,
                send_intent: form
                    .get("send_intent")
                    .map(String::as_str)
                    .unwrap_or_default(),
                draft_id: draft_id.as_deref(),
                draft_revision,
                reply_thread: reply_thread.as_ref(),
                recipients: &recipients,
                cc_recipients: &cc_recipients,
                bcc_recipients: &bcc_recipients,
                subject: &subject,
                body: &body,
                body_format: super::compose_actions::body_format(&form).unwrap_or_default(),
                attachments: &send_attachments,
            },
        );
        audit_events.extend(outcome.audit_events);

        let mut handled = match outcome.decision {
            BrowserSendDecision::Submitted {
                sent_copy_stored,
                receipt_persisted,
            } => {
                let mut draft_cleanup_confirmed = draft_id.is_none();
                // Keep the saved recovery copy if Sent storage is unconfirmed.
                if sent_copy_stored && receipt_persisted {
                    if let (Some(draft_id), Some(revision)) = (draft_id.as_deref(), draft_revision)
                    {
                        draft_cleanup_confirmed = self
                            .gateway
                            .cleanup_sent_draft(
                                &validated_session,
                                draft_id,
                                revision,
                                form.get("send_intent")
                                    .map(String::as_str)
                                    .unwrap_or_default(),
                            )
                            .is_ok();
                    }
                }
                let response = if sent_copy_stored && receipt_persisted && draft_cleanup_confirmed {
                    redirect_response(
                        303,
                        "See Other",
                        &format!(
                            "/compose?receipt={}",
                            url_encode(
                                form.get("send_intent")
                                    .map(String::as_str)
                                    .unwrap_or_default()
                            )
                        ),
                    )
                } else {
                    submission_result_response(
                        &validated_session,
                        &form,
                        &send_attachments,
                        crate::compose_result_ui::SubmissionResult::Accepted {
                            sent_copy_stored,
                            draft_cleanup_confirmed,
                            receipt_persisted,
                        },
                    )
                };
                HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
            BrowserSendDecision::DraftSaved { .. } => HandledHttpResponse {
                response: self.send_receipt_response(
                    context,
                    &validated_session,
                    form.get("send_intent")
                        .map(String::as_str)
                        .unwrap_or_default(),
                ),
                audit_events,
            },
            BrowserSendDecision::RecoveryRefused { capacity } => HandledHttpResponse {
                response: submission_result_response(
                    &validated_session,
                    &form,
                    &send_attachments,
                    crate::compose_result_ui::SubmissionResult::RecoveryRefused { capacity },
                ),
                audit_events,
            },
            BrowserSendDecision::Unconfirmed { .. } => HandledHttpResponse {
                response: submission_result_response(
                    &validated_session,
                    &form,
                    &send_attachments,
                    crate::compose_result_ui::SubmissionResult::Unconfirmed,
                ),
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
                let mut response = super::compose_enhancement::response(
                    status_code,
                    reason_phrase,
                    "Compose",
                    self.render_protected_compose_page(&validated_session, ComposePageModel {
                        protection: super::compose_protection::retained_intent_from_form(&form),
                        openpgp: None,
                    sender_identity: None,
                        send_intent: form.get("send_intent").map(String::as_str).unwrap_or_default(),
                        contacts: self.contact_snapshot(&validated_session).ok().as_ref(),
                        reply_reference: reply_reference.as_ref(),
                        heading: "Compose",
                        canonical_username: &validated_session.record.canonical_username,
                        csrf_token: &validated_session.record.csrf_token,
                        success_message: None,
                        error_message: Some(public_reason_message(&public_reason)),
                        context_notice: Some("Nothing was sent. Re-select any new uploads before trying again; existing saved-draft attachments are unchanged."),
                        to_value: &recipients,
                        cc_value: &cc_recipients,
                        bcc_value: &bcc_recipients,
                        subject_value: &subject,
                        body_value: &body,
                        body_format: super::compose_actions::body_format(&form).unwrap_or_default(),
                        preview: false,
                    preflight: false,
                        draft_id: draft_id.as_deref(),
                        draft_revision,
                        draft_attachments: &persisted_draft_attachments,
                        removed_attachment_indices: &removed_attachment_indices,
                        source_mailbox_name: form.get("source_mailbox").map(String::as_str),
                        source_uid: form.get("source_uid").and_then(|value| value.parse().ok()),
                        source_version: super::routes_source_attachments::source_version(&form).ok().flatten().as_ref(),
                        source_attachments: &[],
                        selected_source_part_paths: &original_attachment_parts,
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

    pub(super) fn retained_compose_failure(
        &self,
        session: &ValidatedSession,
        form: &BTreeMap<String, String>,
        reply_reference: Option<&crate::reply_thread::ReplyReference>,
        public_reason: &str,
        status: u16,
        reason: &'static str,
    ) -> HttpResponse {
        self.retained_compose_response(
            session,
            form,
            reply_reference,
            (public_reason, public_reason_message(public_reason)),
            (status, reason),
        )
    }

    pub(super) fn retained_compose_input_error(
        &self,
        session: &ValidatedSession,
        form: &BTreeMap<String, String>,
        reply_reference: Option<&crate::reply_thread::ReplyReference>,
        message: &str,
    ) -> HttpResponse {
        self.retained_compose_response(
            session,
            form,
            reply_reference,
            ("invalid_request", message),
            (400, "Bad Request"),
        )
    }

    fn retained_compose_response(
        &self,
        session: &ValidatedSession,
        form: &BTreeMap<String, String>,
        reply_reference: Option<&crate::reply_thread::ReplyReference>,
        failure: (&str, &str),
        status: (u16, &'static str),
    ) -> HttpResponse {
        let (public_reason, message) = failure;
        let (status, reason) = status;
        super::compose_enhancement::response(
            status,
            reason,
            "Compose",
            self.render_protected_compose_page(session, ComposePageModel {
                protection: super::compose_protection::retained_intent_from_form(form),
                openpgp: None,
                sender_identity: None,
                send_intent: form
                    .get("send_intent")
                    .map(String::as_str)
                    .unwrap_or_default(),
                contacts: self.contact_snapshot(session).ok().as_ref(),
                reply_reference,
                heading: "Compose",
                canonical_username: &session.record.canonical_username,
                csrf_token: &session.record.csrf_token,
                success_message: None,
                error_message: Some(message),
                context_notice: Some(if public_reason == "draft_save_unconfirmed" {
                    "Your text remains in this tab. Save and Send are paused until you compare with the stored version."
                } else {
                    "Nothing was sent. Your text is retained. Re-select any new uploads before saving; existing saved-draft attachments are unchanged."
                }),
                to_value: form.get("to").map(String::as_str).unwrap_or_default(),
                cc_value: form.get("cc").map(String::as_str).unwrap_or_default(),
                bcc_value: form.get("bcc").map(String::as_str).unwrap_or_default(),
                subject_value: form.get("subject").map(String::as_str).unwrap_or_default(),
                body_value: form.get("body").map(String::as_str).unwrap_or_default(),
                body_format: super::compose_actions::body_format(form).unwrap_or_default(),
                preview: false,
                preflight: false,
                draft_id: form.get("draft_id").map(String::as_str),
                draft_revision: super::routes_draft::submitted_draft_revision(form)
                    .ok()
                    .flatten(),
                draft_attachments: &[],
                removed_attachment_indices: &super::routes_draft::removed_attachment_indices(form)
                    .unwrap_or_default(),
                source_mailbox_name: form.get("source_mailbox").map(String::as_str),
                source_uid: form.get("source_uid").and_then(|value| value.parse().ok()),
                source_version: super::routes_source_attachments::source_version(form)
                    .ok()
                    .flatten()
                    .as_ref(),
                source_attachments: &[],
                selected_source_part_paths: &selected_original_attachment_parts(form)
                    .unwrap_or_default(),
            }),
        )
    }
}

pub(super) fn invalid_compose_metadata() -> HttpResponse {
    html_response(400, "Bad Request", "Invalid Compose Request", "<p>The sender or original-message metadata was not valid. Use the current compose form; no message was submitted or draft saved.</p>")
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

pub(super) fn selected_original_attachment_parts(
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

// A read-only result has no Send form or local compose script. It preserves
// the submitted text without converting an uncertain outcome into a retry.
pub(super) fn submission_result_response(
    session: &ValidatedSession,
    form: &BTreeMap<String, String>,
    attachments: &[UploadedAttachment],
    result: crate::compose_result_ui::SubmissionResult,
) -> HttpResponse {
    use crate::compose_result_ui::{ComposeResultModel, SubmissionResult};
    let (status, reason, title) = match result {
        SubmissionResult::AlreadyRecorded => {
            (200, "OK", "This intent already has a recorded action")
        }
        SubmissionResult::Accepted { .. } => (200, "OK", "Message accepted for submission"),
        SubmissionResult::RecoveryRefused { .. } => {
            (503, "Service Unavailable", "Submission was not invoked")
        }
        SubmissionResult::Paused => (503, "Service Unavailable", "This form is paused"),
        SubmissionResult::Unconfirmed => (
            503,
            "Service Unavailable",
            "Submission could not be confirmed",
        ),
    };
    html_response(
        status,
        reason,
        title,
        crate::compose_result_ui::render(&ComposeResultModel {
            account: &session.record.canonical_username,
            csrf: &session.record.csrf_token,
            result,
            send_intent: form.get("send_intent").map(String::as_str),
            draft_id: form
                .get("draft_id")
                .filter(|id| !id.trim().is_empty())
                .map(String::as_str),
            to: form.get("to").map(String::as_str).unwrap_or_default(),
            cc: form.get("cc").map(String::as_str).unwrap_or_default(),
            bcc: form.get("bcc").map(String::as_str).unwrap_or_default(),
            subject: form.get("subject").map(String::as_str).unwrap_or_default(),
            body: form.get("body").map(String::as_str).unwrap_or_default(),
            body_format: super::compose_actions::body_format(form).unwrap_or_default(),
            attachments,
        }),
    )
}
