//! Draft route handlers for the bounded browser runtime.

use super::*;

pub(super) fn removed_attachment_indices(
    form: &BTreeMap<String, String>,
) -> Result<Vec<usize>, ()> {
    let mut removed = Vec::new();
    for (name, value) in form {
        if let Some(suffix) = name.strip_prefix("remove_saved_attachment_") {
            let index = suffix.parse::<usize>().map_err(|_| ())?;
            if index >= ComposePolicy::default().max_attachments
                || index.to_string() != suffix
                || value != "1"
                || form.get("draft_id").is_none_or(|id| id.is_empty())
            {
                return Err(());
            }
            removed.push(index);
        }
    }
    Ok(removed)
}
use crate::draft_list::DraftListView;

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
        let view = match DraftListView::parse(&request.query_params) {
            Ok(view) => view,
            Err(message) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Drafts",
                        TrustedHtml::from_template(format!(
                            "<p>{}</p><p><a href=\"/drafts\">Return to Drafts</a></p>",
                            escape_html(message)
                        )),
                    ),
                    audit_events,
                }
            }
        };
        let outcome = self.gateway.list_drafts(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftListDecision::Listed {
                canonical_username,
                drafts,
                states,
                usage,
            } if canonical_username == validated_session.record.canonical_username => {
                let total_count = drafts.len();
                let drafts = view.select(&drafts);
                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Drafts",
                        render_draft_list_page(&DraftListPageModel {
                            canonical_username: &canonical_username,
                            csrf_token: &validated_session.record.csrf_token,
                            success_message: None,
                            error_message: None,
                            drafts: &drafts,
                            view: &view,
                            total_count,
                            states: &states,
                            usage: &usage,
                        }),
                    ),
                    audit_events,
                }
            }
            BrowserDraftListDecision::Listed { .. } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Drafts Unavailable",
                    "<p>Your drafts could not be loaded safely. Reload the page to try again.</p>",
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

    pub(super) fn handle_draft_star(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return HandledHttpResponse {
                response: invalid_draft_star(),
                audit_events,
            };
        }
        let form = match parse_urlencoded_form(&request.body, 7, self.policy.max_body_bytes) {
            Ok(form) => form,
            Err(_) => {
                return HandledHttpResponse {
                    response: invalid_draft_star(),
                    audit_events,
                }
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

        if form.len() != 7
            || form.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "csrf_token"
                        | "draft_id"
                        | "draft_revision"
                        | "send_intent"
                        | "starred"
                        | "filter"
                        | "sort"
                        | "q"
                )
            })
        {
            return HandledHttpResponse {
                response: invalid_draft_star(),
                audit_events,
            };
        }
        let Some(id) = form.get("draft_id") else {
            return HandledHttpResponse {
                response: invalid_draft_star(),
                audit_events,
            };
        };
        let revision = match submitted_draft_revision(&form) {
            Ok(Some(value)) => value,
            _ => {
                return HandledHttpResponse {
                    response: invalid_draft_star(),
                    audit_events,
                }
            }
        };
        let starred = match form.get("starred").map(String::as_str) {
            Some("1") => true,
            Some("0") => false,
            _ => {
                return HandledHttpResponse {
                    response: invalid_draft_star(),
                    audit_events,
                }
            }
        };
        let query = form
            .iter()
            .filter(|(key, _)| matches!(key.as_str(), "filter" | "sort" | "q"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let view = match DraftListView::parse(&query) {
            Ok(view) => view,
            Err(_) => {
                return HandledHttpResponse {
                    response: invalid_draft_star(),
                    audit_events,
                }
            }
        };
        let destination = format!(
            "/drafts?filter={}&sort={}&q={}",
            view.filter.value(),
            view.sort.value(),
            url_encode(&view.query)
        );
        let outcome = self
            .gateway
            .set_draft_star(context, &session, id, revision, starred);
        audit_events.extend(outcome.audit_events);
        let response = match outcome.decision {
            BrowserDraftSaveDecision::Saved { .. } => redirect_response(303, "See Other", &destination),
            BrowserDraftSaveDecision::Unconfirmed { .. } => html_response(503, "Service Unavailable", "Draft Update Not Confirmed", TrustedHtml::from_template(format!("<p>The star change could not be confirmed. It may already be saved. Reload the list before making another change.</p><p><a href=\"{}\">Reload Drafts</a></p>", escape_html(&destination)))),
            BrowserDraftSaveDecision::Denied { public_reason } => html_response(
                if public_reason == "draft_conflict" { 409 } else { 503 },
                if public_reason == "draft_conflict" { "Conflict" } else { "Service Unavailable" },
                "Draft Update Unavailable", TrustedHtml::from_template(format!("<p>The draft could not be updated. Reload the list to check its saved state before trying again.</p><p><a href=\"{}\">Reload Drafts</a></p>", escape_html(&destination)))),
        };
        HandledHttpResponse {
            response,
            audit_events,
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
            BrowserDraftLoadDecision::Loaded {
                draft,
                canonical_username,
            } if canonical_username == validated_session.record.canonical_username
                && draft.canonical_username == validated_session.record.canonical_username
                && draft.draft_id == draft_id =>
            {
                let send_intent = match draft.revision.and_then(|revision| {
                    crate::send_journal::intent_for_draft(
                        &canonical_username,
                        &draft.draft_id,
                        revision,
                        draft.updated_at,
                    )
                    .ok()
                }) {
                    Some(value) => value,
                    None => {
                        return HandledHttpResponse {
                            response: html_response(
                                409,
                                "Conflict",
                                "Draft intent unavailable",
                                "<p>The saved revision cannot be resumed safely.</p>",
                            ),
                            audit_events,
                        }
                    }
                };
                if !matches!(
                    self.gateway.send_receipt(&validated_session, &send_intent),
                    Ok(None)
                ) {
                    return HandledHttpResponse {
                        response: self.saved_draft_receipt_response(&validated_session, &send_intent, &draft),
                        audit_events,
                    };
                }
                let mut source_attachments = Vec::new();
                let mut source_notice = None;
                if let Some(source) = &draft.source_attachments {
                    source_notice = Some("Only the source attachments explicitly selected when this draft was saved remain selected.");
                    if source.version.is_none() {
                        source_notice = Some(public_reason_message("source_attachment_unverified"));
                    } else {
                        match self.acquire_mailbox_budget(
                            context,
                            &validated_session,
                            "draft_resume_source",
                        ) {
                            Ok((guard, event)) => {
                                audit_events.push(event);
                                let source_outcome = self.gateway.view_message(
                                    context,
                                    &validated_session,
                                    &source.mailbox_name,
                                    source.uid,
                                );
                                audit_events.extend(source_outcome.audit_events);
                                audit_events.push(self.release_request_budget(
                                    guard,
                                    "draft_resume_source",
                                    context,
                                    &validated_session,
                                ));
                                match source_outcome.decision {
                                    BrowserMessageViewDecision::Rendered {
                                        canonical_username,
                                        rendered,
                                    } if canonical_username
                                        == validated_session.record.canonical_username
                                        && rendered.mailbox_name == source.mailbox_name
                                        && rendered.uid == source.uid
                                        && rendered
                                            .metadata
                                            .as_ref()
                                            .map(|metadata| &metadata.version)
                                            == source.version.as_ref()
                                        && source.part_paths.iter().all(|selected| {
                                            rendered
                                                .attachments
                                                .iter()
                                                .any(|attachment| &attachment.part_path == selected)
                                        }) =>
                                    {
                                        source_attachments = rendered.attachments
                                    }
                                    BrowserMessageViewDecision::Rendered { .. } => {
                                        source_notice =
                                            Some(public_reason_message("source_attachment_changed"))
                                    }
                                    BrowserMessageViewDecision::Denied { .. } => {
                                        source_notice = Some(public_reason_message(
                                            "source_attachment_unavailable",
                                        ))
                                    }
                                }
                            }
                            Err(response) => {
                                audit_events.extend(response.audit_events);
                                source_notice =
                                    Some(public_reason_message("source_attachment_unavailable"));
                            }
                        }
                    }
                }
                HandledHttpResponse {
                    response: super::compose_enhancement::response(
                        200,
                        "OK",
                        "Resume Draft",
                        self.render_protected_compose_page(&validated_session, ComposePageModel {
 sender_choices: None,
 selected_sender_id: None,
                            protection: draft.request.protection,
                            openpgp: None,
                    sender_identity: Some(&draft.request.sender_identity),
                            send_intent: &send_intent,
                            contacts: self.contact_snapshot(&validated_session).ok().as_ref(),
                            reply_reference: None,
                            heading: "Resume Draft",
                            canonical_username: &validated_session.record.canonical_username,
                            csrf_token: &validated_session.record.csrf_token,
                            success_message: None,
                            error_message: None,
                            context_notice: source_notice,
                            to_value: &draft.request.recipients_text,
                            cc_value: &draft.request.cc_text,
                            bcc_value: &draft.request.bcc_text,
                            subject_value: &draft.request.subject,
                            body_value: &draft.request.body,
                            body_format: draft.request.body_format,
                            preview: request.query_params.get("preview").map(String::as_str)
                                == Some("1"),
                            preflight: request.query_params.get("preflight").map(String::as_str)
                                == Some("1"),
                            draft_id: Some(&draft.draft_id),
                            draft_revision: draft.revision,
                            draft_attachments: &draft.request.attachments,
                            removed_attachment_indices: &[],
                            source_mailbox_name: draft
                                .source_attachments
                                .as_ref()
                                .map(|source| source.mailbox_name.as_str()),
                            source_uid: draft.source_attachments.as_ref().map(|source| source.uid),
                            source_version: draft
                                .source_attachments
                                .as_ref()
                                .and_then(|source| source.version.as_ref()),
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
            BrowserDraftLoadDecision::Loaded { .. } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Draft Unavailable",
                    "<p>This draft could not be loaded safely. Return to Drafts and try again.</p>",
                ),
                audit_events,
            },
            BrowserDraftLoadDecision::NotFound => HandledHttpResponse {
                response: html_response(
                    404,
                    "Not Found",
                    "Draft Not Found",
                    "<p>The saved draft is absent. It may have expired after 30 days, been discarded, or been removed after confirmed submission.</p>",
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
        let mut form = parsed_form.fields;

        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }

        let mut protection = match super::compose_protection::intent_from_form(&form) {
            Ok(intent) => intent,
            Err(message) if request.path == "/drafts/autosave" => {
                let _ = message;
                return HandledHttpResponse {
                    response: super::routes_autosave::json(
                        409,
                        serde_json::json!({"version":1,"state":"paused"}),
                    ),
                    audit_events,
                };
            }
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

        if request.path == "/drafts/autosave" {
            let allowed = [
                "csrf_token",
                "sender_id",
                "send_intent",
                "from",
                "to",
                "cc",
                "bcc",
                "subject",
                "body",
                "body_format",
                "pgp_sign",
                "pgp_encrypt",
                "pgp_self",
                "pgp_binding_revision",
                "draft_id",
                "draft_revision",
                "reply_mailbox",
                "reply_uid",
                "reply_mailbox_guid",
                "reply_message_guid",
            ];
            if form.keys().any(|k| !allowed.contains(&k.as_str()))
                || !parsed_form.attachments.is_empty()
                || parsed_form.upload_error.is_some()
                || !self
                    .gateway
                    .load_autosave(&validated_session)
                    .is_ok_and(|v| v.enabled)
            {
                return HandledHttpResponse {
                    response: super::routes_autosave::json(
                        409,
                        serde_json::json!({"version":1,"state":"paused"}),
                    ),
                    audit_events,
                };
            }
        }

        if request.path == "/drafts/autosave" {
            if let Some(id) = form.get("draft_id") {
                let existing = self.gateway.load_draft(context, &validated_session, id);
                audit_events.extend(existing.audit_events);
                if !matches!(existing.decision,BrowserDraftLoadDecision::Loaded{canonical_username,draft} if canonical_username==validated_session.record.canonical_username && draft.canonical_username==canonical_username && draft.draft_id==*id && draft.source_attachments.is_none())
                {
                    return HandledHttpResponse {
                        response: super::routes_autosave::json(
                            409,
                            serde_json::json!({"version":1,"state":"paused"}),
                        ),
                        audit_events,
                    };
                }
            }
        }

        if let Some(response) =
            self.intent_guard_response(context, &validated_session, &form, &parsed_form.attachments)
        {
            return HandledHttpResponse {
                response,
                audit_events,
            };
        }
        if !super::routes_reply::compose_metadata_valid(
            &form,
            &validated_session.record.canonical_username,
        ) {
            return HandledHttpResponse {
                response: super::routes_compose::invalid_compose_metadata(),
                audit_events,
            };
        }
        let reply_reference = match super::routes_reply::reply_reference(&form) {
            Ok(reference) => reference,
            Err(_) => {
                return HandledHttpResponse {
                    response: super::routes_compose::invalid_compose_metadata(),
                    audit_events,
                }
            }
        };
        let contact_result = if matches!(
            form.get("compose_action").map(String::as_str),
            Some("theme-light" | "theme-dark")
        ) {
            Ok(())
        } else {
            self.add_selected_contact(&validated_session, &mut form)
        };
        if let Err(error) = contact_result {
            return HandledHttpResponse {
                response: super::compose_enhancement::response(409, "Conflict", "Choose a Contact", self.render_protected_compose_page(&validated_session, ComposePageModel {
 sender_choices: None,
 selected_sender_id: form.get("sender_id").map(String::as_str),
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
                    error_message: Some(error.message()),
                    context_notice: Some("Nothing was saved or sent. Your text is retained. Re-select any new uploads before saving; existing saved-draft attachments are unchanged."),
                    to_value: form.get("to").map(String::as_str).unwrap_or_default(),
                    cc_value: form.get("cc").map(String::as_str).unwrap_or_default(),
                    bcc_value: form.get("bcc").map(String::as_str).unwrap_or_default(),
                    subject_value: form.get("subject").map(String::as_str).unwrap_or_default(),
                    body_value: form.get("body").map(String::as_str).unwrap_or_default(),
                    body_format: super::compose_actions::body_format(&form).unwrap_or_default(),
                    preview: false,
                    preflight: false,
                    draft_id: form.get("draft_id").map(String::as_str),
                    draft_revision: super::routes_contacts::revision(form.get("draft_revision")),
                    draft_attachments: &[],
                    removed_attachment_indices: &removed_attachment_indices(&form).unwrap_or_default(),
                    source_mailbox_name: form.get("source_mailbox").map(String::as_str),
                    source_uid: form.get("source_uid").and_then(|value| value.parse().ok()),
                    source_version: super::routes_source_attachments::source_version(&form).ok().flatten().as_ref(),
                    source_attachments: &[],
                    selected_source_part_paths: &super::routes_compose::selected_original_attachment_parts(&form).unwrap_or_default(),
                })),
                audit_events,
            };
        }
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
        if let Err(message) = super::compose_actions::apply_format(&mut form) {
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
        let recipients = form.get("to").cloned().unwrap_or_default();
        let reply_thread = match reply_reference.as_ref() {
            Some(reference) => match self.resolve_reply_thread(
                context,
                &validated_session,
                reference,
                &mut audit_events,
            ) {
                Ok(thread) => thread,
                Err(response) => {
                    let response = if matches!(
                        form.get("compose_action").map(String::as_str),
                        Some("theme-light" | "theme-dark")
                    ) {
                        self.retained_compose_input_error(&validated_session, &form, reply_reference.as_ref(), "The original reply context could not be confirmed. Your draft and theme were not changed. Re-select any new uploads before retrying.")
                    } else {
                        response
                    };
                    return HandledHttpResponse {
                        response,
                        audit_events,
                    };
                }
            },
            None => None,
        };
        let cc_recipients = form.get("cc").cloned().unwrap_or_default();
        let bcc_recipients = form.get("bcc").cloned().unwrap_or_default();
        let subject = form.get("subject").cloned().unwrap_or_default();
        let body = form.get("body").cloned().unwrap_or_default();
        let draft_id = form.get("draft_id").map(String::as_str);
        let expected_revision = match submitted_draft_revision(&form) {
            Ok(revision) => revision,
            Err(()) => {
                return HandledHttpResponse {
                    response: super::routes_compose::invalid_compose_metadata(),
                    audit_events,
                }
            }
        };
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
        let source_attachments = match self.resolve_source_attachments(
            context,
            &validated_session,
            &form,
            &selected_source_parts,
            &mut audit_events,
            "original_attachment_save",
        ) {
            Ok(value) => value.map(|(reference, _)| reference),
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
        };
        // Pre-send check is an explicit review of the current public binding
        // snapshot. Only this action may replace a saved draft's pinned revision;
        // ordinary saves, autosaves and resumed drafts keep their original pin.
        // Send performs its own locked-revision check after this draft save.
        if form.get("compose_action").map(String::as_str) == Some("preflight")
            && (protection.sign || protection.encrypt || protection.binding_revision.is_some())
        {
            let current = self.gateway.compose_protection(
                &validated_session,
                &recipients,
                &cc_recipients,
                &bcc_recipients,
                protection,
            );
            match current {
                Some(view) if view.runtime_configured => {
                    match (view.revision, view.preflight.as_ref()) {
                        (Some(revision), Some(preflight)) if preflight.revision == revision => {
                            protection.binding_revision = Some(revision);
                        }
                        (Some(_), Some(_)) => {
                            return HandledHttpResponse {
                                response: self.retained_compose_failure(
                                    &validated_session,
                                    &form,
                                    reply_reference.as_ref(),
                                    "openpgp_binding_changed",
                                    409,
                                    "Conflict",
                                ),
                                audit_events,
                            };
                        }
                        _ => {
                            return HandledHttpResponse {
                                response: self.retained_compose_input_error(
                                    &validated_session,
                                    &form,
                                    reply_reference.as_ref(),
                                    "Current OpenPGP key status could not be checked for these recipients. Check the addresses and retry Pre-send check; the saved draft was not updated.",
                                ),
                                audit_events,
                            };
                        }
                    }
                }
                _ => {
                    return HandledHttpResponse {
                        response: self.retained_compose_failure(
                            &validated_session,
                            &form,
                            reply_reference.as_ref(),
                            "openpgp_inventory_unavailable",
                            503,
                            "Service Unavailable",
                        ),
                        audit_events,
                    };
                }
            }
        }
        let outcome = self.gateway.save_draft(
            context,
            &validated_session,
            BrowserDraftSaveRequest {
                sender_id: form.get("sender_id").map(String::as_str),
                protection,
                send_intent: form
                    .get("send_intent")
                    .map(String::as_str)
                    .unwrap_or_default(),
                reply_thread: reply_thread.as_ref(),
                draft_id,
                expected_revision,
                recipients: &recipients,
                cc_recipients: &cc_recipients,
                bcc_recipients: &bcc_recipients,
                subject: &subject,
                body: &body,
                body_format: super::compose_actions::body_format(&form).unwrap_or_default(),
                attachments: &parsed_form.attachments,
                removed_attachment_indices: &removed_attachment_indices(&form).unwrap_or_default(),
                source_attachments: source_attachments.as_ref(),
            },
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftSaveDecision::Unconfirmed { draft_id } => {
                let mut retained = form;
                retained.insert("draft_id".into(), draft_id);
                retained.remove("draft_revision");
                HandledHttpResponse {
                    response: self.retained_compose_failure(
                        &validated_session,
                        &retained,
                        reply_reference.as_ref(),
                        "draft_save_unconfirmed",
                        503,
                        "Service Unavailable",
                    ),
                    audit_events,
                }
            }
            BrowserDraftSaveDecision::Saved { draft_id } if request.path == "/drafts/autosave" => {
                let response = self.autosave_confirmation(
                    context,
                    &validated_session,
                    &draft_id,
                    &form,
                    &mut audit_events,
                );
                HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
            BrowserDraftSaveDecision::Saved { draft_id }
                if matches!(
                    form.get("compose_action").map(String::as_str),
                    Some("theme-light" | "theme-dark")
                ) =>
            {
                let appearance =
                    if form.get("compose_action").map(String::as_str) == Some("theme-dark") {
                        AppearancePreference::Dark
                    } else {
                        AppearancePreference::Light
                    };
                let destination = format!("/draft?id={}", url_encode(&draft_id));
                // Draft confirmation is the ordering boundary. A refused,
                // conflicted or unconfirmed save never writes appearance.
                if self
                    .gateway
                    .update_appearance(context, &validated_session, appearance)
                    .is_err()
                {
                    audit_events.push(build_http_warning_event(
                        "http_draft_theme_unconfirmed",
                        "draft saved but appearance save could not be confirmed",
                        context,
                    ));
                    return HandledHttpResponse {
                        response: html_response(503, "Service Unavailable", "Draft Saved; Appearance Unconfirmed", TrustedHtml::from_template(format!("<p>Your draft was saved, including accepted attachments. The appearance change could not be confirmed.</p><p><a href=\"{}\">Return to your saved draft</a> or <a href=\"/settings?section=appearance\">review your saved appearance</a> before trying again.</p>", escape_html(&destination)))),
                        audit_events,
                    };
                }
                audit_events.push(build_http_info_event(
                    "http_draft_theme_updated",
                    "draft saved and appearance preference updated",
                    context,
                ));
                HandledHttpResponse {
                    response: redirect_response(303, "See Other", &destination).with_header(
                        "Set-Cookie",
                        appearance.cookie(self.policy.secure_session_cookie),
                    ),
                    audit_events,
                }
            }
            BrowserDraftSaveDecision::Saved { draft_id } => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    &if form.get("compose_action").map(String::as_str) == Some("minimize") {
                        "/drafts".into()
                    } else {
                        format!(
                            "/draft?id={}{}",
                            url_encode(&draft_id),
                            if form.get("compose_action").is_some_and(
                                |action| action == "preview" || action.starts_with("format-")
                            ) {
                                "&preview=1"
                            } else if form.get("compose_action").map(String::as_str)
                                == Some("preflight")
                            {
                                "&preflight=1"
                            } else {
                                ""
                            }
                        )
                    },
                ),
                audit_events,
            },
            BrowserDraftSaveDecision::Denied { public_reason }
                if public_reason == "send_attempt_paused" =>
            {
                HandledHttpResponse {
                    response: super::routes_compose::submission_result_response(
                        &validated_session,
                        &form,
                        &parsed_form.attachments,
                        crate::compose_result_ui::SubmissionResult::Paused,
                    ),
                    audit_events,
                }
            }
            BrowserDraftSaveDecision::Denied { public_reason } => {
                let (status_code, reason_phrase) = if public_reason == "draft_conflict" {
                    (409, "Conflict")
                } else if public_reason == "invalid_request" {
                    (400, "Bad Request")
                } else {
                    (503, "Service Unavailable")
                };
                HandledHttpResponse {
                    response: super::compose_enhancement::response(
                        status_code,
                        reason_phrase,
                        "Compose",
                        self.render_protected_compose_page(&validated_session, ComposePageModel {
 sender_choices: None,
 selected_sender_id: form.get("sender_id").map(String::as_str),
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
                            context_notice: Some("Nothing was saved or sent. Your text is retained. Re-select any new uploads before saving; existing saved-draft attachments are unchanged."),
                            to_value: &recipients,
                            cc_value: &cc_recipients,
                            bcc_value: &bcc_recipients,
                            subject_value: &subject,
                            body_value: &body,
                            body_format: super::compose_actions::body_format(&form).unwrap_or_default(),
                            preview: false,
                    preflight: false,
                            draft_id,
                            draft_revision: expected_revision,
                            draft_attachments: &[],
                            removed_attachment_indices: &removed_attachment_indices(&form).unwrap_or_default(),
                            source_mailbox_name: source_attachments.as_ref().map(|source| source.mailbox_name.as_str()),
                            source_uid: source_attachments.as_ref().map(|source| source.uid),
                            source_version: source_attachments.as_ref().and_then(|source| source.version.as_ref()),
                            source_attachments: &[],
                            selected_source_part_paths: source_attachments.as_ref().map(|source| source.part_paths.as_slice()).unwrap_or_default(),
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
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
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

        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &validated_session,
            context,
        ) {
            return response;
        }
        if !matches!(form.len(), 4 | 7)
            || form.get("confirm").map(String::as_str) != Some("1")
            || form.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "csrf_token"
                        | "draft_id"
                        | "draft_revision"
                        | "send_intent"
                        | "confirm"
                        | "filter"
                        | "sort"
                        | "q"
                )
            })
        {
            return HandledHttpResponse {
                response: invalid_draft_delete(),
                audit_events,
            };
        }
        let expected_revision = match submitted_draft_revision(&form) {
            Ok(Some(revision)) => revision,
            _ => {
                return HandledHttpResponse {
                    response: invalid_draft_delete(),
                    audit_events,
                }
            }
        };
        let destination = if form.len() == 7 {
            let query = form
                .iter()
                .filter(|(key, _)| matches!(key.as_str(), "filter" | "sort" | "q"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            match DraftListView::parse(&query) {
                Ok(view) => view.href(),
                Err(_) => {
                    return HandledHttpResponse {
                        response: invalid_draft_delete(),
                        audit_events,
                    }
                }
            }
        } else {
            "/drafts".into()
        };
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

        let outcome =
            self.gateway
                .delete_draft(context, &validated_session, draft_id, expected_revision);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserDraftDeleteDecision::Deleted | BrowserDraftDeleteDecision::NotFound => {
                HandledHttpResponse {
                    response: redirect_response(303, "See Other", &destination),
                    audit_events,
                }
            }
            BrowserDraftDeleteDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    if public_reason == "draft_conflict" {
                        409
                    } else {
                        503
                    },
                    if public_reason == "draft_conflict" {
                        "Conflict"
                    } else {
                        "Service Unavailable"
                    },
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

/// A revision must travel with its draft id, including legacy revision zero.
pub(super) fn submitted_draft_revision(form: &BTreeMap<String, String>) -> Result<Option<u64>, ()> {
    match (form.get("draft_id"), form.get("draft_revision")) {
        (None, None) => Ok(None),
        (Some(id), Some(revision)) if crate::draft::validate_draft_id(id).is_ok() => {
            let parsed = revision.parse::<u64>().map_err(|_| ())?;
            if parsed.to_string() == *revision {
                Ok(Some(parsed))
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

fn invalid_draft_delete() -> HttpResponse {
    html_response(
        400,
        "Bad Request",
        "Invalid Draft Request",
        "<p>Use the current draft's Delete confirmation. Nothing was deleted.</p>",
    )
}

fn invalid_draft_star() -> HttpResponse {
    html_response(400, "Bad Request", "Invalid Draft Request", "<p>Use the current draft's Star control. No draft was changed.</p><p><a href=\"/drafts\">Return to Drafts</a></p>")
}
