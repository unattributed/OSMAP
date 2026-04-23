//! Mailbox and content route handlers for the bounded browser runtime.
//!
//! Keeping mailbox and message routes separate from auth/session and transport
//! code reduces the amount of mail-specific browser behavior concentrated in
//! `http.rs` without changing the route surface.

use super::*;

fn mailbox_is_user_visible(mailbox_name: &str) -> bool {
    matches!(mailbox_name, "INBOX" | "Drafts" | "Junk" | "Sent" | "Trash")
        || mailbox_name.starts_with("INBOX.")
}

fn filter_user_visible_mailboxes(mailboxes: &[MailboxEntry]) -> Vec<MailboxEntry> {
    mailboxes
        .iter()
        .filter(|mailbox| mailbox_is_user_visible(&mailbox.name))
        .cloned()
        .collect()
}

fn mailbox_name_exists(mailboxes: &[MailboxEntry], mailbox_name: &str) -> bool {
    mailboxes.iter().any(|mailbox| mailbox.name == mailbox_name)
}

const MAX_BULK_ARCHIVE_MESSAGES: usize = 10;

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    fn validated_archive_mailbox_name(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        audit_events: &mut Vec<LogEvent>,
    ) -> Option<String> {
        let archive_mailbox_name = match self.gateway.load_settings(context, validated_session) {
            BrowserSettingsOutcome {
                decision: BrowserSettingsDecision::Loaded { settings, .. },
                audit_events: settings_audit_events,
            } => {
                audit_events.extend(settings_audit_events);
                settings.archive_mailbox_name
            }
            BrowserSettingsOutcome {
                decision: BrowserSettingsDecision::Denied { .. },
                audit_events: settings_audit_events,
            } => {
                audit_events.extend(settings_audit_events);
                None
            }
        }?;

        let mailbox_outcome = self.gateway.list_mailboxes(context, validated_session);
        audit_events.extend(mailbox_outcome.audit_events);

        match mailbox_outcome.decision {
            BrowserMailboxDecision::Listed { mailboxes, .. } => {
                if mailbox_name_exists(&mailboxes, &archive_mailbox_name) {
                    Some(archive_mailbox_name)
                } else {
                    audit_events.push(
                        build_http_warning_event(
                            "archive_mailbox_setting_ignored",
                            "stored archive mailbox was not present in mailbox listing",
                            context,
                        )
                        .with_field("archive_mailbox_name", archive_mailbox_name),
                    );
                    None
                }
            }
            BrowserMailboxDecision::Denied { public_reason } => {
                audit_events.push(
                    build_http_warning_event(
                        "archive_mailbox_setting_unresolved",
                        "archive mailbox setting could not be resolved",
                        context,
                    )
                    .with_field("public_reason", public_reason),
                );
                None
            }
        }
    }

    /// Handles the mailbox-home page for the validated browser session.
    pub(super) fn handle_mailboxes(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self.gateway.list_mailboxes(context, &validated_session);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } => {
                let visible_mailboxes = filter_user_visible_mailboxes(&mailboxes);
                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Mailboxes",
                        &render_mailboxes_page(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            &visible_mailboxes,
                        ),
                    ),
                    audit_events,
                }
            }
            BrowserMailboxDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Mailbox Access Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles per-mailbox message-list requests.
    pub(super) fn handle_mailbox_messages(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mailbox_name = match request.query_params.get("name") {
            Some(mailbox_name) if !mailbox_name.is_empty() => mailbox_name.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Mailbox Request",
                        "<p>A mailbox name is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_mailbox_request_rejected",
                        "mailbox query parameter missing",
                        context,
                    )],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let success_message = request.query_params.get("moved_to").and_then(|value| {
            if value.is_empty() {
                return None;
            }
            let moved_count = request
                .query_params
                .get("moved_count")
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|count| *count > 1);
            match moved_count {
                Some(count) => Some(format!("{count} messages moved to {value}.")),
                None => Some(format!("Message moved to {value}.")),
            }
        });

        let outcome = self
            .gateway
            .list_messages(context, &validated_session, &mailbox_name);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
            } => {
                let archive_mailbox_name = self.validated_archive_mailbox_name(
                    context,
                    &validated_session,
                    &mut audit_events,
                );

                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Mailbox Messages",
                        &render_message_list_page(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            &mailbox_name,
                            &messages,
                            success_message.as_deref(),
                            archive_mailbox_name.as_deref(),
                        ),
                    ),
                    audit_events,
                }
            }
            BrowserMessageListDecision::Denied { public_reason } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Message List Unavailable",
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
                ),
                audit_events,
            },
        }
    }

    /// Handles one CSRF-bound message-move request from the message view.
    pub(super) fn handle_message_move(
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
                    "Invalid Message Move Request",
                    "<p>The move form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_message_move_content_type_rejected",
                    "message move form content type was not supported",
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
                        "Invalid Message Move Request",
                        "<p>The move form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_message_move_parse_failed",
                        "message move form parsing failed",
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

        let source_mailbox_name = form.get("mailbox").cloned().unwrap_or_default();
        let destination_mailbox_name = form.get("destination_mailbox").cloned().unwrap_or_default();
        let uid = match form.get("uid").and_then(|value| value.parse::<u64>().ok()) {
            Some(uid) => uid,
            None => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Message Move Request",
                        "<p>A positive IMAP UID is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_message_move_uid_rejected",
                        "message move uid parameter invalid",
                        context,
                    )],
                };
            }
        };

        let outcome = self.gateway.move_message(
            context,
            &validated_session,
            &source_mailbox_name,
            uid,
            &destination_mailbox_name,
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageMoveDecision::Moved {
                source_mailbox_name,
                destination_mailbox_name,
                ..
            } => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    &format!(
                        "/mailbox?name={}&moved_to={}",
                        url_encode(&source_mailbox_name),
                        url_encode(&destination_mailbox_name)
                    ),
                ),
                audit_events,
            },
            BrowserMessageMoveDecision::Denied {
                public_reason,
                retry_after_seconds,
            } => {
                let (status_code, reason_phrase, title) = match public_reason.as_str() {
                    "invalid_mailbox" | "invalid_request" => {
                        (400, "Bad Request", "Invalid Message Move Request")
                    }
                    "invalid_message_reference" => {
                        (404, "Not Found", "Message Move Not Available")
                    }
                    "not_found" => (404, "Not Found", "Message Move Not Available"),
                    TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON => {
                        (429, "Too Many Requests", "Message Move Temporarily Limited")
                    }
                    _ => (503, "Service Unavailable", "Message Move Unavailable"),
                };

                let mut response = html_response(
                    status_code,
                    reason_phrase,
                    title,
                    &format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    ),
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

    /// Handles a bounded CSRF-bound selected-message archive request.
    pub(super) fn handle_bulk_archive(
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
                    "Invalid Bulk Archive Request",
                    "<p>The archive form content type was not supported.</p>",
                ),
                audit_events: vec![build_http_warning_event(
                    "http_bulk_archive_content_type_rejected",
                    "bulk archive form content type was not supported",
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
                        "Invalid Bulk Archive Request",
                        "<p>The archive form could not be parsed.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_bulk_archive_parse_failed",
                        "bulk archive form parsing failed",
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

        let source_mailbox_name = form.get("mailbox").cloned().unwrap_or_default();
        let destination_mailbox_name = form.get("destination_mailbox").cloned().unwrap_or_default();
        let selected_uids = match selected_bulk_archive_uids(&form) {
            Ok(selected_uids) if !selected_uids.is_empty() => selected_uids,
            Ok(_) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Bulk Archive Request",
                        "<p>Select at least one message to archive.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_bulk_archive_empty_selection",
                        "bulk archive request did not include selected messages",
                        context,
                    )],
                };
            }
            Err(reason) => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Bulk Archive Request",
                        "<p>The archive selection was not valid.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_bulk_archive_uid_rejected",
                        "bulk archive uid parameter invalid",
                        context,
                    )
                    .with_field("reason", reason)],
                };
            }
        };

        let mut moved_count = 0_usize;
        for uid in selected_uids {
            let outcome = self.gateway.move_message(
                context,
                &validated_session,
                &source_mailbox_name,
                uid,
                &destination_mailbox_name,
            );
            audit_events.extend(outcome.audit_events);

            match outcome.decision {
                BrowserMessageMoveDecision::Moved { .. } => {
                    moved_count += 1;
                }
                BrowserMessageMoveDecision::Denied {
                    public_reason,
                    retry_after_seconds,
                } => {
                    let (status_code, reason_phrase, title) = match public_reason.as_str() {
                        "invalid_mailbox" | "invalid_request" => {
                            (400, "Bad Request", "Invalid Bulk Archive Request")
                        }
                        "invalid_message_reference" => {
                            (404, "Not Found", "Bulk Archive Not Available")
                        }
                        "not_found" => (404, "Not Found", "Bulk Archive Not Available"),
                        TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON => {
                            (429, "Too Many Requests", "Bulk Archive Temporarily Limited")
                        }
                        _ => (503, "Service Unavailable", "Bulk Archive Unavailable"),
                    };

                    let mut response = html_response(
                        status_code,
                        reason_phrase,
                        title,
                        &format!(
                            "<p>{}</p><p>{} message(s) were archived before this request stopped.</p>",
                            escape_html(public_reason_message(&public_reason)),
                            moved_count
                        ),
                    );
                    if let Some(retry_after_seconds) = retry_after_seconds {
                        response =
                            response.with_header("Retry-After", retry_after_seconds.to_string());
                    }
                    return HandledHttpResponse {
                        response,
                        audit_events,
                    };
                }
            }
        }

        HandledHttpResponse {
            response: redirect_response(
                303,
                "See Other",
                &format!(
                    "/mailbox?name={}&moved_to={}&moved_count={}",
                    url_encode(&source_mailbox_name),
                    url_encode(&destination_mailbox_name),
                    moved_count
                ),
            ),
            audit_events,
        }
    }

    /// Handles bounded message-search requests for one mailbox or all mailboxes.
    pub(super) fn handle_message_search(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let query = match request.query_params.get("q") {
            Some(query) if !query.trim().is_empty() => query.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Search Request",
                        "<p>A search query is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_search_query_rejected",
                        "search query parameter missing",
                        context,
                    )],
                };
            }
        };
        let mut mailbox_name = request
            .query_params
            .get("mailbox")
            .filter(|mailbox_name| !mailbox_name.is_empty())
            .cloned();
        if request.query_params.get("scope").map(String::as_str) == Some("all") {
            mailbox_name = None;
        }

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self.gateway.search_messages(
            context,
            &validated_session,
            mailbox_name.as_deref(),
            &query,
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageSearchDecision::Listed {
                canonical_username,
                mailbox_name,
                query,
                results,
            } => HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Message Search",
                    &render_message_search_page(
                        &canonical_username,
                        &validated_session.record.csrf_token,
                        mailbox_name.as_deref(),
                        &query,
                        &results,
                    ),
                ),
                audit_events,
            },
            BrowserMessageSearchDecision::Denied { public_reason } => {
                let (status_code, reason_phrase, title) = match public_reason.as_str() {
                    "invalid_mailbox" | "invalid_request" => {
                        (400, "Bad Request", "Invalid Search Request")
                    }
                    "not_found" => (404, "Not Found", "Message Search Not Available"),
                    _ => (503, "Service Unavailable", "Message Search Unavailable"),
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

    /// Handles per-message view requests for the validated browser session.
    pub(super) fn handle_message_view(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mailbox_name = match request.query_params.get("mailbox") {
            Some(mailbox_name) if !mailbox_name.is_empty() => mailbox_name.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Message Request",
                        "<p>A mailbox name is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_message_request_rejected",
                        "message mailbox parameter missing",
                        context,
                    )],
                };
            }
        };
        let uid = match request
            .query_params
            .get("uid")
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(uid) if uid > 0 => uid,
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Message Request",
                        "<p>A positive IMAP UID is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_message_uid_rejected",
                        "message uid parameter invalid",
                        context,
                    )],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self
            .gateway
            .view_message(context, &validated_session, &mailbox_name, uid);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageViewDecision::Rendered {
                canonical_username,
                rendered,
            } => {
                let archive_mailbox_name = self.validated_archive_mailbox_name(
                    context,
                    &validated_session,
                    &mut audit_events,
                );

                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Message View",
                        &render_message_view_page(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            &rendered,
                            archive_mailbox_name.as_deref(),
                        ),
                    ),
                    audit_events,
                }
            }
            BrowserMessageViewDecision::Denied { public_reason } => HandledHttpResponse {
                response: {
                    let (status_code, reason_phrase, title) = match public_reason.as_str() {
                        "invalid_request" => (400, "Bad Request", "Invalid Message Request"),
                        "not_found" => (404, "Not Found", "Message Not Found"),
                        _ => (503, "Service Unavailable", "Message View Unavailable"),
                    };
                    html_response(
                        status_code,
                        reason_phrase,
                        title,
                        &format!(
                            "<p>{}</p>",
                            escape_html(public_reason_message(&public_reason))
                        ),
                    )
                },
                audit_events,
            },
        }
    }

    /// Handles one session-gated attachment download request.
    pub(super) fn handle_attachment_download(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let mailbox_name = match request.query_params.get("mailbox") {
            Some(mailbox_name) if !mailbox_name.is_empty() => mailbox_name.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Attachment Request",
                        "<p>A mailbox name is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_attachment_mailbox_rejected",
                        "attachment mailbox parameter missing",
                        context,
                    )],
                };
            }
        };
        let uid = match request
            .query_params
            .get("uid")
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(uid) if uid > 0 => uid,
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Attachment Request",
                        "<p>A positive IMAP UID is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_attachment_uid_rejected",
                        "attachment uid parameter invalid",
                        context,
                    )],
                };
            }
        };
        let part_path = match request.query_params.get("part") {
            Some(part_path) if !part_path.is_empty() => part_path.clone(),
            _ => {
                return HandledHttpResponse {
                    response: html_response(
                        400,
                        "Bad Request",
                        "Invalid Attachment Request",
                        "<p>An attachment part path is required.</p>",
                    ),
                    audit_events: vec![build_http_warning_event(
                        "http_attachment_part_rejected",
                        "attachment part parameter missing",
                        context,
                    )],
                };
            }
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };

        let outcome = self.gateway.download_attachment(
            context,
            &validated_session,
            &mailbox_name,
            uid,
            &part_path,
        );
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserAttachmentDownloadDecision::Downloaded { attachment, .. } => {
                HandledHttpResponse {
                    response: attachment_download_response(&attachment),
                    audit_events,
                }
            }
            BrowserAttachmentDownloadDecision::Denied { public_reason } => {
                let (status_code, reason_phrase, title) = match public_reason.as_str() {
                    "invalid_request" => (400, "Bad Request", "Invalid Attachment Request"),
                    "not_found" => (404, "Not Found", "Attachment Not Found"),
                    _ => (
                        503,
                        "Service Unavailable",
                        "Attachment Download Unavailable",
                    ),
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

fn selected_bulk_archive_uids(
    form: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<u64>, String> {
    let mut selected = std::collections::BTreeSet::new();
    for (field_name, field_value) in form {
        if !field_name.starts_with("uid_") {
            continue;
        }
        if selected.len() >= MAX_BULK_ARCHIVE_MESSAGES {
            return Err("too many selected messages".to_string());
        }
        let uid = field_value
            .parse::<u64>()
            .map_err(|_| format!("invalid selected uid value in {field_name}"))?;
        if uid == 0 {
            return Err(format!("invalid selected uid value in {field_name}"));
        }
        selected.insert(uid);
    }

    Ok(selected.into_iter().collect())
}
