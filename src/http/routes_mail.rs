//! Mailbox and content route handlers for the bounded browser runtime.
//!
//! Keeping mailbox and message routes separate from auth/session and transport
//! code reduces the amount of mail-specific browser behavior concentrated in
//! `http.rs` without changing the route surface.

use super::*;
use crate::mail_list::ListViewState;

pub(super) fn mailbox_is_user_visible(mailbox_name: &str) -> bool {
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

fn list_view_state(request: &HttpRequest) -> Result<ListViewState, HttpResponse> {
    let mut query = request.query_params.clone();
    if !query.contains_key("sort") && !query.contains_key("dir") {
        let preferences = crate::reading_preferences::ReadingPreferences::from_cookie_header(
            request.headers.get("cookie").map(String::as_str),
        );
        query.insert("sort".into(), "received".into());
        query.insert("dir".into(), preferences.date_order.sort_direction().into());
    }
    ListViewState::from_query(&query).map_err(|message| {
        html_response(
            400,
            "Bad Request",
            "Invalid Message List Request",
            TrustedHtml::from_template(format!("<p>{}</p>", escape_html(message))),
        )
    })
}

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    /// The URL chooses a candidate, not authority. Bind this response to the
    /// fresh filtered list identity before exposing the rendered message body.
    fn selected_message_pane(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        view: &ListViewState,
        audit: &mut Vec<LogEvent>,
    ) -> SelectedMessagePane {
        let Some(selection) = &view.selection else {
            return SelectedMessagePane::Unselected;
        };
        if view.selection_page.is_none() {
            return SelectedMessagePane::Unavailable("The selected message is no longer in these results. Choose another message or clear the selection.");
        }
        let Some(version) = &view.selected_version else {
            return SelectedMessagePane::Unavailable("The selected message has no current stored identity. Refresh the list or open the standalone message view.");
        };
        let (guard, event) = match self.acquire_mailbox_budget(context, session, "selected_message")
        {
            Ok(value) => value,
            Err(response) => {
                audit.extend(response.audit_events);
                return SelectedMessagePane::Unavailable(
                    "The reading pane is busy. Refresh this page to try again.",
                );
            }
        };
        audit.push(event);
        let outcome =
            self.gateway
                .view_message(context, session, &selection.mailbox, selection.uid);
        audit.extend(outcome.audit_events);
        audit.push(self.release_request_budget(guard, "selected_message", context, session));
        match outcome.decision {
            BrowserMessageViewDecision::Rendered { canonical_username, rendered }
                if canonical_username == session.record.canonical_username
                    && rendered.mailbox_name == selection.mailbox
                    && rendered.uid == selection.uid
                    && rendered.metadata.as_ref().is_some_and(|metadata| &metadata.version == version) => {
                SelectedMessagePane::Ready(rendered)
            }
            BrowserMessageViewDecision::Rendered { .. } => {
                audit.push(build_http_warning_event("selected_message_identity_changed", "selected message no longer matched the current list identity", context));
                SelectedMessagePane::Unavailable("The selected message changed while opening it. Refresh the list before opening it again.")
            }
            BrowserMessageViewDecision::Denied { .. } => SelectedMessagePane::Unavailable("The selected message could not be opened. Refresh this page or choose another message."),
        }
    }

    /// Resolves an account's configured archive target; never invents a folder.
    pub(super) fn handle_mailbox_shortcut(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let notice = |status, reason, title, message, audit_events| HandledHttpResponse {
            response: html_response(
                status,
                reason,
                title,
                render_navigation_notice(
                    &validated_session.record.canonical_username,
                    &validated_session.record.csrf_token,
                    title,
                    message,
                ),
            ),
            audit_events,
        };
        if request.query_params.len() != 1
            || request.query_params.get("kind").map(String::as_str) != Some("archive")
        {
            return notice(
                400,
                "Bad Request",
                "Unknown Mailbox Shortcut",
                "Choose a mailbox from the navigation.",
                audit_events,
            );
        }
        let outcome = self.gateway.load_settings(context, &validated_session);
        audit_events.extend(outcome.audit_events);
        let archive = match outcome.decision {
            BrowserSettingsDecision::Loaded { settings, .. } => match settings.archive_mailbox_name
            {
                Some(name) => name,
                None => {
                    return notice(
                        200,
                        "OK",
                        "Choose Your Archive Mailbox",
                        "Select an existing archive mailbox in Settings to use this shortcut.",
                        audit_events,
                    )
                }
            },
            BrowserSettingsDecision::Denied { .. } => {
                return notice(
                    503,
                    "Service Unavailable",
                    "Archive Temporarily Unavailable",
                    "Your archive setting could not be loaded. Try again shortly.",
                    audit_events,
                )
            }
        };
        let outcome = self.gateway.list_mailboxes(context, &validated_session);
        audit_events.extend(outcome.audit_events);
        match outcome.decision {
            BrowserMailboxDecision::Listed { mailboxes, .. } if mailbox_name_exists(&mailboxes, &archive) => HandledHttpResponse {
                response: redirect_response(303, "See Other", &format!("/mailbox?name={}", url_encode(&archive))),
                audit_events,
            },
            BrowserMailboxDecision::Listed { .. } => notice(404, "Not Found", "Archive Mailbox Not Found", "Your saved archive mailbox is no longer available. Choose another mailbox in Settings.", audit_events),
            BrowserMailboxDecision::Denied { .. } => notice(503, "Service Unavailable", "Archive Temporarily Unavailable", "Your mailboxes could not be loaded. Try again shortly.", audit_events),
        }
    }

    pub(super) fn validated_archive_mailbox_name(
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
                        render_mailboxes_page(
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
                    TrustedHtml::from_template(format!(
                        "<p>{}</p>",
                        escape_html(public_reason_message(&public_reason))
                    )),
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
        // A query parameter is not evidence that a mutation completed.
        let success_message: Option<String> = None;

        let mut view = match list_view_state(request) {
            Ok(view) => view,
            Err(response) => {
                return HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
        };
        let outcome = self
            .gateway
            .list_messages(context, &validated_session, &mailbox_name);
        audit_events.extend(outcome.audit_events);

        match outcome.decision {
            BrowserMessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                mut messages,
            } => {
                let archive_mailbox_name = self.validated_archive_mailbox_name(
                    context,
                    &validated_session,
                    &mut audit_events,
                );
                let bulk_move_destinations = self.bulk_move_destinations(
                    context,
                    &validated_session,
                    &mut audit_events,
                    &mailbox_name,
                    archive_mailbox_name.as_deref(),
                );
                view.apply_messages(&mut messages);
                let reader = MailReaderContext {
                    pane: self.selected_message_pane(
                        context,
                        &validated_session,
                        &view,
                        &mut audit_events,
                    ),
                    archive_mailbox_name: archive_mailbox_name.clone(),
                    mailboxes: bulk_move_destinations
                        .iter()
                        .map(|name| MailboxEntry { name: name.clone() })
                        .collect(),
                };
                let search_query = request
                    .query_params
                    .get("q")
                    .map(String::as_str)
                    .filter(|query| !query.is_empty());
                let search_scope = request
                    .query_params
                    .get("scope")
                    .map(String::as_str)
                    .filter(|scope| *scope == "all");

                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Mailbox Messages",
                        render_message_list_page(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            &mailbox_name,
                            &messages,
                            success_message.as_deref(),
                            MessageListBulkActions {
                                archive_mailbox_name: archive_mailbox_name.as_deref(),
                                move_destinations: &bulk_move_destinations,
                            },
                            MessageListSortLinks {
                                view: &view,
                                search_query,
                                search_scope,
                                reader: &reader,
                            },
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
                    crate::http_ui::render_content_notice(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        "Message list unavailable",
                        public_reason_message(&public_reason),
                        "/mailboxes",
                        Some(&format!("/mailbox?name={}", url_encode(&mailbox_name))),
                    ),
                ),
                audit_events,
            },
        }
    }

    fn bulk_move_destinations(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        audit_events: &mut Vec<LogEvent>,
        source_mailbox_name: &str,
        archive_mailbox_name: Option<&str>,
    ) -> Vec<String> {
        let outcome = self.gateway.list_mailboxes(context, validated_session);
        audit_events.extend(outcome.audit_events);
        let mailboxes = match outcome.decision {
            BrowserMailboxDecision::Listed { mailboxes, .. } => mailboxes,
            BrowserMailboxDecision::Denied { public_reason } => {
                audit_events.push(
                    build_http_warning_event(
                        "bulk_move_destinations_unresolved",
                        "bulk move visible destinations could not be resolved",
                        context,
                    )
                    .with_field("public_reason", public_reason),
                );
                return Vec::new();
            }
        };

        let mut destinations = Vec::new();
        for mailbox in filter_user_visible_mailboxes(&mailboxes) {
            if mailbox.name != source_mailbox_name && !destinations.contains(&mailbox.name) {
                destinations.push(mailbox.name);
            }
        }
        if let Some(archive_mailbox_name) = archive_mailbox_name {
            if archive_mailbox_name != source_mailbox_name
                && mailbox_name_exists(&mailboxes, archive_mailbox_name)
                && !destinations
                    .iter()
                    .any(|destination| destination == archive_mailbox_name)
            {
                destinations.insert(0, archive_mailbox_name.to_string());
            }
        }
        destinations
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
        let search_field = match request.query_params.get("field").map(String::as_str) {
            Some(value) => match MessageSearchField::from_query_value(value) {
                Some(field) => field,
                None => {
                    return HandledHttpResponse {
                        response: html_response(
                            400,
                            "Bad Request",
                            "Invalid Search Request",
                            "<p>The selected search field is not supported.</p>",
                        ),
                        audit_events: vec![build_http_warning_event(
                            "http_search_field_rejected",
                            "search field parameter rejected",
                            context,
                        )
                        .with_field("field", "unsupported")],
                    };
                }
            },
            None => MessageSearchField::All,
        };

        let (validated_session, mut audit_events) =
            match self.require_validated_session(request, context) {
                Ok(result) => result,
                Err(response) => return response,
            };
        let mut view = match list_view_state(request) {
            Ok(view) => view,
            Err(response) => {
                return HandledHttpResponse {
                    response,
                    audit_events,
                }
            }
        };
        let (budget_guard, budget_event) =
            match self.acquire_search_budget(context, &validated_session) {
                Ok(result) => result,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
        audit_events.push(budget_event);

        let outcome = self.gateway.search_messages(
            context,
            &validated_session,
            mailbox_name.as_deref(),
            &query,
            search_field,
        );
        audit_events.extend(outcome.audit_events);

        let mut handled = match outcome.decision {
            BrowserMessageSearchDecision::Listed {
                canonical_username,
                mailbox_name,
                query,
                mut results,
            } => {
                view.apply_search(&mut results);
                let pane = self.selected_message_pane(
                    context,
                    &validated_session,
                    &view,
                    &mut audit_events,
                );
                let mut reader = MailReaderContext {
                    pane,
                    ..MailReaderContext::default()
                };
                if let SelectedMessagePane::Ready(rendered) = &reader.pane {
                    reader.archive_mailbox_name = self.validated_archive_mailbox_name(
                        context,
                        &validated_session,
                        &mut audit_events,
                    );
                    reader.mailboxes = self
                        .bulk_move_destinations(
                            context,
                            &validated_session,
                            &mut audit_events,
                            &rendered.mailbox_name,
                            reader.archive_mailbox_name.as_deref(),
                        )
                        .into_iter()
                        .map(|name| MailboxEntry { name })
                        .collect();
                }

                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Message Search",
                        render_message_search_page(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            mailbox_name.as_deref(),
                            &query,
                            &results,
                            MessageSearchContext {
                                view: &view,
                                field: search_field,
                                reader: &reader,
                            },
                        ),
                    ),
                    audit_events,
                }
            }
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
                        TrustedHtml::from_template(format!(
                            "<p>{}</p>",
                            escape_html(public_reason_message(&public_reason))
                        )),
                    ),
                    audit_events,
                }
            }
        };
        handled.audit_events.push(self.release_request_budget(
            budget_guard,
            "message_search",
            context,
            &validated_session,
        ));
        handled
    }

    /// Handles per-message view requests for the validated browser session.
    pub(super) fn handle_message_view(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        if request.query_params.contains_key("view") {
            return self.handle_stored_content(request, context, false);
        }
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
        let (budget_guard, budget_event) =
            match self.acquire_mailbox_budget(context, &validated_session, "message_view") {
                Ok(result) => result,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
        audit_events.push(budget_event);

        let outcome = self
            .gateway
            .view_message(context, &validated_session, &mailbox_name, uid);
        audit_events.extend(outcome.audit_events);

        let mut handled = match outcome.decision {
            BrowserMessageViewDecision::Rendered {
                canonical_username,
                rendered,
            } if canonical_username == validated_session.record.canonical_username
                && rendered.mailbox_name == mailbox_name
                && rendered.uid == uid =>
            {
                let archive_mailbox_name = self.validated_archive_mailbox_name(
                    context,
                    &validated_session,
                    &mut audit_events,
                );
                let visible_mailboxes =
                    match self.gateway.list_mailboxes(context, &validated_session) {
                        BrowserMailboxOutcome {
                            decision: BrowserMailboxDecision::Listed { mailboxes, .. },
                            audit_events: mailbox_audit_events,
                        } => {
                            audit_events.extend(mailbox_audit_events);
                            filter_user_visible_mailboxes(&mailboxes)
                        }
                        BrowserMailboxOutcome {
                            decision: BrowserMailboxDecision::Denied { public_reason },
                            audit_events: mailbox_audit_events,
                        } => {
                            audit_events.extend(mailbox_audit_events);
                            audit_events.push(
                                build_http_warning_event(
                                    "message_view_move_destinations_unresolved",
                                    "message view visible move destinations could not be resolved",
                                    context,
                                )
                                .with_field("public_reason", public_reason),
                            );
                            Vec::new()
                        }
                    };

                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Message View",
                        render_message_view_page(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            &rendered,
                            archive_mailbox_name.as_deref(),
                            &visible_mailboxes,
                        ),
                    ),
                    audit_events,
                }
            }
            BrowserMessageViewDecision::Rendered { .. } => HandledHttpResponse {
                response: html_response(
                    503,
                    "Service Unavailable",
                    "Message View Unavailable",
                    crate::http_ui::render_content_notice(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        "Message unavailable",
                        "The message identity could not be confirmed. Return to the mailbox.",
                        &format!("/mailbox?name={}", url_encode(&mailbox_name)),
                        None,
                    ),
                ),
                audit_events,
            },
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
                        crate::http_ui::render_content_notice(
                            &validated_session.record.canonical_username,
                            &validated_session.record.csrf_token,
                            title,
                            public_reason_message(&public_reason),
                            &format!("/mailbox?name={}", url_encode(&mailbox_name)),
                            (status_code == 503)
                                .then_some(format!(
                                    "/message?mailbox={}&uid={uid}",
                                    url_encode(&mailbox_name)
                                ))
                                .as_deref(),
                        ),
                    )
                },
                audit_events,
            },
        };
        handled.audit_events.push(self.release_request_budget(
            budget_guard,
            "message_view",
            context,
            &validated_session,
        ));
        handled
    }

    /// Handles one session-gated attachment download request.
    pub(super) fn handle_attachment_download(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        if request.query_params.contains_key("mailbox_guid")
            || request.query_params.contains_key("message_guid")
        {
            return self.handle_stored_content(request, context, true);
        }
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

        let (budget_guard, budget_event) =
            match self.acquire_mailbox_budget(context, &validated_session, "attachment_download") {
                Ok(result) => result,
                Err(mut response) => {
                    audit_events.extend(response.audit_events);
                    response.audit_events = audit_events;
                    return response;
                }
            };
        audit_events.push(budget_event);

        let outcome = self.gateway.download_attachment(
            context,
            &validated_session,
            &mailbox_name,
            uid,
            &part_path,
        );
        audit_events.extend(outcome.audit_events);

        let mut handled = match outcome.decision {
            BrowserAttachmentDownloadDecision::Downloaded { canonical_username, attachment }
                if canonical_username == validated_session.record.canonical_username
                    && attachment.mailbox_name == mailbox_name && attachment.uid == uid
                    && attachment.part_path == part_path => {
                HandledHttpResponse {
                    response: attachment_download_response(&attachment),
                    audit_events,
                }
            }
            BrowserAttachmentDownloadDecision::Downloaded { .. } => HandledHttpResponse {
                response: html_response(503, "Service Unavailable", "Attachment Download Unavailable", "<p>The attachment identity could not be confirmed. Return to the message and try again.</p>"),
                audit_events,
            },
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
                        crate::http_ui::render_content_notice(&validated_session.record.canonical_username,
                            &validated_session.record.csrf_token, title, public_reason_message(&public_reason),
                            &format!("/message?mailbox={}&uid={uid}", url_encode(&mailbox_name)),
                            (status_code == 503).then_some(format!("/attachment?mailbox={}&uid={uid}&part={}", url_encode(&mailbox_name), url_encode(&part_path))).as_deref()),
                    ),
                    audit_events,
                }
            }
        };
        handled.audit_events.push(self.release_request_budget(
            budget_guard,
            "attachment_download",
            context,
            &validated_session,
        ));
        handled
    }
}
