//! Mailbox and content route handlers for the bounded browser runtime.
//!
//! Keeping mailbox and message routes separate from auth/session and transport
//! code reduces the amount of mail-specific browser behavior concentrated in
//! `http.rs` without changing the route surface.

use super::*;
use crate::mail_list::ListViewState;

pub(super) fn mailbox_is_user_visible(mailbox_name: &str) -> bool {
    matches!(
        mailbox_name,
        "INBOX" | "Archive" | "Drafts" | "Junk" | "Sent" | "Trash"
    ) || mailbox_name.starts_with("INBOX.")
}

pub(super) fn filter_user_visible_mailboxes(mailboxes: &[MailboxEntry]) -> Vec<MailboxEntry> {
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

fn list_origin(request: &HttpRequest) -> Option<String> {
    crate::mail_navigation::safe_mail_return(&format!(
        "{}?{}",
        request.path,
        request
            .query_params
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    ))
}

impl<G> BrowserApp<G>
where
    G: BrowserGateway,
{
    fn standalone_neighbours(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        rendered: &RenderedMessageView,
        audit: &mut Vec<LogEvent>,
    ) -> crate::reader_neighbours::ReaderNeighbours {
        use crate::reader_neighbours::{ReaderLocation, ReaderNeighbours};
        let account = &session.record.canonical_username;
        let Some(return_to) = request.query_params.get("return_to") else {
            let preferences = self.gateway.load_reading_preferences(context, session).ok();
            let summaries = self
                .gateway
                .list_messages(context, session, &rendered.mailbox_name);
            audit.extend(summaries.audit_events);
            return ReaderNeighbours::derive(
                account,
                rendered,
                preferences,
                &summaries.decision,
                None,
            );
        };
        let Some(origin) = crate::mail_navigation::safe_mail_return(return_to) else {
            return ReaderNeighbours::default();
        };
        let Some((path, query)) = origin.split_once('?') else {
            return ReaderNeighbours::unavailable(Some(origin.clone()));
        };
        let Ok(fields) = crate::http_form::parse_urlencoded_form(
            query.as_bytes(),
            crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
            2048,
        ) else {
            return ReaderNeighbours::unavailable(Some(origin.clone()));
        };
        let mut origin_request = request.clone();
        origin_request.query_params = fields.clone();
        let Ok(view) = list_view_state(&origin_request) else {
            return ReaderNeighbours::unavailable(Some(origin.clone()));
        };
        match path {
            "/mailbox" => {
                let Some(name) = fields.get("name") else {
                    return ReaderNeighbours::unavailable(Some(origin.clone()));
                };
                let mut summaries = self.gateway.list_messages(context, session, name);
                audit.append(&mut summaries.audit_events);
                if let BrowserMessageListDecision::Listed {
                    canonical_username,
                    mailbox_name,
                    messages,
                } = &mut summaries.decision
                {
                    self.apply_snooze(session, canonical_username, mailbox_name, messages);
                }
                ReaderNeighbours::derive_messages(
                    account,
                    rendered,
                    &summaries.decision,
                    &view,
                    &origin,
                    ReaderLocation::Standalone,
                )
            }
            "/search" if !fields.contains_key("category") => {
                let Some(query) = fields.get("q") else {
                    return ReaderNeighbours::unavailable(Some(origin.clone()));
                };
                let mailbox = if fields.get("scope").map(String::as_str) == Some("all") {
                    None
                } else {
                    fields.get("mailbox").map(String::as_str)
                };
                let field = fields
                    .get("field")
                    .and_then(|field| MessageSearchField::from_query_value(field))
                    .unwrap_or(MessageSearchField::All);
                let (guard, event) = match self.acquire_search_budget(context, session) {
                    Ok(value) => value,
                    Err(response) => {
                        audit.extend(response.audit_events);
                        return ReaderNeighbours::unavailable(Some(origin.clone()));
                    }
                };
                audit.push(event);
                let outcome = self
                    .gateway
                    .search_messages(context, session, mailbox, query, field);
                audit.extend(outcome.audit_events);
                audit.push(self.release_request_budget(guard, "message_search", context, session));
                ReaderNeighbours::derive_search(
                    account,
                    rendered,
                    &outcome.decision,
                    &view,
                    &origin,
                    ReaderLocation::Standalone,
                )
            }
            _ => ReaderNeighbours::unavailable(Some(origin.clone())),
        }
    }

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
        if view
            .requested_version
            .as_ref()
            .is_some_and(|expected| expected != version)
        {
            return SelectedMessagePane::Unavailable(
                "The selected message identity changed. Refresh the list before opening it again.",
            );
        }
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
            BrowserSettingsDecision::Loaded {
                ref canonical_username,
                ..
            } if canonical_username != &validated_session.record.canonical_username => {
                return notice(
                    503,
                    "Service Unavailable",
                    "Archive Temporarily Unavailable",
                    "Your archive setting could not be confirmed for this account.",
                    audit_events,
                );
            }
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
            BrowserMailboxDecision::Listed { ref canonical_username, .. } if canonical_username != &validated_session.record.canonical_username => notice(503, "Service Unavailable", "Archive Temporarily Unavailable", "Your mailbox list could not be confirmed for this account.", audit_events),
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
                decision:
                    BrowserSettingsDecision::Loaded {
                        canonical_username,
                        settings,
                    },
                audit_events: settings_audit_events,
            } => {
                audit_events.extend(settings_audit_events);
                (canonical_username == validated_session.record.canonical_username)
                    .then_some(settings.archive_mailbox_name)
                    .flatten()
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
            BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } => {
                if canonical_username != validated_session.record.canonical_username {
                    return None;
                }
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
                if canonical_username != validated_session.record.canonical_username {
                    return HandledHttpResponse {
                        response: html_response(
                            503,
                            "Service Unavailable",
                            "Mailbox Access Unavailable",
                            "<p>The mailbox list could not be verified.</p>",
                        ),
                        audit_events,
                    };
                }
                let (recent, draft_count, sent_count, snooze_notice) =
                    self.welcome_data(context, &validated_session, &mailboxes, &mut audit_events);
                let activity = self.gateway.list_sessions(context, &validated_session);
                audit_events.extend(activity.audit_events);
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
                            (recent.as_deref(), snooze_notice.as_deref()),
                            draft_count,
                            sent_count,
                            &activity.decision,
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
                if canonical_username != validated_session.record.canonical_username
                    || request.query_params.get("name") != Some(&mailbox_name)
                {
                    return HandledHttpResponse {
                        response: html_response(
                            503,
                            "Service Unavailable",
                            "Mailbox unavailable",
                            "<p>The returned mailbox summaries could not be verified.</p>",
                        ),
                        audit_events,
                    };
                }
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
                let snooze_notice = self.apply_snooze(
                    &validated_session,
                    &canonical_username,
                    &mailbox_name,
                    &mut messages,
                );
                let snapshot = BrowserMessageListDecision::Listed {
                    canonical_username: canonical_username.clone(),
                    mailbox_name: mailbox_name.clone(),
                    messages: messages.clone(),
                };
                view.apply_messages(&mut messages);
                let mut reader = MailReaderContext {
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
                    ..MailReaderContext::default()
                };
                if let (SelectedMessagePane::Ready(rendered), Some(origin)) =
                    (&reader.pane, list_origin(request))
                {
                    reader.neighbours = crate::reader_neighbours::ReaderNeighbours::derive_messages(
                        &canonical_username,
                        rendered,
                        &snapshot,
                        &view,
                        &origin,
                        crate::reader_neighbours::ReaderLocation::Coordinated,
                    );
                }
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
                            (!snooze_notice.is_empty()).then_some(snooze_notice.as_str()),
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
                    crate::http_ui::render_mail_load_failure(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        crate::http_ui::mailbox_nav_section(&mailbox_name, None),
                        public_reason_message(&public_reason),
                        &crate::http_ui::list_navigation_href(
                            &format!("/mailbox?name={}", url_encode(&mailbox_name)),
                            &view,
                            view.requested_page,
                        ),
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
        let query = request.query_params.get("q").cloned().unwrap_or_default();
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
        if query.trim().is_empty() {
            view.selection = None;
            view.page = 1;
            view.requested_page = 1;
            return HandledHttpResponse {
                response: html_response(
                    200,
                    "OK",
                    "Search",
                    render_message_search_page(
                        &validated_session.record.canonical_username,
                        &validated_session.record.csrf_token,
                        mailbox_name.as_deref(),
                        &query,
                        &[],
                        MessageSearchContext {
                            view: &view,
                            field: search_field,
                            reader: &MailReaderContext::default(),
                        },
                    ),
                ),
                audit_events,
            };
        }
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
                canonical_username, ..
            } if canonical_username != validated_session.record.canonical_username => {
                HandledHttpResponse {
                    response: html_response(
                        503,
                        "Service Unavailable",
                        "Message Search Unavailable",
                        "<p>The search results could not be verified for this account.</p>",
                    ),
                    audit_events,
                }
            }
            BrowserMessageSearchDecision::Listed {
                canonical_username,
                mailbox_name,
                query,
                mut results,
            } => {
                let snapshot = BrowserMessageSearchDecision::Listed {
                    canonical_username: canonical_username.clone(),
                    mailbox_name: mailbox_name.clone(),
                    query: query.clone(),
                    results: results.clone(),
                };
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
                    if let Some(origin) = list_origin(request) {
                        reader.neighbours =
                            crate::reader_neighbours::ReaderNeighbours::derive_search(
                                &canonical_username,
                                rendered,
                                &snapshot,
                                &view,
                                &origin,
                                crate::reader_neighbours::ReaderLocation::Coordinated,
                            );
                    }
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
                        if status_code == 503 {
                            let base = match &mailbox_name {
                                Some(name) => format!("/search?mailbox={}", url_encode(name)),
                                None => "/search?scope=all".into(),
                            };
                            crate::http_ui::render_mail_load_failure(
                                &validated_session.record.canonical_username,
                                &validated_session.record.csrf_token,
                                "search",
                                public_reason_message(&public_reason),
                                &crate::http_ui::list_navigation_href(
                                    &format!(
                                        "{base}&q={}&field={}",
                                        url_encode(&query),
                                        search_field.query_value()
                                    ),
                                    &view,
                                    view.requested_page,
                                ),
                            )
                        } else {
                            TrustedHtml::from_template(format!(
                                "<p>{}</p>",
                                escape_html(public_reason_message(&public_reason))
                            ))
                        },
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
                && rendered.uid == uid
                && crate::reader_neighbours::query_version_matches(
                    &request.query_params,
                    &rendered,
                ) =>
            {
                let neighbours = self.standalone_neighbours(
                    request,
                    context,
                    &validated_session,
                    &rendered,
                    &mut audit_events,
                );
                let archive_mailbox_name = self.validated_archive_mailbox_name(
                    context,
                    &validated_session,
                    &mut audit_events,
                );
                let visible_mailboxes =
                    match self.gateway.list_mailboxes(context, &validated_session) {
                        BrowserMailboxOutcome {
                            decision:
                                BrowserMailboxDecision::Listed {
                                    canonical_username,
                                    mailboxes,
                                },
                            audit_events: mailbox_audit_events,
                        } => {
                            audit_events.extend(mailbox_audit_events);
                            if canonical_username == validated_session.record.canonical_username {
                                filter_user_visible_mailboxes(&mailboxes)
                            } else {
                                Vec::new()
                            }
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
                        render_message_view_page_with_neighbours(
                            &canonical_username,
                            &validated_session.record.csrf_token,
                            &rendered,
                            archive_mailbox_name.as_deref(),
                            &visible_mailboxes,
                            &neighbours,
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

#[cfg(test)]
mod visibility_tests {
    use super::*;

    #[test]
    fn archive_folder_is_offered_only_when_returned_for_the_account() {
        let entry = |name: &str| MailboxEntry { name: name.into() };
        let listed = filter_user_visible_mailboxes(&[
            entry("INBOX"),
            entry("Archive"),
            entry("Shared/Other"),
        ]);
        assert_eq!(
            listed.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            vec!["INBOX", "Archive"]
        );
        assert!(!filter_user_visible_mailboxes(&[entry("INBOX")])
            .iter()
            .any(|m| m.name == "Archive"));
    }
}
