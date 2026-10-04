//! Account-owned Sent destination; this route never submits or moves mail.
use super::*;
use crate::sent_location::Error;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn sent_location_choices(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        audit: &mut Vec<LogEvent>,
    ) -> Option<Vec<MailboxEntry>> {
        let (guard, event) =
            match self.acquire_mailbox_budget(context, session, "sent_location_choices") {
                Ok(value) => value,
                Err(response) => {
                    audit.extend(response.audit_events);
                    return None;
                }
            };
        audit.push(event);
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(
                self.policy.expensive_request_timeout_secs.clamp(1, 30),
            );
        let listing = self.gateway.list_mailboxes(context, session);
        audit.extend(listing.audit_events);
        let choices = match listing.decision {
            BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } if canonical_username == session.record.canonical_username
                && super::routes_settings::valid_folder_listing(&mailboxes)
                && std::time::Instant::now() < deadline =>
            {
                let metadata = self.gateway.folder_metadata(context, session);
                audit.extend(metadata.audit_events);
                if metadata.canonical_username == canonical_username
                    && std::time::Instant::now() < deadline
                {
                    metadata
                        .snapshot
                        .as_ref()
                        .filter(|snapshot| snapshot.validate_for(&canonical_username).is_ok())
                        .map(|snapshot| {
                            mailboxes
                                .into_iter()
                                .filter(|entry| {
                                    crate::sent_location::selectable(
                                        snapshot,
                                        &canonical_username,
                                        &entry.name,
                                    )
                                })
                                .collect()
                        })
                } else {
                    None
                }
            }
            _ => None,
        };
        audit.push(self.release_request_budget(guard, "sent_location_choices", context, session));
        choices
    }

    fn qualified_sent_location(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        name: &str,
        audit: &mut Vec<LogEvent>,
        existing_budget: Option<&RequestBudgetGuard<'_>>,
    ) -> Result<crate::mailbox_status::MailboxStatus, Error> {
        crate::mailbox_status::validate_name(name).map_err(|_| Error::Invalid)?;
        // Standalone reader already holds this exact worker slot. Borrow it
        // through qualification instead of requiring a second slot at limit 1.
        let acquired = if let Some(guard) = existing_budget {
            if guard.released
                || !(std::ptr::eq(guard.budget, &self.request_budgets.mailbox_workers)
                    || std::ptr::eq(guard.budget, &self.request_budgets.search_workers))
            {
                return Err(Error::Unavailable);
            }
            None
        } else {
            let (guard, event) =
                match self.acquire_mailbox_budget(context, session, "sent_location_save") {
                    Ok(value) => value,
                    Err(response) => {
                        audit.extend(response.audit_events);
                        return Err(Error::Unavailable);
                    }
                };
            audit.push(event);
            Some(guard)
        };
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(
                self.policy.expensive_request_timeout_secs.clamp(1, 30),
            );
        let listing = self.gateway.list_mailboxes(context, session);
        audit.extend(listing.audit_events);
        let result = (|| {
            let BrowserMailboxDecision::Listed {
                canonical_username,
                mailboxes,
            } = listing.decision
            else {
                return Err(Error::Unavailable);
            };
            if canonical_username != session.record.canonical_username
                || !super::routes_settings::valid_folder_listing(&mailboxes)
                || std::time::Instant::now() >= deadline
            {
                return Err(Error::Unavailable);
            }
            if !mailboxes.iter().any(|entry| entry.name == name) {
                return Err(Error::Invalid);
            }
            let metadata = self.gateway.folder_metadata(context, session);
            audit.extend(metadata.audit_events);
            if metadata.canonical_username != canonical_username
                || std::time::Instant::now() >= deadline
            {
                return Err(Error::Unavailable);
            }
            let snapshot = metadata.snapshot.ok_or(Error::Unavailable)?;
            snapshot
                .validate_for(&canonical_username)
                .map_err(|_| Error::Unavailable)?;
            if !crate::sent_location::selectable(&snapshot, &canonical_username, name) {
                return Err(Error::Invalid);
            }
            let outcome = self.gateway.mailbox_status(context, session, name);
            audit.extend(outcome.audit_events);
            if outcome.canonical_username != canonical_username
                || std::time::Instant::now() >= deadline
            {
                return Err(Error::Unavailable);
            }
            outcome
                .status
                .filter(|status| status.validate(name).is_ok())
                .ok_or(Error::Unavailable)
        })();
        if let Some(guard) = acquired {
            audit.push(self.release_request_budget(guard, "sent_location_save", context, session));
        }
        result
    }

    pub(super) fn confirmed_sent_folder_role(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        current_mailbox: &str,
        audit: &mut Vec<LogEvent>,
        existing_budget: Option<&RequestBudgetGuard<'_>>,
    ) -> Option<crate::http_ui::SentFolderRole> {
        let saved = self.gateway.load_sent_location_preference(session).ok()?;
        if !saved.valid() {
            return None;
        }
        if saved.mailbox_guid.is_none() {
            return crate::http_ui::SentFolderRole::confirmed(&saved, None);
        }
        // Do not query an unrelated saved folder or reinterpret an arbitrary
        // query name as a rendering role. Current explicit target is rechecked.
        if saved.mailbox_name != current_mailbox {
            return None;
        }
        let status = self
            .qualified_sent_location(context, session, current_mailbox, audit, existing_budget)
            .ok()?;
        crate::http_ui::SentFolderRole::confirmed(&saved, Some(&status))
    }

    pub(super) fn handle_sent_location_settings(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let form = (request.query_params.is_empty()
            && allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ))
        .then(|| parse_urlencoded_form(&request.body, 3, 2048).ok())
        .flatten();
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Sent Location",
                    "<p>Reload Copies &amp; Folders before selecting an existing folder.</p>",
                ),
                audit_events: audit,
            };
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let revision = form.get("expected_revision").and_then(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|revision| revision.to_string() == *value)
        });
        let name = form.get("mailbox_name").map(String::as_str).unwrap_or("");
        let result = if form.keys().any(|key| {
            !matches!(
                key.as_str(),
                "csrf_token" | "expected_revision" | "mailbox_name"
            )
        }) {
            Err(Error::Invalid)
        } else {
            revision.ok_or(Error::Invalid).and_then(|revision| {
                let next = revision.checked_add(1).ok_or(Error::Invalid)?;
                let status =
                    self.qualified_sent_location(context, &session, name, &mut audit, None)?;
                self.gateway
                    .save_sent_location_preference(&session, revision, name, status.guid())
                    .and_then(|saved| {
                        if saved.revision == next
                            && saved.mailbox_name == name
                            && saved.mailbox_guid.as_deref() == Some(status.guid())
                            && saved.valid()
                        {
                            Ok(saved)
                        } else {
                            Err(Error::Unconfirmed)
                        }
                    })
            })
        };
        audit.push(build_http_info_event(
            if result.is_ok() {
                "sent_location_preference_saved"
            } else {
                "sent_location_preference_unconfirmed"
            },
            "Sent destination preference evaluated",
            context,
        ));
        let response = match result {
            Ok(_) => redirect_response(303, "See Other", "/settings?section=copies&updated=1"),
            Err(error) => html_response(match error { Error::Invalid => 400, Error::Stale => 409, Error::Unavailable | Error::Unconfirmed => 503 }, "Preference Not Confirmed", "Sent Location Not Confirmed", TrustedHtml::from_template(format!(
                "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Sent location not confirmed</h1><p>Submitted folder: {}. Reload the saved setting before another change. No mail was submitted and no messages were moved.</p><a href=\"/settings?section=copies\">Load saved Copies &amp; Folders</a></main>", escape_html(name)
            ))),
        };
        HandledHttpResponse {
            response,
            audit_events: audit,
        }
    }

    pub(super) fn handle_sent_location_shortcut(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let saved = self.gateway.load_sent_location_preference(&session);
        let target = match saved {
            Ok(saved) if saved.valid() => match saved.mailbox_guid.as_deref() {
                None => Ok(saved.mailbox_name),
                Some(guid) => self
                    .qualified_sent_location(
                        context,
                        &session,
                        &saved.mailbox_name,
                        &mut audit,
                        None,
                    )
                    .and_then(|status| {
                        if status.guid() == guid {
                            Ok(saved.mailbox_name)
                        } else {
                            Err(Error::Unavailable)
                        }
                    }),
            },
            _ => Err(Error::Unavailable),
        };
        let response = match target {
            Ok(name) => redirect_response(303, "See Other", &format!("/mailbox?name={}", url_encode(&name))),
            Err(_) => html_response(503, "Service Unavailable", "Sent Folder Unavailable", render_navigation_notice(&session.record.canonical_username, &session.record.csrf_token, "Sent folder unavailable", "The saved Sent folder could not be confirmed. Review Copies & Folders; no folder was created or substituted.")),
        };
        HandledHttpResponse {
            response,
            audit_events: audit,
        }
    }
}
