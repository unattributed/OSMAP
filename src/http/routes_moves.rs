//! One bounded form contract for reversible single and bulk mail moves.
use super::*;
use crate::mail_list::MAX_BULK_SELECTION;
use crate::message_metadata::MessageVersion;

fn selected_moves(
    form: &BTreeMap<String, String>,
    source: &str,
    destination: &str,
    bulk: bool,
) -> Option<Vec<MessageMoveRequest>> {
    let mut selected = Vec::new();
    if bulk {
        for (key, value) in form.iter().filter(|(key, _)| key.starts_with("message_")) {
            if selected.len() == MAX_BULK_SELECTION {
                return None;
            }
            let mut parts = value.splitn(3, '|');
            let uid_text = parts.next()?;
            let uid = uid_text.parse::<u32>().ok()?;
            if uid == 0 || uid.to_string() != uid_text || key != &format!("message_{uid}") {
                return None;
            }
            let version = MessageVersion::new(parts.next()?.into(), parts.next()?.into()).ok()?;
            selected.push(
                MessageMoveRequest::new(
                    MessageMovePolicy::default(),
                    source,
                    destination,
                    u64::from(uid),
                    version,
                )
                .ok()?,
            );
        }
    } else {
        let uid_text = form.get("uid")?;
        let uid = uid_text.parse::<u32>().ok()?;
        if uid == 0 || uid.to_string() != *uid_text {
            return None;
        }
        let version = MessageVersion::new(
            form.get("mailbox_guid")?.clone(),
            form.get("message_guid")?.clone(),
        )
        .ok()?;
        selected.push(
            MessageMoveRequest::new(
                MessageMovePolicy::default(),
                source,
                destination,
                u64::from(uid),
                version,
            )
            .ok()?,
        );
    }
    selected.sort_by_key(|message| message.uid);
    if selected.is_empty() {
        None
    } else {
        Some(selected)
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_message_move(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.handle_identity_moves(request, context, false, false)
    }
    pub(super) fn handle_bulk_move(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.handle_identity_moves(request, context, true, false)
    }
    pub(super) fn handle_bulk_archive(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.handle_identity_moves(request, context, true, true)
    }
    fn handle_identity_moves(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        bulk: bool,
        archive_only: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let notice = |status, reason, title, message: &str, events| HandledHttpResponse {
            response: html_response(
                status,
                reason,
                title,
                render_navigation_notice(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    title,
                    message,
                ),
            ),
            audit_events: events,
        };
        let invalid = |events| {
            notice(400, "Bad Request", "Invalid Message Move Request", "Select current messages and an available destination. A selection may contain at most ten messages.", events)
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return invalid(audit_events);
        }
        let form = match parse_urlencoded_form(
            &request.body,
            if bulk { MAX_BULK_SELECTION + 5 } else { 8 },
            16384,
        ) {
            Ok(form) => form,
            Err(_) => return invalid(audit_events),
        };
        if let Some(response) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return response;
        }
        let common = [
            "csrf_token",
            "mailbox",
            "destination_mailbox",
            "action",
            "return_to",
        ];
        if form.keys().any(|key| {
            !common.contains(&key.as_str())
                && !(if bulk {
                    key.starts_with("message_")
                } else {
                    ["uid", "mailbox_guid", "message_guid"].contains(&key.as_str())
                })
        }) {
            return invalid(audit_events);
        }
        let Some(source) = form.get("mailbox") else {
            return invalid(audit_events);
        };
        let Some(return_to) = form
            .get("return_to")
            .and_then(|value| crate::mail_navigation::mail_return_after_move(value, source))
        else {
            return invalid(audit_events);
        };
        let Some(action) = form.get("action").map(String::as_str) else {
            return invalid(audit_events);
        };
        if archive_only && action != "archive" {
            return invalid(audit_events);
        }
        let route_class = if archive_only {
            "bulk_message_archive"
        } else if bulk {
            "bulk_message_move"
        } else {
            "message_move"
        };
        let (guard, event) = match self.acquire_mailbox_budget(context, &session, route_class) {
            Ok(value) => value,
            Err(mut response) => {
                audit_events.extend(response.audit_events);
                response.audit_events = audit_events;
                return response;
            }
        };
        audit_events.push(event);
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(
                self.policy.expensive_request_timeout_secs.clamp(1, 30),
            );
        let destination = match action {
            "move" => form.get("destination_mailbox").cloned(),
            "archive" => self.validated_archive_mailbox_name(context, &session, &mut audit_events),
            "bin" if source != "Trash" => Some("Trash".into()),
            "restore" if source == "Trash" => Some("INBOX".into()),
            _ => None,
        };
        let Some(destination) = destination else {
            return invalid(audit_events);
        };
        if !super::routes_mail::mailbox_is_user_visible(&destination)
            && self
                .validated_archive_mailbox_name(context, &session, &mut audit_events)
                .as_deref()
                != Some(destination.as_str())
        {
            return invalid(audit_events);
        }
        let Some(selected) = selected_moves(&form, source, &destination, bulk) else {
            return invalid(audit_events);
        };
        // Resolve both folders against this session before the first mutation.
        let listing = self.gateway.list_mailboxes(context, &session);
        audit_events.extend(listing.audit_events);
        let BrowserMailboxDecision::Listed {
            canonical_username,
            mailboxes,
        } = listing.decision
        else {
            return notice(
                503,
                "Service Unavailable",
                "Move Unavailable",
                "Mailboxes could not be checked. No move was attempted.",
                audit_events,
            );
        };
        if canonical_username != session.record.canonical_username {
            return invalid(audit_events);
        }
        if !mailboxes.iter().any(|m| &m.name == source)
            || !mailboxes.iter().any(|m| m.name == destination)
        {
            return invalid(audit_events);
        }
        let next_after_archive = if !bulk
            && action == "archive"
            && std::time::Instant::now() < deadline
            && self
                .gateway
                .load_after_archive(&session)
                .is_ok_and(|v| v.choice == crate::after_archive::Choice::Next)
        {
            self.archive_navigation_rows(
                context,
                &session,
                &selected[0],
                &return_to,
                &mut audit_events,
            )
            .and_then(|rows| super::routes_after_archive::next_candidate(&rows, &selected[0]))
        } else {
            None
        };
        let total = selected.len();
        let mut label_uncertain = false;
        for (confirmed, selected) in selected.iter().enumerate() {
            let pending = if std::time::Instant::now() >= deadline {
                Err(crate::labels::LabelError::Unavailable)
            } else if self.gateway.labels_available() {
                self.labels_before_move(context, &session, selected, &mut audit_events)
            } else {
                Ok(None)
            };
            let outcome = if std::time::Instant::now() >= deadline {
                BrowserMessageMoveOutcome {
                    decision: BrowserMessageMoveDecision::Denied {
                        public_reason: "message_move_deadline".into(),
                        retry_after_seconds: None,
                    },
                    audit_events: Vec::new(),
                }
            } else {
                self.gateway.move_message(context, &session, selected)
            };
            audit_events.extend(outcome.audit_events);
            match outcome.decision {
                BrowserMessageMoveDecision::Moved {
                    source_mailbox_name,
                    destination_mailbox_name,
                    uid,
                } if source_mailbox_name == *source
                    && destination_mailbox_name == destination
                    && uid == selected.uid =>
                {
                    label_uncertain |= !self.labels_after_move(
                        context,
                        &session,
                        selected,
                        pending,
                        deadline,
                        &mut audit_events,
                    );
                }
                decision => {
                    let (public_reason, retry_after_seconds) = match decision {
                        BrowserMessageMoveDecision::Denied {
                            public_reason,
                            retry_after_seconds,
                        } => (public_reason, retry_after_seconds),
                        _ => ("message_move_unknown".into(), None),
                    };
                    let (status, reason, detail, uncertain) = match public_reason.as_str() {
                        "message_move_stale" | "invalid_message_reference" => (409, "Conflict", "The current message was moved, removed or replaced. Its move was refused.", 0),
                        "message_move_busy" => (409, "Conflict", "Another mail action is active. This move was refused.", 0),
                        "invalid_mailbox" | "invalid_request" => (400, "Bad Request", "The selected message or destination is no longer available. This move was refused.", 0),
                        TOO_MANY_MESSAGE_MOVES_PUBLIC_REASON => (429, "Too Many Requests", "The mail action limit has been reached. This move was refused.", 0),
                        "message_move_unavailable" => (503, "Service Unavailable", "The current message could not be checked. Its move was not attempted.", 0),
                        "message_move_deadline" => (503, "Service Unavailable", "The action time limit was reached. The current message and remaining selection were not attempted.", 0),
                        _ => (503, "Service Unavailable", "The current move may have completed, but its result could not be confirmed. Check both mailboxes before choosing another action.", 1),
                    };
                    let detail = if label_uncertain {
                        format!("{detail} Label continuity for earlier confirmed moves could not be confirmed. Do not repeat those mail moves.")
                    } else {
                        detail.to_owned()
                    };
                    let remaining = total - confirmed - 1;
                    let mut response = html_response(status, reason, "Move Stopped", TrustedHtml::from_template(format!(
                        "{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"panel\"><h1>Move stopped</h1><p>{}</p><p>{confirmed} confirmed moved; {uncertain} uncertain; {remaining} remaining messages were not attempted.</p><p><a class=\"button-link\" href=\"{}\">Refresh message list</a> <a class=\"button-link\" href=\"/mailbox?name={}\">Check destination</a></p></section></main>",
                        crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "mailboxes"),
                        escape_html(&detail), escape_html(&return_to), url_encode(&destination))));
                    if let Some(seconds) = retry_after_seconds {
                        response = response.with_header("Retry-After", seconds.to_string());
                    }
                    drop(guard);
                    return HandledHttpResponse {
                        response,
                        audit_events,
                    };
                }
            }
        }
        if label_uncertain {
            return notice(200,"OK","Messages Moved","All selected mail moves were confirmed. Label continuity could not be confirmed; labels may remain attached to old identities. Do not repeat the mail move to repair labels.",audit_events);
        }
        let next = next_after_archive.and_then(|candidate| {
            if std::time::Instant::now() >= deadline {
                return None;
            }
            let rows = self.archive_navigation_rows(
                context,
                &session,
                &selected[0],
                &return_to,
                &mut audit_events,
            )?;
            super::routes_after_archive::candidate_link(&rows, &candidate, &return_to)
        });
        drop(guard);
        HandledHttpResponse {
            response: redirect_response(303, "See Other", next.as_deref().unwrap_or(&return_to)),
            audit_events,
        }
    }
}
