use super::*;
use crate::snooze::{MessageIdentity, SnoozeError};
use std::collections::{BTreeMap, BTreeSet};
fn matching(id: &MessageIdentity, f: &BTreeMap<String, String>) -> bool {
    f.get("mailbox").is_some_and(|v| v == id.folder())
        && f.get("uid").is_some_and(|v| *v == id.uid().to_string())
        && f.get("mailbox_guid")
            .is_some_and(|v| v == id.mailbox_guid())
        && f.get("message_guid")
            .is_some_and(|v| v == id.message_guid())
}
fn error_details(error: SnoozeError) -> (u16, &'static str, &'static str) {
    match error {
        SnoozeError::Invalid|SnoozeError::Missing => (400,"Bad Request","Choose a current message and an explicit UTC date/time in the next 30 days. The submitted snooze request was refused."),
        SnoozeError::Stale => (409,"Conflict","Snooze markers changed. Reload the current list before trying another change."),
        SnoozeError::Capacity => (409,"Conflict","The account already has 100 snooze markers. Cancel a marker or wait for expiry."),
        _ => (503,"Service Unavailable","Snooze state or this change could not be confirmed. Messages remain accessible; reload to inspect the stored markers."),
    }
}
impl<G: BrowserGateway> BrowserApp<G> {
    fn current_snooze_identity(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        fields: &BTreeMap<String, String>,
        audit: &mut Vec<LogEvent>,
    ) -> Result<MessageIdentity, SnoozeError> {
        let folder = fields.get("mailbox").ok_or(SnoozeError::Invalid)?;
        MailboxEntry::new(MailboxListingPolicy::default(), folder)
            .map_err(|_| SnoozeError::Invalid)?;
        let (guard, event) = self
            .acquire_mailbox_budget(context, session, "snooze_identity")
            .map_err(|_| SnoozeError::Unavailable)?;
        audit.push(event);
        let outcome = self.gateway.list_messages(context, session, folder);
        audit.extend(outcome.audit_events);
        audit.push(self.release_request_budget(guard, "snooze_identity", context, session));
        let BrowserMessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
        } = outcome.decision
        else {
            return Err(SnoozeError::Unavailable);
        };
        if canonical_username != session.record.canonical_username
            || mailbox_name != *folder
            || messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
        {
            return Err(SnoozeError::Unavailable);
        }
        let mut ids = BTreeSet::new();
        let mut guids = BTreeSet::new();
        let mut generation = None;
        let mut selected = None;
        for row in &messages {
            let id = MessageIdentity::from_summary(
                &session.record.canonical_username,
                &canonical_username,
                folder,
                row,
            )?;
            if !ids.insert(id.uid())
                || !guids.insert(id.message_guid().to_owned())
                || generation.as_ref().is_some_and(|g| g != id.mailbox_guid())
            {
                return Err(SnoozeError::Unavailable);
            }
            generation = Some(id.mailbox_guid().to_owned());
            if matching(&id, fields) {
                selected = Some(id)
            }
        }
        selected.ok_or(SnoozeError::Missing)
    }
    pub(super) fn handle_snoozed(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let result = if request.query_params.is_empty() {
            self.gateway.snooze_load(&session)
        } else {
            Err(SnoozeError::Invalid)
        };
        let (status, reason, error) = match result.as_ref() {
            Ok(_) => (200, "OK", None),
            Err(e) => {
                let (s, r, t) = error_details(*e);
                (s, r, Some(t))
            }
        };
        HandledHttpResponse {
            response: html_response(
                status,
                reason,
                "Snoozed messages",
                crate::http_ui::render_snoozed_page(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    result.as_ref().ok(),
                    error,
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_snooze(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.snooze_editor(request, context, None)
    }
    fn snooze_editor(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        posted: Option<&BTreeMap<String, String>>,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let fields = posted.unwrap_or(&request.query_params);
        let allowed = if posted.is_some() {
            &[
                "csrf_token",
                "action",
                "revision",
                "mailbox",
                "uid",
                "mailbox_guid",
                "message_guid",
                "until",
                "return_to",
            ][..]
        } else {
            &[
                "mailbox",
                "uid",
                "mailbox_guid",
                "message_guid",
                "return_to",
            ][..]
        };
        let valid = fields.keys().all(|k| allowed.contains(&k.as_str()))
            && fields
                .get("return_to")
                .is_none_or(|v| crate::mail_navigation::safe_mail_return(v).is_some());
        let identity = if valid {
            self.current_snooze_identity(context, &session, fields, &mut audit_events)
        } else {
            Err(SnoozeError::Invalid)
        };
        let identity = match identity {
            Ok(v) => v,
            Err(e) => {
                let (s, r, t) = error_details(e);
                return HandledHttpResponse {
                    response: html_response(
                        s,
                        r,
                        "Snooze unavailable",
                        crate::http_ui::render_snoozed_page(
                            &session.record.canonical_username,
                            &session.record.csrf_token,
                            None,
                            Some(t),
                        ),
                    ),
                    audit_events,
                };
            }
        };
        let record = self.gateway.snooze_load(&session);
        let mut result = record.as_ref().map(|_| ()).map_err(|e| *e);
        if posted.is_some() && result.is_ok() {
            result = (|| {
                if fields.get("action").map(String::as_str) != Some("set") {
                    return Err(SnoozeError::Invalid);
                }
                let revision = fields
                    .get("revision")
                    .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v))
                    .ok_or(SnoozeError::Invalid)?;
                let until = crate::snooze::parse_utc(
                    fields.get("until").ok_or(SnoozeError::Invalid)?,
                    self.gateway.snooze_clock(),
                )?;
                self.gateway
                    .snooze_change(&session, &identity, revision, Some(until))
                    .map(|_| ())
            })();
            if result.is_ok() {
                return HandledHttpResponse {
                    response: redirect_response(
                        303,
                        "See Other",
                        &fields
                            .get("return_to")
                            .and_then(|v| {
                                crate::mail_navigation::mail_return_after_move(v, identity.folder())
                            })
                            .unwrap_or_else(|| "/snoozed".into()),
                    ),
                    audit_events,
                };
            }
        }
        let paused = matches!(
            result,
            Err(SnoozeError::Stale
                | SnoozeError::Unconfirmed
                | SnoozeError::Unavailable
                | SnoozeError::Corrupt
                | SnoozeError::ClockRollback)
        );
        let (s, r, error) = match result {
            Ok(()) => (200, "OK", None),
            Err(e) => {
                let (s, r, t) = error_details(e);
                (s, r, Some(t))
            }
        };
        let current = record.as_ref().ok();
        HandledHttpResponse {
            response: html_response(
                s,
                r,
                "Snooze message",
                crate::http_ui::render_snooze_page(&crate::http_ui::SnoozePageModel {
                    account: &session.record.canonical_username,
                    csrf: &session.record.csrf_token,
                    identity: &identity,
                    revision: fields
                        .get("revision")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(|| current.map_or(0, |r| r.revision())),
                    until_utc: fields.get("until").map_or("", String::as_str),
                    return_to: fields.get("return_to").map_or("", String::as_str),
                    error,
                    available: current.is_some() && !paused,
                    now: self.gateway.snooze_clock(),
                    current_until: current.and_then(|r| {
                        r.markers()
                            .iter()
                            .find(|m| m.identity() == &identity)
                            .map(|m| m.until())
                    }),
                }),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_snooze_change(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let fields = if allows_urlencoded_request_body(
            request.headers.get("content-type").map(String::as_str),
        ) {
            parse_urlencoded_form(&request.body, 9, 4096).ok()
        } else {
            None
        };
        let Some(fields) = fields else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid snooze request",
                    "<p>Reload Snoozed messages.</p>",
                ),
                audit_events,
            };
        };
        if let Some(r) = self.require_valid_csrf(
            request,
            fields.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return r;
        }
        if fields.get("action").map(String::as_str) != Some("cancel") {
            return self.snooze_editor(request, context, Some(&fields));
        }
        let result = (|| {
            if fields.keys().any(|k| {
                ![
                    "csrf_token",
                    "action",
                    "revision",
                    "mailbox",
                    "uid",
                    "mailbox_guid",
                    "message_guid",
                    "return_to",
                ]
                .contains(&k.as_str())
            }) || fields
                .get("return_to")
                .is_some_and(|v| crate::mail_navigation::safe_mail_return(v).is_none())
            {
                return Err(SnoozeError::Invalid);
            }
            let revision = fields
                .get("revision")
                .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v))
                .ok_or(SnoozeError::Invalid)?;
            let record = self.gateway.snooze_load(&session)?;
            let marker = record
                .markers()
                .iter()
                .find(|m| matching(m.identity(), &fields))
                .ok_or(SnoozeError::Missing)?;
            self.gateway
                .snooze_change(&session, marker.identity(), revision, None)
        })();
        match result {
            Ok(_) => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    fields
                        .get("return_to")
                        .map(String::as_str)
                        .unwrap_or("/snoozed"),
                ),
                audit_events,
            },
            Err(e) => {
                let (s, r, t) = error_details(e);
                let record = self.gateway.snooze_load(&session).ok();
                HandledHttpResponse {
                    response: html_response(
                        s,
                        r,
                        "Snoozed messages",
                        crate::http_ui::render_snoozed_page(
                            &session.record.canonical_username,
                            &session.record.csrf_token,
                            record.as_ref(),
                            Some(t),
                        ),
                    ),
                    audit_events,
                }
            }
        }
    }
    pub(super) fn apply_snooze(
        &self,
        session: &ValidatedSession,
        owner: &str,
        folder: &str,
        rows: &mut Vec<MessageSummary>,
    ) -> String {
        let p = self.gateway.snooze_project(session, owner, folder, rows);
        if p.unavailable.is_some() {
            return "Snooze is unavailable; no messages were hidden. Search and direct Reader access remain available.".into();
        }
        rows.retain(|row| {
            !p.hidden.iter().any(|id| {
                MessageIdentity::from_summary(
                    &session.record.canonical_username,
                    owner,
                    folder,
                    row,
                )
                .is_ok_and(|current| current == *id)
            })
        });
        if p.hidden.is_empty() {
            String::new()
        } else {
            format!(
                "{} snoozed messages hidden from this loaded mailbox set.",
                p.hidden.len()
            )
        }
    }
}
