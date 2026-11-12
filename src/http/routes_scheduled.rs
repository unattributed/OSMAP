//! Owned scheduled snapshots. Gateway keeps journal/CAS and SMTP authority.
use super::*;
use crate::scheduled_send::Error;
use std::collections::BTreeMap;

fn revision(value: Option<&String>) -> Result<u64, Error> {
    value
        .and_then(|v| v.parse::<u64>().ok().filter(|n| n.to_string() == *v))
        .ok_or(Error::Invalid)
}
fn id(value: Option<&String>) -> Result<&str, Error> {
    let value = value.ok_or(Error::Invalid)?;
    crate::draft::validate_draft_id(value).map_err(|_| Error::Invalid)?;
    Ok(value)
}
fn exact(fields: &BTreeMap<String, String>, names: &[&str]) -> Result<(), Error> {
    if fields.len() != names.len() || fields.keys().any(|k| !names.contains(&k.as_str())) {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn due(
    fields: &BTreeMap<String, String>,
    now: u64,
    offset: crate::timezone::FixedOffset,
) -> Result<u64, Error> {
    if fields.get("timezone_offset").map(String::as_str) != Some(offset.as_str().as_str()) {
        return Err(Error::Stale);
    }
    offset
        .parse_schedule(fields.get("due_at").ok_or(Error::Invalid)?, now)
        .ok_or(Error::Invalid)
}
fn details(error: Error) -> (u16, &'static str, &'static str) {
    match error {
        Error::Invalid => (400,"Bad Request","Check the message and choose a future time in your saved OSMAP timezone within 30 days."),
        Error::NotFound => (404,"Not Found","This account's scheduled message is no longer available. Reload Outbox."),
        Error::Stale => (409,"Conflict","The saved message or OSMAP timezone changed, or this message can no longer be edited. Reload before another change."),
        Error::Capacity => (409,"Conflict","The saved-message or Drafts storage limit was reached. Free space before another change. If a return to Drafts was started, sending remains stopped; resume it from Outbox."),
        _ => (503,"Service Unavailable","The scheduled result could not be confirmed. Reload the saved list before another action; do not repeat an uncertain submission."),
    }
}
impl<G: BrowserGateway> BrowserApp<G> {
    fn scheduled_display(&self, session: &ValidatedSession) -> crate::scheduled_ui::Display {
        crate::scheduled_ui::Display {
            now: self.gateway.scheduled_clock(),
            offset: self
                .gateway
                .load_timezone(session)
                .ok()
                .map(|preference| preference.offset),
        }
    }
    fn scheduled_error(
        &self,
        session: &ValidatedSession,
        audit_events: Vec<LogEvent>,
        error: Error,
    ) -> HandledHttpResponse {
        let (status, reason, copy) = details(error);
        HandledHttpResponse {
            response: html_response(
                status,
                reason,
                "Outbox",
                crate::scheduled_ui::render_list(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    None,
                    None,
                    None,
                    Some(copy),
                    self.scheduled_display(session),
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_scheduled(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if request.query_params.keys().any(|k| k != "id") {
            return self.scheduled_error(&session, audit_events, Error::Invalid);
        }
        let selected = match request.query_params.get("id") {
            Some(v) => match id(Some(v)) {
                Ok(v) => Some(v),
                Err(e) => return self.scheduled_error(&session, audit_events, e),
            },
            None => None,
        };
        let list = match self.gateway.scheduled_list(&session) {
            Ok(v) => v,
            Err(e) => return self.scheduled_error(&session, audit_events, e),
        };
        let job = selected.and_then(|selected| list.jobs.iter().find(|j| j.id == selected));
        if selected.is_some() && job.is_none() {
            return self.scheduled_error(&session, audit_events, Error::NotFound);
        }
        let display = self.scheduled_display(&session);
        let attempts = self.gateway.outbox_attempts(&session).ok();
        let mut payload_error = None;
        let payload = match job {
            Some(j)
                if !matches!(
                    j.state,
                    crate::scheduled_send::State::Submitted
                        | crate::scheduled_send::State::Cancelled
                        | crate::scheduled_send::State::Failed
                ) =>
            {
                match self.gateway.scheduled_payload(&session, &j.id) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        if display.now < j.payload_expires_at {
                            payload_error = Some(e);
                        }
                        None
                    }
                }
            }
            _ => None,
        };
        let (status, reason, copy) = payload_error.map_or((200, "OK", None), |error| {
            let (status, reason, copy) = details(error);
            (status, reason, Some(copy))
        });
        HandledHttpResponse {
            response: html_response(
                status,
                reason,
                "Outbox",
                crate::scheduled_ui::render_outbox(
                    &session.record.canonical_username,
                    &session.record.csrf_token,
                    Some(&list),
                    job,
                    payload.as_ref(),
                    copy,
                    display,
                    attempts.as_deref(),
                ),
            ),
            audit_events,
        }
    }
    pub(super) fn handle_scheduled_new(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let parsed = (|| {
            exact(&request.query_params, &["draft", "revision"])?;
            Ok::<_, Error>((
                id(request.query_params.get("draft"))?,
                revision(request.query_params.get("revision"))?,
            ))
        })();
        let (draft_id, expected) = match parsed {
            Ok(v) => v,
            Err(e) => return self.scheduled_error(&session, audit_events, e),
        };
        let result = self.gateway.load_draft(context, &session, draft_id);
        audit_events.extend(result.audit_events);
        match result.decision {
            BrowserDraftLoadDecision::Loaded {
                canonical_username,
                draft,
            } if canonical_username == session.record.canonical_username
                && draft.canonical_username == canonical_username
                && draft.draft_id == draft_id
                && draft.source_attachments.is_none()
                && draft.revision == Some(expected) =>
            {
                HandledHttpResponse {
                    response: html_response(
                        200,
                        "OK",
                        "Schedule message",
                        crate::scheduled_ui::render_new(
                            &session.record.canonical_username,
                            &session.record.csrf_token,
                            &draft,
                            expected,
                            self.scheduled_display(&session),
                        ),
                    ),
                    audit_events,
                }
            }
            BrowserDraftLoadDecision::Loaded { .. } => {
                self.scheduled_error(&session, audit_events, Error::Stale)
            }
            BrowserDraftLoadDecision::NotFound => {
                self.scheduled_error(&session, audit_events, Error::NotFound)
            }
            _ => self.scheduled_error(&session, audit_events, Error::Unavailable),
        }
    }
    pub(super) fn handle_scheduled_create(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.scheduled_post(request, context, "create")
    }
    pub(super) fn handle_scheduled_edit(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.scheduled_post(request, context, "edit")
    }
    pub(super) fn handle_scheduled_change(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        self.scheduled_post(request, context, "change")
    }
    fn scheduled_post(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        operation: &str,
    ) -> HandledHttpResponse {
        let (session, audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if !request.query_params.is_empty() {
            return self.scheduled_error(&session, audit_events, Error::Invalid);
        }
        let fields = if allows_urlencoded_request_body(
            request.headers.get("content-type").map(String::as_str),
        ) {
            parse_urlencoded_form(&request.body, 11, 1024 * 1024).ok()
        } else {
            None
        };
        let Some(fields) = fields else {
            return self.scheduled_error(&session, audit_events, Error::Invalid);
        };
        if let Some(r) = self.require_valid_csrf(
            request,
            fields.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return r;
        }
        let result = (|| {
            let now = self.gateway.scheduled_clock();
            match operation {
                "create" => {
                    exact(
                        &fields,
                        &[
                            "csrf_token",
                            "draft",
                            "revision",
                            "due_at",
                            "timezone_offset",
                        ],
                    )?;
                    let job = self.gateway.scheduled_from_draft(
                        &session,
                        id(fields.get("draft"))?,
                        revision(fields.get("revision"))?,
                        due(
                            &fields,
                            now,
                            self.gateway
                                .load_timezone(&session)
                                .map_err(|_| Error::Unavailable)?
                                .offset,
                        )?,
                    )?;
                    crate::draft::validate_draft_id(&job).map_err(|_| Error::Unavailable)?;
                    Ok(Some(job))
                }
                "edit" => {
                    exact(
                        &fields,
                        &[
                            "csrf_token",
                            "id",
                            "revision",
                            "due_at",
                            "timezone_offset",
                            "to",
                            "cc",
                            "bcc",
                            "subject",
                            "body",
                        ],
                    )?;
                    self.gateway.scheduled_edit(
                        &session,
                        id(fields.get("id"))?,
                        revision(fields.get("revision"))?,
                        due(
                            &fields,
                            now,
                            self.gateway
                                .load_timezone(&session)
                                .map_err(|_| Error::Unavailable)?
                                .offset,
                        )?,
                        &fields["to"],
                        &fields["cc"],
                        &fields["bcc"],
                        &fields["subject"],
                        &fields["body"],
                    )?;
                    Ok(Some(fields["id"].clone()))
                }
                "change" => {
                    let action = fields
                        .get("action")
                        .map(String::as_str)
                        .ok_or(Error::Invalid)?;
                    let due_at = match action {
                        "cancel" | "delete" | "send_now" | "move_to_drafts" => {
                            exact(&fields, &["csrf_token", "id", "revision", "action"])?;
                            None
                        }
                        "reauthorize" => {
                            exact(
                                &fields,
                                &[
                                    "csrf_token",
                                    "id",
                                    "revision",
                                    "action",
                                    "due_at",
                                    "timezone_offset",
                                ],
                            )?;
                            Some(due(
                                &fields,
                                now,
                                self.gateway
                                    .load_timezone(&session)
                                    .map_err(|_| Error::Unavailable)?
                                    .offset,
                            )?)
                        }
                        _ => return Err(Error::Invalid),
                    };
                    self.gateway.scheduled_change(
                        &session,
                        id(fields.get("id"))?,
                        revision(fields.get("revision"))?,
                        action,
                        due_at,
                    )?;
                    Ok(Some(fields["id"].clone()))
                }
                _ => Err(Error::Invalid),
            }
        })();
        match result {
            Ok(selected) => HandledHttpResponse {
                response: redirect_response(
                    303,
                    "See Other",
                    &selected
                        .map(|id| {
                            if fields.get("action").map(String::as_str) == Some("move_to_drafts") {
                                format!("/draft?id={id}")
                            } else {
                                format!("/outbox?id={id}")
                            }
                        })
                        .unwrap_or_else(|| "/outbox".into()),
                ),
                audit_events,
            },
            Err(e) => self.scheduled_error(&session, audit_events, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_schedule_fields_refuse_unknown_duplicate_missing_and_noncanonical_values() {
        let parse = |text: &str| parse_urlencoded_form(text.as_bytes(), 10, 1024 * 1024);
        assert!(parse("revision=1&revision=2").is_err());
        let fields=parse("csrf_token=x&draft=0123456789abcdef0123456789abcdef&revision=1&due_at=2026-11-05T12%3A00").unwrap();
        assert!(exact(&fields, &["csrf_token", "draft", "revision", "due_at"]).is_ok());
        assert!(exact(&fields, &["csrf_token", "draft", "revision"]).is_err());
        assert_eq!(revision(Some(&"01".into())), Err(Error::Invalid));
        assert_eq!(
            revision(Some(&"18446744073709551616".into())),
            Err(Error::Invalid)
        );
        assert_eq!(revision(Some(&"0".into())), Ok(0));
        assert!(id(Some(&"0123456789ABCDEF0123456789ABCDEF".into())).is_err());
    }
    #[test]
    fn schedule_date_rejects_changed_missing_and_forged_account_offset() {
        let offset = crate::timezone::FixedOffset::parse("+07:00").unwrap();
        let now = 1_793_892_900;
        let mut fields = BTreeMap::from([
            ("due_at".into(), "2026-11-05T22:55".into()),
            ("timezone_offset".into(), "+07:00".into()),
        ]);
        assert_eq!(due(&fields, now, offset), Ok(now + 1200));
        for wrong in ["UTC", "+08:00", "UTC+07:00", ""] {
            fields.insert("timezone_offset".into(), wrong.into());
            assert_eq!(due(&fields, now, offset), Err(Error::Stale));
        }
        fields.remove("timezone_offset");
        assert_eq!(due(&fields, now, offset), Err(Error::Stale));
    }

    #[test]
    fn schedule_date_uses_saved_offset_future_and_bounded() {
        let now = 1_000_000;
        let text = crate::logging::format_unix_timestamp_utc(now + 3600);
        let mut fields = BTreeMap::from([
            ("due_at".into(), text[..16].into()),
            ("timezone_offset".into(), "UTC".into()),
        ]);
        assert!(due(&fields, now, crate::timezone::FixedOffset::default()).is_ok());
        for bad in ["2026-02-30T12:00", "2026-11-05T12:00+07:00", ""] {
            fields.insert("due_at".into(), bad.into());
            assert_eq!(
                due(&fields, now, crate::timezone::FixedOffset::default()),
                Err(Error::Invalid)
            );
        }
        fields.insert(
            "due_at".into(),
            crate::logging::format_unix_timestamp_utc(now + 31 * 86400)[..16].into(),
        );
        assert_eq!(
            due(&fields, now, crate::timezone::FixedOffset::default()),
            Err(Error::Invalid)
        );
    }
}
