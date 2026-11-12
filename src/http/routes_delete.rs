//! Explicit confirmation of one owned Bin tuple under helper-owned retention authority.
use super::*;
use crate::mailbox::{
    MessageDeleteError as E, MessageDeleteRequest, MessageDeleteResult, RetentionDecision,
};
use crate::message_metadata::MessageVersion;

fn deletion_target(
    form: &BTreeMap<String, String>,
) -> Option<(String, u64, MessageVersion, String)> {
    let mailbox = crate::bin_folder::parse_mailbox_name(form.get("mailbox")?).ok()?;
    let raw = form.get("uid")?;
    let uid = raw.parse::<u32>().ok()?;
    if uid == 0 || uid.to_string() != *raw {
        return None;
    }
    let version = MessageVersion::new(
        form.get("mailbox_guid")?.clone(),
        form.get("message_guid")?.clone(),
    )
    .ok()?;
    let back = crate::mail_navigation::mail_return_after_move(form.get("return_to")?, &mailbox)?;
    Some((mailbox, u64::from(uid), version, back))
}
pub(super) fn deletion_notice(
    session: &ValidatedSession,
    status: u16,
    reason: &'static str,
    title: &str,
    detail: &str,
    back: &str,
    events: Vec<LogEvent>,
) -> HandledHttpResponse {
    HandledHttpResponse { response: html_response(status, reason, title, TrustedHtml::from_template(format!(
        "{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>{}</h1><p role=\"status\">{}</p><a class=\"button-link\" href=\"{}\">Refresh message list</a></section></main>",
        crate::http_ui::app_header(&session.record.canonical_username, &session.record.csrf_token, "bin"), escape_html(title), escape_html(detail), escape_html(back)))), audit_events: events }
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_message_delete(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
    ) -> HandledHttpResponse {
        let (session, mut events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let invalid = |events| {
            deletion_notice(
                &session,
                400,
                "Bad Request",
                "Invalid Deletion Request",
                "Choose a current message in your saved Bin. No deletion was attempted.",
                "/mailboxes",
                events,
            )
        };
        let post = request.method == HttpMethod::Post;
        let form = if post {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return invalid(events);
            }
            match parse_urlencoded_form(&request.body, 8, 16384) {
                Ok(v) => v,
                Err(_) => return invalid(events),
            }
        } else {
            request.query_params.clone()
        };
        if post {
            if let Some(response) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return response;
            }
        }
        let allowed = [
            "mailbox",
            "uid",
            "mailbox_guid",
            "message_guid",
            "return_to",
        ];
        if form.len() != if post { 8 } else { 5 }
            || form.keys().any(|k| {
                !(allowed.contains(&k.as_str())
                    || post && ["csrf_token", "policy_revision", "confirm"].contains(&k.as_str()))
            })
        {
            return invalid(events);
        }
        let Some((mailbox, uid, version, back)) = deletion_target(&form) else {
            return invalid(events);
        };
        let submitted_revision = if post {
            let Some(raw) = form.get("policy_revision") else {
                return invalid(events);
            };
            let Ok(value) = raw.parse::<u64>() else {
                return invalid(events);
            };
            if value == 0
                || value.to_string() != *raw
                || !matches!(
                    form.get("confirm").map(String::as_str),
                    Some("delete" | "cancel")
                )
            {
                return invalid(events);
            }
            if form.get("confirm").map(String::as_str) == Some("cancel") {
                return HandledHttpResponse {
                    response: redirect_response(303, "See Other", &back),
                    audit_events: events,
                };
            }
            Some(value)
        } else {
            None
        };
        let (guard, event) = match self.acquire_mailbox_budget(context, &session, "message_delete")
        {
            Ok(v) => v,
            Err(mut r) => {
                events.extend(r.audit_events);
                r.audit_events = events;
                return r;
            }
        };
        events.push(event);
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(
                self.policy.expensive_request_timeout_secs.clamp(1, 30),
            );
        let unavailable = |events| {
            deletion_notice(&session, 503, "Service Unavailable", "Deletion Unavailable", "Current mail and retention permission could not be checked. No deletion was attempted.", &back, events)
        };
        let bin = match self.gateway.load_bin_preference(&session) {
            Ok(v) => v,
            Err(_) => return unavailable(events),
        };
        if bin.mailbox_name != mailbox {
            return invalid(events);
        }
        let listing = self.gateway.list_mailboxes(context, &session);
        events.extend(listing.audit_events);
        let BrowserMailboxDecision::Listed {
            canonical_username,
            mailboxes,
        } = listing.decision
        else {
            return unavailable(events);
        };
        if canonical_username != session.record.canonical_username
            || !mailboxes.iter().any(|m| m.name == mailbox)
        {
            return invalid(events);
        }
        if std::time::Instant::now() >= deadline {
            return unavailable(events);
        }
        let hierarchy = self.gateway.folder_metadata(context, &session);
        events.extend(hierarchy.audit_events);
        if hierarchy.canonical_username != session.record.canonical_username
            || !hierarchy.snapshot.as_ref().is_some_and(|s| {
                crate::bin_folder::selectable(s, &session.record.canonical_username, &mailbox)
            })
        {
            return unavailable(events);
        }
        if std::time::Instant::now() >= deadline {
            return unavailable(events);
        }
        // Deletion needs stored identity, not successful body rendering or decryption.
        let listed = self.gateway.list_messages(context, &session, &mailbox);
        events.extend(listed.audit_events);
        let summary = match listed.decision {
            BrowserMessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
            } if canonical_username == session.record.canonical_username
                && mailbox_name == mailbox =>
            {
                let mut candidates = messages.into_iter().filter(|m| m.uid == uid);
                match (candidates.next(), candidates.next()) {
                    (Some(m), None) if m.mailbox_name == mailbox && m.metadata.as_ref().is_some_and(|m| m.version == version) => m,
                    _ => return deletion_notice(&session,409,"Conflict","Message Changed","The stored message identity changed or is outside the current bounded list. No deletion was attempted.",&back,events),
                }
            }
            BrowserMessageListDecision::Listed { .. } => {
                return deletion_notice(
                    &session,
                    409,
                    "Conflict",
                    "Message Changed",
                    "The stored message identity changed. No deletion was attempted.",
                    &back,
                    events,
                )
            }
            _ => return unavailable(events),
        };
        if std::time::Instant::now() >= deadline {
            return unavailable(events);
        }
        let revision = match self.gateway.retention_status(&session, &mailbox) {
            RetentionDecision::Allowed { revision } => revision,
            RetentionDecision::Denied => return deletion_notice(&session,403,"Forbidden","Deletion Refused","Current retention policy does not permit permanent deletion. No deletion was attempted.",&back,events),
            RetentionDecision::Unavailable => return unavailable(events),
        };
        if submitted_revision.is_some_and(|v| v != revision) {
            return deletion_notice(
                &session,
                409,
                "Conflict",
                "Retention Permission Changed",
                "Review the current deletion permission again. No deletion was attempted.",
                &back,
                events,
            );
        }
        if std::time::Instant::now() >= deadline {
            return unavailable(events);
        }
        let target = match MessageDeleteRequest::new(
            &session.record.canonical_username,
            &mailbox,
            uid,
            version,
            revision,
        ) {
            Ok(v) => v,
            Err(_) => return invalid(events),
        };
        if !post {
            let fields = [
                ("csrf_token", session.record.csrf_token.clone()),
                ("mailbox", mailbox),
                ("uid", uid.to_string()),
                ("mailbox_guid", target.version.mailbox_guid),
                ("message_guid", target.version.message_guid),
                ("policy_revision", revision.to_string()),
                ("return_to", back.clone()),
            ]
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "<input type=\"hidden\" name=\"{k}\" value=\"{}\">",
                    escape_html(&v)
                )
            })
            .collect::<String>();
            drop(guard);
            return HandledHttpResponse { response: html_response(200,"OK","Confirm Permanent Deletion",TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Delete permanently?</h1><p>{}</p><p>This permanently removes this message from your Bin. It cannot be restored.</p><form action=\"/message/delete\" method=\"post\">{fields}<button name=\"confirm\" value=\"cancel\">Cancel</button><button name=\"confirm\" value=\"delete\">Delete permanently</button></form></section></main>", crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"bin"),escape_html(summary.subject.as_deref().unwrap_or("(No subject)"))))),audit_events:events };
        }
        let outcome = self.gateway.delete_message(context, &session, &target);
        events.extend(outcome.audit_events);
        events.push(self.release_request_budget(guard, "message_delete", context, &session));
        match outcome.result {
            Ok(MessageDeleteResult::Deleted) => deletion_notice(&session,200,"OK","Message Deleted","Permanent deletion was confirmed. Refresh the list to see the current messages.",&back,events),
            Err(E::Unknown) => deletion_notice(&session,503,"Service Unavailable","Deletion Unconfirmed","Deletion may have completed, but its result could not be confirmed. Refresh the message list before choosing any further action. Do not repeat this request.",&back,events),
            Err(E::Invalid) => invalid(events),
            Err(E::Stale) => deletion_notice(&session,409,"Conflict","Message Changed","The message or retention revision changed. No deletion was performed by this request.",&back,events),
            Err(E::PolicyDenied) => deletion_notice(&session,403,"Forbidden","Deletion Refused","Current retention policy refused deletion. No deletion was performed by this request.",&back,events),
            Err(E::PolicyUnavailable|E::Unavailable) => unavailable(events),
            Err(E::Busy) => {
                let mut r = deletion_notice(&session,429,"Too Many Requests","Deletion Busy","The mail action limit or another active mutation prevented deletion. No deletion was performed by this request.",&back,events);
                if let Some(seconds)=outcome.retry_after_seconds {r.response=r.response.with_header("Retry-After",seconds.to_string());} r
            }
        }
    }
}
