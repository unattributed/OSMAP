//! Review and confirm a bounded set of exact owned Bin tuples; never replay partial work.
use super::routes_delete::deletion_notice;
use super::*;
use crate::mail_list::MAX_BULK_SELECTION;
use crate::mailbox::{
    MessageDeleteError as E, MessageDeleteRequest, MessageDeleteResult, RetentionDecision,
};
use crate::message_metadata::MessageVersion;
use sha2::{Digest, Sha256};

fn trash_snapshot(targets: &[MessageDeleteRequest]) -> String {
    let mut hash = Sha256::new();
    for target in targets {
        for value in [
            target.canonical_username.as_str(),
            target.mailbox_name.as_str(),
            &target.uid.to_string(),
            &target.version.mailbox_guid,
            &target.version.message_guid,
            &target.policy_revision.to_string(),
        ] {
            hash.update(value.len().to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    format!("{:x}", hash.finalize())
}

fn selected_deletions(
    fields: &BTreeMap<String, String>,
    account: &str,
    mailbox: &str,
    revision: u64,
) -> Option<Vec<MessageDeleteRequest>> {
    let mut targets = Vec::new();
    for (key, value) in fields.iter().filter(|(key, _)| key.starts_with("message_")) {
        if targets.len() == MAX_BULK_SELECTION {
            return None;
        }
        let mut parts = value.splitn(3, '|');
        let raw = parts.next()?;
        let uid = raw.parse::<u32>().ok()?;
        if uid == 0 || uid.to_string() != raw || key != &format!("message_{uid}") {
            return None;
        }
        let version = MessageVersion::new(parts.next()?.into(), parts.next()?.into()).ok()?;
        targets.push(
            MessageDeleteRequest::new(account, mailbox, u64::from(uid), version, revision).ok()?,
        );
    }
    targets.sort_by_key(|target| target.uid);
    if targets.is_empty() {
        None
    } else {
        Some(targets)
    }
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_bulk_delete(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        review: bool,
    ) -> HandledHttpResponse {
        let empty_trash = matches!(
            request.path.as_str(),
            "/trash/empty" | "/trash/empty/review"
        );
        let (session, mut events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let invalid = |events| {
            deletion_notice(
                &session,
                400,
                "Bad Request",
                "Invalid Deletion Selection",
                if empty_trash {
                    "Open your Trash and choose Empty trash to review the current messages. No deletion was attempted."
                } else {
                    "Select one to ten current messages in your saved Bin. No deletion was attempted."
                },
                "/mailboxes",
                events,
            )
        };
        if !allows_urlencoded_request_body(request.headers.get("content-type").map(String::as_str))
        {
            return invalid(events);
        }
        let form = match parse_urlencoded_form(&request.body, MAX_BULK_SELECTION + 5, 16384) {
            Ok(v) => v,
            Err(_) => return invalid(events),
        };
        if let Some(r) = self.require_valid_csrf(
            request,
            form.get("csrf_token").map(String::as_str),
            &session,
            context,
        ) {
            return r;
        }
        let common = if empty_trash && review {
            vec!["csrf_token", "mailbox", "return_to"]
        } else if empty_trash {
            vec![
                "csrf_token",
                "mailbox",
                "return_to",
                "policy_revision",
                "confirm",
                "snapshot",
            ]
        } else if review {
            [
                "csrf_token",
                "mailbox",
                "return_to",
                "action",
                "destination_mailbox",
            ]
            .to_vec()
        } else {
            [
                "csrf_token",
                "mailbox",
                "return_to",
                "policy_revision",
                "confirm",
            ]
            .to_vec()
        };
        if form.keys().any(|key| {
            !common.contains(&key.as_str()) && (empty_trash || !key.starts_with("message_"))
        }) {
            return invalid(events);
        }
        let Some(mailbox) = form
            .get("mailbox")
            .and_then(|s| crate::bin_folder::parse_mailbox_name(s).ok())
        else {
            return invalid(events);
        };
        let Some(back) = form
            .get("return_to")
            .and_then(|s| crate::mail_navigation::mail_return_after_move(s, &mailbox))
        else {
            return invalid(events);
        };
        let submitted = if review {
            if !empty_trash && form.get("action").map(String::as_str) != Some("review-delete") {
                return invalid(events);
            }
            None
        } else {
            let Some(raw) = form.get("policy_revision") else {
                return invalid(events);
            };
            let Ok(n) = raw.parse::<u64>() else {
                return invalid(events);
            };
            if n == 0
                || n.to_string() != *raw
                || !matches!(
                    form.get("confirm").map(String::as_str),
                    Some("delete" | "cancel")
                )
            {
                return invalid(events);
            }
            Some(n)
        };
        let mut targets = if empty_trash {
            Vec::new()
        } else {
            match selected_deletions(
                &form,
                &session.record.canonical_username,
                &mailbox,
                submitted.unwrap_or(1),
            ) {
                Some(value) => value,
                None => return invalid(events),
            }
        };
        if !review && form.get("confirm").map(String::as_str) == Some("cancel") {
            return HandledHttpResponse {
                response: redirect_response(303, "See Other", &back),
                audit_events: events,
            };
        }
        let (guard, event) =
            match self.acquire_mailbox_budget(context, &session, "bulk_message_delete") {
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
            deletion_notice(&session,503,"Service Unavailable","Deletion Unavailable","Current Bin mail and retention permission could not be checked. No deletion was attempted.",&back,events)
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
        let listed = self.gateway.list_messages(context, &session, &mailbox);
        events.extend(listed.audit_events);
        let BrowserMessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
        } = listed.decision
        else {
            return unavailable(events);
        };
        if canonical_username != session.record.canonical_username || mailbox_name != mailbox {
            return invalid(events);
        }
        if empty_trash {
            if messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES {
                return unavailable(events);
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut mailbox_guid = None;
            for message in &messages {
                let Some(meta) = message.metadata.as_ref() else {
                    return unavailable(events);
                };
                if message.mailbox_name != mailbox
                    || !seen.insert(message.uid)
                    || mailbox_guid.is_some_and(|guid| guid != &meta.version.mailbox_guid)
                {
                    return unavailable(events);
                }
                mailbox_guid = Some(&meta.version.mailbox_guid);
                let Ok(target) = MessageDeleteRequest::new(
                    &session.record.canonical_username,
                    &mailbox,
                    message.uid,
                    meta.version.clone(),
                    submitted.unwrap_or(1),
                ) else {
                    return unavailable(events);
                };
                targets.push(target);
            }
            targets.sort_by_key(|target| target.uid);
        }
        let mut subjects = Vec::new();
        // Validate the complete selection before the first mutation. Body rendering is irrelevant.
        for target in &targets {
            let mut matches = messages.iter().filter(|m| m.uid == target.uid);
            match(matches.next(),matches.next()){
                (Some(m),None)if m.mailbox_name==mailbox && m.metadata.as_ref().is_some_and(|meta|meta.version==target.version)=>subjects.push(m.subject.as_deref().unwrap_or("(No subject)")),
                _=>return deletion_notice(&session,409,"Conflict","Selection Changed","A selected identity changed or is outside the current bounded list. No deletion was attempted.",&back,events),
            }
        }
        if std::time::Instant::now() >= deadline {
            return unavailable(events);
        }
        let revision=match self.gateway.retention_status(&session,&mailbox){
            RetentionDecision::Allowed{revision}=>revision,
            RetentionDecision::Denied=>return deletion_notice(&session,403,"Forbidden","Deletion Refused","Current retention policy does not permit permanent deletion. No deletion was attempted.",&back,events),
            RetentionDecision::Unavailable=>return unavailable(events),
        };
        if submitted.is_some_and(|n| n != revision) {
            return deletion_notice(
                &session,
                409,
                "Conflict",
                "Retention Permission Changed",
                "Review the current permission again. No deletion was attempted.",
                &back,
                events,
            );
        }
        if std::time::Instant::now() >= deadline {
            return unavailable(events);
        }
        for target in &mut targets {
            target.policy_revision = revision;
        }
        if empty_trash {
            let snapshot = trash_snapshot(&targets);
            if !review && form.get("snapshot") != Some(&snapshot) {
                return deletion_notice(&session,409,"Conflict","Trash changed","Your Trash changed after review. Nothing was deleted. Choose Empty trash again to review the current messages.",&back,events);
            }
            if targets.is_empty() {
                return deletion_notice(
                    &session,
                    200,
                    "OK",
                    "Trash is empty",
                    "There are no messages to delete.",
                    &back,
                    events,
                );
            }
            if review {
                drop(guard);
                return HandledHttpResponse { response: html_response(200,"OK","Empty trash?",TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Empty trash?</h1><p>Permanently delete all {} messages in your Trash? This includes messages on other pages and hidden by filters. This cannot be undone.</p><form method=\"post\" action=\"/trash/empty\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"{}\"><input type=\"hidden\" name=\"policy_revision\" value=\"{revision}\"><input type=\"hidden\" name=\"snapshot\" value=\"{snapshot}\"><button name=\"confirm\" value=\"cancel\">Cancel</button><button class=\"danger\" name=\"confirm\" value=\"delete\">Empty trash</button></form></section></main>",crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"bin"),targets.len(),escape_html(&session.record.csrf_token),escape_html(&mailbox),escape_html(&back)))), audit_events: events };
            }
        }
        if review {
            let mut fields = [
                ("csrf_token", session.record.csrf_token.clone()),
                ("mailbox", mailbox),
                ("return_to", back),
                ("policy_revision", revision.to_string()),
            ]
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "<input type=\"hidden\" name=\"{k}\" value=\"{}\">",
                    escape_html(&v)
                )
            })
            .collect::<String>();
            let mut rows = String::new();
            for (target, subject) in targets.iter().zip(subjects) {
                fields.push_str(&format!(
                    "<input type=\"hidden\" name=\"message_{}\" value=\"{}|{}|{}\">",
                    target.uid,
                    target.uid,
                    escape_html(&target.version.mailbox_guid),
                    escape_html(&target.version.message_guid)
                ));
                rows.push_str(&format!(
                    "<li>Message #{}: {}</li>",
                    target.uid,
                    escape_html(subject)
                ));
            }
            drop(guard);
            return HandledHttpResponse{response:html_response(200,"OK","Confirm Permanent Deletion",TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Delete selected messages permanently?</h1><p>{} messages. This cannot be undone.</p><ul>{rows}</ul><form method=\"post\" action=\"/messages/delete\">{fields}<button name=\"confirm\" value=\"cancel\">Cancel</button><button name=\"confirm\" value=\"delete\">Delete permanently</button></form></section></main>",crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"bin"),targets.len()))),audit_events:events};
        }
        let mut results = String::new();
        let mut confirmed = 0;
        let mut uncertain = 0;
        let mut refused = 0;
        let mut status = (200, "OK");
        for target in &targets {
            if std::time::Instant::now() >= deadline {
                status = (503, "Service Unavailable");
                break;
            }
            let outcome = self.gateway.delete_message(context, &session, target);
            events.extend(outcome.audit_events);
            let label = match outcome.result {
                Ok(MessageDeleteResult::Deleted) => {
                    confirmed += 1;
                    "Deleted: absence confirmed"
                }
                Err(E::Unknown) => {
                    uncertain += 1;
                    status = (503, "Service Unavailable");
                    "Unconfirmed: may have completed; do not repeat this request"
                }
                Err(error) => {
                    refused += 1;
                    status = match error {
                        E::Invalid => (400, "Bad Request"),
                        E::Stale => (409, "Conflict"),
                        E::PolicyDenied => (403, "Forbidden"),
                        E::Busy => (429, "Too Many Requests"),
                        _ => (503, "Service Unavailable"),
                    };
                    match error {
                        E::Invalid => "Refused: invalid identity",
                        E::Stale => "Refused: identity or permission changed",
                        E::PolicyDenied => "Refused: retention policy",
                        E::PolicyUnavailable => "Refused: retention unavailable",
                        E::Busy => "Refused: mail action busy",
                        _ => "Refused: helper unavailable before dispatch",
                    }
                }
            };
            results.push_str(&format!("<li>Message #{}: {label}</li>", target.uid));
            if outcome.result.is_err() {
                break;
            }
        }
        let remaining = targets.len() - confirmed - uncertain - refused;
        for target in targets.iter().skip(confirmed + uncertain + refused) {
            results.push_str(&format!("<li>Message #{}: Not attempted</li>", target.uid));
        }
        events.push(self.release_request_budget(guard, "bulk_message_delete", context, &session));
        HandledHttpResponse{response:html_response(status.0,status.1,"Deletion Results",TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>Deletion results</h1><p>{confirmed} confirmed deleted; {refused} refused; {uncertain} unconfirmed; {remaining} not attempted.</p><ul>{results}</ul><p>Refresh the list before choosing another action. Do not repeat completed or unconfirmed requests.</p><a class=\"button-link\" href=\"{}\">Refresh message list</a></section></main>",crate::http_ui::app_header(&session.record.canonical_username,&session.record.csrf_token,"bin"),escape_html(&back)))),audit_events:events}
    }
}
