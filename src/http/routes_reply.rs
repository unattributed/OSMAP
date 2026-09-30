//! Sender and original-message authority for compose metadata.
use super::*;
use crate::message_metadata::MessageVersion;
use crate::reply_thread::{ReplyReference, ReplyThread};

pub(super) fn compose_metadata_valid(form: &BTreeMap<String, String>, username: &str) -> bool {
    if super::routes_draft::removed_attachment_indices(form).is_err()
        || super::compose_actions::body_format(form).is_none()
        || form.get("compose_action").is_some_and(|action| {
            action.starts_with("theme-") && !matches!(action.as_str(), "theme-light" | "theme-dark")
        })
    {
        return false;
    }
    let allowed = [
        "csrf_token",
        "send_intent",
        "from",
        "to",
        "cc",
        "bcc",
        "subject",
        "body",
        "body_format",
        "format_start",
        "format_end",
        "format_url",
        "format_label",
        "draft_id",
        "draft_revision",
        "source_mailbox",
        "source_uid",
        "source_mailbox_guid",
        "source_message_guid",
        "reply_mailbox",
        "reply_uid",
        "reply_mailbox_guid",
        "reply_message_guid",
        "contact_id",
        "contact_revision",
        "contact_target",
        "compose_action",
    ];
    form.iter().all(|(name, value)| {
        (allowed.contains(&name.as_str())
            || name.starts_with("remove_saved_attachment_")
            || name
                .strip_prefix("include_original_attachment_")
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                }))
            && (name != "from" || value == username)
    })
}

pub(super) fn query_version(
    fields: &BTreeMap<String, String>,
) -> Result<Option<MessageVersion>, &'static str> {
    match (fields.get("mailbox_guid"), fields.get("message_guid")) {
        (None, None) => Ok(None),
        (Some(mailbox), Some(message)) => MessageVersion::new(mailbox.clone(), message.clone())
            .map(Some)
            .map_err(|_| "compose stored identity was invalid"),
        _ => Err("compose stored identity was incomplete"),
    }
}

pub(super) fn reply_reference(
    form: &BTreeMap<String, String>,
) -> Result<Option<ReplyReference>, &'static str> {
    let names = [
        "reply_mailbox",
        "reply_uid",
        "reply_mailbox_guid",
        "reply_message_guid",
    ];
    if names.iter().all(|name| !form.contains_key(*name)) {
        return Ok(None);
    }
    if form.get("draft_id").is_some_and(|value| !value.is_empty()) {
        return Err("a saved draft keeps its original reply context");
    }
    let mailbox = form.get(names[0]).ok_or("missing reply mailbox")?;
    let uid_text = form.get(names[1]).ok_or("missing reply UID")?;
    let uid = uid_text.parse::<u32>().map_err(|_| "invalid reply UID")?;
    if uid == 0 || uid.to_string() != *uid_text {
        return Err("noncanonical reply UID");
    }
    let mailbox_guid = form.get(names[2]).ok_or("missing reply mailbox identity")?;
    let message_guid = form.get(names[3]).ok_or("missing reply message identity")?;
    let version = MessageVersion::new(mailbox_guid.clone(), message_guid.clone())
        .map_err(|_| "invalid reply stored identity")?;
    ReplyReference::new(mailbox.clone(), u64::from(uid), version).map(Some)
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn resolve_reply_thread(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        reference: &ReplyReference,
        audit: &mut Vec<LogEvent>,
    ) -> Result<Option<ReplyThread>, HttpResponse> {
        let request = MessageViewRequest::new(
            MessageViewPolicy::default(),
            &reference.mailbox_name,
            reference.uid,
        )
        .map_err(|_| {
            html_response(
                400,
                "Bad Request",
                "Invalid Reply",
                "<p>Open a fresh reply from the reader.</p>",
            )
        })?;
        let (guard, event) = self
            .acquire_mailbox_budget(context, session, "reply_source")
            .map_err(|response| {
                audit.extend(response.audit_events);
                response.response
            })?;
        audit.push(event);
        let outcome = self.gateway.read_message_source(context, session, &request);
        audit.push(outcome.audit_event);
        audit.push(self.release_request_budget(guard, "reply_source", context, session));
        match outcome.decision {
            MessageViewDecision::Retrieved { canonical_username, session_id, message }
                if canonical_username == session.record.canonical_username && session_id == session.record.session_id
                    && message.mailbox_name == reference.mailbox_name && message.uid == reference.uid
                    && message.metadata.as_ref().is_some_and(|metadata| metadata.version == reference.version)
                    && message.header_block.len() <= MessageViewPolicy::default().message_header_max_len => {
                Ok(ReplyThread::from_original(&message.header_block).ok())
            }
            MessageViewDecision::Retrieved { .. } => Err(html_response(409, "Conflict", "Reply Source Changed", "<p>The original message changed. Open a fresh reply from the reader. Nothing was submitted or saved.</p>")),
            MessageViewDecision::Denied { .. } => Err(html_response(503, "Service Unavailable", "Reply Source Unavailable", "<p>The original message could not be revalidated. Nothing was submitted or saved.</p>")),
        }
    }
}
