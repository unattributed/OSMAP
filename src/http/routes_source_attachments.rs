//! Original attachment selection bound to one owned stored-message snapshot.
use super::*;
use crate::message_metadata::MessageVersion;

#[derive(Clone, Copy)]
pub(super) enum SourceFailure {
    Invalid,
    Count,
    MissingMailbox,
    Unverified,
    Changed,
    Unavailable,
}

impl SourceFailure {
    pub(super) fn response(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::Invalid => (400, "Bad Request", "source_attachment_invalid"),
            Self::Count => (400, "Bad Request", "source_attachment_count"),
            Self::MissingMailbox => (400, "Bad Request", "source_attachment_missing_mailbox"),
            Self::Unverified => (409, "Conflict", "source_attachment_unverified"),
            Self::Changed => (409, "Conflict", "source_attachment_changed"),
            Self::Unavailable => (503, "Service Unavailable", "source_attachment_unavailable"),
        }
    }
}

pub(super) fn source_version(
    form: &BTreeMap<String, String>,
) -> Result<Option<MessageVersion>, ()> {
    match (
        form.get("source_mailbox_guid"),
        form.get("source_message_guid"),
    ) {
        (None, None) => Ok(None),
        (Some(mailbox), Some(message)) => MessageVersion::new(mailbox.clone(), message.clone())
            .map(Some)
            .map_err(|_| ()),
        _ => Err(()),
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn resolve_source_attachments(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        form: &BTreeMap<String, String>,
        parts: &[String],
        audit: &mut Vec<LogEvent>,
        route: &'static str,
    ) -> Result<Option<(DraftSourceAttachments, Vec<UploadedAttachment>)>, SourceFailure> {
        if parts.is_empty() {
            return Ok(None);
        }
        if parts.len() > ComposePolicy::default().max_attachments {
            return Err(SourceFailure::Count);
        }
        let mailbox = form
            .get("source_mailbox")
            .filter(|mailbox| !mailbox.is_empty())
            .ok_or(SourceFailure::MissingMailbox)?;
        let uid_text = form.get("source_uid").ok_or(SourceFailure::Invalid)?;
        let uid = uid_text
            .parse::<u32>()
            .map_err(|_| SourceFailure::Invalid)?;
        if uid == 0 || uid.to_string() != *uid_text {
            return Err(SourceFailure::Invalid);
        }
        let request =
            MessageViewRequest::new(MessageViewPolicy::default(), mailbox, u64::from(uid))
                .map_err(|_| SourceFailure::Invalid)?;
        let version = source_version(form)
            .map_err(|_| SourceFailure::Invalid)?
            .ok_or(SourceFailure::Unverified)?;
        let (guard, event) = self
            .acquire_mailbox_budget(context, session, route)
            .map_err(|response| {
                audit.extend(response.audit_events);
                SourceFailure::Unavailable
            })?;
        audit.push(event);
        let outcome = self.gateway.read_message_source(context, session, &request);
        audit.push(outcome.audit_event);
        let result = (|| {
            let message = match outcome.decision {
                MessageViewDecision::Retrieved {
                    canonical_username,
                    session_id,
                    message,
                } if canonical_username == session.record.canonical_username
                    && session_id == session.record.session_id
                    && message.mailbox_name == *mailbox
                    && message.uid == u64::from(uid)
                    && message
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| metadata.version == version)
                    && message.header_block.len()
                        <= MessageViewPolicy::default().message_header_max_len
                    && message.body_text.len()
                        <= MessageViewPolicy::default().message_body_max_len =>
                {
                    message
                }
                MessageViewDecision::Retrieved { .. } => return Err(SourceFailure::Changed),
                MessageViewDecision::Denied { .. } => return Err(SourceFailure::Unavailable),
            };
            let mut attachments = Vec::new();
            for part in parts {
                let outcome = self
                    .gateway
                    .download_stored_attachment(context, session, &message, part);
                audit.extend(outcome.audit_events);
                let attachment = match outcome.decision {
                    BrowserAttachmentDownloadDecision::Downloaded {
                        canonical_username,
                        attachment,
                    } if canonical_username == session.record.canonical_username
                        && attachment.mailbox_name == message.mailbox_name
                        && attachment.uid == message.uid
                        && attachment.part_path == *part =>
                    {
                        attachment
                    }
                    BrowserAttachmentDownloadDecision::Downloaded { .. } => {
                        return Err(SourceFailure::Changed)
                    }
                    BrowserAttachmentDownloadDecision::Denied { public_reason }
                        if public_reason == "not_found" =>
                    {
                        return Err(SourceFailure::Changed)
                    }
                    BrowserAttachmentDownloadDecision::Denied { .. } => {
                        return Err(SourceFailure::Unavailable)
                    }
                };
                attachments.push(
                    UploadedAttachment::new(
                        ComposePolicy::default(),
                        attachment.filename,
                        attachment.content_type,
                        attachment.body,
                    )
                    .map_err(|_| SourceFailure::Invalid)?,
                );
            }
            crate::send::validate_attachment_set(ComposePolicy::default(), &attachments)
                .map_err(|_| SourceFailure::Invalid)?;
            Ok(Some((
                DraftSourceAttachments {
                    mailbox_name: mailbox.clone(),
                    uid: u64::from(uid),
                    version: Some(version),
                    part_paths: parts.to_vec(),
                },
                attachments,
            )))
        })();
        audit.push(self.release_request_budget(guard, route, context, session));
        result
    }
}
