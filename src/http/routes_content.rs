//! Authenticated stored-source and identity-bound attachment reads.
use super::*;
use crate::attachment::AttachmentDownloadRequest;
use crate::message_metadata::MessageVersion;

struct ContentRequest {
    message: MessageViewRequest,
    version: Option<MessageVersion>,
    part: Option<String>,
    return_to: String,
}

impl ContentRequest {
    fn parse(request: &HttpRequest, attachment: bool) -> Option<Self> {
        let fields = &request.query_params;
        let allowed = [
            "mailbox",
            "uid",
            "mailbox_guid",
            "message_guid",
            "return_to",
            if attachment { "part" } else { "view" },
        ];
        if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
            return None;
        }
        if !attachment && fields.get("view").map(String::as_str) != Some("source") {
            return None;
        }
        let uid_text = fields.get("uid")?;
        let uid = uid_text.parse::<u32>().ok()?;
        if uid == 0 || uid.to_string() != *uid_text {
            return None;
        }
        let message = MessageViewRequest::new(
            MessageViewPolicy::default(),
            fields.get("mailbox")?,
            u64::from(uid),
        )
        .ok()?;
        let version = match (fields.get("mailbox_guid"), fields.get("message_guid")) {
            (Some(mailbox), Some(message)) => {
                Some(MessageVersion::new(mailbox.clone(), message.clone()).ok()?)
            }
            (None, None) if !attachment => None,
            _ => return None,
        };
        let part = if attachment {
            Some(
                AttachmentDownloadRequest::new(
                    AttachmentDownloadPolicy::default(),
                    fields.get("part")?,
                )
                .ok()?
                .part_path,
            )
        } else {
            None
        };
        let return_to = match fields.get("return_to") {
            Some(value) => crate::mail_navigation::safe_mail_return(value)?,
            None => format!(
                "/message?mailbox={}&uid={}",
                url_encode(&message.mailbox_name),
                uid
            ),
        };
        Some(Self {
            message,
            version,
            part,
            return_to,
        })
    }
}

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_stored_content(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        attachment: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let Some(content) = ContentRequest::parse(request, attachment) else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid Content Request",
                    crate::http_ui::render_content_notice(
                        &session.record.canonical_username,
                        &session.record.csrf_token,
                        "Invalid content request",
                        "Open the message again to obtain a current source or download link.",
                        "/mailboxes",
                        None,
                    ),
                ),
                audit_events,
            };
        };
        let route = if attachment {
            "attachment_download"
        } else {
            "message_source"
        };
        let (guard, event) = match self.acquire_mailbox_budget(context, &session, route) {
            Ok(value) => value,
            Err(mut response) => {
                audit_events.extend(response.audit_events);
                response.audit_events = audit_events;
                return response;
            }
        };
        audit_events.push(event);
        let outcome = self
            .gateway
            .read_message_source(context, &session, &content.message);
        audit_events.push(outcome.audit_event);
        let policy = MessageViewPolicy::default();
        let response = match outcome.decision {
            MessageViewDecision::Retrieved {
                canonical_username,
                session_id,
                message,
            } if canonical_username == session.record.canonical_username
                && session_id == session.record.session_id
                && message.mailbox_name == content.message.mailbox_name
                && message.uid == content.message.uid
                && message.header_block.len() <= policy.message_header_max_len
                && message.body_text.len() <= policy.message_body_max_len =>
            {
                if content.version.as_ref().is_some_and(|expected| {
                    message
                        .metadata
                        .as_ref()
                        .is_none_or(|metadata| &metadata.version != expected)
                }) {
                    Err((409, "Conflict", "Message changed", "The stored message identity changed. Return to the reader and open a fresh link.", false))
                } else if let Some(part) = &content.part {
                    // Extract from this single checked snapshot. No second fetch between
                    // identity verification and decoding; same bounded MIME service as before.
                    let result =
                        AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
                            .download_for_validated_session(context, &session, &message, part);
                    audit_events.push(result.audit_event);
                    match result.decision {
                        AttachmentDownloadDecision::Downloaded { attachment, .. } => {
                            Ok(attachment_download_response(&attachment))
                        }
                        AttachmentDownloadDecision::Denied { public_reason } => {
                            Err(match public_reason {
                                AttachmentDownloadPublicFailureReason::NotFound => (404, "Not Found", "Attachment not found", "This attachment is no longer available. Return to the reader to refresh its attachment list.", false),
                                AttachmentDownloadPublicFailureReason::InvalidRequest => (400, "Bad Request", "Invalid attachment", "Open a download link from the message attachment list.", false),
                                _ => (503, "Service Unavailable", "Attachment unavailable", "The attachment could not be decoded within the supported size and format limits. You can safely retry this read or return to the message.", true),
                            })
                        }
                    }
                } else {
                    Ok(html_response(
                        200,
                        "OK",
                        "Message Source",
                        crate::http_ui::render_message_source_page(
                            &session.record.canonical_username,
                            &session.record.csrf_token,
                            &message,
                            &content.return_to,
                        ),
                    ))
                }
            }
            MessageViewDecision::Retrieved { .. } => {
                Err((503, "Service Unavailable", "Content unavailable", "The message could not be safely matched to this request within the supported limits. Return to the reader.", false))
            }
            MessageViewDecision::Denied { public_reason } => {
                Err(match public_reason {
                    crate::mailbox::MailboxPublicFailureReason::NotFound => (404, "Not Found", "Message not found", "This message is no longer available at this location. Return to the reader or mailbox.", false),
                    _ => (503, "Service Unavailable", "Content temporarily unavailable", "The message could not be loaded. You can safely retry this read or return to the reader.", true),
                })
            }
        };
        let response =
            response.unwrap_or_else(|(status, reason, title, description, retryable)| {
                audit_events.push(
                    build_http_warning_event(
                        "stored_content_refused",
                        "stored content was not returned",
                        context,
                    )
                    .with_field("route_class", route)
                    .with_field("status", status.to_string()),
                );
                let retry = retryable.then(|| content_url(&content, attachment));
                html_response(
                    status,
                    reason,
                    title,
                    crate::http_ui::render_content_notice(
                        &session.record.canonical_username,
                        &session.record.csrf_token,
                        title,
                        description,
                        &content.return_to,
                        retry.as_deref(),
                    ),
                )
            });
        audit_events.push(self.release_request_budget(guard, route, context, &session));
        HandledHttpResponse {
            response,
            audit_events,
        }
    }
}

fn content_url(content: &ContentRequest, attachment: bool) -> String {
    let mut url = format!(
        "{}?mailbox={}&uid={}&return_to={}",
        if attachment {
            "/attachment"
        } else {
            "/message"
        },
        url_encode(&content.message.mailbox_name),
        content.message.uid,
        url_encode(&content.return_to)
    );
    if let Some(version) = &content.version {
        url.push_str(&format!(
            "&mailbox_guid={}&message_guid={}",
            url_encode(&version.mailbox_guid),
            url_encode(&version.message_guid)
        ));
    }
    if let Some(part) = &content.part {
        url.push_str(&format!("&part={}", url_encode(part)));
    } else {
        url.push_str("&view=source");
    }
    url
}
