//! Review then atomically change one label on a bounded, freshly verified selection.
use super::*;
use crate::label_selection_ui::{
    render_label_selection_page, LabelSelectionItem, LabelSelectionPageModel,
};
use crate::labels::{LabelChange, LabelError, MessageIdentity};
use crate::mail_list::MAX_BULK_SELECTION;
fn canonical_number(value: Option<&String>) -> Result<u64, LabelError> {
    let v = value.ok_or(LabelError::Invalid)?;
    v.parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == *v)
        .ok_or(LabelError::Invalid)
}
fn selected_versions(
    selected: &[LabelSelectionItem],
) -> Result<Vec<(u64, crate::message_metadata::MessageVersion)>, LabelError> {
    if selected.is_empty() || selected.len() > MAX_BULK_SELECTION {
        return Err(LabelError::Invalid);
    }
    let mut uids = std::collections::BTreeSet::new();
    let mut guids = std::collections::BTreeSet::new();
    let mut generation = None;
    let mut out = Vec::new();
    for item in selected {
        let mut parts = item.value.splitn(3, '|');
        let raw_uid = parts.next().ok_or(LabelError::Invalid)?;
        let uid = raw_uid
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0 && n.to_string() == raw_uid)
            .ok_or(LabelError::Invalid)?;
        let mailbox_guid = parts.next().ok_or(LabelError::Invalid)?;
        let v = crate::message_metadata::MessageVersion::new(
            mailbox_guid.into(),
            parts.next().ok_or(LabelError::Invalid)?.into(),
        )
        .map_err(|_| LabelError::Invalid)?;
        if item.field != format!("message_{uid}")
            || v.mailbox_guid != mailbox_guid
            || !uids.insert(uid)
            || !guids.insert(v.message_guid.clone())
            || generation.as_ref().is_some_and(|g| g != &v.mailbox_guid)
        {
            return Err(LabelError::Invalid);
        }
        generation = Some(v.mailbox_guid.clone());
        out.push((u64::from(uid), v));
    }
    Ok(out)
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn handle_label_selection(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        apply: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit_events) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let form = if allows_urlencoded_request_body(
            request.headers.get("content-type").map(String::as_str),
        ) {
            parse_urlencoded_form(&request.body, MAX_BULK_SELECTION + 7, 16384).ok()
        } else {
            None
        };
        let Some(form) = form else {
            return HandledHttpResponse {
                response: html_response(
                    400,
                    "Bad Request",
                    "Invalid label selection",
                    render_navigation_notice(
                        &session.record.canonical_username,
                        &session.record.csrf_token,
                        "Invalid label selection",
                        "Select up to ten current messages and review again.",
                    ),
                ),
                audit_events,
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
        let mut selected = form
            .iter()
            .filter(|(k, _)| k.starts_with("message_"))
            .map(|(field, value)| LabelSelectionItem {
                field: field.clone(),
                value: value.clone(),
                subject: None,
            })
            .collect::<Vec<_>>();
        let mailbox = form.get("mailbox").map(String::as_str).unwrap_or("");
        let return_to = form
            .get("return_to")
            .and_then(|v| crate::mail_navigation::safe_mail_return(v))
            .unwrap_or_default();
        let record = self.gateway.load_labels(&session);
        let revision = if apply {
            canonical_number(form.get("revision")).unwrap_or(0)
        } else {
            record.as_ref().map_or(0, |r| r.revision())
        };
        let label_id = form.get("label_id").map(String::as_str).unwrap_or("");
        let action = form.get("action").map(String::as_str).unwrap_or("");
        let result = (|| {
            let allowed = if apply {
                &[
                    "csrf_token",
                    "mailbox",
                    "return_to",
                    "revision",
                    "label_id",
                    "action",
                    "confirm",
                ][..]
            } else {
                &[
                    "csrf_token",
                    "mailbox",
                    "return_to",
                    "destination_mailbox",
                    "action",
                ][..]
            };
            if form
                .keys()
                .any(|k| !allowed.contains(&k.as_str()) && !k.starts_with("message_"))
                || form.contains_key("return_to") && return_to.is_empty()
            {
                return Err(LabelError::Invalid);
            }
            MailboxEntry::new(MailboxListingPolicy::default(), mailbox)
                .map_err(|_| LabelError::Invalid)?;
            if apply {
                canonical_number(form.get("revision"))?;
                if !matches!(action, "attach" | "detach")
                    || form.get("confirm").map(String::as_str) != Some("apply")
                {
                    return Err(LabelError::Invalid);
                }
            } else {
                if !matches!(action, "" | "review") {
                    return Err(LabelError::Invalid);
                }
                // The existing shared selection form also submits its move chooser. It grants no label/move authority.
                if let Some(destination) = form.get("destination_mailbox") {
                    MailboxEntry::new(MailboxListingPolicy::default(), destination)
                        .map_err(|_| LabelError::Invalid)?;
                }
            }
            let versions = selected_versions(&selected)?;
            let (guard, event) = self
                .acquire_mailbox_budget(context, &session, "label_selection")
                .map_err(|_| LabelError::Unavailable)?;
            audit_events.push(event);
            let rows = self.label_rows(context, &session, mailbox, &mut audit_events);
            audit_events.push(self.release_request_budget(
                guard,
                "label_selection",
                context,
                &session,
            ));
            let rows = rows?;
            let mut identities: Vec<MessageIdentity> = Vec::with_capacity(versions.len());
            for (item, (uid, version)) in selected.iter_mut().zip(versions) {
                let (identity, row) = rows
                    .iter()
                    .find(|(_, row)| {
                        row.uid == uid
                            && row.metadata.as_ref().is_some_and(|m| m.version == version)
                    })
                    .ok_or(LabelError::Stale)?;
                item.subject = row.subject.clone();
                identities.push(identity.clone());
            }
            record.as_ref().map_err(|e| *e)?;
            if apply {
                self.gateway.change_labels(
                    &session,
                    revision,
                    LabelChange::Selection {
                        id: label_id,
                        messages: &identities,
                        attach: action == "attach",
                    },
                )?;
            }
            Ok(())
        })();
        let(status,reason,notice)=match result{
            Ok(()) if apply=>(200,"OK",Some("The selected label change was saved for every reviewed message. No mail was moved or changed.")),
            Ok(())=>(200,"OK",None),
            Err(LabelError::Stale)=>(409,"Conflict",Some("The messages or labels changed. Nothing from this selection was saved. Review the selection again before applying.")),
            Err(LabelError::Capacity)=>(409,"Conflict",Some("The selection would exceed a label limit. None of its label assignments were saved.")),
            Err(LabelError::Invalid|LabelError::Missing)=>(400,"Bad Request",Some("This selection or label is not valid for the account. No label assignments were saved. Return to the list and review current messages.")),
            Err(LabelError::Unconfirmed)=>(503,"Service Unavailable",Some("The label update could not be confirmed. Do not resubmit automatically; review the saved labels first.")),
            Err(_)=>(503,"Service Unavailable",Some("Labels or current message identities could not be verified. No label update was attempted. Review again when available.")),
        };
        if apply {
            audit_events.push(
                build_http_info_event(
                    if result.is_ok() {
                        "label_selection_changed"
                    } else {
                        "label_selection_refused"
                    },
                    "bounded atomic label selection evaluated",
                    context,
                )
                .with_field("selected_count", selected.len().to_string()),
            );
        }
        HandledHttpResponse {
            response: html_response(
                status,
                reason,
                "Labels for selected messages",
                render_label_selection_page(&LabelSelectionPageModel {
                    account: &session.record.canonical_username,
                    csrf: &session.record.csrf_token,
                    mailbox,
                    selected: &selected,
                    record: record.as_ref().ok(),
                    revision,
                    label_id,
                    action,
                    return_to: &return_to,
                    notice,
                    editable: result.is_ok() && !apply,
                }),
            ),
            audit_events,
        }
    }
}
