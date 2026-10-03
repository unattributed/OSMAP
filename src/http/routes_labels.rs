use super::*;
use crate::labels::{LabelChange, LabelError, MessageIdentity};
use crate::labels_ui::{LabelMessageContext, LabelPageModel};
fn number(value: Option<&String>) -> Result<u64, LabelError> {
    let s = value.ok_or(LabelError::Invalid)?;
    s.parse::<u64>()
        .ok()
        .filter(|v| v.to_string() == *s)
        .ok_or(LabelError::Invalid)
}
fn context_fields(
    form: &BTreeMap<String, String>,
) -> Result<Option<LabelMessageContext>, LabelError> {
    let names = ["mailbox", "uid", "mailbox_guid", "message_guid"];
    if !names.iter().any(|n| form.contains_key(*n)) {
        return Ok(None);
    }
    if !names.iter().all(|n| form.contains_key(*n)) {
        return Err(LabelError::Invalid);
    }
    MailboxEntry::new(MailboxListingPolicy::default(), form["mailbox"].clone())
        .map_err(|_| LabelError::Invalid)?;
    let uid = number(form.get("uid"))?;
    if uid == 0 || uid > u32::MAX as u64 {
        return Err(LabelError::Invalid);
    }
    let v = crate::message_metadata::MessageVersion::new(
        form["mailbox_guid"].clone(),
        form["message_guid"].clone(),
    )
    .map_err(|_| LabelError::Invalid)?;
    Ok(Some(LabelMessageContext {
        mailbox: form["mailbox"].clone(),
        uid,
        mailbox_guid: v.mailbox_guid,
        message_guid: v.message_guid,
        attached_label_ids: vec![],
    }))
}
fn owned_rows(
    account: &str,
    folder: &str,
    decision: BrowserMessageListDecision,
) -> Result<Vec<(MessageIdentity, MessageSummary)>, LabelError> {
    let BrowserMessageListDecision::Listed {
        canonical_username,
        mailbox_name,
        messages,
    } = decision
    else {
        return Err(LabelError::Unavailable);
    };
    if canonical_username != account
        || mailbox_name != folder
        || messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
    {
        return Err(LabelError::Invalid);
    }
    let mut uids = std::collections::BTreeSet::new();
    let mut guids = std::collections::BTreeSet::new();
    let mut generation = None;
    let mut out = Vec::new();
    for row in messages {
        let identity = MessageIdentity::from_summary(account, &canonical_username, folder, &row)?;
        let metadata = row.metadata.as_ref().ok_or(LabelError::Invalid)?;
        if !uids.insert(row.uid)
            || !guids.insert(metadata.version.message_guid.clone())
            || generation
                .as_ref()
                .is_some_and(|g| g != &metadata.version.mailbox_guid)
        {
            return Err(LabelError::Invalid);
        }
        generation = Some(metadata.version.mailbox_guid.clone());
        out.push((identity, row));
    }
    Ok(out)
}
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn label_rows(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        folder: &str,
        audit: &mut Vec<LogEvent>,
    ) -> Result<Vec<(MessageIdentity, MessageSummary)>, LabelError> {
        let outcome = self.gateway.list_messages(context, session, folder);
        audit.extend(outcome.audit_events);
        owned_rows(&session.record.canonical_username, folder, outcome.decision)
    }
    fn label_identity(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        c: &LabelMessageContext,
        audit: &mut Vec<LogEvent>,
    ) -> Result<MessageIdentity, LabelError> {
        self.label_rows(context, session, &c.mailbox, audit)?
            .into_iter()
            .find(|(_, r)| {
                r.uid == c.uid
                    && r.metadata.as_ref().is_some_and(|m| {
                        m.version.mailbox_guid == c.mailbox_guid
                            && m.version.message_guid == c.message_guid
                    })
            })
            .map(|(id, _)| id)
            .ok_or(LabelError::Stale)
    }
    pub(super) fn handle_labels(
        &self,
        request: &HttpRequest,
        context: &AuthenticationContext,
        post: bool,
    ) -> HandledHttpResponse {
        let (session, mut audit) = match self.require_validated_session(request, context) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let form = if post {
            if !allows_urlencoded_request_body(
                request.headers.get("content-type").map(String::as_str),
            ) {
                return label_bad(audit);
            }
            match parse_urlencoded_form(&request.body, 10, 8192) {
                Ok(v) => v,
                Err(_) => return label_bad(audit),
            }
        } else {
            request.query_params.clone()
        };
        if post {
            if let Some(r) = self.require_valid_csrf(
                request,
                form.get("csrf_token").map(String::as_str),
                &session,
                context,
            ) {
                return r;
            }
        }
        let allowed = if post {
            &[
                "csrf_token",
                "revision",
                "action",
                "label_id",
                "name",
                "confirm",
                "mailbox",
                "uid",
                "mailbox_guid",
                "message_guid",
            ][..]
        } else {
            &["mailbox", "uid", "mailbox_guid", "message_guid"][..]
        };
        if form.keys().any(|k| !allowed.contains(&k.as_str())) {
            return label_bad(audit);
        }
        let mut message = match context_fields(&form) {
            Ok(v) => v,
            Err(_) => return label_bad(audit),
        };
        let mut identity = None;
        let mut failure = None;
        if let Some(c) = &message {
            let (guard, event) =
                match self.acquire_mailbox_budget(context, &session, "labels_summary") {
                    Ok(v) => v,
                    Err(r) => return r,
                };
            audit.push(event);
            match self.label_identity(context, &session, c, &mut audit) {
                Ok(v) => identity = Some(v),
                Err(e) => failure = Some(e),
            }
            audit.push(self.release_request_budget(guard, "labels_summary", context, &session));
        }
        if post && failure.is_none() {
            let id = form.get("label_id").map(String::as_str).unwrap_or("");
            let name = form.get("name").map(String::as_str).unwrap_or("");
            let action = form.get("action").map(String::as_str).unwrap_or("");
            let result = (|| {
                let revision = number(form.get("revision"))?;
                if (form.contains_key("name") && !matches!(action, "create" | "rename"))
                    || (form.contains_key("confirm") && action != "delete")
                {
                    return Err(LabelError::Invalid);
                }
                let change = match action {
                    "create" if id.is_empty() => LabelChange::Create(name),
                    "rename" => LabelChange::Rename { id, name },
                    "delete" if form.get("confirm").map(String::as_str) == Some("delete") => {
                        LabelChange::Delete(id)
                    }
                    "attach" => LabelChange::Attach {
                        id,
                        message: identity.as_ref().ok_or(LabelError::Invalid)?,
                    },
                    "detach" => LabelChange::Detach {
                        id,
                        message: identity.as_ref().ok_or(LabelError::Invalid)?,
                    },
                    _ => return Err(LabelError::Invalid),
                };
                self.gateway.change_labels(&session, revision, change)
            })();
            failure = result.err();
            audit.push(
                build_http_info_event(
                    if failure.is_none() {
                        "labels_changed"
                    } else {
                        "labels_change_refused"
                    },
                    "account label change evaluated",
                    context,
                )
                .with_field(
                    "session_ref",
                    crate::logging::audit_session_ref(&session.record.session_id),
                ),
            );
        }
        let record = self.gateway.load_labels(&session);
        if failure.is_none() {
            failure = record.as_ref().err().copied()
        }
        if let (Ok(record), Some(c), Some(identity)) = (&record, &mut message, &identity) {
            c.attached_label_ids = record
                .labels_for(identity)
                .unwrap_or_default()
                .iter()
                .map(|l| l.id().to_owned())
                .collect()
        }
        let(status,reason,notice)=match failure{None=>(200,"OK",if post{Some("Label change saved.")}else{None}),Some(LabelError::Invalid|LabelError::Missing)=>(400,"Bad Request",Some("Label request was invalid. No label change was saved.")),Some(LabelError::Stale)=>(409,"Conflict",Some("The label revision or message identity changed. Reload and reconcile before another change.")),Some(LabelError::Capacity)=>(409,"Conflict",Some("The label or assignment limit was reached. Existing labels were retained.")),_=>(503,"Service Unavailable",Some("Label storage or message identity could not be confirmed. A write may have completed; reload before another change."))};
        HandledHttpResponse {
            response: html_response(
                status,
                reason,
                "Labels",
                crate::labels_ui::render_labels_page(&LabelPageModel {
                    account: &session.record.canonical_username,
                    csrf: &session.record.csrf_token,
                    record: record.as_ref().ok(),
                    message: message.as_ref(),
                    submitted_label_id: form.get("label_id").map(String::as_str).unwrap_or(""),
                    submitted_action: form.get("action").map(String::as_str).unwrap_or(""),
                    entered_name: form.get("name").map(String::as_str).unwrap_or(""),
                    notice,
                    editable: failure.is_none(),
                }),
            ),
            audit_events: audit,
        }
    }
    pub(super) fn labels_before_move(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        m: &MessageMoveRequest,
        audit: &mut Vec<LogEvent>,
    ) -> Result<Option<(u64, MessageIdentity)>, LabelError> {
        let record = self.gateway.load_labels(session)?;
        if record.assigned_messages() == 0 {
            return Ok(None);
        }
        let c = LabelMessageContext {
            mailbox: m.source_mailbox_name.clone(),
            uid: m.uid,
            mailbox_guid: m.version.mailbox_guid.clone(),
            message_guid: m.version.message_guid.clone(),
            attached_label_ids: vec![],
        };
        let source = self.label_identity(context, session, &c, audit)?;
        if record.labels_for(&source)?.is_empty() {
            Ok(None)
        } else {
            Ok(Some((record.revision(), source)))
        }
    }
    pub(super) fn labels_after_move(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        m: &MessageMoveRequest,
        pending: Result<Option<(u64, MessageIdentity)>, LabelError>,
        deadline: std::time::Instant,
        audit: &mut Vec<LogEvent>,
    ) -> bool {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        let (revision, source) = match pending {
            Ok(None) => return true,
            Ok(Some(v)) => v,
            Err(_) => return false,
        };
        let Ok(rows) = self.label_rows(context, session, &m.destination_mailbox_name, audit) else {
            return false;
        };
        let mut matches = rows.into_iter().filter(|(_, row)| {
            row.metadata
                .as_ref()
                .is_some_and(|v| v.version.message_guid == m.version.message_guid)
        });
        let Some((destination, _)) = matches.next() else {
            return false;
        };
        if matches.next().is_some() {
            return false;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        self.gateway
            .reconcile_labels(session, revision, &source, &destination)
            .is_ok()
    }
}
fn label_bad(audit: Vec<LogEvent>) -> HandledHttpResponse {
    HandledHttpResponse {
        response: html_response(
            400,
            "Bad Request",
            "Invalid Labels Request",
            "<p>The label request could not be read. Reload Labels before editing.</p>",
        ),
        audit_events: audit,
    }
}
#[cfg(test)]
mod validation_tests {
    use super::*;
    #[test]
    fn labels_entire_summary_set_must_be_unambiguous() {
        let row = MessageSummary {
            mailbox_name: "INBOX".into(),
            uid: 1,
            flags: vec![],
            date_received: String::new(),
            size_virtual: 0,
            subject: None,
            from: None,
            to: None,
            metadata: Some(crate::message_metadata::MessageMetadata {
                attachments: None,
                protection: crate::message_metadata::MessageProtection::Unknown,
                version: crate::message_metadata::MessageVersion::new("a".repeat(32), "one".into())
                    .unwrap(),
                attachment_count: None,
                preview: None,
            }),
        };
        for fault in 0..7 {
            let mut rows = vec![row.clone()];
            let mut account = "alice@example.com";
            let mut folder = "INBOX";
            match fault {
                0 => account = "bob@example.com",
                1 => folder = "Sent",
                2 => rows.push(row.clone()),
                3 => {
                    let mut second = row.clone();
                    second.uid = 2;
                    rows.push(second)
                }
                4 => rows[0].metadata = None,
                5 => rows.resize(crate::mailbox::DEFAULT_MAX_MESSAGES + 1, row.clone()),
                _ => rows[0].metadata.as_mut().unwrap().version.mailbox_guid = "invalid".into(),
            };
            assert!(owned_rows(
                "alice@example.com",
                "INBOX",
                BrowserMessageListDecision::Listed {
                    canonical_username: account.into(),
                    mailbox_name: folder.into(),
                    messages: rows
                }
            )
            .is_err());
        }
    }
}
