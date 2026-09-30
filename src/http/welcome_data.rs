use super::*;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn welcome_data(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        mailboxes: &[MailboxEntry],
        audit: &mut Vec<LogEvent>,
    ) -> (Option<Vec<MessageSummary>>, Option<usize>) {
        let mut recent = None;
        if mailboxes.iter().any(|entry| entry.name == "INBOX") {
            match self.acquire_mailbox_budget(context, session, "welcome_inbox") {
                Ok((guard, event)) => {
                    audit.push(event);
                    let result = self.gateway.list_messages(context, session, "INBOX");
                    audit.extend(result.audit_events);
                    recent = verified_inbox(&session.record.canonical_username, result.decision);
                    audit.push(self.release_request_budget(
                        guard,
                        "welcome_inbox",
                        context,
                        session,
                    ));
                }
                Err(result) => audit.extend(result.audit_events),
            }
        }
        let result = self.gateway.list_drafts(context, session);
        audit.extend(result.audit_events);
        let count = verified_draft_count(&session.record.canonical_username, result.decision);
        (recent, count)
    }
}

fn verified_inbox(
    account: &str,
    result: BrowserMessageListDecision,
) -> Option<Vec<MessageSummary>> {
    let BrowserMessageListDecision::Listed {
        canonical_username,
        mailbox_name,
        mut messages,
    } = result
    else {
        return None;
    };
    let mut ids = std::collections::BTreeSet::new();
    if canonical_username != account
        || mailbox_name != "INBOX"
        || messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
        || messages.iter().any(|row| {
            row.mailbox_name != "INBOX"
                || row.uid == 0
                || !ids.insert(row.uid)
                || row.metadata.as_ref().is_some_and(|metadata| {
                    crate::message_metadata::MessageVersion::new(
                        metadata.version.mailbox_guid.clone(),
                        metadata.version.message_guid.clone(),
                    )
                    .is_err()
                })
        })
    {
        return None;
    }
    crate::mailbox::sort_message_summaries(
        &mut messages,
        Some(crate::mailbox::MessageSort {
            column: crate::mailbox::MessageSortColumn::Received,
            direction: crate::mailbox::MessageSortDirection::Desc,
        }),
    );
    Some(messages)
}
fn verified_draft_count(account: &str, result: BrowserDraftListDecision) -> Option<usize> {
    let BrowserDraftListDecision::Listed {
        canonical_username,
        drafts,
        ..
    } = result
    else {
        return None;
    };
    let mut ids = std::collections::BTreeSet::new();
    if canonical_username != account
        || drafts.len() > DraftPolicy::default().max_drafts_per_user
        || drafts.iter().any(|row| {
            crate::draft::validate_draft_id(&row.draft_id).is_err()
                || row.revision == 0
                || !ids.insert(&row.draft_id)
        })
    {
        return None;
    }
    Some(drafts.len())
}
