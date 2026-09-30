use super::*;

impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn welcome_data(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        mailboxes: &[MailboxEntry],
        audit: &mut Vec<LogEvent>,
    ) -> (Option<Vec<MessageSummary>>, Option<usize>, Option<usize>) {
        let mut recent = None;
        let mut sent_count = None;
        for (mailbox, operation) in [("INBOX", "welcome_inbox"), ("Sent", "welcome_sent")] {
            if !mailboxes.iter().any(|entry| entry.name == mailbox) {
                continue;
            }
            match self.acquire_mailbox_budget(context, session, operation) {
                Ok((guard, event)) => {
                    audit.push(event);
                    let result = self.gateway.list_messages(context, session, mailbox);
                    audit.extend(result.audit_events);
                    let rows = verified_summaries(
                        &session.record.canonical_username,
                        mailbox,
                        result.decision,
                    );
                    if mailbox == "INBOX" {
                        recent = rows;
                    } else {
                        sent_count = rows.map(|rows| rows.len());
                    }
                    audit.push(self.release_request_budget(guard, operation, context, session));
                }
                Err(result) => audit.extend(result.audit_events),
            }
        }
        let result = self.gateway.list_drafts(context, session);
        audit.extend(result.audit_events);
        let count = verified_draft_count(&session.record.canonical_username, result.decision);
        (recent, count, sent_count)
    }
}

fn verified_summaries(
    account: &str,
    expected_mailbox: &str,
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
        || mailbox_name != expected_mailbox
        || messages.len() > crate::mailbox::DEFAULT_MAX_MESSAGES
        || messages.iter().any(|row| {
            row.mailbox_name != expected_mailbox
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
