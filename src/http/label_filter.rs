//! Resolve one private label against fresh current tuples before list pagination.
use super::*;
impl<G: BrowserGateway> BrowserApp<G> {
    pub(super) fn owned_label_record(
        &self,
        session: &ValidatedSession,
    ) -> Option<crate::labels::LabelRecord> {
        let account = &session.record.canonical_username;
        self.gateway
            .load_labels(session)
            .ok()
            .filter(|record| record.owned_labels(account).is_ok())
    }
    pub(super) fn filter_labeled_messages(
        &self,
        session: &ValidatedSession,
        view: &mut crate::mail_list::ListViewState,
        returned_account: &str,
        folder: &str,
        rows: &mut Vec<MessageSummary>,
    ) -> Result<Option<crate::labels::LabelRecord>, &'static str> {
        let account = &session.record.canonical_username;
        if returned_account != account {
            return Err("The current mailbox owner could not be confirmed. No unfiltered results are displayed.");
        }
        let Some(record) = self.owned_label_record(session) else {
            return if view.label.is_some() {
                Err("The private label record is unavailable. Clear the label filter or reload; no unfiltered results are displayed.")
            } else {
                Ok(None)
            };
        };
        view.label_choices = record
            .labels()
            .iter()
            .map(|label| (label.id().into(), label.name().into()))
            .collect();
        let Some(id) = &view.label else {
            return Ok(Some(record));
        };
        if !record.labels().iter().any(|label| label.id() == id) {
            return Err("The selected label is no longer available in this account. Return to Labels or clear the filter.");
        }
        view.label_backend_truncated = rows.len() > crate::mailbox::DEFAULT_MAX_MESSAGES;
        rows.truncate(crate::mailbox::DEFAULT_MAX_MESSAGES);
        let mut identities = std::collections::BTreeSet::new();
        let mut versions = std::collections::BTreeSet::new();
        let mut mailbox_guid = None;
        let mut keep = Vec::with_capacity(rows.len());
        for row in rows.iter() {
            let identity = crate::labels::MessageIdentity::from_summary(account, returned_account, folder, row)
                .map_err(|_| "Current message identities could not be confirmed for this label. No unfiltered results are displayed.")?;
            let version = &row
                .metadata
                .as_ref()
                .ok_or("Current message metadata is unavailable.")?
                .version;
            if !identities.insert(row.uid)
                || !versions.insert(version.message_guid.clone())
                || mailbox_guid
                    .as_ref()
                    .is_some_and(|guid| guid != &version.mailbox_guid)
            {
                return Err("Ambiguous current message identities prevent label filtering. No unfiltered results are displayed.");
            }
            mailbox_guid = Some(version.mailbox_guid.clone());
            keep.push(
                record
                    .labels_for(&identity)
                    .map_err(|_| "The label owner could not be confirmed.")?
                    .iter()
                    .any(|label| label.id() == id),
            );
        }
        let mut matches = keep.into_iter();
        rows.retain(|_| matches.next().unwrap_or(false));
        Ok(Some(record))
    }
}
