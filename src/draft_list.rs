//! Bounded projections for the account's saved-draft list. No body or Bcc data.
use std::cmp::Reverse;
use std::collections::BTreeMap;

use crate::draft::DraftSummary;

pub(crate) const MAX_DRAFT_SELECTION: usize = 10;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DraftFilter {
    #[default]
    All,
    Starred,
    Attachments,
    NoAttachments,
}

impl DraftFilter {
    pub(crate) const ALL: [Self; 4] = [
        Self::All,
        Self::Starred,
        Self::Attachments,
        Self::NoAttachments,
    ];
    pub(crate) fn value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Starred => "starred",
            Self::Attachments => "attachments",
            Self::NoAttachments => "no-attachments",
        }
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::All => "All drafts",
            Self::Starred => "Starred drafts",
            Self::Attachments => "With attachments",
            Self::NoAttachments => "Without attachments",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DraftSort {
    #[default]
    Newest,
    Oldest,
    Subject,
    Recipient,
}

impl DraftSort {
    pub(crate) const ALL: [Self; 4] = [Self::Newest, Self::Oldest, Self::Subject, Self::Recipient];
    pub(crate) fn value(self) -> &'static str {
        match self {
            Self::Newest => "newest",
            Self::Oldest => "oldest",
            Self::Subject => "subject",
            Self::Recipient => "recipient",
        }
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Newest => "Newest first",
            Self::Oldest => "Oldest first",
            Self::Subject => "Subject A–Z",
            Self::Recipient => "Recipient A–Z",
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct DraftListView {
    pub(crate) filter: DraftFilter,
    pub(crate) sort: DraftSort,
    pub(crate) query: String,
    pub(crate) select_editable: bool,
}

impl DraftListView {
    // Returning from an action never selects a new set of current drafts.
    pub(crate) fn href(&self) -> String {
        format!(
            "/drafts?filter={}&sort={}&q={}",
            self.filter.value(),
            self.sort.value(),
            crate::http_support::url_encode(&self.query)
        )
    }
    pub(crate) fn parse(query: &BTreeMap<String, String>) -> Result<Self, &'static str> {
        if query.keys().any(|key| {
            !matches!(
                key.as_str(),
                "q" | "filter" | "sort" | "saved" | "deleted" | "select"
            )
        }) {
            return Err("Use the draft list's filter and sort controls.");
        }
        let filter = match query.get("filter").map(String::as_str) {
            None | Some("all") => DraftFilter::All,
            Some("starred") => DraftFilter::Starred,
            Some("attachments") => DraftFilter::Attachments,
            Some("no-attachments") => DraftFilter::NoAttachments,
            _ => return Err("Choose a valid draft filter."),
        };
        let sort = match query.get("sort").map(String::as_str) {
            None | Some("newest") => DraftSort::Newest,
            Some("oldest") => DraftSort::Oldest,
            Some("subject") => DraftSort::Subject,
            Some("recipient") => DraftSort::Recipient,
            _ => return Err("Choose a valid draft order."),
        };
        let select_editable = match query.get("select").map(String::as_str) {
            None | Some("clear") => false,
            Some("editable") => true,
            _ => return Err("Choose a valid draft selection."),
        };
        let query = query.get("q").cloned().unwrap_or_default();
        if query.len() > 800 || query.chars().count() > 200 || query.chars().any(char::is_control) {
            return Err("Search draft subjects and recipients with up to 200 characters.");
        }
        Ok(Self {
            filter,
            sort,
            query,
            select_editable,
        })
    }

    pub(crate) fn select(&self, drafts: &[DraftSummary]) -> Vec<DraftSummary> {
        let needle = self.query.trim().to_lowercase();
        let mut selected: Vec<_> = drafts
            .iter()
            .filter(|draft| {
                let matches_filter = match self.filter {
                    DraftFilter::All => true,
                    DraftFilter::Starred => draft.starred,
                    DraftFilter::Attachments => draft.attachment_count > 0,
                    DraftFilter::NoAttachments => draft.attachment_count == 0,
                };
                matches_filter
                    && (needle.is_empty()
                        || draft.subject.to_lowercase().contains(&needle)
                        || draft
                            .recipient_preview
                            .as_deref()
                            .unwrap_or_default()
                            .to_lowercase()
                            .contains(&needle))
            })
            .cloned()
            .collect();
        match self.sort {
            DraftSort::Newest => selected.sort_by_key(|draft| {
                (
                    Reverse(draft.updated_at),
                    Reverse(draft.created_at),
                    draft.draft_id.clone(),
                )
            }),
            DraftSort::Oldest => selected
                .sort_by_key(|draft| (draft.updated_at, draft.created_at, draft.draft_id.clone())),
            DraftSort::Subject => selected
                .sort_by_cached_key(|draft| (draft.subject.to_lowercase(), draft.draft_id.clone())),
            DraftSort::Recipient => selected.sort_by_cached_key(|draft| {
                (
                    draft
                        .recipient_preview
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase(),
                    draft.draft_id.clone(),
                )
            }),
        }
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::draft::{DraftPolicy, DraftRecord, DraftRecordInput};

    fn row(id: u32, subject: &str, recipient: &str, updated: u64) -> DraftSummary {
        DraftRecord::new(
            DraftPolicy::default(),
            DraftRecordInput {
                draft_id: format!("{id:032x}"),
                canonical_username: "alice@example.test".into(),
                now: updated,
                recipients_text: recipient.into(),
                cc_text: String::new(),
                bcc_text: "private@example.test".into(),
                subject: subject.into(),
                body: "Body content never searched".into(),
                attachments: vec![],
                source_attachments: None,
            },
        )
        .unwrap()
        .summary()
    }

    #[test]
    fn ordering_and_filtering_preserve_metadata_and_do_not_search_bcc_or_body() {
        let mut rows = vec![
            row(2, "Zulu notes", "second@example.test", 300),
            row(1, "Alpha", "first@example.test", 100),
        ];
        rows[0].starred = true;
        rows[0].attachment_count = 1;
        let parse = |pairs: &[(&str, &str)]| {
            DraftListView::parse(
                &pairs
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
            )
            .unwrap()
        };
        for (filter, expected) in [
            ("all", 2),
            ("starred", 1),
            ("attachments", 1),
            ("no-attachments", 1),
        ] {
            assert_eq!(parse(&[("filter", filter)]).select(&rows).len(), expected);
        }
        assert_eq!(
            parse(&[("sort", "oldest")]).select(&rows)[0].draft_id,
            rows[1].draft_id
        );
        assert_eq!(
            parse(&[("sort", "subject")]).select(&rows)[0].subject,
            "Alpha"
        );
        assert_eq!(
            parse(&[("sort", "recipient")]).select(&rows)[0].recipient_preview,
            rows[1].recipient_preview
        );
        assert_eq!(
            parse(&[("q", "ZULU"), ("filter", "attachments")]).select(&rows)[0],
            rows[0]
        );
        for query in ["private@example.test", "Body content"] {
            assert!(parse(&[("q", query)]).select(&rows).is_empty());
        }
        assert_eq!(rows[0].subject, "Zulu notes");
    }

    #[test]
    fn malformed_and_unbounded_list_state_is_refused() {
        for (key, value) in [
            ("sort", "arbitrary"),
            ("filter", "sent"),
            ("owner", "bob@example.test"),
            ("q", "bad\nquery"),
        ] {
            assert!(DraftListView::parse(&BTreeMap::from([(key.into(), value.into())])).is_err());
        }
        assert!(DraftListView::parse(&BTreeMap::from([("q".into(), "é".repeat(201))])).is_err());
        assert!(DraftListView::parse(&BTreeMap::from([("q".into(), "é".repeat(200))])).is_ok());
    }
}
