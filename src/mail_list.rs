//! Bounded, presentation-only mailbox navigation and result windows.

use crate::message_metadata::MessageVersion;
use std::collections::BTreeMap;

use crate::mailbox::{
    sort_message_search_results, sort_message_summaries, MailboxEntry, MailboxListingPolicy,
    MessageSearchResult, MessageSort, MessageSortColumn, MessageSortDirection, MessageSummary,
    DEFAULT_MAX_MESSAGES, DEFAULT_MAX_SEARCH_RESULTS,
};

pub const MESSAGE_PAGE_SIZE: usize = 50;
pub const MAX_BULK_SELECTION: usize = 10;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BulkSelection {
    #[default]
    None,
    Move,
    Archive,
}

/// Decorative initials from the untrusted displayed header, never identity proof.
pub fn sender_initials(sender: Option<&str>) -> String {
    let sender = sender.unwrap_or("").trim();
    let name = sender.split('<').next().unwrap_or("").trim();
    let name = if name.is_empty() {
        sender.trim_start_matches('<')
    } else {
        name
    };
    let name = name.split('@').next().unwrap_or("");
    let initials: String = name
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .take(2)
        .filter_map(|word| word.chars().next())
        .flat_map(char::to_uppercase)
        .take(2)
        .collect();
    if initials.is_empty() {
        "?".into()
    } else {
        initials
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MessageFilter {
    #[default]
    All,
    Unread,
    Starred,
}

impl MessageFilter {
    pub fn value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Unread => "unread",
            Self::Starred => "starred",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All messages",
            Self::Unread => "Unread",
            Self::Starred => "Starred",
        }
    }

    pub fn matches(self, flags: &[String]) -> bool {
        match self {
            Self::All => true,
            Self::Unread => !has_flag(flags, "\\Seen"),
            Self::Starred => has_flag(flags, "\\Flagged"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AttachmentFilter {
    #[default]
    All,
    With,
    Without,
    Unknown,
}
impl AttachmentFilter {
    pub fn value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::With => "with",
            Self::Without => "without",
            Self::Unknown => "unknown",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All attachment states",
            Self::With => "Has attachment",
            Self::Without => "No attachments",
            Self::Unknown => "Attachment status unknown",
        }
    }
    pub fn matches(self, count: Option<usize>) -> bool {
        match self {
            Self::All => true,
            Self::With => count.is_some_and(|n| n > 0),
            Self::Without => count == Some(0),
            Self::Unknown => count.is_none(),
        }
    }
}

pub fn has_flag(flags: &[String], flag: &str) -> bool {
    flags.iter().any(|value| value.eq_ignore_ascii_case(flag))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceivedDateRange {
    pub after: Option<String>,
    pub before: Option<String>,
    start: Option<i64>,
    end: Option<i64>,
}
impl ReceivedDateRange {
    fn parse(query: &BTreeMap<String, String>) -> Result<Self, &'static str> {
        let bound = |key: &str| -> Result<_, &'static str> {
            match query.get(key).filter(|value| !value.is_empty()) {
                None => Ok((None, None)),
                Some(value) => crate::mailbox::parse_calendar_date(value)
                    .map(|timestamp| (Some(value.clone()), Some(timestamp)))
                    .ok_or("Choose a valid received date in YYYY-MM-DD format."),
            }
        };
        let (after, start) = bound("after")?;
        let (before, end) = bound("before")?;
        if start.zip(end).is_some_and(|(start, end)| start > end) {
            return Err("From date must be on or before Through date.");
        }
        Ok(Self {
            after,
            before,
            start,
            end,
        })
    }
    pub fn active(&self) -> bool {
        self.start.is_some() || self.end.is_some()
    }
    fn matches(&self, value: &str) -> bool {
        if !self.active() {
            return true;
        }
        crate::mailbox::parse_received_timestamp(value).is_some_and(|time| {
            self.start.is_none_or(|start| time >= start)
                && self.end.is_none_or(|end| time < end + 86_400)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSelection {
    pub mailbox: String,
    pub uid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListViewState {
    pub dates: ReceivedDateRange,
    pub bulk_selection: BulkSelection,
    pub sort: MessageSort,
    pub filter: MessageFilter,
    pub attachment: AttachmentFilter,
    pub requested_page: usize,
    pub page: usize,
    pub total_results: usize,
    pub backend_limit: usize,
    pub backend_truncated: bool,
    pub selection: Option<ListSelection>,
    /// Derived from this request's filtered backend results, never URL authority.
    pub selection_page: Option<usize>,
    pub selected_version: Option<MessageVersion>,
}

impl ListViewState {
    pub fn from_query(query: &BTreeMap<String, String>) -> Result<Self, &'static str> {
        let bulk_selection = match query.get("select").map(String::as_str) {
            None | Some("none") => BulkSelection::None,
            Some("move") => BulkSelection::Move,
            Some("archive") => BulkSelection::Archive,
            Some(_) => return Err("Choose a supported message selection."),
        };
        if query.get("q").is_some_and(|value| {
            value.len() > crate::mailbox::DEFAULT_SEARCH_QUERY_MAX_LEN
                || value.chars().any(char::is_control)
        }) {
            return Err("The search query is too long or contains unsupported characters.");
        }
        let filter = match query.get("filter").map(String::as_str) {
            None | Some("all") => MessageFilter::All,
            Some("unread") => MessageFilter::Unread,
            Some("starred") => MessageFilter::Starred,
            Some(_) => return Err("Choose All messages, Unread or Starred."),
        };
        let attachment = match query.get("attachment").map(String::as_str) {
            None | Some("all") => AttachmentFilter::All,
            Some("with") => AttachmentFilter::With,
            Some("without") => AttachmentFilter::Without,
            Some("unknown") => AttachmentFilter::Unknown,
            Some(_) => return Err("Choose a supported attachment filter."),
        };
        let page = match query.get("page") {
            None => 1,
            Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => value
                .parse::<usize>()
                .ok()
                .filter(|page| {
                    (1..=DEFAULT_MAX_MESSAGES.div_ceil(MESSAGE_PAGE_SIZE)).contains(page)
                })
                .ok_or("The requested page is outside the supported range.")?,
            Some(_) => return Err("The requested page must be a positive number."),
        };
        let selection = match (query.get("selected_mailbox"), query.get("selected_uid")) {
            (None, None) => None,
            (Some(mailbox), Some(uid)) => {
                MailboxEntry::new(MailboxListingPolicy::default(), mailbox)
                    .map_err(|_| "The selected mailbox is invalid.")?;
                let uid = uid
                    .parse::<u32>()
                    .ok()
                    .filter(|uid| *uid > 0)
                    .ok_or("The selected message is invalid.")?;
                Some(ListSelection {
                    mailbox: mailbox.clone(),
                    uid: u64::from(uid),
                })
            }
            _ => return Err("The selected message requires both its mailbox and UID."),
        };
        Ok(Self {
            dates: ReceivedDateRange::parse(query)?,
            bulk_selection,
            sort: MessageSort::from_query_values(
                query.get("sort").map(String::as_str),
                query.get("dir").map(String::as_str),
            )
            .unwrap_or(MessageSort {
                column: MessageSortColumn::Received,
                direction: MessageSortDirection::Desc,
            }),
            filter,
            attachment,
            requested_page: page,
            page,
            total_results: 0,
            backend_limit: DEFAULT_MAX_MESSAGES,
            backend_truncated: false,
            selection,
            selection_page: None,
            selected_version: None,
        })
    }

    pub fn apply_messages(&mut self, messages: &mut Vec<MessageSummary>) {
        self.backend_limit = DEFAULT_MAX_MESSAGES;
        self.backend_truncated = messages.len() > self.backend_limit;
        messages.truncate(self.backend_limit);
        messages.retain(|message| {
            self.dates.matches(&message.date_received)
                && self.filter.matches(&message.flags)
                && self
                    .attachment
                    .matches(message.metadata.as_ref().and_then(|m| m.attachment_count))
        });
        sort_message_summaries(messages, Some(self.sort));
        let selected = messages
            .iter()
            .enumerate()
            .find(|(_, message)| self.is_selected(&message.mailbox_name, message.uid));
        self.selection_page = selected.map(|(index, _)| index / MESSAGE_PAGE_SIZE + 1);
        self.selected_version = selected.and_then(|(_, message)| {
            message
                .metadata
                .as_ref()
                .map(|metadata| metadata.version.clone())
        });
        self.window(messages);
    }

    pub fn apply_search(&mut self, results: &mut Vec<MessageSearchResult>) {
        self.backend_limit = DEFAULT_MAX_SEARCH_RESULTS;
        self.backend_truncated = results.len() > self.backend_limit;
        results.truncate(self.backend_limit);
        results.retain(|message| {
            self.dates.matches(&message.date_received)
                && self.filter.matches(&message.flags)
                && self
                    .attachment
                    .matches(message.metadata.as_ref().and_then(|m| m.attachment_count))
        });
        sort_message_search_results(results, Some(self.sort));
        let selected = results
            .iter()
            .enumerate()
            .find(|(_, message)| self.is_selected(&message.mailbox_name, message.uid));
        self.selection_page = selected.map(|(index, _)| index / MESSAGE_PAGE_SIZE + 1);
        self.selected_version = selected.and_then(|(_, message)| {
            message
                .metadata
                .as_ref()
                .map(|metadata| metadata.version.clone())
        });
        self.window(results);
    }

    fn window<T>(&mut self, items: &mut Vec<T>) {
        self.total_results = items.len();
        self.page = self.requested_page.min(self.pages());
        let start = (self.page - 1) * MESSAGE_PAGE_SIZE;
        items.drain(..start);
        items.truncate(MESSAGE_PAGE_SIZE);
    }

    pub fn pages(&self) -> usize {
        self.total_results.div_ceil(MESSAGE_PAGE_SIZE).max(1)
    }

    pub fn first_result(&self) -> usize {
        if self.total_results == 0 {
            0
        } else {
            (self.page - 1) * MESSAGE_PAGE_SIZE + 1
        }
    }

    pub fn last_result(&self) -> usize {
        (self.page * MESSAGE_PAGE_SIZE).min(self.total_results)
    }

    pub fn is_selected(&self, mailbox: &str, uid: u64) -> bool {
        self.selection
            .as_ref()
            .is_some_and(|value| value.mailbox == mailbox && value.uid == uid)
    }

    pub fn is_bulk_selected(&self, action: BulkSelection, visible_index: usize) -> bool {
        action != BulkSelection::None
            && self.bulk_selection == action
            && visible_index < MAX_BULK_SELECTION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_dates_are_strict_inclusive_utc_and_bounded() {
        use crate::mailbox::{parse_calendar_date as day, parse_received_timestamp as time};
        for good in ["0001-01-01", "2000-02-29", "2024-02-29", "9999-12-31"] {
            assert!(day(good).is_some());
        }
        for bad in [
            "0000-01-01",
            "1900-02-29",
            "2026-02-29",
            "2026-04-31",
            "2026-1-01",
            "+2026-01-01",
            "２０２６-01-01",
            "999999999999999999-01-01",
            "2026-01-01x",
        ] {
            assert_eq!(day(bad), None, "{bad}");
        }
        for bad in [
            "2026-01-01 00:00:00 +é00",
            "2026-01-01 00:00:00 +0000 extra",
            "2026-01-01 24:00:00",
            "2026-01-01 00:00:60",
            "2026-01-01 00:00:00 +2400",
            "2026-01-01 00:00:00 +0060",
        ] {
            assert_eq!(time(bad), None, "{bad}");
        }
        let range = ReceivedDateRange::parse(&BTreeMap::from([
            ("after".into(), "2026-03-28".into()),
            ("before".into(), "2026-03-28".into()),
        ]))
        .unwrap();
        for good in [
            "2026-03-28 00:00:00 +0000",
            "2026-03-28 23:59:59",
            "2026-03-29 00:30:00 +0100",
            "2026-03-27 23:30:00 -0100",
        ] {
            assert!(range.matches(good), "{good}");
        }
        for bad in [
            "",
            "unknown",
            "2026-03-28 00:30:00 +0100",
            "2026-03-28 23:30:00 -0100",
        ] {
            assert!(!range.matches(bad), "{bad}");
        }
        assert!(ReceivedDateRange::default().matches("unknown"));
        assert!(ReceivedDateRange::parse(&BTreeMap::from([
            ("after".into(), "2026-03-29".into()),
            ("before".into(), "2026-03-28".into())
        ]))
        .is_err());
    }

    #[test]
    fn received_dates_compose_with_unread_before_paging_and_selection() {
        let mut state = ListViewState::from_query(&BTreeMap::from([
            ("after".into(), "2026-03-28".into()),
            ("filter".into(), "unread".into()),
            ("page".into(), "2".into()),
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "1".into()),
        ]))
        .unwrap();
        let mut rows: Vec<_> = (1..=240)
            .map(|uid| {
                let mut r = row(uid, if uid % 2 == 0 { &["\\Seen"] } else { &[] });
                r.date_received = if uid <= 120 {
                    "2026-03-28 00:00:00 +0000"
                } else {
                    "unknown"
                }
                .into();
                r
            })
            .collect();
        state.apply_messages(&mut rows);
        assert_eq!(state.total_results, 60);
        assert_eq!(rows.len(), 10);
        assert_eq!(state.selection_page, Some(2));
    }

    #[test]
    fn attachment_filter_distinguishes_unknown_and_composes_before_paging() {
        let metadata = |count| crate::message_metadata::MessageMetadata {
            version: MessageVersion::new("a".repeat(32), "synthetic".into()).unwrap(),
            attachment_count: count,
            preview: None,
        };
        let rows = (1..=240)
            .map(|uid| {
                let mut r = row(uid, if uid % 2 == 0 { &["\\Seen"] } else { &[] });
                r.metadata = match uid % 4 {
                    0 => None,
                    1 => Some(metadata(None)),
                    2 => Some(metadata(Some(0))),
                    _ => Some(metadata(Some(2))),
                };
                r
            })
            .collect::<Vec<_>>();
        for (value, count) in [
            ("all", 240),
            ("with", 60),
            ("without", 60),
            ("unknown", 120),
        ] {
            let mut state = ListViewState::from_query(&BTreeMap::from([
                ("attachment".into(), value.into()),
                ("page".into(), "2".into()),
            ]))
            .unwrap();
            let mut selected = rows.clone();
            state.apply_messages(&mut selected);
            assert_eq!(state.total_results, count);
            assert_eq!(selected.len(), (count - 50).min(50));
        }
        let mut state = ListViewState::from_query(&BTreeMap::from([
            ("attachment".into(), "unknown".into()),
            ("filter".into(), "unread".into()),
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "1".into()),
        ]))
        .unwrap();
        let mut selected = rows;
        state.apply_messages(&mut selected);
        assert_eq!(state.total_results, 60);
        assert_eq!(state.selection_page, Some(2));
        assert!(ListViewState::from_query(&BTreeMap::from([(
            "attachment".into(),
            "invalid".into()
        )]))
        .is_err());
    }

    #[test]
    fn selection_menu_is_closed_and_bounded_to_the_current_page() {
        let view = ListViewState::from_query(&BTreeMap::from([("select".into(), "move".into())]))
            .expect("selection");
        assert_eq!(
            (0..50)
                .filter(|index| view.is_bulk_selected(BulkSelection::Move, *index))
                .count(),
            MAX_BULK_SELECTION
        );
        assert!(!view.is_bulk_selected(BulkSelection::Archive, 0));
        assert!(ListViewState::from_query(&BTreeMap::from([(
            "select".into(),
            "arbitrary".into()
        )]))
        .is_err());
        assert_eq!(
            sender_initials(Some("Alice Johnson <alice@example.test>")),
            "AJ"
        );
        assert_eq!(sender_initials(Some("<john.smith@example.test>")), "JS");
        assert_eq!(sender_initials(Some("Élodie Roy")), "ÉR");
        assert_eq!(sender_initials(None), "?");
        assert!(sender_initials(Some("<b>Untrusted</b>"))
            .chars()
            .all(char::is_alphanumeric));
    }

    fn row(uid: u64, flags: &[&str]) -> MessageSummary {
        MessageSummary {
            to: None,
            metadata: None,
            mailbox_name: "INBOX".into(),
            uid,
            flags: flags.iter().map(|value| value.to_string()).collect(),
            date_received: "2026-09-30 00:00:00 +0000".into(),
            size_virtual: 12,
            subject: Some("same subject".into()),
            from: None,
        }
    }

    #[test]
    fn invalid_and_partial_navigation_is_rejected() {
        for (key, value) in [
            ("filter", "script"),
            ("page", "0"),
            ("page", "41"),
            ("page", "-1"),
            ("page", "999999999999999999999999999"),
            ("selected_uid", "1"),
        ] {
            assert!(
                ListViewState::from_query(&BTreeMap::from([(key.into(), value.into())])).is_err()
            );
        }
    }

    #[test]
    fn filters_use_imap_flags_and_selection_includes_mailbox() {
        let mut state = ListViewState::from_query(&BTreeMap::from([
            ("filter".into(), "unread".into()),
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "2".into()),
        ]))
        .expect("valid state");
        let mut rows = vec![row(1, &["\\sEeN"]), row(2, &["\\Flagged"]), row(3, &[])];
        state.apply_messages(&mut rows);
        assert_eq!(rows.iter().map(|r| r.uid).collect::<Vec<_>>(), vec![3, 2]);
        assert!(state.is_selected("INBOX", 2));
        assert!(!state.is_selected("Sent", 2));
        assert!(MessageFilter::Starred.matches(&["\\flagged".into()]));
    }

    #[test]
    fn selected_identity_is_derived_before_paging_and_removed_when_results_change() {
        let mut state = ListViewState::from_query(&BTreeMap::from([
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "1".into()),
        ]))
        .expect("selection");
        let version = MessageVersion::new("a".repeat(32), "synthetic-1".into()).expect("version");
        let mut rows = (1..=120).map(|uid| row(uid, &[])).collect::<Vec<_>>();
        rows[0].metadata = Some(crate::message_metadata::MessageMetadata {
            version: version.clone(),
            attachment_count: Some(0),
            preview: None,
        });
        state.apply_messages(&mut rows);
        assert_eq!(state.selection_page, Some(3));
        assert_eq!(state.selected_version, Some(version));
        assert!(!rows.iter().any(|row| row.uid == 1));
        state.apply_messages(&mut vec![row(2, &[])]);
        assert_eq!(state.selection_page, None);
        assert_eq!(state.selected_version, None);
        assert!(ListViewState::from_query(&BTreeMap::from([
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "4294967296".into()),
        ]))
        .is_err());
    }

    #[test]
    fn bounded_pages_are_stable_and_outdated_pages_clamp() {
        let query = BTreeMap::from([("page".into(), "2".into())]);
        let mut state = ListViewState::from_query(&query).expect("page two");
        let mut rows = (1..=120).map(|uid| row(uid, &[])).collect::<Vec<_>>();
        state.apply_messages(&mut rows);
        assert_eq!(
            (
                state.total_results,
                state.first_result(),
                state.last_result(),
                state.pages()
            ),
            (120, 51, 100, 3)
        );
        assert_eq!((rows.len(), rows[0].uid, rows[49].uid), (50, 70, 21));
        let mut fewer = vec![row(1, &[])];
        state.apply_messages(&mut fewer);
        assert_eq!((state.page, state.requested_page), (1, 2));
        let mut empty = Vec::new();
        state.apply_messages(&mut empty);
        assert_eq!(
            (state.first_result(), state.last_result(), state.pages()),
            (0, 0, 1)
        );
    }
}
