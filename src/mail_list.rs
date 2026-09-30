//! Bounded, presentation-only mailbox navigation and result windows.

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

pub fn has_flag(flags: &[String], flag: &str) -> bool {
    flags.iter().any(|value| value.eq_ignore_ascii_case(flag))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSelection {
    pub mailbox: String,
    pub uid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListViewState {
    pub bulk_selection: BulkSelection,
    pub sort: MessageSort,
    pub filter: MessageFilter,
    pub requested_page: usize,
    pub page: usize,
    pub total_results: usize,
    pub backend_limit: usize,
    pub backend_truncated: bool,
    pub selection: Option<ListSelection>,
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
                    .parse::<u64>()
                    .ok()
                    .filter(|uid| *uid > 0)
                    .ok_or("The selected message is invalid.")?;
                Some(ListSelection {
                    mailbox: mailbox.clone(),
                    uid,
                })
            }
            _ => return Err("The selected message requires both its mailbox and UID."),
        };
        Ok(Self {
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
            requested_page: page,
            page,
            total_results: 0,
            backend_limit: DEFAULT_MAX_MESSAGES,
            backend_truncated: false,
            selection,
        })
    }

    pub fn apply_messages(&mut self, messages: &mut Vec<MessageSummary>) {
        self.backend_limit = DEFAULT_MAX_MESSAGES;
        self.backend_truncated = messages.len() > self.backend_limit;
        messages.truncate(self.backend_limit);
        messages.retain(|message| self.filter.matches(&message.flags));
        sort_message_summaries(messages, Some(self.sort));
        self.window(messages);
    }

    pub fn apply_search(&mut self, results: &mut Vec<MessageSearchResult>) {
        self.backend_limit = DEFAULT_MAX_SEARCH_RESULTS;
        self.backend_truncated = results.len() > self.backend_limit;
        results.truncate(self.backend_limit);
        results.retain(|message| self.filter.matches(&message.flags));
        sort_message_search_results(results, Some(self.sort));
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
