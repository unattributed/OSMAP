//! Bounded, presentation-only mailbox navigation and result windows.

use crate::message_metadata::{MessageProtection, MessageVersion};
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

/// Outer OpenPGP MIME metadata, never signature verification or decryption proof.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtectionFilter {
    #[default]
    All,
    Plain,
    Signed,
    Encrypted,
    Unknown,
}

impl ProtectionFilter {
    pub fn value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Plain => "plain",
            Self::Signed => "signed",
            Self::Encrypted => "encrypted",
            Self::Unknown => "unknown",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All OpenPGP states",
            Self::Plain => "No outer OpenPGP MIME",
            Self::Signed => "Signed MIME",
            Self::Encrypted => "Encrypted MIME",
            Self::Unknown => "OpenPGP MIME unknown",
        }
    }

    pub fn matches(self, protection: MessageProtection) -> bool {
        match self {
            Self::All => true,
            Self::Plain => protection == MessageProtection::Plain,
            Self::Signed => protection == MessageProtection::Signed,
            Self::Encrypted => protection == MessageProtection::Encrypted,
            Self::Unknown => protection == MessageProtection::Unknown,
        }
    }
}

/// Exact public From mailbox matching, never proof of sender identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderFilter {
    address: Option<String>,
}

impl SenderFilter {
    fn parse(query: &BTreeMap<String, String>) -> Result<Self, &'static str> {
        let Some(value) = query.get("from") else {
            return Ok(Self::default());
        };
        let policy = Self::policy();
        if value.len() > policy.recipient_max_len || value.chars().any(char::is_control) {
            return Err("The sender address is too long or contains unsupported characters.");
        }
        let address = value.trim();
        if address.is_empty() {
            return Ok(Self::default());
        }
        crate::mail_address::validate_address(policy, address)
            .map_err(|_| "Enter one supported sender email address.")?;
        Ok(Self {
            address: Some(crate::mail_address::comparison_key(address)),
        })
    }

    fn policy() -> crate::send::ComposePolicy {
        crate::send::ComposePolicy {
            max_recipients: 1,
            ..crate::send::ComposePolicy::default()
        }
    }

    pub fn value(&self) -> &str {
        self.address.as_deref().unwrap_or("")
    }

    pub fn active(&self) -> bool {
        self.address.is_some()
    }

    pub fn matches(&self, header: Option<&str>) -> bool {
        let Some(address) = &self.address else {
            return true;
        };
        let Some(header) = header else {
            return false;
        };
        let policy = Self::policy();
        if header.len() > policy.recipient_max_len.saturating_add(256) {
            return false;
        }
        // The authoring list parser permits empty comma-separated fields.
        // A From singleton must not accept those malformed list separators;
        // quoted display-name commas remain supported by the shared parser.
        let mut quoted = false;
        let mut escaped = false;
        for character in header.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            match character {
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                ',' if !quoted => return false,
                _ => {}
            }
        }
        crate::mail_address::parse_address_list(policy, header)
            .ok()
            .filter(|mailboxes| mailboxes.len() == 1)
            .is_some_and(|mailboxes| crate::mail_address::comparison_key(&mailboxes[0]) == *address)
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
    /// Saved conversation mode applies only without an explicit URL sort.
    pub(crate) conversation_order: Option<crate::reading_preferences::DateOrder>,
    explicit_sort: bool,
    pub filter: MessageFilter,
    pub attachment: AttachmentFilter,
    pub protection: ProtectionFilter,
    pub sender: SenderFilter,
    pub requested_page: usize,
    pub page: usize,
    pub total_results: usize,
    pub backend_limit: usize,
    pub backend_truncated: bool,
    pub selection: Option<ListSelection>,
    /// An expected identity from a navigation link; fresh summaries still grant authority.
    pub requested_version: Option<MessageVersion>,
    /// Derived from this request's filtered backend results, never URL authority.
    pub selection_page: Option<usize>,
    pub selected_version: Option<MessageVersion>,
    /// Loaded from the authenticated account store, never a query/cookie choice.
    pub open_on_select: bool,
    /// Read-only presentation of a current Seen selection after it leaves Unread.
    pub opened_read: bool,
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
        let protection = match query.get("pgp").map(String::as_str) {
            None | Some("all") => ProtectionFilter::All,
            Some("plain") => ProtectionFilter::Plain,
            Some("signed") => ProtectionFilter::Signed,
            Some("encrypted") => ProtectionFilter::Encrypted,
            Some("unknown") => ProtectionFilter::Unknown,
            Some(_) => return Err("Choose a supported OpenPGP MIME filter."),
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
        let requested_version = match (
            query.get("selected_mailbox_guid"),
            query.get("selected_message_guid"),
        ) {
            (None, None) => None,
            (Some(mailbox), Some(message)) if selection.is_some() => Some(
                MessageVersion::new(mailbox.clone(), message.clone())
                    .map_err(|_| "The selected message identity is invalid.")?,
            ),
            _ => {
                return Err("The selected message identity requires its selection and both GUIDs.")
            }
        };
        let opened_read = match query.get("opened_read").map(String::as_str) {
            None => false,
            Some("1") if filter == MessageFilter::Unread && requested_version.is_some() => true,
            _ => return Err("The opened reader context requires Unread and both selected GUIDs."),
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
            protection,
            sender: SenderFilter::parse(query)?,
            requested_page: page,
            page,
            total_results: 0,
            backend_limit: DEFAULT_MAX_MESSAGES,
            backend_truncated: false,
            selection,
            requested_version,
            selection_page: None,
            selected_version: None,
            open_on_select: false,
            opened_read,
            conversation_order: None,
            explicit_sort: query.contains_key("sort") || query.contains_key("dir"),
        })
    }

    pub(crate) fn apply_saved_reading_defaults(
        &mut self,
        preferences: crate::reading_preferences::ReadingPreferences,
    ) {
        if !self.explicit_sort {
            self.sort = MessageSort {
                column: MessageSortColumn::Received,
                direction: match preferences.date_order {
                    crate::reading_preferences::DateOrder::Newest => MessageSortDirection::Desc,
                    crate::reading_preferences::DateOrder::Oldest => MessageSortDirection::Asc,
                },
            };
            self.conversation_order = Some(preferences.date_order);
        }
    }

    pub fn apply_messages(&mut self, messages: &mut Vec<MessageSummary>) {
        self.order_messages(messages);
        self.window(messages);
    }

    /// Keep the complete bounded, filtered order for reader navigation.
    pub(crate) fn order_messages(&mut self, messages: &mut Vec<MessageSummary>) {
        self.backend_limit = DEFAULT_MAX_MESSAGES;
        self.backend_truncated = messages.len() > self.backend_limit;
        messages.truncate(self.backend_limit);
        messages.retain(|message| {
            self.dates.matches(&message.date_received)
                && self.filter.matches(&message.flags)
                && self.sender.matches(message.from.as_deref())
                && self
                    .attachment
                    .matches(message.metadata.as_ref().and_then(|m| m.attachment_count))
                && self.protection.matches(
                    message
                        .metadata
                        .as_ref()
                        .map_or(MessageProtection::Unknown, |m| m.protection),
                )
        });
        if let Some(order) = self.conversation_order {
            crate::conversation::order_message_summaries(messages, order);
        } else {
            sort_message_summaries(messages, Some(self.sort));
        }
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
    }

    pub fn apply_search(&mut self, results: &mut Vec<MessageSearchResult>) {
        self.order_search(results);
        self.window(results);
    }

    /// Only a fresh Seen selection may stay in the reader after leaving Unread.
    /// This temporary snapshot affects navigation, never displayed rows/counts
    /// or stored flags. All other predicates are evaluated without alteration.
    pub(crate) fn recover_opened_messages(&mut self, snapshot: &mut [MessageSummary]) {
        if !self.opened_read
            || self.filter != MessageFilter::Unread
            || self.selection_page.is_some()
        {
            return;
        }
        let matching: Vec<_> = snapshot
            .iter()
            .take(DEFAULT_MAX_MESSAGES)
            .enumerate()
            .filter(|(_, row)| {
                self.is_selected(&row.mailbox_name, row.uid)
                    && row
                        .metadata
                        .as_ref()
                        .is_some_and(|m| Some(&m.version) == self.requested_version.as_ref())
                    && has_flag(&row.flags, "\\Seen")
            })
            .map(|(index, _)| index)
            .collect();
        let [index] = matching.as_slice() else {
            return;
        };
        let old = snapshot[*index].flags.clone();
        snapshot[*index]
            .flags
            .retain(|flag| !flag.eq_ignore_ascii_case("\\Seen"));
        let mut rows = snapshot.to_vec();
        let mut probe = self.clone();
        probe.order_messages(&mut rows);
        if probe.selected_version == self.requested_version && probe.selection_page.is_some() {
            self.selected_version = probe.selected_version;
            self.selection_page = Some(self.page);
        } else {
            snapshot[*index].flags = old;
        }
    }

    pub(crate) fn recover_opened_search(&mut self, snapshot: &mut [MessageSearchResult]) {
        if !self.opened_read
            || self.filter != MessageFilter::Unread
            || self.selection_page.is_some()
        {
            return;
        }
        let matching: Vec<_> = snapshot
            .iter()
            .take(DEFAULT_MAX_SEARCH_RESULTS)
            .enumerate()
            .filter(|(_, row)| {
                self.is_selected(&row.mailbox_name, row.uid)
                    && row
                        .metadata
                        .as_ref()
                        .is_some_and(|m| Some(&m.version) == self.requested_version.as_ref())
                    && has_flag(&row.flags, "\\Seen")
            })
            .map(|(index, _)| index)
            .collect();
        let [index] = matching.as_slice() else {
            return;
        };
        let old = snapshot[*index].flags.clone();
        snapshot[*index]
            .flags
            .retain(|flag| !flag.eq_ignore_ascii_case("\\Seen"));
        let mut rows = snapshot.to_vec();
        let mut probe = self.clone();
        probe.order_search(&mut rows);
        if probe.selected_version == self.requested_version && probe.selection_page.is_some() {
            self.selected_version = probe.selected_version;
            self.selection_page = Some(self.page);
        } else {
            snapshot[*index].flags = old;
        }
    }

    /// Search neighbours come from this result prefix, never a mailbox fallback.
    pub(crate) fn order_search(&mut self, results: &mut Vec<MessageSearchResult>) {
        self.backend_limit = DEFAULT_MAX_SEARCH_RESULTS;
        self.backend_truncated = results.len() > self.backend_limit;
        results.truncate(self.backend_limit);
        results.retain(|message| {
            self.dates.matches(&message.date_received)
                && self.filter.matches(&message.flags)
                && self.sender.matches(message.from.as_deref())
                && self
                    .attachment
                    .matches(message.metadata.as_ref().and_then(|m| m.attachment_count))
                && self.protection.matches(
                    message
                        .metadata
                        .as_ref()
                        .map_or(MessageProtection::Unknown, |m| m.protection),
                )
        });
        if let Some(order) = self.conversation_order {
            crate::conversation::order_search_results(results, order);
        } else {
            sort_message_search_results(results, Some(self.sort));
        }
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
    fn sender_filter_query_is_independent_and_canonical() {
        let inactive = ListViewState::from_query(&BTreeMap::new()).unwrap();
        assert!(!inactive.sender.active());
        let empty =
            ListViewState::from_query(&BTreeMap::from([("from".into(), "".into())])).unwrap();
        assert!(!empty.sender.active());
        let state = ListViewState::from_query(&BTreeMap::from([
            ("from".into(), " Sender@EXAMPLE.test ".into()),
            ("q".into(), "independent subject words".into()),
            ("field".into(), "subject".into()),
            ("pgp".into(), "signed".into()),
        ]))
        .unwrap();
        assert!(state.sender.active());
        assert_eq!(state.sender.value(), "Sender@example.test");
        assert_eq!(state.protection, ProtectionFilter::Signed);
    }

    #[test]
    fn sender_filter_query_rejects_multiple_malformed_control_and_oversize() {
        for value in [
            "not-a-mailbox",
            "sender@example.test,other@example.test",
            "sender@example.test,",
            "Public Sender <sender@example.test>",
            "sender@example.test\r\nBcc: other@example.test",
            "sender@example.test\0",
            "sender@-example.test",
            "sender@example..test",
        ] {
            assert!(
                ListViewState::from_query(&BTreeMap::from([("from".into(), value.into())]))
                    .is_err(),
                "{value:?}"
            );
        }
        assert!(
            ListViewState::from_query(&BTreeMap::from([("from".into(), "s".repeat(321))])).is_err()
        );
    }

    #[test]
    fn sender_filter_matches_only_one_exact_parsed_public_mailbox() {
        let filter = ListViewState::from_query(&BTreeMap::from([(
            "from".into(),
            "sender@example.test".into(),
        )]))
        .unwrap()
        .sender;
        for header in [
            "sender@example.test",
            "Sender Name <sender@EXAMPLE.test>",
            "\"Last, First\" <sender@example.test>",
        ] {
            assert!(filter.matches(Some(header)), "{header:?}");
        }
        for header in [
            None,
            Some(""),
            Some("sender@example.test <other@example.test>"),
            Some("not-sender@example.test"),
            Some("Sender@example.test"),
            Some("sender@example.test.evil"),
            Some("sender@example.test,other@example.test"),
            Some(",sender@example.test"),
            Some("sender@example.test,"),
            Some("sender@example.test,,"),
            Some("Sender <sender@example.test>\r\nX: bad"),
            Some("incomplete <sender@example.test"),
        ] {
            assert!(!filter.matches(header), "{header:?}");
        }
        assert!(!filter.matches(Some(&format!("{} <sender@example.test>", "x".repeat(600)))));
        assert!(SenderFilter::default().matches(None));
    }

    #[test]
    fn sender_filter_combines_with_query_metadata_and_selection_before_paging() {
        use crate::message_metadata::MessageMetadata;
        let rows = (1..=240)
            .map(|uid| {
                let mut message = row(uid, if uid % 2 == 0 { &["\\Seen"] } else { &[] });
                message.from = Some(
                    if uid <= 120 {
                        "\"Public, Sender\" <sender@EXAMPLE.test>"
                    } else {
                        "sender@example.test <other@example.test>"
                    }
                    .into(),
                );
                message.date_received = if uid <= 220 {
                    "2026-03-28 00:00:00 +0000"
                } else {
                    "unknown"
                }
                .into();
                message.metadata = Some(MessageMetadata {
                    threading: None,
                    version: MessageVersion::new("a".repeat(32), format!("synthetic-{uid}"))
                        .unwrap(),
                    attachment_count: Some(usize::from(uid % 2 == 1)),
                    attachments: None,
                    preview: None,
                    protection: if uid <= 200 {
                        MessageProtection::Signed
                    } else {
                        MessageProtection::Plain
                    },
                });
                message
            })
            .collect::<Vec<_>>();
        let query = BTreeMap::from([
            ("from".into(), "sender@example.test".into()),
            ("q".into(), "same subject".into()),
            ("field".into(), "subject".into()),
            ("pgp".into(), "signed".into()),
            ("filter".into(), "unread".into()),
            ("attachment".into(), "with".into()),
            ("after".into(), "2026-03-28".into()),
            ("page".into(), "2".into()),
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "1".into()),
        ]);
        let mut messages = rows.clone();
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_messages(&mut messages);
        assert_eq!(state.total_results, 60);
        assert_eq!(state.page, 2);
        assert_eq!(state.selection_page, Some(2));
        assert_eq!(
            state.selected_version.as_ref().unwrap().message_guid,
            "synthetic-1"
        );
        assert_eq!(
            messages.iter().map(|r| r.uid).collect::<Vec<_>>(),
            (1..=19).rev().step_by(2).collect::<Vec<_>>()
        );
        let mut search = rows.clone().into_iter().map(search_row).collect();
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_search(&mut search);
        assert_eq!(state.total_results, 60);
        assert_eq!(state.selection_page, Some(2));
        assert_eq!(
            search.iter().map(|r| r.uid).collect::<Vec<_>>(),
            messages.iter().map(|r| r.uid).collect::<Vec<_>>()
        );

        let mut other = query;
        other.insert("from".into(), "other@example.test".into());
        let mut state = ListViewState::from_query(&other).unwrap();
        let mut search = rows.into_iter().map(search_row).collect();
        state.apply_search(&mut search);
        assert_eq!(state.total_results, 40);
        assert_eq!(state.page, 1);
        assert_eq!(state.selection_page, None);
        assert_eq!(state.selected_version, None);
        assert!(search.iter().all(|r| (121..=199).contains(&r.uid)));
    }

    #[test]
    fn sender_filter_does_not_extend_the_validated_backend_prefix() {
        let rows = (1..=DEFAULT_MAX_MESSAGES + 1)
            .map(|uid| {
                let mut message = row(uid as u64, &[]);
                message.from = Some(
                    if uid > DEFAULT_MAX_MESSAGES {
                        "sender@example.test"
                    } else {
                        "other@example.test"
                    }
                    .into(),
                );
                message
            })
            .collect::<Vec<_>>();
        let query = BTreeMap::from([("from".into(), "sender@example.test".into())]);
        let mut messages = rows.clone();
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_messages(&mut messages);
        assert!(messages.is_empty());
        assert!(state.backend_truncated);
        assert_eq!(state.total_results, 0);
        let mut search = rows.into_iter().map(search_row).collect::<Vec<_>>();
        search[DEFAULT_MAX_SEARCH_RESULTS].from = Some("sender@example.test".into());
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_search(&mut search);
        assert!(search.is_empty());
        assert!(state.backend_truncated);
        assert_eq!(state.total_results, 0);
    }

    #[test]
    fn protection_filter_query_is_not_ignored() {
        assert_eq!(
            ListViewState::from_query(&BTreeMap::new())
                .unwrap()
                .protection,
            ProtectionFilter::All
        );
        for protection in [
            ProtectionFilter::All,
            ProtectionFilter::Plain,
            ProtectionFilter::Signed,
            ProtectionFilter::Encrypted,
            ProtectionFilter::Unknown,
        ] {
            let state = ListViewState::from_query(&BTreeMap::from([(
                "pgp".into(),
                protection.value().into(),
            )]))
            .unwrap();
            assert_eq!(state.protection, protection);
        }
    }

    #[test]
    fn protection_filter_query_refuses_unsupported_or_assurance_values() {
        for value in [
            "",
            "verified",
            "decrypted",
            "Signed",
            " signed",
            "signed\n",
            "<script>",
        ] {
            assert!(
                ListViewState::from_query(&BTreeMap::from([("pgp".into(), value.into(),)]))
                    .is_err(),
                "{value:?}"
            );
        }
        assert!(
            ListViewState::from_query(&BTreeMap::from([("pgp".into(), "s".repeat(8192),)]))
                .is_err()
        );
    }

    #[test]
    fn protection_filter_uses_metadata_and_keeps_unknown_distinct_in_both_lists() {
        use crate::message_metadata::{MessageMetadata, MessageProtection};
        let mut rows = [
            MessageProtection::Plain,
            MessageProtection::Signed,
            MessageProtection::Encrypted,
            MessageProtection::Unknown,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, protection)| {
            let mut message = row(index as u64 + 1, &[]);
            message.subject = Some("[signed] [encrypted] decorative header".into());
            message.metadata = Some(MessageMetadata {
                threading: None,
                version: MessageVersion::new("a".repeat(32), format!("synthetic-{index}")).unwrap(),
                attachment_count: Some(0),
                attachments: None,
                preview: None,
                protection,
            });
            message
        })
        .collect::<Vec<_>>();
        let mut missing = row(5, &[]);
        missing.subject = Some("Signed and encrypted message".into());
        rows.push(missing);
        for (value, expected) in [
            ("all", vec![5, 4, 3, 2, 1]),
            ("plain", vec![1]),
            ("signed", vec![2]),
            ("encrypted", vec![3]),
            ("unknown", vec![5, 4]),
        ] {
            let query = BTreeMap::from([("pgp".into(), value.into())]);
            let mut mailbox = rows.clone();
            let mut state = ListViewState::from_query(&query).unwrap();
            state.apply_messages(&mut mailbox);
            assert_eq!(mailbox.iter().map(|r| r.uid).collect::<Vec<_>>(), expected);
            assert_eq!(state.total_results, expected.len());
            let mut search = rows.iter().cloned().map(search_row).collect();
            let mut state = ListViewState::from_query(&query).unwrap();
            state.apply_search(&mut search);
            assert_eq!(search.iter().map(|r| r.uid).collect::<Vec<_>>(), expected);
            assert_eq!(state.total_results, expected.len());
        }
    }

    #[test]
    fn protection_filter_composes_before_selection_and_paging_in_both_lists() {
        use crate::message_metadata::MessageMetadata;
        let rows = (1..=240)
            .map(|uid| {
                let mut message = row(uid, if uid % 2 == 0 { &["\\Seen"] } else { &[] });
                message.date_received = if uid <= 120 {
                    "2026-03-28 00:00:00 +0000"
                } else {
                    "unknown"
                }
                .into();
                message.metadata = Some(MessageMetadata {
                    threading: None,
                    version: MessageVersion::new("a".repeat(32), format!("synthetic-{uid}"))
                        .unwrap(),
                    attachment_count: Some(usize::from(uid % 2 == 1)),
                    attachments: None,
                    preview: None,
                    protection: if uid <= 160 {
                        MessageProtection::Signed
                    } else {
                        MessageProtection::Plain
                    },
                });
                message
            })
            .collect::<Vec<_>>();
        let query = BTreeMap::from([
            ("pgp".into(), "signed".into()),
            ("filter".into(), "unread".into()),
            ("attachment".into(), "with".into()),
            ("after".into(), "2026-03-28".into()),
            ("page".into(), "2".into()),
            ("selected_mailbox".into(), "INBOX".into()),
            ("selected_uid".into(), "1".into()),
        ]);
        let mut messages = rows.clone();
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_messages(&mut messages);
        assert_eq!(state.total_results, 60);
        assert_eq!(state.page, 2);
        assert_eq!(state.selection_page, Some(2));
        assert_eq!(
            state.selected_version.as_ref().unwrap().message_guid,
            "synthetic-1"
        );
        assert_eq!(messages.len(), 10);
        assert_eq!(
            messages.iter().map(|r| r.uid).collect::<Vec<_>>(),
            (1..=19).rev().step_by(2).collect::<Vec<_>>()
        );

        let mut stale_search = rows.clone().into_iter().map(search_row).collect();
        let mut search = rows.into_iter().map(search_row).collect();
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_search(&mut search);
        assert_eq!(state.total_results, 60);
        assert_eq!(state.selection_page, Some(2));
        assert_eq!(
            state.selected_version.as_ref().unwrap().message_guid,
            "synthetic-1"
        );
        assert_eq!(
            search.iter().map(|r| r.uid).collect::<Vec<_>>(),
            messages.iter().map(|r| r.uid).collect::<Vec<_>>()
        );

        let mut stale = query;
        stale.insert("selected_uid".into(), "200".into());
        let mut state = ListViewState::from_query(&stale).unwrap();
        state.apply_search(&mut stale_search);
        assert_eq!(state.selection_page, None);
        assert_eq!(state.selected_version, None);
    }

    #[test]
    fn protection_filter_never_searches_beyond_the_validated_backend_prefix() {
        use crate::message_metadata::MessageMetadata;
        let rows = (1..=DEFAULT_MAX_MESSAGES + 1)
            .map(|uid| {
                let mut message = row(uid as u64, &[]);
                message.metadata = Some(MessageMetadata {
                    threading: None,
                    version: MessageVersion::new("a".repeat(32), format!("synthetic-{uid}"))
                        .unwrap(),
                    attachment_count: Some(0),
                    attachments: None,
                    preview: None,
                    protection: if uid > DEFAULT_MAX_MESSAGES {
                        MessageProtection::Signed
                    } else {
                        MessageProtection::Plain
                    },
                });
                message
            })
            .collect::<Vec<_>>();
        let query = BTreeMap::from([("pgp".into(), "signed".into()), ("page".into(), "2".into())]);
        let mut messages = rows.clone();
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_messages(&mut messages);
        assert!(messages.is_empty());
        assert!(state.backend_truncated);
        assert_eq!(state.backend_limit, DEFAULT_MAX_MESSAGES);
        assert_eq!(state.total_results, 0);
        assert_eq!(state.page, 1);

        let mut search = rows.into_iter().map(search_row).collect::<Vec<_>>();
        search[DEFAULT_MAX_SEARCH_RESULTS]
            .metadata
            .as_mut()
            .unwrap()
            .protection = MessageProtection::Signed;
        let mut state = ListViewState::from_query(&query).unwrap();
        state.apply_search(&mut search);
        assert!(search.is_empty());
        assert!(state.backend_truncated);
        assert_eq!(state.backend_limit, DEFAULT_MAX_SEARCH_RESULTS);
        assert_eq!(state.total_results, 0);
        assert_eq!(state.page, 1);
    }

    fn search_row(message: MessageSummary) -> MessageSearchResult {
        MessageSearchResult {
            metadata: message.metadata,
            mailbox_name: message.mailbox_name,
            uid: message.uid,
            flags: message.flags,
            date_received: message.date_received,
            size_virtual: message.size_virtual,
            subject: message.subject,
            from: message.from,
        }
    }

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
            threading: None,
            version: MessageVersion::new("a".repeat(32), "synthetic".into()).unwrap(),
            attachment_count: count,
            attachments: None,
            preview: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
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
            threading: None,
            version: version.clone(),
            attachment_count: Some(0),
            attachments: None,
            preview: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
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
