use super::*;
use std::cmp::Ordering;

/// Conservative maximum length for a mailbox name returned by the backend.
pub const DEFAULT_MAILBOX_NAME_MAX_LEN: usize = 255;

/// Conservative upper bound for the number of mailboxes returned in one listing.
pub const DEFAULT_MAX_MAILBOXES: usize = 1024;

/// Conservative upper bound for the number of messages returned in one listing.
pub const DEFAULT_MAX_MESSAGES: usize = 2000;

/// Conservative upper bound for the number of messages returned in one search.
pub const DEFAULT_MAX_SEARCH_RESULTS: usize = 250;

/// Conservative maximum length for rendered date strings returned by the backend.
pub const DEFAULT_MESSAGE_DATE_MAX_LEN: usize = 128;

/// Conservative maximum length for rendered flag strings returned by the backend.
pub const DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN: usize = 256;

/// Conservative maximum length for one free-text mailbox search query.
pub const DEFAULT_SEARCH_QUERY_MAX_LEN: usize = 256;

/// Conservative maximum length for a surfaced header field in search results.
pub const DEFAULT_SEARCH_HEADER_VALUE_MAX_LEN: usize = 512;

/// Conservative maximum length for fetched message headers.
pub const DEFAULT_MESSAGE_HEADER_MAX_LEN: usize = 65_536;

/// Conservative maximum length for fetched message bodies in the first view slice.
pub const DEFAULT_MESSAGE_BODY_MAX_LEN: usize = 262_144;

/// Policy controlling mailbox-output bounds for the first read-path slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxListingPolicy {
    pub mailbox_name_max_len: usize,
    pub max_mailboxes: usize,
}

impl Default for MailboxListingPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        }
    }
}

/// Policy controlling message-list request and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageListPolicy {
    pub mailbox_name_max_len: usize,
    pub max_messages: usize,
    pub message_date_max_len: usize,
    pub message_flag_string_max_len: usize,
    pub header_value_max_len: usize,
}

impl Default for MessageListPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_messages: DEFAULT_MAX_MESSAGES,
            message_date_max_len: DEFAULT_MESSAGE_DATE_MAX_LEN,
            message_flag_string_max_len: DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN,
            header_value_max_len: DEFAULT_SEARCH_HEADER_VALUE_MAX_LEN,
        }
    }
}

/// Policy controlling single-message retrieval request and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageViewPolicy {
    pub mailbox_name_max_len: usize,
    pub message_date_max_len: usize,
    pub message_flag_string_max_len: usize,
    pub message_header_max_len: usize,
    pub message_body_max_len: usize,
}

impl Default for MessageViewPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            message_date_max_len: DEFAULT_MESSAGE_DATE_MAX_LEN,
            message_flag_string_max_len: DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN,
            message_header_max_len: DEFAULT_MESSAGE_HEADER_MAX_LEN,
            message_body_max_len: DEFAULT_MESSAGE_BODY_MAX_LEN,
        }
    }
}

/// Policy controlling mailbox-scoped search request and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSearchPolicy {
    pub mailbox_name_max_len: usize,
    pub max_results: usize,
    pub query_max_len: usize,
    pub message_date_max_len: usize,
    pub message_flag_string_max_len: usize,
    pub header_value_max_len: usize,
}

impl Default for MessageSearchPolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_results: DEFAULT_MAX_SEARCH_RESULTS,
            query_max_len: DEFAULT_SEARCH_QUERY_MAX_LEN,
            message_date_max_len: DEFAULT_MESSAGE_DATE_MAX_LEN,
            message_flag_string_max_len: DEFAULT_MESSAGE_FLAG_STRING_MAX_LEN,
            header_value_max_len: DEFAULT_SEARCH_HEADER_VALUE_MAX_LEN,
        }
    }
}

/// A single mailbox visible to the authenticated user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    pub name: String,
}

impl MailboxEntry {
    /// Validates a mailbox name so later UI and logging code does not inherit
    /// unbounded or ambiguous backend output.
    pub fn new(
        policy: MailboxListingPolicy,
        name: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        let name = name.into();

        if name.is_empty() {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: "mailbox name must not be empty".to_string(),
            });
        }

        if name.len() > policy.mailbox_name_max_len {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: format!(
                    "mailbox name exceeded maximum length of {} bytes",
                    policy.mailbox_name_max_len
                ),
            });
        }

        if name.chars().any(char::is_control) {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: "mailbox name contains control characters".to_string(),
            });
        }

        Ok(Self { name })
    }
}

/// A validated request for listing messages from a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageListRequest {
    pub mailbox_name: String,
}

impl MessageListRequest {
    /// Validates the mailbox name used for message-list retrieval.
    pub fn new(
        policy: MessageListPolicy,
        mailbox_name: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_name = mailbox_name.into();
        let _ = MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: policy.mailbox_name_max_len,
                max_mailboxes: DEFAULT_MAX_MAILBOXES,
            },
            mailbox_name.clone(),
        )?;

        Ok(Self { mailbox_name })
    }
}

/// A single summary row in a message list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    pub mailbox_name: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub date_received: String,
    pub size_virtual: u64,
    pub subject: Option<String>,
    pub from: Option<String>,
}

/// Sortable message-list columns accepted from browser query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSortColumn {
    Uid,
    Subject,
    From,
    Received,
    Flags,
    Size,
}

impl MessageSortColumn {
    pub fn from_query_value(value: &str) -> Option<Self> {
        match value {
            "uid" => Some(Self::Uid),
            "subject" => Some(Self::Subject),
            "from" => Some(Self::From),
            "received" => Some(Self::Received),
            "flags" => Some(Self::Flags),
            "size" => Some(Self::Size),
            _ => None,
        }
    }

    pub fn query_value(self) -> &'static str {
        match self {
            Self::Uid => "uid",
            Self::Subject => "subject",
            Self::From => "from",
            Self::Received => "received",
            Self::Flags => "flags",
            Self::Size => "size",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Uid => "UID",
            Self::Subject => "Subject",
            Self::From => "From",
            Self::Received => "Received",
            Self::Flags => "Flags",
            Self::Size => "Size",
        }
    }

    pub fn default_direction(self) -> MessageSortDirection {
        match self {
            Self::Received => MessageSortDirection::Desc,
            Self::Uid | Self::Subject | Self::From | Self::Flags | Self::Size => {
                MessageSortDirection::Asc
            }
        }
    }
}

/// Sort direction accepted from browser query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSortDirection {
    Asc,
    Desc,
}

impl MessageSortDirection {
    pub fn from_query_value(value: &str) -> Option<Self> {
        match value {
            "asc" => Some(Self::Asc),
            "desc" => Some(Self::Desc),
            _ => None,
        }
    }

    pub fn query_value(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }
}

/// Validated message-list sort request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSort {
    pub column: MessageSortColumn,
    pub direction: MessageSortDirection,
}

impl MessageSort {
    pub fn from_query_values(sort: Option<&str>, dir: Option<&str>) -> Option<Self> {
        let column = MessageSortColumn::from_query_value(sort?)?;
        let direction = dir
            .and_then(MessageSortDirection::from_query_value)
            .unwrap_or_else(|| column.default_direction());

        Some(Self { column, direction })
    }
}

pub fn sort_message_summaries(messages: &mut [MessageSummary], sort: Option<MessageSort>) {
    let Some(sort) = sort else {
        return;
    };

    messages.sort_by(|left, right| compare_message_summary(left, right, sort));
}

pub(crate) fn validate_message_search_query(
    policy: MessageSearchPolicy,
    query: impl Into<String>,
) -> Result<String, MailboxBackendError> {
    let query = query.into().trim().to_string();
    if query.is_empty() {
        return Err(MailboxBackendError {
            backend: "message-search-parser",
            reason: "search query must not be empty".to_string(),
        });
    }
    if query.len() > policy.query_max_len {
        return Err(MailboxBackendError {
            backend: "message-search-parser",
            reason: format!(
                "search query exceeded maximum length of {} bytes",
                policy.query_max_len
            ),
        });
    }
    if query.chars().any(char::is_control) {
        return Err(MailboxBackendError {
            backend: "message-search-parser",
            reason: "search query contains control characters".to_string(),
        });
    }

    Ok(query)
}

/// A validated mailbox-scoped search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSearchRequest {
    pub mailbox_name: String,
    pub query: String,
    pub field: MessageSearchField,
}

impl MessageSearchRequest {
    /// Validates the mailbox name and free-text query used for message search.
    pub fn new(
        policy: MessageSearchPolicy,
        mailbox_name: impl Into<String>,
        query: impl Into<String>,
    ) -> Result<Self, MailboxBackendError> {
        Self::new_with_field(policy, mailbox_name, query, MessageSearchField::All)
    }

    /// Validates the mailbox name, free-text query, and whitelisted field
    /// refinement used for message search.
    pub fn new_with_field(
        policy: MessageSearchPolicy,
        mailbox_name: impl Into<String>,
        query: impl Into<String>,
        field: MessageSearchField,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_name = mailbox_name.into();
        let _ = MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: policy.mailbox_name_max_len,
                max_mailboxes: DEFAULT_MAX_MAILBOXES,
            },
            mailbox_name.clone(),
        )?;

        let query = validate_message_search_query(policy, query)?;

        Ok(Self {
            mailbox_name,
            query,
            field,
        })
    }
}

/// Bounded search fields accepted from browser query parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSearchField {
    All,
    Subject,
    From,
}

impl MessageSearchField {
    pub fn from_query_value(value: &str) -> Option<Self> {
        match value {
            "all" => Some(Self::All),
            "subject" => Some(Self::Subject),
            "from" => Some(Self::From),
            _ => None,
        }
    }

    pub fn query_value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Subject => "subject",
            Self::From => "from",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All message text",
            Self::Subject => "Subject",
            Self::From => "From",
        }
    }

    pub(crate) fn doveadm_search_key(self) -> &'static str {
        match self {
            Self::All => "TEXT",
            Self::Subject => "SUBJECT",
            Self::From => "FROM",
        }
    }
}

/// A single summary row returned from a mailbox-scoped search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSearchResult {
    pub mailbox_name: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub date_received: String,
    pub size_virtual: u64,
    pub subject: Option<String>,
    pub from: Option<String>,
}

pub fn sort_message_search_results(results: &mut [MessageSearchResult], sort: Option<MessageSort>) {
    let Some(sort) = sort else {
        return;
    };

    results.sort_by(|left, right| compare_message_search_result(left, right, sort));
}

fn compare_message_summary(
    left: &MessageSummary,
    right: &MessageSummary,
    sort: MessageSort,
) -> Ordering {
    match sort.column {
        MessageSortColumn::Uid => compare_ord(left.uid, right.uid, sort.direction),
        MessageSortColumn::Subject => compare_optional_text(
            left.subject.as_deref(),
            right.subject.as_deref(),
            sort.direction,
        ),
        MessageSortColumn::From => {
            compare_optional_text(left.from.as_deref(), right.from.as_deref(), sort.direction)
        }
        MessageSortColumn::Received => compare_optional_ord(
            parse_received_timestamp(&left.date_received),
            parse_received_timestamp(&right.date_received),
            sort.direction,
        ),
        MessageSortColumn::Flags => compare_text(
            &left.flags.join(" ").to_lowercase(),
            &right.flags.join(" ").to_lowercase(),
            sort.direction,
        ),
        MessageSortColumn::Size => {
            compare_ord(left.size_virtual, right.size_virtual, sort.direction)
        }
    }
}

fn compare_message_search_result(
    left: &MessageSearchResult,
    right: &MessageSearchResult,
    sort: MessageSort,
) -> Ordering {
    match sort.column {
        MessageSortColumn::Uid => compare_ord(left.uid, right.uid, sort.direction),
        MessageSortColumn::Subject => compare_optional_text(
            left.subject.as_deref(),
            right.subject.as_deref(),
            sort.direction,
        ),
        MessageSortColumn::From => {
            compare_optional_text(left.from.as_deref(), right.from.as_deref(), sort.direction)
        }
        MessageSortColumn::Received => compare_optional_ord(
            parse_received_timestamp(&left.date_received),
            parse_received_timestamp(&right.date_received),
            sort.direction,
        ),
        MessageSortColumn::Flags => compare_text(
            &left.flags.join(" ").to_lowercase(),
            &right.flags.join(" ").to_lowercase(),
            sort.direction,
        ),
        MessageSortColumn::Size => {
            compare_ord(left.size_virtual, right.size_virtual, sort.direction)
        }
    }
}

fn compare_ord<T: Ord>(left: T, right: T, direction: MessageSortDirection) -> Ordering {
    apply_sort_direction(left.cmp(&right), direction)
}

fn compare_optional_ord<T: Ord>(
    left: Option<T>,
    right: Option<T>,
    direction: MessageSortDirection,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => compare_ord(left, right, direction),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn compare_optional_text(
    left: Option<&str>,
    right: Option<&str>,
    direction: MessageSortDirection,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            compare_text(&left.to_lowercase(), &right.to_lowercase(), direction)
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn compare_text(left: &str, right: &str, direction: MessageSortDirection) -> Ordering {
    apply_sort_direction(left.cmp(right), direction)
}

fn apply_sort_direction(ordering: Ordering, direction: MessageSortDirection) -> Ordering {
    match direction {
        MessageSortDirection::Asc => ordering,
        MessageSortDirection::Desc => ordering.reverse(),
    }
}

fn parse_received_timestamp(value: &str) -> Option<i64> {
    let mut fields = value.split_whitespace();
    let date = fields.next()?;
    let time = fields.next()?;
    let offset = fields.next().unwrap_or("+0000");

    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() || !valid_month_day(year, month, day) {
        return None;
    }

    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<i64>().ok()?;
    let minute = time_parts.next()?.parse::<i64>().ok()?;
    let second = time_parts.next()?.parse::<i64>().ok()?;
    if time_parts.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    let offset_seconds = parse_timezone_offset_seconds(offset)?;
    let day_seconds = hour * 3600 + minute * 60 + second;

    Some(days_from_civil(year, month, day) * 86_400 + day_seconds - offset_seconds)
}

fn parse_timezone_offset_seconds(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 5 || (bytes[0] != b'+' && bytes[0] != b'-') {
        return None;
    }
    let sign = if bytes[0] == b'+' { 1 } else { -1 };
    let hours = value[1..3].parse::<i64>().ok()?;
    let minutes = value[3..5].parse::<i64>().ok()?;
    if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
        return None;
    }

    Some(sign * (hours * 3600 + minutes * 60))
}

fn valid_month_day(year: i64, month: u32, day: u32) -> bool {
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };

    (1..=max_day).contains(&day)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day = day as i64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

/// A validated request for retrieving one message from a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageViewRequest {
    pub mailbox_name: String,
    pub uid: u64,
}

impl MessageViewRequest {
    /// Validates the mailbox name and UID used for message retrieval.
    pub fn new(
        policy: MessageViewPolicy,
        mailbox_name: impl Into<String>,
        uid: u64,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_name = mailbox_name.into();
        let _ = MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: policy.mailbox_name_max_len,
                max_mailboxes: DEFAULT_MAX_MAILBOXES,
            },
            mailbox_name.clone(),
        )?;

        if uid == 0 {
            return Err(MailboxBackendError {
                backend: "message-view-parser",
                reason: "uid must be greater than zero".to_string(),
            });
        }

        Ok(Self { mailbox_name, uid })
    }
}

/// Policy controlling one-message move request validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageMovePolicy {
    pub mailbox_name_max_len: usize,
}

impl Default for MessageMovePolicy {
    fn default() -> Self {
        Self {
            mailbox_name_max_len: DEFAULT_MAILBOX_NAME_MAX_LEN,
        }
    }
}

/// A validated request for moving one message between existing mailboxes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMoveRequest {
    pub source_mailbox_name: String,
    pub destination_mailbox_name: String,
    pub uid: u64,
}

impl MessageMoveRequest {
    /// Validates the source mailbox, destination mailbox, and UID for a
    /// one-message move operation.
    pub fn new(
        policy: MessageMovePolicy,
        source_mailbox_name: impl Into<String>,
        destination_mailbox_name: impl Into<String>,
        uid: u64,
    ) -> Result<Self, MailboxBackendError> {
        let mailbox_policy = MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        };
        let source_mailbox_name =
            MailboxEntry::new(mailbox_policy, source_mailbox_name.into())?.name;
        let destination_mailbox_name =
            MailboxEntry::new(mailbox_policy, destination_mailbox_name.into())?.name;

        if source_mailbox_name == destination_mailbox_name {
            return Err(MailboxBackendError {
                backend: "message-move-parser",
                reason: "destination mailbox must differ from source mailbox".to_string(),
            });
        }

        if uid == 0 {
            return Err(MailboxBackendError {
                backend: "message-move-parser",
                reason: "uid must be greater than zero".to_string(),
            });
        }

        Ok(Self {
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        })
    }
}

/// A bounded per-message payload for the first message-view slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageView {
    pub mailbox_name: String,
    pub uid: u64,
    pub flags: Vec<String>,
    pub date_received: String,
    pub size_virtual: u64,
    pub header_block: String,
    pub body_text: String,
}

/// The user-facing reason returned when mailbox listing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxPublicFailureReason {
    NotFound,
    TemporarilyUnavailable,
}

impl MailboxPublicFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Internal audit reason used when mailbox listing fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxAuditFailureReason {
    NotFound,
    BackendUnavailable,
    OutputRejected,
}

impl MailboxAuditFailureReason {
    /// Returns the canonical string representation used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::BackendUnavailable => "backend_unavailable",
            Self::OutputRejected => "output_rejected",
        }
    }
}

/// The outcome of a mailbox-list request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxListingDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailboxes: Vec<MailboxEntry>,
    },
}

/// The outcome of a message-list request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageListDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailbox_name: String,
        messages: Vec<MessageSummary>,
    },
}

/// The outcome of a message-view request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageViewDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Retrieved {
        canonical_username: String,
        session_id: String,
        message: MessageView,
    },
}

/// The outcome of a message-search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageSearchDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Listed {
        canonical_username: String,
        session_id: String,
        mailbox_name: String,
        query: String,
        results: Vec<MessageSearchResult>,
    },
}

/// The outcome of a one-message move request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageMoveDecision {
    Denied {
        public_reason: MailboxPublicFailureReason,
    },
    Moved {
        canonical_username: String,
        session_id: String,
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
    },
}

/// The decision plus audit event emitted by mailbox listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxListingOutcome {
    pub decision: MailboxListingDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by message-list retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageListOutcome {
    pub decision: MessageListDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by message retrieval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageViewOutcome {
    pub decision: MessageViewDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by message search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSearchOutcome {
    pub decision: MessageSearchDecision,
    pub audit_event: LogEvent,
}

/// The decision plus audit event emitted by one-message move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMoveOutcome {
    pub decision: MessageMoveDecision,
    pub audit_event: LogEvent,
}

/// Backend failures that should not leak detailed internals to mailbox users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxBackendError {
    pub backend: &'static str,
    pub reason: String,
}

/// A backend capable of listing mailboxes for a canonical user.
pub trait MailboxBackend {
    fn list_mailboxes(
        &self,
        canonical_username: &str,
    ) -> Result<Vec<MailboxEntry>, MailboxBackendError>;
}

/// A backend capable of listing message summaries for a mailbox.
pub trait MessageListBackend {
    fn list_messages(
        &self,
        canonical_username: &str,
        request: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError>;
}

/// A backend capable of retrieving one message view for a mailbox and UID.
pub trait MessageViewBackend {
    fn fetch_message(
        &self,
        canonical_username: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError>;
}

/// A backend capable of searching for messages within one mailbox.
pub trait MessageSearchBackend {
    fn search_messages(
        &self,
        canonical_username: &str,
        request: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError>;
}

/// A backend capable of moving one message between existing mailboxes.
pub trait MessageMoveBackend {
    fn move_message(
        &self,
        canonical_username: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError>;
}
