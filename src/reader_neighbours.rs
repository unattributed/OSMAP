//! Standalone navigation through one verified, bounded mailbox summary snapshot.
use crate::http::BrowserMessageListDecision;
use crate::http_support::{escape_html, url_encode};
use crate::mailbox::{
    sort_message_summaries, MessageSort, MessageSortColumn, MessageSortDirection,
    DEFAULT_MAX_MESSAGES,
};
use crate::message_metadata::MessageVersion;
use crate::reading_preferences::{DateOrder, ReadingPreferences};
use crate::rendering::RenderedMessageView;
use std::collections::{BTreeMap, HashSet};

#[derive(Default)]
pub(crate) struct ReaderNeighbours {
    pub back: Option<String>,
    previous: Option<String>,
    next: Option<String>,
    scope: Option<String>,
}

pub(crate) fn query_version_matches(
    query: &BTreeMap<String, String>,
    rendered: &RenderedMessageView,
) -> bool {
    match (query.get("mailbox_guid"), query.get("message_guid")) {
        (None, None) => true,
        (Some(mailbox), Some(message)) => MessageVersion::new(mailbox.clone(), message.clone())
            .ok()
            .is_some_and(|version| {
                rendered
                    .metadata
                    .as_ref()
                    .is_some_and(|m| m.version == version)
            }),
        _ => false,
    }
}
impl ReaderNeighbours {
    pub(crate) fn derive(
        account: &str,
        rendered: &RenderedMessageView,
        preferences: Option<ReadingPreferences>,
        decision: &BrowserMessageListDecision,
        return_to: Option<&str>,
    ) -> Self {
        let back = return_to
            .and_then(crate::mail_navigation::safe_mail_return)
            .filter(|value| value.starts_with("/mailbox?") || value.starts_with("/search?"));
        let unavailable = || Self {
            back: back.clone(),
            ..Self::default()
        };
        let Some(preferences) = preferences else {
            return unavailable();
        };
        let BrowserMessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
        } = decision
        else {
            return unavailable();
        };
        let Some(current) = rendered.metadata.as_ref() else {
            return unavailable();
        };
        if account != canonical_username
            || mailbox_name != &rendered.mailbox_name
            || messages.is_empty()
            || messages.len() > DEFAULT_MAX_MESSAGES
            || rendered.uid == 0
        {
            return unavailable();
        }
        let mut uids = HashSet::new();
        let mut identities = HashSet::new();
        for row in messages {
            let Some(metadata) = row.metadata.as_ref() else {
                return unavailable();
            };
            let version = &metadata.version;
            if row.mailbox_name != *mailbox_name
                || row.uid == 0
                || !uids.insert(row.uid)
                || !identities.insert(&version.message_guid)
                || version.mailbox_guid != current.version.mailbox_guid
                || MessageVersion::new(version.mailbox_guid.clone(), version.message_guid.clone())
                    .as_ref()
                    != Ok(version)
                || crate::mailbox::parse_received_timestamp(&row.date_received).is_none()
            {
                return unavailable();
            }
        }
        let Some(selected) = messages.iter().find(|row| row.uid == rendered.uid) else {
            return unavailable();
        };
        if selected.metadata.as_ref().map(|m| &m.version) != Some(&current.version) {
            return unavailable();
        }
        let mut sorted = messages.clone();
        sort_message_summaries(
            &mut sorted,
            Some(MessageSort {
                column: MessageSortColumn::Received,
                direction: if preferences.date_order == DateOrder::Newest {
                    MessageSortDirection::Desc
                } else {
                    MessageSortDirection::Asc
                },
            }),
        );
        let Some(index) = sorted.iter().position(|row| row.uid == rendered.uid) else {
            return unavailable();
        };
        let link = |row: &crate::mailbox::MessageSummary| {
            row.metadata.as_ref().map(|metadata| {
                let mut href = format!(
                    "/message?mailbox={}&uid={}&mailbox_guid={}&message_guid={}",
                    url_encode(mailbox_name),
                    row.uid,
                    url_encode(&metadata.version.mailbox_guid),
                    url_encode(&metadata.version.message_guid)
                );
                if let Some(back) = &back {
                    href.push_str(&format!("&return_to={}", url_encode(back)));
                }
                href
            })
        };
        Self { previous:index.checked_sub(1).and_then(|i| sorted.get(i)).and_then(link),next:sorted.get(index+1).and_then(link),scope:Some(format!("Loaded {} messages only, {} first (up to {}). Previous and Next do not follow list filters or search results. Mailbox contents can change between requests.",mailbox_name,preferences.date_order.as_str(),DEFAULT_MAX_MESSAGES)),back }
    }
    pub(crate) fn html(&self) -> String {
        let control = |href: &Option<String>, label: &str, symbol: &str| match href {
            Some(href) => format!(
                "<a class=\"button-link\" aria-label=\"{label} message\" href=\"{}\">{symbol}</a>",
                escape_html(href)
            ),
            None => format!(
                "<button type=\"button\" aria-label=\"{label} message\" disabled>{symbol}</button>"
            ),
        };
        format!("<nav class=\"reader-neighbours\" aria-label=\"Previous and next messages\">{}{}<details><summary>Loaded mailbox order</summary><p>{}</p></details></nav>",control(&self.previous,"Previous","←"),control(&self.next,"Next","→"),escape_html(self.scope.as_deref().unwrap_or("Navigation unavailable: mailbox identities, received dates or the saved Reading order could not be verified. Return to the list.")))
    }
}
