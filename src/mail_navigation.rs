//! Reconstruct only bounded, authenticated mail GET destinations after actions.
use crate::http_form::parse_urlencoded_form;
use crate::http_support::url_encode;
use crate::mail_list::ListViewState;
use crate::mailbox::{MailboxEntry, MailboxListingPolicy, MessageSearchField};

// Finite mail-context allowlists plus the expected selected GUID pair.
pub(crate) const MAIL_RETURN_MAX_FIELDS: usize = 19;

/// Validated mail filters carried through mixed search; not contact metadata.
#[derive(Clone)]
pub(crate) struct SearchFilterContext {
    pub view: ListViewState,
    pub mailbox: Option<String>,
}

#[derive(Clone, Copy)]
pub(crate) enum SearchTab {
    All,
    Messages,
    People,
}

impl SearchFilterContext {
    pub fn parse(fields: &std::collections::BTreeMap<String, String>) -> Option<Self> {
        let max_page = match fields.get("category").map(String::as_str) {
            Some("all") => 23,
            Some("people") => 10,
            _ => return None,
        };
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "category"
                    | "q"
                    | "page"
                    | "from"
                    | "after"
                    | "before"
                    | "attachment"
                    | "pgp"
                    | "filter"
                    | "mailbox"
            )
        }) {
            return None;
        }
        let mut page_number = 1;
        if let Some(page) = fields.get("page") {
            let number = page.parse::<usize>().ok()?;
            if !(1..=max_page).contains(&number) || number.to_string() != *page {
                return None;
            }
            page_number = number;
        }
        // Category windows are 20 rows; the mail-list 50-row page cap does not
        // constrain them. Validate only predicates with the existing model.
        let mut predicates = fields.clone();
        predicates.remove("page");
        let mut view = ListViewState::from_query(&predicates).ok()?;
        view.page = page_number;
        view.requested_page = page_number;
        let mailbox = fields
            .get("mailbox")
            .filter(|name| !name.is_empty())
            .cloned();
        if let Some(name) = &mailbox {
            MailboxEntry::new(MailboxListingPolicy::default(), name).ok()?;
        }
        Some(Self { view, mailbox })
    }

    /// No sort, reader selection, read marker or bulk fields enter category URLs.
    pub fn fields(&self) -> std::collections::BTreeMap<String, String> {
        use crate::mail_list::{AttachmentFilter, MessageFilter, ProtectionFilter};
        let mut fields = std::collections::BTreeMap::new();
        if self.view.sender.active() {
            fields.insert("from".into(), self.view.sender.value().into());
        }
        for (key, value) in [
            ("after", &self.view.dates.after),
            ("before", &self.view.dates.before),
        ] {
            if let Some(value) = value {
                fields.insert(key.into(), value.clone());
            }
        }
        if self.view.filter != MessageFilter::All {
            fields.insert("filter".into(), self.view.filter.value().into());
        }
        if self.view.attachment != AttachmentFilter::All {
            fields.insert("attachment".into(), self.view.attachment.value().into());
        }
        if self.view.protection != ProtectionFilter::All {
            fields.insert("pgp".into(), self.view.protection.value().into());
        }
        if let Some(name) = &self.mailbox {
            fields.insert("mailbox".into(), name.clone());
        }
        fields
    }

    pub fn href(&self, tab: SearchTab, query: &str, page: Option<usize>) -> String {
        let mut fields = self.fields();
        match tab {
            SearchTab::All => {
                fields.insert("category".into(), "all".into());
            }
            SearchTab::People => {
                fields.insert("category".into(), "people".into());
            }
            SearchTab::Messages if self.mailbox.is_none() => {
                fields.insert("scope".into(), "all".into());
            }
            SearchTab::Messages => {}
        }
        fields.insert("q".into(), query.into());
        if let Some(page) = page {
            fields.insert("page".into(), page.to_string());
        }
        format!(
            "/search?{}",
            fields
                .iter()
                .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
                .collect::<Vec<_>>()
                .join("&")
        )
    }
}

/// Clear action selection after a move; the next GET recomputes counts/pages.
pub fn mail_return_after_move(value: &str, source: &str) -> Option<String> {
    let safe = safe_mail_return(value)?;
    let (path, query) = safe.split_once('?')?;
    if path == "/message" {
        let fields = parse_urlencoded_form(query.as_bytes(), MAIL_RETURN_MAX_FIELDS, 2048).ok()?;
        return fields
            .get("return_to")
            .and_then(|back| mail_return_after_move(back, source))
            .or_else(|| Some(format!("/mailbox?name={}", url_encode(source))));
    }
    let mut fields = parse_urlencoded_form(query.as_bytes(), MAIL_RETURN_MAX_FIELDS, 2048).ok()?;
    for key in [
        "select",
        "selected_mailbox",
        "selected_uid",
        "selected_mailbox_guid",
        "selected_message_guid",
        "opened_read",
    ] {
        fields.remove(key);
    }
    Some(format!(
        "{path}?{}",
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    ))
}

pub fn safe_mail_return(value: &str) -> Option<String> {
    if value.len() > 2048 || value.contains('#') || value.chars().any(char::is_control) {
        return None;
    }
    let (path, query) = value.split_once('?')?;
    let fields = parse_urlencoded_form(query.as_bytes(), MAIL_RETURN_MAX_FIELDS, 2048).ok()?;
    let mailbox_valid =
        |name: &str| MailboxEntry::new(MailboxListingPolicy::default(), name).is_ok();
    let allowed: &[&str] = match path {
        "/mailbox" => {
            if !mailbox_valid(fields.get("name")?) {
                return None;
            }
            ListViewState::from_query(&fields).ok()?;
            &[
                "name",
                "sort",
                "dir",
                "filter",
                "attachment",
                "pgp",
                "from",
                "after",
                "before",
                "page",
                "q",
                "scope",
                "selected_mailbox",
                "selected_uid",
                "selected_mailbox_guid",
                "selected_message_guid",
                "opened_read",
                "select",
            ]
        }
        "/search"
            if matches!(
                fields.get("category").map(String::as_str),
                Some("all" | "people")
            ) =>
        {
            SearchFilterContext::parse(&fields)?;
            &[
                "category",
                "q",
                "page",
                "from",
                "after",
                "before",
                "attachment",
                "pgp",
                "filter",
                "mailbox",
            ]
        }
        "/search" => {
            if fields.get("q")?.trim().is_empty() {
                return None;
            }
            ListViewState::from_query(&fields).ok()?;
            if let Some(name) = fields.get("mailbox") {
                if !mailbox_valid(name) {
                    return None;
                }
            }
            if let Some(field) = fields.get("field") {
                MessageSearchField::from_query_value(field)?;
            }
            &[
                "mailbox",
                "q",
                "scope",
                "field",
                "sort",
                "dir",
                "filter",
                "attachment",
                "pgp",
                "from",
                "after",
                "before",
                "page",
                "selected_mailbox",
                "selected_uid",
                "selected_mailbox_guid",
                "selected_message_guid",
                "opened_read",
                "select",
            ]
        }
        "/message" => {
            if !mailbox_valid(fields.get("mailbox")?) {
                return None;
            }
            let uid = fields.get("uid")?.parse::<u32>().ok()?;
            if uid == 0 {
                return None;
            }
            match (fields.get("mailbox_guid"), fields.get("message_guid")) {
                (None, None) => {}
                (Some(mailbox), Some(message)) => {
                    crate::message_metadata::MessageVersion::new(mailbox.clone(), message.clone())
                        .ok()?;
                }
                _ => return None,
            }
            if let Some(back) = fields.get("return_to") {
                if !(back.starts_with("/mailbox?") || back.starts_with("/search?")) {
                    return None;
                }
                safe_mail_return(back)?;
            }
            &[
                "mailbox",
                "uid",
                "mailbox_guid",
                "message_guid",
                "return_to",
            ]
        }
        _ => return None,
    };
    if fields.keys().any(|name| !allowed.contains(&name.as_str())) {
        return None;
    }
    if fields
        .get("scope")
        .is_some_and(|value| value != "all" && value != "mailbox")
    {
        return None;
    }
    let encoded: Vec<_> = fields
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect();
    Some(format!("{path}?{}", encoded.join("&")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn people_theme_return_retains_query_page_and_refuses_other_route_fields() {
        assert_eq!(
            safe_mail_return("/search?category=people&q=Alice+%26+Bob&page=2"),
            Some("/search?category=people&page=2&q=Alice+%26+Bob".into())
        );
        assert_eq!(
            safe_mail_return("/search?category=people"),
            Some("/search?category=people".into())
        );
        for value in [
            "/search?category=people&page=0",
            "/search?category=people&page=11",
            "/search?category=people&page=01",
            "/search?category=people&scope=all",
            "/search?category=people&selected_uid=9",
            "/search?category=people&q=%00",
            "/search?category=other&q=Alice",
            "https://example.test/search?category=people",
        ] {
            assert!(safe_mail_return(value).is_none(), "{value}");
        }
    }

    #[test]
    fn attachment_return_preserves_search_scope_and_clears_only_moved_selection() {
        let target="/search?q=report&field=subject&scope=all&filter=unread&attachment=unknown&sort=received&dir=asc&page=2&selected_mailbox=INBOX&selected_uid=7&select=move";
        let safe = safe_mail_return(target).unwrap();
        assert!(safe.contains("attachment=unknown"));
        assert!(safe.contains("field=subject"));
        let moved = mail_return_after_move(target, "INBOX").unwrap();
        assert!(moved.contains("attachment=unknown"));
        assert!(moved.contains("page=2"));
        assert!(!moved.contains("selected_"));
        assert!(safe_mail_return("/mailbox?name=INBOX&attachment=invalid").is_none());
    }

    #[test]
    fn only_bounded_mail_get_context_is_reconstructed() {
        assert_eq!(
            safe_mail_return("/search?q=quarterly+report&scope=all&filter=unread&page=2"),
            Some("/search?filter=unread&page=2&q=quarterly+report&scope=all".into())
        );
        for value in [
            "https://example.test/",
            "//example.test/mailbox?name=INBOX",
            "/logout?a=1",
            "/message?mailbox=INBOX&uid=0",
            "/mailbox?name=INBOX&page=41",
            "/mailbox?name=INBOX&filter=invalid",
            "/search?q=test&field=invalid",
            "/mailbox?name=INBOX&name=Sent",
            "/mailbox?name=INBOX#fragment",
            "/mailbox?name=INBOX&unexpected=1",
        ] {
            assert_eq!(safe_mail_return(value), None, "{value}");
        }
    }
}

#[cfg(test)]
#[test]
fn reader_return_keeps_versions_and_one_bounded_list_context() {
    let back = "/mailbox?name=INBOX&filter=unread&selected_uid=9&selected_mailbox=INBOX";
    let reader = format!(
        "/message?mailbox=INBOX&uid=9&mailbox_guid={}&message_guid=stored&return_to={}",
        "a".repeat(32),
        url_encode(back)
    );
    let safe = safe_mail_return(&reader).unwrap();
    assert!(safe.contains("message_guid=stored"));
    assert!(safe.contains("return_to="));
    let moved = mail_return_after_move(&safe, "INBOX").unwrap();
    assert!(moved.contains("filter=unread"));
    assert!(!moved.contains("selected_uid"));
    for nested in [
        reader.as_str(),
        "https://foreign.test/path",
        "/message?mailbox=INBOX&uid=9",
    ] {
        assert!(safe_mail_return(&format!(
            "/message?mailbox=INBOX&uid=9&return_to={}",
            url_encode(nested)
        ))
        .is_none());
    }
}
