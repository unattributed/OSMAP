//! Reconstruct only bounded, authenticated mail GET destinations after actions.
use crate::http_form::parse_urlencoded_form;
use crate::http_support::url_encode;
use crate::mail_list::ListViewState;
use crate::mailbox::{MailboxEntry, MailboxListingPolicy, MessageSearchField};

/// Clear action selection after a move; the next GET recomputes counts/pages.
pub fn mail_return_after_move(value: &str, source: &str) -> Option<String> {
    let safe = safe_mail_return(value)?;
    let (path, query) = safe.split_once('?')?;
    if path == "/message" {
        return Some(format!("/mailbox?name={}", url_encode(source)));
    }
    let mut fields = parse_urlencoded_form(query.as_bytes(), 16, 2048).ok()?;
    for key in ["select", "selected_mailbox", "selected_uid"] {
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
    let fields = parse_urlencoded_form(query.as_bytes(), 16, 2048).ok()?;
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
                "after",
                "before",
                "page",
                "q",
                "scope",
                "selected_mailbox",
                "selected_uid",
                "select",
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
                "after",
                "before",
                "page",
                "selected_mailbox",
                "selected_uid",
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
            &["mailbox", "uid"]
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
