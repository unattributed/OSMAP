//! Previous/next through authenticated, bounded originating list snapshots.
use crate::http::{BrowserMessageListDecision, BrowserMessageSearchDecision};
use crate::http_form::parse_urlencoded_form;
use crate::http_support::{escape_html, url_encode};
use crate::mail_list::{ListSelection, ListViewState, MESSAGE_PAGE_SIZE};
use crate::mailbox::{
    MailboxEntry, MailboxListingPolicy, MessageSearchResult, DEFAULT_MAX_MESSAGES,
    DEFAULT_MAX_SEARCH_RESULTS,
};
use crate::message_metadata::MessageVersion;
use crate::reading_preferences::ReadingPreferences;
use crate::rendering::RenderedMessageView;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy)]
pub(crate) enum ReaderLocation {
    Standalone,
    Coordinated,
}

#[derive(Default)]
pub(crate) struct ReaderNeighbours {
    pub back: Option<String>,
    previous: Option<String>,
    next: Option<String>,
    scope: Option<String>,
    open_on_select: bool,
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

fn origin(value: &str) -> Option<(String, String, BTreeMap<String, String>)> {
    let safe = crate::mail_navigation::safe_mail_return(value)?;
    let (path, query) = safe.split_once('?')?;
    if path != "/mailbox" && path != "/search" {
        return None;
    }
    let fields = parse_urlencoded_form(
        query.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .ok()?;
    Some((safe.clone(), path.into(), fields))
}

// The route may supply the saved date order when no explicit URL sort exists.
// All other selectors must agree with the validated origin URL.
fn matching_view(fields: &BTreeMap<String, String>, view: &ListViewState) -> bool {
    let Ok(parsed) = ListViewState::from_query(fields) else {
        return false;
    };
    parsed.dates == view.dates
        && parsed.filter == view.filter
        && parsed.attachment == view.attachment
        && parsed.protection == view.protection
        && parsed.sender == view.sender
        && (!(fields.contains_key("sort") || fields.contains_key("dir"))
            || parsed.sort == view.sort)
}

fn valid_rows<'a>(
    rows: impl IntoIterator<Item = (&'a str, u64, &'a str, Option<&'a MessageVersion>)>,
) -> bool {
    let mut tuples = HashSet::new();
    let mut identities = HashSet::new();
    let mut mailbox_guids = BTreeMap::new();
    let mut guid_mailboxes = BTreeMap::new();
    for (mailbox, uid, received, version) in rows {
        let Some(version) = version else {
            return false;
        };
        if uid == 0
            || uid > u64::from(u32::MAX)
            || MailboxEntry::new(MailboxListingPolicy::default(), mailbox).is_err()
            || !tuples.insert((mailbox, uid))
            || !identities.insert((&version.mailbox_guid, &version.message_guid))
            || MessageVersion::new(version.mailbox_guid.clone(), version.message_guid.clone())
                .as_ref()
                != Ok(version)
            || crate::mailbox::parse_received_timestamp(received).is_none()
        {
            return false;
        }
        if mailbox_guids
            .insert(mailbox, &version.mailbox_guid)
            .is_some_and(|previous| previous != &version.mailbox_guid)
            || guid_mailboxes
                .insert(&version.mailbox_guid, mailbox)
                .is_some_and(|previous| previous != mailbox)
        {
            return false;
        }
    }
    true
}

impl ReaderNeighbours {
    pub(crate) fn unavailable(back: Option<String>) -> Self {
        Self {
            back,
            ..Self::default()
        }
    }

    /// Legacy standalone reader. A real origin uses its filters and explicit
    /// sort; Search requires a fresh search decision and never a mailbox fallback.
    pub(crate) fn derive(
        account: &str,
        rendered: &RenderedMessageView,
        preferences: Option<ReadingPreferences>,
        decision: &BrowserMessageListDecision,
        return_to: Option<&str>,
    ) -> Self {
        if let Some(value) = return_to {
            let Some((back, path, fields)) = origin(value) else {
                return Self::default();
            };
            if path != "/mailbox" || fields.get("q").is_some_and(|q| !q.is_empty()) {
                return Self::unavailable(Some(back));
            }
            let Ok(mut view) = ListViewState::from_query(&fields) else {
                return Self::unavailable(Some(back));
            };
            if !fields.contains_key("sort") && !fields.contains_key("dir") {
                let Some(preferences) = preferences else {
                    return Self::unavailable(Some(back));
                };
                view.apply_saved_reading_defaults(preferences);
            }
            return Self::derive_messages(
                account,
                rendered,
                decision,
                &view,
                &back,
                ReaderLocation::Standalone,
            );
        }
        let Some(preferences) = preferences else {
            return Self::default();
        };
        let back = format!("/mailbox?name={}", url_encode(&rendered.mailbox_name));
        let Some((_, _, fields)) = origin(&back) else {
            return Self::default();
        };
        let Ok(mut view) = ListViewState::from_query(&fields) else {
            return Self::default();
        };
        view.apply_saved_reading_defaults(preferences);
        let mut result = Self::derive_messages(
            account,
            rendered,
            decision,
            &view,
            &back,
            ReaderLocation::Standalone,
        );
        // Preserve the existing unscoped reader's Back default.
        result.back = None;
        result
    }

    pub(crate) fn derive_messages(
        account: &str,
        rendered: &RenderedMessageView,
        decision: &BrowserMessageListDecision,
        view: &ListViewState,
        return_to: &str,
        location: ReaderLocation,
    ) -> Self {
        let Some((back, path, fields)) = origin(return_to) else {
            return Self::default();
        };
        let unavailable = || Self::unavailable(Some(back.clone()));
        let BrowserMessageListDecision::Listed {
            canonical_username,
            mailbox_name,
            messages,
        } = decision
        else {
            return unavailable();
        };
        if path != "/mailbox"
            || fields.get("name") != Some(mailbox_name)
            || fields.get("q").is_some_and(|q| !q.is_empty())
            || !matching_view(&fields, view)
            || view.requested_version.as_ref().is_some_and(|version| {
                rendered.metadata.as_ref().map(|m| &m.version) != Some(version)
            })
            || account != canonical_username
            || rendered.mailbox_name != *mailbox_name
            || messages.is_empty()
            || messages.len() > DEFAULT_MAX_MESSAGES
            || messages.iter().any(|row| row.mailbox_name != *mailbox_name)
            || !valid_rows(messages.iter().map(|row| {
                (
                    row.mailbox_name.as_str(),
                    row.uid,
                    row.date_received.as_str(),
                    row.metadata.as_ref().map(|m| &m.version),
                )
            }))
        {
            return unavailable();
        }
        let mut rows = messages.clone();
        let mut ordered = selected_view(view, rendered);
        ordered.order_messages(&mut rows);
        if ordered.selected_version.as_ref() != rendered.metadata.as_ref().map(|m| &m.version)
            || ordered.selected_version.is_none()
        {
            return unavailable();
        }
        Self::from_ordered(
            rendered,
            &back,
            rows.iter()
                .map(|row| {
                    (
                        &row.mailbox_name,
                        row.uid,
                        row.metadata.as_ref().map(|m| &m.version),
                    )
                })
                .collect(),
            DEFAULT_MAX_MESSAGES,
            location,
        )
    }

    pub(crate) fn derive_search(
        account: &str,
        rendered: &RenderedMessageView,
        decision: &BrowserMessageSearchDecision,
        view: &ListViewState,
        return_to: &str,
        location: ReaderLocation,
    ) -> Self {
        let Some((back, path, fields)) = origin(return_to) else {
            return Self::default();
        };
        let unavailable = || Self::unavailable(Some(back.clone()));
        let BrowserMessageSearchDecision::Listed {
            canonical_username,
            mailbox_name,
            query,
            results,
        } = decision
        else {
            return unavailable();
        };
        let expected_scope = if fields.get("scope").map(String::as_str) == Some("all") {
            None
        } else {
            fields
                .get("mailbox")
                .filter(|name| !name.is_empty())
                .map(String::as_str)
        };
        if path != "/search"
            || fields.contains_key("category")
            || fields.get("q").map(|q| q.trim()) != Some(query.trim())
            || query.trim().is_empty()
            || expected_scope != mailbox_name.as_deref()
            || !matching_view(&fields, view)
            || view.requested_version.as_ref().is_some_and(|version| {
                rendered.metadata.as_ref().map(|m| &m.version) != Some(version)
            })
            || account != canonical_username
            || results.is_empty()
            || results.len() > DEFAULT_MAX_SEARCH_RESULTS
            || mailbox_name
                .as_ref()
                .is_some_and(|name| results.iter().any(|row| &row.mailbox_name != name))
            || !valid_rows(results.iter().map(|row| {
                (
                    row.mailbox_name.as_str(),
                    row.uid,
                    row.date_received.as_str(),
                    row.metadata.as_ref().map(|m| &m.version),
                )
            }))
        {
            return unavailable();
        }
        let mut rows: Vec<MessageSearchResult> = results.clone();
        let mut ordered = selected_view(view, rendered);
        ordered.order_search(&mut rows);
        if ordered.selected_version.as_ref() != rendered.metadata.as_ref().map(|m| &m.version)
            || ordered.selected_version.is_none()
        {
            return unavailable();
        }
        Self::from_ordered(
            rendered,
            &back,
            rows.iter()
                .map(|row| {
                    (
                        &row.mailbox_name,
                        row.uid,
                        row.metadata.as_ref().map(|m| &m.version),
                    )
                })
                .collect(),
            DEFAULT_MAX_SEARCH_RESULTS,
            location,
        )
    }

    fn from_ordered(
        rendered: &RenderedMessageView,
        back: &str,
        rows: Vec<(&String, u64, Option<&MessageVersion>)>,
        limit: usize,
        location: ReaderLocation,
    ) -> Self {
        let Some(index) = rows.iter().position(|(mailbox, uid, version)| {
            **mailbox == rendered.mailbox_name
                && *uid == rendered.uid
                && *version == rendered.metadata.as_ref().map(|m| &m.version)
        }) else {
            return Self::unavailable(Some(back.into()));
        };
        let link = |index: usize| {
            rows.get(index).and_then(|(mailbox, uid, version)| {
                let version = (*version)?;
                match location {
                    ReaderLocation::Standalone => {
                        let (_, path, mut fields) = origin(back)?;
                        fields.remove("opened_read");
                        let destination = format!(
                            "{path}?{}",
                            fields
                                .iter()
                                .map(|(key, value)| format!(
                                    "{}={}",
                                    url_encode(key),
                                    url_encode(value)
                                ))
                                .collect::<Vec<_>>()
                                .join("&")
                        );
                        Some(format!(
                    "/message?mailbox={}&uid={}&mailbox_guid={}&message_guid={}&return_to={}",
                    url_encode(mailbox), uid, url_encode(&version.mailbox_guid),
                    url_encode(&version.message_guid), url_encode(&destination)))
                    }
                    ReaderLocation::Coordinated => {
                        let (_, path, mut fields) = origin(back)?;
                        fields.remove("select");
                        fields.remove("opened_read");
                        fields.insert("selected_mailbox".into(), (*mailbox).clone());
                        fields.insert("selected_uid".into(), uid.to_string());
                        fields.insert("selected_mailbox_guid".into(), version.mailbox_guid.clone());
                        fields.insert("selected_message_guid".into(), version.message_guid.clone());
                        fields.insert("page".into(), (index / MESSAGE_PAGE_SIZE + 1).to_string());
                        let href = format!(
                            "{path}?{}",
                            fields
                                .iter()
                                .map(|(key, value)| format!(
                                    "{}={}",
                                    url_encode(key),
                                    url_encode(value)
                                ))
                                .collect::<Vec<_>>()
                                .join("&")
                        );
                        Some(format!(
                            "{}#reading-pane",
                            crate::mail_navigation::safe_mail_return(&href)?
                        ))
                    }
                }
            })
        };
        Self { back: Some(back.into()), previous: index.checked_sub(1).and_then(link),
            next: link(index + 1), open_on_select: false, scope: Some(format!(
                "Previous and Next follow this request's filtered and sorted result snapshot (up to {limit} messages). Mailbox contents can change between requests.")) }
    }

    pub(crate) fn set_open_on_select(&mut self, value: bool) {
        self.open_on_select = value;
    }

    pub(crate) fn controls_html_with_policy(&self, csrf: &str) -> String {
        let control = |href: &Option<String>, label: &str, symbol: &str| match href {
            Some(href) if !self.open_on_select => format!(
                "<a class=\"button-link\" aria-label=\"{label} message\" href=\"{}\">{symbol}</a>",
                escape_html(href)
            ),
            Some(href) => crate::http_ui::message_open_control(
                csrf,
                href,
                "button-link",
                symbol,
                false,
                self.open_on_select,
                Some(&format!("{label} message")),
            ),
            None => format!(
                "<button type=\"button\" aria-label=\"{label} message\" disabled>{symbol}</button>"
            ),
        };
        format!(
            "<nav class=\"reader-neighbours\" aria-label=\"Previous and next messages\">{}{}</nav>",
            control(&self.previous, "Previous", "←"),
            control(&self.next, "Next", "→")
        )
    }
    pub(crate) fn scope_html(&self) -> String {
        format!("<details class=\"reader-order-scope\"><summary>Loaded mailbox order</summary><p>{}</p></details>", escape_html(self.scope.as_deref().unwrap_or(
            "Navigation unavailable: the originating results, identities or bounded ordering could not be verified. Return to the list.")))
    }
    pub(crate) fn html_with_policy(&self, csrf: &str) -> String {
        format!(
            "{}{}",
            self.controls_html_with_policy(csrf),
            self.scope_html()
        )
    }
    #[cfg(test)]
    pub(crate) fn html(&self) -> String {
        self.html_with_policy("")
    }
}

fn selected_view(view: &ListViewState, rendered: &RenderedMessageView) -> ListViewState {
    let mut selected = view.clone();
    selected.selection = Some(ListSelection {
        mailbox: rendered.mailbox_name.clone(),
        uid: rendered.uid,
    });
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html::TrustedHtml;
    use crate::mailbox::MessageSummary;
    use crate::message_metadata::{MessageMetadata, MessageProtection};
    use crate::mime::MimeBodySource;
    use crate::rendering::RenderingMode;

    #[test]
    fn neighbour_controls_follow_server_open_policy_and_require_identity() {
        let mut neighbours = ReaderNeighbours {
            previous: Some(
                "/message?mailbox=INBOX&uid=7&mailbox_guid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&message_guid=message-7".into(),
            ),
            next: Some("/message?mailbox=INBOX&uid=8".into()),
            ..ReaderNeighbours::default()
        };
        assert_eq!(neighbours.html().matches("<a ").count(), 2);
        neighbours.set_open_on_select(true);
        let html = neighbours.html_with_policy("csrf&value");
        assert_eq!(html.matches("action=\"/message/open\"").count(), 1);
        assert!(html.contains("aria-label=\"Previous message\""));
        assert!(html.contains("aria-label=\"Next message\" dir=\"auto\" disabled"));
        assert!(html.contains("csrf&amp;value"));
        assert!(!html.contains("<a "));
    }

    #[test]
    fn moving_to_a_neighbour_does_not_reuse_opened_read_marker() {
        let current = row(7, "Alpha", false);
        let next = row(8, "Beta", false);
        let rows = vec![
            (
                &current.mailbox_name,
                current.uid,
                current.metadata.as_ref().map(|m| &m.version),
            ),
            (
                &next.mailbox_name,
                next.uid,
                next.metadata.as_ref().map(|m| &m.version),
            ),
        ];
        let back = "/mailbox?name=INBOX&filter=unread&selected_mailbox=INBOX&selected_uid=7&selected_mailbox_guid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&selected_message_guid=message-7&opened_read=1";
        for location in [ReaderLocation::Standalone, ReaderLocation::Coordinated] {
            let neighbours = ReaderNeighbours::from_ordered(
                &rendered(&current),
                back,
                rows.clone(),
                2000,
                location,
            );
            let href = neighbours.next.as_ref().expect("bounded next identity");
            let query = href
                .strip_suffix("#reading-pane")
                .unwrap_or(href)
                .split_once('?')
                .unwrap()
                .1;
            let fields = parse_urlencoded_form(
                query.as_bytes(),
                crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
                2048,
            )
            .unwrap();
            assert!(!fields.contains_key("opened_read"));
            assert!(href.contains("message-8"));
            assert!(neighbours.back.as_ref().unwrap().contains("opened_read=1"));
        }
    }

    fn row(uid: u64, subject: &str, starred: bool) -> MessageSummary {
        MessageSummary {
            to: None,
            metadata: Some(MessageMetadata {
                threading: None,
                version: MessageVersion::new("a".repeat(32), format!("message-{uid}"))
                    .expect("fixture identity"),
                attachment_count: Some(0),
                attachments: None,
                protection: MessageProtection::Plain,
                preview: None,
            }),
            mailbox_name: "INBOX".into(),
            uid,
            flags: if starred {
                vec!["\\Flagged".into()]
            } else {
                vec![]
            },
            date_received: "2026-09-30 00:00:00 +0000".into(),
            size_virtual: 10,
            subject: Some(subject.into()),
            from: Some("Sender <sender@example.test>".into()),
        }
    }

    fn rendered(row: &MessageSummary) -> RenderedMessageView {
        RenderedMessageView {
            openpgp: None,
            metadata: row.metadata.clone(),
            flags: row.flags.clone(),
            mailbox_name: row.mailbox_name.clone(),
            uid: row.uid,
            subject: row.subject.clone(),
            from: row.from.clone(),
            to: None,
            cc: None,
            reply_metadata: None,
            date_received: row.date_received.clone(),
            mime_top_level_content_type: "text/plain".into(),
            body_source: MimeBodySource::SinglePartPlainText,
            contains_html_body: false,
            body_html: TrustedHtml::from_template("<pre>Public fixture</pre>".into()),
            body_text_for_compose: "Public fixture".into(),
            attachments: vec![],
            rendering_mode: RenderingMode::PlainTextPreformatted,
        }
    }

    #[test]
    fn filtered_reader_neighbours_use_subject_order_and_exclude_unstarred_rows() {
        let current = row(10, "Zulu", true);
        let decision = BrowserMessageListDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: "INBOX".into(),
            messages: vec![
                row(9, "Middle", false),
                current.clone(),
                row(11, "Alpha", true),
            ],
        };
        let neighbours = ReaderNeighbours::derive(
            "alice@example.test",
            &rendered(&current),
            Some(ReadingPreferences::default()),
            &decision,
            Some("/mailbox?name=INBOX&filter=starred&sort=subject&dir=asc"),
        );
        assert!(neighbours
            .previous
            .as_deref()
            .is_some_and(|href| href.contains("uid=11&")));
        assert!(neighbours.next.is_none());
        assert!(!neighbours.html().contains("uid=9&amp;"));
    }

    fn view(back: &str) -> ListViewState {
        let (_, _, fields) = origin(back).expect("fixture origin");
        ListViewState::from_query(&fields).expect("fixture selectors")
    }

    fn link_fields(href: &str) -> BTreeMap<String, String> {
        let query = href
            .split_once('?')
            .expect("fixture link")
            .1
            .split('#')
            .next()
            .unwrap();
        parse_urlencoded_form(query.as_bytes(), 18, 2048).expect("fixture link fields")
    }

    #[test]
    fn coordinated_filtered_neighbours_cross_pages_and_pin_each_guid_pair() {
        let rows: Vec<_> = (1..=95)
            .map(|uid| row(uid, &format!("Subject {uid:03}"), true))
            .collect();
        let current = rendered(&rows[49]);
        let decision = BrowserMessageListDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: "INBOX".into(),
            messages: rows,
        };
        let back = "/mailbox?name=INBOX&filter=starred&sort=subject&dir=asc&page=1";
        let neighbours = ReaderNeighbours::derive_messages(
            "alice@example.test",
            &current,
            &decision,
            &view(back),
            back,
            ReaderLocation::Coordinated,
        );
        let previous = link_fields(neighbours.previous.as_deref().expect("preceding row"));
        let next = link_fields(neighbours.next.as_deref().expect("following row"));
        assert_eq!(previous.get("selected_uid").map(String::as_str), Some("49"));
        assert_eq!(previous.get("page").map(String::as_str), Some("1"));
        assert_eq!(next.get("selected_uid").map(String::as_str), Some("51"));
        assert_eq!(next.get("page").map(String::as_str), Some("2"));
        assert_eq!(next.get("selected_mailbox_guid"), Some(&"a".repeat(32)));
        assert_eq!(
            next.get("selected_message_guid").map(String::as_str),
            Some("message-51")
        );
        assert_eq!(next.get("filter").map(String::as_str), Some("starred"));
        assert_eq!(next.get("sort").map(String::as_str), Some("subject"));
        assert!(neighbours
            .next
            .as_deref()
            .unwrap()
            .ends_with("#reading-pane"));
    }

    #[test]
    fn search_neighbours_use_actual_query_scope_and_distinct_same_uid_folders() {
        let current = row(10, "Zulu", true);
        let mut sent = row(10, "Alpha", true);
        sent.mailbox_name = "Sent".into();
        sent.metadata.as_mut().unwrap().version =
            MessageVersion::new("b".repeat(32), "sent-copy".into()).unwrap();
        let results = [current.clone(), sent, row(11, "Middle", false)]
            .into_iter()
            .map(|row| MessageSearchResult {
                metadata: row.metadata,
                mailbox_name: row.mailbox_name,
                uid: row.uid,
                flags: row.flags,
                date_received: row.date_received,
                size_virtual: row.size_virtual,
                subject: row.subject,
                from: row.from,
            })
            .collect();
        let decision = BrowserMessageSearchDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: None,
            query: "report".into(),
            results,
        };
        let back = "/search?q=report&scope=all&filter=starred&sort=subject&dir=asc";
        let neighbours = ReaderNeighbours::derive_search(
            "alice@example.test",
            &rendered(&current),
            &decision,
            &view(back),
            back,
            ReaderLocation::Coordinated,
        );
        let previous = link_fields(
            neighbours
                .previous
                .as_deref()
                .expect("filtered search neighbour"),
        );
        assert_eq!(
            previous.get("selected_mailbox").map(String::as_str),
            Some("Sent")
        );
        assert_eq!(previous.get("selected_uid").map(String::as_str), Some("10"));
        assert_eq!(previous.get("selected_mailbox_guid"), Some(&"b".repeat(32)));
        assert_eq!(
            previous.get("selected_message_guid").map(String::as_str),
            Some("sent-copy")
        );
        assert_eq!(previous.get("q").map(String::as_str), Some("report"));
        assert!(neighbours.next.is_none());
        let standalone = ReaderNeighbours::derive_search(
            "alice@example.test",
            &rendered(&current),
            &decision,
            &view(back),
            back,
            ReaderLocation::Standalone,
        );
        assert_eq!(
            link_fields(standalone.previous.as_deref().unwrap())
                .get("mailbox")
                .map(String::as_str),
            Some("Sent")
        );
        let mut wrong = decision.clone();
        if let BrowserMessageSearchDecision::Listed { query, .. } = &mut wrong {
            *query = "different".into();
        }
        assert!(ReaderNeighbours::derive_search(
            "alice@example.test",
            &rendered(&current),
            &wrong,
            &view(back),
            back,
            ReaderLocation::Standalone
        )
        .previous
        .is_none());
        let list = BrowserMessageListDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: "INBOX".into(),
            messages: vec![current.clone(), row(9, "Other", true)],
        };
        let fallback = ReaderNeighbours::derive(
            "alice@example.test",
            &rendered(&current),
            Some(ReadingPreferences::default()),
            &list,
            Some(back),
        );
        assert!(fallback.previous.is_none() && fallback.next.is_none());
    }

    #[test]
    fn neighbour_snapshots_refuse_foreign_stale_duplicate_malformed_and_oversized_rows() {
        let current = row(10, "Middle", true);
        let good = BrowserMessageListDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: "INBOX".into(),
            messages: vec![
                row(9, "Alpha", true),
                current.clone(),
                row(11, "Zulu", true),
            ],
        };
        let back = "/mailbox?name=INBOX&filter=starred&sort=subject&dir=asc";
        for fault in 0..8 {
            let mut bad = good.clone();
            if let BrowserMessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
            } = &mut bad
            {
                match fault {
                    0 => *canonical_username = "bob@example.test".into(),
                    1 => *mailbox_name = "Sent".into(),
                    2 => {
                        messages[1].metadata.as_mut().unwrap().version.message_guid =
                            "replacement".into()
                    }
                    3 => messages.push(messages[0].clone()),
                    4 => messages[0].metadata = None,
                    5 => messages[0].date_received = "Unknown".into(),
                    6 => messages.resize(DEFAULT_MAX_MESSAGES + 1, messages[0].clone()),
                    _ => {
                        messages[0].metadata.as_mut().unwrap().version.mailbox_guid = "b".repeat(32)
                    }
                }
            }
            let result = ReaderNeighbours::derive_messages(
                "alice@example.test",
                &rendered(&current),
                &bad,
                &view(back),
                back,
                ReaderLocation::Coordinated,
            );
            assert!(
                result.previous.is_none() && result.next.is_none(),
                "fault {fault}"
            );
        }
        let mut mismatch = view(back);
        mismatch.filter = crate::mail_list::MessageFilter::Unread;
        assert!(ReaderNeighbours::derive_messages(
            "alice@example.test",
            &rendered(&current),
            &good,
            &mismatch,
            back,
            ReaderLocation::Standalone
        )
        .previous
        .is_none());
        let mut stale_request = view(back);
        stale_request.requested_version =
            Some(MessageVersion::new("a".repeat(32), "previous-object".into()).unwrap());
        assert!(ReaderNeighbours::derive_messages(
            "alice@example.test",
            &rendered(&current),
            &good,
            &stale_request,
            back,
            ReaderLocation::Standalone
        )
        .previous
        .is_none());
        let excluded = row(10, "Middle", false);
        let filtered = BrowserMessageListDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: "INBOX".into(),
            messages: vec![row(9, "Alpha", true), excluded.clone()],
        };
        assert!(ReaderNeighbours::derive_messages(
            "alice@example.test",
            &rendered(&excluded),
            &filtered,
            &view(back),
            back,
            ReaderLocation::Standalone
        )
        .next
        .is_none());
    }

    #[test]
    fn search_neighbours_preserve_complete_bounded_selector_and_identity_context() {
        let current = row(10, "Alpha", true);
        let next = row(11, "Zulu", true);
        let results = [current.clone(), next]
            .into_iter()
            .map(|row| MessageSearchResult {
                metadata: row.metadata,
                mailbox_name: row.mailbox_name,
                uid: row.uid,
                flags: row.flags,
                date_received: row.date_received,
                size_virtual: row.size_virtual,
                subject: row.subject,
                from: row.from,
            })
            .collect();
        let decision = BrowserMessageSearchDecision::Listed {
            canonical_username: "alice@example.test".into(),
            mailbox_name: None,
            query: "report".into(),
            results,
        };
        let back = format!("/search?mailbox=INBOX&q=report&scope=all&field=subject&sort=subject&dir=asc&filter=starred&attachment=without&pgp=plain&from=sender%40example.test&after=2026-09-30&before=2026-09-30&page=1&select=move&selected_mailbox=INBOX&selected_uid=10&selected_mailbox_guid={}&selected_message_guid=message-10", "a".repeat(32));
        let neighbours = ReaderNeighbours::derive_search(
            "alice@example.test",
            &rendered(&current),
            &decision,
            &view(&back),
            &back,
            ReaderLocation::Coordinated,
        );
        let next = link_fields(neighbours.next.as_deref().expect("full supported context"));
        for (key, value) in [
            ("mailbox", "INBOX"),
            ("q", "report"),
            ("scope", "all"),
            ("field", "subject"),
            ("sort", "subject"),
            ("dir", "asc"),
            ("filter", "starred"),
            ("attachment", "without"),
            ("pgp", "plain"),
            ("from", "sender@example.test"),
            ("after", "2026-09-30"),
            ("before", "2026-09-30"),
            ("selected_mailbox", "INBOX"),
            ("selected_uid", "11"),
            ("selected_message_guid", "message-11"),
        ] {
            assert_eq!(next.get(key).map(String::as_str), Some(value), "{key}");
        }
        assert!(!next.contains_key("select"));
        assert_eq!(next.len(), 17);
        assert_eq!(next.get("selected_mailbox_guid"), Some(&"a".repeat(32)));
    }
}
