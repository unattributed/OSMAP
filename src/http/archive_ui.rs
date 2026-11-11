// Archive/Bin presentation reuses the authenticated list and move contracts.
use super::*;

pub(super) struct RowState {
    pub timezone: crate::timezone::FixedOffset,
    pub selected: bool,
    pub on_open: bool,
    pub kind: FolderView,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FolderView {
    Archive,
    Bin,
    Junk,
}

pub(super) fn row(
    known: (&MessageSummary, crate::archive_event::Date),
    selection: &str,
    href: &str,
    csrf: &str,
    return_to: &str,
    state: RowState,
    labels: &str,
) -> String {
    let (message, archived_at) = known;
    let archived = match archived_at {
        crate::archive_event::Date::Known(time) => crate::logging::format_unix_timestamp_utc(time),
        crate::archive_event::Date::Unknown => "Unknown".into(),
        crate::archive_event::Date::Unavailable => "Unavailable".into(),
    };
    let RowState {
        timezone,
        selected,
        on_open,
        kind,
    } = state;
    let date = if message.date_received.is_empty() {
        "Unavailable".into()
    } else {
        timezone.display_received(&message.date_received)
    };
    let subject = message_open_control(
        csrf,
        href,
        "archive-subject",
        message.subject.as_deref().unwrap_or("(No subject)"),
        selected,
        on_open,
        None,
    );
    let date_label = if kind == FolderView::Archive {
        "Archived"
    } else {
        "Received"
    };
    let delete = if kind == FolderView::Bin {
        message.metadata.as_ref().map(|metadata| format!("<a class=\"button-link\" href=\"/message/delete?mailbox={}&amp;uid={}&amp;mailbox_guid={}&amp;message_guid={}&amp;return_to={}\">Delete permanently</a>", url_encode(&message.mailbox_name), message.uid, url_encode(&metadata.version.mailbox_guid), url_encode(&metadata.version.message_guid), url_encode(return_to))).unwrap_or_default()
    } else {
        String::new()
    };
    format!("<tr data-selected=\"{selected}\"><td>{selection}</td><td data-label=\"From\" class=\"archive-sender\">{}</td><td data-label=\"Subject\">{subject}{labels}</td><td data-label=\"Folder\">{}</td><td data-label=\"{date_label}\">{}</td><td data-label=\"Size\">{} B</td><td><details class=\"archive-row-more\"><summary aria-label=\"Actions for message #{}\">⋮</summary><div><p>Received: <span data-label=\"Received\">{}</span></p>{}{delete}</div></details></td></tr>", escape_html(message.from.as_deref().unwrap_or("Sender unavailable")), escape_html(&message.mailbox_name), escape_html(if kind == FolderView::Archive { &archived } else { &date }), message.size_virtual, message.uid, escape_html(&date), render_message_state_controls(csrf, &message.mailbox_name, message.uid, &message.flags, message.metadata.as_ref(), return_to))
}

pub(super) struct Page<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub mailbox: &'a str,
    pub actions: &'a MessageListBulkActions<'a>,
    pub links: &'a MessageListSortLinks<'a>,
    pub base: &'a str,
    pub rows: &'a str,
    pub banner: &'a str,
    pub bulk_form: &'a str,
    pub automatic_selection_count: usize,
    pub kind: FolderView,
    pub junk_available: bool,
}

pub(super) fn page(p: Page<'_>) -> TrustedHtml {
    let view = p.links.view;
    let bin_name = p.links.reader.bin_mailbox_name.as_deref();
    let is_bin = p.kind == FolderView::Bin;
    let is_junk = p.kind == FolderView::Junk;
    let tab_href = |mailbox: &str| {
        let mut destination = view.clone();
        destination.selection = None;
        escape_html(&list_navigation_href(
            &format!("/mailbox?name={}", url_encode(mailbox)),
            &destination,
            1,
        ))
    };
    let archive = match p.actions.archive_mailbox_name {
        Some(name) => format!(
            "<a class=\"button-link\" href=\"{}\"{}>Archive</a>",
            tab_href(name),
            if p.kind == FolderView::Archive {
                " aria-current=\"page\""
            } else {
                ""
            }
        ),
        None if is_bin => String::new(),
        None => {
            "<a class=\"button-link\" href=\"/settings?section=copies\">Choose Archive folder</a>"
                .into()
        }
    };
    let bin = if bin_name.is_some_and(|name| {
        is_bin
            || p.actions
                .move_destinations
                .iter()
                .any(|target| target == name)
    }) {
        format!(
            "<a class=\"button-link\" href=\"{}\"{}>Trash</a>",
            tab_href(bin_name.unwrap_or("")),
            if is_bin { " aria-current=\"page\"" } else { "" }
        )
    } else {
        "<button disabled>Bin unavailable</button>".into()
    };
    let junk = if p.junk_available {
        format!(
            "<a class=\"button-link\" href=\"{}\"{}>Junk</a>",
            tab_href("Junk"),
            if is_junk {
                " aria-current=\"page\""
            } else {
                ""
            }
        )
    } else {
        "<button disabled>Junk unavailable</button>".into()
    };
    let mut navigation = render_list_navigation(p.base, view, true).replace(
        "aria-label=\"Sent filters\"",
        "aria-label=\"Archive and Bin filters\"",
    );
    navigation = navigation.replace(" messages · Page", " loaded matches · Page");
    let sort =
        render_mailbox_sort_controls(p.mailbox, view, p.links.search_query, p.links.search_scope);
    let sort = sort
        .replace("Sorted by Received descending", "Newest first")
        .replace("Sorted by Received ascending", "Oldest first");
    let search = format!("<form class=\"archive-search\" action=\"/search\" method=\"get\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\">{}<label class=\"sr-only\" for=\"archive-search\">Search this folder</label><input id=\"archive-search\" name=\"q\" value=\"{}\" placeholder=\"Search {} messages…\"><button type=\"submit\">Search</button></form>", escape_html(p.mailbox), list_form_state(view), escape_html(p.links.search_query.unwrap_or("")), match p.kind { FolderView::Archive => "archived", FolderView::Bin => "Trash", FolderView::Junk => "Junk" });
    let empty = format!("<tr><td colspan=\"7\">{}</td></tr>", mail_state_card("No messages", "No messages are shown in this folder view. Active filters and snoozed messages may limit the loaded results.", "/compose", "Compose", false));
    let rows = if p.rows.is_empty() { &empty } else { p.rows };
    let reader = render_coordinated_reader(p.base, view, p.csrf, p.links.reader, p.account);
    let (title, date_heading, caption, retention) = match p.kind {
        FolderView::Archive => ("Archive / Bin / Junk", "Archived", "Archived messages. Archived shows the known OSMAP action date; older messages may have no recorded action date.", "Move selected messages to another folder or Bin. Permanent deletion is available only in Trash."),
        FolderView::Bin => ("Trash", "Received", "Messages in your Trash. Date shows when the message was received.", "Restore returns selected messages to Inbox. Permanent deletion asks for confirmation and cannot be undone."),
        FolderView::Junk => ("Junk", "Received", "Messages in your Junk folder. Date shows when the message was received.", "Move selected messages to Inbox or another folder. Move to Bin before permanent deletion."),
    };
    let empty_trash = if is_bin {
        format!("<form class=\"empty-trash-control\" method=\"post\" action=\"/trash/empty/review\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"{}\"><button class=\"danger\" type=\"submit\">Empty trash</button></form>", escape_html(p.csrf), escape_html(p.mailbox), escape_html(&format!("/mailbox?name={}", url_encode(p.mailbox))))
    } else {
        String::new()
    };
    let selection = render_bulk_selection_menu(p.base, view, p.automatic_selection_count);
    let selection = if is_bin {
        selection
            .replace(
                "<details class=\"bulk-selection-menu\"><summary>Select messages</summary>",
                "<div class=\"bulk-selection-menu\">",
            )
            .replace("</details>", "</div>")
    } else {
        selection
    };
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell coordinated-mail archive-page{}\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>{title}</h1><p>Manage messages in this folder.</p>{empty_trash}</div><section class=\"content-pane coordinated-list\" aria-label=\"Archive, Bin and Junk messages\"><nav class=\"archive-tabs\" aria-label=\"Archive, Bin and Junk\">{archive}{bin}{junk}</nav>{}<div class=\"mail-list-toolbar\">{}{search}{navigation}{sort}</div><div class=\"archive-actions\">{}</div><table class=\"archive-table\"><caption class=\"sr-only\">{caption}</caption><thead><tr><th scope=\"col\"><span class=\"sr-only\">Select</span></th><th scope=\"col\">From</th><th scope=\"col\">Subject</th><th scope=\"col\">Folder</th><th scope=\"col\">{date_heading}</th><th scope=\"col\">Size</th><th scope=\"col\"><span class=\"sr-only\">Actions</span></th></tr></thead><tbody>{rows}</tbody></table><p id=\"archive-retention\" class=\"archive-retention\">{retention}</p></section>{reader}</main>", app_header(p.account, p.csrf, if is_bin { "bin" } else { "archive" }), if view.selection.is_some() { " has-selection" } else { "" }, p.banner, selection, p.bulk_form))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_metadata::{MessageMetadata, MessageProtection, MessageVersion};
    #[test]
    fn archive_rows_use_literal_owned_summary_fields_without_archived_date_claims() {
        let message = MessageSummary {
            mailbox_name: "INBOX.<Archive>".into(),
            uid: 9,
            flags: vec![],
            date_received: "2026-09-30".into(),
            size_virtual: 512,
            subject: Some("<img src=x> & subject".into()),
            from: Some("<sender@example.test>".into()),
            to: None,
            metadata: None,
        };
        let text = row(
            (&message, crate::archive_event::Date::Unknown),
            "",
            "/message?mailbox=INBOX&uid=9",
            "csrf",
            "/mailbox?name=INBOX",
            RowState {
                timezone: crate::timezone::FixedOffset::default(),
                selected: false,
                on_open: false,
                kind: FolderView::Archive,
            },
            "",
        );
        assert!(text.contains("&lt;img src=x&gt; &amp; subject"));
        assert!(text.contains("&lt;sender@example.test&gt;"));
        assert!(text.contains("INBOX.&lt;Archive&gt;"));
        assert!(text.contains("data-label=\"Received\">2026-09-30"));
        assert!(text.contains("data-label=\"Size\">512 B"));
        assert!(text.contains("data-label=\"Archived\">Unknown"));
        assert_eq!(text.matches("<td").count(), 7);
        assert!(!text.contains("<td data-label=\"Received\""));
        assert!(!text.contains("<img"));
        assert!(!text.contains("method=\"post\""));
        let unknown = MessageSummary {
            from: None,
            date_received: String::new(),
            ..message
        };
        let text = row(
            (&unknown, crate::archive_event::Date::Unknown),
            "",
            "/message",
            "csrf",
            "/mailbox",
            RowState {
                timezone: crate::timezone::FixedOffset::default(),
                selected: false,
                on_open: false,
                kind: FolderView::Archive,
            },
            "",
        );
        assert!(text.contains("Sender unavailable"));
        assert!(text.contains("data-label=\"Received\">Unavailable"));
        let known = row(
            (&unknown, crate::archive_event::Date::Known(1234)),
            "",
            "/message",
            "csrf",
            "/mailbox",
            RowState {
                timezone: crate::timezone::FixedOffset::default(),
                selected: false,
                on_open: false,
                kind: FolderView::Archive,
            },
            "",
        );
        assert!(known.contains("data-label=\"Received\">Unavailable"));
        assert!(known.contains("data-label=\"Archived\">1970-01-01T00:20:34Z"));
        let failed = row(
            (&unknown, crate::archive_event::Date::Unavailable),
            "",
            "/message",
            "csrf",
            "/mailbox",
            RowState {
                timezone: crate::timezone::FixedOffset::default(),
                selected: false,
                on_open: false,
                kind: FolderView::Archive,
            },
            "",
        );
        assert!(failed.contains("data-label=\"Archived\">Unavailable"));
    }

    #[test]
    fn junk_rows_show_received_date_without_bin_deletion() {
        let message = MessageSummary {
            mailbox_name: "Junk".into(),
            uid: 9,
            flags: vec![],
            date_received: "2026-09-30".into(),
            size_virtual: 512,
            subject: Some("<untrusted>".into()),
            from: Some("<sender@example.test>".into()),
            to: None,
            metadata: Some(MessageMetadata {
                threading: None,
                version: MessageVersion {
                    mailbox_guid: "1234567890abcdef1234567890abcdef".into(),
                    message_guid: "abcdef1234567890abcdef1234567890".into(),
                },
                attachment_count: Some(0),
                attachments: Some(vec![]),
                protection: MessageProtection::Plain,
                preview: None,
            }),
        };
        let text = row(
            (&message, crate::archive_event::Date::Known(1234)),
            "",
            "/message?mailbox=Junk&uid=9",
            "csrf",
            "/mailbox?name=Junk",
            RowState {
                timezone: crate::timezone::FixedOffset::default(),
                selected: false,
                on_open: false,
                kind: FolderView::Junk,
            },
            "",
        );
        assert!(text.contains("data-label=\"Received\">2026-09-30"));
        assert!(!text.contains("data-label=\"Archived\""));
        assert!(!text.contains("Delete permanently"));
        assert!(text.contains("&lt;untrusted&gt;"));
        assert!(text.contains("&lt;sender@example.test&gt;"));
        assert!(!text.contains("1970-01-01"));
    }
}
