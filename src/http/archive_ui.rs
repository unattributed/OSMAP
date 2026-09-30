// Archive/Bin presentation reuses the authenticated list and move contracts.
use super::*;

pub(super) fn row(
    message: &MessageSummary,
    selection: &str,
    href: &str,
    csrf: &str,
    return_to: &str,
    selected: bool,
) -> String {
    let date = if message.date_received.is_empty() {
        "Unavailable"
    } else {
        &message.date_received
    };
    format!("<tr data-selected=\"{selected}\"><td>{selection}</td><td data-label=\"From\" class=\"archive-sender\">{}</td><td data-label=\"Subject\"><a class=\"archive-subject\" href=\"{}\">{}</a></td><td data-label=\"Folder\">{}</td><td data-label=\"Received\">{}</td><td data-label=\"Size\">{} B</td><td><details class=\"archive-row-more\"><summary aria-label=\"Actions for message #{}\">⋮</summary><div>{}</div></details></td></tr>", escape_html(message.from.as_deref().unwrap_or("Sender unavailable")), escape_html(href), escape_html(message.subject.as_deref().unwrap_or("(No subject)")), escape_html(&message.mailbox_name), escape_html(date), message.size_virtual, message.uid, render_message_state_controls(csrf, &message.mailbox_name, message.uid, &message.flags, message.metadata.as_ref(), return_to))
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
}

pub(super) fn page(p: Page<'_>) -> TrustedHtml {
    let view = p.links.view;
    let is_bin = p.mailbox == "Trash";
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
            if !is_bin {
                " aria-current=\"page\""
            } else {
                ""
            }
        ),
        None => {
            "<a class=\"button-link\" href=\"/settings?section=copies\">Choose Archive folder</a>"
                .into()
        }
    };
    let bin = if is_bin
        || p.actions
            .move_destinations
            .iter()
            .any(|name| name == "Trash")
    {
        format!(
            "<a class=\"button-link\" href=\"{}\"{}>Bin</a>",
            tab_href("Trash"),
            if is_bin { " aria-current=\"page\"" } else { "" }
        )
    } else {
        "<button disabled>Bin unavailable</button>".into()
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
    let search = format!("<form class=\"archive-search\" action=\"/search\" method=\"get\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\">{}<label class=\"sr-only\" for=\"archive-search\">Search this folder</label><input id=\"archive-search\" name=\"q\" value=\"{}\" placeholder=\"Search {} messages…\"><button type=\"submit\">Search</button></form>", escape_html(p.mailbox), list_form_state(view), escape_html(p.links.search_query.unwrap_or("")), if is_bin { "Bin" } else { "archived" });
    let rows = if p.rows.is_empty() {
        "<tr><td colspan=\"7\">No messages match this view.</td></tr>"
    } else {
        p.rows
    };
    let reader = render_coordinated_reader(p.base, view, p.csrf, p.links.reader);
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell coordinated-mail archive-page{}\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>Archive / Bin</h1><p>Manage archived and deleted messages with reversible actions.</p></div><section class=\"content-pane coordinated-list\" aria-label=\"Archive and Bin messages\"><nav class=\"archive-tabs\" aria-label=\"Archive and Bin\">{archive}{bin}</nav>{}<div class=\"mail-list-toolbar\">{}{search}{navigation}{sort}</div><table class=\"archive-table\"><caption class=\"sr-only\">Messages in {}. Dates are received dates; archive dates are unavailable.</caption><thead><tr><th scope=\"col\"><span class=\"sr-only\">Select</span></th><th scope=\"col\">From</th><th scope=\"col\">Subject</th><th scope=\"col\">Folder</th><th scope=\"col\">Received</th><th scope=\"col\">Size</th><th scope=\"col\"><span class=\"sr-only\">Actions</span></th></tr></thead><tbody>{rows}</tbody></table><div class=\"archive-actions\">{}<button disabled aria-describedby=\"archive-retention\">Delete permanently</button></div><p id=\"archive-retention\" class=\"archive-retention\">Permanent deletion and retention management are unavailable. Bin moves messages to Trash; restore returns them to Inbox. To return archived messages, choose Inbox in Move selected to.</p></section>{reader}</main>", app_header(p.account, p.csrf, if is_bin { "bin" } else { "archive" }), if view.selection.is_some() { " has-selection" } else { "" }, p.banner, render_bulk_selection_menu(p.base, view, !p.actions.move_destinations.is_empty(), false), escape_html(p.mailbox), p.bulk_form))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            &message,
            "",
            "/message?mailbox=INBOX&uid=9",
            "csrf",
            "/mailbox?name=INBOX",
            false,
        );
        assert!(text.contains("&lt;img src=x&gt; &amp; subject"));
        assert!(text.contains("&lt;sender@example.test&gt;"));
        assert!(text.contains("INBOX.&lt;Archive&gt;"));
        assert!(text.contains("data-label=\"Received\">2026-09-30"));
        assert!(text.contains("data-label=\"Size\">512 B"));
        assert!(!text.contains("<img"));
        assert!(!text.contains("method=\"post\""));
        let unknown = MessageSummary {
            from: None,
            date_received: String::new(),
            ..message
        };
        let text = row(&unknown, "", "/message", "csrf", "/mailbox", false);
        assert!(text.contains("Sender unavailable"));
        assert!(text.contains("data-label=\"Received\">Unavailable"));
    }
}
