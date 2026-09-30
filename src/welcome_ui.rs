//! PAGE-01 welcome surface. Only supplied mailbox identities are projected.
use super::*;

pub(crate) fn render_mailboxes_page(
    canonical_username: &str,
    csrf_token: &str,
    mailboxes: &[MailboxEntry],
    summaries: Option<&[MessageSummary]>,
    draft_count: Option<usize>,
) -> TrustedHtml {
    let has = |name: &str| mailboxes.iter().any(|mailbox| mailbox.name == name);
    let inbox = has("INBOX");
    let sent = has("Sent");
    let unread = summaries.map(|rows| {
        rows.iter()
            .filter(|row| !has_flag(&row.flags, "\\Seen"))
            .count()
    });
    let flagged = summaries.map(|rows| {
        rows.iter()
            .filter(|row| has_flag(&row.flags, "\\Flagged"))
            .count()
    });
    let mut metrics = String::new();
    for (label, icon, destination, count) in [
        (
            "Unread · loaded Inbox",
            "inbox",
            inbox.then_some("/mailbox?name=INBOX&filter=unread"),
            unread,
        ),
        ("Saved drafts", "drafts", Some("/drafts"), draft_count),
        ("Sent", "sent", sent.then_some("/mailbox?name=Sent"), None),
        (
            "Flagged · loaded Inbox",
            "folders",
            inbox.then_some("/mailbox?name=INBOX&filter=starred"),
            flagged,
        ),
    ] {
        let value = count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "Unknown".into());
        let contents = format!("<span class=\"welcome-icon\">{}</span><span><strong>{value}</strong><span>{label}</span></span>", shell_icon(icon));
        metrics.push_str(&if let Some(href) = destination {
            format!("<a class=\"welcome-metric\" href=\"{}\" aria-label=\"{label}: {value}; open list\">{contents}</a>", escape_html(href))
        } else { format!("<div class=\"welcome-metric\">{contents}</div>") });
    }
    let recent = recent_rows(summaries, inbox);
    let mut shortcuts = String::new();
    for (label, description, icon, href) in [
        ("Compose", "New message", "compose", Some("/compose")),
        (
            "Inbox",
            if inbox {
                "View messages"
            } else {
                "Mailbox unavailable"
            },
            "inbox",
            inbox.then_some("/mailbox?name=INBOX"),
        ),
        ("Documents", "Unavailable", "drafts", None),
        ("Security", "Manage sessions", "shield", Some("/sessions")),
        (
            "Settings",
            "Account & preferences",
            "settings",
            Some("/settings"),
        ),
    ] {
        // Archive / Bin occupies its approved position between Documents and Security.
        if label == "Security" {
            shortcuts.push_str(&format!("<details class=\"welcome-shortcut welcome-shortcut-menu\"><summary><span class=\"welcome-icon\">{}</span><span><strong>Archive / Bin</strong><span>Mailbox shortcuts</span></span></summary><div><a href=\"/mailbox/shortcut?kind=archive\">Open configured Archive</a>{}</div></details>", shell_icon("archive"), if has("Trash") { "<a href=\"/mailbox?name=Trash\">Open Bin</a>" } else { "<span>Bin mailbox unavailable</span>" }));
        }
        let content = format!("<span class=\"welcome-icon\">{}</span><span><strong>{label}</strong><span>{description}</span></span>", shell_icon(icon));
        shortcuts.push_str(&match href {
            Some(href) => format!("<a class=\"welcome-shortcut\" href=\"{href}\">{content}</a>"),
            None => format!("<div class=\"welcome-shortcut welcome-unavailable\" aria-disabled=\"true\">{content}</div>"),
        });
    }
    let mut folders = String::new();
    for mailbox in mailboxes.iter().take(DEFAULT_RENDERED_MAILBOXES_MAX) {
        folders.push_str(&format!("<li><a href=\"/mailbox?name={}\"><span class=\"welcome-folder-icon\">{}</span><strong>{}</strong><span class=\"welcome-folder-open\">Open mailbox <span aria-hidden=\"true\">→</span></span></a></li>", escape_html(&url_encode(&mailbox.name)), shell_icon(if mailbox.name == "INBOX" { "inbox" } else { "folders" }), escape_html(&mailbox.name)));
    }
    if folders.is_empty() {
        folders.push_str(
            "<li class=\"welcome-empty\">No visible mailboxes were returned for this account.</li>",
        );
    }
    let limit = if mailboxes.len() > DEFAULT_RENDERED_MAILBOXES_MAX {
        format!("<p class=\"welcome-note\">Mailbox list display limit reached: showing first {} of {} visible mailboxes.</p>", DEFAULT_RENDERED_MAILBOXES_MAX, mailboxes.len())
    } else {
        String::new()
    };
    let view_all = if inbox {
        "<a href=\"/mailbox?name=INBOX\">Open Inbox <span aria-hidden=\"true\">→</span></a>"
    } else {
        "<a href=\"#welcome-mailboxes\">Browse mailboxes</a>"
    };
    let mut system = String::new();
    for (label, icon) in [
        ("Mail server", "inbox"),
        ("OpenPGP", "shield"),
        ("Security services", "shield"),
        ("Backup", "archive"),
        ("System updates", "settings"),
    ] {
        system.push_str(&format!(
            "<li><span>{}{label}</span><span>Unknown</span></li>",
            shell_icon(icon)
        ));
    }
    let search = format!("<details class=\"welcome-search\"><summary>Search all mailboxes</summary><form class=\"search-row\" method=\"get\" action=\"/search\"><label for=\"mailbox-global-search\">Search all mailboxes<input id=\"mailbox-global-search\" type=\"text\" name=\"q\" autocomplete=\"off\" maxlength=\"256\" required></label>{}<button type=\"submit\">Search</button></form></details>", render_search_field_select(MessageSearchField::All));
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell welcome-page\" tabindex=\"-1\">",
        "<section class=\"welcome-intro\" aria-labelledby=\"mailboxes-title\"><div class=\"welcome-greeting\"><h1 id=\"mailboxes-title\">Welcome back.</h1><p>Choose a mailbox to get started.</p><p class=\"welcome-account\">Signed in as <strong>{account}</strong></p></div><div class=\"welcome-metrics\" aria-label=\"Message counts and scope\">{metrics}</div></section>",
        "<nav class=\"welcome-shortcuts\" aria-label=\"Workspace shortcuts\">{shortcuts}</nav>",
        "<div class=\"welcome-primary-grid\"><section class=\"welcome-panel welcome-messages\" aria-labelledby=\"welcome-messages-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-messages-title\">Recent Messages</h2>{view_all}</div>{recent}<details class=\"welcome-browse\"><summary id=\"welcome-mailboxes\">Browse your mailboxes</summary><div class=\"welcome-folder-scroll\" tabindex=\"0\" role=\"region\" aria-labelledby=\"welcome-mailboxes\"><ul>{folders}</ul></div>{limit}</details></section>",
        "<section class=\"welcome-panel welcome-account-security\" aria-labelledby=\"welcome-security-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-security-title\">Account Security</h2></div><div class=\"welcome-protection\">{shield}<div><strong>Protected by Default</strong><p>Remote images and active content are blocked.</p></div></div><div class=\"welcome-security-detail\"><h3>Authenticated session</h3><p>Password and TOTP were required at sign-in.</p><a href=\"/sessions\">Manage sessions <span aria-hidden=\"true\">→</span></a></div></section>",
        "<section class=\"welcome-panel welcome-openpgp\" aria-labelledby=\"welcome-openpgp-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-openpgp-title\">OpenPGP Status</h2></div><div class=\"welcome-key-state\">{shield}<div><strong>Unknown</strong><p>Account key status is unavailable here.</p></div></div><dl class=\"welcome-key-details\"><div><dt>Key fingerprint</dt><dd>Unavailable</dd></div><div><dt>Signing</dt><dd>Unknown</dd></div><div><dt>Encryption</dt><dd>Unknown</dd></div><div><dt>Encrypt-to-self</dt><dd>Unknown</dd></div></dl><button type=\"button\" disabled title=\"Key management is unavailable\">Manage Keys — unavailable</button></section></div>",
        "<div class=\"welcome-secondary-grid\"><section class=\"welcome-panel welcome-activity\" aria-labelledby=\"welcome-activity-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-activity-title\">Recent Activity</h2></div><div class=\"welcome-activity-empty\">{history}<h3>Activity history unavailable</h3><p>Sign-in history, key changes and account-recovery events are not available on this page.</p><a href=\"/sessions\">Review active sessions <span aria-hidden=\"true\">→</span></a></div></section>",
        "<div class=\"welcome-middle-stack\"><section class=\"welcome-panel welcome-actions\" aria-labelledby=\"welcome-actions-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-actions-title\">Quick Actions</h2></div><div class=\"welcome-action-grid\"><a href=\"/search\">{search_icon}<strong>Search</strong><span>Find messages</span></a><a href=\"{filter_target}\">{filter_icon}<strong>Filters</strong><span>{filter_description}</span></a><span aria-disabled=\"true\">{label_icon}<strong>Labels</strong><span>Unavailable</span></span><details><summary>{more_icon}<strong>More</strong><span>Available tools</span></summary><div><a href=\"/contacts\">Contacts</a><a href=\"/sessions\">Sessions</a><a href=\"/drafts\">Saved drafts</a></div></details></div>{search}</section>",
        "<section class=\"welcome-panel welcome-storage\" aria-labelledby=\"welcome-storage-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-storage-title\">Storage Usage</h2></div><div class=\"welcome-storage-body\"><div><strong>Usage and quota unknown</strong><p>Mailbox, document and other storage totals are unavailable.</p></div><button type=\"button\" disabled>Manage Storage</button></div></section></div>",
        "<section class=\"welcome-panel welcome-system\" aria-labelledby=\"welcome-system-title\"><div class=\"welcome-panel-heading\"><h2 id=\"welcome-system-title\">System Status</h2></div><ul>{system}</ul><p class=\"welcome-note\">Service health and backup results are unavailable here.</p></section></div>",
        "<footer class=\"welcome-footer\"><span>OSMAP · Secure by Design. Private by Default.</span><span>System health unavailable</span><span aria-disabled=\"true\">Help unavailable</span><span aria-disabled=\"true\">Feedback unavailable</span></footer></main>"
    ), header=app_header(canonical_username,csrf_token,"mailboxes"), account=escape_html(canonical_username), metrics=metrics, recent=recent, shortcuts=shortcuts, view_all=view_all, folders=folders, limit=limit, shield=shell_icon("shield"), history=shell_icon("folders"), search_icon=shell_icon("search"), filter_icon=shell_icon("inbox"), label_icon=shell_icon("drafts"), more_icon=shell_icon("menu"), filter_target=if inbox { "/mailbox?name=INBOX&filter=unread" } else { "/search" }, filter_description=if inbox { "Unread in Inbox" } else { "Search mail" }, search=search, system=system))
}

fn recent_rows(summaries: Option<&[MessageSummary]>, inbox: bool) -> String {
    let Some(rows) = summaries else {
        return format!(
            "<p class=\"welcome-note\">{}</p>",
            if inbox {
                "Inbox summaries are unavailable. Open Inbox to try again."
            } else {
                "Inbox is unavailable for this account."
            }
        );
    };
    let mut html = format!("<p class=\"welcome-note\">Newest from {} loaded Inbox messages. Counts cover this loaded set; additional messages may exist.</p>", rows.len());
    if rows.is_empty() {
        html.push_str("<p class=\"welcome-empty\">No messages were returned from Inbox.</p>");
    }
    html.push_str("<ul class=\"welcome-recent\">");
    for row in rows.iter().take(5) {
        let mut href = format!("/message?mailbox=INBOX&uid={}", row.uid);
        if let Some(metadata) = &row.metadata {
            href.push_str(&format!(
                "&mailbox_guid={}&message_guid={}",
                url_encode(&metadata.version.mailbox_guid),
                url_encode(&metadata.version.message_guid)
            ));
        }
        let sender = row.from.as_deref().unwrap_or("Sender unavailable");
        let subject = row
            .subject
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("(No subject)");
        html.push_str(&format!("<li><a class=\"welcome-recent-link{}\" href=\"{}\"><span class=\"message-avatar\" aria-hidden=\"true\">{}</span><span class=\"welcome-recent-sender\" title=\"{}\">{}</span><span class=\"welcome-recent-subject\" title=\"{}\">{}</span><span class=\"welcome-recent-date\" title=\"{}\">{}</span><span class=\"welcome-recent-flags\"><span class=\"sr-only\">{}</span><span aria-label=\"{}\">{}</span></span></a></li>", if has_flag(&row.flags,"\\Seen") { "" } else { " welcome-unread" }, escape_html(&href), escape_html(&sender_initials(row.from.as_deref())), escape_html(sender), escape_html(sender), escape_html(subject), escape_html(subject), escape_html(&row.date_received), escape_html(row.date_received.split_whitespace().next().unwrap_or("Date unavailable")), if has_flag(&row.flags,"\\Seen") { "Read. " } else { "Unread. " }, if has_flag(&row.flags,"\\Flagged") { "Flagged" } else { "Not flagged" }, if has_flag(&row.flags,"\\Flagged") { "★" } else { "☆" }));
    }
    html.push_str("</ul>");
    html
}
