//! Server-rendered browser HTML helpers for the current OSMAP web slice.
//!
//! Keeping these rendering helpers separate from routing reduces the amount of
//! browser-facing template code inside the request parser and route logic.

use crate::draft::DraftSummary;
use crate::html::TrustedHtml;
use crate::http::BrowserVisibleSession;
use crate::http_support::{escape_html, url_encode};
use crate::mailbox::{
    MailboxEntry, MessageSearchField, MessageSearchResult, MessageSort, MessageSortColumn,
    MessageSortDirection, MessageSummary, DEFAULT_MAX_MAILBOXES, DEFAULT_MAX_SEARCH_RESULTS,
};
use crate::mime::{AttachmentMetadata, DEFAULT_MIME_PARTS_MAX};
use crate::rendering::{HtmlDisplayPreference, RenderedMessageView};

/// Defense-in-depth cap for attachment metadata rows rendered by one route.
const DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX: usize = DEFAULT_MIME_PARTS_MAX;

/// Defense-in-depth cap for mailbox links rendered by one route.
const DEFAULT_RENDERED_MAILBOXES_MAX: usize = DEFAULT_MAX_MAILBOXES;

/// Small view model for the current server-rendered compose page.
pub(crate) struct ComposePageModel<'a> {
    pub heading: &'a str,
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub success_message: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub context_notice: Option<&'a str>,
    pub to_value: &'a str,
    pub cc_value: &'a str,
    pub bcc_value: &'a str,
    pub subject_value: &'a str,
    pub body_value: &'a str,
    pub draft_id: Option<&'a str>,
    pub draft_attachment_count: usize,
    pub source_mailbox_name: Option<&'a str>,
    pub source_uid: Option<u64>,
    pub source_attachments: &'a [AttachmentMetadata],
    pub selected_source_part_paths: &'a [String],
}

/// Small view model for the draft list page.
pub(crate) struct DraftListPageModel<'a> {
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub success_message: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub drafts: &'a [DraftSummary],
}

/// Small view model for mailbox message-list sort links.
pub(crate) struct MessageListSortLinks<'a> {
    pub active_sort: Option<MessageSort>,
    pub search_query: Option<&'a str>,
    pub search_scope: Option<&'a str>,
}

/// Small view model for bounded selected-message mailbox actions.
pub(crate) struct MessageListBulkActions<'a> {
    pub archive_mailbox_name: Option<&'a str>,
    pub move_destinations: &'a [String],
}

/// Small view model for the first bounded settings page.
pub(crate) struct SettingsPageModel<'a> {
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub success_message: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub html_display_preference: HtmlDisplayPreference,
    pub archive_mailbox_name: Option<&'a str>,
}

fn logout_form(csrf_token: &str) -> String {
    format!(
        "<form class=\"logout-form\" method=\"post\" action=\"/logout\" aria-label=\"Sign out of current session\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button class=\"logout-button\" type=\"submit\">Log Out</button></form>",
        escape_html(csrf_token)
    )
}

fn app_header(canonical_username: &str, csrf_token: &str, current: &str) -> String {
    format!(
        concat!(
            "<a class=\"skip-link\" href=\"#main-content\">Skip to content</a>",
            "<header class=\"topbar\" role=\"banner\" aria-label=\"Authenticated OSMAP shell\">",
            "<div class=\"brand\"><span class=\"brand-mark\" aria-hidden=\"true\"><span class=\"ui-icon brand-icon\">OS</span></span><span>OSMAP</span></div>",
            "<nav class=\"top-actions\" aria-label=\"Primary navigation\">",
            "<a href=\"/mailboxes\"{}>Mailboxes</a>",
            "<a href=\"/compose\"{}>Compose</a>",
            "<a href=\"/drafts\"{}>Drafts</a>",
            "<a href=\"/sessions\"{}>Sessions</a>",
            "<a href=\"/settings\"{}>Settings</a>",
            "{}",
            "</nav>",
            "<div class=\"status-row auth-status\" aria-label=\"Session status and identity\">",
            "<span class=\"status-pill badge-ok shell-session-chip\">2FA session</span>",
            "<span class=\"status-pill identity-chip\">signed in as <strong>{}</strong></span>",
            "</div>",
            "</header>"
        ),
        if current == "mailboxes" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "compose" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "drafts" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "sessions" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "settings" {
            " aria-current=\"page\""
        } else {
            ""
        },
        logout_form(csrf_token),
        escape_html(canonical_username),
    )
}

fn folder_pane(mailboxes: &[MailboxEntry], current_mailbox_name: Option<&str>) -> String {
    let mut items = String::new();
    for mailbox in mailboxes.iter().take(DEFAULT_RENDERED_MAILBOXES_MAX) {
        let mailbox_href = format!("/mailbox?name={}", url_encode(&mailbox.name));
        let current = if current_mailbox_name == Some(mailbox.name.as_str()) {
            " aria-current=\"page\""
        } else {
            ""
        };
        items.push_str(&format!(
            "<li><a href=\"{}\"{}>{}</a></li>",
            escape_html(&mailbox_href),
            current,
            escape_html(&mailbox.name),
        ));
    }
    if mailboxes.len() > DEFAULT_RENDERED_MAILBOXES_MAX {
        items.push_str(&format!(
            "<li class=\"muted\">Mailbox list display limit reached: showing first {} of {} visible mailboxes.</li>",
            DEFAULT_RENDERED_MAILBOXES_MAX,
            mailboxes.len(),
        ));
    }

    format!(
        "<aside class=\"folder-pane\" aria-label=\"Mail folders\"><h2>Folders</h2><ul class=\"folder-list\">{}</ul></aside>",
        items,
    )
}

/// Renders the current login page with an optional operator-safe error banner.
pub(crate) fn render_login_page(error_message: Option<&str>) -> TrustedHtml {
    let banner = match error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Sign-in failed.</strong> {}</div>",
            escape_html(error_message)
        ),
        None => String::new(),
    };

    TrustedHtml::from_template(format!(
        concat!(
            "<main class=\"login-page\" aria-labelledby=\"login-title\">",
            "<div class=\"login-decor login-decor-left\" aria-hidden=\"true\"><svg viewBox=\"0 0 420 420\"><g fill=\"none\" stroke=\"currentColor\"><ellipse cx=\"190\" cy=\"315\" rx=\"190\" ry=\"42\" transform=\"rotate(-24 190 315)\" opacity=\".08\"/><circle cx=\"210\" cy=\"210\" r=\"130\" opacity=\".22\"/><circle cx=\"210\" cy=\"210\" r=\"165\" stroke-dasharray=\"2 7\" opacity=\".28\"/><path d=\"M210 98 296 132v74c0 62-31 104-86 132-55-28-86-70-86-132v-74l86-34Z\" opacity=\".14\"/><path d=\"M210 122 273 148v58c0 47-22 78-63 101-41-23-63-54-63-101v-58l63-26Z\" opacity=\".17\"/></g><rect x=\"172\" y=\"197\" width=\"76\" height=\"64\" rx=\"12\" fill=\"currentColor\" opacity=\".16\"/><path d=\"M184 198v-26a26 26 0 0 1 52 0v26\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"9\" opacity=\".18\"/><circle cx=\"210\" cy=\"225\" r=\"7\" fill=\"#fff\" opacity=\".85\"/><path d=\"M207 230h6l4 20h-14l4-20Z\" fill=\"#fff\" opacity=\".85\"/><circle cx=\"99\" cy=\"111\" r=\"5\" fill=\"currentColor\" opacity=\".38\"/><circle cx=\"314\" cy=\"102\" r=\"4\" fill=\"currentColor\" opacity=\".3\"/><circle cx=\"121\" cy=\"314\" r=\"4\" fill=\"currentColor\" opacity=\".38\"/><circle cx=\"331\" cy=\"290\" r=\"4\" fill=\"currentColor\" opacity=\".32\"/></svg></div>",
            "<div class=\"login-decor login-decor-right\" aria-hidden=\"true\"><svg viewBox=\"0 0 320 320\"><g fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\"><path d=\"M83 28 124 52v48l-41 24-41-24V52l41-24Z\" opacity=\".28\"/><path d=\"M165 78 206 102v48l-41 24-41-24v-48l41-24Z\" opacity=\".24\"/><path d=\"M247 78 288 102v48l-41 24-41-24v-48l41-24Z\" opacity=\".2\"/><path d=\"M83 170 124 194v48l-41 24-41-24v-48l41-24Z\" opacity=\".22\"/><path d=\"M165 220 206 244v48l-41 24-41-24v-48l41-24Z\" opacity=\".18\"/><path d=\"M247 220 288 244v48l-41 24-41-24v-48l41-24Z\" opacity=\".14\"/><path d=\"M124 76h41M206 126h41M124 218h41\" opacity=\".14\"/><path d=\"M288 22v80M42 52V5\" opacity=\".08\"/></g><g fill=\"currentColor\"><circle cx=\"83\" cy=\"28\" r=\"4\" opacity=\".32\"/><circle cx=\"124\" cy=\"52\" r=\"4\" opacity=\".28\"/><circle cx=\"165\" cy=\"78\" r=\"4\" opacity=\".26\"/><circle cx=\"206\" cy=\"102\" r=\"4\" opacity=\".22\"/><circle cx=\"247\" cy=\"78\" r=\"4\" opacity=\".2\"/><circle cx=\"288\" cy=\"102\" r=\"4\" opacity=\".18\"/><circle cx=\"83\" cy=\"266\" r=\"4\" opacity=\".2\"/><circle cx=\"165\" cy=\"316\" r=\"4\" opacity=\".14\"/></g></svg></div>",
            "<section class=\"login-card\">",
            "<div class=\"login-brand\">",
            "<svg class=\"login-shield\" aria-hidden=\"true\" viewBox=\"0 0 64 72\" role=\"img\"><path d=\"M32 4 56 13v18c0 17-9 29-24 37C17 60 8 48 8 31V13L32 4Z\" fill=\"#eaf2ff\" stroke=\"#9db9ee\" stroke-width=\"2\"/><path d=\"M32 10 49 17v14c0 12-6 22-17 29C21 53 15 43 15 31V17l17-7Z\" fill=\"#2f66d8\"/><circle cx=\"32\" cy=\"31\" r=\"7\" fill=\"#fff\"/><path d=\"M29 37h6l2 14H27l2-14Z\" fill=\"#fff\"/></svg>",
            "<div class=\"login-brand-text\"><h1 id=\"login-title\" class=\"login-title\">OSMAP</h1><p class=\"login-subtitle\">Secure Webmail</p></div>",
            "</div>",
            "<div class=\"login-rule\" aria-hidden=\"true\"><svg viewBox=\"0 0 24 24\"><path d=\"M12 3 19 6v5c0 5-2.6 8.5-7 10-4.4-1.5-7-5-7-10V6l7-3Z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"/></svg></div>",
            "<h2 class=\"login-kicker\">Sign in securely</h2>",
            "<p class=\"login-helper\">Access your protected mailbox with two-factor authentication.</p>",
            "{}",
            "<form class=\"login-form\" method=\"post\" action=\"/login\" aria-describedby=\"login-help\">",
            "<div class=\"login-field\"><label for=\"login-username\">Username or Email</label><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\"><path d=\"M20 21a8 8 0 0 0-16 0\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><circle cx=\"12\" cy=\"7\" r=\"4\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg><input id=\"login-username\" type=\"text\" name=\"username\" autocomplete=\"username\" placeholder=\"Enter your username or email\"></div>",
            "<div class=\"login-field\"><label for=\"login-password\">Password</label><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\"><rect x=\"5\" y=\"10\" width=\"14\" height=\"10\" rx=\"2\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><path d=\"M8 10V7a4 4 0 0 1 8 0v3\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg><input id=\"login-password\" type=\"password\" name=\"password\" autocomplete=\"current-password\" placeholder=\"Enter your password\"></div>",
            "<div class=\"login-field\"><label for=\"login-totp\">TOTP Code</label><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\"><path d=\"M12 3 19 6v5c0 5-2.6 8.5-7 10-4.4-1.5-7-5-7-10V6l7-3Z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><path d=\"m9 12 2 2 4-5\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg><input id=\"login-totp\" type=\"text\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" placeholder=\"Enter 6-digit code from authenticator\"></div>",
            "<button class=\"primary-button\" type=\"submit\"><svg class=\"login-lock\" aria-hidden=\"true\" viewBox=\"0 0 24 24\"><rect x=\"5\" y=\"10\" width=\"14\" height=\"10\" rx=\"2\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><path d=\"M8 10V7a4 4 0 0 1 8 0v3\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg>Sign In</button>",
            "<p id=\"login-help\" class=\"login-help\">Password and TOTP are both required.</p>",
            "</form>",
            "<div class=\"security-grid\" aria-label=\"Security indicators\">",
            "<div class=\"security-item\"><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\"><rect x=\"5\" y=\"10\" width=\"14\" height=\"10\" rx=\"2\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><path d=\"M8 10V7a4 4 0 0 1 8 0v3\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg><div><strong>TLS Protected</strong><span>Encrypted in transit</span></div></div>",
            "<div class=\"security-item\"><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\"><path d=\"M12 3 19 6v5c0 5-2.6 8.5-7 10-4.4-1.5-7-5-7-10V6l7-3Z\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><path d=\"m9 12 2 2 4-5\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg><div><strong>2FA Required</strong><span>Password plus TOTP</span></div></div>",
            "<div class=\"security-item\"><svg aria-hidden=\"true\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"9\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/><path d=\"m8 12 3 3 5-6\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\"/></svg><div><strong>Session Secured</strong><span>Protected cookies</span></div></div>",
            "</div>",
            "</section>",
            "<footer class=\"login-footer\"><p><span class=\"login-seal\" aria-hidden=\"true\">OB</span>OSMAP is powered by OpenBSD-first security principles.</p><p>Respect your privacy. Protect your data.</p></footer>",
            "</main>"
        ),
        banner,
    ))
}

/// Renders the mailbox home page for the validated user.
pub(crate) fn render_mailboxes_page(
    canonical_username: &str,
    csrf_token: &str,
    mailboxes: &[MailboxEntry],
) -> TrustedHtml {
    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<div class=\"mail-shell\">",
            "{}",
            "<section class=\"content-pane\" aria-labelledby=\"mailboxes-title\">",
            "<div class=\"section-header\"><div><h1 id=\"mailboxes-title\" class=\"section-title\">Mailboxes</h1><p class=\"muted\">Choose a visible mailbox, compose a message, or run a bounded backend search.</p></div>",
            "<div class=\"badge-list\"><span class=\"badge badge-ok\">2FA active</span><span class=\"badge\">mail access bounded by helper policy</span></div></div>",
            "<form class=\"search-row\" method=\"get\" action=\"/search\">",
            "<label for=\"mailbox-global-search\">Search all mailboxes<input id=\"mailbox-global-search\" type=\"text\" name=\"q\" autocomplete=\"off\"></label>",
            "{}",
            "<button type=\"submit\">Search</button>",
            "</form>",
            "<div class=\"notice\"><strong>Security posture:</strong> Remote content is not loaded by the browser, message rendering remains server-side, and state-changing actions stay CSRF-bound.</div>",
            "</section>",
            "</div>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        folder_pane(mailboxes, None),
        render_search_field_select(MessageSearchField::All),
    ))
}

const MESSAGE_SORT_COLUMNS: [MessageSortColumn; 6] = [
    MessageSortColumn::Uid,
    MessageSortColumn::Subject,
    MessageSortColumn::From,
    MessageSortColumn::Received,
    MessageSortColumn::Flags,
    MessageSortColumn::Size,
];

const MESSAGE_SEARCH_FIELDS: [MessageSearchField; 3] = [
    MessageSearchField::All,
    MessageSearchField::Subject,
    MessageSearchField::From,
];

fn message_sort_indicator(
    column: MessageSortColumn,
    active_sort: Option<MessageSort>,
) -> &'static str {
    match active_sort {
        Some(sort) if sort.column == column && sort.direction == MessageSortDirection::Asc => " ↑",
        Some(sort) if sort.column == column && sort.direction == MessageSortDirection::Desc => " ↓",
        _ => "",
    }
}

fn next_message_sort_direction(
    column: MessageSortColumn,
    active_sort: Option<MessageSort>,
) -> MessageSortDirection {
    match active_sort {
        Some(sort) if sort.column == column => sort.direction.toggled(),
        _ => column.default_direction(),
    }
}

fn render_mailbox_sort_headers(
    mailbox_name: &str,
    active_sort: Option<MessageSort>,
    search_query: Option<&str>,
    search_scope: Option<&str>,
) -> String {
    MESSAGE_SORT_COLUMNS
        .iter()
        .map(|column| {
            let direction = next_message_sort_direction(*column, active_sort);
            let mut href = format!("/mailbox?name={}", url_encode(mailbox_name));
            if let Some(query) = search_query {
                href.push_str("&q=");
                href.push_str(&url_encode(query));
            }
            if let Some(scope) = search_scope {
                href.push_str("&scope=");
                href.push_str(&url_encode(scope));
            }
            href.push_str("&sort=");
            href.push_str(column.query_value());
            href.push_str("&dir=");
            href.push_str(direction.query_value());

            format!(
                "<th><a href=\"{}\">{}{}</a></th>",
                escape_html(&href),
                column.label(),
                message_sort_indicator(*column, active_sort),
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_search_sort_headers(
    mailbox_name: Option<&str>,
    query: &str,
    active_sort: Option<MessageSort>,
    search_field: MessageSearchField,
) -> String {
    let mut headers = String::new();
    for column in MESSAGE_SORT_COLUMNS {
        let direction = next_message_sort_direction(column, active_sort);
        let mut href = String::from("/search?");
        if let Some(mailbox_name) = mailbox_name {
            href.push_str("mailbox=");
            href.push_str(&url_encode(mailbox_name));
            href.push('&');
        } else {
            href.push_str("scope=all&");
        }
        href.push_str("q=");
        href.push_str(&url_encode(query));
        href.push_str("&field=");
        href.push_str(search_field.query_value());
        href.push_str("&sort=");
        href.push_str(column.query_value());
        href.push_str("&dir=");
        href.push_str(direction.query_value());

        headers.push_str(&format!(
            "<th><a href=\"{}\">{}{}</a></th>",
            escape_html(&href),
            column.label(),
            message_sort_indicator(column, active_sort),
        ));
        if column == MessageSortColumn::Uid {
            headers.push_str("<th>Mailbox</th>");
        }
    }
    headers
}

fn render_search_field_select(active_field: MessageSearchField) -> String {
    let mut options = String::new();
    for field in MESSAGE_SEARCH_FIELDS {
        let selected = if field == active_field {
            " selected"
        } else {
            ""
        };
        options.push_str(&format!(
            "<option value=\"{}\"{}>{}</option>",
            field.query_value(),
            selected,
            escape_html(field.label()),
        ));
    }

    format!(
        "<label for=\"search-field\">Search field<select id=\"search-field\" name=\"field\">{}</select></label>",
        options
    )
}

/// Renders the message-list page for one mailbox.
pub(crate) fn render_message_list_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: &str,
    messages: &[MessageSummary],
    success_message: Option<&str>,
    bulk_actions: MessageListBulkActions<'_>,
    sort_links: MessageListSortLinks<'_>,
) -> TrustedHtml {
    let success_banner = match success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Update complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let mut rows = String::new();
    let archive_actions_available = bulk_actions
        .archive_mailbox_name
        .is_some_and(|archive_mailbox_name| archive_mailbox_name != mailbox_name);
    let bulk_actions_available = !bulk_actions.move_destinations.is_empty();
    for message in messages {
        let message_href = format!(
            "/message?mailbox={}&uid={}",
            url_encode(mailbox_name),
            message.uid
        );
        let archive_action = if let Some(archive_mailbox_name) = bulk_actions.archive_mailbox_name {
            if archive_mailbox_name != mailbox_name {
                format!(
                    "<form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"{}\"><button type=\"submit\">Archive</button></form>",
                    escape_html(csrf_token),
                    escape_html(mailbox_name),
                    message.uid,
                    escape_html(archive_mailbox_name),
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let selection_cells = match (bulk_actions_available, archive_actions_available) {
            (true, true) => format!(
                "<td><input form=\"bulk-move-form\" type=\"checkbox\" name=\"uid_{}\" value=\"{}\"></td><td><input form=\"bulk-archive-form\" type=\"checkbox\" name=\"uid_{}\" value=\"{}\"></td>",
                message.uid, message.uid, message.uid, message.uid
            ),
            (true, false) => format!(
                "<td><input form=\"bulk-move-form\" type=\"checkbox\" name=\"uid_{}\" value=\"{}\"></td>",
                message.uid, message.uid
            ),
            (false, true) => format!(
                "<td><input form=\"bulk-archive-form\" type=\"checkbox\" name=\"uid_{}\" value=\"{}\"></td>",
                message.uid, message.uid
            ),
            (false, false) => String::new(),
        };
        rows.push_str(&format!(
            "<tr>{}<td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>{}</tr>",
            selection_cells,
            escape_html(&message_href),
            message.uid,
            escape_html(message.subject.as_deref().unwrap_or("<none>")),
            escape_html(message.from.as_deref().unwrap_or("<none>")),
            escape_html(&message.date_received),
            escape_html(&message.flags.join(" ")),
            message.size_virtual,
            if archive_actions_available {
                format!("<td>{archive_action}</td>")
            } else {
                String::new()
            },
        ));
    }
    let bulk_move_form = if bulk_actions_available && !messages.is_empty() {
        let destination_options = bulk_actions
            .move_destinations
            .iter()
            .map(|destination| {
                format!(
                    "<option value=\"{}\">{}</option>",
                    escape_html(destination),
                    escape_html(destination)
                )
            })
            .collect::<Vec<_>>()
            .join("");
        format!(
            "<form id=\"bulk-move-form\" method=\"post\" action=\"/messages/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><label for=\"bulk-destination-mailbox\">Move selected to<select id=\"bulk-destination-mailbox\" name=\"destination_mailbox\">{}</select></label><button type=\"submit\">Move Selected</button></form>",
            escape_html(csrf_token),
            escape_html(mailbox_name),
            destination_options,
        )
    } else {
        String::new()
    };
    let bulk_archive_form = if archive_actions_available && !messages.is_empty() {
        let archive_mailbox_name = bulk_actions.archive_mailbox_name.unwrap_or_default();
        format!(
            "<form id=\"bulk-archive-form\" method=\"post\" action=\"/messages/archive\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"{}\"><button type=\"submit\">Archive Selected</button></form>",
            escape_html(csrf_token),
            escape_html(mailbox_name),
            escape_html(archive_mailbox_name),
        )
    } else {
        String::new()
    };
    let archive_notice = match bulk_actions.archive_mailbox_name {
        Some(archive_mailbox_name) if archive_mailbox_name != mailbox_name => format!(
            "<p class=\"muted\">Archive shortcut sends messages from this mailbox to <strong>{}</strong>.</p>",
            escape_html(archive_mailbox_name)
        ),
        Some(_) => "<p class=\"muted\">This mailbox matches your configured archive destination, so archive shortcuts are hidden here.</p>".to_string(),
        None => "<p class=\"muted\">Set an archive mailbox in Settings to add one-click archive actions on list and message pages.</p>".to_string(),
    };
    let sort_headers = render_mailbox_sort_headers(
        mailbox_name,
        sort_links.active_sort,
        sort_links.search_query,
        sort_links.search_scope,
    );

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<section class=\"content-pane\" aria-labelledby=\"mailbox-title\">",
            "<div class=\"section-header\"><div><h1 id=\"mailbox-title\" class=\"section-title\">Mailbox: {}</h1><p class=\"muted\">Signed in as <strong>{}</strong>. Message data remains fetched through the reviewed mailbox route.</p></div>",
            "<div class=\"badge-list\"><span class=\"badge badge-ok\">2FA active</span><span class=\"badge\">Remote content blocked</span></div></div>",
            "{}{}",
            "<form class=\"search-row\" method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><label for=\"mailbox-search\">Search query<input id=\"mailbox-search\" type=\"text\" name=\"q\" autocomplete=\"off\"></label>{}<button type=\"submit\">Search</button><label><input type=\"checkbox\" name=\"scope\" value=\"all\"> Search all mailboxes</label></form>",
            "<div class=\"toolbar\" aria-label=\"Mailbox actions\">{}{}</div>",
            "<div class=\"table-wrap\"><table class=\"message-list-table\"><thead><tr>{}{}{}{}</tr></thead><tbody>{}</tbody></table></div>",
            "</section>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        escape_html(mailbox_name),
        escape_html(canonical_username),
        success_banner,
        archive_notice,
        escape_html(mailbox_name),
        render_search_field_select(MessageSearchField::All),
        bulk_move_form,
        bulk_archive_form,
        if bulk_actions_available {
            "<th>Move</th>"
        } else {
            ""
        },
        if archive_actions_available {
            "<th>Archive</th>"
        } else {
            ""
        },
        sort_headers,
        if archive_actions_available {
            "<th>Action</th>"
        } else {
            ""
        },
        rows,
    ))
}

/// Renders a bounded search-results page for one mailbox or all mailboxes.
pub(crate) fn render_message_search_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: Option<&str>,
    query: &str,
    results: &[MessageSearchResult],
    active_sort: Option<MessageSort>,
    search_field: MessageSearchField,
) -> TrustedHtml {
    let displayed_results = results
        .iter()
        .take(DEFAULT_MAX_SEARCH_RESULTS)
        .collect::<Vec<_>>();
    let truncation_notice = if results.len() > displayed_results.len() {
        format!(
            "<div class=\"notice notice-error\" role=\"status\"><strong>Result limit reached.</strong> Displaying the first {} of {} backend results.</div>",
            displayed_results.len(),
            results.len(),
        )
    } else {
        String::new()
    };
    let back_link = match mailbox_name {
        Some(mailbox_name) => format!(
            "<a href=\"/mailbox?name={}\">Back to mailbox</a> | ",
            escape_html(&url_encode(mailbox_name))
        ),
        None => String::new(),
    };
    let search_scope = mailbox_name.unwrap_or("All mailboxes");
    let mailbox_hidden_input = mailbox_name.map_or_else(String::new, |mailbox_name| {
        format!(
            "<input type=\"hidden\" name=\"mailbox\" value=\"{}\">",
            escape_html(mailbox_name)
        )
    });
    let search_all_checked = if mailbox_name.is_none() {
        " checked"
    } else {
        ""
    };
    let search_field_select = render_search_field_select(search_field);
    let sort_headers = render_search_sort_headers(mailbox_name, query, active_sort, search_field);
    let mut rows = String::new();
    if results.is_empty() {
        rows.push_str("<tr><td colspan=\"7\">No messages matched this search.</td></tr>");
    } else {
        for result in &displayed_results {
            let message_href = format!(
                "/message?mailbox={}&uid={}",
                url_encode(&result.mailbox_name),
                result.uid
            );
            rows.push_str(&format!(
                "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&message_href),
                result.uid,
                escape_html(&result.mailbox_name),
                escape_html(result.subject.as_deref().unwrap_or("<none>")),
                escape_html(result.from.as_deref().unwrap_or("<none>")),
                escape_html(&result.date_received),
                escape_html(&result.flags.join(" ")),
                result.size_virtual,
            ));
        }
    }

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<section class=\"content-pane\">",
            "<p>{}<a href=\"/mailboxes\">All mailboxes</a></p>",
            "<h1>Search Results</h1>",
            "<p class=\"muted\">This bounded retrieval slice keeps Dovecot authoritative for the query while letting the browser search one mailbox or all visible mailboxes without turning OSMAP into a broad search product.</p>",
            "{}",
            "<form class=\"search-row\" method=\"get\" action=\"/search\">{}<label for=\"search-query\">Search query<input id=\"search-query\" type=\"text\" name=\"q\" value=\"{}\" autocomplete=\"off\"></label>{}<button type=\"submit\">Search</button><label><input type=\"checkbox\" name=\"scope\" value=\"all\"{}> Search all mailboxes</label></form>",
            "<p><strong>Scope:</strong> {}<br><strong>Field:</strong> {}<br><strong>Query:</strong> {}<br><strong>Results:</strong> {}</p>",
            "<div class=\"table-wrap\"><table><thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>",
            "</section>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        back_link,
        truncation_notice,
        mailbox_hidden_input,
        escape_html(query),
        search_field_select,
        search_all_checked,
        escape_html(search_scope),
        escape_html(search_field.label()),
        escape_html(query),
        displayed_results.len(),
        sort_headers,
        rows,
    ))
}

/// Renders the message-view page using the existing safe renderer output.
pub fn render_message_view_page(
    canonical_username: &str,
    csrf_token: &str,
    rendered: &RenderedMessageView,
    archive_mailbox_name: Option<&str>,
    user_visible_mailboxes: &[MailboxEntry],
) -> TrustedHtml {
    let displayed_attachments = rendered
        .attachments
        .iter()
        .take(DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX)
        .collect::<Vec<_>>();
    let inline_image_count = rendered
        .attachments
        .iter()
        .take(DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX)
        .filter(|attachment| {
            attachment.disposition == crate::mime::AttachmentDisposition::Inline
                && attachment.content_type.starts_with("image/")
        })
        .count();
    let inline_cid_image_count = rendered
        .attachments
        .iter()
        .take(DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX)
        .filter(|attachment| {
            attachment.disposition == crate::mime::AttachmentDisposition::Inline
                && attachment.content_type.starts_with("image/")
                && attachment.content_id.is_some()
        })
        .count();
    let mut attachments = String::new();
    if rendered.attachments.is_empty() {
        attachments.push_str(
            "<li class=\"attachment-item\">No attachment metadata surfaced for this message.</li>",
        );
    } else {
        for attachment in &displayed_attachments {
            let download_href = format!(
                "/attachment?mailbox={}&uid={}&part={}",
                url_encode(&rendered.mailbox_name),
                rendered.uid,
                url_encode(&attachment.part_path),
            );
            let content_id_metadata = attachment
                .content_id
                .as_deref()
                .map(|content_id| {
                    format!(
                        ", Content-ID <strong>cid:{}</strong>",
                        escape_html(content_id)
                    )
                })
                .unwrap_or_default();
            attachments.push_str(&format!(
                "<li class=\"attachment-item\"><strong>{}</strong><br>Part {}. {}, {}, {} bytes{}<br><a class=\"button-link\" href=\"{}\">Download</a></li>",
                escape_html(attachment.filename.as_deref().unwrap_or("<unnamed>")),
                escape_html(&attachment.part_path),
                escape_html(&attachment.content_type),
                escape_html(attachment.disposition.as_str()),
                attachment.size_hint_bytes,
                content_id_metadata,
                escape_html(&download_href),
            ));
        }
        if rendered.attachments.len() > displayed_attachments.len() {
            attachments.push_str(&format!(
                "<li class=\"attachment-item\"><strong>Attachment metadata limit reached.</strong><br>Displaying the first {} of {} surfaced parts.</li>",
                displayed_attachments.len(),
                rendered.attachments.len(),
            ));
        }
    }

    let archive_form = match archive_mailbox_name {
        Some(archive_mailbox_name) if archive_mailbox_name != rendered.mailbox_name => format!(
            "<section class=\"panel\"><h2>Archive Message</h2><p class=\"muted\">This shortcut reuses the bounded move path with your configured archive mailbox.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"{}\"><button type=\"submit\">Archive Message</button></form></section>",
            escape_html(csrf_token),
            escape_html(&rendered.mailbox_name),
            rendered.uid,
            escape_html(archive_mailbox_name),
        ),
        Some(_) => "<section class=\"panel\"><p class=\"muted\">This message is already in your configured archive mailbox.</p></section>".to_string(),
        None => "<section class=\"panel\"><p class=\"muted\">Set an archive mailbox in Settings to add a one-click archive shortcut here.</p></section>".to_string(),
    };
    let trash_mailbox_available = user_visible_mailboxes
        .iter()
        .any(|mailbox| mailbox.name == "Trash" && mailbox.name != rendered.mailbox_name);
    let delete_form = if trash_mailbox_available {
        format!(
            "<section class=\"panel\"><h2>Delete Message</h2><p class=\"muted\">This delete control stays inside the current bounded mailbox-move slice by moving the message into <strong>Trash</strong>.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"Trash\"><button type=\"submit\">Delete to Trash</button></form></section>",
            escape_html(csrf_token),
            escape_html(&rendered.mailbox_name),
            rendered.uid,
        )
    } else {
        String::new()
    };
    let move_destination_options = user_visible_mailboxes
        .iter()
        .filter(|mailbox| mailbox.name != rendered.mailbox_name)
        .map(|mailbox| {
            format!(
                "<option value=\"{}\">{}</option>",
                escape_html(&mailbox.name),
                escape_html(&mailbox.name)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let move_form = if move_destination_options.is_empty() {
        "<section class=\"panel\"><h2>Move Message</h2><p class=\"muted\">No alternate visible mailbox destinations are currently available for this bounded move action.</p></section>".to_string()
    } else {
        format!(
            "<section class=\"panel\"><h2>Move Message</h2><p class=\"muted\">This first folder-organization slice still keeps the general move path narrow: one message into one existing visible mailbox per request.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><label>Destination Mailbox<select name=\"destination_mailbox\">{}</select></label><button type=\"submit\">Move Message</button></form></section>",
            escape_html(csrf_token),
            escape_html(&rendered.mailbox_name),
            rendered.uid,
            move_destination_options,
        )
    };
    let rendering_notice = match rendered.rendering_mode.as_str() {
        "sanitized_html" => "<div class=\"notice\"><strong>Sanitized HTML:</strong> HTML content is shown through the current allowlist sanitization policy. Active content, external fetches, and unsafe URLs are removed.</div>",
        _ => "",
    };
    let inline_image_notice = if rendered.contains_html_body && inline_image_count > 0 {
        if inline_cid_image_count > 0 {
            format!(
                "<div class=\"notice\"><strong>Remote content blocked by policy:</strong> This message surfaced <strong>{}</strong> inline image part{}, including <strong>{}</strong> with Content-ID metadata used by `cid:` HTML references. Current browser policy does not render inline images inside the message body. Review the rendered body and download any needed image parts explicitly from the attachment list.</div>",
                inline_image_count,
                if inline_image_count == 1 { "" } else { "s" },
                inline_cid_image_count,
            )
        } else {
            format!(
                "<div class=\"notice\"><strong>Remote content blocked by policy:</strong> This message surfaced <strong>{}</strong> inline image part{}. Current browser policy does not render inline images inside the message body. Review the rendered body and download any needed image parts explicitly from the attachment list.</div>",
                inline_image_count,
                if inline_image_count == 1 { "" } else { "s" },
            )
        }
    } else {
        String::new()
    };
    let html_state_badge = if rendered.contains_html_body {
        "<span class=\"badge badge-warn\">HTML present</span>"
    } else {
        "<span class=\"badge badge-ok\">Plain text message</span>"
    };

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<div class=\"mail-shell mail-shell-three\">",
            "{}",
            "<section class=\"message-summary-pane\" aria-labelledby=\"message-title\">",
            "<p><a href=\"/mailbox?name={}\">Back to mailbox</a></p>",
            "<h1 id=\"message-title\" class=\"section-title\">{}</h1>",
            "<p class=\"muted\">from {}</p>",
            "<div class=\"badge-list\"><span class=\"badge badge-ok\">2FA session</span>{}<span class=\"badge\">{}</span></div>",
            "<dl class=\"message-meta\"><dt>Mailbox</dt><dd>{}</dd><dt>UID</dt><dd>{}</dd><dt>Received</dt><dd>{}</dd><dt>MIME Type</dt><dd>{}</dd><dt>Body Source</dt><dd>{}</dd><dt>Rendering Mode</dt><dd>{}</dd><dt>HTML Present</dt><dd>{}</dd></dl>",
            "<div class=\"toolbar\" aria-label=\"Message actions\"><a class=\"button-link\" href=\"/compose?mode=reply&mailbox={}&uid={}\">Reply</a><a class=\"button-link\" href=\"/compose?mode=forward&mailbox={}&uid={}\">Forward</a></div>",
            "<div class=\"action-stack\">{}{}{}</div>",
            "</section>",
            "<article class=\"reading-pane\" aria-labelledby=\"reading-title\">",
            "<h2 id=\"reading-title\">Reading Pane</h2>",
            "{}{}",
            "<section class=\"panel\"><h2>Attachments</h2><ul class=\"attachment-list\">{}</ul></section>",
            "<section class=\"body-panel\"><h2>Body</h2>{}</section>",
            "</article>",
            "</div>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        folder_pane(user_visible_mailboxes, Some(&rendered.mailbox_name)),
        escape_html(&url_encode(&rendered.mailbox_name)),
        escape_html(rendered.subject.as_deref().unwrap_or("<none>")),
        escape_html(rendered.from.as_deref().unwrap_or("<none>")),
        html_state_badge,
        if rendered.contains_html_body {
            "remote content blocked"
        } else {
            "safe text render"
        },
        escape_html(&rendered.mailbox_name),
        rendered.uid,
        escape_html(&rendered.date_received),
        escape_html(&rendered.mime_top_level_content_type),
        escape_html(rendered.body_source.as_str()),
        escape_html(rendered.rendering_mode.as_str()),
        if rendered.contains_html_body { "yes" } else { "no" },
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        archive_form,
        delete_form,
        move_form,
        rendering_notice,
        inline_image_notice,
        attachments,
        rendered.body_html,
    ))
}

/// Renders the browser-visible session-management page.
pub(crate) fn render_sessions_page(
    canonical_username: &str,
    current_session_id: &str,
    csrf_token: &str,
    session_lifetime_seconds: u64,
    session_idle_timeout_seconds: u64,
    sessions: &[BrowserVisibleSession],
    success_message: Option<&str>,
) -> TrustedHtml {
    let success_banner = match success_message {
        Some(success_message) => format!(
            "<p><strong>Update complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };

    let mut rows = String::new();
    for session in sessions {
        let state = if session.revoked_at.is_some() {
            "revoked"
        } else if session.session_id == current_session_id {
            "current"
        } else {
            "active"
        };
        let action = if session.revoked_at.is_some() {
            "<span class=\"muted\">Already revoked</span>".to_string()
        } else {
            format!(
                "<form method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"session_id\" value=\"{}\"><button type=\"submit\">{}</button></form>",
                escape_html(csrf_token),
                escape_html(&session.session_id),
                if session.session_id == current_session_id {
                    "Revoke This Session"
                } else {
                    "Revoke"
                }
            )
        };
        let revoked_at = session
            .revoked_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());

        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&session.session_id),
            escape_html(state),
            escape_html(&session.device_label),
            session.issued_at,
            session.last_seen_at,
            session.expires_at,
            escape_html(&revoked_at),
            escape_html(&session.remote_addr),
            escape_html(&session.user_agent),
            action,
        ));
    }

    let controls = format!(
        "<section class=\"panel\"><h2>Session Controls</h2><p><strong>Idle timeout:</strong> {} seconds. <strong>Absolute lifetime:</strong> {} seconds.</p><div class=\"toolbar\"><form method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"scope\" value=\"others\"><button type=\"submit\">Revoke Other Sessions</button></form><form method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"scope\" value=\"all\"><button type=\"submit\">Revoke All Sessions</button></form></div></section>",
        session_idle_timeout_seconds,
        session_lifetime_seconds,
        escape_html(csrf_token),
        escape_html(csrf_token),
    );

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>Sessions</h1>",
            "<p class=\"muted\">Concurrent browser sessions are allowed. Use the device label, remote address, and last-seen time to identify sessions before revoking one, other sessions, or all sessions.</p>",
            "{}{}",
            "<div class=\"table-wrap\"><table><thead><tr><th>Session ID</th><th>Status</th><th>Device</th><th>Issued</th><th>Last Seen</th><th>Expires</th><th>Revoked</th><th>Remote Address</th><th>User Agent</th><th>Action</th></tr></thead><tbody>{}</tbody></table></div>",
            "</section>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "sessions"),
        success_banner,
        controls,
        rows,
    ))
}

/// Renders the compose page for the current user and CSRF-bound session.
pub(crate) fn render_compose_page(model: &ComposePageModel<'_>) -> TrustedHtml {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Submission complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Request failed:</strong> {}</div>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let context_banner = match model.context_notice {
        Some(context_notice) => format!(
            "<div class=\"notice\"><strong>Context:</strong> {}</div>",
            escape_html(context_notice)
        ),
        None => String::new(),
    };
    let draft_id_field = model
        .draft_id
        .map(|draft_id| {
            format!(
                "<input type=\"hidden\" name=\"draft_id\" value=\"{}\">",
                escape_html(draft_id)
            )
        })
        .unwrap_or_default();
    let draft_attachment_notice = if model.draft_attachment_count > 0 {
        format!(
            "<div class=\"notice\"><strong>Draft attachments:</strong> {} stored attachment(s) will stay send-only and are not previewed.</div>",
            model.draft_attachment_count
        )
    } else {
        String::new()
    };
    let source_attachment_controls = render_source_attachment_controls(
        model.source_mailbox_name,
        model.source_uid,
        model.source_attachments,
        model.selected_source_part_paths,
    );

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>{}</h1>",
            "<p class=\"muted\">This send slice uses the local submission surface, keeps the browser body plain-text-first, and accepts bounded new file uploads or explicitly selected source-message attachments.</p>",
            "{}{}{}{}",
            "<form method=\"post\" action=\"/send\" enctype=\"multipart/form-data\">",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            "{}",
            "{}",
            "{}",
            "<label for=\"compose-to\">To<input id=\"compose-to\" type=\"text\" name=\"to\" value=\"{}\" autocomplete=\"off\"></label>",
            "<label for=\"compose-cc\">Cc<input id=\"compose-cc\" type=\"text\" name=\"cc\" value=\"{}\" autocomplete=\"off\"></label>",
            "<label for=\"compose-bcc\">Bcc<input id=\"compose-bcc\" type=\"text\" name=\"bcc\" value=\"{}\" autocomplete=\"off\"></label>",
            "<label for=\"compose-subject\">Subject<input id=\"compose-subject\" type=\"text\" name=\"subject\" value=\"{}\"></label>",
            "<label for=\"compose-body\">Body<textarea id=\"compose-body\" name=\"body\">{}</textarea></label>",
            "<label for=\"compose-attachment\">Attachments<input id=\"compose-attachment\" type=\"file\" name=\"attachment\" multiple></label>",
            "<button class=\"primary-button\" type=\"submit\">Send Message</button>",
            "<button type=\"submit\" formaction=\"/drafts/save\">Save Draft</button>",
            "</form>",
            "</section>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "compose"),
        escape_html(model.heading),
        success_banner,
        error_banner,
        context_banner,
        draft_attachment_notice,
        escape_html(model.csrf_token),
        draft_id_field,
        render_source_attachment_hidden_fields(model.source_mailbox_name, model.source_uid),
        source_attachment_controls,
        escape_html(model.to_value),
        escape_html(model.cc_value),
        escape_html(model.bcc_value),
        escape_html(model.subject_value),
        escape_html(model.body_value),
    ))
}

fn render_source_attachment_hidden_fields(
    source_mailbox_name: Option<&str>,
    source_uid: Option<u64>,
) -> String {
    match (source_mailbox_name, source_uid) {
        (Some(mailbox), Some(uid)) => format!(
            concat!(
                "<input type=\"hidden\" name=\"source_mailbox\" value=\"{}\">",
                "<input type=\"hidden\" name=\"source_uid\" value=\"{}\">"
            ),
            escape_html(mailbox),
            uid,
        ),
        _ => String::new(),
    }
}

fn render_source_attachment_controls(
    source_mailbox_name: Option<&str>,
    source_uid: Option<u64>,
    attachments: &[AttachmentMetadata],
    selected_part_paths: &[String],
) -> String {
    if source_mailbox_name.is_none() || source_uid.is_none() || attachments.is_empty() {
        return String::new();
    }

    let mut rows = String::new();
    for (index, attachment) in attachments
        .iter()
        .take(DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX)
        .enumerate()
    {
        let field_name = format!("include_original_attachment_{}", index + 1);
        let label = format!(
            "{} ({}, {}, {} bytes, part {})",
            attachment.filename.as_deref().unwrap_or("<unnamed>"),
            attachment.content_type,
            attachment.disposition.as_str(),
            attachment.size_hint_bytes,
            attachment.part_path,
        );
        rows.push_str(&format!(
            concat!(
                "<label class=\"checkbox-row\" for=\"{}\">",
                "<input id=\"{}\" type=\"checkbox\" name=\"{}\" value=\"{}\"{}>",
                "{}",
                "</label>"
            ),
            escape_html(&field_name),
            escape_html(&field_name),
            escape_html(&field_name),
            escape_html(&attachment.part_path),
            if selected_part_paths
                .iter()
                .any(|selected| selected == &attachment.part_path)
            {
                " checked"
            } else {
                ""
            },
            escape_html(&label),
        ));
    }

    if attachments.len() > DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX {
        rows.push_str(&format!(
            "<p class=\"muted\">Attachment selection display limit reached: showing first {} of {} surfaced attachments.</p>",
            DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX,
            attachments.len(),
        ));
    }

    format!(
        concat!(
            "<fieldset class=\"panel\">",
            "<legend>Source Attachments</legend>",
            "<p class=\"muted\">Selected source attachments are fetched again at send time and count against the compose attachment limits.</p>",
            "{}",
            "</fieldset>"
        ),
        rows,
    )
}

/// Renders the bounded draft list page.
pub(crate) fn render_draft_list_page(model: &DraftListPageModel<'_>) -> TrustedHtml {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Draft update:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Request failed:</strong> {}</div>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let mut rows = String::new();
    for draft in model.drafts {
        let resume_href = format!("/draft?id={}", url_encode(&draft.draft_id));
        rows.push_str(&format!(
            concat!(
                "<tr>",
                "<td><a href=\"{}\">Resume</a></td>",
                "<td>{}</td>",
                "<td>{}</td>",
                "<td>{}</td>",
                "<td>{}</td>",
                "<td>",
                "<form method=\"post\" action=\"/drafts/delete\">",
                "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
                "<input type=\"hidden\" name=\"draft_id\" value=\"{}\">",
                "<button type=\"submit\">Delete</button>",
                "</form>",
                "</td>",
                "</tr>"
            ),
            escape_html(&resume_href),
            draft.updated_at,
            draft.recipient_count,
            draft.body_len,
            draft.attachment_count,
            escape_html(model.csrf_token),
            escape_html(&draft.draft_id),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"6\" class=\"muted\">No saved drafts.</td></tr>");
    }

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>Drafts</h1>{}{}",
            "<p class=\"muted\">Saved drafts are bounded server-side compose state. Stored attachments remain send-only and are not previewed.</p>",
            "<p><a class=\"primary-button\" href=\"/compose\">New Message</a></p>",
            "<table>",
            "<thead><tr><th>Action</th><th>Updated</th><th>Recipients</th><th>Body Bytes</th><th>Attachments</th><th>Delete</th></tr></thead>",
            "<tbody>{}</tbody>",
            "</table>",
            "</section>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "drafts"),
        success_banner,
        error_banner,
        rows,
    ))
}

/// Renders the first bounded end-user settings page.
pub(crate) fn render_settings_page(model: &SettingsPageModel<'_>) -> TrustedHtml {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Update complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Request failed:</strong> {}</div>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let prefer_sanitized_html_checked =
        if model.html_display_preference == HtmlDisplayPreference::PreferSanitizedHtml {
            " checked"
        } else {
            ""
        };
    let prefer_plain_text_checked =
        if model.html_display_preference == HtmlDisplayPreference::PreferPlainText {
            " checked"
        } else {
            ""
        };
    let archive_mailbox_name = model.archive_mailbox_name.unwrap_or("");

    TrustedHtml::from_template(format!(
        concat!(
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>Settings</h1>{}{}",
            "<p class=\"muted\">This settings slice stays intentionally small. It controls HTML display preference and one optional archive mailbox shortcut without turning OSMAP into a broad preference UI.</p>",
            "<form method=\"post\" action=\"/settings\" class=\"action-stack\">",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            "<fieldset class=\"panel\">",
            "<legend>HTML Message Display</legend>",
            "<div><input id=\"html-display-prefer-sanitized\" type=\"radio\" name=\"html_display_preference\" value=\"prefer_sanitized_html\"{}><label for=\"html-display-prefer-sanitized\">Prefer sanitized HTML when available</label></div>",
            "<div><input id=\"html-display-prefer-plain\" type=\"radio\" name=\"html_display_preference\" value=\"prefer_plain_text\"{}><label for=\"html-display-prefer-plain\">Prefer plain text when available</label></div>",
            "</fieldset>",
            "<fieldset class=\"panel\">",
            "<legend>Archive Shortcut</legend>",
            "<label for=\"archive-mailbox-name\">Archive Mailbox</label>",
            "<input id=\"archive-mailbox-name\" type=\"text\" name=\"archive_mailbox_name\" value=\"{}\" autocomplete=\"off\">",
            "<p class=\"muted\">Leave this blank to keep only the manual move flow.</p>",
            "</fieldset>",
            "<div><button type=\"submit\">Save Settings</button></div>",
            "</form>",
            "</section>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "settings"),
        success_banner,
        error_banner,
        escape_html(model.csrf_token),
        prefer_sanitized_html_checked,
        prefer_plain_text_checked,
        escape_html(archive_mailbox_name),
    ))
}

#[cfg(test)]
mod v7_rendering_regression_tests {
    use super::*;
    use crate::html::TrustedHtml;
    use crate::mailbox::{MailboxEntry, MailboxListingPolicy};
    use crate::mime::{AttachmentDisposition, AttachmentMetadata, MimeBodySource};
    use crate::rendering::RenderingMode;

    #[test]
    fn ui_message_view_surfaces_truthful_rendering_labels() {
        let rendered = RenderedMessageView {
            mailbox_name: "INBOX".to_string(),
            uid: 42,
            subject: Some("Decoded café".to_string()),
            from: Some("Example Sender <sender@example.invalid>".to_string()),
            date_received: "2026-06-20 00:00:00 +0000".to_string(),
            mime_top_level_content_type: "multipart/alternative".to_string(),
            body_source: MimeBodySource::MultipartHtmlSanitized,
            contains_html_body: true,
            body_html: TrustedHtml::from_sanitized(
                "<div class=\"message-html\"><p>Safe rendered body</p></div>".to_string(),
            ),
            body_text_for_compose: "Safe rendered body".to_string(),
            attachments: vec![AttachmentMetadata {
                part_path: "1.2".to_string(),
                filename: Some("logo.png".to_string()),
                content_type: "image/png".to_string(),
                disposition: AttachmentDisposition::Inline,
                content_id: Some("logo@example.invalid".to_string()),
                size_hint_bytes: 128,
            }],
            rendering_mode: RenderingMode::SanitizedHtml,
        };
        let mailboxes = vec![
            MailboxEntry::new(MailboxListingPolicy::default(), "INBOX")
                .expect("mailbox should validate"),
            MailboxEntry::new(MailboxListingPolicy::default(), "Trash")
                .expect("mailbox should validate"),
        ];

        let page = render_message_view_page(
            "alice@example.com",
            "csrf-token-placeholder",
            &rendered,
            Some("Archive"),
            &mailboxes,
        );

        assert!(page.contains("Body Source</dt><dd>multipart_html_sanitized</dd>"));
        assert!(page.contains("Rendering Mode</dt><dd>sanitized_html</dd>"));
        assert!(page.contains("HTML Present</dt><dd>yes</dd>"));
        assert!(page.contains("HTML present"));
        assert!(page.contains("remote content blocked"));
        assert!(page.contains("<strong>Sanitized HTML:</strong>"));
        assert!(page.contains("Remote content blocked by policy"));
        assert!(page.contains("Safe rendered body"));
    }
}
