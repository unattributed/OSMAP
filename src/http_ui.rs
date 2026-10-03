//! Server-rendered browser HTML helpers for the current OSMAP web slice.
//!
//! Keeping these rendering helpers separate from routing reduces the amount of
//! browser-facing template code inside the request parser and route logic.

#[path = "folder_create_ui.rs"]
mod folder_create_ui;
#[path = "key_inventory_ui.rs"]
pub(crate) mod key_inventory_ui;
pub(crate) use folder_create_ui::render_folder_create;

#[path = "snooze_ui.rs"]
mod snooze_ui;
pub(crate) use snooze_ui::{render_snooze_page, render_snoozed_page, SnoozePageModel};
#[path = "notifications_ui.rs"]
mod notifications_ui;
pub(crate) use notifications_ui::render_notification_inbox;

#[path = "settings_ui.rs"]
mod settings_ui;
use crate::draft::DraftSummary;
use crate::draft_list::{DraftFilter, DraftListView, DraftSort};
use crate::html::TrustedHtml;
use crate::http::BrowserVisibleSession;
use crate::http_support::{escape_html, url_encode};
use crate::mail_list::{
    has_flag, sender_initials, AttachmentFilter, BulkSelection, ListViewState, MessageFilter,
    MAX_BULK_SELECTION,
};
use crate::mailbox::{
    MailboxEntry, MessageSearchField, MessageSearchResult, MessageSort, MessageSortColumn,
    MessageSortDirection, MessageSummary, DEFAULT_MAX_MAILBOXES,
};
use crate::message_metadata::{MessageFlag, MessageMetadata};
use crate::mime::{AttachmentMetadata, DEFAULT_MIME_PARTS_MAX};
use crate::rendering::{HtmlDisplayPreference, RenderedMessageView};
pub(crate) use settings_ui::render_openpgp_settings;
pub(crate) use settings_ui::{
    render_appearance_page, render_composition_page_with_signature, render_copies_page,
    render_general_page, render_identity_page, render_identity_page_with_signature,
    render_notifications_page, render_privacy_page, render_reading_page_with_after_archive,
    render_security_page, IdentityPageModel,
};

/// Defense-in-depth cap for attachment metadata rows rendered by one route.
const DEFAULT_RENDERED_ATTACHMENT_METADATA_MAX: usize = DEFAULT_MIME_PARTS_MAX;

/// Defense-in-depth cap for mailbox links rendered by one route.
const DEFAULT_RENDERED_MAILBOXES_MAX: usize = DEFAULT_MAX_MAILBOXES;

#[path = "http/archive_ui.rs"]
mod archive_ui;

#[path = "http/sessions_ui.rs"]
mod sessions_ui;
pub(crate) use sessions_ui::render_sessions_page;

/// Small view model for the current server-rendered compose page.
pub(crate) struct ComposePageModel<'a> {
    pub protection: crate::send::ProtectionIntent,
    pub openpgp: Option<crate::http::ComposeProtectionView>,
    pub sender_identity: Option<&'a crate::identity_preferences::IdentityPreferences>,
    pub send_intent: &'a str,
    pub contacts: Option<&'a crate::contacts::ContactBook>,
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
    pub body_format: crate::compose_format::BodyFormat,
    pub preview: bool,
    pub preflight: bool,
    pub draft_id: Option<&'a str>,
    pub draft_revision: Option<u64>,
    pub draft_attachments: &'a [crate::send::UploadedAttachment],
    pub removed_attachment_indices: &'a [usize],
    pub source_mailbox_name: Option<&'a str>,
    pub source_uid: Option<u64>,
    pub source_version: Option<&'a crate::message_metadata::MessageVersion>,
    pub source_attachments: &'a [AttachmentMetadata],
    pub selected_source_part_paths: &'a [String],
    pub reply_reference: Option<&'a crate::reply_thread::ReplyReference>,
}

/// Small view model for the draft list page.
pub(crate) struct DraftListPageModel<'a> {
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub success_message: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub drafts: &'a [DraftSummary],
    pub view: &'a DraftListView,
    pub total_count: usize,
    pub states: &'a [crate::http::BrowserDraftState],
    pub usage: &'a crate::http::BrowserDraftStorageUsage,
}

/// Small view model for mailbox message-list sort links.
pub(crate) struct MessageListSortLinks<'a> {
    pub view: &'a ListViewState,
    pub search_query: Option<&'a str>,
    pub search_scope: Option<&'a str>,
    pub reader: &'a MailReaderContext,
}

#[derive(Default)]
pub(crate) enum SelectedMessagePane {
    #[default]
    Unselected,
    Unavailable(&'static str),
    Ready(Box<RenderedMessageView>),
}

#[derive(Default)]
pub(crate) struct MailReaderContext {
    pub pane: SelectedMessagePane,
    pub archive_mailbox_name: Option<String>,
    pub mailboxes: Vec<MailboxEntry>,
}

pub(crate) struct MessageSearchContext<'a> {
    pub view: &'a ListViewState,
    pub field: MessageSearchField,
    pub reader: &'a MailReaderContext,
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

/// Repository-owned vector paths; decorative, never fetched from a network.
#[path = "http/reader_toolbar.rs"]
mod reader_toolbar;

fn shell_icon(name: &str) -> String {
    let path = match name {
        "approved-brand" => "<path d=\"M12 2 21 6v6c0 5-4 8.2-9 10-5-1.8-9-5-9-10V6z\"/><path d=\"m12 5 6 2.6V12c0 3.3-2.5 5.7-6 7.2C8.5 17.7 6 15.3 6 12V7.6z\"/><path d=\"m12 8 1.1 2.9L16 12l-2.9 1.1L12 16l-1.1-2.9L8 12l2.9-1.1z\"/>",
        "brand" => "<path d=\"m12 3 8 9-8 9-8-9z\"/><path d=\"m12 6 5.4 6-5.4 6-5.4-6z\"/>",
        "back" => "<path d=\"M20 12H4m6-6-6 6 6 6\"/>",
        "reply" => "<path d=\"m9 4-6 6 6 6M3 10h11c5 0 7 4 7 10\"/>",
        "read" => "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2\"/><path d=\"m3 6 9 7 9-7\"/>",
        "clock" => "<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 6v6l4 2\"/>",
        "label" => "<path d=\"m3 3 9 0 9 9-9 9-9-9z\"/><circle cx=\"8\" cy=\"8\" r=\"1\"/>",
        "more" => "<circle cx=\"12\" cy=\"5\" r=\"1\"/><circle cx=\"12\" cy=\"12\" r=\"1\"/><circle cx=\"12\" cy=\"19\" r=\"1\"/>",
        "bell" => "<path d=\"M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4\"/>",
        "light" => "<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 1v3m0 16v3M1 12h3m16 0h3M4 4l2 2m12 12 2 2M4 20l2-2M18 6l2-2\"/>",
        "dark" => "<path d=\"M16 3a9 9 0 1 0 0 18 10 10 0 0 1 0-18z\"/>",
        "shield" => "<path d=\"M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z\"/><path d=\"m8 12 3 3 5-6\"/>",
        "inbox" => "<path d=\"M4 4h16l2 10v6H2v-6zM2 14h6l2 3h4l2-3h6\"/>",
        "sent" => "<path d=\"m3 3 18 9-18 9 4-9zM7 12h14\"/>",
        "archive" => "<rect x=\"3\" y=\"3\" width=\"18\" height=\"5\" rx=\"1\"/><path d=\"M5 8v13h14V8M9 12h6\"/>",
        "bin" => "<path d=\"M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7\"/>",
        "compose" => "<path d=\"m14 4 6 6M4 20l5-1L21 7l-4-4L5 15z\"/>",
        "drafts" => "<path d=\"M5 3h9l5 5v13H5zM14 3v6h5M9 13h6M9 17h6\"/>",
        "settings" => "<path d=\"m10 3-.5 3-2 1-3-.7-2 3 2.3 2v2l-2.3 2 2 3 3-.7 2 1 .5 3h4l.5-3 2-1 3 .7 2-3-2.3-2v-2l2.3-2-2-3-3 .7-2-1L14 3z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/>",
        "folders" => "<path d=\"M3 5h7l2 3h9v13H3zM3 5V3h7l2 2h9v3\"/>",
        "menu" => "<path d=\"M4 6h16M4 12h16M4 18h16\"/>",
        "search" => "<circle cx=\"10\" cy=\"10\" r=\"7\"/><path d=\"m15 15 6 6\"/>",
        _ => "<path d=\"m7 10 5 5 5-5\"/>",
    };
    format!("<svg class=\"shell-icon\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" focusable=\"false\">{path}</svg>")
}

pub(crate) fn notification_header_link(account: &str, unread: Option<usize>) -> String {
    let (label, badge, state) = match unread {
        Some(0) => ("Notifications: no unread notices".into(), String::new(), "0".into()),
        Some(count) => (format!("Notifications: {count} unread"), format!("<span class=\"notification-badge\" aria-hidden=\"true\">{count}</span>"), count.to_string()),
        None => ("Notifications: unread count unavailable".into(), "<span class=\"notification-badge notification-badge-unknown\" aria-hidden=\"true\">?</span>".into(), "unknown".into()),
    };
    format!("<a class=\"header-notifications\" href=\"/notifications\" aria-label=\"{label}\" title=\"{label}\" data-notification-account=\"{}\" data-unread=\"{state}\">{}{badge}</a>", escape_html(account), shell_icon("bell"))
}

fn header_theme_controls(csrf: &str, current: &str) -> String {
    let compose = current == "compose";
    let disabled = current == "compose-result"
        || current == "settings"
        || (current.starts_with("settings-")
            && !matches!(current, "settings-search" | "settings-openpgp"))
        || current == "contacts"
        || current == "labels"
        || current == "snooze";
    let explanation = if current == "compose-result" {
        "Theme switching is unavailable here. Keep this result page open to retain the text from this submission attempt."
    } else if compose {
        "Changing theme saves this draft first, including selected attachments. If saving fails, the theme stays unchanged; reselect any unsaved uploads before retrying."
    } else if disabled {
        "Quick theme changes are unavailable while editing settings or contacts. Save your changes and use Appearance settings."
    } else {
        "Saves your account theme. System theme is available in Appearance settings."
    };
    let mut controls = if compose || disabled {
        "<div class=\"header-theme\" role=\"group\" aria-label=\"Quick theme\" aria-describedby=\"header-theme-help\">".to_owned()
    } else {
        format!("<form class=\"header-theme\" method=\"post\" action=\"/settings/appearance\" aria-label=\"Quick theme\" aria-describedby=\"header-theme-help\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"/settings?section=appearance\" data-header-return>", escape_html(csrf))
    };
    for (theme, label) in [("light", "Light"), ("dark", "Dark")] {
        let action = if compose {
            format!(" form=\"compose-form\" formaction=\"/drafts/save\" formmethod=\"post\" formenctype=\"multipart/form-data\" name=\"compose_action\" value=\"theme-{theme}\" data-compose-theme")
        } else if disabled {
            " disabled".to_owned()
        } else {
            format!(" name=\"appearance\" value=\"{theme}\"")
        };
        controls.push_str(&format!("<button type=\"submit\"{action} data-header-theme=\"{theme}\" aria-pressed=\"false\" aria-label=\"Use {label} theme\" title=\"{}\">{}</button>", escape_html(explanation), shell_icon(theme)));
    }
    controls.push_str(&format!(
        "<span id=\"header-theme-help\" class=\"sr-only\">{}</span>{}",
        escape_html(explanation),
        if compose || disabled {
            "</div>"
        } else {
            "</form>"
        }
    ));
    controls
}

pub(crate) fn app_header(canonical_username: &str, csrf_token: &str, current: &str) -> String {
    let clock = request_clock(crate::totp::TimeProvider::unix_timestamp(
        &crate::totp::SystemTimeProvider,
    ));
    let welcome = current == "mailboxes";
    let brand_mark = shell_icon(if welcome { "approved-brand" } else { "brand" });
    let brand_copy = if welcome {
        "<span class=\"brand-copy\"><strong>OSMAP</strong><small>Secure Email. Your Data. Your Control.</small></span>"
    } else {
        "<span>OSMAP</span>"
    };
    let theme_controls = header_theme_controls(csrf_token, current);
    let mut links = String::new();
    for (name, label, href, icon) in [
        ("mailboxes", "Mailbox", "/mailboxes", "folders"),
        ("compose", "Compose", "/compose", "compose"),
        ("inbox", "Inbox", "/mailbox?name=INBOX", "inbox"),
        ("drafts", "Drafts", "/drafts", "drafts"),
        ("sent", "Sent", "/mailbox?name=Sent", "sent"),
        ("documents", "Documents", "", "drafts"),
        (
            "archive",
            "Archive / Bin",
            "/mailbox/shortcut?kind=archive",
            "archive",
        ),
        (
            "security",
            "Security",
            "/settings?section=security",
            "shield",
        ),
        ("settings", "Settings", "/settings", "settings"),
        ("search", "Search", "/search", "search"),
    ] {
        if name == "documents" {
            links.push_str(&format!("<span class=\"rail-link\" role=\"link\" aria-disabled=\"true\" aria-label=\"Documents, unavailable\" aria-describedby=\"documents-unavailable\" title=\"Documents are unavailable\">{}<span class=\"rail-label\">Documents</span></span><span id=\"documents-unavailable\" class=\"sr-only\">Document storage and browsing are unavailable.</span>", shell_icon(icon)));
            continue;
        }
        links.push_str(&format!(
            "<a class=\"rail-link{}\" href=\"{}\" aria-label=\"{}\" title=\"{}\"{}>{}<span class=\"rail-label\">{}</span></a>",
            if name == "compose" { " rail-compose" } else { "" },
            escape_html(href), label, label,
            if name == current || name == "compose" && current == "compose-result" || name == "archive" && current == "bin" || name == "settings" && (current == "sessions" || current.starts_with("settings-")) { " aria-current=\"page\"" } else { "" },
            shell_icon(icon), label));
    }
    let search_menu = if current == "settings" || current.starts_with("settings-") {
        concat!(
            "<div class=\"header-search\"><form role=\"search\" method=\"get\" action=\"/settings\"><label class=\"sr-only\" for=\"settings-query\">Search settings</label>",
            "<input id=\"settings-query\" name=\"q\" type=\"search\" placeholder=\"Search settings…\" maxlength=\"128\" autocomplete=\"off\" accesskey=\"s\"><button type=\"submit\" aria-label=\"Search settings\">Search</button></form></div>"
        )
    } else {
        concat!(
        "<div class=\"header-search\"><form role=\"search\" method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"scope\" value=\"all\"><label class=\"sr-only\" for=\"global-mail-query\">Search all mail</label><input id=\"global-mail-query\" name=\"q\" type=\"search\" placeholder=\"Search mail…\" maxlength=\"256\" autocomplete=\"off\" accesskey=\"s\" required><button type=\"submit\" aria-label=\"Search mail\">Search</button></form>",
        "<details class=\"global-search-menu\" name=\"toolbar-menu\"><summary title=\"Mail shortcuts\">Shortcuts</summary>",
        "<div class=\"account-menu-panel global-search-panel\">",
        "<nav aria-label=\"Mail shortcuts\"><h2>Shortcuts</h2><a href=\"/compose\">Compose a message</a><a href=\"/mailbox?name=INBOX\">Open Inbox</a><a href=\"/mailbox?name=Sent\">Open Sent</a><a href=\"/mailbox/shortcut?kind=archive\">Open Archive</a><a href=\"/mailbox?name=Trash\">Open Bin</a><a href=\"/drafts\">Open Drafts</a><a href=\"/mailboxes\">Browse mailboxes</a><a href=\"/settings\">Open account settings</a></nav></div></details></div>"
    )
    };
    format!(concat!(
        "<a class=\"skip-link\" href=\"#main-content\">Skip to content</a>",
        "<aside class=\"app-rail\" aria-label=\"Application navigation\">",
        "<details class=\"rail-disclosure\"><summary title=\"Navigation labels\">{}<span class=\"sr-only rail-expand-label\">Expand navigation</span><span class=\"sr-only rail-collapse-label\">Collapse navigation</span></summary><p class=\"sr-only\">Navigation labels are expanded.</p></details>",
        "<nav class=\"rail-links\" aria-label=\"Primary navigation\">{}</nav><section class=\"rail-storage\" aria-label=\"Storage\"><strong>Storage</strong><p>Usage unavailable</p></section></aside>",
        "<header class=\"topbar{brand_variant}\" role=\"banner\" aria-label=\"Authenticated OSMAP shell\">",
        "<a class=\"brand\" href=\"/mailboxes\" aria-label=\"OSMAP mailboxes\"><span class=\"brand-mark\" aria-hidden=\"true\"><span class=\"ui-icon brand-icon\">{}</span></span>{brand_copy}</a>",
        "{}",
        "<div class=\"status-row auth-status\" aria-label=\"Session status and identity\">",
        "<details class=\"protection-menu\" name=\"toolbar-menu\"><summary>Protected by Default</summary><div class=\"account-menu-panel\"><p>Remote images and active content are blocked. These protections do not encrypt a message or verify its sender.</p><p class=\"shell-session-chip\">Your browser session was authenticated with two factors.</p></div></details>",
        "{notification_link}",
        "<details class=\"account-menu\" name=\"toolbar-menu\"><summary class=\"identity-chip\"><span class=\"account-avatar\" aria-hidden=\"true\">{}</span><span class=\"account-name\" title=\"{}\">{}</span>{}</summary>",
        "<div class=\"account-menu-panel\"><p class=\"muted\">Signed in as <strong>{}</strong></p><a href=\"/settings\">Account settings</a><a href=\"/settings?section=appearance\">Appearance</a><a href=\"/contacts\">Contacts</a><a href=\"/sessions\">Manage sessions</a>{}</div>",
        "</details>{theme_controls}</div></header>{clock}"
    ), shell_icon("menu"), links, brand_mark, search_menu, escape_html(&sender_initials(Some(canonical_username))), escape_html(canonical_username),
        escape_html(canonical_username), shell_icon("chevron"), escape_html(canonical_username), logout_form(csrf_token), theme_controls = theme_controls, clock = clock, brand_copy = brand_copy, notification_link = notification_header_link(canonical_username, None), brand_variant = if welcome { " topbar-welcome" } else { "" })
}

fn request_clock(timestamp: u64) -> String {
    // SystemTimeProvider reports zero when a pre-epoch system time cannot be read.
    // Do not turn that fallback into a purported current date.
    if timestamp == 0 {
        return "<div class=\"shell-request-clock\" aria-label=\"Server time\"><span>UTC time unavailable</span><small>Updated on page load</small></div>".into();
    }
    let date = crate::logging::format_unix_timestamp_utc(timestamp);
    format!("<div class=\"shell-request-clock\" aria-label=\"Server time\"><time datetime=\"{}\">{} UTC</time><small>Updated on page load</small></div>", escape_html(&date), escape_html(date.replace('T', " ").trim_end_matches('Z')))
}

#[cfg(test)]
mod request_clock_tests {
    use super::*;
    #[test]
    fn request_clock_uses_utc_and_unavailable_sentinel() {
        let clock = request_clock(1_735_689_600);
        assert!(clock.contains("datetime=\"2025-01-01T00:00:00Z\""));
        assert!(clock.contains(">2025-01-01 00:00:00 UTC</time>"));
        assert!(clock.contains("Updated on page load"));
        let unknown = request_clock(0);
        assert!(unknown.contains("UTC time unavailable"));
        assert!(!unknown.contains("<time"));
        assert!(!unknown.contains("1970"));
    }
}

pub(crate) fn render_settings_search_page(account: &str, csrf: &str, query: &str) -> TrustedHtml {
    let query_lower = query.to_lowercase();
    let mut results = String::new();
    for (label, terms, href) in [
        (
            "Theme",
            "appearance light dark system colours",
            "/settings?section=appearance#settings-appearance-title",
        ),
        (
            "Density",
            "appearance comfortable compact spacing",
            "/settings?section=appearance#settings-density",
        ),
        (
            "Font size",
            "appearance typography text small medium large",
            "/settings?section=appearance#settings-font-size",
        ),
        (
            "Reader layout",
            "appearance split stacked reader",
            "/settings?section=appearance#settings-reader-layout",
        ),
        (
            "Show avatars",
            "appearance sender initials pictures",
            "/settings?section=appearance#settings-show-avatars",
        ),
        (
            "Message preview",
            "appearance snippet mail summary",
            "/settings?section=appearance#settings-message-preview",
        ),
        (
            "Default format",
            "composition compose new blank message plain formatted",
            "/settings?section=composition#composition-format",
        ),
        (
            "Reply placement",
            "composition reply reply-all above below quoted text",
            "/settings?section=composition#composition-reply-placement",
        ),
        (
            "Identity",
            "identity display name reply-to sender profile email",
            "/settings?section=identity",
        ),
        (
            "Security",
            "security authentication password totp sessions protection",
            "/settings?section=security",
        ),
        (
            "OpenPGP public inventory",
            "openpgp keys public inventory fingerprint",
            "/settings?section=openpgp",
        ),
        (
            "Notifications",
            "notifications session events in-app notices read unread",
            "/settings?section=notifications",
        ),
        (
            "Authentication & Recovery",
            "authentication recovery password totp sessions contact",
            "/settings?section=authentication",
        ),
        (
            "Privacy & Security",
            "privacy security protected rendering remote images source attachments content plain html",
            "/settings?section=privacy",
        ),
        (
            "HTML Message Display",
            "reading plain sanitized content",
            "/settings?section=reading#html-display-prefer-sanitized",
        ),
        (
            "Default start page",
            "reading mailbox inbox drafts sent login",
            "/settings?section=reading#reading-start-page",
        ),
        (
            "Message ordering",
            "reading newest oldest date default",
            "/settings?section=reading#reading-date-order",
        ),
        (
            "Show source shortcut",
            "reading reader source headers MIME",
            "/settings?section=reading#reading-show-source",
        ),
        (
            "Attachment details",
            "reading reader file metadata",
            "/settings?section=reading#reading-attachment-details",
        ),
        (
            "Archive Mailbox",
            "reading shortcut folder",
            "/settings?section=copies#copies-archive",
        ),
        (
            "Active Sessions",
            "security browser revoke sign out",
            "/sessions",
        ),
    ] {
        if query_lower
            .split_whitespace()
            .all(|word| format!("{label} {terms}").to_lowercase().contains(word))
        {
            results.push_str(&format!("<li><a href=\"{href}\">{label}</a></li>"));
        }
    }
    let content = if results.is_empty() {
        "<p>No available settings match this search.</p>".into()
    } else {
        format!("<ul class=\"settings-search-results\">{results}</ul>")
    };
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell settings-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Search settings</h1><p>Available settings matching <strong>{}</strong>.</p></div><section class=\"content-pane\">{}<a class=\"button-link\" href=\"/settings?section=appearance\">Appearance settings</a></section></main>", app_header(account, csrf, "settings-search"), escape_html(query), content))
}

pub(crate) fn mailbox_nav_section(
    mailbox_name: &str,
    archive_mailbox_name: Option<&str>,
) -> &'static str {
    match mailbox_name {
        "INBOX" => "inbox",
        "Sent" => "sent",
        "Trash" => "bin",
        value if Some(value) == archive_mailbox_name => "archive",
        _ => "mailboxes",
    }
}

pub(crate) fn render_navigation_notice(
    canonical_username: &str,
    csrf_token: &str,
    title: &str,
    message: &str,
) -> TrustedHtml {
    TrustedHtml::from_template(format!(
        "{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>{}</h1><p>{}</p><div class=\"toolbar\"><a class=\"button-link\" href=\"/mailboxes\">All mailboxes</a><a class=\"button-link\" href=\"/settings\">Settings</a></div></section></main>",
        app_header(canonical_username, csrf_token, "archive"), escape_html(title), escape_html(message)))
}

// PAGE27 states use native links only; callers supply bounded, constructed routes.
pub(crate) fn mail_state_card(
    title: &str,
    detail: &str,
    href: &str,
    action: &str,
    failed: bool,
) -> String {
    format!("<section class=\"mail-state-card{}\"><h2>{}</h2><p>{}</p><a class=\"button-link\" href=\"{}\">{}</a></section>", if failed { " mail-state-failed" } else { "" }, escape_html(title), escape_html(detail), escape_html(href), escape_html(action))
}

pub(crate) fn render_mail_load_failure(
    account: &str,
    csrf: &str,
    current: &str,
    detail: &str,
    retry: &str,
) -> TrustedHtml {
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell mail-state-page\" tabindex=\"-1\"><h1>Mail unavailable</h1>{}</main>", app_header(account, csrf, current), mail_state_card("Failed load", detail, retry, "Retry", true)))
}

pub(crate) fn render_content_notice(
    username: &str,
    csrf: &str,
    title: &str,
    message: &str,
    return_to: &str,
    retry: Option<&str>,
) -> TrustedHtml {
    let retry = retry
        .map(|url| {
            format!(
                "<a class=\"button-link\" href=\"{}\">Retry loading</a>",
                escape_html(url)
            )
        })
        .unwrap_or_default();
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><section class=\"content-pane\"><h1>{}</h1><p>{}</p><nav class=\"toolbar\" aria-label=\"Content recovery\"><a class=\"button-link\" href=\"{}\">Back to message</a>{}<a href=\"/mailboxes\">All mailboxes</a></nav></section></main>",
        app_header(username, csrf, "mailboxes"), escape_html(title), escape_html(message), escape_html(return_to), retry))
}

pub(crate) fn render_message_source_page(
    username: &str,
    csrf: &str,
    message: &crate::mailbox::MessageView,
    return_to: &str,
) -> TrustedHtml {
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell source-page\" tabindex=\"-1\"><section class=\"content-pane\">",
        "<nav class=\"toolbar\" aria-label=\"Source navigation\"><a class=\"button-link\" href=\"{}\">Back to message</a></nav>",
        "<h1>Message source</h1><p class=\"muted\">Stored headers and MIME body text are shown as escaped text. Content is not rendered or fetched. Line endings and text decoding may differ from the original wire message.</p>",
        "<p class=\"muted\">{} · Message {}</p><pre class=\"message-source\" aria-label=\"Stored message source\" tabindex=\"0\">{}\n\n{}</pre></section></main>"),
        app_header(username, csrf, mailbox_nav_section(&message.mailbox_name, None)), escape_html(return_to), escape_html(&message.mailbox_name), message.uid,
        escape_html(message.header_block.trim_end_matches(['\r', '\n'])), escape_html(&message.body_text)))
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

#[path = "welcome_ui.rs"]
mod welcome_ui;
pub(crate) use welcome_ui::render_mailboxes_page;

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

fn render_mailbox_sort_controls(
    mailbox_name: &str,
    view: &ListViewState,
    search_query: Option<&str>,
    search_scope: Option<&str>,
) -> String {
    let active_sort = Some(view.sort);
    let links = MESSAGE_SORT_COLUMNS
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
            append_list_filter_selection(&mut href, view);

            format!(
                "<a href=\"{}\" aria-label=\"Sort by {} {}\"{}>{}{}</a>",
                escape_html(&href),
                column.label(),
                sort_direction_label(direction),
                if view.sort.column == *column {
                    " aria-current=\"true\""
                } else {
                    ""
                },
                column.label(),
                message_sort_indicator(*column, active_sort),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    render_sort_control_group(&links, view)
}

fn render_search_sort_controls(
    mailbox_name: Option<&str>,
    query: &str,
    view: &ListViewState,
    search_field: MessageSearchField,
) -> String {
    let active_sort = Some(view.sort);
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
        append_list_filter_selection(&mut href, view);

        headers.push_str(&format!(
            "<a href=\"{}\" aria-label=\"Sort by {} {}\"{}>{}{}</a>",
            escape_html(&href),
            column.label(),
            sort_direction_label(direction),
            if view.sort.column == column {
                " aria-current=\"true\""
            } else {
                ""
            },
            column.label(),
            message_sort_indicator(column, active_sort),
        ));
    }
    render_sort_control_group(&headers, view)
}

fn append_list_filter_selection(href: &mut String, view: &ListViewState) {
    for (key, value) in [("after", &view.dates.after), ("before", &view.dates.before)] {
        if let Some(value) = value {
            href.push_str(&format!("&{key}={}", url_encode(value)));
        }
    }

    if view.filter != MessageFilter::All {
        href.push_str("&filter=");
        href.push_str(view.filter.value());
    }
    if view.attachment != AttachmentFilter::All {
        href.push_str("&attachment=");
        href.push_str(view.attachment.value());
    }
    if let Some(selected) = &view.selection {
        href.push_str("&selected_mailbox=");
        href.push_str(&url_encode(&selected.mailbox));
        href.push_str("&selected_uid=");
        href.push_str(&selected.uid.to_string());
    }
}

pub(crate) fn list_navigation_href(base: &str, view: &ListViewState, page: usize) -> String {
    let mut href = format!(
        "{base}&sort={}&dir={}",
        view.sort.column.query_value(),
        view.sort.direction.query_value()
    );
    append_list_filter_selection(&mut href, view);
    if page > 1 {
        href.push_str(&format!("&page={page}"));
    }
    href
}

fn list_form_state(view: &ListViewState) -> String {
    let mut fields = format!("<input type=\"hidden\" name=\"filter\" value=\"{}\"><input type=\"hidden\" name=\"sort\" value=\"{}\"><input type=\"hidden\" name=\"dir\" value=\"{}\">", view.filter.value(), view.sort.column.query_value(), view.sort.direction.query_value());
    fields.push_str(&format!(
        "<input type=\"hidden\" name=\"attachment\" value=\"{}\">",
        view.attachment.value()
    ));
    for (key, value) in [("after", &view.dates.after), ("before", &view.dates.before)] {
        if let Some(value) = value {
            fields.push_str(&format!(
                "<input type=\"hidden\" name=\"{key}\" value=\"{}\">",
                escape_html(value)
            ));
        }
    }
    if let Some(selected) = &view.selection {
        fields.push_str(&format!("<input type=\"hidden\" name=\"selected_mailbox\" value=\"{}\"><input type=\"hidden\" name=\"selected_uid\" value=\"{}\">", escape_html(&selected.mailbox), selected.uid));
    }
    fields
}

fn selected_message_href(base: &str, view: &ListViewState, mailbox: &str, uid: u64) -> String {
    let mut selected = view.clone();
    selected.selection = Some(crate::mail_list::ListSelection {
        mailbox: mailbox.into(),
        uid,
    });
    format!(
        "{}#reading-pane",
        list_navigation_href(base, &selected, view.page)
    )
}

fn render_coordinated_reader(
    base: &str,
    view: &ListViewState,
    csrf: &str,
    reader: &MailReaderContext,
) -> String {
    let mut cleared = view.clone();
    cleared.selection = None;
    let back = list_navigation_href(base, &cleared, view.page);
    match &reader.pane {
        SelectedMessagePane::Unselected => "<article class=\"reading-pane reader-empty\" aria-label=\"Reading pane\"><h2>Choose a message</h2><p class=\"muted\">Open a subject to read it alongside this list.</p></article>".into(),
        SelectedMessagePane::Unavailable(message) => format!("<article id=\"reading-pane\" class=\"reading-pane\" tabindex=\"-1\" aria-labelledby=\"reading-unavailable\"><a href=\"{}\">Back to list</a><h2 id=\"reading-unavailable\">Message unavailable</h2><p role=\"status\">{}</p></article>", escape_html(&back), escape_html(message)),
        SelectedMessagePane::Ready(rendered) => {
            let locate = match view.selection_page {
                Some(page) if page != view.page => format!("<p class=\"reader-locate\"><a href=\"{}\">Locate selected message on page {page}</a></p>", escape_html(&list_navigation_href(base, view, page))),
                _ => String::new(),
            };
            format!("<div class=\"reader-column\">{locate}{}</div>", render_reader_fragment(csrf, rendered, reader.archive_mailbox_name.as_deref(), &reader.mailboxes, &back, &list_navigation_href(base, view, view.page), None))
        }
    }
}

fn render_date_filter(base: &str, view: &ListViewState) -> String {
    let Some((path, query)) = base.split_once('?') else {
        return String::new();
    };
    if !matches!(path, "/mailbox" | "/search") || query.len() > 2048 {
        return String::new();
    }
    let Ok(fields) = crate::http_form::parse_query_string(query, 8) else {
        return String::new();
    };
    if fields
        .keys()
        .any(|key| !["name", "mailbox", "q", "scope", "field"].contains(&key.as_str()))
    {
        return String::new();
    }
    let base_fields: String = fields
        .iter()
        .map(|(key, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape_html(key),
                escape_html(value)
            )
        })
        .collect();
    let mut cleared = view.clone();
    cleared.dates = crate::mail_list::ReceivedDateRange::default();
    let state = list_form_state(&cleared);
    let label = if view.dates.active() {
        "Received dates: filtered"
    } else {
        "Received dates: all"
    };
    format!("<details class=\"date-filter\"><summary>{label}</summary><form method=\"get\" action=\"{path}\">{base_fields}{state}<label>From date (UTC)<input type=\"date\" name=\"after\" min=\"0001-01-01\" max=\"9999-12-31\" value=\"{}\"></label><label>Through date (UTC)<input type=\"date\" name=\"before\" min=\"0001-01-01\" max=\"9999-12-31\" value=\"{}\"></label><button type=\"submit\">Apply dates</button><a href=\"{}\">Clear dates</a><p class=\"muted\">Inclusive UTC received dates, applied to loaded results. Messages with missing or invalid dates are excluded while a range is active. These are not archive or delivery dates.</p></form></details>", escape_html(view.dates.after.as_deref().unwrap_or("")), escape_html(view.dates.before.as_deref().unwrap_or("")), escape_html(&list_navigation_href(base, &cleared, 1)))
}

fn render_list_navigation(base: &str, view: &ListViewState, compact: bool) -> String {
    let (filters, pages, notices) = render_list_navigation_parts(base, view, compact);
    format!("<div class=\"list-navigation\">{filters}{pages}</div>{notices}")
}

fn render_list_navigation_parts(
    base: &str,
    view: &ListViewState,
    compact: bool,
) -> (String, String, String) {
    let mut filters = String::new();
    for filter in [
        MessageFilter::All,
        MessageFilter::Unread,
        MessageFilter::Starred,
    ] {
        let mut target = view.clone();
        target.filter = filter;
        filters.push_str(&format!(
            "<a class=\"filter-link\" href=\"{}\"{}>{}</a>",
            escape_html(&list_navigation_href(base, &target, 1)),
            if filter == view.filter {
                " aria-current=\"page\""
            } else {
                ""
            },
            filter.label()
        ));
    }
    filters.push_str(&format!("<details class=\"attachment-filter\"><summary>Attachments: {}</summary><div role=\"group\" aria-label=\"Attachment filter\">", view.attachment.label()));
    for attachment in [
        AttachmentFilter::All,
        AttachmentFilter::With,
        AttachmentFilter::Without,
        AttachmentFilter::Unknown,
    ] {
        let mut target = view.clone();
        target.attachment = attachment;
        filters.push_str(&format!(
            "<a class=\"filter-link\" href=\"{}\"{}>{}</a>",
            escape_html(&list_navigation_href(base, &target, 1)),
            if attachment == view.attachment {
                " aria-current=\"page\""
            } else {
                ""
            },
            attachment.label()
        ));
    }
    filters.push_str(
        "</div><p class=\"muted\">Unknown means attachment metadata is unavailable.</p></details>",
    );
    filters.push_str(&render_date_filter(base, view));
    if compact {
        filters = format!("<details class=\"sent-filter-menu\" name=\"list-tools\"><summary>{}</summary><div class=\"mail-tools-panel\"><nav aria-label=\"Sent filters\">{filters}</nav></div></details>", if view.attachment == AttachmentFilter::All { format!("{}{}", view.filter.label(), if view.dates.active() { " · Dates" } else { "" }) } else { format!("{} · {}", view.filter.label(), view.attachment.label()) });
    }
    let previous = if view.page > 1 {
        format!(
            "<a class=\"button-link\" rel=\"prev\" href=\"{}\">Previous page</a>",
            escape_html(&list_navigation_href(base, view, view.page - 1))
        )
    } else {
        "<span class=\"muted\" aria-disabled=\"true\">Previous page</span>".to_string()
    };
    let next = if view.page < view.pages() {
        format!(
            "<a class=\"button-link\" rel=\"next\" href=\"{}\">Next page</a>",
            escape_html(&list_navigation_href(base, view, view.page + 1))
        )
    } else {
        "<span class=\"muted\" aria-disabled=\"true\">Next page</span>".to_string()
    };
    let adjustment = if view.page != view.requested_page {
        "<p class=\"notice\" role=\"status\">The requested page is outside the current results. Showing the last available page.</p>"
    } else {
        ""
    };
    let limit = if view.backend_truncated {
        format!("<p class=\"notice\" role=\"status\"><strong>Result limit reached.</strong> Showing up to {} backend results. Narrow your search for more specific results.</p>", view.backend_limit)
    } else {
        String::new()
    };
    (
        format!("<nav class=\"message-filters\" aria-label=\"Message filters\">{filters}</nav>"),
        format!("<p class=\"list-window muted\">Showing {}–{} of {} messages · Page {} of {}</p><nav class=\"list-pagination\" aria-label=\"Result pages\">{previous}{next}</nav>", view.first_result(), view.last_result(), view.total_results, view.page, view.pages()),
        format!("{adjustment}{limit}"),
    )
}

fn render_message_flags(flags: &[String]) -> String {
    let read = if has_flag(flags, "\\Seen") {
        "Read"
    } else {
        "Unread"
    };
    let (star, label) = if has_flag(flags, "\\Flagged") {
        ("★", "Starred")
    } else {
        ("☆", "Not starred")
    };
    format!("<span class=\"message-star\" role=\"img\" aria-label=\"{label}\">{star}</span><span class=\"message-flags\" title=\"{}\">{read}</span>", escape_html(&flags.join(" ")))
}

fn render_message_state_controls(
    csrf: &str,
    mailbox: &str,
    uid: u64,
    flags: &[String],
    metadata: Option<&MessageMetadata>,
    return_to: &str,
) -> String {
    let indicators = render_message_flags(flags);
    let Some(metadata) = metadata else {
        return format!("{indicators}<span class=\"state-unavailable muted\" title=\"Message state controls are unavailable. Refresh the list to check again.\">State controls unavailable</span>");
    };
    let mut controls = String::new();
    for flag in [MessageFlag::Seen, MessageFlag::Flagged] {
        let current = has_flag(flags, flag.imap());
        controls.push_str(&render_message_flag_form(
            csrf, mailbox, uid, metadata, flag, current, return_to,
        ));
    }
    let attachments = render_attachment_count(Some(metadata));
    format!("<div class=\"message-state-controls\" role=\"group\" aria-label=\"Message state\">{controls}{attachments}</div>")
}

fn render_message_flag_form(
    csrf: &str,
    mailbox: &str,
    uid: u64,
    metadata: &MessageMetadata,
    flag: MessageFlag,
    current: bool,
    return_to: &str,
) -> String {
    let state_label = if flag == MessageFlag::Seen {
        "Read"
    } else {
        "Star"
    };
    let (label, text) = match (flag, current) {
        (MessageFlag::Seen, false) => ("Mark read", "Mark read"),
        (MessageFlag::Seen, true) => ("Mark unread", "Mark unread"),
        (MessageFlag::Flagged, false) => ("Star", "☆"),
        (MessageFlag::Flagged, true) => ("Remove star from", "★"),
    };
    format!(
            "<form class=\"message-state-form\" method=\"post\" action=\"/message/flag\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{uid}\"><input type=\"hidden\" name=\"mailbox_guid\" value=\"{}\"><input type=\"hidden\" name=\"message_guid\" value=\"{}\"><input type=\"hidden\" name=\"flag\" value=\"{}\"><input type=\"hidden\" name=\"enabled\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"{}\"><button class=\"flag-control\" type=\"submit\" aria-label=\"{state_label} message #{uid} in {}\" aria-pressed=\"{current}\" title=\"{label}\">{text}</button></form>",
            escape_html(csrf), escape_html(mailbox), escape_html(&metadata.version.mailbox_guid), escape_html(&metadata.version.message_guid), flag.value(),
            if current { "0" } else { "1" }, escape_html(return_to), escape_html(mailbox),
        )
}

fn render_attachment_count(metadata: Option<&MessageMetadata>) -> String {
    match metadata.and_then(|metadata| metadata.attachment_count) {
        Some(0) => String::new(),
        Some(count) => format!("<span class=\"badge attachment-count\" data-attachment-count=\"{count}\">{count} {}</span>", if count == 1 { "attachment" } else { "attachments" }),
        None => "<span class=\"muted attachment-count\" aria-label=\"Attachment metadata unavailable\" title=\"Attachment metadata unavailable\">–</span>".into(),
    }
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

struct MessageCard<'a> {
    recipient: bool,
    mailbox: &'a str,
    uid: u64,
    subject: Option<&'a str>,
    sender: Option<&'a str>,
    received: &'a str,
    flags: &'a [String],
    metadata: Option<&'a MessageMetadata>,
    size: u64,
}

fn render_message_card(
    message: MessageCard<'_>,
    csrf: &str,
    href: &str,
    selected: bool,
    return_to: &str,
    actions: &str,
    selection: &str,
) -> String {
    let party = message.sender.unwrap_or(if message.recipient {
        "Recipient unavailable"
    } else {
        "Sender unavailable"
    });
    let visible_party = if message.recipient && message.sender.is_some() {
        format!("To: {party}")
    } else {
        party.to_string()
    };
    let (star, read_action) = match message.metadata {
        Some(metadata) => (
            render_message_flag_form(
                csrf,
                message.mailbox,
                message.uid,
                metadata,
                MessageFlag::Flagged,
                has_flag(message.flags, "\\Flagged"),
                return_to,
            ),
            render_message_flag_form(
                csrf,
                message.mailbox,
                message.uid,
                metadata,
                MessageFlag::Seen,
                has_flag(message.flags, "\\Seen"),
                return_to,
            ),
        ),
        None => (
            render_message_flags(message.flags),
            "<span class=\"state-unavailable muted\">State controls unavailable</span>".into(),
        ),
    };
    format!(
        concat!(
            "<li class=\"message-row message-card{}\" data-selected=\"{}\">{selection}",
            "<div class=\"message-card-main\"><span class=\"message-avatar\" aria-hidden=\"true\" title=\"{initials_hint}\">{}</span><span class=\"message-sender\" title=\"{}\" dir=\"auto\">{}</span>",
            "<span class=\"message-date\" title=\"{}\">{}</span>",
            "<a class=\"message-subject-link\" href=\"{}\"{} dir=\"auto\">{}</a><span class=\"message-body-preview\" dir=\"auto\">{}</span></div>",
            "<div class=\"message-card-footer message-preview-meta\"><span class=\"message-mailbox\">{}</span><div class=\"message-star-cell\">{star}</div>{}<span class=\"message-security\" title=\"OpenPGP protection has not been assessed for this message. Open the message for available details.\">Not assessed</span>",
            "<details class=\"message-more\"><summary aria-label=\"More for message #{} in {}\"><span aria-hidden=\"true\">⋮</span><span class=\"sr-only\">More</span></summary>",
            "<div class=\"message-more-content\"><p class=\"muted\">Message #{} · {} bytes</p><p><strong>{party_label}:</strong> {}</p><p><strong>Subject:</strong> {}</p>{read_action}{}</div></details></div></li>"
        ),
        if has_flag(message.flags, "\\Seen") { "" } else { " message-unread" },
        selected,
        escape_html(&sender_initials(message.sender)),
        escape_html(party),
        escape_html(&visible_party),
        escape_html(message.received),
        escape_html(message.received),
        escape_html(href),
        if selected { " aria-current=\"true\"" } else { "" },
        escape_html(message.subject.unwrap_or("(No subject)")),
        escape_html(message.metadata.and_then(|metadata| metadata.preview.as_deref()).filter(|preview| crate::message_metadata::valid_message_preview(preview)).unwrap_or("No preview available")),
        escape_html(message.mailbox),
        render_attachment_count(message.metadata),
        message.uid, escape_html(message.mailbox), message.uid, message.size,
        escape_html(party),
        escape_html(message.subject.unwrap_or("(No subject)")), actions,
        initials_hint = if message.recipient { "Initials from the recipient header" } else { "Initials from the sender header" },
        party_label = if message.recipient { "To" } else { "From" },
        selection = selection,
        star = star,
        read_action = read_action,
    )
}

fn message_column_headings(recipient: bool) -> String {
    let heading = "<div class=\"message-columns\" aria-hidden=\"true\"><span class=\"column-sender\">From</span><span class=\"column-subject\">Subject</span><span class=\"column-attachment\">Attachment</span><span class=\"column-security\">Security</span><span class=\"column-date\">Date</span></div>";
    if recipient {
        heading.replace(">From<", ">Recipient<")
    } else {
        heading.to_string()
    }
}

fn render_sort_control_group(links: &str, view: &ListViewState) -> String {
    format!(
        "<details class=\"message-sort\"><summary>Sorted by {} {}</summary><nav aria-label=\"Sort messages\">{links}</nav></details>",
        view.sort.column.label(),
        sort_direction_label(view.sort.direction),
    )
}

fn move_identity_fields(
    csrf: &str,
    mailbox: &str,
    uid: u64,
    metadata: Option<&MessageMetadata>,
    return_to: &str,
) -> Option<String> {
    let version = &metadata?.version;
    Some(format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{uid}\"><input type=\"hidden\" name=\"mailbox_guid\" value=\"{}\"><input type=\"hidden\" name=\"message_guid\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"{}\">",
        escape_html(csrf), escape_html(mailbox), escape_html(&version.mailbox_guid), escape_html(&version.message_guid), escape_html(return_to)))
}

fn render_reader_move_controls(
    csrf: &str,
    rendered: &RenderedMessageView,
    archive: Option<&str>,
    mailboxes: &[MailboxEntry],
    return_to: &str,
) -> String {
    let Some(fields) = move_identity_fields(
        csrf,
        &rendered.mailbox_name,
        rendered.uid,
        rendered.metadata.as_ref(),
        return_to,
    ) else {
        return "<p class=\"muted\">Move actions unavailable: current stored message identity could not be confirmed. Refresh the message before choosing an action.</p>".into();
    };
    let options: String = mailboxes
        .iter()
        .filter(|m| m.name != rendered.mailbox_name)
        .map(|m| {
            format!(
                "<option value=\"{}\">{}</option>",
                escape_html(&m.name),
                escape_html(&m.name)
            )
        })
        .collect();
    let mut buttons = String::new();
    if archive.is_some_and(|name| name != rendered.mailbox_name) {
        buttons.push_str(
            "<button type=\"submit\" name=\"action\" value=\"archive\">Archive Message</button>",
        );
    }
    if archive.is_none() {
        buttons.push_str("<p class=\"muted\">Set an archive mailbox in Settings to enable the archive shortcut.</p>");
    }
    if rendered.mailbox_name != "Trash" && mailboxes.iter().any(|m| m.name == "Trash") {
        buttons
            .push_str("<button type=\"submit\" name=\"action\" value=\"bin\">Move to Bin</button>");
    }
    if rendered.mailbox_name == "Trash" && mailboxes.iter().any(|m| m.name == "INBOX") {
        buttons.push_str(
            "<button type=\"submit\" name=\"action\" value=\"restore\">Restore to Inbox</button>",
        );
    }
    let chooser = if options.is_empty() {
        String::new()
    } else {
        format!("<label>Destination Mailbox<select name=\"destination_mailbox\">{options}</select></label><button type=\"submit\" name=\"action\" value=\"move\">Move Message</button>")
    };
    format!("<form class=\"message-move-controls\" method=\"post\" action=\"/message/move\">{fields}<div class=\"toolbar\">{buttons}</div>{chooser}<p class=\"muted\">Bin moves mail to Trash. Restore returns it to Inbox. These controls never permanently delete mail.</p></form>")
}

fn render_bulk_selection_menu(
    base: &str,
    view: &ListViewState,
    _move_available: bool,
    _archive_available: bool,
) -> String {
    if view.total_results == 0 {
        return String::new();
    }
    let visible = view.last_result() - view.first_result() + 1;
    let count = visible.min(MAX_BULK_SELECTION);
    let base = list_navigation_href(base, view, view.page);
    let label = if visible <= MAX_BULK_SELECTION {
        format!("Select all {count} on this page")
    } else {
        format!("Select first {count} on this page")
    };
    let mut links = format!(
        "<a href=\"{}\">{}</a>",
        escape_html(&format!("{base}&select=move")),
        label
    );
    links.push_str(&format!(
        "<a href=\"{}\">Clear selection</a>",
        escape_html(&base)
    ));
    let selected = match view.bulk_selection {
        BulkSelection::Move | BulkSelection::Archive => {
            format!("{count} selected for the next action.")
        }
        _ => "No automatic selection.".into(),
    };
    format!("<details class=\"bulk-selection-menu\"><summary>Select messages</summary><nav aria-label=\"Select messages on this page\">{links}</nav><p class=\"muted\">Actions accept at most {MAX_BULK_SELECTION} messages. A selection applies only to the current page. {selected}</p></details>")
}

fn sort_direction_label(direction: MessageSortDirection) -> &'static str {
    if direction == MessageSortDirection::Asc {
        "ascending"
    } else {
        "descending"
    }
}

/// Renders the message-list page for one mailbox.
pub(crate) fn render_message_list_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: &str,
    messages: &[MessageSummary],
    list_notice: Option<&str>,
    bulk_actions: MessageListBulkActions<'_>,
    sort_links: MessageListSortLinks<'_>,
) -> TrustedHtml {
    let archive_page = mailbox_name == "Trash"
        || (Some(mailbox_name) == bulk_actions.archive_mailbox_name
            && !matches!(mailbox_name, "INBOX" | "Sent"));
    let list_notice_banner = match list_notice {
        Some(list_notice) => format!(
            "<div class=\"notice\" role=\"status\">{}</div>",
            escape_html(list_notice)
        ),
        None => String::new(),
    };
    let mut navigation_base = format!("/mailbox?name={}", url_encode(mailbox_name));
    if let Some(query) = sort_links.search_query {
        navigation_base.push_str(&format!("&q={}", url_encode(query)));
    }
    if let Some(scope) = sort_links.search_scope {
        navigation_base.push_str(&format!("&scope={}", url_encode(scope)));
    }
    let mut rows = String::new();
    let archive_actions_available = bulk_actions
        .archive_mailbox_name
        .is_some_and(|archive_mailbox_name| archive_mailbox_name != mailbox_name);
    let bulk_actions_available = !bulk_actions.move_destinations.is_empty();
    for (index, message) in messages.iter().enumerate() {
        let message_href = if message.metadata.is_some() {
            selected_message_href(&navigation_base, sort_links.view, mailbox_name, message.uid)
        } else {
            format!(
                "/message?mailbox={}&uid={}",
                url_encode(mailbox_name),
                message.uid
            )
        };
        let return_to =
            list_navigation_href(&navigation_base, sort_links.view, sort_links.view.page);
        let archive_action = if archive_actions_available {
            move_identity_fields(csrf_token, mailbox_name, message.uid, message.metadata.as_ref(), &return_to)
                .map(|fields| format!("<form method=\"post\" action=\"/message/move\">{fields}<button type=\"submit\" name=\"action\" value=\"archive\">Archive</button></form>"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let selection_cells = if message.metadata.is_some() {
            message.metadata.as_ref().map(|metadata| format!(
                "<label class=\"bulk-row-choice\"><input form=\"bulk-move-form\" type=\"checkbox\" name=\"message_{}\" value=\"{}|{}|{}\" aria-label=\"Select message #{}\"{}><span class=\"sr-only\">Select message</span></label>",
                message.uid, message.uid, escape_html(&metadata.version.mailbox_guid), escape_html(&metadata.version.message_guid), message.uid,
                if index < MAX_BULK_SELECTION && sort_links.view.bulk_selection != BulkSelection::None { " checked" } else { "" })).unwrap_or_default()
        } else {
            String::new()
        };
        if archive_page {
            rows.push_str(&archive_ui::row(
                message,
                &selection_cells,
                &message_href,
                csrf_token,
                &return_to,
                sort_links.view.is_selected(mailbox_name, message.uid),
            ));
            continue;
        }
        let actions = archive_action;
        rows.push_str(&render_message_card(
            MessageCard {
                mailbox: mailbox_name,
                uid: message.uid,
                subject: message.subject.as_deref(),
                recipient: mailbox_name == "Sent",
                sender: if mailbox_name == "Sent" {
                    message.to.as_deref()
                } else {
                    message.from.as_deref()
                },
                received: &message.date_received,
                flags: &message.flags,
                metadata: message.metadata.as_ref(),
                size: message.size_virtual,
            },
            csrf_token,
            &message_href,
            sort_links.view.is_selected(mailbox_name, message.uid),
            &list_navigation_href(&navigation_base, sort_links.view, sort_links.view.page),
            &actions,
            &selection_cells,
        ));
    }
    if messages.is_empty() && !archive_page {
        rows.push_str(&format!("<li class=\"message-empty-state\">{}</li>", mail_state_card("No messages", "No messages are shown in this mailbox view. Active filters and snoozed messages may limit the loaded results.", "/compose", "Compose", false)));
    }

    let bulk_move_form = if messages.iter().any(|m| m.metadata.is_some()) {
        let options: String = bulk_actions
            .move_destinations
            .iter()
            .map(|name| {
                format!(
                    "<option value=\"{}\">{}</option>",
                    escape_html(name),
                    escape_html(name)
                )
            })
            .collect();
        let chooser = if options.is_empty() {
            String::new()
        } else {
            format!("<label for=\"bulk-destination-mailbox\">Move selected to<select id=\"bulk-destination-mailbox\" name=\"destination_mailbox\">{options}</select></label><button type=\"submit\" name=\"action\" value=\"move\">Move Selected</button>")
        };
        let mut buttons = String::from("<button type=\"submit\" formaction=\"/messages/labels/review\" name=\"action\" value=\"review\">Review labels for selected</button>");
        if archive_actions_available {
            buttons.push_str("<button type=\"submit\" name=\"action\" value=\"archive\">Archive Selected</button>");
        }
        if mailbox_name != "Trash"
            && bulk_actions
                .move_destinations
                .iter()
                .any(|name| name == "Trash")
        {
            buttons.push_str("<button type=\"submit\" name=\"action\" value=\"bin\">Move Selected to Bin</button>");
        }
        if mailbox_name == "Trash"
            && bulk_actions
                .move_destinations
                .iter()
                .any(|name| name == "INBOX")
        {
            buttons.push_str("<button type=\"submit\" name=\"action\" value=\"restore\">Restore Selected to Inbox</button>");
        }
        format!("<form id=\"bulk-move-form\" class=\"bulk-move-controls\" method=\"post\" action=\"/messages/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"return_to\" value=\"{}\"><div class=\"toolbar\">{buttons}</div>{chooser}<p class=\"muted\">Select up to ten messages. Bin moves to Trash; restore returns to Inbox.</p></form>", escape_html(csrf_token), escape_html(mailbox_name), escape_html(&list_navigation_href(&navigation_base, sort_links.view, sort_links.view.page)))
    } else {
        String::new()
    };
    if archive_page {
        return archive_ui::page(archive_ui::Page {
            account: canonical_username,
            csrf: csrf_token,
            mailbox: mailbox_name,
            actions: &bulk_actions,
            links: &sort_links,
            base: &navigation_base,
            rows: &rows,
            banner: &list_notice_banner,
            bulk_form: &bulk_move_form,
        });
    }
    let bulk_archive_form = String::new();
    let archive_notice = match bulk_actions.archive_mailbox_name {
        Some(archive_mailbox_name) if archive_mailbox_name != mailbox_name => format!(
            "<p class=\"muted\">Archive shortcut sends messages from this mailbox to <strong>{}</strong>.</p>",
            escape_html(archive_mailbox_name)
        ),
        Some(_) => "<p class=\"muted\">This mailbox matches your configured archive destination, so archive shortcuts are hidden here.</p>".to_string(),
        None => "<p class=\"muted\">Set an archive mailbox in Settings to add one-click archive actions on list and message pages.</p>".to_string(),
    };
    let sort_headers = render_mailbox_sort_controls(
        mailbox_name,
        sort_links.view,
        sort_links.search_query,
        sort_links.search_scope,
    );
    let search_controls = format!(concat!(
        "<details class=\"mail-search-disclosure\" name=\"list-tools\"><summary>Search this mailbox</summary><div class=\"mail-tools-panel\">",
        "<form class=\"search-row compact-search\" method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\">{}<label for=\"mailbox-search\">Search query<input id=\"mailbox-search\" type=\"text\" name=\"q\" value=\"{}\" autocomplete=\"off\"></label><button type=\"submit\">Search</button><details class=\"search-options\"><summary>Search options</summary><div>{}<label><input type=\"checkbox\" name=\"scope\" value=\"all\"> Search all mailboxes</label></div></details></form></div></details>"
    ), escape_html(mailbox_name), list_form_state(sort_links.view), escape_html(sort_links.search_query.unwrap_or("")), render_search_field_select(MessageSearchField::All));
    let action_controls = format!(concat!(
        "<details class=\"bulk-actions\" name=\"list-tools\"><summary>Bulk actions</summary><div class=\"mail-tools-panel\">{}<p class=\"muted\">Use the row checkboxes to select messages for an action.</p><div class=\"toolbar\" aria-label=\"Mailbox actions\">{}{}</div></div></details>"
    ), archive_notice, bulk_move_form, bulk_archive_form);

    let table_mailbox = matches!(mailbox_name, "INBOX" | "Sent");
    let compact_tool = |html: String, text: &str, icon: &str| {
        if table_mailbox {
            html.replace(
                &format!("<summary>{text}</summary>"),
                &format!(
                    "<summary aria-label=\"{text}\" title=\"{text}\">{}</summary>",
                    shell_icon(icon)
                ),
            )
        } else {
            html
        }
    };
    let selection_controls = compact_tool(
        render_bulk_selection_menu(
            &navigation_base,
            sort_links.view,
            bulk_actions_available,
            archive_actions_available,
        ),
        "Select messages",
        "inbox",
    );
    let search_controls = compact_tool(search_controls, "Search this mailbox", "search");
    let action_controls = compact_tool(action_controls, "Bulk actions", "more");
    let mut navigation =
        render_list_navigation(&navigation_base, sort_links.view, mailbox_name == "Sent");
    let mut sort_headers = sort_headers;
    if table_mailbox {
        navigation = navigation.replace("Attachments: All attachment states", "Attachments: all");
        for (label, symbol) in [("Previous page", "‹"), ("Next page", "›")] {
            navigation = navigation.replace(
                &format!(">{label}</a>"),
                &format!(" aria-label=\"{label}\" title=\"{label}\">{symbol}</a>"),
            );
            navigation = navigation.replace(
                &format!(">{label}</span>"),
                &format!(" aria-label=\"{label}\" title=\"{label}\">{symbol}</span>"),
            );
        }
        sort_headers = sort_headers
            .replace("Sorted by Received descending", "Newest first")
            .replace("Sorted by Received ascending", "Oldest first");
    }
    TrustedHtml::from_template(format!(
        concat!(
            "{}",
            "<main id=\"main-content\" class=\"page-shell coordinated-mail{}{table_class}\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>{}</h1><p>{list_intro}</p></div>",
            "<section class=\"content-pane coordinated-list\" aria-labelledby=\"mailbox-title\">",
            "<div class=\"section-header sr-only\"><h2 id=\"mailbox-title\" class=\"section-title message-list-summary\">Mailbox: {}</h2></div>",
            "{}",
            "<div class=\"mail-list-toolbar\">{}{}{}{}{}</div>",
            "{}<ul role=\"list\" class=\"message-cards\" aria-label=\"Mailbox message list\">{}</ul>",
            "</section>{}",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, mailbox_nav_section(mailbox_name, bulk_actions.archive_mailbox_name)),
        if sort_links.view.selection.is_some() { " has-selection" } else { "" },
        escape_html(if mailbox_name == "INBOX" { "Inbox" } else { mailbox_name }),
        escape_html(mailbox_name),
        list_notice_banner,
        selection_controls,
        navigation,
        sort_headers,
        search_controls,
        action_controls,
        message_column_headings(mailbox_name == "Sent"),
        rows,
        render_coordinated_reader(&navigation_base, sort_links.view, csrf_token, sort_links.reader),
        table_class = if mailbox_name == "INBOX" { " approved-mail-table inbox-table" } else if mailbox_name == "Sent" { " approved-mail-table sent-table" } else { "" },
        list_intro = if mailbox_name == "Sent" { "Stored Sent copies. Their presence does not confirm delivery." } else { "Search, filter, sort and work with messages without losing context." },
    ))
}

/// Renders a bounded search-results page for one mailbox or all mailboxes.
pub(crate) fn render_message_search_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: Option<&str>,
    query: &str,
    results: &[MessageSearchResult],
    context: MessageSearchContext<'_>,
) -> TrustedHtml {
    let view = context.view;
    let search_field = context.field;
    let back_link = match mailbox_name {
        Some(mailbox_name) => format!(
            "<a href=\"/mailbox?name={}\">Back to mailbox</a>",
            escape_html(&url_encode(mailbox_name))
        ),
        None => String::new(),
    };
    let search_scope = mailbox_name.unwrap_or("All mailboxes");
    let mailbox_input = format!(
        "<label>Folder<input name=\"mailbox\" value=\"{}\" placeholder=\"Mailbox name\"></label>",
        escape_html(mailbox_name.unwrap_or(""))
    );
    let search_all_checked = if mailbox_name.is_none() {
        " checked"
    } else {
        ""
    };
    let search_field_select = render_search_field_select(search_field);
    let sort_headers = render_search_sort_controls(mailbox_name, query, view, search_field);
    let mut navigation_base = match mailbox_name {
        Some(name) => format!("/search?mailbox={}", url_encode(name)),
        None => "/search?scope=all".to_string(),
    };
    navigation_base.push_str(&format!(
        "&q={}&field={}",
        url_encode(query),
        search_field.query_value()
    ));
    let mut rows = String::new();
    if results.is_empty() {
        let clear = match mailbox_name {
            Some(name) => format!("/search?mailbox={}", url_encode(name)),
            None => "/search?scope=all".into(),
        };
        rows.push_str(&format!(
            "<li class=\"message-empty-state\">{}</li>",
            mail_state_card(
                "Empty search",
                "No results match the current search and filters.",
                &clear,
                "Clear filters",
                false
            )
        ));
    } else {
        for result in results {
            let message_href = if result.metadata.is_some() {
                selected_message_href(&navigation_base, view, &result.mailbox_name, result.uid)
            } else {
                format!(
                    "/message?mailbox={}&uid={}",
                    url_encode(&result.mailbox_name),
                    result.uid
                )
            };
            rows.push_str(&format!(
                "<li class=\"message-row search-result-row\" data-selected=\"{}\"><span class=\"search-result-type\">{}</span><div class=\"search-result-title\"><a class=\"message-subject-link\" href=\"{}\"{} dir=\"auto\">{}</a><span class=\"message-sender\" dir=\"auto\"><span class=\"sr-only\">From</span> {}{preview}</span></div><span class=\"search-result-location message-mailbox\" dir=\"auto\">{}</span><time class=\"search-result-date\">{}</time><details class=\"search-result-more\"><summary aria-label=\"More for message #{} in {}\">More</summary><div>{}</div></details></li>",
                view.is_selected(&result.mailbox_name, result.uid), shell_icon("inbox"), escape_html(&message_href),
                if view.is_selected(&result.mailbox_name, result.uid) { " aria-current=\"true\"" } else { "" },
                escape_html(result.subject.as_deref().unwrap_or("(No subject)")),
                escape_html(result.from.as_deref().unwrap_or("Sender unavailable")), escape_html(&result.mailbox_name), escape_html(&result.date_received),
                result.uid, escape_html(&result.mailbox_name),
                render_message_state_controls(csrf_token, &result.mailbox_name, result.uid, &result.flags, result.metadata.as_ref(), &list_navigation_href(&navigation_base, view, view.page)),
                preview = result.metadata.as_ref().and_then(|metadata| metadata.preview.as_deref()).filter(|preview| crate::message_metadata::valid_message_preview(preview)).map(|preview| format!(" · {}", escape_html(preview))).unwrap_or_default(),
            ));
        }
    }

    let (navigation, pages, notices) = render_list_navigation_parts(&navigation_base, view, false);
    let landing = query.trim().is_empty();
    if landing {
        rows = "<li class=\"message-empty-state\">Enter keywords to search your mail.</li>".into();
    }
    TrustedHtml::from_template(format!(
        concat!(
            "{}<main id=\"main-content\" class=\"page-shell coordinated-mail search-results{}\" tabindex=\"-1\"><div class=\"page-intro mail-page-intro\"><h1>Search</h1><p>Find messages across your mailboxes.</p></div>",
            "<section class=\"content-pane coordinated-list\"><h2 class=\"section-title sr-only\">Search Results</h2>",
            "<div class=\"search-query-panel\"><form class=\"search-row compact-search\" method=\"get\" action=\"/search\">{}<label class=\"search-query-label\" for=\"search-query\"><span class=\"sr-only\">Search query</span><input id=\"search-query\" type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Search mail…\" autocomplete=\"off\"></label><button type=\"submit\">Search</button><details class=\"search-options\"><summary>Search options</summary><div>{}{}<label><input type=\"checkbox\" name=\"scope\" value=\"all\"{}> Search all mailboxes</label></div></details></form>{}</div>",
            "<div class=\"search-result-tabs\" aria-label=\"Search types\"><span aria-current=\"true\">Messages{}</span><span aria-disabled=\"true\">Documents</span><a href=\"/search?category=people&amp;q={people_query}\">People</a><span class=\"search-scope\">{}</span>{}</div>",
            "<div class=\"search-result-headings\" aria-hidden=\"true\"><span>Type</span><span>Result</span><span>Location</span><span>Received</span><span></span></div><ul role=\"list\" class=\"message-cards search-result-list\" aria-label=\"Search results\">{}</ul>",
            "<div class=\"search-result-footer\">{}{}</div>{}<p class=\"search-capability-note muted\">Search covers accessible messages. Documents and protection-status filters are unavailable. People search covers your saved contacts. Message protection is assessed when opened.</p></section>{}</main>"
        ),
        app_header(canonical_username, csrf_token, "search"),
        if view.selection.is_some() { " has-selection" } else { "" },
        list_form_state(view), escape_html(query), search_field_select, mailbox_input, search_all_checked, navigation,
        if landing { String::new() } else { format!(" ({})", view.total_results) }, escape_html(search_scope),
        sort_headers, rows, pages, back_link, notices,
        render_coordinated_reader(&navigation_base, view, csrf_token, context.reader),
        people_query = escape_html(&url_encode(query)),
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
    render_message_view_page_with_neighbours(
        canonical_username,
        csrf_token,
        rendered,
        archive_mailbox_name,
        user_visible_mailboxes,
        &crate::reader_neighbours::ReaderNeighbours::default(),
    )
}

pub(crate) fn render_message_view_page_with_neighbours(
    canonical_username: &str,
    csrf_token: &str,
    rendered: &RenderedMessageView,
    archive_mailbox_name: Option<&str>,
    user_visible_mailboxes: &[MailboxEntry],
    neighbours: &crate::reader_neighbours::ReaderNeighbours,
) -> TrustedHtml {
    let back = neighbours
        .back
        .clone()
        .unwrap_or_else(|| format!("/mailbox?name={}", url_encode(&rendered.mailbox_name)));
    let mut current = format!(
        "/message?mailbox={}&uid={}",
        url_encode(&rendered.mailbox_name),
        rendered.uid
    );
    if let Some(metadata) = &rendered.metadata {
        current.push_str(&format!(
            "&mailbox_guid={}&message_guid={}",
            url_encode(&metadata.version.mailbox_guid),
            url_encode(&metadata.version.message_guid)
        ));
    }
    if let Some(back) = &neighbours.back {
        current.push_str(&format!("&return_to={}", url_encode(back)));
    }
    let current =
        crate::mail_navigation::safe_mail_return(&current).unwrap_or_else(|| back.clone());
    let header = app_header(
        canonical_username,
        csrf_token,
        mailbox_nav_section(&rendered.mailbox_name, archive_mailbox_name),
    )
    .replace(
        "name=\"return_to\" value=\"/settings?section=appearance\" data-header-return",
        &format!(
            "name=\"return_to\" value=\"{}\" data-header-return",
            escape_html(&current)
        ),
    );
    TrustedHtml::from_template(format!(
        "{}<main id=\"main-content\" class=\"page-shell standalone-reader\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Message Reader</h1><p>Protected reading with message details, isolated attachments and source view.</p></div>{}</main>",
        header,
        render_reader_fragment(csrf_token, rendered, archive_mailbox_name, user_visible_mailboxes, &back, &current, Some(neighbours))))
}

fn render_reader_fragment(
    csrf_token: &str,
    rendered: &RenderedMessageView,
    archive_mailbox_name: Option<&str>,
    user_visible_mailboxes: &[MailboxEntry],
    back_href: &str,
    return_to: &str,
    neighbours: Option<&crate::reader_neighbours::ReaderNeighbours>,
) -> String {
    let standalone = neighbours.is_some();
    let navigation = neighbours.map(|value| value.html()).unwrap_or_default();
    let snooze_control=rendered.metadata.as_ref().map(|m|format!("<a class=\"reader-snooze\" aria-label=\"Snooze message\" title=\"Snooze message\" href=\"/snooze?mailbox={}&amp;uid={}&amp;mailbox_guid={}&amp;message_guid={}&amp;return_to={}\"><span aria-hidden=\"true\">◷</span></a>",escape_html(&url_encode(&rendered.mailbox_name)),rendered.uid,escape_html(&url_encode(&m.version.mailbox_guid)),escape_html(&url_encode(&m.version.message_guid)),escape_html(&url_encode(return_to)))).unwrap_or_else(||"<button class=\"reader-snooze\" aria-label=\"Snooze unavailable\" disabled><span aria-hidden=\"true\">◷</span></button>".into());
    let label_control = rendered.metadata.as_ref().map(|metadata| format!("<details class=\"reader-labels\"><summary>Labels</summary><div><p>Manage private labels for this message. Its current identity is checked before changes.</p><a class=\"button-link secondary\" href=\"/labels?mailbox={}&amp;uid={}&amp;mailbox_guid={}&amp;message_guid={}\">Edit message labels</a></div></details>", escape_html(&url_encode(&rendered.mailbox_name)), rendered.uid, escape_html(&url_encode(&metadata.version.mailbox_guid)), escape_html(&url_encode(&metadata.version.message_guid)))).unwrap_or_else(|| "<span class=\"muted\" aria-disabled=\"true\">Labels unavailable</span>".into());
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
        attachments.push_str("<li class=\"attachment-item\">No attachments.</li>");
    } else {
        for attachment in &displayed_attachments {
            let mut download_href = format!(
                "/attachment?mailbox={}&uid={}&part={}",
                url_encode(&rendered.mailbox_name),
                rendered.uid,
                url_encode(&attachment.part_path),
            );
            if let Some(metadata) = &rendered.metadata {
                download_href.push_str(&format!(
                    "&mailbox_guid={}&message_guid={}&return_to={}",
                    url_encode(&metadata.version.mailbox_guid),
                    url_encode(&metadata.version.message_guid),
                    url_encode(return_to)
                ));
            }
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
                "<li class=\"attachment-item\"><div class=\"attachment-description\"><strong>{}</strong><p class=\"muted\">{} bytes · isolated download</p><details class=\"reader-file-details\"><summary>File details</summary><p>Part {}. {}, {}{}</p></details></div><a class=\"button-link\" href=\"{}\">Download</a></li>",
                escape_html(attachment.filename.as_deref().unwrap_or("<unnamed>")),
                attachment.size_hint_bytes,
                escape_html(&attachment.part_path),
                escape_html(&attachment.content_type),
                escape_html(attachment.disposition.as_str()),
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

    let move_form = render_reader_move_controls(
        csrf_token,
        rendered,
        archive_mailbox_name,
        user_visible_mailboxes,
        return_to,
    );
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

    let remote_content_state = if rendered.contains_html_body {
        "blocked by policy"
    } else {
        "not requested by selected body"
    };
    let source_link = rendered.metadata.as_ref().map(|metadata| format!(
        "<a class=\"reader-source-shortcut\" href=\"{}\">View source</a>", escape_html(&format!("/message?mailbox={}&uid={}&view=source&mailbox_guid={}&message_guid={}&return_to={}",
            url_encode(&rendered.mailbox_name), rendered.uid, url_encode(&metadata.version.mailbox_guid), url_encode(&metadata.version.message_guid), url_encode(return_to)))))
        .unwrap_or_else(|| "<span class=\"muted reader-source-shortcut\">Source view unavailable</span>".into());
    let compose_link = |mode: &str, label: &str| {
        let mut href = format!(
            "/compose?mode={mode}&mailbox={}&uid={}",
            url_encode(&rendered.mailbox_name),
            rendered.uid
        );
        if let Some(metadata) = &rendered.metadata {
            href.push_str(&format!(
                "&mailbox_guid={}&message_guid={}",
                url_encode(&metadata.version.mailbox_guid),
                url_encode(&metadata.version.message_guid)
            ));
        }
        format!(
            "<a class=\"button-link\" href=\"{}\">{label}</a>",
            escape_html(&href)
        )
    };
    let protected_reader_strip = format!(
        concat!(
            "<details class=\"protected-trust-strip\" aria-label=\"Protected by Default reader trust strip\"><summary><strong>Protected by Default</strong><span>Remote content blocked</span></summary>",
            "<div><strong>Protected by Default</strong><p>Verified signatures do not make content safe. Rendered and future decrypted content must still pass protected rendering.</p></div>",
            "<div class=\"trust-strip-badges\" aria-label=\"Reader protection states\">",
            "<span class=\"badge badge-ok\">Remote content blocked</span>",
            "<span class=\"badge\">{} rendering</span>",
            "<span class=\"badge\">Source is never active HTML</span>",
            "</div></details>"
        ),
        escape_html(rendered.rendering_mode.as_str()),
    );
    let openpgp_reader_states = rendered.openpgp.as_ref().map(crate::openpgp_reader_ui::render).unwrap_or_else(|| concat!(
        "<details class=\"openpgp-reader-states\" aria-label=\"OpenPGP reader states\" data-openpgp-reader-states=\"ui-only\"><summary><strong>OpenPGP unavailable</strong><span>Signature not verified</span></summary>",
        "<div><strong>OpenPGP reader state</strong><p>No account OpenPGP capability is configured for this reader session. No decrypt, verify, key discovery, private-key access, or passphrase handling was attempted.</p></div>",
        "<dl class=\"openpgp-state-list\"><dt>Encrypted</dt><dd>not assessed</dd><dt>Decrypted on mail host</dt><dd>not produced</dd><dt>Signature</dt><dd>not verified</dd><dt>Signer</dt><dd>unknown until configured evidence exists</dd><dt>Missing key</dt><dd>not actionable in this UI-only slice</dd></dl>",
        "<p class=\"muted openpgp-boundary-note\">Verified signatures do not make content safe. Future decrypted content must still pass Protected by Default rendering.</p>",
        "</details>"
    ).to_string());
    let toolbar = if let Some(neighbours) = neighbours {
        reader_toolbar::render(
            csrf_token,
            rendered,
            archive_mailbox_name,
            user_visible_mailboxes,
            back_href,
            return_to,
            neighbours,
            &compose_link("reply", "Reply to message"),
            &label_control,
            &snooze_control,
            &move_form,
        )
    } else {
        format!(concat!(
            "<div class=\"reader-toolbar\"><nav class=\"reader-navigation toolbar\" aria-label=\"Reader navigation\"><a href=\"{}\">Back to list</a>{}</nav><div class=\"reader-quick-actions\">{}{label_control}{snooze_control}</div>",
            "{navigation}<details class=\"reader-more-actions\"><summary>Move, archive, bin or restore</summary><div class=\"action-stack\">{}</div></details></div>",

        ), escape_html(back_href), &source_link, render_message_state_controls(csrf_token, &rendered.mailbox_name, rendered.uid, &rendered.flags, rendered.metadata.as_ref(), return_to), &move_form, navigation = navigation, label_control = label_control, snooze_control = snooze_control)
    };
    format!(
        concat!(
            "<article id=\"reading-pane\" class=\"reading-pane protected-reading-pane\" tabindex=\"-1\" aria-labelledby=\"message-title\" data-reader-mode=\"Protected Reader\">",
            "{toolbar}",
            "<header class=\"message-heading\"><div class=\"reader-message-top\"><h2 id=\"message-title\" dir=\"auto\">{}</h2><p class=\"muted reader-date\">{} · {}</p></div><div class=\"reader-message-person\"><span class=\"message-avatar\" aria-hidden=\"true\">{}</span><div><p class=\"message-from\" dir=\"auto\">From: {}</p><p class=\"muted reader-to\" dir=\"auto\">To: {}</p></div></div></header>",
            "<div class=\"reader-status\">{}{}{}</div>",
            "<span id=\"reading-title\" class=\"sr-only\">Reading Pane</span>",
            "<div class=\"reader-section-heading sr-only\" data-protected-body-panel=\"true\"><span class=\"badge badge-ok\">Protected rendering</span></div><p class=\"notice reader-boundary-note\">Message content is displayed with active content and remote images removed.</p><section class=\"body-panel\"><h2 class=\"sr-only\">Body</h2>{}</section>",
            "<section class=\"panel reader-attachments\"><h2>{}</h2><ul class=\"attachment-list\">{}</ul></section>",
            "<div class=\"toolbar reader-primary-actions\" aria-label=\"Message actions\">{}{}{}</div>",
            "<details class=\"reader-details\"><summary>Message details</summary>{}{}{}<dl class=\"message-meta reader-meta\"><dt>Subject</dt><dd dir=\"auto\">{}</dd><dt>From</dt><dd dir=\"auto\">{}</dd><dt>To</dt><dd dir=\"auto\">{}</dd><dt>Cc</dt><dd dir=\"auto\">{}</dd><dt>Mailbox</dt><dd>{}</dd><dt>UID</dt><dd>{}</dd><dt>Received</dt><dd>{}</dd><dt>MIME Type</dt><dd>{}</dd><dt>Body Source</dt><dd>{}</dd><dt>Rendering Mode</dt><dd>{}</dd><dt>HTML Present</dt><dd>{}</dd><dt>Protection</dt><dd>Protected by Default</dd><dt>Remote Content</dt><dd>{}</dd></dl></details>",
            "</article>"
        ),
        escape_html(rendered.subject.as_deref().unwrap_or("(No subject)")),
        escape_html(&rendered.mailbox_name), escape_html(&rendered.date_received),
        escape_html(&sender_initials(rendered.from.as_deref())),
        escape_html(rendered.from.as_deref().unwrap_or("Sender unavailable")),
        escape_html(rendered.to.as_deref().unwrap_or("Not present")),
        protected_reader_strip, openpgp_reader_states, if standalone { &source_link } else { "" },
        rendered.body_html, if standalone { format!("Attachments ({})", rendered.attachments.len()) } else { "Attachments".into() }, attachments,
        compose_link("reply", "Reply"), compose_link("reply-all", "Reply all"), compose_link("forward", "Forward"),
        html_state_badge, rendering_notice, inline_image_notice,
        escape_html(rendered.subject.as_deref().unwrap_or("(No subject)")), escape_html(rendered.from.as_deref().unwrap_or("Sender unavailable")),
        escape_html(rendered.to.as_deref().unwrap_or("Not present")), escape_html(rendered.cc.as_deref().unwrap_or("Not present")),
        escape_html(&rendered.mailbox_name), rendered.uid, escape_html(&rendered.date_received),
        escape_html(&rendered.mime_top_level_content_type), escape_html(rendered.body_source.as_str()),
        escape_html(rendered.rendering_mode.as_str()), if rendered.contains_html_body { "yes" } else { "no" }, remote_content_state,
        toolbar = toolbar,
    )
}

/// Renders the compose page for the current user and CSRF-bound session.
fn render_live_openpgp_compose_controls(model: &ComposePageModel<'_>) -> String {
    let checked = |selected| if selected { " checked" } else { "" };
    let stale_binding = model
        .protection
        .binding_revision
        .zip(model.openpgp.as_ref().and_then(|view| view.revision))
        .is_some_and(|(saved, current)| saved != current);
    let review_action = if stale_binding {
        let disabled = if model.draft_id.is_some() && model.draft_revision.is_none() {
            " disabled"
        } else {
            ""
        };
        format!("<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"preflight\">Review current keys</button>")
    } else {
        String::new()
    };
    let revision = model
        .protection
        .binding_revision
        .or_else(|| model.openpgp.as_ref().and_then(|view| view.revision));
    let revision_field = revision
        .map(|value| {
            format!("<input type=\"hidden\" name=\"pgp_binding_revision\" value=\"{value}\">")
        })
        .unwrap_or_default();
    let (summary, status, requirements) = match model.openpgp.as_ref().and_then(|view| {
        view.preflight.as_ref().map(|preflight| (view, preflight))
    }) {
        Some((view, preflight)) => {
            let state = if stale_binding {
                "Keys changed — review required"
            } else if model.protection.sign || model.protection.encrypt
                || preflight.state == crate::openpgp_bindings::PreflightState::Blocked {
                crate::http::compose_protection::selection_text(preflight.state)
            } else {
                "No protection selected"
            };
            let recipients = preflight.recipients.iter().map(|recipient| {
                let readiness = match recipient.state {
                    crate::openpgp_bindings::KeyStatus::Ready => "Public key eligible",
                    crate::openpgp_bindings::KeyStatus::MissingBinding => "No approved key binding",
                    crate::openpgp_bindings::KeyStatus::InventoryUnavailable => "Key inventory unavailable",
                    crate::openpgp_bindings::KeyStatus::MissingKey => "Bound key missing",
                    crate::openpgp_bindings::KeyStatus::Revoked => "Key revoked",
                    crate::openpgp_bindings::KeyStatus::Expired => "Key expired",
                    crate::openpgp_bindings::KeyStatus::Invalid => "Key invalid",
                    crate::openpgp_bindings::KeyStatus::Unsupported => "Key unsupported",
                    crate::openpgp_bindings::KeyStatus::WrongUsage => "Key cannot encrypt",
                    crate::openpgp_bindings::KeyStatus::Ambiguous => "Key ambiguous",
                };
                let policy = match recipient.requirement {
                    crate::openpgp_bindings::Requirement::Required => "Encryption required",
                    crate::openpgp_bindings::Requirement::Optional => "Encryption optional",
                    crate::openpgp_bindings::Requirement::Disabled => "Encryption disabled",
                };
                format!("<li><span>{}</span>: {readiness}; {policy}</li>", escape_html(&recipient.address))
            }).collect::<String>();
            let reasons = preflight.reasons.iter().map(|reason| {
                use crate::openpgp_bindings::BlockReason;
                let message = match reason {
                    BlockReason::RecipientRequiresEncryption => "A recipient binding requires encryption. Select Encrypt on send, or explicitly edit that recipient's policy in Manage keys.",
                    BlockReason::RecipientForbidsEncryption => "A recipient binding disables encryption. Review that recipient's policy in Manage keys.",
                    BlockReason::RecipientKeyUnavailable => "A recipient has no eligible approved encryption key. Review Recipient key status.",
                    BlockReason::SigningRequired => "The account policy requires signing. Select Sign on send, or explicitly edit the account policy in Manage keys.",
                    BlockReason::SigningDisabled => "The account policy disables signing. Review the account policy in Manage keys.",
                    BlockReason::EncryptionRequired => "The account policy requires encryption. Select Encrypt on send, or explicitly edit the account policy in Manage keys.",
                    BlockReason::EncryptionDisabled => "The account policy disables encryption. Review the account policy in Manage keys.",
                    BlockReason::SigningUnavailable => "The approved signing public key is not eligible. Review the account key in Manage keys.",
                    BlockReason::EncryptedBccUnqualified => "Encrypted Bcc delivery is not available. Remove Bcc before an encrypted send.",
                    BlockReason::SelfRequiresEncryption => "Include my approved key requires Encrypt on send.",
                    BlockReason::SelfKeyUnavailable => "The account encryption public key is not eligible. Review the account key in Manage keys.",
                };
                format!("<li>{message}</li>")
            }).collect::<String>();
            let requirements = preflight.recipients.iter().map(|recipient| {
                let policy = match recipient.requirement {
                    crate::openpgp_bindings::Requirement::Required => "Encryption required",
                    crate::openpgp_bindings::Requirement::Optional => "Encryption optional",
                    crate::openpgp_bindings::Requirement::Disabled => "Encryption disabled",
                };
                format!("<li><span>{}</span>: {policy}</li>", escape_html(&recipient.address))
            }).collect::<String>();
            let policy = view.policy;
            let requirement = |value| match value {
                crate::openpgp_bindings::Requirement::Required => "required",
                crate::openpgp_bindings::Requirement::Optional => "optional",
                crate::openpgp_bindings::Requirement::Disabled => "disabled",
            };
            (
                state,
                format!("<p>Public-key eligibility for the addresses shown when this page loaded. It does not establish private-key readiness or delivery.</p><ul>{recipients}</ul>"),
                format!("<strong>{state}</strong><p>Account policy: signing {}; encryption {}.</p><ul>{requirements}</ul><ul>{reasons}</ul><p>After changing recipients or protection choices, use Pre-send check to save this draft and check the current choices without sending. Send checks the final choices again.</p>", requirement(policy.signing), requirement(policy.encryption)),
            )
        }
        None => (
            "Not checked",
            "<p>OpenPGP key status could not be checked. Public-key eligibility and private-key readiness are not confirmed.</p>".to_string(),
            "<strong>Recipient protection not checked</strong><p>Use Pre-send check after entering recipients to save this draft and check current keys and policy without sending. A selected protected send pauses if its checks fail; it does not fall back to plaintext.</p>".to_string(),
        ),
    };
    format!(
        "<section class=\"openpgp-compose-controls compose-policy-row\" aria-label=\"OpenPGP compose controls\" data-openpgp-compose-controls=\"server-enforced\">{revision_field}<label class=\"compose-protection-choice\"><span>Sign</span><span class=\"compose-choice-toggle\"><input type=\"checkbox\" name=\"pgp_sign\"{}/> Sign on send</span></label><label class=\"compose-protection-choice\"><span>Encrypt</span><span class=\"compose-choice-toggle\"><input type=\"checkbox\" name=\"pgp_encrypt\"{}/> Encrypt on send</span></label><label class=\"compose-protection-choice\"><span>Encrypt to self</span><span class=\"compose-choice-toggle\"><input type=\"checkbox\" name=\"pgp_self\"{}/> Include my approved key</span></label><details class=\"compose-key-status\"><summary><span>Recipient key status</span><strong>{summary}</strong></summary><div class=\"compose-policy-detail\">{status}</div></details><div class=\"compose-key-management\"><span>Approved keys</span>{review_action}<a href=\"/settings/keys\" target=\"_blank\" rel=\"noopener noreferrer\">Manage keys</a></div></section><div class=\"notice compose-protection-requirements\" role=\"status\" data-protection-snapshot=\"page-load\">{requirements}</div>",
        checked(model.protection.sign),
        checked(model.protection.encrypt),
        checked(model.protection.encrypt_to_self),
    )
}

pub(crate) fn render_compose_page(model: &ComposePageModel<'_>) -> TrustedHtml {
    let confirmation_required = model.draft_id.is_some() && model.draft_revision.is_none();
    let (save_state, save_status) = if confirmation_required {
        (
            "unconfirmed",
            "Save not confirmed — compare with the stored version.",
        )
    } else if model.error_message.is_some()
        || (model.draft_id.is_none()
            && [
                model.to_value,
                model.cc_value,
                model.bcc_value,
                model.subject_value,
                model.body_value,
            ]
            .iter()
            .any(|value| !value.is_empty()))
    {
        (
            "unsaved",
            "Unsaved changes — Save Draft to keep this version.",
        )
    } else if model.draft_id.is_some() {
        ("saved", "Saved draft.")
    } else {
        ("new", "Not saved yet.")
    };
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Submission complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner =
        match model.error_message {
            Some(error_message) => {
                format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>{}</strong> {}</div>",
            if confirmation_required { "Save not confirmed:" } else { "Request failed:" },
            escape_html(error_message)
        )
            }
            None => String::new(),
        };
    let context_banner = match model.context_notice {
        Some(context_notice) => format!(
            "<div class=\"notice\"><strong>Context:</strong> {}</div>",
            escape_html(context_notice)
        ),
        None => String::new(),
    };
    let sender_initial = sender_initials(Some(model.canonical_username));
    let sender_label = model
        .sender_identity
        .map(|identity| identity.display_name())
        .filter(|name| !name.is_empty())
        .unwrap_or(&sender_initial);
    let sender_detail = match model.sender_identity {
        Some(identity) => format!("{} Reply-to: {}. Only {} is authorized as the sender.",
            if model.draft_id.is_some() { "This draft keeps its captured identity after profile changes." }
            else { "Current profile shown; preferences are captured when first saved or submitted and may change before then." },
            identity.reply_to().unwrap_or(model.canonical_username), model.canonical_username),
        None if model.draft_id.is_some() => "Captured sender presentation is unavailable in this response. Open the saved draft to inspect it; current profile values have not been substituted.".into(),
        None => "Sender preferences could not be confirmed here. New messages capture the account profile when first saved or submitted.".into(),
    };
    let intent_field = format!(
        "<input type=\"hidden\" name=\"send_intent\" value=\"{}\">",
        escape_html(model.send_intent)
    );
    let mut draft_id_field = model
        .draft_id
        .map(|draft_id| {
            format!(
                "<input type=\"hidden\" name=\"draft_id\" value=\"{}\">",
                escape_html(draft_id)
            )
        })
        .unwrap_or_default();
    draft_id_field.push_str(&intent_field);
    if let Some(revision) = model.draft_revision {
        draft_id_field.push_str(&format!(
            "<input type=\"hidden\" name=\"draft_revision\" value=\"{revision}\">"
        ));
    }
    if model.error_message.is_some() {
        if let Some(draft_id) = model.draft_id {
            draft_id_field.push_str(&format!("<p class=\"notice\"><a href=\"/draft?id={}\" target=\"_blank\" rel=\"noopener\">Open saved version in a new tab</a>. Keep this tab open to preserve your unsaved text.</p>", url_encode(draft_id)));
        }
    }
    let draft_attachment_notice = render_saved_attachment_controls(model);
    let (discard_control, discard_form) = crate::http::compose_actions::discard_controls(model);
    let source_attachment_controls = render_source_attachment_controls(
        model.source_mailbox_name,
        model.source_uid,
        model.source_attachments,
        model.selected_source_part_paths,
    );
    let openpgp_compose_controls = if model.openpgp.is_some()
        || model.protection.sign
        || model.protection.encrypt
        || model.protection.encrypt_to_self
    {
        render_live_openpgp_compose_controls(model)
    } else {
        concat!(
        "<section class=\"openpgp-compose-controls compose-policy-row\" aria-label=\"OpenPGP compose controls\" data-openpgp-compose-controls=\"ui-only\">",
        "<details name=\"compose-policy\"><summary><span>Sign</span><strong>Unsigned</strong></summary><div class=\"compose-policy-detail\"><p>Signing is unavailable for this account.</p></div></details>",
        "<details name=\"compose-policy\"><summary><span>Encrypt</span><strong>Not encrypted</strong></summary><div class=\"compose-policy-detail\"><p>Encryption is unavailable for this account.</p></div></details>",
        "<details name=\"compose-policy\"><summary><span>Encrypt to self</span><strong>Off</strong></summary><div class=\"compose-policy-detail\"><p>No encrypted copy will be created for your account.</p></div></details>",
        "<details name=\"compose-policy\"><summary><span>Recipient key status</span><strong>Unavailable</strong></summary><div class=\"compose-policy-detail\"><p>Recipient keys have not been checked. OpenPGP is unavailable for this account.</p></div></details>",
        "<details name=\"compose-policy\" class=\"compose-policy-attention\"><summary><span>Security pre-flight</span><strong>Attention</strong></summary><div class=\"compose-policy-detail\"><p>This message will be sent without OpenPGP protection.</p><p class=\"openpgp-compose-boundary-note\">Send Message and Save Draft use unencrypted message content.</p></div></details>",
        "</section>"
        ).to_string()
    };

    TrustedHtml::from_template(format!(
        concat!(
            "{}",
            "<main id=\"main-content\" class=\"page-shell compose-shell\" tabindex=\"-1\">",
            "<div class=\"page-intro\"><h1>{}</h1><p>Create mail with drafts, attachments, delivery controls and OpenPGP policy.</p></div>",
            "{}{}{}",
            "<section class=\"content-pane compose-card\">",
            "<form id=\"compose-form\" data-enhancement=\"local-v1\" data-save-state=\"{save_state}\" method=\"post\" action=\"/send\" enctype=\"multipart/form-data\">",
            "<div class=\"compose-card-header\"><h2>{}</h2><div class=\"compose-window-actions\"><button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"minimize\" title=\"Save this draft and return to Drafts\">− Minimize</button><input class=\"sr-only compose-expand-state\" id=\"compose-expanded\" type=\"checkbox\"><label class=\"button-link\" for=\"compose-expanded\"><span class=\"expand-text\">↗ Expand</span><span class=\"collapse-text\">↙ Restore</span></label><details class=\"compose-more\"><summary>⋮ More</summary><div><a href=\"/drafts\">Open Drafts</a><a href=\"/contacts\" target=\"_blank\" rel=\"noopener\">Manage contacts</a></div></details></div></div>",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            "{}",
            "{}",
            "{}",
            "<div class=\"compose-field\"><label for=\"compose-from\">From</label><div class=\"compose-sender\"><span class=\"compose-sender-chip\" >{sender_label}</span><input id=\"compose-from\" name=\"from\" value=\"{}\" readonly aria-describedby=\"sender-policy\"><details class=\"compose-sender-details\"><summary>Sender details</summary><p id=\"sender-policy\">{sender_detail}</p></details></div></div>",
            "<div class=\"compose-field\"><label for=\"compose-to\">To</label><input id=\"compose-to\" type=\"text\" name=\"to\" value=\"{}\" autocomplete=\"off\"></div>",
            "<div class=\"compose-recipient-tools\"><details class=\"compose-cc\"{}><summary>+ Cc</summary><label for=\"compose-cc\">Cc</label><input id=\"compose-cc\" type=\"text\" name=\"cc\" value=\"{}\" autocomplete=\"off\"></details>",
            "<details class=\"compose-bcc\"{}><summary>+ Bcc</summary><label for=\"compose-bcc\">Bcc</label><input id=\"compose-bcc\" type=\"text\" name=\"bcc\" value=\"{}\" autocomplete=\"off\"></details>{}</div>",
            "<div class=\"compose-field compose-subject-field\"><label for=\"compose-subject\">Subject</label><input id=\"compose-subject\" type=\"text\" name=\"subject\" value=\"{}\"></div>",
            "{}",
            "{formatting_controls}<label class=\"sr-only\" for=\"compose-body\">Body</label><textarea id=\"compose-body\" name=\"body\" placeholder=\"Write your message…\">\n{}</textarea>{preview}{preflight}",
            "<section class=\"compose-attachments\" aria-labelledby=\"compose-attachments-heading\"><h2 id=\"compose-attachments-heading\">Attachments</h2>{}{}<label for=\"compose-attachment\">Add attachments</label><input id=\"compose-attachment\" type=\"file\" name=\"attachment\" multiple><details class=\"compose-attachment-help\"><summary>Attachment help</summary><p>Up to 3 attachments, 10 MiB each and 30 MiB total, including saved and selected source files. Local images have a 5 MiB limit. Select Remove, then Save Draft or Send Message to apply removal. Other saved files stay attached.</p></details></section>",
            "<div class=\"compose-save-bar\"><p id=\"compose-save-status\" role=\"status\" aria-live=\"polite\" data-state=\"{save_state}\">{save_status}</p><span id=\"compose-auto-status\" class=\"muted\" role=\"status\">Auto-save requires scripting. Save Draft remains available.</span></div>",
            "<div class=\"compose-footer\"><div class=\"compose-footer-actions\">{discard_control}<button id=\"compose-save\" type=\"submit\"{disabled} formaction=\"/drafts/save\" aria-keyshortcuts=\"Control+S Meta+S\">Save Draft</button><button type=\"button\" disabled aria-describedby=\"compose-schedule-status\">Schedule</button><span id=\"compose-schedule-status\" class=\"muted\">Scheduling unavailable</span>{footer_more}</div>",
            "{send_controls}",
            "</div>",
            "</form>{discard_form}",
            "</section>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "compose").replace(" data-compose-theme", if confirmation_required { " disabled data-compose-theme" } else { " data-compose-theme" }),
        escape_html(model.heading),
        success_banner,
        error_banner,
        context_banner,
        if confirmation_required { "Save not confirmed" } else if model.draft_id.is_some() { "Saved Draft" } else { "New Message" },
        escape_html(model.csrf_token),
        draft_id_field,
        render_source_attachment_hidden_fields(model.source_mailbox_name, model.source_uid, model.source_version),
        render_reply_reference(model.reply_reference), escape_html(model.canonical_username),
        escape_html(model.to_value),
        if model.cc_value.is_empty() { "" } else { " open" },
        escape_html(model.cc_value),
        if model.bcc_value.is_empty() { "" } else { " open" },
        escape_html(model.bcc_value),
        render_contact_selection(model.contacts, confirmation_required),
        escape_html(model.subject_value),
        openpgp_compose_controls,
        escape_html(model.body_value),
        draft_attachment_notice,
        source_attachment_controls,
        disabled = if confirmation_required { " disabled" } else { "" },
        save_state = save_state,
        save_status = save_status,
        discard_control = discard_control,
        discard_form = discard_form,
        formatting_controls = crate::http::compose_actions::formatting_controls(model),
        preview = crate::http::compose_actions::preview(model),
        preflight = crate::http::compose_preflight::render(model),
        footer_more = crate::http::compose_delivery_ui::footer_more(model),
        send_controls = crate::http::compose_delivery_ui::send_controls(model),
        sender_label = escape_html(sender_label),
        sender_detail = escape_html(&sender_detail),
    ))
}

fn format_draft_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn render_saved_attachment_controls(model: &ComposePageModel<'_>) -> String {
    if model.draft_attachments.is_empty() && model.removed_attachment_indices.is_empty() {
        return String::new();
    }
    let mut rows = String::new();
    for (index, attachment) in model.draft_attachments.iter().enumerate() {
        rows.push_str(&format!("<li class=\"saved-attachment\" data-bytes=\"{}\"><div><strong dir=\"auto\">📄 {}</strong><span class=\"muted\">{} · saved file</span></div><label class=\"saved-attachment-remove\"><input type=\"checkbox\" name=\"remove_saved_attachment_{index}\" value=\"1\" aria-label=\"Remove {}\"{}><span>Remove</span></label></li>", attachment.body.len(), escape_html(&attachment.filename), format_draft_bytes(attachment.body.len() as u64), escape_html(&attachment.filename), if model.removed_attachment_indices.contains(&index) { " checked" } else { "" }));
    }
    // A failed stale form must not borrow attachment names from a newer revision.
    // Retain its explicit indices, still bound to the submitted draft revision.
    if model.draft_attachments.is_empty() {
        for index in model.removed_attachment_indices {
            rows.push_str(&format!("<li class=\"saved-attachment\"><label class=\"checkbox-row\"><input type=\"checkbox\" name=\"remove_saved_attachment_{index}\" value=\"1\" checked>Remove saved file {}</label></li>", index + 1));
        }
    }
    let count = if model.draft_attachments.is_empty() {
        "Your pending removal selection is retained.".into()
    } else {
        format!("{} stored attachment(s).", model.draft_attachments.len())
    };
    format!("<div class=\"saved-attachments\"><ul class=\"saved-attachment-list\">{rows}</ul><p class=\"sr-only compose-attachment-guidance\">{count} Select Remove, then Save Draft or Send Message to apply. Other saved files stay attached.</p></div>")
}

fn render_reply_reference(reference: Option<&crate::reply_thread::ReplyReference>) -> String {
    reference
        .map(|reference| {
            format!(
                concat!(
                    "<input type=\"hidden\" name=\"reply_mailbox\" value=\"{}\">",
                    "<input type=\"hidden\" name=\"reply_uid\" value=\"{}\">",
                    "<input type=\"hidden\" name=\"reply_mailbox_guid\" value=\"{}\">",
                    "<input type=\"hidden\" name=\"reply_message_guid\" value=\"{}\">"
                ),
                escape_html(&reference.mailbox_name),
                reference.uid,
                escape_html(&reference.version.mailbox_guid),
                escape_html(&reference.version.message_guid)
            )
        })
        .unwrap_or_default()
}

fn render_contact_selection(
    book: Option<&crate::contacts::ContactBook>,
    confirmation_required: bool,
) -> String {
    let manage =
        "<a href=\"/contacts\" target=\"_blank\" rel=\"noopener\">Manage contacts in a new tab</a>";
    let Some(book) = book else {
        return format!("<details class=\"compose-contacts\"><summary>Contacts</summary><div><p class=\"muted\">Contacts are unavailable. {manage}</p></div></details>");
    };
    if book.contacts.is_empty() {
        return format!("<details class=\"compose-contacts\"><summary>Contacts</summary><div><p class=\"muted\">No saved contacts. {manage}</p></div></details>");
    }
    let options: String = book
        .contacts
        .iter()
        .map(|contact| {
            format!(
                "<option value=\"{}\">{} &lt;{}&gt;</option>",
                escape_html(&contact.id),
                escape_html(&contact.display_name),
                escape_html(&contact.address)
            )
        })
        .collect();
    format!(concat!(
        "<details class=\"compose-contacts panel\"><summary>Choose a contact</summary>",
        "<p>Adding a contact saves this message as a draft, including selected uploads.</p>",
        "<input type=\"hidden\" name=\"contact_revision\" value=\"{}\">",
        "<label for=\"compose-contact\">Saved contact</label><select id=\"compose-contact\" name=\"contact_id\"><option value=\"\">Choose a saved contact</option>{}</select>",
        "<label for=\"compose-contact-target\">Add contact to</label><select id=\"compose-contact-target\" name=\"contact_target\"><option value=\"to\">To</option><option value=\"cc\">Cc</option><option value=\"bcc\">Bcc</option></select>",
        "<button type=\"submit\" formaction=\"/drafts/save\" name=\"compose_action\" value=\"add-contact\"{}>Add contact and save draft</button><p>{}</p></details>"
    ), book.revision, options, if confirmation_required { " disabled" } else { "" }, manage)
}

fn render_source_attachment_hidden_fields(
    source_mailbox_name: Option<&str>,
    source_uid: Option<u64>,
    source_version: Option<&crate::message_metadata::MessageVersion>,
) -> String {
    match (source_mailbox_name, source_uid) {
        (Some(mailbox), Some(uid)) => format!(
            concat!(
                "<input type=\"hidden\" name=\"source_mailbox\" value=\"{}\">",
                "<input type=\"hidden\" name=\"source_uid\" value=\"{}\">{}"
            ),
            escape_html(mailbox),
            uid,
            source_version.map(|version| format!("<input type=\"hidden\" name=\"source_mailbox_guid\" value=\"{}\"><input type=\"hidden\" name=\"source_message_guid\" value=\"{}\">", escape_html(&version.mailbox_guid), escape_html(&version.message_guid))).unwrap_or_default(),
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
    if source_mailbox_name.is_none() || source_uid.is_none() {
        return String::new();
    }
    if attachments.is_empty() {
        if selected_part_paths.is_empty() {
            return String::new();
        }
        let retained: String = selected_part_paths.iter().enumerate().map(|(index, path)| format!(
            "<label class=\"checkbox-row\"><input type=\"checkbox\" name=\"include_original_attachment_{}\" value=\"{}\" checked>Source attachment part {}</label>",
            index + 1, escape_html(path), escape_html(path))).collect();
        return format!("<fieldset class=\"panel\"><legend>Retained source attachments</legend><p>Your selection is retained and will be checked again when you save or send.</p>{retained}</fieldset>");
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
    let mut editable_count = 0;
    for draft in model.drafts {
        let mut matching = model
            .states
            .iter()
            .filter(|state| state.draft_id == draft.draft_id && state.revision == draft.revision);
        let state = matching
            .next()
            .filter(|_| matching.next().is_none())
            .map(|value| &value.state);
        if !matches!(state, Some(crate::http::BrowserDraftEditState::Editable)) {
            rows.push_str(&render_locked_draft_row(draft, state));
            continue;
        }
        editable_count += 1;
        let resume_href = format!("/draft?id={}", url_encode(&draft.draft_id));
        rows.push_str(&format!(
            concat!(
                "<tr data-draft-state=\"editable\">",
                "<td class=\"draft-select\"><input type=\"checkbox\" form=\"draft-selection\" name=\"selected_{}\" value=\"{}\"{checked} aria-label=\"Select draft: {}\"></td>",
                "<td class=\"draft-star\"><form method=\"post\" action=\"/drafts/star\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"draft_id\" value=\"{}\"><input type=\"hidden\" name=\"draft_revision\" value=\"{}\"><input type=\"hidden\" name=\"starred\" value=\"{}\">{}<button type=\"submit\" aria-label=\"{}\" aria-pressed=\"{}\" title=\"{}\">{}</button></form></td>",
                "<td class=\"draft-recipient\" dir=\"auto\"><div class=\"draft-recipient-person\"><span class=\"sender-avatar\" aria-hidden=\"true\">{}</span><span>{}</span></div></td>",
                "<td class=\"draft-subject\"><a href=\"{}\" dir=\"auto\">{}</a><span class=\"muted\">Draft saved, continue editing.</span></td>",
                "<td>{}</td>",
                "<td><span class=\"badge\">Draft</span></td>",
                "<td><time datetime=\"{}\">{}</time></td>",
                "<td>",
                "<details class=\"draft-discard\" name=\"draft-actions\"><summary aria-label=\"Draft actions\" title=\"Draft actions\">⋮</summary><div class=\"draft-action-menu\"><a class=\"draft-resume\" href=\"{}\">Resume</a><p>Discard this saved draft?</p>",
                "<form method=\"post\" action=\"/drafts/delete\">",
                "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
                "<input type=\"hidden\" name=\"draft_id\" value=\"{}\">",
                "<input type=\"hidden\" name=\"draft_revision\" value=\"{}\">",
                "{}",
                "<button type=\"submit\" name=\"confirm\" value=\"1\">Delete</button>",
                "</form></div></details>",
                "</td>",
                "</tr>"
            ),
            escape_html(&draft.draft_id), draft.revision, escape_html(if draft.subject.is_empty() { "(No subject)" } else { &draft.subject }),
            escape_html(model.csrf_token), escape_html(&draft.draft_id), draft.revision, u8::from(!draft.starred), render_draft_list_state(model.view),
            if draft.starred { "Unstar draft" } else { "Star draft" }, draft.starred, if draft.starred { "Unstar draft" } else { "Star draft" }, if draft.starred { "★" } else { "☆" },
            escape_html(&sender_initials(draft.recipient_preview.as_deref())),
            escape_html(draft.recipient_preview.as_deref().unwrap_or(if draft.recipient_count == 0 { "No recipients yet" } else { "Undisclosed recipients" })),
            escape_html(&resume_href),
            escape_html(if draft.subject.is_empty() { "(No subject)" } else { &draft.subject }),
            if draft.attachment_count > 0 { format!("<span class=\"draft-attachment-count\" aria-label=\"{} attachments\">📎 {}</span>", draft.attachment_count, draft.attachment_count) } else { "<span class=\"muted\" aria-label=\"No attachments\">—</span>".into() },
            crate::logging::format_unix_timestamp_utc(draft.updated_at),
            crate::logging::format_unix_timestamp_utc(draft.updated_at).replace('T', " ").replace('Z', " UTC"),
            escape_html(&resume_href),
            escape_html(model.csrf_token),
            escape_html(&draft.draft_id),
            draft.revision,
            render_draft_list_state(model.view),
            checked = if model.view.select_editable && editable_count <= crate::draft_list::MAX_DRAFT_SELECTION { " checked" } else { "" },
        ));
    }
    if rows.is_empty() {
        rows.push_str(if model.total_count == 0 { "<tr><td colspan=\"8\" class=\"muted\">No saved drafts.</td></tr>" } else { "<tr><td colspan=\"8\" class=\"muted\">No drafts match these filters. <a href=\"/drafts\">Show all drafts</a>.</td></tr>" });
    }

    TrustedHtml::from_template(format!(
        concat!(
            "{}",
            "<main id=\"main-content\" class=\"page-shell drafts-page\" tabindex=\"-1\">",
            "<div class=\"page-intro\"><h1>Drafts</h1><p>Resume, organize and safely discard saved messages.</p></div>{}{}",
            "<div class=\"draft-list-toolbar\"><details class=\"draft-selection-menu\"><summary>Select drafts</summary><nav aria-label=\"Draft selection\"><a href=\"{select_href}\">Select up to 10 editable drafts shown</a><a href=\"{clear_href}\">Clear selection</a><p>This checks current editable rows only. Review discard before confirming any deletion.</p></nav></details><form method=\"get\" action=\"/drafts\"><label class=\"sr-only\" for=\"draft-filter\">Draft filter</label><select id=\"draft-filter\" name=\"filter\">{}</select><label class=\"sr-only\" for=\"draft-sort\">Draft order</label><select id=\"draft-sort\" name=\"sort\">{}</select><label class=\"sr-only\" for=\"draft-query\">Search drafts</label><input id=\"draft-query\" name=\"q\" value=\"{}\" maxlength=\"200\" placeholder=\"Search subjects or recipients\"><button type=\"submit\">Apply</button></form><a class=\"button-link primary-button\" href=\"/compose\">+ New Message</a></div>",
            "<div class=\"table-wrap draft-list\" role=\"region\" aria-label=\"Saved drafts\" tabindex=\"0\"><table>",
            "<thead><tr><th><span class=\"sr-only\">Select</span></th><th><span class=\"sr-only\">Star</span></th><th>Recipient</th><th>Subject</th><th>Attachment</th><th>Status</th><th>Saved</th><th><span class=\"sr-only\">Actions</span></th></tr></thead>",
            "<tbody>{}</tbody>",
            "</table></div>",
            "<p class=\"draft-list-status muted\" role=\"status\">Showing {} of {} saved drafts</p><p class=\"draft-storage-status muted\">{}</p>",
            "<form id=\"draft-selection\" class=\"draft-selection-actions\" method=\"post\" action=\"/drafts/discard\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\">{}<p class=\"muted\">Select up to 10 editable drafts to discard together.</p><button type=\"submit\" name=\"stage\" value=\"review\"{review_disabled}>Review discard</button></form>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "drafts"),
        success_banner,
        error_banner,
        DraftFilter::ALL.iter().map(|filter| format!("<option value=\"{}\"{}>{}</option>", filter.value(), if *filter == model.view.filter { " selected" } else { "" }, filter.label())).collect::<String>(),
        DraftSort::ALL.iter().map(|sort| format!("<option value=\"{}\"{}>{}</option>", sort.value(), if *sort == model.view.sort { " selected" } else { "" }, sort.label())).collect::<String>(),
        escape_html(&model.view.query),
        rows,
        model.drafts.len(),
        model.total_count,
        render_draft_storage(model.usage),
        escape_html(model.csrf_token), render_draft_list_state(model.view),
        select_href = escape_html(&format!("{}&select=editable",model.view.href())),
        clear_href = escape_html(&format!("{}&select=clear",model.view.href())),
        review_disabled = if editable_count == 0 { " disabled" } else { "" },
    ))
}

fn render_locked_draft_row(
    draft: &DraftSummary,
    state: Option<&crate::http::BrowserDraftEditState>,
) -> String {
    use crate::http::BrowserDraftEditState as State;
    let (kind, label, explanation, intent) = match state {
        Some(State::Attempted { receipt_intent }) => (
            "attempted",
            "Attempt recorded",
            "Review the receipt; this saved version is read-only.",
            Some(receipt_intent),
        ),
        Some(State::Paused { receipt_intent }) => (
            "paused",
            "Paused",
            "Submission state needs review. This saved version is read-only.",
            Some(receipt_intent),
        ),
        _ => (
            "unknown",
            "Unavailable",
            "Editing status could not be verified. Reload Drafts before making changes.",
            None,
        ),
    };
    let intent = intent.filter(|value| crate::send_journal::receipt_intent_valid(value));
    let title = if draft.subject.is_empty() {
        "(No subject)"
    } else {
        &draft.subject
    };
    let links = if let Some(intent) = intent {
        format!("<a href=\"/compose?receipt={}\">View attempt</a><a href=\"/draft?id={}\">Saved version</a>", escape_html(&url_encode(intent)), escape_html(&url_encode(&draft.draft_id)))
    } else {
        "<a href=\"/drafts\">Reload Drafts</a>".into()
    };
    format!(concat!("<tr data-draft-state=\"{kind}\"><td class=\"draft-select\"><input type=\"checkbox\" disabled aria-label=\"Select draft: {title}\"></td><td class=\"draft-star\"><button disabled aria-label=\"Star unavailable\">{star}</button></td>",
        "<td class=\"draft-recipient\"><div class=\"draft-recipient-person\"><span class=\"sender-avatar\" aria-hidden=\"true\">{initials}</span><span>{recipient}</span></div></td><td class=\"draft-subject\"><strong dir=\"auto\">{title}</strong><span class=\"muted\">{explanation}</span></td><td>{files}</td><td><span class=\"badge\">{label}</span></td><td><time datetime=\"{utc}\">{time}</time></td><td><details class=\"draft-discard\"><summary aria-label=\"Draft actions\">⋮</summary><div class=\"draft-action-menu\">{links}<button disabled>Delete unavailable</button></div></details></td></tr>"),kind=kind,title=escape_html(title),star=if draft.starred {"★"} else {"☆"},initials=escape_html(&sender_initials(draft.recipient_preview.as_deref())),recipient=escape_html(draft.recipient_preview.as_deref().unwrap_or("No visible recipients")),explanation=explanation,files=if draft.attachment_count>0 {format!("{} files",draft.attachment_count)} else {"—".into()},label=label,utc=crate::logging::format_unix_timestamp_utc(draft.updated_at),time=crate::logging::format_unix_timestamp_utc(draft.updated_at).replace('T'," ").replace('Z'," UTC"),links=links)
}
fn render_draft_storage(usage: &crate::http::BrowserDraftStorageUsage) -> String {
    let size = |bytes: u64| {
        if bytes < 1024 {
            format!("{bytes} B")
        } else if bytes < 1024 * 1024 {
            format!("{} KiB", bytes.div_ceil(1024))
        } else {
            format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
        }
    };
    match usage {
        crate::http::BrowserDraftStorageUsage::Verified { ordinary_count, ordinary_bytes, recovery_count, recovery_bytes, max_count, max_bytes } => format!("Saved drafts: {ordinary_count} ({}). Retained attempts: {recovery_count} ({}). Combined storage: {} of {}; {} of {max_count} items. This limit covers drafts and attempt recovery.",size(*ordinary_bytes),size(*recovery_bytes),size(ordinary_bytes.saturating_add(*recovery_bytes)),size(*max_bytes),ordinary_count.saturating_add(*recovery_count)),
        crate::http::BrowserDraftStorageUsage::Unknown => "Combined storage usage could not be verified. Limits include saved drafts and retained attempts.".into(),
    }
}

fn render_draft_list_state(view: &DraftListView) -> String {
    format!("<input type=\"hidden\" name=\"filter\" value=\"{}\"><input type=\"hidden\" name=\"sort\" value=\"{}\"><input type=\"hidden\" name=\"q\" value=\"{}\">", view.filter.value(), view.sort.value(), escape_html(&view.query))
}

pub(crate) fn render_draft_selection_review(
    account: &str,
    csrf: &str,
    drafts: &[DraftSummary],
    view: &DraftListView,
) -> TrustedHtml {
    let rows: String = drafts.iter().map(|draft| format!("<li><strong dir=\"auto\">{}</strong><span class=\"muted\"> · {} attachment(s)</span><input type=\"hidden\" name=\"selected_{}\" value=\"{}\"></li>", escape_html(if draft.subject.is_empty() { "(No subject)" } else { &draft.subject }), draft.attachment_count, escape_html(&draft.draft_id), draft.revision)).collect();
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Discard selected drafts?</h1><p>Review these {} saved drafts before discarding their text and saved attachments.</p></div><section class=\"content-pane\"><form method=\"post\" action=\"/drafts/discard\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\">{}<ul class=\"draft-discard-review\">{}</ul><p>Discard cannot be undone. If a draft changes, discard stops; any earlier completed deletions remain.</p><div class=\"inline-actions\"><a class=\"button-link\" href=\"{}\">Keep drafts</a><button type=\"submit\" name=\"stage\" value=\"confirm\">Discard {} drafts</button></div></form></section></main>", app_header(account, csrf, "drafts"), drafts.len(), escape_html(csrf), render_draft_list_state(view), rows, escape_html(&view.href()), drafts.len()))
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
            openpgp: None,
            metadata: None,
            flags: Vec::new(),
            mailbox_name: "INBOX".to_string(),
            uid: 42,
            subject: Some("Decoded café".to_string()),
            from: Some("Example Sender <sender@example.invalid>".to_string()),
            to: Some("Reader <reader@example.invalid>".into()),
            cc: None,
            reply_metadata: None,
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
        assert!(page.contains("Remote content blocked"));
        assert!(page.contains("<strong>Sanitized HTML:</strong>"));
        assert!(page.contains("Remote content blocked by policy"));
        assert!(page.contains("Safe rendered body"));
    }
}

#[cfg(test)]
#[test]
fn draft_ui_unmatched_revision_and_duplicate_state_never_enable_editing() {
    use crate::http::{BrowserDraftEditState, BrowserDraftState, BrowserDraftStorageUsage};
    let drafts = vec![DraftSummary {
        draft_id: "a".repeat(32),
        created_at: 100,
        updated_at: 100,
        expires_at: 200,
        revision: 2,
        starred: false,
        storage_bytes: 1,
        recipient_count: 0,
        recipient_preview: None,
        subject: "Synthetic".into(),
        subject_len: 9,
        body_len: 1,
        attachment_count: 0,
        total_attachment_bytes: 0,
    }];
    let good = BrowserDraftState {
        draft_id: drafts[0].draft_id.clone(),
        revision: 2,
        state: BrowserDraftEditState::Editable,
    };
    let mut stale = good.clone();
    stale.revision = 1;
    for states in [vec![], vec![stale], vec![good.clone(), good.clone()]] {
        let view = DraftListView::parse(&[("select".into(), "editable".into())].into()).unwrap();
        let html = render_draft_list_page(&DraftListPageModel {
            canonical_username: "alice@example.test",
            csrf_token: "synthetic",
            success_message: None,
            error_message: None,
            drafts: &drafts,
            view: &view,
            total_count: 1,
            states: &states,
            usage: &BrowserDraftStorageUsage::Unknown,
        });
        let html = html.as_str();
        assert!(html.contains("data-draft-state=\"unknown\""));
        assert!(!html.contains("action=\"/drafts/star\""));
        assert!(!html.contains("action=\"/drafts/delete\""));
        assert!(!html.contains("continue editing"));
        assert!(!html.contains(" checked"));
        assert!(html.contains("Combined storage usage could not be verified"));
        assert!(html.contains("value=\"review\" disabled"));
    }
    let drafts: Vec<_> = (1..=12)
        .map(|id| {
            let mut d = drafts[0].clone();
            d.draft_id = format!("{id:032x}");
            d
        })
        .collect();
    let states: Vec<_> = drafts
        .iter()
        .map(|d| BrowserDraftState {
            draft_id: d.draft_id.clone(),
            revision: d.revision,
            state: BrowserDraftEditState::Editable,
        })
        .collect();
    let view = DraftListView::parse(&[("select".into(), "editable".into())].into()).unwrap();
    let html = render_draft_list_page(&DraftListPageModel {
        canonical_username: "alice@example.test",
        csrf_token: "synthetic",
        success_message: None,
        error_message: None,
        drafts: &drafts,
        view: &view,
        total_count: 12,
        states: &states,
        usage: &BrowserDraftStorageUsage::Unknown,
    });
    assert_eq!(html.as_str().matches(" checked").count(), 10);
    assert!(!view.href().contains("select="));
    assert!(!render_draft_list_state(&view).contains("select="));
    assert!(DraftListView::parse(&[("select".into(), "all".into())].into()).is_err());
}

#[cfg(test)]
#[path = "http_ui_state_tests.rs"]
mod mail_state_tests;
