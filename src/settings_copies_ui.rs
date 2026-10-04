//! PAGE16 folder settings backed by the existing account settings store.
use super::*;

fn render_sent_location_form(
    model: &SettingsPageModel<'_>,
    saved: Option<&crate::sent_location::Preference>,
    choices: Option<&[MailboxEntry]>,
) -> String {
    let Some(saved) = saved.filter(|saved| saved.valid()) else {
        return "<div class=\"general-field\"><label for=\"copies-sent-location\">Sent location</label><select id=\"copies-sent-location\" disabled><option>Unavailable</option></select></div><p>The saved Sent folder could not be loaded. Reload Copies &amp; Folders.</p>".into();
    };
    let entries = choices.unwrap_or(&[]);
    let visible = entries.iter().take(DEFAULT_RENDERED_MAILBOXES_MAX);
    let included = visible
        .clone()
        .any(|entry| entry.name == saved.mailbox_name);
    let mut options = String::new();
    if !included {
        let name = escape_html(&saved.mailbox_name);
        let unavailable = !entries.iter().any(|entry| entry.name == saved.mailbox_name);
        options.push_str(&format!(
            "<option value=\"{name}\" selected>{name}{}</option>",
            if unavailable { " (unavailable)" } else { "" }
        ));
    }
    for entry in visible {
        let name = escape_html(&entry.name);
        options.push_str(&format!(
            "<option value=\"{name}\"{}>{name}</option>",
            if entry.name == saved.mailbox_name {
                " selected"
            } else {
                ""
            }
        ));
    }
    let disabled = if choices.is_none() || entries.is_empty() {
        " disabled"
    } else {
        ""
    };
    format!("<form id=\"copies-sent-location-form\" method=\"post\" action=\"/settings/sent-location\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"expected_revision\" value=\"{}\"><div class=\"general-field\"><label for=\"copies-sent-location\">Sent location</label><select id=\"copies-sent-location\" name=\"mailbox_name\"{disabled}>{options}</select></div><button type=\"submit\"{disabled}>Save Sent folder</button></form><p class=\"general-help\">Choose an existing folder in this account. This changes where future Sent copies are saved; it does not move existing mail. An unavailable destination is reported separately from submission.</p>", escape_html(model.csrf_token), saved.revision)
}

pub(crate) struct CopiesPageState<'a> {
    pub mailboxes: Option<&'a [MailboxEntry]>,
    pub chosen: Option<&'a str>,
    pub counts: Option<(usize, usize)>,
    pub status: Option<&'a crate::mailbox_status::MailboxStatus>,
    pub hierarchy: Option<&'a crate::http::FolderTree>,
    pub creation: bool,
    pub bin: Option<&'a crate::bin_folder::BinPreference>,
    pub bin_choices: Option<&'a [MailboxEntry]>,
    pub sent_copy: Option<&'a crate::sent_copy::Preference>,
    pub sent_location: Option<&'a crate::sent_location::Preference>,
    pub sent_location_choices: Option<&'a [MailboxEntry]>,
}
pub(crate) fn render_copies_page_with_state(
    model: &SettingsPageModel<'_>,
    state: CopiesPageState<'_>,
) -> TrustedHtml {
    let CopiesPageState {
        mailboxes,
        chosen,
        counts,
        status,
        hierarchy,
        creation,
        bin,
        bin_choices,
        sent_copy,
        sent_location,
        sent_location_choices,
    } = state;
    let bin_form = render_bin_folder_form(model, "copies-bin", "copies", bin, bin_choices);
    let sent_copy_form = match sent_copy {
        Some(saved) => format!("<form id=\"copies-sent-copy-form\" method=\"post\" action=\"/settings/sent-copy\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"expected_revision\" value=\"{}\"><div class=\"general-field\"><label for=\"copies-save-sent\">Save sent messages</label><select id=\"copies-save-sent\" name=\"save_sent\"><option value=\"on\"{}>On</option><option value=\"off\"{}>Off</option></select></div><button type=\"submit\">Save Sent choice</button></form><p class=\"general-help\">The saved choice is captured when a new submission starts. Changing it never submits mail or changes an existing attempt. Off skips the Sent append; attempt recovery remains separate.</p>", escape_html(model.csrf_token), saved.revision, if saved.save_sent { " selected" } else { "" }, if saved.save_sent { "" } else { " selected" }),
        None => "<div class=\"general-field\"><label for=\"copies-save-sent\">Save sent messages</label><select id=\"copies-save-sent\" disabled><option>Unavailable</option></select></div><p>Saved copy preference unavailable. Reload Copies &amp; Folders before submitting.</p>".into(),
    };
    let entries = mailboxes.unwrap_or(&[]);
    let sent_location_form = render_sent_location_form(model, sent_location, sent_location_choices);
    let has = |name: &str| entries.iter().any(|v| v.name == name);
    let missing = model.archive_mailbox_name.is_some_and(|name| !has(name));
    let mut options = format!(
        "<option value=\"\"{}>Not configured</option>",
        if model.archive_mailbox_name.is_none() {
            " selected"
        } else {
            ""
        }
    );
    if missing
        || model.archive_mailbox_name.is_some_and(|stored| {
            !entries
                .iter()
                .take(DEFAULT_RENDERED_MAILBOXES_MAX)
                .any(|entry| entry.name == stored)
        })
    {
        let name = escape_html(model.archive_mailbox_name.unwrap_or(""));
        options.push_str(&format!(
            "<option value=\"{name}\" selected>{name}{}</option>",
            if missing { " (unavailable)" } else { "" }
        ));
    }
    for entry in entries.iter().take(DEFAULT_RENDERED_MAILBOXES_MAX) {
        let name = escape_html(&entry.name);
        options.push_str(&format!(
            "<option value=\"{name}\"{}>{name}</option>",
            if model.archive_mailbox_name == Some(entry.name.as_str()) {
                " selected"
            } else {
                ""
            }
        ));
    }
    let unavailable = mailboxes.is_none();
    let mut rows = String::new();
    for entry in entries.iter().take(DEFAULT_RENDERED_MAILBOXES_MAX) {
        rows.push_str(&format!(
            "<li><a href=\"/settings?section=copies&amp;folder={}\"{}>{}<span>{}</span></a></li>",
            url_encode(&entry.name),
            if chosen == Some(entry.name.as_str()) {
                " aria-current=\"true\""
            } else {
                ""
            },
            shell_icon("folders"),
            escape_html(&entry.name)
        ));
    }
    if let Some(tree) = hierarchy {
        rows = tree.render(chosen);
    }
    if rows.is_empty() {
        rows.push_str("<li>No available mailbox listing.</li>");
    }
    let (messages, unread) = counts.map_or_else(
        || ("Unknown".to_owned(), "Unknown".to_owned()),
        |(all, unread)| (all.to_string(), unread.to_string()),
    );
    let scope = if counts.is_some() {
        "Loaded unread covers up to 2,000 summaries before filters or snooze. Virtual size is not disk use or quota."
    } else {
        "Verified summary counts are unavailable. Opening this folder remains separate from selecting it."
    };
    let total = status.map_or_else(|| "Unknown".into(), |v| v.messages().to_string());
    let size = status.map_or_else(
        || "Unknown".into(),
        |v| format!("{} bytes", v.virtual_bytes()),
    );
    let selected = chosen.map_or_else(|| "<p>No available folder to inspect.</p>".to_owned(), |name| {
        let (parent,children)=hierarchy.map(|tree|tree.primary(name)).unwrap_or_else(||("Unknown".into(),"Unknown".into()));
        let facts=hierarchy.map(|tree|tree.details(name)).unwrap_or_else(||"<p>Hierarchy and reported roles are unavailable.</p>".into());
        format!("<h3>{}</h3><dl><dt>Parent</dt><dd>{parent}</dd><dt>Total messages</dt><dd data-folder-total>{total}</dd><dt>Visible direct subfolders</dt><dd>{children}</dd><dt>Mailbox owner</dt><dd>{}</dd></dl><a class=\"button-link\" href=\"/mailbox?name={}\">Open folder</a><details class=\"copies-secondary\"><summary>Folder details</summary><dl><dt>Virtual message size</dt><dd data-folder-vsize>{size}</dd><dt>Loaded unread</dt><dd><span data-folder-unread>{unread}</span> of <span data-folder-messages>{messages}</span> loaded</dd></dl>{facts}<p class=\"copies-count-scope\">{scope}</p></details>",escape_html(name),escape_html(model.canonical_username),url_encode(name))
    });
    let create = if creation {
        format!("<a class=\"button-link\" href=\"/settings/folders/create?parent={}\">New subfolder</a>",url_encode(chosen.unwrap_or("")))
    } else {
        "<button disabled>New subfolder</button>".into()
    };
    let notices = [
        (model.success_message, "status"),
        (model.error_message, "alert"),
    ]
    .into_iter()
    .filter_map(|(v, role)| {
        v.map(|v| format!("<p class=\"notice\" role=\"{role}\">{}</p>", escape_html(v)))
    })
    .collect::<String>();
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-copies-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Review storage locations and choose Archive and Bin folders.</p></div>{notices}<div class=\"settings-layout\">{nav}<div class=\"copies-content\"><div class=\"copies-top-grid\">",
        "<section class=\"general-card\"><h2>Copies</h2>{sent_copy_form}{sent_location_form}<div class=\"general-field\"><label for=\"copies-drafts\">Draft location</label><input id=\"copies-drafts\" readonly value=\"OSMAP drafts (fixed)\"></div><div class=\"general-field\"><span>Keep Bcc private</span><span>Bcc omitted from message headers</span></div><div class=\"copies-links\">{sent}<a href=\"/drafts\">Open drafts</a></div></section>",
        "<section class=\"general-card\"><h2>Folders</h2><form id=\"copies-archive-form\" method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"return_section\" value=\"copies\"><input type=\"hidden\" name=\"settings_action\" value=\"archive\"><div class=\"general-field\"><label for=\"copies-archive\">Archive</label><select id=\"copies-archive\" name=\"archive_mailbox_name\"{disabled}>{options}</select></div></form>{bin_form}<div class=\"general-field\"><span>Delete action</span><span>Explicit message controls</span></div><div class=\"general-field\"><span>Permanent deletion</span><span>Unavailable here</span></div><div class=\"copies-links\">{bin}<button type=\"submit\" form=\"copies-archive-form\"{disabled}>Save archive folder</button></div></section></div>",
        "<section class=\"copies-management\"><div class=\"copies-management-heading\"><div><h2>Mailbox Folder Management</h2><p>Browse available mailboxes. Rename, move and deletion are unavailable.</p></div><div class=\"copies-management-actions\">{create}<button disabled>Rename</button><button disabled>Move</button><button disabled>Delete</button></div></div>",
        "<div class=\"copies-browser\"><section class=\"copies-tree\"><h3>{tree_heading}</h3><ul>{rows}</ul>{limit}{tree_notice}</section><section class=\"copies-details\"><h3>Selected folder</h3>{selected}<div class=\"copies-safety\"><h4>Folder safety</h4><p>Opening folders does not change mail. Folder rename, move and delete are unavailable.</p><p>Documents, scheduled storage and quota information are unavailable.</p></div></section></div></section><p class=\"copies-help\">{help}</p></div></div></main>"
    ), sent_copy_form=sent_copy_form, sent_location_form=sent_location_form, bin_form=bin_form, create=create, header=app_header(model.canonical_username,model.csrf_token,"settings-copies"), nav=settings_navigation("copies"), tree_heading=if hierarchy.is_some(){"Folder hierarchy"}else{"Available folders"}, tree_notice=if hierarchy.is_some(){""}else{"<p class=\"copies-count-scope\">Hierarchy unavailable. The verified flat folder list remains available.</p>"}, notices=notices, sent="<a href=\"/mailbox/shortcut?kind=sent\">Open Sent</a>", bin="<a href=\"/mailbox/shortcut?kind=bin\">Open Bin</a>", csrf=escape_html(model.csrf_token),disabled=if unavailable {" disabled"} else {""},options=options, rows=rows, selected=selected, limit=if entries.len()>DEFAULT_RENDERED_MAILBOXES_MAX {"<p>Mailbox display limit reached.</p>"} else {""},help=if unavailable {"The mailbox list could not be loaded. Archive changes are unavailable."} else if missing {"The stored Archive folder is unavailable. Select an available folder or Not configured before saving. The saved content preference is preserved."} else {"Archive changes preserve your saved content preference. Sent changes apply to new copy attempts. Draft storage remains OSMAP drafts."}))
}
