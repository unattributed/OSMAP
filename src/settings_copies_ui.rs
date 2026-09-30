//! PAGE16 folder settings backed by the existing account settings store.
use super::*;

pub(crate) fn render_copies_page(
    model: &SettingsPageModel<'_>,
    mailboxes: Option<&[MailboxEntry]>,
) -> TrustedHtml {
    let entries = mailboxes.unwrap_or(&[]);
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
            "<li><a href=\"/mailbox?name={}\">{}<span>{}</span></a></li>",
            url_encode(&entry.name),
            shell_icon("folders"),
            escape_html(&entry.name)
        ));
    }
    if rows.is_empty() {
        rows.push_str("<li>No available mailbox listing.</li>");
    }
    let chosen = model
        .archive_mailbox_name
        .filter(|name| has(name))
        .or_else(|| entries.first().map(|v| v.name.as_str()));
    let selected = chosen.map_or_else(|| "<p>No available folder to inspect.</p>".to_owned(), |name| format!("<h3>{}</h3><dl><dt>Messages</dt><dd>Unknown</dd><dt>Mailbox owner</dt><dd>{}</dd></dl><a class=\"button-link\" href=\"/mailbox?name={}\">Open folder</a>", escape_html(name), escape_html(model.canonical_username), url_encode(name)));
    let notices = [
        (model.success_message, "status"),
        (model.error_message, "alert"),
    ]
    .into_iter()
    .filter_map(|(v, role)| {
        v.map(|v| format!("<p class=\"notice\" role=\"{role}\">{}</p>", escape_html(v)))
    })
    .collect::<String>();
    let open = |name: &str, label: &str| {
        if has(name) {
            format!("<a href=\"/mailbox?name={}\">{label}</a>", url_encode(name))
        } else {
            format!("<span aria-disabled=\"true\">{label}: unavailable</span>")
        }
    };
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-copies-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Review fixed storage locations and choose an Archive folder.</p></div>{notices}<div class=\"settings-layout\">{nav}<div class=\"copies-content\"><div class=\"copies-top-grid\">",
        "<section class=\"general-card\"><h2>Copies</h2><div class=\"general-field\"><span>Save sent messages</span><span>Submission workflow (fixed)</span></div><div class=\"general-field\"><label for=\"copies-sent\">Sent location</label><input id=\"copies-sent\" readonly value=\"Sent (fixed)\"></div><div class=\"general-field\"><label for=\"copies-drafts\">Draft location</label><input id=\"copies-drafts\" readonly value=\"OSMAP drafts (fixed)\"></div><div class=\"general-field\"><span>Keep Bcc private</span><span>Bcc omitted from message headers</span></div><div class=\"copies-links\">{sent}<a href=\"/drafts\">Open drafts</a></div></section>",
        "<section class=\"general-card\"><h2>Folders</h2><form id=\"copies-archive-form\" method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"return_section\" value=\"copies\"><input type=\"hidden\" name=\"settings_action\" value=\"archive\"><div class=\"general-field\"><label for=\"copies-archive\">Archive</label><select id=\"copies-archive\" name=\"archive_mailbox_name\"{disabled}>{options}</select></div></form><div class=\"general-field\"><label for=\"copies-bin\">Bin</label><input id=\"copies-bin\" readonly value=\"Trash (fixed)\"></div><div class=\"general-field\"><span>Delete action</span><span>Explicit message controls</span></div><div class=\"general-field\"><span>Permanent deletion</span><span>Unavailable here</span></div><div class=\"copies-links\">{bin}<button type=\"submit\" form=\"copies-archive-form\"{disabled}>Save archive folder</button></div></section></div>",
        "<section class=\"copies-management\"><div class=\"copies-management-heading\"><div><h2>Mailbox Folder Management</h2><p>Browse available mailboxes. Folder creation, rename, move and deletion are unavailable.</p></div><div class=\"copies-management-actions\"><button disabled>New subfolder</button><button disabled>Rename</button><button disabled>Move</button><button disabled>Delete</button></div></div>",
        "<div class=\"copies-browser\"><section class=\"copies-tree\"><h3>Available folders</h3><ul>{rows}</ul>{limit}</section><section class=\"copies-details\"><h3>Folder details</h3>{selected}<div class=\"copies-safety\"><h4>Folder safety</h4><p>Opening a folder does not change its contents. This page does not rename, move or delete folders.</p><p>Documents, scheduled storage and quota information are unavailable.</p></div></section></div></section><p class=\"copies-help\">{help}</p></div></div></main>"
    ), header=app_header(model.canonical_username,model.csrf_token,"settings-copies"), nav=settings_navigation("copies"), notices=notices, sent=open("Sent","Open Sent"), bin=open("Trash","Open Bin"), csrf=escape_html(model.csrf_token),disabled=if unavailable {" disabled"} else {""},options=options, rows=rows, selected=selected, limit=if entries.len()>DEFAULT_RENDERED_MAILBOXES_MAX {"<p>Mailbox display limit reached.</p>"} else {""},help=if unavailable {"The mailbox list could not be loaded. Archive changes are unavailable."} else if missing {"The stored Archive folder is unavailable. Select an available folder or Not configured before saving. The saved content preference is preserved."} else {"Archive changes preserve your saved content preference. Sent and draft storage locations cannot be changed here."}))
}
