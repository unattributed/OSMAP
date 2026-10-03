//! PAGE-14 native settings. Each save names the independent preference it writes.
use super::*;
use crate::reading_preferences::ReadingPreferences;

#[cfg(test)]
pub(crate) fn render_reading_page(
    model: &SettingsPageModel<'_>,
    preferences: &ReadingPreferences,
    mailboxes: Option<&[MailboxEntry]>,
) -> TrustedHtml {
    render_reading_page_with_after_archive(model, preferences, mailboxes, None)
}

#[cfg(test)]
pub(crate) fn render_reading_page_with_after_archive(
    model: &SettingsPageModel<'_>,
    preferences: &ReadingPreferences,
    mailboxes: Option<&[MailboxEntry]>,
    after_archive: Option<&crate::after_archive::Preference>,
) -> TrustedHtml {
    render_reading_page_with_policies(model, preferences, mailboxes, after_archive, None)
}

#[cfg(test)]
pub(crate) fn render_reading_page_with_policies(
    model: &SettingsPageModel<'_>,
    preferences: &ReadingPreferences,
    mailboxes: Option<&[MailboxEntry]>,
    after_archive: Option<&crate::after_archive::Preference>,
    mark_read: Option<&crate::mark_read::Preference>,
) -> TrustedHtml {
    render_reading_page_with_folders(
        model,
        preferences,
        mailboxes,
        after_archive,
        mark_read,
        None,
        None,
    )
}

pub(crate) fn render_reading_page_with_folders(
    model: &SettingsPageModel<'_>,
    preferences: &ReadingPreferences,
    mailboxes: Option<&[MailboxEntry]>,
    after_archive: Option<&crate::after_archive::Preference>,
    mark_read: Option<&crate::mark_read::Preference>,
    bin: Option<&crate::bin_folder::BinPreference>,
    bin_choices: Option<&[MailboxEntry]>,
) -> TrustedHtml {
    let bin_form = render_bin_folder_form(model, "reading-bin-folder", "reading", bin, bin_choices);
    let csrf = escape_html(model.csrf_token);
    let start = select_options(
        preferences.start_page.as_str(),
        &[
            ("mailbox", "Mailbox"),
            ("inbox", "Inbox"),
            ("drafts", "Drafts"),
            ("sent", "Sent"),
        ],
    );
    let order = select_options(
        preferences.date_order.as_str(),
        &[("newest", "Newest first"), ("oldest", "Oldest first")],
    );
    let after_options = after_archive
        .map(|v| {
            select_options(
                v.choice.as_str(),
                &[("list", "Return to list"), ("next", "Select next message")],
            )
        })
        .unwrap_or_else(|| "<option>Unavailable</option>".into());
    let after_disabled = if after_archive.is_some() {
        ""
    } else {
        " disabled"
    };
    let after_revision = after_archive.map_or(0, |v| v.revision);
    let (mark_control, mark_form, mark_button) = match mark_read {
        Some(saved) => (
            format!("<div class=\"general-field\"><label for=\"reading-mark-read\">Mark read</label><select id=\"reading-mark-read\" name=\"policy\" form=\"reading-mark-read-form\" aria-describedby=\"reading-mark-read-help\">{}</select></div>", select_options(saved.policy.as_str(), &[("manual", "Manual"), ("on_open", "On Open")])),
            format!("<form id=\"reading-mark-read-form\" method=\"post\" action=\"/settings/mark-read\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"expected_revision\" value=\"{}\"><input type=\"hidden\" name=\"section\" value=\"reading\"></form>", saved.revision),
            "<button type=\"submit\" form=\"reading-mark-read-form\">Save mark-read choice</button>",
        ),
        None => ("<div class=\"general-field\"><label for=\"reading-mark-read\">Mark read</label><select id=\"reading-mark-read\" disabled aria-describedby=\"reading-mark-read-help\"><option>Unavailable</option></select></div>".into(), String::new(), "<span>Saved mark-read preference unavailable. Reload settings.</span>"),
    };
    let behaviour = format!(concat!(
        "<div class=\"reading-card-column\"><section class=\"general-card\" aria-labelledby=\"reading-behaviour-title\"><h2 id=\"reading-behaviour-title\">Mailbox Behavior</h2>",
        "<div class=\"general-field\"><label for=\"reading-start-page\">Default start page</label><select id=\"reading-start-page\" form=\"reading-preferences-form\" name=\"start_page\">{start}</select></div>",
        "{mark_control}",
        "<div class=\"general-field\"><label for=\"reading-after-archive\">After archive</label><select id=\"reading-after-archive\" form=\"after-archive-form\" name=\"choice\"{after_disabled} aria-describedby=\"after-archive-help\">{after_options}</select></div>",
        "<div class=\"general-field\"><label for=\"reading-date-order\">Conversation ordering</label><select id=\"reading-date-order\" form=\"reading-preferences-form\" name=\"date_order\">{order}</select></div></section>",
        "{mark_form}<form id=\"after-archive-form\" method=\"post\" action=\"/settings/after-archive\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"revision\" value=\"{after_revision}\"></form><div class=\"reading-card-actions\">{mark_button}<button type=\"submit\" form=\"after-archive-form\"{after_disabled}>Save after-archive choice</button><button class=\"primary-button\" type=\"submit\" form=\"reading-preferences-form\">Save reading preferences</button></div>",
        "<details class=\"reading-help\"><summary>Reading preference details</summary><p id=\"reading-behaviour-help\">Start page applies after sign-in. Conversation ordering keeps related messages together using available thread headers within the loaded, filtered results. Members follow received time; missing or ambiguous thread headers remain independent. Explicit list sorts take priority. Thread headers do not verify a sender.</p><p id=\"reading-mark-read-help\">Manual keeps the current read state when opening. On Open marks an unread message read through its opening action. Reload and Back do not mark messages read. Save this choice separately.</p><p id=\"after-archive-help\">After archive applies only to a confirmed single-message Archive. Next uses verified loaded mailbox order and supported list filters; Search, last-row or unavailable context returns to the list. Save this choice separately.</p><p>This save also updates Show source shortcut and Attachment details in the Reader card.</p></details></div>"
    ), start=start, order=order,after_options=after_options,after_disabled=after_disabled,after_revision=after_revision,csrf=csrf,mark_control=mark_control,mark_form=mark_form,mark_button=mark_button);
    let archive_missing = model.archive_mailbox_name.is_some_and(|stored| {
        mailboxes.is_some_and(|entries| !entries.iter().any(|entry| entry.name == stored))
    });
    let content = select_options(
        model.html_display_preference.as_str(),
        &[
            ("prefer_sanitized_html", "Protected HTML"),
            ("prefer_plain_text", "Plain text"),
        ],
    );
    let reader = format!(concat!(
        "<div class=\"reading-card-column\"><section class=\"general-card\" aria-labelledby=\"reading-reader-title\"><h2 id=\"reading-reader-title\">Reader</h2>",
        "<form id=\"reading-content-form\" method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"return_section\" value=\"reading\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"settings_action\" value=\"content\">",
        "<div class=\"general-field\"><label for=\"html-display-prefer-sanitized\">Default content</label><select id=\"html-display-prefer-sanitized\" name=\"html_display_preference\">{content}</select></div></form>{source}{attachments}",
        "<div class=\"general-field reading-policy\"><span>External images</span><span class=\"general-enforced\">Blocked by policy</span></div></section>",
        "<div class=\"reading-card-actions\"><button type=\"submit\" form=\"reading-content-form\">Save content preference</button></div>",
        "<p class=\"reading-help\">{help}</p></div>"
    ), csrf=csrf, content=content,
        source=reading_switch("reading-show-source", "Show source shortcut", "show_source_shortcut", preferences.show_source_shortcut),
        attachments=reading_switch("reading-attachment-details", "Attachment details", "attachment_details", preferences.attachment_details),
        help="Protected HTML uses sanitized content when available. This save preserves Archive. Source and attachment switches use Save reading preferences.");
    let (archive, archive_save) = if let Some(mailboxes) = mailboxes {
        let mut options = format!(
            "<option value=\"\"{}>Not configured</option>",
            if model.archive_mailbox_name.is_none() {
                " selected"
            } else {
                ""
            }
        );
        if archive_missing {
            // This option remains a successful form value. Disabling it would
            // omit the stored value and could accidentally submit a clear.
            let stored = model.archive_mailbox_name.unwrap_or("");
            options.push_str(&format!(
                "<option value=\"{}\" selected>{} (unavailable)</option>",
                escape_html(stored),
                escape_html(stored)
            ));
        }
        for mailbox in mailboxes {
            options.push_str(&format!(
                "<option value=\"{}\"{}>{}</option>",
                escape_html(&mailbox.name),
                if model.archive_mailbox_name == Some(mailbox.name.as_str()) {
                    " selected"
                } else {
                    ""
                },
                escape_html(&mailbox.name)
            ));
        }
        (format!("<form id=\"reading-archive-form\" method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"return_section\" value=\"reading\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"html_display_preference\" value=\"{}\"><div class=\"general-field\"><label for=\"archive-mailbox-name\">Archive folder</label><select id=\"archive-mailbox-name\" name=\"archive_mailbox_name\"{}>{options}</select></div></form>", model.html_display_preference.as_str(), if archive_missing { " aria-describedby=\"reading-archive-help\"" } else { "" }),
        "<button type=\"submit\" form=\"reading-archive-form\">Save archive folder</button>".to_owned())
    } else {
        (format!("<div class=\"general-field\"><label for=\"archive-mailbox-name\">Archive folder</label><input id=\"archive-mailbox-name\" readonly value=\"{}\" aria-describedby=\"reading-archive-help\"></div>", escape_html(model.archive_mailbox_name.unwrap_or("Not configured"))), "<button type=\"button\" disabled aria-describedby=\"reading-archive-help\">Save archive folder</button>".to_owned())
    };
    let archive_help = if mailboxes.is_none() {
        "The mailbox list could not be loaded. Archive changes are unavailable."
    } else if archive_missing {
        "The stored Archive folder is unavailable. Select an available folder or Not configured before saving."
    } else {
        "Archive changes preserve the saved content preference."
    };
    let folders = format!(concat!(
        "<div class=\"reading-card-column\"><section class=\"general-card\" aria-labelledby=\"reading-folders-title\"><h2 id=\"reading-folders-title\">Folders</h2>{archive}",
        "{bin_form}",
        "<div class=\"general-field\"><label for=\"reading-sent-folder\">Sent folder</label><input id=\"reading-sent-folder\" value=\"Sent (fixed)\" readonly></div>",
        "<div class=\"general-field\"><label for=\"reading-drafts-folder\">Drafts folder</label><input id=\"reading-drafts-folder\" value=\"OSMAP drafts (fixed)\" readonly></div></section>",
        "<div class=\"reading-card-actions\">{archive_save}</div><p class=\"reading-help\" id=\"reading-archive-help\">{archive_help}</p>",
        "<details class=\"reading-help\"><summary>Folder details</summary><p>Bin moves messages to your saved existing folder; Restore returns them to Inbox. Sent and draft storage locations cannot be changed here.</p></details></div>"
    ), bin_form=bin_form, archive=archive, archive_save=archive_save, archive_help=archive_help);
    let notices = [
        model
            .success_message
            .map(|v| ("notice-success", "status", v)),
        model.error_message.map(|v| ("notice-error", "alert", v)),
    ]
    .into_iter()
    .flatten()
    .map(|(class, role, value)| {
        format!(
            "<div class=\"notice {class}\" role=\"{role}\">{}</div>",
            escape_html(value)
        )
    })
    .collect::<String>();
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-reading-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Configure mailbox behavior, reading state and folder defaults.</p></div>{notices}",
        "<form id=\"reading-preferences-form\" method=\"post\" action=\"/settings/reading\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"></form>",
        "<div class=\"settings-layout\">{navigation}<div class=\"settings-reading-grid\">{behaviour}{reader}{folders}</div></div></main>"
    ), header=app_header(model.canonical_username, model.csrf_token, "settings-reading"), notices=notices, csrf=csrf, navigation=settings_navigation("reading"), behaviour=behaviour, reader=reader, folders=folders))
}

fn reading_switch(id: &str, label: &str, name: &str, checked: bool) -> String {
    format!("<div class=\"general-field reading-toggle-field\"><label for=\"{id}\">{label}</label><input class=\"settings-switch\" id=\"{id}\" name=\"{name}\" type=\"checkbox\" role=\"switch\" form=\"reading-preferences-form\" value=\"1\"{}></div>", if checked { " checked" } else { "" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(archive: Option<&str>) -> SettingsPageModel<'_> {
        SettingsPageModel {
            canonical_username: "synthetic@example.test",
            csrf_token: "synthetic-csrf",
            success_message: None,
            error_message: None,
            html_display_preference: HtmlDisplayPreference::default(),
            archive_mailbox_name: archive,
        }
    }

    #[test]
    fn reading_mark_read_uses_its_own_native_form_and_saved_revision() {
        for policy in [
            crate::mark_read::Policy::Manual,
            crate::mark_read::Policy::OnOpen,
        ] {
            let saved = crate::mark_read::Preference {
                revision: 9,
                policy,
            };
            let html = render_reading_page_with_policies(
                &model(None),
                &ReadingPreferences::default(),
                Some(&[]),
                None,
                Some(&saved),
            );
            let html = html.as_str();
            assert!(html.contains(&format!("<option value=\"{}\" selected>", policy.as_str())));
            assert!(html.contains(
                "id=\"reading-mark-read\" name=\"policy\" form=\"reading-mark-read-form\""
            ));
            assert!(html.contains("action=\"/settings/mark-read\""));
            assert!(html.contains("name=\"expected_revision\" value=\"9\""));
            assert!(html.contains("name=\"section\" value=\"reading\""));
            assert!(html
                .contains("type=\"submit\" form=\"reading-mark-read-form\">Save mark-read choice"));
            assert!(html.contains("Reload and Back do not mark messages read."));
        }
    }

    #[test]
    fn reading_unavailable_mark_read_does_not_offer_a_write_or_default_claim() {
        let html = render_reading_page(&model(None), &ReadingPreferences::default(), Some(&[]));
        let html = html.as_str();
        assert!(html.contains("id=\"reading-mark-read\" disabled"));
        assert!(html.contains("Saved mark-read preference unavailable. Reload settings."));
        assert!(!html.contains("action=\"/settings/mark-read\""));
        assert!(!html.contains("Save mark-read choice</button>"));
    }

    #[test]
    fn reading_ui_missing_archive_preserves_escaped_successful_option() {
        let html = render_reading_page(
            &model(Some("Old & <missing>")),
            &ReadingPreferences::default(),
            Some(&[]),
        );
        let html = html.as_str();
        assert!(html.contains("<option value=\"Old &amp; &lt;missing&gt;\" selected>Old &amp; &lt;missing&gt; (unavailable)</option>"));
        assert!(!html.contains("value=\"\" selected"));
        assert!(html.contains("name=\"settings_action\" value=\"content\""));
        assert!(!html.contains("form=\"reading-content-form\" disabled"));
        assert!(html.contains("Select an available folder or Not configured before saving."));
    }

    #[test]
    fn reading_ui_native_forms_preserve_independent_preferences_and_return_section() {
        let html = render_reading_page(&model(None), &ReadingPreferences::default(), Some(&[]));
        let html = html.as_str();
        assert_eq!(
            html.matches("name=\"return_section\" value=\"reading\"")
                .count(),
            2
        );
        assert!(html.contains("<option value=\"\" selected>Not configured</option>"));
        assert_eq!(html.matches("class=\"settings-switch\"").count(), 2);
        assert_eq!(
            html.matches("form=\"reading-preferences-form\" value=\"1\" checked")
                .count(),
            2
        );
        assert!(html.contains("name=\"html_display_preference\" value=\"prefer_sanitized_html\""));
        assert!(html.contains("<label for=\"reading-date-order\">Conversation ordering</label>"));
        assert!(html.contains(
            "id=\"reading-date-order\" form=\"reading-preferences-form\" name=\"date_order\""
        ));
        assert!(html.contains("missing or ambiguous thread headers remain independent"));
        assert!(html.contains("Explicit list sorts take priority"));
    }

    #[test]
    fn reading_ui_listing_failure_retains_archive_and_disables_archive_write() {
        let html = render_reading_page(
            &model(Some("Archive")),
            &ReadingPreferences::default(),
            None,
        );
        let html = html.as_str();
        assert!(html.contains("readonly value=\"Archive\""));
        assert!(!html.contains("id=\"reading-archive-form\""));
        assert!(html.contains("<button type=\"button\" disabled aria-describedby=\"reading-archive-help\">Save archive folder"));
    }
}
