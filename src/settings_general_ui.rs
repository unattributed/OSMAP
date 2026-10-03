//! PAGE-11 General overview. Each writable card uses its existing native route.
use super::*;

#[cfg(test)]
pub(crate) fn render_general_page(
    model: &SettingsPageModel<'_>,
    preferences: &crate::appearance::AppearanceSettings,
    composition: Option<crate::composition_preferences::CompositionPreferences>,
    identity: Option<crate::identity_preferences::IdentityPreferencesRecord>,
    reading: Option<crate::reading_preferences::ReadingPreferences>,
    signature: Option<&crate::signature::SignatureRecord>,
) -> TrustedHtml {
    render_general_page_with_mark_read(
        model,
        preferences,
        composition,
        identity,
        reading,
        signature,
        None,
    )
}

pub(crate) fn render_general_page_with_mark_read(
    model: &SettingsPageModel<'_>,
    preferences: &crate::appearance::AppearanceSettings,
    composition: Option<crate::composition_preferences::CompositionPreferences>,
    identity: Option<crate::identity_preferences::IdentityPreferencesRecord>,
    reading: Option<crate::reading_preferences::ReadingPreferences>,
    signature: Option<&crate::signature::SignatureRecord>,
    mark_read: Option<&crate::mark_read::Preference>,
) -> TrustedHtml {
    let profile_input = |id: &str, label: &str, value: Option<&str>| {
        match value {
        Some(value) => format!("<div class=\"general-field\"><label for=\"{id}\">{label}</label><input id=\"{id}\" value=\"{}\" readonly></div>", escape_html(value)),
        None => unavailable_input(id, label, "Unknown"),
    }
    };
    let profile = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-profile-title\"><h2 id=\"general-profile-title\">Account Profile</h2>",
        "{}<div class=\"general-field\"><label for=\"general-email\">Email address</label><input id=\"general-email\" value=\"{}\" readonly></div>{}{}{}",
        "<p class=\"general-help\">{}<a href=\"/settings?section=identity\">Edit in Identity</a>. UTC and English are fixed.</p></section>"
    ), profile_input("general-display-name", "Display name", identity.as_ref().map(|record| record.preferences.display_name())), escape_html(model.canonical_username),
        profile_input("general-reply-to", "Reply-to address", identity.as_ref().map(|record| record.preferences.reply_to().unwrap_or(model.canonical_username))),
        unavailable_select("general-timezone", "Timezone", "UTC"), unavailable_select("general-language", "Language", "English"), if identity.is_none() { "Saved profile unavailable. " } else { "" });

    let appearance = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-appearance-title\"><h2 id=\"general-appearance-title\">Appearance</h2>",
        "<form method=\"post\" action=\"/settings/display\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"font_size\" value=\"{}\">{}{}",
        "<div class=\"general-field\"><label for=\"general-theme\">Theme</label><select id=\"general-theme\" name=\"appearance\">{}</select></div>",
        "<div class=\"general-field\"><label for=\"general-density\">Density</label><select id=\"general-density\" name=\"density\">{}</select></div>",
        "<div class=\"general-field\"><label for=\"general-reader-layout\">Reader layout</label><select id=\"general-reader-layout\" name=\"reader_layout\">{}</select></div>",
        "<div class=\"general-card-actions\"><a class=\"button-link\" href=\"/settings?section=appearance\">Configure appearance</a><button type=\"submit\">Save appearance</button></div></form></section>"
    ), escape_html(model.csrf_token), preferences.font_size.as_str(),
        preserved_flag("show_avatars", preferences.show_avatars), preserved_flag("message_preview", preferences.message_preview),
        select_options(preferences.theme.as_str(), &[("light", "Light"), ("dark", "Dark"), ("system", "System (match device)")]),
        select_options(preferences.density.as_str(), &[("comfortable", "Comfortable"), ("compact", "Compact")]),
        select_options(preferences.reader_layout.as_str(), &[("split", "Split view"), ("stacked", "Stacked view")]));

    let start_control = reading.map(|v| format!("<div class=\"general-field\"><label for=\"general-start-page\">Default start page</label><select id=\"general-start-page\" name=\"start_page\" form=\"general-start-form\">{}</select></div>", select_options(v.start_page.as_str(), &[("mailbox","Mailbox"),("inbox","Inbox"),("drafts","Drafts"),("sent","Sent")]))).unwrap_or_else(||unavailable_select("general-start-page","Default start page","Unavailable"));
    let start_form = if reading.is_some() {
        format!("<form id=\"general-start-form\" method=\"post\" action=\"/settings/reading\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"reading_action\" value=\"start_page\"></form>",escape_html(model.csrf_token))
    } else {
        String::new()
    };
    let (mark_control, mark_form, mark_button) = match mark_read {
        Some(saved) => (
            format!("<div class=\"general-field\"><label for=\"general-mark-read\">Mark read</label><select id=\"general-mark-read\" name=\"policy\" form=\"general-mark-read-form\" aria-describedby=\"general-mark-read-help\">{}</select></div>", select_options(saved.policy.as_str(), &[("manual", "Manual"), ("on_open", "On Open")])),
            format!("<form id=\"general-mark-read-form\" method=\"post\" action=\"/settings/mark-read\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"expected_revision\" value=\"{}\"><input type=\"hidden\" name=\"section\" value=\"general\"></form>", escape_html(model.csrf_token), saved.revision),
            "<button type=\"submit\" form=\"general-mark-read-form\">Save mark-read choice</button>",
        ),
        None => (unavailable_select("general-mark-read", "Mark read", "Unavailable"), String::new(), "<span>Saved mark-read preference unavailable. Reload settings.</span>"),
    };
    let mailbox = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-mailbox-title\"><h2 id=\"general-mailbox-title\">Mailbox Defaults</h2>{start_form}{mark_form}",
        "<form method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"settings_action\" value=\"archive\">{}",
        "<div class=\"general-field\"><label for=\"general-archive\">Archive folder</label><input id=\"general-archive\" name=\"archive_mailbox_name\" value=\"{}\" autocomplete=\"off\"></div>{}{}",
        "<p class=\"general-help\">Save each choice separately. Blank Archive uses manual moves.</p><p class=\"general-help\" id=\"general-mark-read-help\">Manual keeps the current read state when opening. On Open marks an unread message read through its opening action. Reload and Back do not mark messages read.</p><div class=\"general-card-actions\"><button type=\"submit\">Save archive folder</button>{start_button}{mark_button}</div></form></section>"
    ), escape_html(model.csrf_token),
        start_control, escape_html(model.archive_mailbox_name.unwrap_or("")),
        unavailable_select("general-delete-behaviour", "Delete behaviour", "Unavailable"),
        mark_control, start_form=start_form, mark_form=mark_form, mark_button=mark_button, start_button=if reading.is_some(){"<button type=\"submit\" form=\"general-start-form\">Save start page</button>"}else{"<span>Saved Reading preferences unavailable.</span>"});

    let format_control = match composition {
        Some(value) => format!("<form id=\"general-composition-form\" method=\"post\" action=\"/settings/composition\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><div class=\"general-field\"><label for=\"general-default-format\">Default format</label><select id=\"general-default-format\" name=\"default_body_format\">{}</select></div></form>", escape_html(model.csrf_token), select_options(value.default_body_format.as_str(), &[("plain", "Plain text"), ("formatted", "Formatted text")])),
        None => format!("{}<p class=\"general-help\">Saved composition preferences are unavailable.</p>", unavailable_select("general-default-format", "Default format", "Unavailable")),
    };
    let placement_control = match composition {
        Some(value) => format!("<div class=\"general-field\"><label for=\"general-reply-placement\">Reply placement</label><select id=\"general-reply-placement\" name=\"reply_placement\" form=\"general-composition-form\">{}</select></div>", select_options(value.reply_placement.as_str(), &[("above", "Above quoted text"), ("below", "Below quoted text")])),
        None => unavailable_select("general-reply-placement", "Reply placement", "Unavailable"),
    };
    let protection_controls = match composition {
        Some(value) => [
            ("general-signing", "Sign outgoing", "pgp_sign", value.openpgp.sign),
            ("general-encryption", "Encryption", "pgp_encrypt", value.openpgp.encrypt),
            ("general-encrypt-self", "Encrypt to self", "pgp_self", value.openpgp.encrypt_to_self),
        ].iter().map(|(id, label, name, enabled)| format!("<div class=\"general-field\"><label for=\"{id}\">{label}</label><select id=\"{id}\" name=\"{name}\" form=\"general-composition-form\">{}</select></div>", select_options(if *enabled { "on" } else { "off" }, &[("off", "Off"), ("on", "On")]))).collect::<String>(),
        None => format!("{}{}{}", unavailable_select("general-signing", "OpenPGP signing", "Unavailable"), unavailable_select("general-encryption", "Encryption", "Unavailable"), unavailable_select("general-encrypt-self", "Encrypt to self", "Unavailable")),
    };
    let signature_control = signature.map(|r| format!("<form id=\"general-signature-form\" method=\"post\" action=\"/settings/signature\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"signature_revision\" value=\"{}\"><input type=\"hidden\" name=\"operation\" value=\"selection\"><input type=\"hidden\" name=\"return_section\" value=\"general\"><div class=\"general-field\"><label for=\"general-signature\">Signature</label><select id=\"general-signature\" name=\"selection\">{}</select></div></form>",escape_html(model.csrf_token),r.revision,select_options(r.selection.as_str(), &[("none","None"),("default","Default signature")]))).unwrap_or_else(|| unavailable_select("general-signature","Signature","Unavailable"));
    let composition = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-composition-title\"><h2 id=\"general-composition-title\">Composition Defaults</h2>{}{}{}{}",
        "<div class=\"general-card-actions general-composition-actions\">{}{signature_save}<details><summary>About composition defaults</summary><p class=\"general-help\">Format applies to new blank messages. Replies and forwards use Plain text to preserve quoted message text. Reply placement applies to new replies and reply-all; move the cursor to the blank reply space before typing. Saved drafts remain unchanged. Signature is ordinary footer text for newly opened composers; existing drafts stay unchanged. <a href=\"/settings?section=identity\">Edit the footer in Identity</a>. OpenPGP choices apply to newly opened messages and remain subject to account and recipient policy and a fresh key check before sending.</p></details></div></section>"
    ), format_control,
        signature_control, placement_control,
        protection_controls,
        if composition.is_some() { "<button type=\"submit\" form=\"general-composition-form\" aria-label=\"Save composition defaults\">Save composition</button>" } else { "" }, signature_save=if signature.is_some(){"<button type=\"submit\" form=\"general-signature-form\" aria-label=\"Save signature choice\">Save signature</button>"}else{"<span>Saved signature unavailable.</span>"});

    let privacy = concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-privacy-title\"><h2 id=\"general-privacy-title\">Privacy &amp; Security</h2><ul class=\"general-status-list\">",
        "<li><span class=\"general-row-icon\" aria-hidden=\"true\">◎</span><div><strong>Remote content</strong><span>Blocked by message rendering policy</span></div><span class=\"general-enforced\">Enforced</span></li>",
        "<li><span class=\"general-row-icon\" aria-hidden=\"true\">&lt;/&gt;</span><div><strong>HTML sanitization</strong><span>Allowlist-based rendering</span></div><span class=\"general-enforced\">Enforced</span></li>",
        "<li><span class=\"general-row-icon\" aria-hidden=\"true\">♢</span><div><strong>Content Security Policy</strong></div><span class=\"general-enforced\">Enforced</span></li>",
        "<li><span class=\"general-row-icon\" aria-hidden=\"true\">▤</span><div><strong>Source isolation</strong><span>Source is never active HTML</span></div><span class=\"general-enforced\">Enforced</span></li></ul></section>"
    );
    let mut security_rows = String::new();
    for (label, icon) in [
        ("OpenPGP keys", "⌘"),
        ("Password", "▣"),
        ("TOTP", "◉"),
        ("Recovery contact", "♧"),
    ] {
        let (destination, link_label, visible) = if label == "OpenPGP keys" {
            ("security", "View security settings", "View security")
        } else {
            (
                "authentication",
                "View authentication settings",
                "View authentication",
            )
        };
        security_rows.push_str(&format!("<li><span class=\"general-row-icon\" aria-hidden=\"true\">{icon}</span><div><strong>{label}</strong><span>Status unknown</span></div><a class=\"button-link\" href=\"/settings?section={destination}\" aria-label=\"{link_label}\">{visible}</a></li>"));
    }
    let security = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-security-title\"><h2 id=\"general-security-title\">Account Security</h2><ul class=\"general-status-list\">{}</ul>",
        "</section>"
    ), security_rows);
    let storage = concat!(
        "<section class=\"general-card general-storage\" aria-labelledby=\"general-storage-title\"><h2 id=\"general-storage-title\">Storage &amp; Data</h2><div class=\"general-storage-columns\">",
        "<div><h3>Mailbox usage</h3><p>Unknown</p><span>Usage and quota are unavailable.</span></div>",
        "<div><h3>Documents usage</h3><p>Unknown</p><span>Shared storage usage is unavailable.</span></div>",
        "<div><h3>Retention</h3><p>Unknown</p><span>No retention policy is available to this page.</span></div></div></section>"
    );
    let mut notices = String::new();
    if let Some(message) = model.success_message {
        notices.push_str(&format!(
            "<div class=\"notice notice-success\" role=\"status\">{}</div>",
            escape_html(message)
        ));
    }
    if let Some(message) = model.error_message {
        notices.push_str(&format!(
            "<div class=\"notice notice-error\" role=\"alert\">{}</div>",
            escape_html(message)
        ));
    }
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell settings-page settings-general-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Manage account, mailbox, appearance, composition, privacy and security preferences.</p></div>{}",
        "<div class=\"settings-layout settings-general-layout\">{}<div class=\"settings-general-grid\">{}{}{}{}{}{}{}<div class=\"general-overview-actions\"><a class=\"button-link\" href=\"/sessions\">Manage active sessions</a><span>Section reset is unavailable.</span><button type=\"button\" disabled>Reset this section</button></div></div></div></main>"
    ), app_header(model.canonical_username, model.csrf_token, "settings-general"), notices, settings_navigation("general"), profile, appearance, mailbox, composition, privacy, security, storage))
}

fn unavailable_input(id: &str, label: &str, value: &str) -> String {
    format!("<div class=\"general-field\"><label for=\"{id}\">{label}</label><input id=\"{id}\" value=\"{value}\" disabled aria-label=\"{label}, unavailable\"></div>")
}

fn unavailable_select(id: &str, label: &str, value: &str) -> String {
    format!("<div class=\"general-field\"><label for=\"{id}\">{label}</label><select id=\"{id}\" disabled aria-label=\"{label}, unavailable\"><option>{value}</option></select></div>")
}

fn preserved_flag(name: &str, enabled: bool) -> String {
    if enabled {
        format!("<input type=\"hidden\" name=\"{name}\" value=\"1\">")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> SettingsPageModel<'static> {
        SettingsPageModel {
            canonical_username: "synthetic@example.test",
            csrf_token: "synthetic&<csrf>",
            success_message: None,
            error_message: None,
            html_display_preference: HtmlDisplayPreference::default(),
            archive_mailbox_name: None,
        }
    }

    #[test]
    fn general_mark_read_uses_its_own_native_form_and_saved_revision() {
        let saved = crate::mark_read::Preference {
            revision: 7,
            policy: crate::mark_read::Policy::OnOpen,
        };
        let html = render_general_page_with_mark_read(
            &model(),
            &crate::appearance::AppearanceSettings::default(),
            None,
            None,
            None,
            None,
            Some(&saved),
        );
        let html = html.as_str();
        assert!(html.contains("<option value=\"on_open\" selected>On Open</option>"));
        assert!(html.contains("name=\"expected_revision\" value=\"7\""));
        assert!(html.contains("name=\"section\" value=\"general\""));
        assert!(html.contains("value=\"synthetic&amp;&lt;csrf&gt;\""));
        assert!(html
            .contains("id=\"general-mark-read\" name=\"policy\" form=\"general-mark-read-form\""));
        assert!(
            html.contains("type=\"submit\" form=\"general-mark-read-form\">Save mark-read choice")
        );
        let mark_start = html.find("<form id=\"general-mark-read-form\"").unwrap();
        let mark_end = mark_start + html[mark_start..].find("</form>").unwrap();
        assert!(!html[mark_start + 5..mark_end].contains("<form"));
        assert!(!html[mark_start..mark_end].contains("settings_action"));
    }

    #[test]
    fn general_unavailable_mark_read_does_not_offer_a_write_or_default_claim() {
        let html = render_general_page(
            &model(),
            &crate::appearance::AppearanceSettings::default(),
            None,
            None,
            None,
            None,
        );
        let html = html.as_str();
        assert!(html.contains("id=\"general-mark-read\" disabled"));
        assert!(html.contains("Saved mark-read preference unavailable. Reload settings."));
        assert!(!html.contains("action=\"/settings/mark-read\""));
        assert!(!html.contains("Save mark-read choice</button>"));
    }
}
