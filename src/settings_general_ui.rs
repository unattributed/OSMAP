//! PAGE-11 General overview. Each writable card uses its existing native route.
use super::*;

pub(crate) fn render_general_page(
    model: &SettingsPageModel<'_>,
    preferences: &crate::appearance::AppearanceSettings,
    composition: Option<crate::composition_preferences::CompositionPreferences>,
) -> TrustedHtml {
    let profile = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-profile-title\"><h2 id=\"general-profile-title\">Account Profile</h2>",
        "{}<div class=\"general-field\"><label for=\"general-email\">Email address</label><input id=\"general-email\" value=\"{}\" readonly></div>{}{}{}",
        "<p class=\"general-help\">Profile editing is unavailable. UTC and English are fixed.</p></section>"
    ), unavailable_input("general-display-name", "Display name", "Unknown"), escape_html(model.canonical_username),
        unavailable_input("general-reply-to", "Reply-to address", "Unknown"),
        unavailable_select("general-timezone", "Timezone", "UTC"), unavailable_select("general-language", "Language", "English"));

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

    let mailbox = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-mailbox-title\"><h2 id=\"general-mailbox-title\">Mailbox Defaults</h2>",
        "<form method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"html_display_preference\" value=\"{}\">{}",
        "<div class=\"general-field\"><label for=\"general-archive\">Archive folder</label><input id=\"general-archive\" name=\"archive_mailbox_name\" value=\"{}\" autocomplete=\"off\"></div>{}{}",
        "<p class=\"general-help\">Only Archive folder can be changed here. Leave it blank to use manual moves.</p><div class=\"general-card-actions\"><button type=\"submit\">Save archive folder</button></div></form></section>"
    ), escape_html(model.csrf_token), model.html_display_preference.as_str(),
        unavailable_select("general-start-page", "Default start page", "Unavailable"), escape_html(model.archive_mailbox_name.unwrap_or("")),
        unavailable_select("general-delete-behaviour", "Delete behaviour", "Unavailable"),
        unavailable_select("general-mark-read", "Mark read", "Unavailable"));

    let format_control = match composition {
        Some(value) => format!("<form id=\"general-composition-form\" method=\"post\" action=\"/settings/composition\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><div class=\"general-field\"><label for=\"general-default-format\">Default format</label><select id=\"general-default-format\" name=\"default_body_format\">{}</select></div></form>", escape_html(model.csrf_token), select_options(value.default_body_format.as_str(), &[("plain", "Plain text"), ("formatted", "Formatted text")])),
        None => format!("{}<p class=\"general-help\">Saved composition preferences are unavailable.</p>", unavailable_select("general-default-format", "Default format", "Unavailable")),
    };
    let composition = format!(concat!(
        "<section class=\"general-card\" aria-labelledby=\"general-composition-title\"><h2 id=\"general-composition-title\">Composition Defaults</h2>{}{}{}{}{}",
        "<div class=\"general-card-actions general-composition-actions\">{}<details><summary>About default format</summary><p class=\"general-help\">Default applies to new blank messages. Replies and forwards use Plain text to preserve quoted message text; existing drafts keep their saved format. Other composition preferences are unavailable.</p></details></div></section>"
    ), format_control,
        unavailable_select("general-signature", "Signature", "Unavailable"), unavailable_select("general-reply-placement", "Reply placement", "Unavailable"),
        unavailable_select("general-signing", "OpenPGP signing", "Unavailable"), unavailable_select("general-encryption", "Encryption", "Unavailable"),
        if composition.is_some() { "<button type=\"submit\" form=\"general-composition-form\">Save default format</button>" } else { "" });

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
        security_rows.push_str(&format!("<li><span class=\"general-row-icon\" aria-hidden=\"true\">{icon}</span><div><strong>{label}</strong><span>Status unknown</span></div><button type=\"button\" disabled aria-label=\"Manage {label} unavailable\">Manage</button></li>"));
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
