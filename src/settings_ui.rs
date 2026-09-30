//! Native Settings presentation, separate from browser route handlers.
use super::*;
#[path = "settings_security_ui.rs"]
mod settings_security_ui;
pub(crate) use settings_security_ui::render_security_page;
#[path = "settings_privacy_ui.rs"]
mod settings_privacy_ui;
pub(crate) use settings_privacy_ui::render_privacy_page;
#[path = "settings_copies_ui.rs"]
mod settings_copies_ui;
pub(crate) use settings_copies_ui::render_copies_page;

#[path = "settings_general_ui.rs"]
mod settings_general_ui;
pub(crate) use settings_general_ui::render_general_page;
#[path = "settings_reading_ui.rs"]
mod settings_reading_ui;
pub(crate) use settings_reading_ui::render_reading_page;
#[path = "settings_composition_ui.rs"]
mod settings_composition_ui;
pub(crate) use settings_composition_ui::render_composition_page;

pub(crate) fn render_appearance_page(
    model: &SettingsPageModel<'_>,
    preferences: &crate::appearance::AppearanceSettings,
) -> TrustedHtml {
    let mut themes = String::new();
    for (value, label, icon, hint) in [
        ("light", "Light", "☼", "Light colours"),
        ("dark", "Dark", "☾", "Dark colours"),
        ("system", "System", "◫", "Match device"),
    ] {
        themes.push_str(&format!(concat!(
            "<label class=\"settings-theme settings-theme-{value}\"><input class=\"sr-only\" type=\"radio\" name=\"appearance\" value=\"{value}\" aria-label=\"{label}\"{checked}>",
            "<span class=\"settings-theme-icon\" aria-hidden=\"true\">{icon}</span><strong>{label}</strong>",
            "<span class=\"settings-theme-selected\" aria-hidden=\"true\">Selected</span><span class=\"settings-theme-hint\" aria-hidden=\"true\">{hint}</span></label>"
        ), value=value, label=label, icon=icon, hint=hint,
            checked = if preferences.theme.as_str() == value { " checked" } else { "" }));
    }
    let density = select_options(
        preferences.density.as_str(),
        &[("comfortable", "Comfortable"), ("compact", "Compact")],
    );
    let font = select_options(
        preferences.font_size.as_str(),
        &[("small", "Small"), ("medium", "Medium"), ("large", "Large")],
    );
    let layout = select_options(
        preferences.reader_layout.as_str(),
        &[
            ("split", "Split list + reader"),
            ("stacked", "Stacked list + reader"),
        ],
    );
    let success = model
        .success_message
        .map(|value| {
            format!(
                "<div class=\"notice notice-success\" role=\"status\">{}</div>",
                escape_html(value)
            )
        })
        .unwrap_or_default();
    let error = model
        .error_message
        .map(|value| {
            format!(
                "<div class=\"notice notice-error\" role=\"alert\">{}</div>",
                escape_html(value)
            )
        })
        .unwrap_or_default();
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Control theme, density, typography and reader layout.</p></div>{success}{error}",
        "<div class=\"settings-layout\">{navigation}<section class=\"settings-content\" aria-labelledby=\"settings-appearance-title\"><h2 id=\"settings-appearance-title\">Appearance</h2>",
        "<form class=\"settings-display-form\" method=\"post\" action=\"/settings/display\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">",
        "<fieldset class=\"settings-themes\"><legend class=\"sr-only\">Theme</legend>{themes}</fieldset><div class=\"settings-appearance-grid\"><div class=\"settings-display-fields\">",
        "<div class=\"settings-field\"><label for=\"settings-density\">Density</label><select id=\"settings-density\" name=\"density\">{density}</select></div>",
        "<div class=\"settings-field\"><label for=\"settings-font-size\">Font size</label><select id=\"settings-font-size\" name=\"font_size\">{font}</select></div>",
        "<div class=\"settings-field\"><label for=\"settings-reader-layout\">Reader layout</label><select id=\"settings-reader-layout\" name=\"reader_layout\">{layout}</select></div>",
        "<div class=\"settings-field settings-toggle-field\"><label for=\"settings-show-avatars\">Show avatars</label><input class=\"settings-switch\" id=\"settings-show-avatars\" type=\"checkbox\" role=\"switch\" name=\"show_avatars\" value=\"1\"{avatars_checked}></div>",
        "<div class=\"settings-field settings-toggle-field\"><label for=\"settings-message-preview\">Message preview</label><input class=\"settings-switch\" id=\"settings-message-preview\" type=\"checkbox\" role=\"switch\" name=\"message_preview\" value=\"1\"{preview_checked}></div></div>",
        "<section class=\"settings-preview\" aria-labelledby=\"settings-preview-title\" data-preview-theme=\"{theme}\" data-preview-density=\"{saved_density}\" data-preview-font=\"{saved_font}\" data-preview-avatars=\"{avatars}\" data-preview-snippet=\"{snippet}\" data-preview-layout=\"{saved_layout}\"><h3 id=\"settings-preview-title\">Preview</h3>",
        "<div class=\"settings-preview-message\"><span class=\"settings-preview-avatar\" aria-hidden=\"true\">S</span><div><strong>Sample message</strong><span class=\"settings-preview-snippet\">A short example of a message preview.</span></div></div>",
        "<div class=\"settings-preview-reader\"><p>This preview shows your saved settings. Save changes to update the preview and your mailbox.</p><p class=\"settings-preview-layout-note\">Saved reader layout: {layout_label}.</p></div></section></div>",
        "<div class=\"settings-save-row\"><button class=\"primary-button\" type=\"submit\">Save changes</button></div></form></section></div></main>"
    ), header=app_header(model.canonical_username, model.csrf_token, "settings-appearance"),
        success=success, error=error, themes=themes, density=density, font=font, layout=layout,
        navigation=settings_navigation("appearance"), csrf=escape_html(model.csrf_token),
        avatars_checked=if preferences.show_avatars { " checked" } else { "" }, preview_checked=if preferences.message_preview { " checked" } else { "" },
        theme=preferences.theme.as_str(), saved_density=preferences.density.as_str(), saved_font=preferences.font_size.as_str(),
        avatars=preferences.show_avatars, snippet=preferences.message_preview, saved_layout=preferences.reader_layout.as_str(),
        layout_label=if preferences.reader_layout.as_str()=="split" { "Split list + reader" } else { "Stacked list + reader" }))
}

fn select_options(selected: &str, options: &[(&str, &str)]) -> String {
    options
        .iter()
        .map(|(value, label)| {
            format!(
                "<option value=\"{}\"{}>{}</option>",
                escape_html(value),
                if selected == *value { " selected" } else { "" },
                escape_html(label)
            )
        })
        .collect()
}

fn settings_navigation(current_section: &str) -> String {
    let mut result =
        String::from("<nav class=\"settings-navigation\" aria-label=\"Settings sections\"><ul>");
    for (label, section) in [
        ("General", Some("general")),
        ("Appearance", Some("appearance")),
        ("Identity", None),
        ("Reading & Mailbox", Some("reading")),
        ("Composition", Some("composition")),
        ("Copies & Folders", Some("copies")),
        ("Notifications", None),
        ("Privacy & Security", Some("privacy")),
        ("OpenPGP", None),
        ("Authentication & Recovery", Some("authentication")),
    ] {
        if label == "OpenPGP" && current_section == "security" {
            result.push_str("<li><a href=\"/settings?section=security\" aria-current=\"page\">Security</a></li>");
        }
        if let Some(section) = section {
            result.push_str(&format!(
                "<li><a href=\"/settings?section={section}\"{}>{}</a></li>",
                if section == current_section {
                    " aria-current=page"
                } else {
                    ""
                },
                escape_html(label)
            ));
        } else {
            result.push_str(&format!("<li><span class=\"settings-section-unavailable\" aria-disabled=\"true\" aria-describedby=\"settings-unavailable-note\">{}</span></li>", escape_html(label)));
        }
    }
    result.push_str("</ul><p class=\"settings-navigation-note\" id=\"settings-unavailable-note\">Additional sections are unavailable.</p></nav>");
    result
}
