//! PAGE-15 native defaults; unavailable delivery controls make no policy claims.
use super::*;
use crate::composition_preferences::CompositionPreferences;

pub(crate) fn render_composition_page(
    model: &SettingsPageModel<'_>,
    preferences: Option<CompositionPreferences>,
) -> TrustedHtml {
    let unavailable = preferences.is_none();
    let value = preferences.unwrap_or_default();
    let disabled = if unavailable { " disabled" } else { "" };
    let formats = select_options(
        value.default_body_format.as_str(),
        &[("plain", "Plain text"), ("formatted", "Formatted text")],
    );
    let placement = select_options(
        value.reply_placement.as_str(),
        &[
            ("above", "Above quoted text"),
            ("below", "Below quoted text"),
        ],
    );
    let mut protected = String::new();
    for (id, label) in [
        ("signing", "Sign outgoing"),
        ("encryption", "Encryption"),
        ("self", "Encrypt to self"),
        ("missing-key", "Missing recipient key"),
    ] {
        protected.push_str(&format!("<div class=\"general-field\"><label for=\"composition-{id}\">{label}</label><select id=\"composition-{id}\" disabled><option>Unavailable</option></select></div>"));
    }
    let mut notices = String::new();
    for (message, kind, role) in [
        (model.success_message, "notice-success", "status"),
        (model.error_message, "notice-error", "alert"),
    ] {
        if let Some(message) = message {
            notices.push_str(&format!(
                "<div class=\"notice {kind}\" role=\"{role}\">{}</div>",
                escape_html(message)
            ));
        }
    }
    if unavailable {
        notices.push_str("<div class=\"notice notice-error\" role=\"alert\">Saved composition preferences are unavailable. The controls show defaults and cannot be saved.</div>");
    }
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-composition-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Set defaults for messages and replies. Signatures and protected delivery preferences are unavailable.</p></div>{notices}",
        "<div class=\"settings-layout\">{navigation}<div class=\"composition-settings-content\"><div class=\"composition-settings-grid\">",
        "<section class=\"general-card\" aria-labelledby=\"composition-defaults-title\"><h2 id=\"composition-defaults-title\">Message Defaults</h2><form id=\"composition-settings-form\" method=\"post\" action=\"/settings/composition\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"return_section\" value=\"composition\">",
        "<div class=\"general-field\"><label for=\"composition-format\">Format</label><select id=\"composition-format\" name=\"default_body_format\"{disabled}>{formats}</select></div>",
        "<div class=\"general-field\"><label for=\"composition-reply-placement\">Reply placement</label><select id=\"composition-reply-placement\" name=\"reply_placement\"{disabled}>{placement}</select></div>",
        "<div class=\"general-field composition-toggle\"><label for=\"composition-signature\">Include signature</label><span><input class=\"settings-switch\" id=\"composition-signature\" type=\"checkbox\" role=\"switch\" disabled aria-describedby=\"composition-unavailable\"><span>Unavailable</span></span></div>",
        "<div class=\"general-field composition-toggle\"><label for=\"composition-autosave\">Auto-save drafts</label><span><input class=\"settings-switch\" id=\"composition-autosave\" type=\"checkbox\" role=\"switch\" disabled aria-describedby=\"composition-unavailable\"><span>Unavailable</span></span></div>",
        "<div class=\"general-field\"><label for=\"composition-interval\">Auto-save interval</label><select id=\"composition-interval\" disabled><option>Unavailable</option></select></div></form></section>",
        "<section class=\"general-card\" aria-labelledby=\"composition-delivery-title\"><h2 id=\"composition-delivery-title\">Protected Delivery</h2>{protected}<div class=\"general-field\"><span>Delayed send revalidation</span><span class=\"composition-unavailable-state\">Scheduling unavailable</span></div></section></div>",
        "<div class=\"composition-policy-note\" id=\"composition-unavailable\">Signature identity, automatic saving, scheduled sending and outgoing cryptography are unavailable. Drafts save only when you choose a save action. An uncertain submission must be checked before retrying.</div>",
        "<div class=\"composition-save-row\"><details><summary>How these defaults apply</summary><p>Format applies only to new blank messages. Replies and forwards start in Plain text so quoted notation stays literal. Reply placement moves blank reply space above or below the quote in new replies and reply-all; it does not change forwards or saved drafts.</p><p>Move the cursor to the blank reply space before typing. Below does not move the cursor automatically. Preview before sending.</p></details><button type=\"submit\" form=\"composition-settings-form\"{disabled}>Save composition preferences</button></div></div></div></main>"
    ), header=app_header(model.canonical_username,model.csrf_token,"settings-composition"), navigation=settings_navigation("composition"), notices=notices, csrf=escape_html(model.csrf_token), disabled=disabled, formats=formats, placement=placement, protected=protected))
}
