//! PAGE-15 native defaults; unavailable delivery controls make no policy claims.
use super::*;
use crate::composition_preferences::CompositionPreferences;

pub(crate) fn render_composition_page_with_signature(
    model: &SettingsPageModel<'_>,
    preferences: Option<CompositionPreferences>,
    signature: Option<&crate::signature::SignatureRecord>,
    autosave: Option<&crate::autosave::Preference>,
) -> TrustedHtml {
    let auto_disabled = if autosave.is_some() { "" } else { " disabled" };
    let auto_checked = if autosave.is_some_and(|v| v.enabled) {
        " checked"
    } else {
        ""
    };
    let auto_interval = select_options(
        &autosave.map_or(30, |v| v.interval).to_string(),
        &[
            ("30", "30 seconds"),
            ("60", "60 seconds"),
            ("120", "2 minutes"),
        ],
    );
    let auto_form=autosave.map(|v|format!("<form id=\"autosave-settings-form\" method=\"post\" action=\"/settings/autosave\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><button type=\"submit\">Save auto-save preferences</button></form>",escape_html(model.csrf_token),v.revision)).unwrap_or_else(||"<p>Auto-save preferences unavailable. Reload settings before changing them.</p>".into());
    let signature_selection = crate::signature_ui::selection(signature, true);
    let signature_editor = crate::signature_ui::editor(model.csrf_token, signature, "composition");
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
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-composition-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Set defaults for messages, replies and signatures.</p></div>{notices}",
        "<div class=\"settings-layout\">{navigation}<div class=\"composition-settings-content\"><div class=\"composition-settings-grid\">",
        "<section class=\"general-card\" aria-labelledby=\"composition-defaults-title\"><h2 id=\"composition-defaults-title\">Message Defaults</h2><form id=\"composition-settings-form\" method=\"post\" action=\"/settings/composition\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"return_section\" value=\"composition\">",
        "<div class=\"general-field\"><label for=\"composition-format\">Format</label><select id=\"composition-format\" name=\"default_body_format\"{disabled}>{formats}</select></div>",
        "<div class=\"general-field\"><label for=\"composition-reply-placement\">Reply placement</label><select id=\"composition-reply-placement\" name=\"reply_placement\"{disabled}>{placement}</select></div>",
        "<div class=\"general-field composition-toggle\"><label for=\"composition-signature\">Include signature</label><span>{signature_selection}</span></div>",
        "<div class=\"general-field composition-toggle\"><label for=\"composition-autosave\">Auto-save drafts</label><span><input class=\"settings-switch\" id=\"composition-autosave\" type=\"checkbox\" role=\"switch\" name=\"enabled\" value=\"1\" form=\"autosave-settings-form\"{auto_checked}{auto_disabled}></span></div>",
        "<div class=\"general-field\"><label for=\"composition-interval\">Auto-save interval</label><select id=\"composition-interval\" name=\"interval\" form=\"autosave-settings-form\"{auto_disabled}>{auto_interval}</select></div></form></section>",
        "<section class=\"general-card\" aria-labelledby=\"composition-delivery-title\"><h2 id=\"composition-delivery-title\">Protected Delivery</h2>{protected}<div class=\"general-field\"><span>Delayed send revalidation</span><span class=\"composition-unavailable-state\">Scheduling unavailable</span></div></section></div>",
        "<div class=\"composition-policy-note\" id=\"composition-unavailable\">Scheduled sending and outgoing cryptography are unavailable. Auto-save is optional and runs only on a visible composer with scripting enabled. Pending files require a manual save; uncertain saves pause. An uncertain submission must be checked before retrying.</div>",
        "<div class=\"composition-save-row\"><details><summary>How these defaults apply</summary><p>Format applies only to new blank messages. Replies and forwards start in Plain text so quoted notation stays literal. Reply placement moves blank reply space above or below the quote in new replies and reply-all; it does not change forwards or saved drafts.</p><p>Move the cursor to the blank reply space before typing. Below does not move the cursor automatically. Preview before sending.</p></details><button type=\"submit\" form=\"composition-settings-form\"{disabled}>Save composition preferences</button></div>{signature_editor}<div class=\"composition-save-row\">{auto_form}</div></div></div></main>"
    ), auto_disabled=auto_disabled,auto_checked=auto_checked,auto_interval=auto_interval,auto_form=auto_form, signature_selection=signature_selection, signature_editor=signature_editor, header=app_header(model.canonical_username,model.csrf_token,"settings-composition"), navigation=settings_navigation("composition"), notices=notices, csrf=escape_html(model.csrf_token), disabled=disabled, formats=formats, placement=placement, protected=protected))
}
