//! PAGE18: enforced browser protections and native access to Reading preferences.
use super::*;

pub(crate) fn render_privacy_page(model: &SettingsPageModel<'_>) -> TrustedHtml {
    let notices = [
        (model.success_message, "status"),
        (model.error_message, "alert"),
    ]
    .into_iter()
    .filter_map(|(v, role)| {
        v.map(|v| format!("<p class=\"notice\" role=\"{role}\">{}</p>", escape_html(v)))
    })
    .collect::<String>();
    let row = |label: &str, status: &str| {
        format!("<div class=\"privacy-policy\"><span>{label}</span><span class=\"general-enforced\">{status}</span></div>")
    };
    TrustedHtml::from_template(format!(concat!(
        "{header}<main id=\"main-content\" class=\"page-shell settings-page settings-privacy-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Review privacy controls and OSMAP-enforced browser protections.</p></div>{notices}<div class=\"settings-layout\">{nav}<div class=\"privacy-content\"><div class=\"privacy-cards\">",
        "<section class=\"general-card\"><h2>Remote Content</h2>{remote}{tracking}<div class=\"privacy-policy\"><label for=\"privacy-exceptions\">Allow per-message exceptions</label><input id=\"privacy-exceptions\" class=\"settings-switch\" type=\"checkbox\" role=\"switch\" disabled aria-describedby=\"privacy-exceptions-help\"></div></section>",
        "<section class=\"general-card\"><h2>Protected Rendering</h2>{sanitization}{csp}{source}</section>",
        "<section class=\"general-card\"><h2>Links &amp; Attachments</h2>{attachments}{filenames}{active}</section></div>",
        "<section class=\"general-card privacy-notes\"><h2>Privacy Notes</h2><p class=\"privacy-note\">“Protected by Default” refers to protected rendering, remote-content blocking, bounded source view and attachment isolation. It is not an OpenPGP verification result and does not claim zero-knowledge or end-to-end architecture.</p><p id=\"privacy-exceptions-help\" class=\"privacy-help\">Per-message remote-content exceptions are unavailable. Choose your content default in <a href=\"/settings?section=reading#html-display-prefer-sanitized\">Reading &amp; Mailbox</a>.</p></section></div></div></main>",
    ), header=app_header(model.canonical_username, model.csrf_token, "settings-privacy"), notices=notices, nav=settings_navigation("privacy"),
        remote=row("Images/styles/iframes", "Blocked by policy"), tracking=row("Remote tracking images", "Blocked"), sanitization=row("HTML sanitization", "Enforced"), csp=row("Content Security Policy", "Enforced"), source=row("Message source isolation", "Enforced"), attachments=row("Attachment isolation", "Enforced"), filenames=row("Filename safety", "Enforced"), active=row("Inline active content", "Disabled") ))
}
