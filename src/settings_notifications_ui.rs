//! Native notification settings; unsupported channels carry no save authority.
use super::*;

pub(crate) fn render_notifications_page(
    account: &str,
    csrf: &str,
    preference: Option<&crate::notification_preferences::Preference>,
    notice: Option<&str>,
) -> TrustedHtml {
    let notice = notice
        .map(|text| {
            format!(
                "<p class=\"notice\" role=\"alert\">{}</p>",
                escape_html(text)
            )
        })
        .unwrap_or_default();
    let digest = preference.map(|saved| format!("<form id=\"notification-preferences-form\" method=\"post\" action=\"/settings/notifications\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"expected_revision\" value=\"{}\"><div class=\"notification-setting\"><label for=\"notice-digest\">Digest</label><select id=\"notice-digest\" name=\"digest\" aria-describedby=\"notice-digest-scope\"><option value=\"individual\"{}>Individual</option><option value=\"daily\"{}>Daily (UTC)</option></select></div><p id=\"notice-digest-scope\">In-app inbox presentation only. Daily (UTC) groups retained notices by event day; every original notice and read control remains available. No scheduled or external digest is sent.</p><button type=\"submit\">Save notification preferences</button></form>", escape_html(csrf), saved.revision, if saved.digest == crate::notification_preferences::DigestMode::Individual { " selected" } else { "" }, if saved.digest == crate::notification_preferences::DigestMode::Daily { " selected" } else { "" })).unwrap_or_else(|| "<div class=\"notification-setting\"><label for=\"notice-digest\">Digest</label><select id=\"notice-digest\" disabled><option>Unavailable</option></select></div><p>Digest preference unavailable. Reload before saving; no saved value was reset.</p>".into());
    let mut toggles = String::new();
    for (id, label, checked, hint) in [
        ("mail", "New mail", false, "Unavailable"),
        ("mentions", "Mentions", false, "Unavailable"),
        ("security", "Security events", true, "Session notices only"),
        ("keys", "OpenPGP status changes", false, "Unavailable"),
        ("delivery", "Delivery status", false, "Unavailable"),
    ] {
        toggles.push_str(&format!("<div class=\"notification-setting\"><label for=\"notice-{id}\">{label}</label><div><input id=\"notice-{id}\" class=\"settings-switch\" type=\"checkbox\" disabled{} aria-describedby=\"notice-{id}-scope\"><span id=\"notice-{id}-scope\" class=\"notification-availability\">{hint}</span></div></div>", if checked { " checked" } else { "" }));
    }
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell settings-page settings-notifications-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Settings</h1><p>Review in-app notices and notification delivery availability.</p></div>{}<div class=\"settings-layout\">{}<div class=\"notification-settings-content\"><div class=\"notification-settings-cards\">",
        "<section class=\"notification-settings-card\"><h2>In-app Notifications</h2>{}</section>",
        "<section class=\"notification-settings-card\"><h2>Notification Delivery</h2>{}<div class=\"notification-setting\"><label for=\"notice-sound\">Sound</label><div><input id=\"notice-sound\" class=\"settings-switch\" type=\"checkbox\" disabled><span class=\"notification-availability\">Unavailable</span></div></div><div class=\"notification-setting\"><label for=\"notice-desktop\">Desktop notifications</label><div><input id=\"notice-desktop\" class=\"settings-switch\" type=\"checkbox\" disabled><span class=\"notification-availability\">Unavailable</span></div></div><div class=\"notification-setting\"><span>Recovery/security alerts</span><span class=\"notification-fixed\">In-app session notices only; digest does not suppress events</span></div></section></div>",
        "<div class=\"notification-settings-note\"><p>Session notices are factual events, not a security score. Other security events and external delivery are unavailable.</p><a class=\"button-link secondary\" href=\"/notifications\">Open notifications</a></div></div></div></main>"
    ), app_header(account, csrf, "settings-notifications"), notice, settings_navigation("notifications"), toggles, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_settings_scope_controls_and_account_are_truthful() {
        let html = render_notifications_page(
            "<foreign&name>@example.test",
            "token",
            Some(&crate::notification_preferences::Preference::default()),
            None,
        );
        let html = html.as_str();
        assert!(!html.contains("<foreign&name>"));
        assert!(html.contains("&lt;foreign&amp;name&gt;@example.test"));
        assert_eq!(html.matches("notification-settings-card\"").count(), 2);
        assert!(html.contains("Session notices only"));
        assert!(html.contains("href=\"/notifications\""));
        assert!(!html.contains("Daily summary"));
        assert!(!html.contains("Always on"));
    }
}
