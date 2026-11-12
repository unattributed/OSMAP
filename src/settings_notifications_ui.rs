//! Native saved choices; mandatory security facts retain recording authority.
use super::*;

pub(crate) fn render_notifications_page(
    account: &str,
    csrf: &str,
    preference: Option<&crate::notification_preferences::Preference>,
    notice: Option<&str>,
) -> TrustedHtml {
    let notice = notice
        .map(|text| format!("<p class=notice role=alert>{}</p>", escape_html(text)))
        .unwrap_or_default();
    let mut categories = String::new();
    let mut channels = String::new();
    let choices = preference.map(|p| p.choices).unwrap_or_default();
    for (name,label,checked,scope) in [
        ("new_mail","New mail",choices.new_mail,"New owned Inbox messages observed after the initial baseline; checked on Inbox refresh."),
        ("mentions","Mentions",choices.mentions,"Your exact email address mentioned in readable message text; checked when that text is opened."),
        ("openpgp","OpenPGP status changes",choices.openpgp,"Confirmed public-key imports and removals. Personal-key and protection-policy changes remain mandatory security notices."),
        ("submission","Submission updates",choices.submission,"Observed local submission and scheduled-send results. Acceptance does not prove remote delivery."),
    ] {categories.push_str(&checkbox(name,label,checked,scope,preference.is_some()));}
    categories.push_str("<div class=notification-setting><span>Security events</span><strong>Required</strong></div><p>Confirmed session, password, TOTP, recovery, personal-key and protection-policy events remain recorded and visible. Optional choices cannot turn off mandatory recovery/security alerts.</p>");
    for (name,label,checked,scope) in [
        ("sound","Sound",choices.sound,"Save this preference, then explicitly enable sound in this browser. A user gesture is required; an audio request is not proof that a sound was heard."),
        ("desktop","Desktop notifications",choices.desktop,"Save this preference, then explicitly enable desktop notices for this account in this browser. Browser permission and platform support are separate checks."),
    ]{channels.push_str(&checkbox(name,label,checked,scope,preference.is_some()));}
    let form_start=preference.map(|p|format!("<form id=\"notification-preferences-form\" method=\"post\" action=\"/settings/notifications\"><input type=hidden name=\"csrf_token\" value=\"{}\"><input type=hidden name=\"expected_revision\" value=\"{}\"><input type=\"hidden\" name=\"choice_version\" value=\"1\">",escape_html(csrf),p.revision)).unwrap_or_else(||"<p class=notice>Notification preferences are unavailable. Reload to inspect the saved state; no saved value was reset.</p>".into());
    let digest=preference.map(|p|format!("<div class=notification-setting><label for=notice-digest>Digest</label><select id=\"notice-digest\" name=\"digest\"><option value=\"individual\"{}>Individual</option><option value=\"daily\"{}>Daily (UTC)</option></select></div><p>In-app inbox presentation only. Every retained mandatory notice and its read control remains available. No scheduled or external digest is sent.</p>",if p.digest==crate::notification_preferences::DigestMode::Individual{" selected"}else{""},if p.digest==crate::notification_preferences::DigestMode::Daily{" selected"}else{""})).unwrap_or_else(||"<label for=notice-digest>Digest</label><select id=\"notice-digest\" disabled><option>Unavailable</option></select>".into());
    let form_end = if preference.is_some() {
        "<button type=submit><span class=\"presentation-icon presentation-icon-save\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Save notification preferences</span></button></form>"
    } else {
        ""
    };
    TrustedHtml::from_template(format!("{}<main id=main-content class=\"page-shell settings-page settings-notifications-page\" tabindex=-1><div class=page-intro><h1>Settings</h1><p>Choose optional notices and browser delivery for this account.</p></div>{notice}<div class=settings-layout>{}<div class=notification-settings-content>{form_start}<div class=notification-settings-cards><section class=\"notification-settings-card\"><h2>In-app Notifications</h2>{categories}</section><section class=\"notification-settings-card\"><h2>Notification Delivery</h2>{digest}{channels}</section></div>{form_end}<div class=notification-settings-note><p>Events report observed actions, not a security score. Browser delivery is available only while this notification page is open and visible; unsupported or denied permissions do not change the saved inbox.</p><a class=\"button-link secondary\" href=\"/notifications\"><span class=\"presentation-icon presentation-icon-notifications\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Open notifications</span></a></div>{}</div></div></main>",app_header(account,csrf,"settings-notifications"),settings_navigation("notifications"),crate::http::notification_delivery::controls()))
}
fn checkbox(name: &str, label: &str, checked: bool, scope: &str, available: bool) -> String {
    format!("<div class=notification-setting><label for=notice-{name}>{label}</label><input form=\"notification-preferences-form\" id=notice-{name} class=settings-switch type=checkbox name=\"{name}\" value=\"1\"{}{} aria-describedby=notice-{name}-scope></div><p id=notice-{name}-scope>{scope}</p>",if checked{" checked"}else{""},if available{""}else{" disabled"})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_choices_are_native_mandatory_security_and_escaped() {
        let html = render_notifications_page(
            "<foreign&name>@example.test",
            "token",
            Some(&crate::notification_preferences::Preference::default()),
            None,
        );
        assert!(!html.contains("<foreign&name>"));
        assert!(html.contains("&lt;foreign&amp;name&gt;@example.test"));
        assert_eq!(html.matches("notification-settings-card\"").count(), 2);
        for name in [
            "new_mail",
            "mentions",
            "openpgp",
            "submission",
            "sound",
            "desktop",
        ] {
            assert!(html.contains(&format!("name=\"{name}\" value=\"1\"")));
        }
        assert!(html.contains("Security events</span><strong>Required"));
        assert!(html.contains("type=\"hidden\" name=\"choice_version\" value=\"1\""));
        assert!(html.contains("Acceptance does not prove remote delivery"));
        assert!(!html.contains("name=\"security\""));
    }
    #[test]
    fn all_optional_choices_off_still_publish_the_explicit_choice_version() {
        let saved = crate::notification_preferences::Preference {
            choices: crate::notification_preferences::Choice {
                new_mail: false,
                mentions: false,
                openpgp: false,
                submission: false,
                sound: false,
                desktop: false,
            },
            ..crate::notification_preferences::Preference::default()
        };
        let html = render_notifications_page("alice@example.test", "csrf", Some(&saved), None);
        assert!(html.contains("name=\"choice_version\" value=\"1\""));
        assert!(!html.contains("value=\"1\" checked"));
        assert!(html.contains("Security events</span><strong>Required"));
    }
    #[test]
    fn unavailable_preferences_cannot_be_saved_or_fabricated() {
        let html =
            render_notifications_page("alice@example.test", "token", None, Some("<unknown>"));
        assert!(!html.contains("method=\"post\" action=\"/settings/notifications\""));
        assert!(html.contains("&lt;unknown&gt;"));
        assert!(!html.contains("name=\"choice_version\""));
        for name in [
            "new_mail",
            "mentions",
            "openpgp",
            "submission",
            "sound",
            "desktop",
        ] {
            let id = format!("id=notice-{name} ");
            let input = html
                .split_once(&id)
                .expect("native checkbox")
                .1
                .split('>')
                .next()
                .unwrap();
            assert!(
                input.contains(" disabled"),
                "{name} must be disabled without saved preferences"
            );
        }
        let digest = html
            .split_once("id=\"notice-digest\"")
            .expect("native digest")
            .1
            .split('>')
            .next()
            .unwrap();
        assert!(digest.contains(" disabled"));
    }
}
