//! Password fields are always empty; no submitted secret is accepted by rendering.
use super::*;

pub(crate) fn render_password_page(
    account: &str,
    csrf: &str,
    available: bool,
    notice: Option<&str>,
) -> TrustedHtml {
    let mut fields = String::new();
    for (name, label, autocomplete, maximum) in [
        (
            "current_password",
            "Current password",
            "current-password",
            1024,
        ),
        // HTML maxlength counts UTF-16 units; each of the server's at most
        // 128 Unicode scalar values can require two. Server byte/scalar
        // validation remains authoritative and is never inferred from this cap.
        ("new_password", "New password", "new-password", 256),
        ("confirmation", "Confirm new password", "new-password", 256),
    ] {
        fields.push_str(&format!("<div><label for=\"{name}\">{label}</label><input id=\"{name}\" name=\"{name}\" type=\"password\" autocomplete=\"{autocomplete}\" maxlength=\"{maximum}\" required><button id=\"show-{name}\" type=\"button\" aria-controls=\"{name}\" aria-label=\"Show or hide {label}\" aria-pressed=\"false\" hidden>Show</button></div>"));
    }
    let notice = notice
        .map(|text| format!("<p role=\"alert\">{}</p>", escape_html(text)))
        .unwrap_or_default();
    let unavailable = if available {
        ""
    } else {
        "<p>Password change is unavailable until the account service is qualified. No password change can be submitted here.</p>"
    };
    TrustedHtml::from_template(format!(
        "{}<main id=\"main-content\" class=\"page-shell settings-page\" tabindex=\"-1\"><nav aria-label=\"Breadcrumb\"><a href=\"/settings?section=security\">Security</a> / Change password</nav><section class=\"panel\"><h1>Change password</h1>{notice}{unavailable}<p>Choose 15–128 characters, at most 512 UTF-8 bytes. Use a different password. Confirm with your current password and a fresh authenticator code. A confirmed change signs out your existing sessions.</p><form id=\"password-change-form\" method=\"post\" action=\"/settings/password\" autocomplete=\"off\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><fieldset{}><legend>Confirm your own account</legend>{fields}<label for=\"password-totp\">Fresh authenticator code</label><input id=\"password-totp\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required><button type=\"submit\">Change password</button></fieldset><a class=\"button-link secondary\" href=\"/settings?section=security\">Cancel</a></form><noscript><p>Password fields stay hidden without scripting. You can still submit the form when the account service is available.</p></noscript></section></main>",
        app_header(account, csrf, "settings-security"), escape_html(csrf), if available { "" } else { " disabled" },
    ))
}
