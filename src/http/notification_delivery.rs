//! Fixed first-party enhancement for the native notification/settings surfaces.
use super::*;

pub(super) const SCRIPT: &str = include_str!("notification_local.js");
pub(super) const SCRIPT_HASH: &str = "sha256-2nVyQbOkltiXViQKNARlGeOd0NlQFrBybHjr5Y0hBSU=";

pub(crate) fn controls() -> &'static str {
    concat!(
        "<section id=\"osmap-notification-browser\" class=\"panel notification-browser-controls\"><h2>This browser</h2>",
        "<p>Desktop and sound are off here until you explicitly enable them. Save your account preferences first, then choose the channels for this browser. Notices use generic OSMAP text, without message subjects or contents.</p>",
        "<p id=\"notification-browser-status\" role=\"status\" aria-live=\"polite\">Browser delivery is off. JavaScript and a successful authenticated update are required to enable it.</p>",
        "<div class=\"notification-browser-actions\"><button type=\"button\" id=\"notification-desktop-enable\" disabled>Enable desktop notices</button> ",
        "<button type=\"button\" id=\"notification-desktop-disable\" class=\"secondary\" disabled>Disable desktop notices</button> ",
        "<button type=\"button\" id=\"notification-sound-enable\" disabled>Enable sound on this page</button> ",
        "<button type=\"button\" id=\"notification-sound-disable\" class=\"secondary\" disabled>Disable sound</button></div>",
        "<p class=\"muted\">Only this open, visible page checks for new notices, at most once every 30 seconds. Existing notices are not announced when the page opens or resumes. Permission and API requests do not prove an alert was displayed or heard. Signing out ends authenticated updates. Disable the channels here to clear your browser delivery choices.</p></section>"
    )
}

pub(super) fn csp() -> String {
    format!(
        "{}; connect-src 'self'; script-src '{}'; script-src-attr 'none'",
        crate::http_support::browser_csp(),
        SCRIPT_HASH
    )
}

pub(super) fn response(
    status_code: u16,
    reason_phrase: &'static str,
    title: &str,
    body: TrustedHtml,
) -> HttpResponse {
    let enhanced = TrustedHtml::from_template(format!(
        "{body}<script id=\"osmap-notification-local\">{SCRIPT}</script>"
    ));
    let mut response = html_response(status_code, reason_phrase, title, enhanced);
    for (name, value) in &mut response.headers {
        if name.eq_ignore_ascii_case("Content-Security-Policy") {
            *value = csp();
        }
    }
    response
}

#[cfg(test)]
mod tests {
    include!("notification_delivery_tests.rs");
}
