//! The only scripted response boundary: our own escaped compose form.
use super::*;

pub(super) const SCRIPT: &str = include_str!("compose_local.js");
// The source gate verifies this digest against the exact included bytes.
pub(super) const SCRIPT_HASH: &str = "sha256-kh8tYa8AQwqxy9l64g1sCx8epjT43a/Wj5pR91Smywc=";

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
    // No dynamic string or message content is interpolated into the script.
    let enhanced = TrustedHtml::from_template(format!(
        "{body}<script id=\"osmap-compose-local\">{SCRIPT}</script>"
    ));
    let mut response = html_response(status_code, reason_phrase, title, enhanced);
    for (name, value) in &mut response.headers {
        if name.eq_ignore_ascii_case("Content-Security-Policy") {
            *value = csp();
        }
    }
    response
}
