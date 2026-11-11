//! The only scripted response boundary: our own escaped compose form.
use super::*;

pub(super) const SCRIPT: &str = include_str!("compose_local.js");
// The source gate verifies this digest against the exact included bytes.
pub(super) const SCRIPT_HASH: &str = "sha256-Z4wtSIvYB89ZOCoTTRSeQXI1/EKfobT0I2ljt4nWqj4=";

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
        "{body}<dialog id=\"compose-leave-dialog\" aria-labelledby=\"compose-leave-title\" aria-describedby=\"compose-leave-description\">\
         <h2 id=\"compose-leave-title\">Save your changes?</h2>\
         <p id=\"compose-leave-description\">You have unsaved changes. Save this message as a draft, discard your changes and leave, or keep editing.</p>\
         <p>Save draft opens the saved message. You can then continue to your destination. Discard changes keeps any previously saved version.</p>\
         <div class=\"compose-leave-actions\">\
         <button type=\"button\" id=\"compose-leave-save\"><span class=\"presentation-icon presentation-icon-save\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Save draft</span></button>\
         <button type=\"button\" id=\"compose-leave-discard\"><span class=\"presentation-icon presentation-icon-bin\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Discard changes</span></button>\
         <button type=\"button\" id=\"compose-leave-keep\" autofocus><span class=\"presentation-icon presentation-icon-close\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Keep editing</span></button>\
         </div></dialog><script id=\"osmap-compose-local\">{SCRIPT}</script>"
    ));
    let mut response = html_response(status_code, reason_phrase, title, enhanced);
    for (name, value) in &mut response.headers {
        if name.eq_ignore_ascii_case("Content-Security-Policy") {
            *value = csp();
        }
    }
    response
}
