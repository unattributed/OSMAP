//! The only scripted response boundary: our own escaped compose form.
use super::*;

pub(super) const SCRIPT: &str = include_str!("compose_local.js");
// The source gate verifies this digest against the exact included bytes.
pub(super) const SCRIPT_HASH: &str = "sha256-W+KmkRKSGzAL/iijb6GfSB2+XK9QNg25om80ZfDjdCY=";

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
         <button type=\"button\" id=\"compose-leave-save\">Save draft</button>\
         <button type=\"button\" id=\"compose-leave-discard\">Discard changes</button>\
         <button type=\"button\" id=\"compose-leave-keep\" autofocus>Keep editing</button>\
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
