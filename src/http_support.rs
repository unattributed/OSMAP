//! Shared HTTP response, logging, and low-level helper functions.
//!
//! These helpers are kept separate from routing so the browser boundary remains
//! easier to review without mixing protocol utilities and route behavior in one
//! file.

use crate::attachment::DownloadedAttachment;
use crate::auth::AuthenticationContext;
use crate::config::LogLevel;
use crate::http::HttpResponse;
use crate::logging::{EventCategory, LogEvent};
use crate::session::SessionError;
use crate::throttle::LoginThrottleError;

/// Builds a redirect response with the current browser-safety headers.
pub(crate) fn redirect_response(
    status_code: u16,
    reason_phrase: &'static str,
    location: &str,
) -> HttpResponse {
    HttpResponse::text(
        status_code,
        reason_phrase,
        format!(
            "<!doctype html><html><body><p>Redirecting to <a href=\"{}\">{}</a>.</p></body></html>",
            escape_html(location),
            escape_html(location),
        ),
    )
    .with_header("Location", location)
    .with_header("Cache-Control", "no-store")
    .with_header("Content-Security-Policy", browser_csp())
    .with_header("Cross-Origin-Resource-Policy", "same-origin")
    .with_header("Referrer-Policy", "no-referrer")
    .with_header("X-Content-Type-Options", "nosniff")
    .with_header("X-Frame-Options", "DENY")
}

/// Builds an HTML response with the current browser-safety headers.
pub(crate) fn html_response(
    status_code: u16,
    reason_phrase: &'static str,
    title: &str,
    body_html: &str,
) -> HttpResponse {
    HttpResponse::text(
        status_code,
        reason_phrase,
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>{}</style></head><body>{}</body></html>",
            escape_html(title),
            browser_css(),
            body_html,
        ),
    )
    .with_header("Cache-Control", "no-store")
    .with_header("Content-Security-Policy", browser_csp())
    .with_header("Cross-Origin-Resource-Policy", "same-origin")
    .with_header("Referrer-Policy", "no-referrer")
    .with_header("X-Content-Type-Options", "nosniff")
    .with_header("X-Frame-Options", "DENY")
}

/// Builds a forced-download response for one resolved attachment payload.
pub(crate) fn attachment_download_response(attachment: &DownloadedAttachment) -> HttpResponse {
    HttpResponse::binary(200, "OK", attachment.body.clone())
        .with_header("Content-Type", attachment.content_type.clone())
        .with_header(
            "Content-Disposition",
            build_attachment_content_disposition(&attachment.filename),
        )
        .with_header("Cache-Control", "no-store")
        .with_header("Cross-Origin-Resource-Policy", "same-origin")
        .with_header("Referrer-Policy", "no-referrer")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("X-Frame-Options", "DENY")
}

/// Returns the current narrow content-security-policy for HTML responses.
pub(crate) fn browser_csp() -> &'static str {
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}

/// Returns the dependency-free CSS used by the server-rendered browser pages.
fn browser_css() -> &'static str {
    concat!(
        ":root{color-scheme:light;--bg:#f5f7fb;--panel:#fff;--panel-soft:#f8fafc;--ink:#0f172a;--muted:#5f6b7a;--line:#d8e0ea;--line-strong:#b7c4d4;--accent:#2563eb;--accent-strong:#1d4ed8;--ok:#137333;--warn:#9a5b00;--danger:#b42318;--focus:#0ea5e9}",
        "*{box-sizing:border-box}",
        "body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;background:var(--bg);color:var(--ink);max-width:none;margin:0;padding:0;line-height:1.5}",
        "a{color:#0f4eb8;text-decoration:none}a:hover{text-decoration:underline}",
        "main{width:100%}",
        "h1,h2,h3,p{margin-top:0}",
        "table{border-collapse:separate;border-spacing:0;width:100%;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}",
        "th,td{border-bottom:1px solid var(--line);padding:.65rem .75rem;text-align:left;vertical-align:top}",
        "th{background:#eef4fb;font-size:.8rem;text-transform:uppercase;color:#344255;letter-spacing:0}",
        "tr:last-child td{border-bottom:0}",
        "form{margin:0}",
        "label{font-weight:650;color:#223047}",
        "fieldset{margin:0;border:0}legend{font-weight:800;margin-bottom:.5rem}",
        "input,textarea,select{display:block;margin:.3rem 0 1rem;padding:.7rem .75rem;width:100%;max-width:48rem;border:1px solid var(--line-strong);border-radius:7px;background:#fff;color:var(--ink);font:inherit}",
        "input[type=checkbox],input[type=radio]{display:inline-block;width:auto;margin:.15rem .45rem .15rem 0}",
        "textarea{min-height:16rem}",
        "button,.button-link{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;min-height:2.35rem;padding:.55rem .9rem;border:1px solid var(--line-strong);border-radius:7px;background:#fff;color:#172033;font:inherit;font-weight:650;cursor:pointer;text-decoration:none}",
        "button:hover,.button-link:hover{border-color:#8ba2bd;text-decoration:none}",
        ".primary-button{background:var(--accent);border-color:var(--accent);color:#fff}",
        ".primary-button:hover{background:var(--accent-strong);border-color:var(--accent-strong)}",
        "a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid var(--focus);outline-offset:2px}",
        "nav{margin:0}",
        ".muted{color:var(--muted)}",
        ".page-shell{min-height:100vh;padding:1.5rem}",
        ".topbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:1rem;padding:.8rem 1rem;background:var(--panel);border:1px solid var(--line);border-radius:8px}",
        ".brand{display:flex;align-items:center;gap:.65rem;font-weight:800}",
        ".brand-mark{display:inline-grid;place-items:center;width:2.1rem;height:2.1rem;border-radius:7px;background:#dbeafe;color:#123b7a;border:1px solid #b8cffc;font-weight:900}",
        ".top-actions,.toolbar,.status-row,.badge-list{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}",
        ".logout-form{display:inline-flex}",
        ".badge,.status-pill{display:inline-flex;align-items:center;gap:.35rem;border:1px solid var(--line);border-radius:999px;background:#fff;padding:.35rem .6rem;color:#223047;font-size:.86rem}",
        ".badge-ok{border-color:#b7dfc2;background:#eefaf1;color:#14532d}",
        ".badge-warn{border-color:#f2d394;background:#fff8e6;color:#714500}",
        ".notice{border:1px solid var(--line);border-radius:8px;background:var(--panel-soft);padding:.75rem .9rem;margin:.75rem 0}",
        ".notice-success{border-color:#a8d8b2;background:#effaf1;color:#14532d}",
        ".notice-error{border-color:#f1b4ae;background:#fff1f0;color:#8a1f16}",
        ".login-page{min-height:100vh;display:grid;place-items:center;padding:2rem;background:linear-gradient(180deg,#f8fbff 0%,#eef4fb 100%)}",
        ".login-card{width:min(100%,30rem);background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:8px;box-shadow:0 16px 45px rgba(15,23,42,.13);padding:2rem}",
        ".login-brand{display:flex;align-items:center;justify-content:center;gap:.9rem;margin-bottom:1.25rem}",
        ".login-brand .brand-mark{width:3rem;height:3rem;font-size:1.2rem}",
        ".login-title{font-size:2rem;line-height:1.05;margin:0}",
        ".login-subtitle{text-align:center;font-weight:750;color:#2563eb;margin:-.65rem 0 1.5rem}",
        ".login-helper{text-align:center;color:var(--muted);margin-bottom:1.25rem}",
        ".security-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.65rem;margin-top:1.25rem;padding-top:1.25rem;border-top:1px solid var(--line)}",
        ".security-item{border:1px solid var(--line);border-radius:8px;background:var(--panel-soft);padding:.65rem}",
        ".security-item strong{display:block;font-size:.86rem}",
        ".security-item span{display:block;color:var(--muted);font-size:.78rem}",
        ".mail-shell{display:grid;grid-template-columns:minmax(12rem,16rem) minmax(0,1fr);gap:1rem;align-items:start}",
        ".mail-shell-three{grid-template-columns:minmax(12rem,16rem) minmax(16rem,24rem) minmax(0,1fr)}",
        ".folder-pane,.content-pane,.reading-pane,.message-summary-pane,.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px}",
        ".folder-pane{padding:.8rem}",
        ".folder-pane h2,.panel h2,.message-summary-pane h2,.reading-pane h2{font-size:.9rem;text-transform:uppercase;color:#3e4b5f;letter-spacing:0;margin:0 0 .65rem}",
        ".folder-list{list-style:none;padding:0;margin:0;display:grid;gap:.15rem}",
        ".folder-list a{display:block;padding:.45rem .55rem;border-radius:6px;color:#172033}",
        ".folder-list a[aria-current=page],.folder-list a:hover{background:#eaf2ff;text-decoration:none}",
        ".content-pane,.reading-pane,.message-summary-pane,.panel{padding:1rem;min-width:0}",
        ".section-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem}",
        ".section-title{margin:0;font-size:1.35rem}",
        ".search-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.65rem;align-items:end;margin:1rem 0}",
        ".search-row input{margin-bottom:0;max-width:none}",
        ".search-row label:last-child{grid-column:1/-1}",
        ".table-wrap{overflow:auto}",
        ".message-list-table td,.message-list-table th{white-space:nowrap}",
        ".message-list-table td:nth-child(3),.message-list-table td:nth-child(4){white-space:normal}",
        ".message-meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.35rem .75rem;margin:0 0 1rem}",
        ".message-meta dt{font-weight:750;color:#344255}.message-meta dd{margin:0;overflow-wrap:anywhere}",
        ".action-stack{display:grid;gap:.75rem;margin-top:1rem}",
        ".body-panel{padding:1rem;background:#fff;border:1px solid var(--line);border-radius:8px;overflow:auto}",
        ".attachment-list{list-style:none;padding:0;margin:.5rem 0 0;display:grid;gap:.5rem}",
        ".attachment-item{border:1px solid var(--line);border-radius:8px;padding:.65rem;background:var(--panel-soft)}",
        ".message-html{overflow-wrap:anywhere}",
        ".message-html p,.message-html ul,.message-html ol,.message-html blockquote,.message-html pre,.message-html table{margin:.75rem 0}",
        ".message-html pre,pre{white-space:pre-wrap;overflow-wrap:anywhere}",
        ".message-html a{word-break:break-word}",
        "@media (max-width:56rem){.page-shell{padding:.75rem}.topbar,.section-header{align-items:stretch;flex-direction:column}.mail-shell,.mail-shell-three{grid-template-columns:1fr}.security-grid{grid-template-columns:1fr}.search-row{grid-template-columns:1fr}.login-card{padding:1.25rem}}"
    )
}

/// Builds a structured HTTP info event with the shared request fields attached.
pub(crate) fn build_http_info_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Info, EventCategory::Http, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Builds a structured HTTP warning event with the shared request fields
/// attached.
pub(crate) fn build_http_warning_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Warn, EventCategory::Http, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Builds a structured auth warning event with the shared request fields
/// attached.
pub(crate) fn build_auth_warning_event(
    action: &'static str,
    message: &str,
    context: &AuthenticationContext,
) -> LogEvent {
    LogEvent::new(LogLevel::Warn, EventCategory::Auth, action, message)
        .with_field("request_id", context.request_id.clone())
        .with_field("remote_addr", context.remote_addr.clone())
        .with_field("user_agent", context.user_agent.clone())
}

/// Maps session errors into small stable labels for browser-operation logs.
pub(crate) fn session_error_label(error: &SessionError) -> &'static str {
    match error {
        SessionError::InvalidToken { .. } => "invalid_token",
        SessionError::RandomSourceFailure { .. } => "random_source_failure",
        SessionError::StoreFailure { .. } => "store_failure",
        SessionError::SessionNotFound { .. } => "session_not_found",
    }
}

/// Maps throttle-store errors into small stable labels for auth-abuse logs.
pub(crate) fn throttle_store_error_label(error: &LoginThrottleError) -> &'static str {
    match error {
        LoginThrottleError::StoreFailure { .. } => "store_failure",
    }
}

/// Maps a public reason string into a small browser-facing message.
pub(crate) fn public_reason_message(reason: &str) -> &'static str {
    match reason {
        "invalid_credentials" => "The supplied credentials were not accepted.",
        "invalid_archive_mailbox" => {
            "The selected archive mailbox does not exist for this account."
        }
        "invalid_mailbox" => "The selected mailbox does not exist for this account.",
        "invalid_message_reference" => "The selected message was not found in that mailbox.",
        "invalid_request" => "The submitted request was not valid.",
        "invalid_second_factor" => "The supplied credentials were not accepted.",
        "too_many_attempts" => "Too many login attempts were observed. Please try again later.",
        "too_many_submissions" => {
            "Too many outbound submissions were observed. Please try again later."
        }
        "too_many_message_moves" => {
            "Too many mailbox move requests were observed. Please try again later."
        }
        "not_found" => "The requested item was not found.",
        _ => "The service could not complete the request at this time.",
    }
}

/// Escapes HTML-significant characters for simple template insertion.
pub(crate) fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// URL-encodes a query component without bringing in an HTTP utility crate.
pub(crate) fn url_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{:02X}", byte)),
        }
    }
    encoded
}

/// Compares two byte slices without early exit for CSRF token validation.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }

    diff == 0
}

/// Builds a conservative attachment-style `Content-Disposition` header value.
fn build_attachment_content_disposition(filename: &str) -> String {
    format!(
        "attachment; filename=\"{}\"",
        escape_header_quoted_string(filename)
    )
}

/// Escapes a response header quoted-string without widening filename syntax.
fn escape_header_quoted_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
