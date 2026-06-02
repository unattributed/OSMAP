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
        ".login-page{position:relative;min-height:100vh;display:grid;justify-items:center;align-items:start;padding:2.4rem 1.5rem 1.4rem;overflow:hidden;background:radial-gradient(circle at 23% 46%,rgba(37,99,235,.1),transparent 15rem),radial-gradient(circle at 86% 30%,rgba(37,99,235,.08),transparent 14rem),linear-gradient(180deg,#fbfdff 0%,#eef5fc 100%)}",
        ".login-decor{position:absolute;z-index:0;pointer-events:none;color:#2563eb;opacity:.42}",
        ".login-decor-left{left:8.5%;top:18%;width:min(28vw,27rem);min-width:18rem}",
        ".login-decor-right{right:6%;top:13%;width:min(22vw,20rem);min-width:14rem;opacity:.32}",
        ".login-decor svg{display:block;width:100%;height:auto}",
        ".login-card{position:relative;z-index:1;width:min(100%,31.5rem);background:rgba(255,255,255,.98);border:1px solid #d4dde9;border-radius:8px;box-shadow:0 20px 50px rgba(15,23,42,.16);padding:1.55rem 1.7rem 1.35rem}",
        ".login-brand{display:flex;align-items:center;justify-content:center;gap:1.15rem;margin-bottom:.9rem}",
        ".login-shield{flex:0 0 auto;width:4.65rem;height:4.65rem;color:#2563eb;filter:drop-shadow(0 10px 14px rgba(37,99,235,.18))}",
        ".login-brand-text{min-width:0}",
        ".login-title{font-size:3rem;line-height:.94;margin:0;font-weight:850;letter-spacing:0;color:#0f172a}",
        ".login-subtitle{font-weight:800;color:#2563eb;margin:.25rem 0 0;font-size:1.05rem}",
        ".login-rule{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:.7rem;color:#8fa3c0;margin:.95rem 0 1rem}",
        ".login-rule:before,.login-rule:after{content:\"\";height:1px;background:#dde5f0}",
        ".login-rule svg{width:1.1rem;height:1.1rem}",
        ".login-kicker{text-align:center;font-size:1.05rem;font-weight:800;margin:0 0 .45rem;color:#111827}",
        ".login-helper{text-align:center;color:#64748b;margin:0 auto 1rem;max-width:21rem;line-height:1.35}",
        ".login-form label{font-size:.86rem}",
        ".login-field{position:relative}",
        ".login-field svg{position:absolute;left:.85rem;top:2.35rem;width:1rem;height:1rem;color:#64748b;pointer-events:none}",
        ".login-field input{height:2.4rem;margin:.25rem 0 .8rem;padding:.58rem .75rem .58rem 2.4rem;max-width:none;border-color:#c7d4e5;box-shadow:0 1px 0 rgba(15,23,42,.02)}",
        ".login-form .primary-button{width:100%;height:2.65rem;margin-top:.1rem;font-size:1rem}",
        ".login-lock{width:1rem;height:1rem}",
        ".login-help{margin:.75rem 0 0;text-align:center;font-size:.86rem;color:#2563eb}",
        ".security-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem;margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--line)}",
        ".security-item{display:grid;grid-template-columns:auto minmax(0,1fr);gap:.5rem;align-items:start;padding:.25rem .1rem}",
        ".security-item svg{width:1.55rem;height:1.55rem;color:#0f172a}",
        ".security-item strong{display:block;font-size:.78rem;line-height:1.15;text-transform:none}",
        ".security-item span{display:block;color:#64748b;font-size:.72rem;line-height:1.2;margin-top:.15rem}",
        ".login-footer{position:relative;z-index:1;margin-top:1.05rem;text-align:center;color:#64748b;font-size:.84rem}",
        ".login-seal{display:inline-grid;place-items:center;width:2.05rem;height:2.05rem;margin-right:.5rem;border-radius:50%;border:1px solid #d5a517;background:#ffdf5d;color:#715100;font-size:.72rem;font-weight:900;vertical-align:middle}",
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
        ".message-html a[href]::after{content:\" (\" attr(href) \")\";font-size:.86em;color:var(--muted);overflow-wrap:anywhere}",
        "@media (max-width:56rem){.page-shell{padding:.75rem}.topbar,.section-header{align-items:stretch;flex-direction:column}.mail-shell,.mail-shell-three{grid-template-columns:1fr}.search-row{grid-template-columns:1fr}.login-card{padding:1.25rem}.login-title{font-size:2.35rem}.login-shield{width:3.8rem;height:3.8rem}.security-grid{grid-template-columns:1fr}.login-decor{display:none}}"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_html_links_visually_disclose_destinations() {
        assert!(browser_css().contains(".message-html a[href]::after"));
        assert!(browser_css().contains("attr(href)"));
    }
}
