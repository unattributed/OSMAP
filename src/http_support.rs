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
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>body{{font-family:ui-monospace,monospace;max-width:72rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #444;padding:.5rem;text-align:left;vertical-align:top}}form{{margin:0}}input,textarea{{display:block;margin:.25rem 0 1rem;padding:.5rem;width:100%;max-width:48rem}}textarea{{min-height:16rem}}button{{padding:.5rem .9rem}}nav{{margin-bottom:1.5rem}}.muted{{color:#555}}.message-html{{overflow-wrap:anywhere}}.message-html p,.message-html ul,.message-html ol,.message-html blockquote,.message-html pre,.message-html table{{margin:.75rem 0}}.message-html pre{{white-space:pre-wrap}}.message-html a{{word-break:break-word}}</style></head><body>{}</body></html>",
            escape_html(title),
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
