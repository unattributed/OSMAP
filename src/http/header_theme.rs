//! Bounded return destinations for native header theme submissions.
use super::*;

pub(super) const FALLBACK: &str = "/settings?section=appearance";
const SLOT: &str = "<input type=\"hidden\" name=\"return_to\" value=\"/settings?section=appearance\" data-header-return>";

pub(super) fn safe_return(value: &str) -> Option<String> {
    if value.len() > 2048 || value.contains(['#', '\\']) || value.chars().any(char::is_control) {
        return None;
    }
    let (path, query) = value.split_once('?').unwrap_or((value, ""));
    let mut fields = parse_urlencoded_form(query.as_bytes(), 16, 2048).ok()?;
    let allowed: &[&str] = match path {
        "/settings" => &["section", "q"],
        "/sessions" | "/mailboxes" | "/contacts" | "/snoozed" => &[],
        "/drafts" => {
            crate::draft_list::DraftListView::parse(&fields).ok()?;
            &["filter", "sort", "q", "saved", "deleted"]
        }
        "/draft" => &["id", "preview", "preflight"],
        "/compose" => &["mode", "mailbox", "uid", "mailbox_guid", "message_guid"],
        "/message" => &[
            "mailbox",
            "uid",
            "view",
            "mailbox_guid",
            "message_guid",
            "return_to",
        ],
        "/mailbox" | "/search" => return crate::mail_navigation::safe_mail_return(value),
        _ => return None,
    };
    if fields
        .iter()
        .any(|(key, value)| !allowed.contains(&key.as_str()) || value.chars().any(char::is_control))
    {
        return None;
    }
    if let Some(value) = fields.get_mut("return_to") {
        if !(value.starts_with("/mailbox?") || value.starts_with("/search?")) {
            return None;
        }
        *value = crate::mail_navigation::safe_mail_return(value)?;
    }
    // Destination GET handlers validate their own identifiers and permissions.
    // Reconstructing each query value prevents it becoming URL structure.
    let query = fields
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    Some(if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    })
}

pub(super) fn apply_context(response: &mut HttpResponse, request: &HttpRequest) {
    if !response.headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("Content-Type") && value == "text/html; charset=utf-8"
    }) || response
        .headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("Content-Disposition"))
    {
        return;
    }
    let Ok(html) = std::str::from_utf8(&response.body) else {
        return;
    };
    if !html.starts_with("<!doctype html><html lang=\"en\" data-appearance=\"")
        || !html.contains("data-header-theme=")
    {
        return;
    }
    let candidate = if request.method == HttpMethod::Get {
        let query = request
            .query_params
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        if query.is_empty() {
            request.path.clone()
        } else {
            format!("{}?{query}", request.path)
        }
    } else {
        FALLBACK.to_owned()
    };
    let destination = safe_return(&candidate).unwrap_or_else(|| FALLBACK.to_owned());
    let mut rendered = html.replacen(
        SLOT,
        &format!(
            "<input type=\"hidden\" name=\"return_to\" value=\"{}\" data-header-return>",
            escape_html(&destination)
        ),
        1,
    );
    for theme in ["light", "dark"] {
        if html.starts_with(&format!(
            "<!doctype html><html lang=\"en\" data-appearance=\"{theme}\""
        )) {
            rendered = rendered.replacen(
                &format!("data-header-theme=\"{theme}\" aria-pressed=\"false\""),
                &format!("data-header-theme=\"{theme}\" aria-pressed=\"true\""),
                1,
            );
        }
    }
    response.body = rendered.into_bytes();
}
