//! Server-rendered browser HTML helpers for the current OSMAP web slice.
//!
//! Keeping these rendering helpers separate from routing reduces the amount of
//! browser-facing template code inside the request parser and route logic.

use crate::http::BrowserVisibleSession;
use crate::http_support::{escape_html, url_encode};
use crate::mailbox::{MailboxEntry, MessageSearchResult, MessageSummary};
use crate::rendering::{HtmlDisplayPreference, RenderedMessageView};

/// Small view model for the current server-rendered compose page.
pub(crate) struct ComposePageModel<'a> {
    pub heading: &'a str,
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub success_message: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub context_notice: Option<&'a str>,
    pub to_value: &'a str,
    pub subject_value: &'a str,
    pub body_value: &'a str,
}

/// Small view model for the first bounded settings page.
pub(crate) struct SettingsPageModel<'a> {
    pub canonical_username: &'a str,
    pub csrf_token: &'a str,
    pub success_message: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub html_display_preference: HtmlDisplayPreference,
}

/// Renders the current login page with an optional operator-safe error banner.
pub(crate) fn render_login_page(error_message: Option<&str>) -> String {
    let banner = match error_message {
        Some(error_message) => format!(
            "<p><strong>Request failed:</strong> {}</p>",
            escape_html(error_message)
        ),
        None => String::new(),
    };

    format!(
        "<h1>OSMAP Login</h1><p class=\"muted\">This first browser slice uses one form for username, password, and TOTP while still enforcing the underlying primary-auth and second-factor boundaries.</p>{banner}<form method=\"post\" action=\"/login\"><label>Username<input type=\"text\" name=\"username\" autocomplete=\"username\"></label><label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\"></label><label>TOTP Code<input type=\"text\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\"></label><button type=\"submit\">Sign In</button></form>"
    )
}

/// Renders the mailbox home page for the validated user.
pub(crate) fn render_mailboxes_page(
    canonical_username: &str,
    csrf_token: &str,
    mailboxes: &[MailboxEntry],
) -> String {
    let mut items = String::new();
    for mailbox in mailboxes {
        let mailbox_name = escape_html(&mailbox.name);
        let mailbox_href = format!("/mailbox?name={}", url_encode(&mailbox.name));
        items.push_str(&format!(
            "<li><a href=\"{}\">{}</a></li>",
            escape_html(&mailbox_href),
            mailbox_name,
        ));
    }

    format!(
        "<nav><a href=\"/compose\">Compose</a> | <a href=\"/sessions\">Sessions</a> | <a href=\"/settings\">Settings</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Mailboxes</h1><p>Signed in as <strong>{}</strong>.</p><ul>{}</ul>",
        escape_html(csrf_token),
        escape_html(canonical_username),
        items,
    )
}

/// Renders the message-list page for one mailbox.
pub(crate) fn render_message_list_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: &str,
    messages: &[MessageSummary],
    success_message: Option<&str>,
) -> String {
    let success_banner = match success_message {
        Some(success_message) => format!(
            "<p><strong>Update complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let mut rows = String::new();
    for message in messages {
        let message_href = format!(
            "/message?mailbox={}&uid={}",
            url_encode(mailbox_name),
            message.uid
        );
        rows.push_str(&format!(
            "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&message_href),
            message.uid,
            escape_html(&message.date_received),
            escape_html(&message.flags.join(" ")),
            message.size_virtual,
        ));
    }

    format!(
        "<nav><a href=\"/mailboxes\">Back to mailboxes</a> | <a href=\"/compose\">Compose</a> | <a href=\"/sessions\">Sessions</a> | <a href=\"/settings\">Settings</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Mailbox: {}</h1><p>Signed in as <strong>{}</strong>.</p>{}<form method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><label>Search this mailbox<input type=\"text\" name=\"q\" autocomplete=\"off\"></label><button type=\"submit\">Search</button></form><table><thead><tr><th>UID</th><th>Received</th><th>Flags</th><th>Size</th></tr></thead><tbody>{}</tbody></table>",
        escape_html(csrf_token),
        escape_html(mailbox_name),
        escape_html(canonical_username),
        success_banner,
        escape_html(mailbox_name),
        rows,
    )
}

/// Renders a mailbox-scoped search-results page.
pub(crate) fn render_message_search_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: &str,
    query: &str,
    results: &[MessageSearchResult],
) -> String {
    let mut rows = String::new();
    if results.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"6\">No messages matched this mailbox-scoped search.</td></tr>",
        );
    } else {
        for result in results {
            let message_href = format!(
                "/message?mailbox={}&uid={}",
                url_encode(mailbox_name),
                result.uid
            );
            rows.push_str(&format!(
                "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&message_href),
                result.uid,
                escape_html(result.subject.as_deref().unwrap_or("<none>")),
                escape_html(result.from.as_deref().unwrap_or("<none>")),
                escape_html(&result.date_received),
                escape_html(&result.flags.join(" ")),
                result.size_virtual,
            ));
        }
    }

    format!(
        "<nav><a href=\"/mailbox?name={}\">Back to mailbox</a> | <a href=\"/mailboxes\">All mailboxes</a> | <a href=\"/compose\">Compose</a> | <a href=\"/sessions\">Sessions</a> | <a href=\"/settings\">Settings</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Search Results</h1><p>Signed in as <strong>{}</strong>.</p><p class=\"muted\">This first search slice stays mailbox-scoped and backend-authoritative: Dovecot evaluates the query and the browser only renders bounded results.</p><form method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><label>Search this mailbox<input type=\"text\" name=\"q\" value=\"{}\" autocomplete=\"off\"></label><button type=\"submit\">Search</button></form><p><strong>Mailbox:</strong> {}<br><strong>Query:</strong> {}<br><strong>Results:</strong> {}</p><table><thead><tr><th>UID</th><th>Subject</th><th>From</th><th>Received</th><th>Flags</th><th>Size</th></tr></thead><tbody>{}</tbody></table>",
        escape_html(&url_encode(mailbox_name)),
        escape_html(csrf_token),
        escape_html(canonical_username),
        escape_html(mailbox_name),
        escape_html(query),
        escape_html(mailbox_name),
        escape_html(query),
        results.len(),
        rows,
    )
}

/// Renders the message-view page using the existing safe renderer output.
pub(crate) fn render_message_view_page(
    canonical_username: &str,
    csrf_token: &str,
    rendered: &RenderedMessageView,
) -> String {
    let mut attachments = String::new();
    if rendered.attachments.is_empty() {
        attachments.push_str("<li>No attachment metadata surfaced for this message.</li>");
    } else {
        for attachment in &rendered.attachments {
            let download_href = format!(
                "/attachment?mailbox={}&uid={}&part={}",
                url_encode(&rendered.mailbox_name),
                rendered.uid,
                url_encode(&attachment.part_path),
            );
            attachments.push_str(&format!(
                "<li>Part <strong>{}</strong>: {} ({}, {}, {} bytes) [<a href=\"{}\">Download</a>]</li>",
                escape_html(&attachment.part_path),
                escape_html(attachment.filename.as_deref().unwrap_or("<unnamed>")),
                escape_html(&attachment.content_type),
                escape_html(attachment.disposition.as_str()),
                attachment.size_hint_bytes,
                escape_html(&download_href),
            ));
        }
    }

    let move_form = format!(
        "<h2>Move Message</h2><p class=\"muted\">This first folder-organization slice moves one message into an existing mailbox. Archive behavior uses the same path by selecting your archive mailbox name.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><label>Destination Mailbox<input type=\"text\" name=\"destination_mailbox\" autocomplete=\"off\"></label><button type=\"submit\">Move Message</button></form>",
        escape_html(csrf_token),
        escape_html(&rendered.mailbox_name),
        rendered.uid,
    );
    let rendering_notice = match rendered.rendering_mode.as_str() {
        "sanitized_html" => "<p class=\"muted\">HTML content is shown through the current allowlist sanitization policy. Active content, external fetches, and unsafe URLs are removed.</p>",
        _ => "",
    };

    format!(
        "<nav><a href=\"/mailbox?name={}\">Back to mailbox</a> | <a href=\"/compose\">Compose</a> | <a href=\"/sessions\">Sessions</a> | <a href=\"/settings\">Settings</a> | <a href=\"/compose?mode=reply&mailbox={}&uid={}\">Reply</a> | <a href=\"/compose?mode=forward&mailbox={}&uid={}\">Forward</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Message View</h1><p>Signed in as <strong>{}</strong>.</p><dl><dt>Mailbox</dt><dd>{}</dd><dt>UID</dt><dd>{}</dd><dt>Subject</dt><dd>{}</dd><dt>From</dt><dd>{}</dd><dt>Received</dt><dd>{}</dd><dt>MIME Type</dt><dd>{}</dd><dt>Body Source</dt><dd>{}</dd><dt>Rendering Mode</dt><dd>{}</dd><dt>HTML Present</dt><dd>{}</dd></dl>{}{}<h2>Attachments</h2><ul>{}</ul><h2>Body</h2>{}",
        escape_html(&url_encode(&rendered.mailbox_name)),
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        escape_html(csrf_token),
        escape_html(canonical_username),
        escape_html(&rendered.mailbox_name),
        rendered.uid,
        escape_html(rendered.subject.as_deref().unwrap_or("<none>")),
        escape_html(rendered.from.as_deref().unwrap_or("<none>")),
        escape_html(&rendered.date_received),
        escape_html(&rendered.mime_top_level_content_type),
        escape_html(rendered.body_source.as_str()),
        escape_html(rendered.rendering_mode.as_str()),
        if rendered.contains_html_body { "yes" } else { "no" },
        rendering_notice,
        move_form,
        attachments,
        rendered.body_html,
    )
}

/// Renders the browser-visible session-management page.
pub(crate) fn render_sessions_page(
    canonical_username: &str,
    current_session_id: &str,
    csrf_token: &str,
    sessions: &[BrowserVisibleSession],
    success_message: Option<&str>,
) -> String {
    let success_banner = match success_message {
        Some(success_message) => format!(
            "<p><strong>Update complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };

    let mut rows = String::new();
    for session in sessions {
        let state = if session.revoked_at.is_some() {
            "revoked"
        } else if session.session_id == current_session_id {
            "current"
        } else {
            "active"
        };
        let action = if session.revoked_at.is_some() {
            "<span class=\"muted\">Already revoked</span>".to_string()
        } else {
            format!(
                "<form method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"session_id\" value=\"{}\"><button type=\"submit\">{}</button></form>",
                escape_html(csrf_token),
                escape_html(&session.session_id),
                if session.session_id == current_session_id {
                    "Revoke This Session"
                } else {
                    "Revoke"
                }
            )
        };
        let revoked_at = session
            .revoked_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());

        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&session.session_id),
            escape_html(state),
            session.issued_at,
            session.last_seen_at,
            session.expires_at,
            escape_html(&revoked_at),
            escape_html(&session.remote_addr),
            escape_html(&session.user_agent),
            action,
        ));
    }

    format!(
        "<nav><a href=\"/mailboxes\">Back to mailboxes</a> | <a href=\"/compose\">Compose</a> | <a href=\"/settings\">Settings</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Sessions</h1><p>Signed in as <strong>{}</strong>.</p><p class=\"muted\">This first self-service session view exposes the persisted session metadata already tracked by the runtime so users can see and revoke their own browser sessions without introducing a heavier device-management model.</p>{}<table><thead><tr><th>Session ID</th><th>Status</th><th>Issued</th><th>Last Seen</th><th>Expires</th><th>Revoked</th><th>Remote Address</th><th>User Agent</th><th>Action</th></tr></thead><tbody>{}</tbody></table>",
        escape_html(csrf_token),
        escape_html(canonical_username),
        success_banner,
        rows,
    )
}

/// Renders the compose page for the current user and CSRF-bound session.
pub(crate) fn render_compose_page(model: &ComposePageModel<'_>) -> String {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<p><strong>Submission complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<p><strong>Request failed:</strong> {}</p>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let context_banner = match model.context_notice {
        Some(context_notice) => format!(
            "<p><strong>Context:</strong> {}</p>",
            escape_html(context_notice)
        ),
        None => String::new(),
    };

    format!(
        "<nav><a href=\"/mailboxes\">Back to mailboxes</a> | <a href=\"/sessions\">Sessions</a> | <a href=\"/settings\">Settings</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>{}</h1><p>Signed in as <strong>{}</strong>.</p><p class=\"muted\">This send slice uses the local submission surface, keeps the browser body plain-text-first, accepts bounded new file uploads, and still does not reattach files from the source message automatically.</p>{}{}{}<form method=\"post\" action=\"/send\" enctype=\"multipart/form-data\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><label>To<input type=\"text\" name=\"to\" value=\"{}\" autocomplete=\"off\"></label><label>Subject<input type=\"text\" name=\"subject\" value=\"{}\"></label><label>Body<textarea name=\"body\">{}</textarea></label><label>Attachments<input type=\"file\" name=\"attachment\" multiple></label><button type=\"submit\">Send Message</button></form>",
        escape_html(model.csrf_token),
        escape_html(model.heading),
        escape_html(model.canonical_username),
        success_banner,
        error_banner,
        context_banner,
        escape_html(model.csrf_token),
        escape_html(model.to_value),
        escape_html(model.subject_value),
        escape_html(model.body_value),
    )
}

/// Renders the first bounded end-user settings page.
pub(crate) fn render_settings_page(model: &SettingsPageModel<'_>) -> String {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<p><strong>Update complete:</strong> {}</p>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<p><strong>Request failed:</strong> {}</p>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let prefer_sanitized_html_checked =
        if model.html_display_preference == HtmlDisplayPreference::PreferSanitizedHtml {
            " checked"
        } else {
            ""
        };
    let prefer_plain_text_checked =
        if model.html_display_preference == HtmlDisplayPreference::PreferPlainText {
            " checked"
        } else {
            ""
        };

    format!(
        "<nav><a href=\"/mailboxes\">Mailboxes</a> | <a href=\"/compose\">Compose</a> | <a href=\"/sessions\">Sessions</a> | <form method=\"post\" action=\"/logout\" style=\"display:inline\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form></nav><h1>Settings</h1><p>Signed in as <strong>{}</strong>.</p>{}{}<p class=\"muted\">This first settings slice is intentionally small. It controls whether HTML-capable messages prefer sanitized HTML or plain-text fallback during browser rendering.</p><form method=\"post\" action=\"/settings\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><fieldset><legend>HTML Message Display</legend><label><input type=\"radio\" name=\"html_display_preference\" value=\"prefer_sanitized_html\"{}> Prefer sanitized HTML when available</label><label><input type=\"radio\" name=\"html_display_preference\" value=\"prefer_plain_text\"{}> Prefer plain text when available</label></fieldset><button type=\"submit\">Save Settings</button></form>",
        escape_html(model.csrf_token),
        escape_html(model.canonical_username),
        success_banner,
        error_banner,
        escape_html(model.csrf_token),
        prefer_sanitized_html_checked,
        prefer_plain_text_checked,
    )
}
