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
    pub archive_mailbox_name: Option<&'a str>,
}

fn logout_form(csrf_token: &str) -> String {
    format!(
        "<form class=\"logout-form\" method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Log Out</button></form>",
        escape_html(csrf_token)
    )
}

fn app_header(canonical_username: &str, csrf_token: &str, current: &str) -> String {
    format!(
        concat!(
            "<header class=\"topbar\">",
            "<div class=\"brand\"><span class=\"brand-mark\" aria-hidden=\"true\">OS</span><span>OSMAP</span></div>",
            "<nav class=\"top-actions\" aria-label=\"Primary\">",
            "<a href=\"/mailboxes\"{}>Mailboxes</a>",
            "<a href=\"/compose\"{}>Compose</a>",
            "<a href=\"/sessions\"{}>Sessions</a>",
            "<a href=\"/settings\"{}>Settings</a>",
            "{}",
            "</nav>",
            "<div class=\"status-row\" aria-label=\"Security status\">",
            "<span class=\"status-pill badge-ok\">2FA session</span>",
            "<span class=\"status-pill\">signed in as <strong>{}</strong></span>",
            "</div>",
            "</header>"
        ),
        if current == "mailboxes" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "compose" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "sessions" {
            " aria-current=\"page\""
        } else {
            ""
        },
        if current == "settings" {
            " aria-current=\"page\""
        } else {
            ""
        },
        logout_form(csrf_token),
        escape_html(canonical_username),
    )
}

fn folder_pane(mailboxes: &[MailboxEntry], current_mailbox_name: Option<&str>) -> String {
    let mut items = String::new();
    for mailbox in mailboxes {
        let mailbox_href = format!("/mailbox?name={}", url_encode(&mailbox.name));
        let current = if current_mailbox_name == Some(mailbox.name.as_str()) {
            " aria-current=\"page\""
        } else {
            ""
        };
        items.push_str(&format!(
            "<li><a href=\"{}\"{}>{}</a></li>",
            escape_html(&mailbox_href),
            current,
            escape_html(&mailbox.name),
        ));
    }

    format!(
        "<aside class=\"folder-pane\" aria-label=\"Mail folders\"><h2>Folders</h2><ul class=\"folder-list\">{}</ul></aside>",
        items,
    )
}

/// Renders the current login page with an optional operator-safe error banner.
pub(crate) fn render_login_page(error_message: Option<&str>) -> String {
    let banner = match error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Sign-in failed.</strong> {}</div>",
            escape_html(error_message)
        ),
        None => String::new(),
    };

    format!(
        concat!(
            "<main class=\"login-page\" aria-labelledby=\"login-title\">",
            "<section class=\"login-card\">",
            "<div class=\"login-brand\"><span class=\"brand-mark\" aria-hidden=\"true\">OS</span><div><h1 id=\"login-title\" class=\"login-title\">OSMAP Login</h1><p class=\"login-subtitle\">Secure Webmail</p></div></div>",
            "<p class=\"login-helper\">Access requires your mailbox password and a current TOTP code. Authentication failures use one generic response.</p>",
            "{}",
            "<form method=\"post\" action=\"/login\" aria-describedby=\"login-help\">",
            "<label for=\"login-username\">Username or Email</label>",
            "<input id=\"login-username\" type=\"text\" name=\"username\" autocomplete=\"username\">",
            "<label for=\"login-password\">Password</label>",
            "<input id=\"login-password\" type=\"password\" name=\"password\" autocomplete=\"current-password\">",
            "<label for=\"login-totp\">TOTP Code</label>",
            "<input id=\"login-totp\" type=\"text\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\">",
            "<p id=\"login-help\" class=\"muted\">Enter the code from your authenticator app for this sign-in attempt.</p>",
            "<button class=\"primary-button\" type=\"submit\">Sign In</button>",
            "</form>",
            "<div class=\"security-grid\" aria-label=\"Security indicators\">",
            "<div class=\"security-item\"><strong>TLS protected</strong><span>Expected on the reviewed HTTPS edge</span></div>",
            "<div class=\"security-item\"><strong>2FA required</strong><span>Password plus TOTP</span></div>",
            "<div class=\"security-item\"><strong>Session secured</strong><span>HttpOnly and SameSite cookies</span></div>",
            "</div>",
            "</section>",
            "</main>"
        ),
        banner,
    )
}

/// Renders the mailbox home page for the validated user.
pub(crate) fn render_mailboxes_page(
    canonical_username: &str,
    csrf_token: &str,
    mailboxes: &[MailboxEntry],
) -> String {
    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<div class=\"mail-shell\">",
            "{}",
            "<section class=\"content-pane\" aria-labelledby=\"mailboxes-title\">",
            "<div class=\"section-header\"><div><h1 id=\"mailboxes-title\" class=\"section-title\">Mailboxes</h1><p class=\"muted\">Choose a visible mailbox, compose a message, or run a bounded backend search.</p></div>",
            "<div class=\"badge-list\"><span class=\"badge badge-ok\">2FA active</span><span class=\"badge\">mail access bounded by helper policy</span></div></div>",
            "<form class=\"search-row\" method=\"get\" action=\"/search\">",
            "<label for=\"mailbox-global-search\">Search all mailboxes<input id=\"mailbox-global-search\" type=\"text\" name=\"q\" autocomplete=\"off\"></label>",
            "<button type=\"submit\">Search</button>",
            "</form>",
            "<div class=\"notice\"><strong>Security posture:</strong> Remote content is not loaded by the browser, message rendering remains server-side, and state-changing actions stay CSRF-bound.</div>",
            "</section>",
            "</div>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        folder_pane(mailboxes, None),
    )
}

/// Renders the message-list page for one mailbox.
pub(crate) fn render_message_list_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: &str,
    messages: &[MessageSummary],
    success_message: Option<&str>,
    archive_mailbox_name: Option<&str>,
) -> String {
    let success_banner = match success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Update complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let mut rows = String::new();
    let archive_actions_available = archive_mailbox_name
        .is_some_and(|archive_mailbox_name| archive_mailbox_name != mailbox_name);
    for message in messages {
        let message_href = format!(
            "/message?mailbox={}&uid={}",
            url_encode(mailbox_name),
            message.uid
        );
        let archive_action = if let Some(archive_mailbox_name) = archive_mailbox_name {
            if archive_mailbox_name != mailbox_name {
                format!(
                    "<form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"{}\"><button type=\"submit\">Archive</button></form>",
                    escape_html(csrf_token),
                    escape_html(mailbox_name),
                    message.uid,
                    escape_html(archive_mailbox_name),
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        rows.push_str(&format!(
            "<tr>{}<td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>{}</tr>",
            if archive_actions_available {
                format!(
                    "<td><input form=\"bulk-archive-form\" type=\"checkbox\" name=\"uid_{}\" value=\"{}\"></td>",
                    message.uid, message.uid
                )
            } else {
                String::new()
            },
            escape_html(&message_href),
            message.uid,
            escape_html(message.subject.as_deref().unwrap_or("<none>")),
            escape_html(message.from.as_deref().unwrap_or("<none>")),
            escape_html(&message.date_received),
            escape_html(&message.flags.join(" ")),
            message.size_virtual,
            if archive_actions_available {
                format!("<td>{archive_action}</td>")
            } else {
                String::new()
            },
        ));
    }
    let bulk_archive_form = match archive_mailbox_name {
        Some(archive_mailbox_name) if archive_mailbox_name != mailbox_name && !messages.is_empty() => format!(
            "<form id=\"bulk-archive-form\" method=\"post\" action=\"/messages/archive\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"{}\"><button type=\"submit\">Archive Selected</button></form>",
            escape_html(csrf_token),
            escape_html(mailbox_name),
            escape_html(archive_mailbox_name),
        ),
        _ => String::new(),
    };
    let archive_notice = match archive_mailbox_name {
        Some(archive_mailbox_name) if archive_mailbox_name != mailbox_name => format!(
            "<p class=\"muted\">Archive shortcut sends messages from this mailbox to <strong>{}</strong>.</p>",
            escape_html(archive_mailbox_name)
        ),
        Some(_) => "<p class=\"muted\">This mailbox matches your configured archive destination, so archive shortcuts are hidden here.</p>".to_string(),
        None => "<p class=\"muted\">Set an archive mailbox in Settings to add one-click archive actions on list and message pages.</p>".to_string(),
    };

    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<section class=\"content-pane\" aria-labelledby=\"mailbox-title\">",
            "<div class=\"section-header\"><div><h1 id=\"mailbox-title\" class=\"section-title\">Mailbox: {}</h1><p class=\"muted\">Signed in as <strong>{}</strong>. Message data remains fetched through the reviewed mailbox route.</p></div>",
            "<div class=\"badge-list\"><span class=\"badge badge-ok\">2FA active</span><span class=\"badge\">Remote content blocked</span></div></div>",
            "{}{}",
            "<form class=\"search-row\" method=\"get\" action=\"/search\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><label for=\"mailbox-search\">Search query<input id=\"mailbox-search\" type=\"text\" name=\"q\" autocomplete=\"off\"></label><button type=\"submit\">Search</button><label><input type=\"checkbox\" name=\"scope\" value=\"all\"> Search all mailboxes</label></form>",
            "<div class=\"toolbar\" aria-label=\"Mailbox actions\">{}</div>",
            "<div class=\"table-wrap\"><table class=\"message-list-table\"><thead><tr>{}<th>UID</th><th>Subject</th><th>From</th><th>Received</th><th>Flags</th><th>Size</th>{}</tr></thead><tbody>{}</tbody></table></div>",
            "</section>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        escape_html(mailbox_name),
        escape_html(canonical_username),
        success_banner,
        archive_notice,
        escape_html(mailbox_name),
        bulk_archive_form,
        if archive_actions_available {
            "<th>Select</th>"
        } else {
            ""
        },
        if archive_actions_available {
            "<th>Action</th>"
        } else {
            ""
        },
        rows,
    )
}

/// Renders a bounded search-results page for one mailbox or all mailboxes.
pub(crate) fn render_message_search_page(
    canonical_username: &str,
    csrf_token: &str,
    mailbox_name: Option<&str>,
    query: &str,
    results: &[MessageSearchResult],
) -> String {
    let back_link = match mailbox_name {
        Some(mailbox_name) => format!(
            "<a href=\"/mailbox?name={}\">Back to mailbox</a> | ",
            escape_html(&url_encode(mailbox_name))
        ),
        None => String::new(),
    };
    let search_scope = mailbox_name.unwrap_or("All mailboxes");
    let mailbox_hidden_input = mailbox_name.map_or_else(String::new, |mailbox_name| {
        format!(
            "<input type=\"hidden\" name=\"mailbox\" value=\"{}\">",
            escape_html(mailbox_name)
        )
    });
    let search_all_checked = if mailbox_name.is_none() {
        " checked"
    } else {
        ""
    };
    let mut rows = String::new();
    if results.is_empty() {
        rows.push_str("<tr><td colspan=\"7\">No messages matched this search.</td></tr>");
    } else {
        for result in results {
            let message_href = format!(
                "/message?mailbox={}&uid={}",
                url_encode(&result.mailbox_name),
                result.uid
            );
            rows.push_str(&format!(
                "<tr><td><a href=\"{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&message_href),
                result.uid,
                escape_html(&result.mailbox_name),
                escape_html(result.subject.as_deref().unwrap_or("<none>")),
                escape_html(result.from.as_deref().unwrap_or("<none>")),
                escape_html(&result.date_received),
                escape_html(&result.flags.join(" ")),
                result.size_virtual,
            ));
        }
    }

    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<section class=\"content-pane\">",
            "<p>{}<a href=\"/mailboxes\">All mailboxes</a></p>",
            "<h1>Search Results</h1>",
            "<p class=\"muted\">This bounded retrieval slice keeps Dovecot authoritative for the query while letting the browser search one mailbox or all visible mailboxes without turning OSMAP into a broad search product.</p>",
            "<form class=\"search-row\" method=\"get\" action=\"/search\">{}<label for=\"search-query\">Search query<input id=\"search-query\" type=\"text\" name=\"q\" value=\"{}\" autocomplete=\"off\"></label><button type=\"submit\">Search</button><label><input type=\"checkbox\" name=\"scope\" value=\"all\"{}> Search all mailboxes</label></form>",
            "<p><strong>Scope:</strong> {}<br><strong>Query:</strong> {}<br><strong>Results:</strong> {}</p>",
            "<div class=\"table-wrap\"><table><thead><tr><th>UID</th><th>Mailbox</th><th>Subject</th><th>From</th><th>Received</th><th>Flags</th><th>Size</th></tr></thead><tbody>{}</tbody></table></div>",
            "</section>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        back_link,
        mailbox_hidden_input,
        escape_html(query),
        search_all_checked,
        escape_html(search_scope),
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
    archive_mailbox_name: Option<&str>,
    user_visible_mailboxes: &[MailboxEntry],
) -> String {
    let inline_image_count = rendered
        .attachments
        .iter()
        .filter(|attachment| {
            attachment.disposition == crate::mime::AttachmentDisposition::Inline
                && attachment.content_type.starts_with("image/")
        })
        .count();
    let inline_cid_image_count = rendered
        .attachments
        .iter()
        .filter(|attachment| {
            attachment.disposition == crate::mime::AttachmentDisposition::Inline
                && attachment.content_type.starts_with("image/")
                && attachment.content_id.is_some()
        })
        .count();
    let mut attachments = String::new();
    if rendered.attachments.is_empty() {
        attachments.push_str(
            "<li class=\"attachment-item\">No attachment metadata surfaced for this message.</li>",
        );
    } else {
        for attachment in &rendered.attachments {
            let download_href = format!(
                "/attachment?mailbox={}&uid={}&part={}",
                url_encode(&rendered.mailbox_name),
                rendered.uid,
                url_encode(&attachment.part_path),
            );
            let content_id_metadata = attachment
                .content_id
                .as_deref()
                .map(|content_id| {
                    format!(
                        ", Content-ID <strong>cid:{}</strong>",
                        escape_html(content_id)
                    )
                })
                .unwrap_or_default();
            attachments.push_str(&format!(
                "<li class=\"attachment-item\"><strong>{}</strong><br>Part {}. {}, {}, {} bytes{}<br><a class=\"button-link\" href=\"{}\">Download</a></li>",
                escape_html(attachment.filename.as_deref().unwrap_or("<unnamed>")),
                escape_html(&attachment.part_path),
                escape_html(&attachment.content_type),
                escape_html(attachment.disposition.as_str()),
                attachment.size_hint_bytes,
                content_id_metadata,
                escape_html(&download_href),
            ));
        }
    }

    let archive_form = match archive_mailbox_name {
        Some(archive_mailbox_name) if archive_mailbox_name != rendered.mailbox_name => format!(
            "<section class=\"panel\"><h2>Archive Message</h2><p class=\"muted\">This shortcut reuses the bounded move path with your configured archive mailbox.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"{}\"><button type=\"submit\">Archive Message</button></form></section>",
            escape_html(csrf_token),
            escape_html(&rendered.mailbox_name),
            rendered.uid,
            escape_html(archive_mailbox_name),
        ),
        Some(_) => "<section class=\"panel\"><p class=\"muted\">This message is already in your configured archive mailbox.</p></section>".to_string(),
        None => "<section class=\"panel\"><p class=\"muted\">Set an archive mailbox in Settings to add a one-click archive shortcut here.</p></section>".to_string(),
    };
    let trash_mailbox_available = user_visible_mailboxes
        .iter()
        .any(|mailbox| mailbox.name == "Trash" && mailbox.name != rendered.mailbox_name);
    let delete_form = if trash_mailbox_available {
        format!(
            "<section class=\"panel\"><h2>Delete Message</h2><p class=\"muted\">This delete control stays inside the current bounded mailbox-move slice by moving the message into <strong>Trash</strong>.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"destination_mailbox\" value=\"Trash\"><button type=\"submit\">Delete to Trash</button></form></section>",
            escape_html(csrf_token),
            escape_html(&rendered.mailbox_name),
            rendered.uid,
        )
    } else {
        String::new()
    };
    let move_destination_options = user_visible_mailboxes
        .iter()
        .filter(|mailbox| mailbox.name != rendered.mailbox_name)
        .map(|mailbox| {
            format!(
                "<option value=\"{}\">{}</option>",
                escape_html(&mailbox.name),
                escape_html(&mailbox.name)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let move_form = if move_destination_options.is_empty() {
        "<section class=\"panel\"><h2>Move Message</h2><p class=\"muted\">No alternate visible mailbox destinations are currently available for this bounded move action.</p></section>".to_string()
    } else {
        format!(
            "<section class=\"panel\"><h2>Move Message</h2><p class=\"muted\">This first folder-organization slice still keeps the general move path narrow: one message into one existing visible mailbox per request.</p><form method=\"post\" action=\"/message/move\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><label>Destination Mailbox<select name=\"destination_mailbox\">{}</select></label><button type=\"submit\">Move Message</button></form></section>",
            escape_html(csrf_token),
            escape_html(&rendered.mailbox_name),
            rendered.uid,
            move_destination_options,
        )
    };
    let rendering_notice = match rendered.rendering_mode.as_str() {
        "sanitized_html" => "<div class=\"notice\"><strong>Sanitized HTML:</strong> HTML content is shown through the current allowlist sanitization policy. Active content, external fetches, and unsafe URLs are removed.</div>",
        _ => "",
    };
    let inline_image_notice = if rendered.contains_html_body && inline_image_count > 0 {
        if inline_cid_image_count > 0 {
            format!(
                "<div class=\"notice\"><strong>Remote content blocked by policy:</strong> This message surfaced <strong>{}</strong> inline image part{}, including <strong>{}</strong> with Content-ID metadata used by `cid:` HTML references. Current browser policy does not render inline images inside the message body. Review the rendered body and download any needed image parts explicitly from the attachment list.</div>",
                inline_image_count,
                if inline_image_count == 1 { "" } else { "s" },
                inline_cid_image_count,
            )
        } else {
            format!(
                "<div class=\"notice\"><strong>Remote content blocked by policy:</strong> This message surfaced <strong>{}</strong> inline image part{}. Current browser policy does not render inline images inside the message body. Review the rendered body and download any needed image parts explicitly from the attachment list.</div>",
                inline_image_count,
                if inline_image_count == 1 { "" } else { "s" },
            )
        }
    } else {
        String::new()
    };
    let html_state_badge = if rendered.contains_html_body {
        "<span class=\"badge badge-warn\">HTML present</span>"
    } else {
        "<span class=\"badge badge-ok\">Plain text message</span>"
    };

    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<div class=\"mail-shell mail-shell-three\">",
            "{}",
            "<section class=\"message-summary-pane\" aria-labelledby=\"message-title\">",
            "<p><a href=\"/mailbox?name={}\">Back to mailbox</a></p>",
            "<h1 id=\"message-title\" class=\"section-title\">{}</h1>",
            "<p class=\"muted\">from {}</p>",
            "<div class=\"badge-list\"><span class=\"badge badge-ok\">2FA session</span>{}<span class=\"badge\">{}</span></div>",
            "<dl class=\"message-meta\"><dt>Mailbox</dt><dd>{}</dd><dt>UID</dt><dd>{}</dd><dt>Received</dt><dd>{}</dd><dt>MIME Type</dt><dd>{}</dd><dt>Body Source</dt><dd>{}</dd><dt>Rendering Mode</dt><dd>{}</dd><dt>HTML Present</dt><dd>{}</dd></dl>",
            "<div class=\"toolbar\" aria-label=\"Message actions\"><a class=\"button-link\" href=\"/compose?mode=reply&mailbox={}&uid={}\">Reply</a><a class=\"button-link\" href=\"/compose?mode=forward&mailbox={}&uid={}\">Forward</a></div>",
            "<div class=\"action-stack\">{}{}{}</div>",
            "</section>",
            "<article class=\"reading-pane\" aria-labelledby=\"reading-title\">",
            "<h2 id=\"reading-title\">Reading Pane</h2>",
            "{}{}",
            "<section class=\"panel\"><h2>Attachments</h2><ul class=\"attachment-list\">{}</ul></section>",
            "<section class=\"body-panel\"><h2>Body</h2>{}</section>",
            "</article>",
            "</div>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "mailboxes"),
        folder_pane(user_visible_mailboxes, Some(&rendered.mailbox_name)),
        escape_html(&url_encode(&rendered.mailbox_name)),
        escape_html(rendered.subject.as_deref().unwrap_or("<none>")),
        escape_html(rendered.from.as_deref().unwrap_or("<none>")),
        html_state_badge,
        if rendered.contains_html_body {
            "remote content blocked"
        } else {
            "safe text render"
        },
        escape_html(&rendered.mailbox_name),
        rendered.uid,
        escape_html(&rendered.date_received),
        escape_html(&rendered.mime_top_level_content_type),
        escape_html(rendered.body_source.as_str()),
        escape_html(rendered.rendering_mode.as_str()),
        if rendered.contains_html_body { "yes" } else { "no" },
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        escape_html(&url_encode(&rendered.mailbox_name)),
        rendered.uid,
        archive_form,
        delete_form,
        move_form,
        rendering_notice,
        inline_image_notice,
        attachments,
        rendered.body_html,
    )
}

/// Renders the browser-visible session-management page.
pub(crate) fn render_sessions_page(
    canonical_username: &str,
    current_session_id: &str,
    csrf_token: &str,
    session_lifetime_seconds: u64,
    session_idle_timeout_seconds: u64,
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

    let controls = format!(
        "<section class=\"panel\"><h2>Session Controls</h2><p><strong>Idle timeout:</strong> {} seconds. <strong>Absolute lifetime:</strong> {} seconds.</p><div class=\"toolbar\"><form method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"scope\" value=\"others\"><button type=\"submit\">Revoke Other Sessions</button></form><form method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"scope\" value=\"all\"><button type=\"submit\">Revoke All Sessions</button></form></div></section>",
        session_idle_timeout_seconds,
        session_lifetime_seconds,
        escape_html(csrf_token),
        escape_html(csrf_token),
    );

    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>Sessions</h1>",
            "<p class=\"muted\">This first self-service session view exposes the persisted session metadata already tracked by the runtime so users can see and revoke their own browser sessions without introducing a heavier device-management model.</p>",
            "{}{}",
            "<div class=\"table-wrap\"><table><thead><tr><th>Session ID</th><th>Status</th><th>Issued</th><th>Last Seen</th><th>Expires</th><th>Revoked</th><th>Remote Address</th><th>User Agent</th><th>Action</th></tr></thead><tbody>{}</tbody></table></div>",
            "</section>",
            "</main>"
        ),
        app_header(canonical_username, csrf_token, "sessions"),
        success_banner,
        controls,
        rows,
    )
}

/// Renders the compose page for the current user and CSRF-bound session.
pub(crate) fn render_compose_page(model: &ComposePageModel<'_>) -> String {
    let success_banner = match model.success_message {
        Some(success_message) => format!(
            "<div class=\"notice notice-success\" role=\"status\"><strong>Submission complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Request failed:</strong> {}</div>",
            escape_html(error_message)
        ),
        None => String::new(),
    };
    let context_banner = match model.context_notice {
        Some(context_notice) => format!(
            "<div class=\"notice\"><strong>Context:</strong> {}</div>",
            escape_html(context_notice)
        ),
        None => String::new(),
    };

    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>{}</h1>",
            "<p class=\"muted\">This send slice uses the local submission surface, keeps the browser body plain-text-first, accepts bounded new file uploads, and still does not reattach files from the source message automatically.</p>",
            "{}{}{}",
            "<form method=\"post\" action=\"/send\" enctype=\"multipart/form-data\">",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            "<label for=\"compose-to\">To<input id=\"compose-to\" type=\"text\" name=\"to\" value=\"{}\" autocomplete=\"off\"></label>",
            "<label for=\"compose-subject\">Subject<input id=\"compose-subject\" type=\"text\" name=\"subject\" value=\"{}\"></label>",
            "<label for=\"compose-body\">Body<textarea id=\"compose-body\" name=\"body\">{}</textarea></label>",
            "<label for=\"compose-attachment\">Attachments<input id=\"compose-attachment\" type=\"file\" name=\"attachment\" multiple></label>",
            "<button class=\"primary-button\" type=\"submit\">Send Message</button>",
            "</form>",
            "</section>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "compose"),
        escape_html(model.heading),
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
            "<div class=\"notice notice-success\" role=\"status\"><strong>Update complete:</strong> {}</div>",
            escape_html(success_message)
        ),
        None => String::new(),
    };
    let error_banner = match model.error_message {
        Some(error_message) => format!(
            "<div class=\"notice notice-error\" role=\"alert\"><strong>Request failed:</strong> {}</div>",
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
    let archive_mailbox_name = model.archive_mailbox_name.unwrap_or("");

    format!(
        concat!(
            "<main class=\"page-shell\">",
            "{}",
            "<section class=\"content-pane\">",
            "<h1>Settings</h1>{}{}",
            "<p class=\"muted\">This settings slice stays intentionally small. It controls HTML display preference and one optional archive mailbox shortcut without turning OSMAP into a broad preference UI.</p>",
            "<form method=\"post\" action=\"/settings\" class=\"action-stack\">",
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
            "<fieldset class=\"panel\">",
            "<legend>HTML Message Display</legend>",
            "<div><input id=\"html-display-prefer-sanitized\" type=\"radio\" name=\"html_display_preference\" value=\"prefer_sanitized_html\"{}><label for=\"html-display-prefer-sanitized\">Prefer sanitized HTML when available</label></div>",
            "<div><input id=\"html-display-prefer-plain\" type=\"radio\" name=\"html_display_preference\" value=\"prefer_plain_text\"{}><label for=\"html-display-prefer-plain\">Prefer plain text when available</label></div>",
            "</fieldset>",
            "<fieldset class=\"panel\">",
            "<legend>Archive Shortcut</legend>",
            "<label for=\"archive-mailbox-name\">Archive Mailbox</label>",
            "<input id=\"archive-mailbox-name\" type=\"text\" name=\"archive_mailbox_name\" value=\"{}\" autocomplete=\"off\">",
            "<p class=\"muted\">Leave this blank to keep only the manual move flow.</p>",
            "</fieldset>",
            "<div><button type=\"submit\">Save Settings</button></div>",
            "</form>",
            "</section>",
            "</main>"
        ),
        app_header(model.canonical_username, model.csrf_token, "settings"),
        success_banner,
        error_banner,
        escape_html(model.csrf_token),
        prefer_sanitized_html_checked,
        prefer_plain_text_checked,
        escape_html(archive_mailbox_name),
    )
}
