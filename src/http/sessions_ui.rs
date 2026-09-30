//! Approved Active Sessions presentation; session authority stays in the routes.
use super::*;

pub(crate) fn render_sessions_page(
    canonical_username: &str,
    current_session_id: &str,
    csrf_token: &str,
    session_lifetime_seconds: u64,
    session_idle_timeout_seconds: u64,
    sessions: &[BrowserVisibleSession],
    success_message: Option<&str>,
) -> TrustedHtml {
    let success = success_message
        .map(|message| format!("<div class=\"notice notice-success\" role=\"status\"><strong>Update complete:</strong> {}</div>", escape_html(message)))
        .unwrap_or_default();
    let mut rows = String::new();
    let mut inspections = String::new();
    let display_sessions = sessions
        .iter()
        .filter(|session| session.session_id == current_session_id)
        .chain(
            sessions
                .iter()
                .filter(|session| session.session_id != current_session_id),
        );
    for (index, session) in display_sessions.enumerate() {
        let current = session.session_id == current_session_id;
        let (state, state_class) = if session.revoked_at.is_some() {
            ("Revoked", "revoked")
        } else if current {
            ("Current", "current")
        } else {
            ("Active", "active")
        };
        let device = if session.device_label.trim().is_empty() {
            "Unknown device"
        } else {
            &session.device_label
        };
        let revoke = if session.revoked_at.is_none() {
            session_revoke_form(
                csrf_token,
                "session_id",
                &session.session_id,
                if current {
                    "Revoke This Session"
                } else {
                    "Revoke"
                },
            )
        } else {
            String::new()
        };
        let activity = crate::logging::format_unix_timestamp_utc(session.last_seen_at);
        let (date, clock) = activity.split_once('T').unwrap_or((&activity, ""));
        let action = if current || session.revoked_at.is_some() {
            ""
        } else {
            &revoke
        };
        rows.push_str(&format!(concat!(
            "<tr><td data-label=\"Device\"><strong>{}</strong>{}</td>",
            "<td data-label=\"Browser\">{}</td><td data-label=\"Location\">Unknown</td>",
            "<td data-label=\"Last active\"><time datetime=\"{}\"><span>{}</span><span class=\"session-clock\">{} UTC</span></time></td>",
            "<td data-label=\"Status\"><span class=\"session-status session-status-{}\">{}</span></td>",
            "<td data-label=\"Action\" class=\"session-action\">{}</td></tr>"
        ), escape_html(device), if current { "<span class=\"session-device-note\">Current device</span>" } else { "" },
            escape_html(&reported_browser(&session.user_agent)), escape_html(&activity), escape_html(date),
            escape_html(clock.trim_end_matches('Z')), state_class, state, action));
        inspections.push_str(&format!(concat!(
            "<section class=\"session-inspection\" aria-labelledby=\"session-inspection-{}\"><h3 id=\"session-inspection-{}\">{}</h3>",
            "<dl><dt>Session ID</dt><dd><code>{}</code></dd><dt>Remote address</dt><dd>{}</dd>",
            "<dt>User agent</dt><dd>{}</dd><dt>Issued</dt><dd>{}</dd><dt>Last seen</dt><dd>{}</dd>",
            "<dt>Expires</dt><dd>{}</dd><dt>Revoked</dt><dd>{}</dd></dl>{}</section>"
        ), index, index, escape_html(device), escape_html(&session.session_id),
            escape_html(&session.remote_addr), escape_html(&session.user_agent),
            detailed_timestamp(session.issued_at), detailed_timestamp(session.last_seen_at),
            detailed_timestamp(session.expires_at), session.revoked_at.map(detailed_timestamp).unwrap_or_else(|| "Not revoked".into()),
            if current { &revoke } else { "" }));
    }
    if sessions.is_empty() {
        rows.push_str("<tr><td colspan=\"6\" class=\"sessions-empty\">No browser sessions are available.</td></tr>");
    }
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell sessions-page\" tabindex=\"-1\">",
        "<div class=\"page-intro\"><h1>Active Sessions</h1><p>Review and revoke authenticated browser sessions.</p></div>{}",
        "<section class=\"content-pane sessions-card\" aria-labelledby=\"sessions-heading\"><div class=\"sessions-card-header\"><h2 id=\"sessions-heading\">Your Sessions</h2>{}</div>",
        "<table class=\"sessions-table\"><caption class=\"sr-only\">Browser sessions</caption><colgroup><col class=\"sessions-device-col\"><col class=\"sessions-browser-col\"><col class=\"sessions-location-col\"><col class=\"sessions-activity-col\"><col class=\"sessions-status-col\"><col class=\"sessions-action-col\"></colgroup><thead><tr><th scope=\"col\">Device</th><th scope=\"col\">Browser</th><th scope=\"col\">Location</th><th scope=\"col\">Last active</th><th scope=\"col\">Status</th><th scope=\"col\"><span class=\"sr-only\">Action</span></th></tr></thead><tbody>{}</tbody></table></section>",
        "<p class=\"sessions-scope-note\">Session revocation is server-authoritative. Revoking a browser session does not imply revocation of unrelated IMAP/SMTP credentials unless explicitly configured by account policy.</p>",
        "<details class=\"sessions-details\"><summary>Session details and timeout policy</summary><div class=\"sessions-details-body\"><p>Concurrent browser sessions are allowed. Device and browser names are derived from the reported user agent; location is unknown.</p>",
        "<p><strong>Idle timeout:</strong> {} seconds. <strong>Absolute lifetime:</strong> {} seconds.</p>{}",
        "<section class=\"sessions-revoke-all\"><h3>Sign out every browser session</h3><p>This includes your current session.</p>{}</section></div></details></main>"
    ), app_header(canonical_username, csrf_token, "sessions"), success,
        session_revoke_form(csrf_token, "scope", "others", "Sign out all other sessions"), rows,
        session_idle_timeout_seconds, session_lifetime_seconds, inspections,
        session_revoke_form(csrf_token, "scope", "all", "Revoke All Sessions")))
}

fn session_revoke_form(csrf: &str, field: &str, value: &str, label: &str) -> String {
    format!("<form class=\"session-revoke-form\" method=\"post\" action=\"/sessions/revoke\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"{}\" value=\"{}\"><button type=\"submit\">{}</button></form>", escape_html(csrf), field, escape_html(value), label)
}

fn detailed_timestamp(timestamp: u64) -> String {
    let date = crate::logging::format_unix_timestamp_utc(timestamp);
    format!(
        "<time datetime=\"{date}\">{}</time> <span class=\"muted\">(Unix: {timestamp})</span>",
        date.replace('T', " ").replace('Z', " UTC")
    )
}

fn reported_browser(agent: &str) -> String {
    // Match distinctive products before the compatibility tokens they include.
    for (token, name) in [
        ("EdgiOS/", "Edge"),
        ("EdgA/", "Edge"),
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("FxiOS/", "Firefox"),
        ("Firefox/", "Firefox"),
        ("CriOS/", "Chrome"),
        ("Chromium/", "Chromium"),
        ("Chrome/", "Chrome"),
    ] {
        if let Some(version) = agent
            .split_ascii_whitespace()
            .find_map(|part| part.strip_prefix(token))
        {
            let major = version.split('.').next().filter(|value| {
                !value.is_empty() && value.len() <= 4 && value.bytes().all(|ch| ch.is_ascii_digit())
            });
            return match major {
                Some(major) => format!("{name} {major}"),
                None => name.into(),
            };
        }
    }
    if agent
        .split_ascii_whitespace()
        .any(|part| part.starts_with("Safari/"))
        && agent
            .split_ascii_whitespace()
            .any(|part| part.starts_with("Version/"))
    {
        "Safari".into()
    } else {
        "Unknown".into()
    }
}
