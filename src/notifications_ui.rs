//! Account-owned native event inbox; the gateway supplies verified bounded data.
use super::*;
use crate::notifications::{NotificationInbox, NotificationKind};

pub(crate) fn render_notification_inbox(
    account: &str,
    csrf: &str,
    inbox: Option<&NotificationInbox>,
    error_message: Option<&str>,
) -> TrustedHtml {
    let notice = error_message
        .map(|message| {
            format!(
                "<p class=\"notice\" role=\"alert\">{}</p>",
                escape_html(message)
            )
        })
        .unwrap_or_default();
    let mut rows = String::new();
    let summary = match inbox {
        None => {
            rows.push_str("<li class=\"notification-empty\">Notifications could not be loaded. No read state can be changed until the saved inbox is available.</li>");
            "Inbox unavailable".into()
        }
        Some(inbox) => {
            for event in &inbox.events {
                let title = match &event.kind {
                    NotificationKind::SessionIssued => "Browser session started",
                    NotificationKind::SessionRevoked => "Browser session revoked",
                };
                let time = crate::logging::format_unix_timestamp_utc(event.occurred_at);
                rows.push_str(&format!(concat!(
                    "<li class=\"notification-event\" data-read=\"{}\"><div><h2>{title}</h2><time datetime=\"{}\">{} UTC</time></div><span class=\"notification-read-state\">{}</span>",
                    "<form method=\"post\" action=\"/notifications/read\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"event_id\" value=\"{}\"><input type=\"hidden\" name=\"read\" value=\"{}\"><button class=\"secondary\" type=\"submit\">{}</button></form></li>"
                ), event.read, escape_html(&time), escape_html(time.replace('T', " ").trim_end_matches('Z')), if event.read { "Read" } else { "Unread" }, escape_html(csrf), inbox.revision, escape_html(&event.event_id), if event.read { "0" } else { "1" }, if event.read { "Mark unread" } else { "Mark read" }, title=title));
            }
            if inbox.events.is_empty() {
                rows.push_str("<li class=\"notification-empty\">No retained session notices are available.</li>");
            }
            format!(
                "{} retained notices · {} unread",
                inbox.events.len(),
                inbox.events.iter().filter(|e| !e.read).count()
            )
        }
    };
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell notifications-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Notifications</h1><p>Session events recorded for your account.</p></div>{notice}",
        "<div class=\"notification-inbox-toolbar\"><p>{summary}</p><nav aria-label=\"Notification actions\"><a class=\"button-link secondary\" href=\"/notifications\">Refresh inbox</a><a class=\"button-link secondary\" href=\"/settings?section=notifications\">Notification settings</a></nav></div>",
        "<ul class=\"notification-events\" aria-label=\"Session notifications\">{rows}</ul><p class=\"notification-inbox-scope muted\">Only recorded session starts and revocations appear here. Up to 200 notices are retained for 90 days; older events and other security history are unavailable. Read state is saved for this account.</p><a href=\"/sessions\">Manage sessions</a></main>"
    ), app_header(account, csrf, "notifications"), notice=notice, summary=summary, rows=rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_inbox_distinguishes_empty_unavailable_and_escapes_errors() {
        let unavailable =
            render_notification_inbox("alice@example.test", "csrf", None, Some("<unsafe&reason>"));
        assert!(unavailable.as_str().contains("&lt;unsafe&amp;reason&gt;"));
        assert!(!unavailable
            .as_str()
            .contains("action=\"/notifications/read\""));
        let inbox = NotificationInbox {
            revision: 4,
            events: Vec::new(),
        };
        let empty = render_notification_inbox("alice@example.test", "csrf", Some(&inbox), None);
        assert!(empty.as_str().contains("No retained session notices"));
        assert!(empty.as_str().contains("0 retained notices · 0 unread"));
    }
}
