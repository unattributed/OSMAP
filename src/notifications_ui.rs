//! Account-owned native event inbox; the gateway supplies verified bounded data.
use super::*;
use crate::notifications::{NotificationInbox, NotificationKind};

pub(crate) fn render_notification_inbox(
    account: &str,
    csrf: &str,
    inbox: Option<&NotificationInbox>,
    preference: Option<&crate::notification_preferences::Preference>,
    error_message: Option<&str>,
) -> TrustedHtml {
    let daily = preference
        .is_some_and(|saved| saved.digest == crate::notification_preferences::DigestMode::Daily);
    let mode = preference.map_or("unavailable", |saved| saved.digest.value());
    let preference_notice = if preference.is_none() {
        "<p class=\"notice\" role=\"status\">Digest preference could not be loaded. Individual notices are shown without hiding or changing any event; the saved preference was not reset.</p>"
    } else {
        ""
    };
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
            let mut days = std::collections::BTreeMap::<u64, (usize, usize, String)>::new();
            for event in &inbox.events {
                let title = match &event.kind {
                    NotificationKind::SessionIssued => "Browser session started",
                    NotificationKind::SessionRevoked => "Browser session revoked",
                };
                let time = crate::logging::format_unix_timestamp_utc(event.occurred_at);
                let row = format!(concat!(
                    "<li class=\"notification-event\" data-read=\"{}\"><div><h2>{title}</h2><time datetime=\"{}\">{} UTC</time></div><span class=\"notification-read-state\">{}</span>",
                    "<form method=\"post\" action=\"/notifications/read\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"event_id\" value=\"{}\"><input type=\"hidden\" name=\"read\" value=\"{}\"><button class=\"secondary\" type=\"submit\">{}</button></form></li>"
                ), event.read, escape_html(&time), escape_html(time.replace('T', " ").trim_end_matches('Z')), if event.read { "Read" } else { "Unread" }, escape_html(csrf), inbox.revision, escape_html(&event.event_id), if event.read { "0" } else { "1" }, if event.read { "Mark unread" } else { "Mark read" }, title=title);
                if daily {
                    let group = days.entry(event.occurred_at / 86400).or_default();
                    group.0 += 1;
                    group.1 += usize::from(!event.read);
                    group.2.push_str(&row);
                } else {
                    rows.push_str(&row);
                }
            }
            for (day, (count, unread, group_rows)) in days.into_iter().rev() {
                let timestamp = crate::logging::format_unix_timestamp_utc(day * 86400);
                let date = timestamp.split('T').next().unwrap_or("Unknown date");
                rows.push_str(&format!("<li class=\"notification-day\" data-utc-day=\"{day}\"><section><h2>{} UTC · {count} notices · {unread} unread</h2><ul class=\"notification-events\" aria-label=\"{} UTC notices\">{group_rows}</ul></section></li>", escape_html(date), escape_html(date)));
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
        "{}<main id=\"main-content\" class=\"page-shell notifications-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Notifications</h1><p>Session events recorded for your account.</p></div>{notice}{preference_notice}",
        "<div class=\"notification-inbox-toolbar\"><p>{summary}</p><nav aria-label=\"Notification actions\"><a class=\"button-link secondary\" href=\"/notifications\">Refresh inbox</a><a class=\"button-link secondary\" href=\"/settings?section=notifications\">Notification settings</a></nav></div>",
        "<ul class=\"notification-events\" data-digest=\"{mode}\" aria-label=\"Session notifications\">{rows}</ul><p class=\"notification-inbox-scope muted\">Only recorded session starts and revocations appear here. Up to 200 notices are retained for 90 days; older events and other security history are unavailable. Read state is saved for this account. Digest changes only in-app presentation; all original security notices remain available. No scheduled or external digest is sent.</p><a href=\"/sessions\">Manage sessions</a></main>"
    ), app_header(account, csrf, "notifications"), notice=notice, preference_notice=preference_notice, mode=mode, summary=summary, rows=rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_daily_utc_boundaries_preserve_every_original_event_read_control_and_unknown_history(
    ) {
        use crate::notification_preferences::{DigestMode, Preference};
        let inbox = NotificationInbox {
            revision: 7,
            events: vec![
                crate::notifications::NotificationEvent {
                    event_id: "a".repeat(32),
                    kind: NotificationKind::SessionRevoked,
                    occurred_at: 86401,
                    read: false,
                },
                crate::notifications::NotificationEvent {
                    event_id: "b".repeat(32),
                    kind: NotificationKind::SessionIssued,
                    occurred_at: 86400,
                    read: true,
                },
                crate::notifications::NotificationEvent {
                    event_id: "c".repeat(32),
                    kind: NotificationKind::SessionIssued,
                    occurred_at: 86399,
                    read: false,
                },
            ],
        };
        let daily = render_notification_inbox(
            "alice@example.test",
            "csrf",
            Some(&inbox),
            Some(&Preference {
                revision: 1,
                digest: DigestMode::Daily,
            }),
            None,
        );
        let individual = render_notification_inbox(
            "alice@example.test",
            "csrf",
            Some(&inbox),
            Some(&Preference::default()),
            None,
        );
        let unknown =
            render_notification_inbox("alice@example.test", "csrf", Some(&inbox), None, None);
        assert_eq!(
            daily.as_str().matches("class=\"notification-day\"").count(),
            2
        );
        assert!(daily
            .as_str()
            .contains("1970-01-02 UTC · 2 notices · 1 unread"));
        assert!(daily
            .as_str()
            .contains("1970-01-01 UTC · 1 notices · 1 unread"));
        assert!(!individual.as_str().contains("class=\"notification-day\""));
        for html in [daily.as_str(), individual.as_str(), unknown.as_str()] {
            assert_eq!(html.matches("class=\"notification-event\"").count(), 3);
            assert_eq!(html.matches("action=\"/notifications/read\"").count(), 3);
            assert!(html.contains("3 retained notices · 2 unread"));
            for event in &inbox.events {
                assert!(html.contains(&format!("name=\"event_id\" value=\"{}\"", event.event_id)));
            }
        }
        assert!(unknown.as_str().contains("data-digest=\"unavailable\""));
        assert!(unknown
            .as_str()
            .contains("the saved preference was not reset"));
    }
    #[test]
    fn notification_inbox_distinguishes_empty_unavailable_and_escapes_errors() {
        let unavailable = render_notification_inbox(
            "alice@example.test",
            "csrf",
            None,
            None,
            Some("<unsafe&reason>"),
        );
        assert!(unavailable.as_str().contains("&lt;unsafe&amp;reason&gt;"));
        assert!(!unavailable
            .as_str()
            .contains("action=\"/notifications/read\""));
        let inbox = NotificationInbox {
            revision: 4,
            events: Vec::new(),
        };
        let empty = render_notification_inbox(
            "alice@example.test",
            "csrf",
            Some(&inbox),
            Some(&crate::notification_preferences::Preference::default()),
            None,
        );
        assert!(empty.as_str().contains("No retained session notices"));
        assert!(empty.as_str().contains("0 retained notices · 0 unread"));
    }
}
