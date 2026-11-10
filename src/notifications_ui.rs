//! Account-owned native event inbox; the gateway supplies verified bounded data.
use super::*;
use crate::notifications::NotificationInbox;

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
        "<p class=\"notice\" role=\"status\">Notification preferences could not be loaded. Individual notices are shown without hiding or changing any event; the saved preference was not reset.</p>"
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
    let mark_all = match inbox {
        Some(inbox) => format!(
            concat!("<div class=\"notification-bulk-actions\" role=\"group\" aria-label=\"All notifications\"><form method=\"post\" action=\"/notifications/read-all\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><button class=\"secondary\" type=\"submit\"{}><span class=\"presentation-icon presentation-icon-read\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Mark all as read</span></button></form>",
            "<form method=\"post\" action=\"/notifications/delete-all\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><button class=\"secondary\" type=\"submit\"{}><span class=\"presentation-icon presentation-icon-bin\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Delete all notifications</span></button></form></div>",
            "<p class=\"muted\">Both controls include optional notices hidden by your choices. Delete all clears this account’s notification inbox; separate audit records are kept.</p>"),
            escape_html(csrf), inbox.revision,
            if inbox.events.iter().any(|event|!event.read){""}else{" disabled"},
            escape_html(csrf), inbox.revision, if inbox.events.is_empty(){" disabled"}else{""}
        ),
        None=>"<div class=\"notification-bulk-actions\" role=\"group\" aria-label=\"All notifications\"><button class=\"secondary\" type=\"button\" disabled><span class=\"presentation-icon presentation-icon-read\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Mark all as read</span></button><button class=\"secondary\" type=\"button\" disabled><span class=\"presentation-icon presentation-icon-bin\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Delete all notifications</span></button></div>".into(),
    };
    let summary = match inbox {
        None => {
            rows.push_str("<li class=\"notification-empty\">Notifications could not be loaded. No read state can be changed until the saved inbox is available.</li>");
            "Inbox unavailable".into()
        }
        Some(inbox) => {
            let mut days = std::collections::BTreeMap::<u64, (usize, usize, String)>::new();
            let shown: Vec<_> = inbox
                .events
                .iter()
                .filter(|event| preference.is_none_or(|saved| saved.choices.allows(event.kind)))
                .collect();
            for event in &shown {
                let title = event.kind.title();
                let time = crate::logging::format_unix_timestamp_utc(event.occurred_at);
                let row = format!(concat!(
                    "<li class=\"notification-event\" data-read=\"{read}\"><div><h2>{title}</h2><time datetime=\"{iso}\">{time} UTC</time></div><span class=\"notification-read-state\">{read_state}</span><div class=\"notification-event-actions\">",
                    "<form method=\"post\" action=\"/notifications/read\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"revision\" value=\"{revision}\"><input type=\"hidden\" name=\"event_id\" value=\"{id}\"><input type=\"hidden\" name=\"read\" value=\"{next_read}\"><button class=\"secondary\" type=\"submit\">{read_action}</button></form>",
                    "<form method=\"post\" action=\"/notifications/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\"><input type=\"hidden\" name=\"revision\" value=\"{revision}\"><input type=\"hidden\" name=\"event_id\" value=\"{id}\"><button class=\"secondary\" type=\"submit\"><span class=\"presentation-icon presentation-icon-bin\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Delete notification</span></button></form></div></li>"
                ), read=event.read, iso=escape_html(&time), time=escape_html(time.replace('T', " ").trim_end_matches('Z')),read_state=if event.read { "Read" } else { "Unread" },csrf=escape_html(csrf),revision=inbox.revision,id=escape_html(&event.event_id),next_read=if event.read { "0" } else { "1" },read_action=crate::http_ui::presentation_label(if event.read { "Mark unread" } else { "Mark read" }, if event.read { "unread" } else { "read" }), title=title);
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
            if shown.is_empty() {
                rows.push_str("<li class=\"notification-empty\">No retained notices match your notification choices.</li>");
            }
            format!(
                "{} retained notices · {} unread{}",
                shown.len(),
                shown.iter().filter(|e| !e.read).count(),
                if shown.len() < inbox.events.len() {
                    format!(
                        " · {} optional notices hidden by your choices",
                        inbox.events.len() - shown.len()
                    )
                } else {
                    String::new()
                }
            )
        }
    };
    TrustedHtml::from_template(format!(concat!(
        "{}<main id=\"main-content\" class=\"page-shell notifications-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Notifications</h1><p>Recorded events for your account.</p></div>{notice}{preference_notice}",
        "<div class=\"notification-inbox-toolbar\"><p>{summary}</p><nav aria-label=\"Notification actions\"><a class=\"button-link secondary\" href=\"/notifications\">Refresh inbox</a><a class=\"button-link secondary\" href=\"/settings?section=notifications\">Notification settings</a></nav></div>",
        "{mark_all}<ul class=\"notification-events\" data-digest=\"{mode}\" aria-label=\"Account notifications\">{rows}</ul><p class=\"notification-inbox-scope muted\">Up to 200 recorded notices are retained for 90 days. This is not a complete audit history or a security score. Optional preferences cannot hide mandatory recovery and security notices. Deleting a notification dismisses it from this inbox; it does not undo the underlying action or alter separate audit records. Digest groups the in-app inbox only. Submission acceptance does not prove delivery. New mail is observed on Inbox refresh; mentions are checked when readable message text is opened.</p>{browser}<a href=\"/sessions\"><span class=\"presentation-icon presentation-icon-sessions\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Manage sessions</span></a></main>"
    ), app_header(account, csrf, "notifications"), notice=notice, preference_notice=preference_notice, mode=mode, summary=summary, rows=rows,mark_all=mark_all,browser=crate::http::notification_delivery::controls()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::NotificationKind;
    #[test]
    fn notification_bulk_controls_cover_hidden_read_notices_and_disable_empty_or_unavailable() {
        let mut inbox = NotificationInbox {
            revision: 4,
            events: vec![crate::notifications::NotificationEvent {
                event_id: "a".repeat(32),
                kind: NotificationKind::NewMail,
                occurred_at: 100,
                read: true,
            }],
        };
        let saved = crate::notification_preferences::Preference {
            choices: crate::notification_preferences::Choice {
                new_mail: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let html = render_notification_inbox(
            "alice@example.test",
            "<csrf&>",
            Some(&inbox),
            Some(&saved),
            None,
        );
        let controls = html
            .split("class=\"notification-bulk-actions\"")
            .nth(1)
            .unwrap()
            .split("</div>")
            .next()
            .unwrap();
        let read_form = controls
            .split_once("<form method=\"post\" action=\"/notifications/read-all\">")
            .expect("native bulk read form")
            .1
            .split("</form>")
            .next()
            .unwrap();
        assert!(read_form.contains("<button class=\"secondary\" type=\"submit\" disabled>"));
        assert!(read_form.contains("Mark all as read"));
        let delete_form = controls
            .split_once("<form method=\"post\" action=\"/notifications/delete-all\">")
            .expect("native bulk delete form")
            .1
            .split("</form>")
            .next()
            .unwrap();
        assert!(delete_form.contains("<button class=\"secondary\" type=\"submit\">"));
        assert!(!delete_form.contains(" disabled"));
        assert!(delete_form.contains("Delete all notifications"));
        assert_eq!(
            controls
                .matches("name=\"csrf_token\" value=\"&lt;csrf&amp;&gt;\"")
                .count(),
            2
        );
        assert_eq!(controls.matches("name=\"revision\" value=\"4\"").count(), 2);
        assert!(!controls.contains("event_id"));
        assert!(html.contains("0 retained notices · 0 unread · 1 optional notices hidden"));
        inbox.events.clear();
        for current in [Some(&inbox), None] {
            let html = render_notification_inbox(
                "alice@example.test",
                "csrf",
                current,
                Some(&saved),
                None,
            );
            for label in ["Mark all as read", "Delete all notifications"] {
                let button = html
                    .split("<button ")
                    .skip(1)
                    .map(|button| button.split("</button>").next().unwrap())
                    .find(|button| button.contains(label))
                    .expect("readable bulk action");
                assert!(button
                    .split_once('>')
                    .unwrap()
                    .0
                    .split_whitespace()
                    .any(|attribute| attribute == "disabled"));
            }
            if current.is_none() {
                assert!(!html.contains("action=\"/notifications/read-all\""));
                assert!(!html.contains("action=\"/notifications/delete-all\""));
            }
        }
    }
    #[test]
    fn optional_choices_hide_only_optional_events_without_removing_mandatory_read_controls() {
        use crate::notification_preferences::{Choice, Preference};
        let inbox = NotificationInbox {
            revision: 3,
            events: vec![
                crate::notifications::NotificationEvent {
                    event_id: "a".repeat(32),
                    kind: NotificationKind::NewMail,
                    occurred_at: 100,
                    read: false,
                },
                crate::notifications::NotificationEvent {
                    event_id: "b".repeat(32),
                    kind: NotificationKind::PersonalKeyLocked,
                    occurred_at: 99,
                    read: false,
                },
                crate::notifications::NotificationEvent {
                    event_id: "c".repeat(32),
                    kind: NotificationKind::RecoveryCompleted,
                    occurred_at: 98,
                    read: true,
                },
            ],
        };
        let saved = Preference {
            choices: Choice {
                new_mail: false,
                mentions: false,
                openpgp: false,
                submission: false,
                sound: false,
                desktop: false,
            },
            ..Preference::default()
        };
        let html = render_notification_inbox(
            "alice@example.test",
            "<csrf&>",
            Some(&inbox),
            Some(&saved),
            None,
        );
        assert!(html.contains("2 retained notices · 1 unread · 1 optional notices hidden"));
        assert!(!html.contains("New Inbox message observed"));
        assert!(html.contains(NotificationKind::PersonalKeyLocked.title()));
        assert!(html.contains(NotificationKind::RecoveryCompleted.title()));
        assert_eq!(html.matches("action=\"/notifications/read\"").count(), 2);
        assert!(html.contains("value=\"&lt;csrf&amp;&gt;\""));
        assert!(!html.contains(&format!("name=\"event_id\" value=\"{}\"", "a".repeat(32))));
        assert_eq!(inbox.events.len(), 3);
        let unavailable =
            render_notification_inbox("alice@example.test", "csrf", Some(&inbox), None, None);
        assert_eq!(
            unavailable
                .matches("action=\"/notifications/read\"")
                .count(),
            3
        );
    }
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
                ..Preference::default()
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
        assert!(empty.as_str().contains("No retained notices"));
        assert!(empty.as_str().contains("0 retained notices · 0 unread"));
    }
}
