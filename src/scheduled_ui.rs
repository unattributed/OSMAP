//! Native HTML for private scheduled messages; no browser timers or SMTP claims.
use crate::html::TrustedHtml;
use crate::http_support::escape_html;
use crate::scheduled_send::{BlockReason, JobList, JobView, State};
use crate::send::ComposeRequest;

#[derive(Clone, Copy)]
pub(crate) struct Display {
    pub now: u64,
    pub offset: Option<crate::timezone::FixedOffset>,
}
fn shown_date(time: u64, display: Display) -> String {
    let utc = date(time);
    match display.offset {
        Some(offset) => format!(
            "{} · {utc}",
            // Existing mail-date formatting expects the native metadata shape,
            // not the ISO timestamp used by logs and the HTML datetime value.
            offset.display_received(
                &crate::logging::format_unix_timestamp_utc(time)
                    .replace('T', " ")
                    .replace('Z', " +0000")
            )
        ),
        None => format!("{utc} · saved account offset unavailable"),
    }
}
fn date(t: u64) -> String {
    crate::logging::format_unix_timestamp_utc(t)
        .replace('T', " ")
        .replace('Z', " UTC")
}
fn hidden(name: &str, value: &str) -> String {
    format!(
        "<input type=hidden name={name} value=\"{}\">",
        escape_html(value)
    )
}
fn editable(state: State) -> bool {
    matches!(state, State::Pending | State::Blocked)
}
fn label(state: State) -> &'static str {
    match state {
        State::Staged => "Save not yet confirmed",
        State::Pending => "Scheduled",
        State::Blocked => "Needs your attention",
        State::ReturningToDraft => "Returning to Drafts — sending stopped",
        State::Claimed => "Submission in progress",
        State::Unknown => "Submission result unknown",
        State::Submitted => "Submitted",
        State::Cancelled => "Cancelled",
        State::Failed => "Expired or refused",
    }
}
fn reason(reason: BlockReason) -> &'static str {
    match reason{BlockReason::KeyLocked=>"Unlock your personal key, then explicitly authorize another future send time.",BlockReason::SessionExpired=>"The original authorization expired. Sign in and explicitly authorize another future send time.",BlockReason::AccountChanged=>"Account protection changed. Review this message before authorizing it again.",BlockReason::ServiceUnavailable=>"A required service was unavailable. Review the saved message before authorizing it again.",BlockReason::PolicyChanged=>"Keys or protection policy changed. Review them before authorizing this message again.",BlockReason::InvalidContent=>"The captured message could not pass current send checks.",BlockReason::PayloadExpired=>"The 60-day saved-message lifetime expired; its message content is no longer retained."}
}
fn limits() -> &'static str {
    "<p>Up to 20 active messages and 50 MiB per account. Choose a future time in your saved OSMAP timezone within 30 days. Keys, account authorization and policies are checked again when sending. A blocked message needs your explicit action; an unknown result is never automatically sent again.</p>"
}
fn time_input(display: Display, value: u64, context: &str) -> String {
    let Some(offset) = display.offset else {
        return "<p class=notice>Your saved OSMAP timezone could not be loaded. Reload before choosing a send time.</p>".into();
    };
    let now = display.now;
    let first = (now / 60 + 1) * 60;
    let (Some(min), Some(max), Some(value), Some(current)) = (
        offset.schedule_input(first),
        offset.schedule_input(now.saturating_add(30 * 86400)),
        offset.schedule_input(value.max(first)),
        offset.schedule_input(now),
    ) else {
        return "<p class=notice>The scheduling time could not be displayed. Reload before scheduling.</p>".into();
    };
    format!("<label for=scheduled-due-{context}>Send at ({})</label><input id=scheduled-due-{context} name=due_at type=datetime-local step=60 min=\"{min}\" max=\"{max}\" value=\"{value}\" required>{}<p>Current time in your saved OSMAP timezone: {} {}. Fixed offsets do not automatically adjust for daylight saving.</p>",offset.label(),hidden("timezone_offset",&offset.as_str()),current.replace('T'," "),offset.label())
}
fn shell(account: &str, csrf: &str, title: &str, body: String) -> TrustedHtml {
    TrustedHtml::from_template(format!("{}<main id=main-content class=\"page-shell scheduled-page\" tabindex=-1><div class=page-intro><h1>{title}</h1><p>Manage scheduled messages and send attempts that need attention.</p></div>{body}<nav><a href=\"/outbox\">Outbox</a> · <a href=\"/drafts\">Drafts</a> · <a href=\"/compose\">Compose</a></nav></main>",crate::http_ui::app_header(account,csrf,"outbox")))
}
fn field(name: &str, title: &str, value: &str) -> String {
    format!("<label for=scheduled-{name}>{title}</label><input id=scheduled-{name} name={name} value=\"{}\">",escape_html(value))
}
fn summary(to: &str, cc: &str, bcc: &str, subject: &str, body: &str, attachments: usize) -> String {
    format!("<dl><dt>To</dt><dd>{}</dd><dt>Cc</dt><dd>{}</dd><dt>Bcc</dt><dd>{}</dd><dt>Subject</dt><dd>{}</dd><dt>Saved attachments</dt><dd>{attachments}</dd></dl><details><summary>Message text</summary><pre>{}</pre></details>",escape_html(to),escape_html(cc),escape_html(bcc),escape_html(subject),escape_html(body))
}

pub(crate) fn render_new(
    account: &str,
    csrf: &str,
    draft: &crate::draft::DraftRecord,
    revision: u64,
    display: Display,
) -> TrustedHtml {
    let now = display.now;
    let d = &draft.request;
    let body=format!("<section class=panel><h2>Review saved message</h2>{}<p>This schedules the exact saved revision shown here. Return to the draft to change the message or its attachments.</p><form method=post action=\"/scheduled/create\">{}{}{}{}{}<button>Schedule this saved message</button></form><p><a href=\"/draft?id={}\">Back to draft</a></p></section>",summary(&d.recipients_text,&d.cc_text,&d.bcc_text,&d.subject,&d.body,d.attachments.len()),hidden("csrf_token",csrf),hidden("draft",&draft.draft_id),hidden("revision",&revision.to_string()),time_input(display,now.saturating_add(3600),"new"),limits(),escape_html(&draft.draft_id));
    shell(
        account,
        csrf,
        "Schedule message",
        format!(
            "<p>Current time: {}. Choose the send time in your saved OSMAP timezone.</p>{body}",
            escape_html(&shown_date(now, display))
        ),
    )
}
pub(crate) fn render_list(
    account: &str,
    csrf: &str,
    list: Option<&JobList>,
    selected: Option<&JobView>,
    payload: Option<&ComposeRequest>,
    error: Option<&str>,
    display: Display,
) -> TrustedHtml {
    render_outbox(account, csrf, list, selected, payload, error, display, None)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_outbox(
    account: &str,
    csrf: &str,
    list: Option<&JobList>,
    selected: Option<&JobView>,
    payload: Option<&ComposeRequest>,
    error: Option<&str>,
    display: Display,
    attempts: Option<&[crate::send_recovery::OutboxAttempt]>,
) -> TrustedHtml {
    let now = display.now;
    let mut body = String::new();
    if let Some(error) = error {
        body.push_str(&format!(
            "<p class=notice role=status>{}</p>",
            escape_html(error)
        ));
    }
    body.push_str("<section class=panel><h2>Your scheduled messages</h2>");
    if let Some(list) = list {
        let active = list
            .jobs
            .iter()
            .filter(|j| !matches!(j.state, State::Submitted | State::Cancelled | State::Failed))
            .count();
        body.push_str(&format!(
            "<p>{active} active messages. Status reflects this page load; refresh for changes.</p>"
        ));
        for history in [false, true] {
            if history {
                body.push_str("<details><summary>Completed and cancelled messages</summary>");
            }
            body.push_str("<table><thead><tr><th scope=col>Message</th><th scope=col>Send time</th><th scope=col>Status</th><th scope=col>Actions</th></tr></thead><tbody>");
            let mut rows = 0;
            for job in list.jobs.iter().filter(|j| {
                matches!(j.state, State::Submitted | State::Cancelled | State::Failed) == history
            }) {
                rows += 1;
                body.push_str(&format!("<tr><td>{}</td><td><time datetime=\"{}\">{}</time></td><td>{}</td><td><a href=\"/outbox?id={}\">View message and controls</a>",escape_html(if job.subject.is_empty(){"(No subject)"}else{&job.subject}),crate::logging::format_unix_timestamp_utc(job.due_at),escape_html(&shown_date(job.due_at,display)),label(job.state),escape_html(&job.id)));
                if editable(job.state) || job.state == State::Staged {
                    body.push_str(&format!("<form method=post action=\"/scheduled/change\">{}{}{}<button class=secondary name=action value=cancel>Cancel</button></form>",hidden("csrf_token",csrf),hidden("id",&job.id),hidden("revision",&list.revision.to_string())));
                }
                body.push_str("</td></tr>");
            }
            if rows == 0 {
                body.push_str(if history {"<tr><td colspan=4>No retained history.</td></tr>"} else {"<tr><td colspan=4>No scheduled messages. Use Schedule in Compose to save a message and choose its send time.</td></tr>"});
            }
            body.push_str("</tbody></table>");
            if history {
                body.push_str("</details>");
            }
        }
    } else {
        body.push_str("<p>Scheduled messages could not be loaded. Their current state has not been confirmed.</p>");
    }
    body.push_str(limits());
    body.push_str("</section>");
    body.push_str("<section class=panel><h2>Send attempts needing attention</h2>");
    match attempts {
        Some([]) => body.push_str("<p>No retained send attempts need attention.</p>"),
        Some(attempts) => {
            body.push_str("<table><thead><tr><th scope=col>Message</th><th scope=col>Attempted</th><th scope=col>Status</th><th scope=col>Actions</th></tr></thead><tbody>");
            for attempt in attempts {
                body.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><a href=\"/compose?receipt={}\">Review send result</a></td></tr>", escape_html(if attempt.subject.is_empty() {"(No subject)"} else {&attempt.subject}), escape_html(&shown_date(attempt.created_at, display)), escape_html(attempt.status), escape_html(&attempt.intent)));
            }
            body.push_str("</tbody></table>");
        }
        None => body.push_str("<p>Retained send attempts could not be loaded. Their current state has not been confirmed.</p>"),
    }
    body.push_str("<p>Review an uncertain result before creating another send. Submission acceptance is separate from recipient delivery; this page does not inspect the mail server's delivery queue.</p></section>");
    if let (Some(list), Some(job)) = (list, selected) {
        body.push_str(&format!("<section class=panel><h2>Saved message</h2><p>Status: <strong>{}</strong>. Send time: {}.</p>",label(job.state),escape_html(&shown_date(job.due_at,display))));
        if let Some(r) = job.reason {
            body.push_str(&format!("<p class=notice>{}</p>", reason(r)));
        }
        if let Some(p) = payload {
            body.push_str(&summary(
                &p.recipients.join(", "),
                &p.cc_recipients.join(", "),
                &p.bcc_recipients.join(", "),
                &p.subject,
                &p.body,
                p.attachments.len(),
            ));
            body.push_str(&format!("<p>Saved protection choices: signing {}; encryption {}; include your key for encrypted access {}. Current account and recipient policies are checked again before sending.</p>",if p.protection.sign{"requested"}else{"not requested"},if p.protection.encrypt{"requested"}else{"not requested"},if p.protection.encrypt_to_self{"yes"}else{"no"}));
            if editable(job.state) {
                body.push_str(&format!("<details><summary>Edit message or send time</summary><form method=post action=\"/scheduled/edit\">{}{}{}{}{}{}{}<label for=scheduled-body>Message text (saved format: {})</label><textarea id=scheduled-body name=body rows=12 required>{}</textarea>{}<p>Saved attachments, sender, message format, reply headers and protection choices are preserved. Return to Drafts to change attachments or protection choices.</p><button>Save scheduled message</button></form></details>",hidden("csrf_token",csrf),hidden("id",&job.id),hidden("revision",&list.revision.to_string()),field("to","To",&p.recipients.join(", ")),field("cc","Cc",&p.cc_recipients.join(", ")),field("bcc","Bcc",&p.bcc_recipients.join(", ")),field("subject","Subject",&p.subject),escape_html(p.body_format.as_str()),escape_html(&p.body),time_input(display,job.due_at,"edit")));
                for (action, title, explanation) in [
                    ("send_now", "Send now", "Submit this saved message as soon as the worker checks it. Current keys, authorization and protection policy must still pass."),
                    ("move_to_drafts", "Return to Drafts", "Stop this schedule and move its complete saved message into an editable draft. Nothing is sent."),
                    ("delete", "Delete unsent message", "Cancel this schedule and delete its saved message content. A status record is retained; this cannot recall a message already submitted."),
                ] { body.push_str(&confirm_action(csrf, list.revision, &job.id, action, title, explanation)); }
            }
        } else {
            body.push_str(if now>=job.payload_expires_at {"<p>Saved message content is unavailable because its fixed 60-day lifetime expired. The confirmed submission status above remains available.</p>"} else if matches!(job.state,State::Submitted|State::Cancelled|State::Failed) {"<p>Message content is no longer retained for this terminal entry.</p>"} else {"<p>Saved message content could not be loaded. Its confirmed status is shown above; reload before another action.</p>"});
        }
        if job.state == State::Blocked {
            body.push_str(&format!("<form method=post action=\"/scheduled/change\">{}{}{}{}<button name=action value=reauthorize>Authorize this message for the chosen time</button></form>",hidden("csrf_token",csrf),hidden("id",&job.id),hidden("revision",&list.revision.to_string()),time_input(display,now.saturating_add(3600),"reauthorize")));
        }
        if job.state == State::Staged {
            body.push_str("<p>This incomplete entry is not scheduled and will not dispatch. Cancel it from the list to release its saved-message space, then return to Compose.</p>");
        }
        if job.state == State::ReturningToDraft {
            body.push_str("<p>Sending is stopped. Complete the interrupted return to Drafts; the saved Outbox content is retained until the draft is confirmed.</p>");
            body.push_str(&format!("<p>If the draft was already saved, <a href=\"/draft?id={}\">open the returned draft</a>. A changed draft is kept and will not be overwritten.</p>", escape_html(&job.id)));
            body.push_str(&confirm_action(csrf, list.revision, &job.id, "move_to_drafts", "Resume return to Drafts", "Confirm the saved draft, then finish retiring this schedule. An existing changed draft is never overwritten."));
        }
        if matches!(job.state, State::Claimed | State::Unknown) {
            body.push_str("<p>This submission cannot be edited, cancelled or restarted. Its existing journal receipt must be reconciled; no automatic resend is performed.</p>");
            if let Some(intent) = &job.intent {
                body.push_str(&format!(
                    "<a href=\"/compose?receipt={}\">Review send result</a>",
                    escape_html(intent)
                ));
            }
        }
        if job.state == State::Submitted {
            body.push_str("<p>The mail submission was accepted. This does not confirm delivery to the recipient.</p>");
        }
        body.push_str("</section>");
    }
    shell(account, csrf, "Outbox", body)
}

fn confirm_action(
    csrf: &str,
    revision: u64,
    id: &str,
    action: &str,
    title: &str,
    explanation: &str,
) -> String {
    format!("<details><summary>{title}</summary><p>{explanation}</p><form method=post action=\"/scheduled/change\">{}{}{}<button name=action value={action}>Confirm: {title}</button></form></details>",hidden("csrf_token",csrf),hidden("id",id),hidden("revision",&revision.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outbox_controls_are_state_bound_and_navigation_is_discoverable() {
        let payload = crate::send::ComposeRequest::new(
            crate::send::ComposePolicy::default(),
            "bob@example.test",
            "subject",
            "body",
        )
        .unwrap();
        for state in [
            State::Pending,
            State::Blocked,
            State::ReturningToDraft,
            State::Claimed,
            State::Unknown,
            State::Submitted,
            State::Cancelled,
        ] {
            let job = job(state);
            let list = JobList {
                revision: 3,
                jobs: vec![job.clone()],
            };
            let html = render_outbox(
                "alice@example.test",
                "csrf",
                Some(&list),
                Some(&job),
                Some(&payload),
                None,
                Display {
                    now: 100,
                    offset: None,
                },
                Some(&[]),
            );
            for action in ["send_now", "delete"] {
                assert_eq!(
                    html.contains(&format!("value={action}>")),
                    matches!(state, State::Pending | State::Blocked)
                );
            }
            assert_eq!(
                html.contains("value=move_to_drafts>"),
                matches!(
                    state,
                    State::Pending | State::Blocked | State::ReturningToDraft
                )
            );
            let draft = html.find("href=\"/drafts\"").unwrap();
            let outbox = html.find("href=\"/outbox\"").unwrap();
            let sent = html.find("href=\"/mailbox/shortcut?kind=sent\"").unwrap();
            assert!(draft < outbox && outbox < sent);
        }
    }
    #[test]
    fn outbox_attempts_escape_subject_and_separate_uncertainty_from_delivery() {
        let attempt = crate::send_recovery::OutboxAttempt {
            intent: "a".repeat(64),
            subject: "<script>bad</script>".into(),
            created_at: 100,
            status: "Submission result unknown",
        };
        let html = render_outbox(
            "alice@example.test",
            "csrf",
            None,
            None,
            None,
            None,
            Display {
                now: 100,
                offset: None,
            },
            Some(&[attempt]),
        );
        assert!(html.contains("&lt;script&gt;bad&lt;/script&gt;") && !html.contains("<script>bad"));
        assert!(
            html.contains("Review send result")
                && html.contains("does not inspect the mail server")
        );
        assert!(!html.contains("Confirm: Send now"));
    }
    fn job(state: State) -> JobView {
        JobView {
            id: "0123456789abcdef0123456789abcdef".into(),
            subject: "<script>listed subject</script>".into(),
            digest: "a".repeat(64),
            state,
            due_at: 10000,
            created_at: 100,
            updated_at: 100,
            payload_expires_at: 60 * 86400 + 100,
            reason: None,
            intent: None,
        }
    }
    #[test]
    fn scheduling_form_uses_account_time_and_refuses_missing_timezone() {
        let display = Display {
            now: 1_793_892_900,
            offset: crate::timezone::FixedOffset::parse("+07:00"),
        };
        let html = time_input(display, display.now + 1200, "test");
        assert!(html.contains("Send at (UTC+07:00)"));
        assert!(html.contains("value=\"2026-11-05T22:55\""));
        assert!(html.contains("name=timezone_offset value=\"+07:00\""));
        let missing = time_input(
            Display {
                offset: None,
                ..display
            },
            display.now + 1200,
            "missing",
        );
        assert!(missing.contains("could not be loaded"));
        assert!(!missing.contains("name=due_at"));
        let date = shown_date(display.now + 1200, display);
        assert!(date.starts_with("2026-11-05 22:55:00 UTC+07:00"));
    }

    #[test]
    fn pending_ui_is_native_escaped_and_preserves_cas_and_private_routing() {
        let job = job(State::Pending);
        let list = JobList {
            revision: 7,
            jobs: vec![job.clone()],
        };
        let mut p = ComposeRequest::new(
            crate::send::ComposePolicy::default(),
            "bob@example.test",
            "<script>subject</script>",
            "</textarea><img src=x>",
        )
        .unwrap();
        p.bcc_recipients.push("private@example.test".into());
        let html = render_list(
            "alice@example.test",
            "token",
            Some(&list),
            Some(&job),
            Some(&p),
            None,
            Display {
                now: 100,
                offset: None,
            },
        )
        .to_string();
        assert!(
            html.contains("&lt;script&gt;subject&lt;/script&gt;")
                && html.contains("&lt;/textarea&gt;&lt;img src=x&gt;")
        );
        assert!(!html.contains("<script>subject") && !html.contains("<img src=x>"));
        assert!(html.contains("&lt;script&gt;listed subject&lt;/script&gt;"));
        assert!(!html.contains("<script>listed subject"));
        assert!(
            html.contains("private@example.test") && html.contains("name=revision value=\"7\"")
        );
        assert!(html.contains("/scheduled/edit") && html.contains("value=cancel"));
    }
    #[test]
    fn uncertain_and_terminal_ui_never_offer_automatic_rearm() {
        for state in [
            State::Unknown,
            State::Claimed,
            State::Submitted,
            State::Cancelled,
            State::Failed,
        ] {
            let job = job(state);
            let list = JobList {
                revision: 1,
                jobs: vec![job.clone()],
            };
            let html = render_list(
                "alice@example.test",
                "token",
                Some(&list),
                Some(&job),
                None,
                None,
                Display {
                    now: 100,
                    offset: None,
                },
            )
            .to_string();
            assert!(
                !html.contains("/scheduled/edit")
                    && !html.contains("value=cancel")
                    && !html.contains("value=reauthorize")
            );
        }
        let html = render_list(
            "alice@example.test",
            "token",
            None,
            None,
            None,
            Some("unavailable"),
            Display {
                now: 100,
                offset: None,
            },
        )
        .to_string();
        assert!(html.contains("could not be loaded") && !html.contains("No scheduled messages."));
    }
    #[test]
    fn incomplete_staged_entry_can_be_cancelled_without_edit_or_rearm() {
        let job = job(State::Staged);
        let list = JobList {
            revision: 9,
            jobs: vec![job.clone()],
        };
        let html = render_list(
            "alice@example.test",
            "token",
            Some(&list),
            Some(&job),
            None,
            None,
            Display {
                now: 100,
                offset: None,
            },
        )
        .to_string();
        assert!(html.contains("value=cancel") && html.contains("name=revision value=\"9\""));
        assert!(html.contains("not scheduled and will not dispatch"));
        assert!(!html.contains("/scheduled/edit") && !html.contains("value=reauthorize"));
    }
    #[test]
    fn overview_empty_subject_has_a_practical_label() {
        let mut job = job(State::Pending);
        job.subject.clear();
        let list = JobList {
            revision: 1,
            jobs: vec![job],
        };
        let html = render_list(
            "alice@example.test",
            "token",
            Some(&list),
            None,
            None,
            None,
            Display {
                now: 100,
                offset: None,
            },
        );
        assert!(html.contains("(No subject)"));
        assert!(!html.contains("Saved message 01234567"));
    }
    #[test]
    fn scheduled_dates_include_exact_utc_and_current_saved_fixed_offset() {
        let job = job(State::Pending);
        let list = JobList {
            revision: 1,
            jobs: vec![job],
        };
        let html = render_list(
            "alice@example.test",
            "token",
            Some(&list),
            None,
            None,
            None,
            Display {
                now: 100,
                offset: crate::timezone::FixedOffset::parse("+07:00"),
            },
        );
        assert!(html.contains("1970-01-01 02:46:40 UTC"));
        assert!(html.contains("1970-01-01 09:46:40 UTC+07:00"));
        assert!(html.contains("datetime=\"1970-01-01T02:46:40Z\""));
    }
    #[test]
    fn missing_unknown_payload_preserves_status_without_terminal_or_retry_claims() {
        let job = job(State::Unknown);
        let list = JobList {
            revision: 1,
            jobs: vec![job.clone()],
        };
        for now in [100, job.payload_expires_at] {
            let html = render_list(
                "alice@example.test",
                "token",
                Some(&list),
                Some(&job),
                None,
                None,
                Display { now, offset: None },
            );
            assert!(html.contains("Submission result unknown"));
            assert!(
                !html.contains("terminal entry")
                    && !html.contains("value=cancel")
                    && !html.contains("value=reauthorize")
            );
            assert!(html.contains(if now >= job.payload_expires_at {
                "fixed 60-day lifetime expired"
            } else {
                "could not be loaded"
            }));
        }
    }
}
