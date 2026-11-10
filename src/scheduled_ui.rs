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
fn label(job: &JobView) -> &'static str {
    match job.state {
        State::Staged => "Save not yet confirmed",
        State::Pending => "Scheduled",
        State::Blocked => match job.reason {
            Some(BlockReason::KeyLocked) => "Not sent — personal key access was locked",
            Some(BlockReason::SessionExpired) => "Not sent — send authorization expired",
            Some(BlockReason::AccountChanged) => "Not sent — account protection changed",
            Some(BlockReason::ServiceUnavailable) => "Not sent — required service was unavailable",
            Some(BlockReason::PolicyChanged) => "Not sent — key or protection-policy check failed",
            Some(BlockReason::InvalidContent) => "Not sent — message failed send checks",
            Some(BlockReason::PayloadExpired) => "Not sent — saved message expired",
            None => "Not sent — reason unavailable",
        },
        State::ReturningToDraft => "Returning to Drafts — sending stopped",
        State::Claimed => "Submission in progress",
        State::Unknown => "Submission result unknown",
        State::Submitted => "Submitted",
        State::Cancelled => "Cancelled",
        State::Failed if job.reason == Some(BlockReason::PayloadExpired) => "Saved message expired",
        State::Failed => "Expired or refused",
    }
}
fn reason(reason: BlockReason) -> &'static str {
    match reason {
        BlockReason::KeyLocked => "Personal key access was locked when this scheduled send was checked. <a href=\"/settings/keys\"><span class=\"presentation-icon presentation-icon-key\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Open Your personal key in Settings</span></a> and unlock it, then choose Send now or authorize a new send time below. Unlocking alone does not restart this message.",
        BlockReason::SessionExpired => "The original send authorization expired. Sign in again, review this message, then choose Send now or authorize a new send time below.",
        BlockReason::AccountChanged => "Account protection changed after this message was authorized. Review your account security and this message before choosing Send now or authorizing a new send time.",
        BlockReason::ServiceUnavailable => "A required service was unavailable when this scheduled send was checked. Review this message and try Send now or a new send time once the service is available. If it fails again, contact the mail operator.",
        BlockReason::PolicyChanged => "The current key or protection-policy check did not pass. Review the recipients, keys and protection choices before choosing Send now or authorizing a new send time.",
        BlockReason::InvalidContent => "The saved message failed current send checks. Return it to Drafts to review and correct its recipients, text or attachments before sending again.",
        BlockReason::PayloadExpired => "The fixed 60-day saved-message lifetime expired; its message content is no longer retained.",
    }
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
    TrustedHtml::from_template(format!("{}<main id=main-content class=\"page-shell scheduled-page\" tabindex=-1><div class=page-intro><h1>{title}</h1><p>Manage scheduled messages and send attempts that need attention.</p></div>{body}<nav><a href=\"/outbox\"><span class=\"presentation-icon presentation-icon-outbox\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Outbox</span></a> · <a href=\"/drafts\"><span class=\"presentation-icon presentation-icon-drafts\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Drafts</span></a> · <a href=\"/compose\"><span class=\"presentation-icon presentation-icon-compose\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Compose</span></a></nav></main>",crate::http_ui::app_header(account,csrf,"outbox")))
}
fn field(name: &str, title: &str, value: &str) -> String {
    format!("<label for=scheduled-{name}>{title}</label><input id=scheduled-{name} name={name} value=\"{}\">",escape_html(value))
}
fn summary(to: &str, cc: &str, bcc: &str, subject: &str, body: &str, attachments: usize) -> String {
    format!("<dl><dt>To</dt><dd>{}</dd><dt>Cc</dt><dd>{}</dd><dt>Bcc</dt><dd>{}</dd><dt>Subject</dt><dd>{}</dd><dt>Saved attachments</dt><dd>{attachments}</dd></dl><details><summary><span class=\"presentation-icon presentation-icon-info\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Message text</span></summary><pre>{}</pre></details>",escape_html(to),escape_html(cc),escape_html(bcc),escape_html(subject),escape_html(body))
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
    let body=format!("<section class=panel><h2>Review saved message</h2>{}<p>This schedules the exact saved revision shown here. Return to the draft to change the message or its attachments.</p><form method=post action=\"/scheduled/create\">{}{}{}{}{}<button><span class=\"presentation-icon presentation-icon-clock\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Schedule this saved message</span></button></form><p><a href=\"/draft?id={}\"><span class=\"presentation-icon presentation-icon-drafts\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Back to draft</span></a></p></section>",summary(&d.recipients_text,&d.cc_text,&d.bcc_text,&d.subject,&d.body,d.attachments.len()),hidden("csrf_token",csrf),hidden("draft",&draft.draft_id),hidden("revision",&revision.to_string()),time_input(display,now.saturating_add(3600),"new"),limits(),escape_html(&draft.draft_id));
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
                body.push_str("<details><summary><span class=\"presentation-icon presentation-icon-clock\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Completed and cancelled messages</span></summary>");
            }
            body.push_str("<div class=table-wrap tabindex=0 role=region aria-label=\"Scheduled messages\"><table><thead><tr><th scope=col>Message</th><th scope=col>Send time</th><th scope=col>Status</th><th scope=col>Actions</th></tr></thead><tbody>");
            let mut rows = 0;
            for job in list.jobs.iter().filter(|j| {
                matches!(j.state, State::Submitted | State::Cancelled | State::Failed) == history
            }) {
                rows += 1;
                body.push_str(&format!("<tr><td>{}</td><td><time datetime=\"{}\">{}</time></td><td>{}</td><td><a href=\"/outbox?id={}\"><span class=\"presentation-icon presentation-icon-eye\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">View message and controls</span></a>",escape_html(if job.subject.is_empty(){"(No subject)"}else{&job.subject}),crate::logging::format_unix_timestamp_utc(job.due_at),escape_html(&shown_date(job.due_at,display)),label(job),escape_html(&job.id)));
                if editable(job.state) || job.state == State::Staged {
                    body.push_str(&format!("<form method=post action=\"/scheduled/change\">{}{}{}<button class=secondary name=action value=cancel><span class=\"presentation-icon presentation-icon-close\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Cancel</span></button></form>",hidden("csrf_token",csrf),hidden("id",&job.id),hidden("revision",&list.revision.to_string())));
                }
                body.push_str("</td></tr>");
            }
            if rows == 0 {
                body.push_str(if history {"<tr><td colspan=4>No retained history.</td></tr>"} else {"<tr><td colspan=4>No scheduled messages. Use Schedule in Compose to save a message and choose its send time.</td></tr>"});
            }
            body.push_str("</tbody></table></div>");
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
            body.push_str("<div class=table-wrap tabindex=0 role=region aria-label=\"Send attempts\"><table><thead><tr><th scope=col>Message</th><th scope=col>Attempted</th><th scope=col>Status</th><th scope=col>Actions</th></tr></thead><tbody>");
            for attempt in attempts {
                body.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td><a href=\"/compose?receipt={}\"><span class=\"presentation-icon presentation-icon-eye\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Review send result</span></a></td></tr>", escape_html(if attempt.subject.is_empty() {"(No subject)"} else {&attempt.subject}), escape_html(&shown_date(attempt.created_at, display)), escape_html(attempt.status), escape_html(&attempt.intent)));
            }
            body.push_str("</tbody></table></div>");
        }
        None => body.push_str("<p>Retained send attempts could not be loaded. Their current state has not been confirmed.</p>"),
    }
    body.push_str("<p>Review an uncertain result before creating another send. Submission acceptance is separate from recipient delivery; this page does not inspect the mail server's delivery queue.</p></section>");
    if let (Some(list), Some(job)) = (list, selected) {
        body.push_str(&format!("<section class=panel><h2>Saved message</h2><p>Status: <strong>{}</strong>. Send time: {}.</p>",label(job),escape_html(&shown_date(job.due_at,display))));
        if job.state == State::Blocked {
            body.push_str("<p class=notice>Nothing was submitted by this scheduled attempt. It will not retry automatically.</p>");
        }
        if job.state == State::Blocked
            || (job.state == State::Failed && job.reason == Some(BlockReason::PayloadExpired))
        {
            if let Some(r) = job.reason {
                body.push_str(&format!("<p class=notice>{}</p>", reason(r)));
            } else if job.state == State::Blocked {
                body.push_str("<p class=notice>The reason for this stopped attempt could not be loaded. Reload before choosing another action; contact the mail operator if it remains unavailable.</p>");
            }
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
                body.push_str(&format!("<details><summary><span class=\"presentation-icon presentation-icon-compose\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Edit message or send time</span></summary><form method=post action=\"/scheduled/edit\">{}{}{}{}{}{}{}<label for=scheduled-body>Message text (saved format: {})</label><textarea id=scheduled-body name=body rows=12 required>{}</textarea>{}<p>Saved attachments, sender, message format, reply headers and protection choices are preserved. Return to Drafts to change attachments or protection choices.</p><button><span class=\"presentation-icon presentation-icon-save\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Save scheduled message</span></button></form></details>",hidden("csrf_token",csrf),hidden("id",&job.id),hidden("revision",&list.revision.to_string()),field("to","To",&p.recipients.join(", ")),field("cc","Cc",&p.cc_recipients.join(", ")),field("bcc","Bcc",&p.bcc_recipients.join(", ")),field("subject","Subject",&p.subject),escape_html(p.body_format.as_str()),escape_html(&p.body),time_input(display,job.due_at,"edit")));
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
            body.push_str(&format!("<form method=post action=\"/scheduled/change\">{}{}{}{}<button name=action value=reauthorize><span class=\"presentation-icon presentation-icon-clock\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Authorize this message for the chosen time</span></button></form>",hidden("csrf_token",csrf),hidden("id",&job.id),hidden("revision",&list.revision.to_string()),time_input(display,now.saturating_add(3600),"reauthorize")));
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
                    "<a href=\"/compose?receipt={}\"><span class=\"presentation-icon presentation-icon-eye\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Review send result</span></a>",
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
    let icon = match action {
        "send_now" => "sent",
        "move_to_drafts" => "drafts",
        "delete" => "bin",
        _ => "",
    };
    let summary = crate::http_ui::presentation_label(title, icon);
    let confirm = crate::http_ui::presentation_label(&format!("Confirm: {title}"), icon);
    format!("<details><summary>{summary}</summary><p>{explanation}</p><form method=post action=\"/scheduled/change\">{}{}{}<button name=action value={action}>{confirm}</button></form></details>",hidden("csrf_token",csrf),hidden("id",id),hidden("revision",&revision.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outbox_reports_recorded_block_cause_in_list_and_detail() {
        for (cause, status, explanation) in [
            (
                BlockReason::KeyLocked,
                "personal key access was locked",
                "Unlocking alone does not restart this message.",
            ),
            (
                BlockReason::SessionExpired,
                "send authorization expired",
                "Sign in again",
            ),
            (
                BlockReason::AccountChanged,
                "account protection changed",
                "Review your account security",
            ),
            (
                BlockReason::ServiceUnavailable,
                "required service was unavailable",
                "contact the mail operator",
            ),
            (
                BlockReason::PolicyChanged,
                "key or protection-policy check failed",
                "Review the recipients",
            ),
            (
                BlockReason::InvalidContent,
                "message failed send checks",
                "Return it to Drafts",
            ),
            (
                BlockReason::PayloadExpired,
                "saved message expired",
                "60-day saved-message lifetime expired",
            ),
        ] {
            let mut job = job(State::Blocked);
            job.reason = Some(cause);
            let list = JobList {
                revision: 3,
                jobs: vec![job.clone()],
            };
            let html = render_outbox(
                "alice@example.test",
                "csrf",
                Some(&list),
                Some(&job),
                None,
                None,
                Display {
                    now: 100,
                    offset: None,
                },
                Some(&[]),
            )
            .to_string();
            assert_eq!(
                html.matches(&format!("Not sent — {status}")).count(),
                2,
                "{cause:?}"
            );
            assert!(html.contains(explanation), "{cause:?}");
            assert!(html.contains(
                "Nothing was submitted by this scheduled attempt. It will not retry automatically."
            ));
            assert!(!html.contains("Needs your attention"));
            if cause == BlockReason::KeyLocked {
                assert!(html.contains("href=\"/settings/keys\""));
                assert!(html.contains("when this scheduled send was checked"));
            }
        }
    }

    #[test]
    fn outbox_missing_reason_is_explicit_and_stale_reason_never_suggests_resend() {
        for state in [
            State::Blocked,
            State::Claimed,
            State::Unknown,
            State::Submitted,
            State::Cancelled,
            State::Failed,
        ] {
            let mut job = job(state);
            job.reason = if state == State::Blocked {
                None
            } else {
                Some(BlockReason::KeyLocked)
            };
            let list = JobList {
                revision: 3,
                jobs: vec![job.clone()],
            };
            let html = render_outbox(
                "alice@example.test",
                "csrf",
                Some(&list),
                Some(&job),
                None,
                None,
                Display {
                    now: 100,
                    offset: None,
                },
                Some(&[]),
            )
            .to_string();
            assert!(!html.contains("Unlocking alone"), "{state:?}");
            assert!(!html.contains("Open Your personal key"), "{state:?}");
            assert_eq!(
                html.contains("Nothing was submitted by this scheduled attempt"),
                state == State::Blocked
            );
            assert_eq!(
                html.contains("Not sent — reason unavailable"),
                state == State::Blocked
            );
            assert_eq!(
                html.contains("The reason for this stopped attempt could not be loaded"),
                state == State::Blocked
            );
            if matches!(state, State::Claimed | State::Unknown) {
                assert!(html.contains("cannot be edited, cancelled or restarted"));
                assert!(!html.contains("value=reauthorize"));
                assert!(!html.contains("value=send_now"));
            }
        }
    }

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
