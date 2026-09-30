//! Native account-private hide-until controls; no mail movement.
use super::*;
use crate::snooze::{MessageIdentity, SnoozeRecord, MAX_DURATION, MAX_MARKERS};
pub(crate) struct SnoozePageModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub identity: &'a MessageIdentity,
    pub revision: u64,
    pub until_utc: &'a str,
    pub return_to: &'a str,
    pub error: Option<&'a str>,
    pub available: bool,
    pub now: u64,
    pub current_until: Option<u64>,
}
const SCOPE:&str="Snooze hides this exact message from its source mailbox list and Welcome. Search and direct Reader access remain available. It does not move, delete or change mail. Visibility is restored when you reload the list at or after expiry; this page does not update automatically.";
fn fields(csrf: &str, revision: u64, id: &MessageIdentity) -> String {
    format!("<input type=hidden name=csrf_token value=\"{}\"><input type=hidden name=revision value=\"{revision}\"><input type=hidden name=mailbox value=\"{}\"><input type=hidden name=uid value=\"{}\"><input type=hidden name=mailbox_guid value=\"{}\"><input type=hidden name=message_guid value=\"{}\">",escape_html(csrf),escape_html(id.folder()),id.uid(),escape_html(id.mailbox_guid()),escape_html(id.message_guid()))
}
fn date(t: u64) -> String {
    crate::logging::format_unix_timestamp_utc(t)
        .replace('T', " ")
        .replace('Z', " UTC")
}
fn input_date(t: u64) -> String {
    crate::logging::format_unix_timestamp_utc(t)
        .chars()
        .take(16)
        .collect()
}
pub(crate) fn render_snooze_page(m: &SnoozePageModel<'_>) -> TrustedHtml {
    let notice = m
        .error
        .map(|v| format!("<p class=notice role=status>{}</p>", escape_html(v)))
        .unwrap_or_default();
    let state = if !m.available {
        "<p>Current snooze state could not be confirmed in this response.</p>".to_owned()
    } else {
        m.current_until
            .map(|t| {
                format!(
                    "<p>This message is snoozed until <strong>{}</strong>.</p>",
                    escape_html(&date(t))
                )
            })
            .unwrap_or_else(|| "<p>This message has no current snooze marker.</p>".into())
    };
    let safe_return = crate::mail_navigation::safe_mail_return(m.return_to);
    let return_field = safe_return
        .as_ref()
        .map(|value| {
            format!(
                "<input type=hidden name=return_to value=\"{}\">",
                escape_html(value)
            )
        })
        .unwrap_or_default();
    let reload_context = safe_return
        .as_ref()
        .map(|value| format!("&amp;return_to={}", escape_html(&url_encode(value))))
        .unwrap_or_default();
    let reload = if !m.available {
        format!("<p><a href=\"/snooze?mailbox={}&amp;uid={}&amp;mailbox_guid={}&amp;message_guid={}{reload_context}\">Reload saved snooze</a> before another change. Your submitted time is retained below.</p>",escape_html(&url_encode(m.identity.folder())),m.identity.uid(),escape_html(&url_encode(m.identity.mailbox_guid())),escape_html(&url_encode(m.identity.message_guid())))
    } else {
        String::new()
    };
    let value = if m.until_utc.is_empty() {
        input_date(
            m.current_until
                .unwrap_or_else(|| m.now.saturating_add(3600)),
        )
    } else {
        m.until_utc.into()
    };
    let cancel = if m.current_until.is_some() {
        format!("<form method=post action=\"/snooze/change\">{}<button class=secondary name=action value=cancel {}>Cancel snooze</button></form>",fields(m.csrf,m.revision,m.identity),if m.available{""}else{"disabled"})
    } else {
        String::new()
    };
    let back = crate::mail_navigation::safe_mail_return(m.return_to)
        .map(|v| {
            format!(
                "<a class=\"button-link secondary\" href=\"{}\">Back to message or list</a>",
                escape_html(&v)
            )
        })
        .unwrap_or_default();
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell snooze-page\" tabindex=-1><div class=page-intro><h1>Snooze message</h1><p>Choose when this message returns to its source list.</p></div>{notice}<section class=\"panel snooze-card\"><h2>Return time</h2><p class=snooze-reference>{} · Message #{}</p>{state}{reload}<p class=snooze-now>Current server time: {}</p><form method=post action=\"/snooze/change\">{}{return_field}<fieldset {}><label for=snooze-until>Return at (UTC)</label><input id=snooze-until name=until type=datetime-local step=60 min=\"{}\" max=\"{}\" value=\"{}\" required aria-describedby=snooze-limits><p id=snooze-limits>Choose a future UTC time within 30 days. Up to 100 messages can be snoozed per account.</p><button name=action value=set>Save snooze</button></fieldset></form>{cancel}<p class=snooze-scope>{SCOPE}</p><nav class=snooze-links>{back}<a class=\"button-link secondary\" href=\"/snoozed\">Snoozed messages</a></nav></section></main>",app_header(m.account,m.csrf,"snooze"),escape_html(m.identity.folder()),m.identity.uid(),escape_html(&date(m.now)),fields(m.csrf,m.revision,m.identity),if m.available{""}else{"disabled"},input_date((m.now/60+1)*60),input_date(m.now.saturating_add(MAX_DURATION)),escape_html(&value)))
}
pub(crate) fn render_snoozed_page(
    account: &str,
    csrf: &str,
    record: Option<&SnoozeRecord>,
    error: Option<&str>,
) -> TrustedHtml {
    let mut body = String::new();
    if let Some(e) = error {
        body.push_str(&format!(
            "<p class=notice role=status>{}</p>",
            escape_html(e)
        ))
    }
    if let Some(r) = record {
        body.push_str(&format!("<p class=snooze-count>{} of {MAX_MARKERS} snooze markers used.</p><ul class=snooze-markers>",r.markers().len()));
        for m in r.markers() {
            let i = m.identity();
            body.push_str(&format!("<li><div><h2>{} · Message #{}</h2><p>Returns <time datetime=\"{}\">{}</time></p></div><form method=post action=\"/snooze/change\">{}<button class=secondary name=action value=cancel>Cancel snooze</button></form></li>",escape_html(i.folder()),i.uid(),crate::logging::format_unix_timestamp_utc(m.until()),escape_html(&date(m.until())),fields(csrf,r.revision(),i)))
        }
        if r.markers().is_empty() {
            body.push_str("<li>No active snooze markers.</li>")
        }
        body.push_str("</ul>");
    } else {
        body.push_str("<p>Snooze markers could not be loaded. Their state is unknown; cancellation is unavailable.</p>")
    }
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell snooze-page\" tabindex=-1><div class=page-intro><h1>Snoozed messages</h1><p>Private return times for your messages.</p></div><section class=\"panel snooze-card\">{body}<p class=snooze-scope>{SCOPE}</p><nav class=snooze-links><a class=\"button-link secondary\" href=\"/snoozed\">Refresh markers</a><a class=\"button-link secondary\" href=\"/mailboxes\">Mailbox</a></nav></section></main>",app_header(account,csrf,"snoozed")))
}
