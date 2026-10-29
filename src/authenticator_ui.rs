//! Account-owned factor metadata and case-bound operator handoff.
use super::*;
use crate::authenticator::Snapshot;

pub(crate) fn authenticator_summary(state: Option<&Snapshot>) -> (String, String) {
    let Some(state) = state else {
        return (
            "Unknown".into(),
            "Authenticator state and last use are unavailable.".into(),
        );
    };
    let enrollment = if state.enrolled {
        "Enrolled"
    } else {
        "No active factor"
    };
    let last = state.last_accepted_counter.and_then(|v| v.checked_mul(30)).and_then(|at| at.checked_add(29).map(|end| (at, end))).map_or_else(
        || "Last use unknown; no accepted account TOTP time window is available.".into(),
        |(at,end)| format!("Last accepted account TOTP time window: {} to {}. This may predate the current factor; the exact verification time is not recorded.", crate::logging::format_unix_timestamp_utc(at), crate::logging::format_unix_timestamp_utc(end)),
    );
    (enrollment.into(), last)
}

pub(crate) fn render_authenticator_page(
    account: &str,
    csrf: &str,
    state: Option<&Snapshot>,
    notice: Option<&str>,
) -> TrustedHtml {
    let state = state.filter(|v| v.account == account);
    let (status, last) = authenticator_summary(state);
    let notice = notice
        .map(|v| format!("<p role=\"status\">{}</p>", escape_html(v)))
        .unwrap_or_default();
    let mut case = String::new();
    if let Some(record) = state
        .and_then(|v| v.case.as_ref())
        .filter(|v| v.account == account)
    {
        case.push_str(&format!("<section class=\"security-card\"><h2>Operator recovery case</h2><p>Case <code>{}</code>: <strong>{}</strong>.</p><p>Reported {}. Account admission and the operator's authoritative readback determine whether access is contained.</p></section>", escape_html(&record.case_id), escape_html(&record.state.replace('_', " ")), escape_html(&crate::logging::format_unix_timestamp_utc(record.updated_at))));
        if let (Some(state), Some(epoch)) = (record.account_state.as_ref(), record.account_epoch) {
            case.push_str(&format!("<p>Last observed account admission: <strong>{}</strong>, epoch {}. Reconcile with the operator if this observation is incomplete.</p>", escape_html(state), epoch));
        }
    }
    let request = state
        .and_then(|v| v.request.as_ref())
        .filter(|v| v.account == account);
    let completed = request.is_some_and(|request| {
        state.and_then(|v| v.case.as_ref()).is_some_and(|case| {
            case.case_id == request.case_id
                && case.state == "reconciled"
                && case.account_state.as_deref() == Some("active")
        })
    });
    let request_body = if let Some(record) = request.filter(|_| !completed) {
        format!("<p>Request <code>{}</code> is recorded. Give this case reference to the operator through the established independent channel. Recording a request supplies no recovery authorization.</p>", escape_html(&record.case_id))
    } else {
        format!("<form method=\"post\" action=\"/settings/authenticator\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"action\" value=\"request\"><button type=\"submit\"{}>{}</button></form>", escape_html(csrf), request.map_or(0, |r| r.revision), if state.is_some() { "" } else { " disabled" }, if completed { "Request another recovery" } else { "Request operator recovery" })
    };
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell settings-page settings-security-page\" tabindex=\"-1\"><nav aria-label=\"Breadcrumb\"><a href=\"/settings?section=authentication\">Authentication &amp; Recovery</a> / Authenticator</nav><div class=\"page-intro\"><h1>Authenticator management</h1><p>Current factor state and governed operator recovery for your account.</p></div>{notice}<div class=\"security-two-cards\"><section class=\"security-card\"><h2>TOTP authenticator</h2><strong>{}</strong><p>{}</p></section><section class=\"security-card\"><h2>Request recovery</h2>{request_body}<p>If you cannot sign in, contact the operator through the established independent channel. Account lookup requires authentication; email possession cannot authorize a reset.</p></section></div>{case}<section class=\"security-card\"><h2>Recovery boundary</h2><p>An operator must independently verify identity, contain access and revoke sessions before replacing a factor. A verified recovery contact does not prove identity or bypass MFA. Replacement and final reconciliation require the operator's private terminal. Interrupted or uncertain effects require read-only reconciliation and manual escalation; the old factor is never automatically restored.</p><p>The supported recovery preserves your current password. Lost-password and missing-factor cases require manual review. A request does not change your password, factor or sessions.</p></section></main>", app_header(account, csrf, "settings-authentication"), escape_html(&status), escape_html(&last)))
}
