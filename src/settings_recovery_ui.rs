//! Contact metadata only: rendering never accepts a credential or proof token.
use super::*;
use crate::recovery_contact::{RecoveryContactDelivery, RecoveryContactSnapshot};

pub(crate) fn recovery_contact_summary(
    state: Option<&RecoveryContactSnapshot>,
) -> (&'static str, String) {
    match state {
        None => (
            "Unknown",
            "Contact and verification status unavailable".into(),
        ),
        Some(state) => {
            let mut detail = if let Some(contact) = &state.verified {
                format!(
                    "{} — verified {}",
                    escape_html(&contact.email),
                    escape_html(&crate::logging::format_unix_timestamp_utc(
                        contact.verified_at
                    ))
                )
            } else {
                "No verified recovery contact".into()
            };
            if let Some(pending) = &state.pending {
                detail.push_str(&format!(
                    "; pending verification: {}",
                    escape_html(&pending.email)
                ));
            }
            (
                if state.verified.is_some() {
                    "Verified"
                } else if state.pending.is_some() {
                    "Pending"
                } else {
                    "Not configured"
                },
                detail,
            )
        }
    }
}

fn delivery_label(delivery: RecoveryContactDelivery) -> &'static str {
    match delivery {
        RecoveryContactDelivery::Accepted => {
            "Accepted by the mail service; receipt is not confirmed."
        }
        RecoveryContactDelivery::Refused => {
            "Message submission was refused. No successful delivery is claimed."
        }
        RecoveryContactDelivery::Unconfirmed => {
            "Message submission is unconfirmed. Do not repeat it; contact support to reconcile it."
        }
    }
}

pub(crate) fn render_recovery_contact_page(
    account: &str,
    csrf: &str,
    state: Option<&RecoveryContactSnapshot>,
    notice: Option<&str>,
    entered_email: Option<&str>,
) -> TrustedHtml {
    let entered_email = entered_email
        .filter(|value| {
            crate::mail_address::validate_address(
                crate::send::ComposePolicy {
                    recipient_max_len: 254,
                    ..Default::default()
                },
                value,
            )
            .is_ok()
        })
        .map(escape_html)
        .unwrap_or_else(|| escape_html(""));
    let (status, detail) = recovery_contact_summary(state);
    let notice = notice
        .map(|v| format!("<p role=\"alert\">{}</p>", escape_html(v)))
        .unwrap_or_default();
    let common = format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\">", escape_html(csrf), state.map_or(0, |v| v.revision));
    let disabled = if state.is_some() { "" } else { " disabled" };
    let stepup = |prefix: &str| {
        format!("<label for=\"{prefix}-password\">Confirm current password</label><input id=\"{prefix}-password\" name=\"current_password\" type=\"password\" autocomplete=\"current-password\" maxlength=\"1024\" required><label for=\"{prefix}-totp\">Fresh authenticator code</label><input id=\"{prefix}-totp\" name=\"totp_code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required>")
    };
    let mut pending = String::new();
    if let Some(value) = state.and_then(|v| v.pending.as_ref()) {
        let expired = crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider)
            >= value.token_expires_at;
        pending = format!("<section class=\"security-card\"><h2>Verify pending contact</h2><p>{} — {}</p><p>{}</p><p>Verification expires {}. {} attempts remain.</p><form method=\"post\" action=\"/settings/recovery\" autocomplete=\"off\">{common}<input type=\"hidden\" name=\"action\" value=\"verify\"><label for=\"recovery-proof\">Verification code from the message</label><input id=\"recovery-proof\" name=\"token\" autocomplete=\"off\" minlength=\"64\" maxlength=\"64\" pattern=\"[0-9a-f]{{64}}\" required><button type=\"submit\">Verify contact</button></form><details><summary>Resend verification</summary><p>Wait at least 60 seconds between messages. At most three per hour and ten per day.</p><form method=\"post\" action=\"/settings/recovery\" autocomplete=\"off\">{common}<input type=\"hidden\" name=\"action\" value=\"resend\">{}<button type=\"submit\">Resend verification</button></form></details></section>", escape_html(&value.email), if expired { "Code expired" } else { "Pending verification" }, delivery_label(value.delivery), escape_html(&crate::logging::format_unix_timestamp_utc(value.token_expires_at)), value.attempts_remaining, stepup("resend"));
    }
    let old_notice = state.and_then(|v| v.notice.as_ref()).map(|v| format!("<p role=\"status\">Previous-contact notification: {}</p>{}", delivery_label(v.delivery), if v.earlier_unconfirmed { "<p role=\"alert\">An earlier previous-contact notification remains unconfirmed. Contact support to reconcile it.</p>" } else { "" })).unwrap_or_default();
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell settings-page settings-security-page recovery-contact-page\" tabindex=\"-1\"><nav aria-label=\"Breadcrumb\"><a href=\"/settings?section=security\">Security</a> / Recovery contact</nav><div class=\"page-intro\"><h1>Recovery Contact</h1><p>Add, verify, change or remove the recovery contact for your account.</p></div>{notice}<div class=\"security-two-cards\"><section class=\"security-card\"><h2>Current Recovery Contact</h2><strong>{status}</strong><p>{detail}</p>{old_notice}<a class=\"button-link secondary\" href=\"#recovery-change\">Change contact</a><details><summary>Remove contact</summary><p>This removes the verified contact and any pending proof. A previous verified contact receives a notification.</p><form method=\"post\" action=\"/settings/recovery\" autocomplete=\"off\">{common}<fieldset{disabled}><legend>Confirm removal</legend><input type=\"hidden\" name=\"action\" value=\"remove\">{}<button type=\"submit\" class=\"secondary\">Remove contact</button></fieldset></form></details></section><section id=\"recovery-change\" class=\"security-card\"><h2>Add or Change Contact</h2><form method=\"post\" action=\"/settings/recovery\" autocomplete=\"off\">{common}<fieldset{disabled}><legend>Verify your own account</legend><input type=\"hidden\" name=\"action\" value=\"begin\"><label for=\"recovery-email\">New email</label><input id=\"recovery-email\" name=\"email\" type=\"email\" autocomplete=\"off\" maxlength=\"254\" value=\"{entered_email}\" required>{}<button type=\"submit\">Send verification</button></fieldset><a class=\"button-link secondary\" href=\"/settings?section=security\">Cancel</a></form><p>Verification codes are single-use and expire after 30 minutes. A pending request expires after 24 hours. Your current verified contact stays active until replacement verification succeeds. The previous verified contact receives a change notification.</p></section></div>{pending}<section class=\"security-card\"><h2>Recovery boundary</h2><p>Possession of this email address does not bypass TOTP, automatically restore a factor, or prove identity by itself.</p></section></main>", app_header(account, csrf, "settings-security"), stepup("remove"), stepup("change")))
}
