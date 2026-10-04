//! Read-only recovery after a submission outcome that needs user attention.
use crate::html::TrustedHtml;
use crate::http_support::{escape_html, url_encode};
use crate::send::UploadedAttachment;

#[derive(Clone, Copy)]
pub(crate) enum SubmissionResult {
    AlreadyRecorded,
    RecoveryRefused {
        capacity: bool,
    },
    Accepted {
        sent_copy_stored: bool,
        draft_cleanup_confirmed: bool,
        receipt_persisted: bool,
    },
    AcceptedWithoutSentCopy {
        draft_cleanup_confirmed: bool,
        receipt_persisted: bool,
    },
    Unconfirmed,
    Paused,
}

pub(crate) struct ComposeResultModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub result: SubmissionResult,
    pub send_intent: Option<&'a str>,
    pub draft_id: Option<&'a str>,
    pub to: &'a str,
    pub cc: &'a str,
    pub bcc: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub body_format: crate::compose_format::BodyFormat,
    pub attachments: &'a [UploadedAttachment],
}

pub(crate) fn render(model: &ComposeResultModel<'_>) -> TrustedHtml {
    let (heading, explanation) = match model.result {
        SubmissionResult::AlreadyRecorded => ("This intent already has a recorded action", "No new save or submission was started. The current form text and files shown below may differ from the recorded action. Inspect the existing receipt in a new tab to compare; do not retry this form."),
        SubmissionResult::RecoveryRefused { capacity } => ("Submission was not invoked", if capacity { "The combined draft and attempt-recovery storage limit was reached. Submission was not invoked. This intent remains paused; do not retry or recreate this message automatically." } else { "The exact attempt recovery copy could not be confirmed. Submission was not invoked. This intent remains paused; do not retry or recreate this message automatically." }),
        SubmissionResult::Accepted { .. } | SubmissionResult::AcceptedWithoutSentCopy { .. } => (
            "Message accepted for submission",
            "The mail system accepted this message for submission. This does not confirm delivery. Do not send this message again to repair its Sent copy or remove its draft.",
        ),
        SubmissionResult::Paused => (
            "This form is paused",
            "The attempt state could not be confirmed. Another save or submission may already be in progress or recorded. Do not retry this form. Keep this page open while checking the recorded outcome.",
        ),
        SubmissionResult::Unconfirmed => (
            "Submission could not be confirmed",
            "The mail system may have accepted this message. Ask the mail operator to confirm acceptance before sending it again. An empty Sent folder does not prove that submission failed.",
        ),
    };
    let mut details = if let Some(intent) = model
        .send_intent
        .filter(|value| crate::send_journal::receipt_intent_valid(value))
    {
        format!("<p><a href=\"/compose?receipt={}\" target=\"_blank\" rel=\"noopener noreferrer\">Check this attempt’s receipt (opens in a new tab)</a>. Keep this tab open to preserve the text shown below. The receipt may also provide a separately retained, verified attempt snapshot. Either may be unavailable; opening it does not submit a message.</p>", escape_html(&url_encode(intent)))
    } else {
        "<p>This form’s tracking value is missing or invalid, so no receipt link is available. Keep this page open to copy your text and ask the mail operator to reconcile the outcome. Do not retry submission.</p>".into()
    };
    if let SubmissionResult::Accepted {
        sent_copy_stored,
        draft_cleanup_confirmed,
        receipt_persisted,
    } = model.result
    {
        if !receipt_persisted {
            details.push_str("<p>Submission acceptance is known, but receipt persistence could not be confirmed. Do not retry.</p>");
        }
        details.push_str(if sent_copy_stored {
            "<p>A copy was stored in Sent.</p>"
        } else {
            "<p>Sent-copy storage could not be confirmed. The copy may be missing or may already be present. Submission was accepted; sending again would risk a duplicate.</p>"
        });
        if model.draft_id.is_some() {
            details.push_str(if !sent_copy_stored {
                "<p>The saved draft was not removed by this response. Drafts expire after 30 days and may differ from the text or attachments used in this attempt.</p>"
            } else if !draft_cleanup_confirmed {
                "<p>Removal of the saved draft could not be confirmed. It may still appear in Drafts. Do not send it again.</p>"
            } else {
                "<p>The saved draft is no longer present.</p>"
            });
        }
    } else if let SubmissionResult::AcceptedWithoutSentCopy {
        draft_cleanup_confirmed,
        receipt_persisted,
    } = model.result
    {
        details.push_str("<p>Sent copy was not requested for this attempt. No Sent append was invoked. This does not confirm delivery.</p>");
        if !receipt_persisted {
            details.push_str("<p>Submission acceptance is known, but receipt persistence could not be confirmed. Do not retry.</p>");
        }
        if model.draft_id.is_some() {
            details.push_str(if draft_cleanup_confirmed {
                "<p>The saved draft is no longer present.</p>"
            } else {
                "<p>Removal of the saved draft could not be confirmed. It may still appear in Drafts. Do not send it again.</p>"
            });
        }
    } else if model.draft_id.is_some() {
        details.push_str("<p>The saved draft was not removed by this response. Drafts expire after 30 days and may differ from the text or attachments used in this attempt.</p>");
    }
    if let Some(id) = model.draft_id {
        details.push_str(&format!(
            "<p><a href=\"/draft?id={}\" target=\"_blank\" rel=\"noopener\">Compare the saved draft (opens in a new tab)</a>. This link does not confirm submission.</p>",
            escape_html(&url_encode(id)),
        ));
    }
    let mut retained = String::new();
    for (id, label, value, rows) in [
        ("to", "To", model.to, 2),
        ("cc", "Cc", model.cc, 2),
        ("bcc", "Bcc", model.bcc, 2),
        ("subject", "Subject", model.subject, 2),
        ("body", "Message source", model.body, 12),
    ] {
        retained.push_str(&format!(
            "<label for=\"result-{id}\">{label}</label><textarea id=\"result-{id}\" rows=\"{rows}\" readonly>\n{}</textarea>",
            escape_html(value),
        ));
    }
    let mut attachments = String::new();
    for attachment in model.attachments {
        attachments.push_str(&format!(
            "<li>{} ({} bytes)</li>",
            escape_html(&attachment.filename),
            attachment.body.len(),
        ));
    }
    let attachment_summary = if attachments.is_empty() {
        "<p>No files were listed with this form response. Check the verified attempt snapshot for the prepared attachments.</p>".to_string()
    } else {
        format!("<h3>Files supplied with this form</h3><ul>{attachments}</ul><p>This list is not an attachment backup. New uploads are not saved by this result page; saved-draft files are subject to the 30-day draft expiry and may have been removed. This page does not establish their present availability.</p>")
    };
    TrustedHtml::from_template(format!(
        concat!(
            "{}<main id=\"main-content\" class=\"page-shell submission-result-page\" tabindex=\"-1\">",
            "<section class=\"panel\" aria-labelledby=\"submission-result-heading\">",
            "<h1 id=\"submission-result-heading\">{heading}</h1>",
            "<div class=\"notice notice-error\" role=\"alert\"><p>{explanation}</p>{details}</div>",
            "<p>Keep this page open to copy your text. Do not reload or resubmit this page.</p>",
            "<section aria-labelledby=\"retained-message-heading\"><h2 id=\"retained-message-heading\">Text retained from this attempt</h2>",
            "<p>Message format: {}. These fields are read-only and can be selected and copied.</p>",
            "{retained}{attachment_summary}</section>",
            "<p><a href=\"/mailbox?name=Sent\">Open Sent</a> · <a href=\"/drafts\">Open Drafts</a></p>",
            "</section></main>"
        ),
        crate::http_ui::app_header(model.account, model.csrf, "compose-result"),
        model.body_format.as_str(),
        heading = heading,
        explanation = explanation,
        details = details,
        retained = retained,
        attachment_summary = attachment_summary,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_retains_exact_escaped_text_without_a_send_action() {
        let text = "</textarea><script>private & synthetic</script>\n🦊";
        for result in [
            SubmissionResult::AcceptedWithoutSentCopy {
                draft_cleanup_confirmed: false,
                receipt_persisted: false,
            },
            SubmissionResult::AcceptedWithoutSentCopy {
                draft_cleanup_confirmed: true,
                receipt_persisted: true,
            },
            SubmissionResult::AlreadyRecorded,
            SubmissionResult::RecoveryRefused { capacity: false },
            SubmissionResult::RecoveryRefused { capacity: true },
            SubmissionResult::Paused,
            SubmissionResult::Unconfirmed,
            SubmissionResult::Accepted {
                sent_copy_stored: true,
                draft_cleanup_confirmed: false,
                receipt_persisted: false,
            },
            SubmissionResult::Accepted {
                sent_copy_stored: false,
                draft_cleanup_confirmed: false,
                receipt_persisted: true,
            },
            SubmissionResult::Accepted {
                sent_copy_stored: true,
                draft_cleanup_confirmed: false,
                receipt_persisted: true,
            },
        ] {
            let html = render(&ComposeResultModel {
                account: "alice@example.test",
                csrf: "synthetic-token",
                result,
                send_intent: None,
                draft_id: Some("draft&\"id"),
                to: text,
                cc: "",
                bcc: "hidden@example.test",
                subject: text,
                body: text,
                body_format: crate::compose_format::BodyFormat::Formatted,
                attachments: &[],
            });
            let html = html.as_str();
            assert!(html.contains(escape_html(text).as_str()));
            assert!(html.contains("readonly"));
            assert!(html.contains("role=\"alert\""));
            assert!(html.contains("/draft?id=draft%26%22id"));
            assert!(!html.contains("<script>"));
            assert!(!html.contains("action=\"/send\""));
            assert!(!html.contains("Send Message"));
            assert!(!html.contains("Nothing was sent"));
            assert!(html.contains("Do not reload or resubmit"));
            if matches!(result, SubmissionResult::AcceptedWithoutSentCopy { .. }) {
                assert!(html.contains("Sent copy was not requested for this attempt"));
                assert!(html.contains("No Sent append was invoked"));
                assert!(!html.contains("Sent-copy storage could not be confirmed"));
                assert!(!html.contains("A copy was stored in Sent"));
                assert!(html.contains("does not confirm delivery"));
            }
        }
    }
}

#[cfg(test)]
#[test]
fn readonly_receipt_navigation_uses_only_existing_valid_tracking() {
    let valid = "100.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for result in [
        SubmissionResult::Paused,
        SubmissionResult::Unconfirmed,
        SubmissionResult::Accepted {
            sent_copy_stored: true,
            draft_cleanup_confirmed: false,
            receipt_persisted: false,
        },
    ] {
        for intent in [
            None,
            Some(""),
            Some("0.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some("100.\"><script>x</script>"),
            Some(valid),
        ] {
            let html = render(&ComposeResultModel {
                account: "alice@example.com",
                csrf: "synthetic",
                result,
                send_intent: intent,
                draft_id: None,
                to: "bob@example.com",
                cc: "",
                bcc: "",
                subject: "Synthetic",
                body: "Keep exact 🦊 & source",
                body_format: crate::compose_format::BodyFormat::Plain,
                attachments: &[],
            });
            let html = html.as_str();
            assert!(html.contains("Keep exact 🦊 &amp; source"));
            if intent == Some(valid) {
                assert_eq!(html.matches("/compose?receipt=").count(), 1);
                assert!(html.contains(&format!("href=\"/compose?receipt={valid}\" target=\"_blank\" rel=\"noopener noreferrer\"")));
                assert!(html.contains("Keep this tab open"));
            } else {
                assert!(!html.contains("/compose?receipt="));
                assert!(html.contains("tracking value is missing or invalid"));
            }
            for absent in [
                "action=\"/send\"",
                "action=\"/drafts/save\"",
                "name=\"send_intent\"",
                "<script",
                "http-equiv=\"refresh\"",
                "onload=",
            ] {
                assert!(!html.contains(absent));
            }
        }
    }
}
