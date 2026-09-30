//! Read-only recovery after a submission outcome that needs user attention.
use crate::html::TrustedHtml;
use crate::http_support::{escape_html, url_encode};
use crate::send::UploadedAttachment;

#[derive(Clone, Copy)]
pub(crate) enum SubmissionResult {
    Accepted {
        sent_copy_stored: bool,
        draft_cleanup_confirmed: bool,
    },
    Unconfirmed,
}

pub(crate) struct ComposeResultModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub result: SubmissionResult,
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
        SubmissionResult::Accepted { .. } => (
            "Message accepted for submission",
            "The mail system accepted this message for submission. This does not confirm delivery. Do not send this message again to repair its Sent copy or remove its draft.",
        ),
        SubmissionResult::Unconfirmed => (
            "Submission could not be confirmed",
            "The mail system may have accepted this message. Ask the mail operator to confirm acceptance before sending it again. An empty Sent folder does not prove that submission failed.",
        ),
    };
    let mut details = String::new();
    if let SubmissionResult::Accepted {
        sent_copy_stored,
        draft_cleanup_confirmed,
    } = model.result
    {
        details.push_str(if sent_copy_stored {
            "<p>A copy was stored in Sent.</p>"
        } else {
            "<p>Sent-copy storage could not be confirmed. The copy may be missing or may already be present. Submission was accepted; sending again would risk a duplicate.</p>"
        });
        if model.draft_id.is_some() {
            details.push_str(if !sent_copy_stored {
                "<p>Your saved draft was kept for recovery. It may differ from the text or attachments used in this attempt.</p>"
            } else if !draft_cleanup_confirmed {
                "<p>Removal of the saved draft could not be confirmed. It may still appear in Drafts. Do not send it again.</p>"
            } else {
                "<p>The saved draft is no longer present.</p>"
            });
        }
    } else if model.draft_id.is_some() {
        details.push_str("<p>Your saved draft was kept for recovery. It may differ from the text or attachments used in this attempt.</p>");
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
            "<label for=\"result-{id}\">{label}</label><textarea id=\"result-{id}\" rows=\"{rows}\" readonly>{}</textarea>",
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
        "<p>No attachments were included in this attempt.</p>".to_string()
    } else {
        format!("<h3>Attachments included in this attempt</h3><ul>{attachments}</ul><p>This list is not an attachment backup. New uploads are not saved by this result page; existing saved-draft files remain available unless draft removal was confirmed.</p>")
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
            SubmissionResult::Unconfirmed,
            SubmissionResult::Accepted {
                sent_copy_stored: false,
                draft_cleanup_confirmed: false,
            },
            SubmissionResult::Accepted {
                sent_copy_stored: true,
                draft_cleanup_confirmed: false,
            },
        ] {
            let html = render(&ComposeResultModel {
                account: "alice@example.test",
                csrf: "synthetic-token",
                result,
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
        }
    }
}
