//! Read-only composition checks on the draft saved by the explicit action.
use crate::http_support::escape_html;
use crate::http_ui::ComposePageModel;
use crate::send::{ComposePolicy, ComposeRequest};

pub(crate) fn render(model: &ComposePageModel<'_>) -> String {
    if !model.preflight {
        return String::new();
    }
    let result = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        model.to_value,
        model.cc_value,
        model.bcc_value,
        model.subject_value,
        model.body_value,
        model.draft_attachments.to_vec(),
    )
    .and_then(|request| request.with_body_format(model.body_format));
    let summary = match result {
        Ok(request) => format!(
            "<p class=\"notice notice-success\">Recipient addresses, message text and stored files pass composition checks.</p><dl class=\"message-meta\"><dt>Sender</dt><dd>{}</dd><dt>Recipients</dt><dd>{} To · {} Cc · {} Bcc · {} unique delivery addresses</dd><dt>Message format</dt><dd>{}</dd><dt>Stored attachments</dt><dd>{} files · {} bytes</dd></dl>",
            escape_html(model.canonical_username), request.recipients.len(),
            request.cc_recipients.len(), request.bcc_recipients.len(),
            request.all_recipients().len(),
            if model.body_format == crate::compose_format::BodyFormat::Plain { "Plain text" } else { "Formatted text with a plain-text alternative" },
            model.draft_attachments.len(), model.draft_attachments.iter().map(|file| file.body.len()).sum::<usize>(),
        ),
        Err(error) => format!("<p class=\"notice notice-error\" role=\"alert\">Edit this draft before sending: {}</p>", escape_html(&error.reason)),
    };
    let source = if model.selected_source_part_paths.is_empty() {
        String::new()
    } else {
        format!("<p class=\"notice\">{} original-message attachment(s) selected. Their current availability and combined size will be checked again when you send.</p>", model.selected_source_part_paths.len())
    };
    format!(concat!(
        "<section class=\"compose-preview compose-preflight\" aria-label=\"Pre-send check\"><h2>Pre-send check</h2>",
        "<p>This check shows the saved draft. After editing, check again. No message was sent.</p>{summary}{source}",
        "<p class=\"notice\">Signing and encryption are unavailable for this account. This message is unsigned and not encrypted.</p>",
        "<p class=\"muted\">These checks do not establish delivery or recipient-key availability. Sending rechecks the current account, draft and attachments.</p></section>"
    ), summary = summary, source = source)
}
