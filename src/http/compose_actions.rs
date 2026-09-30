//! Native confirmation controls for discarding a composed message.
use crate::compose_format::BodyFormat;
use crate::http_support::escape_html;
use crate::http_ui::ComposePageModel;
use std::collections::BTreeMap;

pub(super) fn body_format(form: &BTreeMap<String, String>) -> Option<BodyFormat> {
    match form.get("body_format") {
        None => Some(BodyFormat::Plain),
        Some(value) => BodyFormat::parse(value),
    }
}

/// Apply the explicitly submitted native action. A selected range is measured
/// in browser UTF-16 units and must end on complete Unicode characters.
pub(super) fn apply_format(form: &mut BTreeMap<String, String>) -> Result<(), &'static str> {
    let action = form.get("compose_action").map(String::as_str).unwrap_or("");
    if !action.starts_with("format-") {
        return Ok(());
    }
    // Native forms transmit textarea newlines as CRLF; selectionStart/End are
    // measured against the DOM's LF-normalized value.
    let source = form
        .get("body")
        .map(String::as_str)
        .unwrap_or("")
        .replace("\r\n", "\n");
    let (mut start, mut end) = match (
        form.get("format_start").map(String::as_str).unwrap_or(""),
        form.get("format_end").map(String::as_str).unwrap_or(""),
    ) {
        ("", "") => (0, source.len()),
        (start, end) => {
            let start = start
                .parse::<usize>()
                .map_err(|_| "Select the text again before formatting.")?;
            let end = end
                .parse::<usize>()
                .map_err(|_| "Select the text again before formatting.")?;
            let offset = |wanted| {
                let mut units = 0;
                for (offset, character) in source.char_indices() {
                    if units == wanted {
                        return Some(offset);
                    }
                    units += character.len_utf16();
                }
                (units == wanted).then_some(source.len())
            };
            let start =
                offset(start).ok_or("The text selection was incomplete. Select it again.")?;
            let end = offset(end).ok_or("The text selection was incomplete. Select it again.")?;
            if start > end {
                return Err("Select the text again before formatting.");
            }
            (start, end)
        }
    };
    if matches!(action, "format-bullets" | "format-numbers") {
        // Lists apply to whole selected lines, including a partially selected
        // first or last line, without joining neighbouring paragraphs.
        start = source[..start].rfind('\n').map_or(0, |index| index + 1);
        if end > 0 && !source[..end].ends_with('\n') {
            end = source[end..]
                .find('\n')
                .map_or(source.len(), |index| end + index + 1);
        }
    }
    let selected = &source[start..end];
    let replacement = match action {
        "format-bold" | "format-italic" | "format-underline" => {
            let marker = match action {
                "format-bold" => "**",
                "format-italic" => "*",
                _ => "__",
            };
            // Inline notation is line-scoped. Preserve selected line endings
            // and blank paragraphs while formatting every nonempty line.
            selected
                .split_inclusive('\n')
                .map(|line| {
                    let text = line.strip_suffix('\n').unwrap_or(line);
                    let ending = if line.ends_with('\n') { "\n" } else { "" };
                    if text.is_empty() {
                        ending.to_string()
                    } else {
                        format!("{marker}{text}{marker}{ending}")
                    }
                })
                .collect::<String>()
        }
        "format-bullets" | "format-numbers" => {
            let mut result = selected
                .split_inclusive('\n')
                .enumerate()
                .map(|(index, line)| {
                    if action == "format-bullets" {
                        format!("- {line}")
                    } else {
                        format!("{}. {line}", index + 1)
                    }
                })
                .collect::<String>();
            if result.is_empty() {
                result.push_str(if action == "format-bullets" {
                    "- "
                } else {
                    "1. "
                });
            }
            result
        }
        "format-link" => {
            let url = form
                .get("format_url")
                .map(String::as_str)
                .unwrap_or("")
                .trim();
            let label = form
                .get("format_label")
                .map(String::as_str)
                .filter(|text| !text.is_empty())
                .unwrap_or(selected);
            let label = if label.is_empty() { url } else { label };
            // Keep the notation unambiguous; the shared renderer is URL authority.
            if label.contains(['[', ']', '\n', '\r']) || url.contains(['(', ')', '\n', '\r']) {
                return Err(
                    "Use a link label without brackets and an HTTP, HTTPS or mailto address.",
                );
            }
            let link = format!("[{label}]({url})");
            crate::compose_format::render(&link).map_err(|_| {
                "Enter a supported HTTP, HTTPS or mailto link address in Formatting options."
            })?;
            link
        }
        "format-emoji" => "🙂".into(),
        _ => return Err("Choose a supported formatting action."),
    };
    let result = if action == "format-emoji" {
        format!("{source}🙂")
    } else {
        format!("{}{replacement}{}", &source[..start], &source[end..])
    };
    if result.len() > crate::send::DEFAULT_BODY_MAX_LEN {
        return Err("Formatting would exceed the message text limit.");
    }
    form.insert("body".into(), result);
    form.insert("body_format".into(), BodyFormat::Formatted.as_str().into());
    Ok(())
}

pub(crate) fn formatting_controls(model: &ComposePageModel<'_>) -> String {
    let disabled = if model.draft_id.is_some() && model.draft_revision.is_none() {
        " disabled"
    } else {
        ""
    };
    let mut buttons = String::new();
    for (action, label, caption) in [
        ("bold", "Bold", "<b>B</b>"),
        ("italic", "Italic", "<i>I</i>"),
        ("underline", "Underline", "<u>U</u>"),
        ("bullets", "Bulleted list", "• list"),
        ("numbers", "Numbered list", "1. list"),
        ("link", "Insert link", "↗ link"),
    ] {
        buttons.push_str(&format!("<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"format-{action}\" aria-label=\"{label}\" title=\"{label}: format selected text, or the whole message, and save draft\">{caption}</button>"));
    }
    let attach = if disabled.is_empty() {
        "<a class=\"compose-toolbar-attach\" href=\"#compose-attachment\" aria-label=\"Attach local files\" title=\"Select local files to attach\">📎 attach</a>"
    } else {
        "<span class=\"compose-toolbar-attach\" aria-disabled=\"true\" title=\"Compare the stored version before adding attachments\">📎 attach</span>"
    };
    let options = "<details class=\"compose-format-options\" name=\"compose-authoring\"><summary>Formatting options</summary><div><p>Formatting buttons save this draft. Select message text to format it; without a selection, the whole message is used. Lists apply to complete selected lines. Emoji appends 🙂. Source notation stays editable.</p><label for=\"format-url\">Link address</label><input id=\"format-url\" name=\"format_url\" type=\"text\" placeholder=\"https://example.com\"><label for=\"format-label\">Link label (optional)</label><input id=\"format-label\" name=\"format_label\" type=\"text\"><p>Enter the link address, select text or supply a label, then choose Insert link. Preview shows the outgoing alternatives.</p></div></details>";
    format!(concat!(
        "<div class=\"compose-editor-toolbar\"><div class=\"compose-format-tools\" role=\"group\" aria-label=\"Text formatting\">{buttons}",
        "<details class=\"compose-image-action\" name=\"compose-authoring\"><summary aria-label=\"Attach local image\">▧ image</summary><div><label for=\"compose-image\">Local image</label><input id=\"compose-image\" type=\"file\" name=\"image_attachment\" accept=\"image/png,image/jpeg,image/gif\"><p class=\"muted\">PNG, JPEG or GIF, up to 5 MiB. Sent as an attachment.</p><button type=\"submit\"{disabled} formaction=\"/drafts/save\">Save image attachment</button></div></details>",
        "{attach}<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"format-emoji\" aria-label=\"Insert emoji\" title=\"Append an emoji and save draft\">☺</button>",
        "<label class=\"sr-only\" for=\"compose-body-format\">Message format</label><select id=\"compose-body-format\" name=\"body_format\"><option value=\"plain\"{plain}>Plain text</option><option value=\"formatted\"{formatted}>Formatted source</option></select>",
        "<button type=\"submit\"{disabled} formaction=\"/drafts/save\" name=\"compose_action\" value=\"preview\">Preview</button>{options}</div><span class=\"compose-inline-policy\">Attention: unsigned, not encrypted.</span></div>",
        "<input type=\"hidden\" name=\"format_start\" value=\"\"><input type=\"hidden\" name=\"format_end\" value=\"\">",
    ), buttons = buttons, disabled = disabled, options = options, attach = attach,
    plain = if model.body_format == BodyFormat::Plain { " selected" } else { "" },
    formatted = if model.body_format == BodyFormat::Formatted { " selected" } else { "" })
}

pub(crate) fn preview(model: &ComposePageModel<'_>) -> String {
    if !model.preview {
        return String::new();
    }
    let content = match model.body_format {
        BodyFormat::Plain => format!("<h3>Plain-text message</h3><pre dir=\"auto\">{}</pre>", escape_html(model.body_value)),
        BodyFormat::Formatted => match crate::compose_format::render(model.body_value) {
            Ok(body) => format!("<h3>Formatted message</h3><div class=\"compose-preview-html\" dir=\"auto\">{}</div><details><summary>Plain-text alternative</summary><pre dir=\"auto\">{}</pre></details>", body.html, escape_html(&body.plain)),
            Err(error) => format!("<p class=\"notice notice-error\" role=\"alert\">Draft saved. Preview and sending are blocked: {}. Edit the source and preview again.</p>", escape_html(&error.to_string())),
        }
    };
    format!("<section class=\"compose-preview\" aria-label=\"Message preview\"><h2>Message preview</h2>{content}<p class=\"muted\">This preview shows the saved draft. After editing, preview again. Preview sends no mail.</p></section>")
}

/// Return the visible disclosure and its separate form, avoiding nested forms.
pub(crate) fn discard_controls(model: &ComposePageModel<'_>) -> (String, String) {
    match (model.draft_id, model.draft_revision) {
        (Some(id), Some(revision)) => (
            concat!(
                "<details class=\"compose-discard\"><summary>Discard</summary>",
                "<div><p>Review this saved draft before discarding it. Unsaved changes in this tab will not be saved.</p>",
                "<button type=\"submit\" form=\"compose-discard-form\" name=\"stage\" value=\"review\">Review discard</button></div></details>"
            ).into(),
            format!(concat!(
                "<form id=\"compose-discard-form\" method=\"post\" action=\"/drafts/discard\" hidden>",
                "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
                "<input type=\"hidden\" name=\"selected_{}\" value=\"{revision}\">",
                "<input type=\"hidden\" name=\"filter\" value=\"all\">",
                "<input type=\"hidden\" name=\"sort\" value=\"newest\">",
                "<input type=\"hidden\" name=\"q\" value=\"\"></form>"
            ), escape_html(model.csrf_token), escape_html(id), revision = revision),
        ),
        (Some(_), None) => (
            "<button type=\"button\" disabled title=\"Compare with the stored version before discarding\">Discard</button>".into(), String::new()
        ),
        (None, _) => (
            concat!(
                "<details class=\"compose-discard\"><summary>Discard</summary>",
                "<div><p>Discard this unsaved message and its selected files?</p>",
                "<a class=\"button-link\" href=\"/drafts\" data-confirm-discard=\"true\">Discard unsaved message</a></div></details>"
            ).into(), String::new()
        ),
    }
}
