//! Native ordinary-footer preferences, independent of identity and cryptography.
use crate::{html::TrustedHtml, http_support::escape_html, signature::SignatureRecord};
pub(crate) struct SignatureEditorModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub revision: u64,
    pub selection: &'a str,
    pub text: &'a str,
    pub operation: &'a str,
    pub return_section: &'a str,
    pub notice: &'a str,
    pub editable: bool,
}
fn fields(csrf: &str, r: u64, section: &str, operation: &str) -> String {
    format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"signature_revision\" value=\"{r}\"><input type=\"hidden\" name=\"return_section\" value=\"{}\"><input type=\"hidden\" name=\"operation\" value=\"{operation}\">",escape_html(csrf),escape_html(section))
}
pub(crate) fn selection(record: Option<&SignatureRecord>, composition: bool) -> String {
    let disabled = if record.is_some() { "" } else { " disabled" };
    let enabled = record.is_some_and(|r| r.selection.as_str() == "default");
    if composition {
        format!("<input form=\"signature-selection-form\" class=\"settings-switch\" id=\"composition-signature\" type=\"checkbox\" role=\"switch\" name=\"selection\" value=\"default\"{}{} aria-describedby=\"signature-scope\">",if enabled{" checked"}else{""},disabled)
    } else {
        format!("<select form=\"signature-selection-form\" id=\"identity-signature\" name=\"selection\"{disabled}><option value=\"none\"{}>{}</option><option value=\"default\"{}>Default signature</option></select>",if !enabled{" selected"}else{""},if record.is_some(){"None"}else{"Unavailable"},if enabled{" selected"}else{""})
    }
}
pub(crate) fn editor(csrf: &str, record: Option<&SignatureRecord>, section: &str) -> String {
    let Some(r) = record else {
        return "<p class=\"signature-unavailable\" role=\"status\">Saved signature preferences are unavailable. Reload settings before changing the signature.</p>".into();
    };
    format!("<div class=\"signature-settings\"><form id=\"signature-selection-form\" method=\"post\" action=\"/settings/signature\">{}<button type=\"submit\">Save signature choice</button></form><details class=\"signature-editor\"><summary>Edit Default signature text</summary><form method=\"post\" action=\"/settings/signature\">{}<input type=\"hidden\" name=\"selection\" value=\"{}\"><label for=\"signature-text\">Default signature text</label><textarea id=\"signature-text\" name=\"text\" rows=\"5\" aria-describedby=\"signature-scope signature-limit\">\n{}</textarea><p id=\"signature-limit\">Up to 2,000 characters and 8,000 bytes. Save the text, then select Default or enable Include signature.</p><button type=\"submit\">Save signature text</button></form></details><p id=\"signature-scope\">Ordinary footer text, not an OpenPGP signature. When enabled, it is inserted visibly into newly opened composers only. Existing drafts keep their text. Formatted insertion requires exact literal rendering; otherwise the composer explains how to add it manually.</p></div>",fields(csrf,r.revision,section,"selection"),fields(csrf,r.revision,section,"definition"),r.selection.as_str(),escape_html(&r.text))
}
pub(crate) fn render_signature_error(m: &SignatureEditorModel<'_>) -> TrustedHtml {
    let section = if m.return_section == "composition" {
        "composition"
    } else {
        "identity"
    };
    let disabled = if m.editable { "" } else { " disabled" };
    let text_field = if m.operation == "selection" {
        String::new()
    } else {
        format!("<label for=\"submitted-signature-text\">Submitted signature text</label><textarea id=\"submitted-signature-text\" name=\"text\" rows=\"6\">\n{}</textarea>",escape_html(m.text))
    };
    let instruction = if m.editable {
        "Correct the retained values and save, or load the saved preferences."
    } else {
        "Your submitted values are retained below. Load saved preferences explicitly before another change."
    };
    let choices=format!("<option value=\"none\"{}>None</option><option value=\"default\"{}>Default signature</option>",if m.selection=="none" {" selected"}else{""},if m.selection=="default" {" selected"}else{""});
    let choices = if matches!(m.selection, "none" | "default") {
        choices
    } else {
        format!(
            "<option value=\"{}\" selected>Submitted selection unavailable</option>{choices}",
            escape_html(m.selection)
        )
    };
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell signature-error-page\" tabindex=\"-1\"><h1>Signature change not confirmed</h1><p class=\"notice\" role=\"alert\">{}</p><p>{instruction}</p><form method=\"post\" action=\"/settings/signature\">{}<fieldset{disabled}><label for=\"submitted-signature-selection\">Submitted selection</label><select id=\"submitted-signature-selection\" name=\"selection\">{choices}</select>{text_field}<button type=\"submit\">Save signature</button></fieldset></form><a class=\"button-link\" href=\"/settings?section={section}\">Load saved signature preferences</a></main>",crate::http_ui::app_header(m.account,m.csrf,"settings"),escape_html(m.notice),fields(m.csrf,m.revision,section,if m.operation=="selection"{"selection"}else{"definition"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_refusal_keeps_operation_and_stale_literal_text() {
        let m = SignatureEditorModel {
            account: "alice@example.test",
            csrf: "synthetic",
            revision: 3,
            selection: "default",
            text: "\n<script>literal</script>",
            operation: "definition",
            return_section: "identity",
            notice: "Stale",
            editable: false,
        };
        let html = render_signature_error(&m).as_str().to_owned();
        assert!(html.contains("<fieldset disabled>"));
        assert!(html.contains("name=\"signature_revision\" value=\"3\""));
        assert!(html.contains("rows=\"6\">\n\n&lt;script&gt;literal&lt;/script&gt;"));
        let selection = render_signature_error(&SignatureEditorModel {
            operation: "selection",
            editable: true,
            ..m
        })
        .as_str()
        .to_owned();
        assert!(!selection.contains("name=\"text\""));
        assert!(selection.contains("name=\"operation\" value=\"selection\""));
        assert!(!selection.contains("<fieldset disabled>"));
    }
}
