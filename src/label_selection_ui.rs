//! Native confirmation for bounded, verified message selections.
use crate::{html::TrustedHtml, http_support::escape_html, labels::LabelRecord};
#[derive(Clone, Debug)]
pub(crate) struct LabelSelectionItem {
    pub field: String,
    pub value: String,
    pub subject: Option<String>,
}
pub(crate) struct LabelSelectionPageModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub mailbox: &'a str,
    pub selected: &'a [LabelSelectionItem],
    pub record: Option<&'a LabelRecord>,
    pub revision: u64,
    pub label_id: &'a str,
    pub action: &'a str,
    pub return_to: &'a str,
    pub notice: Option<&'a str>,
    pub editable: bool,
}
pub(crate) fn render_label_selection_page(m: &LabelSelectionPageModel<'_>) -> TrustedHtml {
    let mut h = crate::http_ui::app_header(m.account, m.csrf, "labels");
    h.push_str("<main id=\"main-content\" class=\"page-shell labels-page label-selection-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Labels for selected messages</h1><p>Review this selection, then confirm one label change for every message.</p></div>");
    if let Some(n) = m.notice {
        h.push_str(&format!(
            "<p class=\"notice\" role=\"status\">{}</p>",
            escape_html(n)
        ));
    }
    let back = if m.return_to.is_empty() {
        "/mailboxes"
    } else {
        m.return_to
    };
    h.push_str(&format!("<nav class=\"labels-navigation\" aria-label=\"Label navigation\"><a href=\"{}\">Back to messages</a><a href=\"/labels\">Manage labels</a></nav><section class=\"labels-panel\"><h2>{} selected messages</h2><p class=\"muted\">Mailbox: {}</p><ul class=\"label-selected-messages\">",escape_html(back),m.selected.len(),escape_html(m.mailbox)));
    let mut fields=format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"mailbox\" value=\"{}\">",escape_html(m.csrf),escape_html(m.mailbox));
    if !m.return_to.is_empty() {
        fields.push_str(&format!(
            "<input type=\"hidden\" name=\"return_to\" value=\"{}\">",
            escape_html(m.return_to)
        ));
    }
    for i in m.selected {
        fields.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape_html(&i.field),
            escape_html(&i.value)
        ));
        h.push_str(&format!(
            "<li><strong dir=\"auto\">{}</strong><span class=\"muted\">Message #{}</span></li>",
            escape_html(i.subject.as_deref().unwrap_or("Subject unavailable")),
            escape_html(i.field.strip_prefix("message_").unwrap_or(&i.field))
        ));
    }
    h.push_str("</ul></section><section class=\"labels-panel\"><h2>Label change</h2>");
    let mut options = "<option value=\"\">Choose a label</option>".to_string();
    let mut found = false;
    if let Some(r) = m.record {
        h.push_str(&format!("<p class=\"labels-usage\">{} of 32 labels · {} of 2,000 message assignments at review</p>",r.labels().len(),r.assigned_messages()));
        for l in r.labels() {
            let selected = l.id() == m.label_id;
            found |= selected;
            options.push_str(&format!(
                "<option value=\"{}\"{}>{}</option>",
                escape_html(l.id()),
                if selected { " selected" } else { "" },
                escape_html(l.name())
            ));
        }
    }
    if !m.label_id.is_empty() && !found {
        options.push_str(&format!(
            "<option value=\"{}\" selected>Submitted label unavailable</option>",
            escape_html(m.label_id)
        ));
    }
    let enabled = m.editable && m.record.is_some_and(|r| !r.labels().is_empty());
    if m.editable && !enabled {
        h.push_str("<p>No labels are available. Create a label in Manage labels, then reload this selection.</p>");
    }
    h.push_str(&format!("<form method=\"post\" action=\"/messages/labels/apply\">{fields}<input type=\"hidden\" name=\"revision\" value=\"{}\"><fieldset{}><label for=\"selection-label\">Existing label</label><select id=\"selection-label\" name=\"label_id\" required>{options}</select><label for=\"selection-action\">Change</label><select id=\"selection-action\" name=\"action\"><option value=\"attach\"{}>Attach to every selected message</option><option value=\"detach\"{}>Detach from every selected message</option></select><label class=\"label-confirm\"><input type=\"checkbox\" name=\"confirm\" value=\"apply\" required>Confirm this label change for all {} selected messages</label><button type=\"submit\">Apply label change</button></fieldset></form><p class=\"labels-policy muted\">Up to 10 messages per selection and 8 labels per message. The whole selection is saved together. Messages are not moved or deleted.</p></section>",m.revision,if enabled{""}else{" disabled"},if m.action!="detach"{" selected"}else{""},if m.action=="detach"{" selected"}else{""},m.selected.len()));
    h.push_str(&format!("<form class=\"label-selection-reload\" method=\"post\" action=\"/messages/labels/review\">{fields}<button type=\"submit\">Reload selection</button><p class=\"muted\">Reload checks current messages and saved labels. It does not apply a label change.</p></form></main>"));
    TrustedHtml::from_template(h)
}
