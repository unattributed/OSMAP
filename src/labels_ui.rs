//! Native account label management and verified-message assignments.
use crate::{
    html::TrustedHtml,
    http_support::{escape_html, url_encode},
    labels::LabelRecord,
};
#[derive(Clone, Debug)]
pub(crate) struct LabelMessageContext {
    pub mailbox: String,
    pub uid: u64,
    pub mailbox_guid: String,
    pub message_guid: String,
    pub attached_label_ids: Vec<String>,
}
pub(crate) struct LabelPageModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub record: Option<&'a LabelRecord>,
    pub message: Option<&'a LabelMessageContext>,
    pub entered_name: &'a str,
    pub submitted_label_id: &'a str,
    pub submitted_action: &'a str,
    pub notice: Option<&'a str>,
    pub editable: bool,
}
fn context_query(c: &LabelMessageContext) -> String {
    format!(
        "mailbox={}&uid={}&mailbox_guid={}&message_guid={}",
        url_encode(&c.mailbox),
        c.uid,
        url_encode(&c.mailbox_guid),
        url_encode(&c.message_guid)
    )
}
pub(crate) fn render_labels_page(m: &LabelPageModel<'_>) -> TrustedHtml {
    let mut html = crate::http_ui::app_header(m.account, m.csrf, "labels");
    html.push_str("<main id=\"main-content\" class=\"page-shell labels-page\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Labels</h1><p>Organize your messages with private account labels.</p></div>");
    if let Some(n) = m.notice {
        html.push_str(&format!(
            "<p class=\"notice\" role=\"status\">{}</p>",
            escape_html(n)
        ));
    }
    let reload = m
        .message
        .map(|c| format!("/labels?{}", context_query(c)))
        .unwrap_or_else(|| "/labels".into());
    html.push_str(&format!("<nav class=\"labels-navigation\" aria-label=\"Label navigation\"><a href=\"{}\">Reload labels</a><a href=\"/mailboxes\">All mailboxes</a></nav>",escape_html(&reload)));
    if let Some(c) = m.message {
        let assignment_status = if m.editable {
            format!("{} of 8 labels assigned", c.attached_label_ids.len())
        } else {
            "Assignment status unavailable".into()
        };
        html.push_str(&format!("<section class=\"labels-message-context\"><div><h2>Labels for this message</h2><p>{} · Message #{} · {}</p></div><a class=\"button-link secondary\" href=\"/message?{}\">Back to message</a></section>",escape_html(&c.mailbox),c.uid,assignment_status,escape_html(&context_query(c))));
    }
    if let Some(r) = m.record {
        html.push_str(&format!(
            "<p class=\"labels-usage muted\">{} of 32 labels · {} of 2,000 message assignments</p>",
            r.labels().len(),
            r.assigned_messages()
        ));
        let context=m.message.map(|v|format!("<input type=\"hidden\" name=\"mailbox\" value=\"{}\"><input type=\"hidden\" name=\"uid\" value=\"{}\"><input type=\"hidden\" name=\"mailbox_guid\" value=\"{}\"><input type=\"hidden\" name=\"message_guid\" value=\"{}\">",escape_html(&v.mailbox),v.uid,escape_html(&v.mailbox_guid),escape_html(&v.message_guid))).unwrap_or_default();
        let start = |action: &str, id: &str| {
            format!("<form method=\"post\" action=\"/labels/change\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"revision\" value=\"{}\"><input type=\"hidden\" name=\"action\" value=\"{}\"><input type=\"hidden\" name=\"label_id\" value=\"{}\">{}<fieldset{}>",escape_html(m.csrf),r.revision(),action,escape_html(id),context,if m.editable {""}else{" disabled"})
        };
        html.push_str(&format!("<section class=\"labels-create labels-panel\"><h2>Create a label</h2>{}<label for=\"new-label-name\">Label name<input id=\"new-label-name\" name=\"name\" maxlength=\"32\" value=\"{}\" required></label><button type=\"submit\">Create label</button></fieldset></form><p class=\"muted\">Use up to 32 characters. Labels belong only to this account.</p></section><section class=\"labels-panel labels-existing\"><h2>Your labels</h2>",start("create",""),escape_html(if m.submitted_action == "rename" { "" } else { m.entered_name })));
        if r.labels().is_empty() {
            html.push_str(
                "<p class=\"labels-empty\">No labels yet. Create one above to begin.</p>",
            );
        }
        for label in r.labels() {
            let submitted = m.submitted_action == "rename" && m.submitted_label_id == label.id();
            let rename_name = if submitted {
                m.entered_name
            } else {
                label.name()
            };
            let editor_open = if submitted && !m.editable {
                " open"
            } else {
                ""
            };
            html.push_str(&format!("<article class=\"label-item\"><h3 dir=\"auto\">{}</h3><div class=\"label-item-controls\">",escape_html(label.name())));
            if let Some(c) = m.message {
                let attached = c.attached_label_ids.iter().any(|id| id == label.id());
                html.push_str(&format!("<span class=\"label-assignment-state\">{}</span>{}<button type=\"submit\">{}</button></fieldset></form>",if !m.editable {"Assignment unknown"} else if attached{"Assigned"}else{"Not assigned"},start(if attached{"detach"}else{"attach"},label.id()),if attached{"Detach label"}else{"Attach label"}));
            }
            html.push_str(&format!("<details class=\"label-editor\"{editor_open}><summary>Rename</summary>{}<label>New label name<input name=\"name\" maxlength=\"32\" value=\"{}\" required></label><button type=\"submit\">Save name</button></fieldset></form></details><details class=\"label-editor label-delete\"><summary>Delete</summary><p>Deletes this label and its assignments. Messages are kept.</p>{}<label class=\"label-confirm\"><input type=\"checkbox\" name=\"confirm\" value=\"delete\" required>Confirm delete label and its assignments</label><button type=\"submit\" class=\"danger\">Delete label</button></fieldset></form></details></div></article>",start("rename",label.id()),escape_html(rename_name),start("delete",label.id())));
        }
        html.push_str("</section>");
    } else {
        html.push_str("<section class=\"labels-panel\"><h2>Labels unavailable</h2><p>The saved label record could not be confirmed. No changes can be made here.</p></section>");
    }
    html.push_str("<p class=\"labels-policy muted\">Labels are private app metadata, separate from mailbox names. Up to eight labels can be assigned to each verified message.</p></main>");
    TrustedHtml::from_template(html)
}
