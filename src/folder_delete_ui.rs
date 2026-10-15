//! Explicit review for removing one empty private container.
use super::*;
pub(crate) struct DeletePageModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub source: &'a str,
    pub source_guid: &'a str,
    pub parent_guid: &'a str,
    pub review: bool,
    pub pending: bool,
    pub notice: Option<&'a str>,
}
pub(crate) fn render_folder_delete(m: DeletePageModel<'_>) -> TrustedHtml {
    let mut s=format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><h1>Delete empty folder</h1><section class=\"panel\"><h2>{}</h2><p>Folder: <strong>{}</strong></p><p>This removes only an empty private leaf folder. Populated folders are refused by empty deletion. No message is moved or expunged by this operation.</p>",app_header(m.account,m.csrf,"settings-copies"),if m.review {"Review deletion"}else{"Empty folder only"},escape_html(m.source));
    if let Some(n) = m.notice {
        s.push_str(&format!("<p role=\"alert\">{}</p>", escape_html(n)));
    }
    if m.pending {
        s.push_str(
            "<p><a href=\"/settings/folders/delete/check\">Check original deletion result</a></p>",
        );
    } else if m.review {
        s.push_str(&format!("<form method=\"post\" action=\"/settings/folders/delete\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"source\" value=\"{}\"><input type=\"hidden\" name=\"source_guid\" value=\"{}\"><input type=\"hidden\" name=\"parent_guid\" value=\"{}\"><button name=\"confirm\" value=\"delete-empty\">Confirm delete empty folder</button></form>",escape_html(m.csrf),escape_html(m.source),escape_html(m.source_guid),escape_html(m.parent_guid)));
    }
    if !m.pending && !crate::folder_rename::protected_name(m.source) {
        s.push_str(&format!("<p><a href=\"/settings/folders/bin?source={}\">Review moving the complete folder to Bin</a> to preserve its messages and attachments for receipt-bound Restore. Bin retention remains separate.</p>", url_encode(m.source)));
    }
    s.push_str("<p><a href=\"/folders/deleted\">Deleted folders / Restore</a> · <a href=\"/settings?section=copies\">Inspect Copies &amp; Folders</a></p></section></main>");
    TrustedHtml::from_template(s)
}
