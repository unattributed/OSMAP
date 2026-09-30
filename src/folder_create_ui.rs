//! Native folder entry and explicit confirmation, separate from PAGE16's card.
use super::*;
pub(crate) fn render_folder_create(
    account: &str,
    csrf: &str,
    parent: &str,
    guid: &str,
    leaf: &str,
    stage: &str,
    notice: Option<&str>,
) -> TrustedHtml {
    let reload = format!("/settings?section=copies&folder={}", url_encode(parent));
    let mut html=format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>New subfolder</h1><p>Create one private subfolder. Existing mail and folders are kept.</p></div><section class=\"panel\"><h2>{}</h2>",app_header(account,csrf,"settings-copies"),if stage=="review"{"Review creation"}else{"Folder name"});
    if let Some(n) = notice {
        html.push_str(&format!(
            "<p class=\"notice\" role=\"alert\">{}</p>",
            escape_html(n)
        ));
    }
    html.push_str(&format!(
        "<p>Parent: <strong>{}</strong></p>",
        escape_html(parent)
    ));
    if stage == "refused" {
        html.push_str(&format!("<label>Requested name<input readonly value=\"{}\"></label><p>Creation controls are paused. Reload to verify the current folders.</p>",escape_html(leaf)));
    } else {
        html.push_str(&format!("<form method=\"post\" action=\"/settings/folders/create\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"parent\" value=\"{}\"><input type=\"hidden\" name=\"parent_guid\" value=\"{}\"><input type=\"hidden\" name=\"action\" value=\"{}\"><label for=\"folder-leaf\">Subfolder name</label><input id=\"folder-leaf\" name=\"leaf\" maxlength=\"128\" value=\"{}\" required{}><p>Use a single folder name without a dot or slash.</p>{}</form>",escape_html(csrf),escape_html(parent),escape_html(guid),if stage=="review"{"create"}else{"review"},escape_html(leaf),if stage=="review"{" readonly"}else{""},if stage=="review"{"<p>This creates the folder shown above. This page has not created it yet.</p><button name=\"confirm\" value=\"create\">Confirm create folder</button>"}else{"<button>Review creation</button>"}));
    }
    html.push_str(&format!(
        "<p><a href=\"{}\">Reload Copies &amp; Folders</a></p></section></main>",
        escape_html(&reload)
    ));
    TrustedHtml::from_template(html)
}
