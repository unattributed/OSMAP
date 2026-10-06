//! Native entry and confirmation; an ambiguous result offers only inspection.
use super::*;
pub(crate) struct RenamePageModel<'a> {
    pub account: &'a str,
    pub csrf: &'a str,
    pub source: &'a str,
    pub source_guid: &'a str,
    pub parent_guid: &'a str,
    pub leaf: &'a str,
    pub stage: &'a str,
    pub notice: Option<&'a str>,
}
pub(crate) fn render_folder_rename(model: RenamePageModel<'_>) -> TrustedHtml {
    let RenamePageModel {
        account,
        csrf,
        source,
        source_guid,
        parent_guid,
        leaf,
        stage,
        notice,
    } = model;
    let mut html = format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Rename folder</h1><p>Rename a private user folder in its current parent. System folders and saved mail destinations are protected.</p></div><section class=\"panel\"><h2>{}</h2><p>Current folder: <strong>{}</strong></p>", app_header(account, csrf, "settings-copies"), if stage == "review" { "Review rename" } else { "New name" }, escape_html(source));
    if let Some(notice) = notice {
        html.push_str(&format!(
            "<p class=\"notice\" role=\"alert\">{}</p>",
            escape_html(notice)
        ));
    }
    if matches!(stage, "entry" | "review") {
        html.push_str(&format!("<form method=\"post\" action=\"/settings/folders/rename\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"source\" value=\"{}\"><input type=\"hidden\" name=\"source_guid\" value=\"{}\"><input type=\"hidden\" name=\"parent_guid\" value=\"{}\"><input type=\"hidden\" name=\"action\" value=\"{}\"><label for=\"rename-leaf\">Folder name</label><input id=\"rename-leaf\" name=\"leaf\" maxlength=\"128\" value=\"{}\" required{}><p>Use a single name without a dot or slash. Contents stay with the renamed folder, including messages that arrive during the rename. This does not open or delete message bodies.</p>{}</form>", escape_html(csrf), escape_html(source), escape_html(source_guid), escape_html(parent_guid), if stage == "review" { "rename" } else { "review" }, escape_html(leaf), if stage == "review" { " readonly" } else { "" }, if stage == "review" { "<button name=\"confirm\" value=\"rename\">Confirm rename folder</button>" } else { "<button>Review rename</button>" }));
    }
    if stage == "pending" {
        html.push_str("<p><a href=\"/settings/folders/rename/check\">Check rename result</a></p>");
    }
    html.push_str("<p><a href=\"/settings?section=copies\">Reload Copies &amp; Folders</a></p></section></main>");
    TrustedHtml::from_template(html)
}
