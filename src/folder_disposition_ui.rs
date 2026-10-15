//! Reviewable container preservation and account-owned restore receipts.
use super::*;
pub(crate) fn render_folder_disposition(
    account: &str,
    csrf: &str,
    restoring: bool,
    request: Option<&crate::folder_rename::RenameFolderRequest>,
    stage: &str,
    notice: Option<&str>,
) -> TrustedHtml {
    let title = if restoring {
        "Restore folder"
    } else {
        "Move folder to Bin"
    };
    let mut html = format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>{title}</h1><p>Keep the complete email folder, including all messages and attachments. No message is copied, sent or permanently deleted.</p></div><section class=\"panel\">", app_header(account, csrf, "folders"));
    if let Some(notice) = notice {
        html.push_str(&format!("<p role=\"status\">{}</p>", escape_html(notice)));
    }
    if let Some(request) = request {
        html.push_str(&format!(
            "<dl><dt>Current folder</dt><dd>{}</dd><dt>Requested destination</dt><dd>{}</dd></dl>",
            escape_html(request.source()),
            escape_html(&request.destination())
        ));
        if matches!(stage, "entry" | "review") {
            if let Ok(json) = serde_json::to_string(request) {
                html.push_str(&format!("<form method=\"post\" action=\"/settings/folders/{}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><input type=\"hidden\" name=\"expected_request\" value=\"{}\"><button name=\"confirm\" value=\"{}\">{}</button></form>", if restoring { "restore" } else { "bin" }, escape_html(csrf), escape_html(&json), if stage == "review" { "apply" } else { "review" }, if stage == "review" { if restoring { "Confirm restore original folder" } else { "Confirm move complete folder to Bin" } } else if restoring { "Review restore" } else { "Review move to Bin" }));
            }
        }
    }
    html.push_str("<p>Only private folders without subfolders are supported. Restore needs the unchanged original parent and an unused original name. Bin retention may remove mail independently; no restoration window is promised.</p><p><a href=\"/folders/deleted\">Deleted folders / Restore</a> · <a href=\"/settings/folders/disposition/check\">Check original result without retry</a> · <a href=\"/folders\">Folders</a></p></section></main>");
    TrustedHtml::from_template(html)
}

pub(crate) fn render_deleted_folders(
    account: &str,
    csrf: &str,
    receipts: Option<&[crate::folder_disposition::Receipt]>,
) -> TrustedHtml {
    let mut rows = String::new();
    if let Some(receipts) = receipts {
        for receipt in receipts {
            rows.push_str(&format!("<li><h2>{}</h2><p>Stored folder: {}</p><p>State: {}</p>{}</li>", escape_html(&receipt.source), escape_html(&receipt.stored_name()), match receipt.state { crate::folder_disposition::State::BinReserved => "Move to Bin reserved; not dispatched", crate::folder_disposition::State::BinPending => "Move to Bin pending", crate::folder_disposition::State::Binned => "Moved to Bin", crate::folder_disposition::State::RestoreReserved => "Restore reserved; not dispatched", crate::folder_disposition::State::RestorePending => "Restore pending", crate::folder_disposition::State::Restored => "Restored; receipt cleanup pending", crate::folder_disposition::State::Cancelled => "No mutation; receipt cleanup pending" }, if receipt.state == crate::folder_disposition::State::Binned { format!("<a class=\"button-link\" href=\"/settings/folders/restore?id={}\">Review restore</a>", url_encode(&receipt.id)) } else { "<a href=\"/settings/folders/disposition/check\">Check original result</a>".into() }));
        }
        if rows.is_empty() {
            rows.push_str("<li>No retained deleted-folder receipts.</li>");
        }
    } else {
        rows.push_str("<li role=\"status\">Your deleted-folder receipts could not be loaded. No restore is available.</li>");
    }
    TrustedHtml::from_template(format!("{}<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Deleted folders / Restore</h1><p>Account-owned receipts retain the original name and Bin used at the time. Changing your Bin preference does not hide these receipts or move their contents.</p></div><section class=\"panel\"><ul>{rows}</ul><p>Current folder identities and the original parent are checked again before restore. No retention window is promised.</p><a href=\"/folders\">Back to Folders</a></section></main>", app_header(account, csrf, "folders")))
}
