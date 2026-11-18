//! OSMAP welcome/settings composition for service-authorized admin projections.
use super::*;
use crate::admin_access::{DomainDetails, DomainOverview, SettingsPage};
use crate::http_ui::{presentation_label, shell_icon};

fn date(value: &Option<String>) -> String {
    value
        .as_ref()
        .map(|s| escape_html(s).to_string())
        .unwrap_or_else(|| "Not recorded".into())
}
fn domain_url(id: &str) -> String {
    format!("/admin/domains/{id}")
}
pub(crate) fn overview_page(page: &DomainOverview, domains: bool) -> HttpResponse {
    if !page.valid() {
        return error_page(503);
    }
    if !domains {
        let mut body=String::from("<section class=\"welcome-intro\" aria-label=\"Administration overview\"><div class=\"welcome-greeting\"><h2>Welcome to OSMAP Admin</h2><p>Manage mailbox configuration across your authorized domains.</p></div><div class=\"welcome-metrics\" aria-label=\"Managed resources and access\">");
        for (label, value, icon) in [
            ("Domains", page.domain_total.to_string(), "folders"),
            ("Mailbox addresses", page.mailbox_total.to_string(), "inbox"),
            (
                "Forwarding addresses",
                page.forward_total.to_string(),
                "sent",
            ),
            (
                "Administrator role",
                if page.system {
                    "System".into()
                } else {
                    "Domain".into()
                },
                "shield",
            ),
        ] {
            body.push_str(&format!("<div class=\"welcome-metric\"><span class=\"welcome-icon\">{}</span><span><strong>{value}</strong><span>{label}</span></span></div>",shell_icon(icon)));
        }
        body.push_str("</div></section><section class=\"welcome-panel\"><div class=\"welcome-panel-heading\"><h2>Administration shortcuts</h2></div><nav class=\"welcome-action-grid\" aria-label=\"Administration shortcuts\">");
        for (href, label, description, icon) in [
            (
                "/admin/domains",
                "Domains",
                "Search domains and inspect configured limits",
                "folders",
            ),
            (
                "/admin/mailboxes",
                "Mailboxes",
                "Open a domain's mailboxes or create a mailbox",
                "inbox",
            ),
            (
                "/admin/settings",
                "Settings",
                "Appearance and administrator information",
                "settings",
            ),
            (
                "/admin/account/scope",
                "Current access",
                "Review your administrator scope",
                "shield",
            ),
        ] {
            body.push_str(&format!(
                "<a href=\"{href}\">{}<strong>{label}</strong><span>{description}</span></a>",
                shell_icon(icon)
            ));
        }
        body.push_str("</nav><p class=\"welcome-note\">Counts cover configured addresses, including disabled records. Mailbox creation requires the configured writer and current authorization. Domain editing and existing mailbox editing are not available.</p></section>");
        return page_shell(
            &page.login,
            &page.csrf,
            "Overview",
            if page.system {
                "All managed domains."
            } else {
                "Your assigned domains."
            },
            "overview",
            body,
        );
    }
    let mut body = String::from("<section class=\"panel\" id=\"domain-list\"><div class=\"section-header\"><h2>Domain inventory</h2><span class=\"badge\">Domain editing unavailable</span></div>");
    let action = "/admin/domains";
    body.push_str(&format!("<form method=\"get\" action=\"{action}\" class=\"search-row\"><label class=\"sr-only\" for=\"domain-query\">Find a domain</label><input id=\"domain-query\" type=\"search\" name=\"q\" maxlength=\"64\" placeholder=\"Find a domain\" value=\"{}\"><button>{search}</button></form><p role=\"status\">{} matching domains of {}. Page {} of {}.</p>",escape_html(&page.query),page.total,page.domain_total,page.page,page.pages(),search=presentation_label("Search domains","search")));
    if page.rows.is_empty() {
        body.push_str(if page.query.is_empty() {
            "<p>No managed domains are available to this administrator.</p>"
        } else {
            "<p>No domains match this search.</p>"
        });
    } else {
        body.push_str("<div role=\"region\" aria-label=\"Domain inventory\" tabindex=\"0\" style=\"overflow-x:auto\"><table><thead><tr><th scope=\"col\">Domain</th><th scope=\"col\">Mailbox addresses</th><th scope=\"col\">Forwarding addresses</th><th scope=\"col\">Status</th><th scope=\"col\">Created</th><th scope=\"col\">Actions</th></tr></thead><tbody>");
        for row in &page.rows {
            body.push_str(&format!("<tr><th scope=\"row\"><a href=\"{}\">{}</a></th><td>{}</td><td>{}</td><td><span class=\"badge\">{}</span></td><td>{}</td><td><a class=\"button-link\" href=\"{}\">{open}</a> <a class=\"button-link\" href=\"/admin/mailboxes?domain={}\">{mail}</a></td></tr>",domain_url(&row.id),escape_html(&row.name),row.mailboxes,row.forwards,enabled(row.active),date(&row.created),domain_url(&row.id),escape_html(&url_encode(&row.name)),open=presentation_label("Open domain","folders"),mail=presentation_label("Mailboxes","inbox")));
        }
        body.push_str("</tbody></table></div>");
    }
    body.push_str("<nav aria-label=\"Domain pages\">");
    for (label, next) in [
        ("Previous page", page.page.checked_sub(1).filter(|n| *n > 0)),
        (
            "Next page",
            (page.page < page.pages()).then_some(page.page + 1),
        ),
    ] {
        if let Some(next) = next {
            body.push_str(&format!(
                "<a class=\"button-link\" href=\"{action}?q={}&amp;page={next}\">{}</a> ",
                escape_html(&url_encode(&page.query)),
                presentation_label(label, if next < page.page { "previous" } else { "next" })
            ));
        }
    }
    body.push_str("</nav><p>Counts cover configured records, including disabled addresses. Forwarding addresses are counted once per source; empty destinations and direct self-delivery records are excluded.</p><p>Domain creation and editing are not available. Open a domain's mailboxes to view addresses or create a mailbox with the configured writer.</p></section>");
    page_shell(
        &page.login,
        &page.csrf,
        "Domains",
        if page.system {
            "All managed domains."
        } else {
            "Your assigned domains."
        },
        "domains",
        body,
    )
}

pub(crate) fn mailbox_workspace_page(page: &DomainOverview) -> HttpResponse {
    if !page.valid() {
        return error_page(503);
    }
    let mut body=format!(concat!(
        "<section class=\"welcome-panel\"><div class=\"welcome-panel-heading\"><h2>Choose a hosted domain</h2></div><div class=\"content-pane\">",
        "<form method=\"get\" action=\"/admin/mailboxes\" class=\"search-row\"><label for=\"mailbox-domain-query\">Find a hosted domain</label><input id=\"mailbox-domain-query\" type=\"search\" name=\"q\" maxlength=\"64\" value=\"{}\"><button type=\"submit\">{search}</button></form>",
        "<p role=\"status\">{} matching domains of {}. Page {} of {}.</p>"
    ),escape_html(&page.query),page.total,page.domain_total,page.page,page.pages(),search=presentation_label("Search hosted domains","search"));
    if page.rows.is_empty() {
        body.push_str(if page.query.is_empty() {"<p>No hosted domains are available to this administrator.</p>"} else {"<p>No hosted domains match this search. Change the search to choose another domain.</p>"});
    } else {
        body.push_str("<form method=\"get\" action=\"/admin/mailboxes\" class=\"search-row\"><label for=\"mailbox-domain\">Hosted domain</label><select id=\"mailbox-domain\" name=\"domain\" required><option value=\"\" selected disabled>Choose a hosted domain</option>");
        for row in &page.rows {
            body.push_str(&format!(
                "<option value=\"{}\">{} — {} mailbox addresses{}</option>",
                escape_html(&row.name),
                escape_html(&row.name),
                row.mailboxes,
                if row.active { "" } else { " (domain disabled)" }
            ));
        }
        body.push_str("</select><button type=\"submit\">Open mailboxes</button></form>");
    }
    body.push_str("<nav aria-label=\"Hosted domain choices\">");
    for next in [
        page.page.checked_sub(1).filter(|n| *n > 0),
        (page.page < page.pages()).then_some(page.page + 1),
    ]
    .into_iter()
    .flatten()
    {
        body.push_str(&format!(
            "<a class=\"button-link\" href=\"/admin/mailboxes?q={}&amp;page={next}\">{}</a> ",
            escape_html(&url_encode(&page.query)),
            presentation_label(
                if next < page.page {
                    "Previous page"
                } else {
                    "Next page"
                },
                if next < page.page { "previous" } else { "next" }
            )
        ));
    }
    body.push_str("</nav><p>Open a domain to view its actual mailbox inventory and Create mailbox control. Creation requires the configured writer and current authorization; existing mailbox editing is not available.</p></div></section>");
    page_shell(
        &page.login,
        &page.csrf,
        "Mailboxes",
        "Choose an authorized hosted domain to work with its mailboxes.",
        "mailboxes",
        body,
    )
}
pub(crate) fn domain_page(page: &DomainDetails) -> HttpResponse {
    if !page.valid() {
        return error_page(503);
    }
    let sections = [
        ("#domain-overview".into(), "Overview".into(), "folders"),
        (
            format!("/admin/mailboxes?domain={}", url_encode(&page.domain.name)),
            format!("Mailboxes ({})", page.domain.mailboxes),
            "inbox",
        ),
        (
            "#domain-forwarding".into(),
            format!("Forwards ({})", page.domain.forwards),
            "sent",
        ),
        (
            "#domain-settings".into(),
            "Domain settings".into(),
            "settings",
        ),
    ];
    let mut content = String::from("<nav aria-label=\"Domain sections\">");
    for (href, label, icon) in sections {
        content.push_str(&format!(
            "<a class=\"button-link\" href=\"{}\">{}</a> ",
            escape_html(&href),
            presentation_label(&label, icon)
        ));
    }
    content.push_str("</nav>");
    content.push_str(&format!("<section class=\"panel\" id=\"domain-overview\"><div class=\"section-header\"><h2>Domain information</h2><span class=\"badge\">{}</span></div><dl><dt>Domain</dt><dd>{}</dd><dt>Description</dt><dd>{}</dd><dt>Created</dt><dd>{}</dd><dt>Last modified</dt><dd>{}</dd><dt>Mailbox addresses</dt><dd>{}</dd><dt>Forwarding addresses</dt><dd>{}</dd></dl></section>",enabled(page.domain.active),escape_html(&page.domain.name),if page.description.is_empty(){"Not set".into()}else{escape_html(&page.description).to_string()},date(&page.domain.created),date(&page.modified),page.domain.mailboxes,page.domain.forwards));
    content.push_str(&format!("<section class=\"panel\" id=\"domain-settings\"><h2>Domain settings</h2><dl><dt>Configured mailbox limit</dt><dd>{}</dd><dt>Configured alias limit</dt><dd>{}</dd><dt>Configured mailbox quota limit</dt><dd>{}</dd><dt>Configured domain quota</dt><dd>{}</dd><dt>Backup MX flag</dt><dd>{}</dd><dt>Delivery transport</dt><dd>{}</dd></dl><p>Quota units and native enforcement have not been verified. These are stored configuration values.</p><p>Domain editing is not available. Use Mailboxes to view addresses or create a mailbox with the configured writer.</p></section>",page.mailbox_limit,page.alias_limit,page.mailbox_quota,page.domain_quota,enabled(page.backup_mx),escape_html(&page.transport)));
    content.push_str(&format!("<section class=\"panel\" id=\"domain-forwarding\"><h2>Forwarding</h2><p>{} configured forwarding addresses. Self-delivery mappings are excluded.</p><p>Forward editing will be available with the forwarding-management backend.</p></section><a class=\"button-link\" href=\"/admin/domains\">{}</a>",page.domain.forwards,presentation_label("Back to domains","back")));
    page_shell(
        &page.login,
        &page.csrf,
        &page.domain.name,
        "Domain information and configured limits.",
        "domains",
        content,
    )
}
pub(crate) fn settings_page(page: &SettingsPage, section: &str, saved: bool) -> HttpResponse {
    if !page.valid() {
        return error_page(503);
    }
    if section == "system" && !page.system {
        return error_page(404);
    }
    let mut body=String::from("<div class=\"settings-layout\"><nav class=\"settings-navigation\" aria-label=\"Settings sections\"><ul>");
    for (key, label, icon) in [
        ("appearance", "Appearance", "eye"),
        ("account", "Account & Security", "shield"),
        ("system", "Installation information", "info"),
    ] {
        if key == "system" && !page.system {
            continue;
        }
        body.push_str(&format!(
            "<li><a href=\"/admin/settings?section={key}\" aria-label=\"{label}\"{}>{}</a></li>",
            if key == section {
                " aria-current=\"page\""
            } else {
                ""
            },
            presentation_label(label, icon)
        ));
    }
    body.push_str("</ul></nav><section class=\"settings-content\">");
    match section {
        "appearance"=>{
            body.push_str("<h2>Appearance</h2><p>Personalize your administration pages. These preferences belong to your administrator account.</p>");
            if saved {body.push_str("<div class=\"notice notice-success\" role=\"status\">Appearance saved.</div>");}
            body.push_str(&format!("<form class=\"settings-display-form\" method=\"post\" action=\"/admin/settings/appearance\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><fieldset class=\"settings-themes\"><legend class=\"sr-only\">Theme</legend>",escape_html(&page.csrf)));
            for (value,label,icon) in [("light","Light","☼"),("dark","Dark","☾"),("system","System","◫")] {
                body.push_str(&format!("<label class=\"settings-theme settings-theme-{value}\"><input class=\"sr-only\" type=\"radio\" name=\"theme\" value=\"{value}\" aria-label=\"{label}\"{}><span class=\"settings-theme-icon\" aria-hidden=\"true\">{icon}</span><strong>{label}</strong><span class=\"settings-theme-selected\">Selected</span></label>",if page.preferences.theme==value {" checked"}else{""}));
            }
            body.push_str("</fieldset><div class=\"settings-display-fields\">");
            for (name,label,selected,options) in [("density","Density",page.preferences.density.as_str(),&[("comfortable","Comfortable"),("compact","Compact")][..]),("font_size","Font size",page.preferences.font_size.as_str(),&[("small","Small"),("medium","Medium"),("large","Large")][..]),("presentation_style","Presentation style",page.preferences.presentation_style.as_str(),&[("text_labels","Text labels"),("icons","Icons")][..])] {
                body.push_str(&format!("<div class=\"settings-field\"><label for=\"admin-{name}\">{label}</label><select id=\"admin-{name}\" name=\"{name}\">"));
                for (value,text) in options {body.push_str(&format!("<option value=\"{value}\"{}>{text}</option>",if *value==selected {" selected"}else{""}));}
                body.push_str("</select></div>");
            }
            body.push_str("<p class=\"settings-field-help\">Icons use compact desktop menus with names on hover or keyboard focus. Touch devices keep visible labels.</p></div><div class=\"settings-save-row\"><button class=\"primary-button presentation-text\">Save changes</button></div></form>");
        },
        "account"=>body.push_str(&format!("<h2>Account &amp; Security</h2><section class=\"panel\"><h3>Administrator account</h3><dl><dt>Login</dt><dd>{}</dd><dt>Role</dt><dd>{}</dd><dt>Sign-in policy</dt><dd>Administrator password and TOTP are required.</dd></dl><p>Administrator credentials and preferences are separate from mailbox sign-in.</p><a class=\"button-link\" href=\"/admin/account/scope\">View current domain access</a><p>Password changes, authenticator management and session administration will appear here when those lifecycle controls are enabled.</p></section>",escape_html(&page.login),if page.system {"System administrator"}else{"Domain administrator"})),
        "system"=>body.push_str("<h2>Installation information</h2><section class=\"panel\"><dl><dt>Domain inventory</dt><dd>Available to authorized administrators</dd><dt>Domain editing</dt><dd>Not available</dd><dt>Mailbox inventory</dt><dd>Available for authorized hosted domains</dd><dt>Mailbox creation</dt><dd>Requires the configured writer and current authorization</dd><dt>Existing mailbox editing</dt><dd>Not available</dd><dt>Application</dt><dd>OSMAP Admin</dd></dl><p>Domains and address counts come from the selected account directory. Open the mailbox workspace to view addresses and the scoped creation form.</p><a class=\"button-link\" href=\"/admin/mailboxes\">Open mailbox workspace</a><p>This information page does not change mail-service configuration.</p></section>"),
        _=>return error_page(400),
    }
    body.push_str("</section></div>");
    page_shell(
        &page.login,
        &page.csrf,
        "Settings",
        "Manage your administrator preferences and account information.",
        "settings",
        body,
    )
}
