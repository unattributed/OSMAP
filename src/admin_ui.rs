//! Admin-only presentation. Authority and sessions are supplied by the service.
//! This module neither authenticates an identity nor reads private state.
use crate::admin_access::{MailboxPage, MailboxView};
use crate::html::TrustedHtml;
use crate::http::HttpResponse;
use crate::http_support::{escape_html, html_response, url_encode};
use crate::http_ui::presentation_label;

#[path = "admin_dashboard_ui.rs"]
mod dashboard;
pub(crate) use dashboard::{domain_page, overview_page, settings_page};
#[path = "admin_create_ui.rs"]
mod create;
pub(crate) use create::{create_failure_page, create_mailbox_page, mailbox_created_page};

fn admin_rail(current: &str) -> String {
    let mut links = String::new();
    for (key, label, href, icon) in [
        ("overview", "Overview", "/admin", "shield"),
        ("domains", "Domains", "/admin/domains", "folders"),
        (
            "mailboxes",
            "Mailboxes",
            "/admin/domains#domain-list",
            "inbox",
        ),
        ("settings", "Settings", "/admin/settings", "settings"),
    ] {
        links.push_str(&format!("<a class=\"rail-link\" href=\"{href}\" aria-label=\"{label}\" title=\"{label}\"{}>{}<span class=\"rail-label\">{label}</span></a>",if key==current {" aria-current=\"page\""} else {""},crate::http_ui::shell_icon(icon)));
    }
    format!(concat!(
        "<aside class=\"app-rail\" aria-label=\"Admin navigation\">",
        "<details class=\"rail-disclosure\"><summary title=\"Navigation labels\">{menu}<span class=\"sr-only rail-expand-label\">Expand navigation</span><span class=\"sr-only rail-collapse-label\">Collapse navigation</span></summary><p class=\"sr-only\">Navigation labels are expanded.</p></details>",
        "<nav class=\"rail-links\" aria-label=\"Primary navigation\">{links}</nav></aside>"
    ), menu = crate::http_ui::shell_icon("menu"), links=links)
}

fn admin_html_response(
    status: u16,
    reason: &'static str,
    title: &str,
    body: TrustedHtml,
) -> HttpResponse {
    let mut response = html_response(status, reason, title, body);
    // A no-referrer document makes normal browser form POST Origin opaque.
    // Preserve the value required by the private admin router; cross-origin
    // requests still receive no referrer.
    for (name, value) in &mut response.headers {
        if name.eq_ignore_ascii_case("Referrer-Policy") {
            *value = "same-origin".into();
        }
    }
    response
}

/// Display the combined password/TOTP form without retaining submitted values.
pub(crate) fn login_page(csrf: &str, denied: bool) -> HttpResponse {
    let body = crate::http_ui::render_admin_login_page(csrf, denied);
    admin_html_response(
        if denied { 401 } else { 200 },
        if denied { "Unauthorized" } else { "OK" },
        "OSMAP Admin — Sign in",
        body,
    )
}

/// Render only the current scope returned by an authenticated service response.
/// The service, not this renderer, owns identity, role and grant validation.
pub(crate) fn scope_page(
    login: &str,
    system: bool,
    domains: &[String],
    csrf: &str,
) -> HttpResponse {
    // The authority reader has a sixteen-grant limit. Refuse an incompatible
    // projection rather than silently presenting a partial administrator scope.
    if domains.len() > 16 {
        return error_page(503);
    }
    let scope = if system {
        "<p><strong>System administrator</strong></p><p>All managed domains.</p>".into()
    } else if domains.is_empty() {
        "<p><strong>Domain administrator</strong></p><p>No active domain grants were returned.</p>"
            .into()
    } else {
        let mut items = String::new();
        for domain in domains {
            items.push_str(&format!(
                "<li>{} <a href=\"/admin/mailboxes?domain={}\">View mailboxes</a></li>",
                escape_html(domain),
                escape_html(&url_encode(domain))
            ));
        }
        format!("<p><strong>Domain administrator</strong></p><ul aria-label=\"Assigned domains\">{items}</ul>")
    };
    let body = TrustedHtml::from_template(format!(
        concat!(
            "<a class=\"skip-link\" href=\"#main-content\">Skip to current scope</a>",
            "{rail}",
            "<header class=\"topbar\" aria-label=\"OSMAP Admin\"><a class=\"brand\" href=\"/admin\" style=\"flex-basis:auto;white-space:nowrap\"><span class=\"brand-mark\" aria-hidden=\"true\">OA</span>OSMAP Admin</a>",
            "<div class=\"status-row auth-status\"><span>Signed in as <strong>{login}</strong></span>",
            "<form method=\"post\" action=\"/admin/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><button type=\"submit\">{logout}</button></form></div></header>",
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Administration</h1><p>Your current administrator scope is shown below.</p></div>",
            "<section class=\"panel\" aria-labelledby=\"admin-scope-title\"><h2 id=\"admin-scope-title\">Current scope</h2>{scope}</section>",
            "<section class=\"panel\" aria-labelledby=\"admin-access-title\"><h2 id=\"admin-access-title\">Available access</h2><p><span class=\"badge\">Scoped administration</span></p>",
            "<p>Mailbox metadata is available for an authorized domain. Mailbox creation requires the configured writer and current authorization.</p>",
            "<form id=\"admin-domain-selection\" method=\"get\" action=\"/admin/mailboxes\"><label for=\"domain\">Hosted domain</label><input id=\"domain\" name=\"domain\" maxlength=\"255\" required><button type=\"submit\">View mailboxes</button></form></section></main>"
        ),
        login = escape_html(login),
        csrf = escape_html(csrf),
        scope = scope,
        rail = admin_rail("overview"),
        logout = presentation_label("Sign out", "logout"),
    ));
    admin_html_response(200, "OK", "OSMAP Admin — Current scope", body)
}

fn page_shell(
    login: &str,
    csrf: &str,
    title: &str,
    intro: &str,
    current: &str,
    content: String,
) -> HttpResponse {
    let page_class = if current == "settings" {
        " settings-page"
    } else {
        ""
    };
    let body = format!(concat!(
        "<a class=\"skip-link\" href=\"#main-content\">Skip to main content</a>",
        "{}",
        "<header class=\"topbar\" aria-label=\"OSMAP Admin\"><a class=\"brand\" href=\"/admin\" style=\"flex-basis:auto;white-space:nowrap\"><span class=\"brand-mark\" aria-hidden=\"true\">OA</span>OSMAP Admin</a><div class=\"status-row auth-status\"><span style=\"min-width:0;overflow-wrap:anywhere\">Signed in as <strong>{}</strong></span><form method=\"post\" action=\"/admin/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">{logout}</button></form></div></header>",
        "<main id=\"main-content\" class=\"page-shell{}\" tabindex=\"-1\"><div class=\"page-intro\"><h1>{}</h1><p>{}</p></div>{}</main>"
    ), admin_rail(current), escape_html(login), escape_html(csrf),page_class, escape_html(title),escape_html(intro), content, logout=presentation_label("Sign out","logout"));
    admin_html_response(
        200,
        "OK",
        &format!("OSMAP Admin — {title}"),
        TrustedHtml::from_template(body),
    )
}

fn inventory_shell(login: &str, csrf: &str, title: &str, content: String) -> HttpResponse {
    page_shell(login,csrf,title,"Read-only mailbox metadata. Mailbox authentication, delivery, usage and browser MFA have not been verified.","mailboxes",content)
}

fn list_url(domain: &str, query: &str, page: u8, sort: &str) -> String {
    format!(
        "/admin/mailboxes?domain={}&q={}&page={page}&sort={}",
        url_encode(domain),
        url_encode(query),
        url_encode(sort)
    )
}

pub(crate) fn mailboxes_page(page: &MailboxPage) -> HttpResponse {
    if !page.valid() {
        return error_page(503);
    }
    let mut content = format!(concat!(
        "<section class=\"panel\"><h2>Mailboxes for {}</h2>",
        "<form method=\"get\" action=\"/admin/mailboxes\"><input type=\"hidden\" name=\"domain\" value=\"{}\"><input type=\"hidden\" name=\"page\" value=\"1\">",
        "<label for=\"mailbox-filter\">Address contains</label><input id=\"mailbox-filter\" name=\"q\" maxlength=\"64\" value=\"{}\">",
        "<label for=\"mailbox-sort\">Sort by</label><select id=\"mailbox-sort\" name=\"sort\"><option value=\"address\"{}>Address A–Z</option><option value=\"quota\"{}>Configured quota, highest first</option></select><button type=\"submit\">{filter}</button></form>",
        "<p role=\"status\">{} matching mailboxes. Page {} of {}.</p>"
    ), escape_html(&page.domain), escape_html(&page.domain), escape_html(&page.query), if page.sort == "address" { " selected" } else { "" }, if page.sort == "quota" { " selected" } else { "" }, page.total, page.page, page.pages(),filter=presentation_label("Filter mailboxes","search"));
    content.push_str(&format!(
        "<p><a class=\"button-link\" href=\"/admin/mailboxes/new?domain={}\">{}</a></p>",
        escape_html(&url_encode(&page.domain)),
        presentation_label("Create mailbox", "add")
    ));
    if page.rows.is_empty() {
        content.push_str(if page.query.is_empty() {
            "<p>No mailboxes are configured for this domain.</p>"
        } else {
            "<p>No mailboxes match this filter.</p>"
        });
    } else {
        content.push_str("<div role=\"region\" aria-label=\"Mailbox inventory\" tabindex=\"0\" style=\"overflow-x:auto\"><table><thead><tr><th scope=\"col\">Mailbox address</th><th scope=\"col\">Account flag</th><th scope=\"col\">SMTP flag</th><th scope=\"col\">Configured quota (unit unverified)</th></tr></thead><tbody>");
        for row in &page.rows {
            content.push_str(&format!("<tr><th scope=\"row\"><a href=\"/admin/mailboxes/{}?domain={}\">{}</a></th><td>{}</td><td>{}</td><td>{}</td></tr>", row.id, escape_html(&url_encode(&page.domain)), escape_html(&row.username), enabled(row.active), enabled(row.smtp_active), row.quota));
        }
        content.push_str("</tbody></table></div>");
    }
    content.push_str("<nav aria-label=\"Mailbox pages\">");
    if page.page > 1 {
        content.push_str(&format!(
            "<a class=\"button-link\" href=\"{}\">{}</a> ",
            escape_html(&list_url(
                &page.domain,
                &page.query,
                page.page - 1,
                &page.sort
            )),
            presentation_label("Previous page", "previous")
        ));
    }
    if page.page < page.pages() {
        content.push_str(&format!(
            "<a class=\"button-link\" href=\"{}\">{}</a>",
            escape_html(&list_url(
                &page.domain,
                &page.query,
                page.page + 1,
                &page.sort
            )),
            presentation_label("Next page", "next")
        ));
    }
    content.push_str("</nav><p>Quota is the stored configured value; its unit, usage and enforcement have not been verified. Lists refresh between views; object links remain bound to mailbox identity.</p></section>");
    inventory_shell(&page.login, &page.csrf, "Mailboxes", content)
}

fn enabled(value: bool) -> &'static str {
    if value {
        "Enabled"
    } else {
        "Disabled"
    }
}

pub(crate) fn mailbox_page(
    login: &str,
    csrf: &str,
    domain: &str,
    row: &MailboxView,
) -> HttpResponse {
    let content = format!(concat!(
        "<section class=\"panel\"><h2>{}</h2><dl><dt>Hosted domain</dt><dd>{}</dd><dt>Account flag</dt><dd>{}</dd><dt>SMTP flag</dt><dd>{}</dd><dt>Configured quota (unit unverified)</dt><dd>{}</dd>",
        "<dt>Display name</dt><dd>Not available from this inventory</dd><dt>Native authentication</dt><dd>Not verified</dd><dt>Message delivery</dt><dd>Not verified</dd><dt>Storage usage</dt><dd>Unknown</dd><dt>Browser TOTP and recovery</dt><dd>Not observed</dd><dt>Last live verification</dt><dd>Not observed</dd></dl>",
        "<a class=\"button-link\" href=\"{}\">{back}</a></section>"
    ), escape_html(&row.username), escape_html(domain), enabled(row.active), enabled(row.smtp_active), row.quota, escape_html(&list_url(domain, "", 1, "address")),back=presentation_label("Back to mailboxes","back"));
    inventory_shell(login, csrf, "Mailbox details", content)
}

pub(crate) fn capacity_page() -> HttpResponse {
    admin_html_response(503, "Service Unavailable", "Mailbox inventory limit", TrustedHtml::from_template("<main class=\"standalone-notice\"><section class=\"panel\"><h1>Mailbox inventory limit</h1><p>This read-only view supports at most 100 mailboxes per domain. No partial list has been displayed.</p><a href=\"/admin\">Return to overview</a></section></main>".into()))
}

pub(crate) fn domain_capacity_page() -> HttpResponse {
    admin_html_response(503,"Service Unavailable","Domain inventory limit",TrustedHtml::from_template("<main class=\"standalone-notice\"><section class=\"panel\"><h1>Domain inventory limit</h1><p>This view supports at most 100 domains. No partial domain list has been displayed.</p><a href=\"/admin\">Return to overview</a></section></main>".into()))
}

/// Use fixed user-facing messages; native diagnostics never cross this API.
pub(crate) fn error_page(status: u16) -> HttpResponse {
    let (status, reason, title, message) = match status {
        400 => (
            400,
            "Bad Request",
            "Invalid request",
            "The request could not be accepted.",
        ),
        403 => (
            403,
            "Forbidden",
            "Request refused",
            "The request was refused. Return to sign in to continue.",
        ),
        404 => (
            404,
            "Not Found",
            "Page not found",
            "This administration page is unavailable.",
        ),
        405 => (
            405,
            "Method Not Allowed",
            "Method not allowed",
            "This administration page does not accept that request method.",
        ),
        _ => (
            503,
            "Service Unavailable",
            "Admin service unavailable",
            "Administration is temporarily unavailable. Try again later.",
        ),
    };
    admin_html_response(
        status,
        reason,
        title,
        TrustedHtml::from_template(format!(
            "<a class=\"skip-link\" href=\"#main-content\">Skip to message</a><main id=\"main-content\" class=\"standalone-notice\" tabindex=\"-1\"><section class=\"panel\"><h1>{title}</h1><p>{message}</p><nav aria-label=\"Admin navigation\"><a class=\"button-link\" href=\"/admin/login\">Return to admin sign-in</a></nav></section></main>"
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(response: &HttpResponse) -> &str {
        std::str::from_utf8(&response.body).expect("owned HTML is UTF-8")
    }

    fn assert_admin_response(response: &HttpResponse) {
        let html = body(response);
        assert_eq!(html.matches("<main ").count(), 1);
        assert!(html.contains("id=\"main-content\""));
        assert!(!html.contains("Return to mail"));
        assert!(!html.contains("href=\"/\""));
        for route in ["/mailbox?", "/settings", "/contacts", "/sessions"] {
            assert!(!html.contains(&format!("href=\"{route}")));
            assert!(!html.contains(&format!("action=\"{route}")));
        }
        assert!(!html.contains("<script"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("<iframe"));
        for header in [
            ("Cache-Control", "no-store"),
            (
                "Content-Security-Policy",
                crate::http_support::browser_csp(),
            ),
            ("Referrer-Policy", "same-origin"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ] {
            assert!(response
                .headers
                .iter()
                .any(|(name, value)| (name.as_str(), value.as_str()) == header));
        }
    }

    #[test]
    fn form_documents_preserve_same_origin_for_strict_browser_post_admission() {
        for response in [
            login_page("public-csrf", false),
            login_page("public-csrf", true),
            scope_page(
                "operator@example.test",
                false,
                &["example.test".into()],
                "public-csrf",
            ),
        ] {
            let policies = response
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("Referrer-Policy"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>();
            assert_eq!(policies, ["same-origin"]);
            assert!(body(&response).contains("method=\"post\""));
        }
    }

    #[test]
    fn sign_in_is_an_admin_only_password_totp_form_with_no_submitted_values() {
        let response = login_page("public-synthetic-csrf", false);
        assert_admin_response(&response);
        assert_eq!(response.status_code, 200);
        let html = body(&response);
        assert!(html.contains("method=\"post\" action=\"/admin/login\""));
        assert!(html.contains("<label for=\"login-username\">Administrator login</label>"));
        assert!(html.contains("<label for=\"login-password\">Password</label>"));
        assert!(html.contains("<label for=\"login-totp\">TOTP Code</label>"));
        assert!(html.contains("type=\"password\" name=\"password\""));
        assert!(html.contains("name=\"totp\""));
        assert!(html.contains("name=\"csrf\" value=\"public-synthetic-csrf\""));
        assert_eq!(html.matches("public-synthetic-csrf").count(), 1);
        assert!(!html.contains("name=\"login\" value="));
        assert!(!html.contains("name=\"password\" value="));
        assert!(!html.contains("name=\"totp\" value="));
        assert!(!html.contains("name=\"token\""));
        assert!(html.contains("class=\"login-decor login-decor-left\""));
        assert!(html.contains("class=\"login-brand-text\""));
        assert!(html.contains("Mailbox sign-in is separate."));
        assert!(!html.contains("href=\"/recover\""));
    }

    #[test]
    fn refused_sign_in_uses_a_fixed_generic_message_and_escapes_csrf() {
        let response = login_page("\"><script>alert('public')</script>", true);
        assert_admin_response(&response);
        assert_eq!(response.status_code, 401);
        let html = body(&response);
        assert!(html.contains("Sign-in could not be completed."));
        assert!(html.contains("role=\"alert\""));
        assert!(html.contains("&quot;&gt;&lt;script&gt;alert(&#39;public&#39;)&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("synthetic-admin-password"));
        assert!(!html.contains("osmap-admin1."));
    }

    #[test]
    fn domain_scope_is_escaped_and_logout_has_only_its_bound_csrf_field() {
        let domains = vec![
            "one.example.test".into(),
            "<img src=x onerror='public'>".into(),
        ];
        let response = scope_page(
            "<script>public</script>",
            false,
            &domains,
            "public-scope-csrf",
        );
        assert_admin_response(&response);
        assert_eq!(response.status_code, 200);
        let html = body(&response);
        assert!(html.contains("&lt;script&gt;public&lt;/script&gt;"));
        assert!(html.contains(
            "<li>one.example.test <a href=\"/admin/mailboxes?domain=one.example.test\">"
        ));
        assert!(html.contains("&lt;img src=x onerror=&#39;public&#39;&gt;"));
        assert!(!html.contains("<img"));
        assert!(html.contains("method=\"post\" action=\"/admin/logout\""));
        assert_eq!(html.matches("public-scope-csrf").count(), 1);
        let navigation = html
            .split_once("<nav class=\"rail-links\"")
            .unwrap()
            .1
            .split_once("</nav>")
            .unwrap()
            .0;
        assert_eq!(navigation.matches("aria-current=\"page\"").count(), 1);
        assert!(!html.contains("name=\"token\""));
        assert!(html.contains("Scoped administration"));
        assert!(html.contains(
            "Mailbox creation requires the configured writer and current authorization."
        ));
        assert!(html.contains("Mailbox metadata is available for an authorized domain."));
    }

    #[test]
    fn system_scope_does_not_invent_domain_inventory_and_empty_scope_is_explicit() {
        let response = scope_page(
            "operator@example.test",
            true,
            &["not-an-inventory.example.test".into()],
            "public-csrf",
        );
        assert_admin_response(&response);
        assert!(body(&response).contains("All managed domains."));
        assert!(!body(&response).contains("not-an-inventory.example.test"));
        let empty = scope_page("operator@example.test", false, &[], "public-csrf");
        assert_admin_response(&empty);
        assert!(body(&empty).contains("No active domain grants were returned."));
    }

    #[test]
    fn oversized_scope_refuses_instead_of_silently_showing_a_partial_list() {
        let domains = vec!["example.test".into(); 17];
        let response = scope_page("operator@example.test", false, &domains, "public-csrf");
        assert_admin_response(&response);
        assert_eq!(response.status_code, 503);
        assert!(!body(&response).contains("public-csrf"));
    }

    #[test]
    fn error_pages_stay_within_admin_routes_and_fixed_safe_statuses() {
        for status in [400, 403, 404, 405, 503] {
            let response = error_page(status);
            assert_admin_response(&response);
            assert_eq!(response.status_code, status);
            assert!(body(&response).contains("href=\"/admin/login\""));
        }
        let unknown = error_page(999);
        assert_eq!(unknown.status_code, 503);
        assert!(!body(&unknown).contains("<h1>999"));
    }
}
