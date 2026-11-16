//! Admin-only presentation. Authority and sessions are supplied by the service.
//! This module neither authenticates an identity nor reads private state.
use crate::html::TrustedHtml;
use crate::http::HttpResponse;
use crate::http_support::{escape_html, html_response};

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
    let notice = if denied {
        "<div class=\"notice notice-error\" role=\"alert\"><strong>Sign-in could not be completed.</strong> Check your details or try again later.</div>"
    } else {
        ""
    };
    let body = TrustedHtml::from_template(format!(
        concat!(
            "<a class=\"skip-link\" href=\"#main-content\">Skip to sign-in</a>",
            "<main id=\"main-content\" class=\"login-page\" tabindex=\"-1\" aria-labelledby=\"admin-login-title\">",
            "<section class=\"login-card\"><div class=\"login-brand\"><span class=\"brand-mark\" aria-hidden=\"true\">OA</span>",
            "<div><p class=\"muted\">Private administration</p><h1 id=\"admin-login-title\" class=\"login-title\">Sign in to OSMAP Admin</h1></div></div>",
            "<p>Use your administrator password and a current authenticator code.</p>{notice}",
            "<form method=\"post\" action=\"/admin/login\" class=\"login-form\">",
            "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">",
            "<label for=\"admin-login\">Login</label><input id=\"admin-login\" type=\"text\" name=\"login\" autocomplete=\"username\" maxlength=\"96\" autocapitalize=\"none\" spellcheck=\"false\" required>",
            "<label for=\"admin-password\">Password</label><input id=\"admin-password\" type=\"password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"72\" required>",
            "<label for=\"admin-totp\">TOTP code</label><input id=\"admin-totp\" type=\"text\" name=\"totp\" autocomplete=\"one-time-code\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" minlength=\"6\" maxlength=\"6\" aria-describedby=\"admin-totp-help\" required>",
            "<p id=\"admin-totp-help\" class=\"muted\">Enter the six-digit code from your authenticator.</p>",
            "<button type=\"submit\" class=\"primary-button\">Sign in</button></form></section></main>"
        ),
        csrf = escape_html(csrf),
        notice = notice,
    ));
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
            items.push_str(&format!("<li>{}</li>", escape_html(domain)));
        }
        format!("<p><strong>Domain administrator</strong></p><ul aria-label=\"Assigned domains\">{items}</ul>")
    };
    let body = TrustedHtml::from_template(format!(
        concat!(
            "<a class=\"skip-link\" href=\"#main-content\">Skip to current scope</a>",
            "<aside class=\"app-rail\" aria-label=\"Admin navigation\"><nav class=\"rail-links\" aria-label=\"Primary navigation\">",
            "<a class=\"rail-link selected\" href=\"/admin\" aria-current=\"page\"><span class=\"presentation-icon presentation-icon-shield\" aria-hidden=\"true\"><i></i></span><span class=\"presentation-label\">Overview</span></a></nav></aside>",
            "<header class=\"topbar\" aria-label=\"OSMAP Admin\"><a class=\"brand\" href=\"/admin\"><span class=\"brand-mark\" aria-hidden=\"true\">OA</span>OSMAP Admin</a>",
            "<div class=\"status-row auth-status\"><span>Signed in as <strong>{login}</strong></span>",
            "<form method=\"post\" action=\"/admin/logout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><button type=\"submit\">Sign out</button></form></div></header>",
            "<main id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"><div class=\"page-intro\"><h1>Administration</h1><p>Your current administrator scope is shown below.</p></div>",
            "<section class=\"panel\" aria-labelledby=\"admin-scope-title\"><h2 id=\"admin-scope-title\">Current scope</h2>{scope}</section>",
            "<section class=\"panel\" aria-labelledby=\"admin-access-title\"><h2 id=\"admin-access-title\">Available access</h2><p><span class=\"badge\">Read-only</span></p>",
            "<p>Account changes are unavailable. Mailbox administration is not available yet.</p></section></main>"
        ),
        login = escape_html(login),
        csrf = escape_html(csrf),
        scope = scope,
    ));
    admin_html_response(200, "OK", "OSMAP Admin — Current scope", body)
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
        for route in [
            "/mailboxes",
            "/mailbox?",
            "/settings",
            "/contacts",
            "/sessions",
        ] {
            assert!(!html.contains(route));
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
        assert!(html.contains("<label for=\"admin-login\">Login</label>"));
        assert!(html.contains("<label for=\"admin-password\">Password</label>"));
        assert!(html.contains("<label for=\"admin-totp\">TOTP code</label>"));
        assert!(html.contains("type=\"password\" name=\"password\""));
        assert!(html.contains("name=\"totp\""));
        assert!(html.contains("name=\"csrf\" value=\"public-synthetic-csrf\""));
        assert_eq!(html.matches("public-synthetic-csrf").count(), 1);
        assert!(!html.contains("name=\"login\" value="));
        assert!(!html.contains("name=\"password\" value="));
        assert!(!html.contains("name=\"totp\" value="));
        assert!(!html.contains("name=\"token\""));
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
        assert!(html.contains("<li>one.example.test</li>"));
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
        assert!(html.contains("Read-only"));
        assert!(html.contains("Mailbox administration is not available yet."));
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
