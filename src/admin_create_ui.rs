//! Scoped mailbox creation presentation. Proof and writer authority stay in the service.
use crate::admin_access::{CreateFailure, CreatePage, CreateReceipt};
use crate::html::TrustedHtml;
use crate::http::HttpResponse;
use crate::http_support::{escape_html, url_encode};

pub(crate) fn create_mailbox_page(page: &CreatePage) -> HttpResponse {
    if !page.valid() {
        return super::error_page(503);
    }
    let credentials = if page.setup_enabled {
        concat!(
            "<p><label for=\"create-setup-contact\">Approved external setup email</label><input id=\"create-setup-contact\" type=\"email\" name=\"setup_contact\" autocomplete=\"off\" maxlength=\"254\" aria-describedby=\"create-setup-help\" required></p>",
            "<p id=\"create-setup-help\" class=\"muted\">Use an independent address already verified with the intended user. A single-use invitation lets that user choose their own password and register their authenticator.</p>",
        )
    } else {
        concat!(
            "<p><label for=\"create-password\">Mailbox password</label><input id=\"create-password\" type=\"password\" name=\"password\" autocomplete=\"new-password\" minlength=\"15\" maxlength=\"256\" aria-describedby=\"create-password-help\" required></p>",
            "<p id=\"create-password-help\" class=\"muted\">Use 15–128 characters, at most 512 UTF-8 bytes. The service checks this limit when you submit. Passwords are never displayed on the result page.</p>",
            "<p><label for=\"create-confirmation\">Confirm mailbox password</label><input id=\"create-confirmation\" type=\"password\" name=\"confirmation\" autocomplete=\"new-password\" minlength=\"15\" maxlength=\"256\" required></p>",
        )
    };
    let setup_notice = if page.setup_enabled {
        "The account remains pending until the user completes password and authenticator setup. You will not receive their password or authenticator seed."
    } else {
        "Mailbox browser MFA enrollment is pending. Native mailbox authentication and message delivery require separate verification after configuration."
    };
    let content = format!(concat!(
        "<section class=\"panel\"><h2>Mailbox details</h2>",
        "<form method=\"post\" action=\"/admin/mailboxes/new\">",
        "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">",
        "<input type=\"hidden\" name=\"request_id\" value=\"{request_id}\">",
        "<input type=\"hidden\" name=\"revision\" value=\"{revision}\">",
        "<p><label for=\"create-domain\">Hosted domain</label><input id=\"create-domain\" name=\"domain\" value=\"{domain}\" readonly required></p>",
        "<p><label for=\"create-local-part\">Mailbox name before @</label><input id=\"create-local-part\" name=\"local_part\" autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" maxlength=\"64\" required><span class=\"muted\">@{domain}</span></p>",
        "<p><label for=\"create-display-name\">Display name</label><input id=\"create-display-name\" name=\"display_name\" maxlength=\"255\"></p>",
        "<p><label for=\"create-quota\">Configured quota (MiB)</label><input id=\"create-quota\" type=\"number\" name=\"quota_mib\" min=\"1\" max=\"1048576\" step=\"1\" aria-describedby=\"create-quota-help\" required></p>",
        "<p id=\"create-quota-help\" class=\"muted\">Enter a positive limit in MiB (1 MiB = 1,048,576 bytes). The domain's remaining capacity is checked when you submit.</p>",
        "{credentials}",
        "<p><label for=\"create-totp\">Current administrator TOTP code</label><input id=\"create-totp\" type=\"text\" name=\"totp\" autocomplete=\"one-time-code\" inputmode=\"numeric\" pattern=\"[0-9]{{6}}\" minlength=\"6\" maxlength=\"6\" required></p>",
        "<p>{setup_notice}</p>",
        "<div class=\"toolbar\"><button type=\"submit\" class=\"primary-button\">Create mailbox</button> <a class=\"button-link\" href=\"/admin/mailboxes?domain={domain_url}\">Cancel</a></div></form></section>"
    ), csrf=escape_html(&page.csrf), request_id=escape_html(&page.request_id), revision=page.revision,
       domain=escape_html(&page.domain), domain_url=escape_html(&url_encode(&page.domain)), credentials=credentials, setup_notice=setup_notice);
    super::page_shell(
        &page.login,
        &page.csrf,
        "Create mailbox",
        "Configure one mailbox in the selected hosted domain.",
        "mailboxes",
        content,
    )
}

pub(crate) fn mailbox_created_page(receipt: &CreateReceipt) -> HttpResponse {
    if !receipt.valid() {
        return super::error_page(503);
    }
    let content = format!(concat!(
        "<section class=\"panel\" role=\"status\"><h2>Mailbox configured</h2>",
        "<dl><dt>Mailbox address</dt><dd>{username}</dd><dt>Hosted domain</dt><dd>{domain}</dd>",
        "<dt>Configured quota</dt><dd>{quota_mib} MiB ({quota} bytes)</dd>",
        "<dt>Operation ID</dt><dd style=\"overflow-wrap:anywhere\">{request_id}</dd></dl>",
        "<p>{setup_status}</p>",
        "<p>Keep this operation ID when checking the result. Refreshing this submission uses the same operation ID.</p>",
        "<a class=\"button-link\" href=\"/admin/mailboxes?domain={domain_url}\">Back to mailboxes</a></section>"
    ), username=escape_html(&receipt.username), domain=escape_html(&receipt.domain), quota_mib=receipt.quota / 1_048_576,
       quota=receipt.quota, request_id=escape_html(&receipt.request_id), domain_url=escape_html(&url_encode(&receipt.domain)),
       setup_status=if receipt.setup_pending { "The account is pending user setup. The mail service accepted the invitation for the approved external contact; recipient delivery is not yet confirmed. The user must choose a password and prove their own authenticator before sign-in is enabled." } else { "Native authentication and message delivery have not yet been verified. Mailbox browser MFA enrollment is pending." });
    let mut response = super::page_shell(
        &receipt.login,
        &receipt.csrf,
        "Mailbox configured",
        "The mailbox configuration was recorded by the administration service.",
        "mailboxes",
        content,
    );
    response.status_code = 201;
    response.reason_phrase = "Created";
    response
}

pub(crate) fn create_failure_page(
    failure: CreateFailure,
    domain: &str,
    request_id: Option<&str>,
) -> HttpResponse {
    let (status, reason, message) = match failure {
        CreateFailure::WriterDisabled => (503, "Service Unavailable", "Mailbox creation is unavailable because the administration writer is disabled."),
        CreateFailure::Invalid => (400, "Bad Request", "The mailbox details were refused. Open a fresh form and check the entered values."),
        CreateFailure::Denied => (403, "Forbidden", "This mailbox creation is not authorized for your current administrator scope."),
        CreateFailure::Missing => (404, "Not Found", "The selected hosted domain is unavailable."),
        CreateFailure::Conflict => (409, "Conflict", "The mailbox address or operation is already in use. Check the mailbox list before opening a fresh form."),
        CreateFailure::Stale => (409, "Conflict", "The domain changed after this form was opened. Review its current configuration before opening a fresh form."),
        CreateFailure::Limit => (409, "Conflict", "The mailbox or quota limit for this domain would be exceeded."),
        CreateFailure::StepUp => (403, "Forbidden", "Administrator verification was refused. Open a fresh form and use a current authenticator code."),
        CreateFailure::Unconfirmed => (503, "Service Unavailable", "The mailbox creation result is unconfirmed. Do not retry or resubmit this operation. Check the mailbox list and have this operation ID reconciled before taking further action."),
        CreateFailure::Unavailable => (503, "Service Unavailable", "The administration service could not complete mailbox creation. Review the mailbox list before taking further action."),
    };
    let operation = request_id
        .map(|id| {
            format!(
                "<dl><dt>Operation ID</dt><dd style=\"overflow-wrap:anywhere\">{}</dd></dl>",
                escape_html(id)
            )
        })
        .unwrap_or_default();
    let body = format!("<main id=\"main-content\" class=\"standalone-notice\" tabindex=\"-1\"><section class=\"panel\"><h1>Mailbox creation unavailable</h1><p role=\"alert\">{message}</p>{operation}<a class=\"button-link\" href=\"/admin/mailboxes?domain={}\">Back to mailboxes</a> <a class=\"button-link\" href=\"/admin\">Return to overview</a></section></main>",escape_html(&url_encode(domain)));
    super::admin_html_response(
        status,
        reason,
        "OSMAP Admin — Mailbox creation",
        TrustedHtml::from_template(body),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> CreatePage {
        CreatePage {
            login: "operator@example.test".into(),
            csrf: "a".repeat(64),
            domain: "example.test".into(),
            revision: 1,
            request_id: "b".repeat(64),
            setup_enabled: true,
        }
    }

    #[test]
    fn scoped_creation_form_has_exact_fields_and_empty_private_inputs() {
        let response = create_mailbox_page(&page());
        assert_eq!(response.status_code, 200);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("action=\"/admin/mailboxes/new\""));
        let form = html
            .split("action=\"/admin/mailboxes/new\"")
            .nth(1)
            .unwrap()
            .split("</form>")
            .next()
            .unwrap();
        assert_eq!(form.matches(" name=\"").count(), 9);
        for name in [
            "domain",
            "local_part",
            "display_name",
            "setup_contact",
            "totp",
            "csrf",
            "request_id",
            "quota_mib",
            "revision",
        ] {
            assert!(form.contains(&format!("name=\"{name}\"")));
        }
        for name in ["setup_contact", "totp"] {
            let input = form
                .split(&format!("name=\"{name}\""))
                .nth(1)
                .unwrap()
                .split('>')
                .next()
                .unwrap();
            assert!(!input.contains("value="));
        }
        assert!(form.contains("Configured quota (MiB)"));
        assert!(form.contains("Approved external setup email"));
        assert!(!form.contains("name=\"password\""));
        assert!(!form.contains("name=\"confirmation\""));
        assert!(!html.contains("osmap-admin1."));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn disabled_onboarding_preserves_the_qualified_legacy_creation_form() {
        let mut page = page();
        page.setup_enabled = false;
        let response = create_mailbox_page(&page);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("name=\"confirmation\""));
        assert!(!html.contains("name=\"setup_contact\""));
    }

    #[test]
    fn receipt_claims_configuration_and_preserves_identity_without_private_proof() {
        let receipt = CreateReceipt {
            login: "operator@example.test".into(),
            csrf: "a".repeat(64),
            domain: "example.test".into(),
            username: "alice@example.test".into(),
            request_id: "b".repeat(64),
            quota: 2 * 1_048_576,
            setup_pending: false,
        };
        let response = mailbox_created_page(&receipt);
        assert_eq!(response.status_code, 201);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("alice@example.test"));
        assert!(html.contains("2 MiB (2097152 bytes)"));
        assert!(html.contains("Signed in as"));
        assert!(
            html.contains("Native authentication and message delivery have not yet been verified.")
        );
        assert!(!html.contains("synthetic-mailbox-password"));
        assert!(!html.contains("name=\"password\""));
    }

    #[test]
    fn unconfirmed_result_prohibits_retry_and_escapes_operation_reference() {
        let response = create_failure_page(
            CreateFailure::Unconfirmed,
            "example.test",
            Some("<public-operation>"),
        );
        assert_eq!(response.status_code, 503);
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("Do not retry or resubmit this operation."));
        assert!(html.contains("&lt;public-operation&gt;"));
        assert!(!html.contains("<form"));
        assert!(!html.contains("/admin/mailboxes/new"));
        assert!(html.contains("Back to mailboxes"));
    }
}
