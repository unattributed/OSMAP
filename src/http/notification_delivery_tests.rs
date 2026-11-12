use super::*;
use sha2::{Digest, Sha256};

#[test]
fn notification_script_is_exact_hash_pinned_with_no_dynamic_private_data() {
    let digest = Sha256::digest(SCRIPT.as_bytes());
    let encoded = crate::send::base64_encode_wrapped(&digest);
    assert_eq!(SCRIPT_HASH, format!("sha256-{}", encoded.trim()));
    assert!(!SCRIPT.contains("</script"));
    let response = response(
        200,
        "OK",
        "<private-title>",
        TrustedHtml::from_template(format!(
            "<main><p>{}</p>{}</main>",
            escape_html("</p><script>private-marker</script>"),
            controls()
        )),
    );
    let html = String::from_utf8(response.body).expect("template is UTF-8");
    assert_eq!(html.matches("<script").count(), 1);
    assert!(html.contains("&lt;private-title&gt;"));
    assert!(html.contains("&lt;script&gt;private-marker&lt;/script&gt;"));
    assert!(html.contains(&format!(
        "<script id=\"osmap-notification-local\">{SCRIPT}</script>"
    )));
    assert!(response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("Content-Security-Policy") && value == &csp()
    }));
    assert!(csp().starts_with(crate::http_support::browser_csp()));
    assert!(csp().contains("connect-src 'self'"));
    assert!(csp().contains("script-src-attr 'none'"));
    assert!(!csp().contains("script-src 'self'"));
    assert!(!csp().contains("script-src 'unsafe-inline'"));
}

#[test]
fn browser_controls_start_disabled_and_never_submit_permission_as_account_settings() {
    let html = controls();
    assert_eq!(html.matches("type=\"button\"").count(), 4);
    assert_eq!(html.matches(" disabled").count(), 4);
    assert!(!html.contains("<form"));
    assert!(html.contains("without message subjects or contents"));
    assert!(html.contains("Signing out ends authenticated updates"));
    assert!(html.contains("do not prove an alert was displayed or heard"));
}
