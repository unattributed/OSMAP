use super::*;

fn contact_app() -> BrowserApp<StubGateway> {
    BrowserApp::new(HttpPolicy::default(), StubGateway {
        recovery_snapshot: Some(crate::recovery_contact::RecoveryContactSnapshot {
            revision: 7,
            verified: Some(crate::recovery_contact::VerifiedRecoveryContact { email: "backup@example.test".into(), verified_at: 1_700_000_000 }),
            pending: None, notice: None, resend_at: None,
        }),
        ..StubGateway::default()
    })
}

fn contact_request(body: &str) -> HttpRequest {
    let mut value = request("POST", "/settings/recovery", &authenticated_same_origin_headers(), body);
    value.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
    value
}

#[test]
fn recovery_contact_navigation_projects_real_metadata_and_keeps_secrets_empty() {
    let app = contact_app();
    for path in ["/settings/recovery", "/settings?section=security", "/settings?section=authentication"] {
        let result = app.handle_request(&request("GET", path, &authenticated_same_origin_headers(), ""), "127.0.0.1");
        assert_eq!(result.response.status_code, 200, "{path}");
        let html = body_text(&result);
        assert!(html.contains("backup@example.test"));
        assert!(html.contains("2023-11-14T22:13:20Z"));
        assert!(html.contains("/settings/recovery"));
        assert!(!html.contains("Recovery-contact management is unavailable."));
    }
    assert_eq!(*app.gateway.recovery_calls.lock().unwrap(), 0);
}

#[test]
fn recovery_contact_route_refuses_origin_csrf_extra_fields_and_query_before_mutation() {
    let app = contact_app();
    let csrf = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let good = format!("csrf_token={csrf}&revision=7&action=verify&token={}", "a".repeat(64));
    let mut wrong_origin = contact_request(&good);
    wrong_origin.headers.insert("origin".into(), "https://foreign.example.test".into());
    for value in [wrong_origin, contact_request(&good.replace(csrf, "wrong")), contact_request(&(good.clone()+"&account=other")), request("GET", "/settings/recovery?token=private", &authenticated_same_origin_headers(), "")] {
        let result = app.handle_request(&value, "127.0.0.1");
        assert_ne!(result.response.status_code, 200);
    }
    assert_eq!(*app.gateway.recovery_calls.lock().unwrap(), 0);
    let result = app.handle_request(&contact_request(&good), "127.0.0.1");
    assert_eq!(result.response.status_code, 400);
    assert_eq!(*app.gateway.recovery_calls.lock().unwrap(), 1);
    assert!(!body_text(&result).contains(&"a".repeat(64)));
    assert!(!body_text(&result).contains("id=\"recovery-proof\"")); // no pending proof form is fabricated
    for event in result.audit_events { assert!(!format!("{event:?}").contains(&"a".repeat(64))); }
}

#[test]
fn recovery_contact_page_preserves_prior_uncertain_notification_warning() {
    let mut app = contact_app();
    app.gateway.recovery_snapshot.as_mut().unwrap().notice = Some(crate::recovery_contact::RecoveryContactNotice {
        kind: crate::recovery_contact::RecoveryContactNoticeKind::Removed,
        attempted_at: 1_700_000_001,
        delivery: crate::recovery_contact::RecoveryContactDelivery::Accepted,
        earlier_unconfirmed: true,
    });
    let response = app.handle_request(&request("GET", "/settings/recovery", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    let html = body_text(&response);
    assert!(html.contains("Accepted by the mail service"));
    assert!(html.contains("An earlier previous-contact notification remains unconfirmed"));
}

#[test]
fn recovery_contact_unavailable_is_truthful_and_anonymous_cannot_manage() {
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway::default());
    let result = app.handle_request(&request("GET", "/settings/recovery", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("status unavailable"));
    assert!(body_text(&result).contains("<fieldset disabled>"));
    let result = app.handle_request(&request("GET", "/settings/recovery", &[], ""), "127.0.0.1");
    assert_ne!(result.response.status_code, 200);
    assert!(!body_text(&result).contains("backup@example.test"));
}

#[test]
fn recovery_contact_refusal_preserves_only_valid_email_and_clears_secrets() {
    let app = contact_app();
    let csrf = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let form = |email: &str| format!("csrf_token={csrf}&revision=7&action=begin&email={email}&current_password=do-not-echo-this-secret&totp_code=909090");
    let result = app.handle_request(&contact_request(&form("backup%2Bcorrection%40example.test")), "127.0.0.1");
    assert_eq!(result.response.status_code, 400);
    let html = body_text(&result);
    assert!(html.contains("value=\"backup+correction@example.test\""));
    assert!(!html.contains("do-not-echo-this-secret"));
    assert!(!html.contains("909090"));
    for email in ["bad%22%3E%3Cscript%3E%40example.test".to_string(), "a".repeat(255)+"%40example.test"] {
        let result = app.handle_request(&contact_request(&form(&email)), "127.0.0.1");
        let html = body_text(&result);
        assert!(!html.contains("<script>"));
        assert!(html.contains("id=\"recovery-email\" name=\"email\" type=\"email\" autocomplete=\"off\" maxlength=\"254\" value=\"\""));
    }
    let result = app.handle_request(&request("GET", "/settings/recovery", &authenticated_same_origin_headers(), ""), "127.0.0.1");
    assert!(!body_text(&result).contains("backup+correction@example.test"));
}
