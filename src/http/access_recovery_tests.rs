use super::*;
use crate::browser_access::{AccessCookie, AccessError, AccessOutcome, AccessView};

const CSRF: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
fn enrollment() -> crate::totp_enrollment::PendingEnrollment {
    crate::totp_enrollment::PendingEnrollment {
        id: ID.into(), revision: 1,
        // Public RFC 6238 test vector only.
        secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
        otpauth_uri: "otpauth://totp/Test:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test".into(),
        expires_at: 1_700_000_600,
    }
}
fn post(path: &str, fields: &str, signed_in: bool, grant: bool) -> HttpRequest {
    let mut cookie = format!("__Host-osmap_recovery_csrf={CSRF}");
    if signed_in {
        cookie.push_str(
            "; osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    }
    if grant {
        cookie.push_str(&format!("; __Host-osmap_recovery={TOKEN}"));
    }
    request(
        "POST",
        path,
        &[
            ("Cookie", &cookie),
            ("Origin", "https://localhost"),
            ("User-Agent", "Firefox/Test"),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        &format!("csrf_token={CSRF}&{fields}"),
    )
}
fn queue(app: &BrowserApp<StubGateway>, view: AccessView, cookie: AccessCookie) {
    app.gateway
        .access_outcomes
        .lock()
        .unwrap()
        .push_back(Ok(AccessOutcome {
            view,
            grant_cookie: cookie,
        }));
}
fn headers(response: &HandledHttpResponse) -> String {
    response
        .response
        .headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\n"))
        .collect()
}

#[test]
fn public_recovery_get_issues_private_double_submit_cookie_without_mail_session() {
    let app = app();
    app.gateway
        .access_views
        .lock()
        .unwrap()
        .push_back(Ok(AccessView::RecoveryEmail {
            csrf: String::new(),
        }));
    let result = app.handle_request(&request("GET", "/recover", &[], ""), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    let h = headers(&result);
    assert!(h.contains("__Host-osmap_recovery_csrf="));
    assert!(h.contains("Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Strict"));
    assert!(h.contains("no-store"));
    assert!(h.contains("no-referrer"));
    assert!(!h.contains("osmap_session="));
    assert!(body_text(&result).contains("If recovery is available"));
    assert!(!body_text(&result).contains("backup"));
}

#[test]
fn recovery_csrf_origin_and_extra_authority_are_refused_before_gateway_action() {
    let app = app();
    let valid = post(
        "/recover",
        "action=send_code&email=alice%40example.com",
        false,
        false,
    );
    let mut origin = valid.clone();
    origin
        .headers
        .insert("origin".into(), "https://foreign.example.com".into());
    let mut missing = valid.clone();
    missing.headers.remove("cookie");
    let mut mismatch = valid.clone();
    mismatch.body = String::from_utf8(mismatch.body)
        .unwrap()
        .replace(CSRF, ID)
        .into_bytes();
    for value in [
        origin,
        missing,
        mismatch,
        post(
            "/recover",
            "action=send_code&email=alice%40example.com&account=bob%40example.com",
            false,
            false,
        ),
    ] {
        let result = app.handle_request(&value, "127.0.0.1");
        assert!(matches!(result.response.status_code, 400 | 403));
    }
    assert!(app.gateway.access_calls.lock().unwrap().is_empty());
}

#[test]
fn wrong_email_code_keeps_challenge_retryable_without_repopulating_the_code() {
    let app = app();
    app.gateway
        .access_outcomes
        .lock()
        .unwrap()
        .push_back(Err(AccessError::Refused));
    let result = app.handle_request(
        &post(
            "/recover",
            &format!("action=verify_code&challenge_id={ID}&code=123456"),
            false,
            false,
        ),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 403);
    let html = body_text(&result);
    assert!(html.contains(&format!("name=\"challenge_id\" value=\"{ID}\"")));
    assert!(html.contains("name=\"code\""));
    assert!(!html.contains("123456"));
    assert_eq!(*app.gateway.access_calls.lock().unwrap(), ["verify_code"]);
}

#[test]
fn verified_email_enters_restricted_local_qr_setup_and_cookie_is_not_a_mail_session() {
    let app = app();
    queue(
        &app,
        AccessView::RecoverySetup {
            csrf: CSRF.into(),
            enrollment: enrollment(),
        },
        AccessCookie::Set(TOKEN.into()),
    );
    let result = app.handle_request(
        &post(
            "/recover",
            &format!("action=verify_code&challenge_id={ID}&code=123456"),
            false,
            false,
        ),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 200);
    let html = body_text(&result);
    assert!(html.contains("<svg"));
    assert!(!html.contains("<img"));
    assert!(!html.contains("otpauth://"));
    assert!(html.contains("name=\"new_password\""));
    assert!(html.contains("name=\"new_totp_code\""));
    assert!(headers(&result).contains(&format!("__Host-osmap_recovery={TOKEN};")));
    assert!(!headers(&result).contains("osmap_session="));
    let mail = app.handle_request(
        &request(
            "GET",
            "/mailboxes",
            &[("Cookie", &format!("__Host-osmap_recovery={TOKEN}"))],
            "",
        ),
        "127.0.0.1",
    );
    assert_ne!(mail.response.status_code, 200);
}

#[test]
fn restricted_setup_requires_grant_and_confirmed_completion_requires_fresh_signin() {
    let app = app();
    let missing = app.handle_request(&request("GET", "/recover/setup", &[], ""), "127.0.0.1");
    assert_eq!(missing.response.status_code, 303);
    assert_eq!(location_header(&missing), "/recover");
    assert!(app.gateway.access_calls.lock().unwrap().is_empty());
    queue(&app, AccessView::Complete, AccessCookie::Clear);
    let result = app.handle_request(&post("/recover/setup", &format!("action=confirm_recovery&enrollment_id={ID}&revision=1&new_password=synthetic-password-only&confirmation=synthetic-password-only&new_totp_code=123456"), false, true), "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    assert!(body_text(&result).contains("The update was confirmed"));
    assert!(!body_text(&result).contains("synthetic-password-only"));
    for name in [
        "osmap_session",
        "__Host-osmap_recovery",
        "__Host-osmap_recovery_csrf",
    ] {
        assert!(headers(&result).contains(&format!("{name}=;")), "{name}");
    }
}

#[test]
fn uncertain_commit_never_retries_or_displays_completed_setup() {
    let app = app();
    app.gateway
        .access_outcomes
        .lock()
        .unwrap()
        .push_back(Err(AccessError::Unconfirmed));
    let result = app.handle_request(
        &post(
            "/settings/authenticator",
            &format!("action=confirm_reset&enrollment_id={ID}&revision=1&new_totp_code=123456"),
            true,
            false,
        ),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("Do not submit it again"));
    assert!(!body_text(&result).contains("<form"));
    assert_eq!(*app.gateway.access_calls.lock().unwrap(), ["confirm_reset"]);
}

#[test]
fn signedin_reset_needs_current_password_and_code_and_refuses_foreign_view() {
    let app = app();
    let fields =
        "action=begin_reset&current_password=synthetic-current-only&current_totp_code=123456";
    let missing = app.handle_request(
        &post(
            "/settings/authenticator",
            "action=begin_reset&current_totp_code=123456",
            true,
            false,
        ),
        "127.0.0.1",
    );
    assert_eq!(missing.response.status_code, 400);
    assert!(app.gateway.access_calls.lock().unwrap().is_empty());
    queue(
        &app,
        AccessView::TotpReplacement {
            account: "bob@example.com".into(),
            csrf: CSRF.into(),
            enrollment: enrollment(),
        },
        AccessCookie::Unchanged,
    );
    let result = app.handle_request(
        &post("/settings/authenticator", fields, true, false),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 503);
    assert!(!body_text(&result).contains("<svg"));
    assert!(!body_text(&result).contains("synthetic-current-only"));
    assert_eq!(*app.gateway.access_calls.lock().unwrap(), ["begin_reset"]);
}

#[test]
fn malformed_enrollment_and_native_flow_mismatch_fail_without_secret_presentation() {
    for bad_csrf in [false, true] {
        let app = app();
        let mut pending = enrollment();
        if !bad_csrf {
            pending.otpauth_uri = "https://foreign.example/qr".into();
        }
        queue(
            &app,
            AccessView::RecoverySetup {
                csrf: if bad_csrf { ID.into() } else { CSRF.into() },
                enrollment: pending,
            },
            AccessCookie::Set(TOKEN.into()),
        );
        let result = app.handle_request(
            &post(
                "/recover",
                &format!("action=verify_code&challenge_id={ID}&code=123456"),
                false,
                false,
            ),
            "127.0.0.1",
        );
        assert_eq!(result.response.status_code, 503);
        assert!(!body_text(&result).contains("GEZDGNBV"));
        assert!(!headers(&result).contains(TOKEN));
    }
    let debug = format!(
        "{:?} {:?}",
        AccessView::RecoverySetup {
            csrf: CSRF.into(),
            enrollment: enrollment()
        },
        crate::browser_access::AccessAction::BeginTotpReset {
            current_password: "synthetic-current-only",
            current_totp_code: "123456"
        }
    );
    assert!(!debug.contains(CSRF));
    assert!(!debug.contains("GEZDGNBV"));
    assert!(!debug.contains("synthetic-current-only"));
    assert!(!debug.contains("123456"));
}

#[test]
fn signedin_reset_get_requires_session_and_query_cannot_select_another_account() {
    let app = app();
    let query = app.handle_request(
        &request(
            "GET",
            "/settings/authenticator?account=bob%40example.com",
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(query.response.status_code, 400);
    assert!(app.gateway.access_calls.lock().unwrap().is_empty());
    app.gateway
        .access_views
        .lock()
        .unwrap()
        .push_back(Ok(AccessView::TotpResetStart {
            account: "alice@example.com".into(),
            csrf: CSRF.into(),
        }));
    let response = app.handle_request(
        &request(
            "GET",
            "/settings/authenticator",
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(html.contains("name=\"current_password\""));
    assert!(html.contains("name=\"current_totp_code\""));
    assert!(!html.contains("private terminal"));
    assert!(!html.contains("name=\"account\""));
    // The shared app header has SVG navigation icons; only enrollment QR/key
    // presentation must remain absent before fresh reauthentication.
    assert!(!html.contains("New authenticator QR code"));
    assert!(!html.contains("GEZDGNBV"));
}
