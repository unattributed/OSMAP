use super::*;

#[test]
fn general_account_security_reads_owned_current_metadata() {
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            authenticator_snapshot: Some(crate::authenticator::Snapshot {
                account: "alice@example.com".into(),
                enrolled: true,
                last_accepted_counter: None,
                request: None,
                case: None,
            }),
            recovery_snapshot: Some(crate::recovery_contact::RecoveryContactSnapshot {
                revision: 1,
                verified: Some(crate::recovery_contact::VerifiedRecoveryContact {
                    email: "backup@example.test".into(),
                    verified_at: 1_700_000_000,
                }),
                pending: None,
                notice: None,
                resend_at: None,
            }),
            password_changed_at: Some("20261103123456".into()),
            ..StubGateway::default()
        },
    );
    for path in ["/settings", "/settings?section=general"] {
        let mut headers = authenticated_same_origin_headers().to_vec();
        headers.iter_mut().find(|(name, _)| name.eq_ignore_ascii_case("user-agent")).unwrap().1 = "KeyInventoryPractical";
        let result = app.handle_request(&request("GET", path, &headers, ""), "127.0.0.1");
        assert_eq!(result.response.status_code, 200);
        let body = body_text(&result);
        let card = body.split("<h2 id=\"general-security-title\">").nth(1).unwrap().split("</section>").next().unwrap();
        for fact in ["Account binding configured", "0123456789ABCDEF0123456789ABCDEF01234567", "Enrolled", "Verified", "backup@example.test", "2026-11-03 12:34:56 UTC"] {
            assert!(card.contains(fact), "missing {fact} on {path}");
        }
        for path in ["/settings/keys", "/settings/password", "/settings/authenticator", "/settings/recovery"] {
            assert!(card.contains(&format!("href=\"{path}\"")));
        }
        assert!(!card.contains("Status unknown"));
        assert!(!card.contains("private key unlocked"));
    }
    assert_eq!(*app.gateway.recovery_calls.lock().unwrap(), 0);
    assert!(app.gateway.password_calls.lock().unwrap().is_empty());
    assert_eq!(*app.gateway.authenticator_reads.lock().unwrap(), vec!["alice@example.com", "alice@example.com"]);
}

#[test]
fn general_account_security_unavailable_and_foreign_reads_do_not_invent_success() {
    let app = BrowserApp::new(HttpPolicy::default(), StubGateway {
        authenticator_snapshot: Some(crate::authenticator::Snapshot {
            account: "foreign@example.com".into(), enrolled: true,
            last_accepted_counter: Some(12345), request: None, case: None,
        }),
        password_changed_at: Some("<script>foreign timestamp</script>".into()),
        ..StubGateway::default()
    });
    for mode in ["KeyInventoryPracticalForeign", "KeyInventoryPracticalUnavailable"] {
        let mut headers = authenticated_same_origin_headers();
        headers.iter_mut().find(|(name, _)| name.eq_ignore_ascii_case("user-agent")).unwrap().1 = mode;
        let response = app.handle_request(&request("GET", "/settings", &headers, ""), "127.0.0.1");
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        let card = body.split("<h2 id=\"general-security-title\">").nth(1).unwrap().split("</section>").next().unwrap();
        assert_eq!(card.matches(">Unavailable</span>").count(), 3);
        for absent in ["foreign@example.com", "0123456789ABCDEF0123456789ABCDEF01234567", "Enrolled", "Verified", "foreign timestamp", "Status unknown"] {
            assert!(!card.contains(absent), "exposed {absent}");
        }
        assert!(card.contains("Used at sign-in; last-change history unavailable"));
    }
    let response = app.handle_request(&request("GET", "/settings", &[], ""), "127.0.0.1");
    assert_ne!(response.response.status_code, 200);
    assert!(app.gateway.password_calls.lock().unwrap().is_empty());
    assert_eq!(*app.gateway.recovery_calls.lock().unwrap(), 0);
}

#[test]
fn security_settings_foreign_loaded_preferences_never_render() {
    for section in [
        "general",
        "appearance",
        "reading",
        "composition",
        "copies",
        "privacy",
    ] {
        let response = app().handle_request(&request("GET", &format!("/settings?section={section}"), &[("User-Agent", "SettingsWrongOwner"), ("Cookie", "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")], ""), "127.0.0.1");
        assert_eq!(response.response.status_code, 503, "{section}");
        let body = body_text(&response);
        assert!(body.contains("could not be confirmed for this account"));
        assert!(!body.contains("foreign-settings-owner"));
        assert!(!body.contains("foreign-private-archive"));
        assert!(!body.contains("class=\"account-menu\""));
    }
}

#[test]
fn security_settings_native_routes_are_readonly_and_linked() {
    for (section, title) in [
        ("security", "Security Controls"),
        ("authentication", "Authentication"),
    ] {
        let response = app().handle_request(&request("GET", &format!("/settings?section={section}"), &[("User-Agent", "Firefox/Test"), ("Cookie", "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")], ""), "127.0.0.1");
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains(&format!("<h2>{title}</h2>")));
        assert!(body.contains("2 active browser sessions"));
        assert!(body.contains("href=\"/sessions\" aria-label=\"Manage sessions\""));
        assert!(body.contains("Password changes are currently unavailable."));
        assert!(body.contains("disabled>Unavailable</button>"));
        assert!(!body.contains("aria-label=\"Change password\""));
        assert!(!body.contains("action=\"/settings/"));
        assert!(body.contains("Authenticator state and last use are unavailable."));
        assert!(body.contains("href=\"/settings/authenticator\" aria-label=\"Manage TOTP\""));
        assert!(!body.contains("<strong>Enrolled</strong>"));
        assert!(!body.contains("<script"));
    }
}
