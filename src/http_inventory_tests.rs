use super::*;

const INVENTORY_SESSION: &str =
    "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn inventory_routes_require_session_and_reject_mutation_or_account_selection() {
    for path in ["/settings/keys", "/settings?section=openpgp"] {
        let response = app().handle_request(&request("GET", path, &[], ""), "127.0.0.1");
        assert_ne!(response.response.status_code, 200);
        assert!(!body_text(&response).contains("0123456789ABCDEF"));
        let response = app().handle_request(
            &request("POST", path, &[("Cookie", INVENTORY_SESSION)], ""),
            "127.0.0.1",
        );
        assert_ne!(response.response.status_code, 200);
    }
    for path in [
        "/settings/keys?account=bob",
        "/settings/keys?fingerprint=other",
    ] {
        let response = app().handle_request(
            &request("GET", path, &[("Cookie", INVENTORY_SESSION)], ""),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 400);
        assert!(!body_text(&response).contains("0123456789ABCDEF"));
    }
}

#[test]
fn inventory_routes_project_only_session_owned_metadata_and_keep_capabilities_disabled() {
    for path in ["/settings/keys", "/settings?section=openpgp"] {
        for mode in [
            "KeyInventoryListed",
            "KeyInventoryEmpty",
            "KeyInventoryForeign",
            "KeyInventoryUnavailable",
        ] {
            let response = app().handle_request(
                &request(
                    "GET",
                    path,
                    &[("Cookie", INVENTORY_SESSION), ("User-Agent", mode)],
                    "",
                ),
                "127.0.0.1",
            );
            assert_eq!(response.response.status_code, 200);
            let body = body_text(&response);
            assert!(!body.contains("<script"));
            if path == "/settings/keys" {
                // Public inventory alone grants no binding-change authority.
                assert!(body.contains("Binding changes unavailable"));
                assert!(body.contains("<fieldset disabled>"));
                assert_eq!(body.matches("<fieldset>").count(), 0);
                assert!(body.contains("<button disabled>Import public key</button>"));
                assert!(!body.contains("name=\"passphrase\""));
                assert!(!body.contains("<strong>Configured</strong>"));
            } else {
                assert!(!body.contains("name=\"signing\""));
                assert!(!body.contains("name=\"encryption\""));
            }
            assert!(!body.contains("action=\"/settings/keys\""));
            if path == "/settings?section=openpgp" {
                // Authenticated public metadata cannot turn an absent runtime
                // or binding projection into a configured account.
                assert!(body.contains("<strong>OpenPGP unavailable</strong>"));
                assert!(body.contains("readonly value=\"Account binding unavailable\""));
                assert!(!body.contains("<strong>OpenPGP configured</strong>"));
                assert!(!body.contains("bob@example.com"));
                continue;
            }
            match mode {
                "KeyInventoryForeign" | "KeyInventoryUnavailable" => {
                    assert!(body.contains("Public inventory unavailable"));
                    assert!(!body.contains("0123456789ABCDEF"));
                    assert!(!body.contains("bob@example.com"));
                }
                "KeyInventoryEmpty" if path == "/settings/keys" => {
                    assert!(body.contains("No public keys were reported"));
                    assert!(!body.contains("0123456789ABCDEF"));
                }
                "KeyInventoryListed" if path == "/settings/keys" => {
                    assert!(body.contains("0123456789ABCDEF0123456789ABCDEF01234567"));
                    assert!(body.contains("Account binding unavailable"));
                }
                _ => unreachable!("all key inventory fixture states handled"),
            }
        }
    }
}
