use super::*;

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
        assert!(!body.contains("action=\"/settings/"));
        assert!(
            body.contains("Current enrollment unknown")
                || body.contains("current enrollment unknown")
        );
        assert!(!body.contains("<script"));
    }
}
