use super::*;

#[test]
fn shell_has_real_named_navigation_and_main_follows_the_header() {
    for (route, selected) in [
        ("/settings", "Settings"),
        ("/compose", "Compose"),
        ("/drafts", "Drafts"),
        ("/sessions", "Sessions"),
        ("/mailbox?name=INBOX", "Inbox"),
        ("/message?mailbox=INBOX&uid=9", "Inbox"),
    ] {
        let result = authenticated_get(route);
        let body = body_text(&result);
        let needle =
            format!("aria-label=\"{selected}\" title=\"{selected}\" aria-current=\"page\"");
        assert!(body.contains(&needle), "{route}");
        assert_body_order(&body, "</header>", "<main id=\"main-content\"");
        for (label, href) in [
            ("Inbox", "/mailbox?name=INBOX"),
            ("Sent", "/mailbox?name=Sent"),
            ("Archive", "/mailbox/shortcut?kind=archive"),
            ("Bin", "/mailbox?name=Trash"),
        ] {
            assert!(body.contains(&format!("href=\"{href}\" aria-label=\"{label}\"")));
        }
        assert!(body.contains("<details class=\"rail-disclosure\">"));
        assert!(body.contains("<details class=\"account-menu\" name=\"toolbar-menu\">"));
        assert!(body.contains("action=\"/logout\""));
        assert!(body.contains("name=\"csrf_token\""));
        assert!(!body.contains("<script"));
    }
}

#[test]
fn archive_navigation_resolves_only_the_authenticated_saved_folder() {
    let result = authenticated_get("/mailbox/shortcut?kind=archive");
    assert_eq!(result.response.status_code, 303);
    assert_eq!(location_header(&result), "/mailbox?name=Archive%2F2026");
    let mut req = request(
        "GET",
        "/mailbox/shortcut?kind=archive",
        &authenticated_headers(),
        "",
    );
    req.headers
        .insert("user-agent".into(), "Firefox/InvalidArchiveTest".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 404);
    assert!(body_text(&result).contains("Archive Mailbox Not Found"));
    assert!(body_text(&result).contains("href=\"/settings\""));
    req.headers
        .insert("user-agent".into(), "OSMAP/NoArchiveTest".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    assert!(body_text(&result).contains("Choose Your Archive Mailbox"));
    req.headers
        .insert("user-agent".into(), "OSMAP/SettingsUnavailable".into());
    let result = app().handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("Archive Temporarily Unavailable"));
    for path in [
        "/mailbox/shortcut?kind=unknown",
        "/mailbox/shortcut?kind=archive&account=bob",
        "/mailbox/shortcut?kind=archive&destination=INBOX",
        "/mailbox/shortcut",
    ] {
        assert_eq!(authenticated_get(path).response.status_code, 400);
    }
    let result = app().handle_request(
        &request("GET", "/mailbox/shortcut?kind=archive", &[], ""),
        "127.0.0.1",
    );
    assert_eq!(result.response.status_code, 303);
    assert_eq!(location_header(&result), "/login");
}

#[test]
fn shell_escapes_identity_and_retains_full_accessible_account_name() {
    let identity = format!(
        "{}<img src=x>@example.test",
        "long-account-name-".repeat(16)
    );
    let page = render_navigation_notice(&identity, "fixture-only", "Archive", "Choose a mailbox");
    assert!(!page.contains("<img src=x>"));
    assert!(page.contains(&*escape_html(&identity)));
    assert!(page.contains("class=\"account-name\" title=\""));
    assert!(page.contains("class=\"account-menu-panel\""));
}
