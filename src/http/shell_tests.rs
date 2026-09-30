use super::*;

#[test]
fn shell_has_real_named_navigation_and_main_follows_the_header() {
    for (route, selected) in [
        ("/settings", "Settings"),
        ("/compose", "Compose"),
        ("/drafts", "Drafts"),
        ("/sessions", "Settings"),
        ("/settings?section=security", "Settings"),
        ("/mailbox?name=Trash", "Archive / Bin"),
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
            ("Archive / Bin", "/mailbox/shortcut?kind=archive"),
            ("Security", "/settings?section=security"),
        ] {
            assert!(body.contains(&format!("href=\"{href}\" aria-label=\"{label}\"")));
        }
        assert!(body.contains("<details class=\"rail-disclosure\">"));
        assert!(body.contains("<details class=\"account-menu\" name=\"toolbar-menu\">"));
        assert!(body.contains("action=\"/logout\""));
        assert!(body.contains("name=\"csrf_token\""));
        if route == "/compose" {
            assert_eq!(body.matches("<script").count(), 1);
            assert!(body.contains("<script id=\"osmap-compose-local\">"));
        } else {
            assert!(!body.contains("<script"));
        }
    }
}

#[test]
fn shell_primary_order_single_selection_and_foreign_archive_refusal() {
    for current in ["settings-security", "settings-privacy", "bin", "archive"] {
        let body = crate::http_ui::app_header("alice@example.test", "synthetic", current);
        let nav = body
            .split("aria-label=\"Primary navigation\">")
            .nth(1)
            .unwrap()
            .split("</nav>")
            .next()
            .unwrap();
        assert_eq!(nav.matches("aria-current=\"page\"").count(), 1);
        let mut tail = nav;
        for label in [
            "Mailbox",
            "Compose",
            "Inbox",
            "Drafts",
            "Sent",
            "Documents",
            "Archive / Bin",
            "Security",
            "Settings",
            "Search",
        ] {
            tail = tail
                .split_once(&format!("<span class=\"rail-label\">{label}</span>"))
                .unwrap()
                .1;
        }
        assert!(nav.contains(
            "role=\"link\" aria-disabled=\"true\" aria-label=\"Documents, unavailable\""
        ));
        assert!(!nav.contains("href=\"\""));
    }
    for agent in ["SettingsWrongOwner", "CopiesWrongOwner"] {
        let result = app().handle_request(&request("GET", "/mailbox/shortcut?kind=archive", &[("User-Agent", agent), ("Cookie", "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")], ""), "127.0.0.1");
        assert_eq!(result.response.status_code, 503);
        let body = body_text(&result);
        assert!(!body.contains("foreign-private-archive"));
        assert!(!body.contains("foreign@example"));
        assert!(!result
            .response
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("location")));
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
