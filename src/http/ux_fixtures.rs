// Test-only route snapshots. Uses the existing in-memory gateway and never
// constructs a runtime gateway, opens a socket, or contacts a mail host.
use super::*;
use sha2::{Digest, Sha256};

fn redact_fixture_tokens(html: &str) -> String {
    let mut output = String::with_capacity(html.len());
    let mut hex_run = String::new();
    for character in html.chars().chain(std::iter::once('\0')) {
        if character.is_ascii_hexdigit() {
            hex_run.push(character);
            continue;
        }
        if hex_run.len() >= 32 {
            output.push_str("SYNTHETIC-REDACTED");
        } else {
            output.push_str(&hex_run);
        }
        hex_run.clear();
        if character != '\0' {
            output.push(character);
        }
    }
    output.replace("@example.com", "@example.test")
}

#[test]
fn ux_synthetic_route_baselines() {
    let output_dir = std::env::var_os("OSMAP_UX_FIXTURE_DIR").map(PathBuf::from);
    if let Some(path) = &output_dir {
        assert!(path.is_absolute(), "fixture directory must be absolute");
        fs::create_dir_all(path).expect("create fixture directory");
    }
    let cases = [
        ("login", "/login", false, 200),
        ("redirect", "/", false, 303),
        ("mailboxes", "/mailboxes", true, 200),
        ("inbox", "/mailbox?name=INBOX", true, 200),
        ("search", "/search?mailbox=INBOX&q=report", true, 200),
        ("reader", "/message?mailbox=INBOX&uid=9", true, 200),
        (
            "source",
            "/message?mailbox=INBOX&uid=9&view=source",
            true,
            200,
        ),
        ("compose", "/compose", true, 200),
        (
            "reply",
            "/compose?mode=reply&mailbox=INBOX&uid=9",
            true,
            200,
        ),
        ("drafts-empty", "/drafts", true, 200),
        ("settings", "/settings", true, 200),
        ("sessions", "/sessions", true, 200),
        ("not-found", "/not-a-route", false, 404),
        ("invalid-search", "/search", true, 400),
        (
            "reader-unavailable",
            "/message?mailbox=INBOX&uid=900",
            true,
            503,
        ),
    ];
    let mut manifest = Vec::new();
    for (name, path, authenticated, expected_status) in cases {
        let headers = if authenticated {
            authenticated_headers().to_vec()
        } else {
            vec![("User-Agent", "OSMAP/SyntheticUX")]
        };
        let response = app().handle_request(&request("GET", path, &headers, ""), "127.0.0.1");
        assert_eq!(response.response.status_code, expected_status, "{name}");
        let csp = response
            .response
            .headers
            .iter()
            .find(|(header, _)| header == "Content-Security-Policy")
            .map(|(_, value)| value.as_str())
            .expect("HTML has CSP");
        assert_eq!(csp, crate::http_support::browser_csp());
        let html = redact_fixture_tokens(&body_text(&response));
        assert!(!html.contains("<script"), "script-free fixture {name}");
        if let Some(directory) = &output_dir {
            fs::write(directory.join(format!("{name}.html")), &html).expect("write fixture");
        }
        manifest.push(serde_json::json!({
            "name": name, "method": "GET", "route": path,
            "status": expected_status, "authenticated_fixture": authenticated,
            "html_sha256": format!("{:x}", Sha256::digest(html.as_bytes())),
            "csp": csp, "synthetic": true, "tokens_redacted": true,
        }));
    }
    if let Some(directory) = &output_dir {
        fs::write(
            directory.join("routes.json"),
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
    }
}
