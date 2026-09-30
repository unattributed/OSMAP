use super::*;
const SOURCE: &str = "\n\nExact 🦊 </textarea><script>inert</script>\r\nsource & literal";
const BYTES: &[u8] = &[0, 255, 10, 13, 42];
fn submitted() -> (BrowserApp<StubGateway>, String) {
    let mut app = app();
    app.gateway.browser_fixture_accounts = true;
    let mut body = String::new();
    for (name, value) in [
        (
            "csrf_token",
            StubGateway::validated_session().record.csrf_token.as_str(),
        ),
        ("to", "bob@example.test"),
        ("cc", "copy@example.test"),
        ("bcc", "hidden@example.test"),
        ("subject", "Exact subject 🦊"),
        ("body", SOURCE),
        ("body_format", "plain"),
    ] {
        body.push_str(&format!(
            "--proof\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str("--proof\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"exact.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n");
    let mut bytes = body.into_bytes();
    bytes.extend_from_slice(BYTES);
    bytes.extend_from_slice(b"\r\n--proof--\r\n");
    let mut headers = authenticated_same_origin_headers().to_vec();
    headers.push(("Content-Type", "multipart/form-data; boundary=proof"));
    let req = native_compose_request_bytes(&app, "POST", "/send", &headers, &bytes);
    let result = app.handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 303, "{}", body_text(&result));
    let location = location_header(&result);
    (app, location)
}
fn get(app: &BrowserApp<StubGateway>, url: &str) -> HandledHttpResponse {
    app.handle_request(
        &request("GET", url, &authenticated_headers(), ""),
        "127.0.0.1",
    )
}
#[test]
fn durable_ui_exact_source_bytes_restart_and_missing_or_corrupt_outcome() {
    let (mut app, url) = submitted();
    let root = app.gateway.recovery_root.clone();
    let original = app.gateway.submitted.lock().unwrap()[0].clone();
    for state in ["present", "missing", "corrupt"] {
        if state == "missing" {
            app.gateway.send_journal =
                crate::send_journal::SendJournal::new(root.join("missing-journal"));
        }
        if state == "corrupt" {
            let path = root.join("invalid-journal");
            fs::write(&path, b"not a directory").unwrap();
            app.gateway.send_journal = crate::send_journal::SendJournal::new(path);
        }
        // Clone rebuilds the browser application; snapshot reads reopen file descriptors.
        let reopened = BrowserApp::new(HttpPolicy::default(), app.gateway.clone());
        let result = get(&reopened, &url);
        assert_eq!(result.response.status_code, 200);
        let html = body_text(&result);
        for text in [
            escape_html(SOURCE).to_string(),
            "hidden@example.test".into(),
            "Exact subject 🦊".into(),
            "Exact prepared attempt".into(),
            "1970-01-31 00:01:40 UTC".into(),
        ] {
            assert!(html.contains(&text));
        }
        assert!(
            !html.contains("action=\"/send\"")
                && !html.contains("name=\"send_intent\"")
                && !html.contains("<script")
        );
        let source = get(&reopened, &format!("{url}&recovery_body=1"));
        assert_eq!(source.response.status_code, 200);
        assert_eq!(source.response.body, SOURCE.as_bytes());
        assert!(source
            .response
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Disposition" && v.contains("attempt-body.txt")));
        let file = get(&reopened, &format!("{url}&recovery_attachment=0"));
        assert_eq!(file.response.status_code, 200);
        assert_eq!(file.response.body, BYTES);
        for (name, value) in [
            ("Content-Type", "application/octet-stream"),
            ("X-Content-Type-Options", "nosniff"),
            ("Cache-Control", "no-store"),
            (
                "Content-Security-Policy",
                "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            ),
        ] {
            assert!(file
                .response
                .headers
                .iter()
                .any(|(n, v)| n == name && v == value));
        }
        assert_eq!(
            app.gateway.submitted.lock().unwrap().as_slice(),
            std::slice::from_ref(&original)
        );
        assert!(app.gateway.drafts.lock().unwrap().is_empty());
    }
}
#[test]
fn recovery_download_query_and_account_boundaries_refuse() {
    let (app, url) = submitted();
    for suffix in [
        "&recovery_attachment=-1",
        "&recovery_attachment=00",
        "&recovery_attachment=3",
        "&recovery_attachment=18446744073709551616",
        "&unexpected=1",
    ] {
        assert_eq!(
            get(&app, &format!("{url}{suffix}")).response.status_code,
            400
        );
    }
    assert_eq!(
        get(&app, &format!("{url}&recovery_attachment=1"))
            .response
            .status_code,
        404
    );
    assert_eq!(
        get(&app, "/compose?recovery_attachment=0")
            .response
            .status_code,
        400
    );
    let mut foreign = request(
        "GET",
        &format!("{url}&recovery_attachment=0"),
        &authenticated_headers(),
        "",
    );
    foreign
        .headers
        .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
    assert_eq!(
        app.handle_request(&foreign, "127.0.0.1")
            .response
            .status_code,
        404
    );
    assert_eq!(app.gateway.submitted.lock().unwrap().len(), 1);
}
#[test]
fn recovery_expired_missing_and_tampered_snapshots_never_return_bytes() {
    for state in ["expired", "missing", "tampered"] {
        let (mut app, url) = submitted();
        if state == "expired" {
            app.gateway.recovery_now = Some(100 + crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS);
        } else {
            let store = FileDraftStore::new(
                app.gateway.recovery_root.join("snapshots"),
                DraftPolicy::default(),
            );
            let owner = store.owner_dir_for_username("alice@example.com");
            let dir = fs::read_dir(owner).unwrap().next().unwrap().unwrap().path();
            if state == "missing" {
                fs::remove_dir_all(dir).unwrap();
            } else {
                let blob = fs::read_dir(dir)
                    .unwrap()
                    .map(|p| p.unwrap().path())
                    .find(|p| p.extension().is_some_and(|e| e == "body"))
                    .unwrap();
                fs::write(blob, b"wrong").unwrap();
            }
        }
        let result = get(&app, &format!("{url}&recovery_attachment=0"));
        assert_eq!(
            result.response.status_code,
            match state {
                "expired" => 410,
                "missing" => 404,
                _ => 503,
            }
        );
        assert_ne!(result.response.body, BYTES);
        let body_result = get(&app, &format!("{url}&recovery_body=1"));
        assert_eq!(body_result.response.status_code, result.response.status_code);
        assert_ne!(body_result.response.body, SOURCE.as_bytes());
        let html = body_text(&get(&app, &url));
        assert!(html.contains(match state {
            "expired" => "Attempt recovery expired",
            "missing" => "Attempt recovery missing",
            _ => "Attempt recovery unavailable",
        }));
        assert!(!html.contains("id=\"attempt-body\""));
        assert_eq!(app.gateway.submitted.lock().unwrap().len(), 1);
    }
}
#[test]
fn recorded_save_and_send_keep_changed_second_form_readonly_without_mutation() {
    for first_path in ["/drafts/save", "/send"] {
        let app = app();
        let first = native_compose_request(
            &app,
            "POST",
            first_path,
            &authenticated_same_origin_headers(),
            &format!(
                "csrf_token={}&to=bob%40example.com&body=Original",
                StubGateway::validated_session().record.csrf_token
            ),
        );
        let form = parse_urlencoded_form(&first.body, 128, 100000).unwrap();
        let token = &form["send_intent"];
        assert_eq!(
            app.handle_request(&first, "127.0.0.1").response.status_code,
            303
        );
        let drafts = app.gateway.drafts.lock().unwrap().clone();
        let sends = app.gateway.submitted.lock().unwrap().clone();
        for second_path in ["/drafts/save", "/send"] {
            let mut body = String::new();
            for (name, value) in [
                (
                    "csrf_token",
                    StubGateway::validated_session().record.csrf_token.as_str(),
                ),
                ("send_intent", token),
                ("to", "bob@example.test"),
                ("bcc", "changed@example.test"),
                ("body", SOURCE),
            ] {
                body.push_str(&format!("--second\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
            }
            for name in ["first.txt", "second.txt"] {
                body.push_str(&format!("--second\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{name}\"\r\nContent-Type: text/plain\r\n\r\nexact\r\n"));
            }
            body.push_str("--second--\r\n");
            let mut headers = authenticated_same_origin_headers().to_vec();
            headers.push(("Content-Type", "multipart/form-data; boundary=second"));
            let result =
                app.handle_request(&request("POST", second_path, &headers, &body), "127.0.0.1");
            let html = body_text(&result);
            assert_eq!(result.response.status_code, 200);
            for exact in [
                escape_html(SOURCE).to_string(),
                "changed@example.test".into(),
                "first.txt (5 bytes)".into(),
                "second.txt (5 bytes)".into(),
                format!("/compose?receipt={token}"),
            ] {
                assert!(html.contains(&exact));
            }
            assert!(
                html.contains("This intent already has a recorded action")
                    && html.contains("readonly")
            );
            assert!(!html.contains("action=\"/send\"") && !html.contains("name=\"send_intent\""));
            assert_eq!(*app.gateway.drafts.lock().unwrap(), drafts);
            assert_eq!(*app.gateway.submitted.lock().unwrap(), sends);
        }
    }
}

#[test]
fn recovery_body_query_account_and_expiry_boundaries() {
    let (mut app, url) = submitted();
    for suffix in [
        "&recovery_body=0",
        "&recovery_body=01",
        "&recovery_body=",
        "&recovery_body=1&recovery_attachment=0",
        "&recovery_body=1&unexpected=x",
    ] {
        assert_eq!(
            get(&app, &format!("{url}{suffix}")).response.status_code,
            400
        );
    }
    assert_eq!(
        get(&app, "/compose?recovery_body=1").response.status_code,
        400
    );
    let mut foreign = request(
        "GET",
        &format!("{url}&recovery_body=1"),
        &authenticated_headers(),
        "",
    );
    foreign
        .headers
        .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
    assert_eq!(
        app.handle_request(&foreign, "127.0.0.1")
            .response
            .status_code,
        404
    );
    app.gateway.recovery_now = Some(100 + crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS);
    assert_eq!(
        get(&app, &format!("{url}&recovery_body=1"))
            .response
            .status_code,
        410
    );
    assert_eq!(app.gateway.submitted.lock().unwrap().len(), 1);
}
