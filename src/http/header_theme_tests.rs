use super::*;

struct Fixture {
    app: BrowserApp<StubGateway>,
    root: PathBuf,
    appearance: AppearanceStore,
    drafts: crate::draft::FileDraftStore,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "header-theme-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let appearance = AppearanceStore::new(root.join("appearance"));
        appearance
            .save("alice@example.com", AppearancePreference::Light)
            .unwrap();
        let drafts = crate::draft::FileDraftStore::new(root.join("drafts"), DraftPolicy::default());
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                appearance_store: Some(appearance.clone()),
                draft_store: Some(drafts.clone()),
                ..StubGateway::default()
            },
        );
        Self {
            app,
            root,
            appearance,
            drafts,
        }
    }
    fn perform(&self, method: &str, path: &str, body: &str) -> HandledHttpResponse {
        self.app.handle_request(
            &request(method, path, &authenticated_same_origin_headers(), body),
            "127.0.0.1",
        )
    }
    fn theme(&self, destination: &str) -> HandledHttpResponse {
        self.perform(
            "POST",
            "/settings/appearance",
            &format!(
                "csrf_token={}&appearance=dark&return_to={}",
                StubGateway::validated_session().record.csrf_token,
                url_encode(destination)
            ),
        )
    }
    fn save(
        &self,
        fields: &[(&str, &str)],
        files: &[(&str, &str)],
        ua: &str,
    ) -> HandledHttpResponse {
        let csrf = StubGateway::validated_session().record.csrf_token;
        let mut body = String::new();
        for (name, value) in [
            ("csrf_token", csrf.as_str()),
            ("to", "desk@example.test"),
            ("cc", "copy@example.test"),
            ("bcc", "private@example.test"),
            ("subject", "Synthetic exact subject"),
            ("body", "Exact 🦊 source **literal**"),
            ("body_format", "plain"),
        ]
        .into_iter()
        .chain(fields.iter().copied())
        {
            body.push_str(&format!("--theme-test\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        for (name, value) in files {
            body.push_str(&format!("--theme-test\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{name}\"\r\nContent-Type: text/plain\r\n\r\n{value}\r\n"));
        }
        body.push_str("--theme-test--\r\n");
        let mut req = request(
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &body,
        );
        req.headers.insert(
            "content-type".into(),
            "multipart/form-data; boundary=theme-test".into(),
        );
        req.headers.insert("user-agent".into(), ua.into());
        if req.method == HttpMethod::Post && matches!(req.path.as_str(), "/send" | "/drafts/save") {
            add_native_compose_intent(&self.app, &mut req);
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn appearance_record(&self) -> PathBuf {
        fs::read_dir(self.root.join("appearance"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|v| v == "appearance"))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn header_theme_saves_current_fields_new_upload_and_attachment_removal_before_theme() {
    let f = Fixture::new();
    let saved = f.save(
        &[],
        &[("remove.txt", "remove"), ("keep.txt", "keep")],
        "Firefox/Test",
    );
    assert_eq!(saved.response.status_code, 303);
    let location = location_header(&saved);
    let id = location.strip_prefix("/draft?id=").unwrap();
    let themed = f.save(
        &[
            ("draft_id", id),
            ("draft_revision", "1"),
            ("remove_saved_attachment_0", "1"),
            ("compose_action", "theme-dark"),
        ],
        &[("new.txt", "new upload")],
        "Firefox/Test",
    );
    assert_eq!(themed.response.status_code, 303, "{}", body_text(&themed));
    assert_eq!(location_header(&themed), location);
    let record = f
        .drafts
        .load("alice@example.com", id, 100)
        .unwrap()
        .unwrap();
    assert_eq!(record.request.body, "Exact 🦊 source **literal**");
    assert_eq!(record.request.cc_text, "copy@example.test");
    assert_eq!(record.request.bcc_text, "private@example.test");
    assert_eq!(
        record
            .request
            .attachments
            .iter()
            .map(|a| (&*a.filename, a.body.as_slice()))
            .collect::<Vec<_>>(),
        vec![
            ("keep.txt", b"keep".as_slice()),
            ("new.txt", b"new upload".as_slice())
        ]
    );
    assert_eq!(
        f.appearance.load("alice@example.com").unwrap(),
        AppearancePreference::Dark
    );
    assert_eq!(
        f.appearance.load("bob@example.com").unwrap(),
        AppearancePreference::System
    );
    assert!(f.app.gateway.submitted.lock().unwrap().is_empty());
}

#[test]
fn header_theme_conflict_and_unconfirmed_draft_do_not_write_appearance() {
    for unconfirmed in [false, true] {
        let f = Fixture::new();
        let before = fs::read(f.appearance_record()).unwrap();
        let saved = f.save(&[], &[], "Firefox/Test");
        let location = location_header(&saved);
        let id = location.strip_prefix("/draft?id=").unwrap();
        let response = f.save(
            &[
                ("draft_id", id),
                ("draft_revision", if unconfirmed { "1" } else { "99" }),
                ("compose_action", "theme-dark"),
            ],
            &[("new.txt", "unsaved")],
            if unconfirmed {
                "OSMAP/DraftSaveUnconfirmed"
            } else {
                "Firefox/Test"
            },
        );
        assert_eq!(
            response.response.status_code,
            if unconfirmed { 503 } else { 409 }
        );
        assert_eq!(fs::read(f.appearance_record()).unwrap(), before);
        assert!(body_text(&response).contains("Exact 🦊 source **literal**"));
        assert!(!response
            .response
            .headers
            .iter()
            .any(|(k, _)| k == "Set-Cookie"));
        if unconfirmed {
            assert!(body_text(&response).contains("disabled data-compose-theme"));
        }
    }
}

#[test]
fn header_theme_failed_appearance_after_save_links_confirmed_draft() {
    let f = Fixture::new();
    fs::write(f.appearance_record(), b"corrupt synthetic preference").unwrap();
    let response = f.save(
        &[("compose_action", "theme-dark")],
        &[("new.txt", "accepted upload")],
        "Firefox/Test",
    );
    assert_eq!(response.response.status_code, 503);
    let records = f.drafts.list("alice@example.com", 100).unwrap();
    assert_eq!(records.len(), 1);
    let record = f
        .drafts
        .load("alice@example.com", &records[0].draft_id, 100)
        .unwrap()
        .unwrap();
    assert_eq!(record.request.attachments[0].body, b"accepted upload");
    let html = body_text(&response);
    assert!(html.contains("Your draft was saved"));
    assert!(html.contains(&format!("/draft?id={}", record.draft_id)));
    assert!(!response
        .response
        .headers
        .iter()
        .any(|(k, _)| k == "Set-Cookie"));
}

#[test]
fn header_theme_invalid_returns_never_change_record_and_valid_queries_survive() {
    let f = Fixture::new();
    let before = fs::read(f.appearance_record()).unwrap();
    for target in [
        "https://example.test/",
        "//example.test/",
        "/logout",
        "/drafts?filter=wrong",
        "/draft?id=a&id=b",
        "/message?mailbox=INBOX&uid=9&return_to=https%3A%2F%2Fexample.test",
        "/draft?id=%0d%0aLocation%3Aevil",
    ] {
        assert_eq!(f.theme(target).response.status_code, 400, "{target}");
        assert_eq!(fs::read(f.appearance_record()).unwrap(), before);
    }
    for target in ["/drafts?filter=attachments&sort=oldest&q=report","/message?mailbox=INBOX&uid=9&mailbox_guid=box&message_guid=msg&return_to=%2Fmailbox%3Fname%3DINBOX%26filter%3Dunread","/search?q=report&scope=all&filter=unread&page=2"] {
        let expected=super::super::header_theme::safe_return(target).unwrap();
        let response=f.theme(target); assert_eq!(response.response.status_code,303); assert_eq!(location_header(&response),expected);
        let page=f.perform("GET",target,""); assert_eq!(page.response.status_code,200);
        assert!(body_text(&page).contains(&format!("value=\"{}\" data-header-return",escape_html(&expected))));
    }
}

#[test]
fn header_theme_settings_and_recovery_are_disabled_but_compose_posts_its_form() {
    let f = Fixture::new();
    for current in ["settings-general", "settings-appearance", "compose-result"] {
        let html = crate::http_ui::app_header("alice@example.com", "synthetic", current);
        assert_eq!(
            html.matches("type=\"submit\" disabled data-header-theme")
                .count(),
            2
        );
        assert!(!html.contains("data-header-return") && !html.contains("data-compose-theme"));
    }
    let page = f.perform("GET", "/compose", "");
    let html = body_text(&page);
    assert_eq!(
        html.matches("form=\"compose-form\" formaction=\"/drafts/save\"")
            .count(),
        2
    );
    let req = request(
        "POST",
        "/send",
        &authenticated_same_origin_headers(),
        &format!(
            "csrf_token={}&to=desk%40example.test&body=Retained",
            StubGateway::validated_session().record.csrf_token
        ),
    );
    let mut req = req;
    req.headers
        .insert("user-agent".into(), "OSMAP/SendUnconfirmed".into());
    add_native_compose_intent(&f.app, &mut req);
    let result = f.app.handle_request(&req, "127.0.0.1");
    let html = body_text(&result);
    assert!(!html.contains("data-compose-theme"));
    assert!(html.contains("Keep this page open"));
    assert!(html.contains("title=\"Compose\" aria-current=\"page\""));
}
