use super::*;
use crate::compose_format::BodyFormat;

struct Fixture {
    app: BrowserApp<StubGateway>,
    root: PathBuf,
    store: crate::draft::FileDraftStore,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-format-http-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::draft::FileDraftStore::new(&root, DraftPolicy::default());
        let gateway = StubGateway {
            draft_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        };
        Self {
            app: BrowserApp::new(HttpPolicy::default(), gateway),
            root,
            store,
        }
    }

    // Deliberately use native multipart bytes, including CRLF textarea content,
    // rather than URL encoding away the DOM/submission offset distinction.
    fn post(&self, path: &str, fields: &[(&str, &str)], attachment: bool) -> HandledHttpResponse {
        let mut body = String::new();
        let csrf = StubGateway::validated_session().record.csrf_token;
        for (name, value) in [
            ("csrf_token", csrf.as_str()),
            ("from", "alice@example.com"),
            ("to", "desk@example.test"),
            ("subject", "Synthetic formatting regression"),
        ]
        .into_iter()
        .chain(fields.iter().copied())
        {
            body.push_str(&format!("--format-test\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
        }
        if attachment {
            body.push_str("--format-test\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"public.txt\"\r\nContent-Type: text/plain\r\n\r\nSynthetic retained file\r\n");
        }
        body.push_str("--format-test--\r\n");
        let mut req = request("POST", path, &authenticated_same_origin_headers(), &body);
        req.headers.insert(
            "content-type".into(),
            "multipart/form-data; boundary=format-test".into(),
        );
        self.app.handle_request(&req, "127.0.0.1")
    }

    fn resumed(&self, saved: &HandledHttpResponse) -> String {
        assert_eq!(saved.response.status_code, 303, "{}", body_text(saved));
        let response = self.app.handle_request(
            &request("GET", &location_header(saved), &authenticated_headers(), ""),
            "127.0.0.1",
        );
        assert_eq!(response.response.status_code, 200);
        body_text(&response)
    }

    fn saved(&self, response: &HandledHttpResponse) -> crate::draft::DraftRecord {
        let location = location_header(response);
        let id = location
            .strip_prefix("/draft?id=")
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        self.store
            .load("alice@example.com", id, 100)
            .unwrap()
            .unwrap()
    }

    fn assert_no_mutation(&self) {
        assert!(self.app.gateway.submitted.lock().unwrap().is_empty());
        assert!(self
            .store
            .list("alice@example.com", 100)
            .unwrap()
            .is_empty());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn native_selection_after_crlf_and_astral_text_saves_correct_range_and_file() {
    let fixture = Fixture::new();
    let saved = fixture.post(
        "/drafts/save",
        &[
            ("body", "Lead\r\nA🦊B\r\nTail"),
            ("body_format", "plain"),
            ("compose_action", "format-bold"),
            ("format_start", "6"),
            ("format_end", "9"),
        ],
        true,
    );
    let html = fixture.resumed(&saved);
    let draft = fixture.saved(&saved);
    assert_eq!(draft.request.body, "Lead\nA**🦊B**\nTail");
    assert_eq!(draft.request.body_format, BodyFormat::Formatted);
    assert_eq!(draft.request.attachments.len(), 1);
    assert_eq!(
        draft.request.attachments[0].body,
        b"Synthetic retained file"
    );
    assert!(html.contains("<option value=\"formatted\" selected>"));
    assert!(html.contains("<div>A<strong>🦊B</strong></div>"));
    assert!(html.contains("Message preview"));
    assert!(html.contains("public.txt"));
    assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
}

#[test]
fn list_selection_retains_newline_and_numbered_action_previews_every_item() {
    for (action, end, expected_source, expected_html) in [
        (
            "format-bullets",
            "6",
            "- first\nsecond",
            "<ul><li>first</li></ul><div>second</div>",
        ),
        (
            "format-numbers",
            "6",
            "1. first\nsecond",
            "<ol><li>first</li></ol><div>second</div>",
        ),
        (
            "format-numbers",
            "12",
            "1. first\n2. second",
            "<ol><li>first</li><li>second</li></ol>",
        ),
    ] {
        let fixture = Fixture::new();
        let saved = fixture.post(
            "/drafts/save",
            &[
                ("body", "first\r\nsecond"),
                ("body_format", "plain"),
                ("compose_action", action),
                ("format_start", "0"),
                ("format_end", end),
            ],
            false,
        );
        let html = fixture.resumed(&saved);
        assert_eq!(fixture.saved(&saved).request.body, expected_source);
        assert!(html.contains(expected_html), "{action}: {html}");
        assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
    }
}

#[test]
fn invalid_formatted_send_retains_exact_source_and_mode_without_submission() {
    let fixture = Fixture::new();
    let source = "**Keep** 🦊\r\n[unsafe](javascript:alert)\r\n<literal>";
    let response = fixture.post(
        "/send",
        &[("body", source), ("body_format", "formatted")],
        false,
    );
    assert_eq!(response.response.status_code, 400);
    let html = body_text(&response);
    assert!(html.contains(&format!(
        ">{}</textarea>",
        crate::http_support::escape_html(source)
    )));
    assert!(html.contains("<option value=\"formatted\" selected>"));
    assert!(html.contains("name=\"to\" value=\"desk@example.test\""));
    fixture.assert_no_mutation();
}

#[test]
fn unsupported_body_modes_never_save_or_submit() {
    let fixture = Fixture::new();
    for path in ["/drafts/save", "/send"] {
        for mode in ["html", "Formatted", "", " formatted"] {
            let response = fixture.post(
                path,
                &[("body", "Keep this source"), ("body_format", mode)],
                false,
            );
            assert_eq!(response.response.status_code, 400, "{path} {mode:?}");
            fixture.assert_no_mutation();
        }
    }
}

#[test]
fn utf16_selection_inside_surrogate_pair_refuses_without_saving_or_losing_source() {
    let fixture = Fixture::new();
    let source = "Lead\r\nA🦊B\r\nTail";
    let response = fixture.post(
        "/drafts/save",
        &[
            ("body", source),
            ("body_format", "plain"),
            ("compose_action", "format-italic"),
            ("format_start", "7"),
            ("format_end", "9"),
        ],
        false,
    );
    assert_eq!(response.response.status_code, 400);
    assert!(body_text(&response).contains(&format!(
        ">{}</textarea>",
        crate::http_support::escape_html(source)
    )));
    fixture.assert_no_mutation();
}

#[test]
fn invalid_image_retains_surrounding_fields_and_never_partially_saves_sibling_file() {
    let fixture = Fixture::new();
    let saved = fixture.post(
        "/drafts/save",
        &[
            ("body", "Previously stored source"),
            ("body_format", "plain"),
        ],
        true,
    );
    assert_eq!(saved.response.status_code, 303);
    let original = fixture.saved(&saved);
    let source = "**Retain** 🦊\r\n<literal before image>";
    let csrf = StubGateway::validated_session().record.csrf_token;
    for path in ["/send", "/drafts/save"] {
        for existing in [false, true] {
            let mut body = String::new();
            for (name, value) in [
                ("csrf_token", csrf.as_str()),
                ("from", "alice@example.com"),
                ("to", "desk@example.test"),
                ("body", source),
            ] {
                body.push_str(&format!("--image-refusal\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
            }
            // A valid sibling occurs before the invalid image. Neither may be
            // published, even when the parser continues to later text fields.
            body.push_str("--image-refusal\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"sibling.txt\"\r\nContent-Type: text/plain\r\n\r\nUnsaved sibling\r\n");
            body.push_str("--image-refusal\r\nContent-Disposition: form-data; name=\"image_attachment\"; filename=\"fake.png\"\r\nContent-Type: image/png\r\n\r\nThis is not an image\r\n");
            for (name, value) in [
                ("body_format", "formatted"),
                ("subject", "Retained after invalid image"),
            ] {
                body.push_str(&format!("--image-refusal\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
            }
            if existing {
                for (name, value) in [
                    ("draft_id", original.draft_id.clone()),
                    ("draft_revision", original.revision.unwrap().to_string()),
                ] {
                    body.push_str(&format!("--image-refusal\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
                }
            }
            body.push_str("--image-refusal--\r\n");
            let mut req = request("POST", path, &authenticated_same_origin_headers(), &body);
            req.headers.insert(
                "content-type".into(),
                "multipart/form-data; boundary=image-refusal".into(),
            );
            let response = fixture.app.handle_request(&req, "127.0.0.1");
            assert_eq!(
                response.response.status_code, 400,
                "{path} existing={existing}"
            );
            let html = body_text(&response);
            assert!(html.contains(&format!(
                ">{}</textarea>",
                crate::http_support::escape_html(source)
            )));
            assert!(html.contains("<option value=\"formatted\" selected>"));
            assert!(html.contains("name=\"subject\" value=\"Retained after invalid image\""));
            assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
            assert_eq!(
                fixture.store.list("alice@example.com", 100).unwrap().len(),
                1
            );
            assert_eq!(
                fixture
                    .store
                    .load("alice@example.com", &original.draft_id, 100)
                    .unwrap()
                    .unwrap(),
                original
            );
        }
    }
}

#[test]
fn native_whole_body_multiline_emphasis_preserves_lines_and_plain_alternative() {
    for (action, marker, element) in [
        ("format-bold", "**", "strong"),
        ("format-italic", "*", "em"),
        ("format-underline", "__", "u"),
    ] {
        let fixture = Fixture::new();
        // No selection fields exercises the documented native whole-message
        // fallback, including a blank line, Unicode and final newline.
        let saved = fixture.post(
            "/drafts/save",
            &[
                ("body", "first\r\n\r\nsecond 🦊\r\n"),
                ("body_format", "plain"),
                ("compose_action", action),
            ],
            false,
        );
        let html = fixture.resumed(&saved);
        let draft = fixture.saved(&saved);
        let expected_source = format!("{marker}first{marker}\n\n{marker}second 🦊{marker}\n");
        assert_eq!(draft.request.body, expected_source, "{action}");
        assert_eq!(draft.request.body_format, BodyFormat::Formatted);
        let expected_html = format!("<div><{element}>first</{element}></div><div><br></div><div><{element}>second 🦊</{element}></div><div><br></div>");
        assert!(html.contains(&expected_html), "{action}: {html}");
        let alternatives = crate::compose_format::render(&draft.request.body).unwrap();
        assert_eq!(alternatives.html, expected_html);
        assert_eq!(alternatives.plain, "first\n\nsecond 🦊\n");
        assert!(html.contains("<pre dir=\"auto\">first\n\nsecond 🦊\n</pre>"));
        assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
    }
}

#[test]
fn partial_list_selection_formats_complete_lines_without_joining_neighbours() {
    for (action, expected) in [
        (
            "format-bullets",
            "before\n- first selected line\n- second selected line\nafter",
        ),
        (
            "format-numbers",
            "before\n1. first selected line\n2. second selected line\nafter",
        ),
    ] {
        let mut form = BTreeMap::from([
            ("compose_action".to_string(), action.to_string()),
            (
                "body".to_string(),
                "before\nfirst selected line\nsecond selected line\nafter".to_string(),
            ),
            ("format_start".to_string(), "13".to_string()),
            ("format_end".to_string(), "32".to_string()),
        ]);
        crate::http::compose_actions::apply_format(&mut form).unwrap();
        assert_eq!(form["body"], expected);
        let rendered = crate::compose_format::render(&form["body"]).unwrap();
        assert_eq!(rendered.html.matches("<li>").count(), 2);
        assert!(rendered.html.starts_with("<div>before</div>"));
        assert!(rendered.html.ends_with("<div>after</div>"));
    }
}
