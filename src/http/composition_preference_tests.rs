use super::*;
use crate::compose_format::BodyFormat;
use crate::composition_preferences::{CompositionPreferences, CompositionPreferencesStore};

pub(super) const LITERAL_SOURCE: &str = "**literal** *stars* __underlines__\n[x](https://example.test)\n[x](unsupported:target)\n- list prefix\n1. numbered prefix\n\\backslash <literal> & text";

struct Fixture {
    app: BrowserApp<StubGateway>,
    root: PathBuf,
    store: CompositionPreferencesStore,
    drafts: crate::draft::FileDraftStore,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "composition-preference-http-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = CompositionPreferencesStore::new(root.join("preferences"));
        let drafts = crate::draft::FileDraftStore::new(root.join("drafts"), DraftPolicy::default());
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                composition_preferences_store: Some(store.clone()),
                draft_store: Some(drafts.clone()),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self {
            app,
            root,
            store,
            drafts,
        }
    }
    fn perform(&self, method: &str, path: &str, body: &str, bob: bool) -> HandledHttpResponse {
        let mut req = request(method, path, &authenticated_same_origin_headers(), body);
        req.headers
            .insert("user-agent".into(), "CompositionLiteralSource".into());
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn preference(&self, mode: BodyFormat) {
        let form = format!(
            "csrf_token={}&default_body_format={}",
            StubGateway::validated_session().record.csrf_token,
            mode.as_str()
        );
        let result = self.perform("POST", "/settings/composition", &form, false);
        assert_eq!(result.response.status_code, 303, "{}", body_text(&result));
    }
    fn save(&self, body: &str, mode: BodyFormat) -> HandledHttpResponse {
        self.perform("POST", "/drafts/save", &format!("csrf_token={}&from=alice%40example.com&to=desk%40example.test&subject=Synthetic&body={}&body_format={}", StubGateway::validated_session().record.csrf_token, url_encode(body), mode.as_str()), false)
    }
    fn record_bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut records: Vec<_> = fs::read_dir(self.root.join("preferences"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        records.sort();
        records
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn assert_mode(response: &HandledHttpResponse, mode: BodyFormat) {
    assert_eq!(
        response.response.status_code,
        200,
        "{}",
        body_text(response)
    );
    assert!(body_text(response).contains(&format!("<option value=\"{}\" selected>", mode.as_str())));
}
fn textarea(response: &HandledHttpResponse) -> String {
    body_text(response)
        .split("id=\"compose-body\"")
        .nth(1)
        .unwrap()
        .split_once('>')
        .unwrap()
        .1
        .split("</textarea>")
        .next()
        .unwrap()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[test]
fn preference_http_persists_reopens_and_isolates_accounts() {
    let fixture = Fixture::new();
    assert_mode(
        &fixture.perform("GET", "/compose", "", false),
        BodyFormat::Plain,
    );
    fixture.preference(BodyFormat::Formatted);
    let reopened = CompositionPreferencesStore::new(fixture.root.join("preferences"));
    assert_eq!(
        reopened
            .load("alice@example.com")
            .unwrap()
            .default_body_format,
        BodyFormat::Formatted
    );
    assert_eq!(
        reopened.load("bob@example.com").unwrap(),
        CompositionPreferences::default()
    );
    assert_mode(
        &fixture.perform("GET", "/compose", "", false),
        BodyFormat::Formatted,
    );
    assert_mode(
        &fixture.perform("GET", "/compose", "", true),
        BodyFormat::Plain,
    );
    let bob_save = fixture.perform(
        "POST",
        "/settings/composition",
        &format!("csrf_token={}&default_body_format=plain", "c".repeat(64)),
        true,
    );
    assert_eq!(bob_save.response.status_code, 303);
    assert_eq!(
        reopened
            .load("alice@example.com")
            .unwrap()
            .default_body_format,
        BodyFormat::Formatted
    );
}

#[test]
fn preference_http_rejections_preserve_exact_record_bytes() {
    let fixture = Fixture::new();
    fixture.preference(BodyFormat::Formatted);
    let before = fixture.record_bytes();
    assert_eq!(before.len(), 1);
    let csrf = StubGateway::validated_session().record.csrf_token;
    for (form, status) in [
        (format!("csrf_token={csrf}&default_body_format=html"), 400),
        (
            format!("csrf_token={csrf}&default_body_format=plain&default_body_format=formatted"),
            400,
        ),
        (format!("csrf_token={csrf}"), 400),
        ("default_body_format=plain".into(), 403),
        ("csrf_token=wrong&default_body_format=plain".into(), 403),
        (format!("csrf_token={csrf}&unexpected=plain"), 400),
    ] {
        let response = fixture.perform("POST", "/settings/composition", &form, false);
        assert_eq!(response.response.status_code, status);
        assert_eq!(fixture.record_bytes(), before);
    }
}

#[test]
fn preference_http_source_compose_is_plain_and_preserves_literal_quotes() {
    let fixture = Fixture::new();
    fixture.preference(BodyFormat::Formatted);
    for mode in ["reply", "reply-all", "forward"] {
        let response = fixture.perform(
            "GET",
            &format!("/compose?mode={mode}&mailbox=INBOX&uid=9"),
            "",
            false,
        );
        assert_mode(&response, BodyFormat::Plain);
        assert!(body_text(&response).contains("preserve quoted message text"));
        let body = textarea(&response);
        for line in LITERAL_SOURCE.lines() {
            assert!(body.contains(line), "missing source line for {mode}");
        }
        let saved = fixture.save(&body, BodyFormat::Plain);
        assert_eq!(saved.response.status_code, 303, "{}", body_text(&saved));
        let location = location_header(&saved);
        let id = location.strip_prefix("/draft?id=").unwrap();
        let record = fixture
            .drafts
            .load("alice@example.com", id, 100)
            .unwrap()
            .unwrap();
        assert_eq!(record.request.body, body);
        assert_eq!(record.request.body_format, BodyFormat::Plain);
    }
}

#[test]
fn preference_http_source_compose_survives_unavailable_preference_store() {
    let fixture = Fixture::new();
    fixture.preference(BodyFormat::Formatted);
    let record = fixture.record_bytes().remove(0).0;
    fs::write(record, b"corrupt synthetic preference").unwrap();
    assert!(fixture.store.load("alice@example.com").is_err());
    assert_eq!(
        fixture
            .perform("GET", "/compose", "", false)
            .response
            .status_code,
        503
    );
    for mode in ["reply", "reply-all", "forward"] {
        let response = fixture.perform(
            "GET",
            &format!("/compose?mode={mode}&mailbox=INBOX&uid=9"),
            "",
            false,
        );
        assert_mode(&response, BodyFormat::Plain);
        assert!(body_text(&response).contains("preserve quoted message text"));
        assert!(textarea(&response).contains("[x](unsupported:target)"));
    }
}

#[test]
fn preference_http_existing_drafts_keep_their_stored_formats() {
    let fixture = Fixture::new();
    for (stored, default) in [
        (BodyFormat::Plain, BodyFormat::Formatted),
        (BodyFormat::Formatted, BodyFormat::Plain),
    ] {
        fixture.preference(default);
        let source = "**Stored source** [x](https://example.test)";
        let saved = fixture.save(source, stored);
        assert_eq!(saved.response.status_code, 303);
        let resumed = fixture.perform("GET", &location_header(&saved), "", false);
        assert_mode(&resumed, stored);
        assert_eq!(textarea(&resumed), source);
    }
}

#[test]
fn placement_http_native_save_moves_only_new_reply_blank_space_and_preserves_legacy_format_save() {
    let f = Fixture::new();
    let forward_before = textarea(&f.perform(
        "GET",
        "/compose?mode=forward&mailbox=INBOX&uid=9",
        "",
        false,
    ));
    let above = textarea(&f.perform("GET", "/compose?mode=reply&mailbox=INBOX&uid=9", "", false));
    let form=format!("csrf_token={}&default_body_format=formatted&reply_placement=below&return_section=composition",StubGateway::validated_session().record.csrf_token);
    let saved = f.perform("POST", "/settings/composition", &form, false);
    assert_eq!(saved.response.status_code, 303);
    assert_eq!(
        location_header(&saved),
        "/settings?section=composition&updated=1"
    );
    for mode in ["reply", "reply-all"] {
        let response = f.perform(
            "GET",
            &format!("/compose?mode={mode}&mailbox=INBOX&uid=9"),
            "",
            false,
        );
        assert_mode(&response, BodyFormat::Plain);
        assert_eq!(
            textarea(&response),
            format!("{}\n\n", above.strip_prefix("\n\n").unwrap())
        );
        assert!(body_text(&response).contains("cursor is not moved automatically"));
    }
    assert_eq!(
        textarea(&f.perform(
            "GET",
            "/compose?mode=forward&mailbox=INBOX&uid=9",
            "",
            false
        )),
        forward_before
    );
    f.preference(BodyFormat::Plain);
    assert_eq!(
        f.store.load("alice@example.com").unwrap().reply_placement,
        crate::composition_preferences::ReplyPlacement::Below
    );
    let before = f.record_bytes();
    for invalid in [
        form.replace("below", "bottom"),
        format!("{form}&reply_placement=above"),
        form.replace(
            "return_section=composition",
            "return_section=https%3A%2F%2Fexample.test",
        ),
    ] {
        assert_eq!(
            f.perform("POST", "/settings/composition", &invalid, false)
                .response
                .status_code,
            400
        );
        assert_eq!(f.record_bytes(), before);
    }
}

#[test]
fn composition_page_and_general_native_form_project_saved_defaults() {
    let f = Fixture::new();
    let form = format!(
        "csrf_token={}&default_body_format=formatted&reply_placement=below",
        StubGateway::validated_session().record.csrf_token
    );
    assert_eq!(
        f.perform("POST", "/settings/composition", &form, false)
            .response
            .status_code,
        303
    );
    for (section, format_id, placement_id) in [
        (
            "general",
            "general-default-format",
            "general-reply-placement",
        ),
        (
            "composition",
            "composition-format",
            "composition-reply-placement",
        ),
    ] {
        let response = f.perform("GET", &format!("/settings?section={section}"), "", false);
        assert_eq!(response.response.status_code, 200);
        let body = body_text(&response);
        assert!(body.contains(&format!("id=\"{format_id}\" name=\"default_body_format\"")));
        assert!(body.contains(&format!("id=\"{placement_id}\" name=\"reply_placement\"")));
        assert!(body.contains("<option value=\"formatted\" selected>"));
        assert!(body.contains("<option value=\"below\" selected>"));
        assert!(body.contains("href=\"/settings?section=composition\""));
        if section == "general" {
            assert!(body.contains("name=\"reply_placement\" form=\"general-composition-form\""));
            assert!(body
                .contains("form=\"general-composition-form\">Save composition defaults</button>"));
        } else {
            assert!(body.contains("name=\"return_section\" value=\"composition\""));
            assert!(body.contains("id=\"composition-signing\" disabled"));
            assert!(body.contains("Below does not move the cursor automatically"));
        }
    }
    let search = f.perform("GET", "/settings?q=placement", "", false);
    assert!(
        body_text(&search).contains("/settings?section=composition#composition-reply-placement")
    );
    let mut unavailable = Fixture::new();
    unavailable.app.gateway.composition_preferences_store = Some(CompositionPreferencesStore::new(
        unavailable.root.join("bad"),
    ));
    fs::write(unavailable.root.join("bad"), b"not a directory").unwrap();
    let response = unavailable.perform("GET", "/settings?section=composition", "", false);
    assert_eq!(response.response.status_code, 200);
    assert!(body_text(&response).contains("name=\"reply_placement\" disabled"));
}
