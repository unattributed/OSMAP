use super::*;
const COPY_ALICE: &str = "alice@example.com";
const COPY_BOB: &str = "bob@example.com";
struct CopyFixture {
    root: PathBuf,
    store: crate::sent_copy::Store,
    app: BrowserApp<StubGateway>,
}
impl CopyFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "sent-copy-route-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::sent_copy::Store::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                sent_copy_store: Some(store.clone()),
                sent_location_store: Some(crate::sent_location::Store::new(root.join("settings"))),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }
    fn get(&self) -> HandledHttpResponse {
        self.app.handle_request(
            &request(
                "GET",
                "/settings?section=copies",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        )
    }
    fn fields(&self) -> BTreeMap<String, String> {
        let page = self.get();
        assert_eq!(page.response.status_code, 200);
        let html = body_text(&page);
        let form = html
            .split("<form id=\"copies-sent-copy-form\"")
            .nth(1)
            .unwrap()
            .split("</form>")
            .next()
            .unwrap();
        assert!(form.contains("method=\"post\" action=\"/settings/sent-copy\""));
        let mut result = BTreeMap::new();
        for name in ["csrf_token", "expected_revision"] {
            let value = form
                .split(&format!("name=\"{name}\" value=\""))
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            result.insert(name.into(), value.into());
        }
        assert!(form.contains("<select id=\"copies-save-sent\" name=\"save_sent\""));
        result.insert("save_sent".into(), "off".into());
        result
    }
    fn post(&self, fields: &BTreeMap<String, String>, bob: bool) -> HandledHttpResponse {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.raw_post(&body, bob)
    }
    fn raw_post(&self, body: &str, bob: bool) -> HandledHttpResponse {
        let mut req = request(
            "POST",
            "/settings/sent-copy",
            &authenticated_same_origin_headers(),
            body,
        );
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
}
impl Drop for CopyFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn sent_copy_generated_settings_form_persists_off_reload_and_stale_cas() {
    let f = CopyFixture::new();
    let fields = f.fields();
    let first = f.post(&fields, false);
    assert_eq!(first.response.status_code, 303);
    assert_eq!(
        location_header(&first),
        "/settings?section=copies&updated=1"
    );
    assert_eq!(
        f.store.load(COPY_ALICE).unwrap(),
        crate::sent_copy::Preference {
            revision: 1,
            save_sent: false
        }
    );
    let reloaded = f.get();
    let html = body_text(&reloaded);
    assert!(html.contains("<option value=\"off\" selected>Off</option>"));
    assert!(html.contains("name=\"expected_revision\" value=\"1\""));
    assert!(html.contains("<select id=\"copies-sent-location\" name=\"mailbox_name\""));
    assert!(!html.contains("Sent (fixed)"));
    assert!(html.contains("id=\"copies-draft-location\" disabled"));
    assert!(!html.contains("OSMAP drafts (fixed)"));
    assert_eq!(f.post(&fields, false).response.status_code, 409);
    assert!(!f.store.load(COPY_ALICE).unwrap().save_sent);
    assert_eq!(
        f.store.load(COPY_BOB).unwrap(),
        crate::sent_copy::Preference::default()
    );
    let mut latest = f.fields();
    latest.insert("save_sent".into(), "on".into());
    assert_eq!(f.post(&latest, false).response.status_code, 303);
    assert!(f.store.load(COPY_ALICE).unwrap().save_sent);
}
#[test]
fn sent_copy_settings_csrf_strict_values_unknown_and_duplicate_refuse_without_reset() {
    let f = CopyFixture::new();
    let fields = f.fields();
    for (key, value, status) in [
        ("csrf_token", "bad", 403),
        ("expected_revision", "00", 400),
        ("expected_revision", "18446744073709551616", 400),
        ("save_sent", "false", 400),
        ("save_sent", "on\r\n", 400),
        ("account", "bob@example.com", 400),
    ] {
        let mut bad = fields.clone();
        bad.insert(key.into(), value.into());
        assert_eq!(f.post(&bad, false).response.status_code, status);
        assert_eq!(
            f.store.load(COPY_ALICE).unwrap(),
            crate::sent_copy::Preference::default()
        );
    }
    let mut missing = fields.clone();
    missing.remove("save_sent");
    assert_eq!(f.post(&missing, false).response.status_code, 400);
    let duplicate = format!(
        "csrf_token={}&expected_revision=0&save_sent=off&save_sent=on",
        fields["csrf_token"]
    );
    assert_eq!(f.raw_post(&duplicate, false).response.status_code, 400);
    let unauth = f.app.handle_request(
        &request(
            "POST",
            "/settings/sent-copy",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            "expected_revision=0&save_sent=off",
        ),
        "127.0.0.1",
    );
    assert_eq!(unauth.response.status_code, 303);
    assert_eq!(
        f.store.load(COPY_ALICE).unwrap(),
        crate::sent_copy::Preference::default()
    );
}
#[test]
fn sent_copy_settings_two_accounts_and_unrelated_sections_are_isolated() {
    let f = CopyFixture::new();
    let alice = f.fields();
    assert_eq!(f.post(&alice, false).response.status_code, 303);
    let before = f.store.load(COPY_ALICE).unwrap();
    let mut bob = alice.clone();
    bob.insert("csrf_token".into(), "c".repeat(64));
    bob.insert("save_sent".into(), "on".into());
    assert_eq!(f.post(&alice, true).response.status_code, 403);
    assert_eq!(f.post(&bob, true).response.status_code, 303);
    assert_eq!(f.store.load(COPY_ALICE).unwrap(), before);
    assert_eq!(
        f.store.load(COPY_BOB).unwrap(),
        crate::sent_copy::Preference {
            revision: 1,
            save_sent: true
        }
    );
    let unrelated = f.root.join("settings").join("synthetic-legacy.settings");
    std::fs::write(&unrelated, b"content=plain\narchive=Archive\n").unwrap();
    let bytes = std::fs::read(&unrelated).unwrap();
    let mut latest = f.fields();
    latest.insert("save_sent".into(), "on".into());
    assert_eq!(f.post(&latest, false).response.status_code, 303);
    assert_eq!(std::fs::read(unrelated).unwrap(), bytes);
}
#[test]
fn sent_copy_settings_corruption_is_unavailable_and_not_automatic_default_or_reset() {
    let f = CopyFixture::new();
    let fields = f.fields();
    assert_eq!(f.post(&fields, false).response.status_code, 303);
    let record = crate::private_account_file::PrivateAccountFile::new(
        f.root.join("settings"),
        "osmap-sent-copy-v1",
        512,
    );
    record
        .lock(COPY_ALICE)
        .unwrap()
        .write(b"corrupt synthetic record")
        .unwrap();
    assert_eq!(
        f.store.load(COPY_ALICE),
        Err(crate::sent_copy::Error::Unavailable)
    );
    let html = body_text(&f.get());
    assert!(html.contains("id=\"copies-save-sent\" disabled"));
    let mut next = fields;
    next.insert("expected_revision".into(), "1".into());
    assert_eq!(f.post(&next, false).response.status_code, 503);
    assert_eq!(
        record.read(COPY_ALICE).unwrap().unwrap(),
        b"corrupt synthetic record"
    );
}
