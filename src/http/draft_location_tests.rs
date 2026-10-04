use super::*;
use crate::draft_location::{Location, Preference, Store};
struct Fixture {
    root: PathBuf,
    store: Store,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "draft-location-http-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = Store::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                draft_location_store: Some(store.clone()),
                draft_store: Some(crate::draft::FileDraftStore::new(
                    root.join("drafts"),
                    crate::draft::DraftPolicy::default(),
                )),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }
    fn get(&self, path: &str) -> HandledHttpResponse {
        self.app.handle_request(
            &request("GET", path, &authenticated_headers(), ""),
            "127.0.0.1",
        )
    }
    fn fields(&self) -> BTreeMap<String, String> {
        let response = self.get("/settings?section=copies");
        assert_eq!(response.response.status_code, 200);
        let html = body_text(&response);
        let form = html
            .split("<form id=\"copies-draft-location-form\"")
            .nth(1)
            .unwrap()
            .split("</form>")
            .next()
            .unwrap();
        assert!(form.contains("action=\"/settings/draft-location\""));
        let mut fields = BTreeMap::new();
        for name in ["csrf_token", "expected_revision"] {
            let v = form
                .split(&format!("name=\"{name}\" value=\""))
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            fields.insert(name.into(), v.into());
        }
        fields.insert("location".into(), "working".into());
        fields
    }
    fn post(&self, fields: &BTreeMap<String, String>, bob: bool) -> HandledHttpResponse {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = request(
            "POST",
            "/settings/draft-location",
            &authenticated_same_origin_headers(),
            &body,
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
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn draft_location_generated_choice_persists_reading_mirror_and_stale_cas() {
    let f = Fixture::new();
    let fields = f.fields();
    assert_eq!(f.post(&fields, false).response.status_code, 303);
    assert_eq!(
        Store::new(f.root.join("settings"))
            .load("alice@example.com")
            .unwrap(),
        Preference {
            revision: 1,
            location: Location::Working
        }
    );
    let html = body_text(&f.get("/settings?section=copies"));
    assert!(html.contains("<option value=\"working\" selected>Working drafts</option>"));
    let reading = body_text(&f.get("/settings?section=reading"));
    assert!(reading.contains("id=\"reading-drafts-folder\" value=\"Working drafts\" readonly"));
    assert_eq!(f.post(&fields, false).response.status_code, 409);
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        Preference::default()
    );
    assert!(f.root.join("drafts/.locations/working").is_dir());
}
#[test]
fn draft_location_csrf_paths_foreign_and_strict_fields_never_reset_choice() {
    let f = Fixture::new();
    let fields = f.fields();
    assert_eq!(f.post(&fields, false).response.status_code, 303);
    for (key, value, status) in [
        ("csrf_token", "bad", 403),
        ("location", "/tmp", 400),
        ("location", "../working", 400),
        ("location", "Working", 400),
        ("expected_revision", "00", 400),
        ("path", "working", 400),
    ] {
        let mut bad = f.fields();
        bad.insert(key.into(), value.into());
        assert_eq!(f.post(&bad, false).response.status_code, status);
        assert_eq!(f.store.load("alice@example.com").unwrap().revision, 1);
    }
    assert_eq!(f.post(&f.fields(), true).response.status_code, 403);
    assert_eq!(
        f.store.load("bob@example.com").unwrap(),
        Preference::default()
    );
}
#[cfg(unix)]
#[test]
fn draft_location_unsafe_namespace_save_preserves_preference_and_authoring() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let fields = f.fields();
    std::fs::create_dir_all(f.root.join("drafts")).unwrap();
    std::fs::set_permissions(
        f.root.join("drafts"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    symlink(&f.root, f.root.join("drafts/.locations")).unwrap();
    assert_eq!(f.post(&fields, false).response.status_code, 503);
    assert_eq!(
        f.store.load("alice@example.com").unwrap(),
        Preference::default()
    );
    assert!(!f.root.join("working").exists());
}

#[test]
fn draft_location_missing_working_retains_generated_cas_recovery_without_save_recreation() {
    let f = Fixture::new();
    assert_eq!(f.post(&f.fields(), false).response.status_code, 303);
    let working = f.root.join("drafts/.locations/working");
    let parked = f.root.join("parked-working");
    std::fs::rename(&working, &parked).unwrap();
    let copies = body_text(&f.get("/settings?section=copies"));
    assert!(copies.contains("Saved draft location is unavailable."));
    assert!(copies.contains("<option value=\"working\" selected>Working drafts</option>"));
    let fields = f.fields();
    assert_eq!(fields["expected_revision"], "1");
    assert!(!working.exists()); // GET is read-only.
    let reading = body_text(&f.get("/settings?section=reading"));
    assert!(reading.contains("value=\"Working drafts\" readonly"));
    assert!(reading.contains("Saved draft location is unavailable"));
    let mut default = fields.clone();
    default.insert("location".into(), "default".into());
    assert_eq!(f.post(&default, false).response.status_code, 503);
    assert!(!working.exists());
    assert_eq!(
        f.store.load("alice@example.com").unwrap().location,
        Location::Working
    );
    let current = f.fields(); // Explicit current-CAS qualification may initialize it.
    assert_eq!(f.post(&current, false).response.status_code, 303);
    assert!(working.is_dir());
    assert!(parked.is_dir()); // No migration or deletion of existing private drafts.
}

#[test]
fn draft_location_stale_generated_request_never_initializes_working() {
    let f = Fixture::new();
    let stale = f.fields();
    let mut default = stale.clone();
    default.insert("location".into(), "default".into());
    assert_eq!(f.post(&default, false).response.status_code, 303);
    assert!(!f.root.join("drafts/.locations").exists());
    assert_eq!(f.post(&stale, false).response.status_code, 409);
    assert!(!f.root.join("drafts/.locations").exists());
    assert_eq!(
        f.store.load("alice@example.com").unwrap(),
        Preference {
            revision: 1,
            location: Location::Default
        }
    );
}

#[test]
fn draft_location_post_rejects_query_authority_and_oversize_body() {
    let f = Fixture::new();
    let fields = f.fields();
    let body = fields
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    for (target, submitted) in [
        ("/settings/draft-location?location=default", body),
        ("/settings/draft-location", "x".repeat(2049)),
    ] {
        let mut req = request(
            "POST",
            target,
            &authenticated_same_origin_headers(),
            &submitted,
        );
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        assert_eq!(
            f.app.handle_request(&req, "127.0.0.1").response.status_code,
            400
        );
        assert_eq!(
            f.store.load("alice@example.com").unwrap(),
            Preference::default()
        );
        assert!(!f.root.join("drafts/.locations").exists());
    }
}
