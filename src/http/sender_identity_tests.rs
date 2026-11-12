#[cfg(unix)]
#[test]
fn sender_identity_generated_authorized_form_selects_default_and_preserves_captured_draft() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = std::path::Path::new("/tmp").join(format!(
        "osmap-authorized-identities-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let authority = root.join("authorized.json");
    fs::write(&authority, br#"{"version":1,"accounts":[{"account":"alice@example.com","revision":1,"identities":[{"id":"desk","address":"desk@example.test"}]}]}"#).unwrap();
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).unwrap();
    let provider = crate::sender_authority::Provider::new(
        Some(authority.clone()),
        fs::metadata(&authority).unwrap().uid(),
    );
    let profile = crate::identity_preferences::IdentityPreferencesStore::new(root.join("settings"));
    assert_eq!(
        provider
            .snapshot("alice@example.com")
            .unwrap()
            .identities
            .len(),
        2
    );
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            identity_preferences_store: Some(profile.clone()),
            draft_store: Some(crate::draft::FileDraftStore::new(
                root.join("drafts"),
                crate::draft::DraftPolicy::default(),
            )),
            browser_fixture_accounts: true,
            sender_authority: provider,
            ..StubGateway::default()
        },
    );
    let old_form = format!(
        "csrf_token={}&to=receiver%40example.test&subject=Canonical&body=Public+draft",
        StubGateway::validated_session().record.csrf_token
    );
    let old_saved = app.handle_request(
        &native_compose_request(
            &app,
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &old_form,
        ),
        "127.0.0.1",
    );
    assert_eq!(old_saved.response.status_code, 303);
    let id = location_header(&old_saved)
        .trim_start_matches("/draft?id=")
        .to_owned();
    let drafts = crate::draft::FileDraftStore::new(
        root.join("drafts"),
        crate::draft::DraftPolicy::default(),
    );
    let before = drafts.load("alice@example.com", &id, 100).unwrap().unwrap();
    assert!(before.request.sender_identity.sender().is_none());
    let page = app.handle_request(
        &request(
            "GET",
            "/settings?section=identity",
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(page.response.status_code, 200);
    let html = body_text(&page);
    assert!(
        html.contains("id=\"sender-primary-form\""),
        "actual Identity GET must expose its native authorized choice form"
    );
    assert!(html.contains("value=\"desk\"") && html.contains("desk@example.test"));
    let generated = html
        .split("<form id=\"sender-primary-form\"")
        .nth(1)
        .unwrap()
        .split("</form>")
        .next()
        .unwrap();
    assert!(generated.contains("method=\"post\" action=\"/settings/sender-identity\""));
    let mut fields = BTreeMap::new();
    for name in ["csrf_token", "sender_revision", "action"] {
        let value = generated
            .split(&format!("name=\"{name}\" value=\""))
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        fields.insert(name.to_string(), value.to_string());
    }
    fields.insert("identity_id".into(), "desk".into());
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let chosen = app.handle_request(
        &request(
            "POST",
            "/settings/sender-identity",
            &authenticated_same_origin_headers(),
            &body,
        ),
        "127.0.0.1",
    );
    assert_eq!(chosen.response.status_code, 303);
    assert_eq!(
        profile.load("alice@example.com").unwrap().primary_id(),
        "desk"
    );
    let fresh = app.handle_request(
        &request("GET", "/compose", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert_eq!(fresh.response.status_code, 200);
    assert!(body_text(&fresh).contains("Captured sender: desk@example.test"));
    let resumed = app.handle_request(
        &request(
            "GET",
            &format!("/draft?id={id}"),
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert_eq!(resumed.response.status_code, 200);
    assert!(body_text(&resumed).contains("Captured sender: alice@example.com"));
    assert!(drafts.load("alice@example.com", &id, 100).unwrap().unwrap() == before);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
struct SenderRouteFixture {
    root: PathBuf,
    authority: PathBuf,
    profile: crate::identity_preferences::IdentityPreferencesStore,
    app: BrowserApp<StubGateway>,
}
#[cfg(unix)]
impl SenderRouteFixture {
    fn new() -> Self {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = std::path::Path::new("/tmp").join(format!(
            "osmap-sender-forms-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = root.join("authority.json");
        fs::write(&authority, br#"{"version":1,"accounts":[{"account":"alice@example.com","revision":1,"identities":[{"id":"desk","address":"desk@example.test"}]},{"account":"bob@example.com","revision":1,"identities":[{"id":"bobdesk","address":"bobdesk@example.test"}]}]}"#).unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).unwrap();
        let provider = crate::sender_authority::Provider::new(
            Some(authority.clone()),
            fs::metadata(&authority).unwrap().uid(),
        );
        let profile =
            crate::identity_preferences::IdentityPreferencesStore::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                identity_preferences_store: Some(profile.clone()),
                sender_authority: provider,
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self {
            root,
            authority,
            profile,
            app,
        }
    }
    fn get(&self) -> HandledHttpResponse {
        self.app.handle_request(
            &request(
                "GET",
                "/settings?section=identity",
                &authenticated_headers(),
                "",
            ),
            "127.0.0.1",
        )
    }
    fn form(&self, action: &str) -> BTreeMap<String, String> {
        let page = self.get();
        assert_eq!(page.response.status_code, 200);
        let html = body_text(&page);
        let marker = format!("name=\"action\" value=\"{action}\"");
        let form = html
            .split("<form")
            .find_map(|part| {
                let form = part.split("</form>").next()?;
                (form.contains("action=\"/settings/sender-identity\"") && form.contains(&marker))
                    .then_some(form)
            })
            .unwrap();
        let mut fields = BTreeMap::new();
        for name in ["csrf_token", "sender_revision", "action"] {
            fields.insert(
                name.into(),
                form.split(&format!("name=\"{name}\" value=\""))
                    .nth(1)
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap()
                    .into(),
            );
        }
        fields.insert("identity_id".into(), "desk".into());
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
            "/settings/sender-identity",
            &authenticated_same_origin_headers(),
            &body,
        );
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
}
#[cfg(unix)]
impl Drop for SenderRouteFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
#[test]
fn sender_identity_generated_add_edit_use_new_and_legacy_merge_are_persisted() {
    let f = SenderRouteFixture::new();
    let authority_before = fs::read(&f.authority).unwrap();
    let add = f.form("add");
    assert_eq!(f.post(&add, false).response.status_code, 303);
    let added = f.profile.load("alice@example.com").unwrap();
    assert_eq!(added.revision, 1);
    assert_eq!(added.primary_id(), "canonical");
    assert!(added.presentation("desk").is_some());
    let mut edit = f.form("edit");
    edit.insert("display_name".into(), "Desk <public> 🦊".into());
    edit.insert("reply_to".into(), "desk-replies@example.test".into());
    edit.insert("use_for_new".into(), "on".into());
    assert_eq!(f.post(&edit, false).response.status_code, 303);
    let selected = f.profile.load("alice@example.com").unwrap();
    assert_eq!(selected.revision, 2);
    assert_eq!(selected.primary_id(), "desk");
    assert_eq!(
        selected.presentation("desk").unwrap().display_name(),
        "Desk <public> 🦊"
    );
    let reloaded = body_text(&f.get());
    assert!(reloaded.contains("Desk &lt;public&gt; 🦊"));
    assert!(reloaded.contains("value=\"desk\" selected"));
    assert!(reloaded.contains("value=\"on\" checked"));
    let body=format!("csrf_token={}&identity_revision=2&display_name=Canonical+profile&reply_to=canonical-replies%40example.test",StubGateway::validated_session().record.csrf_token);
    let saved = f.app.handle_request(
        &request(
            "POST",
            "/settings/identity",
            &authenticated_same_origin_headers(),
            &body,
        ),
        "127.0.0.1",
    );
    assert_eq!(saved.response.status_code, 303);
    let merged = f.profile.load("alice@example.com").unwrap();
    assert_eq!(merged.revision, 3);
    assert_eq!(merged.primary_id(), "desk");
    assert_eq!(merged.presentation("desk"), selected.presentation("desk"));
    assert_eq!(merged.preferences.display_name(), "Canonical profile");
    let mut off = f.form("edit");
    off.insert("display_name".into(), "Desk retained".into());
    off.insert("reply_to".into(), "desk-replies@example.test".into());
    assert_eq!(f.post(&off, false).response.status_code, 303);
    assert_eq!(
        f.profile.load("alice@example.com").unwrap().primary_id(),
        "canonical"
    );
    assert_eq!(f.profile.load("bob@example.com").unwrap().revision, 0);
    assert_eq!(fs::read(&f.authority).unwrap(), authority_before);
}

#[cfg(unix)]
#[test]
fn sender_identity_actual_forms_refuse_csrf_foreign_stale_and_arbitrary_authority() {
    let f = SenderRouteFixture::new();
    let form = f.form("primary");
    let original = f.profile.load("alice@example.com").unwrap();
    let bob = f.profile.load("bob@example.com").unwrap();
    let authority_before = fs::read(&f.authority).unwrap();
    for (name, value, status) in [
        ("csrf_token", "wrong", 403),
        ("identity_id", "bobdesk", 400),
        ("identity_id", "invented@example.test", 400),
        ("identity_id", "desk\r\nBcc: bad@example.test", 400),
        ("sender_revision", "01", 400),
        ("action", "provision", 400),
        ("from", "invented@example.test", 400),
        ("account", "bob@example.com", 400),
        ("authority_revision", "1", 400),
    ] {
        let mut altered = form.clone();
        altered.insert(name.into(), value.into());
        assert_eq!(
            f.post(&altered, false).response.status_code,
            status,
            "{name}"
        );
        assert_eq!(f.profile.load("alice@example.com").unwrap(), original);
    }
    let mut foreign = form.clone();
    foreign.insert("csrf_token".into(), "c".repeat(64));
    assert_eq!(f.post(&foreign, true).response.status_code, 400);
    assert_eq!(f.profile.load("bob@example.com").unwrap(), bob);
    assert_eq!(f.post(&form, false).response.status_code, 303);
    let chosen = f.profile.load("alice@example.com").unwrap();
    assert_eq!(f.post(&form, false).response.status_code, 409);
    assert_eq!(f.profile.load("alice@example.com").unwrap(), chosen);
    assert_eq!(fs::read(&f.authority).unwrap(), authority_before);
    let mut invalid = f.form("edit");
    invalid.insert("display_name".into(), "bad\nname".into());
    invalid.insert("reply_to".into(), "reply@example.test".into());
    assert_eq!(f.post(&invalid, false).response.status_code, 400);
    assert_eq!(f.profile.load("alice@example.com").unwrap(), chosen);
    let mut valid = f.form("primary");
    valid.insert("identity_id".into(), "canonical".into());
    fs::write(&f.authority, b"corrupt").unwrap();
    assert_eq!(f.post(&valid, false).response.status_code, 503);
    assert_eq!(f.profile.load("alice@example.com").unwrap(), chosen);
}

#[cfg(unix)]
#[test]
fn sender_identity_generated_per_message_choice_captures_without_changing_default() {
    let f = SenderRouteFixture::new();
    let page = f.app.handle_request(
        &request("GET", "/compose", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    let html = body_text(&page);
    assert!(html.contains("id=\"compose-sender-identity\" name=\"sender_id\""));
    assert!(html.contains("value=\"desk\""));
    let fields = format!(
        "csrf_token={}&to=receiver%40example.test&subject=Public&body=Public+body&sender_id=desk",
        StubGateway::validated_session().record.csrf_token
    );
    let saved = f.app.handle_request(
        &native_compose_request(
            &f.app,
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &fields,
        ),
        "127.0.0.1",
    );
    assert_eq!(saved.response.status_code, 303);
    let id = location_header(&saved)
        .trim_start_matches("/draft?id=")
        .to_owned();
    assert_eq!(
        f.profile.load("alice@example.com").unwrap().primary_id(),
        "canonical"
    );
    let record = f.app.gateway.load_draft(
        &AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "sender-fixture",
            "127.0.0.1",
            "Synthetic/Test",
        )
        .unwrap(),
        &StubGateway::validated_session(),
        &id,
    );
    let BrowserDraftLoadDecision::Loaded { draft, .. } = record.decision else {
        panic!("actual saved sender draft")
    };
    assert_eq!(
        draft.request.sender_identity.sender().unwrap().address(),
        "desk@example.test"
    );
    let resumed = f.app.handle_request(
        &request(
            "GET",
            &format!("/draft?id={id}"),
            &authenticated_headers(),
            "",
        ),
        "127.0.0.1",
    );
    assert!(body_text(&resumed).contains("value=\"desk\" selected"));
    let resume_html = body_text(&resumed);
    let mut chosen = BTreeMap::new();
    for name in ["csrf_token","send_intent","draft_id","draft_revision"] {
        let value=resume_html.split(&format!("name=\"{name}\" value=\"" )).nth(1).unwrap().split('"').next().unwrap();
        chosen.insert(name.to_owned(),value.to_owned());
    }
    for (name,value) in [("to","receiver@example.test"),("subject","Public"),("body","Public body"),("sender_id","canonical")] {chosen.insert(name.into(),value.into());}
    let changed=f.app.handle_request(&request("POST","/drafts/save",&authenticated_same_origin_headers(),&chosen.iter().map(|(k,v)|format!("{}={}",url_encode(k),url_encode(v))).collect::<Vec<_>>().join("&")),"127.0.0.1");
    assert_eq!(changed.response.status_code,303);
    let loaded=f.app.gateway.load_draft(&AuthenticationContext::new(AuthenticationPolicy::default(),"sender-fixture","127.0.0.1","Synthetic/Test").unwrap(),&StubGateway::validated_session(),&id);
    let BrowserDraftLoadDecision::Loaded{draft,..}=loaded.decision else {panic!("explicit changed sender draft")};
    assert!(draft.request.sender_identity.sender().is_none());
    assert_eq!(draft.revision,Some(2));
    assert_eq!(f.profile.load("alice@example.com").unwrap().primary_id(),"canonical");
    let invalid = format!("{fields}&sender_id=other");
    let refused = f.app.handle_request(
        &native_compose_request(
            &f.app,
            "POST",
            "/drafts/save",
            &authenticated_same_origin_headers(),
            &invalid,
        ),
        "127.0.0.1",
    );
    assert_eq!(refused.response.status_code, 400);
}
