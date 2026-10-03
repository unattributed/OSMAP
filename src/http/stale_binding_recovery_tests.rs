use super::*;

struct RecoveryFixture {
    app: BrowserApp<StubGateway>,
    root: PathBuf,
    store: crate::draft::FileDraftStore,
    snapshot: Arc<Mutex<FixtureOpenPgpSnapshot>>,
}

impl RecoveryFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "openpgp-recovery-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::draft::FileDraftStore::new(root.join("drafts"), DraftPolicy::default());
        let snapshot = Arc::new(Mutex::new(FixtureOpenPgpSnapshot {
            revision: 2,
            preflight_revision: Some(2),
            available: true,
        }));
        let gateway = StubGateway {
            draft_store: Some(store.clone()),
            autosave_store: Some(crate::autosave::Store::new(root.join("settings"))),
            browser_fixture_accounts: true,
            fixture_openpgp_snapshot: Some(snapshot.clone()),
            ..StubGateway::default()
        };
        Self {
            app: BrowserApp::new(HttpPolicy::default(), gateway),
            root,
            store,
            snapshot,
        }
    }

    fn post(&self, path: &str, fields: &[(&str, &str)], upload: bool) -> HandledHttpResponse {
        let mut body = String::new();
        let csrf = StubGateway::validated_session().record.csrf_token;
        for (name, value) in [("csrf_token", csrf.as_str())]
            .into_iter()
            .chain(fields.iter().copied())
        {
            body.push_str(&format!(
                "--recovery-test\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ));
        }
        if upload {
            body.push_str("--recovery-test\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"synthetic.txt\"\r\nContent-Type: text/plain\r\n\r\nSynthetic retained attachment\r\n");
        }
        body.push_str("--recovery-test--\r\n");
        let mut request = request("POST", path, &authenticated_same_origin_headers(), &body);
        request.headers.insert(
            "content-type".into(),
            "multipart/form-data; boundary=recovery-test".into(),
        );
        if matches!(path, "/send" | "/drafts/save" | "/drafts/autosave") {
            add_native_compose_intent(&self.app, &mut request);
        }
        self.app.handle_request(&request, "127.0.0.1")
    }

    fn get(&self, path: &str) -> HandledHttpResponse {
        self.app.handle_request(
            &request("GET", path, &authenticated_headers(), ""),
            "127.0.0.1",
        )
    }

    fn saved(&self, id: &str) -> DraftRecord {
        self.store
            .load("alice@example.com", id, 100)
            .unwrap()
            .unwrap()
    }

    fn initial_draft(&self) -> String {
        let result = self.post(
            "/drafts/save",
            &[
                ("from", "alice@example.com"),
                ("to", "bob@example.test"),
                ("subject", "Synthetic protected draft"),
                ("body", "Initial synthetic text"),
                ("pgp_sign", "on"),
                ("pgp_encrypt", "on"),
                ("pgp_self", "on"),
                ("pgp_binding_revision", "2"),
            ],
            true,
        );
        assert_eq!(
            result.response.status_code,
            303,
            "{}",
            body_text(&result)
                .split("Request failed:")
                .nth(1)
                .unwrap_or("no request-failed notice")
                .chars()
                .take(240)
                .collect::<String>()
        );
        location_header(&result)
            .trim_start_matches("/draft?id=")
            .to_string()
    }

    fn set_snapshot(&self, revision: u64, preflight_revision: Option<u64>, available: bool) {
        *self.snapshot.lock().unwrap() = FixtureOpenPgpSnapshot {
            revision,
            preflight_revision,
            available,
        };
    }
}

impl Drop for RecoveryFixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn explicit_pre_send_check_rebinds_only_reviewed_draft_and_keeps_content_files_and_choices() {
    let fixture = RecoveryFixture::new();
    let id = fixture.initial_draft();
    let saved = fixture.saved(&id);
    assert_eq!(saved.revision, Some(1));
    assert_eq!(saved.request.protection.binding_revision, Some(2));
    assert_eq!(saved.request.attachments.len(), 1);

    fixture.set_snapshot(4, Some(4), true);
    let reopened = fixture.get(&format!("/draft?id={id}&preflight=1"));
    let reopened_html = body_text(&reopened);
    assert!(reopened_html.contains("name=\"pgp_binding_revision\" value=\"2\""));
    assert!(reopened_html.contains("older or inconsistent OpenPGP binding snapshot"));
    assert!(reopened_html.contains(">Review current keys</button>"));
    assert!(reopened_html.contains("Keys changed — review required"));
    assert!(!reopened_html.contains("Public keys eligible in the saved-draft snapshot"));
    assert_eq!(fixture.saved(&id).request.protection.binding_revision, Some(2));

    let ordinary = fixture.post(
        "/drafts/save",
        &[
            ("from", "alice@example.com"),
            ("to", "bob@example.test"),
            ("subject", "Synthetic protected draft"),
            ("body", "Ordinary save retained"),
            ("pgp_sign", "on"),
            ("pgp_encrypt", "on"),
            ("pgp_self", "on"),
            ("pgp_binding_revision", "2"),
            ("draft_id", &id),
            ("draft_revision", "1"),
        ],
        false,
    );
    assert_eq!(ordinary.response.status_code, 303, "{}", body_text(&ordinary));
    assert_eq!(fixture.saved(&id).request.protection.binding_revision, Some(2));

    let csrf = StubGateway::validated_session().record.csrf_token;
    let enable = fixture.app.handle_request(
        &request(
            "POST",
            "/settings/autosave",
            &authenticated_same_origin_headers(),
            &format!("csrf_token={csrf}&revision=0&enabled=1&interval=30"),
        ),
        "127.0.0.1",
    );
    assert_eq!(enable.response.status_code, 303);
    let autosave = fixture.post(
        "/drafts/autosave",
        &[
            ("from", "alice@example.com"),
            ("to", "bob@example.test"),
            ("subject", "Synthetic protected draft"),
            ("body", "Autosave retained"),
            ("pgp_sign", "on"),
            ("pgp_encrypt", "on"),
            ("pgp_self", "on"),
            ("pgp_binding_revision", "2"),
            ("draft_id", &id),
            ("draft_revision", "2"),
        ],
        false,
    );
    assert_eq!(autosave.response.status_code, 200, "{}", body_text(&autosave));
    assert_eq!(fixture.saved(&id).request.protection.binding_revision, Some(2));

    let review = fixture.post(
        "/drafts/save",
        &[
            ("from", "alice@example.com"),
            ("to", "bob@example.test"),
            ("subject", "Synthetic protected draft"),
            ("body", "Reviewed text with all choices"),
            ("pgp_sign", "on"),
            ("pgp_encrypt", "on"),
            ("pgp_self", "on"),
            ("pgp_binding_revision", "2"),
            ("draft_id", &id),
            ("draft_revision", "3"),
            ("compose_action", "preflight"),
        ],
        false,
    );
    assert_eq!(review.response.status_code, 303, "{}", body_text(&review));
    assert!(location_header(&review).ends_with("&preflight=1"));
    let reviewed = fixture.saved(&id);
    assert_eq!(reviewed.revision, Some(4));
    assert_eq!(reviewed.request.protection.binding_revision, Some(4));
    assert!(reviewed.request.protection.sign);
    assert!(reviewed.request.protection.encrypt);
    assert!(reviewed.request.protection.encrypt_to_self);
    assert_eq!(reviewed.request.recipients_text, "bob@example.test");
    assert_eq!(reviewed.request.subject, "Synthetic protected draft");
    assert_eq!(reviewed.request.body, "Reviewed text with all choices");
    assert_eq!(reviewed.request.attachments.len(), 1);
    assert_eq!(reviewed.request.attachments[0].body, b"Synthetic retained attachment");
    let review_html = body_text(&fixture.get(&location_header(&review)));
    assert!(review_html.contains("name=\"pgp_binding_revision\" value=\"4\""));
    assert!(!review_html.contains(">Review current keys</button>"));
    assert!(review_html.contains("Selected signing fingerprint"));
    assert!(review_html.contains(&"A".repeat(40)));
    assert!(review_html.contains(&"B".repeat(40)));
    assert!(review_html.contains("This check does not sign, encrypt or send"));
    assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());

    fixture.set_snapshot(5, Some(5), true);
    let refused = fixture.post(
        "/send",
        &[
            ("from", "alice@example.com"),
            ("to", "bob@example.test"),
            ("subject", "Synthetic protected draft"),
            ("body", "Reviewed text with all choices"),
            ("pgp_sign", "on"),
            ("pgp_encrypt", "on"),
            ("pgp_self", "on"),
            ("pgp_binding_revision", "4"),
            ("draft_id", &id),
            ("draft_revision", "4"),
        ],
        false,
    );
    assert_eq!(refused.response.status_code, 503, "{}", body_text(&refused));
    assert!(body_text(&refused).contains("OpenPGP key bindings changed"));
    assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
}

#[test]
fn unavailable_or_inconsistent_public_snapshot_never_rebases_saved_draft() {
    for (revision, preflight_revision, available, status) in [
        (4, Some(4), false, 503),
        (4, None, true, 400),
        (4, Some(3), true, 409),
    ] {
        let fixture = RecoveryFixture::new();
        let id = fixture.initial_draft();
        fixture.set_snapshot(revision, preflight_revision, available);
        let refused = fixture.post(
            "/drafts/save",
            &[
                ("from", "alice@example.com"),
                ("to", "bob@example.test"),
                ("subject", "Synthetic protected draft"),
                ("body", "Retained review text"),
                ("pgp_sign", "on"),
                ("pgp_encrypt", "on"),
                ("pgp_self", "on"),
                ("pgp_binding_revision", "2"),
                ("draft_id", &id),
                ("draft_revision", "1"),
                ("compose_action", "preflight"),
            ],
            false,
        );
        assert_eq!(refused.response.status_code, status, "{}", body_text(&refused));
        let html = body_text(&refused);
        assert!(html.contains("Retained review text"));
        assert!(html.contains("name=\"pgp_binding_revision\" value=\"2\""));
        for selected in ["pgp_sign", "pgp_encrypt", "pgp_self"] {
            assert!(html.contains(&format!("name=\"{selected}\" checked")));
        }
        let saved = fixture.saved(&id);
        assert_eq!(saved.revision, Some(1));
        assert_eq!(saved.request.protection.binding_revision, Some(2));
        assert_eq!(saved.request.attachments.len(), 1);
        assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
    }
}

#[test]
fn explicit_review_updates_pinned_revision_without_choosing_protection_for_user() {
    let fixture = RecoveryFixture::new();
    let initial = fixture.post(
        "/drafts/save",
        &[
            ("from", "alice@example.com"),
            ("to", "bob@example.test"),
            ("subject", "Synthetic unselected draft"),
            ("body", "Unselected choices stay unselected"),
            ("pgp_binding_revision", "2"),
        ],
        false,
    );
    assert_eq!(initial.response.status_code, 303);
    let id = location_header(&initial)
        .trim_start_matches("/draft?id=")
        .to_string();
    fixture.set_snapshot(4, Some(4), true);
    let stale = body_text(&fixture.get(&format!("/draft?id={id}")));
    assert!(stale.contains(">Review current keys</button>"));
    assert!(stale.contains("name=\"pgp_binding_revision\" value=\"2\""));

    let reviewed = fixture.post(
        "/drafts/save",
        &[
            ("from", "alice@example.com"),
            ("to", "bob@example.test"),
            ("subject", "Synthetic unselected draft"),
            ("body", "Unselected choices stay unselected"),
            ("pgp_binding_revision", "2"),
            ("draft_id", &id),
            ("draft_revision", "1"),
            ("compose_action", "preflight"),
        ],
        false,
    );
    assert_eq!(reviewed.response.status_code, 303);
    let saved = fixture.saved(&id);
    assert_eq!(saved.request.protection.binding_revision, Some(4));
    assert!(!saved.request.protection.sign);
    assert!(!saved.request.protection.encrypt);
    assert!(!saved.request.protection.encrypt_to_self);
    assert_eq!(saved.request.body, "Unselected choices stay unselected");
    assert!(fixture.app.gateway.submitted.lock().unwrap().is_empty());
}
