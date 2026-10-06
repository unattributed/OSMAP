use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn selected_protection_requires_exact_finite_form_and_version() {
    let mut fields = BTreeMap::new();
    fields.insert("pgp_sign".to_string(), "on".to_string());
    assert!(intent_from_form(&fields).is_err());
    fields.insert("pgp_binding_revision".to_string(), "7".to_string());
    let intent = intent_from_form(&fields).unwrap();
    assert!(intent.sign);
    assert_eq!(intent.binding_revision, Some(7));
    fields.insert("pgp_sign".to_string(), "false".to_string());
    assert!(intent_from_form(&fields).is_err());
    fields.remove("pgp_sign");
    fields.insert("pgp_self".to_string(), "on".to_string());
    assert!(intent_from_form(&fields).is_err());
    fields.insert("pgp_encrypt".to_string(), "on".to_string());
    assert!(intent_from_form(&fields).is_ok());
    fields.insert(
        "pgp_binding_revision".to_string(),
        "18446744073709551616".to_string(),
    );
    assert!(intent_from_form(&fields).is_err());
    let retained = retained_intent_from_form(&fields);
    assert!(retained.encrypt && retained.encrypt_to_self);
    assert_eq!(retained.binding_revision, None);
}

struct OrdinaryContextFixture {
    root: std::path::PathBuf,
    settings: std::path::PathBuf,
    app: BrowserApp<RuntimeBrowserGateway>,
    issued: crate::session::IssuedSession,
    now: u64,
    inventory: crate::openpgp_inventory::Inventory,
}
impl OrdinaryContextFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-ordinary-context-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let config = crate::config::AppConfig::from_env_map(&BTreeMap::from([
            ("OSMAP_RUN_MODE".into(), "serve".into()),
            (
                "OSMAP_STATE_DIR".into(),
                root.join("state").to_string_lossy().into_owned(),
            ),
            (
                "OSMAP_OPENPGP_CRYPTO_SOCKET".into(),
                root.join("absent.sock").to_string_lossy().into_owned(),
            ),
            (
                "OSMAP_OPENPGP_CRYPTO_KEY_FILE".into(),
                root.join("absent.key").to_string_lossy().into_owned(),
            ),
            ("OSMAP_OPENPGP_CRYPTO_HELPER_UID".into(), "1".into()),
        ]))
        .unwrap();
        // A local-only owned sendmail process lets route tests cross the real
        // Runtime gateway without ever using the workstation's MTA.
        let script = root.join("fixture-sendmail");
        let called = root.join("fixture-sendmail-called");
        let called_literal =
            serde_json::to_string(called.to_str().expect("owned fixture path is UTF-8")).unwrap();
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env python3\nimport sys\nsys.stdin.buffer.read()\nwith open({}, 'ab') as recorder:\n    recorder.write(b'x')\n",
                called_literal,
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let gateway =
            RuntimeBrowserGateway::from_config(&config).with_fixture_sendmail_path(script);
        assert!(gateway.crypto_client().is_none());
        let context = AuthenticationContext::new(
            crate::auth::AuthenticationPolicy::default(),
            "ordinary-context-fixture",
            "127.0.0.1",
            "OSMAP/ordinary-context-fixture",
        )
        .unwrap();
        let sessions = crate::session::SessionService::new(
            crate::session::FileSessionStore::new(&config.state_layout.session_dir),
            crate::totp::SystemTimeProvider,
            crate::session::SystemRandomSource,
            1800,
            1800,
        );
        // Issued controlled session: no password/TOTP login qualification.
        let issued = sessions
            .issue(
                &context,
                "alice@example.test",
                crate::auth::RequiredSecondFactor::Totp,
            )
            .unwrap();
        let now = issued.record.issued_at;
        let inventory = crate::openpgp_inventory::Inventory::parse(
            serde_json::to_vec(&serde_json::json!({
                "version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18",
                "keys":[{"primary":{"fingerprint":"A".repeat(40),"algorithm":1,"bits":3072,
                "created":1,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,
                "can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},"subkeys":[]}]
            })).unwrap().as_slice(),
        ).unwrap();
        let fixture = Self {
            root,
            settings: config.state_layout.settings_dir.clone(),
            app: BrowserApp::new(HttpPolicy::from_config(&config), gateway),
            issued,
            now,
            inventory,
        };
        fixture.replace(
            0,
            crate::openpgp_bindings::ProtectionPolicy::default(),
            false,
        );
        fixture
    }
    fn replace(
        &self,
        revision: u64,
        policy: crate::openpgp_bindings::ProtectionPolicy,
        recipient_required: bool,
    ) {
        crate::openpgp_bindings::BindingStore::new(self.settings.join("openpgp-bindings"))
            .replace_operator(
                "alice@example.test",
                revision,
                crate::openpgp_bindings::Update {
                    account_binding: None,
                    recipient_bindings: if recipient_required {
                        vec![crate::openpgp_bindings::RecipientBinding {
                            address: "recipient@example.test".into(),
                            primary_fingerprint: "A".repeat(40),
                            encryption: crate::openpgp_bindings::Requirement::Required,
                        }]
                    } else {
                        vec![]
                    },
                    policy,
                },
                &self.inventory,
                self.now,
            )
            .unwrap();
    }
    fn page(&self) -> HandledHttpResponse {
        let wire = format!("GET /compose HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/ordinary-context-fixture\r\nCookie: osmap_session={}\r\n\r\n", self.issued.token.as_str());
        let request = crate::http::parse_http_request(&wire, self.app.policy()).unwrap();
        self.app.handle_request(&request, "127.0.0.1")
    }
    fn rendered_revision(&self, response: &HandledHttpResponse) -> String {
        assert_eq!(response.response.status_code, 200);
        let html = std::str::from_utf8(&response.response.body).unwrap();
        let tag = html
            .split("<input ")
            .find_map(|part| {
                let tag = part.split_once('>')?.0;
                tag.contains("name=\"pgp_binding_revision\"").then_some(tag)
            })
            .expect(
                "actual compose form must project current revision without crypto construction",
            );
        tag.split_once("value=\"")
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0
            .to_owned()
    }
    fn prepare(
        &self,
        recipient: &str,
        form: &BTreeMap<String, String>,
    ) -> Result<(crate::protected_submission::PreparedSubmission, u64), &'static str> {
        let mut request = crate::send::ComposeRequest::new(
            crate::send::ComposePolicy::default(),
            recipient,
            "Synthetic ordinary context",
            "Public synthetic body",
        )
        .unwrap();
        request.protection = intent_from_form(form).unwrap();
        // Exercise the exact runtime preparation path, without submission.
        self.app
            .gateway
            .test_prepare_outbound_request("alice@example.test", &request, self.now)
    }
}

#[test]
fn actual_route_runtime_plain_self_submits_once_and_required_recipient_refuses() {
    let fixture = OrdinaryContextFixture::new();
    crate::sent_copy::Store::new(&fixture.settings)
        .save("alice@example.test", 0, false)
        .unwrap();
    let post = |page: &HandledHttpResponse, to: &str| {
        let html = std::str::from_utf8(&page.response.body).unwrap();
        let intent = html
            .split("name=\"send_intent\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let _revision = fixture.rendered_revision(page);
        let body = format!(
            "csrf_token={}&send_intent={intent}&to={to}&subject=RouteOrdinary&body=RouteOrdinaryBody",
            fixture.issued.record.csrf_token,
        );
        let raw = format!(
            "POST /send HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/ordinary-context-fixture\r\nOrigin: http://localhost\r\nCookie: osmap_session={}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            fixture.issued.token.as_str(), body.len(),
        );
        let request = crate::http::parse_http_request(&raw, fixture.app.policy()).unwrap();
        fixture.app.handle_request(&request, "127.0.0.1")
    };
    // This is the exact route form omission accepted by intent_from_form.
    let plain = post(&fixture.page(), "alice%40example.test");
    assert_eq!(plain.response.status_code, 303, "{:?}", plain.audit_events);
    assert_eq!(
        std::fs::read(fixture.root.join("fixture-sendmail-called")).unwrap(),
        b"x"
    );
    assert!(!plain
        .audit_events
        .iter()
        .any(|event| event.action == "send_preparation_refused"));

    fixture.replace(
        1,
        crate::openpgp_bindings::ProtectionPolicy::default(),
        true,
    );
    let required = post(&fixture.page(), "recipient%40example.test");
    assert_eq!(required.response.status_code, 503);
    assert!(required
        .audit_events
        .iter()
        .any(|event| event.action == "send_preparation_refused"
            && event.fields.iter().any(|field| field.key == "reason"
                && field.value == "openpgp_recipient_encryption_required")));
    assert_eq!(
        std::fs::read(fixture.root.join("fixture-sendmail-called")).unwrap(),
        b"x"
    );
}
impl Drop for OrdinaryContextFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn ordinary_compose_projects_existing_revision_when_crypto_client_cannot_construct() {
    let fixture = OrdinaryContextFixture::new();
    let revision = fixture.rendered_revision(&fixture.page());
    assert_eq!(revision, "1");
    let form = BTreeMap::from([("pgp_binding_revision".into(), revision)]);
    let (ordinary, current_revision) = fixture.prepare("alice@example.test", &form).unwrap();
    assert_eq!(current_revision, 1);
    assert_eq!(
        ordinary.protection(),
        crate::protected_submission::SubmissionProtection::Ordinary
    );
    assert!(ordinary
        .as_bytes()
        .windows(b"Public synthetic body".len())
        .any(|w| w == b"Public synthetic body"));
    for flag in ["pgp_sign", "pgp_encrypt"] {
        let mut selected = form.clone();
        selected.insert(flag.into(), "on".into());
        assert!(matches!(
            fixture.prepare("alice@example.test", &selected),
            Err("openpgp_inventory_unavailable")
        ));
    }
    let mut stale = form;
    stale.insert("pgp_binding_revision".into(), "0".into());
    assert!(matches!(
        fixture.prepare("alice@example.test", &stale),
        Err("openpgp_binding_changed")
    ));
}

#[test]
fn crypto_unavailable_compose_keeps_defaults_editable_and_required_policy_enforced() {
    let fixture = OrdinaryContextFixture::new();
    crate::composition_preferences::CompositionPreferencesStore::new(&fixture.settings)
        .save(
            "alice@example.test",
            crate::composition_preferences::CompositionPreferences {
                openpgp: crate::composition_preferences::OpenPgpDefaults {
                    sign: true,
                    encrypt: true,
                    encrypt_to_self: true,
                },
                ..Default::default()
            },
        )
        .unwrap();
    let page = fixture.page();
    let revision = fixture.rendered_revision(&page);
    let html = std::str::from_utf8(&page.response.body).unwrap();
    for name in ["pgp_sign", "pgp_encrypt", "pgp_self"] {
        let tag = html
            .split("<input ")
            .find_map(|part| {
                let tag = part.split_once('>')?.0;
                tag.contains(&format!("name=\"{name}\"")).then_some(tag)
            })
            .unwrap();
        assert!(tag
            .split_whitespace()
            .any(|field| field.trim_end_matches('/') == "checked"));
        assert!(!tag
            .split_whitespace()
            .any(|field| field.trim_end_matches('/') == "disabled"));
    }
    // Native unchecked controls omit these fields; choosing ordinary is possible.
    let form = BTreeMap::from([("pgp_binding_revision".into(), revision)]);
    assert!(fixture.prepare("alice@example.test", &form).is_ok());
    fixture.replace(
        1,
        crate::openpgp_bindings::ProtectionPolicy {
            signing: crate::openpgp_bindings::Requirement::Required,
            ..Default::default()
        },
        false,
    );
    let form = BTreeMap::from([(
        "pgp_binding_revision".into(),
        fixture.rendered_revision(&fixture.page()),
    )]);
    assert!(matches!(
        fixture.prepare("alice@example.test", &form),
        Err("openpgp_signing_required")
    ));
    fixture.replace(
        2,
        crate::openpgp_bindings::ProtectionPolicy::default(),
        true,
    );
    let form = BTreeMap::from([(
        "pgp_binding_revision".into(),
        fixture.rendered_revision(&fixture.page()),
    )]);
    assert!(matches!(
        fixture.prepare("recipient@example.test", &form),
        Err("openpgp_recipient_encryption_required")
    ));
}
