use super::*;
struct KeyChangeSpy {
    inner: StubGateway,
    calls: Arc<AtomicUsize>,
}
impl BrowserGateway for KeyChangeSpy {
    fn key_management(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
    ) -> crate::key_management::StateOutcome {
        crate::key_management::StateOutcome {
            state: security_overview_key_state(
                &session.record.canonical_username,
                &context.user_agent,
            ),
            audit_events: vec![],
        }
    }
    fn send_receipt(
        &self,
        session: &ValidatedSession,
        intent: &str,
    ) -> Result<Option<BrowserSendDecision>, String> {
        self.inner.send_receipt(session, intent)
    }
    fn cleanup_sent_draft(
        &self,
        session: &ValidatedSession,
        id: &str,
        revision: u64,
        intent: &str,
    ) -> Result<bool, String> {
        self.inner.cleanup_sent_draft(session, id, revision, intent)
    }
    fn load_contacts(
        &self,
        session: &ValidatedSession,
    ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError> {
        self.inner.load_contacts(session)
    }
    fn change_contact(
        &self,
        session: &ValidatedSession,
        expected_revision: u64,
        change: crate::contacts::ContactChange,
    ) -> Result<crate::contacts::ContactBook, crate::contacts::ContactError> {
        self.inner
            .change_contact(session, expected_revision, change)
    }
    fn login(
        &self,
        context: &AuthenticationContext,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> BrowserLoginOutcome {
        self.inner.login(context, username, password, totp_code)
    }
    fn validate_session(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserSessionValidationOutcome {
        self.inner.validate_session(context, presented_token)
    }
    fn logout(
        &self,
        context: &AuthenticationContext,
        presented_token: &str,
    ) -> BrowserLogoutOutcome {
        self.inner.logout(context, presented_token)
    }
    fn list_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSessionListOutcome {
        self.inner.list_sessions(context, validated_session)
    }
    fn revoke_session(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        session_id: &str,
    ) -> BrowserSessionRevokeOutcome {
        self.inner
            .revoke_session(context, validated_session, session_id)
    }
    fn revoke_sessions(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        scope: BrowserSessionRevokeScope,
    ) -> BrowserSessionRevokeOutcome {
        self.inner
            .revoke_sessions(context, validated_session, scope)
    }
    fn load_appearance(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> std::io::Result<AppearancePreference> {
        self.inner.load_appearance(context, validated_session)
    }
    fn update_appearance(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        appearance: AppearancePreference,
    ) -> std::io::Result<()> {
        self.inner
            .update_appearance(context, validated_session, appearance)
    }
    fn load_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserSettingsOutcome {
        self.inner.load_settings(context, validated_session)
    }
    fn update_settings(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        html_display_preference: HtmlDisplayPreference,
        archive_mailbox_name: Option<&str>,
    ) -> BrowserSettingsUpdateOutcome {
        self.inner.update_settings(
            context,
            validated_session,
            html_display_preference,
            archive_mailbox_name,
        )
    }
    fn list_mailboxes(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserMailboxOutcome {
        self.inner.list_mailboxes(context, validated_session)
    }
    fn list_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
    ) -> BrowserMessageListOutcome {
        self.inner
            .list_messages(context, validated_session, mailbox_name)
    }
    fn search_messages(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: Option<&str>,
        query: &str,
        field: MessageSearchField,
    ) -> BrowserMessageSearchOutcome {
        self.inner
            .search_messages(context, validated_session, mailbox_name, query, field)
    }
    fn view_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
    ) -> BrowserMessageViewOutcome {
        self.inner
            .view_message(context, validated_session, mailbox_name, uid)
    }
    fn download_attachment(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        mailbox_name: &str,
        uid: u64,
        part_path: &str,
    ) -> BrowserAttachmentDownloadOutcome {
        self.inner
            .download_attachment(context, validated_session, mailbox_name, uid, part_path)
    }
    fn read_message_source(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageViewRequest,
    ) -> crate::mailbox::MessageViewOutcome {
        self.inner
            .read_message_source(context, validated_session, request)
    }
    fn move_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: &MessageMoveRequest,
    ) -> BrowserMessageMoveOutcome {
        self.inner.move_message(context, validated_session, request)
    }
    fn send_message(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserSendRequest<'_>,
    ) -> BrowserSendOutcome {
        self.inner.send_message(context, validated_session, request)
    }
    fn list_drafts(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
    ) -> BrowserDraftListOutcome {
        self.inner.list_drafts(context, validated_session)
    }
    fn load_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
    ) -> BrowserDraftLoadOutcome {
        self.inner.load_draft(context, validated_session, draft_id)
    }
    fn save_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        request: BrowserDraftSaveRequest<'_>,
    ) -> BrowserDraftSaveOutcome {
        self.inner.save_draft(context, validated_session, request)
    }
    fn delete_draft(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
    ) -> BrowserDraftDeleteOutcome {
        self.inner
            .delete_draft(context, validated_session, draft_id, expected_revision)
    }
    fn set_draft_star(
        &self,
        context: &AuthenticationContext,
        validated_session: &ValidatedSession,
        draft_id: &str,
        expected_revision: u64,
        starred: bool,
    ) -> BrowserDraftSaveOutcome {
        self.inner.set_draft_star(
            context,
            validated_session,
            draft_id,
            expected_revision,
            starred,
        )
    }
    fn change_keys(
        &self,
        _context: &AuthenticationContext,
        _session: &ValidatedSession,
        _request: crate::key_management::MutationRequest<'_>,
    ) -> crate::key_management::MutationOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        crate::key_management::MutationOutcome {
            result: Err(crate::key_management::Error::Unavailable),
            audit_events: vec![],
        }
    }
}
#[test]
fn key_management_post_reaches_gateway_only_after_session_csrf_and_strict_fields() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = BrowserApp::new(
        HttpPolicy::default(),
        KeyChangeSpy {
            inner: StubGateway::default(),
            calls: calls.clone(),
        },
    );
    let body=format!("key_action=clear_account&binding_revision=0&csrf_token={}&current_password=fixture-password&totp_code=123456","fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned());
    let headers = [
        ("User-Agent", "Firefox/Test"),
        (
            "Cookie",
            "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("Origin", "https://localhost"),
        ("Content-Type", "application/x-www-form-urlencoded"),
    ];
    let no_session = app.handle_request(
        &request(
            "POST",
            "/settings/keys/change",
            &[
                ("Origin", "https://localhost"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            &body,
        ),
        "127.0.0.1",
    );
    assert_ne!(no_session.response.status_code, 503);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let wrong_csrf = body.replace(
        &"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned(),
        &"d".repeat(64),
    );
    let r = app.handle_request(
        &request("POST", "/settings/keys/change", &headers, &wrong_csrf),
        "127.0.0.1",
    );
    assert_eq!(r.response.status_code, 403);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    for field in [
        "username=bob%40example.test",
        "confirmed=true",
        "home=%2Ftmp%2Fforeign",
    ] {
        let r = app.handle_request(
            &request(
                "POST",
                "/settings/keys/change",
                &headers,
                &format!("{body}&{field}"),
            ),
            "127.0.0.1",
        );
        assert_eq!(r.response.status_code, 400);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!body_text(&r).contains("fixture-password"));
        assert!(!body_text(&r).contains("123456"));
    }
    let valid = app.handle_request(
        &request("POST", "/settings/keys/change", &headers, &body),
        "127.0.0.1",
    );
    assert_eq!(valid.response.status_code, 503);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!body_text(&valid).contains("fixture-password"));
    let import = body.replace("key_action=clear_account", "key_action=import_public");
    let missing_revision = app.handle_request(
        &request("POST", "/settings/keys/change", &headers, &import),
        "127.0.0.1",
    );
    assert_eq!(missing_revision.response.status_code, 400);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let import = format!(
        "{import}&public_inventory_revision={}&expected_primary_fingerprint={}&certificate=fixture",
        "a".repeat(64),
        "A".repeat(40)
    );
    let accepted_form = app.handle_request(
        &request("POST", "/settings/keys/change", &headers, &import),
        "127.0.0.1",
    );
    assert_eq!(accepted_form.response.status_code, 503);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn key_management_panel_navigation_opens_forms_without_mutating_state() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = BrowserApp::new(HttpPolicy::default(), KeyChangeSpy { inner: StubGateway::default(), calls: calls.clone() });
    let headers = [("User-Agent", "Firefox/Test"), ("Cookie", "osmap_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")];
    for (panel, id) in [("account", "account-binding"), ("policy", "protection-policy"), ("recipient", "recipient-binding"), ("import", "public-import"), ("inventory", "public-inventory")] {
        let response = app.handle_request(&request("GET", &format!("/settings/keys?panel={panel}"), &headers, ""), "127.0.0.1");
        assert_eq!(response.response.status_code, 200);
        assert!(body_text(&response).contains(&format!("<details id=\"{id}\" open>")));
    }
    for query in ["panel=invalid", "panel=import&extra=1", "panel="] {
        let response = app.handle_request(&request("GET", &format!("/settings/keys?{query}"), &headers, ""), "127.0.0.1");
        assert_eq!(response.response.status_code, 400);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

fn compose_protection_model() -> crate::http_ui::ComposePageModel<'static> {
    crate::http_ui::ComposePageModel {
 sender_choices: None,
 selected_sender_id: None,
        protection: crate::send::ProtectionIntent::default(),
        openpgp: Some(ComposeProtectionView {
            runtime_configured: true,
            revision: Some(1),
            preflight: None,
            account_binding: None,
            policy: crate::openpgp_bindings::ProtectionPolicy::default(),
            recipient_binding_count: 0,
        }),
        sender_identity: None,
        send_intent: "0",
        contacts: None,
        heading: "Compose",
        canonical_username: "alice@example.test",
        csrf_token: "test",
        success_message: None,
        error_message: None,
        context_notice: None,
        to_value: "",
        cc_value: "",
        bcc_value: "",
        subject_value: "",
        body_value: "",
        body_format: crate::compose_format::BodyFormat::Plain,
        preview: false,
        preflight: false,
        draft_id: None,
        draft_revision: None,
        draft_attachments: &[],
        removed_attachment_indices: &[],
        source_mailbox_name: None,
        source_uid: None,
        source_version: None,
        source_attachments: &[],
        selected_source_part_paths: &[],
        reply_reference: None,
    }
}

fn evaluated_recipient_protection(
    requirement: crate::openpgp_bindings::Requirement,
    encrypt: bool,
    bound: bool,
) -> crate::openpgp_bindings::Preflight {
    use crate::openpgp_bindings::{BindingRecord, RecipientBinding, Recipients, Selections};
    let key = |fingerprint: &str, encrypt: bool| serde_json::json!({
        "fingerprint": fingerprint, "algorithm": 1, "bits": 3072,
        "created": 1, "expires": 0, "revoked": false, "expired": false,
        "disabled": false, "invalid": false, "can_sign": !encrypt,
        "can_encrypt": encrypt, "can_certify": false, "can_authenticate": false,
    });
    let inventory = crate::openpgp_inventory::Inventory::parse(
        &serde_json::to_vec(&serde_json::json!({
            "version": 1, "ok": true, "protocol": "openpgp",
            "gpgme_version": "2.0.1", "engine_version": "2.4.8",
            "keys": [{"primary": key(&"D".repeat(40), false),
                "subkeys": [key(&"F".repeat(40), true)]}],
        })).unwrap(),
    ).unwrap();
    let mut record = BindingRecord::empty("alice@example.test").unwrap();
    // A configured binding record has a persisted revision; revision zero is
    // reserved by the production validator for an empty initial record.
    record.revision = 1;
    if bound {
        record.recipient_bindings.push(RecipientBinding {
            address: "bob@example.test".into(),
            primary_fingerprint: "D".repeat(40),
            encryption: requirement,
        });
    }
    let to = ["bob@example.test".to_string()];
    crate::openpgp_bindings::evaluate(
        "alice@example.test", &record, &inventory,
        Recipients { to: &to, cc: &[], bcc: &[] },
        Selections { sign: false, encrypt, encrypt_to_self: false }, 100,
    ).unwrap()
}

// The policy notice must be outside every collapsed disclosure, not merely
// present somewhere in the page source. Public readiness remains a snapshot.
fn visible_protection_notice(body: &str) -> &str {
    let (_, notice) = body.split_once("<div class=\"notice compose-protection-requirements\"").unwrap();
    notice.split_once("</div>").unwrap().0
}

#[test]
fn compose_live_protection_controls_are_direct_and_preserve_selection() {
    let mut model = compose_protection_model();
    let body = crate::http_ui::render_compose_page(&model)
        .as_str()
        .to_owned();
    assert!(body.contains("<label class=\"compose-protection-choice\"><span>Sign</span>"));
    assert!(body.contains("<label class=\"compose-protection-choice\"><span>Encrypt</span>"));
    assert!(body.contains("<label class=\"compose-protection-choice\"><span>Encrypt to self</span>"));
    assert!(!body.contains("<details name=\"compose-policy\">"));
    assert!(!body.contains("name=\"pgp_sign\" checked"));
    assert!(!body.contains("name=\"pgp_encrypt\" checked"));
    model.protection.sign = true;
    let body = crate::http_ui::render_compose_page(&model)
        .as_str()
        .to_owned();
    assert!(body.contains("name=\"pgp_sign\" checked"));
    assert!(!body.contains("<span>Sign</span><strong>Signed</strong>"));
    model.protection.sign = false;
    model.to_value = "bob@example.test";
    model.openpgp.as_mut().unwrap().preflight = Some(evaluated_recipient_protection(
        crate::openpgp_bindings::Requirement::Required, false, true,
    ));
    let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
    assert!(body.contains("<strong>Blocked</strong>"));
    assert!(body.contains("bob@example.test</span>: Public key eligible; Encryption required"));
    assert!(body.contains("A recipient binding requires encryption. Select Encrypt on send"));
    assert!(!body.contains("<strong>No protection selected</strong>"));
    assert!(!body.contains("name=\"pgp_encrypt\" checked"));
}

#[test]
fn compose_required_recipient_policy_is_visible_without_changing_intent() {
    let mut model = compose_protection_model();
    model.to_value = "bob@example.test";
    model.openpgp.as_mut().unwrap().preflight = Some(evaluated_recipient_protection(
        crate::openpgp_bindings::Requirement::Required, false, true,
    ));
    let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
    let notice = visible_protection_notice(&body);
    assert!(notice.contains("<strong>Blocked</strong>"));
    assert!(notice.contains("bob@example.test</span>: Encryption required"));
    assert!(notice.contains("Select Encrypt on send"));
    assert!(notice.contains("signing optional; encryption optional"));
    assert!(body.contains("<strong>Blocked</strong></summary>"));
    let before_notice = body.split_once("<div class=\"notice compose-protection-requirements\"").unwrap().0;
    assert!(before_notice.ends_with("</div></section>"));
    assert!(!body.contains("name=\"pgp_sign\" checked"));
    assert!(!body.contains("name=\"pgp_encrypt\" checked"));
    assert!(!body.contains("name=\"pgp_self\" checked"));
    // This snapshot must not disable Send after the operator changes choices.
    assert!(body.contains("type=\"submit\" aria-label=\"Send Message\""));
    let check = body.find("aria-describedby=\"compose-pre-send-description\"").unwrap();
    let menu = body.find("<details class=\"compose-send-options\"").unwrap();
    assert!(check < menu);
    assert_eq!(body.matches(">Pre-send check</button>").count(), 1);
}

#[test]
fn compose_encrypt_only_and_optional_plain_choices_match_evaluated_policy() {
    use crate::openpgp_bindings::{PreflightState, Requirement};
    for (requirement, encrypt, state) in [
        (Requirement::Required, true, "Attention"),
        (Requirement::Optional, false, "No protection selected"),
    ] {
        let mut model = compose_protection_model();
        model.to_value = "bob@example.test";
        model.protection.encrypt = encrypt;
        let preflight = evaluated_recipient_protection(requirement, encrypt, true);
        assert_eq!(preflight.state, PreflightState::Orange);
        assert!(preflight.reasons.is_empty());
        let plan = preflight.plan.as_ref().unwrap();
        assert!(plan.signer_fingerprint.is_none());
        assert!(!plan.encrypt_to_self);
        assert_eq!(plan.recipient_fingerprints.len(), usize::from(encrypt));
        model.openpgp.as_mut().unwrap().preflight = Some(preflight);
        let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
        let notice = visible_protection_notice(&body);
        assert!(notice.contains(&format!("<strong>{state}</strong>")));
        assert!(!notice.contains("Blocked"));
        assert!(!body.contains("name=\"pgp_sign\" checked"));
        assert!(!body.contains("name=\"pgp_self\" checked"));
        assert_eq!(body.contains("name=\"pgp_encrypt\" checked"), encrypt);
        assert!(!body.contains("private key is unlocked"));
        assert!(!body.contains("Signing and encryption are confirmed only when delivery completes"));
    }
}

#[test]
fn compose_missing_key_unchecked_stale_and_unconfirmed_states_remain_honest() {
    let mut model = compose_protection_model();
    let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
    assert!(visible_protection_notice(&body).contains("Recipient protection not checked"));
    assert!(body.contains("<strong>Not checked</strong></summary>"));
    model.to_value = "bob@example.test";
    model.protection.encrypt = true;
    model.openpgp.as_mut().unwrap().preflight = Some(evaluated_recipient_protection(
        crate::openpgp_bindings::Requirement::Optional, true, false,
    ));
    let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
    let notice = visible_protection_notice(&body);
    assert!(notice.contains("<strong>Blocked</strong>"));
    assert!(notice.contains("no eligible approved encryption key"));
    assert!(body.contains("name=\"pgp_encrypt\" checked"));
    model.protection.binding_revision = Some(0);
    model.openpgp.as_mut().unwrap().revision = Some(1);
    model.draft_id = Some("0");
    model.draft_revision = None;
    let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
    assert!(visible_protection_notice(&body).contains("Keys changed — review required"));
    assert!(body.contains("type=\"submit\" disabled aria-label=\"Send Message\""));
    assert!(body.contains("type=\"submit\" disabled formaction=\"/drafts/save\" name=\"compose_action\" value=\"preflight\" aria-describedby"));
    assert!(body.contains("name=\"pgp_binding_revision\" value=\"0\""));
    assert!(!body.contains("name=\"pgp_binding_revision\" value=\"1\""));
}

fn security_overview_key_state(account: &str, mode: &str) -> crate::key_management::State {
    if !mode.starts_with("OSMAP/SecurityKeys-") || mode.ends_with("unavailable") {
        return crate::key_management::State::unavailable(account);
    }
    let owner = if mode.ends_with("foreign-state") {
        "bob@example.com"
    } else {
        account
    };
    let binding_owner = if mode.ends_with("foreign-binding") {
        "bob@example.com"
    } else {
        owner
    };
    let mut state = crate::key_management::State::unavailable(owner);
    let mut record = crate::openpgp_bindings::BindingRecord::empty(binding_owner).unwrap();
    if !mode.ends_with("unbound") {
        record.revision = 1;
        record.account_binding = Some(crate::openpgp_bindings::AccountBinding {
            primary_fingerprint: "A".repeat(40),
            signing_fingerprint: Some("A".repeat(40)),
            decrypt_primary_fingerprints: vec!["A".repeat(40)],
        });
    }
    state.bindings = Some(record);
    let keys = if mode.ends_with("missing-key") {
        vec![]
    } else {
        vec![serde_json::json!({
            "primary": {
                "fingerprint": "A".repeat(40), "algorithm": 1, "bits": 3072,
                "created": 1, "expires": 0, "revoked": mode.ends_with("revoked"),
                "expired": false, "disabled": false, "invalid": false,
                "can_sign": true, "can_encrypt": false, "can_certify": true,
                "can_authenticate": false,
            }, "subkeys": [],
        })]
    };
    state.inventory = Some(
        crate::openpgp_inventory::Inventory::parse(
            &serde_json::to_vec(&serde_json::json!({
                "version": 1, "ok": true, "protocol": "openpgp",
                "gpgme_version": "2.0.1", "engine_version": "2.4.8", "keys": keys,
            }))
            .unwrap(),
        )
        .unwrap(),
    );
    state
}

#[test]
fn security_overview_loads_owned_public_binding_and_opens_real_key_management() {
    let calls = Arc::new(AtomicUsize::new(0));
    let browser = BrowserApp::new(
        HttpPolicy::default(),
        KeyChangeSpy {
            inner: StubGateway::default(),
            calls: calls.clone(),
        },
    );
    let mut req = request(
        "GET",
        "/settings?section=security",
        &authenticated_headers(),
        "",
    );
    req.headers
        .insert("user-agent".into(), "OSMAP/SecurityKeys-configured".into());
    let result = browser.handle_request(&req, "127.0.0.1");
    assert_eq!(result.response.status_code, 200);
    let html = body_text(&result);
    if let Some(directory) = std::env::var_os("OSMAP_UX_SECURITY_FIXTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        assert!(directory.is_absolute() && directory.is_dir());
        assert_eq!(std::fs::canonicalize(&directory).unwrap(), directory);
        let path = directory.join("configured-security.html");
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(path).unwrap().write_all(html.as_bytes()).unwrap();
    }
    assert!(html.contains("Account binding configured"));
    assert!(html.contains(&"A".repeat(40)));
    assert!(html.contains("private-key readiness is checked when an operation runs"));
    assert!(html.contains("href=\"/settings/keys\" aria-label=\"Manage OpenPGP keys\""));
    assert!(!html.contains("Key management and capability unavailable"));
    assert!(!html.contains("private key is unlocked"));
    let keys = browser.handle_request(
        &request("GET", "/settings/keys", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert_eq!(keys.response.status_code, 200);
    assert!(body_text(&keys).contains("OpenPGP Key Management"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "overview/navigation must not mutate keys"
    );
}

#[test]
fn security_overview_unknown_foreign_and_ineligible_public_states_do_not_claim_readiness() {
    let browser = BrowserApp::new(
        HttpPolicy::default(),
        KeyChangeSpy {
            inner: StubGateway::default(),
            calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    for (mode, expected) in [
        (
            "unavailable",
            "Account bindings or public inventory unavailable",
        ),
        (
            "foreign-state",
            "Account bindings or public inventory unavailable",
        ),
        (
            "foreign-binding",
            "Account bindings or public inventory unavailable",
        ),
        ("unbound", "Account binding needed"),
        ("missing-key", "Bound public key missing"),
        ("revoked", "Bound public key ineligible"),
    ] {
        let mut req = request(
            "GET",
            "/settings?section=security",
            &authenticated_headers(),
            "",
        );
        req.headers
            .insert("user-agent".into(), format!("OSMAP/SecurityKeys-{mode}"));
        let result = browser.handle_request(&req, "127.0.0.1");
        assert_eq!(result.response.status_code, 200);
        let html = body_text(&result);
        assert!(html.contains(expected), "{mode}");
        assert!(
            !html.contains(&"A".repeat(40)),
            "{mode}: no unsupported/foreign fingerprint"
        );
        assert!(!html.contains("Account binding configured"), "{mode}");
        assert!(!html.contains("private key is unlocked"), "{mode}");
        assert!(html.contains("href=\"/settings/keys\" aria-label=\"Manage OpenPGP keys\""));
    }
    let unauthenticated = browser.handle_request(
        &request("GET", "/settings?section=security", &[], ""),
        "127.0.0.1",
    );
    assert_eq!(unauthenticated.response.status_code, 303);
    assert_eq!(location_header(&unauthenticated), "/login");
    assert!(!body_text(&unauthenticated).contains(&"A".repeat(40)));
}
