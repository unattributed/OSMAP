use super::*;
struct KeyChangeSpy {
    inner: StubGateway,
    calls: Arc<AtomicUsize>,
}
impl BrowserGateway for KeyChangeSpy {
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

#[test]
fn compose_live_protection_controls_are_direct_and_preserve_selection() {
    let mut model = crate::http_ui::ComposePageModel {
        protection: crate::send::ProtectionIntent::default(),
        openpgp: Some(ComposeProtectionView {
            runtime_configured: true,
            revision: Some(0),
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
    };
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
    model.openpgp.as_mut().unwrap().preflight = Some(crate::openpgp_bindings::Preflight {
        revision: 0,
        state: crate::openpgp_bindings::PreflightState::Blocked,
        signing: crate::openpgp_bindings::KeyStatus::Ready,
        self_encryption: crate::openpgp_bindings::KeyStatus::Ready,
        recipients: vec![crate::openpgp_bindings::RecipientReadiness {
            address: "bob@example.test".into(),
            state: crate::openpgp_bindings::KeyStatus::Ready,
            requirement: crate::openpgp_bindings::Requirement::Required,
        }],
        reasons: vec![crate::openpgp_bindings::BlockReason::RecipientRequiresEncryption],
        plan: None,
    });
    let body = crate::http_ui::render_compose_page(&model).as_str().to_owned();
    assert!(body.contains("<strong>Blocked</strong>"));
    assert!(body.contains("bob@example.test</span>: Public key eligible; Encryption required"));
    assert!(body.contains("A recipient binding requires encryption. Select Encrypt on send"));
    assert!(!body.contains("<strong>No protection selected</strong>"));
    assert!(!body.contains("name=\"pgp_encrypt\" checked"));
}
