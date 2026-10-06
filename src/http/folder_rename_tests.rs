use super::*;
struct Fixture {
    root: PathBuf,
    app: BrowserApp<StubGateway>,
}
impl Fixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "folder-rename-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let gateway = StubGateway {
            sent_location_store: Some(crate::sent_location::Store::new(root.join("sent"))),
            bin_store: Some(crate::bin_folder::BinPreferencesStore::new(
                root.join("bin"),
            )),
            settings_store: Some(crate::settings::FileUserSettingsStore::new(
                root.join("settings"),
            )),
            labels_store: Some(crate::labels::LabelStore::new(
                root.join("settings/labels-v1"),
            )),
            snooze_store: Some(crate::snooze::SnoozeStore::new(root.join("settings"))),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        };
        gateway.created_folders.lock().unwrap().insert(
            "alice@example.com".into(),
            vec!["INBOX.Alpha".into(), "INBOX.Existing".into()],
        );
        let app = BrowserApp::new(HttpPolicy::default(), gateway);
        Self { root, app }
    }
    fn run(
        &self,
        method: &str,
        path: &str,
        body: &str,
        agent: &str,
        bob: bool,
    ) -> HandledHttpResponse {
        let mut req = request(method, path, &authenticated_same_origin_headers(), body);
        req.headers.insert("user-agent".into(), agent.into());
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn form(&self) -> String {
        format!("csrf_token={}&source=INBOX.Alpha&source_guid={}&parent_guid=1234567890abcdef1234567890abcdef&leaf=Beta&action=review", StubGateway::validated_session().record.csrf_token, self.app.gateway.created_folder_guid("alice@example.com", "INBOX.Alpha").unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn folder_rename_route_review_confirmation_csrf_stale_unknown_and_continuity() {
    let f = Fixture::new();
    let form = f.form();
    let apply = form.replace("action=review", "action=rename&confirm=rename");
    let get = f.run(
        "GET",
        "/settings/folders/rename?source=INBOX.Alpha",
        "",
        "FolderCreateValid",
        false,
    );
    assert_eq!(get.response.status_code, 200);
    assert!(body_text(&get).contains("Review rename"));
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/rename",
            &form,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        200
    );
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    for (body, agent, code) in [
        (
            apply.replace("csrf_token=", "csrf_token=wrong"),
            "FolderCreateValid",
            403,
        ),
        (
            apply.replace("confirm=rename", "confirm=no"),
            "FolderCreateValid",
            400,
        ),
        (
            apply.replace("leaf=Beta", "leaf=Existing"),
            "FolderCreateValid",
            409,
        ),
        (
            apply.replace(
                "parent_guid=1234567890abcdef1234567890abcdef",
                &format!("parent_guid={}", "b".repeat(32)),
            ),
            "FolderCreateValid",
            409,
        ),
        (
            apply.replace("source_guid=", "source_guid=wrong"),
            "FolderCreateValid",
            409,
        ),
        (apply.clone() + "&leaf=Gamma", "FolderCreateValid", 403),
        (apply.clone(), "FolderTreeStatusWrongOwner", 503),
        (apply.clone(), "FolderTreeWrongOwner", 503),
        (
            apply.clone() + "&account=bob%40example.com",
            "FolderCreateValid",
            400,
        ),
    ] {
        let r = f.run("POST", "/settings/folders/rename", &body, agent, false);
        assert_eq!(r.response.status_code, code, "{agent}/{body}");
        assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
        if agent == "FolderCreateRenameUnknown" {
            assert!(!body_text(&r).contains("action=\"/settings/folders/rename\""));
            assert!(body_text(&r).contains("href=\"/settings?section=copies\""));
        }
    }
    let unicode = apply.replace(
        "leaf=Beta",
        &format!("leaf={}", url_encode("Élodie & Office")),
    );
    let r = f.run(
        "POST",
        "/settings/folders/rename",
        &unicode,
        "FolderCreateValid",
        false,
    );
    assert_eq!(r.response.status_code, 303);
    let renamed = f.app.gateway.renamed_folders.lock().unwrap();
    assert_eq!(renamed.len(), 1);
    assert_eq!(renamed[0].destination(), "INBOX.Élodie & Office");
    assert_eq!(renamed[0].account(), "alice@example.com");
    let guid = renamed[0].source_guid().to_owned();
    drop(renamed);
    assert_eq!(
        f.app
            .gateway
            .created_folder_guid("alice@example.com", "INBOX.Élodie & Office"),
        Some(guid)
    );
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/rename",
            &apply,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        409
    );
}
#[test]
fn folder_rename_route_protected_destinations_and_accounts() {
    for role in ["archive", "bin", "sent"] {
        let f = Fixture::new();
        let form = f.form();
        match role {
            "archive" => {
                f.app
                    .gateway
                    .settings_store
                    .as_ref()
                    .unwrap()
                    .save_archive("alice@example.com", Some("INBOX.Alpha"))
                    .unwrap();
            }
            "bin" => {
                f.app
                    .gateway
                    .bin_store
                    .as_ref()
                    .unwrap()
                    .save("alice@example.com", 0, "INBOX.Alpha")
                    .unwrap();
            }
            "sent" => {
                f.app
                    .gateway
                    .sent_location_store
                    .as_ref()
                    .unwrap()
                    .save(
                        "alice@example.com",
                        0,
                        "INBOX.Alpha",
                        &f.app
                            .gateway
                            .created_folder_guid("alice@example.com", "INBOX.Alpha")
                            .unwrap(),
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            f.run(
                "POST",
                "/settings/folders/rename",
                &form,
                "FolderCreateValid",
                false
            )
            .response
            .status_code,
            409,
            "{role}"
        );
        assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    }
    let f = Fixture::new();
    let r = f.run(
        "POST",
        "/settings/folders/rename",
        &f.form()
            .replace("action=review", "action=rename&confirm=rename")
            .replace(
                &StubGateway::validated_session().record.csrf_token,
                &"c".repeat(64),
            ),
        "FolderCreateValid",
        true,
    );
    assert_ne!(r.response.status_code, 303);
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    let r = f.run(
        "GET",
        "/settings?section=copies&folder=INBOX.Alpha",
        "",
        "FolderCreateValid",
        false,
    );
    assert_eq!(r.response.status_code, 200);
    assert!(body_text(&r).contains("/settings/folders/rename?source=INBOX.Alpha"));
    assert_eq!(
        f.run(
            "GET",
            "/settings/folders/rename?source=INBOX",
            "",
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        503
    );
}
#[test]
fn folder_rename_runtime_preferences_share_nonwaiting_admission() {
    let root = temp_dir(&format!(
        "folder-rename-admission-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-rename",
        "127.0.0.1",
        "Fixture",
    )
    .unwrap();
    let guard = crate::folder_rename::settings_gate(
        &gateway.settings_dir,
        &session.record.canonical_username,
    )
    .unwrap();
    assert!(gateway
        .update_bin_preference(&session, 0, "INBOX.User")
        .is_err());
    assert!(gateway
        .save_sent_location_preference(&session, 0, "INBOX.User", &"a".repeat(32))
        .is_err());
    assert!(matches!(
        gateway
            .update_content_setting(
                &context,
                &session,
                HtmlDisplayPreference::PreferSanitizedHtml
            )
            .decision,
        BrowserSettingsUpdateDecision::Denied { .. }
    ));
    assert!(matches!(
        gateway
            .update_archive_setting(&context, &session, Some("INBOX.User"))
            .decision,
        BrowserSettingsUpdateDecision::Denied { .. }
    ));
    assert!(matches!(
        gateway
            .update_settings(
                &context,
                &session,
                HtmlDisplayPreference::PreferSanitizedHtml,
                Some("INBOX.User")
            )
            .decision,
        BrowserSettingsUpdateDecision::Denied { .. }
    ));
    assert!(crate::folder_rename::settings_gate(
        &gateway.settings_dir,
        &session.record.canonical_username
    )
    .is_err());
    assert!(crate::folder_rename::settings_gate(&gateway.settings_dir, "bob@example.com").is_ok());
    drop(guard);
    assert!(crate::folder_rename::settings_gate(
        &gateway.settings_dir,
        &session.record.canonical_username
    )
    .is_ok());
    assert!(gateway
        .update_bin_preference(&session, 0, "INBOX.User")
        .is_ok());
    assert!(gateway
        .save_sent_location_preference(&session, 0, "INBOX.User", &"a".repeat(32))
        .is_ok());
    assert_eq!(
        gateway
            .update_archive_setting(&context, &session, Some("INBOX.User"))
            .decision,
        BrowserSettingsUpdateDecision::Updated
    );
    assert_eq!(
        gateway
            .update_content_setting(
                &context,
                &session,
                HtmlDisplayPreference::PreferSanitizedHtml
            )
            .decision,
        BrowserSettingsUpdateDecision::Updated
    );
    assert_eq!(
        gateway
            .update_settings(
                &context,
                &session,
                HtmlDisplayPreference::PreferSanitizedHtml,
                Some("INBOX.User")
            )
            .decision,
        BrowserSettingsUpdateDecision::Updated
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn folder_rename_route_rechecks_changed_roles_and_refuses_missing_authority() {
    let mut f = Fixture::new();
    let form = f.form();
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/rename",
            &form,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        200
    );
    f.app
        .gateway
        .bin_store
        .as_ref()
        .unwrap()
        .save("alice@example.com", 0, "INBOX.Beta")
        .unwrap();
    let confirmed = form.replace("action=review", "action=rename&confirm=rename");
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/rename",
            &confirmed,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        409
    );
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    f.app.gateway.sent_location_store = None;
    assert_eq!(
        f.run(
            "POST",
            "/settings/folders/rename",
            &confirmed,
            "FolderCreateValid",
            false
        )
        .response
        .status_code,
        503
    );
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
}
#[test]
fn folder_rename_pending_result_is_account_bound_and_never_retried() {
    for (agent, confirmed) in [
        ("FolderCreateRenameUnknown", false),
        ("FolderCreateRenameUnknownCommitted", true),
    ] {
        let f = Fixture::new();
        let apply = f
            .form()
            .replace("action=review", "action=rename&confirm=rename");
        let unknown = f.run("POST", "/settings/folders/rename", &apply, agent, false);
        assert_eq!(unknown.response.status_code, 503);
        assert!(!body_text(&unknown).contains("action=\"/settings/folders/rename\""));
        let session = StubGateway::validated_session();
        let stored = f
            .app
            .gateway
            .pending_folder_rename(&session)
            .unwrap()
            .unwrap();
        assert_eq!(stored.destination(), "INBOX.Beta");
        assert_eq!(
            f.run(
                "POST",
                "/settings/folders/rename",
                &apply,
                "FolderCreateValid",
                false
            )
            .response
            .status_code,
            409
        );
        let before = f.app.gateway.renamed_folders.lock().unwrap().len();
        let fields = format!("csrf_token={}&confirm=check", session.record.csrf_token);
        assert_eq!(
            f.run(
                "POST",
                "/settings/folders/rename/check",
                &fields.replace("csrf_token=", "csrf_token=wrong"),
                "FolderCreateValid",
                false
            )
            .response
            .status_code,
            403
        );
        assert_eq!(
            f.run(
                "POST",
                "/settings/folders/rename/check",
                &(fields.clone() + "&result=renamed"),
                "FolderCreateValid",
                false
            )
            .response
            .status_code,
            400
        );
        let result = f.run(
            "POST",
            "/settings/folders/rename/check",
            &fields,
            "FolderCreateValid",
            false,
        );
        assert_eq!(
            result.response.status_code,
            if confirmed { 303 } else { 409 }
        );
        assert_eq!(f.app.gateway.renamed_folders.lock().unwrap().len(), before);
        assert_eq!(
            f.app
                .gateway
                .pending_folder_rename(&session)
                .unwrap()
                .is_none(),
            confirmed
        );
        let mut bob = session.clone();
        bob.record.canonical_username = "bob@example.com".into();
        assert!(f.app.gateway.pending_folder_rename(&bob).unwrap().is_none());
        if !confirmed {
            assert!(body_text(&result).contains("A proven settled helper result is required"));
            assert!(crate::folder_rename::settings_gate(
                f.app
                    .gateway
                    .settings_store
                    .as_ref()
                    .unwrap()
                    .settings_path_for_username("alice@example.com")
                    .parent()
                    .unwrap(),
                "alice@example.com"
            )
            .is_err());
        }
    }
}
#[test]
fn folder_rename_pending_record_restart_and_corruption_fail_closed() {
    let f = Fixture::new();
    let account = "alice@example.com";
    let directory = f
        .app
        .gateway
        .settings_store
        .as_ref()
        .unwrap()
        .settings_path_for_username(account)
        .parent()
        .unwrap()
        .to_path_buf();
    let request = crate::folder_rename::RenameFolderRequest::new(
        account,
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let mut lease = crate::folder_rename::settings_gate(&directory, account).unwrap();
    lease.begin(&request).unwrap();
    drop(lease);
    assert!(crate::folder_rename::settings_gate(&directory, account).is_err());
    let recovered = crate::folder_rename::role_lease(&directory, account).unwrap();
    assert_eq!(recovered.pending(), Some(&request));
    drop(recovered);
    let file = crate::private_account_file::PrivateAccountFile::new(
        directory.clone(),
        "osmap-folder-roles-v1",
        4096,
    );
    let corrupt = file.lock(account).unwrap();
    corrupt
        .write(b"{\"version\":1,\"account\":\"bob@example.com\",\"pending\":null}")
        .unwrap();
    drop(corrupt);
    assert!(crate::folder_rename::role_lease(&directory, account).is_err());
    assert!(crate::folder_rename::settings_gate(&directory, account).is_err());
}

#[test]
fn folder_rename_lost_settled_refusal_clears_only_current_unchanged_identity() {
    let f = Fixture::new();
    let apply = f
        .form()
        .replace("action=review", "action=rename&confirm=rename");
    let result = f.run(
        "POST",
        "/settings/folders/rename",
        &apply,
        "FolderCreateRenameRefusedLost",
        false,
    );
    assert_eq!(result.response.status_code, 503);
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    let session = StubGateway::validated_session();
    assert!(f
        .app
        .gateway
        .pending_folder_rename(&session)
        .unwrap()
        .is_some());
    let fields = format!("csrf_token={}&confirm=check", session.record.csrf_token);
    let checked = f.run(
        "POST",
        "/settings/folders/rename/check",
        &fields,
        "FolderCreateValid",
        false,
    );
    assert_eq!(checked.response.status_code, 200);
    assert!(body_text(&checked).contains("finished without attempting a rename"));
    assert!(f
        .app
        .gateway
        .pending_folder_rename(&session)
        .unwrap()
        .is_none());
    assert!(f.app.gateway.renamed_folders.lock().unwrap().is_empty());
    assert!(crate::folder_rename::settings_gate(
        f.app
            .gateway
            .settings_store
            .as_ref()
            .unwrap()
            .settings_path_for_username("alice@example.com")
            .parent()
            .unwrap(),
        "alice@example.com"
    )
    .is_ok());
}

#[test]
fn folder_rename_preserves_private_labels_snooze_and_idempotent_reconciliation() {
    use crate::labels::{LabelChange, MessageIdentity as LabelIdentity};
    use crate::snooze::MessageIdentity as SnoozeIdentity;
    for mode in [0, 1, 2] {
        let uncertain = mode != 0;
        let f = Fixture::new();
        let account = "alice@example.com";
        let guid = f
            .app
            .gateway
            .created_folder_guid(account, "INBOX.Alpha")
            .unwrap();
        let row = MessageSummary {
            uid: 17,
            mailbox_name: "INBOX.Alpha".into(),
            metadata: Some(crate::message_metadata::MessageMetadata {
                threading: None,
                attachments: None,
                protection: crate::message_metadata::MessageProtection::Unknown,
                version: crate::message_metadata::MessageVersion::new(
                    guid.clone(),
                    "message-17".into(),
                )
                .unwrap(),
                attachment_count: Some(0),
                preview: None,
            }),
            to: None,
            flags: vec![],
            date_received: String::new(),
            size_virtual: 77,
            subject: None,
            from: None,
        };
        let labels = f.app.gateway.labels_store.as_ref().unwrap();
        let snooze = f.app.gateway.snooze_store.as_ref().unwrap();
        let original = LabelIdentity::from_summary(account, account, "INBOX.Alpha", &row).unwrap();
        let created = labels
            .change(account, 0, LabelChange::Create("Keep me"))
            .unwrap();
        let id = created.labels()[0].id().to_owned();
        let mut attached = labels
            .change(
                account,
                created.revision(),
                LabelChange::Attach {
                    id: &id,
                    message: &original,
                },
            )
            .unwrap();
        let snooze_identity =
            SnoozeIdentity::from_summary(account, account, "INBOX.Alpha", &row).unwrap();
        let now = f.app.gateway.snooze_clock();
        let before = snooze
            .set(account, &snooze_identity, 0, now + 600, now)
            .unwrap();
        let mut other = row.clone();
        other.uid = 18;
        other.metadata.as_mut().unwrap().version =
            crate::message_metadata::MessageVersion::new("f".repeat(32), "other-message".into())
                .unwrap();
        let other_label =
            LabelIdentity::from_summary(account, account, "INBOX.Alpha", &other).unwrap();
        attached = labels
            .change(
                account,
                attached.revision(),
                LabelChange::Attach {
                    id: &id,
                    message: &other_label,
                },
            )
            .unwrap();
        let other_snooze =
            SnoozeIdentity::from_summary(account, account, "INBOX.Alpha", &other).unwrap();
        snooze
            .set(account, &other_snooze, before.revision(), now + 700, now)
            .unwrap();
        let bob_original =
            LabelIdentity::from_summary("bob@example.com", "bob@example.com", "INBOX.Alpha", &row)
                .unwrap();
        let bob_labels = labels
            .change("bob@example.com", 0, LabelChange::Create("Bob only"))
            .unwrap();
        let bob_id = bob_labels.labels()[0].id().to_owned();
        let bob_labels = labels
            .change(
                "bob@example.com",
                bob_labels.revision(),
                LabelChange::Attach {
                    id: &bob_id,
                    message: &bob_original,
                },
            )
            .unwrap();
        let bob_snooze_identity =
            SnoozeIdentity::from_summary("bob@example.com", "bob@example.com", "INBOX.Alpha", &row)
                .unwrap();
        let bob_snooze = snooze
            .set("bob@example.com", &bob_snooze_identity, 0, now + 900, now)
            .unwrap();
        let apply = f
            .form()
            .replace("action=review", "action=rename&confirm=rename");
        let result = f.run(
            "POST",
            "/settings/folders/rename",
            &apply,
            match mode {
                0 => "FolderCreateValid",
                1 => "FolderCreateRenameUnknownCommitted",
                _ => "FolderCreateRenameMetadataFailure",
            },
            false,
        );
        assert_eq!(
            result.response.status_code,
            if uncertain { 503 } else { 303 }
        );
        if uncertain {
            let fields = format!(
                "csrf_token={}&confirm=check",
                StubGateway::validated_session().record.csrf_token
            );
            assert_eq!(
                f.run(
                    "POST",
                    "/settings/folders/rename/check",
                    &fields,
                    "FolderCreateValid",
                    false
                )
                .response
                .status_code,
                303
            );
        }
        let mut destination = row.clone();
        destination.mailbox_name = "INBOX.Beta".into();
        let dest =
            LabelIdentity::from_summary(account, account, "INBOX.Beta", &destination).unwrap();
        let current = labels.load(account).unwrap();
        assert_eq!(current.labels_for(&dest).unwrap()[0].id(), id);
        assert_eq!(current.labels_for(&other_label).unwrap()[0].id(), id);
        assert!(current.labels_for(&original).unwrap().is_empty());
        assert_eq!(current.revision(), attached.revision() + 1);
        let after = snooze.load(account, now).unwrap();
        assert_eq!(after.markers()[0].identity().folder(), "INBOX.Beta");
        assert_eq!(after.markers()[0].identity().mailbox_guid(), guid);
        assert_eq!(after.markers()[0].identity().message_guid(), "message-17");
        assert_eq!(after.markers()[0].identity().uid(), 17);
        assert_eq!(after.markers()[0].until(), before.markers()[0].until());
        assert_eq!(after.markers()[1].identity(), &other_snooze);
        let rename = f.app.gateway.renamed_folders.lock().unwrap()[0].clone();
        labels.reconcile_folder_rename(&rename).unwrap();
        snooze.reconcile_folder_rename(&rename).unwrap();
        assert_eq!(labels.load(account).unwrap().revision(), current.revision());
        assert_eq!(
            snooze.load(account, now).unwrap().revision(),
            after.revision()
        );
        assert_eq!(labels.load("bob@example.com").unwrap(), bob_labels);
        assert_eq!(snooze.load("bob@example.com", now).unwrap(), bob_snooze);
    }
}
