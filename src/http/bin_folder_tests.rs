use super::*;

fn bin_settings_selector(section: &str, control: &str) {
    let mut req = request(
        "GET",
        &format!("/settings?section={section}"),
        &authenticated_headers(),
        "",
    );
    req.headers.insert("user-agent".into(), "FolderTree".into());
    let response = app().handle_request(&req, "127.0.0.1");
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    // Positive control: the real account-owned Archive selector is loaded.
    assert!(html.contains("name=\"archive_mailbox_name\""));
    assert!(html.contains("INBOX.Projects"));
    assert!(
        html.contains(&format!("<select id=\"{control}\"")),
        "{section} must offer a real owned Bin choice"
    );
    assert!(html.contains("action=\"/settings/bin-folder\""));
    assert!(html.contains("name=\"mailbox_name\""));
    assert!(html.contains("name=\"expected_revision\""));
    assert!(!html.contains("Trash (fixed)"));
}

#[test]
fn bin_folder_reading_has_real_owned_selector_and_save() {
    bin_settings_selector("reading", "reading-bin-folder");
}

#[test]
fn bin_folder_copies_has_real_owned_selector_and_save() {
    bin_settings_selector("copies", "copies-bin");
}

const BIN_ALICE: &str = "alice@example.com";
const BIN_BOB: &str = "bob@example.com";

struct BinFixture {
    root: PathBuf,
    store: crate::bin_folder::BinPreferencesStore,
    app: BrowserApp<StubGateway>,
}

impl BinFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "bin-folder-integrated-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::bin_folder::BinPreferencesStore::new(root.join("settings"));
        let gateway = StubGateway {
            bin_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        };
        gateway
            .created_folders
            .lock()
            .unwrap()
            .insert(BIN_ALICE.into(), vec!["Deleted".into()]);
        let app = BrowserApp::new(
            HttpPolicy {
                mailbox_worker_budget: 1,
                ..HttpPolicy::default()
            },
            gateway,
        );
        Self { root, store, app }
    }

    fn settings_form(
        &self,
        revision: u64,
        folder: &str,
        section: &str,
    ) -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "csrf_token".into(),
                StubGateway::validated_session().record.csrf_token,
            ),
            ("expected_revision".into(), revision.to_string()),
            ("mailbox_name".into(), folder.into()),
            ("section".into(), section.into()),
        ])
    }

    fn post(
        &self,
        path: &str,
        fields: &BTreeMap<String, String>,
        agent: &str,
    ) -> HandledHttpResponse {
        self.post_as(path, fields, agent, None, None)
    }

    fn post_as(
        &self,
        path: &str,
        fields: &BTreeMap<String, String>,
        agent: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> HandledHttpResponse {
        let body = fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = request("POST", path, &authenticated_same_origin_headers(), &body);
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        req.headers.insert("user-agent".into(), agent.into());
        if let Some(cookie) = cookie {
            req.headers.insert("cookie".into(), cookie.into());
        }
        if let Some(origin) = origin {
            req.headers.insert("origin".into(), origin.into());
        }
        self.app.handle_request(&req, "127.0.0.1")
    }

    fn get(&self, path: &str, agent: &str) -> HandledHttpResponse {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers.insert("user-agent".into(), agent.into());
        self.app.handle_request(&req, "127.0.0.1")
    }

    fn move_form(&self, source: &str, uid: u64, action: &str) -> BTreeMap<String, String> {
        let version = self
            .app
            .gateway
            .fixture_current_metadata(BIN_ALICE, source, uid)
            .unwrap()
            .version;
        BTreeMap::from([
            (
                "csrf_token".into(),
                StubGateway::validated_session().record.csrf_token,
            ),
            ("mailbox".into(), source.into()),
            ("uid".into(), uid.to_string()),
            ("mailbox_guid".into(), version.mailbox_guid),
            ("message_guid".into(), version.message_guid),
            ("action".into(), action.into()),
            // Bin must resolve its stored destination rather than trust this field.
            ("destination_mailbox".into(), "Trash".into()),
            (
                "return_to".into(),
                format!("/mailbox?name={}", url_encode(source)),
            ),
        ])
    }

    fn assert_idle(&self) {
        assert_eq!(self.app.request_budgets.mailbox_workers.active_count(), 0);
    }
}

impl Drop for BinFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn saved_bin_control<'a>(html: &'a str, section: &str) -> &'a str {
    let id = if section == "reading" {
        "reading-bin-folder-form"
    } else {
        "copies-bin-form"
    };
    let start = html
        .find(&format!("<form id=\"{id}\""))
        .expect("real Bin form");
    let end = html[start..].find("</form>").expect("Bin form end") + start;
    &html[start..end]
}

#[test]
fn bin_folder_save_reload_restart_account_isolation_and_stale_revision() {
    let fixture = BinFixture::new();
    assert_eq!(
        fixture.store.load(BIN_ALICE).unwrap(),
        crate::bin_folder::BinPreference::default()
    );
    let form = fixture.settings_form(0, "Deleted", "reading");
    let saved = fixture.post("/settings/bin-folder", &form, "FolderTree");
    assert_eq!(saved.response.status_code, 303, "{}", body_text(&saved));
    assert_eq!(
        location_header(&saved),
        "/settings?section=reading&updated=1"
    );
    let expected = crate::bin_folder::BinPreference {
        revision: 1,
        mailbox_name: "Deleted".into(),
    };
    assert_eq!(
        crate::bin_folder::BinPreferencesStore::new(fixture.root.join("settings"))
            .load(BIN_ALICE)
            .unwrap(),
        expected
    );
    for section in ["reading", "copies"] {
        let page = fixture.get(&format!("/settings?section={section}"), "FolderTree");
        assert_eq!(page.response.status_code, 200);
        let html = body_text(&page);
        let control = saved_bin_control(&html, section);
        assert!(control.contains("action=\"/settings/bin-folder\""));
        assert!(control.contains("name=\"expected_revision\" value=\"1\""));
        assert!(control.contains("<option value=\"Deleted\" selected>Deleted</option>"));
    }
    assert_eq!(
        fixture
            .post("/settings/bin-folder", &form, "FolderTree")
            .response
            .status_code,
        409
    );
    assert_eq!(fixture.store.load(BIN_ALICE).unwrap(), expected);
    assert_eq!(
        fixture.store.load(BIN_BOB).unwrap(),
        crate::bin_folder::BinPreference::default()
    );
    let mut bob = fixture.settings_form(0, "Trash", "copies");
    bob.insert("csrf_token".into(), "c".repeat(64));
    let response = fixture.post_as(
        "/settings/bin-folder",
        &bob,
        "FolderTree",
        Some(&format!("osmap_session={}", "b".repeat(64))),
        None,
    );
    assert_eq!(response.response.status_code, 303);
    assert_eq!(
        location_header(&response),
        "/settings?section=copies&updated=1"
    );
    assert_eq!(fixture.store.load(BIN_BOB).unwrap().revision, 1);
    assert_eq!(fixture.store.load(BIN_ALICE).unwrap(), expected);
    fixture.assert_idle();
}

#[test]
fn bin_folder_save_refuses_bad_auth_csrf_origin_and_exact_form_without_writes() {
    let fixture = BinFixture::new();
    let form = fixture.settings_form(0, "Deleted", "reading");
    for (key, value, status) in [
        ("csrf_token", "bad", 403),
        ("expected_revision", "00", 400),
        ("expected_revision", "18446744073709551616", 400),
        ("mailbox_name", "INBOX", 400),
        ("mailbox_name", "Deleted\r\nOther", 400),
        ("section", "general", 400),
        ("unexpected", "1", 400),
    ] {
        let mut changed = form.clone();
        changed.insert(key.into(), value.into());
        let refused = fixture.post("/settings/bin-folder", &changed, "FolderTree");
        assert_eq!(
            refused.response.status_code,
            status,
            "{key}: {}",
            body_text(&refused)
        );
        assert_eq!(
            fixture.store.load(BIN_ALICE).unwrap(),
            crate::bin_folder::BinPreference::default()
        );
        fixture.assert_idle();
    }
    let mut missing = form.clone();
    missing.remove("mailbox_name");
    assert_eq!(
        fixture
            .post("/settings/bin-folder", &missing, "FolderTree")
            .response
            .status_code,
        400
    );
    assert_eq!(
        fixture
            .post_as(
                "/settings/bin-folder",
                &form,
                "FolderTree",
                None,
                Some("https://foreign.example.test")
            )
            .response
            .status_code,
        403
    );
    let unauthenticated = fixture.post_as(
        "/settings/bin-folder",
        &form,
        "FolderTree",
        Some("osmap_session=invalid"),
        None,
    );
    assert_eq!(unauthenticated.response.status_code, 303);
    assert_eq!(location_header(&unauthenticated), "/login");
    assert_eq!(
        fixture.store.load(BIN_ALICE).unwrap(),
        crate::bin_folder::BinPreference::default()
    );
    fixture.assert_idle();
}

#[test]
fn bin_folder_save_requires_current_exact_owned_selectable_metadata() {
    for (folder, agent, status) in [
        ("Missing", "FolderTree", 400),
        ("deleted", "FolderTree", 400),
        ("Deleted", "FolderTreeBinNoselect", 400),
        ("Deleted", "FolderTreeBinAbsent", 400),
        ("Deleted", "FolderTreeWrongOwner", 503),
        ("Deleted", "FolderTreeMalformed", 503),
    ] {
        let fixture = BinFixture::new();
        let response = fixture.post(
            "/settings/bin-folder",
            &fixture.settings_form(0, folder, "copies"),
            agent,
        );
        assert_eq!(
            response.response.status_code,
            status,
            "{agent}/{folder}: {}",
            body_text(&response)
        );
        assert_eq!(
            fixture.store.load(BIN_ALICE).unwrap(),
            crate::bin_folder::BinPreference::default()
        );
        assert_eq!(
            fixture.store.load(BIN_BOB).unwrap(),
            crate::bin_folder::BinPreference::default()
        );
        fixture.assert_idle();
    }
}

#[test]
fn bin_folder_move_and_restore_resolve_saved_exact_owned_target_with_one_worker() {
    let fixture = BinFixture::new();
    assert_eq!(
        fixture
            .post(
                "/settings/bin-folder",
                &fixture.settings_form(0, "Deleted", "copies"),
                "FolderTree"
            )
            .response
            .status_code,
        303
    );
    let original = fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 9)
        .unwrap();
    let flags = fixture
        .app
        .gateway
        .fixture_message_flags(BIN_ALICE, "INBOX", 9);
    let neighbour = fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 10);
    let foreign = fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_BOB, "INBOX", 9);
    let moved = fixture.post(
        "/message/move",
        &fixture.move_form("INBOX", 9, "bin"),
        "FolderTree",
    );
    assert_eq!(moved.response.status_code, 303, "{}", body_text(&moved));
    assert_eq!(
        moved
            .audit_events
            .iter()
            .filter(|event| event.action == "stub_message_move")
            .count(),
        1
    );
    assert!(fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 9)
        .is_none());
    let rows = fixture
        .app
        .gateway
        .fixture_reconcile_messages(BIN_ALICE, "Deleted", vec![]);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].metadata.as_ref().unwrap().version.message_guid,
        original.version.message_guid
    );
    assert_eq!(rows[0].flags, flags);
    assert!(fixture
        .app
        .gateway
        .fixture_reconcile_messages(BIN_ALICE, "Trash", vec![])
        .is_empty());
    assert_eq!(
        fixture
            .app
            .gateway
            .fixture_current_metadata(BIN_ALICE, "INBOX", 10),
        neighbour
    );
    assert_eq!(
        fixture
            .app
            .gateway
            .fixture_current_metadata(BIN_BOB, "INBOX", 9),
        foreign
    );
    fixture.assert_idle();
    let restored = fixture.post(
        "/message/move",
        &fixture.move_form("Deleted", rows[0].uid, "restore"),
        "FolderTree",
    );
    assert_eq!(
        restored.response.status_code,
        303,
        "{}",
        body_text(&restored)
    );
    assert!(fixture
        .app
        .gateway
        .fixture_reconcile_messages(BIN_ALICE, "Deleted", vec![])
        .is_empty());
    let restored_rows = fixture
        .app
        .gateway
        .fixture_reconcile_messages(BIN_ALICE, "INBOX", vec![]);
    assert_eq!(restored_rows.len(), 1);
    assert_eq!(
        restored_rows[0]
            .metadata
            .as_ref()
            .unwrap()
            .version
            .message_guid,
        original.version.message_guid
    );
    assert_eq!(restored_rows[0].flags, flags);
    assert_eq!(
        fixture
            .app
            .gateway
            .fixture_current_metadata(BIN_ALICE, "INBOX", 10),
        neighbour
    );
    assert_eq!(
        fixture
            .app
            .gateway
            .fixture_current_metadata(BIN_BOB, "INBOX", 9),
        foreign
    );
    fixture.assert_idle();
}

#[test]
fn bin_folder_move_rechecks_metadata_and_never_falls_back_to_trash() {
    for agent in [
        "FolderTreeBinNoselect",
        "FolderTreeBinAbsent",
        "FolderTreeWrongOwner",
        "FolderTreeMalformed",
    ] {
        let fixture = BinFixture::new();
        fixture.store.save(BIN_ALICE, 0, "Deleted").unwrap();
        let original = fixture
            .app
            .gateway
            .fixture_current_metadata(BIN_ALICE, "INBOX", 9);
        let refused = fixture.post(
            "/message/move",
            &fixture.move_form("INBOX", 9, "bin"),
            agent,
        );
        assert_eq!(
            refused.response.status_code,
            503,
            "{agent}: {}",
            body_text(&refused)
        );
        assert!(!refused
            .audit_events
            .iter()
            .any(|event| event.action == "stub_message_move"));
        assert_eq!(
            fixture
                .app
                .gateway
                .fixture_current_metadata(BIN_ALICE, "INBOX", 9),
            original
        );
        for folder in ["Deleted", "Trash"] {
            assert!(fixture
                .app
                .gateway
                .fixture_reconcile_messages(BIN_ALICE, folder, vec![])
                .is_empty());
        }
        fixture.assert_idle();
    }
}

#[test]
fn bin_folder_restore_requires_exact_current_saved_source_and_guid() {
    let fixture = BinFixture::new();
    fixture.store.save(BIN_ALICE, 0, "Deleted").unwrap();
    for (source, action) in [
        ("Trash", "restore"),
        ("INBOX", "restore"),
        ("Deleted", "bin"),
    ] {
        let refused = fixture.post(
            "/message/move",
            &fixture.move_form(source, 9, action),
            "FolderTree",
        );
        assert_eq!(refused.response.status_code, 400);
        assert!(!refused
            .audit_events
            .iter()
            .any(|event| event.action == "stub_message_move"));
    }
    let mut stale = fixture.move_form("INBOX", 9, "bin");
    stale.insert("message_guid".into(), "absent-guid".into());
    let refused = fixture.post("/message/move", &stale, "FolderTree");
    assert_eq!(refused.response.status_code, 409);
    assert!(!refused
        .audit_events
        .iter()
        .any(|event| event.action == "stub_message_move"));
    assert!(fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 9)
        .is_some());
    fixture.assert_idle();
}

#[test]
fn bin_folder_missing_saved_target_and_corrupt_record_stop_before_any_move() {
    let fixture = BinFixture::new();
    fixture.store.save(BIN_ALICE, 0, "Missing").unwrap();
    let form = fixture.move_form("INBOX", 9, "bin");
    let missing = fixture.post("/message/move", &form, "FolderTree");
    assert_eq!(missing.response.status_code, 400);
    assert!(!missing
        .audit_events
        .iter()
        .any(|event| event.action == "stub_message_move"));
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"osmap-bin-folder-v1\0");
    digest.update(BIN_ALICE.as_bytes());
    let path = fixture
        .root
        .join("settings")
        .join(format!("{:x}.json", digest.finalize()));
    fs::write(&path, b"invalid-bin-record").unwrap();
    let corrupt = fixture.post("/message/move", &form, "FolderTree");
    assert_eq!(corrupt.response.status_code, 503);
    assert!(!corrupt
        .audit_events
        .iter()
        .any(|event| event.action == "stub_message_move"));
    assert_eq!(fs::read(&path).unwrap(), b"invalid-bin-record");
    assert!(fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 9)
        .is_some());
    for folder in ["Missing", "Trash"] {
        assert!(fixture
            .app
            .gateway
            .fixture_reconcile_messages(BIN_ALICE, folder, vec![])
            .is_empty());
    }
    fixture.assert_idle();
}

fn bin_record_path(fixture: &BinFixture) -> PathBuf {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"osmap-bin-folder-v1\0");
    digest.update(BIN_ALICE.as_bytes());
    fixture
        .root
        .join("settings")
        .join(format!("{:x}.json", digest.finalize()))
}

fn bin_native_attribute(tag: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let start = tag.find(&marker)? + marker.len();
    let end = tag[start..].find('"')? + start;
    Some(
        tag[start..end]
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">"),
    )
}

fn rendered_bin_move_fields(html: &str, uid: u64, action: &str) -> BTreeMap<String, String> {
    html.split("<form ")
        .find_map(|part| {
            let form = part.split_once("</form>")?.0;
            let open_tag = form.split_once('>')?.0;
            if bin_native_attribute(open_tag, "action").as_deref() != Some("/message/move") {
                return None;
            }
            let enabled = form.split("<button ").any(|button| {
                let Some(tag) = button.split_once('>').map(|value| value.0) else {
                    return false;
                };
                bin_native_attribute(tag, "name").as_deref() == Some("action")
                    && bin_native_attribute(tag, "value").as_deref() == Some(action)
                    && !tag.contains(" disabled")
                    && bin_native_attribute(tag, "type").as_deref() == Some("submit")
            });
            if !enabled {
                return None;
            }
            let mut fields: BTreeMap<String, String> = form
                .split("<input ")
                .filter_map(|input| {
                    let tag = input.split_once('>')?.0;
                    Some((
                        bin_native_attribute(tag, "name")?,
                        bin_native_attribute(tag, "value")?,
                    ))
                })
                .collect();
            if fields.get("uid") != Some(&uid.to_string()) {
                return None;
            }
            fields.insert("action".into(), action.into());
            Some(fields)
        })
        .expect("an actual enabled identity-bound Bin/Restore submit form")
}

#[test]
fn bin_folder_shortcut_resolves_saved_owned_folder_and_refuses_missing_or_corrupt() {
    let fixture = BinFixture::new();
    fixture.store.save(BIN_ALICE, 0, "Deleted").unwrap();
    let shortcut = fixture.get("/mailbox/shortcut?kind=bin", "FolderTree");
    assert_eq!(
        shortcut.response.status_code,
        303,
        "{}",
        body_text(&shortcut)
    );
    assert_eq!(location_header(&shortcut), "/mailbox?name=Deleted");
    fixture.store.save(BIN_ALICE, 1, "Missing").unwrap();
    let missing = fixture.get("/mailbox/shortcut?kind=bin", "FolderTree");
    assert_eq!(missing.response.status_code, 404);
    assert!(!missing
        .response
        .headers
        .iter()
        .any(|(name, _)| name == "Location"));
    assert_eq!(
        fixture.store.load(BIN_ALICE).unwrap().mailbox_name,
        "Missing"
    );
    fs::write(bin_record_path(&fixture), b"corrupt-bin-record").unwrap();
    let corrupt = fixture.get("/mailbox/shortcut?kind=bin", "FolderTree");
    assert_eq!(corrupt.response.status_code, 503);
    assert!(!corrupt
        .response
        .headers
        .iter()
        .any(|(name, _)| name == "Location"));
    assert_eq!(
        fs::read(bin_record_path(&fixture)).unwrap(),
        b"corrupt-bin-record"
    );
    assert!(fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 9)
        .is_some());
    fixture.assert_idle();
}

#[test]
fn bin_folder_top_level_page_and_reader_offer_actual_bin_then_restore_forms() {
    let fixture = BinFixture::new();
    fixture.store.save(BIN_ALICE, 0, "Deleted").unwrap();
    let selected = fixture.get(
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9",
        "FolderTree",
    );
    assert_eq!(selected.response.status_code, 200);
    let html = body_text(&selected);
    assert!(html.contains("aria-label=\"Move message to Bin\""));
    let form = rendered_bin_move_fields(&html, 9, "bin");
    let original = fixture
        .app
        .gateway
        .fixture_current_metadata(BIN_ALICE, "INBOX", 9)
        .unwrap()
        .version;
    assert_eq!(form.get("mailbox").map(String::as_str), Some("INBOX"));
    assert_eq!(form.get("mailbox_guid"), Some(&original.mailbox_guid));
    assert_eq!(form.get("message_guid"), Some(&original.message_guid));
    assert_eq!(
        fixture
            .post("/message/move", &form, "FolderTree")
            .response
            .status_code,
        303
    );
    let rows = fixture
        .app
        .gateway
        .fixture_reconcile_messages(BIN_ALICE, "Deleted", vec![]);
    assert_eq!(rows.len(), 1);
    let uid = rows[0].uid;
    let bin_page = fixture.get(
        &format!("/mailbox?name=Deleted&selected_mailbox=Deleted&selected_uid={uid}"),
        "FolderTree",
    );
    assert_eq!(bin_page.response.status_code, 200);
    let html = body_text(&bin_page);
    assert!(html.contains("class=\"page-shell coordinated-mail archive-page has-selection\""));
    assert!(html.contains("<h1>Archive / Bin</h1>"));
    assert!(html.contains("aria-label=\"Archive and Bin messages\""));
    assert!(html.contains("aria-current=\"page\">Bin</a>"));
    assert!(html.contains("aria-label=\"Restore message to Inbox\""));
    let restore = rendered_bin_move_fields(&html, uid, "restore");
    assert_eq!(restore.get("mailbox").map(String::as_str), Some("Deleted"));
    assert_eq!(restore.get("message_guid"), Some(&original.message_guid));
    assert_eq!(
        fixture
            .post("/message/move", &restore, "FolderTree")
            .response
            .status_code,
        303
    );
    assert!(fixture
        .app
        .gateway
        .fixture_reconcile_messages(BIN_ALICE, "Deleted", vec![])
        .is_empty());
    assert_eq!(
        fixture
            .app
            .gateway
            .fixture_reconcile_messages(BIN_ALICE, "INBOX", vec![])
            .len(),
        1
    );
    fixture.assert_idle();
}

#[test]
fn bin_folder_settings_preserve_missing_saved_choice_and_disable_corrupt_state() {
    let fixture = BinFixture::new();
    fixture.store.save(BIN_ALICE, 0, "Missing").unwrap();
    for section in ["reading", "copies"] {
        let page = fixture.get(&format!("/settings?section={section}"), "FolderTree");
        assert_eq!(page.response.status_code, 200);
        let html = body_text(&page);
        let control = saved_bin_control(&html, section);
        assert!(
            control.contains("<option value=\"Missing\" selected>Missing (unavailable)</option>")
        );
        assert!(control.contains("name=\"expected_revision\" value=\"1\""));
        assert!(!control.contains("<option value=\"Trash\" selected"));
    }
    fs::write(bin_record_path(&fixture), b"corrupt-bin-record").unwrap();
    for (section, id) in [("reading", "reading-bin-folder"), ("copies", "copies-bin")] {
        let page = fixture.get(&format!("/settings?section={section}"), "FolderTree");
        assert_eq!(page.response.status_code, 200);
        let html = body_text(&page);
        assert!(html.contains(&format!(
            "<select id=\"{id}\" disabled><option>Unavailable</option>"
        )));
        assert!(!html.contains("action=\"/settings/bin-folder\""));
        assert!(!html.contains("value=\"Trash\" selected"));
    }
    assert_eq!(
        fs::read(bin_record_path(&fixture)).unwrap(),
        b"corrupt-bin-record"
    );
    fixture.assert_idle();
}

#[test]
fn bin_folder_previous_trash_is_an_ordinary_folder_after_alternate_selection() {
    let fixture = BinFixture::new();
    fixture.store.save(BIN_ALICE, 0, "Deleted").unwrap();
    let page = fixture.get("/mailbox?name=Trash", "FolderTree");
    assert_eq!(page.response.status_code, 200);
    let html = body_text(&page);
    assert!(!html.contains("class=\"page-shell coordinated-mail archive-page"));
    assert!(html.contains("aria-label=\"Mailbox\" title=\"Mailbox\" aria-current=\"page\""), "Old Trash must not be classified as the configured Bin");
    assert!(!html.contains("name=\"action\" value=\"restore\""));
    fixture.assert_idle();
}
