use super::*;
use crate::mailbox::{MessageDeleteError as E, MessageDeleteResult, RetentionDecision as D};

const DELETE_ACCOUNT: &str = "alice@example.com";
struct DeleteRouteFixture {
    root: PathBuf,
    store: crate::bin_folder::BinPreferencesStore,
    app: BrowserApp<StubGateway>,
}
impl DeleteRouteFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "delete-route-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::bin_folder::BinPreferencesStore::new(root.join("settings"));
        store.save(DELETE_ACCOUNT, 0, "Deleted").unwrap();
        let gateway = StubGateway {
            bin_store: Some(store.clone()),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        };
        gateway
            .created_folders
            .lock()
            .unwrap()
            .insert(DELETE_ACCOUNT.into(), vec!["Deleted".into()]);
        *gateway.delete_decision.lock().unwrap() = D::Allowed { revision: 9 };
        *gateway.delete_result.lock().unwrap() = Ok(MessageDeleteResult::Deleted);
        *gateway.delete_list_decision.lock().unwrap() = Some(BrowserMessageListDecision::Listed {
            canonical_username: DELETE_ACCOUNT.into(),
            mailbox_name: "Deleted".into(),
            messages: vec![MessageSummary {
                metadata: gateway.fixture_current_metadata(DELETE_ACCOUNT, "Deleted", 7),
                mailbox_name: "Deleted".into(),
                uid: 7,
                flags: vec![],
                date_received: "2026-10-03 00:00:00 +0000".into(),
                size_virtual: 512,
                subject: Some("Public controlled Bin message <img src=x>".into()),
                from: Some("sender@example.test".into()),
                to: None,
            }],
        });
        let app = BrowserApp::new(
            HttpPolicy {
                mailbox_worker_budget: 1,
                ..HttpPolicy::default()
            },
            gateway,
        );
        Self { root, store, app }
    }
    fn identity(&self) -> BTreeMap<String, String> {
        let version = self
            .app
            .gateway
            .fixture_current_metadata(DELETE_ACCOUNT, "Deleted", 7)
            .unwrap()
            .version;
        BTreeMap::from([
            ("mailbox".into(), "Deleted".into()),
            ("uid".into(), "7".into()),
            ("mailbox_guid".into(), version.mailbox_guid),
            ("message_guid".into(), version.message_guid),
            ("return_to".into(), "/mailbox?name=Deleted".into()),
        ])
    }
    fn form(&self, confirm: &str) -> BTreeMap<String, String> {
        let mut fields = self.identity();
        fields.insert(
            "csrf_token".into(),
            StubGateway::validated_session().record.csrf_token,
        );
        fields.insert("policy_revision".into(), "9".into());
        fields.insert("confirm".into(), confirm.into());
        fields
    }
    fn encoded(fields: &BTreeMap<String, String>) -> String {
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    }
    fn get(&self, fields: &BTreeMap<String, String>, agent: &str) -> HandledHttpResponse {
        let mut req = request(
            "GET",
            &format!("/message/delete?{}", Self::encoded(fields)),
            &authenticated_headers(),
            "",
        );
        req.headers.insert("user-agent".into(), agent.into());
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn post(&self, fields: &BTreeMap<String, String>, agent: &str) -> HandledHttpResponse {
        self.post_raw(&Self::encoded(fields), agent, None, None)
    }
    fn post_raw(
        &self,
        body: &str,
        agent: &str,
        origin: Option<&str>,
        cookie: Option<&str>,
    ) -> HandledHttpResponse {
        let mut req = request(
            "POST",
            "/message/delete",
            &authenticated_same_origin_headers(),
            body,
        );
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        req.headers.insert("user-agent".into(), agent.into());
        if let Some(origin) = origin {
            req.headers.insert("origin".into(), origin.into());
        }
        if let Some(cookie) = cookie {
            req.headers.insert("cookie".into(), cookie.into());
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn assert_zero(&self) {
        assert!(self.app.gateway.delete_calls.lock().unwrap().is_empty());
        self.assert_idle();
    }
    fn assert_idle(&self) {
        assert_eq!(self.app.request_budgets.mailbox_workers.active_count(), 0);
    }
}
impl Drop for DeleteRouteFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn single_delete_get_requires_separate_native_confirmation_and_never_mutates() {
    let fixture = DeleteRouteFixture::new();
    let response = fixture.get(&fixture.identity(), "FolderTree");
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(html.contains("action=\"/message/delete\""));
    assert!(html.contains("method=\"post\""));
    for key in [
        "csrf_token",
        "mailbox",
        "uid",
        "mailbox_guid",
        "message_guid",
        "policy_revision",
        "confirm",
        "return_to",
    ] {
        assert!(
            html.contains(&format!("name=\"{key}\"")),
            "confirmation field {key}"
        );
    }
    assert!(html.contains("value=\"delete\""));
    assert!(html.contains("value=\"cancel\""));
    fixture.assert_zero();
}
#[test]
fn single_delete_cancel_has_no_mutation_even_when_policy_is_unavailable() {
    let fixture = DeleteRouteFixture::new();
    *fixture.app.gateway.delete_decision.lock().unwrap() = D::Unavailable;
    let response = fixture.post(&fixture.form("cancel"), "FolderTree");
    assert_eq!(response.response.status_code, 303);
    assert_eq!(location_header(&response), "/mailbox?name=Deleted");
    fixture.assert_zero();
}
#[test]
fn single_delete_success_dispatches_one_complete_owned_tuple_with_one_budget() {
    let fixture = DeleteRouteFixture::new();
    let response = fixture.post(&fixture.form("delete"), "FolderTree");
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(html.contains("Permanent deletion was confirmed"));
    assert!(!html.contains("action=\"/message/delete\""));
    let calls = fixture.app.gateway.delete_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let target = &calls[0];
    let fields = fixture.identity();
    assert_eq!(target.canonical_username, DELETE_ACCOUNT);
    assert_eq!(target.mailbox_name, "Deleted");
    assert_eq!(target.uid, 7);
    assert_eq!(target.policy_revision, 9);
    assert_eq!(target.version.mailbox_guid, fields["mailbox_guid"]);
    assert_eq!(target.version.message_guid, fields["message_guid"]);
    drop(calls);
    fixture.assert_idle();
}
#[test]
fn single_delete_unknown_is_one_uncertain_dispatch_without_resubmit_form() {
    let fixture = DeleteRouteFixture::new();
    *fixture.app.gateway.delete_result.lock().unwrap() = Err(E::Unknown);
    let response = fixture.post(&fixture.form("delete"), "FolderTree");
    assert_eq!(response.response.status_code, 503);
    let html = body_text(&response);
    assert!(html.contains("may have completed"));
    assert!(!html.contains("action=\"/message/delete\""));
    assert_eq!(fixture.app.gateway.delete_calls.lock().unwrap().len(), 1);
    fixture.assert_idle();
}
#[test]
fn single_delete_missing_duplicate_extra_and_noncanonical_form_fields_never_dispatch() {
    for field in 0..8 {
        let fixture = DeleteRouteFixture::new();
        let mut form = fixture.form("delete");
        match field {
            0 => {
                form.remove("confirm");
            }
            1 => {
                form.insert("confirm".into(), "yes".into());
            }
            2 => {
                form.insert("uid".into(), "07".into());
            }
            3 => {
                form.insert("policy_revision".into(), "09".into());
            }
            4 => {
                form.insert("policy_revision".into(), "0".into());
            }
            5 => {
                form.remove("mailbox_guid");
            }
            6 => {
                form.remove("message_guid");
            }
            _ => {
                form.insert("account".into(), "bob@example.com".into());
            }
        }
        let response = fixture.post(&form, "FolderTree");
        assert_eq!(response.response.status_code, 400, "bad field {field}");
        fixture.assert_zero();
    }
    let fixture = DeleteRouteFixture::new();
    let body = format!(
        "{}&confirm=delete",
        DeleteRouteFixture::encoded(&fixture.form("delete"))
    );
    assert_eq!(
        fixture
            .post_raw(&body, "FolderTree", None, None)
            .response
            .status_code,
        400
    );
    fixture.assert_zero();
}
#[test]
fn single_delete_csrf_origin_and_session_failures_never_dispatch() {
    let fixture = DeleteRouteFixture::new();
    let mut form = fixture.form("delete");
    form.insert("csrf_token".into(), "wrong-public-token".into());
    assert_eq!(fixture.post(&form, "FolderTree").response.status_code, 403);
    fixture.assert_zero();
    let fixture = DeleteRouteFixture::new();
    let body = DeleteRouteFixture::encoded(&fixture.form("delete"));
    assert_eq!(
        fixture
            .post_raw(
                &body,
                "FolderTree",
                Some("https://foreign.example.test"),
                None
            )
            .response
            .status_code,
        403
    );
    fixture.assert_zero();
    let fixture = DeleteRouteFixture::new();
    let response = fixture.post_raw(
        &DeleteRouteFixture::encoded(&fixture.form("delete")),
        "FolderTree",
        None,
        Some("osmap_session=invalid"),
    );
    assert_eq!(response.response.status_code, 303);
    assert_eq!(location_header(&response), "/login");
    fixture.assert_zero();
}
#[test]
fn single_delete_both_stale_guids_and_foreign_owned_tuple_never_dispatch() {
    for field in ["mailbox_guid", "message_guid"] {
        let fixture = DeleteRouteFixture::new();
        let mut form = fixture.form("delete");
        form.insert(
            field.into(),
            if field == "mailbox_guid" {
                "b".repeat(32)
            } else {
                "absent-public-guid".into()
            },
        );
        assert_eq!(fixture.post(&form, "FolderTree").response.status_code, 409);
        fixture.assert_zero();
    }
    let fixture = DeleteRouteFixture::new();
    let foreign = fixture
        .app
        .gateway
        .fixture_current_metadata("bob@example.com", "Deleted", 7)
        .unwrap()
        .version;
    let mut form = fixture.form("delete");
    form.insert("mailbox_guid".into(), foreign.mailbox_guid);
    form.insert("message_guid".into(), foreign.message_guid);
    assert_eq!(fixture.post(&form, "FolderTree").response.status_code, 409);
    fixture.assert_zero();
}
#[test]
fn single_delete_requires_one_current_owned_summary_without_missing_or_ambiguous_fallback() {
    for mode in 0..9 {
        let fixture = DeleteRouteFixture::new();
        {
            let mut snapshot = fixture.app.gateway.delete_list_decision.lock().unwrap();
            if let Some(BrowserMessageListDecision::Listed {
                canonical_username,
                mailbox_name,
                messages,
            }) = snapshot.as_mut()
            {
                match mode {
                    0 => messages[0].metadata = None,
                    1 => messages.clear(),
                    2 => messages.push(messages[0].clone()),
                    3 => *canonical_username = "bob@example.com".into(),
                    4 => *mailbox_name = "Trash".into(),
                    5 => messages[0].mailbox_name = "Trash".into(),
                    6 => {
                        messages[0].metadata.as_mut().unwrap().version.message_guid =
                            "changed-public-guid".into()
                    }
                    7 => {
                        messages[0].metadata.as_mut().unwrap().version.mailbox_guid = "b".repeat(32)
                    }
                    _ => {
                        *snapshot = Some(BrowserMessageListDecision::Denied {
                            public_reason: "temporarily_unavailable".into(),
                        })
                    }
                }
            }
        }
        let response = fixture.post(&fixture.form("delete"), "FolderTree");
        assert_eq!(
            response.response.status_code,
            if mode == 8 { 503 } else { 409 },
            "summary case {mode}"
        );
        fixture.assert_zero();
    }
}
#[test]
fn single_delete_does_not_require_body_rendering_for_current_owned_summary() {
    let fixture = DeleteRouteFixture::new();
    // This existing real Stub reader seam denies every attempted body render.
    // A stable summary plus policy permission must still allow confirmation/delete.
    let response = fixture.get(&fixture.identity(), "FolderTreeReaderUnavailable");
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(html.contains("Public controlled Bin message &lt;img src=x&gt;"));
    assert!(!html.contains("Public controlled Bin message <img"));
    fixture.assert_zero();
    let response = fixture.post(&fixture.form("delete"), "FolderTreeReaderUnavailable");
    assert_eq!(response.response.status_code, 200);
    assert_eq!(fixture.app.gateway.delete_calls.lock().unwrap().len(), 1);
    fixture.assert_idle();
}

#[test]
fn single_delete_requires_current_selectable_private_bin_folder() {
    for agent in [
        "FolderTreeBinNoselect",
        "FolderTreeBinAbsent",
        "FolderTreeWrongOwner",
        "FolderTreeMalformed",
    ] {
        let fixture = DeleteRouteFixture::new();
        let response = fixture.post(&fixture.form("delete"), agent);
        assert_eq!(response.response.status_code, 503, "{agent}");
        fixture.assert_zero();
    }
    let fixture = DeleteRouteFixture::new();
    fixture
        .store
        .save(DELETE_ACCOUNT, 1, "Shared/Team/Review")
        .unwrap();
    fixture
        .app
        .gateway
        .created_folders
        .lock()
        .unwrap()
        .get_mut(DELETE_ACCOUNT)
        .unwrap()
        .push("Shared/Team/Review".into());
    let mut form = fixture.form("delete");
    form.insert("mailbox".into(), "Shared/Team/Review".into());
    let v = fixture
        .app
        .gateway
        .fixture_current_metadata(DELETE_ACCOUNT, "Shared/Team/Review", 7)
        .unwrap()
        .version;
    form.insert("mailbox_guid".into(), v.mailbox_guid);
    form.insert("message_guid".into(), v.message_guid);
    form.insert(
        "return_to".into(),
        "/mailbox?name=Shared%2FTeam%2FReview".into(),
    );
    assert_eq!(fixture.post(&form, "FolderTree").response.status_code, 503);
    fixture.assert_zero();
}
#[test]
fn single_delete_refuses_non_bin_and_changed_bin_preference_before_dispatch() {
    let fixture = DeleteRouteFixture::new();
    let mut form = fixture.form("delete");
    form.insert("mailbox".into(), "INBOX".into());
    assert_eq!(fixture.post(&form, "FolderTree").response.status_code, 400);
    fixture.assert_zero();
    let fixture = DeleteRouteFixture::new();
    assert_eq!(
        fixture
            .get(&fixture.identity(), "FolderTree")
            .response
            .status_code,
        200
    );
    fixture.store.save(DELETE_ACCOUNT, 1, "Trash").unwrap();
    assert_eq!(
        fixture
            .post(&fixture.form("delete"), "FolderTree")
            .response
            .status_code,
        400
    );
    fixture.assert_zero();
}
#[test]
fn single_delete_policy_denied_missing_or_changed_after_confirmation_never_dispatches() {
    for (decision, status) in [
        (D::Denied, 403),
        (D::Unavailable, 503),
        (D::Allowed { revision: 10 }, 409),
    ] {
        let fixture = DeleteRouteFixture::new();
        assert_eq!(
            fixture
                .get(&fixture.identity(), "FolderTree")
                .response
                .status_code,
            200
        );
        *fixture.app.gateway.delete_decision.lock().unwrap() = decision;
        assert_eq!(
            fixture
                .post(&fixture.form("delete"), "FolderTree")
                .response
                .status_code,
            status
        );
        fixture.assert_zero();
    }
}
#[test]
fn single_delete_unsafe_return_and_incomplete_get_contract_never_dispatch() {
    for destination in [
        "https://foreign.example.test/",
        "//foreign.example.test/",
        "/message/delete?confirm=delete",
        "/mailbox?name=Deleted#unsafe",
    ] {
        let fixture = DeleteRouteFixture::new();
        let mut form = fixture.form("delete");
        form.insert("return_to".into(), destination.into());
        assert_eq!(fixture.post(&form, "FolderTree").response.status_code, 400);
        fixture.assert_zero();
    }
    let fixture = DeleteRouteFixture::new();
    let mut fields = fixture.identity();
    fields.remove("message_guid");
    assert_eq!(fixture.get(&fields, "FolderTree").response.status_code, 400);
    fixture.assert_zero();
}
