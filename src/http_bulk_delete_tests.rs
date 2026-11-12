use super::*;
use crate::mailbox::{MessageDeleteError as E, MessageDeleteResult, RetentionDecision as D};
const BULK_ACCOUNT: &str = "alice@example.com";
struct BulkDeleteFixture {
    root: PathBuf,
    app: BrowserApp<StubGateway>,
}
impl BulkDeleteFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "bulk-delete-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::bin_folder::BinPreferencesStore::new(root.join("settings"));
        store.save(BULK_ACCOUNT, 0, "Deleted").unwrap();
        let gateway = StubGateway {
            bin_store: Some(store),
            browser_fixture_accounts: true,
            ..StubGateway::default()
        };
        gateway
            .created_folders
            .lock()
            .unwrap()
            .insert(BULK_ACCOUNT.into(), vec!["Deleted".into()]);
        *gateway.delete_decision.lock().unwrap() = D::Allowed { revision: 9 };
        *gateway.delete_result.lock().unwrap() = Ok(MessageDeleteResult::Deleted);
        *gateway.delete_list_decision.lock().unwrap() = Some(BrowserMessageListDecision::Listed {
            canonical_username: BULK_ACCOUNT.into(),
            mailbox_name: "Deleted".into(),
            messages: (1..=11)
                .map(|uid| MessageSummary {
                    metadata: gateway.fixture_current_metadata(BULK_ACCOUNT, "Deleted", uid),
                    mailbox_name: "Deleted".into(),
                    uid,
                    flags: vec![],
                    date_received: "2026-10-03 00:00:00 +0000".into(),
                    size_virtual: 512,
                    subject: Some(format!("Public {uid} <img src=x>")),
                    from: Some("sender@example.test".into()),
                    to: None,
                })
                .collect(),
        });
        Self {
            root,
            app: BrowserApp::new(
                HttpPolicy {
                    mailbox_worker_budget: 1,
                    ..HttpPolicy::default()
                },
                gateway,
            ),
        }
    }
    fn form(&self, count: usize, review: bool) -> BTreeMap<String, String> {
        let mut form = BTreeMap::from([
            (
                "csrf_token".into(),
                StubGateway::validated_session().record.csrf_token,
            ),
            ("mailbox".into(), "Deleted".into()),
            ("return_to".into(), "/mailbox?name=Deleted".into()),
        ]);
        if review {
            form.insert("action".into(), "review-delete".into());
            form.insert("destination_mailbox".into(), "INBOX".into());
        } else {
            form.insert("policy_revision".into(), "9".into());
            form.insert("confirm".into(), "delete".into());
        }
        for uid in 1..=count {
            let version = self
                .app
                .gateway
                .fixture_current_metadata(BULK_ACCOUNT, "Deleted", uid as u64)
                .unwrap()
                .version;
            form.insert(
                format!("message_{uid}"),
                format!("{uid}|{}|{}", version.mailbox_guid, version.message_guid),
            );
        }
        form
    }
    fn encode(fields: &BTreeMap<String, String>) -> String {
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    }
    fn post(&self, fields: &BTreeMap<String, String>, review: bool) -> HandledHttpResponse {
        self.raw(&Self::encode(fields), review, None, None)
    }
    fn raw(
        &self,
        body: &str,
        review: bool,
        origin: Option<&str>,
        cookie: Option<&str>,
    ) -> HandledHttpResponse {
        let path = if review {
            "/messages/delete/review"
        } else {
            "/messages/delete"
        };
        let mut req = request("POST", path, &authenticated_same_origin_headers(), body);
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        req.headers
            .insert("user-agent".into(), "FolderTreeReaderUnavailable".into());
        if let Some(origin) = origin {
            req.headers.insert("origin".into(), origin.into());
        }
        if let Some(cookie) = cookie {
            req.headers.insert("cookie".into(), cookie.into());
        }
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn queue(&self, results: impl IntoIterator<Item = Result<MessageDeleteResult, E>>) {
        self.app
            .gateway
            .delete_results
            .lock()
            .unwrap()
            .extend(results);
    }
    fn calls(&self) -> Vec<u64> {
        self.app
            .gateway
            .delete_calls
            .lock()
            .unwrap()
            .iter()
            .map(|target| target.uid)
            .collect()
    }
    fn idle(&self) {
        assert_eq!(self.app.request_budgets.mailbox_workers.active_count(), 0);
    }
    fn zero(&self) {
        assert!(self.calls().is_empty());
        self.idle();
    }
}
impl Drop for BulkDeleteFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl BulkDeleteFixture {
    fn empty(&self, form: &BTreeMap<String, String>, review: bool) -> HandledHttpResponse {
        let mut req = request("POST", if review { "/trash/empty/review" } else { "/trash/empty" }, &authenticated_same_origin_headers(), &Self::encode(form));
        req.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
        req.headers.insert("user-agent".into(), "FolderTreeReaderUnavailable".into());
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn empty_review_form(&self) -> BTreeMap<String, String> {
        self.form(0, true).into_iter().filter(|(k, _)| !["action", "destination_mailbox"].contains(&k.as_str())).collect()
    }
    fn empty_confirm_form(&self) -> BTreeMap<String, String> {
        let response = self.empty(&self.empty_review_form(), true);
        assert_eq!(response.response.status_code, 200);
        let html = body_text(&response);
        let snapshot = html.split("name=\"snapshot\" value=\"").nth(1).unwrap().split('"').next().unwrap();
        let mut form = self.empty_review_form();
        form.insert("snapshot".into(), snapshot.into());
        form.insert("policy_revision".into(), "9".into());
        form.insert("confirm".into(), "delete".into());
        form
    }
}

#[test]
fn empty_trash_reviews_all_pages_then_deletes_exact_snapshot() {
    let fixture = BulkDeleteFixture::new();
    if let Some(BrowserMessageListDecision::Listed { messages, .. }) = fixture.app.gateway.delete_list_decision.lock().unwrap().as_mut() {
        let first = messages[0].clone();
        *messages = (1..=75).map(|uid| { let mut m = first.clone(); m.uid = uid; m.metadata = fixture.app.gateway.fixture_current_metadata(BULK_ACCOUNT, "Deleted", uid); m }).collect();
    }
    let review = fixture.empty(&fixture.empty_review_form(), true);
    assert!(body_text(&review).contains("all 75 messages"));
    fixture.zero();
    let form = fixture.empty_confirm_form();
    let response = fixture.empty(&form, false);
    assert_eq!(response.response.status_code, 200);
    assert_eq!(fixture.calls(), (1..=75).collect::<Vec<_>>());
    fixture.idle();
}

#[test]
fn empty_trash_changed_snapshot_and_cancel_are_zero_dispatch() {
    let fixture = BulkDeleteFixture::new();
    let mut form = fixture.empty_confirm_form();
    form.insert("confirm".into(), "cancel".into());
    assert_eq!(fixture.empty(&form, false).response.status_code, 303);
    fixture.zero();
    form.insert("confirm".into(), "delete".into());
    if let Some(BrowserMessageListDecision::Listed { messages, .. }) = fixture.app.gateway.delete_list_decision.lock().unwrap().as_mut() {
        messages.pop();
    }
    assert_eq!(fixture.empty(&form, false).response.status_code, 409);
    fixture.zero();
}

#[test]
fn empty_trash_new_arrival_or_recreated_folder_requires_fresh_review() {
    for arrival in [true, false] {
        let fixture = BulkDeleteFixture::new();
        let form = fixture.empty_confirm_form();
        if let Some(BrowserMessageListDecision::Listed { messages, .. }) = fixture.app.gateway.delete_list_decision.lock().unwrap().as_mut() {
            if arrival {
                let mut message = messages[0].clone();
                message.uid = 99;
                message.metadata = fixture.app.gateway.fixture_current_metadata(BULK_ACCOUNT, "Deleted", 99);
                messages.push(message);
            } else {
                for message in messages { message.metadata.as_mut().unwrap().version.mailbox_guid = "c".repeat(32); }
            }
        }
        assert_eq!(fixture.empty(&form, false).response.status_code, 409);
        fixture.zero();
    }
}

#[test]
fn empty_trash_refuses_bad_authority_identity_and_snapshot_before_mutation() {
    for fault in 0..8 {
        let fixture = BulkDeleteFixture::new();
        let mut form = fixture.empty_confirm_form();
        match fault {
            0 => { form.insert("csrf_token".into(), "wrong".into()); }
            1 => { form.insert("mailbox".into(), "INBOX".into()); }
            2 => { form.insert("snapshot".into(), "0".repeat(64)); }
            3 => { form.insert("policy_revision".into(), "8".into()); }
            4 => { *fixture.app.gateway.delete_decision.lock().unwrap() = D::Denied; }
            5 => { form.insert("message_1".into(), "forged".into()); }
            _ => {
                if let Some(BrowserMessageListDecision::Listed { messages, .. }) = fixture.app.gateway.delete_list_decision.lock().unwrap().as_mut() {
                    if fault == 6 { messages[0].metadata = None; } else { messages.push(messages[0].clone()); }
                }
            }
        }
        assert_ne!(fixture.empty(&form, false).response.status_code, 200, "fault {fault}");
        fixture.zero();
    }
}

#[test]
fn empty_trash_empty_oversize_foreign_origin_get_and_partial_unknown() {
    let fixture = BulkDeleteFixture::new();
    let form = fixture.empty_confirm_form();
    fixture.queue([Ok(MessageDeleteResult::Deleted), Err(E::Unknown)]);
    let response = fixture.empty(&form, false);
    assert_eq!(fixture.calls(), vec![1, 2]);
    assert!(body_text(&response).contains("1 confirmed deleted; 0 refused; 1 unconfirmed; 9 not attempted"));
    fixture.idle();
    for count in [0, 2001] {
        let fixture = BulkDeleteFixture::new();
        if let Some(BrowserMessageListDecision::Listed { messages, .. }) = fixture.app.gateway.delete_list_decision.lock().unwrap().as_mut() {
            messages.resize(count, messages[0].clone());
        }
        assert_eq!(fixture.empty(&fixture.empty_review_form(), true).response.status_code, if count == 0 { 200 } else { 503 });
        fixture.zero();
    }
    for method in ["GET", "POST"] {
        let fixture = BulkDeleteFixture::new();
        let encoded = BulkDeleteFixture::encode(&fixture.empty_review_form());
        let mut req = request(method, "/trash/empty", &authenticated_same_origin_headers(), if method == "GET" { "" } else { &encoded });
        req.headers.insert("origin".into(), "https://foreign.example.test".into());
        req.headers.insert("content-type".into(), "application/x-www-form-urlencoded".into());
        assert_ne!(fixture.app.handle_request(&req, "127.0.0.1").response.status_code, 200);
        fixture.zero();
    }
}

#[test]
fn bulk_delete_review_and_cancel_are_zero_mutation_native_forms() {
    let fixture = BulkDeleteFixture::new();
    let response = fixture.post(&fixture.form(3, true), true);
    assert_eq!(response.response.status_code, 200);
    let html = body_text(&response);
    assert!(html.contains("action=\"/messages/delete\""));
    assert!(html.contains("value=\"delete\""));
    assert!(html.contains("value=\"cancel\""));
    assert!(html.contains("Public 1 &lt;img src=x&gt;"));
    assert!(!html.contains("Public 1 <img"));
    for uid in 1..=3 {
        assert!(html.contains(&format!("name=\"message_{uid}\"")));
    }
    fixture.zero();
    *fixture.app.gateway.delete_decision.lock().unwrap() = D::Unavailable;
    let mut form = fixture.form(3, false);
    form.insert("confirm".into(), "cancel".into());
    let response = fixture.post(&form, false);
    assert_eq!(response.response.status_code, 303);
    assert_eq!(location_header(&response), "/mailbox?name=Deleted");
    fixture.zero();
}
#[test]
fn bulk_delete_get_endpoints_never_dispatch_even_with_valid_mutation_body() {
    let fixture = BulkDeleteFixture::new();
    for (path, review) in [
        ("/messages/delete/review", true),
        ("/messages/delete", false),
    ] {
        let encoded = BulkDeleteFixture::encode(&fixture.form(3, review));
        let raw = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{encoded}", encoded.len());
        assert!(parse_http_request_bytes(raw.as_bytes(), &HttpPolicy::default()).is_err());
        let mut req = request(
            "POST",
            path,
            &authenticated_headers(),
            &encoded,
        );
        // Also exercise the route dispatcher independently of parser refusal.
        req.method = HttpMethod::Get;
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        let response = fixture.app.handle_request(&req, "127.0.0.1");
        assert!(response.response.status_code >= 400);
        fixture.zero();
    }
}
#[test]
fn bulk_delete_ten_is_allowed_eleven_and_empty_are_refused_without_dispatch() {
    let fixture = BulkDeleteFixture::new();
    let response = fixture.post(&fixture.form(10, true), true);
    assert_eq!(response.response.status_code, 200);
    fixture.zero();
    let response = fixture.post(&fixture.form(10, false), false);
    assert_eq!(response.response.status_code, 200);
    assert_eq!(fixture.calls(), (1..=10).collect::<Vec<_>>());
    assert!(body_text(&response)
        .contains("10 confirmed deleted; 0 refused; 0 unconfirmed; 0 not attempted"));
    fixture.idle();
    for count in [0, 11] {
        for review in [true, false] {
            let fixture = BulkDeleteFixture::new();
            assert_eq!(
                fixture
                    .post(&fixture.form(count, review), review)
                    .response
                    .status_code,
                400
            );
            fixture.zero();
        }
    }
}
#[test]
fn bulk_delete_stops_on_second_refusal_without_attempting_third_or_repeating_first() {
    for (error, status, label) in [
        (E::Stale, 409, "identity or permission changed"),
        (E::PolicyDenied, 403, "retention policy"),
        (E::PolicyUnavailable, 503, "retention unavailable"),
        (E::Busy, 429, "mail action busy"),
        (E::Unavailable, 503, "helper unavailable before dispatch"),
    ] {
        let fixture = BulkDeleteFixture::new();
        fixture.queue([
            Ok(MessageDeleteResult::Deleted),
            Err(error),
            Ok(MessageDeleteResult::Deleted),
        ]);
        let response = fixture.post(&fixture.form(3, false), false);
        assert_eq!(response.response.status_code, status);
        assert_eq!(fixture.calls(), vec![1, 2]);
        assert_eq!(fixture.app.gateway.delete_results.lock().unwrap().len(), 1);
        let html = body_text(&response);
        assert!(html.contains("1 confirmed deleted; 1 refused; 0 unconfirmed; 1 not attempted"));
        assert!(html.contains(&format!("Message #2: Refused: {label}")));
        assert!(html.contains("Message #3: Not attempted"));
        assert!(!html.contains("action=\"/messages/delete\""));
        fixture.idle();
    }
}
#[test]
fn bulk_delete_second_unknown_is_reported_once_with_third_not_attempted() {
    let fixture = BulkDeleteFixture::new();
    fixture.queue([
        Ok(MessageDeleteResult::Deleted),
        Err(E::Unknown),
        Ok(MessageDeleteResult::Deleted),
    ]);
    let response = fixture.post(&fixture.form(3, false), false);
    assert_eq!(response.response.status_code, 503);
    assert_eq!(fixture.calls(), vec![1, 2]);
    assert_eq!(fixture.app.gateway.delete_results.lock().unwrap().len(), 1);
    let html = body_text(&response);
    assert!(html.contains("1 confirmed deleted; 0 refused; 1 unconfirmed; 1 not attempted"));
    assert!(html.contains("Message #2: Unconfirmed: may have completed"));
    assert!(html.contains("Message #3: Not attempted"));
    assert!(!html.contains("action=\"/messages/delete\""));
    fixture.idle();
}
#[test]
fn bulk_delete_validates_later_tuple_and_entire_current_selection_before_first_dispatch() {
    for mode in 0..7 {
        let fixture = BulkDeleteFixture::new();
        let mut form = fixture.form(3, false);
        match mode {
            0 => {
                form.insert(
                    "message_3".into(),
                    "3|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb|changed-public-guid".into(),
                );
            }
            1 => {
                form.insert("message_3".into(), form["message_1"].clone());
            }
            2 => {
                let value = form.remove("message_3").unwrap();
                form.insert("message_03".into(), value);
            }
            _ => {
                let mut snapshot = fixture.app.gateway.delete_list_decision.lock().unwrap();
                if let Some(BrowserMessageListDecision::Listed {
                    canonical_username,
                    mailbox_name,
                    messages,
                }) = snapshot.as_mut()
                {
                    match mode {
                        3 => messages.push(messages[2].clone()),
                        4 => messages[2].metadata = None,
                        5 => *canonical_username = "bob@example.com".into(),
                        _ => *mailbox_name = "Trash".into(),
                    }
                }
            }
        }
        let response = fixture.post(&form, false);
        assert_eq!(
            response.response.status_code,
            if mode == 1 || mode == 2 || mode == 5 || mode == 6 {
                400
            } else {
                409
            },
            "whole-selection case {mode}"
        );
        fixture.zero();
    }
}
#[test]
fn bulk_delete_duplicate_native_selection_field_is_refused_without_dispatch() {
    let fixture = BulkDeleteFixture::new();
    let form = fixture.form(3, false);
    let body = format!(
        "{}&message_2={}",
        BulkDeleteFixture::encode(&form),
        url_encode(&form["message_2"])
    );
    assert_eq!(
        fixture.raw(&body, false, None, None).response.status_code,
        400
    );
    fixture.zero();
}
#[test]
fn bulk_delete_policy_change_denial_and_missing_authority_before_dispatch() {
    for (decision, status) in [
        (D::Allowed { revision: 10 }, 409),
        (D::Denied, 403),
        (D::Unavailable, 503),
    ] {
        let fixture = BulkDeleteFixture::new();
        assert_eq!(
            fixture
                .post(&fixture.form(3, true), true)
                .response
                .status_code,
            200
        );
        *fixture.app.gateway.delete_decision.lock().unwrap() = decision;
        assert_eq!(
            fixture
                .post(&fixture.form(3, false), false)
                .response
                .status_code,
            status
        );
        fixture.zero();
    }
}
#[test]
fn bulk_delete_csrf_foreign_origin_auth_and_unsafe_return_are_zero_dispatch() {
    let fixture = BulkDeleteFixture::new();
    let mut form = fixture.form(3, false);
    form.insert("csrf_token".into(), "wrong-public-token".into());
    assert_eq!(fixture.post(&form, false).response.status_code, 403);
    fixture.zero();
    let fixture = BulkDeleteFixture::new();
    assert_eq!(
        fixture
            .raw(
                &BulkDeleteFixture::encode(&fixture.form(3, false)),
                false,
                Some("https://foreign.example.test"),
                None
            )
            .response
            .status_code,
        403
    );
    fixture.zero();
    let fixture = BulkDeleteFixture::new();
    let response = fixture.raw(
        &BulkDeleteFixture::encode(&fixture.form(3, false)),
        false,
        None,
        Some("osmap_session=invalid"),
    );
    assert_eq!(response.response.status_code, 303);
    assert_eq!(location_header(&response), "/login");
    fixture.zero();
    let fixture = BulkDeleteFixture::new();
    let mut form = fixture.form(3, false);
    form.insert("return_to".into(), "https://foreign.example.test".into());
    assert_eq!(fixture.post(&form, false).response.status_code, 400);
    fixture.zero();
}
#[test]
fn bulk_delete_requires_explicit_confirmation_and_rejects_extra_authority_fields() {
    for mode in 0..5 {
        let fixture = BulkDeleteFixture::new();
        let mut form = fixture.form(3, false);
        match mode {
            0 => {
                form.remove("confirm");
            }
            1 => {
                form.insert("confirm".into(), "yes".into());
            }
            2 => {
                form.insert("policy_revision".into(), "09".into());
            }
            3 => {
                form.insert("account".into(), "bob@example.com".into());
            }
            _ => {
                form.insert("destination_mailbox".into(), "Deleted".into());
            }
        }
        assert_eq!(fixture.post(&form, false).response.status_code, 400);
        fixture.zero();
    }
}
