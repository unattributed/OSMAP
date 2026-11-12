use super::*;
const COPY_ALICE: &str = "alice@example.com";
const COPY_BOB: &str = "bob@example.com";
struct LocationFixture {
    root: PathBuf,
    store: crate::sent_location::Store,
    app: BrowserApp<StubGateway>,
}
impl LocationFixture {
    fn new() -> Self {
        let root = temp_dir(&format!(
            "sent-location-route-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = crate::sent_location::Store::new(root.join("settings"));
        let app = BrowserApp::new(
            HttpPolicy::default(),
            StubGateway {
                sent_location_store: Some(store.clone()),
                browser_fixture_accounts: true,
                ..StubGateway::default()
            },
        );
        Self { root, store, app }
    }
    fn get(&self) -> HandledHttpResponse {
        self.get_path("/settings?section=copies", "FolderTree")
    }
    fn get_path(&self, path: &str, agent: &str) -> HandledHttpResponse {
        let mut req = request("GET", path, &authenticated_headers(), "");
        req.headers.insert("user-agent".into(), agent.into());
        self.app.handle_request(&req, "127.0.0.1")
    }
    fn fields(&self) -> BTreeMap<String, String> {
        let page = self.get();
        assert_eq!(page.response.status_code, 200);
        let html = body_text(&page);
        let form = html
            .split("<form id=\"copies-sent-location-form\"")
            .nth(1)
            .unwrap()
            .split("</form>")
            .next()
            .unwrap();
        assert!(form.contains("method=\"post\" action=\"/settings/sent-location\""));
        let mut result = BTreeMap::new();
        for name in ["csrf_token", "expected_revision"] {
            let value = form
                .split(&format!("name=\"{name}\" value=\""))
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            result.insert(name.into(), value.into());
        }
        assert!(form.contains("<select id=\"copies-sent-location\" name=\"mailbox_name\""));
        result.insert("mailbox_name".into(), "INBOX.Projects".into());
        result
    }
    fn post(&self, fields: &BTreeMap<String, String>, bob: bool) -> HandledHttpResponse {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        self.raw_post(&body, bob)
    }
    fn raw_post(&self, body: &str, bob: bool) -> HandledHttpResponse {
        let mut req = request(
            "POST",
            "/settings/sent-location",
            &authenticated_same_origin_headers(),
            body,
        );
        req.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        if bob {
            req.headers
                .insert("cookie".into(), format!("osmap_session={}", "b".repeat(64)));
        }
        req.headers.insert("user-agent".into(), "FolderTree".into());
        self.app.handle_request(&req, "127.0.0.1")
    }
}
impl Drop for LocationFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn sent_location_generated_picker_persists_exact_own_guid_and_shortcut_after_restart() {
    let f = LocationFixture::new();
    let fields = f.fields();
    let saved = f.post(&fields, false);
    assert_eq!(saved.response.status_code, 303);
    let preference = f.store.load(COPY_ALICE).unwrap();
    assert_eq!(preference.revision, 1);
    assert_eq!(preference.mailbox_name, "INBOX.Projects");
    assert_eq!(
        preference.mailbox_guid.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );
    assert_eq!(
        crate::sent_location::Store::new(f.root.join("settings"))
            .load(COPY_ALICE)
            .unwrap(),
        preference
    );
    assert_eq!(f.post(&fields, false).response.status_code, 409);
    assert_eq!(
        f.store.load(COPY_BOB).unwrap(),
        crate::sent_location::Preference::default()
    );
    assert!(body_text(&f.get())
        .contains("<option value=\"INBOX.Projects\" selected>INBOX.Projects</option>"));
    let shortcut = f.get_path("/mailbox/shortcut?kind=sent", "FolderTree");
    assert_eq!(shortcut.response.status_code, 303);
    assert_eq!(location_header(&shortcut), "/mailbox?name=INBOX.Projects");
}
#[test]
fn sent_location_picker_csrf_foreign_oversize_and_browser_guid_override_never_reset_saved_choice() {
    let f = LocationFixture::new();
    let fields = f.fields();
    assert_eq!(f.post(&fields, false).response.status_code, 303);
    let before = f.store.load(COPY_ALICE).unwrap();
    for (key, value, status) in [
        ("csrf_token", "bad", 403),
        ("expected_revision", "00", 400),
        ("expected_revision", "18446744073709551616", 400),
        ("mailbox_name", "NotOwned", 400),
        ("mailbox_name", "Shared/Team/Review", 400),
        ("mailbox_name", "Public/Old/News", 400),
        ("mailbox_name", "INBOX.Projects\r\n", 400),
        ("account", "bob@example.com", 400),
        ("mailbox_guid", "1234567890abcdef1234567890abcdef", 400),
    ] {
        let mut bad = fields.clone();
        bad.insert("expected_revision".into(), "1".into());
        bad.insert(key.into(), value.into());
        assert_eq!(f.post(&bad, false).response.status_code, status);
        assert_eq!(f.store.load(COPY_ALICE).unwrap(), before);
    }
    let mut oversized = fields.clone();
    oversized.insert("mailbox_name".into(), "x".repeat(256));
    assert_eq!(f.post(&oversized, false).response.status_code, 400);
    let mut missing = fields.clone();
    missing.remove("csrf_token");
    assert_eq!(f.post(&missing, false).response.status_code, 403);
    let mut bob = fields.clone();
    bob.insert("csrf_token".into(), "c".repeat(64));
    bob.insert("mailbox_name".into(), "Sent".into());
    assert_eq!(f.post(&bob, true).response.status_code, 303);
    assert_eq!(f.store.load(COPY_ALICE).unwrap(), before);
    assert_eq!(f.store.load(COPY_BOB).unwrap().mailbox_name, "Sent");
    let unauth = f.app.handle_request(
        &request(
            "POST",
            "/settings/sent-location",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            "expected_revision=0&mailbox_name=Sent",
        ),
        "127.0.0.1",
    );
    assert_eq!(unauth.response.status_code, 303);
    assert_eq!(f.store.load(COPY_ALICE).unwrap(), before);
}
#[test]
fn sent_location_save_and_shortcut_require_whole_owner_snapshot_and_matching_guid() {
    let f = LocationFixture::new();
    let fields = f.fields();
    assert_eq!(f.post(&fields, false).response.status_code, 303);
    let before = f.store.load(COPY_ALICE).unwrap();
    for agent in [
        "FolderTreeWrongOwner",
        "FolderTreeMalformed",
        "FolderTreeStatusWrongOwner",
        "FolderTreeStatusUnavailable",
    ] {
        let response = f.get_path("/mailbox/shortcut?kind=sent", agent);
        assert_eq!(response.response.status_code, 503);
        assert_eq!(f.store.load(COPY_ALICE).unwrap(), before);
    }
    f.store
        .save(
            COPY_ALICE,
            1,
            "INBOX.Projects",
            "abcdef1234567890abcdef1234567890",
        )
        .unwrap();
    let changed = f.get_path("/mailbox/shortcut?kind=sent", "FolderTree");
    assert_eq!(changed.response.status_code, 503);
    assert!(!body_text(&changed).contains("/mailbox?name=Sent"));
}
#[test]
fn sent_location_default_shortcut_and_unrelated_saved_sections_remain_independent() {
    let f = LocationFixture::new();
    let legacy = f.get_path("/mailbox/shortcut?kind=sent", "FolderTree");
    assert_eq!(legacy.response.status_code, 303);
    assert_eq!(location_header(&legacy), "/mailbox?name=Sent");
    let sent_copy = crate::sent_copy::Store::new(f.root.join("settings"));
    sent_copy.save(COPY_ALICE, 0, false).unwrap();
    let bytes_before = std::fs::read_dir(f.root.join("settings"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|v| v.to_str()) == Some("json") {
                Some((path.clone(), std::fs::read(path).unwrap()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(f.post(&f.fields(), false).response.status_code, 303);
    for (path, bytes) in bytes_before {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    assert!(!sent_copy.load(COPY_ALICE).unwrap().save_sent);
}

#[test]
fn sent_location_immediate_known_acceptance_survives_terminal_record_failure_but_later_receipt_is_unknown(
) {
    let f = LocationFixture::new();
    let session = StubGateway::validated_session();
    let account = &session.record.canonical_username;
    let journal = crate::send_journal::SendJournal::new(f.root.join("journal"))
        .with_terminal_write_failure_for_test();
    let intent = crate::send_journal::mint_intent(100).unwrap();
    let chosen = crate::sent_location::CapturedLocation::Selected {
        mailbox_name: "INBOX.CopyA".into(),
        mailbox_guid: "1234567890abcdef1234567890abcdef".into(),
    };
    let result = journal
        .execute_prepared_with_sent_location(
            account,
            &intent,
            100,
            |_| {
                Ok::<_, ()>((
                    crate::send::ComposeRequest::new(
                        crate::send::ComposePolicy::default(),
                        "bob@example.test",
                        "Public fixture",
                        "Public fixture",
                    )
                    .unwrap(),
                    crate::sent_location::SentCopyCapture {
                        requested: true,
                        location: Some(chosen),
                    },
                ))
            },
            |_, _| crate::send_journal::AttemptOutcome::Accepted {
                sent_copy_stored: true,
            },
        )
        .unwrap();
    let crate::send_journal::LocatedPreparedResult::Outcome(recorded) = result else {
        panic!("accepted dispatch must return its known outcome")
    };
    assert!(!recorded.result.receipt_persisted);
    assert_eq!(
        recorded.result.outcome,
        crate::send_journal::AttemptOutcome::Accepted {
            sent_copy_stored: true
        }
    );
    assert_eq!(
        journal
            .receipt_with_sent_location(account, &intent)
            .unwrap()
            .unwrap()
            .result
            .outcome,
        crate::send_journal::AttemptOutcome::Unconfirmed
    );
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            send_journal: journal,
            ..StubGateway::default()
        },
    );
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-location-receipt",
        "127.0.0.1",
        "Fixture",
    )
    .unwrap();
    let immediate = app.send_receipt_decision_response(
        &context,
        &session,
        &intent,
        Ok(Some(BrowserSendDecision::SubmittedTo {
            mailbox_name: "INBOX.CopyA".into(),
            copy_available: true,
            sent_copy_stored: true,
            receipt_persisted: false,
        })),
    );
    let html = std::str::from_utf8(&immediate.body).unwrap();
    assert!(html.contains("Submission acceptance is known."));
    assert!(html.contains("A copy was stored in INBOX.CopyA."));
    assert!(html.contains("Saving the outcome record could not be confirmed."));
    assert!(!html.contains("Submission could not be confirmed"));
    let later = app.send_receipt_response(&context, &session, &intent);
    assert!(std::str::from_utf8(&later.body)
        .unwrap()
        .contains("Submission could not be confirmed"));
    assert!(!std::str::from_utf8(&later.body)
        .unwrap()
        .contains("A copy was stored"));
}

#[test]
fn sent_location_role_borrows_exact_search_or_mailbox_slot_at_limit_one_and_rejects_foreign_guard()
{
    let f = LocationFixture::new();
    f.store
        .save(
            COPY_ALICE,
            0,
            "INBOX.Projects",
            "1234567890abcdef1234567890abcdef",
        )
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy {
            mailbox_worker_budget: 1,
            search_worker_budget: 1,
            ..HttpPolicy::default()
        },
        StubGateway {
            sent_location_store: Some(f.store.clone()),
            ..StubGateway::default()
        },
    );
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "req-location-role",
        "127.0.0.1",
        "FolderTree",
    )
    .unwrap();
    let mailbox = app.request_budgets.mailbox_workers.try_acquire().unwrap();
    let search = app.request_budgets.search_workers.try_acquire().unwrap();
    assert!(app.request_budgets.mailbox_workers.try_acquire().is_none());
    assert!(app.request_budgets.search_workers.try_acquire().is_none());
    for guard in [&mailbox, &search] {
        let mut audit = Vec::new();
        assert!(app
            .confirmed_sent_folder_role(
                &context,
                &session,
                "INBOX.Projects",
                &mut audit,
                Some(guard)
            )
            .is_some());
        assert!(!audit
            .iter()
            .any(|event| event.action == "request_budget_acquired"));
        assert_eq!(app.request_budgets.mailbox_workers.active_count(), 1);
        assert_eq!(app.request_budgets.search_workers.active_count(), 1);
    }
    let foreign_budget = RequestBudget::new("foreign", 1);
    let foreign = foreign_budget.try_acquire().unwrap();
    assert!(app
        .confirmed_sent_folder_role(
            &context,
            &session,
            "INBOX.Projects",
            &mut Vec::new(),
            Some(&foreign)
        )
        .is_none());
    drop(search);
    drop(mailbox);
    assert_eq!(app.request_budgets.search_workers.active_count(), 0);
    assert_eq!(app.request_budgets.mailbox_workers.active_count(), 0);
}
