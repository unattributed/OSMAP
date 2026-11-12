use super::*;
fn selected(app: &BrowserApp<StubGateway>, uid: u64) -> String {
    let m = app
        .gateway
        .fixture_current_metadata("alice@example.com", "INBOX", uid)
        .unwrap();
    format!(
        "message_{uid}={}",
        url_encode(&format!(
            "{uid}|{}|{}",
            m.version.mailbox_guid, m.version.message_guid
        ))
    )
}
#[test]
fn label_selection_native_review_apply_is_bounded_revalidated_atomic_and_readonly_on_failure() {
    let root = temp_dir("label-selection");
    let store = crate::labels::LabelStore::new(root.join("labels"));
    let account = "alice@example.com";
    let initial = store
        .change(account, 0, crate::labels::LabelChange::Create("Review"))
        .unwrap();
    let label = initial.labels()[0].id().to_owned();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            labels_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let csrf = StubGateway::validated_session().record.csrf_token;
    let selection=format!("csrf_token={csrf}&mailbox=INBOX&{}&{}&return_to=%2Fmailbox%3Fname%3DINBOX%26filter%3Dunread",selected(&app,9),selected(&app,10));
    let call = |path: &str, body: &str, agent: &str| {
        let mut req = request("POST", path, &authenticated_same_origin_headers(), body);
        if !agent.is_empty() {
            req.headers.insert("user-agent".into(), agent.into());
        }
        app.handle_request(&req, "127.0.0.1")
    };
    let review = call("/messages/labels/review", &selection, "");
    assert_eq!(review.response.status_code, 200);
    assert_eq!(store.load(account).unwrap(), initial);
    assert_eq!(
        review
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_list")
            .count(),
        1
    );
    let apply = format!("{selection}&revision=1&label_id={label}&action=attach&confirm=apply");
    for (body, agent, status) in [
        (apply.replace(&csrf, "invalid"), "", 403),
        (format!("{apply}&unexpected=1"), "", 400),
        (format!("{apply}&{}", selected(&app, 9)), "", 400),
        (apply.replace("message_9=9", "message_9=0"), "", 400),
        (apply.replace("message_10=10", "message_10=11"), "", 400),
        (apply.clone(), "WelcomeData/wrong-owner", 400),
        (apply.clone(), "WelcomeData/wrong-mailbox", 400),
        (apply.clone(), "OSMAP/LegacyMetadata", 400),
    ] {
        assert_eq!(
            call("/messages/labels/apply", &body, agent)
                .response
                .status_code,
            status,
            "{agent}"
        );
        assert_eq!(store.load(account).unwrap(), initial);
    }
    let changed = apply.replace(
        &url_encode(
            &app.gateway
                .fixture_current_metadata(account, "INBOX", 10)
                .unwrap()
                .version
                .message_guid,
        ),
        "changed-guid",
    );
    assert_eq!(
        call("/messages/labels/apply", &changed, "")
            .response
            .status_code,
        409
    );
    assert_eq!(store.load(account).unwrap(), initial);
    let saved = call("/messages/labels/apply", &apply, "");
    assert_eq!(saved.response.status_code, 200);
    assert_eq!(
        saved
            .audit_events
            .iter()
            .filter(|e| e.action == "stub_message_list")
            .count(),
        1
    );
    let r = store.load(account).unwrap();
    assert_eq!(r.revision(), 2);
    assert_eq!(r.assigned_messages(), 2);
    let stale = call("/messages/labels/apply", &apply, "");
    assert_eq!(stale.response.status_code, 409);
    assert_eq!(store.load(account).unwrap(), r);
    assert!(body_text(&stale).contains(&label));
    let detach = apply
        .replace("revision=1", "revision=2")
        .replace("action=attach", "action=detach");
    assert_eq!(
        call("/messages/labels/apply", &detach, "")
            .response
            .status_code,
        200
    );
    assert_eq!(store.load(account).unwrap().assigned_messages(), 0);
    assert!(store.load("bob@example.com").unwrap().labels().is_empty());
    fs::remove_dir_all(root).unwrap();
}
