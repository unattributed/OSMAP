//! Composite native HTTP/Runtime proof, separate from browser JavaScript execution.
//! Reuses the original bounded signed-helper and private-storage fixture guards.
use super::*;
use std::sync::Barrier;

fn hidden_fields(form: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split_once('>').unwrap().0;
        if attribute(tag, "type").as_deref() != Some("hidden") {
            continue;
        }
        let name = attribute(tag, "name").unwrap();
        assert!(fields
            .insert(name, attribute(tag, "value").unwrap_or_default())
            .is_none());
    }
    fields
}
fn generated_form<'a>(body: &'a str, opening: &str, action: &str) -> &'a str {
    let form = body
        .split_once(opening)
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(
        format!("{opening}{form}").contains("method=\"post\"")
            && form.contains(&format!("action=\"{action}\""))
    );
    form
}
fn enable_automatic_saves(app: &BrowserApp<RuntimeBrowserGateway>, session: &IssuedSession) {
    let page = get(app, session, "/settings?section=composition");
    assert_eq!(page.response.status_code, 200);
    let body = text(&page);
    let form = generated_form(
        body,
        "<form id=\"autosave-settings-form\"",
        "/settings/autosave",
    );
    let mut fields = hidden_fields(form);
    assert_eq!(fields.get("revision").map(String::as_str), Some("0"));
    assert!(
        body.contains("id=\"composition-autosave\"")
            && body.contains("form=\"autosave-settings-form\"")
    );
    assert!(body.contains("id=\"composition-interval\"") && body.contains("value=\"30\""));
    fields.insert("enabled".into(), "1".into());
    fields.insert("interval".into(), "30".into());
    assert_eq!(
        http(app, Some(session), "POST", "/settings/autosave", &fields)
            .response
            .status_code,
        303
    );
    let enabled = get(app, session, "/drafts/autosave/config");
    assert_eq!(enabled.response.status_code, 200);
    let value: serde_json::Value = serde_json::from_slice(&enabled.response.body).unwrap();
    assert_eq!(value["enabled"], true);
    assert_eq!(value["interval"], 30);
}
fn automatic_save(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    fields: &BTreeMap<String, String>,
) -> HandledHttpResponse {
    http(app, Some(session), "POST", "/drafts/autosave", fields)
}
fn confirmed(response: &HandledHttpResponse, id: &str, revision: u64) -> String {
    assert_eq!(response.response.status_code, 200);
    assert!(response
        .response
        .headers
        .iter()
        .any(|(key, value)| key.eq_ignore_ascii_case("cache-control") && value == "no-store"));
    let value: serde_json::Value = serde_json::from_slice(&response.response.body).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["state"], "saved");
    assert!(value["draft_id"].as_str() == Some(id));
    assert_eq!(value["revision"], revision);
    let intent = value["send_intent"].as_str().unwrap().to_owned();
    assert!(!intent.is_empty());
    intent
}
fn resumed(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    id: &str,
) -> HandledHttpResponse {
    let page = get(app, session, &format!("/draft?id={}", encode(id)));
    assert_eq!(page.response.status_code, 200);
    page
}
fn stored_with_attachment(store: &FileDraftStore, id: &str, revision: u64, expected_body: &str) {
    let record = store
        .load(ALICE, id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(record.revision, Some(revision));
    assert!(record.request.body == expected_body);
    assert_eq!(record.request.attachments.len(), 1);
    assert!(record.request.attachments[0].body == PUBLIC_ATTACHMENT);
}

fn run_interactions() {
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-dai-{}-{}",
        std::process::id(),
        crate::draft::generate_draft_id().unwrap()
    ));
    // OpenBSD's sockaddr_un is smaller than Linux's. Keep the actual helper
    // pathname within the native limit before starting the owned fixture.
    assert!(root.join("owned-unavailable-mail.sock").as_os_str().len() < 100);
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture {
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        threads: vec![],
    };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("app-state"))
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = unavailable_helper(
        &mut fixture,
        UnavailableMail {
            reads: reads.clone(),
            forbidden: forbidden.clone(),
        },
    );
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let sendmail = root.join("owned-denied-sendmail");
    let marker = root.join("forbidden-send-invoked");
    let interpreter = if std::env::consts::OS == "openbsd" {
        "/usr/local/bin/python3"
    } else {
        "/usr/bin/python3"
    };
    // Fixed script only records forbidden invocation in this owned fixture.
    let script = format!("#!{interpreter}\nimport os\nimport sys\nfrom pathlib import Path\np = Path(sys.argv[0]).with_name('forbidden-send-invoked')\nf = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)\nos.close(f)\nraise SystemExit(71)\n");
    fs::write(&sendmail, script).unwrap();
    fs::set_permissions(&sendmail, fs::Permissions::from_mode(0o700)).unwrap();
    let config = AppConfig::from_env_map(&BTreeMap::from([
        ("OSMAP_RUN_MODE".into(), "serve".into()),
        (
            "OSMAP_STATE_DIR".into(),
            root.join("app-state").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_SOCKET_PATH".into(),
            helper.to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH".into(),
            key.to_string_lossy().into_owned(),
        ),
        ("OSMAP_MAILBOX_HELPER_PEER_UID".into(), uid.to_string()),
        ("OSMAP_MAILBOX_WORKER_BUDGET".into(), "1".into()),
    ]))
    .unwrap();
    assert!(
        config.openpgp_crypto.is_none()
            && config.openpgp_inventory.is_none()
            && config.openpgp_public_admin.is_none()
    );
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "draft-autosave-interactions",
        "127.0.0.1",
        "OSMAP/native-reader",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(&config.state_layout.session_dir),
        SystemTimeProvider,
        SystemRandomSource,
        180,
        180,
    );
    let alice = sessions
        .issue(&context, ALICE, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::from_config(&config),
        RuntimeBrowserGateway::from_config(&config).with_fixture_sendmail_path(sendmail),
    );
    let ordinary = FileDraftStore::new(&config.state_layout.draft_dir, DraftPolicy::default());
    let working = ordinary.clone().with_new_location(Location::Working);
    let default_neighbour = seed(
        &ordinary,
        ALICE,
        "Untouched Default neighbour",
        SystemTimeProvider.unix_timestamp(),
    );
    let default_path = ordinary
        .resolved_draft_dir(ALICE, &default_neighbour)
        .unwrap()
        .unwrap();
    let default_bytes = tree_bytes(&default_path);
    working.qualify_location(BOB, Location::Working).unwrap();
    let bob_id = seed(
        &working,
        BOB,
        "Untouched Bob neighbour",
        SystemTimeProvider.unix_timestamp(),
    );
    let bob_path = working.resolved_draft_dir(BOB, &bob_id).unwrap().unwrap();
    let bob_bytes = tree_bytes(&bob_path);
    enable_automatic_saves(&app, &alice);
    choose(&app, &alice, Location::Working, 0);
    let fields = fresh(&app, &alice, "Automatic Working public fixture");
    let id = saved_id(&compose_post(
        &app,
        Some(&alice),
        "/drafts/save",
        &fields,
        true,
    ));
    let working_path = working.resolved_draft_dir(ALICE, &id).unwrap().unwrap();
    assert!(working_path.starts_with(config.state_layout.draft_dir.join(".locations/working")));
    assert!(!ordinary.draft_dir_for_username_and_id(ALICE, &id).exists());
    stored_with_attachment(&ordinary, &id, 1, PUBLIC_BODY);
    let page = resumed(&app, &alice, &id);
    let mut discard = hidden_fields(generated_form(
        text(&page),
        "<form id=\"compose-discard-form\"",
        "/drafts/discard",
    ));
    let selected = format!("selected_{id}");
    assert_eq!(discard.get(&selected).map(String::as_str), Some("1"));
    assert!(!discard.contains_key("send_intent"));
    // Match the finite native autosave request constructed by compose_local.js.
    // New uploads/formatting controls stay outside automatic-save admission.
    let allowed = [
        "csrf_token",
        "send_intent",
        "from",
        "to",
        "cc",
        "bcc",
        "subject",
        "body",
        "body_format",
        "pgp_sign",
        "pgp_encrypt",
        "pgp_self",
        "pgp_binding_revision",
        "draft_id",
        "draft_revision",
        "reply_mailbox",
        "reply_uid",
        "reply_mailbox_guid",
        "reply_message_guid",
    ];
    let mut automatic: BTreeMap<_, _> = compose_fields(text(&page))
        .into_iter()
        .filter(|(key, _)| allowed.contains(&key.as_str()))
        .collect();
    automatic.insert("body".into(), "Working automatic first publication".into());
    let first = automatic_save(&app, &alice, &automatic);
    let first_intent = confirmed(&first, &id, 2);
    stored_with_attachment(&ordinary, &id, 2, "Working automatic first publication");
    choose(&app, &alice, Location::Default, 1);
    automatic.insert("draft_revision".into(), "2".into());
    automatic.insert("send_intent".into(), first_intent);
    automatic.insert(
        "body".into(),
        "Original Working after Default switch".into(),
    );
    let second = automatic_save(&app, &alice, &automatic);
    let second_intent = confirmed(&second, &id, 3);
    stored_with_attachment(&ordinary, &id, 3, "Original Working after Default switch");
    assert!(ordinary.resolved_draft_dir(ALICE, &id).unwrap().unwrap() == working_path);
    assert!(!ordinary.draft_dir_for_username_and_id(ALICE, &id).exists());
    // Both competing requests use the same actual confirmed revision/intent.
    automatic.insert("draft_revision".into(), "3".into());
    automatic.insert("send_intent".into(), second_intent);
    let barrier = Arc::new(Barrier::new(3));
    let outcomes = thread::scope(|scope| {
        let mut handles = vec![];
        for body in ["Concurrent public author A", "Concurrent public author B"] {
            let mut competing = automatic.clone();
            competing.insert("body".into(), body.into());
            let barrier = barrier.clone();
            let app = &app;
            let alice = &alice;
            handles.push(scope.spawn(move || {
                barrier.wait();
                (body, automatic_save(app, alice, &competing))
            }));
        }
        barrier.wait();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, r)| r.response.status_code == 200)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, r)| r.response.status_code == 409)
            .count(),
        1
    );
    let (winning_body, winning_response) = outcomes
        .iter()
        .find(|(_, r)| r.response.status_code == 200)
        .unwrap();
    let winning_intent = confirmed(winning_response, &id, 4);
    stored_with_attachment(&ordinary, &id, 4, winning_body);
    let latest_bytes = tree_bytes(&working_path);
    let conflicting = &outcomes
        .iter()
        .find(|(_, r)| r.response.status_code == 409)
        .unwrap()
        .1;
    let conflict: serde_json::Value = serde_json::from_slice(&conflicting.response.body).unwrap();
    assert_eq!(conflict["state"], "paused");
    // Old discard form cannot delete the newer saved content.
    discard.insert("stage".into(), "review".into());
    assert_eq!(
        http(&app, Some(&alice), "POST", "/drafts/discard", &discard)
            .response
            .status_code,
        409
    );
    assert!(tree_bytes(&working_path) == latest_bytes);
    automatic.insert("draft_revision".into(), "4".into());
    automatic.insert("send_intent".into(), winning_intent);
    automatic.insert(
        "body".into(),
        "Unsaved public missing-root authoring".into(),
    );
    let working_root = config.state_layout.draft_dir.join(".locations/working");
    let parked = root.join("parked-owned-working");
    fs::rename(&working_root, &parked).unwrap();
    let parked_bytes = tree_bytes(&parked);
    let missing = automatic_save(&app, &alice, &automatic);
    assert_eq!(missing.response.status_code, 409);
    let missing_state: serde_json::Value = serde_json::from_slice(&missing.response.body).unwrap();
    assert_eq!(missing_state["version"], 1);
    assert_eq!(missing_state["state"], "paused");
    assert!(!working_root.exists());
    assert!(!ordinary.draft_dir_for_username_and_id(ALICE, &id).exists());
    assert!(tree_bytes(&parked) == parked_bytes && tree_bytes(&default_path) == default_bytes);
    fs::rename(&parked, &working_root).unwrap();
    assert!(tree_bytes(&working_path) == latest_bytes);
    // Apply only the revision confirmed by autosave, exactly as the client does.
    // This is native form semantics, not execution of compose_local.js.
    discard.insert(selected, "4".into());
    let review = http(&app, Some(&alice), "POST", "/drafts/discard", &discard);
    assert_eq!(review.response.status_code, 200);
    assert!(text(&review).contains("Discard selected drafts?"));
    let mut confirm = hidden_fields(generated_form(
        text(&review),
        "<form method=\"post\"",
        "/drafts/discard",
    ));
    assert!(confirm.get(&format!("selected_{id}")).map(String::as_str) == Some("4"));
    assert_eq!(
        confirm
            .keys()
            .filter(|key| key.starts_with("selected_"))
            .count(),
        1
    );
    confirm.insert("stage".into(), "confirm".into());
    assert_eq!(
        http(&app, Some(&alice), "POST", "/drafts/discard", &confirm)
            .response
            .status_code,
        303
    );
    assert!(ordinary
        .load(ALICE, &id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    assert!(!working_path.exists());
    assert!(tree_bytes(&default_path) == default_bytes && tree_bytes(&bob_path) == bob_bytes);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    assert!(!marker.exists());
    assert!(reads.load(Ordering::SeqCst) > 0);
    sessions.revoke_by_token(&context, &alice.token).unwrap();
    sessions.revoke_by_token(&context, &bob.token).unwrap();
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert!(standard_metadata() == before);
    for marker in [
        "draft_autosave_generated_preferences_and_working_attachment",
        "draft_autosave_current_default_does_not_retarget_existing_id",
        "draft_autosave_concurrent_one_saved_one_conflict_exact_latest_bytes",
        "draft_autosave_stale_discard_refused_current_confirmed_revision_exact_id",
        "draft_autosave_missing_registered_working_no_create_no_fallback",
        "draft_autosave_foreign_and_default_neighbours_unchanged",
        "draft_autosave_no_smtp_mail_mutation_or_private_crypto",
        "draft_autosave_owned_cleanup_and_standard_metadata_unchanged",
    ] {
        println!("{marker}=PASS");
    }
}
#[test]
fn generated_runtime_automatic_working_interactions_and_concurrency() {
    run_interactions();
}

#[test]
#[ignore = "explicit OpenBSD automatic draft save/location interactions; no SMTP or mailbox mutation"]
fn isolated_openbsd_generated_automatic_working_location_concurrency_and_discard() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    run_interactions();
}
