//! Actual disposable Runtime -> authenticated helper -> Dovecot All search.
//! Existing reader/move/delete fixture guards remain unchanged.
use super::*;

fn all_search_row_link(body: &str, mailbox: &str, uid: u64) -> String {
    body.split("<a ")
        .find_map(|anchor| {
            let tag = anchor.split_once('>')?.0;
            if !tag.contains("class=\"message-subject-link\"") {
                return None;
            }
            let href = attribute(tag, "href")?;
            let (_, query) = href.split_once('?')?;
            let fields = crate::http_form::parse_urlencoded_form(
                query.as_bytes(),
                crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
                2048,
            )
            .ok()?;
            (fields.get("mailbox").map(String::as_str) == Some(mailbox)
                && fields.get("uid") == Some(&uid.to_string()))
            .then_some(href)
        })
        .expect("actual selected row GUID-bound opening link")
}

#[test]
#[ignore = "explicit OpenBSD All search proof; disposable Dovecot/helper/contact-store only"]
fn isolated_openbsd_all_search_browser_owned_categories() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let started = Instant::now();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-all-search-native-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture {
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        threads: vec![],
    };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    let group = SystemCommandExecutor
        .run_with_stdin_timeout("/usr/bin/id", &["-g".into()], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(group.status_code, 0);
    let gid = group.stdout.trim().parse::<u32>().unwrap();
    assert_ne!(gid, 0);
    for directory in ["run", "state", "app-state"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(directory))
            .unwrap();
    }
    for user in ["alice", "bob"] {
        for folder in ["", ".Sent"] {
            for part in ["cur", "new", "tmp"] {
                fs::create_dir_all(root.join(user).join("Maildir").join(folder).join(part))
                    .unwrap();
            }
        }
    }
    for index in 0..4 {
        write_message(&root, "alice", index, if index == 1 { 3 } else { 0 });
        let path = root.join(format!("alice/Maildir/new/synthetic-{index:03}"));
        let mut wire = fs::read_to_string(&path)
            .unwrap()
            .replace("Subject: Native ", "Subject: All Public <Row> ");
        if index == 0 {
            wire = wire.replacen(
                "Public preview. ",
                "Public preview <b>only text</b> & safe. ",
                1,
            );
        }
        fs::write(&path, wire).unwrap();
        if index == 3 {
            fs::rename(path, root.join("alice/Maildir/.Sent/new/synthetic-003")).unwrap();
        }
    }
    write_message(&root, "bob", 0, 0);
    let bob_path = root.join("bob/Maildir/new/synthetic-000");
    fs::write(
        &bob_path,
        fs::read_to_string(&bob_path)
            .unwrap()
            .replace("Subject: Native ", "Subject: All Public <Row> "),
    )
    .unwrap();
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = NativeExecutor {
        config,
        calls: calls.clone(),
        bin_move_count: None,
    };
    let native_list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(),
        executor.clone(),
        "/usr/local/bin/doveadm",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let inbox = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let sent_request = MessageListRequest::new(MessageListPolicy::default(), "Sent").unwrap();
    let initial = native_list.list_messages(ALICE, &inbox).unwrap();
    let sent = native_list.list_messages(ALICE, &sent_request).unwrap();
    let bob_initial = native_list.list_messages(BOB, &inbox).unwrap();
    assert_eq!(initial.len(), 3);
    assert_eq!(sent.len(), 1);
    assert_eq!(bob_initial.len(), 1);
    let target = initial
        .iter()
        .find(|row| row.subject.as_deref() == Some("All Public <Row> 000"))
        .unwrap();
    assert_eq!(target.uid, sent[0].uid);
    assert_eq!(target.uid, bob_initial[0].uid);
    let version = target.metadata.as_ref().unwrap().version.clone();
    assert_ne!(
        version.mailbox_guid,
        sent[0].metadata.as_ref().unwrap().version.mailbox_guid
    );
    assert_ne!(version, bob_initial[0].metadata.as_ref().unwrap().version);
    let preview = target
        .metadata
        .as_ref()
        .unwrap()
        .preview
        .clone()
        .expect("actual bounded public native preview");
    assert!(crate::message_metadata::valid_message_preview(&preview));
    let encrypted = initial
        .iter()
        .find(|row| row.subject.as_deref() == Some("All Public <Row> 001"))
        .unwrap();
    assert_eq!(
        encrypted.metadata.as_ref().unwrap().protection,
        MessageProtection::Encrypted
    );
    assert!(encrypted.metadata.as_ref().unwrap().preview.is_none());
    let alice_wire = scoped_delete_wire_bytes(&root, "alice", "");
    let sent_wire = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    let bob_wire = scoped_delete_wire_bytes(&root, "bob", "");
    let armed = Arc::new(AtomicBool::new(false));
    let triggered = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = start_helper(
        &mut fixture,
        executor,
        userdb,
        target.uid,
        armed,
        triggered.clone(),
        forbidden.clone(),
    );
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let app_config = AppConfig::from_env_map(&BTreeMap::from([
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
        (
            "OSMAP_MAILBOX_HELPER_PEER_UID".into(),
            test_runtime_uid().to_string(),
        ),
        ("OSMAP_MAILBOX_WORKER_BUDGET".into(), "1".into()),
        ("OSMAP_SEARCH_WORKER_BUDGET".into(), "1".into()),
    ]))
    .unwrap();
    assert!(
        app_config.openpgp_crypto.is_none()
            && app_config.openpgp_inventory.is_none()
            && app_config.openpgp_public_admin.is_none()
    );
    let contacts = crate::contacts::ContactStore::new(
        app_config.state_layout.settings_dir.join("contacts-v1"),
    );
    let own = contacts
        .change(
            ALICE,
            0,
            crate::contacts::ContactChange::Save {
                id: None,
                display_name: "All Public <Person>".into(),
                address: "own-public@example.test".into(),
            },
        )
        .unwrap();
    let foreign = contacts
        .change(
            BOB,
            0,
            crate::contacts::ContactChange::Save {
                id: None,
                display_name: "All Public FOREIGN-SENTINEL".into(),
                address: "foreign-public@example.test".into(),
            },
        )
        .unwrap();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "native-reader-session",
        "127.0.0.1",
        "OSMAP/native-reader",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(&app_config.state_layout.session_dir),
        SystemTimeProvider,
        SystemRandomSource,
        1800,
        1800,
    );
    // This deliberately qualifies synthetic post-auth sessions, not login/TOTP.
    let alice = sessions
        .issue(&context, ALICE, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config),
    );
    let all = get(&app, &alice, "/search?category=all&q=Public");
    assert_eq!(all.response.status_code, 200);
    budget_pair(&all);
    let body = text(&all);
    assert_eq!(body.matches("class=\"search-result-row\"").count(), 5);
    assert!(
        body.contains("All available (5)")
            && body.contains("Messages (4)")
            && body.contains("People (1)")
    );
    assert!(body.contains("Documents unavailable") && !body.contains("Documents (0)"));
    assert!(body.contains("All Public &lt;Person&gt;") && body.contains("All Public &lt;Row&gt;"));
    assert!(body.contains(&*crate::http_support::escape_html(&preview)));
    assert!(
        !body.contains("<b>only text</b>") && !body.contains("Public invalid ciphertext fixture.")
    );
    assert!(
        !body.contains("FOREIGN-SENTINEL")
            && !body.contains("foreign-public@example.test")
            && !body.contains("BOB_READER_ONLY")
    );
    assert!(
        !body.contains("ALICE_READER_ONLY"),
        "native list cannot supply the post-preview body sentinel"
    );
    assert!(
        body.contains(">INBOX</span>")
            && body.contains(">Sent</span>")
            && body.contains("Saved contacts")
    );
    let contact_link = format!(
        "/contacts?edit={}&revision={}",
        encode(&own.contacts[0].id),
        own.revision
    );
    assert!(body.contains(&*crate::http_support::escape_html(&contact_link)));
    let actual_contact = get(&app, &alice, &contact_link);
    assert_eq!(actual_contact.response.status_code, 200);
    assert!(
        text(&actual_contact).contains("value=\"All Public &lt;Person&gt;\"")
            && !text(&actual_contact).contains("FOREIGN-SENTINEL")
    );
    let link = all_search_row_link(body, "INBOX", target.uid);
    assert!(
        link.contains("mailbox_guid=")
            && link.contains("message_guid=")
            && link.contains("return_to=")
    );
    let read = get(&app, &alice, &link);
    assert_eq!(read.response.status_code, 200);
    assert!(
        text(&read).contains("ALICE_READER_ONLY_000") && !text(&read).contains("BOB_READER_ONLY")
    );
    let back = back_href(text(&read));
    assert_eq!(back, "/search?category=all&page=1&q=Public");
    let returned = get(&app, &alice, &back);
    assert_eq!(returned.response.status_code, 200);
    budget_pair(&returned);
    assert!(text(&returned).contains("Messages (4)") && text(&returned).contains("People (1)"));
    let stale = link.replace(&version.message_guid, "stale-native-message-guid");
    assert_ne!(stale, link);
    let denied = get(&app, &alice, &stale);
    assert_eq!(denied.response.status_code, 503);
    assert!(!text(&denied).contains("ALICE_READER_ONLY_000"));
    let foreign_open = get(&app, &bob, &link);
    assert_eq!(foreign_open.response.status_code, 503);
    assert!(
        !text(&foreign_open).contains("ALICE_READER_ONLY_000")
            && !text(&foreign_open).contains("BOB_READER_ONLY_000")
    );
    let before_unauth = calls.load(Ordering::SeqCst);
    let unauth = http(
        &app,
        None,
        "GET",
        "/search?category=all&q=Public",
        &BTreeMap::new(),
    );
    assert_eq!(unauth.response.status_code, 303);
    assert_eq!(calls.load(Ordering::SeqCst), before_unauth);
    assert_eq!(contacts.load(ALICE).unwrap(), own);
    assert_eq!(contacts.load(BOB).unwrap(), foreign);
    assert_eq!(native_list.list_messages(ALICE, &inbox).unwrap(), initial);
    assert_eq!(
        native_list.list_messages(ALICE, &sent_request).unwrap(),
        sent
    );
    assert_eq!(native_list.list_messages(BOB, &inbox).unwrap(), bob_initial);
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ""), alice_wire);
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ".Sent"), sent_wire);
    assert_eq!(scoped_delete_wire_bytes(&root, "bob", ""), bob_wire);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    assert_eq!(triggered.load(Ordering::SeqCst), 0);
    assert!(started.elapsed() < NATIVE_LIMIT);
    drop(app);
    drop(sessions);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_all_search_browser=PASS actual_browser_runtime_authenticated_helper_dovecot=PASS measured_messages_and_owned_people=PASS public_snippet_escaped_protected_absent=PASS rendered_guid_open_actual_body_and_all_back=PASS foreign_stale_unauth_refused=PASS same_uid_inbox_sent_bob_bytes_flags_guids_unchanged=PASS contact_records_unchanged=PASS no_move_append_delete_send_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
