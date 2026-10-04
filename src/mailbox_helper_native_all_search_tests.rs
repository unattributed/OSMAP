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

fn all_search_native_neighbour_link(body: &str, label: &str) -> Option<String> {
    body.split("<a ").find_map(|anchor| {
        let tag = anchor.split_once('>')?.0;
        (attribute(tag, "aria-label")?.as_str() == format!("{label} message"))
            .then(|| attribute(tag, "href"))
            .flatten()
    })
}

fn all_search_native_filter_form(body: &str, class: &str) -> BTreeMap<String, String> {
    let detail = body
        .split_once(&format!("<details class=\"{class}\""))
        .unwrap()
        .1
        .split_once("</details>")
        .unwrap()
        .0;
    let form = detail
        .split_once("<form ")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains("method=\"get\"") && form.contains("action=\"/search\""));
    let mut fields = BTreeMap::new();
    for input in form.split("<input ").skip(1) {
        let tag = input.split_once('>').unwrap().0;
        assert!(fields
            .insert(
                attribute(tag, "name").unwrap(),
                attribute(tag, "value").unwrap()
            )
            .is_none());
    }
    assert!(!fields.keys().any(|key| matches!(
        key.as_str(),
        "sort" | "dir" | "page" | "scope" | "select" | "selected_uid" | "field"
    )));
    fields
}
fn all_search_native_form_href(fields: &BTreeMap<String, String>) -> String {
    format!(
        "/search?{}",
        fields
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    )
}
fn all_search_native_tab_href(body: &str, label: &str) -> String {
    let nav = body
        .split_once("class=\"search-result-tabs\"")
        .unwrap()
        .1
        .split_once("</nav>")
        .unwrap()
        .0;
    let tag = nav
        .split("<a ")
        .find(|anchor| {
            anchor
                .split_once('>')
                .is_some_and(|(_, text)| text.starts_with(label))
        })
        .unwrap()
        .split_once('>')
        .unwrap()
        .0;
    attribute(tag, "href").unwrap()
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
    // Apply actual rendered native GET forms, not handcrafted UI-only state.
    let mut filter_fields = all_search_native_filter_form(body, "sender-filter");
    filter_fields.insert("from".into(), "sender@example.test".into());
    let by_sender = get(&app, &alice, &all_search_native_form_href(&filter_fields));
    assert_eq!(by_sender.response.status_code, 200);
    budget_pair(&by_sender);
    assert!(text(&by_sender).contains("Messages (3)") && text(&by_sender).contains("People (1)"));
    assert!(!text(&by_sender).contains("All Public &lt;Row&gt; 001"));
    let mut filter_fields = all_search_native_filter_form(text(&by_sender), "date-filter");
    let day = &target.date_received[..10];
    filter_fields.insert("after".into(), day.into());
    filter_fields.insert("before".into(), day.into());
    let by_date = get(&app, &alice, &all_search_native_form_href(&filter_fields));
    assert_eq!(by_date.response.status_code, 200);
    budget_pair(&by_date);
    assert!(text(&by_date).contains("All Public &lt;Row&gt; 000"));
    let mut filter_fields = all_search_native_filter_form(text(&by_date), "folder-filter");
    filter_fields.insert("mailbox".into(), "INBOX".into());
    filter_fields.insert("filter".into(), "unread".into());
    filter_fields.insert("pgp".into(), "plain".into());
    filter_fields.insert("attachment".into(), "without".into());
    let filtered_path = all_search_native_form_href(&filter_fields);
    let scoped = get(&app, &alice, &filtered_path);
    assert_eq!(scoped.response.status_code, 200);
    budget_pair(&scoped);
    assert!(text(&scoped).contains("Messages (2)") && text(&scoped).contains("People (1)"));
    assert_eq!(
        text(&scoped).matches("class=\"search-result-row\"").count(),
        3
    );
    assert!(
        !text(&scoped).contains("All Public &lt;Row&gt; 001")
            && !text(&scoped).contains("All Public &lt;Row&gt; 003")
    );
    let filtered_link = all_search_row_link(text(&scoped), "INBOX", target.uid);
    let filtered_read = get(&app, &alice, &filtered_link);
    assert_eq!(filtered_read.response.status_code, 200);
    assert!(text(&filtered_read).contains("ALICE_READER_ONLY_000"));
    // Follow actual authenticated native All neighbours, not a fabricated URL.
    // Sender excludes001 and folder excludes003, so the next owned row is002.
    let second_target = initial
        .iter()
        .find(|row| row.subject.as_deref() == Some("All Public <Row> 002"))
        .unwrap();
    let second_version = &second_target.metadata.as_ref().unwrap().version;
    assert!(all_search_native_neighbour_link(text(&filtered_read), "Previous").is_none());
    let native_next = all_search_native_neighbour_link(text(&filtered_read), "Next")
        .expect("actual All next link");
    let native_next_fields = crate::http_form::parse_urlencoded_form(
        native_next.split_once('?').unwrap().1.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    assert_eq!(
        native_next_fields.get("mailbox").map(String::as_str),
        Some("INBOX")
    );
    assert_eq!(
        native_next_fields.get("uid"),
        Some(&second_target.uid.to_string())
    );
    assert_eq!(
        native_next_fields.get("mailbox_guid"),
        Some(&second_version.mailbox_guid)
    );
    assert_eq!(
        native_next_fields.get("message_guid"),
        Some(&second_version.message_guid)
    );
    let native_next_back = crate::http_form::parse_urlencoded_form(
        native_next_fields["return_to"]
            .split_once('?')
            .unwrap()
            .1
            .as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    for (key, value) in &filter_fields {
        assert_eq!(
            native_next_back.get(key),
            Some(value),
            "native next retains {key}"
        );
    }
    assert_eq!(native_next_back.get("page").map(String::as_str), Some("1"));
    let second_read = get(&app, &alice, &native_next);
    assert_eq!(second_read.response.status_code, 200);
    budget_pair(&filtered_read);
    budget_pair(&second_read);
    assert!(
        text(&second_read).contains("ALICE_READER_ONLY_002")
            && !text(&second_read).contains("ALICE_READER_ONLY_000")
            && !text(&second_read).contains("BOB_READER_ONLY")
    );
    assert!(
        all_search_native_neighbour_link(text(&second_read), "Next").is_none(),
        "Person is not a reader neighbour"
    );
    let native_previous = all_search_native_neighbour_link(text(&second_read), "Previous")
        .expect("actual All previous link");
    let native_previous_fields = crate::http_form::parse_urlencoded_form(
        native_previous.split_once('?').unwrap().1.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    assert_eq!(
        native_previous_fields.get("mailbox").map(String::as_str),
        Some("INBOX")
    );
    assert_eq!(
        native_previous_fields.get("uid"),
        Some(&target.uid.to_string())
    );
    assert_eq!(
        native_previous_fields.get("mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_eq!(
        native_previous_fields.get("message_guid"),
        Some(&version.message_guid)
    );
    let native_previous_back = crate::http_form::parse_urlencoded_form(
        native_previous_fields["return_to"]
            .split_once('?')
            .unwrap()
            .1
            .as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    assert_eq!(native_previous_back, native_next_back);
    let first_again = get(&app, &alice, &native_previous);
    assert_eq!(first_again.response.status_code, 200);
    budget_pair(&first_again);
    assert!(
        text(&first_again).contains("ALICE_READER_ONLY_000")
            && !text(&first_again).contains("ALICE_READER_ONLY_002")
    );
    assert_eq!(
        get(&app, &alice, &back_href(text(&second_read)))
            .response
            .status_code,
        200
    );
    let filtered_back = back_href(text(&filtered_read));
    let back_fields = crate::http_form::parse_urlencoded_form(
        filtered_back.split_once('?').unwrap().1.as_bytes(),
        19,
        2048,
    )
    .unwrap();
    for (key, value) in &filter_fields {
        assert_eq!(back_fields.get(key), Some(value), "retained {key}");
    }
    assert_eq!(back_fields.get("page").map(String::as_str), Some("1"));
    let filtered_return = get(&app, &alice, &filtered_back);
    assert_eq!(filtered_return.response.status_code, 200);
    budget_pair(&filtered_return);
    assert!(text(&filtered_return).contains("Messages (2)"));
    let people_href = all_search_native_tab_href(text(&scoped), "People");
    let before_people = calls.load(Ordering::SeqCst);
    let only_people = get(&app, &alice, &people_href);
    assert_eq!(only_people.response.status_code, 200);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        before_people,
        "People must not dispatch mail filters"
    );
    assert!(
        text(&only_people).contains("People (1)")
            && text(&only_people).contains("do not filter People")
    );
    assert!(!text(&only_people).contains("FOREIGN-SENTINEL"));
    let all_tab_href = all_search_native_tab_href(text(&only_people), "All");
    let all_tab = get(&app, &alice, &all_tab_href);
    assert_eq!(all_tab.response.status_code, 200);
    budget_pair(&all_tab);
    assert!(text(&all_tab).contains("Messages (2)") && text(&all_tab).contains("People (1)"));
    let messages_href = all_search_native_tab_href(text(&scoped), "Messages");
    let messages_tab = get(&app, &alice, &messages_href);
    assert_eq!(messages_tab.response.status_code, 200);
    budget_pair(&messages_tab);
    assert!(
        text(&messages_tab).contains("All Public &lt;Row&gt; 000")
            && !text(&messages_tab).contains("All Public &lt;Row&gt; 001")
            && !text(&messages_tab).contains("All Public &lt;Row&gt; 003")
    );
    let encrypted_filter = get(&app, &alice, "/search?category=all&q=Public&pgp=encrypted");
    assert_eq!(encrypted_filter.response.status_code, 200);
    budget_pair(&encrypted_filter);
    assert!(
        text(&encrypted_filter).contains("Messages (1)")
            && text(&encrypted_filter).contains("People (1)")
    );
    assert!(
        text(&encrypted_filter).contains("All Public &lt;Row&gt; 001")
            && !text(&encrypted_filter).contains("Public invalid ciphertext fixture.")
    );
    let before_clear = calls.load(Ordering::SeqCst);
    let clear_tag = text(&scoped)
        .split("<a ")
        .find(|anchor| {
            anchor
                .split_once('>')
                .is_some_and(|(_, text)| text.starts_with("Clear search</a>"))
        })
        .unwrap()
        .split_once('>')
        .unwrap()
        .0;
    let clear_href = attribute(clear_tag, "href").unwrap();
    let cleared = get(&app, &alice, &clear_href);
    assert_eq!(cleared.response.status_code, 200);
    assert_eq!(calls.load(Ordering::SeqCst), before_clear);
    assert!(
        text(&cleared).contains("Messages not searched")
            && !text(&cleared).contains("name=\"from\" value=\"sender@example.test\"")
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
    println!("native_all_search_browser=PASS all_message_filters_actual_owned_scope_context=PASS all_reader_navigation_actual_filtered_next_previous=PASS actual_browser_runtime_authenticated_helper_dovecot=PASS measured_messages_and_owned_people=PASS public_snippet_escaped_protected_absent=PASS rendered_guid_open_actual_body_and_all_back=PASS foreign_stale_unauth_refused=PASS same_uid_inbox_sent_bob_bytes_flags_guids_unchanged=PASS contact_records_unchanged=PASS no_move_append_delete_send_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
