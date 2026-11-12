//! Additive opt-in proof. The existing reader/Bin expunge and move guards stay unchanged.
use super::*;

#[derive(Clone)]
struct ArchiveExecutor {
    inner: NativeExecutor,
    permitted_move: Vec<String>,
    moved: Arc<AtomicUsize>,
}
impl CommandExecutor for ArchiveExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("Archive fixture requires bounded execution")
    }
    fn run_with_stdin_bytes_timeout(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(p, a, input, timeout, 1024 * 1024)
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert!(!a
            .iter()
            .any(|v| matches!(v.as_str(), "expunge" | "save" | "-A" | "-F" | "-c")));
        if !a.iter().any(|v| v == "move") {
            return self
                .inner
                .run_with_stdin_bytes_timeout_and_output_limit(p, a, input, timeout, limit);
        }
        assert_eq!(p, "/usr/local/bin/doveadm");
        assert!(input.is_empty());
        assert_eq!(a, self.permitted_move.as_slice());
        assert!(timeout > Duration::ZERO && timeout <= Duration::from_secs(3));
        assert_eq!(
            self.moved.fetch_add(1, Ordering::SeqCst),
            0,
            "no second Archive or automatic retry"
        );
        let mut isolated = vec![
            "-c".into(),
            self.inner.config.to_string_lossy().into_owned(),
        ];
        isolated.extend_from_slice(a);
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(p, &isolated, input, timeout, limit)
    }
}

struct ArchiveForbiddenFlag(Arc<AtomicUsize>);
impl MessageFlagBackend for ArchiveForbiddenFlag {
    fn set_message_flag(
        &self,
        _: &str,
        _: &crate::mailbox::MessageFlagRequest,
    ) -> Result<crate::mailbox::MessageFlagResult, MailboxBackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(MailboxBackendError {
            backend: "archive-fixture-forbidden",
            reason: "flag mutation outside Archive fixture".into(),
        })
    }
}

fn start_archive_helper(
    fixture: &mut Fixture,
    executor: ArchiveExecutor,
    userdb: PathBuf,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("archive.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = fixture.stop.clone();
    fixture.threads.push(thread::spawn(move || {
        let listing = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let messages = DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let search = DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let view = DoveadmMessageViewBackend::new(
            MessageViewPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let moves = DoveadmMessageMoveBackend::new(executor, "/usr/local/bin/doveadm")
            .with_userdb_socket_path(Some(userdb));
        let append = ForbiddenMutation(forbidden.clone());
        let flags = ArchiveForbiddenFlag(forbidden);
        let replay = Mutex::new(BTreeMap::new());
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("Archive helper accept failed: {error}"),
            };
            handle_helper_client(
                HelperBackends {
                    mailbox_backend: &listing,
                    message_list_backend: &messages,
                    message_search_backend: &search,
                    message_view_backend: &view,
                    message_move_backend: &moves,
                    message_append_backend: &append,
                    message_flag_backend: &flags,
                },
                &Logger::new(crate::config::LogFormat::Text, LogLevel::Error),
                &mut stream,
                MailboxHelperPolicy::default(),
                MailboxHelperTrustedCallerPolicy {
                    trusted_peer_uid: test_runtime_uid(),
                    grant_key: test_helper_grant_key(),
                },
                &replay,
            );
        }
    }));
    socket
}

#[test]
#[ignore = "explicit OpenBSD S02-03 Archive-event routes; disposable owned Dovecot and signed helper only"]
fn isolated_openbsd_confirmed_archive_event_browser_persistence() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-archive-native-{}-{}",
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
        for folder in ["", ".Archive"] {
            for part in ["cur", "new", "tmp"] {
                fs::create_dir_all(root.join(user).join("Maildir").join(folder).join(part))
                    .unwrap();
            }
        }
    }
    for index in 0..3 {
        write_message(&root, "alice", index, 0);
    }
    for index in 0..2 {
        write_message(&root, "bob", index, 0);
    }
    // Three legacy Archive messages force the moved target to get a different
    // destination UID; no assumption that a move preserves or changes a UID.
    for index in 10..13 {
        write_message(&root, "alice", index, 0);
        fs::rename(
            root.join(format!("alice/Maildir/new/synthetic-{index:03}")),
            root.join(format!("alice/Maildir/.Archive/new/legacy-{index:03}")),
        )
        .unwrap();
    }
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let reader = NativeExecutor {
        config,
        calls: Arc::new(AtomicUsize::new(0)),
        bin_move_count: None,
    };
    let native_list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(),
        reader.clone(),
        "/usr/local/bin/doveadm",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let inbox = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let archive = MessageListRequest::new(MessageListPolicy::default(), "Archive").unwrap();
    let initial = native_list.list_messages(ALICE, &inbox).unwrap();
    let foreign = native_list.list_messages(BOB, &inbox).unwrap();
    let legacy = native_list.list_messages(ALICE, &archive).unwrap();
    assert_eq!(initial.len(), 3);
    assert_eq!(foreign.len(), 2);
    assert_eq!(legacy.len(), 3);
    let target = initial
        .iter()
        .find(|row| row.subject.as_deref() == Some("Native 000"))
        .unwrap();
    let version = &target.metadata.as_ref().unwrap().version;
    let neighbours: Vec<_> = initial
        .iter()
        .filter(|row| row.uid != target.uid)
        .cloned()
        .collect();
    let neighbour_versions: Vec<_> = neighbours
        .iter()
        .map(|row| row.metadata.as_ref().unwrap().version.clone())
        .collect();
    let target_wire = fs::read(root.join("alice/Maildir/new/synthetic-000")).unwrap();
    let neighbour_wire: Vec<_> = scoped_delete_wire_bytes(&root, "alice", "")
        .into_iter()
        .filter(|bytes| bytes != &target_wire)
        .collect();
    assert_eq!(neighbour_wire.len(), neighbours.len());
    let foreign_wire = scoped_delete_wire_bytes(&root, "bob", "");
    let legacy_wire = scoped_delete_wire_bytes(&root, "alice", ".Archive");
    let moved = Arc::new(AtomicUsize::new(0));
    let executor = ArchiveExecutor {
        inner: reader,
        moved: moved.clone(),
        permitted_move: vec![
            "-o".into(),
            "stats_writer_socket_path=".into(),
            "-o".into(),
            format!("auth_socket_path={}", userdb.display()),
            "move".into(),
            "-u".into(),
            ALICE.into(),
            "Archive".into(),
            "mailbox".into(),
            "INBOX".into(),
            "mailbox-guid".into(),
            version.mailbox_guid.clone(),
            "uid".into(),
            target.uid.to_string(),
            "guid".into(),
            version.message_guid.clone(),
        ],
    };
    let forbidden = Arc::new(AtomicUsize::new(0));
    let socket = start_archive_helper(&mut fixture, executor, userdb, forbidden.clone());
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
            socket.to_string_lossy().into_owned(),
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
    ]))
    .unwrap();
    assert!(
        app_config.openpgp_crypto.is_none()
            && app_config.openpgp_inventory.is_none()
            && app_config.openpgp_public_admin.is_none()
    );
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
    let settings = BTreeMap::from([
        ("csrf_token".into(), alice.record.csrf_token.clone()),
        ("settings_action".into(), "archive".into()),
        ("return_section".into(), "copies".into()),
        ("archive_mailbox_name".into(), "Archive".into()),
    ]);
    assert_eq!(
        http(&app, Some(&alice), "POST", "/settings", &settings)
            .response
            .status_code,
        303
    );
    let mut bob_settings = settings.clone();
    bob_settings.insert("csrf_token".into(), bob.record.csrf_token.clone());
    assert_eq!(
        http(&app, Some(&bob), "POST", "/settings", &bob_settings)
            .response
            .status_code,
        303
    );
    let events = crate::archive_event::Store::new(
        app_config
            .state_layout
            .settings_dir
            .join("archive-events-v1"),
    );
    let previous = get(&app, &alice, "/mailbox?name=Archive");
    assert_eq!(previous.response.status_code, 200);
    assert!(text(&previous).contains("data-label=\"Archived\">Unknown"));
    let selected = get(&app, &alice, &format!("/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid={}&selected_mailbox_guid={}&selected_message_guid={}", target.uid, encode(&version.mailbox_guid), encode(&version.message_guid)));
    assert_eq!(selected.response.status_code, 200);
    let form = bin_move_form(text(&selected), "INBOX", target.uid, "archive");
    let mut invalid = form.clone();
    invalid.insert("csrf_token".into(), "0".repeat(64));
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/move", &invalid)
            .response
            .status_code,
        403
    );
    let mut foreign_form = form.clone();
    foreign_form.insert("csrf_token".into(), bob.record.csrf_token.clone());
    assert_eq!(
        http(&app, Some(&bob), "POST", "/message/move", &foreign_form)
            .response
            .status_code,
        409
    );
    assert_eq!(moved.load(Ordering::SeqCst), 0);
    assert_eq!(events.load(ALICE).unwrap().revision(), 0);
    let earliest = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let response = http(&app, Some(&alice), "POST", "/message/move", &form);
    let latest = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(response.response.status_code, 303, "{}", text(&response));
    assert_eq!(moved.load(Ordering::SeqCst), 1);
    let after = native_list.list_messages(ALICE, &archive).unwrap();
    assert_eq!(after.len(), 4);
    for previous in &legacy {
        let current = after.iter().find(|row| row.uid == previous.uid).unwrap();
        assert_eq!(current.metadata, previous.metadata);
        assert_eq!(current.flags, previous.flags);
        assert_eq!(current.date_received, previous.date_received);
    }
    let destination = after
        .iter()
        .find(|row| row.metadata.as_ref().unwrap().version.message_guid == version.message_guid)
        .unwrap();
    assert_ne!(destination.uid, target.uid);
    assert_ne!(
        destination.metadata.as_ref().unwrap().version.mailbox_guid,
        version.mailbox_guid
    );
    let identity =
        crate::archive_event::Identity::from_summary(ALICE, ALICE, "Archive", destination).unwrap();
    let snapshot = events.load(ALICE).unwrap();
    let time = snapshot.archived_at(&identity).unwrap().unwrap();
    assert!((earliest..=latest).contains(&time));
    assert_eq!(snapshot.revision(), 1);
    for row in &legacy {
        assert_eq!(
            snapshot.archived_at(
                &crate::archive_event::Identity::from_summary(ALICE, ALICE, "Archive", row)
                    .unwrap()
            ),
            Ok(None)
        );
    }
    assert_eq!(events.load(BOB).unwrap().revision(), 0);
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/move", &form)
            .response
            .status_code,
        409
    );
    assert_eq!(moved.load(Ordering::SeqCst), 1);
    assert_eq!(events.load(ALICE).unwrap().revision(), 1);
    let restarted = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config),
    );
    let page = get(&restarted, &alice, "/mailbox?name=Archive");
    assert_eq!(page.response.status_code, 200);
    let table = text(&page).split("<table class=\"archive-table\">").nth(1).unwrap().split("</thead>").next().unwrap();
    assert_eq!(table.matches("<th scope=\"col\">").count(), 7);
    assert!(table.contains("<th scope=\"col\">Archived</th>"));
    assert!(!table.contains("<th scope=\"col\">Received</th>"));
    assert!(text(&page).contains(&format!(
        "data-label=\"Archived\">{}",
        crate::logging::format_unix_timestamp_utc(time)
    )));
    assert!(text(&page).contains("data-label=\"Received\">"));
    assert!(text(&page).contains("data-label=\"Archived\">Unknown"));
    let remaining = native_list.list_messages(ALICE, &inbox).unwrap();
    assert_eq!(persisted_flags(&remaining), persisted_flags(&neighbours));
    for (row, identity) in remaining.iter().zip(neighbour_versions) {
        assert_eq!(row.metadata.as_ref().unwrap().version, identity);
    }
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ""), neighbour_wire);
    assert_eq!(
        persisted_flags(&native_list.list_messages(BOB, &inbox).unwrap()),
        persisted_flags(&foreign)
    );
    assert_eq!(scoped_delete_wire_bytes(&root, "bob", ""), foreign_wire);
    let current_legacy: Vec<_> = scoped_delete_wire_bytes(&root, "alice", ".Archive")
        .into_iter()
        .filter(|bytes| legacy_wire.contains(bytes))
        .collect();
    assert_eq!(current_legacy, legacy_wire);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_confirmed_archive_event=PASS actual_destination_uid_and_mailbox_guid=PASS received_not_relabelled=PASS unknown_legacy_dates=PASS persisted_restart=PASS csrf_foreign_stale_zero_event=PASS single_archive_no_retry=PASS neighbour_foreign_legacy_unchanged=PASS no_expunge_append_flag_crypto=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
