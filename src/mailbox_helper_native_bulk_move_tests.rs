//! Actual native reversible bulk move proof; original reader/Bin guards unchanged.
use super::*;

type MoveQueue = Arc<Mutex<std::collections::VecDeque<Vec<String>>>>;
type MoveAdmissions = Arc<Mutex<Vec<(String, MessageMoveRequest)>>>;

#[derive(Clone)]
struct BulkMoveExecutor {
    inner: NativeExecutor,
    permitted: MoveQueue,
    moved: Arc<AtomicUsize>,
}
impl CommandExecutor for BulkMoveExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bulk fixture requires bounded execution")
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
        assert!(timeout > Duration::ZERO && timeout <= Duration::from_secs(3));
        let expected = self
            .permitted
            .lock()
            .unwrap()
            .pop_front()
            .expect("no extra move or retry permitted");
        assert_eq!(a, expected.as_slice(), "entire exact owned argument array");
        assert!(self.moved.fetch_add(1, Ordering::SeqCst) < 7);
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
struct CountedBulkMoves {
    inner: DoveadmMessageMoveBackend<BulkMoveExecutor>,
    admissions: MoveAdmissions,
}
impl MessageMoveBackend for CountedBulkMoves {
    fn move_message(
        &self,
        account: &str,
        request: &MessageMoveRequest,
    ) -> Result<(), MailboxBackendError> {
        self.admissions
            .lock()
            .unwrap()
            .push((account.into(), request.clone()));
        self.inner.move_message(account, request)
    }
}
struct BulkMoveForbiddenFlag(Arc<AtomicUsize>);
impl MessageFlagBackend for BulkMoveForbiddenFlag {
    fn set_message_flag(
        &self,
        _: &str,
        _: &crate::mailbox::MessageFlagRequest,
    ) -> Result<crate::mailbox::MessageFlagResult, MailboxBackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(MailboxBackendError {
            backend: "bulk-fixture-forbidden",
            reason: "flag outside move proof".into(),
        })
    }
}
fn literal_move(
    userdb: &Path,
    source: &str,
    destination: &str,
    row: &MessageSummary,
) -> Vec<String> {
    let version = &row.metadata.as_ref().unwrap().version;
    vec![
        "-o".into(),
        "stats_writer_socket_path=".into(),
        "-o".into(),
        format!("auth_socket_path={}", userdb.display()),
        "move".into(),
        "-u".into(),
        ALICE.into(),
        destination.into(),
        "mailbox".into(),
        source.into(),
        "mailbox-guid".into(),
        version.mailbox_guid.clone(),
        "uid".into(),
        row.uid.to_string(),
        "guid".into(),
        version.message_guid.clone(),
    ]
}
fn rendered_bulk_form(
    body: &str,
    mailbox: &str,
    selected: &[MessageSummary],
    action: &str,
    destination: Option<&str>,
) -> BTreeMap<String, String> {
    let form = body
        .split("<form ")
        .find_map(|part| {
            let form = part.split_once("</form>")?.0;
            (attribute(form, "id").as_deref() == Some("bulk-move-form")).then_some(form)
        })
        .expect("rendered actual bulk move form");
    assert_eq!(attribute(form, "method").as_deref(), Some("post"));
    assert_eq!(attribute(form, "action").as_deref(), Some("/messages/move"));
    assert!(
        form.split("<button ").any(|button| {
            let Some(tag) = button.split_once('>').map(|v| v.0) else {
                return false;
            };
            attribute(tag, "name").as_deref() == Some("action")
                && attribute(tag, "value").as_deref() == Some(action)
                && !tag.contains(" disabled")
                && attribute(tag, "formaction").is_none()
        }),
        "actual enabled selected action"
    );
    let mut fields: BTreeMap<_, _> = form
        .split("<input ")
        .filter_map(|input| {
            let tag = input.split_once('>')?.0;
            Some((attribute(tag, "name")?, attribute(tag, "value")?))
        })
        .collect();
    assert_eq!(fields["mailbox"], mailbox);
    for row in selected {
        let name = format!("message_{}", row.uid);
        let value = body
            .split("<input ")
            .find_map(|input| {
                let tag = input.split_once('>')?.0;
                (attribute(tag, "form").as_deref() == Some("bulk-move-form")
                    && attribute(tag, "name").as_deref() == Some(name.as_str()))
                .then(|| attribute(tag, "value"))
                .flatten()
            })
            .expect("actual current GUID-bound checkbox");
        let v = &row.metadata.as_ref().unwrap().version;
        assert_eq!(
            value,
            format!("{}|{}|{}", row.uid, v.mailbox_guid, v.message_guid)
        );
        fields.insert(name, value);
    }
    if let Some(destination) = destination {
        assert!(
            form.split("<option ").any(|option| {
                option
                    .split_once('>')
                    .is_some_and(|(tag, _)| attribute(tag, "value").as_deref() == Some(destination))
            }),
            "actual owned destination option"
        );
        fields.insert("destination_mailbox".into(), destination.into());
    }
    fields.insert("action".into(), action.into());
    assert_eq!(
        fields
            .keys()
            .filter(|key| key.starts_with("message_"))
            .count(),
        selected.len()
    );
    fields
}
fn same_stored_message(actual: &MessageSummary, original: &MessageSummary) {
    assert_eq!(
        actual.metadata.as_ref().unwrap().version.message_guid,
        original.metadata.as_ref().unwrap().version.message_guid
    );
    assert_eq!(actual.flags, original.flags);
    assert_eq!(actual.date_received, original.date_received);
    assert_eq!(actual.size_virtual, original.size_virtual);
}

fn refreshed_inbox_rows(body: &str, expected: usize) {
    assert_eq!(
        body.matches("<li class=\"message-row message-card").count(),
        expected
    );
    assert!(body.contains(&format!("Select all {expected} on this page")));
    assert!(!body.contains("data-selected=\"true\""));
    let selections: Vec<_> = body
        .split("<input ")
        .filter_map(|input| {
            let tag = input.split_once('>')?.0;
            if attribute(tag, "type").as_deref() != Some("checkbox")
                || attribute(tag, "form").as_deref() != Some("bulk-move-form")
            {
                return None;
            }
            let name = attribute(tag, "name")?;
            let uid_text = name.strip_prefix("message_")?;
            let uid = uid_text.parse::<u32>().ok()?;
            (uid > 0 && uid.to_string() == uid_text).then_some(tag)
        })
        .collect();
    assert_eq!(selections.len(), expected);
    assert!(selections.iter().all(|tag| !tag
        .split_whitespace()
        .any(|field| field.trim_end_matches('/') == "checked")));
    assert!(!body.split("<input ").any(|input| input
        .split_once('>')
        .is_some_and(|(tag, _)| attribute(tag, "name").as_deref() == Some("selected_uid"))));
}

fn assert_return_context(actual: &str, rendered: &str, mailbox: &str) {
    let parse = |value: &str| {
        assert!(!value.contains('#'));
        let (path, query) = value.split_once('?').expect("native list return query");
        assert_eq!(path, "/mailbox");
        crate::http_form::parse_urlencoded_form(
            query.as_bytes(),
            crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
            2048,
        )
        .expect("bounded actual return fields")
    };
    let actual_fields = parse(actual);
    let mut originating_fields = parse(rendered);
    for key in [
        "select",
        "selected_mailbox",
        "selected_uid",
        "selected_mailbox_guid",
        "selected_message_guid",
        "opened_read",
    ] {
        originating_fields.remove(key);
        assert!(!actual_fields.contains_key(key), "action selection cleared");
    }
    assert_eq!(
        actual_fields, originating_fields,
        "originating semantic context retained"
    );
    assert_eq!(actual_fields.get("name").map(String::as_str), Some(mailbox));
    assert_eq!(
        actual_fields.get("sort").map(String::as_str),
        Some("subject")
    );
    assert_eq!(actual_fields.get("dir").map(String::as_str), Some("asc"));
}

fn rendered_refresh_href(body: &str) -> String {
    let links: Vec<_> = body
        .split("<a ")
        .filter_map(|anchor| {
            let (tag, content) = anchor.split_once('>')?;
            let label = content.split_once("</a>")?.0;
            if label != "Refresh message list" {
                return None;
            }
            assert!(!tag.contains(" disabled"));
            assert_ne!(attribute(tag, "aria-disabled").as_deref(), Some("true"));
            Some(attribute(tag, "href").expect("enabled actual refresh anchor"))
        })
        .collect();
    assert_eq!(links.len(), 1);
    links[0].clone()
}

fn start_bulk_move_helper(
    fixture: &mut Fixture,
    executor: BulkMoveExecutor,
    admissions: MoveAdmissions,
    userdb: PathBuf,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("bulk-move.sock");
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
        let moves = CountedBulkMoves {
            inner: DoveadmMessageMoveBackend::new(executor, "/usr/local/bin/doveadm")
                .with_userdb_socket_path(Some(userdb)),
            admissions,
        };
        let append = ForbiddenMutation(forbidden.clone());
        let flags = BulkMoveForbiddenFlag(forbidden);
        let replay = Mutex::new(BTreeMap::new());
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("Bulk move helper accept failed: {error}"),
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
#[ignore = "explicit OpenBSD reversible bulk Move/Archive/Restore; disposable signed helper and Dovecot only"]
fn isolated_openbsd_reversible_bulk_move_archive_restore_browser() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-bulk-move-native-{}-{}",
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
        for folder in ["", ".Archive", ".Deleted"] {
            for part in ["cur", "new", "tmp"] {
                fs::create_dir_all(root.join(user).join("Maildir").join(folder).join(part))
                    .unwrap();
            }
        }
    }
    for index in 0..4 {
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
    assert_eq!(initial.len(), 4);
    assert_eq!(foreign.len(), 2);
    assert_eq!(legacy.len(), 3);

    let mut targets: Vec<_> = initial
        .iter()
        .filter(|row| row.subject.as_deref() != Some("Native 003"))
        .cloned()
        .collect();
    targets.sort_by_key(|row| row.uid);
    assert_eq!(targets.len(), 3);
    let neighbour = initial
        .iter()
        .find(|row| row.subject.as_deref() == Some("Native 003"))
        .unwrap()
        .clone();
    let initial_wire = scoped_delete_wire_bytes(&root, "alice", "");
    let foreign_wire = scoped_delete_wire_bytes(&root, "bob", "");
    let legacy_wire = scoped_delete_wire_bytes(&root, "alice", ".Archive");
    let permitted: MoveQueue = Arc::new(Mutex::new(std::collections::VecDeque::from([
        literal_move(&userdb, "INBOX", "Archive", &targets[0]),
    ])));
    let moved = Arc::new(AtomicUsize::new(0));
    let admissions: MoveAdmissions = Arc::new(Mutex::new(Vec::new()));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let executor = BulkMoveExecutor {
        inner: reader,
        permitted: permitted.clone(),
        moved: moved.clone(),
    };
    let socket = start_bulk_move_helper(
        &mut fixture,
        executor,
        admissions.clone(),
        userdb.clone(),
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
    let bob_session = sessions
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
    bob_settings.insert("csrf_token".into(), bob_session.record.csrf_token.clone());
    assert_eq!(
        http(&app, Some(&bob_session), "POST", "/settings", &bob_settings)
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

    let bin_settings = BTreeMap::from([
        ("csrf_token".into(), alice.record.csrf_token.clone()),
        ("expected_revision".into(), "0".into()),
        ("mailbox_name".into(), "Deleted".into()),
        ("section".into(), "reading".into()),
    ]);
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/bin-folder",
            &bin_settings
        )
        .response
        .status_code,
        303
    );
    let origin = "/mailbox?name=INBOX&sort=subject&dir=asc";
    let page = get(&app, &alice, origin);
    assert_eq!(page.response.status_code, 200);
    let original_form = rendered_bulk_form(text(&page), "INBOX", &targets, "archive", None);
    let back = original_form["return_to"].clone();
    let mut bad_csrf = original_form.clone();
    bad_csrf.insert("csrf_token".into(), "0".repeat(64));
    assert_eq!(
        http(&app, Some(&alice), "POST", "/messages/move", &bad_csrf)
            .response
            .status_code,
        403
    );
    assert!(admissions.lock().unwrap().is_empty());
    assert_eq!(moved.load(Ordering::SeqCst), 0);
    let mut partial_form = original_form.clone();
    let second = &targets[1];
    let second_version = &second.metadata.as_ref().unwrap().version;
    partial_form.insert(
        format!("message_{}", second.uid),
        format!(
            "{}|{}|stale-{}",
            second.uid, second_version.mailbox_guid, second_version.message_guid
        ),
    );
    let earliest = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let partial = http(&app, Some(&alice), "POST", "/messages/move", &partial_form);
    let latest = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(partial.response.status_code, 409);
    assert!(text(&partial)
        .contains("1 confirmed moved; 0 uncertain; 1 remaining messages were not attempted."));
    assert!(text(&partial).contains("was refused"));
    let refresh_href = rendered_refresh_href(text(&partial));
    assert_return_context(&refresh_href, &back, "INBOX");
    let seen = admissions.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|(account, _)| account == ALICE));
    assert_eq!(seen[0].1.uid, targets[0].uid);
    assert_eq!(seen[1].1.uid, targets[1].uid);
    assert_eq!(moved.load(Ordering::SeqCst), 1);
    assert!(permitted.lock().unwrap().is_empty());
    let archived = native_list.list_messages(ALICE, &archive).unwrap();
    assert_eq!(archived.len(), 4);
    let archived_first = archived
        .iter()
        .find(|row| {
            row.metadata.as_ref().unwrap().version.message_guid
                == targets[0].metadata.as_ref().unwrap().version.message_guid
        })
        .unwrap()
        .clone();
    assert_ne!(archived_first.uid, targets[0].uid);
    assert_ne!(
        archived_first
            .metadata
            .as_ref()
            .unwrap()
            .version
            .mailbox_guid,
        targets[0].metadata.as_ref().unwrap().version.mailbox_guid
    );
    same_stored_message(&archived_first, &targets[0]);
    let archive_identity =
        crate::archive_event::Identity::from_summary(ALICE, ALICE, "Archive", &archived_first)
            .unwrap();
    let event_snapshot = events.load(ALICE).unwrap();
    assert_eq!(event_snapshot.revision(), 1);
    let archive_time = event_snapshot
        .archived_at(&archive_identity)
        .unwrap()
        .unwrap();
    assert!((earliest..=latest).contains(&archive_time));
    for row in &legacy {
        assert_eq!(archived.iter().find(|v| v.uid == row.uid).unwrap(), row);
    }
    let remaining = native_list.list_messages(ALICE, &inbox).unwrap();
    assert_eq!(remaining.len(), 3);
    for row in &targets[1..] {
        assert_eq!(remaining.iter().find(|v| v.uid == row.uid).unwrap(), row);
    }
    assert_eq!(
        remaining.iter().find(|v| v.uid == neighbour.uid).unwrap(),
        &neighbour
    );
    let before_replay = admissions.lock().unwrap().len();
    assert_eq!(
        http(&app, Some(&alice), "POST", "/messages/move", &partial_form)
            .response
            .status_code,
        409
    );
    assert_eq!(admissions.lock().unwrap().len(), before_replay + 1);
    assert_eq!(moved.load(Ordering::SeqCst), 1);
    assert_eq!(events.load(ALICE).unwrap().revision(), 1);
    let mut foreign_form = original_form.clone();
    foreign_form.insert("csrf_token".into(), bob_session.record.csrf_token.clone());
    assert_eq!(
        http(
            &app,
            Some(&bob_session),
            "POST",
            "/messages/move",
            &foreign_form
        )
        .response
        .status_code,
        409
    );
    assert_eq!(moved.load(Ordering::SeqCst), 1);
    let page = get(&app, &alice, &refresh_href);
    assert_eq!(page.response.status_code, 200);
    refreshed_inbox_rows(text(&page), 3);
    for row in &targets[1..] {
        permitted
            .lock()
            .unwrap()
            .push_back(literal_move(&userdb, "INBOX", "Deleted", row));
    }
    let move_form =
        rendered_bulk_form(text(&page), "INBOX", &targets[1..], "move", Some("Deleted"));
    let moved_remaining = http(&app, Some(&alice), "POST", "/messages/move", &move_form);
    assert_eq!(moved_remaining.response.status_code, 303);
    assert_return_context(
        stored_content_header(&moved_remaining, "Location"),
        &move_form["return_to"],
        "INBOX",
    );
    assert_eq!(moved.load(Ordering::SeqCst), 3);
    assert!(permitted.lock().unwrap().is_empty());
    assert_eq!(
        native_list.list_messages(ALICE, &inbox).unwrap(),
        vec![neighbour.clone()]
    );
    let archive_page = get(&app, &alice, "/mailbox?name=Archive&sort=subject&dir=asc");
    assert_eq!(archive_page.response.status_code, 200);
    permitted.lock().unwrap().push_back(literal_move(
        &userdb,
        "Archive",
        "Deleted",
        &archived_first,
    ));
    let move_archived = rendered_bulk_form(
        text(&archive_page),
        "Archive",
        std::slice::from_ref(&archived_first),
        "move",
        Some("Deleted"),
    );
    let moved_archived = http(&app, Some(&alice), "POST", "/messages/move", &move_archived);
    assert_eq!(moved_archived.response.status_code, 303);
    assert_return_context(
        stored_content_header(&moved_archived, "Location"),
        &move_archived["return_to"],
        "Archive",
    );
    assert_eq!(moved.load(Ordering::SeqCst), 4);
    assert!(permitted.lock().unwrap().is_empty());
    let deleted_request = MessageListRequest::new(MessageListPolicy::default(), "Deleted").unwrap();
    let mut deleted = native_list.list_messages(ALICE, &deleted_request).unwrap();
    assert_eq!(deleted.len(), 3);
    deleted.sort_by_key(|v| v.uid);
    for row in &deleted {
        let old = targets
            .iter()
            .find(|v| {
                v.metadata.as_ref().unwrap().version.message_guid
                    == row.metadata.as_ref().unwrap().version.message_guid
            })
            .unwrap();
        same_stored_message(row, old);
    }
    let deleted_page = get(&app, &alice, "/mailbox?name=Deleted&sort=subject&dir=asc");
    assert_eq!(deleted_page.response.status_code, 200);
    permitted.lock().unwrap().extend(
        deleted
            .iter()
            .map(|row| literal_move(&userdb, "Deleted", "INBOX", row)),
    );
    let restore = rendered_bulk_form(text(&deleted_page), "Deleted", &deleted, "restore", None);
    let restored_response = http(&app, Some(&alice), "POST", "/messages/move", &restore);
    assert_eq!(restored_response.response.status_code, 303);
    assert_return_context(
        stored_content_header(&restored_response, "Location"),
        &restore["return_to"],
        "Deleted",
    );
    assert_eq!(moved.load(Ordering::SeqCst), 7);
    assert!(permitted.lock().unwrap().is_empty());
    assert!(native_list
        .list_messages(ALICE, &deleted_request)
        .unwrap()
        .is_empty());
    let restored = native_list.list_messages(ALICE, &inbox).unwrap();
    assert_eq!(restored.len(), 4);
    for original in &initial {
        let current = restored
            .iter()
            .find(|row| {
                row.metadata.as_ref().unwrap().version.message_guid
                    == original.metadata.as_ref().unwrap().version.message_guid
            })
            .unwrap();
        same_stored_message(current, original);
        assert_eq!(
            current.metadata.as_ref().unwrap().version,
            original.metadata.as_ref().unwrap().version
        );
        if original.uid == neighbour.uid {
            assert_eq!(current, original);
        }
    }
    assert_eq!(
        http(&app, Some(&alice), "POST", "/messages/move", &restore)
            .response
            .status_code,
        409
    );
    assert_eq!(moved.load(Ordering::SeqCst), 7);
    let refreshed = get(&app, &alice, &refresh_href);
    assert_eq!(refreshed.response.status_code, 200);
    refreshed_inbox_rows(text(&refreshed), 4);
    assert_eq!(native_list.list_messages(ALICE, &archive).unwrap(), legacy);
    assert_eq!(native_list.list_messages(BOB, &inbox).unwrap(), foreign);
    assert!(native_list.list_messages(BOB, &archive).unwrap().is_empty());
    assert!(native_list
        .list_messages(BOB, &deleted_request)
        .unwrap()
        .is_empty());
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ""), initial_wire);
    assert_eq!(
        scoped_delete_wire_bytes(&root, "alice", ".Archive"),
        legacy_wire
    );
    assert_eq!(scoped_delete_wire_bytes(&root, "bob", ""), foreign_wire);
    assert_eq!(events.load(BOB).unwrap().revision(), 0);
    assert_eq!(events.load(ALICE).unwrap().revision(), 1);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_reversible_bulk_moves=PASS actual_browser_runtime_helper_dovecot=PASS rendered_selection_three=PASS archive_first_confirmed_second_stale_third_unattempted=PASS destination_guid_archive_event=PASS replay_no_repeated_move=PASS bulk_move_and_three_restore=PASS neighbour_foreign_bytes_flags_guids_unchanged=PASS no_expunge_append_flag_send_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
