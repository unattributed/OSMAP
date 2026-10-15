use super::*;
pub(super) fn metadata_through_helper<B: MailboxBackend + Send + 'static>(
    root: &Path,
    backend: B,
    account: &str,
) -> Result<crate::folder_metadata::FolderSnapshot, MailboxBackendError> {
    let socket = root.join("status.sock");
    let key_path = root.join("fixture-grant.key");
    let socket_for_thread = socket.clone();
    let server = thread::spawn(move || {
        let unused = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "fixture-unused",
                reason: "unused".into(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let listener = UnixListener::bind(socket_for_thread).expect("isolated socket");
        listener
            .set_nonblocking(true)
            .expect("bounded fixture accept");
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("fixture accept failed: {error}"),
            }
        };
        handle_helper_client(
            HelperBackends {
                mailbox_backend: &backend,
                message_list_backend: &unused,
                message_search_backend: &unused,
                message_view_backend: &unused,
                message_move_backend: &unused,
                message_append_backend: &unused,
                message_flag_backend: &unused,
            },
            &Logger::new(crate::config::LogFormat::Text, LogLevel::Info),
            &mut stream,
            MailboxHelperPolicy::default(),
            MailboxHelperTrustedCallerPolicy {
                trusted_peer_uid: test_runtime_uid(),
                grant_key: test_helper_grant_key(),
            },
            &Mutex::new(BTreeMap::new()),
        );
    });
    wait_for_socket(&socket);
    let result =
        MailboxHelperMailboxListBackend::new(&socket, &key_path, MailboxHelperPolicy::default())
            .folder_metadata(account);
    server.join().expect("native helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}
const TRANSCRIPT:&[u8]=b"* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\HasNoChildren) \".\" INBOX\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n";
#[test]
fn folder_metadata_signed_grant_wire_and_socket() {
    let mut request = MailboxHelperRequest::FolderMetadata {
        canonical_username: "alice@fixture.test".into(),
        grant: MailboxHelperGrant::unsigned(),
    };
    issue_request_grant_with_nonce(
        &mut request,
        &test_helper_grant_key(),
        100,
        &test_grant_nonce(7),
    )
    .unwrap();
    let wire = encode_request(&request);
    assert_eq!(parse_request(&wire).unwrap(), request);
    verify_request_grant(&request, &test_helper_grant_key(), 101).unwrap();
    let changed = wire.replace("YWxpY2VAZml4dHVyZS50ZXN0", "Ym9iQGZpeHR1cmUudGVzdA==");
    assert!(verify_request_grant(
        &parse_request(&changed).unwrap(),
        &test_helper_grant_key(),
        101
    )
    .is_err());
    assert!(verify_request_grant(
        &parse_request(&wire.replace("folder_metadata", "mailbox_list")).unwrap(),
        &test_helper_grant_key(),
        101
    )
    .is_err());
    assert!(parse_request(&(wire.clone() + "command_b64=QQ==\n")).is_err());
    assert!(verify_request_grant(&request, &test_helper_grant_key(), 161).is_err());
    struct Backend(bool);
    impl MailboxBackend for Backend {
        fn list_mailboxes(&self, _: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            panic!("wrong operation")
        }
        fn folder_metadata(
            &self,
            account: &str,
        ) -> Result<crate::folder_metadata::FolderSnapshot, MailboxBackendError> {
            assert_eq!(account, "alice@fixture.test");
            crate::folder_metadata::FolderSnapshot::parse(
                if self.0 { "bob@fixture.test" } else { account },
                TRANSCRIPT,
            )
            .map_err(|_| crate::folder_metadata_backend::unavailable())
        }
    }
    let root = env::temp_dir().join(format!(
        "osmap-folder-metadata-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        metadata_through_helper(&root, Backend(false), "alice@fixture.test")
            .unwrap()
            .validate_for("alice@fixture.test")
            .is_ok()
    );
    assert!(metadata_through_helper(&root, Backend(true), "alice@fixture.test").is_err());
    let client = MailboxHelperMailboxListBackend::new(
        root.join("missing.sock"),
        key,
        MailboxHelperPolicy::default(),
    );
    assert!(client.folder_metadata("alice@fixture.test").is_err());
    fs::remove_dir_all(root).unwrap();
}

pub(super) fn facts_through_helper<B: MailboxBackend + Send + 'static>(
    root: &Path,
    backend: B,
    account: &str,
    names: &[String],
) -> Result<crate::mailbox_status::FolderFacts, MailboxBackendError> {
    let socket = root.join("status.sock");
    let key_path = root.join("fixture-grant.key");
    let socket_for_thread = socket.clone();
    let server = thread::spawn(move || {
        let unused = StaticHelperBackend {
            mailbox_result: Arc::new(Ok(Vec::new())),
            message_list_result: Arc::new(Ok(Vec::new())),
            message_search_result: Arc::new(Ok(Vec::new())),
            message_view_result: Arc::new(Err(MailboxBackendError {
                backend: "fixture-unused",
                reason: "unused".into(),
            })),
            message_move_result: Arc::new(Ok(())),
        };
        let listener = UnixListener::bind(socket_for_thread).expect("isolated socket");
        listener
            .set_nonblocking(true)
            .expect("bounded fixture accept");
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("fixture accept failed: {error}"),
            }
        };
        handle_helper_client(
            HelperBackends {
                mailbox_backend: &backend,
                message_list_backend: &unused,
                message_search_backend: &unused,
                message_view_backend: &unused,
                message_move_backend: &unused,
                message_append_backend: &unused,
                message_flag_backend: &unused,
            },
            &Logger::new(crate::config::LogFormat::Text, LogLevel::Info),
            &mut stream,
            MailboxHelperPolicy::default(),
            MailboxHelperTrustedCallerPolicy {
                trusted_peer_uid: test_runtime_uid(),
                grant_key: test_helper_grant_key(),
            },
            &Mutex::new(BTreeMap::new()),
        );
    });
    wait_for_socket(&socket);
    let client = MailboxHelperMailboxListBackend::new(&socket, &key_path, MailboxHelperPolicy::default()).with_helper_uid(Some(test_runtime_uid()));
    let result = MailboxBackend::folder_facts(&client, account, names);
    server.join().expect("native helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}
#[test]
fn folder_facts_signed_single_exchange_and_account_name_reply_bounds() {
    const ACCOUNT: &str = "alice@fixture.test";
    let names = vec!["INBOX".into()];
    let mut request = MailboxHelperRequest::FolderFacts {canonical_username: ACCOUNT.into(), mailbox_names: names.clone(), grant: MailboxHelperGrant::unsigned()};
    issue_request_grant_with_nonce(&mut request, &test_helper_grant_key(), 100, &test_grant_nonce(8)).unwrap();
    let wire = encode_request(&request);
    assert_eq!(parse_request(&wire).unwrap(), request);
    verify_request_grant(&request, &test_helper_grant_key(), 101).unwrap();
    for changed in [
        wire.replace("YWxpY2VAZml4dHVyZS50ZXN0", "Ym9iQGZpeHR1cmUudGVzdA=="),
        wire.replace("WyJJTkJPWCJd", "WyJUcmFzaCJd"),
        wire.replace("folder_facts", "folder_metadata"),
    ] {
        assert!(parse_request(&changed).and_then(|value| verify_request_grant(&value, &test_helper_grant_key(), 101)).is_err());
    }
    assert!(parse_request(&(wire.clone() + "command_b64=QQ==\n")).is_err());
    let snapshot = crate::folder_metadata::FolderSnapshot::parse(ACCOUNT, TRANSCRIPT).unwrap();
    let status = crate::mailbox_status::MailboxStatus::new("INBOX", &"a".repeat(32), 0, 0).unwrap();
    let facts = crate::mailbox_status::FolderFacts::new(ACCOUNT, &names, snapshot.clone(), vec![status.clone()]).unwrap();
    let response = MailboxHelperResponse::FolderFactsOk {facts: Box::new(facts.clone()), nonce: test_grant_nonce(8)};
    let text = encode_response(&response);
    let parse = |text: &str| parse_response(MailboxListingPolicy::default(), MessageListPolicy::default(), MessageSearchPolicy::default(), MessageViewPolicy::default(), text);
    assert_eq!(parse(&text).unwrap(), response);
    assert!(parse(&(text.clone() + "nonce=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")).is_err());
    assert!(facts.validate_for("bob@fixture.test", &names).is_err());
    assert!(facts.validate_for(ACCOUNT, &["Trash".into()]).is_err());
    assert!(crate::mailbox_status::FolderFacts::new(ACCOUNT, &names, snapshot.clone(), vec![]).is_err());
    assert!(crate::mailbox_status::FolderFacts::new(ACCOUNT, &names, snapshot.clone(), vec![status.clone(), status.clone()]).is_err());
    assert!(crate::mailbox_status::validate_fact_names(ACCOUNT, &["INBOX".into(), "INBOX".into()]).is_err());
    assert!(crate::mailbox_status::validate_fact_names(ACCOUNT, &["INBOX.*".into()]).is_err());
    assert!(crate::mailbox_status::validate_fact_names(ACCOUNT, &(0..12).map(|i| format!("INBOX.X{i}")).collect::<Vec<_>>()).is_err());
    struct Backend(Arc<std::sync::atomic::AtomicUsize>);
    impl MailboxBackend for Backend {
        fn list_mailboxes(&self, _: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {panic!("wrong operation")}
        fn folder_facts(&self, account: &str, names: &[String]) -> Result<crate::mailbox_status::FolderFacts, MailboxBackendError> {
            assert_eq!(account, "alice@fixture.test");
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let snapshot = crate::folder_metadata::FolderSnapshot::parse(account, TRANSCRIPT).unwrap();
            crate::mailbox_status::FolderFacts::new(account, names, snapshot, vec![crate::mailbox_status::MailboxStatus::new("INBOX", &"a".repeat(32), 0, 0).unwrap()])
        }
    }
    let root = env::temp_dir().join(format!("osmap-folder-facts-{}", crate::draft::generate_draft_id().unwrap()));
    fs::create_dir(&root).unwrap();
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = facts_through_helper(&root, Backend(Arc::clone(&calls)), ACCOUNT, &names).unwrap();
    assert_eq!(observed, facts);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}
