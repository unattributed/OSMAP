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
