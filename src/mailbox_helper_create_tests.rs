use super::*;
pub(super) fn create_through_helper<B: MailboxBackend + Send + 'static>(
    root: &Path,
    backend: B,
    request: &crate::folder_create::CreateFolderRequest,
) -> crate::folder_create::Outcome {
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
            .create_folder(request);
    server.join().expect("native helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}
#[test]
fn folder_create_grant_response_and_foreign_binding() {
    let value = crate::folder_create::CreateFolderRequest::new(
        "alice@fixture.test",
        "INBOX",
        &"a".repeat(32),
        "Child",
    )
    .unwrap();
    let mut request = MailboxHelperRequest::FolderCreate {
        request: value.clone(),
        grant: MailboxHelperGrant::unsigned(),
    };
    issue_request_grant_with_nonce(
        &mut request,
        &test_helper_grant_key(),
        100,
        &test_grant_nonce(9),
    )
    .unwrap();
    let wire = encode_request(&request);
    assert_eq!(parse_request(&wire).unwrap(), request);
    verify_request_grant(&request, &test_helper_grant_key(), 101).unwrap();
    if let MailboxHelperRequest::FolderCreate {
        request: ref mut v, ..
    } = request
    {
        *v = crate::folder_create::CreateFolderRequest::new(
            "alice@fixture.test",
            "INBOX",
            &"a".repeat(32),
            "Different",
        )
        .unwrap();
    }
    assert!(verify_request_grant(&request, &test_helper_grant_key(), 101).is_err());
    assert!(parse_request(&(wire + "command_b64=QQ==\n")).is_err());
    let response = MailboxHelperResponse::FolderCreateOk {
        request: value.clone(),
        outcome: crate::folder_create::Outcome::Created {
            guid: "b".repeat(32),
        },
    };
    assert_eq!(
        parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &encode_response(&response)
        )
        .unwrap(),
        response
    );
    let foreign_request = crate::folder_create::CreateFolderRequest::new(
        "bob@fixture.test",
        "INBOX",
        &"a".repeat(32),
        "Child",
    )
    .unwrap();
    assert!(!value.accepts_response(
        &foreign_request,
        &crate::folder_create::Outcome::Created {
            guid: "b".repeat(32)
        }
    ));
    for guid in ["a".repeat(32), "bad".into()] {
        let bad = MailboxHelperResponse::FolderCreateOk {
            request: value.clone(),
            outcome: crate::folder_create::Outcome::Created { guid },
        };
        assert!(parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &encode_response(&bad)
        )
        .is_err());
    }
    let transcript=b"* PREAUTH ready\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST (\\HasChildren) \".\" INBOX\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n";
    let foreign =
        crate::folder_metadata::FolderSnapshot::parse("bob@fixture.test", transcript).unwrap();
    let status = crate::mailbox_status::MailboxStatus::new("INBOX", &"a".repeat(32), 0, 0).unwrap();
    assert_eq!(
        value.validate_parent(&foreign, &status),
        Err(crate::folder_create::Refusal::Unavailable)
    );
}
