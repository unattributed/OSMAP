use super::*;
pub(super) fn rename_through_helper<B: MailboxBackend + Send + 'static>(
    root: &Path,
    backend: B,
    request: &crate::folder_rename::RenameFolderRequest,
    peer: u32,
) -> crate::folder_rename::Outcome {
    with_rename_helper(root, backend, peer, |client| client.rename_folder(request))
}
pub(super) fn with_rename_helper<B: MailboxBackend + Send + 'static, T>(
    root: &Path,
    backend: B,
    peer: u32,
    call: impl FnOnce(MailboxHelperMailboxListBackend) -> T,
) -> T {
    let socket = root.join("status.sock");
    let key_path = root.join("fixture-grant.key");
    let socket_for_thread = socket.clone();
    let trusted_peer_uid = fs::symlink_metadata(&key_path).unwrap().uid();
    let completion_dir = root.join("completion");
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
        handle_helper_client_with_documents_and_rename(
            HelperBackends {
                mailbox_backend: &backend,
                message_list_backend: &unused,
                message_search_backend: &unused,
                message_view_backend: &unused,
                message_move_backend: &unused,
                message_append_backend: &unused,
                message_flag_backend: &unused,
            },
            None,
            None,
            &Logger::new(crate::config::LogFormat::Text, LogLevel::Info),
            &mut stream,
            MailboxHelperPolicy::default(),
            HelperRequestAuthority {
                trusted_caller_policy: MailboxHelperTrustedCallerPolicy {
                    trusted_peer_uid,
                    grant_key: test_helper_grant_key(),
                },
                replay_cache: &Mutex::new(BTreeMap::new()),
                rename_completion_dir: Some(&completion_dir),
            },
        );
    });
    wait_for_socket(&socket);
    let result = call(
        MailboxHelperMailboxListBackend::new(&socket, &key_path, MailboxHelperPolicy::default())
            .with_helper_uid(Some(peer)),
    );
    server.join().expect("local helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}
struct RenameBackend(Arc<std::sync::atomic::AtomicUsize>);
impl MailboxBackend for RenameBackend {
    fn list_mailboxes(&self, _: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        Ok(vec![])
    }
    fn rename_folder(
        &self,
        request: &crate::folder_rename::RenameFolderRequest,
    ) -> crate::folder_rename::Outcome {
        assert_eq!(request.account(), "alice@fixture.test");
        assert_eq!(request.source(), "INBOX.Alpha");
        assert_eq!(request.destination(), "INBOX.Beta");
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::folder_rename::Outcome::Renamed
    }
}
#[test]
fn folder_rename_signed_helper_peer_and_nonce() {
    let root = temp_socket_path("folder-rename-socket").with_extension("root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let value = crate::folder_rename::RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    assert_eq!(
        rename_through_helper(
            &root,
            RenameBackend(writes.clone()),
            &value,
            test_runtime_uid()
        ),
        crate::folder_rename::Outcome::Renamed
    );
    assert_eq!(writes.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        rename_through_helper(
            &root,
            RenameBackend(writes.clone()),
            &value,
            test_runtime_uid().wrapping_add(1)
        ),
        crate::folder_rename::Outcome::Unknown
    );
    assert_eq!(writes.load(std::sync::atomic::Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn folder_rename_grant_exact_account_identity_action_and_closed_fields() {
    let value = crate::folder_rename::RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let mut request = MailboxHelperRequest::FolderRename {
        request: value.clone(),
        grant: MailboxHelperGrant::unsigned(),
    };
    issue_request_grant_with_nonce(
        &mut request,
        &test_helper_grant_key(),
        100,
        value.action_nonce(),
    )
    .unwrap();
    let wire = encode_request(&request);
    assert_eq!(parse_request(&wire).unwrap(), request);
    verify_request_grant(&request, &test_helper_grant_key(), 101).unwrap();
    for (account, source, guid, parent, leaf) in [
        ("bob@fixture.test", "INBOX.Alpha", "a", "b", "Beta"),
        ("alice@fixture.test", "INBOX.Other", "a", "b", "Beta"),
        ("alice@fixture.test", "INBOX.Alpha", "c", "b", "Beta"),
        ("alice@fixture.test", "INBOX.Alpha", "a", "c", "Beta"),
        ("alice@fixture.test", "INBOX.Alpha", "a", "b", "Other"),
    ] {
        let mut changed = request.clone();
        if let MailboxHelperRequest::FolderRename {
            request: ref mut r, ..
        } = changed
        {
            let mut fields = serde_json::to_value(&*r).unwrap();
            fields["account"] = account.into();
            fields["source"] = source.into();
            fields["source_guid"] = guid.repeat(32).into();
            fields["parent_guid"] = parent.repeat(32).into();
            fields["leaf"] = leaf.into();
            *r = serde_json::from_value(fields).unwrap();
        }
        assert!(verify_request_grant(&changed, &test_helper_grant_key(), 101).is_err());
    }
    let mut changed = request.clone();
    if let MailboxHelperRequest::FolderRename { grant, .. } = &mut changed {
        grant.nonce = test_grant_nonce(13);
    }
    assert!(verify_request_grant(&changed, &test_helper_grant_key(), 101).is_err());
    assert!(parse_request(&(wire.clone() + "command_b64=QQ==\n")).is_err());
    assert!(parse_request(&(wire.clone() + "operation=folder_create\n")).is_err());
    let parse = |wire: &str| {
        parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            wire,
        )
    };
    let response = MailboxHelperResponse::FolderRenameOk {
        request: Box::new(value.clone()),
        outcome: crate::folder_rename::Outcome::Renamed,
        nonce: test_grant_nonce(12),
    };
    assert_eq!(parse(&encode_response(&response)).unwrap(), response);
    assert!(parse(&(encode_response(&response) + "extra=x\n")).is_err());
    let foreign = crate::folder_rename::RenameFolderRequest::new(
        "bob@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    assert!(!value.accepts_response(&foreign));
}

#[test]
fn folder_rename_grant_replay_and_action_denied() {
    let value = crate::folder_rename::RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let mut request = MailboxHelperRequest::FolderRename {
        request: value.clone(),
        grant: MailboxHelperGrant::unsigned(),
    };
    issue_request_grant_with_nonce(
        &mut request,
        &test_helper_grant_key(),
        current_unix_time_secs().unwrap(),
        value.action_nonce(),
    )
    .unwrap();
    let cache = Mutex::new(BTreeMap::new());
    verify_helper_request_authority(&request, &test_helper_grant_key(), &cache).unwrap();
    assert!(verify_helper_request_authority(&request, &test_helper_grant_key(), &cache).is_err());
    let action = MailboxHelperRequest::FolderCreate {
        request: crate::folder_create::CreateFolderRequest::new(
            "alice@fixture.test",
            "INBOX",
            &"b".repeat(32),
            "Beta",
        )
        .unwrap(),
        grant: super::super::mailbox_helper_protocol::request_grant(&request).clone(),
    };
    assert!(verify_request_grant(
        &action,
        &test_helper_grant_key(),
        current_unix_time_secs().unwrap()
    )
    .is_err());
}

#[test]
fn folder_rename_settled_refusal_original_nonce_replay_and_uncertainty() {
    use crate::folder_rename::{Completion, Outcome, RenameFolderRequest};
    struct Refused(Arc<std::sync::atomic::AtomicUsize>);
    impl MailboxBackend for Refused {
        fn list_mailboxes(&self, _: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            Ok(vec![])
        }
        fn rename_folder(&self, _: &RenameFolderRequest) -> Outcome {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Outcome::Refused(crate::folder_create::Refusal::Stale)
        }
    }
    let root = temp_socket_path("rename-completion").with_extension("root");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let request = RenameFolderRequest::new(
        "alice@fixture.test",
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Beta",
    )
    .unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Send the genuine signed request, then close without reading the response.
    // The backend's refusal is persisted before the failed socket reply.
    with_rename_helper(&root, Refused(calls.clone()), test_runtime_uid(), |_| {
        let mut action = MailboxHelperRequest::FolderRename {
            request: request.clone(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes =
            super::super::mailbox_helper_client::encode_authorized_request(&key, &mut action)
                .unwrap();
        let mut stream = UnixStream::connect(root.join("status.sock")).unwrap();
        stream.write_all(&bytes).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
    });
    let read = |value: &RenameFolderRequest, peer| {
        with_rename_helper(&root, Refused(calls.clone()), peer, |client| {
            client.folder_rename_completion(value)
        })
    };
    assert_eq!(read(&request, test_runtime_uid()), Completion::NoMutation);
    assert_eq!(
        read(&request, test_runtime_uid().wrapping_add(1)),
        Completion::Unconfirmed
    );
    let changed = RenameFolderRequest::new(
        request.account(),
        request.source(),
        request.source_guid(),
        request.parent_guid(),
        request.leaf(),
    )
    .unwrap();
    assert_ne!(request.action_nonce(), changed.action_nonce());
    assert_eq!(read(&changed, test_runtime_uid()), Completion::Unconfirmed);
    let foreign = RenameFolderRequest::new(
        "bob@fixture.test",
        request.source(),
        request.source_guid(),
        request.parent_guid(),
        request.leaf(),
    )
    .unwrap();
    assert_eq!(read(&foreign, test_runtime_uid()), Completion::Unconfirmed);
    // Even after grant replay cache restart, the same original nonce cannot redispatch.
    assert_eq!(
        rename_through_helper(&root, Refused(calls.clone()), &request, test_runtime_uid()),
        Outcome::Refused(crate::folder_create::Refusal::Stale)
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let file = crate::private_account_file::PrivateAccountFile::new(
        root.join("completion"),
        "osmap-folder-rename-helper-v1",
        4096,
    )
    .lock(request.account())
    .unwrap();
    let record = |outcome| {
        serde_json::to_vec(&serde_json::json!({"version":1,"request":request,"outcome":outcome}))
            .unwrap()
    };
    file.write(&record(serde_json::Value::Null)).unwrap();
    assert_eq!(
        super::super::mailbox_helper_rename::completion(&root.join("completion"), &request),
        Completion::Unconfirmed
    );
    drop(file);
    assert_eq!(read(&request, test_runtime_uid()), Completion::Unconfirmed);
    assert_eq!(
        rename_through_helper(&root, Refused(calls.clone()), &request, test_runtime_uid()),
        Outcome::Unknown
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let file = crate::private_account_file::PrivateAccountFile::new(
        root.join("completion"),
        "osmap-folder-rename-helper-v1",
        4096,
    )
    .lock(request.account())
    .unwrap();
    file.write(&record(serde_json::json!(Outcome::Unknown)))
        .unwrap();
    drop(file);
    assert_eq!(read(&request, test_runtime_uid()), Completion::Unconfirmed);
    let file = crate::private_account_file::PrivateAccountFile::new(
        root.join("completion"),
        "osmap-folder-rename-helper-v1",
        4096,
    )
    .lock(request.account())
    .unwrap();
    file.write(b"{broken").unwrap();
    drop(file);
    assert_eq!(read(&request, test_runtime_uid()), Completion::Unconfirmed);
    assert_eq!(
        rename_through_helper(&root, Refused(calls.clone()), &request, test_runtime_uid()),
        Outcome::Refused(crate::folder_create::Refusal::Unavailable)
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}
