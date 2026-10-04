use crate::mailbox::{
    MessageDeleteBackend, MessageDeleteError as E, MessageDeleteRequest, MessageDeleteResult,
    RetentionDecision as D,
};
use crate::message_metadata::MessageVersion;

const DELETE_ACCOUNT: &str = "alice@example.test";
const DELETE_FOLDER: &str = "Deleted";

fn delete_request() -> MessageDeleteRequest {
    MessageDeleteRequest::new(
        DELETE_ACCOUNT,
        DELETE_FOLDER,
        7,
        MessageVersion::new("a".repeat(32), "public-message-7".into()).unwrap(),
        9,
    )
    .unwrap()
}
fn delete_wire() -> MailboxHelperRequest {
    MailboxHelperRequest::MessageDelete {
        request: delete_request(),
        grant: MailboxHelperGrant::unsigned(),
    }
}
fn status_wire() -> MailboxHelperRequest {
    MailboxHelperRequest::RetentionStatus {
        canonical_username: DELETE_ACCOUNT.into(),
        mailbox_name: DELETE_FOLDER.into(),
        grant: MailboxHelperGrant::unsigned(),
    }
}
fn signed(mut request: MailboxHelperRequest, seed: u8) -> MailboxHelperRequest {
    issue_request_grant_with_nonce(
        &mut request,
        &test_helper_grant_key(),
        current_unix_time_secs().unwrap(),
        &test_grant_nonce(seed),
    )
    .unwrap();
    request
}
fn decode_reply(bytes: &[u8]) -> Result<MailboxHelperResponse, String> {
    parse_response(
        MailboxListingPolicy::default(),
        MessageListPolicy::default(),
        MessageSearchPolicy::default(),
        MessageViewPolicy::default(),
        std::str::from_utf8(bytes).map_err(|_| "not utf8".to_string())?,
    )
}
fn reply_for(
    request: &MailboxHelperRequest,
    result: Result<MessageDeleteResult, E>,
) -> MailboxHelperResponse {
    match request {
        MailboxHelperRequest::MessageDelete {
            request: target,
            grant,
        } => MailboxHelperResponse::MessageDelete {
            request: Box::new(target.clone()),
            result,
            nonce: grant.nonce.clone(),
        },
        MailboxHelperRequest::RetentionStatus {
            canonical_username,
            mailbox_name,
            grant,
        } => MailboxHelperResponse::RetentionStatus {
            canonical_username: canonical_username.clone(),
            mailbox_name: mailbox_name.clone(),
            decision: D::Allowed { revision: 9 },
            nonce: grant.nonce.clone(),
        },
        _ => panic!("fixture accepts only deletion/status operations"),
    }
}

#[derive(Clone)]
struct DeleteStub {
    calls: Arc<Mutex<Vec<MessageDeleteRequest>>>,
    statuses: Arc<AtomicUsize>,
    decision: D,
    result: Result<MessageDeleteResult, E>,
}
impl DeleteStub {
    fn allowed() -> Self {
        Self {
            calls: Arc::new(Mutex::new(vec![])),
            statuses: Arc::new(AtomicUsize::new(0)),
            decision: D::Allowed { revision: 9 },
            result: Ok(MessageDeleteResult::Deleted),
        }
    }
}
impl MessageDeleteBackend for DeleteStub {
    fn retention_status(&self, account: &str, mailbox: &str) -> D {
        assert_eq!((account, mailbox), (DELETE_ACCOUNT, DELETE_FOLDER));
        self.statuses.fetch_add(1, Ordering::SeqCst);
        self.decision
    }
    fn delete_message(
        &self,
        account: &str,
        request: &MessageDeleteRequest,
    ) -> Result<MessageDeleteResult, E> {
        assert_eq!(account, DELETE_ACCOUNT);
        assert_eq!(request, &delete_request());
        self.calls.lock().unwrap().push(request.clone());
        self.result
    }
}

// Bind before returning and bound every accept/read. Drop joins before removing paths.
// A panic therefore cannot detach a service that still uses fixture-owned files.
struct DeleteSocketFixture {
    socket: PathBuf,
    key: PathBuf,
    handle: Option<thread::JoinHandle<()>>,
}
impl DeleteSocketFixture {
    fn spawn(count: usize, mut handler: impl FnMut(&mut UnixStream) + Send + 'static) -> Self {
        let socket = temp_socket_path("delete-helper-qa");
        let key = temp_grant_key_path("delete-helper-qa");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..count {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("bounded fixture accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                handler(&mut stream);
            }
        });
        Self {
            socket,
            key,
            handle: Some(handle),
        }
    }
    fn service(count: usize, stub: Option<DeleteStub>, trusted_uid: u32) -> Self {
        let replay = Mutex::new(BTreeMap::new());
        let backend = helper_test_backends();
        Self::spawn(count, move |stream| {
            let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Info);
            handle_helper_client_with_delete(
                HelperBackends {
                    mailbox_backend: &backend,
                    message_list_backend: &backend,
                    message_search_backend: &backend,
                    message_view_backend: &backend,
                    message_move_backend: &backend,
                    message_append_backend: &backend,
                    message_flag_backend: &backend,
                },
                stub.as_ref().map(|s| s as &dyn MessageDeleteBackend),
                &logger,
                stream,
                MailboxHelperPolicy {
                    read_timeout_secs: 1,
                    write_timeout_secs: 1,
                    ..MailboxHelperPolicy::default()
                },
                MailboxHelperTrustedCallerPolicy {
                    trusted_peer_uid: trusted_uid,
                    grant_key: test_helper_grant_key(),
                },
                &replay,
            );
        })
    }
    fn client(&self) -> MailboxHelperMessageDeleteBackend {
        MailboxHelperMessageDeleteBackend::new(
            &self.socket,
            &self.key,
            MailboxHelperPolicy {
                read_timeout_secs: 1,
                write_timeout_secs: 1,
                ..MailboxHelperPolicy::default()
            },
        )
        .with_helper_uid(crate::openbsd::effective_uid())
    }
    fn raw(&self, request: &str) -> MailboxHelperResponse {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes).unwrap();
        decode_reply(&bytes).unwrap()
    }
    fn finish(mut self) {
        self.handle
            .take()
            .unwrap()
            .join()
            .expect("fixture service should complete");
    }
}
impl Drop for DeleteSocketFixture {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.key);
    }
}
fn receive_request(stream: &mut UnixStream) -> MailboxHelperRequest {
    let mut bytes = vec![];
    stream.read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() <= 4096);
    parse_request(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

#[test]
fn delete_codec_round_trips_all_finite_outcomes_and_retention_decisions() {
    for request in [signed(delete_wire(), 1), signed(status_wire(), 2)] {
        assert_eq!(parse_request(&encode_request(&request)).unwrap(), request);
    }
    for result in [
        Ok(MessageDeleteResult::Deleted),
        Err(E::Invalid),
        Err(E::Stale),
        Err(E::PolicyDenied),
        Err(E::PolicyUnavailable),
        Err(E::Busy),
        Err(E::Unavailable),
        Err(E::Unknown),
    ] {
        let response = reply_for(&signed(delete_wire(), 3), result);
        assert_eq!(
            decode_reply(encode_response(&response).as_bytes()).unwrap(),
            response
        );
    }
    for decision in [D::Allowed { revision: u64::MAX }, D::Denied, D::Unavailable] {
        let response = MailboxHelperResponse::RetentionStatus {
            canonical_username: DELETE_ACCOUNT.into(),
            mailbox_name: DELETE_FOLDER.into(),
            decision,
            nonce: test_grant_nonce(4),
        };
        assert_eq!(
            decode_reply(encode_response(&response).as_bytes()).unwrap(),
            response
        );
    }
}
#[test]
fn delete_codec_refuses_duplicate_extra_mixed_incomplete_and_noncanonical_fields() {
    let request = encode_request(&signed(delete_wire(), 5));
    for bad in [
        format!("{request}policy_revision=9\n"),
        format!("{request}extra=1\n"),
        request.replace("delete_uid=7", "delete_uid=07"),
        request.replace("policy_revision=9", "policy_revision=0"),
        request.replace("delete_mailbox_guid=", "absent_mailbox_guid="),
        request.replace("operation=message_delete", "operation=retention_status"),
        format!("{request}{}", "x".repeat(4096)),
    ] {
        assert!(parse_request(&bad).is_err());
    }
    let response = encode_response(&reply_for(
        &signed(delete_wire(), 6),
        Ok(MessageDeleteResult::Deleted),
    ));
    for bad in [
        format!("{response}delete_result=deleted\n"),
        format!("{response}extra=1\n"),
        response.replace("delete_uid=7", "delete_uid=07"),
        response.replace("delete_result=deleted", "delete_result=success"),
        response.replace("request_nonce=", "missing_nonce="),
        response.replace("operation=message_delete", "operation=retention_status"),
        format!("{response}{}", "x".repeat(4096)),
    ] {
        assert!(decode_reply(bad.as_bytes()).is_err());
    }
    let status = encode_response(&reply_for(
        &signed(status_wire(), 7),
        Ok(MessageDeleteResult::Deleted),
    ));
    for bad in [
        status.replace("policy_revision=9", "policy_revision=0"),
        status.replace("retention_state=allowed", "retention_state=denied"),
        status.replace("request_nonce=", "request_nonce=Z"),
    ] {
        assert!(decode_reply(bad.as_bytes()).is_err());
    }
}
#[test]
fn delete_grant_covers_every_target_policy_field_and_operation() {
    let original = signed(delete_wire(), 8);
    let now = current_unix_time_secs().unwrap();
    assert!(verify_request_grant(&original, &test_helper_grant_key(), now).is_ok());
    for field in 0..6 {
        let mut altered = original.clone();
        if let MailboxHelperRequest::MessageDelete { request, .. } = &mut altered {
            match field {
                0 => request.canonical_username = "bob@example.test".into(),
                1 => request.mailbox_name = "Trash".into(),
                2 => request.uid += 1,
                3 => request.version.mailbox_guid = "b".repeat(32),
                4 => request.version.message_guid = "public-other".into(),
                _ => request.policy_revision += 1,
            }
        }
        assert!(
            verify_request_grant(&altered, &test_helper_grant_key(), now).is_err(),
            "field {field} must be covered"
        );
    }
    let altered = MailboxHelperRequest::RetentionStatus {
        canonical_username: DELETE_ACCOUNT.into(),
        mailbox_name: DELETE_FOLDER.into(),
        grant: request_grant(&original).clone(),
    };
    assert!(verify_request_grant(&altered, &test_helper_grant_key(), now).is_err());
    let status = signed(status_wire(), 9);
    for field in 0..2 {
        let mut altered = status.clone();
        if let MailboxHelperRequest::RetentionStatus {
            canonical_username,
            mailbox_name,
            ..
        } = &mut altered
        {
            if field == 0 {
                *canonical_username = "bob@example.test".into();
            } else {
                *mailbox_name = "Trash".into();
            }
        }
        assert!(verify_request_grant(&altered, &test_helper_grant_key(), now).is_err());
    }
}
#[test]
fn delete_actual_authenticated_socket_delivers_exact_tuple_and_decisions() {
    let stub = DeleteStub::allowed();
    let fixture =
        DeleteSocketFixture::service(2, Some(stub.clone()), crate::openbsd::effective_uid());
    assert_eq!(
        fixture
            .client()
            .retention_status(DELETE_ACCOUNT, DELETE_FOLDER),
        D::Allowed { revision: 9 }
    );
    assert_eq!(
        fixture
            .client()
            .delete_message(DELETE_ACCOUNT, &delete_request()),
        Ok(MessageDeleteResult::Deleted)
    );
    fixture.finish();
    assert_eq!(*stub.calls.lock().unwrap(), vec![delete_request()]);
    assert_eq!(stub.statuses.load(Ordering::SeqCst), 1);
}
#[test]
fn delete_actual_socket_preserves_every_typed_failure_without_retry() {
    for error in [
        E::Invalid,
        E::Stale,
        E::PolicyDenied,
        E::PolicyUnavailable,
        E::Busy,
        E::Unavailable,
        E::Unknown,
    ] {
        let mut stub = DeleteStub::allowed();
        stub.result = Err(error);
        let fixture =
            DeleteSocketFixture::service(1, Some(stub.clone()), crate::openbsd::effective_uid());
        assert_eq!(
            fixture
                .client()
                .delete_message(DELETE_ACCOUNT, &delete_request()),
            Err(error)
        );
        fixture.finish();
        assert_eq!(stub.calls.lock().unwrap().len(), 1);
    }
}
#[test]
fn delete_unconfigured_backend_never_acquires_implicit_permission() {
    let fixture = DeleteSocketFixture::service(2, None, crate::openbsd::effective_uid());
    assert_eq!(
        fixture
            .client()
            .retention_status(DELETE_ACCOUNT, DELETE_FOLDER),
        D::Unavailable
    );
    assert_eq!(
        fixture
            .client()
            .delete_message(DELETE_ACCOUNT, &delete_request()),
        Err(E::PolicyUnavailable)
    );
    fixture.finish();
}
#[test]
fn delete_signed_socket_replay_and_target_tampering_do_not_reach_backend() {
    let stub = DeleteStub::allowed();
    let fixture =
        DeleteSocketFixture::service(3, Some(stub.clone()), crate::openbsd::effective_uid());
    let original = signed(delete_wire(), 10);
    assert!(matches!(
        fixture.raw(&encode_request(&original)),
        MailboxHelperResponse::MessageDelete {
            result: Ok(MessageDeleteResult::Deleted),
            ..
        }
    ));
    assert!(matches!(
        fixture.raw(&encode_request(&original)),
        MailboxHelperResponse::Error { .. }
    ));
    let mut altered = signed(delete_wire(), 11);
    if let MailboxHelperRequest::MessageDelete { request, .. } = &mut altered {
        request.policy_revision += 1;
    }
    assert!(matches!(
        fixture.raw(&encode_request(&altered)),
        MailboxHelperResponse::Error { .. }
    ));
    fixture.finish();
    assert_eq!(stub.calls.lock().unwrap().len(), 1);
}
#[test]
fn delete_server_refuses_wrong_caller_uid_before_backend_admission() {
    let stub = DeleteStub::allowed();
    let fixture = DeleteSocketFixture::service(
        1,
        Some(stub.clone()),
        crate::openbsd::effective_uid().wrapping_add(1),
    );
    assert_eq!(
        fixture
            .client()
            .delete_message(DELETE_ACCOUNT, &delete_request()),
        Err(E::Unknown)
    );
    fixture.finish();
    assert!(stub.calls.lock().unwrap().is_empty());
    assert_eq!(stub.statuses.load(Ordering::SeqCst), 0);
}
#[test]
fn delete_client_requires_configured_peer_identity_and_checks_it_before_writing() {
    let missing = temp_socket_path("delete-no-listener");
    let key = temp_grant_key_path("delete-no-listener");
    let client =
        MailboxHelperMessageDeleteBackend::new(&missing, &key, MailboxHelperPolicy::default());
    assert_eq!(
        client.delete_message(DELETE_ACCOUNT, &delete_request()),
        Err(E::Unavailable)
    );
    assert_eq!(
        client.retention_status(DELETE_ACCOUNT, DELETE_FOLDER),
        D::Unavailable
    );
    fs::remove_file(key).unwrap();
    let fixture = DeleteSocketFixture::spawn(1, |stream| {
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes).unwrap();
        assert!(
            bytes.is_empty(),
            "wrong helper peer must receive zero request bytes"
        );
    });
    let client = fixture
        .client()
        .with_helper_uid(crate::openbsd::effective_uid().wrapping_add(1));
    assert_eq!(
        client.delete_message(DELETE_ACCOUNT, &delete_request()),
        Err(E::Unavailable)
    );
    fixture.finish();
}
#[test]
fn delete_client_rejects_foreign_account_before_connecting() {
    let missing = temp_socket_path("delete-foreign-no-listener");
    let client =
        MailboxHelperMessageDeleteBackend::new(&missing, &missing, MailboxHelperPolicy::default())
            .with_helper_uid(crate::openbsd::effective_uid());
    assert_eq!(
        client.delete_message("bob@example.test", &delete_request()),
        Err(E::Invalid)
    );
}
#[test]
fn delete_client_requires_complete_identity_policy_and_nonce_echo() {
    for field in 0..8 {
        let fixture = DeleteSocketFixture::spawn(1, move |stream| {
            let request = receive_request(stream);
            let mut response = reply_for(&request, Ok(MessageDeleteResult::Deleted));
            if let MailboxHelperResponse::MessageDelete { request, nonce, .. } = &mut response {
                match field {
                    0 => request.canonical_username = "bob@example.test".into(),
                    1 => request.mailbox_name = "Trash".into(),
                    2 => request.uid += 1,
                    3 => request.version.mailbox_guid = "b".repeat(32),
                    4 => request.version.message_guid = "public-other".into(),
                    5 => request.policy_revision += 1,
                    6 => *nonce = test_grant_nonce(33),
                    _ => {
                        response =
                            reply_for(&signed(status_wire(), 34), Ok(MessageDeleteResult::Deleted))
                    }
                }
            }
            stream
                .write_all(encode_response(&response).as_bytes())
                .unwrap();
        });
        assert_eq!(
            fixture
                .client()
                .delete_message(DELETE_ACCOUNT, &delete_request()),
            Err(E::Unknown),
            "echo mismatch {field}"
        );
        fixture.finish();
    }
}
#[test]
fn retention_client_refuses_foreign_folder_nonce_and_operation_echo() {
    for field in 0..4 {
        let fixture = DeleteSocketFixture::spawn(1, move |stream| {
            let request = receive_request(stream);
            let mut response = reply_for(&request, Ok(MessageDeleteResult::Deleted));
            if let MailboxHelperResponse::RetentionStatus {
                canonical_username,
                mailbox_name,
                nonce,
                ..
            } = &mut response
            {
                match field {
                    0 => *canonical_username = "bob@example.test".into(),
                    1 => *mailbox_name = "Trash".into(),
                    2 => *nonce = test_grant_nonce(35),
                    _ => {
                        response =
                            reply_for(&signed(delete_wire(), 36), Ok(MessageDeleteResult::Deleted))
                    }
                }
            }
            stream
                .write_all(encode_response(&response).as_bytes())
                .unwrap();
        });
        assert_eq!(
            fixture
                .client()
                .retention_status(DELETE_ACCOUNT, DELETE_FOLDER),
            D::Unavailable
        );
        fixture.finish();
    }
}
#[test]
fn delete_lost_truncated_invalid_and_oversized_replies_are_unknown_not_retried() {
    for mode in 0..5 {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let fixture = DeleteSocketFixture::spawn(1, move |stream| {
            observed.fetch_add(1, Ordering::SeqCst);
            if mode == 0 {
                let mut prefix = [0_u8; 1];
                assert_eq!(stream.read(&mut prefix).unwrap(), 1);
                return;
            }
            let request = receive_request(stream);
            match mode {
                1 => {}
                2 => {
                    let response =
                        encode_response(&reply_for(&request, Ok(MessageDeleteResult::Deleted)));
                    let truncated = response.lines().take(3).collect::<Vec<_>>().join("\n");
                    stream.write_all(truncated.as_bytes()).unwrap();
                }
                3 => {
                    stream.write_all(&[0xff, 0xfe]).unwrap();
                }
                _ => {
                    stream.write_all(&vec![b'x'; 4097]).unwrap();
                }
            }
        });
        assert_eq!(
            fixture
                .client()
                .delete_message(DELETE_ACCOUNT, &delete_request()),
            Err(E::Unknown),
            "transport mode {mode}"
        );
        fixture.finish();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
