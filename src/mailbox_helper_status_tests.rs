use super::*;
pub(super) fn status_through_helper<B: MailboxBackend + Send + 'static>(
    root: &Path,
    backend: B,
    folder: &str,
) -> Result<crate::mailbox_status::MailboxStatus, MailboxBackendError> {
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
        let (mut stream, _) = listener.accept().expect("accept fixture connection");
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
            .mailbox_status("osmap-native-fixture@example.test", folder);
    server.join().expect("native helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}

#[test]
fn mailbox_status_grant_and_protocol_binding() {
 let mut req=MailboxHelperRequest::MailboxStatus {canonical_username:"alice@example.test".into(),mailbox_name:"INBOX".into(),grant:MailboxHelperGrant::unsigned()};
 issue_request_grant_with_nonce(&mut req,&test_helper_grant_key(),100,&test_grant_nonce(1)).unwrap();
 let text=encode_request(&req);assert_eq!(parse_request(&text).unwrap(),req);
 verify_request_grant(&req,&test_helper_grant_key(),101).unwrap();
 for altered in [text.replace("operation=mailbox_status","operation=message_list"),text.replace("SU5CT1g=","U2VudA=="),text.replace("YWxpY2VAZXhhbXBsZS50ZXN0","Ym9iQGV4YW1wbGUudGVzdA==")] {let parsed=parse_request(&altered).unwrap();assert!(verify_request_grant(&parsed,&test_helper_grant_key(),101).is_err());}
 assert!(verify_request_grant(&req,&test_helper_grant_key(),161).is_err());
 let status=crate::mailbox_status::MailboxStatus::new("INBOX","a123456789abcdef123456789abcdef0",42,8192).unwrap();
 let text=encode_response(&MailboxHelperResponse::MailboxStatusOk {status:status.clone()});
 let parse=|s:&str|parse_response(MailboxListingPolicy::default(),MessageListPolicy::default(),MessageSearchPolicy::default(),MessageViewPolicy::default(),s);
 assert_eq!(parse(&text).unwrap(),MailboxHelperResponse::MailboxStatusOk {status});
 for bad in [format!("{text}status_messages=1\n"),text.replace("status_vsize=8192","status_vsize=-1"),format!("{text}unexpected=1\n")] {assert!(parse(&bad).is_err());}
}
#[test]
fn mailbox_status_signed_socket_roundtrip() {
 struct Backend;
 impl MailboxBackend for Backend {
  fn list_mailboxes(&self,_:&str)->Result<Vec<MailboxEntry>,MailboxBackendError>{panic!("wrong operation")}
  fn mailbox_status(&self,account:&str,folder:&str)->Result<crate::mailbox_status::MailboxStatus,MailboxBackendError>{assert_eq!(account,"osmap-native-fixture@example.test");crate::mailbox_status::MailboxStatus::new(folder,"a123456789abcdef123456789abcdef0",42,8192)}
 }
 let root=env::temp_dir().join(format!("osmap-status-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
 fs::create_dir(&root).unwrap();let key=root.join("fixture-grant.key");fs::write(&key,test_helper_grant_key()).unwrap();fs::set_permissions(&key,fs::Permissions::from_mode(0o600)).unwrap();
 assert_eq!(status_through_helper(&root,Backend,"INBOX").unwrap().messages(),42);fs::remove_dir_all(root).unwrap();
}
