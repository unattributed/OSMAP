// Explicit native qualification with a new owner-private disposable Maildir.
// No live configuration, daemon, userdb, real account or external delivery.
use super::*;
use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
use crate::message_metadata::MessageFlag;
use std::os::unix::fs::DirBuilderExt as _;

const FIXTURE_ACCOUNT: &str = "osmap-native-fixture@example.test";

#[derive(Clone)]
struct IsolatedDoveadm {
    config: PathBuf,
    os_username: String,
}

impl CommandExecutor for IsolatedDoveadm {
    fn run_with_stdin_bytes(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout(program, args, input, Duration::from_secs(3))
    }

    fn run_with_stdin_bytes_timeout(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, "/usr/local/bin/doveadm");
        // The production executor clears inherited environment. Standalone
        // doveadm needs only the verified current OS username, not live userdb.
        let mut isolated = vec![
            format!("USER={}", self.os_username),
            program.into(),
            "-c".into(),
            self.config.to_string_lossy().into_owned(),
        ];
        let mut index = 0;
        while index < args.len() {
            if args[index] == "-u" {
                assert_eq!(
                    args.get(index + 1).map(String::as_str),
                    Some(FIXTURE_ACCOUNT)
                );
                index += 2; // Only this fixture account maps to the current OS user.
            } else {
                assert!(!matches!(args[index].as_str(), "-c" | "-A" | "-F"));
                isolated.push(args[index].clone());
                index += 1;
            }
        }
        SystemCommandExecutor.run_with_stdin_bytes_timeout(
            "/usr/bin/env",
            &isolated,
            input,
            timeout,
        )
    }
}

fn through_helper(
    root: &Path,
    backend: DoveadmMessageFlagBackend<IsolatedDoveadm>,
    request: &MessageFlagRequest,
) -> Result<MessageFlagResult, MailboxBackendError> {
    let socket = root.join("flag.sock");
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
                mailbox_backend: &unused,
                message_list_backend: &unused,
                message_search_backend: &unused,
                message_view_backend: &unused,
                message_move_backend: &unused,
                message_append_backend: &unused,
                message_flag_backend: &backend,
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
        MailboxHelperMessageFlagBackend::new(&socket, &key_path, MailboxHelperPolicy::default())
            .set_message_flag(FIXTURE_ACCOUNT, request);
    server.join().expect("native helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}

fn move_through_helper(
    root: &Path,
    backend: DoveadmMessageMoveBackend<IsolatedDoveadm>,
    request: &MessageMoveRequest,
) -> Result<(), MailboxBackendError> {
    let socket = root.join("move.sock");
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
                mailbox_backend: &unused,
                message_list_backend: &unused,
                message_search_backend: &unused,
                message_view_backend: &unused,
                message_move_backend: &backend,
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
        MailboxHelperMessageMoveBackend::new(&socket, &key_path, MailboxHelperPolicy::default())
            .move_message(FIXTURE_ACCOUNT, request);
    server.join().expect("native helper thread");
    fs::remove_file(socket).expect("remove fixture socket");
    result
}

#[test]
#[ignore = "explicit OpenBSD qualification; creates and removes only a new standalone synthetic Maildir"]
fn isolated_openbsd_json_and_signed_flag_helper() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "native qualification requires OpenBSD"
    );
    let root = env::temp_dir().join(format!(
        "osmap-ux-native-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("new private fixture root");
    let owner = fs::metadata(&root).expect("fixture owner");
    assert_ne!(owner.uid(), 0, "run as a nonprivileged operator");
    let os_identity = |option: &str| {
        let result = SystemCommandExecutor
            .run_with_stdin_timeout("/usr/bin/id", &[option.into()], "", Duration::from_secs(1))
            .expect("current OS identity");
        assert_eq!(result.status_code, 0);
        result.stdout.trim().to_string()
    };
    let os_username = os_identity("-un");
    let os_group = os_identity("-g").parse::<u32>().expect("OS group");
    assert_eq!(
        os_identity("-u").parse::<u32>().expect("OS uid"),
        owner.uid()
    );
    assert_ne!(
        os_group, 0,
        "qualification requires a non-root process group"
    );
    assert!(
        !os_username.is_empty()
            && os_username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    );
    for directory in ["run", "state", "home", "mail"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(directory))
            .expect("fixture directory");
    }
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_home = {0}/home\nmail_location = maildir:{0}/mail\nmail_uid = {1}\nmail_gid = {2}\nfirst_valid_uid = {1}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/run/no-auth-socket\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\n", root.display(), owner.uid(), os_group)).expect("standalone configuration");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("private config");
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).expect("public synthetic signing fixture");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("private fixture key");
    let executor = IsolatedDoveadm {
        config,
        os_username,
    };
    let save = vec!["save".into(), "-m".into(), "INBOX".into()];
    for message in [
        "From: Synthetic sender <sender@example.test>\r\nTo: fixture@example.test\r\nSubject: Plain fixture\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPublic synthetic body.\r\n",
        "From: Synthetic sender <sender@example.test>\r\nReply-To: \"Reply, Desk\" <desk@example.test>\r\nTo: fixture@example.test, other@example.test\r\nCc: copied@example.test\r\nMessage-ID: <native-parent@example.test>\r\nReferences: <native-root@example.test>\r\nSubject: Attachment fixture\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=fixture\r\n\r\n--fixture\r\nContent-Type: text/plain\r\n\r\nPublic synthetic body.\r\n--fixture\r\nContent-Type: application/octet-stream; name=fixture.txt\r\nContent-Disposition: attachment; filename=fixture.txt\r\nContent-Transfer-Encoding: base64\r\n\r\nU3ludGhldGljIGZpeHR1cmUu\r\n--fixture--\r\n",
        "From: Synthetic sender <sender@example.test>\r\nBcc: private-synthetic-sentinel@example.test\r\nSubject: Missing recipient fixture\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPublic synthetic body.\r\n",
        "From: Synthetic sender <sender@example.test>\r\nTo: \"Élodie, Desk\" <elodie@example.test>,\r\n \"Quoted \\\"Name\\\"\" <quoted@example.test>\r\nSubject: Unicode quoted recipient fixture\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPublic synthetic body.\r\n",
    ] {
        assert_eq!(executor.run_with_stdin("/usr/local/bin/doveadm", &save, message).expect("save synthetic mail").status_code, 0);
    }
    let list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(),
        executor.clone(),
        "/usr/local/bin/doveadm",
    );
    let query =
        MessageListRequest::new(MessageListPolicy::default(), "INBOX").expect("list request");
    let initial = list
        .list_messages(FIXTURE_ACCOUNT, &query)
        .expect("native structured list");
    assert_eq!(initial.len(), 4);
    assert_eq!(initial[0].to.as_deref(), Some("fixture@example.test"));
    assert_eq!(
        initial[1].to.as_deref(),
        Some("fixture@example.test, other@example.test")
    );
    assert_eq!(
        initial[2].to, None,
        "missing To must not fall back to From or Bcc"
    );
    assert_eq!(
        initial[3].to.as_deref(),
        Some(
            "\"Élodie, Desk\" <elodie@example.test>, \"Quoted \\\"Name\\\"\" <quoted@example.test>"
        )
    );
    let response = MailboxHelperResponse::MessageListOk {
        mailbox_name: "INBOX".into(),
        messages: initial.clone(),
    };
    let encoded = encode_response(&response);
    assert!(!encoded.contains("message_bcc"));
    assert!(!format!("{initial:?}").contains("private-synthetic-sentinel"));
    assert_eq!(
        parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            &encoded,
        )
        .expect("native To summary helper roundtrip"),
        response
    );
    assert!(initial.iter().all(|message| message
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.preview.as_deref())
        == Some("Public synthetic body.")));
    assert_eq!(
        initial[0]
            .metadata
            .as_ref()
            .expect("identity")
            .attachment_count,
        Some(0)
    );
    assert_eq!(
        initial[1]
            .metadata
            .as_ref()
            .expect("identity")
            .attachment_count,
        Some(1)
    );
    let view = DoveadmMessageViewBackend::new(
        MessageViewPolicy::default(),
        executor.clone(),
        "/usr/local/bin/doveadm",
    );
    let viewed = view
        .fetch_message(
            FIXTURE_ACCOUNT,
            &MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", initial[1].uid)
                .expect("view request"),
        )
        .expect("native structured view");
    assert_eq!(viewed.metadata, initial[1].metadata);
    assert!(viewed.header_block.contains("Attachment fixture"));
    let source = source_through_helper(&root, view, initial[1].uid);
    assert_eq!(
        source, viewed,
        "signed source transport preserves the complete bounded snapshot"
    );
    let attachment = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(&source, "1.2")
    .expect("attachment from checked native source");
    assert_eq!(attachment.body, b"Synthetic fixture.");
    assert_eq!(attachment.filename, "fixture.txt");
    let reply = crate::reply_thread::ReplyMetadata::from_original(&source.header_block)
        .expect("native original reply metadata");
    assert_eq!(reply.reply_targets(), ["desk@example.test"]);
    let (to, cc) = reply
        .reply_all_targets("fixture@example.test")
        .expect("native reply-all targets");
    assert_eq!(to, ["desk@example.test", "other@example.test"]);
    assert_eq!(cc, ["copied@example.test"]);
    let thread = reply.thread.expect("native thread");
    assert_eq!(thread.in_reply_to(), Some("<native-parent@example.test>"));
    assert_eq!(
        thread.references(),
        "<native-root@example.test> <native-parent@example.test>"
    );
    assert_eq!(
        list.list_messages(FIXTURE_ACCOUNT, &query)
            .expect("flags after source read"),
        initial
    );
    let backend = DoveadmMessageFlagBackend::new(executor.clone(), "/usr/local/bin/doveadm");
    let mut request = MessageFlagRequest::new(
        "INBOX".into(),
        initial[0].uid,
        initial[0]
            .metadata
            .as_ref()
            .expect("identity")
            .version
            .clone(),
        MessageFlag::Seen,
        true,
    )
    .expect("flag request");
    assert_eq!(
        through_helper(&root, backend.clone(), &request),
        Ok(MessageFlagResult::Updated)
    );
    assert_eq!(
        through_helper(&root, backend.clone(), &request),
        Ok(MessageFlagResult::AlreadySet)
    );
    request.flag = MessageFlag::Flagged;
    assert_eq!(
        through_helper(&root, backend.clone(), &request),
        Ok(MessageFlagResult::Updated)
    );
    let flagged = list
        .list_messages(FIXTURE_ACCOUNT, &query)
        .expect("confirmed flags");
    assert!(crate::mail_list::has_flag(&flagged[0].flags, "\\Seen"));
    assert!(crate::mail_list::has_flag(&flagged[0].flags, "\\Flagged"));
    assert_eq!(flagged[1].flags, initial[1].flags);
    request.enabled = false;
    let mut stale = request.clone();
    stale.version.message_guid = "nonexistent-synthetic-guid".into();
    assert_eq!(
        through_helper(&root, backend.clone(), &stale)
            .expect_err("stale message")
            .backend,
        "message-flag-stale"
    );
    stale = request.clone();
    stale.uid = initial[1].uid;
    assert_eq!(
        through_helper(&root, backend.clone(), &stale)
            .expect_err("wrong UID")
            .backend,
        "message-flag-stale"
    );
    stale = request.clone();
    stale.version.mailbox_guid = "0".repeat(32);
    assert!(through_helper(&root, backend.clone(), &stale).is_err());
    assert_eq!(
        list.list_messages(FIXTURE_ACCOUNT, &query)
            .expect("unchanged after stale"),
        flagged
    );
    assert_eq!(
        through_helper(&root, backend.clone(), &request),
        Ok(MessageFlagResult::Updated)
    );
    request.flag = MessageFlag::Seen;
    assert_eq!(
        through_helper(&root, backend, &request),
        Ok(MessageFlagResult::Updated)
    );
    assert_eq!(
        list.list_messages(FIXTURE_ACCOUNT, &query)
            .expect("restored flags"),
        initial
    );
    let create = vec![
        "mailbox".into(),
        "create".into(),
        "Archive".into(),
        "Trash".into(),
    ];
    assert_eq!(
        executor
            .run_with_stdin("/usr/local/bin/doveadm", &create, "")
            .unwrap()
            .status_code,
        0
    );
    let mover = DoveadmMessageMoveBackend::new(executor, "/usr/local/bin/doveadm");
    let original_version = initial[0].metadata.as_ref().unwrap().version.clone();
    let original_request = MessageMoveRequest::new(
        MessageMovePolicy::default(),
        "INBOX",
        "Archive",
        initial[0].uid,
        original_version.clone(),
    )
    .unwrap();
    let mut stale = original_request.clone();
    stale.version.message_guid = "absent-synthetic-guid".into();
    assert_eq!(
        move_through_helper(&root, mover.clone(), &stale)
            .unwrap_err()
            .backend,
        "message-move-stale"
    );
    assert_eq!(
        move_through_helper(&root, mover.clone(), &original_request),
        Ok(())
    );
    assert_eq!(
        move_through_helper(&root, mover.clone(), &original_request)
            .unwrap_err()
            .backend,
        "message-move-stale"
    );
    let inbox = list.list_messages(FIXTURE_ACCOUNT, &query).unwrap();
    assert_eq!(inbox, initial[1..].to_vec());
    let archive_query = MessageListRequest::new(MessageListPolicy::default(), "Archive").unwrap();
    let archive = list.list_messages(FIXTURE_ACCOUNT, &archive_query).unwrap();
    assert_eq!(archive.len(), 1);
    assert_eq!(
        archive[0].metadata.as_ref().unwrap().version.message_guid,
        original_version.message_guid
    );
    assert_eq!(archive[0].flags, initial[0].flags);
    let bin = MessageMoveRequest::new(
        MessageMovePolicy::default(),
        "Archive",
        "Trash",
        archive[0].uid,
        archive[0].metadata.as_ref().unwrap().version.clone(),
    )
    .unwrap();
    assert_eq!(move_through_helper(&root, mover.clone(), &bin), Ok(()));
    assert!(list
        .list_messages(FIXTURE_ACCOUNT, &archive_query)
        .unwrap()
        .is_empty());
    let trash_query = MessageListRequest::new(MessageListPolicy::default(), "Trash").unwrap();
    let trash = list.list_messages(FIXTURE_ACCOUNT, &trash_query).unwrap();
    assert_eq!(trash.len(), 1);
    let restore = MessageMoveRequest::new(
        MessageMovePolicy::default(),
        "Trash",
        "INBOX",
        trash[0].uid,
        trash[0].metadata.as_ref().unwrap().version.clone(),
    )
    .unwrap();
    assert_eq!(move_through_helper(&root, mover.clone(), &restore), Ok(()));
    assert!(list
        .list_messages(FIXTURE_ACCOUNT, &trash_query)
        .unwrap()
        .is_empty());
    let restored = list.list_messages(FIXTURE_ACCOUNT, &query).unwrap();
    assert_eq!(restored.len(), initial.len());
    let restored_message = restored
        .iter()
        .find(|message| {
            message.metadata.as_ref().unwrap().version.message_guid == original_version.message_guid
        })
        .unwrap();
    assert_ne!(restored_message.uid, initial[0].uid);
    assert_eq!(restored_message.metadata, initial[0].metadata);
    assert_eq!(restored_message.flags, initial[0].flags);
    assert!(initial[1..]
        .iter()
        .all(|message| restored.contains(message)));
    assert_eq!(
        move_through_helper(&root, mover, &original_request)
            .unwrap_err()
            .backend,
        "message-move-stale"
    );
    assert_eq!(
        list.list_messages(FIXTURE_ACCOUNT, &query).unwrap(),
        restored
    );
    fs::remove_dir_all(&root).expect("remove only owned synthetic fixture tree");
}

fn source_through_helper(
    root: &Path,
    backend: DoveadmMessageViewBackend<IsolatedDoveadm>,
    uid: u64,
) -> MessageView {
    let socket = root.join("source.sock");
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
        let listener = UnixListener::bind(socket_for_thread).expect("isolated source socket");
        let (mut stream, _) = listener.accept().expect("source fixture connection");
        handle_helper_client(
            HelperBackends {
                mailbox_backend: &unused,
                message_list_backend: &unused,
                message_search_backend: &unused,
                message_view_backend: &backend,
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
    let result = MailboxHelperMessageViewBackend::new(
        &socket,
        &key_path,
        MailboxHelperPolicy::default(),
        MessageViewPolicy::default(),
    )
    .fetch_message(
        FIXTURE_ACCOUNT,
        &MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", uid)
            .expect("source selector"),
    );
    server.join().expect("source helper thread");
    fs::remove_file(socket).expect("remove source socket");
    result.expect("signed native source")
}
