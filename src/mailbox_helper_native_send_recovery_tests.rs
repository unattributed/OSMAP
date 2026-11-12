//! Opt-in recovery BrowserApp submission to a loopback sink and real owned Sent.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Ordinary public fixture.";
const PUBLIC_BODY: &str = "Harmless recovery native body café.";
const MAX_FIXTURE_WIRE: usize = 64 * 1024;

#[derive(Clone)]
struct ScopedAppendExecutor {
    expected: Vec<String>,
    appends: Arc<AtomicUsize>,
    refused_wire: Arc<Mutex<Vec<Vec<u8>>>>,
}
impl CommandExecutor for ScopedAppendExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("native append requires bounded execution")
    }
    fn run_with_stdin_bytes_timeout(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(p, a, input, timeout, MAX_FIXTURE_WIRE)
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(p, "/usr/local/bin/doveadm");
        assert!(
            a == self.expected.as_slice(),
            "only exact Alice/Sent save arguments admitted"
        );
        assert!(timeout <= Duration::from_secs(10));
        assert!(limit >= "controlled owned Sent append refusal".len());
        assert!(!input.is_empty() && input.len() <= MAX_FIXTURE_WIRE);
        let headers = input
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty() && *line != b"\r");
        assert!(!headers
            .into_iter()
            .any(|line| line.to_ascii_lowercase().starts_with(b"bcc:")));
        let call = self.appends.fetch_add(1, Ordering::SeqCst);
        assert!(
            call < 1,
            "fixture permits exactly one refused append admission, never replay"
        );
        self.refused_wire.lock().unwrap().push(input.to_vec());
        // This separately owned fixture never invokes a save command. The
        // actual authenticated helper returns the normal finite append refusal.
        Ok(CommandExecution {
            status_code: 75,
            stdout: String::new(),
            stderr: "controlled owned Sent append refusal".into(),
        })
    }
}

struct NoFixtureFlags(Arc<AtomicUsize>);
impl crate::mailbox::MessageFlagBackend for NoFixtureFlags {
    fn set_message_flag(
        &self,
        _: &str,
        _: &crate::mailbox::MessageFlagRequest,
    ) -> Result<crate::mailbox::MessageFlagResult, MailboxBackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(MailboxBackendError {
            backend: "recovery-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn recovery_helper(
    fixture: &mut Fixture,
    native: NativeExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
    refused_wire: Arc<Mutex<Vec<Vec<u8>>>>,
) -> PathBuf {
    let socket = fixture.root.join("recovery-helper.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = fixture.stop.clone();
    fixture.threads.push(thread::spawn(move || {
        let listing = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            native.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let messages = DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            native.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let search = DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
            native.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let view = DoveadmMessageViewBackend::new(
            MessageViewPolicy::default(),
            native.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let append = DoveadmMessageAppendBackend::new(
            ScopedAppendExecutor {
                expected: vec![
                    "-o".into(),
                    "stats_writer_socket_path=".into(),
                    "-o".into(),
                    format!("auth_socket_path={}", userdb.display()),
                    "save".into(),
                    "-u".into(),
                    ALICE.into(),
                    "-m".into(),
                    "Sent".into(),
                ],
                appends,
                refused_wire,
            },
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb));
        let denied = ForbiddenMutation(forbidden.clone());
        let flags = NoFixtureFlags(forbidden);
        let replay = Mutex::new(BTreeMap::new());
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => panic!("recovery native helper listener"),
            };
            handle_helper_client(
                HelperBackends {
                    mailbox_backend: &listing,
                    message_list_backend: &messages,
                    message_search_backend: &search,
                    message_view_backend: &view,
                    message_move_backend: &denied,
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

#[derive(Clone)]
struct SmtpRecord {
    wire: Vec<u8>,
    recipients: Vec<String>,
}
fn recovery_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    listener.set_nonblocking(true).unwrap();
    let stop = fixture.stop.clone();
    fixture.threads.push(thread::spawn(move || {
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, peer) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => panic!("owned SMTP listener"),
            };
            assert!(peer.ip().is_loopback());
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(b"220 owned fixture ESMTP\r\n").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut recipients = Vec::new();
            let mut data = false;
            let mut wire = Vec::new();
            let connection_deadline = Instant::now() + Duration::from_secs(10);
            loop {
                assert!(Instant::now() < connection_deadline);
                let mut line = Vec::new();
                let n = Read::by_ref(&mut reader)
                    .take((MAX_FIXTURE_WIRE + 1) as u64)
                    .read_until(b'\n', &mut line)
                    .unwrap();
                if n == 0 {
                    break;
                }
                assert!(n <= MAX_FIXTURE_WIRE && line.ends_with(b"\n"));
                if data {
                    if line == b".\r\n" {
                        assert!(
                            recipients.contains(&ALICE.to_string())
                                && recipients.contains(&BOB.to_string())
                                && recipients.len() == 2
                        );
                        let mut captured = records.lock().unwrap();
                        assert!(captured.is_empty(), "no repeated SMTP admission");
                        captured.push(SmtpRecord {
                            wire: std::mem::take(&mut wire),
                            recipients: std::mem::take(&mut recipients),
                        });
                        data = false;
                        stream.write_all(b"250 fixture accepted\r\n").unwrap();
                    } else {
                        if line.starts_with(b"..") {
                            line.remove(0);
                        }
                        assert!(wire.len() + line.len() <= MAX_FIXTURE_WIRE);
                        wire.extend(line);
                    }
                    continue;
                }
                let command = std::str::from_utf8(&line)
                    .unwrap()
                    .trim_end_matches(['\r', '\n']);
                if command.starts_with("ehlo ")
                    || command.starts_with("helo ")
                    || command.starts_with("EHLO ")
                    || command.starts_with("HELO ")
                {
                    stream.write_all(b"250 fixture\r\n").unwrap();
                } else if command.eq_ignore_ascii_case(&format!("mail FROM:<{ALICE}>")) {
                    stream.write_all(b"250 fixture sender\r\n").unwrap();
                } else if let Some(recipient) = command
                    .get(..8)
                    .filter(|prefix| prefix.eq_ignore_ascii_case("rcpt TO:"))
                    .and_then(|_| command[8..].strip_prefix('<'))
                    .and_then(|value| value.strip_suffix('>'))
                {
                    assert!([ALICE, BOB].contains(&recipient));
                    assert!(!recipients.iter().any(|existing| existing == recipient));
                    recipients.push(recipient.to_string());
                    stream.write_all(b"250 fixture recipient\r\n").unwrap();
                } else if command.eq_ignore_ascii_case("data") {
                    data = true;
                    stream.write_all(b"354 fixture data\r\n").unwrap();
                } else if command.eq_ignore_ascii_case("quit") {
                    stream.write_all(b"221 fixture bye\r\n").unwrap();
                    break;
                } else {
                    panic!("SMTP command outside finite fixture protocol");
                }
            }
        }
    }));
    address.port()
}

fn compose_fields(body: &str) -> BTreeMap<String, String> {
    let form = body
        .split_once("<form id=\"compose-form\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains("action=\"/send\"") && form.contains("enctype=\"multipart/form-data\""));
    let mut fields = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split_once('>').unwrap().0;
        let Some(name) = attribute(tag, "name") else {
            continue;
        };
        let kind = attribute(tag, "type").unwrap_or_else(|| "text".into());
        if matches!(kind.as_str(), "file" | "checkbox") {
            continue;
        }
        assert!(fields
            .insert(name, attribute(tag, "value").unwrap_or_default())
            .is_none());
    }
    let textarea = form
        .split_once("<textarea id=\"compose-body\"")
        .unwrap()
        .1
        .split_once('>')
        .unwrap()
        .1
        .split_once("</textarea>")
        .unwrap()
        .0;
    fields.insert(
        "body".into(),
        decode(textarea.strip_prefix('\n').unwrap_or(textarea)),
    );
    assert!(form.contains("name=\"body_format\"") && form.contains("value=\"plain\""));
    fields.insert("body_format".into(), "plain".into());
    assert!(fields.contains_key("csrf_token") && fields.contains_key("send_intent"));
    assert_eq!(fields.get("from").map(String::as_str), Some(ALICE));
    fields
}

fn recovery_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    path: &str,
    fields: &BTreeMap<String, String>,
    upload: bool,
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-recovery-native-boundary";
    let mut body = Vec::new();
    for (key, value) in fields {
        assert!(!key.chars().any(char::is_control) && !key.contains('"'));
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    if upload {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"recovery-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
        body.extend_from_slice(PUBLIC_ATTACHMENT);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let cookie = session
        .map(|session| format!("Cookie: osmap_session={}\r\n", session.token.as_str()))
        .unwrap_or_default();
    let mut wire = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/native-reader\r\nOrigin: http://localhost\r\n{cookie}Content-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend(body);
    let request = crate::http::parse_http_request_bytes(&wire, app.policy()).unwrap();
    app.handle_request(&request, "127.0.0.1")
}
fn location(response: &HandledHttpResponse) -> String {
    response
        .response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .unwrap()
        .1
        .clone()
}

#[test]
#[ignore = "explicit OpenBSD SMTP acceptance with refused Sent copy; owned local fixture only"]
fn isolated_openbsd_accepted_submission_refused_sent_preserves_exact_recovery() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-recovery-{}-{}",
        std::process::id(),
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture {
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        threads: Vec::new(),
    };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    let group = SystemCommandExecutor
        .run_with_stdin_timeout("/usr/bin/id", &["-g".into()], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(group.status_code, 0);
    let gid = group.stdout.trim().parse::<u32>().unwrap();
    assert_ne!(gid, 0);
    for dir in ["run", "state", "app-state"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(dir))
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
    write_message(&root, "alice", 0, 0);
    write_message(&root, "alice", 1, 0);
    fs::rename(
        root.join("alice/Maildir/new/synthetic-001"),
        root.join("alice/Maildir/.Sent/new/synthetic-001"),
    )
    .unwrap();
    write_message(&root, "bob", 0, 0);
    for index in 1..=1 {
        write_message(&root, "bob", index, 0);
        fs::rename(
            root.join(format!("bob/Maildir/new/synthetic-{index:03}")),
            root.join(format!("bob/Maildir/.Sent/new/synthetic-{index:03}")),
        )
        .unwrap();
    }
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nmail_save_crlf = no\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let native = NativeExecutor {
        config,
        calls: Arc::new(AtomicUsize::new(0)),
        bin_move_count: None,
    };
    let list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(),
        native.clone(),
        "/usr/local/bin/doveadm",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let inbox = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let sent = MessageListRequest::new(MessageListPolicy::default(), "Sent").unwrap();
    let alice_before = list.list_messages(ALICE, &inbox).unwrap();
    let bob_before = list.list_messages(BOB, &inbox).unwrap();
    let sent_before = list.list_messages(ALICE, &sent).unwrap();
    assert!(alice_before.len() == 1 && bob_before.len() == 1 && sent_before.len() == 1);
    let bob_sent_before = list.list_messages(BOB, &sent).unwrap();
    assert_eq!(bob_sent_before.len(), 1);
    let inbox_bytes = scoped_delete_wire_bytes(&root, "alice", "");
    let bob_bytes = scoped_delete_wire_bytes(&root, "bob", "");
    let bob_sent_bytes = scoped_delete_wire_bytes(&root, "bob", ".Sent");
    let neighbour_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    let appends = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let refused_wire = Arc::new(Mutex::new(Vec::new()));
    let helper = recovery_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
        refused_wire.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = recovery_sink(&mut fixture, records.clone());
    let sendmail = root.join("owned-loopback-sendmail");
    fs::write(&sendmail, format!("#!/usr/local/bin/python3\nimport smtplib,sys\nassert sys.argv[1:3]==['-oi','-f'] and sys.argv[3]=={ALICE:?} and sys.argv[4]=='--'\nassert sorted(sys.argv[5:])==sorted([{ALICE:?},{BOB:?}])\ncontent=sys.stdin.buffer.read({})\nassert len(content)<={}\nwith smtplib.SMTP('127.0.0.1',{port},timeout=3) as client:\n    client.sendmail(sys.argv[3],sys.argv[5:],content)\n", MAX_FIXTURE_WIRE + 1, MAX_FIXTURE_WIRE)).unwrap();
    fs::set_permissions(&sendmail, fs::Permissions::from_mode(0o700)).unwrap();
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
        ("OSMAP_MAILBOX_HELPER_PEER_UID".into(), uid.to_string()),
        ("OSMAP_MAILBOX_WORKER_BUDGET".into(), "1".into()),
    ]))
    .unwrap();
    assert!(
        app_config.openpgp_crypto.is_none()
            && app_config.openpgp_inventory.is_none()
            && app_config.openpgp_public_admin.is_none()
    );
    let public_inventory = crate::openpgp_inventory::Inventory::parse(
        serde_json::to_vec(&serde_json::json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]})).unwrap().as_slice()
    ).unwrap();
    let binding = crate::openpgp_bindings::BindingStore::new(
        app_config
            .state_layout
            .settings_dir
            .join("openpgp-bindings"),
    )
    .replace_operator(
        ALICE,
        0,
        crate::openpgp_bindings::Update {
            account_binding: None,
            recipient_bindings: Vec::new(),
            policy: crate::openpgp_bindings::ProtectionPolicy::default(),
        },
        &public_inventory,
        SystemTimeProvider.unix_timestamp(),
    )
    .unwrap();
    assert_eq!(binding.revision, 1);
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "native-recovery-session",
        "127.0.0.1",
        "OSMAP/native-reader",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(&app_config.state_layout.session_dir),
        SystemTimeProvider,
        SystemRandomSource,
        180,
        180,
    );
    let alice = sessions
        .issue(&context, ALICE, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config)
            .with_fixture_sendmail_path(sendmail.clone()),
    );

    let page = get(&app, &alice, "/compose");
    assert_eq!(page.response.status_code, 200);
    let mut fields = compose_fields(text(&page));
    fields.insert("to".into(), ALICE.into());
    fields.insert("bcc".into(), BOB.into());
    fields.insert("subject".into(), "Older owned recovery draft".into());
    fields.insert("body".into(), PUBLIC_BODY.into());
    assert_eq!(
        fields.get("pgp_binding_revision"),
        Some(&binding.revision.to_string())
    );
    let saved = recovery_post(&app, Some(&alice), "/drafts/save", &fields, true);
    assert_eq!(saved.response.status_code, 303);
    let draft_url = location(&saved);
    let resumed = get(&app, &alice, &draft_url);
    assert_eq!(resumed.response.status_code, 200);
    let mut submit = compose_fields(text(&resumed));
    let draft_id = submit.get("draft_id").unwrap().clone();
    let store = crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default(),
    );
    let older = store
        .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(older.request.body, PUBLIC_BODY);
    assert_eq!(older.request.attachments.len(), 1);
    assert_eq!(older.request.attachments[0].body, PUBLIC_ATTACHMENT);
    let sentinel_page = get(&app, &alice, "/compose");
    assert_eq!(sentinel_page.response.status_code, 200);
    let mut sentinel_fields = compose_fields(text(&sentinel_page));
    sentinel_fields.insert("to".into(), ALICE.into());
    sentinel_fields.insert("subject".into(), "Unrelated recovery sentinel draft".into());
    sentinel_fields.insert("body".into(), "Preserve separate public draft.".into());
    let sentinel_saved = recovery_post(&app, Some(&alice), "/drafts/save", &sentinel_fields, false);
    assert_eq!(sentinel_saved.response.status_code, 303);
    let sentinel_url = location(&sentinel_saved);
    let sentinel_page = get(&app, &alice, &sentinel_url);
    assert_eq!(sentinel_page.response.status_code, 200);
    let sentinel_id = compose_fields(text(&sentinel_page))
        .get("draft_id")
        .unwrap()
        .clone();
    let sentinel = store
        .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
    let attempted_body =
        "\n\nExact recovery 🦊 </textarea><script>inert</script>\r\npublic & literal";
    submit.insert("body".into(), attempted_body.into());
    submit.insert(
        "subject".into(),
        "Actual accepted copy-refused recovery".into(),
    );
    let intent = submit.get("send_intent").unwrap().clone();
    let submitted = recovery_post(&app, Some(&alice), "/send", &submit, false);
    assert_eq!(submitted.response.status_code, 200);
    let html = text(&submitted);
    assert!(html.contains("Sent-copy storage could not be confirmed"));
    assert!(!html.contains("A copy was saved in Sent") && !html.contains("Nothing was sent"));
    assert!(html.contains(&*crate::http_support::escape_html(attempted_body)));
    assert!(html.contains("recovery-public.txt"));
    assert!(!html.contains("action=\"/send\"") && !html.contains("<script"));
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(refused_wire.lock().unwrap().len(), 1);
    assert_eq!(list.list_messages(ALICE, &sent).unwrap(), sent_before);
    assert_eq!(
        scoped_delete_wire_bytes(&root, "alice", ".Sent"),
        neighbour_bytes
    );
    assert_eq!(
        store
            .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .unwrap(),
        older
    );
    assert_eq!(
        store
            .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .unwrap(),
        sentinel
    );

    let receipt_url = format!("/compose?receipt={}", encode(&intent));
    let receipt = get(&app, &alice, &receipt_url);
    assert_eq!(receipt.response.status_code, 200);
    assert!(text(&receipt).contains("Message accepted for submission"));
    assert!(text(&receipt).contains("Submission acceptance is known. Delivery is not confirmed."));
    assert!(text(&receipt).contains("Sent-copy storage could not be confirmed"));
    assert!(text(&receipt).contains("Do not send again to repair Sent or draft cleanup."));
    assert!(
        !text(&receipt).contains("action=\"/send\"")
            && !text(&receipt).contains("name=\"send_intent\"")
    );
    assert!(text(&receipt).contains("Exact prepared attempt"));
    assert!(text(&receipt).contains(&*crate::http_support::escape_html(attempted_body)));
    let recovery_link = |flag: &str| {
        text(&receipt)
            .split("<a ")
            .find_map(|part| {
                let tag = part.split_once('>')?.0;
                let href = attribute(tag, "href")?;
                if href.split_once('?')?.0 != "/compose" {
                    return None;
                }
                let fields = crate::http_form::parse_urlencoded_form(
                    href.split_once('?')?.1.as_bytes(),
                    4,
                    2048,
                )
                .ok()?;
                (fields.get("receipt") == Some(&intent) && fields.contains_key(flag))
                    .then_some(href)
            })
            .expect("actual read-only recovery body/file download link")
    };
    let body_href = recovery_link("recovery_body");
    let file_href = recovery_link("recovery_attachment");
    let body_download = get(&app, &alice, &body_href);
    assert_eq!(body_download.response.status_code, 200);
    assert_eq!(body_download.response.body, attempted_body.as_bytes());
    let file_download = get(&app, &alice, &file_href);
    assert_eq!(file_download.response.status_code, 200);
    assert_eq!(file_download.response.body, PUBLIC_ATTACHMENT);
    for response in [&body_download, &file_download] {
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "Cache-Control" && value == "no-store"));
        assert!(response
            .response
            .headers
            .iter()
            .any(|(name, value)| name == "X-Content-Type-Options" && value == "nosniff"));
        assert!(response.response.headers.iter().any(|(name, value)| name
            == "Content-Security-Policy"
            && value == "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    }
    assert_eq!(get(&app, &bob, &receipt_url).response.status_code, 404);
    assert_eq!(get(&app, &bob, &body_href).response.status_code, 404);
    assert_eq!(get(&app, &bob, &file_href).response.status_code, 404);
    assert_eq!(
        http(&app, None, "GET", &body_href, &BTreeMap::new())
            .response
            .status_code,
        303
    );

    // Rebuilding the web application reopens durable state; it does not restart
    // a host service and does not simulate a power loss.
    let reopened = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config).with_fixture_sendmail_path(sendmail),
    );
    let reopened_receipt = get(&reopened, &alice, &receipt_url);
    assert_eq!(reopened_receipt.response.status_code, 200);
    assert!(text(&reopened_receipt).contains("Sent-copy storage could not be confirmed"));
    assert_eq!(
        get(&reopened, &alice, &body_href).response.body,
        attempted_body.as_bytes()
    );
    assert_eq!(
        get(&reopened, &alice, &file_href).response.body,
        PUBLIC_ATTACHMENT
    );
    let replay = recovery_post(&reopened, Some(&alice), "/send", &submit, false);
    assert_eq!(replay.response.status_code, 200);
    assert!(text(&replay).contains("This intent already has a recorded action"));
    assert!(text(&replay).contains("No new save or submission was started."));
    assert!(!text(&replay).contains("action=\"/send\""));
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(refused_wire.lock().unwrap().len(), 1);
    let consumed = get(&reopened, &alice, &draft_url);
    assert_eq!(consumed.response.status_code, 200);
    assert!(
        !text(&consumed).contains("id=\"compose-form\"")
            && !text(&consumed).contains("action=\"/send\"")
    );
    assert!(text(&consumed).contains(&intent));
    let cannot_save = recovery_post(&reopened, Some(&alice), "/drafts/save", &submit, false);
    assert_eq!(cannot_save.response.status_code, 200);
    assert!(text(&cannot_save).contains("This intent already has a recorded action"));
    assert!(text(&cannot_save).contains("No new save or submission was started."));
    assert!(!text(&cannot_save).contains("id=\"compose-form\""));
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .unwrap(),
        older
    );
    assert_eq!(
        store
            .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .unwrap(),
        sentinel
    );
    let unrelated = get(&reopened, &alice, &sentinel_url);
    assert_eq!(unrelated.response.status_code, 200);
    assert!(
        text(&unrelated).contains("id=\"compose-form\"")
            && text(&unrelated).contains("Preserve separate public draft.")
    );
    let captured = records.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert!(
        captured[0].recipients.contains(&ALICE.to_string())
            && captured[0].recipients.contains(&BOB.to_string())
    );
    assert_eq!(refused_wire.lock().unwrap()[0], captured[0].wire);
    let wire = std::str::from_utf8(&captured[0].wire).unwrap();
    let header = wire.split_once("\r\n\r\n").unwrap().0;
    assert!(
        !header
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("bcc:"))
            && !wire.contains(BOB)
    );
    assert!(
        !wire.contains("application/pgp-encrypted") && !wire.contains("application/pgp-signature")
    );
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(list.list_messages(ALICE, &sent).unwrap(), sent_before);
    assert_eq!(list.list_messages(ALICE, &inbox).unwrap(), alice_before);
    assert_eq!(list.list_messages(BOB, &inbox).unwrap(), bob_before);
    assert_eq!(list.list_messages(BOB, &sent).unwrap(), bob_sent_before);
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ""), inbox_bytes);
    assert_eq!(scoped_delete_wire_bytes(&root, "bob", ""), bob_bytes);
    assert_eq!(
        scoped_delete_wire_bytes(&root, "alice", ".Sent"),
        neighbour_bytes
    );
    assert_eq!(
        scoped_delete_wire_bytes(&root, "bob", ".Sent"),
        bob_sent_bytes
    );
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_accepted_sent_refusal_recovery=PASS actual_generated_saved_draft_send_form=PASS loopback_smtp_accepted_exactly_once=PASS authenticated_helper_refused_append_once_no_save=PASS real_dovecot_sent_and_neighbours_unchanged=PASS accepted_not_stored_not_delivered_truthful=PASS exact_durable_attempt_body_attachment_downloads=PASS consumed_draft_preserved_readonly_unrelated_editable=PASS application_reopen_replays_without_submission_append=PASS foreign_unauth_recovery_refused=PASS bcc_envelope_not_headers=PASS no_move_expunge_flag_private_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
