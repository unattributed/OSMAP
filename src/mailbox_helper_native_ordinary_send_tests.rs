//! Opt-in ordinary BrowserApp submission to a loopback sink and real owned Sent.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Ordinary public fixture.";
const PUBLIC_BODY: &str = "Harmless ordinary native body café.";
const MAX_FIXTURE_WIRE: usize = 64 * 1024;

#[derive(Clone)]
struct ScopedAppendExecutor {
    config: PathBuf,
    expected: Vec<String>,
    appends: Arc<AtomicUsize>,
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
        assert!(!input.is_empty() && input.len() <= MAX_FIXTURE_WIRE);
        let headers = input
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty() && *line != b"\r");
        assert!(!headers
            .into_iter()
            .any(|line| line.to_ascii_lowercase().starts_with(b"bcc:")));
        let call = self.appends.fetch_add(1, Ordering::SeqCst);
        assert!(
            call < 2,
            "fixture permits exactly two Sent saves, never replay"
        );
        let mut isolated = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
        isolated.extend_from_slice(a);
        SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
            p,
            &isolated,
            input,
            timeout,
            limit.min(MAX_FIXTURE_WIRE),
        )
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
            backend: "ordinary-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn ordinary_helper(
    fixture: &mut Fixture,
    native: NativeExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("ordinary-helper.sock");
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
                config: native.config,
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
                Err(_) => panic!("ordinary native helper listener"),
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
// Match the explicitly pinned Maildir storage contract; preserve every byte
// except CRLF pairs, including any standalone CR and trailing whitespace.
fn maildir_lf(wire: &[u8]) -> Vec<u8> {
    let mut stored = Vec::with_capacity(wire.len());
    let mut index = 0;
    while index < wire.len() {
        if wire[index..].starts_with(b"\r\n") {
            stored.push(b'\n');
            index += 2;
        } else {
            stored.push(wire[index]);
            index += 1;
        }
    }
    stored
}
fn ordinary_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
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
                        assert!(captured.len() < 2, "no repeated SMTP admission");
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

fn ordinary_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    path: &str,
    fields: &BTreeMap<String, String>,
    upload: bool,
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-ordinary-native-boundary";
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
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"ordinary-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
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
fn message_link(body: &str, uid: u64) -> String {
    body.split("<a ")
        .find_map(|anchor| {
            let tag = anchor.split_once('>')?.0;
            if !tag.contains("class=\"message-subject-link\"") {
                return None;
            }
            let href = attribute(tag, "href")?;
            let target = href.strip_suffix("#reading-pane")?;
            let (path, query) = target.split_once('?')?;
            if path != "/mailbox" {
                return None;
            }
            let fields = crate::http_form::parse_urlencoded_form(
                query.as_bytes(),
                crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
                2048,
            )
            .ok()?;
            (fields.get("selected_uid") == Some(&uid.to_string())
                && fields.get("selected_mailbox").map(String::as_str) == Some("Sent")
                && fields.get("name").map(String::as_str) == Some("Sent"))
            .then_some(href)
        })
        .expect("actual current Sent row opening")
}
fn assert_sent_read(
    app: &BrowserApp<RuntimeBrowserGateway>,
    alice: &IssuedSession,
    bob: &IssuedSession,
    row: &MessageSummary,
    foreign_rows: &[MessageSummary],
) {
    let listing = get(app, alice, "/mailbox?name=Sent");
    assert_eq!(listing.response.status_code, 200);
    assert!(
        !text(&listing).contains(BOB),
        "Bcc is not projected into Sent recipient rows"
    );
    let opening = message_link(text(&listing), row.uid);
    let target = opening.strip_suffix("#reading-pane").unwrap();
    let fields = crate::http_form::parse_urlencoded_form(
        target.split_once('?').unwrap().1.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    let version = &row.metadata.as_ref().unwrap().version;
    let foreign_version = &foreign_rows
        .iter()
        .find(|foreign| foreign.uid == row.uid)
        .expect("same-UID owned foreign Sent control")
        .metadata
        .as_ref()
        .unwrap()
        .version;
    assert_ne!(version, foreign_version);
    assert!(
        fields.get("selected_mailbox_guid") == Some(&version.mailbox_guid)
            && fields.get("selected_message_guid") == Some(&version.message_guid)
    );
    let read = get(app, alice, target);
    assert_eq!(read.response.status_code, 200);
    assert!(text(&read).contains(PUBLIC_BODY) && text(&read).contains("ordinary-public.txt"));
    let download = text(&read)
        .split("<a ")
        .find_map(|part| {
            let (tag, content) = part.split_once('>')?;
            (content.split_once("</a>")?.0 == "Download")
                .then(|| attribute(tag, "href"))
                .flatten()
        })
        .expect("actual isolated attachment Download link");
    let downloaded = get(app, alice, &download);
    assert_eq!(downloaded.response.status_code, 200);
    assert!(downloaded.response.body == PUBLIC_ATTACHMENT);
    assert!(downloaded.response.headers.iter().any(
        |(name, value)| name == "Content-Disposition" && value.contains("ordinary-public.txt")
    ));
    let assert_unavailable = |response: HandledHttpResponse, case: &str| {
        assert_eq!(response.response.status_code, 200, "{case}");
        let pane = text(&response)
            .split_once("<article id=\"reading-pane\"")
            .unwrap()
            .1
            .split_once("</article>")
            .unwrap()
            .0;
        assert!(pane.contains("id=\"reading-unavailable\""), "{case}");
        assert!(
            pane.contains("The selected message identity changed."),
            "{case}"
        );
        assert!(
            !pane.contains(PUBLIC_BODY) && !pane.contains("Download"),
            "{case}"
        );
    };
    assert_unavailable(get(app, bob, target), "foreign same-UID Sent identity");
    assert_eq!(get(app, bob, &download).response.status_code, 409);
    let mut stale_fields = fields.clone();
    stale_fields.insert(
        "selected_message_guid".into(),
        "stale-ordinary-version".into(),
    );
    let stale_query = stale_fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let stale = format!("/mailbox?{stale_query}");
    assert_ne!(
        stale, target,
        "stale request must alter the generated target"
    );
    let parsed_stale = crate::http_form::parse_urlencoded_form(
        stale_query.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    assert_eq!(
        parsed_stale
            .get("selected_message_guid")
            .map(String::as_str),
        Some("stale-ordinary-version")
    );
    assert_eq!(
        parsed_stale.get("selected_mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_unavailable(get(app, alice, &stale), "stale current Sent GUID");
}

#[test]
#[ignore = "explicit OpenBSD ordinary BrowserApp submission; isolated SMTP and Dovecot only"]
fn isolated_openbsd_ordinary_compose_and_draft_submit_to_sink_with_authoritative_sent() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-ordinary-{}-{}",
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
    for index in 1..=3 {
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
    assert_eq!(bob_sent_before.len(), 3);
    let inbox_bytes = scoped_delete_wire_bytes(&root, "alice", "");
    let bob_bytes = scoped_delete_wire_bytes(&root, "bob", "");
    let bob_sent_bytes = scoped_delete_wire_bytes(&root, "bob", ".Sent");
    let neighbour_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    let appends = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = ordinary_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = ordinary_sink(&mut fixture, records.clone());
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
        "native-ordinary-session",
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
        RuntimeBrowserGateway::from_config(&app_config).with_fixture_sendmail_path(sendmail),
    );
    let page = get(&app, &alice, "/compose");
    assert_eq!(page.response.status_code, 200);
    let mut fields = compose_fields(text(&page));
    assert_eq!(
        fields.get("pgp_binding_revision"),
        Some(&binding.revision.to_string())
    );
    fields.insert("to".into(), ALICE.into());
    fields.insert("bcc".into(), BOB.into());
    fields.insert("subject".into(), "Ordinary Fresh Native".into());
    fields.insert("body".into(), PUBLIC_BODY.into());
    assert!(!fields
        .keys()
        .any(|key| matches!(key.as_str(), "pgp_sign" | "pgp_encrypt" | "pgp_self")));
    // Refusals occur before the first local transport or helper append.
    assert_eq!(
        ordinary_post(&app, None, "/send", &fields, true)
            .response
            .status_code,
        303
    );
    let mut wrong_csrf = fields.clone();
    wrong_csrf.insert("csrf_token".into(), "invalid".into());
    assert_eq!(
        ordinary_post(&app, Some(&alice), "/send", &wrong_csrf, true)
            .response
            .status_code,
        403
    );
    assert_eq!(
        ordinary_post(&app, Some(&bob), "/send", &fields, true)
            .response
            .status_code,
        403
    );
    let mut stale = fields.clone();
    stale.insert(
        "pgp_binding_revision".into(),
        (binding.revision + 1).to_string(),
    );
    let refused = ordinary_post(&app, Some(&alice), "/send", &stale, true);
    assert!(refused.response.status_code >= 400);
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
    let submitted = ordinary_post(&app, Some(&alice), "/send", &fields, true);
    assert_eq!(submitted.response.status_code, 303);
    let receipt_url = location(&submitted);
    assert!(receipt_url.starts_with("/compose?receipt="));
    let receipt = get(&app, &alice, &receipt_url);
    assert_eq!(receipt.response.status_code, 200);
    assert!(
        text(&receipt).contains("A copy was saved in Sent")
            && text(&receipt).contains("Delivery to the recipient is not yet confirmed")
    );
    let first = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(first.len(), 2);
    let first_row = first
        .iter()
        .find(|row| row.subject.as_deref() == Some("Ordinary Fresh Native"))
        .unwrap();
    assert_sent_read(&app, &alice, &bob, first_row, &bob_sent_before);
    let replay = ordinary_post(&app, Some(&alice), "/send", &fields, true);
    assert!(matches!(replay.response.status_code, 200 | 303));
    assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
    assert_eq!(list.list_messages(ALICE, &sent).unwrap().len(), 2);

    let sentinel_page = get(&app, &alice, "/compose");
    assert_eq!(sentinel_page.response.status_code, 200);
    let mut sentinel_fields = compose_fields(text(&sentinel_page));
    sentinel_fields.insert("to".into(), ALICE.into());
    sentinel_fields.insert("subject".into(), "Unrelated native saved draft".into());
    sentinel_fields.insert("body".into(), "Preserved unrelated public draft.".into());
    let sentinel_saved = ordinary_post(&app, Some(&alice), "/drafts/save", &sentinel_fields, false);
    assert_eq!(sentinel_saved.response.status_code, 303);
    let sentinel_url = location(&sentinel_saved);
    let sentinel_resume = get(&app, &alice, &sentinel_url);
    assert_eq!(sentinel_resume.response.status_code, 200);
    let sentinel_id = compose_fields(text(&sentinel_resume))
        .get("draft_id")
        .unwrap()
        .clone();
    let draft_store = crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default(),
    );
    let sentinel_before = draft_store
        .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();

    let fresh_draft = get(&app, &alice, "/compose");
    assert_eq!(fresh_draft.response.status_code, 200);
    let mut draft_fields = compose_fields(text(&fresh_draft));
    draft_fields.insert("to".into(), ALICE.into());
    draft_fields.insert("bcc".into(), BOB.into());
    draft_fields.insert("subject".into(), "Ordinary Draft Native".into());
    draft_fields.insert("body".into(), PUBLIC_BODY.into());
    let saved = ordinary_post(&app, Some(&alice), "/drafts/save", &draft_fields, true);
    assert_eq!(saved.response.status_code, 303);
    let draft_url = location(&saved);
    assert!(draft_url.starts_with("/draft?id="));
    assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
    let resume = get(&app, &alice, &draft_url);
    assert_eq!(resume.response.status_code, 200);
    let resumed = compose_fields(text(&resume));
    assert!(resumed.get("body").map(String::as_str) == Some(PUBLIC_BODY));
    assert!(resumed.get("bcc").map(String::as_str) == Some(BOB));
    assert!(
        text(&resume).contains("ordinary-public.txt") && resumed.contains_key("draft_revision")
    );
    let draft_id = resumed.get("draft_id").unwrap().clone();
    let mut stale_draft = resumed.clone();
    let actual_revision = resumed
        .get("draft_revision")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    stale_draft.insert("draft_revision".into(), (actual_revision + 1).to_string());
    let stale_refused = ordinary_post(&app, Some(&alice), "/send", &stale_draft, false);
    assert_eq!(stale_refused.response.status_code, 409);
    assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
    assert_eq!(get(&app, &alice, &draft_url).response.status_code, 200);
    let sent_draft = ordinary_post(&app, Some(&alice), "/send", &resumed, false);
    assert_eq!(sent_draft.response.status_code, 303);
    let draft_receipt = get(&app, &alice, &location(&sent_draft));
    assert_eq!(draft_receipt.response.status_code, 200);
    assert!(text(&draft_receipt).contains("A copy was saved in Sent"));
    let missing = get(&app, &alice, &draft_url);
    assert_eq!(
        missing.response.status_code, 404,
        "only submitted exact draft is removed"
    );
    let now = SystemTimeProvider.unix_timestamp();
    assert!(crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default()
    )
    .load(ALICE, &draft_id, now)
    .unwrap()
    .is_none());
    assert!(draft_store.load(ALICE, &sentinel_id, now).unwrap().as_ref() == Some(&sentinel_before));
    let sentinel_after = get(&app, &alice, &sentinel_url);
    assert_eq!(sentinel_after.response.status_code, 200);
    assert!(text(&sentinel_after).contains("Preserved unrelated public draft."));
    let final_sent = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(final_sent.len(), 3);
    let draft_row = final_sent
        .iter()
        .find(|row| row.subject.as_deref() == Some("Ordinary Draft Native"))
        .unwrap();
    assert_sent_read(&app, &alice, &bob, draft_row, &bob_sent_before);
    assert!(final_sent.iter().any(|row| row.uid == sent_before[0].uid
        && row.metadata == sent_before[0].metadata
        && row.flags == sent_before[0].flags));
    let repeat = ordinary_post(&app, Some(&alice), "/send", &resumed, false);
    assert!(matches!(repeat.response.status_code, 200 | 303));
    assert_eq!(appends.load(Ordering::SeqCst), 2);
    let captured = records.lock().unwrap().clone();
    assert_eq!(captured.len(), 2);
    let stored_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    for capture in &captured {
        assert!(
            capture.recipients.contains(&ALICE.to_string())
                && capture.recipients.contains(&BOB.to_string())
        );
        assert!(
            stored_bytes.iter().any(|wire| wire == &maildir_lf(&capture.wire)),
            "SMTP accepted bytes match an authoritative Sent object under pinned CRLF-to-LF storage"
        );
        let header = capture
            .wire
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty() && *line != b"\r");
        assert!(!header
            .into_iter()
            .any(|line| line.to_ascii_lowercase().starts_with(b"bcc:")));
        assert!(!capture
            .wire
            .windows(b"application/pgp-encrypted".len())
            .any(|window| window == b"application/pgp-encrypted"));
    }
    assert!(stored_bytes.iter().any(|wire| wire == &neighbour_bytes[0]));
    assert!(list.list_messages(ALICE, &inbox).unwrap() == alice_before);
    assert!(list.list_messages(BOB, &inbox).unwrap() == bob_before);
    assert!(list.list_messages(BOB, &sent).unwrap() == bob_sent_before);
    assert!(scoped_delete_wire_bytes(&root, "alice", "") == inbox_bytes);
    assert!(scoped_delete_wire_bytes(&root, "bob", "") == bob_bytes);
    assert!(scoped_delete_wire_bytes(&root, "bob", ".Sent") == bob_sent_bytes);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_ordinary_submission_browser=PASS actual_generated_fresh_and_resumed_draft_forms=PASS normal_runtime_authenticated_append_real_dovecot_sent=PASS loopback_smtp_only_two_submissions=PASS fresh_and_draft_receipts_sent_guids_reader_download=PASS replay_no_duplicate_submit_append=PASS bcc_envelope_not_headers=PASS exact_submitted_draft_cleanup=PASS neighbour_foreign_bytes_flags_guids_unchanged=PASS no_move_expunge_flag_private_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
