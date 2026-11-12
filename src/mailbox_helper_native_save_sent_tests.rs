//! Opt-in generated Save Sent form, durable choice and real owned Sent storage.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Save Sent public fixture.";
const PUBLIC_BODY: &str = "Harmless save_sent native body café.";
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
            call < 1,
            "fixture permits exactly one Sent save, never replay"
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
            backend: "save_sent-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn save_sent_helper(
    fixture: &mut Fixture,
    native: NativeExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("save_sent-helper.sock");
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
                Err(_) => panic!("save_sent native helper listener"),
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
fn save_sent_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
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

fn compose_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    path: &str,
    fields: &BTreeMap<String, String>,
    upload: bool,
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-save_sent-native-boundary";
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
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"save_sent-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
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
    assert!(text(&read).contains(PUBLIC_BODY) && text(&read).contains("save_sent-public.txt"));
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
        |(name, value)| name == "Content-Disposition" && value.contains("save_sent-public.txt")
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
        "stale-save_sent-version".into(),
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
        Some("stale-save_sent-version")
    );
    assert_eq!(
        parsed_stale.get("selected_mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_unavailable(get(app, alice, &stale), "stale current Sent GUID");
}

#[test]
#[ignore = "explicit OpenBSD generated Save Sent choice; isolated SMTP and Dovecot only"]
fn isolated_openbsd_generated_save_sent_preference_captured_draft_and_on_submit() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-save_sent-{}-{}",
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
    let helper = save_sent_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = save_sent_sink(&mut fixture, records.clone());
    let sendmail = root.join("owned-loopback-sendmail");
    let pending = root.join("send-reservation-ready");
    let release = root.join("release-reserved-send");
    fs::write(&sendmail, format!("#!/usr/local/bin/python3\nimport smtplib,sys,time,pathlib\nassert sys.argv[1:3]==['-oi','-f'] and sys.argv[3]=={ALICE:?} and sys.argv[4]=='--'\nassert sorted(sys.argv[5:])==sorted([{ALICE:?},{BOB:?}])\ncontent=sys.stdin.buffer.read({})\nassert len(content)<={}\nready=pathlib.Path({:?})\nrelease=pathlib.Path({:?})\nif not release.exists():\n    ready.touch(mode=0o600)\n    deadline=time.monotonic()+8\n    while not release.exists():\n        assert time.monotonic()<deadline\n        time.sleep(0.005)\nwith smtplib.SMTP('127.0.0.1',{port},timeout=3) as client:\n    client.sendmail(sys.argv[3],sys.argv[5:],content)\n", MAX_FIXTURE_WIRE + 1, MAX_FIXTURE_WIRE, pending.to_string_lossy(), release.to_string_lossy())).unwrap();
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
        // Private test-only budget covers the bounded reservation barrier plus
        // actual SMTP. The production config/defaults are never changed.
        (
            "OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS".into(),
            "10".into(),
        ),
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
        "native-save_sent-session",
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
    let preferences = crate::sent_copy::Store::new(&app_config.state_layout.settings_dir);
    assert_eq!(
        preferences.load(ALICE).unwrap(),
        crate::sent_copy::Preference::default()
    );
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::sent_copy::Preference::default()
    );
    let unrelated =
        crate::settings::FileUserSettingsStore::new(&app_config.state_layout.settings_dir);
    crate::settings::UserSettingsStore::save(
        &unrelated,
        ALICE,
        &crate::settings::UserSettings {
            html_display_preference: crate::rendering::HtmlDisplayPreference::PreferPlainText,
            archive_mailbox_name: Some("INBOX".into()),
        },
    )
    .unwrap();
    let unrelated_path = unrelated.settings_path_for_username(ALICE);
    let unrelated_before = fs::read(&unrelated_path).unwrap();
    let copies = get(&app, &alice, "/settings?section=copies");
    assert_eq!(copies.response.status_code, 200);
    let mut off = copy_fields(text(&copies));
    assert_eq!(off.get("expected_revision").map(String::as_str), Some("0"));
    assert_eq!(off.get("save_sent").map(String::as_str), Some("on"));
    off.insert("save_sent".into(), "off".into());
    assert_eq!(
        http(&app, None, "POST", "/settings/sent-copy", &off)
            .response
            .status_code,
        303
    );
    let mut wrong = off.clone();
    wrong.insert("csrf_token".into(), "invalid".into());
    assert_eq!(
        http(&app, Some(&alice), "POST", "/settings/sent-copy", &wrong)
            .response
            .status_code,
        403
    );
    assert_eq!(
        http(&app, Some(&bob), "POST", "/settings/sent-copy", &off)
            .response
            .status_code,
        403
    );
    let mut invalid = off.clone();
    invalid.insert("save_sent".into(), "invalid".into());
    assert_eq!(
        http(&app, Some(&alice), "POST", "/settings/sent-copy", &invalid)
            .response
            .status_code,
        400
    );
    let mut oversized = off.clone();
    oversized.insert("save_sent".into(), "x".repeat(1024));
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sent-copy",
            &oversized
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        preferences.load(ALICE).unwrap(),
        crate::sent_copy::Preference::default()
    );
    let saved_off = http(&app, Some(&alice), "POST", "/settings/sent-copy", &off);
    assert_eq!(saved_off.response.status_code, 303);
    assert_eq!(
        preferences.load(ALICE).unwrap(),
        crate::sent_copy::Preference {
            revision: 1,
            save_sent: false
        }
    );
    assert_eq!(
        http(&app, Some(&alice), "POST", "/settings/sent-copy", &off)
            .response
            .status_code,
        409
    );
    let restarted = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config)
            .with_fixture_sendmail_path(sendmail.clone()),
    );
    let reload = get(&restarted, &alice, "/settings?section=copies");
    assert_eq!(reload.response.status_code, 200);
    let mut on = copy_fields(text(&reload));
    assert_eq!(on.get("expected_revision").map(String::as_str), Some("1"));
    assert_eq!(on.get("save_sent").map(String::as_str), Some("off"));
    on.insert("save_sent".into(), "on".into());
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::sent_copy::Preference::default()
    );
    assert!(fs::read(&unrelated_path).unwrap() == unrelated_before);
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);

    let sentinel_page = get(&restarted, &alice, "/compose");
    assert_eq!(sentinel_page.response.status_code, 200);
    let mut sentinel_fields = compose_fields(text(&sentinel_page));
    sentinel_fields.insert("to".into(), ALICE.into());
    sentinel_fields.insert(
        "subject".into(),
        "Unrelated Save Sent native saved draft".into(),
    );
    sentinel_fields.insert("body".into(), "Preserved unrelated public draft.".into());
    let sentinel_saved = compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &sentinel_fields,
        false,
    );
    assert_eq!(sentinel_saved.response.status_code, 303);
    let sentinel_url = location(&sentinel_saved);
    let sentinel_resume = get(&restarted, &alice, &sentinel_url);
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

    let draft_page = get(&restarted, &alice, "/compose");
    assert_eq!(draft_page.response.status_code, 200);
    let mut draft_fields = compose_fields(text(&draft_page));
    draft_fields.insert("to".into(), ALICE.into());
    draft_fields.insert("bcc".into(), BOB.into());
    draft_fields.insert("subject".into(), "Save Sent Off Draft Native".into());
    draft_fields.insert("body".into(), PUBLIC_BODY.into());
    let saved = compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &draft_fields,
        true,
    );
    assert_eq!(saved.response.status_code, 303);
    let draft_url = location(&saved);
    let resume = get(&restarted, &alice, &draft_url);
    assert_eq!(resume.response.status_code, 200);
    let resumed = compose_fields(text(&resume));
    assert!(resumed.get("body").map(String::as_str) == Some(PUBLIC_BODY));
    assert!(resumed.get("bcc").map(String::as_str) == Some(BOB));
    assert!(text(&resume).contains("save_sent-public.txt"));
    let draft_id = resumed.get("draft_id").unwrap().clone();
    let draft_before = draft_store
        .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    let mut stale_draft = resumed.clone();
    let revision = resumed
        .get("draft_revision")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    stale_draft.insert("draft_revision".into(), (revision + 1).to_string());
    assert_eq!(
        compose_post(&restarted, Some(&alice), "/send", &stale_draft, false)
            .response
            .status_code,
        409
    );
    let mut bad_send = resumed.clone();
    bad_send.insert("csrf_token".into(), "invalid".into());
    assert_eq!(
        compose_post(&restarted, Some(&alice), "/send", &bad_send, false)
            .response
            .status_code,
        403
    );
    assert_eq!(
        compose_post(&restarted, Some(&bob), "/send", &resumed, false)
            .response
            .status_code,
        403
    );
    assert!(
        draft_store
            .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .as_ref()
            == Some(&draft_before)
    );
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
    let intent = resumed.get("send_intent").unwrap();
    let submitted_off = thread::scope(|scope| {
        let sending =
            scope.spawn(|| compose_post(&restarted, Some(&alice), "/send", &resumed, false));
        let release_guard = ReleaseReservedSend(release.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pending.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            pending.exists(),
            "sendmail pre-SMTP barrier must actually be reached"
        );
        assert_journal(
            &app_config.state_layout.settings_dir,
            intent,
            "reserved",
            Some(false),
        );
        assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
        let changed = http(&app, Some(&alice), "POST", "/settings/sent-copy", &on);
        assert_eq!(changed.response.status_code, 303);
        assert_eq!(
            preferences.load(ALICE).unwrap(),
            crate::sent_copy::Preference {
                revision: 2,
                save_sent: true
            }
        );
        assert!(fs::read(&unrelated_path).unwrap() == unrelated_before);
        assert_journal(
            &app_config.state_layout.settings_dir,
            intent,
            "reserved",
            Some(false),
        );
        drop(release_guard);
        sending.join().unwrap()
    });
    assert_eq!(submitted_off.response.status_code, 303);
    let off_receipt_url = location(&submitted_off);
    assert!(off_receipt_url.starts_with("/compose?receipt="));
    let reconstructed = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config)
            .with_fixture_sendmail_path(sendmail.clone()),
    );
    let off_receipt = get(&reconstructed, &alice, &off_receipt_url);
    assert_eq!(off_receipt.response.status_code, 200);
    assert_off_receipt(text(&off_receipt));
    let source_href = recovery_href(text(&off_receipt), "recovery_body");
    let file_href = recovery_href(text(&off_receipt), "recovery_attachment");
    let source = get(&reconstructed, &alice, &source_href);
    let file = get(&reconstructed, &alice, &file_href);
    assert_eq!(source.response.status_code, 200);
    assert_eq!(file.response.status_code, 200);
    assert!(source.response.body == PUBLIC_BODY.as_bytes());
    assert!(file.response.body == PUBLIC_ATTACHMENT);
    assert!(get(&reconstructed, &bob, &source_href).response.status_code >= 400);
    assert!(get(&reconstructed, &bob, &file_href).response.status_code >= 400);
    assert_journal(
        &app_config.state_layout.settings_dir,
        intent,
        "accepted_without_sent_copy",
        Some(false),
    );
    let journal = crate::send_journal::SendJournal::new(
        app_config.state_layout.settings_dir.join("send-journal"),
    );
    assert_eq!(
        journal
            .receipt(ALICE, intent, SystemTimeProvider.unix_timestamp())
            .unwrap(),
        Some(crate::send_journal::AttemptOutcome::AcceptedWithoutSentCopy)
    );
    assert!(journal
        .receipt(BOB, intent, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 0);
    assert!(list.list_messages(ALICE, &sent).unwrap() == sent_before);
    assert!(scoped_delete_wire_bytes(&root, "alice", ".Sent") == neighbour_bytes);
    assert_eq!(
        get(&reconstructed, &alice, &draft_url).response.status_code,
        404
    );
    let now = SystemTimeProvider.unix_timestamp();
    assert!(draft_store.load(ALICE, &draft_id, now).unwrap().is_none());
    assert!(draft_store.load(ALICE, &sentinel_id, now).unwrap().as_ref() == Some(&sentinel_before));
    let replay = compose_post(&reconstructed, Some(&alice), "/send", &resumed, false);
    assert!(matches!(replay.response.status_code, 200 | 303));
    assert_off_receipt(text(&get(&reconstructed, &alice, &off_receipt_url)));
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 0);

    // A distinct fresh intent sees the persisted On preference and stores once.
    let fresh = get(&reconstructed, &alice, "/compose");
    assert_eq!(fresh.response.status_code, 200);
    let mut fields = compose_fields(text(&fresh));
    assert_eq!(
        fields.get("pgp_binding_revision"),
        Some(&binding.revision.to_string())
    );
    fields.insert("to".into(), ALICE.into());
    fields.insert("bcc".into(), BOB.into());
    fields.insert("subject".into(), "Save Sent On Fresh Native".into());
    fields.insert("body".into(), PUBLIC_BODY.into());
    assert!(!fields
        .keys()
        .any(|key| matches!(key.as_str(), "pgp_sign" | "pgp_encrypt" | "pgp_self")));
    let submitted_on = compose_post(&reconstructed, Some(&alice), "/send", &fields, true);
    assert_eq!(submitted_on.response.status_code, 303);
    let on_receipt_url = location(&submitted_on);
    let on_receipt = get(&reconstructed, &alice, &on_receipt_url);
    assert_eq!(on_receipt.response.status_code, 200);
    assert!(
        text(&on_receipt).contains("A copy was saved in Sent")
            && text(&on_receipt).contains("Delivery to the recipient is not yet confirmed")
    );
    assert_journal(
        &app_config.state_layout.settings_dir,
        fields.get("send_intent").unwrap(),
        "accepted_stored",
        None,
    );
    let final_sent = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(final_sent.len(), 2);
    let row = final_sent
        .iter()
        .find(|row| row.subject.as_deref() == Some("Save Sent On Fresh Native"))
        .unwrap();
    assert_sent_read(&reconstructed, &alice, &bob, row, &bob_sent_before);
    assert!(final_sent.iter().any(|row| row.uid == sent_before[0].uid
        && row.metadata == sent_before[0].metadata
        && row.flags == sent_before[0].flags));
    let again = compose_post(&reconstructed, Some(&alice), "/send", &fields, true);
    assert!(matches!(again.response.status_code, 200 | 303));
    assert_off_receipt(text(&get(&reconstructed, &alice, &off_receipt_url)));
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    let captured = records.lock().unwrap().clone();
    assert_eq!(captured.len(), 2);
    let stored_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    assert!(
        stored_bytes
            .iter()
            .any(|wire| wire == &maildir_lf(&captured[1].wire)),
        "On SMTP bytes match real authoritative Sent"
    );
    assert!(
        !stored_bytes
            .iter()
            .any(|wire| wire == &maildir_lf(&captured[0].wire)),
        "Off SMTP bytes have no Sent object"
    );
    for capture in &captured {
        assert!(
            capture.recipients.contains(&ALICE.to_string())
                && capture.recipients.contains(&BOB.to_string())
                && capture.recipients.len() == 2
        );
        let headers = capture
            .wire
            .split(|byte| *byte == b'\n')
            .take_while(|line| !line.is_empty() && *line != b"\r");
        assert!(!headers
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
    assert!(fs::read(&unrelated_path).unwrap() == unrelated_before);
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::sent_copy::Preference::default()
    );
    assert!(
        draft_store
            .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .as_ref()
            == Some(&sentinel_before)
    );
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_save_sent_generated_copies_form=PASS default_on_persisted_off_restart=PASS csrf_foreign_invalid_stale_preserve=PASS durable_reserved_off_before_smtp=PASS generated_on_change_after_reservation=PASS off_normal_runtime_smtp_one_append_zero=PASS off_real_dovecot_sent_unchanged=PASS off_truthful_receipt_reconstructed_replay=PASS exact_consumed_draft_cleanup_sentinel_preserved=PASS on_normal_runtime_real_authenticated_sent_one=PASS finite_two_submissions_one_append=PASS sent_reader_download_current_stale_foreign_guids=PASS bcc_neighbour_bytes_flags_guids_preserved=PASS no_move_expunge_flag_private_crypto=PASS scratch_and_standard_metadata_unchanged=PASS");
}

fn copy_fields(body: &str) -> BTreeMap<String, String> {
    let form = body
        .split_once("<form id=\"copies-sent-copy-form\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains("method=\"post\"") && form.contains("action=\"/settings/sent-copy\""));
    let mut fields = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split_once('>').unwrap().0;
        let name = attribute(tag, "name").unwrap();
        assert!(fields
            .insert(name, attribute(tag, "value").unwrap_or_default())
            .is_none());
    }
    let select = form
        .split_once("<select id=\"copies-save-sent\"")
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0;
    assert!(select.contains("name=\"save_sent\""));
    let selected: Vec<_> = select
        .split("<option ")
        .skip(1)
        .filter_map(|option| {
            let tag = option.split_once('>')?.0;
            tag.contains(" selected")
                .then(|| attribute(tag, "value"))
                .flatten()
        })
        .collect();
    assert_eq!(selected.len(), 1);
    fields.insert("save_sent".into(), selected[0].clone());
    assert_eq!(fields.len(), 3);
    fields
}

fn assert_journal(settings: &std::path::Path, intent: &str, state: &str, captured: Option<bool>) {
    // Read only the actual private metadata store in memory; never emit its
    // contents, intent, CSRF, session or prepared body to retained evidence.
    let bytes = crate::private_account_file::PrivateAccountFile::new(
        settings.join("send-journal"),
        "osmap-send-journal-v1",
        128 * 1024,
    )
    .read(ALICE)
    .unwrap()
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let entry = value
        .get("attempts")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry.get("intent").and_then(serde_json::Value::as_str) == Some(intent))
        .unwrap();
    assert_eq!(
        entry.get("state").and_then(serde_json::Value::as_str),
        Some(state)
    );
    assert_eq!(
        entry
            .get("sent_copy_requested")
            .and_then(serde_json::Value::as_bool),
        captured
    );
}

fn assert_off_receipt(body: &str) {
    assert!(body.contains("Sent copy was not requested for this attempt"));
    assert!(body.contains("No Sent append was invoked"));
    assert!(body.contains("Delivery is not confirmed"));
    assert!(!body.contains("A copy was saved in Sent"));
}

fn recovery_href(body: &str, field: &str) -> String {
    body.split("<a ")
        .find_map(|anchor| {
            let tag = anchor.split_once('>')?.0;
            let href = attribute(tag, "href")?;
            let (path, query) = href.split_once('?')?;
            let fields = crate::http_form::parse_urlencoded_form(query.as_bytes(), 4, 2048).ok()?;
            (path == "/compose" && fields.contains_key("receipt") && fields.contains_key(field))
                .then_some(href)
        })
        .expect("actual generated owned exact attempt download link")
}

struct ReleaseReservedSend(PathBuf);
impl Drop for ReleaseReservedSend {
    fn drop(&mut self) {
        // Also releases the finite child process when a parent assertion fails.
        let _ = fs::write(&self.0, b"release owned synthetic reservation\n");
    }
}
