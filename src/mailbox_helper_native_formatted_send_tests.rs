//! Opt-in formatted BrowserApp submission to a loopback sink and real owned Sent.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::http::BrowserGateway;
use crate::mailbox::MessageViewDecision;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Ordinary public fixture.";
const PUBLIC_BODY: &str = "Harmless formatted native body café.";
const PUBLIC_PNG: &[u8] = &[
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 4, 0,
    0, 0, 181, 28, 12, 2, 0, 0, 0, 11, 73, 68, 65, 84, 120, 218, 99, 252, 255, 31, 0, 3, 3, 2, 0,
    239, 163, 55, 91, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
];
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
            backend: "formatted-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn formatted_helper(
    fixture: &mut Fixture,
    native: NativeExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("formatted-helper.sock");
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
                Err(_) => panic!("formatted native helper listener"),
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
fn formatted_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
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
    let mode = form
        .split_once("<select id=\"compose-body-format\"")
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0
        .split("<option ")
        .skip(1)
        .find_map(|part| {
            let tag = part.split_once('>')?.0;
            tag.split_whitespace()
                .any(|field| field == "selected")
                .then(|| attribute(tag, "value").unwrap())
        })
        .unwrap();
    assert!(["plain", "formatted"].contains(&mode.as_str()));
    fields.insert("body_format".into(), mode);
    assert!(fields.contains_key("csrf_token") && fields.contains_key("send_intent"));
    assert_eq!(fields.get("from").map(String::as_str), Some(ALICE));
    fields
}

type FixtureUpload<'a> = (&'a str, &'a str, &'a str, &'a [u8]);

fn formatted_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    path: &str,
    fields: &BTreeMap<String, String>,
    uploads: &[FixtureUpload<'_>],
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-formatted-native-boundary";
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
    for (field, name, content_type, bytes) in uploads {
        assert!(["attachment", "image_attachment"].contains(field));
        assert!([
            "formatted-public.txt",
            "public-pixel.png",
            "invalid-public.png"
        ]
        .contains(name));
        assert!(["text/plain", "image/png"].contains(content_type));
        assert!(bytes.len() < 1024);
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\nContent-Type: {content_type}\r\n\r\n").as_bytes());
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let mut wire=format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/native-reader\r\nOrigin: http://localhost\r\nCookie: osmap_session={}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n",session.token.as_str(),body.len()).into_bytes();
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

fn generated_action(body: &str, action: &str) -> String {
    body.split("<button ")
        .find_map(|part| {
            let tag = part.split_once('>')?.0;
            (attribute(tag, "type").as_deref() == Some("submit")
                && attribute(tag, "formaction").as_deref() == Some("/drafts/save")
                && attribute(tag, "name").as_deref() == Some("compose_action")
                && attribute(tag, "value").as_deref() == Some(action))
            .then(|| attribute(tag, "value").unwrap())
        })
        .expect("actual generated native formatting/preview action")
}

fn select_text(fields: &mut BTreeMap<String, String>, text: &str) {
    let body = fields.get("body").unwrap();
    let start = body.find(text).expect("finite authored text selection");
    let end = start + text.len();
    let start_units = body[..start].encode_utf16().count();
    let end_units = body[..end].encode_utf16().count();
    fields.insert("format_start".into(), start_units.to_string());
    fields.insert("format_end".into(), end_units.to_string());
}

fn saved_page(
    app: &BrowserApp<RuntimeBrowserGateway>,
    alice: &IssuedSession,
    saved: &HandledHttpResponse,
) -> HandledHttpResponse {
    assert_eq!(saved.response.status_code, 303);
    let url = location(saved);
    assert!(url.starts_with("/draft?id="));
    let response = get(app, alice, &url);
    assert_eq!(response.response.status_code, 200);
    response
}

fn stored_draft(
    store: &crate::draft::FileDraftStore,
    fields: &BTreeMap<String, String>,
) -> crate::draft::DraftRecord {
    store
        .load(
            ALICE,
            fields.get("draft_id").unwrap(),
            SystemTimeProvider.unix_timestamp(),
        )
        .unwrap()
        .unwrap()
}

fn analyse_wire(wire: &[u8], uid: u64) -> crate::mime::MimeAnalysis {
    let normalized = String::from_utf8(maildir_lf(wire)).unwrap();
    let (headers, body) = normalized.split_once("\n\n").unwrap();
    crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&crate::mailbox::MessageView {
            metadata: None,
            mailbox_name: "Sent".into(),
            uid,
            flags: Vec::new(),
            date_received: String::new(),
            size_virtual: wire.len() as u64,
            header_block: headers.into(),
            body_text: body.into(),
        })
        .unwrap()
}

fn assert_alternatives(
    analysis: &crate::mime::MimeAnalysis,
    expected: &crate::compose_format::FormattedBody,
) {
    assert_eq!(analysis.top_level_content_type, "multipart/mixed");
    assert_eq!(
        analysis
            .selected_plain_text_body
            .as_ref()
            .unwrap()
            .replace("\r\n", "\n"),
        expected.plain
    );
    assert_eq!(
        analysis
            .selected_html_body
            .as_ref()
            .unwrap()
            .replace("\r\n", "\n"),
        expected.html
    );
    assert_eq!(analysis.attachments.len(), 2);
    assert!(analysis
        .attachments
        .iter()
        .any(
            |part| part.filename.as_deref() == Some("formatted-public.txt")
                && part.content_type == "text/plain"
        ));
    assert!(analysis
        .attachments
        .iter()
        .any(|part| part.filename.as_deref() == Some("public-pixel.png")
            && part.content_type == "image/png"));
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
            if target.split_once('?')?.0 != "/mailbox" {
                return None;
            }
            let fields = crate::http_form::parse_urlencoded_form(
                target.split_once('?')?.1.as_bytes(),
                crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
                2048,
            )
            .ok()?;
            (fields.get("selected_uid") == Some(&uid.to_string())
                && fields.get("selected_mailbox").map(String::as_str) == Some("Sent"))
            .then_some(href)
        })
        .expect("actual native Sent GUID-bound subject")
}

#[test]
#[ignore = "explicit OpenBSD generated formatting and MIME submission; local SMTP and owned Sent only"]
fn isolated_openbsd_generated_formatted_preview_to_sink_with_authoritative_sent() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-formatted-{}-{}",
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
    for index in 1..=2 {
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
    assert_eq!(bob_sent_before.len(), 2);
    let inbox_bytes = scoped_delete_wire_bytes(&root, "alice", "");
    let bob_bytes = scoped_delete_wire_bytes(&root, "bob", "");
    let bob_sent_bytes = scoped_delete_wire_bytes(&root, "bob", ".Sent");
    let neighbour_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    let appends = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = formatted_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = formatted_sink(&mut fixture, records.clone());
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
        "native-formatted-session",
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
    fields.insert("to".into(), ALICE.into());
    fields.insert("bcc".into(), BOB.into());
    fields.insert(
        "subject".into(),
        "Formatted native generated actions".into(),
    );
    fields.insert(
        "body".into(),
        format!("{PUBLIC_BODY}\nLead café 🦊\nOne item\nTwo item\nVisit site\n<literal>"),
    );
    assert_eq!(
        fields.get("pgp_binding_revision"),
        Some(&binding.revision.to_string())
    );
    let bold = generated_action(text(&page), "format-bold");
    fields.insert("compose_action".into(), bold);
    select_text(&mut fields, "Lead café 🦊");
    let uploaded = [(
        "attachment",
        "formatted-public.txt",
        "text/plain",
        PUBLIC_ATTACHMENT,
    )];
    let first = formatted_post(&app, &alice, "/drafts/save", &fields, &uploaded);
    let mut current_page = saved_page(&app, &alice, &first);
    fields = compose_fields(text(&current_page));
    assert_eq!(
        fields.get("body_format").map(String::as_str),
        Some("formatted")
    );
    assert!(fields.get("body").unwrap().contains("**Lead café 🦊**"));
    let store = crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default(),
    );
    let initial = stored_draft(&store, &fields);
    assert_eq!(initial.request.attachments.len(), 1);
    assert_eq!(initial.request.attachments[0].body, PUBLIC_ATTACHMENT);

    fields.insert(
        "compose_action".into(),
        generated_action(text(&current_page), "format-bullets"),
    );
    select_text(&mut fields, "One item\nTwo item");
    let bullets = formatted_post(&app, &alice, "/drafts/save", &fields, &[]);
    current_page = saved_page(&app, &alice, &bullets);
    fields = compose_fields(text(&current_page));
    assert!(fields
        .get("body")
        .unwrap()
        .contains("\n- One item\n- Two item\nVisit site\n"));
    assert_eq!(
        stored_draft(&store, &fields).request.attachments,
        initial.request.attachments
    );

    fields.insert(
        "compose_action".into(),
        generated_action(text(&current_page), "format-link"),
    );
    select_text(&mut fields, "Visit site");
    fields.insert(
        "format_url".into(),
        "https://example.invalid/public?a=1&b=2".into(),
    );
    fields.insert("format_label".into(), "Visit site".into());
    let link = formatted_post(&app, &alice, "/drafts/save", &fields, &[]);
    current_page = saved_page(&app, &alice, &link);
    fields = compose_fields(text(&current_page));
    assert!(fields
        .get("body")
        .unwrap()
        .contains("[Visit site](https://example.invalid/public?a=1&b=2)"));

    fields.insert(
        "compose_action".into(),
        generated_action(text(&current_page), "format-emoji"),
    );
    let emoji = formatted_post(&app, &alice, "/drafts/save", &fields, &[]);
    current_page = saved_page(&app, &alice, &emoji);
    fields = compose_fields(text(&current_page));
    assert!(fields.get("body").unwrap().ends_with("<literal>🙂"));
    assert_eq!(
        stored_draft(&store, &fields).request.attachments,
        initial.request.attachments
    );
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);

    let image_button = text(&current_page)
        .split("<button ")
        .find_map(|part| {
            let (tag, content) = part.split_once('>')?;
            (content.split_once("</button>")?.0 == "Save image attachment")
                .then(|| attribute(tag, "formaction").unwrap())
        })
        .expect("actual generated Save image attachment action");
    assert_eq!(image_button, "/drafts/save");
    let image_upload = [(
        "image_attachment",
        "public-pixel.png",
        "image/png",
        PUBLIC_PNG,
    )];
    let image_saved = formatted_post(&app, &alice, &image_button, &fields, &image_upload);
    current_page = saved_page(&app, &alice, &image_saved);
    fields = compose_fields(text(&current_page));
    let with_image = stored_draft(&store, &fields);
    assert_eq!(with_image.request.attachments.len(), 2);
    assert_eq!(
        with_image.request.attachments[0],
        initial.request.attachments[0]
    );
    let image = with_image
        .request
        .attachments
        .iter()
        .find(|file| file.filename == "public-pixel.png")
        .unwrap();
    assert_eq!(image.content_type, "image/png");
    assert_eq!(image.body, PUBLIC_PNG);

    fields.insert(
        "compose_action".into(),
        generated_action(text(&current_page), "preview"),
    );
    let preview_saved = formatted_post(&app, &alice, "/drafts/save", &fields, &[]);
    current_page = saved_page(&app, &alice, &preview_saved);
    fields = compose_fields(text(&current_page));
    let prepared = stored_draft(&store, &fields);
    assert_eq!(prepared.request.attachments, with_image.request.attachments);
    let alternatives = crate::compose_format::render(&prepared.request.body).unwrap();
    assert!(alternatives.html.contains("<strong>Lead café 🦊</strong>"));
    assert!(
        alternatives.html.contains("<li>One item</li>")
            && alternatives.html.contains("<li>Two item</li>")
    );
    assert!(alternatives
        .html
        .contains("https://example.invalid/public?a=1&amp;b=2"));
    assert!(
        alternatives.html.contains("&lt;literal&gt;🙂") && !alternatives.html.contains("<literal>")
    );
    assert!(
        text(&current_page).contains("Message preview")
            && text(&current_page).contains(&alternatives.html)
    );
    assert!(text(&current_page).contains(&format!(
        "<pre dir=\"auto\">{}</pre>",
        crate::http_support::escape_html(&alternatives.plain)
    )));
    assert!(
        !text(&current_page).contains("<img src=\"https://")
            && !text(&current_page).contains("<iframe")
    );
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);

    let mut invalid_link = fields.clone();
    invalid_link.insert(
        "compose_action".into(),
        generated_action(text(&current_page), "format-link"),
    );
    select_text(&mut invalid_link, "Lead café 🦊");
    invalid_link.insert("format_url".into(), "javascript:invalid".into());
    invalid_link.insert("format_label".into(), "public invalid link".into());
    let refused = formatted_post(&app, &alice, "/drafts/save", &invalid_link, &[]);
    assert_eq!(refused.response.status_code, 400);
    assert!(text(&refused).contains(&format!(
        ">\n{}</textarea>",
        crate::http_support::escape_html(&prepared.request.body)
    )));
    assert_eq!(stored_draft(&store, &fields), prepared);
    let invalid_image = [(
        "image_attachment",
        "invalid-public.png",
        "image/png",
        b"This is not a PNG".as_slice(),
    )];
    let refused_image = formatted_post(&app, &alice, "/drafts/save", &fields, &invalid_image);
    assert_eq!(refused_image.response.status_code, 400);
    assert!(text(&refused_image).contains(&format!(
        ">\n{}</textarea>",
        crate::http_support::escape_html(&prepared.request.body)
    )));
    assert_eq!(stored_draft(&store, &fields), prepared);
    let mut invalid_format = fields.clone();
    invalid_format.insert("body".into(), "[public](javascript:invalid)".into());
    let refused_send = formatted_post(&app, &alice, "/send", &invalid_format, &[]);
    assert_eq!(refused_send.response.status_code, 400);
    assert!(text(&refused_send).contains("[public](javascript:invalid)"));
    assert_eq!(stored_draft(&store, &fields), prepared);
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);

    let draft_id = fields.get("draft_id").unwrap().clone();
    let sent_response = formatted_post(&app, &alice, "/send", &fields, &[]);
    assert_eq!(sent_response.response.status_code, 303);
    let receipt = get(&app, &alice, &location(&sent_response));
    assert_eq!(receipt.response.status_code, 200);
    assert!(
        text(&receipt).contains("A copy was saved in Sent")
            && text(&receipt).contains("Delivery to the recipient is not yet confirmed")
    );
    let actual_sent = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(actual_sent.len(), 2);
    let row = actual_sent
        .iter()
        .find(|row| row.subject.as_deref() == Some("Formatted native generated actions"))
        .unwrap();
    let version = &row.metadata.as_ref().unwrap().version;
    let sent_listing = get(&app, &alice, "/mailbox?name=Sent");
    assert_eq!(sent_listing.response.status_code, 200);
    assert!(!text(&sent_listing).contains(BOB));
    let opening = message_link(text(&sent_listing), row.uid);
    let target = opening.strip_suffix("#reading-pane").unwrap();
    let opening_fields = crate::http_form::parse_urlencoded_form(
        target.split_once('?').unwrap().1.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap();
    assert_eq!(
        opening_fields.get("selected_mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_eq!(
        opening_fields.get("selected_message_guid"),
        Some(&version.message_guid)
    );
    let reader = get(&app, &alice, target);
    assert_eq!(reader.response.status_code, 200);
    assert!(text(&reader).contains(PUBLIC_BODY) && text(&reader).contains("public-pixel.png"));
    let foreign_version = &bob_sent_before
        .iter()
        .find(|foreign| foreign.uid == row.uid)
        .unwrap()
        .metadata
        .as_ref()
        .unwrap()
        .version;
    assert_ne!(foreign_version, version);
    let mut stale_fields = opening_fields.clone();
    stale_fields.insert(
        "selected_message_guid".into(),
        "stale-formatted-sent".into(),
    );
    let stale_query = stale_fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let stale = format!("/mailbox?{stale_query}");
    assert_ne!(stale, target);
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
        Some("stale-formatted-sent")
    );
    for refused in [get(&app, &bob, target), get(&app, &alice, &stale)] {
        assert_eq!(refused.response.status_code, 200);
        let pane = text(&refused)
            .split_once("<article id=\"reading-pane\"")
            .unwrap()
            .1
            .split_once("</article>")
            .unwrap()
            .0;
        assert!(
            pane.contains("id=\"reading-unavailable\"")
                && pane.contains("The selected message identity changed.")
        );
        assert!(!pane.contains(PUBLIC_BODY) && !pane.contains("Download"));
    }
    let downloads: Vec<_> = text(&reader)
        .split("<a ")
        .filter_map(|part| {
            let (tag, content) = part.split_once('>')?;
            (content.split_once("</a>")?.0 == "Download")
                .then(|| attribute(tag, "href"))
                .flatten()
        })
        .collect();
    assert_eq!(downloads.len(), 2);
    let mut downloaded_names = Vec::new();
    for href in &downloads {
        let downloaded = get(&app, &alice, href);
        assert_eq!(downloaded.response.status_code, 200);
        let disposition = downloaded
            .response
            .headers
            .iter()
            .find(|(name, _)| name == "Content-Disposition")
            .unwrap()
            .1
            .as_str();
        if disposition.contains("public-pixel.png") {
            assert_eq!(downloaded.response.body, PUBLIC_PNG);
            assert!(downloaded
                .response
                .headers
                .iter()
                .any(|(name, value)| name == "Content-Type" && value == "image/png"));
            downloaded_names.push("image");
        } else {
            assert!(disposition.contains("formatted-public.txt"));
            assert_eq!(downloaded.response.body, PUBLIC_ATTACHMENT);
            downloaded_names.push("text");
        }
        assert_eq!(get(&app, &bob, href).response.status_code, 409);
    }
    downloaded_names.sort();
    assert_eq!(downloaded_names, vec!["image", "text"]);

    let validated = sessions.validate(&context, &alice.token).unwrap();
    let inspection = RuntimeBrowserGateway::from_config(&app_config);
    let source_request =
        MessageViewRequest::new(MessageViewPolicy::default(), "Sent", row.uid).unwrap();
    let source = inspection.read_message_source(&context, &validated, &source_request);
    let source = match source.decision {
        MessageViewDecision::Retrieved {
            canonical_username,
            session_id,
            message,
        } => {
            assert_eq!(canonical_username, ALICE);
            assert_eq!(session_id, validated.record.session_id);
            assert_eq!(message.metadata.as_ref().unwrap().version, *version);
            assert_eq!(message.mailbox_name, "Sent");
            assert_eq!(message.uid, row.uid);
            message
        }
        MessageViewDecision::Denied { .. } => {
            panic!("actual authenticated Sent MIME source unavailable")
        }
    };
    let stored_analysis =
        crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
            .analyze_message(&source)
            .unwrap();
    assert_alternatives(&stored_analysis, &alternatives);
    let captured = records.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert!(
        captured[0].recipients.contains(&ALICE.to_string())
            && captured[0].recipients.contains(&BOB.to_string())
    );
    let sink_analysis = analyse_wire(&captured[0].wire, row.uid);
    assert_alternatives(&sink_analysis, &alternatives);
    let stored_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    assert!(stored_bytes
        .iter()
        .any(|wire| wire == &maildir_lf(&captured[0].wire)));
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
    let replay = formatted_post(&app, &alice, "/send", &fields, &[]);
    assert!(matches!(replay.response.status_code, 200 | 303));
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(records.lock().unwrap().len(), 1);
    assert!(store
        .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    assert!(actual_sent.iter().any(|row| row.uid == sent_before[0].uid
        && row.metadata == sent_before[0].metadata
        && row.flags == sent_before[0].flags));
    assert!(stored_bytes.iter().any(|wire| wire == &neighbour_bytes[0]));
    assert_eq!(list.list_messages(ALICE, &inbox).unwrap(), alice_before);
    assert_eq!(list.list_messages(BOB, &inbox).unwrap(), bob_before);
    assert_eq!(list.list_messages(BOB, &sent).unwrap(), bob_sent_before);
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ""), inbox_bytes);
    assert_eq!(scoped_delete_wire_bytes(&root, "bob", ""), bob_bytes);
    assert_eq!(
        scoped_delete_wire_bytes(&root, "bob", ".Sent"),
        bob_sent_bytes
    );
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_formatted_submission_browser=PASS actual_generated_bold_list_link_emoji_image_preview_actions=PASS utf16_unicode_selection_and_exact_retained_blobs=PASS actual_persisted_preview_plain_html_alternatives=PASS invalid_link_image_format_refused_without_mutation=PASS normal_runtime_local_smtp_authenticated_real_sent=PASS smtp_sent_mime_equal_preview_alternatives=PASS exact_png_public_attachment_downloads=PASS bcc_envelope_not_headers=PASS replay_exactly_one_submit_append=PASS neighbour_foreign_bytes_flags_guids_unchanged=PASS no_move_expunge_flag_private_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
