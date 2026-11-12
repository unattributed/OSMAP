//! Opt-in generated Reply/Reply all/Forward submission from a real owned origin.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Origin uploaded public fixture.";
const PUBLIC_BODY: &str = "Harmless origin native body café.";
const DESK: &str = "desk@fixture.test";
const OTHER: &str = "other@fixture.test";
const COPIED: &str = "copied@fixture.test";
const SOURCE_BCC: &str = "hidden-source@fixture.test";
const SOURCE_ATTACHMENT: &[u8] = b"Origin source public fixture.";
const ORIGIN_ID: &str = "<origin-native@fixture.test>";
const ROOT_ID: &str = "<root-origin@fixture.test>";
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
            call < 3,
            "fixture permits exactly three Sent saves, never replay"
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
            backend: "origin-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn origin_helper(
    fixture: &mut Fixture,
    native: NativeExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("origin-helper.sock");
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
                Err(_) => panic!("origin native helper listener"),
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
fn origin_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
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
                        let mut captured = records.lock().unwrap();
                        assert!(captured.len() < 3, "no repeated SMTP admission");
                        recipients.sort();
                        assert_eq!(recipients, expected_recipients(captured.len()));
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
                    assert!([DESK, OTHER, COPIED, BOB].contains(&recipient));
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

fn origin_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    path: &str,
    fields: &BTreeMap<String, String>,
    upload: bool,
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-origin-native-boundary";
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
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"origin-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
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

fn expected_recipients(index: usize) -> Vec<String> {
    let mut values: Vec<String> = match index {
        0 => vec![DESK.into(), BOB.into()],
        1 => vec![DESK.into(), OTHER.into(), COPIED.into(), BOB.into()],
        2 => vec![BOB.into()],
        _ => panic!("origin SMTP outside exact three admissions"),
    };
    values.sort();
    values
}

fn write_origin(root: &Path) {
    let path = root.join("alice/Maildir/new/synthetic-000");
    let wire = format!(
        concat!(
            "From: Origin Bob <{bob}>\r\nReply-To: \"Reply, Desk\" <{desk}>\r\n",
            "To: Alice <{alice}>, Desk <desk@FIXTURE.TEST>, Other <{other}>\r\n",
            "Cc: {copied}, {other}, {alice}\r\nBcc: {bcc}\r\n",
            "Subject: Origin native public\r\nDate: Sat, 03 Oct 2026 00:00:00 +0000\r\n",
            "Message-ID: {id}\r\nReferences: {root_id}\r\nMIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=owned-origin\r\n\r\n",
            "--owned-origin\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{body}\r\n",
            "--owned-origin\r\nContent-Type: text/plain\r\n",
            "Content-Disposition: attachment; filename=origin-source-public.txt\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\nT3JpZ2luIHNvdXJjZSBwdWJsaWMgZml4dHVyZS4=\r\n",
            "--owned-origin--\r\n"
        ),
        bob = BOB,
        desk = DESK,
        alice = ALICE,
        other = OTHER,
        copied = COPIED,
        bcc = SOURCE_BCC,
        id = ORIGIN_ID,
        root_id = ROOT_ID,
        body = PUBLIC_BODY
    );
    fs::write(&path, wire).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn query_fields(href: &str) -> BTreeMap<String, String> {
    let target = href.strip_suffix("#reading-pane").unwrap_or(href);
    assert!(!target.contains('#'));
    crate::http_form::parse_urlencoded_form(
        target.split_once('?').unwrap().1.as_bytes(),
        crate::mail_navigation::MAIL_RETURN_MAX_FIELDS,
        2048,
    )
    .unwrap()
}

fn changed_query(href: &str, key: &str, value: &str) -> String {
    let mut fields = query_fields(href);
    assert!(fields.insert(key.into(), value.into()).is_some());
    let path = href.split_once('?').unwrap().0;
    let query = fields
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let changed = format!("{path}?{query}");
    assert_ne!(changed, href);
    assert_eq!(
        query_fields(&changed).get(key).map(String::as_str),
        Some(value)
    );
    changed
}

fn message_link(body: &str, mailbox: &str, uid: u64) -> String {
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
            let fields = query_fields(&href);
            (fields.get("selected_uid") == Some(&uid.to_string())
                && fields.get("selected_mailbox").map(String::as_str) == Some(mailbox)
                && fields.get("name").map(String::as_str) == Some(mailbox))
            .then_some(href)
        })
        .expect("actual GUID-bound mailbox subject link")
}

fn origin_action(body: &str, mode: &str, row: &MessageSummary) -> String {
    let version = &row.metadata.as_ref().unwrap().version;
    body.split("<a ")
        .find_map(|anchor| {
            let tag = anchor.split_once('>')?.0;
            let href = attribute(tag, "href")?;
            if href.split_once('?')?.0 != "/compose" {
                return None;
            }
            let fields = query_fields(&href);
            (fields.get("mode").map(String::as_str) == Some(mode)
                && fields.get("uid") == Some(&row.uid.to_string())
                && fields.get("mailbox").map(String::as_str) == Some("INBOX")
                && fields.get("mailbox_guid") == Some(&version.mailbox_guid)
                && fields.get("message_guid") == Some(&version.message_guid))
            .then_some(href)
        })
        .expect("actual currentGUID-bound reader reply/forward action")
}

fn select_original_attachment(body: &str, fields: &mut BTreeMap<String, String>) {
    let selected = body
        .split("<input ")
        .find_map(|part| {
            let tag = part.split_once('>')?.0;
            let name = attribute(tag, "name")?;
            (name == "include_original_attachment_1"
                && attribute(tag, "type").as_deref() == Some("checkbox"))
            .then(|| (name, attribute(tag, "value").unwrap()))
        })
        .expect("actual generated original attachment choice");
    // MimeAnalyzer numbers the root as 1; this owned multipart's second
    // leaf is the explicitly named public source attachment, hence 1.2.
    assert!(body.contains("origin-source-public.txt"));
    assert_eq!(selected.1, "1.2");
    assert!(fields.insert(selected.0, selected.1).is_none());
}

fn assert_sent_read(
    app: &BrowserApp<RuntimeBrowserGateway>,
    alice: &IssuedSession,
    bob: &IssuedSession,
    row: &MessageSummary,
    foreign_rows: &[MessageSummary],
    filename: &str,
    attachment_bytes: &[u8],
) {
    let listing = get(app, alice, "/mailbox?name=Sent");
    assert_eq!(listing.response.status_code, 200);
    assert!(!text(&listing).contains(SOURCE_BCC));
    let opening = message_link(text(&listing), "Sent", row.uid);
    let target = opening.strip_suffix("#reading-pane").unwrap();
    let fields = query_fields(&opening);
    let version = &row.metadata.as_ref().unwrap().version;
    assert_eq!(
        fields.get("selected_mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_eq!(
        fields.get("selected_message_guid"),
        Some(&version.message_guid)
    );
    let foreign = foreign_rows
        .iter()
        .find(|foreign| foreign.uid == row.uid)
        .expect("same UID distinct foreign Sent object");
    assert_ne!(foreign.metadata.as_ref().unwrap().version, *version);
    let read = get(app, alice, target);
    assert_eq!(read.response.status_code, 200);
    assert!(text(&read).contains(PUBLIC_BODY) && text(&read).contains(filename));
    assert!(!text(&read).contains(SOURCE_BCC));
    let download = text(&read)
        .split("<a ")
        .find_map(|part| {
            let (tag, content) = part.split_once('>')?;
            (content.split_once("</a>")?.0 == "Download")
                .then(|| attribute(tag, "href"))
                .flatten()
        })
        .expect("actual isolated Sent attachment Download");
    let downloaded = get(app, alice, &download);
    assert_eq!(downloaded.response.status_code, 200);
    assert_eq!(downloaded.response.body, attachment_bytes);
    assert!(downloaded
        .response
        .headers
        .iter()
        .any(|(name, value)| name == "Content-Disposition" && value.contains(filename)));
    assert_eq!(get(app, bob, &download).response.status_code, 409);
    for (who, path, label) in [
        (bob, target.to_string(), "foreign sameUID"),
        (
            alice,
            changed_query(target, "selected_message_guid", "stale-origin-sent"),
            "stale GUID",
        ),
    ] {
        let refused = get(app, who, &path);
        assert_eq!(refused.response.status_code, 200, "{label}");
        let pane = text(&refused)
            .split_once("<article id=\"reading-pane\"")
            .unwrap()
            .1
            .split_once("</article>")
            .unwrap()
            .0;
        assert!(
            pane.contains("id=\"reading-unavailable\"")
                && pane.contains("The selected message identity changed."),
            "{label}"
        );
        assert!(
            !pane.contains(PUBLIC_BODY) && !pane.contains("Download"),
            "{label}"
        );
    }
}

#[test]
#[ignore = "explicit OpenBSD generated origin submissions; isolated SMTP and Dovecot only"]
fn isolated_openbsd_generated_reply_all_forward_to_sink_with_authoritative_sent() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-origin-{}-{}",
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
    write_origin(&root);
    write_message(&root, "alice", 1, 0);
    fs::rename(
        root.join("alice/Maildir/new/synthetic-001"),
        root.join("alice/Maildir/.Sent/new/synthetic-001"),
    )
    .unwrap();
    write_message(&root, "bob", 0, 0);
    for index in 1..=4 {
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
    assert_eq!(bob_sent_before.len(), 4);
    let inbox_bytes = scoped_delete_wire_bytes(&root, "alice", "");
    let bob_bytes = scoped_delete_wire_bytes(&root, "bob", "");
    let bob_sent_bytes = scoped_delete_wire_bytes(&root, "bob", ".Sent");
    let neighbour_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    let appends = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = origin_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = origin_sink(&mut fixture, records.clone());
    let sendmail = root.join("owned-loopback-sendmail");
    fs::write(&sendmail, format!("#!/usr/local/bin/python3\nimport smtplib,sys\nassert sys.argv[1:3]==['-oi','-f'] and sys.argv[3]=={ALICE:?} and sys.argv[4]=='--'\nassert sorted(sys.argv[5:]) in [sorted([{DESK:?},{BOB:?}]),sorted([{DESK:?},{OTHER:?},{COPIED:?},{BOB:?}]),[{BOB:?}]]\ncontent=sys.stdin.buffer.read({})\nassert len(content)<={}\nwith smtplib.SMTP('127.0.0.1',{port},timeout=3) as client:\n    client.sendmail(sys.argv[3],sys.argv[5:],content)\n", MAX_FIXTURE_WIRE + 1, MAX_FIXTURE_WIRE)).unwrap();
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
        "native-origin-session",
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

    let origin_row = &alice_before[0];
    let origin_version = &origin_row.metadata.as_ref().unwrap().version;
    let inbox_page = get(&app, &alice, "/mailbox?name=INBOX");
    assert_eq!(inbox_page.response.status_code, 200);
    let origin_opening = message_link(text(&inbox_page), "INBOX", origin_row.uid);
    let opened_fields = query_fields(&origin_opening);
    assert_eq!(
        opened_fields.get("selected_mailbox_guid"),
        Some(&origin_version.mailbox_guid)
    );
    assert_eq!(
        opened_fields.get("selected_message_guid"),
        Some(&origin_version.message_guid)
    );
    let reader = get(
        &app,
        &alice,
        origin_opening.strip_suffix("#reading-pane").unwrap(),
    );
    assert_eq!(reader.response.status_code, 200);
    assert!(text(&reader).contains(PUBLIC_BODY));
    let actions: Vec<_> = ["reply", "reply-all", "forward"]
        .iter()
        .map(|mode| origin_action(text(&reader), mode, origin_row))
        .collect();
    assert_eq!(get(&app, &bob, &actions[0]).response.status_code, 409);
    let stale_origin = changed_query(&actions[0], "message_guid", "stale-origin-version");
    assert_eq!(get(&app, &alice, &stale_origin).response.status_code, 409);
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);

    let draft_store = crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default(),
    );
    let mut submitted_draft: Option<String> = None;
    for (index, (mode, opening)) in ["reply", "reply-all", "forward"]
        .iter()
        .zip(&actions)
        .enumerate()
    {
        let page = get(&app, &alice, opening);
        assert_eq!(page.response.status_code, 200, "generated {mode}");
        let mut fields = compose_fields(text(&page));
        assert_eq!(
            fields.get("pgp_binding_revision"),
            Some(&binding.revision.to_string())
        );
        assert!(fields.get("body").unwrap().contains(PUBLIC_BODY));
        assert!(!text(&page).contains(SOURCE_BCC));
        assert_eq!(fields.get("bcc").map(String::as_str), Some(""));
        if *mode == "forward" {
            assert_eq!(fields.get("to").map(String::as_str), Some(""));
            assert!(
                !fields.contains_key("reply_mailbox") && !fields.contains_key("reply_message_guid")
            );
            fields.insert("to".into(), BOB.into());
            select_original_attachment(text(&page), &mut fields);
            assert_eq!(
                fields.get("source_message_guid"),
                Some(&origin_version.message_guid)
            );
        } else {
            let expected_to = if *mode == "reply" {
                DESK.to_string()
            } else {
                format!("{DESK}, {OTHER}")
            };
            assert_eq!(fields.get("to"), Some(&expected_to));
            assert_eq!(
                fields.get("cc").map(String::as_str),
                Some(if *mode == "reply" { "" } else { COPIED })
            );
            assert_eq!(
                fields.get("reply_mailbox_guid"),
                Some(&origin_version.mailbox_guid)
            );
            assert_eq!(
                fields.get("reply_message_guid"),
                Some(&origin_version.message_guid)
            );
            assert_eq!(fields.get("reply_uid"), Some(&origin_row.uid.to_string()));
            fields.insert("bcc".into(), BOB.into());
        }
        assert!(!fields
            .keys()
            .any(|key| matches!(key.as_str(), "pgp_sign" | "pgp_encrypt" | "pgp_self")));
        let subject = format!("Origin native {mode}");
        fields.insert("subject".into(), subject.clone());
        let upload = *mode != "forward";
        if index == 0 {
            let mut forged_from = fields.clone();
            forged_from.insert("from".into(), BOB.into());
            assert_eq!(
                origin_post(&app, Some(&alice), "/send", &forged_from, upload)
                    .response
                    .status_code,
                400
            );
            let mut forged_thread = fields.clone();
            forged_thread.insert("in_reply_to".into(), "<forged-origin@fixture.test>".into());
            assert_eq!(
                origin_post(&app, Some(&alice), "/send", &forged_thread, upload)
                    .response
                    .status_code,
                400
            );
            let mut stale_thread = fields.clone();
            stale_thread.insert("reply_message_guid".into(), "stale-origin-thread".into());
            assert_eq!(
                origin_post(&app, Some(&alice), "/send", &stale_thread, upload)
                    .response
                    .status_code,
                409
            );
            let mut bad_csrf = fields.clone();
            bad_csrf.insert("csrf_token".into(), "invalid".into());
            assert_eq!(
                origin_post(&app, Some(&alice), "/send", &bad_csrf, upload)
                    .response
                    .status_code,
                403
            );
            assert_eq!(
                origin_post(&app, None, "/send", &fields, upload)
                    .response
                    .status_code,
                303
            );
            assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
        }
        if *mode == "reply-all" {
            let saved = origin_post(&app, Some(&alice), "/drafts/save", &fields, upload);
            assert_eq!(saved.response.status_code, 303);
            let draft_url = location(&saved);
            let resumed = get(&app, &alice, &draft_url);
            assert_eq!(resumed.response.status_code, 200);
            fields = compose_fields(text(&resumed));
            assert!(
                !fields.contains_key("reply_mailbox") && !fields.contains_key("reply_message_guid")
            );
            let id = fields.get("draft_id").unwrap().clone();
            let stored = draft_store
                .load(ALICE, &id, SystemTimeProvider.unix_timestamp())
                .unwrap()
                .unwrap();
            let thread = stored.request.reply_thread.as_ref().unwrap();
            assert_eq!(thread.in_reply_to(), Some(ORIGIN_ID));
            assert_eq!(thread.references(), format!("{ROOT_ID} {ORIGIN_ID}"));
            assert!(fields.get("body").unwrap().contains(PUBLIC_BODY));
            assert_eq!(fields.get("cc").map(String::as_str), Some(COPIED));
            let mut stale = fields.clone();
            let revision = fields
                .get("draft_revision")
                .unwrap()
                .parse::<u64>()
                .unwrap();
            stale.insert("draft_revision".into(), (revision + 1).to_string());
            assert_eq!(
                origin_post(&app, Some(&alice), "/send", &stale, false)
                    .response
                    .status_code,
                409
            );
            assert_eq!(records.lock().unwrap().len(), index);
            assert_eq!(appends.load(Ordering::SeqCst), index);
            submitted_draft = Some(id);
        }
        let send_upload = upload && *mode != "reply-all";
        let submitted = origin_post(&app, Some(&alice), "/send", &fields, send_upload);
        assert_eq!(submitted.response.status_code, 303, "{mode}");
        let receipt_url = location(&submitted);
        assert!(receipt_url.starts_with("/compose?receipt="));
        let receipt = get(&app, &alice, &receipt_url);
        assert_eq!(receipt.response.status_code, 200);
        assert!(
            text(&receipt).contains("A copy was saved in Sent")
                && text(&receipt).contains("Delivery to the recipient is not yet confirmed")
        );
        let now_sent = list.list_messages(ALICE, &sent).unwrap();
        assert_eq!(now_sent.len(), index + 2);
        let row = now_sent
            .iter()
            .find(|row| row.subject.as_deref() == Some(subject.as_str()))
            .unwrap();
        let (filename, bytes) = if *mode == "forward" {
            ("origin-source-public.txt", SOURCE_ATTACHMENT)
        } else {
            ("origin-public.txt", PUBLIC_ATTACHMENT)
        };
        assert_sent_read(&app, &alice, &bob, row, &bob_sent_before, filename, bytes);
        let replay = origin_post(&app, Some(&alice), "/send", &fields, send_upload);
        assert!(matches!(replay.response.status_code, 200 | 303));
        assert_eq!(appends.load(Ordering::SeqCst), index + 1);
        assert_eq!(records.lock().unwrap().len(), index + 1);
    }
    let id = submitted_draft.unwrap();
    assert!(draft_store
        .load(ALICE, &id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    let captured = records.lock().unwrap().clone();
    assert_eq!(captured.len(), 3);
    assert_eq!(appends.load(Ordering::SeqCst), 3);
    let stored_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    for (index, capture) in captured.iter().enumerate() {
        assert_eq!(capture.recipients, expected_recipients(index));
        assert!(
            stored_bytes
                .iter()
                .any(|wire| wire == &maildir_lf(&capture.wire)),
            "SMTP matches authoritative Sent under pinned CRLF-to-LF storage"
        );
        let wire = std::str::from_utf8(&capture.wire).unwrap();
        let headers = wire.split_once("\r\n\r\n").unwrap().0;
        assert!(headers.lines().any(|line| line == format!("From: {ALICE}")));
        assert!(!headers
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("bcc:")));
        assert!(!wire.contains(SOURCE_BCC));
        if index < 2 {
            assert_eq!(
                headers
                    .lines()
                    .filter(|line| line.starts_with("In-Reply-To:"))
                    .count(),
                1
            );
            assert!(headers
                .lines()
                .any(|line| line == format!("In-Reply-To: {ORIGIN_ID}")));
            assert!(headers
                .lines()
                .any(|line| line == format!("References: {ROOT_ID} {ORIGIN_ID}")));
            assert!(headers.lines().any(|line| line
                == format!(
                    "To: {}",
                    if index == 0 {
                        DESK.to_string()
                    } else {
                        format!("{DESK}, {OTHER}")
                    }
                )));
            if index == 1 {
                assert!(headers.lines().any(|line| line == format!("Cc: {COPIED}")));
            }
        } else {
            assert!(!headers
                .lines()
                .any(|line| line.starts_with("In-Reply-To:") || line.starts_with("References:")));
            assert!(headers.lines().any(|line| line == format!("To: {BOB}")));
        }
        assert!(
            !wire.contains("application/pgp-encrypted")
                && !wire.contains("application/pgp-signature")
        );
    }
    let final_sent = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(final_sent.len(), 4);
    assert!(final_sent.iter().any(|row| row.uid == sent_before[0].uid
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
    println!("native_origin_submission_browser=PASS actual_generated_reply_reply_all_forward_forms=PASS current_guid_origin_and_captured_draft_thread=PASS exact_recipient_roles_self_dedup_bcc_privacy=PASS forged_stale_foreign_origin_refused_before_transport=PASS normal_runtime_authenticated_append_real_dovecot_sent=PASS loopback_smtp_only_three_submissions=PASS reply_thread_forward_no_thread_actual_sent=PASS original_forward_attachment_exact_download=PASS replay_no_duplicate_submit_append=PASS neighbour_foreign_bytes_flags_guids_unchanged=PASS no_move_expunge_flag_private_crypto=PASS synthetic_session_not_login_proof=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
