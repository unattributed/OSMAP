//! Opt-in generated Sent location form, durable choice and real owned Sent storage.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Sent location public fixture.";
const PUBLIC_BODY: &str = "Harmless sent_location native body café.";
const MAX_FIXTURE_WIRE: usize = 64 * 1024;
const TARGET_A: &str = "INBOX.SentCopyA";
const TARGET_B: &str = "INBOX.SentCopyB";

#[derive(Clone)]
struct ScopedAppendExecutor {
    config: PathBuf,
    expected: Vec<String>,
    appends: Arc<AtomicUsize>,
    status_calls: Arc<AtomicUsize>,
    guard_steps: Arc<Mutex<Vec<&'static str>>>,
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
        if a.first().map(String::as_str) == Some("exec") {
            let expected = vec![
                "exec".into(),
                "imap".into(),
                "-o".into(),
                "stats_writer_socket_path=".into(),
                "-o".into(),
                self.expected[3].clone(),
                "-u".into(),
                ALICE.into(),
            ];
            assert!(a == expected.as_slice());
            assert!(input == crate::folder_metadata_backend::TRANSCRIPT);
            assert!(timeout <= Duration::from_secs(10) && limit <= 512 * 1024);
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            self.guard_steps.lock().unwrap().push("namespace_list");
            let mut isolated = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
            isolated.extend_from_slice(a);
            return SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
                p, &isolated, input, timeout, limit,
            );
        }
        if a.iter().any(|value| value == "status") {
            let mut status = self.expected[..4].to_vec();
            status.extend([
                "-f".into(),
                "json".into(),
                "mailbox".into(),
                "status".into(),
                "-u".into(),
                ALICE.into(),
                "guid messages vsize".into(),
                TARGET_A.into(),
            ]);
            assert!(
                a == status.as_slice(),
                "only exact captured owned-target GUID status admitted"
            );
            assert!(input.is_empty() && limit <= 4096 && timeout <= Duration::from_secs(10));
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            self.guard_steps.lock().unwrap().push("guid_status");
            let mut isolated = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
            isolated.extend_from_slice(a);
            return SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
                p, &isolated, input, timeout, limit,
            );
        }
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
        self.guard_steps.lock().unwrap().push("save");
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

#[derive(Clone)]
struct GuardedReadExecutor {
    native: NativeExecutor,
    status_calls: Arc<AtomicUsize>,
}
impl CommandExecutor for GuardedReadExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded read execution required")
    }
    fn run_with_stdin_bytes_timeout(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(p, a, input, timeout, 1024 * 1024)
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert!(
            !a.iter().any(|v| matches!(
                v.as_str(),
                "create"
                    | "delete"
                    | "rename"
                    | "subscribe"
                    | "unsubscribe"
                    | "move"
                    | "expunge"
                    | "save"
                    | "flags"
            )),
            "no implicit folder or message mutation"
        );
        if a.windows(2)
            .any(|pair| pair[0] == "mailbox" && pair[1] == "status")
            || input == crate::folder_metadata_backend::TRANSCRIPT
        {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
        }
        self.native
            .run_with_stdin_bytes_timeout_and_output_limit(p, a, input, timeout, limit)
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
            backend: "sent_location-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn sent_location_helper(
    fixture: &mut Fixture,
    native: GuardedReadExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
    guard_steps: Arc<Mutex<Vec<&'static str>>>,
) -> PathBuf {
    let socket = fixture.root.join("sent_location-helper.sock");
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
                config: native.native.config,
                expected: vec![
                    "-o".into(),
                    "stats_writer_socket_path=".into(),
                    "-o".into(),
                    format!("auth_socket_path={}", userdb.display()),
                    "save".into(),
                    "-u".into(),
                    ALICE.into(),
                    "-m".into(),
                    TARGET_A.into(),
                ],
                appends,
                status_calls: native.status_calls,
                guard_steps,
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
                Err(_) => panic!("sent_location native helper listener"),
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
fn sent_location_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
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
                        assert!(captured.len() < 3, "no repeated SMTP admission");
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
    let boundary = "owned-sent_location-native-boundary";
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
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"sent_location-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
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
                && fields.get("selected_mailbox").map(String::as_str) == Some(TARGET_A)
                && fields.get("name").map(String::as_str) == Some(TARGET_A))
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
    let listing = get(app, alice, &format!("/mailbox?name={TARGET_A}"));
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
    assert!(text(&read).contains(PUBLIC_BODY) && text(&read).contains("sent_location-public.txt"));
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
    assert!(downloaded
        .response
        .headers
        .iter()
        .any(|(name, value)| name == "Content-Disposition"
            && value.contains("sent_location-public.txt")));
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
        "stale-sent_location-version".into(),
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
        Some("stale-sent_location-version")
    );
    assert_eq!(
        parsed_stale.get("selected_mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_unavailable(get(app, alice, &stale), "stale current Sent GUID");
}

#[test]
#[ignore = "explicit OpenBSD generated Sent location choice; isolated SMTP and Dovecot only"]
fn isolated_openbsd_generated_owned_sent_location_capture_unavailable_and_off() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-sent_location-{}-{}",
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
        for folder in ["", ".Sent", ".INBOX.SentCopyA", ".INBOX.SentCopyB"] {
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
    for (user, folder, indices) in [
        ("alice", ".INBOX.SentCopyA", vec![11]),
        ("alice", ".INBOX.SentCopyB", vec![12]),
        ("bob", ".INBOX.SentCopyA", vec![11, 12, 13]),
        ("bob", ".INBOX.SentCopyB", vec![14]),
    ] {
        for index in indices {
            write_message(&root, user, index, 0);
            fs::rename(
                root.join(format!("{user}/Maildir/new/synthetic-{index:03}")),
                root.join(format!("{user}/Maildir/{folder}/new/synthetic-{index:03}")),
            )
            .unwrap();
        }
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
    let location_readiness = Arc::new(AtomicUsize::new(0));
    let native = GuardedReadExecutor {
        native,
        status_calls: location_readiness.clone(),
    };
    let list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(),
        native.clone(),
        "/usr/local/bin/doveadm",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let inbox = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let sent = MessageListRequest::new(MessageListPolicy::default(), TARGET_A).unwrap();
    let alice_before = list.list_messages(ALICE, &inbox).unwrap();
    let bob_before = list.list_messages(BOB, &inbox).unwrap();
    let sent_before = list.list_messages(ALICE, &sent).unwrap();
    assert!(alice_before.len() == 1 && bob_before.len() == 1 && sent_before.len() == 1);
    let bob_sent_before = list.list_messages(BOB, &sent).unwrap();
    assert_eq!(bob_sent_before.len(), 3);
    let inbox_bytes = scoped_delete_wire_bytes(&root, "alice", "");
    let bob_bytes = scoped_delete_wire_bytes(&root, "bob", "");
    let bob_sent_bytes = scoped_delete_wire_bytes(&root, "bob", ".INBOX.SentCopyA");
    let neighbour_bytes = scoped_delete_wire_bytes(&root, "alice", ".INBOX.SentCopyA");
    let default_sent = MessageListRequest::new(MessageListPolicy::default(), "Sent").unwrap();
    let other = MessageListRequest::new(MessageListPolicy::default(), TARGET_B).unwrap();
    let default_alice = list.list_messages(ALICE, &default_sent).unwrap();
    let default_bob = list.list_messages(BOB, &default_sent).unwrap();
    let other_alice = list.list_messages(ALICE, &other).unwrap();
    let other_bob = list.list_messages(BOB, &other).unwrap();
    let default_alice_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    let default_bob_bytes = scoped_delete_wire_bytes(&root, "bob", ".Sent");
    let other_alice_bytes = scoped_delete_wire_bytes(&root, "alice", ".INBOX.SentCopyB");
    let other_bob_bytes = scoped_delete_wire_bytes(&root, "bob", ".INBOX.SentCopyB");
    let appends = Arc::new(AtomicUsize::new(0));
    let guard_steps = Arc::new(Mutex::new(Vec::new()));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = sent_location_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
        guard_steps.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = sent_location_sink(&mut fixture, records.clone());
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
        "native-sent_location-session",
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
    let preferences = crate::sent_location::Store::new(&app_config.state_layout.settings_dir);
    assert_eq!(
        preferences.load(ALICE).unwrap(),
        crate::sent_location::Preference::default()
    );
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::sent_location::Preference::default()
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
    let choose_a = location_fields(text(&copies), TARGET_A);
    assert_eq!(
        choose_a.get("expected_revision").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        http(&app, None, "POST", "/settings/sent-location", &choose_a)
            .response
            .status_code,
        303
    );
    let mut wrong = choose_a.clone();
    wrong.insert("csrf_token".into(), "invalid".into());
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sent-location",
            &wrong
        )
        .response
        .status_code,
        403
    );
    let mut missing = choose_a.clone();
    missing.remove("csrf_token");
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sent-location",
            &missing
        )
        .response
        .status_code,
        403
    );
    assert_eq!(
        http(
            &app,
            Some(&bob),
            "POST",
            "/settings/sent-location",
            &choose_a
        )
        .response
        .status_code,
        403
    );
    for value in ["INBOX.Unlisted", "INBOX.*", &"x".repeat(2048)] {
        let mut invalid = choose_a.clone();
        invalid.insert("mailbox_name".into(), value.into());
        assert!(
            http(
                &app,
                Some(&alice),
                "POST",
                "/settings/sent-location",
                &invalid
            )
            .response
            .status_code
                >= 400
        );
    }
    let mut forged = choose_a.clone();
    forged.insert("mailbox_guid".into(), "not-browser-authority".into());
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sent-location",
            &forged
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        preferences.load(ALICE).unwrap(),
        crate::sent_location::Preference::default()
    );
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sent-location",
            &choose_a
        )
        .response
        .status_code,
        303
    );
    let saved_a = preferences.load(ALICE).unwrap();
    assert_eq!(saved_a.revision, 1);
    assert_eq!(saved_a.mailbox_name, TARGET_A);
    let a_guid = saved_a.mailbox_guid.clone().unwrap();
    assert_eq!(
        a_guid,
        sent_before[0]
            .metadata
            .as_ref()
            .unwrap()
            .version
            .mailbox_guid
    );
    assert_ne!(
        a_guid,
        bob_sent_before[0]
            .metadata
            .as_ref()
            .unwrap()
            .version
            .mailbox_guid
    );
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sent-location",
            &choose_a
        )
        .response
        .status_code,
        409
    );
    let restarted = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config)
            .with_fixture_sendmail_path(sendmail.clone()),
    );
    let reloaded = get(&restarted, &alice, "/settings?section=copies");
    assert_eq!(reloaded.response.status_code, 200);
    let choose_b = location_fields(text(&reloaded), TARGET_B);
    assert_eq!(
        choose_b.get("expected_revision").map(String::as_str),
        Some("1")
    );
    assert!(text(&reloaded).contains(&format!("value=\"{TARGET_A}\" selected")));
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::sent_location::Preference::default()
    );
    assert!(fs::read(&unrelated_path).unwrap() == unrelated_before);
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);

    let draft_store = crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default(),
    );
    let current_a = current_sent_listing(&restarted, &alice, TARGET_A);
    assert_role_projection(text(&current_a), "Native 011", true);
    let first_a_link = message_link(text(&current_a), sent_before[0].uid);
    let first_a_reader = get(
        &restarted,
        &alice,
        first_a_link.strip_suffix("#reading-pane").unwrap(),
    );
    assert_eq!(first_a_reader.response.status_code, 200);
    assert_role_projection(text(&first_a_reader), "Native 011", true);
    assert!(text(&first_a_reader).contains("ALICE_READER_ONLY_011"));
    let sentinel_page = get(&restarted, &alice, "/compose");
    assert_eq!(sentinel_page.response.status_code, 200);
    let mut sentinel_fields = compose_fields(text(&sentinel_page));
    sentinel_fields.insert("to".into(), ALICE.into());
    sentinel_fields.insert(
        "subject".into(),
        "Unrelated Sent location saved draft".into(),
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
    let sentinel_before = draft_store
        .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    let (draft_url, resumed) =
        saved_submission(&restarted, &alice, "Captured Sent location On Draft");
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
    assert!(
        draft_store
            .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .as_ref()
            == Some(&draft_before)
    );
    let intent = resumed.get("send_intent").unwrap();
    let submitted = thread::scope(|scope| {
        let sending =
            scope.spawn(|| compose_post(&restarted, Some(&alice), "/send", &resumed, false));
        let release_guard = ReleaseReservedSend(release.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pending.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            pending.exists(),
            "actual pre-SMTP sendmail barrier must be reached"
        );
        assert_location_journal(
            &app_config.state_layout.settings_dir,
            intent,
            "reserved",
            Some(("selected", TARGET_A, &a_guid)),
        );
        assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
        assert_eq!(
            http(
                &app,
                Some(&alice),
                "POST",
                "/settings/sent-location",
                &choose_b
            )
            .response
            .status_code,
            303
        );
        let saved_b = preferences.load(ALICE).unwrap();
        assert_eq!(saved_b.revision, 2);
        assert_eq!(saved_b.mailbox_name, TARGET_B);
        assert_eq!(
            saved_b.mailbox_guid.as_deref(),
            Some(
                other_alice[0]
                    .metadata
                    .as_ref()
                    .unwrap()
                    .version
                    .mailbox_guid
                    .as_str()
            )
        );
        assert_location_journal(
            &app_config.state_layout.settings_dir,
            intent,
            "reserved",
            Some(("selected", TARGET_A, &a_guid)),
        );
        drop(release_guard);
        sending.join().unwrap()
    });
    assert_eq!(submitted.response.status_code, 303);
    let first_receipt_url = location(&submitted);
    let reopened = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config)
            .with_fixture_sendmail_path(sendmail.clone()),
    );
    let receipt = get(&reopened, &alice, &first_receipt_url);
    assert_eq!(receipt.response.status_code, 200);
    let current_b = current_sent_listing(&reopened, &alice, TARGET_B);
    assert_role_projection(text(&current_b), "Native 012", true);
    let historical_a = get(&reopened, &alice, &format!("/mailbox?name={TARGET_A}"));
    assert_eq!(historical_a.response.status_code, 200);
    assert_role_projection(text(&historical_a), "Native 011", false);
    assert!(text(&receipt).contains(&format!("A copy was stored in {TARGET_A}.")));
    assert!(text(&receipt).contains("Delivery is not confirmed"));
    assert!(!text(&receipt).contains(&format!("A copy was stored in {TARGET_B}.")));
    assert!(text(&receipt).contains(&format!("href=\"/mailbox?name={TARGET_A}\"")));
    assert_location_journal(
        &app_config.state_layout.settings_dir,
        intent,
        "accepted_stored",
        Some(("selected", TARGET_A, &a_guid)),
    );
    let first = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(first.len(), 2);
    let row = first
        .iter()
        .find(|row| row.subject.as_deref() == Some("Captured Sent location On Draft"))
        .unwrap();
    assert_sent_read(&reopened, &alice, &bob, row, &bob_sent_before);
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert!(
        guard_steps.lock().unwrap().as_slice()
            == ["namespace_list", "guid_status", "save", "guid_status"],
        "actual selected Runtime must use GUID-bound helper append, including post-check"
    );
    assert_eq!(get(&reopened, &alice, &draft_url).response.status_code, 404);
    assert!(draft_store
        .load(ALICE, &draft_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    let replay = compose_post(&reopened, Some(&alice), "/send", &resumed, false);
    assert!(matches!(replay.response.status_code, 200 | 303));
    assert_eq!(records.lock().unwrap().len(), 1);
    assert_eq!(appends.load(Ordering::SeqCst), 1);

    // Only this owned selected folder is moved out of the disposable Maildir.
    // SMTP authorization and copy readiness remain separate outcomes.
    let missing_folder = root.join("alice/Maildir/.INBOX.SentCopyB");
    let parked_folder = root.join("owned-parked-SentCopyB");
    fs::rename(&missing_folder, &parked_folder).unwrap();
    assert!(!missing_folder.exists());
    let (missing_draft_url, missing_fields) = saved_submission(
        &reopened,
        &alice,
        "Unavailable captured Sent location Draft",
    );
    let missing_id = missing_fields.get("draft_id").unwrap();
    let missing_before = draft_store
        .load(ALICE, missing_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    let unavailable = compose_post(&reopened, Some(&alice), "/send", &missing_fields, false);
    assert_eq!(unavailable.response.status_code, 200);
    let missing_intent = missing_fields.get("send_intent").unwrap();
    let missing_receipt_url = format!("/compose?receipt={}", encode(missing_intent));
    let missing_receipt = get(&reopened, &alice, &missing_receipt_url);
    assert_eq!(missing_receipt.response.status_code, 200);
    assert!(text(&missing_receipt).contains(&format!(
        "The captured copy destination {TARGET_B} was unavailable; no copy append was invoked."
    )));
    assert!(text(&missing_receipt).contains("Delivery is not confirmed"));
    assert!(!text(&missing_receipt).contains("A copy was stored in"));
    let b_guid = preferences.load(ALICE).unwrap().mailbox_guid.unwrap();
    assert_location_journal(
        &app_config.state_layout.settings_dir,
        missing_intent,
        "accepted_unconfirmed",
        Some(("unavailable", TARGET_B, &b_guid)),
    );
    let source_href = recovery_href(text(&missing_receipt), "recovery_body");
    let file_href = recovery_href(text(&missing_receipt), "recovery_attachment");
    assert!(get(&reopened, &alice, &source_href).response.body == PUBLIC_BODY.as_bytes());
    assert!(get(&reopened, &alice, &file_href).response.body == PUBLIC_ATTACHMENT);
    assert!(get(&reopened, &bob, &source_href).response.status_code >= 400);
    assert!(get(&reopened, &bob, &file_href).response.status_code >= 400);
    let readonly = get(&reopened, &alice, &missing_draft_url);
    assert_eq!(readonly.response.status_code, 200);
    assert!(
        !text(&readonly).contains("id=\"compose-form\"")
            && !text(&readonly).contains("action=\"/send\"")
    );
    assert!(
        draft_store
            .load(ALICE, missing_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .as_ref()
            == Some(&missing_before)
    );
    assert_eq!(records.lock().unwrap().len(), 2);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert!(
        !missing_folder.exists(),
        "unavailable destination must never be implicitly created"
    );

    let missing_copies = get(&reopened, &alice, "/settings?section=copies");
    assert_eq!(missing_copies.response.status_code, 200);
    let mut off = save_copy_fields(text(&missing_copies));
    off.insert("save_sent".into(), "off".into());
    assert_eq!(
        http(&reopened, Some(&alice), "POST", "/settings/sent-copy", &off)
            .response
            .status_code,
        303
    );
    let fresh = get(&reopened, &alice, "/compose");
    assert_eq!(fresh.response.status_code, 200);
    let mut off_fields = compose_fields(text(&fresh));
    off_fields.insert("to".into(), ALICE.into());
    off_fields.insert("bcc".into(), BOB.into());
    off_fields.insert(
        "subject".into(),
        "Off ignores unavailable Sent location".into(),
    );
    off_fields.insert("body".into(), PUBLIC_BODY.into());
    let readiness_before = location_readiness.load(Ordering::SeqCst);
    let off_submitted = compose_post(&reopened, Some(&alice), "/send", &off_fields, true);
    assert_eq!(off_submitted.response.status_code, 303);
    assert_eq!(
        location_readiness.load(Ordering::SeqCst),
        readiness_before,
        "Off does not invoke namespace/list/status copy readiness"
    );
    assert_eq!(records.lock().unwrap().len(), 3);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    let off_receipt_url = location(&off_submitted);
    let off_receipt = get(&reopened, &alice, &off_receipt_url);
    assert_eq!(off_receipt.response.status_code, 200);
    assert!(text(&off_receipt).contains("Sent copy was not requested for this attempt"));
    assert!(text(&off_receipt).contains("Delivery is not confirmed"));
    assert_location_journal(
        &app_config.state_layout.settings_dir,
        off_fields.get("send_intent").unwrap(),
        "accepted_without_sent_copy",
        None,
    );
    assert!(!missing_folder.exists());
    fs::rename(&parked_folder, &missing_folder).unwrap();
    assert!(list.list_messages(ALICE, &other).unwrap() == other_alice);
    let reconstruct_again = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config).with_fixture_sendmail_path(sendmail),
    );
    // Restoring the destination and changing preference to Off cannot rewrite
    // the earlier unavailable attempt into a stored or intentionally Off copy.
    assert!(
        text(&get(&reconstruct_again, &alice, &missing_receipt_url)).contains(&format!(
            "The captured copy destination {TARGET_B} was unavailable; no copy append was invoked."
        ))
    );
    assert_eq!(
        compose_post(
            &reconstruct_again,
            Some(&alice),
            "/send",
            &missing_fields,
            false
        )
        .response
        .status_code,
        200
    );
    assert_eq!(
        compose_post(
            &reconstruct_again,
            Some(&alice),
            "/drafts/save",
            &missing_fields,
            false
        )
        .response
        .status_code,
        200
    );
    let again_off = compose_post(&reconstruct_again, Some(&alice), "/send", &off_fields, true);
    assert!(matches!(again_off.response.status_code, 200 | 303));
    assert_eq!(records.lock().unwrap().len(), 3);
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    let captured = records.lock().unwrap().clone();
    let stored = scoped_delete_wire_bytes(&root, "alice", ".INBOX.SentCopyA");
    assert!(stored
        .iter()
        .any(|wire| wire == &maildir_lf(&captured[0].wire)));
    for capture in &captured[1..] {
        assert!(!stored.iter().any(|wire| wire == &maildir_lf(&capture.wire)));
    }
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
    let final_a = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(final_a.len(), 2);
    assert!(final_a.iter().any(|row| row.uid == sent_before[0].uid
        && row.metadata == sent_before[0].metadata
        && row.flags == sent_before[0].flags));
    assert!(stored.iter().any(|wire| wire == &neighbour_bytes[0]));
    assert!(list.list_messages(ALICE, &default_sent).unwrap() == default_alice);
    assert!(list.list_messages(BOB, &default_sent).unwrap() == default_bob);
    assert!(list.list_messages(ALICE, &other).unwrap() == other_alice);
    assert!(list.list_messages(BOB, &other).unwrap() == other_bob);
    assert!(list.list_messages(ALICE, &inbox).unwrap() == alice_before);
    assert!(list.list_messages(BOB, &inbox).unwrap() == bob_before);
    assert!(list.list_messages(BOB, &sent).unwrap() == bob_sent_before);
    for (user, folder, expected) in [
        ("alice", "", inbox_bytes),
        ("bob", "", bob_bytes),
        ("bob", ".INBOX.SentCopyA", bob_sent_bytes),
        ("alice", ".Sent", default_alice_bytes),
        ("bob", ".Sent", default_bob_bytes),
        ("alice", ".INBOX.SentCopyB", other_alice_bytes),
        ("bob", ".INBOX.SentCopyB", other_bob_bytes),
    ] {
        assert!(scoped_delete_wire_bytes(&root, user, folder) == expected);
    }
    assert!(fs::read(&unrelated_path).unwrap() == unrelated_before);
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::sent_location::Preference::default()
    );
    assert!(
        draft_store
            .load(ALICE, &sentinel_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .as_ref()
            == Some(&sentinel_before)
    );
    assert!(
        draft_store
            .load(ALICE, missing_id, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .as_ref()
            == Some(&missing_before)
    );
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    assert!(
        guard_steps.lock().unwrap().as_slice()
            == ["namespace_list", "guid_status", "save", "guid_status"],
        "replay, unavailable and Off must not start another guarded append"
    );
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_sent_location_generated_owned_picker=PASS defaults_reload_csrf_foreign_invalid_stale=PASS unrelated_preferences_draft_preserved=PASS durable_selected_name_guid_before_smtp=PASS later_generated_location_change_not_retarget=PASS normal_runtime_authenticated_chosen_folder_save=PASS actual_reader_download_current_stale_foreign_identity=PASS current_sent_recipient_rail_historical_from=PASS exact_confirmed_draft_cleanup=PASS unavailable_destination_smtp_accepted_no_append_create_fallback=PASS truthful_captured_destination_receipt_exact_recovery=PASS unavailable_reconstructed_replay_after_restore_no_retry=PASS off_missing_destination_zero_readiness=PASS finite_three_submissions_one_real_save=PASS bcc_neighbour_foreign_bytes_flags_guids_preserved=PASS scratch_no_move_expunge_flag_crypto_host_metadata=PASS");
}

fn form_fields(body: &str, id: &str) -> (BTreeMap<String, String>, String) {
    let form = body
        .split_once(&format!("<form id=\"{id}\""))
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    let mut fields = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split_once('>').unwrap().0;
        assert!(fields
            .insert(
                attribute(tag, "name").unwrap(),
                attribute(tag, "value").unwrap_or_default()
            )
            .is_none());
    }
    (fields, form.into())
}
fn location_fields(body: &str, target: &str) -> BTreeMap<String, String> {
    let (mut fields, form) = form_fields(body, "copies-sent-location-form");
    assert!(
        form.contains("action=\"/settings/sent-location\"")
            && form.contains("name=\"mailbox_name\"")
    );
    let select = form
        .split_once("<select id=\"copies-sent-location\"")
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0;
    assert!(select.contains("name=\"mailbox_name\""));
    let offered = select.split("<option ").skip(1).any(|option| {
        let tag = option.split_once('>').unwrap().0;
        attribute(tag, "value").as_deref() == Some(target) && !tag.contains("disabled")
    });
    assert!(
        offered,
        "target must be an actual current generated owned picker option"
    );
    fields.insert("mailbox_name".into(), target.into());
    assert_eq!(fields.len(), 3);
    assert!(!fields.contains_key("mailbox_guid"));
    fields
}
fn save_copy_fields(body: &str) -> BTreeMap<String, String> {
    let (mut fields, form) = form_fields(body, "copies-sent-copy-form");
    assert!(form.contains("action=\"/settings/sent-copy\""));
    fields.insert("save_sent".into(), "on".into());
    assert_eq!(fields.len(), 3);
    fields
}
fn saved_submission(
    app: &BrowserApp<RuntimeBrowserGateway>,
    alice: &IssuedSession,
    subject: &str,
) -> (String, BTreeMap<String, String>) {
    let page = get(app, alice, "/compose");
    assert_eq!(page.response.status_code, 200);
    let mut fields = compose_fields(text(&page));
    fields.insert("to".into(), ALICE.into());
    fields.insert("bcc".into(), BOB.into());
    fields.insert("subject".into(), subject.into());
    fields.insert("body".into(), PUBLIC_BODY.into());
    let saved = compose_post(app, Some(alice), "/drafts/save", &fields, true);
    assert_eq!(saved.response.status_code, 303);
    let url = location(&saved);
    let resume = get(app, alice, &url);
    assert_eq!(resume.response.status_code, 200);
    assert!(text(&resume).contains("sent_location-public.txt"));
    let resumed = compose_fields(text(&resume));
    assert!(
        resumed.get("body").map(String::as_str) == Some(PUBLIC_BODY)
            && resumed.get("bcc").map(String::as_str) == Some(BOB)
    );
    (url, resumed)
}
fn assert_location_journal(
    settings: &std::path::Path,
    intent: &str,
    state: &str,
    target: Option<(&str, &str, &str)>,
) {
    let bytes = crate::private_account_file::PrivateAccountFile::new(
        settings.join("send-journal"),
        "osmap-send-journal-v1",
        1024 * 1024,
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
    if let Some((mode, name, guid)) = target {
        assert!(
            entry.get("sent_copy_requested").is_none(),
            "captured On retains legacy boolean encoding"
        );
        let location = entry.get("sent_location").unwrap();
        assert_eq!(
            location.get("mode").and_then(serde_json::Value::as_str),
            Some(mode)
        );
        assert_eq!(
            location
                .get("mailbox_name")
                .and_then(serde_json::Value::as_str),
            Some(name)
        );
        assert_eq!(
            location
                .get("mailbox_guid")
                .and_then(serde_json::Value::as_str),
            Some(guid)
        );
    } else {
        assert!(entry.get("sent_location").is_none());
        assert_eq!(
            entry
                .get("sent_copy_requested")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }
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
        .expect("actual generated exact attempt download link")
}
struct ReleaseReservedSend(PathBuf);
impl Drop for ReleaseReservedSend {
    fn drop(&mut self) {
        let _ = fs::write(&self.0, b"release owned synthetic reservation\n");
    }
}

fn current_sent_listing(
    app: &BrowserApp<RuntimeBrowserGateway>,
    alice: &IssuedSession,
    target: &str,
) -> HandledHttpResponse {
    let shortcut = get(app, alice, "/mailbox/shortcut?kind=sent");
    assert_eq!(shortcut.response.status_code, 303);
    let href = location(&shortcut);
    let (path, query) = href.split_once('?').unwrap();
    assert_eq!(path, "/mailbox");
    let fields = crate::http_form::parse_urlencoded_form(query.as_bytes(), 4, 2048).unwrap();
    assert_eq!(fields.get("name").map(String::as_str), Some(target));
    let listing = get(app, alice, &href);
    assert_eq!(listing.response.status_code, 200);
    listing
}
fn assert_role_projection(body: &str, subject: &str, current_sent: bool) {
    let sent_anchor = body
        .split("<a ")
        .find_map(|anchor| {
            let tag = anchor.split_once('>')?.0;
            (attribute(tag, "href").as_deref() == Some("/mailbox/shortcut?kind=sent"))
                .then_some(tag)
        })
        .expect("actual shared Sent rail anchor");
    assert_eq!(
        attribute(sent_anchor, "aria-current").as_deref() == Some("page"),
        current_sent
    );
    let row = body
        .split("<li class=\"message-row message-card")
        .skip(1)
        .find_map(|row| {
            let row = row.split_once("</li>")?.0;
            row.contains(subject).then_some(row)
        })
        .expect("actual native neighbouring public message row");
    if current_sent {
        assert!(body.contains("approved-mail-table sent-table"));
        assert!(body.contains("class=\"column-sender\">Recipient</span>"));
        assert!(body.contains("Stored Sent copies. Their presence does not confirm delivery."));
        assert!(row.contains(&format!("<strong>To:</strong> {ALICE}")));
        assert!(row.contains(&format!("To: {ALICE}")));
        assert!(!row.contains("<strong>From:</strong>"));
    } else {
        assert!(!body.contains("approved-mail-table sent-table"));
        assert!(body.contains("class=\"column-sender\">From</span>"));
        assert!(row.contains("<strong>From:</strong> Public Sender &lt;sender@example.test&gt;"));
        assert!(!row.contains("<strong>To:</strong>"));
    }
}
