//! Opt-in generated sender identities through Runtime, loopback SMTP and owned Sent.
//! Synthetic-owner cfg(test) authority injection is NOT production root-owner/Serve confinement.
//! Issued synthetic sessions, not login, provider receipt or private-key proof.
use super::*;
use crate::draft::DraftStore;
use crate::totp::TimeProvider;
use std::io::Write;
use std::net::TcpListener;

const PUBLIC_ATTACHMENT: &[u8] = b"Sender Identity public fixture.";
const DESK: &str = "desk@example.test";
const REPLY: &str = "reply@example.test";
const PUBLIC_BODY: &str = "Harmless sender_identity native body café.";
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
            backend: "sender_identity-native-no-flags",
            reason: "flag writes are outside fixture".into(),
        })
    }
}

fn sender_identity_helper(
    fixture: &mut Fixture,
    native: NativeExecutor,
    userdb: PathBuf,
    appends: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("sender_identity-helper.sock");
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
                Err(_) => panic!("sender_identity native helper listener"),
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
    sender: String,
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
fn sender_identity_sink(fixture: &mut Fixture, records: Arc<Mutex<Vec<SmtpRecord>>>) -> u16 {
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
            let mut sender_accepted = false;
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
                        assert!(
                            sender_accepted,
                            "actual exact Desk SMTP MAIL FROM precedes DATA"
                        );
                        captured.push(SmtpRecord {
                            sender: DESK.into(),
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
                } else if command.eq_ignore_ascii_case(&format!("mail FROM:<{DESK}>")) {
                    assert!(!sender_accepted);
                    sender_accepted = true;
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
    if let Some((_, tail)) = form.split_once("<select id=\"compose-sender-identity\"") {
        let options = tail.split_once("</select>").unwrap().0;
        assert!(options.contains("name=\"sender_id\""));
        let mut selected = None;
        for option in options.split("<option ").skip(1) {
            let tag = option.split_once('>').unwrap().0;
            if tag.split_whitespace().any(|word| word == "selected") {
                assert!(selected.replace(attribute(tag, "value").unwrap()).is_none());
            }
        }
        fields.insert(
            "sender_id".into(),
            selected.expect("generated selected sender ID"),
        );
    }
    assert!(fields.contains_key("csrf_token") && fields.contains_key("send_intent"));
    assert_eq!(fields.get("from").map(String::as_str), Some(ALICE));
    fields
}

fn sender_identity_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    path: &str,
    fields: &BTreeMap<String, String>,
    upload: bool,
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-sender_identity-native-boundary";
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
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"sender_identity-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
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
    assert!(
        text(&read).contains(PUBLIC_BODY) && text(&read).contains("sender_identity-public.txt")
    );
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
            && value.contains("sender_identity-public.txt")));
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
        "stale-sender_identity-version".into(),
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
        Some("stale-sender_identity-version")
    );
    assert_eq!(
        parsed_stale.get("selected_mailbox_guid"),
        Some(&version.mailbox_guid)
    );
    assert_unavailable(get(app, alice, &stale), "stale current Sent GUID");
}

fn identity_form(body: &str, action: &str, id: &str) -> BTreeMap<String, String> {
    for raw in body.split("<form ").skip(1) {
        let form = raw.split_once("</form>").unwrap().0;
        let tag = form.split_once('>').unwrap().0;
        if attribute(tag, "action").as_deref() != Some("/settings/sender-identity") {
            continue;
        }
        let mut fields = BTreeMap::new();
        for part in form.split("<input ").skip(1) {
            let input = part.split_once('>').unwrap().0;
            if attribute(input, "type").as_deref() == Some("checkbox") {
                continue;
            }
            if let Some(name) = attribute(input, "name") {
                assert!(fields
                    .insert(name, attribute(input, "value").unwrap_or_default())
                    .is_none());
            }
        }
        if fields.get("action").map(String::as_str) != Some(action) {
            continue;
        }
        if action == "primary" {
            assert!(tag.contains("id=\"sender-primary-form\""));
            let select = form
                .split_once("<select id=\"sender-primary-choice\"")
                .unwrap()
                .1
                .split_once("</select>")
                .unwrap()
                .0;
            assert!(select.contains("name=\"identity_id\""));
            assert!(select.split("<option ").skip(1).any(|part| attribute(
                part.split_once('>').unwrap().0,
                "value"
            )
            .as_deref()
                == Some(id)));
            fields.insert("identity_id".into(), id.into());
        } else if fields.get("identity_id").map(String::as_str) != Some(id) {
            continue;
        }
        assert!(fields.contains_key("csrf_token") && fields.contains_key("sender_revision"));
        return fields;
    }
    panic!("expected actual generated authorized identity form");
}
fn identity_update(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    action: &str,
    id: &str,
    display: Option<&str>,
    reply: Option<&str>,
) -> BTreeMap<String, String> {
    let page = get(app, session, "/settings?section=identity");
    assert_eq!(page.response.status_code, 200);
    let mut fields = identity_form(text(&page), action, id);
    if action == "edit" {
        fields.insert("display_name".into(), display.unwrap().into());
        fields.insert("reply_to".into(), reply.unwrap().into());
    }
    let result = http(
        app,
        Some(session),
        "POST",
        "/settings/sender-identity",
        &fields,
    );
    assert_eq!(
        result.response.status_code, 303,
        "actual generated identity update"
    );
    fields
}
fn assert_choice(body: &str, expected: &str) {
    let select = body
        .split_once("<select id=\"compose-sender-identity\"")
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0;
    let selected = select
        .split("<option ")
        .skip(1)
        .filter_map(|part| {
            let tag = part.split_once('>').unwrap().0;
            tag.split_whitespace()
                .any(|word| word == "selected")
                .then(|| attribute(tag, "value").unwrap())
        })
        .collect::<Vec<_>>();
    assert!(
        selected.len() == 1 && selected[0] == expected,
        "actual generated per-message selected ID"
    );
}
fn choose_desk(body: &str, fields: &mut BTreeMap<String, String>) {
    let select = body
        .split_once("<select id=\"compose-sender-identity\"")
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0;
    assert!(
        select.split("<option ").skip(1).any(|part| {
            let (tag, label) = part.split_once('>').unwrap();
            attribute(tag, "value").as_deref() == Some("desk")
                && decode(label.split_once("</option>").unwrap().0) == DESK
        }),
        "select exact server-owned Desk option"
    );
    fields.insert("sender_id".into(), "desk".into());
}
fn authority_bytes(revision: u64, aliases: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":1,"accounts":[
        {"account":ALICE,"revision":revision,"identities":aliases},
        {"account":BOB,"revision":1,"identities":[{"id":"other","address":"other@example.test"}]}
    ]}))
    .unwrap()
}
fn assert_durable_capture(config: &AppConfig, intent: &str) {
    let journal = crate::send_journal::SendJournal::new(
        config.state_layout.settings_dir.join("send-journal"),
    );
    let now = SystemTimeProvider.unix_timestamp();
    assert!(
        journal.receipt(ALICE, intent, now).unwrap()
            == Some(crate::send_journal::AttemptOutcome::Accepted {
                sent_copy_stored: true
            })
    );
    let recovery = crate::send_recovery::SendRecovery::new(
        config.state_layout.settings_dir.join("send-recovery"),
    );
    let crate::send_recovery::RecoveryRead::Available(snapshot) =
        recovery.lookup(&journal, ALICE, intent, now).unwrap()
    else {
        panic!("actual durable prepared sender snapshot");
    };
    let identity = &snapshot.request.sender_identity;
    assert!(identity
        .sender()
        .is_some_and(|sender| sender.id() == "desk" && sender.address() == DESK));
    assert!(identity.display_name() == "Desk" && identity.reply_to() == Some(REPLY));
    assert!(
        snapshot.request.body == PUBLIC_BODY
            && snapshot.request.bcc_recipients == [BOB.to_string()]
    );
    assert!(
        snapshot.request.attachments.len() == 1
            && snapshot.request.attachments[0].body == PUBLIC_ATTACHMENT
    );
}

#[test]
#[ignore = "explicit OpenBSD synthetic-owner sender fixture; isolated SMTP and Dovecot only"]
fn isolated_openbsd_generated_authorized_sender_fresh_and_captured_draft_current_authority() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-sender_identity-{}-{}",
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
    let helper = sender_identity_helper(
        &mut fixture,
        native,
        userdb,
        appends.clone(),
        forbidden.clone(),
    );
    let records = Arc::new(Mutex::new(Vec::new()));
    let port = sender_identity_sink(&mut fixture, records.clone());
    let sendmail = root.join("owned-loopback-sendmail");
    fs::write(&sendmail, format!("#!/usr/local/bin/python3\nimport smtplib,sys\nassert sys.argv[1:3]==['-oi','-f'] and sys.argv[3]=={DESK:?} and sys.argv[4]=='--'\nassert sorted(sys.argv[5:])==sorted([{ALICE:?},{BOB:?}])\ncontent=sys.stdin.buffer.read({})\nassert len(content)<={}\nwith smtplib.SMTP('127.0.0.1',{port},timeout=3) as client:\n    client.sendmail(sys.argv[3],sys.argv[5:],content)\n", MAX_FIXTURE_WIRE + 1, MAX_FIXTURE_WIRE)).unwrap();
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
        "native-sender_identity-session",
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
    // The no-inventory canonical path remains usable without any test authority.
    let canonical_app = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config)
            .with_fixture_sendmail_path(sendmail.clone()),
    );
    let canonical_page = get(&canonical_app, &alice, "/compose");
    assert_eq!(canonical_page.response.status_code, 200);
    let mut canonical_fields = compose_fields(text(&canonical_page));
    assert_choice(text(&canonical_page), crate::sender_authority::CANONICAL_ID);
    canonical_fields.insert("subject".into(), "Unrelated canonical saved draft".into());
    canonical_fields.insert("body".into(), "Preserved unrelated public draft.".into());
    let canonical_saved = sender_identity_post(
        &canonical_app,
        Some(&alice),
        "/drafts/save",
        &canonical_fields,
        false,
    );
    assert_eq!(canonical_saved.response.status_code, 303);
    let sentinel_url = location(&canonical_saved);
    let canonical_resume = get(&canonical_app, &alice, &sentinel_url);
    assert_eq!(canonical_resume.response.status_code, 200);
    let sentinel_id = compose_fields(text(&canonical_resume))["draft_id"].clone();
    let draft_store = crate::draft::FileDraftStore::new(
        app_config.state_layout.draft_dir.clone(),
        crate::draft::DraftPolicy::default(),
    );
    let sentinel_before = draft_store
        .read_immutable(ALICE, &sentinel_id)
        .unwrap()
        .unwrap();
    assert!(sentinel_before.request.sender_identity.sender().is_none());
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
    let bindings_before = fs::read_dir(
        app_config
            .state_layout
            .settings_dir
            .join("openpgp-bindings"),
    )
    .unwrap()
    .map(|entry| {
        let path = entry.unwrap().path();
        (path.clone(), fs::read(path).unwrap())
    })
    .collect::<Vec<_>>();
    let authority_path = root.join("synthetic-sender-authority.json");
    let authority_original = authority_bytes(1, serde_json::json!([{"id":"desk","address":DESK}]));
    fs::write(&authority_path, &authority_original).unwrap();
    fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o600)).unwrap();
    // Fixture-owner injection exercises Runtime only. Production always trusts owner0;
    // real configured inventory confinement needs a separate root-owned Serve proof.
    let new_app = || {
        BrowserApp::new(
            HttpPolicy::from_config(&app_config),
            RuntimeBrowserGateway::from_config(&app_config)
                .with_fixture_sendmail_path(sendmail.clone())
                .with_fixture_sender_authority(crate::sender_authority::Provider::new(
                    Some(authority_path.clone()),
                    uid,
                )),
        )
    };
    let app = new_app();
    let preferences = crate::identity_preferences::IdentityPreferencesStore::new(
        &app_config.state_layout.settings_dir,
    );
    let bob_preferences = preferences.load(BOB).unwrap();
    let add_fields = identity_update(&app, &alice, "add", "desk", None, None);
    identity_update(&app, &alice, "edit", "desk", Some("Desk"), Some(REPLY));
    identity_update(&app, &alice, "primary", "desk", None, None);
    let alias_profile = preferences.load(ALICE).unwrap();
    assert!(alias_profile.revision == 3 && alias_profile.primary_id() == "desk");
    assert!(alias_profile.presentation("desk").unwrap().display_name() == "Desk");
    let reloaded = new_app();
    let default_page = get(&reloaded, &alice, "/compose");
    assert_eq!(default_page.response.status_code, 200);
    assert_choice(text(&default_page), "desk");
    let identity_page = get(&reloaded, &alice, "/settings?section=identity");
    assert_eq!(identity_page.response.status_code, 200);
    assert!(identity_form(text(&identity_page), "primary", "desk")["sender_revision"] == "3");
    let current_primary = identity_form(text(&identity_page), "primary", "desk");
    assert_eq!(
        http(
            &app,
            None,
            "POST",
            "/settings/sender-identity",
            &current_primary
        )
        .response
        .status_code,
        303
    );
    assert_eq!(
        http(
            &app,
            Some(&bob),
            "POST",
            "/settings/sender-identity",
            &current_primary
        )
        .response
        .status_code,
        403
    );
    let mut wrong = current_primary.clone();
    wrong.insert("csrf_token".into(), "invalid".into());
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sender-identity",
            &wrong
        )
        .response
        .status_code,
        403
    );
    let mut arbitrary = current_primary.clone();
    arbitrary.insert("address".into(), "forged@example.test".into());
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sender-identity",
            &arbitrary
        )
        .response
        .status_code,
        400
    );
    let mut unknown = current_primary.clone();
    unknown.insert("identity_id".into(), "unlisted".into());
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sender-identity",
            &unknown
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/sender-identity",
            &add_fields
        )
        .response
        .status_code,
        409
    );
    assert!(
        preferences.load(ALICE).unwrap() == alias_profile
            && preferences.load(BOB).unwrap() == bob_preferences
    );
    assert!(fs::read(&authority_path).unwrap() == authority_original);
    identity_update(
        &app,
        &alice,
        "primary",
        crate::sender_authority::CANONICAL_ID,
        None,
        None,
    );
    assert!(
        preferences.load(ALICE).unwrap().revision == 4
            && preferences.load(ALICE).unwrap().primary_id()
                == crate::sender_authority::CANONICAL_ID
    );
    let page = get(&app, &alice, "/compose");
    assert_eq!(page.response.status_code, 200);
    let mut fields = compose_fields(text(&page));
    assert_choice(text(&page), crate::sender_authority::CANONICAL_ID);
    choose_desk(text(&page), &mut fields);
    assert_eq!(
        fields.get("pgp_binding_revision"),
        Some(&binding.revision.to_string())
    );
    fields.insert("to".into(), ALICE.into());
    fields.insert("bcc".into(), BOB.into());
    fields.insert("subject".into(), "Sender Identity Fresh Native".into());
    fields.insert("body".into(), PUBLIC_BODY.into());
    assert!(!fields
        .keys()
        .any(|key| matches!(key.as_str(), "pgp_sign" | "pgp_encrypt" | "pgp_self")));
    // Refusals occur before the first local transport or helper append.
    assert_eq!(
        sender_identity_post(&app, None, "/send", &fields, true)
            .response
            .status_code,
        303
    );
    let mut wrong_csrf = fields.clone();
    wrong_csrf.insert("csrf_token".into(), "invalid".into());
    assert_eq!(
        sender_identity_post(&app, Some(&alice), "/send", &wrong_csrf, true)
            .response
            .status_code,
        403
    );
    assert_eq!(
        sender_identity_post(&app, Some(&bob), "/send", &fields, true)
            .response
            .status_code,
        403
    );
    let mut stale = fields.clone();
    stale.insert(
        "pgp_binding_revision".into(),
        (binding.revision + 1).to_string(),
    );
    let refused = sender_identity_post(&app, Some(&alice), "/send", &stale, true);
    assert!(refused.response.status_code >= 400);
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
    let mut forged_from = fields.clone();
    forged_from.insert("from".into(), DESK.into());
    assert_eq!(
        sender_identity_post(&app, Some(&alice), "/send", &forged_from, true)
            .response
            .status_code,
        400
    );
    assert!(records.lock().unwrap().is_empty() && appends.load(Ordering::SeqCst) == 0);
    let submitted = sender_identity_post(&app, Some(&alice), "/send", &fields, true);
    assert_eq!(submitted.response.status_code, 303);
    let receipt_url = location(&submitted);
    assert!(receipt_url.starts_with("/compose?receipt="));
    let receipt = get(&app, &alice, &receipt_url);
    assert_eq!(receipt.response.status_code, 200);
    assert!(
        text(&receipt).contains("A copy was saved in Sent")
            && text(&receipt).contains("Delivery to the recipient is not yet confirmed")
    );
    assert_durable_capture(&app_config, &fields["send_intent"]);
    let first = list.list_messages(ALICE, &sent).unwrap();
    assert_eq!(first.len(), 2);
    let first_row = first
        .iter()
        .find(|row| row.subject.as_deref() == Some("Sender Identity Fresh Native"))
        .unwrap();
    assert_sent_read(&app, &alice, &bob, first_row, &bob_sent_before);
    let replay = sender_identity_post(&app, Some(&alice), "/send", &fields, true);
    assert!(matches!(replay.response.status_code, 200 | 303));
    assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
    assert_eq!(list.list_messages(ALICE, &sent).unwrap().len(), 2);

    let fresh_draft = get(&app, &alice, "/compose");
    assert_eq!(fresh_draft.response.status_code, 200);
    let mut draft_fields = compose_fields(text(&fresh_draft));
    assert_choice(text(&fresh_draft), crate::sender_authority::CANONICAL_ID);
    choose_desk(text(&fresh_draft), &mut draft_fields);
    draft_fields.insert("to".into(), ALICE.into());
    draft_fields.insert("bcc".into(), BOB.into());
    draft_fields.insert("subject".into(), "Sender Identity Draft Native".into());
    draft_fields.insert("body".into(), PUBLIC_BODY.into());
    let saved = sender_identity_post(&app, Some(&alice), "/drafts/save", &draft_fields, true);
    assert_eq!(saved.response.status_code, 303);
    let draft_url = location(&saved);
    assert!(draft_url.starts_with("/draft?id="));
    assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
    let draft_id_initial = compose_fields(text(&get(&app, &alice, &draft_url)))["draft_id"].clone();
    let captured_draft = draft_store
        .read_immutable(ALICE, &draft_id_initial)
        .unwrap()
        .unwrap();
    assert!(captured_draft
        .request
        .sender_identity
        .sender()
        .is_some_and(|sender| sender.id() == "desk" && sender.address() == DESK));
    assert!(
        captured_draft.request.sender_identity.display_name() == "Desk"
            && captured_draft.request.sender_identity.reply_to() == Some(REPLY)
    );
    identity_update(
        &app,
        &alice,
        "edit",
        "desk",
        Some("Changed Desk"),
        Some("changed-reply@example.test"),
    );
    assert!(
        preferences.load(ALICE).unwrap().revision == 5
            && preferences.load(ALICE).unwrap().primary_id()
                == crate::sender_authority::CANONICAL_ID
    );
    identity_update(&app, &alice, "primary", "desk", None, None);
    identity_update(
        &app,
        &alice,
        "primary",
        crate::sender_authority::CANONICAL_ID,
        None,
        None,
    );
    assert!(preferences.load(ALICE).unwrap().revision == 7);
    let app = new_app();
    let resume = get(&app, &alice, &draft_url);
    assert_eq!(resume.response.status_code, 200);
    let resumed = compose_fields(text(&resume));
    assert!(resumed.get("body").map(String::as_str) == Some(PUBLIC_BODY));
    assert!(resumed.get("bcc").map(String::as_str) == Some(BOB));
    assert!(
        text(&resume).contains("sender_identity-public.txt")
            && resumed.contains_key("draft_revision")
    );
    let draft_id = resumed.get("draft_id").unwrap().clone();
    assert_choice(text(&resume), "desk");
    assert!(
        text(&resume).contains("Reply-to: reply@example.test.")
            && !text(&resume).contains("changed-reply@example.test")
    );
    assert!(
        draft_store
            .read_immutable(ALICE, &draft_id)
            .unwrap()
            .as_ref()
            == Some(&captured_draft)
    );
    let journal = crate::send_journal::SendJournal::new(
        app_config.state_layout.settings_dir.join("send-journal"),
    );
    let intent = &resumed["send_intent"];
    assert!(journal
        .receipt(ALICE, intent, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    // All refusal fields came from the actual healthy resumed form. Same captured ID
    // reaches current first-dispatch authority validation, not a profile substitution.
    let negative_inventories = [
        authority_bytes(2, serde_json::json!([])),
        authority_bytes(
            3,
            serde_json::json!([{"id":"desk","address":"reassigned@example.test"}]),
        ),
        b"unavailable public fixture inventory".to_vec(),
    ];
    for inventory in &negative_inventories {
        fs::write(&authority_path, inventory).unwrap();
        let refused = sender_identity_post(&app, Some(&alice), "/send", &resumed, false);
        assert_eq!(
            refused.response.status_code, 400,
            "current captured alias authority refusal"
        );
        assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
        assert!(
            draft_store
                .read_immutable(ALICE, &draft_id)
                .unwrap()
                .as_ref()
                == Some(&captured_draft)
        );
        assert!(journal
            .receipt(ALICE, intent, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .is_none());
        assert!(scoped_delete_wire_bytes(&root, "alice", ".Sent").len() == 2);
    }
    fs::write(&authority_path, &authority_original).unwrap();
    let mut stale_draft = resumed.clone();
    let actual_revision = resumed
        .get("draft_revision")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    stale_draft.insert("draft_revision".into(), (actual_revision + 1).to_string());
    let stale_refused = sender_identity_post(&app, Some(&alice), "/send", &stale_draft, false);
    assert_eq!(stale_refused.response.status_code, 409);
    assert!(records.lock().unwrap().len() == 1 && appends.load(Ordering::SeqCst) == 1);
    assert_eq!(get(&app, &alice, &draft_url).response.status_code, 200);
    let sent_draft = sender_identity_post(&app, Some(&alice), "/send", &resumed, false);
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
        .find(|row| row.subject.as_deref() == Some("Sender Identity Draft Native"))
        .unwrap();
    assert_sent_read(&app, &alice, &bob, draft_row, &bob_sent_before);
    assert!(final_sent.iter().any(|row| row.uid == sent_before[0].uid
        && row.metadata == sent_before[0].metadata
        && row.flags == sent_before[0].flags));
    assert_durable_capture(&app_config, &resumed["send_intent"]);
    fs::write(&authority_path, &negative_inventories[0]).unwrap();
    let revoked_reopened = new_app();
    let retained_receipt = get(&revoked_reopened, &alice, &location(&sent_draft));
    assert_eq!(retained_receipt.response.status_code, 200);
    assert!(text(&retained_receipt).contains("A copy was saved in Sent"));
    assert_durable_capture(&app_config, &resumed["send_intent"]);
    let repeat = sender_identity_post(&revoked_reopened, Some(&alice), "/send", &resumed, false);
    assert!(matches!(repeat.response.status_code, 200 | 303));
    assert_eq!(appends.load(Ordering::SeqCst), 2);
    let captured = records.lock().unwrap().clone();
    assert_eq!(captured.len(), 2);
    let stored_bytes = scoped_delete_wire_bytes(&root, "alice", ".Sent");
    for capture in &captured {
        assert!(capture.sender == DESK);
        assert!(capture.wire.starts_with(
            format!("From: =?UTF-8?B?RGVzaw==?=\r\n <{DESK}>\r\nReply-To: {REPLY}\r\n").as_bytes()
        ));
        assert!(!capture
            .wire
            .windows(b"changed-reply@example.test".len())
            .any(|window| window == b"changed-reply@example.test"));
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
    fs::write(&authority_path, &authority_original).unwrap();
    assert!(preferences.load(BOB).unwrap() == bob_preferences);
    assert!(
        preferences.load(ALICE).unwrap().revision == 7
            && preferences.load(ALICE).unwrap().primary_id()
                == crate::sender_authority::CANONICAL_ID
    );
    assert!(
        draft_store
            .read_immutable(ALICE, &sentinel_id)
            .unwrap()
            .as_ref()
            == Some(&sentinel_before)
    );
    for (path, bytes) in &bindings_before {
        assert!(
            fs::read(path).unwrap() == *bytes,
            "canonical OpenPGP authority bytes preserved"
        );
    }
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_generated_authorized_identity_add_edit_primary=PASS shared_cas_csrf_foreign_arbitrary_address_refused=PASS persisted_primary_reconstructed_generated_choice=PASS canonical_absent_inventory_save_resume_legacy=PASS generated_per_message_id_canonical_metadata=PASS normal_runtime_alias_mime_replyto_loopback_envelope=PASS authenticated_real_sent_canonical_account=PASS saved_resumed_capture_profile_default_immutable=PASS current_revoked_reassigned_unavailable_before_dispatch=PASS negative_original_draft_attachment_journal_preserved=PASS durable_journal_recovery_sender_capture=PASS revoked_reconstructed_receipt_replay_no_resubmit=PASS exact_confirmed_draft_cleanup_sentinel_preserved=PASS current_stale_foreign_sent_guid_download=PASS bcc_envelope_not_headers=PASS finite_two_submissions_two_actual_sent_saves=PASS neighbour_foreign_bytes_flags_guids_preserved=PASS canonical_openpgp_authority_no_private_crypto=PASS synthetic_owner_not_production_confinement_login_provider=PASS owned_scratch_standard_metadata_unchanged=PASS");
}
