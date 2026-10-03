// Opt-in native S02 reader proof: actual owned Dovecot -> authenticated helper ->
// runtime browser routes. Public MIME shapes are classification fixtures only.
use super::*;
use crate::auth::{
    AuthenticationContext, AuthenticationPolicy, CommandExecution, CommandExecutionError,
    CommandExecutor, RequiredSecondFactor,
};
use crate::http::{
    parse_http_request, BrowserApp, HandledHttpResponse, HttpPolicy, RuntimeBrowserGateway,
};
use crate::message_metadata::MessageProtection;
use crate::session::{FileSessionStore, IssuedSession, SessionService, SystemRandomSource};
use crate::totp::SystemTimeProvider;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::AtomicBool;

const ALICE: &str = "alice@fixture.test";
const BOB: &str = "bob@fixture.test";
const NATIVE_LIMIT: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct NativeExecutor {
    config: PathBuf,
    calls: Arc<AtomicUsize>,
}
impl CommandExecutor for NativeExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("native fixture requires bounded command execution")
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
        assert_eq!(p, "/usr/local/bin/doveadm");
        assert!(timeout <= Duration::from_secs(10));
        assert!(input.is_empty() || input == crate::folder_metadata_backend::TRANSCRIPT);
        let user = a
            .iter()
            .position(|value| value == "-u")
            .expect("native canonical account");
        assert!([ALICE, BOB].contains(&a[user + 1].as_str()));
        assert!(!a.iter().any(|value| matches!(
            value.as_str(),
            "-c" | "-A" | "-F" | "save" | "move" | "expunge"
        )));
        let mut isolated = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
        isolated.extend_from_slice(a);
        self.calls.fetch_add(1, Ordering::SeqCst);
        SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(p, &isolated, input, timeout, limit)
    }
}

struct Fixture {
    root: PathBuf,
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}
impl Fixture {
    fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let mut failed = 0;
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                failed += 1;
            }
        }
        // A failed listener must not detach another drained handle or allow
        // Drop to remove scratch while another listener still uses it.
        assert_eq!(
            failed, 0,
            "fixture listener failed after all listeners joined"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
type StandardMetadata = Option<(u64, u64, u64, i64, i64)>;
fn standard_metadata() -> Vec<StandardMetadata> {
    [
        "/etc/dovecot/dovecot.conf",
        "/var/dovecot/auth-userdb",
        "/var/run/dovecot/auth-userdb",
    ]
    .iter()
    .map(|path| {
        fs::symlink_metadata(path)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
    })
    .collect()
}

fn serve_userdb(fixture: &mut Fixture, uid: u32, gid: u32) -> PathBuf {
    let socket = fixture.root.join("userdb");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let root = fixture.root.clone();
    let stop = fixture.stop.clone();
    fixture.threads.push(thread::spawn(move || {
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("fixture userdb listener: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write!(stream, "VERSION\t1\t2\nSPID\t{}\n", std::process::id()).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            for _ in 0..4 {
                let mut line = Vec::new();
                let count = Read::by_ref(&mut reader)
                    .take(4097)
                    .read_until(b'\n', &mut line)
                    .unwrap();
                if count == 0 {
                    break;
                }
                assert!(count <= 4096 && line.ends_with(b"\n"));
                let fields = std::str::from_utf8(&line)
                    .unwrap()
                    .trim_end_matches('\n')
                    .split('\t')
                    .collect::<Vec<_>>();
                if fields[0] == "VERSION" {
                    assert!(fields.len() == 3 && fields[1] == "1");
                    continue;
                }
                assert!(fields[0] == "USER" && fields.len() >= 4);
                let id = fields[1];
                assert!(!id.is_empty() && id.bytes().all(|c| c.is_ascii_digit()));
                let user = match fields[2] {
                    ALICE => Some("alice"),
                    BOB => Some("bob"),
                    _ => None,
                };
                if let Some(user) = user {
                    writeln!(
                        stream,
                        "USER\t{id}\t{}\tuid={uid}\tgid={gid}\thome={}",
                        fields[2],
                        root.join(user).display()
                    )
                    .unwrap();
                } else {
                    writeln!(stream, "NOTFOUND\t{id}").unwrap();
                }
            }
        }
    }));
    socket
}

struct ForbiddenMutation(Arc<AtomicUsize>);
impl MessageMoveBackend for ForbiddenMutation {
    fn move_message(&self, _: &str, _: &MessageMoveRequest) -> Result<(), MailboxBackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(MailboxBackendError {
            backend: "native-fixture-forbidden",
            reason: "move is outside reader fixture".into(),
        })
    }
}
impl MessageAppendBackend for ForbiddenMutation {
    fn append_message(&self, _: &str, _: &MessageAppendRequest) -> Result<(), MailboxBackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(MailboxBackendError {
            backend: "native-fixture-forbidden",
            reason: "append is outside reader fixture".into(),
        })
    }
}

struct StaleView {
    inner: DoveadmMessageViewBackend<NativeExecutor>,
    root: PathBuf,
    target_uid: u64,
    armed: Arc<AtomicBool>,
    triggered: Arc<AtomicUsize>,
}
impl MessageViewBackend for StaleView {
    fn fetch_message(
        &self,
        account: &str,
        request: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        // Deterministic test scheduling: selected_message_pane has already
        // received the actual list GUID, but the actual native view has not run.
        if account == ALICE
            && request.mailbox_name == "INBOX"
            && request.uid == self.target_uid
            && self.armed.swap(false, Ordering::SeqCst)
        {
            let file = ["new", "cur"]
                .iter()
                .flat_map(|part| fs::read_dir(self.root.join("alice/Maildir").join(part)).unwrap())
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("synthetic-002")
                })
                .expect("exact owned stale fixture file");
            fs::rename(file, self.root.join("quarantined-public-message")).unwrap();
            self.triggered.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.fetch_message(account, request)
    }
}

fn start_helper(
    fixture: &mut Fixture,
    executor: NativeExecutor,
    userdb: PathBuf,
    stale_uid: u64,
    armed: Arc<AtomicBool>,
    triggered: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
) -> PathBuf {
    let socket = fixture.root.join("reader.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = fixture.stop.clone();
    let root = fixture.root.clone();
    fixture.threads.push(thread::spawn(move || {
        let listing = DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let messages = DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let search = DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(userdb.clone()));
        let view = StaleView {
            inner: DoveadmMessageViewBackend::new(
                MessageViewPolicy::default(),
                executor.clone(),
                "/usr/local/bin/doveadm",
            )
            .with_userdb_socket_path(Some(userdb.clone())),
            root,
            target_uid: stale_uid,
            armed,
            triggered,
        };
        let flags = DoveadmMessageFlagBackend::new(executor, "/usr/local/bin/doveadm")
            .with_userdb_socket_path(Some(userdb));
        let forbidden = ForbiddenMutation(forbidden);
        let replay = Mutex::new(BTreeMap::new());
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("native helper listener: {error}"),
            };
            handle_helper_client(
                HelperBackends {
                    mailbox_backend: &listing,
                    message_list_backend: &messages,
                    message_search_backend: &search,
                    message_view_backend: &view,
                    message_move_backend: &forbidden,
                    message_append_backend: &forbidden,
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

fn write_message(root: &Path, user: &str, index: usize, shape: usize) {
    let sentinel = format!("{}_READER_ONLY_{index:03}", user.to_ascii_uppercase());
    // The sentinel follows the bounded list preview. Its presence proves a
    // native body fetch; it cannot be supplied by list metadata alone.
    let plain = format!("{}\r\n{sentinel}\r\n", "Public preview. ".repeat(32));
    let mime = match shape {
        1 => format!("Content-Type: multipart/mixed; boundary=owned\r\n\r\n--owned\r\nContent-Type: text/plain\r\n\r\n{plain}--owned\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=public.txt\r\nContent-Transfer-Encoding: base64\r\n\r\nUHVibGljIGZpeHR1cmUu\r\n--owned--\r\n"),
        2 => format!("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=owned\r\n\r\n--owned\r\nContent-Type: text/plain\r\n\r\n{plain}--owned\r\nContent-Type: application/pgp-signature\r\n\r\nPublic invalid signature fixture.\r\n--owned--\r\n"),
        3 => "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=owned\r\n\r\n--owned\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--owned\r\nContent-Type: application/octet-stream\r\n\r\nPublic invalid ciphertext fixture.\r\n--owned--\r\n".into(),
        4 => format!("Content-Type: multipart/signed; boundary=owned\r\n\r\n--owned\r\nContent-Type: text/plain\r\n\r\n{plain}--owned\r\nContent-Type: application/pgp-signature\r\n\r\nPublic invalid structure fixture.\r\n--owned--\r\n"),
        _ => format!("Content-Type: text/plain; charset=UTF-8\r\n\r\n{plain}"),
    };
    let path = root
        .join(user)
        .join("Maildir/new")
        .join(format!("synthetic-{index:03}"));
    let sender = if index == 1 {
        "Other Sender <other@example.test>"
    } else {
        "Public Sender <sender@example.test>"
    };
    fs::write(&path, format!("From: {sender}\r\nTo: {user}@fixture.test\r\nSubject: Native {index:03}\r\nDate: Sat, 03 Oct 2026 00:00:00 +0000\r\nMessage-ID: <{user}-{index}@fixture.test>\r\nMIME-Version: 1.0\r\n{mime}")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn http(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    method: &str,
    path: &str,
    form: &BTreeMap<String, String>,
) -> HandledHttpResponse {
    let body = form
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let cookie = session
        .map(|session| format!("Cookie: osmap_session={}\r\n", session.token.as_str()))
        .unwrap_or_default();
    let wire = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/native-reader\r\nOrigin: http://localhost\r\n{cookie}Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let request = parse_http_request(&wire, app.policy()).expect("native fixture HTTP request");
    app.handle_request(&request, "127.0.0.1")
}
fn get(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    path: &str,
) -> HandledHttpResponse {
    http(app, Some(session), "GET", path, &BTreeMap::new())
}
fn text(response: &HandledHttpResponse) -> &str {
    std::str::from_utf8(&response.response.body).unwrap()
}
fn decode(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
fn attribute(tag: &str, name: &str) -> Option<String> {
    tag.split_once(&format!("{name}=\""))?
        .1
        .split_once('"')
        .map(|(value, _)| decode(value))
}
fn back_href(body: &str) -> String {
    body.split("<a ")
        .find_map(|part| {
            let element = part.split_once("</a>")?.0;
            element
                .contains("Back to list")
                .then(|| attribute(element, "href"))
                .flatten()
        })
        .expect("rendered Back to list control")
}
fn neighbour_href(body: &str, label: &str) -> Option<String> {
    body.split("<a ").find_map(|part| {
        let element = part.split_once('>')?.0;
        (attribute(element, "aria-label").as_deref() == Some(label))
            .then(|| attribute(element, "href"))
            .flatten()
    })
}
fn neighbour_disabled(body: &str, label: &str) -> bool {
    body.split("<button ").any(|part| {
        let Some((element, _)) = part.split_once('>') else {
            return false;
        };
        attribute(element, "aria-label").as_deref() == Some(label)
            && element.split_whitespace().any(|value| value == "disabled")
    })
}
fn neighbour_fields(
    app: &BrowserApp<RuntimeBrowserGateway>,
    href: &str,
) -> BTreeMap<String, String> {
    let target = href.split('#').next().unwrap();
    parse_http_request(
        &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        app.policy(),
    )
    .expect("rendered native neighbour target")
    .query_params
}
fn flag_form(body: &str, uid: u64, flag: &str) -> BTreeMap<String, String> {
    body.split("<form ")
        .find_map(|part| {
            let form = part.split_once("</form>")?.0;
            if attribute(form, "action").as_deref() != Some("/message/flag") {
                return None;
            }
            let fields: BTreeMap<_, _> = form
                .split("<input ")
                .filter_map(|input| {
                    let tag = input.split_once('>')?.0;
                    Some((attribute(tag, "name")?, attribute(tag, "value")?))
                })
                .collect();
            (fields.get("uid").map(String::as_str) == Some(uid.to_string().as_str())
                && fields.get("flag").map(String::as_str) == Some(flag))
            .then_some(fields)
        })
        .expect("actual rendered native flag form")
}
fn budget_pair(response: &HandledHttpResponse) {
    assert_eq!(
        response
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_acquired")
            .count(),
        response
            .audit_events
            .iter()
            .filter(|event| event.action == "request_budget_released")
            .count()
    );
    assert!(response
        .audit_events
        .iter()
        .any(|event| event.action == "request_budget_acquired"));
}
fn persisted_flags(messages: &[MessageSummary]) -> Vec<(u64, bool, bool)> {
    messages
        .iter()
        .map(|message| {
            (
                message.uid,
                crate::mail_list::has_flag(&message.flags, "\\Seen"),
                crate::mail_list::has_flag(&message.flags, "\\Flagged"),
            )
        })
        .collect()
}

#[test]
#[ignore = "explicit OpenBSD S02-01 native routes; disposable two-account Dovecot and signed helper only"]
fn isolated_openbsd_coordinated_reader_signed_helper() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = env::temp_dir().join(format!(
        "osmap-reader-native-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture {
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        threads: vec![],
    };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    let group = SystemCommandExecutor
        .run_with_stdin_timeout("/usr/bin/id", &["-g".into()], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(group.status_code, 0);
    let gid = group.stdout.trim().parse::<u32>().unwrap();
    assert_ne!(gid, 0);
    for directory in ["run", "state", "app-state"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(directory))
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
    for index in 0..53 {
        write_message(
            &root,
            "alice",
            index,
            match index {
                1 => 1,
                49 => 2,
                50 => 3,
                51 => 4,
                _ => 0,
            },
        );
    }
    for index in 0..2 {
        write_message(&root, "bob", index, 0);
    }
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = NativeExecutor {
        config,
        calls: calls.clone(),
    };
    let native_list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(),
        executor.clone(),
        "/usr/local/bin/doveadm",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let query = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let initial = native_list
        .list_messages(ALICE, &query)
        .expect("actual Alice metadata");
    let foreign = native_list
        .list_messages(BOB, &query)
        .expect("actual Bob metadata");
    assert_eq!(initial.len(), 53);
    assert_eq!(foreign.len(), 2);
    assert_eq!(initial.iter().map(|message| message.uid).min(), Some(1));
    assert_eq!(foreign.iter().map(|message| message.uid).min(), Some(1));
    assert_ne!(
        initial
            .iter()
            .find(|message| message.uid == 1)
            .unwrap()
            .metadata
            .as_ref()
            .unwrap()
            .version,
        foreign
            .iter()
            .find(|message| message.uid == 1)
            .unwrap()
            .metadata
            .as_ref()
            .unwrap()
            .version
    );
    assert!(initial.iter().all(|message| !message
        .metadata
        .as_ref()
        .unwrap()
        .preview
        .as_deref()
        .unwrap_or("")
        .contains("READER_ONLY")));
    let by_subject = |index: usize| {
        initial
            .iter()
            .find(|message| {
                message.subject.as_deref() == Some(format!("Native {index:03}").as_str())
            })
            .unwrap()
    };
    for (index, protection) in [
        (0, MessageProtection::Plain),
        (49, MessageProtection::Signed),
        (50, MessageProtection::Encrypted),
        (51, MessageProtection::Unknown),
    ] {
        assert_eq!(
            by_subject(index).metadata.as_ref().unwrap().protection,
            protection
        );
    }
    assert_eq!(
        by_subject(1).metadata.as_ref().unwrap().attachment_count,
        Some(1)
    );
    let attachment_details = by_subject(1)
        .metadata
        .as_ref()
        .unwrap()
        .attachments
        .as_ref()
        .expect("native public attachment descriptors");
    assert_eq!(attachment_details.len(), 1);
    assert_eq!(
        attachment_details[0].filename.as_deref(),
        Some("public.txt")
    );
    // Native BODYSTRUCTURE counts encoded MIME octets, including any final
    // line terminator attributed to this part, never the 15 decoded bytes.
    let public_encoded_bytes = b"UHVibGljIGZpeHR1cmUu".len() as u64;
    assert!((public_encoded_bytes..=public_encoded_bytes + 2)
        .contains(&attachment_details[0].encoded_size_bytes));
    assert!(by_subject(0)
        .metadata
        .as_ref()
        .unwrap()
        .attachments
        .as_ref()
        .expect("known ordinary no attachments")
        .is_empty());
    let selected_uid = by_subject(52).uid;
    let stale_uid = by_subject(2).uid;
    let flag_uid = by_subject(0).uid;
    let armed = Arc::new(AtomicBool::new(false));
    let triggered = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = start_helper(
        &mut fixture,
        executor,
        userdb,
        stale_uid,
        armed.clone(),
        triggered.clone(),
        forbidden.clone(),
    );
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
        ("OSMAP_MAILBOX_WORKER_BUDGET".into(), "1".into()),
    ]))
    .unwrap();
    assert!(
        app_config.state_layout.session_dir.starts_with(&root)
            && app_config.state_layout.settings_dir.starts_with(&root)
    );
    assert!(
        app_config.openpgp_crypto.is_none()
            && app_config.openpgp_inventory.is_none()
            && app_config.openpgp_public_admin.is_none()
    );
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "native-reader-session",
        "127.0.0.1",
        "OSMAP/native-reader",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(&app_config.state_layout.session_dir),
        SystemTimeProvider,
        SystemRandomSource,
        1800,
        1800,
    );
    // Synthetic session issuance deliberately does not claim password/TOTP login.
    let alice = sessions
        .issue(&context, ALICE, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config),
    );
    let selection = format!("/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc&pgp=all&attachment=all&after=2000-01-01&before=2099-12-31&selected_mailbox=INBOX&selected_uid={selected_uid}");
    let response = get(&app, &alice, &selection);
    assert_eq!(response.response.status_code, 200);
    assert!(text(&response).contains("ALICE_READER_ONLY_052"));
    assert!(text(&response).contains("Locate selected message on page 2"));
    assert_eq!(
        text(&response)
            .matches("class=\"message-row message-card")
            .count(),
        50
    );
    budget_pair(&response);
    let back = back_href(text(&response));
    let back_request = parse_http_request(
        &format!("GET {back} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        app.policy(),
    )
    .unwrap();
    assert!(!back_request.query_params.contains_key("selected_uid"));
    for (key, value) in [
        ("filter", "unread"),
        ("sort", "subject"),
        ("dir", "asc"),
        ("after", "2000-01-01"),
        ("before", "2099-12-31"),
    ] {
        assert_eq!(
            back_request.query_params.get(key).map(String::as_str),
            Some(value)
        );
    }
    let back_state =
        crate::mail_list::ListViewState::from_query(&back_request.query_params).unwrap();
    assert_eq!(
        back_state.protection,
        crate::mail_list::ProtectionFilter::All
    );
    assert_eq!(
        back_state.attachment,
        crate::mail_list::AttachmentFilter::All
    );
    let response = get(&app, &alice, &back);
    assert_eq!(response.response.status_code, 200);
    assert!(!text(&response).contains("ALICE_READER_ONLY_052"));
    let page = get(&app, &alice, &format!("{selection}&page=2"));
    assert_eq!(page.response.status_code, 200);
    assert_eq!(
        text(&page)
            .matches("class=\"message-row message-card")
            .count(),
        3
    );
    assert!(text(&page).contains("data-selected=\"true\""));
    let rows = text(&response)
        .split("class=\"message-row message-card")
        .skip(1)
        .collect::<Vec<_>>();
    assert!(rows.first().unwrap().contains("Native 000"));
    assert!(rows.last().unwrap().contains("Native 049"));
    let descending = get(
        &app,
        &alice,
        "/mailbox?name=INBOX&sort=subject&dir=desc&pgp=all",
    );
    assert_eq!(descending.response.status_code, 200);
    let first_row = text(&descending)
        .split("class=\"message-row message-card")
        .nth(1)
        .unwrap();
    assert!(first_row
        .split("</li>")
        .next()
        .unwrap()
        .contains("Native 052"));
    let empty = get(
        &app,
        &alice,
        "/search?mailbox=INBOX&field=subject&q=public-no-such-message&pgp=all",
    );
    assert_eq!(empty.response.status_code, 200);
    assert_eq!(
        text(&empty)
            .matches("class=\"message-row message-card")
            .count(),
        0
    );
    assert_eq!(
        get(&app, &alice, "/mailbox?name=INBOX&pgp=verified")
            .response
            .status_code,
        400
    );
    for (filter, count) in [
        ("plain", 50),
        ("signed", 1),
        ("encrypted", 1),
        ("unknown", 1),
    ] {
        let response = get(
            &app,
            &alice,
            &format!("/mailbox?name=INBOX&sort=subject&dir=asc&pgp={filter}"),
        );
        assert_eq!(response.response.status_code, 200);
        assert_eq!(
            text(&response)
                .matches("class=\"message-row message-card")
                .count(),
            count
        );
    }
    let attachment = get(
        &app,
        &alice,
        "/mailbox?name=INBOX&attachment=with&sort=subject&dir=asc&pgp=plain",
    );
    assert_eq!(attachment.response.status_code, 200);
    assert_eq!(
        text(&attachment)
            .matches("class=\"message-row message-card")
            .count(),
        1
    );
    assert!(text(&attachment).contains("Native 001"));
    assert!(text(&attachment).contains("public.txt"));
    let without = get(
        &app,
        &alice,
        "/mailbox?name=INBOX&attachment=without&sort=subject&dir=asc&pgp=plain",
    );
    assert_eq!(without.response.status_code, 200);
    assert_eq!(
        text(&without)
            .matches("class=\"message-row message-card")
            .count(),
        49
    );
    assert!(!text(&without).contains(">Native 001</a>"));
    let unknown_attachment_records = initial
        .iter()
        .filter(|message| {
            message
                .metadata
                .as_ref()
                .unwrap()
                .attachment_count
                .is_none()
        })
        .count();
    let unknown_attachments = get(
        &app,
        &alice,
        "/mailbox?name=INBOX&attachment=unknown&sort=subject&dir=asc&pgp=all",
    );
    assert_eq!(unknown_attachments.response.status_code, 200);
    assert_eq!(
        text(&unknown_attachments)
            .matches("class=\"message-row message-card")
            .count(),
        unknown_attachment_records
    );
    let mismatch = get(
        &app,
        &alice,
        &selection.replace("attachment=all", "attachment=with"),
    );
    assert!(text(&mismatch).contains("Message unavailable"));
    assert!(!text(&mismatch).contains("ALICE_READER_ONLY_052"));
    let search = get(&app, &alice, &format!("/search?q=Native%20052&field=subject&mailbox=INBOX&filter=unread&sort=subject&dir=asc&pgp=plain&selected_mailbox=INBOX&selected_uid={selected_uid}"));
    assert_eq!(search.response.status_code, 200);
    assert!(text(&search).contains("ALICE_READER_ONLY_052"));
    let search_back = back_href(text(&search));
    assert!(
        search_back.starts_with("/search?")
            && search_back.contains("pgp=plain")
            && search_back.contains("mailbox=INBOX")
            && !search_back.contains("selected_uid")
    );
    assert_eq!(get(&app, &alice, &search_back).response.status_code, 200);
    // The singleton search must not borrow neighbours from the full mailbox.
    assert!(neighbour_disabled(text(&search), "Previous message"));
    assert!(neighbour_disabled(text(&search), "Next message"));

    // Public MIME, attachment and sender filters compose before adjacency:
    // 049/050/051 are protected/unknown outer MIME and cannot intervene.
    let filtered_origin = "/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc&pgp=plain&attachment=without&from=sender%40example.test";
    let filtered_reader = get(
        &app,
        &alice,
        &format!(
            "{filtered_origin}&selected_mailbox=INBOX&selected_uid={}",
            by_subject(48).uid
        ),
    );
    assert_eq!(filtered_reader.response.status_code, 200);
    assert!(text(&filtered_reader).contains("ALICE_READER_ONLY_048"));
    let filtered_previous = neighbour_href(text(&filtered_reader), "Previous message").unwrap();
    let filtered_next = neighbour_href(text(&filtered_reader), "Next message").unwrap();
    for (href, index) in [(&filtered_previous, 47), (&filtered_next, 52)] {
        let fields = neighbour_fields(&app, href);
        assert_eq!(
            fields.get("selected_uid"),
            Some(&by_subject(index).uid.to_string())
        );
        assert_eq!(fields.get("pgp").map(String::as_str), Some("plain"));
        assert_eq!(
            fields.get("attachment").map(String::as_str),
            Some("without")
        );
        assert_eq!(
            fields.get("from").map(String::as_str),
            Some("sender@example.test")
        );
        let viewed = get(&app, &alice, href.split('#').next().unwrap());
        assert_eq!(viewed.response.status_code, 200);
        assert!(text(&viewed).contains(&format!("ALICE_READER_ONLY_{index:03}")));
        budget_pair(&viewed);
    }

    // Descending order places ordinary 003/002 on either side of page 1/2.
    // Follow both actual links rather than inspecting their labels alone.
    let cross_page = get(&app, &alice, &format!("/mailbox?name=INBOX&sort=subject&dir=desc&pgp=all&selected_mailbox=INBOX&selected_uid={}", by_subject(3).uid));
    assert_eq!(cross_page.response.status_code, 200);
    let cross_next = neighbour_href(text(&cross_page), "Next message").unwrap();
    let fields = neighbour_fields(&app, &cross_next);
    assert_eq!(fields.get("page").map(String::as_str), Some("2"));
    assert_eq!(
        fields.get("selected_uid"),
        Some(&by_subject(2).uid.to_string())
    );
    assert_eq!(
        fields.get("selected_mailbox_guid"),
        Some(
            &by_subject(2)
                .metadata
                .as_ref()
                .unwrap()
                .version
                .mailbox_guid
        )
    );
    assert_eq!(
        fields.get("selected_message_guid"),
        Some(
            &by_subject(2)
                .metadata
                .as_ref()
                .unwrap()
                .version
                .message_guid
        )
    );
    let crossed = get(&app, &alice, cross_next.split('#').next().unwrap());
    assert_eq!(crossed.response.status_code, 200);
    assert!(text(&crossed).contains("ALICE_READER_ONLY_002"));
    let cross_previous = neighbour_href(text(&crossed), "Previous message").unwrap();
    let fields = neighbour_fields(&app, &cross_previous);
    assert_eq!(fields.get("page").map(String::as_str), Some("1"));
    assert_eq!(
        fields.get("selected_uid"),
        Some(&by_subject(3).uid.to_string())
    );
    let returned = get(&app, &alice, cross_previous.split('#').next().unwrap());
    assert_eq!(returned.response.status_code, 200);
    assert!(text(&returned).contains("ALICE_READER_ONLY_003"));
    let mut stale_fields = neighbour_fields(&app, &cross_next);
    stale_fields.insert(
        "selected_message_guid".into(),
        "absent-native-neighbour".into(),
    );
    let stale_target = format!(
        "/mailbox?{}",
        stale_fields
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    );
    let stale_neighbour = get(&app, &alice, &stale_target);
    assert_eq!(stale_neighbour.response.status_code, 200);
    assert!(text(&stale_neighbour).contains("Message unavailable"));
    assert!(!text(&stale_neighbour).contains("ALICE_READER_ONLY_002"));

    // A real query restricts the upper boundary to 009; full-mailbox order
    // would incorrectly offer 010 as Previous. Preserve every search selector.
    let scoped_search = "/search?mailbox=INBOX&q=Native%2000&field=subject&sort=subject&dir=desc&filter=unread&pgp=plain&attachment=without&from=sender%40example.test";
    let scoped_reader = get(
        &app,
        &alice,
        &format!(
            "{scoped_search}&selected_mailbox=INBOX&selected_uid={}",
            by_subject(9).uid
        ),
    );
    assert_eq!(scoped_reader.response.status_code, 200);
    assert!(text(&scoped_reader).contains("ALICE_READER_ONLY_009"));
    assert!(neighbour_disabled(text(&scoped_reader), "Previous message"));
    let scoped_next = neighbour_href(text(&scoped_reader), "Next message").unwrap();
    assert!(scoped_next.starts_with("/search?"));
    let fields = neighbour_fields(&app, &scoped_next);
    for (key, value) in [
        ("q", "Native 00"),
        ("field", "subject"),
        ("mailbox", "INBOX"),
        ("pgp", "plain"),
        ("attachment", "without"),
        ("from", "sender@example.test"),
    ] {
        assert_eq!(fields.get(key).map(String::as_str), Some(value));
    }
    assert_eq!(
        fields.get("selected_uid"),
        Some(&by_subject(8).uid.to_string())
    );
    let scoped_followed = get(&app, &alice, scoped_next.split('#').next().unwrap());
    assert_eq!(scoped_followed.response.status_code, 200);
    assert!(text(&scoped_followed).contains("ALICE_READER_ONLY_008"));

    // Standalone readers must rerun their originating search, preserving its
    // boundary and exact public identity instead of silently listing INBOX.
    let standalone = format!(
        "/message?mailbox=INBOX&uid={}&mailbox_guid={}&message_guid={}&return_to={}",
        by_subject(9).uid,
        encode(
            &by_subject(9)
                .metadata
                .as_ref()
                .unwrap()
                .version
                .mailbox_guid
        ),
        encode(
            &by_subject(9)
                .metadata
                .as_ref()
                .unwrap()
                .version
                .message_guid
        ),
        encode(scoped_search)
    );
    let standalone_reader = get(&app, &alice, &standalone);
    assert_eq!(standalone_reader.response.status_code, 200);
    assert!(text(&standalone_reader).contains("ALICE_READER_ONLY_009"));
    assert!(neighbour_disabled(
        text(&standalone_reader),
        "Previous message"
    ));
    let standalone_next = neighbour_href(text(&standalone_reader), "Next message").unwrap();
    let fields = neighbour_fields(&app, &standalone_next);
    assert!(standalone_next.starts_with("/message?"));
    assert_eq!(fields.get("uid"), Some(&by_subject(8).uid.to_string()));
    assert_eq!(
        fields.get("message_guid"),
        Some(
            &by_subject(8)
                .metadata
                .as_ref()
                .unwrap()
                .version
                .message_guid
        )
    );
    let origin = fields.get("return_to").unwrap();
    let origin_fields = neighbour_fields(&app, origin);
    assert_eq!(
        origin_fields.get("q").map(String::as_str),
        Some("Native 00")
    );
    assert_eq!(
        origin_fields.get("from").map(String::as_str),
        Some("sender@example.test")
    );
    let standalone_followed = get(&app, &alice, &standalone_next);
    assert_eq!(standalone_followed.response.status_code, 200);
    assert!(text(&standalone_followed).contains("ALICE_READER_ONLY_008"));
    budget_pair(&standalone_followed);
    let mut stale_fields = fields;
    stale_fields.insert("message_guid".into(), "absent-native-neighbour".into());
    let stale_target = format!(
        "/message?{}",
        stale_fields
            .iter()
            .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    );
    let stale_standalone = get(&app, &alice, &stale_target);
    assert_eq!(stale_standalone.response.status_code, 503);
    assert!(!text(&stale_standalone).contains("ALICE_READER_ONLY_008"));
    let foreign_neighbour = get(&app, &bob, &standalone_next);
    assert_ne!(foreign_neighbour.response.status_code, 200);
    assert!(!text(&foreign_neighbour).contains("ALICE_READER_ONLY_008"));
    let sender_selection = get(
        &app,
        &alice,
        &format!("{selection}&from=sender%40example.test"),
    );
    assert_eq!(sender_selection.response.status_code, 200);
    assert!(text(&sender_selection).contains("ALICE_READER_ONLY_052"));
    let sender_back = back_href(text(&sender_selection));
    let sender_back_request = parse_http_request(
        &format!("GET {sender_back} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        app.policy(),
    )
    .unwrap();
    assert_eq!(
        sender_back_request
            .query_params
            .get("from")
            .map(String::as_str),
        Some("sender@example.test")
    );
    assert_eq!(get(&app, &alice, &sender_back).response.status_code, 200);
    for (from, expected) in [
        ("sender%40example.test", 0),
        ("other%40example.test", 1),
        ("other%2Bsubaddress%40example.test", 0),
    ] {
        let filtered = get(
            &app,
            &alice,
            &format!(
                "/mailbox?name=INBOX&attachment=with&sort=subject&dir=asc&pgp=plain&from={from}"
            ),
        );
        assert_eq!(filtered.response.status_code, 200);
        assert_eq!(
            text(&filtered)
                .matches("class=\"message-row message-card")
                .count(),
            expected
        );
        let searched = get(&app, &alice, &format!("/search?mailbox=INBOX&q=Native%20001&field=subject&pgp=plain&attachment=with&from={from}"));
        assert_eq!(searched.response.status_code, 200);
        assert_eq!(
            text(&searched)
                .matches("class=\"message-row search-result-row")
                .count(),
            expected
        );
        assert!(text(&searched).contains("name=\"q\" value=\"Native 001\""));
        assert!(text(&searched).contains("value=\"subject\" selected"));
    }

    let return_path = "/mailbox?name=INBOX&sort=subject&dir=asc&pgp=plain";
    let mut current = get(&app, &alice, return_path);
    let original_form = flag_form(text(&current), flag_uid, "seen");
    let mut invalid_csrf = original_form.clone();
    invalid_csrf.insert("csrf_token".into(), "0".repeat(64));
    let before_calls = calls.load(Ordering::SeqCst);
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/flag", &invalid_csrf)
            .response
            .status_code,
        403
    );
    assert_eq!(calls.load(Ordering::SeqCst), before_calls);
    for flag in ["seen", "seen", "flagged", "flagged"] {
        let form = flag_form(text(&current), flag_uid, flag);
        let response = http(&app, Some(&alice), "POST", "/message/flag", &form);
        assert_eq!(response.response.status_code, 303);
        let location = response
            .response
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("location"))
            .unwrap()
            .1
            .clone();
        current = get(&app, &alice, &location);
        assert_eq!(current.response.status_code, 200);
        let actual = native_list.list_messages(ALICE, &query).unwrap();
        let row = actual
            .iter()
            .find(|message| message.uid == flag_uid)
            .unwrap();
        assert_eq!(
            crate::mail_list::has_flag(
                &row.flags,
                if flag == "seen" {
                    "\\Seen"
                } else {
                    "\\Flagged"
                }
            ),
            form["enabled"] == "1"
        );
        let unread = get(
            &app,
            &alice,
            "/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc&pgp=plain",
        );
        let unread_count = actual
            .iter()
            .filter(|message| {
                message.metadata.as_ref().unwrap().protection == MessageProtection::Plain
                    && !crate::mail_list::has_flag(&message.flags, "\\Seen")
            })
            .count();
        assert_eq!(unread.response.status_code, 200);
        assert_eq!(
            text(&unread)
                .matches("class=\"message-row message-card")
                .count(),
            unread_count
        );
        assert_eq!(
            text(&unread).contains(">Native 000</a>"),
            !crate::mail_list::has_flag(&row.flags, "\\Seen")
        );
        let starred = get(
            &app,
            &alice,
            "/mailbox?name=INBOX&filter=starred&sort=subject&dir=asc&pgp=plain",
        );
        assert_eq!(starred.response.status_code, 200);
        assert_eq!(
            text(&starred)
                .matches("class=\"message-row message-card")
                .count(),
            usize::from(crate::mail_list::has_flag(&row.flags, "\\Flagged"))
        );
        assert_eq!(
            text(&starred).contains(">Native 000</a>"),
            crate::mail_list::has_flag(&row.flags, "\\Flagged")
        );
        assert_eq!(
            persisted_flags(
                &actual
                    .iter()
                    .filter(|message| message.uid != flag_uid)
                    .cloned()
                    .collect::<Vec<_>>()
            ),
            persisted_flags(
                &initial
                    .iter()
                    .filter(|message| message.uid != flag_uid)
                    .cloned()
                    .collect::<Vec<_>>()
            )
        );
        assert_eq!(
            persisted_flags(&native_list.list_messages(BOB, &query).unwrap()),
            persisted_flags(&foreign)
        );
    }
    let mut foreign_form = original_form.clone();
    foreign_form.insert("csrf_token".into(), bob.record.csrf_token.clone());
    assert_eq!(
        http(&app, Some(&bob), "POST", "/message/flag", &foreign_form)
            .response
            .status_code,
        409
    );
    let mut stale_form = original_form;
    stale_form.insert("message_guid".into(), "absent-public-fixture-guid".into());
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/flag", &stale_form)
            .response
            .status_code,
        409
    );
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
        persisted_flags(&initial)
    );
    assert_eq!(
        persisted_flags(&native_list.list_messages(BOB, &query).unwrap()),
        persisted_flags(&foreign)
    );

    let foreign_selection = get(
        &app,
        &bob,
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=1&sort=subject&dir=asc",
    );
    assert_eq!(foreign_selection.response.status_code, 200);
    assert!(
        text(&foreign_selection).contains("BOB_READER_ONLY_")
            && !text(&foreign_selection).contains("ALICE_READER_ONLY_")
    );
    let folder_switch = get(
        &app,
        &alice,
        &format!("/mailbox?name=Sent&selected_mailbox=INBOX&selected_uid={selected_uid}"),
    );
    assert_eq!(folder_switch.response.status_code, 200);
    assert!(!text(&folder_switch).contains("ALICE_READER_ONLY_052"));
    let before_calls = calls.load(Ordering::SeqCst);
    assert_eq!(
        http(&app, None, "GET", &selection, &BTreeMap::new())
            .response
            .status_code,
        303
    );
    assert_eq!(calls.load(Ordering::SeqCst), before_calls);

    // Real account-owned policy and explicit opening use the same native Seen
    // path as the earlier flag forms. GET, Back and policy changes never write.
    let mark_read = crate::mark_read::Store::new(&app_config.state_layout.settings_dir);
    assert_eq!(
        mark_read.load(ALICE).unwrap().policy,
        crate::mark_read::Policy::Manual
    );
    let open_form = |uid: u64,
                     version: &crate::message_metadata::MessageVersion,
                     return_to: &str,
                     csrf: &str| {
        BTreeMap::from([
            ("csrf_token".into(), csrf.into()),
            ("mailbox".into(), "INBOX".into()),
            ("uid".into(), uid.to_string()),
            ("mailbox_guid".into(), version.mailbox_guid.clone()),
            ("message_guid".into(), version.message_guid.clone()),
            ("return_to".into(), return_to.into()),
        ])
    };
    let current_version = &by_subject(52).metadata.as_ref().unwrap().version;
    let opening = open_form(
        selected_uid,
        current_version,
        &selection,
        &alice.record.csrf_token,
    );
    let manual = http(&app, Some(&alice), "POST", "/message/open", &opening);
    assert_eq!(manual.response.status_code, 303);
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
        persisted_flags(&initial)
    );
    mark_read
        .save(ALICE, 0, crate::mark_read::Policy::OnOpen)
        .unwrap();
    let readonly = get(&app, &alice, &selection);
    assert_eq!(readonly.response.status_code, 200);
    assert!(text(&readonly).contains("ALICE_READER_ONLY_052"));
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
        persisted_flags(&initial)
    );
    let opened = http(&app, Some(&alice), "POST", "/message/open", &opening);
    assert_eq!(opened.response.status_code, 303);
    let opened_target = opened
        .response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("location"))
        .unwrap()
        .1
        .clone();
    assert!(opened_target.contains("opened_read=1"));
    let actual_seen = native_list.list_messages(ALICE, &query).unwrap();
    assert!(crate::mail_list::has_flag(
        &actual_seen
            .iter()
            .find(|row| row.uid == selected_uid)
            .unwrap()
            .flags,
        "\\Seen"
    ));
    for row in actual_seen.iter().filter(|row| row.uid != selected_uid) {
        assert_eq!(
            persisted_flags(std::slice::from_ref(row)),
            persisted_flags(std::slice::from_ref(
                initial.iter().find(|old| old.uid == row.uid).unwrap()
            ))
        );
    }
    let retained_reader = get(&app, &alice, &opened_target);
    assert_eq!(retained_reader.response.status_code, 200);
    assert!(text(&retained_reader).contains("ALICE_READER_ONLY_052"));
    assert!(!text(&retained_reader).contains(&format!("More for message #{selected_uid} in INBOX")));
    let ordinary_unread = get(&app, &alice, &selection);
    assert_eq!(ordinary_unread.response.status_code, 200);
    assert!(text(&ordinary_unread).contains("Message unavailable"));
    assert!(!text(&ordinary_unread).contains("ALICE_READER_ONLY_052"));
    let reload = get(&app, &alice, &opened_target);
    assert_eq!(reload.response.status_code, 200);
    let back = get(&app, &alice, &back_href(text(&reload)));
    assert_eq!(back.response.status_code, 200);
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
        persisted_flags(&actual_seen)
    );
    let mut stale_opening = opening.clone();
    stale_opening.insert("message_guid".into(), "absent-native-opening-guid".into());
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/open", &stale_opening)
            .response
            .status_code,
        409
    );
    mark_read
        .save(BOB, 0, crate::mark_read::Policy::OnOpen)
        .unwrap();
    let shared_uid = initial.iter().find(|row| row.uid == 1).unwrap();
    let foreign_opening = open_form(
        1,
        &shared_uid.metadata.as_ref().unwrap().version,
        "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=1",
        &bob.record.csrf_token,
    );
    assert_eq!(
        http(&app, Some(&bob), "POST", "/message/open", &foreign_opening)
            .response
            .status_code,
        409
    );
    assert_eq!(
        persisted_flags(&native_list.list_messages(BOB, &query).unwrap()),
        persisted_flags(&foreign)
    );
    let unread = flag_form(text(&retained_reader), selected_uid, "seen");
    assert_eq!(unread.get("enabled").map(String::as_str), Some("0"));
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/flag", &unread)
            .response
            .status_code,
        303
    );
    mark_read
        .save(ALICE, 1, crate::mark_read::Policy::Manual)
        .unwrap();
    let manual_after_change = http(&app, Some(&alice), "POST", "/message/open", &opening);
    assert_eq!(manual_after_change.response.status_code, 303);
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
        persisted_flags(&initial)
    );
    assert_eq!(
        persisted_flags(&native_list.list_messages(BOB, &query).unwrap()),
        persisted_flags(&foreign)
    );

    armed.store(true, Ordering::SeqCst);
    let stale_selection = get(&app, &alice, &format!("/mailbox?name=INBOX&sort=subject&dir=asc&selected_mailbox=INBOX&selected_uid={stale_uid}"));
    assert_eq!(stale_selection.response.status_code, 200);
    assert_eq!(triggered.load(Ordering::SeqCst), 1);
    assert!(text(&stale_selection).contains("Message unavailable"));
    assert!(!text(&stale_selection).contains("ALICE_READER_ONLY_002"));
    budget_pair(&stale_selection);
    let healthy = get(&app, &alice, &selection);
    assert_eq!(healthy.response.status_code, 200);
    assert!(text(&healthy).contains("ALICE_READER_ONLY_052"));
    budget_pair(&healthy);
    assert_eq!(
        persisted_flags(&native_list.list_messages(BOB, &query).unwrap()),
        persisted_flags(&foreign)
    );
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_reader_cases=PASS rows53_two_accounts=PASS classification_only=PASS page50_selected_back_search=PASS filtered_previous_next_crosspage_search_origin=PASS stale_navigation_guid_refusal=PASS native_csrf_read_star_filtered_membership_reload=PASS native_manual_onopen_seen_unread_reconciliation=PASS opening_stale_foreign_guid_refusal=PASS attachment_without_and_actual_unknown_count={unknown_attachment_records} foreign_neighbour_stale_refusal=PASS budget_reuse=PASS no_move_append_or_crypto_configuration=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
