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
    // None retains the original reader-only no-move boundary.
    bin_move_count: Option<Arc<AtomicUsize>>,
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
            "-c" | "-A" | "-F" | "save" | "expunge"
        )));
        if let Some(index) = a.iter().position(|value| value == "move") {
            let count = self.bin_move_count.as_ref().expect("reader-only fixture forbids moves");
            assert_eq!(a[user + 1], ALICE);
            assert_eq!(a[index + 1], "-u");
            let destination = &a[index + 3];
            let source = a.iter().position(|value| value == "mailbox").unwrap();
            assert!(matches!((a[source + 1].as_str(), destination.as_str()),
                ("INBOX", "Deleted") | ("Deleted", "INBOX")));
            count.fetch_add(1, Ordering::SeqCst);
        }
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

struct RestrictedBinMove {
    inner: DoveadmMessageMoveBackend<NativeExecutor>,
}

// A concrete fixture dispatch keeps the production HelperBackends bounds
// unchanged, with reader-only and restricted Bin modes explicit.
enum FixtureMoveBackend<'a> {
    ReaderOnly(&'a ForbiddenMutation),
    Bin(&'a RestrictedBinMove),
}
impl MessageMoveBackend for FixtureMoveBackend<'_> {
    fn move_message(&self, account: &str, request: &MessageMoveRequest) -> Result<(), MailboxBackendError> {
        match self {
            Self::ReaderOnly(backend) => backend.move_message(account, request),
            Self::Bin(backend) => backend.move_message(account, request),
        }
    }
}
impl MessageMoveBackend for RestrictedBinMove {
    fn move_message(&self, account: &str, request: &MessageMoveRequest) -> Result<(), MailboxBackendError> {
        // The foreign Alice GUID case must reach Bob's real read-only source
        // check. NativeExecutor independently forbids every Bob move command.
        if account == BOB && request.source_mailbox_name == "INBOX"
            && request.destination_mailbox_name == "Trash"
        {
            return self.inner.move_message(account, request);
        }
        if account != ALICE || !matches!(
            (request.source_mailbox_name.as_str(), request.destination_mailbox_name.as_str()),
            ("INBOX", "Deleted") | ("Deleted", "INBOX")
        ) {
            return Err(MailboxBackendError {
                backend: "native-fixture-forbidden",
                reason: "move outside owned Bin fixture".into(),
            });
        }
        self.inner.move_message(account, request)
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
        let bin_moves = executor.bin_move_count.is_some();
        let restricted = RestrictedBinMove {
            inner: DoveadmMessageMoveBackend::new(executor.clone(), "/usr/local/bin/doveadm")
                .with_userdb_socket_path(Some(userdb.clone())),
        };
        let flags = DoveadmMessageFlagBackend::new(executor, "/usr/local/bin/doveadm")
            .with_userdb_socket_path(Some(userdb));
        let forbidden = ForbiddenMutation(forbidden);
        let move_backend = if bin_moves {
            FixtureMoveBackend::Bin(&restricted)
        } else {
            FixtureMoveBackend::ReaderOnly(&forbidden)
        };
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
                    message_move_backend: &move_backend,
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
    let threading = if user == "alice" && index == 12 {
        "In-Reply-To: <alice-10@fixture.test>\r\nReferences: <alice-10@fixture.test>\r\n"
    } else {
        ""
    };
    fs::write(&path, format!("From: {sender}\r\nTo: {user}@fixture.test\r\nSubject: Native {index:03}\r\nDate: Sat, 03 Oct 2026 00:00:00 +0000\r\nMessage-ID: <{user}-{index}@fixture.test>\r\n{threading}MIME-Version: 1.0\r\n{mime}")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    if user == "alice" && (10..=12).contains(&index) {
        // Actual Maildir receipt times distinguish root1/unrelated2/reply3.
        // Preserve the original 53 records, subjects, MIME shapes and date day.
        let modified =
            std::time::UNIX_EPOCH + Duration::from_secs(1_790_985_600 + (index as u64 - 9) * 3600);
        fs::File::open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }
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
// Fixed public stale hints only; sessions remain actual issued fixture sessions.
fn get_with_reading_cookie(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    path: &str,
    reading_cookie: &str,
) -> HandledHttpResponse {
    assert!(matches!(
        reading_cookie,
        "osmap_reading=v1.mailbox.newest.1.0" | "osmap_reading=v1.mailbox.newest.0.1"
    ));
    let wire = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/native-reader\r\nCookie: osmap_session={}; {reading_cookie}\r\n\r\n",
        session.token.as_str()
    );
    let request = parse_http_request(&wire, app.policy()).expect("native reading fixture request");
    app.handle_request(&request, "127.0.0.1")
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
    let href = body.split("<a ")
        .find_map(|part| {
            let element = part.split_once("</a>")?.0;
            element
                .contains("Back to list")
                .then(|| attribute(element, "href"))
                .flatten()
        })
        .expect("rendered Back to list control");
    // A browser retains its native focus fragment locally, never in the HTTP
    // request target. Verify the actual rendered target before following GET.
    if let Some((target, fragment)) = href.split_once('#') {
        let digest = fragment.strip_prefix("mail-row-").expect("generated row target");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(body.matches(&format!("id=\"{fragment}\" tabindex=\"-1\" data-list-focus=\"true\"")).count(), 1);
        target.into()
    } else {
        href
    }
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
fn rendered_row_uids(body: &str) -> Vec<u64> {
    body.split("aria-label=\"More for message #")
        .skip(1)
        .map(|part| part.split_once(" in INBOX\"").unwrap().0.parse().unwrap())
        .collect()
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
fn stored_content_href(body: &str, label: &str) -> String {
    body.split("<a ").find_map(|part| {
        let (tag, content) = part.split_once('>')?;
        (content.split_once("</a>")?.0 == label)
            .then(|| attribute(tag, "href"))
            .flatten()
    }).expect("actual native stored-content link")
}
fn stored_content_header<'a>(response: &'a HandledHttpResponse, name: &str) -> &'a str {
    response.response.headers.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .expect("native stored-content response header").1.as_str()
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
    // Public synthetic Sent fixture only; no submission or append backend.
    // Keep the original Inbox53/Bob2 subjects and search matches unchanged.
    let sent_file = root.join("alice/Maildir/.Sent/new/synthetic-sent-recipient");
    fs::write(
        &sent_file,
        concat!(
            "From: Sent Sender <alice@fixture.test>\r\n",
            "To: Public Recipient <recipient@fixture.test>\r\n",
            "Bcc: SENT_BCC_PROJECTION_SENTINEL <hidden-recipient@fixture.test>\r\n",
            "Subject: Sent recipient visibility\r\n",
            "Date: Sat, 03 Oct 2026 12:00:00 +0000\r\n",
            "Message-ID: <sent-recipient@fixture.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n\r\n",
            "Public synthetic Sent fixture body.\r\n",
        ),
    )
    .unwrap();
    fs::set_permissions(&sent_file, fs::Permissions::from_mode(0o600)).unwrap();
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = NativeExecutor {
        config,
        calls: calls.clone(),
        bin_move_count: None,
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
    for index in [10, 11, 12] {
        let threading = by_subject(index)
            .metadata
            .as_ref()
            .unwrap()
            .threading
            .as_ref()
            .expect("actual native public Message-ID metadata");
        assert_eq!(
            threading.message_id(),
            format!("<alice-{index}@fixture.test>")
        );
        assert_eq!(
            threading.in_reply_to(),
            (index == 12).then_some("<alice-10@fixture.test>")
        );
        assert_eq!(
            threading.references(),
            if index == 12 {
                vec!["<alice-10@fixture.test>".to_string()]
            } else {
                vec![]
            }
        );
    }
    for (order, expected) in [
        (crate::reading_preferences::DateOrder::Newest, [12, 10, 11]),
        (crate::reading_preferences::DateOrder::Oldest, [10, 12, 11]),
    ] {
        let mut rows = [10, 11, 12].map(|index| by_subject(index).clone()).to_vec();
        let mut view = crate::mail_list::ListViewState::from_query(&BTreeMap::new()).unwrap();
        view.apply_saved_reading_defaults(crate::reading_preferences::ReadingPreferences {
            date_order: order,
            ..Default::default()
        });
        view.apply_messages(&mut rows);
        assert_eq!(
            rows.iter().map(|row| row.uid).collect::<Vec<_>>(),
            expected.map(|index| by_subject(index).uid)
        );
    }
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
    // Actual Sent projection and same-UID folder isolation through the native
    // Dovecot -> signed helper -> browser route, never through SMTP or crypto.
    let sent_query = MessageListRequest::new(MessageListPolicy::default(), "Sent").unwrap();
    let initial_sent = native_list.list_messages(ALICE, &sent_query).unwrap();
    assert_eq!(initial_sent.len(), 1);
    let sent_row = &initial_sent[0];
    assert_eq!(sent_row.uid, 1);
    assert_eq!(
        sent_row.to.as_deref(),
        Some("Public Recipient <recipient@fixture.test>")
    );
    assert_eq!(sent_row.from.as_deref(), Some("Sent Sender <alice@fixture.test>"));
    let sent_version = &sent_row.metadata.as_ref().unwrap().version;
    let inbox_version = &initial
        .iter()
        .find(|row| row.uid == sent_row.uid)
        .unwrap()
        .metadata
        .as_ref()
        .unwrap()
        .version;
    assert_ne!(sent_version.mailbox_guid, inbox_version.mailbox_guid);
    assert_ne!(sent_version.message_guid, inbox_version.message_guid);
    assert!(native_list.list_messages(BOB, &sent_query).unwrap().is_empty());
    assert!(!crate::mail_list::has_flag(&sent_row.flags, "\\Flagged"));
    let sent_path = "/mailbox?dir=asc&name=Sent&sort=subject";
    let mut sent_page = get(&app, &alice, sent_path);
    for enabled in ["1", "0"] {
        assert_eq!(sent_page.response.status_code, 200);
        assert_eq!(
            text(&sent_page).matches("class=\"message-row message-card").count(),
            1
        );
        let party = text(&sent_page)
            .split_once("class=\"message-sender\"")
            .unwrap()
            .1
            .split_once("</span>")
            .unwrap()
            .0;
        assert!(party.contains("To: Public Recipient &lt;recipient@fixture.test&gt;"));
        assert!(!party.contains("Sent Sender"));
        assert!(!text(&sent_page).contains("SENT_BCC_PROJECTION_SENTINEL"));
        assert!(!text(&sent_page).contains("hidden-recipient@fixture.test"));
        let form = flag_form(text(&sent_page), sent_row.uid, "flagged");
        assert_eq!(form["mailbox"], "Sent");
        assert_eq!(form["mailbox_guid"], sent_version.mailbox_guid);
        assert_eq!(form["message_guid"], sent_version.message_guid);
        assert_eq!(form["enabled"], enabled);
        let changed = http(&app, Some(&alice), "POST", "/message/flag", &form);
        assert_eq!(changed.response.status_code, 303);
        // Unselected lists do not acquire the browser reader budget. Flag
        // POSTs acquire it and release via RAII without a release audit event.
        assert_eq!(
            changed.audit_events.iter()
                .filter(|event| event.action == "request_budget_acquired")
                .count(),
            1
        );
        assert!(changed.audit_events.iter().any(|event| {
            event.action == "message_flag_result"
                && event.fields.iter().any(|field| {
                    field.key == "outcome" && field.value == "updated"
                })
        }));
        let location = changed.response.headers.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("location"))
            .unwrap().1.clone();
        assert_eq!(location, sent_path);
        sent_page = get(&app, &alice, &location);
        assert_eq!(sent_page.response.status_code, 200);
        let actual_sent = native_list.list_messages(ALICE, &sent_query).unwrap();
        assert_eq!(actual_sent.len(), 1);
        assert_eq!(actual_sent[0].metadata.as_ref().unwrap().version, *sent_version);
        assert_eq!(
            crate::mail_list::has_flag(&actual_sent[0].flags, "\\Flagged"),
            enabled == "1"
        );
        assert_eq!(
            crate::mail_list::has_flag(&actual_sent[0].flags, "\\Seen"),
            crate::mail_list::has_flag(&sent_row.flags, "\\Seen")
        );
        assert_eq!(
            persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
            persisted_flags(&initial)
        );
        assert_eq!(
            persisted_flags(&native_list.list_messages(BOB, &query).unwrap()),
            persisted_flags(&foreign)
        );
        assert!(native_list.list_messages(BOB, &sent_query).unwrap().is_empty());
    }
    assert_eq!(flag_form(text(&sent_page), sent_row.uid, "flagged")["enabled"], "1");
    assert!(!text(&sent_page).contains("SENT_BCC_PROJECTION_SENTINEL"));
    assert!(!text(&sent_page).contains("hidden-recipient@fixture.test"));
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &sent_query).unwrap()),
        persisted_flags(&initial_sent)
    );
    let reading_store = crate::reading_preferences::ReadingPreferencesStore::new(
        &app_config.state_layout.settings_dir,
    );
    // Actual persisted independent switches override the inverse stale cookie
    // in native runtime readers/settings. Only this disposable account is saved.
    let presentation_before = reading_store.load(ALICE).unwrap();
    let bob_presentation_before = reading_store.load(BOB).unwrap();
    let presentation_row = by_subject(1);
    let presentation_identity = &presentation_row.metadata.as_ref().unwrap().version;
    let standalone_presentation = format!(
        "/message?mailbox=INBOX&uid={}", presentation_row.uid
    );
    let coordinated_presentation = format!(
        "/mailbox?name=INBOX&sort=subject&dir=asc&selected_mailbox=INBOX&selected_uid={}&selected_mailbox_guid={}&selected_message_guid={}",
        presentation_row.uid, encode(&presentation_identity.mailbox_guid),
        encode(&presentation_identity.message_guid)
    );
    for (source, details, hint) in [
        (false, true, "osmap_reading=v1.mailbox.newest.1.0"),
        (true, false, "osmap_reading=v1.mailbox.newest.0.1"),
    ] {
        let mut form = BTreeMap::from([
            ("csrf_token".into(), alice.record.csrf_token.clone()),
            ("start_page".into(), presentation_before.start_page.as_str().into()),
            ("date_order".into(), presentation_before.date_order.as_str().into()),
        ]);
        if source { form.insert("show_source_shortcut".into(), "1".into()); }
        if details { form.insert("attachment_details".into(), "1".into()); }
        assert_eq!(http(&app, Some(&alice), "POST", "/settings/reading", &form).response.status_code, 303);
        let persisted = crate::reading_preferences::ReadingPreferencesStore::new(
            &app_config.state_layout.settings_dir,
        ).load(ALICE).unwrap();
        assert_eq!(persisted.show_source_shortcut, source);
        assert_eq!(persisted.attachment_details, details);
        assert_eq!(persisted.start_page, presentation_before.start_page);
        assert_eq!(persisted.date_order, presentation_before.date_order);
        for path in [standalone_presentation.as_str(), coordinated_presentation.as_str(), "/settings?section=reading"] {
            let page = get_with_reading_cookie(&app, &alice, path, hint);
            assert_eq!(page.response.status_code, 200);
            assert!(text(&page).contains(&format!(
                "<body data-reading-source=\"{source}\" data-reading-attachment-details=\"{details}\">"
            )));
            if path != "/settings?section=reading" {
                assert!(text(&page).contains("ALICE_READER_ONLY_001"));
                assert!(text(&page).contains("public.txt"));
            }
        }
        let bob_page = get_with_reading_cookie(&app, &bob, "/settings?section=reading", hint);
        assert_eq!(bob_page.response.status_code, 200);
        assert!(text(&bob_page).contains(&format!(
            "<body data-reading-source=\"{}\" data-reading-attachment-details=\"{}\">",
            bob_presentation_before.show_source_shortcut, bob_presentation_before.attachment_details
        )));
        assert_eq!(reading_store.load(BOB).unwrap(), bob_presentation_before);
        assert_eq!(persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()), persisted_flags(&initial));
        assert_eq!(persisted_flags(&native_list.list_messages(BOB, &query).unwrap()), persisted_flags(&foreign));
        assert_eq!(persisted_flags(&native_list.list_messages(ALICE, &sent_query).unwrap()), persisted_flags(&initial_sent));
    }
    let mut restore_presentation = BTreeMap::from([
        ("csrf_token".into(), alice.record.csrf_token.clone()),
        ("start_page".into(), presentation_before.start_page.as_str().into()),
        ("date_order".into(), presentation_before.date_order.as_str().into()),
    ]);
    if presentation_before.show_source_shortcut { restore_presentation.insert("show_source_shortcut".into(), "1".into()); }
    if presentation_before.attachment_details { restore_presentation.insert("attachment_details".into(), "1".into()); }
    assert_eq!(http(&app, Some(&alice), "POST", "/settings/reading", &restore_presentation).response.status_code, 303);
    assert_eq!(reading_store.load(ALICE).unwrap(), presentation_before);

    // Follow current renderer links through actual runtime, signed helper and
    // Dovecot. Source is exact escaped stored text, not original wire bytes.
    let content_reader = get(&app, &alice, &standalone_presentation);
    assert_eq!(content_reader.response.status_code, 200);
    let source_href = stored_content_href(text(&content_reader), "View source");
    let download_href = stored_content_href(text(&content_reader), "Download");
    assert!(source_href.starts_with("/message?") && download_href.starts_with("/attachment?"));
    for target in [&source_href, &download_href] {
        let fields = neighbour_fields(&app, target);
        assert_eq!(fields.get("mailbox").map(String::as_str), Some("INBOX"));
        assert_eq!(fields.get("uid"), Some(&presentation_row.uid.to_string()));
        assert_eq!(fields.get("mailbox_guid"), Some(&presentation_identity.mailbox_guid));
        assert_eq!(fields.get("message_guid"), Some(&presentation_identity.message_guid));
    }
    let stored = MailboxHelperMessageViewBackend::new(
        helper.clone(), key.clone(), MailboxHelperPolicy::default(), MessageViewPolicy::default(),
    ).fetch_message(ALICE, &MessageViewRequest::new(
        MessageViewPolicy::default(), "INBOX", presentation_row.uid,
    ).unwrap()).unwrap();
    assert_eq!(stored.metadata.as_ref().unwrap().version, *presentation_identity);
    assert!(stored.body_text.contains("ALICE_READER_ONLY_001"));
    let source = get(&app, &alice, &source_href);
    assert_eq!(source.response.status_code, 200);
    budget_pair(&source);
    let escaped_source = text(&source).split_once("<pre class=\"message-source\"")
        .unwrap().1.split_once('>').unwrap().1.split_once("</pre>").unwrap().0;
    assert_eq!(escaped_source, format!("{}\n\n{}",
        crate::http_support::escape_html(stored.header_block.trim_end_matches(['\r', '\n'])),
        crate::http_support::escape_html(&stored.body_text)));
    assert!(escaped_source.contains("&lt;alice-1@fixture.test&gt;"));
    assert!(!text(&source).contains("<script"));
    assert_eq!(stored_content_header(&source, "Cache-Control"), "no-store");
    assert_eq!(stored_content_header(&source, "Content-Security-Policy"), crate::http_support::browser_csp());
    let download = get(&app, &alice, &download_href);
    assert_eq!(download.response.status_code, 200);
    budget_pair(&download);
    assert_eq!(download.response.body, b"Public fixture.");
    assert_eq!(download.response.body.len(), 15);
    assert_eq!(stored_content_header(&download, "Content-Type"), "application/octet-stream");
    assert_eq!(stored_content_header(&download, "Content-Disposition"), "attachment; filename=\"public.txt\"");
    assert_eq!(stored_content_header(&download, "Cache-Control"), "no-store");
    assert_eq!(stored_content_header(&download, "X-Content-Type-Options"), "nosniff");
    assert_eq!(stored_content_header(&download, "Cross-Origin-Resource-Policy"), "same-origin");
    assert_eq!(stored_content_header(&download, "Referrer-Policy"), "no-referrer");
    assert_eq!(stored_content_header(&download, "X-Frame-Options"), "DENY");
    assert_eq!(stored_content_header(&download, "Content-Security-Policy"),
        "sandbox; default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    assert!(download.response.to_http_bytes().windows(b"Content-Length: 15\r\n".len())
        .any(|window| window == b"Content-Length: 15\r\n"));
    for target in [&source_href, &download_href] {
        let before_calls = calls.load(Ordering::SeqCst);
        let unauth = http(&app, None, "GET", target, &BTreeMap::new());
        assert_eq!(unauth.response.status_code, 303);
        assert_eq!(stored_content_header(&unauth, "Location"), "/login");
        assert_eq!(calls.load(Ordering::SeqCst), before_calls);
        assert!(!text(&unauth).contains("ALICE_READER_ONLY_001"));
        let foreign_content = get(&app, &bob, target);
        assert_eq!(foreign_content.response.status_code, 409);
        budget_pair(&foreign_content);
        assert!(!text(&foreign_content).contains("ALICE_READER_ONLY_001"));
        assert_ne!(foreign_content.response.body, b"Public fixture.");
        let prefix = target.split_once('?').unwrap().0;
        let fields = neighbour_fields(&app, target);
        let href = |fields: &BTreeMap<String, String>| format!("{prefix}?{}",
            fields.iter().map(|(key, value)| format!("{}={}", encode(key), encode(value)))
                .collect::<Vec<_>>().join("&"));
        let mut stale_fields = fields.clone();
        stale_fields.insert("message_guid".into(), "stale-native-content-guid".into());
        let stale_content = get(&app, &alice, &href(&stale_fields));
        assert_eq!(stale_content.response.status_code, 409);
        budget_pair(&stale_content);
        assert!(!text(&stale_content).contains("ALICE_READER_ONLY_001"));
        assert_ne!(stale_content.response.body, b"Public fixture.");
        let mut incomplete = fields;
        incomplete.remove("mailbox_guid");
        let before_calls = calls.load(Ordering::SeqCst);
        let invalid = get(&app, &alice, &href(&incomplete));
        assert_eq!(invalid.response.status_code, 400);
        assert_eq!(calls.load(Ordering::SeqCst), before_calls);
    }
    let mut invalid_part = neighbour_fields(&app, &download_href);
    invalid_part.insert("part".into(), "1..2".into());
    let invalid_part_url = format!("/attachment?{}", invalid_part.iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>().join("&"));
    let before_calls = calls.load(Ordering::SeqCst);
    assert_eq!(get(&app, &alice, &invalid_part_url).response.status_code, 400);
    assert_eq!(calls.load(Ordering::SeqCst), before_calls);
    let recovered_download = get(&app, &alice, &download_href);
    assert_eq!(recovered_download.response.status_code, 200);
    assert_eq!(recovered_download.response.body, b"Public fixture.");
    budget_pair(&recovered_download);
    assert_eq!(persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()), persisted_flags(&initial));
    assert_eq!(persisted_flags(&native_list.list_messages(BOB, &query).unwrap()), persisted_flags(&foreign));
    assert_eq!(persisted_flags(&native_list.list_messages(ALICE, &sent_query).unwrap()), persisted_flags(&initial_sent));
    let save_reading = |order: &str| {
        BTreeMap::from([
            ("csrf_token".into(), alice.record.csrf_token.clone()),
            ("start_page".into(), "inbox".into()),
            ("date_order".into(), order.into()),
            ("show_source_shortcut".into(), "1".into()),
            ("attachment_details".into(), "1".into()),
        ])
    };
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/reading",
            &save_reading("newest")
        )
        .response
        .status_code,
        303
    );
    let newest_threads = get(&app, &alice, "/mailbox?name=INBOX&page=2");
    assert_eq!(newest_threads.response.status_code, 200);
    assert_eq!(
        rendered_row_uids(text(&newest_threads)),
        [12, 10, 11].map(|index| by_subject(index).uid)
    );
    let thread_identity = &by_subject(12).metadata.as_ref().unwrap().version;
    let thread_target = format!("/mailbox?name=INBOX&page=2&selected_mailbox=INBOX&selected_uid={}&selected_mailbox_guid={}&selected_message_guid={}", by_subject(12).uid, encode(&thread_identity.mailbox_guid), encode(&thread_identity.message_guid));
    let thread_reader = get(&app, &alice, &thread_target);
    assert_eq!(thread_reader.response.status_code, 200);
    assert!(text(&thread_reader).contains("ALICE_READER_ONLY_012"));
    let thread_next = neighbour_href(text(&thread_reader), "Next message")
        .expect("real conversation next member");
    let thread_fields = neighbour_fields(&app, &thread_next);
    assert_eq!(
        thread_fields.get("selected_uid"),
        Some(&by_subject(10).uid.to_string())
    );
    assert!(!thread_fields.contains_key("sort") && !thread_fields.contains_key("dir"));
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/reading",
            &save_reading("oldest")
        )
        .response
        .status_code,
        303
    );
    assert_eq!(
        reading_store.load(ALICE).unwrap().date_order,
        crate::reading_preferences::DateOrder::Oldest
    );
    assert_eq!(
        reading_store.load(BOB).unwrap().date_order,
        crate::reading_preferences::DateOrder::Newest
    );
    let oldest_threads = get(&app, &alice, "/mailbox?name=INBOX");
    assert_eq!(oldest_threads.response.status_code, 200);
    assert_eq!(
        &rendered_row_uids(text(&oldest_threads))[..3],
        &[10, 12, 11].map(|index| by_subject(index).uid)
    );
    let reading_page = get(&app, &alice, "/settings?section=reading");
    assert_eq!(reading_page.response.status_code, 200);
    assert!(text(&reading_page).contains("<option value=\"oldest\" selected>"));
    let explicit_threads = get(&app, &alice, "/mailbox?name=INBOX&sort=received&dir=asc");
    assert_eq!(
        &rendered_row_uids(text(&explicit_threads))[..3],
        &[10, 11, 12].map(|index| by_subject(index).uid)
    );
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/settings/reading",
            &save_reading("newest")
        )
        .response
        .status_code,
        303
    );
    let stale_thread_target = thread_target.replace(
        &format!(
            "selected_message_guid={}",
            encode(&thread_identity.message_guid)
        ),
        "selected_message_guid=stale-conversation-probe",
    );
    let stale_thread = get(&app, &alice, &stale_thread_target);
    assert_eq!(stale_thread.response.status_code, 200);
    assert!(text(&stale_thread).contains("Message unavailable"));
    assert!(!text(&stale_thread).contains("ALICE_READER_ONLY_012"));
    let root_reader = get(&app, &alice, thread_next.split('#').next().unwrap());
    assert_eq!(root_reader.response.status_code, 200);
    assert!(text(&root_reader).contains("ALICE_READER_ONLY_010"));
    let parent_seen = flag_form(text(&root_reader), by_subject(10).uid, "seen");
    assert_eq!(parent_seen.get("enabled").map(String::as_str), Some("1"));
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/flag", &parent_seen)
            .response
            .status_code,
        303
    );
    let filtered_thread = get(&app, &alice, &format!("{thread_target}&filter=unread"));
    assert_eq!(filtered_thread.response.status_code, 200);
    assert!(text(&filtered_thread).contains("ALICE_READER_ONLY_012"));
    assert_eq!(
        rendered_row_uids(text(&filtered_thread)),
        [12, 11].map(|index| by_subject(index).uid)
    );
    let filtered_next = neighbour_href(text(&filtered_thread), "Next message")
        .expect("next eligible loaded member");
    assert_eq!(
        neighbour_fields(&app, &filtered_next).get("selected_uid"),
        Some(&by_subject(11).uid.to_string()),
        "excluded Seen parent cannot re-enter via conversation adjacency"
    );
    let parent_changed = get(&app, &alice, thread_next.split('#').next().unwrap());
    let parent_unread = flag_form(text(&parent_changed), by_subject(10).uid, "seen");
    assert_eq!(parent_unread.get("enabled").map(String::as_str), Some("0"));
    assert_eq!(
        http(&app, Some(&alice), "POST", "/message/flag", &parent_unread)
            .response
            .status_code,
        303
    );
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &query).unwrap()),
        persisted_flags(&initial)
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
    assert_eq!(
        persisted_flags(&native_list.list_messages(ALICE, &sent_query).unwrap()),
        persisted_flags(&initial_sent)
    );
    assert!(native_list.list_messages(BOB, &sent_query).unwrap().is_empty());
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
    println!("native_saved_reading_presentation_cookie_independent_account_isolated=PASS");
    println!("native_rendered_source_attachment_exact_stored_text_decoded_bytes=PASS foreign_stale_unauth_content_refused=PASS content_read_flags_unchanged_budget_reusable=PASS");
    println!("native_sent_guid_recipient_star_unstar_restore=PASS bcc_not_in_sent_list=PASS same_uid_inbox_and_foreign_account_unchanged=PASS");
    println!("native_reader_cases=PASS rows53_two_accounts=PASS classification_only=PASS page50_selected_back_search=PASS filtered_previous_next_crosspage_search_origin=PASS stale_navigation_guid_refusal=PASS native_csrf_read_star_filtered_membership_reload=PASS native_manual_onopen_seen_unread_reconciliation=PASS opening_stale_foreign_guid_refusal=PASS native_conversation_headers_saved_order_reader_next_explicit_precedence=PASS conversation_excluded_parent_stale_guid_refusal=PASS attachment_without_and_actual_unknown_count={unknown_attachment_records} foreign_neighbour_stale_refusal=PASS budget_reuse=PASS no_move_append_or_crypto_configuration=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}

fn bin_move_form(body: &str, mailbox: &str, uid: u64, action: &str) -> BTreeMap<String, String> {
    body.split("<form ").find_map(|part| {
        let form = part.split_once("</form>")?.0;
        if attribute(form, "action").as_deref() != Some("/message/move") { return None; }
        let enabled = form.split("<button ").any(|button| {
            let Some(tag) = button.split_once('>').map(|value| value.0) else { return false; };
            attribute(tag, "name").as_deref() == Some("action")
                && attribute(tag, "value").as_deref() == Some(action)
                && !tag.contains(" disabled")
        });
        if !enabled { return None; }
        let mut fields: BTreeMap<_, _> = form.split("<input ").filter_map(|input| {
            let tag = input.split_once('>')?.0;
            Some((attribute(tag, "name")?, attribute(tag, "value")?))
        }).collect();
        if fields.get("mailbox").map(String::as_str) != Some(mailbox)
            || fields.get("uid").map(String::as_str) != Some(uid.to_string().as_str())
        { return None; }
        fields.insert("action".into(), action.into());
        Some(fields)
    }).expect("actual enabled native Bin/Restore form for selected owned identity")
}

#[test]
#[ignore = "explicit OpenBSD S02-03 Bin routes; disposable two-account Dovecot and signed helper only"]
fn isolated_openbsd_configured_bin_browser_moves_restore() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor.run_with_stdin_timeout(
        "/bin/hostname", &[], "", Duration::from_secs(1),
    ).unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = env::temp_dir().join(format!("osmap-bin-native-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture { root: root.clone(), stop: Arc::new(AtomicBool::new(false)), threads: vec![] };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    let group = SystemCommandExecutor.run_with_stdin_timeout(
        "/usr/bin/id", &["-g".into()], "", Duration::from_secs(1),
    ).unwrap();
    assert_eq!(group.status_code, 0);
    let gid = group.stdout.trim().parse::<u32>().unwrap();
    assert_ne!(gid, 0);
    for directory in ["run", "state", "app-state"] {
        fs::DirBuilder::new().mode(0o700).create(root.join(directory)).unwrap();
    }
    for user in ["alice", "bob"] {
        for folder in ["", ".Deleted", ".Trash"] {
            for part in ["cur", "new", "tmp"] {
                fs::create_dir_all(root.join(user).join("Maildir").join(folder).join(part)).unwrap();
            }
        }
    }
    for index in 0..3 { write_message(&root, "alice", index, 0); }
    for index in 0..2 { write_message(&root, "bob", index, 0); }
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let calls = Arc::new(AtomicUsize::new(0));
    let move_count = Arc::new(AtomicUsize::new(0));
    let executor = NativeExecutor { config, calls, bin_move_count: Some(move_count.clone()) };
    let native_list = DoveadmMessageListBackend::new(
        MessageListPolicy::default(), executor.clone(), "/usr/local/bin/doveadm",
    ).with_userdb_socket_path(Some(userdb.clone()));
    let query = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let deleted_query = MessageListRequest::new(MessageListPolicy::default(), "Deleted").unwrap();
    let trash_query = MessageListRequest::new(MessageListPolicy::default(), "Trash").unwrap();
    let initial = native_list.list_messages(ALICE, &query).unwrap();
    let foreign = native_list.list_messages(BOB, &query).unwrap();
    assert_eq!(initial.len(), 3); assert_eq!(foreign.len(), 2);
    assert!(native_list.list_messages(ALICE, &deleted_query).unwrap().is_empty());
    assert!(native_list.list_messages(ALICE, &trash_query).unwrap().is_empty());
    let target = initial.iter().find(|row| row.subject.as_deref() == Some("Native 000")).unwrap();
    let version = target.metadata.as_ref().unwrap().version.clone();
    let neighbours: Vec<_> = initial.iter().filter(|row| row.uid != target.uid).cloned().collect();
    let forbidden = Arc::new(AtomicUsize::new(0));
    let triggered = Arc::new(AtomicUsize::new(0));
    let helper = start_helper(&mut fixture, executor, userdb, 0,
        Arc::new(AtomicBool::new(false)), triggered.clone(), forbidden.clone());
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let app_config = AppConfig::from_env_map(&BTreeMap::from([
        ("OSMAP_RUN_MODE".into(), "serve".into()),
        ("OSMAP_STATE_DIR".into(), root.join("app-state").to_string_lossy().into_owned()),
        ("OSMAP_MAILBOX_HELPER_SOCKET_PATH".into(), helper.to_string_lossy().into_owned()),
        ("OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH".into(), key.to_string_lossy().into_owned()),
        ("OSMAP_MAILBOX_WORKER_BUDGET".into(), "1".into()),
    ])).unwrap();
    assert!(app_config.state_layout.settings_dir.starts_with(&root));
    assert!(app_config.state_layout.session_dir.starts_with(&root));
    assert!(app_config.openpgp_crypto.is_none() && app_config.openpgp_inventory.is_none()
        && app_config.openpgp_public_admin.is_none());
    let context = AuthenticationContext::new(AuthenticationPolicy::default(),
        "native-reader-session", "127.0.0.1", "OSMAP/native-reader").unwrap();
    let sessions = SessionService::new(FileSessionStore::new(&app_config.state_layout.session_dir),
        SystemTimeProvider, SystemRandomSource, 1800, 1800);
    // Synthetic issuance is not a real password/TOTP login proof.
    let alice = sessions.issue(&context, ALICE, RequiredSecondFactor::Totp).unwrap();
    let bob = sessions.issue(&context, BOB, RequiredSecondFactor::Totp).unwrap();
    let app = BrowserApp::new(HttpPolicy::from_config(&app_config),
        RuntimeBrowserGateway::from_config(&app_config));
    let store = crate::bin_folder::BinPreferencesStore::new(&app_config.state_layout.settings_dir);
    assert_eq!(store.load(ALICE).unwrap(), crate::bin_folder::BinPreference::default());
    let settings = BTreeMap::from([
        ("csrf_token".into(), alice.record.csrf_token.clone()),
        ("expected_revision".into(), "0".into()),
        ("mailbox_name".into(), "Deleted".into()),
        ("section".into(), "reading".into()),
    ]);
    let mut invalid = settings.clone(); invalid.insert("csrf_token".into(), "0".repeat(64));
    assert_eq!(http(&app, Some(&alice), "POST", "/settings/bin-folder", &invalid).response.status_code, 403);
    assert_eq!(store.load(ALICE).unwrap(), crate::bin_folder::BinPreference::default());
    let saved = http(&app, Some(&alice), "POST", "/settings/bin-folder", &settings);
    assert_eq!(saved.response.status_code, 303);
    assert_eq!(store.load(ALICE).unwrap(), crate::bin_folder::BinPreference {
        revision: 1, mailbox_name: "Deleted".into(),
    });
    assert_eq!(store.load(BOB).unwrap(), crate::bin_folder::BinPreference::default());
    assert_eq!(http(&app, Some(&alice), "POST", "/settings/bin-folder", &settings).response.status_code, 409);
    let reading = get(&app, &alice, "/settings?section=reading");
    assert_eq!(reading.response.status_code, 200);
    assert!(text(&reading).contains("value=\"Deleted\" selected"));
    let copies = get(&app, &alice, "/settings?section=copies");
    assert_eq!(copies.response.status_code, 200);
    assert!(text(&copies).contains("value=\"Deleted\" selected"));
    let select = |mailbox: &str, row: &MessageSummary| {
        let identity = &row.metadata.as_ref().unwrap().version;
        format!("/mailbox?name={}&sort=subject&dir=asc&selected_mailbox={}&selected_uid={}&selected_mailbox_guid={}&selected_message_guid={}",
            encode(mailbox), encode(mailbox), row.uid, encode(&identity.mailbox_guid), encode(&identity.message_guid))
    };
    let selected = get(&app, &alice, &select("INBOX", target));
    assert_eq!(selected.response.status_code, 200);
    let bin = bin_move_form(text(&selected), "INBOX", target.uid, "bin");
    assert_eq!(bin["mailbox_guid"], version.mailbox_guid);
    assert_eq!(bin["message_guid"], version.message_guid);
    let mut invalid_bin = bin.clone(); invalid_bin.insert("csrf_token".into(), "0".repeat(64));
    assert_eq!(http(&app, Some(&alice), "POST", "/message/move", &invalid_bin).response.status_code, 403);
    let mut foreign_bin = bin.clone(); foreign_bin.insert("csrf_token".into(), bob.record.csrf_token.clone());
    assert_eq!(http(&app, Some(&bob), "POST", "/message/move", &foreign_bin).response.status_code, 409);
    assert_eq!(move_count.load(Ordering::SeqCst), 0);
    let moved = http(&app, Some(&alice), "POST", "/message/move", &bin);
    assert_eq!(moved.response.status_code, 303);
    assert_eq!(move_count.load(Ordering::SeqCst), 1);
    let remaining = native_list.list_messages(ALICE, &query).unwrap();
    assert_eq!(remaining.len(), neighbours.len());
    assert_eq!(persisted_flags(&remaining), persisted_flags(&neighbours));
    for row in &remaining {
        assert_eq!(row.metadata, neighbours.iter().find(|item| item.uid == row.uid).unwrap().metadata);
    }
    let deleted = native_list.list_messages(ALICE, &deleted_query).unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].metadata.as_ref().unwrap().version.message_guid, version.message_guid);
    assert_ne!(deleted[0].metadata.as_ref().unwrap().version.mailbox_guid, version.mailbox_guid);
    assert_eq!(persisted_flags(&deleted)[0].1, persisted_flags(std::slice::from_ref(target))[0].1);
    assert_eq!(persisted_flags(&deleted)[0].2, persisted_flags(std::slice::from_ref(target))[0].2);
    assert!(native_list.list_messages(ALICE, &trash_query).unwrap().is_empty());
    assert_eq!(http(&app, Some(&alice), "POST", "/message/move", &bin).response.status_code, 409);
    assert_eq!(move_count.load(Ordering::SeqCst), 1);
    let selected_bin = get(&app, &alice, &select("Deleted", &deleted[0]));
    assert_eq!(selected_bin.response.status_code, 200);
    let restore = bin_move_form(text(&selected_bin), "Deleted", deleted[0].uid, "restore");
    assert_eq!(restore["mailbox_guid"], deleted[0].metadata.as_ref().unwrap().version.mailbox_guid);
    assert_eq!(restore["message_guid"], version.message_guid);
    assert_eq!(http(&app, Some(&alice), "POST", "/message/move", &restore).response.status_code, 303);
    assert_eq!(move_count.load(Ordering::SeqCst), 2);
    assert!(native_list.list_messages(ALICE, &deleted_query).unwrap().is_empty());
    let restored = native_list.list_messages(ALICE, &query).unwrap();
    assert_eq!(restored.len(), initial.len());
    let restored_target = restored.iter().find(|row| row.metadata.as_ref().unwrap().version.message_guid == version.message_guid).unwrap();
    assert_ne!(restored_target.uid, target.uid);
    assert_eq!(restored_target.metadata.as_ref().unwrap().version, version);
    assert_eq!(persisted_flags(std::slice::from_ref(restored_target))[0].1, persisted_flags(std::slice::from_ref(target))[0].1);
    assert_eq!(persisted_flags(std::slice::from_ref(restored_target))[0].2, persisted_flags(std::slice::from_ref(target))[0].2);
    for row in &neighbours {
        let current = restored.iter().find(|item| item.uid == row.uid).unwrap();
        assert_eq!(current.metadata, row.metadata);
        assert_eq!(persisted_flags(std::slice::from_ref(current)), persisted_flags(std::slice::from_ref(row)));
    }
    assert_eq!(http(&app, Some(&alice), "POST", "/message/move", &restore).response.status_code, 409);
    assert_eq!(move_count.load(Ordering::SeqCst), 2);
    let reselected = get(&app, &alice, &select("INBOX", restored_target));
    let current_bin = bin_move_form(text(&reselected), "INBOX", restored_target.uid, "bin");
    fs::rename(root.join("alice/Maildir/.Deleted"), root.join("removed-owned-Deleted")).unwrap();
    let absent = http(&app, Some(&alice), "POST", "/message/move", &current_bin);
    assert!(matches!(absent.response.status_code, 400 | 503));
    assert_eq!(move_count.load(Ordering::SeqCst), 2);
    assert!(native_list.list_messages(ALICE, &trash_query).unwrap().is_empty());
    fs::rename(root.join("removed-owned-Deleted"), root.join("alice/Maildir/.Deleted")).unwrap();
    let final_inbox = native_list.list_messages(ALICE, &query).unwrap();
    assert_eq!(persisted_flags(&final_inbox), persisted_flags(&restored));
    assert_eq!(native_list.list_messages(BOB, &query).unwrap(), foreign);
    assert!(native_list.list_messages(BOB, &deleted_query).unwrap().is_empty());
    assert!(native_list.list_messages(BOB, &trash_query).unwrap().is_empty());
    assert_eq!(store.load(BOB).unwrap(), crate::bin_folder::BinPreference::default());
    assert_eq!(store.load(ALICE).unwrap().mailbox_name, "Deleted");
    assert_eq!(triggered.load(Ordering::SeqCst), 0);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    fixture.finish(); drop(fixture);
    assert!(!root.exists()); assert_eq!(before, standard_metadata());
    println!("native_configured_bin=PASS saved_top_level_deleted=PASS owned_guid_moves=2 restored_new_uid=PASS stale_csrf_foreign_missing_refusal=PASS no_trash_fallback=PASS neighbours_foreign_unchanged=PASS no_append_expunge_crypto=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}

// Separate opt-in backend proof. The existing reader/Bin executor and their
// expunge bans above stay unchanged; this wrapper allows one declared tuple.
#[derive(Clone)]
struct ScopedDeleteExecutor {
    inner: NativeExecutor,
    permitted_args: Vec<String>,
    expunge_count: Arc<AtomicUsize>,
}
impl CommandExecutor for ScopedDeleteExecutor {
    fn run_with_stdin_bytes(&self, _: &str, _: &[String], _: &[u8]) -> Result<CommandExecution, CommandExecutionError> {
        panic!("scoped delete fixture requires bounded execution")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self, program: &str, args: &[String], input: &[u8], timeout: Duration, limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        if !args.iter().any(|value| value == "expunge") {
            assert!(args.iter().any(|value| value == "fetch"));
            return self.inner.run_with_stdin_bytes_timeout_and_output_limit(program, args, input, timeout, limit);
        }
        assert_eq!(program, "/usr/local/bin/doveadm");
        assert!(input.is_empty());
        assert_eq!(args, self.permitted_args.as_slice());
        assert!(timeout > Duration::ZERO && timeout <= Duration::from_secs(3));
        assert!(limit > 0 && limit <= crate::mailbox::DELETE_STATE_OUTPUT_MAX_BYTES);
        assert_eq!(self.expunge_count.fetch_add(1, Ordering::SeqCst), 0, "no duplicate expunge/retry");
        assert!(self.inner.config.is_absolute());
        let mut isolated = vec!["-c".into(), self.inner.config.to_string_lossy().into_owned()];
        isolated.extend_from_slice(args);
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(program, &isolated, input, timeout, limit)
    }
}

fn scoped_delete_wire_bytes(root: &Path, user: &str, folder: &str) -> Vec<Vec<u8>> {
    let mut values = Vec::new();
    for part in ["cur", "new"] {
        for entry in fs::read_dir(root.join(user).join("Maildir").join(folder).join(part)).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            values.push(fs::read(entry.path()).unwrap());
        }
    }
    values.sort();
    values
}

#[test]
#[ignore = "explicit OpenBSD retention/delete backend proof; one configured disposable tuple only"]
fn isolated_openbsd_retention_bound_single_delete_backend() {
    use crate::mailbox::{DoveadmMessageDeleteBackend, FileMailboxRetentionPolicy, MessageDeleteBackend,
        MessageDeleteError, MessageDeleteRequest, MessageDeleteResult};
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor.run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1)).unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = fs::canonicalize("/tmp").unwrap().join(format!("osmap-delete-native-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture { root: root.clone(), stop: Arc::new(AtomicBool::new(false)), threads: vec![] };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    let group = SystemCommandExecutor.run_with_stdin_timeout("/usr/bin/id", &["-g".into()], "", Duration::from_secs(1)).unwrap();
    assert_eq!(group.status_code, 0);
    let gid = group.stdout.trim().parse::<u32>().unwrap();
    assert_ne!(gid, 0);
    for directory in ["run", "state"] { fs::DirBuilder::new().mode(0o700).create(root.join(directory)).unwrap(); }
    for user in ["alice", "bob"] {
        for folder in ["", ".Deleted"] {
            for part in ["cur", "new", "tmp"] { fs::create_dir_all(root.join(user).join("Maildir").join(folder).join(part)).unwrap(); }
        }
    }
    write_message(&root, "alice", 0, 0);
    write_message(&root, "bob", 0, 0);
    write_message(&root, "alice", 1, 0);
    fs::rename(root.join("alice/Maildir/new/synthetic-001"), root.join("alice/Maildir/.Deleted/new/selected-001")).unwrap();
    let inbox_bytes = scoped_delete_wire_bytes(&root, "alice", "");
    let bob_bytes = scoped_delete_wire_bytes(&root, "bob", "");
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = serve_userdb(&mut fixture, uid, gid);
    let native = NativeExecutor { config, calls: Arc::new(AtomicUsize::new(0)), bin_move_count: None };
    let native_list = DoveadmMessageListBackend::new(MessageListPolicy::default(), native.clone(), "/usr/local/bin/doveadm")
        .with_userdb_socket_path(Some(userdb.clone()));
    let inbox_query = MessageListRequest::new(MessageListPolicy::default(), "INBOX").unwrap();
    let deleted_query = MessageListRequest::new(MessageListPolicy::default(), "Deleted").unwrap();
    // Index the sole selected object first, so same-UID cross-folder controls
    // do not depend on Maildir readdir order when the neighbour is introduced.
    assert_eq!(native_list.list_messages(ALICE, &deleted_query).unwrap().len(), 1);
    write_message(&root, "alice", 2, 0);
    let neighbour_file = root.join("alice/Maildir/.Deleted/cur/neighbour-002:2,T");
    fs::rename(root.join("alice/Maildir/new/synthetic-002"), &neighbour_file).unwrap();
    let neighbour_bytes = fs::read(&neighbour_file).unwrap();
    let inbox = native_list.list_messages(ALICE, &inbox_query).unwrap();
    let bob = native_list.list_messages(BOB, &inbox_query).unwrap();
    let deleted = native_list.list_messages(ALICE, &deleted_query).unwrap();
    assert_eq!(inbox.len(), 1); assert_eq!(bob.len(), 1); assert_eq!(deleted.len(), 2);
    let target = deleted.iter().find(|row| row.subject.as_deref() == Some("Native 001")).unwrap();
    let neighbour = deleted.iter().find(|row| row.subject.as_deref() == Some("Native 002")).unwrap().clone();
    assert_eq!(target.uid, inbox[0].uid); assert_eq!(target.uid, bob[0].uid);
    assert!(crate::mail_list::has_flag(&neighbour.flags, "\\Deleted"));
    let version = target.metadata.as_ref().unwrap().version.clone();
    assert_ne!(version.mailbox_guid, inbox[0].metadata.as_ref().unwrap().version.mailbox_guid);
    assert_ne!(version.mailbox_guid, bob[0].metadata.as_ref().unwrap().version.mailbox_guid);
    let request = MessageDeleteRequest::new(ALICE, "Deleted", target.uid, version.clone(), 7).unwrap();
    let expunge_count = Arc::new(AtomicUsize::new(0));
    let permitted_args = vec!["-o".into(), "stats_writer_socket_path=".into(), "-o".into(),
        format!("auth_socket_path={}", userdb.display()), "expunge".into(), "-u".into(), ALICE.into(),
        "mailbox".into(), "Deleted".into(), "mailbox-guid".into(), version.mailbox_guid.clone(),
        "uid".into(), target.uid.to_string(), "guid".into(), version.message_guid.clone()];
    let executor = ScopedDeleteExecutor { inner: native, permitted_args, expunge_count: expunge_count.clone() };
    let policy_path = root.join("retention.json");
    let write_policy = |revision, permission: &str| {
        fs::write(&policy_path, serde_json::to_vec(&serde_json::json!({"version":1,"rules":[{
            "account":ALICE,"mailbox_name":"Deleted","revision":revision,"permanent_delete":permission
        }]})).unwrap()).unwrap();
        fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    };
    let gate = Arc::new(Mutex::new(()));
    let backend = |policy| DoveadmMessageDeleteBackend::new(executor.clone(), "/usr/local/bin/doveadm", policy)
        .with_userdb_socket_path(Some(userdb.clone())).with_operation_gate(gate.clone());
    assert_eq!(backend(FileMailboxRetentionPolicy::default()).delete_message(ALICE, &request), Err(MessageDeleteError::PolicyUnavailable));
    write_policy(7u64, "denied");
    let authority = FileMailboxRetentionPolicy::new(Some(policy_path.clone()), uid);
    assert_eq!(backend(authority.clone()).delete_message(ALICE, &request), Err(MessageDeleteError::PolicyDenied));
    write_policy(8u64, "allowed");
    assert_eq!(backend(authority.clone()).delete_message(ALICE, &request), Err(MessageDeleteError::Stale));
    write_policy(7u64, "allowed");
    let mut stale = request.clone(); stale.version.message_guid = "stale-public-tuple".into();
    assert_eq!(backend(authority.clone()).delete_message(ALICE, &stale), Err(MessageDeleteError::Stale));
    assert_eq!(backend(authority.clone()).delete_message(BOB, &request), Err(MessageDeleteError::Invalid));
    let guard = gate.lock().unwrap();
    assert_eq!(backend(authority.clone()).delete_message(ALICE, &request), Err(MessageDeleteError::Busy));
    drop(guard);
    assert_eq!(expunge_count.load(Ordering::SeqCst), 0);
    assert_eq!(native_list.list_messages(ALICE, &deleted_query).unwrap(), deleted);
    assert_eq!(backend(authority.clone()).delete_message(ALICE, &request), Ok(MessageDeleteResult::Deleted));
    assert_eq!(expunge_count.load(Ordering::SeqCst), 1);
    assert_eq!(backend(authority).delete_message(ALICE, &request), Err(MessageDeleteError::Stale));
    assert_eq!(expunge_count.load(Ordering::SeqCst), 1);
    assert_eq!(native_list.list_messages(ALICE, &deleted_query).unwrap(), vec![neighbour]);
    assert_eq!(native_list.list_messages(ALICE, &inbox_query).unwrap(), inbox);
    assert_eq!(native_list.list_messages(BOB, &inbox_query).unwrap(), bob);
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ".Deleted"), vec![neighbour_bytes]);
    assert_eq!(scoped_delete_wire_bytes(&root, "alice", ""), inbox_bytes);
    assert_eq!(scoped_delete_wire_bytes(&root, "bob", ""), bob_bytes);
    fixture.finish(); drop(fixture);
    assert!(!root.exists()); assert_eq!(before, standard_metadata());
    println!("native_retention_single_delete_backend=PASS exact_identity_expunge_once=PASS absent_denied_changed_revision_stale_busy_foreign_refusal=PASS preexisting_deleted_neighbour_intact=PASS same_uid_inbox_bob_bytes_flags_guids_unchanged=PASS no_helper_http_claim=PASS scratch_cleanup=PASS standard_host_metadata_unchanged=PASS");
}
