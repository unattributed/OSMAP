// Explicit opt-in OpenBSD qualification: owned synthetic Maildirs/userdb only.
use super::*;
use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
use crate::mailbox::MessageSearchBatchRequest;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicBool, Ordering};
// Diagnostic records contain finite stage labels and elapsed times only. They
// never retain native output, mail queries, userdb identities or credentials.
struct NativeDiagnostics {
    started: std::time::Instant,
    events: BTreeMap<&'static str, (usize, u128)>,
}
impl NativeDiagnostics {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            events: BTreeMap::new(),
        }
    }
    fn record(&mut self, phase: &'static str) {
        let elapsed = self.started.elapsed().as_millis();
        let entry = self.events.entry(phase).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = elapsed;
    }
    fn report(&self, phase: &'static str) {
        println!("native_fixture_diagnostic_phase={phase}; elapsed_ms={}; userdb_stage_counts_and_last_ms={:?}",
            self.started.elapsed().as_millis(), self.events);
    }
}
fn report_native_log_classification(root: &Path) {
    const MAX_DIAGNOSTIC_BYTES: u64 = 16 * 1024;
    let Ok(file) = fs::File::open(root.join("native.log")) else {
        println!("native_fixture_log_available=false");
        return;
    };
    let mut bytes = Vec::new();
    if std::io::Read::read_to_end(
        &mut std::io::Read::take(file, MAX_DIAGNOSTIC_BYTES + 1),
        &mut bytes,
    )
    .is_err()
    {
        println!("native_fixture_log_read_failed=true");
        return;
    }
    let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
    println!("native_fixture_log_available=true; inspected_bytes={}; truncated={}; auth_diagnostic={}; timeout_diagnostic={}; permission_diagnostic={}; storage_diagnostic={}; error_diagnostic={}",
        bytes.len(), bytes.len() as u64 > MAX_DIAGNOSTIC_BYTES,
        text.contains("auth") || text.contains("userdb"),
        text.contains("timeout") || text.contains("timed out"),
        text.contains("permission denied") || text.contains("operation not permitted"),
        text.contains("maildir") || text.contains("index") || text.contains("lock"),
        text.contains("error:") || text.contains("fatal:"));
}
#[derive(Clone)]
struct BatchNativeExecutor {
    config: PathBuf,
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    diagnostics: Arc<Mutex<NativeDiagnostics>>,
}
impl CommandExecutor for BatchNativeExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded native execution required")
    }
    fn run_with_stdin_bytes_timeout(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, "/usr/local/bin/doveadm");
        assert!(input.is_empty());
        assert!(timeout <= Duration::from_secs(5));
        let index = args
            .iter()
            .position(|arg| arg == "-u")
            .expect("canonical -u");
        assert!([
            "alice@fixture.test",
            "bob@fixture.test",
            "unknown@fixture.test"
        ]
        .contains(&args[index + 1].as_str()));
        self.calls.lock().unwrap().push(args.to_vec());
        let mut native = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
        native.extend_from_slice(args);
        let phase = if args.iter().any(|arg| arg == "status") {
            "guid_discovery"
        } else if args.iter().any(|arg| arg == "fetch") {
            "fetch"
        } else if args.iter().any(|arg| arg == "list") {
            "listing"
        } else {
            "other"
        };
        let started = std::time::Instant::now();
        let start_offset = self
            .diagnostics
            .lock()
            .unwrap()
            .started
            .elapsed()
            .as_millis();
        let result =
            SystemCommandExecutor.run_with_stdin_bytes_timeout(program, &native, input, timeout);
        let (status, output_bytes, stderr_bytes, refusal) = match &result {
            Ok(execution) => (
                Some(execution.status_code),
                Some(execution.stdout.len()),
                Some(execution.stderr.len()),
                "none",
            ),
            Err(error) => (
                None,
                None,
                None,
                if error.reason.contains("timed out") {
                    "command_timeout"
                } else {
                    "executor_refused"
                },
            ),
        };
        println!("native_fixture_command_phase={phase}; start_offset_ms={start_offset}; elapsed_ms={}; timeout_ms={}; status={status:?}; stdout_bytes={output_bytes:?}; stderr_bytes={stderr_bytes:?}; refusal={refusal}", started.elapsed().as_millis(), timeout.as_millis());
        if result.is_err() || status.is_some_and(|value| value != 0) {
            self.diagnostics
                .lock()
                .unwrap()
                .report("native_command_refused");
        }
        result
    }
}
struct Fixture {
    root: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
    diagnostics: Arc<Mutex<NativeDiagnostics>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if thread::panicking() {
            self.diagnostics
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .report("failure_before_cleanup");
            report_native_log_classification(&self.root);
        }
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.server.take() {
            thread.join().unwrap();
        }
        fs::remove_dir_all(&self.root).unwrap();
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
    .map(|p| {
        fs::symlink_metadata(p)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
    })
    .collect()
}
fn native_batch_through_signed_helper(
    root: &Path,
    backend: DoveadmMessageSearchBackend<BatchNativeExecutor>,
    account: &str,
    request: &MessageSearchBatchRequest,
) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
    let socket = root.join("batch.sock");
    let thread_socket = socket.clone();
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
        let listener = UnixListener::bind(thread_socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        handle_helper_client(
            HelperBackends {
                mailbox_backend: &unused,
                message_list_backend: &unused,
                message_search_backend: &backend,
                message_view_backend: &unused,
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
    let result = MailboxHelperMessageSearchBackend::new(
        &socket,
        root.join("fixture-grant.key"),
        MailboxHelperPolicy::default(),
        MessageSearchPolicy::default(),
    )
    .search_messages_batch(account, request);
    server.join().unwrap();
    fs::remove_file(socket).unwrap();
    result
}
fn fixture_message(root: &Path, user: &str, folder: Option<&str>, name: &str, subject: &str) {
    let mut maildir = root.join(user).join("Maildir");
    if let Some(folder) = folder {
        maildir = maildir.join(format!(".{folder}"));
    }
    for part in ["cur", "new", "tmp"] {
        fs::create_dir_all(maildir.join(part)).unwrap();
    }
    let file = maildir.join("new").join(name);
    fs::write(&file, format!("From: fixture@example.test\r\nTo: {user}@fixture.test\r\nSubject: {subject}\r\nDate: Sat, 03 Oct 2026 00:00:00 +0000\r\nMessage-ID: <{name}@fixture.test>\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nSynthetic owned fixture only.\r\n")).unwrap();
    fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
}
#[test]
#[ignore = "explicit owned OpenBSD Dovecot2.3 batch/helper qualification; no standard Maildir"]
fn isolated_openbsd_signed_search_batch_39_folders_and_scope() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = env::temp_dir().join(format!(
        "osmap-search-batch-native-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let diagnostics = Arc::new(Mutex::new(NativeDiagnostics::new()));
    let mut fixture = Fixture {
        diagnostics: diagnostics.clone(),
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        server: None,
    };
    let owner = fs::metadata(&root).unwrap();
    assert_ne!(owner.uid(), 0);
    assert_eq!(owner.mode() & 0o777, 0o700);
    // OpenBSD temp directories may inherit wheel; use the process group for userdb.
    let group = SystemCommandExecutor
        .run_with_stdin_timeout("/usr/bin/id", &["-g".into()], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(group.status_code, 0);
    let fixture_gid = group.stdout.trim().parse::<u32>().unwrap();
    for n in ["run", "state"] {
        fs::create_dir(root.join(n)).unwrap();
    }
    for (user, folder) in [("alice", "AliceOnly"), ("bob", "BobOnly")] {
        for part in ["cur", "new", "tmp"] {
            fs::create_dir_all(root.join(user).join("Maildir").join(part)).unwrap();
            fs::create_dir_all(
                root.join(user)
                    .join("Maildir")
                    .join(format!(".{folder}"))
                    .join(part),
            )
            .unwrap();
        }
    }
    let config = root.join("dovecot.conf");
    fs::write(&config,format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {1}\nmail_gid = {2}\nfirst_valid_uid = {1}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n",root.display(),owner.uid(),fixture_gid)).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let socket = root.join("userdb");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let observed = diagnostics.clone();
    let stop = fixture.stop.clone();
    let private = root.clone();
    fixture.server = Some(thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        while !stop.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("fixture accept: {e}"),
            };
            observed.lock().unwrap().record("accept");
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
                let n = std::io::Read::by_ref(&mut reader)
                    .take(4097)
                    .read_until(b'\n', &mut line)
                    .inspect_err(|error| {
                        let mut stats = observed.lock().unwrap();
                        stats.record(
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                            ) {
                                "read_timeout"
                            } else {
                                "read_error"
                            },
                        );
                        stats.report("userdb_read_refused");
                    })
                    .unwrap();
                if n == 0 {
                    observed.lock().unwrap().record("eof");
                    break;
                }
                assert!(n <= 4096 && line.ends_with(b"\n"));
                let fields: Vec<_> = std::str::from_utf8(&line)
                    .unwrap()
                    .trim_end_matches('\n')
                    .split('\t')
                    .collect();
                if fields[0] == "VERSION" {
                    assert!(fields.len() == 3 && fields[1] == "1");
                    observed.lock().unwrap().record("version");
                    continue;
                }
                assert_eq!(fields[0], "USER");
                assert!(fields.len() >= 4);
                let id = fields[1];
                assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()));
                let account = fields[2];
                observed.lock().unwrap().record("user_request");
                match account {
                    "alice@fixture.test" | "bob@fixture.test" => {
                        let user = if account.starts_with("alice@") {
                            "alice"
                        } else {
                            "bob"
                        };
                        writeln!(
                            stream,
                            "USER\t{id}\t{account}\tuid={}\tgid={}\thome={}",
                            owner.uid(),
                            fixture_gid,
                            private.join(user).display()
                        )
                        .unwrap();
                    }
                    _ => writeln!(stream, "NOTFOUND\t{id}").unwrap(),
                }
                observed.lock().unwrap().record("reply");
            }
        }
    }));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let executor = BatchNativeExecutor {
        config: config.clone(),
        calls: calls.clone(),
        diagnostics: diagnostics.clone(),
    };
    for index in 0..38 {
        for part in ["cur", "new", "tmp"] {
            fs::create_dir_all(
                root.join("alice/Maildir")
                    .join(format!(".INBOX.fixture{index:02}"))
                    .join(part),
            )
            .unwrap();
        }
    }
    fixture_message(&root, "alice", None, "first-1", "batch-native-needle");
    fixture_message(
        &root,
        "alice",
        Some("INBOX.fixture37"),
        "late-1",
        "batch-native-needle",
    );
    fixture_message(
        &root,
        "alice",
        Some("AliceOnly"),
        "hidden-1",
        "batch-native-needle",
    );
    fixture_message(&root, "bob", None, "bob-1", "batch-native-needle");
    let listing = DoveadmMailboxListBackend::new(
        MailboxListingPolicy::default(),
        executor.clone(),
        "/usr/local/bin/doveadm",
    )
    .with_userdb_socket_path(Some(socket.clone()))
    .with_command_timeout_secs(4)
    .list_mailboxes("alice@fixture.test")
    .unwrap();
    let names = listing
        .into_iter()
        .filter(|folder| folder.name == "INBOX" || folder.name.starts_with("INBOX."))
        .map(|folder| folder.name)
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 39, "actual native visible-folder discovery");
    let backend = || {
        DoveadmMessageSearchBackend::new(
            MessageSearchPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(socket.clone()))
        .with_command_timeout_secs(3)
    };
    let request = MessageSearchBatchRequest::new(
        MessageSearchPolicy::default(),
        names,
        "batch-native-needle",
        MessageSearchField::Subject,
    )
    .unwrap();
    let started = std::time::Instant::now();
    let rows = native_batch_through_signed_helper(&root, backend(), "alice@fixture.test", &request)
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| row.mailbox_name == "INBOX.fixture37"));
    assert!(rows
        .iter()
        .all(|row| request.mailbox_names.contains(&row.mailbox_name) && row.metadata.is_some()));
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|args| args.iter().any(|arg| arg == "fetch"))
            .count(),
        1,
        "accepted signed batch invokes exactly one native fetch"
    );
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .filter(|args| args.iter().any(|arg| arg == "status"))
            .count(),
        0,
        "ordinary 39-folder scope does not add a GUID metadata discovery"
    );

    let bob = MessageSearchBatchRequest::new(
        MessageSearchPolicy::default(),
        vec!["INBOX".into()],
        "batch-native-needle",
        MessageSearchField::Subject,
    )
    .unwrap();
    let rows =
        native_batch_through_signed_helper(&root, backend(), "bob@fixture.test", &bob).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].metadata.is_some());
    assert!(
        native_batch_through_signed_helper(&root, backend(), "unknown@fixture.test", &bob).is_err()
    );
    println!("native_39_folder_grouped_signed_batch=PASS; late_folder_match=PASS; native_account_separation=PASS");
    fixture_message(
        &root,
        "alice",
        Some("INBOX.literal*folder"),
        "literal-1",
        "wildcard-native-needle",
    );
    fixture_message(
        &root,
        "alice",
        Some("INBOX.literalXfolder"),
        "sibling-1",
        "wildcard-native-needle",
    );
    let wildcard = MessageSearchBatchRequest::new(
        MessageSearchPolicy::default(),
        vec!["INBOX.literal*folder".into()],
        "wildcard-native-needle",
        MessageSearchField::Subject,
    )
    .unwrap();
    let before_wildcard = calls.lock().unwrap().len();
    let rows =
        native_batch_through_signed_helper(&root, backend(), "alice@fixture.test", &wildcard)
            .expect("valid wildcard-shaped folder must retain literal scope");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].mailbox_name, "INBOX.literal*folder");
    {
        let all = calls.lock().unwrap();
        let wildcard_calls = &all[before_wildcard..];
        assert_eq!(
            wildcard_calls.len(),
            2,
            "one metadata discovery and one fetch"
        );
        assert!(wildcard_calls[0].iter().any(|arg| arg == "status"));
        assert!(wildcard_calls[1].iter().any(|arg| arg == "mailbox-guid"));
        assert!(!wildcard_calls[1]
            .iter()
            .any(|arg| arg == "INBOX.literal*folder"));
    }

    for index in 0..260 {
        fixture_message(
            &root,
            "alice",
            None,
            &format!("cap-{index}"),
            "cap-native-needle",
        );
    }
    let cap = MessageSearchBatchRequest::new(
        MessageSearchPolicy::default(),
        vec!["INBOX".into()],
        "cap-native-needle",
        MessageSearchField::Subject,
    )
    .unwrap();
    assert_eq!(
        native_batch_through_signed_helper(&root, backend(), "alice@fixture.test", &cap)
            .unwrap()
            .len(),
        250
    );
    assert_eq!(standard_metadata(), before);
    drop(fixture);
    assert!(!root.exists());
    println!(
        "native_literal_wildcard_scope=PASS; native_250_prefix=PASS; native_fixture_cleanup=PASS"
    );
}
