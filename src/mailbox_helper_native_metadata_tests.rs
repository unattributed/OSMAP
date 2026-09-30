// Opt-in native test: private synthetic accounts, no standard config/userdb access.
use super::*;
use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicBool, Ordering};
#[derive(Clone)]
struct FixtureExecutor {
    config: PathBuf,
    calls: Arc<Mutex<Vec<String>>>,
}
impl CommandExecutor for FixtureExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded execution required")
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
        assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
        assert_eq!(a.len(), 8);
        assert_eq!(&a[..4], ["exec", "imap", "-o", "stats_writer_socket_path="]);
        assert_eq!(a[4], "-o");
        assert!(a[5].starts_with("auth_socket_path="));
        assert_eq!(a[6], "-u");
        assert!([
            "alice@fixture.test",
            "bob@fixture.test",
            "unknown@fixture.test"
        ]
        .contains(&a[7].as_str()));
        assert!(timeout <= Duration::from_secs(10));
        assert_eq!(limit, 512 * 1024);
        self.calls.lock().unwrap().push(a[7].clone());
        // Only prepend fixture config. Preserve exact canonical -u; never set USER.
        let mut args = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
        args.extend_from_slice(a);
        SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(p, &args, input, timeout, limit)
    }
}
struct Fixture {
    root: PathBuf,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.server.take() {
            let _ = t.join();
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
    .map(|p| {
        fs::symlink_metadata(p)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
    })
    .collect()
}
#[test]
#[ignore = "explicit OpenBSD two-account userdb and signed helper qualification"]
fn isolated_openbsd_folder_metadata_signed_helper() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let root = env::temp_dir().join(format!(
        "osmap-folder-native-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let owner = fs::metadata(&root).unwrap();
    assert_ne!(owner.uid(), 0);
    assert_ne!(owner.gid(), 0);
    let mut fixture = Fixture {
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        server: None,
    };
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
    fs::write(&config,format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {1}\nmail_gid = {2}\nfirst_valid_uid = {1}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n",root.display(),owner.uid(),owner.gid())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let socket = root.join("userdb");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let queries = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed = queries.clone();
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
                    .unwrap();
                if n == 0 {
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
                    continue;
                }
                assert_eq!(fields[0], "USER");
                assert!(fields.len() >= 4);
                let id = fields[1];
                assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()));
                let account = fields[2];
                observed.lock().unwrap().push(account.into());
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
                            owner.gid(),
                            private.join(user).display()
                        )
                        .unwrap();
                    }
                    _ => writeln!(stream, "NOTFOUND\t{id}").unwrap(),
                }
            }
        }
    }));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let backend = |missing| {
        DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            FixtureExecutor {
                config: config.clone(),
                calls: calls.clone(),
            },
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(if missing {
            root.join("missing")
        } else {
            socket.clone()
        }))
    };
    let alice =
        super::metadata_tests::metadata_through_helper(&root, backend(false), "alice@fixture.test")
            .unwrap();
    let bob =
        super::metadata_tests::metadata_through_helper(&root, backend(false), "bob@fixture.test")
            .unwrap();
    assert!(alice.folder("alice@fixture.test", "AliceOnly").is_ok());
    assert!(alice.folder("alice@fixture.test", "BobOnly").is_err());
    assert!(alice.validate_for("bob@fixture.test").is_err());
    assert!(bob.folder("bob@fixture.test", "BobOnly").is_ok());
    assert!(bob.folder("bob@fixture.test", "AliceOnly").is_err());
    assert!(super::metadata_tests::metadata_through_helper(
        &root,
        backend(false),
        "unknown@fixture.test"
    )
    .is_err());
    assert!(super::metadata_tests::metadata_through_helper(
        &root,
        backend(true),
        "alice@fixture.test"
    )
    .is_err());
    assert_eq!(
        *queries.lock().unwrap(),
        [
            "alice@fixture.test",
            "bob@fixture.test",
            "unknown@fixture.test"
        ]
    );
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "alice@fixture.test",
            "bob@fixture.test",
            "unknown@fixture.test",
            "alice@fixture.test"
        ]
    );
    fixture.stop.store(true, Ordering::SeqCst);
    fixture.server.take().unwrap().join().unwrap();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(before, standard_metadata());
}
