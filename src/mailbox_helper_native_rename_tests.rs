// Opt-in native Rename qualification. Parent owns the disposable root/userdb;
// one bounded child enforces real helper confinement and reports closed stages.
use super::*;
use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
use crate::folder_rename::{Completion, Outcome, RenameFolderRequest};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicBool, Ordering};

const ALICE: &str = "alice@osmap-rename.invalid";
const BOB: &str = "bob@osmap-rename.invalid";
const CHILD: &str =
    "mailbox_helper::tests::native_rename_tests::isolated_openbsd_folder_rename_confined_worker";
const WHOLE: Duration = Duration::from_secs(60);
const MESSAGE: &[u8] = b"From: fixture@osmap-rename.invalid\r\nTo: alice@osmap-rename.invalid\r\nSubject: Owned rename fixture\r\nDate: Tue, 06 Oct 2026 00:00:00 +0000\r\nMessage-ID: <rename@osmap-rename.invalid>\r\nContent-Type: text/plain\r\n\r\nPopulated folder contents stay with its native identity.\r\n";

fn numeric_id(flag: &str) -> u32 {
    assert!(matches!(flag, "-u" | "-g"));
    let out = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/bin/id",
            &[flag.into()],
            b"",
            Duration::from_secs(2),
            32,
        )
        .unwrap();
    assert_eq!(out.status_code, 0);
    assert!(out.stderr.is_empty() && out.stdout.ends_with('\n'));
    let digits = out.stdout.strip_suffix('\n').unwrap();
    assert!(!digits.is_empty() && digits.len() <= 10 && digits.bytes().all(|b| b.is_ascii_digit()));
    digits.parse().unwrap()
}

#[derive(Clone)]
struct ScopedExecutor {
    config: PathBuf,
    renames: Arc<AtomicUsize>,
}
impl CommandExecutor for ScopedExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("native Rename requires bounded execution")
    }
    fn run_with_stdin_bytes_timeout(
        &self,
        p: &str,
        a: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        self.run_with_stdin_bytes_timeout_and_output_limit(p, a, input, timeout, 512 * 1024)
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
        assert!(!timeout.is_zero() && timeout <= Duration::from_secs(10));
        assert!(limit <= 512 * 1024);
        assert!(!a
            .iter()
            .any(|s| matches!(s.as_str(), "-A" | "-F" | "-s" | "-c")));
        assert_eq!(a.iter().filter(|s| s.as_str() == "-u").count(), 1);
        let pos = a.iter().position(|s| s == "-u").unwrap();
        assert!([ALICE, BOB].contains(&a[pos + 1].as_str()));
        if a.first().is_some_and(|s| s == "exec") {
            assert_eq!(a.get(1).map(String::as_str), Some("imap"));
            assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
        } else {
            assert!(input.is_empty());
        }
        if a.windows(2).any(|s| s == ["mailbox", "rename"]) {
            assert_eq!(a[pos + 1], ALICE);
            assert_eq!(&a[pos + 2..], ["INBOX.Alpha", "INBOX.Beta"]);
            self.renames.fetch_add(1, Ordering::SeqCst);
        }
        let args = scoped_args(&self.config, a);
        // Existing disposable native-create pattern: canonical -u is preserved.
        let began = std::time::Instant::now();
        let phase = if a.first().is_some_and(|s| s == "exec") {
            "metadata"
        } else if a.iter().any(|s| s == "rename") {
            "rename"
        } else if a.iter().any(|s| s == "status") {
            "status"
        } else {
            "summary"
        };
        let result = SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(p, &args, input, timeout, limit);
        let (code, out_bytes, err_bytes) = result
            .as_ref()
            .map(|r| (Some(r.status_code), r.stdout.len(), r.stderr.len()))
            .unwrap_or((None, 0, 0));
        let refusal = result
            .as_ref()
            .err()
            .map(|error| {
                if error.reason.contains("timed out") {
                    "timeout"
                } else {
                    "executor_refused"
                }
            })
            .unwrap_or("none");
        println!("native_rename_command phase={phase} code={code:?} stdout_bytes={out_bytes} stderr_bytes={err_bytes} refusal={refusal} elapsed_ms={}", began.elapsed().as_millis());
        result
    }
}

fn scoped_args(config: &Path, args: &[String]) -> Vec<String> {
    let mut result = vec!["-c".into(), config.to_string_lossy().into_owned()];
    if args.first().is_some_and(|arg| arg == "exec") {
        result.extend_from_slice(&args[..2]);
        // Dovecot2.3 exec passes only explicit binary parameters. The owned
        // config therefore also belongs to imap's argv, never its host default.
        result.extend(["-c".into(), config.to_string_lossy().into_owned()]);
        result.extend_from_slice(&args[2..]);
    } else {
        result.extend_from_slice(args);
    }
    result
}

// Closed child diagnostics: payloads, commands, paths and raw stderr never escape.
const CHILD_STAGES: &[&str] = &[
    "entry",
    "read_lease",
    "parse_lease",
    "validate_lease",
    "grant_owner",
    "create_settings",
    "config_parse",
    "confinement_plan",
    "apply_confinement",
    "native_preflight",
    "private_indexes",
    "signed_rename",
    "rename_confirmation",
    "metadata_continuity",
    "lost_refusal",
    "completion_query",
    "recovery_check",
    "authority_controls",
    "complete",
];
static CHILD_STAGE: AtomicUsize = AtomicUsize::new(0);

fn mark_child_stage(stage: &'static str) {
    let index = CHILD_STAGES
        .iter()
        .position(|value| *value == stage)
        .unwrap();
    CHILD_STAGE.store(index, Ordering::SeqCst);
    println!("\nnative_rename child_stage={stage}");
    let _ = std::io::stdout().flush();
}
fn panic_kind(payload: &(dyn std::any::Any + Send)) -> &'static str {
    let value = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    if value.starts_with("called `Result::unwrap()`") {
        "unwrap_result"
    } else if value.starts_with("called `Option::unwrap()`") {
        "unwrap_option"
    } else if value.starts_with("assertion") {
        "assertion"
    } else {
        "other"
    }
}
fn public_panic_location(file: &str, line: u32, column: u32) -> (&'static str, u32, u32) {
    match file {
        "src/mailbox_helper_native_rename_tests.rs" => ("native_test", line, column),
        "src/mailbox_helper_rename_tests.rs" => ("helper_test", line, column),
        _ => ("other_source", 0, 0),
    }
}
fn install_child_diagnostics() {
    std::panic::set_hook(Box::new(|info| {
        let stage = CHILD_STAGES
            .get(CHILD_STAGE.load(Ordering::SeqCst))
            .copied()
            .unwrap_or("entry");
        let (file, line, column) = info
            .location()
            .map(|location| {
                public_panic_location(location.file(), location.line(), location.column())
            })
            .unwrap_or(("other_source", 0, 0));
        println!("native_rename child_panic stage={stage} file={file} line={line} column={column} kind={} diagnostic=v1", panic_kind(info.payload()));
        let _ = std::io::stdout().flush();
    }));
}
fn closed_child_diagnostic(line: &str) -> bool {
    if let Some(stage) = line.strip_prefix("native_rename child_stage=") {
        return CHILD_STAGES.contains(&stage);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 8 || fields[..2] != ["native_rename", "child_panic"] {
        return false;
    }
    let stage = fields[2].strip_prefix("stage=").unwrap_or("");
    let file = fields[3].strip_prefix("file=").unwrap_or("");
    let number = |field: &str, prefix: &str| {
        field.strip_prefix(prefix).is_some_and(|value| {
            !value.is_empty()
                && value.len() <= 10
                && value.bytes().all(|b| b.is_ascii_digit())
                && value.parse::<u32>().is_ok()
        })
    };
    CHILD_STAGES.contains(&stage)
        && ["native_test", "helper_test", "other_source"].contains(&file)
        && number(fields[4], "line=")
        && number(fields[5], "column=")
        && [
            "kind=unwrap_result",
            "kind=unwrap_option",
            "kind=assertion",
            "kind=other",
        ]
        .contains(&fields[6])
        && fields[7] == "diagnostic=v1"
}
fn forward_child_diagnostics(stdout: &str) {
    for line in stdout
        .lines()
        .filter(|line| closed_child_diagnostic(line))
        .take(64)
    {
        println!("{line}");
    }
}
fn native_child_values(lease: &Lease) -> BTreeMap<String, String> {
    let root = &lease.root;
    let helper = root.join("helper");
    let mut values = BTreeMap::new();
    for (name, value) in [
        ("OSMAP_RUN_MODE", "mailbox-helper".to_string()),
        ("OSMAP_STATE_DIR", root.display().to_string()),
        ("OSMAP_RUNTIME_DIR", helper.display().to_string()),
        (
            "OSMAP_DOVEADM_AUTH_SOCKET_PATH",
            root.join("userdb").display().to_string(),
        ),
        (
            "OSMAP_DOVEADM_USERDB_SOCKET_PATH",
            root.join("userdb").display().to_string(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_SOCKET_PATH",
            helper.join("status.sock").display().to_string(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH",
            helper.join("fixture-grant.key").display().to_string(),
        ),
        ("OSMAP_TRUSTED_WEB_RUNTIME_UID", lease.uid.to_string()),
        ("OSMAP_OPENBSD_CONFINEMENT_MODE", "enforce".to_string()),
    ] {
        values.insert(name.into(), value);
    }
    values
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    root: PathBuf,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl Lease {
    fn validate(&self) {
        assert_eq!(self.root.parent(), Some(Path::new("/tmp")));
        let name = self.root.file_name().unwrap().to_str().unwrap();
        let suffix = name.strip_prefix("osmap-rename-native-").unwrap();
        assert!(
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let m = fs::symlink_metadata(&self.root).unwrap();
        assert!(m.is_dir() && !m.file_type().is_symlink());
        assert_eq!(
            (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o7777),
            (self.dev, self.ino, self.uid, self.gid, self.mode)
        );
        assert_eq!(self.mode, 0o700);
        assert_eq!(self.uid, numeric_id("-u"));
        assert_ne!(self.uid, 0);
        assert_ne!(numeric_id("-g"), 0);
    }
}
struct Fixture {
    lease: Lease,
    stop: Arc<AtomicBool>,
    userdb: Option<thread::JoinHandle<()>>,
    cleanup_allowed: bool,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.userdb.take() {
            let _ = t.join();
        }
        if !self.cleanup_allowed {
            println!("native_rename cleanup=UNCONFIRMED fixture_retained=true root={} dev={} ino={} uid={} gid={} mode={:o}", self.lease.root.display(), self.lease.dev, self.lease.ino, self.lease.uid, self.lease.gid, self.lease.mode);
            return;
        }
        if fs::symlink_metadata(&self.lease.root)
            .ok()
            .is_some_and(|m| {
                m.is_dir()
                    && (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o7777)
                        == (
                            self.lease.dev,
                            self.lease.ino,
                            self.lease.uid,
                            self.lease.gid,
                            0o700,
                        )
            })
        {
            let _ = fs::remove_dir_all(&self.lease.root);
        }
    }
}
fn userdb(f: &mut Fixture, uid: u32, gid: u32) {
    let listener = UnixListener::bind(f.lease.root.join("userdb")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let root = f.lease.root.clone();
    let stop = f.stop.clone();
    f.userdb = Some(thread::spawn(move || {
        let until = std::time::Instant::now() + WHOLE;
        while !stop.load(Ordering::SeqCst) && std::time::Instant::now() < until {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("owned Rename userdb accept: {e}"),
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
                let size = std::io::Read::by_ref(&mut reader)
                    .take(4097)
                    .read_until(b'\n', &mut line)
                    .unwrap();
                if size == 0 {
                    break;
                }
                assert!(size <= 4096 && line.ends_with(b"\n"));
                let fields: Vec<_> = std::str::from_utf8(&line)
                    .unwrap()
                    .trim_end_matches('\n')
                    .split('\t')
                    .collect();
                if fields.first() == Some(&"VERSION") {
                    assert_eq!(fields.len(), 3);
                    continue;
                }
                assert_eq!(fields.first(), Some(&"USER"));
                assert!(fields.len() >= 4);
                let id = fields[1];
                assert!(!id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()));
                match fields[2] {
                    ALICE | BOB => {
                        let who = if fields[2] == ALICE { "alice" } else { "bob" };
                        writeln!(
                            stream,
                            "USER\t{id}\t{}\tuid={uid}\tgid={gid}\thome={}",
                            fields[2],
                            root.join(who).display()
                        )
                        .unwrap();
                    }
                    _ => writeln!(stream, "NOTFOUND\t{id}").unwrap(),
                }
            }
        }
    }));
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
fn bodies(root: &Path, who: &str, folder: &str) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    for part in ["new", "cur"] {
        let dir = root
            .join(who)
            .join("Maildir")
            .join(format!(".{folder}"))
            .join(part);
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let m = fs::symlink_metadata(entry.path()).unwrap();
            assert!(m.is_file() && m.len() <= 4096 && result.len() < 4);
            result.push(fs::read(entry.path()).unwrap());
        }
    }
    result.sort();
    result
}
#[test]
fn native_rename_scopes_parent_and_imap_config_without_changing_account() {
    let args: Vec<String> = [
        "exec",
        "imap",
        "-o",
        "stats_writer_socket_path=",
        "-u",
        ALICE,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let prepared = scoped_args(Path::new("/owned/fixture.conf"), &args);
    assert_eq!(
        prepared,
        [
            "-c",
            "/owned/fixture.conf",
            "exec",
            "imap",
            "-c",
            "/owned/fixture.conf",
            "-o",
            "stats_writer_socket_path=",
            "-u",
            ALICE
        ]
    );
    assert_eq!(
        args,
        [
            "exec",
            "imap",
            "-o",
            "stats_writer_socket_path=",
            "-u",
            ALICE
        ]
    );
    let status: Vec<String> = ["mailbox", "status", "-u", ALICE, "guid", "INBOX"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        scoped_args(Path::new("/owned/fixture.conf"), &status),
        [
            "-c",
            "/owned/fixture.conf",
            "mailbox",
            "status",
            "-u",
            ALICE,
            "guid",
            "INBOX"
        ]
    );
}

#[test]
fn native_rename_cleanup_retains_unconfirmed_child_or_changed_lease() {
    for confirmed in [false, true] {
        let root = Path::new("/tmp").join(format!(
            "osmap-rename-cleanup-control-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let m = fs::symlink_metadata(&root).unwrap();
        let original = (m.dev(), m.ino(), m.uid(), m.gid(), m.mode() & 0o7777);
        let f = Fixture {
            lease: Lease {
                root: root.clone(),
                dev: m.dev(),
                ino: m.ino() + u64::from(confirmed),
                uid: m.uid(),
                gid: m.gid(),
                mode: 0o700,
            },
            stop: Arc::new(AtomicBool::new(false)),
            userdb: None,
            cleanup_allowed: confirmed,
        };
        drop(f);
        assert!(root.exists());
        let retained = fs::symlink_metadata(&root).unwrap();
        assert_eq!(
            (
                retained.dev(),
                retained.ino(),
                retained.uid(),
                retained.gid(),
                retained.mode() & 0o7777
            ),
            original
        );
        fs::remove_dir(&root).unwrap();
    }
}

#[test]
fn native_rename_executor_refuses_foreign_authority_before_dispatch() {
    let e = ScopedExecutor {
        config: PathBuf::from("/dev/null"),
        renames: Arc::new(AtomicUsize::new(0)),
    };
    for (p, args) in [
        ("/usr/bin/true", vec!["-u", ALICE]),
        (
            "/usr/local/bin/doveadm",
            vec!["-u", "operator@example.test"],
        ),
        ("/usr/local/bin/doveadm", vec!["-A", "-u", ALICE]),
        (
            "/usr/local/bin/doveadm",
            vec!["-u", BOB, "mailbox", "rename"],
        ),
    ] {
        assert!(
            std::panic::catch_unwind(|| e.run_with_stdin_bytes_timeout_and_output_limit(
                p,
                &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                b"",
                Duration::from_secs(1),
                4096
            ))
            .is_err()
        );
    }
    assert_eq!(e.renames.load(Ordering::SeqCst), 0);
}
#[test]
#[ignore = "explicit disposable OpenBSD populated Rename and confined signed helper"]
fn isolated_openbsd_folder_rename_populated_and_recovery() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let began = std::time::Instant::now();
    let host = SystemCommandExecutor
        .run_with_stdin_timeout("/bin/hostname", &[], "", Duration::from_secs(1))
        .unwrap();
    assert_eq!(host.status_code, 0);
    assert_eq!(host.stdout.trim(), "obsd1.blackbagsecurity.com");
    let before = standard_metadata();
    let uid = numeric_id("-u");
    let gid = numeric_id("-g");
    assert!(uid > 0 && gid > 0);
    let root = Path::new("/tmp").join(format!(
        "osmap-rename-native-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let m = fs::symlink_metadata(&root).unwrap();
    let mut f = Fixture {
        lease: Lease {
            root: root.clone(),
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
        },
        stop: Arc::new(AtomicBool::new(false)),
        userdb: None,
        cleanup_allowed: true,
    };
    f.lease.validate();
    for dir in ["run", "state", "helper"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(dir))
            .unwrap();
    }
    for who in ["alice", "bob"] {
        for folder in ["", ".INBOX.Alpha"] {
            for part in ["new", "cur", "tmp"] {
                fs::create_dir_all(root.join(who).join("Maildir").join(folder).join(part)).unwrap();
            }
        }
        fs::write(
            root.join(who)
                .join("Maildir/.INBOX.Alpha/new/owned-message"),
            MESSAGE,
        )
        .unwrap();
    }
    fs::write(
        root.join("helper/fixture-grant.key"),
        test_helper_grant_key(),
    )
    .unwrap();
    fs::set_permissions(
        root.join("helper/fixture-grant.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(root.join("dovecot.conf"), format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {uid}\nmail_gid = {gid}\nfirst_valid_uid = {uid}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nmailbox_list_index = yes\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator = .\n}}\n", root.display())).unwrap();
    fs::set_permissions(root.join("dovecot.conf"), fs::Permissions::from_mode(0o600)).unwrap();
    userdb(&mut f, uid, gid);
    let executable = std::env::current_exe().unwrap();
    f.cleanup_allowed = false;
    let child = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            executable.to_str().unwrap(),
            &[
                "--exact".into(),
                CHILD.into(),
                "--ignored".into(),
                "--nocapture".into(),
                "--test-threads=1".into(),
            ],
            &serde_json::to_vec(&f.lease).unwrap(),
            Duration::from_secs(45),
            65536,
        )
        .unwrap();
    forward_child_diagnostics(&child.stdout);
    assert_eq!(
        child.status_code,
        0,
        "native_rename stage=confined_child code={} stderr_bytes={}",
        child.status_code,
        child.stderr.len()
    );
    for stage in [
        "populated_guid_bytes=PASS",
        "label_snooze=PASS",
        "lost_no_mutation=PASS",
        "authority_refusals=PASS",
        "confinement=PASS",
    ] {
        assert!(child.stdout.contains(stage), "missing closed stage {stage}");
        println!("native_rename {stage}");
    }
    f.cleanup_allowed = true;
    assert!(began.elapsed() < WHOLE);
    assert_eq!(standard_metadata(), before);
    drop(f);
    assert!(!root.exists());
    assert_eq!(standard_metadata(), before);
    println!("native_rename cleanup=PASS standard_three_path_metadata_unchanged=PASS");
}

#[test]
#[ignore = "private child of exact disposable Rename parent; stdin lease required"]
fn isolated_openbsd_folder_rename_confined_worker() {
    install_child_diagnostics();
    mark_child_stage("entry");
    assert_eq!(std::env::consts::OS, "openbsd");
    mark_child_stage("read_lease");
    let mut bytes = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 4096);
    mark_child_stage("parse_lease");
    let lease: Lease = serde_json::from_slice(&bytes).unwrap();
    mark_child_stage("validate_lease");
    lease.validate();
    let root = &lease.root;
    let helper = root.join("helper");
    mark_child_stage("grant_owner");
    assert_eq!(
        fs::symlink_metadata(helper.join("fixture-grant.key"))
            .unwrap()
            .uid(),
        lease.uid
    );
    mark_child_stage("create_settings");
    let settings = helper.join("settings");
    fs::DirBuilder::new().mode(0o700).create(&settings).unwrap();
    mark_child_stage("config_parse");
    let values = native_child_values(&lease);
    let config = AppConfig::from_env_map(&values).unwrap();
    mark_child_stage("confinement_plan");
    let plan = crate::openbsd::OpenbsdConfinementPlan::from_config(&config);
    assert!(plan
        .unveil_rules
        .iter()
        .any(|r| r.path == helper && r.permissions.contains('w') && r.permissions.contains('c')));
    assert!(!plan
        .unveil_rules
        .iter()
        .any(|r| r.path == root.join("alice") && r.permissions.contains('w')));
    let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Info);
    mark_child_stage("apply_confinement");
    crate::openbsd::apply_runtime_confinement(&config, &logger).unwrap();
    println!("native_rename confinement=PASS");
    let count = Arc::new(AtomicUsize::new(0));
    let executor = ScopedExecutor {
        config: root.join("dovecot.conf"),
        renames: count.clone(),
    };
    let backend = |missing| {
        DoveadmMailboxListBackend::new(
            MailboxListingPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(root.join(if missing {
            "missing-userdb"
        } else {
            "userdb"
        })))
    };
    let summaries = |account: &str, folder: &str| {
        DoveadmMessageListBackend::new(
            MessageListPolicy::default(),
            executor.clone(),
            "/usr/local/bin/doveadm",
        )
        .with_userdb_socket_path(Some(root.join("userdb")))
        .list_messages(
            account,
            &MessageListRequest::new(MessageListPolicy::default(), folder).unwrap(),
        )
        .unwrap()
    };
    mark_child_stage("native_preflight");
    let source = backend(false).mailbox_status(ALICE, "INBOX.Alpha").unwrap();
    let parent = backend(false).mailbox_status(ALICE, "INBOX").unwrap();
    assert_eq!(source.messages(), 1);
    let before = summaries(ALICE, "INBOX.Alpha");
    assert_eq!(before.len(), 1);
    let bob_before = summaries(BOB, "INBOX.Alpha");
    assert_eq!(bob_before.len(), 1);
    let request =
        RenameFolderRequest::new(ALICE, "INBOX.Alpha", source.guid(), parent.guid(), "Beta")
            .unwrap();
    mark_child_stage("private_indexes");
    let labels = crate::labels::LabelStore::new(settings.join("labels-v1"));
    let label = labels
        .change(
            ALICE,
            0,
            crate::labels::LabelChange::Create("Native continuity"),
        )
        .unwrap();
    let id = label.labels()[0].id().to_owned();
    labels
        .change(
            ALICE,
            label.revision(),
            crate::labels::LabelChange::Attach {
                id: &id,
                message: &crate::labels::MessageIdentity::from_summary(
                    ALICE,
                    ALICE,
                    "INBOX.Alpha",
                    &before[0],
                )
                .unwrap(),
            },
        )
        .unwrap();
    let snooze = crate::snooze::SnoozeStore::new(&settings);
    snooze
        .set(
            ALICE,
            &crate::snooze::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Alpha", &before[0])
                .unwrap(),
            0,
            4600,
            1000,
        )
        .unwrap();
    // Real signed helper operation. Keep browser private pending until both
    // native identity confirmation and private metadata updates have finished.
    let mut role = crate::folder_rename::settings_gate(&settings, ALICE).unwrap();
    role.begin(&request).unwrap();
    mark_child_stage("signed_rename");
    let outcome =
        super::rename_tests::rename_through_helper(&helper, backend(false), &request, lease.uid);
    assert_eq!(
        outcome,
        Outcome::Renamed,
        "native_rename populated outcome={outcome:?}"
    );
    mark_child_stage("rename_confirmation");
    let after = backend(false).folder_metadata(ALICE).unwrap();
    let destination = backend(false).mailbox_status(ALICE, "INBOX.Beta").unwrap();
    let new_parent = backend(false).mailbox_status(ALICE, "INBOX").unwrap();
    assert!(crate::folder_rename::confirmed_result(
        &request,
        &after,
        &destination,
        &new_parent
    ));
    assert_eq!(destination.guid(), source.guid());
    assert_eq!(destination.messages(), 1);
    let new_rows = summaries(ALICE, "INBOX.Beta");
    assert_eq!(new_rows.len(), 1);
    assert_eq!(new_rows[0].uid, before[0].uid);
    assert_eq!(new_rows[0].metadata, before[0].metadata);
    assert_eq!(bodies(root, "alice", "INBOX.Beta"), vec![MESSAGE.to_vec()]);
    assert_eq!(summaries(BOB, "INBOX.Alpha"), bob_before);
    assert_eq!(bodies(root, "bob", "INBOX.Alpha"), vec![MESSAGE.to_vec()]);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    println!("native_rename populated_guid_bytes=PASS");
    mark_child_stage("metadata_continuity");
    crate::folder_rename::reconcile_metadata(&settings, &request).unwrap();
    role.confirm().unwrap();
    drop(role);
    let labelled =
        crate::labels::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Beta", &new_rows[0])
            .unwrap();
    let record = labels.load(ALICE).unwrap();
    assert_eq!(record.labels_for(&labelled).unwrap()[0].id(), id);
    let marker = snooze.load(ALICE, 1001).unwrap();
    assert_eq!(marker.markers().len(), 1);
    assert_eq!(marker.markers()[0].until(), 4600);
    assert_eq!(
        serde_json::to_value(&marker.markers()[0]).unwrap()["created_at"],
        1000
    );
    assert_eq!(
        marker.markers()[0].identity().message_guid(),
        before[0].metadata.as_ref().unwrap().version.message_guid
    );
    assert_eq!(marker.markers()[0].identity().folder(), "INBOX.Beta");
    assert_eq!(marker.markers()[0].identity().uid(), before[0].uid);
    assert_eq!(marker.markers()[0].identity().mailbox_guid(), source.guid());
    assert!(labels.load(BOB).unwrap().labels().is_empty());
    assert!(snooze.load(BOB, 1001).unwrap().markers().is_empty());
    println!("native_rename label_snooze=PASS");
    // Missing private userdb is a settled no-dispatch refusal. Lose the genuine
    // signed response, then read the original action's durable witness using a
    // fresh signed grant and current normal native identity observations.
    mark_child_stage("lost_refusal");
    let no_op = RenameFolderRequest::new(
        ALICE,
        "INBOX.Beta",
        destination.guid(),
        parent.guid(),
        "Gamma",
    )
    .unwrap();
    let mut role = crate::folder_rename::settings_gate(&settings, ALICE).unwrap();
    role.begin(&no_op).unwrap();
    drop(role);
    super::rename_tests::with_rename_helper(&helper, backend(true), lease.uid, |_| {
        let mut action = MailboxHelperRequest::FolderRename {
            request: no_op.clone(),
            grant: MailboxHelperGrant::unsigned(),
        };
        let bytes = super::super::mailbox_helper_client::encode_authorized_request(
            &helper.join("fixture-grant.key"),
            &mut action,
        )
        .unwrap();
        let mut stream = UnixStream::connect(helper.join("status.sock")).unwrap();
        assert_eq!(
            crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
            lease.uid
        );
        stream.write_all(&bytes).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();
    });
    assert!(crate::folder_rename::settings_gate(&settings, ALICE).is_err());
    mark_child_stage("completion_query");
    let completion =
        super::rename_tests::with_rename_helper(&helper, backend(false), lease.uid, |client| {
            client.folder_rename_completion(&no_op)
        });
    assert_eq!(completion, Completion::NoMutation);
    mark_child_stage("recovery_check");
    let current = backend(false).folder_metadata(ALICE).unwrap();
    let old = backend(false).mailbox_status(ALICE, "INBOX.Beta").unwrap();
    let parent = backend(false).mailbox_status(ALICE, "INBOX").unwrap();
    assert!(crate::folder_rename::confirmed_unchanged(
        &no_op, &current, &old, &parent
    ));
    let mut role = crate::folder_rename::role_lease(&settings, ALICE).unwrap();
    assert_eq!(role.pending(), Some(&no_op));
    role.confirm().unwrap();
    drop(role);
    assert!(crate::folder_rename::settings_gate(&settings, ALICE).is_ok());
    assert!(matches!(
        super::rename_tests::rename_through_helper(&helper, backend(false), &no_op, lease.uid),
        Outcome::Refused(crate::folder_create::Refusal::Unavailable)
    ));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    println!("native_rename lost_no_mutation=PASS");
    // Original nonce and caller peer remain mandatory; no mutation retry.
    mark_child_stage("authority_controls");
    let changed =
        RenameFolderRequest::new(ALICE, "INBOX.Beta", old.guid(), parent.guid(), "Gamma").unwrap();
    assert_ne!(changed.action_nonce(), no_op.action_nonce());
    assert_eq!(
        super::rename_tests::with_rename_helper(&helper, backend(false), lease.uid, |client| {
            client.folder_rename_completion(&changed)
        }),
        Completion::Unconfirmed
    );
    assert_eq!(
        super::rename_tests::with_rename_helper(
            &helper,
            backend(false),
            lease.uid.wrapping_add(1),
            |client| client.folder_rename_completion(&no_op)
        ),
        Completion::Unconfirmed
    );
    let stale =
        RenameFolderRequest::new(ALICE, "INBOX.Beta", &"c".repeat(32), parent.guid(), "Gamma")
            .unwrap();
    assert_eq!(
        super::rename_tests::rename_through_helper(&helper, backend(false), &stale, lease.uid),
        Outcome::Refused(crate::folder_create::Refusal::Stale)
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(bodies(root, "alice", "INBOX.Beta"), vec![MESSAGE.to_vec()]);
    println!("native_rename authority_refusals=PASS");
    mark_child_stage("complete");
}

#[test]
fn native_rename_child_configuration_missing_auth_red_complete_owned_green() {
    let lease = Lease {
        root: PathBuf::from("/tmp/osmap-rename-native-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        dev: 1,
        ino: 1,
        uid: 1000,
        gid: 1000,
        mode: 0o700,
    };
    let complete = native_child_values(&lease);
    let mut old = complete.clone();
    old.remove("OSMAP_DOVEADM_AUTH_SOCKET_PATH");
    assert!(matches!(
        AppConfig::from_env_map(&old),
        Err(crate::error::BootstrapError::InvalidConfig {
            field: "OSMAP_DOVEADM_AUTH_SOCKET_PATH",
            ..
        })
    ));
    let config = AppConfig::from_env_map(&complete).unwrap();
    assert_eq!(
        config.doveadm_auth_socket_path,
        Some(lease.root.join("userdb"))
    );
    assert_eq!(
        config.doveadm_userdb_socket_path,
        config.doveadm_auth_socket_path
    );
    assert_eq!(config.trusted_web_runtime_uid, Some(lease.uid));
    assert_eq!(
        config.openbsd_confinement_mode,
        crate::config::OpenbsdConfinementMode::Enforce
    );
    let mut without_auth = config.clone();
    without_auth.doveadm_auth_socket_path = None;
    assert_eq!(
        crate::openbsd::OpenbsdConfinementPlan::from_config(&config),
        crate::openbsd::OpenbsdConfinementPlan::from_config(&without_auth)
    );
    assert_eq!(config.expensive_request_timeout_seconds, 5);
    assert_eq!(MailboxHelperPolicy::default().read_timeout_secs, 5);
    assert_eq!(MailboxHelperPolicy::default().write_timeout_secs, 5);
}
#[test]
fn native_rename_child_diagnostics_are_closed_and_redact_payloads() {
    for stage in CHILD_STAGES {
        assert!(closed_child_diagnostic(&format!(
            "native_rename child_stage={stage}"
        )));
    }
    let safe = "native_rename child_panic stage=config_parse file=native_test line=600 column=5 kind=unwrap_result diagnostic=v1";
    assert!(closed_child_diagnostic(safe));
    for bad in ["native_rename child_stage=private-body", "raw secret stderr", "native_rename child_panic stage=config_parse file=/tmp/private line=1 column=1 kind=unwrap_result diagnostic=v1", "native_rename child_panic stage=config_parse file=native_test line=1 column=1 kind=private-secret diagnostic=v1"] { assert!(!closed_child_diagnostic(bad)); }
    assert!(!closed_child_diagnostic(&format!("{safe} private_secret")));
    assert_eq!(
        public_panic_location("/private/source/key.rs", 40, 9),
        ("other_source", 0, 0)
    );
    assert_eq!(
        public_panic_location("src/mailbox_helper_native_rename_tests.rs", 40, 9),
        ("native_test", 40, 9)
    );
    for secret in [
        "called `Result::unwrap()` on an `Err` value: private-secret",
        "private-body",
    ] {
        let payload: Box<dyn std::any::Any + Send> = Box::new(secret.to_owned());
        assert!(["unwrap_result", "other"].contains(&panic_kind(payload.as_ref())));
    }
}

#[test]
fn native_rename_child_diagnostics_forward_actual_panic_without_private_payload() {
    const CONTROL: &str = "OSMAP_RENAME_CLOSED_DIAGNOSTIC_CONTROL";
    if std::env::var_os(CONTROL).as_deref() == Some(std::ffi::OsStr::new("1")) {
        install_child_diagnostics();
        mark_child_stage("config_parse");
        panic!("private-fixture-payload-never-exported /private/operator-path");
    }
    let out = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/bin/env",
            &[
                format!("{CONTROL}=1"),
                std::env::current_exe().unwrap().display().to_string(),
                "--exact".into(),
                "mailbox_helper::tests::native_rename_tests::native_rename_child_diagnostics_forward_actual_panic_without_private_payload".into(),
                "--nocapture".into(),
                "--test-threads=1".into(),
            ],
            b"",
            Duration::from_secs(2),
            4096,
        )
        .unwrap();
    assert_eq!(out.status_code, 101);
    let diagnostics: Vec<_> = out
        .stdout
        .lines()
        .filter(|line| closed_child_diagnostic(line))
        .collect();
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(diagnostics[0], "native_rename child_stage=config_parse");
    assert!(diagnostics[1]
        .starts_with("native_rename child_panic stage=config_parse file=native_test line="));
    assert!(diagnostics[1].ends_with("kind=other diagnostic=v1"));
    for text in [&out.stdout, &out.stderr] {
        assert!(!text.contains("private-fixture-payload-never-exported"));
        assert!(!text.contains("/private/operator-path"));
    }
}
