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
const MESSAGE: &[u8] = b"From: fixture@osmap-rename.invalid\r\nTo: alice@osmap-rename.invalid\r\nSubject: Owned rename fixture\r\nDate: Tue, 06 Oct 2026 00:00:00 +0000\r\nMessage-ID: <rename@osmap-rename.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=owned-move\r\n\r\n--owned-move\r\nContent-Type: text/plain\r\n\r\nPopulated folder contents stay with its native identity.\r\n--owned-move\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=synthetic.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAH/\r\n--owned-move--\r\n";

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
    deletes: Arc<AtomicUsize>,
    delete_results:Arc<Mutex<Vec<i32>>>,
    inject_append: Arc<AtomicBool>,
    arrival_before: Arc<Mutex<Option<Vec<MessageSummary>>>>,
    arrival_bytes: Arc<Mutex<Option<Vec<Vec<u8>>>>>,
    bin_arrival: Arc<AtomicBool>,
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
        let began=std::time::Instant::now();
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
            assert!(matches!(&a[pos + 2..], [source, destination]
                if (source == "INBOX.Alpha" && destination == "INBOX.Beta")
                || (source == "INBOX.Beta" && destination == "INBOX.Target.Beta")
                || (source == "INBOX.Target.Beta" && owned_disposition_name(destination))
                || (owned_disposition_name(source) && destination == "INBOX.Target.Beta")
                || (source == "INBOX.Tree" && destination == "INBOX.RenamedTree")
                || (source == "INBOX.RenamedTree" && destination == "INBOX.Target.RenamedTree")
                || (source == "INBOX.Target.RenamedTree" && owned_disposition_name(destination))
                || (owned_disposition_name(source) && destination == "INBOX.Target.RenamedTree")
                || (source == "INBOX.Target.RenamedTree.Child" && destination == "INBOX.Target.RecoveredTree.Child")));
            if matches!(a[pos + 2].as_str(), "INBOX.Target.Beta" | "INBOX.Target.RenamedTree")
                && owned_disposition_name(&a[pos + 3])
                && self.bin_arrival.swap(false, Ordering::SeqCst)
            {
                let arriving = if a[pos + 2] == "INBOX.Target.RenamedTree" {
                    "INBOX.Target.RenamedTree.Child"
                } else { "INBOX.Target.Beta" };
                let append = scoped_args(
                    &self.config,
                    &[
                        "-o".into(),
                        "stats_writer_socket_path=".into(),
                        "-o".into(),
                        format!(
                            "auth_socket_path={}",
                            self.config.parent().unwrap().join("userdb").display()
                        ),
                        "save".into(),
                        "-u".into(),
                        ALICE.into(),
                        "-m".into(),
                        arriving.into(),
                    ],
                );
                let remaining = timeout
                    .checked_sub(began.elapsed())
                    .filter(|v| !v.is_zero())
                    .ok_or_else(|| CommandExecutionError {
                        reason: "owned Bin arrival budget timed out".into(),
                    })?;
                let saved = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
                    p, &append, MESSAGE, remaining, 4096,
                )?;
                assert_eq!(saved.status_code, 0);
                assert!(saved.stderr.is_empty());
                *self.arrival_bytes.lock().unwrap() = Some(bodies(
                    self.config.parent().unwrap(),
                    "alice",
                    arriving,
                ));
            }
            self.renames.fetch_add(1, Ordering::SeqCst);
        }
        if a.windows(2).any(|v|v==["mailbox","delete"]) {
            assert_eq!(a[pos+1],ALICE);
            assert_eq!(&a[..=pos],&["-o","stats_writer_socket_path=","-o",&format!("auth_socket_path={}",self.config.parent().unwrap().join("userdb").display()),"mailbox","delete","-e","-u"]);
            assert!(matches!(&a[pos+2..],[source] if source=="INBOX.Empty" || source=="INBOX.Arriving"));
            if a[pos+2]=="INBOX.Arriving" && self.inject_append.swap(false,Ordering::SeqCst) {
                // The backend has already completed its final advisory empty
                // read. Intercept only exact native Delete dispatch, append via
                // Dovecot, then let the unchanged -e command enforce emptiness.
                let append=scoped_args(&self.config,&["-o".into(),"stats_writer_socket_path=".into(),"-o".into(),format!("auth_socket_path={}",self.config.parent().unwrap().join("userdb").display()),"save".into(),"-u".into(),ALICE.into(),"-m".into(),"INBOX.Arriving".into()]);
                let remaining=timeout.checked_sub(began.elapsed()).filter(|v|!v.is_zero()).ok_or_else(||CommandExecutionError{reason:"owned append budget timed out".into()})?;
                let saved=SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(p,&append,MESSAGE,remaining,4096)?;
                assert_eq!(saved.status_code,0);assert!(saved.stderr.is_empty());
                // Dovecot owns storage representation. Preserve the actual
                // whole stored message across -e, not the pre-save input bytes.
                let stored=bodies(self.config.parent().unwrap(),"alice","INBOX.Arriving");
                assert_eq!(stored.len(),1);assert_known_arrival_payload(&stored[0]);
                *self.arrival_bytes.lock().unwrap()=Some(stored);

                let bounded=crate::folder_create_backend::Deadline{inner:self,until:began+timeout};
                let rows=DoveadmMessageListBackend::new(MessageListPolicy::default(),&bounded,p).with_userdb_socket_path(Some(self.config.parent().unwrap().join("userdb"))).list_messages(ALICE,&MessageListRequest::new(MessageListPolicy::default(),"INBOX.Arriving").unwrap()).unwrap();
                assert_eq!(rows.len(),1);*self.arrival_before.lock().unwrap()=Some(rows);
                println!("native_rename delete_append_after_advisory_before_dispatch=PASS");
            }
            self.deletes.fetch_add(1,Ordering::SeqCst);
        }
        let args = scoped_args(&self.config, a);
        // Existing disposable native-create pattern: canonical -u is preserved.
        let phase = if a.first().is_some_and(|s| s == "exec") {
            "metadata"
        } else if a.iter().any(|s| s == "rename") {
            "rename"
        } else if a.iter().any(|s| s == "delete") {
            "delete"
        } else if a.iter().any(|s| s == "status") {
            "status"
        } else {
            "summary"
        };
        let result = SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(p, &args, input, timeout.checked_sub(began.elapsed()).filter(|v|!v.is_zero()).ok_or_else(||CommandExecutionError{reason:"native command budget timed out".into()})?, limit);
        if a.windows(2).any(|v|v==["mailbox","delete"]) {if let Ok(result)=&result {self.delete_results.lock().unwrap().push(result.status_code);}}
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

fn owned_disposition_name(name: &str) -> bool {
    name.strip_prefix("Trash.OSMAP-Deleted-")
        .is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        })
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
    "signed_move",
    "empty_delete",
    "arrival_delete",
    "lost_refusal",
    "completion_query",
    "recovery_check",
    "authority_controls",
    "bin_restore",
    "subtree",
    "injected_partial_recovery",
    "recovery_metadata_unavailable",
    "recovery_placement_ready",
    "recovery_placement_invalid",
    "recovery_placement_stale",
    "recovery_placement_unavailable",
    "recovery_placement_capacity",
    "recovery_return_complete",
    "recovery_return_unchanged",
    "recovery_return_progress",
    "recovery_return_inspected",
    "recovery_return_refused",
    "recovery_return_unknown",
    "recovery_return_unavailable",
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
    if fields.len() == 7 && fields[0] == "native_rename" && fields[1].starts_with("recovery_node=") {
        return ["recovery_node=source_root","recovery_node=intended_child"].contains(&fields[1])
            && ["exists=true","exists=false"].contains(&fields[2])
            && ["noselect=true","noselect=false"].contains(&fields[3])
            && ["nonexistent=true","nonexistent=false"].contains(&fields[4])
            && ["haschildren=true","haschildren=false"].contains(&fields[5])
            && fields[6].strip_prefix("special_use_count=").is_some_and(|v| !v.is_empty() && v.len()<=2 && v.bytes().all(|b|b.is_ascii_digit()) && v.parse::<usize>().is_ok_and(|n|n<=32));
    }
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
        deletes:Arc::new(AtomicUsize::new(0)),
        delete_results:Arc::new(Mutex::new(Vec::new())),
        inject_append:Arc::new(AtomicBool::new(true)),
        arrival_before:Arc::new(Mutex::new(None)),
        arrival_bytes:Arc::new(Mutex::new(None)),
        bin_arrival:Arc::new(AtomicBool::new(false)),
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
        for folder in ["", ".INBOX.Alpha", ".INBOX.Target", ".INBOX.Empty", ".INBOX.Arriving", ".Trash", ".INBOX.Tree", ".INBOX.Tree.Child", ".INBOX.Tree.Child.Grand"] {
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
        for folder in [".INBOX.Tree", ".INBOX.Tree.Child", ".INBOX.Tree.Child.Grand"] {
            fs::write(root.join(who).join("Maildir").join(folder).join("new/owned-tree-message"), MESSAGE).unwrap();
        }
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
        "move_populated_guid_bytes_labels_snooze_bob=PASS",
        "delete_empty_and_mutation_time_arrival_refusal=PASS",
        "bin_restore_complete_arrival_labels_snooze_bob=PASS",
        "subtree_rename_move_bin_restore_guid_bytes_arrival_indexes_bob=PASS",
        "injected_partial_signed_native_child_recovery_no_root_replay=PASS",
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
        deletes:Arc::new(AtomicUsize::new(0)),
        delete_results:Arc::new(Mutex::new(Vec::new())),
        inject_append:Arc::new(AtomicBool::new(true)),
        arrival_before:Arc::new(Mutex::new(None)),
        arrival_bytes:Arc::new(Mutex::new(None)),
        bin_arrival:Arc::new(AtomicBool::new(false)),
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
    // Reuse the same signed helper and populated private indexes for one real
    // cross-parent Move; no copying, message rewrite or new native framework.
    mark_child_stage("signed_move");
    let target_parent = backend(false).mailbox_status(ALICE, "INBOX.Target").unwrap();
    let move_request = RenameFolderRequest::for_move(ALICE, "INBOX.Beta", destination.guid(),
        parent.guid(), "INBOX.Target", target_parent.guid()).unwrap();
    let mut role = crate::folder_rename::settings_gate(&settings, ALICE).unwrap();
    role.begin(&move_request).unwrap();
    assert_eq!(super::rename_tests::rename_through_helper(&helper, backend(false), &move_request, lease.uid), Outcome::Renamed);
    let moved_snapshot = backend(false).folder_metadata(ALICE).unwrap();
    let moved = backend(false).mailbox_status(ALICE, "INBOX.Target.Beta").unwrap();
    assert!(crate::folder_rename::confirmed_result(&move_request, &moved_snapshot, &moved, &target_parent));
    assert_eq!(moved.guid(), source.guid());
    assert_eq!(moved.messages(), 1);
    let moved_rows = summaries(ALICE, "INBOX.Target.Beta");
    assert!(move_summaries_preserved(
        &new_rows,
        &moved_rows,
        "INBOX.Beta",
        "INBOX.Target.Beta"
    ));
    assert_eq!(bodies(root, "alice", "INBOX.Target.Beta"), vec![MESSAGE.to_vec()]);
    crate::folder_rename::reconcile_metadata(&settings, &move_request).unwrap();
    role.confirm().unwrap();
    drop(role);
    let moved_identity = crate::labels::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Target.Beta", &moved_rows[0]).unwrap();
    assert_eq!(labels.load(ALICE).unwrap().labels_for(&moved_identity).unwrap()[0].id(), id);
    let moved_marker = snooze.load(ALICE, 1001).unwrap();
    assert_eq!(moved_marker.markers()[0].identity().folder(), "INBOX.Target.Beta");
    assert_eq!(moved_marker.markers()[0].identity().message_guid(), before[0].metadata.as_ref().unwrap().version.message_guid);
    assert_eq!(moved_marker.markers()[0].identity().mailbox_guid(), source.guid());
    assert_eq!(summaries(BOB, "INBOX.Alpha"), bob_before);
    assert_eq!(bodies(root, "bob", "INBOX.Alpha"), vec![MESSAGE.to_vec()]);
    assert!(labels.load(BOB).unwrap().labels().is_empty());
    assert!(snooze.load(BOB, 1001).unwrap().markers().is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 2);
    println!("native_rename move_populated_guid_bytes_labels_snooze_bob=PASS");
    // Exactly one empty deletion, then one arrival after the last advisory
    // check. Both operations use the same real signed/helper/native mechanism.
    mark_child_stage("empty_delete");
    let empty=backend(false).mailbox_status(ALICE,"INBOX.Empty").unwrap();
    let bob_empty=backend(false).mailbox_status(BOB,"INBOX.Empty").unwrap();
    let deletion=crate::folder_delete::DeleteFolderRequest::new(ALICE,"INBOX.Empty",empty.guid(),parent.guid()).unwrap();
    let delete_call=|r:&crate::folder_delete::DeleteFolderRequest|super::rename_tests::with_rename_helper(&helper,backend(false),lease.uid,|c|c.delete_folder(r));
    assert_eq!(delete_call(&deletion),crate::folder_delete::Outcome::Deleted);
    assert!(backend(false).folder_metadata(ALICE).unwrap().folder(ALICE,"INBOX.Empty").is_err());
    assert_eq!(backend(false).mailbox_status(BOB,"INBOX.Empty").unwrap(),bob_empty);
    mark_child_stage("arrival_delete");
    let arriving=backend(false).mailbox_status(ALICE,"INBOX.Arriving").unwrap();assert_eq!(arriving.messages(),0);
    let delete_arrival=crate::folder_delete::DeleteFolderRequest::new(ALICE,"INBOX.Arriving",arriving.guid(),parent.guid()).unwrap();
    assert_eq!(delete_call(&delete_arrival),crate::folder_delete::Outcome::Unknown);
    assert!(!executor.inject_append.load(Ordering::SeqCst));
    assert_eq!(summaries(ALICE,"INBOX.Arriving"),executor.arrival_before.lock().unwrap().clone().unwrap());
    assert_eq!(bodies(root,"alice","INBOX.Arriving"),executor.arrival_bytes.lock().unwrap().clone().unwrap());
    let preserved_arrival=backend(false).mailbox_status(ALICE,"INBOX.Arriving").unwrap();assert_eq!(preserved_arrival.guid(),arriving.guid());assert_eq!(preserved_arrival.messages(),1);
    assert_eq!(backend(false).mailbox_status(ALICE,"INBOX").unwrap().guid(),parent.guid());
    assert_eq!(summaries(ALICE,"INBOX.Target.Beta"),moved_rows);
    assert_eq!(bodies(root,"alice","INBOX.Target.Beta"),vec![MESSAGE.to_vec()]);
    assert_eq!(summaries(BOB,"INBOX.Alpha"),bob_before);assert_eq!(bodies(root,"bob","INBOX.Alpha"),vec![MESSAGE.to_vec()]);
    assert_eq!(executor.deletes.load(Ordering::SeqCst),2);
    let delete_codes=executor.delete_results.lock().unwrap();assert_eq!(delete_codes.len(),2);assert_eq!(delete_codes[0],0);assert_ne!(delete_codes[1],0);drop(delete_codes);
    println!("native_rename delete_empty_and_mutation_time_arrival_refusal=PASS");
    // Missing private userdb is a settled no-dispatch refusal. Lose the genuine
    // signed response, then read the original action's durable witness using a
    // fresh signed grant and current normal native identity observations.
    mark_child_stage("lost_refusal");
    let no_op = RenameFolderRequest::for_move(
        ALICE,
        "INBOX.Target.Beta",
        moved.guid(),
        target_parent.guid(),
        "INBOX",
        parent.guid(),
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
    let old = backend(false).mailbox_status(ALICE, "INBOX.Target.Beta").unwrap();
    let parent = backend(false).mailbox_status(ALICE, "INBOX").unwrap();
    assert!(crate::folder_rename::confirmed_unchanged(
        &no_op, &current, &old, &parent
    ));
    no_op.validate_source_parent(&current, &backend(false).mailbox_status(ALICE, "INBOX.Target").unwrap()).unwrap();
    let mut role = crate::folder_rename::role_lease(&settings, ALICE).unwrap();
    assert_eq!(role.pending(), Some(&no_op));
    role.confirm().unwrap();
    drop(role);
    assert!(crate::folder_rename::settings_gate(&settings, ALICE).is_ok());
    assert!(matches!(
        super::rename_tests::rename_through_helper(&helper, backend(false), &no_op, lease.uid),
        Outcome::Refused(crate::folder_create::Refusal::Unavailable)
    ));
    assert_eq!(count.load(Ordering::SeqCst), 2);
    println!("native_rename lost_no_mutation=PASS");
    // Original nonce and caller peer remain mandatory; no mutation retry.
    mark_child_stage("authority_controls");
    let changed =
        RenameFolderRequest::for_move(ALICE, "INBOX.Target.Beta", old.guid(), target_parent.guid(), "INBOX", parent.guid()).unwrap();
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
        RenameFolderRequest::for_move(ALICE, "INBOX.Target.Beta", &"c".repeat(32), target_parent.guid(), "INBOX", parent.guid())
            .unwrap();
    assert_eq!(
        super::rename_tests::rename_through_helper(&helper, backend(false), &stale, lease.uid),
        Outcome::Refused(crate::folder_create::Refusal::Stale)
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(bodies(root, "alice", "INBOX.Target.Beta"), vec![MESSAGE.to_vec()]);
    println!("native_rename authority_refusals=PASS");
    mark_child_stage("bin_restore");
    struct ServiceBackend {
        helper: PathBuf,
        executor: ScopedExecutor,
        peer: u32,
        lose_bin_reply: std::cell::Cell<bool>,
        inject_partial: std::cell::Cell<bool>,
    }
    impl ServiceBackend {
        fn native(&self) -> DoveadmMailboxListBackend<ScopedExecutor> {
            DoveadmMailboxListBackend::new(
                MailboxListingPolicy::default(),
                self.executor.clone(),
                "/usr/local/bin/doveadm",
            )
            .with_userdb_socket_path(Some(self.executor.config.parent().unwrap().join("userdb")))
        }
    }
    impl MailboxBackend for ServiceBackend {
        fn list_mailboxes(&self, account: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
            self.native().list_mailboxes(account)
        }
        fn folder_metadata(
            &self,
            account: &str,
        ) -> Result<crate::folder_metadata::FolderSnapshot, MailboxBackendError> {
            self.native().folder_metadata(account)
        }
        fn mailbox_status(
            &self,
            account: &str,
            name: &str,
        ) -> Result<crate::mailbox_status::MailboxStatus, MailboxBackendError> {
            self.native().mailbox_status(account, name)
        }
        fn rename_folder(&self, request: &RenameFolderRequest) -> Outcome {
            if self.inject_partial.replace(false) {
                return super::rename_tests::rename_through_helper(
                    &self.helper,
                    InjectedPartial { native: self.native(), config: self.executor.config.clone() },
                    request,
                    self.peer,
                );
            }
            if self.lose_bin_reply.replace(false) {
                super::rename_tests::with_rename_helper(
                    &self.helper,
                    self.native(),
                    self.peer,
                    |_| {
                        let mut action = MailboxHelperRequest::FolderRename {
                            request: request.clone(),
                            grant: MailboxHelperGrant::unsigned(),
                        };
                        let bytes = super::super::mailbox_helper_client::encode_authorized_request(
                            &self.helper.join("fixture-grant.key"),
                            &mut action,
                        )
                        .unwrap();
                        let mut stream =
                            UnixStream::connect(self.helper.join("status.sock")).unwrap();
                        assert_eq!(
                            crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
                            self.peer
                        );
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        stream.write_all(&bytes).unwrap();
                        stream.shutdown(Shutdown::Both).unwrap();
                    },
                );
                return Outcome::Unknown;
            }
            super::rename_tests::rename_through_helper(
                &self.helper,
                self.native(),
                request,
                self.peer,
            )
        }
        fn folder_rename_completion(&self, request: &RenameFolderRequest) -> Completion {
            super::rename_tests::with_rename_helper(
                &self.helper,
                self.native(),
                self.peer,
                |client| client.folder_rename_completion(request),
            )
        }
    }
    let service = ServiceBackend {
        helper: helper.clone(),
        executor: executor.clone(),
        peer: lease.uid,
        lose_bin_reply: std::cell::Cell::new(true),
        inject_partial: std::cell::Cell::new(false),
    };
    let bin =
        crate::folder_disposition::prepare_bin(&settings, &service, ALICE, "INBOX.Target.Beta")
            .unwrap();
    let mut stale_bin = serde_json::to_value(&bin).unwrap();
    stale_bin["disposition"]["Bin"]["bin_revision"] = 1.into();
    let stale_bin: RenameFolderRequest = serde_json::from_value(stale_bin).unwrap();
    assert_eq!(
        crate::folder_disposition::execute(&settings, &service, &stale_bin, 1001),
        Outcome::Refused(crate::folder_create::Refusal::Stale)
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
    executor.bin_arrival.store(true, Ordering::SeqCst);
    assert_eq!(
        crate::folder_disposition::execute(&settings, &service, &bin, 1001),
        Outcome::Unknown
    );
    assert!(crate::folder_rename::settings_gate(&settings, ALICE).is_err());
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(
        crate::folder_disposition::execute(&settings, &service, &bin, 1001),
        Outcome::Refused(crate::folder_create::Refusal::Unavailable)
    );
    assert_eq!(
        crate::folder_disposition::check(&settings, &service, ALICE),
        crate::folder_rename::CheckOutcome::Renamed {
            destination: bin.destination()
        }
    );
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert!(!executor.bin_arrival.load(Ordering::SeqCst));
    let bin_wire = executor.arrival_bytes.lock().unwrap().clone().unwrap();
    assert_eq!(bin_wire.len(), 2);
    for message in &bin_wire {
        assert_known_arrival_payload(message)
    }
    let receipt = crate::folder_disposition::list(&settings, ALICE)
        .unwrap()
        .remove(0);
    assert_eq!(receipt.state, crate::folder_disposition::State::Binned);
    let binned = service
        .mailbox_status(ALICE, &receipt.stored_name())
        .unwrap();
    assert_eq!(binned.guid(), source.guid());
    assert_eq!(binned.messages(), 2);
    assert_eq!(bodies(root, "alice", &receipt.stored_name()), bin_wire);
    let bin_rows = summaries(ALICE, &receipt.stored_name());
    let original_uid = before[0].uid;
    let binned_original = bin_rows.iter().find(|row| row.uid == original_uid).unwrap();
    assert_eq!(binned_original.metadata, moved_rows[0].metadata);
    let labelled = crate::labels::MessageIdentity::from_summary(
        ALICE,
        ALICE,
        &receipt.stored_name(),
        binned_original,
    )
    .unwrap();
    assert_eq!(
        labels.load(ALICE).unwrap().labels_for(&labelled).unwrap()[0].id(),
        id
    );
    let marker = snooze.load(ALICE, 1001).unwrap();
    assert_eq!(
        marker.markers()[0].identity().folder(),
        receipt.stored_name()
    );
    assert_eq!(marker.markers()[0].until(), 4600);
    crate::bin_folder::BinPreferencesStore::new(&settings)
        .save(ALICE, 0, "INBOX.Arriving")
        .unwrap();
    let receipt = crate::folder_disposition::list(&settings, ALICE)
        .unwrap()
        .remove(0);
    assert_eq!(receipt.bin, "Trash");
    let restore = receipt.restore_request(ALICE).unwrap();
    assert_eq!(
        crate::folder_disposition::execute(&settings, &service, &restore, 1001),
        Outcome::Renamed
    );
    assert!(crate::folder_disposition::list(&settings, ALICE)
        .unwrap()
        .is_empty());
    assert_eq!(bodies(root, "alice", "INBOX.Target.Beta"), bin_wire);
    assert_eq!(
        service
            .mailbox_status(ALICE, "INBOX.Target.Beta")
            .unwrap()
            .guid(),
        source.guid()
    );
    let restored = summaries(ALICE, "INBOX.Target.Beta");
    let restored_original = restored.iter().find(|row| row.uid == original_uid).unwrap();
    assert_eq!(restored_original.metadata, moved_rows[0].metadata);
    let labelled = crate::labels::MessageIdentity::from_summary(
        ALICE,
        ALICE,
        "INBOX.Target.Beta",
        restored_original,
    )
    .unwrap();
    assert_eq!(
        labels.load(ALICE).unwrap().labels_for(&labelled).unwrap()[0].id(),
        id
    );
    assert_eq!(
        snooze.load(ALICE, 1001).unwrap().markers()[0]
            .identity()
            .folder(),
        "INBOX.Target.Beta"
    );
    assert_eq!(summaries(BOB, "INBOX.Alpha"), bob_before);
    assert_eq!(bodies(root, "bob", "INBOX.Alpha"), vec![MESSAGE.to_vec()]);
    assert!(labels.load(BOB).unwrap().labels().is_empty());
    assert!(snooze.load(BOB, 1001).unwrap().markers().is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 4);
    println!("native_rename bin_restore_complete_arrival_labels_snooze_bob=PASS");
    mark_child_stage("subtree");
    let tree_before = summaries(ALICE, "INBOX.Tree");
    let child_before = summaries(ALICE, "INBOX.Tree.Child");
    let grand_before = summaries(ALICE, "INBOX.Tree.Child.Grand");
    let bob_tree = [summaries(BOB, "INBOX.Tree"), summaries(BOB, "INBOX.Tree.Child"), summaries(BOB, "INBOX.Tree.Child.Grand")];
    assert_eq!(tree_before.len(), 1);
    assert_eq!(child_before.len(), 1);
    assert_eq!(grand_before.len(), 1);
    let revision = labels.load(ALICE).unwrap().revision();
    labels.change(ALICE, revision, crate::labels::LabelChange::Attach {
        id: &id,
        message: &crate::labels::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Tree.Child", &child_before[0]).unwrap(),
    }).unwrap();
    let revision = snooze.load(ALICE, 1001).unwrap().revision();
    snooze.set(ALICE, &crate::snooze::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Tree.Child", &child_before[0]).unwrap(), revision, 4600, 1001).unwrap();
    for (source_name, destination_name) in [("INBOX.Tree", "INBOX.RenamedTree"), ("INBOX.RenamedTree", "INBOX.Target.RenamedTree")] {
        let source = service.mailbox_status(ALICE, source_name).unwrap();
        let request = if source_name == "INBOX.Tree" {
            RenameFolderRequest::new(ALICE, source_name, source.guid(), parent.guid(), "RenamedTree").unwrap()
        } else {
            RenameFolderRequest::for_move(ALICE, source_name, source.guid(), parent.guid(), "INBOX.Target", target_parent.guid()).unwrap()
        }.bind_subtree(&service).unwrap();
        assert_eq!(request.descendants().len(), 2);
        let mut role = crate::folder_rename::settings_gate(&settings, ALICE).unwrap();
        role.begin(&request).unwrap();
        assert_eq!(service.rename_folder(&request), Outcome::Renamed);
        crate::folder_rename::reconcile_metadata(&settings, &request).unwrap();
        role.confirm().unwrap();
        for (suffix, before) in [("", &tree_before), (".Child", &child_before), (".Child.Grand", &grand_before)] {
            let name = format!("{destination_name}{suffix}");
            let current = summaries(ALICE, &name);
            assert_eq!(current.len(), 1);
            assert_eq!(current[0].uid, before[0].uid);
            assert_eq!(current[0].metadata, before[0].metadata);
            assert_eq!(bodies(root, "alice", &name), vec![MESSAGE.to_vec()]);
        }
    }
    crate::bin_folder::BinPreferencesStore::new(&settings).save(ALICE, 1, "Trash").unwrap();
    let tree_bin = crate::folder_disposition::prepare_bin(&settings, &service, ALICE, "INBOX.Target.RenamedTree").unwrap();
    service.lose_bin_reply.set(true);
    executor.bin_arrival.store(true, Ordering::SeqCst);
    assert_eq!(crate::folder_disposition::execute(&settings, &service, &tree_bin, 1001), Outcome::Unknown);
    assert_eq!(count.load(Ordering::SeqCst), 7);
    // Dovecot save owns the arriving wire representation. Preserve the exact
    // pre-rename bytes, as in the leaf-arrival case above, then compare both
    // the Bin and Restore results without treating raw input as stored wire.
    assert!(!executor.bin_arrival.load(Ordering::SeqCst));
    let tree_arrival = executor.arrival_bytes.lock().unwrap().clone().unwrap();
    assert_eq!(tree_arrival.len(), 2);
    for message in &tree_arrival {
        assert_known_arrival_payload(message);
    }
    assert!(matches!(crate::folder_disposition::check(&settings, &service, ALICE), crate::folder_rename::CheckOutcome::Renamed { .. }));
    assert_eq!(count.load(Ordering::SeqCst), 7);
    let receipt = crate::folder_disposition::list(&settings, ALICE).unwrap().remove(0);
    let child_name = format!("{}.Child", receipt.stored_name());
    assert_eq!(bodies(root, "alice", &child_name), tree_arrival);
    let binned_child = summaries(ALICE, &child_name);
    let original_child = binned_child.iter().find(|row| row.uid == child_before[0].uid).unwrap();
    assert_eq!(original_child.metadata, child_before[0].metadata);
    assert_eq!(labels.load(ALICE).unwrap().labels_for(&crate::labels::MessageIdentity::from_summary(ALICE, ALICE, &child_name, original_child).unwrap()).unwrap()[0].id(), id);
    assert!(snooze.load(ALICE, 1001).unwrap().markers().iter().any(|m| m.identity().folder() == child_name));
    let restore = receipt.restore_request(ALICE).unwrap();
    assert_eq!(crate::folder_disposition::execute(&settings, &service, &restore, 1001), Outcome::Renamed);
    assert_eq!(count.load(Ordering::SeqCst), 8);
    for (suffix, before, messages) in [("", &tree_before, 1), (".Child", &child_before, 2), (".Child.Grand", &grand_before, 1)] {
        let name = format!("INBOX.Target.RenamedTree{suffix}");
        let current = summaries(ALICE, &name);
        assert_eq!(current.len(), messages);
        let original = current.iter().find(|row| row.uid == before[0].uid).unwrap();
        assert_eq!(original.metadata, before[0].metadata);
        if suffix == ".Child" {
            assert_eq!(bodies(root, "alice", &name), tree_arrival);
        } else {
            assert_eq!(bodies(root, "alice", &name), vec![MESSAGE.to_vec(); messages]);
        }
    }
    let restored_child = summaries(ALICE, "INBOX.Target.RenamedTree.Child");
    let original = restored_child.iter().find(|row| row.uid == child_before[0].uid).unwrap();
    assert_eq!(labels.load(ALICE).unwrap().labels_for(&crate::labels::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Target.RenamedTree.Child", original).unwrap()).unwrap()[0].id(), id);
    assert!(snooze.load(ALICE, 1001).unwrap().markers().iter().any(|m| m.identity().folder() == "INBOX.Target.RenamedTree.Child"));
    for ((suffix, original), name) in ["", ".Child", ".Child.Grand"].into_iter().zip(bob_tree).zip(["INBOX.Tree", "INBOX.Tree.Child", "INBOX.Tree.Child.Grand"]) {
        assert_eq!(name, format!("INBOX.Tree{suffix}"));
        assert_eq!(summaries(BOB, name), original);
        assert_eq!(bodies(root, "bob", name), vec![MESSAGE.to_vec()]);
    }
    assert!(crate::folder_disposition::list(&settings, ALICE).unwrap().is_empty());
    println!("native_rename subtree_rename_move_bin_restore_guid_bytes_arrival_indexes_bob=PASS");
    // INJECTED fixture state and settlement, not a reproduced Dovecot fault or
    // actual crash proof. The following repair runs the real signed helper and
    // native Dovecot under the same confined child and unchanged total budget.
    mark_child_stage("injected_partial_recovery");
    let source_name = "INBOX.Target.RenamedTree";
    let destination_name = "INBOX.Target.RecoveredTree";
    let recovery_bob: Vec<_> = ["INBOX.Tree","INBOX.Tree.Child","INBOX.Tree.Child.Grand"].into_iter().map(|name|(name,summaries(BOB,name),bodies(root,"bob",name))).collect();
    let recovery_before: Vec<_> = ["", ".Child", ".Child.Grand"].into_iter().map(|suffix| {
        let name = format!("{source_name}{suffix}");
        (suffix, service.mailbox_status(ALICE, &name).unwrap(), summaries(ALICE,&name), bodies(root,"alice",&name))
    }).collect();
    let request = RenameFolderRequest::new(ALICE,source_name,recovery_before[0].1.guid(),target_parent.guid(),"RecoveredTree").unwrap().bind_subtree(&service).unwrap();
    let mut role = crate::folder_rename::settings_gate(&settings,ALICE).unwrap();
    role.begin(&request).unwrap();
    drop(role);
    service.inject_partial.set(true);
    assert_eq!(service.rename_folder(&request),Outcome::Unknown);
    assert_eq!(count.load(Ordering::SeqCst),8);
    assert_eq!(service.mailbox_status(ALICE,destination_name).unwrap().guid(),recovery_before[0].1.guid());
    assert_eq!(service.mailbox_status(ALICE,&format!("{destination_name}.Child.Grand")).unwrap().guid(),recovery_before[2].1.guid());
    assert_eq!(service.mailbox_status(ALICE,&format!("{source_name}.Child")).unwrap().guid(),recovery_before[1].1.guid());
    let nonce = crate::draft::generate_draft_id().unwrap();
    service.lose_bin_reply.set(true);
    // Closed, test-only diagnostic facts. No path/GUID/body/command is exported
    // and no product flag policy is changed before the original assertion.
    match service.folder_metadata(ALICE) {
        Ok(snapshot) => {
            for (label,name) in [("source_root",source_name),("intended_child","INBOX.Target.RecoveredTree.Child")] {
                let entry=snapshot.folder(ALICE,name).ok();
                println!("native_rename recovery_node={label} exists={} noselect={} nonexistent={} haschildren={} special_use_count={}",entry.is_some(),entry.is_some_and(|e|e.has_flag("\\Noselect")),entry.is_some_and(|e|e.has_flag("\\NonExistent")),entry.is_some_and(|e|e.has_flag("\\HasChildren")),entry.map_or(0,|e|e.special_use().len()));
            }
        }
        Err(_) => mark_child_stage("recovery_metadata_unavailable"),
    }
    mark_child_stage(match crate::folder_subtree_recovery::placement(&service,&request) {
        Ok(_) => "recovery_placement_ready",
        Err(crate::folder_create::Refusal::Invalid) => "recovery_placement_invalid",
        Err(crate::folder_create::Refusal::Stale) => "recovery_placement_stale",
        Err(crate::folder_create::Refusal::Unavailable) => "recovery_placement_unavailable",
        Err(crate::folder_create::Refusal::Capacity) => "recovery_placement_capacity",
    });
    let recovered=crate::folder_subtree_recovery::recover(&settings,&service,ALICE,&nonce);
    mark_child_stage(match &recovered {
        crate::folder_rename::RecoveryOutcome::Complete { .. } => "recovery_return_complete",
        crate::folder_rename::RecoveryOutcome::Unchanged => "recovery_return_unchanged",
        crate::folder_rename::RecoveryOutcome::Progress => "recovery_return_progress",
        crate::folder_rename::RecoveryOutcome::Inspected => "recovery_return_inspected",
        crate::folder_rename::RecoveryOutcome::Refused => "recovery_return_refused",
        crate::folder_rename::RecoveryOutcome::Unknown => "recovery_return_unknown",
        crate::folder_rename::RecoveryOutcome::Unavailable => "recovery_return_unavailable",
    });
    assert_eq!(recovered,crate::folder_rename::RecoveryOutcome::Progress);
    assert_eq!(count.load(Ordering::SeqCst),9);
    assert_eq!(crate::folder_subtree_recovery::recover(&settings,&service,ALICE,&nonce),crate::folder_rename::RecoveryOutcome::Progress);
    assert_eq!(count.load(Ordering::SeqCst),9);
    assert_eq!(service.folder_rename_completion(&request),Completion::Renamed);
    for (suffix,status,rows,wire) in recovery_before {
        let name=format!("{destination_name}{suffix}");
        assert_eq!(service.mailbox_status(ALICE,&name).unwrap().guid(),status.guid());
        assert!(move_summaries_preserved(&rows,&summaries(ALICE,&name),&format!("{source_name}{suffix}"),&name));
        assert_eq!(bodies(root,"alice",&name),wire);
    }
    crate::folder_rename::reconcile_metadata(&settings,&request).unwrap();
    crate::folder_rename::role_lease(&settings,ALICE).unwrap().confirm().unwrap();
    let rows=summaries(ALICE,&format!("{destination_name}.Child"));
    let original=rows.iter().find(|row|row.uid==child_before[0].uid).unwrap();
    assert_eq!(labels.load(ALICE).unwrap().labels_for(&crate::labels::MessageIdentity::from_summary(ALICE,ALICE,&format!("{destination_name}.Child"),original).unwrap()).unwrap()[0].id(),id);
    assert!(snooze.load(ALICE,1001).unwrap().markers().iter().any(|m|m.identity().folder()==format!("{destination_name}.Child")));
    for (name,rows,wire) in recovery_bob {
        assert_eq!(summaries(BOB,name),rows);
        assert_eq!(bodies(root,"bob",name),wire);
    }
    assert!(labels.load(BOB).unwrap().labels().is_empty());
    assert!(snooze.load(BOB,1001).unwrap().markers().is_empty());
    assert!(crate::folder_disposition::list(&settings,ALICE).unwrap().is_empty());
    println!("native_rename injected_partial_signed_native_child_recovery_no_root_replay=PASS");
    mark_child_stage("complete");
}

// Test-only injection has no general path or mutation authority: fixed owned
// fixture containers only, exactly one root+Grand split. Every actual repair
// uses the ordinary production native backend, not this injected witness.
struct InjectedPartial {
    native: DoveadmMailboxListBackend<ScopedExecutor>,
    config: PathBuf,
}
impl MailboxBackend for InjectedPartial {
    fn list_mailboxes(&self,account:&str)->Result<Vec<MailboxEntry>,MailboxBackendError>{self.native.list_mailboxes(account)}
    fn folder_metadata(&self,account:&str)->Result<crate::folder_metadata::FolderSnapshot,MailboxBackendError>{self.native.folder_metadata(account)}
    fn mailbox_status(&self,account:&str,name:&str)->Result<crate::mailbox_status::MailboxStatus,MailboxBackendError>{self.native.mailbox_status(account,name)}
    fn rename_folder_attempt(&self,request:&RenameFolderRequest)->crate::folder_rename::NativeAttempt {
        let until=std::time::Instant::now()+Duration::from_secs(10);
        assert_eq!(request.account(),ALICE);
        assert_eq!(request.source(),"INBOX.Target.RenamedTree");
        assert_eq!(request.destination(),"INBOX.Target.RecoveredTree");
        assert_eq!(request.descendants().len(),2);
        let snapshot=self.native.folder_metadata(ALICE).unwrap();
        let source=self.native.mailbox_status(ALICE,request.source()).unwrap();
        let parent=self.native.mailbox_status(ALICE,request.parent()).unwrap();
        request.validate_before(&snapshot,&source,&parent).unwrap();
        crate::folder_subtree::check(&self.native,request,&snapshot,false).unwrap();
        assert!(snapshot.folder(ALICE,"INBOX.Target.RecoveredTree").is_err());
        assert!(snapshot.folder(ALICE,"INBOX.RecoveryHold").is_err());
        // Four fixed, actually reaped native setup commands construct the
        // injected split without adding direct Maildir write confinement.
        // The original root command runs once while its children are held;
        // its genuine success is deliberately represented as injected partial
        // uncertainty, not a reproduced error from Dovecot.
        let mut completed=0;
        for (source,target) in [
            ("INBOX.Target.RenamedTree.Child","INBOX.RecoveryHold"),
            ("INBOX.Target.RenamedTree","INBOX.Target.RecoveredTree"),
            ("INBOX.RecoveryHold","INBOX.Target.RenamedTree.Child"),
            ("INBOX.Target.RenamedTree.Child.Grand","INBOX.Target.RecoveredTree.Child.Grand"),
        ] {
            let args=scoped_args(&self.config,&[
                "-o".into(),"stats_writer_socket_path=".into(),"-o".into(),
                format!("auth_socket_path={}",self.config.parent().unwrap().join("userdb").display()),
                "mailbox".into(),"rename".into(),"-u".into(),ALICE.into(),source.into(),target.into(),
            ]);
            let remaining=until.checked_duration_since(std::time::Instant::now()).filter(|d|!d.is_zero()).expect("injected native setup original budget");
            let result=SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit("/usr/local/bin/doveadm",&args,b"",remaining,4096).unwrap();
            assert_eq!(result.status_code,0);
            assert!(result.stderr.is_empty());
            completed+=1;
        }
        assert_eq!(completed,4);
        crate::folder_rename::NativeAttempt::returned(Outcome::Unknown)
    }
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
    let node="native_rename recovery_node=source_root exists=true noselect=false nonexistent=true haschildren=true special_use_count=0";
    assert!(closed_child_diagnostic(node));
    assert!(closed_child_diagnostic(&node.replace("source_root","intended_child")));
    for bad in [node.replace("source_root","/private/mailbox"),node.replace("special_use_count=0","special_use_count=33"),node.replace("exists=true","exists=private-secret"),format!("{node} raw_secret")] {assert!(!closed_child_diagnostic(&bad));}
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

fn move_summaries_preserved(
    before: &[MessageSummary],
    after: &[MessageSummary],
    source: &str,
    destination: &str,
) -> bool {
    !before.is_empty()
        && before.len() == after.len()
        && before.iter().zip(after).all(|(old, new)| {
            if old.mailbox_name != source || new.mailbox_name != destination {
                return false;
            }
            let mut expected = old.clone();
            expected.mailbox_name = destination.into();
            *new == expected
        })
}

#[test]
fn native_move_summary_continuity_changes_only_exact_mailbox_name() {
    let before = MessageSummary {
        to: Some("alice@osmap-rename.invalid".into()),
        metadata: Some(crate::message_metadata::MessageMetadata {
            threading: None,
            version: crate::message_metadata::MessageVersion::new(
                "a".repeat(32),
                "owned-message".into(),
            )
            .unwrap(),
            attachment_count: Some(1),
            attachments: Some(vec![crate::message_metadata::AttachmentSummary {
                filename: Some("synthetic.bin".into()),
                encoded_size_bytes: 8,
            }]),
            protection: crate::message_metadata::MessageProtection::Plain,
            preview: Some("Owned text".into()),
        }),
        mailbox_name: "INBOX.Beta".into(),
        uid: 7,
        flags: vec!["\\Seen".into()],
        date_received: "2026-10-14 13:00:00".into(),
        size_virtual: 512,
        subject: Some("Owned subject".into()),
        from: Some("fixture@osmap-rename.invalid".into()),
    };
    let mut after = before.clone();
    after.mailbox_name = "INBOX.Target.Beta".into();
    assert_ne!(after, before); // The original native assertion rejects every real Move.
    let preserved = |new: &MessageSummary| {
        move_summaries_preserved(
            std::slice::from_ref(&before),
            std::slice::from_ref(new),
            "INBOX.Beta",
            "INBOX.Target.Beta",
        )
    };
    assert!(preserved(&after));
    assert!(!preserved(&before));
    let mut changed = after.clone();
    changed.metadata.as_mut().unwrap().version.message_guid.push('x');
    assert!(!preserved(&changed));
    let mut wrong_destination = after.clone();
    wrong_destination.mailbox_name = "INBOX.Other.Beta".into();
    assert!(!preserved(&wrong_destination));
    assert!(!move_summaries_preserved(
        &[],
        &[],
        "INBOX.Beta",
        "INBOX.Target.Beta"
    ));
    assert!(!move_summaries_preserved(
        std::slice::from_ref(&before),
        &[],
        "INBOX.Beta",
        "INBOX.Target.Beta"
    ));
    assert!(!move_summaries_preserved(
        std::slice::from_ref(&before),
        std::slice::from_ref(&after),
        "INBOX.Other",
        "INBOX.Target.Beta"
    ));
}

fn assert_known_arrival_payload(bytes: &[u8]) {
    let raw=std::str::from_utf8(bytes).unwrap();
    let (headers,body)=raw.split_once("\r\n\r\n").or_else(||raw.split_once("\n\n")).unwrap();
    let message=MessageView{metadata:None,mailbox_name:"INBOX.Arriving".into(),uid:1,flags:Vec::new(),date_received:String::new(),size_virtual:bytes.len() as u64,header_block:headers.into(),body_text:body.into()};
    let analysis=crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default()).analyze_message(&message).unwrap();
    assert_eq!(analysis.selected_plain_text_body.as_deref().map(|text|text.trim_end_matches(['\r','\n'])),Some("Populated folder contents stay with its native identity."));
    assert_eq!(analysis.attachments.len(),1);
    assert_eq!(analysis.attachments[0].filename.as_deref(),Some("synthetic.bin"));
    let attachment=crate::attachment::AttachmentDownloadService::new(crate::attachment::AttachmentDownloadPolicy::default()).download_from_message(&message,"1.2").unwrap();
    assert_eq!(attachment.body,[0,1,255]);
}

#[test]
fn native_delete_arrival_payload_uses_existing_mime_and_attachment_decoder() {
    assert_known_arrival_payload(MESSAGE);
}
