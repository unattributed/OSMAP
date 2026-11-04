// Opt-in first-upload discriminator on the authoritative OpenBSD mail host.
// All account data and configuration live in one owned scratch directory.
use super::*;
use crate::auth::{
    CommandExecution, CommandExecutionError, CommandExecutor, SystemCommandExecutor,
};
use crate::documents_doveadm::DoveadmDocumentsBackend;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const ACCOUNT: &str = "alice@osmap-documents.invalid";
const NATIVE_LIMIT: Duration = Duration::from_secs(120);

#[cfg(target_os = "openbsd")]
mod ffs {
    include!("documents_native_ffs_tests.rs");
}

#[cfg(target_os = "openbsd")]
mod migration {
    include!("documents_native_migration_tests.rs");
}

fn quota_test_message(kind: &str, id: usize, bytes: usize) -> Vec<u8> {
    assert!(matches!(kind, "seed" | "candidate"));
    let mut message = format!(
        "From: local@osmap.invalid\r\nTo: {ACCOUNT}\r\nMessage-ID: <quota-{kind}-{id}@osmap.invalid>\r\nX-OSMAP-Quota-Test: {kind}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
    ).into_bytes();
    assert!(message.len() + 2 <= bytes);
    while message.len() + 82 <= bytes {
        message.extend_from_slice(&[b'x'; 78]);
        message.extend_from_slice(b"\r\n");
    }
    message.resize(bytes - 2, b'x');
    message.extend_from_slice(b"\r\n");
    assert_eq!(message.len(), bytes);
    message
}

fn native_concurrent_quota_saves(root: &Path, config: &Path, userdb: &Path) {
    let executor = ScopedExecutor {
        config: config.into(),
        diagnostic: false,
    };
    let backend = DoveadmDocumentsBackend::new(
        executor.clone(),
        "/usr/local/bin/doveadm",
        "/usr/local/bin/doveconf",
    )
    .with_userdb_socket_path(Some(userdb.into()));
    let initial = backend
        .quota_status(ACCOUNT)
        .expect("native_documents_concurrent_quota stage=initial_quota result=unavailable")
        .expect("native_documents_concurrent_quota stage=initial_quota result=not_ready");
    assert_eq!(initial.limit_bytes, 64 * 1024);
    assert_eq!(initial.used_bytes, 0);
    let args = vec![
        "-o".into(),
        format!("auth_socket_path={}", userdb.display()),
        "save".into(),
        "-u".into(),
        ACCOUNT.into(),
        "-m".into(),
        "INBOX".into(),
    ];
    let seeded = executor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/doveadm",
            &args,
            &quota_test_message("seed", 0, 48 * 1024),
            Duration::from_secs(5),
            4096,
        )
        .expect("native_documents_concurrent_quota stage=seed result=transport_unknown");
    assert_eq!(
        seeded.status_code, 0,
        "native_documents_concurrent_quota stage=seed result=refused"
    );
    let seeded_quota = backend
        .quota_status(ACCOUNT)
        .expect("native_documents_concurrent_quota stage=seed_quota result=unavailable")
        .expect("native_documents_concurrent_quota stage=seed_quota result=not_ready");
    assert_eq!(seeded_quota.used_bytes, 48 * 1024);
    let outcomes = thread::scope(|scope| {
        // A bounded ready/release barrier also terminates safely if a worker
        // cannot start; an unbounded Barrier::wait would strand its peers.
        let (ready, prepared) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        let mut releases = Vec::new();
        for (id, mailbox) in ["INBOX", "OSMAP.Documents", "OSMAP.DocumentsBin"]
            .into_iter()
            .enumerate()
        {
            let executor = executor.clone();
            let mut args = args.clone();
            *args.last_mut().unwrap() = mailbox.into();
            let ready = ready.clone();
            let (release, start) = std::sync::mpsc::channel();
            releases.push(release);
            handles.push(scope.spawn(move || {
                let message = quota_test_message("candidate", id, 12 * 1024);
                ready.send(()).unwrap();
                start.recv_timeout(Duration::from_secs(2)).expect(
                    "native_documents_concurrent_quota stage=launch result=release_timeout",
                );
                executor.run_with_stdin_bytes_timeout_and_output_limit(
                    "/usr/local/bin/doveadm",
                    &args,
                    &message,
                    Duration::from_secs(5),
                    4096,
                )
            }));
        }
        for _ in 0..3 {
            prepared.recv_timeout(Duration::from_secs(2)).expect(
                "native_documents_concurrent_quota stage=launch result=preparation_timeout",
            );
        }
        for release in releases {
            release.send(()).unwrap();
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    // Inspect only the controlled fixture's three owned mailboxes, independently of
    // quota-plugin counters and command success. No production mailbox read.
    let mut candidates = 0usize;
    let mut exact_virtual_bytes = 0u64;
    for mailbox in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"] {
        for directory in ["cur", "new"] {
            for entry in
                fs::read_dir(root.join("alice/Maildir").join(mailbox).join(directory)).unwrap()
            {
                let path = entry.unwrap().path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(metadata.is_file() && metadata.len() <= 64 * 1024);
                let bytes = fs::read(path).unwrap();
                // Maildir may normalize CRLF to LF. Dovecot vsize counts CRLF.
                let lf = bytes.iter().filter(|byte| **byte == b'\n').count();
                let crlf = bytes.windows(2).filter(|pair| *pair == b"\r\n").count();
                exact_virtual_bytes += bytes.len() as u64 + (lf - crlf) as u64;
                if bytes
                    .windows(b"X-OSMAP-Quota-Test: candidate".len())
                    .any(|part| part == b"X-OSMAP-Quota-Test: candidate")
                {
                    candidates += 1;
                }
            }
        }
    }
    let quota = backend
        .quota_status(ACCOUNT)
        .expect("native_documents_concurrent_quota stage=post_quota result=unavailable")
        .expect("native_documents_concurrent_quota stage=post_quota result=not_ready");
    let accepted = outcomes
        .iter()
        .filter(|result| result.as_ref().is_ok_and(|done| done.status_code == 0))
        .count();
    let transport_known = outcomes.iter().all(Result::is_ok);
    println!("native_documents_concurrent_quota stage=three_native_saves candidates={candidates} accepted={accepted} virtual_bytes={exact_virtual_bytes} reported_bytes={} limit_bytes={} transport_known={transport_known}", quota.used_bytes, quota.limit_bytes);
    assert!(
        transport_known,
        "native_documents_concurrent_quota stage=save result=transport_unknown"
    );
    assert_eq!(
        accepted, candidates,
        "native_documents_concurrent_quota stage=reconcile result=status_storage_mismatch"
    );
    assert_eq!(
        candidates, 1,
        "native_documents_concurrent_quota stage=three_native_saves result=not_exactly_one"
    );
    assert_eq!(
        exact_virtual_bytes,
        60 * 1024,
        "native_documents_concurrent_quota stage=reconcile result=seed_or_candidate_bytes_changed"
    );
    assert!(
        exact_virtual_bytes <= quota.limit_bytes && quota.used_bytes <= quota.limit_bytes,
        "native_documents_concurrent_quota stage=three_native_saves result=limit_exceeded"
    );
    assert_eq!(
        quota.used_bytes, exact_virtual_bytes,
        "native_documents_concurrent_quota stage=reconcile result=quota_counter_mismatch"
    );
    println!("native_documents_concurrent_quota native_save_processes=3 joint_limit=PASS all_protocols=NOT_QUALIFIED");
}

#[test]
fn documents_quota_control_messages_count_exact_wire_bytes() {
    for (kind, bytes) in [("seed", 48 * 1024), ("candidate", 12 * 1024)] {
        let message = quota_test_message(kind, 0, bytes);
        assert_eq!(message.len(), bytes);
        assert!(message.ends_with(b"\r\n"));
        assert_eq!(
            message.iter().filter(|byte| **byte == b'\n').count(),
            message.windows(2).filter(|pair| *pair == b"\r\n").count()
        );
    }
}

fn process_numeric_id(flag: &str) -> u32 {
    assert!(matches!(flag, "-u" | "-g"));
    let result = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/bin/id",
            &[flag.to_string()],
            b"",
            Duration::from_secs(2),
            32,
        )
        .unwrap();
    assert_eq!(result.status_code, 0);
    assert!(result.stderr.is_empty());
    let bytes = result.stdout.as_bytes();
    assert!(bytes.ends_with(b"\n") && bytes.len() <= 11);
    let digits = &bytes[..bytes.len() - 1];
    assert!(!digits.is_empty() && digits.iter().all(u8::is_ascii_digit));
    digits.iter().fold(0u32, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
            .unwrap()
    })
}

#[derive(Clone)]
struct ScopedExecutor {
    config: PathBuf,
    diagnostic: bool,
}

impl CommandExecutor for ScopedExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("Documents native qualification requires bounded commands")
    }

    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        output_limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert!(matches!(
            program,
            "/usr/local/bin/doveadm" | "/usr/local/bin/doveconf"
        ));
        assert!(timeout <= Duration::from_secs(5));
        assert!(!args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-A" | "-F" | "-c")));
        if program.ends_with("doveadm") {
            let position = args.iter().position(|arg| arg == "-u").unwrap();
            assert_eq!(args.get(position + 1).map(String::as_str), Some(ACCOUNT));
        } else {
            assert_eq!(args, ["-n"]);
            assert!(input.is_empty());
        }
        let mut scoped = vec!["-c".into(), self.config.to_string_lossy().into_owned()];
        scoped.extend_from_slice(args);
        let result = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
            program,
            &scoped,
            input,
            timeout,
            output_limit,
        );
        if self.diagnostic {
            match (&result, program.ends_with("doveconf")) {
                (Ok(done), true) => {
                    let (ready, _) =
                        crate::documents_doveadm::native_quota_probe_flags(&done.stdout, "");
                    println!("native_documents_first_upload quota_config status={} bytes={} ready={} count={} vsizes={} grace_zero={} global_plugin={}",
                        done.status_code, done.stdout.len(), ready,
                        done.stdout.contains("quota = count:"),
                        done.stdout.contains("quota_vsizes = yes"),
                        done.stdout.contains("quota_grace = 0%"),
                        done.stdout.contains("mail_plugins = quota"));
                }
                (Ok(done), false) if args.iter().any(|arg| arg == "quota") => {
                    let (_, finite) =
                        crate::documents_doveadm::native_quota_probe_flags("", &done.stdout);
                    let error = done.stderr.to_ascii_lowercase();
                    let class = if error.contains("userdb") {
                        "userdb"
                    } else if error.contains("permission") {
                        "permission"
                    } else if error.contains("quota") {
                        "quota"
                    } else if error.contains("connect") {
                        "connect"
                    } else if error.is_empty() {
                        "none"
                    } else {
                        "other"
                    };
                    println!("native_documents_first_upload quota_get status={} bytes={} finite={} error_class={}",
                        done.status_code, done.stdout.len(), finite, class);
                }
                (Err(_), true) => {
                    println!("native_documents_first_upload quota_config transport=refused")
                }
                (Err(_), false) if args.iter().any(|arg| arg == "quota") => {
                    println!("native_documents_first_upload quota_get transport=refused")
                }
                _ => {}
            }
        }
        result
    }
}

// Deliberately fails the first reserved-mailbox status check in the same
// native Store, after live quota and lookup preflights. No storage mutation
// may be dispatched or left pending after this confirmed pre-dispatch fault.
struct RefuseReservedStatus {
    scoped: ScopedExecutor,
}

impl CommandExecutor for RefuseReservedStatus {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("Documents native qualification requires bounded commands")
    }

    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        output_limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        if args.windows(2).any(|pair| pair == ["mailbox", "status"]) {
            return Err(CommandExecutionError {
                reason: "synthetic reserved status unavailable before mutation".into(),
            });
        }
        assert!(
            !args
                .iter()
                .any(|arg| matches!(arg.as_str(), "save" | "move" | "expunge")),
            "pre-dispatch fault must not reach native mutation"
        );
        self.scoped.run_with_stdin_bytes_timeout_and_output_limit(
            program,
            args,
            input,
            timeout,
            output_limit,
        )
    }
}

struct Fixture {
    root: PathBuf,
    root_lease: (u64, u64, u32, u32, u32),
    stop: Arc<AtomicBool>,
    userdb: Option<thread::JoinHandle<()>>,
    retain_on_failure: bool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.userdb.take() {
            if thread.join().is_err() {
                println!("native_documents_fixture failure_state=RETAINED root={} cleanup=NOT_CLAIMED reason=userdb_join_failed", self.root.display());
                return;
            }
        }
        if self.retain_on_failure && thread::panicking() {
            println!("native_documents_fixture failure_state=RETAINED root={} device={} inode={} uid={} gid={} mode={:o} native_log=native.log cleanup=NOT_CLAIMED", self.root.display(),self.root_lease.0,self.root_lease.1,self.root_lease.2,self.root_lease.3,self.root_lease.4);
            return;
        }
        if fs::symlink_metadata(&self.root)
            .ok()
            .is_some_and(|metadata| {
                metadata.is_dir()
                    && (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.uid(),
                        metadata.gid(),
                        metadata.mode() & 0o777,
                    ) == self.root_lease
            })
            && fs::remove_dir_all(&self.root).is_err()
        {
            println!("native_documents_fixture failure_state=RETAINED root={} cleanup=NOT_CLAIMED reason=owned_remove_failed", self.root.display());
        }
    }
}

fn fixture_userdb(fixture: &mut Fixture, uid: u32, gid: u32) -> PathBuf {
    let home = fixture.root.join("alice");
    fixture_userdb_with_fields(fixture, uid, gid, home, Vec::new())
}

fn fixture_userdb_with_fields(
    fixture: &mut Fixture,
    uid: u32,
    gid: u32,
    home: PathBuf,
    extras: Vec<(String, String)>,
) -> PathBuf {
    assert!(uid > 0 && gid > 0);
    assert!(home.is_absolute());
    let home = home.to_str().unwrap();
    assert!(home.len() <= 1024 && !home.chars().any(char::is_control));
    let home = home.to_owned();
    assert!(extras.len() <= 5);
    let mut names = std::collections::BTreeSet::new();
    let mut extra_fields = String::new();
    for (name, value) in extras {
        assert!(matches!(
            name.as_str(),
            "mail" | "quota" | "quota_rule" | "osmap_quota_mount" | "osmap_configured_quota"
        ));
        assert!(names.insert(name.clone()));
        assert!(!value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control));
        extra_fields.push('\t');
        extra_fields.push_str(&name);
        extra_fields.push('=');
        extra_fields.push_str(&value);
    }
    let path = fixture.root.join("auth-userdb");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = fixture.stop.clone();
    fixture.userdb = Some(thread::spawn(move || {
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("owned userdb accept: {error}"),
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
                let size = Read::by_ref(&mut reader)
                    .take(4097)
                    .read_until(b'\n', &mut line)
                    .unwrap();
                if size == 0 {
                    break;
                }
                assert!(size <= 4096 && line.ends_with(b"\n"));
                let fields: Vec<&str> = std::str::from_utf8(&line)
                    .unwrap()
                    .trim_end_matches('\n')
                    .split('\t')
                    .collect();
                if fields.first() == Some(&"VERSION") {
                    continue;
                }
                assert_eq!(fields.first(), Some(&"USER"));
                assert!(fields.len() >= 4);
                let id = fields[1];
                assert!(!id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()));
                if fields[2] == ACCOUNT {
                    writeln!(
                        stream,
                        "USER\t{id}\t{ACCOUNT}\tuid={uid}\tgid={gid}\thome={home}{extra_fields}"
                    )
                    .unwrap();
                } else {
                    writeln!(stream, "NOTFOUND\t{id}").unwrap();
                }
                // One lookup per owned connection. Close both handles after
                // replying so the serial fixture listener can admit peers.
                break;
            }
        }
    }));
    path
}

// Only these two named standard paths are observed; an unreadable path stays
// None and this does not attest the rest of the host.
fn standard_metadata() -> Vec<Option<(u64, u64, u64)>> {
    ["/etc/dovecot/dovecot.conf", "/var/dovecot/auth-userdb"]
        .iter()
        .map(|path| {
            fs::symlink_metadata(path)
                .ok()
                .map(|m| (m.dev(), m.ino(), m.len()))
        })
        .collect()
}

#[test]
fn documents_native_executor_refuses_other_program_or_account_before_dispatch() {
    let scoped = ScopedExecutor {
        config: PathBuf::from("/dev/null"),
        diagnostic: false,
    };
    let run = |program: &str, args: &[String]| {
        std::panic::catch_unwind(|| {
            let _ = scoped.run_with_stdin_bytes_timeout_and_output_limit(
                program,
                args,
                b"",
                Duration::from_secs(5),
                4096,
            );
        })
    };
    assert!(run("/usr/bin/true", &["-n".into()]).is_err());
    assert!(run(
        "/usr/local/bin/doveadm",
        &[
            "quota".into(),
            "get".into(),
            "-u".into(),
            "bob@osmap-documents.invalid".into()
        ]
    )
    .is_err());
    assert!(run(
        "/usr/local/bin/doveadm",
        &[
            "-A".into(),
            "quota".into(),
            "get".into(),
            "-u".into(),
            ACCOUNT.into()
        ]
    )
    .is_err());
}

#[test]
#[ignore = "requires a non-root local developer identity"]
fn documents_native_fixture_uses_process_identity_not_scratch_group() {
    let uid = process_numeric_id("-u");
    let gid = process_numeric_id("-g");
    assert!(uid > 0 && gid > 0);
    assert!(std::panic::catch_unwind(|| process_numeric_id("-G")).is_err());
}

#[test]
#[ignore = "explicit disposable OpenBSD Dovecot quota and first document save"]
fn isolated_openbsd_documents_first_upload_without_reserved_mailbox() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let whole = Instant::now();
    let before = standard_metadata();
    let process_uid = process_numeric_id("-u");
    let process_gid = process_numeric_id("-g");
    assert_ne!(process_uid, 0);
    assert_ne!(process_gid, 0);
    let root = std::env::temp_dir().join(format!(
        "osmap-documents-native-{}-{}",
        std::process::id(),
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let owner = fs::symlink_metadata(&root).unwrap();
    let mut fixture = Fixture {
        root: root.clone(),
        root_lease: (
            owner.dev(),
            owner.ino(),
            owner.uid(),
            owner.gid(),
            owner.mode() & 0o777,
        ),
        stop: Arc::new(AtomicBool::new(false)),
        userdb: None,
        retain_on_failure: true,
    };
    assert_eq!(owner.uid(), process_uid);
    assert_eq!(owner.mode() & 0o777, 0o700);
    for directory in [
        "run",
        "state",
        "alice/Maildir/cur",
        "alice/Maildir/new",
        "alice/Maildir/tmp",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    // Neither reserved Documents mailbox is provisioned in advance.
    assert!(!root.join("alice/Maildir/.OSMAP.Documents").exists());
    assert!(!root.join("alice/Maildir/.OSMAP.DocumentsBin").exists());
    let config = root.join("dovecot.conf");
    fs::write(&config, format!(
        "base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = {1}\nmail_gid = {2}\nfirst_valid_uid = {1}\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins = quota\nmailbox_list_index = yes\nplugin {{\n quota = count:User quota\n quota_rule = *:storage=64K\n quota_grace = 0%\n quota_vsizes = yes\n}}\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n",
        root.display(), process_uid, process_gid
    )).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    // On OpenBSD, a new directory can inherit the parent group. Its st_gid
    // does not attest the process's primary GID for Dovecot userdb admission.
    let userdb = fixture_userdb(&mut fixture, process_uid, process_gid);
    let backend = DoveadmDocumentsBackend::new(
        ScopedExecutor {
            config: config.clone(),
            diagnostic: true,
        },
        "/usr/local/bin/doveadm",
        "/usr/local/bin/doveconf",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let quota = match backend.quota_status(ACCOUNT) {
        Ok(Some(quota)) => quota,
        Ok(None) => panic!("native_documents_first_upload stage=quota_ready result=unavailable"),
        Err(error) => panic!("native_documents_first_upload stage=quota_ready result={error:?}"),
    };
    assert!(quota.limit_bytes >= 64 * 1024 && quota.used_bytes == 0);
    assert!(whole.elapsed() < NATIVE_LIMIT);
    println!("native_documents_first_upload quota_ready=PASS reserved_mailboxes_precreated=false");
    let store = Store::new(root.join("documents-index"), backend);
    let uploaded = match store.upload(
        ACCOUNT,
        0,
        "first.bin",
        "application/octet-stream",
        b"first",
        100,
    ) {
        Ok(uploaded) => uploaded,
        Err(error) => panic!("native_documents_first_upload stage=first_save result={error:?}"),
    };
    assert_eq!(uploaded.documents.len(), 1);
    assert_eq!(
        store
            .download(ACCOUNT, &uploaded.documents[0].id)
            .unwrap()
            .1,
        b"first"
    );
    assert!(whole.elapsed() < NATIVE_LIMIT);
    println!("native_documents_first_upload first_save_and_exact_download=PASS bytes=5");
    assert!(root.join("alice/Maildir/.OSMAP.Documents").exists());
    let id = uploaded.documents[0].id.clone();
    let inspector = DoveadmDocumentsBackend::new(
        ScopedExecutor {
            config: config.clone(),
            diagnostic: false,
        },
        "/usr/local/bin/doveadm",
        "/usr/local/bin/doveconf",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    assert_eq!(
        inspector.inspect(ACCOUNT, &id).unwrap(),
        vec![uploaded.documents[0].location.clone().unwrap()]
    );
    let binned = store.bin(ACCOUNT, uploaded.revision, &id, 101).unwrap();
    assert_eq!(binned.documents[0].state, State::InBin);
    assert_eq!(
        binned.documents[0].location.as_ref().unwrap().mailbox,
        "OSMAP.DocumentsBin"
    );
    assert!(root.join("alice/Maildir/.OSMAP.DocumentsBin").exists());
    assert_eq!(store.download(ACCOUNT, &id), Err(Error::NotFound));
    assert_eq!(
        inspector.inspect(ACCOUNT, &id).unwrap(),
        vec![binned.documents[0].location.clone().unwrap()]
    );
    assert_eq!(
        inspector
            .read(ACCOUNT, &id, binned.documents[0].location.as_ref().unwrap())
            .unwrap(),
        b"first"
    );
    println!("native_documents_bin first_move_and_reserved_bin=PASS");

    let restored = store.restore(ACCOUNT, binned.revision, &id, 102).unwrap();
    assert_eq!(restored.documents[0].state, State::Available);
    assert_eq!(
        restored.documents[0].location.as_ref().unwrap().mailbox,
        "OSMAP.Documents"
    );
    assert_eq!(store.download(ACCOUNT, &id).unwrap().1, b"first");
    assert_eq!(
        inspector.inspect(ACCOUNT, &id).unwrap(),
        vec![restored.documents[0].location.clone().unwrap()]
    );
    println!("native_documents_bin restore_and_exact_download=PASS bytes=5");

    let binned_again = store.bin(ACCOUNT, restored.revision, &id, 103).unwrap();
    let deleted = store
        .delete_confirmed(ACCOUNT, binned_again.revision, &id, 104)
        .unwrap();
    assert!(deleted.documents.is_empty());
    assert!(inspector.inspect(ACCOUNT, &id).unwrap().is_empty());
    assert_eq!(
        inspector.quota_status(ACCOUNT).unwrap().unwrap().used_bytes,
        0
    );
    println!("native_documents_bin confirmed_expunge_and_quota_release=PASS");

    let fault_backend = DoveadmDocumentsBackend::new(
        RefuseReservedStatus {
            scoped: ScopedExecutor {
                config: config.clone(),
                diagnostic: false,
            },
        },
        "/usr/local/bin/doveadm",
        "/usr/local/bin/doveconf",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let fault_store = Store::new(root.join("documents-index"), fault_backend);
    assert_eq!(
        fault_store.upload(
            ACCOUNT,
            deleted.revision,
            "refused.bin",
            "application/octet-stream",
            b"no write",
            105
        ),
        Err(Error::PreDispatchUnavailable)
    );
    let after_fault = fault_store.load(ACCOUNT).unwrap();
    assert!(after_fault.documents.is_empty());
    assert_eq!(after_fault.revision, deleted.revision + 2);
    println!("native_documents_bin predispatch_refusal_no_pending_or_mutation=PASS");
    native_concurrent_quota_saves(&root, &config, &userdb);
    assert!(whole.elapsed() < NATIVE_LIMIT);
    assert_eq!(standard_metadata(), before);
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!Path::new(&root).exists());
    println!("native_documents_first_upload owned_cleanup=PASS standard_two_path_metadata_unchanged=PASS");
}
