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
        assert!(matches!(program, "/usr/local/bin/doveadm" | "/usr/local/bin/doveconf"));
        assert!(timeout <= Duration::from_secs(5));
        assert!(!args.iter().any(|arg| matches!(arg.as_str(), "-A" | "-F" | "-c")));
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
                    let (ready, _) = crate::documents_doveadm::native_quota_probe_flags(&done.stdout, "");
                    println!("native_documents_first_upload quota_config status={} bytes={} ready={} count={} vsizes={} grace_zero={} global_plugin={}",
                        done.status_code, done.stdout.len(), ready,
                        done.stdout.contains("quota = count:"),
                        done.stdout.contains("quota_vsizes = yes"),
                        done.stdout.contains("quota_grace = 0%"),
                        done.stdout.contains("mail_plugins = quota"));
                }
                (Ok(done), false) if args.iter().any(|arg| arg == "quota") => {
                    let (_, finite) = crate::documents_doveadm::native_quota_probe_flags("", &done.stdout);
                    let error = done.stderr.to_ascii_lowercase();
                    let class = if error.contains("userdb") { "userdb" }
                        else if error.contains("permission") { "permission" }
                        else if error.contains("quota") { "quota" }
                        else if error.contains("connect") { "connect" }
                        else if error.is_empty() { "none" }
                        else { "other" };
                    println!("native_documents_first_upload quota_get status={} bytes={} finite={} error_class={}",
                        done.status_code, done.stdout.len(), finite, class);
                }
                (Err(_), true) => println!("native_documents_first_upload quota_config transport=refused"),
                (Err(_), false) if args.iter().any(|arg| arg == "quota") => println!("native_documents_first_upload quota_get transport=refused"),
                _ => {}
            }
        }
        result
    }
}

struct Fixture {
    root: PathBuf,
    root_lease: (u64, u64, u32, u32, u32),
    stop: Arc<AtomicBool>,
    userdb: Option<thread::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.userdb.take() {
            let _ = thread.join();
        }
        if fs::symlink_metadata(&self.root).ok().is_some_and(|metadata| {
            metadata.is_dir()
                && (metadata.dev(), metadata.ino(), metadata.uid(), metadata.gid(), metadata.mode() & 0o777)
                    == self.root_lease
        }) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn fixture_userdb(fixture: &mut Fixture, uid: u32, gid: u32) -> PathBuf {
    let path = fixture.root.join("auth-userdb");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let root = fixture.root.clone();
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
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
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
                        "USER\t{id}\t{ACCOUNT}\tuid={uid}\tgid={gid}\thome={}",
                        root.join("alice").display()
                    )
                    .unwrap();
                } else {
                    writeln!(stream, "NOTFOUND\t{id}").unwrap();
                }
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
        .map(|path| fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino(), m.len())))
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
    assert!(run("/usr/local/bin/doveadm", &["quota".into(), "get".into(), "-u".into(), "bob@osmap-documents.invalid".into()]).is_err());
    assert!(run("/usr/local/bin/doveadm", &["-A".into(), "quota".into(), "get".into(), "-u".into(), ACCOUNT.into()]).is_err());
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
        root_lease: (owner.dev(), owner.ino(), owner.uid(), owner.gid(), owner.mode() & 0o777),
        stop: Arc::new(AtomicBool::new(false)),
        userdb: None,
    };
    assert_eq!(owner.uid(), process_uid);
    assert_eq!(owner.mode() & 0o777, 0o700);
    for directory in ["run", "state", "alice/Maildir/cur", "alice/Maildir/new", "alice/Maildir/tmp"] {
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
        ScopedExecutor { config, diagnostic: true },
        "/usr/local/bin/doveadm",
        "/usr/local/bin/doveconf",
    )
    .with_userdb_socket_path(Some(userdb));
    let quota = match backend.quota_status(ACCOUNT) {
        Ok(Some(quota)) => quota,
        Ok(None) => panic!("native_documents_first_upload stage=quota_ready result=unavailable"),
        Err(error) => panic!("native_documents_first_upload stage=quota_ready result={error:?}"),
    };
    assert!(quota.limit_bytes >= 64 * 1024 && quota.used_bytes == 0);
    assert!(whole.elapsed() < NATIVE_LIMIT);
    println!("native_documents_first_upload quota_ready=PASS reserved_mailboxes_precreated=false");
    let store = Store::new(root.join("documents-index"), backend);
    let uploaded = match store.upload(ACCOUNT, 0, "first.bin", "application/octet-stream", b"first", 100) {
        Ok(uploaded) => uploaded,
        Err(error) => panic!("native_documents_first_upload stage=first_save result={error:?}"),
    };
    assert_eq!(uploaded.documents.len(), 1);
    assert_eq!(store.download(ACCOUNT, &uploaded.documents[0].id).unwrap().1, b"first");
    assert!(whole.elapsed() < NATIVE_LIMIT);
    println!("native_documents_first_upload first_save_and_exact_download=PASS bytes=5");
    assert!(root.join("alice/Maildir/.OSMAP.Documents").exists());
    assert_eq!(standard_metadata(), before);
    drop(fixture);
    assert!(!Path::new(&root).exists());
    println!("native_documents_first_upload owned_cleanup=PASS standard_two_path_metadata_unchanged=PASS");
}
