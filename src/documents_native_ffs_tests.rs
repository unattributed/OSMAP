// Explicit isolated FFS candidate. This never admits a production quota driver.
use super::*;
use sha2::Sha256;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

mod http {
    include!("documents_native_http_tests.rs");
}

const QUOTA_UID: u32 = 1000;
const BLOCK_BYTES: u32 = 512;

// Copied quota fields returned by the reviewed platform boundary.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Dqblk {
    bhard: u32,
    bsoft: u32,
    blocks: u32,
    ihard: u32,
    isoft: u32,
    inodes: u32,
    btime: u32,
    itime: u32,
}

pub(super) fn fixture_path(variable: &str, prefix: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var(variable).expect("ffs stage=admission result=missing_path"));
    checked_fixture_path(path, prefix)
}

fn checked_fixture_path(path: PathBuf, prefix: &str) -> PathBuf {
    assert_eq!(path.parent(), Some(Path::new("/tmp")));
    let name = path.file_name().unwrap().to_str().unwrap();
    let suffix = name
        .strip_prefix(prefix)
        .expect("ffs stage=admission result=wrong_prefix");
    assert!(
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(fs::canonicalize(&path).unwrap(), path);
    path
}

pub(super) fn hard_bytes() -> u32 {
    match std::env::var("OSMAP_FFS_HARD_BYTES").as_deref() {
        Ok("262144") => 262144,
        Ok("1048576") => 1048576,
        Ok("33554432") => 33554432,
        _ => panic!("ffs stage=admission result=invalid_hard_limit"),
    }
}

pub(super) fn checked_mount(base: &Path) -> PathBuf {
    let owner = fs::symlink_metadata(base).unwrap();
    assert!(owner.is_dir() && owner.uid() == 0 && owner.mode() & 0o777 == 0o711);
    let data = base.join("data");
    assert_eq!(fs::canonicalize(&data).unwrap(), data);
    let owner = fs::symlink_metadata(&data).unwrap();
    assert!(owner.is_dir() && owner.uid() == 0 && owner.mode() & 0o777 == 0o755);
    assert_ne!(owner.dev(), fs::metadata(base).unwrap().dev());
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&data)
        .unwrap();
    let (mounted, source) = crate::openbsd::ffs_mount_info(&directory).unwrap();
    assert_eq!(mounted, data);
    assert!(matches!(
        source.as_os_str().as_bytes(),
        b"/dev/vnd0a" | b"/dev/vnd1a" | b"/dev/vnd2a" | b"/dev/vnd3a"
    ));
    data
}

fn get_quota(data: &Path) -> Dqblk {
    let [bhard, bsoft, blocks, ihard, isoft, inodes, btime, itime] =
        crate::openbsd::read_user_quota(data, QUOTA_UID).unwrap();
    let quota = Dqblk {
        bhard,
        bsoft,
        blocks,
        ihard,
        isoft,
        inodes,
        btime,
        itime,
    };
    assert_eq!(quota.bsoft, 0);
    assert_eq!(quota.bhard * BLOCK_BYTES, hard_bytes());
    assert!(
        quota.blocks <= quota.bhard,
        "ffs stage=kernel_bound result=exceeded"
    );
    quota
}

#[test]
#[ignore = "root only, exact pre-mounted owned disposable FFS volume"]
fn isolated_openbsd_ffs_root_prepare() {
    assert_eq!(process_numeric_id("-u"), 0);
    assert_eq!(std::mem::size_of::<Dqblk>(), 32);
    let base = fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q.");
    let data = checked_mount(&base);
    // Fresh volume only: refuse user allocations or an existing quota database.
    assert!(
        fs::read_dir(&data).unwrap().next().is_none(),
        "ffs stage=prepare result=nonempty_volume"
    );
    let quota_path = data.join("quota.user");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&quota_path)
        .unwrap();
    file.write_all(&vec![0; (QUOTA_UID as usize + 1) * 32])
        .unwrap();
    file.sync_all().unwrap();
    let meta = file.metadata().unwrap();
    assert_eq!(
        (meta.uid(), meta.mode() & 0o777, meta.len()),
        (0, 0o600, 1001 * 32)
    );
    crate::openbsd::prepare_ffs_fixture_quota(&data, hard_bytes()).unwrap();
    let actual = get_quota(&data);
    assert_eq!(actual.blocks, 0);
    println!(
        "native_ffs_prepare result=PASS uid=1000 hard_bytes={} soft_bytes=0 cleanup=ROOT_OWNED",
        hard_bytes()
    );
}

#[test]
#[ignore = "root only, exact still-mounted disposable FFS quota teardown"]
fn isolated_openbsd_ffs_root_quota_off() {
    assert_eq!(process_numeric_id("-u"), 0);
    let base = fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q.");
    let data = checked_mount(&base);
    let file = fs::symlink_metadata(data.join("quota.user")).unwrap();
    assert!(
        file.is_file()
            && file.uid() == 0
            && file.mode() & 0o777 == 0o600
            && file.len() == 1001 * 32
    );
    let _ = get_quota(&data);
    crate::openbsd::disable_ffs_fixture_quota(&data).unwrap();
    println!("native_ffs_quotaoff result=PASS volume_cleanup=ROOT_OWNED");
}

fn native(
    executor: &ScopedExecutor,
    userdb: &Path,
    operation: &[&str],
    input: &[u8],
) -> CommandExecution {
    let mut args = vec![
        "-o".into(),
        format!("auth_socket_path={}", userdb.display()),
    ];
    args.extend(operation.iter().map(|s| (*s).into()));
    let result = executor.run_with_stdin_bytes_timeout_and_output_limit(
        "/usr/local/bin/doveadm",
        &args,
        input,
        Duration::from_secs(5),
        2 * 1024 * 1024,
    );
    let label = if operation.first() == Some(&"save") {
        match operation.last().copied() {
            Some("INBOX") => "native-save-inbox",
            Some("OSMAP.Documents") => "native-save-documents",
            Some("OSMAP.DocumentsBin") => "native-save-bin",
            _ => panic!("ffs stage=diagnostic result=unowned_save_target"),
        }
    } else {
        "native"
    };
    retain_response(executor.config.parent().unwrap(), label, &result);
    result.expect("ffs stage=native result=transport_unknown")
}

// A private last response per fixed writer; no command/payload text is logged.
// Save workers have distinct names so concurrent results cannot overwrite peers.
fn retain_response(
    root: &Path,
    label: &str,
    result: &Result<CommandExecution, CommandExecutionError>,
) {
    assert!(matches!(
        label,
        "native"
            | "native-save-inbox"
            | "native-save-documents"
            | "native-save-bin"
            | "imap"
            | "lmtp"
            | "worker"
            | "worker-refused"
    ));
    let owner = fs::symlink_metadata(root).unwrap();
    assert!(owner.is_dir() && owner.uid() == QUOTA_UID && owner.mode() & 0o777 == 0o700);
    let status = match result {
        Ok(done) => format!("status={}\ntransport=known\n", done.status_code),
        Err(_) => "transport=unknown\n".into(),
    };
    let (stdout, stderr) = match result {
        Ok(done) => (done.stdout.as_bytes(), done.stderr.as_bytes()),
        Err(_) => (&[][..], &[][..]),
    };
    for (extension, bytes) in [
        ("stdout", stdout),
        ("stderr", stderr),
        ("status", status.as_bytes()),
    ] {
        // The real maximum-file read is bounded by the product MIME fetch cap.
        assert!(bytes.len() <= 15 * 1024 * 1024);
        let path = root.join(format!("last-{label}.{extension}"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        assert!(
            metadata.is_file()
                && metadata.uid() == QUOTA_UID
                && metadata.mode() & 0o777 == 0o600
                && metadata.nlink() == 1
                && metadata.dev() == owner.dev()
        );
        file.set_len(0).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}

fn normalized(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len());
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
            result.push(b'\r');
        }
        result.push(*byte);
    }
    result
}

fn quota_reason(done: &CommandExecution) -> bool {
    let output = format!("{}\n{}", done.stdout, done.stderr).to_ascii_lowercase();
    output.contains("quota exceeded")
        || output.contains("disk quota exceeded")
        || output.contains("overquota")
        || output.contains("not enough disk quota")
}

#[test]
fn quota_reason_accepts_observed_lmtp_refusal_without_generic_errors() {
    let result = |stdout: &str, stderr: &str| CommandExecution {
        status_code: 0,
        stdout: stdout.into(),
        stderr: stderr.into(),
    };
    assert!(quota_reason(&result(
        "552 5.2.2 <alice@osmap-documents.invalid> Not enough disk quota\r\n",
        "save failed to INBOX: Not enough disk quota"
    )));
    for (stdout, stderr) in [
        (
            "552 5.2.2 Temporary backend unavailable",
            "quota lookup failed",
        ),
        ("", "Not enough disk space"),
        ("", "quota service unavailable"),
        ("250 2.0.0 Saved", ""),
    ] {
        assert!(!quota_reason(&result(stdout, stderr)));
    }
    // The recognized reason alone cannot substitute for the required LMTP
    // enhanced status or make a successfully accepted delivery a refusal.
    let wrong_status = result("451 4.3.0 Not enough disk quota", "");
    assert!(std::panic::catch_unwind(|| assert_protocol_quota_refusal(
        &wrong_status,
        WireProtocol::Lmtp
    ))
    .is_err());
    let accepted = result("250 2.0.0 Saved\r\n552 5.2.2 Not enough disk quota", "");
    assert!(std::panic::catch_unwind(|| assert_protocol_quota_refusal(
        &accepted,
        WireProtocol::Lmtp
    ))
    .is_err());
}

fn assert_native_quota_refusal(done: &CommandExecution) {
    let quota = quota_reason(done);
    println!(
        "native_ffs_refusal protocol=doveadm status={} quota_reason={quota}",
        done.status_code
    );
    assert!(
        matches!(done.status_code, 73 | 75) && quota,
        "ffs stage=native_refusal result=not_confirmed_quota_refusal"
    );
}

#[derive(Clone, Copy)]
enum WireProtocol {
    Imap,
    Lmtp,
}

fn protocol_write(
    executor: &ScopedExecutor,
    userdb: &Path,
    protocol: WireProtocol,
    mailbox: &str,
    message: &[u8],
) -> CommandExecution {
    assert!(matches!(mailbox, "INBOX" | "OSMAP.Documents"));
    let cfg = executor.config.to_string_lossy().into_owned();
    let socket = format!("auth_socket_path={}", userdb.display());
    let (program, args, input) = match protocol {
        WireProtocol::Imap => {
            // Reuse the already-qualified direct imap exec shape: -c must also
            // reach imap, since doveadm exec does not propagate its own config.
            let args = vec![
                "-c".into(),
                cfg.clone(),
                "exec".into(),
                "imap".into(),
                "-c".into(),
                cfg,
                "-o".into(),
                "stats_writer_socket_path=".into(),
                "-o".into(),
                socket,
                "-u".into(),
                ACCOUNT.into(),
            ];
            let mut input = format!("A1 APPEND {mailbox} {{{}+}}\r\n", message.len()).into_bytes();
            input.extend_from_slice(message);
            input.extend_from_slice(b"\r\nZ1 LOGOUT\r\n");
            ("/usr/local/bin/doveadm", args, input)
        }
        WireProtocol::Lmtp => {
            assert_eq!(mailbox, "INBOX");
            let args = vec![
                "-c".into(),
                cfg,
                "-o".into(),
                "stats_writer_socket_path=".into(),
                "-o".into(),
                socket,
            ];
            let mut input = format!("LHLO fixture.osmap.invalid\r\nMAIL FROM:<local@osmap.invalid>\r\nRCPT TO:<{ACCOUNT}>\r\nDATA\r\n").into_bytes();
            for line in message.split_inclusive(|b| *b == b'\n') {
                if line.first() == Some(&b'.') {
                    input.push(b'.');
                }
                input.extend_from_slice(line);
            }
            input.extend_from_slice(b".\r\nQUIT\r\n");
            ("/usr/local/libexec/dovecot/lmtp", args, input)
        }
    };
    let result = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
        program,
        &args,
        &input,
        Duration::from_secs(5),
        2 * 1024 * 1024,
    );
    retain_response(
        executor.config.parent().unwrap(),
        match protocol {
            WireProtocol::Imap => "imap",
            WireProtocol::Lmtp => "lmtp",
        },
        &result,
    );
    result.expect("ffs stage=protocol result=transport_unknown")
}

fn protocol_accepted(done: &CommandExecution, protocol: WireProtocol) -> bool {
    match protocol {
        WireProtocol::Imap => {
            done.status_code == 0 && done.stdout.lines().any(|s| s.starts_with("A1 OK "))
        }
        WireProtocol::Lmtp => {
            done.status_code == 0
                && done
                    .stdout
                    .lines()
                    .any(|s| s.starts_with("250 2.0.0 ") && s.contains("Saved"))
        }
    }
}

fn assert_protocol_quota_refusal(done: &CommandExecution, protocol: WireProtocol) {
    let quota = quota_reason(done);
    let (name, refused) = match protocol {
        WireProtocol::Imap => (
            "imap",
            done.stdout
                .lines()
                .any(|s| s.starts_with("A1 NO ") && s.contains("OVERQUOTA")),
        ),
        WireProtocol::Lmtp => (
            "lmtp",
            done.stdout
                .lines()
                .any(|s| s.starts_with("552 5.2.2 ") || s.starts_with("452 5.2.2 ")),
        ),
    };
    println!(
        "native_ffs_refusal protocol={name} status={} quota_reason={quota} protocol_refusal={refused}",
        done.status_code
    );
    assert!(
        done.status_code == 0 && refused && quota && !protocol_accepted(done, protocol),
        "ffs stage=protocol_refusal result=not_confirmed_quota_refusal"
    );
}

fn stored_messages(home: &Path, mailbox: &str) -> Vec<Vec<u8>> {
    assert!(matches!(
        mailbox,
        "" | ".OSMAP.Documents" | ".OSMAP.DocumentsBin"
    ));
    let mut result = Vec::new();
    for directory in ["cur", "new"] {
        for entry in fs::read_dir(home.join("Maildir").join(mailbox).join(directory)).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(
                metadata.is_file()
                    && metadata.uid() == QUOTA_UID
                    && metadata.len() <= u64::from(hard_bytes())
            );
            result.push(normalized(&fs::read(path).unwrap()));
        }
    }
    result
}

fn same_delivered_payload(actual: &[u8], expected: &[u8]) -> bool {
    let split = |bytes: &[u8]| bytes.windows(4).position(|p| p == b"\r\n\r\n");
    let (Some(a), Some(e)) = (split(actual), split(expected)) else {
        return false;
    };
    // LMTP adds Received/Return-Path/Delivered-To headers. Every original
    // controlled header and the complete body must survive unchanged.
    actual[a + 4..] == expected[e + 4..]
        && expected[..e].split(|b| *b == b'\n').all(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            actual[..a]
                .split(|b| *b == b'\n')
                .filter(|s| s.strip_suffix(b"\r").unwrap_or(s) == line)
                .count()
                == 1
        })
}

fn protocol_positive_and_refusal(
    executor: &ScopedExecutor,
    userdb: &Path,
    data: &Path,
    home: &Path,
) {
    for (id, protocol, mailbox, native_mailbox) in [
        (
            10,
            WireProtocol::Imap,
            "OSMAP.Documents",
            ".OSMAP.Documents",
        ),
        (11, WireProtocol::Lmtp, "INBOX", ""),
    ] {
        assert!(stored_messages(home, native_mailbox).is_empty());
        let message = quota_test_message("candidate", id, 4096);
        let done = protocol_write(executor, userdb, protocol, mailbox, &message);
        assert!(
            protocol_accepted(&done, protocol),
            "ffs stage=protocol_positive result=not_accepted"
        );
        let actual = stored_messages(home, native_mailbox);
        assert_eq!(actual.len(), 1);
        assert!(same_delivered_payload(&actual[0], &message));
        let fetched = native(
            executor,
            userdb,
            &["fetch", "-u", ACCOUNT, "text", "mailbox", mailbox, "all"],
            b"",
        );
        assert_eq!(fetched.status_code, 0);
        assert!(normalized(fetched.stdout.as_bytes())
            .windows(actual[0].len())
            .any(|s| s == actual[0]));
        println!(
            "native_ffs stage=protocol_positive protocol={} result=PASS stored_sha256={:x}",
            if id == 10 { "imap" } else { "lmtp" },
            Sha256::digest(&actual[0])
        );
        let oversized = quota_test_message("candidate", id + 10, hard_bytes() as usize + 8192);
        let refused = protocol_write(executor, userdb, protocol, mailbox, &oversized);
        assert_protocol_quota_refusal(&refused, protocol);
        assert_eq!(
            stored_messages(home, native_mailbox),
            actual,
            "ffs stage=protocol_refusal result=visible_mutation"
        );
        let _ = get_quota(data);
        assert_eq!(
            native(
                executor,
                userdb,
                &["expunge", "-u", ACCOUNT, "mailbox", mailbox, "all"],
                b""
            )
            .status_code,
            0
        );
        assert!(stored_messages(home, native_mailbox).is_empty());
    }
}

fn mixed_protocol_round(executor: &ScopedExecutor, userdb: &Path, data: &Path, home: &Path) {
    for mailbox in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"] {
        assert!(stored_messages(home, mailbox).is_empty());
    }
    let seed = quota_test_message("seed", 50, hard_bytes() as usize / 2);
    assert_eq!(
        native(
            executor,
            userdb,
            &["save", "-u", ACCOUNT, "-m", "INBOX"],
            &seed
        )
        .status_code,
        0
    );
    let messages: Vec<_> = (0..3)
        .map(|id| quota_test_message("candidate", id + 50, hard_bytes() as usize / 3))
        .collect();
    let outcomes = thread::scope(|scope| {
        let (ready, prepared) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        let mut releases = Vec::new();
        for (id, message) in messages.iter().enumerate() {
            let executor = executor.clone();
            let userdb = userdb.to_owned();
            let ready = ready.clone();
            let (release, start) = std::sync::mpsc::channel();
            releases.push(release);
            handles.push(scope.spawn(move || {
                ready.send(()).unwrap();
                start.recv_timeout(Duration::from_secs(2)).unwrap();
                match id {
                    0 => protocol_write(&executor, &userdb, WireProtocol::Lmtp, "INBOX", message),
                    1 => protocol_write(
                        &executor,
                        &userdb,
                        WireProtocol::Imap,
                        "OSMAP.Documents",
                        message,
                    ),
                    2 => native(
                        &executor,
                        &userdb,
                        &["save", "-u", ACCOUNT, "-m", "OSMAP.DocumentsBin"],
                        message,
                    ),
                    _ => unreachable!(),
                }
            }));
        }
        for _ in 0..3 {
            prepared.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        for release in releases {
            release.send(()).unwrap();
        }
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut total = 0;
    for (id, mailbox) in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"]
        .iter()
        .enumerate()
    {
        let accepted = match id {
            0 => protocol_accepted(&outcomes[id], WireProtocol::Lmtp),
            1 => protocol_accepted(&outcomes[id], WireProtocol::Imap),
            _ => outcomes[id].status_code == 0,
        };
        if !accepted {
            match id {
                0 => assert_protocol_quota_refusal(&outcomes[id], WireProtocol::Lmtp),
                1 => assert_protocol_quota_refusal(&outcomes[id], WireProtocol::Imap),
                _ => assert_native_quota_refusal(&outcomes[id]),
            }
        }
        let mut found = 0;
        for actual in stored_messages(home, mailbox) {
            if actual == seed {
                assert_eq!(id, 0);
                continue;
            }
            assert!(
                same_delivered_payload(&actual, &messages[id]),
                "ffs stage=mixed_reconcile result=unexpected_message"
            );
            if id != 0 {
                assert_eq!(actual, messages[id]);
            }
            println!(
                "native_ffs stage=mixed_stored writer={id} sha256={:x}",
                Sha256::digest(&actual)
            );
            found += 1;
        }
        assert_eq!(
            found,
            usize::from(accepted),
            "ffs stage=mixed_reconcile result=status_storage_mismatch"
        );
        total += found;
    }
    let quota = get_quota(data);
    assert!(
        total < 3,
        "ffs stage=mixed result=all_writes_unexpectedly_fit"
    );
    println!(
        "native_ffs stage=mixed_lmtp_imap_native result=PASS accepted={total} physical_bytes={} hard_bytes={} product_store=NOT_QUALIFIED",
        quota.blocks * BLOCK_BYTES,
        hard_bytes()
    );
    for mailbox in ["INBOX", "OSMAP.Documents", "OSMAP.DocumentsBin"] {
        assert_eq!(
            native(
                executor,
                userdb,
                &["expunge", "-u", ACCOUNT, "mailbox", mailbox, "all"],
                b""
            )
            .status_code,
            0
        );
    }
    let _ = get_quota(data);
}

#[test]
#[ignore = "non-root only, root-prepared isolated FFS hard quota"]
fn isolated_openbsd_ffs_native_writes() {
    let whole = Instant::now();
    assert_eq!(process_numeric_id("-u"), QUOTA_UID);
    assert!(
        hard_bytes() <= 1048576,
        "ffs stage=protocol_admission result=large_product_limit_refused"
    );
    let gid = process_numeric_id("-g");
    let before = standard_metadata();
    let base = fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q.");
    let data = checked_mount(&base);
    let home = data.join("foo");
    let owner = fs::symlink_metadata(&home).unwrap();
    assert!(owner.is_dir() && owner.uid() == QUOTA_UID && owner.mode() & 0o777 == 0o700);
    let root = fixture_path("OSMAP_FFS_CONTROL_ROOT", "osmap-documents-ffs-");
    let owner = fs::symlink_metadata(&root).unwrap();
    assert!(owner.is_dir() && owner.uid() == QUOTA_UID && owner.mode() & 0o777 == 0o700);
    assert_ne!(owner.dev(), fs::metadata(&data).unwrap().dev());
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
    for directory in ["run", "state", "alice", "index", "control"] {
        fs::create_dir(root.join(directory)).unwrap();
    }
    for mailbox in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"] {
        for directory in ["cur", "new", "tmp"] {
            fs::create_dir_all(home.join("Maildir").join(mailbox).join(directory)).unwrap();
        }
    }
    let userdb = fixture_userdb(&mut fixture, QUOTA_UID, gid);
    let config = root.join("dovecot.conf");
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:{1}/Maildir:INDEX={0}/index:CONTROL={0}/control\nmail_uid = 1000\nmail_gid = {2}\nfirst_valid_uid = 1000\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins = quota\npostmaster_address = postmaster@osmap.invalid\nlmtp_rcpt_check_quota = no\nplugin {{\n quota = fs:User quota:user:mount={3}\n}}\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display(), home.display(), gid, data.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let executor = ScopedExecutor {
        config,
        diagnostic: false,
    };
    let report = native(&executor, &userdb, &["quota", "get", "-u", ACCOUNT], b"");
    assert_eq!(
        report.status_code, 0,
        "ffs stage=native_quota result=refused"
    );
    assert!(report.stdout.contains("STORAGE"));
    protocol_positive_and_refusal(&executor, &userdb, &data, &home);
    let initial = get_quota(&data);
    let seed = quota_test_message("seed", 0, hard_bytes() as usize / 2);
    assert_eq!(
        native(
            &executor,
            &userdb,
            &["save", "-u", ACCOUNT, "-m", "INBOX"],
            &seed
        )
        .status_code,
        0,
        "ffs stage=serial_save result=refused"
    );
    let seed_quota = get_quota(&data);
    assert!(seed_quota.blocks > initial.blocks);
    let fetched = native(
        &executor,
        &userdb,
        &["fetch", "-u", ACCOUNT, "text", "mailbox", "INBOX", "all"],
        b"",
    );
    assert_eq!(fetched.status_code, 0);
    assert!(normalized(fetched.stdout.as_bytes())
        .windows(seed.len())
        .any(|part| part == seed));
    println!(
        "native_ffs stage=serial_save_fetch result=PASS physical_bytes={} hard_bytes={}",
        seed_quota.blocks * BLOCK_BYTES,
        hard_bytes()
    );
    let mailboxes = ["INBOX", "OSMAP.Documents", "OSMAP.DocumentsBin"];
    let messages: Vec<_> = (0..3)
        .map(|id| quota_test_message("candidate", id, hard_bytes() as usize / 3))
        .collect();
    let outcomes = thread::scope(|scope| {
        let (ready, prepared) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        let mut releases = Vec::new();
        for (id, mailbox) in mailboxes.iter().enumerate() {
            let executor = executor.clone();
            let userdb = userdb.clone();
            let message = &messages[id];
            let ready = ready.clone();
            let (release, start) = std::sync::mpsc::channel();
            releases.push(release);
            handles.push(scope.spawn(move || {
                ready.send(()).unwrap();
                start.recv_timeout(Duration::from_secs(2)).unwrap();
                native(
                    &executor,
                    &userdb,
                    &["save", "-u", ACCOUNT, "-m", mailbox],
                    message,
                )
            }));
        }
        for _ in 0..3 {
            prepared.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        for release in releases {
            release.send(()).unwrap();
        }
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut stored = 0;
    for outcome in &outcomes {
        if outcome.status_code != 0 {
            assert_native_quota_refusal(outcome);
        }
    }
    for (id, mailbox) in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"]
        .iter()
        .enumerate()
    {
        let mut found = 0;
        for directory in ["cur", "new"] {
            for entry in fs::read_dir(home.join("Maildir").join(mailbox).join(directory)).unwrap() {
                let path = entry.unwrap().path();
                let meta = fs::symlink_metadata(&path).unwrap();
                assert!(
                    meta.is_file()
                        && meta.uid() == QUOTA_UID
                        && meta.len() <= u64::from(hard_bytes())
                );
                let bytes = normalized(&fs::read(path).unwrap());
                if bytes == messages[id] {
                    found += 1;
                } else {
                    assert!(
                        id == 0 && bytes == seed,
                        "ffs stage=reconcile result=unexpected_message"
                    );
                }
            }
        }
        assert_eq!(
            found,
            usize::from(outcomes[id].status_code == 0),
            "ffs stage=reconcile result=status_storage_mismatch"
        );
        stored += found;
    }
    let quota = get_quota(&data);
    assert!(
        stored < 3,
        "ffs stage=concurrent result=all_writes_unexpectedly_fit"
    );
    println!(
        "native_ffs stage=three_native_saves result=PASS accepted={stored} physical_bytes={} hard_bytes={} all_protocols=NOT_QUALIFIED",
        quota.blocks * BLOCK_BYTES,
        hard_bytes()
    );
    for mailbox in mailboxes {
        assert_eq!(
            native(
                &executor,
                &userdb,
                &["expunge", "-u", ACCOUNT, "mailbox", mailbox, "all"],
                b""
            )
            .status_code,
            0
        );
    }
    let final_quota = get_quota(&data);
    assert!(final_quota.blocks < seed_quota.blocks);
    assert_eq!(
        native(
            &executor,
            &userdb,
            &["save", "-u", ACCOUNT, "-m", "INBOX"],
            &seed
        )
        .status_code,
        0,
        "ffs stage=recovered_capacity result=save_refused"
    );
    let fetched = native(
        &executor,
        &userdb,
        &["fetch", "-u", ACCOUNT, "text", "mailbox", "INBOX", "all"],
        b"",
    );
    assert_eq!(fetched.status_code, 0);
    assert!(normalized(fetched.stdout.as_bytes())
        .windows(seed.len())
        .any(|part| part == seed));
    assert_eq!(
        native(
            &executor,
            &userdb,
            &["expunge", "-u", ACCOUNT, "mailbox", "INBOX", "all"],
            b""
        )
        .status_code,
        0
    );
    let _ = get_quota(&data);
    println!("native_ffs stage=recovered_capacity result=PASS");
    mixed_protocol_round(&executor, &userdb, &data, &home);
    assert_eq!(before, standard_metadata());
    assert!(whole.elapsed() < NATIVE_LIMIT);
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists());
    println!(
        "native_ffs result=PASS control_cleanup=PASS volume_cleanup=ROOT_OWNED production_driver=NOT_ADMITTED"
    );
}

#[derive(Clone)]
struct ProductExecutor {
    scoped: ScopedExecutor,
    userdb_socket: PathBuf,
    diagnostics_root: PathBuf,
    worker_args: Vec<String>,
    wrong_worker_limit: bool,
    saves: Arc<std::sync::atomic::AtomicUsize>,
}

impl CommandExecutor for ProductExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("FFS product fixture requires bounded commands")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        cap: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert!(!timeout.is_zero() && timeout <= Duration::from_secs(5));
        let result = if program == "/usr/local/libexec/osmap/storage-quota" {
            assert_eq!(args, self.worker_args);
            assert!(input.is_empty() && cap <= 4096);
            let mut args = args.to_vec();
            if self.wrong_worker_limit {
                // Deliberately inject one mismatched finite expected limit
                // into the real read-only worker. No kernel limit is changed.
                args[2] = (u64::from(hard_bytes()) + 512).to_string();
            }
            SystemCommandExecutor
                .run_with_stdin_bytes_timeout_and_output_limit(program, &args, input, timeout, cap)
        } else if program == "/usr/local/bin/doveadm" && args.iter().any(|s| s == "user") {
            assert!(input.is_empty() && cap <= 4096);
            assert_eq!(args.len(), 8);
            assert_eq!(&args[..3], ["-o", "stats_writer_socket_path=", "-o"]);
            assert_eq!(
                args[3],
                format!("auth_socket_path={}", self.userdb_socket.display())
            );
            assert_eq!(&args[4..], ["-f", "json", "user", ACCOUNT]);
            let mut private = vec![
                "-c".into(),
                self.scoped.config.to_string_lossy().into_owned(),
            ];
            private.extend_from_slice(args);
            SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
                program, &private, input, timeout, cap,
            )
        } else {
            if args.iter().any(|s| s == "save") {
                self.saves.fetch_add(1, Ordering::SeqCst);
            }
            self.scoped
                .run_with_stdin_bytes_timeout_and_output_limit(program, args, input, timeout, cap)
        };
        let label = if program == "/usr/local/libexec/osmap/storage-quota" {
            if self.wrong_worker_limit {
                "worker-refused"
            } else {
                "worker"
            }
        } else {
            "native"
        };
        retain_response(&self.diagnostics_root, label, &result);
        if program == "/usr/local/libexec/osmap/storage-quota" && self.wrong_worker_limit {
            assert_eq!(
                result.as_ref().unwrap().status_code,
                1,
                "ffs product stage=wrong_limit_worker result=unexpected_status"
            );
        }
        result
    }
}

struct ProductFixture {
    fixture: Fixture,
    root: PathBuf,
    data: PathBuf,
    home: PathBuf,
    executor: ProductExecutor,
    userdb: PathBuf,
}

fn product_fixture() -> ProductFixture {
    product_fixture_with_reserved(true)
}

fn product_fixture_with_reserved(precreate_reserved: bool) -> ProductFixture {
    assert_eq!(process_numeric_id("-u"), QUOTA_UID);
    let gid = process_numeric_id("-g");
    let base = fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q.");
    let data = checked_mount(&base);
    let home = data.join("foo");
    let owner = fs::symlink_metadata(&home).unwrap();
    assert!(owner.is_dir() && owner.uid() == QUOTA_UID && owner.mode() & 0o777 == 0o700);
    let root = fixture_path("OSMAP_FFS_CONTROL_ROOT", "osmap-documents-ffs-");
    let owner = fs::symlink_metadata(&root).unwrap();
    assert!(owner.is_dir() && owner.uid() == QUOTA_UID && owner.mode() & 0o777 == 0o700);
    assert_ne!(owner.dev(), fs::metadata(&data).unwrap().dev());
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
    for directory in ["run", "state", "index", "control"] {
        fs::create_dir(root.join(directory)).unwrap();
    }
    for mailbox in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"] {
        if !precreate_reserved && !mailbox.is_empty() {
            assert!(
                !home.join("Maildir").join(mailbox).exists(),
                "ffs product stage=first_use result=reserved_path_already_exists"
            );
            continue;
        }
        for directory in ["cur", "new", "tmp"] {
            fs::create_dir_all(home.join("Maildir").join(mailbox).join(directory)).unwrap();
        }
        assert!(stored_messages(&home, mailbox).is_empty());
    }
    let mail = format!(
        "maildir:{}/Maildir:INDEX={}/index:CONTROL={}/control",
        home.display(),
        root.display(),
        root.display()
    );
    let userdb = fixture_userdb_with_fields(
        &mut fixture,
        QUOTA_UID,
        gid,
        home.clone(),
        vec![
            ("mail".into(), mail.clone()),
            (
                "quota".into(),
                format!("fs:User quota:user:mount={}", data.display()),
            ),
            ("quota_rule".into(), format!("*:bytes={}", hard_bytes())),
            (
                "osmap_quota_mount".into(),
                data.to_string_lossy().into_owned(),
            ),
            // The ordinary reporting scalar coexists with the independently
            // verified kernel limit and must not replace its authority.
            ("osmap_configured_quota".into(), "102400000".into()),
        ],
    );
    let config = root.join("dovecot.conf");
    // The effective per-account quota root comes only from userdb. No global
    // root is allowed to masquerade as an account-to-filesystem mapping.
    fs::write(&config, format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = {1}\nmail_uid = 1000\nmail_gid = {2}\nfirst_valid_uid = 1000\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins = quota\nplugin {{\n quota_grace = 0%\n}}\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator =\n}}\n", root.display(), mail, gid)).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let saves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = ProductExecutor {
        scoped: ScopedExecutor {
            config: config.clone(),
            diagnostic: false,
        },
        userdb_socket: userdb.clone(),
        diagnostics_root: root.clone(),
        worker_args: vec![
            home.to_string_lossy().into_owned(),
            QUOTA_UID.to_string(),
            hard_bytes().to_string(),
            data.to_string_lossy().into_owned(),
            root.join("index").to_string_lossy().into_owned(),
            root.join("control").to_string_lossy().into_owned(),
        ],
        wrong_worker_limit: false,
        saves: saves.clone(),
    };
    ProductFixture {
        fixture,
        root,
        data,
        home,
        executor,
        userdb,
    }
}

#[test]
#[ignore = "real Documents Store with installed read-only quota worker and prepared FFS"]
fn isolated_openbsd_ffs_documents_store() {
    let whole = Instant::now();
    let before = standard_metadata();
    let ProductFixture {
        mut fixture,
        root,
        data,
        home,
        executor,
        userdb,
    } = product_fixture_with_reserved(false);
    let config = executor.scoped.config.clone();
    let saves = executor.saves.clone();
    let backend = DoveadmDocumentsBackend::new(
        executor.clone(),
        "/usr/local/bin/doveadm",
        "/usr/local/bin/doveconf",
    )
    .with_userdb_socket_path(Some(userdb.clone()));
    let quota = backend
        .quota_status(ACCOUNT)
        .unwrap()
        .expect("ffs product stage=quota result=unavailable");
    assert_eq!(quota.limit_bytes, u64::from(hard_bytes()));
    assert_eq!(
        quota.used_bytes,
        u64::from(get_quota(&data).blocks) * u64::from(BLOCK_BYTES)
    );
    println!("native_ffs_product stage=real_kernel_authority result=PASS");
    // The synthetic userdb explicitly refuses every other canonical account.
    let foreign = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
        "/usr/local/bin/doveadm",
        &[
            "-c".into(),
            config.to_string_lossy().into_owned(),
            "-o".into(),
            format!("auth_socket_path={}", userdb.display()),
            "-f".into(),
            "json".into(),
            "user".into(),
            "bob@osmap-documents.invalid".into(),
        ],
        b"",
        Duration::from_secs(5),
        4096,
    );
    retain_response(&root, "native", &foreign);
    assert_ne!(
        foreign.unwrap().status_code,
        0,
        "ffs product stage=foreign_userdb result=unexpected_admission"
    );
    let store = Store::new(root.join("documents-index"), backend.clone());
    let payload = b"\x00\x01\xffnative-documents\n";
    let uploaded = store
        .upload(
            ACCOUNT,
            0,
            "native.bin",
            "application/octet-stream",
            payload,
            100,
        )
        .unwrap();
    assert_eq!(uploaded.documents.len(), 1);
    assert!(!uploaded.has_unconfirmed_change());
    assert!(home.join("Maildir/.OSMAP.Documents").is_dir());
    assert!(!home.join("Maildir/.OSMAP.DocumentsBin").exists());
    let id = uploaded.documents[0].id.clone();
    assert_eq!(
        store.download(ACCOUNT, &id).unwrap(),
        ("native.bin".into(), payload.to_vec())
    );
    assert_eq!(
        store.download("bob@osmap-documents.invalid", &id),
        Err(Error::NotFound)
    );
    let reopened = Store::new(root.join("documents-index"), backend.clone());
    assert_eq!(reopened.load(ACCOUNT).unwrap(), uploaded);
    assert_eq!(reopened.download(ACCOUNT, &id).unwrap().1, payload);
    let used_with_document = get_quota(&data).blocks;
    assert!(u64::from(used_with_document) * u64::from(BLOCK_BYTES) > quota.used_bytes);
    let folder = store
        .create_folder(ACCOUNT, uploaded.revision, "Project", 101)
        .unwrap();
    let folder_id = folder.folders[0].id.clone();
    let moved = store
        .move_to_folder(ACCOUNT, folder.revision, &id, &folder_id, 102)
        .unwrap();
    assert_eq!(moved.documents[0].folder, folder_id);
    let binned = store.bin(ACCOUNT, moved.revision, &id, 103).unwrap();
    assert_eq!(binned.documents[0].state, State::InBin);
    assert!(home.join("Maildir/.OSMAP.DocumentsBin").is_dir());
    let summary = binned.storage_summary(ACCOUNT).unwrap();
    assert_eq!(summary.used_bytes, payload.len() as u64);
    assert_eq!(summary.bin_bytes, payload.len() as u64);
    assert_eq!(store.download(ACCOUNT, &id), Err(Error::NotFound));
    assert_eq!(
        backend
            .read(ACCOUNT, &id, binned.documents[0].location.as_ref().unwrap())
            .unwrap(),
        payload
    );
    let restored = store.restore(ACCOUNT, binned.revision, &id, 104).unwrap();
    assert_eq!(restored.documents[0].state, State::Available);
    assert_eq!(store.download(ACCOUNT, &id).unwrap().1, payload);
    let binned = store.bin(ACCOUNT, restored.revision, &id, 105).unwrap();
    // First-use provisioning leaves the Bin's directory allocation charged.
    // Measure deletion against the complete current layout, not its earlier
    // state before the Bin existed.
    let used_before_delete = get_quota(&data).blocks;
    let deleted = store
        .delete_confirmed(ACCOUNT, binned.revision, &id, 106)
        .unwrap();
    assert!(deleted.documents.is_empty() && !deleted.has_unconfirmed_change());
    assert!(backend.inspect(ACCOUNT, &id).unwrap().is_empty());
    assert!(get_quota(&data).blocks < used_before_delete);
    println!(
        "native_ffs_product stage=upload_download_reload_folder_bin_restore_delete result=PASS"
    );
    let saved = saves.load(Ordering::SeqCst);
    let mut refused = executor;
    refused.wrong_worker_limit = true;
    let fault_backend =
        DoveadmDocumentsBackend::new(refused, "/usr/local/bin/doveadm", "/usr/local/bin/doveconf")
            .with_userdb_socket_path(Some(userdb));
    assert_eq!(fault_backend.quota_status(ACCOUNT), Ok(None));
    assert_eq!(store.load(ACCOUNT).unwrap(), deleted);
    assert_eq!(saves.load(Ordering::SeqCst), saved);
    let fault_store = Store::new(root.join("documents-index"), fault_backend);
    assert_eq!(
        fault_store.upload(
            ACCOUNT,
            deleted.revision,
            "refused.bin",
            "application/octet-stream",
            b"not dispatched",
            107
        ),
        Err(Error::PreDispatchUnavailable)
    );
    assert_eq!(saves.load(Ordering::SeqCst), saved);
    let settled = fault_store.load(ACCOUNT).unwrap();
    assert!(settled.documents.is_empty() && !settled.has_unconfirmed_change());
    assert!(stored_messages(&home, ".OSMAP.Documents").is_empty());
    println!(
        "native_ffs_product stage=real_worker_wrong_limit_refusal_no_save_no_pending result=PASS"
    );
    assert_eq!(before, standard_metadata());
    assert!(whole.elapsed() < NATIVE_LIMIT);
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists());
    println!("native_ffs_product result=PASS control_cleanup=PASS volume_cleanup=ROOT_OWNED");
}

struct NativeDocumentsServer {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl NativeDocumentsServer {
    fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            assert!(
                worker.join().is_ok(),
                "ffs helper stage=server result=worker_failed"
            );
        }
    }
}
impl Drop for NativeDocumentsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                println!("native_ffs_helper server_failure=RETAINED cleanup=NOT_CLAIMED");
            }
        }
    }
}

fn product_documents_server(
    root: &Path,
    native: Arc<DoveadmDocumentsBackend<ProductExecutor>>,
) -> (
    NativeDocumentsServer,
    PathBuf,
    PathBuf,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let socket = root.join("run/documents.sock");
    let key_path = root.join("run/grant.key");
    let key = b"native-Documents-fixture-key-not-a-production-credential-123";
    fs::write(&key_path, key).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let exchanges = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server_exchanges = exchanges.clone();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + NATIVE_LIMIT;
        let replay = std::sync::Mutex::new(std::collections::BTreeMap::new());
        while !server_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(stream) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => panic!("ffs helper stage=accept result=unavailable"),
            };
            crate::mailbox_helper::native_documents_test_stream(
                native.as_ref(),
                &mut stream,
                key,
                QUOTA_UID,
                &replay,
            )
            .unwrap();
            server_exchanges.fetch_add(1, Ordering::SeqCst);
        }
    });
    (
        NativeDocumentsServer {
            stop,
            worker: Some(worker),
        },
        socket,
        key_path,
        exchanges,
    )
}

#[test]
#[ignore = "actual authenticated Documents socket and native maximum-file Store journey"]
fn isolated_openbsd_ffs_documents_helper_maximum() {
    let whole = Instant::now();
    assert_eq!(hard_bytes(), 32 * 1024 * 1024);
    let before = standard_metadata();
    let ProductFixture {
        mut fixture,
        root,
        data,
        home,
        executor,
        userdb,
    } = product_fixture();
    let native = Arc::new(
        DoveadmDocumentsBackend::new(
            executor.clone(),
            "/usr/local/bin/doveadm",
            "/usr/local/bin/doveconf",
        )
        .with_userdb_socket_path(Some(userdb)),
    );
    let initial = native.quota_status(ACCOUNT).unwrap().unwrap();
    let (mut server, socket, key_path, exchanges) = product_documents_server(&root, native.clone());
    let client = crate::mailbox_helper::MailboxHelperDocumentsBackend::new(
        &socket,
        &key_path,
        crate::mailbox_helper::MailboxHelperPolicy::default(),
    )
    .with_helper_uid(QUOTA_UID);
    let store = Store::new(root.join("documents-index"), client.clone());
    assert_eq!(store.quota_status(ACCOUNT).unwrap(), Some(initial));
    let payload: Vec<u8> = (0..MAX_FILE_BYTES).map(|i| (i % 256) as u8).collect();
    let uploaded = store
        .upload(
            ACCOUNT,
            0,
            "maximum.bin",
            "application/octet-stream",
            &payload,
            100,
        )
        .unwrap();
    assert_eq!(uploaded.documents.len(), 1);
    assert_eq!(uploaded.documents[0].size, MAX_FILE_BYTES as u64);
    let id = uploaded.documents[0].id.clone();
    let downloaded = store.download(ACCOUNT, &id).unwrap();
    assert_eq!(downloaded.0, "maximum.bin");
    assert_eq!(downloaded.1, payload);
    assert_eq!(Sha256::digest(&downloaded.1), Sha256::digest(&payload));
    assert!(u64::from(get_quota(&data).blocks) * u64::from(BLOCK_BYTES) > initial.used_bytes);
    println!(
        "native_ffs_helper stage=maximum_upload_download result=PASS bytes={} sha256={:x}",
        MAX_FILE_BYTES,
        Sha256::digest(&payload)
    );
    let saved = executor.saves.load(Ordering::SeqCst);
    let mut oversized = payload.clone();
    oversized.push(0);
    assert_eq!(
        store.upload(
            ACCOUNT,
            uploaded.revision,
            "oversized.bin",
            "application/octet-stream",
            &oversized,
            101
        ),
        Err(Error::Invalid)
    );
    assert_eq!(executor.saves.load(Ordering::SeqCst), saved);
    assert_eq!(store.load(ACCOUNT).unwrap(), uploaded);
    assert_eq!(
        store.download("bob@osmap-documents.invalid", &id),
        Err(Error::NotFound)
    );
    let reopened = Store::new(root.join("documents-index"), client);
    assert_eq!(reopened.load(ACCOUNT).unwrap(), uploaded);
    let binned = reopened.bin(ACCOUNT, uploaded.revision, &id, 102).unwrap();
    assert_eq!(
        binned.storage_summary(ACCOUNT).unwrap().bin_bytes,
        MAX_FILE_BYTES as u64
    );
    let restored = reopened
        .restore(ACCOUNT, binned.revision, &id, 103)
        .unwrap();
    assert_eq!(reopened.download(ACCOUNT, &id).unwrap().1, payload);
    let binned = reopened.bin(ACCOUNT, restored.revision, &id, 104).unwrap();
    let deleted = reopened
        .delete_confirmed(ACCOUNT, binned.revision, &id, 105)
        .unwrap();
    assert!(deleted.documents.is_empty() && !deleted.has_unconfirmed_change());
    assert!(native.inspect(ACCOUNT, &id).unwrap().is_empty());
    assert!(stored_messages(&home, ".OSMAP.Documents").is_empty());
    assert!(stored_messages(&home, ".OSMAP.DocumentsBin").is_empty());
    assert!(u64::from(get_quota(&data).blocks) * u64::from(BLOCK_BYTES) < MAX_FILE_BYTES as u64);
    server.finish();
    assert!(exchanges.load(Ordering::SeqCst) >= 8);
    assert_eq!(before, standard_metadata());
    assert!(whole.elapsed() < NATIVE_LIMIT);
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists());
    println!(
        "native_ffs_helper result=PASS peer_uid_hmac_nonce=PRODUCTION_PATH maximum_bytes=10485760 control_cleanup=PASS volume_cleanup=ROOT_OWNED"
    );
}

// Admit only the single controlled Uploading record left by the failed maximum
// journey. This entry never calls upload/append or edits metadata by hand.
#[test]
#[ignore = "one-time native reconciliation of the retained maximum-file failure"]
fn isolated_openbsd_ffs_reconcile_retained_upload() {
    let whole = Instant::now();
    assert_eq!(process_numeric_id("-u"), QUOTA_UID);
    assert_eq!(hard_bytes(), 32 * 1024 * 1024);
    let before = standard_metadata();
    let data = checked_mount(&fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q."));
    let home = data.join("foo");
    let retained = fixture_path("OSMAP_FFS_CONTROL_ROOT", "osmap-documents-ffs-");
    for path in [
        home.clone(),
        retained.clone(),
        retained.join("documents-index"),
    ] {
        let owner = fs::symlink_metadata(&path).unwrap();
        assert!(owner.is_dir() && owner.uid() == QUOTA_UID && owner.mode() & 0o777 == 0o700);
        assert_eq!(fs::canonicalize(&path).unwrap(), path);
    }
    assert_ne!(
        fs::metadata(&retained).unwrap().dev(),
        fs::metadata(&data).unwrap().dev()
    );
    let config = retained.join("dovecot.conf");
    let owner = fs::symlink_metadata(&config).unwrap();
    assert!(
        owner.is_file()
            && owner.uid() == QUOTA_UID
            && owner.mode() & 0o777 == 0o600
            && owner.nlink() == 1
    );
    for directory in ["index", "control"] {
        let path = retained.join(directory);
        let owner = fs::symlink_metadata(&path).unwrap();
        assert!(owner.is_dir() && owner.uid() == QUOTA_UID);
        assert_eq!(owner.dev(), fs::metadata(&retained).unwrap().dev());
        assert_eq!(fs::canonicalize(&path).unwrap(), path);
    }

    // All new sockets and diagnostic responses go into a new private child.
    // Original failed-run sockets, configuration and responses remain intact.
    let root = retained.join("recovery");
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
    let userdb = fixture_userdb_with_fields(
        &mut fixture,
        QUOTA_UID,
        process_numeric_id("-g"),
        home.clone(),
        vec![
            (
                "mail".into(),
                format!(
                    "maildir:{}/Maildir:INDEX={}/index:CONTROL={}/control",
                    home.display(),
                    retained.display(),
                    retained.display()
                ),
            ),
            (
                "quota".into(),
                format!("fs:User quota:user:mount={}", data.display()),
            ),
            ("quota_rule".into(), format!("*:bytes={}", hard_bytes())),
            (
                "osmap_quota_mount".into(),
                data.to_string_lossy().into_owned(),
            ),
        ],
    );
    let saves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = ProductExecutor {
        scoped: ScopedExecutor {
            config,
            diagnostic: false,
        },
        userdb_socket: userdb.clone(),
        diagnostics_root: root.clone(),
        worker_args: vec![
            home.to_string_lossy().into_owned(),
            QUOTA_UID.to_string(),
            hard_bytes().to_string(),
            data.to_string_lossy().into_owned(),
            retained.join("index").to_string_lossy().into_owned(),
            retained.join("control").to_string_lossy().into_owned(),
        ],
        wrong_worker_limit: false,
        saves: saves.clone(),
    };
    let native = Arc::new(
        DoveadmDocumentsBackend::new(
            executor,
            "/usr/local/bin/doveadm",
            "/usr/local/bin/doveconf",
        )
        .with_userdb_socket_path(Some(userdb)),
    );
    assert_eq!(
        native.quota_status(ACCOUNT).unwrap().unwrap().limit_bytes,
        u64::from(hard_bytes())
    );
    let socket = root.join("documents.sock");
    let key_path = root.join("grant.key");
    let key = b"native-Documents-fixture-key-not-a-production-credential-123";
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap()
        .write_all(key)
        .unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let backend = native.clone();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + NATIVE_LIMIT;
        let replay = std::sync::Mutex::new(std::collections::BTreeMap::new());
        while !server_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(stream) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => panic!("ffs recovery stage=accept result=unavailable"),
            };
            crate::mailbox_helper::native_documents_test_stream(
                backend.as_ref(),
                &mut stream,
                key,
                QUOTA_UID,
                &replay,
            )
            .unwrap();
        }
    });
    let mut server = NativeDocumentsServer {
        stop,
        worker: Some(worker),
    };
    let client = crate::mailbox_helper::MailboxHelperDocumentsBackend::new(
        &socket,
        &key_path,
        crate::mailbox_helper::MailboxHelperPolicy::default(),
    )
    .with_helper_uid(QUOTA_UID);
    let store = Store::new(retained.join("documents-index"), client);
    let pending = store.load(ACCOUNT).unwrap();
    assert_eq!(pending.documents.len(), 1);
    let document = pending.documents[0].clone();
    let payload: Vec<u8> = (0..MAX_FILE_BYTES).map(|i| (i % 256) as u8).collect();
    let expected_hash = format!("{:x}", Sha256::digest(&payload));
    assert_eq!(document.state, State::Uploading);
    assert_eq!(document.name, "maximum.bin");
    assert_eq!(document.media_type, "application/octet-stream");
    assert_eq!(document.size, MAX_FILE_BYTES as u64);
    assert_eq!(document.sha256, expected_hash);
    assert_eq!(document.created_at, 100);
    assert_eq!(document.modified_at, 100);
    assert!(document.location.is_none() && document.binned_at.is_none());
    let snapshot = retained_native_snapshot(&home);
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].0, ".OSMAP.Documents");
    let locations = native.inspect(ACCOUNT, &document.id).unwrap();
    assert_eq!(locations.len(), 1);
    assert_eq!(locations[0].mailbox, "OSMAP.Documents");
    assert_eq!(
        store.reconcile(ACCOUNT, pending.revision, &document.id, 399),
        Err(Error::Busy)
    );
    assert_eq!(store.load(ACCOUNT).unwrap(), pending);
    let settled = store
        .reconcile(ACCOUNT, pending.revision, &document.id, 400)
        .unwrap();
    assert_eq!(settled.documents.len(), 1);
    assert_eq!(settled.documents[0].state, State::Available);
    assert_eq!(settled.documents[0].location.as_ref(), Some(&locations[0]));
    assert_eq!(settled.documents[0].sha256, expected_hash);
    assert_eq!(
        store.download(ACCOUNT, &document.id).unwrap(),
        ("maximum.bin".into(), payload)
    );
    assert_eq!(
        store.download("bob@osmap-documents.invalid", &document.id),
        Err(Error::NotFound)
    );
    assert_eq!(
        store.reconcile(ACCOUNT, pending.revision, &document.id, 401),
        Err(Error::Stale)
    );
    assert_eq!(retained_native_snapshot(&home), snapshot);
    assert_eq!(saves.load(Ordering::SeqCst), 0);
    println!(
        "native_ffs_recovery stage=reconcile result=PASS bytes={} sha256={} native_files=1 unchanged=PASS saves=0",
        MAX_FILE_BYTES, expected_hash
    );

    // Clean up through the existing confirmed Store lifecycle only after the
    // no-append, unchanged-native-byte proof has completed.
    let binned = store
        .bin(ACCOUNT, settled.revision, &document.id, 402)
        .unwrap();
    let deleted = store
        .delete_confirmed(ACCOUNT, binned.revision, &document.id, 403)
        .unwrap();
    assert!(deleted.documents.is_empty() && !deleted.has_unconfirmed_change());
    assert!(native.inspect(ACCOUNT, &document.id).unwrap().is_empty());
    assert!(retained_native_snapshot(&home).is_empty());
    assert_eq!(saves.load(Ordering::SeqCst), 0);
    get_quota(&data);
    server.finish();
    assert_eq!(before, standard_metadata());
    assert!(whole.elapsed() < NATIVE_LIMIT);
    let receipt = format!(
        "reconcile=PASS\nbytes={}\nsha256={}\nnative_files_before=1\nnative_files_after_reconcile=1\nnative_hashes_unchanged=PASS\nsaves=0\nconfirmed_bin_delete=PASS\nnative_files_after_cleanup=0\n",
        MAX_FILE_BYTES, expected_hash
    );
    let mut receipt_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(retained.join("recovery-receipt.txt"))
        .unwrap();
    receipt_file.write_all(receipt.as_bytes()).unwrap();
    receipt_file.sync_all().unwrap();
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists() && retained.is_dir());
    println!(
        "native_ffs_recovery result=PASS original_failure_evidence=RETAINED receipt=RETAINED recovery_control_cleanup=PASS native_message_cleanup=PASS"
    );
}

fn retained_native_snapshot(home: &Path) -> Vec<(String, u64, String)> {
    let mut result = Vec::new();
    for mailbox in ["", ".OSMAP.Documents", ".OSMAP.DocumentsBin"] {
        for directory in ["cur", "new"] {
            for entry in fs::read_dir(home.join("Maildir").join(mailbox).join(directory)).unwrap() {
                let path = entry.unwrap().path();
                let owner = fs::symlink_metadata(&path).unwrap();
                assert!(
                    owner.is_file()
                        && owner.uid() == QUOTA_UID
                        && owner.nlink() == 1
                        && owner.len() <= u64::from(hard_bytes())
                );
                result.push((
                    mailbox.into(),
                    owner.len(),
                    format!("{:x}", Sha256::digest(fs::read(path).unwrap())),
                ));
            }
        }
    }
    result.sort();
    result
}

const SEALED_CHILD: &str = "documents::native_tests::ffs::confined_quota_worker_child";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedInput {
    base: PathBuf,
    control: PathBuf,
    hard: u32,
}

#[test]
#[ignore = "child-only actual helper-mode OpenBSD seal; parent launches separately"]
fn confined_quota_worker_child() {
    assert_eq!(process_numeric_id("-u"), QUOTA_UID);
    let mut input = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut input).unwrap();
    assert!(input.len() <= 4096);
    let input: SealedInput = serde_json::from_slice(&input).unwrap();
    assert!(matches!(input.hard, 262144 | 1048576 | 33554432));
    let base = checked_fixture_path(input.base, "s8q.");
    let data = checked_mount(&base);
    let home = data.join("foo");
    let root = checked_fixture_path(input.control, "osmap-documents-ffs-");
    let expected = crate::documents_fs_quota::probe(
        &home,
        QUOTA_UID,
        u64::from(input.hard),
        &data,
        &root.join("index"),
        &root.join("control"),
    )
    .unwrap();
    let mut values = std::collections::BTreeMap::new();
    for (name, value) in [
        ("OSMAP_RUN_MODE", "mailbox-helper".into()),
        ("OSMAP_STATE_DIR", root.to_string_lossy().into_owned()),
        (
            "OSMAP_RUNTIME_DIR",
            root.join("run").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_DOVEADM_AUTH_SOCKET_PATH",
            root.join("auth-userdb").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_DOVEADM_USERDB_SOCKET_PATH",
            root.join("auth-userdb").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_SOCKET_PATH",
            root.join("run/helper.sock").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH",
            root.join("run/grant.key").to_string_lossy().into_owned(),
        ),
        ("OSMAP_TRUSTED_WEB_RUNTIME_UID", QUOTA_UID.to_string()),
        ("OSMAP_OPENBSD_CONFINEMENT_MODE", "enforce".into()),
    ] {
        values.insert(name.into(), value);
    }
    let config = crate::config::AppConfig::from_env_map(&values).unwrap();
    let plan = crate::openbsd::OpenbsdConfinementPlan::from_config(&config);
    assert!(plan.unveil_rules.iter().any(|r| r.path
        == Path::new("/usr/local/libexec/osmap/storage-quota")
        && r.permissions == "x"));
    let logger = crate::logging::Logger::new(
        crate::config::LogFormat::Text,
        crate::config::LogLevel::Info,
    );
    crate::openbsd::apply_runtime_confinement(&config, &logger).unwrap();
    println!("native_ffs_sealed stage=actual_helper_seal result=PASS");
    let mut args = vec![
        home.to_string_lossy().into_owned(),
        QUOTA_UID.to_string(),
        input.hard.to_string(),
        data.to_string_lossy().into_owned(),
        root.join("index").to_string_lossy().into_owned(),
        root.join("control").to_string_lossy().into_owned(),
    ];
    let valid = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/libexec/osmap/storage-quota",
            &args,
            b"",
            Duration::from_secs(5),
            4096,
        )
        .unwrap();
    assert_eq!(valid.status_code, 0, "ffs seal stage=worker result=refused");
    let quota: QuotaStatus = serde_json::from_str(&valid.stdout).unwrap();
    assert_eq!(quota.limit_bytes, expected.limit_bytes);
    assert_eq!(quota.used_bytes, expected.used_bytes);
    args[2] = (u64::from(input.hard) + 512).to_string();
    let invalid = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/libexec/osmap/storage-quota",
            &args,
            b"",
            Duration::from_secs(5),
            4096,
        )
        .unwrap();
    assert_eq!(invalid.status_code, 1);
    assert!(invalid.stdout.is_empty());
    println!("native_ffs_sealed stage=worker_valid_and_wrong_limit result=PASS");
}

#[test]
#[ignore = "launches a separate actual sealed helper-mode worker child"]
fn isolated_openbsd_ffs_helper_worker_confinement() {
    let whole = Instant::now();
    assert_eq!(process_numeric_id("-u"), QUOTA_UID);
    let base = fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q.");
    let data = checked_mount(&base);
    assert_eq!(
        fs::symlink_metadata(data.join("foo")).unwrap().uid(),
        QUOTA_UID
    );
    let root = fixture_path("OSMAP_FFS_CONTROL_ROOT", "osmap-documents-ffs-");
    let owner = fs::symlink_metadata(&root).unwrap();
    assert!(
        owner.is_dir()
            && owner.uid() == QUOTA_UID
            && owner.mode() & 0o777 == 0o700
            && owner.dev() != fs::metadata(data).unwrap().dev()
    );
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
    for dir in ["run", "index", "control"] {
        fs::create_dir(root.join(dir)).unwrap();
    }
    let listener = UnixListener::bind(root.join("auth-userdb")).unwrap();
    fs::write(
        root.join("run/grant.key"),
        b"sealed-Documents-fixture-key-not-production-123",
    )
    .unwrap();
    fs::set_permissions(
        root.join("run/grant.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let child = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
        std::env::current_exe().unwrap().to_str().unwrap(),
        &[
            "--exact".into(),
            SEALED_CHILD.into(),
            "--ignored".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        &serde_json::to_vec(&SealedInput {
            base,
            control: root.clone(),
            hard: hard_bytes(),
        })
        .unwrap(),
        Duration::from_secs(60),
        65536,
    );
    retain_response(&root, "native", &child);
    let child = child.unwrap();
    assert_eq!(child.status_code, 0, "ffs seal stage=child result=failed");
    for marker in [
        "native_ffs_sealed stage=actual_helper_seal result=PASS",
        "native_ffs_sealed stage=worker_valid_and_wrong_limit result=PASS",
    ] {
        assert!(child.stdout.contains(marker));
        println!("{marker}");
    }
    drop(listener);
    assert!(whole.elapsed() < NATIVE_LIMIT);
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists());
    println!(
        "native_ffs_sealed result=PASS child_exit=CONFIRMED control_cleanup=PASS volume_cleanup=ROOT_OWNED"
    );
}
