// Native Maildir migration sample only. No owner account or live configuration.
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

const FOLDERS: [&str; 3] = ["INBOX", "Projects", "Projects.Child"];

#[derive(PartialEq, Eq)]
struct Snapshot {
    mailboxes: BTreeMap<String, MailboxFacts>,
    messages: BTreeMap<(String, u64), MessageFacts>,
    subscriptions: BTreeSet<String>,
    raw: BTreeMap<(String, String), String>,
}

#[derive(PartialEq, Eq)]
struct MailboxFacts {
    guid: String,
    uidvalidity: u64,
    uidnext: u64,
    messages: u64,
}

#[derive(PartialEq, Eq)]
struct MessageFacts {
    mailbox_guid: String,
    guid: String,
    flags: BTreeSet<String>,
    received: u64,
}

struct Migration {
    executor: ScopedExecutor,
    userdb: PathBuf,
    root: PathBuf,
    destination: String,
    began: Instant,
    sequence: usize,
}

impl Migration {
    fn call(&mut self, stage: &str, target: bool, operation: &[&str]) -> CommandExecution {
        let remaining = NATIVE_LIMIT
            .checked_sub(self.began.elapsed())
            .expect("migration stage=deadline result=expired");
        let mut args = vec![
            "-o".into(),
            format!("auth_socket_path={}", self.userdb.display()),
        ];
        if target {
            args.extend(["-o".into(), format!("mail_location={}", self.destination)]);
        }
        args.extend(operation.iter().map(|value| (*value).to_owned()));
        let result = self.executor.run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/doveadm",
            &args,
            b"",
            remaining.min(Duration::from_secs(5)),
            32 * 1024,
        );
        self.sequence += 1;
        let prefix = format!("migration-command-{:03}", self.sequence);
        match &result {
            Ok(done) => {
                retain(
                    &self.root.join(format!("{prefix}.stdout")),
                    done.stdout.as_bytes(),
                );
                retain(
                    &self.root.join(format!("{prefix}.stderr")),
                    done.stderr.as_bytes(),
                );
                println!("native_maildir_migration stage={stage} command={} status={} stdout_bytes={} stderr_bytes={}",self.sequence,done.status_code,done.stdout.len(),done.stderr.len());
            }
            Err(error) => {
                retain(
                    &self.root.join(format!("{prefix}.transport")),
                    &error.reason.as_bytes()[..error.reason.len().min(4096)],
                );
                println!(
                    "native_maildir_migration stage={stage} command={} result=transport_unknown",
                    self.sequence
                );
            }
        }
        let done = result.expect("migration stage=native result=transport_unknown");
        assert_eq!(
            done.status_code, 0,
            "migration stage={stage} result=native_refusal"
        );
        done
    }

    fn snapshot(&mut self, target: bool, maildir: &Path) -> Snapshot {
        let status = self.call(
            "mailbox_status",
            target,
            &[
                "-f",
                "json",
                "mailbox",
                "status",
                "-u",
                ACCOUNT,
                "guid uidvalidity uidnext messages",
                "*",
            ],
        );
        let mut mailboxes = BTreeMap::new();
        for row in rows(&status.stdout) {
            let name = text(&row, "mailbox");
            assert!(FOLDERS.contains(&name.as_str()));
            let previous = mailboxes.insert(
                name,
                MailboxFacts {
                    guid: text(&row, "guid"),
                    uidvalidity: number(&row, "uidvalidity"),
                    uidnext: number(&row, "uidnext"),
                    messages: number(&row, "messages"),
                },
            );
            assert!(previous.is_none());
        }
        assert_eq!(mailboxes.len(), FOLDERS.len());
        let fetched = self.call(
            "message_facts",
            target,
            &[
                "-f",
                "json",
                "fetch",
                "-u",
                ACCOUNT,
                "mailbox uid mailbox-guid guid flags date.received.unixtime",
                "all",
            ],
        );
        let mut messages = BTreeMap::new();
        for row in rows(&fetched.stdout) {
            let name = text(&row, "mailbox");
            assert!(FOLDERS.contains(&name.as_str()));
            let uid = number(&row, "uid");
            assert!(uid > 0);
            let mailbox_guid = text(&row, "mailbox-guid");
            assert_eq!(mailbox_guid, mailboxes[&name].guid);
            let flags = text_or_empty(&row, "flags")
                .split_whitespace()
                .filter(|flag| !flag.eq_ignore_ascii_case("\\Recent"))
                .map(str::to_owned)
                .collect();
            assert!(messages
                .insert(
                    (name, uid),
                    MessageFacts {
                        mailbox_guid,
                        guid: text(&row, "guid"),
                        flags,
                        received: number(&row, "date.received.unixtime")
                    }
                )
                .is_none());
        }
        assert_eq!(
            mailboxes.values().map(|row| row.messages).sum::<u64>(),
            messages.len() as u64
        );
        let subscribed = self.call(
            "subscriptions",
            target,
            &["mailbox", "list", "-s", "-u", ACCOUNT],
        );
        let subscriptions = subscribed
            .stdout
            .lines()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert!(subscriptions
            .iter()
            .all(|name| FOLDERS.contains(&name.as_str())));
        let mut raw = BTreeMap::new();
        for folder in FOLDERS {
            let path = if folder == "INBOX" {
                maildir.to_owned()
            } else {
                maildir.join(format!(".{folder}"))
            };
            for directory in ["cur", "new"] {
                for entry in fs::read_dir(path.join(directory)).unwrap() {
                    let path = entry.unwrap().path();
                    let metadata = fs::symlink_metadata(&path).unwrap();
                    assert!(metadata.is_file() && metadata.uid() == 1000 && metadata.len() <= 4096);
                    let bytes = fs::read(path).unwrap();
                    let value = std::str::from_utf8(&bytes).unwrap();
                    let message_id = value
                        .lines()
                        .find_map(|line| line.strip_prefix("Message-ID: "))
                        .unwrap()
                        .trim()
                        .to_owned();
                    assert!(
                        message_id.starts_with("<osmap-migration-")
                            && message_id.ends_with("@example.invalid>")
                    );
                    assert!(raw
                        .insert(
                            (folder.to_owned(), message_id),
                            format!("{:x}", Sha256::digest(&bytes))
                        )
                        .is_none());
                }
            }
        }
        assert_eq!(raw.len(), messages.len());
        Snapshot {
            mailboxes,
            messages,
            subscriptions,
            raw,
        }
    }
}

fn retain(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn rows(value: &str) -> Vec<Value> {
    let rows: Vec<Value> =
        serde_json::from_str(value).expect("migration stage=json result=invalid");
    assert!(rows.len() <= 16);
    rows
}

fn text_or_empty(row: &Value, key: &str) -> String {
    let value = row
        .get(key)
        .and_then(Value::as_str)
        .expect("migration stage=facts result=missing_text");
    assert!(value.len() <= 512 && !value.chars().any(char::is_control));
    value.to_owned()
}

fn text(row: &Value, key: &str) -> String {
    let value = text_or_empty(row, key);
    assert!(!value.is_empty());
    value
}

fn number(row: &Value, key: &str) -> u64 {
    let value = row
        .get(key)
        .expect("migration stage=facts result=missing_number");
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .expect("migration stage=facts result=invalid_number")
}

fn add_message(maildir: &Path, folder: &str, id: u64) {
    let folder = if folder == "INBOX" {
        maildir.to_owned()
    } else {
        maildir.join(format!(".{folder}"))
    };
    let path = folder
        .join("new")
        .join(format!("1700000000.M{id}P1.osmap-migration"));
    let bytes = format!(concat!(
        "From: local@example.invalid\r\nTo: {account}\r\nMessage-ID: <osmap-migration-{id}@example.invalid>\r\n",
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=migration\r\n\r\n",
        "--migration\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
        "Controlled caf=C3=A9 sample {id}.\r\n--migration\r\nContent-Type: application/octet-stream\r\n",
        "Content-Transfer-Encoding: base64\r\n\r\nAAH/\r\n--migration--\r\n"
    ),account=ACCOUNT,id=id);
    // Native Maildir saves use LF storage on this fixture. The MIME payload is
    // encoded, so this is an exact stored-byte migration check of that profile.
    let bytes = bytes.replace("\r\n", "\n");
    retain(&path, bytes.as_bytes());
    // Set the controlled Maildir INTERNALDATE before Dovecot first sees it;
    // no 2.4-only doveadm save -r option or control-file editing is needed.
    File::open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_600_000_000 + id))
        .unwrap();
}

fn lease(root: PathBuf) -> Fixture {
    let metadata = fs::symlink_metadata(&root).unwrap();
    assert!(metadata.is_dir() && metadata.uid() == 1000 && metadata.mode() & 0o777 == 0o700);
    Fixture {
        root,
        root_lease: (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o777,
        ),
        stop: Arc::new(AtomicBool::new(false)),
        userdb: None,
        retain_on_failure: true,
    }
}

#[test]
#[ignore = "non-root disposable FFS and private Dovecot Maildir migration only"]
fn isolated_openbsd_maildir_backup_preserves_identity() {
    let began = Instant::now();
    assert_eq!(process_numeric_id("-u"), 1000);
    let gid = process_numeric_id("-g");
    let before = standard_metadata();
    let base = super::ffs::fixture_path("OSMAP_FFS_FIXTURE_ROOT", "s8q.");
    let data = super::ffs::checked_mount(&base);
    let root = super::ffs::fixture_path("OSMAP_FFS_CONTROL_ROOT", "osmap-documents-ffs-");
    assert!(fs::read_dir(&root).unwrap().next().is_none());
    let mut fixture = lease(root.clone());
    assert_ne!(
        fs::metadata(&root).unwrap().dev(),
        fs::metadata(&data).unwrap().dev()
    );
    let destination_home = data.join("foo/Migration");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination_home)
        .unwrap();
    let mut destination_lease = lease(destination_home.clone());
    let source = root.join("alice/Maildir");
    for directory in [
        "run",
        "state",
        "alice/Maildir/cur",
        "alice/Maildir/new",
        "alice/Maildir/tmp",
        "destination-index",
        "destination-control",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    let index = root.join("destination-index");
    let control = root.join("destination-control");
    crate::documents_fs_quota::probe(
        &destination_home,
        1000,
        u64::from(super::ffs::hard_bytes()),
        &data,
        &index,
        &control,
    )
    .expect("migration stage=mount_admission result=refused");
    let config = root.join("migration.conf");
    fs::write(&config,format!("base_dir = {0}/run\nstate_dir = {0}/state\nmail_location = maildir:~/Maildir\nmail_uid = 1000\nmail_gid = {gid}\nfirst_valid_uid = 1000\nprotocols =\nlisten = 127.0.0.1\nssl = no\nmail_plugins =\nstats_writer_socket_path =\nauth_socket_path = {0}/never-default\nlog_path = {0}/native.log\ninfo_log_path = {0}/native.log\nnamespace inbox {{\n inbox = yes\n separator = .\n}}\n",root.display())).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let userdb = fixture_userdb(&mut fixture, 1000, gid);
    let destination = format!(
        "maildir:{}/Maildir:INDEX={}:CONTROL={}",
        destination_home.display(),
        index.display(),
        control.display()
    );
    let mut migration = Migration {
        executor: ScopedExecutor {
            config,
            diagnostic: false,
        },
        userdb,
        root: root.clone(),
        destination,
        began,
        sequence: 0,
    };
    migration.call(
        "create_source",
        false,
        &[
            "mailbox",
            "create",
            "-u",
            ACCOUNT,
            "Projects",
            "Projects.Child",
        ],
    );
    for id in 1..=3 {
        add_message(&source, "INBOX", id);
    }
    add_message(&source, "Projects.Child", 4);
    let initial = migration.snapshot(false, &source);
    assert_eq!(initial.messages.len(), 4);
    let inbox_uids = initial
        .messages
        .keys()
        .filter(|(name, _)| name == "INBOX")
        .map(|(_, uid)| *uid)
        .collect::<Vec<_>>();
    let first = inbox_uids[0].to_string();
    let middle = inbox_uids[1].to_string();
    let last = inbox_uids[2].to_string();
    migration.call(
        "source_uid_gap",
        false,
        &["expunge", "-u", ACCOUNT, "mailbox", "INBOX", "uid", &middle],
    );
    migration.call(
        "source_flags",
        false,
        &[
            "flags",
            "replace",
            "-u",
            ACCOUNT,
            "\\Seen \\Flagged UATKeyword",
            "mailbox",
            "INBOX",
            "uid",
            &first,
        ],
    );
    migration.call(
        "source_subscription",
        false,
        &["mailbox", "subscribe", "-u", ACCOUNT, "Projects.Child"],
    );
    let first_source = migration.snapshot(false, &source);
    assert_eq!(first_source.messages.len(), 3);
    assert!(first_source
        .messages
        .values()
        .any(|row| row.flags.contains("UATKeyword")));
    assert!(first_source
        .messages
        .values()
        .all(|row| row.received >= 1_600_000_000 && row.received <= 1_600_000_010));
    let location = migration.destination.clone();
    migration.call(
        "first_backup",
        false,
        &["backup", "-u", ACCOUNT, "-l", "2", &location],
    );
    let target = destination_home.join("Maildir");
    assert!(
        first_source == migration.snapshot(true, &target),
        "migration stage=first_backup result=identity_or_bytes_mismatch"
    );
    assert!(
        first_source == migration.snapshot(false, &source),
        "migration stage=first_backup result=source_changed"
    );
    for (kind, expected) in [("index", &index), ("control", &control)] {
        let path = migration.call(
            "external_metadata",
            true,
            &["mailbox", "path", "-u", ACCOUNT, "-t", kind, "INBOX"],
        );
        let path = PathBuf::from(path.stdout.trim());
        assert_eq!(fs::canonicalize(&path).unwrap(), path);
        assert!(path.starts_with(expected));
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_dir() && metadata.uid() == 1000);
        assert_eq!(metadata.dev(), fs::metadata(&root).unwrap().dev());
    }
    println!("native_maildir_migration stage=first_backup identities_flags_dates_subscriptions_raw_bytes=PASS");

    add_message(&source, "Projects.Child", 5);
    migration.call(
        "delta_flags",
        false,
        &[
            "flags",
            "replace",
            "-u",
            ACCOUNT,
            "\\Answered UATKeyword",
            "mailbox",
            "INBOX",
            "uid",
            &first,
        ],
    );
    migration.call(
        "delta_expunge",
        false,
        &["expunge", "-u", ACCOUNT, "mailbox", "INBOX", "uid", &last],
    );
    migration.call(
        "delta_subscription",
        false,
        &["mailbox", "subscribe", "-u", ACCOUNT, "Projects"],
    );
    let second_source = migration.snapshot(false, &source);
    assert!(first_source != second_source);
    migration.call(
        "second_backup",
        false,
        &["backup", "-u", ACCOUNT, "-l", "2", &location],
    );
    assert!(
        second_source == migration.snapshot(true, &target),
        "migration stage=second_backup result=identity_or_bytes_mismatch"
    );
    assert!(
        second_source == migration.snapshot(false, &source),
        "migration stage=second_backup result=source_changed"
    );
    println!(
        "native_maildir_migration stage=second_backup append_expunge_flag_subscription_delta=PASS"
    );
    assert_eq!(standard_metadata(), before);
    assert!(began.elapsed() < NATIVE_LIMIT);
    destination_lease.retain_on_failure = false;
    drop(destination_lease);
    assert!(!destination_home.exists());
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists());
    println!("native_maildir_migration result=PASS owned_cleanup=PASS owner_data=NOT_ACCESSED");
}
