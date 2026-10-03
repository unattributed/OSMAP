use super::*;
use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
use crate::message_metadata::MessageVersion;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

const ACCOUNT: &str = "alice@example.test";
const FOLDER: &str = "Deleted";
const REVISION: u64 = 9;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct PolicyFixture {
    root: std::path::PathBuf,
    path: std::path::PathBuf,
}
impl PolicyFixture {
    fn new() -> Self {
        // The aggregate gate may deliberately use a writable TMPDIR ancestor.
        // Exercise the actual trusted-path provider in owned sticky-root scratch.
        let root = fs::canonicalize("/tmp").unwrap().join(format!(
            "osmap-delete-backend-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            path: root.join("retention.json"),
            root,
        };
        fixture.write(ACCOUNT, FOLDER, REVISION, "allowed");
        fixture
    }
    fn write(&self, account: &str, mailbox: &str, revision: u64, permission: &str) {
        fs::write(
            &self.path,
            policy_bytes(account, mailbox, revision, permission),
        )
        .unwrap();
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn provider(&self) -> FileMailboxRetentionPolicy {
        FileMailboxRetentionPolicy::new(Some(self.path.clone()), crate::openbsd::effective_uid())
    }
}
impl Drop for PolicyFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn policy_bytes(account: &str, mailbox: &str, revision: u64, permission: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":1,"rules":[{"account":account,"mailbox_name":mailbox,"revision":revision,"permanent_delete":permission}]})).unwrap()
}
fn version() -> MessageVersion {
    MessageVersion::new("a".repeat(32), "message-7".into()).unwrap()
}
fn request() -> MessageDeleteRequest {
    MessageDeleteRequest::new(ACCOUNT, FOLDER, 7, version(), REVISION).unwrap()
}
fn row(mailbox: &str, uid: &str, mailbox_guid: &str, guid: &str) -> serde_json::Value {
    serde_json::json!({"uid":uid,"flags":"\\Seen \\Flagged","date.received":"2026-10-03 00:00:00","size.virtual":"32","mailbox":mailbox,"mailbox-guid":mailbox_guid,"guid":guid})
}
fn current() -> CommandExecution {
    ok(serde_json::to_string(&vec![row(FOLDER, "7", &"a".repeat(32), "message-7")]).unwrap())
}
fn ok(text: impl Into<String>) -> CommandExecution {
    CommandExecution {
        status_code: 0,
        stdout: text.into(),
        stderr: String::new(),
    }
}
struct Step {
    result: Result<CommandExecution, CommandExecutionError>,
    rewrite: Option<(std::path::PathBuf, Vec<u8>)>,
    delay: std::time::Duration,
}
impl Step {
    fn reply(reply: CommandExecution) -> Self {
        Self {
            result: Ok(reply),
            rewrite: None,
            delay: std::time::Duration::ZERO,
        }
    }
    fn failure() -> Self {
        Self {
            result: Err(CommandExecutionError {
                reason: "synthetic timeout or lost reply".into(),
            }),
            rewrite: None,
            delay: std::time::Duration::ZERO,
        }
    }
}
struct Call {
    program: String,
    args: Vec<String>,
    timeout: std::time::Duration,
    output_limit: usize,
}
struct Executor {
    steps: RefCell<VecDeque<Step>>,
    calls: RefCell<Vec<Call>>,
}
impl Executor {
    fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: RefCell::new(steps.into_iter().collect()),
            calls: RefCell::new(vec![]),
        }
    }
    fn expunge_count(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "expunge"))
            .count()
    }
}
impl CommandExecutor for &Executor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("delete must use bounded native execution")
    }
    fn run_with_stdin_bytes_timeout(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
        _: std::time::Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("delete must bound native output as well as time")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: std::time::Duration,
        output_limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert!(input.is_empty());
        assert!(
            timeout > std::time::Duration::ZERO && timeout <= std::time::Duration::from_secs(3)
        );
        assert!(
            output_limit > 0
                && output_limit <= crate::auth::DEFAULT_EXTERNAL_COMMAND_OUTPUT_MAX_BYTES
        );
        self.calls.borrow_mut().push(Call {
            program: program.into(),
            args: args.to_vec(),
            timeout,
            output_limit,
        });
        let step = self
            .steps
            .borrow_mut()
            .pop_front()
            .expect("unexpected native command/retry");
        if let Some((path, bytes)) = step.rewrite {
            fs::write(path, bytes).unwrap();
        }
        if !step.delay.is_zero() {
            std::thread::sleep(step.delay);
        }
        step.result
    }
}
fn backend<'a>(
    executor: &'a Executor,
    fixture: &PolicyFixture,
) -> DoveadmMessageDeleteBackend<&'a Executor> {
    DoveadmMessageDeleteBackend::new(executor, "/usr/local/bin/doveadm", fixture.provider())
}

#[test]
fn actual_permitted_file_policy_deletes_exact_tuple_once_and_confirms_absence() {
    let fixture = PolicyFixture::new();
    let mut first = Step::reply(current());
    first.delay = std::time::Duration::from_millis(12);
    let executor = Executor::new([first, Step::reply(ok("")), Step::reply(ok("[]"))]);
    let before = fs::read(&fixture.path).unwrap();
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
        Ok(MessageDeleteResult::Deleted)
    );
    assert_eq!(executor.expunge_count(), 1);
    assert_eq!(executor.calls.borrow().len(), 3);
    assert!(executor.steps.borrow().is_empty());
    let calls = executor.calls.borrow();
    let tuple = vec![
        "mailbox".to_string(),
        FOLDER.into(),
        "mailbox-guid".into(),
        "a".repeat(32),
        "uid".into(),
        "7".into(),
        "guid".into(),
        "message-7".into(),
    ];
    for call in calls.iter() {
        assert_eq!(call.program, "/usr/local/bin/doveadm");
        assert!(call.args.ends_with(&tuple));
        assert!(call.args.windows(2).any(|w| w == ["-u", ACCOUNT]));
        assert!(!call.args.iter().any(|a| matches!(
            a.as_str(),
            "-A" | "-F" | "-c" | "all" | "OR" | "move" | "save"
        )));
        assert!(call.output_limit <= crate::auth::DEFAULT_EXTERNAL_COMMAND_OUTPUT_MAX_BYTES);
    }
    assert_eq!(
        calls[1].args,
        [
            vec![
                "-o".into(),
                "stats_writer_socket_path=".into(),
                "expunge".into(),
                "-u".into(),
                ACCOUNT.into()
            ],
            tuple
        ]
        .concat()
    );
    assert!(calls[1].timeout < calls[0].timeout);
    assert!(calls[2].timeout <= calls[1].timeout);
    assert_eq!(fs::read(&fixture.path).unwrap(), before);
}

#[test]
fn denied_absent_corrupt_foreign_or_insecure_policy_never_invokes_expunge() {
    for variant in 0..6 {
        let fixture = PolicyFixture::new();
        match variant {
            0 => fixture.write(ACCOUNT, FOLDER, REVISION, "denied"),
            1 => {
                fs::remove_file(&fixture.path).unwrap();
            }
            2 => {
                fs::write(&fixture.path, b"broken JSON").unwrap();
            }
            3 => fixture.write("bob@example.test", FOLDER, REVISION, "allowed"),
            4 => {
                fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o666)).unwrap();
            }
            5 => fixture.write(ACCOUNT, "Trash", REVISION, "allowed"),
            _ => unreachable!(),
        }
        let executor = Executor::new([Step::reply(current())]);
        let result = backend(&executor, &fixture).delete_message(ACCOUNT, &request());
        assert!(matches!(
            result,
            Err(MessageDeleteError::PolicyDenied | MessageDeleteError::PolicyUnavailable)
        ));
        assert_eq!(executor.expunge_count(), 0);
    }
}

#[test]
fn changed_policy_revision_or_revocation_during_read_refuses_before_mutation() {
    for permission in ["allowed", "denied"] {
        let fixture = PolicyFixture::new();
        let mut first = Step::reply(current());
        first.rewrite = Some((
            fixture.path.clone(),
            policy_bytes(ACCOUNT, FOLDER, REVISION + 1, permission),
        ));
        let executor = Executor::new([first]);
        let result = backend(&executor, &fixture).delete_message(ACCOUNT, &request());
        assert!(matches!(
            result,
            Err(MessageDeleteError::Stale | MessageDeleteError::PolicyDenied)
        ));
        assert_eq!(executor.expunge_count(), 0);
    }
    let fixture = PolicyFixture::new();
    fixture.write(ACCOUNT, FOLDER, REVISION + 1, "allowed");
    let executor = Executor::new([Step::reply(current())]);
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Stale)
    );
    assert_eq!(executor.expunge_count(), 0);
}

#[test]
fn stale_duplicate_foreign_folder_and_inconsistent_snapshot_never_expunge() {
    let matching = row(FOLDER, "7", &"a".repeat(32), "message-7");
    for response in [
        "[]".into(),
        serde_json::to_string(&vec![matching.clone(), matching]).unwrap(),
        serde_json::to_string(&vec![row("Trash", "7", &"a".repeat(32), "message-7")]).unwrap(),
        serde_json::to_string(&vec![row(FOLDER, "8", &"a".repeat(32), "message-7")]).unwrap(),
        serde_json::to_string(&vec![row(FOLDER, "7", &"b".repeat(32), "message-7")]).unwrap(),
        serde_json::to_string(&vec![row(FOLDER, "7", &"a".repeat(32), "foreign-message")]).unwrap(),
        serde_json::to_string(&vec![row(FOLDER, "07", &"a".repeat(32), "message-7")]).unwrap(),
        "[{\"uid\":\"7\",\"mailbox\":\"Deleted\"}]".into(),
        "not JSON".into(),
    ] {
        let fixture = PolicyFixture::new();
        let executor = Executor::new([Step::reply(ok(response))]);
        assert!(matches!(
            backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
            Err(MessageDeleteError::Stale
                | MessageDeleteError::Unavailable
                | MessageDeleteError::Invalid)
        ));
        assert_eq!(executor.expunge_count(), 0);
        assert_eq!(executor.calls.borrow().len(), 1);
    }
}

#[test]
fn dispatched_failure_or_uncertain_confirmation_is_unknown_and_not_retried() {
    let outcomes = [
        vec![Step::reply(current()), Step::failure()],
        vec![
            Step::reply(current()),
            Step::reply(CommandExecution {
                status_code: 1,
                stdout: "".into(),
                stderr: "public synthetic diagnostic".into(),
            }),
        ],
        vec![Step::reply(current()), Step::reply(ok("")), Step::failure()],
        vec![
            Step::reply(current()),
            Step::reply(ok("")),
            Step::reply(current()),
        ],
        vec![
            Step::reply(current()),
            Step::reply(ok("")),
            Step::reply(ok("broken JSON")),
        ],
        vec![
            Step::reply(current()),
            Step::reply(ok("")),
            Step::reply(ok(serde_json::to_string(&vec![row(
                FOLDER,
                "8",
                &"a".repeat(32),
                "neighbour-8",
            )])
            .unwrap())),
        ],
    ];
    for steps in outcomes {
        let fixture = PolicyFixture::new();
        let executor = Executor::new(steps);
        assert_eq!(
            backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
            Err(MessageDeleteError::Unknown)
        );
        assert_eq!(executor.expunge_count(), 1);
        assert!(executor.steps.borrow().is_empty());
    }
}

#[test]
fn source_read_failure_is_unavailable_before_dispatch_and_budget_is_absolute() {
    let fixture = PolicyFixture::new();
    let executor = Executor::new([Step::failure()]);
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Unavailable)
    );
    assert_eq!(executor.expunge_count(), 0);
    let mut delayed = Step::reply(current());
    delayed.delay = std::time::Duration::from_millis(1100);
    let executor = Executor::new([delayed]);
    assert_eq!(
        backend(&executor, &fixture)
            .with_command_timeout_secs(1)
            .delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Unavailable)
    );
    assert_eq!(executor.expunge_count(), 0);
    assert_eq!(executor.calls.borrow().len(), 1);
}

#[test]
fn foreign_account_and_occupied_mutation_gate_do_not_reach_native_executor() {
    let fixture = PolicyFixture::new();
    let executor = Executor::new([]);
    assert_eq!(
        backend(&executor, &fixture).delete_message("bob@example.test", &request()),
        Err(MessageDeleteError::Invalid)
    );
    let gate = std::sync::Arc::new(std::sync::Mutex::new(()));
    let guard = gate.lock().unwrap();
    assert_eq!(
        backend(&executor, &fixture)
            .with_operation_gate(gate.clone())
            .delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Busy)
    );
    drop(guard);
    assert!(executor.calls.borrow().is_empty());
}

#[test]
fn invalid_request_fields_cannot_become_native_selection() {
    for uid in [0, u64::from(u32::MAX) + 1] {
        assert!(MessageDeleteRequest::new(ACCOUNT, FOLDER, uid, version(), REVISION).is_err());
    }
    for account in ["", "alice\n@example.test", "*@example.test"] {
        assert!(MessageDeleteRequest::new(account, FOLDER, 7, version(), REVISION).is_err());
    }
    for folder in ["", "Deleted\n"] {
        assert!(MessageDeleteRequest::new(ACCOUNT, folder, 7, version(), REVISION).is_err());
    }
    assert!(MessageDeleteRequest::new(ACCOUNT, FOLDER, 7, version(), 0).is_err());
    let invalid = MessageVersion {
        mailbox_guid: "bad".into(),
        message_guid: "message-7".into(),
    };
    assert!(MessageDeleteRequest::new(ACCOUNT, FOLDER, 7, invalid, REVISION).is_err());
}

#[test]
fn literal_glob_and_shell_like_folder_names_still_require_complete_guid_tuple() {
    let fixture = PolicyFixture::new();
    let folder = "Deleted*?;$(id)";
    fixture.write(ACCOUNT, folder, REVISION, "allowed");
    let request = MessageDeleteRequest::new(ACCOUNT, folder, 7, version(), REVISION).unwrap();
    let response =
        ok(serde_json::to_string(&vec![row(folder, "7", &"a".repeat(32), "message-7")]).unwrap());
    let executor = Executor::new([
        Step::reply(response),
        Step::reply(ok("")),
        Step::reply(ok("[]")),
    ]);
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &request),
        Ok(MessageDeleteResult::Deleted)
    );
    for call in executor.calls.borrow().iter() {
        assert_eq!(call.program, "/usr/local/bin/doveadm");
        let complete = vec![
            "mailbox".to_string(),
            folder.into(),
            "mailbox-guid".into(),
            "a".repeat(32),
            "uid".into(),
            "7".into(),
            "guid".into(),
            "message-7".into(),
        ];
        assert!(call.args.ends_with(&complete));
        assert_eq!(
            call.args
                .iter()
                .filter(|arg| arg.as_str() == folder)
                .count(),
            1
        );
    }
    for response in [
        row("DeletedOther", "7", &"a".repeat(32), "message-7"),
        row(folder, "7", &"b".repeat(32), "message-7"),
    ] {
        let executor = Executor::new([Step::reply(ok(
            serde_json::to_string(&vec![response]).unwrap()
        ))]);
        assert_eq!(
            backend(&executor, &fixture).delete_message(ACCOUNT, &request),
            Err(MessageDeleteError::Stale)
        );
        assert_eq!(executor.expunge_count(), 0);
    }
}

#[derive(Clone, Debug, PartialEq)]
struct StoredRow {
    account: String,
    data: serde_json::Value,
}
struct PreservingExecutor {
    rows: RefCell<Vec<StoredRow>>,
    calls: RefCell<Vec<Vec<String>>>,
}
impl CommandExecutor for &PreservingExecutor {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("unbounded command")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: std::time::Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, "/usr/local/bin/doveadm");
        assert!(
            input.is_empty()
                && timeout > std::time::Duration::ZERO
                && timeout <= std::time::Duration::from_secs(3)
        );
        assert!(limit > 0 && limit <= crate::auth::DEFAULT_EXTERNAL_COMMAND_OUTPUT_MAX_BYTES);
        assert!(!args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-A" | "-F" | "all" | "OR")));
        let value = |key: &str| {
            let positions: Vec<_> = args
                .iter()
                .enumerate()
                .filter(|(_, arg)| arg.as_str() == key)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(
                positions.len(),
                1,
                "selection must include each identity exactly once"
            );
            args[positions[0] + 1].as_str()
        };
        let account = value("-u");
        let mailbox = value("mailbox");
        let mailbox_guid = value("mailbox-guid");
        let uid = value("uid");
        let guid = value("guid");
        let matches = |row: &StoredRow| {
            row.account == account
                && row.data["mailbox"] == mailbox
                && row.data["mailbox-guid"] == mailbox_guid
                && row.data["uid"] == uid
                && row.data["guid"] == guid
        };
        self.calls.borrow_mut().push(args.to_vec());
        if args.iter().any(|arg| arg == "expunge") {
            self.rows.borrow_mut().retain(|row| !matches(row));
            Ok(ok(""))
        } else {
            assert!(args.iter().any(|arg| arg == "fetch"));
            let result: Vec<_> = self
                .rows
                .borrow()
                .iter()
                .filter(|row| matches(row))
                .map(|row| row.data.clone())
                .collect();
            Ok(ok(serde_json::to_string(&result).unwrap()))
        }
    }
}

#[test]
fn exact_account_folder_uid_and_guid_selection_preserves_neighbour_and_foreign_records() {
    let fixture = PolicyFixture::new();
    let neighbour = StoredRow {
        account: ACCOUNT.into(),
        data: row(FOLDER, "8", &"a".repeat(32), "neighbour-8"),
    };
    let foreign = StoredRow {
        account: "bob@example.test".into(),
        data: row(FOLDER, "7", &"b".repeat(32), "message-7"),
    };
    let other_folder = StoredRow {
        account: ACCOUNT.into(),
        data: row("AnotherDeleted", "7", &"c".repeat(32), "message-7"),
    };
    let preserved = vec![neighbour, foreign, other_folder];
    let mut rows = preserved.clone();
    rows.push(StoredRow {
        account: ACCOUNT.into(),
        data: row(FOLDER, "7", &"a".repeat(32), "message-7"),
    });
    let executor = PreservingExecutor {
        rows: RefCell::new(rows),
        calls: RefCell::new(vec![]),
    };
    let backend =
        DoveadmMessageDeleteBackend::new(&executor, "/usr/local/bin/doveadm", fixture.provider());
    assert_eq!(
        backend.delete_message(ACCOUNT, &request()),
        Ok(MessageDeleteResult::Deleted)
    );
    assert_eq!(*executor.rows.borrow(), preserved);
    assert_eq!(
        executor
            .calls
            .borrow()
            .iter()
            .filter(|args| args.iter().any(|arg| arg == "expunge"))
            .count(),
        1
    );
    // A duplicate explicit attempt sees the authoritative absence and cannot
    // issue another expunge, even though its policy revision remains valid.
    assert_eq!(
        backend.delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Stale)
    );
    assert_eq!(*executor.rows.borrow(), preserved);
    assert_eq!(
        executor
            .calls
            .borrow()
            .iter()
            .filter(|args| args.iter().any(|arg| arg == "expunge"))
            .count(),
        1
    );
}

#[test]
fn native_output_limits_refuse_before_dispatch_or_report_unknown_after_dispatch() {
    let fixture = PolicyFixture::new();
    let pre = CommandExecution {
        status_code: 0,
        stdout: current().stdout,
        stderr: "x".repeat(64 * 1024 + 1),
    };
    let executor = Executor::new([Step::reply(pre)]);
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Unavailable)
    );
    assert_eq!(executor.expunge_count(), 0);
    let dispatched = CommandExecution {
        status_code: 0,
        stdout: "x".repeat(64 * 1024 + 1),
        stderr: String::new(),
    };
    let executor = Executor::new([Step::reply(current()), Step::reply(dispatched)]);
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &request()),
        Err(MessageDeleteError::Unknown)
    );
    assert_eq!(executor.expunge_count(), 1);
    assert!(executor.steps.borrow().is_empty());
}

#[test]
fn public_request_fields_are_revalidated_before_any_native_call() {
    let fixture = PolicyFixture::new();
    let executor = Executor::new([]);
    let mut tampered = request();
    tampered.uid = 0;
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &tampered),
        Err(MessageDeleteError::Invalid)
    );
    let mut tampered = request();
    tampered.version.mailbox_guid = "not-a-guid".into();
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &tampered),
        Err(MessageDeleteError::Invalid)
    );
    let mut tampered = request();
    tampered.canonical_username = "bob@example.test".into();
    assert_eq!(
        backend(&executor, &fixture).delete_message(ACCOUNT, &tampered),
        Err(MessageDeleteError::Invalid)
    );
    assert!(executor.calls.borrow().is_empty());
}
