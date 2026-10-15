use super::*;
use crate::{
    auth::{CommandExecution, CommandExecutionError},
    folder_rename::Completion,
    mailbox::{MailboxBackendError, MailboxEntry},
    mailbox_status::MailboxStatus,
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    rc::Rc,
};
const ALICE: &str = "alice@fixture.test";
#[derive(Clone, PartialEq, Eq, Debug)]
struct Container {
    guid: String,
    body: Vec<u8>,
}
struct State {
    folders: RefCell<BTreeMap<String, Container>>,
    calls: RefCell<Vec<(String, String)>>,
    original_error: Cell<bool>,
    recovery_error: Cell<bool>,
    measured_reaped_error: Cell<bool>,
    original_noop: Cell<bool>,
    original_source: RefCell<String>,
    original_destination: RefCell<String>,
}
#[derive(Clone)]
struct Exec(Rc<State>);
impl Exec {
    fn wire(&self) -> String {
        let folders = self.0.folders.borrow();
        let mut names: BTreeSet<_> = folders.keys().cloned().collect();
        for name in folders.keys() {
            let mut parent = name.as_str();
            while let Some((next, _)) = parent.rsplit_once('.') {
                names.insert(next.into());
                parent = next;
            }
        }
        let mut wire =
            "* PREAUTH fixture\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n".to_owned();
        for name in names {
            let children = folders.keys().any(|n| n.starts_with(&format!("{name}.")));
            wire.push_str(&format!(
                "* LIST ({}) \".\" {name}\r\n",
                if name == "Trash" {
                    "\\Trash"
                } else if !folders.contains_key(&name) {
                    "\\Noselect \\HasChildren"
                } else if children {
                    "\\HasChildren"
                } else {
                    "\\HasNoChildren"
                }
            ));
        }
        wire.push_str("L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n");
        wire
    }
    fn status(&self, name: &str) -> Result<MailboxStatus, MailboxBackendError> {
        let folders = self.0.folders.borrow();
        let row = folders
            .get(name)
            .ok_or_else(crate::mailbox_status::unavailable)?;
        MailboxStatus::new(name, &row.guid, 1, row.body.len() as u64)
    }
}
impl CommandExecutor for Exec {
    fn run_folder_mutation(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> crate::auth::FolderCommandAttempt {
        let result = self
            .run_with_stdin_bytes_timeout_and_output_limit(program, args, input, timeout, limit);
        crate::auth::FolderCommandAttempt {
            settled: result.is_ok() || self.0.measured_reaped_error.get(),
            result,
        }
    }
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("bounded only")
    }
    fn run_with_stdin_bytes_timeout_and_output_limit(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, "/fixed/doveadm");
        assert!(timeout <= Duration::from_secs(10));
        let pos = args.iter().position(|a| a == "-u").unwrap();
        assert_eq!(args[pos + 1], ALICE);
        let stdout = if args.first().is_some_and(|a| a == "exec") {
            assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
            self.wire()
        } else if args.windows(2).any(|p| p == ["mailbox", "rename"]) {
            assert!(input.is_empty());
            assert_eq!(limit, 4096);
            let source = &args[pos + 2];
            let target = &args[pos + 3];
            let original_source = self.0.original_source.borrow().clone();
            let original_destination = self.0.original_destination.borrow().clone();
            let suffix = source.strip_prefix(&original_source).unwrap();
            assert!(matches!(suffix, "" | ".Child" | ".Other"));
            assert_eq!(target, &format!("{original_destination}{suffix}"));
            let root_command = source == &original_source;
            self.0
                .calls
                .borrow_mut()
                .push((source.clone(), target.clone()));
            let keys: Vec<_> = self
                .0
                .folders
                .borrow()
                .keys()
                .filter(|name| {
                    !self.0.original_noop.get() && name.as_str() == source
                        || !root_command && name.starts_with(&format!("{source}."))
                })
                .cloned()
                .collect();
            for old in keys {
                let row = self.0.folders.borrow_mut().remove(&old).unwrap();
                let new = format!("{target}{}", old.strip_prefix(source).unwrap());
                assert!(self.0.folders.borrow_mut().insert(new, row).is_none());
            }
            if root_command && self.0.original_error.get()
                || !root_command && self.0.recovery_error.get()
            {
                return Err(CommandExecutionError {
                    reason: "synthetic unconfirmed native lifecycle".into(),
                });
            }
            return Ok(CommandExecution {
                status_code: if root_command { 75 } else { 0 },
                stdout: String::new(),
                stderr: String::new(),
            });
        } else {
            assert!(input.is_empty());
            let name = args.last().unwrap();
            match self.status(name) {
                Ok(s) => serde_json::json!([{"mailbox":name,"guid":s.guid(),"messages":"1","vsize":s.virtual_bytes().to_string()}]).to_string(),
                Err(_) => "[]".into(),
            }
        };
        Ok(CommandExecution {
            status_code: 0,
            stdout,
            stderr: String::new(),
        })
    }
}
struct Backend {
    helper: PathBuf,
    exec: Exec,
}
impl MailboxBackend for Backend {
    fn list_mailboxes(&self, _: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        Ok(vec![])
    }
    fn folder_metadata(
        &self,
        account: &str,
    ) -> Result<crate::folder_metadata::FolderSnapshot, MailboxBackendError> {
        if account != ALICE {
            return Err(crate::folder_metadata_backend::unavailable());
        }
        crate::folder_metadata::FolderSnapshot::parse(account, self.exec.wire().as_bytes())
            .map_err(|_| crate::folder_metadata_backend::unavailable())
    }
    fn mailbox_status(
        &self,
        account: &str,
        name: &str,
    ) -> Result<MailboxStatus, MailboxBackendError> {
        if account != ALICE {
            return Err(crate::mailbox_status::unavailable());
        }
        self.exec.status(name)
    }
    fn rename_folder_attempt(&self, request: &RenameFolderRequest) -> NativeAttempt {
        crate::folder_rename_backend::rename_attempt(
            &self.exec,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            request,
        )
    }
    fn rename_folder(&self, request: &RenameFolderRequest) -> Outcome {
        crate::mailbox_helper::mailbox_helper_rename::execute(&self.helper, self, request)
    }
    fn folder_rename_completion(&self, request: &RenameFolderRequest) -> Completion {
        crate::mailbox_helper::mailbox_helper_rename::completion(&self.helper, request)
    }
    fn recover_folder_subtree(&self, permit: &RecoveryPermit<'_>) -> NativeRecoveryAttempt {
        native_recover(
            &self.exec,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            permit,
        )
    }
}
struct Fixture {
    root: PathBuf,
    backend: Backend,
    original: RenameFolderRequest,
    before: BTreeMap<String, Container>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-subtree-recovery-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut folders = BTreeMap::new();
        for (name, guid) in [
            ("INBOX", "b"),
            ("INBOX.Alpha", "a"),
            ("INBOX.Alpha.Child", "e"),
            ("INBOX.Alpha.Child.Grand", "f"),
            ("INBOX.Alpha.Other", "9"),
        ] {
            folders.insert(
                name.into(),
                Container {
                    guid: guid.repeat(32),
                    body: b"synthetic complete email including attachment \0\x01\xff".to_vec(),
                },
            );
        }
        let before = folders.clone();
        let exec = Exec(Rc::new(State {
            folders: RefCell::new(folders),
            calls: RefCell::new(vec![]),
            original_error: Cell::new(false),
            recovery_error: Cell::new(false),
            measured_reaped_error: Cell::new(false),
            original_noop: Cell::new(false),
            original_source: RefCell::new("INBOX.Alpha".into()),
            original_destination: RefCell::new("INBOX.Beta".into()),
        }));
        let backend = Backend {
            helper: root.join("helper"),
            exec,
        };
        let original = RenameFolderRequest::new(
            ALICE,
            "INBOX.Alpha",
            &"a".repeat(32),
            &"b".repeat(32),
            "Beta",
        )
        .unwrap()
        .bind_subtree(&backend)
        .unwrap();
        Self {
            root,
            backend,
            original,
            before,
        }
    }
    fn start(&self) {
        let mut role = crate::folder_rename::settings_gate(&self.root, ALICE).unwrap();
        role.begin(&self.original).unwrap();
        drop(role);
        assert_eq!(self.backend.rename_folder(&self.original), Outcome::Unknown);
        assert_eq!(self.backend.exec.0.calls.borrow().len(), 1);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn subtree_recovery_bin_restore_settles_exact_receipt_and_descendant_labels_snooze() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let mut f = Fixture::new();
    f.backend.exec.0.folders.borrow_mut().insert(
        "Trash".into(),
        Container {
            guid: "d".repeat(32),
            body: vec![],
        },
    );
    f.original =
        crate::folder_disposition::prepare_bin(&f.root, &f.backend, ALICE, "INBOX.Alpha").unwrap();
    *f.backend.exec.0.original_destination.borrow_mut() = f.original.destination();
    let labels = crate::labels::LabelStore::new(f.root.join("labels-v1"));
    let created = labels
        .change(
            ALICE,
            0,
            crate::labels::LabelChange::Create("Preserved child"),
        )
        .unwrap();
    let id = created.labels()[0].id().to_owned();
    let mut row = crate::mailbox::MessageSummary {
        uid: 1,
        mailbox_name: "INBOX.Alpha.Child".into(),
        to: None,
        flags: vec![],
        date_received: String::new(),
        size_virtual: 50,
        subject: None,
        from: None,
        metadata: Some(crate::message_metadata::MessageMetadata {
            threading: None,
            attachments: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
            version: crate::message_metadata::MessageVersion::new(
                "e".repeat(32),
                "original-child-message".into(),
            )
            .unwrap(),
            attachment_count: Some(1),
            preview: None,
        }),
    };
    labels
        .change(
            ALICE,
            created.revision(),
            crate::labels::LabelChange::Attach {
                id: &id,
                message: &crate::labels::MessageIdentity::from_summary(
                    ALICE,
                    ALICE,
                    &row.mailbox_name,
                    &row,
                )
                .unwrap(),
            },
        )
        .unwrap();
    let snooze = crate::snooze::SnoozeStore::new(&f.root);
    snooze
        .set(
            ALICE,
            &crate::snooze::MessageIdentity::from_summary(ALICE, ALICE, &row.mailbox_name, &row)
                .unwrap(),
            0,
            700,
            100,
        )
        .unwrap();
    let bob_labels = labels.load("bob@fixture.test").unwrap();
    let bob_snooze = snooze.load("bob@fixture.test", 100).unwrap();
    assert_eq!(
        crate::folder_disposition::execute(&f.root, &f.backend, &f.original, 100),
        Outcome::Unknown
    );
    for digit in ["1", "2"] {
        assert_eq!(
            recover(&f.root, &f.backend, ALICE, &digit.repeat(32)),
            RecoveryOutcome::Progress
        );
    }
    assert!(matches!(
        crate::folder_disposition::check(&f.root, &f.backend, ALICE),
        crate::folder_rename::CheckOutcome::Renamed { .. }
    ));
    let receipt = crate::folder_disposition::list(&f.root, ALICE)
        .unwrap()
        .remove(0);
    assert_eq!(receipt.state, crate::folder_disposition::State::Binned);
    row.mailbox_name = format!("{}.Child", receipt.stored_name());
    assert_eq!(
        labels
            .load(ALICE)
            .unwrap()
            .labels_for(
                &crate::labels::MessageIdentity::from_summary(
                    ALICE,
                    ALICE,
                    &row.mailbox_name,
                    &row
                )
                .unwrap()
            )
            .unwrap()[0]
            .id(),
        id
    );
    assert_eq!(
        snooze.load(ALICE, 100).unwrap().markers()[0]
            .identity()
            .folder(),
        row.mailbox_name
    );
    let restore = receipt.restore_request(ALICE).unwrap();
    *f.backend.exec.0.original_source.borrow_mut() = restore.source().into();
    *f.backend.exec.0.original_destination.borrow_mut() = restore.destination();
    assert_eq!(
        crate::folder_disposition::execute(&f.root, &f.backend, &restore, 100),
        Outcome::Unknown
    );
    for digit in ["3", "4"] {
        assert_eq!(
            recover(&f.root, &f.backend, ALICE, &digit.repeat(32)),
            RecoveryOutcome::Progress
        );
    }
    assert!(matches!(
        crate::folder_disposition::check(&f.root, &f.backend, ALICE),
        crate::folder_rename::CheckOutcome::Renamed { .. }
    ));
    assert!(crate::folder_disposition::list(&f.root, ALICE)
        .unwrap()
        .is_empty());
    for suffix in ["", ".Child", ".Child.Grand", ".Other"] {
        assert_eq!(
            f.backend.exec.0.folders.borrow()[&format!("INBOX.Alpha{suffix}")],
            f.before[&format!("INBOX.Alpha{suffix}")]
        );
    }
    row.mailbox_name = "INBOX.Alpha.Child".into();
    assert_eq!(
        labels
            .load(ALICE)
            .unwrap()
            .labels_for(
                &crate::labels::MessageIdentity::from_summary(
                    ALICE,
                    ALICE,
                    &row.mailbox_name,
                    &row
                )
                .unwrap()
            )
            .unwrap()[0]
            .id(),
        id
    );
    assert_eq!(
        snooze.load(ALICE, 100).unwrap().markers()[0]
            .identity()
            .folder(),
        row.mailbox_name
    );
    assert_eq!(labels.load("bob@fixture.test").unwrap(), bob_labels);
    assert_eq!(snooze.load("bob@fixture.test", 100).unwrap(), bob_snooze);
    let calls = f.backend.exec.0.calls.borrow();
    assert_eq!(calls.len(), 6);
    assert_eq!(
        calls
            .iter()
            .filter(|(source, _)| source == "INBOX.Alpha")
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|(source, _)| source == &receipt.stored_name())
            .count(),
        1
    );
}

#[test]
fn subtree_recovery_completes_only_original_children_and_replay_never_repeats_root() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.start();
    assert_eq!(placement(&f.backend, &f.original).unwrap().old.len(), 3);
    let first = "1".repeat(32);
    let second = "2".repeat(32);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &first),
        RecoveryOutcome::Progress
    );
    assert_eq!(
        placement(&f.backend, &f.original).unwrap().old,
        vec![".Other"]
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 2);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &first),
        RecoveryOutcome::Progress
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 2);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &second),
        RecoveryOutcome::Progress
    );
    assert!(placement(&f.backend, &f.original).unwrap().old.is_empty());
    assert_eq!(
        f.backend.folder_rename_completion(&f.original),
        Completion::Renamed
    );
    assert!(crate::folder_rename::confirmed_settled_result(
        &f.backend,
        &f.original,
        &f.backend.folder_metadata(ALICE).unwrap(),
        &f.backend.mailbox_status(ALICE, "INBOX.Beta").unwrap(),
        &f.backend.mailbox_status(ALICE, "INBOX").unwrap(),
    ));
    assert_eq!(
        *f.backend.exec.0.calls.borrow(),
        vec![
            ("INBOX.Alpha".into(), "INBOX.Beta".into()),
            ("INBOX.Alpha.Child".into(), "INBOX.Beta.Child".into()),
            ("INBOX.Alpha.Other".into(), "INBOX.Beta.Other".into())
        ]
    );
    for suffix in ["", ".Child", ".Child.Grand", ".Other"] {
        assert_eq!(
            f.backend.exec.0.folders.borrow()[&format!("INBOX.Beta{suffix}")],
            f.before[&format!("INBOX.Alpha{suffix}")]
        );
    }
    assert_eq!(
        f.backend.exec.0.folders.borrow()["INBOX"],
        f.before["INBOX"]
    );
    crate::folder_rename::reconcile_metadata(&f.root, &f.original).unwrap();
    let mut role = crate::folder_rename::role_lease(&f.root, ALICE).unwrap();
    role.confirm().unwrap();
}

#[test]
fn subtree_recovery_refuses_unsettled_original_or_step_and_does_not_retry() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.backend.exec.0.original_error.set(true);
    f.start();
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &"1".repeat(32)),
        RecoveryOutcome::Refused
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
    let g = Fixture::new();
    g.start();
    g.backend.exec.0.recovery_error.set(true);
    let nonce = "1".repeat(32);
    assert_eq!(
        recover(&g.root, &g.backend, ALICE, &nonce),
        RecoveryOutcome::Unknown
    );
    assert_eq!(
        recover(&g.root, &g.backend, ALICE, &nonce),
        RecoveryOutcome::Unknown
    );
    assert_eq!(
        recover(&g.root, &g.backend, ALICE, &"2".repeat(32)),
        RecoveryOutcome::Unknown
    );
    assert_eq!(g.backend.exec.0.calls.borrow().len(), 2);
    assert!(crate::folder_rename::role_lease(&g.root, ALICE)
        .unwrap()
        .recovery()
        .is_some());
}

#[test]
fn subtree_recovery_injected_before_witness_retains_operation_mail_indexes_across_restart() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.start();
    // INJECTED stop boundary, not an actual process crash: consumed original
    // request survives but no outcome/native-settlement witness was published.
    let store = crate::private_account_file::PrivateAccountFile::new(
        f.backend.helper.clone(),
        "osmap-folder-rename-helper-v1",
        4096,
    );
    let original_record =
        serde_json::to_vec(&serde_json::json!({"version":1,"request":f.original,"outcome":null}))
            .unwrap();
    store.lock(ALICE).unwrap().write(&original_record).unwrap();
    let labels = crate::labels::LabelStore::new(f.root.join("labels-v1"));
    let created = labels
        .change(
            ALICE,
            0,
            crate::labels::LabelChange::Create("Retained original index"),
        )
        .unwrap();
    let row = crate::mailbox::MessageSummary {
        uid: 1,
        mailbox_name: "INBOX.Alpha.Child".into(),
        to: None,
        flags: vec![],
        date_received: String::new(),
        size_virtual: 50,
        subject: None,
        from: None,
        metadata: Some(crate::message_metadata::MessageMetadata {
            threading: None,
            attachments: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
            version: crate::message_metadata::MessageVersion::new(
                "e".repeat(32),
                "retained-child-message".into(),
            )
            .unwrap(),
            attachment_count: Some(1),
            preview: None,
        }),
    };
    labels
        .change(
            ALICE,
            created.revision(),
            crate::labels::LabelChange::Attach {
                id: created.labels()[0].id(),
                message: &crate::labels::MessageIdentity::from_summary(
                    ALICE,
                    ALICE,
                    &row.mailbox_name,
                    &row,
                )
                .unwrap(),
            },
        )
        .unwrap();
    labels
        .change(
            "bob@fixture.test",
            0,
            crate::labels::LabelChange::Create("Bob retained"),
        )
        .unwrap();
    let alice_labels = labels.load(ALICE).unwrap();
    let bob_labels = labels.load("bob@fixture.test").unwrap();
    let snooze = crate::snooze::SnoozeStore::new(&f.root);
    snooze
        .set(
            ALICE,
            &crate::snooze::MessageIdentity::from_summary(ALICE, ALICE, &row.mailbox_name, &row)
                .unwrap(),
            0,
            700,
            100,
        )
        .unwrap();
    let alice_snooze = snooze.load(ALICE, 100).unwrap();
    let bob_snooze = snooze.load("bob@fixture.test", 100).unwrap();
    let partial = f.backend.exec.0.folders.borrow().clone();
    for digit in ["1", "2"] {
        // Reconstruct the backend and account role from persisted state. No
        // in-memory cache or prior process result can supply settlement.
        let restarted = Backend {
            helper: f.backend.helper.clone(),
            exec: f.backend.exec.clone(),
        };
        assert_eq!(restarted.rename_folder(&f.original), Outcome::Unknown);
        assert_eq!(
            recover(&f.root, &restarted, ALICE, &digit.repeat(32)),
            RecoveryOutcome::Refused
        );
        assert_eq!(
            restarted.folder_rename_completion(&f.original),
            Completion::Unconfirmed
        );
        assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
        assert_eq!(*f.backend.exec.0.folders.borrow(), partial);
        assert_eq!(store.read(ALICE).unwrap().unwrap(), original_record);
        let role = crate::folder_rename::role_lease(&f.root, ALICE).unwrap();
        assert_eq!(role.pending(), Some(&f.original));
        assert!(role.recovery().is_none());
        assert!(
            crate::folder_rename::role_lease(&f.root, "bob@fixture.test")
                .unwrap()
                .pending()
                .is_none()
        );
    }
    // Even a later fully placed GUID snapshot is not a durable child witness.
    {
        let mut folders = f.backend.exec.0.folders.borrow_mut();
        for suffix in [".Child", ".Child.Grand", ".Other"] {
            let row = folders.remove(&format!("INBOX.Alpha{suffix}")).unwrap();
            folders.insert(format!("INBOX.Beta{suffix}"), row);
        }
    }
    let snapshot = f.backend.folder_metadata(ALICE).unwrap();
    let destination = f.backend.mailbox_status(ALICE, "INBOX.Beta").unwrap();
    let parent = f.backend.mailbox_status(ALICE, "INBOX").unwrap();
    assert!(crate::folder_rename::confirmed_result(
        &f.original,
        &snapshot,
        &destination,
        &parent
    ));
    assert!(!crate::folder_rename::confirmed_settled_result(
        &f.backend,
        &f.original,
        &snapshot,
        &destination,
        &parent
    ));
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
    assert_eq!(store.read(ALICE).unwrap().unwrap(), original_record);
    assert_eq!(labels.load(ALICE).unwrap(), alice_labels);
    assert_eq!(labels.load("bob@fixture.test").unwrap(), bob_labels);
    assert_eq!(snooze.load(ALICE, 100).unwrap(), alice_snooze);
    assert_eq!(snooze.load("bob@fixture.test", 100).unwrap(), bob_snooze);
    for suffix in ["", ".Child", ".Child.Grand", ".Other"] {
        assert_eq!(
            f.backend.exec.0.folders.borrow()[&format!("INBOX.Beta{suffix}")],
            f.before[&format!("INBOX.Alpha{suffix}")]
        );
    }
}

#[test]
fn subtree_recovery_requires_measured_reap_after_original_and_step_error() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.backend.exec.0.original_error.set(true);
    f.backend.exec.0.measured_reaped_error.set(true);
    f.start();
    f.backend.exec.0.recovery_error.set(true);
    let first = "1".repeat(32);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &first),
        RecoveryOutcome::Inspected
    );
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &first),
        RecoveryOutcome::Inspected
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 2);
    f.backend.exec.0.recovery_error.set(false);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &"2".repeat(32)),
        RecoveryOutcome::Progress
    );
    assert_eq!(
        f.backend.folder_rename_completion(&f.original),
        Completion::Renamed
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 3);
}

#[test]
fn subtree_recovery_releases_exact_settled_unchanged_tree_without_root_redispatch() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.backend.exec.0.original_noop.set(true);
    f.start();
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &"1".repeat(32)),
        RecoveryOutcome::Inspected
    );
    assert_eq!(
        f.backend.folder_rename_completion(&f.original),
        Completion::NoMutation
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
    assert_eq!(*f.backend.exec.0.folders.borrow(), f.before);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &"1".repeat(32)),
        RecoveryOutcome::Inspected
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
}

#[test]
fn subtree_recovery_foreign_missing_duplicate_extra_and_parent_refuse() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    for mode in 0..5 {
        let f = Fixture::new();
        f.start();
        {
            let mut folders = f.backend.exec.0.folders.borrow_mut();
            match mode {
                0 => {
                    folders.get_mut("INBOX.Alpha.Child").unwrap().guid = "7".repeat(32);
                }
                1 => {
                    folders.remove("INBOX.Alpha.Child.Grand");
                }
                2 => {
                    let duplicate = folders["INBOX.Alpha.Child"].clone();
                    folders.insert("INBOX.Beta.Child".into(), duplicate);
                }
                3 => {
                    folders.insert(
                        "INBOX.Alpha.Foreign".into(),
                        Container {
                            guid: "7".repeat(32),
                            body: vec![],
                        },
                    );
                }
                _ => {
                    folders.get_mut("INBOX").unwrap().guid = "7".repeat(32);
                }
            }
        }
        assert!(placement(&f.backend, &f.original).is_err(), "mode{mode}");
        assert_eq!(
            recover(&f.root, &f.backend, ALICE, &"1".repeat(32)),
            RecoveryOutcome::Refused,
            "mode{mode}"
        );
        assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
        assert_eq!(
            recover(&f.root, &f.backend, "bob@fixture.test", &"2".repeat(32)),
            RecoveryOutcome::Unavailable
        );
    }
}

#[test]
fn subtree_recovery_completes_split_known_children_and_retains_legacy_terminal_witness() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.start();
    {
        let mut folders = f.backend.exec.0.folders.borrow_mut();
        let grand = folders.remove("INBOX.Alpha.Child.Grand").unwrap();
        folders.insert("INBOX.Beta.Child.Grand".into(), grand);
    }
    assert_eq!(placement(&f.backend, &f.original).unwrap().old.len(), 2);
    for digit in ["1", "2"] {
        assert_eq!(
            recover(&f.root, &f.backend, ALICE, &digit.repeat(32)),
            RecoveryOutcome::Progress
        );
    }
    assert_eq!(
        f.backend.folder_rename_completion(&f.original),
        Completion::Renamed
    );
    assert_eq!(
        f.backend
            .folder_rename_completion(&f.original.for_recovery(&"2".repeat(32)).unwrap()),
        Completion::Renamed
    );
    for suffix in ["", ".Child", ".Child.Grand", ".Other"] {
        assert_eq!(
            f.backend.exec.0.folders.borrow()[&format!("INBOX.Beta{suffix}")],
            f.before[&format!("INBOX.Alpha{suffix}")]
        );
    }
    let file = crate::private_account_file::PrivateAccountFile::new(
        f.backend.helper.clone(),
        "osmap-folder-rename-helper-v1",
        4096,
    )
    .lock(ALICE)
    .unwrap();
    let bytes = file.read().unwrap().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 3);
    assert!(json.get("native_settled").is_none());
    assert!(json.get("recovery_steps").is_none());
    drop(file);
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &"2".repeat(32)),
        RecoveryOutcome::Progress
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 3);
}

#[test]
fn subtree_recovery_reserved_root_intent_is_undispatched_and_request_cannot_supply_settlement() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    let f = Fixture::new();
    f.start();
    let nonce = "1".repeat(32);
    {
        let mut role = crate::folder_rename::role_lease(&f.root, ALICE).unwrap();
        role.set_recovery(Some(crate::folder_rename::RecoveryIntent {
            nonce: nonce.clone(),
            dispatched: false,
        }))
        .unwrap();
    }
    assert_eq!(
        recover(&f.root, &f.backend, ALICE, &nonce),
        RecoveryOutcome::Inspected
    );
    assert_eq!(f.backend.exec.0.calls.borrow().len(), 1);
    let action = f.original.for_recovery(&nonce).unwrap();
    let mut wire = serde_json::to_value(action).unwrap();
    wire["native_settled"] = true.into();
    assert!(serde_json::from_value::<RenameFolderRequest>(wire).is_err());
    assert!(f.original.for_recovery(f.original.action_nonce()).is_err());
}
