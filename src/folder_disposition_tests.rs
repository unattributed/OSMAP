use super::*;
use crate::mailbox::{MailboxBackendError, MailboxEntry};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::PathBuf,
};
const ALICE: &str = "alice@fixture.test";
const BOB: &str = "bob@fixture.test";
#[derive(Clone, PartialEq, Eq, Debug)]
struct Container {
    guid: String,
    messages: Vec<Vec<u8>>,
}
pub(crate) struct Backend {
    folders: RefCell<BTreeMap<String, Container>>,
    witnesses: RefCell<BTreeMap<String, (RenameFolderRequest, Completion)>>,
    writes: Cell<usize>,
    mode: Cell<u8>,
}
impl Backend {
    fn new() -> Self {
        let mut folders = BTreeMap::new();
        for (name, guid) in [
            ("INBOX", "b"),
            ("INBOX.Alpha", "a"),
            ("INBOX.Sibling", "c"),
            ("Trash", "d"),
            ("INBOX.OtherBin", "e"),
        ] {
            folders.insert(name.into(), Container { guid: guid.repeat(32), messages: if name == "INBOX.Alpha" { vec![b"Content-Type: multipart/mixed; boundary=q\r\n\r\n--q\r\nContent-Type: text/plain\r\n\r\nPreserve me\r\n--q\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\n\r\n\0\x01\xff\r\n--q--\r\n".to_vec()] } else { vec![] } });
        }
        Self {
            folders: RefCell::new(folders),
            witnesses: RefCell::new(BTreeMap::new()),
            writes: Cell::new(0),
            mode: Cell::new(0),
        }
    }
    fn wire(&self) -> String {
        let mut rows =
            "* PREAUTH fixture\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n".to_owned();
        for name in self.folders.borrow().keys() {
            rows.push_str(&format!(
                "* LIST ({}) \".\" {name}\r\n",
                if name == "Trash" {
                    "\\Trash"
                } else if name == "INBOX"
                    || self
                        .folders
                        .borrow()
                        .keys()
                        .any(|n| n.starts_with(&format!("{name}.")))
                {
                    "\\HasChildren"
                } else {
                    "\\HasNoChildren"
                }
            ));
        }
        rows.push_str("L1 OK done\r\n* BYE done\r\nZ1 OK done\r\n");
        rows
    }
}
impl MailboxBackend for Backend {
    fn list_mailboxes(&self, account: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        if account != ALICE {
            return Err(crate::folder_metadata_backend::unavailable());
        }
        Ok(self
            .folders
            .borrow()
            .keys()
            .map(|name| MailboxEntry { name: name.clone() })
            .collect())
    }
    fn folder_metadata(&self, account: &str) -> Result<FolderSnapshot, MailboxBackendError> {
        if account != ALICE {
            return Err(crate::folder_metadata_backend::unavailable());
        }
        FolderSnapshot::parse(account, self.wire().as_bytes())
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
        let folders = self.folders.borrow();
        let entry = folders
            .get(name)
            .ok_or_else(crate::mailbox_status::unavailable)?;
        MailboxStatus::new(
            name,
            &entry.guid,
            entry.messages.len() as u64,
            entry.messages.iter().map(|m| m.len() as u64).sum(),
        )
    }
    fn folder_rename_completion(&self, request: &RenameFolderRequest) -> Completion {
        self.witnesses
            .borrow()
            .get(request.action_nonce())
            .filter(|(stored, _)| stored == request)
            .map(|(_, witness)| witness.clone())
            .unwrap_or(Completion::Unconfirmed)
    }
    fn rename_folder(&self, request: &RenameFolderRequest) -> Outcome {
        let snapshot = self.folder_metadata(request.account()).unwrap();
        let source = self
            .mailbox_status(request.account(), request.source())
            .unwrap();
        let parent = self
            .mailbox_status(request.account(), request.parent())
            .unwrap();
        request
            .validate_before(&snapshot, &source, &parent)
            .unwrap();
        request
            .validate_source_parent(
                &snapshot,
                &self
                    .mailbox_status(request.account(), request.source_parent())
                    .unwrap(),
            )
            .unwrap();
        self.writes.set(self.writes.get() + 1);
        if self.mode.get() == 3 {
            self.witnesses.borrow_mut().insert(
                request.action_nonce().into(),
                (request.clone(), Completion::NoMutation),
            );
            return Outcome::Refused(Refusal::Stale);
        }
        if self.mode.get() == 2 {
            return Outcome::Unknown;
        }
        let moving: Vec<_> = self
            .folders
            .borrow()
            .keys()
            .filter(|name| {
                name.as_str() == request.source()
                    || name.starts_with(&format!("{}.", request.source()))
            })
            .cloned()
            .collect();
        for old in moving {
            if self.mode.get() == 4 && old != request.source() {
                continue;
            }
            let value = self.folders.borrow_mut().remove(&old).unwrap();
            let new = format!(
                "{}{}",
                request.destination(),
                old.strip_prefix(request.source()).unwrap()
            );
            assert!(self.folders.borrow_mut().insert(new, value).is_none());
        }
        self.witnesses.borrow_mut().insert(
            request.action_nonce().into(),
            (request.clone(), Completion::Renamed),
        );
        if self.mode.get() == 1 {
            Outcome::Unknown
        } else {
            Outcome::Renamed
        }
    }
}

#[test]
fn folder_subtree_bin_restore_preserves_child_identity_bytes_indexes_and_lost_reply() {
    let f = Fixture::new();
    let original = f.backend.folders.borrow()["INBOX.Alpha"].clone();
    for (name, guid) in [("INBOX.Alpha.Child", "f"), ("INBOX.Alpha.Child.Grand", "8")] {
        f.backend.folders.borrow_mut().insert(
            name.into(),
            Container {
                guid: guid.repeat(32),
                messages: original.messages.clone(),
            },
        );
    }
    let mut row = crate::mailbox::MessageSummary {
        uid: 7,
        mailbox_name: "INBOX.Alpha.Child".into(),
        to: None,
        flags: vec![],
        date_received: String::new(),
        size_virtual: 100,
        subject: None,
        from: None,
        metadata: Some(crate::message_metadata::MessageMetadata {
            threading: None,
            attachments: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
            version: crate::message_metadata::MessageVersion::new(
                "f".repeat(32),
                "opaque-child-seven".into(),
            )
            .unwrap(),
            attachment_count: Some(1),
            preview: None,
        }),
    };
    let labels = crate::labels::LabelStore::new(f.root.join("labels-v1"));
    let created = labels
        .change(ALICE, 0, crate::labels::LabelChange::Create("Child label"))
        .unwrap();
    let id = created.labels()[0].id().to_owned();
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
    let bob_labels = labels.load(BOB).unwrap();
    let bob_snooze = snooze.load(BOB, 100).unwrap();
    let request = f.prepare();
    assert_eq!(request.descendants().len(), 2);
    // Native container contents may grow after advisory reads.
    f.backend
        .folders
        .borrow_mut()
        .get_mut("INBOX.Alpha.Child")
        .unwrap()
        .messages
        .push(b"new arrival including attachment".to_vec());
    let before = f.backend.folders.borrow().clone();
    f.backend.mode.set(1);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Unknown
    );
    assert_eq!(f.backend.writes.get(), 1);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Refused(Refusal::Unavailable)
    );
    assert!(matches!(
        check(&f.root, &f.backend, ALICE),
        crate::folder_rename::CheckOutcome::Renamed { .. }
    ));
    assert_eq!(f.backend.writes.get(), 1);
    let receipt = list(&f.root, ALICE).unwrap().remove(0);
    assert_eq!(receipt.descendants, request.descendants());
    for suffix in ["", ".Child", ".Child.Grand"] {
        assert_eq!(
            f.backend.folders.borrow()[&format!("{}{suffix}", receipt.stored_name())],
            before[&format!("INBOX.Alpha{suffix}")]
        );
    }
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
    f.backend.mode.set(0);
    let restore = receipt.restore_request(ALICE).unwrap();
    assert_eq!(restore.descendants(), request.descendants());
    assert_eq!(
        execute(&f.root, &f.backend, &restore, 100),
        Outcome::Renamed
    );
    assert_eq!(*f.backend.folders.borrow(), before);
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
    assert_eq!(labels.load(BOB).unwrap(), bob_labels);
    assert_eq!(snooze.load(BOB, 100).unwrap(), bob_snooze);
    assert!(list(&f.root, ALICE).unwrap().is_empty());
    assert_eq!(f.backend.writes.get(), 2);
}

#[test]
fn folder_subtree_refuses_stale_protected_foreign_capacity_and_retains_partial_uncertainty() {
    let f = Fixture::new();
    f.backend.folders.borrow_mut().insert(
        "INBOX.Alpha.Child".into(),
        Container {
            guid: "f".repeat(32),
            messages: vec![b"child bytes".to_vec()],
        },
    );
    let request = f.prepare();
    f.backend
        .folders
        .borrow_mut()
        .get_mut("INBOX.Alpha.Child")
        .unwrap()
        .guid = "9".repeat(32);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Refused(Refusal::Stale)
    );
    assert_eq!(f.backend.writes.get(), 0);
    f.backend.folders.borrow_mut().insert(
        "INBOX.Alpha.Sent".into(),
        Container {
            guid: "7".repeat(32),
            messages: vec![],
        },
    );
    assert!(prepare_bin(&f.root, &f.backend, ALICE, "INBOX.Alpha").is_err());
    f.backend.folders.borrow_mut().remove("INBOX.Alpha.Sent");
    assert!(prepare_bin(&f.root, &f.backend, BOB, "INBOX.Alpha").is_err());
    let request = f.prepare();
    f.backend.mode.set(4);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Unknown
    );
    assert_eq!(
        check(&f.root, &f.backend, ALICE),
        crate::folder_rename::CheckOutcome::Unconfirmed
    );
    assert_eq!(f.backend.writes.get(), 1);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Refused(Refusal::Unavailable)
    );
    assert_eq!(f.backend.writes.get(), 1);
    assert!(f.backend.folders.borrow().contains_key("INBOX.Alpha.Child"));
    assert!(f
        .backend
        .folders
        .borrow()
        .contains_key(&request.destination()));
    assert!(crate::folder_rename::settings_gate(&f.root, ALICE).is_err());
    let capacity = Fixture::new();
    for i in 0..9 {
        capacity.backend.folders.borrow_mut().insert(
            format!("INBOX.Alpha.Child{i}"),
            Container {
                guid: format!("{:032x}", 100 + i),
                messages: vec![],
            },
        );
    }
    assert_eq!(
        prepare_bin(&capacity.root, &capacity.backend, ALICE, "INBOX.Alpha"),
        Err(Refusal::Capacity)
    );
    assert_eq!(capacity.backend.writes.get(), 0);
    let wire_capacity = Fixture::new();
    let long_parent = format!("INBOX.Alpha.P{}", "x".repeat(124));
    wire_capacity.backend.folders.borrow_mut().insert(
        long_parent.clone(),
        Container {
            guid: format!("{:032x}", 100),
            messages: vec![],
        },
    );
    for i in 0..7 {
        wire_capacity.backend.folders.borrow_mut().insert(
            format!("{long_parent}.C{i}{}", "x".repeat(65)),
            Container {
                guid: format!("{:032x}", 200 + i),
                messages: vec![],
            },
        );
    }
    assert_eq!(
        prepare_bin(
            &wire_capacity.root,
            &wire_capacity.backend,
            ALICE,
            "INBOX.Alpha"
        ),
        Err(Refusal::Capacity)
    );
    assert_eq!(wire_capacity.backend.writes.get(), 0);
}
struct Fixture {
    root: PathBuf,
    backend: Backend,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-disposition-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            root,
            backend: Backend::new(),
        }
    }
    fn prepare(&self) -> RenameFolderRequest {
        prepare_bin(&self.root, &self.backend, ALICE, "INBOX.Alpha").unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn folder_disposition_interrupted_reservation_never_dispatches_or_strands_capacity() {
    use crate::folder_rename::CheckOutcome;
    // Real durable receipt publication, then process interruption before role
    // begin, or after role begin but before the dispatch-ready publication.
    for role_published in [false, true] {
        let f = Fixture::new();
        let request = f.prepare();
        let original = f.backend.folders.borrow().clone();
        {
            let mut role = crate::folder_rename::settings_gate(&f.root, ALICE).unwrap();
            let mut receipts = Receipts::lock(&f.root, ALICE).unwrap();
            reserve_before_dispatch(&mut receipts, &request, &role).unwrap();
            if role_published {
                role.begin(&request).unwrap();
            }
        }
        assert_eq!(check(&f.root, &f.backend, ALICE), CheckOutcome::Unchanged);
        assert!(list(&f.root, ALICE).unwrap().is_empty());
        assert!(crate::folder_rename::role_lease(&f.root, ALICE)
            .unwrap()
            .pending()
            .is_none());
        assert_eq!(f.backend.writes.get(), 0);
        assert_eq!(*f.backend.folders.borrow(), original);

        // The same two boundaries during Restore retain the complete original
        // Bin receipt and original action, allowing a fresh explicit review.
        assert_eq!(execute(&f.root, &f.backend, &request, 10), Outcome::Renamed);
        let binned = list(&f.root, ALICE).unwrap().remove(0);
        let restore = binned.restore_request(ALICE).unwrap();
        {
            let mut role = crate::folder_rename::settings_gate(&f.root, ALICE).unwrap();
            let mut receipts = Receipts::lock(&f.root, ALICE).unwrap();
            reserve_before_dispatch(&mut receipts, &restore, &role).unwrap();
            if role_published {
                role.begin(&restore).unwrap();
            }
        }
        assert_eq!(check(&f.root, &f.backend, ALICE), CheckOutcome::Unchanged);
        let recovered = list(&f.root, ALICE).unwrap().remove(0);
        assert_eq!(recovered.state, State::Binned);
        assert_eq!(recovered.original_action, binned.original_action);
        assert_eq!(recovered.source, binned.source);
        assert_eq!(recovered.parent_guid, binned.parent_guid);
        assert_eq!(recovered.folder_guid, binned.folder_guid);
        assert_eq!(
            recovered.restore_action.as_deref(),
            Some(restore.action_nonce())
        );
        assert!(recovered.restore_request(ALICE).is_ok());
        assert_eq!(f.backend.writes.get(), 1);
        assert_eq!(
            f.backend.folders.borrow()[&binned.stored_name()],
            original["INBOX.Alpha"]
        );

        // Once dispatch is permitted, neither an unconfirmed helper outcome
        // nor a missing role may be reclassified as a never-dispatched action.
        let restore = recovered.restore_request(ALICE).unwrap();
        f.backend.mode.set(2);
        assert_eq!(execute(&f.root, &f.backend, &restore, 11), Outcome::Unknown);
        assert_eq!(check(&f.root, &f.backend, ALICE), CheckOutcome::Unconfirmed);
        crate::folder_rename::role_lease(&f.root, ALICE)
            .unwrap()
            .confirm()
            .unwrap();
        assert_eq!(check(&f.root, &f.backend, ALICE), CheckOutcome::Unconfirmed);
        assert_eq!(
            list(&f.root, ALICE).unwrap()[0].state,
            State::RestorePending
        );
        assert_eq!(f.backend.writes.get(), 2);
    }
}

#[test]
fn folder_disposition_roundtrip_preserves_complete_container_and_old_bin_receipt() {
    let f = Fixture::new();
    let original = f
        .backend
        .folders
        .borrow()
        .get("INBOX.Alpha")
        .unwrap()
        .clone();
    let sibling = f
        .backend
        .folders
        .borrow()
        .get("INBOX.Sibling")
        .unwrap()
        .clone();
    let request = f.prepare();
    let mut row = crate::mailbox::MessageSummary {
        uid: 7,
        mailbox_name: "INBOX.Alpha".into(),
        to: None,
        flags: vec![],
        date_received: String::new(),
        size_virtual: 100,
        subject: None,
        from: None,
        metadata: Some(crate::message_metadata::MessageMetadata {
            threading: None,
            attachments: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
            version: crate::message_metadata::MessageVersion::new(
                original.guid.clone(),
                "opaque-message-seven".into(),
            )
            .unwrap(),
            attachment_count: Some(1),
            preview: None,
        }),
    };
    let labels = crate::labels::LabelStore::new(f.root.join("labels-v1"));
    let created = labels
        .change(ALICE, 0, crate::labels::LabelChange::Create("Keep"))
        .unwrap();
    let label_id = created.labels()[0].id().to_owned();
    let identity =
        crate::labels::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Alpha", &row).unwrap();
    labels
        .change(
            ALICE,
            created.revision(),
            crate::labels::LabelChange::Attach {
                id: &label_id,
                message: &identity,
            },
        )
        .unwrap();
    let snooze = crate::snooze::SnoozeStore::new(&f.root);
    let identity =
        crate::snooze::MessageIdentity::from_summary(ALICE, ALICE, "INBOX.Alpha", &row).unwrap();
    snooze.set(ALICE, &identity, 0, 700, 100).unwrap();
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Renamed
    );
    let receipts = list(&f.root, ALICE).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, State::Binned);
    row.mailbox_name = receipts[0].stored_name();
    let moved = crate::labels::MessageIdentity::from_summary(ALICE, ALICE, &row.mailbox_name, &row)
        .unwrap();
    assert_eq!(
        labels.load(ALICE).unwrap().labels_for(&moved).unwrap()[0].id(),
        label_id
    );
    assert_eq!(
        snooze.load(ALICE, 100).unwrap().markers()[0]
            .identity()
            .folder(),
        row.mailbox_name
    );
    assert_eq!(
        f.backend.folders.borrow().get(&receipts[0].stored_name()),
        Some(&original)
    );
    assert!(list(&f.root, BOB).unwrap().is_empty());
    crate::bin_folder::BinPreferencesStore::new(&f.root)
        .save(ALICE, 0, "INBOX.OtherBin")
        .unwrap();
    let receipts = list(&f.root, ALICE).unwrap();
    assert_eq!(receipts[0].bin, "Trash");
    let restore = receipts[0].restore_request(ALICE).unwrap();
    {
        let role = crate::folder_rename::settings_gate(&f.root, ALICE).unwrap();
        assert_eq!(
            guard_ordinary(&f.root, &role, &receipts[0].stored_name(), "INBOX.Other"),
            Err(Refusal::Invalid)
        );
        assert_eq!(
            guard_ordinary(
                &f.root,
                &role,
                "INBOX.Other",
                &format!("{}.Child", receipts[0].stored_name())
            ),
            Err(Refusal::Invalid)
        );
        assert!(guard_ordinary(&f.root, &role, "INBOX.Alpha", "INBOX.New").is_ok());
    }
    assert_eq!(
        execute(&f.root, &f.backend, &restore, 100),
        Outcome::Renamed
    );
    assert!(list(&f.root, ALICE).unwrap().is_empty());
    assert_eq!(
        f.backend.folders.borrow().get("INBOX.Alpha"),
        Some(&original)
    );
    assert_eq!(
        f.backend.folders.borrow().get("INBOX.Sibling"),
        Some(&sibling)
    );
    assert_eq!(f.backend.writes.get(), 2);
    row.mailbox_name = "INBOX.Alpha".into();
    let restored =
        crate::labels::MessageIdentity::from_summary(ALICE, ALICE, &row.mailbox_name, &row)
            .unwrap();
    assert_eq!(
        labels.load(ALICE).unwrap().labels_for(&restored).unwrap()[0].id(),
        label_id
    );
    let markers = snooze.load(ALICE, 100).unwrap();
    assert_eq!(markers.markers()[0].identity().folder(), "INBOX.Alpha");
    assert_eq!(markers.markers()[0].until(), 700);
}

#[test]
fn folder_disposition_stale_bin_parent_occupied_original_and_forged_purpose_refuse() {
    let f = Fixture::new();
    let request = f.prepare();
    crate::bin_folder::BinPreferencesStore::new(&f.root)
        .save(ALICE, 0, "INBOX.OtherBin")
        .unwrap();
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Refused(Refusal::Stale)
    );
    assert_eq!(f.backend.writes.get(), 0);
    let request = f.prepare();
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Renamed
    );
    let receipt = list(&f.root, ALICE).unwrap().remove(0);
    let restore = receipt.restore_request(ALICE).unwrap();
    f.backend.folders.borrow_mut().insert(
        "INBOX.Alpha".into(),
        Container {
            guid: "f".repeat(32),
            messages: vec![],
        },
    );
    assert!(matches!(
        execute(&f.root, &f.backend, &restore, 100),
        Outcome::Refused(_)
    ));
    f.backend.folders.borrow_mut().remove("INBOX.Alpha");
    f.backend
        .folders
        .borrow_mut()
        .get_mut("INBOX")
        .unwrap()
        .guid = "9".repeat(32);
    assert!(matches!(
        execute(&f.root, &f.backend, &restore, 100),
        Outcome::Refused(_)
    ));
    assert_eq!(f.backend.writes.get(), 1);
    assert!(RenameFolderRequest::for_move(
        ALICE,
        "INBOX.Alpha",
        &"a".repeat(32),
        &"b".repeat(32),
        "Trash",
        &"d".repeat(32)
    )
    .is_err());
    let mut changed = serde_json::to_value(&request).unwrap();
    changed["disposition"]["Bin"]["bin"] = "Sent".into();
    let changed: RenameFolderRequest = serde_json::from_value(changed).unwrap();
    assert!(changed.validate().is_err());
    assert!(receipt.restore_request(BOB).is_ok()); // Syntax is not ownership: service must reject.
    let foreign = receipt.restore_request(BOB).unwrap();
    assert!(matches!(
        execute(&f.root, &f.backend, &foreign, 100),
        Outcome::Refused(_)
    ));
    assert_eq!(f.backend.writes.get(), 1);
}

#[test]
fn folder_disposition_unknown_requires_original_witness_and_never_redispatches() {
    for mode in [1, 2] {
        let f = Fixture::new();
        f.backend.mode.set(mode);
        let request = f.prepare();
        assert_eq!(
            execute(&f.root, &f.backend, &request, 100),
            Outcome::Unknown
        );
        assert_eq!(
            execute(&f.root, &f.backend, &request, 100),
            Outcome::Refused(Refusal::Unavailable)
        );
        assert_eq!(f.backend.writes.get(), 1);
        assert!(crate::folder_rename::settings_gate(&f.root, ALICE).is_err());
        assert_eq!(
            check(&f.root, &f.backend, ALICE),
            if mode == 1 {
                crate::folder_rename::CheckOutcome::Renamed {
                    destination: request.destination(),
                }
            } else {
                crate::folder_rename::CheckOutcome::Unconfirmed
            }
        );
        assert_eq!(f.backend.writes.get(), 1);
        assert_eq!(
            list(&f.root, ALICE).unwrap()[0].state,
            if mode == 1 {
                State::Binned
            } else {
                State::BinPending
            }
        );
    }
}

#[test]
fn folder_disposition_capacity_reserves_exact_later_bytes_before_mutation() {
    let f = Fixture::new();
    let mut receipts = Receipts::lock(&f.root, ALICE).unwrap();
    let mut count = 0;
    loop {
        let id = format!("{count:032x}");
        let receipt = Receipt {
            id: id.clone(),
            source: format!("INBOX.{}", "Long".repeat(35)),
            parent_guid: "b".repeat(32),
            folder_guid: format!("{:032x}", count + 32),
            bin: "Trash".into(),
            bin_guid: "d".repeat(32),
            bin_revision: u64::MAX,
            original_action: id,
            restore_action: None,
            state: State::Binned,
            descendants: Vec::new(),
        };
        receipts.record.receipts.push(receipt);
        if receipts.reserved_bytes().is_err() {
            receipts.record.receipts.pop();
            break;
        }
        count += 1;
    }
    assert!(count > 0 && count < MAX_RECEIPTS);
    receipts.publish().unwrap();
    let original = receipts.file.read().unwrap().unwrap();
    drop(receipts);
    // The new row's actual source is enlarged while maintaining a valid leaf.
    let source = format!("INBOX.{}", "Long".repeat(35));
    let container = f
        .backend
        .folders
        .borrow_mut()
        .remove("INBOX.Alpha")
        .unwrap();
    f.backend
        .folders
        .borrow_mut()
        .insert(source.clone(), container);
    let request = prepare_bin(&f.root, &f.backend, ALICE, &source).unwrap();
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Refused(Refusal::Capacity)
    );
    let receipts = Receipts::lock(&f.root, ALICE).unwrap();
    assert_eq!(receipts.file.read().unwrap().unwrap(), original);
    assert_eq!(f.backend.writes.get(), 0);
    assert!(crate::folder_rename::settings_gate(&f.root, ALICE).is_ok());
}

#[test]
fn folder_disposition_receipt_corruption_and_no_witness_do_not_clear_pending() {
    let f = Fixture::new();
    let request = f.prepare();
    f.backend.mode.set(1);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Unknown
    );
    f.backend.witnesses.borrow_mut().clear();
    assert_eq!(
        check(&f.root, &f.backend, ALICE),
        crate::folder_rename::CheckOutcome::Unconfirmed
    );
    assert_eq!(f.backend.writes.get(), 1);
    {
        let receipts = Receipts::lock(&f.root, ALICE).unwrap();
        receipts.file.write(b"{}\n").unwrap();
    }
    assert!(list(&f.root, ALICE).is_err());
    assert_eq!(
        check(&f.root, &f.backend, ALICE),
        crate::folder_rename::CheckOutcome::Unavailable
    );
    assert!(crate::folder_rename::settings_gate(&f.root, ALICE).is_err());
    assert!(list(&f.root, BOB).unwrap().is_empty());
}

#[test]
fn folder_disposition_settled_no_mutation_witness_releases_only_its_receipt() {
    let f = Fixture::new();
    let request = f.prepare();
    f.backend.mode.set(3);
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Refused(Refusal::Stale)
    );
    assert!(list(&f.root, ALICE).unwrap().is_empty());
    assert!(crate::folder_rename::settings_gate(&f.root, ALICE).is_ok());
    assert!(f.backend.folders.borrow().contains_key("INBOX.Alpha"));
    f.backend.mode.set(0);
    let request = f.prepare();
    assert_eq!(
        execute(&f.root, &f.backend, &request, 100),
        Outcome::Renamed
    );
    let receipt = list(&f.root, ALICE).unwrap().remove(0);
    let restore = receipt.restore_request(ALICE).unwrap();
    f.backend.mode.set(3);
    assert_eq!(
        execute(&f.root, &f.backend, &restore, 100),
        Outcome::Refused(Refusal::Stale)
    );
    let kept = list(&f.root, ALICE).unwrap().remove(0);
    assert_eq!(kept.state, State::Binned);
    assert_eq!(kept.original_action, receipt.original_action);
    assert_eq!(kept.restore_action.as_deref(), Some(restore.action_nonce()));
    assert!(crate::folder_rename::settings_gate(&f.root, ALICE).is_ok());
    assert!(!f.backend.folders.borrow().contains_key("INBOX.Alpha"));
}

#[test]
fn folder_disposition_native_adapter_uses_one_exact_rename_and_keeps_container() {
    let _case = crate::folder_rename_backend::TEST_GATE.lock().unwrap();
    use crate::auth::{CommandExecution, CommandExecutionError, CommandExecutor};
    use std::time::Duration;
    struct Exec<'a> {
        backend: &'a Backend,
        expected: &'a RenameFolderRequest,
    }
    impl CommandExecutor for Exec<'_> {
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
            let stdout = if args.first().map(String::as_str) == Some("exec") {
                assert_eq!(input, crate::folder_metadata_backend::TRANSCRIPT);
                self.backend.wire()
            } else if args.iter().any(|a| a == "rename") {
                assert_eq!(
                    args,
                    [
                        "-o",
                        "stats_writer_socket_path=",
                        "-o",
                        "auth_socket_path=/private/userdb",
                        "mailbox",
                        "rename",
                        "-u",
                        ALICE,
                        self.expected.source(),
                        &self.expected.destination()
                    ]
                );
                assert!(input.is_empty());
                assert_eq!(limit, 4096);
                self.backend.writes.set(self.backend.writes.get() + 1);
                let value = self
                    .backend
                    .folders
                    .borrow_mut()
                    .remove(self.expected.source())
                    .unwrap();
                assert!(self
                    .backend
                    .folders
                    .borrow_mut()
                    .insert(self.expected.destination(), value)
                    .is_none());
                String::new()
            } else {
                assert!(input.is_empty());
                let name = args.last().unwrap();
                let status = self.backend.mailbox_status(ALICE, name).unwrap();
                serde_json::json!([{"mailbox":name,"guid":status.guid(),"messages":status.messages().to_string(),"vsize":status.virtual_bytes().to_string()}]).to_string()
            };
            Ok(CommandExecution {
                status_code: 0,
                stdout,
                stderr: String::new(),
            })
        }
    }
    let f = Fixture::new();
    let bin = f.prepare();
    let original = f.backend.folders.borrow()["INBOX.Alpha"].clone();
    let exec = Exec {
        backend: &f.backend,
        expected: &bin,
    };
    assert_eq!(
        crate::folder_rename_backend::rename(
            &exec,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            &bin
        ),
        Outcome::Renamed
    );
    assert_eq!(
        f.backend.folders.borrow().get(&bin.destination()),
        Some(&original)
    );
    let receipt = Receipt {
        id: bin.action_nonce().into(),
        source: bin.source().into(),
        parent_guid: bin.source_parent_guid().into(),
        folder_guid: bin.source_guid().into(),
        bin: bin.parent().into(),
        bin_guid: bin.parent_guid().into(),
        bin_revision: 0,
        original_action: bin.action_nonce().into(),
        restore_action: None,
        state: State::Binned,
        descendants: Vec::new(),
    };
    let restore = receipt.restore_request(ALICE).unwrap();
    let exec = Exec {
        backend: &f.backend,
        expected: &restore,
    };
    assert_eq!(
        crate::folder_rename_backend::rename(
            &exec,
            Path::new("/fixed/doveadm"),
            Some(Path::new("/private/userdb")),
            &restore
        ),
        Outcome::Renamed
    );
    assert_eq!(
        f.backend.folders.borrow().get("INBOX.Alpha"),
        Some(&original)
    );
    assert_eq!(f.backend.writes.get(), 2);
}
