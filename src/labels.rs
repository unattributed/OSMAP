//! Account-private label metadata; callers must authenticate and revalidate native identities.
//! GUIDs are native Dovecot mailbox/message identities, not a claimed UIDVALIDITY value.
use crate::{
    mailbox::{MailboxEntry, MailboxListingPolicy, MessageSummary},
    private_account_file::PrivateAccountFile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io,
    path::PathBuf,
    time::{Duration, Instant},
};
pub const MAX_LABELS: usize = 32;
pub const MAX_ASSIGNED_MESSAGES: usize = crate::mailbox::DEFAULT_MAX_MESSAGES;
pub const MAX_LABELS_PER_MESSAGE: usize = 8;
// 2000 identities, each bounded folder/GUID/UID + 8 opaque IDs, plus 32 names.
// 8 MiB accommodates worst-case JSON escapes; this is not a mailbox/storage quota.
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelError {
    Invalid,
    Corrupt,
    Stale,
    Missing,
    Capacity,
    Unavailable,
    Unconfirmed,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    folder: String,
    uid: u64,
    mailbox_guid: String,
    message_guid: String,
}
impl Key {
    fn valid(&self) -> bool {
        self.uid > 0
            && self.uid <= u32::MAX as u64
            && MailboxEntry::new(MailboxListingPolicy::default(), &self.folder).is_ok()
            && crate::message_metadata::MessageVersion::new(
                self.mailbox_guid.clone(),
                self.message_guid.clone(),
            )
            .is_ok_and(|v| {
                v.mailbox_guid == self.mailbox_guid && v.message_guid == self.message_guid
            })
    }
}
/// A projection from an owned, current summary; construction is validation, not authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageIdentity {
    owner: String,
    key: Key,
}
impl MessageIdentity {
    pub fn from_summary(
        account: &str,
        returned_account: &str,
        expected_folder: &str,
        row: &MessageSummary,
    ) -> Result<Self, LabelError> {
        account_valid(account)?;
        if account != returned_account || row.mailbox_name != expected_folder {
            return Err(LabelError::Invalid);
        }
        let m = row.metadata.as_ref().ok_or(LabelError::Invalid)?;
        let key = Key {
            folder: row.mailbox_name.clone(),
            uid: row.uid,
            mailbox_guid: m.version.mailbox_guid.clone(),
            message_guid: m.version.message_guid.clone(),
        };
        if !key.valid() {
            return Err(LabelError::Invalid);
        }
        Ok(Self {
            owner: account.into(),
            key,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    id: String,
    name: String,
}
impl Label {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    key: Key,
    labels: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRecord {
    version: u8,
    account: String,
    revision: u64,
    labels: Vec<Label>,
    assignments: Vec<Assignment>,
}
impl LabelRecord {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }
    pub fn assigned_messages(&self) -> usize {
        self.assignments.len()
    }
    pub fn labels_for(&self, message: &MessageIdentity) -> Result<Vec<&Label>, LabelError> {
        if self.account != message.owner {
            return Err(LabelError::Invalid);
        }
        Ok(self
            .assignments
            .iter()
            .find(|a| a.key == message.key)
            .map(|a| {
                self.labels
                    .iter()
                    .filter(|l| a.labels.contains(&l.id))
                    .collect()
            })
            .unwrap_or_default())
    }
    fn empty(account: &str) -> Self {
        Self {
            version: 1,
            account: account.into(),
            revision: 0,
            labels: vec![],
            assignments: vec![],
        }
    }
    fn parse(account: &str, bytes: Option<Vec<u8>>) -> Result<Self, LabelError> {
        let Some(bytes) = bytes else {
            return Ok(Self::empty(account));
        };
        let r: Self = serde_json::from_slice(&bytes).map_err(|_| LabelError::Corrupt)?;
        if r.account != account
            || r.version != 1
            || r.revision == 0
            || r.labels.len() > MAX_LABELS
            || r.assignments.len() > MAX_ASSIGNED_MESSAGES
        {
            return Err(LabelError::Corrupt);
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for l in &r.labels {
            if !valid_id(&l.id)
                || !valid_name(&l.name)
                || !ids.insert(&l.id)
                || !names.insert(&l.name)
            {
                return Err(LabelError::Corrupt);
            }
        }
        for a in &r.assignments {
            let unique: BTreeSet<_> = a.labels.iter().collect();
            if !a.key.valid()
                || !keys.insert(&a.key)
                || a.labels.is_empty()
                || a.labels.len() > MAX_LABELS_PER_MESSAGE
                || unique.len() != a.labels.len()
                || a.labels.iter().any(|id| !ids.contains(id))
            {
                return Err(LabelError::Corrupt);
            }
        }
        Ok(r)
    }
}
fn account_valid(account: &str) -> Result<(), LabelError> {
    crate::identity::CanonicalUsername::parse(account)
        .map(|_| ())
        .map_err(|_| LabelError::Invalid)
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.trim() == name
        && name.len() <= 128
        && name.chars().count() <= 32
        && !name.chars().any(|c| {
            c.is_control()
                || matches!(c,'\u{2028}'|'\u{2029}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
}
pub enum LabelChange<'a> {
    /// One atomic update of at most ten freshly verified identities.
    Selection {
        id: &'a str,
        messages: &'a [MessageIdentity],
        attach: bool,
    },
    Create(&'a str),
    Rename {
        id: &'a str,
        name: &'a str,
    },
    Delete(&'a str),
    Attach {
        id: &'a str,
        message: &'a MessageIdentity,
    },
    Detach {
        id: &'a str,
        message: &'a MessageIdentity,
    },
}
#[derive(Debug, Clone)]
pub struct LabelStore {
    file: PrivateAccountFile,
}
impl LabelStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), "osmap-labels-v1", MAX_RECORD_BYTES),
        }
    }
    pub fn load(&self, account: &str) -> Result<LabelRecord, LabelError> {
        account_valid(account)?;
        LabelRecord::parse(
            account,
            self.file
                .read(account)
                .map_err(|_| LabelError::Unavailable)?,
        )
    }
    fn update(
        &self,
        account: &str,
        revision: u64,
        f: impl FnOnce(&mut LabelRecord) -> Result<(), LabelError>,
    ) -> Result<LabelRecord, LabelError> {
        account_valid(account)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        let lock = loop {
            match self.file.lock(account) {
                Ok(l) => break l,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(LabelError::Unavailable),
            }
        };
        let mut r = LabelRecord::parse(account, lock.read().map_err(|_| LabelError::Unavailable)?)?;
        if r.revision != revision {
            return Err(LabelError::Stale);
        }
        f(&mut r)?;
        r.revision = r.revision.checked_add(1).ok_or(LabelError::Corrupt)?;
        let bytes = serde_json::to_vec(&r).map_err(|_| LabelError::Unavailable)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(LabelError::Capacity);
        }
        LabelRecord::parse(account, Some(bytes.clone()))?;
        lock.write(&bytes).map_err(|_| LabelError::Unconfirmed)?;
        Ok(r)
    }
    /// Call only after native old/new-name and original folder-GUID confirmation.
    /// Idempotent so a pending action can finish private metadata after a restart.
    pub(crate) fn reconcile_folder_rename(
        &self,
        request: &crate::folder_rename::RenameFolderRequest,
    ) -> Result<(), LabelError> {
        request.validate().map_err(|_| LabelError::Invalid)?;
        let account = request.account();
        let lock = self
            .file
            .lock(account)
            .map_err(|_| LabelError::Unavailable)?;
        let mut record =
            LabelRecord::parse(account, lock.read().map_err(|_| LabelError::Unavailable)?)?;
        let mut changed = false;
        for assignment in &mut record.assignments {
            if assignment.key.folder == request.source()
                && assignment.key.mailbox_guid == request.source_guid()
            {
                assignment.key.folder = request.destination();
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        record.revision = record.revision.checked_add(1).ok_or(LabelError::Corrupt)?;
        let bytes = serde_json::to_vec(&record).map_err(|_| LabelError::Corrupt)?;
        LabelRecord::parse(account, Some(bytes.clone()))?;
        lock.write(&bytes).map_err(|_| LabelError::Unconfirmed)
    }
    pub fn change(
        &self,
        account: &str,
        revision: u64,
        change: LabelChange<'_>,
    ) -> Result<LabelRecord, LabelError> {
        self.update(account, revision, |r| {
            match change {
                LabelChange::Selection {
                    id,
                    messages,
                    attach,
                } => {
                    if messages.is_empty() || messages.len() > crate::mail_list::MAX_BULK_SELECTION
                    {
                        return Err(LabelError::Invalid);
                    }
                    let mut uids = BTreeSet::new();
                    let mut guids = BTreeSet::new();
                    let first = messages.first().ok_or(LabelError::Invalid)?;
                    for message in messages {
                        if message.owner != account
                            || !message.key.valid()
                            || message.key.folder != first.key.folder
                            || message.key.mailbox_guid != first.key.mailbox_guid
                            || !uids.insert(message.key.uid)
                            || !guids.insert(&message.key.message_guid)
                        {
                            return Err(LabelError::Invalid);
                        }
                    }
                    for message in messages {
                        assign_label(r, id, message, attach)?;
                    }
                }
                LabelChange::Create(name) => {
                    if !valid_name(name) || r.labels.iter().any(|l| l.name == name) {
                        return Err(LabelError::Invalid);
                    }
                    if r.labels.len() == MAX_LABELS {
                        return Err(LabelError::Capacity);
                    }
                    let id =
                        crate::draft::generate_draft_id().map_err(|_| LabelError::Unavailable)?;
                    if r.labels.iter().any(|l| l.id == id) {
                        return Err(LabelError::Unavailable);
                    }
                    r.labels.push(Label {
                        id,
                        name: name.into(),
                    });
                }
                LabelChange::Rename { id, name } => {
                    if !valid_name(name) || r.labels.iter().any(|l| l.name == name && l.id != id) {
                        return Err(LabelError::Invalid);
                    }
                    r.labels
                        .iter_mut()
                        .find(|l| l.id == id)
                        .ok_or(LabelError::Missing)?
                        .name = name.into();
                }
                LabelChange::Delete(id) => {
                    let i = r
                        .labels
                        .iter()
                        .position(|l| l.id == id)
                        .ok_or(LabelError::Missing)?;
                    r.labels.remove(i);
                    for a in &mut r.assignments {
                        a.labels.retain(|v| v != id)
                    }
                    r.assignments.retain(|a| !a.labels.is_empty());
                }
                LabelChange::Attach { id, message } | LabelChange::Detach { id, message } => {
                    if message.owner != account {
                        return Err(LabelError::Invalid);
                    }
                    assign_label(r, id, message, matches!(change, LabelChange::Attach { .. }))?;
                }
            }
            Ok(())
        })
    }
    /// Call only after authoritative move confirmation and destination revalidation.
    /// Unknown/partial outcomes must not call this method. No mail operation is performed here.
    pub fn reconcile_confirmed_move(
        &self,
        account: &str,
        revision: u64,
        source: &MessageIdentity,
        destination: &MessageIdentity,
    ) -> Result<LabelRecord, LabelError> {
        if source.owner != account
            || destination.owner != account
            || source.key.message_guid != destination.key.message_guid
            || source.key == destination.key
        {
            return Err(LabelError::Invalid);
        }
        self.update(account, revision, |r| {
            let Some(i) = r.assignments.iter().position(|a| a.key == source.key) else {
                return Ok(());
            };
            let labels = r.assignments[i].labels.clone();
            if let Some(target) = r.assignments.iter_mut().find(|a| a.key == destination.key) {
                let mut merged = target.labels.clone();
                for id in labels {
                    if !merged.contains(&id) {
                        merged.push(id)
                    }
                }
                if merged.len() > MAX_LABELS_PER_MESSAGE {
                    return Err(LabelError::Capacity);
                }
                target.labels = merged;
            } else {
                r.assignments.push(Assignment {
                    key: destination.key.clone(),
                    labels,
                });
            }
            r.assignments.remove(i);
            Ok(())
        })
    }
    /// Explicit cleanup after confirmed message removal; never inferred from a bounded listing.
    pub fn forget_confirmed_message(
        &self,
        account: &str,
        revision: u64,
        message: &MessageIdentity,
    ) -> Result<LabelRecord, LabelError> {
        if message.owner != account {
            return Err(LabelError::Invalid);
        }
        self.update(account, revision, |r| {
            r.assignments.retain(|a| a.key != message.key);
            Ok(())
        })
    }
}
fn assign_label(
    r: &mut LabelRecord,
    id: &str,
    message: &MessageIdentity,
    attaching: bool,
) -> Result<(), LabelError> {
    if !r.labels.iter().any(|l| l.id == id) {
        return Err(LabelError::Missing);
    }
    if let Some(a) = r.assignments.iter_mut().find(|a| a.key == message.key) {
        if attaching && !a.labels.iter().any(|v| v == id) {
            if a.labels.len() == MAX_LABELS_PER_MESSAGE {
                return Err(LabelError::Capacity);
            }
            a.labels.push(id.into());
        } else if !attaching {
            a.labels.retain(|v| v != id);
        }
    } else if attaching {
        if r.assignments.len() == MAX_ASSIGNED_MESSAGES {
            return Err(LabelError::Capacity);
        }
        r.assignments.push(Assignment {
            key: message.key.clone(),
            labels: vec![id.into()],
        });
    }
    r.assignments.retain(|a| !a.labels.is_empty());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    const ALICE: &str = "alice@example.test";
    const BOB: &str = "bob@example.test";
    fn store() -> (PathBuf, LabelStore) {
        let p = std::env::temp_dir().join(format!(
            "osmap-labels-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        (p.clone(), LabelStore::new(p))
    }
    fn message(uid: u64) -> MessageIdentity {
        MessageIdentity {
            owner: ALICE.into(),
            key: Key {
                folder: "INBOX".into(),
                uid,
                mailbox_guid: "a".repeat(32),
                message_guid: format!("message-{uid}"),
            },
        }
    }
    #[test]
    fn selection_atomic_caps_and_rejected_inputs_preserve_exact_record() {
        let (p, s) = store();
        let mut r = LabelRecord::empty(ALICE);
        r.revision = 1;
        for n in 0..9 {
            r.labels.push(Label {
                id: format!("{n:032x}"),
                name: format!("Label {n}"),
            });
        }
        r.assignments.push(Assignment {
            key: message(2).key,
            labels: r.labels[..8].iter().map(|l| l.id.clone()).collect(),
        });
        let bytes = serde_json::to_vec(&r).unwrap();
        s.file.lock(ALICE).unwrap().write(&bytes).unwrap();
        let id = r.labels[8].id.clone();
        assert_eq!(
            s.change(
                ALICE,
                1,
                LabelChange::Selection {
                    id: &id,
                    messages: &[message(1), message(2)],
                    attach: true
                }
            ),
            Err(LabelError::Capacity)
        );
        assert_eq!(s.file.read(ALICE).unwrap().unwrap(), bytes);
        let mut foreign = message(3);
        foreign.owner = BOB.into();
        for messages in [
            vec![],
            vec![message(1), message(1)],
            vec![message(1), foreign],
            (1..=11).map(message).collect(),
        ] {
            assert_eq!(
                s.change(
                    ALICE,
                    1,
                    LabelChange::Selection {
                        id: &id,
                        messages: &messages,
                        attach: true
                    }
                ),
                Err(LabelError::Invalid)
            );
            assert_eq!(s.file.read(ALICE).unwrap().unwrap(), bytes);
        }
        assert_eq!(
            s.change(
                ALICE,
                0,
                LabelChange::Selection {
                    id: &id,
                    messages: &[message(1)],
                    attach: true
                }
            ),
            Err(LabelError::Stale)
        );
        assert_eq!(s.file.read(ALICE).unwrap().unwrap(), bytes);
        r.assignments = (1..MAX_ASSIGNED_MESSAGES)
            .map(|uid| Assignment {
                key: message(uid as u64).key,
                labels: vec![id.clone()],
            })
            .collect();
        let bytes = serde_json::to_vec(&r).unwrap();
        s.file.lock(ALICE).unwrap().write(&bytes).unwrap();
        assert_eq!(
            s.change(
                ALICE,
                1,
                LabelChange::Selection {
                    id: &id,
                    messages: &[message(2000), message(2001)],
                    attach: true
                }
            ),
            Err(LabelError::Capacity)
        );
        assert_eq!(s.file.read(ALICE).unwrap().unwrap(), bytes);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn selection_single_revision_attach_detach_and_competing_cas() {
        let (p, s) = store();
        let r = s.change(ALICE, 0, LabelChange::Create("Review")).unwrap();
        let id = r.labels()[0].id().to_owned();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let jobs = (0..2)
            .map(|n| {
                let s = s.clone();
                let id = id.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    s.change(
                        ALICE,
                        1,
                        LabelChange::Selection {
                            id: &id,
                            messages: &[message(1 + n * 2), message(2 + n * 2)],
                            attach: true,
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = jobs
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(LabelError::Stale))
                .count(),
            1
        );
        let r = s.load(ALICE).unwrap();
        assert_eq!(r.revision(), 2);
        assert_eq!(r.assigned_messages(), 2);
        let messages = r
            .assignments
            .iter()
            .map(|a| MessageIdentity {
                owner: ALICE.into(),
                key: a.key.clone(),
            })
            .collect::<Vec<_>>();
        let r = s
            .change(
                ALICE,
                2,
                LabelChange::Selection {
                    id: &id,
                    messages: &messages,
                    attach: false,
                },
            )
            .unwrap();
        assert_eq!(r.revision(), 3);
        assert_eq!(r.assigned_messages(), 0);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn private_roundtrip_cas_names_and_account_binding() {
        let (p, s) = store();
        let r = s
            .change(ALICE, 0, LabelChange::Create("Review 🦊 / ../metadata"))
            .unwrap();
        let id = r.labels()[0].id().to_owned();
        assert!(valid_id(&id));
        assert_eq!(s.load(ALICE).unwrap(), r);
        assert_eq!(s.load(BOB).unwrap().assigned_messages(), 0);
        let r = s
            .change(
                ALICE,
                r.revision(),
                LabelChange::Attach {
                    id: &id,
                    message: &message(1),
                },
            )
            .unwrap();
        assert_eq!(r.labels_for(&message(1)).unwrap().len(), 1);
        assert_eq!(
            s.change(ALICE, 0, LabelChange::Delete(&id)),
            Err(LabelError::Stale)
        );
        assert_eq!(
            s.change(
                BOB,
                0,
                LabelChange::Attach {
                    id: &id,
                    message: &message(1)
                }
            ),
            Err(LabelError::Invalid)
        );
        let mut foreign = message(1);
        foreign.owner = BOB.into();
        assert_eq!(r.labels_for(&foreign), Err(LabelError::Invalid));
        let reopened = LabelStore::new(&p);
        assert_eq!(reopened.load(ALICE).unwrap(), r);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for f in std::fs::read_dir(&p).unwrap() {
                assert_eq!(
                    f.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                )
            }
        }
        for name in [
            "",
            " bad",
            "bad\n",
            "bad\u{202e}",
            &"é".repeat(33),
            &"🦊".repeat(33),
        ] {
            assert_eq!(
                s.change(ALICE, r.revision(), LabelChange::Create(name)),
                Err(LabelError::Invalid)
            );
        }
        let renamed = s
            .change(
                ALICE,
                r.revision(),
                LabelChange::Rename {
                    id: &id,
                    name: &"🦊".repeat(32),
                },
            )
            .unwrap();
        assert_eq!(renamed.labels()[0].name().len(), 128);
        let bytes = s.file.read(ALICE).unwrap().unwrap();
        s.file.lock(BOB).unwrap().write(&bytes).unwrap();
        assert_eq!(s.load(BOB), Err(LabelError::Corrupt));
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn stale_identity_confirmed_move_and_delete_cleanup() {
        let (p, s) = store();
        let r = s.change(ALICE, 0, LabelChange::Create("One")).unwrap();
        let id = r.labels()[0].id().to_owned();
        let source = message(1);
        let r = s
            .change(
                ALICE,
                r.revision(),
                LabelChange::Attach {
                    id: &id,
                    message: &source,
                },
            )
            .unwrap();
        let mut reused = source.clone();
        reused.key.message_guid = "different".into();
        assert!(r.labels_for(&reused).unwrap().is_empty());
        let mut dest = source.clone();
        dest.key.folder = "Archive".into();
        dest.key.mailbox_guid = "b".repeat(32);
        dest.key.uid = 7;
        assert_eq!(
            s.reconcile_confirmed_move(ALICE, r.revision(), &source, &reused),
            Err(LabelError::Invalid)
        );
        assert_eq!(s.load(ALICE).unwrap(), r);
        let r = s
            .reconcile_confirmed_move(ALICE, r.revision(), &source, &dest)
            .unwrap();
        assert!(r.labels_for(&source).unwrap().is_empty());
        assert_eq!(r.labels_for(&dest).unwrap().len(), 1);
        let r = s
            .change(
                ALICE,
                r.revision(),
                LabelChange::Detach {
                    id: &id,
                    message: &dest,
                },
            )
            .unwrap();
        assert_eq!(r.assigned_messages(), 0);
        let r = s
            .change(
                ALICE,
                r.revision(),
                LabelChange::Attach {
                    id: &id,
                    message: &dest,
                },
            )
            .unwrap();
        let r = s
            .forget_confirmed_message(ALICE, r.revision(), &source)
            .unwrap();
        assert_eq!(r.assigned_messages(), 1);
        let r = s
            .forget_confirmed_message(ALICE, r.revision(), &dest)
            .unwrap();
        assert_eq!(r.assigned_messages(), 0);
        let r = s
            .change(
                ALICE,
                r.revision(),
                LabelChange::Attach {
                    id: &id,
                    message: &source,
                },
            )
            .unwrap();
        let r = s
            .change(ALICE, r.revision(), LabelChange::Delete(&id))
            .unwrap();
        assert!(r.labels().is_empty());
        assert_eq!(r.assigned_messages(), 0);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn limits_refuse_without_truncating_and_move_merge_is_atomic() {
        let (p, s) = store();
        let mut r = LabelRecord::empty(ALICE);
        r.revision = 1;
        for n in 0..MAX_LABELS {
            r.labels.push(Label {
                id: format!("{n:032x}"),
                name: format!("Label {n}"),
            })
        }
        let id = r.labels[0].id.clone();
        let ids = r
            .labels
            .iter()
            .take(8)
            .map(|l| l.id.clone())
            .collect::<Vec<_>>();
        for n in 1..=MAX_ASSIGNED_MESSAGES {
            r.assignments.push(Assignment {
                key: message(n as u64).key,
                labels: ids.clone(),
            })
        }
        let bytes = serde_json::to_vec(&r).unwrap();
        assert!(bytes.len() < MAX_RECORD_BYTES);
        s.file.lock(ALICE).unwrap().write(&bytes).unwrap();
        assert_eq!(
            s.change(ALICE, 1, LabelChange::Create("Extra")),
            Err(LabelError::Capacity)
        );
        assert_eq!(
            s.change(
                ALICE,
                1,
                LabelChange::Attach {
                    id: &id,
                    message: &message(2001)
                }
            ),
            Err(LabelError::Capacity)
        );
        assert_eq!(
            s.change(
                ALICE,
                1,
                LabelChange::Attach {
                    id: &r.labels[8].id,
                    message: &message(1)
                }
            ),
            Err(LabelError::Capacity)
        );
        assert_eq!(s.load(ALICE).unwrap(), r);
        let mut altered = r.clone();
        altered.assignments[1].labels = vec![r.labels[8].id.clone()];
        altered.assignments[1].key.message_guid = altered.assignments[0].key.message_guid.clone();
        s.file
            .lock(ALICE)
            .unwrap()
            .write(&serde_json::to_vec(&altered).unwrap())
            .unwrap();
        let target = MessageIdentity {
            owner: ALICE.into(),
            key: altered.assignments[1].key.clone(),
        };
        assert_eq!(
            s.reconcile_confirmed_move(ALICE, 1, &message(1), &target),
            Err(LabelError::Capacity)
        );
        assert_eq!(s.load(ALICE).unwrap(), altered);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn race_and_malformed_record_refusal() {
        let (p, s) = store();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = vec![];
        for name in ["A", "B"] {
            let s = s.clone();
            let b = barrier.clone();
            threads.push(std::thread::spawn(move || {
                b.wait();
                s.change(ALICE, 0, LabelChange::Create(name))
            }));
        }
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == Err(LabelError::Stale))
                .count(),
            1
        );
        let good = s.file.read(ALICE).unwrap().unwrap();
        let text = String::from_utf8(good.clone()).unwrap();
        for corrupt in [
            text.replacen("\"version\":1", "\"version\":2", 1)
                .into_bytes(),
            text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                .into_bytes(),
            text.replacen("\"version\":1", "\"extra\":1,\"version\":1", 1)
                .into_bytes(),
            vec![255],
        ] {
            s.file.lock(ALICE).unwrap().write(&corrupt).unwrap();
            assert_eq!(
                s.change(ALICE, 1, LabelChange::Create("C")),
                Err(LabelError::Corrupt)
            );
            assert_eq!(s.file.read(ALICE).unwrap().unwrap(), corrupt);
        }
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn owned_summary_boundary_and_structural_corruption() {
        let identity = message(1);
        let mut row = MessageSummary {
            mailbox_name: "INBOX".into(),
            uid: 1,
            flags: vec![],
            date_received: String::new(),
            size_virtual: 0,
            subject: None,
            from: None,
            to: None,
            metadata: Some(crate::message_metadata::MessageMetadata {
                threading: None,
                attachments: None,
                protection: crate::message_metadata::MessageProtection::Unknown,
                version: crate::message_metadata::MessageVersion::new(
                    "a".repeat(32),
                    "message-1".into(),
                )
                .unwrap(),
                attachment_count: None,
                preview: None,
            }),
        };
        assert_eq!(
            MessageIdentity::from_summary(ALICE, ALICE, "INBOX", &row),
            Ok(identity.clone())
        );
        assert_eq!(
            MessageIdentity::from_summary(ALICE, BOB, "INBOX", &row),
            Err(LabelError::Invalid)
        );
        assert_eq!(
            MessageIdentity::from_summary(ALICE, ALICE, "Sent", &row),
            Err(LabelError::Invalid)
        );
        row.uid = 0;
        assert_eq!(
            MessageIdentity::from_summary(ALICE, ALICE, "INBOX", &row),
            Err(LabelError::Invalid)
        );
        row.uid = 1;
        row.metadata = None;
        assert_eq!(
            MessageIdentity::from_summary(ALICE, ALICE, "INBOX", &row),
            Err(LabelError::Invalid)
        );
        let mut r = LabelRecord::empty(ALICE);
        r.revision = 1;
        r.labels.push(Label {
            id: "a".repeat(32),
            name: "One".into(),
        });
        r.assignments.push(Assignment {
            key: identity.key,
            labels: vec!["b".repeat(32)],
        });
        assert_eq!(
            LabelRecord::parse(ALICE, Some(serde_json::to_vec(&r).unwrap())),
            Err(LabelError::Corrupt)
        );
        r.assignments[0].labels = vec!["a".repeat(32); 2];
        assert_eq!(
            LabelRecord::parse(ALICE, Some(serde_json::to_vec(&r).unwrap())),
            Err(LabelError::Corrupt)
        );
    }
}
