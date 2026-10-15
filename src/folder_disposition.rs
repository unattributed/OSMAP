//! Preserve one private leaf container in the exact Bin, then restore by receipt.
//! No message copy/delete, recursive operation, expunge, or uncertain replay.
use crate::{
    bin_folder::BinPreference,
    folder_create::Refusal,
    folder_metadata::FolderSnapshot,
    folder_rename::{Completion, Outcome, RenameFolderRequest, RoleLease},
    mailbox::MailboxBackend,
    mailbox_status::MailboxStatus,
    private_account_file::{LockedAccountFile, PrivateAccountFile},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_RECEIPTS: usize = 12;
const MAX_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub receipt_id: String,
    pub bin: String,
    pub bin_guid: String,
    pub bin_revision: u64,
    pub original_action: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Purpose {
    Bin(Context),
    Restore(Context),
}
impl Purpose {
    pub fn context(&self) -> &Context {
        match self {
            Self::Bin(value) | Self::Restore(value) => value,
        }
    }
    pub fn restoring(&self) -> bool {
        matches!(self, Self::Restore(_))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    BinReserved,
    BinPending,
    Binned,
    RestoreReserved,
    RestorePending,
    Restored,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub id: String,
    pub source: String,
    pub parent_guid: String,
    pub folder_guid: String,
    pub bin: String,
    pub bin_guid: String,
    pub bin_revision: u64,
    pub original_action: String,
    pub restore_action: Option<String>,
    pub state: State,
}
impl Receipt {
    pub fn stored_name(&self) -> String {
        format!("{}.OSMAP-Deleted-{}", self.bin, self.id)
    }
    fn context(&self) -> Context {
        Context {
            receipt_id: self.id.clone(),
            bin: self.bin.clone(),
            bin_guid: self.bin_guid.clone(),
            bin_revision: self.bin_revision,
            original_action: self.original_action.clone(),
        }
    }
    pub fn bin_request(
        account: &str,
        source: &str,
        guid: &str,
        parent_guid: &str,
        bin: &BinPreference,
        bin_guid: &str,
    ) -> Result<RenameFolderRequest, Refusal> {
        let nonce = crate::draft::generate_draft_id().map_err(|_| Refusal::Unavailable)?;
        RenameFolderRequest::for_disposition(
            account,
            source,
            guid,
            parent_guid,
            &bin.mailbox_name,
            bin_guid,
            &format!("OSMAP-Deleted-{nonce}"),
            &nonce,
            Purpose::Bin(Context {
                receipt_id: nonce.clone(),
                bin: bin.mailbox_name.clone(),
                bin_guid: bin_guid.into(),
                bin_revision: bin.revision,
                original_action: nonce.clone(),
            }),
        )
    }
    pub fn restore_request(&self, account: &str) -> Result<RenameFolderRequest, Refusal> {
        self.validate(account)?;
        if self.state != State::Binned {
            return Err(Refusal::Unavailable);
        }
        let (parent, leaf) = self.source.rsplit_once('.').ok_or(Refusal::Invalid)?;
        let nonce = crate::draft::generate_draft_id().map_err(|_| Refusal::Unavailable)?;
        RenameFolderRequest::for_disposition(
            account,
            &self.stored_name(),
            &self.folder_guid,
            &self.bin_guid,
            parent,
            &self.parent_guid,
            leaf,
            &nonce,
            Purpose::Restore(self.context()),
        )
    }
    fn validate(&self, account: &str) -> Result<(), Refusal> {
        if !nonce(&self.id)
            || self.id != self.original_action
            || self
                .restore_action
                .as_ref()
                .is_some_and(|v| !nonce(v) || *v == self.original_action)
            || matches!(
                self.state,
                State::RestoreReserved | State::RestorePending | State::Restored
            ) && self.restore_action.is_none()
            || matches!(self.state, State::BinReserved | State::BinPending)
                && self.restore_action.is_some()
        {
            return Err(Refusal::Invalid);
        }
        let (parent, leaf) = self.source.rsplit_once('.').ok_or(Refusal::Invalid)?;
        crate::folder_create::CreateFolderRequest::new(account, parent, &self.parent_guid, leaf)?;
        if crate::folder_rename::protected_name(&self.source)
            || self.folder_guid == self.parent_guid
            || self.folder_guid == self.bin_guid
            || self.parent_guid == self.bin_guid
        {
            return Err(Refusal::Invalid);
        }
        MailboxStatus::new(&self.source, &self.folder_guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        MailboxStatus::new(&self.bin, &self.bin_guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        crate::bin_folder::parse_mailbox_name(&self.bin).map_err(|_| Refusal::Invalid)?;
        crate::mailbox_status::validate_name(&self.stored_name()).map_err(|_| Refusal::Invalid)?;
        Ok(())
    }
    pub(crate) fn matches(&self, request: &RenameFolderRequest) -> bool {
        let Some(purpose) = request.disposition() else {
            return false;
        };
        purpose.context() == &self.context()
            && request.source_guid() == self.folder_guid
            && if purpose.restoring() {
                request.source() == self.stored_name()
                    && request.destination() == self.source
                    && request.parent_guid() == self.parent_guid
                    && request.source_parent_guid() == self.bin_guid
                    && (self.state == State::Binned
                        || self.restore_action.as_deref() == Some(request.action_nonce()))
            } else {
                request.source() == self.source
                    && request.destination() == self.stored_name()
                    && request.source_parent_guid() == self.parent_guid
                    && request.parent_guid() == self.bin_guid
                    && request.action_nonce() == self.original_action
            }
    }
}

fn nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn validate_request(request: &RenameFolderRequest) -> Result<(), Refusal> {
    let purpose = request.disposition().ok_or(Refusal::Invalid)?;
    let context = purpose.context();
    if !request.is_move()
        || !nonce(request.action_nonce())
        || !nonce(&context.receipt_id)
        || context.original_action != context.receipt_id
        || request.source_guid() == request.parent_guid()
        || request.source_guid() == request.source_parent_guid()
        || request.parent_guid() == request.source_parent_guid()
    {
        return Err(Refusal::Invalid);
    }
    crate::identity::CanonicalUsername::parse(request.account()).map_err(|_| Refusal::Invalid)?;
    for (name, guid) in [
        (request.source(), request.source_guid()),
        (request.parent(), request.parent_guid()),
        (request.source_parent(), request.source_parent_guid()),
        (&context.bin, &context.bin_guid),
    ] {
        MailboxStatus::new(name, guid, 0, 0).map_err(|_| Refusal::Invalid)?;
    }
    crate::bin_folder::parse_mailbox_name(&context.bin).map_err(|_| Refusal::Invalid)?;
    let stored = format!("{}.OSMAP-Deleted-{}", context.bin, context.receipt_id);
    crate::mailbox_status::validate_name(&request.destination()).map_err(|_| Refusal::Invalid)?;
    if purpose.restoring() {
        crate::folder_create::CreateFolderRequest::new(
            request.account(),
            request.parent(),
            request.parent_guid(),
            request.leaf(),
        )?;
        if request.source() != stored
            || request.source_parent_guid() != context.bin_guid
            || request.action_nonce() == context.original_action
            || crate::folder_rename::protected_name(&request.destination())
        {
            return Err(Refusal::Invalid);
        }
    } else {
        let (parent, leaf) = request.source().rsplit_once('.').ok_or(Refusal::Invalid)?;
        crate::folder_create::CreateFolderRequest::new(
            request.account(),
            parent,
            request.source_parent_guid(),
            leaf,
        )?;
        if request.destination() != stored
            || request.parent_guid() != context.bin_guid
            || request.action_nonce() != context.original_action
            || crate::folder_rename::protected_name(request.source())
            || context.bin == request.source()
            || context.bin.starts_with(&format!("{}.", request.source()))
            || request.source().starts_with(&format!("{}.", context.bin))
        {
            return Err(Refusal::Invalid);
        }
    }
    // The existing signed helper's decoded request cap is 2048 bytes. Keep it
    // unchanged and refuse before publishing any pending action or receipt.
    if serde_json::to_vec(request)
        .map_err(|_| Refusal::Unavailable)?
        .len()
        > 2048
    {
        return Err(Refusal::Capacity);
    }
    Ok(())
}

fn validate_bin(
    account: &str,
    context: &Context,
    snapshot: &FolderSnapshot,
    status: &MailboxStatus,
) -> Result<(), Refusal> {
    snapshot
        .validate_for(account)
        .map_err(|_| Refusal::Unavailable)?;
    status
        .validate(&context.bin)
        .map_err(|_| Refusal::Unavailable)?;
    if status.guid() != context.bin_guid {
        return Err(Refusal::Stale);
    }
    crate::folder_create::validate_private_namespace(snapshot, &context.bin)?;
    let folder = snapshot
        .folder(account, &context.bin)
        .map_err(|_| Refusal::Unavailable)?;
    if !crate::bin_folder::selectable(snapshot, account, &context.bin)
        || context.bin.split('.').enumerate().any(|(index, part)| {
            crate::folder_rename::protected_name(&format!("INBOX.{part}"))
                && !(part.eq_ignore_ascii_case("trash")
                    || part.eq_ignore_ascii_case("bin")
                    || index == 0 && part == "INBOX")
        })
        || folder.delimiter() != Some('.')
        || folder.flags().iter().any(|flag| {
            ![
                "\\HasChildren",
                "\\HasNoChildren",
                "\\Subscribed",
                "\\Marked",
                "\\Unmarked",
                "\\Trash",
            ]
            .iter()
            .any(|v| flag.eq_ignore_ascii_case(v))
        })
    {
        return Err(Refusal::Invalid);
    }
    for ancestor in snapshot
        .folders()
        .iter()
        .filter(|f| context.bin.starts_with(&format!("{}.", f.name())))
    {
        if ancestor
            .special_use()
            .iter()
            .any(|role| !role.eq_ignore_ascii_case("\\Trash"))
            || ancestor.has_flag("\\NonExistent")
            || ancestor.has_flag("\\Noselect")
            || ancestor.has_flag("\\Noinferiors")
        {
            return Err(Refusal::Invalid);
        }
    }
    Ok(())
}
fn validate_stored_leaf(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    status: &MailboxStatus,
    name: &str,
) -> Result<(), Refusal> {
    snapshot
        .validate_for(request.account())
        .map_err(|_| Refusal::Unavailable)?;
    status.validate(name).map_err(|_| Refusal::Unavailable)?;
    crate::folder_create::validate_private_namespace(snapshot, name)?;
    let folder = snapshot
        .folder(request.account(), name)
        .map_err(|_| Refusal::Unavailable)?;
    if status.guid() != request.source_guid() {
        return Err(Refusal::Stale);
    }
    if folder.delimiter() != Some('.')
        || folder.flags().iter().any(|flag| {
            !["\\HasNoChildren", "\\Subscribed", "\\Marked", "\\Unmarked"]
                .iter()
                .any(|v| flag.eq_ignore_ascii_case(v))
        })
        || snapshot
            .folders()
            .iter()
            .any(|f| f.name().starts_with(&format!("{name}.")))
    {
        return Err(Refusal::Invalid);
    }
    Ok(())
}
pub(crate) fn validate_source_parent(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    parent: &MailboxStatus,
) -> Result<(), Refusal> {
    let purpose = request.disposition().ok_or(Refusal::Invalid)?;
    if purpose.restoring() {
        validate_bin(request.account(), purpose.context(), snapshot, parent)
    } else {
        match crate::folder_create::validate_creation_parent(
            request.account(),
            request.source_parent(),
            snapshot,
            parent,
        ) {
            Ok(()) | Err(Refusal::Capacity) => (),
            Err(e) => return Err(e),
        }
        if parent.guid() != request.source_parent_guid() {
            return Err(Refusal::Stale);
        }
        Ok(())
    }
}
pub(crate) fn validate_destination_parent(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    parent: &MailboxStatus,
) -> Result<(), Refusal> {
    let purpose = request.disposition().ok_or(Refusal::Invalid)?;
    if !purpose.restoring() {
        return validate_bin(request.account(), purpose.context(), snapshot, parent);
    }
    match crate::folder_create::validate_creation_parent(
        request.account(),
        request.parent(),
        snapshot,
        parent,
    ) {
        Ok(()) | Err(Refusal::Capacity) => (),
        Err(e) => return Err(e),
    }
    if parent.guid() != request.parent_guid() {
        return Err(Refusal::Stale);
    }
    if request.parent() != "INBOX" && crate::folder_rename::protected_name(request.parent()) {
        return Err(Refusal::Invalid);
    }
    for folder in snapshot.folders().iter().filter(|f| {
        f.name() == request.parent() || request.parent().starts_with(&format!("{}.", f.name()))
    }) {
        if !folder.special_use().is_empty()
            || folder.has_flag("\\Noinferiors")
            || folder.has_flag("\\NonExistent")
            || folder.has_flag("\\Noselect")
        {
            return Err(Refusal::Invalid);
        }
    }
    Ok(())
}
pub(crate) fn validate_before(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    source: &MailboxStatus,
    parent: &MailboxStatus,
) -> Result<(), Refusal> {
    validate_request(request)?;
    if request.disposition().is_some_and(Purpose::restoring) {
        validate_stored_leaf(request, snapshot, source, request.source())?
    } else {
        crate::folder_rename::validate_source(
            request.account(),
            request.source(),
            snapshot,
            source,
        )?
    }
    if source.guid() != request.source_guid() {
        return Err(Refusal::Stale);
    }
    validate_destination_parent(request, snapshot, parent)
}
pub(crate) fn confirmed_result(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    destination: &MailboxStatus,
    parent: &MailboxStatus,
) -> bool {
    if validate_request(request).is_err()
        || validate_destination_parent(request, snapshot, parent).is_err()
        || snapshot.folder(request.account(), request.source()).is_ok()
        || destination.guid() != request.source_guid()
    {
        return false;
    }
    if request.disposition().is_some_and(Purpose::restoring) {
        crate::folder_rename::validate_source(
            request.account(),
            &request.destination(),
            snapshot,
            destination,
        )
        .is_ok()
    } else {
        validate_stored_leaf(request, snapshot, destination, &request.destination()).is_ok()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    account: String,
    receipts: Vec<Receipt>,
}
struct Receipts {
    file: LockedAccountFile,
    record: Record,
}
impl Receipts {
    fn lock(directory: &Path, account: &str) -> Result<Self, Refusal> {
        let file =
            PrivateAccountFile::new(directory.into(), "osmap-folder-disposition-v1", MAX_BYTES)
                .lock(account)
                .map_err(|_| Refusal::Unavailable)?;
        let record = match file.read().map_err(|_| Refusal::Unavailable)? {
            None => Record {
                version: 1,
                account: account.into(),
                receipts: vec![],
            },
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| Refusal::Unavailable)?,
        };
        let result = Self { file, record };
        result.validate(account)?;
        Ok(result)
    }
    fn validate(&self, account: &str) -> Result<(), Refusal> {
        if self.record.version != 1
            || self.record.account != account
            || self.record.receipts.len() > MAX_RECEIPTS
        {
            return Err(Refusal::Unavailable);
        }
        for (i, receipt) in self.record.receipts.iter().enumerate() {
            receipt
                .validate(account)
                .map_err(|_| Refusal::Unavailable)?;
            if self.record.receipts[..i]
                .iter()
                .any(|other| other.id == receipt.id || other.folder_guid == receipt.folder_guid)
            {
                return Err(Refusal::Unavailable);
            }
        }
        self.reserved_bytes().map(|_| ())
    }
    fn reserved_bytes(&self) -> Result<Vec<u8>, Refusal> {
        // Reserve the exact longest later state and restore nonce for EVERY row.
        let future = Record {
            version: 1,
            account: self.record.account.clone(),
            receipts: self
                .record
                .receipts
                .iter()
                .cloned()
                .map(|mut receipt| {
                    receipt.state = State::RestoreReserved;
                    receipt.restore_action = Some("f".repeat(32));
                    receipt
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&future).map_err(|_| Refusal::Unavailable)?;
        if bytes.len() > MAX_BYTES || future.receipts.len() > MAX_RECEIPTS {
            return Err(Refusal::Capacity);
        }
        Ok(bytes)
    }
    fn publish(&self) -> Result<(), Refusal> {
        self.validate(&self.record.account)?;
        let bytes = serde_json::to_vec(&self.record).map_err(|_| Refusal::Unavailable)?;
        if bytes.len() > MAX_BYTES {
            return Err(Refusal::Capacity);
        }
        self.file.write(&bytes).map_err(|_| Refusal::Unavailable)
    }
}
pub(crate) fn list(directory: &Path, account: &str) -> Result<Vec<Receipt>, Refusal> {
    // All callers use role -> receipt order, including read-only presentation.
    let _role = crate::folder_rename::role_lease(directory, account)?;
    Ok(Receipts::lock(directory, account)?.record.receipts)
}
/// Caller retains the shared role lease through native dispatch. Earlier Bins
/// remain protected by their account receipt even after the preference changes.
pub(crate) fn guard_ordinary(
    directory: &Path,
    role: &RoleLease,
    source: &str,
    destination: &str,
) -> Result<(), Refusal> {
    let receipts = Receipts::lock(directory, role.account())?;
    let names = protected_names(&receipts.record.receipts);
    if crate::folder_rename::role_conflict(&names, source, destination) {
        return Err(Refusal::Invalid);
    }
    Ok(())
}
pub(crate) fn protected_names(receipts: &[Receipt]) -> Vec<String> {
    receipts
        .iter()
        .filter(|r| !matches!(r.state, State::Restored | State::Cancelled))
        .map(Receipt::stored_name)
        .collect()
}

fn fresh_result<B: MailboxBackend>(
    backend: &B,
    request: &RenameFolderRequest,
    changed: bool,
) -> bool {
    let (Ok(snapshot), Ok(parent), Ok(source_parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), request.parent()),
        backend.mailbox_status(request.account(), request.source_parent()),
    ) else {
        return false;
    };
    if validate_source_parent(request, &snapshot, &source_parent).is_err() {
        return false;
    }
    if changed {
        backend
            .mailbox_status(request.account(), &request.destination())
            .is_ok_and(|dest| confirmed_result(request, &snapshot, &dest, &parent))
    } else {
        backend
            .mailbox_status(request.account(), request.source())
            .is_ok_and(|source| {
                validate_before(request, &snapshot, &source, &parent).is_ok()
                    && snapshot
                        .folder(request.account(), &request.destination())
                        .is_err()
            })
    }
}
fn settle<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    role: &mut RoleLease,
    receipts: &mut Receipts,
    request: &RenameFolderRequest,
    changed: bool,
) -> Result<(), Refusal> {
    let purpose = request.disposition().ok_or(Refusal::Invalid)?;
    let i = receipts
        .record
        .receipts
        .iter()
        .position(|r| r.matches(request))
        .ok_or(Refusal::Unavailable)?;
    if changed {
        if backend.folder_rename_completion(request) != Completion::Renamed
            || !fresh_result(backend, request, true)
        {
            return Err(Refusal::Unavailable);
        }
        crate::folder_rename::reconcile_metadata(directory, request)?;
        receipts.record.receipts[i].state = if request.disposition().is_some_and(Purpose::restoring)
        {
            State::Restored
        } else {
            State::Binned
        };
    } else {
        if backend.folder_rename_completion(request) != Completion::NoMutation
            || !fresh_result(backend, request, false)
        {
            return Err(Refusal::Unavailable);
        }
        if request.disposition().is_some_and(Purpose::restoring) {
            receipts.record.receipts[i].state = State::Binned;
        } else {
            receipts.record.receipts[i].state = State::Cancelled;
        }
    }
    receipts.publish()?;
    role.confirm()?;
    if changed && request.disposition().is_some_and(Purpose::restoring)
        || !changed && !request.disposition().is_some_and(Purpose::restoring)
    {
        receipts
            .record
            .receipts
            .retain(|r| r.id != purpose.context().receipt_id);
        receipts.publish()?;
    }
    Ok(())
}

fn current_roles(directory: &Path, account: &str) -> Result<(BinPreference, Vec<String>), Refusal> {
    let bin = crate::bin_folder::BinPreferencesStore::new(directory)
        .load(account)
        .map_err(|_| Refusal::Unavailable)?;
    let sent = crate::sent_location::Store::new(directory)
        .load(account)
        .map_err(|_| Refusal::Unavailable)?;
    if !sent.valid() {
        return Err(Refusal::Unavailable);
    }
    let settings = crate::settings::UserSettingsStore::load(
        &crate::settings::FileUserSettingsStore::new(directory),
        account,
    )
    .map_err(|_| Refusal::Unavailable)?
    .unwrap_or_default();
    let mut names = vec![sent.mailbox_name];
    names.extend(settings.archive_mailbox_name);
    Ok((bin, names))
}
pub(crate) fn prepare_bin<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    account: &str,
    source: &str,
) -> Result<RenameFolderRequest, Refusal> {
    let _role = crate::folder_rename::settings_gate(directory, account)?;
    let (bin, names) = current_roles(directory, account)?;
    let parent = source.rsplit_once('.').ok_or(Refusal::Invalid)?.0;
    let status = backend
        .mailbox_status(account, source)
        .map_err(|_| Refusal::Unavailable)?;
    let parent = backend
        .mailbox_status(account, parent)
        .map_err(|_| Refusal::Unavailable)?;
    let bin_status = backend
        .mailbox_status(account, &bin.mailbox_name)
        .map_err(|_| Refusal::Unavailable)?;
    let request = Receipt::bin_request(
        account,
        source,
        status.guid(),
        parent.guid(),
        &bin,
        bin_status.guid(),
    )?;
    if crate::folder_rename::role_conflict(&names, source, &request.destination())
        || !fresh_result(backend, &request, false)
    {
        return Err(Refusal::Invalid);
    }
    Ok(request)
}

// Publish the exact private reservation before taking the role intent. Kept
// separate so interruption of this publication boundary is recoverable.
fn reserve_before_dispatch(
    receipts: &mut Receipts,
    request: &RenameFolderRequest,
    role: &RoleLease,
) -> Result<(), Refusal> {
    let purpose = request.disposition().ok_or(Refusal::Invalid)?;
    // A prior interrupted reservation must be explicitly checked first. The
    // shared role lock serializes this test with both receipt publications.
    if receipts
        .record
        .receipts
        .iter()
        .any(|r| r.state != State::Binned)
    {
        return Err(Refusal::Unavailable);
    }
    if purpose.restoring() {
        let Some(receipt) = receipts
            .record
            .receipts
            .iter_mut()
            .find(|r| r.id == purpose.context().receipt_id)
        else {
            return Err(Refusal::Invalid);
        };
        if receipt.state != State::Binned || !receipt.matches(request) {
            return Err(Refusal::Stale);
        }
        receipt.restore_action = Some(request.action_nonce().into());
        receipt.state = State::RestoreReserved;
    } else {
        if receipts.record.receipts.len() >= MAX_RECEIPTS
            || receipts.record.receipts.iter().any(|r| {
                r.id == purpose.context().receipt_id || r.folder_guid == request.source_guid()
            })
        {
            return Err(Refusal::Capacity);
        }
        receipts.record.receipts.push(Receipt {
            id: purpose.context().receipt_id.clone(),
            source: request.source().into(),
            parent_guid: request.source_parent_guid().into(),
            folder_guid: request.source_guid().into(),
            bin: purpose.context().bin.clone(),
            bin_guid: purpose.context().bin_guid.clone(),
            bin_revision: purpose.context().bin_revision,
            original_action: request.action_nonce().into(),
            restore_action: None,
            state: State::BinReserved,
        });
        let mut future = receipts
            .record
            .receipts
            .last()
            .cloned()
            .ok_or(Refusal::Unavailable);
        if let Ok(receipt) = future.as_mut() {
            receipt.state = State::Binned;
        }
        if future
            .and_then(|receipt| receipt.restore_request(request.account()))
            .and_then(|restore| role.can_begin(&restore))
            .is_err()
        {
            return Err(Refusal::Capacity);
        }
    }
    receipts.reserved_bytes()?;
    receipts.publish()
}

fn mark_dispatch_ready(
    receipts: &mut Receipts,
    request: &RenameFolderRequest,
) -> Result<(), Refusal> {
    let restoring = request.disposition().ok_or(Refusal::Invalid)?.restoring();
    let receipt = receipts
        .record
        .receipts
        .iter_mut()
        .find(|r| r.matches(request))
        .ok_or(Refusal::Unavailable)?;
    if receipt.state
        != if restoring {
            State::RestoreReserved
        } else {
            State::BinReserved
        }
    {
        return Err(Refusal::Unavailable);
    }
    receipt.state = if restoring {
        State::RestorePending
    } else {
        State::BinPending
    };
    // Helper dispatch is impossible until BOTH role.begin and this durable
    // publication succeed. On any error, only a freshly reloaded phase can
    // establish whether the reservation is still provably undispatched.
    receipts.publish()
}

fn finish_no_mutation(
    role: &mut RoleLease,
    receipts: &mut Receipts,
    request: &RenameFolderRequest,
) -> Result<(), Refusal> {
    if role.account() != request.account() || role.pending() != Some(request) {
        return Err(Refusal::Unavailable);
    }
    let restoring = request.disposition().ok_or(Refusal::Invalid)?.restoring();
    let i = receipts
        .record
        .receipts
        .iter()
        .position(|r| r.matches(request))
        .ok_or(Refusal::Unavailable)?;
    let receipt = &mut receipts.record.receipts[i];
    match (&receipt.state, restoring) {
        (State::BinReserved, false) => receipt.state = State::Cancelled,
        (State::RestoreReserved, true) => receipt.state = State::Binned,
        // A previous explicit check durably recorded this terminal no-mutation
        // result but may have failed to clear the role. Binned is terminal for
        // this Restore only with its exact retained restore action.
        (State::Cancelled, false) => (),
        (State::Binned, true)
            if receipt.restore_action.as_deref() == Some(request.action_nonce()) => {}
        _ => return Err(Refusal::Unavailable),
    }
    receipts.publish()?;
    role.confirm()?;
    if !restoring {
        receipts.record.receipts.remove(i);
        receipts.publish()?;
    }
    Ok(())
}

pub(crate) fn execute<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    request: &RenameFolderRequest,
    now: u64,
) -> Outcome {
    if validate_request(request).is_err() {
        return Outcome::Refused(Refusal::Invalid);
    }
    let Ok(mut role) = crate::folder_rename::settings_gate(directory, request.account()) else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    let Ok((current_bin, other_roles)) = current_roles(directory, request.account()) else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    let Ok(mut receipts) = Receipts::lock(directory, request.account()) else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    let Some(purpose) = request.disposition() else {
        return Outcome::Refused(Refusal::Invalid);
    };
    if crate::folder_rename::role_conflict(&other_roles, request.source(), &request.destination()) {
        return Outcome::Refused(Refusal::Invalid);
    }
    if !purpose.restoring()
        && (current_bin.mailbox_name != purpose.context().bin
            || current_bin.revision != purpose.context().bin_revision)
    {
        return Outcome::Refused(Refusal::Stale);
    }
    if purpose.restoring()
        && crate::folder_rename::role_conflict(
            &[current_bin.mailbox_name],
            &request.destination(),
            &request.destination(),
        )
    {
        return Outcome::Refused(Refusal::Invalid);
    }
    if !fresh_result(backend, request, false) {
        return Outcome::Refused(Refusal::Stale);
    }
    if crate::labels::LabelStore::new(directory.join("labels-v1"))
        .load(request.account())
        .is_err()
        || crate::snooze::SnoozeStore::new(directory)
            .load(request.account(), now)
            .is_err()
    {
        return Outcome::Refused(Refusal::Unavailable);
    }
    if role.can_begin(request).is_err() {
        return Outcome::Refused(Refusal::Capacity);
    }
    if let Err(reason) = reserve_before_dispatch(&mut receipts, request, &role) {
        return if reason == Refusal::Unavailable {
            Outcome::Unknown
        } else {
            Outcome::Refused(reason)
        };
    }
    if role.begin(request).is_err() {
        return Outcome::Unknown;
    }
    if mark_dispatch_ready(&mut receipts, request).is_err() {
        return Outcome::Unknown;
    }
    let result = backend.rename_folder(request);
    match result {
        Outcome::Renamed => {
            if settle(directory, backend, &mut role, &mut receipts, request, true).is_ok() {
                Outcome::Renamed
            } else {
                Outcome::Unknown
            }
        }
        Outcome::Refused(_) | Outcome::Conflict => {
            if settle(directory, backend, &mut role, &mut receipts, request, false).is_ok() {
                result
            } else {
                Outcome::Unknown
            }
        }
        Outcome::Unknown => Outcome::Unknown,
    }
}
pub(crate) fn check<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    account: &str,
) -> crate::folder_rename::CheckOutcome {
    use crate::folder_rename::CheckOutcome;
    let Ok(mut role) = crate::folder_rename::role_lease(directory, account) else {
        return CheckOutcome::Unavailable;
    };
    let Some(request) = role.pending().cloned() else {
        if role.pending_delete().is_some() {
            return CheckOutcome::Unavailable;
        }
        let Ok(mut receipts) = Receipts::lock(directory, account) else {
            return CheckOutcome::Unavailable;
        };
        // Pending includes legacy rows and any possibly dispatched action. An
        // absent role cannot turn uncertainty into proof of no mutation.
        if receipts
            .record
            .receipts
            .iter()
            .any(|r| matches!(r.state, State::BinPending | State::RestorePending))
        {
            return CheckOutcome::Unconfirmed;
        }
        let mut undispatched = false;
        for receipt in &mut receipts.record.receipts {
            match receipt.state {
                State::BinReserved => {
                    receipt.state = State::Cancelled;
                    undispatched = true;
                }
                State::RestoreReserved => {
                    receipt.state = State::Binned;
                    undispatched = true;
                }
                _ => (),
            }
        }
        // Persist terminal no-mutation states before removing any reservation.
        // Failed writes never authorize an inferred state or mailbox retry.
        if undispatched && receipts.publish().is_err() {
            return CheckOutcome::Unavailable;
        }
        // Terminal cleanup is private bookkeeping only; original action and
        // Restore parent/GUID/nonce remain in every retained Binned receipt.
        let before = receipts.record.receipts.len();
        receipts
            .record
            .receipts
            .retain(|r| !matches!(r.state, State::Restored | State::Cancelled));
        if before != receipts.record.receipts.len() && receipts.publish().is_err() {
            return CheckOutcome::Unavailable;
        }
        return if undispatched {
            CheckOutcome::Unchanged
        } else {
            CheckOutcome::NoPending
        };
    };
    if request.disposition().is_none() {
        return CheckOutcome::NoPending;
    }
    let Ok(mut receipts) = Receipts::lock(directory, account) else {
        return CheckOutcome::Unavailable;
    };
    if receipts.record.receipts.iter().any(|r| {
        r.matches(&request)
            && (matches!(
                r.state,
                State::BinReserved | State::RestoreReserved | State::Cancelled
            ) || r.state == State::Binned
                && request.disposition().is_some_and(Purpose::restoring)
                && r.restore_action.as_deref() == Some(request.action_nonce()))
    }) {
        return if finish_no_mutation(&mut role, &mut receipts, &request).is_ok() {
            CheckOutcome::Unchanged
        } else {
            CheckOutcome::Unavailable
        };
    }
    match backend.folder_rename_completion(&request) {
        Completion::Renamed
            if settle(directory, backend, &mut role, &mut receipts, &request, true).is_ok() =>
        {
            CheckOutcome::Renamed {
                destination: request.destination(),
            }
        }
        Completion::NoMutation
            if settle(
                directory,
                backend,
                &mut role,
                &mut receipts,
                &request,
                false,
            )
            .is_ok() =>
        {
            CheckOutcome::Unchanged
        }
        _ => CheckOutcome::Unconfirmed,
    }
}

#[cfg(test)]
#[path = "folder_disposition_tests.rs"]
mod tests;
