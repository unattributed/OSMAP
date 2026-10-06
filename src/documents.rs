//! Account-private document lifecycle. File bytes are held by the mailbox
//! backend, so its quota authority must cover ordinary mail and documents.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::private_account_file::PrivateAccountFile;

pub const MAX_DOCUMENTS: usize = 100;
pub const MAX_FOLDERS: usize = 100;
pub const MAX_FILE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_ACCOUNT_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_NAME_BYTES: usize = 200;
const MAX_INDEX_BYTES: usize = 96 * 1024;
pub(crate) const BIN_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const RECONCILE_COOLDOWN_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NotFound,
    Stale,
    Limit,
    Busy,
    Unavailable,
    /// A backend preflight refused before any storage mutation was dispatched.
    PreDispatchUnavailable,
    /// A dispatched command has terminated and exact storage inspection
    /// confirms that no document mutation was applied.
    ConfirmedNoWrite,
    Unconfirmed,
}

#[cfg(test)]
mod native_tests {
    include!("documents_native_tests.rs");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub mailbox: String,
    pub uid: u32,
    pub mailbox_guid: String,
    pub message_guid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Uploading,
    Available,
    MovingToBin,
    InBin,
    Restoring,
    Deleting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub id: String,
    pub name: String,
    pub media_type: String,
    pub size: u64,
    pub sha256: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub folder: String,
    pub state: State,
    pub location: Option<Location>,
    pub binned_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    version: u8,
    account: String,
    pub revision: u64,
    pub documents: Vec<Document>,
    pub folders: Vec<Folder>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaStatus {
    pub used_bytes: u64,
    pub limit_bytes: u64,
}

impl Index {
    fn empty(account: &str) -> Self {
        Self {
            version: 1,
            account: account.into(),
            revision: 0,
            documents: Vec::new(),
            folders: Vec::new(),
        }
    }

    fn validate(&self, account: &str) -> Result<(), Error> {
        if self.version != 1
            || self.account != account
            || self.documents.len() > MAX_DOCUMENTS
            || self.folders.len() > MAX_FOLDERS
        {
            return Err(Error::Unavailable);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut folder_names = std::collections::BTreeSet::new();
        for folder in &self.folders {
            if !valid_id(&folder.id)
                || !ids.insert(&folder.id)
                || !valid_name(&folder.name)
                || !folder_names.insert(folder.name.to_lowercase())
            {
                return Err(Error::Unavailable);
            }
        }
        let mut bytes = 0u64;
        for document in &self.documents {
            if !valid_id(&document.id)
                || !ids.insert(&document.id)
                || !valid_name(&document.name)
                || !valid_media_type(&document.media_type)
                || document.size == 0
                || document.size > MAX_FILE_BYTES as u64
                || document.sha256.len() != 64
                || !document
                    .sha256
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                || (!document.folder.is_empty()
                    && !self
                        .folders
                        .iter()
                        .any(|folder| folder.id == document.folder))
                || document.modified_at < document.created_at
                || match document.state {
                    State::Uploading => document.location.is_some() || document.binned_at.is_some(),
                    State::Available | State::MovingToBin => {
                        document.location.is_none() || document.binned_at.is_some()
                    }
                    State::InBin | State::Restoring | State::Deleting => {
                        document.location.is_none() || document.binned_at.is_none()
                    }
                }
            {
                return Err(Error::Unavailable);
            }
            bytes = bytes.checked_add(document.size).ok_or(Error::Unavailable)?;
        }
        if bytes > MAX_ACCOUNT_BYTES {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub fn used_bytes(&self) -> u64 {
        self.documents.iter().map(|document| document.size).sum()
    }

    pub fn has_unconfirmed_change(&self) -> bool {
        self.documents.iter().any(|document| {
            matches!(
                document.state,
                State::Uploading | State::MovingToBin | State::Restoring | State::Deleting
            )
        })
    }
}

/// A backend must use the same Dovecot quota authority as ordinary delivery.
/// `quota_ready` is an attestation of both a finite account limit and active
/// enforcement on the native save path, not a local free-space estimate.
pub trait Backend {
    fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error>;
    fn quota_ready(&self, account: &str) -> Result<bool, Error> {
        Ok(self.quota_status(account)?.is_some())
    }
    fn append(
        &self,
        account: &str,
        id: &str,
        name: &str,
        media_type: &str,
        body: &[u8],
    ) -> Result<Location, Error>;
    fn read(&self, account: &str, id: &str, location: &Location) -> Result<Vec<u8>, Error>;
    fn move_to_bin(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error>;
    fn restore(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error>;
    fn expunge(&self, account: &str, id: &str, location: &Location) -> Result<(), Error>;
    fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error>;
}

#[derive(Clone, Debug)]
pub struct Store<B> {
    files: PrivateAccountFile,
    backend: B,
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    type Records = Arc<Mutex<BTreeMap<(String, String), Vec<u8>>>>;

    #[derive(Clone, Debug)]
    pub struct FixtureBackend {
        pub ready: bool,
        records: Records,
    }
    impl FixtureBackend {
        pub fn new(ready: bool) -> Self {
            Self {
                ready,
                records: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }
        pub fn with_ready(&self, ready: bool) -> Self {
            Self {
                ready,
                records: self.records.clone(),
            }
        }
    }
    impl Backend for FixtureBackend {
        fn quota_status(&self, _: &str) -> Result<Option<QuotaStatus>, Error> {
            Ok(self.ready.then_some(QuotaStatus {
                used_bytes: 0,
                limit_bytes: 1024 * 1024,
            }))
        }
        fn append(
            &self,
            account: &str,
            id: &str,
            _: &str,
            _: &str,
            body: &[u8],
        ) -> Result<Location, Error> {
            if !self.ready {
                return Err(Error::PreDispatchUnavailable);
            }
            self.records
                .lock()
                .unwrap()
                .insert((account.into(), id.into()), body.to_vec());
            Ok(Location {
                mailbox: "OSMAP.Documents".into(),
                uid: 1,
                mailbox_guid: "f".repeat(32),
                message_guid: "a".repeat(32),
            })
        }
        fn read(&self, account: &str, id: &str, _: &Location) -> Result<Vec<u8>, Error> {
            self.records
                .lock()
                .unwrap()
                .get(&(account.into(), id.into()))
                .cloned()
                .ok_or(Error::NotFound)
        }
        fn move_to_bin(&self, _: &str, _: &str, _: &Location) -> Result<Location, Error> {
            Ok(Location {
                mailbox: "OSMAP.DocumentsBin".into(),
                uid: 1,
                mailbox_guid: "f".repeat(32),
                message_guid: "a".repeat(32),
            })
        }
        fn restore(&self, _: &str, _: &str, _: &Location) -> Result<Location, Error> {
            Ok(Location {
                mailbox: "OSMAP.Documents".into(),
                uid: 1,
                mailbox_guid: "f".repeat(32),
                message_guid: "a".repeat(32),
            })
        }
        fn expunge(&self, account: &str, id: &str, _: &Location) -> Result<(), Error> {
            self.records
                .lock()
                .unwrap()
                .remove(&(account.into(), id.into()));
            Ok(())
        }
        fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .contains_key(&(account.into(), id.into()))
                .then(|| Location {
                    mailbox: "OSMAP.Documents".into(),
                    uid: 1,
                    mailbox_guid: "f".repeat(32),
                    message_guid: "a".repeat(32),
                })
                .into_iter()
                .collect())
        }
    }
}

impl<B: Backend> Store<B> {
    pub fn new(directory: PathBuf, backend: B) -> Self {
        Self {
            files: PrivateAccountFile::new(directory, "documents-v1", MAX_INDEX_BYTES),
            backend,
        }
    }

    pub fn load(&self, account: &str) -> Result<Index, Error> {
        valid_account(account)?;
        let bytes = self.files.read(account).map_err(io_error)?;
        decode(account, bytes.as_deref())
    }

    pub fn quota_ready(&self, account: &str) -> Result<bool, Error> {
        valid_account(account)?;
        self.backend.quota_ready(account)
    }

    pub fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error> {
        valid_account(account)?;
        self.backend.quota_status(account)
    }

    pub fn create_folder(
        &self,
        account: &str,
        expected_revision: u64,
        name: &str,
        now: u64,
    ) -> Result<Index, Error> {
        valid_account(account)?;
        if !valid_name(name) {
            return Err(Error::Invalid);
        }
        let locked = self.files.lock(account).map_err(io_error)?;
        let mut index = decode(account, locked.read().map_err(io_error)?.as_deref())?;
        ensure_mutable(&index, expected_revision)?;
        if index.folders.len() >= MAX_FOLDERS
            || index
                .folders
                .iter()
                .any(|folder| folder.name.eq_ignore_ascii_case(name))
        {
            return Err(Error::Limit);
        }
        if !self.backend.quota_ready(account)? {
            return Err(Error::Unavailable);
        }
        let id = crate::draft::generate_draft_id().map_err(|_| Error::Unavailable)?;
        if !valid_id(&id) || index.folders.iter().any(|folder| folder.id == id) {
            return Err(Error::Unavailable);
        }
        index.folders.push(Folder {
            id,
            name: name.into(),
            created_at: now,
        });
        increment(&mut index)?;
        write(&locked, &index)?;
        Ok(index)
    }

    pub fn move_to_folder(
        &self,
        account: &str,
        expected_revision: u64,
        document_id: &str,
        folder_id: &str,
        now: u64,
    ) -> Result<Index, Error> {
        valid_account(account)?;
        if !valid_id(document_id) || (!folder_id.is_empty() && !valid_id(folder_id)) {
            return Err(Error::Invalid);
        }
        let locked = self.files.lock(account).map_err(io_error)?;
        let mut index = decode(account, locked.read().map_err(io_error)?.as_deref())?;
        ensure_mutable(&index, expected_revision)?;
        if !folder_id.is_empty() && !index.folders.iter().any(|folder| folder.id == folder_id) {
            return Err(Error::NotFound);
        }
        let document = index
            .documents
            .iter_mut()
            .find(|doc| doc.id == document_id)
            .ok_or(Error::NotFound)?;
        if document.state != State::Available {
            return Err(Error::Invalid);
        }
        if document.folder == folder_id {
            return Ok(index);
        }
        if !self.backend.quota_ready(account)? {
            return Err(Error::Unavailable);
        }
        document.folder = folder_id.into();
        document.modified_at = now;
        increment(&mut index)?;
        write(&locked, &index)?;
        Ok(index)
    }

    /// The pending record is durable before dispatch. An uncertain native
    /// result remains visible as pending and is never retried automatically.
    pub fn upload(
        &self,
        account: &str,
        expected_revision: u64,
        name: &str,
        media_type: &str,
        body: &[u8],
        now: u64,
    ) -> Result<Index, Error> {
        valid_account(account)?;
        if !valid_name(name)
            || !valid_media_type(media_type)
            || body.is_empty()
            || body.len() > MAX_FILE_BYTES
        {
            return Err(Error::Invalid);
        }
        let locked = self.files.lock(account).map_err(io_error)?;
        let mut index = decode(account, locked.read().map_err(io_error)?.as_deref())?;
        ensure_mutable(&index, expected_revision)?;
        if index.documents.len() >= MAX_DOCUMENTS
            || index.used_bytes().saturating_add(body.len() as u64) > MAX_ACCOUNT_BYTES
        {
            return Err(Error::Limit);
        }
        let id = crate::draft::generate_draft_id().map_err(|_| Error::Unavailable)?;
        if !valid_id(&id) || index.documents.iter().any(|document| document.id == id) {
            return Err(Error::Unavailable);
        }
        index.documents.push(Document {
            id: id.clone(),
            name: name.into(),
            media_type: media_type.into(),
            size: body.len() as u64,
            sha256: format!("{:x}", Sha256::digest(body)),
            created_at: now,
            modified_at: now,
            folder: String::new(),
            state: State::Uploading,
            location: None,
            binned_at: None,
        });
        increment(&mut index)?;
        write(&locked, &index)?;
        let location = match self.backend.append(account, &id, name, media_type, body) {
            Ok(location) => location,
            Err(
                error @ (Error::Invalid
                | Error::Limit
                | Error::NotFound
                | Error::PreDispatchUnavailable
                | Error::ConfirmedNoWrite),
            ) => {
                // These are backend-confirmed no-write results. Unavailable or
                // interrupted dispatch must retain the pending record.
                index.documents.pop();
                increment(&mut index)?;
                write(&locked, &index)?;
                return Err(error);
            }
            Err(_) => return Err(Error::Unconfirmed),
        };
        let document = index.documents.last_mut().ok_or(Error::Unavailable)?;
        document.location = Some(location);
        document.state = State::Available;
        increment(&mut index)?;
        write(&locked, &index)?;
        Ok(index)
    }

    pub fn download(&self, account: &str, id: &str) -> Result<(String, Vec<u8>), Error> {
        valid_account(account)?;
        if !valid_id(id) {
            return Err(Error::Invalid);
        }
        let index = self.load(account)?;
        let document = index
            .documents
            .iter()
            .find(|doc| doc.id == id)
            .ok_or(Error::NotFound)?;
        if document.state != State::Available {
            return Err(Error::NotFound);
        }
        let location = document.location.as_ref().ok_or(Error::Unavailable)?;
        let body = self.backend.read(account, id, location)?;
        if !matches_document(document, &body) {
            return Err(Error::Unavailable);
        }
        Ok((document.name.clone(), body))
    }

    pub fn bin(
        &self,
        account: &str,
        expected_revision: u64,
        id: &str,
        now: u64,
    ) -> Result<Index, Error> {
        self.change_location(account, expected_revision, id, now, false)
    }

    pub fn restore(
        &self,
        account: &str,
        expected_revision: u64,
        id: &str,
        now: u64,
    ) -> Result<Index, Error> {
        self.change_location(account, expected_revision, id, now, true)
    }

    /// The caller must have completed an explicit confirmation step. A
    /// pending deletion is durable before its single exact native dispatch.
    pub fn delete_confirmed(
        &self,
        account: &str,
        expected_revision: u64,
        id: &str,
        now: u64,
    ) -> Result<Index, Error> {
        valid_account(account)?;
        if !valid_id(id) {
            return Err(Error::Invalid);
        }
        let locked = self.files.lock(account).map_err(io_error)?;
        let mut index = decode(account, locked.read().map_err(io_error)?.as_deref())?;
        ensure_mutable(&index, expected_revision)?;
        let position = index
            .documents
            .iter()
            .position(|doc| doc.id == id)
            .ok_or(Error::NotFound)?;
        if index.documents[position].state != State::InBin {
            return Err(Error::Invalid);
        }
        let old = index.documents[position]
            .location
            .clone()
            .ok_or(Error::Unavailable)?;
        index.documents[position].state = State::Deleting;
        index.documents[position].modified_at = now;
        increment(&mut index)?;
        write(&locked, &index)?;
        match self.backend.expunge(account, id, &old) {
            Ok(()) => {}
            Err(
                error @ (Error::Invalid
                | Error::Limit
                | Error::NotFound
                | Error::Stale
                | Error::PreDispatchUnavailable
                | Error::ConfirmedNoWrite),
            ) => {
                index.documents[position].state = State::InBin;
                increment(&mut index)?;
                write(&locked, &index)?;
                return Err(error);
            }
            Err(_) => return Err(Error::Unconfirmed),
        }
        index.documents.remove(position);
        increment(&mut index)?;
        write(&locked, &index)?;
        Ok(index)
    }

    /// Reconciles one known pending ID after the bounded native command has
    /// had time to exit. This never dispatches a second storage mutation.
    pub fn reconcile(
        &self,
        account: &str,
        expected_revision: u64,
        id: &str,
        now: u64,
    ) -> Result<Index, Error> {
        valid_account(account)?;
        if !valid_id(id) {
            return Err(Error::Invalid);
        }
        let locked = self.files.lock(account).map_err(io_error)?;
        let mut index = decode(account, locked.read().map_err(io_error)?.as_deref())?;
        let position = index
            .documents
            .iter()
            .position(|doc| doc.id == id)
            .ok_or(Error::NotFound)?;
        if index.revision != expected_revision {
            return Err(Error::Stale);
        }
        let pending = index.documents[position].clone();
        if !matches!(
            pending.state,
            State::Uploading | State::MovingToBin | State::Restoring | State::Deleting
        ) {
            return Err(Error::Invalid);
        }
        if now.saturating_sub(pending.modified_at) < RECONCILE_COOLDOWN_SECONDS {
            return Err(Error::Busy);
        }
        let mut locations = self.backend.inspect(account, id)?;
        if locations.len() > 1 {
            return Err(Error::Unconfirmed);
        }
        let current = locations.pop();
        match (pending.state, current) {
            (State::Uploading, None) | (State::Deleting, None) => {
                index.documents.remove(position);
            }
            (State::Uploading, Some(location)) if location.mailbox == "OSMAP.Documents" => {
                let bytes = self.backend.read(account, id, &location)?;
                if !matches_document(&pending, &bytes) {
                    return Err(Error::Unconfirmed);
                }
                index.documents[position].location = Some(location);
                index.documents[position].state = State::Available;
            }
            (State::MovingToBin | State::Restoring | State::Deleting, Some(location)) => {
                let old = pending.location.as_ref().ok_or(Error::Unavailable)?;
                let is_source = old == &location;
                let target = match pending.state {
                    State::MovingToBin => "OSMAP.DocumentsBin",
                    State::Restoring => "OSMAP.Documents",
                    State::Deleting => "",
                    _ => unreachable!(),
                };
                if !is_source && location.mailbox != target {
                    return Err(Error::Unconfirmed);
                }
                let bytes = self.backend.read(account, id, &location)?;
                if !matches_document(&pending, &bytes) {
                    return Err(Error::Unconfirmed);
                }
                let document = &mut index.documents[position];
                document.location = Some(location);
                document.state = if is_source {
                    match pending.state {
                        State::MovingToBin => State::Available,
                        State::Restoring | State::Deleting => State::InBin,
                        _ => unreachable!(),
                    }
                } else if pending.state == State::MovingToBin {
                    State::InBin
                } else {
                    State::Available
                };
                document.binned_at = if document.state == State::InBin {
                    Some(pending.binned_at.unwrap_or(now))
                } else {
                    None
                };
            }
            _ => return Err(Error::Unconfirmed),
        }
        increment(&mut index)?;
        write(&locked, &index)?;
        Ok(index)
    }

    fn change_location(
        &self,
        account: &str,
        expected_revision: u64,
        id: &str,
        now: u64,
        restoring: bool,
    ) -> Result<Index, Error> {
        valid_account(account)?;
        if !valid_id(id) {
            return Err(Error::Invalid);
        }
        let locked = self.files.lock(account).map_err(io_error)?;
        let mut index = decode(account, locked.read().map_err(io_error)?.as_deref())?;
        ensure_mutable(&index, expected_revision)?;
        let document = index
            .documents
            .iter_mut()
            .find(|doc| doc.id == id)
            .ok_or(Error::NotFound)?;
        if (restoring && document.state != State::InBin)
            || (!restoring && document.state != State::Available)
        {
            return Err(Error::Invalid);
        }
        if restoring
            && now.saturating_sub(document.binned_at.ok_or(Error::Unavailable)?)
                > BIN_RETENTION_SECONDS
        {
            return Err(Error::Invalid);
        }
        let old = document.location.clone().ok_or(Error::Unavailable)?;
        document.state = if restoring {
            State::Restoring
        } else {
            State::MovingToBin
        };
        document.modified_at = now;
        increment(&mut index)?;
        write(&locked, &index)?;
        let result = if restoring {
            self.backend.restore(account, id, &old)
        } else {
            self.backend.move_to_bin(account, id, &old)
        };
        let location = match result {
            Ok(location) => location,
            Err(
                error @ (Error::Invalid
                | Error::Limit
                | Error::NotFound
                | Error::Stale
                | Error::PreDispatchUnavailable
                | Error::ConfirmedNoWrite),
            ) => {
                // A confirmed no-write refusal restores the prior visible
                // state. Any uncertain dispatch leaves the pending marker.
                let document = index
                    .documents
                    .iter_mut()
                    .find(|doc| doc.id == id)
                    .ok_or(Error::Unavailable)?;
                document.state = if restoring {
                    State::InBin
                } else {
                    State::Available
                };
                increment(&mut index)?;
                write(&locked, &index)?;
                return Err(error);
            }
            Err(_) => return Err(Error::Unconfirmed),
        };
        let document = index
            .documents
            .iter_mut()
            .find(|doc| doc.id == id)
            .ok_or(Error::Unavailable)?;
        document.location = Some(location);
        document.state = if restoring {
            State::Available
        } else {
            State::InBin
        };
        document.binned_at = if restoring { None } else { Some(now) };
        document.modified_at = now;
        increment(&mut index)?;
        write(&locked, &index)?;
        Ok(index)
    }
}

fn write(
    locked: &crate::private_account_file::LockedAccountFile,
    index: &Index,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(index).map_err(|_| Error::Unavailable)?;
    locked.write(&bytes).map_err(io_error)
}

fn decode(account: &str, bytes: Option<&[u8]>) -> Result<Index, Error> {
    let index = match bytes {
        Some(bytes) => serde_json::from_slice(bytes).map_err(|_| Error::Unavailable)?,
        None => Index::empty(account),
    };
    index.validate(account)?;
    Ok(index)
}

fn ensure_mutable(index: &Index, expected_revision: u64) -> Result<(), Error> {
    if index.revision != expected_revision {
        return Err(Error::Stale);
    }
    if index.has_unconfirmed_change() {
        return Err(Error::Unconfirmed);
    }
    Ok(())
}

fn increment(index: &mut Index) -> Result<(), Error> {
    index.revision = index.revision.checked_add(1).ok_or(Error::Unavailable)?;
    Ok(())
}

fn matches_document(document: &Document, bytes: &[u8]) -> bool {
    bytes.len() as u64 == document.size && format!("{:x}", Sha256::digest(bytes)) == document.sha256
}

fn valid_account(account: &str) -> Result<(), Error> {
    crate::identity::CanonicalUsername::parse(account)
        .map(|_| ())
        .map_err(|_| Error::Invalid)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
}

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'+' | b'.'))
        && value.contains('/')
}

fn valid_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn io_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Error::Busy
    } else {
        Error::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    type Records = Arc<Mutex<BTreeMap<(String, String), Vec<u8>>>>;

    #[derive(Clone)]
    struct Fixture {
        ready: bool,
        reject: bool,
        records: Records,
    }

    impl Fixture {
        fn new(ready: bool) -> Self {
            Self {
                ready,
                reject: false,
                records: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }
        fn location(mailbox: &str) -> Location {
            Location {
                mailbox: mailbox.into(),
                uid: 1,
                mailbox_guid: "f".repeat(32),
                message_guid: "a".repeat(32),
            }
        }
    }

    impl Backend for Fixture {
        fn quota_status(&self, _: &str) -> Result<Option<QuotaStatus>, Error> {
            Ok(self.ready.then_some(QuotaStatus {
                used_bytes: 0,
                limit_bytes: 1024 * 1024,
            }))
        }
        fn append(
            &self,
            account: &str,
            id: &str,
            _: &str,
            _: &str,
            body: &[u8],
        ) -> Result<Location, Error> {
            if !self.ready {
                return Err(Error::PreDispatchUnavailable);
            }
            if self.reject {
                return Err(Error::Limit);
            }
            self.records
                .lock()
                .unwrap()
                .insert((account.into(), id.into()), body.to_vec());
            Ok(Self::location("OSMAP.Documents"))
        }
        fn read(&self, account: &str, id: &str, _: &Location) -> Result<Vec<u8>, Error> {
            self.records
                .lock()
                .unwrap()
                .get(&(account.into(), id.into()))
                .cloned()
                .ok_or(Error::NotFound)
        }
        fn move_to_bin(&self, _: &str, _: &str, _: &Location) -> Result<Location, Error> {
            Ok(Self::location("OSMAP.DocumentsBin"))
        }
        fn restore(&self, _: &str, _: &str, _: &Location) -> Result<Location, Error> {
            Ok(Self::location("OSMAP.Documents"))
        }
        fn expunge(&self, account: &str, id: &str, _: &Location) -> Result<(), Error> {
            self.records
                .lock()
                .unwrap()
                .remove(&(account.into(), id.into()));
            Ok(())
        }
        fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .contains_key(&(account.into(), id.into()))
                .then(|| Self::location("OSMAP.Documents"))
                .into_iter()
                .collect())
        }
    }

    #[derive(Clone)]
    struct AmbiguousAppend {
        inner: Fixture,
        dispatched: Arc<AtomicUsize>,
    }
    impl Backend for AmbiguousAppend {
        fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error> {
            self.inner.quota_status(account)
        }
        fn append(
            &self,
            account: &str,
            id: &str,
            name: &str,
            media_type: &str,
            body: &[u8],
        ) -> Result<Location, Error> {
            self.dispatched.fetch_add(1, Ordering::SeqCst);
            self.inner.append(account, id, name, media_type, body)?;
            Err(Error::Unconfirmed)
        }
        fn read(&self, account: &str, id: &str, location: &Location) -> Result<Vec<u8>, Error> {
            self.inner.read(account, id, location)
        }
        fn move_to_bin(
            &self,
            account: &str,
            id: &str,
            location: &Location,
        ) -> Result<Location, Error> {
            self.inner.move_to_bin(account, id, location)
        }
        fn restore(&self, account: &str, id: &str, location: &Location) -> Result<Location, Error> {
            self.inner.restore(account, id, location)
        }
        fn expunge(&self, account: &str, id: &str, location: &Location) -> Result<(), Error> {
            self.inner.expunge(account, id, location)
        }
        fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error> {
            self.inner.inspect(account, id)
        }
    }

    fn private_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "osmap-document-test-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    #[test]
    fn ambiguous_append_reconciles_exact_bytes_without_second_dispatch() {
        let root = private_root();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let store = Store::new(
            root.clone(),
            AmbiguousAppend {
                inner: Fixture::new(true),
                dispatched: dispatched.clone(),
            },
        );
        let account = "alice@example.test";
        assert_eq!(
            store.upload(account, 0, "file", "text/plain", b"exact", 100),
            Err(Error::Unconfirmed)
        );
        let pending = store.load(account).unwrap();
        let id = &pending.documents[0].id;
        assert_eq!(pending.documents[0].state, State::Uploading);
        assert_eq!(
            store.reconcile(account, pending.revision, id, 200),
            Err(Error::Busy)
        );
        assert_eq!(
            store.reconcile("bob@example.test", pending.revision, id, 500),
            Err(Error::NotFound)
        );
        let settled = store.reconcile(account, pending.revision, id, 500).unwrap();
        assert_eq!(settled.documents[0].state, State::Available);
        assert_eq!(store.download(account, id).unwrap().1, b"exact");
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upload_download_bin_restore_owner_revision_and_quota() {
        let root = private_root();
        let backend = Fixture::new(true);
        let store = Store::new(root.clone(), backend.clone());
        let account = "alice@example.test";
        let index = store
            .upload(
                account,
                0,
                "report.pdf",
                "application/pdf",
                b"synthetic",
                100,
            )
            .unwrap();
        assert_eq!(index.documents.len(), 1);
        assert_eq!(index.used_bytes(), 9);
        let id = &index.documents[0].id;
        assert_eq!(
            store.download(account, id).unwrap(),
            ("report.pdf".into(), b"synthetic".to_vec())
        );
        // A same-length change in the native store must never be served as
        // the approved document merely because its ID and size still match.
        backend
            .records
            .lock()
            .unwrap()
            .insert((account.into(), id.clone()), b"synthetiX".to_vec());
        assert_eq!(store.download(account, id), Err(Error::Unavailable));
        backend
            .records
            .lock()
            .unwrap()
            .insert((account.into(), id.clone()), b"synthetic".to_vec());
        assert_eq!(store.download("bob@example.test", id), Err(Error::NotFound));
        assert_eq!(store.bin(account, 0, id, 101), Err(Error::Stale));
        let binned = store.bin(account, index.revision, id, 101).unwrap();
        assert_eq!(binned.documents[0].state, State::InBin);
        assert_eq!(binned.used_bytes(), 9);
        assert_eq!(store.download(account, id), Err(Error::NotFound));
        let restored = store.restore(account, binned.revision, id, 102).unwrap();
        assert_eq!(restored.documents[0].state, State::Available);
        assert_eq!(store.download(account, id).unwrap().1, b"synthetic");
        assert_eq!(
            store.restore(account, restored.revision, id, 103),
            Err(Error::Invalid)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_quota_authority_or_confirmed_rejection_never_leaves_a_document() {
        let root = private_root();
        let absent = Store::new(root.clone(), Fixture::new(false));
        assert_eq!(
            absent.upload("alice@example.test", 0, "f", "text/plain", b"x", 1),
            Err(Error::PreDispatchUnavailable)
        );
        assert!(absent
            .load("alice@example.test")
            .unwrap()
            .documents
            .is_empty());
        let mut rejected = Fixture::new(true);
        rejected.reject = true;
        let store = Store::new(root.clone(), rejected);
        let current_revision = store.load("alice@example.test").unwrap().revision;
        assert_eq!(
            store.upload(
                "alice@example.test",
                current_revision,
                "f",
                "text/plain",
                b"x",
                1
            ),
            Err(Error::Limit)
        );
        assert!(store
            .load("alice@example.test")
            .unwrap()
            .documents
            .is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn names_ids_and_unconfirmed_records_fail_closed() {
        let root = private_root();
        let store = Store::new(root.clone(), Fixture::new(true));
        for name in ["", "../x", "x\r\nY", "a/b", "x\\y"] {
            assert_eq!(
                store.upload("alice@example.test", 0, name, "text/plain", b"x", 1),
                Err(Error::Invalid)
            );
        }
        assert_eq!(
            store.download("alice@example.test", "../foreign"),
            Err(Error::Invalid)
        );
        assert!(store
            .load("alice@example.test")
            .unwrap()
            .documents
            .is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
