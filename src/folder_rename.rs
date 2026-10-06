//! Confirmed same-parent rename of a private user folder.
use crate::{
    folder_create::Refusal, folder_metadata::FolderSnapshot, mailbox_status::MailboxStatus,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Outcome {
    Renamed,
    Conflict,
    Refused(Refusal),
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameFolderRequest {
    account: String,
    source: String,
    source_guid: String,
    parent_guid: String,
    leaf: String,
    action_nonce: String,
}
impl RenameFolderRequest {
    pub fn new(
        account: &str,
        source: &str,
        source_guid: &str,
        parent_guid: &str,
        leaf: &str,
    ) -> Result<Self, Refusal> {
        let (parent, old_leaf) = source.rsplit_once('.').ok_or(Refusal::Invalid)?;
        crate::folder_create::CreateFolderRequest::new(account, parent, parent_guid, old_leaf)?;
        let create =
            crate::folder_create::CreateFolderRequest::new(account, parent, parent_guid, leaf)?;
        MailboxStatus::new(source, source_guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        if source == create.child()
            || protected_name(source)
            || protected_name(&create.child())
            || source_guid == parent_guid
        {
            return Err(Refusal::Invalid);
        }
        Ok(Self {
            account: account.into(),
            source: source.into(),
            source_guid: source_guid.into(),
            parent_guid: parent_guid.into(),
            leaf: leaf.into(),
            action_nonce: crate::draft::generate_draft_id().map_err(|_| Refusal::Unavailable)?,
        })
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn source_guid(&self) -> &str {
        &self.source_guid
    }
    pub fn parent_guid(&self) -> &str {
        &self.parent_guid
    }
    pub fn leaf(&self) -> &str {
        &self.leaf
    }
    pub fn parent(&self) -> &str {
        self.source.rsplit_once('.').map_or("", |v| v.0)
    }
    pub fn destination(&self) -> String {
        format!("{}.{}", self.parent(), self.leaf)
    }
    pub fn action_nonce(&self) -> &str {
        &self.action_nonce
    }
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.action_nonce.len() != 32
            || !self
                .action_nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Refusal::Invalid);
        }
        Self::new(
            &self.account,
            &self.source,
            &self.source_guid,
            &self.parent_guid,
            &self.leaf,
        )
        .map(|_| ())
    }
    pub fn validate_before(
        &self,
        snapshot: &FolderSnapshot,
        source: &MailboxStatus,
        parent: &MailboxStatus,
    ) -> Result<(), Refusal> {
        self.validate()?;
        validate_source(self.account(), self.source(), snapshot, source)?;
        let create = crate::folder_create::CreateFolderRequest::new(
            self.account(),
            self.parent(),
            self.parent_guid(),
            self.leaf(),
        )?;
        match create.validate_parent(snapshot, parent) {
            Ok(()) | Err(Refusal::Capacity) => (),
            Err(e) => return Err(e),
        }
        if source.guid() != self.source_guid() || parent.guid() != self.parent_guid() {
            return Err(Refusal::Stale);
        }
        Ok(())
    }
    pub(crate) fn accepts_response(&self, returned: &Self) -> bool {
        self == returned && returned.validate().is_ok()
    }
}
/// Fixed system names are protected at every INBOX hierarchy level.
pub(crate) fn protected_name(name: &str) -> bool {
    !name.starts_with("INBOX.")
        || name.split('.').skip(1).any(|part| {
            [
                "inbox",
                "drafts",
                "working drafts",
                "sent",
                "archive",
                "bin",
                "trash",
                "junk",
                "spam",
                "osmap",
                "documents",
                "documentsbin",
            ]
            .iter()
            .any(|protected| part.eq_ignore_ascii_case(protected))
        })
}
pub(crate) fn validate_source(
    account: &str,
    name: &str,
    snapshot: &FolderSnapshot,
    status: &MailboxStatus,
) -> Result<(), Refusal> {
    snapshot
        .validate_for(account)
        .map_err(|_| Refusal::Unavailable)?;
    status.validate(name).map_err(|_| Refusal::Unavailable)?;
    if protected_name(name) {
        return Err(Refusal::Invalid);
    }
    crate::folder_create::validate_private_namespace(snapshot, name)?;
    let folder = snapshot
        .folder(account, name)
        .map_err(|_| Refusal::Unavailable)?;
    if !crate::sent_location::selectable(snapshot, account, name)
        || folder.delimiter() != Some('.')
        || folder.flags().iter().any(|flag| {
            !["\\HasNoChildren", "\\Subscribed", "\\Marked", "\\Unmarked"]
                .iter()
                .any(|allowed| flag.eq_ignore_ascii_case(allowed))
        })
        || snapshot
            .folders()
            .iter()
            .any(|f| f.name().starts_with(&format!("{name}.")))
    {
        return Err(Refusal::Invalid);
    }
    // Ancestor role facts also protect user-looking children of system folders.
    for ancestor in snapshot
        .folders()
        .iter()
        .filter(|f| name.starts_with(&format!("{}.", f.name())) && f.name() != "INBOX")
    {
        if !ancestor.special_use().is_empty() || ancestor.has_flag("\\NonExistent") {
            return Err(Refusal::Invalid);
        }
    }
    Ok(())
}
/// One account-bound pending rename; role writers use the same private lock.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleRecord {
    version: u8,
    account: String,
    pending: Option<RenameFolderRequest>,
}
pub(crate) struct RoleLease {
    file: crate::private_account_file::LockedAccountFile,
    account: String,
    pending: Option<RenameFolderRequest>,
}
impl RoleLease {
    pub(crate) fn pending(&self) -> Option<&RenameFolderRequest> {
        self.pending.as_ref()
    }
    pub(crate) fn begin(&mut self, request: &RenameFolderRequest) -> Result<(), Refusal> {
        request.validate()?;
        if request.account() != self.account || self.pending.is_some() {
            return Err(Refusal::Invalid);
        }
        self.publish(Some(request.clone()))
    }
    pub(crate) fn confirm(&mut self) -> Result<(), Refusal> {
        self.publish(None)
    }
    fn publish(&mut self, pending: Option<RenameFolderRequest>) -> Result<(), Refusal> {
        let bytes = serde_json::to_vec(&RoleRecord {
            version: 1,
            account: self.account.clone(),
            pending: pending.clone(),
        })
        .map_err(|_| Refusal::Unavailable)?;
        self.file.write(&bytes).map_err(|_| Refusal::Unavailable)?;
        self.pending = pending;
        Ok(())
    }
}
pub(crate) fn role_lease(directory: &std::path::Path, account: &str) -> Result<RoleLease, Refusal> {
    crate::identity::CanonicalUsername::parse(account).map_err(|_| Refusal::Invalid)?;
    let file = crate::private_account_file::PrivateAccountFile::new(
        directory.to_path_buf(),
        "osmap-folder-roles-v1",
        4096,
    )
    .lock(account)
    .map_err(|_| Refusal::Unavailable)?;
    let pending = match file.read().map_err(|_| Refusal::Unavailable)? {
        None => None,
        Some(bytes) => {
            let record: RoleRecord =
                serde_json::from_slice(&bytes).map_err(|_| Refusal::Unavailable)?;
            if record.version != 1
                || record.account != account
                || record
                    .pending
                    .as_ref()
                    .is_some_and(|r| r.account() != account || r.validate().is_err())
            {
                return Err(Refusal::Unavailable);
            }
            record.pending
        }
    };
    Ok(RoleLease {
        file,
        account: account.into(),
        pending,
    })
}
pub(crate) fn settings_gate(
    directory: &std::path::Path,
    account: &str,
) -> Result<RoleLease, Refusal> {
    let lease = role_lease(directory, account)?;
    if lease.pending.is_some() {
        return Err(Refusal::Unavailable);
    }
    Ok(lease)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Renamed { destination: String },
    Unconfirmed,
    Unavailable,
    NoPending,
    Unchanged,
}
pub(crate) fn confirmed_result(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    destination: &MailboxStatus,
    parent: &MailboxStatus,
) -> bool {
    let parent_authority = crate::folder_create::CreateFolderRequest::new(
        request.account(),
        request.parent(),
        request.parent_guid(),
        request.leaf(),
    )
    .and_then(|r| r.validate_parent(snapshot, parent));
    matches!(parent_authority, Ok(()) | Err(Refusal::Capacity))
        && snapshot
            .folder(request.account(), request.source())
            .is_err()
        && destination.guid() == request.source_guid()
        && parent.guid() == request.parent_guid()
        && validate_source(
            request.account(),
            &request.destination(),
            snapshot,
            destination,
        )
        .is_ok()
        && parent.validate(request.parent()).is_ok()
}

pub(crate) fn protected_destinations<G: crate::http::BrowserGateway>(
    gateway: &G,
    context: &crate::auth::AuthenticationContext,
    session: &crate::session::ValidatedSession,
) -> Result<Vec<String>, Refusal> {
    let settings = gateway.load_settings(context, session);
    let crate::http::BrowserSettingsDecision::Loaded {
        canonical_username,
        settings,
    } = settings.decision
    else {
        return Err(Refusal::Unavailable);
    };
    if canonical_username != session.record.canonical_username {
        return Err(Refusal::Unavailable);
    }
    let bin = gateway
        .load_bin_preference(session)
        .map_err(|_| Refusal::Unavailable)?;
    let sent = gateway
        .load_sent_location_preference(session)
        .map_err(|_| Refusal::Unavailable)?;
    if !sent.valid() || crate::mailbox_status::validate_name(&bin.mailbox_name).is_err() {
        return Err(Refusal::Unavailable);
    }
    let mut names = vec![bin.mailbox_name, sent.mailbox_name];
    names.extend(settings.archive_mailbox_name);
    Ok(names)
}
pub(crate) fn role_conflict(names: &[String], source: &str, destination: &str) -> bool {
    names.iter().any(|name| {
        name == source
            || name == destination
            || name.starts_with(&format!("{source}."))
            || name.starts_with(&format!("{destination}."))
            || source.starts_with(&format!("{name}."))
            || destination.starts_with(&format!("{name}."))
    })
}

/// Only a durably settled pre-dispatch refusal is a no-mutation witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completion {
    NoMutation,
    Renamed,
    Unconfirmed,
}
pub(crate) fn confirmed_unchanged(
    request: &RenameFolderRequest,
    snapshot: &FolderSnapshot,
    source: &MailboxStatus,
    parent: &MailboxStatus,
) -> bool {
    request.validate_before(snapshot, source, parent).is_ok()
        && snapshot
            .folder(request.account(), &request.destination())
            .is_err()
}

/// Role lease remains held across both bounded index updates; pending survives partial failure.
pub(crate) fn reconcile_metadata(
    directory: &std::path::Path,
    request: &RenameFolderRequest,
) -> Result<(), Refusal> {
    crate::labels::LabelStore::new(directory.join("labels-v1"))
        .reconcile_folder_rename(request)
        .map_err(|_| Refusal::Unavailable)?;
    crate::snooze::SnoozeStore::new(directory)
        .reconcile_folder_rename(request)
        .map_err(|_| Refusal::Unavailable)
}
