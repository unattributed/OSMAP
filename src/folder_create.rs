//! Create one private INBOX child. No rename, delete, move or subscription authority.
use crate::{
    folder_metadata::{FolderSnapshot, NamespaceKind},
    mailbox_status::MailboxStatus,
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    Invalid,
    Stale,
    Unavailable,
    Capacity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Outcome {
    Created { guid: String },
    Conflict,
    Refused(Refusal),
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFolderRequest {
    account: String,
    parent: String,
    parent_guid: String,
    leaf: String,
}
impl CreateFolderRequest {
    pub fn new(account: &str, parent: &str, guid: &str, leaf: &str) -> Result<Self, Refusal> {
        crate::identity::CanonicalUsername::parse(account).map_err(|_| Refusal::Invalid)?;
        crate::mailbox_status::validate_account(account).map_err(|_| Refusal::Invalid)?;
        if !(parent == "INBOX" || parent.starts_with("INBOX."))
            || parent.ends_with('.')
            || parent.split('.').any(str::is_empty)
            || leaf.is_empty()
            || leaf.trim() != leaf
            || leaf.contains(['.', '/'])
        {
            return Err(Refusal::Invalid);
        }
        for n in [parent, leaf] {
            crate::mailbox_status::validate_name(n).map_err(|_| Refusal::Invalid)?;
        }
        let child = format!("{parent}.{leaf}");
        crate::mailbox_status::validate_name(&child).map_err(|_| Refusal::Invalid)?;
        MailboxStatus::new(parent, guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        Ok(Self {
            account: account.into(),
            parent: parent.into(),
            parent_guid: guid.into(),
            leaf: leaf.into(),
        })
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn parent(&self) -> &str {
        &self.parent
    }
    pub fn parent_guid(&self) -> &str {
        &self.parent_guid
    }
    pub fn leaf(&self) -> &str {
        &self.leaf
    }
    pub fn child(&self) -> String {
        format!("{}.{}", self.parent, self.leaf)
    }
    pub fn validate(&self) -> Result<(), Refusal> {
        Self::new(&self.account, &self.parent, &self.parent_guid, &self.leaf).map(|_| ())
    }
    pub fn validate_parent(
        &self,
        snapshot: &FolderSnapshot,
        status: &MailboxStatus,
    ) -> Result<(), Refusal> {
        self.validate()?;
        validate_private_namespace(snapshot, &self.child())?;
        validate_creation_parent(&self.account, &self.parent, snapshot, status)?;
        if status.guid() != self.parent_guid {
            return Err(Refusal::Stale);
        }
        Ok(())
    }
    pub(crate) fn accepts_response(&self, returned: &Self, outcome: &Outcome) -> bool {
        self == returned && self.validate_outcome(outcome).is_ok()
    }
    pub(crate) fn validate_outcome(&self, outcome: &Outcome) -> Result<(), Refusal> {
        self.validate()?;
        if let Outcome::Created { guid } = outcome {
            if guid == self.parent_guid() {
                return Err(Refusal::Invalid);
            }
            MailboxStatus::new(&self.child(), guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        }
        Ok(())
    }
}
pub fn validate_creation_parent(
    account: &str,
    parent: &str,
    snapshot: &FolderSnapshot,
    status: &MailboxStatus,
) -> Result<(), Refusal> {
    if !(parent == "INBOX" || parent.starts_with("INBOX.")) {
        return Err(Refusal::Invalid);
    }
    snapshot
        .validate_for(account)
        .map_err(|_| Refusal::Unavailable)?;
    status.validate(parent).map_err(|_| Refusal::Unavailable)?;

    let folder = snapshot
        .folder(account, parent)
        .map_err(|_| Refusal::Unavailable)?;
    if folder.delimiter() != Some('.')
        || folder.has_flag("\\Noselect")
        || folder.has_flag("\\NonExistent")
        || folder.has_flag("\\Noinferiors")
    {
        return Err(Refusal::Invalid);
    }
    validate_private_namespace(snapshot, parent)?;
    if snapshot.folders().len() >= 1024 {
        return Err(Refusal::Capacity);
    }
    Ok(())
}

pub(crate) fn validate_private_namespace(
    snapshot: &FolderSnapshot,
    name: &str,
) -> Result<(), Refusal> {
    let ns: Vec<_> = snapshot
        .namespaces()
        .iter()
        .filter(|n| {
            n.prefix().is_empty()
                || name.starts_with(n.prefix())
                || n.delimiter()
                    .and_then(|delimiter| n.prefix().strip_suffix(delimiter))
                    == Some(name)
        })
        .collect();
    if ns.len() != 1 || ns[0].kind() != NamespaceKind::Private || ns[0].delimiter() != Some('.') {
        return Err(Refusal::Invalid);
    }
    Ok(())
}
