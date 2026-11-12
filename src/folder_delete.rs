//! Explicit empty private-leaf deletion; never message disposal or expunge.
use crate::{
    folder_create::Refusal, folder_metadata::FolderSnapshot, mailbox_status::MailboxStatus,
};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteFolderRequest {
    account: String,
    source: String,
    source_guid: String,
    parent_guid: String,
    action_nonce: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Deleted,
    Refused(Refusal),
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Completion {
    NoMutation,
    Deleted,
    Unconfirmed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Deleted,
    Unchanged,
    NoPending,
    Unconfirmed,
    Unavailable,
}
impl DeleteFolderRequest {
    pub fn new(
        account: &str,
        source: &str,
        guid: &str,
        parent_guid: &str,
    ) -> Result<Self, Refusal> {
        let (parent, leaf) = source.rsplit_once('.').ok_or(Refusal::Invalid)?;
        crate::folder_create::CreateFolderRequest::new(account, parent, parent_guid, leaf)?;
        MailboxStatus::new(source, guid, 0, 0).map_err(|_| Refusal::Invalid)?;
        if crate::folder_rename::protected_name(source) || guid == parent_guid {
            return Err(Refusal::Invalid);
        }
        Ok(Self {
            account: account.into(),
            source: source.into(),
            source_guid: guid.into(),
            parent_guid: parent_guid.into(),
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
    pub fn parent(&self) -> &str {
        self.source.rsplit_once('.').map_or("", |v| v.0)
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
            self.account(),
            self.source(),
            self.source_guid(),
            self.parent_guid(),
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
        crate::folder_rename::validate_source(self.account(), self.source(), snapshot, source)?;
        match crate::folder_create::validate_creation_parent(
            self.account(),
            self.parent(),
            snapshot,
            parent,
        ) {
            Ok(()) | Err(Refusal::Capacity) => (),
            Err(e) => return Err(e),
        }
        if source.guid() != self.source_guid() || parent.guid() != self.parent_guid() {
            return Err(Refusal::Stale);
        }
        if source.messages() != 0
            || snapshot
                .folders()
                .iter()
                .any(|f| f.name().starts_with(&format!("{}.", self.source())))
        {
            return Err(Refusal::Invalid);
        }
        Ok(())
    }
    pub fn confirmed_absent(&self, snapshot: &FolderSnapshot, parent: &MailboxStatus) -> bool {
        self.validate().is_ok()
            && crate::folder_create::validate_creation_parent(
                self.account(),
                self.parent(),
                snapshot,
                parent,
            )
            .is_ok()
            && parent.guid() == self.parent_guid()
            && snapshot.folder(self.account(), self.source()).is_err()
            && !snapshot
                .folders()
                .iter()
                .any(|f| f.name().starts_with(&format!("{}.", self.source())))
    }
    pub(crate) fn confirmed_unchanged(
        &self,
        snapshot: &FolderSnapshot,
        source: &MailboxStatus,
        parent: &MailboxStatus,
    ) -> bool {
        self.validate().is_ok()
            && crate::folder_rename::validate_source(
                self.account(),
                self.source(),
                snapshot,
                source,
            )
            .is_ok()
            && matches!(
                crate::folder_create::validate_creation_parent(
                    self.account(),
                    self.parent(),
                    snapshot,
                    parent
                ),
                Ok(()) | Err(Refusal::Capacity)
            )
            && source.guid() == self.source_guid()
            && parent.guid() == self.parent_guid()
    }
    pub(crate) fn accepts_response(&self, other: &Self) -> bool {
        self == other && other.validate().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn folder_delete_pending_preserves_legacy_rename_and_cross_kind_exclusion() {
        let root = std::env::temp_dir().join(format!(
            "osmap-delete-role-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let account = "alice@fixture.test";
        let rename = crate::folder_rename::RenameFolderRequest::new(
            account,
            "INBOX.Alpha",
            &"a".repeat(32),
            &"b".repeat(32),
            "Beta",
        )
        .unwrap();
        let old = serde_json::to_vec(
            &serde_json::json!({"version":1,"account":account,"pending":rename}),
        )
        .unwrap();
        {
            let f = crate::private_account_file::PrivateAccountFile::new(
                root.clone(),
                "osmap-folder-roles-v1",
                4096,
            )
            .lock(account)
            .unwrap();
            f.write(&old).unwrap();
        }
        let deletion =
            DeleteFolderRequest::new(account, "INBOX.Alpha", &"a".repeat(32), &"b".repeat(32))
                .unwrap();
        {
            let mut l = crate::folder_rename::role_lease(&root, account).unwrap();
            assert_eq!(l.pending(), Some(&rename));
            assert!(l.pending_delete().is_none());
            assert_eq!(l.begin_delete(&deletion), Err(Refusal::Invalid));
        }
        {
            let f = crate::private_account_file::PrivateAccountFile::new(
                root.clone(),
                "osmap-folder-roles-v1",
                4096,
            )
            .lock(account)
            .unwrap();
            assert_eq!(f.read().unwrap(), Some(old));
        }
        assert!(crate::folder_rename::settings_gate(&root, account).is_err());
        {
            let mut l = crate::folder_rename::role_lease(&root, account).unwrap();
            l.confirm().unwrap();
            l.begin_delete(&deletion).unwrap();
            assert_eq!(l.begin(&rename), Err(Refusal::Invalid));
        }
        {
            let l = crate::folder_rename::role_lease(&root, account).unwrap();
            assert_eq!(l.pending_delete(), Some(&deletion));
            assert!(l.pending().is_none());
        }
        assert!(crate::folder_rename::settings_gate(&root, account).is_err());
        assert!(crate::folder_rename::settings_gate(&root, "bob@fixture.test").is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
}
