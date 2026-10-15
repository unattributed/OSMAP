//! One bounded, helper-owned completion witness per account. No retry action.
use super::{MailboxHelperRequest, MailboxHelperResponse};
use crate::{
    folder_rename::{Completion, Outcome, RenameFolderRequest},
    mailbox::MailboxBackend,
    private_account_file::{LockedAccountFile, PrivateAccountFile},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    request: RenameFolderRequest,
    outcome: Option<Outcome>,
}
fn read(file: &LockedAccountFile, account: &str) -> Result<Option<Record>, ()> {
    let Some(bytes) = file.read().map_err(|_| ())? else {
        return Ok(None);
    };
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if record.version != 1
        || record.request.account() != account
        || record.request.validate().is_err()
    {
        return Err(());
    }
    Ok(Some(record))
}
fn publish(
    file: &LockedAccountFile,
    request: &RenameFolderRequest,
    outcome: Option<Outcome>,
) -> Result<(), ()> {
    let bytes = serde_json::to_vec(&Record {
        version: 1,
        request: request.clone(),
        outcome,
    })
    .map_err(|_| ())?;
    file.write(&bytes).map_err(|_| ())
}
pub(crate) fn completion(directory: &Path, request: &RenameFolderRequest) -> Completion {
    if request.validate().is_err() {
        return Completion::Unconfirmed;
    }
    let Ok(file) = PrivateAccountFile::new(directory.into(), "osmap-folder-rename-helper-v1", 4096)
        .lock(request.account())
    else {
        return Completion::Unconfirmed;
    };
    match read(&file, request.account()) {
        Ok(Some(record)) if record.request == *request => match record.outcome {
            Some(Outcome::Refused(_)) | Some(Outcome::Conflict) => Completion::NoMutation,
            Some(Outcome::Renamed) => Completion::Renamed,
            _ => Completion::Unconfirmed,
        },
        _ => Completion::Unconfirmed,
    }
}
pub(crate) fn execute<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    request: &RenameFolderRequest,
) -> Outcome {
    if let Err(reason) = request.validate() {
        return Outcome::Refused(reason);
    }
    let Ok(file) = PrivateAccountFile::new(directory.into(), "osmap-folder-rename-helper-v1", 4096)
        .lock(request.account())
    else {
        return Outcome::Refused(crate::folder_create::Refusal::Unavailable);
    };
    match read(&file, request.account()) {
        Err(()) => return Outcome::Refused(crate::folder_create::Refusal::Unavailable),
        Ok(Some(record)) if record.request == *request => {
            return record.outcome.unwrap_or(Outcome::Unknown)
        }
        Ok(Some(record)) if record.request.action_nonce() == request.action_nonce() => {
            return Outcome::Refused(crate::folder_create::Refusal::Invalid)
        }
        // A consumed original action remains unresolved across helper restarts.
        Ok(Some(record))
            if record.outcome.is_none() || record.outcome == Some(Outcome::Unknown) =>
        {
            return Outcome::Refused(crate::folder_create::Refusal::Unavailable)
        }
        _ => (),
    }
    if publish(&file, request, None).is_err() {
        return Outcome::Refused(crate::folder_create::Refusal::Unavailable);
    }
    let outcome = backend.rename_folder(request);
    // Publish only after backend return, while retaining the same account lock.
    // Unknown never attests child exit/no write, even if the helper has returned.
    if publish(&file, request, Some(outcome.clone())).is_err() {
        return Outcome::Unknown;
    }
    outcome
}
pub(crate) mod delete_witness {
    use super::*;
    use crate::folder_delete::{Completion, DeleteFolderRequest, Outcome};
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DeleteRecord {
        version: u8,
        request: DeleteFolderRequest,
        outcome: Option<Outcome>,
    }
    fn read_delete(file: &LockedAccountFile, account: &str) -> Result<Option<DeleteRecord>, ()> {
        let Some(bytes) = file.read().map_err(|_| ())? else {
            return Ok(None);
        };
        let record: DeleteRecord = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if record.version != 1
            || record.request.account() != account
            || record.request.validate().is_err()
        {
            return Err(());
        }
        Ok(Some(record))
    }
    fn publish_delete(
        file: &LockedAccountFile,
        request: &DeleteFolderRequest,
        outcome: Option<Outcome>,
    ) -> Result<(), ()> {
        let bytes = serde_json::to_vec(&DeleteRecord {
            version: 1,
            request: request.clone(),
            outcome,
        })
        .map_err(|_| ())?;
        file.write(&bytes).map_err(|_| ())
    }
    pub(crate) fn completion_delete(directory: &Path, request: &DeleteFolderRequest) -> Completion {
        if request.validate().is_err() {
            return Completion::Unconfirmed;
        }
        let Ok(file) =
            PrivateAccountFile::new(directory.into(), "osmap-folder-delete-helper-v1", 4096)
                .lock(request.account())
        else {
            return Completion::Unconfirmed;
        };
        match read_delete(&file, request.account()) {
            Ok(Some(record)) if record.request == *request => match record.outcome {
                Some(Outcome::Refused(_)) => Completion::NoMutation,
                Some(Outcome::Deleted) => Completion::Deleted,
                _ => Completion::Unconfirmed,
            },
            _ => Completion::Unconfirmed,
        }
    }
    pub(crate) fn execute_delete<B: MailboxBackend>(
        directory: &Path,
        backend: &B,
        request: &DeleteFolderRequest,
    ) -> Outcome {
        if let Err(reason) = request.validate() {
            return Outcome::Refused(reason);
        }
        let Ok(file) =
            PrivateAccountFile::new(directory.into(), "osmap-folder-delete-helper-v1", 4096)
                .lock(request.account())
        else {
            return Outcome::Refused(crate::folder_create::Refusal::Unavailable);
        };
        match read_delete(&file, request.account()) {
            Err(()) => return Outcome::Refused(crate::folder_create::Refusal::Unavailable),
            Ok(Some(record)) if record.request == *request => {
                return record.outcome.unwrap_or(Outcome::Unknown)
            }
            Ok(Some(record)) if record.request.action_nonce() == request.action_nonce() => {
                return Outcome::Refused(crate::folder_create::Refusal::Invalid)
            }
            // A consumed original action remains unresolved across helper restarts.
            Ok(Some(record))
                if record.outcome.is_none() || record.outcome == Some(Outcome::Unknown) =>
            {
                return Outcome::Refused(crate::folder_create::Refusal::Unavailable)
            }
            _ => (),
        }
        if publish_delete(&file, request, None).is_err() {
            return Outcome::Refused(crate::folder_create::Refusal::Unavailable);
        }
        let outcome = backend.delete_folder(request);
        // Publish only after backend return, while retaining the same account lock.
        // Unknown never attests child exit/no write, even if the helper has returned.
        if publish_delete(&file, request, Some(outcome.clone())).is_err() {
            return Outcome::Unknown;
        }
        outcome
    }
}
pub(super) fn handle<B: MailboxBackend>(
    directory: Option<&Path>,
    backend: &B,
    action: &MailboxHelperRequest,
) -> Option<MailboxHelperResponse> {
    match action {
        MailboxHelperRequest::FolderDelete { request, grant } => {
            Some(MailboxHelperResponse::FolderDeleteOk {
                request: Box::new(request.clone()),
                nonce: grant.nonce.clone(),
                outcome: directory
                    .map(|d| delete_witness::execute_delete(d, backend, request))
                    .unwrap_or(crate::folder_delete::Outcome::Refused(
                        crate::folder_create::Refusal::Unavailable,
                    )),
            })
        }
        MailboxHelperRequest::FolderDeleteCompletion { request, grant } => {
            Some(MailboxHelperResponse::FolderDeleteCompletionOk {
                request: Box::new(request.clone()),
                nonce: grant.nonce.clone(),
                completion: directory
                    .map(|d| delete_witness::completion_delete(d, request))
                    .unwrap_or(crate::folder_delete::Completion::Unconfirmed),
            })
        }
        MailboxHelperRequest::FolderRename { request, grant } => {
            Some(MailboxHelperResponse::FolderRenameOk {
                request: Box::new(request.clone()),
                nonce: grant.nonce.clone(),
                outcome: directory
                    .map(|d| execute(d, backend, request))
                    .unwrap_or(Outcome::Refused(crate::folder_create::Refusal::Unavailable)),
            })
        }
        MailboxHelperRequest::FolderRenameCompletion { request, grant } => {
            Some(MailboxHelperResponse::FolderRenameCompletionOk {
                request: Box::new(request.clone()),
                nonce: grant.nonce.clone(),
                completion: directory
                    .map(|d| completion(d, request))
                    .unwrap_or(Completion::Unconfirmed),
            })
        }
        _ => None,
    }
}
