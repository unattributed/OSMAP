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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_settled: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recovery_steps: Vec<RecoveryStep>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryStep {
    nonce: String,
    dispatched: bool,
    outcome: Option<Outcome>,
    settled: bool,
}
fn read(file: &LockedAccountFile, account: &str) -> Result<Option<Record>, ()> {
    let Some(bytes) = file.read().map_err(|_| ())? else {
        return Ok(None);
    };
    let record: Record = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if record.version != 1
        || record.request.account() != account
        || record.request.validate().is_err()
        || record.request.is_recovery()
        || record.recovery_steps.len() > 8
        || record.recovery_steps.iter().any(|s| {
            s.nonce.len() != 32
                || s.nonce == record.request.action_nonce()
                || !s
                    .nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || record.recovery_steps.iter().enumerate().any(|(i, s)| {
            record.recovery_steps[..i]
                .iter()
                .any(|old| old.nonce == s.nonce)
        })
        || record.native_settled == Some(false)
        || record.native_settled == Some(true)
            && (record.request.descendants().is_empty()
                || !matches!(record.outcome, Some(Outcome::Unknown | Outcome::Renamed)))
        || record.recovery_steps.iter().any(|s| {
            !s.dispatched && (s.outcome.is_some() || s.settled) || s.settled && s.outcome.is_none()
        })
        || !record.recovery_steps.is_empty() && record.native_settled != Some(true)
    {
        return Err(());
    }
    Ok(Some(record))
}
fn publish(
    file: &LockedAccountFile,
    request: &RenameFolderRequest,
    outcome: Option<Outcome>,
    native_settled: Option<bool>,
) -> Result<(), ()> {
    let bytes = serde_json::to_vec(&Record {
        version: 1,
        request: request.clone(),
        outcome,
        native_settled,
        recovery_steps: Vec::new(),
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
    if request.is_recovery() {
        let Ok(original) = request.recovery_original() else {
            return Completion::Unconfirmed;
        };
        return match read(&file, request.account()) {
            Ok(Some(record)) if record.request == original => {
                if record.outcome == Some(Outcome::Renamed) {
                    return Completion::Renamed;
                }
                if record.outcome == Some(Outcome::Conflict) {
                    return Completion::NoMutation;
                }
                match record
                    .recovery_steps
                    .iter()
                    .find(|s| s.nonce == request.action_nonce())
                {
                    Some(step) if !step.dispatched => Completion::NoMutation,
                    Some(step) if step.settled => match step.outcome {
                        Some(Outcome::Renamed) => Completion::Renamed,
                        Some(Outcome::Refused(_)) | Some(Outcome::Conflict) => {
                            Completion::NoMutation
                        }
                        _ => Completion::SettledRecovery,
                    },
                    _ => Completion::Unconfirmed,
                }
            }
            _ => Completion::Unconfirmed,
        };
    }
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
    if request.is_recovery() {
        return execute_recovery(directory, backend, request);
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
    if publish(&file, request, None, None).is_err() {
        return Outcome::Refused(crate::folder_create::Refusal::Unavailable);
    }
    let attempt = backend.rename_folder_attempt(request);
    let outcome = attempt.outcome;
    // Publish only after backend return, while retaining the same account lock.
    // Unknown never attests child exit/no write, even if the helper has returned.
    let native_settled =
        (outcome == Outcome::Unknown && !request.descendants().is_empty() && attempt.settled)
            .then_some(true);
    if publish(&file, request, Some(outcome.clone()), native_settled).is_err() {
        return Outcome::Unknown;
    }
    outcome
}

fn write_record(file: &LockedAccountFile, record: &Record) -> Result<(), ()> {
    let bytes = serde_json::to_vec(record).map_err(|_| ())?;
    if bytes.len() > 4096 {
        return Err(());
    }
    file.write(&bytes).map_err(|_| ())
}

fn execute_recovery<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    request: &RenameFolderRequest,
) -> Outcome {
    use crate::{folder_create::Refusal, folder_rename::RecoveryPermit};
    let Ok(original) = request.recovery_original() else {
        return Outcome::Refused(Refusal::Invalid);
    };
    let Ok(file) = PrivateAccountFile::new(directory.into(), "osmap-folder-rename-helper-v1", 4096)
        .lock(request.account())
    else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    let Ok(Some(mut record)) = read(&file, request.account()) else {
        return Outcome::Refused(Refusal::Unavailable);
    };
    if record.request != original {
        return Outcome::Refused(Refusal::Stale);
    }
    if let Some(step) = record
        .recovery_steps
        .iter()
        .find(|s| s.nonce == request.action_nonce())
    {
        return if !step.dispatched {
            Outcome::Refused(Refusal::Unavailable)
        } else {
            step.outcome.clone().unwrap_or(Outcome::Unknown)
        };
    }
    if let Some(outcome @ (Outcome::Renamed | Outcome::Conflict)) = record.outcome {
        return outcome;
    }
    if record.outcome != Some(Outcome::Unknown)
        || record.native_settled != Some(true)
        || record
            .recovery_steps
            .iter()
            .any(|s| s.dispatched && !s.settled)
    {
        return Outcome::Refused(Refusal::Unavailable);
    }
    if record.recovery_steps.len() == 8 {
        return Outcome::Refused(Refusal::Capacity);
    }
    record.recovery_steps.push(RecoveryStep {
        nonce: request.action_nonce().into(),
        dispatched: false,
        outcome: None,
        settled: false,
    });
    if write_record(&file, &record).is_err() {
        return Outcome::Unknown;
    }
    let Some(step) = record.recovery_steps.last_mut() else {
        return Outcome::Unknown;
    };
    step.dispatched = true;
    if write_record(&file, &record).is_err() {
        return Outcome::Unknown;
    }
    let permit = RecoveryPermit::new(&record.request, request.action_nonce(), &file);
    let result = backend.recover_folder_subtree(&permit);
    let Some(step) = record.recovery_steps.last_mut() else {
        return Outcome::Unknown;
    };
    step.settled = result.attempt.settled;
    step.outcome = Some(result.attempt.outcome.clone());
    if result.complete
        && result.attempt.settled
        && matches!(result.attempt.outcome, Outcome::Renamed | Outcome::Conflict)
    {
        record.outcome = Some(result.attempt.outcome.clone());
        // Complete current GUID placement is terminal. Keep the original
        // legacy-readable Renamed witness; replay remains inspection-only
        // because the original action is already consumed. Unresolved steps
        // are never erased by this compatibility transition.
        record.native_settled = None;
        record.recovery_steps.clear();
    }
    if write_record(&file, &record).is_err() {
        return Outcome::Unknown;
    }
    result.attempt.outcome
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
