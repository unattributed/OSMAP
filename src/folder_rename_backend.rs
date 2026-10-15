use crate::{
    auth::CommandExecutor,
    folder_create::Refusal,
    folder_rename::{NativeAttempt, Outcome, RenameFolderRequest},
    mailbox::{DoveadmMailboxListBackend, MailboxBackend, MailboxListingPolicy},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};
#[cfg(test)]
pub(crate) static TEST_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub(crate) fn rename<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    request: &RenameFolderRequest,
) -> Outcome {
    rename_attempt(executor, path, socket, request).outcome
}
pub(crate) fn rename_attempt<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    request: &RenameFolderRequest,
) -> NativeAttempt {
    if request.is_recovery() {
        return NativeAttempt::undispatched(Outcome::Refused(Refusal::Invalid));
    }
    if let Err(e) = request.validate() {
        return NativeAttempt::undispatched(Outcome::Refused(e));
    }
    let Ok(_guard) = GATE.try_lock() else {
        return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
    };
    let limited = crate::folder_create_backend::Deadline {
        inner: executor,
        until: Instant::now() + Duration::from_secs(10),
    };
    let backend = DoveadmMailboxListBackend::new(MailboxListingPolicy::default(), &limited, path)
        .with_userdb_socket_path(socket.map(Path::to_path_buf));
    let (Ok(before), Ok(source), Ok(parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), request.source()),
        backend.mailbox_status(request.account(), request.parent()),
    ) else {
        return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
    };
    if let Err(e) = request.validate_before(&before, &source, &parent) {
        return NativeAttempt::undispatched(Outcome::Refused(e));
    }
    if request.is_move() {
        let Ok(source_parent) = backend.mailbox_status(request.account(), request.source_parent())
        else {
            return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
        };
        if let Err(e) = request.validate_source_parent(&before, &source_parent) {
            return NativeAttempt::undispatched(Outcome::Refused(e));
        }
    }
    if before
        .folder(request.account(), &request.destination())
        .is_ok()
        || before
            .folders()
            .iter()
            .any(|f| f.name().starts_with(&format!("{}.", request.destination())))
    {
        return NativeAttempt::undispatched(Outcome::Conflict);
    }
    if let Err(reason) = crate::folder_subtree::check(&backend, request, &before, false) {
        return NativeAttempt::undispatched(Outcome::Refused(reason));
    }
    let mut args = vec!["-o".into(), "stats_writer_socket_path=".into()];
    if let Some(socket) = socket {
        args.extend([
            "-o".into(),
            format!("auth_socket_path={}", socket.display()),
        ]);
    }
    args.extend([
        "mailbox".into(),
        "rename".into(),
        "-u".into(),
        request.account().into(),
        request.source().into(),
        request.destination(),
    ]);
    let attempt = limited.run_folder_mutation(
        &path.to_string_lossy(),
        &args,
        b"",
        Duration::from_secs(10),
        4096,
    );
    let Ok(result) = attempt.result else {
        return if attempt.settled {
            NativeAttempt::returned(Outcome::Unknown)
        } else {
            NativeAttempt::unsettled(Outcome::Unknown)
        };
    };
    if result.status_code != 0 {
        return NativeAttempt::returned(Outcome::Unknown);
    }
    let (Ok(after), Ok(destination), Ok(parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), &request.destination()),
        backend.mailbox_status(request.account(), request.parent()),
    ) else {
        return NativeAttempt::returned(Outcome::Unknown);
    };
    if !crate::folder_rename::confirmed_result(request, &after, &destination, &parent) {
        return NativeAttempt::returned(Outcome::Unknown);
    }
    if crate::folder_subtree::check(&backend, request, &after, true).is_err() {
        return NativeAttempt::returned(Outcome::Unknown);
    }
    NativeAttempt::returned(Outcome::Renamed)
}

#[cfg(test)]
#[path = "folder_rename_backend_tests.rs"]
mod tests;
