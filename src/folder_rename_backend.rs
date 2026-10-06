use crate::{
    auth::CommandExecutor,
    folder_create::Refusal,
    folder_rename::{Outcome, RenameFolderRequest},
    mailbox::{DoveadmMailboxListBackend, MailboxBackend, MailboxListingPolicy},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};
pub(crate) fn rename<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    request: &RenameFolderRequest,
) -> Outcome {
    if let Err(e) = request.validate() {
        return Outcome::Refused(e);
    }
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let Ok(_guard) = GATE.try_lock() else {
        return Outcome::Refused(Refusal::Unavailable);
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
        return Outcome::Refused(Refusal::Unavailable);
    };
    if let Err(e) = request.validate_before(&before, &source, &parent) {
        return Outcome::Refused(e);
    }
    if before
        .folder(request.account(), &request.destination())
        .is_ok()
    {
        return Outcome::Conflict;
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
    let result = limited.run_with_stdin_bytes_timeout_and_output_limit(
        &path.to_string_lossy(),
        &args,
        b"",
        Duration::from_secs(10),
        4096,
    );
    let Ok(result) = result else {
        return Outcome::Unknown;
    };
    if result.status_code != 0 {
        return Outcome::Unknown;
    }
    let (Ok(after), Ok(destination), Ok(parent)) = (
        backend.folder_metadata(request.account()),
        backend.mailbox_status(request.account(), &request.destination()),
        backend.mailbox_status(request.account(), request.parent()),
    ) else {
        return Outcome::Unknown;
    };
    if !crate::folder_rename::confirmed_result(request, &after, &destination, &parent) {
        return Outcome::Unknown;
    }
    Outcome::Renamed
}

#[cfg(test)]
#[path = "folder_rename_backend_tests.rs"]
mod tests;
