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
    let before_names = phase_names(request, false);
    let Ok(before) = backend.folder_facts(request.account(), &before_names) else {
        return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
    };
    if before
        .validate_for(request.account(), &before_names)
        .is_err()
    {
        return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
    }
    let (Ok(source), Ok(parent)) = (
        before.status(request.source()),
        before.status(request.parent()),
    ) else {
        return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
    };
    if let Err(e) = request.validate_before(before.snapshot(), source, parent) {
        return NativeAttempt::undispatched(Outcome::Refused(e));
    }
    if request.is_move() {
        let Ok(source_parent) = before.status(request.source_parent()) else {
            return NativeAttempt::undispatched(Outcome::Refused(Refusal::Unavailable));
        };
        if let Err(e) = request.validate_source_parent(before.snapshot(), source_parent) {
            return NativeAttempt::undispatched(Outcome::Refused(e));
        }
    }
    if before
        .snapshot()
        .folder(request.account(), &request.destination())
        .is_ok()
        || before
            .snapshot()
            .folders()
            .iter()
            .any(|f| f.name().starts_with(&format!("{}.", request.destination())))
    {
        return NativeAttempt::undispatched(Outcome::Conflict);
    }
    if let Err(reason) =
        crate::folder_subtree::check_from(request, before.snapshot(), false, |name| {
            before
                .status(name)
                .cloned()
                .map_err(|_| Refusal::Unavailable)
        })
    {
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
    // Capture a new phase after native return. Nothing from before dispatch
    // supplies after-state authority; the same outer Deadline still applies.
    let after_names = phase_names(request, true);
    let Ok(after) = backend.folder_facts(request.account(), &after_names) else {
        return NativeAttempt::returned(Outcome::Unknown);
    };
    if after.validate_for(request.account(), &after_names).is_err() {
        return NativeAttempt::returned(Outcome::Unknown);
    }
    let (Ok(destination), Ok(parent)) = (
        after.status(&request.destination()),
        after.status(request.parent()),
    ) else {
        return NativeAttempt::returned(Outcome::Unknown);
    };
    if !crate::folder_rename::confirmed_result(request, after.snapshot(), destination, parent) {
        return NativeAttempt::returned(Outcome::Unknown);
    }
    if crate::folder_subtree::check_from(request, after.snapshot(), true, |name| {
        after
            .status(name)
            .cloned()
            .map_err(|_| Refusal::Unavailable)
    })
    .is_err()
    {
        return NativeAttempt::returned(Outcome::Unknown);
    }
    NativeAttempt::returned(Outcome::Renamed)
}

// Only the identities already required by this native phase are requested.
// The typed backend observes one current metadata transcript and one bounded
// exact-name STATUS batch under the original shared ten-second operation cap.
fn phase_names(request: &RenameFolderRequest, changed: bool) -> Vec<String> {
    let root = if changed {
        request.destination()
    } else {
        request.source().to_owned()
    };
    let mut names = vec![root.clone(), request.parent().to_owned()];
    if !changed && request.is_move() {
        names.push(request.source_parent().to_owned());
    }
    names.extend(
        request
            .descendants()
            .iter()
            .map(|child| format!("{root}{}", child.suffix())),
    );
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
#[path = "folder_rename_backend_tests.rs"]
mod tests;
