//! Explicit repair of a proven-settled native partial rename. Never root replay.
use crate::{
    auth::CommandExecutor,
    folder_create::Refusal,
    folder_rename::{
        NativeAttempt, NativeRecoveryAttempt, Outcome, RecoveryPermit, RenameFolderRequest,
    },
    mailbox::{DoveadmMailboxListBackend, MailboxBackend, MailboxListingPolicy},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Complete { destination: String },
    Unchanged,
    Progress,
    Inspected,
    Refused,
    Unknown,
    Unavailable,
}

pub(crate) fn recover<B: MailboxBackend>(
    directory: &Path,
    backend: &B,
    account: &str,
    nonce: &str,
) -> RecoveryOutcome {
    use crate::folder_rename::{Completion, RecoveryIntent};
    let Ok(mut role) = crate::folder_rename::role_lease(directory, account) else {
        return RecoveryOutcome::Unavailable;
    };
    let Some(original) = role.pending().cloned() else {
        return RecoveryOutcome::Unavailable;
    };
    let Ok(request) = original.for_recovery(nonce) else {
        return RecoveryOutcome::Refused;
    };
    if let Some(intent) = role.recovery() {
        if intent.nonce != nonce {
            return RecoveryOutcome::Unknown;
        }
        if !intent.dispatched {
            return if role.set_recovery(None).is_ok() {
                RecoveryOutcome::Inspected
            } else {
                RecoveryOutcome::Unknown
            };
        }
    } else {
        if placement(backend, &original).is_err() {
            return RecoveryOutcome::Refused;
        }
        if role
            .set_recovery(Some(RecoveryIntent {
                nonce: nonce.into(),
                dispatched: false,
            }))
            .is_err()
            || role
                .set_recovery(Some(RecoveryIntent {
                    nonce: nonce.into(),
                    dispatched: true,
                }))
                .is_err()
        {
            return RecoveryOutcome::Unknown;
        }
        match backend.rename_folder(&request) {
            Outcome::Refused(_) | Outcome::Conflict => {
                return if role.set_recovery(None).is_ok() {
                    if backend.folder_rename_completion(&original) == Completion::NoMutation {
                        RecoveryOutcome::Inspected
                    } else {
                        RecoveryOutcome::Refused
                    }
                } else {
                    RecoveryOutcome::Unknown
                }
            }
            Outcome::Renamed => {
                return if role.set_recovery(None).is_ok() {
                    RecoveryOutcome::Progress
                } else {
                    RecoveryOutcome::Unknown
                }
            }
            Outcome::Unknown => (),
        }
    }
    let outcome = match backend.folder_rename_completion(&request) {
        Completion::Renamed => RecoveryOutcome::Progress,
        Completion::NoMutation | Completion::SettledRecovery => RecoveryOutcome::Inspected,
        Completion::Unconfirmed => return RecoveryOutcome::Unknown,
    };
    if role.set_recovery(None).is_err() {
        return RecoveryOutcome::Unknown;
    }
    outcome
}

pub(crate) struct Placement {
    pub(crate) old: Vec<String>,
    next: Option<(String, String)>,
    unchanged: bool,
}

pub(crate) fn placement<B: MailboxBackend>(
    backend: &B,
    original: &RenameFolderRequest,
) -> Result<Placement, Refusal> {
    original.validate()?;
    if original.is_recovery() || original.descendants().is_empty() {
        return Err(Refusal::Invalid);
    }
    let snapshot = backend
        .folder_metadata(original.account())
        .map_err(|_| Refusal::Unavailable)?;
    snapshot
        .validate_for(original.account())
        .map_err(|_| Refusal::Invalid)?;
    let source_parent = backend
        .mailbox_status(original.account(), original.source_parent())
        .map_err(|_| Refusal::Unavailable)?;
    let destination_parent = backend
        .mailbox_status(original.account(), original.parent())
        .map_err(|_| Refusal::Unavailable)?;
    original.validate_source_parent(&snapshot, &source_parent)?;
    original.validate_destination_parent(&snapshot, &destination_parent)?;
    let identities = crate::folder_subtree::identities(original);
    let mut allowed = std::collections::BTreeSet::new();
    let mut old = Vec::new();
    let mut root_before = false;
    for (suffix, guid) in &identities {
        let before = format!("{}{suffix}", original.source());
        let after = format!("{}{suffix}", original.destination());
        allowed.insert(before.clone());
        allowed.insert(after.clone());
        let mut positions = Vec::new();
        for name in [&before, &after] {
            crate::folder_create::validate_private_namespace(&snapshot, name)?;
            if let Ok(entry) = snapshot.folder(original.account(), name) {
                if entry.has_flag("\\Noselect") || entry.has_flag("\\NonExistent") {
                    if entry.delimiter() != Some('.')
                        || !entry.special_use().is_empty()
                        || entry.flags().iter().any(|f| {
                            ![
                                "\\Noselect",
                                "\\NonExistent",
                                "\\HasChildren",
                                "\\HasNoChildren",
                                "\\Subscribed",
                                "\\Marked",
                                "\\Unmarked",
                            ]
                            .iter()
                            .any(|v| f.eq_ignore_ascii_case(v))
                        })
                    {
                        return Err(Refusal::Invalid);
                    }
                    continue;
                }
                if entry.delimiter() != Some('.')
                    || !entry.special_use().is_empty()
                    || entry.flags().iter().any(|f| {
                        ![
                            "\\HasChildren",
                            "\\HasNoChildren",
                            "\\Subscribed",
                            "\\Marked",
                            "\\Unmarked",
                        ]
                        .iter()
                        .any(|v| f.eq_ignore_ascii_case(v))
                    })
                {
                    return Err(Refusal::Invalid);
                }
                let status = backend
                    .mailbox_status(original.account(), name)
                    .map_err(|_| Refusal::Unavailable)?;
                status.validate(name).map_err(|_| Refusal::Unavailable)?;
                if status.guid() != guid {
                    return Err(Refusal::Stale);
                }
                positions.push(name);
            }
        }
        if positions.len() != 1 {
            return Err(Refusal::Stale);
        }
        if suffix.is_empty() {
            root_before = positions[0] == &before;
        }
        if positions[0] == &before {
            old.push(suffix.clone());
        }
    }
    if snapshot.folders().iter().any(|entry| {
        (entry.name() == original.source()
            || entry.name().starts_with(&format!("{}.", original.source()))
            || entry.name() == original.destination()
            || entry
                .name()
                .starts_with(&format!("{}.", original.destination())))
            && !allowed.contains(entry.name())
    }) {
        return Err(Refusal::Invalid);
    }
    old.sort_by(|a, b| {
        a.matches('.')
            .count()
            .cmp(&b.matches('.').count())
            .then(a.cmp(b))
    });
    let unchanged = root_before && old.len() == identities.len();
    if root_before && !unchanged {
        return Err(Refusal::Stale);
    }
    let next = if unchanged {
        None
    } else if let Some(suffix) = old.first() {
        let source = format!("{}{suffix}", original.source());
        let target = format!("{}{suffix}", original.destination());
        // The selected root is proven at its old path and absent at its new
        // path. A virtual new parent may already contain original descendants:
        // the complete placement loop above proves every one has exactly one
        // original GUID at either path, so the two child sets are disjoint.
        // Maildir++ rename can complete this missing-root merge. Never admit
        // an existing selectable destination or an unbound child.
        if snapshot
            .folder(original.account(), &target)
            .is_ok_and(|entry| !entry.has_flag("\\Noselect") && !entry.has_flag("\\NonExistent"))
        {
            return Err(Refusal::Stale);
        }
        let parent = target.rsplit_once('.').ok_or(Refusal::Invalid)?.0;
        if !crate::sent_location::selectable(&snapshot, original.account(), parent) {
            return Err(Refusal::Unavailable);
        }
        Some((source, target))
    } else {
        None
    };
    Ok(Placement {
        old,
        next,
        unchanged,
    })
}

pub(crate) fn native_recover<E: CommandExecutor>(
    executor: &E,
    path: &Path,
    socket: Option<&Path>,
    permit: &RecoveryPermit<'_>,
) -> NativeRecoveryAttempt {
    let original = permit.original();
    let refusal = |reason| NativeRecoveryAttempt {
        attempt: NativeAttempt::undispatched(Outcome::Refused(reason)),
        complete: false,
    };
    let Ok(_guard) = crate::folder_rename_backend::GATE.try_lock() else {
        return refusal(Refusal::Unavailable);
    };
    let limited = crate::folder_create_backend::Deadline {
        inner: executor,
        until: Instant::now() + Duration::from_secs(10),
    };
    let backend = DoveadmMailboxListBackend::new(MailboxListingPolicy::default(), &limited, path)
        .with_userdb_socket_path(socket.map(Path::to_path_buf));
    let before = match placement(&backend, original) {
        Ok(value) => value,
        Err(reason) => return refusal(reason),
    };
    let Some((source, destination)) = &before.next else {
        return NativeRecoveryAttempt {
            attempt: NativeAttempt::undispatched(if before.unchanged {
                Outcome::Conflict
            } else {
                Outcome::Renamed
            }),
            complete: true,
        };
    };
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
        original.account().into(),
        source.clone(),
        destination.clone(),
    ]);
    let attempt = limited.run_folder_mutation(
        &path.to_string_lossy(),
        &args,
        b"",
        Duration::from_secs(10),
        4096,
    );
    let Ok(result) = attempt.result else {
        return NativeRecoveryAttempt {
            attempt: if attempt.settled {
                NativeAttempt::returned(Outcome::Unknown)
            } else {
                NativeAttempt::unsettled(Outcome::Unknown)
            },
            complete: false,
        };
    };
    // SystemCommandExecutor returns CommandExecution only after wait() and
    // bounded stream joins. Never infer this from a status code or an error.
    let after = match placement(&backend, original) {
        Ok(value) => value,
        Err(_) => {
            return NativeRecoveryAttempt {
                attempt: NativeAttempt::returned(Outcome::Unknown),
                complete: false,
            }
        }
    };
    let complete = after.old.is_empty();
    let selected_suffix = source.strip_prefix(original.source()).unwrap_or("");
    let selected_remaining = after
        .old
        .iter()
        .any(|s| s == selected_suffix || s.starts_with(&format!("{selected_suffix}.")));
    let outcome = if complete
        || result.status_code == 0 && !selected_remaining && after.old.len() < before.old.len()
    {
        Outcome::Renamed
    } else {
        Outcome::Unknown
    };
    NativeRecoveryAttempt {
        attempt: NativeAttempt::returned(outcome),
        complete,
    }
}

#[cfg(test)]
#[path = "folder_subtree_recovery_tests.rs"]
mod tests;
