//! Publish one complete draft version without removing the previous manifest.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const SAVE_UNCONFIRMED: &str = "draft save publication unconfirmed";

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SaveFault {
    BeforePublish,
    AfterPublish,
}

pub(super) fn blob_name(body: &[u8]) -> String {
    format!("attachment-{}.body", hex_lower(&Sha256::digest(body)))
}

pub(super) fn is_blob_name(name: &str) -> bool {
    name.strip_prefix("attachment-")
        .and_then(|name| name.strip_suffix(".body"))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

pub(super) fn legacy_backup_id(name: &str) -> Option<&str> {
    let fields: Vec<_> = name.split('.').collect();
    if fields.len() != 5
        || !fields[0].is_empty()
        || fields[4] != "backup"
        || validate_draft_id(fields[1]).is_err()
    {
        return None;
    }
    for value in &fields[2..4] {
        let number = value.parse::<u64>().ok()?;
        if number.to_string() != *value {
            return None;
        }
    }
    Some(fields[1])
}

fn sync_directory(path: &Path) -> Result<(), DraftError> {
    crate::private_account_file::check_directory(path).map_err(|_| unavailable())?;
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| unavailable())
}

fn unavailable() -> DraftError {
    DraftError {
        reason: "draft atomic storage unavailable".into(),
    }
}

fn temporary_name() -> String {
    format!(
        ".draft-write-{}-{}.tmp",
        std::process::id(),
        NEXT_DRAFT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed)
    )
}

fn is_temporary_name(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix(".draft-write-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let parts: Vec<_> = middle.split('-').collect();
    parts.len() == 2
        && parts.iter().all(|value| {
            value
                .parse::<u64>()
                .ok()
                .is_some_and(|number| number.to_string() == *value)
        })
}

fn cleanup_blobs(
    directory: &Path,
    keep: &BTreeSet<String>,
    policy: DraftPolicy,
) -> Result<(), DraftError> {
    let entries = fs::read_dir(directory).map_err(|_| unavailable())?;
    for (index, entry) in entries.enumerate() {
        if index > 64 {
            return Err(unavailable());
        }
        let entry = entry.map_err(|_| unavailable())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let legacy = (0..policy.compose_policy.max_attachments)
            .any(|index| name == attachment_body_file_name(index));
        if !keep.contains(name) && (is_blob_name(name) || legacy || is_temporary_name(name)) {
            // Reuse the private regular-file, owner, link and size checks before cleanup.
            crate::private_account_file::read_record(
                &entry.path(),
                policy.compose_policy.attachment_max_bytes,
            )
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
            fs::remove_file(entry.path()).map_err(|_| unavailable())?;
        }
    }
    Ok(())
}

impl FileDraftStore {
    pub(super) fn recover_legacy_backups(&self, account: &str) -> Result<(), DraftError> {
        let owner = self.owner_dir_for_username(account);
        if !private_directory_exists(&owner)? {
            return Ok(());
        }
        let mut backups = BTreeMap::<String, Vec<PathBuf>>::new();
        for (index, entry) in fs::read_dir(&owner).map_err(|_| unavailable())?.enumerate() {
            if index > 256 {
                return Err(unavailable());
            }
            let entry = entry.map_err(|_| unavailable())?;
            if let Some(id) = entry.file_name().to_str().and_then(legacy_backup_id) {
                backups.entry(id.into()).or_default().push(entry.path());
            }
        }
        for (id, candidates) in backups {
            if candidates.len() != 1 {
                return Err(DraftError {
                    reason: "draft recovery is ambiguous".into(),
                });
            }
            let backup = &candidates[0];
            let old = self
                .read_record_from_metadata(account, &backup.join(DRAFT_METADATA_FILE))?
                .ok_or_else(unavailable)?;
            let final_dir = owner.join(&id);
            if private_directory_exists(&final_dir)? {
                let current = self
                    .read_record_from_metadata(account, &final_dir.join(DRAFT_METADATA_FILE))?
                    .ok_or_else(unavailable)?;
                if current.revision <= old.revision {
                    return Err(DraftError {
                        reason: "draft recovery is ambiguous".into(),
                    });
                }
                sync_directory(&final_dir)?;
                sync_directory(&owner)?;
                // Once the newer version is durable, retire the backup name
                // atomically so a later discard cannot resurrect it.
                let retired = owner.join(format!(
                    ".draft-retired-{}-{}-{}",
                    id,
                    std::process::id(),
                    NEXT_DRAFT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed)
                ));
                fs::rename(backup, &retired).map_err(|_| unavailable())?;
                sync_directory(&owner)?;
                let _ = remove_draft_dir(retired);
            } else {
                fs::rename(backup, &final_dir).map_err(|_| unavailable())?;
                sync_directory(&final_dir)?;
            }
            sync_directory(&owner)?;
        }
        // An interrupted first save has no published manifest. Only remove our
        // generated private files; unexpected entries remain and refuse cleanup.
        for entry in fs::read_dir(&owner).map_err(|_| unavailable())? {
            let entry = entry.map_err(|_| unavailable())?;
            if entry
                .file_name()
                .to_str()
                .is_none_or(|name| validate_draft_id(name).is_err())
            {
                continue;
            }
            crate::private_account_file::check_directory(&entry.path())
                .map_err(|_| unavailable())?;
            let missing_manifest =
                match fs::symlink_metadata(entry.path().join(DRAFT_METADATA_FILE)) {
                    Ok(_) => false,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                    Err(_) => return Err(unavailable()),
                };
            if missing_manifest {
                cleanup_blobs(&entry.path(), &BTreeSet::new(), self.policy)?;
                fs::remove_dir(entry.path()).map_err(|_| unavailable())?;
                sync_directory(&owner)?;
            }
        }
        Ok(())
    }

    pub(super) fn publish_atomic_record(
        &self,
        record: &DraftRecord,
        previous: Option<&DraftRecord>,
    ) -> Result<(), DraftError> {
        let owner = self.ensure_owner_dir(&record.canonical_username)?;
        sync_directory(&self.draft_root)?;
        let directory = owner.join(&record.draft_id);
        create_private_directory(&directory)?;
        sync_directory(&owner)?;

        // Preserve both possible filename forms while migrating an older manifest.
        let mut old_files = BTreeSet::new();
        if let Some(previous) = previous {
            for (index, file) in previous.request.attachments.iter().enumerate() {
                old_files.insert(blob_name(&file.body));
                old_files.insert(attachment_body_file_name(index));
            }
        }
        cleanup_blobs(&directory, &old_files, self.policy)?;
        let mut published_files = BTreeSet::new();
        for file in &record.request.attachments {
            let name = blob_name(&file.body);
            let destination = directory.join(&name);
            match crate::private_account_file::read_record(
                &destination,
                self.policy.compose_policy.attachment_max_bytes,
            )
            .map_err(|_| unavailable())?
            {
                Some(bytes) if bytes != file.body => return Err(unavailable()),
                Some(_) => {}
                None => {
                    write_file_atomic(&directory.join(temporary_name()), &destination, &file.body)?
                }
            }
            published_files.insert(name);
        }
        // All referenced blob names and bytes precede the new manifest's publication.
        sync_directory(&directory)?;
        #[cfg(test)]
        if self.save_fault == Some(SaveFault::BeforePublish) {
            return Err(unavailable());
        }
        write_file_atomic(
            &directory.join(temporary_name()),
            &directory.join(DRAFT_METADATA_FILE),
            serialize_draft_metadata(record).as_bytes(),
        )?;
        #[cfg(test)]
        if self.save_fault == Some(SaveFault::AfterPublish) {
            return Err(DraftError {
                reason: SAVE_UNCONFIRMED.into(),
            });
        }
        sync_directory(&directory).map_err(|_| DraftError {
            reason: SAVE_UNCONFIRMED.into(),
        })?;
        // Cleanup cannot turn an acknowledged, durable version into a failed save.
        // The next write must complete cleanup before allocating more blobs.
        let _ = cleanup_blobs(&directory, &published_files, self.policy);
        Ok(())
    }
}
