//! Pinned-descriptor projection of operator state for the unprivileged UI.
use super::*;
use sha2::{Digest as _, Sha256};
use std::fs::{File, Metadata};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

fn failure<T>(_: T) -> Error {
    Error::Unavailable
}
fn name(value: &str) -> Result<std::ffi::CString, Error> {
    std::ffi::CString::new(value).map_err(failure)
}
fn open_at(directory: &File, leaf: &std::ffi::CStr, flags: i32) -> Result<File, Error> {
    crate::openbsd::private_leaf_open(directory, leaf, flags).map_err(failure)
}
fn same_at(directory: &File, leaf: &std::ffi::CStr, expected: &Metadata) -> bool {
    open_at(directory, leaf, libc::O_RDONLY)
        .and_then(|f| f.metadata().map_err(failure))
        .is_ok_and(|m| {
            m.is_file() && m.dev() == expected.dev() && m.ino() == expected.ino() && m.nlink() == 1
        })
}
fn private_directory(file: &File, owner: u32, group: u32) -> Result<(), Error> {
    let m = file.metadata().map_err(failure)?;
    if !m.is_dir() || m.uid() != owner || m.gid() != group || m.mode() & 0o7777 != 0o700 {
        return Err(Error::Unavailable);
    }
    Ok(())
}
fn existing_path(path: &Path, owner: u32) -> Result<File, Error> {
    if !path.is_absolute() {
        return Err(Error::Refused);
    }
    let mut directory = File::open("/").map_err(failure)?;
    for part in path.components() {
        match part {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(part) => {
                let leaf = std::ffi::CString::new(part.as_encoded_bytes()).map_err(failure)?;
                directory = open_at(&directory, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
                let m = directory.metadata().map_err(failure)?;
                let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
                if !m.is_dir()
                    || (m.uid() != 0 && m.uid() != owner)
                    || m.mode() & 0o022 != 0 && !sticky_root
                {
                    return Err(Error::Unavailable);
                }
            }
            _ => return Err(Error::Refused),
        }
    }
    Ok(directory)
}
fn child_directory(parent: &File, leaf: &str, owner: u32, group: u32) -> Result<File, Error> {
    let leaf = name(leaf)?;
    let created = crate::openbsd::private_directory_create(parent, &leaf).map_err(failure)?;
    let directory = open_at(parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
    if created {
        let m = directory.metadata().map_err(failure)?;
        if m.uid() != crate::openbsd::effective_uid() || !m.is_dir() {
            return Err(Error::Unavailable);
        }
        directory
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(failure)?;
        crate::openbsd::private_file_set_owner(&directory, owner, group).map_err(failure)?;
        directory.sync_all().map_err(failure)?;
        parent.sync_all().map_err(failure)?;
    }
    private_directory(&directory, owner, group)?;
    Ok(directory)
}
fn read_at(directory: &File, leaf: &std::ffi::CStr, owner: u32) -> Result<Option<Vec<u8>>, Error> {
    let mut file = match crate::openbsd::private_leaf_open(directory, leaf, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(failure(error)),
    };
    let m = file.metadata().map_err(failure)?;
    if !m.is_file()
        || m.uid() != owner
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > MAX_BYTES as u64
    {
        return Err(Error::Unavailable);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::Unavailable);
    }
    Ok(Some(bytes))
}

/// Publish only bounded nonsecret metadata. This projection never authorizes
/// identity, factor replacement, reconciliation or containment release.
pub(crate) fn publish_operator_status(
    root: &Path,
    account: &str,
    status: &crate::account_recovery::Status,
    owner: u32,
    group: u32,
    now: u64,
) -> Result<(), Error> {
    let Some(case_id) = status.case_id.as_ref() else {
        return Ok(());
    };
    if status.account != account {
        return Err(Error::Refused);
    }
    crate::identity::CanonicalUsername::parse(account.to_owned()).map_err(|_| Error::Refused)?;
    if now == 0 || root.file_name().and_then(|v| v.to_str()) != Some("account-recovery") {
        return Err(Error::Refused);
    }
    let parent = existing_path(root.parent().ok_or(Error::Refused)?, owner)?;
    private_directory(&parent, owner, group)?;
    let root_dir = child_directory(&parent, "account-recovery", owner, group)?;
    let directory = child_directory(&root_dir, "cases", owner, group)?;
    let mut hash = Sha256::new();
    hash.update(NAMESPACE.as_bytes());
    hash.update(b"\0");
    hash.update(account.as_bytes());
    let leaf = name(&format!("{:x}.json", hash.finalize()))?;
    let previous = decode(read_at(&directory, &leaf, owner)?, account)?;
    let state = match status.case_state {
        Some(crate::account_recovery::CaseState::ReleasePending) => "manual_review".into(),
        Some(value) => serde_json::to_value(value)
            .map_err(failure)?
            .as_str()
            .ok_or(Error::Unavailable)?
            .to_owned(),
        None => return Err(Error::Unavailable),
    };
    let record = RequestRecord {
        account: account.into(),
        case_id: case_id.clone(),
        state,
        revision: previous.as_ref().map_or(Ok(1), |r| {
            r.revision.checked_add(1).ok_or(Error::Unavailable)
        })?,
        requested_at: previous
            .as_ref()
            .filter(|r| r.case_id == *case_id)
            .map_or(now, |r| r.requested_at),
        updated_at: now,
        account_state: Some(status.state.into()),
        account_epoch: Some(status.epoch),
    };
    if !valid(&record, account) {
        return Err(Error::Unavailable);
    }
    let bytes = serde_json::to_vec(&record).map_err(failure)?;
    let temp = name(&format!(
        ".recovery-status-{}-{}",
        std::process::id(),
        crate::draft::generate_draft_id().map_err(failure)?
    ))?;
    let mut file = open_at(
        &directory,
        &temp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    let created = file.metadata().map_err(failure)?;
    let result = (|| {
        crate::openbsd::private_file_set_owner(&file, owner, group).map_err(failure)?;
        file.write_all(&bytes).map_err(failure)?;
        file.sync_all().map_err(failure)?;
        if !same_at(&directory, &temp, &created) {
            return Err(Error::Unavailable);
        }
        crate::openbsd::private_leaf_rename(&directory, &temp, &leaf).map_err(failure)?;
        directory.sync_all().map_err(failure)?;
        if read_at(&directory, &leaf, owner)?.as_deref() != Some(bytes.as_slice()) {
            return Err(Error::Unavailable);
        }
        // Publication is useful only if the UI still names these same dirs.
        let current = existing_path(root, owner)?;
        let m = current.metadata().map_err(failure)?;
        let held = root_dir.metadata().map_err(failure)?;
        if m.dev() != held.dev() || m.ino() != held.ino() {
            return Err(Error::Unavailable);
        }
        let current = open_at(
            &current,
            &name("cases")?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let m = current.metadata().map_err(failure)?;
        let held = directory.metadata().map_err(failure)?;
        if m.dev() != held.dev() || m.ino() != held.ino() {
            return Err(Error::Unavailable);
        }
        Ok(())
    })();
    if result.is_err() && same_at(&directory, &temp, &created) {
        let _ = crate::openbsd::private_leaf_unlink(&directory, &temp);
    }
    result
}
