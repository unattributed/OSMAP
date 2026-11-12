//! The existing custody checks, with payload-free failure provenance.
//! Legacy callers retain their original error contract through thin wrappers.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Check {
    AncestorMetadata,
    AncestorDirectory,
    AncestorOwner,
    AncestorPermissions,
    AbsolutePath,
    PathLength,
    Canonicalize,
    CanonicalPath,
    ParentPath,
    DirectoryMetadata,
    DirectoryType,
    DirectoryOwner,
    DirectoryPermissions,
    FileOpen,
    FileMetadata,
    FileType,
    FileOwner,
    FileSize,
    FilePermissions,
    Executable,
    KeyRead,
    KeyLength,
    SocketMetadata,
    SocketType,
    SocketOwner,
    SocketPermissions,
    SocketLinks,
    ParentMetadata,
    KeyMetadata,
    KeyLinks,
    DescriptorFlags,
    CloseOnExec,
    ParentIdentity,
    SocketIdentity,
    KeyDescriptorIdentity,
    KeyPathIdentity,
    KeyContent,
    CoreDumpLimit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Category {
    Invariant,
    Absent,
    Denied,
    Invalid,
    Busy,
    Capacity,
    Deadline,
    Interrupted,
    Unsupported,
    OtherIo,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Failure {
    pub(crate) check: Check,
    pub(crate) category: Category,
    #[serde(skip)]
    original: Error,
}
impl Failure {
    pub(crate) fn invariant(check: Check) -> Self {
        Self {
            check,
            category: Category::Invariant,
            original: Error::Unavailable,
        }
    }
    fn invalid(check: Check) -> Self {
        Self {
            original: Error::Invalid,
            ..Self::invariant(check)
        }
    }
    pub(crate) fn io(check: Check, error: std::io::Error) -> Self {
        use std::io::ErrorKind as K;
        let category = match error.kind() {
            K::NotFound => Category::Absent,
            K::PermissionDenied => Category::Denied,
            K::InvalidInput | K::InvalidData => Category::Invalid,
            K::WouldBlock | K::AlreadyExists => Category::Busy,
            K::OutOfMemory | K::StorageFull => Category::Capacity,
            K::TimedOut => Category::Deadline,
            K::Interrupted => Category::Interrupted,
            K::Unsupported => Category::Unsupported,
            _ => Category::OtherIo,
        };
        Self {
            check,
            category,
            original: Error::Unavailable,
        }
    }
    pub(crate) fn into_original(self) -> Error {
        self.original
    }
}
fn protected_ancestors(path: &Path, owner: u32) -> Result<(), Failure> {
    for ancestor in path.ancestors().skip(1) {
        // Preserve the OS-owned root trust anchor and sticky-root exception.
        if ancestor == Path::new("/") {
            break;
        }
        let m =
            fs::symlink_metadata(ancestor).map_err(|e| Failure::io(Check::AncestorMetadata, e))?;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir() {
            return Err(Failure::invariant(Check::AncestorDirectory));
        }
        if m.uid() != 0 && m.uid() != owner {
            return Err(Failure::invariant(Check::AncestorOwner));
        }
        if m.mode() & 0o022 != 0 && !sticky_root {
            return Err(Failure::invariant(Check::AncestorPermissions));
        }
    }
    Ok(())
}
pub(crate) fn exact_path(path: &Path, owner: u32) -> Result<(), Failure> {
    protected_ancestors(path, owner)?;
    if !path.is_absolute() {
        return Err(Failure::invalid(Check::AbsolutePath));
    }
    if path.as_os_str().len() > 4096 {
        return Err(Failure::invalid(Check::PathLength));
    }
    if fs::canonicalize(path).map_err(|e| Failure::io(Check::Canonicalize, e))? != path {
        return Err(Failure::invalid(Check::CanonicalPath));
    }
    Ok(())
}
pub(crate) fn private_dir(path: &Path, owner: u32, shared: bool) -> Result<(), Failure> {
    exact_path(path, owner)?;
    let m = fs::symlink_metadata(path).map_err(|e| Failure::io(Check::DirectoryMetadata, e))?;
    if !m.is_dir() {
        return Err(Failure::invariant(Check::DirectoryType));
    }
    if m.uid() != owner {
        return Err(Failure::invariant(Check::DirectoryOwner));
    }
    if m.mode() & (if shared { 0o027 } else { 0o077 }) != 0 {
        return Err(Failure::invariant(Check::DirectoryPermissions));
    }
    Ok(())
}
pub(crate) fn file(path: &Path, owner: u32, executable: bool, max: u64) -> Result<File, Failure> {
    exact_path(path, owner)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Failure::io(Check::FileOpen, e))?;
    let m = f
        .metadata()
        .map_err(|e| Failure::io(Check::FileMetadata, e))?;
    if !m.is_file() {
        return Err(Failure::invariant(Check::FileType));
    }
    if m.uid() != owner {
        return Err(Failure::invariant(Check::FileOwner));
    }
    if m.len() > max {
        return Err(Failure::invariant(Check::FileSize));
    }
    if m.mode() & (if executable { 0o022 } else { 0o077 }) != 0 {
        return Err(Failure::invariant(Check::FilePermissions));
    }
    if executable && m.mode() & 0o111 == 0 {
        return Err(Failure::invariant(Check::Executable));
    }
    Ok(f)
}
pub(crate) fn secret(path: &Path) -> Result<Vec<u8>, Failure> {
    let mut b = Vec::new();
    file(path, crate::openbsd::effective_uid(), false, 1024)?
        .take(1025)
        .read_to_end(&mut b)
        .map_err(|e| Failure::io(Check::KeyRead, e))?;
    if !(32..=1024).contains(&b.len()) {
        return Err(Failure::invalid(Check::KeyLength));
    }
    Ok(b)
}
pub(crate) fn validate_socket(path: &Path, owner: u32) -> Result<(), Failure> {
    exact_path(path, owner)?;
    private_dir(
        path.parent()
            .ok_or_else(|| Failure::invalid(Check::ParentPath))?,
        owner,
        true,
    )?;
    let m = fs::symlink_metadata(path).map_err(|e| Failure::io(Check::SocketMetadata, e))?;
    if !m.file_type().is_socket() {
        return Err(Failure::invariant(Check::SocketType));
    }
    if m.uid() != owner {
        return Err(Failure::invariant(Check::SocketOwner));
    }
    if m.mode() & 0o117 != 0 {
        return Err(Failure::invariant(Check::SocketPermissions));
    }
    Ok(())
}
