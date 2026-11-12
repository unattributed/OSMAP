//! Protected directory witnesses captured before unveil hides ancestors.
//! Descriptors here are used only for fstat, never traversal or enumeration.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Unavailable;
pub(crate) type Identity = [u64; 5];
fn identity(m: &fs::Metadata) -> Identity {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
    ]
}
struct Witness {
    descriptor: File,
    identity: Identity,
}
pub(crate) struct Custody {
    parents: BTreeMap<PathBuf, Witness>,
    sealed: AtomicBool,
}
static CUSTODY: OnceLock<Arc<Custody>> = OnceLock::new();
fn directory(m: &fs::Metadata) -> Result<(), Unavailable> {
    if !m.is_dir() || m.mode() & 0o022 != 0 {
        return Err(Unavailable);
    }
    Ok(())
}
impl Custody {
    pub(crate) fn capture(paths: &[&str], deadline: Instant) -> Result<Arc<Self>, Unavailable> {
        Self::capture_checked(paths, deadline, |_, metadata| directory(metadata))
    }
    fn capture_checked<F>(
        paths: &[&str],
        deadline: Instant,
        validate: F,
    ) -> Result<Arc<Self>, Unavailable>
    where
        F: Fn(&Path, &fs::Metadata) -> Result<(), Unavailable>,
    {
        if CUSTODY.get().is_some() {
            return Err(Unavailable);
        }
        let mut parents = BTreeMap::new();
        for path in paths {
            if !Path::new(path).is_absolute() {
                return Err(Unavailable);
            }
            for ancestor in Path::new(path).ancestors().skip(1) {
                if Instant::now() >= deadline {
                    return Err(Unavailable);
                }
                if parents.contains_key(ancestor) {
                    continue;
                }
                if parents.len() >= 256 {
                    return Err(Unavailable);
                }
                let before = fs::symlink_metadata(ancestor).map_err(|_| Unavailable)?;
                validate(ancestor, &before)?;
                let descriptor = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                    .open(ancestor)
                    .map_err(|_| Unavailable)?;
                if identity(&descriptor.metadata().map_err(|_| Unavailable)?) != identity(&before)
                    || identity(&fs::symlink_metadata(ancestor).map_err(|_| Unavailable)?)
                        != identity(&before)
                {
                    return Err(Unavailable);
                }
                parents.insert(
                    ancestor.to_path_buf(),
                    Witness {
                        descriptor,
                        identity: identity(&before),
                    },
                );
            }
        }
        let result = Arc::new(Self {
            parents,
            sealed: AtomicBool::new(false),
        });
        result.recheck(deadline)?;
        CUSTODY.set(result.clone()).map_err(|_| Unavailable)?;
        Ok(result)
    }
    /// The native disposable fixture is admitted by its exact canonical
    /// root-owned private root. Only its actual /tmp ancestor is root-sticky;
    /// production capture keeps its original strict directory policy.
    #[cfg(test)]
    pub(crate) fn capture_access_fixture(
        root: &Path,
        deadline: Instant,
    ) -> Result<Arc<Self>, Unavailable> {
        if !crate::openbsd::password_native_authority()
            || root.parent() != Some(Path::new("/tmp"))
            || !root
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("osmap-factor-"))
            || root.canonicalize().map_err(|_| Unavailable)? != root
        {
            return Err(Unavailable);
        }
        let metadata = fs::symlink_metadata(root).map_err(|_| Unavailable)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(Unavailable);
        }
        let leaf = root.join("runtime/factors");
        Self::capture_checked(
            &[leaf.to_str().ok_or(Unavailable)?],
            deadline,
            |path, metadata| {
                if path == Path::new("/tmp")
                    && metadata.is_dir()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o1000 != 0
                {
                    Ok(())
                } else {
                    directory(metadata)
                }
            },
        )
    }
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Unavailable> {
        for (path, witness) in &self.parents {
            if Instant::now() >= deadline {
                return Err(Unavailable);
            }
            let current = witness.descriptor.metadata().map_err(|_| Unavailable)?;
            // Capture validated the directory policy. Full identity includes
            // mode/type, UID and GID, so any policy change still refuses.
            if identity(&current) != witness.identity {
                return Err(Unavailable);
            }
            if !self.sealed.load(Ordering::Acquire)
                && identity(&fs::symlink_metadata(path).map_err(|_| Unavailable)?)
                    != witness.identity
            {
                return Err(Unavailable);
            }
        }
        Ok(())
    }
    pub(crate) fn activate(
        &self,
        seal: &crate::openbsd::PasswordParentSeal,
    ) -> Result<(), Unavailable> {
        if !seal.is_current_process() || self.sealed.swap(true, Ordering::AcqRel) {
            return Err(Unavailable);
        }
        Ok(())
    }
    pub(crate) fn activate_fstat(
        &self,
        seal: &crate::openbsd::PasswordFstatSeal,
    ) -> Result<(), Unavailable> {
        if !seal.is_current_process() || self.sealed.swap(true, Ordering::AcqRel) {
            return Err(Unavailable);
        }
        Ok(())
    }
    fn ancestor_metadata(&self, path: &Path) -> std::io::Result<fs::Metadata> {
        let witness = self.parents.get(path).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "ancestor witness unavailable")
        })?;
        let metadata = witness.descriptor.metadata()?;
        if identity(&metadata) != witness.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ancestor witness changed",
            ));
        }
        Ok(metadata)
    }
}
/// After unveil, pathname metadata for ancestors may be hidden. Observe only
/// an exact pre-seal vnode witness; never invent visibility for an unseen path.
pub(crate) fn ancestor_metadata(path: &Path) -> std::io::Result<fs::Metadata> {
    let Some(cache) = CUSTODY.get().filter(|v| v.sealed.load(Ordering::Acquire)) else {
        return fs::symlink_metadata(path);
    };
    cache.ancestor_metadata(path)
}

/// Preserve the existing ordered identity shape. After the real seal, only
/// previously captured directory vnodes can answer; unseen paths fail closed.
/// Exact leaf metadata/hash/unveil checks remain the caller's responsibility.
pub(crate) fn ancestors(
    path: &str,
    extra_owner: Option<u32>,
    deadline: Instant,
) -> Result<Vec<(String, Identity)>, Unavailable> {
    let cache = CUSTODY.get();
    let sealed = cache.is_some_and(|v| v.sealed.load(Ordering::Acquire));
    let mut result = Vec::new();
    for parent in Path::new(path).ancestors().skip(1) {
        if Instant::now() >= deadline {
            return Err(Unavailable);
        }
        let info = if sealed {
            let witness = cache
                .and_then(|v| v.parents.get(parent))
                .ok_or(Unavailable)?;
            let m = witness.descriptor.metadata().map_err(|_| Unavailable)?;
            if identity(&m) != witness.identity {
                return Err(Unavailable);
            }
            m
        } else {
            fs::symlink_metadata(parent).map_err(|_| Unavailable)?
        };
        directory(&info)?;
        if info.uid() != 0 && Some(info.uid()) != extra_owner {
            return Err(Unavailable);
        }
        result.push((parent.to_str().ok_or(Unavailable)?.into(), identity(&info)));
    }
    Ok(result)
}
pub(crate) fn directory_metadata(
    path: &str,
    owner: u32,
    deadline: Instant,
) -> Result<fs::Metadata, Unavailable> {
    if Instant::now() >= deadline {
        return Err(Unavailable);
    }
    let info = match CUSTODY.get().filter(|v| v.sealed.load(Ordering::Acquire)) {
        Some(cache) => {
            let witness = cache.parents.get(Path::new(path)).ok_or(Unavailable)?;
            let info = witness.descriptor.metadata().map_err(|_| Unavailable)?;
            if identity(&info) != witness.identity {
                return Err(Unavailable);
            }
            info
        }
        None => fs::symlink_metadata(path).map_err(|_| Unavailable)?,
    };
    directory(&info)?;
    if info.uid() != owner {
        return Err(Unavailable);
    }
    Ok(info)
}

#[cfg(test)]
mod ancestor_metadata_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn held_ancestor_survives_hidden_name_but_refuses_policy_change_and_unknown_path() {
        let root = std::env::temp_dir().join(format!(
            "osmap-ancestor-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("ancestor");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = File::open(&path).unwrap();
        let before = identity(&descriptor.metadata().unwrap());
        let custody = Custody {
            parents: [(
                path.clone(),
                Witness {
                    descriptor,
                    identity: before,
                },
            )]
            .into_iter()
            .collect(),
            sealed: AtomicBool::new(false),
        };
        let moved = root.join("retained");
        fs::rename(&path, &moved).unwrap();
        assert!(!path.exists());
        assert_eq!(identity(&custody.ancestor_metadata(&path).unwrap()), before);
        assert_eq!(
            custody.ancestor_metadata(&moved).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::set_permissions(&moved, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            custody.ancestor_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        fs::remove_dir(&moved).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
