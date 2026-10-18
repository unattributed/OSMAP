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
                directory(&before)?;
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
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Unavailable> {
        for (path, witness) in &self.parents {
            if Instant::now() >= deadline {
                return Err(Unavailable);
            }
            let current = witness.descriptor.metadata().map_err(|_| Unavailable)?;
            directory(&current)?;
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
