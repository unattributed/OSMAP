//! Bounded account-scoped atomic records. Callers own the versioned schema.
//! Names supplied by a user never become paths. A held file lock serializes
//! read/check/write across processes; refusal paths leave the record untouched.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(crate) struct PrivateAccountFile {
    directory: PathBuf,
    namespace: &'static str,
    max_bytes: usize,
}

impl PrivateAccountFile {
    pub(crate) fn new(directory: PathBuf, namespace: &'static str, max_bytes: usize) -> Self {
        Self {
            directory,
            namespace,
            max_bytes,
        }
    }

    fn stem(&self, account: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(self.namespace.as_bytes());
        hash.update(b"\0");
        hash.update(account.as_bytes());
        format!("{:x}", hash.finalize())
    }

    pub(crate) fn read(&self, account: &str) -> io::Result<Option<Vec<u8>>> {
        match check_directory(&self.directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            result => result?,
        }
        read_record(
            &self.directory.join(format!("{}.json", self.stem(account))),
            self.max_bytes,
        )
    }

    pub(crate) fn lock(&self, account: &str) -> io::Result<LockedAccountFile> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.directory)?;
        check_directory(&self.directory)?;
        let stem = self.stem(account);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        private_options(&mut options);
        let file = options.open(self.directory.join(format!("{stem}.lock")))?;
        check_file(&file.metadata()?, 0)?;
        #[cfg(unix)]
        crate::openbsd::try_advisory_file_lock_exclusive(&file)?;
        #[cfg(not(unix))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private account locking requires Unix",
        ));
        Ok(LockedAccountFile {
            _lock: file,
            directory: self.directory.clone(),
            stem,
            max_bytes: self.max_bytes,
        })
    }
}

pub(crate) struct LockedAccountFile {
    // Unlock explicitly on drop: a forked child may retain the open file
    // description until exec, so closing our descriptor alone is insufficient.
    _lock: File,
    directory: PathBuf,
    stem: String,
    max_bytes: usize,
}

impl Drop for LockedAccountFile {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = crate::openbsd::advisory_file_unlock(&self._lock);
        }
    }
}

impl LockedAccountFile {
    fn destination(&self) -> PathBuf {
        self.directory.join(format!("{}.json", self.stem))
    }

    pub(crate) fn read(&self) -> io::Result<Option<Vec<u8>>> {
        check_directory(&self.directory)?;
        read_record(&self.destination(), self.max_bytes)
    }

    pub(crate) fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > self.max_bytes {
            return Err(invalid());
        }
        // Reject unexpected pre-existing state before creating replacement data.
        self.read()?;
        let temporary = self.directory.join(format!(
            ".{}-{}-{}.tmp",
            self.stem,
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_options(&mut options);
        let mut file = options.open(&temporary)?;
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, self.destination())?;
            File::open(&self.directory)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
}

pub(crate) fn check_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != crate::openbsd::effective_uid() || metadata.mode() & 0o777 != 0o700 {
            return Err(invalid());
        }
    }
    Ok(())
}

fn check_file(metadata: &fs::Metadata, max_bytes: usize) -> io::Result<()> {
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != crate::openbsd::effective_uid()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(crate) fn read_record(path: &Path, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    private_options(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    check_file(&file.metadata()?, max_bytes)?;
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(invalid());
    }
    Ok(Some(bytes))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "private account record is unsafe or invalid",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn dropping_guard_unlocks_despite_inherited_open_file_description() {
        let root = Scratch(std::env::temp_dir().join(format!(
            "osmap-private-lock-{}",
            crate::draft::generate_draft_id().unwrap()
        )));
        let store = PrivateAccountFile::new(root.0.clone(), "lock-lifetime-test", 4096);
        let account = "synthetic@example.test";
        let held = store.lock(account).unwrap();
        // dup and fork retain the same open file description. Keep a duplicate
        // alive to reproduce inheritance deterministically without forking the
        // multi-threaded test process or depending on process-spawn timing.
        let inherited = held._lock.try_clone().unwrap();
        assert_eq!(
            store.lock(account).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(held);
        let next = store
            .lock(account)
            .expect("guard drop must release its lock immediately");
        assert_eq!(
            store.lock(account).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(inherited);
        assert_eq!(
            store.lock(account).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(next);
        assert!(store.lock(account).is_ok());
    }
}
