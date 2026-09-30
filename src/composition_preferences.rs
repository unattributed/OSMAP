//! One account default, separate from drafts and security/appearance settings.
use std::io;
use std::path::PathBuf;

use crate::compose_format::BodyFormat;
use crate::private_account_file::PrivateAccountFile;

const MAX_RECORD_BYTES: usize = 96;
const NAMESPACE: &str = "osmap-composition-preferences-v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompositionPreferences {
    pub default_body_format: BodyFormat,
}

impl CompositionPreferences {
    pub fn parse_default_format(value: &str) -> Option<Self> {
        BodyFormat::parse(value).map(|default_body_format| Self {
            default_body_format,
        })
    }

    fn record(self) -> &'static [u8] {
        match self.default_body_format {
            BodyFormat::Plain => b"{\"version\":1,\"default_body_format\":\"plain\"}\n",
            BodyFormat::Formatted => b"{\"version\":1,\"default_body_format\":\"formatted\"}\n",
        }
    }

    // Exactly two canonical records: unknown versions/fields, duplicate fields,
    // partial records and noncanonical encodings fail instead of resetting.
    fn parse_record(bytes: &[u8]) -> io::Result<Self> {
        for default_body_format in [BodyFormat::Plain, BodyFormat::Formatted] {
            let value = Self {
                default_body_format,
            };
            if bytes == value.record() {
                return Ok(value);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid composition preferences",
        ))
    }
}

#[derive(Debug, Clone)]
pub struct CompositionPreferencesStore {
    file: PrivateAccountFile,
    #[cfg(test)]
    fail_before_publish: bool,
}

impl CompositionPreferencesStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), NAMESPACE, MAX_RECORD_BYTES),
            #[cfg(test)]
            fail_before_publish: false,
        }
    }

    pub fn load(&self, canonical_account: &str) -> io::Result<CompositionPreferences> {
        self.file.read(canonical_account)?.map_or_else(
            || Ok(CompositionPreferences::default()),
            |bytes| CompositionPreferences::parse_record(&bytes),
        )
    }

    /// A busy account refuses immediately. Callers must not claim success on
    /// any error, including a directory-sync failure after atomic publication.
    pub fn save(&self, canonical_account: &str, value: CompositionPreferences) -> io::Result<()> {
        let locked = self.file.lock(canonical_account)?;
        if let Some(bytes) = locked.read()? {
            CompositionPreferences::parse_record(&bytes)?;
        }
        #[cfg(test)]
        if self.fail_before_publish {
            return Err(io::Error::other("injected pre-publication failure"));
        }
        locked.write(value.record())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "osmap-composition-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn store(&self) -> CompositionPreferencesStore {
            CompositionPreferencesStore::new(&self.0)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn formatted() -> CompositionPreferences {
        CompositionPreferences {
            default_body_format: BodyFormat::Formatted,
        }
    }

    #[test]
    fn absent_record_defaults_plain_and_reopen_is_account_isolated() {
        let root = Scratch::new();
        assert_eq!(
            root.store().load("alice@example.test").unwrap(),
            CompositionPreferences::default()
        );
        assert!(!root.0.exists());
        root.store()
            .save("alice@example.test", formatted())
            .unwrap();
        assert_eq!(
            root.store().load("alice@example.test").unwrap(),
            formatted()
        );
        assert_eq!(
            root.store().load("bob@example.test").unwrap(),
            CompositionPreferences::default()
        );
        root.store()
            .save("bob@example.test", CompositionPreferences::default())
            .unwrap();
        assert_eq!(
            root.store().load("alice@example.test").unwrap(),
            formatted()
        );
        assert!(fs::read_dir(&root.0).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("alice")));
    }

    #[test]
    fn input_and_record_schema_are_finite() {
        for value in ["plain", "formatted"] {
            let parsed = CompositionPreferences::parse_default_format(value).unwrap();
            assert_eq!(
                CompositionPreferences::parse_record(parsed.record()).unwrap(),
                parsed
            );
        }
        for value in ["", "html", "Plain", "plain ", "formatted\n"] {
            assert!(CompositionPreferences::parse_default_format(value).is_none());
        }
        for bytes in [b"".as_slice(), b"{}\n", b"{\"version\":2,\"default_body_format\":\"plain\"}\n", b"{\"version\":1,\"default_body_format\":\"html\"}\n", b"{\"version\":1,\"default_body_format\":\"plain\",\"default_body_format\":\"formatted\"}\n", b"\xff"] {
            assert_eq!(CompositionPreferences::parse_record(bytes).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn failed_publication_and_corrupt_record_never_reset_saved_state() {
        let root = Scratch::new();
        let mut store = root.store();
        store.save("alice", formatted()).unwrap();
        store.fail_before_publish = true;
        assert!(store
            .save("alice", CompositionPreferences::default())
            .is_err());
        assert_eq!(root.store().load("alice").unwrap(), formatted());
        let locked = store.file.lock("alice").unwrap();
        locked.write(b"{\"version\":99}\n").unwrap();
        drop(locked);
        let before = store.file.read("alice").unwrap();
        assert!(root.store().load("alice").is_err());
        assert!(root.store().save("alice", formatted()).is_err());
        assert_eq!(store.file.read("alice").unwrap(), before);
    }

    #[test]
    fn busy_account_refuses_boundedly_without_blocking_another_account() {
        let root = Scratch::new();
        let store = root.store();
        store
            .save("alice", CompositionPreferences::default())
            .unwrap();
        let held = store.file.lock("alice").unwrap();
        let other = store.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            assert_eq!(
                other.save("alice", formatted()).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            other.save("bob", formatted()).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(
            store.load("alice").unwrap(),
            CompositionPreferences::default()
        );
        drop(held);
        store.save("alice", formatted()).unwrap();
    }

    #[test]
    fn competing_writers_leave_one_complete_typed_record() {
        let root = Scratch::new();
        let store = root.store();
        store
            .save("alice", CompositionPreferences::default())
            .unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let preference = if index % 2 == 0 {
                        formatted()
                    } else {
                        CompositionPreferences::default()
                    };
                    match store.save("alice", preference) {
                        Ok(()) => true,
                        Err(error) => {
                            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                            false
                        }
                    }
                })
            })
            .collect();
        assert!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|saved| *saved)
                .count()
                > 0
        );
        let result = root.store().load("alice").unwrap();
        assert!(matches!(
            result.default_body_format,
            BodyFormat::Plain | BodyFormat::Formatted
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_and_unsafe_record_refusal() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = Scratch::new();
        let store = root.store();
        store.save("alice", formatted()).unwrap();
        assert_eq!(
            fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let record = fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        assert_eq!(
            fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(&record, vec![b'x'; MAX_RECORD_BYTES + 1]).unwrap();
        assert!(store.load("alice").is_err());
        assert!(store.save("alice", formatted()).is_err());
        assert_eq!(
            fs::metadata(&record).unwrap().len(),
            (MAX_RECORD_BYTES + 1) as u64
        );
        fs::remove_file(&record).unwrap();
        let target = root.0.join("outside-record");
        fs::write(&target, b"preserved").unwrap();
        symlink(&target, &record).unwrap();
        assert!(store.load("alice").is_err());
        assert!(store.save("alice", formatted()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserved");
    }
}
