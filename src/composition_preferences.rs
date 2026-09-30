//! Account composition defaults, separate from drafts and security/appearance settings.
use std::io;
use std::path::PathBuf;

use crate::compose_format::BodyFormat;
use crate::private_account_file::PrivateAccountFile;

const MAX_RECORD_BYTES: usize = 96;
const NAMESPACE: &str = "osmap-composition-preferences-v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReplyPlacement {
    #[default]
    Above,
    Below,
}
impl ReplyPlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Above => "above",
            Self::Below => "below",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "above" => Some(Self::Above),
            "below" => Some(Self::Below),
            _ => None,
        }
    }
    /// Move only the builder's two leading blank lines. Quoted bytes and body
    /// length stay unchanged, including its existing truncation notice.
    pub fn initial_reply_body(self, body: &str) -> Option<String> {
        match self {
            Self::Above => Some(body.to_owned()),
            Self::Below => body
                .strip_prefix("\n\n")
                .map(|quote| format!("{quote}\n\n")),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompositionPreferences {
    pub default_body_format: BodyFormat,
    pub reply_placement: ReplyPlacement,
}

impl CompositionPreferences {
    pub fn parse_default_format(value: &str) -> Option<Self> {
        BodyFormat::parse(value).map(|default_body_format| Self {
            default_body_format,
            reply_placement: ReplyPlacement::Above,
        })
    }

    fn record(self) -> Vec<u8> {
        format!(
            "{{\"version\":2,\"default_body_format\":\"{}\",\"reply_placement\":\"{}\"}}\n",
            self.default_body_format.as_str(),
            self.reply_placement.as_str()
        )
        .into_bytes()
    }

    fn parse_record(bytes: &[u8]) -> io::Result<Self> {
        for default_body_format in [BodyFormat::Plain, BodyFormat::Formatted] {
            let legacy = format!(
                "{{\"version\":1,\"default_body_format\":\"{}\"}}\n",
                default_body_format.as_str()
            );
            if bytes == legacy.as_bytes() {
                return Ok(Self {
                    default_body_format,
                    reply_placement: ReplyPlacement::Above,
                });
            }
            for reply_placement in [ReplyPlacement::Above, ReplyPlacement::Below] {
                let value = Self {
                    default_body_format,
                    reply_placement,
                };
                if bytes == value.record() {
                    return Ok(value);
                }
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

    /// Older format-only forms preserve reply placement under
    /// the same account lock; no read/merge/write race between separate calls.
    pub fn save_format(&self, account: &str, format: BodyFormat) -> io::Result<()> {
        let locked = self.file.lock(account)?;
        let mut value = locked.read()?.map_or_else(
            || Ok(CompositionPreferences::default()),
            |bytes| CompositionPreferences::parse_record(&bytes),
        )?;
        value.default_body_format = format;
        #[cfg(test)]
        if self.fail_before_publish {
            return Err(io::Error::other("injected pre-publication failure"));
        }
        locked.write(&value.record())
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
        locked.write(&value.record())
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
            reply_placement: ReplyPlacement::Above,
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
                CompositionPreferences::parse_record(&parsed.record()).unwrap(),
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

#[cfg(test)]
mod placement_tests {
    use super::*;
    #[test]
    fn v1_reads_above_without_migration_and_format_only_save_preserves_below() {
        let root = std::env::temp_dir().join(format!(
            "osmap-placement-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = CompositionPreferencesStore::new(&root);
        let legacy = b"{\"version\":1,\"default_body_format\":\"formatted\"}\n";
        {
            let locked = store.file.lock("alice").unwrap();
            locked.write(legacy).unwrap();
        }
        assert_eq!(
            store.load("alice").unwrap().reply_placement,
            ReplyPlacement::Above
        );
        assert_eq!(store.file.read("alice").unwrap().unwrap(), legacy);
        let below = CompositionPreferences {
            default_body_format: BodyFormat::Formatted,
            reply_placement: ReplyPlacement::Below,
        };
        store.save("alice", below).unwrap();
        assert_eq!(
            CompositionPreferencesStore::new(&root)
                .load("alice")
                .unwrap(),
            below
        );
        assert_eq!(
            store.load("bob").unwrap(),
            CompositionPreferences::default()
        );
        store.save_format("alice", BodyFormat::Plain).unwrap();
        assert_eq!(
            store.load("alice").unwrap(),
            CompositionPreferences {
                default_body_format: BodyFormat::Plain,
                ..below
            }
        );
        assert!(store
            .file
            .read("alice")
            .unwrap()
            .unwrap()
            .starts_with(b"{\"version\":2,"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn reply_blank_space_moves_without_interpreting_or_trimming_quote_bytes() {
        let quote="On synthetic date, synthetic sender wrote:\n> **literal** [x](unsupported:target)\n> - list\n> 1. item\n> \\escape 🦊\n[quoted content truncated]";
        let source = format!("\n\n{quote}");
        assert_eq!(
            ReplyPlacement::Above.initial_reply_body(&source),
            Some(source.clone())
        );
        let below = ReplyPlacement::Below.initial_reply_body(&source).unwrap();
        assert_eq!(below, format!("{quote}\n\n"));
        assert_eq!(below.len(), source.len());
        assert!(ReplyPlacement::Below
            .initial_reply_body("unrecognized builder output")
            .is_none());
    }
    #[test]
    fn placement_schema_rejects_unknown_duplicate_and_noncanonical_values() {
        for value in ["", "Above", "bottom", "below "] {
            assert!(ReplyPlacement::parse(value).is_none());
        }
        let value = CompositionPreferences {
            default_body_format: BodyFormat::Formatted,
            reply_placement: ReplyPlacement::Below,
        };
        assert_eq!(
            CompositionPreferences::parse_record(&value.record()).unwrap(),
            value
        );
        let valid = String::from_utf8(value.record()).unwrap();
        for invalid in [
            valid.replace("below", "bottom"),
            valid.replace(
                "\"reply_placement\":\"below\"",
                "\"reply_placement\":\"below\",\"reply_placement\":\"above\"",
            ),
            valid.replace("version\":2", "version\":3"),
            valid.trim_end().into(),
        ] {
            assert!(CompositionPreferences::parse_record(invalid.as_bytes()).is_err());
        }
    }
}
