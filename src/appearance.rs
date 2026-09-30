//! Presentation-only preferences, isolated from security settings and authority.

use std::fs::{self, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

pub const APPEARANCE_COOKIE: &str = "osmap_appearance";
const MAX_RECORD_BYTES: u64 = 64;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// This value changes colours only; it is never an authorization decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AppearancePreference {
    Light,
    Dark,
    #[default]
    System,
}

impl AppearancePreference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::System => "system",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            "system" => Some(Self::System),
            _ => None,
        }
    }

    pub fn cookie(self, secure: bool) -> String {
        format!(
            "{APPEARANCE_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000{}",
            self.as_str(),
            if secure { "; Secure" } else { "" }
        )
    }

    /// Duplicate or invalid cookie values fall back to the system preference.
    pub fn from_cookie_header(header: Option<&str>) -> Self {
        let mut found = None;
        for part in header.unwrap_or("").split(';') {
            if let Some((name, value)) = part.trim().split_once('=') {
                if name == APPEARANCE_COOKIE {
                    if found.is_some() {
                        return Self::System;
                    }
                    found = Some(Self::parse(value).unwrap_or_default());
                }
            }
        }
        found.unwrap_or_default()
    }
}

/// A versioned sidecar permits rollback without rewriting the old settings
/// format. Writes replace only this one field, so concurrent security-setting
/// changes cannot be lost. Concurrent theme writes use last-completed-write.
#[derive(Debug, Clone)]
pub struct AppearanceStore {
    directory: PathBuf,
}

impl AppearanceStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, canonical_username: &str) -> PathBuf {
        let mut digest = Sha256::new();
        digest.update(b"osmap-appearance-v1\0");
        digest.update(canonical_username.as_bytes());
        self.directory
            .join(format!("{:x}.appearance", digest.finalize()))
    }

    pub fn load(&self, canonical_username: &str) -> io::Result<AppearancePreference> {
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AppearancePreference::System)
            }
            Err(error) => return Err(error),
            Ok(_) => return Err(invalid_record()),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = match options.open(self.path(canonical_username)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AppearancePreference::System)
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
            return Err(invalid_record());
        }
        let mut content = String::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_string(&mut content)?;
        for value in [
            AppearancePreference::System,
            AppearancePreference::Light,
            AppearancePreference::Dark,
        ] {
            if content == format!("version=1\nappearance={}\n", value.as_str()) {
                return Ok(value);
            }
        }
        Err(invalid_record())
    }

    pub fn save(&self, canonical_username: &str, value: AppearancePreference) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        let metadata = fs::symlink_metadata(&self.directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid_record());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        }
        let destination = self.path(canonical_username);
        let temporary = self.directory.join(format!(
            ".appearance-{}-{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| {
            writeln!(file, "version=1\nappearance={}", value.as_str())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, destination)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn invalid_record() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid appearance record")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "osmap-appearance-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated scratch");
        path
    }

    #[test]
    fn cookie_is_typed_host_only_and_never_authority() {
        assert_eq!(
            AppearancePreference::from_cookie_header(None),
            AppearancePreference::System
        );
        assert_eq!(
            AppearancePreference::from_cookie_header(Some("osmap_appearance=dark")),
            AppearancePreference::Dark
        );
        for invalid in [
            "osmap_appearance=Dark",
            "osmap_appearance=<bad>",
            "osmap_appearance=light; osmap_appearance=dark",
            "osmap_appearance=; osmap_appearance=light",
        ] {
            assert_eq!(
                AppearancePreference::from_cookie_header(Some(invalid)),
                AppearancePreference::System
            );
        }
        let cookie = AppearancePreference::Dark.cookie(true);
        assert!(cookie.contains("HttpOnly; SameSite=Strict"));
        assert!(cookie.ends_with("; Secure"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn sidecar_is_account_isolated_and_preserves_old_settings() {
        let root = scratch();
        let old = root.join("existing.settings");
        fs::write(&old, "html_display_preference=prefer_plain_text\n").expect("write old settings");
        let store = AppearanceStore::new(&root);
        assert_eq!(
            store.load("alice@example.test").expect("default"),
            AppearancePreference::System
        );
        store
            .save("alice@example.test", AppearancePreference::Dark)
            .expect("save");
        assert_eq!(
            store.load("alice@example.test").expect("load"),
            AppearancePreference::Dark
        );
        assert_eq!(
            store.load("bob@example.test").expect("other account"),
            AppearancePreference::System
        );
        assert_eq!(
            fs::read_to_string(old).expect("unchanged"),
            "html_display_preference=prefer_plain_text\n"
        );
        assert!(!store.path("../../other").to_string_lossy().contains("../"));
        fs::remove_dir_all(root).expect("cleanup owned fixture");
    }

    #[test]
    fn malformed_duplicate_oversized_and_future_records_fail() {
        let root = scratch();
        let store = AppearanceStore::new(&root);
        for content in [
            "version=2\nappearance=dark\n",
            "version=1\nappearance=invalid\n",
            "version=1\nappearance=dark\nappearance=light\n",
            "appearance=dark\n",
            &"x".repeat(65),
        ] {
            fs::write(store.path("alice@example.test"), content).expect("fixture");
            assert!(store.load("alice@example.test").is_err());
        }
        fs::remove_dir_all(root).expect("cleanup owned fixture");
    }

    #[test]
    fn concurrent_legacy_settings_and_appearance_remain_independent() {
        use crate::rendering::HtmlDisplayPreference;
        use crate::settings::{FileUserSettingsStore, UserSettings, UserSettingsStore};
        use std::sync::Barrier;

        let root = scratch();
        let appearance = AppearanceStore::new(&root);
        let legacy = FileUserSettingsStore::new(&root);
        let original = UserSettings {
            html_display_preference: HtmlDisplayPreference::PreferPlainText,
            archive_mailbox_name: Some("Archive/Before".to_string()),
        };
        legacy
            .save("alice@example.test", &original)
            .expect("old format");
        let original_bytes = fs::read(legacy.settings_path_for_username("alice@example.test"))
            .expect("legacy bytes");
        appearance
            .save("alice@example.test", AppearancePreference::Dark)
            .expect("sidecar");
        assert_eq!(
            fs::read(legacy.settings_path_for_username("alice@example.test"))
                .expect("unchanged old format"),
            original_bytes
        );
        let updated = UserSettings {
            html_display_preference: HtmlDisplayPreference::PreferSanitizedHtml,
            archive_mailbox_name: Some("Archive/After".to_string()),
        };
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..32 {
                    barrier.wait();
                    appearance
                        .save("alice@example.test", AppearancePreference::Light)
                        .expect("concurrent appearance write");
                }
            });
            scope.spawn(|| {
                for _ in 0..32 {
                    barrier.wait();
                    legacy
                        .save("alice@example.test", &updated)
                        .expect("concurrent legacy write");
                }
            });
        });
        assert_eq!(
            legacy.load("alice@example.test").expect("legacy reload"),
            Some(updated)
        );
        assert_eq!(
            appearance
                .load("alice@example.test")
                .expect("appearance reload"),
            AppearancePreference::Light
        );
        assert_eq!(fs::read_dir(&root).expect("owned records").count(), 2);
        fs::remove_dir_all(root).expect("cleanup owned fixture");
    }

    #[test]
    fn concurrent_writes_leave_one_complete_record_and_no_scratch() {
        let root = scratch();
        let store = AppearanceStore::new(&root);
        let threads: Vec<_> = (0..16)
            .map(|index| {
                let store = store.clone();
                std::thread::spawn(move || {
                    store
                        .save(
                            "alice@example.test",
                            if index % 2 == 0 {
                                AppearancePreference::Light
                            } else {
                                AppearancePreference::Dark
                            },
                        )
                        .expect("atomic update")
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("writer");
        }
        assert!(matches!(
            store.load("alice@example.test").expect("complete record"),
            AppearancePreference::Light | AppearancePreference::Dark
        ));
        assert_eq!(fs::read_dir(&root).expect("list").count(), 1);
        fs::remove_dir_all(root).expect("cleanup owned fixture");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_read_is_refused_and_writes_have_private_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = scratch();
        let store = AppearanceStore::new(&root);
        store
            .save("alice@example.test", AppearancePreference::Dark)
            .expect("save");
        let path = store.path("alice@example.test");
        assert_eq!(
            fs::metadata(&path).expect("file").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&root).expect("dir").permissions().mode() & 0o777,
            0o700
        );
        symlink(&path, store.path("bob@example.test")).expect("symlink fixture");
        assert!(store.load("bob@example.test").is_err());
        let linked_root = root.join("linked-root");
        symlink(&root, &linked_root).expect("directory symlink fixture");
        let linked_store = AppearanceStore::new(&linked_root);
        assert!(linked_store.load("alice@example.test").is_err());
        assert!(linked_store
            .save("alice@example.test", AppearancePreference::Light)
            .is_err());
        assert_eq!(
            AppearanceStore::new(&root)
                .load("alice@example.test")
                .expect("fresh store"),
            AppearancePreference::Dark
        );
        fs::remove_dir_all(root).expect("cleanup owned fixture");
    }
}
