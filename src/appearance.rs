//! Presentation-only preferences, isolated from security settings and authority.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

pub const APPEARANCE_COOKIE: &str = "osmap_appearance";
pub const PRESENTATION_COOKIE: &str = "osmap_presentation";
const MAX_RECORD_BYTES: usize = 256;
const LOCK_WAIT: Duration = Duration::from_millis(500);
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

macro_rules! preference {
    ($name:ident, $default:ident, {$($variant:ident => $value:literal),+}) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl Default for $name { fn default() -> Self { Self::$default } }
        impl $name {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $value),+ } }
            pub fn parse(value: &str) -> Option<Self> { match value { $($value => Some(Self::$variant),)+ _ => None } }
        }
    };
}

preference!(Density, Comfortable, {Comfortable => "comfortable", Compact => "compact"});
preference!(FontSize, Medium, {Small => "small", Medium => "medium", Large => "large"});
preference!(ReaderLayout, Split, {Split => "split", Stacked => "stacked"});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppearanceSettings {
    pub theme: AppearancePreference,
    pub density: Density,
    pub font_size: FontSize,
    pub reader_layout: ReaderLayout,
    pub show_avatars: bool,
    pub message_preview: bool,
}

impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            theme: AppearancePreference::System,
            density: Density::Comfortable,
            font_size: FontSize::Medium,
            reader_layout: ReaderLayout::Split,
            show_avatars: true,
            message_preview: true,
        }
    }
}

impl AppearanceSettings {
    fn record(self) -> String {
        format!("version=2\nappearance={}\ndensity={}\nfont_size={}\nreader_layout={}\nshow_avatars={}\nmessage_preview={}\n",
            self.theme.as_str(), self.density.as_str(), self.font_size.as_str(), self.reader_layout.as_str(),
            u8::from(self.show_avatars), u8::from(self.message_preview))
    }

    fn parse_record(bytes: &[u8]) -> io::Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| invalid_record())?;
        for theme in [
            AppearancePreference::System,
            AppearancePreference::Light,
            AppearancePreference::Dark,
        ] {
            if text == format!("version=1\nappearance={}\n", theme.as_str()) {
                return Ok(Self {
                    theme,
                    ..Self::default()
                });
            }
        }
        let lines: Vec<_> = text.split('\n').collect();
        if bytes.len() > MAX_RECORD_BYTES
            || lines.len() != 8
            || lines[0] != "version=2"
            || !lines[7].is_empty()
        {
            return Err(invalid_record());
        }
        let field = |index: usize, prefix: &str| {
            lines[index].strip_prefix(prefix).ok_or_else(invalid_record)
        };
        let value = Self {
            theme: AppearancePreference::parse(field(1, "appearance=")?)
                .ok_or_else(invalid_record)?,
            density: Density::parse(field(2, "density=")?).ok_or_else(invalid_record)?,
            font_size: FontSize::parse(field(3, "font_size=")?).ok_or_else(invalid_record)?,
            reader_layout: ReaderLayout::parse(field(4, "reader_layout=")?)
                .ok_or_else(invalid_record)?,
            show_avatars: parse_bool(field(5, "show_avatars=")?).ok_or_else(invalid_record)?,
            message_preview: parse_bool(field(6, "message_preview=")?)
                .ok_or_else(invalid_record)?,
        };
        Ok(value)
    }

    /// Host-only display hints, never identity or security authority. Theme
    /// remains in its established cookie; this cookie carries only new fields.
    pub fn cookie(self, secure: bool) -> String {
        format!("{PRESENTATION_COOKIE}=v1.{}.{}.{}.{}.{}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000{}",
            self.density.as_str(), self.font_size.as_str(), self.reader_layout.as_str(),
            u8::from(self.show_avatars), u8::from(self.message_preview), if secure { "; Secure" } else { "" })
    }

    pub fn from_cookie_header(header: Option<&str>) -> Self {
        let mut settings = Self::default();
        let mut values = header.unwrap_or("").split(';').filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == PRESENTATION_COOKIE).then_some(value)
        });
        let Some(value) = values.next() else {
            return settings;
        };
        if values.next().is_some() || value.len() > 64 {
            return settings;
        }
        let parts: Vec<_> = value.split('.').collect();
        if let ["v1", density, font, layout, avatars, preview] = parts.as_slice() {
            if let (
                Some(density),
                Some(font_size),
                Some(reader_layout),
                Some(show_avatars),
                Some(message_preview),
            ) = (
                Density::parse(density),
                FontSize::parse(font),
                ReaderLayout::parse(layout),
                parse_bool(avatars),
                parse_bool(preview),
            ) {
                settings = Self {
                    theme: settings.theme,
                    density,
                    font_size,
                    reader_layout,
                    show_avatars,
                    message_preview,
                };
            }
        }
        settings
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// The account's atomic sidecar remains separate from security settings.
/// Full writes replace the presentation snapshot. Theme-only updates merge
/// under the same bounded cross-process lock, preserving all other fields.
#[derive(Debug, Clone)]
pub struct AppearanceStore {
    directory: PathBuf,
    #[cfg(test)]
    fail_before_publish: bool,
}

impl AppearanceStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            #[cfg(test)]
            fail_before_publish: false,
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
        self.load_settings(canonical_username)
            .map(|settings| settings.theme)
    }

    pub fn load_settings(&self, canonical_username: &str) -> io::Result<AppearanceSettings> {
        match crate::private_account_file::check_directory(&self.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AppearanceSettings::default())
            }
            Err(error) => return Err(error),
        }
        match crate::private_account_file::read_record(
            &self.path(canonical_username),
            MAX_RECORD_BYTES,
        )? {
            Some(bytes) => AppearanceSettings::parse_record(&bytes),
            None => Ok(AppearanceSettings::default()),
        }
    }

    pub fn save(&self, canonical_username: &str, value: AppearancePreference) -> io::Result<()> {
        let _lock = self.lock(canonical_username)?;
        let mut settings = self.load_settings(canonical_username)?;
        settings.theme = value;
        self.replace_record(canonical_username, settings)
    }

    pub fn save_settings(
        &self,
        canonical_username: &str,
        settings: AppearanceSettings,
    ) -> io::Result<()> {
        let _lock = self.lock(canonical_username)?;
        self.load_settings(canonical_username)?;
        self.replace_record(canonical_username, settings)
    }

    fn lock(&self, canonical_username: &str) -> io::Result<File> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.directory)?;
        crate::private_account_file::check_directory(&self.directory)?;
        let path = self
            .path(canonical_username)
            .with_extension("appearance.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(invalid_record());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.uid() != crate::openbsd::effective_uid()
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(invalid_record());
            }
        }
        #[cfg(unix)]
        {
            let deadline = Instant::now() + LOCK_WAIT;
            loop {
                match crate::openbsd::try_advisory_file_lock_exclusive(&file) {
                    Ok(()) => return Ok(file),
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        #[cfg(not(unix))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "appearance locking requires Unix",
        ))
    }

    fn replace_record(
        &self,
        canonical_username: &str,
        settings: AppearanceSettings,
    ) -> io::Result<()> {
        let destination = self.path(canonical_username);
        let temporary = self.directory.join(format!(
            ".appearance-{}-{}.tmp",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_options(&mut options);
        let mut file = options.open(&temporary)?;
        let result = (|| {
            file.write_all(settings.record().as_bytes())?;
            file.sync_all()?;
            drop(file);
            #[cfg(test)]
            if self.fail_before_publish {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected appearance interruption",
                ));
            }
            fs::rename(&temporary, destination)?;
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn fixture(store: &AppearanceStore, bytes: impl AsRef<[u8]>) {
        let path = store.path("alice@example.test");
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
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
            "version=3\nappearance=dark\n",
            "version=1\nappearance=invalid\n",
            "version=1\nappearance=dark\nappearance=light\n",
            "appearance=dark\n",
            &"x".repeat(MAX_RECORD_BYTES + 1),
        ] {
            fixture(&store, content);
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
                barrier.wait();
                for _ in 0..32 {
                    appearance
                        .save("alice@example.test", AppearancePreference::Light)
                        .expect("concurrent appearance write");
                }
            });
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..32 {
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
        // Two records and their separate account locks; no temporary files.
        assert_eq!(fs::read_dir(&root).expect("owned records").count(), 4);
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
        assert_eq!(fs::read_dir(&root).expect("list").count(), 2);
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
        assert!(store
            .save_settings("bob@example.test", AppearanceSettings::default())
            .is_err());
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

    fn compact() -> AppearanceSettings {
        AppearanceSettings {
            theme: AppearancePreference::Dark,
            density: Density::Compact,
            font_size: FontSize::Large,
            reader_layout: ReaderLayout::Stacked,
            show_avatars: false,
            message_preview: false,
        }
    }

    #[test]
    fn legacy_migration_and_complete_settings_round_trip() {
        let root = scratch();
        let store = AppearanceStore::new(&root);
        fixture(&store, "version=1\nappearance=dark\n");
        assert_eq!(
            store.load_settings("alice@example.test").unwrap(),
            AppearanceSettings {
                theme: AppearancePreference::Dark,
                ..AppearanceSettings::default()
            }
        );
        store
            .save_settings("alice@example.test", compact())
            .unwrap();
        assert_eq!(
            store.load_settings("alice@example.test").unwrap(),
            compact()
        );
        assert_eq!(
            store.load_settings("bob@example.test").unwrap(),
            AppearanceSettings::default()
        );
        store
            .save("alice@example.test", AppearancePreference::Light)
            .unwrap();
        assert_eq!(
            store.load_settings("alice@example.test").unwrap(),
            AppearanceSettings {
                theme: AppearancePreference::Light,
                ..compact()
            }
        );
        let bytes = fs::read(store.path("alice@example.test")).unwrap();
        assert!(bytes.starts_with(b"version=2\n"));
        assert!(!String::from_utf8(bytes).unwrap().contains("alice"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn v2_is_strict_and_refusal_never_overwrites_invalid_records() {
        let root = scratch();
        let store = AppearanceStore::new(&root);
        let valid = compact().record();
        for invalid in [
            valid.replace("version=2", "version=3"),
            valid.replace("density=compact", "density=unknown"),
            valid.replace("font_size=large", "font_size=Large"),
            valid.replace("reader_layout=stacked", "reader_layout=unknown"),
            valid.replace("show_avatars=0", "show_avatars=false"),
            valid.replace("message_preview=0\n", ""),
            valid.replace("density=compact", "appearance=dark"),
            format!("{valid}message_preview=1\n"),
            valid.replace('\n', "\r\n"),
            "x".repeat(MAX_RECORD_BYTES + 1),
        ] {
            fixture(&store, &invalid);
            assert!(store.load_settings("alice@example.test").is_err());
            assert!(store
                .save_settings("alice@example.test", compact())
                .is_err());
            assert!(store
                .save("alice@example.test", AppearancePreference::Light)
                .is_err());
            assert_eq!(
                fs::read_to_string(store.path("alice@example.test")).unwrap(),
                invalid
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn presentation_cookie_has_finite_values_independent_of_theme() {
        let settings = compact();
        let cookie = settings.cookie(true);
        assert!(cookie.starts_with("osmap_presentation=v1.compact.large.stacked.0.0;"));
        assert!(cookie.ends_with("; Secure"));
        assert!(cookie.contains("HttpOnly; SameSite=Strict"));
        assert!(!cookie.contains("Domain="));
        let header = format!(
            "{}; osmap_appearance=dark",
            cookie.split(';').next().unwrap()
        );
        assert_eq!(
            AppearanceSettings::from_cookie_header(Some(&header)),
            AppearanceSettings {
                theme: AppearancePreference::System,
                ..settings
            }
        );
        assert_eq!(
            AppearancePreference::from_cookie_header(Some(&header)),
            AppearancePreference::Dark
        );
        for invalid in [
            "v2.compact.large.stacked.0.0",
            "v1.Compact.large.stacked.0.0",
            "v1.compact.large.stacked.false.0",
            "v1.compact.large.stacked.0.0.extra",
            "<script>",
            "v1.compact.large.stacked.0.0; osmap_presentation=v1.compact.large.stacked.0.0",
        ] {
            assert_eq!(
                AppearanceSettings::from_cookie_header(Some(&format!(
                    "osmap_presentation={invalid}"
                ))),
                AppearanceSettings::default()
            );
        }
    }

    #[test]
    fn concurrent_full_and_theme_writes_never_drop_other_fields() {
        let root = scratch();
        let store = AppearanceStore::new(&root);
        for _ in 0..16 {
            store
                .save_settings("alice@example.test", AppearanceSettings::default())
                .unwrap();
            let barrier = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    store
                        .save_settings("alice@example.test", compact())
                        .unwrap();
                });
                scope.spawn(|| {
                    barrier.wait();
                    store
                        .save("alice@example.test", AppearancePreference::Light)
                        .unwrap();
                });
            });
            let actual = store.load_settings("alice@example.test").unwrap();
            assert_eq!(
                actual,
                AppearanceSettings {
                    theme: actual.theme,
                    ..compact()
                }
            );
            assert!(matches!(
                actual.theme,
                AppearancePreference::Light | AppearancePreference::Dark
            ));
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_replacement_preserves_old_record_and_cleans_its_temporary() {
        let root = scratch();
        let mut store = AppearanceStore::new(&root);
        store
            .save_settings("alice@example.test", compact())
            .unwrap();
        let before = fs::read(store.path("alice@example.test")).unwrap();
        let unrelated = root.join(".appearance-unrelated.tmp");
        fs::write(&unrelated, "unrelated synthetic state").unwrap();
        store.fail_before_publish = true;
        assert_eq!(
            store
                .save("alice@example.test", AppearancePreference::Light)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(fs::read(store.path("alice@example.test")).unwrap(), before);
        assert_eq!(
            fs::read_to_string(&unrelated).unwrap(),
            "unrelated synthetic state"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lock_is_bounded_and_account_scoped_across_processes() {
        let root = scratch();
        let store = AppearanceStore::new(&root);
        let lock = store.lock("alice@example.test").unwrap();
        use crate::auth::{CommandExecutor as _, SystemCommandExecutor};
        let executable = std::env::current_exe().unwrap();
        let result = SystemCommandExecutor
            .run_with_stdin_bytes_timeout(
                executable.to_str().unwrap(),
                &[
                    "--exact".into(),
                    "appearance::tests::lock_child_process".into(),
                    "--ignored".into(),
                ],
                root.to_str().unwrap().as_bytes(),
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(result.status_code, 0, "child lock assertions failed");
        drop(lock);
        store
            .save_settings("alice@example.test", compact())
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "invoked by the cross-process lock test"]
    fn lock_child_process() {
        use std::io::Read as _;
        let mut root = String::new();
        std::io::stdin().read_to_string(&mut root).unwrap();
        assert!(PathBuf::from(&root).is_absolute());
        let store = AppearanceStore::new(root);
        let started = Instant::now();
        assert_eq!(
            store
                .save("alice@example.test", AppearancePreference::Dark)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        store.save_settings("bob@example.test", compact()).unwrap();
    }
}
