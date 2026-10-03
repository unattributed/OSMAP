//! Account reading preferences; presentation/default navigation only.
use std::io;
use std::path::PathBuf;

use crate::private_account_file::PrivateAccountFile;

const MAX_RECORD_BYTES: usize = 256;
const NAMESPACE: &str = "osmap-reading-preferences-v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StartPage {
    #[default]
    Mailbox,
    Inbox,
    Drafts,
    Sent,
}

impl StartPage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mailbox => "mailbox",
            Self::Inbox => "inbox",
            Self::Drafts => "drafts",
            Self::Sent => "sent",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mailbox" => Some(Self::Mailbox),
            "inbox" => Some(Self::Inbox),
            "drafts" => Some(Self::Drafts),
            "sent" => Some(Self::Sent),
            _ => None,
        }
    }

    /// Fixed authenticated GET destination; caller must still authorize login.
    pub const fn path(self) -> &'static str {
        match self {
            Self::Mailbox => "/mailboxes",
            Self::Inbox => "/mailbox?name=INBOX",
            Self::Drafts => "/drafts",
            Self::Sent => "/mailbox?name=Sent",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DateOrder {
    #[default]
    Newest,
    Oldest,
}

impl DateOrder {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Newest => "newest",
            Self::Oldest => "oldest",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "newest" => Some(Self::Newest),
            "oldest" => Some(Self::Oldest),
            _ => None,
        }
    }

    /// Received-time direction for saved conversation members or an explicit date sort.
    pub const fn sort_direction(self) -> &'static str {
        match self {
            Self::Newest => "desc",
            Self::Oldest => "asc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadingPreferences {
    pub start_page: StartPage,
    pub date_order: DateOrder,
    pub show_source_shortcut: bool,
    pub attachment_details: bool,
}

impl Default for ReadingPreferences {
    fn default() -> Self {
        Self {
            start_page: StartPage::Mailbox,
            date_order: DateOrder::Newest,
            show_source_shortcut: true,
            attachment_details: true,
        }
    }
}

impl ReadingPreferences {
    /// Host-only presentation hints, never account or security authority.
    /// Login and preference saves must issue this from the stored account value;
    /// login redirects must use the store's StartPage, not a received cookie.
    pub fn cookie(self, secure: bool) -> String {
        format!(
            "osmap_reading=v1.{}.{}.{}.{}; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000{}",
            self.start_page.as_str(),
            self.date_order.as_str(),
            u8::from(self.show_source_shortcut),
            u8::from(self.attachment_details),
            if secure { "; Secure" } else { "" }
        )
    }

    /// Missing, duplicate, malformed or oversized hints fall back to defaults.
    /// This parser performs no storage writes and grants no authority.
    pub fn from_cookie_header(header: Option<&str>) -> Self {
        let parse = || -> Option<Self> {
            let header = header?;
            if header.len() > 8192 || header.chars().any(char::is_control) {
                return None;
            }
            let mut found = None;
            for part in header.split(';') {
                let part = part.trim();
                let (name, value) = part.split_once('=').unwrap_or((part, ""));
                if name.trim() != "osmap_reading" {
                    continue;
                }
                if name != "osmap_reading" || found.is_some() || value.len() > 64 {
                    return None;
                }
                found = Some(value);
            }
            let mut parts = found?.split('.');
            if parts.next()? != "v1" {
                return None;
            }
            let start_page = StartPage::parse(parts.next()?)?;
            let date_order = DateOrder::parse(parts.next()?)?;
            let boolean = |text| match text {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
            let show_source_shortcut = boolean(parts.next()?)?;
            let attachment_details = boolean(parts.next()?)?;
            if parts.next().is_some() {
                return None;
            }
            Some(Self {
                start_page,
                date_order,
                show_source_shortcut,
                attachment_details,
            })
        };
        parse().unwrap_or_default()
    }

    fn record(self) -> String {
        format!("{{\"version\":1,\"start_page\":\"{}\",\"date_order\":\"{}\",\"show_source_shortcut\":{},\"attachment_details\":{}}}\n",
            self.start_page.as_str(), self.date_order.as_str(), self.show_source_shortcut, self.attachment_details)
    }

    // Accept only our canonical v1 encoding. Fixed delimiters and finite values
    // reject duplicate/extra fields, unknown versions, trailing data and partial
    // records without a permissive parser or unbounded nesting.
    fn parse_record(bytes: &[u8]) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid reading preferences");
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
        let text = text
            .strip_prefix("{\"version\":1,\"start_page\":\"")
            .ok_or_else(invalid)?;
        let (start, text) = text
            .split_once("\",\"date_order\":\"")
            .ok_or_else(invalid)?;
        let (order, text) = text
            .split_once("\",\"show_source_shortcut\":")
            .ok_or_else(invalid)?;
        let (source, text) = text
            .split_once(",\"attachment_details\":")
            .ok_or_else(invalid)?;
        let attachments = text.strip_suffix("}\n").ok_or_else(invalid)?;
        let boolean = |value| match value {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        Ok(Self {
            start_page: StartPage::parse(start).ok_or_else(invalid)?,
            date_order: DateOrder::parse(order).ok_or_else(invalid)?,
            show_source_shortcut: boolean(source).ok_or_else(invalid)?,
            attachment_details: boolean(attachments).ok_or_else(invalid)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReadingPreferencesStore {
    file: PrivateAccountFile,
}

impl ReadingPreferencesStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), NAMESPACE, MAX_RECORD_BYTES),
        }
    }

    /// Missing means defaults; malformed or unsafe existing state is an error.
    pub fn load(&self, canonical_account: &str) -> io::Result<ReadingPreferences> {
        self.file.read(canonical_account)?.map_or_else(
            || Ok(ReadingPreferences::default()),
            |bytes| ReadingPreferences::parse_record(&bytes),
        )
    }

    /// Updates only the start page under the same lock as complete saves.
    pub fn save_start_page(
        &self,
        account: &str,
        start_page: StartPage,
    ) -> io::Result<ReadingPreferences> {
        let locked = self.file.lock(account)?;
        let mut value = locked.read()?.map_or_else(
            || Ok(ReadingPreferences::default()),
            |bytes| ReadingPreferences::parse_record(&bytes),
        )?;
        value.start_page = start_page;
        locked.write(value.record().as_bytes())?;
        Ok(value)
    }

    /// Saves a complete typed snapshot under an account lock. Existing corrupt
    /// state is never replaced. Errors, including post-rename directory sync,
    /// mean unconfirmed publication; callers must not claim state is unchanged.
    pub fn save(&self, canonical_account: &str, value: ReadingPreferences) -> io::Result<()> {
        let locked = self.file.lock(canonical_account)?;
        if let Some(bytes) = locked.read()? {
            ReadingPreferences::parse_record(&bytes)?;
        }
        locked.write(value.record().as_bytes())
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
                "osmap-reading-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
        }
        fn store(&self) -> ReadingPreferencesStore {
            ReadingPreferencesStore::new(&self.0)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn changed() -> ReadingPreferences {
        ReadingPreferences {
            start_page: StartPage::Drafts,
            date_order: DateOrder::Oldest,
            show_source_shortcut: false,
            attachment_details: false,
        }
    }

    #[test]
    fn cookie_roundtrips_all_values_with_host_only_flags() {
        for start_page in [
            StartPage::Mailbox,
            StartPage::Inbox,
            StartPage::Drafts,
            StartPage::Sent,
        ] {
            for date_order in [DateOrder::Newest, DateOrder::Oldest] {
                for show_source_shortcut in [false, true] {
                    for attachment_details in [false, true] {
                        let value = ReadingPreferences {
                            start_page,
                            date_order,
                            show_source_shortcut,
                            attachment_details,
                        };
                        for secure in [false, true] {
                            let cookie = value.cookie(secure);
                            assert!(cookie
                                .contains("; Path=/; HttpOnly; SameSite=Strict; Max-Age=31536000"));
                            assert_eq!(cookie.ends_with("; Secure"), secure);
                            assert!(!cookie.contains("Domain="));
                            let pair = cookie.split(';').next().unwrap();
                            assert_eq!(ReadingPreferences::from_cookie_header(Some(pair)), value);
                            assert_eq!(
                                ReadingPreferences::from_cookie_header(Some(&format!(
                                    "unrelated=public; {pair}; another=fixture"
                                ))),
                                value
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn cookies_default_on_malformed_duplicate_oversized_or_absent_values() {
        let default = ReadingPreferences::default();
        assert_eq!(ReadingPreferences::from_cookie_header(None), default);
        let good = "osmap_reading=v1.drafts.oldest.0.0";
        for header in [
            "".to_owned(),
            "other=1".into(),
            "osmap_reading".into(),
            "osmap_reading=".into(),
            good.replace("v1", "v2"),
            good.replace("drafts", "Drafts"),
            good.replace("oldest", "asc"),
            good.replace(".0.0", ".true.0"),
            good.replace(".0.0", ".0.2"),
            format!("{good}.extra"),
            good.replace(".oldest.0.0", ".oldest.0"),
            format!("{good}; {good}"),
            format!("osmap_reading; {good}"),
            format!("{good}; osmap_reading=invalid"),
            good.replace("=v1", " =v1"),
            good.replace("drafts", "%64rafts"),
            format!("{good}\r\n"),
            format!("osmap_reading={}", "x".repeat(65)),
            format!("other={}; {good}", "x".repeat(8192)),
        ] {
            assert_eq!(
                ReadingPreferences::from_cookie_header(Some(&header)),
                default
            );
        }
    }

    #[test]
    fn absent_defaults_finite_routes_and_all_states_reopen_isolated() {
        let root = Scratch::new();
        assert_eq!(
            root.store().load("alice").unwrap(),
            ReadingPreferences::default()
        );
        assert!(!root.0.exists());
        for (start_page, route) in [
            (StartPage::Mailbox, "/mailboxes"),
            (StartPage::Inbox, "/mailbox?name=INBOX"),
            (StartPage::Drafts, "/drafts"),
            (StartPage::Sent, "/mailbox?name=Sent"),
        ] {
            assert_eq!(start_page.path(), route);
            assert_eq!(StartPage::parse(start_page.as_str()), Some(start_page));
            for date_order in [DateOrder::Newest, DateOrder::Oldest] {
                assert_eq!(DateOrder::parse(date_order.as_str()), Some(date_order));
                assert_eq!(
                    date_order.sort_direction(),
                    if date_order == DateOrder::Newest {
                        "desc"
                    } else {
                        "asc"
                    }
                );
                for show_source_shortcut in [true, false] {
                    for attachment_details in [true, false] {
                        let value = ReadingPreferences {
                            start_page,
                            date_order,
                            show_source_shortcut,
                            attachment_details,
                        };
                        root.store().save("alice", value).unwrap();
                        assert_eq!(root.store().load("alice").unwrap(), value);
                        assert_eq!(
                            root.store().load("bob").unwrap(),
                            ReadingPreferences::default()
                        );
                        assert!(value.record().len() <= MAX_RECORD_BYTES);
                    }
                }
            }
        }
        for text in ["", "Inbox", "inbox ", "//outside.test", "/drafts"] {
            assert!(StartPage::parse(text).is_none());
        }
        for text in ["", "Newest", "asc", "threaded", "oldest\n"] {
            assert!(DateOrder::parse(text).is_none());
        }
    }

    #[test]
    fn corrupt_schema_is_never_silently_overwritten() {
        let root = Scratch::new();
        let store = root.store();
        let valid = changed().record();
        let invalid = [
            "".to_string(),
            "{}\n".into(),
            valid.replace("\"version\":1", "\"version\":2"),
            valid.replace(
                "\"date_order\":\"oldest\"",
                "\"date_order\":\"oldest\",\"date_order\":\"newest\"",
            ),
            valid.replace("}\n", ",\"extra\":true}\n"),
            valid.replace("false", "0"),
            valid.replace("drafts", "unsupported"),
            valid.trim_end().into(),
            format!("{valid}{{}}"),
        ];
        for bytes in invalid
            .iter()
            .map(|v| v.as_bytes())
            .chain([b"\xff".as_slice()])
        {
            store.file.lock("alice").unwrap().write(bytes).unwrap();
            assert_eq!(
                store.load("alice").unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(store.save("alice", ReadingPreferences::default()).is_err());
            assert_eq!(store.file.read("alice").unwrap().unwrap(), bytes);
        }
    }

    #[test]
    fn busy_account_refuses_without_changing_bytes_or_blocking_other_account() {
        let root = Scratch::new();
        let store = root.store();
        store.save("alice", changed()).unwrap();
        let before = store.file.read("alice").unwrap();
        let held = store.file.lock("alice").unwrap();
        let start = Instant::now();
        assert_eq!(
            store
                .save("alice", ReadingPreferences::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(store.file.read("alice").unwrap(), before);
        store.save("bob", ReadingPreferences::default()).unwrap();
        drop(held);
        store.save("alice", ReadingPreferences::default()).unwrap();
    }

    #[test]
    fn concurrent_writes_publish_whole_snapshots() {
        let root = Scratch::new();
        let store = root.store();
        store.save("alice", ReadingPreferences::default()).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|i| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    match store.save(
                        "alice",
                        if i % 2 == 0 {
                            changed()
                        } else {
                            ReadingPreferences::default()
                        },
                    ) {
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
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .filter(|v| *v)
                .count()
                > 0
        );
        let loaded = store.load("alice").unwrap();
        assert!(loaded == changed() || loaded == ReadingPreferences::default());
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_size_and_symlink_refusals() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = Scratch::new();
        let store = root.store();
        store.save("alice", changed()).unwrap();
        assert_eq!(
            fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let record = fs::read_dir(&root.0)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .unwrap();
        assert!(!record
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("alice"));
        assert_eq!(
            fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::write(&record, vec![b'x'; MAX_RECORD_BYTES + 1]).unwrap();
        assert!(store.load("alice").is_err());
        assert!(store.save("alice", changed()).is_err());
        assert_eq!(
            fs::metadata(&record).unwrap().len(),
            (MAX_RECORD_BYTES + 1) as u64
        );
        fs::remove_file(&record).unwrap();
        let outside = root.0.join("outside");
        fs::write(&outside, b"preserved").unwrap();
        symlink(&outside, &record).unwrap();
        assert!(store.load("alice").is_err());
        assert!(store.save("alice", changed()).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"preserved");
    }
}
