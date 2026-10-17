//! Account-owned fixed UTC offsets for mail display, never scheduling authority.
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const NAMESPACE: &str = "osmap-timezone-v1";
const MAX_RECORD_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FixedOffset(i16);

impl FixedOffset {
    fn from_minutes(minutes: i16) -> Option<Self> {
        ((-720..=840).contains(&minutes) && minutes % 15 == 0).then_some(Self(minutes))
    }

    /// Canonical explicit offsets only; no named-zone or daylight-saving claim.
    pub fn parse(value: &str) -> Option<Self> {
        if value == "UTC" {
            return Some(Self::default());
        }
        let b = value.as_bytes();
        if b.len() != 6
            || !matches!(b[0], b'+' | b'-')
            || b[3] != b':'
            || ![b[1], b[2], b[4], b[5]].iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let hours = value[1..3].parse::<i16>().ok()?;
        let minutes = value[4..6].parse::<i16>().ok()?;
        let total = hours * 60 + minutes;
        if minutes > 59 || total == 0 {
            return None;
        }
        Self::from_minutes(if b[0] == b'-' { -total } else { total })
    }

    pub fn as_str(self) -> String {
        if self.0 == 0 {
            "UTC".into()
        } else {
            let absolute = self.0.unsigned_abs();
            format!(
                "{}{:02}:{:02}",
                if self.0 < 0 { '-' } else { '+' },
                absolute / 60,
                absolute % 60
            )
        }
    }

    pub fn label(self) -> String {
        if self.0 == 0 {
            "UTC".into()
        } else {
            format!("UTC{}", self.as_str())
        }
    }

    pub fn choices() -> impl Iterator<Item = Self> {
        (-720..=840).step_by(15).map(Self)
    }

    /// Convert strict backend metadata only. Invalid or unrepresentable dates
    /// remain unchanged and are escaped by the existing HTML caller.
    pub fn display_received(self, value: &str) -> String {
        crate::mailbox::parse_received_timestamp(value)
            .and_then(|timestamp| crate::logging::format_unix_timestamp_offset(timestamp, self.0))
            .map(|date| format!("{date} {}", self.label()))
            .unwrap_or_else(|| value.into())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preference {
    pub revision: u64,
    pub offset: FixedOffset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Stale,
    Unavailable,
    Unconfirmed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    account: String,
    revision: u64,
    offset_minutes: i16,
}

#[derive(Debug, Clone)]
pub struct Store {
    file: PrivateAccountFile,
}

impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), NAMESPACE, MAX_RECORD_BYTES),
        }
    }

    fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<Preference, Error> {
        let Some(bytes) = bytes else {
            return Ok(Preference::default());
        };
        let record: Stored = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if bytes.len() > MAX_RECORD_BYTES
            || record.version != 1
            || record.account != account
            || record.revision == 0
        {
            return Err(Error::Unavailable);
        }
        Ok(Preference {
            revision: record.revision,
            offset: FixedOffset::from_minutes(record.offset_minutes).ok_or(Error::Unavailable)?,
        })
    }

    pub fn load(&self, account: &str) -> Result<Preference, Error> {
        crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        Self::decode(
            account,
            self.file.read(account).map_err(|_| Error::Unavailable)?,
        )
    }

    pub fn save(
        &self,
        account: &str,
        expected_revision: u64,
        offset: FixedOffset,
    ) -> Result<Preference, Error> {
        crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        let locked = loop {
            match self.file.lock(account) {
                Ok(locked) => break locked,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(Error::Unavailable),
            }
        };
        let current = Self::decode(account, locked.read().map_err(|_| Error::Unavailable)?)?;
        if current.revision != expected_revision {
            return Err(Error::Stale);
        }
        let revision = expected_revision.checked_add(1).ok_or(Error::Unavailable)?;
        let bytes = serde_json::to_vec(&Stored {
            version: 1,
            account: account.into(),
            revision,
            offset_minutes: offset.0,
        })
        .map_err(|_| Error::Unavailable)?;
        // Publication may have renamed before a failed directory sync: callers
        // must reload rather than claim no change or automatically retry.
        locked.write(&bytes).map_err(|_| Error::Unconfirmed)?;
        Ok(Preference { revision, offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn timezone_offsets_are_finite_canonical_and_convert_real_instants() {
        assert_eq!(FixedOffset::choices().count(), 105);
        for offset in FixedOffset::choices() {
            assert_eq!(FixedOffset::parse(&offset.as_str()), Some(offset));
        }
        for invalid in [
            "",
            "+00:00",
            "-00:00",
            "+14:15",
            "-12:15",
            "+05:10",
            "+5:30",
            "+01:60",
            "UTC+05:30",
            "America/Toronto",
            "+99:99",
            "+01:00\n",
            "＋01:00",
        ] {
            assert_eq!(FixedOffset::parse(invalid), None, "{invalid}");
        }
        let west = FixedOffset::parse("-05:00").unwrap();
        let east = FixedOffset::parse("+05:45").unwrap();
        assert_eq!(
            west.display_received("2026-01-01 02:00:00 +0000"),
            "2025-12-31 21:00:00 UTC-05:00"
        );
        assert_eq!(
            east.display_received("2024-02-28 23:00:00 +0000"),
            "2024-02-29 04:45:00 UTC+05:45"
        );
        assert_eq!(
            west.display_received("1970-01-01 00:00:00 +0000"),
            "1969-12-31 19:00:00 UTC-05:00"
        );
        assert_eq!(
            east.display_received("2026-03-01 01:00:00 +0200"),
            "2026-03-01 04:45:00 UTC+05:45"
        );
        for invalid in [
            "<untrusted>",
            "2026-02-30 00:00:00 +0000",
            "0001-01-01 00:00:00 +0000",
        ] {
            assert_eq!(west.display_received(invalid), invalid);
        }
        assert_eq!(
            east.display_received("9999-12-31 23:59:59 +0000"),
            "9999-12-31 23:59:59 +0000"
        );
    }

    #[test]
    fn timezone_store_persists_cas_and_preserves_other_account_and_settings() {
        let root = std::env::temp_dir().join(format!(
            "osmap-tz-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = Store::new(&root);
        assert_eq!(store.load("alice@example.com"), Ok(Preference::default()));
        assert!(!root.exists());
        let other = crate::mark_read::Store::new(&root)
            .save("alice@example.com", 0, crate::mark_read::Policy::OnOpen)
            .unwrap();
        let saved = store
            .save(
                "alice@example.com",
                0,
                FixedOffset::parse("+05:45").unwrap(),
            )
            .unwrap();
        assert_eq!(
            Store::new(&root).load("alice@example.com"),
            Ok(saved.clone())
        );
        assert_eq!(
            store.save("alice@example.com", 0, FixedOffset::default()),
            Err(Error::Stale)
        );
        assert_eq!(store.load("alice@example.com"), Ok(saved));
        assert_eq!(store.load("bob@example.com"), Ok(Preference::default()));
        assert_eq!(
            crate::mark_read::Store::new(&root).load("alice@example.com"),
            Ok(other)
        );
        assert_eq!(
            store.save("", 0, FixedOffset::default()),
            Err(Error::Invalid)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn timezone_corrupt_foreign_and_exhausted_records_are_never_reset() {
        let root = std::env::temp_dir().join(format!(
            "osmap-tz-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        let store = Store::new(&root);
        store
            .save("alice@example.com", 0, FixedOffset::default())
            .unwrap();
        let record = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|value| value == "json"))
            .unwrap();
        for bytes in [b"corrupt".to_vec(), br#"{"version":1,"account":"bob@example.com","revision":1,"offset_minutes":0}"#.to_vec(), br#"{"version":1,"account":"alice@example.com","revision":1,"offset_minutes":1}"#.to_vec(), br#"{"version":1,"account":"alice@example.com","revision":1,"offset_minutes":0,"revision":2}"#.to_vec()] {
            fs::write(&record, &bytes).unwrap();
            assert_eq!(store.load("alice@example.com"), Err(Error::Unavailable));
            assert_eq!(store.save("alice@example.com", 0, FixedOffset::default()), Err(Error::Unavailable));
            assert_eq!(fs::read(&record).unwrap(), bytes);
        }
        let bytes = format!("{{\"version\":1,\"account\":\"alice@example.com\",\"revision\":{},\"offset_minutes\":0}}", u64::MAX);
        fs::write(&record, &bytes).unwrap();
        assert_eq!(
            store.save("alice@example.com", u64::MAX, FixedOffset::default()),
            Err(Error::Unavailable)
        );
        assert_eq!(fs::read(&record).unwrap(), bytes.as_bytes());
        fs::remove_dir_all(root).unwrap();
    }
}
