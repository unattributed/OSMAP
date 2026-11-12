//! D04 failure admission, independent account/source buckets and private atomic records.
use crate::password_change::Error;
use crate::private_account_file::{LockedAccountFile, PrivateAccountFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::PathBuf;

const WINDOW: u64 = 900;
const ACCOUNT_LIMIT: usize = 5;
const SOURCE_LIMIT: usize = 10;

#[derive(Clone)]
pub struct Store {
    files: PrivateAccountFile,
    #[cfg(test)]
    fail_source_publication: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    subject_ref: String,
    failures: Vec<u64>,
    locked_until: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Safety {
    version: u8,
    contained: bool,
}
pub(crate) struct Admission {
    store: Store,
    account: LockedAccountFile,
    source: LockedAccountFile,
    account_record: Record,
    source_record: Record,
    admitted_at: u64,
}
impl Store {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            files: PrivateAccountFile::new(directory, "osmap-password-stepup-rate-v1", 1024),
            #[cfg(test)]
            fail_source_publication: Default::default(),
        }
    }
    fn safety(&self) -> Result<LockedAccountFile, Error> {
        let lock = self
            .files
            .lock("publication-safety")
            .map_err(|_| Error::Unavailable)?;
        if let Some(bytes) = lock.read().map_err(|_| Error::Unavailable)? {
            let value: Safety = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
            if value.version != 1 || value.contained {
                return Err(Error::Unavailable);
            }
        }
        Ok(lock)
    }
    pub(crate) fn healthy(&self) -> Result<(), Error> {
        self.safety().map(|_| ())
    }
    pub(crate) fn admit(&self, account: &str, source: &str, now: u64) -> Result<Admission, Error> {
        crate::account_admission::valid_account(account).map_err(|_| Error::Invalid)?;
        let source: IpAddr = source.parse().map_err(|_| Error::Invalid)?;
        if now == 0 || now.checked_add(WINDOW).is_none() {
            return Err(Error::Unavailable);
        }
        // Admission acquires safety before the independent locks. Publication
        // reacquires it while holding its own pair; all acquisitions are
        // nonblocking, so competing operations refuse instead of deadlocking.
        // Safety is never held across credential verification.
        let safety = self.safety()?;
        let account_key = format!("account:{account}");
        let source_key = format!("source:{source}");
        // Fixed role order across processes; locks are nonblocking, never queued.
        let account_lock = self
            .files
            .lock(&account_key)
            .map_err(|_| Error::Unavailable)?;
        let source_lock = self
            .files
            .lock(&source_key)
            .map_err(|_| Error::Unavailable)?;
        let account_record = read(&account_lock, &account_key, ACCOUNT_LIMIT, now)?;
        let source_record = read(&source_lock, &source_key, SOURCE_LIMIT, now)?;
        drop(safety);
        Ok(Admission {
            store: self.clone(),
            account: account_lock,
            source: source_lock,
            account_record,
            source_record,
            admitted_at: now,
        })
    }
}
fn subject_ref(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))
}
fn read(lock: &LockedAccountFile, key: &str, limit: usize, now: u64) -> Result<Record, Error> {
    let reference = subject_ref(key);
    let mut record = match lock.read().map_err(|_| Error::Unavailable)? {
        None => Record {
            version: 1,
            subject_ref: reference.clone(),
            failures: vec![],
            locked_until: None,
        },
        Some(bytes) => serde_json::from_slice::<Record>(&bytes).map_err(|_| Error::Unavailable)?,
    };
    if record.version != 1
        || record.subject_ref != reference
        || record.failures.len() > limit
        || record
            .failures
            .iter()
            .any(|value| *value == 0 || *value > now)
        || record.failures.windows(2).any(|pair| pair[0] > pair[1])
        || (record.failures.len() == limit) != record.locked_until.is_some()
        || record.locked_until.is_some_and(|until| {
            record
                .failures
                .last()
                .and_then(|last| last.checked_add(WINDOW))
                != Some(until)
        })
    {
        return Err(Error::Unavailable);
    }
    if record.locked_until.is_some_and(|until| now < until) {
        return Err(Error::Throttled);
    }
    record.failures.retain(|failed| now - *failed < WINDOW);
    record.locked_until = None;
    Ok(record)
}
fn write<T: Serialize>(lock: &LockedAccountFile, value: &T) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Unavailable)?;
    lock.write(&bytes).map_err(|_| Error::Unavailable)
}
impl Admission {
    pub(crate) fn confirm(&self) -> Result<(), Error> {
        self.store.healthy()
    }
    pub(crate) fn failed(mut self, now: u64) -> Result<bool, Error> {
        if now < self.admitted_at || now.checked_add(WINDOW).is_none() {
            return Err(Error::Unavailable);
        }
        for (record, limit) in [
            (&mut self.account_record, ACCOUNT_LIMIT),
            (&mut self.source_record, SOURCE_LIMIT),
        ] {
            record.failures.retain(|failed| now - *failed < WINDOW);
            record.failures.push(now);
            if record.failures.len() >= limit {
                record.locked_until = Some(now + WINDOW);
            }
        }
        // Hold safety ownership until BOTH publications and confirmed clear.
        // Any partial/unconfirmed write leaves all step-up admission contained;
        // disjoint requests cannot clear this marker or silently lose a failure.
        let safety = self.store.safety()?;
        write(
            &safety,
            &Safety {
                version: 1,
                contained: true,
            },
        )?;
        write(&self.account, &self.account_record)?;
        #[cfg(test)]
        if self
            .store
            .fail_source_publication
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::Unavailable);
        }
        write(&self.source, &self.source_record)?;
        write(
            &safety,
            &Safety {
                version: 1,
                contained: false,
            },
        )?;
        Ok(self.account_record.locked_until.is_some() || self.source_record.locked_until.is_some())
    }
}
#[cfg(test)]
#[path = "password_change_rate_tests.rs"]
mod tests;
