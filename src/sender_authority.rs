//! Bounded operator-declared sender authority. Browser preferences cannot add authority.
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

pub const CANONICAL_ID: &str = "canonical";
pub const MAX_IDENTITIES: usize = 16;
const MAX_BYTES: usize = 64 * 1024;
const MAX_ACCOUNTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unavailable,
    NotAuthorized,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
    pub address: String,
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedIdentity").finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub account: String,
    pub revision: u64,
    pub identities: Vec<Identity>,
}
impl Snapshot {
    pub fn validate(&self, account: &str) -> Result<(), Error> {
        valid_account(account)?;
        if self.account != account
            || self.identities.is_empty()
            || self.identities.len() > MAX_IDENTITIES
            || (self.revision == 0 && self.identities.len() != 1)
        {
            return Err(Error::Invalid);
        }
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for identity in &self.identities {
            if !valid_id(&identity.id)
                || crate::identity_preferences::IdentityPreferences::new(
                    "",
                    Some(&identity.address),
                )
                .is_err()
                || !ids.insert(identity.id.clone())
                || !addresses.insert(crate::mail_address::comparison_key(&identity.address))
            {
                return Err(Error::Invalid);
            }
            if identity.id == CANONICAL_ID && identity.address != account {
                return Err(Error::Invalid);
            }
        }
        if !ids.contains(CANONICAL_ID) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn canonical(account: &str) -> Result<Self, Error> {
        valid_account(account)?;
        Ok(Self {
            account: account.into(),
            revision: 0,
            identities: vec![Identity {
                id: CANONICAL_ID.into(),
                address: account.into(),
            }],
        })
    }
    pub fn get(&self, id: &str) -> Result<&Identity, Error> {
        self.identities
            .iter()
            .find(|identity| identity.id == id)
            .ok_or(Error::NotAuthorized)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    path: Option<PathBuf>,
    owner_uid: u32,
}
impl Default for Provider {
    fn default() -> Self {
        Self::new(None, 0)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8,
    accounts: Vec<Account>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    account: String,
    revision: u64,
    identities: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    address: String,
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
fn valid_account(account: &str) -> Result<(), Error> {
    crate::identity::CanonicalUsername::parse(account).map_err(|_| Error::Invalid)?;
    if account.contains(['*', '?']) {
        return Err(Error::Invalid);
    }
    crate::identity_preferences::IdentityPreferences::new("", Some(account))
        .map_err(|_| Error::Invalid)?;
    Ok(())
}

impl Provider {
    /// Production construction requires the configured administrative owner, never an HTTP UID.
    pub fn new(path: Option<PathBuf>, owner_uid: u32) -> Self {
        Self { path, owner_uid }
    }
    pub fn snapshot(&self, account: &str) -> Result<Snapshot, Error> {
        let mut selected = Snapshot::canonical(account)?;
        let Some(path) = &self.path else {
            return Ok(selected);
        };
        let deadline = Instant::now() + Duration::from_millis(500);
        let bytes = self.read(path, deadline)?;
        let inventory: Inventory =
            serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        if inventory.version != 1 || inventory.accounts.len() > MAX_ACCOUNTS {
            return Err(Error::Unavailable);
        }
        let mut accounts = BTreeSet::new();
        for entry in inventory.accounts {
            if valid_account(&entry.account).is_err()
                || entry.revision == 0
                || entry.identities.len() >= MAX_IDENTITIES
                || !accounts.insert(entry.account.clone())
            {
                return Err(Error::Unavailable);
            }
            let mut ids = BTreeSet::from([CANONICAL_ID.to_string()]);
            let mut addresses =
                BTreeSet::from([crate::mail_address::comparison_key(&entry.account)]);
            let mut aliases = Vec::new();
            for alias in entry.identities {
                if !valid_id(&alias.id)
                    || crate::identity_preferences::IdentityPreferences::new(
                        "",
                        Some(&alias.address),
                    )
                    .is_err()
                    || !ids.insert(alias.id.clone())
                    || !addresses.insert(crate::mail_address::comparison_key(&alias.address))
                {
                    return Err(Error::Unavailable);
                }
                aliases.push(Identity {
                    id: alias.id,
                    address: alias.address,
                });
            }
            if entry.account == account {
                selected.revision = entry.revision;
                selected.identities.extend(aliases);
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        selected.validate(account)?;
        Ok(selected)
    }
    /// Canonical session authority is independent of optional aliases. Captured aliases
    /// must still match the same current inventory ID and address at first dispatch.
    pub fn authorize(
        &self,
        account: &str,
        capture: Option<&crate::identity_preferences::CapturedSender>,
    ) -> Result<String, Error> {
        valid_account(account)?;
        let Some(capture) = capture else {
            return Ok(account.into());
        };
        if capture.id() == CANONICAL_ID || capture.address() == account {
            return Err(Error::NotAuthorized);
        }
        let current = self.snapshot(account)?;
        let selected = current.get(capture.id())?;
        if selected.address != capture.address() {
            return Err(Error::NotAuthorized);
        }
        Ok(selected.address.clone())
    }
    #[cfg(unix)]
    fn read(&self, path: &std::path::Path, deadline: Instant) -> Result<Vec<u8>, Error> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(Error::Unavailable);
        }
        if !path.exists() {
            return Err(Error::Unavailable);
        }
        if path.canonicalize().map_err(|_| Error::Unavailable)? != path {
            return Err(Error::Unavailable);
        }
        for ancestor in path.ancestors().skip(1) {
            if ancestor == std::path::Path::new("/") {
                break;
            }
            let metadata = ancestor
                .symlink_metadata()
                .map_err(|_| Error::Unavailable)?;
            let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !metadata.is_dir()
                || ![0, self.owner_uid].contains(&metadata.uid())
                || (metadata.mode() & 0o022 != 0 && !sticky_root)
            {
                return Err(Error::Unavailable);
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error::Unavailable)?;
        let before = file.metadata().map_err(|_| Error::Unavailable)?;
        if !before.is_file()
            || before.uid() != self.owner_uid
            || before.nlink() != 1
            || before.mode() & 0o022 != 0
            || before.len() > MAX_BYTES as u64
            || Instant::now() >= deadline
        {
            return Err(Error::Unavailable);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let after = file.metadata().map_err(|_| Error::Unavailable)?;
        if bytes.len() > MAX_BYTES
            || bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || Instant::now() >= deadline
        {
            return Err(Error::Unavailable);
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    fn read(&self, _: &std::path::Path, _: Instant) -> Result<Vec<u8>, Error> {
        Err(Error::Unavailable)
    }
}

#[cfg(test)]
#[path = "sender_authority_tests.rs"]
mod tests;
