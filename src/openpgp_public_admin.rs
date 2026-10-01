//! Helper-only public keybox transactions. No browser-supplied paths or private
//! material files. The caller owns peer/grant authentication and must hold its
//! binding record lock across removal checks and this transaction's RPC.
use crate::identity::CanonicalUsername;
use crate::openpgp_inventory::Inventory;
use crate::openpgp_inventory_runtime::{file, private_dir};
use crate::private_account_file::PrivateAccountFile;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAX_PUBLIC_FILE: usize = 4 * 1024 * 1024;
const MAX_CERTIFICATE: usize = 65536;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    Invalid,
    Unavailable,
    Stale,
    Busy,
    Expired,
    Unconfirmed,
}
#[derive(Debug, Clone)]
pub struct AccountHome {
    pub account: CanonicalUsername,
    pub home: PathBuf,
}
#[derive(Debug, Clone)]
pub struct PublicSnapshot {
    pub inventory: Inventory,
    /// Hash of the actual public keybox, not a claim about binding trust.
    pub revision: String,
}
pub struct PublicAdminStore {
    directory: PathBuf,
    worker: PathBuf,
    engine: PathBuf,
    accounts: Vec<AccountHome>,
    locks: PrivateAccountFile,
    unconfirmed: AtomicBool,
}
impl PublicAdminStore {
    /// Called by the operator-configured helper principal. This is not an HTTP
    /// authentication constructor; the helper service must authenticate first.
    pub fn from_operator_mappings(
        directory: PathBuf,
        worker: PathBuf,
        engine: PathBuf,
        accounts: Vec<AccountHome>,
    ) -> Result<Self, AdminError> {
        crate::openbsd::disable_core_dumps().map_err(|_| AdminError::Unavailable)?;
        let owner = crate::openbsd::effective_uid();
        private_dir(&directory, owner, false).map_err(|_| AdminError::Invalid)?;
        file(&worker, owner, true, 64 * 1024 * 1024).map_err(|_| AdminError::Invalid)?;
        file(&engine, owner, true, 64 * 1024 * 1024).map_err(|_| AdminError::Invalid)?;
        if accounts.is_empty() || accounts.len() > 128 || worker == engine {
            return Err(AdminError::Invalid);
        }
        let mut names = BTreeSet::new();
        for mapping in &accounts {
            if !names.insert(mapping.account.as_str())
                || mapping.home.starts_with(&directory)
                || directory.starts_with(&mapping.home)
            {
                return Err(AdminError::Invalid);
            }
            validate_home(&mapping.home)?;
        }
        for (index, mapping) in accounts.iter().enumerate() {
            if accounts.iter().skip(index + 1).any(|other| {
                mapping.home.starts_with(&other.home) || other.home.starts_with(&mapping.home)
            }) {
                return Err(AdminError::Invalid);
            }
        }
        Ok(Self {
            locks: PrivateAccountFile::new(directory.join("locks"), "osmap-public-admin-v1", 0),
            directory,
            worker,
            engine,
            accounts,
            unconfirmed: AtomicBool::new(false),
        })
    }
    pub fn snapshot(
        &self,
        account: &CanonicalUsername,
        deadline: Instant,
    ) -> Result<PublicSnapshot, AdminError> {
        self.ready(deadline)?;
        let home = self.home(account)?;
        let _lock = self.locks.lock(account.as_str()).map_err(lock_error)?;
        self.read_snapshot(home, deadline)
    }
    pub fn import_public(
        &self,
        account: &CanonicalUsername,
        expected_revision: &str,
        primary_fingerprint: &str,
        certificate: &[u8],
        deadline: Instant,
    ) -> Result<PublicSnapshot, AdminError> {
        if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE {
            return Err(AdminError::Invalid);
        }
        self.mutate(
            account,
            expected_revision,
            primary_fingerprint,
            Some(certificate),
            deadline,
        )
    }
    pub fn remove_public(
        &self,
        account: &CanonicalUsername,
        expected_revision: &str,
        primary_fingerprint: &str,
        deadline: Instant,
    ) -> Result<PublicSnapshot, AdminError> {
        self.mutate(
            account,
            expected_revision,
            primary_fingerprint,
            None,
            deadline,
        )
    }
    fn ready(&self, deadline: Instant) -> Result<(), AdminError> {
        if self.unconfirmed.load(Ordering::SeqCst) {
            return Err(AdminError::Unconfirmed);
        }
        if deadline.saturating_duration_since(Instant::now()) < Duration::from_millis(100) {
            return Err(AdminError::Expired);
        }
        private_dir(&self.directory, crate::openbsd::effective_uid(), false)
            .map_err(|_| AdminError::Unavailable)
    }
    fn home(&self, account: &CanonicalUsername) -> Result<&Path, AdminError> {
        let mapping = self
            .accounts
            .iter()
            .find(|m| &m.account == account)
            .ok_or(AdminError::Invalid)?;
        validate_home(&mapping.home)?;
        Ok(&mapping.home)
    }
    fn read_snapshot(&self, home: &Path, deadline: Instant) -> Result<PublicSnapshot, AdminError> {
        let before = read_public(&home.join("pubring.kbx"))?;
        let inventory = self.worker_inventory(home, None, &[], deadline)?;
        if before != read_public(&home.join("pubring.kbx"))? {
            return Err(AdminError::Stale);
        }
        Ok(PublicSnapshot {
            inventory,
            revision: digest(&before),
        })
    }
    fn worker_inventory(
        &self,
        home: &Path,
        operation: Option<(&str, &str)>,
        input: &[u8],
        deadline: Instant,
    ) -> Result<Inventory, AdminError> {
        file(
            &self.worker,
            crate::openbsd::effective_uid(),
            true,
            64 * 1024 * 1024,
        )
        .map_err(|_| AdminError::Unavailable)?;
        file(
            &self.engine,
            crate::openbsd::effective_uid(),
            true,
            64 * 1024 * 1024,
        )
        .map_err(|_| AdminError::Unavailable)?;
        let mut command = crate::auth::public_inventory_command(&self.worker, home);
        if let Some((operation, fingerprint)) = operation {
            command.arg(operation).arg(fingerprint).arg(&self.engine);
        }
        let bytes = crate::openpgp_crypto_process::run_public_admin(command, input, deadline)
            .map_err(|error| match error {
                crate::openpgp_crypto::Error::Expired => AdminError::Expired,
                _ => AdminError::Unavailable,
            })?;
        let inventory = Inventory::parse(&bytes).map_err(|_| AdminError::Unavailable)?;
        if inventory.keys().is_none() {
            return Err(AdminError::Unavailable);
        }
        Ok(inventory)
    }
    fn mutate(
        &self,
        account: &CanonicalUsername,
        expected_revision: &str,
        fingerprint: &str,
        certificate: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<PublicSnapshot, AdminError> {
        self.ready(deadline)?;
        if !revision(expected_revision) || !fingerprint_v4(fingerprint) {
            return Err(AdminError::Invalid);
        }
        let home = self.home(account)?;
        let _lock = self.locks.lock(account.as_str()).map_err(lock_error)?;
        let before = self.read_snapshot(home, deadline)?;
        if before.revision != expected_revision {
            return Err(AdminError::Stale);
        }
        if certificate.is_none() {
            // This is an exact actual-home check through the already-existing
            // account agent. A public staging copy cannot prove private absence.
            self.worker_inventory(home, Some(("guard-removal", fingerprint)), &[], deadline)?;
        }
        let stage = Stage::create(&self.directory)?;
        let old_keybox = read_public(&home.join("pubring.kbx"))?;
        if digest(&old_keybox) != expected_revision {
            return Err(AdminError::Stale);
        }
        write_new(&stage.path.join("pubring.kbx"), &old_keybox)?;
        write_new(
            &stage.path.join("trustdb.gpg"),
            &read_public(&home.join("trustdb.gpg"))?,
        )?;
        let operation = if certificate.is_some() {
            "import-public"
        } else {
            "remove-public"
        };
        let inventory = self.worker_inventory(
            &stage.path,
            Some((operation, fingerprint)),
            certificate.unwrap_or(&[]),
            deadline,
        )?;
        validate_delta(
            &before.inventory,
            &inventory,
            fingerprint,
            certificate.is_some(),
        )?;
        let new_keybox = read_public(&stage.path.join("pubring.kbx"))?;
        self.ready(deadline)?;
        if read_public(&home.join("pubring.kbx"))? != old_keybox {
            return Err(AdminError::Stale);
        }
        // Re-check the actual secret capability immediately before a removal
        // commit. Trusted custody imports must use this same helper account lock.
        if certificate.is_none() {
            self.worker_inventory(home, Some(("guard-removal", fingerprint)), &[], deadline)?;
        }
        self.ready(deadline)?;
        if read_public(&home.join("pubring.kbx"))? != old_keybox {
            return Err(AdminError::Stale);
        }
        let temporary = home.join(format!(
            ".osmap-public-{}-{}.tmp",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        write_new(&temporary, &new_keybox)?;
        if self.ready(deadline).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(AdminError::Expired);
        }
        if fs::rename(&temporary, home.join("pubring.kbx")).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(AdminError::Unavailable);
        }
        // Actual trustdb/private files are not committed from staging. Explicit
        // binding trust is separate from GnuPG ownertrust and local trust cache.
        if File::open(home)
            .and_then(|directory| directory.sync_all())
            .is_err()
        {
            self.unconfirmed.store(true, Ordering::SeqCst);
            return Err(AdminError::Unconfirmed);
        }
        Ok(PublicSnapshot {
            inventory,
            revision: digest(&new_keybox),
        })
    }
}
fn validate_home(home: &Path) -> Result<(), AdminError> {
    let owner = crate::openbsd::effective_uid();
    private_dir(home, owner, false).map_err(|_| AdminError::Invalid)?;
    for name in ["pubring.kbx", "trustdb.gpg"] {
        file(&home.join(name), owner, false, MAX_PUBLIC_FILE as u64)
            .map_err(|_| AdminError::Invalid)?;
    }
    for name in ["gpg.conf", "common.conf", "gpg-agent.conf"] {
        match fs::symlink_metadata(home.join(name)) {
            Ok(_) => return Err(AdminError::Invalid),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AdminError::Unavailable),
        }
    }
    Ok(())
}
fn read_public(path: &Path) -> Result<Vec<u8>, AdminError> {
    let handle = file(
        path,
        crate::openbsd::effective_uid(),
        false,
        MAX_PUBLIC_FILE as u64,
    )
    .map_err(|_| AdminError::Unavailable)?;
    let mut bytes = Vec::new();
    handle
        .take(MAX_PUBLIC_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AdminError::Unavailable)?;
    if bytes.len() > MAX_PUBLIC_FILE {
        return Err(AdminError::Unavailable);
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AdminError> {
    let mut handle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| AdminError::Unavailable)?;
    if handle
        .write_all(bytes)
        .and_then(|()| handle.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(path);
        return Err(AdminError::Unavailable);
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn revision(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn fingerprint_v4(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}
fn lock_error(error: std::io::Error) -> AdminError {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        AdminError::Busy
    } else {
        AdminError::Unavailable
    }
}
fn validate_delta(
    before: &Inventory,
    after: &Inventory,
    fingerprint: &str,
    importing: bool,
) -> Result<(), AdminError> {
    let old = before.keys().ok_or(AdminError::Unavailable)?;
    let new = after.keys().ok_or(AdminError::Unavailable)?;
    if new.iter().any(|key| key.primary.fingerprint == fingerprint) != importing {
        return Err(AdminError::Unavailable);
    }
    let unrelated =
        |keys: &[crate::openpgp_inventory::PublicKey]| -> Result<Vec<Vec<u8>>, AdminError> {
            let mut values = keys
                .iter()
                .filter(|key| key.primary.fingerprint != fingerprint)
                .map(|key| serde_json::to_vec(key).map_err(|_| AdminError::Unavailable))
                .collect::<Result<Vec<_>, _>>()?;
            values.sort();
            Ok(values)
        };
    if unrelated(old)? != unrelated(new)? {
        return Err(AdminError::Unavailable);
    }
    Ok(())
}
struct Stage {
    path: PathBuf,
}
impl Stage {
    fn create(directory: &Path) -> Result<Self, AdminError> {
        let path = directory.join(format!(
            "stage-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| AdminError::Unavailable)?;
        Ok(Self { path })
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
#[cfg(test)]
#[path = "openpgp_public_admin_tests.rs"]
mod tests;
