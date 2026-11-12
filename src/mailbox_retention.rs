//! Explicit helper-side retention authority. Missing policy never permits delete.
//!
//! A configured file is an operator-owned declaration, not a browser preference
//! or a fact inferred from message flags/dates. This module never writes policy.
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

pub const MAX_RETENTION_POLICY_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionDecision {
    Allowed { revision: u64 },
    Denied,
    Unavailable,
}

/// The configured owner UID is selected by the trusted helper construction,
/// never supplied in an HTTP/helper request. Production can require root (0).
/// Policy replacement must share the native mutation gate or occur while the
/// service is stopped. Fresh reads detect changes before the final check but
/// cannot make an unrelated external file rewrite atomic with native expunge.
#[derive(Debug, Clone)]
pub struct FileMailboxRetentionPolicy {
    path: Option<PathBuf>,
    trusted_owner_uid: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u8,
    rules: Vec<Rule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    account: String,
    mailbox_name: String,
    revision: u64,
    permanent_delete: Permission,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Permission {
    Allowed,
    Denied,
}

pub(super) fn valid_account(account: &str) -> bool {
    crate::identity::CanonicalUsername::parse(account).is_ok() && !account.contains(['*', '?'])
}

impl Default for FileMailboxRetentionPolicy {
    fn default() -> Self {
        Self::new(None, 0)
    }
}
impl FileMailboxRetentionPolicy {
    pub fn new(path: Option<PathBuf>, trusted_owner_uid: u32) -> Self {
        Self {
            path,
            trusted_owner_uid,
        }
    }

    pub fn decision(
        &self,
        account: &str,
        mailbox_name: &str,
        deadline: Instant,
    ) -> RetentionDecision {
        if !valid_account(account)
            || crate::bin_folder::parse_mailbox_name(mailbox_name).is_err()
            || Instant::now() >= deadline
        {
            return RetentionDecision::Unavailable;
        }
        self.read_decision(account, mailbox_name, deadline)
            .unwrap_or(RetentionDecision::Unavailable)
    }

    fn read_decision(
        &self,
        account: &str,
        mailbox_name: &str,
        deadline: Instant,
    ) -> Option<RetentionDecision> {
        let path = self.path.as_ref()?;
        if !path.is_absolute() || path.canonicalize().ok()?.as_path() != path.as_path() {
            return None;
        }
        #[cfg(not(unix))]
        {
            let _ = (account, mailbox_name, deadline);
            None
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if path.as_os_str().len() > 4096 {
                return None;
            }
            for ancestor in path.ancestors().skip(1) {
                if ancestor == std::path::Path::new("/") {
                    break;
                }
                let metadata = ancestor.symlink_metadata().ok()?;
                let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
                if !metadata.is_dir()
                    || ![0, self.trusted_owner_uid].contains(&metadata.uid())
                    || (metadata.mode() & 0o022 != 0 && !sticky_root)
                {
                    return None;
                }
            }
            let mut file: File = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)
                .ok()?;
            let metadata = file.metadata().ok()?;
            if !metadata.is_file()
                || metadata.uid() != self.trusted_owner_uid
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
                || metadata.len() > MAX_RETENTION_POLICY_BYTES as u64
                || Instant::now() >= deadline
            {
                return None;
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take((MAX_RETENTION_POLICY_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .ok()?;
            let after = file.metadata().ok()?;
            if bytes.len() > MAX_RETENTION_POLICY_BYTES
                || bytes.len() as u64 != metadata.len()
                || after.len() != metadata.len()
                || after.mtime() != metadata.mtime()
                || after.mtime_nsec() != metadata.mtime_nsec()
                || after.ctime() != metadata.ctime()
                || after.ctime_nsec() != metadata.ctime_nsec()
                || Instant::now() >= deadline
            {
                return None;
            }
            let policy: PolicyFile = serde_json::from_slice(&bytes).ok()?;
            if policy.version != 1 || policy.rules.len() > MAX_RULES {
                return None;
            }
            let mut identities = BTreeSet::new();
            let mut selected = RetentionDecision::Unavailable;
            for rule in policy.rules {
                if !valid_account(&rule.account)
                    || crate::bin_folder::parse_mailbox_name(&rule.mailbox_name).is_err()
                    || rule.revision == 0
                    || !identities.insert((rule.account.clone(), rule.mailbox_name.clone()))
                {
                    return None;
                }
                if rule.account == account && rule.mailbox_name == mailbox_name {
                    selected = match rule.permanent_delete {
                        Permission::Allowed => RetentionDecision::Allowed {
                            revision: rule.revision,
                        },
                        Permission::Denied => RetentionDecision::Denied,
                    };
                }
            }
            (Instant::now() < deadline).then_some(selected)
        }
    }
}

#[cfg(test)]
#[path = "mailbox_retention_tests.rs"]
mod tests;
