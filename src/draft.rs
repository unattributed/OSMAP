//! Server-side draft persistence primitives for the Version 3 draft slice.
//!
//! This module intentionally sits below the HTTP route layer. It gives the
//! later browser routes a bounded, owner-scoped storage surface without mixing
//! route behavior into the first persistence step.

use std::cmp::Reverse;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::draft_content::DraftContent;

#[path = "draft_atomic.rs"]
mod atomic;
use crate::send::{ComposePolicy, UploadedAttachment};

/// Maximum persisted source mailbox length.
pub const DEFAULT_DRAFT_SOURCE_MAILBOX_MAX_LEN: usize = 255;

/// Maximum persisted source attachment part-path length.
pub const DEFAULT_DRAFT_SOURCE_PART_PATH_MAX_LEN: usize = 64;

/// Draft ids are 128-bit random values encoded as lower-case hex.
pub const DRAFT_ID_BYTES: usize = 16;
pub const DRAFT_ID_HEX_LEN: usize = DRAFT_ID_BYTES * 2;

/// Default maximum draft lifetime before opportunistic cleanup.
pub const DEFAULT_DRAFT_MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Default maximum number of drafts one user may keep.
pub const DEFAULT_MAX_DRAFTS_PER_USER: usize = 50;

pub const DEFAULT_DRAFT_STORAGE_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Default maximum number of summaries rendered from one list operation.
pub const DEFAULT_MAX_DRAFT_SUMMARY_ROWS: usize = 100;

/// Default maximum metadata file size before parse rejection.
pub const DEFAULT_DRAFT_METADATA_MAX_BYTES: u64 = 1024 * 1024;

const DRAFT_METADATA_FILE: &str = "metadata.draft";

/// Policy controlling bounded draft persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftPolicy {
    pub compose_policy: ComposePolicy,
    pub max_age_seconds: u64,
    pub max_drafts_per_user: usize,
    pub max_summary_rows: usize,
    pub metadata_max_bytes: u64,
    pub storage_max_bytes: u64,
}

impl Default for DraftPolicy {
    fn default() -> Self {
        Self {
            compose_policy: ComposePolicy::default(),
            max_age_seconds: DEFAULT_DRAFT_MAX_AGE_SECONDS,
            max_drafts_per_user: DEFAULT_MAX_DRAFTS_PER_USER,
            max_summary_rows: DEFAULT_MAX_DRAFT_SUMMARY_ROWS,
            metadata_max_bytes: DEFAULT_DRAFT_METADATA_MAX_BYTES,
            storage_max_bytes: DEFAULT_DRAFT_STORAGE_MAX_BYTES,
        }
    }
}

/// Errors raised while validating or storing drafts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftError {
    pub reason: String,
}

impl DraftError {
    pub(crate) fn save_unconfirmed(&self) -> bool {
        self.reason == atomic::SAVE_UNCONFIRMED
    }
}

/// One persisted draft record.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftRecord {
    pub draft_id: String,
    pub canonical_username: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    /// None denotes a new draft; Some(0) denotes a legacy persisted record.
    pub revision: Option<u64>,
    pub starred: bool,
    pub request: DraftContent,
    pub source_attachments: Option<DraftSourceAttachments>,
}

/// Bounded references to source-message attachments explicitly selected by the
/// user. Source bytes and raw MIME content are never persisted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftSourceAttachments {
    pub mailbox_name: String,
    pub uid: u64,
    pub version: Option<crate::message_metadata::MessageVersion>,
    pub part_paths: Vec<String>,
}

/// Validated draft creation input supplied by the future browser route layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftRecordInput {
    pub draft_id: String,
    pub canonical_username: String,
    pub now: u64,
    pub recipients_text: String,
    pub cc_text: String,
    pub bcc_text: String,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<UploadedAttachment>,
    pub source_attachments: Option<DraftSourceAttachments>,
}

impl std::fmt::Debug for DraftRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DraftRecord")
            .field("draft_id", &self.draft_id)
            .field("canonical_username", &self.canonical_username)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("expires_at", &self.expires_at)
            .field("revision", &self.revision)
            .field("recipient_count", &self.request.total_recipient_count())
            .field("subject_len", &self.request.subject.len())
            .field("body_len", &self.request.body.len())
            .field("attachment_count", &self.request.attachments.len())
            .field(
                "source_attachment_count",
                &self
                    .source_attachments
                    .as_ref()
                    .map(|source| source.part_paths.len())
                    .unwrap_or_default(),
            )
            .finish()
    }
}

impl DraftRecord {
    /// Builds and validates one draft record from current compose fields.
    pub fn new(policy: DraftPolicy, input: DraftRecordInput) -> Result<Self, DraftError> {
        validate_draft_id(&input.draft_id)?;
        validate_canonical_username(&input.canonical_username)?;

        let request = DraftContent::new(
            policy.compose_policy,
            input.recipients_text,
            input.cc_text,
            input.bcc_text,
            input.subject,
            input.body,
            input.attachments,
        )
        .map_err(|error| DraftError {
            reason: error.reason,
        })?;
        let source_attachments = input
            .source_attachments
            .map(|source| validate_source_attachments(policy, source))
            .transpose()?;
        validate_combined_attachment_count(policy, &request, source_attachments.as_ref())?;

        Ok(Self {
            draft_id: input.draft_id,
            canonical_username: input.canonical_username,
            created_at: input.now,
            updated_at: input.now,
            expires_at: input.now.saturating_add(policy.max_age_seconds),
            revision: None,
            starred: false,
            request,
            source_attachments,
        })
    }

    /// Returns a bounded list projection that excludes body and attachment data.
    pub fn summary(&self) -> DraftSummary {
        DraftSummary {
            draft_id: self.draft_id.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            revision: self.revision.unwrap_or(0),
            starred: self.starred,
            storage_bytes: serialize_draft_metadata(self).len() as u64
                + self
                    .request
                    .attachments
                    .iter()
                    .map(|attachment| attachment.size_bytes() as u64)
                    .sum::<u64>(),
            recipient_count: self.request.total_recipient_count(),
            recipient_preview: self.request.recipient_preview(),
            subject: self.request.subject.clone(),
            subject_len: self.request.subject.len(),
            body_len: self.request.body.len(),
            attachment_count: self.request.attachments.len()
                + self
                    .source_attachments
                    .as_ref()
                    .map(|source| source.part_paths.len())
                    .unwrap_or_default(),
            total_attachment_bytes: self
                .request
                .attachments
                .iter()
                .map(UploadedAttachment::size_bytes)
                .sum(),
        }
    }
}

/// Owner-only draft list projection. Bcc and body text are never included.
#[derive(Clone, PartialEq, Eq)]
pub struct DraftSummary {
    pub draft_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub revision: u64,
    pub starred: bool,
    pub storage_bytes: u64,
    pub recipient_count: usize,
    pub recipient_preview: Option<String>,
    pub subject: String,
    pub subject_len: usize,
    pub body_len: usize,
    pub attachment_count: usize,
    pub total_attachment_bytes: usize,
}

impl std::fmt::Debug for DraftSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftSummary")
            .field("updated_at", &self.updated_at)
            .field("recipient_count", &self.recipient_count)
            .field("subject_len", &self.subject_len)
            .field("attachment_count", &self.attachment_count)
            .finish_non_exhaustive()
    }
}

/// Draft storage operations needed by the later browser route slice.
pub trait DraftStore {
    fn save(&self, record: &DraftRecord, now: u64) -> Result<(), DraftError>;
    fn load(
        &self,
        canonical_username: &str,
        draft_id: &str,
        now: u64,
    ) -> Result<Option<DraftRecord>, DraftError>;
    fn list(&self, canonical_username: &str, now: u64) -> Result<Vec<DraftSummary>, DraftError>;
    fn delete(
        &self,
        canonical_username: &str,
        draft_id: &str,
        expected_revision: u64,
    ) -> Result<bool, DraftError>;
    fn cleanup_expired(&self, canonical_username: &str, now: u64) -> Result<usize, DraftError>;
}

/// File-backed draft store rooted under the OSMAP state tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDraftStore {
    draft_root: PathBuf,
    policy: DraftPolicy,
    #[cfg(test)]
    save_fault: Option<atomic::SaveFault>,
}

impl FileDraftStore {
    /// Creates a file-backed draft store.
    pub fn new(draft_root: impl Into<PathBuf>, policy: DraftPolicy) -> Self {
        Self {
            draft_root: draft_root.into(),
            policy,
            #[cfg(test)]
            save_fault: None,
        }
    }

    /// Returns the per-user draft directory derived from the canonical username.
    pub fn owner_dir_for_username(&self, canonical_username: &str) -> PathBuf {
        self.draft_root.join(owner_hash(canonical_username))
    }

    /// Returns the directory for one draft id inside one owner namespace.
    pub fn draft_dir_for_username_and_id(
        &self,
        canonical_username: &str,
        draft_id: &str,
    ) -> PathBuf {
        self.owner_dir_for_username(canonical_username)
            .join(draft_id)
    }

    /// Non-mutating immutable recovery read. Caller owns publication coordination;
    /// this does not run expiry cleanup, legacy recovery, or create a record.
    pub(crate) fn read_immutable(
        &self,
        account: &str,
        id: &str,
    ) -> Result<Option<DraftRecord>, DraftError> {
        validate_canonical_username(account)?;
        validate_draft_id(id)?;
        self.read_record_from_metadata(account, &self.metadata_path(account, id))
    }
    fn metadata_path(&self, canonical_username: &str, draft_id: &str) -> PathBuf {
        self.draft_dir_for_username_and_id(canonical_username, draft_id)
            .join(DRAFT_METADATA_FILE)
    }

    fn acquire_exclusive_lock(
        &self,
        account: &str,
    ) -> Result<crate::private_account_file::LockedAccountFile, DraftError> {
        let guard = crate::private_account_file::PrivateAccountFile::new(
            self.draft_root.clone(),
            "draft-v5",
            0,
        )
        .lock(account)
        .map_err(|error| DraftError {
            reason: if error.kind() == std::io::ErrorKind::WouldBlock {
                "draft store busy".into()
            } else {
                "draft store lock unavailable".into()
            },
        })?;
        self.recover_legacy_backups(account)?;
        Ok(guard)
    }

    fn ensure_owner_dir(&self, canonical_username: &str) -> Result<PathBuf, DraftError> {
        let owner_dir = self.owner_dir_for_username(canonical_username);
        create_private_directory(&owner_dir)?;
        Ok(owner_dir)
    }

    fn cleanup_expired_unlocked(
        &self,
        canonical_username: &str,
        now: u64,
    ) -> Result<usize, DraftError> {
        let owner_dir = self.owner_dir_for_username(canonical_username);
        if !private_directory_exists(&owner_dir)? {
            return Ok(0);
        }

        let mut removed = 0;
        for entry in fs::read_dir(&owner_dir).map_err(|error| DraftError {
            reason: format!(
                "failed to read draft owner directory {:?}: {error}",
                owner_dir
            ),
        })? {
            let entry = entry.map_err(|error| DraftError {
                reason: format!("failed to read draft directory entry: {error}"),
            })?;
            if !entry
                .file_type()
                .map_err(|error| DraftError {
                    reason: format!("failed to inspect draft directory entry: {error}"),
                })?
                .is_dir()
            {
                continue;
            }
            let draft_id = entry.file_name().to_string_lossy().to_string();
            if validate_draft_id(&draft_id).is_err() {
                continue;
            }
            let metadata_path = entry.path().join(DRAFT_METADATA_FILE);
            if let Some(record) =
                self.read_record_from_metadata(canonical_username, &metadata_path)?
            {
                if record.expires_at <= now {
                    remove_draft_dir(entry.path())?;
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }

    fn read_record_from_metadata(
        &self,
        canonical_username: &str,
        metadata_path: &Path,
    ) -> Result<Option<DraftRecord>, DraftError> {
        if !private_directory_exists(&self.owner_dir_for_username(canonical_username))? {
            return Ok(None);
        }
        let directory = metadata_path.parent().ok_or_else(|| DraftError {
            reason: "invalid draft metadata directory".into(),
        })?;
        if !private_directory_exists(directory)? {
            return Ok(None);
        }
        let Some(bytes) = crate::private_account_file::read_record(
            metadata_path,
            self.policy.metadata_max_bytes as usize,
        )
        .map_err(|_| DraftError {
            reason: "draft metadata is unsafe or exceeded maximum size".into(),
        })?
        else {
            return Ok(None);
        };
        let content = String::from_utf8(bytes).map_err(|_| DraftError {
            reason: "invalid draft metadata encoding".into(),
        })?;
        parse_draft_metadata(self.policy, canonical_username, metadata_path, &content)
    }

    fn list_summaries_for_owner(
        &self,
        canonical_username: &str,
        now: u64,
    ) -> Result<Vec<DraftSummary>, DraftError> {
        let mut records = Vec::new();
        let owner_dir = self.owner_dir_for_username(canonical_username);
        if !private_directory_exists(&owner_dir)? {
            return Ok(records);
        }

        for entry in fs::read_dir(&owner_dir).map_err(|error| DraftError {
            reason: format!(
                "failed to read draft owner directory {:?}: {error}",
                owner_dir
            ),
        })? {
            let entry = entry.map_err(|error| DraftError {
                reason: format!("failed to read draft directory entry: {error}"),
            })?;
            if !entry
                .file_type()
                .map_err(|error| DraftError {
                    reason: format!("failed to inspect draft directory entry: {error}"),
                })?
                .is_dir()
            {
                continue;
            }

            let draft_id = entry.file_name().to_string_lossy().to_string();
            if validate_draft_id(&draft_id).is_err() {
                continue;
            }
            let metadata_path = entry.path().join(DRAFT_METADATA_FILE);
            if let Some(record) =
                self.read_record_from_metadata(canonical_username, &metadata_path)?
            {
                if record.expires_at <= now {
                    remove_draft_dir(entry.path())?;
                    continue;
                }
                let mut summary = record.summary();
                summary.storage_bytes = fs::metadata(&metadata_path)
                    .map_err(|_| DraftError {
                        reason: "draft metadata size unavailable".into(),
                    })?
                    .len()
                    + summary.total_attachment_bytes as u64;
                records.push(summary);
            }
        }

        records.sort_by_key(|record| Reverse(record.updated_at));
        Ok(records)
    }
}

impl DraftStore for FileDraftStore {
    fn save(&self, record: &DraftRecord, now: u64) -> Result<(), DraftError> {
        validate_draft_id(&record.draft_id)?;
        validate_canonical_username(&record.canonical_username)?;
        record
            .request
            .validate(self.policy.compose_policy)
            .map_err(|error| DraftError {
                reason: error.reason,
            })?;
        if let Some(source) = record.source_attachments.clone() {
            validate_source_attachments(self.policy, source)?;
        }
        validate_combined_attachment_count(
            self.policy,
            &record.request,
            record.source_attachments.as_ref(),
        )?;
        let _lock = self.acquire_exclusive_lock(&record.canonical_username)?;

        self.cleanup_expired_unlocked(&record.canonical_username, now)?;

        let existing = self.read_record_from_metadata(
            &record.canonical_username,
            &self.metadata_path(&record.canonical_username, &record.draft_id),
        )?;
        let is_new = existing.is_none();
        if existing.as_ref().and_then(|current| current.revision) != record.revision
            || is_new != record.revision.is_none()
        {
            return Err(DraftError {
                reason: "draft revision is stale".into(),
            });
        }
        let summaries = self.list_summaries_for_owner(&record.canonical_username, now)?;
        if is_new {
            let existing_count = summaries.len();
            if existing_count >= self.policy.max_drafts_per_user {
                return Err(DraftError {
                    reason: "draft quota exceeded".to_string(),
                });
            }
        }

        let mut updated = record.clone();
        updated.created_at = existing
            .as_ref()
            .map(|saved| saved.created_at)
            .unwrap_or(now);
        updated.updated_at = now;
        updated.expires_at = now.saturating_add(self.policy.max_age_seconds);
        updated.revision =
            Some(
                record
                    .revision
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| DraftError {
                        reason: "draft revision exhausted".into(),
                    })?,
            );
        let metadata_bytes = serialize_draft_metadata(&updated).len() as u64;
        if metadata_bytes > self.policy.metadata_max_bytes {
            return Err(DraftError {
                reason: "draft metadata exceeded maximum size".into(),
            });
        }
        let used = summaries
            .iter()
            .filter(|summary| summary.draft_id != record.draft_id)
            .try_fold(updated.summary().storage_bytes, |total, summary| {
                total.checked_add(summary.storage_bytes)
            })
            .ok_or_else(|| DraftError {
                reason: "draft storage quota exceeded".into(),
            })?;
        if used > self.policy.storage_max_bytes {
            return Err(DraftError {
                reason: "draft storage quota exceeded".into(),
            });
        }

        let result = self.publish_atomic_record(&updated, existing.as_ref());
        if is_new
            && result
                .as_ref()
                .is_err_and(|error| error.reason != atomic::SAVE_UNCONFIRMED)
        {
            let _ = remove_draft_dir(
                self.draft_dir_for_username_and_id(&record.canonical_username, &record.draft_id),
            );
        }
        result
    }

    fn load(
        &self,
        canonical_username: &str,
        draft_id: &str,
        now: u64,
    ) -> Result<Option<DraftRecord>, DraftError> {
        validate_canonical_username(canonical_username)?;
        validate_draft_id(draft_id)?;
        let _lock = self.acquire_exclusive_lock(canonical_username)?;

        let metadata_path = self.metadata_path(canonical_username, draft_id);
        let Some(record) = self.read_record_from_metadata(canonical_username, &metadata_path)?
        else {
            return Ok(None);
        };
        if record.expires_at <= now {
            remove_draft_dir(self.draft_dir_for_username_and_id(canonical_username, draft_id))?;
            return Ok(None);
        }

        Ok(Some(record))
    }

    fn list(&self, canonical_username: &str, now: u64) -> Result<Vec<DraftSummary>, DraftError> {
        validate_canonical_username(canonical_username)?;
        let _lock = self.acquire_exclusive_lock(canonical_username)?;
        let summaries = self
            .list_summaries_for_owner(canonical_username, now)?
            .into_iter()
            .take(self.policy.max_summary_rows)
            .collect();
        Ok(summaries)
    }

    fn delete(
        &self,
        canonical_username: &str,
        draft_id: &str,
        expected_revision: u64,
    ) -> Result<bool, DraftError> {
        validate_canonical_username(canonical_username)?;
        validate_draft_id(draft_id)?;
        let _lock = self.acquire_exclusive_lock(canonical_username)?;

        let draft_dir = self.draft_dir_for_username_and_id(canonical_username, draft_id);
        if !draft_dir.exists() {
            return Ok(false);
        }
        let current = self
            .read_record_from_metadata(
                canonical_username,
                &self.metadata_path(canonical_username, draft_id),
            )?
            .ok_or_else(|| DraftError {
                reason: "draft revision is stale".into(),
            })?;
        if current.revision != Some(expected_revision) {
            return Err(DraftError {
                reason: "draft revision is stale".into(),
            });
        }
        remove_draft_dir(draft_dir)?;
        Ok(true)
    }

    fn cleanup_expired(&self, canonical_username: &str, now: u64) -> Result<usize, DraftError> {
        validate_canonical_username(canonical_username)?;
        let _lock = self.acquire_exclusive_lock(canonical_username)?;
        self.cleanup_expired_unlocked(canonical_username, now)
    }
}

/// Generates a new high-entropy draft id.
pub fn generate_draft_id() -> Result<String, DraftError> {
    let mut bytes = [0_u8; DRAFT_ID_BYTES];
    getrandom::getrandom(&mut bytes).map_err(|error| DraftError {
        reason: format!("failed to read secure randomness: {error}"),
    })?;
    Ok(hex_lower(&bytes))
}

pub(crate) fn validate_draft_id(draft_id: &str) -> Result<(), DraftError> {
    if draft_id.len() != DRAFT_ID_HEX_LEN {
        return Err(DraftError {
            reason: format!("draft id must be exactly {DRAFT_ID_HEX_LEN} hex characters"),
        });
    }
    if !draft_id
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DraftError {
            reason: "draft id must be lower-case hex".to_string(),
        });
    }
    Ok(())
}

fn validate_canonical_username(canonical_username: &str) -> Result<(), DraftError> {
    if canonical_username.trim().is_empty() {
        return Err(DraftError {
            reason: "canonical username must not be empty".to_string(),
        });
    }
    if canonical_username.chars().any(char::is_control) {
        return Err(DraftError {
            reason: "canonical username must not contain control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_combined_attachment_count(
    policy: DraftPolicy,
    content: &DraftContent,
    source: Option<&DraftSourceAttachments>,
) -> Result<(), DraftError> {
    if content.attachments.len() + source.map_or(0, |source| source.part_paths.len())
        > policy.compose_policy.max_attachments
    {
        return Err(DraftError {
            reason: "draft attachment count exceeded maximum".into(),
        });
    }
    Ok(())
}

fn validate_source_attachments(
    policy: DraftPolicy,
    source: DraftSourceAttachments,
) -> Result<DraftSourceAttachments, DraftError> {
    if source.mailbox_name.is_empty() {
        return Err(DraftError {
            reason: "draft source mailbox must not be empty".to_string(),
        });
    }
    if source.mailbox_name.len() > DEFAULT_DRAFT_SOURCE_MAILBOX_MAX_LEN {
        return Err(DraftError {
            reason: "draft source mailbox exceeded maximum length".to_string(),
        });
    }
    if source.mailbox_name.chars().any(char::is_control) {
        return Err(DraftError {
            reason: "draft source mailbox contained control characters".to_string(),
        });
    }
    if source.uid == 0 {
        return Err(DraftError {
            reason: "draft source UID must be positive".to_string(),
        });
    }
    let version = if let Some(version) = &source.version {
        Some(
            crate::message_metadata::MessageVersion::new(
                version.mailbox_guid.clone(),
                version.message_guid.clone(),
            )
            .map_err(|_| DraftError {
                reason: "draft source identity was invalid".into(),
            })?,
        )
    } else {
        None
    };
    if source.part_paths.is_empty() {
        return Err(DraftError {
            reason: "draft source attachment selection must not be empty".to_string(),
        });
    }
    if source.part_paths.len() > policy.compose_policy.max_attachments {
        return Err(DraftError {
            reason: "draft source attachment count exceeded maximum".to_string(),
        });
    }

    let mut validated = Vec::with_capacity(source.part_paths.len());
    for part_path in source.part_paths {
        if part_path.is_empty()
            || part_path.len() > DEFAULT_DRAFT_SOURCE_PART_PATH_MAX_LEN
            || part_path.chars().any(char::is_control)
            || !part_path.split('.').all(|component| {
                !component.is_empty() && component.chars().all(|c| c.is_ascii_digit())
            })
        {
            return Err(DraftError {
                reason: "draft source attachment part path was invalid".to_string(),
            });
        }
        if validated.iter().any(|existing| existing == &part_path) {
            return Err(DraftError {
                reason: "duplicate draft source attachment part path".to_string(),
            });
        }
        validated.push(part_path);
    }

    Ok(DraftSourceAttachments {
        mailbox_name: source.mailbox_name,
        uid: source.uid,
        version,
        part_paths: validated,
    })
}

fn serialize_draft_metadata(record: &DraftRecord) -> String {
    let mut content = format!(
        "version=9\n\
revision={}\n\
starred={}\n\
draft_id={}\n\
canonical_username_hex={}\n\
created_at={}\n\
updated_at={}\n\
expires_at={}\n\
to_hex={}\n\
cc_hex={}\n\
bcc_hex={}\n\
subject_hex={}\n\
body_hex={}\n\
body_format={}\n\
attachment_count={}\n",
        record.revision.unwrap_or(0),
        u8::from(record.starred),
        record.draft_id,
        hex_lower(record.canonical_username.as_bytes()),
        record.created_at,
        record.updated_at,
        record.expires_at,
        hex_lower(record.request.recipients_text.as_bytes()),
        hex_lower(record.request.cc_text.as_bytes()),
        hex_lower(record.request.bcc_text.as_bytes()),
        hex_lower(record.request.subject.as_bytes()),
        hex_lower(record.request.body.as_bytes()),
        record.request.body_format.as_str(),
        record.request.attachments.len()
    );

    if let Some(thread) = &record.request.reply_thread {
        content.push_str(&format!(
            "reply_parent_hex={}\nreply_references_hex={}\nreply_shortened={}\n",
            hex_lower(thread.in_reply_to().unwrap_or_default().as_bytes()),
            hex_lower(thread.references().as_bytes()),
            u8::from(thread.shortened())
        ));
    }
    for (index, attachment) in record.request.attachments.iter().enumerate() {
        content.push_str(&format!(
            "attachment_{index}_filename_hex={}\n\
attachment_{index}_content_type_hex={}\n\
attachment_{index}_size_bytes={}\n\
attachment_{index}_body_file={}\n",
            hex_lower(attachment.filename.as_bytes()),
            hex_lower(attachment.content_type.as_bytes()),
            attachment.size_bytes(),
            atomic::blob_name(&attachment.body)
        ));
    }

    if let Some(source) = &record.source_attachments {
        content.push_str(&format!(
            "source_mailbox_hex={}\nsource_uid={}\nsource_attachment_count={}\n",
            hex_lower(source.mailbox_name.as_bytes()),
            source.uid,
            source.part_paths.len(),
        ));
        for (index, part_path) in source.part_paths.iter().enumerate() {
            content.push_str(&format!(
                "source_attachment_{index}_part_path_hex={}\n",
                hex_lower(part_path.as_bytes())
            ));
        }
        if let Some(version) = &source.version {
            content.push_str(&format!(
                "source_mailbox_guid_hex={}\nsource_message_guid_hex={}\n",
                hex_lower(version.mailbox_guid.as_bytes()),
                hex_lower(version.message_guid.as_bytes())
            ));
        }
    } else {
        content.push_str("source_attachment_count=0\n");
    }

    content
}

fn parse_draft_metadata(
    policy: DraftPolicy,
    requested_canonical_username: &str,
    metadata_path: &Path,
    content: &str,
) -> Result<Option<DraftRecord>, DraftError> {
    let mut version = None;
    let mut revision = None;
    let mut starred = None;
    let mut draft_id = None;
    let mut canonical_username = None;
    let mut created_at = None;
    let mut updated_at = None;
    let mut expires_at = None;
    let mut recipients = None;
    let mut cc_recipients = None;
    let mut bcc_recipients = None;
    let mut subject = None;
    let mut body = None;
    let mut body_format = None;
    let mut attachment_count = None;
    let mut attachment_fields = Vec::<AttachmentMetadataFields>::new();
    let mut source_mailbox = None;
    let mut source_uid = None;
    let mut source_mailbox_guid = None;
    let mut source_message_guid = None;
    let mut source_attachment_count = None;
    let mut source_part_paths = Vec::<Option<String>>::new();
    let mut reply_parent = None;
    let mut reply_references = None;
    let mut reply_shortened = None;
    let mut seen_fields = std::collections::BTreeSet::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(DraftError {
                reason: "draft metadata line did not contain '='".to_string(),
            });
        };

        let canonical_key = if key == "recipients_hex" {
            "to_hex"
        } else {
            key
        };
        if !seen_fields.insert(canonical_key) {
            return Err(DraftError {
                reason: "duplicate draft metadata field".into(),
            });
        }
        match key {
            "version" => version = Some(value.to_string()),
            "revision" => revision = Some(parse_u64_field("revision", value)?),
            "starred" => {
                starred = Some(match value {
                    "0" => false,
                    "1" => true,
                    _ => {
                        return Err(DraftError {
                            reason: "invalid draft star state".into(),
                        })
                    }
                })
            }
            "draft_id" => draft_id = Some(value.to_string()),
            "canonical_username_hex" => canonical_username = Some(decode_hex_string(value)?),
            "created_at" => created_at = Some(parse_u64_field("created_at", value)?),
            "updated_at" => updated_at = Some(parse_u64_field("updated_at", value)?),
            "expires_at" => expires_at = Some(parse_u64_field("expires_at", value)?),
            "recipients_hex" => recipients = Some(decode_hex_string(value)?),
            "to_hex" => recipients = Some(decode_hex_string(value)?),
            "cc_hex" => cc_recipients = Some(decode_hex_string(value)?),
            "bcc_hex" => bcc_recipients = Some(decode_hex_string(value)?),
            "subject_hex" => subject = Some(decode_hex_string(value)?),
            "body_hex" => body = Some(decode_hex_string(value)?),
            "body_format" => {
                body_format = Some(crate::compose_format::BodyFormat::parse(value).ok_or_else(
                    || DraftError {
                        reason: "unsupported draft body format".into(),
                    },
                )?)
            }
            "reply_parent_hex" => reply_parent = Some(decode_hex_string(value)?),
            "reply_references_hex" => reply_references = Some(decode_hex_string(value)?),
            "reply_shortened" => {
                reply_shortened = Some(match value {
                    "0" => false,
                    "1" => true,
                    _ => {
                        return Err(DraftError {
                            reason: "invalid reply shortening metadata".into(),
                        })
                    }
                })
            }
            "attachment_count" => {
                attachment_count = Some(parse_usize_field("attachment_count", value)?)
            }
            "source_mailbox_hex" => source_mailbox = Some(decode_hex_string(value)?),
            "source_uid" => source_uid = Some(parse_u64_field("source_uid", value)?),
            "source_mailbox_guid_hex" => source_mailbox_guid = Some(decode_hex_string(value)?),
            "source_message_guid_hex" => source_message_guid = Some(decode_hex_string(value)?),
            "source_attachment_count" => {
                source_attachment_count = Some(parse_usize_field("source_attachment_count", value)?)
            }
            _ if key.starts_with("source_attachment_") => parse_source_attachment_metadata_field(
                key,
                value,
                &mut source_part_paths,
                policy.compose_policy.max_attachments,
            )?,
            _ if key.starts_with("attachment_") => parse_attachment_metadata_field(
                key,
                value,
                &mut attachment_fields,
                policy.compose_policy.max_attachments,
            )?,
            _ => {
                return Err(DraftError {
                    reason: format!("unsupported draft metadata key {key}"),
                })
            }
        }
    }

    if draft_id.is_none() {
        return Ok(None);
    }
    if !matches!(
        version.as_deref(),
        Some("1")
            | Some("2")
            | Some("3")
            | Some("4")
            | Some("5")
            | Some("6")
            | Some("7")
            | Some("8")
            | Some("9")
    ) {
        return Err(DraftError {
            reason: "unsupported draft metadata version".to_string(),
        });
    }

    let draft_id = required_field("draft_id", draft_id)?;
    let revision = match (version.as_deref(), revision) {
        (Some("5" | "6" | "7" | "8" | "9"), Some(value)) if value > 0 => value,
        (Some("1" | "2" | "3" | "4"), None) => 0,
        _ => {
            return Err(DraftError {
                reason: "invalid or incompatible draft revision".into(),
            })
        }
    };
    let starred = match (version.as_deref(), starred) {
        (Some("6" | "7" | "8" | "9"), Some(value)) => value,
        (Some("1" | "2" | "3" | "4" | "5"), None) => false,
        _ => {
            return Err(DraftError {
                reason: "invalid or incompatible draft star state".into(),
            })
        }
    };
    let body_format = match (version.as_deref(), body_format) {
        (Some("9"), Some(value)) => value,
        (Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8"), None) => {
            crate::compose_format::BodyFormat::Plain
        }
        _ => {
            return Err(DraftError {
                reason: "missing or incompatible draft body format".into(),
            })
        }
    };
    let reply_thread = match (reply_parent, reply_references, reply_shortened) {
        (None, None, None) => None,
        (Some(parent), Some(references), Some(shortened))
            if matches!(version.as_deref(), Some("4" | "5" | "6" | "7" | "8" | "9")) =>
        {
            Some(
                crate::reply_thread::ReplyThread::from_stored(
                    (!parent.is_empty()).then_some(parent.as_str()),
                    &references,
                    shortened,
                )
                .map_err(|_| DraftError {
                    reason: "invalid stored reply metadata".into(),
                })?,
            )
        }
        _ => {
            return Err(DraftError {
                reason: "incomplete or incompatible stored reply metadata".into(),
            })
        }
    };
    validate_draft_id(&draft_id)?;
    let canonical_username = required_field("canonical_username", canonical_username)?;
    validate_canonical_username(&canonical_username)?;
    if canonical_username != requested_canonical_username {
        return Ok(None);
    }

    let attachment_count = required_field("attachment_count", attachment_count)?;
    if attachment_count > policy.compose_policy.max_attachments
        || attachment_fields.len() != attachment_count
    {
        return Err(DraftError {
            reason: "draft attachment metadata exceeded maximum count".to_string(),
        });
    }
    let draft_dir = metadata_path.parent().ok_or_else(|| DraftError {
        reason: "draft metadata path did not have a parent directory".to_string(),
    })?;
    let directory_name = draft_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if directory_name != draft_id
        && atomic::legacy_backup_id(directory_name) != Some(draft_id.as_str())
    {
        return Err(DraftError {
            reason: "draft metadata identity does not match its directory".into(),
        });
    }
    let mut attachments = Vec::new();
    for (index, fields) in attachment_fields.into_iter().enumerate() {
        let filename = required_field("attachment filename", fields.filename)?;
        let content_type = required_field("attachment content type", fields.content_type)?;
        let size_bytes = required_field("attachment size", fields.size_bytes)?;
        let body_file = required_field("attachment body file", fields.body_file)?;
        let expected_body_file = attachment_body_file_name(index);
        if if matches!(version.as_deref(), Some("8" | "9")) {
            !atomic::is_blob_name(&body_file)
        } else {
            body_file != expected_body_file
        } {
            return Err(DraftError {
                reason: "draft attachment body file name was not generated".to_string(),
            });
        }

        let body_path = draft_dir.join(&body_file);
        if size_bytes > policy.compose_policy.attachment_max_bytes {
            return Err(DraftError {
                reason: "draft attachment exceeded maximum size".into(),
            });
        }
        let body = crate::private_account_file::read_record(&body_path, size_bytes)
            .map_err(|_| DraftError {
                reason: "draft attachment is unsafe or exceeded maximum size".into(),
            })?
            .ok_or_else(|| DraftError {
                reason: "draft attachment body missing".into(),
            })?;
        if body.len() != size_bytes {
            return Err(DraftError {
                reason: "draft attachment body size did not match metadata".to_string(),
            });
        }
        if matches!(version.as_deref(), Some("8" | "9")) && atomic::blob_name(&body) != body_file {
            return Err(DraftError {
                reason: "draft attachment content identity mismatch".into(),
            });
        }
        attachments.push(
            UploadedAttachment::new(policy.compose_policy, filename, content_type, body).map_err(
                |error| DraftError {
                    reason: error.reason,
                },
            )?,
        );
    }

    let mut request = DraftContent::new(
        policy.compose_policy,
        required_field("recipients", recipients)?,
        cc_recipients.unwrap_or_default(),
        bcc_recipients.unwrap_or_default(),
        required_field("subject", subject)?,
        required_field("body", body)?,
        attachments,
    )
    .map_err(|error| DraftError {
        reason: error.reason,
    })?;
    request.reply_thread = reply_thread;
    request.body_format = body_format;
    if !matches!(version.as_deref(), Some("5" | "6" | "7" | "8" | "9")) {
        crate::send::ComposeRequest::new_with_routing(
            policy.compose_policy,
            &request.recipients_text,
            &request.cc_text,
            &request.bcc_text,
            &request.subject,
            &request.body,
            Vec::new(),
        )
        .map_err(|error| DraftError {
            reason: error.reason,
        })?;
    }
    let source_version = match (source_mailbox_guid, source_message_guid) {
        (None, None) => None,
        (Some(mailbox), Some(message)) if matches!(version.as_deref(), Some("7" | "8" | "9")) => {
            Some(
                crate::message_metadata::MessageVersion::new(mailbox, message).map_err(|_| {
                    DraftError {
                        reason: "invalid stored source identity".into(),
                    }
                })?,
            )
        }
        _ => {
            return Err(DraftError {
                reason: "incomplete or incompatible stored source identity".into(),
            })
        }
    };
    let source_attachments = if version.as_deref() == Some("1") {
        None
    } else {
        let count = required_field("source_attachment_count", source_attachment_count)?;
        if count == 0 {
            if source_mailbox.is_some()
                || source_uid.is_some()
                || source_version.is_some()
                || !source_part_paths.is_empty()
            {
                return Err(DraftError {
                    reason: "draft source metadata was inconsistent".to_string(),
                });
            }
            None
        } else {
            if source_part_paths.len() != count {
                return Err(DraftError {
                    reason: "draft source attachment metadata count did not match".to_string(),
                });
            }
            let part_paths = source_part_paths
                .into_iter()
                .map(|part| required_field("source attachment part path", part))
                .collect::<Result<Vec<_>, _>>()?;
            Some(validate_source_attachments(
                policy,
                DraftSourceAttachments {
                    mailbox_name: required_field("source mailbox", source_mailbox)?,
                    uid: required_field("source UID", source_uid)?,
                    version: source_version,
                    part_paths,
                },
            )?)
        }
    };

    if matches!(version.as_deref(), Some("7" | "8" | "9")) {
        validate_combined_attachment_count(policy, &request, source_attachments.as_ref())?;
    }
    Ok(Some(DraftRecord {
        draft_id,
        canonical_username,
        created_at: required_field("created_at", created_at)?,
        updated_at: required_field("updated_at", updated_at)?,
        expires_at: required_field("expires_at", expires_at)?,
        revision: Some(revision),
        starred,
        request,
        source_attachments,
    }))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AttachmentMetadataFields {
    filename: Option<String>,
    content_type: Option<String>,
    size_bytes: Option<usize>,
    body_file: Option<String>,
}

fn parse_attachment_metadata_field(
    key: &str,
    value: &str,
    attachment_fields: &mut Vec<AttachmentMetadataFields>,
    max_count: usize,
) -> Result<(), DraftError> {
    let key = key.strip_prefix("attachment_").ok_or_else(|| DraftError {
        reason: "invalid attachment metadata key".to_string(),
    })?;
    let Some((index_text, field)) = key.split_once('_') else {
        return Err(DraftError {
            reason: "invalid attachment metadata key".to_string(),
        });
    };
    let index = parse_usize_field("attachment index", index_text)?;
    if index >= max_count || index.to_string() != index_text {
        return Err(DraftError {
            reason: "draft attachment index exceeded maximum or was invalid".into(),
        });
    }
    if attachment_fields.len() <= index {
        attachment_fields.resize_with(index + 1, AttachmentMetadataFields::default);
    }
    let metadata = &mut attachment_fields[index];
    match field {
        "filename_hex" => metadata.filename = Some(decode_hex_string(value)?),
        "content_type_hex" => metadata.content_type = Some(decode_hex_string(value)?),
        "size_bytes" => metadata.size_bytes = Some(parse_usize_field("attachment size", value)?),
        "body_file" => metadata.body_file = Some(value.to_string()),
        _ => {
            return Err(DraftError {
                reason: format!("unsupported attachment metadata field {field}"),
            })
        }
    }
    Ok(())
}

fn parse_source_attachment_metadata_field(
    key: &str,
    value: &str,
    part_paths: &mut Vec<Option<String>>,
    max_count: usize,
) -> Result<(), DraftError> {
    let key = key
        .strip_prefix("source_attachment_")
        .ok_or_else(|| DraftError {
            reason: "invalid source attachment metadata key".to_string(),
        })?;
    let Some((index_text, field)) = key.split_once('_') else {
        return Err(DraftError {
            reason: "invalid source attachment metadata key".to_string(),
        });
    };
    if field != "part_path_hex" {
        return Err(DraftError {
            reason: format!("unsupported source attachment metadata field {field}"),
        });
    }
    let index = parse_usize_field("source attachment index", index_text)?;
    if index >= max_count || index.to_string() != index_text {
        return Err(DraftError {
            reason: "draft source attachment index exceeded maximum or was invalid".into(),
        });
    }
    if part_paths.len() <= index {
        part_paths.resize(index + 1, None);
    }
    if part_paths[index].is_some() {
        return Err(DraftError {
            reason: "duplicate source attachment metadata field".to_string(),
        });
    }
    part_paths[index] = Some(decode_hex_string(value)?);
    Ok(())
}

fn parse_u64_field(field: &'static str, value: &str) -> Result<u64, DraftError> {
    value.parse::<u64>().map_err(|error| DraftError {
        reason: format!("failed parsing {field}: {error}"),
    })
}

fn parse_usize_field(field: &'static str, value: &str) -> Result<usize, DraftError> {
    value.parse::<usize>().map_err(|error| DraftError {
        reason: format!("failed parsing {field}: {error}"),
    })
}

fn required_field<T>(field: &'static str, value: Option<T>) -> Result<T, DraftError> {
    value.ok_or_else(|| DraftError {
        reason: format!("missing required draft field {field}"),
    })
}

fn owner_hash(canonical_username: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"osmap-draft-owner-v1");
    digest.update([0]);
    digest.update(canonical_username.as_bytes());
    hex_lower(&digest.finalize())
}

fn attachment_body_file_name(index: usize) -> String {
    format!("attachment-{index}.body")
}

fn remove_draft_dir(path: impl AsRef<Path>) -> Result<(), DraftError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(());
    }
    fs::remove_dir_all(path).map_err(|error| DraftError {
        reason: format!("failed to remove draft directory {:?}: {error}", path),
    })
}

fn write_file_atomic(tmp_path: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), DraftError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(tmp_path).map_err(|error| DraftError {
        reason: format!("failed to create draft temp file {:?}: {error}", tmp_path),
    })?;
    file.write_all(bytes).map_err(|error| DraftError {
        reason: format!("failed to write draft temp file {:?}: {error}", tmp_path),
    })?;
    set_file_permissions(tmp_path)?;
    file.sync_all().map_err(|error| DraftError {
        reason: format!("failed to sync draft temp file {:?}: {error}", tmp_path),
    })?;
    fs::rename(tmp_path, final_path).map_err(|error| DraftError {
        reason: format!("failed to finalize draft file {:?}: {error}", final_path),
    })
}

fn set_file_permissions(path: &Path) -> Result<(), DraftError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            DraftError {
                reason: format!("failed to set draft file permissions {:?}: {error}", path),
            }
        })?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), DraftError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => {
            return Err(DraftError {
                reason: "draft directory creation failed".into(),
            })
        }
    }
    crate::private_account_file::check_directory(path).map_err(|_| DraftError {
        reason: "draft directory is unsafe".into(),
    })?;
    Ok(())
}

fn private_directory_exists(path: &Path) -> Result<bool, DraftError> {
    match crate::private_account_file::check_directory(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(DraftError {
            reason: "draft directory is unsafe".into(),
        }),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{:02x}", byte));
    }
    encoded
}

fn decode_hex_string(value: &str) -> Result<String, DraftError> {
    let bytes = decode_hex_bytes(value)?;
    String::from_utf8(bytes).map_err(|error| DraftError {
        reason: format!("draft metadata field was not valid UTF-8: {error}"),
    })
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, DraftError> {
    if value.len() % 2 != 0 {
        return Err(DraftError {
            reason: "hex field length was not even".to_string(),
        });
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        output.push((hex_value(bytes[index])? << 4) | hex_value(bytes[index + 1])?);
        index += 2;
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Result<u8, DraftError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(DraftError {
            reason: "hex field contained invalid characters".to_string(),
        }),
    }
}

static NEXT_DRAFT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;
    mod preservation {
        include!("draft_preservation_tests.rs");
    }
    mod atomic_tests {
        include!("draft_atomic_tests.rs");
    }

    fn temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT_DRAFT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn draft_id(index: u8) -> String {
        format!("{index:032x}")
    }

    fn attachment(body: &[u8]) -> UploadedAttachment {
        UploadedAttachment::new(
            ComposePolicy::default(),
            "report.txt",
            "text/plain",
            body.to_vec(),
        )
        .expect("attachment should be valid")
    }

    fn input(
        id: &str,
        username: &str,
        now: u64,
        subject: &str,
        body: &str,
        attachments: Vec<UploadedAttachment>,
    ) -> DraftRecordInput {
        DraftRecordInput {
            draft_id: id.to_string(),
            canonical_username: username.to_string(),
            now,
            recipients_text: "bob@example.com".to_string(),
            cc_text: String::new(),
            bcc_text: String::new(),
            subject: subject.to_string(),
            body: body.to_string(),
            attachments,
            source_attachments: None,
        }
    }

    fn record(id: &str, username: &str, now: u64) -> DraftRecord {
        DraftRecord::new(
            DraftPolicy::default(),
            input(
                id,
                username,
                now,
                "Quarterly update",
                "Hello from a saved draft.",
                Vec::new(),
            ),
        )
        .expect("draft should be valid")
    }

    #[test]
    fn generate_draft_id_returns_lower_case_hex() {
        let generated = generate_draft_id().expect("draft id generation should succeed");
        assert_eq!(generated.len(), DRAFT_ID_HEX_LEN);
        assert!(generated
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }

    #[test]
    fn draft_record_reuses_compose_validation() {
        let error = DraftRecord::new(
            DraftPolicy::default(),
            input(
                &draft_id(1),
                "alice@example.com",
                10,
                "bad\nsubject",
                "body",
                Vec::new(),
            ),
        )
        .expect_err("compose subject validation should reject newlines");

        assert!(error.reason.contains("subject"));
    }

    #[test]
    fn formatted_draft_preserves_unfinished_notation_attachments_and_cas_star_edits() {
        use crate::compose_format::BodyFormat;
        let dir = temp_dir("osmap-draft-body-format");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let mut draft = record(&draft_id(29), "alice@example.com", 100);
        let unfinished = "**Unfinished formatting\n[link not finished](https://example.test/";
        draft.request.body = unfinished.into();
        draft.request.body_format = BodyFormat::Formatted;
        draft
            .request
            .attachments
            .push(attachment(b"synthetic attachment"));
        store.save(&draft, 100).unwrap();
        let mut loaded = store
            .load("alice@example.com", &draft.draft_id, 100)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.request, draft.request);
        let stale = loaded.clone();
        loaded.starred = true;
        store.save(&loaded, 101).unwrap();
        assert!(store.save(&stale, 102).is_err());
        let mut updated = store
            .load("alice@example.com", &draft.draft_id, 102)
            .unwrap()
            .unwrap();
        assert!(updated.starred);
        assert_eq!(updated.revision, Some(2));
        assert_eq!(updated.request.body, unfinished);
        assert_eq!(updated.request.body_format, BodyFormat::Formatted);
        assert_eq!(updated.request.attachments, draft.request.attachments);

        // V8 already used content-addressed attachment blobs, but no format mode.
        let path = store.metadata_path("alice@example.com", &draft.draft_id);
        let metadata = fs::read_to_string(&path).unwrap();
        let legacy = metadata
            .replace("version=9\n", "version=8\n")
            .replace("body_format=formatted\n", "");
        let v8 = parse_draft_metadata(DraftPolicy::default(), "alice@example.com", &path, &legacy)
            .unwrap()
            .unwrap();
        assert_eq!(v8.request.body_format, BodyFormat::Plain);
        assert_eq!(v8.request.body, unfinished);
        assert_eq!(v8.request.attachments, updated.request.attachments);

        updated.request.body_format = BodyFormat::Plain;
        store.save(&updated, 103).unwrap();
        let plain = store
            .load("alice@example.com", &draft.draft_id, 103)
            .unwrap()
            .unwrap();
        assert_eq!(plain.request.body_format, BodyFormat::Plain);
        assert_eq!(plain.request.body, unfinished);
        assert_eq!(plain.request.attachments, updated.request.attachments);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_draft_versions_read_as_plain_and_body_format_metadata_is_strict() {
        use crate::compose_format::BodyFormat;
        let dir = temp_dir("osmap-draft-legacy-body-format");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let mut draft = record(&draft_id(30), "alice@example.com", 100);
        draft.request.body = "**This remains literal legacy text [unfinished".into();
        assert_eq!(draft.request.body_format, BodyFormat::Plain);
        store.save(&draft, 100).unwrap();
        let path = store.metadata_path("alice@example.com", &draft.draft_id);
        let metadata = fs::read_to_string(&path).unwrap();
        let parse = |value: &str| {
            parse_draft_metadata(DraftPolicy::default(), "alice@example.com", &path, value)
        };
        assert!(metadata.starts_with("version=9\n"));
        assert!(metadata.contains("\nbody_format=plain\n"));
        for version in 1..=8 {
            let mut legacy = metadata
                .replace("version=9\n", &format!("version={version}\n"))
                .replace("body_format=plain\n", "");
            if version < 5 {
                legacy = legacy.replace("revision=1\n", "");
            }
            if version < 6 {
                legacy = legacy.replace("starred=0\n", "");
            }
            let loaded = parse(&legacy).unwrap().unwrap();
            assert_eq!(
                loaded.request.body_format,
                BodyFormat::Plain,
                "version {version}"
            );
            assert_eq!(loaded.request.body, draft.request.body, "version {version}");
        }
        for invalid in [
            metadata.replace("body_format=plain\n", ""),
            metadata.replace("body_format=plain", "body_format=unknown"),
            metadata.replace("body_format=plain", "body_format=Formatted"),
            metadata.replace("version=9\n", "version=8\n"),
            metadata.replace("version=9\n", "version=10\n"),
            format!("{metadata}body_format=plain\n"),
        ] {
            assert!(parse(&invalid).is_err());
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), metadata);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn draft_reply_metadata_survives_storage_and_refuses_corrupt_or_downgraded_fields() {
        let dir = temp_dir("osmap-draft-reply-thread");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let mut draft = record(&draft_id(28), "alice@example.com", 100);
        draft.request.reply_thread = Some(
            crate::reply_thread::ReplyThread::from_original(
                "Message-ID: <parent@example.test>\nReferences: <root@example.test>\n",
            )
            .unwrap(),
        );
        store.save(&draft, 100).unwrap();
        draft.revision = Some(1);
        assert_eq!(
            store
                .load("alice@example.com", &draft.draft_id, 100)
                .unwrap()
                .unwrap(),
            draft
        );
        let path = store.metadata_path("alice@example.com", &draft.draft_id);
        let metadata = fs::read_to_string(&path).unwrap();
        let parse = |value: &str| {
            parse_draft_metadata(DraftPolicy::default(), "alice@example.com", &path, value)
        };
        assert!(parse(
            &metadata
                .replace("version=9", "version=3")
                .replace("body_format=plain\n", "")
                .replace("starred=0\n", "")
                .replace("revision=1\n", "")
        )
        .is_err());
        assert!(parse(&format!("{metadata}reply_shortened=0\n")).is_err());
        assert!(parse(&metadata.replace("reply_shortened=0\n", "")).is_err());
        assert!(parse(&metadata.replace("reply_shortened=0", "reply_shortened=2")).is_err());
        assert!(parse(&metadata.replace(
            &hex_lower(b"<parent@example.test>"),
            &hex_lower(b"<parent@example.test>\r\nBcc: hidden@example.test")
        ))
        .is_err());
        assert!(parse(&format!(
            "{metadata}recipients_hex={}\n",
            hex_lower(b"changed@example.test")
        ))
        .is_err());
        draft.request.reply_thread = None;
        let legacy = serialize_draft_metadata(&draft)
            .replace("version=9", "version=3")
            .replace("body_format=plain\n", "")
            .replace("starred=0\n", "")
            .replace("revision=1\n", "");
        draft.revision = Some(0);
        assert_eq!(parse(&legacy).unwrap().unwrap(), draft);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            metadata,
            "invalid reads never alter the saved draft"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn file_draft_store_round_trips_text_and_attachments() {
        let dir = temp_dir("osmap-draft-round-trip");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let draft = DraftRecord::new(
            DraftPolicy::default(),
            DraftRecordInput {
                cc_text: "carol@example.net".to_string(),
                bcc_text: "dana@example.org".to_string(),
                ..input(
                    &draft_id(2),
                    "alice@example.com",
                    100,
                    "Quarterly update",
                    "Hello\nsaved draft",
                    vec![attachment(b"attachment bytes")],
                )
            },
        )
        .expect("draft should be valid");

        store.save(&draft, 100).expect("save should succeed");
        let loaded = store
            .load("alice@example.com", &draft.draft_id, 100)
            .expect("load should succeed")
            .expect("draft should exist");

        assert_eq!(
            loaded,
            DraftRecord {
                revision: Some(1),
                ..draft
            }
        );
        assert_eq!(loaded.request.cc_text, "carol@example.net");
        assert_eq!(loaded.request.bcc_text, "dana@example.org");
        assert_eq!(loaded.request.attachments[0].body, b"attachment bytes");
    }

    #[test]
    fn file_draft_store_round_trips_only_explicit_source_attachment_references() {
        let dir = temp_dir("osmap-draft-source-reference");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let mut draft = record(&draft_id(12), "alice@example.com", 100);
        draft.source_attachments = Some(DraftSourceAttachments {
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            version: None,
            part_paths: vec!["1.2".to_string()],
        });

        store.save(&draft, 100).expect("save should succeed");
        let loaded = store
            .load("alice@example.com", &draft.draft_id, 100)
            .expect("load should succeed")
            .expect("draft should exist");
        let metadata =
            fs::read_to_string(store.metadata_path("alice@example.com", &draft.draft_id))
                .expect("metadata should be readable");

        assert_eq!(loaded.source_attachments, draft.source_attachments);
        assert_eq!(loaded.summary().attachment_count, 1);
        assert!(metadata.contains("source_attachment_count=1"));
        assert!(!metadata.contains("attachment bytes"));
        assert!(!metadata.contains("%PDF"));
        assert!(!metadata.contains("Content-Type:"));
    }

    #[test]
    fn source_attachment_metadata_rejects_duplicates_controls_and_oversized_fields() {
        let base = input(
            &draft_id(13),
            "alice@example.com",
            100,
            "Subject",
            "Body",
            Vec::new(),
        );
        let mut duplicate = base.clone();
        duplicate.source_attachments = Some(DraftSourceAttachments {
            mailbox_name: "INBOX".to_string(),
            uid: 9,
            version: None,
            part_paths: vec!["1.2".to_string(), "1.2".to_string()],
        });
        assert!(DraftRecord::new(DraftPolicy::default(), duplicate)
            .expect_err("duplicate source parts must fail")
            .reason
            .contains("duplicate"));

        let mut control = base.clone();
        control.source_attachments = Some(DraftSourceAttachments {
            mailbox_name: "INBOX\nJunk".to_string(),
            uid: 9,
            version: None,
            part_paths: vec!["1.2".to_string()],
        });
        assert!(DraftRecord::new(DraftPolicy::default(), control)
            .expect_err("control characters must fail")
            .reason
            .contains("control"));

        let mut oversized = base;
        oversized.source_attachments = Some(DraftSourceAttachments {
            mailbox_name: "M".repeat(DEFAULT_DRAFT_SOURCE_MAILBOX_MAX_LEN + 1),
            uid: 9,
            version: None,
            part_paths: vec!["1.2".to_string()],
        });
        assert!(DraftRecord::new(DraftPolicy::default(), oversized)
            .expect_err("oversized source mailbox must fail")
            .reason
            .contains("maximum"));
    }

    #[test]
    fn file_draft_store_scopes_loads_by_owner() {
        let dir = temp_dir("osmap-draft-owner");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let draft = record(&draft_id(3), "alice@example.com", 100);

        store.save(&draft, 100).expect("save should succeed");

        assert!(store
            .load("bob@example.com", &draft.draft_id, 100)
            .expect("cross-owner load should not fail")
            .is_none());
    }

    #[test]
    fn file_draft_store_list_is_redacted_and_sorted() {
        let dir = temp_dir("osmap-draft-list");
        let policy = DraftPolicy {
            max_summary_rows: 1,
            ..DraftPolicy::default()
        };
        let store = FileDraftStore::new(&dir, policy);
        let first = record(&draft_id(4), "alice@example.com", 100);
        let second = record(&draft_id(5), "alice@example.com", 200);

        store.save(&first, 100).expect("first save should succeed");
        store
            .save(&second, 200)
            .expect("second save should succeed");

        let summaries = store
            .list("alice@example.com", 200)
            .expect("list should succeed");

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].draft_id, second.draft_id);
        assert_eq!(summaries[0].body_len, "Hello from a saved draft.".len());
        assert_eq!(summaries[0].attachment_count, 0);
    }

    #[test]
    fn file_draft_store_deletes_draft_directory_and_attachment_bodies() {
        let dir = temp_dir("osmap-draft-delete");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let draft = DraftRecord::new(
            DraftPolicy::default(),
            input(
                &draft_id(6),
                "alice@example.com",
                100,
                "Subject",
                "Body",
                vec![attachment(b"delete me")],
            ),
        )
        .expect("draft should be valid");

        store.save(&draft, 100).expect("save should succeed");
        let draft_dir = store.draft_dir_for_username_and_id("alice@example.com", &draft.draft_id);
        assert!(draft_dir.exists());

        assert!(store
            .delete("alice@example.com", &draft.draft_id, 1)
            .expect("delete should succeed"));
        assert!(!draft_dir.exists());
    }

    #[test]
    fn expired_drafts_are_removed_on_load() {
        let dir = temp_dir("osmap-draft-expired");
        let policy = DraftPolicy {
            max_age_seconds: 10,
            ..DraftPolicy::default()
        };
        let store = FileDraftStore::new(&dir, policy);
        let draft = DraftRecord::new(
            policy,
            input(
                &draft_id(7),
                "alice@example.com",
                100,
                "Subject",
                "Body",
                Vec::new(),
            ),
        )
        .expect("draft should be valid");

        store.save(&draft, 100).expect("save should succeed");
        assert!(store
            .load("alice@example.com", &draft.draft_id, 111)
            .expect("expired load should not fail")
            .is_none());
        assert!(!store
            .draft_dir_for_username_and_id("alice@example.com", &draft.draft_id)
            .exists());
    }

    #[test]
    fn quota_rejects_new_draft_but_allows_update() {
        let dir = temp_dir("osmap-draft-quota");
        let policy = DraftPolicy {
            max_drafts_per_user: 1,
            ..DraftPolicy::default()
        };
        let store = FileDraftStore::new(&dir, policy);
        let mut first = record(&draft_id(8), "alice@example.com", 100);
        let second = record(&draft_id(9), "alice@example.com", 100);

        store.save(&first, 100).expect("first save should succeed");
        let error = store
            .save(&second, 100)
            .expect_err("new draft over quota should fail");
        assert!(error.reason.contains("quota"));

        first = store
            .load("alice@example.com", &first.draft_id, 101)
            .unwrap()
            .unwrap();
        first.updated_at = 101;
        first.request.body = "updated body".to_string();
        store
            .save(&first, 101)
            .expect("updating existing draft should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_saves_cannot_exceed_the_per_user_quota() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = temp_dir("osmap-draft-concurrent-quota");
        let store = Arc::new(FileDraftStore::new(
            &dir,
            DraftPolicy {
                max_drafts_per_user: 1,
                ..DraftPolicy::default()
            },
        ));
        let barrier = Arc::new(Barrier::new(3));
        let records = [
            record(&draft_id(20), "alice@example.com", 100),
            record(&draft_id(21), "alice@example.com", 100),
        ];
        let mut workers = Vec::new();
        for record in records {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                store.save(&record, 100)
            }));
        }
        barrier.wait();

        let successful = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker should join"))
            .filter(Result::is_ok)
            .count();
        let listed = store
            .list("alice@example.com", 100)
            .expect("draft list should remain readable");

        assert_eq!(successful, 1);
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn metadata_rejects_non_generated_attachment_body_file() {
        let dir = temp_dir("osmap-draft-bad-body-file");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let draft = DraftRecord::new(
            DraftPolicy::default(),
            input(
                &draft_id(10),
                "alice@example.com",
                100,
                "Subject",
                "Body",
                vec![attachment(b"body")],
            ),
        )
        .expect("draft should be valid");

        store.save(&draft, 100).expect("save should succeed");
        let metadata_path = store.metadata_path("alice@example.com", &draft.draft_id);
        let mut metadata = fs::read_to_string(&metadata_path).expect("metadata should be readable");
        metadata = metadata.replace(
            &format!("attachment_0_body_file={}", atomic::blob_name(b"body")),
            "attachment_0_body_file=../attachment-0.body",
        );
        fs::write(&metadata_path, metadata).expect("metadata fixture should be writable");

        let error = store
            .load("alice@example.com", &draft.draft_id, 100)
            .expect_err("path-like attachment body file should fail");
        assert!(error.reason.contains("body file name"));
    }

    #[cfg(unix)]
    #[test]
    fn file_draft_store_uses_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("osmap-draft-permissions");
        let store = FileDraftStore::new(&dir, DraftPolicy::default());
        let draft = record(&draft_id(11), "alice@example.com", 100);

        store.save(&draft, 100).expect("save should succeed");
        let owner_dir = store.owner_dir_for_username("alice@example.com");
        let draft_dir = store.draft_dir_for_username_and_id("alice@example.com", &draft.draft_id);
        let metadata_path = store.metadata_path("alice@example.com", &draft.draft_id);

        assert_eq!(
            fs::metadata(owner_dir)
                .expect("owner dir metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(draft_dir)
                .expect("draft dir metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(metadata_path)
                .expect("metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn documented_default_caps_match_compose_policy_defaults() {
        use crate::send::{
            DEFAULT_ATTACHMENT_MAX_BYTES, DEFAULT_BODY_MAX_LEN, DEFAULT_MAX_ATTACHMENTS,
            DEFAULT_MAX_RECIPIENTS, DEFAULT_RECIPIENT_MAX_LEN, DEFAULT_SUBJECT_MAX_LEN,
            DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES,
        };

        let policy = DraftPolicy::default().compose_policy;
        assert_eq!(policy.max_recipients, DEFAULT_MAX_RECIPIENTS);
        assert_eq!(policy.recipient_max_len, DEFAULT_RECIPIENT_MAX_LEN);
        assert_eq!(policy.subject_max_len, DEFAULT_SUBJECT_MAX_LEN);
        assert_eq!(policy.body_max_len, DEFAULT_BODY_MAX_LEN);
        assert_eq!(policy.max_attachments, DEFAULT_MAX_ATTACHMENTS);
        assert_eq!(policy.attachment_max_bytes, DEFAULT_ATTACHMENT_MAX_BYTES);
        assert_eq!(
            policy.total_attachment_max_bytes,
            DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES
        );
    }
}
