//! Account-private explicit public-key bindings and delivery policy. Inventory
//! presence is capability, not identity trust. Only the trusted helper/operator
//! update boundary may persist bindings; HTTP step-up is supplied separately.
use crate::identity::CanonicalUsername;
use crate::openpgp_crypto::{full_fingerprint, MAX_RECIPIENTS};
use crate::openpgp_inventory::{Inventory, KeyMaterial, PublicKey};
use crate::private_account_file::PrivateAccountFile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

pub const MAX_BINDINGS: usize = 200;
const MAX_DECRYPT_KEYS: usize = 8;
const MAX_RECORD: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    Required,
    #[default]
    Optional,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProtectionPolicy {
    pub signing: Requirement,
    pub encryption: Requirement,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBinding {
    pub primary_fingerprint: String,
    pub signing_fingerprint: Option<String>,
    pub decrypt_primary_fingerprints: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientBinding {
    pub address: String,
    pub primary_fingerprint: String,
    pub encryption: Requirement,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRecord {
    version: u8,
    canonical_username: String,
    pub revision: u64,
    pub account_binding: Option<AccountBinding>,
    pub recipient_bindings: Vec<RecipientBinding>,
    pub policy: ProtectionPolicy,
}
impl std::fmt::Debug for BindingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindingRecord")
            .field("revision", &self.revision)
            .field("recipient_count", &self.recipient_bindings.len())
            .field("account_binding_present", &self.account_binding.is_some())
            .finish()
    }
}
/// Replacement values. Its caller supplies real operator/helper authority; there
/// is intentionally no caller-selected `confirmed` or `step_up_passed` flag.
#[derive(Clone)]
pub struct Update {
    pub account_binding: Option<AccountBinding>,
    pub recipient_bindings: Vec<RecipientBinding>,
    pub policy: ProtectionPolicy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    Invalid,
    Quota,
    Duplicate,
    ForeignAccount,
    Stale,
    Busy,
    Unavailable,
    Unconfirmed,
    InvalidKey,
}
impl From<std::io::Error> for BindingError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            Self::Busy
        } else {
            Self::Unavailable
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Ready,
    MissingBinding,
    InventoryUnavailable,
    MissingKey,
    Revoked,
    Expired,
    Invalid,
    Unsupported,
    WrongUsage,
    Ambiguous,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Selections {
    pub sign: bool,
    pub encrypt: bool,
    pub encrypt_to_self: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightState {
    Green,
    Orange,
    Blocked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    SigningRequired,
    SigningDisabled,
    SigningUnavailable,
    EncryptionRequired,
    EncryptionDisabled,
    RecipientRequiresEncryption,
    RecipientForbidsEncryption,
    RecipientKeyUnavailable,
    SelfRequiresEncryption,
    SelfKeyUnavailable,
    EncryptedBccUnqualified,
}
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientReadiness {
    pub address: String,
    pub state: KeyStatus,
    pub requirement: Requirement,
}
#[derive(Clone, PartialEq, Eq)]
pub struct OperationPlan {
    pub signer_fingerprint: Option<String>,
    pub recipient_fingerprints: Vec<String>,
    pub encrypt_to_self: bool,
}
#[derive(Clone, PartialEq, Eq)]
pub struct Preflight {
    pub revision: u64,
    pub state: PreflightState,
    pub signing: KeyStatus,
    pub self_encryption: KeyStatus,
    pub recipients: Vec<RecipientReadiness>,
    pub reasons: Vec<BlockReason>,
    pub plan: Option<OperationPlan>,
}
pub struct Recipients<'a> {
    pub to: &'a [String],
    pub cc: &'a [String],
    pub bcc: &'a [String],
}

impl BindingRecord {
    pub fn empty(account: &str) -> Result<Self, BindingError> {
        CanonicalUsername::parse(account).map_err(|_| BindingError::Invalid)?;
        Ok(Self {
            version: 1,
            canonical_username: account.into(),
            revision: 0,
            account_binding: None,
            recipient_bindings: Vec::new(),
            policy: ProtectionPolicy::default(),
        })
    }
    pub fn ensure_account(&self, account: &str) -> Result<(), BindingError> {
        CanonicalUsername::parse(account).map_err(|_| BindingError::Invalid)?;
        if self.canonical_username != account {
            return Err(BindingError::ForeignAccount);
        }
        if self.version != 1 {
            return Err(BindingError::Invalid);
        }
        if self.recipient_bindings.len() > MAX_BINDINGS {
            return Err(BindingError::Quota);
        }
        if self.revision == 0
            && (self.account_binding.is_some()
                || !self.recipient_bindings.is_empty()
                || self.policy != ProtectionPolicy::default())
        {
            return Err(BindingError::Invalid);
        }
        if let Some(b) = &self.account_binding {
            if !full_fingerprint(&b.primary_fingerprint)
                || b.signing_fingerprint
                    .as_deref()
                    .is_some_and(|s| !full_fingerprint(s))
                || b.decrypt_primary_fingerprints.len() > MAX_DECRYPT_KEYS
                || b.decrypt_primary_fingerprints
                    .iter()
                    .any(|s| !full_fingerprint(s))
            {
                return Err(BindingError::Invalid);
            }
            if b.decrypt_primary_fingerprints
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != b.decrypt_primary_fingerprints.len()
            {
                return Err(BindingError::Duplicate);
            }
        }
        let mut addresses = BTreeSet::new();
        for b in &self.recipient_bindings {
            address(&b.address)?;
            if !full_fingerprint(&b.primary_fingerprint) {
                return Err(BindingError::Invalid);
            }
            if !addresses.insert(crate::mail_address::comparison_key(&b.address)) {
                return Err(BindingError::Duplicate);
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct BindingStore {
    file: PrivateAccountFile,
}
impl BindingStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(
                directory.into(),
                "osmap-openpgp-bindings-v1",
                MAX_RECORD,
            ),
        }
    }
    pub fn load(&self, account: &str) -> Result<BindingRecord, BindingError> {
        CanonicalUsername::parse(account).map_err(|_| BindingError::Invalid)?;
        decode(account, self.file.read(account)?)
    }
    /// Serialize final protected-send dispatch or a helper-side public-key
    /// mutation with every binding writer. The caller must hold a bounded
    /// operation; public-key mutation additionally requires fresh authority.
    pub(crate) fn with_locked_revision<T>(
        &self,
        account: &str,
        expected_revision: u64,
        operation: impl FnOnce(&BindingRecord) -> Result<T, BindingError>,
    ) -> Result<T, BindingError> {
        CanonicalUsername::parse(account).map_err(|_| BindingError::Invalid)?;
        let locked = self.file.lock(account)?;
        let record = decode(account, locked.read()?)?;
        if record.revision != expected_revision {
            return Err(BindingError::Stale);
        }
        let outcome = operation(&record);
        drop(locked);
        outcome
    }
    /// Must be invoked by the operator or an authenticated narrow helper after
    /// real fresh password/TOTP confirmation. Never exposes a web auth shortcut.
    /// Operator/helper entry point, not a browser authorization decision. The
    /// caller must independently authenticate inventory and mutation authority;
    /// this store never accepts a form's assertion that step-up was completed.
    pub fn replace_operator(
        &self,
        account: &str,
        expected_revision: u64,
        update: Update,
        inventory: &Inventory,
        now: u64,
    ) -> Result<BindingRecord, BindingError> {
        CanonicalUsername::parse(account).map_err(|_| BindingError::Invalid)?;
        let locked = self.file.lock(account)?;
        let old = decode(account, locked.read()?)?;
        if old.revision != expected_revision {
            return Err(BindingError::Stale);
        }
        let mut record = BindingRecord {
            version: 1,
            canonical_username: account.into(),
            revision: old
                .revision
                .checked_add(1)
                .ok_or(BindingError::Unavailable)?,
            account_binding: update.account_binding,
            recipient_bindings: update.recipient_bindings,
            policy: update.policy,
        };
        record.ensure_account(account)?;
        if now == 0 || now > 253402300799 {
            return Err(BindingError::Invalid);
        }
        if let Some(binding) = &record.account_binding {
            let key = primary(inventory, &binding.primary_fingerprint)
                .map_err(|_| BindingError::InvalidKey)?;
            material(&key.primary, now).map_err(|_| BindingError::InvalidKey)?;
            if let Some(signing) = &binding.signing_fingerprint {
                signer(inventory, &binding.primary_fingerprint, signing, now)
                    .map_err(|_| BindingError::InvalidKey)?;
            }
            for fingerprint in &binding.decrypt_primary_fingerprints {
                encryption(inventory, fingerprint, now).map_err(|_| BindingError::InvalidKey)?;
            }
        }
        for binding in &record.recipient_bindings {
            encryption(inventory, &binding.primary_fingerprint, now)
                .map_err(|_| BindingError::InvalidKey)?;
        }
        // Persist in a stable order independent of arbitrary form order.
        record
            .recipient_bindings
            .sort_by_key(|b| crate::mail_address::comparison_key(&b.address));
        if let Some(binding) = record.account_binding.as_mut() {
            binding.decrypt_primary_fingerprints.sort();
        }
        let bytes = serde_json::to_vec(&record).map_err(|_| BindingError::Unavailable)?;
        locked
            .write(&bytes)
            .map_err(|_| BindingError::Unconfirmed)?;
        Ok(record)
    }
}
fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<BindingRecord, BindingError> {
    let Some(bytes) = bytes else {
        return BindingRecord::empty(account);
    };
    let record: BindingRecord =
        serde_json::from_slice(&bytes).map_err(|_| BindingError::Unavailable)?;
    if record.revision == 0 {
        return Err(BindingError::Invalid);
    }
    record.ensure_account(account)?;
    Ok(record)
}
fn address(value: &str) -> Result<(), BindingError> {
    crate::mail_address::validate_address(crate::send::ComposePolicy::default(), value)
        .map_err(|_| BindingError::Invalid)
}
fn primary<'a>(inventory: &'a Inventory, fingerprint: &str) -> Result<&'a PublicKey, KeyStatus> {
    inventory
        .keys()
        .ok_or(KeyStatus::InventoryUnavailable)?
        .iter()
        .find(|k| k.primary.fingerprint == fingerprint)
        .ok_or(KeyStatus::MissingKey)
}
fn material(key: &KeyMaterial, now: u64) -> Result<(), KeyStatus> {
    if key.fingerprint.len() != 40 {
        return Err(KeyStatus::Unsupported);
    }
    if key.revoked {
        return Err(KeyStatus::Revoked);
    }
    if key.expired || key.expires != 0 && key.expires <= now {
        return Err(KeyStatus::Expired);
    }
    if key.invalid || key.disabled || key.created > now {
        return Err(KeyStatus::Invalid);
    }
    let supported = match key.algorithm {
        1..=3 => key.bits >= 3072,
        303 => key.curve.as_deref() == Some("ed25519"),
        // Inventory carries GPGME algorithm identifiers (ECDH=302), not the
        // OpenPGP packet algorithm number 18.
        302 => key.curve.as_deref() == Some("cv25519"),
        _ => false,
    };
    if !supported {
        return Err(KeyStatus::Unsupported);
    }
    Ok(())
}
fn signer(
    inventory: &Inventory,
    primary_fp: &str,
    signing_fp: &str,
    now: u64,
) -> Result<(), KeyStatus> {
    let key = primary(inventory, primary_fp)?;
    material(&key.primary, now)?;
    let selected = std::iter::once(&key.primary)
        .chain(&key.subkeys)
        .find(|m| m.fingerprint == signing_fp)
        .ok_or(KeyStatus::MissingKey)?;
    material(selected, now)?;
    if !selected.can_sign {
        return Err(KeyStatus::WrongUsage);
    }
    if !matches!(selected.algorithm, 1 | 3 | 303) {
        return Err(KeyStatus::Unsupported);
    }
    // An exact subkey binding resolves multiple signing-capable choices. No
    // search for a replacement signer is permitted if this one becomes invalid.
    Ok(())
}
fn encryption(inventory: &Inventory, primary_fp: &str, now: u64) -> Result<(), KeyStatus> {
    let key = primary(inventory, primary_fp)?;
    material(&key.primary, now)?;
    let mut capable = 0;
    for subkey in std::iter::once(&key.primary).chain(&key.subkeys) {
        if !subkey.can_encrypt
            || subkey.revoked
            || subkey.expired
            || subkey.disabled
            || subkey.invalid
            || subkey.expires != 0 && subkey.expires <= now
        {
            continue;
        }
        material(subkey, now)?;
        if !matches!(subkey.algorithm, 1 | 2 | 302) {
            return Err(KeyStatus::Unsupported);
        }
        capable += 1;
    }
    match capable {
        0 => Err(KeyStatus::WrongUsage),
        1 => Ok(()),
        _ => Err(KeyStatus::Ambiguous),
    }
}
fn status(result: Result<(), KeyStatus>) -> KeyStatus {
    result.err().unwrap_or(KeyStatus::Ready)
}

/// Reevaluate immediately before crypto/submission using freshly authenticated
/// inventory. A blocked result never contains a usable operation plan.
pub fn evaluate(
    account: &str,
    record: &BindingRecord,
    inventory: &Inventory,
    recipients: Recipients<'_>,
    selection: Selections,
    now: u64,
) -> Result<Preflight, BindingError> {
    record.ensure_account(account)?;
    if now == 0 || now > 253402300799 {
        return Err(BindingError::Invalid);
    }
    let all: Vec<_> = recipients
        .to
        .iter()
        .chain(recipients.cc)
        .chain(recipients.bcc)
        .collect();
    if all.is_empty() || all.len() > MAX_RECIPIENTS {
        return Err(BindingError::Quota);
    }
    for recipient in &all {
        address(recipient)?;
    }
    let signing = match &record.account_binding {
        Some(binding) => binding
            .signing_fingerprint
            .as_deref()
            .map(|fp| status(signer(inventory, &binding.primary_fingerprint, fp, now)))
            .unwrap_or(KeyStatus::MissingBinding),
        None => KeyStatus::MissingBinding,
    };
    let self_encryption = record
        .account_binding
        .as_ref()
        .map(|b| status(encryption(inventory, &b.primary_fingerprint, now)))
        .unwrap_or(KeyStatus::MissingBinding);
    let mut readiness = Vec::new();
    let mut reasons = Vec::new();
    let mut recipient_fingerprints = BTreeSet::new();
    let mut seen_addresses = BTreeSet::new();
    for recipient in all {
        let compare = crate::mail_address::comparison_key(recipient);
        if !seen_addresses.insert(compare.clone()) {
            continue;
        }
        let binding = record
            .recipient_bindings
            .iter()
            .find(|b| crate::mail_address::comparison_key(&b.address) == compare);
        let requirement = binding.map(|b| b.encryption).unwrap_or_default();
        let state = binding
            .map(|b| status(encryption(inventory, &b.primary_fingerprint, now)))
            .unwrap_or(KeyStatus::MissingBinding);
        if requirement == Requirement::Required && !selection.encrypt {
            reasons.push(BlockReason::RecipientRequiresEncryption);
        }
        if requirement == Requirement::Disabled && selection.encrypt {
            reasons.push(BlockReason::RecipientForbidsEncryption);
        }
        if selection.encrypt {
            if state != KeyStatus::Ready {
                reasons.push(BlockReason::RecipientKeyUnavailable);
            } else if let Some(binding) = binding {
                recipient_fingerprints.insert(binding.primary_fingerprint.clone());
            }
        }
        readiness.push(RecipientReadiness {
            address: recipient.clone(),
            state,
            requirement,
        });
    }
    for (requirement, chosen, required, disabled) in [
        (
            record.policy.signing,
            selection.sign,
            BlockReason::SigningRequired,
            BlockReason::SigningDisabled,
        ),
        (
            record.policy.encryption,
            selection.encrypt,
            BlockReason::EncryptionRequired,
            BlockReason::EncryptionDisabled,
        ),
    ] {
        if requirement == Requirement::Required && !chosen {
            reasons.push(required);
        }
        if requirement == Requirement::Disabled && chosen {
            reasons.push(disabled);
        }
    }
    if selection.sign && signing != KeyStatus::Ready {
        reasons.push(BlockReason::SigningUnavailable);
    }
    if selection.encrypt && !recipients.bcc.is_empty() {
        reasons.push(BlockReason::EncryptedBccUnqualified);
    }
    if selection.encrypt_to_self {
        if !selection.encrypt {
            reasons.push(BlockReason::SelfRequiresEncryption);
        }
        if self_encryption != KeyStatus::Ready {
            reasons.push(BlockReason::SelfKeyUnavailable);
        } else if let Some(binding) = &record.account_binding {
            recipient_fingerprints.insert(binding.primary_fingerprint.clone());
        }
    }
    if recipient_fingerprints.len() > MAX_RECIPIENTS {
        return Err(BindingError::Quota);
    }
    let (state, plan) = if reasons.is_empty() {
        let signer_fingerprint = if selection.sign {
            record
                .account_binding
                .as_ref()
                .and_then(|b| b.signing_fingerprint.clone())
        } else {
            None
        };
        (
            if selection.sign && selection.encrypt {
                PreflightState::Green
            } else {
                PreflightState::Orange
            },
            Some(OperationPlan {
                signer_fingerprint,
                recipient_fingerprints: recipient_fingerprints.into_iter().collect(),
                encrypt_to_self: selection.encrypt_to_self,
            }),
        )
    } else {
        (PreflightState::Blocked, None)
    };
    Ok(Preflight {
        revision: record.revision,
        state,
        signing,
        self_encryption,
        recipients: readiness,
        reasons,
        plan,
    })
}

#[cfg(test)]
#[path = "openpgp_bindings_tests.rs"]
mod tests;
