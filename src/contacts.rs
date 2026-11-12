//! Explicit account-private address shortcuts; no harvesting or trust inference.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::private_account_file::PrivateAccountFile;

pub const MAX_CONTACTS: usize = 200;
pub const MAX_DISPLAY_NAME_BYTES: usize = 100;
const MAX_BOOK_BYTES: usize = 128 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub id: String,
    pub display_name: String,
    pub address: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactBook {
    version: u8,
    canonical_username: String,
    pub revision: u64,
    pub contacts: Vec<Contact>,
}

/// Read-only recipient shortcuts from the current imported public inventory.
/// These opaque handles carry no contact revision or authentication authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedRecipientChoice {
    pub id: String,
    pub address: String,
    primary_fingerprint: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ImportedRecipientSnapshot {
    canonical_username: String,
    pub choices: Vec<ImportedRecipientChoice>,
}

impl std::fmt::Debug for ImportedRecipientChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImportedRecipientChoice(<redacted>)")
    }
}
impl std::fmt::Debug for ImportedRecipientSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedRecipientSnapshot")
            .field("count", &self.choices.len())
            .finish()
    }
}

impl ImportedRecipientSnapshot {
    pub fn from_inventory(
        account: &str,
        record: &crate::openpgp_bindings::BindingRecord,
        inventory: &crate::openpgp_inventory::Inventory,
    ) -> Result<Self, ContactError> {
        validate_account(account)?;
        record
            .ensure_account(account)
            .map_err(|_| ContactError::Unavailable)?;
        let keys = inventory.keys().ok_or(ContactError::Unavailable)?;
        let mut seen = BTreeSet::new();
        let mut choices = Vec::new();
        for address in keys.iter().flat_map(|key| &key.email_addresses) {
            let comparison = crate::mail_address::comparison_key(address);
            if seen.contains(&comparison) {
                continue;
            }
            let Ok(selected) = record.resolve_recipient(inventory, address) else {
                continue;
            };
            if !keys
                .iter()
                .any(|key| key.primary.fingerprint == selected.primary_fingerprint)
            {
                continue;
            }
            validate_values("", address)?;
            if choices.len() == MAX_CONTACTS {
                return Err(ContactError::Quota);
            }
            choices.push(ImportedRecipientChoice {
                id: imported_choice_id(account, address, &selected.primary_fingerprint)?,
                address: address.clone(),
                primary_fingerprint: selected.primary_fingerprint,
            });
            seen.insert(comparison);
        }
        choices.sort_by_key(|choice| crate::mail_address::comparison_key(&choice.address));
        let snapshot = Self {
            canonical_username: account.into(),
            choices,
        };
        snapshot.ensure_account(account)?;
        Ok(snapshot)
    }

    /// Check the trusted gateway projection before display or membership lookup.
    pub fn ensure_account(&self, account: &str) -> Result<(), ContactError> {
        validate_account(account)?;
        if self.canonical_username != account || self.choices.len() > MAX_CONTACTS {
            return Err(ContactError::Unavailable);
        }
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for choice in &self.choices {
            if validate_values("", &choice.address).is_err()
                || !crate::openpgp_crypto::full_fingerprint(&choice.primary_fingerprint)
                || choice.id
                    != imported_choice_id(account, &choice.address, &choice.primary_fingerprint)?
                || !ids.insert(&choice.id)
                || !addresses.insert(crate::mail_address::comparison_key(&choice.address))
            {
                return Err(ContactError::Unavailable);
            }
        }
        Ok(())
    }

    pub fn selected(
        &self,
        account: &str,
        id: &str,
    ) -> Result<&ImportedRecipientChoice, ContactError> {
        self.ensure_account(account)?;
        if id.len() != 68
            || !id.starts_with("key:")
            || !id.as_bytes()[4..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(ContactError::Invalid);
        }
        self.choices
            .iter()
            .find(|choice| choice.id == id)
            .ok_or(ContactError::Stale)
    }
}

fn imported_choice_id(
    account: &str,
    address: &str,
    fingerprint: &str,
) -> Result<String, ContactError> {
    let tuple = serde_json::to_vec(&(
        account,
        crate::mail_address::comparison_key(address),
        fingerprint,
    ))
    .map_err(|_| ContactError::Unavailable)?;
    let mut hash = Sha256::new();
    hash.update(b"osmap-imported-recipient-choice-v1\0");
    hash.update(tuple);
    Ok(format!("key:{:x}", hash.finalize()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryEncryption {
    OffByDefault,
    Required,
    Disabled,
    Conflict,
    Unavailable,
}

/// Current public recipient capability and policy, never private-key readiness.
#[derive(Clone, PartialEq, Eq)]
pub struct ContactDirectoryEntry {
    pub display_name: String,
    pub address: String,
    pub saved_id: Option<String>,
    pub imported_id: Option<String>,
    pub key_status: Option<crate::openpgp_bindings::KeyStatus>,
    pub encryption: DirectoryEncryption,
    pub imported: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ContactDirectory {
    pub entries: Vec<ContactDirectoryEntry>,
    pub saved_available: bool,
    pub keys_available: bool,
}

impl std::fmt::Debug for ContactDirectoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContactDirectoryEntry(<redacted>)")
    }
}
impl std::fmt::Debug for ContactDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactDirectory")
            .field("count", &self.entries.len())
            .field("saved_available", &self.saved_available)
            .field("keys_available", &self.keys_available)
            .finish()
    }
}

impl ContactDirectory {
    /// Merge independently owned sources without changing contacts or bindings.
    /// The caller supplies inventory authenticated for this account; Inventory
    /// contains public metadata, not an independently encoded account identity.
    pub fn from_sources(
        account: &str,
        book: Option<&ContactBook>,
        bindings: Option<&crate::openpgp_bindings::BindingRecord>,
        inventory: Option<&crate::openpgp_inventory::Inventory>,
        now: u64,
    ) -> Result<Self, ContactError> {
        validate_account(account)?;
        if now == 0 || now > 253402300799 {
            return Err(ContactError::Unavailable);
        }
        if book.is_some_and(|book| {
            book.canonical_username == account && book.contacts.len() > MAX_CONTACTS
        }) {
            return Err(ContactError::Quota);
        }
        let book = book.filter(|book| book.ensure_account(account).is_ok());
        let bindings = bindings.filter(|record| record.ensure_account(account).is_ok());
        let public_inventory = bindings
            .and(inventory)
            .filter(|inventory| inventory.keys().is_some());
        let mut entries = BTreeMap::new();
        if let Some(book) = book {
            for contact in &book.contacts {
                entries.insert(
                    crate::mail_address::comparison_key(&contact.address),
                    ContactDirectoryEntry {
                        display_name: contact.display_name.clone(),
                        address: contact.address.clone(),
                        saved_id: Some(contact.id.clone()),
                        imported_id: None,
                        key_status: None,
                        encryption: DirectoryEncryption::Unavailable,
                        imported: false,
                    },
                );
            }
        }
        if let (Some(record), Some(inventory)) = (bindings, public_inventory) {
            let mut imported = BTreeSet::new();
            for email in inventory
                .keys()
                .ok_or(ContactError::Unavailable)?
                .iter()
                .flat_map(|key| &key.email_addresses)
            {
                let comparison = crate::mail_address::comparison_key(email);
                if imported.insert(comparison.clone()) && imported.len() > MAX_CONTACTS {
                    return Err(ContactError::Quota);
                }
                let entry = entries
                    .entry(comparison)
                    .or_insert_with(|| ContactDirectoryEntry {
                        display_name: String::new(),
                        address: email.clone(),
                        saved_id: None,
                        imported_id: None,
                        key_status: None,
                        encryption: DirectoryEncryption::Unavailable,
                        imported: true,
                    });
                entry.imported = true;
            }
            let selectable = ImportedRecipientSnapshot::from_inventory(account, record, inventory)?;
            for choice in selectable.choices {
                if let Some(entry) =
                    entries.get_mut(&crate::mail_address::comparison_key(&choice.address))
                {
                    entry.imported_id = Some(choice.id);
                }
            }
        }
        if entries.len() > MAX_CONTACTS * 2 {
            return Err(ContactError::Quota);
        }
        let unavailable = crate::openpgp_inventory::Inventory::parse(
            br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#,
        )
        .map_err(|_| ContactError::Unavailable)?;
        if let Some(record) = bindings {
            for entry in entries.values_mut() {
                let recipient = [entry.address.clone()];
                let assessment = crate::openpgp_bindings::evaluate(
                    account,
                    record,
                    public_inventory.unwrap_or(&unavailable),
                    crate::openpgp_bindings::Recipients {
                        to: &recipient,
                        cc: &[],
                        bcc: &[],
                    },
                    crate::openpgp_bindings::Selections::default(),
                    now,
                )
                .map_err(|_| ContactError::Unavailable)?;
                let readiness = assessment
                    .recipients
                    .first()
                    .ok_or(ContactError::Unavailable)?;
                entry.key_status = Some(readiness.state);
                entry.encryption =
                    directory_encryption(record.policy.encryption, readiness.requirement);
            }
        }
        Ok(Self {
            entries: entries.into_values().collect(),
            saved_available: book.is_some(),
            keys_available: public_inventory.is_some(),
        })
    }
}

fn directory_encryption(
    global: crate::openpgp_bindings::Requirement,
    recipient: crate::openpgp_bindings::Requirement,
) -> DirectoryEncryption {
    use crate::openpgp_bindings::Requirement::{Disabled, Optional, Required};
    match (global, recipient) {
        (Required, Disabled) | (Disabled, Required) => DirectoryEncryption::Conflict,
        (Required, _) | (_, Required) => DirectoryEncryption::Required,
        (Disabled, _) | (_, Disabled) => DirectoryEncryption::Disabled,
        (Optional, Optional) => DirectoryEncryption::OffByDefault,
    }
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contact")
            .field("display_name_bytes", &self.display_name.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ContactBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactBook")
            .field("revision", &self.revision)
            .field("count", &self.contacts.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactError {
    Invalid,
    NotFound,
    Duplicate,
    Quota,
    Stale,
    Busy,
    Unavailable,
}

impl ContactError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid => {
                "Use a display name of at most 100 bytes and one supported email address."
            }
            Self::NotFound => "This contact was not found in your account.",
            Self::Duplicate => "This address is already in your contacts.",
            Self::Quota => "Your contacts have reached the limit of 200 entries.",
            Self::Stale => {
                "Your contacts changed. Reload the list before choosing or changing an entry."
            }
            Self::Busy => "Another contact change is in progress. Your change was not saved.",
            Self::Unavailable => {
                "Contacts could not be read or saved safely. Reload to check the current state."
            }
        }
    }
}

impl From<std::io::Error> for ContactError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Self::Busy
        } else {
            Self::Unavailable
        }
    }
}

#[derive(Clone)]
pub enum ContactChange {
    Save {
        id: Option<String>,
        display_name: String,
        address: String,
    },
    Delete {
        id: String,
    },
}

impl ContactBook {
    pub fn empty(account: &str) -> Self {
        Self {
            version: 1,
            canonical_username: account.into(),
            revision: 0,
            contacts: Vec::new(),
        }
    }

    pub fn selected(&self, expected_revision: u64, id: &str) -> Result<&Contact, ContactError> {
        if self.revision != expected_revision {
            return Err(ContactError::Stale);
        }
        if !valid_id(id) {
            return Err(ContactError::Invalid);
        }
        self.contacts
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(ContactError::NotFound)
    }

    /// Validate the gateway boundary before displaying or selecting any entry.
    pub fn ensure_account(&self, account: &str) -> Result<(), ContactError> {
        validate_account(account)?;
        if self.revision == 0 {
            if self.version == 1 && self.canonical_username == account && self.contacts.is_empty() {
                return Ok(());
            }
            return Err(ContactError::Unavailable);
        }
        self.validate(account)
    }

    fn validate(&self, account: &str) -> Result<(), ContactError> {
        if self.version != 1
            || self.canonical_username != account
            || self.revision == 0
            || self.contacts.len() > MAX_CONTACTS
        {
            return Err(ContactError::Unavailable);
        }
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for contact in &self.contacts {
            if !valid_id(&contact.id)
                || validate_values(&contact.display_name, &contact.address).is_err()
                || !ids.insert(&contact.id)
                || !addresses.insert(crate::mail_address::comparison_key(&contact.address))
            {
                return Err(ContactError::Unavailable);
            }
        }
        Ok(())
    }

    fn change(&mut self, expected: u64, change: ContactChange) -> Result<(), ContactError> {
        if self.revision != expected {
            return Err(ContactError::Stale);
        }
        match change {
            ContactChange::Save {
                id,
                display_name,
                address,
            } => {
                let display_name = display_name.trim().to_string();
                let address = address.trim().to_string();
                validate_values(&display_name, &address)?;
                if let Some(id) = &id {
                    self.selected(expected, id)?;
                }
                let key = crate::mail_address::comparison_key(&address);
                if self.contacts.iter().any(|entry| {
                    Some(&entry.id) != id.as_ref()
                        && crate::mail_address::comparison_key(&entry.address) == key
                }) {
                    return Err(ContactError::Duplicate);
                }
                if let Some(id) = id {
                    let entry = self
                        .contacts
                        .iter_mut()
                        .find(|entry| entry.id == id)
                        .ok_or(ContactError::NotFound)?;
                    entry.display_name = display_name;
                    entry.address = address;
                } else {
                    if self.contacts.len() == MAX_CONTACTS {
                        return Err(ContactError::Quota);
                    }
                    let id =
                        crate::draft::generate_draft_id().map_err(|_| ContactError::Unavailable)?;
                    if self.contacts.iter().any(|entry| entry.id == id) {
                        return Err(ContactError::Unavailable);
                    }
                    self.contacts.push(Contact {
                        id,
                        display_name,
                        address,
                    });
                }
            }
            ContactChange::Delete { id } => {
                self.selected(expected, &id)?;
                self.contacts.retain(|entry| entry.id != id);
            }
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContactError::Unavailable)?;
        self.contacts.sort_by(|left, right| {
            left.display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase())
                .then_with(|| left.address.cmp(&right.address))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ContactStore {
    file: PrivateAccountFile,
}

impl ContactStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            file: PrivateAccountFile::new(directory.into(), "osmap-contacts-v1", MAX_BOOK_BYTES),
        }
    }

    pub fn load(&self, account: &str) -> Result<ContactBook, ContactError> {
        validate_account(account)?;
        decode(account, self.file.read(account)?)
    }

    pub fn change(
        &self,
        account: &str,
        expected_revision: u64,
        change: ContactChange,
    ) -> Result<ContactBook, ContactError> {
        validate_account(account)?;
        let locked = self.file.lock(account)?;
        let mut book = decode(account, locked.read()?)?;
        book.change(expected_revision, change)?;
        book.validate(account)?;
        let bytes = serde_json::to_vec(&book).map_err(|_| ContactError::Unavailable)?;
        locked.write(&bytes)?;
        Ok(book)
    }
}

fn decode(account: &str, bytes: Option<Vec<u8>>) -> Result<ContactBook, ContactError> {
    let Some(bytes) = bytes else {
        return Ok(ContactBook::empty(account));
    };
    let book: ContactBook =
        serde_json::from_slice(&bytes).map_err(|_| ContactError::Unavailable)?;
    book.validate(account)?;
    Ok(book)
}

fn validate_account(account: &str) -> Result<(), ContactError> {
    crate::identity::CanonicalUsername::parse(account)
        .map(|_| ())
        .map_err(|_| ContactError::Unavailable)
}

fn validate_values(name: &str, address: &str) -> Result<(), ContactError> {
    if name.len() > MAX_DISPLAY_NAME_BYTES
        || name.chars().any(char::is_control)
        || name.trim() != name
    {
        return Err(ContactError::Invalid);
    }
    crate::mail_address::validate_address(crate::send::ComposePolicy::default(), address)
        .map_err(|_| ContactError::Invalid)
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Barrier};

    fn imported_inventory(keys: &[(String, Vec<String>)]) -> crate::openpgp_inventory::Inventory {
        crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&serde_json::json!({
            "version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8",
            "keys":keys.iter().map(|(fingerprint, emails)| serde_json::json!({
                "primary":{"fingerprint":fingerprint,"algorithm":1,"bits":3072,"created":1,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,"can_sign":true,"can_encrypt":true,"can_certify":true,"can_authenticate":false},
                "subkeys":[],"email_addresses":emails,
            })).collect::<Vec<_>>(),
        })).unwrap()).unwrap()
    }

    fn directory_book(account: &str, entries: &[(&str, &str)]) -> ContactBook {
        let mut book = ContactBook::empty(account);
        for (name, address) in entries {
            book.change(book.revision, add(name, address)).unwrap();
        }
        book
    }

    #[test]
    fn directory_merges_saved_labels_and_imported_ids_without_changing_sources() {
        use crate::openpgp_bindings::KeyStatus;
        let account = "alice@example.test";
        let book = directory_book(
            account,
            &[
                ("Saved desk", "Desk@example.test"),
                ("Plain contact", "plain@example.test"),
            ],
        );
        let record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        let inventory = imported_inventory(&[(
            "A".repeat(40),
            vec!["Desk@EXAMPLE.test".into(), "imported@example.test".into()],
        )]);
        let before = book.clone();
        let binding_before = record.clone();
        let directory = ContactDirectory::from_sources(
            account,
            Some(&book),
            Some(&record),
            Some(&inventory),
            50,
        )
        .unwrap();
        assert!(directory.saved_available && directory.keys_available);
        assert_eq!(directory.entries.len(), 3);
        let desk = directory
            .entries
            .iter()
            .find(|entry| entry.address == "Desk@example.test")
            .unwrap();
        assert_eq!(desk.display_name, "Saved desk");
        assert_eq!(
            desk.saved_id.as_ref(),
            Some(
                &book
                    .contacts
                    .iter()
                    .find(|entry| entry.address == desk.address)
                    .unwrap()
                    .id
            )
        );
        assert!(desk.imported && desk.imported_id.is_some());
        assert_eq!(desk.key_status, Some(KeyStatus::Ready));
        assert_eq!(desk.encryption, DirectoryEncryption::OffByDefault);
        let plain = directory
            .entries
            .iter()
            .find(|entry| entry.address == "plain@example.test")
            .unwrap();
        assert!(!plain.imported && plain.imported_id.is_none());
        assert_eq!(plain.key_status, Some(KeyStatus::MissingBinding));
        assert_eq!(plain.encryption, DirectoryEncryption::OffByDefault);
        assert_eq!(book, before);
        assert_eq!(record, binding_before);
        assert!(!format!("{directory:?} {desk:?}").contains("example.test"));
    }

    #[test]
    fn directory_source_ownership_and_availability_are_independent() {
        use crate::openpgp_bindings::{KeyStatus, Requirement};
        let account = "alice@example.test";
        let book = directory_book(account, &[("Saved", "saved@example.test")]);
        let foreign_book =
            directory_book("bob@example.test", &[("Foreign", "foreign@example.test")]);
        let mut record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        record.revision = 1;
        record.policy.encryption = Requirement::Required;
        let foreign_record =
            crate::openpgp_bindings::BindingRecord::empty("bob@example.test").unwrap();
        let inventory =
            imported_inventory(&[("A".repeat(40), vec!["imported@example.test".into()])]);
        let foreign = ContactDirectory::from_sources(
            account,
            Some(&foreign_book),
            Some(&record),
            Some(&inventory),
            50,
        )
        .unwrap();
        assert!(!foreign.saved_available && foreign.keys_available);
        assert_eq!(foreign.entries.len(), 1);
        assert_eq!(foreign.entries[0].address, "imported@example.test");
        for binding in [None, Some(&foreign_record)] {
            let result =
                ContactDirectory::from_sources(account, Some(&book), binding, Some(&inventory), 50)
                    .unwrap();
            assert!(result.saved_available && !result.keys_available);
            assert_eq!(result.entries.len(), 1);
            assert_eq!(result.entries[0].address, "saved@example.test");
            assert_eq!(
                result.entries[0].encryption,
                DirectoryEncryption::Unavailable
            );
            assert_eq!(result.entries[0].key_status, None);
        }
        let keys_only =
            ContactDirectory::from_sources(account, None, Some(&record), Some(&inventory), 50)
                .unwrap();
        assert!(!keys_only.saved_available && keys_only.keys_available);
        let unavailable =
            ContactDirectory::from_sources(account, Some(&book), Some(&record), None, 50).unwrap();
        assert!(unavailable.saved_available && !unavailable.keys_available);
        assert_eq!(
            unavailable.entries[0].key_status,
            Some(KeyStatus::InventoryUnavailable)
        );
        assert_eq!(
            unavailable.entries[0].encryption,
            DirectoryEncryption::Required
        );
        let mut malformed = record.clone();
        malformed.revision = 0;
        assert!(
            !ContactDirectory::from_sources(account, None, Some(&malformed), Some(&inventory), 50)
                .unwrap()
                .keys_available
        );
        assert_eq!(
            ContactDirectory::from_sources(account, None, Some(&record), Some(&inventory), 0),
            Err(ContactError::Unavailable)
        );
    }

    #[test]
    fn directory_keeps_ambiguous_and_missing_selected_keys_visible_without_compose_ids() {
        use crate::openpgp_bindings::{KeyStatus, RecipientBinding, Requirement};
        let account = "alice@example.test";
        let mut record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        let inventory = imported_inventory(&[
            ("A".repeat(40), vec!["same@example.test".into()]),
            ("B".repeat(40), vec!["same@example.test".into()]),
        ]);
        let ambiguous =
            ContactDirectory::from_sources(account, None, Some(&record), Some(&inventory), 50)
                .unwrap();
        assert_eq!(ambiguous.entries.len(), 1);
        assert!(ambiguous.entries[0].imported && ambiguous.entries[0].imported_id.is_none());
        assert_eq!(ambiguous.entries[0].key_status, Some(KeyStatus::Ambiguous));
        record.revision = 1;
        record.recipient_bindings.push(RecipientBinding {
            address: "same@example.test".into(),
            primary_fingerprint: "C".repeat(40),
            encryption: Requirement::Disabled,
        });
        let missing =
            ContactDirectory::from_sources(account, None, Some(&record), Some(&inventory), 50)
                .unwrap();
        assert_eq!(missing.entries[0].key_status, Some(KeyStatus::MissingKey));
        assert!(missing.entries[0].imported_id.is_none());
        assert_eq!(missing.entries[0].encryption, DirectoryEncryption::Disabled);
    }

    #[test]
    fn directory_combines_actual_global_and_recipient_encryption_without_default_encryption() {
        use crate::openpgp_bindings::{
            RecipientBinding,
            Requirement::{Disabled, Optional, Required},
        };
        let account = "alice@example.test";
        let inventory =
            imported_inventory(&[("A".repeat(40), vec!["recipient@example.test".into()])]);
        for (global, recipient, expected) in [
            (Optional, Optional, DirectoryEncryption::OffByDefault),
            (Optional, Required, DirectoryEncryption::Required),
            (Required, Optional, DirectoryEncryption::Required),
            (Required, Required, DirectoryEncryption::Required),
            (Optional, Disabled, DirectoryEncryption::Disabled),
            (Disabled, Optional, DirectoryEncryption::Disabled),
            (Disabled, Disabled, DirectoryEncryption::Disabled),
            (Required, Disabled, DirectoryEncryption::Conflict),
            (Disabled, Required, DirectoryEncryption::Conflict),
        ] {
            let mut record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
            record.revision = 1;
            record.policy.encryption = global;
            record.recipient_bindings.push(RecipientBinding {
                address: "recipient@example.test".into(),
                primary_fingerprint: "A".repeat(40),
                encryption: recipient,
            });
            let result =
                ContactDirectory::from_sources(account, None, Some(&record), Some(&inventory), 50)
                    .unwrap();
            assert_eq!(result.entries[0].encryption, expected);
        }
    }

    #[test]
    fn directory_bounds_all_imported_identities_even_when_ambiguous_and_never_truncates() {
        let account = "alice@example.test";
        let record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        let inventory = |count: usize| {
            imported_inventory(
                &(0..count.div_ceil(16))
                    .map(|key| {
                        (
                            format!("{:040X}", key + 1),
                            (key * 16..count.min((key + 1) * 16))
                                .map(|index| format!("key{index}@example.test"))
                                .collect(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let names = (0..MAX_CONTACTS)
            .map(|index| {
                (
                    format!("Saved {index}"),
                    format!("saved{index}@example.test"),
                )
            })
            .collect::<Vec<_>>();
        let book = directory_book(
            account,
            &names
                .iter()
                .map(|(name, address)| (name.as_str(), address.as_str()))
                .collect::<Vec<_>>(),
        );
        let full = ContactDirectory::from_sources(
            account,
            Some(&book),
            Some(&record),
            Some(&inventory(MAX_CONTACTS)),
            50,
        )
        .unwrap();
        assert_eq!(full.entries.len(), MAX_CONTACTS * 2);
        assert_eq!(
            ContactDirectory::from_sources(
                account,
                Some(&book),
                Some(&record),
                Some(&inventory(MAX_CONTACTS + 1)),
                50
            ),
            Err(ContactError::Quota)
        );
        let ambiguous = imported_inventory(
            &(0..(MAX_CONTACTS + 1).div_ceil(16))
                .flat_map(|group| {
                    let emails = (group * 16..(MAX_CONTACTS + 1).min((group + 1) * 16))
                        .map(|index| format!("ambiguous{index}@example.test"))
                        .collect::<Vec<_>>();
                    (0..2)
                        .map(move |copy| (format!("{:040X}", group * 2 + copy + 1), emails.clone()))
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            ContactDirectory::from_sources(account, None, Some(&record), Some(&ambiguous), 50),
            Err(ContactError::Quota)
        );
        let mut oversized = book;
        oversized.contacts.push(oversized.contacts[0].clone());
        assert_eq!(
            ContactDirectory::from_sources(
                account,
                Some(&oversized),
                Some(&record),
                Some(&inventory(1)),
                50
            ),
            Err(ContactError::Quota)
        );
    }

    #[test]
    fn imported_recipient_snapshot_is_owned_stable_deduplicated_and_not_a_contact_book() {
        let account = "alice@example.test";
        let record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        let inventory = imported_inventory(&[(
            "A".repeat(40),
            vec![
                "Desk@EXAMPLE.test".into(),
                "Desk@example.TEST".into(),
                "alias@example.test".into(),
            ],
        )]);
        let snapshot =
            ImportedRecipientSnapshot::from_inventory(account, &record, &inventory).unwrap();
        assert_eq!(snapshot.choices.len(), 2);
        assert!(snapshot
            .choices
            .iter()
            .all(|choice| choice.id.starts_with("key:") && choice.id.len() == 68));
        let desk = snapshot
            .choices
            .iter()
            .find(|choice| choice.address.starts_with("Desk@"))
            .unwrap();
        assert_eq!(
            snapshot.selected(account, &desk.id).unwrap().address,
            "Desk@EXAMPLE.test"
        );
        let reordered = imported_inventory(&[(
            "A".repeat(40),
            vec!["alias@example.test".into(), "Desk@example.test".into()],
        )]);
        let fresh =
            ImportedRecipientSnapshot::from_inventory(account, &record, &reordered).unwrap();
        assert_eq!(
            fresh
                .choices
                .iter()
                .find(|choice| choice.address.starts_with("Desk@"))
                .unwrap()
                .id,
            desk.id
        );
        let other = "bob@example.test";
        let other_record = crate::openpgp_bindings::BindingRecord::empty(other).unwrap();
        let other_snapshot =
            ImportedRecipientSnapshot::from_inventory(other, &other_record, &inventory).unwrap();
        assert_ne!(other_snapshot.choices[0].id, snapshot.choices[0].id);
        assert!(snapshot.ensure_account(other).is_err());
        assert!(snapshot.selected(other, &desk.id).is_err());
        assert!(ImportedRecipientSnapshot::from_inventory(other, &record, &inventory).is_err());
        assert_eq!(
            snapshot.selected(account, &format!("key:{}", "0".repeat(64))),
            Err(ContactError::Stale)
        );
        assert_eq!(
            snapshot.selected(account, &"a".repeat(32)),
            Err(ContactError::Invalid)
        );
        assert!(!format!("{snapshot:?} {desk:?}").contains("example.test"));
        assert_eq!(record.revision, 0);
        assert!(record.recipient_bindings.is_empty() && record.account_binding.is_none());
    }

    #[test]
    fn imported_recipient_handles_do_not_survive_removed_rebound_or_ambiguous_membership() {
        let account = "alice@example.test";
        let mut record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        let first = imported_inventory(&[("A".repeat(40), vec!["recipient@example.test".into()])]);
        let old = ImportedRecipientSnapshot::from_inventory(account, &record, &first).unwrap();
        let id = &old.choices[0].id;
        let changed =
            imported_inventory(&[("B".repeat(40), vec!["recipient@example.test".into()])]);
        let rebound =
            ImportedRecipientSnapshot::from_inventory(account, &record, &changed).unwrap();
        assert_eq!(rebound.selected(account, id), Err(ContactError::Stale));
        let removed = imported_inventory(&[]);
        assert!(
            ImportedRecipientSnapshot::from_inventory(account, &record, &removed)
                .unwrap()
                .choices
                .is_empty()
        );
        let conflict = imported_inventory(&[
            ("A".repeat(40), vec!["recipient@example.test".into()]),
            ("B".repeat(40), vec!["recipient@example.test".into()]),
        ]);
        assert!(
            ImportedRecipientSnapshot::from_inventory(account, &record, &conflict)
                .unwrap()
                .choices
                .is_empty()
        );
        record.revision = 1;
        record
            .recipient_bindings
            .push(crate::openpgp_bindings::RecipientBinding {
                address: "recipient@example.test".into(),
                primary_fingerprint: "B".repeat(40),
                encryption: crate::openpgp_bindings::Requirement::Required,
            });
        let selected =
            ImportedRecipientSnapshot::from_inventory(account, &record, &conflict).unwrap();
        assert_eq!(selected.choices.len(), 1);
        assert_eq!(selected.choices[0].id, rebound.choices[0].id);
        assert!(
            ImportedRecipientSnapshot::from_inventory(account, &record, &first)
                .unwrap()
                .choices
                .is_empty(),
            "a missing explicitly selected primary cannot be replaced"
        );
        let unavailable = crate::openpgp_inventory::Inventory::parse(
            br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#,
        )
        .unwrap();
        assert_eq!(
            ImportedRecipientSnapshot::from_inventory(account, &record, &unavailable),
            Err(ContactError::Unavailable)
        );
    }

    #[test]
    fn imported_recipient_snapshot_refuses_quota_and_tampered_gateway_choices_without_truncation() {
        let account = "alice@example.test";
        let record = crate::openpgp_bindings::BindingRecord::empty(account).unwrap();
        let inventory = |count: usize| {
            imported_inventory(
                &(0..count.div_ceil(16))
                    .map(|key| {
                        (
                            format!("{:040X}", key + 1),
                            (key * 16..count.min((key + 1) * 16))
                                .map(|email| format!("user{email}@example.test"))
                                .collect(),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let snapshot =
            ImportedRecipientSnapshot::from_inventory(account, &record, &inventory(MAX_CONTACTS))
                .unwrap();
        assert_eq!(snapshot.choices.len(), MAX_CONTACTS);
        assert_eq!(
            ImportedRecipientSnapshot::from_inventory(
                account,
                &record,
                &inventory(MAX_CONTACTS + 1)
            ),
            Err(ContactError::Quota)
        );
        let mut changed = snapshot.clone();
        changed.choices[0].address = "foreign@example.test".into();
        assert_eq!(
            changed.ensure_account(account),
            Err(ContactError::Unavailable)
        );
        let mut duplicate = snapshot;
        duplicate.choices[1] = duplicate.choices[0].clone();
        assert_eq!(
            duplicate.ensure_account(account),
            Err(ContactError::Unavailable)
        );
    }

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!(
            "osmap-contacts-{}",
            crate::draft::generate_draft_id().unwrap()
        ))
    }
    fn add(name: &str, address: &str) -> ContactChange {
        ContactChange::Save {
            id: None,
            display_name: name.into(),
            address: address.into(),
        }
    }

    #[test]
    fn account_private_contacts_survive_restart_and_refuse_stale_or_foreign_changes() {
        let root = scratch();
        let store = ContactStore::new(&root);
        assert_eq!(store.load("alice@example.test").unwrap().revision, 0);
        let book = store
            .change(
                "alice@example.test",
                0,
                add("Reply Desk", "desk@example.test"),
            )
            .unwrap();
        let id = &book.contacts[0].id;
        assert_eq!(book.revision, 1);
        assert!(!format!("{book:?} {:?}", book.contacts[0]).contains("example.test"));
        assert_eq!(
            ContactStore::new(&root).load("alice@example.test").unwrap(),
            book
        );
        let bob = store.load("bob@example.test").unwrap();
        assert_eq!(bob.selected(0, id), Err(ContactError::NotFound));
        assert_eq!(
            store.change(
                "bob@example.test",
                0,
                ContactChange::Delete { id: id.clone() }
            ),
            Err(ContactError::NotFound)
        );
        assert_eq!(
            store.change("alice@example.test", 0, add("Other", "other@example.test")),
            Err(ContactError::Stale)
        );
        assert_eq!(
            store.change(
                "alice@example.test",
                1,
                add("Duplicate", "desk@EXAMPLE.TEST")
            ),
            Err(ContactError::Duplicate)
        );
        assert_eq!(store.load("alice@example.test").unwrap(), book);
        let edited = store
            .change(
                "alice@example.test",
                1,
                ContactChange::Save {
                    id: Some(id.clone()),
                    display_name: "Updated".into(),
                    address: "updated@example.test".into(),
                },
            )
            .unwrap();
        assert_eq!(edited.revision, 2);
        assert_eq!(edited.selected(1, id), Err(ContactError::Stale));
        let deleted = store
            .change(
                "alice@example.test",
                2,
                ContactChange::Delete { id: id.clone() },
            )
            .unwrap();
        assert_eq!(deleted.revision, 3);
        assert!(deleted.contacts.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn contacts_validate_names_addresses_quota_and_serialized_shape_without_changing_state() {
        let root = scratch();
        let store = ContactStore::new(&root);
        let mut book = store
            .change("alice@example.test", 0, add("Desk", "desk@example.test"))
            .unwrap();
        for (name, address) in [
            ("bad\nname".to_string(), "valid@example.test"),
            ("界".repeat(34), "valid@example.test"),
            ("Desk".into(), "bad"),
            ("Desk".into(), "a@example.test\r\nBcc: hidden@example.test"),
            ("Desk".into(), "a@example.test,b@example.test"),
        ] {
            assert_eq!(
                store.change("alice@example.test", 1, add(&name, address)),
                Err(ContactError::Invalid)
            );
        }
        assert_eq!(store.load("alice@example.test").unwrap(), book);
        for i in 1..MAX_CONTACTS {
            book.contacts.push(Contact {
                id: format!("{i:032x}"),
                display_name: format!("Contact {i}"),
                address: format!("user{i}@example.test"),
            });
        }
        store
            .file
            .lock("alice@example.test")
            .unwrap()
            .write(&serde_json::to_vec(&book).unwrap())
            .unwrap();
        assert_eq!(
            store.change(
                "alice@example.test",
                1,
                add("Overflow", "overflow@example.test")
            ),
            Err(ContactError::Quota)
        );
        assert_eq!(store.load("alice@example.test").unwrap(), book);
        let record = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        let bytes = fs::read(&record).unwrap();
        for bad in [
            b"{\"version\":1,\"version\":1}".to_vec(),
            serde_json::to_vec(&ContactBook {
                canonical_username: "bob@example.test".into(),
                ..book.clone()
            })
            .unwrap(),
            vec![b'x'; MAX_BOOK_BYTES + 1],
        ] {
            fs::write(&record, bad).unwrap();
            assert_eq!(
                store.load("alice@example.test"),
                Err(ContactError::Unavailable)
            );
            assert_eq!(
                store.change("alice@example.test", 1, add("Other", "other@example.test")),
                Err(ContactError::Unavailable)
            );
            fs::write(&record, &bytes).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_contact_changes_allow_only_one_writer_for_a_revision() {
        let root = scratch();
        let store = ContactStore::new(&root);
        store
            .change("alice@example.test", 0, add("Desk", "desk@example.test"))
            .unwrap();
        let held = store.file.lock("alice@example.test").unwrap();
        assert_eq!(
            store.change("alice@example.test", 1, add("Other", "other@example.test")),
            Err(ContactError::Busy)
        );
        drop(held);
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for i in 0..2 {
            let store = store.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store.change(
                    "alice@example.test",
                    1,
                    add("Concurrent", &format!("user{i}@example.test")),
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| matches!(error, ContactError::Busy | ContactError::Stale)));
        let book = store.load("alice@example.test").unwrap();
        assert_eq!((book.revision, book.contacts.len()), (2, 2));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn contact_store_refuses_symlinks_hardlinks_and_unsafe_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let root = scratch();
        let store = ContactStore::new(&root);
        let book = store
            .change("alice@example.test", 0, add("Desk", "desk@example.test"))
            .unwrap();
        let record = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "json"))
            .unwrap();
        let backup = root.join("owned-backup");
        fs::rename(&record, &backup).unwrap();
        symlink(&backup, &record).unwrap();
        assert_eq!(
            store.load("alice@example.test"),
            Err(ContactError::Unavailable)
        );
        assert_eq!(
            store.change("alice@example.test", 1, add("Other", "other@example.test")),
            Err(ContactError::Unavailable)
        );
        fs::remove_file(&record).unwrap();
        fs::hard_link(&backup, &record).unwrap();
        assert_eq!(
            store.load("alice@example.test"),
            Err(ContactError::Unavailable)
        );
        fs::remove_file(&record).unwrap();
        fs::rename(&backup, &record).unwrap();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.load("alice@example.test"),
            Err(ContactError::Unavailable)
        );
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            store.load("alice@example.test"),
            Err(ContactError::Unavailable)
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(store.load("alice@example.test").unwrap(), book);
        fs::remove_dir_all(root).unwrap();
    }
}
