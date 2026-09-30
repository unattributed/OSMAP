//! Explicit account-private address shortcuts; no harvesting or trust inference.
use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
