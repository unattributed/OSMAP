//! Own-account factor metadata and untrusted recovery requests. Browser requests
//! never supply identity approval, containment, revocation or factor authority.
use crate::private_account_file::PrivateAccountFile;
use crate::totp::{FileTotpSecretStore, TotpSecretStore as _};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const NAMESPACE: &str = "osmap-account-recovery-status-v1";
const MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub account: String,
    pub enrolled: bool,
    /// Account replay history deliberately survives factor replacement. This
    /// counter is not an exact verification time or proof of current-factor use.
    pub last_accepted_counter: Option<u64>,
    pub request: Option<RequestRecord>,
    pub case: Option<RequestRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    pub account: String,
    pub case_id: String,
    pub state: String,
    pub revision: u64,
    pub requested_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub account_state: Option<String>,
    #[serde(default)]
    pub account_epoch: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Refused,
    Unavailable,
}

fn valid(record: &RequestRecord, account: &str) -> bool {
    record.account == account
        && record.case_id.len() <= 64
        && !record.case_id.is_empty()
        && record
            .case_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && record.revision > 0
        && record.requested_at > 0
        && record.updated_at >= record.requested_at
        && matches!(
            record.state.as_str(),
            "requested"
                | "identity_reviewed"
                | "contained"
                | "sessions_revoked"
                | "factor_replacement"
                | "reconciled"
                | "manual_review"
        )
}

fn decode(bytes: Option<Vec<u8>>, account: &str) -> Result<Option<RequestRecord>, Error> {
    bytes
        .map(|bytes| {
            let record: RequestRecord =
                serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
            if !valid(&record, account) {
                return Err(Error::Unavailable);
            }
            Ok(record)
        })
        .transpose()
}

/// Operator-published metadata and browser requests occupy separate private
/// directories. Neither record is ever accepted as a recovery authorization.
#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}
impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn requests(&self) -> PrivateAccountFile {
        PrivateAccountFile::new(self.root.join("requests"), NAMESPACE, MAX_BYTES)
    }
    fn cases(&self) -> PrivateAccountFile {
        PrivateAccountFile::new(self.root.join("cases"), NAMESPACE, MAX_BYTES)
    }
    pub fn read_request(&self, account: &str) -> Result<Option<RequestRecord>, Error> {
        crate::identity::CanonicalUsername::parse(account.to_owned())
            .map_err(|_| Error::Refused)?;
        decode(
            self.requests()
                .read(account)
                .map_err(|_| Error::Unavailable)?,
            account,
        )
    }
    pub fn read_case(&self, account: &str) -> Result<Option<RequestRecord>, Error> {
        crate::identity::CanonicalUsername::parse(account.to_owned())
            .map_err(|_| Error::Refused)?;
        decode(
            self.cases().read(account).map_err(|_| Error::Unavailable)?,
            account,
        )
    }
    pub fn request(&self, account: &str, revision: u64, now: u64) -> Result<RequestRecord, Error> {
        crate::identity::CanonicalUsername::parse(account.to_owned())
            .map_err(|_| Error::Refused)?;
        if now == 0 {
            return Err(Error::Refused);
        }
        let lock = self
            .requests()
            .lock(account)
            .map_err(|_| Error::Unavailable)?;
        let current = decode(lock.read().map_err(|_| Error::Unavailable)?, account)?;
        if current.as_ref().map_or(0, |r| r.revision) != revision {
            return Err(Error::Refused);
        }
        if let Some(current) = current.as_ref() {
            let completed = self.read_case(account)?.is_some_and(|case| {
                case.case_id == current.case_id
                    && case.state == "reconciled"
                    && case.account_state.as_deref() == Some("active")
            });
            // Ordinary repeats cannot erase progress. An explicit request at
            // the current revision may start again after observed completion.
            if !completed {
                return Ok(current.clone());
            }
        }
        let mut random = [0; 32];
        getrandom::getrandom(&mut random).map_err(|_| Error::Unavailable)?;
        let record = RequestRecord {
            account: account.into(),
            case_id: random.iter().map(|b| format!("{b:02x}")).collect(),
            state: "requested".into(),
            revision: revision.checked_add(1).ok_or(Error::Unavailable)?,
            requested_at: now,
            updated_at: now,
            account_state: None,
            account_epoch: None,
        };
        lock.write(&serde_json::to_vec(&record).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?;
        Ok(record)
    }
}

#[cfg(unix)]
#[path = "authenticator_publish.rs"]
mod publish;
#[cfg(unix)]
pub(crate) use publish::publish_operator_status;
pub fn snapshot(
    account: &str,
    secret_dir: &Path,
    replay_dir: &Path,
    store: &Store,
) -> Result<Snapshot, Error> {
    crate::identity::CanonicalUsername::parse(account.to_owned()).map_err(|_| Error::Refused)?;
    let secrets = FileTotpSecretStore::new(secret_dir);
    let enrolled = secrets
        .load_secret(account)
        .map_err(|_| Error::Unavailable)?
        .is_some();
    let leaf = format!(
        "{}.counter",
        account
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let counter = crate::private_account_file::read_record(&replay_dir.join(leaf), 32)
        .map_err(|_| Error::Unavailable)?;
    let last_accepted_counter = counter
        .map(|bytes| {
            let text = std::str::from_utf8(&bytes).map_err(|_| Error::Unavailable)?;
            let counter = text.trim().parse::<u64>().map_err(|_| Error::Unavailable)?;
            counter
                .checked_mul(30)
                .and_then(|v| v.checked_add(29))
                .ok_or(Error::Unavailable)?;
            Ok(counter)
        })
        .transpose()?;
    Ok(Snapshot {
        account: account.into(),
        enrolled,
        last_accepted_counter,
        request: store.read_request(account)?,
        case: store.read_case(account)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_request_is_durable_idempotent_and_never_an_identity_grant() {
        let root =
            std::env::temp_dir().join(format!("osmap-recovery-request-{}", std::process::id()));
        let store = Store::new(&root);
        let first = store.request("alice@example.com", 0, 100).unwrap();
        assert_eq!(first.state, "requested");
        assert_eq!(first.case_id.len(), 64);
        assert_eq!(
            Store::new(&root).read_request("alice@example.com").unwrap(),
            Some(first.clone())
        );
        assert_eq!(store.request("alice@example.com", 1, 110).unwrap(), first);
        assert_eq!(
            store.request("alice@example.com", 0, 110),
            Err(Error::Refused)
        );
        assert!(store.read_request("bob@example.com").unwrap().is_none());
        assert!(store.read_case("alice@example.com").unwrap().is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn actual_operator_publication_is_read_by_browser_without_becoming_authority() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let parent = std::env::temp_dir().join(format!(
            "osmap-recovery-publish-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("account-recovery");
        let metadata = std::fs::metadata(&parent).unwrap();
        let status = crate::account_recovery::Status {
            schema: "osmap-account-recovery-v1",
            account: "alice@example.com".into(),
            state: "pending",
            epoch: 3,
            existing_factor_sha256: Some("a".repeat(64)),
            case_id: Some("human-case-1".into()),
            case_state: Some(crate::account_recovery::CaseState::SessionsRevoked),
            failure: None,
            session_failure: None,
        };
        publish_operator_status(
            &root,
            "alice@example.com",
            &status,
            metadata.uid(),
            metadata.gid(),
            100,
        )
        .unwrap();
        let record = Store::new(&root)
            .read_case("alice@example.com")
            .unwrap()
            .unwrap();
        assert_eq!(record.case_id, "human-case-1");
        assert_eq!(record.state, "sessions_revoked");
        assert_eq!(record.account_state.as_deref(), Some("pending"));
        assert_eq!(record.account_epoch, Some(3));
        assert!(Store::new(&root)
            .read_case("bob@example.com")
            .unwrap()
            .is_none());
        assert!(Store::new(&root)
            .read_request("alice@example.com")
            .unwrap()
            .is_none());
        assert_eq!(
            publish_operator_status(
                &root,
                "bob@example.com",
                &status,
                metadata.uid(),
                metadata.gid(),
                101
            ),
            Err(Error::Refused)
        );
        let mut status = status;
        status.state = "active";
        status.epoch = 4;
        status.case_state = Some(crate::account_recovery::CaseState::ReleasePending);
        publish_operator_status(
            &root,
            "alice@example.com",
            &status,
            metadata.uid(),
            metadata.gid(),
            102,
        )
        .unwrap();
        let record = Store::new(&root)
            .read_case("alice@example.com")
            .unwrap()
            .unwrap();
        assert_eq!(record.state, "manual_review");
        assert_eq!(record.account_state.as_deref(), Some("active"));
        assert_eq!(record.account_epoch, Some(4));
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn factor_metadata_uses_actual_bounded_store_and_preserves_account_replay_history() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "osmap-factor-metadata-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        for path in [&root, &root.join("factor"), &root.join("replay")] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let factors = FileTotpSecretStore::new(root.join("factor"));
        let factor = factors.secret_path_for_username("alice@example.com");
        std::fs::write(&factor, b"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n").unwrap();
        std::fs::set_permissions(&factor, std::fs::Permissions::from_mode(0o600)).unwrap();
        let replay = root.join("replay/616c696365406578616d706c652e636f6d.counter");
        std::fs::write(&replay, b"123\n").unwrap();
        std::fs::set_permissions(&replay, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = Store::new(root.join("account-recovery"));
        let read = || {
            snapshot(
                "alice@example.com",
                &root.join("factor"),
                &root.join("replay"),
                &store,
            )
        };
        assert!(read().unwrap().enrolled);
        assert_eq!(read().unwrap().last_accepted_counter, Some(123));
        std::fs::remove_file(&factor).unwrap();
        assert!(!read().unwrap().enrolled);
        assert_eq!(read().unwrap().last_accepted_counter, Some(123));
        std::fs::write(&replay, b"not-a-counter\n").unwrap();
        assert_eq!(read(), Err(Error::Unavailable));
        std::fs::write(&replay, b"123\n").unwrap();
        std::fs::write(&factor, vec![b'A'; 4097]).unwrap();
        std::fs::set_permissions(&factor, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(), Err(Error::Unavailable));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn completed_matching_case_allows_explicit_new_request_without_erasing_old_case() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let parent = std::env::temp_dir().join(format!(
            "osmap-repeat-request-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("account-recovery");
        let store = Store::new(&root);
        let first = store.request("alice@example.com", 0, 100).unwrap();
        let status = crate::account_recovery::Status {
            schema: "osmap-account-recovery-v1",
            account: "alice@example.com".into(),
            state: "active",
            epoch: 4,
            existing_factor_sha256: Some("b".repeat(64)),
            case_id: Some(first.case_id.clone()),
            case_state: Some(crate::account_recovery::CaseState::Reconciled),
            failure: None,
            session_failure: None,
        };
        let m = std::fs::metadata(&parent).unwrap();
        publish_operator_status(&root, "alice@example.com", &status, m.uid(), m.gid(), 120)
            .unwrap();
        let second = store.request("alice@example.com", 1, 130).unwrap();
        assert_ne!(first.case_id, second.case_id);
        assert_eq!(second.revision, 2);
        assert_eq!(second.state, "requested");
        assert_eq!(
            store
                .read_case("alice@example.com")
                .unwrap()
                .unwrap()
                .case_id,
            first.case_id
        );
        assert_eq!(store.request("alice@example.com", 2, 140).unwrap(), second);
        assert_eq!(
            store.request("alice@example.com", 1, 140),
            Err(Error::Refused)
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn privileged_publication_refuses_symlinked_root_or_cases_without_touching_target() {
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};
        let parent = std::env::temp_dir().join(format!(
            "osmap-publish-symlink-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let external = parent.join("external");
        std::fs::create_dir(&external).unwrap();
        std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(external.join("sentinel"), b"preserve external bytes").unwrap();
        let status = crate::account_recovery::Status {
            schema: "osmap-account-recovery-v1",
            account: "alice@example.com".into(),
            state: "pending",
            epoch: 3,
            existing_factor_sha256: Some("a".repeat(64)),
            case_id: Some("case-symlink-test".into()),
            case_state: Some(crate::account_recovery::CaseState::SessionsRevoked),
            failure: None,
            session_failure: None,
        };
        let m = std::fs::metadata(&parent).unwrap();
        let root = parent.join("account-recovery");
        symlink(&external, &root).unwrap();
        assert_eq!(
            publish_operator_status(&root, "alice@example.com", &status, m.uid(), m.gid(), 100),
            Err(Error::Unavailable)
        );
        std::fs::remove_file(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&external, root.join("cases")).unwrap();
        assert_eq!(
            publish_operator_status(&root, "alice@example.com", &status, m.uid(), m.gid(), 100),
            Err(Error::Unavailable)
        );
        assert_eq!(std::fs::metadata(&external).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(
            std::fs::read(external.join("sentinel")).unwrap(),
            b"preserve external bytes"
        );
        assert_eq!(std::fs::read_dir(&external).unwrap().count(), 1);
        std::fs::remove_dir_all(parent).unwrap();
    }
}
