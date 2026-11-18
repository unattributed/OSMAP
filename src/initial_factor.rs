//! Native first-factor installation for an already authorized mailbox owner.
//!
//! The caller owns the one-use invitation, proved TOTP code, account lock and
//! pending-account transition. This module only publishes the proved factor
//! and its consumed replay counter into the existing runtime file formats.
use crate::totp::{decode_base32, encode_base32, MIN_TOTP_SECRET_BYTES};
use sha2::{Digest as _, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Expired,
    Refused,
    Unavailable,
    /// A private file may have been created. Retain it for exact reconciliation.
    Unconfirmed,
}
impl Error {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Expired => "expired",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
            Self::Unconfirmed => "unconfirmed",
        }
    }
}

pub(crate) struct Paths {
    pub(crate) factors: PathBuf,
    pub(crate) replay: PathBuf,
    pub(crate) runtime_uid: u32,
    pub(crate) runtime_gid: u32,
}

pub(crate) struct InitialFactor {
    paths: Paths,
}

impl InitialFactor {
    pub(crate) fn new(paths: Paths) -> Self {
        Self { paths }
    }

    pub(crate) fn check_paths(&self) -> Result<(), Error> {
        self.check_principal()?;
        let factors = Directory::open(
            &self.paths.factors,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )?;
        let replay = Directory::open(
            &self.paths.replay,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )?;
        if (factors.dev, factors.ino) == (replay.dev, replay.ino) {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Custody-checked readiness only. The installer repeats this test while
    /// publishing; a readiness reply grants no installation authority.
    pub(crate) fn check_absent(&self, account: &str, deadline: Instant) -> Result<(), Error> {
        before(deadline)?;
        crate::account_admission::valid_account(account).map_err(|_| Error::Invalid)?;
        self.check_principal()?;
        let factors = Directory::open(
            &self.paths.factors,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )?;
        let replay = Directory::open(
            &self.paths.replay,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )?;
        if (factors.dev, factors.ino) == (replay.dev, replay.ino) {
            return Err(Error::Invalid);
        }
        before(deadline)?;
        let leaf = format!("{}.totp", hex(account.as_bytes()));
        let counter_leaf = format!("{}.counter", hex(account.as_bytes()));
        let (factor_temp, replay_temp) = temp_names(account);
        if factors.exists(&leaf)?
            || replay.exists(&counter_leaf)?
            || factors.exists(&factor_temp)?
            || replay.exists(&replay_temp)?
        {
            return Err(Error::Refused);
        }
        Ok(())
    }

    fn check_principal(&self) -> Result<(), Error> {
        if self.paths.factors == self.paths.replay
            || (!cfg!(test) && (self.paths.runtime_uid == 0 || self.paths.runtime_gid == 0))
            || self.paths.runtime_uid == u32::MAX
            || self.paths.runtime_gid == u32::MAX
        {
            return Err(Error::Invalid);
        }
        let caller = crate::openbsd::effective_uid();
        if caller != 0 && !(cfg!(test) && caller == self.paths.runtime_uid) {
            return Err(Error::Refused);
        }
        Ok(())
    }

    /// Only a trusted native caller may supply a secret and accepted counter.
    /// Factor publication is last; any interrupted installation remains denied
    /// and is never retried by overwriting either final file.
    pub(crate) fn install(
        &self,
        account: &str,
        secret_base32: &str,
        accepted_counter: u64,
        deadline: Instant,
    ) -> Result<(), Error> {
        before(deadline)?;
        crate::account_admission::valid_account(account).map_err(|_| Error::Invalid)?;
        self.check_principal()?;
        let secret = decode_base32(secret_base32).map_err(|_| Error::Invalid)?;
        if secret.len() != MIN_TOTP_SECRET_BYTES
            || encode_base32(&secret) != secret_base32
            || secret_base32.len() > 64
        {
            return Err(Error::Invalid);
        }
        let leaf = format!("{}.totp", hex(account.as_bytes()));
        let counter_leaf = format!("{}.counter", hex(account.as_bytes()));
        let (factor_temp, replay_temp) = temp_names(account);
        let factor_bytes = format!("# {account}\nsecret={secret_base32}\n").into_bytes();
        let replay_bytes = format!("{accepted_counter}\n").into_bytes();
        let factors = Directory::open(
            &self.paths.factors,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )?;
        let replay = Directory::open(
            &self.paths.replay,
            self.paths.runtime_uid,
            self.paths.runtime_gid,
        )?;
        if (factors.dev, factors.ino) == (replay.dev, replay.ino) {
            return Err(Error::Invalid);
        }
        before(deadline)?;
        if factors.exists(&leaf)?
            || replay.exists(&counter_leaf)?
            || factors.exists(&factor_temp)?
            || replay.exists(&replay_temp)?
        {
            return Err(Error::Refused);
        }

        // From the first create onward, failure may leave retained private
        // state. Never turn a later failure into a safe-to-retry refusal.
        replay.write_new(&replay_temp, &replay_bytes)?;
        before(deadline).map_err(|_| Error::Unconfirmed)?;
        replay
            .publish(&replay_temp, &counter_leaf, &replay_bytes)
            .map_err(|_| Error::Unconfirmed)?;
        before(deadline).map_err(|_| Error::Unconfirmed)?;
        factors
            .write_new(&factor_temp, &factor_bytes)
            .map_err(|_| Error::Unconfirmed)?;
        before(deadline).map_err(|_| Error::Unconfirmed)?;
        if replay.read(&counter_leaf).map_err(|_| Error::Unconfirmed)? != replay_bytes {
            return Err(Error::Unconfirmed);
        }
        factors
            .publish(&factor_temp, &leaf, &factor_bytes)
            .map_err(|_| Error::Unconfirmed)?;
        before(deadline).map_err(|_| Error::Unconfirmed)?;
        if replay.read(&counter_leaf).map_err(|_| Error::Unconfirmed)? != replay_bytes
            || factors.read(&leaf).map_err(|_| Error::Unconfirmed)? != factor_bytes
        {
            return Err(Error::Unconfirmed);
        }
        Ok(())
    }
}

fn before(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn temp_names(account: &str) -> (String, String) {
    let key = format!("{:x}", Sha256::digest(account.as_bytes()));
    (
        format!(".initial-{key}.totp.tmp"),
        format!(".initial-{key}.counter.tmp"),
    )
}

struct Directory {
    path: PathBuf,
    fd: File,
    owner: u32,
    group: u32,
    dev: u64,
    ino: u64,
}

impl Directory {
    fn open(path: &Path, owner: u32, group: u32) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::Invalid);
        }
        for (index, ancestor) in path.ancestors().enumerate() {
            let m = if index == 0 {
                fs::symlink_metadata(ancestor)
            } else {
                crate::account_password_custody::ancestor_metadata(ancestor)
            }
            .map_err(|_| Error::Unavailable)?;
            let sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
            if !m.is_dir()
                || m.file_type().is_symlink()
                || (m.uid() != 0 && m.uid() != owner)
                || (m.mode() & 0o022 != 0 && !sticky)
            {
                return Err(Error::Unavailable);
            }
        }
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error::Unavailable)?;
        let m = fd.metadata().map_err(|_| Error::Unavailable)?;
        if !m.is_dir() || m.uid() != owner || m.gid() != group || m.mode() & 0o7777 != 0o700 {
            return Err(Error::Unavailable);
        }
        let directory = Self {
            path: path.into(),
            fd,
            owner,
            group,
            dev: m.dev(),
            ino: m.ino(),
        };
        directory.check()?;
        Ok(directory)
    }

    fn check(&self) -> Result<(), Error> {
        let path = fs::symlink_metadata(&self.path).map_err(|_| Error::Unavailable)?;
        let fd = self.fd.metadata().map_err(|_| Error::Unavailable)?;
        if !path.is_dir()
            || path.file_type().is_symlink()
            || (
                path.dev(),
                path.ino(),
                path.uid(),
                path.gid(),
                path.mode() & 0o7777,
            ) != (self.dev, self.ino, self.owner, self.group, 0o700)
            || (fd.dev(), fd.ino(), fd.uid(), fd.gid(), fd.mode() & 0o7777)
                != (self.dev, self.ino, self.owner, self.group, 0o700)
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    fn exists(&self, name: &str) -> Result<bool, Error> {
        self.check()?;
        let name = CString::new(name).map_err(|_| Error::Invalid)?;
        crate::openbsd::private_leaf_exists(&self.fd, &name).map_err(|_| Error::Unavailable)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, Error> {
        self.check()?;
        let name = CString::new(name).map_err(|_| Error::Invalid)?;
        let mut file = crate::openbsd::private_leaf_open(&self.fd, &name, libc::O_RDONLY)
            .map_err(|_| Error::Unconfirmed)?;
        let m = file.metadata().map_err(|_| Error::Unconfirmed)?;
        if !m.is_file()
            || m.uid() != self.owner
            || m.gid() != self.group
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() == 0
            || m.len() > 4096
        {
            return Err(Error::Unconfirmed);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unconfirmed)?;
        let after = file.metadata().map_err(|_| Error::Unconfirmed)?;
        if bytes.len() as u64 != m.len()
            || (
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
                m.nlink(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
                after.nlink(),
            )
        {
            return Err(Error::Unconfirmed);
        }
        self.check().map_err(|_| Error::Unconfirmed)?;
        Ok(bytes)
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        self.check()?;
        let name = CString::new(name).map_err(|_| Error::Invalid)?;
        let mut file = crate::openbsd::private_leaf_open(
            &self.fd,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| Error::Unconfirmed)?;
        crate::openbsd::private_file_set_owner(&file, self.owner, self.group)
            .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o600)))
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all())
            .and_then(|()| self.fd.sync_all())
            .map_err(|_| Error::Unconfirmed)?;
        self.read(name.to_str().map_err(|_| Error::Unconfirmed)?)
            .and_then(|actual| {
                if actual == bytes {
                    Ok(())
                } else {
                    Err(Error::Unconfirmed)
                }
            })
    }

    fn publish(&self, temporary: &str, final_name: &str, bytes: &[u8]) -> Result<(), Error> {
        self.check()?;
        if self.read(temporary)? != bytes {
            return Err(Error::Unconfirmed);
        }
        let temporary = CString::new(temporary).map_err(|_| Error::Unconfirmed)?;
        let final_name = CString::new(final_name).map_err(|_| Error::Unconfirmed)?;
        // Both names are single components beneath the same pinned directory.
        // linkat refuses an existing final leaf instead of replacing it.
        crate::openbsd::private_leaf_link(&self.fd, &temporary, &final_name)
            .map_err(|_| Error::Unconfirmed)?;
        self.fd.sync_all().map_err(|_| Error::Unconfirmed)?;
        crate::openbsd::private_leaf_unlink(&self.fd, &temporary)
            .and_then(|()| self.fd.sync_all())
            .map_err(|_| Error::Unconfirmed)?;
        if self.read(final_name.to_str().map_err(|_| Error::Unconfirmed)?)? != bytes {
            return Err(Error::Unconfirmed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::{FileTotpSecretStore, TotpSecretStore};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    const ACCOUNT: &str = "alice@example.test";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        factors: PathBuf,
        replay: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "osmap-initial-factor-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let factors = root.join("factors");
            let replay = root.join("replay");
            let mut builder = fs::DirBuilder::new();
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
            builder.create(&root).unwrap();
            builder.create(&factors).unwrap();
            builder.create(&replay).unwrap();
            Self {
                root,
                factors,
                replay,
            }
        }
        fn installer(&self) -> InitialFactor {
            InitialFactor::new(Paths {
                factors: self.factors.clone(),
                replay: self.replay.clone(),
                runtime_uid: crate::openbsd::effective_uid(),
                runtime_gid: crate::openbsd::effective_gid(),
            })
        }
        fn deadline() -> Instant {
            Instant::now() + Duration::from_secs(5)
        }
        fn factor_leaf(&self) -> PathBuf {
            self.factors
                .join(format!("{}.totp", hex(ACCOUNT.as_bytes())))
        }
        fn replay_leaf(&self) -> PathBuf {
            self.replay
                .join(format!("{}.counter", hex(ACCOUNT.as_bytes())))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "INITIAL_FACTOR_FIXTURE_RETAINED root={}",
                    self.root.display()
                );
            } else {
                fs::remove_dir_all(&self.root).unwrap();
            }
        }
    }

    fn secret() -> String {
        encode_base32(b"0123456789abcdefghij")
    }

    #[test]
    fn installs_only_missing_factor_with_consumed_counter() {
        let f = Fixture::new();
        f.installer()
            .install(ACCOUNT, &secret(), 1234, Fixture::deadline())
            .unwrap();
        let store = FileTotpSecretStore::new(&f.factors).with_replay_dir(&f.replay);
        assert_eq!(
            store.load_secret(ACCOUNT).unwrap().unwrap().secret_bytes,
            b"0123456789abcdefghij"
        );
        assert!(!store.consume_counter(ACCOUNT, 1234).unwrap());
        assert!(store.consume_counter(ACCOUNT, 1235).unwrap());
        assert_eq!(
            f.installer()
                .install(ACCOUNT, &secret(), 1234, Fixture::deadline()),
            Err(Error::Refused)
        );
        assert_eq!(fs::symlink_metadata(f.factor_leaf()).unwrap().nlink(), 1);
        assert_eq!(fs::symlink_metadata(f.replay_leaf()).unwrap().nlink(), 1);
    }

    #[test]
    fn existing_factor_replay_or_symlink_refuses_before_publication() {
        for kind in ["factor", "replay", "factor_symlink", "replay_symlink"] {
            let f = Fixture::new();
            let leaf = if kind.starts_with("factor") {
                f.factor_leaf()
            } else {
                f.replay_leaf()
            };
            if kind.ends_with("symlink") {
                std::os::unix::fs::symlink("missing", &leaf).unwrap();
            } else {
                fs::write(&leaf, b"existing").unwrap();
            }
            assert_eq!(
                f.installer()
                    .install(ACCOUNT, &secret(), 2, Fixture::deadline()),
                Err(Error::Refused),
                "{kind}"
            );
            if kind.starts_with("factor") {
                assert!(fs::symlink_metadata(f.replay_leaf()).is_err());
            } else {
                assert!(fs::symlink_metadata(f.factor_leaf()).is_err());
            }
        }
    }

    #[test]
    fn retained_replay_without_factor_is_not_reinstalled() {
        let f = Fixture::new();
        // A crash after the first final publication leaves this exact state.
        fs::write(f.replay_leaf(), b"8\n").unwrap();
        assert_eq!(
            f.installer()
                .install(ACCOUNT, &secret(), 8, Fixture::deadline()),
            Err(Error::Refused)
        );
        assert!(fs::symlink_metadata(f.factor_leaf()).is_err());
    }

    #[test]
    fn retained_temporary_file_blocks_a_new_invitation_or_install() {
        for factor_side in [false, true] {
            let f = Fixture::new();
            let (factor_temp, replay_temp) = temp_names(ACCOUNT);
            let temporary = if factor_side {
                f.factors.join(factor_temp)
            } else {
                f.replay.join(replay_temp)
            };
            fs::write(temporary, b"retained").unwrap();
            assert_eq!(
                f.installer().check_absent(ACCOUNT, Fixture::deadline()),
                Err(Error::Refused)
            );
            assert_eq!(
                f.installer()
                    .install(ACCOUNT, &secret(), 8, Fixture::deadline()),
                Err(Error::Refused)
            );
            assert!(fs::symlink_metadata(f.factor_leaf()).is_err());
        }
    }

    #[test]
    fn invalid_or_expired_proof_never_creates_private_state() {
        let f = Fixture::new();
        assert_eq!(
            f.installer()
                .install(ACCOUNT, "invalid", 1, Fixture::deadline()),
            Err(Error::Invalid)
        );
        assert_eq!(
            f.installer().install(ACCOUNT, &secret(), 1, Instant::now()),
            Err(Error::Expired)
        );
        assert_eq!(fs::read_dir(&f.factors).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&f.replay).unwrap().count(), 0);
    }
}
