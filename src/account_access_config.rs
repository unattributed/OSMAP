//! Fixed native recovery configuration reader. Shared OpenPGP/Web custody is
//! unchanged; this native reader can use pre-seal ancestor vnode witnesses.
use crate::account_password_custody::ancestor_metadata;
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(crate) const PATH: &str = "/etc/osmap/account-runtime/access-recovery.json";
const LIMIT: u64 = 32768;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Ancestor,
    Canonical,
    Open,
    Custody,
    Read,
    Changed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub stage: Stage,
    pub errno: Option<i32>,
}
impl Failure {
    fn refusal(stage: Stage) -> Self {
        Self { stage, errno: None }
    }
    fn io(stage: Stage, error: std::io::Error) -> Self {
        Self {
            stage,
            errno: error.raw_os_error().filter(|v| (1..4096).contains(v)),
        }
    }
}
type Identity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
fn identity(m: &fs::Metadata) -> Identity {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
pub(crate) fn read() -> Result<Option<Vec<u8>>, Failure> {
    read_path(Path::new(PATH), 0)
}
fn read_path(path: &Path, owner: u32) -> Result<Option<Vec<u8>>, Failure> {
    if !path.is_absolute() {
        return Err(Failure::refusal(Stage::Canonical));
    }
    for parent in path.ancestors().skip(1) {
        if parent == Path::new("/") {
            break;
        }
        let m = ancestor_metadata(parent).map_err(|e| Failure::io(Stage::Ancestor, e))?;
        let sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != 0 && m.uid() != owner)
            || (m.mode() & 0o022 != 0 && !sticky)
        {
            return Err(Failure::refusal(Stage::Ancestor));
        }
    }
    // Only a genuinely absent leaf disables this optional service. An absent
    // or changed ancestor never becomes a successful "not configured" result.
    let initial = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Failure::io(Stage::Open, e)),
    };
    if !initial.is_file() || initial.file_type().is_symlink() {
        return Err(Failure::refusal(Stage::Custody));
    }
    if fs::canonicalize(path).map_err(|e| Failure::io(Stage::Canonical, e))? != path {
        return Err(Failure::refusal(Stage::Canonical));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| Failure::io(Stage::Open, e))?;
    read_opened(path, &mut file, &initial, owner).map(Some)
}
fn read_opened(
    path: &Path,
    file: &mut File,
    initial: &fs::Metadata,
    owner: u32,
) -> Result<Vec<u8>, Failure> {
    let before = file
        .metadata()
        .map_err(|e| Failure::io(Stage::Custody, e))?;
    if !before.is_file()
        || before.uid() != owner
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() > LIMIT
    {
        return Err(Failure::refusal(Stage::Custody));
    }
    if identity(&before) != identity(initial) {
        return Err(Failure::refusal(Stage::Changed));
    }
    let mut bytes = Vec::new();
    (&mut *file)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Failure::io(Stage::Read, e))?;
    let after = file
        .metadata()
        .map_err(|e| Failure::io(Stage::Changed, e))?;
    let leaf = fs::symlink_metadata(path).map_err(|e| Failure::io(Stage::Changed, e))?;
    if bytes.len() as u64 > LIMIT
        || bytes.len() as u64 != before.len()
        || identity(&before) != identity(&after)
        || identity(&before) != identity(&leaf)
    {
        return Err(Failure::refusal(Stage::Changed));
    }
    Ok(bytes)
}

/// Sole native-test seam: the same reader under real confinement, limited to
/// the already admitted disposable fixture. Absent from application binaries.
#[cfg(test)]
pub(crate) fn read_native_fixture(path: &Path) -> Result<Option<Vec<u8>>, Failure> {
    let root = path
        .parent()
        .ok_or_else(|| Failure::refusal(Stage::Ancestor))?;
    if !crate::openbsd::password_native_authority()
        || root.parent() != Some(Path::new("/tmp"))
        || !root
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("osmap-factor-"))
        || path.file_name() != Some(std::ffi::OsStr::new("access-config.fixture.json"))
    {
        return Err(Failure::refusal(Stage::Ancestor));
    }
    let m = fs::symlink_metadata(root).map_err(|e| Failure::io(Stage::Ancestor, e))?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err(Failure::refusal(Stage::Ancestor));
    }
    read_path(path, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "osmap-config-reader-{}",
                crate::draft::generate_draft_id().unwrap()
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("config.json")
        }
        fn write(&self) {
            fs::write(self.path(), b"{\"version\":1,\"contacts\":[]}\n").unwrap();
            fs::set_permissions(self.path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn read(&self) -> Result<Option<Vec<u8>>, Failure> {
            read_path(&self.path(), crate::openbsd::effective_uid())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn private_regular_config_and_genuine_leaf_absence_use_actual_reader() {
        let f = Fixture::new();
        assert_eq!(f.read(), Ok(None));
        f.write();
        assert!(f.read().unwrap().is_some());
        assert_eq!(
            read_path(
                &f.0.join("missing-parent/config.json"),
                crate::openbsd::effective_uid()
            )
            .unwrap_err()
            .stage,
            Stage::Ancestor
        );
    }
    #[test]
    fn changed_mode_links_size_and_symlink_refuse_without_adopting_new_bytes() {
        let f = Fixture::new();
        f.write();
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(f.read().unwrap_err().stage, Stage::Custody);
        f.write();
        let link = f.0.join("hardlink");
        fs::hard_link(f.path(), &link).unwrap();
        assert_eq!(f.read().unwrap_err().stage, Stage::Custody);
        fs::remove_file(link).unwrap();
        fs::write(f.path(), vec![b'x'; LIMIT as usize + 1]).unwrap();
        assert_eq!(f.read().unwrap_err().stage, Stage::Custody);
        fs::remove_file(f.path()).unwrap();
        symlink("missing-target", f.path()).unwrap();
        assert_eq!(f.read().unwrap_err().stage, Stage::Custody);
    }
    #[test]
    fn actual_open_descriptor_refuses_replaced_namespace_and_mode() {
        let f = Fixture::new();
        f.write();
        let mut held = File::open(f.path()).unwrap();
        let before = held.metadata().unwrap();
        fs::rename(f.path(), f.0.join("old")).unwrap();
        f.write();
        assert_eq!(
            read_opened(
                &f.path(),
                &mut held,
                &before,
                crate::openbsd::effective_uid()
            )
            .unwrap_err()
            .stage,
            Stage::Changed
        );
        fs::set_permissions(f.0.join("old"), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            read_opened(
                &f.path(),
                &mut held,
                &before,
                crate::openbsd::effective_uid()
            )
            .unwrap_err()
            .stage,
            Stage::Custody
        );
    }
}
