//! Read-only OpenBSD FFS user-quota observation for a trusted account mapping.
//! This never enables or changes quotas. Mail index/control storage must be on
//! another device so quota exhaustion cannot prevent reconciliation metadata.
use crate::documents::{Error, QuotaStatus};
use std::ffi::OsString;
use std::path::Path;

const WORKER_OUTPUT_MAX: usize = 128;
const WORKER_PATH_MAX: usize = 1024;

struct WorkerArguments<'a> {
    data_home: &'a Path,
    account_uid: u32,
    expected_bytes: u64,
    expected_mount: &'a Path,
    mail_index_dir: &'a Path,
    mail_control_dir: &'a Path,
}

fn worker_arguments(arguments: &[OsString]) -> Result<WorkerArguments<'_>, Error> {
    if arguments.len() != 6 {
        return Err(Error::Invalid);
    }
    for argument in arguments {
        let value = argument.to_str().ok_or(Error::Invalid)?;
        if value.is_empty() || value.len() > WORKER_PATH_MAX || value.chars().any(char::is_control)
        {
            return Err(Error::Invalid);
        }
    }
    let uid = arguments[1].to_str().ok_or(Error::Invalid)?;
    let account_uid = uid.parse::<u32>().map_err(|_| Error::Invalid)?;
    if account_uid.to_string() != uid || quota_uid(account_uid).is_err() {
        return Err(Error::Invalid);
    }
    let bytes = arguments[2].to_str().ok_or(Error::Invalid)?;
    let expected_bytes = bytes.parse::<u64>().map_err(|_| Error::Invalid)?;
    if expected_bytes.to_string() != bytes
        || expected_bytes == 0
        || expected_bytes % DEVICE_BLOCK_BYTES != 0
        || expected_bytes / DEVICE_BLOCK_BYTES > u64::from(u32::MAX)
    {
        return Err(Error::Invalid);
    }
    for position in [0, 3, 4, 5] {
        let path = Path::new(&arguments[position]);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(Error::Invalid);
        }
    }
    Ok(WorkerArguments {
        data_home: Path::new(&arguments[0]),
        account_uid,
        expected_bytes,
        expected_mount: Path::new(&arguments[3]),
        mail_index_dir: Path::new(&arguments[4]),
        mail_control_dir: Path::new(&arguments[5]),
    })
}

fn encode_status(status: QuotaStatus) -> Result<Vec<u8>, Error> {
    if status.limit_bytes == 0 {
        return Err(Error::Unavailable);
    }
    let mut bytes = serde_json::to_vec(&status).map_err(|_| Error::Unavailable)?;
    if bytes.len() >= WORKER_OUTPUT_MAX {
        return Err(Error::Unavailable);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

/// Fixed read-only worker entry for the already confined mailbox helper.
/// Its arguments are operator-controlled native userdb values, not HTTP input.
pub fn worker(arguments: &[OsString]) -> Result<Vec<u8>, Error> {
    let arguments = worker_arguments(arguments)?;
    #[cfg(unix)]
    if crate::openbsd::real_uid() != arguments.account_uid
        || crate::openbsd::effective_uid() != arguments.account_uid
    {
        return Err(Error::Unavailable);
    }
    encode_status(probe(
        arguments.data_home,
        arguments.account_uid,
        arguments.expected_bytes,
        arguments.expected_mount,
        arguments.mail_index_dir,
        arguments.mail_control_dir,
    )?)
}

pub(crate) fn probe(
    data_home: &Path,
    account_uid: u32,
    expected_bytes: u64,
    expected_mount: &Path,
    mail_index_dir: &Path,
    mail_control_dir: &Path,
) -> Result<QuotaStatus, Error> {
    #[cfg(target_os = "openbsd")]
    {
        native::probe(
            data_home,
            account_uid,
            expected_bytes,
            expected_mount,
            mail_index_dir,
            mail_control_dir,
        )
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = (
            data_home,
            account_uid,
            expected_bytes,
            expected_mount,
            mail_index_dir,
            mail_control_dir,
        );
        Err(Error::Unavailable)
    }
}

const DEVICE_BLOCK_BYTES: u64 = 512;

/// Native quota.h order: block hard/soft/current, inode hard/soft/current,
/// block grace expiry and inode grace expiry. All eight members are u32.
#[cfg(any(target_os = "openbsd", test))]
#[repr(C)]
#[derive(Default)]
struct DiskQuota {
    fields: [u32; 8],
}

fn quota_uid(uid: u32) -> Result<libc::c_int, Error> {
    if uid == 0 {
        return Err(Error::Unavailable);
    }
    libc::c_int::try_from(uid).map_err(|_| Error::Unavailable)
}

#[cfg(any(target_os = "openbsd", test))]
fn blocks_to_bytes(blocks: u64) -> Result<u64, Error> {
    blocks
        .checked_mul(DEVICE_BLOCK_BYTES)
        .ok_or(Error::Unavailable)
}

#[cfg(any(target_os = "openbsd", test))]
fn quota_status(quota: &DiskQuota, expected_bytes: u64) -> Result<QuotaStatus, Error> {
    let [hard, soft, used, _, _, _, _, _] = quota.fields;
    if hard == 0 || (soft != 0 && soft != hard) {
        return Err(Error::Unavailable);
    }
    let limit_bytes = blocks_to_bytes(u64::from(hard))?;
    if expected_bytes != limit_bytes {
        return Err(Error::Unavailable);
    }
    Ok(QuotaStatus {
        used_bytes: blocks_to_bytes(u64::from(used))?,
        limit_bytes,
    })
}

#[cfg(any(target_os = "openbsd", test))]
#[derive(Clone, Copy)]
struct DirectoryFacts {
    device: u64,
    owner: u32,
    canonical: bool,
    directory: bool,
    symlink: bool,
}

#[cfg(any(target_os = "openbsd", test))]
fn directory_layout(
    uid: u32,
    data: DirectoryFacts,
    index: DirectoryFacts,
    control: DirectoryFacts,
) -> Result<(), Error> {
    quota_uid(uid)?;
    if [data, index, control].iter().any(|directory| {
        directory.owner != uid || !directory.canonical || !directory.directory || directory.symlink
    }) || data.device == index.device
        || data.device == control.device
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

#[cfg(any(target_os = "openbsd", test))]
fn mount_matches(
    data_home: &Path,
    actual_mount: &Path,
    expected_mount: &Path,
) -> Result<(), Error> {
    if !expected_mount.is_absolute()
        || actual_mount != expected_mount
        || !data_home.starts_with(expected_mount)
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
mod native {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;

    struct Directory {
        path: PathBuf,
        file: File,
        facts: DirectoryFacts,
        inode: u64,
    }

    impl Directory {
        fn open(path: &Path) -> Result<Self, Error> {
            if !path.is_absolute()
                || fs::canonicalize(path).map_err(|_| Error::Unavailable)? != path
            {
                return Err(Error::Unavailable);
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| Error::Unavailable)?;
            let metadata = file.metadata().map_err(|_| Error::Unavailable)?;
            let result = Self {
                path: path.to_owned(),
                file,
                inode: metadata.ino(),
                facts: DirectoryFacts {
                    device: metadata.dev(),
                    owner: metadata.uid(),
                    canonical: true,
                    directory: metadata.is_dir(),
                    symlink: false,
                },
            };
            result.revalidate()?;
            Ok(result)
        }

        fn revalidate(&self) -> Result<(), Error> {
            let metadata = fs::symlink_metadata(&self.path).map_err(|_| Error::Unavailable)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || (metadata.dev(), metadata.ino(), metadata.uid())
                    != (self.facts.device, self.inode, self.facts.owner)
                || fs::canonicalize(&self.path).map_err(|_| Error::Unavailable)? != self.path
            {
                return Err(Error::Unavailable);
            }
            Ok(())
        }

        fn mount(&self) -> Result<PathBuf, Error> {
            let (mount, _) =
                crate::openbsd::ffs_mount_info(&self.file).map_err(|_| Error::Unavailable)?;
            if !mount.is_absolute() || !self.path.starts_with(&mount) {
                return Err(Error::Unavailable);
            }
            Ok(mount)
        }
    }

    pub(super) fn probe(
        data_home: &Path,
        account_uid: u32,
        expected_bytes: u64,
        expected_mount: &Path,
        mail_index_dir: &Path,
        mail_control_dir: &Path,
    ) -> Result<QuotaStatus, Error> {
        quota_uid(account_uid)?;
        let data = Directory::open(data_home)?;
        let index = Directory::open(mail_index_dir)?;
        let control = Directory::open(mail_control_dir)?;
        directory_layout(account_uid, data.facts, index.facts, control.facts)?;
        let mount_path = data.mount()?;
        mount_matches(data_home, &mount_path, expected_mount)?;
        // The expected mount is trusted account configuration, never a request
        // field. Its mounted root may be root-owned rather than account-owned.
        let mount = Directory::open(expected_mount)?;
        if mount.facts.device != data.facts.device || mount.mount()? != mount_path {
            return Err(Error::Unavailable);
        }
        let quota = DiskQuota {
            fields: crate::openbsd::read_user_quota(&mount_path, account_uid)
                .map_err(|_| Error::Unavailable)?,
        };
        let result = quota_status(&quota, expected_bytes)?;
        for directory in [&data, &index, &control, &mount] {
            directory.revalidate()?;
        }
        if data.mount()? != mount_path {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker_args() -> Vec<OsString> {
        [
            "/mail/alice/Maildir",
            "2000",
            "102400000",
            "/mail/alice",
            "/state/index",
            "/state/control",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn worker_accepts_only_six_bounded_native_arguments() {
        let args = worker_args();
        let parsed = worker_arguments(&args).unwrap();
        assert_eq!(parsed.account_uid, 2000);
        assert_eq!(parsed.expected_bytes, 102400000);
        assert_eq!(parsed.expected_mount, Path::new("/mail/alice"));
        for count in 0..6 {
            assert!(worker_arguments(&args[..count]).is_err());
        }
        let mut extra = args.clone();
        extra.push("extra".into());
        assert!(worker_arguments(&extra).is_err());
        for (position, value) in [
            (0, "relative"),
            (0, "/mail/../other"),
            (1, "0"),
            (1, "02000"),
            (1, "4294967295"),
            (1, "2000\n"),
            (2, "0"),
            (2, "1000"),
            (2, "18446744073709551615"),
            (3, "relative"),
            (4, "/state\nindex"),
            (5, ""),
        ] {
            let mut changed = args.clone();
            changed[position] = value.into();
            assert!(worker_arguments(&changed).is_err());
        }
        for position in 0..6 {
            let mut changed = args.clone();
            changed[position] = "x".repeat(WORKER_PATH_MAX + 1).into();
            assert!(worker_arguments(&changed).is_err());
        }
    }

    #[test]
    fn worker_status_bytes_roundtrip_through_strict_existing_consumer() {
        let status = QuotaStatus {
            used_bytes: u64::MAX,
            limit_bytes: u64::MAX,
        };
        let bytes = encode_status(status).unwrap();
        assert!(bytes.len() <= WORKER_OUTPUT_MAX);
        assert!(bytes.ends_with(b"\n"));
        assert_eq!(
            serde_json::from_slice::<QuotaStatus>(&bytes).unwrap(),
            status
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert!(serde_json::from_slice::<QuotaStatus>(
            b"{\"used_bytes\":1,\"limit_bytes\":2,\"ready\":true}"
        )
        .is_err());
        assert!(encode_status(QuotaStatus {
            used_bytes: 0,
            limit_bytes: 0
        })
        .is_err());
    }

    #[test]
    fn native_record_layout_units_bounds_and_soft_hard_validation() {
        assert_eq!(std::mem::size_of::<DiskQuota>(), 32);
        assert_eq!(std::mem::align_of::<DiskQuota>(), 4);
        let record = |hard, soft, used| DiskQuota {
            fields: [hard, soft, used, 4, 5, 6, 7, 8],
        };
        for soft in [0, 200000] {
            assert_eq!(
                quota_status(&record(200000, soft, 3), 102400000),
                Ok(QuotaStatus {
                    used_bytes: 1536,
                    limit_bytes: 102400000
                })
            );
        }
        for (hard, soft, expected) in [
            (0, 0, 0),
            (2, 1, 1024),
            (2, 3, 1024),
            (2, 0, 1000),
            (2, 0, 0),
        ] {
            assert_eq!(
                quota_status(&record(hard, soft, 1), expected),
                Err(Error::Unavailable)
            );
        }
        assert_eq!(
            quota_status(&record(1, 0, 3), 512).unwrap().used_bytes,
            1536
        );
        let maximum = u64::from(u32::MAX) * 512;
        assert_eq!(
            quota_status(&record(u32::MAX, 0, u32::MAX), maximum),
            Ok(QuotaStatus {
                used_bytes: maximum,
                limit_bytes: maximum
            })
        );
        assert_eq!(blocks_to_bytes(u64::MAX), Err(Error::Unavailable));
        for uid in [0, u32::MAX, i32::MAX as u32 + 1] {
            assert_eq!(quota_uid(uid), Err(Error::Unavailable));
        }
        assert_eq!(quota_uid(2000), Ok(2000));
    }

    #[test]
    fn directory_facts_require_owned_canonical_separate_storage() {
        let data = DirectoryFacts {
            device: 1,
            owner: 2000,
            canonical: true,
            directory: true,
            symlink: false,
        };
        let metadata = DirectoryFacts { device: 2, ..data };
        assert_eq!(directory_layout(2000, data, metadata, metadata), Ok(()));
        for bad in [
            DirectoryFacts {
                owner: 0,
                ..metadata
            },
            DirectoryFacts {
                canonical: false,
                ..metadata
            },
            DirectoryFacts {
                directory: false,
                ..metadata
            },
            DirectoryFacts {
                symlink: true,
                ..metadata
            },
            DirectoryFacts {
                device: 1,
                ..metadata
            },
        ] {
            assert_eq!(
                directory_layout(2000, data, bad, metadata),
                Err(Error::Unavailable)
            );
            assert_eq!(
                directory_layout(2000, data, metadata, bad),
                Err(Error::Unavailable)
            );
        }
        assert_eq!(
            directory_layout(0, data, metadata, metadata),
            Err(Error::Unavailable)
        );
        assert_eq!(
            directory_layout(
                2000,
                DirectoryFacts {
                    owner: 1000,
                    ..data
                },
                metadata,
                metadata
            ),
            Err(Error::Unavailable)
        );
    }

    #[test]
    fn trusted_mount_must_match_exactly_and_contain_the_data_path() {
        let expected = Path::new("/mail/alice");
        assert_eq!(
            mount_matches(Path::new("/mail/alice/Maildir"), expected, expected),
            Ok(())
        );
        assert_eq!(mount_matches(expected, expected, expected), Ok(()));
        for (home, actual, expected) in [
            ("/mail/alice/Maildir", "/mail", "/mail/alice"),
            ("/mail/alice/Maildir", "/mail/alice", "/mail/bob"),
            ("/mail/alice-other/Maildir", "/mail/alice", "/mail/alice"),
            ("/mail/alice/Maildir", "mail/alice", "mail/alice"),
        ] {
            assert_eq!(
                mount_matches(Path::new(home), Path::new(actual), Path::new(expected)),
                Err(Error::Unavailable)
            );
        }
    }

    #[cfg(not(target_os = "openbsd"))]
    #[test]
    fn other_platforms_never_claim_kernel_quota() {
        assert_eq!(
            probe(
                Path::new("/"),
                2000,
                102400000,
                Path::new("/"),
                Path::new("/"),
                Path::new("/")
            ),
            Err(Error::Unavailable)
        );
    }
}
