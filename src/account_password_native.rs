//! Fixed child-role custody for authoritative password utilities. Public pins
//! are transcribed from the existing reviewed installed graphs. No provision,
//! permission repair, host discovery or production activation occurs here.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

#[path = "account_password_native_pins.rs"]
mod pins;

#[cfg(test)]
pub(crate) const NATIVE_QUALIFIED: bool = false;
// Filesystem owner518 is not a kernel binder observation. Preserve the actual
// existing source refusal until the private listener peer is qualified.
#[cfg(test)]
const PRIMARY_PEER_UID: Option<u32> = None;
#[cfg(test)]
const CONTROL_PEER_UID: Option<u32> = None;
const CONTROL_AUTH: &str = "/var/dovecot/osmap-account-auth-master";
const CONTROL_ANVIL: &str = "/var/dovecot/osmap-account-anvil";
const SQL_CONFIG: &str = "/etc/osmap/account-mariadb.cnf";
const SQL_PLAN: &str = "/etc/osmap/account-runtime/sql-endpoint.json";
const SQL_SOCKET: &str = "/var/run/mysql/mysql.sock";
const PRIMARY_SOCKET: &str = "/var/dovecot/osmap-account-auth-client";
const FILE_CAP: u64 = 64 * 1024 * 1024;
const TOTAL_CAP: u64 = 128 * 1024 * 1024;

type Fingerprint = [u64; 9];
type Ancestry = Vec<(String, [u64; 5])>;
type Endpoint = (String, Fingerprint, Ancestry);
struct ParentPin {
    path: &'static str,
    identity: [u64; 5],
}
struct FilePin {
    path: &'static str,
    identity: Fingerprint,
    sha256: &'static str,
    parents: &'static [ParentPin],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Sql,
    Hash,
    Primary,
    Control,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unavailable;
fn unavailable<T>(_: T) -> Unavailable {
    Unavailable
}
fn before(deadline: Instant) -> Result<(), Unavailable> {
    if Instant::now() >= deadline {
        Err(Unavailable)
    } else {
        Ok(())
    }
}
fn fingerprint(m: &fs::Metadata) -> Result<Fingerprint, Unavailable> {
    let stamp = |s: i64, ns: i64| {
        u64::try_from(i128::from(s) * 1_000_000_000 + i128::from(ns)).map_err(unavailable)
    };
    Ok([
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
        m.nlink(),
        m.len(),
        stamp(m.mtime(), m.mtime_nsec())?,
        stamp(m.ctime(), m.ctime_nsec())?,
    ])
}
fn dir_identity(m: &fs::Metadata) -> [u64; 5] {
    [
        m.dev(),
        m.ino(),
        m.uid().into(),
        m.gid().into(),
        m.mode().into(),
    ]
}
fn parents(
    path: &str,
    extra_owner: Option<u32>,
    deadline: Instant,
) -> Result<Ancestry, Unavailable> {
    crate::account_password_custody::ancestors(path, extra_owner, deadline).map_err(unavailable)
}
fn pinned_parents(
    path: &str,
    expected: &[ParentPin],
    deadline: Instant,
) -> Result<(), Unavailable> {
    let actual = parents(path, None, deadline)?;
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(expected)
            .any(|((p, m), e)| p != e.path || *m != e.identity)
    {
        return Err(Unavailable);
    }
    Ok(())
}
#[derive(PartialEq, Eq)]
struct Observation {
    ids: (u32, u32),
    public: Vec<(String, Fingerprint, [u8; 32])>,
    private_ancestry: Vec<(String, Ancestry)>,
    endpoints: Vec<Endpoint>,
    null: (Vec<u64>, Ancestry),
}

/// All child strings are prepared before fork; the root-owned FFI applies this
/// closed plan without allocation, filesystem parsing or caller callbacks.
pub(crate) struct PreparedChild {
    rules: Vec<(CString, CString)>,
    promises: CString,
    #[cfg(any(test, target_os = "openbsd"))]
    ids: (u32, u32),
    deadline: Instant,
}
impl PreparedChild {
    pub(crate) fn rules(&self) -> &[(CString, CString)] {
        &self.rules
    }
    pub(crate) fn promises(&self) -> &CStr {
        &self.promises
    }
    #[cfg(any(test, target_os = "openbsd"))]
    pub(crate) fn ids(&self) -> (u32, u32) {
        self.ids
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}

struct StartupAuthority {
    startup: std::sync::Arc<crate::account_password_peer::Startup>,
    metadata: std::sync::Arc<dyn crate::auth::CommandExecutor + Send + Sync>,
}
pub(crate) struct NativeProfile {
    role: Role,
    original_deadline: Instant,
    observed: Observation,
    primary: Option<std::sync::Arc<crate::account_password_peer::PrimaryPeer>>,
    control: Option<std::sync::Arc<crate::account_password_peer::ControlPeer>>,
    startup: Option<StartupAuthority>,
}
impl NativeProfile {
    #[cfg(test)]
    pub(crate) fn fixed(role: Role, original_deadline: Instant) -> Result<Self, Unavailable> {
        if !NATIVE_QUALIFIED {
            return Err(Unavailable);
        }
        Self::observe(role, original_deadline)
    }
    #[cfg(all(test, target_os = "openbsd"))]
    pub(crate) fn qualification_candidate(
        role: Role,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        Self::observe(role, deadline)
    }
    #[cfg(test)]
    fn observe(role: Role, original_deadline: Instant) -> Result<Self, Unavailable> {
        before(original_deadline)?;
        if !crate::openbsd::password_native_authority() {
            return Err(Unavailable);
        }
        if role == Role::Primary && PRIMARY_PEER_UID.is_none() {
            return Err(Unavailable);
        }
        if role == Role::Control && CONTROL_PEER_UID.is_none() {
            return Err(Unavailable);
        }
        let observed = observe(role, original_deadline, None, None)?;
        before(original_deadline)?;
        Ok(Self {
            role,
            original_deadline,
            observed,
            primary: None,
            control: None,
            startup: None,
        })
    }
    /// The real service's measured fixed self/master authority, never a caller
    /// qualification Boolean. SQL/hash use their unchanged graph/config checks.
    pub(crate) fn from_startup(
        role: Role,
        startup: std::sync::Arc<crate::account_password_peer::Startup>,
        metadata: std::sync::Arc<dyn crate::auth::CommandExecutor + Send + Sync>,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        if !matches!(role, Role::Sql | Role::Hash) {
            return Err(Unavailable);
        }
        startup
            .recheck(metadata.as_ref(), deadline)
            .map_err(unavailable)?;
        let observed = observe(role, deadline, None, None)?;
        Ok(Self {
            role,
            original_deadline: deadline,
            observed,
            primary: None,
            control: None,
            startup: Some(StartupAuthority { startup, metadata }),
        })
    }
    pub(crate) fn from_primary(
        peer: std::sync::Arc<crate::account_password_peer::PrimaryPeer>,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        Self::from_primary_with_stage(peer, deadline, &mut "admission_profile")
    }
    pub(crate) fn from_primary_with_stage(
        peer: std::sync::Arc<crate::account_password_peer::PrimaryPeer>,
        deadline: Instant,
        stage: &mut &'static str,
    ) -> Result<Self, Unavailable> {
        let observed =
            observe_with_stage(Role::Primary, deadline, Some(peer.as_ref()), None, stage)?;
        Ok(Self {
            role: Role::Primary,
            original_deadline: deadline,
            observed,
            primary: Some(peer),
            control: None,
            startup: None,
        })
    }
    pub(crate) fn from_control(
        peer: std::sync::Arc<crate::account_password_peer::ControlPeer>,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        let observed = observe(Role::Control, deadline, None, Some(peer.as_ref()))?;
        Ok(Self {
            role: Role::Control,
            original_deadline: deadline,
            observed,
            primary: None,
            control: Some(peer),
            startup: None,
        })
    }
    /// Read only the fixed control identity already admitted by observe(). No
    /// fabricated command/utility preparation is used to discover its GID.
    pub(crate) fn selected_control_gid(&self) -> Result<u32, Unavailable> {
        before(self.original_deadline)?;
        if self.role != Role::Control || self.observed.ids.1 == 0 {
            return Err(Unavailable);
        }
        Ok(self.observed.ids.1)
    }
    /// Run in the privileged parent before every spawn. This rechecks bytes,
    /// inode/ancestry, private material and zero-byte kernel peer observations.
    pub(crate) fn prepare(
        &self,
        program: &str,
        args: &[String],
        phase_deadline: Instant,
    ) -> Result<PreparedChild, Unavailable> {
        let deadline = self.original_deadline.min(phase_deadline);
        before(deadline)?;
        if let Some(authority) = &self.startup {
            authority
                .startup
                .recheck(authority.metadata.as_ref(), deadline)
                .map_err(unavailable)?;
        }
        if !matches_command(self.role, program, args)
            || !crate::openbsd::password_native_authority()
            || observe(
                self.role,
                deadline,
                self.primary.as_deref(),
                self.control.as_deref(),
            )? != self.observed
        {
            return Err(Unavailable);
        }
        prepared(self.role, self.observed.ids, deadline)
    }
}

fn matches_command(role: Role, program: &str, args: &[String]) -> bool {
    use crate::account_password_backend::{HASH_ARGS, HASH_PROGRAM, SQL_ARGS, SQL_PROGRAM};
    match role {
        Role::Sql => {
            program == SQL_PROGRAM && args.iter().map(String::as_str).eq(SQL_ARGS.iter().copied())
        }
        Role::Hash => {
            program == HASH_PROGRAM
                && args
                    .iter()
                    .map(String::as_str)
                    .eq(HASH_ARGS.iter().copied())
        }
        Role::Primary => {
            program == HASH_PROGRAM
                && args.len() == crate::account_password_mail::PRIMARY.len() + 1
                && args[..args.len() - 1]
                    .iter()
                    .map(String::as_str)
                    .eq(crate::account_password_mail::PRIMARY.iter().copied())
                && args
                    .last()
                    .is_some_and(|account| crate::account_admission::valid_account(account).is_ok())
        }
        Role::Control => {
            program == HASH_PROGRAM && crate::account_password_mail::fixed_control_args(args)
        }
    }
}
/// Closed parent union of the existing child graphs. Duplicates are merged
/// by ParentPlan; no runtime request contributes a path or permission.
pub(crate) fn parent_rules() -> Vec<(&'static str, &'static str)> {
    let mut rows = Vec::new();
    rows.extend(pins::METADATA_FILES.iter().map(|pin| (pin.path, "r")));
    for (files, program) in [
        (
            pins::SQL_FILES,
            crate::account_password_backend::SQL_PROGRAM,
        ),
        (
            pins::HASH_FILES,
            crate::account_password_backend::HASH_PROGRAM,
        ),
    ] {
        rows.extend(
            files
                .iter()
                .map(|pin| (pin.path, if pin.path == program { "rx" } else { "r" })),
        );
    }
    rows.extend([
        (pins::MODULE_DIRECTORY, "r"),
        (pins::SEARCH_DIRECTORY, "r"),
        (SQL_CONFIG, "r"),
        (SQL_PLAN, "r"),
        ("/etc/passwd", "r"),
        ("/etc/group", "r"),
        ("/dev/null", "rwc"),
        (SQL_SOCKET, "rw"),
        (PRIMARY_SOCKET, "rw"),
        (CONTROL_AUTH, "rw"),
        (CONTROL_ANVIL, "rw"),
        (crate::account_password_topology::IPC, "rw"),
    ]);
    rows
}

/// The measured additional public closure required by fixed fstat after seal.
/// Other metadata authority is unchanged; no library directory is exposed.
pub(crate) fn verify_metadata_graph(deadline: Instant) -> Result<(), Unavailable> {
    for pin in pins::METADATA_FILES {
        pinned_parents(pin.path, pin.parents, deadline)?;
        let (identity, digest, _) = public_file(pin.path, false, FILE_CAP, deadline)?;
        let text: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if identity != pin.identity || text != pin.sha256 {
            return Err(Unavailable);
        }
    }
    before(deadline)
}
fn fstat_worker_pins() -> Result<Vec<&'static FilePin>, Unavailable> {
    let mut files = vec![&pins::FSTAT_PROGRAM];
    files.extend(pins::METADATA_FILES.iter());
    for path in [
        "/usr/lib/libc.so.103.0",
        "/usr/libexec/ld.so",
        "/var/run/ld.so.hints",
    ] {
        files.push(
            pins::SQL_FILES
                .iter()
                .chain(pins::HASH_FILES.iter())
                .find(|pin| pin.path == path)
                .ok_or(Unavailable)?,
        );
    }
    Ok(files)
}
pub(crate) fn verify_fstat_worker_graph(deadline: Instant) -> Result<(), Unavailable> {
    for pin in fstat_worker_pins()? {
        pinned_parents(pin.path, pin.parents, deadline)?;
        let (identity, digest, _) = public_file(pin.path, false, FILE_CAP, deadline)?;
        let text: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if identity != pin.identity || text != pin.sha256 {
            return Err(Unavailable);
        }
    }
    before(deadline)
}
/// One fixed metadata process, not a password Role or a caller execution plan.
pub(crate) struct FstatWorkerPlan {
    rules: Vec<(CString, CString)>,
    promises: CString,
    custody: std::sync::Arc<crate::account_password_custody::Custody>,
}
impl FstatWorkerPlan {
    pub(crate) fn capture(deadline: Instant) -> Result<Self, Unavailable> {
        if !crate::openbsd::password_native_authority() {
            return Err(Unavailable);
        }
        verify_fstat_worker_graph(deadline)?;
        let files = fstat_worker_pins()?;
        let paths = files.iter().map(|pin| pin.path).collect::<Vec<_>>();
        let custody = crate::account_password_custody::Custody::capture(&paths, deadline)
            .map_err(unavailable)?;
        let mut rules = std::collections::BTreeMap::new();
        for pin in files {
            for parent in pin.parents {
                rules.entry(parent.path).or_insert("");
            }
            rules.insert(
                pin.path,
                if pin.path == "/usr/bin/fstat" {
                    "rx"
                } else {
                    "r"
                },
            );
        }
        Ok(Self {
            rules: rules
                .into_iter()
                .map(|(p, a)| {
                    Ok((
                        CString::new(p).map_err(unavailable)?,
                        CString::new(a).map_err(unavailable)?,
                    ))
                })
                .collect::<Result<_, Unavailable>>()?,
            // No execpromises are set: fixed fstat exec resets the view, runs
            // its KERN_FILE observation, then installs its own native pledge.
            promises: CString::new("stdio rpath proc exec prot_exec").map_err(unavailable)?,
            custody,
        })
    }
    pub(crate) fn rules(&self) -> &[(CString, CString)] {
        &self.rules
    }
    pub(crate) fn promises(&self) -> &std::ffi::CStr {
        &self.promises
    }
    pub(crate) fn activate(
        &self,
        seal: &crate::openbsd::PasswordFstatSeal,
    ) -> Result<(), Unavailable> {
        self.custody.activate_fstat(seal).map_err(unavailable)
    }
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Unavailable> {
        self.custody.recheck(deadline).map_err(unavailable)?;
        verify_fstat_worker_graph(deadline)
    }
}
fn prepared(role: Role, _ids: (u32, u32), deadline: Instant) -> Result<PreparedChild, Unavailable> {
    let files = if role == Role::Sql {
        pins::SQL_FILES
    } else {
        pins::HASH_FILES
    };
    let program = if role == Role::Sql {
        crate::account_password_backend::SQL_PROGRAM
    } else {
        crate::account_password_backend::HASH_PROGRAM
    };
    let mut rows: Vec<(&str, &str)> = files
        .iter()
        .map(|p| (p.path, if p.path == program { "rx" } else { "r" }))
        .collect();
    let promises = match role {
        Role::Sql => {
            rows.extend([(SQL_CONFIG, "r"), (SQL_SOCKET, "w"), ("/dev/null", "r")]);
            "stdio rpath unix prot_exec exec tty"
        }
        Role::Hash => {
            rows.extend([
                (pins::MODULE_DIRECTORY, "r"),
                (pins::SEARCH_DIRECTORY, "r"),
                ("/dev/null", "rwc"),
            ]);
            "stdio rpath wpath cpath prot_exec exec"
        }
        Role::Primary => {
            rows.extend([
                (pins::MODULE_DIRECTORY, "r"),
                (pins::SEARCH_DIRECTORY, "r"),
                ("/dev/null", "rwc"),
                (PRIMARY_SOCKET, "rw"),
            ]);
            "stdio rpath unix prot_exec exec wpath cpath"
        }
        Role::Control => {
            rows.extend([
                (pins::MODULE_DIRECTORY, "r"),
                (pins::SEARCH_DIRECTORY, "r"),
                ("/dev/null", "rwc"),
                (CONTROL_AUTH, "rw"),
                (CONTROL_ANVIL, "rw"),
                (crate::account_password_topology::IPC, "rw"),
            ]);
            "stdio rpath unix prot_exec exec wpath cpath"
        }
    };
    Ok(PreparedChild {
        rules: rows
            .into_iter()
            .map(|(p, a)| {
                Ok((
                    CString::new(p).map_err(unavailable)?,
                    CString::new(a).map_err(unavailable)?,
                ))
            })
            .collect::<Result<_, Unavailable>>()?,
        promises: CString::new(promises).map_err(unavailable)?,
        #[cfg(any(test, target_os = "openbsd"))]
        ids: _ids,
        deadline,
    })
}

fn public_file(
    path: &str,
    private: bool,
    limit: u64,
    deadline: Instant,
) -> Result<(Fingerprint, [u8; 32], Vec<u8>), Unavailable> {
    protected_file(path, private, None, limit, deadline)
}

// The only group-readable private material is the fixed SQL client file.
// Parent-owned authority plans and keys retain their root0600 boundary.
fn sql_config_metadata(uid: u32, gid: u32, mode: u32, links: u64, sql_gid: u32) -> bool {
    uid == 0
        && gid == sql_gid
        && sql_gid != 0
        && sql_gid != u32::MAX
        && mode & 0o7777 == 0o440
        && links == 1
}
fn role_permission(uid: u32, gid: u32, mode: u32, ids: (u32, u32), permission: u32) -> bool {
    let shift = if uid == ids.0 {
        6
    } else if gid == ids.1 {
        3
    } else {
        0
    };
    mode >> shift & permission == permission
}
fn role_traverses(ancestry: &[(String, [u64; 5])], ids: (u32, u32)) -> bool {
    ancestry
        .iter()
        .all(|(_, row)| role_permission(row[2] as u32, row[3] as u32, row[4] as u32, ids, 1))
}
fn protected_file(
    path: &str,
    private: bool,
    sql_gid: Option<u32>,
    limit: u64,
    deadline: Instant,
) -> Result<(Fingerprint, [u8; 32], Vec<u8>), Unavailable> {
    before(deadline)?;
    let ancestry = parents(path, None, deadline)?;
    let m = fs::symlink_metadata(path).map_err(unavailable)?;
    let link_cap = if path.contains(".so") {
        64
    } else if path == "/usr/bin/fstat" {
        2
    } else {
        1
    };
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() == 0
        || m.nlink() > link_cap
        || m.mode() & 0o6022 != 0
        || m.len() == 0
        || m.len() > limit
        || if let Some(gid) = sql_gid {
            path != SQL_CONFIG
                || !private
                || !sql_config_metadata(m.uid(), m.gid(), m.mode(), m.nlink(), gid)
        } else if private {
            m.nlink() != 1 || m.mode() & 0o7777 != 0o600
        } else {
            m.mode() & 0o004 == 0
        }
    {
        return Err(Unavailable);
    }
    let expected = fingerprint(&m)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(unavailable)?;
    if fingerprint(&file.metadata().map_err(unavailable)?)? != expected {
        return Err(Unavailable);
    }
    let mut data = Vec::new();
    let mut hash = Sha256::new();
    let mut buf = [0u8; 4096];
    loop {
        before(deadline)?;
        let n = file.read(&mut buf).map_err(unavailable)?;
        if n == 0 {
            break;
        }
        if data.len() as u64 + n as u64 > limit {
            return Err(Unavailable);
        }
        hash.update(&buf[..n]);
        data.extend_from_slice(&buf[..n]);
    }
    if data.len() as u64 != m.len()
        || fingerprint(&file.metadata().map_err(unavailable)?)? != expected
        || fingerprint(&fs::symlink_metadata(path).map_err(unavailable)?)? != expected
        || parents(path, None, deadline)? != ancestry
    {
        return Err(Unavailable);
    }
    before(deadline)?;
    Ok((expected, hash.finalize().into(), data))
}
fn graph(
    role: Role,
    deadline: Instant,
) -> Result<Vec<(String, Fingerprint, [u8; 32])>, Unavailable> {
    let mut result = Vec::new();
    let mut total = 0u64;
    for pin in if role == Role::Sql {
        pins::SQL_FILES
    } else {
        pins::HASH_FILES
    } {
        pinned_parents(pin.path, pin.parents, deadline)?;
        let (identity, digest, _) = public_file(pin.path, false, FILE_CAP, deadline)?;
        total = total.checked_add(identity[6]).ok_or(Unavailable)?;
        if total > TOTAL_CAP || identity != pin.identity {
            return Err(Unavailable);
        }
        let text: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if text != pin.sha256 {
            return Err(Unavailable);
        }
        result.push((pin.path.into(), identity, digest));
    }
    if role != Role::Sql {
        directories(deadline)?;
    }
    Ok(result)
}
fn directories(deadline: Instant) -> Result<(), Unavailable> {
    for (path, ancestry) in [
        (pins::MODULE_DIRECTORY, pins::MODULE_ANCESTRY),
        (pins::SEARCH_DIRECTORY, pins::SEARCH_ANCESTRY),
    ] {
        pinned_parents(path, ancestry, deadline)?;
        let before_info = fs::symlink_metadata(path).map_err(unavailable)?;
        if !before_info.is_dir() || before_info.uid() != 0 || before_info.mode() & 0o022 != 0 {
            return Err(Unavailable);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(unavailable)?;
        if dir_identity(&directory.metadata().map_err(unavailable)?) != dir_identity(&before_info) {
            return Err(Unavailable);
        }
        let mut names = Vec::new();
        let mut name_bytes = 0usize;
        for entry in fs::read_dir(path).map_err(unavailable)? {
            before(deadline)?;
            let entry = entry.map_err(unavailable)?;
            let name = entry.file_name().into_string().map_err(unavailable)?;
            name_bytes += name.len();
            if name.is_empty() || name.len() > 255 || names.len() >= 256 || name_bytes > 16384 {
                return Err(Unavailable);
            }
            names.push(name);
        }
        names.sort();
        if path == pins::MODULE_DIRECTORY {
            let mut expected: Vec<_> = pins::MODULE_NAMES.iter().map(|v| v.to_string()).collect();
            expected.sort();
            if dir_identity(&before_info) != pins::MODULE_IDENTITY || names != expected {
                return Err(Unavailable);
            }
        } else {
            if fingerprint(&before_info)? != pins::SEARCH_IDENTITY
                || names.len() != pins::SEARCH_ENTRIES.len()
            {
                return Err(Unavailable);
            }
            for (actual, (name, expected)) in names.iter().zip(pins::SEARCH_ENTRIES) {
                before(deadline)?;
                if actual != name
                    || fingerprint(
                        &fs::symlink_metadata(Path::new(path).join(name)).map_err(unavailable)?,
                    )? != *expected
                {
                    return Err(Unavailable);
                }
            }
        }
        if dir_identity(&fs::symlink_metadata(path).map_err(unavailable)?)
            != dir_identity(&before_info)
            || dir_identity(&directory.metadata().map_err(unavailable)?)
                != dir_identity(&before_info)
        {
            return Err(Unavailable);
        }
        if path == pins::SEARCH_DIRECTORY
            && fingerprint(&directory.metadata().map_err(unavailable)?)? != pins::SEARCH_IDENTITY
        {
            return Err(Unavailable);
        }
        pinned_parents(path, ancestry, deadline)?;
    }
    Ok(())
}

fn records(raw: &[u8], fields: usize) -> Result<Vec<Vec<&[u8]>>, Unavailable> {
    if raw.is_empty() || raw.len() > 65536 || raw.contains(&0) {
        return Err(Unavailable);
    }
    let mut result = Vec::new();
    for line in raw
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty() && !line.starts_with(b"#"))
    {
        let row: Vec<_> = line.split(|b| *b == b':').collect();
        if line.len() > 1024
            || row.len() != fields
            || row[0].is_empty()
            || matches!(row[0][0], b'+' | b'-')
            || result.len() >= 1024
        {
            return Err(Unavailable);
        }
        result.push(row);
    }
    Ok(result)
}
fn number(raw: &[u8]) -> Result<u32, Unavailable> {
    if raw.is_empty() || raw.len() > 10 || !raw.iter().all(u8::is_ascii_digit) {
        return Err(Unavailable);
    }
    std::str::from_utf8(raw)
        .map_err(unavailable)?
        .parse()
        .map_err(unavailable)
}
fn selected(passwd: &[u8], group: &[u8], name: &[u8]) -> Result<(u32, u32), Unavailable> {
    let users = records(passwd, 7)?;
    let groups = records(group, 4)?;
    for user in &users {
        number(user[2])?;
        number(user[3])?;
    }
    for entry in &groups {
        number(entry[2])?;
    }
    let chosen: Vec<_> = users.iter().filter(|u| u[0] == name).collect();
    let own: Vec<_> = groups.iter().filter(|g| g[0] == name).collect();
    if chosen.len() != 1 || own.len() != 1 {
        return Err(Unavailable);
    }
    let user = chosen[0];
    let entry = own[0];
    let uid = number(user[2])?;
    let gid = number(user[3])?;
    if uid == 0
        || gid == 0
        || uid > i32::MAX as u32
        || gid > i32::MAX as u32
        || [32766, 32767].contains(&uid)
        || [32766, 32767].contains(&gid)
        || number(entry[2])? != gid
        || user[5] != b"/var/empty"
        || user[6] != b"/sbin/nologin"
        || !entry[3].is_empty()
        || users
            .iter()
            .filter(|u| number(u[2]).ok() == Some(uid))
            .count()
            != 1
        || users
            .iter()
            .filter(|u| number(u[3]).ok() == Some(gid))
            .count()
            != 1
        || groups
            .iter()
            .filter(|g| number(g[2]).ok() == Some(gid))
            .count()
            != 1
        || groups.iter().any(|g| {
            g[3].split(|b| *b == b',')
                .any(|member| member.trim_ascii() == name)
        })
        || (name == b"_osmapprimary" && uid == 518)
    {
        return Err(Unavailable);
    }
    Ok((uid, gid))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlPlan {
    version: u64,
    authority: String,
    purpose: String,
    server: String,
    socket: String,
    database_user: String,
}
fn valid_plan(raw: &[u8]) -> Result<(), Unavailable> {
    let plan: SqlPlan = serde_json::from_slice(raw).map_err(unavailable)?;
    if plan.version != 1
        || plan.authority != "mail.blackbagsecurity.com"
        || plan.purpose != "osmap-account-mutation"
        || plan.server != "_mysql"
        || plan.socket != SQL_SOCKET
        || plan.database_user != "osmap_account_mutation"
    {
        return Err(Unavailable);
    }
    Ok(())
}
fn valid_config(raw: &[u8]) -> Result<(), Unavailable> {
    if !raw.is_ascii() || !raw.ends_with(b"\n") || raw.contains(&b'\r') {
        return Err(Unavailable);
    }
    let text = std::str::from_utf8(raw).map_err(unavailable)?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 5 || lines[0] != "[client]" {
        return Err(Unavailable);
    }
    let mut fields = std::collections::BTreeMap::new();
    for line in &lines[1..] {
        let (k, v) = line.split_once('=').ok_or(Unavailable)?;
        if fields.insert(k, v).is_some() {
            return Err(Unavailable);
        }
    }
    let password = fields.get("password").ok_or(Unavailable)?;
    if fields.len() != 4
        || fields.get("user") != Some(&"osmap_account_mutation")
        || fields.get("protocol") != Some(&"SOCKET")
        || fields.get("socket") != Some(&SQL_SOCKET)
        || !(20..=256).contains(&password.len())
        || !password
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
    {
        return Err(Unavailable);
    }
    Ok(())
}
fn socket(
    path: &str,
    owner: u32,
    gid: Option<u32>,
    peer: u32,
    deadline: Instant,
) -> Result<Endpoint, Unavailable> {
    let ancestry_owner = if gid.is_some() { None } else { Some(owner) };
    before(deadline)?;
    let ancestry = parents(path, ancestry_owner, deadline)?;
    let m = fs::symlink_metadata(path).map_err(unavailable)?;
    if !m.file_type().is_socket()
        || m.uid() != owner
        || m.nlink() != 1
        || gid.is_some_and(|g| m.gid() != g || m.mode() & 0o777 != 0o660)
    {
        return Err(Unavailable);
    }
    let identity = fingerprint(&m)?;
    let stream = crate::openbsd::connect_unix_before(
        Path::new(path),
        deadline.min(Instant::now() + Duration::from_secs(1)),
    )
    .map_err(unavailable)?;
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(unavailable)? != peer
        || fingerprint(&fs::symlink_metadata(path).map_err(unavailable)?)? != identity
        || parents(path, ancestry_owner, deadline)? != ancestry
    {
        return Err(Unavailable);
    }
    drop(stream);
    before(deadline)?;
    Ok((path.into(), identity, ancestry))
}
fn observe(
    role: Role,
    deadline: Instant,
    primary: Option<&crate::account_password_peer::PrimaryPeer>,
    control: Option<&crate::account_password_peer::ControlPeer>,
) -> Result<Observation, Unavailable> {
    observe_with_stage(role, deadline, primary, control, &mut "native_profile")
}
fn observe_with_stage(
    role: Role,
    deadline: Instant,
    primary: Option<&crate::account_password_peer::PrimaryPeer>,
    control: Option<&crate::account_password_peer::ControlPeer>,
    stage: &mut &'static str,
) -> Result<Observation, Unavailable> {
    *stage = "primary_profile_deadline";
    before(deadline)?;
    *stage = "primary_profile_graph";
    let mut public = graph(role, deadline)?;
    let mut endpoints = Vec::new();
    let ids = if role == Role::Sql {
        let (p, ph, passwd) = public_file("/etc/passwd", false, 65536, deadline)?;
        let (g, gh, group) = public_file("/etc/group", false, 65536, deadline)?;
        let ids = selected(&passwd, &group, b"_osmapsql")?;
        public.extend([("/etc/passwd".into(), p, ph), ("/etc/group".into(), g, gh)]);
        let (m, h, raw) = public_file(SQL_PLAN, true, 16384, deadline)?;
        valid_plan(&raw)?;
        public.push((SQL_PLAN.into(), m, h));
        let (m, h, raw) = protected_file(SQL_CONFIG, true, Some(ids.1), 16384, deadline)?;
        valid_config(&raw)?;
        if !role_traverses(&parents(SQL_CONFIG, None, deadline)?, ids) {
            return Err(Unavailable);
        }
        public.push((SQL_CONFIG.into(), m, h));
        let users = records(&passwd, 7)?;
        let found: Vec<_> = users.iter().filter(|u| u[0] == b"_mysql").collect();
        if found.len() != 1 {
            return Err(Unavailable);
        }
        let uid = number(found[0][2])?;
        if uid == 0 || uid == u32::MAX {
            return Err(Unavailable);
        }
        let endpoint = socket(SQL_SOCKET, uid, None, uid, deadline)?;
        if !role_traverses(&endpoint.2, ids)
            || !role_permission(
                endpoint.1[2] as u32,
                endpoint.1[3] as u32,
                endpoint.1[4] as u32,
                ids,
                2,
            )
        {
            return Err(Unavailable);
        }
        endpoints.push(endpoint);
        ids
    } else {
        *stage = "primary_profile_principal";
        let (p, ph, passwd) = public_file("/etc/passwd", false, 65536, deadline)?;
        let (g, gh, group) = public_file("/etc/group", false, 65536, deadline)?;
        let ids = selected(
            &passwd,
            &group,
            if role == Role::Hash {
                b"_osmaphash"
            } else if role == Role::Control {
                b"_osmapcontrol"
            } else {
                b"_osmapprimary"
            },
        )?;
        public.extend([("/etc/passwd".into(), p, ph), ("/etc/group".into(), g, gh)]);
        if role == Role::Primary {
            let peer = primary.ok_or(Unavailable)?;
            let (server_uid, binder_uid) = peer.identities(deadline, stage).map_err(unavailable)?;
            *stage = "primary_profile_socket_dac";
            endpoints.push(socket(
                PRIMARY_SOCKET,
                server_uid,
                Some(ids.1),
                binder_uid,
                deadline,
            )?);
            peer.recheck_with_stage(deadline, stage)
                .map_err(unavailable)?;
        }
        if role == Role::Control {
            let binders = control
                .ok_or(Unavailable)?
                .identities(deadline)
                .map_err(unavailable)?;
            for (path, binder) in [
                CONTROL_AUTH,
                CONTROL_ANVIL,
                crate::account_password_topology::IPC,
            ]
            .into_iter()
            .zip(binders)
            {
                endpoints.push(socket(path, 0, Some(ids.1), binder, deadline)?);
            }
        }
        ids
    };
    *stage = "primary_profile_null";
    let ancestry = parents("/dev/null", None, deadline)?;
    let m = fs::symlink_metadata("/dev/null").map_err(unavailable)?;
    if !m.file_type().is_char_device()
        || m.uid() != 0
        || m.gid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o666
        || m.rdev() != 514
    {
        return Err(Unavailable);
    }
    let null = (
        vec![
            m.dev(),
            m.ino(),
            m.uid().into(),
            m.gid().into(),
            m.mode().into(),
            m.nlink(),
            m.len(),
            m.rdev(),
        ],
        ancestry,
    );
    *stage = "primary_profile_material_ancestry";
    let mut private_ancestry = Vec::new();
    let material_paths: &[&str] = if role == Role::Sql {
        &[SQL_PLAN, SQL_CONFIG, "/etc/passwd", "/etc/group"]
    } else {
        &["/etc/passwd", "/etc/group"]
    };
    for path in material_paths {
        private_ancestry.push(((*path).into(), parents(path, None, deadline)?));
    }
    *stage = "primary_profile_final_deadline";
    before(deadline)?;
    Ok(Observation {
        ids,
        public,
        private_ancestry,
        endpoints,
        null,
    })
}

#[cfg(test)]
#[path = "account_password_native_tests.rs"]
mod tests;

/// Identity lookup alone supplies no execution authority. Measured ControlPeer
/// plus this same fixed principal/DAC check is required by from_control.
pub(crate) fn control_gid(deadline: Instant) -> Result<u32, Unavailable> {
    let (_, _, passwd) = public_file("/etc/passwd", false, 65536, deadline)?;
    let (_, _, group) = public_file("/etc/group", false, 65536, deadline)?;
    Ok(selected(&passwd, &group, b"_osmapcontrol")?.1)
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn original_expired_profile_refusal_has_a_closed_stage_before_io() {
        let mut stage = "not_observed";
        let result = observe_with_stage(Role::Primary, Instant::now(), None, None, &mut stage);
        assert!(matches!(result, Err(Unavailable)));
        assert_eq!(stage, "primary_profile_deadline");
    }
}
