//! OpenBSD-native runtime confinement planning and activation.
//!
//! The current implementation keeps this layer explicit and reviewable:
//! - build a concrete filesystem and promise plan from validated config
//! - emit that plan in operator-visible logs
//! - enforce it only when the operator explicitly enables it
//! - stay honest about platform boundaries in non-OpenBSD environments

use std::collections::BTreeMap;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use crate::config::{AppConfig, LogLevel, OpenbsdConfinementMode};
use crate::logging::{EventCategory, LogEvent, Logger};

/// Restore the foreground Crypto helper's native rc.subr stop signal.
/// Exec preserves inherited ignored dispositions; call before serving requests.
#[cfg(unix)]
pub fn restore_crypto_termination_signal() -> io::Result<()> {
    if unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) } == libc::SIG_ERR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
static ACCOUNT_ADMISSION_STOP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
static ACCOUNT_ADMISSION_SIGNALS_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn stop_account_admission(_: libc::c_int) {
    ACCOUNT_ADMISSION_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Process-owned termination handlers; expose only the safe admission stop flag.
#[cfg(unix)]
pub struct AccountAdmissionSignals {
    previous: [(libc::c_int, libc::sighandler_t); 2],
    installed: usize,
}
#[cfg(unix)]
impl AccountAdmissionSignals {
    pub fn install() -> io::Result<Self> {
        if ACCOUNT_ADMISSION_SIGNALS_ACTIVE
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        ACCOUNT_ADMISSION_STOP.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut value = Self {
            previous: [
                (libc::SIGTERM, libc::SIG_DFL),
                (libc::SIGINT, libc::SIG_DFL),
            ],
            installed: 0,
        };
        for (index, signal) in [libc::SIGTERM, libc::SIGINT].into_iter().enumerate() {
            // SAFETY: static C-ABI handler only stores an atomic flag. No I/O,
            // allocation, credentials, locks or process signalling in handler.
            let previous = unsafe {
                libc::signal(
                    signal,
                    stop_account_admission as *const () as libc::sighandler_t,
                )
            };
            if previous == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            value.previous[index] = (signal, previous);
            value.installed += 1;
        }
        Ok(value)
    }
    pub fn stop_flag(&self) -> &'static std::sync::atomic::AtomicBool {
        &ACCOUNT_ADMISSION_STOP
    }
}
#[cfg(unix)]
impl Drop for AccountAdmissionSignals {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.iter().take(self.installed) {
            // SAFETY: restore only exact captured dispositions installed by
            // this exclusive guard, including a partially failed setup.
            unsafe { libc::signal(*signal, *previous) };
        }
        ACCOUNT_ADMISSION_SIGNALS_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Disable and verify helper core dumps before loading authentication material.
#[cfg(unix)]
pub(crate) fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut actual = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut actual) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if actual.rlim_cur != 0 || actual.rlim_max != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

/// Retained executable custody descriptors must close at every exec boundary.
#[cfg(unix)]
pub(crate) fn descriptor_is_cloexec(fd: i32) -> io::Result<bool> {
    if fd < 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: F_GETFD only inspects this already-owned descriptor's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
}

/// Nonblocking pipe drains keep worker output under the same absolute deadline.
#[cfg(unix)]
pub(crate) fn set_descriptor_nonblocking(fd: i32) -> io::Result<()> {
    if fd < 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
/// Wait for duplex worker pipes without imposing a sleep on ready small pipes.
/// The outer loop retains its absolute operation and cleanup deadlines.
#[cfg(unix)]
pub(crate) fn wait_worker_pipes(
    input: Option<i32>,
    output: Option<i32>,
    error: Option<i32>,
    deadline: std::time::Instant,
) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or(io::ErrorKind::TimedOut)?;
    let mut pipes = Vec::with_capacity(3);
    for (fd, events) in [
        (input, libc::POLLOUT),
        (output, libc::POLLIN),
        (error, libc::POLLIN),
    ] {
        if let Some(fd) = fd {
            if fd < 0 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            pipes.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            });
        }
    }
    let wait = remaining.as_millis().min(2) as i32;
    let result = unsafe { libc::poll(pipes.as_mut_ptr(), pipes.len() as libc::nfds_t, wait) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    if pipes.iter().any(|p| p.revents & libc::POLLNVAL != 0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}
/// Only a child started as its own process-group leader may be passed here.
#[cfg(unix)]
pub(crate) fn kill_process_group(child_pid: u32) -> io::Result<()> {
    let pid = i32::try_from(child_pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pid <= 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    if unsafe { libc::kill(-pid, libc::SIGKILL) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Exact owned process-group existence; permission/other errors are unknown.
#[cfg(unix)]
pub(crate) fn process_group_exists(child_pid: u32) -> io::Result<bool> {
    let pid = i32::try_from(child_pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pid <= 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if unsafe { libc::kill(-pid, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Deadline-bound local connect; avoids blocking on a full Unix listener backlog.
#[cfg(unix)]
pub(crate) fn connect_unix_before(
    path: &Path,
    deadline: std::time::Instant,
) -> io::Result<UnixStream> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    address.sun_family = libc::AF_UNIX as _;
    #[cfg(target_os = "openbsd")]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    for (dest, source) in address.sun_path.iter_mut().zip(bytes) {
        *dest = *source as _;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let result = unsafe {
        libc::connect(
            raw,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as _,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        loop {
            let left = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or(io::ErrorKind::TimedOut)?;
            let mut poll = libc::pollfd {
                fd: raw,
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout = left.as_millis().clamp(1, i32::MAX as u128) as i32;
            let result = unsafe { libc::poll(&mut poll, 1, timeout) };
            if result == 0 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if result < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let mut error: libc::c_int = 0;
            let mut len = std::mem::size_of_val(&error) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    raw,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut len,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// Acquires a blocking advisory exclusive lock on an already-open file.
///
/// The unsafe system-call boundary stays in this reviewed platform module so
/// session state code can use a small safe RAII wrapper.
#[cfg(unix)]
pub(crate) fn advisory_file_lock_exclusive(file: &fs::File) -> io::Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Acquires a nonblocking exclusive lock; a busy account returns immediately.
#[cfg(unix)]
pub(crate) fn try_advisory_file_lock_exclusive(file: &fs::File) -> io::Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Releases an advisory lock previously acquired on an open file.
#[cfg(unix)]
pub(crate) fn advisory_file_unlock(file: &fs::File) -> io::Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The promise set used while `unveil(2)` calls are still permitted.
const OPENBSD_SERVE_PROMISES_BEFORE_LOCK: &str =
    "stdio rpath wpath cpath fattr flock inet proc exec unveil";

/// The narrower promise set kept after the filesystem view is locked.
const OPENBSD_SERVE_PROMISES_AFTER_LOCK: &str =
    "stdio rpath wpath cpath fattr flock inet proc exec";

/// The promise set used while `unveil(2)` calls are still permitted in the
/// browser-facing runtime when it also connects to the local mailbox helper.
const OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK: &str =
    "stdio rpath wpath cpath fattr flock inet unix proc exec unveil";

/// The narrower promise set kept after the filesystem view is locked in the
/// browser-facing runtime when it also connects to the local mailbox helper.
const OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK: &str =
    "stdio rpath wpath cpath fattr flock inet unix proc exec";

/// The promise set used while `unveil(2)` calls are still permitted in the
/// local mailbox-helper runtime.
const OPENBSD_HELPER_PROMISES_BEFORE_LOCK: &str =
    "stdio rpath wpath cpath fattr flock unix proc exec unveil";

/// The narrower promise set kept after the filesystem view is locked in the
/// local mailbox-helper runtime.
const OPENBSD_HELPER_PROMISES_AFTER_LOCK: &str =
    "stdio rpath wpath cpath fattr flock unix proc exec";

/// The system-library prefixes the helper-side `doveadm` execution currently
/// resolves on the validated OpenBSD host.
const OPENBSD_SYSTEM_LIBRARY_PREFIXES: [&str; 4] =
    ["libc.so.", "libm.so.", "libpthread.so.", "libz.so."];

/// The local-library prefixes the helper-side `doveadm` execution currently
/// resolves on the validated OpenBSD host.
const OPENBSD_LOCAL_LIBRARY_PREFIXES: [&str; 6] = [
    "libbz2.so.",
    "libiconv.so.",
    "liblz4.so.",
    "liblzma.so.",
    "libsodium.so.",
    "libzstd.so.",
];

/// The system-library prefixes the local sendmail path resolves on the
/// validated OpenBSD host.
const OPENBSD_SENDMAIL_SYSTEM_LIBRARY_PREFIXES: [&str; 7] = [
    "libc.so.",
    "libcrypto.so.",
    "libm.so.",
    "libpthread.so.",
    "libssl.so.",
    "libutil.so.",
    "libz.so.",
];

/// The local-library prefixes the local sendmail path resolves on the
/// validated OpenBSD host.
const OPENBSD_SENDMAIL_LOCAL_LIBRARY_PREFIXES: [&str; 4] = [
    "libmariadb.so.",
    "libpcre2-8.so.",
    "libsasl2.so.",
    "libsqlite3.so.",
];

/// One unveiled path plus the permissions granted to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenbsdUnveilRule {
    pub path: PathBuf,
    pub permissions: String,
}

/// A concrete confinement plan derived from the current runtime shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenbsdConfinementPlan {
    pub promises_before_lock: &'static str,
    pub promises_after_lock: &'static str,
    pub unveil_rules: Vec<OpenbsdUnveilRule>,
}

/// Admission's Rust supervisor only. The fixed worker starts without inherited
/// pledge/unveil (unset exec promises); its separate native command policy and
/// full workflow qualification remain required. Never grant the supervisor
/// recursive reads of public ancestors or epoch/private-material directories.
pub(crate) fn account_admission_parent_plan(
    socket: &Path,
) -> Result<OpenbsdConfinementPlan, String> {
    use std::path::Component;
    if !socket.is_absolute()
        || socket.file_name().is_none()
        || socket
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err("account admission endpoint unavailable".into());
    }
    let parent = socket
        .parent()
        .ok_or("account admission endpoint unavailable")?;
    // The bound namespace is root-private; no public tree is an eligible
    // recursive directory read grant. Service additionally holds its inode.
    crate::openpgp_inventory_runtime::private_dir(parent, effective_uid(), true)
        .map_err(|_| "account admission namespace unavailable")?;
    let mut rules = BTreeMap::new();
    for path in [socket, Path::new("/usr/local/bin/python3.13")] {
        for ancestor in path.ancestors().skip(1) {
            // Empty ancestor permissions pin the unveiled directory inodes;
            // they do not permit ancestor lstat (measured native ENOENT).
            // Full protected ancestry is checked before this locked plan.
            add_rule(&mut rules, ancestor, "");
        }
    }
    add_rule(&mut rules, parent, "r");
    add_rule(&mut rules, socket, "rwc");
    add_rule(&mut rules, Path::new("/usr/local/bin/python3.13"), "rx");
    Ok(OpenbsdConfinementPlan {
        promises_before_lock: "stdio rpath wpath cpath unix proc exec unveil",
        promises_after_lock: "stdio rpath wpath cpath unix proc exec",
        unveil_rules: rules
            .into_iter()
            .map(|(path, permissions)| OpenbsdUnveilRule { path, permissions })
            .collect(),
    })
}

// Only actual locked native application can mint this capability. No public
// constructor/Clone/caller Boolean selects a postseal metadata phase.
pub(crate) struct AccountAdmissionParentSeal {
    _native: (),
}

/// Called after exact socket publication and before any accept or frame read.
/// No disabled/log-only branch exists for this mandatory parent policy.
pub(crate) fn apply_account_admission_parent_confinement(
    socket: &Path,
) -> Result<AccountAdmissionParentSeal, String> {
    let plan = account_admission_parent_plan(socket)?;
    #[cfg(target_os = "openbsd")]
    {
        imp::apply_plan(&plan)?;
        Ok(AccountAdmissionParentSeal { _native: () })
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = plan;
        Err("account admission native parent confinement unavailable".into())
    }
}

impl OpenbsdConfinementPlan {
    /// Builds the current confinement plan from validated runtime configuration.
    pub fn from_config(config: &AppConfig) -> Self {
        let mut rules = BTreeMap::<PathBuf, String>::new();
        match config.run_mode {
            crate::config::AppRunMode::Serve => {
                // The browser runtime owns sessions, runtime sockets, cache,
                // and TOTP secrets. Those explicit mutable paths remain
                // writable instead of widening the tree above them.
                add_rule(&mut rules, &config.state_root, "r");
                add_rule(&mut rules, &config.state_layout.runtime_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.session_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.settings_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.draft_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.audit_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.cache_dir, "rwc");
                add_rule(&mut rules, &config.state_layout.totp_secret_dir, "rwc");
                if let Some(path) = &config.sender_authority_path {
                    add_rule(&mut rules, path, "r");
                    add_parent_dir_rules(&mut rules, path);
                }

                add_doveadm_dependency_rules(&mut rules);
                add_sendmail_dependency_rules(&mut rules);
                add_rule(&mut rules, Path::new("/dev/null"), "rw");

                if let Some(auth_socket_path) = &config.doveadm_auth_socket_path {
                    add_rule(&mut rules, auth_socket_path, "rw");
                    add_parent_dir_rules(&mut rules, auth_socket_path);
                }

                let use_direct_mailbox_backends = config.mailbox_helper_socket_path.is_none();
                if use_direct_mailbox_backends {
                    if let Some(userdb_socket_path) = &config.doveadm_userdb_socket_path {
                        add_rule(&mut rules, userdb_socket_path, "rw");
                        add_parent_dir_rules(&mut rules, userdb_socket_path);
                    }
                }

                if let Some(mailbox_helper_socket_path) = &config.mailbox_helper_socket_path {
                    // The web-facing runtime only connects to the local
                    // helper socket, so it keeps a narrower connect-only view
                    // of that path.
                    add_rule(&mut rules, mailbox_helper_socket_path, "rw");
                    add_parent_dir_rules(&mut rules, mailbox_helper_socket_path);
                }
                if let Some(grant_key_path) = &config.mailbox_helper_grant_key_path {
                    add_rule(&mut rules, grant_key_path, "r");
                    add_parent_dir_rules(&mut rules, grant_key_path);
                }

                // Account authority stays at the two authenticated endpoints
                // and three separate purpose keys. No account state, SQL
                // material or additional ancestor directory is exposed here.
                if let Some(account) = &config.account_runtime {
                    for socket in [&account.admission_socket, &account.mutation_socket] {
                        add_rule(&mut rules, socket, "rw");
                    }
                    for key in [
                        &account.admission_key_file,
                        &account.mutation_key_file,
                        &account.session_proof_key_file,
                    ] {
                        add_rule(&mut rules, key, "r");
                    }
                }

                // Web access stops at authenticated helper sockets and its own
                // grants. Mailbox key homes are never part of the web unveil view.
                for client in [
                    config.openpgp_inventory.as_ref(),
                    config.openpgp_crypto.as_ref(),
                    config.openpgp_public_admin.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    add_rule(&mut rules, &client.socket, "rw");
                    add_parent_dir_rules(&mut rules, &client.socket);
                    add_rule(&mut rules, &client.key_file, "r");
                    add_parent_dir_rules(&mut rules, &client.key_file);
                }

                Self {
                    promises_before_lock: if config.mailbox_helper_socket_path.is_some()
                        || config.openpgp_inventory.is_some()
                        || config.openpgp_crypto.is_some()
                        || config.openpgp_public_admin.is_some()
                        || config.account_runtime.is_some()
                    {
                        OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK
                    } else {
                        OPENBSD_SERVE_PROMISES_BEFORE_LOCK
                    },
                    promises_after_lock: if config.mailbox_helper_socket_path.is_some()
                        || config.openpgp_inventory.is_some()
                        || config.openpgp_crypto.is_some()
                        || config.openpgp_public_admin.is_some()
                        || config.account_runtime.is_some()
                    {
                        OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
                    } else {
                        OPENBSD_SERVE_PROMISES_AFTER_LOCK
                    },
                    unveil_rules: rules
                        .into_iter()
                        .map(|(path, permissions)| OpenbsdUnveilRule { path, permissions })
                        .collect(),
                }
            }
            crate::config::AppRunMode::MailboxHelper => {
                // The local helper only needs its own runtime socket plus the
                // current doveadm and Dovecot surfaces required for bounded
                // mailbox reads.
                add_rule(&mut rules, &config.state_root, "r");
                add_rule(&mut rules, &config.state_layout.runtime_dir, "rwc");
                add_doveadm_dependency_rules(&mut rules);
                add_rule(&mut rules, Path::new("/dev/null"), "rw");

                if let Some(userdb_socket_path) = &config.doveadm_userdb_socket_path {
                    add_rule(&mut rules, userdb_socket_path, "rw");
                    add_parent_dir_rules(&mut rules, userdb_socket_path);
                }
                if let Some(mailbox_helper_socket_path) = &config.mailbox_helper_socket_path {
                    // The helper binds and recreates its own Unix-domain
                    // socket, so the explicit socket path must retain create
                    // permission in helper mode instead of the narrower
                    // connect-only view used by the web runtime.
                    add_rule(&mut rules, mailbox_helper_socket_path, "rwc");
                    add_parent_dir_rules(&mut rules, mailbox_helper_socket_path);
                }
                if let Some(grant_key_path) = &config.mailbox_helper_grant_key_path {
                    add_rule(&mut rules, grant_key_path, "r");
                    add_parent_dir_rules(&mut rules, grant_key_path);
                }

                if let Some(policy_path) = &config.mailbox_retention_policy_path {
                    add_rule(&mut rules, policy_path, "r");
                    add_parent_dir_rules(&mut rules, policy_path);
                }

                Self {
                    promises_before_lock: OPENBSD_HELPER_PROMISES_BEFORE_LOCK,
                    promises_after_lock: OPENBSD_HELPER_PROMISES_AFTER_LOCK,
                    unveil_rules: rules
                        .into_iter()
                        .map(|(path, permissions)| OpenbsdUnveilRule { path, permissions })
                        .collect(),
                }
            }
            crate::config::AppRunMode::Bootstrap => Self {
                promises_before_lock: OPENBSD_SERVE_PROMISES_BEFORE_LOCK,
                promises_after_lock: OPENBSD_SERVE_PROMISES_AFTER_LOCK,
                unveil_rules: Vec::new(),
            },
        }
    }
}

/// Applies the current OpenBSD confinement mode for the serve runtime.
pub fn apply_runtime_confinement(config: &AppConfig, logger: &Logger) -> Result<(), String> {
    apply_runtime_confinement_for_accounts(config, logger, None).map(|_| ())
}

/// Authority for precisely the account leaves admitted by an actual locked
/// Serve plan. No constructor, caller flag or log-only path can mint it.
pub(crate) struct ServeAccountSeal {
    account: crate::config::AccountRuntimeConfig,
}
impl ServeAccountSeal {
    pub(crate) fn permits(&self, socket: &Path, keys: &[PathBuf], helper_uid: u32) -> bool {
        (socket == self.account.admission_socket
            && helper_uid == self.account.admission_helper_uid
            && keys == [self.account.admission_key_file.clone()])
            || (socket == self.account.mutation_socket
                && helper_uid == self.account.mutation_helper_uid
                && keys
                    == [
                        self.account.mutation_key_file.clone(),
                        self.account.session_proof_key_file.clone(),
                    ])
    }
}

pub(crate) fn apply_runtime_confinement_for_accounts(
    config: &AppConfig,
    logger: &Logger,
    clients: Option<(
        &crate::account_admission_runtime::Client,
        &crate::account_mutation_client::Client,
    )>,
) -> Result<Option<std::sync::Arc<ServeAccountSeal>>, String> {
    match config.openbsd_confinement_mode {
        OpenbsdConfinementMode::Disabled => Ok(None),
        OpenbsdConfinementMode::LogOnly => {
            let plan = OpenbsdConfinementPlan::from_config(config);
            logger.emit(&build_plan_event(config, &plan, "plan_logged"));
            Ok(None)
        }
        OpenbsdConfinementMode::Enforce => {
            let plan = OpenbsdConfinementPlan::from_config(config);
            logger.emit(&build_plan_event(config, &plan, "plan_enforcing"));
            // Concrete paired preflight immediately precedes actual apply.
            // A constructor-time snapshot alone cannot authorize the seal.
            let prepared_account = if config.run_mode == crate::config::AppRunMode::Serve {
                match (config.account_runtime.as_ref(), clients) {
                    (Some(account), Some((admission, mutation))) => {
                        if !mutation.purpose_separated_from(admission) {
                            return Err("account Serve custody unavailable".into());
                        }
                        admission
                            .preflight_serve(account)
                            .map_err(|_| "account Serve custody unavailable")?;
                        mutation
                            .preflight_serve(account)
                            .map_err(|_| "account Serve custody unavailable")?;
                        Some(account.clone())
                    }
                    _ => None,
                }
            } else {
                None
            };

            #[cfg(target_os = "openbsd")]
            {
                imp::apply_plan(&plan)?;
                logger.emit(
                    &LogEvent::new(
                        LogLevel::Info,
                        EventCategory::Bootstrap,
                        "openbsd_confinement_enabled",
                        "OpenBSD runtime confinement enabled",
                    )
                    .with_field(
                        "openbsd_confinement_mode",
                        config.openbsd_confinement_mode.as_str(),
                    )
                    .with_field("unveil_rule_count", plan.unveil_rules.len().to_string())
                    .with_field("promises_after_lock", plan.promises_after_lock),
                );
                Ok(prepared_account
                    .map(|account| std::sync::Arc::new(ServeAccountSeal { account })))
            }

            #[cfg(not(target_os = "openbsd"))]
            {
                let _ = prepared_account;
                Err(
                    "OpenBSD confinement enforcement was requested on a non-OpenBSD platform"
                        .to_string(),
                )
            }
        }
    }
}

/// Returns the peer UID for one connected Unix-domain socket through the
/// reviewed FFI boundary.
#[cfg(unix)]
pub(crate) fn unix_stream_peer_uid(stream: &UnixStream) -> Result<u32, String> {
    unix_stream_peer_uid_from_raw_fd(stream.as_raw_fd())
}

/// Inspect an inherited unnamed stream inside the reviewed Unix FFI boundary.
/// The caller retains ownership and rechecks this tuple around every frame.
#[cfg(all(test, unix))]
pub(crate) fn fixture_unix_stream_identity(
    stream: &UnixStream,
) -> Result<(libc::dev_t, libc::ino_t, libc::mode_t), String> {
    fixture_unix_stream_identity_for_peer(stream, None)
}

#[cfg(all(test, unix))]
fn fixture_unix_stream_identity_for_peer(
    stream: &UnixStream,
    expected_peer: Option<u32>,
) -> Result<(libc::dev_t, libc::ino_t, libc::mode_t), String> {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(stream.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err("fixture descriptor metadata unavailable".into());
    }
    let info = unsafe { info.assume_init() };
    let mut kind: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    if info.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut size,
            )
        } != 0
        || size as usize != std::mem::size_of_val(&kind)
        || kind != libc::SOCK_STREAM
        || !stream
            .local_addr()
            .map_err(|_| "fixture local address unavailable")?
            .is_unnamed()
        || !stream
            .peer_addr()
            .map_err(|_| "fixture peer address unavailable")?
            .is_unnamed()
        || unix_stream_peer_uid(stream)? != expected_peer.unwrap_or_else(effective_uid)
    {
        return Err("fixture unnamed stream identity refused".into());
    }
    Ok((info.st_dev, info.st_ino, info.st_mode))
}

/// Fixed HTTP qualification role only: irreversibly dropped web identity and
/// a root-created unnamed stream whose connected peer is still root. These
/// are descriptor/credential witnesses; root also owns the exact born process
/// and socketpair. No caller-selected UID or privilege drop occurs here.
#[cfg(all(test, unix))]
pub(crate) fn fixture_http_pilot_root_control_identity(
    stream: &UnixStream,
) -> Result<(libc::dev_t, libc::ino_t, libc::mode_t), String> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: native credential queries write only to these local scalars.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
        || (real_uid, effective_uid, saved_uid) != (1001, 1001, 1001)
        || (real_gid, effective_gid, saved_gid) != (1003, 1003, 1003)
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return Err("fixed HTTP web identity refused".into());
    }
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat inspects the already-owned descriptor without changing it.
    if unsafe { libc::fstat(stream.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err("HTTP root control metadata unavailable".into());
    }
    let info = unsafe { info.assume_init() };
    if info.st_uid != 0 {
        return Err("HTTP control was not created by root".into());
    }
    fixture_unix_stream_identity_for_peer(stream, Some(0))
}

/// Transfer the one fixed HTTP control descriptor and close its authority at
/// every later exec boundary. It was inheritable only for this launch.
#[cfg(all(test, unix))]
pub(crate) fn fixture_owned_http_pilot_control(raw: i32) -> Result<UnixStream, String> {
    let stream = fixture_owned_unix_stream(raw)?;
    fixture_http_pilot_root_control_identity(&stream)?;
    // SAFETY: only this already-owned descriptor's exec-inheritance flag changes.
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        || !descriptor_is_cloexec(stream.as_raw_fd())
            .map_err(|_| "HTTP control flags unavailable")?
    {
        return Err("HTTP control exec inheritance refused".into());
    }
    Ok(stream)
}

/// Take exactly one valid inherited fixture descriptor. The caller must not
/// retain another owner of the raw descriptor after this transfer.
#[cfg(all(test, unix))]
pub(crate) fn fixture_owned_unix_stream(raw: i32) -> Result<UnixStream, String> {
    use std::os::fd::FromRawFd;
    if !(3..=1024).contains(&raw) {
        return Err("fixture descriptor number refused".into());
    }
    let stream = unsafe { UnixStream::from_raw_fd(raw) };
    Ok(stream)
}

/// Returns the effective Unix UID through the reviewed FFI boundary.
#[cfg(unix)]
pub(crate) fn effective_uid() -> u32 {
    effective_uid_raw()
}

#[cfg(unix)]
fn effective_uid_raw() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

#[cfg(all(
    unix,
    any(
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios"
    )
))]
fn unix_stream_peer_uid_from_raw_fd(raw_fd: i32) -> Result<u32, String> {
    let mut peer_uid = 0 as libc::uid_t;
    let mut peer_gid = 0 as libc::gid_t;
    let result = unsafe { libc::getpeereid(raw_fd, &mut peer_uid, &mut peer_gid) };
    if result != 0 {
        return Err(format!(
            "failed to inspect helper peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(peer_uid as u32)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn unix_stream_peer_uid_from_raw_fd(raw_fd: i32) -> Result<u32, String> {
    let mut peer_credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut peer_credentials_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer_credentials as *mut libc::ucred).cast(),
            &mut peer_credentials_len,
        )
    };
    if result != 0 {
        return Err(format!(
            "failed to inspect helper peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(peer_credentials.uid)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    ))
))]
fn unix_stream_peer_uid_from_raw_fd(_raw_fd: i32) -> Result<u32, String> {
    Err("helper peer credential inspection is not supported on this Unix platform".to_string())
}

/// Adds one unveil rule while preserving the strongest permissions per path.
fn add_rule(rules: &mut BTreeMap<PathBuf, String>, path: &Path, permissions: &str) {
    let entry = rules.entry(path.to_path_buf()).or_default();
    for permission in permissions.chars() {
        if !entry.contains(permission) {
            entry.push(permission);
        }
    }
}

/// Adds read-only unveil rules for parent directories of an explicit helper path.
fn add_parent_dir_rules(rules: &mut BTreeMap<PathBuf, String>, path: &Path) {
    let mut current = path.parent();
    while let Some(parent) = current {
        if parent == Path::new("/") {
            break;
        }
        add_rule(rules, parent, "r");
        current = parent.parent();
    }
}

/// Adds the current helper-side `doveadm` dependency view. The helper prefers
/// exact executable, loader, library, config, and Dovecot socket paths when it
/// can resolve them on the current host, but falls back to the broader library
/// roots if a host does not expose the expected versioned files.
fn add_doveadm_dependency_rules(rules: &mut BTreeMap<PathBuf, String>) {
    add_rule(rules, Path::new("/usr/local/bin/doveadm"), "x");
    add_if_exists(rules, Path::new("/usr/local/bin/doveconf"), "x");

    if !add_if_exists(rules, Path::new("/usr/libexec/ld.so"), "r") {
        add_rule(rules, Path::new("/usr/libexec"), "rx");
    }
    add_if_exists(rules, Path::new("/var/run/ld.so.hints"), "r");

    add_resolved_library_rules(
        rules,
        Path::new("/usr/lib"),
        &OPENBSD_SYSTEM_LIBRARY_PREFIXES,
    );
    add_resolved_library_rules(
        rules,
        Path::new("/usr/local/lib"),
        &OPENBSD_LOCAL_LIBRARY_PREFIXES,
    );

    if !add_if_exists(rules, Path::new("/usr/local/lib/dovecot"), "rx") {
        add_rule(rules, Path::new("/usr/local/lib"), "rx");
    }

    let mut added_explicit_config_path = false;
    added_explicit_config_path |= add_if_exists(rules, Path::new("/etc/dovecot/dovecot.conf"), "r");
    added_explicit_config_path |= add_if_exists(rules, Path::new("/etc/dovecot/conf.d"), "r");
    added_explicit_config_path |= add_if_exists(rules, Path::new("/etc/dovecot/local.conf"), "r");
    if !added_explicit_config_path {
        add_if_exists(rules, Path::new("/etc/dovecot"), "r");
    }

    add_if_exists(rules, Path::new("/var/dovecot/config"), "rw");
}

/// Adds the current browser-runtime sendmail dependency view. This follows the
/// validated OpenBSD path where `/usr/sbin/sendmail` is a mailwrapper that
/// dispatches into the local Postfix sendmail compatibility binary.
fn add_sendmail_dependency_rules(rules: &mut BTreeMap<PathBuf, String>) {
    add_if_exists(rules, Path::new("/usr/sbin/sendmail"), "x");
    add_if_exists(rules, Path::new("/usr/local/sbin/sendmail"), "x");
    add_if_exists(rules, Path::new("/usr/local/sbin/postdrop"), "x");

    if !add_if_exists(rules, Path::new("/usr/libexec/ld.so"), "r") {
        add_rule(rules, Path::new("/usr/libexec"), "rx");
    }
    add_if_exists(rules, Path::new("/var/run/ld.so.hints"), "r");

    add_resolved_library_rules(
        rules,
        Path::new("/usr/lib"),
        &OPENBSD_SENDMAIL_SYSTEM_LIBRARY_PREFIXES,
    );
    add_resolved_library_rules(
        rules,
        Path::new("/usr/local/lib"),
        &OPENBSD_SENDMAIL_LOCAL_LIBRARY_PREFIXES,
    );

    add_if_exists(rules, Path::new("/etc/mailer.conf"), "r");
    add_if_exists(rules, Path::new("/etc/postfix/main.cf"), "r");
    add_if_exists(rules, Path::new("/etc/localtime"), "r");
    add_if_exists(rules, Path::new("/usr/share/zoneinfo/posixrules"), "r");
    add_if_exists(rules, Path::new("/etc/pwd.db"), "r");
    add_if_exists(rules, Path::new("/etc/group"), "r");
    add_if_exists(rules, Path::new("/dev/urandom"), "r");
    add_if_exists(rules, Path::new("/var/spool/postfix"), "rwc");
}

/// Adds exact versioned library paths when they can be resolved under the
/// supplied directory, otherwise falls back to the broader directory path.
fn add_resolved_library_rules(
    rules: &mut BTreeMap<PathBuf, String>,
    dir: &Path,
    prefixes: &[&str],
) {
    match resolve_prefixed_paths(dir, prefixes) {
        Some(paths) => {
            for path in paths {
                add_rule(rules, &path, "r");
            }
        }
        None => {
            if dir.exists() {
                add_rule(rules, dir, "rx");
            }
        }
    }
}

/// Returns one stable exact path for every requested filename prefix inside the
/// supplied directory, or `None` when any prefix cannot be resolved.
fn resolve_prefixed_paths(dir: &Path, prefixes: &[&str]) -> Option<Vec<PathBuf>> {
    let entries = fs::read_dir(dir).ok()?;
    let mut file_names = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    file_names.sort();

    let mut resolved = Vec::with_capacity(prefixes.len());
    for prefix in prefixes {
        let path = file_names.iter().find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })?;
        resolved.push(path.clone());
    }

    Some(resolved)
}

/// Adds one rule only when the path currently exists on the host.
fn add_if_exists(rules: &mut BTreeMap<PathBuf, String>, path: &Path, permissions: &str) -> bool {
    if path.exists() {
        add_rule(rules, path, permissions);
        true
    } else {
        false
    }
}

/// Builds the operator-visible summary event for the current confinement plan.
fn build_plan_event(
    config: &AppConfig,
    plan: &OpenbsdConfinementPlan,
    action: &'static str,
) -> LogEvent {
    let unveiled_paths = plan
        .unveil_rules
        .iter()
        .map(|rule| format!("{}:{}", rule.path.display(), rule.permissions))
        .collect::<Vec<_>>()
        .join(",");

    LogEvent::new(
        LogLevel::Info,
        EventCategory::Bootstrap,
        action,
        "OpenBSD runtime confinement plan prepared",
    )
    .with_field(
        "openbsd_confinement_mode",
        config.openbsd_confinement_mode.as_str(),
    )
    .with_field("promises_before_lock", plan.promises_before_lock)
    .with_field("promises_after_lock", plan.promises_after_lock)
    .with_field("unveil_rule_count", plan.unveil_rules.len().to_string())
    .with_field("unveiled_paths", unveiled_paths)
}

#[cfg(target_os = "openbsd")]
mod imp {
    use std::ffi::CString;
    use std::io;
    use std::os::raw::{c_char, c_int};

    use super::{OpenbsdConfinementPlan, OpenbsdUnveilRule};

    unsafe extern "C" {
        fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
        fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;
    }

    /// Applies the current plan by reducing promises, unveiling paths, locking
    /// the view, and then dropping the `unveil` promise.
    pub fn apply_plan(plan: &OpenbsdConfinementPlan) -> Result<(), String> {
        pledge_raw(plan.promises_before_lock)?;

        for rule in &plan.unveil_rules {
            unveil_rule(rule)?;
        }

        lock_unveil()?;
        pledge_raw(plan.promises_after_lock)?;
        Ok(())
    }

    /// Calls pledge with the supplied promise string and no execpromises so
    /// helper processes can start unpledged after `execve(2)`.
    fn pledge_raw(promises: &str) -> Result<(), String> {
        let promises = CString::new(promises)
            .map_err(|_| "pledge promise string contained interior NUL".to_string())?;
        let result = unsafe { pledge(promises.as_ptr(), std::ptr::null()) };
        if result == -1 {
            return Err(format!("pledge failed: {}", io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Applies one unveil rule using the exact path and permission set chosen
    /// by the current confinement plan.
    fn unveil_rule(rule: &OpenbsdUnveilRule) -> Result<(), String> {
        let path = CString::new(rule.path.as_os_str().as_encoded_bytes().to_vec())
            .map_err(|_| format!("unveil path {:?} contained interior NUL", rule.path))?;
        let permissions = CString::new(rule.permissions.clone())
            .map_err(|_| "unveil permission string contained interior NUL".to_string())?;

        let result = unsafe { unveil(path.as_ptr(), permissions.as_ptr()) };
        if result == -1 {
            return Err(format!(
                "unveil failed for {} with permissions {}: {}",
                rule.path.display(),
                rule.permissions,
                io::Error::last_os_error(),
            ));
        }

        Ok(())
    }

    /// Locks the current unveil table so later code cannot widen filesystem
    /// visibility accidentally.
    fn lock_unveil() -> Result<(), String> {
        let result = unsafe { unveil(std::ptr::null(), std::ptr::null()) };
        if result == -1 {
            return Err(format!(
                "unveil lock failed: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(())
    }
}

/// Test child only: expose EOF while the owned disposable leader stays alive.
#[cfg(test)]
pub(crate) fn close_disposable_fixture_output() -> Result<(), String> {
    if std::env::var("OSMAP_CRYPTO_PROCESS_FIXTURE").as_deref() != Ok("closed_output_running") {
        return Err("disposable output fixture required".into());
    }
    for descriptor in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // The exact test child owns these standard descriptors; production
        // builds do not contain this helper or its fixture-only entrypoint.
        if unsafe { libc::close(descriptor) } != 0 {
            return Err("disposable output close failed".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppRunMode, LogFormat, RuntimeEnvironment};
    use crate::state::{StateLayout, StateLayoutPaths};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn account_admission_stop_signal_is_exclusive_and_restored_in_disposable_process() {
        use crate::auth::{CommandExecutor, SystemCommandExecutor};
        const CHILD: &str = "OSMAP_TEST_ACCOUNT_ADMISSION_SIGNAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            let guard = AccountAdmissionSignals::install().unwrap();
            assert!(!guard.stop_flag().load(std::sync::atomic::Ordering::SeqCst));
            assert!(AccountAdmissionSignals::install().is_err());
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            assert!(guard.stop_flag().load(std::sync::atomic::Ordering::SeqCst));
            drop(guard);
            assert_eq!(
                unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) },
                libc::SIG_IGN
            );
            println!("account_admission_stop_and_restore=PASS");
            return;
        }
        let result = SystemCommandExecutor.run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/bin/env",
            &[
                format!("{CHILD}=1"),
                std::env::current_exe().unwrap().to_str().unwrap().into(),
                "--exact".into(),
                "openbsd::tests::account_admission_stop_signal_is_exclusive_and_restored_in_disposable_process".into(),
                "--nocapture".into(),
            ],
            &[], std::time::Duration::from_secs(2), 4096,
        ).unwrap();
        assert_eq!(result.status_code, 0);
        assert!(result
            .stdout
            .contains("account_admission_stop_and_restore=PASS\n"));
    }

    #[cfg(unix)]
    #[test]
    fn inherited_ignored_term_is_restored_in_a_disposable_process() {
        use crate::auth::{CommandExecutor, SystemCommandExecutor};
        use std::io::Write as _;
        const CHILD: &str = "OSMAP_TEST_CRYPTO_TERMINATION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            restore_crypto_termination_signal().unwrap();
            assert_eq!(
                unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) },
                libc::SIG_DFL
            );
            println!("crypto_termination_default_restored=PASS");
            std::io::stdout().flush().unwrap();
            unsafe { libc::raise(libc::SIGTERM) };
            std::process::exit(77);
        }
        let result = SystemCommandExecutor
            .run_with_stdin_bytes_timeout_and_output_limit(
                "/usr/bin/env",
                &[
                    format!("{CHILD}=1"),
                    std::env::current_exe().unwrap().to_str().unwrap().into(),
                    "--exact".into(),
                    "openbsd::tests::inherited_ignored_term_is_restored_in_a_disposable_process"
                        .into(),
                    "--nocapture".into(),
                ],
                &[],
                std::time::Duration::from_secs(2),
                4096,
            )
            .unwrap();
        assert_eq!(result.status_code, -1);
        assert!(result
            .stdout
            .contains("crypto_termination_default_restored=PASS\n"));
    }

    fn config_fixture(mode: OpenbsdConfinementMode) -> AppConfig {
        AppConfig {
            account_runtime: None,
            openpgp_inventory: None,
            openpgp_crypto: None,
            openpgp_public_admin: None,
            run_mode: AppRunMode::Serve,
            environment: RuntimeEnvironment::Production,
            listen_addr: "127.0.0.1:8080".to_string(),
            allowed_hosts: vec!["localhost".to_string()],
            doveadm_auth_socket_path: None,
            trusted_web_runtime_uid: None,
            doveadm_userdb_socket_path: None,
            mailbox_helper_socket_path: None,
            mailbox_helper_grant_key_path: None,
            mailbox_helper_peer_uid: None,
            mailbox_retention_policy_path: None,
            sender_authority_path: None,
            state_root: PathBuf::from("/var/lib/osmap"),
            log_level: LogLevel::Info,
            log_format: LogFormat::Text,
            state_layout: StateLayout::new(StateLayoutPaths {
                root_dir: PathBuf::from("/var/lib/osmap"),
                runtime_dir: PathBuf::from("/var/lib/osmap/run"),
                session_dir: PathBuf::from("/var/lib/osmap/sessions"),
                settings_dir: PathBuf::from("/var/lib/osmap/settings"),
                draft_dir: PathBuf::from("/var/lib/osmap/drafts"),
                audit_dir: PathBuf::from("/var/lib/osmap/audit"),
                cache_dir: PathBuf::from("/var/lib/osmap/cache"),
                totp_secret_dir: PathBuf::from("/var/lib/osmap/secrets/totp"),
            })
            .expect("layout should be valid"),
            http_max_concurrent_connections: 16,
            mailbox_worker_budget: 8,
            search_worker_budget: 4,
            send_worker_budget: 2,
            auth_worker_budget: 4,
            expensive_request_timeout_seconds: 5,
            auth_backend_timeout_seconds: 20,
            session_lifetime_seconds: 43200,
            session_idle_timeout_seconds: 1800,
            totp_allowed_skew_steps: 1,
            login_throttle_max_failures: 5,
            login_throttle_remote_max_failures: 12,
            login_throttle_window_seconds: 300,
            login_throttle_lockout_seconds: 900,
            submission_throttle_max_submissions: 10,
            submission_throttle_remote_max_submissions: 25,
            submission_throttle_window_seconds: 300,
            submission_throttle_lockout_seconds: 900,
            message_move_throttle_max_moves: 20,
            message_move_throttle_remote_max_moves: 60,
            message_move_throttle_window_seconds: 300,
            message_move_throttle_lockout_seconds: 900,
            openbsd_confinement_mode: mode,
        }
    }

    #[test]
    fn sender_identity_inventory_is_unveiled_read_only_for_serve_without_helper_authority() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        let path = PathBuf::from("/etc/osmap/sender-authority.json");
        assert!(!OpenbsdConfinementPlan::from_config(&config)
            .unveil_rules
            .iter()
            .any(|rule| rule.path == path));
        config.sender_authority_path = Some(path.clone());
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));
        let plan = OpenbsdConfinementPlan::from_config(&config);
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == path && rule.permissions == "r"));
        assert_eq!(
            plan.promises_after_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
        );
        config.run_mode = AppRunMode::MailboxHelper;
        assert!(!OpenbsdConfinementPlan::from_config(&config)
            .unveil_rules
            .iter()
            .any(|rule| rule.path == path));
    }

    #[test]
    fn retention_policy_is_added_read_only_in_helper_plan_only() {
        let mut config = config_fixture(OpenbsdConfinementMode::Enforce);
        let policy = PathBuf::from("/var/db/osmap-retention/policy.json");
        config.mailbox_retention_policy_path = Some(policy.clone());
        let web = OpenbsdConfinementPlan::from_config(&config);
        assert!(!web.unveil_rules.iter().any(|rule| rule.path == policy));
        config.run_mode = AppRunMode::MailboxHelper;
        let helper = OpenbsdConfinementPlan::from_config(&config);
        assert!(helper
            .unveil_rules
            .iter()
            .any(|rule| rule.path == policy && rule.permissions == "r"));
        assert!(helper.unveil_rules.iter().any(|rule| rule.path
            == Path::new("/var/db/osmap-retention")
            && rule.permissions == "r"));
        assert_eq!(
            helper.promises_after_lock,
            OPENBSD_HELPER_PROMISES_AFTER_LOCK
        );
        config.mailbox_retention_policy_path = None;
        let absent = OpenbsdConfinementPlan::from_config(&config);
        assert!(!absent.unveil_rules.iter().any(|rule| rule.path == policy));
    }

    #[test]
    fn folder_rename_helper_completion_retains_only_required_flock_promise() {
        let mut config = config_fixture(OpenbsdConfinementMode::Enforce);
        config.run_mode = crate::config::AppRunMode::MailboxHelper;
        let plan = OpenbsdConfinementPlan::from_config(&config);
        assert_eq!(
            plan.promises_before_lock,
            "stdio rpath wpath cpath fattr flock unix proc exec unveil"
        );
        assert_eq!(
            plan.promises_after_lock,
            "stdio rpath wpath cpath fattr flock unix proc exec"
        );
        assert!(!plan
            .promises_after_lock
            .split_whitespace()
            .any(|p| matches!(p, "inet" | "unveil")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|r| r.path == config.state_layout.settings_dir && r.permissions.contains('w')));
    }

    #[test]
    fn configured_account_pair_adds_only_exact_endpoint_and_purpose_key_rules() {
        use std::collections::BTreeMap;
        let mut env = BTreeMap::from([
            ("OSMAP_RUN_MODE".into(), "serve".into()),
            ("OSMAP_STATE_DIR".into(), "/var/lib/osmap".into()),
            ("OSMAP_OPENBSD_CONFINEMENT_MODE".into(), "enforce".into()),
        ]);
        let disabled = OpenbsdConfinementPlan::from_config(&AppConfig::from_env_map(&env).unwrap());
        let expected = [
            ("/var/lib/osmap/account-helper/admission.sock", "rw"),
            ("/var/lib/osmap/account-helper/mutation.sock", "rw"),
            ("/var/lib/osmap/account-helper/admission.key", "r"),
            ("/var/lib/osmap/account-helper/mutation.key", "r"),
            ("/var/lib/osmap/account-helper/session-proof.key", "r"),
        ];
        for (name, value) in [
            ("OSMAP_ACCOUNT_ADMISSION_SOCKET", expected[0].0),
            ("OSMAP_ACCOUNT_ADMISSION_KEY_FILE", expected[2].0),
            ("OSMAP_ACCOUNT_ADMISSION_HELPER_UID", "0"),
            ("OSMAP_ACCOUNT_MUTATION_SOCKET", expected[1].0),
            ("OSMAP_ACCOUNT_MUTATION_KEY_FILE", expected[3].0),
            (
                "OSMAP_ACCOUNT_MUTATION_SESSION_PROOF_KEY_FILE",
                expected[4].0,
            ),
            ("OSMAP_ACCOUNT_MUTATION_HELPER_UID", "0"),
        ] {
            env.insert(name.into(), value.into());
        }
        let configured = AppConfig::from_env_map(&env).unwrap();
        let plan = OpenbsdConfinementPlan::from_config(&configured);
        let added: Vec<_> = plan
            .unveil_rules
            .iter()
            .filter(|rule| !disabled.unveil_rules.contains(rule))
            .map(|rule| (rule.path.as_path(), rule.permissions.as_str()))
            .collect();
        let mut expected: Vec<_> = expected
            .into_iter()
            .map(|(path, permissions)| (Path::new(path), permissions))
            .collect();
        expected.sort_by_key(|row| row.0);
        assert_eq!(added, expected);
        assert!(disabled
            .unveil_rules
            .iter()
            .all(|rule| plan.unveil_rules.contains(rule)));
        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK
        );
        assert_eq!(
            plan.promises_after_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
        );
        assert!(!disabled
            .promises_before_lock
            .split_whitespace()
            .any(|p| p == "unix"));
        assert!(!disabled
            .promises_after_lock
            .split_whitespace()
            .any(|p| p == "unix"));
        const {
            assert!(!crate::account_admission_runtime::NATIVE_CONFINEMENT_QUALIFIED);
            assert!(!crate::account_mutation_client::NATIVE_CONFINEMENT_QUALIFIED);
        }
    }

    #[test]
    fn builds_concrete_plan_from_runtime_config() {
        let plan =
            OpenbsdConfinementPlan::from_config(&config_fixture(OpenbsdConfinementMode::LogOnly));

        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_SERVE_PROMISES_BEFORE_LOCK
        );
        assert_eq!(plan.promises_after_lock, OPENBSD_SERVE_PROMISES_AFTER_LOCK);
        assert!(plan
            .promises_before_lock
            .split_whitespace()
            .any(|promise| promise == "flock"));
        assert!(plan
            .promises_after_lock
            .split_whitespace()
            .any(|promise| promise == "flock"));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/usr/local/bin/doveadm")
                && rule.permissions.contains('x')));
        if Path::new("/usr/sbin/sendmail").exists() {
            assert!(plan
                .unveil_rules
                .iter()
                .any(|rule| rule.path == Path::new("/usr/sbin/sendmail")
                    && rule.permissions.contains('x')));
        }
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap") && rule.permissions == "r"));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap/sessions")
                && rule.permissions.contains('w')));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap/settings")
                && rule.permissions.contains('w')));
        if Path::new("/usr/sbin/sendmail").exists() {
            assert!(plan
                .unveil_rules
                .iter()
                .any(|rule| rule.path == Path::new("/usr/sbin/sendmail")
                    && rule.permissions.contains('x')));
        }
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/dovecot")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/etc/mail")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/log/dovecot.log")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/spool/smtpd")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var")));
    }

    #[test]
    fn adds_explicit_auth_socket_and_parent_dirs_when_configured() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.doveadm_auth_socket_path = Some(PathBuf::from("/var/run/osmap/dovecot-auth"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/run/osmap/dovecot-auth")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/run/osmap") && rule.permissions == "r"));
    }

    #[test]
    fn applies_log_only_mode_without_platform_specific_failure() {
        let config = config_fixture(OpenbsdConfinementMode::LogOnly);
        let logger = Logger::new(LogFormat::Text, LogLevel::Info);

        assert!(apply_runtime_confinement(&config, &logger).is_ok());
    }

    #[test]
    fn account_serve_seal_is_absent_without_actual_native_enforcement() {
        let logger = Logger::new(LogFormat::Text, LogLevel::Info);
        for mode in [
            OpenbsdConfinementMode::Disabled,
            OpenbsdConfinementMode::LogOnly,
        ] {
            let config = config_fixture(mode);
            assert!(
                apply_runtime_confinement_for_accounts(&config, &logger, None)
                    .unwrap()
                    .is_none()
            );
        }
        #[cfg(not(target_os = "openbsd"))]
        assert!(apply_runtime_confinement_for_accounts(
            &config_fixture(OpenbsdConfinementMode::Enforce),
            &logger,
            None
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn http_pilot_root_control_refuses_self_peer_and_keeps_legacy_same_uid_check() {
        let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(fixture_unix_stream_identity(&left).is_ok());
        // A locally created pair cannot establish both irreversibly dropped
        // web credentials and root-born socket ownership/root peer authority.
        assert!(fixture_http_pilot_root_control_identity(&left).is_err());
    }

    #[test]
    fn adds_explicit_userdb_socket_and_parent_dirs_when_configured() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.doveadm_userdb_socket_path = Some(PathBuf::from("/var/run/osmap-userdb"));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/run/osmap-userdb")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/run") && rule.permissions == "r"));
    }

    #[test]
    fn adds_mailbox_helper_socket_and_parent_dirs_when_configured() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));
        config.mailbox_helper_grant_key_path = Some(PathBuf::from(
            "/var/lib/osmap/secrets/mailbox-helper-grant.key",
        ));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/run/mailbox-helper.sock")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap/run")
                && rule.permissions.contains('r')));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/secrets/mailbox-helper-grant.key")
                && rule.permissions == "r"
        }));
    }

    #[test]
    fn public_admin_client_unveils_only_socket_and_grant() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.openpgp_public_admin = Some(crate::config::OpenPgpAdminConfig {
            socket: PathBuf::from("/var/lib/osmap-gpg/run/public-admin.sock"),
            key_file: PathBuf::from("/var/lib/osmap/secrets/openpgp-public-admin.key"),
            helper_uid: 1234,
        });
        let plan = OpenbsdConfinementPlan::from_config(&config);
        assert_eq!(
            plan.promises_after_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
        );
        assert!(plan.unveil_rules.iter().any(|rule| rule.path
            == config.openpgp_public_admin.as_ref().unwrap().socket
            && rule.permissions.contains('w')));
        assert!(plan.unveil_rules.iter().any(|rule| rule.path
            == config.openpgp_public_admin.as_ref().unwrap().key_file
            && rule.permissions == "r"));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap-gpg/accounts")));
    }

    #[test]
    fn helper_mode_uses_unix_promises_and_skips_sendmail_paths() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.run_mode = AppRunMode::MailboxHelper;
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));
        config.doveadm_userdb_socket_path = Some(PathBuf::from("/var/run/osmap-userdb"));
        config.mailbox_helper_grant_key_path = Some(PathBuf::from(
            "/var/lib/osmap/secrets/mailbox-helper-grant.key",
        ));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_HELPER_PROMISES_BEFORE_LOCK
        );
        assert_eq!(plan.promises_after_lock, OPENBSD_HELPER_PROMISES_AFTER_LOCK);
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/usr/sbin/sendmail")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/spool/postfix")));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/run/osmap-userdb")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap") && rule.permissions == "r"));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/run/mailbox-helper.sock")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/secrets/mailbox-helper-grant.key")
                && rule.permissions == "r"
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/usr/local/bin/doveadm")
                && rule.permissions.contains('x')));
        if Path::new("/var/dovecot/config").exists() {
            assert!(plan
                .unveil_rules
                .iter()
                .any(|rule| rule.path == Path::new("/var/dovecot/config")
                    && rule.permissions.contains('w')));
        }
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/log/dovecot.log")));
    }

    #[test]
    fn serve_mode_with_helper_socket_uses_unix_promises_and_skips_userdb_socket() {
        let mut config = config_fixture(OpenbsdConfinementMode::LogOnly);
        config.mailbox_helper_socket_path =
            Some(PathBuf::from("/var/lib/osmap/run/mailbox-helper.sock"));
        config.doveadm_userdb_socket_path = Some(PathBuf::from("/var/run/osmap-userdb"));
        config.mailbox_helper_grant_key_path = Some(PathBuf::from(
            "/var/lib/osmap/secrets/mailbox-helper-grant.key",
        ));

        let plan = OpenbsdConfinementPlan::from_config(&config);

        assert_eq!(
            plan.promises_before_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_BEFORE_LOCK
        );
        assert_eq!(
            plan.promises_after_lock,
            OPENBSD_SERVE_WITH_HELPER_PROMISES_AFTER_LOCK
        );
        assert!(plan
            .promises_before_lock
            .split_whitespace()
            .any(|promise| promise == "flock"));
        assert!(plan
            .promises_after_lock
            .split_whitespace()
            .any(|promise| promise == "flock"));
        assert!(plan.unveil_rules.iter().any(|rule| {
            rule.path == Path::new("/var/lib/osmap/run/mailbox-helper.sock")
                && rule.permissions.contains('r')
                && rule.permissions.contains('w')
        }));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/lib/osmap") && rule.permissions == "r"));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/run/osmap-userdb")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/dovecot")));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == Path::new("/var/log/dovecot.log")));
    }

    #[test]
    fn resolves_prefixed_paths_to_stable_exact_matches() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("osmap-openbsd-paths-{now}"));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        fs::write(temp_dir.join("libalpha.so.2.0"), "").expect("alpha file should exist");
        fs::write(temp_dir.join("libbeta.so.1.0"), "").expect("beta file should exist");
        fs::write(temp_dir.join("libgamma.txt"), "").expect("noise file should exist");

        let resolved = resolve_prefixed_paths(&temp_dir, &["libalpha.so.", "libbeta.so."])
            .expect("prefixes should resolve");

        assert_eq!(
            resolved,
            vec![
                temp_dir.join("libalpha.so.2.0"),
                temp_dir.join("libbeta.so.1.0")
            ]
        );

        fs::remove_dir_all(&temp_dir).expect("temp dir should be removed");
    }
}
