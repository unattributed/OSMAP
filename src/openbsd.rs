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

/// Owned ancillary sockets; no Clone, raw-FD constructor or serialization.
#[cfg(unix)]
pub(crate) struct ReceivedImapIo {
    sockets: Vec<std::os::fd::OwnedFd>,
}
#[cfg(unix)]
impl ReceivedImapIo {
    pub(crate) fn len(&self) -> usize {
        self.sockets.len()
    }
    pub(crate) fn fd(&self, index: usize) -> Option<&std::os::fd::OwnedFd> {
        self.sockets.get(index)
    }
}
#[cfg(unix)]
pub(crate) fn password_shutdown_imap_io(io: &ReceivedImapIo) -> io::Result<()> {
    let mut failure = None;
    for socket in &io.sockets {
        if let Err(error) = password_shutdown_socket(socket) {
            // Input/output can be distinct FDs for one socket description, or
            // the client can already have disconnected. This alone is never a
            // completion witness: Registry still requires control EOF and WHO0.
            if error.raw_os_error() != Some(libc::ENOTCONN) {
                failure = Some(error);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

/// Observe only the private lifetime-control socket; never read/peek mail data.
#[cfg(unix)]
pub(crate) fn password_imap_control_eof(stream: &UnixStream) -> io::Result<bool> {
    let mut byte = 0u8;
    let count = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if count == 0 {
        return Ok(true);
    }
    if count > 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Receive the first publication byte and one or two socket descriptors. The
/// caller has already authenticated the Unix peer. Kernel CLOEXEC is atomic
/// with receipt, so concurrently spawned utilities cannot inherit these FDs.
#[cfg(unix)]
pub(crate) fn password_receive_imap_io_first(
    stream: &UnixStream,
    deadline: std::time::Instant,
) -> io::Result<(u8, ReceivedImapIo)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut byte = [0u8; 1];
    loop {
        let left = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(left))?;
        // cmsghdr elements supply native alignment as well as enough capacity
        // to recover and close surplus descriptors on a rejected transfer.
        let mut control: [libc::cmsghdr; 16] = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let mut descriptors: Vec<OwnedFd> = Vec::new();
        let mut valid =
            received == 1 && message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0;
        let mut count = 0usize;
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            let h = unsafe { &*header };
            let base = unsafe { libc::CMSG_LEN(0) } as usize;
            let length = h.cmsg_len as usize;
            let data = length.checked_sub(base);
            if h.cmsg_level != libc::SOL_SOCKET
                || h.cmsg_type != libc::SCM_RIGHTS
                || data.is_none()
                || data.unwrap_or(1) % std::mem::size_of::<libc::c_int>() != 0
            {
                valid = false;
            } else {
                count += 1;
                let slots = data.unwrap_or(0) / std::mem::size_of::<libc::c_int>();
                for index in 0..slots {
                    let fd = unsafe {
                        std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        )
                    };
                    if fd < 0 {
                        valid = false;
                        continue;
                    }
                    // Every installed right is owned immediately, including
                    // surplus/non-socket rights; all refusals drop the vector.
                    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
                    if password_stream_socket(&fd).is_err() {
                        valid = false;
                    }
                    descriptors.push(fd);
                }
            }
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        if !valid
            || count != 1
            || !(1..=2).contains(&descriptors.len())
            || std::time::Instant::now() >= deadline
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok((
            byte[0],
            ReceivedImapIo {
                sockets: descriptors,
            },
        ));
    }
}

#[cfg(unix)]
pub(crate) fn password_stream_socket(fd: &std::os::fd::OwnedFd) -> io::Result<()> {
    let mut kind: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&kind) || kind != libc::SOCK_STREAM {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn password_shutdown_socket(fd: &std::os::fd::OwnedFd) -> io::Result<()> {
    password_stream_socket(fd)?;
    if unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Observe only this direct child's exit while retaining its unreaped PID/PGID
/// lease. EOF is not process completion. The caller remains responsible for
/// final owned-group cleanup and Child::try_wait reaping.
#[cfg(unix)]
pub(crate) fn owned_child_exited_without_reap(child_pid: u32) -> io::Result<bool> {
    if child_pid <= 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            child_pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // P_PID selects only this exact owned child. The public event header is
    // sufficient and avoids libc 0.2.183's incorrect OpenBSD si_pid() accessor.
    // WNOHANG with no event leaves this zeroed header at zero; WNOWAIT retains
    // the selected child's PID/PGID ownership for subsequent cleanup.
    Ok(info.si_signo == libc::SIGCHLD
        && matches!(
            info.si_code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        ))
}

#[cfg(unix)]
pub(crate) fn private_leaf_open(
    directory: &fs::File,
    name: &std::ffi::CStr,
    flags: i32,
) -> io::Result<fs::File> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}
#[cfg(unix)]
pub(crate) fn private_file_try_lock(file: &fs::File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(unix)]
pub(crate) fn private_file_unlock(file: &fs::File) -> io::Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(unix)]
pub(crate) fn private_leaf_rename(
    directory: &fs::File,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> io::Result<()> {
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(unix)]
pub(crate) fn private_leaf_unlink(directory: &fs::File, name: &std::ffi::CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(unix)]
pub(crate) fn private_leaf_exists(directory: &fs::File, name: &std::ffi::CStr) -> io::Result<bool> {
    let mut info: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut info,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Fixed production and operator-selected development hosts. The kernel
/// hostname is read into a zeroed fixed buffer; hidden bytes after a terminator
/// or an unterminated/truncated observation are never an admitted identity.
#[cfg(any(test, target_os = "openbsd"))]
fn password_native_hostname(host: &[u8; 256]) -> bool {
    host.iter().position(|v| *v == 0).is_some_and(|end| {
        matches!(
            &host[..end],
            b"mail.blackbagsecurity.com" | b"obsd1.blackbagsecurity.com"
        ) && host[end..].iter().all(|v| *v == 0)
    })
}

/// Fixed native password-service authority, without caller-selected host or
/// numeric identity. The selected development host uses the same platform,
/// root, custody and confinement checks; client qualification remains separate.
pub(crate) fn password_native_authority() -> bool {
    #[cfg(target_os = "openbsd")]
    {
        if !cfg!(target_arch = "x86_64")
            || !cfg!(target_endian = "little")
            || unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
        {
            return false;
        }
        let mut info: libc::utsname = unsafe { std::mem::zeroed() };
        let mut host = [0u8; 256];
        if unsafe { libc::uname(&mut info) } != 0
            || unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len()) } != 0
        {
            return false;
        }
        let system = unsafe { std::ffi::CStr::from_ptr(info.sysname.as_ptr()) };
        system.to_bytes() == b"OpenBSD" && password_native_hostname(&host)
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        false
    }
}

/// Installs already prepared code-owned strings/IDs. The post-fork closure
/// performs only fixed syscalls: no hashes, filesystem inspection or allocation.
#[cfg(unix)]
pub(crate) fn install_password_child_profile(
    command: &mut std::process::Command,
    plan: crate::account_password_native::PreparedChild,
) -> io::Result<()> {
    if std::time::Instant::now() >= plan.deadline()
        || plan.rules().is_empty()
        || plan.promises().to_bytes().is_empty()
        || plan.exec_promises().to_bytes().is_empty()
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    #[cfg(target_os = "openbsd")]
    {
        imp::password_child_profile(command, plan)
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = (command, plan);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Constructible only after the current process actually locks its fixed native
/// unveil table and installs its pledge promises. No caller Boolean is accepted.
pub(crate) struct PasswordParentSeal {
    pid: u32,
}
/// Separate exec domain; never accepted as the normal password-parent seal.
pub(crate) struct PasswordFstatSeal {
    pid: u32,
}
impl PasswordFstatSeal {
    pub(crate) fn is_current_process(&self) -> bool {
        password_native_authority() && self.pid == std::process::id()
    }
}
pub(crate) fn password_monotonic_ns() -> io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| io::ErrorKind::InvalidData)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| io::ErrorKind::InvalidData)?;
    if nanos >= 1_000_000_000 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}
#[cfg(any(test, target_os = "openbsd"))]
fn password_fstat_descriptor_closure(result: i32, error: io::Error) -> io::Result<()> {
    // Fixed closefrom(3): EBADF proves that all open descriptors are below3.
    // An interrupted/other failure supplies no such absence proof.
    if result == 0 || (result == -1 && error.raw_os_error() == Some(libc::EBADF)) {
        Ok(())
    } else {
        Err(error)
    }
}
pub(crate) fn password_close_fstat_inherited_descriptors() -> io::Result<()> {
    #[cfg(target_os = "openbsd")]
    {
        if !password_native_authority() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // This fixed mode has no parent lock/key/listener descriptors. Its
        // private duplex channel is fd0, stdout/stderr are already /dev/null.
        let result = unsafe { libc::closefrom(3) };
        password_fstat_descriptor_closure(result, io::Error::last_os_error())
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}
pub(crate) fn seal_password_fstat_worker(
    plan: &crate::account_password_native::FstatWorkerPlan,
) -> io::Result<PasswordFstatSeal> {
    #[cfg(target_os = "openbsd")]
    {
        if !password_native_authority() || password_parent_is_sealed() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        std::env::set_current_dir("/")?;
        imp::password_fstat_seal(plan)?;
        Ok(PasswordFstatSeal {
            pid: std::process::id(),
        })
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = (plan.rules(), plan.promises());
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[cfg(target_os = "openbsd")]
static PASSWORD_PARENT_SEALED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "openbsd")]
pub(crate) fn password_parent_is_sealed() -> bool {
    PASSWORD_PARENT_SEALED.load(std::sync::atomic::Ordering::Acquire)
}
#[cfg(not(target_os = "openbsd"))]
pub(crate) fn password_parent_is_sealed() -> bool {
    false
}
#[cfg(all(unix, any(test, target_os = "openbsd")))]
pub(crate) fn password_process_birth(seconds: u64) -> io::Result<String> {
    let stamp: libc::time_t = seconds
        .try_into()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    // libc's localtime has the same local timezone as the pre-seal fixed PS.
    // The existing stdio promise permits its internal timezone lookup.
    if unsafe { libc::localtime_r(&stamp, &mut local) }.is_null() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut birth = [0u8; 64];
    let count = unsafe {
        libc::strftime(
            birth.as_mut_ptr().cast(),
            birth.len(),
            c"%a %b %e %T %Y".as_ptr(),
            &local,
        )
    };
    if count == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    std::str::from_utf8(&birth[..count])
        .map(str::to_owned)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

#[cfg(target_os = "openbsd")]
pub(crate) fn password_process_observation(
    args: &[String],
    deadline: std::time::Instant,
    cap: usize,
) -> io::Result<String> {
    use crate::account_password_metadata::{
        arguments, before, bounded, refused, render_row, request, row_count, ProcessRow, Request,
        BYTES, ROWS,
    };
    if !crate::openbsd::password_native_authority()
        || !crate::openbsd::password_parent_is_sealed()
        || !matches!(cap, 4096 | 16384 | BYTES)
    {
        return Err(refused());
    }
    let fail = |tag| io::Error::other(tag);
    let request = request(args).map_err(|_| fail("metadata_ps_request"))?;
    before(deadline).map_err(|_| fail("metadata_query_deadline"))?;
    if let Request::Arguments(pid) = request {
        let mut raw = vec![0u8; BYTES];
        let mut length = raw.len();
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC_ARGS,
            pid,
            libc::KERN_PROC_ARGV,
        ];
        if unsafe {
            libc::sysctl(
                mib.as_ptr(),
                mib.len() as u32,
                raw.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            return Err(fail(crate::account_password_process::metadata_errno_tag(
                "ps_argv", &error,
            )));
        }
        if length > raw.len() {
            return Err(fail("metadata_ps_argv_frame"));
        }
        return arguments(&raw[..length], raw.as_ptr() as usize, cap, deadline).map_err(|error| {
            fail(if error.kind() == io::ErrorKind::TimedOut {
                "metadata_query_deadline"
            } else {
                "metadata_ps_argv_frame"
            })
        });
    }
    let (selection, pid, count) = match request {
        Request::All => (libc::KERN_PROC_ALL, 0, ROWS),
        Request::Row(pid) => (libc::KERN_PROC_PID, pid, 1),
        Request::Arguments(_) => return Err(refused()),
    };
    let mut rows: Vec<libc::kinfo_proc> = vec![unsafe { std::mem::zeroed() }; count];
    let width = std::mem::size_of::<libc::kinfo_proc>();
    let mut length = rows.len().checked_mul(width).ok_or_else(refused)?;
    let capacity = length;
    let mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        selection,
        pid,
        width.try_into().map_err(|_| refused())?,
        count.try_into().map_err(|_| refused())?,
    ];
    if unsafe {
        libc::sysctl(
            mib.as_ptr(),
            mib.len() as u32,
            rows.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(fail(crate::account_password_process::metadata_errno_tag(
            "ps_row", &error,
        )));
    }
    before(deadline).map_err(|_| fail("metadata_query_deadline"))?;
    rows.truncate(row_count(length, capacity, width).map_err(|_| fail("metadata_ps_row_count"))?);
    rows.sort_by_key(|row| row.p_pid);
    let mut result = String::new();
    for row in rows {
        if matches!(request, Request::Row(expected) if row.p_pid != expected) {
            return Err(refused());
        }
        let command = row.p_comm.map(|byte| byte as u8);
        result.push_str(
            &render_row(
                ProcessRow {
                    pid: row.p_pid,
                    parent: row.p_ppid,
                    group: row.p__pgid,
                    uid: row.p_uid,
                    gid: row.p_gid,
                    started: row.p_ustart_sec,
                    valid: row.p_uvalid != 0,
                    command: &command,
                },
                deadline,
            )
            .map_err(|error| {
                fail(if error.kind() == io::ErrorKind::TimedOut {
                    "metadata_query_deadline"
                } else {
                    "metadata_ps_row_render"
                })
            })?,
        );
        if result.len() > cap {
            return Err(fail("metadata_query_output"));
        }
    }
    bounded(result, cap, deadline).map_err(|error| {
        fail(if error.kind() == io::ErrorKind::TimedOut {
            "metadata_query_deadline"
        } else {
            "metadata_query_output"
        })
    })
}

impl PasswordParentSeal {
    pub(crate) fn is_current_process(&self) -> bool {
        self.pid == std::process::id()
    }
}
pub(crate) fn seal_password_parent(
    plan: &crate::account_password_confinement::ParentPlan,
) -> io::Result<PasswordParentSeal> {
    if plan.rules().is_empty()
        || plan.promises().to_bytes().is_empty()
        || plan.exec_promises().to_bytes().is_empty()
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    #[cfg(target_os = "openbsd")]
    {
        if !password_native_authority() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Establish the inherited cwd before unveil hides ancestor paths.
        std::env::set_current_dir("/")?;
        imp::password_parent_seal(plan)?;
        PASSWORD_PARENT_SEALED.store(true, std::sync::atomic::Ordering::Release);
        Ok(PasswordParentSeal {
            pid: std::process::id(),
        })
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = plan;
        Err(io::ErrorKind::Unsupported.into())
    }
}

pub(crate) struct PasswordKernelPeer {
    pid: u32,
    uid: u32,
    gid: u32,
}
#[cfg(unix)]
pub(crate) fn password_device_parts(device: u64) -> (u32, u32) {
    (
        libc::major(device as libc::dev_t) as u32,
        libc::minor(device as libc::dev_t) as u32,
    )
}
impl PasswordKernelPeer {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }
}
/// Connect-time kernel credentials from the accepted native Unix socket. File
/// ownership or a PID in request bytes cannot construct this value.
#[cfg(unix)]
pub(crate) fn password_kernel_peer(stream: &UnixStream) -> io::Result<PasswordKernelPeer> {
    #[cfg(target_os = "openbsd")]
    {
        let mut value: libc::sockpeercred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::sockpeercred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut value as *mut libc::sockpeercred).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of::<libc::sockpeercred>()
            || value.pid <= 1
            || value.uid == u32::MAX
            || value.gid == u32::MAX
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(PasswordKernelPeer {
            pid: value.pid as u32,
            uid: value.uid,
            gid: value.gid,
        })
    }
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = stream;
        Err(io::ErrorKind::Unsupported.into())
    }
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
    dependency_error: Option<String>,
}

/// Admission's Rust supervisor only. The fixed worker starts without inherited
/// pledge/unveil (unset exec promises); its separate native command policy and
/// full workflow qualification remain required. Never grant the supervisor
/// recursive reads of public ancestors or epoch/private-material directories.
pub(crate) fn account_admission_parent_plan(
    socket: &Path,
    python: &Path,
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
    for path in [socket, python] {
        for ancestor in path.ancestors().skip(1) {
            // Empty ancestor permissions pin the unveiled directory inodes;
            // they do not permit ancestor lstat (measured native ENOENT).
            // Full protected ancestry is checked before this locked plan.
            add_rule(&mut rules, ancestor, "");
        }
    }
    add_rule(&mut rules, parent, "r");
    add_rule(&mut rules, socket, "rwc");
    add_rule(&mut rules, python, "rx");
    Ok(OpenbsdConfinementPlan {
        dependency_error: None,
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
    python: &Path,
) -> Result<AccountAdmissionParentSeal, String> {
    let plan = account_admission_parent_plan(socket, python)?;
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

                let dependency_error = add_doveadm_dependency_rules(&mut rules)
                    .and_then(|()| add_sendmail_dependency_rules(&mut rules))
                    .err();
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
                    dependency_error,
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
                let dependency_error = add_doveadm_dependency_rules(&mut rules).err();
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
                    dependency_error,
                    promises_before_lock: OPENBSD_HELPER_PROMISES_BEFORE_LOCK,
                    promises_after_lock: OPENBSD_HELPER_PROMISES_AFTER_LOCK,
                    unveil_rules: rules
                        .into_iter()
                        .map(|(path, permissions)| OpenbsdUnveilRule { path, permissions })
                        .collect(),
                }
            }
            crate::config::AppRunMode::Bootstrap => Self {
                dependency_error: None,
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

// The original private error remains available only to the existing String
// wrapper. Debug and the native fixture export only source-owned categories.
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(any(target_os = "openbsd", test)), allow(dead_code))]
enum ConfinementStage {
    DependencyPlan,
    PurposeSeparation,
    AdmissionPreflight,
    MutationPreflight,
    InitialPledge,
    UnveilRule,
    UnveilLock,
    FinalPledge,
    UnsupportedPlatform,
}
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(any(target_os = "openbsd", test)), allow(dead_code))]
enum ConfinementReason {
    BoundaryRefused,
    InvalidArgument,
    SyscallFailed,
}
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(any(target_os = "openbsd", test)), allow(dead_code))]
enum ConfinementSyscall {
    Pledge,
    Unveil,
}
#[derive(Debug, serde::Serialize)]
struct ConfinementDiagnostic {
    schema: &'static str,
    stage: ConfinementStage,
    reason: ConfinementReason,
    syscall: Option<ConfinementSyscall>,
    errno: Option<i32>,
    rule_ordinal: Option<u32>,
}
pub(crate) struct ConfinementFailure {
    diagnostic: ConfinementDiagnostic,
    original: String,
}
impl std::fmt::Debug for ConfinementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}
impl ConfinementFailure {
    fn boundary(stage: ConfinementStage, original: String) -> Self {
        Self {
            diagnostic: ConfinementDiagnostic {
                schema: "osmap-serve-confinement-v1",
                stage,
                reason: ConfinementReason::BoundaryRefused,
                syscall: None,
                errno: None,
                rule_ordinal: None,
            },
            original,
        }
    }
    fn into_original(self) -> String {
        self.original
    }
    #[cfg(any(target_os = "openbsd", test))]
    fn invalid(stage: ConfinementStage, ordinal: Option<u32>, original: String) -> Self {
        let mut failure = Self::boundary(stage, original);
        failure.diagnostic.reason = ConfinementReason::InvalidArgument;
        failure.diagnostic.rule_ordinal = ordinal;
        failure
    }
    #[cfg(any(target_os = "openbsd", test))]
    fn syscall(
        stage: ConfinementStage,
        syscall: ConfinementSyscall,
        ordinal: Option<u32>,
        error: &io::Error,
        original: String,
    ) -> Self {
        let mut failure = Self::boundary(stage, original);
        failure.diagnostic.reason = ConfinementReason::SyscallFailed;
        failure.diagnostic.syscall = Some(syscall);
        // Preserve only an actual bounded errno; absent/out-of-range values
        // remain unknown and must never be reconstructed from error text.
        failure.diagnostic.errno = error.raw_os_error().filter(|n| (1..=4095).contains(n));
        failure.diagnostic.rule_ordinal = ordinal;
        failure
    }
    #[cfg(test)]
    fn diagnostic_line(&self) -> String {
        format!(
            "OSMAP_SERVE_CONFINEMENT_V1 {}\n",
            serde_json::to_string(&self.diagnostic).expect("fixed confinement schema")
        )
    }
    #[cfg(test)]
    pub(crate) fn emit_native_fixture_diagnostic(&self) {
        use std::io::Write as _;
        // Best effort only: a broken diagnostic stream cannot replace the
        // original confinement refusal or make the fixture continue.
        let _ = std::io::stderr()
            .lock()
            .write_all(self.diagnostic_line().as_bytes());
    }
}

fn check_account_preflight(
    separated: bool,
    admission: impl FnOnce() -> Result<(), ()>,
    mutation: impl FnOnce() -> Result<(), ()>,
) -> Result<(), ConfinementFailure> {
    let refused =
        |stage| ConfinementFailure::boundary(stage, "account Serve custody unavailable".into());
    if !separated {
        return Err(refused(ConfinementStage::PurposeSeparation));
    }
    admission().map_err(|()| refused(ConfinementStage::AdmissionPreflight))?;
    mutation().map_err(|()| refused(ConfinementStage::MutationPreflight))?;
    Ok(())
}

fn preflight_concrete_account_clients(
    account: &crate::config::AccountRuntimeConfig,
    admission: &crate::account_admission_runtime::Client,
    mutation: &crate::account_mutation_client::Client,
) -> Result<(), ConfinementFailure> {
    check_account_preflight(
        mutation.purpose_separated_from(admission),
        || admission.preflight_serve(account).map_err(|_| ()),
        || mutation.preflight_serve(account).map_err(|_| ()),
    )
}

pub(crate) fn apply_runtime_confinement_for_accounts(
    config: &AppConfig,
    logger: &Logger,
    clients: Option<(
        &crate::account_admission_runtime::Client,
        &crate::account_mutation_client::Client,
    )>,
) -> Result<Option<std::sync::Arc<ServeAccountSeal>>, String> {
    apply_runtime_confinement_for_accounts_detailed(config, logger, clients)
        .map_err(ConfinementFailure::into_original)
}

pub(crate) fn apply_runtime_confinement_for_accounts_detailed(
    config: &AppConfig,
    logger: &Logger,
    clients: Option<(
        &crate::account_admission_runtime::Client,
        &crate::account_mutation_client::Client,
    )>,
) -> Result<Option<std::sync::Arc<ServeAccountSeal>>, ConfinementFailure> {
    match config.openbsd_confinement_mode {
        OpenbsdConfinementMode::Disabled => Ok(None),
        OpenbsdConfinementMode::LogOnly => {
            let plan = OpenbsdConfinementPlan::from_config(config);
            logger.emit(&build_plan_event(config, &plan, "plan_logged"));
            Ok(None)
        }
        OpenbsdConfinementMode::Enforce => {
            let plan = OpenbsdConfinementPlan::from_config(config);
            if let Some(error) = &plan.dependency_error {
                return Err(ConfinementFailure::boundary(
                    ConfinementStage::DependencyPlan,
                    error.clone(),
                ));
            }
            logger.emit(&build_plan_event(config, &plan, "plan_enforcing"));
            // Concrete paired preflight immediately precedes actual apply.
            // A constructor-time snapshot alone cannot authorize the seal.
            let prepared_account = if config.run_mode == crate::config::AppRunMode::Serve {
                match (config.account_runtime.as_ref(), clients) {
                    (Some(account), Some((admission, mutation))) => {
                        preflight_concrete_account_clients(account, admission, mutation)?;
                        Some(account.clone())
                    }
                    _ => None,
                }
            } else {
                None
            };

            #[cfg(target_os = "openbsd")]
            {
                imp::apply_plan_detailed(&plan)?;
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
                Err(ConfinementFailure::boundary(
                    ConfinementStage::UnsupportedPlatform,
                    "OpenBSD confinement enforcement was requested on a non-OpenBSD platform"
                        .to_string(),
                ))
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
#[allow(dead_code)] // Retained historical HTTP pilot role/profile.
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

/// Exact executable and loader-selected library grants. Resolution failure
/// prevents confinement activation; it never expands a library-directory grant.
fn add_doveadm_dependency_rules(rules: &mut BTreeMap<PathBuf, String>) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    add_rule(rules, Path::new("/usr/local/bin/doveadm"), "x");
    add_rule(rules, Path::new("/usr/local/bin/doveconf"), "x");
    add_installed_dependency_rules(rules, Path::new("/usr/local/bin/doveadm"), deadline)?;
    add_installed_dependency_rules(rules, Path::new("/usr/local/bin/doveconf"), deadline)?;
    // Dovecot enumerates these fixed protected module directories at runtime.
    // Keep that required read grant, without the old /usr/local/lib fallback.
    for dir in ["/usr/local/lib/dovecot", "/usr/local/lib/dovecot/doveadm"] {
        trusted_dependency_directory(Path::new(dir))?;
        add_rule(rules, Path::new(dir), "r");
        for (count, entry) in fs::read_dir(dir)
            .map_err(|_| "Dovecot modules unavailable")?
            .enumerate()
        {
            if count >= 256 {
                return Err("Dovecot module inventory limit".into());
            }
            let path = entry.map_err(|_| "Dovecot modules unavailable")?.path();
            if dependency_program_allowed(&path) {
                add_rule(rules, &path, "r");
                add_installed_dependency_rules(rules, &path, deadline)?;
            }
        }
    }
    add_if_exists(rules, Path::new("/etc/dovecot/dovecot.conf"), "r");
    add_if_exists(rules, Path::new("/etc/dovecot/conf.d"), "r");
    add_if_exists(rules, Path::new("/etc/dovecot/local.conf"), "r");
    add_if_exists(rules, Path::new("/var/dovecot/config"), "rw");
    Ok(())
}

fn add_sendmail_dependency_rules(rules: &mut BTreeMap<PathBuf, String>) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    for program in [
        "/usr/sbin/sendmail",
        "/usr/local/sbin/sendmail",
        "/usr/local/sbin/postdrop",
    ] {
        add_rule(rules, Path::new(program), "x");
        add_installed_dependency_rules(rules, Path::new(program), deadline)?;
    }
    for path in [
        "/etc/mailer.conf",
        "/etc/postfix/main.cf",
        "/etc/localtime",
        "/usr/share/zoneinfo/posixrules",
        "/etc/pwd.db",
        "/etc/group",
        "/dev/urandom",
    ] {
        add_if_exists(rules, Path::new(path), "r");
    }
    add_if_exists(rules, Path::new("/var/spool/postfix"), "rwc");
    Ok(())
}

fn add_installed_dependency_rules(
    rules: &mut BTreeMap<PathBuf, String>,
    program: &Path,
    deadline: std::time::Instant,
) -> Result<(), String> {
    let libraries = installed_library_paths_before(program, deadline)?;
    if program == Path::new("/usr/sbin/sendmail") {
        add_rule(rules, Path::new("/usr/sbin/mailwrapper"), "x");
    }
    for path in libraries {
        add_rule(rules, &path, "r");
    }
    for path in ["/usr/libexec/ld.so", "/var/run/ld.so.hints"] {
        trusted_dependency_file(Path::new(path))?;
        add_rule(rules, Path::new(path), "r");
    }
    Ok(())
}

/// The caller cannot turn dependency discovery into arbitrary program execution.
pub(crate) fn dependency_program_allowed(program: &Path) -> bool {
    matches!(
        program.to_str(),
        Some(
            "/usr/bin/fstat"
                | "/usr/local/bin/doveadm"
                | "/usr/local/bin/doveconf"
                | "/usr/local/bin/mariadb"
                | "/usr/sbin/sendmail"
                | "/usr/sbin/mailwrapper"
                | "/usr/local/sbin/sendmail"
                | "/usr/local/sbin/postdrop"
        )
    ) || (matches!(
        program.parent().and_then(Path::to_str),
        Some("/usr/local/lib/dovecot" | "/usr/local/lib/dovecot/doveadm")
    ) && program
        .file_name()
        .and_then(|p| p.to_str())
        .is_some_and(|name| {
            (name.ends_with(".so")
                || name.rsplit_once(".so.").is_some_and(|(_, suffix)| {
                    !suffix.is_empty()
                        && suffix.split('.').all(|part| {
                            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
                        })
                }))
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        }))
}

fn dependency_library_allowed(path: &Path) -> bool {
    path == Path::new("/usr/libexec/ld.so")
        || (matches!(
            path.parent().and_then(Path::to_str),
            Some(
                "/usr/lib"
                    | "/usr/local/lib"
                    | "/usr/local/lib/dovecot"
                    | "/usr/local/lib/dovecot/doveadm"
            )
        ) && path
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|name| {
                name.starts_with("lib")
                    && name.contains(".so")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
            }))
}

#[cfg(unix)]
fn trusted_dependency_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor).map_err(|_| "dependency ancestry unavailable")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("dependency ancestry is not protected".into());
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn trusted_dependency_directory(_: &Path) -> Result<(), String> {
    Err("native dependencies unavailable".into())
}

#[cfg(unix)]
fn trusted_dependency_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    trusted_dependency_directory(path.parent().ok_or("dependency parent unavailable")?)?;
    let m = fs::symlink_metadata(path).map_err(|_| "dependency file unavailable")?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > 128 * 1024 * 1024 {
        return Err("dependency file is not protected".into());
    }
    Ok(())
}
#[cfg(not(unix))]
fn trusted_dependency_file(_: &Path) -> Result<(), String> {
    Err("native dependencies unavailable".into())
}

/// sendmail is the system mailwrapper alias on OpenBSD. No other program
/// symlink is admitted, and its one supported target is checked independently.
#[cfg(unix)]
fn trusted_dependency_program(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if path == Path::new("/usr/sbin/sendmail") {
        trusted_dependency_directory(Path::new("/usr/sbin"))?;
        let metadata = fs::symlink_metadata(path).map_err(|_| "mailwrapper alias unavailable")?;
        if metadata.file_type().is_symlink() {
            if metadata.uid() != 0
                || !matches!(fs::read_link(path).ok().as_deref(),
                Some(p) if p == Path::new("mailwrapper") || p == Path::new("/usr/sbin/mailwrapper"))
            {
                return Err("mailwrapper alias target refused".into());
            }
            return trusted_dependency_program(Path::new("/usr/sbin/mailwrapper"));
        }
    }
    trusted_dependency_file(path)?;
    let metadata = fs::metadata(path).map_err(|_| "dependency program unavailable")?;
    if metadata.mode() & 0o004 == 0 {
        return Err("dependency program must be readable for loader tracing".into());
    }
    Ok(())
}

/// Parse OpenBSD ld.so trace rows, rejecting unknown rows and unresolved names.
/// The actual loader chooses versions: no lexical prefix or directory fallback.
fn parse_installed_libraries(output: &str, program: &Path) -> Result<Vec<PathBuf>, String> {
    let mut libraries = std::collections::BTreeSet::new();
    let mut header = false;
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line == format!("{}:", program.display())
            || (program == Path::new("/usr/sbin/sendmail") && line == "/usr/sbin/mailwrapper:")
            || (program.starts_with("/usr/local/lib/dovecot") && line == "/usr/bin/ldd:")
        {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields == ["Start", "End", "Type", "Open", "Ref", "GrpRef", "Name"] {
            if header {
                return Err("duplicate dependency header".into());
            }
            header = true;
            continue;
        }
        if !header
            || fields.len() != 7
            || !fields[..2]
                .iter()
                .all(|v| v.bytes().all(|b| b.is_ascii_hexdigit()))
            || !fields[3..6].iter().all(|v| v.parse::<u64>().is_ok())
        {
            return Err("unsupported dependency trace".into());
        }
        let path = Path::new(fields[6]);
        match fields[2] {
            "exe"
                if path == program
                    || (program == Path::new("/usr/sbin/sendmail")
                        && path == Path::new("/usr/sbin/mailwrapper")) => {}
            "rlib" | "dlib" | "ld.so" if dependency_library_allowed(path) => {
                libraries.insert(path.to_path_buf());
            }
            _ => return Err("untrusted or unresolved dependency".into()),
        }
    }
    if !header || libraries.is_empty() {
        return Err("dependency trace is empty".into());
    }
    Ok(libraries.into_iter().collect())
}

#[cfg(unix)]
fn dependency_identity(path: &Path) -> Result<[u64; 10], String> {
    let m = fs::symlink_metadata(path).map_err(|_| "dependency identity unavailable")?;
    Ok(dependency_metadata_identity(&m))
}

#[cfg(unix)]
fn dependency_metadata_identity(m: &fs::Metadata) -> [u64; 10] {
    use std::os::unix::fs::MetadataExt;
    [
        m.dev(),
        m.ino(),
        m.mode() as u64,
        m.uid() as u64,
        m.gid() as u64,
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]
}

fn native_elf_machine() -> Option<u64> {
    match std::env::consts::ARCH {
        "x86" => Some(3),
        "x86_64" => Some(62),
        "arm" => Some(40),
        "aarch64" => Some(183),
        "mips" | "mips64" => Some(8),
        "powerpc" => Some(20),
        "powerpc64" => Some(21),
        "riscv64" => Some(243),
        "sparc64" => Some(43),
        _ => None,
    }
}

/// Inspect only the bounded ELF prefix needed to prove that the fixed trace
/// variable reaches the native loader. No script/static/alternate interpreter
/// may enter the direct postdrop trace route.
fn postdrop_trace_elf_prefix(bytes: &[u8]) -> bool {
    (|| -> Option<()> {
        let class = if cfg!(target_pointer_width = "64") {
            2
        } else {
            1
        };
        let endian = if cfg!(target_endian = "little") { 1 } else { 2 };
        if bytes.get(..4)? != b"\x7fELF"
            || *bytes.get(4)? != class
            || *bytes.get(5)? != endian
            || *bytes.get(6)? != 1
            || bytes.len() > 65536
        {
            return None;
        }
        let read = |offset: usize, width: usize| -> Option<u64> {
            let mut value = 0;
            for (index, byte) in bytes
                .get(offset..offset.checked_add(width)?)?
                .iter()
                .enumerate()
            {
                let shift = if endian == 1 {
                    index
                } else {
                    width - index - 1
                };
                value |= u64::from(*byte) << (shift * 8);
            }
            Some(value)
        };
        let (ehsize, phsize, phoff_at, size_at, offset_at, filesz_at, flags_at) = if class == 2 {
            (64, 56, 32, 52, 8, 32, 4)
        } else {
            (52, 32, 28, 40, 4, 16, 24)
        };
        if !matches!(read(16, 2)?, 2 | 3)
            || read(18, 2)? != native_elf_machine()?
            || read(20, 4)? != 1
            || read(size_at, 2)? != ehsize as u64
            || read(size_at + 2, 2)? != phsize as u64
        {
            return None;
        }
        let offset_width = if class == 2 { 8 } else { 4 };
        let phoff = usize::try_from(read(phoff_at, offset_width)?).ok()?;
        let phnum = usize::try_from(read(size_at + 4, 2)?).ok()?;
        if phoff < ehsize || phnum == 0 || phnum == 0xffff {
            return None;
        }
        bytes.get(phoff..phoff.checked_add(phnum.checked_mul(phsize)?)?)?;
        let mut interpreter = 0;
        let mut dynamic = 0;
        let mut executable_load = false;
        for index in 0..phnum {
            let at = phoff + index * phsize;
            match read(at, 4)? {
                1 => executable_load |= read(at + flags_at, 4)? & 1 != 0,
                2 => dynamic += 1,
                3 => {
                    interpreter += 1;
                    let start = usize::try_from(read(at + offset_at, offset_width)?).ok()?;
                    let size = usize::try_from(read(at + filesz_at, offset_width)?).ok()?;
                    if bytes.get(start..start.checked_add(size)?)? != b"/usr/libexec/ld.so\0" {
                        return None;
                    }
                }
                _ => {}
            }
        }
        (interpreter == 1 && dynamic == 1 && executable_load).then_some(())
    })()
    .is_some()
}

#[cfg(unix)]
pub(crate) fn validate_postdrop_trace_program() -> io::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if !cfg!(target_os = "openbsd") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "postdrop loader trace requires OpenBSD",
        ));
    }
    let check = || -> Result<(), String> {
        let path = Path::new("/usr/local/sbin/postdrop");
        trusted_dependency_program(path)?;
        let before = dependency_identity(path)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "postdrop trace object unavailable")?;
        if dependency_metadata_identity(
            &file
                .metadata()
                .map_err(|_| "postdrop trace object unavailable")?,
        ) != before
        {
            return Err("postdrop trace object changed".into());
        }
        let mut prefix = Vec::new();
        file.take(65536)
            .read_to_end(&mut prefix)
            .map_err(|_| "postdrop trace header unavailable")?;
        if !postdrop_trace_elf_prefix(&prefix) {
            return Err("postdrop trace interpreter refused".into());
        }
        trusted_dependency_program(path)?;
        if dependency_identity(path)? != before {
            return Err("postdrop trace object changed".into());
        }
        Ok(())
    };
    check().map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))
}

/// The installed MariaDB package exposes its library through one relative
/// SONAME alias. Admit that layout without admitting other library symlinks,
/// arbitrary mysql paths in loader output, or symlinked programs.
fn dependency_library_alias_target(alias: &Path, link: &Path) -> Result<PathBuf, String> {
    let name = alias
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("dependency library alias refused")?;
    let version = name
        .strip_prefix("libmariadb.so.")
        .ok_or("dependency library alias refused")?;
    if alias.parent() != Some(Path::new("/usr/local/lib"))
        || version.is_empty()
        || !version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        || link.as_os_str() != Path::new("mysql").join(name).as_os_str()
    {
        return Err("dependency library alias refused".into());
    }
    Ok(Path::new("/usr/local/lib/mysql").join(name))
}

#[cfg(unix)]
struct DependencyLibraryCustody {
    selected: PathBuf,
    link: Option<PathBuf>,
    identities: Vec<(PathBuf, [u64; 10])>,
}

#[cfg(unix)]
impl DependencyLibraryCustody {
    fn new(selected: &Path) -> Result<Self, String> {
        let identity = dependency_identity(selected)?;
        let mut value = Self {
            selected: selected.to_path_buf(),
            link: None,
            identities: vec![(selected.to_path_buf(), identity)],
        };
        if identity[2] & 0o170000 == 0o120000 {
            // Symlink mode bits do not protect its contents. The owner and
            // parent protect the link; the regular target has the usual guard.
            trusted_dependency_directory(
                selected.parent().ok_or("dependency parent unavailable")?,
            )?;
            if identity[3] != 0 {
                return Err("dependency library alias owner refused".into());
            }
            let link =
                fs::read_link(selected).map_err(|_| "dependency library alias unavailable")?;
            let target = dependency_library_alias_target(selected, &link)?;
            let target_identity = dependency_identity(&target)?;
            value.identities.push((target, target_identity));
            value.link = Some(link);
        }
        value.recheck()?;
        Ok(value)
    }

    fn recheck(&self) -> Result<(), String> {
        // Check both the alias and object before and after their guards. A
        // changed target never becomes a new accepted baseline during admission.
        for (path, before) in &self.identities {
            if dependency_identity(path)? != *before {
                return Err("dependency library changed during resolution".into());
            }
        }
        if let Some(link) = &self.link {
            trusted_dependency_directory(
                self.selected
                    .parent()
                    .ok_or("dependency parent unavailable")?,
            )?;
            if fs::read_link(&self.selected).map_err(|_| "dependency library alias unavailable")?
                != *link
            {
                return Err("dependency library changed during resolution".into());
            }
        }
        for (path, _) in &self.identities {
            if self.link.is_none() || path != &self.selected {
                trusted_dependency_file(path)?;
            }
        }
        for (path, before) in &self.identities {
            if dependency_identity(path)? != *before {
                return Err("dependency library changed during resolution".into());
            }
        }
        if let Some(link) = &self.link {
            if fs::read_link(&self.selected).map_err(|_| "dependency library alias unavailable")?
                != *link
            {
                return Err("dependency library changed during resolution".into());
            }
        }
        Ok(())
    }
}

/// Resolve only protected installed programs before confinement. The result is
/// fresh for this admission; callers hold/recheck their existing operation pins.
#[cfg(unix)]
pub(crate) fn installed_library_paths_before(
    program: &Path,
    deadline: std::time::Instant,
) -> Result<Vec<PathBuf>, String> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    if Instant::now() >= deadline {
        return Err("dependency resolution deadline".into());
    }
    if !dependency_program_allowed(program) {
        return Err("dependency program refused".into());
    }
    trusted_dependency_program(program)?;
    trusted_dependency_file(Path::new("/usr/bin/ldd"))?;
    for path in ["/usr/libexec/ld.so", "/var/run/ld.so.hints"] {
        trusted_dependency_file(Path::new(path))?;
    }
    let mut custody_paths = vec![
        program,
        Path::new("/usr/bin/ldd"),
        Path::new("/usr/libexec/ld.so"),
        Path::new("/var/run/ld.so.hints"),
    ];
    if program == Path::new("/usr/sbin/sendmail")
        && fs::symlink_metadata(program)
            .map_err(|_| "mailwrapper alias unavailable")?
            .file_type()
            .is_symlink()
    {
        custody_paths.push(Path::new("/usr/sbin/mailwrapper"));
    }
    let before = custody_paths
        .iter()
        .map(|p| dependency_identity(p))
        .collect::<Result<Vec<_>, _>>()?;
    let mut command = crate::auth::installed_dependencies_command(program).map_err(|error| {
        if program == Path::new("/usr/local/sbin/postdrop") {
            // The preparation guard emits only fixed source-owned reasons.
            format!("postdrop trace preparation refused: {error}")
        } else {
            "dependency command refused".into()
        }
    })?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| "dependency resolver unavailable")?;
    let mut status = None;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or("dependency stdout unavailable")?;
        let mut stderr = child.stderr.take().ok_or("dependency stderr unavailable")?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err("dependency pipe unavailable".into());
            }
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_eof = false;
        let mut err_eof = false;
        loop {
            for (reader, data, eof) in [
                (&mut stdout as &mut dyn Read, &mut out, &mut out_eof),
                (&mut stderr as &mut dyn Read, &mut err, &mut err_eof),
            ] {
                let mut buffer = [0u8; 4096];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) => {
                            *eof = true;
                            break;
                        }
                        Ok(count) => {
                            data.extend_from_slice(&buffer[..count]);
                            if data.len() > 65536 {
                                return Err("dependency output limit".into());
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => return Err("dependency output unavailable".into()),
                    }
                }
            }
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| "dependency wait unavailable")?;
            }
            if let Some(exit) = status {
                if out_eof && err_eof {
                    if !exit.success() || !err.is_empty() {
                        return Err("dependency resolution failed".into());
                    }
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("dependency resolution deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = std::str::from_utf8(&out).map_err(|_| "dependency output encoding")?;
        let libraries = parse_installed_libraries(output, program)?;
        let library_custody = libraries
            .iter()
            .map(|library| DependencyLibraryCustody::new(library))
            .collect::<Result<Vec<_>, _>>()?;
        trusted_dependency_program(program)?;
        let after = custody_paths
            .iter()
            .map(|p| dependency_identity(p))
            .collect::<Result<Vec<_>, _>>()?;
        if before != after {
            return Err("dependency changed during resolution".into());
        }
        let mut paths = std::collections::BTreeSet::new();
        for library in &library_custody {
            library.recheck()?;
            paths.extend(library.identities.iter().map(|(path, _)| path.clone()));
        }
        Ok(paths.into_iter().collect())
    })();
    if result.is_err() && status.is_none() {
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.wait();
    }
    result
}
#[cfg(not(unix))]
pub(crate) fn installed_library_paths_before(
    _: &Path,
    _: std::time::Instant,
) -> Result<Vec<PathBuf>, String> {
    Err("native dependencies unavailable".into())
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
    .with_field(
        "dependency_admission",
        plan.dependency_error.as_deref().unwrap_or("ready"),
    )
    .with_field("unveiled_paths", unveiled_paths)
}

// One private sequence is used by the native adapter and injected unit tests.
// No runtime flag, test adapter, or caller capability can bypass native sealing.
#[cfg(any(target_os = "openbsd", test))]
trait ConfinementSyscalls {
    fn pledge(&mut self, promises: &std::ffi::CStr) -> io::Result<()>;
    fn unveil(&mut self, rule: Option<(&std::ffi::CStr, &std::ffi::CStr)>) -> io::Result<()>;
}
#[cfg(any(target_os = "openbsd", test))]
fn apply_plan_with_syscalls(
    plan: &OpenbsdConfinementPlan,
    syscalls: &mut impl ConfinementSyscalls,
) -> Result<(), ConfinementFailure> {
    use std::ffi::CString;
    if let Some(error) = &plan.dependency_error {
        return Err(ConfinementFailure::boundary(
            ConfinementStage::DependencyPlan,
            error.clone(),
        ));
    }
    let pledge = |syscalls: &mut _, promises: &str, stage| {
        let promises = CString::new(promises).map_err(|_| {
            ConfinementFailure::invalid(
                stage,
                None,
                "pledge promise string contained interior NUL".into(),
            )
        })?;
        ConfinementSyscalls::pledge(syscalls, &promises).map_err(|error| {
            ConfinementFailure::syscall(
                stage,
                ConfinementSyscall::Pledge,
                None,
                &error,
                format!("pledge failed: {}", error),
            )
        })
    };
    pledge(
        syscalls,
        plan.promises_before_lock,
        ConfinementStage::InitialPledge,
    )?;
    for (index, rule) in plan.unveil_rules.iter().enumerate() {
        // This source-owned plan is far smaller than u32::MAX. Refuse before
        // the rule if its ordinal cannot be represented; never wrap identity.
        let ordinal = u32::try_from(index + 1).map_err(|_| {
            ConfinementFailure::boundary(
                ConfinementStage::DependencyPlan,
                "unveil rule count exceeds diagnostic bound".into(),
            )
        })?;
        let path = CString::new(rule.path.as_os_str().as_encoded_bytes()).map_err(|_| {
            ConfinementFailure::invalid(
                ConfinementStage::UnveilRule,
                Some(ordinal),
                format!("unveil path {:?} contained interior NUL", rule.path),
            )
        })?;
        let permissions = CString::new(rule.permissions.as_str()).map_err(|_| {
            ConfinementFailure::invalid(
                ConfinementStage::UnveilRule,
                Some(ordinal),
                "unveil permission string contained interior NUL".into(),
            )
        })?;
        syscalls
            .unveil(Some((&path, &permissions)))
            .map_err(|error| {
                ConfinementFailure::syscall(
                    ConfinementStage::UnveilRule,
                    ConfinementSyscall::Unveil,
                    Some(ordinal),
                    &error,
                    format!(
                        "unveil failed for {} with permissions {}: {}",
                        rule.path.display(),
                        rule.permissions,
                        error
                    ),
                )
            })?;
    }
    syscalls.unveil(None).map_err(|error| {
        ConfinementFailure::syscall(
            ConfinementStage::UnveilLock,
            ConfinementSyscall::Unveil,
            None,
            &error,
            format!("unveil lock failed: {}", error),
        )
    })?;
    pledge(
        syscalls,
        plan.promises_after_lock,
        ConfinementStage::FinalPledge,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "openbsd/confinement_tests.rs"]
mod confinement_tests;

#[cfg(target_os = "openbsd")]
mod imp {
    use std::io;
    use std::os::raw::{c_char, c_int};

    use super::OpenbsdConfinementPlan;

    unsafe extern "C" {
        fn pledge(promises: *const c_char, execpromises: *const c_char) -> c_int;
        fn unveil(path: *const c_char, permissions: *const c_char) -> c_int;
    }

    pub(super) fn password_parent_seal(
        plan: &crate::account_password_confinement::ParentPlan,
    ) -> io::Result<()> {
        for (path, access) in plan.rules() {
            if unsafe { unveil(path.as_ptr(), access.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { unveil(std::ptr::null(), std::ptr::null()) } != 0
            || unsafe { pledge(plan.promises().as_ptr(), plan.exec_promises().as_ptr()) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub(super) fn password_fstat_seal(
        plan: &crate::account_password_native::FstatWorkerPlan,
    ) -> io::Result<()> {
        for (path, access) in plan.rules() {
            if unsafe { unveil(path.as_ptr(), access.as_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { unveil(std::ptr::null(), std::ptr::null()) } != 0
            || unsafe { pledge(plan.promises().as_ptr(), std::ptr::null()) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn password_child_profile(
        command: &mut std::process::Command,
        plan: crate::account_password_native::PreparedChild,
    ) -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        if !super::password_native_authority()
            || !super::PASSWORD_PARENT_SEALED.load(std::sync::atomic::Ordering::Acquire)
            || std::time::Instant::now() >= plan.deadline()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // SAFETY: all captured C strings and IDs were prepared/validated by the
        // code-owned native profile. Only async-signal-safe fixed syscalls run.
        unsafe {
            command.pre_exec(move || {
                if std::time::Instant::now() >= plan.deadline() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                let (uid, gid) = plan.ids();
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                let (mut ruid, mut euid, mut suid, mut rgid, mut egid, mut sgid) =
                    (0, 0, 0, 0, 0, 0);
                if libc::getresuid(&mut ruid, &mut euid, &mut suid) != 0
                    || libc::getresgid(&mut rgid, &mut egid, &mut sgid) != 0
                    || (ruid, euid, suid) != (uid, uid, uid)
                    || (rgid, egid, sgid) != (gid, gid, gid)
                    || libc::getgroups(0, std::ptr::null_mut()) != 0
                {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                // fork inherits the parent's already locked closed filesystem view.
                // Re-unveiling would fail EPERM. Role-specific UID/GID/DAC and
                // narrower pledge/execpromises reduce that inherited authority.
                if pledge(plan.promises().as_ptr(), plan.exec_promises().as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if std::time::Instant::now() >= plan.deadline() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                Ok(())
            });
        }
        Ok(())
    }

    /// Production adapter captures errno immediately after the failing call.
    struct NativeSyscalls;
    impl super::ConfinementSyscalls for NativeSyscalls {
        fn pledge(&mut self, promises: &std::ffi::CStr) -> io::Result<()> {
            if unsafe { pledge(promises.as_ptr(), std::ptr::null()) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        fn unveil(&mut self, rule: Option<(&std::ffi::CStr, &std::ffi::CStr)>) -> io::Result<()> {
            let (path, permissions) = rule
                .map_or((std::ptr::null(), std::ptr::null()), |(p, a)| {
                    (p.as_ptr(), a.as_ptr())
                });
            if unsafe { unveil(path, permissions) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    pub fn apply_plan(plan: &OpenbsdConfinementPlan) -> Result<(), String> {
        apply_plan_detailed(plan).map_err(super::ConfinementFailure::into_original)
    }
    pub(super) fn apply_plan_detailed(
        plan: &OpenbsdConfinementPlan,
    ) -> Result<(), super::ConfinementFailure> {
        super::apply_plan_with_syscalls(plan, &mut NativeSyscalls)
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
pub(crate) use tests::publish_rights;

#[cfg(all(test, unix))]
fn fixture_current_rust_http_groups_exact() -> bool {
    let mut groups = [0 as libc::gid_t; 3];
    // Fixed observed obsd1 profile, never caller-selected supplementary groups.
    if unsafe { libc::getgroups(3, groups.as_mut_ptr()) } != 3 {
        return false;
    }
    groups.sort_unstable();
    groups == [1001, 1002, 1003]
}

#[cfg(all(test, unix))]
pub(crate) fn fixture_current_rust_http_pilot_root_control_identity(
    stream: &UnixStream,
) -> Result<(libc::dev_t, libc::ino_t, libc::mode_t), String> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: native credential queries write only to these local scalars.
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
        || (real_uid, effective_uid, saved_uid) != (1001, 1001, 1001)
        || (real_gid, effective_gid, saved_gid) != (1001, 1001, 1001)
        || !fixture_current_rust_http_groups_exact()
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

#[cfg(all(test, unix))]
pub(crate) fn fixture_current_rust_owned_http_pilot_control(
    raw: i32,
) -> Result<UnixStream, String> {
    let stream = fixture_owned_unix_stream(raw)?;
    fixture_current_rust_http_pilot_root_control_identity(&stream)?;
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

#[cfg(test)]
mod tests {
    #[test]
    fn password_native_hostname_accepts_only_exact_production_and_selected_development() {
        let buffer = |name: &[u8]| {
            let mut host = [0_u8; 256];
            host[..name.len()].copy_from_slice(name);
            host
        };
        for name in [
            b"mail.blackbagsecurity.com".as_slice(),
            b"obsd1.blackbagsecurity.com".as_slice(),
        ] {
            assert!(super::password_native_hostname(&buffer(name)));
        }
        for name in [
            b"".as_slice(),
            b"mail",
            b"obsd1",
            b"Mail.blackbagsecurity.com",
            b"Obsd1.blackbagsecurity.com",
            b"mail.blackbagsecurity.com.attacker.invalid",
            b"obsd1.blackbagsecurity.com.attacker.invalid",
            b"xmail.blackbagsecurity.com",
            b"xobsd1.blackbagsecurity.com",
            b"mail.blackbagsecurity.com.",
            b"obsd1.blackbagsecurity.com.",
            b"mail.blackbagsecurity.com\0hidden",
            b"obsd1.blackbagsecurity.com\0hidden",
            b"obsd1.blackbagsecurity.co",
        ] {
            assert!(!super::password_native_hostname(&buffer(name)));
        }
        let mut unterminated = [b'x'; 256];
        let name = b"obsd1.blackbagsecurity.com";
        unterminated[..name.len()].copy_from_slice(name);
        assert!(!super::password_native_hostname(&unterminated));
    }

    #[test]
    fn fixed_fstat_closefrom_accepts_only_success_or_already_empty() {
        assert!(super::password_fstat_descriptor_closure(
            0,
            std::io::Error::from_raw_os_error(libc::EINTR)
        )
        .is_ok());
        assert!(super::password_fstat_descriptor_closure(
            -1,
            std::io::Error::from_raw_os_error(libc::EBADF)
        )
        .is_ok());
        for errno in [libc::EINTR, libc::EPERM, libc::EBUSY] {
            assert_eq!(
                super::password_fstat_descriptor_closure(
                    -1,
                    std::io::Error::from_raw_os_error(errno)
                )
                .unwrap_err()
                .raw_os_error(),
                Some(errno)
            );
        }
        assert!(super::password_fstat_descriptor_closure(
            1,
            std::io::Error::from_raw_os_error(libc::EBADF)
        )
        .is_err());
    }
    // Send rights attached to the first byte, matching the fixed C publication
    // contract. No mail data is read or retained by the ancillary transport.
    pub(crate) fn publish_rights(
        stream: &mut std::os::unix::net::UnixStream,
        bytes: &[u8],
        fds: &[&std::os::unix::net::UnixStream],
    ) {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let raw = fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<_>>();
        assert!((1..=2).contains(&raw.len()));
        let length = raw.len() * std::mem::size_of::<libc::c_int>();
        let mut byte = [bytes[0]];
        let mut control: [libc::cmsghdr; 4] = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(length as _) } as _;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(length as _) as _;
            for (index, fd) in raw.into_iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                    fd,
                );
            }
            assert_eq!(libc::sendmsg(stream.as_raw_fd(), &message, 0), 1);
        }
        stream.write_all(&bytes[1..]).unwrap();
    }

    use super::*;
    use crate::config::{AppRunMode, LogFormat, RuntimeEnvironment};
    use crate::state::{StateLayout, StateLayoutPaths};

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
    fn dependency_trace_uses_actual_loader_selection() {
        let program = Path::new("/usr/local/bin/doveadm");
        let output = "/usr/local/bin/doveadm:\nStart End Type Open Ref GrpRef Name\n001 002 exe 1 0 0 /usr/local/bin/doveadm\n003 004 rlib 0 1 0 /usr/lib/libc.so.103.2\n005 006 rlib 0 1 0 /usr/local/lib/libzstd.so.9.0\n";
        let paths = parse_installed_libraries(output, program).unwrap();
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/usr/lib/libc.so.103.2"),
                PathBuf::from("/usr/local/lib/libzstd.so.9.0")
            ]
        );
        assert!(!paths.contains(&PathBuf::from("/usr/lib")));
        assert!(!paths.contains(&PathBuf::from("/usr/lib/libc.so.103.0")));
    }

    #[test]
    fn dependency_trace_accepts_module_trace_and_current_soname() {
        let program = Path::new("/usr/local/lib/dovecot/libdovecot.so.0.0");
        assert!(dependency_program_allowed(program));
        let output = "/usr/bin/ldd:\nStart End Type Open Ref GrpRef Name\n001 002 dlib 1 0 0 /usr/local/lib/dovecot/libdovecot.so.0.0\n003 004 rlib 0 1 0 /usr/lib/libc.so.103.2\n005 006 ld.so 0 1 0 /usr/libexec/ld.so\n";
        let paths = parse_installed_libraries(output, program).unwrap();
        assert!(paths.contains(&program.to_path_buf()));
        assert!(paths.contains(&PathBuf::from("/usr/libexec/ld.so")));
        assert!(!dependency_program_allowed(Path::new(
            "/usr/local/lib/dovecot/libevil.so.bad"
        )));
    }

    #[test]
    fn dependency_trace_accepts_installed_cpp_libraries_only_in_protected_paths() {
        let program = Path::new("/usr/local/bin/mariadb");
        // Exact library names and trace rows observed on obsd1 in capture130.
        let output = concat!(
            "Start End Type Open Ref GrpRef Name\n",
            "0000007534615000 0000007534730000 rlib 0 1 0 /usr/lib/libc++.so.12.0\n",
            "00000074ebb23000 00000074ebb6e000 rlib 0 2 0 /usr/lib/libc++abi.so.9.0\n",
        );
        assert_eq!(
            parse_installed_libraries(output, program),
            Ok(vec![
                PathBuf::from("/usr/lib/libc++.so.12.0"),
                PathBuf::from("/usr/lib/libc++abi.so.9.0"),
            ])
        );
        for path in [
            "/tmp/libc++.so.12.0",
            "/usr/lib/../tmp/libc++.so.12.0",
            "/usr/lib/libc++.so.12.0?",
            "/usr/lib/libc++@abi.so.9.0",
        ] {
            let output =
                format!("Start End Type Open Ref GrpRef Name\n001 002 rlib 0 1 0 {path}\n");
            assert!(parse_installed_libraries(&output, program).is_err());
        }
        assert!(!dependency_program_allowed(Path::new(
            "/usr/local/lib/dovecot/libc++.so.12.0"
        )));
    }

    #[test]
    fn dependency_trace_refuses_missing_foreign_and_malformed_paths() {
        let program = Path::new("/usr/local/bin/doveadm");
        for row in [
            "003 004 rlib 0 1 0 /tmp/libc.so.103.2",
            "libc.so.103.0 => not found",
            "003 004 rlib 0 1 0 /usr/lib/../tmp/libc.so.1",
            "003 004 unknown 0 1 0 /usr/lib/libc.so.103.2",
        ] {
            let output = format!("Start End Type Open Ref GrpRef Name\n{row}\n");
            assert!(parse_installed_libraries(&output, program).is_err());
        }
        assert!(!dependency_program_allowed(Path::new("/tmp/ldd")));
        assert!(!dependency_program_allowed(Path::new(
            "/usr/local/lib/dovecot/../evil.so"
        )));
    }

    #[test]
    fn postdrop_trace_elf_requires_native_dynamic_object_and_exact_loader_before_exec() {
        let class = if cfg!(target_pointer_width = "64") {
            2
        } else {
            1
        };
        let little = cfg!(target_endian = "little");
        let (ehsize, phsize, phoff_at, size_at, offset_at, filesz_at, flags_at) = if class == 2 {
            (64, 56, 32, 52, 8, 32, 4)
        } else {
            (52, 32, 28, 40, 4, 16, 24)
        };
        let width = if class == 2 { 8 } else { 4 };
        let put = |bytes: &mut [u8], at: usize, width: usize, value: u64| {
            for index in 0..width {
                let shift = if little { index } else { width - index - 1 };
                bytes[at + index] = (value >> (shift * 8)) as u8;
            }
        };
        let mut valid = vec![0; 1024];
        valid[..4].copy_from_slice(b"\x7fELF");
        valid[4] = class;
        valid[5] = if little { 1 } else { 2 };
        valid[6] = 1;
        put(&mut valid, 16, 2, 3);
        put(&mut valid, 18, 2, native_elf_machine().unwrap());
        put(&mut valid, 20, 4, 1);
        put(&mut valid, phoff_at, width, ehsize as u64);
        put(&mut valid, size_at, 2, ehsize as u64);
        put(&mut valid, size_at + 2, 2, phsize as u64);
        put(&mut valid, size_at + 4, 2, 3);
        put(&mut valid, ehsize, 4, 1); // executable PT_LOAD
        put(&mut valid, ehsize + flags_at, 4, 1);
        put(&mut valid, ehsize + phsize, 4, 2); // PT_DYNAMIC
        let interp_header = ehsize + phsize * 2;
        put(&mut valid, interp_header, 4, 3);
        put(&mut valid, interp_header + offset_at, width, 0x350);
        put(&mut valid, interp_header + filesz_at, width, 19);
        valid[0x350..0x363].copy_from_slice(b"/usr/libexec/ld.so\0");
        assert!(postdrop_trace_elf_prefix(&valid));
        let mut executable = valid.clone();
        put(&mut executable, 16, 2, 2);
        assert!(postdrop_trace_elf_prefix(&executable));
        assert!(!postdrop_trace_elf_prefix(b"#!/bin/sh\nexit 0\n"));
        assert!(!postdrop_trace_elf_prefix(&valid[..16]));
        assert!(!postdrop_trace_elf_prefix(
            &valid[..interp_header + phsize - 1]
        ));
        for (label, at, width, value) in [
            ("foreign class", 4, 1, if class == 2 { 1 } else { 2 }),
            ("foreign byte order", 5, 1, if little { 2 } else { 1 }),
            ("ident version", 6, 1, 0),
            ("relocatable type", 16, 2, 1),
            ("foreign machine", 18, 2, 0),
            ("ELF version", 20, 4, 0),
            ("header size", size_at, 2, 0),
            ("program header size", size_at + 2, 2, 0),
            ("missing headers", size_at + 4, 2, 0),
            ("extended headers", size_at + 4, 2, 0xffff),
            ("overflow header offset", phoff_at, width, u64::MAX),
            ("overlapping headers", phoff_at, width, 0),
            ("static executable", interp_header, 4, 4),
            ("missing dynamic table", ehsize + phsize, 4, 4),
            ("nonexecutable loads", ehsize + flags_at, 4, 0),
            (
                "unterminated interpreter",
                interp_header + filesz_at,
                width,
                18,
            ),
            (
                "overflow interpreter",
                interp_header + offset_at,
                width,
                u64::MAX,
            ),
        ] {
            let mut bad = valid.clone();
            put(&mut bad, at, width, value);
            assert!(!postdrop_trace_elf_prefix(&bad), "{label}");
        }
        let mut wrong_loader = valid.clone();
        wrong_loader[0x351] = b'x';
        assert!(!postdrop_trace_elf_prefix(&wrong_loader));
        let mut duplicate = valid.clone();
        put(&mut duplicate, size_at + 4, 2, 4);
        duplicate.copy_within(
            interp_header..interp_header + phsize,
            interp_header + phsize,
        );
        assert!(!postdrop_trace_elf_prefix(&duplicate));
    }

    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore = "requires installed readable dynamic setgid postdrop; trace exits before main"]
    fn installed_dependency_native_setgid_postdrop_trace() {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "trace qualifier requires a nonroot actor"
        );
        let target = Path::new("/usr/local/sbin/postdrop");
        assert_ne!(fs::symlink_metadata(target).unwrap().mode() & 0o2000, 0);
        validate_postdrop_trace_program().expect("protected native dynamic postdrop");
        let command = crate::auth::installed_dependencies_command(target).unwrap();
        assert_eq!(command.get_program(), target);
        assert_eq!(command.get_args().len(), 0);
        let libraries = installed_library_paths_before(
            target,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .expect("setgid postdrop loader trace without program initialization");
        assert!(!libraries.is_empty());
        println!("DEPENDENCIES_POSTDROP_TRACE_PASS target_mode=setgid loader_only=true");
    }

    #[test]
    fn dependency_library_alias_accepts_only_numeric_mariadb_soname_and_exact_package_target() {
        for name in ["libmariadb.so.31.0", "libmariadb.so.32.1.2"] {
            let alias = Path::new("/usr/local/lib").join(name);
            let link = Path::new("mysql").join(name);
            let target = Path::new("/usr/local/lib/mysql").join(name);
            assert_eq!(
                dependency_library_alias_target(&alias, &link),
                Ok(target.clone())
            );
            assert!(dependency_library_allowed(&alias));
            // Only the selected alias authorizes its exact package target.
            assert!(!dependency_library_allowed(&target));
            assert!(!dependency_program_allowed(&alias));
        }
        let alias = Path::new("/usr/local/lib/libmariadb.so.31.0");
        for link in [
            "libmariadb.so.31.0",
            "/usr/local/lib/mysql/libmariadb.so.31.0",
            "mysql/../mysql/libmariadb.so.31.0",
            "mysql/./libmariadb.so.31.0",
            "mysql/libmariadb.so.31.1",
            "mysql/libmariadb.so.31.0/child",
            "../libmariadb.so.31.0",
        ] {
            assert!(dependency_library_alias_target(alias, Path::new(link)).is_err());
        }
        for alias in [
            "/usr/lib/libmariadb.so.31.0",
            "/usr/local/lib/dovecot/libmariadb.so.31.0",
            "/usr/local/lib/libmariadb.so.",
            "/usr/local/lib/libmariadb.so.31..0",
            "/usr/local/lib/libmariadb.so.31.0.bad",
            "/usr/local/lib/libevil.so.31.0",
        ] {
            let path = Path::new(alias);
            let link = Path::new("mysql").join(path.file_name().unwrap());
            assert!(dependency_library_alias_target(path, &link).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn dependency_library_custody_refuses_replaced_alias_and_selected_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = std::env::temp_dir().join(format!(
            "osmap-library-custody-{}-{}",
            std::process::id(),
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.join("libmariadb.so.31.0");
        let target = root.join("target");
        fs::write(&target, b"original object").unwrap();
        symlink("target", &alias).unwrap();
        let custody = || DependencyLibraryCustody {
            selected: alias.clone(),
            link: Some(PathBuf::from("target")),
            identities: vec![
                (alias.clone(), dependency_identity(&alias).unwrap()),
                (target.clone(), dependency_identity(&target).unwrap()),
            ],
        };
        // Capturing the identities alone never admits this user-owned fixture.
        assert!(DependencyLibraryCustody::new(&alias).is_err());
        let before = custody();
        let replacement = root.join("replacement");
        fs::write(&replacement, b"different object").unwrap();
        fs::rename(&replacement, &target).unwrap();
        assert_eq!(
            before.recheck(),
            Err("dependency library changed during resolution".into())
        );
        let before = custody();
        symlink("target", &replacement).unwrap();
        fs::rename(&replacement, &alias).unwrap();
        assert_eq!(
            before.recheck(),
            Err("dependency library changed during resolution".into())
        );
        fs::remove_file(&alias).unwrap();
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&root).unwrap();
    }

    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore = "requires installed Dovecot mysql module; read-only loader trace"]
    fn installed_dependency_native_mysql_module_alias_custody() {
        let libraries = installed_library_paths_before(
            Path::new("/usr/local/lib/dovecot/libdriver_mysql.so"),
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .expect("installed mysql module dependencies and package alias custody");
        let mut aliases = 0;
        for alias in &libraries {
            if alias.parent() == Some(Path::new("/usr/local/lib"))
                && alias
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("libmariadb.so."))
                && fs::symlink_metadata(alias)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            {
                let link = fs::read_link(alias).unwrap();
                let target = dependency_library_alias_target(alias, &link).unwrap();
                assert!(libraries.contains(&target));
                aliases += 1;
            }
        }
        assert_eq!(aliases, 1);
        println!("DEPENDENCIES_MYSQL_ALIAS_PASS aliases=1 alias_and_target_retained=true");
    }

    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore = "requires installed OpenBSD mail dependencies; read-only loader trace"]
    fn installed_dependency_native_trace() {
        for program in [
            "/usr/bin/fstat",
            "/usr/local/bin/doveadm",
            "/usr/local/bin/doveconf",
            "/usr/local/bin/mariadb",
            "/usr/sbin/sendmail",
            "/usr/local/sbin/sendmail",
            "/usr/local/sbin/postdrop",
        ] {
            let libraries = installed_library_paths_before(
                Path::new(program),
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .unwrap_or_else(|error| panic!("{program}: {error}"));
            assert!(!libraries.is_empty());
            assert!(libraries.iter().all(|path| {
                dependency_library_allowed(path)
                    || libraries.iter().any(|alias| {
                        fs::read_link(alias)
                            .ok()
                            .and_then(|link| dependency_library_alias_target(alias, &link).ok())
                            .as_deref()
                            == Some(path.as_path())
                    })
            }));
            println!(
                "DEPENDENCIES_PASS program={program} count={}",
                libraries.len()
            );
        }
    }
    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore = "requires installed root-owned Python alias; read-only selection"]
    fn installed_python_native_selection() {
        let python = crate::account_admission_runtime::installed_python_program()
            .expect("trusted installed Python");
        assert_eq!(python.parent(), Some(Path::new("/usr/local/bin")));
        assert!(python
            .file_name()
            .and_then(|p| p.to_str())
            .is_some_and(|p| p.starts_with("python3.")));
        trusted_dependency_file(&python).expect("protected Python executable");
        println!("PYTHON_SELECTION_PASS program={}", python.display());
    }
}

#[cfg(all(test, target_os = "openbsd"))]
/// The two isolated children apply the exact PreparedChild SQL exec policy.
/// They perform no connect/send, database operation or credential action.
/// Capability denial is tested independently of the ordinary product journey.
pub(crate) fn sql_exec_denial_policy_fixture(
    promises: &std::ffi::CStr,
) -> Result<(), &'static str> {
    #[cfg(not(target_os = "openbsd"))]
    {
        let _ = promises;
        Err("native SQL policy denial test requires OpenBSD")
    }
    #[cfg(target_os = "openbsd")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::time::{Duration, Instant};
        unsafe extern "C" {
            fn pledge(
                promises: *const libc::c_char,
                execpromises: *const libc::c_char,
            ) -> libc::c_int;
        }
        if !password_native_authority() {
            return Err("native SQL policy authority refused");
        }
        disable_core_dumps().map_err(|_| "native SQL policy core limit refused")?;
        let root = std::path::Path::new("/var/tmp/osmap-sql-exec-denial-20261025-01");
        std::fs::create_dir(root).map_err(|_| "exclusive policy scratch creation refused")?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "policy scratch mode refused")?;
        let info =
            std::fs::symlink_metadata(root).map_err(|_| "policy scratch metadata refused")?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o7777 != 0o700 {
            return Err("policy scratch custody refused");
        }
        let path = root.join("forbidden-create");
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err("policy forbidden leaf already exists");
        }
        // Prepare every pointer and value before fork. The child executes only
        // fixed libc calls and _exit; no allocation, Rust I/O or destructor.
        let forbidden = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| "fixed policy path encoding refused")?;
        let original = Instant::now() + Duration::from_secs(5);
        let mut all_denied = true;
        for case in [0u8, 1u8] {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err("policy child fork refused");
            }
            if pid == 0 {
                unsafe {
                    if pledge(promises.as_ptr(), std::ptr::null()) != 0 {
                        libc::_exit(2);
                    }
                    let fd = if case == 0 {
                        libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0)
                    } else {
                        libc::open(
                            forbidden.as_ptr(),
                            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                            0o600,
                        )
                    };
                    let denied = fd == -1 && *libc::__errno() == libc::ENOSYS;
                    if fd >= 0 {
                        libc::close(fd);
                    }
                    libc::_exit(if denied { 0 } else { 1 });
                }
            }
            let mut status = 0;
            let mut reaped = false;
            while Instant::now() < original {
                let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if observed == pid {
                    reaped = true;
                    break;
                }
                if observed < 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(
                        "policy child ownership observation refused; disposition unconfirmed",
                    );
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if !reaped {
                eprintln!("native_sql_exec_policy_denial stage=child_deadline cleanup=pending");
                // The direct child remains unreaped, retaining its PID lease.
                let killed = unsafe { libc::kill(pid, libc::SIGKILL) } == 0;
                let cleanup_deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < cleanup_deadline {
                    let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                    if observed == pid {
                        reaped = true;
                        break;
                    }
                    if observed < 0
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                eprintln!("native_sql_exec_policy_denial stage=child_deadline stop_sent={} reaped={} disposition={}",
                    killed, reaped, if reaped { "confirmed" } else { "uncertain_retained" });
                return Err("policy child deadline expired");
            }
            let denied = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            all_denied &= denied;
            println!("\nnative_sql_exec_policy_denial case={} result={} child_pid={} reaped=true outbound_dispatch=false",
                if case == 0 { "inet_socket" } else { "file_create" },
                if denied { "DENIED_ENOSYS" } else { "FAIL" }, pid);
        }
        let absent = matches!(std::fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
        if !all_denied || !absent {
            return Err("SQL policy denial or no-file postcondition failed");
        }
        println!("\nnative_sql_exec_policy_denial result=PASS cases=2 denied_enosys=2 all_children_reaped=true forbidden_file_absent=true scratch=RETAINED product_qualified=false");
        Ok(())
    }
}
