//! Fixed production submission topology and continuity consumer. Existing
//! direct Postfix AUTH listeners cannot construct this authority. The missing
//! native first-registration producer uses a root-owned qualification record
//! and live process/socket continuity, never a readiness Boolean or empty LIST.
use crate::auth::CommandExecutor;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const CONFIG: &str = "/etc/osmap/account-submission/dovecot.conf";
pub(crate) const IPC: &str = "/var/run/osmap-account-submission/login/ipc-client";
pub(crate) const PORT: u16 = 2525;
const POSTCONF: &str = "/usr/local/sbin/postconf";
const DOVECONF: &str = "/usr/local/bin/doveconf";
pub(crate) const REGISTRATION: &str = "/etc/osmap/account-submission/registration.json";
const PFCTL: &str = "/sbin/pfctl";
const PF_CONFIG: &str = "/etc/pf.conf";
const PF_ANCHOR: &str = "osmap/account-submission";
const REGISTRATION_DIR: &str = "/etc/osmap/account-submission";
pub(crate) const REGISTRATION_NEXT: &str = "/etc/osmap/account-submission/.registration.next";
const SUBMISSION: &str = "/usr/local/libexec/dovecot/submission-login";
const IPC_PROGRAM: &str = "/usr/local/libexec/dovecot/ipc";
const MASTER_PROGRAM: &str = "/usr/local/sbin/dovecot";
const LIMIT: usize = 16384;
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct Unavailable;
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

/// Only an actual native bootstrap observer may construct this record after
/// proving the one persistent submission-login process is registered with IPC,
/// its private backend reauthenticates the real password, and direct backend
/// AUTH bypass is restricted to that frontend. A loopback address alone does
/// not provide that restriction. The fixed root record is written only after
/// controlled native qualification; reading it alone is never sufficient.
pub(crate) struct RegisteredSubmission {
    pid: u32,
    record: Identity,
    record_sha256: [u8; 32],
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationRecord {
    version: u8,
    submission_pid: u32,
    master_pid: u32,
    ipc_pid: u32,
    submission_row: String,
    master_row: String,
    ipc_row: String,
    submission_socket: [u64; 2],
    config_sha256: [u8; 32],
    submission_executable_sha256: [u8; 32],
    master_executable_sha256: [u8; 32],
    ipc_executable_sha256: [u8; 32],
    postfix_master_sha256: [u8; 32],
    postfix_overrides_sha256: [u8; 32],
    frontend_effective_sha256: [u8; 32],
    pf_source_sha256: [u8; 32],
    pf_rules_sha256: [u8; 32],
    pf_anchor_sha256: [u8; 32],
}
impl RegisteredSubmission {
    pub(crate) fn observe_current(
        executor: &(dyn CommandExecutor + Send + Sync),
        startup: &crate::account_password_peer::Startup,
        control_gid: u32,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        if !crate::openbsd::password_native_authority() || control_gid == 0 {
            return Err(Unavailable);
        }
        startup
            .recheck(executor, deadline)
            .map_err(|_| Unavailable)?;
        let (record, bytes) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
        let observed: RegistrationRecord =
            serde_json::from_slice(&bytes).map_err(|_| Unavailable)?;
        if observed.version != 2 || observed.submission_socket.contains(&0) {
            return Err(Unavailable);
        }
        let result = Self {
            pid: observed.submission_pid,
            record,
            record_sha256: Sha256::digest(&bytes).into(),
        };
        snapshot(executor, &result, control_gid, deadline)?;
        startup
            .recheck(executor, deadline)
            .map_err(|_| Unavailable)?;
        Ok(result)
    }
}
/// Fixed pre-seal directory ownership for refreshing an ALREADY qualified
/// root record. It can never create the initial admission receipt or change
/// any admitted configuration/executable/PF hash.
pub(crate) struct RegistrationRefresh {
    directory: File,
    directory_identity: [u64; 5],
}
impl RegistrationRefresh {
    pub(crate) fn capture(deadline: Instant) -> Result<Self, Unavailable> {
        if !crate::openbsd::password_native_authority() || Instant::now() >= deadline {
            return Err(Unavailable);
        }
        crate::account_password_custody::ancestors(REGISTRATION, None, deadline)
            .map_err(|_| Unavailable)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(REGISTRATION_DIR)
            .map_err(|_| Unavailable)?;
        let info = directory.metadata().map_err(|_| Unavailable)?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o022 != 0 {
            return Err(Unavailable);
        }
        let expected = [
            info.dev(),
            info.ino(),
            info.uid().into(),
            info.gid().into(),
            info.mode().into(),
        ];
        let value = Self {
            directory,
            directory_identity: expected,
        };
        value.recheck(deadline)?;
        Ok(value)
    }
    fn recheck(&self, deadline: Instant) -> Result<(), Unavailable> {
        let m = crate::account_password_custody::directory_metadata(REGISTRATION_DIR, 0, deadline)
            .map_err(|_| Unavailable)?;
        let held = self.directory.metadata().map_err(|_| Unavailable)?;
        let id = |m: &fs::Metadata| {
            [
                m.dev(),
                m.ino(),
                m.uid().into(),
                m.gid().into(),
                m.mode().into(),
            ]
        };
        if id(&m) != self.directory_identity
            || id(&held) != self.directory_identity
            || Instant::now() >= deadline
        {
            return Err(Unavailable);
        }
        Ok(())
    }
    pub(crate) fn refresh_stale(
        &self,
        executor: &(dyn CommandExecutor + Send + Sync),
        startup: &crate::account_password_peer::Startup,
        gid: u32,
        deadline: Instant,
    ) -> Result<(), Unavailable> {
        self.recheck(deadline)?;
        crate::openbsd::private_file_try_lock(&self.directory).map_err(|_| Unavailable)?;
        let result = self.refresh_locked(executor, startup, gid, deadline);
        let unlock = crate::openbsd::private_file_unlock(&self.directory).map_err(|_| Unavailable);
        result.and(unlock)
    }
    fn refresh_locked(
        &self,
        executor: &(dyn CommandExecutor + Send + Sync),
        startup: &crate::account_password_peer::Startup,
        gid: u32,
        deadline: Instant,
    ) -> Result<(), Unavailable> {
        let (old_identity, admitted_bytes) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
        let mut admitted: RegistrationRecord =
            serde_json::from_slice(&admitted_bytes).map_err(|_| Unavailable)?;
        if admitted.version != 2 {
            return Err(Unavailable);
        }
        startup
            .recheck(executor, deadline)
            .map_err(|_| Unavailable)?;
        let all = query(
            executor,
            crate::account_password_peer::PS,
            &["-ax", "-o", crate::account_password_peer::PS_FIELDS],
            deadline,
        )?;
        let rows = all
            .lines()
            .map(|line| format!("{line}\n"))
            .collect::<Vec<_>>();
        if rows.len() > 256 {
            return Err(Unavailable);
        }
        let find = |old: &str, old_pid: u32, parent: u32| -> Result<(u32, String), Unavailable> {
            let old_fields = process_fields(old, old_pid)?;
            let found = rows
                .iter()
                .filter(|row| {
                    let fields = row.split_whitespace().collect::<Vec<_>>();
                    fields.len() == 11
                        && fields[10] == old_fields[10]
                        && fields[1] == parent.to_string()
                        && fields[2..5] == old_fields[2..5]
                })
                .collect::<Vec<_>>();
            if found.len() != 1 {
                return Err(Unavailable);
            }
            let pid = found[0]
                .split_whitespace()
                .next()
                .ok_or(Unavailable)?
                .parse::<u32>()
                .map_err(|_| Unavailable)?;
            process_fields(found[0], pid)?;
            Ok((pid, (*found[0]).clone()))
        };
        let master_pid = startup.master_pid();
        let master_row = query(
            executor,
            crate::account_password_peer::PS,
            &[
                "-p",
                &master_pid.to_string(),
                "-o",
                crate::account_password_peer::PS_FIELDS,
            ],
            deadline,
        )?;
        let old_master = process_fields(&admitted.master_row, admitted.master_pid)?;
        let new_master = process_fields(&master_row, master_pid)?;
        if old_master[3..5] != new_master[3..5] || old_master[10] != new_master[10] {
            return Err(Unavailable);
        }
        let (submission_pid, submission_row) = find(
            &admitted.submission_row,
            admitted.submission_pid,
            master_pid,
        )?;
        let (ipc_pid, ipc_row) = find(&admitted.ipc_row, admitted.ipc_pid, master_pid)?;
        if submission_row == admitted.submission_row
            && master_row == admitted.master_row
            && ipc_row == admitted.ipc_row
        {
            return Ok(());
        }
        // Hashes remain from the existing root admission. Only current native
        // process identity and its reciprocal IPC session are refreshed.
        let own = native_process(
            executor,
            submission_pid,
            &submission_row,
            SUBMISSION,
            admitted.submission_executable_sha256,
            deadline,
        )?;
        let server = native_process(
            executor,
            ipc_pid,
            &ipc_row,
            IPC_PROGRAM,
            admitted.ipc_executable_sha256,
            deadline,
        )?;
        let pairs = own
            .iter()
            .filter(|pair| server.contains(&(pair.1, pair.0)))
            .copied()
            .collect::<Vec<_>>();
        if pairs.len() != 1 {
            return Err(Unavailable);
        }
        admitted.submission_pid = submission_pid;
        admitted.submission_row = submission_row;
        admitted.master_pid = master_pid;
        admitted.master_row = master_row;
        admitted.ipc_pid = ipc_pid;
        admitted.ipc_row = ipc_row;
        admitted.submission_socket = [pairs[0].0, pairs[0].1];
        record_snapshot(executor, &admitted, gid, old_identity, deadline)?;
        startup
            .recheck(executor, deadline)
            .map_err(|_| Unavailable)?;
        self.recheck(deadline)?;
        let (current_identity, current) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
        if current_identity != old_identity || current != admitted_bytes {
            return Err(Unavailable);
        }
        let bytes = serde_json::to_vec(&admitted).map_err(|_| Unavailable)?;
        if bytes.len() > LIMIT || Instant::now() >= deadline {
            return Err(Unavailable);
        }
        let from = std::ffi::CString::new(".registration.next").map_err(|_| Unavailable)?;
        let to = std::ffi::CString::new("registration.json").map_err(|_| Unavailable)?;
        let mut output = crate::openbsd::private_leaf_open(
            &self.directory,
            &from,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| Unavailable)?;
        let own = identity(&output.metadata().map_err(|_| Unavailable)?);
        let result = (|| {
            if own.2 != 0 || own.3 != 0 || own.4 & 0o7777 != 0o600 || own.5 != 1 {
                return Err(Unavailable);
            }
            output.write_all(&bytes).map_err(|_| Unavailable)?;
            output.sync_all().map_err(|_| Unavailable)?;
            let temp = fs::symlink_metadata(REGISTRATION_NEXT).map_err(|_| Unavailable)?;
            if temp.dev() != own.0 || temp.ino() != own.1 || Instant::now() >= deadline {
                return Err(Unavailable);
            }
            let (current_id, current) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
            if current_id != old_identity || current != admitted_bytes {
                return Err(Unavailable);
            }
            crate::openbsd::private_leaf_rename(&self.directory, &from, &to)
                .map_err(|_| Unavailable)?;
            self.directory.sync_all().map_err(|_| Unavailable)?;
            let (_, readback) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
            if readback != bytes {
                return Err(Unavailable);
            }
            self.recheck(deadline)
        })();
        if fs::symlink_metadata(REGISTRATION_NEXT)
            .is_ok_and(|m| m.dev() == own.0 && m.ino() == own.1)
        {
            crate::openbsd::private_leaf_unlink(&self.directory, &from).map_err(|_| Unavailable)?;
        }
        result
    }
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    config: Identity,
    config_sha256: [u8; 32],
    ipc: Identity,
    registration: Identity,
    commands: Vec<[u8; 32]>,
}
pub(crate) struct Topology {
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    startup: Arc<crate::account_password_peer::Startup>,
    registration: RegisteredSubmission,
    control_gid: u32,
    accounts: BTreeSet<String>,
    captured: Snapshot,
}
impl Topology {
    pub(crate) fn fixed(
        executor: Arc<dyn CommandExecutor + Send + Sync>,
        startup: Arc<crate::account_password_peer::Startup>,
        registration: RegisteredSubmission,
        control_gid: u32,
        accounts: BTreeSet<String>,
        deadline: Instant,
    ) -> Result<Self, Unavailable> {
        if !crate::openbsd::password_native_authority()
            || registration.pid <= 1
            || registration.pid >= i32::MAX as u32
            || control_gid == 0
            || control_gid == u32::MAX
            || accounts.is_empty()
            || accounts.len() > 64
            || accounts
                .iter()
                .any(|a| crate::account_admission::valid_account(a).is_err())
        {
            return Err(Unavailable);
        }
        let captured = snapshot(executor.as_ref(), &registration, control_gid, deadline)?;
        startup
            .recheck(executor.as_ref(), deadline)
            .map_err(|_| Unavailable)?;
        Ok(Self {
            executor,
            startup,
            registration,
            control_gid,
            accounts,
            captured,
        })
    }
    pub(crate) fn recheck(&self, account: &str, deadline: Instant) -> Result<(), Unavailable> {
        if !self.accounts.contains(account) {
            return Err(Unavailable);
        }
        self.startup
            .recheck(self.executor.as_ref(), deadline)
            .map_err(|_| Unavailable)?;
        if snapshot(
            self.executor.as_ref(),
            &self.registration,
            self.control_gid,
            deadline,
        )? != self.captured
        {
            return Err(Unavailable);
        }
        Ok(())
    }
}
fn metadata(path: &str, mode: u32, gid: u32, socket: bool) -> Result<Identity, Unavailable> {
    crate::account_password_custody::ancestors(
        path,
        None,
        Instant::now() + Duration::from_millis(500),
    )
    .map_err(|_| Unavailable)?;
    let m = fs::symlink_metadata(path).map_err(|_| Unavailable)?;
    if m.uid() != 0
        || m.gid() != gid
        || m.mode() & 0o7777 != mode
        || m.nlink() != 1
        || if socket {
            !m.file_type().is_socket()
        } else {
            !m.is_file() || m.len() == 0 || m.len() > LIMIT as u64
        }
    {
        return Err(Unavailable);
    }
    Ok(identity(&m))
}
fn snapshot(
    executor: &(dyn CommandExecutor + Send + Sync),
    registration: &RegisteredSubmission,
    gid: u32,
    deadline: Instant,
) -> Result<Snapshot, Unavailable> {
    let (record, bytes) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
    if record != registration.record
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != registration.record_sha256
    {
        return Err(Unavailable);
    }
    let observed: RegistrationRecord = serde_json::from_slice(&bytes).map_err(|_| Unavailable)?;
    let result = record_snapshot(executor, &observed, gid, record, deadline)?;
    let (after, current) = private_bytes(REGISTRATION, 0o600, 0, LIMIT)?;
    if after != record || current != bytes {
        return Err(Unavailable);
    }
    Ok(result)
}
fn record_snapshot(
    executor: &(dyn CommandExecutor + Send + Sync),
    observed: &RegistrationRecord,
    gid: u32,
    record: Identity,
    deadline: Instant,
) -> Result<Snapshot, Unavailable> {
    registration_current(executor, observed, deadline)?;
    let config = metadata(CONFIG, 0o440, gid, false)?;
    let ipc = metadata(IPC, 0o660, gid, true)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(CONFIG)
        .map_err(|_| Unavailable)?;
    if identity(&file.metadata().map_err(|_| Unavailable)?) != config {
        return Err(Unavailable);
    }
    let mut data = Vec::new();
    file.take(LIMIT as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| Unavailable)?;
    let config_sha256: [u8; 32] = Sha256::digest(&data).into();
    if data.len() > LIMIT
        || config_sha256 != observed.config_sha256
        || metadata(CONFIG, 0o440, gid, false)? != config
    {
        return Err(Unavailable);
    }
    let master = query(executor, POSTCONF, &["-M"], deadline)?;
    let services = query(executor, POSTCONF, &["-P"], deadline)?;
    let auth = query(
        executor,
        POSTCONF,
        &["-h", "smtpd_sasl_auth_enable"],
        deadline,
    )?;
    postfix(&master, &services, &auth)?;
    let frontend = query(executor, DOVECONF, &["-c", CONFIG, "-n"], deadline)?;
    frontend_listeners(&frontend)?;
    if digest(&master) != observed.postfix_master_sha256
        || digest(&services) != observed.postfix_overrides_sha256
        || digest(&frontend) != observed.frontend_effective_sha256
    {
        return Err(Unavailable);
    }
    let pid = observed.submission_pid.to_string();
    let process = query(
        executor,
        crate::account_password_peer::PS,
        &["-p", &pid, "-o", crate::account_password_peer::PS_FIELDS],
        deadline,
    )?;
    // The native producer binds the actual executable inode/birth; do not
    // guess the kernel's potentially truncated submission-login comm spelling.
    if process != observed.submission_row {
        return Err(Unavailable);
    }
    // This successful fixed administrative exchange proves IPC functionality,
    // not first login-process registration. The opaque bootstrap record above
    // is independently required; an empty LIST never grants that authority.
    let list = query(
        executor,
        crate::account_password_mail::PROGRAM,
        &[
            "-O",
            "-o",
            "stats_writer_socket_path=",
            "proxy",
            "list",
            "-a",
            IPC,
        ],
        deadline,
    )?;
    if list
        .lines()
        .next()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        != Some(vec!["username", "proto", "src", "ip", "dest", "ip", "port"])
    {
        return Err(Unavailable);
    }
    if metadata(IPC, 0o660, gid, true)? != ipc
        || metadata(CONFIG, 0o440, gid, false)? != config
        || Instant::now() >= deadline
    {
        return Err(Unavailable);
    }
    Ok(Snapshot {
        config,
        config_sha256,
        ipc,
        registration: record,
        commands: [master, services, auth, frontend, process]
            .iter()
            .map(|v| Sha256::digest(v.as_bytes()).into())
            .collect(),
    })
}
fn query(
    executor: &(dyn CommandExecutor + Send + Sync),
    program: &str,
    args: &[&str],
    deadline: Instant,
) -> Result<String, Unavailable> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Unavailable)?;
    let output = executor
        .run_with_stdin_bytes_timeout_and_output_limit(
            program,
            &args.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            b"",
            left.min(Duration::from_secs(10)),
            LIMIT,
        )
        .map_err(|_| Unavailable)?;
    if output.status_code != 0
        || !output.stderr.is_empty()
        || output.stdout.len() > LIMIT
        || !output.stdout.is_ascii()
        || output.stdout.contains('\0')
        || Instant::now() >= deadline
    {
        return Err(Unavailable);
    }
    Ok(output.stdout)
}
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn private_bytes(
    path: &str,
    mode: u32,
    gid: u32,
    limit: usize,
) -> Result<(Identity, Vec<u8>), Unavailable> {
    let before = metadata(path, mode, gid, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Unavailable)?;
    if identity(&file.metadata().map_err(|_| Unavailable)?) != before {
        return Err(Unavailable);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Unavailable)?;
    if bytes.is_empty() || bytes.len() > limit || metadata(path, mode, gid, false)? != before {
        return Err(Unavailable);
    }
    Ok((before, bytes))
}
fn process_fields(row: &str, pid: u32) -> Result<Vec<&str>, Unavailable> {
    let fields = row.split_whitespace().collect::<Vec<_>>();
    if row.lines().count() != 1
        || fields.len() != 11
        || pid <= 1
        || pid >= i32::MAX as u32
        || fields[0] != pid.to_string()
        || fields[..5].iter().any(|v| {
            v.parse::<u32>()
                .map_or(true, |n| n.to_string() != *v || n == u32::MAX)
        })
    {
        return Err(Unavailable);
    }
    Ok(fields)
}
fn native_process(
    executor: &(dyn CommandExecutor + Send + Sync),
    pid: u32,
    expected: &str,
    executable: &'static str,
    hash: [u8; 32],
    deadline: Instant,
) -> Result<BTreeSet<(u64, u64)>, Unavailable> {
    let fields = process_fields(expected, pid)?;
    let basename = Path::new(executable)
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(Unavailable)?;
    if fields[10].len() < basename.len().min(15) || !basename.starts_with(fields[10]) {
        return Err(Unavailable);
    }
    let pid_text = pid.to_string();
    if query(
        executor,
        crate::account_password_peer::PS,
        &[
            "-p",
            &pid_text,
            "-o",
            crate::account_password_peer::PS_FIELDS,
        ],
        deadline,
    )? != expected
    {
        return Err(Unavailable);
    }
    let pin = fs::symlink_metadata(executable).map_err(|_| Unavailable)?;
    if !pin.is_file()
        || pin.uid() != 0
        || pin.mode() & 0o022 != 0
        || pin.mode() & 0o111 == 0
        || pin.nlink() != 1
        || pin.len() == 0
        || pin.len() > 32 * 1024 * 1024
    {
        return Err(Unavailable);
    }
    crate::account_password_custody::ancestors(executable, None, deadline)
        .map_err(|_| Unavailable)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(executable)
        .map_err(|_| Unavailable)?;
    if identity(&file.metadata().map_err(|_| Unavailable)?) != identity(&pin) {
        return Err(Unavailable);
    }
    let mut hasher = Sha256::new();
    let mut reader = file.take(32 * 1024 * 1024 + 1);
    let mut block = [0u8; 8192];
    loop {
        if Instant::now() >= deadline {
            return Err(Unavailable);
        }
        let n = reader.read(&mut block).map_err(|_| Unavailable)?;
        if n == 0 {
            break;
        }
        hasher.update(&block[..n]);
    }
    if <[u8; 32]>::from(hasher.finalize()) != hash {
        return Err(Unavailable);
    }
    let fstat = query(
        executor,
        crate::account_password_peer::FSTAT,
        &["-n", "-p", &pid_text],
        deadline,
    )?;
    let mut lines = fstat.lines();
    if lines
        .next()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        != Some(vec![
            "USER", "CMD", "PID", "FD", "DEV", "INUM", "MODE", "R/W", "SZ|DV",
        ])
    {
        return Err(Unavailable);
    }
    let mut texts = 0;
    let mut pairs = BTreeSet::new();
    for (count, line) in lines.enumerate() {
        let f = line.split_whitespace().collect::<Vec<_>>();
        if count >= 255 || f.len() < 4 || f[1] != fields[10] || f[2] != pid_text {
            return Err(Unavailable);
        }
        if f[3] == "text" {
            let joined = f[4..].join(" ");
            let (major, tail) = joined.split_once(',').ok_or(Unavailable)?;
            let tail = tail.split_whitespace().collect::<Vec<_>>();
            let device = crate::openbsd::password_device_parts(pin.dev());
            if tail.len() < 3
                || major.trim().parse::<u32>().ok() != Some(device.0)
                || tail[0].parse::<u32>().ok() != Some(device.1)
                || tail[1].parse::<u64>().ok() != Some(pin.ino())
                || u32::from_str_radix(tail[2], 8).ok() != Some(pin.mode())
            {
                return Err(Unavailable);
            }
            texts += 1;
        } else if f.get(4..6) == Some(&["unix", "stream"][..]) && f.get(7) == Some(&"<->") {
            if !(9..=10).contains(&f.len()) {
                return Err(Unavailable);
            }
            let hex = |s: &str| {
                u64::from_str_radix(s.strip_prefix("0x").ok_or(Unavailable)?, 16)
                    .map_err(|_| Unavailable)
            };
            let pair = (hex(f[6])?, hex(f[8])?);
            if pair.0 == 0 || pair.1 == 0 || !pairs.insert(pair) {
                return Err(Unavailable);
            }
        }
    }
    if texts != 1
        || identity(&fs::symlink_metadata(executable).map_err(|_| Unavailable)?) != identity(&pin)
        || query(
            executor,
            crate::account_password_peer::PS,
            &[
                "-p",
                &pid_text,
                "-o",
                crate::account_password_peer::PS_FIELDS,
            ],
            deadline,
        )? != expected
    {
        return Err(Unavailable);
    }
    Ok(pairs)
}
/// Kernel interface state is checked directly: a matching source/rules hash
/// cannot prove that filtering has not been skipped on loopback.
pub(crate) fn loopback_filtered(output: &str) -> Result<(), Unavailable> {
    if output.trim() == "lo0" {
        Ok(())
    } else {
        Err(Unavailable)
    }
}
fn registration_current(
    executor: &(dyn CommandExecutor + Send + Sync),
    record: &RegistrationRecord,
    deadline: Instant,
) -> Result<(), Unavailable> {
    if record.version != 2
        || record.submission_socket.contains(&0)
        || record.submission_pid == record.ipc_pid
        || record.submission_pid == record.master_pid
        || record.master_pid == record.ipc_pid
    {
        return Err(Unavailable);
    }
    let submission = process_fields(&record.submission_row, record.submission_pid)?;
    let master = process_fields(&record.master_row, record.master_pid)?;
    let ipc = process_fields(&record.ipc_row, record.ipc_pid)?;
    if submission[1] != record.master_pid.to_string()
        || ipc[1] != record.master_pid.to_string()
        || submission[3] == "0"
        || master[1] != "1"
        || master[3] != "0"
        || master[4] != "0"
    {
        return Err(Unavailable);
    }
    let all = query(
        executor,
        crate::account_password_peer::PS,
        &["-ax", "-o", crate::account_password_peer::PS_FIELDS],
        deadline,
    )?;
    let candidates = all
        .lines()
        .filter(|l| l.split_whitespace().last() == Some(submission[10]))
        .collect::<Vec<_>>();
    if candidates.len() != 1 || candidates[0].split_whitespace().collect::<Vec<_>>() != submission {
        return Err(Unavailable);
    }
    let own = native_process(
        executor,
        record.submission_pid,
        &record.submission_row,
        SUBMISSION,
        record.submission_executable_sha256,
        deadline,
    )?;
    native_process(
        executor,
        record.master_pid,
        &record.master_row,
        MASTER_PROGRAM,
        record.master_executable_sha256,
        deadline,
    )?;
    let server = native_process(
        executor,
        record.ipc_pid,
        &record.ipc_row,
        IPC_PROGRAM,
        record.ipc_executable_sha256,
        deadline,
    )?;
    let pair = (record.submission_socket[0], record.submission_socket[1]);
    if !own.contains(&pair) || !server.contains(&(pair.1, pair.0)) {
        return Err(Unavailable);
    }
    let (_, source) = private_bytes(PF_CONFIG, 0o600, 0, LIMIT)?;
    if <[u8; 32]>::from(Sha256::digest(&source)) != record.pf_source_sha256 {
        return Err(Unavailable);
    }
    let interface = query(
        executor,
        PFCTL,
        &["-i", "lo0", "-v", "-s", "Interfaces"],
        deadline,
    )?;
    loopback_filtered(&interface)?;
    let status = query(executor, PFCTL, &["-s", "info"], deadline)?;
    if !status
        .lines()
        .next()
        .is_some_and(|l| l.starts_with("Status: Enabled"))
    {
        return Err(Unavailable);
    }
    let rules = query(executor, PFCTL, &["-sr"], deadline)?;
    if digest(&rules) != record.pf_rules_sha256 {
        return Err(Unavailable);
    }
    let anchor = query(executor, PFCTL, &["-a", PF_ANCHOR, "-sr"], deadline)?;
    if digest(&anchor) != record.pf_anchor_sha256 {
        return Err(Unavailable);
    }
    // The source/effective rules above are the exact pair qualified by the
    // operator-owned bootstrap, including backend UID isolation. Config hashes
    // do not independently replace that native denial/real-password proof.
    Ok(())
}
fn postfix(master: &str, services: &str, auth: &str) -> Result<(), Unavailable> {
    if auth.trim() != "no" {
        return Err(Unavailable);
    }
    let mut overrides = BTreeMap::new();
    for line in services.lines().filter(|v| !v.trim().is_empty()) {
        let (key, value) = line.split_once('=').ok_or(Unavailable)?;
        let key = key.trim();
        if key.split('/').count() != 3
            || overrides
                .insert(key.to_string(), value.trim().to_string())
                .is_some()
        {
            return Err(Unavailable);
        }
    }
    let mut records = Vec::<String>::new();
    for line in master
        .lines()
        .filter(|v| !v.trim().is_empty() && !v.trim_start().starts_with('#'))
    {
        if line.starts_with(char::is_whitespace) {
            records
                .last_mut()
                .ok_or(Unavailable)?
                .push_str(&format!(" {}", line.trim()));
        } else {
            records.push(line.into());
        }
    }
    if records.is_empty() || records.len() > 128 {
        return Err(Unavailable);
    }
    let mut seen = BTreeSet::new();
    let mut backend = 0;
    for line in records {
        let f = line.split_whitespace().collect::<Vec<_>>();
        if f.len() < 8 || !seen.insert(format!("{}/{}", f[0], f[1])) {
            return Err(Unavailable);
        }
        if f[1] == "inet" && !matches!(f[7], "smtpd" | "postscreen") {
            return Err(Unavailable);
        }
        if f[7] != "smtpd" {
            continue;
        }
        let key = format!("{}/{}/smtpd_sasl_auth_enable", f[0], f[1]);
        let effective = overrides.get(&key).map_or("no", String::as_str);
        if !matches!(effective, "yes" | "no") {
            return Err(Unavailable);
        }
        for (index, value) in f.iter().enumerate().skip(8) {
            if value.starts_with("smtpd_sasl_auth_enable=")
                && (index == 0
                    || f[index - 1] != "-o"
                    || value.strip_prefix("smtpd_sasl_auth_enable=") != Some(effective))
            {
                return Err(Unavailable);
            }
            if value.starts_with("-osmtpd_sasl_auth_enable") {
                return Err(Unavailable);
            }
        }
        if effective == "yes" {
            if f[1] != "inet" || f[0] != "127.0.0.1:2525" {
                return Err(Unavailable);
            }
            backend += 1;
        } else if f[1] == "inet" && f[0] == "127.0.0.1:2525" {
            return Err(Unavailable);
        }
    }
    if backend != 1
        || overrides
            .keys()
            .any(|k| !seen.contains(&k.split('/').take(2).collect::<Vec<_>>().join("/")))
    {
        return Err(Unavailable);
    }
    Ok(())
}
fn frontend_listeners(config: &str) -> Result<(), Unavailable> {
    let mut stack = Vec::<String>::new();
    let mut global = None;
    let mut listener: Option<(Option<String>, u16, bool)> = None;
    let mut actual = BTreeSet::new();
    let mut process = None;
    let mut count = None;
    for line in config
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if let Some(head) = line.strip_suffix('{') {
            if stack.len() >= 8 {
                return Err(Unavailable);
            }
            stack.push(head.trim().into());
            if head.trim_start().starts_with("inet_listener") {
                if head.split_whitespace().count() != 2
                    || stack.len() != 2
                    || stack[0] != "service submission-login"
                    || listener.is_some()
                {
                    return Err(Unavailable);
                }
                listener = Some((None, 0, false));
            }
            continue;
        }
        if line == "}" {
            let head = stack.pop().ok_or(Unavailable)?;
            if head.starts_with("inet_listener ") {
                let (address, port, _) = listener.take().ok_or(Unavailable)?;
                if port != 0 {
                    let addresses = address.or_else(|| global.clone()).ok_or(Unavailable)?;
                    for address in addresses.split([',', ' ']).filter(|v| !v.is_empty()) {
                        if !actual.insert((address.to_string(), port)) {
                            return Err(Unavailable);
                        }
                    }
                }
            }
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(Unavailable)?;
        let key = key.trim();
        let value = value.trim();
        if key == "proxy_noauth" && value != "no" || key.contains("master_user") {
            return Err(Unavailable);
        }
        if stack.is_empty() && key == "listen" && global.replace(value.to_string()).is_some() {
            return Err(Unavailable);
        }
        if stack == ["service submission-login"] {
            match key {
                "process_limit" => {
                    if process.replace(value.to_string()).is_some() {
                        return Err(Unavailable);
                    }
                }
                "service_count" => {
                    if count.replace(value.to_string()).is_some() {
                        return Err(Unavailable);
                    }
                }
                _ => {}
            }
        }
        if let Some((address, port, port_seen)) = listener.as_mut() {
            if stack.len() == 2 {
                match key {
                    "address" => {
                        if address.replace(value.into()).is_some() {
                            return Err(Unavailable);
                        }
                    }
                    "port" => {
                        if *port_seen {
                            return Err(Unavailable);
                        }
                        *port_seen = true;
                        *port = value.parse().map_err(|_| Unavailable)?;
                    }
                    _ => {}
                }
            }
        }
    }
    let expected: BTreeSet<(String, u16)> = [
        ("127.0.0.1".to_string(), 587),
        ("127.0.0.1".to_string(), 465),
        ("10.44.0.1".to_string(), 587),
        ("10.44.0.1".to_string(), 465),
    ]
    .into();
    if !stack.is_empty()
        || listener.is_some()
        || actual != expected
        || process.as_deref() != Some("1")
        || count.as_deref() != Some("0")
    {
        return Err(Unavailable);
    }
    Ok(())
}
