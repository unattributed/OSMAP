//! Native single-connection IMAP peer and actual anvil registration producer.
//! Only fixed trusted startup plus kernel peer credentials select process IDs.
//! This module starts no listener and changes no native qualification flag.
use crate::account_password_policy::{
    Error as PolicyError, RegistrationEvidence, RegistrationObserver,
};
use crate::account_password_policy_endpoint::{Error, PeerInspector, PublishClaim};
use crate::account_password_state::Guard;
use crate::auth::CommandExecutor;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) const PS: &str = "/bin/ps";
pub(crate) const FSTAT: &str = "/usr/bin/fstat";
pub(crate) const PS_FIELDS: &str = "pid=,ppid=,pgid=,uid=,gid=,lstart=,comm=";
const IMAP: &str = "/usr/local/libexec/dovecot/imap";
const MASTER: &str = "/usr/local/sbin/dovecot";
const HELPER: &str = "/usr/local/libexec/osmap/account-passwd";
const WHO_HEADER: &str = "username\t#\tproto\t(pids)\t(ips)\n";
#[derive(Clone, PartialEq, Eq)]
struct FilePin {
    path: &'static str,
    dev: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn file_pin(path: &'static str) -> Result<FilePin, Error> {
    let p = Path::new(path);
    crate::account_password_custody::ancestors(
        path,
        None,
        Instant::now() + Duration::from_millis(500),
    )
    .map_err(|_| Error::Unavailable)?;
    let m = fs::symlink_metadata(p).map_err(|_| Error::Unavailable)?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || m.mode() & 0o111 == 0
        || m.len() == 0
        || !(m.nlink() == 1 || path == FSTAT && m.nlink() == 2)
    {
        return Err(Error::Refused);
    }
    Ok(FilePin {
        path,
        dev: m.dev(),
        inode: m.ino(),
        mode: m.mode(),
        size: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
#[derive(Clone, PartialEq, Eq)]
struct Row {
    pid: u32,
    parent: u32,
    group: u32,
    uid: u32,
    gid: u32,
    birth: String,
    command: String,
}
fn decimal(v: &str) -> Result<u32, Error> {
    let n: u32 = v.parse().map_err(|_| Error::Refused)?;
    if n.to_string() != v || n == u32::MAX {
        Err(Error::Refused)
    } else {
        Ok(n)
    }
}
fn row(raw: &str, expected: u32) -> Result<Row, Error> {
    let values: Vec<_> = raw.split_whitespace().collect();
    if raw.lines().count() != 1 || values.len() != 11 {
        return Err(Error::Refused);
    }
    let nums = values[..5]
        .iter()
        .map(|v| decimal(v))
        .collect::<Result<Vec<_>, _>>()?;
    let birth = values[5..10].join(" ");
    if nums[0] != expected
        || nums[..3].iter().any(|v| *v >= i32::MAX as u32)
        || !matches!(
            values[5],
            "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
        )
        || !matches!(
            values[6],
            "Jan"
                | "Feb"
                | "Mar"
                | "Apr"
                | "May"
                | "Jun"
                | "Jul"
                | "Aug"
                | "Sep"
                | "Oct"
                | "Nov"
                | "Dec"
        )
        || !decimal(values[7]).is_ok_and(|v| (1..=31).contains(&v))
        || values[9].len() != 4
        || !values[9].bytes().all(|v| v.is_ascii_digit())
    {
        return Err(Error::Refused);
    }
    let time: Vec<_> = values[8].split(':').collect();
    if time.len() != 3
        || time
            .iter()
            .any(|v| v.len() != 2 || !v.bytes().all(|b| b.is_ascii_digit()))
        || time[0].parse::<u8>().map_or(true, |v| v > 23)
        || time[1..]
            .iter()
            .any(|v| v.parse::<u8>().map_or(true, |v| v > 59))
    {
        return Err(Error::Refused);
    }
    Ok(Row {
        pid: nums[0],
        parent: nums[1],
        group: nums[2],
        uid: nums[3],
        gid: nums[4],
        birth,
        command: values[10].into(),
    })
}
fn descriptors(
    raw: &str,
    process: &Row,
    pin: &FilePin,
) -> Result<BTreeMap<i32, (u64, u64)>, Error> {
    let mut lines = raw.lines();
    if lines
        .next()
        .map(|v| v.split_whitespace().collect::<Vec<_>>())
        != Some(vec![
            "USER", "CMD", "PID", "FD", "DEV", "INUM", "MODE", "R/W", "SZ|DV",
        ])
    {
        return Err(Error::Refused);
    }
    let mut texts = 0;
    let mut sockets = BTreeMap::new();
    for (index, line) in lines.enumerate() {
        let f: Vec<_> = line.split_whitespace().collect();
        if index >= 255 || f.len() < 4 || f[1] != process.command || decimal(f[2])? != process.pid {
            return Err(Error::Refused);
        }
        if f[3] == "text" {
            let joined = f[4..].join(" ");
            let (major, rest) = joined.split_once(',').ok_or(Error::Refused)?;
            let tail: Vec<_> = rest.split_whitespace().collect();
            if tail.len() < 3 {
                return Err(Error::Refused);
            }
            let parts = crate::openbsd::password_device_parts(pin.dev);
            if decimal(major.trim())? != parts.0
                || decimal(tail[0])? != parts.1
                || tail[1].parse::<u64>().ok() != Some(pin.inode)
                || u32::from_str_radix(tail[2], 8).ok() != Some(pin.mode)
            {
                return Err(Error::Refused);
            }
            texts += 1;
        } else if f.get(4..6) == Some(&["unix", "stream"][..]) && f.get(7) == Some(&"<->") {
            if !(9..=10).contains(&f.len()) {
                return Err(Error::Refused);
            }
            let fd = decimal(f[3].strip_suffix('*').ok_or(Error::Refused)?)?;
            let hex = |v: &str| {
                u64::from_str_radix(v.strip_prefix("0x").ok_or(Error::Refused)?, 16)
                    .map_err(|_| Error::Refused)
            };
            let pair = (hex(f[6])?, hex(f[8])?);
            if fd >= i32::MAX as u32
                || pair.0 == 0
                || pair.1 == 0
                || sockets.insert(fd as i32, pair).is_some()
            {
                return Err(Error::Refused);
            }
        }
    }
    if texts != 1 {
        return Err(Error::Refused);
    }
    Ok(sockets)
}
/// OpenBSD fstat's complete socket payload identifies the PCB/file
/// description independently of its per-process descriptor number. Connected
/// Unix transports include TLS-login proxies; direct TCP transports use the
/// kernel TCP PCB plus exact endpoints/direction. Other kinds never attest IO.
#[allow(dead_code)] // Historical private registration evidence, not stock admission.
fn socket_descriptions(
    raw: &str,
    process: &Row,
    pin: &FilePin,
) -> Result<BTreeMap<i32, String>, Error> {
    descriptors(raw, process, pin)?;
    let mut result = BTreeMap::new();
    for line in raw.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let family = fields.get(4).copied().unwrap_or("");
        if !matches!(family, "unix" | "internet" | "internet6") {
            continue;
        }
        if fields.get(5) != Some(&"stream") {
            continue;
        }
        let fd = decimal(fields[3].strip_suffix('*').ok_or(Error::Refused)?)?;
        if fd >= i32::MAX as u32 {
            return Err(Error::Refused);
        }
        let hex = |value: &str| -> Result<(), Error> {
            let n = u64::from_str_radix(value.strip_prefix("0x").ok_or(Error::Refused)?, 16)
                .map_err(|_| Error::Refused)?;
            if n == 0 {
                return Err(Error::Refused);
            }
            Ok(())
        };
        if family == "unix" {
            if !(9..=10).contains(&fields.len()) || fields[7] != "<->" {
                return Err(Error::Refused);
            }
            hex(fields[6])?;
            hex(fields[8])?;
        } else {
            if !(11..=12).contains(&fields.len())
                || fields[6] != "tcp"
                || !matches!(fields[9], "<--" | "-->")
                || fields[8].is_empty()
                || fields[10].is_empty()
            {
                return Err(Error::Refused);
            }
            hex(fields[7])?;
        }
        if result.insert(fd as i32, fields[4..].join(" ")).is_some() {
            return Err(Error::Refused);
        }
    }
    Ok(result)
}

fn registered_pids(raw: &str, account: &str) -> Result<BTreeSet<u32>, Error> {
    let rows = raw.strip_prefix(WHO_HEADER).ok_or(Error::Refused)?;
    if !raw.ends_with('\n') || raw.contains(['\r', '\0']) {
        return Err(Error::Refused);
    }
    let mut all = BTreeSet::new();
    for (index, line) in rows.lines().enumerate() {
        let f: Vec<_> = line.split('\t').collect();
        if index >= 64 || f.len() != 5 || f[0] != account || f[2] != "imap" {
            return Err(Error::Refused);
        }
        let count = decimal(f[1])?;
        let pids = f[3]
            .strip_prefix('(')
            .and_then(|v| v.strip_suffix(')'))
            .ok_or(Error::Refused)?;
        let values = pids
            .split(' ')
            .map(decimal)
            .collect::<Result<Vec<_>, _>>()?;
        let pids = values.iter().copied().collect::<BTreeSet<_>>();
        if count == 0
            || pids.len() != values.len()
            || pids.len() != count as usize
            || pids.iter().any(|v| *v <= 1 || *v >= i32::MAX as u32)
        {
            return Err(Error::Refused);
        }
        let ips = f[4]
            .strip_prefix('(')
            .and_then(|v| v.strip_suffix(')'))
            .ok_or(Error::Refused)?;
        if !ips
            .bytes()
            .all(|v| v.is_ascii_hexdigit() || b" .:".contains(&v))
        {
            return Err(Error::Refused);
        }
        for pid in pids {
            if all.len() >= 64 || !all.insert(pid) {
                return Err(Error::Refused);
            }
        }
    }
    Ok(all)
}
/// Fixed account-filtered anvil observation. These IDs are registration
/// coverage only and are never used as signal authority.
pub(crate) fn account_imap_pids(
    control: &impl CommandExecutor,
    account: &str,
    deadline: Instant,
) -> Result<BTreeSet<u32>, Error> {
    crate::account_admission::valid_account(account).map_err(|_| Error::Refused)?;
    let args = crate::account_password_mail::WHO
        .iter()
        .map(|v| v.to_string())
        .chain(std::iter::once(account.into()))
        .collect::<Vec<_>>();
    registered_pids(
        &query(
            control,
            crate::account_password_mail::PROGRAM,
            &args,
            deadline,
        )?,
        account,
    )
}

fn registered(raw: &str, account: &str, pid: u32) -> Result<(), Error> {
    if registered_pids(raw, account)?.contains(&pid) {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}

#[derive(Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct Snapshot {
    master: Row,
    peer: Row,
    own: Row,
    pcb: (u64, u64),
}
#[allow(dead_code)]
struct Bound {
    stream: UnixStream,
    fd: i32,
    credentials: (u32, u32, u32),
    snapshot: Snapshot,
    account: Option<String>,
    session: Option<String>,
    io: Option<Vec<(i32, i32, String)>>,
    deadline: Instant,
}
#[allow(dead_code)]
pub(crate) struct Binding {
    fd: i32,
    deadline: Instant,
}
#[allow(dead_code)]
pub(crate) struct NativeRegistration {
    account: String,
    session: String,
    epoch: u64,
    pid: u32,
    uid: u32,
    birth: u64,
    observed: Instant,
}
#[allow(dead_code)]
impl NativeRegistration {
    pub(crate) fn account(&self) -> &str {
        &self.account
    }
    pub(crate) fn session(&self) -> &str {
        &self.session
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn birth(&self) -> u64 {
        self.birth
    }
    pub(crate) fn observed(&self) -> Instant {
        self.observed
    }
}
#[allow(dead_code)]
pub(crate) struct NativeInspector<'a, E> {
    executor: &'a E,
    master: Row,
    own: Row,
    pins: Vec<FilePin>,
    accounts: BTreeSet<String>,
    bound: Mutex<Option<Bound>>,
}
/// Opaque process/file anchors captured once before service listeners start.
/// A new accepted connection cannot refresh a reused master's birth identity.
#[derive(Clone)]
pub(crate) struct Startup {
    master: Row,
    own: Row,
    pins: Vec<FilePin>,
}
impl Startup {
    pub(crate) fn master_pid(&self) -> u32 {
        self.master.pid
    }
    #[allow(dead_code)] // Retained legacy private-authority constructor; stock service uses StockStartup.
    pub(crate) fn native(
        executor: &(impl CommandExecutor + ?Sized),
        master_pid: u32,
        deadline: Instant,
    ) -> Result<Self, Error> {
        if !crate::openbsd::password_native_authority()
            || master_pid <= 1
            || master_pid >= i32::MAX as u32
        {
            return Err(Error::Refused);
        }
        let pins = [PS, FSTAT, IMAP, MASTER, HELPER]
            .into_iter()
            .map(file_pin)
            .collect::<Result<Vec<_>, _>>()?;
        let own_pid = std::process::id();
        let master = row(
            &query(executor, PS, &ps_args(master_pid), deadline)?,
            master_pid,
        )?;
        let own = row(&query(executor, PS, &ps_args(own_pid), deadline)?, own_pid)?;
        if master.parent != 1
            || master.pid != master.group
            || master.uid != 0
            || master.gid != 0
            || master.command != "dovecot"
            || own.uid != 0
            || own.gid != 0
            || own.group != own.pid
            || own.command != "account-passwd"
            || master.pid == own.pid
        {
            return Err(Error::Refused);
        }
        let value = Self { master, own, pins };
        for (process, path) in [(&value.master, MASTER), (&value.own, HELPER)] {
            descriptors(
                &query(executor, FSTAT, &fstat_args(process.pid), deadline)?,
                process,
                value
                    .pins
                    .iter()
                    .find(|p| p.path == path)
                    .ok_or(Error::Refused)?,
            )?;
        }
        Ok(value)
    }
    /// Uses the originally captured identities; a new connection cannot renew
    /// a replaced master's birth or a changed executable/metadata utility.
    pub(crate) fn recheck(
        &self,
        executor: &(impl CommandExecutor + ?Sized),
        deadline: Instant,
    ) -> Result<(), Error> {
        self.recheck_with_stage(executor, deadline, &mut "primary_startup_recheck")
    }
    fn recheck_with_stage(
        &self,
        executor: &(impl CommandExecutor + ?Sized),
        deadline: Instant,
        stage: &mut &'static str,
    ) -> Result<(), Error> {
        if !crate::openbsd::password_native_authority()
            || std::process::id() != self.own.pid
            || Instant::now() >= deadline
        {
            return Err(Error::Refused);
        }
        for pin in &self.pins {
            *stage = match pin.path {
                PS => "primary_startup_pin_ps",
                FSTAT => "primary_startup_pin_fstat",
                IMAP => "primary_startup_pin_imap",
                MASTER => "primary_startup_pin_master",
                _ => "primary_startup_pin_helper",
            };
            if file_pin(pin.path)? != *pin {
                return Err(Error::Refused);
            }
        }
        for (process, path) in [(&self.master, MASTER), (&self.own, HELPER)] {
            *stage = if path == MASTER {
                "primary_startup_master_row"
            } else {
                "primary_startup_own_row"
            };
            if row(
                &query_with_stage(executor, PS, &ps_args(process.pid), deadline, stage)?,
                process.pid,
            )? != *process
            {
                return Err(Error::Refused);
            }
            *stage = if path == MASTER {
                "primary_startup_master_fstat"
            } else {
                "primary_startup_own_fstat"
            };
            descriptors(
                &query_with_stage(executor, FSTAT, &fstat_args(process.pid), deadline, stage)?,
                process,
                self.pins
                    .iter()
                    .find(|pin| pin.path == path)
                    .ok_or(Error::Refused)?,
            )?;
        }
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl<'a, E: CommandExecutor> NativeInspector<'a, E> {
    pub(crate) fn from_startup(
        executor: &'a E,
        startup: &Startup,
        accounts: BTreeSet<String>,
    ) -> Result<Self, Error> {
        if !crate::openbsd::password_native_authority()
            || std::process::id() != startup.own.pid
            || accounts.is_empty()
            || accounts.len() > 64
            || accounts
                .iter()
                .any(|a| crate::account_admission::valid_account(a).is_err())
        {
            return Err(Error::Refused);
        }
        Ok(Self {
            executor,
            master: startup.master.clone(),
            own: startup.own.clone(),
            pins: startup.pins.clone(),
            accounts,
            bound: Mutex::new(None),
        })
    }
    fn pin(&self, path: &str) -> Result<&FilePin, Error> {
        self.pins
            .iter()
            .find(|p| p.path == path)
            .ok_or(Error::Refused)
    }
    fn io_continuity(&self, bound: &Bound, deadline: Instant) -> Result<(), Error> {
        let labels = bound.io.as_ref().ok_or(Error::Refused)?;
        let peer = socket_descriptions(
            &query(
                self.executor,
                FSTAT,
                &fstat_args(bound.credentials.0),
                deadline,
            )?,
            &bound.snapshot.peer,
            self.pin(IMAP)?,
        )?;
        let own = socket_descriptions(
            &query(self.executor, FSTAT, &fstat_args(self.own.pid), deadline)?,
            &bound.snapshot.own,
            self.pin(HELPER)?,
        )?;
        for (label, received, description) in labels {
            if peer.get(label) != Some(description) || own.get(received) != Some(description) {
                return Err(Error::Refused);
            }
        }
        Ok(())
    }
    fn snapshot(
        &self,
        stream: &UnixStream,
        fd: i32,
        credentials: (u32, u32, u32),
        deadline: Instant,
    ) -> Result<Snapshot, Error> {
        if kernel(stream)? != credentials
            || credentials.1 == 0
            || [self.master.pid, self.own.pid].contains(&credentials.0)
        {
            return Err(Error::Refused);
        }
        for pin in &self.pins {
            if file_pin(pin.path)? != *pin {
                return Err(Error::Refused);
            }
        }
        let rows = [self.master.pid, credentials.0, self.own.pid]
            .into_iter()
            .map(|pid| {
                query(self.executor, PS, &ps_args(pid), deadline).and_then(|raw| row(&raw, pid))
            })
            .collect::<Result<Vec<_>, _>>()?;
        roles(&rows, &self.master, &self.own, credentials)?;
        let peer = descriptors(
            &query(self.executor, FSTAT, &fstat_args(credentials.0), deadline)?,
            &rows[1],
            self.pin(IMAP)?,
        )?;
        let own = descriptors(
            &query(self.executor, FSTAT, &fstat_args(self.own.pid), deadline)?,
            &rows[2],
            self.pin(HELPER)?,
        )?;
        let pcb = reciprocal(&own, &peer, fd)?;
        for process in &rows {
            if row(
                &query(self.executor, PS, &ps_args(process.pid), deadline)?,
                process.pid,
            )? != *process
            {
                return Err(Error::Refused);
            }
        }
        for pin in &self.pins {
            if file_pin(pin.path)? != *pin {
                return Err(Error::Refused);
            }
        }
        if kernel(stream)? != credentials || Instant::now() >= deadline {
            return Err(Error::Refused);
        }
        Ok(Snapshot {
            master: rows[0].clone(),
            peer: rows[1].clone(),
            own: rows[2].clone(),
            pcb,
        })
    }
}
impl<E: CommandExecutor> PeerInspector for NativeInspector<'_, E> {
    type Binding = Binding;
    fn admit(&self, stream: &UnixStream, deadline: Instant) -> Result<Binding, Error> {
        let mut bound = self.bound.try_lock().map_err(|_| Error::Unavailable)?;
        if bound.is_some() {
            return Err(Error::Refused);
        }
        let credentials = kernel(stream)?;
        let fd = stream.as_raw_fd();
        let snapshot = self.snapshot(stream, fd, credentials, deadline)?;
        *bound = Some(Bound {
            stream: stream.try_clone().map_err(|_| Error::Unavailable)?,
            fd,
            credentials,
            snapshot,
            account: None,
            session: None,
            io: None,
            deadline,
        });
        Ok(Binding { fd, deadline })
    }
    fn validate(
        &self,
        binding: &Binding,
        stream: &UnixStream,
        claim: &PublishClaim,
        deadline: Instant,
    ) -> Result<(), Error> {
        let mut guard = self.bound.try_lock().map_err(|_| Error::Unavailable)?;
        let bound = guard.as_mut().ok_or(Error::Refused)?;
        if binding.fd != bound.fd
            || stream.as_raw_fd() != bound.fd
            || binding.deadline != deadline
            || bound.deadline != deadline
            || claim.pid != bound.credentials.0
            || !self.accounts.contains(&claim.account)
            || kernel(stream)? != bound.credentials
        {
            return Err(Error::Refused);
        }
        if self.snapshot(stream, bound.fd, bound.credentials, deadline)? != bound.snapshot {
            return Err(Error::Refused);
        }
        bound.account = Some(claim.account.clone());
        bound.session = Some(claim.session.clone());
        Ok(())
    }
    fn attest_io(
        &self,
        binding: &Binding,
        stream: &UnixStream,
        claim: &PublishClaim,
        io: crate::openbsd::ReceivedImapIo,
        deadline: Instant,
    ) -> Result<crate::account_password_imap::AttestedIo, Error> {
        let mut held = self.bound.try_lock().map_err(|_| Error::Unavailable)?;
        let bound = held.as_mut().ok_or(Error::Refused)?;
        // Endpoint has already called validate. Require that exact consumed
        // binding rather than redispatching the same full metadata campaign.
        if binding.fd != bound.fd
            || binding.deadline != deadline
            || bound.deadline != deadline
            || stream.as_raw_fd() != bound.fd
            || bound.account.as_deref() != Some(claim.account.as_str())
            || bound.session.as_deref() != Some(claim.session.as_str())
            || claim.pid != bound.credentials.0
            || io.len() != claim.fds
            || kernel(stream)? != bound.credentials
            || Instant::now() >= deadline
        {
            return Err(Error::Refused);
        }
        let peer = socket_descriptions(
            &query(
                self.executor,
                FSTAT,
                &fstat_args(bound.credentials.0),
                deadline,
            )?,
            &bound.snapshot.peer,
            self.pin(IMAP)?,
        )?;
        let own = socket_descriptions(
            &query(self.executor, FSTAT, &fstat_args(self.own.pid), deadline)?,
            &bound.snapshot.own,
            self.pin(HELPER)?,
        )?;
        let labels = if claim.fds == 1 {
            vec![claim.fd_in]
        } else {
            vec![claim.fd_in, claim.fd_out]
        };
        let mut descriptions = Vec::new();
        let mut continuity = Vec::new();
        for (index, label) in labels.into_iter().enumerate() {
            let description = peer.get(&label).ok_or(Error::Refused)?;
            let received = io.fd(index).ok_or(Error::Refused)?.as_raw_fd();
            if received == bound.fd
                || own.get(&received) != Some(description)
                || description == own.get(&bound.fd).ok_or(Error::Refused)?
            {
                return Err(Error::Refused);
            }
            descriptions.push(description.clone());
            continuity.push((label, received, description.clone()));
        }
        if Instant::now() >= deadline {
            return Err(Error::Refused);
        }
        // Full fresh process/kernel/text/anvil custody and both IO maps are
        // independently rechecked by observe_registration UNDER the account
        // guard before Registry can receive these still-owned rights.
        bound.io = Some(continuity);
        Ok(crate::account_password_imap::AttestedIo::from_native(
            claim.account.clone(),
            claim.session.clone(),
            claim.pid,
            descriptions,
            io,
        ))
    }
}
impl<E: CommandExecutor> RegistrationObserver for NativeInspector<'_, E> {
    fn observe_registration(
        &self,
        guard: &Guard<'_>,
        account: &str,
        session: &str,
        deadline: Instant,
    ) -> Result<RegistrationEvidence, PolicyError> {
        let observe = || -> Result<NativeRegistration, Error> {
            let held = self.bound.try_lock().map_err(|_| Error::Unavailable)?;
            let bound = held.as_ref().ok_or(Error::Refused)?;
            if bound.account.as_deref() != Some(account)
                || bound.session.as_deref() != Some(session)
                || deadline > bound.deadline
            {
                return Err(Error::Refused);
            }
            let epoch = guard.admission(None).map_err(|_| Error::Refused)?.epoch;
            self.io_continuity(bound, deadline)?;
            if self.snapshot(&bound.stream, bound.fd, bound.credentials, deadline)?
                != bound.snapshot
            {
                return Err(Error::Refused);
            }
            let args = crate::account_password_mail::WHO
                .iter()
                .map(|v| v.to_string())
                .chain(std::iter::once(account.into()))
                .collect::<Vec<_>>();
            registered(
                &query(
                    self.executor,
                    crate::account_password_mail::PROGRAM,
                    &args,
                    deadline,
                )?,
                account,
                bound.credentials.0,
            )?;
            if self.snapshot(&bound.stream, bound.fd, bound.credentials, deadline)?
                != bound.snapshot
            {
                return Err(Error::Refused);
            }
            self.io_continuity(bound, deadline)?;
            let digest = Sha256::digest(bound.snapshot.peer.birth.as_bytes());
            let birth = u64::from_be_bytes(digest[..8].try_into().map_err(|_| Error::Refused)?);
            if birth == 0 {
                return Err(Error::Refused);
            }
            Ok(NativeRegistration {
                account: account.into(),
                session: session.into(),
                epoch,
                pid: bound.credentials.0,
                uid: bound.credentials.1,
                birth,
                observed: Instant::now(),
            })
        };
        observe()
            .map(RegistrationEvidence::from_native_observation)
            .map_err(|_| PolicyError::Unavailable)
    }
}
fn kernel(stream: &UnixStream) -> Result<(u32, u32, u32), Error> {
    let p = crate::openbsd::password_kernel_peer(stream).map_err(|_| Error::Unavailable)?;
    Ok((p.pid(), p.uid(), p.gid()))
}
fn ps_args(pid: u32) -> Vec<String> {
    vec!["-p".into(), pid.to_string(), "-o".into(), PS_FIELDS.into()]
}
fn fstat_args(pid: u32) -> Vec<String> {
    vec!["-n".into(), "-p".into(), pid.to_string()]
}
fn roles(rows: &[Row], master: &Row, own: &Row, credentials: (u32, u32, u32)) -> Result<(), Error> {
    if rows.len() != 3
        || rows[0] != *master
        || rows[2] != *own
        || rows[1].pid != credentials.0
        || rows[1].parent != master.pid
        || rows[1].uid != credentials.1
        || rows[1].gid != credentials.2
        || rows[1].command != "imap"
    {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
fn reciprocal(
    own: &BTreeMap<i32, (u64, u64)>,
    peer: &BTreeMap<i32, (u64, u64)>,
    fd: i32,
) -> Result<(u64, u64), Error> {
    let pcb = *own.get(&fd).ok_or(Error::Refused)?;
    if pcb.0 == pcb.1 || peer.values().filter(|p| **p == (pcb.1, pcb.0)).count() != 1 {
        Err(Error::Refused)
    } else {
        Ok(pcb)
    }
}
fn query<E: CommandExecutor + ?Sized>(
    executor: &E,
    program: &str,
    args: &[String],
    deadline: Instant,
) -> Result<String, Error> {
    query_with_stage(
        executor,
        program,
        args,
        deadline,
        &mut "primary_metadata_query",
    )
}
fn query_with_stage<E: CommandExecutor + ?Sized>(
    executor: &E,
    program: &str,
    args: &[String],
    deadline: Instant,
    stage: &mut &'static str,
) -> Result<String, Error> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or(Error::Expired)?
        .min(Duration::from_millis(500));
    let query_deadline = deadline.min(Instant::now() + left);
    let limit = if program == crate::account_password_mail::PROGRAM {
        4096
    } else {
        65536
    };
    let result = executor
        .run_with_stdin_bytes_timeout_and_output_limit(program, args, b"", left, limit)
        .map_err(|error| {
            if let Some(tag) =
                crate::account_password_process::metadata_phase_failure(stage, &error.reason)
            {
                *stage = tag;
            } else if *stage == "stock_metadata_query" {
                *stage = crate::account_password_process::metadata_failure_tag(&error.reason)
                    .unwrap_or("metadata_ps_unknown");
            }
            Error::Unavailable
        })?;
    let failure = if Instant::now() >= query_deadline {
        Some("metadata_query_deadline")
    } else if result.status_code != 0 {
        Some("metadata_query_exit")
    } else if !result.stderr.is_empty() {
        Some("metadata_query_stderr")
    } else if result.stdout.is_empty()
        || result.stdout.len() > limit
        || !result.stdout.is_ascii()
        || result.stdout.contains('\0')
    {
        Some("metadata_query_output")
    } else {
        None
    };
    if let Some(tag) = failure {
        if let Some(combined) = crate::account_password_process::metadata_phase_failure(stage, tag)
        {
            *stage = combined;
        } else if *stage == "stock_metadata_query" {
            *stage = tag;
        }
        return Err(Error::Unavailable);
    }
    Ok(result.stdout)
}

// A measured private-auth process/socket observation is not a loaded-config or
// deployment qualification receipt. Production still requires its closed gate.
const PRIMARY_AUTH: &str = "/usr/local/libexec/dovecot/auth";
const PRIMARY_SOCKET: &str = "/var/dovecot/osmap-account-auth-client";
const PRIMARY_FRAGMENT: &str = "/etc/dovecot/conf.d/99-osmap-private-primary.conf";
const CONTROL_FRAGMENT: &str = "/etc/dovecot/conf.d/99-osmap-private-control.conf";
const PRIMARY_FRAGMENT_SHA256: [u8; 32] = [
    116, 100, 239, 200, 106, 6, 129, 145, 121, 10, 118, 175, 51, 64, 37, 104, 100, 223, 158, 130,
    219, 195, 1, 118, 1, 94, 138, 64, 48, 74, 81, 244,
];
// Maximum fixed read grants; actual PrimaryFile membership is captured once.
pub(crate) const PRIMARY_CONFIGURATION_PATHS: &[&str] = &[
    "/etc/dovecot/dovecot.conf",
    "/etc/dovecot/conf.d/10-auth.conf",
    "/etc/dovecot/conf.d/10-director.conf",
    "/etc/dovecot/conf.d/10-logging.conf",
    "/etc/dovecot/conf.d/10-mail.conf",
    "/etc/dovecot/conf.d/10-master.conf",
    "/etc/dovecot/conf.d/10-metrics.conf",
    "/etc/dovecot/conf.d/10-ssl.conf",
    "/etc/dovecot/conf.d/15-lda.conf",
    "/etc/dovecot/conf.d/15-mailboxes.conf",
    "/etc/dovecot/conf.d/20-imap.conf",
    "/etc/dovecot/conf.d/20-lmtp.conf",
    "/etc/dovecot/conf.d/20-managesieve.conf",
    "/etc/dovecot/conf.d/20-pop3.conf",
    "/etc/dovecot/conf.d/20-submission.conf",
    "/etc/dovecot/conf.d/90-acl.conf",
    "/etc/dovecot/conf.d/90-plugin.conf",
    "/etc/dovecot/conf.d/90-quota.conf",
    "/etc/dovecot/conf.d/90-sieve-extprograms.conf",
    "/etc/dovecot/conf.d/90-sieve.conf",
    "/etc/dovecot/conf.d/99-bbs-imaps-only.conf",
    "/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf",
    "/etc/dovecot/conf.d/99-rspamd-warning-labels.conf",
    "/etc/dovecot/local.conf",
    "/etc/dovecot/conf.d/auth-sql.conf.ext",
    "/etc/dovecot/conf.d/99-osmap-private-primary.conf",
    "/etc/dovecot/conf.d/99-osmap-private-control.conf",
];
// These production-host policy fragments are absent on the selected development
// host. Absence grants no substitute configuration: the exact conf.d membership
// is still captured and rechecked by StockPeer before each admitted operation.
const STOCK_OPTIONAL_CONFIGURATION_PATHS: &[&str] = &[
    "/etc/dovecot/conf.d/99-bbs-imaps-only.conf",
    "/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf",
];
fn stock_configuration_presence(
    path: &str,
    observed: Result<bool, std::io::ErrorKind>,
) -> Result<bool, Error> {
    match observed {
        Ok(true) => Ok(true),
        Err(std::io::ErrorKind::NotFound) if STOCK_OPTIONAL_CONFIGURATION_PATHS.contains(&path) => {
            Ok(false)
        }
        _ => Err(Error::Unavailable),
    }
}
fn stock_configuration_paths_with(
    deadline: Instant,
    mut present: impl FnMut(&'static str) -> Result<bool, Error>,
) -> Result<Vec<&'static str>, Error> {
    let mut paths = Vec::new();
    for &path in PRIMARY_CONFIGURATION_PATHS {
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        if !matches!(path, PRIMARY_FRAGMENT | CONTROL_FRAGMENT) && present(path)? {
            paths.push(path);
        }
    }
    if Instant::now() >= deadline {
        return Err(Error::Expired);
    }
    Ok(paths)
}
/// Shared pre-seal admission for the stock peer and its actual parent plan.
/// Missing parents, unreadable metadata and symlinks never mean optional absence.
/// Present leaves retain their existing strict file/content/custody checks.
pub(crate) fn stock_configuration_paths(deadline: Instant) -> Result<Vec<&'static str>, Error> {
    stock_configuration_paths_with(deadline, |path| {
        crate::account_password_custody::ancestors(path, None, deadline)
            .map_err(|_| Error::Unavailable)?;
        stock_configuration_presence(
            path,
            fs::symlink_metadata(path)
                .map(|metadata| metadata.is_file())
                .map_err(|error| error.kind()),
        )
    })
}
struct PrimaryFile {
    path: &'static str,
    identity: [u64; 11],
    digest: [u8; 32],
}
fn primary_file(path: &'static str, deadline: Instant) -> Result<PrimaryFile, Error> {
    primary_file_bytes(path, deadline).map(|(pin, _)| pin)
}
// Configuration/SQL/passwd readers retain the existing128KiB ceiling. Only
// these two code-owned executable paths use the existing64MiB binary ceiling.
fn primary_file_limit(path: &str) -> u64 {
    if matches!(path, PRIMARY_AUTH | "/usr/local/bin/doveconf") {
        64 * 1024 * 1024
    } else {
        128 * 1024
    }
}
fn primary_file_bytes(
    path: &'static str,
    deadline: Instant,
) -> Result<(PrimaryFile, Vec<u8>), Error> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    crate::account_password_custody::ancestors(path, None, deadline)
        .map_err(|_| Error::Unavailable)?;
    let metadata = |m: &fs::Metadata| {
        [
            m.dev(),
            m.ino(),
            m.uid().into(),
            m.gid().into(),
            m.mode().into(),
            m.nlink(),
            m.len(),
            m.mtime() as u64,
            m.mtime_nsec() as u64,
            m.ctime() as u64,
            m.ctime_nsec() as u64,
        ]
    };
    let limit = primary_file_limit(path);
    let before = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > limit
        || Instant::now() >= deadline
    {
        return Err(Error::Refused);
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    if metadata(&file.metadata().map_err(|_| Error::Unavailable)?) != metadata(&before) {
        return Err(Error::Refused);
    }
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        let count = file.read(&mut buffer).map_err(|_| Error::Unavailable)?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > limit as usize {
            return Err(Error::Refused);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() as u64 != before.len()
        || metadata(&file.metadata().map_err(|_| Error::Unavailable)?) != metadata(&before)
        || metadata(&fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?)
            != metadata(&before)
        || path == PRIMARY_FRAGMENT
            && <[u8; 32]>::from(Sha256::digest(&bytes)) != PRIMARY_FRAGMENT_SHA256
        || path == CONTROL_FRAGMENT
            && Sha256::digest(&bytes)
                != Sha256::digest(include_bytes!(
                    "../maint/account-runtime/dovecot-private-control.conf"
                ))
    {
        return Err(Error::Refused);
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Ok((
        PrimaryFile {
            path,
            identity: metadata(&before),
            digest,
        },
        bytes,
    ))
}
#[derive(PartialEq, Eq)]
struct PrimarySocketSnapshot {
    binder: (u32, u32, u32),
    listener: u64,
    worker: Row,
    endpoint: [u64; 7],
}
/// Native-only, immutable same-master socket observer. It never supplies a
/// caller-selected UID/path or treats socket chown metadata as kernel identity.
pub(crate) struct PrimaryPeer {
    executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
    startup: Startup,
    auth: FilePin,
    files: Vec<PrimaryFile>,
    server_uid: u32,
    snapshot: PrimarySocketSnapshot,
    selection: MainConfigurationSelection,
}
#[cfg(test)]
fn primary_worker(process: &Row, master: &Row, server_uid: u32) -> Result<(), Error> {
    socket_worker(process, master, server_uid, "auth")
}
fn socket_worker(process: &Row, master: &Row, server_uid: u32, command: &str) -> Result<(), Error> {
    if process.parent != master.pid
        || process.uid != server_uid
        || server_uid == 0
        || process.command != command
        || process.pid == master.pid
    {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
#[cfg(test)]
fn primary_listener(raw: &str, master: &Row, pin: &FilePin) -> Result<u64, Error> {
    socket_listener(raw, master, PRIMARY_SOCKET, pin)
}
fn socket_listener(raw: &str, master: &Row, path: &str, pin: &FilePin) -> Result<u64, Error> {
    descriptors(raw, master, pin)?;
    let mut found = None;
    for line in raw.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.last().copied() != Some(path) {
            continue;
        }
        if fields.len() != 8
            || fields[4..6] != ["unix", "stream"]
            || decimal(fields[3].strip_suffix('*').ok_or(Error::Refused)?)? >= i32::MAX as u32
            || found.is_some()
        {
            return Err(Error::Refused);
        }
        let pcb = u64::from_str_radix(fields[6].strip_prefix("0x").ok_or(Error::Refused)?, 16)
            .map_err(|_| Error::Refused)?;
        if pcb == 0 {
            return Err(Error::Refused);
        }
        found = Some(pcb);
    }
    found.ok_or(Error::Refused)
}
#[allow(dead_code)] // Retained legacy private-primary qualification; stock uses StockPeer.
fn primary_configuration_files(deadline: Instant) -> Result<Vec<PrimaryFile>, Error> {
    let mut files = Vec::with_capacity(PRIMARY_CONFIGURATION_PATHS.len());
    for &path in PRIMARY_CONFIGURATION_PATHS {
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        if path == CONTROL_FRAGMENT {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(Error::Unavailable),
                Ok(_) => {}
            }
        }
        // Present Control receives the same identity/hash checks as every
        // mandatory file. Its absence is never reconsidered as authority.
        files.push(primary_file(path, deadline)?);
    }
    Ok(files)
}
fn captured_control_configuration(files: &[PrimaryFile]) -> Result<(), Error> {
    if files.iter().any(|file| file.path == CONTROL_FRAGMENT) {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}
fn primary_include_names_match(
    found: &BTreeSet<String>,
    files: &[PrimaryFile],
) -> Result<(), Error> {
    let expected = files
        .iter()
        .map(|file| file.path)
        .filter(|path| path.starts_with("/etc/dovecot/conf.d/") && path.ends_with(".conf"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if *found != expected {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
fn primary_include_matches(files: &[PrimaryFile], deadline: Instant) -> Result<(), Error> {
    let mut found = std::collections::BTreeSet::new();
    for (index, entry) in fs::read_dir("/etc/dovecot/conf.d")
        .map_err(|_| Error::Unavailable)?
        .enumerate()
    {
        if index >= 256 || Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        let name = entry
            .map_err(|_| Error::Unavailable)?
            .file_name()
            .into_string()
            .map_err(|_| Error::Refused)?;
        if name.ends_with(".conf") {
            found.insert(format!("/etc/dovecot/conf.d/{name}"));
        }
    }
    primary_include_names_match(&found, files)
}
impl PrimaryPeer {
    #[allow(dead_code)] // Retained legacy private-primary qualification entry.
    pub(crate) fn observe(
        executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
        startup: &Startup,
        deadline: Instant,
        stage: &mut &'static str,
    ) -> Result<Self, Error> {
        *stage = "primary_startup_recheck";
        startup.recheck(executor.as_ref(), deadline)?;
        *stage = "primary_configuration_files";
        let mut files = primary_configuration_files(deadline)?;
        *stage = "primary_include_membership";
        primary_include_matches(&files, deadline)?;
        *stage = "primary_passwd_file";
        let (passwd, bytes) = primary_file_bytes("/etc/passwd", deadline)?;
        *stage = "primary_passwd_shape";
        let records = std::str::from_utf8(&bytes).map_err(|_| Error::Refused)?;
        let matches = records
            .lines()
            .filter(|line| line.starts_with("_dovecot:"))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(Error::Refused);
        }
        let fields = matches[0].split(':').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(Error::Refused);
        }
        *stage = "primary_passwd_continuity";
        let reread = primary_file("/etc/passwd", deadline)?;
        if passwd.identity != reread.identity
            || passwd.digest != reread.digest
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != passwd.digest
        {
            return Err(Error::Refused);
        }
        *stage = "primary_passwd_identity";
        let uid = decimal(fields[2])?;
        if uid == 0
            || records
                .lines()
                .filter(|line| line.split(':').nth(2) == Some(fields[2]))
                .count()
                != 1
        {
            return Err(Error::Refused);
        }
        files.push(passwd);
        *stage = "primary_auth_binary";
        files.push(primary_file(PRIMARY_AUTH, deadline)?);
        let auth = file_pin(PRIMARY_AUTH)?;
        *stage = "primary_main_selection";
        let selection = main_configuration_selection(executor.as_ref(), startup, deadline, stage)?;
        let mut result = Self {
            executor,
            startup: startup.clone(),
            auth,
            files,
            server_uid: uid,
            selection,
            snapshot: PrimarySocketSnapshot {
                binder: (0, 0, 0),
                listener: 0,
                worker: startup.own.clone(),
                endpoint: [0; 7],
            },
        };
        result.snapshot = result.probe_with_stage(deadline, stage)?;
        result.recheck_with_stage(deadline, stage)?;
        Ok(result)
    }
    pub(crate) fn identities(
        &self,
        deadline: Instant,
        stage: &mut &'static str,
    ) -> Result<(u32, u32), Error> {
        self.recheck_with_stage(deadline, stage)?;
        Ok((self.server_uid, self.snapshot.binder.1))
    }
    fn probe_with_stage(
        &self,
        deadline: Instant,
        stage: &mut &'static str,
    ) -> Result<PrimarySocketSnapshot, Error> {
        socket_probe_with_stage(
            self.executor.as_ref(),
            &self.startup,
            &self.auth,
            PRIMARY_SOCKET,
            "auth",
            self.server_uid,
            self.server_uid,
            deadline,
            stage,
        )
    }
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Error> {
        self.recheck_with_stage(deadline, &mut "primary_recheck")
    }
    pub(crate) fn recheck_with_stage(
        &self,
        deadline: Instant,
        stage: &mut &'static str,
    ) -> Result<(), Error> {
        *stage = "primary_recheck_main_selection";
        if main_configuration_selection(self.executor.as_ref(), &self.startup, deadline, stage)?
            != self.selection
        {
            return Err(Error::Refused);
        }
        *stage = "primary_recheck_includes";
        primary_include_matches(&self.files, deadline)?;
        *stage = "primary_recheck_files";
        for old in &self.files {
            let new = primary_file(old.path, deadline)?;
            if old.identity != new.identity || old.digest != new.digest {
                return Err(Error::Refused);
            }
        }
        if {
            let observed = self.probe_with_stage(deadline, stage)?;
            *stage = "primary_recheck_snapshot";
            observed != self.snapshot
        } || {
            *stage = "primary_recheck_main_selection";
            main_configuration_selection(self.executor.as_ref(), &self.startup, deadline, stage)?
                != self.selection
        } {
            return Err(Error::Refused);
        }
        *stage = "primary_final_includes";
        primary_include_matches(&self.files, deadline)
    }
}

const MAIN_CONFIG_LINK: &str = "/var/dovecot/dovecot.conf";
const MAIN_CONFIG: &str = "/etc/dovecot/dovecot.conf";
#[derive(PartialEq, Eq)]
struct MainConfigurationSelection {
    argv: String,
    link: [u64; 11],
}
fn main_master_argv(raw: &str) -> Result<(), Error> {
    let words = raw.split_whitespace().collect::<Vec<_>>();
    if raw.lines().count() != 1
        || !matches!(words.first().copied(), Some("dovecot" | MASTER))
        || !(words.len() == 1 || (words.len() == 3 && words[1..] == ["-c", MAIN_CONFIG]))
    {
        return Err(Error::Refused);
    }
    Ok(())
}
fn main_configuration_selection(
    executor: &(dyn CommandExecutor + Send + Sync),
    startup: &Startup,
    deadline: Instant,
    stage: &mut &'static str,
) -> Result<MainConfigurationSelection, Error> {
    startup.recheck_with_stage(executor, deadline, stage)?;
    main_configuration_selection_bound(executor, &startup.master, deadline, stage)
}
fn main_configuration_selection_bound(
    executor: &(dyn CommandExecutor + Send + Sync),
    master: &Row,
    deadline: Instant,
    stage: &mut &'static str,
) -> Result<MainConfigurationSelection, Error> {
    *stage = "primary_main_argv";
    let argv = query_with_stage(
        executor,
        PS,
        &[
            "-p".into(),
            master.pid.to_string(),
            "-o".into(),
            "args=".into(),
        ],
        deadline,
        stage,
    )?;
    main_master_argv(&argv)?;
    *stage = "primary_main_link_ancestors";
    crate::account_password_custody::ancestors(MAIN_CONFIG_LINK, None, deadline)
        .map_err(|_| Error::Unavailable)?;
    let pin = |m: &fs::Metadata| {
        [
            m.dev(),
            m.ino(),
            u64::from(m.uid()),
            u64::from(m.gid()),
            u64::from(m.mode()),
            m.nlink(),
            m.len(),
            m.mtime() as u64,
            m.mtime_nsec() as u64,
            m.ctime() as u64,
            m.ctime_nsec() as u64,
        ]
    };
    *stage = "primary_main_link_metadata";
    let before = fs::symlink_metadata(MAIN_CONFIG_LINK).map_err(|_| Error::Unavailable)?;
    if !before.file_type().is_symlink()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.len() > 256
        || {
            *stage = "primary_main_link_target";
            fs::read_link(MAIN_CONFIG_LINK).map_err(|_| Error::Unavailable)?
                != Path::new(MAIN_CONFIG)
        }
        || {
            *stage = "primary_main_link_final_metadata";
            pin(&fs::symlink_metadata(MAIN_CONFIG_LINK).map_err(|_| Error::Unavailable)?)
                != pin(&before)
        }
        || Instant::now() >= deadline
    {
        return Err(Error::Refused);
    }
    // Dovecot's own main_init creates this link from the selected full config
    // path. Combined with same-master listener/birth/text and exact argv this
    // binds selection, not proof that current on-disk bytes are loaded.
    Ok(MainConfigurationSelection {
        argv,
        link: pin(&before),
    })
}
fn private_primary_argv(raw: &str) -> Result<(), Error> {
    let fields = raw.split_whitespace().collect::<Vec<_>>();
    if raw.lines().count() != 1
        || fields.len() != 5
        || !matches!(fields[0], "auth" | "dovecot/auth" | PRIMARY_AUTH)
        || fields[1..] != ["-o", "auth_policy_server_url=", "-o", "auth_cache_size=0"]
    {
        return Err(Error::Refused);
    }
    Ok(())
}
// A newly connected private Primary worker can still be starting before it
// drops privileges and accepts this exact FD. Keep that stream held while only
// an empty exact-candidate set settles; ambiguity and observation errors never
// gain a retry. Other socket roles retain their existing one-shot semantics.
fn ready_socket_worker(
    path: &'static str,
    deadline: Instant,
    stage: &mut &'static str,
    mut observe: impl FnMut(Instant, &mut &'static str) -> Result<Vec<Row>, Error>,
) -> Result<Row, Error> {
    let end = if path == PRIMARY_SOCKET {
        deadline.min(Instant::now() + Duration::from_secs(3))
    } else {
        deadline
    };
    loop {
        if Instant::now() >= end {
            return Err(Error::Expired);
        }
        let mut workers = observe(end, stage)?;
        *stage = "primary_probe_unique_worker";
        if workers.len() > 1 {
            return Err(Error::Refused);
        }
        if Instant::now() >= end {
            return Err(Error::Expired);
        }
        if workers.len() == 1 {
            return Ok(workers.remove(0));
        }
        if !matches!(
            path,
            PRIMARY_SOCKET | "/var/dovecot/auth-client" | "/var/dovecot/auth-master"
        ) {
            return Err(Error::Refused);
        }
        let left = end
            .checked_duration_since(Instant::now())
            .ok_or(Error::Expired)?;
        std::thread::sleep(left.min(Duration::from_millis(10)));
    }
}
#[allow(clippy::too_many_arguments)] // Independent fixed process/socket and original-budget witnesses.
fn socket_probe(
    executor: &(dyn CommandExecutor + Send + Sync),
    startup: &Startup,
    auth: &FilePin,
    path: &'static str,
    command: &'static str,
    server_uid: u32,
    owner_uid: u32,
    deadline: Instant,
) -> Result<PrimarySocketSnapshot, Error> {
    socket_probe_with_stage(
        executor,
        startup,
        auth,
        path,
        command,
        server_uid,
        owner_uid,
        deadline,
        &mut "primary_probe",
    )
}
#[allow(clippy::too_many_arguments)] // Same fixed witnesses plus closed diagnostic output.
fn socket_probe_with_stage(
    executor: &(dyn CommandExecutor + Send + Sync),
    startup: &Startup,
    auth: &FilePin,
    path: &'static str,
    command: &'static str,
    server_uid: u32,
    owner_uid: u32,
    deadline: Instant,
    stage: &mut &'static str,
) -> Result<PrimarySocketSnapshot, Error> {
    *stage = "primary_probe_startup";
    startup.recheck(executor, deadline)?;
    *stage = "primary_probe_endpoint";
    let endpoint = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    use std::os::unix::fs::FileTypeExt;
    if !endpoint.file_type().is_socket()
        || endpoint.uid() != owner_uid
        || endpoint.nlink() != 1
        || endpoint.mode() & 0o777
            != if matches!(
                path,
                "/var/dovecot/auth-client" | "/var/dovecot/auth-master"
            ) {
                0o600
            } else {
                0o660
            }
    {
        return Err(Error::Refused);
    }
    let shape = [
        endpoint.dev(),
        endpoint.ino(),
        endpoint.uid().into(),
        endpoint.gid().into(),
        endpoint.mode().into(),
        endpoint.mtime() as u64,
        endpoint.ctime() as u64,
    ];
    *stage = "primary_probe_listener";
    let listener = socket_listener(
        &query(executor, FSTAT, &fstat_args(startup.master.pid), deadline)?,
        &startup.master,
        path,
        startup
            .pins
            .iter()
            .find(|pin| pin.path == MASTER)
            .ok_or(Error::Refused)?,
    )?;
    *stage = "primary_probe_connect";
    let stream = crate::openbsd::connect_unix_before(Path::new(path), deadline)
        .map_err(|_| Error::Unavailable)?;
    *stage = "primary_probe_kernel_peer";
    let binder = kernel(&stream)?;
    *stage = "primary_probe_own_descriptors";
    let own = descriptors(
        &query(executor, FSTAT, &fstat_args(startup.own.pid), deadline)?,
        &startup.own,
        startup
            .pins
            .iter()
            .find(|pin| pin.path == HELPER)
            .ok_or(Error::Refused)?,
    )?;
    let worker = ready_socket_worker(path, deadline, stage, |observation_deadline, stage| {
        *stage = "primary_probe_worker_snapshot";
        let raw = query(
            executor,
            PS,
            &["-ax".into(), "-o".into(), PS_FIELDS.into()],
            observation_deadline,
        )?;
        *stage = "primary_probe_worker_rows";
        let mut workers = Vec::new();
        for (index, line) in raw.lines().enumerate() {
            *stage = "primary_probe_worker_rows";
            if index >= 4096 {
                return Err(Error::Refused);
            }
            let pid = line
                .split_whitespace()
                .next()
                .ok_or(Error::Refused)
                .and_then(decimal)?;
            let candidate = row(line, pid)?;
            if socket_worker(&candidate, &startup.master, server_uid, command).is_err() {
                continue;
            }
            *stage = "primary_probe_worker_descriptors";
            let peer = descriptors(
                &query(executor, FSTAT, &fstat_args(pid), observation_deadline)?,
                &candidate,
                auth,
            )?;
            *stage = "primary_probe_reciprocal_worker";
            if reciprocal(&own, &peer, stream.as_raw_fd()).is_ok() {
                workers.push(candidate);
            }
        }
        Ok(workers)
    })?;
    *stage = "primary_probe_worker_argv";
    if path == PRIMARY_SOCKET {
        private_primary_argv(&query(
            executor,
            PS,
            &[
                "-p".into(),
                worker.pid.to_string(),
                "-o".into(),
                "args=".into(),
            ],
            deadline,
        )?)?;
    }

    if matches!(
        path,
        "/var/dovecot/auth-client" | "/var/dovecot/auth-master"
    ) {
        let args = query(
            executor,
            PS,
            &[
                "-p".into(),
                worker.pid.to_string(),
                "-o".into(),
                "args=".into(),
            ],
            deadline,
        )?;
        let words = args.split_whitespace().collect::<Vec<_>>();
        if args.lines().count() != 1
            || words.len() != 1
            || !matches!(words[0], "auth" | PRIMARY_AUTH)
        {
            return Err(Error::Refused);
        }
    }
    *stage = "primary_probe_process_fd_continuity";
    let expected = if binder.0 == startup.master.pid {
        &startup.master
    } else {
        &worker
    };
    if (expected.pid, expected.uid, expected.gid) != binder
        || file_pin(auth.path)? != *auth
        || row(
            &query(executor, PS, &ps_args(worker.pid), deadline)?,
            worker.pid,
        )? != worker
        || kernel(&stream)? != binder
        || Instant::now() >= deadline
    {
        return Err(Error::Refused);
    }
    *stage = "primary_probe_endpoint_continuity";
    let after = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if [
        after.dev(),
        after.ino(),
        after.uid().into(),
        after.gid().into(),
        after.mode().into(),
        after.mtime() as u64,
        after.ctime() as u64,
    ] != shape
    {
        return Err(Error::Refused);
    }
    Ok(PrimarySocketSnapshot {
        binder,
        listener,
        worker,
        endpoint: shape,
    })
}

/// Source-owned accepting-socket authority for an already-admitted submission
/// registration. The topology module supplies a verified current record; this
/// constructor still measures the actual kernel/descriptor acceptance path.
pub(crate) struct SubmissionIpcPeer {
    executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
    startup: Startup,
    program: FilePin,
    worker: Row,
    captured: PrimarySocketSnapshot,
}
impl SubmissionIpcPeer {
    #[allow(dead_code)]
    pub(crate) fn from_registered(
        executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
        startup: &Startup,
        master_row: &str,
        ipc_row: &str,
        master_pid: u32,
        ipc_pid: u32,
        deadline: Instant,
    ) -> Result<Self, Error> {
        startup.recheck(executor.as_ref(), deadline)?;
        let master = row(master_row, master_pid)?;
        let worker = row(ipc_row, ipc_pid)?;
        if master.parent != 1
            || master.uid != 0
            || master.gid != 0
            || master.command != "dovecot"
            || master.group != master.pid
            || worker.parent != master.pid
            || worker.command != "ipc"
            || worker.uid == 0
        {
            return Err(Error::Refused);
        }
        let mut context = startup.clone();
        context.master = master;
        let program = file_pin("/usr/local/libexec/dovecot/ipc")?;
        let captured = socket_probe(
            executor.as_ref(),
            &context,
            &program,
            crate::account_password_topology::IPC,
            "ipc",
            worker.uid,
            0,
            deadline,
        )?;
        if captured.worker != worker {
            return Err(Error::Refused);
        }
        Ok(Self {
            executor,
            startup: context,
            program,
            worker,
            captured,
        })
    }
    pub(crate) fn binder_uid(&self, deadline: Instant) -> Result<u32, Error> {
        let now = socket_probe(
            self.executor.as_ref(),
            &self.startup,
            &self.program,
            crate::account_password_topology::IPC,
            "ipc",
            self.worker.uid,
            0,
            deadline,
        )?;
        if now != self.captured {
            return Err(Error::Refused);
        }
        Ok(now.binder.1)
    }
}
/// All three control endpoints are measured independently: anvil/auth belong
/// to the original mail master, IPC to the already-qualified submission master.
pub(crate) struct ControlPeer {
    primary: std::sync::Arc<PrimaryPeer>,
    auth: PrimarySocketSnapshot,
    anvil: PrimarySocketSnapshot,
    anvil_program: FilePin,
    ipc: crate::account_password_topology::RegisteredIpcPeer,
}
impl ControlPeer {
    #[allow(dead_code)]
    pub(crate) fn observe(
        primary: std::sync::Arc<PrimaryPeer>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        primary.recheck(deadline)?;
        captured_control_configuration(&primary.files)?;
        let auth = socket_probe(
            primary.executor.as_ref(),
            &primary.startup,
            &primary.auth,
            "/var/dovecot/osmap-account-auth-master",
            "auth",
            primary.server_uid,
            0,
            deadline,
        )?;
        let anvil_program = file_pin("/usr/local/libexec/dovecot/anvil")?;
        let anvil = socket_probe(
            primary.executor.as_ref(),
            &primary.startup,
            &anvil_program,
            "/var/dovecot/osmap-account-anvil",
            "anvil",
            primary.server_uid,
            0,
            deadline,
        )?;
        let ipc = crate::account_password_topology::RegisteredIpcPeer::observe(
            primary.executor.clone(),
            &primary.startup,
            deadline,
        )
        .map_err(|_| Error::Refused)?;
        let result = Self {
            primary,
            auth,
            anvil,
            anvil_program,
            ipc,
        };
        result.identities(deadline)?;
        Ok(result)
    }
    pub(crate) fn identities(&self, deadline: Instant) -> Result<[u32; 3], Error> {
        self.primary.recheck(deadline)?;
        captured_control_configuration(&self.primary.files)?;
        let auth = socket_probe(
            self.primary.executor.as_ref(),
            &self.primary.startup,
            &self.primary.auth,
            "/var/dovecot/osmap-account-auth-master",
            "auth",
            self.primary.server_uid,
            0,
            deadline,
        )?;
        let anvil = socket_probe(
            self.primary.executor.as_ref(),
            &self.primary.startup,
            &self.anvil_program,
            "/var/dovecot/osmap-account-anvil",
            "anvil",
            self.primary.server_uid,
            0,
            deadline,
        )?;
        if auth != self.auth
            || anvil != self.anvil
            || file_pin(self.anvil_program.path)? != self.anvil_program
        {
            return Err(Error::Refused);
        }
        Ok([
            auth.binder.1,
            anvil.binder.1,
            self.ipc.binder_uid(deadline).map_err(|_| Error::Refused)?,
        ])
    }
}

#[cfg(test)]
#[path = "account_password_peer_tests.rs"]
mod tests;

/// Stock-only process/material anchors. These never attest a legacy text or
/// descriptor graph and cannot enter the legacy Startup constructors.
struct StockStartup {
    master: Row,
    own: Row,
    pins: Vec<FilePin>,
}
impl StockStartup {
    fn observe(
        executor: &(dyn CommandExecutor + Send + Sync),
        deadline: Instant,
        trace: &mut crate::account_password_fstat::StartupTrace,
    ) -> Result<Self, Error> {
        if !crate::openbsd::password_native_authority() || Instant::now() >= deadline {
            return Err(Error::Refused);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockMasterPid);
        let master_pid = stock_master_pid(deadline)?;
        let own_pid = std::process::id();
        trace.set(crate::account_password_fstat::StartupOperation::StockMasterRow);
        let master = row(
            &stock_query(executor, PS, &ps_args(master_pid), deadline, trace)?,
            master_pid,
        )?;
        trace.set(crate::account_password_fstat::StartupOperation::StockHelperRow);
        let own = row(
            &stock_query(executor, PS, &ps_args(own_pid), deadline, trace)?,
            own_pid,
        )?;
        trace.set(crate::account_password_fstat::StartupOperation::StockRoles);
        if master.parent != 1
            || master.pid != master.group
            || master.uid != 0
            || master.gid != 0
            || master.command != "dovecot"
            || own.uid != 0
            || own.gid != 0
            || own.group != own.pid
            || own.command != "account-passwd"
            || own.pid == master.pid
        {
            return Err(Error::Refused);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockProgramPins);
        let pins = [PS, MASTER, HELPER]
            .into_iter()
            .map(file_pin)
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self { master, own, pins };
        value.recheck(executor, deadline, trace)?;
        Ok(value)
    }
    fn recheck(
        &self,
        executor: &(dyn CommandExecutor + Send + Sync),
        deadline: Instant,
        trace: &mut crate::account_password_fstat::StartupTrace,
    ) -> Result<(), Error> {
        use crate::account_password_fstat::{StartupCategory as Cat, StartupOperation as Op};
        trace.set(Op::BeforeRecheck);
        if Instant::now() >= deadline {
            trace.category(Cat::Deadline);
            return Err(Error::Refused);
        }
        if !crate::openbsd::password_native_authority() || std::process::id() != self.own.pid {
            trace.category(Cat::Invalid);
            return Err(Error::Refused);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockProgramPins);
        for pin in &self.pins {
            if file_pin(pin.path)? != *pin {
                trace.category(Cat::Invalid);
                return Err(Error::Refused);
            }
        }
        for expected in [&self.master, &self.own] {
            trace.set(if expected.pid == self.master.pid {
                crate::account_password_fstat::StartupOperation::StockMasterRow
            } else {
                crate::account_password_fstat::StartupOperation::StockHelperRow
            });
            if row(
                &stock_query(executor, PS, &ps_args(expected.pid), deadline, trace)?,
                expected.pid,
            )? != *expected
            {
                trace.category(Cat::Invalid);
                return Err(Error::Refused);
            }
        }
        if Instant::now() >= deadline {
            trace.category(Cat::Deadline);
            return Err(Error::Expired);
        }
        Ok(())
    }
}
fn stock_query<E: CommandExecutor + ?Sized>(
    executor: &E,
    program: &str,
    args: &[String],
    deadline: Instant,
    trace: &mut crate::account_password_fstat::StartupTrace,
) -> Result<String, Error> {
    let mut site = "stock_metadata_query";
    query_with_stage(executor, program, args, deadline, &mut site).inspect_err(|_| {
        trace.metadata(site);
    })
}
#[derive(PartialEq, Eq)]
struct StockSocketSnapshot {
    endpoint: [u64; 11],
    binder: (u32, u32, u32),
    worker: Row,
    argv: String,
}
fn stock_auth_argv(raw: &str) -> Result<(), Error> {
    let words = raw.split_whitespace().collect::<Vec<_>>();
    if raw.lines().count() != 1
        || words.len() != 1
        || !matches!(words[0], "auth" | "dovecot/auth" | PRIMARY_AUTH)
    {
        return Err(Error::Refused);
    }
    Ok(())
}
fn stock_auth_role(worker: &Row, master: &Row, uid: u32, gid: u32) -> Result<(), Error> {
    socket_worker(worker, master, uid, "auth")?;
    if gid == 0 || worker.gid != gid {
        return Err(Error::Refused);
    }
    Ok(())
}
fn stock_socket_probe(
    executor: &(dyn CommandExecutor + Send + Sync),
    startup: &StockStartup,
    auth: &FilePin,
    uid: u32,
    gid: u32,
    deadline: Instant,
    trace: &mut crate::account_password_fstat::StartupTrace,
) -> Result<StockSocketSnapshot, Error> {
    let path = crate::account_password_mail::STOCK_AUTH;
    startup.recheck(executor, deadline, trace)?;
    trace.set(crate::account_password_fstat::StartupOperation::StockAuthPin);
    if file_pin(auth.path)? != *auth {
        return Err(Error::Refused);
    }
    trace.set(crate::account_password_fstat::StartupOperation::StockSocketMetadata);
    crate::account_password_custody::ancestors(path, None, deadline)
        .map_err(|_| Error::Unavailable)?;
    let identity = |m: &fs::Metadata| {
        [
            m.dev(),
            m.ino(),
            m.uid().into(),
            m.gid().into(),
            m.mode().into(),
            m.nlink(),
            m.len(),
            m.mtime() as u64,
            m.mtime_nsec() as u64,
            m.ctime() as u64,
            m.ctime_nsec() as u64,
        ]
    };
    let before = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&before.file_type())
        || before.uid() != uid
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
    {
        return Err(Error::Refused);
    }
    // The same held real connection supplies kernel authority throughout this
    // observation. File ownership is distinct from the root listener binder.
    trace.set(crate::account_password_fstat::StartupOperation::StockSocketConnect);
    let stream = crate::openbsd::connect_unix_before(Path::new(path), deadline)
        .map_err(|_| Error::Unavailable)?;
    trace.set(crate::account_password_fstat::StartupOperation::StockSocketPeer);
    let binder = kernel(&stream)?;
    if binder.1 != 0 || binder.2 != 0 {
        return Err(Error::Refused);
    }
    let mut selected_argv = String::new();
    let worker = ready_socket_worker(path, deadline, &mut "stock_auth_worker", |end, _| {
        trace.set(crate::account_password_fstat::StartupOperation::StockWorkerRows);
        let raw = stock_query(
            executor,
            PS,
            &["-ax".into(), "-o".into(), PS_FIELDS.into()],
            end,
            trace,
        )?;
        let mut matches = Vec::new();
        for (index, line) in raw.lines().enumerate() {
            if index >= 4096 {
                return Err(Error::Refused);
            }
            let pid = decimal(line.split_whitespace().next().ok_or(Error::Refused)?)?;
            let candidate = row(line, pid)?;
            if stock_auth_role(&candidate, &startup.master, uid, gid).is_err() {
                continue;
            }
            trace.set(crate::account_password_fstat::StartupOperation::StockWorkerArgv);
            let argv = stock_query(
                executor,
                PS,
                &["-p".into(), pid.to_string(), "-o".into(), "args=".into()],
                end,
                trace,
            )?;
            stock_auth_argv(&argv)?;
            trace.set(crate::account_password_fstat::StartupOperation::StockWorkerBirth);
            if row(&stock_query(executor, PS, &ps_args(pid), end, trace)?, pid)? != candidate {
                return Err(Error::Refused);
            }
            selected_argv = argv;
            matches.push(candidate);
        }
        Ok(matches)
    })?;
    startup.recheck(executor, deadline, trace)?;
    trace.set(crate::account_password_fstat::StartupOperation::StockSocketContinuity);
    if identity(&fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?) != identity(&before)
        || kernel(&stream)? != binder
        || file_pin(auth.path)? != *auth
        || Instant::now() >= deadline
    {
        return Err(Error::Refused);
    }
    Ok(StockSocketSnapshot {
        endpoint: identity(&before),
        binder,
        worker,
        argv: selected_argv,
    })
}
/// Stock Dovecot authority: same live master, protected existing configuration,
/// and actual kernel peer/process observations. No public configuration
/// is written and no private listener, policy callback or Generation is used.
pub(crate) struct StockPeer {
    executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
    startup: StockStartup,
    auth: FilePin,
    files: Vec<PrimaryFile>,
    server_uid: u32,
    selection: MainConfigurationSelection,
    auth_snapshot: StockSocketSnapshot,
    server_gid: u32,
}
pub(crate) fn stock_master_pid(deadline: Instant) -> Result<u32, Error> {
    let (_, bytes) = primary_file_bytes("/var/dovecot/master.pid", deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Refused)?;
    let pid = decimal(text.strip_suffix('\n').ok_or(Error::Refused)?)?;
    if pid <= 1 || pid >= i32::MAX as u32 {
        return Err(Error::Refused);
    }
    Ok(pid)
}
// Keep the configuration closure explicit. No include outside the admitted
// files may influence a later authentication operation without being rechecked.
fn stock_configuration_includes(path: &str, raw: &[u8]) -> Result<(), Error> {
    let text = std::str::from_utf8(raw).map_err(|_| Error::Refused)?;
    if text.contains('\0') {
        return Err(Error::Refused);
    }
    for line in text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
    {
        if !line.starts_with('!') {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || !matches!(fields[0], "!include" | "!include_try") {
            return Err(Error::Refused);
        }
        let target = fields[1];
        let resolved = if target.starts_with('/') {
            std::path::PathBuf::from(target)
        } else {
            Path::new(path).parent().ok_or(Error::Refused)?.join(target)
        };
        if resolved.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(Error::Refused);
        }
        let resolved = resolved.to_str().ok_or(Error::Refused)?;
        if resolved == "/etc/dovecot/conf.d/*.conf" {
            continue;
        }
        if !PRIMARY_CONFIGURATION_PATHS.contains(&resolved)
            || matches!(resolved, PRIMARY_FRAGMENT | CONTROL_FRAGMENT)
        {
            return Err(Error::Refused);
        }
    }
    Ok(())
}
impl StockPeer {
    pub(crate) fn observe(
        executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
        deadline: Instant,
        trace: &mut crate::account_password_fstat::StartupTrace,
    ) -> Result<Self, Error> {
        let startup = StockStartup::observe(executor.as_ref(), deadline, trace)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockConfigFiles);
        let mut files = Vec::new();
        for path in stock_configuration_paths(deadline)? {
            let (file, bytes) = primary_file_bytes(path, deadline)?;
            stock_configuration_includes(path, &bytes)?;
            files.push(file);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockConfigIncludes);
        primary_include_matches(&files, deadline)?;
        // Protected current configuration and its closed include set replace
        // historical whole-file hashes. Validate the effective sole SQL passdb
        // as well as its source before admitting the writer.
        trace.set(crate::account_password_fstat::StartupOperation::StockPassdb);
        let (_, passdb) = primary_file_bytes("/etc/dovecot/conf.d/auth-sql.conf.ext", deadline)?;
        stock_sql::passdb(&passdb).map_err(|_| Error::Refused)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockSql);
        let (sql, sql_bytes) = primary_file_bytes("/etc/dovecot/dovecot-sql.conf.ext", deadline)?;
        stock_sql::validate(&sql_bytes).map_err(|_| Error::Refused)?;
        files.push(sql);
        trace.set(crate::account_password_fstat::StartupOperation::StockRuntimeFiles);
        for path in ["/var/dovecot/master.pid", PRIMARY_AUTH] {
            files.push(primary_file(path, deadline)?);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockPasswd);
        let (passwd, bytes) = primary_file_bytes("/etc/passwd", deadline)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::Refused)?;
        let selected = text
            .lines()
            .filter(|line| line.starts_with("_dovecot:"))
            .collect::<Vec<_>>();
        if selected.len() != 1 {
            return Err(Error::Refused);
        }
        let fields = selected[0].split(':').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(Error::Refused);
        }
        let uid = decimal(fields[2])?;
        let gid = decimal(fields[3])?;
        if gid == 0 || gid >= i32::MAX as u32 {
            return Err(Error::Refused);
        }
        if uid == 0
            || text
                .lines()
                .filter(|line| line.split(':').nth(2) == Some(fields[2]))
                .count()
                != 1
        {
            return Err(Error::Refused);
        }
        files.push(passwd);
        trace.set(crate::account_password_fstat::StartupOperation::StockAuthPin);
        let auth = file_pin(PRIMARY_AUTH)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockMainSelection);
        let selection = main_configuration_selection_bound(
            executor.as_ref(),
            &startup.master,
            deadline,
            &mut "primary_main_selection",
        )?;
        let auth_snapshot = stock_socket_probe(
            executor.as_ref(),
            &startup,
            &auth,
            uid,
            gid,
            deadline,
            trace,
        )?;
        // Fixed current read-only configuration observation, before the parent
        // is sealed. No cache is enabled/populated and no fabricated flush occurs.
        trace.set(crate::account_password_fstat::StartupOperation::StockCachePin);
        let doveconf = primary_file("/usr/local/bin/doveconf", deadline)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockCacheQuery);
        if stock_query(
            executor.as_ref(),
            "/usr/local/bin/doveconf",
            &[
                "-c".into(),
                "/etc/dovecot/dovecot.conf".into(),
                "-h".into(),
                "auth_cache_size".into(),
            ],
            deadline,
            trace,
        )? != "0\n"
        {
            return Err(Error::Refused);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockCachePin);
        let after = primary_file("/usr/local/bin/doveconf", deadline)?;
        if doveconf.identity != after.identity || doveconf.digest != after.digest {
            return Err(Error::Refused);
        }
        // Effective settings catch additional passdb declarations in any admitted
        // fragment. Output is held only in RAM and never emitted as evidence.
        trace.set(crate::account_password_fstat::StartupOperation::StockCacheQuery);
        let effective = stock_query(
            executor.as_ref(),
            "/usr/local/bin/doveconf",
            &["-c".into(), "/etc/dovecot/dovecot.conf".into(), "-n".into()],
            deadline,
            trace,
        )?;
        stock_sql::passdb(effective.as_bytes()).map_err(|_| Error::Refused)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockCacheQuery);
        let username_format = stock_query(
            executor.as_ref(),
            "/usr/local/bin/doveconf",
            &[
                "-c".into(),
                "/etc/dovecot/dovecot.conf".into(),
                "-h".into(),
                "auth_username_format".into(),
            ],
            deadline,
            trace,
        )?;
        if !matches!(username_format.trim(), "%u" | "%Lu") {
            return Err(Error::Refused);
        }
        files.push(doveconf);
        let value = Self {
            executor,
            startup,
            auth,
            files,
            server_uid: uid,
            selection,
            auth_snapshot,
            server_gid: gid,
        };
        value.recheck_with_trace(deadline, trace)?;
        Ok(value)
    }
    pub(crate) fn master_pid(&self) -> u32 {
        self.startup.master.pid
    }
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Error> {
        let mut trace = crate::account_password_fstat::StartupTrace::new(
            crate::account_password_fstat::StartupOperation::StockRecheckSnapshot,
        );
        self.recheck_with_trace(deadline, &mut trace)
    }
    pub(crate) fn recheck_with_trace(
        &self,
        deadline: Instant,
        trace: &mut crate::account_password_fstat::StartupTrace,
    ) -> Result<(), Error> {
        // Startup supplies the outer trace; do not discard a nested failure or
        // overwrite a more precise command/I/O category with the generic error.
        self.recheck_observed(deadline, trace).inspect_err(|error| {
            use crate::account_password_fstat::StartupCategory as Cat;
            trace.category_if_unknown(match error {
                Error::Expired => Cat::Deadline,
                // Legacy Refused also covers combined deadline predicates;
                // only the actual rejected check can identify an invariant.
                Error::Refused | Error::Unavailable => Cat::Unknown,
            });
        })
    }
    fn recheck_observed(
        &self,
        deadline: Instant,
        trace: &mut crate::account_password_fstat::StartupTrace,
    ) -> Result<(), Error> {
        self.startup
            .recheck(self.executor.as_ref(), deadline, trace)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockMainSelection);
        let mut selection_stage = "primary_main_selection";
        if main_configuration_selection_bound(
            self.executor.as_ref(),
            &self.startup.master,
            deadline,
            &mut selection_stage,
        )
        .inspect_err(|_| trace.metadata(selection_stage))?
            != self.selection
        {
            trace.category(crate::account_password_fstat::StartupCategory::Invalid);
            return Err(Error::Refused);
        }
        trace.set(crate::account_password_fstat::StartupOperation::StockConfigIncludes);
        primary_include_matches(&self.files, deadline)?;
        trace.set(crate::account_password_fstat::StartupOperation::StockRecheckFiles);
        for old in &self.files {
            let new = primary_file(old.path, deadline)?;
            if old.identity != new.identity || old.digest != new.digest {
                trace.category(crate::account_password_fstat::StartupCategory::Invalid);
                return Err(Error::Refused);
            }
        }
        let observed = stock_socket_probe(
            self.executor.as_ref(),
            &self.startup,
            &self.auth,
            self.server_uid,
            self.server_gid,
            deadline,
            trace,
        )?;
        trace.set(crate::account_password_fstat::StartupOperation::StockRecheckSnapshot);
        if observed != self.auth_snapshot {
            trace.category(crate::account_password_fstat::StartupCategory::Invalid);
            return Err(Error::Refused);
        }
        Ok(())
    }
    pub(crate) fn stock_ids(&self, deadline: Instant) -> Result<(u32, u32, u32), Error> {
        self.recheck(deadline)?;
        Ok((
            self.server_uid,
            self.server_gid,
            self.auth_snapshot.binder.1,
        ))
    }
}

// Exact reviewed existing SQL-metadata functions retained from composed23.
// Only the public false branch is callable. Original configuration bytes stay
// unchanged and credential fields never leave this bounded private reader.
mod stock_sql {
    use std::collections::{BTreeMap, BTreeSet};
    const LIMIT: usize = 16384;
    const MYSQL_SOCKET: &str = "/var/run/mysql/mysql.sock";
    #[derive(Debug)]
    pub(super) struct Unavailable;
    pub(super) fn validate(raw: &[u8]) -> Result<(), Unavailable> {
        sql_password_source(raw, false)
    }
    fn key_values(raw: &[u8]) -> Result<BTreeMap<String, String>, Unavailable> {
        if raw.len() > LIMIT || !raw.is_ascii() || raw.contains(&0) || raw.contains(&b'\r') {
            return Err(Unavailable);
        }
        let mut fields = BTreeMap::new();
        let mut logical = String::new();
        let mut continuing = false;
        for line in std::str::from_utf8(raw)
            .map_err(|_| Unavailable)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let part = line.strip_suffix('\\');
            if !logical.is_empty() {
                logical.push(' ');
            }
            logical.push_str(part.unwrap_or(line).trim_end());
            if logical.len() > LIMIT {
                return Err(Unavailable);
            }
            continuing = part.is_some();
            if continuing {
                continue;
            }
            let (k, v) = logical.split_once('=').ok_or(Unavailable)?;
            let key = k.trim();
            let value = v.trim();
            let value = if let Some(quote @ (b'\'' | b'"')) = value.as_bytes().first().copied() {
                if value.len() < 2 || value.as_bytes().last() != Some(&quote) {
                    return Err(Unavailable);
                }
                let inner = &value[1..value.len() - 1];
                // Admit only the observed simple whole-value envelope. General
                // escape/environment expansion remains outside this fixed model.
                if inner
                    .bytes()
                    .any(|b| b == quote || b == b'\\' || !(0x20..=0x7e).contains(&b))
                {
                    return Err(Unavailable);
                }
                inner
            } else {
                value
            };
            if key.is_empty()
                || !key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                || fields.insert(key.to_string(), value.to_string()).is_some()
            {
                return Err(Unavailable);
            }
            logical.clear();
        }
        if continuing {
            return Err(Unavailable);
        }
        Ok(fields)
    }

    /// Parse only bounded native mysql connection assignments in RAM. Credentials
    /// are never returned, logged or used to make an extra connection.
    fn mysql_route(connect: &str, frontend: bool) -> Result<(), Unavailable> {
        if connect.is_empty()
            || connect.contains('\\')
            || connect.len() > 4096
            || !connect.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(Unavailable);
        }
        // The maintained Dovecot mysql driver splits literal spaces and the first
        // equals sign. Per-field shell quotes are literal bytes, never decoded.
        let mut fields = BTreeMap::new();
        for token in connect.split(' ').filter(|value| !value.is_empty()) {
            let (key, value) = token.split_once('=').ok_or(Unavailable)?;
            if fields.insert(key, value).is_some() {
                return Err(Unavailable);
            }
        }
        let host = fields.get("host").copied();
        // Public localhost is the observed existing passdb route qualified by the
        // matching same-master C04 nonce admission. It never authorizes a remote
        // route or an implicit dedicated submission endpoint. Dedicated SQL uses
        // the explicit fixed socket and the separate restricted mutation role.
        if fields.len() != 4
            || (host != Some(MYSQL_SOCKET) && (frontend || host != Some("localhost")))
            || fields.get("dbname").copied() != Some("postfixadmin")
            || !fields
                .get("user")
                .is_some_and(|v| !v.is_empty() && v.len() <= 64)
            || !fields
                .get("password")
                .is_some_and(|v| !v.is_empty() && v.len() <= 256)
            || fields
                .keys()
                .any(|k| !matches!(*k, "host" | "dbname" | "user" | "password"))
        {
            return Err(Unavailable);
        }
        Ok(())
    }

    fn sql_password_source(raw: &[u8], frontend: bool) -> Result<(), Unavailable> {
        let fields = key_values(raw)?;
        if fields.get("driver").map(String::as_str) != Some("mysql")
            || fields.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "driver"
                        | "connect"
                        | "password_query"
                        | "user_query"
                        | "iterate_query"
                        | "default_pass_scheme"
                )
            })
        {
            return Err(Unavailable);
        }
        mysql_route(fields.get("connect").ok_or(Unavailable)?, frontend)?;
        let query = fields
            .get("password_query")
            .ok_or(Unavailable)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if frontend {
        // Compare with the existing OSMAP-owned deployment policy, rather than
        // duplicating or constructing SQL in this metadata-only reader.
        let expected = include_str!("../maint/account-runtime/submission/dovecot-sql.conf.ext.in")
            .lines()
            .find_map(|line| line.strip_prefix("password_query = "))
            .ok_or(Unavailable)?;
        if query != expected {
            return Err(Unavailable);
        }
    } else if ![
        "select password from mailbox where username = '%u' and active = 1",
        "select password from mailbox where username = '%u' and active = '1'",
        "select username as user, password from mailbox where username = '%u' and active = 1",
        "select username as user, password from mailbox where username = '%u' and active = '1'",
        "select password, 'after' as osmap_epoch_phase from mailbox where username = '%u' and active = 1",
        "select password, 'after' as osmap_epoch_phase from mailbox where username = '%u' and active = '1'",
        "select username as user, password, 'after' as osmap_epoch_phase from mailbox where username = '%u' and active = 1",
        "select username as user, password, 'after' as osmap_epoch_phase from mailbox where username = '%u' and active = '1'",
    ]
    .contains(&query.to_ascii_lowercase().as_str())
        || (!frontend && query.to_ascii_lowercase().contains("osmap_epoch_phase")
            && !query.contains("'after'"))
    {
        return Err(Unavailable);
    }
        Ok(())
    }
    const BACKEND_SQL: &str = "/etc/dovecot/dovecot-sql.conf.ext";
    pub(super) fn passdb(raw: &[u8]) -> Result<(), Unavailable> {
        if raw.len() > LIMIT || !raw.is_ascii() || raw.contains(&0) || raw.contains(&b'\r') {
            return Err(Unavailable);
        }
        passdb_source(
            std::str::from_utf8(raw).map_err(|_| Unavailable)?,
            BACKEND_SQL,
        )
        .map(|_| ())
    }
    fn passdb_source(effective: &str, sql_source: &'static str) -> Result<bool, Unavailable> {
        let mut stack = Vec::new();
        let mut db = None;
        let mut count = 0;
        let mut lowercases = false;
        for line in effective
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Some(head) = line.strip_suffix('{') {
                if stack.len() >= 8 {
                    return Err(Unavailable);
                }
                stack.push(head.trim());
                if head.trim() == "passdb" && stack != ["passdb"] {
                    return Err(Unavailable);
                }
                if stack == ["passdb"] {
                    db = Some(BTreeMap::new());
                    count += 1;
                }
            } else if line == "}" {
                if stack.pop().is_none() {
                    return Err(Unavailable);
                }
            } else {
                let (key, value) = line.split_once('=').ok_or(Unavailable)?;
                if (key.trim() == "auth_cache_size" && value.trim() != "0")
                    || (key.trim() == "auth_master_user_separator" && !value.trim().is_empty())
                {
                    return Err(Unavailable);
                }
                if key.trim() == "auth_username_format" {
                    lowercases |= username_mapping(value.trim(), "", sql_source == BACKEND_SQL)?;
                }
                if key.trim() == "auth_username_translation" && !value.trim().is_empty() {
                    return Err(Unavailable);
                }
                if key.trim() == "auth_mechanisms" {
                    let methods = value.split_whitespace().collect::<BTreeSet<_>>();
                    if methods.is_empty()
                        || methods
                            .iter()
                            .any(|method| !matches!(*method, "plain" | "login"))
                    {
                        return Err(Unavailable);
                    }
                }
                if stack == ["passdb"] {
                    let key = key.trim();
                    let value = value.trim();
                    if !matches!(key, "driver" | "args")
                        || db.as_mut().ok_or(Unavailable)?.insert(key, value).is_some()
                    {
                        return Err(Unavailable);
                    }
                }
            }
        }
        let db = db.ok_or(Unavailable)?;
        if !stack.is_empty()
            || count != 1
            || db.len() != 2
            || db.get("driver") != Some(&"sql")
            || db.get("args") != Some(&sql_source)
        {
            return Err(Unavailable);
        }
        Ok(lowercases)
    }

    fn username_mapping(
        format: &str,
        translation: &str,
        backend: bool,
    ) -> Result<bool, Unavailable> {
        if !translation.trim().is_empty() {
            return Err(Unavailable);
        }
        match format.trim() {
            "%u" => Ok(false),
            "%Lu" if backend => Ok(true),
            _ => Err(Unavailable),
        }
    }
}

#[cfg(test)]
mod stock_authority_tests {
    use super::*;
    #[cfg(target_os = "openbsd")]
    #[test]
    #[ignore = "operator-run root-only read-only current Dovecot configuration admission"]
    fn installed_configuration_admits_required_authentication_semantics() {
        assert!(crate::openbsd::password_native_authority());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut files = Vec::new();
        for &path in PRIMARY_CONFIGURATION_PATHS {
            if matches!(path, PRIMARY_FRAGMENT | CONTROL_FRAGMENT) {
                continue;
            }
            let (file, bytes) =
                primary_file_bytes(path, deadline).expect("protected current configuration");
            stock_configuration_includes(path, &bytes)
                .expect("bounded configuration include closure");
            files.push(file);
        }
        primary_include_matches(&files, deadline).expect("current include membership");
        let (_, sql) = primary_file_bytes("/etc/dovecot/dovecot-sql.conf.ext", deadline)
            .expect("protected SQL configuration");
        stock_sql::validate(&sql).expect("required SQL password source");
        let executor = crate::auth::SystemCommandExecutor;
        let effective = query(
            &executor,
            "/usr/local/bin/doveconf",
            &["-c".into(), "/etc/dovecot/dovecot.conf".into(), "-n".into()],
            deadline,
        )
        .expect("effective configuration query");
        stock_sql::passdb(effective.as_bytes()).expect("effective sole SQL passdb");
        let cache = query(
            &executor,
            "/usr/local/bin/doveconf",
            &[
                "-c".into(),
                "/etc/dovecot/dovecot.conf".into(),
                "-h".into(),
                "auth_cache_size".into(),
            ],
            deadline,
        )
        .expect("cache query");
        assert_eq!(cache, "0\n");
        for old in files {
            let now = primary_file(old.path, deadline).expect("configuration recheck");
            assert!(old.identity == now.identity && old.digest == now.digest);
        }
        eprintln!("DEPENDENCY_CONFIGURATION_ADMISSION=PASS");
    }

    #[test]
    fn current_configuration_accepts_formatting_but_rejects_external_includes() {
        assert!(stock_configuration_includes(
            "/etc/dovecot/dovecot.conf",
            b"# changed comment\n  !include conf.d/*.conf # comment\n!include_try local.conf\n"
        )
        .is_ok());
        assert!(stock_configuration_includes(
            "/etc/dovecot/conf.d/10-auth.conf",
            b"!include auth-sql.conf.ext\n"
        )
        .is_ok());
        for raw in [
            b"!include /tmp/passdb.conf\n".as_slice(),
            b"!include ../outside.conf\n",
            b"!include conf.d/*\n",
        ] {
            assert!(stock_configuration_includes("/etc/dovecot/dovecot.conf", raw).is_err());
        }
    }
    #[test]
    fn effective_passdb_rejects_extra_or_changed_authentication_routes() {
        let good = b"# formatting changes are harmless\npassdb {\n driver = sql\n args = /etc/dovecot/dovecot-sql.conf.ext\n}\n";
        assert!(stock_sql::passdb(good).is_ok());
        let mut duplicate = good.to_vec();
        duplicate.extend_from_slice(good);
        assert!(stock_sql::passdb(&duplicate).is_err());
        assert!(stock_sql::passdb(
            &String::from_utf8_lossy(good)
                .replace("driver = sql", "driver = pam")
                .into_bytes()
        )
        .is_err());
        assert!(stock_sql::passdb(
            &String::from_utf8_lossy(good)
                .replace("/etc/dovecot/dovecot-sql.conf.ext", "/tmp/passdb")
                .into_bytes()
        )
        .is_err());
    }

    #[test]
    fn fixed_doveconf_binary_bound_preserves_configuration_ceiling() {
        // A fixed executable larger than128KiB must reach the actual cache
        // query; changing its reader bound cannot enlarge any config reader.
        let above_configuration_limit = 128 * 1024 + 1;
        assert!(above_configuration_limit <= primary_file_limit("/usr/local/bin/doveconf"));
        assert_eq!(primary_file_limit(PRIMARY_AUTH), 64 * 1024 * 1024);
        assert_eq!(
            primary_file_limit("/usr/local/bin/doveconf"),
            64 * 1024 * 1024
        );
        for path in [
            "/etc/dovecot/dovecot.conf",
            "/etc/dovecot/dovecot-sql.conf.ext",
            "/etc/passwd",
            "/usr/local/bin/other",
        ] {
            assert_eq!(primary_file_limit(path), 128 * 1024);
            assert!(above_configuration_limit > primary_file_limit(path));
        }
        assert!(64 * 1024 * 1024 + 1 > primary_file_limit("/usr/local/bin/doveconf"));
    }

    #[test]
    fn stock_auth_requires_same_master_nonroot_role_and_no_overrides() {
        let master = Row {
            pid: 42,
            parent: 1,
            group: 42,
            uid: 0,
            gid: 0,
            birth: "Mon Oct 19 01:02:03 2026".into(),
            command: "dovecot".into(),
        };
        let worker = Row {
            pid: 43,
            parent: 42,
            group: 42,
            uid: 518,
            gid: 518,
            birth: "Mon Oct 19 01:02:03 2026".into(),
            command: "auth".into(),
        };
        assert_eq!(stock_auth_role(&worker, &master, 518, 518), Ok(()));
        for wrong in [
            Row {
                parent: 1,
                ..worker.clone()
            },
            Row {
                uid: 0,
                ..worker.clone()
            },
            Row {
                gid: 0,
                ..worker.clone()
            },
            Row {
                command: "imap".into(),
                ..worker.clone()
            },
        ] {
            assert!(stock_auth_role(&wrong, &master, 518, 518).is_err());
        }
        for good in [
            "auth\n",
            "dovecot/auth\n",
            "/usr/local/libexec/dovecot/auth\n",
        ] {
            assert_eq!(stock_auth_argv(good), Ok(()));
        }
        for wrong in [
            "auth -w\n",
            "auth -o auth_cache_size=0\n",
            "auth -o auth_cache_size=1\n",
            "auth -o auth_policy_server_url=http://other\n",
            "auth\nauth\n",
            "/tmp/auth\n",
            "",
        ] {
            assert!(stock_auth_argv(wrong).is_err());
        }
    }
}
