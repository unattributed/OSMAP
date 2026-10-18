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
struct Snapshot {
    master: Row,
    peer: Row,
    own: Row,
    pcb: (u64, u64),
}
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
pub(crate) struct Binding {
    fd: i32,
    deadline: Instant,
}
pub(crate) struct NativeRegistration {
    account: String,
    session: String,
    epoch: u64,
    pid: u32,
    uid: u32,
    birth: u64,
    observed: Instant,
}
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
        if !crate::openbsd::password_native_authority()
            || std::process::id() != self.own.pid
            || Instant::now() >= deadline
        {
            return Err(Error::Refused);
        }
        for pin in &self.pins {
            if file_pin(pin.path)? != *pin {
                return Err(Error::Refused);
            }
        }
        for (process, path) in [(&self.master, MASTER), (&self.own, HELPER)] {
            if row(
                &query(executor, PS, &ps_args(process.pid), deadline)?,
                process.pid,
            )? != *process
            {
                return Err(Error::Refused);
            }
            descriptors(
                &query(executor, FSTAT, &fstat_args(process.pid), deadline)?,
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
        .map_err(|_| Error::Unavailable)?;
    if Instant::now() >= query_deadline
        || result.status_code != 0
        || !result.stderr.is_empty()
        || result.stdout.is_empty()
        || result.stdout.len() > limit
        || !result.stdout.is_ascii()
        || result.stdout.contains('\0')
    {
        return Err(Error::Unavailable);
    }
    Ok(result.stdout)
}

#[cfg(test)]
#[path = "account_password_peer_tests.rs"]
mod tests;
