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

// A measured private-auth process/socket observation is not a loaded-config or
// deployment qualification receipt. Production still requires its closed gate.
const PRIMARY_AUTH: &str = "/usr/local/libexec/dovecot/auth";
const PRIMARY_SOCKET: &str = "/var/dovecot/osmap-account-auth-client";
const PRIMARY_FRAGMENT: &str = "/etc/dovecot/conf.d/99-osmap-private-primary.conf";
const PRIMARY_FRAGMENT_SHA256: [u8; 32] = [
    116, 100, 239, 200, 106, 6, 129, 145, 121, 10, 118, 175, 51, 64, 37, 104, 100, 223, 158, 130,
    219, 195, 1, 118, 1, 94, 138, 64, 48, 74, 81, 244,
];
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
const PRIMARY_CONFIGURATION_HASHES: &[(&str, &str)] = &[
    (
        "/etc/dovecot/conf.d/99-osmap-private-control.conf",
        "ce8b95772da4512462083a248553aac8a30131650839033e65b88fb728a1aabc",
    ),
    (
        "/etc/dovecot/dovecot.conf",
        "2a869bce0fe0a6a193827bd91b716a46a02bff0267f5fb34ce2111e3ac279d66",
    ),
    (
        "/etc/dovecot/conf.d/10-auth.conf",
        "cbd482e1f0177b89902a6d8380e26be8c660ee98ff814e0772a246af7f3fca0b",
    ),
    (
        "/etc/dovecot/conf.d/10-director.conf",
        "49decee086a8fc7b396a1fad842b8b95d707825b2c4072526139731c70a07377",
    ),
    (
        "/etc/dovecot/conf.d/10-logging.conf",
        "5c8205ea0a2276a220caccabbcf3d4201d8758452d613b8a1c89cb2987c09292",
    ),
    (
        "/etc/dovecot/conf.d/10-mail.conf",
        "015a213d56db22168eb171f67816edea22dedf4c69cc644da48f641a2765b267",
    ),
    (
        "/etc/dovecot/conf.d/10-master.conf",
        "2fab3304f7d8bf88ab936cddd43377e1dc6fa0ad3989a94a0b208db17a5ab66b",
    ),
    (
        "/etc/dovecot/conf.d/10-metrics.conf",
        "dd4871b89ca692c560cd6882e9179ba983682d273f3d7aef099de13141e5ee1d",
    ),
    (
        "/etc/dovecot/conf.d/10-ssl.conf",
        "e44e97e4157afe8b05ae2e35813487ac961683aa209969360391a2806ee3d2a9",
    ),
    (
        "/etc/dovecot/conf.d/15-lda.conf",
        "d401e22a98187429b7fb30671553d0f2a5953bf87fb023764dd553b029185c62",
    ),
    (
        "/etc/dovecot/conf.d/15-mailboxes.conf",
        "1edf599e43e8c2498ccd9f8ebe46eb8cfdb68706bb14c514054a8e894ba6bcf6",
    ),
    (
        "/etc/dovecot/conf.d/20-imap.conf",
        "b6e0abad74a8bd3ddb449a25e1d55c346b8afdd676f2d768adeb57a2c08c029a",
    ),
    (
        "/etc/dovecot/conf.d/20-lmtp.conf",
        "897a163ae1b06b883a7c2bf68751457f11179a18a58edf2dd67ceb3e822fc3b8",
    ),
    (
        "/etc/dovecot/conf.d/20-managesieve.conf",
        "7df9d199d3682dfa529b79572692b2b9f15c9df67e90589af0e80edde39b4420",
    ),
    (
        "/etc/dovecot/conf.d/20-pop3.conf",
        "9c44864b6867d1707ff55a1f45ba6112d68e1c7a613df6e814ca38d598a55375",
    ),
    (
        "/etc/dovecot/conf.d/20-submission.conf",
        "6f0dcb7b17579672116c1e8c8e6aee88c70c5cfceb842f8a36f44ee7e4fe7fd2",
    ),
    (
        "/etc/dovecot/conf.d/90-acl.conf",
        "89e257dcdc03b18e4f3a1d4ae8bd95e3abd3278acdc4b5d5bfbb48ff51271ef6",
    ),
    (
        "/etc/dovecot/conf.d/90-plugin.conf",
        "2e07c87dacc547632b902056507ea406ed34ad3d7363c296f0be350d96e4013f",
    ),
    (
        "/etc/dovecot/conf.d/90-quota.conf",
        "cd0a0dfc0af65ec52a283435c71861b7c043d0c423f517c47c901bfd2a323b78",
    ),
    (
        "/etc/dovecot/conf.d/90-sieve-extprograms.conf",
        "ffa14b5f38da5acbd93fd20d3cc0b28517cabeb6797539c97b2090d96983430d",
    ),
    (
        "/etc/dovecot/conf.d/90-sieve.conf",
        "9910f435ce74aceb8b0f2a4e019f789b96785c2248f8c29a8e892a5080b0231c",
    ),
    (
        "/etc/dovecot/conf.d/99-bbs-imaps-only.conf",
        "9c931338bea2c81bab144563f67d0259c75ec16e05481bb37ffe6d542d12f517",
    ),
    (
        "/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf",
        "90bf803ffc0937af5a5e2f1fdf3830275277e1a5a2645eba6ee26609dd218bce",
    ),
    (
        "/etc/dovecot/conf.d/99-rspamd-warning-labels.conf",
        "d22d9ee9c3a730e782cd29397f7a5a2595607233378e61c86dacb668e8ef508b",
    ),
    (
        "/etc/dovecot/local.conf",
        "f1ebb49ef250de35708eb83205a4cb7ea0216776704d32ad5baac2a56200ab09",
    ),
    (
        "/etc/dovecot/conf.d/auth-sql.conf.ext",
        "df0b657c2a4c963e31ab7f693a8afd2601694701d383c282323e3ea5c6e8986d",
    ),
    (
        "/etc/dovecot/conf.d/99-osmap-private-primary.conf",
        "7464efc86a068191790a76af3340256864df9e82dbc30176015e8a40304a51f4",
    ),
];
struct PrimaryFile {
    path: &'static str,
    identity: [u64; 11],
    digest: [u8; 32],
}
fn primary_file(path: &'static str, deadline: Instant) -> Result<PrimaryFile, Error> {
    primary_file_bytes(path, deadline).map(|(pin, _)| pin)
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
    let limit = if path == PRIMARY_AUTH {
        64 * 1024 * 1024
    } else {
        128 * 1024
    };
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
    {
        return Err(Error::Refused);
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if let Some((_, expected)) = PRIMARY_CONFIGURATION_HASHES
        .iter()
        .find(|(name, _)| *name == path)
    {
        let actual: String = digest.iter().map(|value| format!("{value:02x}")).collect();
        if actual != *expected {
            return Err(Error::Refused);
        }
    }
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
fn primary_include_matches(deadline: Instant) -> Result<(), Error> {
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
    let expected = PRIMARY_CONFIGURATION_PATHS
        .iter()
        .filter(|path| path.starts_with("/etc/dovecot/conf.d/") && path.ends_with(".conf"))
        .map(|path| path.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    if found != expected {
        Err(Error::Refused)
    } else {
        Ok(())
    }
}
impl PrimaryPeer {
    pub(crate) fn observe(
        executor: std::sync::Arc<dyn CommandExecutor + Send + Sync>,
        startup: &Startup,
        deadline: Instant,
    ) -> Result<Self, Error> {
        startup.recheck(executor.as_ref(), deadline)?;
        primary_include_matches(deadline)?;
        let (passwd, bytes) = primary_file_bytes("/etc/passwd", deadline)?;
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
        let reread = primary_file("/etc/passwd", deadline)?;
        if passwd.identity != reread.identity
            || passwd.digest != reread.digest
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != passwd.digest
        {
            return Err(Error::Refused);
        }
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
        let mut files = PRIMARY_CONFIGURATION_PATHS
            .iter()
            .map(|path| primary_file(path, deadline))
            .collect::<Result<Vec<_>, _>>()?;
        files.push(passwd);
        files.push(primary_file(PRIMARY_AUTH, deadline)?);
        let auth = file_pin(PRIMARY_AUTH)?;
        let selection = main_configuration_selection(executor.as_ref(), startup, deadline)?;
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
        result.snapshot = result.probe(deadline)?;
        result.recheck(deadline)?;
        Ok(result)
    }
    pub(crate) fn identities(&self, deadline: Instant) -> Result<(u32, u32), Error> {
        self.recheck(deadline)?;
        Ok((self.server_uid, self.snapshot.binder.1))
    }
    fn probe(&self, deadline: Instant) -> Result<PrimarySocketSnapshot, Error> {
        socket_probe(
            self.executor.as_ref(),
            &self.startup,
            &self.auth,
            PRIMARY_SOCKET,
            "auth",
            self.server_uid,
            self.server_uid,
            deadline,
        )
    }
    pub(crate) fn recheck(&self, deadline: Instant) -> Result<(), Error> {
        if main_configuration_selection(self.executor.as_ref(), &self.startup, deadline)?
            != self.selection
        {
            return Err(Error::Refused);
        }
        primary_include_matches(deadline)?;
        for old in &self.files {
            let new = primary_file(old.path, deadline)?;
            if old.identity != new.identity || old.digest != new.digest {
                return Err(Error::Refused);
            }
        }
        if self.probe(deadline)? != self.snapshot
            || main_configuration_selection(self.executor.as_ref(), &self.startup, deadline)?
                != self.selection
        {
            return Err(Error::Refused);
        }
        primary_include_matches(deadline)
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
) -> Result<MainConfigurationSelection, Error> {
    startup.recheck(executor, deadline)?;
    let argv = query(
        executor,
        PS,
        &[
            "-p".into(),
            startup.master.pid.to_string(),
            "-o".into(),
            "args=".into(),
        ],
        deadline,
    )?;
    main_master_argv(&argv)?;
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
    let before = fs::symlink_metadata(MAIN_CONFIG_LINK).map_err(|_| Error::Unavailable)?;
    if !before.file_type().is_symlink()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.len() > 256
        || fs::read_link(MAIN_CONFIG_LINK).map_err(|_| Error::Unavailable)?
            != Path::new(MAIN_CONFIG)
        || pin(&fs::symlink_metadata(MAIN_CONFIG_LINK).map_err(|_| Error::Unavailable)?)
            != pin(&before)
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
    startup.recheck(executor, deadline)?;
    let endpoint = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    use std::os::unix::fs::FileTypeExt;
    if !endpoint.file_type().is_socket()
        || endpoint.uid() != owner_uid
        || endpoint.nlink() != 1
        || endpoint.mode() & 0o777 != 0o660
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
    let stream = crate::openbsd::connect_unix_before(Path::new(path), deadline)
        .map_err(|_| Error::Unavailable)?;
    let binder = kernel(&stream)?;
    let own = descriptors(
        &query(executor, FSTAT, &fstat_args(startup.own.pid), deadline)?,
        &startup.own,
        startup
            .pins
            .iter()
            .find(|pin| pin.path == HELPER)
            .ok_or(Error::Refused)?,
    )?;
    let raw = query(
        executor,
        PS,
        &["-ax".into(), "-o".into(), PS_FIELDS.into()],
        deadline,
    )?;
    let mut workers = Vec::new();
    for (index, line) in raw.lines().enumerate() {
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
        let peer = descriptors(
            &query(executor, FSTAT, &fstat_args(pid), deadline)?,
            &candidate,
            auth,
        )?;
        if reciprocal(&own, &peer, stream.as_raw_fd()).is_ok() {
            workers.push(candidate);
        }
    }
    if workers.len() != 1 {
        return Err(Error::Refused);
    }
    let worker = workers.remove(0);
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
    pub(crate) fn observe(
        primary: std::sync::Arc<PrimaryPeer>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        primary.recheck(deadline)?;
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
