//! Lifetime ownership of actual IMAP transport file descriptions. A PID is
//! coverage metadata only: this module never signals a process.
use crate::account_password_policy::Publication;
use crate::account_password_state::Guard;
use crate::auth::CommandExecutor;
use crate::openbsd::ReceivedImapIo;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Instant;

const GLOBAL_LIMIT: usize = 256;
const ACCOUNT_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Refused,
    Unavailable,
    Expired,
}

/// Constructed only by the native peer inspector after matching each received
/// right to the current peer's specifically labelled client descriptor.
pub(crate) struct AttestedIo {
    account: String,
    session: String,
    pid: u32,
    descriptions: Vec<String>,
    io: ReceivedImapIo,
}
impl AttestedIo {
    pub(super) fn from_native(
        account: String,
        session: String,
        pid: u32,
        descriptions: Vec<String>,
        io: ReceivedImapIo,
    ) -> Self {
        Self {
            account,
            session,
            pid,
            descriptions,
            io,
        }
    }
}
struct Entry {
    epoch: u64,
    pid: u32,
    descriptions: Vec<String>,
    io: ReceivedImapIo,
    control: UnixStream,
}

pub(crate) struct Registry {
    entries: Mutex<BTreeMap<(String, String), Entry>>,
}
impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }
    /// Fence invokes this while holding the SAME account guard used to observe
    /// the actual anvil registration. Successful insertion precedes OK.
    pub(crate) fn register(
        &self,
        guard: &Guard<'_>,
        publication: &Publication,
        attested: AttestedIo,
        control: UnixStream,
        deadline: Instant,
    ) -> Result<(), Error> {
        if Instant::now() >= deadline {
            return Err(Error::Expired);
        }
        guard
            .admission(Some(publication.epoch()))
            .map_err(|_| Error::Refused)?;
        if attested.account != publication.account()
            || attested.session != publication.session()
            || attested.pid != publication.pid()
            || !(1..=2).contains(&attested.io.len())
            || attested.descriptions.len() != attested.io.len()
        {
            return Err(Error::Refused);
        }
        let mut entries = self.entries.try_lock().map_err(|_| Error::Unavailable)?;
        let key = (attested.account, attested.session);
        // Normal client destruction closes its control channel. Bound global
        // reclamation keeps disconnected accounts from exhausting publication.
        let mut closed = Vec::new();
        for (key, entry) in entries.iter() {
            if crate::openbsd::password_imap_control_eof(&entry.control)
                .map_err(|_| Error::Unavailable)?
            {
                closed.push(key.clone());
            }
        }
        for key in closed {
            entries.remove(&key);
        }
        if entries.len() >= GLOBAL_LIMIT
            || entries
                .keys()
                .filter(|(account, _)| account == &key.0)
                .count()
                >= ACCOUNT_LIMIT
            || entries.contains_key(&key)
            || entries.values().any(|entry| {
                entry
                    .descriptions
                    .iter()
                    .any(|description| attested.descriptions.contains(description))
            })
            || crate::openbsd::password_imap_control_eof(&control)
                .map_err(|_| Error::Unavailable)?
            || Instant::now() >= deadline
        {
            return Err(Error::Refused);
        }
        entries.insert(
            key,
            Entry {
                epoch: publication.epoch(),
                pid: attested.pid,
                descriptions: attested.descriptions,
                io: attested.io,
                control,
            },
        );
        Ok(())
    }
    /// Called only by the concrete mutation Effects under Service's held
    /// account guard. Existing unregistered clients refuse BEFORE SQL write.
    pub(crate) fn preflight(
        &self,
        control: &impl CommandExecutor,
        account: &str,
        epoch: u64,
        deadline: Instant,
    ) -> Result<(), Error> {
        let actual = crate::account_password_peer::account_imap_pids(control, account, deadline)
            .map_err(|_| Error::Unavailable)?;
        let mut entries = self.entries.try_lock().map_err(|_| Error::Unavailable)?;
        let mut closed = Vec::new();
        for (key, entry) in entries.iter().filter(|(key, _)| key.0 == account) {
            if crate::openbsd::password_imap_control_eof(&entry.control)
                .map_err(|_| Error::Unavailable)?
            {
                closed.push(key.clone());
            }
        }
        for key in closed {
            entries.remove(&key);
        }
        let selected = entries
            .iter()
            .filter(|(key, _)| key.0 == account)
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        let covered = selected
            .iter()
            .map(|entry| entry.pid)
            .collect::<BTreeSet<_>>();
        if selected.iter().any(|entry| entry.epoch != epoch)
            || actual.iter().any(|pid| !covered.contains(pid))
            || Instant::now() >= deadline
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
    /// Rights refer to the original socket objects even if the peer exits or
    /// its numeric PID is reused. No relookup or process signal occurs.
    pub(crate) fn terminate(
        &self,
        control: &impl CommandExecutor,
        account: &str,
        epoch: u64,
        deadline: Instant,
    ) -> Result<(), Error> {
        self.preflight(control, account, epoch, deadline)?;
        let owned = {
            let mut entries = self.entries.try_lock().map_err(|_| Error::Unavailable)?;
            let keys = entries
                .keys()
                .filter(|key| key.0 == account)
                .cloned()
                .collect::<Vec<_>>();
            keys.into_iter()
                .map(|key| entries.remove(&key).ok_or(Error::Unavailable))
                .collect::<Result<Vec<_>, _>>()?
        };
        // Release the global registry lock before bounded close observations;
        // another account's login does not wait for this account's teardown.
        let mut shutdown_failed = false;
        for entry in &owned {
            if Instant::now() >= deadline {
                return Err(Error::Expired);
            }
            if crate::openbsd::password_shutdown_imap_io(&entry.io).is_err() {
                shutdown_failed = true;
            }
        }
        if shutdown_failed {
            return Err(Error::Unavailable);
        }
        for mut entry in owned {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or(Error::Expired)?;
            entry
                .control
                .set_read_timeout(Some(left))
                .map_err(|_| Error::Unavailable)?;
            let mut byte = [0];
            if entry
                .control
                .read(&mut byte)
                .map_err(|_| Error::Unavailable)?
                != 0
            {
                return Err(Error::Refused);
            }
        }
        if !crate::account_password_peer::account_imap_pids(control, account, deadline)
            .map_err(|_| Error::Unavailable)?
            .is_empty()
            || Instant::now() >= deadline
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
}
