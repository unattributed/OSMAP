//! Helper-only personal lifecycle. Paths and pins come from the operator map;
//! public administration never receives private material or an agent capability.
use crate::auth::{personal_agent_command, PersonalAgentCommand};
use crate::openpgp_personal::{
    PersonalAction, PersonalError as Error, PersonalState, PrivateSession, CACHE_SECONDS,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(super) struct Context<'a> {
    pub account: &'a str,
    pub home: &'a Path,
    pub primary: &'a str,
    pub signer: &'a str,
    pub worker: &'a Path,
    pub engine: &'a Path,
}
struct Grant {
    epoch: Option<u64>,
    until: u64,
    revision: String,
}
#[derive(Default)]
pub(super) struct Manager {
    grants: BTreeMap<(String, String), Grant>,
    failures: BTreeMap<String, Vec<u64>>,
    uncertain: BTreeSet<String>,
}
struct PrivateFiles {
    files: Vec<(String, Vec<u8>)>,
    revision: String,
    protected: bool,
}
impl Drop for PrivateFiles {
    fn drop(&mut self) {
        for (_, bytes) in &mut self.files {
            crate::openpgp_personal::clear(bytes);
        }
    }
}
fn unavailable<T>(_: T) -> Error {
    Error::Unavailable
}
fn time() -> Result<u64, Error> {
    crate::openpgp_inventory_runtime::now().map_err(unavailable)
}
fn private_files(home: &Path) -> Result<PrivateFiles, Error> {
    let directory = home.join("private-keys-v1.d");
    let mut files = Vec::new();
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(Error::Unavailable),
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.uid() != crate::openbsd::effective_uid()
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(Error::Invalid);
            }
            for entry in fs::read_dir(&directory).map_err(unavailable)? {
                if files.len() >= 16 {
                    return Err(Error::Unsupported);
                }
                let path = entry.map_err(unavailable)?.path();
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(Error::Invalid)?;
                if name.len() != 44
                    || !name.ends_with(".key")
                    || !name[..40].bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(Error::Unsupported);
                }
                let file = crate::openpgp_inventory_runtime::file(
                    &path,
                    crate::openbsd::effective_uid(),
                    false,
                    65536,
                )
                .map_err(unavailable)?;
                let mut bytes = Vec::new();
                file.take(65537)
                    .read_to_end(&mut bytes)
                    .map_err(unavailable)?;
                if bytes.is_empty() || bytes.len() > 65536 {
                    return Err(Error::Invalid);
                }
                files.push((name.to_owned(), bytes));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hash = Sha256::new();
    let mut protected = !files.is_empty();
    for (name, bytes) in &files {
        let protected_key = bytes
            .windows(b"protected-private-key".len())
            .any(|part| part == b"protected-private-key");
        let unprotected = bytes
            .windows(b"(private-key".len())
            .any(|part| part == b"(private-key");
        if !protected_key && !unprotected {
            return Err(Error::Unsupported);
        }
        protected &= protected_key;
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(PrivateFiles {
        files,
        revision: format!("{:x}", hash.finalize()),
        protected,
    })
}
fn endpoint(home: &Path, deadline: Instant) -> Result<bool, Error> {
    let path = home.join("S.gpg-agent");
    let before = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error::Unavailable),
    };
    if !before.file_type().is_socket()
        || before.uid() != crate::openbsd::effective_uid()
        || before.nlink() != 1
    {
        return Err(Error::Invalid);
    }
    match crate::openbsd::connect_unix_before(
        &path,
        deadline.min(Instant::now() + Duration::from_millis(250)),
    ) {
        Ok(peer) => {
            if crate::openbsd::unix_stream_peer_uid(&peer).map_err(unavailable)?
                != crate::openbsd::effective_uid()
            {
                return Err(Error::Invalid);
            }
            let after = fs::symlink_metadata(&path).map_err(unavailable)?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err(Error::Unconfirmed);
            }
            Ok(true)
        }
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ECONNREFUSED) | Some(libc::ENOENT)
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(Error::Unavailable),
    }
}
fn agent(home: &Path, action: PersonalAgentCommand, deadline: Instant) -> Result<Vec<u8>, Error> {
    let starting = matches!(&action, PersonalAgentCommand::Start);
    let command = personal_agent_command(home, action);
    let (bytes, success) = if starting {
        crate::openpgp_crypto_process::run_personal_start(command, deadline, |leader, until| {
            let pid =
                agent_pid(home, until).map_err(|_| crate::openpgp_crypto::Error::Unavailable)?;
            Ok(pid != leader
                && crate::openbsd::process_id_exists(pid)
                    .map_err(|_| crate::openpgp_crypto::Error::Unavailable)?
                && endpoint(home, until).map_err(|_| crate::openpgp_crypto::Error::Unavailable)?)
        })
    } else {
        crate::openpgp_crypto_process::run_personal(command, &[], deadline)
    }
    .map_err(unavailable)?;
    if !success {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}
fn agent_pid(home: &Path, deadline: Instant) -> Result<u32, Error> {
    let bytes = agent(home, PersonalAgentCommand::Pid, deadline)?;
    let text = std::str::from_utf8(&bytes).map_err(unavailable)?;
    let mut rows = text.lines().filter_map(|line| line.strip_prefix("D "));
    let value = rows.next().ok_or(Error::Unconfirmed)?;
    if rows.next().is_some() || value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Unconfirmed);
    }
    let value = value.parse::<u32>().map_err(unavailable)?;
    if value <= 1 || value > i32::MAX as u32 {
        return Err(Error::Unconfirmed);
    }
    Ok(value)
}
fn stop_agent(home: &Path, deadline: Instant) -> Result<(), Error> {
    let mut pid = None;
    if endpoint(home, deadline)? {
        pid = Some(agent_pid(home, deadline)?);
    }
    agent(home, PersonalAgentCommand::Stop, deadline)?;
    loop {
        let absent = pid
            .map(|pid| {
                crate::openbsd::process_id_exists(pid)
                    .map(|exists| !exists)
                    .map_err(unavailable)
            })
            .transpose()?
            .unwrap_or(true);
        if absent && !endpoint(home, deadline)? {
            break;
        }
        if Instant::now() >= deadline {
            return Err(Error::Unconfirmed);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let path = home.join("S.gpg-agent");
    if let Ok(before) = fs::symlink_metadata(&path) {
        if !before.file_type().is_socket()
            || before.uid() != crate::openbsd::effective_uid()
            || endpoint(home, deadline)?
        {
            return Err(Error::Unconfirmed);
        }
        let after = fs::symlink_metadata(&path).map_err(unavailable)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Error::Unconfirmed);
        }
        fs::remove_file(path).map_err(unavailable)?;
    }
    Ok(())
}
fn start_agent(home: &Path, deadline: Instant) -> Result<(), Error> {
    if endpoint(home, deadline)? {
        return Err(Error::Conflict);
    }
    agent(home, PersonalAgentCommand::Start, deadline)?;
    if !endpoint(home, deadline)? {
        return Err(Error::Unavailable);
    }
    Ok(())
}
struct Stage {
    path: PathBuf,
    finished: bool,
}
impl Stage {
    fn new(home: &Path, files: Option<&PrivateFiles>) -> Result<Self, Error> {
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).map_err(unavailable)?;
        let path = home.join(format!(
            ".p-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        if path.join("S.gpg-agent").as_os_str().len() > 100 {
            return Err(Error::Unsupported);
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(unavailable)?;
        let stage = Self {
            path,
            finished: false,
        };
        for name in ["pubring.kbx", "trustdb.gpg"] {
            let mut bytes = Vec::new();
            crate::openpgp_inventory_runtime::file(
                &home.join(name),
                crate::openbsd::effective_uid(),
                false,
                4 * 1024 * 1024,
            )
            .map_err(unavailable)?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
            write_new(&stage.path.join(name), &bytes)?;
        }
        if let Some(files) = files {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(stage.path.join("private-keys-v1.d"))
                .map_err(unavailable)?;
            for (name, bytes) in &files.files {
                write_new(&stage.path.join("private-keys-v1.d").join(name), bytes)?;
            }
        }
        Ok(stage)
    }
    fn finish(&mut self, deadline: Instant) -> Result<(), Error> {
        stop_agent(&self.path, deadline)?;
        fs::remove_dir_all(&self.path).map_err(unavailable)?;
        self.finished = true;
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish(Instant::now() + Duration::from_secs(3));
        }
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(unavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(unavailable)
}
fn rollback_links(links: Vec<(PathBuf, PathBuf)>) -> bool {
    let mut certain = true;
    for (original, created) in links {
        match (
            fs::symlink_metadata(original),
            fs::symlink_metadata(&created),
        ) {
            (_, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
            (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino() => {
                if fs::remove_file(created).is_err() {
                    certain = false;
                }
            }
            _ => certain = false,
        }
    }
    certain
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeProof {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}
fn prove(
    context: &Context<'_>,
    home: &Path,
    certificate: &[u8],
    passphrase: &[u8],
    deadline: Instant,
) -> Result<(), Error> {
    if context.account.len() > 254 || context.primary.len() != 40 || context.signer.len() != 40 {
        return Err(Error::Invalid);
    }
    let mut frame =
        Vec::with_capacity(143 + context.account.len() + certificate.len() + passphrase.len());
    frame.extend_from_slice(b"OSMP");
    frame.push(if certificate.is_empty() { 2 } else { 1 });
    for fingerprint in [context.primary, context.signer] {
        frame.extend_from_slice(fingerprint.as_bytes());
        frame.extend_from_slice(&[0; 24]);
    }
    frame.extend_from_slice(&(context.account.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(passphrase.len() as u32).to_be_bytes());
    frame.extend_from_slice(context.account.as_bytes());
    frame.extend_from_slice(certificate);
    frame.extend_from_slice(passphrase);
    let result = crate::openpgp_crypto_process::run_personal(
        crate::auth::personal_crypto_worker_command(context.worker, context.engine, home),
        &frame,
        deadline,
    );
    crate::openpgp_personal::clear(&mut frame);
    let (bytes, success) = result.map_err(unavailable)?;
    let proof: NativeProof = serde_json::from_slice(&bytes).map_err(unavailable)?;
    if success && proof.ok && proof.error.is_none() {
        return Ok(());
    }
    Err(match proof.error.as_deref() {
        Some("locked" | "missing_key") => Error::Locked,
        Some("invalid") => Error::Invalid,
        Some("unsupported") => Error::Unsupported,
        _ => Error::Unavailable,
    })
}
impl Manager {
    fn revoke(&mut self, account: &str) {
        self.grants.retain(|(owner, _), _| owner != account);
    }
    pub(super) fn permitted(
        &mut self,
        context: &Context<'_>,
        session: Option<&PrivateSession>,
        deadline: Instant,
    ) -> bool {
        let Ok(now) = time() else { return false };
        self.grants.retain(|_, grant| grant.until > now);
        let Some(session) = session.filter(|s| s.valid(now)) else {
            return false;
        };
        let Ok(files) = private_files(context.home) else {
            return false;
        };
        !self.uncertain.contains(context.account)
            && self
                .grants
                .get(&(context.account.into(), session.session_id.clone()))
                .is_some_and(|grant| {
                    grant.epoch == session.account_epoch
                        && grant.until > now
                        && grant.until <= session.expires_at
                        && grant.revision == files.revision
                })
            && endpoint(context.home, deadline).unwrap_or(false)
    }
    fn state(
        &mut self,
        context: &Context<'_>,
        session: &PrivateSession,
        deadline: Instant,
    ) -> Result<PersonalState, Error> {
        let files = private_files(context.home)?;
        let permitted = self.permitted(context, Some(session), deadline);
        Ok(PersonalState {
            primary_fingerprint: context.primary.into(),
            private_revision: files.revision.clone(),
            installed: !files.files.is_empty(),
            protected_at_rest: files.protected,
            unlocked_for_session: permitted,
            valid_until: if permitted {
                self.grants
                    .get(&(context.account.into(), session.session_id.clone()))
                    .map(|g| g.until)
            } else {
                None
            },
            cache_seconds: CACHE_SECONDS,
        })
    }
    pub(super) fn handle(
        &mut self,
        context: Context<'_>,
        session: &PrivateSession,
        action: PersonalAction<'_>,
        deadline: Instant,
    ) -> Result<PersonalState, Error> {
        let now = time()?;
        self.grants.retain(|_, grant| grant.until > now);
        if !session.valid(now) {
            return Err(Error::Expired);
        }
        if self.uncertain.contains(context.account) {
            return Err(Error::Unconfirmed);
        }
        if self.grants.len() >= 256
            && !self
                .grants
                .keys()
                .any(|(account, _)| account == context.account)
        {
            return Err(Error::Unavailable);
        }
        match action {
            PersonalAction::Status => return self.state(&context, session, deadline),
            PersonalAction::Lock => {
                self.revoke(context.account);
                if stop_agent(context.home, deadline).is_err() {
                    self.uncertain.insert(context.account.into());
                    return Err(Error::Unconfirmed);
                }
                return self.state(&context, session, deadline);
            }
            _ => (),
        }
        let failures = self.failures.entry(context.account.into()).or_default();
        failures.retain(|at| now.saturating_sub(*at) < 60);
        if failures.len() >= 5 {
            return Err(Error::Locked);
        }
        let (certificate, passphrase) = match action {
            PersonalAction::Import {
                certificate,
                passphrase,
            } => (certificate, passphrase),
            PersonalAction::Unlock { passphrase } => (&[][..], passphrase),
            _ => return Err(Error::Invalid),
        };
        let before = private_files(context.home)?;
        let importing = !certificate.is_empty();
        if importing && !before.files.is_empty() {
            return Err(Error::Conflict);
        }
        if !importing && before.files.is_empty() {
            return Err(Error::Locked);
        }
        let public_before = fs::read(context.home.join("pubring.kbx")).map_err(unavailable)?;
        let mut stage = Stage::new(context.home, if importing { None } else { Some(&before) })?;
        let proof = start_agent(&stage.path, deadline)
            .and_then(|()| prove(&context, &stage.path, certificate, passphrase, deadline));
        if let Err(error) = proof {
            if matches!(error, Error::Locked | Error::Invalid | Error::Unsupported) {
                self.failures
                    .entry(context.account.into())
                    .or_default()
                    .push(now);
            }
            if stage.finish(deadline).is_err() {
                self.uncertain.insert(context.account.into());
                return Err(Error::Unconfirmed);
            }
            return Err(error);
        }
        let prepared = (|| {
            stop_agent(&stage.path, deadline)?;
            if importing {
                let candidate = private_files(&stage.path)?;
                if candidate.files.is_empty() {
                    return Err(Error::Invalid);
                }
                if private_files(context.home)?.revision != before.revision
                    || fs::read(context.home.join("pubring.kbx")).map_err(unavailable)?
                        != public_before
                {
                    return Err(Error::Conflict);
                }
                let destination = context.home.join("private-keys-v1.d");
                if !destination.exists() {
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&destination)
                        .map_err(unavailable)?;
                }
                let mut linked: Vec<(PathBuf, PathBuf)> = Vec::new();
                for (name, _) in &candidate.files {
                    let source = stage.path.join("private-keys-v1.d").join(name);
                    let target = destination.join(name);
                    if fs::hard_link(&source, &target).is_err() {
                        if !rollback_links(linked) {
                            self.uncertain.insert(context.account.into());
                            return Err(Error::Unconfirmed);
                        }
                        return Err(Error::Conflict);
                    }
                    linked.push((source, target));
                }
                if fs::File::open(&destination)
                    .and_then(|directory| directory.sync_all())
                    .is_err()
                {
                    self.uncertain.insert(context.account.into());
                    return Err(Error::Unconfirmed);
                }
            }
            Ok(())
        })();
        if stage.finish(deadline).is_err() {
            self.uncertain.insert(context.account.into());
            return Err(Error::Unconfirmed);
        }
        prepared?;
        self.revoke(context.account);
        let warmed = stop_agent(context.home, deadline)
            .and_then(|()| start_agent(context.home, deadline))
            .and_then(|()| prove(&context, context.home, &[], passphrase, deadline));
        if warmed.is_err() {
            let _ = stop_agent(context.home, deadline);
            return Err(if importing {
                Error::Unconfirmed
            } else {
                Error::Unavailable
            });
        }
        let files = private_files(context.home)?;
        let until = session
            .expires_at
            .min(time()?.saturating_add(CACHE_SECONDS));
        self.grants.insert(
            (context.account.into(), session.session_id.clone()),
            Grant {
                epoch: session.account_epoch,
                until,
                revision: files.revision.clone(),
            },
        );
        self.failures.remove(context.account);
        self.state(&context, session, deadline)
    }
}
#[cfg(test)]
#[path = "openpgp_crypto_personal_tests.rs"]
mod tests;
