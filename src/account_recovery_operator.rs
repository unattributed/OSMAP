//! Fixed root-only operator entrypoint. Independent identity verification and
//! private-terminal consent belong to the pinned-signature SSH adapter. No
//! browser request, environment variable or argument selects filesystem roots.
use crate::account_recovery::{Coordinator, Paths, SCHEMA};
pub use crate::account_recovery::{Error, IdentityMethod, Request};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CONFIG: &str = "/etc/osmap/account-runtime/config.json";
const EPOCH: &str = "/var/db/osmap-account/epoch";
const CASES: &str = "/var/db/osmap-account/recovery";
const SERVE_ENV: &str = "/etc/osmap/osmap-serve.env";
const HOST: &str = "obsd1.blackbagsecurity.com";
const MAX_INPUT: usize = 16384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    authority: String,
    purpose: String,
    accounts: Vec<String>,
    trusted_relay_uid: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    schema: String,
    account: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimePaths {
    pub session_directory: PathBuf,
    pub factor_directory: PathBuf,
    pub revoked_directory: PathBuf,
    pub settings_directory: PathBuf,
}

fn safe_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() > 1
        && value.len() <= 4096
        && !value.ends_with('/')
        && !value.contains("//")
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"/_-".contains(&v))
}

/// Parse the fixed service's literal assignments; never source shell text or
/// use this operator process's environment as the runtime configuration.
fn parse_runtime_paths(bytes: &[u8]) -> Result<RuntimePaths, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::StateUnavailable)?;
    let mut fields = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or(Error::StateUnavailable)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|v| v.is_ascii_uppercase() || v.is_ascii_digit() || v == b'_')
            || !value
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"_/:.,@+-=".contains(&v))
            || fields.insert(name, value).is_some()
        {
            return Err(Error::StateUnavailable);
        }
    }
    let state = fields
        .get("OSMAP_STATE_DIR")
        .copied()
        .unwrap_or("/var/lib/osmap");
    if !safe_path(state) {
        return Err(Error::StateUnavailable);
    }
    let select = |name, suffix: &str| -> Result<PathBuf, Error> {
        let value = fields
            .get(name)
            .map(|v| (*v).to_string())
            .unwrap_or_else(|| format!("{state}/{suffix}"));
        if !safe_path(&value) {
            return Err(Error::StateUnavailable);
        }
        Ok(value.into())
    };
    let factor_directory = select("OSMAP_TOTP_SECRET_DIR", "secrets/totp")?;
    let revoked_directory = factor_directory.with_file_name("totp-revoked");
    if revoked_directory == factor_directory {
        return Err(Error::StateUnavailable);
    }
    Ok(RuntimePaths {
        session_directory: select("OSMAP_SESSION_DIR", "sessions")?,
        factor_directory,
        revoked_directory,
        settings_directory: select("OSMAP_SETTINGS_DIR", "settings")?,
    })
}

fn runtime_paths(runtime_gid: u32) -> Result<RuntimePaths, Error> {
    ancestors(Path::new("/etc/osmap"), 0, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(SERVE_ENV)
        .map_err(|_| Error::StateUnavailable)?;
    let metadata = file.metadata().map_err(|_| Error::StateUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o600 | 0o640)
        || (metadata.mode() & 0o7777 == 0o640 && metadata.gid() != runtime_gid)
        || metadata.len() > 65536
    {
        return Err(Error::StateUnavailable);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::StateUnavailable)?;
    if bytes.len() > 65536 {
        return Err(Error::StateUnavailable);
    }
    parse_runtime_paths(&bytes)
}

fn ancestors(path: &Path, runtime_uid: u32, allow_absent_leaf: bool) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::StateUnavailable);
    }
    for (index, part) in path.ancestors().enumerate() {
        let m = match fs::symlink_metadata(part) {
            Ok(m) => m,
            Err(error)
                if index == 0
                    && allow_absent_leaf
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue
            }
            Err(_) => return Err(Error::StateUnavailable),
        };
        if !m.is_dir()
            || m.file_type().is_symlink()
            || !matches!(m.uid(), 0) && m.uid() != runtime_uid
            || m.mode() & 0o022 != 0
        {
            return Err(Error::StateUnavailable);
        }
    }
    Ok(())
}
fn runtime_identity() -> Result<(u32, u32), Error> {
    crate::openbsd::osmap_runtime_identity().map_err(|_| Error::StateUnavailable)
}
fn host_and_privilege() -> Result<(), Error> {
    if !cfg!(target_os = "openbsd")
        || crate::openbsd::effective_uid() != 0
        || crate::openbsd::real_uid() != 0
    {
        return Err(Error::Unauthorized);
    }
    if !crate::openbsd::hostname_matches(HOST.as_bytes()).map_err(|_| Error::StateUnavailable)? {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
fn operator_configuration() -> Result<Config, Error> {
    ancestors(Path::new("/etc/osmap/account-runtime"), 0, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(CONFIG)
        .map_err(|_| Error::StateUnavailable)?;
    let metadata = file.metadata().map_err(|_| Error::StateUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_INPUT as u64
    {
        return Err(Error::StateUnavailable);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::StateUnavailable)?;
    if bytes.len() > MAX_INPUT {
        return Err(Error::StateUnavailable);
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| Error::StateUnavailable)?;
    let accounts = config.accounts.iter().collect::<BTreeSet<_>>();
    if config.version != 1
        || config.authority != "mail.blackbagsecurity.com"
        || config.purpose != "osmap-account-mutation"
        || config.accounts.is_empty()
        || config.accounts.len() > 64
        || accounts.len() != config.accounts.len()
        || config.trusted_relay_uid == 0
        || config.trusted_relay_uid == u32::MAX
        || config
            .accounts
            .iter()
            .any(|v| crate::account_admission::valid_account(v).is_err())
    {
        return Err(Error::StateUnavailable);
    }
    Ok(config)
}

fn bounded_input() -> Result<Vec<u8>, Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    crate::openbsd::bounded_operator_stdin(MAX_INPUT, deadline).map_err(|_| Error::InvalidRequest)
}

/// All consequential native operations require root plus the exact existing
/// managed-account allowlist. Independent identity decisions remain the SSH
/// adapter's responsibility; these checks do not fabricate such a decision.
pub fn run_cli() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let verb = if args.len() == 1 {
        args[0].to_str().ok_or(Error::InvalidRequest)?
    } else {
        return Err(Error::InvalidRequest);
    };
    if !matches!(verb, "status" | "begin" | "prepare-factor" | "reconcile") {
        return Err(Error::InvalidRequest);
    }
    host_and_privilege()?;
    crate::openbsd::disable_core_dumps().map_err(|_| Error::StateUnavailable)?;
    let bytes = bounded_input()?;
    let config = operator_configuration()?;
    let (runtime_uid, runtime_gid) = runtime_identity()?;
    let paths = runtime_paths(runtime_gid)?;
    ancestors(Path::new(EPOCH), 0, false)?;
    for path in [
        &paths.session_directory,
        &paths.factor_directory,
        &paths.settings_directory,
    ] {
        ancestors(path, runtime_uid, false)?;
    }
    ancestors(Path::new(CASES), 0, true)?;
    ancestors(&paths.revoked_directory, runtime_uid, true)?;
    let coordinator = Coordinator::new(Paths {
        epoch: EPOCH.into(),
        cases: CASES.into(),
        sessions: paths.session_directory.clone(),
        factors: paths.factor_directory.clone(),
        revoked: paths.revoked_directory.clone(),
        operator_uid: 0,
        runtime_uid,
        runtime_gid,
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::StateUnavailable)?
        .as_secs();
    let mut operation_error = None;
    let (account, status) = if verb == "status" {
        let request: StatusRequest =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
        if request.schema != SCHEMA || !config.accounts.contains(&request.account) {
            return Err(Error::Unauthorized);
        }
        let status = coordinator.status(&request.account, deadline)?;
        (request.account, status)
    } else {
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
        if !config.accounts.contains(&request.account) {
            return Err(Error::Unauthorized);
        }
        let result = match verb {
            "begin" => coordinator.begin(&request, now, deadline),
            "prepare-factor" => coordinator.prepare_factor(&request, now, deadline),
            "reconcile" => coordinator.reconcile(&request, now, deadline),
            _ => return Err(Error::InvalidRequest),
        };
        let mut status = match result {
            Ok(status) => status,
            Err(error) => {
                operation_error = Some(error);
                coordinator.status(&request.account, deadline)?
            }
        };
        if let Some(error) = operation_error {
            status.failure = Some(error);
        }
        (request.account, status)
    };
    if verb != "status" {
        crate::authenticator::publish_operator_status(
            &paths.settings_directory.join("account-recovery"),
            &account,
            &status,
            runtime_uid,
            runtime_gid,
            now,
        )
        .map_err(|_| Error::StateUnavailable)?;
    }
    #[derive(Serialize)]
    struct Output<'a> {
        #[serde(flatten)]
        status: &'a crate::account_recovery::Status,
        runtime_paths: &'a RuntimePaths,
    }
    let output = serde_json::to_vec(&Output {
        status: &status,
        runtime_paths: &paths,
    })
    .map_err(|_| Error::StateUnavailable)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .map_err(|_| Error::StateUnavailable)?;
    stdout
        .write_all(b"\n")
        .map_err(|_| Error::StateUnavailable)?;
    operation_error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_custom_state_paths_override_stale_defaults_without_shell_execution() {
        let paths = parse_runtime_paths(b"OSMAP_STATE_DIR=/var/lib/osmap-s04-02/state\nOSMAP_SESSION_DIR=/var/lib/osmap-s04-02/state/sessions\nOSMAP_TOTP_SECRET_DIR=/var/lib/osmap-s04-02/state/secrets/totp\n").unwrap();
        assert_eq!(
            paths.session_directory,
            Path::new("/var/lib/osmap-s04-02/state/sessions")
        );
        assert_eq!(
            paths.factor_directory,
            Path::new("/var/lib/osmap-s04-02/state/secrets/totp")
        );
        assert_eq!(
            paths.revoked_directory,
            Path::new("/var/lib/osmap-s04-02/state/secrets/totp-revoked")
        );
        assert_eq!(
            paths.settings_directory,
            Path::new("/var/lib/osmap-s04-02/state/settings")
        );
        let explicit = parse_runtime_paths(
            b"OSMAP_STATE_DIR=/var/lib/custom\nOSMAP_SETTINGS_DIR=/var/lib/other/settings\n",
        )
        .unwrap();
        assert_eq!(
            explicit.settings_directory,
            Path::new("/var/lib/other/settings")
        );
    }

    #[test]
    fn duplicate_expanding_quoted_relative_and_unsafe_path_assignments_refuse() {
        for input in [
            "OSMAP_STATE_DIR=/var/lib/a\nOSMAP_STATE_DIR=/var/lib/b",
            "export OSMAP_STATE_DIR=/var/lib/a",
            "OSMAP_STATE_DIR=$(id)",
            "OSMAP_STATE_DIR=\"/var/lib/a\"",
            "OSMAP_STATE_DIR=var/lib/a",
            "OSMAP_STATE_DIR=/var/lib/../a",
            "OSMAP_SESSION_DIR=/var//lib/a",
            "OSMAP_TOTP_SECRET_DIR=/var/lib/a/",
            "OSMAP_STATE_DIR=/var/lib/a;id",
            "OSMAP_SETTINGS_DIR=",
            "OSMAP_STATE_DIR=/var/lib/a\nSOME_OTHER=$(id)",
        ] {
            assert_eq!(
                parse_runtime_paths(input.as_bytes()).err(),
                Some(Error::StateUnavailable),
                "{input}"
            );
        }
    }
}
