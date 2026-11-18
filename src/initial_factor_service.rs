//! Root-owned first-factor file service. The SQL/account/invitation authority
//! remains with the separately authenticated admin service; this endpoint has
//! no SQL profile and accepts only its configured admin service peer UID.
use crate::initial_factor::{InitialFactor, Paths};
use crate::openpgp_inventory_runtime::{read_frame, write_frame};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const FRAME: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    socket: PathBuf,
    admin_uid: u32,
    admin_gid: u32,
    factors: PathBuf,
    replay: PathBuf,
    runtime_uid: u32,
    runtime_gid: u32,
    domains: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Check {
        account: String,
    },
    Install {
        account: String,
        secret_base32: String,
        accepted_counter: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Ready {},
    Installed { factor_sha256: String },
    Refused { code: String },
}

fn account_allowed(config: &Config, account: &str) -> bool {
    crate::account_admission::valid_account(account).is_ok()
        && account
            .split_once('@')
            .is_some_and(|(_, domain)| config.domains.iter().any(|allowed| allowed == domain))
}

fn config_valid(config: &Config) -> bool {
    let domains = config
        .domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    config.version == 1
        && config.admin_uid != 0
        && config.admin_uid != u32::MAX
        && config.admin_gid != 0
        && config.admin_gid != u32::MAX
        && config.runtime_uid != 0
        && config.runtime_uid != u32::MAX
        && config.runtime_gid != 0
        && config.runtime_gid != u32::MAX
        && config.socket.is_absolute()
        && config.factors.is_absolute()
        && config.replay.is_absolute()
        && config.factors != config.replay
        && config.socket != config.factors
        && config.socket != config.replay
        && crate::admin_directory::Scope::domains(&domains).is_ok()
        && config
            .domains
            .iter()
            .all(|domain| domain == &domain.to_ascii_lowercase())
        && config.domains.iter().collect::<BTreeSet<_>>().len() == config.domains.len()
}

fn socket_identity(path: &Path, group: u32) -> Result<(u64, u64), &'static str> {
    let m = fs::symlink_metadata(path).map_err(|_| "INITIAL_FACTOR_SOCKET_STAT")?;
    if !m.file_type().is_socket()
        || m.file_type().is_symlink()
        || m.uid() != 0
        || m.gid() != group
        || m.mode() & 0o7777 != 0o660
        || m.nlink() != 1
    {
        return Err("INITIAL_FACTOR_SOCKET_CUSTODY");
    }
    Ok((m.dev(), m.ino()))
}

fn parent_custody(socket: &Path, group: u32) -> Result<(), &'static str> {
    let parent = socket.parent().ok_or("INITIAL_FACTOR_SOCKET_PARENT")?;
    for ancestor in parent.ancestors() {
        let m = crate::account_password_custody::ancestor_metadata(ancestor)
            .map_err(|_| "INITIAL_FACTOR_SOCKET_PARENT")?;
        let sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != 0
            || (m.mode() & 0o022 != 0 && !sticky)
        {
            return Err("INITIAL_FACTOR_SOCKET_PARENT");
        }
    }
    let m = fs::symlink_metadata(parent).map_err(|_| "INITIAL_FACTOR_SOCKET_PARENT")?;
    if m.uid() != 0 || m.gid() != group || !matches!(m.mode() & 0o7777, 0o710 | 0o750) {
        return Err("INITIAL_FACTOR_SOCKET_PARENT");
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, ()> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(())
}

fn terminal_eof(stream: &mut UnixStream, deadline: Instant) -> Result<(), ()> {
    stream
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| ())?;
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        _ => Err(()),
    }
}

fn dispatch(
    config: &Config,
    installer: &InitialFactor,
    request: Request,
    deadline: Instant,
) -> Response {
    let account = match &request {
        Request::Check { account } | Request::Install { account, .. } => account,
    };
    if !account_allowed(config, account) {
        return Response::Refused {
            code: "scope".into(),
        };
    }
    match request {
        Request::Check { account } => match installer.check_absent(&account, deadline) {
            Ok(()) => Response::Ready {},
            Err(error) => {
                eprintln!("INITIAL_FACTOR_CHECK code={}", error.code());
                Response::Refused {
                    code: error.code().into(),
                }
            }
        },
        Request::Install {
            account,
            secret_base32,
            accepted_counter,
        } => match installer.install(&account, &secret_base32, accepted_counter, deadline) {
            Ok(()) => {
                let bytes = format!("# {account}\nsecret={secret_base32}\n");
                Response::Installed {
                    factor_sha256: format!("{:x}", Sha256::digest(bytes.as_bytes())),
                }
            }
            Err(error) => {
                eprintln!("INITIAL_FACTOR_INSTALL code={}", error.code());
                Response::Refused {
                    code: error.code().into(),
                }
            }
        },
    }
}

/// Startup is local and operator-owned. No request supplies paths or identities.
pub(crate) fn run(config_path: &Path) -> Result<(), &'static str> {
    if crate::openbsd::effective_uid() != 0 || crate::openbsd::real_uid() != 0 {
        return Err("INITIAL_FACTOR_PRINCIPAL");
    }
    crate::openbsd::disable_core_dumps().map_err(|_| "INITIAL_FACTOR_CORE")?;
    let raw = crate::admin_config::read_file(config_path, 0, true)
        .map_err(|_| "INITIAL_FACTOR_CONFIG_CUSTODY")?;
    let config: Config =
        serde_json::from_slice(&raw).map_err(|_| "INITIAL_FACTOR_CONFIG_SCHEMA")?;
    if !config_valid(&config) {
        return Err("INITIAL_FACTOR_CONFIG_SCHEMA");
    }
    parent_custody(&config.socket, config.admin_gid)?;
    match fs::symlink_metadata(&config.socket) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("INITIAL_FACTOR_SOCKET_EXISTS"),
    }
    let installer = InitialFactor::new(Paths {
        factors: config.factors.clone(),
        replay: config.replay.clone(),
        runtime_uid: config.runtime_uid,
        runtime_gid: config.runtime_gid,
    });
    installer
        .check_paths()
        .map_err(|_| "INITIAL_FACTOR_PATH_CUSTODY")?;
    let witnesses = [
        config_path.to_str().ok_or("INITIAL_FACTOR_CONFIG_PATH")?,
        config.socket.to_str().ok_or("INITIAL_FACTOR_SOCKET_PATH")?,
        config
            .factors
            .to_str()
            .ok_or("INITIAL_FACTOR_FACTORS_PATH")?,
        config.replay.to_str().ok_or("INITIAL_FACTOR_REPLAY_PATH")?,
    ];
    let custody =
        crate::account_password_custody::Custody::capture(&witnesses, Instant::now() + TIMEOUT)
            .map_err(|_| "INITIAL_FACTOR_ANCESTOR_CUSTODY")?;
    let signals =
        crate::openbsd::AccountAdmissionSignals::install().map_err(|_| "INITIAL_FACTOR_SIGNALS")?;
    // The protected root-owned parent excludes unrelated principals. Set exact
    // socket ownership/mode before accepting or reading any request.
    let listener = UnixListener::bind(&config.socket).map_err(|_| "INITIAL_FACTOR_BIND")?;
    std::os::unix::fs::lchown(&config.socket, None, Some(config.admin_gid))
        .map_err(|_| "INITIAL_FACTOR_SOCKET_GROUP")?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))
        .map_err(|_| "INITIAL_FACTOR_SOCKET_MODE")?;
    let identity = socket_identity(&config.socket, config.admin_gid)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "INITIAL_FACTOR_LISTENER")?;
    custody
        .recheck(Instant::now() + TIMEOUT)
        .map_err(|_| "INITIAL_FACTOR_ANCESTOR_CHANGED")?;
    let seal = crate::openbsd::seal_initial_factor_service(
        config_path,
        &config.socket,
        &config.factors,
        &config.replay,
    )
    .map_err(|_| "INITIAL_FACTOR_SEAL")?;
    custody
        .activate_initial(&seal)
        .map_err(|_| "INITIAL_FACTOR_ANCESTOR_SEAL")?;
    eprintln!("INITIAL_FACTOR_READY");
    while !signals
        .stop_flag()
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let deadline = Instant::now() + TIMEOUT;
                if crate::openbsd::unix_stream_peer_uid(&stream).ok() != Some(config.admin_uid) {
                    eprintln!("INITIAL_FACTOR_PEER_REFUSED");
                    continue;
                }
                let request = read_frame(&mut stream, FRAME, deadline)
                    .map_err(|_| ())
                    .and_then(|raw| terminal_eof(&mut stream, deadline).map(|()| raw))
                    .and_then(|raw| serde_json::from_slice::<Request>(&raw).map_err(|_| ()));
                let response = match request {
                    Ok(request) => dispatch(&config, &installer, request, deadline),
                    Err(()) => {
                        eprintln!("INITIAL_FACTOR_FRAME_REFUSED");
                        Response::Refused {
                            code: "invalid".into(),
                        }
                    }
                };
                if let Ok(raw) = serde_json::to_vec(&response) {
                    if write_frame(&mut stream, &raw, deadline).is_err() {
                        eprintln!("INITIAL_FACTOR_RESPONSE_UNCONFIRMED");
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return Err("INITIAL_FACTOR_ACCEPT"),
        }
    }
    if socket_identity(&config.socket, config.admin_gid)? != identity {
        return Err("INITIAL_FACTOR_SOCKET_CHANGED");
    }
    fs::remove_file(&config.socket).map_err(|error| {
        eprintln!(
            "INITIAL_FACTOR_SOCKET_RETAINED errno={}",
            error
                .raw_os_error()
                .filter(|value| (1..=4095).contains(value))
                .unwrap_or(0)
        );
        "INITIAL_FACTOR_SOCKET_RETAINED"
    })?;
    eprintln!("INITIAL_FACTOR_STOPPED");
    Ok(())
}

fn endpoint(socket: &Path) -> Result<(u64, u64, u64, u64), ()> {
    let parent = socket.parent().ok_or(())?;
    let p = fs::symlink_metadata(parent).map_err(|_| ())?;
    let s = fs::symlink_metadata(socket).map_err(|_| ())?;
    if !p.is_dir()
        || p.file_type().is_symlink()
        || p.uid() != 0
        || p.mode() & 0o022 != 0
        || !s.file_type().is_socket()
        || s.file_type().is_symlink()
        || s.uid() != 0
        || s.mode() & 0o007 != 0
        || s.nlink() != 1
    {
        return Err(());
    }
    Ok((p.dev(), p.ino(), s.dev(), s.ino()))
}

fn exchange(socket: &Path, request: Request, deadline: Instant) -> Result<Response, ()> {
    let before = endpoint(socket)?;
    let mut stream = crate::openbsd::connect_unix_before(socket, deadline).map_err(|_| ())?;
    if crate::openbsd::unix_stream_peer_uid(&stream).map_err(|_| ())? != 0
        || endpoint(socket)? != before
    {
        return Err(());
    }
    let raw = serde_json::to_vec(&request).map_err(|_| ())?;
    if raw.len() > FRAME {
        return Err(());
    }
    write_frame(&mut stream, &raw, deadline).map_err(|_| ())?;
    stream.shutdown(Shutdown::Write).map_err(|_| ())?;
    let raw = read_frame(&mut stream, FRAME, deadline).map_err(|_| ())?;
    terminal_eof(&mut stream, deadline)?;
    serde_json::from_slice(&raw).map_err(|_| ())
}

/// The admin service must first prove its SQL/one-use setup authority. This
/// client only binds the fixed root-owned local factor endpoint.
pub(crate) fn check_absent(socket: &Path, account: &str, deadline: Instant) -> Result<(), ()> {
    crate::account_admission::valid_account(account).map_err(|_| ())?;
    match exchange(
        socket,
        Request::Check {
            account: account.into(),
        },
        deadline,
    )? {
        Response::Ready {} => Ok(()),
        _ => Err(()),
    }
}

pub(crate) fn install(
    socket: &Path,
    account: &str,
    secret_base32: &str,
    accepted_counter: u64,
    deadline: Instant,
) -> Result<String, ()> {
    crate::account_admission::valid_account(account).map_err(|_| ())?;
    if secret_base32.len() > 64 {
        return Err(());
    }
    match exchange(
        socket,
        Request::Install {
            account: account.into(),
            secret_base32: secret_base32.into(),
            accepted_counter,
        },
        deadline,
    )? {
        Response::Installed { factor_sha256 }
            if factor_sha256.len() == 64
                && factor_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            Ok(factor_sha256)
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::Response;

    #[test]
    fn ready_response_rejects_extra_fields() {
        assert!(matches!(
            serde_json::from_slice::<Response>(br#"{"status":"ready"}"#),
            Ok(Response::Ready {})
        ));
        assert!(serde_json::from_slice::<Response>(
            br#"{"status":"ready","factor_sha256":"unexpected"}"#
        )
        .is_err());
    }
}
