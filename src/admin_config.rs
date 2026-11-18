//! Protected startup configuration for the two private admin roles.
//! No browser/request supplies these paths, UIDs or SQL options.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_CONFIG: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid,
    Unavailable,
    Custody,
    ConfigFile,
    ConfigSchema,
    Role,
    State,
    Listener,
    ServiceSocket,
    SqlProfileCustody,
    SqlProfileOptions,
    SqlSocket,
    Origin,
}

impl Error {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
            Self::Custody => "custody",
            Self::ConfigFile => "config_file",
            Self::ConfigSchema => "config_schema",
            Self::Role => "role",
            Self::State => "state",
            Self::Listener => "listener",
            Self::ServiceSocket => "service_socket",
            Self::SqlProfileCustody => "sql_profile_custody",
            Self::SqlProfileOptions => "sql_profile_options",
            Self::SqlSocket => "sql_socket",
            Self::Origin => "origin",
        }
    }
}

// Configuration and profile contents intentionally have no Debug/Serialize.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceConfig {
    pub(crate) state: PathBuf,
    pub(crate) socket: PathBuf,
    pub(crate) web_uid: u32,
    pub(crate) sql_profile: PathBuf,
    pub(crate) database: String,
    pub(crate) sql_socket: PathBuf,
    pub(crate) sql_socket_uid: u32,
    #[serde(default)]
    pub(crate) writer: Option<WriterConfig>,
}

/// Explicit local operator opt-in. Never populated from HTTP or RPC.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WriterConfig {
    pub(crate) profile: PathBuf,
    pub(crate) holder: String,
    pub(crate) epoch: u64,
    pub(crate) domains: Vec<String>,
    pub(crate) administrators: Vec<String>,
    /// Explicit adopted domain-limit unit; mailbox quota is always bytes.
    pub(crate) domain_quota_unit_bytes: u32,
    #[serde(default)]
    pub(crate) onboarding: Option<OnboardingConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OnboardingConfig {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebInput {
    socket: PathBuf,
    proxy_uid: u32,
    service_socket: PathBuf,
    service_uid: u32,
    origin: String,
}

pub(crate) struct WebConfig {
    pub(crate) socket: PathBuf,
    pub(crate) proxy_uid: u32,
    pub(crate) service_socket: PathBuf,
    pub(crate) service_uid: u32,
    pub(crate) origin: String,
    pub(crate) host: String,
}

type FileIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn identity(metadata: &fs::Metadata) -> FileIdentity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn exact(path: &Path, owner: u32) -> Result<(), Error> {
    crate::openpgp_inventory_runtime::custody::exact_path(path, owner).map_err(|_| Error::Custody)
}

fn file_shape(metadata: &fs::Metadata, owner: u32, config: bool) -> bool {
    let mode = metadata.mode() & 0o7777;
    metadata.is_file()
        && metadata.uid() == owner
        && metadata.nlink() == 1
        && metadata.len() <= MAX_CONFIG
        && if config {
            mode == 0o600 || (mode == 0o640 && metadata.gid() == crate::openbsd::effective_gid())
        } else {
            mode == 0o600
        }
}

pub(crate) fn read_file(path: &Path, owner: u32, config: bool) -> Result<Vec<u8>, Error> {
    // Root-owned startup files may reside below the role's protected namespace.
    exact(path, crate::openbsd::effective_uid())?;
    let initial = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !file_shape(&initial, owner, config) {
        return Err(Error::Custody);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    let opened = file.metadata().map_err(|_| Error::Unavailable)?;
    if identity(&opened) != identity(&initial) {
        return Err(Error::Custody);
    }
    let mut raw = Vec::new();
    file.by_ref()
        .take(MAX_CONFIG + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Error::Unavailable)?;
    let after = file.metadata().map_err(|_| Error::Unavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if raw.len() as u64 > MAX_CONFIG
        || identity(&after) != identity(&initial)
        || identity(&named) != identity(&initial)
    {
        return Err(Error::Custody);
    }
    Ok(raw)
}

fn private_dir(path: &Path, owner: u32, modes: &[u32]) -> Result<(), Error> {
    exact(path, owner)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != owner || !modes.contains(&(metadata.mode() & 0o7777))
    {
        return Err(Error::Custody);
    }
    Ok(())
}

fn new_socket(path: &Path, owner: u32) -> Result<(), Error> {
    if !path.is_absolute() || path.as_os_str().len() > 100 || path.file_name().is_none() {
        return Err(Error::Invalid);
    }
    let parent = path.parent().ok_or(Error::Invalid)?;
    private_dir(parent, owner, &[0o700, 0o750])?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Error::Custody),
        Err(_) => Err(Error::Unavailable),
    }
}

fn sql_socket(path: &Path, owner: u32) -> Result<(), Error> {
    if path.as_os_str().len() > 100 {
        return Err(Error::Invalid);
    }
    exact(path, owner)?;
    private_dir(path.parent().ok_or(Error::Invalid)?, owner, &[0o700, 0o750])?;
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    // MariaDB may use 0777 on the socket while its 0750 parent controls access.
    // The selected server UID and protected parent, not a guessed daemon group
    // or version-specific leaf permission, establish this native boundary.
    if !metadata.file_type().is_socket() || metadata.uid() != owner || metadata.nlink() != 1 {
        return Err(Error::Custody);
    }
    Ok(())
}

fn database_valid(database: &str) -> bool {
    !database.is_empty()
        && database.len() <= 64
        && database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// The trusted profile uses one client group and only authentication/socket
/// options. Includes, init commands, plugin/library paths, TCP and output files
/// cannot be smuggled through MariaDB's defaults-file mechanism.
fn profile_options(raw: &[u8], expected_socket: &Path) -> Result<(), Error> {
    if raw.contains(&0) || raw.len() as u64 > MAX_CONFIG {
        return Err(Error::Invalid);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Error::Invalid)?;
    let mut fields = BTreeMap::new();
    let mut group_seen = false;
    for line in text.lines() {
        // Inspect before trimming so a control character at a value's edge is
        // rejected rather than silently removed. CRLF is a line terminator,
        // which str::lines has already consumed.
        if line.chars().any(char::is_control) {
            return Err(Error::Invalid);
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line == "[client]" && !group_seen {
            group_seen = true;
            continue;
        }
        if !group_seen || line.starts_with('[') {
            return Err(Error::Invalid);
        }
        let (key, value) = line.split_once('=').ok_or(Error::Invalid)?;
        if fields.insert(key.trim(), value.trim()).is_some() {
            return Err(Error::Invalid);
        }
    }
    if fields.len() != 4 {
        return Err(Error::Invalid);
    }
    let user = fields.get("user").ok_or(Error::Invalid)?;
    let password = fields.get("password").ok_or(Error::Invalid)?;
    let protocol = fields.get("protocol").ok_or(Error::Invalid)?;
    let socket = fields.get("socket").ok_or(Error::Invalid)?;
    if user.is_empty()
        || user.len() > 64
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        || password.is_empty()
        || password.len() > 512
        || password.chars().any(char::is_control)
        || !protocol.eq_ignore_ascii_case("SOCKET")
        || Some(*socket) != expected_socket.to_str()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Only leaf metadata is touched after confinement; startup performs ancestry,
/// canonical-path and option-content checks. Callers may additionally pin bytes.
pub(crate) fn verify_sql_profile(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::SqlProfileCustody)?;
    if !file_shape(&metadata, crate::openbsd::effective_uid(), false) {
        return Err(Error::SqlProfileCustody);
    }
    Ok(())
}

pub(crate) fn load_service(path: &Path) -> Result<ServiceConfig, Error> {
    let raw = read_file(path, 0, true).map_err(|_| Error::ConfigFile)?;
    let config: ServiceConfig = serde_json::from_slice(&raw).map_err(|_| Error::ConfigSchema)?;
    let own = crate::openbsd::effective_uid();
    if own == 0
        || config.web_uid == 0
        || config.web_uid == own
        || config.sql_socket_uid == own
        || config.sql_socket_uid == config.web_uid
        || !database_valid(&config.database)
    {
        return Err(Error::Role);
    }
    private_dir(&config.state, own, &[0o700]).map_err(|_| Error::State)?;
    new_socket(&config.socket, own).map_err(|_| Error::Listener)?;
    verify_sql_profile(&config.sql_profile)?;
    let profile =
        read_file(&config.sql_profile, own, false).map_err(|_| Error::SqlProfileCustody)?;
    profile_options(&profile, &config.sql_socket).map_err(|_| Error::SqlProfileOptions)?;
    sql_socket(&config.sql_socket, config.sql_socket_uid).map_err(|_| Error::SqlSocket)?;
    if let Some(writer) = &config.writer {
        if writer.profile == config.sql_profile
            || writer.holder.len() != 32
            || !writer.holder.bytes().all(|b| b.is_ascii_hexdigit())
            || writer.epoch == 0
            || writer.domains.is_empty()
            || writer.domains.len() > 16
            || writer.administrators.is_empty()
            || writer.administrators.len() > 16
            || !matches!(writer.domain_quota_unit_bytes, 1_024_000 | 1_048_576)
            || writer.administrators.iter().any(|s| {
                s.is_empty()
                    || s.len() > 96
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"@._-".contains(&b))
            })
            || crate::admin_directory::Scope::domains(
                &writer
                    .domains
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
            .is_err()
        {
            return Err(Error::Invalid);
        }
        let profile = read_file(&writer.profile, own, false)?;
        profile_options(&profile, &config.sql_socket)?;
    }
    Ok(config)
}

fn origin_host(origin: &str) -> Result<String, Error> {
    let host = origin.strip_prefix("https://").ok_or(Error::Invalid)?;
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.contains(['/', '?', '#', '@', '\\'])
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(Error::Invalid);
    }
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    if name.is_empty()
        || name.len() > 253
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || port.is_some_and(|port| {
            port.is_empty()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
                || !matches!(port.parse::<u16>(), Ok(1..=u16::MAX))
        })
    {
        return Err(Error::Invalid);
    }
    Ok(host.to_owned())
}

pub(crate) fn load_web(path: &Path) -> Result<WebConfig, Error> {
    let raw = read_file(path, 0, true).map_err(|_| Error::ConfigFile)?;
    let input: WebInput = serde_json::from_slice(&raw).map_err(|_| Error::ConfigSchema)?;
    let own = crate::openbsd::effective_uid();
    if !web_roles_valid(own, input.proxy_uid, input.service_uid) {
        return Err(Error::Role);
    }
    new_socket(&input.socket, own).map_err(|_| Error::Listener)?;
    // The transport performs complete service namespace custody preflight before
    // it pins the narrowly unveiled parent for later post-seal exchanges.
    crate::admin_transport::Client::new(input.service_socket.clone(), input.service_uid)
        .map_err(|_| Error::ServiceSocket)?;
    let host = origin_host(&input.origin).map_err(|_| Error::Origin)?;
    Ok(WebConfig {
        socket: input.socket,
        proxy_uid: input.proxy_uid,
        service_socket: input.service_socket,
        service_uid: input.service_uid,
        origin: input.origin,
        host,
    })
}

fn web_roles_valid(own: u32, proxy: u32, service: u32) -> bool {
    own != 0 && proxy == own && service != 0 && service != own
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0_u8; 12];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("osmap-admin-config-{suffix}"));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "ADMIN_CONFIG_TEST_FIXTURE_RETAINED root={}",
                    self.0.display()
                );
            } else {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    #[test]
    fn root_loader_policy_is_separate_from_unprivileged_fixture_reader() {
        let f = Fixture::new();
        let path = f.file("operator.json", b"{}", 0o600);
        let own = crate::openbsd::effective_uid();
        assert_eq!(read_file(&path, own, true).unwrap(), b"{}");
        if own != 0 {
            assert!(matches!(load_service(&path), Err(Error::ConfigFile)));
            assert!(matches!(load_web(&path), Err(Error::ConfigFile)));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(read_file(&path, own, true), Err(Error::Custody)));
    }

    #[test]
    fn config_reader_rejects_links_oversize_and_unsafe_group() {
        let f = Fixture::new();
        let path = f.file("operator.json", b"{}", 0o600);
        let own = crate::openbsd::effective_uid();
        let alias = f.0.join("linked.json");
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(read_file(&path, own, true), Err(Error::Custody)));
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_file(&alias, own, true).is_err());
        let oversized = f.file(
            "oversized.json",
            &vec![b' '; MAX_CONFIG as usize + 1],
            0o600,
        );
        assert!(matches!(
            read_file(&oversized, own, true),
            Err(Error::Custody)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert!(file_shape(&metadata, own, true));
        assert!(!file_shape(&metadata, own, false));
    }

    #[test]
    fn strict_config_schema_rejects_runtime_selected_host_or_commands() {
        let web = r#"{"socket":"/private/web.sock","proxy_uid":1001,"service_socket":"/private/service.sock","service_uid":1002,"origin":"https://localhost:8443"}"#;
        assert!(serde_json::from_str::<WebInput>(web).is_ok());
        for field in [
            r#", "host":"attacker.test""#,
            r#", "command":"/usr/bin/false""#,
        ] {
            let raw = format!("{}{}{}", &web[..web.len() - 1], field, "}");
            assert!(serde_json::from_str::<WebInput>(&raw).is_err());
        }
        assert!(!database_valid("authority; DROP TABLE admin"));
        assert!(!database_valid(""));
        assert!(!database_valid(&"a".repeat(65)));
        assert!(database_valid("osmap_admin_fixture"));
        assert!(web_roles_valid(1001, 1001, 1002));
        assert!(!web_roles_valid(1001, 1003, 1002));
        assert!(!web_roles_valid(1001, 1001, 1001));
        assert!(!web_roles_valid(0, 0, 1002));
    }

    #[test]
    fn profile_allows_only_the_declared_local_authentication_options() {
        let socket = Path::new("/private/mysql.sock");
        let good = b"[client]\nuser=osmap_reader\npassword=synthetic-private-password\nprotocol=SOCKET\nsocket=/private/mysql.sock\n";
        assert_eq!(profile_options(good, socket), Ok(()));
        let punctuation = String::from_utf8(good.to_vec()).unwrap().replace(
            "synthetic-private-password",
            r#""synthetic!$:#;=\\\"password""#,
        );
        assert_eq!(profile_options(punctuation.as_bytes(), socket), Ok(()));
        for password in ["\tpassword", "password\t", "pass\rword", "pass\0word"] {
            let raw = String::from_utf8(good.to_vec())
                .unwrap()
                .replace("synthetic-private-password", password);
            assert_eq!(profile_options(raw.as_bytes(), socket), Err(Error::Invalid));
        }
        for extra in [
            "init-command=forbidden-fixture-option\n",
            "plugin-dir=/tmp/attacker\n",
            "!include /tmp/other.cnf\n",
            "[mysql]\n",
            "password=replaced\n",
            "host=example.test\n",
        ] {
            let mut raw = good.to_vec();
            raw.extend_from_slice(extra.as_bytes());
            assert_eq!(profile_options(&raw, socket), Err(Error::Invalid));
        }
        assert_eq!(
            profile_options(good, Path::new("/private/other.sock")),
            Err(Error::Invalid)
        );
        let tcp = String::from_utf8(good.to_vec())
            .unwrap()
            .replace("SOCKET", "TCP");
        assert_eq!(profile_options(tcp.as_bytes(), socket), Err(Error::Invalid));
    }

    #[test]
    fn origins_are_https_authorities_without_ambient_url_components() {
        for good in [
            "https://localhost:8443",
            "https://mail.blackbagsecurity.com",
            "https://127.0.0.1:443",
        ] {
            assert_eq!(
                origin_host(good),
                Ok(good.strip_prefix("https://").unwrap().into())
            );
        }
        for bad in [
            "http://localhost:8443",
            "https://localhost/",
            "https://name@localhost",
            "https://localhost?query=x",
            "https://localhost#fragment",
            "https://localhost:0",
            "https://localhost:65536",
            "https://localhost:443\r\nInjected:x",
            "https://-bad.test",
            "https://localhost:443:80",
        ] {
            assert_eq!(origin_host(bad), Err(Error::Invalid));
        }
    }

    #[test]
    fn fresh_listener_and_profile_leaf_checks_preserve_existing_objects() {
        let f = Fixture::new();
        let path = f.0.join("web.sock");
        assert_eq!(new_socket(&path, crate::openbsd::effective_uid()), Ok(()));
        fs::write(&path, b"preserve").unwrap();
        assert_eq!(
            new_socket(&path, crate::openbsd::effective_uid()),
            Err(Error::Custody)
        );
        assert_eq!(fs::read(&path).unwrap(), b"preserve");
        let profile = f.file("client.cnf", b"private", 0o600);
        assert_eq!(verify_sql_profile(&profile), Ok(()));
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(verify_sql_profile(&profile), Err(Error::SqlProfileCustody));
    }
}
