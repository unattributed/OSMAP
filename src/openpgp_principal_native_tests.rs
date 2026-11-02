//! Explicit ignored native qualification; fixed existing UIDs, disposable state.
//! No account database administration, interpreter, or UID-wide process cleanup.
use crate::auth::{principal_fixture_command, PrincipalFixtureProgram as Program};
use crate::openbsd::{openpgp_fixture_child_profile, OpenPgpFixtureRole as Role};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

type Identity = (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64);
type Result<T> = std::result::Result<T, &'static str>;
const CRYPTO_CLIENT: &str = "openpgp_crypto_runtime::tests::native_crypto_principal_client";
const INVENTORY_CLIENT: &str =
    "openpgp_inventory_runtime::tests::native_inventory_principal_client";
const ADMIN_CLIENT: &str =
    "openpgp_public_admin_runtime::tests::native_public_admin_principal_client";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    test_binary: Artifact,
    crypto_helper: Artifact,
    inventory_helper: Artifact,
    admin_helper: Artifact,
    crypto_worker: Artifact,
    inventory_worker: Artifact,
    engine: Artifact,
    crypto_probe: Artifact,
    inventory_probe: Artifact,
    confinement_probe: Artifact,
    #[serde(default)]
    previous_inventory_helper: Option<Artifact>,
}
fn require(value: bool, code: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(code)
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn artifact_bytes(artifact: &Artifact) -> Result<Vec<u8>> {
    require(
        artifact.path.is_absolute()
            && artifact.path.canonicalize().ok().as_ref() == Some(&artifact.path),
        "ARTIFACT_PATH_REFUSED",
    )?;
    require(
        artifact.sha256.len() == 64
            && artifact
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "ARTIFACT_PIN_REFUSED",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&artifact.path)
        .map_err(|_| "ARTIFACT_OPEN_REFUSED")?;
    let before = file.metadata().map_err(|_| "ARTIFACT_METADATA_REFUSED")?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.mode() & 0o6022 == 0
            && before.mode() & 0o111 != 0
            && before.len() <= 256 * 1024 * 1024,
        "ARTIFACT_CUSTODY_REFUSED",
    )?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "ARTIFACT_READ_REFUSED")?;
    require(
        bytes.len() <= 256 * 1024 * 1024
            && hash(&bytes) == artifact.sha256
            && identity(&file.metadata().map_err(|_| "ARTIFACT_METADATA_REFUSED")?)
                == identity(&before),
        "ARTIFACT_PIN_MISMATCH",
    )?;
    Ok(bytes)
}
fn identity(m: &fs::Metadata) -> Identity {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn account_databases() -> Result<BTreeMap<&'static str, Identity>> {
    [
        "/etc/passwd",
        "/etc/master.passwd",
        "/etc/group",
        "/etc/pwd.db",
        "/etc/spwd.db",
    ]
    .into_iter()
    .map(|name| {
        let metadata =
            fs::symlink_metadata(name).map_err(|_| "ACCOUNT_DATABASE_METADATA_UNAVAILABLE")?;
        require(
            metadata.is_file() && metadata.uid() == 0,
            "ACCOUNT_DATABASE_CUSTODY_REFUSED",
        )?;
        Ok((name, identity(&metadata)))
    })
    .collect()
}
struct Fixture {
    root: PathBuf,
    homes: Vec<PathBuf>,
    agent_pids: BTreeMap<PathBuf, u32>,
    shutdown_failure: Option<&'static str>,
    children: Vec<Option<Child>>,
    started: Instant,
    sequence: usize,
    checks: Vec<&'static str>,
    accounts: BTreeMap<&'static str, Identity>,
    cleaning: bool,
    previous_inventory: Option<Vec<u8>>,
    inventory_candidate: Vec<u8>,
}
impl Fixture {
    fn new() -> Result<Self> {
        require(
            std::env::consts::OS == "openbsd"
                && crate::openbsd::effective_uid() == 0
                && crate::openbsd::hostname_matches(b"obsd1.blackbagsecurity.com").unwrap_or(false),
            "NATIVE_TARGET_REFUSED",
        )?;
        crate::openbsd::openpgp_fixture_identities_valid()
            .map_err(|_| "FIXED_PRINCIPALS_REFUSED")?;
        let accounts = account_databases()?;
        let root = PathBuf::from("/tmp").join(format!(
            "osmap-p-{}",
            crate::draft::generate_draft_id().map_err(|_| "RANDOM_UNAVAILABLE")?
        ));
        fs::create_dir(&root).map_err(|_| "SCRATCH_CREATE_REFUSED")?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .map_err(|_| "SCRATCH_MODE_REFUSED")?;
        Ok(Self {
            root,
            homes: vec![],
            agent_pids: BTreeMap::new(),
            shutdown_failure: None,
            children: vec![],
            started: Instant::now(),
            sequence: 0,
            checks: vec![],
            accounts,
            cleaning: false,
            previous_inventory: None,
            inventory_candidate: Vec::new(),
        })
    }
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    fn directory(&self, name: &str, uid: u32, gid: u32, mode: u32) -> Result<PathBuf> {
        let path = self.path(name);
        fs::create_dir(&path).map_err(|_| "DIRECTORY_CREATE_REFUSED")?;
        let file = File::open(&path).map_err(|_| "DIRECTORY_OPEN_REFUSED")?;
        crate::openbsd::private_file_set_owner(&file, uid, gid)
            .map_err(|_| "DIRECTORY_OWNER_REFUSED")?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| "DIRECTORY_MODE_REFUSED")?;
        Ok(path)
    }
    fn write(&self, path: &Path, bytes: &[u8], uid: u32, gid: u32, mode: u32) -> Result<()> {
        require(path.starts_with(&self.root), "FIXTURE_PATH_REFUSED")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| "FILE_CREATE_REFUSED")?;
        file.write_all(bytes).map_err(|_| "FILE_WRITE_REFUSED")?;
        crate::openbsd::private_file_set_owner(&file, uid, gid)
            .map_err(|_| "FILE_OWNER_REFUSED")?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| "FILE_MODE_REFUSED")?;
        file.sync_all().map_err(|_| "FILE_SYNC_REFUSED")
    }
    fn prepare(&mut self, artifacts: &Artifacts) -> Result<()> {
        self.directory("helper", 1002, 1003, 0o700)?;
        self.directory("web", 1001, 1001, 0o700)?;
        self.directory("control", 0, 0, 0o700)?;
        self.directory("transport", 1002, 1003, 0o750)?;
        for (name, artifact, uid, mode) in [
            ("libtest", &artifacts.test_binary, 0, 0o755),
            ("crypto-helper", &artifacts.crypto_helper, 0, 0o755),
            ("inventory-helper", &artifacts.inventory_helper, 0, 0o755),
            ("admin-helper", &artifacts.admin_helper, 0, 0o755),
            ("crypto-worker", &artifacts.crypto_worker, 1002, 0o700),
            ("inventory-worker", &artifacts.inventory_worker, 1002, 0o700),
            ("engine", &artifacts.engine, 1002, 0o700),
            ("crypto-probe", &artifacts.crypto_probe, 1002, 0o700),
            ("inventory-probe", &artifacts.inventory_probe, 1002, 0o700),
            (
                "confinement-probe",
                &artifacts.confinement_probe,
                1002,
                0o700,
            ),
        ] {
            let bytes = artifact_bytes(artifact)?;
            self.write(
                &self.path(name),
                &bytes,
                uid,
                if uid == 1002 { 1003 } else { uid },
                mode,
            )?;
            require(
                hash(&fs::read(self.path(name)).map_err(|_| "COPIED_ARTIFACT_UNAVAILABLE")?)
                    == artifact.sha256,
                "COPIED_PIN_MISMATCH",
            )?;
        }
        self.inventory_candidate = artifact_bytes(&artifacts.inventory_helper)?;
        self.previous_inventory = artifacts
            .previous_inventory_helper
            .as_ref()
            .map(artifact_bytes)
            .transpose()?;
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| "RANDOM_UNAVAILABLE")?;
        for (name, uid, gid) in [
            ("helper", 1002, 1003),
            ("web", 1001, 1001),
            ("control", 0, 0),
        ] {
            self.write(&self.path(name).join("grant"), &key, uid, gid, 0o600)?;
        }
        Ok(())
    }
    fn command(&self, program: Program<'_>, role: Role) -> Result<Command> {
        let mut command = principal_fixture_command(program).map_err(|_| "COMMAND_REFUSED")?;
        openpgp_fixture_child_profile(&mut command, role);
        command
            .env("GNUPGHOME", self.path("NEVER_DEFAULT"))
            .env("HOME", self.path("helper"));
        Ok(command)
    }
    fn raw(&mut self, command: Command, input: &[u8]) -> Result<(Vec<u8>, bool)> {
        let deadline = (self.started + Duration::from_secs(if self.cleaning { 330 } else { 240 }))
            .min(Instant::now() + Duration::from_secs(10));
        let (output, success) =
            crate::openpgp_crypto_process::run_native_fixture(command, input, deadline)
                .map_err(|_| "COMMAND_UNCONFIRMED")?;
        self.sequence += 1;
        if !success {
            self.write(
                &self
                    .path("control")
                    .join(format!("failed-{}.stdout", self.sequence)),
                &output,
                0,
                0,
                0o600,
            )?;
            println!(
                "{}",
                serde_json::json!({"phase":"child_refused","stdout_bytes":output.len(),"child_success":success})
            );
        }
        Ok((output, success))
    }
    fn run(&mut self, command: Command, input: &[u8]) -> Result<Vec<u8>> {
        let (output, success) = self.raw(command, input)?;
        require(success, "COMMAND_REFUSED")?;
        Ok(output)
    }
    fn gpg(&mut self, home: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        let mut command = self.command(Program::Gpg, Role::Helper)?;
        command
            .args(["--no-options", "--homedir"])
            .arg(home)
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
            ])
            .args(args);
        self.run(command, input)
    }
    /// Only the reviewed probe's argc2 core mode: it cannot fork an engine.
    /// Streams are null, so direct-child observation cannot block on pipes.
    fn core_probe(&mut self, path: &Path) -> Result<()> {
        require(
            matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("crypto-probe" | "inventory-probe")
            ),
            "CORE_PROBE_PATH_REFUSED",
        )?;
        let mut command = self.command(Program::Probe(path), Role::Helper)?;
        command
            .arg("core")
            .current_dir(self.path("helper"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let child = command.spawn().map_err(|_| "CORE_PROBE_START_REFUSED")?;
        let index = self.children.len();
        self.children.push(Some(child));
        let mut expired = false;
        let result: Result<std::process::ExitStatus> = (|| {
            let child = self.children[index]
                .as_mut()
                .ok_or("CORE_PROBE_CHILD_UNAVAILABLE")?;
            let pid = child.id();
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                if crate::openbsd::owned_child_exited_without_reap(pid)
                    .map_err(|_| "CORE_PROBE_OWNERSHIP_UNCONFIRMED")?
                {
                    break;
                }
                if Instant::now() >= until {
                    crate::openbsd::kill_process_group(pid)
                        .map_err(|_| "CORE_PROBE_STOP_UNCONFIRMED")?;
                    expired = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            let reap_until = Instant::now() + Duration::from_secs(1);
            let status = loop {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|_| "CORE_PROBE_REAP_UNCONFIRMED")?
                {
                    break status;
                }
                require(Instant::now() < reap_until, "CORE_PROBE_REAP_UNCONFIRMED")?;
                std::thread::sleep(Duration::from_millis(2));
            };
            require(
                !crate::openbsd::process_group_exists(pid)
                    .map_err(|_| "CORE_PROBE_ABSENCE_UNCONFIRMED")?,
                "CORE_PROBE_ABSENCE_UNCONFIRMED",
            )?;
            Ok(status)
        })();
        if result.is_ok() {
            self.children[index] = None;
        }
        let status = result?;
        require(
            !expired && status.signal() == Some(libc::SIGABRT) && !status.core_dumped(),
            "CORE_PROBE_REFUSED",
        )?;
        require(
            !self.path("helper/crypto-probe.core").exists()
                && !self.path("helper/inventory-probe.core").exists()
                && !self.path("helper/core").exists(),
            "CORE_ARTIFACT_PRESENT",
        )
    }

    fn publish_inventory(&self, bytes: &[u8]) -> Result<()> {
        let staged = self.path("inventory-publication");
        self.write(&staged, bytes, 0, 0, 0o755)?;
        fs::rename(staged, self.path("inventory-helper")).map_err(|_| "FIXTURE_PUBLICATION_REFUSED")
    }
    fn keys(&mut self, exchange: bool) -> Result<(String, String)> {
        for name in ["alice", "bob"] {
            let home = self.directory(&format!("helper/{name}"), 1002, 1003, 0o700)?;
            self.homes.push(home.clone());
            self.gpg(
                &home,
                &[
                    "--quick-generate-key",
                    &format!("Synthetic {name} <{name}@fixture.test>"),
                    "ed25519",
                    "cert,sign",
                    "0",
                ],
                b"\n",
            )?;
            let listing = self.gpg(&home, &["--with-colons", "--list-keys"], b"\n")?;
            let fp = std::str::from_utf8(&listing)
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find(|line| line.starts_with("fpr:"))
                        .and_then(|line| line.split(':').nth(9))
                })
                .ok_or("FINGERPRINT_UNAVAILABLE")?
                .to_owned();
            require(
                crate::openpgp_crypto::full_fingerprint(&fp) && fp.len() == 40,
                "FINGERPRINT_REFUSED",
            )?;
            self.gpg(
                &home,
                &["--quick-add-key", &fp, "cv25519", "encrypt", "0"],
                b"\n",
            )?;
            let mut agent = self.command(Program::GpgConnectAgent, Role::Helper)?;
            agent
                .args(["--no-autostart", "--homedir"])
                .arg(&home)
                .args(["GETINFO pid", "/bye"]);
            let output = self.run(agent, b"")?;
            self.agent_pids
                .insert(home.clone(), parse_agent_pid(&output)?);
            self.write(
                &self.path("control").join(format!("{name}.fingerprint")),
                fp.as_bytes(),
                0,
                0,
                0o600,
            )?;
        }
        let a = fs::read_to_string(self.path("control/alice.fingerprint"))
            .map_err(|_| "FINGERPRINT_UNAVAILABLE")?;
        let b = fs::read_to_string(self.path("control/bob.fingerprint"))
            .map_err(|_| "FINGERPRINT_UNAVAILABLE")?;
        if exchange {
            for (source, target, fp) in [("bob", "alice", &b), ("alice", "bob", &a)] {
                let public = self.gpg(
                    &self.path(&format!("helper/{source}")),
                    &["--export", fp],
                    b"\n",
                )?;
                let mut command = self.command(Program::Gpg, Role::Helper)?;
                command
                    .args(["--no-options", "--homedir"])
                    .arg(self.path(&format!("helper/{target}")))
                    .args(["--batch", "--import"]);
                self.run(command, &public)?;
            }
        }
        Ok((a, b))
    }
    fn start(&mut self, kind: &str, config: &Path, socket: &Path) -> Result<usize> {
        self.start_checked(kind, config, socket, 0o660)
    }
    fn start_checked(
        &mut self,
        kind: &str,
        config: &Path,
        socket: &Path,
        mode: u32,
    ) -> Result<usize> {
        let binary = self.path(kind);
        let program = match kind {
            "crypto-helper" => Program::CryptoHelper(&binary),
            "inventory-helper" => Program::InventoryHelper(&binary),
            "admin-helper" => Program::AdminHelper(&binary),
            _ => return Err("SERVICE_KIND_REFUSED"),
        };
        let mut command = self.command(program, Role::Helper)?;
        command
            .arg(config)
            .arg(self.path("helper/grant"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let child = command.spawn().map_err(|_| "SERVICE_START_REFUSED")?;
        let index = self.children.len();
        self.children.push(Some(child));
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(metadata) = fs::symlink_metadata(socket) {
                require(
                    metadata.file_type().is_socket()
                        && metadata.uid() == 1002
                        && metadata.gid() == 1003
                        && metadata.mode() & 0o777 == mode,
                    "SERVICE_SOCKET_REFUSED",
                )?;
                crate::openbsd::owned_child_exited_without_reap(
                    self.children[index]
                        .as_ref()
                        .ok_or("SERVICE_CHILD_UNAVAILABLE")?
                        .id(),
                )
                .map_err(|_| "SERVICE_CHILD_UNAVAILABLE")
                .and_then(|exited| require(!exited, "SERVICE_EXITED"))?;
                return Ok(index);
            }
            require(Instant::now() < until, "SERVICE_START_TIMEOUT")?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop(&mut self, index: usize) -> Result<()> {
        let child = self
            .children
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or("SERVICE_CHILD_UNAVAILABLE")?;
        let pid = child.id();
        match crate::openbsd::fixture_t04_terminate_owned_group(pid) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(_) => return Err("SERVICE_TERM_UNCONFIRMED"),
        }
        let term_until = Instant::now() + Duration::from_secs(12);
        let mut forced = false;
        loop {
            if crate::openbsd::owned_child_exited_without_reap(pid)
                .map_err(|_| "SERVICE_OWNERSHIP_UNCONFIRMED")?
            {
                break;
            }
            if Instant::now() >= term_until {
                forced = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Both normal and timeout paths retain the unreaped direct-child lease.
        crate::openbsd::owned_child_exited_without_reap(pid)
            .map_err(|_| "SERVICE_OWNERSHIP_UNCONFIRMED")?;
        match crate::openbsd::kill_process_group(pid) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(_) => return Err("SERVICE_GROUP_STOP_UNCONFIRMED"),
        }
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            if child
                .try_wait()
                .map_err(|_| "SERVICE_REAP_UNCONFIRMED")?
                .is_some()
            {
                break;
            }
            require(Instant::now() < until, "SERVICE_REAP_UNCONFIRMED")?;
            std::thread::sleep(Duration::from_millis(5));
        }
        while crate::openbsd::process_group_exists(pid)
            .map_err(|_| "SERVICE_ABSENCE_UNCONFIRMED")?
        {
            require(Instant::now() < until, "SERVICE_ABSENCE_UNCONFIRMED")?;
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut logs_safe = true;
        for mut output in [
            child.stdout.take().map(|p| Box::new(p) as Box<dyn Read>),
            child.stderr.take().map(|p| Box::new(p) as Box<dyn Read>),
        ]
        .into_iter()
        .flatten()
        {
            let mut bytes = Vec::new();
            if output.by_ref().take(8193).read_to_end(&mut bytes).is_err()
                || bytes.len() > 8192
                || bytes
                    .windows(b"disposable principal fixture".len())
                    .any(|part| part == b"disposable principal fixture")
            {
                logs_safe = false;
            }
        }
        self.children[index] = None;
        if forced {
            self.shutdown_failure = Some("SERVICE_STOP_TIMEOUT");
            return Err("SERVICE_STOP_TIMEOUT");
        }
        require(logs_safe, "SERVICE_LOG_REFUSED")
    }
    fn remove_stopped_socket(&self, path: &Path) -> Result<()> {
        let before = fs::symlink_metadata(path).map_err(|_| "STOPPED_SOCKET_UNAVAILABLE")?;
        require(
            path.parent() == Some(self.path("transport").as_path())
                && before.file_type().is_socket()
                && before.uid() == 1002
                && before.gid() == 1003,
            "STOPPED_SOCKET_CUSTODY_REFUSED",
        )?;
        require(
            UnixStream::connect(path).is_err_and(|e| e.raw_os_error() == Some(libc::ECONNREFUSED)),
            "STOPPED_SOCKET_STILL_LIVE",
        )?;
        require(
            identity(&fs::symlink_metadata(path).map_err(|_| "STOPPED_SOCKET_UNAVAILABLE")?)
                == identity(&before),
            "STOPPED_SOCKET_REPLACED",
        )?;
        fs::remove_file(path).map_err(|_| "STOPPED_SOCKET_REMOVE_REFUSED")
    }
    fn client(&mut self, selector: &str, env: &[(&str, String)], root_peer: bool) -> Result<()> {
        require(
            [CRYPTO_CLIENT, INVENTORY_CLIENT, ADMIN_CLIENT].contains(&selector),
            "CLIENT_SELECTOR_REFUSED",
        )?;
        let binary = self.path("libtest");
        let mut command = self.command(
            Program::Libtest(&binary),
            if root_peer { Role::Root } else { Role::Web },
        )?;
        command.args([selector, "--exact", "--ignored", "--test-threads=1"]);
        for (name, value) in env {
            command.env(name, value);
        }
        let output = self.run(command, b"")?;
        require(
            output
                .windows(b"1 passed; 0 failed".len())
                .any(|part| part == b"1 passed; 0 failed"),
            "EXACT_CLIENT_COUNT_REFUSED",
        )
    }
    fn reachable_root_peer(&self, socket: &Path) -> Result<()> {
        require(
            fs::read(self.path("control/grant")).map_err(|_| "ROOT_GRANT_UNAVAILABLE")?
                == fs::read(self.path("web/grant")).map_err(|_| "WEB_GRANT_UNAVAILABLE")?,
            "SYNTHETIC_GRANT_MISMATCH",
        )?;
        let stream =
            crate::openbsd::connect_unix_before(socket, Instant::now() + Duration::from_secs(1))
                .map_err(|_| "ROOT_TRANSPORT_UNREACHABLE")?;
        require(
            crate::openbsd::unix_stream_peer_uid(&stream).ok() == Some(1002),
            "ROOT_TRANSPORT_PEER_REFUSED",
        )
    }
    fn cleanup(&mut self) -> Result<()> {
        self.cleaning = true;
        let mut clean = true;
        for index in (0..self.children.len()).rev() {
            if self.children[index].is_some() {
                match self.stop(index) {
                    Ok(()) => {}
                    Err("SERVICE_STOP_TIMEOUT") if self.children[index].is_none() => {}
                    Err(_) => clean = false,
                }
            }
        }
        for home in self.homes.clone() {
            let metadata = match fs::symlink_metadata(&home) {
                Ok(metadata) => metadata,
                Err(_) => {
                    clean = false;
                    continue;
                }
            };
            if !home.starts_with(self.path("helper"))
                || home.canonicalize().ok().as_ref() != Some(&home)
                || !metadata.is_dir()
                || metadata.uid() != 1002
                || metadata.gid() != 1003
                || metadata.mode() & 0o777 != 0o700
            {
                clean = false;
                continue;
            }
            let mut command = self.command(Program::Gpgconf, Role::Helper)?;
            command
                .args(["--homedir"])
                .arg(&home)
                .args(["--kill", "gpg-agent"]);
            if self.run(command, b"").is_err() {
                clean = false;
            }
            let until = Instant::now() + Duration::from_secs(2);
            let pid = self.agent_pids.get(&home).copied();
            if pid.is_none() {
                clean = false;
            }
            loop {
                let absent = pid
                    .map(crate::openbsd::openpgp_fixture_process_exists)
                    .transpose();
                let gone = matches!(absent, Ok(Some(false))) && !home.join("S.gpg-agent").exists();
                if gone {
                    break;
                }
                if absent.is_err() || Instant::now() >= until {
                    clean = false;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        require(
            account_databases()? == self.accounts,
            "ACCOUNT_DATABASE_CHANGED",
        )?;
        require(!self.path("NEVER_DEFAULT").exists(), "DEFAULT_HOME_CREATED")?;
        require(clean, "CLEANUP_UNCONFIRMED")
    }
}
fn crypto_environment(
    f: &Fixture,
    a: &str,
    b: &str,
    root_peer: bool,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "OSMAP_CRYPTO_PRINCIPAL_SOCKET",
            f.path("transport/crypto.sock").display().to_string(),
        ),
        (
            "OSMAP_CRYPTO_PRINCIPAL_INVENTORY_SOCKET",
            f.path("transport/inventory.sock").display().to_string(),
        ),
        (
            "OSMAP_CRYPTO_PRINCIPAL_KEY",
            f.path(if root_peer {
                "control/grant"
            } else {
                "web/grant"
            })
            .display()
            .to_string(),
        ),
        ("OSMAP_CRYPTO_PRINCIPAL_HELPER_UID", "1002".into()),
        ("OSMAP_CRYPTO_PRINCIPAL_ALICE_FP", a.into()),
        ("OSMAP_CRYPTO_PRINCIPAL_BOB_FP", b.into()),
        (
            "OSMAP_CRYPTO_PRINCIPAL_ALICE_HOME",
            f.path("helper/alice").display().to_string(),
        ),
        (
            "OSMAP_CRYPTO_PRINCIPAL_BOB_HOME",
            f.path("helper/bob").display().to_string(),
        ),
        (
            "OSMAP_CRYPTO_PRINCIPAL_MODE",
            if root_peer {
                "peer_denied"
            } else {
                "authorized"
            }
            .into(),
        ),
    ]
}
fn protected_manifest(f: &Fixture) -> Result<BTreeMap<PathBuf, String>> {
    let mut result = BTreeMap::new();
    for home in &f.homes {
        result.insert(
            home.join("trustdb.gpg"),
            hash(&fs::read(home.join("trustdb.gpg")).map_err(|_| "TRUSTDB_READ_REFUSED")?),
        );
        for entry in
            fs::read_dir(home.join("private-keys-v1.d")).map_err(|_| "PRIVATE_MANIFEST_REFUSED")?
        {
            let path = entry.map_err(|_| "PRIVATE_MANIFEST_REFUSED")?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| "PRIVATE_MANIFEST_REFUSED")?;
            require(
                metadata.is_file()
                    && metadata.uid() == 1002
                    && metadata.gid() == 1003
                    && metadata.mode() & 0o077 == 0
                    && metadata.len() <= 65536,
                "PRIVATE_MANIFEST_CUSTODY_REFUSED",
            )?;
            result.insert(
                path.clone(),
                hash(&fs::read(path).map_err(|_| "PRIVATE_MANIFEST_REFUSED")?),
            );
        }
    }
    Ok(result)
}
fn write_config(f: &Fixture, name: &str, value: serde_json::Value) -> Result<PathBuf> {
    let path = f.path(&format!("helper/{name}.json"));
    f.write(
        &path,
        &serde_json::to_vec(&value).map_err(|_| "CONFIG_SERIALIZATION_REFUSED")?,
        1002,
        1003,
        0o600,
    )?;
    Ok(path)
}
fn crypto_inventory(f: &mut Fixture) -> Result<()> {
    let (a, b) = f.keys(true)?;
    let before = protected_manifest(f)?;
    let accounts = serde_json::json!([
        {"account":"alice","home":f.path("helper/alice"),"signer_fingerprint":a,"decrypt_fingerprints":[a],"recipient_fingerprints":[a,b]},
        {"account":"bob","home":f.path("helper/bob"),"signer_fingerprint":b,"decrypt_fingerprints":[b],"recipient_fingerprints":[a,b]},
    ]);
    let crypto = write_config(
        f,
        "crypto",
        serde_json::json!({"version":1,"worker":f.path("crypto-worker"),"engine":f.path("engine"),"socket":f.path("transport/crypto.sock"),"trusted_web_uid":1001,"accounts":accounts}),
    )?;
    let inventory = write_config(
        f,
        "inventory",
        serde_json::json!({"version":1,"worker":f.path("inventory-worker"),"engine":"/usr/local/bin/gpg","socket":f.path("transport/inventory.sock"),"trusted_web_uid":1001,"accounts":[{"account":"alice","home":f.path("helper/alice")},{"account":"bob","home":f.path("helper/bob")}]}),
    )?;
    let private = before
        .keys()
        .find(|path| {
            path.parent()
                .is_some_and(|parent| parent.ends_with("private-keys-v1.d"))
        })
        .ok_or("PRIVATE_FIXTURE_FILE_UNAVAILABLE")?
        .clone();
    for name in ["crypto-probe", "inventory-probe"] {
        let path = f.path(name);
        let mut command = f.command(Program::Probe(&path), Role::Helper)?;
        command
            .arg(f.path("helper/alice"))
            .arg(f.path("engine"))
            .arg(&private);
        f.run(command, b"")?;
        f.core_probe(&path)?;
    }
    let foreign = f.directory("helper/foreign-agent", 1002, 1003, 0o700)?;
    let foreign_socket = foreign.join("S.gpg-agent");
    let listener =
        UnixListener::bind(&foreign_socket).map_err(|_| "FOREIGN_AGENT_FIXTURE_REFUSED")?;
    let probe = f.path("crypto-probe");
    let mut command = f.command(Program::Probe(&probe), Role::Helper)?;
    command
        .arg(&foreign)
        .arg(f.path("engine"))
        .arg("foreign-agent");
    f.run(command, b"")?;
    drop(listener);
    f.checks.push("foreign_agent_socket_custody_refused");
    let probe = f.path("confinement-probe");
    let mut command = f.command(Program::Probe(&probe), Role::Helper)?;
    command
        .arg(f.path("helper/alice"))
        .arg(f.path("helper/bob/pubring.kbx"));
    f.run(command, b"")?;
    f.checks.push("native_descriptor_core_path_probes");
    f.start("crypto-helper", &crypto, &f.path("transport/crypto.sock"))?;
    let index = f.start(
        "inventory-helper",
        &inventory,
        &f.path("transport/inventory.sock"),
    )?;
    for root_peer in [false, true] {
        if root_peer {
            for name in ["crypto.sock", "inventory.sock"] {
                f.reachable_root_peer(&f.path(&format!("transport/{name}")))?;
            }
        }
        let env = crypto_environment(f, &a, &b, root_peer);
        f.client(CRYPTO_CLIENT, &env, root_peer)?;
        f.client(INVENTORY_CLIENT, &env, root_peer)?;
    }
    f.checks
        .push("actual_crypto_inventory_clients_and_reachable_wrong_peer");
    f.stop(index)?;
    let binary = f.path("inventory-helper");
    let mut collision = f.command(Program::InventoryHelper(&binary), Role::Helper)?;
    collision.arg(&inventory).arg(f.path("helper/grant"));
    let (_, success) = f.raw(collision, b"")?;
    require(!success, "EXISTING_SOCKET_REPLACED")?;
    f.remove_stopped_socket(&f.path("transport/inventory.sock"))?;
    f.start(
        "inventory-helper",
        &inventory,
        &f.path("transport/inventory.sock"),
    )?;
    let env = crypto_environment(f, &a, &b, false);
    f.client(INVENTORY_CLIENT, &env, false)?;
    if let Some(previous) = f.previous_inventory.clone() {
        let index = f.children.len() - 1;
        f.stop(index)?;
        f.remove_stopped_socket(&f.path("transport/inventory.sock"))?;
        f.publish_inventory(&previous)?;
        let index = f.start(
            "inventory-helper",
            &inventory,
            &f.path("transport/inventory.sock"),
        )?;
        f.client(INVENTORY_CLIENT, &env, false)?;
        f.stop(index)?;
        f.remove_stopped_socket(&f.path("transport/inventory.sock"))?;
        f.publish_inventory(&f.inventory_candidate)?;
        f.start(
            "inventory-helper",
            &inventory,
            &f.path("transport/inventory.sock"),
        )?;
        f.client(INVENTORY_CLIENT, &env, false)?;
        f.checks
            .push("previous_inventory_restore_then_candidate_with_actual_clients");
    }

    require(
        protected_manifest(f)? == before,
        "PROTECTED_FIXTURE_CHANGED",
    )?;
    f.checks
        .push("inventory_restart_socket_refusal_and_private_preservation");
    Ok(())
}
fn admin_environment(
    f: &Fixture,
    a: &str,
    b: &str,
    mode: &str,
    root_peer: bool,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_SOCKET",
            f.path("transport/admin.sock").display().to_string(),
        ),
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_KEY",
            f.path(if root_peer {
                "control/grant"
            } else {
                "web/grant"
            })
            .display()
            .to_string(),
        ),
        ("OSMAP_PUBLIC_ADMIN_PRINCIPAL_HELPER_UID", "1002".into()),
        ("OSMAP_PUBLIC_ADMIN_PRINCIPAL_MODE", mode.into()),
        ("OSMAP_PUBLIC_ADMIN_PRINCIPAL_ALICE_FP", a.into()),
        ("OSMAP_PUBLIC_ADMIN_PRINCIPAL_BOB_FP", b.into()),
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_ALICE_HOME",
            f.path("helper/alice").display().to_string(),
        ),
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_BOB_HOME",
            f.path("helper/bob").display().to_string(),
        ),
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_CERTIFICATE",
            f.path("web/public.asc").display().to_string(),
        ),
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_SECRET_CERTIFICATE",
            f.path("web/synthetic-secret.asc").display().to_string(),
        ),
        (
            "OSMAP_PUBLIC_ADMIN_PRINCIPAL_REPLAY_FILE",
            f.path("web/replay").display().to_string(),
        ),
    ]
}
fn public_admin(f: &mut Fixture) -> Result<()> {
    let (a, b) = f.keys(false)?;
    let before = protected_manifest(f)?;
    let public = f.gpg(&f.path("helper/bob"), &["--armor", "--export", &b], b"\n")?;
    let private = f.gpg(
        &f.path("helper/bob"),
        &["--armor", "--export-secret-keys", &b],
        b"\n",
    )?;
    f.write(&f.path("web/public.asc"), &public, 1001, 1001, 0o600)?;
    f.write(
        &f.path("web/synthetic-secret.asc"),
        &private,
        1001,
        1001,
        0o600,
    )?;
    f.directory("helper/admin-state", 1002, 1003, 0o700)?;
    let config = write_config(
        f,
        "admin",
        serde_json::json!({"version":1,"worker":f.path("inventory-worker"),"engine":f.path("engine"),"state_directory":f.path("helper/admin-state"),"socket":f.path("transport/admin.sock"),"trusted_web_uid":1001,"accounts":[{"account":"alice","home":f.path("helper/alice")},{"account":"bob","home":f.path("helper/bob")}]}),
    )?;
    let index = f.start("admin-helper", &config, &f.path("transport/admin.sock"))?;
    let env = admin_environment(f, &a, &b, "authorized", false);
    f.client(ADMIN_CLIENT, &env, false)?;
    let keyboxes = ["alice", "bob"].map(|name| {
        fs::read(f.path(&format!("helper/{name}/pubring.kbx")))
            .map(|bytes| hash(&bytes))
            .map_err(|_| "KEYBOX_READ_REFUSED")
    });
    let keyboxes = [keyboxes[0].clone()?, keyboxes[1].clone()?];
    f.reachable_root_peer(&f.path("transport/admin.sock"))?;
    let env = admin_environment(f, &a, &b, "peer_denied", true);
    f.client(ADMIN_CLIENT, &env, true)?;
    for (index, name) in ["alice", "bob"].into_iter().enumerate() {
        require(
            hash(
                &fs::read(f.path(&format!("helper/{name}/pubring.kbx")))
                    .map_err(|_| "KEYBOX_READ_REFUSED")?,
            ) == keyboxes[index],
            "WRONG_PEER_CHANGED_KEYBOX",
        )?;
    }
    let env = admin_environment(f, &a, &b, "consume_once", false);
    f.client(ADMIN_CLIENT, &env, false)?;
    f.stop(index)?;
    f.remove_stopped_socket(&f.path("transport/admin.sock"))?;
    f.start("admin-helper", &config, &f.path("transport/admin.sock"))?;
    let env = admin_environment(f, &a, &b, "replay_after_restart", false);
    f.client(ADMIN_CLIENT, &env, false)?;
    require(
        protected_manifest(f)? == before,
        "PROTECTED_FIXTURE_CHANGED",
    )?;
    f.checks
        .push("actual_admin_import_remove_cas_private_guard_and_reachable_peer_refusal");
    f.checks
        .push("actual_admin_restart_durable_replay_and_private_preservation");
    Ok(())
}
fn artifacts() -> Result<Artifacts> {
    let path = PathBuf::from(
        std::env::var_os("OSMAP_PRINCIPAL_ARTIFACTS").ok_or("ARTIFACT_MANIFEST_REQUIRED")?,
    );
    let metadata = fs::symlink_metadata(&path).map_err(|_| "MANIFEST_METADATA_REFUSED")?;
    require(
        path.is_absolute()
            && path.canonicalize().ok().as_ref() == Some(&path)
            && metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 8192,
        "MANIFEST_CUSTODY_REFUSED",
    )?;
    let bytes = fs::read(&path).map_err(|_| "MANIFEST_READ_REFUSED")?;
    let artifacts: Artifacts = serde_json::from_slice(&bytes).map_err(|_| "MANIFEST_INVALID")?;
    require(
        hash(
            &fs::read(std::env::current_exe().map_err(|_| "CURRENT_TEST_BINARY_UNAVAILABLE")?)
                .map_err(|_| "CURRENT_TEST_BINARY_UNAVAILABLE")?,
        ) == artifacts.test_binary.sha256,
        "CURRENT_TEST_BINARY_PIN_MISMATCH",
    )?;
    Ok(artifacts)
}
fn parse_agent_pid(output: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(output).map_err(|_| "AGENT_PID_INVALID")?;
    let mut rows = text.lines().filter_map(|line| line.strip_prefix("D "));
    let value = rows.next().ok_or("AGENT_PID_MISSING")?;
    require(
        rows.next().is_none()
            && value.len() <= 10
            && value.bytes().all(|byte| byte.is_ascii_digit()),
        "AGENT_PID_INVALID",
    )?;
    let pid = value.parse::<u32>().map_err(|_| "AGENT_PID_INVALID")?;
    require(pid > 1 && pid <= i32::MAX as u32, "AGENT_PID_INVALID")?;
    Ok(pid)
}
fn qualification(exercise: fn(&mut Fixture) -> Result<()>) {
    let mut fixture = match Fixture::new() {
        Ok(value) => value,
        Err(code) => {
            println!(
                "{}",
                serde_json::json!({"functional":"FAIL","failure":code,"cleanup":"NOT_STARTED"})
            );
            panic!("native principal qualification refused");
        }
    };
    let mut functional = artifacts()
        .and_then(|artifacts| fixture.prepare(&artifacts))
        .and_then(|()| exercise(&mut fixture));
    let cleanup = fixture.cleanup();
    if functional.is_ok() {
        if let Some(code) = fixture.shutdown_failure {
            functional = Err(code);
        }
    }
    let scratch = fs::symlink_metadata(&fixture.root).ok().map(|metadata| serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid()}));
    println!(
        "{}",
        serde_json::json!({"functional":if functional.is_ok(){"PASS"}else{"FAIL"},"failure":functional.err(),"cleanup":if cleanup.is_ok(){"PASS"}else{"UNCONFIRMED"},"cleanup_failure":cleanup.err(),"checks":fixture.checks,"retained_fixture":fixture.root,"scratch_identity":scratch,"unconfirmed_owned_pids":fixture.children.iter().flatten().map(Child::id).collect::<Vec<_>>(),"scratch_disposition":"RETAINED_FOR_ROOT_READBACK","account_database_writes":false,"owned_child_count":fixture.children.len()})
    );
    assert!(
        functional.is_ok() && cleanup.is_ok(),
        "native principal qualification failed; consult fixed-code receipt"
    );
}
#[test]
#[ignore = "explicit OpenBSD root fixture; fixed existing principals and pinned native artifacts"]
fn native_crypto_inventory_principals() {
    qualification(crypto_inventory)
}
#[test]
#[ignore = "explicit OpenBSD root fixture; fixed existing principals and pinned native artifacts"]
fn native_public_admin_principals() {
    qualification(public_admin)
}
#[test]
fn malformed_artifact_pin_refuses_before_file_access() {
    let artifact = Artifact {
        path: PathBuf::from("relative"),
        sha256: "0".repeat(64),
    };
    assert_eq!(
        artifact_bytes(&artifact).unwrap_err(),
        "ARTIFACT_PATH_REFUSED"
    );
}

#[test]
fn agent_pid_witness_requires_one_positive_bounded_pid() {
    assert_eq!(parse_agent_pid(b"D 1234\nOK\n"), Ok(1234));
    for bytes in [
        b"OK\n".as_slice(),
        b"D 0\n",
        b"D -1\n",
        b"D 1\n",
        b"D 2147483648\n",
        b"D 12\nD 13\n",
    ] {
        assert!(parse_agent_pid(bytes).is_err());
    }
}

// S06 functional composition reuses accepted S05 separate-UID qualification;
// this actor intentionally owns the disposable reader and key-agent homes.
fn inbound_stored_profile(f: &mut Fixture) -> Result<()> {
    let (alice, bob) = f.keys(true)?;
    let reader = f.directory("helper/r", 1002, 1003, 0o700)?;
    let crypto = write_config(
        f,
        "s06-crypto",
        serde_json::json!({
            "version":1,"worker":f.path("crypto-worker"),"engine":f.path("engine"),
            "socket":f.path("transport/s06-crypto.sock"),"trusted_web_uid":1002,
            "accounts":[
                {"account":"alice@example.test","home":f.path("helper/alice"),"signer_fingerprint":alice,"decrypt_fingerprints":[alice],"recipient_fingerprints":[alice,bob]},
                {"account":"bob@example.test","home":f.path("helper/bob"),"signer_fingerprint":bob,"decrypt_fingerprints":[bob],"recipient_fingerprints":[alice,bob]}
            ]
        }),
    )?;
    let inventory = write_config(
        f,
        "s06-inventory",
        serde_json::json!({
            "version":1,"worker":f.path("inventory-worker"),"engine":"/usr/local/bin/gpg",
            "socket":f.path("transport/s06-inventory.sock"),"trusted_web_uid":1002,
            "accounts":[{"account":"alice@example.test","home":f.path("helper/alice")},{"account":"bob@example.test","home":f.path("helper/bob")}]
        }),
    )?;
    f.start_checked(
        "crypto-helper",
        &crypto,
        &f.path("transport/s06-crypto.sock"),
        0o600,
    )?;
    f.start_checked(
        "inventory-helper",
        &inventory,
        &f.path("transport/s06-inventory.sock"),
        0o600,
    )?;
    let binary = f.path("libtest");
    let mut command = f.command(Program::Libtest(&binary), Role::Helper)?;
    command
        .args([
            "openpgp_principal_native_tests::native_stored_signed_profile_client",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env("OSMAP_S06_READER_ROOT", reader)
        .env(
            "OSMAP_S06_CRYPTO_SOCKET",
            f.path("transport/s06-crypto.sock"),
        )
        .env(
            "OSMAP_S06_INVENTORY_SOCKET",
            f.path("transport/s06-inventory.sock"),
        )
        .env("OSMAP_S06_GRANT", f.path("helper/grant"))
        .env("OSMAP_S06_ALICE_FP", alice)
        .env("OSMAP_S06_BOB_FP", bob);
    let output = f.run(command, b"")?;
    require(
        output
            .windows(b"1 passed; 0 failed".len())
            .any(|part| part == b"1 passed; 0 failed"),
        "EXACT_S06_CLIENT_COUNT_REFUSED",
    )?;
    f.checks.push("s06_actual_stored_signed_profile_corpus");
    Ok(())
}
#[test]
#[ignore = "explicit OpenBSD root fixture; S06 actual Dovecot stored-byte discriminator"]
fn native_stored_signed_profile_corpus() {
    qualification(inbound_stored_profile)
}
#[test]
#[ignore = "nested S06 helper actor; only outer-owned disposable homes and signed SDKs"]
fn native_stored_signed_profile_client() {
    assert_eq!(std::env::consts::OS, "openbsd");
    assert_eq!(crate::openbsd::effective_uid(), 1002);
    let path = |name| PathBuf::from(std::env::var_os(name).expect("explicit S06 fixture setting"));
    let root = path("OSMAP_S06_READER_ROOT");
    let grant = path("OSMAP_S06_GRANT");
    let crypto = crate::openpgp_crypto_runtime::Client::from_operator_files(
        &path("OSMAP_S06_CRYPTO_SOCKET"),
        &grant,
        1002,
    )
    .unwrap();
    let inventory = crate::openpgp_inventory_runtime::Client::from_operator_files(
        &path("OSMAP_S06_INVENTORY_SOCKET"),
        &grant,
        1002,
    )
    .unwrap();
    let alice = std::env::var("OSMAP_S06_ALICE_FP").unwrap();
    let bob = std::env::var("OSMAP_S06_BOB_FP").unwrap();
    crate::mailbox_helper::prove_native_stored_signed_profile(
        &root, &crypto, &inventory, &alice, &bob,
    );
}

// Unlike the stored-reader corpus, this uses the accepted distinct Web/helper
// principals and deliberately never exchanges the two public certificates.
#[derive(Clone, Copy)]
enum InboundCryptoCase {
    MissingSigner,
    Decryption,
}
fn inbound_disjoint_crypto(f: &mut Fixture, case: InboundCryptoCase) -> Result<()> {
    let (selector, observation, check) = match case {
        InboundCryptoCase::MissingSigner => (
            "openpgp_principal_native_tests::native_missing_signer_client",
            "web/s06-signature-observation.json",
            "s06_actual_missing_signer_and_signature_controls",
        ),
        InboundCryptoCase::Decryption => (
            "openpgp_principal_native_tests::native_decryption_client",
            "web/s06-decryption-observation.json",
            "s06_actual_self_decryption_and_invalid_ciphertext",
        ),
    };
    let (alice, bob) = f.keys(false)?;
    let before = protected_manifest(f)?;
    let public_before = ["alice", "bob"]
        .into_iter()
        .map(|name| {
            fs::read(f.path(&format!("helper/{name}/pubring.kbx")))
                .map(|bytes| hash(&bytes))
                .map_err(|_| "PUBLIC_KEYBOX_READ_REFUSED")
        })
        .collect::<Result<Vec<_>>>()?;
    if matches!(case, InboundCryptoCase::Decryption) {
        let mut command = f.command(Program::Gpg, Role::Helper)?;
        command
            .args(["--no-options", "--homedir"])
            .arg(f.path("helper/alice"))
            .args([
                "--batch",
                "--no-autostart",
                "--no-auto-check-trustdb",
                "--no-throw-keyids",
                "--rfc4880",
                "--trust-model",
                "always",
                "--armor",
                "--cipher-algo",
                "AES256",
                "--compress-algo",
                "none",
                "--recipient",
                &alice,
                "--encrypt",
            ]);
        let ciphertext = f.run(
            command,
            crate::protected_message::native_tests::VISIBLE_DECRYPTION_PLAINTEXT,
        )?;
        require(
            ciphertext.is_ascii()
                && ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----")
                && ciphertext
                    .windows(b"-----END PGP MESSAGE-----".len())
                    .any(|part| part == b"-----END PGP MESSAGE-----"),
            "VISIBLE_RECIPIENT_CIPHERTEXT_REFUSED",
        )?;
        f.write(
            &f.path("web/s06-visible-ciphertext.asc"),
            &ciphertext,
            1001,
            1001,
            0o600,
        )?;
    }
    let socket = f.path("transport/s06-signature.sock");
    let config = write_config(
        f,
        "s06-signature",
        serde_json::json!({
            "version":1,"worker":f.path("crypto-worker"),"engine":f.path("engine"),
            "socket":socket,"trusted_web_uid":1001,
            "accounts":[
                {"account":"alice","home":f.path("helper/alice"),"signer_fingerprint":alice,"decrypt_fingerprints":[alice],"recipient_fingerprints":[alice]},
                {"account":"bob","home":f.path("helper/bob"),"signer_fingerprint":bob,"decrypt_fingerprints":[bob],"recipient_fingerprints":[bob]}
            ]
        }),
    )?;
    f.start("crypto-helper", &config, &socket)?;
    let binary = f.path("libtest");
    let mut command = f.command(Program::Libtest(&binary), Role::Web)?;
    command
        .args([selector, "--exact", "--ignored", "--test-threads=1"])
        .env("OSMAP_S06_SIGNATURE_SOCKET", socket)
        .env("OSMAP_S06_SIGNATURE_GRANT", f.path("web/grant"))
        .env("OSMAP_S06_SIGNATURE_ALICE_FP", alice)
        .env("OSMAP_S06_SIGNATURE_BOB_FP", bob)
        .env(
            "OSMAP_S06_VISIBLE_CIPHERTEXT",
            f.path("web/s06-visible-ciphertext.asc"),
        )
        .env("OSMAP_S06_SIGNATURE_OBSERVATION", f.path(observation));
    let output = f.run(command, b"")?;
    require(
        output
            .windows(b"1 passed; 0 failed".len())
            .any(|part| part == b"1 passed; 0 failed"),
        "EXACT_S06_SIGNATURE_CLIENT_COUNT_REFUSED",
    )?;
    require(
        protected_manifest(f)? == before,
        "SIGNATURE_PRIVATE_STATE_CHANGED",
    )?;
    for (name, expected) in ["alice", "bob"].into_iter().zip(public_before) {
        require(
            hash(
                &fs::read(f.path(&format!("helper/{name}/pubring.kbx")))
                    .map_err(|_| "PUBLIC_KEYBOX_READ_REFUSED")?,
            ) == expected,
            "SIGNATURE_PUBLIC_STATE_CHANGED",
        )?;
    }
    f.checks.push(check);
    Ok(())
}
fn inbound_missing_signer(f: &mut Fixture) -> Result<()> {
    inbound_disjoint_crypto(f, InboundCryptoCase::MissingSigner)
}
fn inbound_decryption(f: &mut Fixture) -> Result<()> {
    inbound_disjoint_crypto(f, InboundCryptoCase::Decryption)
}

#[test]
#[ignore = "explicit OpenBSD root fixture; actual missing-public-signer classification"]
fn native_missing_signer_classification() {
    qualification(inbound_missing_signer)
}

#[test]
#[ignore = "explicit OpenBSD root fixture; actual transient decryption and malformed ciphertext"]
fn native_decryption_classification() {
    qualification(inbound_decryption)
}

#[test]
#[ignore = "nested S06 Web actor; only outer-owned synthetic key homes and signed SDK"]
fn native_decryption_client() {
    assert_eq!(std::env::consts::OS, "openbsd");
    assert_eq!(crate::openbsd::effective_uid(), 1001);
    let path = |name| PathBuf::from(std::env::var_os(name).expect("explicit S06 fixture setting"));
    let client = crate::openpgp_crypto_runtime::Client::from_operator_files(
        &path("OSMAP_S06_SIGNATURE_SOCKET"),
        &path("OSMAP_S06_SIGNATURE_GRANT"),
        1002,
    )
    .unwrap();
    let alice = std::env::var("OSMAP_S06_SIGNATURE_ALICE_FP").unwrap();
    let bob = std::env::var("OSMAP_S06_SIGNATURE_BOB_FP").unwrap();
    let ciphertext = fs::read(path("OSMAP_S06_VISIBLE_CIPHERTEXT")).unwrap();
    let observed = crate::protected_message::native_tests::run_decryption_fixture(
        &client,
        &alice,
        &bob,
        &ciphertext,
    );
    let encoded = serde_json::to_vec(&observed).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path("OSMAP_S06_SIGNATURE_OBSERVATION"))
        .unwrap();
    file.write_all(&encoded).unwrap();
    file.sync_all().unwrap();
    println!("{observed}");
    // Preserve all actual typed observations before a classification can fail.
    assert_eq!(observed["missing_private_key"], "MissingKey");
    assert_eq!(observed["missing_private_processor"], "MissingKey");
    assert_eq!(observed["hidden_recipient_native"], "Unavailable");
    assert_eq!(observed["hidden_recipient_processor"], "Unavailable");
    assert_eq!(observed["hidden_recipient_safe_refusal"], true);
    assert_eq!(observed["wrong_requested_key"], "Invalid");
    assert_eq!(observed["invalid_ciphertext"][0]["native"], "Unsupported");
    assert_eq!(
        observed["invalid_ciphertext"][0]["processor"],
        "UnsupportedCrypto"
    );
    for result in observed["invalid_ciphertext"].as_array().unwrap() {
        assert!(result["native"].is_string());
        assert!(result["processor"].is_string());
        assert_eq!(result["safe_refusal_ui"], true);
    }
}

#[test]
#[ignore = "nested S06 Web actor; only outer-owned synthetic key homes and signed SDK"]
fn native_missing_signer_client() {
    assert_eq!(std::env::consts::OS, "openbsd");
    assert_eq!(crate::openbsd::effective_uid(), 1001);
    let path = |name| PathBuf::from(std::env::var_os(name).expect("explicit S06 fixture setting"));
    let client = crate::openpgp_crypto_runtime::Client::from_operator_files(
        &path("OSMAP_S06_SIGNATURE_SOCKET"),
        &path("OSMAP_S06_SIGNATURE_GRANT"),
        1002,
    )
    .unwrap();
    let alice = std::env::var("OSMAP_S06_SIGNATURE_ALICE_FP").unwrap();
    let observed =
        crate::protected_message::native_tests::run_missing_signer_fixture(&client, &alice);
    let encoded = serde_json::to_vec(&observed).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path("OSMAP_S06_SIGNATURE_OBSERVATION"))
        .unwrap();
    file.write_all(&encoded).unwrap();
    file.sync_all().unwrap();
    println!("{observed}");
    // Persist both actual classifications before distinguishing expectations.
    assert_eq!(observed["native_missing_signer"], "MissingKey");
    assert_eq!(observed["processor_missing_signer"], "UnknownSigner");
    assert_eq!(observed["safe_refusal_ui"], true);
    assert_eq!(observed["missing_public_key_copy"], true);
    assert_eq!(observed["no_decryption_key_copy"], false);
}
