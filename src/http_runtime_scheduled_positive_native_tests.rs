//! Fixed native transport substitutions for one actual enforced Serve child.
//! No production constructor, qualification flag, promise or syscall is changed.
use crate::config::{AppConfig, OpenbsdConfinementMode};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub(crate) const ROOT_ENV: &str = "OSMAP_SCHEDULED_POSITIVE_ROOT";
pub(crate) const PORT_ENV: &str = "OSMAP_SCHEDULED_POSITIVE_PORT";
const ACCOUNT: &str = "alice@example.test";
struct Paths {
    root: PathBuf,
    smtp: PathBuf,
    sent: PathBuf,
    test_binary: PathBuf,
}
static PREPARED: OnceLock<Paths> = OnceLock::new();

fn checked_root(root: &Path) {
    assert_eq!(
        root.file_name().and_then(|name| name.to_str()),
        Some("gateway")
    );
    let parent = root.parent().unwrap();
    assert_eq!(parent.parent(), Some(Path::new("/tmp")));
    let nonce = parent
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("osmap-crypto-fixture-")
        .unwrap();
    assert!(nonce.len() == 8 && nonce.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert_eq!(fs::canonicalize(root).unwrap(), root);
    let uid = crate::openbsd::effective_uid();
    assert!(uid > 0);
    for (path, mode) in [(root, Some(0o700)), (parent, None)] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.mode() & 0o022 == 0
        );
        if let Some(mode) = mode {
            assert_eq!(metadata.mode() & 0o777, mode);
        }
    }
}
pub(crate) fn configuration(root: &Path, port: u16) -> AppConfig {
    checked_root(root);
    assert!(port >= 1024);
    let uid = crate::openbsd::effective_uid().to_string();
    AppConfig::from_env_map(&BTreeMap::from([
        ("OSMAP_RUN_MODE".into(), "serve".into()),
        ("OSMAP_ENV".into(), "development".into()),
        ("OSMAP_OPENBSD_CONFINEMENT_MODE".into(), "enforce".into()),
        (
            "OSMAP_STATE_DIR".into(),
            root.join("serve-state").to_string_lossy().into_owned(),
        ),
        ("OSMAP_LISTEN_ADDR".into(), format!("127.0.0.1:{port}")),
        ("OSMAP_ACCOUNT_ROLLOUT_ACCOUNT".into(), ACCOUNT.into()),
        (
            "OSMAP_ACCOUNT_ADMISSION_SOCKET".into(),
            root.join("e.sock").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_ACCOUNT_ADMISSION_KEY_FILE".into(),
            root.join("admission.key").to_string_lossy().into_owned(),
        ),
        ("OSMAP_ACCOUNT_ADMISSION_HELPER_UID".into(), uid.clone()),
        (
            "OSMAP_ACCOUNT_MUTATION_SOCKET".into(),
            root.join("m.sock").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_ACCOUNT_MUTATION_KEY_FILE".into(),
            root.join("mutation.key").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_ACCOUNT_MUTATION_SESSION_PROOF_KEY_FILE".into(),
            root.join("session-proof.key")
                .to_string_lossy()
                .into_owned(),
        ),
        ("OSMAP_ACCOUNT_MUTATION_HELPER_UID".into(), uid),
    ]))
    .unwrap()
}
fn child_root(config: &AppConfig) -> Option<PathBuf> {
    if std::env::var("OSMAP_GATEWAY_NATIVE_SERVICE")
        .ok()
        .as_deref()
        != Some("scheduled-serve")
    {
        return None;
    }
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("fixed Serve fixture root"));
    checked_root(&root);
    let port: u16 = std::env::var(PORT_ENV).unwrap().parse().unwrap();
    assert_eq!(config.state_root, root.join("serve-state"));
    assert_eq!(config.listen_addr, format!("127.0.0.1:{port}"));
    assert_eq!(
        config.openbsd_confinement_mode,
        OpenbsdConfinementMode::Enforce
    );
    let account = config.account_runtime.as_ref().unwrap();
    assert_eq!(account.rollout_account.as_deref(), Some(ACCOUNT));
    assert_eq!(account.admission_socket, root.join("e.sock"));
    assert_eq!(account.admission_key_file, root.join("admission.key"));
    assert_eq!(account.mutation_socket, root.join("m.sock"));
    assert_eq!(account.mutation_key_file, root.join("mutation.key"));
    assert_eq!(
        account.session_proof_key_file,
        root.join("session-proof.key")
    );
    assert_eq!(
        account.admission_helper_uid,
        crate::openbsd::effective_uid()
    );
    assert_eq!(account.mutation_helper_uid, crate::openbsd::effective_uid());
    assert!(
        config.openpgp_crypto.is_none()
            && config.openpgp_inventory.is_none()
            && config.openpgp_public_admin.is_none()
            && config.mailbox_helper_socket_path.is_none()
    );
    Some(root)
}
fn owned_executable(path: &Path) {
    assert_eq!(fs::canonicalize(path).unwrap(), path);
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.uid() == crate::openbsd::effective_uid()
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o500 == 0o500
    );
}
pub(crate) fn fixture_clients(
    config: &AppConfig,
) -> Option<(
    crate::account_admission_runtime::Client,
    crate::account_mutation_client::Client,
)> {
    let root = child_root(config)?;
    let smtp = root.join("sendmail");
    let sent = root.join("doveadm-save");
    let test_binary = std::env::current_exe().unwrap();
    for path in [&smtp, &sent, &test_binary] {
        owned_executable(path);
    }
    assert!(
        fs::metadata(&smtp).unwrap().len() <= 16384 && fs::metadata(&sent).unwrap().len() <= 16384
    );
    let account = config.account_runtime.as_ref().unwrap();
    let admission = crate::account_admission_runtime::Client::paired_fixture_files(
        &account.admission_socket,
        &account.admission_key_file,
        account.admission_helper_uid,
    )
    .unwrap();
    let mutation = crate::account_mutation_client::Client::stored_fixture_files(
        &account.mutation_socket,
        &account.mutation_key_file,
        &account.session_proof_key_file,
        account.mutation_helper_uid,
    )
    .unwrap();
    assert!(PREPARED
        .set(Paths {
            root,
            smtp,
            sent,
            test_binary
        })
        .is_ok());
    Some((admission, mutation))
}
pub(crate) fn transport_paths(config: &AppConfig) -> Option<(PathBuf, PathBuf)> {
    let paths = PREPARED.get()?;
    // Captured before actual sealing; never lstat hidden ancestors after seal.
    assert_eq!(config.state_root, paths.root.join("serve-state"));
    Some((paths.smtp.clone(), paths.sent.clone()))
}
pub(crate) fn transport_rules(config: &AppConfig) -> Vec<(PathBuf, &'static str)> {
    let Some(paths) = PREPARED.get() else {
        return Vec::new();
    };
    assert_eq!(config.state_root, paths.root.join("serve-state"));
    let rules = vec![
        (paths.smtp.clone(), "rx"),
        (paths.sent.clone(), "rx"),
        (paths.test_binary.clone(), "rx"),
        (PathBuf::from("/bin/sh"), "rx"),
    ];
    assert_eq!(
        rules
            .iter()
            .filter(|(path, _)| path.starts_with(&paths.root))
            .count(),
        2
    );
    assert!(rules
        .iter()
        .all(|(path, _)| path != &paths.root && path != paths.root.parent().unwrap()));
    println!("native_scheduled_serve fixture_exec_leaf_rules=4 private_ancestor_exec=false controlled_peer_not_db=true");
    rules
}
pub(crate) fn run_child() {
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
    let text = std::env::var(PORT_ENV).unwrap();
    let port: u16 = text.parse().unwrap();
    assert_eq!(port.to_string(), text);
    let config = configuration(&root, port);
    let logger = crate::logging::Logger::new(
        crate::config::LogFormat::Text,
        crate::config::LogLevel::Info,
    );
    crate::http::http_runtime::run_http_server(&config, &logger).unwrap();
}

pub(crate) fn assert_plan(config: &AppConfig, plan: &crate::openbsd::OpenbsdConfinementPlan) {
    let Some(paths) = PREPARED.get() else { return };
    assert_eq!(config.state_root, paths.root.join("serve-state"));
    assert_eq!(
        plan.promises_before_lock,
        "stdio rpath wpath cpath fattr flock inet unix proc exec unveil"
    );
    assert_eq!(
        plan.promises_after_lock,
        "stdio rpath wpath cpath fattr flock inet unix proc exec"
    );
    for expected in [
        paths.smtp.as_path(),
        paths.sent.as_path(),
        paths.test_binary.as_path(),
        Path::new("/bin/sh"),
    ] {
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path.as_path() == expected && rule.permissions.contains('x')));
    }
    assert!(plan
        .unveil_rules
        .iter()
        .filter(|rule| rule.path.starts_with(&paths.root) && rule.permissions.contains('x'))
        .all(|rule| rule.path == paths.smtp || rule.path == paths.sent));
    let off_list = paths.root.join("off-list-executable");
    assert!(!plan
        .unveil_rules
        .iter()
        .any(|rule| off_list.starts_with(&rule.path) && rule.permissions.contains('x')));
    println!("native_scheduled_serve actual_plan_inspected=true off_list_exec_unveiled=false native_exec_denial=NOT_EXERCISED promises_unchanged=true");
}
