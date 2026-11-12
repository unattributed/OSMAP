// Actual native Serve seal and worker thread; no account authority or SMTP.
use super::*;
use crate::scheduled_send::{BlockReason, ScheduleInput, ScheduledStore, State};
use crate::totp::{SystemTimeProvider, TimeProvider};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};

const ACCOUNT: &str = "fixture@osmap-scheduled.invalid";
const ROOT_ENV: &str = "OSMAP_SCHEDULED_SERVE_FIXTURE_ROOT";
const PORT_ENV: &str = "OSMAP_SCHEDULED_SERVE_FIXTURE_PORT";
const CHILD_ENV: &str = "OSMAP_SCHEDULED_SERVE_FIXTURE_CHILD";

fn config(root: &Path, port: u16) -> AppConfig {
    assert_eq!(root.parent(), Some(Path::new("/tmp")));
    let suffix = root
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("osmap-sched-serve-")
        .unwrap();
    assert!(
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(fs::canonicalize(root).unwrap(), root);
    let uid = crate::openbsd::effective_uid();
    assert!(uid > 0 && port >= 1024);
    let metadata = fs::symlink_metadata(root).unwrap();
    assert!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == uid
            && metadata.mode() & 0o777 == 0o700
    );
    let map = BTreeMap::from([
        ("OSMAP_RUN_MODE".into(), "serve".into()),
        ("OSMAP_ENV".into(), "development".into()),
        (
            "OSMAP_STATE_DIR".into(),
            root.join("state").to_string_lossy().into_owned(),
        ),
        ("OSMAP_LISTEN_ADDR".into(), format!("127.0.0.1:{port}")),
        ("OSMAP_OPENBSD_CONFINEMENT_MODE".into(), "enforce".into()),
    ]);
    let config = AppConfig::from_env_map(&map).unwrap();
    assert_eq!(
        config.openbsd_confinement_mode,
        crate::config::OpenbsdConfinementMode::Enforce
    );
    assert!(
        config.account_runtime.is_none()
            && config.openpgp_crypto.is_none()
            && config.openpgp_inventory.is_none()
            && config.openpgp_public_admin.is_none()
            && config.mailbox_helper_socket_path.is_none()
    );
    config
}

struct Scratch {
    path: PathBuf,
    identity: (u64, u64, u32),
    complete: bool,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.complete || std::thread::panicking() {
            println!(
                "native_scheduled_serve fixture={} cleanup=NOT_CLAIMED retained=true",
                self.path.display()
            );
            return;
        }
        let metadata = fs::symlink_metadata(&self.path).unwrap();
        assert!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.mode() & 0o777 == 0o700
        );
        assert_eq!(
            (metadata.dev(), metadata.ino(), metadata.uid()),
            self.identity
        );
        fs::remove_dir_all(&self.path).unwrap();
        assert!(!self.path.exists());
    }
}
struct OwnedChild {
    child: Child,
    status: Option<ExitStatus>,
}
impl OwnedChild {
    fn alive(&mut self) -> bool {
        if self.status.is_none() {
            self.status = self.child.try_wait().unwrap();
        }
        self.status.is_none()
    }
    fn stop(&mut self) -> bool {
        if !self.alive() {
            return true;
        }
        // The still-unreaped Child is our signal authority; no remembered PID.
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !self.alive() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.stop() {
            println!("native_scheduled_serve child_cleanup=UNCONFIRMED");
        }
    }
}
fn private_file(root: &Path, name: &str) -> fs::File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap()
}
fn retained(root: &Path, value: serde_json::Value) {
    let path = root.join("observation.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
}
fn health(port: u16) -> bool {
    let endpoint = format!("127.0.0.1:{port}").parse().unwrap();
    let Ok(mut stream) = TcpStream::connect_timeout(&endpoint, Duration::from_millis(250)) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut bytes = Vec::new();
    if Read::by_ref(&mut stream)
        .take(8193)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return false;
    }
    bytes.len() <= 8192 && bytes.starts_with(b"HTTP/1.1 200 ") && bytes.ends_with(b"ok\n")
}

#[test]
#[ignore = "nonroot OpenBSD actual confined Serve scheduled worker/store refusal"]
fn native_confined_serve_scheduled_worker_refuses_unavailable_account() {
    assert_eq!(std::env::consts::OS, "openbsd");
    if let Ok(child) = std::env::var(CHILD_ENV) {
        assert_eq!(child, "yes");
        let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
        let text = std::env::var(PORT_ENV).unwrap();
        let port: u16 = text.parse().unwrap();
        assert_eq!(port.to_string(), text);
        let config = config(&root, port);
        for directory in [
            &config.state_root,
            &config.state_layout.runtime_dir,
            &config.state_layout.settings_dir,
            &config.state_layout.session_dir,
            &config.state_layout.draft_dir,
            &config.state_layout.audit_dir,
            &config.state_layout.cache_dir,
            &config.state_layout.totp_secret_dir,
        ] {
            crate::private_account_file::check_directory(directory).unwrap();
        }
        let logger = Logger::new(crate::config::LogFormat::Text, LogLevel::Info);
        // This is the real entry: it applies the native seal before thread start.
        run_http_server(&config, &logger).unwrap();
        return;
    }
    let whole = Instant::now();
    let uid = crate::openbsd::effective_uid();
    assert!(uid > 0);
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-sched-serve-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let metadata = fs::symlink_metadata(&root).unwrap();
    let mut scratch = Scratch {
        path: root.clone(),
        identity: (metadata.dev(), metadata.ino(), metadata.uid()),
        complete: false,
    };
    let reserved_port = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved_port.local_addr().unwrap().port();
    let config = config(&root, port);
    for directory in [
        &config.state_root,
        &config.state_layout.runtime_dir,
        &config.state_layout.settings_dir,
        &config.state_layout.session_dir,
        &config.state_layout.draft_dir,
        &config.state_layout.audit_dir,
        &config.state_layout.cache_dir,
        &config.state_layout.totp_secret_dir,
    ] {
        fs::create_dir_all(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = ScheduledStore::new(config.state_layout.settings_dir.join("scheduled-send"));
    let journal = crate::send_journal::SendJournal::new(
        config.state_layout.settings_dir.join("send-journal"),
    );
    let now = SystemTimeProvider.unix_timestamp();
    let id = {
        let mut guard = journal.account_guard(ACCOUNT, now).unwrap();
        let request = crate::send::ComposeRequest::new(
            crate::send::ComposePolicy::default(),
            "recipient@osmap-scheduled.invalid",
            "Native refused fixture",
            "Never submitted fixture content",
        )
        .unwrap();
        let staged = store
            .create_staged(
                &guard,
                0,
                ScheduleInput {
                    due_at: now + 1,
                    account_epoch: 2,
                    private_session: crate::openpgp_personal::PrivateSession {
                        session_id: "e".repeat(64),
                        account_epoch: Some(2),
                        expires_at: now + 3600,
                    },
                    request: &request,
                },
                now,
            )
            .unwrap();
        let intent = crate::send_journal::mint_intent(now).unwrap();
        guard
            .begin_schedule(&intent, &staged.id, &staged.digest)
            .unwrap();
        store
            .publish_pending(&guard, staged.revision, &staged.id, &staged.digest, now)
            .unwrap();
        guard
            .finish_schedule(&intent, &staged.id, &staged.digest)
            .unwrap();
        staged.id
    }; // No parent account or codec lock is inherited by the child.
    let stdout = private_file(&root, "child.stdout");
    let stderr = private_file(&root, "child.stderr");
    stdout.sync_all().unwrap();
    stderr.sync_all().unwrap();
    let mut command = crate::auth::scheduled_serve_fixture_command().unwrap();
    command
        .env(CHILD_ENV, "yes")
        .env(ROOT_ENV, &root)
        .env(PORT_ENV, port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    drop(reserved_port);
    let mut child = OwnedChild {
        child: command.spawn().unwrap(),
        status: None,
    };
    let deadline = whole + Duration::from_secs(25);
    let mut healthy = false;
    let mut blocked = None;
    while Instant::now() < deadline && child.alive() {
        if !healthy {
            healthy = health(port);
        }
        let now = SystemTimeProvider.unix_timestamp();
        if let Ok(guard) = journal.account_guard(ACCOUNT, now) {
            if let Ok(list) = store.list(&guard, now) {
                if let Some(job) = list
                    .jobs
                    .into_iter()
                    .find(|job| job.id == id && job.state == State::Blocked)
                {
                    blocked = Some(job);
                }
            }
        }
        if healthy && blocked.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let alive_before_stop = child.alive();
    let stopped = child.stop();
    let status = child.status.as_ref().and_then(ExitStatus::code);
    retained(
        &root,
        serde_json::json!({"healthz_200":healthy,"blocked_seen":blocked.is_some(),
        "alive_before_owned_stop":alive_before_stop,"owned_reaped":stopped,"exit_code":status,
        "runtime_mode":"serve/enforce","smtp_positive":"NOT_QUALIFIED"}),
    );
    assert!(
        stopped && alive_before_stop && healthy,
        "native confined Serve readiness/owned cleanup failed"
    );
    let job = blocked.expect("native confined worker did not settle blocked fixture");
    assert_eq!(job.reason, Some(BlockReason::ServiceUnavailable));
    let intent = job
        .intent
        .expect("native confined worker did not persist claim identity");
    assert!(journal
        .receipt(ACCOUNT, &intent, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .is_none());
    assert!(!config
        .state_layout
        .settings_dir
        .join("send-recovery")
        .exists());
    let logs = crate::private_account_file::read_record(&root.join("child.stderr"), 128 * 1024)
        .unwrap()
        .unwrap();
    let logs = std::str::from_utf8(&logs).unwrap();
    assert!(
        logs.contains("action=openbsd_confinement_enabled")
            && logs.contains("openbsd_confinement_mode=\"enforce\"")
    );
    use sha2::{Digest, Sha256};
    let witness = serde_json::json!({"result":"PASS","actual_serve_seal":true,"healthz_200":true,
        "persisted_claim":true,"blocked_service_unavailable":true,"journal_submission_record":false,
        "send_recovery_created":false,"owned_child_reaped":true,"positive_smtp_or_account_db":"NOT_QUALIFIED",
        "child_stderr_bytes":logs.len(),"child_stderr_sha256":format!("{:x}",Sha256::digest(logs.as_bytes()))});
    retained(&root, witness.clone());
    let readback = crate::private_account_file::read_record(&root.join("observation.json"), 4096)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&readback).unwrap(),
        witness
    );
    println!("native_confined_scheduled_observation={witness}");
    assert!(whole.elapsed() < Duration::from_secs(30));
    drop(child);
    scratch.complete = true;
    drop(scratch);
    assert!(!root.exists());
    println!("native_confined_scheduled result=PASS native_serve_seal=true healthz200=true claim_blocked=true submission_record=false exact_owned_cleanup=true positive_smtp=NOT_QUALIFIED");
}
