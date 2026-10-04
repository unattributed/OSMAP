use super::*;
use crate::message_metadata::MessageVersion;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ACCOUNT: &str = "alice@example.test";

// A concurrent test may briefly hold this newly written owned script open.
// Retry only a spawn that explicitly did not execute the harmless detector.
// This does not wrap or retry any gateway operation.
fn sentinel_positive_control(
    mut run: impl FnMut() -> Result<crate::auth::CommandExecution, crate::auth::CommandExecutionError>,
) -> Result<crate::auth::CommandExecution, crate::auth::CommandExecutionError> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut remaining_retries = 7;
    loop {
        match run() {
            Err(error)
                if error.reason == "failed to spawn command: Text file busy (os error 26)"
                    && remaining_retries > 0
                    && Instant::now() + Duration::from_millis(10) < deadline =>
            {
                remaining_retries -= 1;
                thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

#[test]
fn sentinel_control_retries_only_unexecuted_text_busy_spawns() {
    let mut attempts = 0;
    let control = sentinel_positive_control(|| {
        attempts += 1;
        if attempts == 1 {
            Err(crate::auth::CommandExecutionError {
                reason: "failed to spawn command: Text file busy (os error 26)".into(),
            })
        } else {
            Ok(crate::auth::CommandExecution {
                status_code: 1,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    })
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(control.status_code, 1);

    for reason in [
        "failed to spawn command: Permission denied (os error 13)",
        "command timed out",
    ] {
        attempts = 0;
        let refused = sentinel_positive_control(|| {
            attempts += 1;
            Err(crate::auth::CommandExecutionError {
                reason: reason.into(),
            })
        });
        assert_eq!(attempts, 1);
        assert_eq!(refused.unwrap_err().reason, reason);
    }
    attempts = 0;
    let unexpected_exit = sentinel_positive_control(|| {
        attempts += 1;
        Ok(crate::auth::CommandExecution {
            status_code: 2,
            stdout: String::new(),
            stderr: String::new(),
        })
    })
    .unwrap();
    assert_eq!(attempts, 1);
    assert_eq!(unexpected_exit.status_code, 2);
}

#[test]
fn sentinel_control_exhausted_spawn_conflict_still_fails() {
    let mut attempts = 0;
    let refused = sentinel_positive_control(|| {
        attempts += 1;
        Err(crate::auth::CommandExecutionError {
            reason: "failed to spawn command: Text file busy (os error 26)".into(),
        })
    });
    assert_eq!(attempts, 8);
    assert_eq!(
        refused.unwrap_err().reason,
        "failed to spawn command: Text file busy (os error 26)"
    );
}

struct Fixture {
    root: PathBuf,
    gateway: RuntimeBrowserGateway,
    context: AuthenticationContext,
    session: ValidatedSession,
    socket: PathBuf,
    marker: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from("/tmp").join(format!(
            "osmap-delete-gateway-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let key = root.join("grant.key");
        fs::write(&key, vec![b'q'; 64]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let socket = root.join("helper.sock");
        let marker = root.join("native-attempted");
        let sentinel = root.join("native-sentinel");
        // This owned executable is a discriminating harmless fallback detector.
        // The application must never execute it for the helper-only delete path.
        let interpreter = if cfg!(target_os = "openbsd") {
            "/usr/local/bin/python3"
        } else {
            "/usr/bin/python3"
        };
        fs::write(&sentinel, format!("#!{interpreter}\nfrom pathlib import Path\nPath({:?}).write_text('attempted')\nraise SystemExit(1)\n", marker.to_str().unwrap())).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o700)).unwrap();
        // Prove the owned detector executes before using its absence as evidence.
        let control = sentinel_positive_control(|| {
            crate::auth::CommandExecutor::run_with_stdin_bytes_timeout_and_output_limit(
                &crate::auth::SystemCommandExecutor,
                sentinel.to_str().unwrap(),
                &[],
                &[],
                Duration::from_secs(2),
                64,
            )
        })
        .unwrap();
        assert_eq!(control.status_code, 1);
        assert_eq!(fs::read(&marker).unwrap(), b"attempted");
        fs::remove_file(&marker).unwrap();
        let mut gateway = RuntimeBrowserGateway::for_test(&root);
        gateway.mailbox_helper_socket_path = Some(socket.clone());
        gateway.mailbox_helper_grant_key_path = Some(key);
        gateway.mailbox_helper_peer_uid = Some(crate::openbsd::effective_uid());
        gateway.doveadm_path = sentinel;
        let context = AuthenticationContext::new(
            AuthenticationPolicy::default(),
            "delete-gateway-qa",
            "127.0.0.1",
            "Synthetic/Test",
        )
        .unwrap();
        let session = ValidatedSession {
            record: crate::session::SessionRecord {
                account_epoch: None,
                session_id: "public-synthetic-session".into(),
                csrf_token: "public-synthetic-csrf".into(),
                canonical_username: ACCOUNT.into(),
                issued_at: 1,
                expires_at: u64::MAX,
                last_seen_at: 1,
                revoked_at: None,
                remote_addr: "127.0.0.1".into(),
                user_agent: "Synthetic/Test".into(),
                factor: crate::auth::RequiredSecondFactor::Totp,
            },
            audit_event: LogEvent::new(
                LogLevel::Info,
                EventCategory::Session,
                "synthetic_session",
                "synthetic session",
            ),
        };
        Self {
            root,
            gateway,
            context,
            session,
            socket,
            marker,
        }
    }
    fn request(&self) -> MessageDeleteRequest {
        MessageDeleteRequest::new(
            ACCOUNT,
            "Deleted",
            7,
            MessageVersion::new("a".repeat(32), "public-message-7".into()).unwrap(),
            9,
        )
        .unwrap()
    }
    fn no_transport(&self) -> UnixListener {
        let listener = UnixListener::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }
    fn assert_no_native(&self) {
        assert!(
            !self.marker.exists(),
            "helper-only deletion must not execute direct native sentinel"
        );
    }
    fn outcome(&self, request: &MessageDeleteRequest) -> BrowserMessageDeleteOutcome {
        self.gateway
            .delete_message(&self.context, &self.session, request)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn assert_not_connected(listener: &UnixListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        _ => panic!("refused request must not connect to helper"),
    }
}

struct Peer {
    handle: Option<thread::JoinHandle<()>>,
    count: Arc<AtomicUsize>,
}
impl Peer {
    fn spawn(socket: &std::path::Path, result: Option<&'static str>, wrong_nonce: bool) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("bounded fixture accept failed: {error}"),
                }
            };
            observed.fetch_add(1, Ordering::SeqCst);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = vec![];
            stream.read_to_end(&mut bytes).unwrap();
            assert!(bytes.len() <= 4096);
            let text = std::str::from_utf8(&bytes).unwrap();
            let fields: BTreeMap<_, _> = text
                .lines()
                .map(|line| line.split_once('=').unwrap())
                .collect();
            assert_eq!(fields.get("operation"), Some(&"message_delete"));
            assert_eq!(fields.get("delete_uid"), Some(&"7"));
            assert_eq!(fields.get("policy_revision"), Some(&"9"));
            assert_eq!(
                fields.get("delete_mailbox_guid").copied(),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            );
            assert!(!fields["grant_signature"].is_empty());
            assert!(!fields["grant_nonce"].is_empty());
            if let Some(result) = result {
                let mut response = String::from("operation=message_delete\n");
                for name in [
                    "canonical_username_b64",
                    "mailbox_name_b64",
                    "delete_uid",
                    "delete_mailbox_guid",
                    "delete_message_guid_b64",
                    "policy_revision",
                ] {
                    response.push_str(&format!("{name}={}\n", fields[name]));
                }
                let nonce = if wrong_nonce {
                    "00000000000000000000000000000000"
                } else {
                    fields["grant_nonce"]
                };
                response.push_str(&format!("delete_result={result}\nrequest_nonce={nonce}\n"));
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            handle: Some(handle),
            count,
        }
    }
    fn finish(mut self) {
        self.handle
            .take()
            .unwrap()
            .join()
            .expect("peer fixture should finish");
        assert_eq!(self.count.load(Ordering::SeqCst), 1);
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn delete_gateway_missing_helper_authority_has_no_transport_quota_or_native_fallback() {
    for missing in 0..3 {
        let mut fixture = Fixture::new();
        let listener = fixture.no_transport();
        match missing {
            0 => fixture.gateway.mailbox_helper_socket_path = None,
            1 => fixture.gateway.mailbox_helper_grant_key_path = None,
            _ => fixture.gateway.mailbox_helper_peer_uid = None,
        }
        assert!(fixture.gateway.build_message_delete_backend().is_none());
        assert_eq!(
            fixture.outcome(&fixture.request()).result,
            Err(MessageDeleteError::Unavailable)
        );
        assert_eq!(
            fixture
                .gateway
                .retention_status(&fixture.session, "Deleted"),
            crate::mailbox::RetentionDecision::Unavailable
        );
        assert_not_connected(&listener);
        assert!(!fixture.gateway.message_move_throttle_dir.exists());
        fixture.assert_no_native();
    }
}
#[test]
fn delete_gateway_foreign_and_tampered_tuples_are_invalid_before_quota_or_transport() {
    for field in 0..6 {
        let fixture = Fixture::new();
        let listener = fixture.no_transport();
        let mut request = fixture.request();
        match field {
            0 => request.canonical_username = "bob@example.test".into(),
            1 => request.uid = 0,
            2 => request.uid = u64::MAX,
            3 => request.version.mailbox_guid.clear(),
            4 => request.version.message_guid = "bad\ncontrol".into(),
            _ => request.policy_revision = 0,
        }
        assert_eq!(
            fixture.outcome(&request).result,
            Err(MessageDeleteError::Invalid)
        );
        assert_not_connected(&listener);
        assert!(!fixture.gateway.message_move_throttle_dir.exists());
        fixture.assert_no_native();
    }
}
#[test]
fn delete_gateway_unavailable_quota_refuses_before_helper_write() {
    let fixture = Fixture::new();
    let listener = fixture.no_transport();
    fs::create_dir_all(fixture.gateway.message_move_throttle_dir.parent().unwrap()).unwrap();
    fs::write(
        &fixture.gateway.message_move_throttle_dir,
        b"owned obstruction",
    )
    .unwrap();
    let outcome = fixture.outcome(&fixture.request());
    assert_eq!(outcome.result, Err(MessageDeleteError::Unavailable));
    assert!(outcome
        .audit_events
        .iter()
        .any(|event| event.action == "message_delete_quota_unavailable"));
    assert_not_connected(&listener);
    fixture.assert_no_native();
}
#[test]
fn delete_gateway_existing_shared_quota_refuses_second_mutation_before_transport() {
    let mut fixture = Fixture::new();
    let listener = fixture.no_transport();
    fixture
        .gateway
        .message_move_throttle_policy
        .canonical_user_max_moves = 1;
    let service = fixture.gateway.build_message_move_throttle_service();
    let first = service
        .reserve_mail_action(&fixture.context, ACCOUNT)
        .unwrap();
    assert!(matches!(
        first.decision,
        MessageMoveThrottleDecision::Allowed
    ));
    let outcome = fixture.outcome(&fixture.request());
    assert_eq!(outcome.result, Err(MessageDeleteError::Busy));
    assert!(outcome.retry_after_seconds.is_some());
    assert_not_connected(&listener);
    fixture.assert_no_native();
}
#[test]
fn delete_gateway_actual_helper_transport_preserves_finite_results_and_reserves_once() {
    for (wire, expected) in [
        ("deleted", Ok(MessageDeleteResult::Deleted)),
        ("stale", Err(MessageDeleteError::Stale)),
        ("policy_denied", Err(MessageDeleteError::PolicyDenied)),
        (
            "policy_unavailable",
            Err(MessageDeleteError::PolicyUnavailable),
        ),
        ("busy", Err(MessageDeleteError::Busy)),
        ("unknown", Err(MessageDeleteError::Unknown)),
    ] {
        let mut fixture = Fixture::new();
        fixture
            .gateway
            .message_move_throttle_policy
            .canonical_user_max_moves = 1;
        let peer = Peer::spawn(&fixture.socket, Some(wire), false);
        assert_eq!(fixture.outcome(&fixture.request()).result, expected);
        peer.finish();
        let check = fixture
            .gateway
            .build_message_move_throttle_service()
            .check(&fixture.context, ACCOUNT)
            .unwrap();
        assert!(matches!(
            check.decision,
            MessageMoveThrottleDecision::Throttled { .. }
        ));
        assert_eq!(
            fixture.outcome(&fixture.request()).result,
            Err(MessageDeleteError::Busy)
        );
        fixture.assert_no_native();
    }
}
#[test]
fn delete_gateway_lost_and_wrong_nonce_replies_remain_unknown_without_retry() {
    for result in [None, Some("deleted")] {
        let mut fixture = Fixture::new();
        fixture
            .gateway
            .message_move_throttle_policy
            .canonical_user_max_moves = 1;
        let peer = Peer::spawn(&fixture.socket, result, result.is_some());
        assert_eq!(
            fixture.outcome(&fixture.request()).result,
            Err(MessageDeleteError::Unknown)
        );
        peer.finish();
        assert_eq!(
            fixture.outcome(&fixture.request()).result,
            Err(MessageDeleteError::Busy)
        );
        fixture.assert_no_native();
    }
}
