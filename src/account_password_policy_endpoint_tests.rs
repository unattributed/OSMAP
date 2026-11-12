use super::*;
use crate::account_password_policy::{Error as PolicyError, MonotonicClock, RegistrationEvidence};
use crate::account_password_state::{Guard, Store};
use crate::openbsd::publish_rights;
use sha2::Digest;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const ALICE: &str = "alice@osmap-policy.invalid";
const BOB: &str = "bob@osmap-policy.invalid";
const API: [u8; 64] = [b'a'; 64];
struct Fixture {
    root: PathBuf,
    fence: Fence<MonotonicClock>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-policy-endpoint-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for account in [ALICE, BOB] {
            let name = format!(
                "{:x}",
                Sha256::digest(
                    [b"osmap-account-epoch-v1\0".as_slice(), account.as_bytes()].concat()
                )
            );
            // Test-only provisioning; endpoint does not create account state.
            for (suffix, data) in [("lock", b"".as_slice()), ("json", b"{\"epoch\":0,\"state\":\"active\",\"changed_at\":null,\"intent\":null,\"used_intents\":[]}".as_slice())] {
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(root.join(format!("{name}.{suffix}"))).unwrap(); file.write_all(data).unwrap(); file.sync_all().unwrap();
        }
        }
        let store = Arc::new(Store::open(&root, crate::openbsd::effective_uid()).unwrap());
        Self {
            root,
            fence: Fence::new(store, [ALICE.into(), BOB.into()].into(), MonotonicClock).unwrap(),
        }
    }
    fn endpoint(&self) -> Endpoint<'_, MonotonicClock> {
        Endpoint::new(&self.fence, API).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_millis(500)
}
fn body(phase: &str, account: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"login":account,"protocol":"imap","session_id":"NativeSession01","phase":phase,"tls":true})).unwrap()
}
fn http(body: &[u8], extra: &str) -> Vec<u8> {
    let mut request = format!("POST /epoch/?command=allow HTTP/1.1\r\nX-OSMAP-Policy: {}\r\nContent-Length: {}\r\n{extra}\r\n", std::str::from_utf8(&API).unwrap(), body.len()).into_bytes();
    request.extend_from_slice(body);
    request
}
fn policy_socket(
    endpoint: &Endpoint<'_, MonotonicClock>,
    bytes: &[u8],
) -> (Result<(), Error>, Vec<u8>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(bytes).unwrap();
    // Do not half-close: the real Dovecot caller waits for response first.
    let result = endpoint.policy_connection(server, until());
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    (result, response)
}
struct Inspector {
    deny_before_read: bool,
    expected_pid: u32,
    observations: AtomicUsize,
}
impl RegistrationObserver for Inspector {
    fn observe_registration(
        &self,
        guard: &Guard<'_>,
        account: &str,
        session: &str,
        _deadline: Instant,
    ) -> Result<RegistrationEvidence, PolicyError> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        let epoch = guard
            .admission(None)
            .map_err(|_| PolicyError::Refused)?
            .epoch;
        Ok(RegistrationEvidence::fixture(
            account,
            session,
            epoch,
            self.expected_pid,
            Instant::now(),
        ))
    }
}
impl PeerInspector for Inspector {
    type Binding = ();
    fn admit(&self, stream: &UnixStream, _deadline: Instant) -> Result<(), Error> {
        if self.deny_before_read {
            // Positive observation: pending caller bytes are still available
            // untouched when peer admission refuses before framing intake.
            let _ = stream;
            Err(Error::Refused)
        } else {
            Ok(())
        }
    }
    fn validate(
        &self,
        _: &(),
        _: &UnixStream,
        claim: &PublishClaim,
        _: Instant,
    ) -> Result<(), Error> {
        if claim.pid == self.expected_pid {
            Ok(())
        } else {
            Err(Error::Refused)
        }
    }
    fn attest_io(
        &self,
        _: &(),
        _: &UnixStream,
        claim: &PublishClaim,
        io: crate::openbsd::ReceivedImapIo,
        _: Instant,
    ) -> Result<crate::account_password_imap::AttestedIo, Error> {
        // Test-only native-observation stand-in. Actual SCM_RIGHTS ownership,
        // shutdown and control EOF execute below; this is not OpenBSD custody.
        use std::os::fd::AsRawFd;
        let descriptions = (0..io.len())
            .map(|index| format!("fixture-owned-socket-{}", io.fd(index).unwrap().as_raw_fd()))
            .collect();
        Ok(crate::account_password_imap::AttestedIo::from_native(
            claim.account.clone(),
            claim.session.clone(),
            claim.pid,
            descriptions,
            io,
        ))
    }
}

fn publication(account: &str, pid: &str, fd_in: &UnixStream, fd_out: &UnixStream) -> Vec<u8> {
    use std::os::fd::AsRawFd;
    let count = if fd_in.as_raw_fd() == fd_out.as_raw_fd() {
        1
    } else {
        2
    };
    format!(
        "PUBLISH2\t{account}\tNativeSession01\t1\t{pid}\tfd_in={}\tfd_out={}\tfds={count}\n",
        fd_in.as_raw_fd(),
        fd_out.as_raw_fd()
    )
    .into_bytes()
}

#[test]
fn authenticated_policy_http_normalizes_empty_before_and_report_never_grants_ticket() {
    let f = Fixture::new();
    let endpoint = f.endpoint();
    let (result, response) = policy_socket(&endpoint, &http(&body("", ALICE), ""));
    assert_eq!(result, Ok(()));
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"\r\n\r\n{\"status\":0}"));
    assert_eq!(
        endpoint.policy(&body("after", ALICE), &API, "report", until()),
        Decision::Deny
    );
    assert_eq!(
        endpoint.policy(&body("after", ALICE), &API, "allow", until()),
        Decision::Allow
    );
    assert_eq!(
        endpoint.policy(&body("after", ALICE), &API, "allow", until()),
        Decision::Deny
    );
}

#[test]
fn private_api_and_managed_scope_are_exact_and_duplicate_json_does_not_normalize() {
    let f = Fixture::new();
    let endpoint = f.endpoint();
    let foreign = body("", "outside@osmap-policy.invalid");
    assert_eq!(
        endpoint.policy(&foreign, &[b'b'; 64], "allow", until()),
        Decision::Deny
    );
    assert_eq!(
        endpoint.policy(&foreign, &API, "allow", until()),
        Decision::Allow
    );
    assert_eq!(
        endpoint.policy(&foreign, &API, "report", until()),
        Decision::Allow
    );
    assert_eq!(
        endpoint.policy(
            br#"{"login":"alice@osmap-policy.invalid","login":"outside@osmap-policy.invalid"}"#,
            &API,
            "allow",
            until()
        ),
        Decision::Deny
    );
    assert_eq!(
        endpoint.policy(
            &body("", ALICE),
            &API,
            "allow",
            Instant::now() + Duration::from_secs(1)
        ),
        Decision::Deny
    );
    assert!(Endpoint::new(&f.fence, [b'G'; 64]).is_err());
}

#[test]
fn duplicate_headers_transfer_encoding_and_invalid_lengths_refuse_before_body() {
    let f = Fixture::new();
    let endpoint = f.endpoint();
    for bytes in [
        http(&body("", ALICE), "content-length: 1\r\n"),
        http(&body("", ALICE), "Transfer-Encoding: chunked\r\n"),
        b"POST /epoch/?command=allow HTTP/1.1\r\nContent-Length: 4097\r\n\r\n".to_vec(),
        b"POST /epoch/?command=allow HTTP/1.1\r\nContent-Length: 01\r\n\r\n".to_vec(),
        b"GET /epoch/?command=allow HTTP/1.1\r\nContent-Length: 1\r\n\r\n".to_vec(),
    ] {
        let (result, response) = policy_socket(&endpoint, &bytes);
        assert!(result.is_err());
        assert!(response.is_empty());
    }
}

#[test]
fn native_peer_denies_with_zero_intake_then_validated_pid_publishes_once_without_eof() {
    let f = Fixture::new();
    let endpoint = f.endpoint();
    let registry = crate::account_password_imap::Registry::new();
    let denied = Inspector {
        deny_before_read: true,
        expected_pid: 1234,
        observations: AtomicUsize::new(0),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(b"PUBLISH\t").unwrap();
    // Duplicate descriptor observes unread bytes after endpoint drops its own
    // refused connection, proving actual zero body intake at admission.
    let mut witness = server.try_clone().unwrap();
    assert_eq!(
        endpoint.final_connection(server, &denied, &registry, until()),
        Err(Error::Refused)
    );
    let mut raw = [0; 8];
    witness.read_exact(&mut raw).unwrap();
    assert_eq!(&raw, b"PUBLISH\t");
    drop(witness);
    drop(client);
    for phase in ["", "after"] {
        assert_eq!(
            endpoint.policy(&body(phase, ALICE), &API, "allow", until()),
            Decision::Allow
        );
    }
    let inspector = Inspector {
        deny_before_read: false,
        expected_pid: 1234,
        observations: AtomicUsize::new(0),
    };
    let mut alice_control = None;
    let (alice_io, mut alice_remote) = UnixStream::pair().unwrap();
    let (alice_out, mut alice_remote_out) = UnixStream::pair().unwrap();
    for expected in [b"OK\n".as_slice(), b"NO\n".as_slice()] {
        let (mut client, server) = UnixStream::pair().unwrap();
        publish_rights(
            &mut client,
            &publication(ALICE, "1234", &alice_io, &alice_out),
            &[&alice_io, &alice_out],
        );
        endpoint
            .final_connection(server, &inspector, &registry, until())
            .unwrap();
        let mut reply = [0; 3];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, expected);
        if expected == b"OK\n" {
            alice_control = Some(client);
        }
    }
    for phase in ["", "after"] {
        assert_eq!(
            endpoint.policy(&body(phase, BOB), &API, "allow", until()),
            Decision::Allow
        );
    }
    let bob_inspector = Inspector {
        deny_before_read: false,
        expected_pid: 1235,
        observations: AtomicUsize::new(0),
    };
    let (mut bob_control, server) = UnixStream::pair().unwrap();
    let (mut bob_io, mut bob_remote) = UnixStream::pair().unwrap();
    publish_rights(
        &mut bob_control,
        &publication(BOB, "1235", &bob_io, &bob_io),
        &[&bob_io],
    );
    endpoint
        .final_connection(server, &bob_inspector, &registry, until())
        .unwrap();
    let mut reply = [0; 3];
    bob_control.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"OK\n");
    assert!(!crate::openbsd::password_imap_control_eof(&bob_control).unwrap());
    let watcher = std::thread::spawn(move || {
        alice_remote
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(alice_remote.read(&mut [0]).unwrap(), 0);
        alice_remote_out
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(alice_remote_out.read(&mut [0]).unwrap(), 0);
        drop(alice_control);
    });
    struct Who(std::cell::Cell<usize>);
    impl crate::auth::CommandExecutor for Who {
        fn run_with_stdin_bytes(
            &self,
            program: &str,
            args: &[String],
            input: &[u8],
        ) -> Result<crate::auth::CommandExecution, crate::auth::CommandExecutionError> {
            assert_eq!(program, crate::account_password_mail::PROGRAM);
            assert_eq!(args.last().unwrap(), ALICE);
            assert!(input.is_empty());
            let count = self.0.get();
            self.0.set(count + 1);
            Ok(crate::auth::CommandExecution {
                status_code: 0,
                stdout: if count == 0 {
                    format!("username\t#\tproto\t(pids)\t(ips)\n{ALICE}\t1\timap\t(1234)\t(127.0.0.1)\n")
                } else {
                    "username\t#\tproto\t(pids)\t(ips)\n".into()
                },
                stderr: String::new(),
            })
        }
    }
    registry
        .terminate(
            &Who(std::cell::Cell::new(0)),
            ALICE,
            0,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    watcher.join().unwrap();
    assert!(!crate::openbsd::password_imap_control_eof(&bob_control).unwrap());
    bob_io.write_all(b"B").unwrap();
    let mut byte = [0];
    bob_remote.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"B");
    assert_eq!(inspector.observations.load(Ordering::SeqCst), 1);
}

#[test]
fn mismatched_claimed_pid_and_malformed_publication_never_reach_native_observer() {
    let f = Fixture::new();
    let endpoint = f.endpoint();
    let registry = crate::account_password_imap::Registry::new();
    for phase in ["", "after"] {
        assert_eq!(
            endpoint.policy(&body(phase, ALICE), &API, "allow", until()),
            Decision::Allow
        );
    }
    let inspector = Inspector {
        deny_before_read: false,
        expected_pid: 1234,
        observations: AtomicUsize::new(0),
    };
    for pid in ["1235", "01234", "1", "2147483647"] {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (io, _remote) = UnixStream::pair().unwrap();
        publish_rights(&mut client, &publication(ALICE, pid, &io, &io), &[&io]);
        endpoint
            .final_connection(server, &inspector, &registry, until())
            .unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"NO\n");
    }
    assert_eq!(inspector.observations.load(Ordering::SeqCst), 0);
}
