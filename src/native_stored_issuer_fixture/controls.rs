use super::*;
use std::os::unix::net::UnixListener;
struct Fixture {
    root: PathBuf,
    listener: UnixListener,
    issuer: WarmIssuer,
}
impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "osmap-native-issuer-{}",
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("mutation.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let issuer = WarmIssuer::warm(&root, &socket, &[17; 32], &[19; 32]).unwrap();
        Self {
            root,
            listener,
            issuer,
        }
    }
    fn no_wire(&self) {
        self.listener.set_nonblocking(true).unwrap();
        assert_eq!(
            self.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn exact_native_accounts_are_real_stored_records_and_role_keys_are_distinct() {
    let f = Fixture::new();
    assert_eq!(f.issuer.session.record.canonical_username, ALICE);
    assert_eq!(f.issuer.service().list_for_user(BOB).unwrap().len(), 1);
    assert_ne!(
        fs::read(f.root.join("request.key")).unwrap(),
        fs::read(f.root.join("session.key")).unwrap()
    );
    f.no_wire();
}
#[test]
fn revoked_actual_current_record_refuses_before_any_socket_frame() {
    let f = Fixture::new();
    let mut record = f.issuer.session.record.clone();
    record.revoked_at = Some(SystemTimeProvider.unix_timestamp());
    FileSessionStore::new(f.root.join("sessions"))
        .save(&record)
        .unwrap();
    assert!(matches!(
        f.issuer.execute(Instant::now() + ORIGINAL),
        Err(Refusal::Current)
    ));
    f.no_wire();
}
#[test]
fn wrong_current_stored_account_refuses_without_alias_rewrite_or_frame() {
    let f = Fixture::new();
    let mut record = f.issuer.session.record.clone();
    record.canonical_username = BOB.into();
    FileSessionStore::new(f.root.join("sessions"))
        .save(&record)
        .unwrap();
    assert!(matches!(
        f.issuer.execute(Instant::now() + ORIGINAL),
        Err(Refusal::Current)
    ));
    f.no_wire();
}
#[test]
fn expired_original_preparation_does_not_connect_or_renew() {
    let f = Fixture::new();
    assert_eq!(
        f.issuer
            .execute(Instant::now() - Duration::from_millis(1))
            .err(),
        Some(Refusal::Preparation)
    );
    f.no_wire();
}

// This bridge forwards actual Rust/Python frames without account aliases. Its
// five controls use original3s; native topology/SQL/hash/policy are projections.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            crate::openbsd::kill_process_group(self.0.id()).unwrap();
            self.0.wait().unwrap();
        }
    }
}
fn exact(pipe: &mut impl Read, n: usize, deadline: Instant) -> Option<Vec<u8>> {
    assert!(n <= 12288);
    let mut data = vec![0; n];
    let mut at = 0;
    while at < n {
        assert!(Instant::now() < deadline, "fixture original read expired");
        match pipe.read(&mut data[at..]) {
            Ok(0) => return None,
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => panic!("fixture pipe refused"),
        }
    }
    Some(data)
}
fn child_frame(pipe: &mut impl Read, deadline: Instant) -> Option<Vec<u8>> {
    let head: [u8; 4] = exact(pipe, 4, deadline)?.try_into().unwrap();
    let n = u32::from_be_bytes(head) as usize;
    assert!((1..=4096).contains(&n));
    exact(pipe, n, deadline)
}
fn send(pipe: &mut impl Write, raw: &[u8], deadline: Instant) {
    assert!(!raw.is_empty() && raw.len() <= 12288);
    let data = [
        u32::try_from(raw.len()).unwrap().to_be_bytes().as_slice(),
        raw,
    ]
    .concat();
    let mut at = 0;
    while at < data.len() {
        assert!(Instant::now() < deadline, "fixture original write expired");
        match pipe.write(&data[at..]) {
            Ok(0) => panic!("fixture zero write"),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => panic!("fixture pipe refused"),
        }
    }
}
fn witness(root: &Path) -> serde_json::Value {
    let path = root.join("runtime-real-worker-witness.json");
    let info = fs::symlink_metadata(&path).unwrap();
    assert!(
        info.is_file()
            && info.uid() == crate::openbsd::effective_uid()
            && info.mode() & 0o777 == 0o600
            && info.nlink() == 1
    );
    let raw = fs::read(path).unwrap();
    assert!(raw.len() <= 1024);
    serde_json::from_slice(&raw).unwrap()
}
#[derive(Clone, Copy)]
enum Variant {
    Good,
    ChangedSignedChallenge,
    ForgedProof,
    NoWorkerAck,
    MissingTerminalEof,
}
fn exchange(variant: Variant) {
    let f = Fixture::new();
    let root = f.root.join("sessions");
    let context = f.issuer.context.clone();
    let token = f.issuer.token.clone();
    let epoch = f.issuer.epoch.clone();
    let worker_root = f.root.join("worker");
    fs::create_dir(&worker_root).unwrap();
    fs::set_permissions(&worker_root, fs::Permissions::from_mode(0o700)).unwrap();
    let deadline = Instant::now() + ORIGINAL;
    let (finished, receipt) = std::thread::scope(|scope| {
        let listener = &f.listener;
        let worker_root = &worker_root;
        let task = scope.spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
                crate::openbsd::effective_uid()
            );
            let mut raw =
                crate::openpgp_inventory_runtime::read_frame(&mut stream, 12288, deadline).unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(parsed["budget"]["account"], ALICE);
            let sent = parsed["budget"]["sent_millis"].as_u64().unwrap();
            let end = parsed["budget"]["deadline_millis"].as_u64().unwrap();
            assert!(end > sent && end - sent <= 3000); // Actual signed original receipt.
            if matches!(variant, Variant::ForgedProof) {
                let mut parsed = parsed;
                parsed["session_proof"]["signature"] = serde_json::json!("0".repeat(64));
                raw = serde_json::to_vec(&parsed).unwrap();
            }
            let mut child = OwnedChild(
                crate::auth::stored_issuer_fixture_command(worker_root)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .process_group(0)
                    .spawn()
                    .unwrap(),
            );
            let mut input = child.0.stdin.take().unwrap();
            let mut output = child.0.stdout.take().unwrap();
            let mut error = child.0.stderr.take().unwrap();
            for fd in [input.as_raw_fd(), output.as_raw_fd(), error.as_raw_fd()] {
                crate::openbsd::set_descriptor_nonblocking(fd).unwrap();
            }
            send(&mut input, &raw, deadline);
            if matches!(variant, Variant::ForgedProof) {
                drop(input);
                assert!(child_frame(&mut output, deadline).is_none());
            } else {
                let mut challenge = child_frame(&mut output, deadline).unwrap();
                let pending = witness(worker_root);
                assert_eq!(pending["stage"], "pending-before-challenge");
                assert_eq!(pending["pending_before_challenge"], true);
                assert_eq!(pending["proof_and_budget_verified"], true);
                assert_eq!(pending["epoch_state"], "pending");
                assert_eq!(pending["journal_state"], "pending");
                assert_eq!(pending["writer_calls"], 0);
                let concurrent = SessionService::new(
                    FileSessionStore::new(&root),
                    SystemTimeProvider,
                    SystemRandomSource,
                    3600,
                    1800,
                )
                .with_epoch_authority(epoch.clone());
                assert!(concurrent
                    .with_guarded_validated_session(&context, &token, |_| ())
                    .is_err());
                if matches!(variant, Variant::ChangedSignedChallenge) {
                    let mut value: serde_json::Value = serde_json::from_slice(&challenge).unwrap();
                    value["frame_sha256"] = serde_json::json!("0".repeat(64));
                    let payload = serde_json::to_vec(&serde_json::json!([
                        "osmap-account-mutation-continuity-v1",
                        value["phase"],
                        value["account"],
                        value["epoch"],
                        value["intent_reference"],
                        value["request_signature"],
                        value["frame_sha256"],
                        value["nonce"],
                        value["deadline_millis"],
                        value["challenged_millis"]
                    ]))
                    .unwrap();
                    let mut mac = Hmac::<Sha256>::new_from_slice(&[17; 32]).unwrap();
                    mac.update(&payload);
                    value["signature"] = serde_json::json!(mac
                        .finalize()
                        .into_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>());
                    challenge = serde_json::to_vec(&value).unwrap();
                }
                crate::openpgp_inventory_runtime::write_frame(&mut stream, &challenge, deadline)
                    .unwrap();
                let ack = crate::openpgp_inventory_runtime::read_frame(&mut stream, 2048, deadline);
                if matches!(variant, Variant::ChangedSignedChallenge) {
                    assert!(ack.is_err());
                    drop(input);
                    assert!(child_frame(&mut output, deadline).is_some());
                } else {
                    let ack = ack.unwrap();
                    assert!(concurrent
                        .with_guarded_validated_session(&context, &token, |_| ())
                        .is_err());
                    assert_eq!(exact(&mut stream, 1, deadline), None); // Actual Rust ACK write EOF, no second frame.
                    if !matches!(variant, Variant::NoWorkerAck) {
                        send(&mut input, &ack, deadline);
                    }
                    drop(input);
                    let terminal = child_frame(&mut output, deadline).unwrap();
                    assert!(exact(&mut output, 1, deadline).is_none());
                    crate::openpgp_inventory_runtime::write_frame(&mut stream, &terminal, deadline)
                        .unwrap();
                }
            }
            while child.0.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut metadata = Vec::new();
            error.read_to_end(&mut metadata).unwrap();
            assert!(metadata.len() <= 1024);
            let final_witness = witness(worker_root);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&metadata).unwrap(),
                final_witness
            );
            assert_eq!(final_witness["cleanup_confirmed"], true);
            if matches!(variant, Variant::MissingTerminalEof) {
                while Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            final_witness
        });
        let receipt = f.issuer.execute(deadline);
        let finished = task.join().unwrap();
        (finished, receipt)
    });
    assert_eq!(fs::read(&f.issuer.bob_path).unwrap(), f.issuer.bob_bytes);
    match variant {
        Variant::Good => {
            assert!(matches!(
                receipt.unwrap().outcome(),
                MutationOutcome::Changed { epoch: 1, .. }
            ));
            assert_eq!(finished["writer_calls"], 1);
            assert_eq!(finished["epoch_state"], "active");
        }
        Variant::NoWorkerAck => {
            assert!(matches!(
                receipt.unwrap().outcome(),
                MutationOutcome::Contained
            ));
            assert_eq!(finished["writer_calls"], 0);
            assert_eq!(finished["epoch_state"], "contained");
        }
        Variant::ChangedSignedChallenge | Variant::ForgedProof | Variant::MissingTerminalEof => {
            assert!(matches!(receipt, Err(Refusal::Transport)));
            assert_eq!(
                finished["writer_calls"],
                if matches!(variant, Variant::MissingTerminalEof) {
                    1
                } else {
                    0
                }
            );
            // A fresh attempted operation cannot clear the original client's
            // uncertainty/quarantine latch or reconnect. It is never a retry.
            assert!(matches!(
                f.issuer.execute(Instant::now() + Duration::from_secs(1)),
                Err(Refusal::Transport)
            ));
            f.no_wire();
        }
    }
    assert_eq!(f.issuer.service().list_for_user(BOB).unwrap().len(), 1);
}
#[test]
fn actual_native_account_worker_current_lease_pending_ack_and_terminal_eof() {
    exchange(Variant::Good);
}
#[test]
fn signed_wrong_original_frame_challenge_emits_no_ack_and_zero_writes() {
    exchange(Variant::ChangedSignedChallenge);
}
#[test]
fn wrong_independent_session_proof_never_challenges_and_zero_writes() {
    exchange(Variant::ForgedProof);
}
#[test]
fn worker_without_actual_ack_contains_pending_with_zero_writes() {
    exchange(Variant::NoWorkerAck);
}
#[test]
fn signed_changed_without_terminal_eof_stays_uncertain_and_cannot_reconnect() {
    exchange(Variant::MissingTerminalEof);
}

#[test]
fn actual_owned_bootstrap_socketpair_frames_and_current_identity() {
    let (owned, mut peer) = UnixStream::pair().unwrap();
    let mut control = BootstrapControl::owned(owned).unwrap();
    let end = Instant::now() + Duration::from_millis(500);
    crate::openpgp_inventory_runtime::write_frame(&mut peer, b"G", end).unwrap();
    assert_eq!(control.read(1, end).unwrap(), b"G");
    control.write(b"READY", end).unwrap();
    assert_eq!(
        crate::openpgp_inventory_runtime::read_frame(&mut peer, 5, end).unwrap(),
        b"READY"
    );
    let original = control.identity;
    control.identity.1 ^= 1;
    assert_eq!(
        control.write(b"private bytes must not send", end),
        Err(Refusal::Configuration)
    );
    control.identity = original;
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn nonstream_and_named_bootstrap_descriptors_refuse_before_wire() {
    use std::os::fd::IntoRawFd;
    let (owned, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert!(matches!(
        BootstrapControl::owned(
            crate::openbsd::fixture_owned_unix_stream(owned.into_raw_fd()).unwrap(),
        ),
        Err(Refusal::Configuration)
    ));
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert_eq!(
        peer.recv(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let f = Fixture::new();
    let connected = UnixStream::connect(f.root.join("mutation.sock")).unwrap();
    let (accepted, _) = f.listener.accept().unwrap();
    assert!(matches!(
        BootstrapControl::owned(connected),
        Err(Refusal::Configuration)
    ));
    accepted.set_nonblocking(true).unwrap();
    assert_eq!((&accepted).read(&mut byte).unwrap(), 0);
}
