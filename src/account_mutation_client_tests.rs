use super::*;
use crate::account_mutation::Outcome;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::AtomicU64;

const KEY: [u8; 32] = [17; 32];
const ACCOUNT: &str = "alice@example.test";
fn request() -> Request {
    crate::account_mutation::tests::issue("public-old-value", "public-new-passphrase", 3, 100)
        .unwrap()
}
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);
impl Clock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(101)))
    }
}
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        // Match the existing private-socket fixtures: the gate's shared
        // TMPDIR is group-writable and cannot be a trusted socket ancestor.
        // Only this randomly named, owner-only directory belongs to the test.
        let root = std::fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("osmap-mutation-client-{name}"));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn client(&self) -> (Client, UnixListener) {
        let socket = self.0.join("account.sock");
        let key = self.0.join("grant.key");
        std::fs::write(&key, KEY).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        (
            Client::qualified_files(&socket, &key, crate::openbsd::effective_uid()).unwrap(),
            listener,
        )
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
// Exact previously qualified Python adapter. It uses public disposable stores
// and callbacks only: no private native helper, SQL, authentication or Send.
fn python_reply(raw: &[u8], outcome: Outcome) -> Vec<u8> {
    let input = serde_json::to_vec(&serde_json::json!({
        "raw_hex":hex(raw),"now":101,"mode":"worker","outcome":outcome,
    }))
    .unwrap();
    let output = crate::auth::mutation_compatibility_fixture(&input).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["accepted"], true);
    assert_eq!(value["replay_refused"], true);
    let text = value["response_hex"].as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn changed() -> Outcome {
    Outcome::Changed {
        epoch: 4,
        changed_at: "19700101000140".into(),
    }
}

#[test]
fn native_disabled_even_when_private_paths_do_not_exist() {
    const {
        assert!(!NATIVE_CONFINEMENT_QUALIFIED);
    }
    assert_eq!(
        Client::from_operator_files(
            Path::new("/tmp/not-a-mutation-socket"),
            Path::new("/tmp/not-a-mutation-key"),
            0
        )
        .unwrap_err(),
        Error::Unavailable
    );
}
#[test]
fn actual_private_unix_exchange_python_three_outcomes_returns_only_sealed_receipt() {
    for outcome in [Outcome::KnownRefused, changed(), Outcome::Contained] {
        let scratch = Scratch::new();
        let (client, listener) = scratch.client();
        let expected = serde_json::to_value(&outcome).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                crate::openbsd::unix_stream_peer_uid(&stream).unwrap(),
                crate::openbsd::effective_uid()
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
            let reply = python_reply(&raw, outcome);
            write_frame(&mut stream, &reply, deadline).unwrap();
        });
        let receipt = client
            .execute_with(
                request(),
                Instant::now() + Duration::from_secs(2),
                &Clock::new(),
            )
            .unwrap();
        assert_eq!(serde_json::to_value(receipt.outcome()).unwrap(), expected);
        assert_eq!(receipt.account(), ACCOUNT);
        assert_eq!(receipt.old_epoch(), 3);
        assert_eq!((receipt.issued(), receipt.expires()), (100, 400));
        assert!(!format!("{receipt:?}").contains("public-old-value"));
        assert!(!format!("{client:?}").contains(&scratch.0.to_string_lossy().to_string()));
        server.join().unwrap();
    }
}
#[test]
fn known_refusal_allows_new_intent_but_exact_request_replay_never_reconnects() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
            write_frame(
                &mut stream,
                &python_reply(&raw, Outcome::KnownRefused),
                deadline,
            )
            .unwrap();
        }
    });
    let first = request();
    let bytes = first.bytes().unwrap();
    client
        .execute_with(
            first,
            Instant::now() + Duration::from_secs(2),
            &Clock::new(),
        )
        .unwrap();
    let duplicate = Verifier::default().request(&bytes, &KEY, 101).unwrap();
    assert_eq!(
        client
            .execute_with(
                duplicate,
                Instant::now() + Duration::from_secs(2),
                &Clock::new()
            )
            .unwrap_err(),
        Error::Replay
    );
    client
        .execute_with(
            request(),
            Instant::now() + Duration::from_secs(2),
            &Clock::new(),
        )
        .unwrap();
    server.join().unwrap();
}
#[test]
fn actual_wrong_peer_uid_sends_no_frame_or_private_credential() {
    let scratch = Scratch::new();
    let (mut client, _) = scratch.client();
    Arc::get_mut(&mut client.0).unwrap().helper_uid =
        crate::openbsd::effective_uid().wrapping_add(1);
    let (stream, mut reader) = UnixStream::pair().unwrap();
    assert_eq!(
        client
            .exchange(
                request(),
                request().bytes().unwrap(),
                stream,
                Instant::now() + Duration::from_secs(1),
                &Clock::new(),
                101
            )
            .unwrap_err(),
        Error::Unavailable
    );
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty());
    assert!(client.0.state.lock().unwrap().quarantine.is_empty());
}
#[test]
fn socket_symlink_unsafe_mode_and_wrong_owner_never_construct_qualified_client() {
    let scratch = Scratch::new();
    let (_, listener) = scratch.client();
    let socket = scratch.0.join("account.sock");
    let key = scratch.0.join("grant.key");
    let alias = scratch.0.join("alias.sock");
    std::os::unix::fs::symlink(&socket, &alias).unwrap();
    assert!(Client::qualified_files(&alias, &key, crate::openbsd::effective_uid()).is_err());
    assert!(Client::qualified_files(
        &socket,
        &key,
        crate::openbsd::effective_uid().wrapping_add(1)
    )
    .is_err());
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Client::qualified_files(&socket, &key, crate::openbsd::effective_uid()).is_err());
    drop(listener);
}

#[test]
fn private_mutation_key_hardlink_is_not_an_exclusive_authority_file() {
    let scratch = Scratch::new();
    let (_, _listener) = scratch.client();
    let key = scratch.0.join("grant.key");
    std::fs::hard_link(&key, scratch.0.join("second-grant-link")).unwrap();
    assert!(Client::qualified_files(
        &scratch.0.join("account.sock"),
        &key,
        crate::openbsd::effective_uid()
    )
    .is_err());
}
#[test]
fn malformed_frame_eof_trailing_or_bad_mac_is_uncertain_and_quarantined_no_retry() {
    for mode in 0..7 {
        let scratch = Scratch::new();
        let (client, listener) = scratch.client();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
            let mut reply = python_reply(&raw, changed());
            match mode {
                0 => stream.write_all(&[0, 0]).unwrap(),
                1 => stream.write_all(&0u32.to_be_bytes()).unwrap(),
                2 => stream
                    .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                    .unwrap(),
                3 => {
                    stream.write_all(&100u32.to_be_bytes()).unwrap();
                    stream.write_all(b"{}").unwrap();
                }
                4 => {
                    write_frame(&mut stream, &reply, deadline).unwrap();
                    stream.write_all(b"x").unwrap();
                }
                5 => {
                    let mut v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
                    v["signature"] = serde_json::json!("0".repeat(64));
                    reply = serde_json::to_vec(&v).unwrap();
                    write_frame(&mut stream, &reply, deadline).unwrap();
                }
                6 => {
                    let mut v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
                    v["request_id"] = serde_json::json!("other-public-request");
                    reply = serde_json::to_vec(&v).unwrap();
                    write_frame(&mut stream, &reply, deadline).unwrap();
                }
                _ => unreachable!(),
            }
        });
        assert_eq!(
            client
                .execute_with(
                    request(),
                    Instant::now() + Duration::from_secs(2),
                    &Clock::new()
                )
                .unwrap_err(),
            Error::Uncertain
        );
        assert_eq!(
            client
                .execute_with(
                    request(),
                    Instant::now() + Duration::from_secs(2),
                    &Clock::new()
                )
                .unwrap_err(),
            Error::Uncertain
        );
        assert_eq!(client.0.state.lock().unwrap().quarantine.len(), 1);
        server.join().unwrap();
    }
}
#[test]
fn original_caller_deadline_bounds_reply_timeout_without_new_phase_budget() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    // Prepare before timing the reply-timeout branch. A short setup allowance
    // could expire before any frame and correctly return Expired instead.
    let prepared = request();
    let clock = Clock::new();
    let (received, observed) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_frame(
            &mut stream,
            MAX_FRAME,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        received.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
    });
    let began = Instant::now();
    let outcome = client.execute_with(prepared, began + Duration::from_secs(1), &clock);
    let elapsed = began.elapsed();
    // Confirm actual submission; timeout must use the original caller bound,
    // not a fresh phase or the later server EOF at 1.5 seconds.
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(outcome.unwrap_err(), Error::Uncertain);
    assert_eq!(client.0.state.lock().unwrap().quarantine.len(), 1);
    assert!(elapsed < Duration::from_millis(1300));
    server.join().unwrap();
}
#[test]
fn valid_reply_without_eof_times_out_and_never_yields_success_receipt() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    // Prepare the exact signed reply before starting the transport deadline.
    // Python fixture startup must not consume the EOF timeout discriminator.
    let prepared = request();
    let expected_frame = prepared.bytes().unwrap();
    let reply = python_reply(&expected_frame, changed());
    let clock = Clock::new();
    let (written, observed) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        assert_eq!(raw, expected_frame);
        write_frame(&mut stream, &reply, deadline).unwrap();
        written.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
    });
    let began = Instant::now();
    let outcome = client.execute_with(prepared, began + Duration::from_secs(1), &clock);
    let elapsed = began.elapsed();
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(outcome.unwrap_err(), Error::Uncertain);
    assert_eq!(client.0.state.lock().unwrap().quarantine.len(), 1);
    assert!(elapsed < Duration::from_millis(1300));
    server.join().unwrap();
}
#[test]
fn fresh_signed_reply_after_wall_expiry_or_clock_rollback_is_uncertain() {
    for late in [400, 100] {
        let scratch = Scratch::new();
        let (client, listener) = scratch.client();
        let clock = Clock::new();
        let other = clock.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
            let reply = python_reply(&raw, changed());
            other.0.store(late, Ordering::SeqCst);
            write_frame(&mut stream, &reply, deadline).unwrap();
        });
        assert_eq!(
            client
                .execute_with(request(), Instant::now() + Duration::from_secs(2), &clock)
                .unwrap_err(),
            Error::Uncertain
        );
        server.join().unwrap();
    }
}

#[test]
fn post_verifier_wall_expiry_cannot_escape_as_terminal_receipt() {
    struct FinalExpiry(std::cell::Cell<usize>);
    impl TimeProvider for FinalExpiry {
        fn unix_timestamp(&self) -> u64 {
            let count = self.0.get() + 1;
            self.0.set(count);
            if count >= 6 {
                400
            } else {
                101
            }
        }
    }
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        write_frame(&mut stream, &python_reply(&raw, changed()), deadline).unwrap();
    });
    let clock = FinalExpiry(std::cell::Cell::new(0));
    assert_eq!(
        client
            .execute_with(request(), Instant::now() + Duration::from_secs(2), &clock)
            .unwrap_err(),
        Error::Uncertain
    );
    assert_eq!(clock.0.get(), 6);
    server.join().unwrap();
}
#[test]
fn expired_overlong_deadline_and_full_account_capacity_refuse_before_connection() {
    let scratch = Scratch::new();
    let (client, _) = scratch.client();
    assert_eq!(
        client
            .execute_with(request(), Instant::now(), &Clock::new())
            .unwrap_err(),
        Error::Expired
    );
    assert_eq!(
        client
            .execute_with(
                request(),
                Instant::now() + Duration::from_secs(61),
                &Clock::new()
            )
            .unwrap_err(),
        Error::Expired
    );
    let expired = Clock::new();
    expired.0.store(400, Ordering::SeqCst);
    assert_eq!(
        client
            .execute_with(request(), Instant::now() + Duration::from_secs(1), &expired)
            .unwrap_err(),
        Error::Expired
    );
    let _first = client.enter(ACCOUNT).unwrap();
    assert_eq!(
        client
            .execute_with(
                request(),
                Instant::now() + Duration::from_secs(1),
                &Clock::new()
            )
            .unwrap_err(),
        Error::Capacity
    );
    let _second = client.enter("bob@example.test").unwrap();
    assert!(matches!(
        client.enter("carol@example.test"),
        Err(Error::Capacity)
    ));
}

#[test]
fn bound_terminal_cleanup_failure_quarantines_same_client_after_receipt_consumption() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        write_frame(&mut stream, &python_reply(&raw, changed()), deadline).unwrap();
    });
    let receipt = client
        .execute_with(
            request(),
            Instant::now() + Duration::from_secs(2),
            &Clock::new(),
        )
        .unwrap();
    let account = receipt.account().to_owned();
    drop(receipt);
    client.quarantine_account(&account);
    assert_eq!(
        client
            .execute_with(
                request(),
                Instant::now() + Duration::from_secs(2),
                &Clock::new()
            )
            .unwrap_err(),
        Error::Uncertain
    );
    server.join().unwrap();
}

#[test]
fn quarantine_capacity_or_nonblocking_publication_failure_fail_globally_without_reset() {
    let scratch = Scratch::new();
    let (client, _listener) = scratch.client();
    for i in 0..MAX_QUARANTINE {
        client.quarantine_account(&format!("public{i}@example.test"));
    }
    assert_eq!(
        client.0.state.lock().unwrap().quarantine.len(),
        MAX_QUARANTINE
    );
    client.quarantine_account("overflow@example.test");
    assert!(matches!(client.enter(ACCOUNT), Err(Error::Uncertain)));
    assert_eq!(
        client.0.state.lock().unwrap().quarantine.len(),
        MAX_QUARANTINE
    );
    let (other, _other_listener) = {
        let scratch2 = Scratch::new();
        let pair = scratch2.client();
        (pair.0, pair.1)
    };
    let lock = other.0.state.lock().unwrap();
    other.quarantine_account(ACCOUNT);
    drop(lock);
    assert!(matches!(other.enter(ACCOUNT), Err(Error::Uncertain)));
}

#[test]
fn actual_budget_socket_carries_original_deadline_and_returns_matching_sealed_receipt() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let now = SystemTimeProvider.unix_timestamp();
    let request = crate::account_mutation::tests::issue_timed(
        "public-old-value",
        "public-new-passphrase",
        3,
        now,
        now,
    )
    .unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let frame = read_frame(
            &mut stream,
            crate::account_mutation_budget::MAX_FRAME,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let proof: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let result = crate::auth::mutation_budget_fixture(
            &serde_json::to_vec(&serde_json::json!({"raw_hex":hex(&frame),"now_millis":now_ms}))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&result).unwrap()["accepted"],
            true
        );
        assert!(
            proof["deadline_millis"].as_u64().unwrap() - proof["sent_millis"].as_u64().unwrap()
                <= 1000
        );
        let text = proof["request_hex"].as_str().unwrap();
        let raw: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        let request = Verifier::default().request(&raw, &KEY, now).unwrap();
        let response = request.response(Outcome::KnownRefused, &KEY, now).unwrap();
        write_frame(
            &mut stream,
            &response,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    });
    let receipt = client
        .execute_budget(request, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(receipt.outcome(), &Outcome::KnownRefused);
    server.join().unwrap();
}
