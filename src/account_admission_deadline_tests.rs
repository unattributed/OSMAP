use super::*;
use std::thread;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        // Private transport fixtures cannot use the gate's group-writable
        // shared TMPDIR as an ancestor. Keep the random owned0700 fixture
        // beneath the canonical OS-owned sticky temporary root.
        let root = std::fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("osmap-admission-deadline-{name}"));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn client(&self) -> (Client, UnixListener) {
        let socket = self.0.join("account.sock");
        let key = self.0.join("grant.key");
        std::fs::write(&key, vec![29; 32]).unwrap();
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
#[test]
fn original_caller_deadline_cannot_be_renewed_for_late_signed_epoch_reply() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let bytes = read_frame(
            &mut stream,
            MAX_FRAME,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let mut verifier = Verifier::default();
        let request = verifier.request(&bytes, &[29; 32], now().unwrap()).unwrap();
        thread::sleep(Duration::from_millis(120));
        let response = request
            .response(Some(7), &[29; 32], now().unwrap())
            .unwrap();
        let _ = write_frame(
            &mut stream,
            &response,
            Instant::now() + Duration::from_secs(1),
        );
    });
    let start = Instant::now();
    let result = client.admit_before("alice@example.test", 7, start + Duration::from_millis(20));
    worker.join().unwrap();
    assert!(
        result.is_err(),
        "late signed response must not gain a fresh30s authorization"
    );
}
fn reply(listener: UnixListener, at: u64) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let bytes = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        let request = Verifier::default().request(&bytes, &[29; 32], at).unwrap();
        let response = request.response(Some(7), &[29; 32], at).unwrap();
        let _ = write_frame(&mut stream, &response, deadline);
    })
}
#[test]
fn expired_original_deadline_refuses_before_any_socket_or_credential_submission() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    listener.set_nonblocking(true).unwrap();
    let expired = Instant::now() - Duration::from_millis(1);
    assert_eq!(
        client.admit_before("alice@example.test", 7, expired),
        Err(Error::Expired)
    );
    assert_eq!(
        client.authenticate_before("alice@example.test", "public synthetic", expired),
        Err(Error::Expired)
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn both_bounded_apis_preserve_exact_authenticated_account_and_epoch() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let worker = thread::spawn(move || {
        let s = service(crate::openbsd::effective_uid());
        for n in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            s.connection_with(&mut stream, |request, _| {
                match request.operation() {
                    Operation::Authenticate { password } => {
                        assert_eq!(n, 0);
                        assert_eq!(password, "public synthetic");
                    }
                    Operation::Admit { epoch } => {
                        assert_eq!(n, 1);
                        assert_eq!(*epoch, 7);
                    }
                }
                Ok(Some(7))
            })
            .unwrap();
        }
    });
    let original = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        client
            .authenticate_before("alice@example.test", "public synthetic", original)
            .unwrap(),
        Some(Admission {
            account: "alice@example.test".into(),
            epoch: 7
        })
    );
    client
        .admit_before("alice@example.test", 7, original)
        .unwrap();
    worker.join().unwrap();
}
#[test]
fn authentication_read_timeout_uses_the_supplied_budget_without_a_retry() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let bytes = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        assert!(matches!(
            Verifier::default()
                .request(&bytes, &[29; 32], now().unwrap())
                .unwrap()
                .operation(),
            Operation::Authenticate { .. }
        ));
        thread::sleep(Duration::from_millis(120));
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    });
    let started = Instant::now();
    let result = client.authenticate_before(
        "alice@example.test",
        "public synthetic",
        started + Duration::from_millis(20),
    );
    let elapsed = started.elapsed();
    assert!(matches!(
        result,
        Err(Error::Unavailable) | Err(Error::Expired)
    ));
    assert!(elapsed < Duration::from_millis(100));
    worker.join().unwrap();
}
#[test]
fn final_clock_expiry_or_rollback_after_authenticated_response_is_never_admitted() {
    for final_at in [135, 100] {
        let scratch = Scratch::new();
        let (client, listener) = scratch.client();
        let worker = reply(listener, 100);
        let mut ticks = [100, 100, 100, 100, 101, final_at].into_iter();
        let result = client.execute_before_with_clock(
            "alice@example.test",
            Operation::Admit { epoch: 7 },
            Instant::now() + Duration::from_secs(1),
            || Ok(ticks.next().expect("clock samples")),
        );
        worker.join().unwrap();
        assert_eq!(result, Err(Error::Expired));
        assert!(ticks.next().is_none());
    }
}
#[test]
fn verifier_contention_refuses_without_waiting_past_original_deadline() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let worker = reply(listener, 100);
    let held = client.0.verifier.lock().unwrap();
    let started = Instant::now();
    let result = client.execute_before_with_clock(
        "alice@example.test",
        Operation::Admit { epoch: 7 },
        started + Duration::from_millis(100),
        || Ok(100),
    );
    assert_eq!(result, Err(Error::Unavailable));
    assert!(started.elapsed() < Duration::from_millis(100));
    drop(held);
    worker.join().unwrap();
}

#[test]
fn delayed_final_clock_cannot_return_an_admission_after_original_deadline() {
    let scratch = Scratch::new();
    let (client, listener) = scratch.client();
    let worker = reply(listener, 100);
    let mut samples = 0;
    let result = client.execute_before_with_clock(
        "alice@example.test",
        Operation::Admit { epoch: 7 },
        Instant::now() + Duration::from_millis(100),
        || {
            samples += 1;
            if samples == 6 {
                thread::sleep(Duration::from_millis(120));
            }
            Ok(100)
        },
    );
    worker.join().unwrap();
    assert_eq!(samples, 6);
    assert_eq!(result, Err(Error::Expired));
}
