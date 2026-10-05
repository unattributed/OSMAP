//! Real worker proof/pending/ACK with real stored browser lease. SQL/auth/SMTP
//! remain synthetic; this does not qualify native factory or human password UAT.
use super::*;
use std::io::{Read, Write};
use std::os::{fd::AsRawFd, unix::process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Signal the exact still-owned unreaped group before wait. Never use a
        // historical reaped PID. Cleanup failure is a test failure, not success.
        if self.0.try_wait().unwrap().is_none() {
            crate::openbsd::kill_process_group(self.0.id()).unwrap();
            self.0.wait().unwrap();
        }
    }
}
fn nonblocking(pipe: &impl AsRawFd) {
    crate::openbsd::set_descriptor_nonblocking(pipe.as_raw_fd()).unwrap();
}

fn exact(pipe: &mut impl Read, n: usize, deadline: Instant) -> Option<Vec<u8>> {
    assert!(n <= 12288);
    let mut result = vec![0; n];
    let mut at = 0;
    while at < n {
        assert!(Instant::now() < deadline, "fixture read expired");
        match pipe.read(&mut result[at..]) {
            Ok(0) => return None,
            Ok(count) => at += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => panic!("fixture read refused: {error}"),
        }
    }
    assert!(Instant::now() < deadline);
    Some(result)
}
fn frame(pipe: &mut impl Read, deadline: Instant) -> Option<Vec<u8>> {
    let header: [u8; 4] = exact(pipe, 4, deadline)?.try_into().unwrap();
    let n = u32::from_be_bytes(header) as usize;
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
        assert!(Instant::now() < deadline, "fixture write expired");
        match pipe.write(&data[at..]) {
            Ok(0) => panic!("fixture zero write"),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => panic!("fixture write refused: {e}"),
        }
    }
}
fn witness(root: &Path) -> serde_json::Value {
    let p = root.join("runtime-real-worker-witness.json");
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let raw = std::fs::read(p).unwrap();
    assert!(raw.len() <= 1024);
    serde_json::from_slice(&raw).unwrap()
}
fn epoch_zero_fixture() -> Fixture {
    let mut f = current_fixture();
    f.epoch.value.store(0, Ordering::SeqCst);
    f.session.record.account_epoch = Some(0);
    f.store().save(&f.session.record).unwrap();
    f
}
/// This authority inserts an actual epoch1 login after guarded transport returns
/// and before browser cleanup. Issuance fails if the old store lock still exists.
struct IssuingAuthority {
    epoch: Arc<Epoch>,
    root: PathBuf,
    context: AuthenticationContext,
    fresh: Mutex<Option<(PathBuf, Vec<u8>)>>,
}
impl crate::account_admission::EpochAuthority for IssuingAuthority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        self.epoch.admit(account, epoch)?;
        if epoch == 1 {
            let mut fresh = self.fresh.lock().unwrap();
            if fresh.is_none() {
                let store = FileSessionStore::new(&self.root);
                let service =
                    SessionService::new(store, SystemTimeProvider, SystemRandomSource, 3600, 1800)
                        .with_epoch_authority(self.epoch.clone());
                let issued = service
                    .issue_with_epoch(&self.context, account, RequiredSecondFactor::Totp, Some(1))
                    .unwrap();
                let path =
                    FileSessionStore::new(&self.root).session_path(&issued.record.session_id);
                let bytes = std::fs::read(&path).unwrap();
                *fresh = Some((path, bytes));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Variant {
    Good,
    ForgedProof,
    ForgedAck,
    MissingTerminalEof,
}
fn exchange(variant: Variant) {
    let f = epoch_zero_fixture();
    let bob = SessionService::new(
        f.store(),
        SystemTimeProvider,
        SystemRandomSource,
        3600,
        1800,
    )
    .issue(&f.context, "bob@example.test", RequiredSecondFactor::Totp)
    .unwrap();
    let bob_path = f.store().session_path(&bob.record.session_id);
    let bob_before = std::fs::read(&bob_path).unwrap();
    let (client, listener) = client(&f, true);
    let root = f.scratch.0.join("sessions");
    let witness_root = f.scratch.0.join("real-worker");
    std::fs::create_dir(&witness_root).unwrap();
    std::fs::set_permissions(&witness_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let authority = Arc::new(IssuingAuthority {
        epoch: f.epoch.clone(),
        root: root.clone(),
        context: f.context.clone(),
        fresh: Mutex::new(None),
    });
    let deadline = Instant::now() + Duration::from_secs(4);
    let original = f.prepared_before(deadline);
    let epoch = f.epoch.clone();
    let context = f.context.clone();
    let token = f.token.clone();
    let child_witness = witness_root.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut raw =
            read_frame(&mut stream, crate::account_mutation::MAX_FRAME, deadline).unwrap();
        if matches!(variant, Variant::ForgedProof) {
            let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            v["session_proof"]["signature"] = serde_json::json!("0".repeat(64));
            raw = serde_json::to_vec(&v).unwrap();
        }
        let mut child = OwnedChild(
            crate::auth::mutation_real_worker_fixture_command(&child_witness)
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
        nonblocking(&input);
        nonblocking(&output);
        nonblocking(&error);
        send(&mut input, &raw, deadline);
        if matches!(variant, Variant::ForgedProof) {
            drop(input);
            assert!(frame(&mut output, deadline).is_none());
        } else {
            let challenge = frame(&mut output, deadline).unwrap();
            let pending = witness(&child_witness);
            assert_eq!(pending["stage"], "pending-before-challenge");
            assert_eq!(pending["proof_and_budget_verified"], true);
            assert_eq!(pending["pending_before_challenge"], true);
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
            write_frame(&mut stream, &challenge, deadline).unwrap();
            let mut ack = read_frame(
                &mut stream,
                crate::account_mutation_continuity::LIMIT,
                deadline,
            )
            .unwrap();
            assert!(concurrent
                .with_guarded_validated_session(&context, &token, |_| ())
                .is_err());
            if matches!(variant, Variant::ForgedAck) {
                let mut v: serde_json::Value = serde_json::from_slice(&ack).unwrap();
                v["signature"] = serde_json::json!("0".repeat(64));
                ack = serde_json::to_vec(&v).unwrap();
            }
            send(&mut input, &ack, deadline);
            assert_eq!(exact(&mut stream, 1, deadline), None); // Client ACK write-half-close.
            drop(input);
            let terminal = frame(&mut output, deadline).unwrap();
            assert!(exact(&mut output, 1, deadline).is_none());
            if !matches!(variant, Variant::ForgedAck) {
                epoch.value.store(1, Ordering::SeqCst);
            }
            write_frame(&mut stream, &terminal, deadline).unwrap();
        }
        while child.0.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut metadata = Vec::new();
        error.read_to_end(&mut metadata).unwrap();
        assert!(metadata.len() <= 1024);
        let final_witness = witness(&child_witness);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&metadata).unwrap(),
            final_witness
        );
        assert_eq!(final_witness["cleanup_confirmed"], true);
        if matches!(variant, Variant::MissingTerminalEof) {
            // Actual child is finished; withhold only bridge EOF on original
            // deadline to prove a signed Changed frame alone cannot be success.
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        (final_witness, listener)
    });
    let result = f.gateway.stored_completion_fixture(
        &f.context,
        &f.token,
        original,
        (authority.clone(), &SystemTimeProvider),
        &client,
        deadline,
    );
    let (observed, listener) = server.join().unwrap();
    assert_eq!(std::fs::read(&bob_path).unwrap(), bob_before);
    match variant {
        Variant::Good => {
            assert_eq!(
                result,
                Ok(crate::session::BrowserRevocation::OldSessionsRevoked { count: 1 })
            );
            assert_eq!(observed["writer_calls"], 1);
            assert_eq!(observed["epoch"], 1);
            assert_eq!(observed["epoch_state"], "active");
            let fresh = authority.fresh.lock().unwrap();
            let (path, bytes) = fresh
                .as_ref()
                .expect("new-epoch login entered before cleanup");
            assert_eq!(&std::fs::read(path).unwrap(), bytes);
        }
        Variant::ForgedAck => {
            assert!(matches!(
                result,
                Ok(crate::session::BrowserRevocation::Contained { .. })
            ));
            assert_eq!(observed["writer_calls"], 0);
            assert_eq!(observed["epoch_state"], "contained");
            assert!(authority.fresh.lock().unwrap().is_none());
        }
        Variant::ForgedProof | Variant::MissingTerminalEof => {
            assert_eq!(result, Err(Error::Unavailable));
            assert_eq!(
                observed["writer_calls"],
                if matches!(variant, Variant::ForgedProof) {
                    0
                } else {
                    1
                }
            );
            assert!(authority.fresh.lock().unwrap().is_none());
        }
    }
    if !matches!(variant, Variant::Good) {
        let now = SystemTimeProvider.unix_timestamp();
        let request = crate::account_mutation::tests::issue_timed(
            "public-old-value",
            "public-new-passphrase",
            0,
            now,
            now,
        )
        .unwrap();
        assert!(matches!(
            client.execute_budget(request, Instant::now() + Duration::from_secs(1)),
            Err(crate::account_mutation_client::Error::Uncertain)
        ));
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
#[test]
fn real_worker_pending_ack_original_deadline_then_new_epoch_login_preserved() {
    exchange(Variant::Good);
}
#[test]
fn real_worker_forged_independent_proof_writes_zero_and_never_challenges() {
    exchange(Variant::ForgedProof);
}
#[test]
fn real_worker_forged_ack_after_pending_writes_zero_and_contains() {
    exchange(Variant::ForgedAck);
}
#[test]
fn real_worker_changed_without_terminal_eof_is_uncertain_not_success() {
    exchange(Variant::MissingTerminalEof);
}
