use super::*;
use crate::openpgp_inventory_runtime::{read_frame, write_frame};
use crate::totp::SystemTimeProvider;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::time::{Duration, Instant};
const KEY: [u8; 32] = [17; 32];
const PROOF: [u8; 32] = [19; 32];
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&text[n..n + 2], 16).unwrap())
        .collect()
}
fn current_fixture() -> Fixture {
    let mut f = Fixture::new();
    let now = SystemTimeProvider.unix_timestamp();
    f.clock.0.store(now, Ordering::SeqCst);
    f.session.record.issued_at = now;
    f.session.record.last_seen_at = now;
    f.session.record.expires_at = now + 3600;
    f.store().save(&f.session.record).unwrap();
    f
}
fn client(f: &Fixture, proof: bool) -> (crate::account_mutation_client::Client, UnixListener) {
    let socket = f.scratch.0.join("stored.sock");
    let key = f.scratch.0.join("stored.key");
    let proof_path = f.scratch.0.join("stored.proof");
    for (p, bytes) in [(&key, &KEY), (&proof_path, &PROOF)] {
        std::fs::write(p, bytes).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    let client = if proof {
        crate::account_mutation_client::Client::stored_fixture_files(
            &socket,
            &key,
            &proof_path,
            crate::openbsd::effective_uid(),
        )
    } else {
        crate::account_mutation_client::Client::guarded_fixture_files(
            &socket,
            &key,
            crate::openbsd::effective_uid(),
        )
    }
    .unwrap();
    (client, listener)
}
#[test]
fn runtime_real_stored_lease_challenge_ack_changed_then_unlocked_cleanup() {
    let f = current_fixture();
    let bob = SessionService::new(f.store(), &f.clock, SystemRandomSource, 3600, 1800)
        .issue(&f.context, "bob@example.test", RequiredSecondFactor::Totp)
        .unwrap();
    let bob_path = f.store().session_path(&bob.record.session_id);
    let bob_bytes = std::fs::read(&bob_path).unwrap();
    let (client, listener) = client(&f, true);
    let root = f.scratch.0.join("sessions");
    let context = f.context.clone();
    let token = f.token.clone();
    let epoch = f.epoch.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let raw = read_frame(&mut stream, crate::account_mutation::MAX_FRAME, deadline).unwrap();
        let millis = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let v = crate::account_mutation_continuity::tests::python(
            serde_json::json!({"mode":"challenge","frame_hex":hex(&raw),"now_millis":millis}),
        );
        assert_eq!(v["accepted"], true);
        let challenge = decode(v["challenge_hex"].as_str().unwrap());
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
        let ack = read_frame(
            &mut stream,
            crate::account_mutation_continuity::LIMIT,
            deadline,
        )
        .unwrap();
        let v = crate::account_mutation_continuity::tests::python(
            serde_json::json!({"mode":"ack","frame_hex":hex(&raw),"now_millis":millis,"challenge_hex":hex(&challenge),"ack_hex":hex(&ack)}),
        );
        assert_eq!(v["accepted"], true);
        assert!(concurrent
            .with_guarded_validated_session(&context, &token, |_| ())
            .is_err());
        let frame: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let request = crate::account_mutation::Verifier::default()
            .request(
                &decode(frame["budget"]["request_hex"].as_str().unwrap()),
                &KEY,
                SystemTimeProvider.unix_timestamp(),
            )
            .unwrap();
        let reply = request
            .response(
                crate::account_mutation::Outcome::Changed {
                    epoch: 4,
                    changed_at: "20261005030000".into(),
                },
                &KEY,
                SystemTimeProvider.unix_timestamp(),
            )
            .unwrap();
        epoch.value.store(4, Ordering::SeqCst);
        write_frame(&mut stream, &reply, deadline).unwrap();
    });
    let result = f
        .gateway
        .stored_completion_fixture(
            &f.context,
            &f.token,
            f.prepared(),
            (f.epoch.clone(), &f.clock),
            &client,
            Instant::now() + Duration::from_secs(8),
        )
        .unwrap();
    server.join().unwrap();
    assert_eq!(
        result,
        crate::session::BrowserRevocation::OldSessionsRevoked { count: 1 }
    );
    assert!(f
        .store()
        .load(&f.session.record.session_id)
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());
    assert_eq!(std::fs::read(bob_path).unwrap(), bob_bytes);
    // A fresh new-epoch login after completion proves the real store lock was released.
    let service = SessionService::new(f.store(), &f.clock, SystemRandomSource, 3600, 1800)
        .with_epoch_authority(f.epoch.clone());
    let fresh = service
        .issue_with_epoch(
            &f.context,
            "alice@example.test",
            RequiredSecondFactor::Totp,
            Some(4),
        )
        .unwrap();
    assert!(service.validate(&f.context, &fresh.token).is_ok());
}
#[test]
fn runtime_missing_proof_or_revoked_stored_record_submits_zero_frames() {
    for revoked in [false, true] {
        let f = current_fixture();
        let (client, listener) = client(&f, revoked);
        let prepared = f.prepared();
        if revoked {
            let mut row = f.session.record.clone();
            row.revoked_at = Some(f.clock.unix_timestamp());
            f.store().save(&row).unwrap();
        }
        let path = f.store().session_path(&f.session.record.session_id);
        let original = std::fs::read(&path).unwrap();
        let result = f.gateway.stored_completion_fixture(
            &f.context,
            &f.token,
            prepared,
            (f.epoch.clone(), &f.clock),
            &client,
            Instant::now() + Duration::from_secs(5),
        );
        assert_eq!(
            result,
            Err(if revoked {
                Error::Authentication
            } else {
                Error::Unavailable
            })
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}
#[test]
fn distinct_proof_files_and_default_off_native_authority_refuse_before_io() {
    let f = current_fixture();
    let (_, listener) = client(&f, true);
    let key = f.scratch.0.join("stored.key");
    let socket = f.scratch.0.join("stored.sock");
    assert!(matches!(
        crate::account_mutation_client::Client::stored_fixture_files(
            &socket,
            &key,
            &key,
            crate::openbsd::effective_uid()
        ),
        Err(crate::account_mutation_client::Error::Unavailable)
    ));
    assert!(matches!(
        crate::account_mutation_client::Client::from_operator_files_with_session_proof(
            std::path::Path::new("/missing/socket"),
            std::path::Path::new("/missing/key"),
            std::path::Path::new("/missing/proof"),
            0
        ),
        Err(crate::account_mutation_client::Error::Unavailable)
    ));
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[path = "password_real_worker_runtime_tests.rs"]
mod real_worker;
