use super::*;
use crate::openpgp_inventory_runtime::{read_frame, write_frame};
use crate::totp::SystemTimeProvider;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
        .collect()
}
fn current_service(
    f: &Fixture,
) -> SessionService<FileSessionStore, SystemTimeProvider, SystemRandomSource> {
    SessionService::new(
        FileSessionStore::new(&f.root),
        SystemTimeProvider,
        SystemRandomSource,
        3600,
        1800,
    )
    .with_epoch_authority(Arc::new(Epoch))
}
fn current_request(f: &Fixture, deadline: Instant) -> Request {
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor);
    let rate = crate::password_change_rate::Store::new(f.root.join("current-rate"));
    let prepared = password_change::prepare_before(
        password_change::Services {
            primary: &Epoch,
            factor: &factor,
            epoch: &Epoch,
            rate: &rate,
            clock: &SystemTimeProvider,
            policy: AuthenticationPolicy::default(),
        },
        password_change::Attempt {
            context: &f.context,
            session: &f.session,
            request: password_change::Request::new(
                "public-old-value",
                "public-new-passphrase",
                "public-new-passphrase",
                "123456",
            )
            .unwrap(),
        },
        deadline,
    )
    .authorization
    .unwrap();
    Request::issue(
        prepared
            .into_dispatch(&f.context, &f.session, &Epoch, &SystemTimeProvider)
            .unwrap(),
        &KEY,
        SystemTimeProvider.unix_timestamp(),
    )
    .unwrap()
}
fn scenario(challenge: bool) {
    let mut f = Fixture::new();
    let wall = SystemTimeProvider.unix_timestamp();
    f.session.record.issued_at = wall;
    f.session.record.last_seen_at = wall;
    f.session.record.expires_at = wall + 3600;
    FileSessionStore::new(&f.root)
        .save(&f.session.record)
        .unwrap();
    let socket = f.root.join("continuous.sock");
    let key = f.root.join("continuous.key");
    std::fs::write(&key, KEY).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
    let client = crate::account_mutation_client::Client::guarded_fixture_files(
        &socket,
        &key,
        crate::openbsd::effective_uid(),
    )
    .unwrap();
    let root = f.root.clone();
    let context = f.context.clone();
    let token = f.token.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let raw = read_frame(&mut stream, MAX_FRAME, deadline).unwrap();
        let at = SystemTimeProvider.unix_timestamp();
        let millis = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        assert_eq!(super::python(&raw, millis)["accepted"], true);
        let contending = SessionService::new(
            FileSessionStore::new(root),
            SystemTimeProvider,
            SystemRandomSource,
            3600,
            1800,
        )
        .with_epoch_authority(Arc::new(Epoch));
        assert!(contending
            .with_guarded_validated_session(&context, &token, |_| ())
            .is_err());
        if challenge {
            let v = crate::account_mutation_continuity::tests::python(
                serde_json::json!({"mode":"challenge","frame_hex":hex(&raw),"now_millis":millis}),
            );
            assert_eq!(v["accepted"], true);
            let encoded = unhex(v["challenge_hex"].as_str().unwrap());
            write_frame(&mut stream, &encoded, deadline).unwrap();
            let ack = read_frame(
                &mut stream,
                crate::account_mutation_continuity::LIMIT,
                deadline,
            )
            .unwrap();
            let v = crate::account_mutation_continuity::tests::python(
                serde_json::json!({"mode":"ack","frame_hex":hex(&raw),"now_millis":millis,"challenge_hex":hex(&encoded),"ack_hex":hex(&ack)}),
            );
            assert_eq!(v["accepted"], true);
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            let mut trailing = [0u8; 1];
            assert_eq!(std::io::Read::read(&mut stream, &mut trailing).unwrap(), 0);
            assert!(contending
                .with_guarded_validated_session(&context, &token, |_| ())
                .is_err());
        }
        let guarded: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let outcome = if challenge {
            serde_json::json!({"status":"known_refused"})
        } else {
            serde_json::json!({"status":"changed","epoch":4,"changed_at":"20261004170000"})
        };
        let input=serde_json::to_vec(&serde_json::json!({"raw_hex":guarded["budget"]["request_hex"],"now":at,"mode":"response","outcome":outcome})).unwrap();
        let output = crate::auth::mutation_compatibility_fixture(&input).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["accepted"], true);
        write_frame(
            &mut stream,
            &unhex(response["response_hex"].as_str().unwrap()),
            deadline,
        )
        .unwrap();
    });
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let request = current_request(&f, deadline);
    let result = current_service(&f)
        .with_guarded_session_lease(&f.context, &f.token, |_, lease| {
            let action = lease
                .authorize_mutation(request, &KEY, &SESSION_KEY, deadline)
                .unwrap();
            client.execute_guarded_continuous(action)
        })
        .unwrap();
    if challenge {
        assert!(matches!(
            result.unwrap().outcome(),
            crate::account_mutation::Outcome::KnownRefused
        ));
    } else {
        assert_eq!(
            result.unwrap_err(),
            crate::account_mutation_client::Error::Uncertain
        );
    }
    server.join().unwrap();
    current_service(&f)
        .with_guarded_validated_session(&f.context, &f.token, |_| ())
        .unwrap();
}
#[test]
fn actual_current_stored_lease_and_private_peer_roundtrip_authenticated_ack_without_native_writer()
{
    scenario(true);
}
#[test]
fn signed_changed_reply_without_pending_challenge_never_yields_success_receipt() {
    scenario(false);
}
