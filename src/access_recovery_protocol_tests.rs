use super::*;
use serde_json::{json, Value};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

const KEY: &[u8] = b"public-rpc-test-purpose-key-000000000000000000";
const CSRF: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static NEXT: AtomicU64 = AtomicU64::new(0);
fn make_request() -> Request {
    Request::issue(
        Authority::Unauthenticated {},
        Action::Start {
            email: "alice@example.test".into(),
        },
        CSRF,
        "192.0.2.1",
        100,
        KEY,
    )
    .unwrap()
}
fn response(request: &Request) -> Response {
    Response::issue(
        request,
        Ok(AccessOutcome {
            view: AccessView::RecoveryCode {
                csrf: CSRF.into(),
                challenge_id: "a".repeat(64),
            },
            grant_cookie: AccessCookie::Unchanged,
        }),
        KEY,
        101,
    )
    .unwrap()
}

#[test]
fn signed_request_preserves_exact_browser_action_and_redacts_secret_debug() {
    let a = AccessAction::VerifyRecoveryCode {
        challenge_id: &"a".repeat(64),
        code: "123456",
    };
    let request = Request::from_browser(
        &AccessAuthority::Unauthenticated,
        Some(&a),
        CSRF,
        "192.0.2.1",
        100,
        KEY,
    )
    .unwrap();
    let parsed = Request::parse(&request.bytes().unwrap(), KEY, 101).unwrap();
    assert!(matches!(parsed.action(),Action::Verify{code,..}if code=="123456"));
    assert_eq!(parsed.csrf(), CSRF);
    assert!(!format!("{request:?} {:?}", request.action()).contains("123456"));
    assert_eq!(request.expires() - request.issued(), 30);
    assert_eq!(request.nonce().len(), 64);
}

#[test]
fn tampered_frames_unknown_fields_wrong_key_and_expiry_are_refused() {
    let request = make_request();
    let raw = request.bytes().unwrap();
    for (field, value) in [
        ("csrf", json!("d".repeat(64))),
        ("source", json!("198.51.100.1")),
        ("issued", json!(99)),
        ("expires", json!(131)),
        ("nonce", json!("a".repeat(64))),
        ("extra", json!(true)),
    ] {
        let mut frame: Value = serde_json::from_slice(&raw).unwrap();
        frame[field] = value;
        assert!(Request::parse(&serde_json::to_vec(&frame).unwrap(), KEY, 101).is_err());
    }
    let mut frame: Value = serde_json::from_slice(&raw).unwrap();
    frame["action"]["email"] = json!("bob@example.test");
    assert_eq!(
        Request::parse(&serde_json::to_vec(&frame).unwrap(), KEY, 101).unwrap_err(),
        Error::Authentication
    );
    assert_eq!(
        Request::parse(&raw, b"different-public-test-key-0000000000000000000", 101).unwrap_err(),
        Error::Authentication
    );
    assert_eq!(Request::parse(&raw, KEY, 130).unwrap_err(), Error::Expired);
    assert_eq!(Request::parse(&raw, KEY, 99).unwrap_err(), Error::Expired);
    let duplicate = String::from_utf8(raw)
        .unwrap()
        .replacen('{', "{\"schema\":\"duplicate\",", 1);
    assert_eq!(
        Request::parse(duplicate.as_bytes(), KEY, 101).unwrap_err(),
        Error::Invalid
    );
}

#[test]
fn durable_nonce_consumption_refuses_replay_after_service_reopen() {
    let path = std::env::temp_dir().join(format!(
        "osmap-access-rpc-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let request = make_request();
    let raw = request.bytes().unwrap();
    ReplayStore::new(path.clone())
        .verify_and_consume(&raw, KEY, 101)
        .unwrap();
    assert_eq!(
        ReplayStore::new(path.clone())
            .verify_and_consume(&raw, KEY, 102)
            .unwrap_err(),
        Error::Replay
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn responses_bind_nonce_request_mac_body_and_failure_kind() {
    let request = make_request();
    let raw = response(&request).bytes().unwrap();
    let outcome = Response::verify(&raw, &request, KEY, 102).unwrap().unwrap();
    assert!(matches!(outcome.view, AccessView::RecoveryCode { .. }));
    assert!(Response::verify(&raw, &make_request(), KEY, 102).is_err());
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["result"]["Ok"]["view"]["challenge_id"] = json!("b".repeat(64));
    assert!(Response::verify(&serde_json::to_vec(&changed).unwrap(), &request, KEY, 102).is_err());
    assert!(Response::verify(&raw, &request, KEY, 130).is_err());
    for error in [
        AccessError::Refused,
        AccessError::Expired,
        AccessError::Conflict,
        AccessError::Throttled,
        AccessError::Unavailable,
        AccessError::Unconfirmed,
    ] {
        let bytes = Response::issue(&request, Err(error), KEY, 101)
            .unwrap()
            .bytes()
            .unwrap();
        assert_eq!(
            Response::verify(&bytes, &request, KEY, 102)
                .unwrap()
                .unwrap_err(),
            error
        );
    }
}

#[test]
fn response_unknown_fields_and_wrong_csrf_are_refused_after_real_serialization() {
    let request = make_request();
    let mut raw: Value = serde_json::from_slice(&response(&request).bytes().unwrap()).unwrap();
    raw["result"]["Ok"]["view"]["extra"] = json!("unsupported");
    assert_eq!(
        Response::verify(&serde_json::to_vec(&raw).unwrap(), &request, KEY, 102).unwrap_err(),
        Error::Invalid
    );
    let wrong = Response::issue(
        &request,
        Ok(AccessOutcome {
            view: AccessView::RecoveryEmail {
                csrf: "d".repeat(64),
            },
            grant_cookie: AccessCookie::Unchanged,
        }),
        KEY,
        101,
    )
    .unwrap();
    assert_eq!(
        Response::verify(&wrong.bytes().unwrap(), &request, KEY, 102).unwrap_err(),
        Error::Authentication
    );
}

#[test]
fn authority_action_combinations_cannot_select_unrelated_privileged_route() {
    assert_eq!(
        Request::issue(
            Authority::Unauthenticated {},
            Action::BeginReset {
                password: "public-test-password".into(),
                totp: "123456".into()
            },
            CSRF,
            "192.0.2.1",
            100,
            KEY
        )
        .unwrap_err(),
        Error::Invalid
    );
    let grant = || Authority::Grant {
        token: "a".repeat(64),
    };
    assert_eq!(
        Request::issue(
            grant(),
            Action::Start {
                email: "bob@example.test".into()
            },
            CSRF,
            "192.0.2.1",
            100,
            KEY
        )
        .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        Request::issue(
            grant(),
            Action::Confirm {
                enrollment_id: "b".repeat(64),
                revision: 1,
                code: "123456".into(),
                password: None,
                confirmation: None
            },
            CSRF,
            "192.0.2.1",
            100,
            KEY
        )
        .unwrap_err(),
        Error::Invalid
    );
    assert!(Request::issue(
        grant(),
        Action::Confirm {
            enrollment_id: "b".repeat(64),
            revision: 1,
            code: "123456".into(),
            password: Some("public-new-password".into()),
            confirmation: Some("public-new-password".into())
        },
        CSRF,
        "192.0.2.1",
        100,
        KEY
    )
    .is_ok());
}

#[test]
fn pending_enrollment_roundtrips_privately_without_normal_session_payload() {
    let request = Request::issue(
        Authority::Grant {
            token: "a".repeat(64),
        },
        Action::View {},
        CSRF,
        "192.0.2.1",
        100,
        KEY,
    )
    .unwrap();
    let enrollment = PendingEnrollment {
        id: "b".repeat(64),
        revision: 1,
        secret_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
        otpauth_uri: "otpauth://totp/public-test?secret=PUBLICVECTOR".into(),
        expires_at: 700,
    };
    let raw = Response::issue(
        &request,
        Ok(AccessOutcome {
            view: AccessView::RecoverySetup {
                csrf: CSRF.into(),
                enrollment,
            },
            grant_cookie: AccessCookie::Unchanged,
        }),
        KEY,
        101,
    )
    .unwrap();
    assert!(!format!("{raw:?}").contains("GEZDG"));
    let bytes = raw.bytes().unwrap();
    let result = Response::verify(&bytes, &request, KEY, 102)
        .unwrap()
        .unwrap();
    assert!(
        matches!(result.view,AccessView::RecoverySetup{enrollment,..}if enrollment.revision==1&&enrollment.id=="b".repeat(64))
    );
    assert!(!String::from_utf8(bytes).unwrap().contains("session_token"));
}

#[test]
fn authenticated_response_still_cannot_switch_session_account_or_mint_early_grant() {
    let request = Request::issue(
        Authority::Session {
            account: "alice@example.test".into(),
            epoch: 3,
            session_id: "a".repeat(64),
        },
        Action::View {},
        CSRF,
        "192.0.2.1",
        100,
        KEY,
    )
    .unwrap();
    let response = Response::issue(
        &request,
        Ok(AccessOutcome {
            view: AccessView::TotpResetStart {
                account: "bob@example.test".into(),
                csrf: CSRF.into(),
            },
            grant_cookie: AccessCookie::Unchanged,
        }),
        KEY,
        101,
    )
    .unwrap();
    assert_eq!(
        Response::verify(&response.bytes().unwrap(), &request, KEY, 102).unwrap_err(),
        Error::Authentication
    );
    let unauthenticated = make_request();
    let early = Response::issue(
        &unauthenticated,
        Ok(AccessOutcome {
            view: AccessView::RecoveryEmail { csrf: CSRF.into() },
            grant_cookie: AccessCookie::Set("b".repeat(64)),
        }),
        KEY,
        101,
    )
    .unwrap();
    assert_eq!(
        Response::verify(&early.bytes().unwrap(), &unauthenticated, KEY, 102).unwrap_err(),
        Error::Authentication
    );
}

#[test]
fn original_workflow_expiry_can_only_shorten_request_and_response_authority() {
    let shortened = make_request().bound_expiry(105, KEY).unwrap();
    let bytes = shortened.bytes().unwrap();
    assert_eq!(Request::parse(&bytes, KEY, 104).unwrap().expires(), 105);
    assert_eq!(
        Request::parse(&bytes, KEY, 105).unwrap_err(),
        Error::Expired
    );
    let reply = response(&shortened).bytes().unwrap();
    assert!(Response::verify(&reply, &shortened, KEY, 104).is_ok());
    assert_eq!(
        Response::verify(&reply, &shortened, KEY, 105).unwrap_err(),
        Error::Expired
    );
    assert_eq!(
        shortened.bound_expiry(106, KEY).unwrap_err(),
        Error::Expired
    );
    assert_eq!(
        make_request().bound_expiry(100, KEY).unwrap_err(),
        Error::Expired
    );
    assert_eq!(
        make_request().bound_expiry(131, KEY).unwrap_err(),
        Error::Expired
    );
    assert_eq!(
        make_request()
            .bound_expiry(105, b"wrong-public-key-000000000000000000000000")
            .unwrap_err(),
        Error::Authentication
    );
}

#[test]
fn durable_replay_storage_is_fixed_and_refuses_full_then_prunes_expired_entries() {
    let path = std::env::temp_dir().join(format!(
        "osmap-access-rpc-bounded-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let store = ReplayStore::new(path.clone());
    let locked = store.0.lock("current").unwrap();
    let full = ReplayRecord {
        version: 1,
        updated_at: 100,
        entries: (0..512)
            .map(|n| UsedNonce {
                version: 1,
                nonce: format!("{n:064x}"),
                request_signature: "a".repeat(64),
                issued: 100,
                expires: 130,
            })
            .collect(),
    };
    locked.write(&serde_json::to_vec(&full).unwrap()).unwrap();
    drop(locked);
    assert_eq!(
        store
            .verify_and_consume(&make_request().bytes().unwrap(), KEY, 101)
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    let later = Request::issue(
        Authority::Unauthenticated {},
        Action::View {},
        CSRF,
        "192.0.2.1",
        131,
        KEY,
    )
    .unwrap();
    store
        .verify_and_consume(&later.bytes().unwrap(), KEY, 132)
        .unwrap();
    let actual: ReplayRecord =
        serde_json::from_slice(&store.0.read("current").unwrap().unwrap()).unwrap();
    assert_eq!(actual.entries.len(), 1);
    assert_eq!(actual.entries[0].nonce, later.nonce());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    fs::remove_dir_all(path).unwrap();
}
