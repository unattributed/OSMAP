use super::*;
const KEY: [u8; 32] = [17; 32];
fn authenticate() -> Request {
    Request::issue(
        "alice@example.test",
        Operation::Authenticate {
            password: "synthetic only".into(),
        },
        100,
        &KEY,
    )
    .unwrap()
}
#[test]
fn secret_debug_control_injection_and_unknown_operations_refused() {
    let r = authenticate();
    assert!(!format!("{r:?} {:?}", r.operation()).contains("synthetic only"));
    for password in ["", "line\ninjection", "secret\0", "\u{85}"] {
        assert!(Request::issue(
            "alice@example.test",
            Operation::Authenticate {
                password: password.into()
            },
            100,
            &KEY
        )
        .is_err());
    }
    let mut v: serde_json::Value = serde_json::from_slice(&r.bytes().unwrap()).unwrap();
    v["operation"] = serde_json::json!({"operation":"change","password":"synthetic"});
    assert!(Verifier::default()
        .request(&serde_json::to_vec(&v).unwrap(), &KEY, 100)
        .is_err());
}
#[test]
fn signed_request_password_account_tampering_expiry_replay_refused() {
    let r = authenticate();
    let b = r.bytes().unwrap();
    let mut verifier = Verifier::default();
    assert!(verifier.request(&b, &KEY, 100).is_ok());
    assert_eq!(verifier.request(&b, &KEY, 100).unwrap_err(), Error::Replay);
    for field in ["account", "operation"] {
        let mut v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        v[field] = if field == "account" {
            serde_json::json!("bob@example.test")
        } else {
            serde_json::json!({"operation":"authenticate","password":"changed synthetic"})
        };
        assert!(Verifier::default()
            .request(&serde_json::to_vec(&v).unwrap(), &KEY, 100)
            .is_err());
    }
    assert_eq!(
        Verifier::default().request(&b, &KEY, 135).unwrap_err(),
        Error::Expired
    );
    assert!(Verifier::default().request(&b, &[3; 32], 100).is_err());
}
#[test]
fn exact_response_request_binding_and_epoch_not_retargeted() {
    let r = authenticate();
    let b = r.response(Some(4), &KEY, 100).unwrap();
    let mut v = Verifier::default();
    assert_eq!(v.response(&r, &b, &KEY, 100).unwrap().unwrap().epoch, 4);
    assert_eq!(v.response(&r, &b, &KEY, 100).unwrap_err(), Error::Replay);
    let other = authenticate();
    assert!(Verifier::default().response(&other, &b, &KEY, 100).is_err());
    let epoch = Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: 4 },
        100,
        &KEY,
    )
    .unwrap();
    let changed = epoch.response(Some(5), &KEY, 100).unwrap();
    assert_eq!(
        Verifier::default()
            .response(&epoch, &changed, &KEY, 100)
            .unwrap_err(),
        Error::Refused
    );
    assert!(Verifier::default()
        .response(&epoch, &epoch.response(None, &KEY, 100).unwrap(), &KEY, 100)
        .is_err());
}
#[test]
fn duplicate_unknown_and_oversized_wire_refused() {
    let b = String::from_utf8(authenticate().bytes().unwrap()).unwrap();
    let repeated = b.replacen('{', "{\"account\":\"bob@example.test\",", 1);
    assert!(Verifier::default()
        .request(repeated.as_bytes(), &KEY, 100)
        .is_err());
    let unknown = b.replacen('{', "{\"root\":\"/tmp/untrusted\",", 1);
    assert!(Verifier::default()
        .request(unknown.as_bytes(), &KEY, 100)
        .is_err());
    assert!(Verifier::default()
        .request(&vec![b' '; MAX_FRAME + 1], &KEY, 100)
        .is_err());
}

#[test]
fn authoritative_profile_options_globs_and_noncanonical_accounts_refused() {
    for account in [
        "--help",
        "*",
        "alice*@example.test",
        "-x@example.test",
        "alice@example.test@other",
        "alice@invalid_underscore",
    ] {
        assert!(Request::issue(account, Operation::Admit { epoch: 0 }, 100, &KEY).is_err());
    }
}

#[test]
fn last_readable_epoch_response_and_request_bounds_align() {
    let auth = authenticate();
    let response = auth.response(Some(u64::MAX - 1), &KEY, 100).unwrap();
    assert_eq!(
        Verifier::default()
            .response(&auth, &response, &KEY, 100)
            .unwrap()
            .unwrap()
            .epoch,
        u64::MAX - 1
    );
    assert!(auth.response(Some(u64::MAX), &KEY, 100).is_err());
    let admit = Request::issue(
        "alice@example.test",
        Operation::Admit {
            epoch: u64::MAX - 1,
        },
        100,
        &KEY,
    )
    .unwrap();
    assert!(Verifier::default()
        .request(&admit.bytes().unwrap(), &KEY, 100)
        .is_ok());
    assert!(Request::issue(
        "alice@example.test",
        Operation::Admit { epoch: u64::MAX },
        100,
        &KEY
    )
    .is_err());
}
