use super::*;
const KEY: &[u8] = &[42; 32];
const EMPTY: &[u8] = br#"{"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.5.18","keys":[]}"#;
fn request(action: Action, now: u64) -> Request {
    Request::issue(
        "alice",
        action,
        action.mutation().then_some(&"a".repeat(64)),
        action.mutation().then_some(&"A".repeat(40)),
        if action == Action::ImportPublic {
            b"public certificate fixture"
        } else {
            b""
        },
        now,
        KEY,
    )
    .unwrap()
}
fn snapshot() -> PublicSnapshot {
    PublicSnapshot {
        inventory: Inventory::parse(EMPTY).unwrap(),
        revision: "b".repeat(64),
    }
}
#[test]
fn every_operation_roundtrips_and_signed_errors_remain_typed() {
    for action in [Action::Snapshot, Action::ImportPublic, Action::RemovePublic] {
        let request = request(action, 100);
        let decoded = Verifier::default()
            .request(&request.to_bytes().unwrap(), KEY, 101)
            .unwrap();
        assert_eq!(decoded.account(), "alice");
        assert_eq!(decoded.action(), action);
        assert_eq!(decoded.certificate(), request.certificate());
        let reply = decoded.response(Ok(snapshot()), KEY, 102).unwrap();
        let result = Verifier::default()
            .response(&request, &reply, KEY, 102)
            .unwrap()
            .unwrap();
        assert_eq!(result.revision, "b".repeat(64));
        for error in [
            Error::Stale,
            Error::Busy,
            Error::Invalid,
            Error::Unconfirmed,
        ] {
            let reply = decoded.response(Err(error), KEY, 102).unwrap();
            assert_eq!(
                Verifier::default()
                    .response(&request, &reply, KEY, 102)
                    .unwrap()
                    .unwrap_err(),
                error
            );
        }
    }
}
#[test]
fn tampering_any_authority_or_certificate_refuses() {
    let original = request(Action::ImportPublic, 100);
    let mut changed = original.header.clone();
    for field in 0..6 {
        changed.clone_from(&original.header);
        match field {
            0 => changed.account = "bob".into(),
            1 => changed.nonce = "f".repeat(32),
            2 => changed.revision = Some("c".repeat(64)),
            3 => changed.fingerprint = Some("B".repeat(40)),
            4 => {
                changed.issued = 99;
                changed.expires = 109;
            }
            _ => changed.action = Action::RemovePublic,
        }
        let bytes = frame(&changed, &original.body).unwrap();
        assert!(Verifier::default().request(&bytes, KEY, 101).is_err());
    }
    let mut body = original.body.clone();
    body[0] ^= 1;
    assert_eq!(
        Verifier::default()
            .request(&frame(&original.header, &body).unwrap(), KEY, 101)
            .err(),
        Some(Error::Authentication)
    );
    assert_eq!(
        Verifier::default()
            .request(&original.to_bytes().unwrap(), &[43; 32], 101)
            .err(),
        Some(Error::Authentication)
    );
}
#[test]
fn replay_expiry_and_clock_rollback_refuse() {
    let r = request(Action::RemovePublic, 100);
    let bytes = r.to_bytes().unwrap();
    let mut v = Verifier::default();
    v.request(&bytes, KEY, 100).unwrap();
    assert_eq!(v.request(&bytes, KEY, 101).err(), Some(Error::Replay));
    assert_eq!(v.request(&bytes, KEY, 110).err(), Some(Error::Expired));
    assert_eq!(v.request(&bytes, KEY, 105).err(), Some(Error::Expired));
    let reply = r.response(Ok(snapshot()), KEY, 100).unwrap();
    let mut v = Verifier::default();
    v.response(&r, &reply, KEY, 100).unwrap().unwrap();
    assert_eq!(v.response(&r, &reply, KEY, 100).err(), Some(Error::Replay));
    assert_eq!(v.response(&r, &reply, KEY, 111).err(), Some(Error::Expired));
    assert_eq!(v.response(&r, &reply, KEY, 105).err(), Some(Error::Expired));
}
#[test]
fn response_is_bound_to_account_action_nonce_and_exact_metadata() {
    let r = request(Action::Snapshot, 100);
    let reply = r.response(Ok(snapshot()), KEY, 100).unwrap();
    let other = request(Action::Snapshot, 100);
    assert_eq!(
        Verifier::default().response(&other, &reply, KEY, 100).err(),
        Some(Error::Authentication)
    );
    let mut damaged = reply.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        Verifier::default().response(&r, &damaged, KEY, 100).err(),
        Some(Error::Authentication)
    );
    let (mut header, body) = parse(&reply).unwrap();
    header.account = "bob".into();
    header.mac = hex(&authenticate(KEY, &header, body)
        .unwrap()
        .finalize()
        .into_bytes());
    assert_eq!(
        Verifier::default()
            .response(&r, &frame(&header, body).unwrap(), KEY, 100)
            .err(),
        Some(Error::Authentication)
    );
    let (mut header, body) = parse(&reply).unwrap();
    header.action = Action::RemovePublic;
    header.mac = hex(&authenticate(KEY, &header, body)
        .unwrap()
        .finalize()
        .into_bytes());
    assert_eq!(
        Verifier::default()
            .response(&r, &frame(&header, body).unwrap(), KEY, 100)
            .err(),
        Some(Error::Authentication)
    );
}
#[test]
fn frame_limits_unknown_fields_duplicates_and_private_path_fields_refuse() {
    assert_eq!(
        Request::issue(
            "alice",
            Action::ImportPublic,
            Some(&"a".repeat(64)),
            Some(&"A".repeat(40)),
            &vec![0; 65537],
            100,
            KEY
        )
        .err(),
        Some(Error::Limit)
    );
    let r = request(Action::Snapshot, 100);
    let bytes = r.to_bytes().unwrap();
    let (header, _) = parse(&bytes).unwrap();
    let json = serde_json::to_string(&header).unwrap();
    for extra in [
        ",\"home\":\"/private\"}",
        ",\"account\":\"bob\"}",
        ",\"command\":\"gpg\"}",
    ] {
        let json = format!("{}{}", &json[..json.len() - 1], extra);
        let mut frame = (json.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(json.as_bytes());
        assert_eq!(
            Verifier::default().request(&frame, KEY, 100).err(),
            Some(Error::Invalid)
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        Verifier::default().request(&trailing, KEY, 100).err(),
        Some(Error::Invalid)
    );
    assert!(Request::issue(
        "alice",
        Action::RemovePublic,
        Some(&"A".repeat(64)),
        Some(&"A".repeat(40)),
        &[],
        100,
        KEY
    )
    .is_err());
    assert!(Request::issue(
        "alice",
        Action::RemovePublic,
        Some(&"a".repeat(64)),
        Some(&"A".repeat(64)),
        &[],
        100,
        KEY
    )
    .is_err());
    assert!(Request::issue(
        "alice",
        Action::Snapshot,
        None,
        None,
        b"certificate",
        100,
        KEY
    )
    .is_err());
}
