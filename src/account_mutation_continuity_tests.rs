use super::*;
const KEY: [u8; 32] = [17; 32];
fn hex(v: &[u8]) -> String {
    super::hex(v)
}
pub(crate) fn python(value: serde_json::Value) -> serde_json::Value {
    let result =
        crate::auth::mutation_continuity_fixture(&serde_json::to_vec(&value).unwrap()).unwrap();
    serde_json::from_slice(&result).unwrap()
}
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&value[n..n + 2], 16).unwrap())
        .collect()
}
fn fixture() -> (Request, Vec<u8>, Vec<u8>) {
    let request =
        crate::account_mutation::tests::issue("public-old-value", "public-new-passphrase", 3, 100)
            .unwrap();
    let frame=serde_json::to_vec(&serde_json::json!({"budget":{"request_hex":hex(&request.bytes().unwrap()),"deadline_millis":101000}})).unwrap();
    let result =
        python(serde_json::json!({"mode":"challenge","frame_hex":hex(&frame),"now_millis":100000}));
    assert_eq!(result["accepted"], true);
    let challenge = unhex(result["challenge_hex"].as_str().unwrap());
    (request, frame, challenge)
}
#[test]
fn exact_python_challenge_rust_ack_authenticates_python_original_binding() {
    let (request, frame, challenge) = fixture();
    let ack = acknowledge(&request, &frame, &challenge, &KEY, 100001).unwrap();
    let result = python(
        serde_json::json!({"mode":"ack","frame_hex":hex(&frame),"now_millis":100001,"challenge_hex":hex(&challenge),"ack_hex":hex(&ack)}),
    );
    assert_eq!(result["accepted"], true);
}
#[test]
fn signed_retargeted_challenges_never_acknowledge_another_action_frame_or_deadline() {
    let (request, frame, raw) = fixture();
    for kind in 0..5 {
        let mut c: Challenge = serde_json::from_slice(&raw).unwrap();
        match kind {
            0 => c.account = "bob@example.test".into(),
            1 => c.epoch = 4,
            2 => c.intent_reference = "d".repeat(64),
            3 => c.frame_sha256 = "e".repeat(64),
            _ => c.deadline_millis = 102000,
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(&payload(&c).unwrap());
        c.signature = hex(&mac.finalize().into_bytes());
        assert!(acknowledge(
            &request,
            &frame,
            &serde_json::to_vec(&c).unwrap(),
            &KEY,
            100001
        )
        .is_err());
    }
}
#[test]
fn exact_expiry_future_unknown_duplicate_bad_mac_and_oversize_never_acknowledge() {
    let (request, frame, raw) = fixture();
    for now in [99999, 101000, 101001] {
        assert!(acknowledge(&request, &frame, &raw, &KEY, now).is_err());
    }
    let mut extra: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    extra["live"] = serde_json::json!(true);
    let mut bad: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    bad["signature"] = serde_json::json!("0".repeat(64));
    for value in [
        serde_json::to_vec(&extra).unwrap(),
        serde_json::to_vec(&bad).unwrap(),
        b"{\"schema\":\"x\",\"schema\":\"y\"}".to_vec(),
        vec![b'x'; LIMIT + 1],
    ] {
        assert!(acknowledge(&request, &frame, &value, &KEY, 100001).is_err());
    }
}
