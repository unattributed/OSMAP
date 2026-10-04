use super::*;
const KEY: [u8; 32] = [17; 32];
fn request() -> Request {
    crate::account_mutation::tests::issue("public-old-value", "public-new-passphrase", 3, 100)
        .unwrap()
}
fn python(raw: &[u8], at: u64) -> serde_json::Value {
    let input =
        serde_json::to_vec(&serde_json::json!({"raw_hex":hex(raw),"now_millis":at})).unwrap();
    serde_json::from_slice(&crate::auth::mutation_budget_fixture(&input).unwrap()).unwrap()
}
#[test]
fn rust_original_budget_bytes_match_python_and_keep_inner_v1_exact() {
    let request = request();
    let raw = issue(&request, &KEY, 101001, 101401).unwrap();
    let output = python(&raw, 101201);
    assert_eq!(output["accepted"], true);
    assert_eq!(
        output["inner_sha256"],
        hex(&Sha256::digest(request.bytes().unwrap()))
    );
    assert_eq!(output["reencoded_hex"], hex(&raw));
    assert_eq!(output["remaining_millis"], 200);
}
#[test]
fn expired_future_tampered_retargeted_or_other_domain_outer_never_authenticates() {
    let raw = issue(&request(), &KEY, 101001, 101401).unwrap();
    for at in [101000, 101401] {
        assert_eq!(python(&raw, at)["accepted"], false);
    }
    for (field, value) in [
        ("account", serde_json::json!("bob@example.test")),
        ("deadline_millis", serde_json::json!(102000)),
        ("request_hex", serde_json::json!("01")),
        ("signature", serde_json::json!("0".repeat(64))),
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        changed[field] = value;
        assert_eq!(
            python(&serde_json::to_vec(&changed).unwrap(), 101201)["accepted"],
            false
        );
    }
    for (sent, end) in [(0, 5), (101001, 101001), (101001, 161002), (399999, 400001)] {
        assert!(issue(&request(), &KEY, sent, end).is_err());
    }
}
