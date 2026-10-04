//! Executed public byte compatibility, not private helper/native qualification.
use super::*;

fn python(bytes: &[u8], now: u64, mode: &str, outcome: serde_json::Value) -> serde_json::Value {
    let input = serde_json::to_vec(&serde_json::json!({
        "raw_hex": hex(bytes), "now": now, "mode": mode, "outcome": outcome,
    }))
    .unwrap();
    let output = crate::auth::mutation_compatibility_fixture(&input).unwrap();
    serde_json::from_slice(&output).unwrap()
}
fn decoded_hex(value: &serde_json::Value, field: &str) -> Vec<u8> {
    let text = value[field].as_str().unwrap();
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn actual_rust_sealed_request_authenticates_python_with_exact_unicode_tuple_bytes() {
    for (current, new) in [
        (CURRENT.to_string(), NEW.to_string()),
        (
            "🦀 public current é \\\"".into(),
            "😀 public 新 passphrase é \\\"".into(),
        ),
        ("🦀".repeat(256), "😀".repeat(128)),
    ] {
        let request = issue(&current, &new, 3, 100).unwrap();
        let result = python(
            &request.bytes().unwrap(),
            100,
            "decode",
            serde_json::Value::Null,
        );
        assert_eq!(result["accepted"], true);
        assert_eq!(result["epoch"], 3);
        assert_eq!(
            (result["issued"].as_u64(), result["expires"].as_u64()),
            (Some(100), Some(400))
        );
        assert_eq!(
            decoded_hex(&result, "payload_hex"),
            request.payload().unwrap()
        );
    }
}

#[test]
fn actual_python_three_outcomes_equal_rust_encoding_and_verify_bound_request() {
    let request = request();
    for outcome in [Outcome::KnownRefused, changed(), Outcome::Contained] {
        let value = serde_json::to_value(&outcome).unwrap();
        let result = python(&request.bytes().unwrap(), 101, "response", value);
        assert_eq!(result["accepted"], true);
        let reply = decoded_hex(&result, "response_hex");
        assert_eq!(reply, request.response(outcome, &KEY, 101).unwrap());
        let mut verifier = Verifier::default();
        verifier.response(&request, &reply, &KEY, 101).unwrap();
        assert_eq!(
            verifier.response(&request, &reply, &KEY, 101).unwrap_err(),
            Error::Replay
        );
        assert!(Verifier::default()
            .response(&super::request(), &reply, &KEY, 101)
            .is_err());
        assert_eq!(
            Verifier::default()
                .response(&request, &reply, &[1; 32], 101)
                .unwrap_err(),
            Error::Authentication
        );
        assert_eq!(
            Verifier::default()
                .response(&request, &reply, &KEY, 400)
                .unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            python(&reply, 101, "decode", serde_json::Value::Null)["accepted"],
            false
        );
    }
}

#[test]
fn actual_worker_coordinator_three_outcomes_durable_replay_and_no_second_factor() {
    for outcome in [Outcome::KnownRefused, changed(), Outcome::Contained] {
        let request = request();
        let expected_write = u64::from(!matches!(outcome, Outcome::KnownRefused));
        let result = python(
            &request.bytes().unwrap(),
            101,
            "worker",
            serde_json::to_value(&outcome).unwrap(),
        );
        assert_eq!(result["accepted"], true);
        assert_eq!(result["calls"]["replace"], expected_write);
        assert_eq!(result["calls"]["primary"], 1);
        assert_eq!(result["calls"]["second_factor"], 0);
        assert_eq!(result["replay_refused"], true);
        assert_eq!(result["journal_entries"], 1);
        let reply = decoded_hex(&result, "response_hex");
        assert_eq!(
            Verifier::default()
                .response(&request, &reply, &KEY, 101)
                .unwrap(),
            outcome
        );
    }
}

#[test]
fn both_languages_reject_signed_shape_limits_and_unsigned_tamper_and_expiry() {
    let request = request();
    let original: serde_json::Value = serde_json::from_slice(&request.bytes().unwrap()).unwrap();
    for field in [
        "action",
        "account",
        "session_id",
        "request_id",
        "source",
        "current",
        "new",
    ] {
        let mut tampered = original.clone();
        tampered[field] = serde_json::json!("public-tampered");
        let bytes = serde_json::to_vec(&tampered).unwrap();
        assert!(Verifier::default().request(&bytes, &KEY, 100).is_err());
        assert_eq!(
            python(&bytes, 100, "decode", serde_json::Value::Null)["accepted"],
            false
        );
    }
    for source in ["fe80::1%eth0", "*", "192.168.001.1"] {
        let mut changed = Request(serde_json::from_slice(&request.bytes().unwrap()).unwrap());
        changed.0.source = source.into();
        let bytes = resigned(changed);
        assert!(Verifier::default().request(&bytes, &KEY, 100).is_err());
        assert_eq!(
            python(&bytes, 100, "decode", serde_json::Value::Null)["accepted"],
            false
        );
    }
    for now in [99, 400] {
        assert_eq!(
            python(
                &request.bytes().unwrap(),
                now,
                "decode",
                serde_json::Value::Null
            )["accepted"],
            false
        );
    }
    let text = String::from_utf8(request.bytes().unwrap()).unwrap();
    for bytes in [
        text.replacen('{', "{\"epoch\":3,", 1).into_bytes(),
        text.replacen('{', "{\"fresh\":true,", 1).into_bytes(),
        [vec![0xef, 0xbb, 0xbf], request.bytes().unwrap()].concat(),
        vec![b' '; MAX_FRAME + 1],
    ] {
        assert!(Verifier::default().request(&bytes, &KEY, 100).is_err());
        assert_eq!(
            python(&bytes, 100, "decode", serde_json::Value::Null)["accepted"],
            false
        );
    }
}

#[test]
fn python_response_tamper_unknown_fields_invalid_calendar_and_epoch_never_verify() {
    let request = request();
    let result = python(
        &request.bytes().unwrap(),
        101,
        "response",
        serde_json::to_value(changed()).unwrap(),
    );
    let reply = decoded_hex(&result, "response_hex");
    let original: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    for field in [
        "request_signature",
        "intent_reference",
        "request_id",
        "account",
        "signature",
    ] {
        let mut tampered = original.clone();
        tampered[field] = serde_json::json!("public-other");
        assert!(Verifier::default()
            .response(&request, &serde_json::to_vec(&tampered).unwrap(), &KEY, 101)
            .is_err());
    }
    for outcome in [
        serde_json::json!({"status":"known_refused", "epoch":4}),
        serde_json::json!({"status":"contained", "changed_at":null}),
        serde_json::json!({"status":"changed", "epoch":5, "changed_at":STAMP}),
        serde_json::json!({"status":"changed", "epoch":4, "changed_at":"20261301000000"}),
    ] {
        assert_eq!(
            python(&request.bytes().unwrap(), 101, "response", outcome)["accepted"],
            false
        );
    }
}
