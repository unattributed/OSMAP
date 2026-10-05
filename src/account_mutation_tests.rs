use super::*;
use crate::account_admission::{Admission, EpochAuthority};
use crate::auth::{
    AuthenticationContext, AuthenticationPolicy, PrimaryAuthBackendError, PrimaryAuthVerdict,
    PrimaryCredentialBackend, RequiredSecondFactor, SecondFactorBackendError, SecondFactorService,
    SecondFactorVerdict, SecondFactorVerifier,
};
use crate::password_change::{self, Attempt, EpochPrimaryBackend, Services};
use crate::session::{SessionRecord, ValidatedSession};
use crate::totp::TimeProvider;

const KEY: [u8; 32] = [17; 32];
const ACCOUNT: &str = "alice@example.test";
const CURRENT: &str = "public-old-value";
const NEW: &str = "public-new-passphrase";
const STAMP: &str = "19700101000140";

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("osmap-mutation-{}", hex(&nonce)));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Authority(u64);
impl EpochAuthority for Authority {
    fn admit(&self, account: &str, epoch: u64) -> Result<(), crate::account_admission::Error> {
        if account == ACCOUNT && epoch == self.0 {
            Ok(())
        } else {
            Err(crate::account_admission::Error::Refused)
        }
    }
}
impl PrimaryCredentialBackend for Authority {
    fn verify_primary(
        &self,
        _: &AuthenticationContext,
        account: &str,
        _: &str,
    ) -> Result<PrimaryAuthVerdict, PrimaryAuthBackendError> {
        assert_eq!(account, ACCOUNT);
        Ok(PrimaryAuthVerdict::Accept {
            canonical_username: account.into(),
        })
    }
}
impl EpochPrimaryBackend for Authority {
    fn captured_admission(&self) -> Result<Admission, password_change::Error> {
        Ok(Admission {
            account: ACCOUNT.into(),
            epoch: self.0,
        })
    }
}
struct Factor;
impl SecondFactorVerifier for Factor {
    fn verify_second_factor(
        &self,
        _: &str,
        _: RequiredSecondFactor,
        _: &str,
    ) -> Result<SecondFactorVerdict, SecondFactorBackendError> {
        Ok(SecondFactorVerdict::Accept)
    }
}
struct Clock(u64);
impl TimeProvider for Clock {
    fn unix_timestamp(&self) -> u64 {
        self.0
    }
}
// Only codec preparation dependencies are synthetic here. The request issuer
// still must consume the real sealed preparation type; no mutation/native auth
// result is supplied or claimed by these unit tests.
pub(crate) fn issue(current: &str, new: &str, epoch: u64, sign_at: u64) -> Result<Request, Error> {
    issue_timed(current, new, epoch, 100, sign_at)
}
pub(crate) fn issue_timed(
    current: &str,
    new: &str,
    epoch: u64,
    began: u64,
    sign_at: u64,
) -> Result<Request, Error> {
    let scratch = Scratch::new();
    let authority = Authority(epoch);
    let clock = Clock(began);
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "public-mutation-request",
        "127.0.0.1",
        "Fixture/Test",
    )
    .unwrap();
    let session = ValidatedSession {
        record: SessionRecord {
            account_epoch: Some(epoch),
            canonical_username: ACCOUNT.into(),
            session_id: "a".repeat(64),
            csrf_token: "b".repeat(64),
            issued_at: 1,
            expires_at: began.checked_add(900).unwrap(),
            last_seen_at: 1,
            revoked_at: None,
            remote_addr: "127.0.0.1".into(),
            user_agent: "Fixture/Test".into(),
            factor: RequiredSecondFactor::Totp,
        },
        audit_event: crate::logging::LogEvent::new(
            crate::config::LogLevel::Info,
            crate::logging::EventCategory::Session,
            "fixture",
            "public codec fixture",
        ),
    };
    let factor = SecondFactorService::new(AuthenticationPolicy::default(), Factor);
    let rate = crate::password_change_rate::Store::new(scratch.0.join("rate"));
    let prepared = password_change::prepare(
        Services {
            primary: &authority,
            factor: &factor,
            epoch: &authority,
            rate: &rate,
            clock: &clock,
            policy: AuthenticationPolicy::default(),
        },
        Attempt {
            context: &context,
            session: &session,
            request: password_change::Request::new(current, new, new, "123456").unwrap(),
        },
    )
    .authorization
    .unwrap();
    let dispatch = prepared
        .into_dispatch(&context, &session, &authority, &clock)
        .unwrap();
    Request::issue(dispatch, &KEY, sign_at)
}
fn request() -> Request {
    issue(CURRENT, NEW, 3, 100).unwrap()
}

#[test]
fn terminal_receipt_preserves_exact_action_binding_without_credentials() {
    let request = request();
    let account = request.account().to_owned();
    let session = request.session_id().to_owned();
    let request_id = request.request_id().to_owned();
    let intent = request.intent_reference().to_owned();
    let source = request.source().to_owned();
    let bytes = request
        .response(
            Outcome::Changed {
                epoch: 4,
                changed_at: STAMP.into(),
            },
            &KEY,
            110,
        )
        .unwrap();
    let receipt = Verifier::default()
        .terminal_response(request, &bytes, &KEY, 111)
        .unwrap();
    assert_eq!(receipt.account(), account);
    assert_eq!(receipt.session_id(), session);
    assert_eq!(receipt.request_id(), request_id);
    assert_eq!(receipt.intent_reference(), intent);
    assert_eq!(receipt.source(), source);
    assert_eq!(
        (
            receipt.old_epoch(),
            receipt.issued(),
            receipt.expires(),
            receipt.responded_at()
        ),
        (3, 100, 400, 110)
    );
    assert_eq!(
        receipt.outcome(),
        &Outcome::Changed {
            epoch: 4,
            changed_at: STAMP.into()
        }
    );
    assert_eq!(
        format!("{receipt:?}"),
        "AccountMutationTerminalReceipt(<redacted>)"
    );
}

#[test]
fn terminal_receipt_requires_matching_signature_and_original_window() {
    let request = request();
    let mut bytes = request.response(Outcome::KnownRefused, &KEY, 110).unwrap();
    let value: ResponseWire = serde_json::from_slice(&bytes).unwrap();
    bytes = signed_response(ResponseWire {
        request_id: "different-request".into(),
        ..value
    });
    assert!(matches!(
        Verifier::default().terminal_response(request, &bytes, &KEY, 111),
        Err(Error::Authentication)
    ));
    let request = self::request();
    let bytes = request
        .response(
            Outcome::Changed {
                epoch: 4,
                changed_at: STAMP.into(),
            },
            &KEY,
            399,
        )
        .unwrap();
    assert!(matches!(
        Verifier::default().terminal_response(request, &bytes, &KEY, 400),
        Err(Error::Expired)
    ));
}

#[test]
fn terminal_receipt_and_legacy_reply_share_same_replay_authority() {
    let request = request();
    let copy = Verifier::default()
        .request(&request.bytes().unwrap(), &KEY, 100)
        .unwrap();
    let bytes = request.response(Outcome::KnownRefused, &KEY, 110).unwrap();
    let mut verifier = Verifier::default();
    assert_eq!(
        verifier.response(&request, &bytes, &KEY, 111),
        Ok(Outcome::KnownRefused)
    );
    assert!(matches!(
        verifier.terminal_response(copy, &bytes, &KEY, 111),
        Err(Error::Replay)
    ));
}

#[test]
fn terminal_receipt_preserves_containment_instead_of_success_or_known_refusal() {
    let request = request();
    let bytes = request.response(Outcome::Contained, &KEY, 110).unwrap();
    let receipt = Verifier::default()
        .terminal_response(request, &bytes, &KEY, 111)
        .unwrap();
    assert_eq!(receipt.outcome(), &Outcome::Contained);
}
fn resigned(mut r: Request) -> Vec<u8> {
    r.0.signature = hex(&mac(&KEY, &r.payload().unwrap())
        .unwrap()
        .finalize()
        .into_bytes());
    r.bytes().unwrap()
}
fn signed_response(mut r: ResponseWire) -> Vec<u8> {
    r.signature = hex(&mac(&KEY, &r.payload().unwrap())
        .unwrap()
        .finalize()
        .into_bytes());
    frame(&r).unwrap()
}
fn changed() -> Outcome {
    Outcome::Changed {
        epoch: 4,
        changed_at: STAMP.into(),
    }
}

#[test]
fn sealed_dispatch_roundtrip_retains_every_binding_and_has_no_factor_field() {
    let r = request();
    let bytes = r.bytes().unwrap();
    let verified = Verifier::default().request(&bytes, &KEY, 100).unwrap();
    assert_eq!(verified.account(), ACCOUNT);
    assert_eq!(verified.epoch(), 3);
    assert_eq!(verified.intent_reference(), r.intent_reference());
    assert_eq!(verified.session_id(), "a".repeat(64));
    assert_eq!(verified.request_id(), "public-mutation-request");
    assert_eq!(verified.source(), "127.0.0.1");
    assert_eq!((verified.issued(), verified.expires()), (100, 400));
    assert!(verified.current() == CURRENT);
    assert!(verified.new_password() == NEW && verified.confirmation() == NEW);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("totp").is_none() && value.get("fresh").is_none());
    assert_eq!(format!("{r:?}"), "AccountMutationRequest(<redacted>)");
    assert!(!format!("{r:?}").contains(CURRENT));
}

#[test]
fn every_bound_field_tamper_and_paired_password_or_deadline_change_is_refused() {
    let r = request();
    let original: serde_json::Value = serde_json::from_slice(&r.bytes().unwrap()).unwrap();
    for (name, replacement) in [
        ("schema", serde_json::json!("other-schema")),
        ("action", serde_json::json!("other-action")),
        ("account", serde_json::json!("bob@example.test")),
        ("epoch", serde_json::json!(4)),
        ("intent_reference", serde_json::json!("c".repeat(64))),
        ("session_id", serde_json::json!("d".repeat(64))),
        ("request_id", serde_json::json!("other-request")),
        ("source", serde_json::json!("127.0.0.2")),
        ("issued", serde_json::json!(99)),
        ("expires", serde_json::json!(401)),
        ("current", serde_json::json!("different-public-current")),
        ("new", serde_json::json!("different-public-new")),
        (
            "confirmation",
            serde_json::json!("different-public-confirmation"),
        ),
    ] {
        let mut value = original.clone();
        value[name] = replacement;
        assert!(Verifier::default()
            .request(&serde_json::to_vec(&value).unwrap(), &KEY, 100)
            .is_err());
    }
    for paired_time in [false, true] {
        let mut value = original.clone();
        if paired_time {
            value["issued"] = serde_json::json!(99);
            value["expires"] = serde_json::json!(399);
        } else {
            value["new"] = serde_json::json!("different-public-passphrase");
            value["confirmation"] = value["new"].clone();
        }
        assert_eq!(
            Verifier::default()
                .request(&serde_json::to_vec(&value).unwrap(), &KEY, 100)
                .unwrap_err(),
            Error::Authentication
        );
    }
}

#[test]
fn original_300_second_deadline_is_not_renewed_by_signing_or_reply() {
    let r = issue(CURRENT, NEW, 3, 399).unwrap();
    assert_eq!((r.issued(), r.expires()), (100, 400));
    assert!(Verifier::default()
        .request(&r.bytes().unwrap(), &KEY, 399)
        .is_ok());
    assert_eq!(issue(CURRENT, NEW, 3, 400).unwrap_err(), Error::Expired);
    assert_eq!(issue(CURRENT, NEW, 3, 99).unwrap_err(), Error::Expired);
    for at in [99, 400] {
        assert_eq!(
            Verifier::default()
                .request(&r.bytes().unwrap(), &KEY, at)
                .unwrap_err(),
            Error::Expired
        );
    }
    let known = r.response(Outcome::KnownRefused, &KEY, 399).unwrap();
    assert_eq!(
        Verifier::default()
            .response(&r, &known, &KEY, 400)
            .unwrap_err(),
        Error::Expired
    );
}

#[test]
fn inner_intent_replay_resigning_and_clock_rollback_do_not_dispatch_twice() {
    let r = request();
    let mut v = Verifier::default();
    v.request(&r.bytes().unwrap(), &KEY, 100).unwrap();
    assert_eq!(
        v.request(&r.bytes().unwrap(), &KEY, 100).unwrap_err(),
        Error::Replay
    );
    let mut other = Request(serde_json::from_slice(&r.bytes().unwrap()).unwrap(), None);
    other.0.request_id = "new-outer-request".into();
    assert_eq!(
        v.request(&resigned(other), &KEY, 100).unwrap_err(),
        Error::Replay
    );
    let later = request();
    v.request(&later.bytes().unwrap(), &KEY, 101).unwrap();
    assert_eq!(
        v.request(&request().bytes().unwrap(), &KEY, 100)
            .unwrap_err(),
        Error::Expired
    );
}

#[test]
fn request_policy_unicode_epoch_and_metadata_bounds_are_checked_even_with_valid_mac() {
    let current = "🦀".repeat(256);
    let new = "😀".repeat(128);
    let maximum = issue(&current, &new, MAX_EPOCH - 1, 100).unwrap();
    assert!(maximum.bytes().unwrap().len() <= MAX_FRAME);
    let result = maximum
        .response(
            Outcome::Changed {
                epoch: MAX_EPOCH,
                changed_at: STAMP.into(),
            },
            &KEY,
            100,
        )
        .unwrap();
    assert!(matches!(
        Verifier::default().response(&maximum, &result, &KEY, 100),
        Ok(Outcome::Changed {
            epoch: MAX_EPOCH,
            ..
        })
    ));
    for case in 0..15 {
        let mut r = request();
        match case {
            0 => r.0.current.clear(),
            1 => r.0.current = "x".repeat(1025),
            2 => r.0.current = "a\u{85}b".into(),
            3 => {
                r.0.new = "a".repeat(14);
                r.0.confirmation = r.0.new.clone();
            }
            4 => {
                r.0.new = "😀".repeat(129);
                r.0.confirmation = r.0.new.clone();
            }
            5 => {
                r.0.new = "a\n".repeat(8);
                r.0.confirmation = r.0.new.clone();
            }
            6 => {
                r.0.new = r.0.current.clone();
                r.0.confirmation = r.0.new.clone();
            }
            7 => r.0.epoch = MAX_EPOCH,
            8 => r.0.epoch = u64::MAX,
            9 => r.0.session_id = "e".repeat(63),
            10 => r.0.request_id = "😀".repeat(33),
            11 => r.0.source = "not-an-ip".into(),
            12 => r.0.account = "alice*@example.test".into(),
            13 => r.0.current = "🦀".repeat(257),
            14 => r.0.request_id = " ".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            Verifier::default()
                .request(&resigned(r), &KEY, 100)
                .unwrap_err(),
            Error::Invalid
        );
    }
    let mut overflow = request();
    overflow.0.issued = u64::MAX - 1;
    overflow.0.expires = 299;
    assert_eq!(
        Verifier::default()
            .request(&resigned(overflow), &KEY, 100)
            .unwrap_err(),
        Error::Expired
    );
}

#[test]
fn duplicate_unknown_wrong_type_and_frame_limits_are_strict() {
    let r = request();
    let text = String::from_utf8(r.bytes().unwrap()).unwrap();
    for malformed in [
        text.replacen('{', "{\"epoch\":3,", 1),
        text.replacen('{', "{\"fresh\":true,", 1),
        text.replacen('{', "{\"root\":\"/tmp\",", 1),
    ] {
        assert_eq!(
            Verifier::default()
                .request(malformed.as_bytes(), &KEY, 100)
                .unwrap_err(),
            Error::Invalid
        );
    }
    let mut wrong: serde_json::Value = serde_json::from_str(&text).unwrap();
    wrong["epoch"] = serde_json::json!(true);
    assert_eq!(
        Verifier::default()
            .request(&serde_json::to_vec(&wrong).unwrap(), &KEY, 100)
            .unwrap_err(),
        Error::Invalid
    );
    let mut padded = r.bytes().unwrap();
    padded.resize(MAX_FRAME, b' ');
    assert!(Verifier::default().request(&padded, &KEY, 100).is_ok());
    padded.push(b' ');
    assert_eq!(
        Verifier::default().request(&padded, &KEY, 100).unwrap_err(),
        Error::Invalid
    );
}

#[test]
fn exact_typed_responses_and_response_replay_are_bound_to_the_original_action() {
    let r = request();
    for outcome in [Outcome::KnownRefused, changed(), Outcome::Contained] {
        let bytes = r.response(outcome, &KEY, 101).unwrap();
        let mut v = Verifier::default();
        v.response(&r, &bytes, &KEY, 101).unwrap();
        assert_eq!(
            v.response(&r, &bytes, &KEY, 101).unwrap_err(),
            Error::Replay
        );
        assert!(Verifier::default()
            .response(&request(), &bytes, &KEY, 101)
            .is_err());
    }
    let reply = r.response(Outcome::KnownRefused, &KEY, 101).unwrap();
    let mut different = Request(serde_json::from_slice(&r.bytes().unwrap()).unwrap(), None);
    different.0.current = "different-public-current".into();
    let bytes = resigned(different);
    let different = Verifier::default().request(&bytes, &KEY, 101).unwrap();
    assert_eq!(
        Verifier::default()
            .response(&different, &reply, &KEY, 101)
            .unwrap_err(),
        Error::Authentication
    );
}

#[test]
fn response_wrong_identity_epoch_timestamp_or_shape_is_not_known_refused() {
    let r = request();
    let original = r.response(changed(), &KEY, 101).unwrap();
    for field in [
        "account",
        "intent_reference",
        "request_id",
        "request_signature",
        "schema",
        "action",
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&original).unwrap();
        v[field] = serde_json::json!("wrong");
        assert!(Verifier::default()
            .response(&r, &serde_json::to_vec(&v).unwrap(), &KEY, 101)
            .is_err());
    }
    for at in [99, 102, 400] {
        let mut reply: ResponseWire = serde_json::from_slice(&original).unwrap();
        reply.responded_at = at;
        assert_eq!(
            Verifier::default()
                .response(&r, &signed_response(reply), &KEY, 101)
                .unwrap_err(),
            Error::Expired
        );
    }
    for epoch in [3, 5, MAX_EPOCH, u64::MAX] {
        let mut reply: ResponseWire = serde_json::from_slice(&original).unwrap();
        reply.outcome = Outcome::Changed {
            epoch,
            changed_at: STAMP.into(),
        };
        assert_eq!(
            Verifier::default()
                .response(&r, &signed_response(reply), &KEY, 101)
                .unwrap_err(),
            Error::Invalid
        );
    }
    for text in ["", "{}", "null", "{\"status\":\"known_refused\"}"] {
        assert_eq!(
            Verifier::default()
                .response(&r, text.as_bytes(), &KEY, 101)
                .unwrap_err(),
            Error::Invalid
        );
    }
    let mut extra: serde_json::Value =
        serde_json::from_slice(&r.response(Outcome::KnownRefused, &KEY, 101).unwrap()).unwrap();
    extra["outcome"] = serde_json::json!({"status":"known_refused","epoch":4});
    assert_eq!(
        Verifier::default()
            .response(&r, &serde_json::to_vec(&extra).unwrap(), &KEY, 101)
            .unwrap_err(),
        Error::Invalid
    );
    let mut contained: serde_json::Value =
        serde_json::from_slice(&r.response(Outcome::Contained, &KEY, 101).unwrap()).unwrap();
    contained["outcome"]["changed_at"] = serde_json::Value::Null;
    assert_eq!(
        Verifier::default()
            .response(&r, &serde_json::to_vec(&contained).unwrap(), &KEY, 101)
            .unwrap_err(),
        Error::Invalid
    );
    let repeated =
        String::from_utf8(original.clone())
            .unwrap()
            .replacen('{', "{\"responded_at\":101,", 1);
    assert_eq!(
        Verifier::default()
            .response(&r, repeated.as_bytes(), &KEY, 101)
            .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(
        Verifier::default()
            .response(&r, &vec![b' '; MAX_FRAME + 1], &KEY, 101)
            .unwrap_err(),
        Error::Invalid
    );
}

#[test]
fn authoritative_changed_at_calendar_boundaries_and_impossible_dates_are_checked() {
    let r = request();
    for stamp in ["20000229235959", "20240229000000", "20261004235959"] {
        assert!(r
            .response(
                Outcome::Changed {
                    epoch: 4,
                    changed_at: stamp.into()
                },
                &KEY,
                100
            )
            .is_ok());
    }
    for stamp in [
        "",
        "20261004",
        "00000101000000",
        "19000229000000",
        "20230229000000",
        "20260431000000",
        "20260001000000",
        "20260100000000",
        "20260101240000",
        "20260101006000",
        "20260101000060",
        "2026010100000a",
    ] {
        let mut reply: ResponseWire =
            serde_json::from_slice(&r.response(changed(), &KEY, 100).unwrap()).unwrap();
        reply.outcome = Outcome::Changed {
            epoch: 4,
            changed_at: stamp.into(),
        };
        assert_eq!(
            Verifier::default()
                .response(&r, &signed_response(reply), &KEY, 100)
                .unwrap_err(),
            Error::Invalid
        );
    }
}

#[test]
fn replay_cache_capacity_and_bad_mac_do_not_become_refusal_outcomes() {
    let r = request();
    let mut v = Verifier::default();
    for n in 0..128 {
        let mut each = Request(serde_json::from_slice(&r.bytes().unwrap()).unwrap(), None);
        each.0.intent_reference = format!("{n:064x}");
        v.request(&resigned(each), &KEY, 100).unwrap();
    }
    let mut extra = Request(serde_json::from_slice(&r.bytes().unwrap()).unwrap(), None);
    extra.0.intent_reference = format!("{:064x}", 128);
    assert_eq!(
        v.request(&resigned(extra), &KEY, 100).unwrap_err(),
        Error::Capacity
    );
    let bytes = r.response(Outcome::KnownRefused, &KEY, 100).unwrap();
    assert_eq!(
        Verifier::default()
            .response(&r, &bytes, &[1; 32], 100)
            .unwrap_err(),
        Error::Authentication
    );
    for length in [31, 1025] {
        assert_eq!(
            r.response(Outcome::KnownRefused, &vec![0; length], 100)
                .unwrap_err(),
            Error::Authentication
        );
    }
    let mut wrong: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    wrong["outcome"] = serde_json::json!({"status":"contained"});
    assert_eq!(
        Verifier::default()
            .response(&r, &serde_json::to_vec(&wrong).unwrap(), &KEY, 100)
            .unwrap_err(),
        Error::Authentication
    );
}

#[path = "account_mutation_python_tests.rs"]
mod python_compatibility;
