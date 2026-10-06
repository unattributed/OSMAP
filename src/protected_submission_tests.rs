use super::*;
use crate::openpgp_crypto::{Error, SignatureState};
use crate::pgp_mime::PgpMimeMessage;
use crate::send::UploadedAttachment;
use std::cell::RefCell;
use std::collections::VecDeque;

const SIGNER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const RECIPIENT: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const SIGNATURE: &[u8] =
    b"-----BEGIN PGP SIGNATURE-----\n\nZml4dHVyZQ==\n-----END PGP SIGNATURE-----\n";
const CIPHERTEXT: &[u8] =
    b"-----BEGIN PGP MESSAGE-----\n\nZml4dHVyZQ==\n-----END PGP MESSAGE-----\n";

struct Mock {
    results: RefCell<VecDeque<Result<Outcome, CryptoFailure>>>,
    operations: RefCell<Vec<Operation>>,
}
impl CryptoExecutor for Mock {
    fn execute(
        &self,
        account: &CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        assert_eq!(account.as_str(), "alice@example.test");
        self.operations.borrow_mut().push(operation.clone());
        self.results
            .borrow_mut()
            .pop_front()
            .expect("unexpected crypto call")
    }
}
fn mock(results: Vec<Result<Outcome, CryptoFailure>>) -> Mock {
    Mock {
        results: RefCell::new(results.into()),
        operations: RefCell::new(Vec::new()),
    }
}
fn signed() -> Outcome {
    Outcome {
        operation: "sign".into(),
        content: SIGNATURE.to_vec(),
        signer_fingerprint: Some(SIGNER.into()),
        primary_fingerprint: Some(SIGNER.into()),
        signature: SignatureState::Valid,
        hash_algorithm: Some(8),
    }
}
fn encrypted() -> Outcome {
    Outcome {
        operation: "encrypt".into(),
        content: CIPHERTEXT.to_vec(),
        signer_fingerprint: None,
        primary_fingerprint: None,
        signature: SignatureState::None,
        hash_algorithm: None,
    }
}
fn account() -> CanonicalUsername {
    CanonicalUsername::parse("alice@example.test").unwrap()
}
fn request() -> ComposeRequest {
    let mut request = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        "bob@example.test",
        "carol@example.test",
        "",
        "Synthetic outer subject",
        "Synthetic café body\nSecond line",
        Vec::new(),
    )
    .unwrap();
    request.sender_identity = crate::identity_preferences::IdentityPreferences::new(
        "Alice Synthetic",
        Some("reply@example.test"),
    )
    .unwrap();
    request.reply_thread = Some(
        crate::reply_thread::ReplyThread::from_original("Message-ID: <parent@example.test>")
            .unwrap(),
    );
    request
}
fn plan(sign: bool, encrypt: bool) -> OperationPlan {
    OperationPlan {
        signer_fingerprint: sign.then(|| SIGNER.into()),
        recipient_fingerprints: if encrypt {
            vec![RECIPIENT.into()]
        } else {
            Vec::new()
        },
        encrypt_to_self: false,
    }
}

#[test]
fn ordinary_is_exact_existing_composer_and_has_no_crypto() {
    let executor = mock(Vec::new());
    let request = request();
    let result = prepare(&executor, &account(), &request, &plan(false, false)).unwrap();
    assert_eq!(
        result.as_bytes(),
        crate::send::build_submission_message(account().as_str(), &request).unwrap()
    );
    assert_eq!(result.protection(), SubmissionProtection::Ordinary);
    assert!(executor.operations.borrow().is_empty());
    result.validate_for(&account(), &request).unwrap();
    assert!(!format!("{result:?}").contains("Synthetic"));
}

#[test]
fn sign_exact_transport_safe_entity_preserves_outer_headers() {
    let executor = mock(vec![Ok(signed())]);
    let result = prepare(&executor, &account(), &request(), &plan(true, false)).unwrap();
    let text = std::str::from_utf8(result.as_bytes()).unwrap();
    assert!(text.contains("To: bob@example.test\r\nCc: carol@example.test\r\n"));
    assert!(text.contains("Reply-To: reply@example.test\r\n"));
    assert!(text.contains("In-Reply-To: <parent@example.test>\r\n"));
    assert!(text.contains("Subject: Synthetic outer subject\r\nMIME-Version: 1.0\r\n"));
    let PgpMimeMessage::Signed {
        entity,
        canonical_entity,
        digest,
        ..
    } = pgp_mime::classify(result.as_bytes(), PgpMimePolicy::default()).unwrap()
    else {
        panic!("expected signed MIME")
    };
    let operations = executor.operations.borrow();
    let Operation::Sign { data, .. } = &operations[0] else {
        panic!("expected sign")
    };
    assert_eq!(data, entity);
    assert_eq!(data, &canonical_entity);
    assert!(entity.is_ascii());
    assert!(std::str::from_utf8(entity)
        .unwrap()
        .contains("Content-Transfer-Encoding: base64"));
    assert_eq!(digest, SignatureDigest::Sha256);
    assert!(!std::str::from_utf8(entity).unwrap().contains("Subject:"));
}

#[test]
fn sign_then_encrypt_only_complete_signed_entity_and_exact_final_bytes() {
    let executor = mock(vec![Ok(signed()), Ok(encrypted())]);
    let request = request();
    let result = prepare(&executor, &account(), &request, &plan(true, true)).unwrap();
    assert_eq!(
        result.protection(),
        SubmissionProtection::SignedAndEncrypted
    );
    let operations = executor.operations.borrow();
    let Operation::Sign { data: original, .. } = &operations[0] else {
        panic!("sign first")
    };
    let Operation::Encrypt {
        data,
        recipient_fingerprints,
    } = &operations[1]
    else {
        panic!("encrypt second")
    };
    assert_eq!(recipient_fingerprints, &[RECIPIENT.to_string()]);
    let PgpMimeMessage::Signed {
        canonical_entity, ..
    } = pgp_mime::classify(data, PgpMimePolicy::default()).unwrap()
    else {
        panic!("encrypt full signed MIME")
    };
    assert_eq!(canonical_entity, *original);
    assert!(matches!(
        pgp_mime::classify(result.as_bytes(), PgpMimePolicy::default()).unwrap(),
        PgpMimeMessage::Encrypted { .. }
    ));
    assert!(!std::str::from_utf8(result.as_bytes())
        .unwrap()
        .contains("Synthetic café body"));
    // The same slice is available for submission and append; the adapter does
    // not rebuild plaintext or perform either side effect.
    let sent =
        crate::mailbox::MessageAppendRequest::new("Sent", result.as_bytes().to_vec()).unwrap();
    assert_eq!(sent.message, result.as_bytes());
    result.validate_for(&account(), &request).unwrap();
}

#[test]
fn formatted_and_binary_attachment_entities_are_transport_safe() {
    for format in [BodyFormat::Plain, BodyFormat::Formatted] {
        let executor = mock(vec![Ok(signed())]);
        let mut request = request();
        request.body = "**Synthetic café**\nmore".into();
        request.attachments = vec![UploadedAttachment::new(
            ComposePolicy::default(),
            "synthetic.bin",
            "application/octet-stream",
            vec![0, 1, 255],
        )
        .unwrap()];
        request = request.with_body_format(format).unwrap();
        let result = prepare(&executor, &account(), &request, &plan(true, false)).unwrap();
        let PgpMimeMessage::Signed { entity, .. } =
            pgp_mime::classify(result.as_bytes(), PgpMimePolicy::default()).unwrap()
        else {
            panic!("expected signed")
        };
        assert!(entity.is_ascii());
        let text = std::str::from_utf8(entity).unwrap();
        assert!(text.contains("AAH/"));
        assert!(!text.contains("Content-Transfer-Encoding: 8bit"));
        assert!(text.contains("filename=\"synthetic.bin\""));
    }
}

#[test]
fn invalid_mutated_request_and_invalid_plan_refuse_before_crypto() {
    let executor = mock(Vec::new());
    let mut request = request();
    request.subject = "injected\r\nBcc: other@example.test".into();
    assert_eq!(
        prepare(&executor, &account(), &request, &plan(true, false)).unwrap_err(),
        SubmissionError::InvalidCompose
    );
    let mut request = super::tests::request();
    request.recipients.push("bob@example.test".into());
    assert_eq!(
        prepare(&executor, &account(), &request, &plan(true, false)).unwrap_err(),
        SubmissionError::InvalidCompose
    );
    for invalid in [
        OperationPlan {
            signer_fingerprint: Some("A".repeat(16)),
            ..plan(false, false)
        },
        OperationPlan {
            recipient_fingerprints: vec![RECIPIENT.into(), RECIPIENT.into()],
            ..plan(false, false)
        },
        OperationPlan {
            encrypt_to_self: true,
            ..plan(false, false)
        },
    ] {
        assert_eq!(
            prepare(&executor, &account(), &super::tests::request(), &invalid).unwrap_err(),
            SubmissionError::InvalidPlan
        );
    }
    assert!(executor.operations.borrow().is_empty());
}

#[test]
fn bcc_is_envelope_only_and_encrypted_bcc_stays_unqualified() {
    let executor = mock(Vec::new());
    let mut request = request();
    request.bcc_recipients.push("hidden@example.test".into());
    let result = prepare(&executor, &account(), &request, &plan(false, false)).unwrap();
    assert!(!std::str::from_utf8(result.as_bytes())
        .unwrap()
        .contains("hidden@example.test"));
    assert_eq!(
        prepare(&executor, &account(), &request, &plan(false, true)).unwrap_err(),
        SubmissionError::EncryptedBccUnqualified
    );
    request.bcc_recipients[0] = "different@example.test".into();
    assert_eq!(
        result.validate_for(&account(), &request),
        Err(SubmissionError::RequestMismatch)
    );
    assert!(executor.operations.borrow().is_empty());
}

#[test]
fn failed_sign_never_encrypts_and_forged_success_never_builds_message() {
    let executor = mock(vec![Err(CryptoFailure::Engine(Error::Locked))]);
    assert_eq!(
        prepare(&executor, &account(), &request(), &plan(true, true)).unwrap_err(),
        SubmissionError::Crypto(CryptoFailure::Engine(Error::Locked))
    );
    assert_eq!(executor.operations.borrow().len(), 1);
    let mut wrong = signed();
    wrong.signer_fingerprint = Some(RECIPIENT.into());
    let executor = mock(vec![Ok(wrong)]);
    assert_eq!(
        prepare(&executor, &account(), &request(), &plan(true, true)).unwrap_err(),
        SubmissionError::InvalidOutcome
    );
    assert_eq!(executor.operations.borrow().len(), 1);
    let mut wrong = encrypted();
    wrong.content = b"not armor".to_vec();
    let executor = mock(vec![Ok(wrong)]);
    assert_eq!(
        prepare(&executor, &account(), &request(), &plan(false, true)).unwrap_err(),
        SubmissionError::Mime(PgpMimeError::InvalidArmor)
    );
}

#[test]
fn prepared_bytes_reject_changed_account_body_routing_and_thread() {
    let executor = mock(vec![Ok(signed())]);
    let original = request();
    let result = prepare(&executor, &account(), &original, &plan(true, false)).unwrap();
    assert_eq!(
        result.validate_for(
            &CanonicalUsername::parse("other@example.test").unwrap(),
            &original
        ),
        Err(SubmissionError::RequestMismatch)
    );
    for changed in [
        {
            let mut r = original.clone();
            r.body.push_str(" changed");
            r
        },
        {
            let mut r = original.clone();
            r.cc_recipients.clear();
            r
        },
        {
            let mut r = original.clone();
            r.reply_thread = None;
            r
        },
        {
            let mut r = original.clone();
            r.protection.sign = true;
            r
        },
        {
            let mut r = original.clone();
            r.protection.encrypt = true;
            r
        },
        {
            let mut r = original.clone();
            r.protection.encrypt_to_self = true;
            r
        },
        {
            let mut r = original.clone();
            r.protection.binding_revision = Some(7);
            r
        },
    ] {
        assert_eq!(
            result.validate_for(&account(), &changed),
            Err(SubmissionError::RequestMismatch)
        );
    }
}

#[test]
fn shared_recipient_bound_accepts_fifty_and_refuses_fifty_one_before_crypto() {
    let fingerprints = |count: usize| (1..=count).map(|n| format!("{n:040X}")).collect::<Vec<_>>();
    let executor = mock(vec![Ok(encrypted())]);
    let mut allowed = plan(false, true);
    allowed.recipient_fingerprints = fingerprints(crate::openpgp_crypto::MAX_RECIPIENTS);
    prepare(&executor, &account(), &request(), &allowed).unwrap();
    assert_eq!(executor.operations.borrow().len(), 1);
    let executor = mock(Vec::new());
    allowed.recipient_fingerprints = fingerprints(crate::openpgp_crypto::MAX_RECIPIENTS + 1);
    assert_eq!(
        prepare(&executor, &account(), &request(), &allowed).unwrap_err(),
        SubmissionError::InvalidPlan
    );
    assert!(executor.operations.borrow().is_empty());
}

#[test]
fn crypto_size_refusal_preserves_ordinary_attachment_capacity() {
    let executor = mock(Vec::new());
    let mut request = request();
    request.attachments = [8, 5]
        .into_iter()
        .map(|mib| {
            UploadedAttachment::new(
                ComposePolicy::default(),
                format!("synthetic-{mib}.bin"),
                "application/octet-stream",
                vec![0; mib * 1024 * 1024],
            )
            .unwrap()
        })
        .collect();
    let ordinary = prepare(&executor, &account(), &request, &plan(false, false)).unwrap();
    assert!(ordinary.as_bytes().len() > pgp_mime::MAX_PGP_MIME_BYTES);
    assert!(ordinary.as_bytes().len() <= crate::mailbox::DEFAULT_MESSAGE_APPEND_MAX_BYTES);
    drop(ordinary);
    assert_eq!(
        prepare(&executor, &account(), &request, &plan(true, false)).unwrap_err(),
        SubmissionError::SizeLimit
    );
    assert!(executor.operations.borrow().is_empty());
}

fn bindings() -> crate::openpgp_bindings::BindingRecord {
    use crate::openpgp_bindings::*;
    let mut record = BindingRecord::empty(account().as_str()).unwrap();
    record.revision = 7;
    record.account_binding = Some(AccountBinding {
        primary_fingerprint: SIGNER.into(),
        signing_fingerprint: Some(SIGNER.into()),
        decrypt_primary_fingerprints: vec![SIGNER.into()],
    });
    record.recipient_bindings = ["bob@example.test", "carol@example.test"]
        .into_iter()
        .map(|address| RecipientBinding {
            address: address.into(),
            primary_fingerprint: RECIPIENT.into(),
            encryption: Requirement::Optional,
        })
        .collect();
    record
}

fn inventory() -> crate::openpgp_inventory::Inventory {
    let key = |fp| {
        serde_json::json!({"primary":{"fingerprint":fp,"algorithm":1,"bits":3072,
        "created":1,"expires":0,"revoked":false,"expired":false,"disabled":false,"invalid":false,
        "can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false},"subkeys":[]})
    };
    let value = serde_json::json!({"version":1,"ok":true,"protocol":"openpgp",
        "gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[key(SIGNER),key(RECIPIENT)]});
    crate::openpgp_inventory::Inventory::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

#[test]
fn delivery_reevaluates_exact_final_recipients_and_confirmed_revision() {
    let executor = mock(vec![Ok(signed()), Ok(encrypted())]);
    let mut request = request();
    request.protection = crate::send::ProtectionIntent {
        sign: true,
        encrypt: true,
        encrypt_to_self: false,
        binding_revision: Some(7),
    };
    let result = prepare_for_delivery(
        &executor,
        &account(),
        &request,
        &bindings(),
        Some(&inventory()),
        100,
    )
    .unwrap();
    assert_eq!(
        result.protection(),
        SubmissionProtection::SignedAndEncrypted
    );
    assert_eq!(executor.operations.borrow().len(), 2);
    let executor = mock(Vec::new());
    request.cc_recipients.push("unbound@example.test".into());
    assert_eq!(
        prepare_for_delivery(
            &executor,
            &account(),
            &request,
            &bindings(),
            Some(&inventory()),
            100
        )
        .unwrap_err(),
        SubmissionError::ProtectionBlocked(Some(
            crate::openpgp_bindings::BlockReason::RecipientKeyUnavailable
        ))
    );
    assert!(executor.operations.borrow().is_empty());
}

#[test]
fn delivery_to_exact_self_uses_account_key_once_without_recipient_contact_binding() {
    let executor = mock(vec![Ok(signed()), Ok(encrypted())]);
    let mut request = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        "alice@example.test",
        "",
        "",
        "Synthetic self delivery",
        "Synthetic protected body",
        Vec::new(),
    )
    .unwrap();
    request.protection = crate::send::ProtectionIntent {
        sign: true,
        encrypt: true,
        encrypt_to_self: true,
        binding_revision: Some(7),
    };
    let result = prepare_for_delivery(
        &executor,
        &account(),
        &request,
        &bindings(),
        Some(&inventory()),
        100,
    )
    .unwrap();
    assert_eq!(
        result.protection(),
        SubmissionProtection::SignedAndEncrypted
    );
    let operations = executor.operations.borrow();
    assert_eq!(operations.len(), 2);
    assert!(
        matches!(&operations[0], Operation::Sign { signer_fingerprint, .. } if signer_fingerprint == SIGNER)
    );
    assert!(
        matches!(&operations[1], Operation::Encrypt { recipient_fingerprints, .. } if recipient_fingerprints == &[SIGNER.to_string()])
    );
}

#[test]
fn ordinary_delivery_with_existing_optional_bindings_needs_no_inventory_or_crypto() {
    let mut request = request();
    request.protection.binding_revision = Some(7);
    let record = bindings();
    let result =
        prepare_for_delivery(&UnavailableCrypto, &account(), &request, &record, None, 100).unwrap();
    assert_eq!(result.protection(), SubmissionProtection::Ordinary);
    assert_eq!(
        result.as_bytes(),
        crate::send::build_submission_message(account().as_str(), &request).unwrap()
    );

    let mut required_recipient = record;
    required_recipient.recipient_bindings[0].encryption =
        crate::openpgp_bindings::Requirement::Required;
    assert_eq!(
        prepare_for_delivery(
            &UnavailableCrypto,
            &account(),
            &request,
            &required_recipient,
            None,
            100,
        )
        .unwrap_err(),
        SubmissionError::ProtectionBlocked(Some(
            crate::openpgp_bindings::BlockReason::RecipientRequiresEncryption
        ))
    );
}

#[test]
fn revisionless_ordinary_delivery_reevaluates_current_policy_without_crypto() {
    // A plain form is permitted to omit the key revision. It must still use
    // current trusted policy, rather than fail merely because bindings exist.
    let request = request();
    assert_eq!(request.protection.binding_revision, None);
    let executor = mock(Vec::new());
    let record = bindings();
    let ordinary = prepare_for_delivery(&executor, &account(), &request, &record, None, 100)
        .expect("optional policy permits an explicit plain message");
    assert_eq!(ordinary.protection(), SubmissionProtection::Ordinary);
    assert!(executor.operations.borrow().is_empty());

    let mut required = record.clone();
    required.policy.encryption = crate::openpgp_bindings::Requirement::Required;
    assert_eq!(
        prepare_for_delivery(&executor, &account(), &request, &required, None, 100).unwrap_err(),
        SubmissionError::ProtectionBlocked(Some(
            crate::openpgp_bindings::BlockReason::EncryptionRequired
        ))
    );
    let mut required_recipient = record;
    required_recipient.recipient_bindings[0].encryption =
        crate::openpgp_bindings::Requirement::Required;
    assert_eq!(
        prepare_for_delivery(
            &executor,
            &account(),
            &request,
            &required_recipient,
            None,
            100
        )
        .unwrap_err(),
        SubmissionError::ProtectionBlocked(Some(
            crate::openpgp_bindings::BlockReason::RecipientRequiresEncryption
        ))
    );
    assert!(executor.operations.borrow().is_empty());
}

#[test]
fn stale_missing_foreign_binding_and_missing_inventory_refuse_before_engine() {
    let executor = mock(Vec::new());
    let mut request = request();
    request.protection.sign = true;
    assert_eq!(
        prepare_for_delivery(
            &executor,
            &account(),
            &request,
            &bindings(),
            Some(&inventory()),
            100
        )
        .unwrap_err(),
        SubmissionError::StaleBinding
    );
    request.protection.binding_revision = Some(6);
    assert_eq!(
        prepare_for_delivery(
            &executor,
            &account(),
            &request,
            &bindings(),
            Some(&inventory()),
            100
        )
        .unwrap_err(),
        SubmissionError::StaleBinding
    );
    request.protection.binding_revision = Some(7);
    assert_eq!(
        prepare_for_delivery(&executor, &account(), &request, &bindings(), None, 100).unwrap_err(),
        SubmissionError::InventoryUnavailable
    );
    assert_eq!(
        prepare_for_delivery(
            &executor,
            &account(),
            &request,
            &crate::openpgp_bindings::BindingRecord::empty("other@example.test").unwrap(),
            Some(&inventory()),
            100
        )
        .unwrap_err(),
        SubmissionError::BindingUnavailable
    );
    assert!(executor.operations.borrow().is_empty());
}

#[test]
fn required_protection_cannot_downgrade_when_public_inventory_is_unavailable() {
    let executor = mock(Vec::new());
    let mut request = request();
    request.protection.binding_revision = Some(7);
    let mut record = bindings();
    record.policy.encryption = crate::openpgp_bindings::Requirement::Required;
    assert_eq!(
        prepare_for_delivery(&executor, &account(), &request, &record, None, 100).unwrap_err(),
        SubmissionError::ProtectionBlocked(Some(
            crate::openpgp_bindings::BlockReason::EncryptionRequired
        ))
    );
    assert!(executor.operations.borrow().is_empty());
    let empty = crate::openpgp_bindings::BindingRecord::empty(account().as_str()).unwrap();
    request.protection = crate::send::ProtectionIntent::default();
    assert_eq!(
        prepare_for_delivery(&executor, &account(), &request, &empty, None, 100)
            .unwrap()
            .protection(),
        SubmissionProtection::Ordinary
    );
}

#[test]
fn sender_identity_prepared_alias_keeps_canonical_crypto_account_and_exact_capture() {
    let executor = mock(vec![Ok(signed())]);
    let mut selected = request();
    selected.sender_identity = selected
        .sender_identity
        .clone()
        .with_sender("desk", "desk@example.test")
        .unwrap();
    selected.protection.sign = true;
    let prepared = prepare(&executor, &account(), &selected, &plan(true, false)).unwrap();
    assert_eq!(executor.operations.borrow().len(), 1);
    assert!(std::str::from_utf8(prepared.as_bytes())
        .unwrap()
        .contains("<desk@example.test>"));
    prepared.validate_for(&account(), &selected).unwrap();
    let mut changed = selected.clone();
    changed.sender_identity = changed
        .sender_identity
        .clone()
        .with_sender("other", "desk@example.test")
        .unwrap();
    assert_eq!(
        prepared.validate_for(&account(), &changed),
        Err(SubmissionError::RequestMismatch)
    );
    assert_eq!(
        prepared.validate_for(
            &CanonicalUsername::parse("desk@example.test").unwrap(),
            &selected
        ),
        Err(SubmissionError::RequestMismatch)
    );
}
