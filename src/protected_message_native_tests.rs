//! Called inside the disposable native authenticated-service fixture so the
//! processing layer exercises the production Client, framing and dispatcher.

use super::*;
use crate::openpgp_crypto_runtime::Client;

pub(crate) const CLIENT_REQUESTS: usize = 5;
pub(crate) const VISIBLE_DECRYPTION_PLAINTEXT: &[u8] =
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nVisible-recipient synthetic control.\r\n";

/// Native self-decryption and refusal controls use only the two existing,
/// disjoint fixture homes. No plaintext is returned in the observation receipt.
pub(crate) fn run_decryption_fixture(
    client: &Client,
    alice_fp: &str,
    bob_fp: &str,
    visible_ciphertext: &[u8],
) -> serde_json::Value {
    assert_eq!(std::env::consts::OS, "openbsd");
    let plaintext = String::from_utf8(tests::INNER.to_vec())
        .unwrap()
        .replace(
            "Visible synthetic body",
            "Visible synthetic body — café 日本語",
        )
        .into_bytes();
    let encrypted = client
        .execute(
            "alice",
            &Operation::Encrypt {
                recipient_fingerprints: vec![alice_fp.into()],
                data: plaintext.clone(),
            },
        )
        .unwrap()
        .unwrap();
    let decrypt = |fingerprint: &str, ciphertext: &[u8]| Operation::Decrypt {
        allowed_primary_fingerprints: vec![fingerprint.into()],
        ciphertext: ciphertext.to_vec(),
    };
    let decrypted = client
        .execute("alice", &decrypt(alice_fp, &encrypted.content))
        .unwrap()
        .unwrap();
    assert!(decrypted.content == plaintext);
    assert!(decrypted.primary_fingerprint.as_deref() == Some(alice_fp));
    let processor = Processor::new(client.clone(), RenderingPolicy::default());
    let bindings = |account, fingerprint: &str| InboundBindings {
        signer_key_validities: Default::default(),
        account: CanonicalUsername::parse(account).unwrap(),
        decrypt_primary_fingerprints: vec![fingerprint.into()],
        signer: None,
    };
    let mut alice_session = tests::session();
    alice_session.record.canonical_username = "alice".into();
    let entity = pgp_mime::build_encrypted(
        &encrypted.content,
        "native-self-decryption",
        PgpMimePolicy::default(),
    )
    .unwrap();
    let source = tests::source(&entity);
    let original = tests::original(&source);
    let rendered = processor
        .process(
            &tests::context(),
            &alice_session,
            &original,
            &source,
            &bindings("alice", alice_fp),
        )
        .expect("native self-decrypted UTF8 MIME is transiently rendered");
    assert!(rendered.original_source == source);
    assert!(rendered.protection.decrypted_on_mail_host);
    assert_eq!(rendered.protection.signature, SignatureValidity::Unsigned);
    assert!(rendered.rendered.body_html.contains("café 日本語"));
    assert!(rendered.rendered.body_text_for_compose.is_empty());
    for hostile in [
        "<script",
        "<img",
        "onerror",
        "SYNTHETIC_HOSTILE",
        "fixture.invalid",
    ] {
        assert!(!rendered.rendered.body_html.contains(hostile));
    }
    let attachment = rendered
        .download_attachment(
            &CanonicalUsername::parse("alice").unwrap(),
            "INBOX",
            7,
            &original.metadata.as_ref().unwrap().version,
            "1.2",
        )
        .unwrap();
    assert!(attachment.body == [0, 1, 255]);

    let hidden_error = client
        .execute("bob", &decrypt(bob_fp, &encrypted.content))
        .unwrap()
        .err();
    let hidden_processor = processor
        .process(
            &tests::context(),
            &tests::session(),
            &original,
            &source,
            &bindings("bob", bob_fp),
        )
        .err();
    let hidden_safe_refusal = hidden_processor.is_some_and(|error| {
        let html = crate::openpgp_reader_ui::render(
            &crate::openpgp_reader_ui::ReaderState::Refused(error),
        );
        html.contains("OpenPGP processing refused")
            && html.contains("content has not been displayed")
            && !html.contains("Visible synthetic body")
            && !html.contains("synthetic.bin")
            && !html.contains("cryptographically valid")
    });
    let visible = client
        .execute("alice", &decrypt(alice_fp, visible_ciphertext))
        .unwrap()
        .unwrap();
    assert!(visible.content == VISIBLE_DECRYPTION_PLAINTEXT);
    assert!(visible.primary_fingerprint.as_deref() == Some(alice_fp));
    let missing_error = client
        .execute("bob", &decrypt(bob_fp, visible_ciphertext))
        .unwrap()
        .err();
    let visible_entity = pgp_mime::build_encrypted(
        visible_ciphertext,
        "native-visible-recipient",
        PgpMimePolicy::default(),
    )
    .unwrap();
    let visible_source = tests::source(&visible_entity);
    let missing_processor = processor
        .process(
            &tests::context(),
            &tests::session(),
            &tests::original(&visible_source),
            &visible_source,
            &bindings("bob", bob_fp),
        )
        .err();
    // The server takes key authority from its mapping, not the caller. The
    // client must nevertheless refuse a response outside its requested set.
    let wrong_requested = client
        .execute("alice", &decrypt(bob_fp, &encrypted.content))
        .err();

    let armor = |packet: &[u8]| {
        format!(
            "-----BEGIN PGP MESSAGE-----\n\n{}\n-----END PGP MESSAGE-----\n",
            crate::send::base64_encode_wrapped(packet)
        )
        .into_bytes()
    };
    // A framed tag-18 SEIPD packet declaring only its version, with no encrypted
    // payload, is invalid OpenPGP rather than unavailable service capacity.
    let malformed = armor(&[0xd2, 0x01, 0x01]);
    let exported = std::str::from_utf8(&encrypted.content).unwrap();
    let encoded = exported
        .lines()
        .skip_while(|line| !line.is_empty())
        .skip(1)
        .take_while(|line| !line.starts_with('=') && !line.starts_with("-----END"))
        .collect::<String>();
    let packet =
        crate::attachment::decode_base64_bytes(&encoded, crate::openpgp_crypto::MAX_CONTENT)
            .expect("decode actual synthetic ciphertext armor");
    assert!(packet.len() > 64);
    let truncated = armor(&packet[..packet.len() / 2]);
    let mut refusals = Vec::new();
    for (name, ciphertext) in [("malformed", malformed), ("truncated", truncated)] {
        let native_error = client
            .execute("alice", &decrypt(alice_fp, &ciphertext))
            .unwrap()
            .err();
        let entity = pgp_mime::build_encrypted(
            &ciphertext,
            "native-invalid-ciphertext",
            PgpMimePolicy::default(),
        )
        .unwrap();
        let source = tests::source(&entity);
        let processor_error = processor
            .process(
                &tests::context(),
                &alice_session,
                &tests::original(&source),
                &source,
                &bindings("alice", alice_fp),
            )
            .err();
        let safe_ui = processor_error.is_some_and(|error| {
            let html = crate::openpgp_reader_ui::render(
                &crate::openpgp_reader_ui::ReaderState::Refused(error),
            );
            html.contains("OpenPGP processing refused")
                && (html.contains("content has not been displayed")
                    || html.contains("No decrypted content has been displayed"))
                && !html.contains("Visible synthetic body")
                && !html.contains("synthetic.bin")
                && !html.contains("cryptographically valid")
        });
        refusals.push(serde_json::json!({
            "case":name,
            "native":native_error.map(|error|format!("{error:?}")),
            "processor":processor_error.map(|error|format!("{error:?}")),
            "safe_refusal_ui":safe_ui,
        }));
    }
    serde_json::json!({
        "exact_decryption":true,
        "utf8_rendering":true,
        "binary_attachment":true,
        "sanitized":true,
        "quote_empty":true,
        "original_ciphertext_preserved":true,
        "visible_recipient_exact_decryption":true,
        "missing_private_key":missing_error.map(|error|format!("{error:?}")),
        "missing_private_processor":missing_processor.map(|error|format!("{error:?}")),
        "hidden_recipient_native":hidden_error.map(|error|format!("{error:?}")),
        "hidden_recipient_processor":hidden_processor.map(|error|format!("{error:?}")),
        "hidden_recipient_safe_refusal":hidden_safe_refusal,
        "wrong_requested_key":wrong_requested.map(|error|format!("{error:?}")),
        "invalid_ciphertext":refusals,
    })
}

/// The caller supplies two disjoint, outer-owned native key homes. Alice's
/// public certificate is deliberately absent from Bob's verifier home.
pub(crate) fn run_missing_signer_fixture(client: &Client, alice_fp: &str) -> serde_json::Value {
    assert_eq!(std::env::consts::OS, "openbsd");
    let signed = client
        .execute(
            "alice",
            &Operation::Sign {
                signer_fingerprint: alice_fp.into(),
                data: tests::INNER.to_vec(),
            },
        )
        .unwrap()
        .unwrap();
    let digest = match signed.hash_algorithm {
        Some(8) => SignatureDigest::Sha256,
        Some(10) => SignatureDigest::Sha512,
        _ => panic!("unsupported native digest"),
    };
    let valid = client
        .execute(
            "alice",
            &Operation::Verify {
                data: tests::INNER.to_vec(),
                signature: signed.content.clone(),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        valid.signature,
        crate::openpgp_crypto::SignatureState::Valid
    );
    assert!(valid.primary_fingerprint.as_deref() == Some(alice_fp));

    let tampered = String::from_utf8(tests::INNER.to_vec())
        .unwrap()
        .replace("Visible synthetic body", "Altered synthetic body")
        .into_bytes();
    assert_ne!(tampered.as_slice(), tests::INNER);
    let tamper_error = client
        .execute(
            "alice",
            &Operation::Verify {
                data: tampered,
                signature: signed.content.clone(),
            },
        )
        .unwrap()
        .err();
    assert_eq!(tamper_error, Some(CryptoError::Signature));
    let mut duplicate = signed.content.clone();
    duplicate.push(b'\n');
    duplicate.extend_from_slice(&signed.content);
    let duplicate_error = client
        .execute(
            "alice",
            &Operation::Verify {
                data: tests::INNER.to_vec(),
                signature: duplicate,
            },
        )
        .unwrap()
        .err();
    assert_eq!(duplicate_error, Some(CryptoError::Signature));

    let entity = pgp_mime::build_signed(
        tests::INNER,
        &signed.content,
        digest,
        "native-missing-signer",
        PgpMimePolicy::default(),
    )
    .unwrap();
    let source = tests::source(&entity);
    let original = tests::original(&source);
    let processor = Processor::new(client.clone(), RenderingPolicy::default());
    let mut alice_session = tests::session();
    alice_session.record.canonical_username = "alice".into();
    let bindings = |account| InboundBindings {
        signer_key_validities: Default::default(),
        account: CanonicalUsername::parse(account).unwrap(),
        decrypt_primary_fingerprints: Vec::new(),
        signer: None,
    };
    let known = processor
        .process(
            &tests::context(),
            &alice_session,
            &original,
            &source,
            &bindings("alice"),
        )
        .expect("actual known certificate verifies without implying a sender binding");
    assert_eq!(known.protection.signature, SignatureValidity::Valid);
    assert_eq!(
        known.protection.signer_identity,
        SignerIdentityState::Unknown
    );
    assert!(known.rendered.body_html.contains("Visible synthetic body"));
    assert!(known.rendered.body_text_for_compose.is_empty());

    let native_error = client
        .execute(
            "bob",
            &Operation::Verify {
                data: tests::INNER.to_vec(),
                signature: signed.content,
            },
        )
        .unwrap()
        .err();
    let processor_error = processor
        .process(
            &tests::context(),
            &tests::session(),
            &original,
            &source,
            &bindings("bob"),
        )
        .err();
    let refusal_ui = processor_error.map(|error| {
        crate::openpgp_reader_ui::render(&crate::openpgp_reader_ui::ReaderState::Refused(error))
    });
    let safe_refusal = refusal_ui.as_ref().is_some_and(|html| {
        html.contains("OpenPGP processing refused")
            && html.contains("content has not been displayed")
            && !html.contains("cryptographically valid")
            && !html.contains("Visible synthetic body")
            && !html.contains("synthetic.bin")
    });
    // Only fixed enum categories and booleans leave this actor. In particular,
    // collect both classifications before the caller's distinguishing assertion.
    serde_json::json!({
        "known_certificate_valid": true,
        "known_identity_unknown": true,
        "tamper": tamper_error.map(|error| format!("{error:?}")),
        "duplicate_signature": duplicate_error.map(|error| format!("{error:?}")),
        "native_missing_signer": native_error.map(|error| format!("{error:?}")),
        "processor_missing_signer": processor_error.map(|error| format!("{error:?}")),
        "safe_refusal_ui": safe_refusal,
        "missing_public_key_copy": refusal_ui.as_ref().is_some_and(|html| html.contains("The signing key is unavailable.")),
        "no_decryption_key_copy": refusal_ui.as_ref().is_some_and(|html| html.contains("No usable decryption key"))
    })
}

pub(crate) fn run_client_fixture(client: &Client, alice_fp: &str, bob_fp: &str) {
    assert_eq!(std::env::consts::OS, "openbsd");
    let signed = client
        .execute(
            "alice",
            &Operation::Sign {
                signer_fingerprint: alice_fp.into(),
                data: tests::INNER.to_vec(),
            },
        )
        .unwrap()
        .unwrap();
    let digest = match signed.hash_algorithm {
        Some(8) => SignatureDigest::Sha256,
        Some(10) => SignatureDigest::Sha512,
        _ => panic!("unsupported native digest"),
    };
    let signed = pgp_mime::build_signed(
        tests::INNER,
        &signed.content,
        digest,
        "native-pipeline-signed",
        PgpMimePolicy::default(),
    )
    .unwrap();
    let encrypted = client
        .execute(
            "alice",
            &Operation::Encrypt {
                recipient_fingerprints: vec![bob_fp.into()],
                data: signed.clone(),
            },
        )
        .unwrap()
        .unwrap();
    let entity = pgp_mime::build_encrypted(
        &encrypted.content,
        "native-pipeline-encrypted",
        PgpMimePolicy::default(),
    )
    .unwrap();
    let source = tests::source(&entity);
    let original = tests::original(&source);
    let bindings = InboundBindings {
        signer_key_validities: Default::default(),
        account: CanonicalUsername::parse("bob").unwrap(),
        decrypt_primary_fingerprints: vec![bob_fp.into()],
        signer: Some(SignerIdentityBinding {
            primary_fingerprint: alice_fp.into(),
            mailbox: MailboxIdentity::parse("alice@example.test").unwrap(),
            key_validity: KeyValidity::Current,
        }),
    };
    let processor = Processor::new(client.clone(), RenderingPolicy::default());
    let result = processor
        .process(
            &tests::context(),
            &tests::session(),
            &original,
            &source,
            &bindings,
        )
        .expect("native authenticated client decrypt/verify/render pipeline");
    assert!(result.protection.decrypted_on_mail_host);
    assert_eq!(result.protection.signature, SignatureValidity::Valid);
    assert_eq!(
        result.protection.signer_identity,
        SignerIdentityState::ConfirmedBinding
    );
    assert_eq!(
        result.protection.signer_primary_fingerprint.as_deref(),
        Some(alice_fp)
    );
    assert_eq!(result.original_source, source);
    assert!(result.rendered.body_text_for_compose.is_empty());
    assert!(result.rendered.body_html.contains("Visible synthetic body"));
    for hostile in [
        "<script",
        "<img",
        "onerror",
        "SYNTHETIC_HOSTILE",
        "fixture.invalid",
    ] {
        assert!(!result.rendered.body_html.contains(hostile));
    }
    assert_eq!(
        result.rendered.subject.as_deref(),
        Some("Original outer subject")
    );
    assert_eq!(
        result.rendered.from.as_deref(),
        Some("Alice <alice@example.test>")
    );
    let attachment = result
        .attachment_part(
            &bindings.account,
            "INBOX",
            7,
            &original.metadata.as_ref().unwrap().version,
            "1.2",
        )
        .unwrap()
        .unwrap();
    assert_eq!(attachment.body_text, "AAH/");
    assert_eq!(
        attachment.metadata.filename.as_deref(),
        Some("synthetic.bin")
    );
    let downloaded = result
        .download_attachment(
            &bindings.account,
            "INBOX",
            7,
            &original.metadata.as_ref().unwrap().version,
            "1.2",
        )
        .unwrap();
    assert_eq!(downloaded.body, [0, 1, 255]);

    let tampered = String::from_utf8(signed)
        .unwrap()
        .replace("Visible synthetic body", "Tampered synthetic body")
        .into_bytes();
    let source = tests::source(&tampered);
    assert_eq!(
        processor
            .process(
                &tests::context(),
                &tests::session(),
                &tests::original(&source),
                &source,
                &bindings
            )
            .unwrap_err(),
        ProtectedError::SignatureFailure
    );
}
