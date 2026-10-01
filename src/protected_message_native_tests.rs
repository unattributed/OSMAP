//! Called inside the disposable native authenticated-service fixture so the
//! processing layer exercises the production Client, framing and dispatcher.

use super::*;
use crate::openpgp_crypto_runtime::Client;

pub(crate) const CLIENT_REQUESTS: usize = 5;

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
