use super::*;
use crate::config::LogLevel;
use crate::logging::{EventCategory, LogEvent};
use crate::openpgp_crypto::SignatureState;
use std::cell::RefCell;
use std::collections::VecDeque;

const FP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DECRYPT_FP: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const SIGNATURE: &[u8] =
    b"-----BEGIN PGP SIGNATURE-----\n\nZml4dHVyZQ==\n-----END PGP SIGNATURE-----\n";
const CIPHERTEXT: &[u8] =
    b"-----BEGIN PGP MESSAGE-----\n\nZml4dHVyZQ==\n-----END PGP MESSAGE-----\n";
pub(super) const INNER: &[u8] = b"Content-Type: multipart/mixed; boundary=inner\r\nFrom: forged@example.test\r\nSubject: forged inner subject\r\n\r\n--inner\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Visible synthetic body</p><script>SYNTHETIC_HOSTILE</script><img src=\"https://fixture.invalid/track\" onerror=\"SYNTHETIC_HOSTILE\">\r\n--inner\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=synthetic.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAH/\r\n--inner--\r\n";

struct Mock {
    results: RefCell<VecDeque<Result<Outcome, CryptoFailure>>>,
    operations: RefCell<Vec<Operation>>,
}

impl CryptoExecutor for &Mock {
    fn execute(
        &self,
        account: &CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        assert_eq!(account.as_str(), "bob");
        self.operations.borrow_mut().push(operation.clone());
        self.results
            .borrow_mut()
            .pop_front()
            .expect("unexpected crypto request")
    }
}

fn mock(results: Vec<Result<Outcome, CryptoFailure>>) -> Mock {
    Mock {
        results: RefCell::new(results.into()),
        operations: RefCell::new(Vec::new()),
    }
}

fn verified() -> Outcome {
    Outcome {
        operation: "verify".into(),
        content: Vec::new(),
        signer_fingerprint: Some(FP.into()),
        primary_fingerprint: Some(FP.into()),
        signature: SignatureState::Valid,
        hash_algorithm: Some(8),
    }
}

fn decrypted(content: Vec<u8>) -> Outcome {
    Outcome {
        operation: "decrypt".into(),
        content,
        signer_fingerprint: None,
        primary_fingerprint: Some(DECRYPT_FP.into()),
        signature: SignatureState::None,
        hash_algorithm: None,
    }
}

pub(super) fn session() -> ValidatedSession {
    ValidatedSession {
        record: crate::session::SessionRecord {
            session_id: "0".repeat(64),
            csrf_token: "1".repeat(64),
            canonical_username: "bob".into(),
            issued_at: 10,
            expires_at: 100,
            last_seen_at: 20,
            revoked_at: None,
            remote_addr: "127.0.0.1".into(),
            user_agent: "Synthetic fixture".into(),
            factor: crate::auth::RequiredSecondFactor::Totp,
        },
        audit_event: LogEvent::new(
            LogLevel::Info,
            EventCategory::Session,
            "session_validated",
            "synthetic session validated",
        ),
    }
}

pub(super) fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        crate::auth::AuthenticationPolicy::default(),
        "req-protected",
        "127.0.0.1",
        "Synthetic fixture",
    )
    .unwrap()
}

pub(super) fn source(entity: &[u8]) -> Vec<u8> {
    let mut source = b"From: Alice <alice@example.test>\r\nTo: bob@example.test\r\nSubject: Original outer subject\r\nMessage-ID: <synthetic@example.test>\r\n".to_vec();
    source.extend_from_slice(entity);
    source
}

pub(super) fn original(source: &[u8]) -> MessageView {
    let (headers, body) = split_entity(source).unwrap();
    MessageView {
        metadata: Some(crate::message_metadata::MessageMetadata {
            attachments: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
            version: MessageVersion::new("a".repeat(32), "b".repeat(32)).unwrap(),
            attachment_count: None,
            preview: None,
        }),
        mailbox_name: "INBOX".into(),
        uid: 7,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: source.len() as u64,
        header_block: std::str::from_utf8(headers).unwrap().into(),
        body_text: std::str::from_utf8(body).unwrap().into(),
    }
}

fn bindings() -> InboundBindings {
    InboundBindings {
        account: CanonicalUsername::parse("bob").unwrap(),
        decrypt_primary_fingerprints: vec![DECRYPT_FP.into()],
        signer: Some(SignerIdentityBinding {
            primary_fingerprint: FP.into(),
            mailbox: MailboxIdentity::parse("alice@example.test").unwrap(),
            key_validity: KeyValidity::Current,
        }),
    }
}

fn signed() -> Vec<u8> {
    pgp_mime::build_signed(
        INNER,
        SIGNATURE,
        SignatureDigest::Sha256,
        "signature",
        PgpMimePolicy::default(),
    )
    .unwrap()
}
fn encrypted() -> Vec<u8> {
    pgp_mime::build_encrypted(CIPHERTEXT, "cipher", PgpMimePolicy::default()).unwrap()
}

#[test]
fn signed_pipeline_preserves_exact_verification_input_and_outer_headers() {
    let wire = source(&signed());
    let message = original(&wire);
    let engine = mock(vec![Ok(verified())]);
    let processor = Processor::new(&engine, RenderingPolicy::default());
    let result = processor
        .process(&context(), &session(), &message, &wire, &bindings())
        .unwrap();
    assert_eq!(result.original_source, wire);
    assert_eq!(
        result.rendered.subject.as_deref(),
        Some("Original outer subject")
    );
    assert_eq!(
        result.rendered.from.as_deref(),
        Some("Alice <alice@example.test>")
    );
    assert_eq!(result.protection.signature, SignatureValidity::Valid);
    assert_eq!(
        result.protection.signer_identity,
        SignerIdentityState::ConfirmedBinding
    );
    assert_eq!(result.protection.key_validity, Some(KeyValidity::Current));
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
    let operations = engine.operations.borrow();
    let Operation::Verify { data, .. } = &operations[0] else {
        panic!("verify")
    };
    assert_eq!(data, INNER);
    assert!(!format!("{result:?}").contains("Visible synthetic body"));
}

#[test]
fn encrypted_signed_pipeline_does_not_expose_plaintext_source_or_quote() {
    let wire = source(&encrypted());
    let message = original(&wire);
    let engine = mock(vec![Ok(decrypted(signed())), Ok(verified())]);
    let result = Processor::new(&engine, RenderingPolicy::default())
        .process(&context(), &session(), &message, &wire, &bindings())
        .unwrap();
    assert!(result.protection.decrypted_on_mail_host);
    assert_eq!(result.protection.signature, SignatureValidity::Valid);
    assert_eq!(result.original_source, wire);
    assert!(!String::from_utf8_lossy(result.original_source).contains("Visible synthetic body"));
    assert!(result.rendered.body_text_for_compose.is_empty());
    assert_eq!(engine.operations.borrow().len(), 2);
}

#[test]
fn decrypted_unsigned_body_is_sanitized_without_signature_claim() {
    let wire = source(&encrypted());
    let engine = mock(vec![Ok(decrypted(INNER.to_vec()))]);
    let result = Processor::new(&engine, RenderingPolicy::default())
        .process(&context(), &session(), &original(&wire), &wire, &bindings())
        .unwrap();
    assert!(result.protection.decrypted_on_mail_host);
    assert_eq!(result.protection.signature, SignatureValidity::Unsigned);
    assert_eq!(
        result.protection.signer_identity,
        SignerIdentityState::NotApplicable
    );
    assert_eq!(result.protection.key_validity, None);
}

#[test]
fn malformed_or_partial_crypto_results_never_release_plaintext() {
    let wire = source(&encrypted());
    for failure in [
        CryptoFailure::Transport,
        CryptoFailure::Engine(CryptoError::Locked),
        CryptoFailure::Engine(CryptoError::MissingKey),
        CryptoFailure::Engine(CryptoError::Integrity),
    ] {
        let engine = mock(vec![Err(failure)]);
        assert!(Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &bindings())
            .is_err());
    }
    let mut partial = decrypted(INNER.to_vec());
    partial.primary_fingerprint = Some(FP.into());
    let engine = mock(vec![Ok(partial)]);
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &bindings())
            .unwrap_err(),
        ProtectedError::Unavailable
    );
}

#[test]
fn good_crypto_with_untrusted_or_mismatched_identity_remains_separate() {
    let wire = source(&signed());
    for (signer, expected) in [
        (None, SignerIdentityState::Unknown),
        (
            Some(SignerIdentityBinding {
                primary_fingerprint: DECRYPT_FP.into(),
                mailbox: MailboxIdentity::parse("alice@example.test").unwrap(),
                key_validity: KeyValidity::Current,
            }),
            SignerIdentityState::Mismatch,
        ),
    ] {
        let mut binding = bindings();
        binding.signer = signer;
        let engine = mock(vec![Ok(verified())]);
        let result = Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &binding)
            .unwrap();
        assert_eq!(result.protection.signature, SignatureValidity::Valid);
        assert_eq!(result.protection.signer_identity, expected);
        assert_eq!(result.protection.key_validity, Some(KeyValidity::Unknown));
    }
    let wire = String::from_utf8(wire)
        .unwrap()
        .replacen("alice@example.test", "other@example.test", 1)
        .into_bytes();
    let engine = mock(vec![Ok(verified())]);
    let result = Processor::new(&engine, RenderingPolicy::default())
        .process(&context(), &session(), &original(&wire), &wire, &bindings())
        .unwrap();
    assert_eq!(result.protection.signature, SignatureValidity::Valid);
    assert_eq!(
        result.protection.signer_identity,
        SignerIdentityState::Mismatch
    );
}

#[test]
fn expired_revoked_bad_signature_and_digest_disagreement_refuse() {
    let wire = source(&signed());
    for (validity, expected) in [
        (KeyValidity::Expired, ProtectedError::ExpiredKey),
        (KeyValidity::Revoked, ProtectedError::RevokedKey),
    ] {
        let mut binding = bindings();
        binding.signer.as_mut().unwrap().key_validity = validity;
        let engine = mock(Vec::new());
        assert_eq!(
            Processor::new(&engine, RenderingPolicy::default())
                .process(&context(), &session(), &original(&wire), &wire, &binding)
                .unwrap_err(),
            expected
        );
        assert!(
            engine.operations.borrow().is_empty(),
            "known disallowed sender binding must refuse before crypto verification"
        );
    }
    let engine = mock(vec![Err(CryptoFailure::Engine(CryptoError::Signature))]);
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &bindings())
            .unwrap_err(),
        ProtectedError::SignatureFailure
    );
    let mut wrong_digest = verified();
    wrong_digest.hash_algorithm = Some(10);
    let engine = mock(vec![Ok(wrong_digest)]);
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &bindings())
            .unwrap_err(),
        ProtectedError::SignatureFailure
    );
}

#[test]
fn account_binding_and_source_mismatch_refuse_before_engine() {
    let wire = source(&signed());
    let engine = mock(Vec::new());
    let mut binding = bindings();
    binding.account = CanonicalUsername::parse("alice").unwrap();
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &binding)
            .unwrap_err(),
        ProtectedError::ForeignBindings
    );
    let mut changed = original(&wire);
    changed.body_text.push('X');
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &changed, &wire, &bindings())
            .unwrap_err(),
        ProtectedError::SourceMismatch
    );
    assert!(engine.operations.borrow().is_empty());
}

#[test]
fn invalid_duplicate_missing_private_bindings_refuse_before_engine() {
    let wire = source(&encrypted());
    for keys in [
        vec!["short".into()],
        vec![DECRYPT_FP.into(), DECRYPT_FP.into()],
        vec![DECRYPT_FP.into(); 33],
        Vec::new(),
    ] {
        let mut binding = bindings();
        binding.decrypt_primary_fingerprints = keys;
        let engine = mock(Vec::new());
        assert!(Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &binding)
            .is_err());
        assert!(engine.operations.borrow().is_empty());
    }
}

#[test]
fn attachment_selection_requires_account_mailbox_uid_and_stable_version() {
    let wire = source(&encrypted());
    let message = original(&wire);
    let engine = mock(vec![Ok(decrypted(INNER.to_vec()))]);
    let result = Processor::new(&engine, RenderingPolicy::default())
        .process(&context(), &session(), &message, &wire, &bindings())
        .unwrap();
    let account = CanonicalUsername::parse("bob").unwrap();
    let version = &message.metadata.as_ref().unwrap().version;
    let attachment = result
        .attachment_part(&account, "INBOX", 7, version, "1.2")
        .unwrap()
        .unwrap();
    assert_eq!(attachment.body_text, "AAH/");
    for (owner, mailbox, uid, version) in [
        (
            CanonicalUsername::parse("alice").unwrap(),
            "INBOX",
            7,
            version.clone(),
        ),
        (account.clone(), "Sent", 7, version.clone()),
        (account.clone(), "INBOX", 8, version.clone()),
        (
            account,
            "INBOX",
            7,
            MessageVersion::new("c".repeat(32), "d".repeat(32)).unwrap(),
        ),
    ] {
        assert_eq!(
            result
                .attachment_part(&owner, mailbox, uid, &version, "1.2")
                .unwrap_err(),
            ProtectedError::MessageIdentity
        );
    }
}

#[test]
fn repeated_encryption_layer_and_non_utf8_plaintext_refuse_without_retry() {
    let wire = source(&encrypted());
    let engine = mock(vec![Ok(decrypted(encrypted()))]);
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &bindings())
            .unwrap_err(),
        ProtectedError::UnsupportedProtectionLayer
    );
    assert_eq!(engine.operations.borrow().len(), 1);
    let engine = mock(vec![Ok(decrypted(
        b"Content-Type: text/plain\r\n\r\n\xff".to_vec(),
    ))]);
    assert_eq!(
        Processor::new(&engine, RenderingPolicy::default())
            .process(&context(), &session(), &original(&wire), &wire, &bindings())
            .unwrap_err(),
        ProtectedError::UnsupportedTextEncoding
    );
}

#[test]
fn plain_message_keeps_existing_renderer_and_compose_behavior() {
    let wire = source(b"Content-Type: text/plain\r\n\r\nOrdinary synthetic text");
    let engine = mock(Vec::new());
    let result = Processor::new(&engine, RenderingPolicy::default())
        .process(&context(), &session(), &original(&wire), &wire, &bindings())
        .unwrap();
    assert_eq!(
        result.rendered.body_text_for_compose,
        "Ordinary synthetic text"
    );
    assert_eq!(result.protection.signature, SignatureValidity::Unsigned);
    assert!(!result.protection.decrypted_on_mail_host);
    assert!(engine.operations.borrow().is_empty());
}

#[test]
fn unknown_signature_key_is_distinct_from_missing_decryption_key() {
    for (entity, expected) in [
        (signed(), ProtectedError::UnknownSigner),
        (encrypted(), ProtectedError::MissingKey),
    ] {
        let wire = source(&entity);
        let engine = mock(vec![Err(CryptoFailure::Engine(CryptoError::MissingKey))]);
        assert_eq!(
            Processor::new(&engine, RenderingPolicy::default())
                .process(&context(), &session(), &original(&wire), &wire, &bindings())
                .unwrap_err(),
            expected
        );
    }
}

#[test]
fn protected_download_reuses_transfer_decoding_and_filename_policy() {
    let wire = source(&encrypted());
    let message = original(&wire);
    let engine = mock(vec![Ok(decrypted(INNER.to_vec()))]);
    let result = Processor::new(&engine, RenderingPolicy::default())
        .process(&context(), &session(), &message, &wire, &bindings())
        .unwrap();
    let account = CanonicalUsername::parse("bob").unwrap();
    let version = &message.metadata.as_ref().unwrap().version;
    let attachment = result
        .download_attachment(&account, "INBOX", 7, version, "1.2")
        .unwrap();
    assert_eq!(attachment.body, [0, 1, 255]);
    assert_eq!(attachment.filename, "synthetic.bin");
    assert_eq!(
        result
            .download_attachment(&account, "INBOX", 8, version, "1.2")
            .unwrap_err(),
        ProtectedError::MessageIdentity
    );
    assert_eq!(
        result
            .download_attachment(&account, "INBOX", 7, version, "../2")
            .unwrap_err(),
        ProtectedError::Attachment(
            crate::attachment::AttachmentDownloadPublicFailureReason::InvalidRequest
        )
    );
    assert_eq!(
        result
            .download_attachment(&account, "INBOX", 7, version, "1.9")
            .unwrap_err(),
        ProtectedError::Attachment(
            crate::attachment::AttachmentDownloadPublicFailureReason::NotFound
        )
    );
}
