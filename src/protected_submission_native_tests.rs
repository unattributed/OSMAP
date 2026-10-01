//! Native disposable worker proof for outgoing construction and receiving MIME.
//! It does not qualify Client account mapping, HTTP dispatch, or deployment.
use super::*;
use crate::openpgp_crypto::{Error, SignatureState};
use crate::pgp_mime::PgpMimeMessage;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct NativeFixture {
    worker: PathBuf,
    engine: PathBuf,
    alice_home: PathBuf,
    bob_home: PathBuf,
    alice_fp: String,
    bob_fp: String,
    signed_entity: RefCell<Option<Vec<u8>>>,
}
impl NativeFixture {
    fn run(&self, home: &Path, operation: &Operation) -> Result<Outcome, Error> {
        crate::openpgp_crypto_process::execute(
            &self.worker,
            &self.engine,
            home,
            operation,
            Instant::now() + Duration::from_secs(10),
        )
    }
}
impl CryptoExecutor for NativeFixture {
    fn execute(
        &self,
        account: &CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        assert_eq!(account.as_str(), "alice@example.test");
        if let Operation::Sign { data, .. } = operation {
            *self.signed_entity.borrow_mut() = Some(data.clone());
        }
        self.run(&self.alice_home, operation)
            .map_err(CryptoFailure::Engine)
    }
}

#[test]
#[ignore = "native disposable GPGME outbound fixture; invoked by crypto native harness"]
fn native_crypto_outbound_submission_roundtrip() {
    assert_eq!(std::env::consts::OS, "openbsd");
    let path = |name| {
        let path = PathBuf::from(std::env::var_os(name).expect("native fixture path"));
        assert!(path.is_absolute());
        assert_eq!(std::fs::canonicalize(&path).unwrap(), path);
        path
    };
    let fixture = NativeFixture {
        worker: path("OSMAP_CRYPTO_NATIVE_WORKER"),
        engine: path("OSMAP_CRYPTO_NATIVE_ENGINE"),
        alice_home: path("OSMAP_CRYPTO_NATIVE_ALICE_HOME"),
        bob_home: path("OSMAP_CRYPTO_NATIVE_BOB_HOME"),
        alice_fp: std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap(),
        bob_fp: std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap(),
        signed_entity: RefCell::new(None),
    };
    let scratch = fixture.worker.parent().unwrap();
    assert!(scratch.starts_with("/tmp"));
    assert!(scratch
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    assert!(fixture.alice_home.starts_with(scratch));
    assert!(fixture.bob_home.starts_with(scratch));
    assert_ne!(fixture.alice_home, fixture.bob_home);
    let attachment = crate::send::UploadedAttachment::new(
        ComposePolicy::default(),
        "synthetic.bin",
        "application/octet-stream",
        vec![0, 1, 255],
    )
    .unwrap();
    let request = ComposeRequest::new_with_attachments(
        ComposePolicy::default(),
        "bob@example.test",
        "Synthetic outgoing subject",
        "Synthetic café body\nSecond line",
        vec![attachment],
    )
    .unwrap();
    let account = CanonicalUsername::parse("alice@example.test").unwrap();
    let plan = OperationPlan {
        signer_fingerprint: Some(fixture.alice_fp.clone()),
        recipient_fingerprints: vec![fixture.bob_fp.clone()],
        encrypt_to_self: false,
    };
    let prepared = prepare(&fixture, &account, &request, &plan).expect("actual native prepare");
    prepared.validate_for(&account, &request).unwrap();
    assert_eq!(
        prepared.protection(),
        SubmissionProtection::SignedAndEncrypted
    );
    assert!(!std::str::from_utf8(prepared.as_bytes())
        .unwrap()
        .contains("Synthetic café body"));
    let PgpMimeMessage::Encrypted { ciphertext, .. } =
        pgp_mime::classify(prepared.as_bytes(), PgpMimePolicy::default()).unwrap()
    else {
        panic!("encrypted outgoing MIME")
    };
    let decrypted = fixture
        .run(
            &fixture.bob_home,
            &Operation::Decrypt {
                allowed_primary_fingerprints: vec![fixture.bob_fp.clone()],
                ciphertext: ciphertext.clone(),
            },
        )
        .expect("recipient decrypts actual outgoing MIME");
    let PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = pgp_mime::classify(&decrypted.content, PgpMimePolicy::default()).unwrap()
    else {
        panic!("decrypted signed MIME")
    };
    assert_eq!(
        canonical_entity,
        fixture.signed_entity.borrow().as_ref().unwrap().as_slice()
    );
    assert!(canonical_entity.is_ascii());
    let verified = fixture
        .run(
            &fixture.bob_home,
            &Operation::Verify {
                data: canonical_entity.clone(),
                signature: signature.clone(),
            },
        )
        .expect("recipient verifies exact composed entity");
    assert_eq!(verified.signature, SignatureState::Valid);
    assert_eq!(
        verified.primary_fingerprint.as_deref(),
        Some(fixture.alice_fp.as_str())
    );
    let mut tampered = canonical_entity.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        fixture.run(
            &fixture.bob_home,
            &Operation::Verify {
                data: tampered,
                signature,
            }
        ),
        Err(Error::Signature)
    ));
    assert!(
        fixture
            .run(
                &fixture.alice_home,
                &Operation::Decrypt {
                    allowed_primary_fingerprints: vec![fixture.alice_fp.clone()],
                    ciphertext,
                }
            )
            .is_err(),
        "sender cannot decrypt when encrypt-to-self was not selected"
    );
    let raw = std::str::from_utf8(&canonical_entity).unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "INBOX".into(),
        uid: 1,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: canonical_entity.len() as u64,
        header_block: headers.into(),
        body_text: body.into(),
    };
    let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&message)
        .unwrap();
    assert_eq!(
        analysis.selected_plain_text_body.as_deref(),
        Some("Synthetic café body\r\nSecond line")
    );
    let download = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(&message, "1.2")
    .unwrap();
    assert_eq!(download.body, [0, 1, 255]);
    let sent =
        crate::mailbox::MessageAppendRequest::new("Sent", prepared.as_bytes().to_vec()).unwrap();
    assert_eq!(sent.message, prepared.as_bytes());
}
