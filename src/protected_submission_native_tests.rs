//! Native disposable worker proof for outgoing construction and receiving MIME.
//! It does not qualify Client account mapping, HTTP dispatch, or deployment.
use super::*;
use crate::openpgp_crypto::{Error, SignatureState};
use crate::pgp_mime::PgpMimeMessage;
use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

struct NativeFixture {
    worker: PathBuf,
    engine: PathBuf,
    alice_home: PathBuf,
    bob_home: PathBuf,
    hidden_home: PathBuf,
    alice_fp: String,
    bob_fp: String,
    hidden_fp: String,
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
        hidden_home: path("OSMAP_CRYPTO_NATIVE_HIDDEN_HOME"),
        alice_fp: std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap(),
        bob_fp: std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap(),
        hidden_fp: std::env::var("OSMAP_CRYPTO_NATIVE_HIDDEN_FP").unwrap(),
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
    assert!(fixture.hidden_home.starts_with(scratch));
    assert_ne!(fixture.hidden_home, fixture.alice_home);
    assert_ne!(fixture.hidden_home, fixture.bob_home);
    assert_ne!(fixture.hidden_fp, fixture.alice_fp);
    assert_ne!(fixture.hidden_fp, fixture.bob_fp);
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

    // Distinct visible and hidden recipients must receive one identical private
    // wire entity. The caller's Bcc remains only in the sendmail envelope.
    let hidden_request = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        "bob@example.test",
        "",
        "hidden@example.test",
        "Synthetic hidden recipient",
        "Synthetic private Bcc body",
        Vec::new(),
    )
    .unwrap();
    let mut hidden_plan = OperationPlan {
        signer_fingerprint: None,
        recipient_fingerprints: vec![fixture.bob_fp.clone(), fixture.hidden_fp.clone()],
        encrypt_to_self: false,
    };
    let hidden = prepare(&fixture, &account, &hidden_request, &hidden_plan).unwrap();
    let hidden_wire = std::str::from_utf8(hidden.as_bytes()).unwrap();
    assert!(!hidden_wire.contains("hidden@example.test"));
    assert!(!hidden_wire.to_ascii_lowercase().contains("\r\nbcc:"));
    assert!(!hidden_wire.contains("Synthetic private Bcc body"));
    let PgpMimeMessage::Encrypted { ciphertext, .. } =
        pgp_mime::classify(hidden.as_bytes(), PgpMimePolicy::default()).unwrap()
    else {
        panic!("encrypted hidden-recipient MIME")
    };
    let mut clear = None;
    for (home, fp) in [
        (&fixture.bob_home, &fixture.bob_fp),
        (&fixture.hidden_home, &fixture.hidden_fp),
    ] {
        let outcome = fixture
            .run(
                home,
                &Operation::Decrypt {
                    allowed_primary_fingerprints: vec![fp.clone()],
                    ciphertext: ciphertext.clone(),
                },
            )
            .expect("both intended recipients decrypt the same Bcc ciphertext");
        assert_eq!(outcome.primary_fingerprint.as_ref(), Some(fp));
        let body = std::str::from_utf8(&outcome.content).unwrap();
        assert!(!body.contains("hidden@example.test"));
        assert!(!body.to_ascii_lowercase().contains("\r\nbcc:"));
        let (headers, encoded_body) = body.split_once("\r\n\r\n").unwrap();
        let message = crate::mailbox::MessageView {
            metadata: None,
            mailbox_name: "INBOX".into(),
            uid: 1,
            flags: Vec::new(),
            date_received: String::new(),
            size_virtual: outcome.content.len() as u64,
            header_block: headers.into(),
            body_text: encoded_body.into(),
        };
        let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
            .analyze_message(&message)
            .unwrap();
        assert_eq!(
            analysis.selected_plain_text_body.as_deref(),
            Some("Synthetic private Bcc body")
        );
        if let Some(ref previous) = clear {
            assert_eq!(&outcome.content, previous);
        }
        clear = Some(outcome.content);
    }
    // Alice's signing positive above and self-decrypt positive below rule out a
    // locked private-key agent masquerading as the outsider negative.
    let outsider_refusal = match fixture.run(
        &fixture.alice_home,
        &Operation::Decrypt {
            allowed_primary_fingerprints: vec![fixture.alice_fp.clone()],
            ciphertext: ciphertext.clone(),
        },
    ) {
        Ok(_) => panic!("excluded sender obtained a plaintext outcome"),
        Err(error) => error,
    };
    println!("excluded_sender_refusal={outsider_refusal:?}");
    // The native worker maps non-NO_SECKEY GPG refusal codes to Unavailable.
    // This paired negative establishes no returned plaintext, not the exact
    // engine cause. Alice must also pass self decryption below before PASS.
    assert!(matches!(
        outsider_refusal,
        Error::MissingKey | Error::Unavailable
    ));
    std::fs::write(scratch.join("bcc-ciphertext.asc"), ciphertext).unwrap();
    let sent =
        crate::mailbox::MessageAppendRequest::new("Sent", hidden.as_bytes().to_vec()).unwrap();
    assert_eq!(sent.message, hidden.as_bytes());
    assert!(!std::str::from_utf8(&sent.message)
        .unwrap()
        .contains("hidden@example.test"));

    // The real backend executes a disposable capture command, never sendmail or
    // SMTP. Capture proves envelope arguments and exact emitted/Sent bytes only.
    let capture = scratch.join("capture-envelope");
    std::fs::write(&capture, concat!(
        "#!/usr/local/bin/python3\n",
        "import pathlib, sys\n",
        "assert sys.argv[1:] == ['-oi', '-f', 'alice@example.test', '--', 'bob@example.test', 'hidden@example.test']\n",
        "data = sys.stdin.buffer.read(1048577)\n",
        "assert 0 < len(data) <= 1048576\n",
        "assert b'hidden@example.test' not in data and b'\\r\\nbcc:' not in data.lower()\n",
        "root = pathlib.Path(__file__).parent\n",
        "(root / 'captured-wire').write_bytes(data)\n",
        "(root / 'captured-envelope').write_text('\\n'.join(sys.argv[1:]))\n",
    )).unwrap();
    std::fs::set_permissions(&capture, std::fs::Permissions::from_mode(0o700)).unwrap();
    use crate::send::SubmissionBackend;
    crate::send::SendmailSubmissionBackend::new(crate::auth::SystemCommandExecutor, capture)
        .submit_prepared_message(account.as_str(), &hidden_request, &hidden)
        .unwrap();
    assert_eq!(
        std::fs::read(scratch.join("captured-wire")).unwrap(),
        sent.message
    );
    assert_eq!(
        std::fs::read_to_string(scratch.join("captured-envelope")).unwrap(),
        "-oi\n-f\nalice@example.test\n--\nbob@example.test\nhidden@example.test"
    );

    hidden_plan
        .recipient_fingerprints
        .push(fixture.alice_fp.clone());
    hidden_plan.encrypt_to_self = true;
    let self_prepared = prepare(&fixture, &account, &hidden_request, &hidden_plan).unwrap();
    let PgpMimeMessage::Encrypted { ciphertext, .. } =
        pgp_mime::classify(self_prepared.as_bytes(), PgpMimePolicy::default()).unwrap()
    else {
        panic!("explicit self encrypted MIME")
    };
    let self_clear = fixture
        .run(
            &fixture.alice_home,
            &Operation::Decrypt {
                allowed_primary_fingerprints: vec![fixture.alice_fp.clone()],
                ciphertext,
            },
        )
        .expect("sender decrypts only after explicit self selection");
    assert_eq!(self_clear.content, clear.unwrap());
    println!("encrypted_bcc_distinct_recipients=PASS excluded_sender_no_plaintext=PASS explicit_self_decrypt=PASS envelope_capture=PASS wire_sent_privacy=PASS");
}
