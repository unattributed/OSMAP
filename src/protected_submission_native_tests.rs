//! Native disposable worker proof for outgoing construction and receiving MIME.
//! It does not qualify Client account mapping, HTTP dispatch, or deployment.
use super::*;
use crate::auth::{
    CommandExecution, CommandExecutionError, CommandExecutor, SystemCommandExecutor,
};
use crate::openpgp_crypto::{Error, SignatureState};
use crate::pgp_mime::PgpMimeMessage;
use std::cell::RefCell;
use std::os::unix::fs::DirBuilderExt;
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

#[derive(Default)]
struct EnvelopeCapture {
    calls: RefCell<Vec<(Vec<String>, Vec<u8>)>>,
}
impl CommandExecutor for &EnvelopeCapture {
    fn run_with_stdin_bytes(
        &self,
        _: &str,
        _: &[String],
        _: &[u8],
    ) -> Result<CommandExecution, CommandExecutionError> {
        panic!("native capture requires bounded execution")
    }

    fn run_with_stdin_bytes_timeout(
        &self,
        program: &str,
        args: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandExecution, CommandExecutionError> {
        assert_eq!(program, "/fixture/capture-envelope");
        assert_eq!(
            args.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "-oi",
                "-f",
                "alice@example.test",
                "--",
                "bob@example.test",
                "hidden@example.test",
            ]
        );
        assert!(timeout <= Duration::from_secs(10));
        assert!(!input.is_empty() && input.len() <= 1024 * 1024);
        let mut calls = self.calls.borrow_mut();
        assert!(
            calls.is_empty(),
            "only one captured submission is permitted"
        );
        calls.push((args.to_vec(), input.to_vec()));
        Ok(CommandExecution {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

fn verify_with_only_attached_certificate(
    root: &Path,
    certificate: &[u8],
    entity: &[u8],
    signature: &[u8],
    fingerprint: &str,
) {
    let home = root.join("attached-certificate-recipient");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&home)
        .unwrap();
    assert!(std::fs::read_dir(&home).unwrap().next().is_none());
    let options = vec![
        "--no-options".into(),
        "--homedir".into(),
        home.to_string_lossy().into_owned(),
        "--batch".into(),
        "--no-autostart".into(),
        "--no-auto-key-retrieve".into(),
        "--no-auto-check-trustdb".into(),
    ];
    let mut import = options.clone();
    import.push("--import".into());
    let imported = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/gpg",
            &import,
            certificate,
            Duration::from_secs(10),
            65536,
        )
        .expect("bounded import of only attached public certificate");
    assert_eq!(
        imported.status_code, 0,
        "attached public certificate import"
    );
    let mut packets = options.clone();
    packets.extend(["--list-only".into(), "--list-packets".into()]);
    let public_packets = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/gpg",
            &packets,
            certificate,
            Duration::from_secs(10),
            65536,
        )
        .expect("bounded attached public packet inspection");
    assert_eq!(public_packets.status_code, 0);
    assert_eq!(
        public_packets
            .stdout
            .lines()
            .filter(|line| line.starts_with(":public key packet:"))
            .count(),
        1
    );
    assert!(public_packets
        .stdout
        .lines()
        .any(|line| line.starts_with(":public sub key packet:")));
    assert!(!public_packets.stdout.lines().any(|line| {
        line.starts_with(":secret key packet:") || line.starts_with(":secret sub key packet:")
    }));
    let private = home.join("private-keys-v1.d");
    assert!(!private.exists() || std::fs::read_dir(private).unwrap().next().is_none());
    let signature_path = home.join("message.sig");
    let entity_path = home.join("message.mime");
    std::fs::write(&signature_path, signature).unwrap();
    std::fs::write(&entity_path, entity).unwrap();
    let mut verify = options;
    verify.extend([
        "--status-fd".into(),
        "1".into(),
        "--verify".into(),
        signature_path.to_string_lossy().into_owned(),
        entity_path.to_string_lossy().into_owned(),
    ]);
    let verified = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/gpg",
            &verify,
            &[],
            Duration::from_secs(10),
            65536,
        )
        .expect("bounded independent verification using attached certificate");
    assert_eq!(
        verified.status_code, 0,
        "attached-certificate signature verification"
    );
    assert!(
        verified.stdout.lines().any(|line| {
            line.strip_prefix("[GNUPG:] VALIDSIG ")
                .and_then(|value| value.split_whitespace().next())
                == Some(fingerprint)
        }),
        "independent signature must identify the exact sender primary"
    );
    assert!(!home.join("S.gpg-agent").exists());
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
    let export_state = scratch.join("outbound-public-admin-state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&export_state)
        .unwrap();
    let account = CanonicalUsername::parse("alice@example.test").unwrap();
    let public_admin = crate::openpgp_public_admin::PublicAdminStore::from_operator_mappings(
        export_state,
        path("OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER"),
        fixture.engine.clone(),
        vec![crate::openpgp_public_admin::AccountHome {
            account: account.clone(),
            home: fixture.alice_home.clone(),
        }],
    )
    .unwrap();
    let before_public = std::fs::read(fixture.alice_home.join("pubring.kbx")).unwrap();
    let snapshot = public_admin
        .snapshot(&account, Instant::now() + Duration::from_secs(10))
        .unwrap();
    let custody = || {
        let mut paths = vec![
            fixture.alice_home.join("pubring.kbx"),
            fixture.alice_home.join("trustdb.gpg"),
        ];
        paths.extend(
            std::fs::read_dir(fixture.alice_home.join("private-keys-v1.d"))
                .unwrap()
                .map(|entry| entry.unwrap().path()),
        );
        paths
            .into_iter()
            .map(|path| {
                let digest = Sha256::digest(std::fs::read(&path).unwrap()).to_vec();
                (path, digest)
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let custody_before = custody();
    let certificate = public_admin
        .export_public(
            &account,
            &snapshot.revision,
            &fixture.alice_fp,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    assert_eq!(certificate.primary_fingerprint, fixture.alice_fp);
    assert_eq!(certificate.revision, snapshot.revision);
    let subkey = &snapshot
        .inventory
        .keys()
        .unwrap()
        .iter()
        .find(|key| key.primary.fingerprint == fixture.alice_fp)
        .unwrap()
        .subkeys[0]
        .fingerprint;
    assert!(public_admin
        .export_public(
            &account,
            &snapshot.revision,
            subkey,
            Instant::now() + Duration::from_secs(10)
        )
        .is_err());
    let missing = "F".repeat(40);
    assert!(!snapshot
        .inventory
        .keys()
        .unwrap()
        .iter()
        .any(|key| key.primary.fingerprint == missing));
    assert!(public_admin
        .export_public(
            &account,
            &snapshot.revision,
            &missing,
            Instant::now() + Duration::from_secs(10)
        )
        .is_err());
    assert_eq!(
        custody(),
        custody_before,
        "public export preserves public/trust/private file hashes"
    );
    assert_eq!(
        std::fs::read(fixture.alice_home.join("pubring.kbx")).unwrap(),
        before_public
    );
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
    let plan = OperationPlan {
        signer_fingerprint: Some(fixture.alice_fp.clone()),
        recipient_fingerprints: vec![fixture.bob_fp.clone()],
        encrypt_to_self: false,
    };
    let prepared = prepare_with_certificate(
        &fixture,
        &account,
        &request,
        &plan,
        Some(&certificate.certificate),
    )
    .expect("actual native prepare with exported sender certificate");
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
    let independent_signature = signature.clone();
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
    .download_from_message(
        &message,
        &analysis
            .attachments
            .iter()
            .find(|attachment| attachment.filename.as_deref() == Some("synthetic.bin"))
            .unwrap()
            .part_path,
    )
    .unwrap();
    assert_eq!(download.body, [0, 1, 255]);
    let certificate_parts = analysis
        .attachments
        .iter()
        .filter(|attachment| attachment.filename.as_deref() == Some("openpgp-public-key.asc"))
        .collect::<Vec<_>>();
    assert_eq!(certificate_parts.len(), 1);
    let attached = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(&message, &certificate_parts[0].part_path)
    .unwrap();
    assert_eq!(attached.content_type, "application/pgp-keys");
    assert_eq!(attached.body, certificate.certificate);
    verify_with_only_attached_certificate(
        scratch,
        &attached.body,
        &canonical_entity,
        &independent_signature,
        &fixture.alice_fp,
    );
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
    // Inspect only public packets, with no keys or agent in this fresh home.
    // Header privacy alone cannot establish that PKESK recipient IDs are hidden.
    let packet_home = scratch.join("packet-inspection");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&packet_home)
        .unwrap();
    let packets = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/gpg",
            &[
                "--no-options".into(),
                "--homedir".into(),
                packet_home.to_string_lossy().into_owned(),
                "--batch".into(),
                "--no-autostart".into(),
                "--list-only".into(),
                "--list-packets".into(),
            ],
            &ciphertext,
            Duration::from_secs(10),
            65536,
        )
        .expect("bounded public packet inspection");
    assert_eq!(packets.status_code, 0, "public packet inspection refused");
    let recipient_packets = packets
        .stdout
        .lines()
        .filter(|line| line.starts_with(":pubkey enc packet:"))
        .collect::<Vec<_>>();
    assert_eq!(recipient_packets.len(), 2, "two intended recipient packets");
    for packet in recipient_packets {
        assert_eq!(
            packet
                .split_once("keyid ")
                .and_then(|(_, value)| value.split_whitespace().next()),
            Some("0000000000000000"),
            "every actual PKESK recipient key ID must be hidden"
        );
    }
    println!("encrypted_bcc_pkesk_count=2 all_recipient_keyids_hidden=PASS");
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

    // Exercise the production backend's exact prepared-message/argv boundary.
    // Only its command executor is substituted; no process or SMTP is invoked.
    let capture = EnvelopeCapture::default();
    use crate::send::SubmissionBackend;
    crate::send::SendmailSubmissionBackend::new(&capture, "/fixture/capture-envelope")
        .submit_prepared_message(account.as_str(), &hidden_request, &hidden)
        .unwrap();
    let captures = capture.calls.borrow();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].1, sent.message);
    assert_eq!(
        captures[0].0.join("\n"),
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
