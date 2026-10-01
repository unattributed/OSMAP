//! Explicit native qualification with disposable operator-harness key homes.
//! This does not qualify a deployed service or authenticated browser routes.

use super::*;
use crate::openpgp_crypto::{Error, Operation, Outcome, SignatureState};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const NATIVE_ENTITY: &[u8] = concat!(
    "Content-Type: multipart/mixed; boundary=synthetic-inner\r\n",
    "\r\n",
    "--synthetic-inner\r\n",
    "Content-Type: text/plain; charset=utf-8\r\n",
    "Content-Transfer-Encoding: quoted-printable\r\n",
    "\r\n",
    "Synthetic signed content with trailing =20\r\n",
    "--synthetic-inner\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "Content-Transfer-Encoding: 7bit\r\n",
    "\r\n",
    "<p>Visible synthetic text</p><script>HOSTILE_FIXTURE</script>",
    "<img src=\"https://fixture.invalid/track\" onerror=\"HOSTILE_FIXTURE\">\r\n",
    "--synthetic-inner\r\n",
    "Content-Type: application/octet-stream\r\n",
    "Content-Disposition: attachment; filename=synthetic.bin\r\n",
    "Content-Transfer-Encoding: base64\r\n",
    "\r\n",
    "AAH/\r\n",
    "--synthetic-inner--\r\n",
)
.as_bytes();

struct Fixture {
    worker: PathBuf,
    engine: PathBuf,
    alice_home: PathBuf,
    bob_home: PathBuf,
    alice_fp: String,
    bob_fp: String,
}

impl Fixture {
    fn from_environment() -> Self {
        assert_eq!(
            std::env::consts::OS,
            "openbsd",
            "requires native OpenBSD fixture"
        );
        let path = |name| {
            let path = PathBuf::from(std::env::var_os(name).expect("native fixture path required"));
            assert!(path.is_absolute());
            assert_eq!(
                std::fs::canonicalize(&path).unwrap(),
                path,
                "fixture path must be canonical"
            );
            path
        };
        let fingerprint = |name| {
            let fp = std::env::var(name).expect("disposable fixture fingerprint required");
            assert!(crate::openpgp_crypto::full_fingerprint(&fp));
            fp
        };
        let fixture = Self {
            worker: path("OSMAP_CRYPTO_NATIVE_WORKER"),
            engine: path("OSMAP_CRYPTO_NATIVE_ENGINE"),
            alice_home: path("OSMAP_CRYPTO_NATIVE_ALICE_HOME"),
            bob_home: path("OSMAP_CRYPTO_NATIVE_BOB_HOME"),
            alice_fp: fingerprint("OSMAP_CRYPTO_NATIVE_ALICE_FP"),
            bob_fp: fingerprint("OSMAP_CRYPTO_NATIVE_BOB_FP"),
        };
        assert_ne!(fixture.alice_home, fixture.bob_home);
        assert_ne!(fixture.alice_fp, fixture.bob_fp);
        fixture
    }

    fn run(&self, home: &Path, operation: &Operation) -> Result<Outcome, Error> {
        crate::openpgp_crypto_process::execute(
            &self.worker,
            &self.engine,
            home,
            operation,
            Instant::now() + Duration::from_secs(10),
        )
    }

    fn verify_wire(&self, home: &Path, wire: &[u8]) -> Result<Outcome, Error> {
        let PgpMimeMessage::Signed {
            canonical_entity,
            signature,
            ..
        } = classify(wire, PgpMimePolicy::default()).unwrap()
        else {
            panic!("expected supported signed MIME");
        };
        self.run(
            home,
            &Operation::Verify {
                data: canonical_entity,
                signature,
            },
        )
    }
}

#[test]
#[ignore = "requires disposable native OpenBSD GPGME worker/engine and two key homes"]
fn native_crypto_mime_roundtrip() {
    let fixture = Fixture::from_environment();
    let policy = PgpMimePolicy::default();
    let signature = fixture
        .run(
            &fixture.alice_home,
            &Operation::Sign {
                signer_fingerprint: fixture.alice_fp.clone(),
                data: NATIVE_ENTITY.to_vec(),
            },
        )
        .expect("native detached signature must succeed");
    assert_eq!(signature.signature, SignatureState::Valid);
    assert_eq!(
        signature.primary_fingerprint.as_deref(),
        Some(fixture.alice_fp.as_str())
    );
    let digest = match signature.hash_algorithm {
        Some(8) => SignatureDigest::Sha256,
        Some(10) => SignatureDigest::Sha512,
        _ => panic!("unsupported native signature digest"),
    };
    let signed = build_signed(
        NATIVE_ENTITY,
        &signature.content,
        digest,
        "native-signed",
        policy,
    )
    .unwrap();
    let verified = fixture
        .verify_wire(&fixture.bob_home, &signed)
        .expect("receiver independently verifies emitted MIME");
    assert_eq!(verified.signature, SignatureState::Valid);
    assert_eq!(
        verified.primary_fingerprint.as_deref(),
        Some(fixture.alice_fp.as_str())
    );
    assert_eq!(verified.hash_algorithm, signature.hash_algorithm);

    let mut tampered = signed.clone();
    let position = tampered
        .windows(b"Synthetic signed".len())
        .position(|w| w == b"Synthetic signed")
        .unwrap();
    tampered[position] = b'X';
    assert!(matches!(
        fixture.verify_wire(&fixture.bob_home, &tampered),
        Err(Error::Signature)
    ));

    // Wire builders produce CRLF without changing the independently signed
    // entity, and LF Maildir storage can be canonicalized back identically.
    let lf = String::from_utf8(signed.clone())
        .unwrap()
        .replace("\r\n", "\n")
        .into_bytes();
    assert_eq!(
        fixture
            .verify_wire(&fixture.bob_home, &lf)
            .unwrap()
            .signature,
        SignatureState::Valid
    );

    let encrypted = fixture
        .run(
            &fixture.alice_home,
            &Operation::Encrypt {
                recipient_fingerprints: vec![fixture.bob_fp.clone(), fixture.alice_fp.clone()],
                data: signed.clone(),
            },
        )
        .expect("native sign-then-encrypt must succeed");
    let wire = build_encrypted(&encrypted.content, "native-encrypted", policy).unwrap();
    let PgpMimeMessage::Encrypted { ciphertext, .. } = classify(&wire, policy).unwrap() else {
        panic!("expected encrypted MIME")
    };
    let mut decrypted_entity = None;
    for (home, fp) in [
        (&fixture.alice_home, &fixture.alice_fp),
        (&fixture.bob_home, &fixture.bob_fp),
    ] {
        let decrypted = fixture
            .run(
                home,
                &Operation::Decrypt {
                    allowed_primary_fingerprints: vec![fp.clone()],
                    ciphertext: ciphertext.clone(),
                },
            )
            .expect("intended recipient and encrypt-to-self must decrypt");
        assert_eq!(decrypted.content, signed);
        assert_eq!(decrypted.primary_fingerprint.as_deref(), Some(fp.as_str()));
        assert_eq!(
            fixture
                .verify_wire(home, &decrypted.content)
                .unwrap()
                .signature,
            SignatureState::Valid
        );
        let PgpMimeMessage::Signed {
            canonical_entity, ..
        } = classify(&decrypted.content, policy).unwrap()
        else {
            panic!("decrypted signed MIME")
        };
        decrypted_entity = Some(canonical_entity);
    }

    let recipient_only = fixture
        .run(
            &fixture.alice_home,
            &Operation::Encrypt {
                recipient_fingerprints: vec![fixture.bob_fp.clone()],
                data: signed,
            },
        )
        .unwrap();
    assert!(
        fixture
            .run(
                &fixture.alice_home,
                &Operation::Decrypt {
                    allowed_primary_fingerprints: vec![fixture.alice_fp.clone()],
                    ciphertext: recipient_only.content,
                }
            )
            .is_err(),
        "nonrecipient private key must not decrypt"
    );

    // The plaintext derived by the real decrypt/verify chain crosses existing
    // MIME selection and HTML sanitization again; crypto does not confer safety.
    let decrypted_entity = decrypted_entity.unwrap();
    let raw = std::str::from_utf8(&decrypted_entity).unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "INBOX".into(),
        uid: 1,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: NATIVE_ENTITY.len() as u64,
        header_block: format!("{headers}\r\n"),
        body_text: body.into(),
    };
    let analyzer = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default());
    let analysis = analyzer.analyze_message(&message).unwrap();
    let html = analysis
        .selected_html_body
        .as_deref()
        .expect("synthetic hostile HTML selected for sanitizer");
    let sanitized = crate::rendering_html::sanitize_html_body(
        crate::rendering_html::HtmlRenderingPolicy::default(),
        html,
        analysis.selected_plain_text_body.as_deref(),
        65536,
    )
    .unwrap()
    .expect("safe visible output remains");
    assert!(sanitized.body_html.contains("Visible synthetic text"));
    for unsafe_text in [
        "<script",
        "<img",
        "onerror",
        "HOSTILE_FIXTURE",
        "fixture.invalid",
    ] {
        assert!(!sanitized.body_html.contains(unsafe_text));
    }
    let attachment = analyzer
        .find_attachment_part(&message, "1.3")
        .unwrap()
        .unwrap();
    assert_eq!(
        attachment.metadata.filename.as_deref(),
        Some("synthetic.bin")
    );
    assert_eq!(attachment.body_text, "AAH/");
}
