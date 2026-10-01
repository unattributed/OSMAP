use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-protected-send-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct CountSubmission(Cell<usize>);
impl crate::send::SubmissionBackend for CountSubmission {
    fn submit_message(
        &self,
        _account: &str,
        _request: &ComposeRequest,
    ) -> Result<(), crate::send::SubmissionBackendError> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

#[test]
fn protected_send_stale_or_missing_inventory_does_not_dispatch_or_consume_intent() {
    for (revision, expected_reason) in [
        (None, "openpgp_binding_changed"),
        (Some(1), "openpgp_binding_changed"),
        (Some(0), "openpgp_inventory_unavailable"),
    ] {
        let scratch = Scratch::new();
        let gateway = RuntimeBrowserGateway::for_test(&scratch.0);
        let backend = CountSubmission(Cell::new(0));
        let submission = SubmissionService::new(&backend);
        let append = StubSentAppendBackend::default();
        let now = SystemTimeProvider.unix_timestamp();
        let intent = crate::send_journal::mint_intent(now).unwrap();
        let request = BrowserSendRequest {
            send_intent: &intent,
            draft_id: None,
            draft_revision: None,
            recipients: "bob@example.com",
            cc_recipients: "",
            bcc_recipients: "",
            subject: "Synthetic protected send",
            body: "Synthetic authoring body",
            body_format: crate::compose_format::BodyFormat::Plain,
            attachments: &[],
            reply_thread: None,
            protection: crate::send::ProtectionIntent {
                sign: true,
                encrypt: false,
                encrypt_to_self: false,
                binding_revision: revision,
            },
        };
        let outcome = gateway.send_message_with_backends(
            &test_context(),
            &validated_session(),
            request,
            &submission,
            &append,
        );
        assert!(
            matches!(outcome.decision, BrowserSendDecision::Denied { ref public_reason, .. }
            if public_reason == expected_reason)
        );
        assert_eq!(backend.0.get(), 0);
        assert!(append.calls.borrow().is_empty());
        assert!(
            crate::send_journal::SendJournal::new(gateway.settings_dir.join("send-journal"))
                .receipt("alice@example.com", &intent, now)
                .unwrap()
                .is_none()
        );
    }
}

impl crate::send::SubmissionBackend for &CountSubmission {
    fn submit_message(
        &self,
        account: &str,
        request: &ComposeRequest,
    ) -> Result<(), crate::send::SubmissionBackendError> {
        (**self).submit_message(account, request)
    }
}

struct SyntheticSigner;
impl crate::protected_message::CryptoExecutor for SyntheticSigner {
    fn execute(
        &self,
        _account: &crate::identity::CanonicalUsername,
        operation: &crate::openpgp_crypto::Operation,
    ) -> Result<crate::openpgp_crypto::Outcome, crate::protected_message::CryptoFailure> {
        let crate::openpgp_crypto::Operation::Sign {
            signer_fingerprint, ..
        } = operation
        else {
            panic!("synthetic sign only")
        };
        Ok(crate::openpgp_crypto::Outcome {
            operation: "sign".into(),
            content:
                b"-----BEGIN PGP SIGNATURE-----\n\nZml4dHVyZQ==\n-----END PGP SIGNATURE-----\n"
                    .to_vec(),
            signer_fingerprint: Some(signer_fingerprint.clone()),
            primary_fingerprint: Some(signer_fingerprint.clone()),
            signature: crate::openpgp_crypto::SignatureState::Valid,
            hash_algorithm: Some(8),
        })
    }
}

#[test]
fn sent_stores_exact_protected_submission_bytes_and_never_rebuilds_plaintext() {
    let account = crate::identity::CanonicalUsername::parse("alice@example.com").unwrap();
    let mut request = ComposeRequest::new(
        ComposePolicy::default(),
        "bob@example.com",
        "Synthetic protected subject",
        "Synthetic protected body",
    )
    .unwrap();
    request.protection = crate::send::ProtectionIntent {
        sign: true,
        encrypt: false,
        encrypt_to_self: false,
        binding_revision: Some(7),
    };
    let prepared = crate::protected_submission::prepare(
        &SyntheticSigner,
        &account,
        &request,
        &crate::openpgp_bindings::OperationPlan {
            signer_fingerprint: Some("A".repeat(40)),
            recipient_fingerprints: Vec::new(),
            encrypt_to_self: false,
        },
    )
    .unwrap();
    let backend = StubSentAppendBackend::default();
    let (stored, _) = store_prepared_sent_copy(
        &test_context(),
        account.as_str(),
        &request,
        &prepared,
        &backend,
    );
    assert!(stored);
    let calls = backend.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.message, prepared.as_bytes());
    assert_ne!(
        calls[0].1.message,
        crate::send::build_submission_message(account.as_str(), &request).unwrap()
    );
    assert!(matches!(
        crate::pgp_mime::classify(
            &calls[0].1.message,
            crate::pgp_mime::PgpMimePolicy::default()
        )
        .unwrap(),
        crate::pgp_mime::PgpMimeMessage::Signed { .. }
    ));
}
