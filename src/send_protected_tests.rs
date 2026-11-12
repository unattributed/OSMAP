use super::*;
use crate::openpgp_crypto::{Operation, Outcome, SignatureState};
use crate::protected_message::{CryptoExecutor, CryptoFailure};

struct SyntheticCrypto;
impl CryptoExecutor for SyntheticCrypto {
    fn execute(
        &self,
        _account: &crate::identity::CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        let Operation::Sign {
            signer_fingerprint, ..
        } = operation
        else {
            panic!("test sign only")
        };
        Ok(Outcome {
            operation: "sign".into(),
            content:
                b"-----BEGIN PGP SIGNATURE-----\n\nZml4dHVyZQ==\n-----END PGP SIGNATURE-----\n"
                    .to_vec(),
            signer_fingerprint: Some(signer_fingerprint.clone()),
            primary_fingerprint: Some(signer_fingerprint.clone()),
            signature: SignatureState::Valid,
            hash_algorithm: Some(8),
        })
    }
}

fn prepared_request() -> (
    ComposeRequest,
    crate::protected_submission::PreparedSubmission,
) {
    let mut request = ComposeRequest::new(
        ComposePolicy::default(),
        "bob@example.com",
        "Synthetic protected subject",
        "Synthetic protected body",
    )
    .unwrap();
    request.protection = ProtectionIntent {
        sign: true,
        encrypt: false,
        encrypt_to_self: false,
        binding_revision: Some(7),
    };
    let account = crate::identity::CanonicalUsername::parse("alice@example.com").unwrap();
    let prepared = crate::protected_submission::prepare(
        &SyntheticCrypto,
        &account,
        &request,
        &crate::openpgp_bindings::OperationPlan {
            signer_fingerprint: Some("A".repeat(40)),
            recipient_fingerprints: Vec::new(),
            encrypt_to_self: false,
        },
    )
    .unwrap();
    (request, prepared)
}

#[test]
fn sendmail_uses_exact_prepared_bytes_and_refuses_changed_envelope_without_command() {
    let state = Rc::new(RefCell::new(StubCommandExecutor::success(
        CommandExecution {
            status_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    )));
    let backend = SendmailSubmissionBackend::new(state.clone(), "/synthetic/sendmail");
    let (mut request, prepared) = prepared_request();
    backend
        .submit_prepared_message("alice@example.com", &request, &prepared)
        .unwrap();
    assert_eq!(
        state.borrow().stdin_data.as_deref(),
        Some(prepared.as_bytes())
    );
    assert_eq!(
        state.borrow().args.as_ref().unwrap(),
        &sendmail_args("alice@example.com", &request)
    );
    state.borrow_mut().stdin_data = None;
    request.recipients.push("other@example.com".into());
    assert!(backend
        .submit_prepared_message("alice@example.com", &request, &prepared)
        .is_err());
    assert!(state.borrow().stdin_data.is_none());
}

#[test]
fn legacy_submission_path_and_nonprepared_backend_never_downgrade_protected_request() {
    let backend = FailingSubmissionBackend {
        calls: std::cell::Cell::new(0),
    };
    let (request, prepared) = prepared_request();
    assert!(backend
        .submit_prepared_message("alice@example.com", &request, &prepared)
        .is_err());
    assert_eq!(backend.calls.get(), 0);
    let service = SubmissionService::new(backend);
    let outcome = service.submit_for_validated_session(
        &test_context(),
        &validated_session_fixture(),
        &request,
    );
    assert!(matches!(
        outcome.decision,
        SubmissionDecision::Denied { .. }
    ));
    assert_eq!(service.backend.calls.get(), 0);
    let mut changed = request;
    changed.protection.binding_revision = Some(8);
    let outcome = service.submit_prepared_for_validated_session(
        &test_context(),
        &validated_session_fixture(),
        &changed,
        &prepared,
    );
    assert!(matches!(
        outcome.decision,
        SubmissionDecision::Denied { .. }
    ));
    assert_eq!(service.backend.calls.get(), 0);
}
