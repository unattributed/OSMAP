use super::*;
use crate::config::LogLevel;
use crate::identity::MailboxIdentity;
use crate::logging::{EventCategory, LogEvent};
use crate::openpgp_bindings::{AccountBinding, BindingRecord, RecipientBinding, Requirement};
use crate::openpgp_inventory::Inventory;
use crate::protected_message::{CryptoFailure, KeyValidity};
use crate::rendering::RenderingPolicy;

fn session() -> ValidatedSession {
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
            "synthetic validated session",
        ),
    }
}

fn message() -> MessageView {
    MessageView {
        metadata: Some(crate::message_metadata::MessageMetadata {
            version: MessageVersion::new("a".repeat(32), "b".repeat(32)).unwrap(),
            attachment_count: None,
            preview: None,
        }),
        mailbox_name: "INBOX".into(),
        uid: 7,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: 128,
        header_block:
            "From: Alice <alice@example.test>\r\nSubject: synthetic\r\nContent-Type: text/plain\r\n"
                .into(),
        body_text: "Stored body  \t\r\nsecond line\nfinal".into(),
    }
}

fn decision() -> MessageViewDecision {
    MessageViewDecision::Retrieved {
        canonical_username: "bob".into(),
        session_id: session().record.session_id,
        message: Box::new(message()),
    }
}

fn request() -> MessageViewRequest {
    MessageViewRequest::new(MessageViewPolicy::default(), "INBOX", 7).unwrap()
}

struct NeverCrypto;
impl CryptoExecutor for NeverCrypto {
    fn execute(
        &self,
        _: &CanonicalUsername,
        _: &crate::openpgp_crypto::Operation,
    ) -> Result<crate::openpgp_crypto::Outcome, CryptoFailure> {
        panic!("engine must not execute")
    }
}

fn record() -> BindingRecord {
    let mut record = BindingRecord::empty("bob").unwrap();
    record.revision = 1;
    record.account_binding = Some(AccountBinding {
        primary_fingerprint: "B".repeat(40),
        signing_fingerprint: None,
        decrypt_primary_fingerprints: vec!["B".repeat(40)],
    });
    record.recipient_bindings = vec![RecipientBinding {
        address: "alice@example.test".into(),
        primary_fingerprint: "A".repeat(40),
        encryption: Requirement::Optional,
    }];
    record
}

fn inventory(expired: bool, revoked: bool) -> Inventory {
    let key = serde_json::json!({"fingerprint":"A".repeat(40),"algorithm":1,"bits":3072,"created":1,"expires":if expired {100}else{0},"revoked":revoked,"expired":expired,"disabled":false,"invalid":false,"can_encrypt":true,"can_sign":true,"can_certify":true,"can_authenticate":false});
    let data = serde_json::json!({"version":1,"ok":true,"protocol":"openpgp","gpgme_version":"2.0.1","engine_version":"2.4.8","keys":[{"primary":key,"subkeys":[]}]});
    Inventory::parse(&serde_json::to_vec(&data).unwrap()).unwrap()
}

#[test]
fn owned_snapshot_checks_account_session_mailbox_uid_and_stable_version() {
    let source = assemble_source(&message()).unwrap();
    let version = message().metadata.unwrap().version;
    for kind in 0..5 {
        let mut decision = decision();
        let MessageViewDecision::Retrieved {
            canonical_username,
            session_id,
            message,
        } = &mut decision
        else {
            unreachable!()
        };
        match kind {
            0 => *canonical_username = "alice".into(),
            1 => *session_id = "other-session".into(),
            2 => message.mailbox_name = "Sent".into(),
            3 => message.uid = 8,
            _ => message.metadata = None,
        }
        assert_eq!(
            OwnedSnapshot::from_retrieved(
                &session(),
                &request(),
                Some(&version),
                &decision,
                &source
            )
            .unwrap_err(),
            ProtectedError::MessageIdentity
        );
    }
    let decision = decision();
    let snapshot =
        OwnedSnapshot::from_retrieved(&session(), &request(), Some(&version), &decision, &source)
            .unwrap();
    assert_eq!(snapshot.message().uid, 7);
    assert!(!format!("{snapshot:?}").contains("Stored body"));
}

#[test]
fn snapshot_cannot_be_processed_after_switching_account_or_session() {
    let source = assemble_source(&message()).unwrap();
    let decision = decision();
    let snapshot =
        OwnedSnapshot::from_retrieved(&session(), &request(), None, &decision, &source).unwrap();
    let processor = Processor::new(NeverCrypto, RenderingPolicy::default());
    let context = AuthenticationContext::new(
        crate::auth::AuthenticationPolicy::default(),
        "req",
        "127.0.0.1",
        "Synthetic fixture",
    )
    .unwrap();
    for (account, token) in [("alice", "0".repeat(64)), ("bob", "2".repeat(64))] {
        let mut switched = session();
        switched.record.canonical_username = account.into();
        switched.record.session_id = token;
        let bindings = InboundBindings {
            account: CanonicalUsername::parse(account).unwrap(),
            decrypt_primary_fingerprints: Vec::new(),
            signer: None,
        };
        assert_eq!(
            snapshot
                .process(&processor, &context, &switched, &bindings)
                .unwrap_err(),
            ProtectedError::MessageIdentity
        );
    }
}

#[test]
fn stored_source_assembly_preserves_body_bytes_and_enforces_total_limit() {
    let message = message();
    let source = assemble_source(&message).unwrap();
    assert!(source.ends_with(message.body_text.as_bytes()));
    assert_eq!(&source[..source.len() - message.body_text.len()], b"From: Alice <alice@example.test>\r\nSubject: synthetic\r\nContent-Type: text/plain\r\n\r\n");
    let mut oversized = message;
    oversized.body_text = "X".repeat(crate::pgp_mime::MAX_PGP_MIME_BYTES);
    assert_eq!(
        assemble_source(&oversized).unwrap_err(),
        ProtectedError::Mime(crate::pgp_mime::PgpMimeError::SizeLimit)
    );
}

#[test]
fn inbound_binding_derivation_uses_confirmed_record_not_key_uids_or_guesses() {
    let account = CanonicalUsername::parse("bob").unwrap();
    let record = record();
    let inventory = inventory(false, false);
    let bindings = inbound_bindings(&account, &record, Some(&inventory), &message(), 200).unwrap();
    assert_eq!(bindings.decrypt_primary_fingerprints, ["B".repeat(40)]);
    let signer = bindings.signer.unwrap();
    assert_eq!(signer.primary_fingerprint, "A".repeat(40));
    assert_eq!(
        signer.mailbox,
        MailboxIdentity::parse("alice@example.test").unwrap()
    );
    assert_eq!(signer.key_validity, KeyValidity::Current);
    let no_binding = BindingRecord::empty("bob").unwrap();
    assert!(
        inbound_bindings(&account, &no_binding, Some(&inventory), &message(), 200)
            .unwrap()
            .signer
            .is_none()
    );
    assert_eq!(
        inbound_bindings(
            &CanonicalUsername::parse("alice").unwrap(),
            &record,
            Some(&inventory),
            &message(),
            200
        )
        .unwrap_err(),
        ProtectedError::ForeignBindings
    );
}

#[test]
fn ambiguous_or_unbound_sender_never_produces_confirmed_identity_facts() {
    let account = CanonicalUsername::parse("bob").unwrap();
    for from in [
        "From: other@example.test",
        "From: alice@example.test, bob@example.test",
        "From: alice@example.test\r\nFrom: other@example.test",
        "From: malformed",
        "From: Alice@example.test",
    ] {
        let mut message = message();
        message.header_block = format!("{from}\r\nContent-Type: text/plain\r\n");
        assert!(inbound_bindings(
            &account,
            &record(),
            Some(&inventory(false, false)),
            &message,
            200
        )
        .unwrap()
        .signer
        .is_none());
    }
}

#[test]
fn public_inventory_key_validity_is_separate_from_confirmed_binding() {
    let account = CanonicalUsername::parse("bob").unwrap();
    for (inventory, expected) in [
        (None, KeyValidity::Unknown),
        (Some(inventory(true, false)), KeyValidity::Expired),
        (Some(inventory(false, true)), KeyValidity::Revoked),
    ] {
        let bindings =
            inbound_bindings(&account, &record(), inventory.as_ref(), &message(), 200).unwrap();
        assert_eq!(bindings.signer.unwrap().key_validity, expected);
    }
}
