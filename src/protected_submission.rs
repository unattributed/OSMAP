//! Transient RFC3156 construction. The caller supplies an account-bound plan
//! from the trusted binding store; neither this adapter nor a browser preflight
//! grants helper key authority. Dispatch and Sent consume the same final bytes.
use crate::compose_format::BodyFormat;
use crate::identity::{CanonicalUsername, MailboxIdentity};
use crate::openpgp_bindings::OperationPlan;
use crate::openpgp_crypto::{Operation, Outcome};
use crate::pgp_mime::{self, PgpMimeError, PgpMimePolicy, SignatureDigest};
use crate::protected_message::{CryptoExecutor, CryptoFailure};
use crate::send::{ComposePolicy, ComposeRequest};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionProtection {
    Ordinary,
    Signed,
    Encrypted,
    SignedAndEncrypted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionError {
    InvalidAccount,
    InvalidCompose,
    InvalidPlan,
    EncryptedBccUnqualified,
    RequestMismatch,
    RandomUnavailable,
    SizeLimit,
    Mime(PgpMimeError),
    Crypto(CryptoFailure),
    InvalidOutcome,
    BindingUnavailable,
    StaleBinding,
    InventoryUnavailable,
    ProtectionBlocked(Option<crate::openpgp_bindings::BlockReason>),
}

/// Reevaluation consumes trusted account-store state and optional fresh public
/// inventory. The caller obtains both immediately before this invocation.
pub fn prepare_for_delivery<E: CryptoExecutor>(
    executor: &E,
    account: &CanonicalUsername,
    request: &ComposeRequest,
    record: &crate::openpgp_bindings::BindingRecord,
    inventory: Option<&crate::openpgp_inventory::Inventory>,
    now: u64,
) -> Result<PreparedSubmission, SubmissionError> {
    record
        .ensure_account(account.as_str())
        .map_err(|_| SubmissionError::BindingUnavailable)?;
    let intent = request.protection;
    let selected = intent.sign || intent.encrypt || intent.encrypt_to_self;
    if selected && intent.binding_revision.is_none()
        || intent
            .binding_revision
            .is_some_and(|revision| revision != record.revision)
        || record.revision != 0 && intent.binding_revision.is_none()
    {
        return Err(SubmissionError::StaleBinding);
    }
    if selected && inventory.and_then(|i| i.keys()).is_none() {
        return Err(SubmissionError::InventoryUnavailable);
    }
    // Missing inventory stays explicitly unavailable. It can establish no key
    // capability; policy reevaluation can still refuse plaintext when required.
    let unavailable = crate::openpgp_inventory::Inventory::parse(
        br#"{"version":1,"ok":false,"error":"inventory_unavailable"}"#,
    )
    .map_err(|_| SubmissionError::InventoryUnavailable)?;
    let readiness = crate::openpgp_bindings::evaluate(
        account.as_str(),
        record,
        inventory.unwrap_or(&unavailable),
        crate::openpgp_bindings::Recipients {
            to: &request.recipients,
            cc: &request.cc_recipients,
            bcc: &request.bcc_recipients,
        },
        intent.selections(),
        now,
    )
    .map_err(|_| SubmissionError::BindingUnavailable)?;
    let plan = readiness.plan.ok_or(SubmissionError::ProtectionBlocked(
        readiness.reasons.first().copied(),
    ))?;
    prepare(executor, account, request, &plan)
}

pub(crate) struct UnavailableCrypto;
impl CryptoExecutor for UnavailableCrypto {
    fn execute(
        &self,
        _account: &CanonicalUsername,
        _operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        Err(CryptoFailure::Transport)
    }
}

pub struct PreparedSubmission {
    bytes: Vec<u8>,
    account: CanonicalUsername,
    request_digest: [u8; 32],
    protection: SubmissionProtection,
}

impl PreparedSubmission {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn protection(&self) -> SubmissionProtection {
        self.protection
    }

    /// Check routing/account/request identity before using these exact bytes
    /// with the submission envelope. Bcc participates in the digest even though
    /// it is deliberately absent from the RFC5322 headers.
    pub fn validate_for(
        &self,
        account: &CanonicalUsername,
        request: &ComposeRequest,
    ) -> Result<(), SubmissionError> {
        let raw = validated_message(account, request)?;
        if account != &self.account || request_digest(&raw, request) != self.request_digest {
            return Err(SubmissionError::RequestMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Debug for PreparedSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSubmission")
            .field("bytes", &self.bytes.len())
            .field("protection", &self.protection)
            .finish()
    }
}

pub fn prepare<E: CryptoExecutor>(
    executor: &E,
    account: &CanonicalUsername,
    request: &ComposeRequest,
    plan: &OperationPlan,
) -> Result<PreparedSubmission, SubmissionError> {
    let ordinary = validated_message(account, request)?;
    validate_plan(request, plan)?;
    let request_digest = request_digest(&ordinary, request);
    let sign = plan.signer_fingerprint.is_some();
    let encrypt = !plan.recipient_fingerprints.is_empty();
    if !sign && !encrypt {
        return Ok(PreparedSubmission {
            bytes: ordinary,
            account: account.clone(),
            request_digest,
            protection: SubmissionProtection::Ordinary,
        });
    }
    if ordinary.len() > pgp_mime::MAX_PGP_MIME_BYTES {
        return Err(SubmissionError::SizeLimit);
    }
    let (mut outer, formatted_entity) = split_composed_message(&ordinary)?;
    let mut entity = if request.body_format == BodyFormat::Formatted {
        formatted_entity
    } else {
        plain_entity(request)?
    };
    let policy = PgpMimePolicy::default();
    entity = pgp_mime::canonical_signed_entity(&entity, policy.max_bytes)
        .map_err(SubmissionError::Mime)?;
    // Before cryptography enforce the same tree bounds the reader will apply.
    pgp_mime::classify(&entity, policy).map_err(SubmissionError::Mime)?;
    if let Some(signer) = &plan.signer_fingerprint {
        let operation = Operation::Sign {
            signer_fingerprint: signer.clone(),
            data: entity.clone(),
        };
        let outcome = execute(executor, account, &operation)?;
        let digest = match outcome.hash_algorithm {
            Some(8) => SignatureDigest::Sha256,
            Some(10) => SignatureDigest::Sha512,
            _ => return Err(SubmissionError::InvalidOutcome),
        };
        entity = pgp_mime::build_signed(&entity, &outcome.content, digest, &boundary()?, policy)
            .map_err(SubmissionError::Mime)?;
    }
    if encrypt {
        let operation = Operation::Encrypt {
            recipient_fingerprints: plan.recipient_fingerprints.clone(),
            data: entity,
        };
        let outcome = execute(executor, account, &operation)?;
        entity = pgp_mime::build_encrypted(&outcome.content, &boundary()?, policy)
            .map_err(SubmissionError::Mime)?;
    }
    outer.extend_from_slice(b"MIME-Version: 1.0\r\n");
    if outer.len().saturating_add(entity.len()) > policy.max_bytes {
        return Err(SubmissionError::SizeLimit);
    }
    outer.extend_from_slice(&entity);
    pgp_mime::classify(&outer, policy).map_err(SubmissionError::Mime)?;
    Ok(PreparedSubmission {
        bytes: outer,
        account: account.clone(),
        request_digest,
        protection: match (sign, encrypt) {
            (true, true) => SubmissionProtection::SignedAndEncrypted,
            (true, false) => SubmissionProtection::Signed,
            (false, true) => SubmissionProtection::Encrypted,
            (false, false) => unreachable!(),
        },
    })
}

fn execute<E: CryptoExecutor>(
    executor: &E,
    account: &CanonicalUsername,
    operation: &Operation,
) -> Result<Outcome, SubmissionError> {
    operation
        .validate()
        .map_err(|_| SubmissionError::InvalidPlan)?;
    let outcome = executor
        .execute(account, operation)
        .map_err(SubmissionError::Crypto)?;
    outcome
        .validate_for(operation)
        .map_err(|_| SubmissionError::InvalidOutcome)?;
    Ok(outcome)
}

fn validate_plan(request: &ComposeRequest, plan: &OperationPlan) -> Result<(), SubmissionError> {
    if request.protection != crate::send::ProtectionIntent::default()
        && (request.protection.sign != plan.signer_fingerprint.is_some()
            || request.protection.encrypt == plan.recipient_fingerprints.is_empty()
            || request.protection.encrypt_to_self != plan.encrypt_to_self)
    {
        return Err(SubmissionError::InvalidPlan);
    }
    if plan
        .signer_fingerprint
        .as_deref()
        .is_some_and(|fp| !crate::openpgp_crypto::full_fingerprint(fp))
        || plan.recipient_fingerprints.len() > crate::openpgp_crypto::MAX_RECIPIENTS
        || plan
            .recipient_fingerprints
            .iter()
            .any(|fp| !crate::openpgp_crypto::full_fingerprint(fp))
        || plan
            .recipient_fingerprints
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != plan.recipient_fingerprints.len()
        || plan.encrypt_to_self && plan.recipient_fingerprints.is_empty()
    {
        return Err(SubmissionError::InvalidPlan);
    }
    if !plan.recipient_fingerprints.is_empty() && !request.bcc_recipients.is_empty() {
        return Err(SubmissionError::EncryptedBccUnqualified);
    }
    Ok(())
}

fn validated_message(
    account: &CanonicalUsername,
    request: &ComposeRequest,
) -> Result<Vec<u8>, SubmissionError> {
    MailboxIdentity::parse(account.as_str()).map_err(|_| SubmissionError::InvalidAccount)?;
    // Public request fields may have been changed after construction. Reuse
    // compose validation and require the same canonical routing on this edge.
    let validated = ComposeRequest::new_with_routing(
        ComposePolicy::default(),
        request.recipients.join(", "),
        request.cc_recipients.join(", "),
        request.bcc_recipients.join(", "),
        &request.subject,
        &request.body,
        request.attachments.clone(),
    )
    .map_err(|_| SubmissionError::InvalidCompose)?;
    if validated.recipients != request.recipients
        || validated.cc_recipients != request.cc_recipients
        || validated.bcc_recipients != request.bcc_recipients
    {
        return Err(SubmissionError::InvalidCompose);
    }
    let raw = crate::send::build_submission_message(account.as_str(), request)
        .map_err(|_| SubmissionError::InvalidCompose)?;
    if raw.len() > crate::mailbox::DEFAULT_MESSAGE_APPEND_MAX_BYTES {
        return Err(SubmissionError::SizeLimit);
    }
    Ok(raw)
}

fn request_digest(raw: &[u8], request: &ComposeRequest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"osmap-prepared-submission-v1");
    digest.update((raw.len() as u64).to_be_bytes());
    digest.update(raw);
    for recipients in [
        &request.recipients,
        &request.cc_recipients,
        &request.bcc_recipients,
    ] {
        digest.update((recipients.len() as u64).to_be_bytes());
        for address in recipients {
            digest.update((address.len() as u64).to_be_bytes());
            digest.update(address.as_bytes());
        }
    }
    digest.update([
        u8::from(request.protection.sign),
        u8::from(request.protection.encrypt),
        u8::from(request.protection.encrypt_to_self),
    ]);
    match request.protection.binding_revision {
        Some(revision) => {
            digest.update([1]);
            digest.update(revision.to_be_bytes());
        }
        None => digest.update([0]),
    }
    if let Some(sender) = request.sender_identity.sender() {
        digest.update(b"authorized-sender-v1");
        for value in [sender.id(), sender.address()] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    digest.finalize().into()
}

/// This accepts only bytes just produced by the validated composer. Preserve
/// folded display-name headers exactly; move only MIME authority fields.
fn split_composed_message(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SubmissionError> {
    let index = raw
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or(SubmissionError::InvalidCompose)?;
    let headers =
        std::str::from_utf8(&raw[..index]).map_err(|_| SubmissionError::InvalidCompose)?;
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    let mut target = 0;
    for line in headers.split("\r\n") {
        if !line.starts_with([' ', '\t']) {
            let name = line
                .split_once(':')
                .ok_or(SubmissionError::InvalidCompose)?
                .0;
            target = if name.eq_ignore_ascii_case("MIME-Version") {
                0
            } else if name.to_ascii_lowercase().starts_with("content-") {
                2
            } else {
                1
            };
        }
        let destination = match target {
            1 => &mut outer,
            2 => &mut inner,
            _ => continue,
        };
        destination.extend_from_slice(line.as_bytes());
        destination.extend_from_slice(b"\r\n");
    }
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(&raw[index + 4..]);
    Ok((outer, inner))
}

fn plain_entity(request: &ComposeRequest) -> Result<Vec<u8>, SubmissionError> {
    let text = request
        .body
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");
    let plain = format!(
        "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        crate::send::base64_encode_wrapped(text.as_bytes())
    );
    if request.attachments.is_empty() {
        return Ok(plain.into_bytes());
    }
    let mixed = boundary()?;
    let mut output = format!(
        "Content-Type: multipart/mixed; boundary=\"{mixed}\"\r\n\r\n--{mixed}\r\n{plain}\r\n"
    );
    for attachment in &request.attachments {
        let filename = attachment
            .filename
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        output.push_str(&format!("--{mixed}\r\nContent-Type: {}; name=\"{filename}\"\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n", attachment.content_type, crate::send::base64_encode_wrapped(&attachment.body)));
    }
    output.push_str(&format!("--{mixed}--\r\n"));
    if output.len() > pgp_mime::MAX_PGP_MIME_BYTES {
        return Err(SubmissionError::SizeLimit);
    }
    Ok(output.into_bytes())
}

fn boundary() -> Result<String, SubmissionError> {
    let mut bytes = [0u8; 24];
    getrandom::getrandom(&mut bytes).map_err(|_| SubmissionError::RandomUnavailable)?;
    Ok(format!(
        "osmap-protected-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

#[cfg(test)]
#[path = "protected_submission_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "protected_submission_native_tests.rs"]
mod native_tests;
