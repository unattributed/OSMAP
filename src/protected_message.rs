//! Account-bound, transient protected-mail processing for the reader gateway.
//!
//! Source and MessageView must come from the same authenticated mailbox fetch.
//! Bindings are trusted account-store facts, never message UIDs or form fields.
//! The original source remains ciphertext; decrypted content is never persisted,
//! logged, cached or made available as an automatic reply/forward quote here.

use crate::auth::AuthenticationContext;
use crate::identity::{CanonicalUsername, MailboxIdentity};
use crate::mailbox::{MessageView, MessageViewPolicy, MessageViewRequest};
use crate::message_metadata::MessageVersion;
use crate::openpgp_crypto::{Error as CryptoError, Operation, Outcome};
use crate::pgp_mime::{self, PgpMimeError, PgpMimeMessage, PgpMimePolicy, SignatureDigest};
use crate::rendering::{PlainTextMessageRenderer, RenderedMessageView, RenderingPolicy};
use crate::session::ValidatedSession;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoFailure {
    Transport,
    Engine(CryptoError),
}

/// The production adapter always uses the signed, peer-authenticated client.
/// Test adapters do not supply paths, homes, commands or passphrase callbacks.
pub trait CryptoExecutor {
    fn execute(
        &self,
        account: &CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure>;
}

impl CryptoExecutor for crate::openpgp_crypto_runtime::Client {
    fn execute(
        &self,
        account: &CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, CryptoFailure> {
        self.execute(account.as_str(), operation)
            .map_err(|_| CryptoFailure::Transport)?
            .map_err(CryptoFailure::Engine)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyValidity {
    Current,
    Unknown,
    Expired,
    Revoked,
}

/// A confirmed binding supplied by the account's trusted public-key store.
/// RFC 3156 protects the MIME entity, not the outer From/Subject headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerIdentityBinding {
    pub primary_fingerprint: String,
    pub mailbox: MailboxIdentity,
    pub key_validity: KeyValidity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundBindings {
    pub account: CanonicalUsername,
    pub decrypt_primary_fingerprints: Vec<String>,
    pub signer: Option<SignerIdentityBinding>,
}

impl InboundBindings {
    fn validate(&self, account: &CanonicalUsername) -> Result<(), ProtectedError> {
        if self.account != *account {
            return Err(ProtectedError::ForeignBindings);
        }
        let keys = &self.decrypt_primary_fingerprints;
        if keys.len() > 32
            || keys.iter().any(|fp| !profile_fingerprint(fp))
            || keys.iter().collect::<BTreeSet<_>>().len() != keys.len()
            || self
                .signer
                .as_ref()
                .is_some_and(|s| !profile_fingerprint(&s.primary_fingerprint))
        {
            return Err(ProtectedError::InvalidBinding);
        }
        Ok(())
    }
}

/// Project only trusted account-store bindings and authenticated public facts.
/// Key UIDs or a mail address alone never establish signer identity trust.
/// Callers must first validate the message's authenticated owned snapshot.
pub fn bindings_for_message(
    account: &CanonicalUsername,
    record: &crate::openpgp_bindings::BindingRecord,
    inventory: Option<&crate::openpgp_inventory::Inventory>,
    message: &MessageView,
    now: u64,
) -> Result<InboundBindings, ProtectedError> {
    record.ensure_account(account.as_str()).map_err(|error| {
        if error == crate::openpgp_bindings::BindingError::ForeignAccount {
            ProtectedError::ForeignBindings
        } else {
            ProtectedError::InvalidBinding
        }
    })?;
    if now == 0 || now > 253402300799 {
        return Err(ProtectedError::InvalidBinding);
    }
    let decrypt_primary_fingerprints = record
        .account_binding
        .as_ref()
        .map(|binding| binding.decrypt_primary_fingerprints.clone())
        .unwrap_or_default();
    let signer = single_sender(message).and_then(|sender| {
        let address = crate::mail_address::comparison_key(sender.as_str());
        let binding = record
            .recipient_bindings
            .iter()
            .find(|binding| crate::mail_address::comparison_key(&binding.address) == address)?;
        let key = inventory
            .and_then(crate::openpgp_inventory::Inventory::keys)
            .and_then(|keys| {
                keys.iter()
                    .find(|key| key.primary.fingerprint == binding.primary_fingerprint)
            });
        let key_validity = key
            .map(|key| {
                let primary = &key.primary;
                if primary.revoked {
                    KeyValidity::Revoked
                } else if primary.expired || primary.expires != 0 && primary.expires <= now {
                    KeyValidity::Expired
                } else if primary.disabled || primary.invalid || primary.created > now {
                    KeyValidity::Unknown
                } else {
                    KeyValidity::Current
                }
            })
            .unwrap_or(KeyValidity::Unknown);
        Some(SignerIdentityBinding {
            primary_fingerprint: binding.primary_fingerprint.clone(),
            mailbox: sender,
            key_validity,
        })
    });
    let result = InboundBindings {
        account: account.clone(),
        decrypt_primary_fingerprints,
        signer,
    };
    result.validate(account)?;
    Ok(result)
}

fn profile_fingerprint(value: &str) -> bool {
    value.len() == 40 && crate::openpgp_crypto::full_fingerprint(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureValidity {
    Unsigned,
    Valid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerIdentityState {
    NotApplicable,
    Unknown,
    ConfirmedBinding,
    Mismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionState {
    pub decrypted_on_mail_host: bool,
    pub signature: SignatureValidity,
    pub signer_identity: SignerIdentityState,
    pub signer_primary_fingerprint: Option<String>,
    pub key_validity: Option<KeyValidity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedError {
    InvalidAccount,
    ForeignBindings,
    InvalidBinding,
    MessageIdentity,
    SourceMismatch,
    Mime(PgpMimeError),
    UnsupportedProtectionLayer,
    UnsupportedTextEncoding,
    Unavailable,
    Locked,
    MissingKey,
    UnknownSigner,
    UnsupportedCrypto,
    IntegrityFailure,
    SignatureFailure,
    ExpiredKey,
    RevokedKey,
    RenderFailure,
    Attachment(crate::attachment::AttachmentDownloadPublicFailureReason),
}

impl From<CryptoFailure> for ProtectedError {
    fn from(value: CryptoFailure) -> Self {
        match value {
            CryptoFailure::Transport => Self::Unavailable,
            CryptoFailure::Engine(error) => match error {
                CryptoError::Locked => Self::Locked,
                CryptoError::MissingKey => Self::MissingKey,
                CryptoError::Unsupported => Self::UnsupportedCrypto,
                CryptoError::Integrity => Self::IntegrityFailure,
                CryptoError::Signature => Self::SignatureFailure,
                _ => Self::Unavailable,
            },
        }
    }
}

/// No content-bearing Debug/Serialize/Clone implementation is provided.
/// This request-local value must not be inserted into state or a cache.
pub struct ProtectedMessageView<'a> {
    pub original_source: &'a [u8],
    pub protection: ProtectionState,
    pub rendered: RenderedMessageView,
    account: CanonicalUsername,
    transient_message: MessageView,
    mime_policy: crate::mime::MimeAnalysisPolicy,
}

impl std::fmt::Debug for ProtectedMessageView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedMessageView")
            .field("source_bytes", &self.original_source.len())
            .field("protection", &self.protection)
            .field("uid", &self.rendered.uid)
            .finish()
    }
}

impl ProtectedMessageView<'_> {
    fn validate_attachment_identity(
        &self,
        account: &CanonicalUsername,
        mailbox_name: &str,
        uid: u64,
        version: &MessageVersion,
    ) -> Result<(), ProtectedError> {
        if account != &self.account
            || mailbox_name != self.transient_message.mailbox_name
            || uid != self.transient_message.uid
            || self.transient_message.metadata.as_ref().map(|m| &m.version) != Some(version)
        {
            return Err(ProtectedError::MessageIdentity);
        }
        Ok(())
    }

    /// Use only after the attachment route freshly fetches the owned original
    /// ciphertext and reruns this pipeline. Stable identity is mandatory.
    pub fn attachment_part(
        &self,
        account: &CanonicalUsername,
        mailbox_name: &str,
        uid: u64,
        version: &MessageVersion,
        part_path: &str,
    ) -> Result<Option<crate::mime::AttachmentPart>, ProtectedError> {
        self.validate_attachment_identity(account, mailbox_name, uid, version)?;
        if part_path.len() > 128 {
            return Err(ProtectedError::MessageIdentity);
        }
        crate::mime::MimeAnalyzer::new(self.mime_policy)
            .find_attachment_part(&self.transient_message, part_path)
            .map_err(|_| ProtectedError::RenderFailure)
    }

    /// Reuse existing forced-download bounds, transfer decoding, filenames and
    /// media-type rules after freshly processing the identity-bound ciphertext.
    pub fn download_attachment(
        &self,
        account: &CanonicalUsername,
        mailbox_name: &str,
        uid: u64,
        version: &MessageVersion,
        part_path: &str,
    ) -> Result<crate::attachment::DownloadedAttachment, ProtectedError> {
        self.validate_attachment_identity(account, mailbox_name, uid, version)?;
        crate::attachment::AttachmentDownloadService::new(
            crate::attachment::AttachmentDownloadPolicy::default(),
        )
        .download_from_message(&self.transient_message, part_path)
        .map_err(|error| ProtectedError::Attachment(error.public_reason()))
    }
}

pub struct Processor<E> {
    executor: E,
    mime_policy: PgpMimePolicy,
    rendering_policy: RenderingPolicy,
}

struct VerificationInput<'a> {
    entity: &'a [u8],
    signature: &'a [u8],
    digest: SignatureDigest,
}

impl<E: CryptoExecutor> Processor<E> {
    pub fn new(executor: E, rendering_policy: RenderingPolicy) -> Self {
        Self {
            executor,
            mime_policy: PgpMimePolicy::default(),
            rendering_policy,
        }
    }

    pub fn process<'a>(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        original: &MessageView,
        source: &'a [u8],
        bindings: &InboundBindings,
    ) -> Result<ProtectedMessageView<'a>, ProtectedError> {
        let account = CanonicalUsername::parse(&session.record.canonical_username)
            .map_err(|_| ProtectedError::InvalidAccount)?;
        bindings.validate(&account)?;
        MessageViewRequest::new(
            MessageViewPolicy::default(),
            &original.mailbox_name,
            original.uid,
        )
        .map_err(|_| ProtectedError::MessageIdentity)?;
        let classified =
            pgp_mime::classify(source, self.mime_policy).map_err(ProtectedError::Mime)?;
        let (source_headers, source_body) = split_entity(source)?;
        if strip_final_newlines(source_headers)
            != strip_final_newlines(original.header_block.as_bytes())
            || source_body != original.body_text.as_bytes()
        {
            return Err(ProtectedError::SourceMismatch);
        }
        let mut protection = ProtectionState {
            decrypted_on_mail_host: false,
            signature: SignatureValidity::Unsigned,
            signer_identity: SignerIdentityState::NotApplicable,
            signer_primary_fingerprint: None,
            key_validity: None,
        };
        let plaintext;
        let content = match classified {
            PgpMimeMessage::Unprotected { .. } => None,
            PgpMimeMessage::Signed {
                canonical_entity,
                signature,
                digest,
                ..
            } => {
                self.verify(
                    &account,
                    bindings,
                    original,
                    VerificationInput {
                        entity: &canonical_entity,
                        signature: &signature,
                        digest,
                    },
                    &mut protection,
                )?;
                plaintext = canonical_entity;
                Some(plaintext.as_slice())
            }
            PgpMimeMessage::Encrypted { ciphertext, .. } => {
                if bindings.decrypt_primary_fingerprints.is_empty() {
                    return Err(ProtectedError::MissingKey);
                }
                let operation = Operation::Decrypt {
                    allowed_primary_fingerprints: bindings.decrypt_primary_fingerprints.clone(),
                    ciphertext,
                };
                let result = self.execute(&account, &operation)?;
                let inner = pgp_mime::classify(&result.content, self.mime_policy)
                    .map_err(ProtectedError::Mime)?;
                protection.decrypted_on_mail_host = true;
                match inner {
                    PgpMimeMessage::Unprotected { .. } => plaintext = result.content,
                    PgpMimeMessage::Signed {
                        canonical_entity,
                        signature,
                        digest,
                        ..
                    } => {
                        self.verify(
                            &account,
                            bindings,
                            original,
                            VerificationInput {
                                entity: &canonical_entity,
                                signature: &signature,
                                digest,
                            },
                            &mut protection,
                        )?;
                        plaintext = canonical_entity;
                    }
                    PgpMimeMessage::Encrypted { .. } => {
                        return Err(ProtectedError::UnsupportedProtectionLayer)
                    }
                }
                Some(plaintext.as_slice())
            }
        };
        let mut transient_message = original.clone();
        if let Some(content) = content {
            let (headers, body) = split_entity(content)?;
            // Exact verification is already complete. Only the rendering copy
            // is converted to text; unsupported raw encodings do not use lossy UTF8.
            let headers = std::str::from_utf8(headers)
                .map_err(|_| ProtectedError::UnsupportedTextEncoding)?;
            transient_message.header_block = merge_render_headers(&original.header_block, headers);
            transient_message.body_text = std::str::from_utf8(body)
                .map_err(|_| ProtectedError::UnsupportedTextEncoding)?
                .to_string();
        }
        let mut rendered = PlainTextMessageRenderer::new(self.rendering_policy)
            .render_for_validated_session(context, session, &transient_message)
            .map_err(|_| ProtectedError::RenderFailure)?
            .rendered;
        if content.is_some() {
            // Explicit authoring consent belongs to a separate reply/forward
            // workflow; this reader never supplies plaintext for an autosaved draft.
            rendered.body_text_for_compose.clear();
        }
        Ok(ProtectedMessageView {
            original_source: source,
            protection,
            rendered,
            account,
            transient_message,
            mime_policy: self.rendering_policy.mime_analysis_policy,
        })
    }

    fn execute(
        &self,
        account: &CanonicalUsername,
        operation: &Operation,
    ) -> Result<Outcome, ProtectedError> {
        operation
            .validate()
            .map_err(|_| ProtectedError::UnsupportedCrypto)?;
        let result = self
            .executor
            .execute(account, operation)
            .map_err(ProtectedError::from)?;
        result
            .validate_for(operation)
            .map_err(|_| ProtectedError::Unavailable)?;
        Ok(result)
    }

    fn verify(
        &self,
        account: &CanonicalUsername,
        bindings: &InboundBindings,
        original: &MessageView,
        signed: VerificationInput<'_>,
        protection: &mut ProtectionState,
    ) -> Result<(), ProtectedError> {
        // These are refusals of the configured expected sender binding, not
        // claims that the message signature or an unrelated signer was checked.
        // A binding for a different outer sender does not preflight this message.
        if let Some(binding) = &bindings.signer {
            if sender_matches(original, &binding.mailbox) {
                match binding.key_validity {
                    KeyValidity::Expired => return Err(ProtectedError::ExpiredKey),
                    KeyValidity::Revoked => return Err(ProtectedError::RevokedKey),
                    _ => (),
                }
            }
        }
        let operation = Operation::Verify {
            data: signed.entity.to_vec(),
            signature: signed.signature.to_vec(),
        };
        let verified = self.execute(account, &operation).map_err(|error| {
            if error == ProtectedError::MissingKey {
                ProtectedError::UnknownSigner
            } else {
                error
            }
        })?;
        if verified.hash_algorithm
            != Some(match signed.digest {
                SignatureDigest::Sha256 => 8,
                SignatureDigest::Sha512 => 10,
            })
        {
            return Err(ProtectedError::SignatureFailure);
        }
        protection.signature = SignatureValidity::Valid;
        protection.signer_primary_fingerprint = verified.primary_fingerprint.clone();
        protection.signer_identity = SignerIdentityState::Unknown;
        protection.key_validity = Some(KeyValidity::Unknown);
        if let Some(binding) = &bindings.signer {
            if verified.primary_fingerprint.as_deref() != Some(binding.primary_fingerprint.as_str())
            {
                protection.signer_identity = SignerIdentityState::Mismatch;
                return Ok(());
            }
            match binding.key_validity {
                KeyValidity::Expired => return Err(ProtectedError::ExpiredKey),
                KeyValidity::Revoked => return Err(ProtectedError::RevokedKey),
                _ => (),
            }
            protection.signer_identity = if sender_matches(original, &binding.mailbox) {
                SignerIdentityState::ConfirmedBinding
            } else {
                SignerIdentityState::Mismatch
            };
            protection.key_validity = Some(binding.key_validity);
        }
        Ok(())
    }
}

fn sender_matches(original: &MessageView, expected: &MailboxIdentity) -> bool {
    single_sender(original).is_some_and(|sender| {
        crate::mail_address::comparison_key(sender.as_str())
            == crate::mail_address::comparison_key(expected.as_str())
    })
}

fn single_sender(original: &MessageView) -> Option<MailboxIdentity> {
    let headers = crate::mime::unfold_headers(&original.header_block);
    let values: Vec<_> = headers
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("from").then_some(value.trim())
        })
        .collect();
    if values.len() != 1 {
        return None;
    }
    let addresses =
        crate::mail_address::parse_address_list(crate::send::ComposePolicy::default(), values[0])
            .ok()?;
    if addresses.len() != 1 {
        return None;
    }
    MailboxIdentity::parse(addresses[0].clone()).ok()
}

fn split_entity(source: &[u8]) -> Result<(&[u8], &[u8]), ProtectedError> {
    let mut start = 0;
    while let Some(offset) = source[start..].iter().position(|&b| b == b'\n') {
        let end = start + offset;
        let line = if end > start && source[end - 1] == b'\r' {
            &source[start..end - 1]
        } else {
            &source[start..end]
        };
        if line.is_empty() {
            return Ok((&source[..start], &source[end + 1..]));
        }
        start = end + 1;
    }
    Err(ProtectedError::Mime(PgpMimeError::MalformedHeaders))
}

fn strip_final_newlines(mut source: &[u8]) -> &[u8] {
    while matches!(source.last(), Some(b'\r' | b'\n')) {
        source = &source[..source.len() - 1];
    }
    source
}

/// Header editing is exclusively a post-verification rendering projection.
/// Only the original outer envelope is displayed; inner envelope fields never
/// replace sender/subject/reply metadata. Dropped fields include continuations.
fn merge_render_headers(outer: &str, inner: &str) -> String {
    fn select(headers: &str, want_mime: bool, result: &mut String) {
        let mut selected = false;
        for line in headers.lines() {
            if !line.starts_with([' ', '\t']) {
                selected = line.split_once(':').is_some_and(|(name, _)| {
                    let mime = name.to_ascii_lowercase().starts_with("content-")
                        || name.eq_ignore_ascii_case("mime-version");
                    mime == want_mime
                });
            }
            if selected {
                result.push_str(line);
                result.push_str("\r\n");
            }
        }
    }
    let mut result = String::new();
    select(outer, false, &mut result);
    select(inner, true, &mut result);
    result
}

#[cfg(test)]
#[path = "protected_message_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "protected_message_native_tests.rs"]
pub(crate) mod native_tests;
