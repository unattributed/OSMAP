//! Session/request/stable-identity validation before protected reading.
//! This adapter performs no fetch, key selection, logging or persistence.
use crate::auth::AuthenticationContext;
use crate::identity::CanonicalUsername;
use crate::mailbox::{MessageView, MessageViewDecision, MessageViewPolicy, MessageViewRequest};
use crate::message_metadata::MessageVersion;
use crate::protected_message::{
    CryptoExecutor, InboundBindings, Processor, ProtectedError, ProtectedMessageView,
};
use crate::session::ValidatedSession;

/// Assemble the stored header/body representation without changing body bytes.
/// This is not a claim of original wire-source fidelity; native mailbox tests
/// must qualify the representation used for detached signature verification.
pub fn assemble_source(message: &MessageView) -> Result<Vec<u8>, ProtectedError> {
    let headers = message
        .header_block
        .trim_end_matches(['\r', '\n'])
        .as_bytes();
    if headers
        .len()
        .saturating_add(4)
        .saturating_add(message.body_text.len())
        > crate::pgp_mime::MAX_PGP_MIME_BYTES
    {
        return Err(ProtectedError::Mime(
            crate::pgp_mime::PgpMimeError::SizeLimit,
        ));
    }
    let mut source = Vec::with_capacity(headers.len() + 4 + message.body_text.len());
    source.extend_from_slice(headers);
    source.extend_from_slice(b"\r\n\r\n");
    source.extend_from_slice(message.body_text.as_bytes());
    Ok(source)
}

pub fn inbound_bindings(
    account: &CanonicalUsername,
    record: &crate::openpgp_bindings::BindingRecord,
    inventory: Option<&crate::openpgp_inventory::Inventory>,
    message: &MessageView,
    now: u64,
) -> Result<InboundBindings, ProtectedError> {
    crate::protected_message::bindings_for_message(account, record, inventory, message, now)
}

/// Borrowed source from the same authenticated fetch as the mailbox snapshot.
pub struct OwnedSnapshot<'a> {
    message: &'a MessageView,
    source: &'a [u8],
    account: CanonicalUsername,
    session_id: String,
}

impl<'a> OwnedSnapshot<'a> {
    pub fn from_retrieved(
        session: &ValidatedSession,
        request: &MessageViewRequest,
        expected_version: Option<&MessageVersion>,
        decision: &'a MessageViewDecision,
        exact_source: &'a [u8],
    ) -> Result<Self, ProtectedError> {
        let account = CanonicalUsername::parse(&session.record.canonical_username)
            .map_err(|_| ProtectedError::InvalidAccount)?;
        let MessageViewDecision::Retrieved {
            canonical_username,
            session_id,
            message,
        } = decision
        else {
            return Err(ProtectedError::Unavailable);
        };
        let limits = MessageViewPolicy::default();
        if canonical_username != &session.record.canonical_username
            || session_id != &session.record.session_id
            || message.mailbox_name != request.mailbox_name
            || message.uid != request.uid
            || message.header_block.len() > limits.message_header_max_len
            || message.body_text.len() > limits.message_body_max_len
            || expected_version.is_some_and(|version| {
                message.metadata.as_ref().map(|m| &m.version) != Some(version)
            })
        {
            return Err(ProtectedError::MessageIdentity);
        }
        Ok(Self {
            message,
            source: exact_source,
            account,
            session_id: session.record.session_id.clone(),
        })
    }

    pub fn message(&self) -> &MessageView {
        self.message
    }

    pub fn process<E: CryptoExecutor>(
        &self,
        processor: &Processor<E>,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        bindings: &InboundBindings,
    ) -> Result<ProtectedMessageView<'a>, ProtectedError> {
        if session.record.canonical_username != self.account.as_str()
            || session.record.session_id != self.session_id
        {
            return Err(ProtectedError::MessageIdentity);
        }
        processor.process(context, session, self.message, self.source, bindings)
    }
}

impl std::fmt::Debug for OwnedSnapshot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedSnapshot")
            .field("uid", &self.message.uid)
            .field("source_bytes", &self.source.len())
            .finish()
    }
}

#[cfg(test)]
#[path = "protected_message_gateway_tests.rs"]
mod tests;
