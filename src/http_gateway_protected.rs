//! Runtime reader and attachment integration consumes one owned stored snapshot.
use super::*;
use crate::identity::CanonicalUsername;
use crate::protected_message::{Processor, ProtectedError};
use crate::protected_message_gateway::{assemble_source, inbound_bindings};

pub(crate) fn has_protection_envelope(message: &MessageView) -> bool {
    let Ok(source) = assemble_source(message) else {
        return true;
    };
    // Full bounded MIME classification also catches hidden/nested protected
    // envelopes. A malformed protection envelope never takes a plain path.
    !matches!(
        crate::pgp_mime::classify(&source, crate::pgp_mime::PgpMimePolicy::default()),
        Ok(crate::pgp_mime::PgpMimeMessage::Unprotected { .. })
    )
}

impl RuntimeBrowserGateway {
    fn protected_bindings(
        &self,
        session: &ValidatedSession,
        message: &MessageView,
    ) -> Result<crate::protected_message::InboundBindings, ProtectedError> {
        let account = CanonicalUsername::parse(&session.record.canonical_username)
            .map_err(|_| ProtectedError::InvalidAccount)?;
        let record =
            crate::openpgp_bindings::BindingStore::new(self.settings_dir.join("openpgp-bindings"))
                .load(account.as_str())
                .map_err(|_| ProtectedError::Unavailable)?;
        let inventory = self
            .public_inventory_client
            .as_ref()
            .and_then(|client| client.read(account.as_str()).ok());
        inbound_bindings(
            &account,
            &record,
            inventory.as_ref(),
            message,
            crate::openpgp_inventory_runtime::now().map_err(|_| ProtectedError::Unavailable)?,
        )
    }

    pub(super) fn render_protected_snapshot(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        message: &MessageView,
        policy: RenderingPolicy,
    ) -> Result<RenderedMessageView, ProtectedError> {
        let client = self
            .crypto_client
            .as_ref()
            .ok_or(ProtectedError::Unavailable)?;
        let source = assemble_source(message)?;
        let bindings = self.protected_bindings(session, message)?;
        let processed = Processor::new(client.clone(), policy)
            .process(context, session, message, &source, &bindings)?;
        let mut rendered = processed.rendered;
        rendered.openpgp = Some(crate::openpgp_reader_ui::ReaderState::Assessed(
            processed.protection,
        ));
        Ok(rendered)
    }

    pub(super) fn protected_attachment_snapshot(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        message: &MessageView,
        part: &str,
    ) -> Result<DownloadedAttachment, ProtectedError> {
        let client = self
            .crypto_client
            .as_ref()
            .ok_or(ProtectedError::Unavailable)?;
        let source = assemble_source(message)?;
        let bindings = self.protected_bindings(session, message)?;
        let processed = Processor::new(client.clone(), self.render_policy)
            .process(context, session, message, &source, &bindings)?;
        let version = &message
            .metadata
            .as_ref()
            .ok_or(ProtectedError::MessageIdentity)?
            .version;
        processed.download_attachment(
            &bindings.account,
            &message.mailbox_name,
            message.uid,
            version,
            part,
        )
    }
}
