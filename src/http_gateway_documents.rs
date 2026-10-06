//! Runtime Documents use the existing authenticated mailbox helper. The web
//! process never invokes doveadm or holds mailbox bytes outside this journey.
use super::*;

impl RuntimeBrowserGateway {
    pub(super) fn document_store(
        &self,
    ) -> Result<
        crate::documents::Store<crate::mailbox_helper::MailboxHelperDocumentsBackend>,
        crate::documents::Error,
    > {
        let socket = self
            .mailbox_helper_socket_path
            .as_ref()
            .ok_or(crate::documents::Error::Unavailable)?;
        let key = self
            .mailbox_helper_grant_key_path
            .as_ref()
            .ok_or(crate::documents::Error::Unavailable)?;
        let uid = self
            .mailbox_helper_peer_uid
            .ok_or(crate::documents::Error::Unavailable)?;
        let backend = crate::mailbox_helper::MailboxHelperDocumentsBackend::new(
            socket,
            key,
            crate::mailbox_helper::MailboxHelperPolicy::default(),
        )
        .with_helper_uid(uid);
        Ok(crate::documents::Store::new(
            self.settings_dir.join("documents-v1"),
            backend,
        ))
    }
}
