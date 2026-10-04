//! Exact deletion helper client. No direct native fallback and no automatic retry.
//! Peer identity is operator configuration, never inferred from socket availability.
use super::mailbox_helper_client::encode_authorized_request;
use super::*;
use crate::mailbox::{
    MessageDeleteBackend, MessageDeleteError, MessageDeleteRequest, MessageDeleteResult,
    RetentionDecision,
};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHelperMessageDeleteBackend {
    socket_path: PathBuf,
    grant_key_path: PathBuf,
    policy: MailboxHelperPolicy,
    helper_uid: Option<u32>,
}
impl MailboxHelperMessageDeleteBackend {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        grant_key_path: impl Into<PathBuf>,
        policy: MailboxHelperPolicy,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            grant_key_path: grant_key_path.into(),
            policy,
            helper_uid: None,
        }
    }
    pub fn with_helper_uid(mut self, uid: u32) -> Self {
        self.helper_uid = Some(uid);
        self
    }
    fn exchange(
        &self,
        request: &mut MailboxHelperRequest,
    ) -> Result<MailboxHelperResponse, MessageDeleteError> {
        let seconds = self
            .policy
            .read_timeout_secs
            .saturating_add(self.policy.write_timeout_secs)
            .min(10);
        if seconds == 0 || self.helper_uid.is_none() {
            return Err(MessageDeleteError::Unavailable);
        }
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let bytes = encode_authorized_request(&self.grant_key_path, request)
            .map_err(|_| MessageDeleteError::Unavailable)?;
        if bytes.len() > self.policy.max_request_bytes.min(4096) {
            return Err(MessageDeleteError::Invalid);
        }
        #[cfg(not(unix))]
        {
            let _ = (bytes, deadline);
            Err(MessageDeleteError::Unavailable)
        }
        #[cfg(unix)]
        {
            let mut stream = crate::openbsd::connect_unix_before(&self.socket_path, deadline)
                .map_err(|_| MessageDeleteError::Unavailable)?;
            if crate::openbsd::unix_stream_peer_uid(&stream).ok() != self.helper_uid {
                return Err(MessageDeleteError::Unavailable);
            }
            let mut dispatched = false;
            let mut offset = 0;
            let transport_error = |dispatched: bool| {
                if dispatched {
                    MessageDeleteError::Unknown
                } else {
                    MessageDeleteError::Unavailable
                }
            };
            while offset < bytes.len() {
                let left = remaining(deadline).ok_or_else(|| transport_error(dispatched))?;
                stream
                    .set_write_timeout(Some(left))
                    .map_err(|_| transport_error(dispatched))?;
                // A write can reach the peer even when its returned error cannot prove how much.
                dispatched = true;
                match stream.write(&bytes[offset..]) {
                    Ok(0) => return Err(MessageDeleteError::Unknown),
                    Ok(count) => offset += count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(MessageDeleteError::Unknown),
                }
            }
            remaining(deadline).ok_or(MessageDeleteError::Unknown)?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| MessageDeleteError::Unknown)?;
            let mut response = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                stream
                    .set_read_timeout(Some(
                        remaining(deadline).ok_or(MessageDeleteError::Unknown)?,
                    ))
                    .map_err(|_| MessageDeleteError::Unknown)?;
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => {
                        if response.len().saturating_add(count)
                            > self.policy.max_response_bytes.min(4096)
                        {
                            return Err(MessageDeleteError::Unknown);
                        }
                        response.extend_from_slice(&chunk[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(MessageDeleteError::Unknown),
                }
            }
            remaining(deadline).ok_or(MessageDeleteError::Unknown)?;
            let parsed = parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                std::str::from_utf8(&response).map_err(|_| MessageDeleteError::Unknown)?,
            )
            .map_err(|_| MessageDeleteError::Unknown)?;
            remaining(deadline).ok_or(MessageDeleteError::Unknown)?;
            Ok(parsed)
        }
    }
}
#[cfg(unix)]
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}
impl MessageDeleteBackend for MailboxHelperMessageDeleteBackend {
    fn retention_status(&self, account: &str, mailbox: &str) -> RetentionDecision {
        if crate::identity::CanonicalUsername::parse(account).is_err()
            || account.contains(['*', '?'])
            || crate::bin_folder::parse_mailbox_name(mailbox).is_err()
        {
            return RetentionDecision::Unavailable;
        }
        let mut request = MailboxHelperRequest::RetentionStatus {
            canonical_username: account.into(),
            mailbox_name: mailbox.into(),
            grant: MailboxHelperGrant::unsigned(),
        };
        match self.exchange(&mut request) {
            Ok(MailboxHelperResponse::RetentionStatus {
                canonical_username,
                mailbox_name,
                decision,
                nonce,
            }) if canonical_username == account
                && mailbox_name == mailbox
                && nonce == request_grant(&request).nonce =>
            {
                decision
            }
            _ => RetentionDecision::Unavailable,
        }
    }
    fn delete_message(
        &self,
        authenticated_account: &str,
        request: &MessageDeleteRequest,
    ) -> Result<MessageDeleteResult, MessageDeleteError> {
        let validated = MessageDeleteRequest::new(
            request.canonical_username.clone(),
            request.mailbox_name.clone(),
            request.uid,
            request.version.clone(),
            request.policy_revision,
        )?;
        if authenticated_account != validated.canonical_username || &validated != request {
            return Err(MessageDeleteError::Invalid);
        }
        let mut helper_request = MailboxHelperRequest::MessageDelete {
            request: validated,
            grant: MailboxHelperGrant::unsigned(),
        };
        match self.exchange(&mut helper_request)? {
            MailboxHelperResponse::MessageDelete {
                request: confirmed,
                result,
                nonce,
            } if confirmed.as_ref() == request && nonce == request_grant(&helper_request).nonce => {
                result
            }
            _ => Err(MessageDeleteError::Unknown),
        }
    }
}
