use super::*;
use crate::mailbox::{MessageFlagRequest, MessageFlagResult};
use crate::message_metadata::{MessageMetadata, MessageVersion};
use sha2::{Digest, Sha256};

impl StubGateway {
    pub(super) fn fixture_attachment_metadata(context: &AuthenticationContext, username: &str, mailbox: &str, uid: u64) -> Option<MessageMetadata> {
        let mut metadata=Self::fixture_metadata(username,mailbox,uid);
        if context.user_agent.contains("AttachmentFilter") {
            if uid % 4 == 0 { return None; }
            metadata.attachment_count=match uid % 4 { 1=>None, 2=>Some(0), _=>Some(2) };
        }
        Some(metadata)
    }

    pub(super) fn fixture_metadata(username: &str, mailbox: &str, uid: u64) -> MessageMetadata {
        let hash = format!(
            "{:x}",
            Sha256::digest(format!("synthetic/{username}/{mailbox}").as_bytes())
        );
        MessageMetadata {
            preview: if uid == 124 {
                None
            } else if uid == 125 {
                Some(format!("<b>Untrusted synthetic preview</b> {}", "é".repeat(100)))
            } else {
                Some(format!("Public synthetic preview for message {uid}."))
            },
            version: MessageVersion::new(hash[..32].into(), format!("synthetic-{}-{uid}", &hash[..8]))
                .expect("synthetic version"),
            attachment_count: Some(usize::from(uid % 5 == 0)),
        }
    }

    pub(super) fn fixture_message_flags(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
    ) -> Vec<String> {
        self.message_flags
            .lock()
            .expect("synthetic flags")
            .get(&(username.into(), mailbox.into(), uid))
            .cloned()
            .unwrap_or_else(|| {
                [
                    if uid % 2 == 0 { Some("\\Seen") } else { None },
                    if uid % 7 == 0 {
                        Some("\\Flagged")
                    } else {
                        None
                    },
                ]
                .into_iter()
                .flatten()
                .map(str::to_string)
                .collect()
            })
    }

    pub(super) fn set_fixture_message_flag(
        &self,
        context: &AuthenticationContext,
        session: &ValidatedSession,
        request: &MessageFlagRequest,
    ) -> BrowserMessageFlagOutcome {
        let username = &session.record.canonical_username;
        let result = if context.user_agent.contains("FlagUnknown") {
            Err(BrowserMessageFlagFailure::Unknown)
        } else if request.uid == 0
            || !matches!(
                request.mailbox_name.as_str(),
                "INBOX" | "Sent" | "Trash" | "Archive/2026"
            )
            || self.fixture_current_metadata(username, &request.mailbox_name, request.uid).map(|metadata| metadata.version) != Some(request.version.clone())
        {
            Err(BrowserMessageFlagFailure::Stale)
        } else {
            let mut flags =
                self.fixture_message_flags(username, &request.mailbox_name, request.uid);
            if crate::mail_list::has_flag(&flags, request.flag.imap()) == request.enabled {
                Ok(MessageFlagResult::AlreadySet)
            } else {
                flags.retain(|flag| !flag.eq_ignore_ascii_case(request.flag.imap()));
                if request.enabled {
                    flags.push(request.flag.imap().into());
                }
                self.message_flags.lock().expect("synthetic flags").insert(
                    (username.clone(), request.mailbox_name.clone(), request.uid),
                    flags,
                );
                Ok(MessageFlagResult::Updated)
            }
        };
        BrowserMessageFlagOutcome {
            result,
            audit_events: Vec::new(),
        }
    }
}
