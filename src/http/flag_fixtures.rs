use super::*;
use crate::mailbox::{MessageFlagRequest, MessageFlagResult};
use crate::message_metadata::{MessageMetadata, MessageVersion};
use sha2::{Digest, Sha256};

impl StubGateway {
    pub(super) fn fixture_metadata(username: &str, mailbox: &str, uid: u64) -> MessageMetadata {
        let hash = format!(
            "{:x}",
            Sha256::digest(format!("synthetic/{username}/{mailbox}").as_bytes())
        );
        MessageMetadata {
            version: MessageVersion::new(hash[..32].into(), format!("synthetic-message-{uid}"))
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
            || request.uid > 125
            || !matches!(
                request.mailbox_name.as_str(),
                "INBOX" | "Sent" | "Trash" | "Archive/2026"
            )
            || request.version
                != Self::fixture_metadata(username, &request.mailbox_name, request.uid).version
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
