//! Bounded unfinished authoring state, deliberately distinct from a send request.
//! Partial addresses are retained as text. Submission must validate them again.
use crate::send::{ComposeError, ComposePolicy, UploadedAttachment};

/// Apply explicit removal to the already revision-checked saved attachment set.
/// Indices are local to that version; missing, duplicate or unknown indices refuse.
pub(crate) fn retain_saved_attachments(
    attachments: &[UploadedAttachment],
    removed: &[usize],
) -> Result<Vec<UploadedAttachment>, ComposeError> {
    if removed
        .iter()
        .enumerate()
        .any(|(position, index)| *index >= attachments.len() || removed[..position].contains(index))
    {
        return Err(ComposeError {
            reason: "saved attachment selection was invalid".into(),
        });
    }
    Ok(attachments
        .iter()
        .enumerate()
        .filter(|(index, _)| !removed.contains(index))
        .map(|(_, attachment)| attachment.clone())
        .collect())
}

#[derive(Clone, PartialEq, Eq)]
pub struct DraftContent {
    pub recipients_text: String,
    pub cc_text: String,
    pub bcc_text: String,
    pub subject: String,
    pub body: String,
    pub body_format: crate::compose_format::BodyFormat,
    pub attachments: Vec<UploadedAttachment>,
    pub reply_thread: Option<crate::reply_thread::ReplyThread>,
}

impl std::fmt::Debug for DraftContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DraftContent")
            .field("subject_bytes", &self.subject.len())
            .field("body_bytes", &self.body.len())
            .field("attachments", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

impl DraftContent {
    pub fn new(
        policy: ComposePolicy,
        recipients_text: String,
        cc_text: String,
        bcc_text: String,
        subject: String,
        body: String,
        attachments: Vec<UploadedAttachment>,
    ) -> Result<Self, ComposeError> {
        let value = Self {
            recipients_text,
            cc_text,
            bcc_text,
            subject,
            body,
            body_format: crate::compose_format::BodyFormat::Plain,
            attachments,
            reply_thread: None,
        };
        value.validate(policy)?;
        Ok(value)
    }

    pub fn validate(&self, policy: ComposePolicy) -> Result<(), ComposeError> {
        let address_limit = policy
            .max_recipients
            .saturating_mul(policy.recipient_max_len.saturating_add(256));
        for value in [&self.recipients_text, &self.cc_text, &self.bcc_text] {
            if value.len() > address_limit || value.chars().any(char::is_control) {
                return Err(ComposeError {
                    reason:
                        "draft recipient field exceeds its bound or contains control characters"
                            .into(),
                });
            }
        }
        crate::send::validate_subject(policy, &self.subject)?;
        crate::send::validate_body(policy, &self.body)?;
        crate::send::validate_attachment_set(policy, &self.attachments)?;
        for attachment in &self.attachments {
            // Public record fields must be revalidated at the storage boundary.
            attachment.validate(policy)?;
        }
        Ok(())
    }

    /// Counts only addresses that can currently be parsed; never grants send authority.
    pub fn total_recipient_count(&self) -> usize {
        let addresses: Vec<String> = [&self.recipients_text, &self.cc_text, &self.bcc_text]
            .into_iter()
            .flat_map(|value| {
                crate::mail_address::parse_address_list(ComposePolicy::default(), value)
                    .unwrap_or_default()
            })
            .collect();
        crate::mail_address::deduplicate(&addresses).len()
    }

    pub fn recipient_preview(&self) -> Option<String> {
        [&self.recipients_text, &self.cc_text]
            .into_iter()
            .map(|value| value.trim())
            .find(|value| !value.is_empty())
            .map(|value| value.chars().take(160).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send::ComposeRequest;

    #[test]
    fn unfinished_addresses_round_trip_without_becoming_send_requests() {
        for entered in [
            "",
            "recipient@",
            "still choosing",
            "  Desk <desk@example.test>  ",
        ] {
            let draft = DraftContent::new(
                ComposePolicy::default(),
                entered.into(),
                String::new(),
                "private@example.test".into(),
                "Unfinished".into(),
                "Private draft text".into(),
                Vec::new(),
            )
            .unwrap();
            assert_eq!(draft.recipients_text, entered);
            assert!(!format!("{draft:?}").contains("Private draft text"));
            assert!(!format!("{draft:?}").contains("private@example.test"));
            assert!(!draft
                .recipient_preview()
                .unwrap_or_default()
                .contains("private@example.test"));
            if entered != "  Desk <desk@example.test>  " {
                assert!(ComposeRequest::new(
                    ComposePolicy::default(),
                    draft.recipients_text,
                    draft.subject,
                    draft.body
                )
                .is_err());
            }
        }
    }

    #[test]
    fn unfinished_state_keeps_header_body_and_attachment_limits() {
        let policy = ComposePolicy::default();
        for entered in [
            "someone@example.test\r\nBcc: injected@example.test".to_string(),
            "x".repeat(20_000),
        ] {
            assert!(DraftContent::new(
                policy,
                entered,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Vec::new()
            )
            .is_err());
        }
        assert!(DraftContent::new(
            policy,
            String::new(),
            String::new(),
            String::new(),
            "bad\nheader".into(),
            String::new(),
            Vec::new()
        )
        .is_err());
        assert!(DraftContent::new(
            policy,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "x".repeat(policy.body_max_len + 1),
            Vec::new()
        )
        .is_err());
        let invalid = UploadedAttachment {
            filename: "bad\r\nfile".into(),
            content_type: "text/plain".into(),
            body: b"synthetic".to_vec(),
        };
        assert!(DraftContent::new(
            policy,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            vec![invalid]
        )
        .is_err());
    }
}
