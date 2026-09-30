//! Strict structured fetch responses. Mail headers cannot become protocol keys.
use std::collections::BTreeSet;

use serde::Deserialize;

use super::mailbox_parse::{normalize_header_summary_value, validate_bounded_string};
use super::*;
use crate::message_metadata::{attachment_count, message_preview, MessageMetadata, MessageVersion};

pub(super) const SUMMARY_FIELDS: &str = "uid flags date.received size.virtual mailbox mailbox-guid guid hdr.subject hdr.from imap.bodystructure body.preview";
pub(super) const VIEW_FIELDS: &str =
    "uid flags date.received size.virtual mailbox mailbox-guid guid hdr body imap.bodystructure body.preview";
const BACKEND: &str = "message-json-parser";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRow {
    uid: String,
    flags: String,
    #[serde(rename = "date.received")]
    date_received: String,
    #[serde(rename = "size.virtual")]
    size_virtual: String,
    mailbox: String,
    #[serde(rename = "mailbox-guid")]
    mailbox_guid: String,
    guid: String,
    #[serde(rename = "hdr.subject")]
    subject: Option<String>,
    #[serde(rename = "hdr.from")]
    from: Option<String>,
    hdr: Option<String>,
    body: Option<String>,
    #[serde(rename = "imap.bodystructure")]
    bodystructure: Option<String>,
    #[serde(rename = "body.preview")]
    preview: Option<String>,
}

fn error(reason: &str) -> MailboxBackendError {
    MailboxBackendError {
        backend: BACKEND,
        reason: reason.into(),
    }
}

fn rows(
    execution: &CommandExecution,
    maximum: usize,
) -> Result<Vec<FetchRow>, MailboxBackendError> {
    if execution.status_code != 0 {
        // Fetch diagnostics can contain private content. Retain only the status.
        return Err(error(&format!(
            "native fetch exited with status {}",
            execution.status_code
        )));
    }
    if execution.stdout.len() > crate::auth::DEFAULT_EXTERNAL_COMMAND_OUTPUT_MAX_BYTES {
        return Err(error("native fetch output exceeded its byte limit"));
    }
    let rows: Vec<FetchRow> = serde_json::from_str(&execution.stdout)
        .map_err(|_| error("native fetch returned invalid or inconsistent JSON fields"))?;
    if rows.len() > maximum {
        return Err(error("native fetch exceeded its result limit"));
    }
    let mut identities = BTreeSet::new();
    for row in &rows {
        if !identities.insert((&row.mailbox, &row.uid)) {
            return Err(error("native fetch returned duplicate message identities"));
        }
    }
    Ok(rows)
}

impl FetchRow {
    fn common(
        &self,
        mailbox_max: usize,
        date_max: usize,
        flags_max: usize,
    ) -> Result<(u64, u64, Vec<String>, MessageMetadata), MailboxBackendError> {
        MailboxEntry::new(
            MailboxListingPolicy {
                mailbox_name_max_len: mailbox_max,
                max_mailboxes: 1,
            },
            &self.mailbox,
        )?;
        let uid = self
            .uid
            .parse::<u32>()
            .ok()
            .filter(|uid| *uid > 0)
            .ok_or_else(|| error("native message UID is invalid"))?;
        if self.uid != uid.to_string() {
            return Err(error("native message UID is not canonical"));
        }
        let size = self
            .size_virtual
            .parse::<u64>()
            .map_err(|_| error("native message size is invalid"))?;
        validate_bounded_string(
            "date.received",
            &self.date_received,
            date_max,
            BACKEND,
            false,
            false,
        )?;
        validate_bounded_string("flags", &self.flags, flags_max, BACKEND, true, false)?;
        let metadata = MessageMetadata {
            version: MessageVersion::new(self.mailbox_guid.clone(), self.guid.clone())?,
            attachment_count: self.bodystructure.as_deref().and_then(attachment_count),
            preview: message_preview(self.preview.as_deref(), self.bodystructure.as_deref()),
        };
        Ok((
            u64::from(uid),
            size,
            self.flags.split_whitespace().map(str::to_string).collect(),
            metadata,
        ))
    }

    fn summary(self, policy: MessageListPolicy) -> Result<MessageSummary, MailboxBackendError> {
        if self.hdr.is_some() || self.body.is_some() {
            return Err(error(
                "native summary unexpectedly contained message content",
            ));
        }
        let (uid, size_virtual, flags, metadata) = self.common(
            policy.mailbox_name_max_len,
            policy.message_date_max_len,
            policy.message_flag_string_max_len,
        )?;
        let header = |value: Option<String>| -> Result<Option<String>, MailboxBackendError> {
            let value = value
                .map(|value| normalize_header_summary_value(&value))
                .filter(|value| !value.is_empty());
            if let Some(value) = &value {
                validate_bounded_string(
                    "summary header",
                    value,
                    policy.header_value_max_len,
                    BACKEND,
                    true,
                    false,
                )?;
            }
            Ok(value)
        };
        Ok(MessageSummary {
            metadata: Some(metadata),
            mailbox_name: self.mailbox,
            uid,
            flags,
            date_received: self.date_received,
            size_virtual,
            subject: header(self.subject)?,
            from: header(self.from)?,
        })
    }
}

pub(super) fn parse_json_summaries(
    policy: MessageListPolicy,
    execution: &CommandExecution,
) -> Result<Vec<MessageSummary>, MailboxBackendError> {
    rows(execution, policy.max_messages)?
        .into_iter()
        .map(|row| row.summary(policy))
        .collect()
}

pub(super) fn parse_json_search(
    policy: MessageSearchPolicy,
    execution: &CommandExecution,
) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
    let list_policy = MessageListPolicy {
        mailbox_name_max_len: policy.mailbox_name_max_len,
        max_messages: policy.max_results,
        message_date_max_len: policy.message_date_max_len,
        message_flag_string_max_len: policy.message_flag_string_max_len,
        header_value_max_len: policy.header_value_max_len,
    };
    parse_json_summaries(list_policy, execution).map(|rows| {
        rows.into_iter()
            .map(|row| MessageSearchResult {
                metadata: row.metadata,
                mailbox_name: row.mailbox_name,
                uid: row.uid,
                flags: row.flags,
                date_received: row.date_received,
                size_virtual: row.size_virtual,
                subject: row.subject,
                from: row.from,
            })
            .collect()
    })
}

pub(super) fn parse_json_view(
    policy: MessageViewPolicy,
    execution: &CommandExecution,
) -> Result<MessageView, MailboxBackendError> {
    let mut rows = rows(execution, 1)?;
    let row = rows.pop().ok_or_else(|| MailboxBackendError {
        backend: "message-view-not-found",
        reason: "no message matched the request".into(),
    })?;
    let (uid, size_virtual, flags, metadata) = row.common(
        policy.mailbox_name_max_len,
        policy.message_date_max_len,
        policy.message_flag_string_max_len,
    )?;
    let header_block = row
        .hdr
        .ok_or_else(|| error("native view omitted message headers"))?;
    let body_text = row
        .body
        .ok_or_else(|| error("native view omitted message body"))?;
    validate_bounded_string(
        "headers",
        &header_block,
        policy.message_header_max_len,
        BACKEND,
        true,
        true,
    )?;
    validate_bounded_string(
        "body",
        &body_text,
        policy.message_body_max_len,
        BACKEND,
        true,
        true,
    )?;
    Ok(MessageView {
        metadata: Some(metadata),
        mailbox_name: row.mailbox,
        uid,
        flags,
        date_received: row.date_received,
        size_virtual,
        header_block,
        body_text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(row: serde_json::Value) -> CommandExecution {
        CommandExecution {
            status_code: 0,
            stdout: serde_json::to_string(&vec![row]).expect("fixture"),
            stderr: String::new(),
        }
    }

    fn row() -> serde_json::Value {
        serde_json::json!({"uid":"1", "flags":"\\Seen", "date.received":"2026-09-30 00:00:00", "size.virtual":"12",
            "mailbox":"INBOX", "mailbox-guid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "guid":"fixture.M1P2.obsd1,S=12,W=12",
            "hdr.subject":"Native fixture", "hdr.from":"fixture@example.test",
            "imap.bodystructure":"\"text\" \"plain\" NIL NIL NIL \"7bit\" 12 1 NIL NIL NIL NIL"})
    }

    #[test]
    fn structured_headers_cannot_replace_identity_and_metadata_is_real() {
        let mut fixture = row();
        fixture["hdr.subject"] =
            "A quoted \"subject\" with hdr.from=literal and a\n folded value".into();
        let parsed = parse_json_summaries(MessageListPolicy::default(), &execution(fixture))
            .expect("valid fixture");
        assert_eq!(parsed[0].uid, 1);
        assert_eq!(parsed[0].from.as_deref(), Some("fixture@example.test"));
        assert!(parsed[0]
            .subject
            .as_deref()
            .is_some_and(|value| value.contains("a folded")));
        assert_eq!(
            parsed[0]
                .metadata
                .as_ref()
                .and_then(|value| value.attachment_count),
            Some(0)
        );
    }

    #[test]
    fn native_preview_is_optional_bounded_and_suppressed_for_encryption() {
        for (preview, structure, expected) in [
            (
                Some("Public\n preview"),
                "\"text\" \"plain\" NIL NIL NIL \"7bit\" 12 1",
                Some("Public preview"),
            ),
            (None, "\"text\" \"plain\" NIL NIL NIL \"7bit\" 12 1", None),
            (
                Some("private"),
                "\"application\" \"pgp-encrypted\" NIL NIL NIL \"7bit\" 12",
                None,
            ),
            (Some("private"), "invalid", None),
        ] {
            let mut fixture = row();
            fixture["imap.bodystructure"] = structure.into();
            fixture["body.preview"] = preview.into();
            let parsed = parse_json_summaries(MessageListPolicy::default(), &execution(fixture))
                .expect("native response");
            assert_eq!(
                parsed[0]
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.preview.as_deref()),
                expected
            );
        }
    }

    #[test]
    fn malformed_duplicate_or_unknown_fields_and_duplicate_messages_fail_closed() {
        for field in [
            "uid",
            "mailbox-guid",
            "guid",
            "flags",
            "date.received",
            "size.virtual",
        ] {
            let mut fixture = row();
            fixture.as_object_mut().expect("fixture").remove(field);
            assert!(
                parse_json_summaries(MessageListPolicy::default(), &execution(fixture)).is_err()
            );
        }
        let mut output = execution(row());
        output.stdout = output.stdout.replacen("{", "{\"uid\":\"2\",", 1);
        assert!(parse_json_summaries(MessageListPolicy::default(), &output).is_err());
        let mut fixture = row();
        fixture["unexpected"] = "value".into();
        assert!(parse_json_summaries(MessageListPolicy::default(), &execution(fixture)).is_err());
        output.stdout = serde_json::to_string(&vec![row(), row()]).expect("fixture");
        assert!(parse_json_summaries(MessageListPolicy::default(), &output).is_err());
        output.status_code = 1;
        output.stdout = "private fixture body".into();
        output.stderr = "private fixture header".into();
        let error = parse_json_summaries(MessageListPolicy::default(), &output)
            .expect_err("failed native command");
        assert!(!error.reason.contains("private fixture"));
    }
}
