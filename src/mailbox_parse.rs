//! Bounded Dovecot flow-output parsing helpers for mailbox operations.
//!
//! Keeping the parser cluster separate from service and backend wiring makes
//! mailbox behavior easier to audit without changing the mailbox interfaces.

use std::collections::BTreeMap;

use super::*;

pub(super) fn parse_doveadm_mailbox_list_output(
    policy: MailboxListingPolicy,
    execution: &CommandExecution,
) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
    if execution.status_code != 0 {
        return Err(MailboxBackendError {
            backend: "doveadm-mailbox-list",
            reason: format!(
                "command exited with status {}: {}",
                execution.status_code,
                concise_command_diagnostics(&execution.stdout, &execution.stderr),
            ),
        });
    }

    let mut mailboxes = Vec::new();

    for raw_line in execution.stdout.lines() {
        if raw_line.is_empty() {
            continue;
        }

        mailboxes.push(MailboxEntry::new(policy, raw_line.to_string())?);
        if mailboxes.len() > policy.max_mailboxes {
            return Err(MailboxBackendError {
                backend: "mailbox-parser",
                reason: format!(
                    "mailbox listing exceeded maximum of {} entries",
                    policy.max_mailboxes
                ),
            });
        }
    }

    Ok(mailboxes)
}

pub(super) fn parse_doveadm_message_list_output(
    policy: MessageListPolicy,
    execution: &CommandExecution,
) -> Result<Vec<MessageSummary>, MailboxBackendError> {
    if execution.status_code != 0 {
        return Err(MailboxBackendError {
            backend: "doveadm-message-list",
            reason: format!(
                "command exited with status {}: {}",
                execution.status_code,
                concise_command_diagnostics(&execution.stdout, &execution.stderr),
            ),
        });
    }

    let mut messages = Vec::new();

    for record in parse_uid_started_flow_records(&execution.stdout, "message-list-parser")? {
        messages.push(parse_message_summary_line(policy, &record)?);
        if messages.len() > policy.max_messages {
            return Err(MailboxBackendError {
                backend: "message-list-parser",
                reason: format!(
                    "message listing exceeded maximum of {} entries",
                    policy.max_messages
                ),
            });
        }
    }

    Ok(messages)
}

pub(super) fn parse_doveadm_message_view_output(
    policy: MessageViewPolicy,
    execution: &CommandExecution,
) -> Result<MessageView, MailboxBackendError> {
    if execution.status_code != 0 {
        return Err(MailboxBackendError {
            backend: "doveadm-message-view",
            reason: format!(
                "command exited with status {}: {}",
                execution.status_code,
                concise_command_diagnostics(&execution.stdout, &execution.stderr),
            ),
        });
    }

    let trimmed = execution.stdout.trim();
    if trimmed.is_empty() {
        return Err(MailboxBackendError {
            backend: "message-view-not-found",
            reason: "no message matched the request".to_string(),
        });
    }

    parse_message_view_record(policy, execution.stdout.trim_end())
}

pub(super) fn parse_doveadm_message_search_output(
    policy: MessageSearchPolicy,
    execution: &CommandExecution,
) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
    if execution.status_code != 0 {
        return Err(MailboxBackendError {
            backend: "doveadm-message-search",
            reason: format!(
                "command exited with status {}: {}",
                execution.status_code,
                concise_command_diagnostics(&execution.stdout, &execution.stderr),
            ),
        });
    }

    let mut results = Vec::new();

    for record in parse_uid_started_flow_records(&execution.stdout, "message-search-parser")? {
        results.push(parse_message_search_result_line(policy, &record)?);
        if results.len() > policy.max_results {
            return Err(MailboxBackendError {
                backend: "message-search-parser",
                reason: format!(
                    "message search exceeded maximum of {} entries",
                    policy.max_results
                ),
            });
        }
    }

    Ok(results)
}

fn parse_message_summary_line(
    policy: MessageListPolicy,
    line: &str,
) -> Result<MessageSummary, MailboxBackendError> {
    let fields = parse_flow_fields(line, "message-list-parser")?;
    let mailbox_name = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        },
        required_flow_field(&fields, "mailbox", "message-list", "message-list-parser")?,
    )?
    .name;
    let uid = parse_u64_value(
        "uid",
        required_flow_field(&fields, "uid", "message-list", "message-list-parser")?,
        "message-list-parser",
    )?;
    let date_received = required_flow_field(
        &fields,
        "date.received",
        "message-list",
        "message-list-parser",
    )?
    .to_string();
    validate_bounded_string(
        "date.received",
        &date_received,
        policy.message_date_max_len,
        "message-list-parser",
        false,
        false,
    )?;

    let flags_text =
        required_flow_field(&fields, "flags", "message-list", "message-list-parser")?.to_string();
    validate_bounded_string(
        "flags",
        &flags_text,
        policy.message_flag_string_max_len,
        "message-list-parser",
        true,
        false,
    )?;
    let flags = parse_flags(&flags_text);

    let size_virtual = parse_u64_value(
        "size.virtual",
        required_flow_field(
            &fields,
            "size.virtual",
            "message-list",
            "message-list-parser",
        )?,
        "message-list-parser",
    )?;
    let subject = optional_summary_header_field(
        &fields,
        "hdr.subject",
        policy.header_value_max_len,
        "message-list-parser",
    )?;
    let from = optional_summary_header_field(
        &fields,
        "hdr.from",
        policy.header_value_max_len,
        "message-list-parser",
    )?;

    Ok(MessageSummary {
        mailbox_name,
        uid,
        flags,
        date_received,
        size_virtual,
        subject,
        from,
    })
}

fn parse_message_view_line(
    policy: MessageViewPolicy,
    line: &str,
) -> Result<MessageView, MailboxBackendError> {
    let fields = parse_flow_fields(line, "message-view-parser")?;
    let mailbox_name = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        },
        required_flow_field(&fields, "mailbox", "message-view", "message-view-parser")?,
    )?
    .name;
    let uid = parse_u64_value(
        "uid",
        required_flow_field(&fields, "uid", "message-view", "message-view-parser")?,
        "message-view-parser",
    )?;
    let date_received = required_flow_field(
        &fields,
        "date.received",
        "message-view",
        "message-view-parser",
    )?
    .to_string();
    validate_bounded_string(
        "date.received",
        &date_received,
        policy.message_date_max_len,
        "message-view-parser",
        false,
        false,
    )?;

    let flags_text =
        required_flow_field(&fields, "flags", "message-view", "message-view-parser")?.to_string();
    validate_bounded_string(
        "flags",
        &flags_text,
        policy.message_flag_string_max_len,
        "message-view-parser",
        true,
        false,
    )?;
    let flags = parse_flags(&flags_text);

    let size_virtual = parse_u64_value(
        "size.virtual",
        required_flow_field(
            &fields,
            "size.virtual",
            "message-view",
            "message-view-parser",
        )?,
        "message-view-parser",
    )?;

    let header_block =
        required_flow_field(&fields, "hdr", "message-view", "message-view-parser")?.to_string();
    validate_bounded_string(
        "hdr",
        &header_block,
        policy.message_header_max_len,
        "message-view-parser",
        false,
        true,
    )?;

    let body_text =
        required_flow_field(&fields, "body", "message-view", "message-view-parser")?.to_string();
    validate_bounded_string(
        "body",
        &body_text,
        policy.message_body_max_len,
        "message-view-parser",
        true,
        true,
    )?;

    Ok(MessageView {
        mailbox_name,
        uid,
        flags,
        date_received,
        size_virtual,
        header_block,
        body_text,
    })
}

fn parse_message_search_result_line(
    policy: MessageSearchPolicy,
    line: &str,
) -> Result<MessageSearchResult, MailboxBackendError> {
    let fields = parse_flow_fields(line, "message-search-parser")?;
    let mailbox_name = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: DEFAULT_MAX_MAILBOXES,
        },
        required_flow_field(
            &fields,
            "mailbox",
            "message-search",
            "message-search-parser",
        )?,
    )?
    .name;
    let uid = parse_u64_value(
        "uid",
        required_flow_field(&fields, "uid", "message-search", "message-search-parser")?,
        "message-search-parser",
    )?;
    let date_received = required_flow_field(
        &fields,
        "date.received",
        "message-search",
        "message-search-parser",
    )?
    .to_string();
    validate_bounded_string(
        "date.received",
        &date_received,
        policy.message_date_max_len,
        "message-search-parser",
        false,
        false,
    )?;

    let flags_text =
        required_flow_field(&fields, "flags", "message-search", "message-search-parser")?
            .to_string();
    validate_bounded_string(
        "flags",
        &flags_text,
        policy.message_flag_string_max_len,
        "message-search-parser",
        true,
        false,
    )?;
    let flags = parse_flags(&flags_text);

    let size_virtual = parse_u64_value(
        "size.virtual",
        required_flow_field(
            &fields,
            "size.virtual",
            "message-search",
            "message-search-parser",
        )?,
        "message-search-parser",
    )?;

    let subject = optional_summary_header_field(
        &fields,
        "hdr.subject",
        policy.header_value_max_len,
        "message-search-parser",
    )?;
    let from = optional_summary_header_field(
        &fields,
        "hdr.from",
        policy.header_value_max_len,
        "message-search-parser",
    )?;

    Ok(MessageSearchResult {
        mailbox_name,
        uid,
        flags,
        date_received,
        size_virtual,
        subject,
        from,
    })
}

fn parse_message_view_record(
    policy: MessageViewPolicy,
    record: &str,
) -> Result<MessageView, MailboxBackendError> {
    if let Some((prefix, remainder)) = record.split_once(" hdr=") {
        if let Some((header_block, body_text)) = remainder
            .split_once("\n body=")
            .or_else(|| remainder.split_once("\nbody="))
        {
            let synthetic = format!(
                "{prefix} hdr=\"{}\" body=\"{}\"",
                escape_flow_quoted_value(header_block),
                escape_flow_quoted_value(body_text),
            );
            return parse_message_view_line(policy, &synthetic);
        }
    }

    let mut parsed = Vec::new();
    for raw_line in record.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        parsed.push(parse_message_view_line(policy, line)?);
    }

    match parsed.len() {
        1 => Ok(parsed.remove(0)),
        count => Err(MailboxBackendError {
            backend: "message-view-parser",
            reason: format!("expected one message record but received {count}"),
        }),
    }
}

fn parse_flow_fields(
    line: &str,
    backend: &'static str,
) -> Result<BTreeMap<String, String>, MailboxBackendError> {
    let mut fields = BTreeMap::new();
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }

        let key_start = index;
        while index < chars.len() && chars[index] != '=' {
            index += 1;
        }
        if index >= chars.len() {
            return Err(MailboxBackendError {
                backend,
                reason: format!("invalid flow field in line {line:?}"),
            });
        }

        let key: String = chars[key_start..index].iter().collect();
        index += 1;

        let mut value = String::new();
        if index < chars.len() && chars[index] == '"' {
            index += 1;
            while index < chars.len() {
                let current = chars[index];
                if current == '\\' {
                    index += 1;
                    if index < chars.len() {
                        value.push(match chars[index] {
                            'n' => '\n',
                            'r' => '\r',
                            't' => '\t',
                            other => other,
                        });
                        index += 1;
                    }
                    continue;
                }
                if current == '"' {
                    index += 1;
                    break;
                }
                value.push(current);
                index += 1;
            }
            let mut suffix = String::new();
            while index < chars.len() {
                if chars[index].is_whitespace() && is_flow_field_boundary(&chars, index) {
                    break;
                }
                suffix.push(chars[index]);
                index += 1;
            }
            value.push_str(suffix.trim_end());
        } else {
            let value_start = index;
            while index < chars.len() {
                if chars[index].is_whitespace() && is_flow_field_boundary(&chars, index) {
                    break;
                }
                index += 1;
            }
            value = chars[value_start..index]
                .iter()
                .collect::<String>()
                .trim_end()
                .to_string();
        }

        fields.insert(key, value);
    }

    Ok(fields)
}

fn parse_uid_started_flow_records(
    output: &str,
    backend: &'static str,
) -> Result<Vec<String>, MailboxBackendError> {
    let mut records = Vec::new();
    let mut current = String::new();

    for raw_line in output.lines() {
        if raw_line.is_empty() {
            continue;
        }

        if raw_line.starts_with("uid=") {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            current.push_str(raw_line);
            continue;
        }

        if current.is_empty() {
            return Err(MailboxBackendError {
                backend,
                reason: format!("flow continuation appeared before first uid record: {raw_line:?}"),
            });
        }

        current.push('\n');
        current.push_str(raw_line);
    }

    if !current.is_empty() {
        records.push(current);
    }

    Ok(records)
}

fn optional_summary_header_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
    max_len: usize,
    backend: &'static str,
) -> Result<Option<String>, MailboxBackendError> {
    optional_flow_field(fields, field)
        .map(normalize_header_summary_value)
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_bounded_string(field, &value, max_len, backend, true, false)?;
            Ok(value)
        })
        .transpose()
}

fn normalize_header_summary_value(value: &str) -> String {
    let mut normalized = String::new();
    let mut pending_space = false;

    for ch in value.chars() {
        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }

        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        normalized.push(ch);
    }

    normalized
}

fn escape_flow_quoted_value(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn is_flow_field_boundary(chars: &[char], whitespace_index: usize) -> bool {
    let mut probe = whitespace_index;
    while probe < chars.len() && chars[probe].is_whitespace() {
        probe += 1;
    }
    if probe >= chars.len() {
        return true;
    }

    let key_start = probe;
    while probe < chars.len() && !chars[probe].is_whitespace() && chars[probe] != '=' {
        probe += 1;
    }

    probe > key_start && probe < chars.len() && chars[probe] == '='
}

fn required_flow_field<'a>(
    fields: &'a BTreeMap<String, String>,
    field: &'static str,
    subject: &'static str,
    backend: &'static str,
) -> Result<&'a str, MailboxBackendError> {
    fields
        .get(field)
        .map(String::as_str)
        .ok_or_else(|| MailboxBackendError {
            backend,
            reason: format!("missing required {subject} field {field}"),
        })
}

fn optional_flow_field<'a>(
    fields: &'a BTreeMap<String, String>,
    field: &'static str,
) -> Option<&'a str> {
    fields.get(field).map(String::as_str)
}

fn parse_u64_value(
    field: &'static str,
    value: &str,
    backend: &'static str,
) -> Result<u64, MailboxBackendError> {
    value.parse::<u64>().map_err(|error| MailboxBackendError {
        backend,
        reason: format!("failed parsing {field}: {error}"),
    })
}

fn validate_bounded_string(
    field: &'static str,
    value: &str,
    max_len: usize,
    backend: &'static str,
    allow_empty: bool,
    allow_text_whitespace_controls: bool,
) -> Result<(), MailboxBackendError> {
    if value.is_empty() && !allow_empty {
        return Err(MailboxBackendError {
            backend,
            reason: format!("{field} must not be empty"),
        });
    }

    if value.len() > max_len {
        return Err(MailboxBackendError {
            backend,
            reason: format!("{field} exceeded maximum length of {max_len} bytes"),
        });
    }

    if value.chars().any(|ch| {
        ch.is_control() && !(allow_text_whitespace_controls && matches!(ch, '\n' | '\r' | '\t'))
    }) {
        return Err(MailboxBackendError {
            backend,
            reason: format!("{field} contains control characters"),
        });
    }

    Ok(())
}

fn parse_flags(flags_text: &str) -> Vec<String> {
    if flags_text.is_empty() {
        return Vec::new();
    }

    flags_text
        .split_whitespace()
        .map(ToString::to_string)
        .collect()
}
