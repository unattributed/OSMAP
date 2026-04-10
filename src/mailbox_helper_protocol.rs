//! Mailbox-helper protocol types and bounded parsing helpers.
//!
//! This module keeps the line-oriented helper protocol separate from the Unix
//! socket client/server transport code so the helper boundary stays easier to
//! review.

use std::collections::BTreeMap;

use crate::attachment::{
    AttachmentDownloadPolicy, AttachmentDownloadRequest, DownloadedAttachment,
};
use crate::mailbox::{
    MailboxEntry, MailboxListingPolicy, MessageListPolicy, MessageListRequest, MessageMovePolicy,
    MessageMoveRequest, MessageSearchPolicy, MessageSearchRequest, MessageSearchResult,
    MessageSummary, MessageView, MessageViewPolicy, MessageViewRequest,
};

/// Supported helper requests for the first mailbox-read slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MailboxHelperRequest {
    MailboxList {
        canonical_username: String,
    },
    MessageList {
        canonical_username: String,
        mailbox_name: String,
    },
    MessageSearch {
        canonical_username: String,
        mailbox_name: String,
        query: String,
    },
    MessageView {
        canonical_username: String,
        mailbox_name: String,
        uid: u64,
    },
    AttachmentDownload {
        canonical_username: String,
        mailbox_name: String,
        uid: u64,
        part_path: String,
    },
    MessageMove {
        canonical_username: String,
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
    },
}

/// Supported helper responses for the first mailbox-read slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MailboxHelperResponse {
    MailboxListOk {
        mailboxes: Vec<MailboxEntry>,
    },
    MessageListOk {
        mailbox_name: String,
        messages: Vec<MessageSummary>,
    },
    MessageSearchOk {
        mailbox_name: String,
        query: String,
        results: Vec<MessageSearchResult>,
    },
    MessageViewOk {
        message: Box<MessageView>,
    },
    AttachmentDownloadOk {
        attachment: Box<DownloadedAttachment>,
    },
    MessageMoveOk {
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
    },
    Error {
        backend: String,
        reason: String,
    },
}

pub(super) fn encode_request(request: &MailboxHelperRequest) -> String {
    match request {
        MailboxHelperRequest::MailboxList { canonical_username } => format!(
            "operation=mailbox_list\ncanonical_username={canonical_username}\n"
        ),
        MailboxHelperRequest::MessageList {
            canonical_username,
            mailbox_name,
        } => format!(
            "operation=message_list\ncanonical_username={canonical_username}\nmailbox_name={mailbox_name}\n"
        ),
        MailboxHelperRequest::MessageSearch {
            canonical_username,
            mailbox_name,
            query,
        } => format!(
            "operation=message_search\ncanonical_username={canonical_username}\nmailbox_name={mailbox_name}\nquery={query}\n"
        ),
        MailboxHelperRequest::MessageView {
            canonical_username,
            mailbox_name,
            uid,
        } => format!(
            "operation=message_view\ncanonical_username={canonical_username}\nmailbox_name={mailbox_name}\nuid={uid}\n"
        ),
        MailboxHelperRequest::AttachmentDownload {
            canonical_username,
            mailbox_name,
            uid,
            part_path,
        } => format!(
            "operation=attachment_download\ncanonical_username={canonical_username}\nmailbox_name={mailbox_name}\nuid={uid}\npart_path={part_path}\n"
        ),
        MailboxHelperRequest::MessageMove {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        } => format!(
            "operation=message_move\ncanonical_username={canonical_username}\nsource_mailbox_name={source_mailbox_name}\ndestination_mailbox_name={destination_mailbox_name}\nuid={uid}\n"
        ),
    }
}

pub(super) fn parse_request(input: &str) -> Result<MailboxHelperRequest, String> {
    let fields = parse_kv_lines(input)?;
    let operation = require_field(&fields, "operation")?;
    let canonical_username = require_field(&fields, "canonical_username")?.to_string();
    validate_canonical_username(&canonical_username)?;

    match operation {
        "mailbox_list" => Ok(MailboxHelperRequest::MailboxList { canonical_username }),
        "message_list" => {
            let mailbox_name = require_field(&fields, "mailbox_name")?.to_string();
            let _ = MessageListRequest::new(MessageListPolicy::default(), mailbox_name.clone())
                .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageList {
                canonical_username,
                mailbox_name,
            })
        }
        "message_search" => {
            let mailbox_name = require_field(&fields, "mailbox_name")?.to_string();
            let query = require_field(&fields, "query")?.to_string();
            let request = MessageSearchRequest::new(
                MessageSearchPolicy::default(),
                mailbox_name.clone(),
                query,
            )
            .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageSearch {
                canonical_username,
                mailbox_name: request.mailbox_name,
                query: request.query,
            })
        }
        "message_view" => {
            let mailbox_name = require_field(&fields, "mailbox_name")?.to_string();
            let uid = require_field(&fields, "uid")?
                .parse::<u64>()
                .map_err(|error| format!("invalid helper uid: {error}"))?;
            let request =
                MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name.clone(), uid)
                    .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageView {
                canonical_username,
                mailbox_name: request.mailbox_name,
                uid: request.uid,
            })
        }
        "attachment_download" => {
            let mailbox_name = require_field(&fields, "mailbox_name")?.to_string();
            let uid = require_field(&fields, "uid")?
                .parse::<u64>()
                .map_err(|error| format!("invalid helper uid: {error}"))?;
            let message_request =
                MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name.clone(), uid)
                    .map_err(|error| error.reason)?;
            let attachment_request = AttachmentDownloadRequest::new(
                AttachmentDownloadPolicy::default(),
                require_field(&fields, "part_path")?.to_string(),
            )
            .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::AttachmentDownload {
                canonical_username,
                mailbox_name: message_request.mailbox_name,
                uid: message_request.uid,
                part_path: attachment_request.part_path,
            })
        }
        "message_move" => {
            let source_mailbox_name = require_field(&fields, "source_mailbox_name")?.to_string();
            let destination_mailbox_name =
                require_field(&fields, "destination_mailbox_name")?.to_string();
            let uid = require_field(&fields, "uid")?
                .parse::<u64>()
                .map_err(|error| format!("invalid helper uid: {error}"))?;
            let request = MessageMoveRequest::new(
                MessageMovePolicy::default(),
                source_mailbox_name,
                destination_mailbox_name,
                uid,
            )
            .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageMove {
                canonical_username,
                source_mailbox_name: request.source_mailbox_name,
                destination_mailbox_name: request.destination_mailbox_name,
                uid: request.uid,
            })
        }
        _ => Err(format!("unsupported helper operation: {operation}")),
    }
}

pub(super) fn encode_response(response: &MailboxHelperResponse) -> String {
    match response {
        MailboxHelperResponse::MailboxListOk { mailboxes } => {
            let mut output = format!(
                "status=ok\noperation=mailbox_list\nmailbox_count={}\n",
                mailboxes.len()
            );
            for mailbox in mailboxes {
                output.push_str("mailbox=");
                output.push_str(&mailbox.name);
                output.push('\n');
            }
            output
        }
        MailboxHelperResponse::MessageListOk {
            mailbox_name,
            messages,
        } => {
            let mut output = format!(
                "status=ok\noperation=message_list\nmailbox_name={mailbox_name}\nmessage_count={}\n",
                messages.len()
            );
            for message in messages {
                output.push_str("message_uid=");
                output.push_str(&message.uid.to_string());
                output.push('\n');
                output.push_str("message_flags=");
                output.push_str(&message.flags.join(","));
                output.push('\n');
                output.push_str("message_date_received=");
                output.push_str(&message.date_received);
                output.push('\n');
                output.push_str("message_size_virtual=");
                output.push_str(&message.size_virtual.to_string());
                output.push('\n');
                output.push_str("message_mailbox=");
                output.push_str(&message.mailbox_name);
                output.push('\n');
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageSearchOk {
            mailbox_name,
            query,
            results,
        } => {
            let mut output = format!(
                "status=ok\noperation=message_search\nmailbox_name={mailbox_name}\nquery={query}\nmessage_count={}\n",
                results.len()
            );
            for result in results {
                output.push_str("message_uid=");
                output.push_str(&result.uid.to_string());
                output.push('\n');
                output.push_str("message_flags=");
                output.push_str(&result.flags.join(","));
                output.push('\n');
                output.push_str("message_date_received=");
                output.push_str(&result.date_received);
                output.push('\n');
                output.push_str("message_size_virtual=");
                output.push_str(&result.size_virtual.to_string());
                output.push('\n');
                output.push_str("message_mailbox=");
                output.push_str(&result.mailbox_name);
                output.push('\n');
                output.push_str("message_subject=");
                output.push_str(result.subject.as_deref().unwrap_or(""));
                output.push('\n');
                output.push_str("message_from=");
                output.push_str(result.from.as_deref().unwrap_or(""));
                output.push('\n');
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageViewOk { message } => format!(
            "status=ok\noperation=message_view\nmessage_uid={}\nmessage_flags={}\nmessage_date_received={}\nmessage_size_virtual={}\nmessage_mailbox={}\nmessage_header_block_b64={}\nmessage_body_text_b64={}\n",
            message.uid,
            message.flags.join(","),
            message.date_received,
            message.size_virtual,
            message.mailbox_name,
            encode_base64(message.header_block.as_bytes()),
            encode_base64(message.body_text.as_bytes()),
        ),
        MailboxHelperResponse::AttachmentDownloadOk { attachment } => format!(
            "status=ok\noperation=attachment_download\nattachment_mailbox_name={}\nattachment_uid={}\nattachment_part_path={}\nattachment_filename={}\nattachment_content_type={}\nattachment_body_b64={}\n",
            attachment.mailbox_name,
            attachment.uid,
            attachment.part_path,
            attachment.filename,
            attachment.content_type,
            encode_base64(&attachment.body),
        ),
        MailboxHelperResponse::MessageMoveOk {
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        } => format!(
            "status=ok\noperation=message_move\nsource_mailbox_name={source_mailbox_name}\ndestination_mailbox_name={destination_mailbox_name}\nuid={uid}\n"
        ),
        MailboxHelperResponse::Error { backend, reason } => {
            format!("status=error\nbackend={backend}\nreason={reason}\n")
        }
    }
}

pub(super) fn parse_response(
    mailbox_policy: MailboxListingPolicy,
    message_policy: MessageListPolicy,
    search_policy: MessageSearchPolicy,
    message_view_policy: MessageViewPolicy,
    input: &str,
) -> Result<MailboxHelperResponse, String> {
    let mut status = None::<String>;
    let mut operation = None::<String>;
    let mut backend = None::<String>;
    let mut reason = None::<String>;
    let mut mailboxes = Vec::<MailboxEntry>::new();
    let mut mailbox_name = None::<String>;
    let mut query = None::<String>;
    let mut messages = Vec::<MessageSummary>::new();
    let mut search_results = Vec::<MessageSearchResult>::new();
    let mut current_message_fields = BTreeMap::<String, String>::new();
    let mut attachment_fields = BTreeMap::<String, String>::new();
    let mut source_mailbox_name = None::<String>;
    let mut destination_mailbox_name = None::<String>;
    let mut moved_uid = None::<u64>;

    for raw_line in input.lines() {
        if raw_line.is_empty() {
            continue;
        }
        let (key, value) = raw_line
            .split_once('=')
            .ok_or_else(|| format!("malformed helper response line: {raw_line:?}"))?;
        match key {
            "status" => status = Some(value.to_string()),
            "operation" => operation = Some(value.to_string()),
            "backend" => backend = Some(value.to_string()),
            "reason" => reason = Some(value.to_string()),
            "mailbox_name" => mailbox_name = Some(value.to_string()),
            "query" => query = Some(value.to_string()),
            "source_mailbox_name" => source_mailbox_name = Some(value.to_string()),
            "destination_mailbox_name" => destination_mailbox_name = Some(value.to_string()),
            "attachment_mailbox_name"
            | "attachment_uid"
            | "attachment_part_path"
            | "attachment_filename"
            | "attachment_content_type"
            | "attachment_body_b64" => {
                if attachment_fields
                    .insert(key.to_string(), value.to_string())
                    .is_some()
                {
                    return Err(format!(
                        "duplicate attachment field in helper response: {key}"
                    ));
                }
            }
            "uid" => {
                moved_uid = Some(
                    value
                        .parse::<u64>()
                        .map_err(|error| format!("invalid helper move uid: {error}"))?,
                )
            }
            "mailbox" => {
                mailboxes.push(
                    MailboxEntry::new(mailbox_policy, value.to_string()).map_err(|error| {
                        format!("invalid helper mailbox entry: {}", error.reason)
                    })?,
                );
            }
            "mailbox_count" => {}
            "message_count" => {}
            "message_uid"
            | "message_flags"
            | "message_date_received"
            | "message_size_virtual"
            | "message_mailbox"
            | "message_subject"
            | "message_from"
            | "message_header_block_b64"
            | "message_body_text_b64" => {
                if current_message_fields
                    .insert(key.to_string(), value.to_string())
                    .is_some()
                {
                    return Err(format!("duplicate message field in helper response: {key}"));
                }
            }
            "message_end" => {
                if value != "1" {
                    return Err(format!("unexpected helper message_end marker: {value}"));
                }
                match operation.as_deref() {
                    Some("message_list") => messages.push(parse_message_summary_fields(
                        message_policy,
                        &current_message_fields,
                    )?),
                    Some("message_search") => search_results.push(parse_message_search_fields(
                        search_policy,
                        &current_message_fields,
                    )?),
                    _ => {
                        return Err(
                            "helper response emitted message_end for unsupported operation"
                                .to_string(),
                        );
                    }
                }
                current_message_fields.clear();
            }
            _ => return Err(format!("unexpected helper response field: {key}")),
        }
    }

    if matches!(
        operation.as_deref(),
        Some("message_list" | "message_search")
    ) && !current_message_fields.is_empty()
    {
        return Err("helper response ended before message_end marker".to_string());
    }

    match status.as_deref() {
        Some("ok") => match operation.as_deref() {
            Some("mailbox_list") => Ok(MailboxHelperResponse::MailboxListOk { mailboxes }),
            Some("message_list") => Ok(MailboxHelperResponse::MessageListOk {
                mailbox_name: mailbox_name.unwrap_or_else(|| "unknown".to_string()),
                messages,
            }),
            Some("message_search") => Ok(MailboxHelperResponse::MessageSearchOk {
                mailbox_name: mailbox_name.unwrap_or_else(|| "unknown".to_string()),
                query: query.unwrap_or_default(),
                results: search_results,
            }),
            Some("message_view") => Ok(MailboxHelperResponse::MessageViewOk {
                message: Box::new(parse_message_view_fields(
                    message_view_policy,
                    &current_message_fields,
                )?),
            }),
            Some("attachment_download") => Ok(MailboxHelperResponse::AttachmentDownloadOk {
                attachment: Box::new(parse_attachment_download_fields(&attachment_fields)?),
            }),
            Some("message_move") => Ok(MailboxHelperResponse::MessageMoveOk {
                source_mailbox_name: source_mailbox_name.ok_or_else(|| {
                    "helper response did not include source_mailbox_name".to_string()
                })?,
                destination_mailbox_name: destination_mailbox_name.ok_or_else(|| {
                    "helper response did not include destination_mailbox_name".to_string()
                })?,
                uid: moved_uid.ok_or_else(|| "helper response did not include uid".to_string())?,
            }),
            Some(other) => Err(format!("unsupported helper response operation: {other}")),
            None => Err("helper response did not include an operation".to_string()),
        },
        Some("error") => Ok(MailboxHelperResponse::Error {
            backend: backend.unwrap_or_else(|| "mailbox-helper".to_string()),
            reason: reason.unwrap_or_else(|| "helper returned an unspecified error".to_string()),
        }),
        Some(other) => Err(format!("unsupported helper response status: {other}")),
        None => Err("helper response did not include a status".to_string()),
    }
}

fn parse_kv_lines(input: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();

    for raw_line in input.lines() {
        if raw_line.is_empty() {
            continue;
        }
        let (key, value) = raw_line
            .split_once('=')
            .ok_or_else(|| format!("malformed helper line: {raw_line:?}"))?;
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate helper field: {key}"));
        }
    }

    Ok(fields)
}

fn require_field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing helper field: {key}"))
}

fn validate_canonical_username(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("canonical_username must not be empty".to_string());
    }
    if value.len() > crate::auth::DEFAULT_USERNAME_MAX_LEN {
        return Err(format!(
            "canonical_username exceeded maximum length of {} bytes",
            crate::auth::DEFAULT_USERNAME_MAX_LEN
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("canonical_username contains control characters".to_string());
    }

    Ok(())
}

fn parse_message_summary_fields(
    policy: MessageListPolicy,
    fields: &BTreeMap<String, String>,
) -> Result<MessageSummary, String> {
    let mailbox_name = require_field(fields, "message_mailbox")?.to_string();
    let _ = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: 1,
        },
        mailbox_name.clone(),
    )
    .map_err(|error| error.reason)?;

    let uid = require_field(fields, "message_uid")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message uid: {error}"))?;
    if uid == 0 {
        return Err("helper message uid must be greater than zero".to_string());
    }

    let date_received = require_field(fields, "message_date_received")?.to_string();
    if date_received.is_empty() {
        return Err("helper message date_received must not be empty".to_string());
    }
    if date_received.len() > policy.message_date_max_len {
        return Err(format!(
            "helper message date_received exceeded maximum length of {} bytes",
            policy.message_date_max_len
        ));
    }
    if date_received.chars().any(char::is_control) {
        return Err("helper message date_received contains control characters".to_string());
    }

    let size_virtual = require_field(fields, "message_size_virtual")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message size_virtual: {error}"))?;

    let flags_string = require_field(fields, "message_flags")?.to_string();
    if flags_string.len() > policy.message_flag_string_max_len {
        return Err(format!(
            "helper message flags exceeded maximum length of {} bytes",
            policy.message_flag_string_max_len
        ));
    }
    if flags_string.chars().any(char::is_control) {
        return Err("helper message flags contain control characters".to_string());
    }
    let flags = if flags_string.is_empty() {
        Vec::new()
    } else {
        flags_string
            .split(',')
            .map(|value| value.to_string())
            .collect()
    };

    Ok(MessageSummary {
        mailbox_name,
        uid,
        flags,
        date_received,
        size_virtual,
    })
}

fn parse_message_search_fields(
    policy: MessageSearchPolicy,
    fields: &BTreeMap<String, String>,
) -> Result<MessageSearchResult, String> {
    let mailbox_name = require_field(fields, "message_mailbox")?.to_string();
    let _ = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: 1,
        },
        mailbox_name.clone(),
    )
    .map_err(|error| error.reason)?;

    let uid = require_field(fields, "message_uid")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message uid: {error}"))?;
    if uid == 0 {
        return Err("helper message uid must be greater than zero".to_string());
    }

    let date_received = require_field(fields, "message_date_received")?.to_string();
    validate_helper_string(
        "message date_received",
        &date_received,
        policy.message_date_max_len,
        false,
        false,
    )?;

    let size_virtual = require_field(fields, "message_size_virtual")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message size_virtual: {error}"))?;

    let flags_text = require_field(fields, "message_flags")?.to_string();
    validate_helper_string(
        "message flags",
        &flags_text,
        policy.message_flag_string_max_len,
        true,
        false,
    )?;
    let flags = if flags_text.is_empty() {
        Vec::new()
    } else {
        flags_text
            .split(',')
            .map(|value| value.to_string())
            .collect()
    };

    let subject = fields
        .get("message_subject")
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_helper_string(
                "message subject",
                value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value.clone())
        })
        .transpose()?;
    let from = fields
        .get("message_from")
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_helper_string(
                "message from",
                value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value.clone())
        })
        .transpose()?;

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

fn parse_message_view_fields(
    policy: MessageViewPolicy,
    fields: &BTreeMap<String, String>,
) -> Result<MessageView, String> {
    let mailbox_name = require_field(fields, "message_mailbox")?.to_string();
    let _ = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: policy.mailbox_name_max_len,
            max_mailboxes: 1,
        },
        mailbox_name.clone(),
    )
    .map_err(|error| error.reason)?;

    let uid = require_field(fields, "message_uid")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message uid: {error}"))?;
    if uid == 0 {
        return Err("helper message uid must be greater than zero".to_string());
    }

    let date_received = require_field(fields, "message_date_received")?.to_string();
    validate_helper_string(
        "message date_received",
        &date_received,
        policy.message_date_max_len,
        false,
        false,
    )?;

    let size_virtual = require_field(fields, "message_size_virtual")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper message size_virtual: {error}"))?;

    let flags_text = require_field(fields, "message_flags")?.to_string();
    validate_helper_string(
        "message flags",
        &flags_text,
        policy.message_flag_string_max_len,
        true,
        false,
    )?;
    let flags = if flags_text.is_empty() {
        Vec::new()
    } else {
        flags_text
            .split(',')
            .map(|value| value.to_string())
            .collect()
    };

    let header_block = decode_base64_text(
        require_field(fields, "message_header_block_b64")?,
        policy.message_header_max_len,
        "message header_block",
    )?;
    validate_helper_string(
        "message header_block",
        &header_block,
        policy.message_header_max_len,
        false,
        true,
    )?;

    let body_text = decode_base64_text(
        require_field(fields, "message_body_text_b64")?,
        policy.message_body_max_len,
        "message body_text",
    )?;
    validate_helper_string(
        "message body_text",
        &body_text,
        policy.message_body_max_len,
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

fn parse_attachment_download_fields(
    fields: &BTreeMap<String, String>,
) -> Result<DownloadedAttachment, String> {
    let policy = AttachmentDownloadPolicy::default();
    let mailbox_name = require_field(fields, "attachment_mailbox_name")?.to_string();
    let _ = MailboxEntry::new(
        MailboxListingPolicy {
            mailbox_name_max_len: crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
            max_mailboxes: 1,
        },
        mailbox_name.clone(),
    )
    .map_err(|error| error.reason)?;

    let uid = require_field(fields, "attachment_uid")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper attachment uid: {error}"))?;
    if uid == 0 {
        return Err("helper attachment uid must be greater than zero".to_string());
    }

    let part_path = AttachmentDownloadRequest::new(
        policy,
        require_field(fields, "attachment_part_path")?.to_string(),
    )
    .map_err(|error| error.reason)?
    .part_path;

    let filename = require_field(fields, "attachment_filename")?.to_string();
    validate_helper_string(
        "attachment filename",
        &filename,
        policy.filename_max_len,
        false,
        false,
    )?;

    let content_type = require_field(fields, "attachment_content_type")?.to_string();
    validate_helper_string(
        "attachment content_type",
        &content_type,
        policy.content_type_max_len,
        false,
        false,
    )?;

    let body = decode_base64_bytes(
        require_field(fields, "attachment_body_b64")?,
        policy.download_max_bytes,
        "attachment body",
    )?;

    Ok(DownloadedAttachment {
        mailbox_name,
        uid,
        part_path,
        filename,
        content_type,
        body,
    })
}

fn validate_helper_string(
    field: &str,
    value: &str,
    max_len: usize,
    allow_empty: bool,
    allow_text_whitespace_controls: bool,
) -> Result<(), String> {
    if value.is_empty() && !allow_empty {
        return Err(format!("{field} must not be empty"));
    }

    if value.len() > max_len {
        return Err(format!(
            "{field} exceeded maximum length of {max_len} bytes"
        ));
    }

    if value.chars().any(|ch| {
        ch.is_control() && !(allow_text_whitespace_controls && matches!(ch, '\n' | '\r' | '\t'))
    }) {
        return Err(format!("{field} contains control characters"));
    }

    Ok(())
}

fn encode_base64(bytes: &[u8]) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if bytes.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let byte0 = chunk[0];
        let byte1 = chunk.get(1).copied().unwrap_or(0);
        let byte2 = chunk.get(2).copied().unwrap_or(0);
        let combined = ((byte0 as u32) << 16) | ((byte1 as u32) << 8) | (byte2 as u32);

        output.push(BASE64[((combined >> 18) & 0x3f) as usize] as char);
        output.push(BASE64[((combined >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            output.push(BASE64[((combined >> 6) & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(BASE64[(combined & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn decode_base64_text(input: &str, max_len: usize, field: &str) -> Result<String, String> {
    let bytes = decode_base64_bytes(input, max_len, field)?;
    String::from_utf8(bytes).map_err(|error| format!("{field} was not valid UTF-8: {error}"))
}

fn decode_base64_bytes(input: &str, max_len: usize, field: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let sanitized: Vec<char> = input
        .chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect();
    if (sanitized.len() & 3) != 0 {
        return Err(format!("{field} base64 length was not a multiple of four"));
    }

    let mut output = Vec::with_capacity((sanitized.len() / 4) * 3);
    for chunk in sanitized.chunks(4) {
        let mut values = [0_u8; 4];
        let mut padding = 0usize;

        for (index, ch) in chunk.iter().enumerate() {
            values[index] = match *ch {
                'A'..='Z' => (*ch as u8) - b'A',
                'a'..='z' => (*ch as u8) - b'a' + 26,
                '0'..='9' => (*ch as u8) - b'0' + 52,
                '+' => 62,
                '/' => 63,
                '=' => {
                    padding += 1;
                    0
                }
                _ => return Err(format!("{field} base64 contained invalid characters")),
            };

            if *ch == '=' && index < 2 {
                return Err(format!("{field} base64 used invalid padding"));
            }
        }

        let combined = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | values[3] as u32;

        output.push(((combined >> 16) & 0xff) as u8);
        if padding < 2 {
            output.push(((combined >> 8) & 0xff) as u8);
        }
        if padding < 1 {
            output.push((combined & 0xff) as u8);
        }

        if output.len() > max_len {
            return Err(format!(
                "{field} exceeded maximum length of {max_len} bytes"
            ));
        }
    }

    Ok(output)
}
