//! Mailbox-helper protocol types and bounded parsing helpers.
//!
//! This module keeps the line-oriented helper protocol separate from the Unix
//! socket client/server transport code so the helper boundary stays easier to
//! review.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

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
        grant: MailboxHelperGrant,
    },
    MessageList {
        canonical_username: String,
        mailbox_name: String,
        grant: MailboxHelperGrant,
    },
    MessageSearch {
        canonical_username: String,
        mailbox_name: String,
        query: String,
        grant: MailboxHelperGrant,
    },
    MessageView {
        canonical_username: String,
        mailbox_name: String,
        uid: u64,
        grant: MailboxHelperGrant,
    },
    AttachmentDownload {
        canonical_username: String,
        mailbox_name: String,
        uid: u64,
        part_path: String,
        grant: MailboxHelperGrant,
    },
    MessageMove {
        canonical_username: String,
        source_mailbox_name: String,
        destination_mailbox_name: String,
        uid: u64,
        grant: MailboxHelperGrant,
    },
}

/// Short-lived helper request grant issued by the browser-facing runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MailboxHelperGrant {
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature: String,
}

impl MailboxHelperGrant {
    pub(super) fn unsigned() -> Self {
        Self {
            issued_at: 0,
            expires_at: 0,
            nonce: String::new(),
            signature: String::new(),
        }
    }
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
        MailboxHelperRequest::MailboxList {
            canonical_username,
            grant,
        } => format!(
            "operation=mailbox_list\ncanonical_username_b64={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::MessageList {
            canonical_username,
            mailbox_name,
            grant,
        } => format!(
            "operation=message_list\ncanonical_username_b64={}\nmailbox_name_b64={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(mailbox_name.as_bytes()),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::MessageSearch {
            canonical_username,
            mailbox_name,
            query,
            grant,
        } => format!(
            "operation=message_search\ncanonical_username_b64={}\nmailbox_name_b64={}\nquery_b64={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(mailbox_name.as_bytes()),
            encode_base64(query.as_bytes()),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::MessageView {
            canonical_username,
            mailbox_name,
            uid,
            grant,
        } => format!(
            "operation=message_view\ncanonical_username_b64={}\nmailbox_name_b64={}\nuid={uid}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(mailbox_name.as_bytes()),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::AttachmentDownload {
            canonical_username,
            mailbox_name,
            uid,
            part_path,
            grant,
        } => format!(
            "operation=attachment_download\ncanonical_username_b64={}\nmailbox_name_b64={}\nuid={uid}\npart_path_b64={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(mailbox_name.as_bytes()),
            encode_base64(part_path.as_bytes()),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::MessageMove {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
            grant,
        } => format!(
            "operation=message_move\ncanonical_username_b64={}\nsource_mailbox_name_b64={}\ndestination_mailbox_name_b64={}\nuid={uid}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(source_mailbox_name.as_bytes()),
            encode_base64(destination_mailbox_name.as_bytes()),
            encode_grant_fields(grant),
        ),
    }
}

pub(super) fn parse_request(input: &str) -> Result<MailboxHelperRequest, String> {
    let fields = parse_kv_lines(input)?;
    let operation = require_field(&fields, "operation")?;
    reject_unknown_request_fields(&fields, operation)?;
    let canonical_username = decode_base64_text(
        require_field(&fields, "canonical_username_b64")?,
        crate::auth::DEFAULT_USERNAME_MAX_LEN,
        "canonical_username",
    )?;
    validate_canonical_username(&canonical_username)?;
    let grant = parse_grant_fields(&fields)?;

    match operation {
        "mailbox_list" => Ok(MailboxHelperRequest::MailboxList {
            canonical_username,
            grant,
        }),
        "message_list" => {
            let mailbox_name = decode_base64_text(
                require_field(&fields, "mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "mailbox_name",
            )?;
            let _ = MessageListRequest::new(MessageListPolicy::default(), mailbox_name.clone())
                .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageList {
                canonical_username,
                mailbox_name,
                grant,
            })
        }
        "message_search" => {
            let mailbox_name = decode_base64_text(
                require_field(&fields, "mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "mailbox_name",
            )?;
            let query = decode_base64_text(
                require_field(&fields, "query_b64")?,
                crate::mailbox::DEFAULT_SEARCH_QUERY_MAX_LEN,
                "query",
            )?;
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
                grant,
            })
        }
        "message_view" => {
            let mailbox_name = decode_base64_text(
                require_field(&fields, "mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "mailbox_name",
            )?;
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
                grant,
            })
        }
        "attachment_download" => {
            let mailbox_name = decode_base64_text(
                require_field(&fields, "mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "mailbox_name",
            )?;
            let uid = require_field(&fields, "uid")?
                .parse::<u64>()
                .map_err(|error| format!("invalid helper uid: {error}"))?;
            let message_request =
                MessageViewRequest::new(MessageViewPolicy::default(), mailbox_name.clone(), uid)
                    .map_err(|error| error.reason)?;
            let attachment_request = AttachmentDownloadRequest::new(
                AttachmentDownloadPolicy::default(),
                decode_base64_text(
                    require_field(&fields, "part_path_b64")?,
                    crate::attachment::DEFAULT_ATTACHMENT_PART_PATH_MAX_LEN,
                    "part_path",
                )?,
            )
            .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::AttachmentDownload {
                canonical_username,
                mailbox_name: message_request.mailbox_name,
                uid: message_request.uid,
                part_path: attachment_request.part_path,
                grant,
            })
        }
        "message_move" => {
            let source_mailbox_name = decode_base64_text(
                require_field(&fields, "source_mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "source_mailbox_name",
            )?;
            let destination_mailbox_name = decode_base64_text(
                require_field(&fields, "destination_mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "destination_mailbox_name",
            )?;
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
                grant,
            })
        }
        _ => Err(format!("unsupported helper operation: {operation}")),
    }
}

pub(super) fn issue_request_grant(
    request: &mut MailboxHelperRequest,
    key: &[u8],
    now_secs: u64,
) -> Result<(), String> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("failed to create helper grant nonce: {error}"))?;
    issue_request_grant_with_nonce(request, key, now_secs, &hex_lower(&nonce))
}

#[cfg(test)]
pub(super) fn issue_request_grant_with_nonce(
    request: &mut MailboxHelperRequest,
    key: &[u8],
    now_secs: u64,
    nonce: &str,
) -> Result<(), String> {
    issue_request_grant_with_nonce_impl(request, key, now_secs, nonce)
}

#[cfg(not(test))]
fn issue_request_grant_with_nonce(
    request: &mut MailboxHelperRequest,
    key: &[u8],
    now_secs: u64,
    nonce: &str,
) -> Result<(), String> {
    issue_request_grant_with_nonce_impl(request, key, now_secs, nonce)
}

fn issue_request_grant_with_nonce_impl(
    request: &mut MailboxHelperRequest,
    key: &[u8],
    now_secs: u64,
    nonce: &str,
) -> Result<(), String> {
    let issued_at = now_secs;
    let expires_at = now_secs.saturating_add(60);
    let mut grant = MailboxHelperGrant {
        issued_at,
        expires_at,
        nonce: nonce.to_string(),
        signature: String::new(),
    };
    grant.signature = sign_request_grant(request, &grant, key)?;
    set_request_grant(request, grant);
    Ok(())
}

pub(super) fn verify_request_grant(
    request: &MailboxHelperRequest,
    key: &[u8],
    now_secs: u64,
) -> Result<(), String> {
    let grant = request_grant(request);
    if grant.signature.is_empty() {
        return Err("helper request grant signature was missing".to_string());
    }
    if grant.nonce.is_empty() {
        return Err("helper request grant nonce was missing".to_string());
    }
    if grant.expires_at < grant.issued_at {
        return Err("helper request grant expiry preceded issue time".to_string());
    }
    if now_secs < grant.issued_at {
        return Err("helper request grant was issued in the future".to_string());
    }
    if now_secs > grant.expires_at {
        return Err("helper request grant expired".to_string());
    }

    let expected = sign_request_grant(request, grant, key)?;
    let expected_bytes = decode_hex_bytes(&expected)?;
    let actual_bytes = decode_hex_bytes(&grant.signature)?;
    if expected_bytes.len() != actual_bytes.len() {
        return Err("helper request grant signature was invalid".to_string());
    }
    let mut diff = 0_u8;
    for (left, right) in expected_bytes.iter().zip(actual_bytes.iter()) {
        diff |= left ^ right;
    }
    if diff != 0 {
        return Err("helper request grant signature was invalid".to_string());
    }
    Ok(())
}

pub(super) fn request_grant(request: &MailboxHelperRequest) -> &MailboxHelperGrant {
    match request {
        MailboxHelperRequest::MailboxList { grant, .. }
        | MailboxHelperRequest::MessageList { grant, .. }
        | MailboxHelperRequest::MessageSearch { grant, .. }
        | MailboxHelperRequest::MessageView { grant, .. }
        | MailboxHelperRequest::AttachmentDownload { grant, .. }
        | MailboxHelperRequest::MessageMove { grant, .. } => grant,
    }
}

fn set_request_grant(request: &mut MailboxHelperRequest, new_grant: MailboxHelperGrant) {
    match request {
        MailboxHelperRequest::MailboxList { grant, .. }
        | MailboxHelperRequest::MessageList { grant, .. }
        | MailboxHelperRequest::MessageSearch { grant, .. }
        | MailboxHelperRequest::MessageView { grant, .. }
        | MailboxHelperRequest::AttachmentDownload { grant, .. }
        | MailboxHelperRequest::MessageMove { grant, .. } => *grant = new_grant,
    }
}

pub(super) fn helper_operation_label(request: &MailboxHelperRequest) -> &'static str {
    match request {
        MailboxHelperRequest::MailboxList { .. } => "mailbox_list",
        MailboxHelperRequest::MessageList { .. } => "message_list",
        MailboxHelperRequest::MessageSearch { .. } => "message_search",
        MailboxHelperRequest::MessageView { .. } => "message_view",
        MailboxHelperRequest::AttachmentDownload { .. } => "attachment_download",
        MailboxHelperRequest::MessageMove { .. } => "message_move",
    }
}

fn sign_request_grant(
    request: &MailboxHelperRequest,
    grant: &MailboxHelperGrant,
    key: &[u8],
) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| format!("helper grant key was invalid: {error}"))?;
    mac.update(canonical_grant_payload(request, grant).as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn canonical_grant_payload(request: &MailboxHelperRequest, grant: &MailboxHelperGrant) -> String {
    let mut fields = vec![
        "v1".to_string(),
        helper_operation_label(request).to_string(),
        grant.issued_at.to_string(),
        grant.expires_at.to_string(),
        grant.nonce.clone(),
    ];
    match request {
        MailboxHelperRequest::MailboxList {
            canonical_username, ..
        } => fields.push(canonical_username.clone()),
        MailboxHelperRequest::MessageList {
            canonical_username,
            mailbox_name,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_name.clone());
        }
        MailboxHelperRequest::MessageSearch {
            canonical_username,
            mailbox_name,
            query,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_name.clone());
            fields.push(query.clone());
        }
        MailboxHelperRequest::MessageView {
            canonical_username,
            mailbox_name,
            uid,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_name.clone());
            fields.push(uid.to_string());
        }
        MailboxHelperRequest::AttachmentDownload {
            canonical_username,
            mailbox_name,
            uid,
            part_path,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_name.clone());
            fields.push(uid.to_string());
            fields.push(part_path.clone());
        }
        MailboxHelperRequest::MessageMove {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(source_mailbox_name.clone());
            fields.push(destination_mailbox_name.clone());
            fields.push(uid.to_string());
        }
    }
    fields.join("\0")
}

fn encode_grant_fields(grant: &MailboxHelperGrant) -> String {
    format!(
        "grant_issued_at={}\ngrant_expires_at={}\ngrant_nonce={}\ngrant_signature={}\n",
        grant.issued_at, grant.expires_at, grant.nonce, grant.signature
    )
}

fn parse_grant_fields(fields: &BTreeMap<String, String>) -> Result<MailboxHelperGrant, String> {
    let issued_at = require_field(fields, "grant_issued_at")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper grant issued_at: {error}"))?;
    let expires_at = require_field(fields, "grant_expires_at")?
        .parse::<u64>()
        .map_err(|error| format!("invalid helper grant expires_at: {error}"))?;
    let nonce = require_field(fields, "grant_nonce")?.to_string();
    if !nonce
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("helper grant nonce must be lower-case hex".to_string());
    }
    let signature = require_field(fields, "grant_signature")?.to_string();
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("helper grant signature must be a lower-case sha256 hex digest".to_string());
    }

    Ok(MailboxHelperGrant {
        issued_at,
        expires_at,
        nonce,
        signature,
    })
}

pub(super) fn encode_response(response: &MailboxHelperResponse) -> String {
    match response {
        MailboxHelperResponse::MailboxListOk { mailboxes } => {
            let mut output = format!(
                "status=ok\noperation=mailbox_list\nmailbox_count={}\n",
                mailboxes.len()
            );
            for mailbox in mailboxes {
                output.push_str("mailbox_b64=");
                output.push_str(&encode_base64(mailbox.name.as_bytes()));
                output.push('\n');
            }
            output
        }
        MailboxHelperResponse::MessageListOk {
            mailbox_name,
            messages,
        } => {
            let mut output = format!(
                "status=ok\noperation=message_list\nmailbox_name_b64={}\nmessage_count={}\n",
                encode_base64(mailbox_name.as_bytes()),
                messages.len()
            );
            for message in messages {
                output.push_str("message_uid=");
                output.push_str(&message.uid.to_string());
                output.push('\n');
                output.push_str("message_flags_b64=");
                output.push_str(&encode_base64(message.flags.join(",").as_bytes()));
                output.push('\n');
                output.push_str("message_date_received_b64=");
                output.push_str(&encode_base64(message.date_received.as_bytes()));
                output.push('\n');
                output.push_str("message_size_virtual=");
                output.push_str(&message.size_virtual.to_string());
                output.push('\n');
                output.push_str("message_mailbox_b64=");
                output.push_str(&encode_base64(message.mailbox_name.as_bytes()));
                output.push('\n');
                output.push_str("message_subject_b64=");
                output.push_str(&encode_base64(
                    message.subject.as_deref().unwrap_or("").as_bytes(),
                ));
                output.push('\n');
                output.push_str("message_from_b64=");
                output.push_str(&encode_base64(
                    message.from.as_deref().unwrap_or("").as_bytes(),
                ));
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
                "status=ok\noperation=message_search\nmailbox_name_b64={}\nquery_b64={}\nmessage_count={}\n",
                encode_base64(mailbox_name.as_bytes()),
                encode_base64(query.as_bytes()),
                results.len()
            );
            for result in results {
                output.push_str("message_uid=");
                output.push_str(&result.uid.to_string());
                output.push('\n');
                output.push_str("message_flags_b64=");
                output.push_str(&encode_base64(result.flags.join(",").as_bytes()));
                output.push('\n');
                output.push_str("message_date_received_b64=");
                output.push_str(&encode_base64(result.date_received.as_bytes()));
                output.push('\n');
                output.push_str("message_size_virtual=");
                output.push_str(&result.size_virtual.to_string());
                output.push('\n');
                output.push_str("message_mailbox_b64=");
                output.push_str(&encode_base64(result.mailbox_name.as_bytes()));
                output.push('\n');
                output.push_str("message_subject_b64=");
                output.push_str(&encode_base64(
                    result.subject.as_deref().unwrap_or("").as_bytes(),
                ));
                output.push('\n');
                output.push_str("message_from_b64=");
                output.push_str(&encode_base64(result.from.as_deref().unwrap_or("").as_bytes()));
                output.push('\n');
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageViewOk { message } => format!(
            "status=ok\noperation=message_view\nmessage_uid={}\nmessage_flags_b64={}\nmessage_date_received_b64={}\nmessage_size_virtual={}\nmessage_mailbox_b64={}\nmessage_header_block_b64={}\nmessage_body_text_b64={}\n",
            message.uid,
            encode_base64(message.flags.join(",").as_bytes()),
            encode_base64(message.date_received.as_bytes()),
            message.size_virtual,
            encode_base64(message.mailbox_name.as_bytes()),
            encode_base64(message.header_block.as_bytes()),
            encode_base64(message.body_text.as_bytes()),
        ),
        MailboxHelperResponse::AttachmentDownloadOk { attachment } => format!(
            "status=ok\noperation=attachment_download\nattachment_mailbox_name_b64={}\nattachment_uid={}\nattachment_part_path_b64={}\nattachment_filename_b64={}\nattachment_content_type_b64={}\nattachment_body_b64={}\n",
            encode_base64(attachment.mailbox_name.as_bytes()),
            attachment.uid,
            encode_base64(attachment.part_path.as_bytes()),
            encode_base64(attachment.filename.as_bytes()),
            encode_base64(attachment.content_type.as_bytes()),
            encode_base64(&attachment.body),
        ),
        MailboxHelperResponse::MessageMoveOk {
            source_mailbox_name,
            destination_mailbox_name,
            uid,
        } => format!(
            "status=ok\noperation=message_move\nsource_mailbox_name_b64={}\ndestination_mailbox_name_b64={}\nuid={uid}\n",
            encode_base64(source_mailbox_name.as_bytes()),
            encode_base64(destination_mailbox_name.as_bytes()),
        ),
        MailboxHelperResponse::Error { backend, reason } => {
            format!(
                "status=error\nbackend_b64={}\nreason_b64={}\n",
                encode_base64(backend.as_bytes()),
                encode_base64(reason.as_bytes())
            )
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
            "backend_b64" => {
                backend = Some(decode_base64_text(value, 128, "helper error backend")?)
            }
            "reason_b64" => reason = Some(decode_base64_text(value, 2048, "helper error reason")?),
            "mailbox_name_b64" => {
                mailbox_name = Some(decode_base64_text(
                    value,
                    crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                    "helper mailbox_name",
                )?)
            }
            "query_b64" => {
                query = Some(decode_base64_text(
                    value,
                    crate::mailbox::DEFAULT_SEARCH_QUERY_MAX_LEN,
                    "helper query",
                )?)
            }
            "source_mailbox_name_b64" => {
                source_mailbox_name = Some(decode_base64_text(
                    value,
                    crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                    "helper source_mailbox_name",
                )?)
            }
            "destination_mailbox_name_b64" => {
                destination_mailbox_name = Some(decode_base64_text(
                    value,
                    crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                    "helper destination_mailbox_name",
                )?)
            }
            "attachment_mailbox_name_b64"
            | "attachment_uid"
            | "attachment_part_path_b64"
            | "attachment_filename_b64"
            | "attachment_content_type_b64"
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
            "mailbox_b64" => {
                let mailbox_name = decode_base64_text(
                    value,
                    mailbox_policy.mailbox_name_max_len,
                    "helper mailbox",
                )?;
                mailboxes.push(
                    MailboxEntry::new(mailbox_policy, mailbox_name).map_err(|error| {
                        format!("invalid helper mailbox entry: {}", error.reason)
                    })?,
                );
            }
            "mailbox_count" => {}
            "message_count" => {}
            "message_uid"
            | "message_flags_b64"
            | "message_date_received_b64"
            | "message_size_virtual"
            | "message_mailbox_b64"
            | "message_subject_b64"
            | "message_from_b64"
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
        if key.is_empty() || key.chars().any(|ch| ch.is_control()) {
            return Err(format!("malformed helper field name: {key:?}"));
        }
        if value.chars().any(|ch| ch.is_control()) {
            return Err(format!("helper field {key} contains control characters"));
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate helper field: {key}"));
        }
    }

    Ok(fields)
}

fn reject_unknown_request_fields(
    fields: &BTreeMap<String, String>,
    operation: &str,
) -> Result<(), String> {
    let allowed: &[&str] = match operation {
        "mailbox_list" => &[
            "operation",
            "canonical_username_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "message_list" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_name_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "message_search" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_name_b64",
            "query_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "message_view" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_name_b64",
            "uid",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "attachment_download" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_name_b64",
            "uid",
            "part_path_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "message_move" => &[
            "operation",
            "canonical_username_b64",
            "source_mailbox_name_b64",
            "destination_mailbox_name_b64",
            "uid",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        _ => return Ok(()),
    };

    for key in fields.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unexpected helper request field: {key}"));
        }
    }
    Ok(())
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
    let mailbox_name = decode_base64_text(
        require_field(fields, "message_mailbox_b64")?,
        policy.mailbox_name_max_len,
        "message mailbox",
    )?;
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

    let date_received = decode_base64_text(
        require_field(fields, "message_date_received_b64")?,
        policy.message_date_max_len,
        "message date_received",
    )?;
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

    let flags_string = decode_base64_text(
        require_field(fields, "message_flags_b64")?,
        policy.message_flag_string_max_len,
        "message flags",
    )?;
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
    let subject = fields
        .get("message_subject_b64")
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = decode_base64_text(value, policy.header_value_max_len, "message subject")?;
            validate_helper_string(
                "message subject",
                &value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value)
        })
        .transpose()?;
    let from = fields
        .get("message_from_b64")
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = decode_base64_text(value, policy.header_value_max_len, "message from")?;
            validate_helper_string(
                "message from",
                &value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value)
        })
        .transpose()?;

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

fn parse_message_search_fields(
    policy: MessageSearchPolicy,
    fields: &BTreeMap<String, String>,
) -> Result<MessageSearchResult, String> {
    let mailbox_name = decode_base64_text(
        require_field(fields, "message_mailbox_b64")?,
        policy.mailbox_name_max_len,
        "message mailbox",
    )?;
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

    let date_received = decode_base64_text(
        require_field(fields, "message_date_received_b64")?,
        policy.message_date_max_len,
        "message date_received",
    )?;
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

    let flags_text = decode_base64_text(
        require_field(fields, "message_flags_b64")?,
        policy.message_flag_string_max_len,
        "message flags",
    )?;
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
        .get("message_subject_b64")
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = decode_base64_text(value, policy.header_value_max_len, "message subject")?;
            validate_helper_string(
                "message subject",
                &value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value)
        })
        .transpose()?;
    let from = fields
        .get("message_from_b64")
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = decode_base64_text(value, policy.header_value_max_len, "message from")?;
            validate_helper_string(
                "message from",
                &value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value)
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
    let mailbox_name = decode_base64_text(
        require_field(fields, "message_mailbox_b64")?,
        policy.mailbox_name_max_len,
        "message mailbox",
    )?;
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

    let date_received = decode_base64_text(
        require_field(fields, "message_date_received_b64")?,
        policy.message_date_max_len,
        "message date_received",
    )?;
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

    let flags_text = decode_base64_text(
        require_field(fields, "message_flags_b64")?,
        policy.message_flag_string_max_len,
        "message flags",
    )?;
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
    let mailbox_name = decode_base64_text(
        require_field(fields, "attachment_mailbox_name_b64")?,
        crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
        "attachment mailbox_name",
    )?;
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
        decode_base64_text(
            require_field(fields, "attachment_part_path_b64")?,
            policy.part_path_max_len,
            "attachment part_path",
        )?,
    )
    .map_err(|error| error.reason)?
    .part_path;

    let filename = decode_base64_text(
        require_field(fields, "attachment_filename_b64")?,
        policy.filename_max_len,
        "attachment filename",
    )?;
    validate_helper_string(
        "attachment filename",
        &filename,
        policy.filename_max_len,
        false,
        false,
    )?;

    let content_type = decode_base64_text(
        require_field(fields, "attachment_content_type_b64")?,
        policy.content_type_max_len,
        "attachment content_type",
    )?;
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble values are always <= 15"),
    }
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    if (bytes.len() & 1) != 0 {
        return Err("hex field length was not even".to_string());
    }

    let mut output = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        output.push((hex_value(bytes[index])? << 4) | hex_value(bytes[index + 1])?);
        index += 2;
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("hex field contained invalid characters".to_string()),
    }
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
