//! Mailbox-helper protocol types and bounded parsing helpers.
//!
//! This module keeps the line-oriented helper protocol separate from the Unix
//! socket client/server transport code so the helper boundary stays easier to
//! review.

use std::collections::BTreeMap;

use crate::mailbox::{MessageFlagRequest, MessageFlagResult};
use crate::message_metadata::MessageFlag;
use crate::message_metadata::{
    valid_message_preview, MessageMetadata, MessageVersion, MAX_MESSAGE_GUID_BYTES,
    MAX_MESSAGE_PREVIEW_BYTES,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::attachment::{
    AttachmentDownloadPolicy, AttachmentDownloadRequest, DownloadedAttachment,
};
use crate::mailbox::{
    MailboxEntry, MailboxListingPolicy, MessageAppendRequest, MessageListPolicy,
    MessageListRequest, MessageMovePolicy, MessageMoveRequest, MessageSearchBatchRequest,
    MessageSearchField, MessageSearchPolicy, MessageSearchRequest, MessageSearchResult,
    MessageSummary, MessageView, MessageViewPolicy, MessageViewRequest,
    DEFAULT_MESSAGE_APPEND_MAX_BYTES,
};

/// Supported helper requests for the first mailbox-read slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MailboxHelperRequest {
    FolderCreate {
        request: crate::folder_create::CreateFolderRequest,
        grant: MailboxHelperGrant,
    },
    FolderMetadata {
        canonical_username: String,
        grant: MailboxHelperGrant,
    },
    MailboxStatus {
        canonical_username: String,
        mailbox_name: String,
        grant: MailboxHelperGrant,
    },
    MessageFlag {
        canonical_username: String,
        request: MessageFlagRequest,
        grant: MailboxHelperGrant,
    },
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
        field: MessageSearchField,
        grant: MailboxHelperGrant,
    },
    MessageSearchBatch {
        canonical_username: String,
        mailbox_names: Vec<String>,
        query: String,
        field: MessageSearchField,
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
        version: MessageVersion,
        grant: MailboxHelperGrant,
    },
    MessageAppend {
        canonical_username: String,
        mailbox_name: String,
        message: Vec<u8>,
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
pub(crate) enum MailboxHelperResponse {
    FolderCreateOk {
        request: crate::folder_create::CreateFolderRequest,
        outcome: crate::folder_create::Outcome,
    },
    FolderMetadataOk {
        snapshot: crate::folder_metadata::FolderSnapshot,
    },
    MailboxStatusOk {
        status: crate::mailbox_status::MailboxStatus,
    },
    MessageFlagOk {
        request: MessageFlagRequest,
        result: MessageFlagResult,
    },
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
        field: MessageSearchField,
        results: Vec<MessageSearchResult>,
    },
    MessageSearchBatchOk {
        mailbox_names: Vec<String>,
        query: String,
        field: MessageSearchField,
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
        version: MessageVersion,
    },
    MessageAppendOk {
        mailbox_name: String,
        message_bytes: usize,
    },
    Error {
        backend: String,
        reason: String,
    },
}

pub(super) fn encode_request(request: &MailboxHelperRequest) -> String {
    match request {
        MailboxHelperRequest::FolderCreate {request,grant} => format!("operation=folder_create\ncanonical_username_b64={}\ncreate_request_b64={}\n{}",encode_base64(request.account().as_bytes()),encode_base64(serde_json::to_string(request).unwrap_or_default().as_bytes()),encode_grant_fields(grant)),
        MailboxHelperRequest::FolderMetadata {canonical_username,grant} => format!("operation=folder_metadata\ncanonical_username_b64={}\n{}",encode_base64(canonical_username.as_bytes()),encode_grant_fields(grant)),
        MailboxHelperRequest::MailboxStatus {canonical_username,mailbox_name,grant} => format!("operation=mailbox_status\ncanonical_username_b64={}\nmailbox_name_b64={}\n{}",encode_base64(canonical_username.as_bytes()),encode_base64(mailbox_name.as_bytes()),encode_grant_fields(grant)),
        MailboxHelperRequest::MessageFlag { canonical_username, request, grant } => format!(
            "operation=message_flag\ncanonical_username_b64={}\n{}{}",
            encode_base64(canonical_username.as_bytes()), encode_flag_fields(request), encode_grant_fields(grant)),
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
            field,
            grant,
        } => format!(
            "operation=message_search\ncanonical_username_b64={}\nmailbox_name_b64={}\nquery_b64={}\nsearch_field={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(mailbox_name.as_bytes()),
            encode_base64(query.as_bytes()),
            field.query_value(),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::MessageSearchBatch {
            canonical_username, mailbox_names, query, field, grant,
        } => format!(
            "operation=message_search_batch\ncanonical_username_b64={}\nmailbox_names_b64={}\nquery_b64={}\nsearch_field={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_mailbox_names(mailbox_names),
            encode_base64(query.as_bytes()),
            field.query_value(),
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
            version,
            grant,
        } => format!(
            "operation=message_move\ncanonical_username_b64={}\nsource_mailbox_name_b64={}\ndestination_mailbox_name_b64={}\nuid={uid}\n{}{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(source_mailbox_name.as_bytes()),
            encode_base64(destination_mailbox_name.as_bytes()),
            encode_move_version(version),
            encode_grant_fields(grant),
        ),
        MailboxHelperRequest::MessageAppend {
            canonical_username,
            mailbox_name,
            message,
            grant,
        } => format!(
            "operation=message_append\ncanonical_username_b64={}\nmailbox_name_b64={}\nmessage_b64={}\n{}",
            encode_base64(canonical_username.as_bytes()),
            encode_base64(mailbox_name.as_bytes()),
            encode_base64(message),
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
        "folder_create" => {
            let bytes = decode_base64_bytes(
                require_field(&fields, "create_request_b64")?,
                2048,
                "create_request",
            )?;
            let request: crate::folder_create::CreateFolderRequest =
                serde_json::from_slice(&bytes).map_err(|_| "invalid create request")?;
            request.validate().map_err(|_| "invalid create request")?;
            if request.account() != canonical_username {
                return Err("create account mismatch".into());
            }
            Ok(MailboxHelperRequest::FolderCreate { request, grant })
        }
        "folder_metadata" => {
            crate::mailbox_status::validate_account(&canonical_username).map_err(|e| e.reason)?;
            Ok(MailboxHelperRequest::FolderMetadata {
                canonical_username,
                grant,
            })
        }
        "mailbox_status" => {
            crate::mailbox_status::validate_account(&canonical_username).map_err(|e| e.reason)?;
            let mailbox_name = decode_base64_text(
                require_field(&fields, "mailbox_name_b64")?,
                255,
                "mailbox_name",
            )?;
            crate::mailbox_status::validate_name(&mailbox_name).map_err(|e| e.reason)?;
            Ok(MailboxHelperRequest::MailboxStatus {
                canonical_username,
                mailbox_name,
                grant,
            })
        }
        "message_flag" => Ok(MailboxHelperRequest::MessageFlag {
            canonical_username,
            request: parse_flag_fields(&fields)?,
            grant,
        }),
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
            let field = match fields.get("search_field").map(String::as_str) {
                Some(value) => MessageSearchField::from_query_value(value)
                    .ok_or_else(|| "invalid helper search_field".to_string())?,
                None => MessageSearchField::All,
            };
            let request = MessageSearchRequest::new_with_field(
                MessageSearchPolicy::default(),
                mailbox_name.clone(),
                query,
                field,
            )
            .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageSearch {
                canonical_username,
                mailbox_name: request.mailbox_name,
                query: request.query,
                field: request.field,
                grant,
            })
        }
        "message_search_batch" => {
            let query = decode_batch_text(
                require_field(&fields, "query_b64")?,
                crate::mailbox::DEFAULT_SEARCH_QUERY_MAX_LEN,
                "query",
            )?;
            let request = MessageSearchBatchRequest::new(
                MessageSearchPolicy::default(),
                decode_mailbox_names(require_field(&fields, "mailbox_names_b64")?)?,
                query.clone(),
                MessageSearchField::from_query_value(require_field(&fields, "search_field")?)
                    .ok_or_else(|| "invalid helper search_field".to_string())?,
            )
            .map_err(|error| error.reason)?;
            if request.query != query {
                return Err("helper batch query is not canonical".into());
            }
            Ok(MailboxHelperRequest::MessageSearchBatch {
                canonical_username,
                mailbox_names: request.mailbox_names,
                query: request.query,
                field: request.field,
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
            if uid.to_string() != require_field(&fields, "uid")? {
                return Err("noncanonical move UID".into());
            }
            let request = MessageMoveRequest::new(
                MessageMovePolicy::default(),
                source_mailbox_name,
                destination_mailbox_name,
                uid,
                parse_move_version(&fields)?,
            )
            .map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageMove {
                canonical_username,
                source_mailbox_name: request.source_mailbox_name,
                destination_mailbox_name: request.destination_mailbox_name,
                uid: request.uid,
                version: request.version,
                grant,
            })
        }
        "message_append" => {
            let mailbox_name = decode_base64_text(
                require_field(&fields, "mailbox_name_b64")?,
                crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
                "mailbox_name",
            )?;
            let message = decode_base64_bytes(
                require_field(&fields, "message_b64")?,
                DEFAULT_MESSAGE_APPEND_MAX_BYTES,
                "message",
            )?;
            let request =
                MessageAppendRequest::new(mailbox_name, message).map_err(|error| error.reason)?;
            Ok(MailboxHelperRequest::MessageAppend {
                canonical_username,
                mailbox_name: request.mailbox_name,
                message: request.message,
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
        MailboxHelperRequest::MessageFlag { grant, .. } => grant,
        MailboxHelperRequest::FolderCreate { grant, .. }
        | MailboxHelperRequest::FolderMetadata { grant, .. }
        | MailboxHelperRequest::MailboxStatus { grant, .. }
        | MailboxHelperRequest::MailboxList { grant, .. }
        | MailboxHelperRequest::MessageList { grant, .. }
        | MailboxHelperRequest::MessageSearch { grant, .. }
        | MailboxHelperRequest::MessageSearchBatch { grant, .. }
        | MailboxHelperRequest::MessageView { grant, .. }
        | MailboxHelperRequest::AttachmentDownload { grant, .. }
        | MailboxHelperRequest::MessageMove { grant, .. }
        | MailboxHelperRequest::MessageAppend { grant, .. } => grant,
    }
}

fn set_request_grant(request: &mut MailboxHelperRequest, new_grant: MailboxHelperGrant) {
    match request {
        MailboxHelperRequest::MessageFlag { grant, .. } => *grant = new_grant,
        MailboxHelperRequest::FolderCreate { grant, .. }
        | MailboxHelperRequest::FolderMetadata { grant, .. }
        | MailboxHelperRequest::MailboxStatus { grant, .. }
        | MailboxHelperRequest::MailboxList { grant, .. }
        | MailboxHelperRequest::MessageList { grant, .. }
        | MailboxHelperRequest::MessageSearch { grant, .. }
        | MailboxHelperRequest::MessageSearchBatch { grant, .. }
        | MailboxHelperRequest::MessageView { grant, .. }
        | MailboxHelperRequest::AttachmentDownload { grant, .. }
        | MailboxHelperRequest::MessageMove { grant, .. }
        | MailboxHelperRequest::MessageAppend { grant, .. } => *grant = new_grant,
    }
}

pub(super) fn helper_operation_label(request: &MailboxHelperRequest) -> &'static str {
    match request {
        MailboxHelperRequest::MessageFlag { .. } => "message_flag",
        MailboxHelperRequest::FolderCreate { .. } => "folder_create",
        MailboxHelperRequest::FolderMetadata { .. } => "folder_metadata",
        MailboxHelperRequest::MailboxStatus { .. } => "mailbox_status",
        MailboxHelperRequest::MailboxList { .. } => "mailbox_list",
        MailboxHelperRequest::MessageList { .. } => "message_list",
        MailboxHelperRequest::MessageSearch { .. } => "message_search",
        MailboxHelperRequest::MessageSearchBatch { .. } => "message_search_batch",
        MailboxHelperRequest::MessageView { .. } => "message_view",
        MailboxHelperRequest::AttachmentDownload { .. } => "attachment_download",
        MailboxHelperRequest::MessageMove { .. } => "message_move",
        MailboxHelperRequest::MessageAppend { .. } => "message_append",
    }
}

fn sign_request_grant(
    request: &MailboxHelperRequest,
    grant: &MailboxHelperGrant,
    key: &[u8],
) -> Result<String, String> {
    if let MailboxHelperRequest::MessageSearchBatch {
        canonical_username,
        mailbox_names,
        query,
        field,
        ..
    } = request
    {
        validate_canonical_username(canonical_username)?;
        let validated = MessageSearchBatchRequest::new(
            MessageSearchPolicy::default(),
            mailbox_names.clone(),
            query.clone(),
            *field,
        )
        .map_err(|error| error.reason)?;
        if validated.query != *query {
            return Err("helper batch query is not canonical".into());
        }
    }
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
        MailboxHelperRequest::FolderCreate { request, .. } => fields.extend([
            request.account().into(),
            request.parent().into(),
            request.parent_guid().into(),
            request.leaf().into(),
        ]),
        MailboxHelperRequest::MessageFlag {
            canonical_username,
            request,
            ..
        } => {
            fields.extend([
                canonical_username.clone(),
                request.mailbox_name.clone(),
                request.uid.to_string(),
                request.version.mailbox_guid.clone(),
                request.version.message_guid.clone(),
                request.flag.value().into(),
                if request.enabled {
                    "1".into()
                } else {
                    "0".into()
                },
            ]);
        }
        MailboxHelperRequest::FolderMetadata {
            canonical_username, ..
        }
        | MailboxHelperRequest::MailboxList {
            canonical_username, ..
        } => fields.push(canonical_username.clone()),
        MailboxHelperRequest::MailboxStatus {
            canonical_username,
            mailbox_name,
            ..
        }
        | MailboxHelperRequest::MessageList {
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
            field,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_name.clone());
            fields.push(query.clone());
            fields.push(field.query_value().to_string());
        }
        MailboxHelperRequest::MessageSearchBatch {
            canonical_username,
            mailbox_names,
            query,
            field,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_names.len().to_string());
            fields.extend(mailbox_names.iter().cloned());
            fields.push(query.clone());
            fields.push(field.query_value().to_string());
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
            version,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(source_mailbox_name.clone());
            fields.push(destination_mailbox_name.clone());
            fields.push(uid.to_string());
            fields.push(version.mailbox_guid.clone());
            fields.push(version.message_guid.clone());
        }
        MailboxHelperRequest::MessageAppend {
            canonical_username,
            mailbox_name,
            message,
            ..
        } => {
            fields.push(canonical_username.clone());
            fields.push(mailbox_name.clone());
            fields.push(hex_lower(&Sha256::digest(message)));
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

pub(crate) fn encode_response(response: &MailboxHelperResponse) -> String {
    match response {
        MailboxHelperResponse::FolderCreateOk {request,outcome}=>format!("status=ok\noperation=folder_create\ncreate_request_b64={}\ncreate_outcome_b64={}\n",encode_base64(serde_json::to_string(request).unwrap_or_default().as_bytes()),encode_base64(serde_json::to_string(outcome).unwrap_or_default().as_bytes())),
        MailboxHelperResponse::FolderMetadataOk {snapshot} => format!("status=ok\noperation=folder_metadata\ncanonical_username_b64={}\ntranscript_b64={}\n",encode_base64(snapshot.account().as_bytes()),encode_base64(snapshot.transcript())),
        MailboxHelperResponse::MailboxStatusOk {status} => format!("status=ok\noperation=mailbox_status\nmailbox_name_b64={}\nstatus_guid={}\nstatus_messages={}\nstatus_vsize={}\n",encode_base64(status.mailbox().as_bytes()),status.guid(),status.messages(),status.virtual_bytes()),
        MailboxHelperResponse::MessageFlagOk { request, result } => format!(
            "status=ok\noperation=message_flag\n{}flag_result={}\n", encode_flag_fields(request),
            match result { MessageFlagResult::Updated => "updated", MessageFlagResult::AlreadySet => "already_set" }),
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
                output.push_str("message_to_b64=");
                output.push_str(&encode_base64(message.to.as_deref().unwrap_or("").as_bytes()));
                output.push('\n');
                output.push_str(&encode_message_metadata(message.metadata.as_ref()));
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageSearchOk {
            mailbox_name,
            query,
            field,
            results,
        } => {
            let mut output = format!(
                "status=ok\noperation=message_search\nmailbox_name_b64={}\nquery_b64={}\nsearch_field={}\nmessage_count={}\n",
                encode_base64(mailbox_name.as_bytes()),
                encode_base64(query.as_bytes()),
                field.query_value(),
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
                output.push_str(&encode_message_metadata(result.metadata.as_ref()));
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageSearchBatchOk {
            mailbox_names,
            query,
            field,
            results,
        } => {
            let mut output = format!(
                "status=ok\noperation=message_search_batch\nmailbox_names_b64={}\nquery_b64={}\nsearch_field={}\nmessage_count={}\n",
                encode_mailbox_names(mailbox_names),
                encode_base64(query.as_bytes()),
                field.query_value(),
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
                output.push_str(&encode_message_metadata(result.metadata.as_ref()));
                output.push_str("message_end=1\n");
            }
            output
        }
        MailboxHelperResponse::MessageViewOk { message } => format!(
            "status=ok\noperation=message_view\nmessage_uid={}\nmessage_flags_b64={}\nmessage_date_received_b64={}\nmessage_size_virtual={}\nmessage_mailbox_b64={}\nmessage_header_block_b64={}\nmessage_body_text_b64={}\n{}",
            message.uid,
            encode_base64(message.flags.join(",").as_bytes()),
            encode_base64(message.date_received.as_bytes()),
            message.size_virtual,
            encode_base64(message.mailbox_name.as_bytes()),
            encode_base64(message.header_block.as_bytes()),
            encode_base64(message.body_text.as_bytes()),
            encode_message_metadata(message.metadata.as_ref()),
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
            version,
        } => format!(
            "status=ok\noperation=message_move\nsource_mailbox_name_b64={}\ndestination_mailbox_name_b64={}\nuid={uid}\n{}",
            encode_base64(source_mailbox_name.as_bytes()),
            encode_base64(destination_mailbox_name.as_bytes()),
            encode_move_version(version),
        ),
        MailboxHelperResponse::MessageAppendOk {
            mailbox_name,
            message_bytes,
        } => format!(
            "status=ok\noperation=message_append\nmailbox_name_b64={}\nmessage_bytes={message_bytes}\n",
            encode_base64(mailbox_name.as_bytes()),
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
    if input
        .lines()
        .any(|line| line == "operation=message_search_batch")
    {
        return parse_search_batch_response(search_policy, input);
    }
    if input.lines().any(|line| line == "operation=folder_create") {
        if input.len() > 4096 {
            return Err("create response too large".into());
        }
        let f = parse_kv_lines(input)?;
        if f.len() != 4 || require_field(&f, "status")? != "ok" {
            return Err("invalid create response".into());
        }
        let request: crate::folder_create::CreateFolderRequest = serde_json::from_slice(
            &decode_base64_bytes(require_field(&f, "create_request_b64")?, 2048, "request")?,
        )
        .map_err(|_| "invalid create request")?;
        let outcome: crate::folder_create::Outcome = serde_json::from_slice(&decode_base64_bytes(
            require_field(&f, "create_outcome_b64")?,
            256,
            "outcome",
        )?)
        .map_err(|_| "invalid create outcome")?;
        request
            .validate_outcome(&outcome)
            .map_err(|_| "invalid create response")?;
        return Ok(MailboxHelperResponse::FolderCreateOk { request, outcome });
    }
    if input
        .lines()
        .any(|line| line == "operation=folder_metadata")
    {
        if input.len() > 704 * 1024 {
            return Err("folder metadata response too large".into());
        }
        let fields = parse_kv_lines(input)?;
        if fields.len() != 4 || require_field(&fields, "status")? != "ok" {
            return Err("invalid folder metadata response".into());
        }
        let account = decode_base64_text(
            require_field(&fields, "canonical_username_b64")?,
            320,
            "account",
        )?;
        let transcript = decode_base64_bytes(
            require_field(&fields, "transcript_b64")?,
            512 * 1024,
            "transcript",
        )?;
        let snapshot = crate::folder_metadata::FolderSnapshot::parse(&account, &transcript)
            .map_err(|_| "invalid folder metadata".to_string())?;
        return Ok(MailboxHelperResponse::FolderMetadataOk { snapshot });
    }
    if input.lines().any(|line| line == "operation=mailbox_status") {
        let fields = parse_kv_lines(input)?;
        if fields.len() != 6 || require_field(&fields, "status")? != "ok" {
            return Err("invalid mailbox status response".into());
        }
        let name = decode_base64_text(
            require_field(&fields, "mailbox_name_b64")?,
            255,
            "mailbox_name",
        )?;
        let number = |key| -> Result<u64, String> {
            let value = require_field(&fields, key)?;
            if value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
                || value.len() > 19
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err("invalid status number".into());
            }
            value.parse().map_err(|_| "invalid status number".into())
        };
        let status = crate::mailbox_status::MailboxStatus::new(
            &name,
            require_field(&fields, "status_guid")?,
            number("status_messages")?,
            number("status_vsize")?,
        )
        .map_err(|e| e.reason)?;
        return Ok(MailboxHelperResponse::MailboxStatusOk { status });
    }
    let mut status = None::<String>;
    let mut operation = None::<String>;
    let mut backend = None::<String>;
    let mut reason = None::<String>;
    let mut mailboxes = Vec::<MailboxEntry>::new();
    let mut mailbox_name = None::<String>;
    let mut query = None::<String>;
    let mut search_field = MessageSearchField::All;
    let mut messages = Vec::<MessageSummary>::new();
    let mut search_results = Vec::<MessageSearchResult>::new();
    let mut current_message_fields = BTreeMap::<String, String>::new();
    let mut attachment_fields = BTreeMap::<String, String>::new();
    let mut flag_fields = BTreeMap::<String, String>::new();
    let mut move_fields = BTreeMap::<String, String>::new();
    let mut source_mailbox_name = None::<String>;
    let mut destination_mailbox_name = None::<String>;
    let mut moved_uid = None::<u64>;
    let mut message_bytes = None::<usize>;
    let mut singleton_fields = BTreeMap::<String, ()>::new();
    let mut response_field_names = Vec::new();

    for raw_line in input.lines() {
        if raw_line.is_empty() {
            continue;
        }
        let (key, value) = raw_line
            .split_once('=')
            .ok_or_else(|| "malformed helper response line".to_string())?;
        if key.chars().any(char::is_control) || value.chars().any(char::is_control) {
            return Err("helper response contains control characters".into());
        }
        response_field_names.push(key);
        if matches!(
            key,
            "status"
                | "operation"
                | "backend_b64"
                | "reason_b64"
                | "mailbox_name_b64"
                | "query_b64"
                | "search_field"
                | "source_mailbox_name_b64"
                | "destination_mailbox_name_b64"
                | "uid"
                | "message_bytes"
                | "mailbox_count"
                | "message_count"
        ) && singleton_fields.insert(key.to_string(), ()).is_some()
        {
            return Err("duplicate helper response control field".into());
        }
        match key {
            "move_mailbox_guid" | "move_message_guid_b64" => {
                if move_fields
                    .insert(key.to_string(), value.to_string())
                    .is_some()
                {
                    return Err("duplicate move confirmation field".into());
                }
            }
            "flag_mailbox_b64"
            | "flag_uid"
            | "flag_mailbox_guid"
            | "flag_message_guid_b64"
            | "flag_name"
            | "flag_enabled"
            | "flag_result" => {
                if flag_fields
                    .insert(key.to_string(), value.to_string())
                    .is_some()
                {
                    return Err("duplicate flag response field".into());
                }
            }
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
            "search_field" => {
                search_field = MessageSearchField::from_query_value(value)
                    .ok_or_else(|| "invalid helper response search_field".to_string())?
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
                );
                if moved_uid.map(|uid| uid.to_string()).as_deref() != Some(value) {
                    return Err("noncanonical move confirmation UID".into());
                }
            }
            "message_bytes" => {
                message_bytes = Some(
                    value
                        .parse::<usize>()
                        .map_err(|error| format!("invalid helper message byte count: {error}"))?,
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
            | "message_to_b64"
            | "message_header_block_b64"
            | "message_mailbox_guid"
            | "message_guid_b64"
            | "message_attachment_count"
            | "message_protection"
            | "message_attachments_b64"
            | "message_preview_b64"
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

    if (response_field_names.contains(&"message_protection")
        || response_field_names.contains(&"message_attachments_b64"))
        && (status.as_deref() != Some("ok")
            || !matches!(
                operation.as_deref(),
                Some("message_list" | "message_search" | "message_view")
            ))
    {
        return Err("public message metadata on another helper response operation".into());
    }

    if operation.as_deref() == Some("message_move") {
        if status.as_deref() != Some("ok")
            || response_field_names.iter().any(|key| {
                !matches!(
                    *key,
                    "status"
                        | "operation"
                        | "source_mailbox_name_b64"
                        | "destination_mailbox_name_b64"
                        | "uid"
                        | "move_mailbox_guid"
                        | "move_message_guid_b64"
                )
            })
        {
            return Err("unexpected fields in move confirmation".into());
        }
    } else if !move_fields.is_empty() {
        return Err("move identity on another response operation".into());
    }
    if operation.as_deref() == Some("message_flag") {
        if status.as_deref() != Some("ok")
            || response_field_names.iter().any(|key| {
                !matches!(
                    *key,
                    "status"
                        | "operation"
                        | "flag_mailbox_b64"
                        | "flag_uid"
                        | "flag_mailbox_guid"
                        | "flag_message_guid_b64"
                        | "flag_name"
                        | "flag_enabled"
                        | "flag_result"
                )
            })
        {
            return Err("unexpected fields in flag confirmation".into());
        }
    } else if !flag_fields.is_empty() {
        return Err("flag fields on another helper response operation".into());
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
            Some("message_flag") => Ok(MailboxHelperResponse::MessageFlagOk {
                request: parse_flag_fields(&flag_fields)?,
                result: match require_field(&flag_fields, "flag_result")? {
                    "updated" => MessageFlagResult::Updated,
                    "already_set" => MessageFlagResult::AlreadySet,
                    _ => return Err("invalid helper flag result".into()),
                },
            }),
            Some("mailbox_list") => Ok(MailboxHelperResponse::MailboxListOk { mailboxes }),
            Some("message_list") => Ok(MailboxHelperResponse::MessageListOk {
                mailbox_name: mailbox_name.unwrap_or_else(|| "unknown".to_string()),
                messages,
            }),
            Some("message_search") => Ok(MailboxHelperResponse::MessageSearchOk {
                mailbox_name: mailbox_name.unwrap_or_else(|| "unknown".to_string()),
                query: query.unwrap_or_default(),
                field: search_field,
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
                version: parse_move_version(&move_fields)?,
            }),
            Some("message_append") => Ok(MailboxHelperResponse::MessageAppendOk {
                mailbox_name: mailbox_name.ok_or_else(|| {
                    "helper response did not include append mailbox_name".to_string()
                })?,
                message_bytes: message_bytes
                    .ok_or_else(|| "helper response did not include message_bytes".to_string())?,
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
        "message_flag" => &[
            "operation",
            "canonical_username_b64",
            "flag_mailbox_b64",
            "flag_uid",
            "flag_mailbox_guid",
            "flag_message_guid_b64",
            "flag_name",
            "flag_enabled",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "folder_create" => &[
            "operation",
            "canonical_username_b64",
            "create_request_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "folder_metadata" | "mailbox_list" => &[
            "operation",
            "canonical_username_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "mailbox_status" | "message_list" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_name_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "message_search_batch" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_names_b64",
            "query_b64",
            "search_field",
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
            "search_field",
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
            "move_mailbox_guid",
            "move_message_guid_b64",
            "grant_issued_at",
            "grant_expires_at",
            "grant_nonce",
            "grant_signature",
        ],
        "message_append" => &[
            "operation",
            "canonical_username_b64",
            "mailbox_name_b64",
            "message_b64",
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

fn encode_flag_fields(request: &MessageFlagRequest) -> String {
    format!("flag_mailbox_b64={}\nflag_uid={}\nflag_mailbox_guid={}\nflag_message_guid_b64={}\nflag_name={}\nflag_enabled={}\n",
        encode_base64(request.mailbox_name.as_bytes()), request.uid, request.version.mailbox_guid,
        encode_base64(request.version.message_guid.as_bytes()), request.flag.value(), if request.enabled { "1" } else { "0" })
}

fn parse_flag_fields(fields: &BTreeMap<String, String>) -> Result<MessageFlagRequest, String> {
    let mailbox = decode_base64_text(
        require_field(fields, "flag_mailbox_b64")?,
        crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN,
        "flag mailbox",
    )?;
    let uid_text = require_field(fields, "flag_uid")?;
    let uid = uid_text
        .parse::<u64>()
        .map_err(|_| "invalid flag UID".to_string())?;
    if uid.to_string() != uid_text {
        return Err("noncanonical flag UID".into());
    }
    let version = MessageVersion::new(
        require_field(fields, "flag_mailbox_guid")?.into(),
        decode_base64_text(
            require_field(fields, "flag_message_guid_b64")?,
            MAX_MESSAGE_GUID_BYTES,
            "flag message GUID",
        )?,
    )
    .map_err(|error| error.reason)?;
    let flag = MessageFlag::parse(require_field(fields, "flag_name")?)
        .ok_or_else(|| "unsupported flag".to_string())?;
    let enabled = match require_field(fields, "flag_enabled")? {
        "1" => true,
        "0" => false,
        _ => return Err("invalid flag state".into()),
    };
    MessageFlagRequest::new(mailbox, uid, version, flag, enabled).map_err(|error| error.reason)
}

fn encode_message_metadata(metadata: Option<&MessageMetadata>) -> String {
    let Some(metadata) = metadata else {
        return String::new();
    };
    let mut encoded = format!(
        "message_mailbox_guid={}\nmessage_guid_b64={}\nmessage_attachment_count={}\n",
        metadata.version.mailbox_guid,
        encode_base64(metadata.version.message_guid.as_bytes()),
        metadata
            .attachment_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    if let Some(preview) = &metadata.preview {
        encoded.push_str(&format!(
            "message_preview_b64={}\n",
            encode_base64(preview.as_bytes())
        ));
    }
    if metadata.protection != crate::message_metadata::MessageProtection::Unknown {
        encoded.push_str(&format!(
            "message_protection={}\n",
            metadata.protection.value()
        ));
    }
    if let Some(attachments) = &metadata.attachments {
        // Derived bounded public descriptors, never attachment file contents.
        let data =
            serde_json::to_vec(attachments).expect("public attachment descriptors serialize");
        encoded.push_str(&format!(
            "message_attachments_b64={}\n",
            encode_base64(&data)
        ));
    }
    encoded
}

fn parse_message_metadata(
    fields: &BTreeMap<String, String>,
) -> Result<Option<MessageMetadata>, String> {
    let mailbox_guid = fields.get("message_mailbox_guid");
    let message_guid = fields.get("message_guid_b64");
    let count = fields.get("message_attachment_count");
    let preview = fields.get("message_preview_b64");
    let protection = fields.get("message_protection");
    let attachments = fields.get("message_attachments_b64");
    if mailbox_guid.is_none()
        && message_guid.is_none()
        && count.is_none()
        && preview.is_none()
        && protection.is_none()
        && attachments.is_none()
    {
        // Old helper responses can still be read, but cannot authorize flag writes.
        return Ok(None);
    }
    let (Some(mailbox_guid), Some(message_guid), Some(count)) = (mailbox_guid, message_guid, count)
    else {
        return Err("helper message metadata was incomplete".into());
    };
    let message_guid = decode_base64_text(message_guid, MAX_MESSAGE_GUID_BYTES, "message GUID")?;
    let version =
        MessageVersion::new(mailbox_guid.clone(), message_guid).map_err(|error| error.reason)?;
    let attachment_count = if count == "unknown" {
        None
    } else {
        Some(
            count
                .parse::<usize>()
                .ok()
                .filter(|value| *value <= 1024 && count == &value.to_string())
                .ok_or_else(|| {
                    "helper attachment count was invalid or outside its bound".to_string()
                })?,
        )
    };
    Ok(Some(MessageMetadata {
        attachments: attachments
            .map(|value| -> Result<_, String> {
                let text = decode_base64_text(value, 8192, "public attachment descriptors")?;
                let summaries: Vec<crate::message_metadata::AttachmentSummary> =
                    serde_json::from_str(&text)
                        .map_err(|_| "helper attachment descriptors were malformed".to_string())?;
                if !crate::message_metadata::validate_attachment_summaries(
                    &summaries,
                    attachment_count,
                ) {
                    return Err(
                        "helper attachment descriptors were invalid or outside bounds".into(),
                    );
                }
                Ok(summaries)
            })
            .transpose()?,
        protection: protection
            .map(|value| {
                crate::message_metadata::MessageProtection::parse(value).ok_or_else(|| {
                    "helper message protection classification was invalid".to_string()
                })
            })
            .transpose()?
            .unwrap_or_default(),
        version,
        attachment_count,
        preview: preview
            .map(|value| -> Result<String, String> {
                let text = decode_base64_text(value, MAX_MESSAGE_PREVIEW_BYTES, "message preview")?;
                if !valid_message_preview(&text) {
                    return Err("helper message preview was invalid or outside its bound".into());
                }
                Ok(text)
            })
            .transpose()?,
    }))
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

    let to = fields
        .get("message_to_b64")
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = decode_base64_text(value, policy.header_value_max_len, "message to")?;
            validate_helper_string(
                "message to",
                &value,
                policy.header_value_max_len,
                true,
                false,
            )?;
            Ok::<String, String>(value)
        })
        .transpose()?;
    Ok(MessageSummary {
        to,
        metadata: parse_message_metadata(fields)?,
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
    if fields.contains_key("message_to_b64") {
        return Err("recipient projection is only valid in list summaries".into());
    }
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
        metadata: parse_message_metadata(fields)?,
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
    if fields.contains_key("message_to_b64") {
        return Err("recipient projection is only valid in list summaries".into());
    }
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
        metadata: parse_message_metadata(fields)?,
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

fn encode_move_version(version: &MessageVersion) -> String {
    format!(
        "move_mailbox_guid={}\nmove_message_guid_b64={}\n",
        version.mailbox_guid,
        encode_base64(version.message_guid.as_bytes())
    )
}
fn parse_move_version(fields: &BTreeMap<String, String>) -> Result<MessageVersion, String> {
    MessageVersion::new(
        require_field(fields, "move_mailbox_guid")?.into(),
        decode_base64_text(
            require_field(fields, "move_message_guid_b64")?,
            MAX_MESSAGE_GUID_BYTES,
            "move message GUID",
        )?,
    )
    .map_err(|error| error.reason)
}

// JSON's worst-case escaped representation is six bytes per input byte, plus
// quotes and delimiters. This decoder does not change the transport byte caps.
const MAX_BATCH_SCOPE_JSON_BYTES: usize = crate::mailbox::DEFAULT_MAX_MAILBOXES
    * (crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN * 6 + 3)
    + 2;

fn encode_mailbox_names(names: &[String]) -> String {
    encode_base64(serde_json::to_string(names).unwrap_or_default().as_bytes())
}

fn decode_batch_bytes(value: &str, limit: usize, field: &str) -> Result<Vec<u8>, String> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(format!("{field} exceeded encoded byte limit"));
    }
    let bytes = decode_base64_bytes(value, limit, field)?;
    if encode_base64(&bytes) != value {
        return Err(format!("{field} base64 was not canonical"));
    }
    Ok(bytes)
}

fn decode_batch_text(value: &str, limit: usize, field: &str) -> Result<String, String> {
    String::from_utf8(decode_batch_bytes(value, limit, field)?)
        .map_err(|_| format!("{field} was not valid UTF-8"))
}

fn decode_mailbox_names(value: &str) -> Result<Vec<String>, String> {
    let bytes = decode_batch_bytes(value, MAX_BATCH_SCOPE_JSON_BYTES, "mailbox names")?;
    struct BoundedNames;
    impl<'de> serde::de::Visitor<'de> for BoundedNames {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded mailbox name vector")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            let mut names = Vec::new();
            while let Some(name) = sequence.next_element::<String>()? {
                if names.len() == crate::mailbox::DEFAULT_MAX_MAILBOXES
                    || name.len() > crate::mailbox::DEFAULT_MAILBOX_NAME_MAX_LEN
                {
                    return Err(serde::de::Error::custom("mailbox scope exceeded bounds"));
                }
                names.push(name);
            }
            Ok(names)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    let names = serde::de::Deserializer::deserialize_seq(&mut decoder, BoundedNames)
        .map_err(|_| "invalid helper mailbox names vector".to_string())?;
    decoder
        .end()
        .map_err(|_| "invalid helper mailbox names vector".to_string())?;
    // Scope validation is shared with the model. A harmless literal query only
    // allows this decoder to qualify the vector independently of the header.
    MessageSearchBatchRequest::new(
        MessageSearchPolicy::default(),
        names.clone(),
        "scope",
        MessageSearchField::All,
    )
    .map_err(|error| error.reason)?;
    Ok(names)
}

fn parse_search_batch_response(
    policy: MessageSearchPolicy,
    input: &str,
) -> Result<MailboxHelperResponse, String> {
    if input.len() > super::DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES {
        return Err("helper batch response exceeded byte limit".into());
    }
    let mut headers = BTreeMap::new();
    let mut row = BTreeMap::new();
    let mut results = Vec::new();
    let mut rows_started = false;
    for line in input.lines() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "malformed helper batch response".to_string())?;
        if value.chars().any(char::is_control) {
            return Err("control in helper batch response".into());
        }
        match key {
            "status" | "operation" | "mailbox_names_b64" | "query_b64" | "search_field"
            | "message_count" => {
                if rows_started || headers.insert(key.to_string(), value.to_string()).is_some() {
                    return Err("duplicate or misplaced helper batch header".into());
                }
            }
            "message_end" => {
                rows_started = true;
                if value != "1" || row.is_empty() {
                    return Err("invalid helper batch message marker".into());
                }
                results.push(parse_message_search_fields(policy, &row)?);
                row.clear();
                if results.len() > policy.max_results {
                    return Err("helper batch response exceeded result limit".into());
                }
            }
            "message_uid"
            | "message_flags_b64"
            | "message_date_received_b64"
            | "message_size_virtual"
            | "message_mailbox_b64"
            | "message_subject_b64"
            | "message_from_b64"
            | "message_mailbox_guid"
            | "message_guid_b64"
            | "message_attachment_count"
            | "message_protection"
            | "message_attachments_b64"
            | "message_preview_b64" => {
                rows_started = true;
                if row.insert(key.to_string(), value.to_string()).is_some() {
                    return Err("duplicate helper batch message field".into());
                }
            }
            _ => return Err("unknown helper batch response field".into()),
        }
    }
    if !row.is_empty()
        || headers.len() != 6
        || require_field(&headers, "status")? != "ok"
        || require_field(&headers, "operation")? != "message_search_batch"
    {
        return Err("incomplete helper batch response".into());
    }
    let mailbox_names = decode_mailbox_names(require_field(&headers, "mailbox_names_b64")?)?;
    let query = decode_batch_text(
        require_field(&headers, "query_b64")?,
        policy.query_max_len,
        "query",
    )?;
    let field = MessageSearchField::from_query_value(require_field(&headers, "search_field")?)
        .ok_or_else(|| "invalid helper batch search field".to_string())?;
    let validated =
        MessageSearchBatchRequest::new(policy, mailbox_names.clone(), query.clone(), field)
            .map_err(|error| error.reason)?;
    if validated.query != query {
        return Err("helper batch query is not canonical".into());
    }
    let count = require_field(&headers, "message_count")?;
    if count != results.len().to_string() {
        return Err("helper batch result count mismatch".into());
    }
    let mut identities = std::collections::BTreeSet::new();
    for result in &results {
        if !mailbox_names.contains(&result.mailbox_name) {
            return Err("helper batch result outside requested scope".into());
        }
        if !identities.insert((&result.mailbox_name, result.uid)) {
            return Err("duplicate helper batch message identity".into());
        }
    }
    Ok(MailboxHelperResponse::MessageSearchBatchOk {
        mailbox_names,
        query,
        field,
        results,
    })
}

#[cfg(test)]
mod batch_protocol_tests {
    use super::*;

    const KEY: &[u8] = b"batch-test-key-with-32-bytes-or-more";

    fn signed_batch() -> MailboxHelperRequest {
        let mut request = MailboxHelperRequest::MessageSearchBatch {
            canonical_username: "alice@example.com".into(),
            mailbox_names: vec!["INBOX".into(), "Archive/Été \"quoted\"\\folder".into()],
            query: "quarterly É report $(literal)".into(),
            field: MessageSearchField::Subject,
            grant: MailboxHelperGrant::unsigned(),
        };
        issue_request_grant_with_nonce(&mut request, KEY, 100, &"01".repeat(32)).unwrap();
        request
    }

    fn row(mailbox: &str, uid: u64) -> MessageSearchResult {
        MessageSearchResult {
            mailbox_name: mailbox.into(),
            uid,
            flags: vec!["\\Seen".into()],
            date_received: "2026-10-03 10:00:00 +0000".into(),
            size_virtual: 42,
            subject: Some("fixture É".into()),
            from: Some("fixture@example.com".into()),
            metadata: Some(MessageMetadata {
                attachments: None,
                protection: crate::message_metadata::MessageProtection::Unknown,
                version: MessageVersion::new("a".repeat(32), format!("fixture-{uid}")).unwrap(),
                attachment_count: Some(1),
                preview: Some("fixture preview".into()),
            }),
        }
    }

    fn response(results: Vec<MessageSearchResult>) -> MailboxHelperResponse {
        MailboxHelperResponse::MessageSearchBatchOk {
            mailbox_names: vec!["INBOX".into(), "Archive".into()],
            query: "fixture".into(),
            field: MessageSearchField::From,
            results,
        }
    }

    fn parse_batch(text: &str) -> Result<MailboxHelperResponse, String> {
        parse_response(
            MailboxListingPolicy::default(),
            MessageListPolicy::default(),
            MessageSearchPolicy::default(),
            MessageViewPolicy::default(),
            text,
        )
    }

    #[test]
    fn public_protection_metadata_refuses_wrong_operation_even_with_valid_value() {
        for base in [
            "status=ok\noperation=mailbox_list\nmailbox_count=0\n",
            "status=ok\noperation=message_append\nmailbox_name_b64=SU5CT1g=\nmessage_bytes=1\n",
            "status=error\nbackend_b64=Zml4dHVyZQ==\nreason_b64=cmVmdXNlZA==\n",
        ] {
            for value in ["signed", "verified"] {
                assert!(
                    parse_batch(&format!("{base}message_protection={value}\n")).is_err(),
                    "{base}"
                );
            }
        }
    }

    #[test]
    fn public_attachment_descriptors_roundtrip_and_refuse_malformed_or_unowned_fields() {
        use crate::message_metadata::AttachmentSummary;
        let legacy = encode_response(&response(vec![row("INBOX", 1)]));
        assert!(!legacy.contains("message_attachments_b64="));
        assert!(parse_batch(&legacy).unwrap() == response(vec![row("INBOX", 1)]));
        let mut message = row("INBOX", 1);
        message.metadata.as_mut().unwrap().attachments = Some(vec![AttachmentSummary {
            filename: Some("public-<b>.txt".into()),
            encoded_size_bytes: 129,
        }]);
        let expected = response(vec![message.clone()]);
        let encoded = encode_response(&expected);
        assert_eq!(parse_batch(&encoded).unwrap(), expected);
        let mut edge = message.clone();
        edge.metadata.as_mut().unwrap().attachment_count = Some(8);
        edge.metadata.as_mut().unwrap().attachments = Some(vec![
            AttachmentSummary {
                filename: Some("a".repeat(255)),
                encoded_size_bytes: u64::MAX,
            };
            8
        ]);
        let edge_response = response(vec![edge.clone()]);
        assert_eq!(
            parse_batch(&encode_response(&edge_response)).unwrap(),
            edge_response
        );
        let mut long_name = edge.clone();
        long_name
            .metadata
            .as_mut()
            .unwrap()
            .attachments
            .as_mut()
            .unwrap()[0]
            .filename = Some("a".repeat(256));
        assert!(parse_batch(&encode_response(&response(vec![long_name]))).is_err());
        edge.metadata.as_mut().unwrap().attachment_count = Some(9);
        edge.metadata
            .as_mut()
            .unwrap()
            .attachments
            .as_mut()
            .unwrap()
            .push(AttachmentSummary {
                filename: None,
                encoded_size_bytes: 0,
            });
        assert!(parse_batch(&encode_response(&response(vec![edge]))).is_err());
        let token = encoded
            .lines()
            .find(|line| line.starts_with("message_attachments_b64="))
            .unwrap();
        for json in ["not-json", "null", "[]", "[{\"filename\":\"public.txt\",\"encoded_size_bytes\":-1}]", "[{\"filename\":\"public.txt\",\"encoded_size_bytes\":1,\"body\":\"untrusted\"}]", "[{\"filename\":\"line\\nbreak\",\"encoded_size_bytes\":1}]", "[{\"filename\":null,\"encoded_size_bytes\":1},{\"filename\":null,\"encoded_size_bytes\":2}]"] {
            let replaced = encoded.replace(token, &format!("message_attachments_b64={}", encode_base64(json.as_bytes())));
            assert!(parse_batch(&replaced).is_err(), "{json}");
        }
        assert!(parse_batch(&encoded.replace(token, &format!("{token}\n{token}"))).is_err());
        assert!(parse_batch(&encoded.replace(
            "message_attachment_count=1",
            "message_attachment_count=unknown"
        ))
        .is_err());
        let oversized = format!(
            "message_attachments_b64={}",
            encode_base64(&vec![b' '; 8193])
        );
        assert!(parse_batch(&encoded.replace(token, &oversized)).is_err());
        let single = MailboxHelperResponse::MessageSearchOk {
            mailbox_name: "INBOX".into(),
            query: "public".into(),
            field: MessageSearchField::Subject,
            results: vec![message],
        };
        let single_encoded = encode_response(&single);
        assert_eq!(
            parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                &single_encoded
            )
            .unwrap(),
            single
        );
        for operation in ["mailbox_list", "message_append"] {
            let wrong = format!("status=ok\noperation={operation}\n{token}\n");
            assert!(parse_response(
                MailboxListingPolicy::default(),
                MessageListPolicy::default(),
                MessageSearchPolicy::default(),
                MessageViewPolicy::default(),
                &wrong
            )
            .is_err());
        }
    }

    #[test]
    fn public_protection_metadata_roundtrips_and_legacy_is_unknown() {
        use crate::message_metadata::MessageProtection;
        let legacy = encode_response(&response(vec![row("INBOX", 1)]));
        assert!(!legacy.contains("message_protection="));
        assert_eq!(
            parse_batch(&legacy).unwrap(),
            response(vec![row("INBOX", 1)])
        );
        for protection in [
            MessageProtection::Plain,
            MessageProtection::Signed,
            MessageProtection::Encrypted,
        ] {
            let mut message = row("INBOX", 1);
            message.metadata.as_mut().unwrap().protection = protection;
            let expected = response(vec![message]);
            let encoded = encode_response(&expected);
            assert_eq!(parse_batch(&encoded).unwrap(), expected);
            for token in [
                "verified",
                "decrypted",
                "signed ",
                "Encrypted",
                "",
                "<script>",
            ] {
                let malformed = encoded.replace(
                    &format!("message_protection={}\n", protection.value()),
                    &format!("message_protection={token}\n"),
                );
                assert!(parse_batch(&malformed).is_err(), "{token:?}");
            }
            let duplicate = encoded.replace(
                &format!("message_protection={}\n", protection.value()),
                "message_protection=signed\nmessage_protection=encrypted\n",
            );
            assert!(parse_batch(&duplicate).is_err());
            let incomplete = encoded
                .lines()
                .filter(|line| !line.starts_with("message_mailbox_guid="))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(parse_batch(&incomplete).is_err());
        }
    }

    #[test]
    fn public_protection_metadata_works_in_single_list_search_and_view_codecs() {
        use crate::message_metadata::MessageProtection;
        let metadata = MessageMetadata {
            attachments: Some(vec![crate::message_metadata::AttachmentSummary {
                filename: Some("public.txt".into()),
                encoded_size_bytes: 20,
            }]),
            version: MessageVersion::new("a".repeat(32), "fixture".into()).unwrap(),
            attachment_count: Some(1),
            preview: None,
            protection: MessageProtection::Encrypted,
        };
        let summary = MessageSummary {
            mailbox_name: "INBOX".into(),
            uid: 1,
            flags: vec![],
            date_received: "2026-10-03 10:00:00 +0000".into(),
            size_virtual: 1,
            subject: Some("Public fixture".into()),
            from: None,
            to: None,
            metadata: Some(metadata.clone()),
        };
        let mut searched = row("INBOX", 1);
        searched.metadata = Some(metadata.clone());
        for expected in [
            MailboxHelperResponse::MessageListOk {
                mailbox_name: "INBOX".into(),
                messages: vec![summary],
            },
            MailboxHelperResponse::MessageSearchOk {
                mailbox_name: "INBOX".into(),
                query: "fixture".into(),
                field: MessageSearchField::Subject,
                results: vec![searched],
            },
            MailboxHelperResponse::MessageViewOk {
                message: Box::new(crate::mailbox::MessageView {
                    mailbox_name: "INBOX".into(),
                    uid: 1,
                    flags: vec![],
                    date_received: "2026-10-03 10:00:00 +0000".into(),
                    size_virtual: 1,
                    header_block: "Subject: Public fixture".into(),
                    body_text: "Public synthetic body".into(),
                    metadata: Some(metadata),
                }),
            },
        ] {
            let encoded = encode_response(&expected);
            assert_eq!(parse_batch(&encoded).unwrap(), expected);
        }
    }

    #[test]
    fn batch_codec_roundtrips_ordered_literal_scope_and_bounds() {
        let request = signed_batch();
        let decoded = parse_request(&encode_request(&request)).unwrap();
        assert_eq!(decoded, request);
        verify_request_grant(&decoded, KEY, 100).unwrap();
        let max_names = (0..crate::mailbox::DEFAULT_MAX_MAILBOXES)
            .map(|n| format!("{n:04}{}", "\\".repeat(251)))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_mailbox_names(&encode_mailbox_names(&max_names)).unwrap(),
            max_names
        );
        let expected = response(vec![row("INBOX", 1), row("Archive", 1)]);
        assert_eq!(parse_batch(&encode_response(&expected)).unwrap(), expected);
    }

    #[test]
    fn batch_request_refuses_malformed_scope_and_headers() {
        let signed = encode_request(&signed_batch());
        let scope_line = signed
            .lines()
            .find(|line| line.starts_with("mailbox_names_b64="))
            .unwrap();
        for json in [
            "[]".to_string(),
            "{}".into(),
            "[1]".into(),
            "[\"INBOX\",\"INBOX\"]".into(),
            "[\"bad\\u0000name\"]".into(),
            "[\"bad\\nname\"]".into(),
            serde_json::to_string(&vec!["x".repeat(256)]).unwrap(),
            serde_json::to_string(&(0..1025).map(|n| format!("F{n}")).collect::<Vec<_>>()).unwrap(),
            "[\"INBOX\"] trailing".into(),
        ] {
            let bad = signed.replace(
                scope_line,
                &format!("mailbox_names_b64={}", encode_base64(json.as_bytes())),
            );
            assert!(
                parse_request(&bad).is_err(),
                "scope should refuse {json:.80}"
            );
        }
        for bad in [
            signed.replace(scope_line, "mailbox_names_b64=!!!"),
            signed.replace(scope_line, &format!("{scope_line} ")),
            signed.replace(
                scope_line,
                &format!(
                    "mailbox_names_b64={}",
                    "A".repeat(MAX_BATCH_SCOPE_JSON_BYTES.div_ceil(3) * 4 + 4)
                ),
            ),
            format!("{signed}unexpected=1\n"),
            format!("{signed}{scope_line}\n"),
            signed.replace("search_field=subject", "search_field=body"),
            signed.replace("search_field=subject\n", ""),
            signed.replace("query_b64=", "query_b64=!!!"),
        ] {
            assert!(parse_request(&bad).is_err());
        }
        let query_line = signed
            .lines()
            .find(|line| line.starts_with("query_b64="))
            .unwrap();
        for query in [
            "\nfixture".to_string(),
            "fixture\u{0000}".into(),
            "x".repeat(257),
            "".into(),
        ] {
            let bad = signed.replace(
                query_line,
                &format!("query_b64={}", encode_base64(query.as_bytes())),
            );
            assert!(parse_request(&bad).is_err());
        }
    }

    #[test]
    fn batch_grant_binds_account_order_name_count_query_field_and_operation() {
        let original = signed_batch();
        let mut mutations = Vec::new();
        for selector in 0..6 {
            let mut tampered = original.clone();
            if let MailboxHelperRequest::MessageSearchBatch {
                canonical_username,
                mailbox_names,
                query,
                field,
                ..
            } = &mut tampered
            {
                match selector {
                    0 => *canonical_username = "bob@example.com".into(),
                    1 => mailbox_names.reverse(),
                    2 => mailbox_names[1] = "Foreign".into(),
                    3 => {
                        mailbox_names.pop();
                    }
                    4 => *query = "other query".into(),
                    _ => *field = MessageSearchField::From,
                }
            }
            mutations.push(tampered);
        }
        mutations.push(MailboxHelperRequest::MessageSearch {
            canonical_username: "alice@example.com".into(),
            mailbox_name: "INBOX".into(),
            query: "quarterly É report $(literal)".into(),
            field: MessageSearchField::Subject,
            grant: request_grant(&original).clone(),
        });
        for tampered in mutations {
            assert!(verify_request_grant(&tampered, KEY, 100).is_err());
        }
        assert!(verify_request_grant(&original, KEY, 99).is_err());
        assert!(verify_request_grant(&original, KEY, 161).is_err());
        let mut invalid = original;
        if let MailboxHelperRequest::MessageSearchBatch { query, .. } = &mut invalid {
            *query = "\nfixture".into();
        }
        assert!(issue_request_grant_with_nonce(&mut invalid, KEY, 100, &"01".repeat(32)).is_err());
    }

    #[test]
    fn batch_response_refuses_foreign_duplicate_malformed_and_over_cap_rows() {
        for rows in [
            vec![row("Foreign", 1)],
            vec![row("INBOX", 1), row("INBOX", 1)],
            (1..=251).map(|uid| row("INBOX", uid)).collect(),
        ] {
            assert!(parse_batch(&encode_response(&response(rows))).is_err());
        }
        let good = encode_response(&response(vec![row("INBOX", 1)]));
        for bad in [
            good.replace("message_count=1", "message_count=2"),
            good.replace("message_count=1", "message_count=01"),
            good.replace("message_uid=1", "message_uid=0"),
            good.replace(
                "message_mailbox_guid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "message_mailbox_guid=bad",
            ),
            good.replace(
                "message_attachment_count=1",
                "message_attachment_count=1025",
            ),
            good.replace("message_end=1\n", ""),
            good.replace("message_end=1", "message_end=0"),
            good.replace("message_uid=1", "message_uid=1\nmessage_uid=2"),
            good.replace("status=ok", "status=ok\nstatus=ok"),
            format!("{good}unexpected=1\n"),
            format!(
                "{good}{}",
                "x".repeat(super::super::DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES)
            ),
        ] {
            assert!(parse_batch(&bad).is_err());
        }
        let mut many = (1..=250).map(|uid| row("INBOX", uid)).collect::<Vec<_>>();
        many.push(row("Foreign", 251));
        assert!(parse_batch(&encode_response(&response(many))).is_err());
    }

    #[test]
    fn single_folder_codec_and_hmac_stay_byte_compatible() {
        let mut request = MailboxHelperRequest::MessageSearch {
            canonical_username: "alice@example.com".into(),
            mailbox_name: "INBOX".into(),
            query: "quarterly report".into(),
            field: MessageSearchField::Subject,
            grant: MailboxHelperGrant::unsigned(),
        };
        issue_request_grant_with_nonce(&mut request, KEY, 100, &"01".repeat(32)).unwrap();
        assert_eq!(
            request_grant(&request).signature,
            "bccdf09c77c981ea96c7302dd44981597e740f914e3b6b9422d09b4ac9d4f3e3"
        );
        assert_eq!(encode_request(&request), format!(
            "operation=message_search\ncanonical_username_b64=YWxpY2VAZXhhbXBsZS5jb20=\nmailbox_name_b64=SU5CT1g=\nquery_b64=cXVhcnRlcmx5IHJlcG9ydA==\nsearch_field=subject\ngrant_issued_at=100\ngrant_expires_at=160\ngrant_nonce={}\ngrant_signature={}\n",
            "01".repeat(32), request_grant(&request).signature));
        assert_eq!(parse_request(&encode_request(&request)).unwrap(), request);
    }
}
