use super::*;
const GUID: &str = "1234567890abcdef1234567890abcdef";
const KEY: &[u8] = b"sent-location-fixture-authenticated-key-32";
fn request(guid: Option<&str>) -> MailboxHelperRequest {
    MailboxHelperRequest::MessageAppend {
        canonical_username: "alice@example.test".into(),
        mailbox_name: "INBOX.CopyA".into(),
        message: b"Subject: fixture\r\n\r\npublic".to_vec(),
        destination_mailbox_guid: guid.map(str::to_owned),
        grant: MailboxHelperGrant::unsigned(),
    }
}
fn response_parse(wire: &str) -> Result<MailboxHelperResponse, String> {
    parse_response(
        MailboxListingPolicy::default(),
        MessageListPolicy::default(),
        MessageSearchPolicy::default(),
        MessageViewPolicy::default(),
        wire,
    )
}
#[test]
fn sent_location_append_codec_optional_guid_roundtrip_and_strict_wrong_operation() {
    let mut selected = request(Some(GUID));
    issue_request_grant_with_nonce(&mut selected, KEY, 100, &"a".repeat(32)).unwrap();
    let wire = encode_request(&selected);
    assert_eq!(parse_request(&wire).unwrap(), selected);
    assert!(parse_request(&wire.replace(GUID, "00000000000000000000000000000000")).is_err());
    assert!(parse_request(&format!("{wire}append_mailbox_guid={GUID}\n")).is_err());
    let mut wrong = MailboxHelperRequest::MailboxList {
        canonical_username: "alice@example.test".into(),
        grant: MailboxHelperGrant::unsigned(),
    };
    issue_request_grant_with_nonce(&mut wrong, KEY, 100, &"b".repeat(32)).unwrap();
    assert!(parse_request(&format!(
        "{}append_mailbox_guid={GUID}\n",
        encode_request(&wrong)
    ))
    .is_err());
    let response = MailboxHelperResponse::MessageAppendOk {
        mailbox_name: "INBOX.CopyA".into(),
        message_bytes: 28,
        destination_mailbox_guid: Some(GUID.into()),
    };
    let wire = encode_response(&response);
    assert_eq!(response_parse(&wire).unwrap(), response);
    assert!(response_parse(&format!("{wire}append_mailbox_guid={GUID}\n")).is_err());
    assert!(response_parse(&format!(
        "status=ok\noperation=mailbox_list\nmailbox_count=0\nappend_mailbox_guid={GUID}\n"
    ))
    .is_err());
}
#[test]
fn sent_location_append_legacy_bytes_and_hmac_payload_remain_identical_without_field() {
    let mut old = request(None);
    issue_request_grant_with_nonce(&mut old, KEY, 100, &"a".repeat(32)).unwrap();
    let grant = request_grant(&old);
    let expected = format!(
        "v1\0message_append\0100\0160\0{}\0alice@example.test\0INBOX.CopyA\0{}",
        grant.nonce,
        hex_lower(&Sha256::digest(b"Subject: fixture\r\n\r\npublic"))
    );
    assert_eq!(canonical_grant_payload(&old, grant), expected);
    let wire = encode_request(&old);
    assert!(!wire.contains("append_mailbox_guid"));
    assert_eq!(parse_request(&wire).unwrap(), old);
    let reply = MailboxHelperResponse::MessageAppendOk {
        mailbox_name: "Sent".into(),
        message_bytes: 1,
        destination_mailbox_guid: None,
    };
    assert_eq!(
        encode_response(&reply),
        "status=ok\noperation=message_append\nmailbox_name_b64=U2VudA==\nmessage_bytes=1\n"
    );
}
#[test]
fn sent_location_append_grant_authenticates_guid_and_tampering_removal_expiry_before_dispatch() {
    let mut selected = request(Some(GUID));
    issue_request_grant_with_nonce(&mut selected, KEY, 100, &"a".repeat(32)).unwrap();
    verify_request_grant(&selected, KEY, 100).unwrap();
    assert!(verify_request_grant(&selected, KEY, 161).is_err());
    for guid in [Some("abcdef1234567890abcdef1234567890"), None] {
        let mut tampered = selected.clone();
        if let MailboxHelperRequest::MessageAppend {
            destination_mailbox_guid,
            ..
        } = &mut tampered
        {
            *destination_mailbox_guid = guid.map(str::to_owned);
        }
        assert!(verify_request_grant(&tampered, KEY, 100).is_err());
    }
}
