use super::*;
use crate::message_metadata::{MessageFlag, MessageMetadata, MessageVersion};

fn flag_request() -> MessageFlagRequest {
    MessageFlagRequest::new(
        "INBOX".into(),
        7,
        MessageVersion::new("a".repeat(32), "fixture-7".into()).expect("version"),
        MessageFlag::Seen,
        true,
    )
    .expect("request")
}

fn parse(text: &str) -> Result<MailboxHelperResponse, String> {
    parse_response(
        MailboxListingPolicy::default(),
        MessageListPolicy::default(),
        MessageSearchPolicy::default(),
        MessageViewPolicy::default(),
        text,
    )
}

#[test]
fn flag_grant_binds_every_identity_and_mutation_field() {
    let mut request = MailboxHelperRequest::MessageFlag {
        canonical_username: "alice@example.test".into(),
        request: flag_request(),
        grant: MailboxHelperGrant::unsigned(),
    };
    let key = test_helper_grant_key();
    issue_request_grant_with_nonce(&mut request, &key, 100, &test_grant_nonce(2)).expect("issue");
    assert_eq!(
        parse_request(&encode_request(&request)).expect("decode"),
        request
    );
    verify_request_grant(&request, &key, 101).expect("verify");
    for changed in 0..7 {
        let mut modified = request.clone();
        if let MailboxHelperRequest::MessageFlag {
            canonical_username,
            request,
            ..
        } = &mut modified
        {
            match changed {
                0 => *canonical_username = "bob@example.test".into(),
                1 => request.mailbox_name = "Sent".into(),
                2 => request.uid += 1,
                3 => request.version.mailbox_guid = "b".repeat(32),
                4 => request.version.message_guid = "fixture-other".into(),
                5 => request.flag = MessageFlag::Flagged,
                _ => request.enabled = false,
            }
        }
        assert!(verify_request_grant(&modified, &key, 101).is_err());
    }
    assert!(verify_request_grant(&request, &key, 161).is_err());
    let encoded = encode_request(&request);
    for modified in [
        encoded.replace("flag_enabled=1", "flag_enabled=2"),
        encoded.replace("flag_name=seen", "flag_name=deleted"),
        encoded.replace("flag_uid=7", "flag_uid=0"),
        format!("{encoded}flag_enabled=1\n"),
        format!("{encoded}unexpected=1\n"),
    ] {
        assert!(parse_request(&modified).is_err());
    }
    let cache = Mutex::new(BTreeMap::new());
    issue_request_grant_with_nonce(
        &mut request,
        &key,
        current_unix_time_secs().expect("clock"),
        &test_grant_nonce(3),
    )
    .expect("fresh issue");
    verify_helper_request_authority(&request, &key, &cache).expect("first grant use");
    assert!(verify_helper_request_authority(&request, &key, &cache).is_err());
}

#[test]
fn metadata_survives_read_responses_and_partial_identity_fails() {
    let metadata = MessageMetadata {
        attachments: None,
            protection: crate::message_metadata::MessageProtection::Unknown,
        preview: Some("Public synthetic preview".into()),
        version: flag_request().version,
        attachment_count: Some(2),
    };
    let summary = MessageSummary {
        to: None,
        metadata: Some(metadata.clone()),
        mailbox_name: "INBOX".into(),
        uid: 7,
        flags: vec!["\\Seen".into()],
        date_received: "2026-09-30 00:00:00".into(),
        size_virtual: 20,
        subject: Some("Synthetic fixture".into()),
        from: None,
    };
    let responses = [
        MailboxHelperResponse::MessageListOk {
            mailbox_name: "INBOX".into(),
            messages: vec![summary.clone()],
        },
        MailboxHelperResponse::MessageSearchOk {
            mailbox_name: "INBOX".into(),
            query: "fixture".into(),
            field: MessageSearchField::All,
            results: vec![MessageSearchResult {
                metadata: Some(metadata.clone()),
                mailbox_name: "INBOX".into(),
                uid: 7,
                flags: summary.flags.clone(),
                date_received: summary.date_received.clone(),
                size_virtual: 20,
                subject: summary.subject.clone(),
                from: None,
            }],
        },
        MailboxHelperResponse::MessageViewOk {
            message: Box::new(MessageView {
                metadata: Some(metadata),
                mailbox_name: "INBOX".into(),
                uid: 7,
                flags: summary.flags,
                date_received: summary.date_received,
                size_virtual: 20,
                header_block: "Subject: Synthetic fixture\n".into(),
                body_text: "Synthetic body\n".into(),
            }),
        },
    ];
    for response in responses {
        let encoded = encode_response(&response);
        assert_eq!(parse(&encoded).expect("round trip"), response);
        for preview in [
            "x".repeat(161),
            "private\ncontrol".into(),
            "-----BEGIN PGP MESSAGE-----".into(),
        ] {
            let mut malformed_response = response.clone();
            let metadata = match &mut malformed_response {
                MailboxHelperResponse::MessageListOk { messages, .. } => &mut messages[0].metadata,
                MailboxHelperResponse::MessageSearchOk { results, .. } => &mut results[0].metadata,
                MailboxHelperResponse::MessageViewOk { message } => &mut message.metadata,
                _ => unreachable!(),
            };
            metadata.as_mut().expect("fixture metadata").preview = Some(preview);
            let malformed = encode_response(&malformed_response);
            assert!(parse(&malformed).is_err());
        }
        let partial = encoded
            .lines()
            .filter(|line| !line.starts_with("message_mailbox_guid="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse(&partial).is_err());
        assert!(parse(&encoded.replace(
            "message_attachment_count=2",
            "message_attachment_count=999999"
        ))
        .is_err());
        assert!(parse(&encoded.replace(
            "message_attachment_count=2",
            "message_attachment_count=unknown"
        ))
        .is_ok());
    }
}

#[cfg(unix)]
#[test]
fn signed_flag_operation_crosses_the_helper_socket_boundary() {
    let socket = temp_socket_path("message-flag-helper-ok");
    let backend = StaticHelperBackend {
        mailbox_result: Arc::new(Ok(Vec::new())),
        message_list_result: Arc::new(Ok(Vec::new())),
        message_search_result: Arc::new(Ok(Vec::new())),
        message_view_result: Arc::new(Err(MailboxBackendError {
            backend: "fixture-unused",
            reason: "unused".into(),
        })),
        message_move_result: Arc::new(Ok(())),
    };
    let server = spawn_test_helper(socket.clone(), backend);
    wait_for_socket(&socket);
    let key = temp_grant_key_path("message-flag-helper-ok");
    let client =
        MailboxHelperMessageFlagBackend::new(&socket, &key, MailboxHelperPolicy::default());
    assert_eq!(
        client.set_message_flag("alice@example.test", &flag_request()),
        Ok(MessageFlagResult::Updated)
    );
    server.join().expect("helper exit");
    fs::remove_file(socket).expect("remove socket");
    fs::remove_file(key).expect("remove fixture key");
}

#[cfg(unix)]
#[test]
fn mismatched_helper_confirmation_is_an_unknown_result() {
    let socket = temp_socket_path("message-flag-helper-mismatch");
    let listener = UnixListener::bind(&socket).expect("fixture socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut input = Vec::new();
        stream.read_to_end(&mut input).expect("read");
        let mut request = flag_request();
        request.uid = 8;
        let response = encode_response(&MailboxHelperResponse::MessageFlagOk {
            request,
            result: MessageFlagResult::Updated,
        });
        stream.write_all(response.as_bytes()).expect("write");
    });
    let key = temp_grant_key_path("message-flag-helper-mismatch");
    let client =
        MailboxHelperMessageFlagBackend::new(&socket, &key, MailboxHelperPolicy::default());
    assert_eq!(
        client
            .set_message_flag("alice@example.test", &flag_request())
            .expect_err("mismatch")
            .backend,
        "message-flag-unknown"
    );
    server.join().expect("helper exit");
    fs::remove_file(socket).expect("remove socket");
    fs::remove_file(key).expect("remove fixture key");
}

#[test]
fn flag_confirmation_rejects_duplicate_and_unrelated_fields() {
    let response = encode_response(&MailboxHelperResponse::MessageFlagOk {
        request: flag_request(),
        result: MessageFlagResult::Updated,
    });
    for extra in [
        "status=ok\n",
        "operation=message_flag\n",
        "mailbox_count=0\n",
        "message_bytes=0\n",
        "backend_b64=eA==\n",
        "flag_result=updated\n",
    ] {
        assert!(parse(&format!("{response}{extra}")).is_err());
    }
    assert!(parse(&response.replace("operation=message_flag", "operation=mailbox_list")).is_err());
}

#[test]
fn sent_recipient_helper_roundtrip_is_optional_bounded_and_strict() {
    let row = MessageSummary {
        to: Some("Élodie <elodie@example.test>, <b>Literal</b>".into()),
        metadata: None,
        mailbox_name: "Sent".into(),
        uid: 1,
        flags: vec![],
        date_received: "2026-09-30".into(),
        size_virtual: 12,
        subject: None,
        from: Some("self@example.test".into()),
    };
    let response = MailboxHelperResponse::MessageListOk {
        mailbox_name: "Sent".into(),
        messages: vec![row.clone()],
    };
    let encoded = encode_response(&response);
    assert!(!encoded.contains("bcc"));
    assert_eq!(parse(&encoded).unwrap(), response);
    let legacy = encoded
        .lines()
        .filter(|line| !line.starts_with("message_to_b64="))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let MailboxHelperResponse::MessageListOk { messages, .. } = parse(&legacy).unwrap() else {
        panic!("wrong response")
    };
    assert_eq!(messages[0].to, None);
    let original = encoded
        .lines()
        .find(|line| line.starts_with("message_to_b64="))
        .unwrap();
    assert!(parse(&encoded.replace(original, "message_to_b64=%%%")).is_err());
    for value in [
        "bad\nheader".to_owned(),
        "x".repeat(MessageListPolicy::default().header_value_max_len + 1),
    ] {
        let mut bad = row.clone();
        bad.to = Some(value);
        assert!(
            parse(&encode_response(&MailboxHelperResponse::MessageListOk {
                mailbox_name: "Sent".into(),
                messages: vec![bad]
            }))
            .is_err()
        );
    }
    assert!(parse(&encoded.replace(original, &format!("{original}\n{original}"))).is_err());
}
