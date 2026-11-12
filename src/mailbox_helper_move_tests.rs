use super::*;
use crate::message_metadata::MessageVersion;

fn move_request() -> MessageMoveRequest {
    MessageMoveRequest::new(
        MessageMovePolicy::default(),
        "INBOX",
        "Archive",
        9,
        MessageVersion::new("a".repeat(32), "fixture-9".into()).unwrap(),
    )
    .unwrap()
}
fn confirmation() -> MailboxHelperResponse {
    let request = move_request();
    MailboxHelperResponse::MessageMoveOk {
        source_mailbox_name: request.source_mailbox_name,
        destination_mailbox_name: request.destination_mailbox_name,
        uid: request.uid,
        version: request.version,
    }
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
fn move_grant_binds_account_both_folders_uid_and_stored_generation() {
    let move_request = move_request();
    let mut request = MailboxHelperRequest::MessageMove {
        canonical_username: "alice@example.test".into(),
        source_mailbox_name: move_request.source_mailbox_name,
        destination_mailbox_name: move_request.destination_mailbox_name,
        uid: move_request.uid,
        version: move_request.version,
        grant: MailboxHelperGrant::unsigned(),
    };
    let key = test_helper_grant_key();
    issue_request_grant_with_nonce(&mut request, &key, 100, &test_grant_nonce(7)).unwrap();
    assert_eq!(parse_request(&encode_request(&request)).unwrap(), request);
    verify_request_grant(&request, &key, 101).unwrap();
    for changed in 0..6 {
        let mut modified = request.clone();
        if let MailboxHelperRequest::MessageMove {
            canonical_username,
            source_mailbox_name,
            destination_mailbox_name,
            uid,
            version,
            ..
        } = &mut modified
        {
            match changed {
                0 => *canonical_username = "bob@example.test".into(),
                1 => *source_mailbox_name = "Sent".into(),
                2 => *destination_mailbox_name = "Trash".into(),
                3 => *uid += 1,
                4 => version.mailbox_guid = "b".repeat(32),
                _ => version.message_guid = "other-fixture".into(),
            }
        }
        assert!(verify_request_grant(&modified, &key, 101).is_err());
    }
    assert!(verify_request_grant(&request, &key, 161).is_err());
    let encoded = encode_request(&request);
    for changed in [
        encoded.replace("uid=9\n", "uid=0\n"),
        encoded.replace("uid=9\n", "uid=4294967296\n"),
        format!("{encoded}unexpected=1\n"),
        format!("{encoded}move_mailbox_guid={}\n", "a".repeat(32)),
        encoded
            .lines()
            .filter(|line| !line.starts_with("move_message_guid_b64="))
            .collect::<Vec<_>>()
            .join("\n"),
    ] {
        assert!(parse_request(&changed).is_err());
    }
    issue_request_grant_with_nonce(
        &mut request,
        &key,
        current_unix_time_secs().unwrap(),
        &test_grant_nonce(8),
    )
    .unwrap();
    let cache = Mutex::new(BTreeMap::new());
    verify_helper_request_authority(&request, &key, &cache).unwrap();
    assert!(verify_helper_request_authority(&request, &key, &cache).is_err());
}

#[test]
fn move_confirmation_is_strict_and_old_or_mixed_responses_are_refused() {
    let response = confirmation();
    let encoded = encode_response(&response);
    assert_eq!(parse(&encoded).unwrap(), response);
    for changed in [
        format!("{encoded}message_count=1\n"),
        format!("{encoded}uid=9\n"),
        format!("{encoded}move_message_guid_b64=Zml4dHVyZS05\n"),
        encoded
            .lines()
            .filter(|line| !line.starts_with("move_mailbox_guid="))
            .collect::<Vec<_>>()
            .join("\n"),
        encoded.replace("operation=message_move", "operation=message_append"),
    ] {
        assert!(parse(&changed).is_err());
    }
}

#[cfg(unix)]
#[test]
fn changed_or_truncated_move_confirmation_is_unknown_without_retry() {
    for changed in 0..4 {
        let socket = temp_socket_path("move-confirmation");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).unwrap();
            let mut response = confirmation();
            if let MailboxHelperResponse::MessageMoveOk { uid, version, .. } = &mut response {
                match changed {
                    0 => *uid += 1,
                    1 => version.mailbox_guid = "b".repeat(32),
                    _ => version.message_guid = "other".into(),
                }
            }
            let encoded = if changed == 3 {
                "status=ok\noperation=message_move\n".into()
            } else {
                encode_response(&response)
            };
            stream.write_all(encoded.as_bytes()).unwrap();
        });
        let key = temp_grant_key_path("move-confirmation");
        let client =
            MailboxHelperMessageMoveBackend::new(&socket, &key, MailboxHelperPolicy::default());
        assert_eq!(
            client
                .move_message("alice@example.test", &move_request())
                .unwrap_err()
                .backend,
            "message-move-unknown"
        );
        server.join().unwrap();
        fs::remove_file(socket).unwrap();
        fs::remove_file(key).unwrap();
    }
}
