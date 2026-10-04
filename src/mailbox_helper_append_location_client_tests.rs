use super::*;
use std::os::unix::fs::PermissionsExt;
const GUID: &str = "1234567890abcdef1234567890abcdef";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "osmap-location-client-{}",
            crate::draft::generate_draft_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn selected() -> MessageAppendRequest {
    MessageAppendRequest::new("INBOX.CopyA", b"public fixture".to_vec())
        .unwrap()
        .with_destination_mailbox_guid(GUID)
        .unwrap()
}
fn client(root: &Scratch, uid: Option<u32>) -> MailboxHelperMessageAppendBackend {
    let key = root.0.join("key");
    std::fs::write(&key, b"fixture-private-grant-32-bytes-not-real").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    MailboxHelperMessageAppendBackend::new(root.0.join("sock"), key, MailboxHelperPolicy::default())
        .with_helper_uid(uid)
}
#[test]
fn sent_location_client_selected_exact_echo_and_wrong_guid_or_lost_reply_refuse_without_retry() {
    for response in [
        Some(Some(GUID)),
        Some(Some("abcdef1234567890abcdef1234567890")),
        Some(None),
        None,
    ] {
        let response_guid = response.flatten();
        let root = Scratch::new();
        let listener = UnixListener::bind(root.0.join("sock")).unwrap();
        let c = client(&root, Some(crate::openbsd::effective_uid()));
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            let parsed = parse_request(&request).unwrap();
            verify_request_grant(
                &parsed,
                b"fixture-private-grant-32-bytes-not-real",
                current_unix_time_secs().unwrap(),
            )
            .unwrap();
            assert!(
                matches!(parsed,MailboxHelperRequest::MessageAppend{destination_mailbox_guid:Some(ref guid),..} if guid==GUID)
            );
            if response.is_none() {
                return;
            }
            let reply = MailboxHelperResponse::MessageAppendOk {
                mailbox_name: "INBOX.CopyA".into(),
                message_bytes: 14,
                destination_mailbox_guid: response_guid.map(str::to_owned),
            };
            stream
                .write_all(encode_response(&reply).as_bytes())
                .unwrap();
        });
        assert_eq!(
            c.append_message("alice@example.test", &selected()).is_ok(),
            response_guid == Some(GUID)
        );
        worker.join().unwrap();
    }
}
#[test]
fn sent_location_client_wrong_peer_refuses_before_request_write_and_missing_uid_is_unavailable() {
    let root = Scratch::new();
    let listener = UnixListener::bind(root.0.join("sock")).unwrap();
    let c = client(&root, Some(crate::openbsd::effective_uid().wrapping_add(1)));
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    });
    assert!(c.append_message("alice@example.test", &selected()).is_err());
    worker.join().unwrap();
    assert!(client(&root, None)
        .append_message("alice@example.test", &selected())
        .is_err());
}
