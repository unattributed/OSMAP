use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
const KEY: &[u8] = b"documents-synthetic-key-not-a-credential-123";
const ACCOUNT: &str = "alice@example.test";
const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn location(mailbox: &str) -> Location {
    Location {
        mailbox: mailbox.into(),
        uid: 7,
        mailbox_guid: "b".repeat(32),
        message_guid: "c".repeat(32),
    }
}
fn payload(operation: Operation) -> Payload {
    Payload {
        account: ACCOUNT.into(),
        operation,
        issued_at: 100,
        expires_at: 160,
        nonce: "d".repeat(32),
    }
}
fn signed(payload: Payload) -> Request {
    let signature = hex(&mac(&payload, KEY).unwrap().finalize().into_bytes());
    Request { payload, signature }
}
fn wire(request: &Request) -> Vec<u8> {
    let mut bytes = PREFIX.to_vec();
    bytes.extend(serde_json::to_vec(request).unwrap());
    bytes
}
#[derive(Default)]
struct Fixture {
    writes: AtomicUsize,
    reads: AtomicUsize,
    ready: bool,
    body: Mutex<Vec<u8>>,
    mailbox: Mutex<String>,
}
impl Backend for Fixture {
    fn quota_status(&self, account: &str) -> Result<Option<QuotaStatus>, Error> {
        Ok(self.quota_ready(account)?.then_some(QuotaStatus {
            used_bytes: self.body.lock().unwrap().len() as u64,
            limit_bytes: 100 * 1024 * 1024,
        }))
    }
    fn quota_ready(&self, account: &str) -> Result<bool, Error> {
        if account != ACCOUNT {
            return Err(Error::NotFound);
        }
        Ok(self.ready)
    }
    fn inspect(&self, account: &str, id: &str) -> Result<Vec<Location>, Error> {
        if (account, id) != (ACCOUNT, ID) {
            return Err(Error::NotFound);
        }
        let mailbox = self.mailbox.lock().unwrap();
        Ok(if mailbox.is_empty() {
            vec![]
        } else {
            vec![location(&mailbox)]
        })
    }
    fn append(
        &self,
        account: &str,
        id: &str,
        _: &str,
        _: &str,
        body: &[u8],
    ) -> Result<Location, Error> {
        assert_eq!((account, id), (ACCOUNT, ID));
        if !self.quota_ready(account)? {
            return Err(Error::PreDispatchUnavailable);
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.body.lock().unwrap() = body.to_vec();
        *self.mailbox.lock().unwrap() = "OSMAP.Documents".into();
        Ok(location("OSMAP.Documents"))
    }
    fn read(&self, account: &str, id: &str, old: &Location) -> Result<Vec<u8>, Error> {
        if (account, id) != (ACCOUNT, ID) {
            return Err(Error::NotFound);
        }
        if *old != location(&old.mailbox) || *self.mailbox.lock().unwrap() != old.mailbox {
            return Err(Error::Stale);
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.body.lock().unwrap().clone())
    }
    fn move_to_bin(&self, account: &str, id: &str, old: &Location) -> Result<Location, Error> {
        assert_eq!((account, id), (ACCOUNT, ID));
        if *old != location("OSMAP.Documents") || *self.mailbox.lock().unwrap() != "OSMAP.Documents"
        {
            return Err(Error::Stale);
        }
        *self.mailbox.lock().unwrap() = "OSMAP.DocumentsBin".into();
        Ok(location("OSMAP.DocumentsBin"))
    }
    fn restore(&self, account: &str, id: &str, old: &Location) -> Result<Location, Error> {
        assert_eq!((account, id), (ACCOUNT, ID));
        if *old != location("OSMAP.DocumentsBin")
            || *self.mailbox.lock().unwrap() != "OSMAP.DocumentsBin"
        {
            return Err(Error::Stale);
        }
        *self.mailbox.lock().unwrap() = "OSMAP.Documents".into();
        Ok(location("OSMAP.Documents"))
    }
    fn expunge(&self, account: &str, id: &str, old: &Location) -> Result<(), Error> {
        assert_eq!((account, id), (ACCOUNT, ID));
        if *old != location("OSMAP.DocumentsBin")
            || *self.mailbox.lock().unwrap() != "OSMAP.DocumentsBin"
        {
            return Err(Error::Stale);
        }
        self.body.lock().unwrap().clear();
        self.mailbox.lock().unwrap().clear();
        Ok(())
    }
}
fn append(body: &[u8]) -> Operation {
    Operation::Append {
        id: ID.into(),
        name: "synthetic.bin".into(),
        media_type: "application/octet-stream".into(),
        body_b64: encode_body(body),
        size: body.len(),
        sha256: hash(body),
    }
}

#[test]
fn grants_bind_all_document_identity_content_and_native_revisions() {
    let request = signed(payload(append(b"synthetic")));
    let parsed = parse(&wire(&request)).unwrap();
    verify(&parsed, KEY, 100, &Mutex::new(BTreeMap::new())).unwrap();
    let mut candidates = Vec::new();
    let mut changed = request.clone();
    changed.payload.nonce = "e".repeat(32);
    candidates.push(changed);
    let mut changed = request.clone();
    changed.payload.account = "bob@example.test".into();
    candidates.push(changed);
    let mut changed = request.clone();
    changed.payload.operation = Operation::Quota;
    candidates.push(changed);
    let mut changed = request.clone();
    if let Operation::Append { name, .. } = &mut changed.payload.operation {
        *name = "changed.bin".into();
    }
    candidates.push(changed);
    let mut changed = request.clone();
    if let Operation::Append { media_type, .. } = &mut changed.payload.operation {
        *media_type = "text/plain".into();
    }
    candidates.push(changed);
    let mut changed = request.clone();
    if let Operation::Append { id, .. } = &mut changed.payload.operation {
        *id = "e".repeat(32);
    }
    candidates.push(changed);
    let mut changed = request.clone();
    changed.payload.operation = append(b"different");
    candidates.push(changed);
    let read = signed(payload(Operation::Read {
        id: ID.into(),
        location: location("OSMAP.Documents"),
    }));
    let mut changed = read.clone();
    if let Operation::Read { location, .. } = &mut changed.payload.operation {
        location.uid = 8;
    }
    candidates.push(changed);
    let mut changed = read.clone();
    if let Operation::Read { location, .. } = &mut changed.payload.operation {
        location.message_guid = "e".repeat(32);
    }
    candidates.push(changed);
    for candidate in candidates {
        assert!(verify(&candidate, KEY, 100, &Mutex::new(BTreeMap::new())).is_err());
    }
    assert!(verify(&request, KEY, 99, &Mutex::new(BTreeMap::new())).is_err());
    assert!(verify(&request, KEY, 161, &Mutex::new(BTreeMap::new())).is_err());
    let replay = Mutex::new(BTreeMap::new());
    verify(&request, KEY, 100, &replay).unwrap();
    assert!(verify(&request, KEY, 100, &replay).is_err());
    let mut json = serde_json::to_value(&request).unwrap();
    json["unexpected"] = true.into();
    let mut malformed = PREFIX.to_vec();
    malformed.extend(serde_json::to_vec(&json).unwrap());
    assert!(parse(&malformed).is_err());
    let mut json = serde_json::to_value(&request).unwrap();
    json["payload"]["operation"]["unknown_path"] = "/tmp/untrusted".into();
    let mut malformed = PREFIX.to_vec();
    malformed.extend(serde_json::to_vec(&json).unwrap());
    assert!(parse(&malformed).is_err());
    let mut changed_body = request.clone();
    if let Operation::Append { body_b64, .. } = &mut changed_body.payload.operation {
        *body_b64 = encode_body(b"different");
    }
    verify(&changed_body, KEY, 100, &Mutex::new(BTreeMap::new())).unwrap();
    let fixture = Fixture {
        ready: true,
        ..Fixture::default()
    };
    assert_eq!(
        dispatch(&fixture, &changed_body.payload),
        Err(Error::Invalid)
    );
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn absent_or_wrong_helper_peer_never_dispatches_a_document() {
    let client = MailboxHelperDocumentsBackend::new(
        "/unavailable",
        "/unavailable",
        MailboxHelperPolicy::default(),
    );
    assert_eq!(client.quota_ready(ACCOUNT), Err(Error::Unavailable));
    let root = std::env::temp_dir().join(format!(
        "osmap-doc-peer-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("helper.sock");
    let key = root.join("grant.key");
    fs::write(&key, KEY).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(read_bounded_from_stream(&mut stream, 8192)
            .unwrap()
            .is_empty());
    });
    let client = MailboxHelperDocumentsBackend::new(&socket, &key, MailboxHelperPolicy::default())
        .with_helper_uid(u32::MAX);
    assert_eq!(client.quota_ready(ACCOUNT), Err(Error::Unavailable));
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn dedicated_request_read_has_one_deadline_for_fragmented_bytes() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    let sender = thread::spawn(move || {
        writer.write_all(PREFIX).unwrap();
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(100));
            if writer.write_all(b" ").is_err() {
                break;
            }
        }
    });
    let policy = MailboxHelperPolicy {
        read_timeout_secs: 1,
        write_timeout_secs: 1,
        ..MailboxHelperPolicy::default()
    };
    let start = std::time::Instant::now();
    assert!(read_request_bytes(&mut reader, policy).is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(reader);
    sender.join().unwrap();
}

#[test]
fn ordinary_socket_response_still_refuses_one_mib_plus_one_byte() {
    let root = std::env::temp_dir().join(format!(
        "osmap-doc-ordinary-limit-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("helper.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
        read_bounded_from_stream(&mut stream, 8192).unwrap();
        let _ = stream.write_all(&vec![b'x'; DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES + 1]);
    });
    let policy = MailboxHelperPolicy::default();
    let response = mailbox_helper_client::helper_exchange_before(
        &socket,
        b"ordinary",
        policy,
        mailbox_helper_client::helper_request_deadline(policy),
    );
    assert!(response.unwrap_err().contains("maximum size of 1048576"));
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exact_ten_mib_policy_and_hash_framing_are_bounded() {
    let body = vec![0x9a; MAX_FILE_BYTES];
    let request = signed(payload(append(&body)));
    assert!(wire(&request).len() <= MAX_DOCUMENTS_WIRE_BYTES);
    assert!(wire(&request).len() > DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES);
    parse(&wire(&request)).unwrap();
    let mut invalid = request.clone();
    if let Operation::Append { size, .. } = &mut invalid.payload.operation {
        *size += 1;
    }
    assert!(parse(&wire(&invalid)).is_err());
    if let Operation::Append {
        body_b64,
        size,
        sha256,
        ..
    } = &request.payload.operation
    {
        assert_eq!(decode_body(body_b64, *size, sha256).unwrap(), body);
        assert!(decode_body(body_b64, *size, &"0".repeat(64)).is_err());
    }
    assert!(parse(&vec![b'x'; MAX_DOCUMENTS_WIRE_BYTES + 1]).is_err());
    assert_eq!(DEFAULT_MAILBOX_HELPER_MAX_RESPONSE_BYTES, 1024 * 1024);
}

#[test]
fn only_dedicated_reserved_mailboxes_and_typed_locations_are_accepted() {
    for name in [
        "OSMAP.Documents",
        "osmap.documentsbin",
        "OSMAP.Documents.child",
    ] {
        assert!(reserved_mailbox(name));
    }
    for name in ["INBOX", "Documents", "OSMAP.DocumentsElse"] {
        assert!(!reserved_mailbox(name));
    }
    for mailbox in ["INBOX", "../OSMAP.Documents"] {
        assert!(validate(&payload(Operation::Read {
            id: ID.into(),
            location: location(mailbox)
        }))
        .is_err());
    }
    assert!(validate(&payload(Operation::Read {
        id: ID.into(),
        location: location("OSMAP.DocumentsBin")
    }))
    .is_ok());
    assert!(validate(&payload(Operation::Expunge {
        id: ID.into(),
        location: location("OSMAP.Documents")
    }))
    .is_err());
    assert!(
        validate_locations(&[location("OSMAP.Documents"), location("OSMAP.Documents")]).is_err()
    );
    assert!(validate_locations(&[location("INBOX")]).is_err());
    assert!(validate(&payload(Operation::Read {
        id: "../../foreign".into(),
        location: location("OSMAP.Documents")
    }))
    .is_err());
    let mut wrong_guid = location("OSMAP.Documents");
    wrong_guid.message_guid = "x".repeat(32);
    assert!(validate(&payload(Operation::Read {
        id: ID.into(),
        location: wrong_guid
    }))
    .is_err());
    let backend = Fixture::default();
    assert_eq!(
        dispatch(&backend, &payload(append(b"x"))),
        Err(Error::PreDispatchUnavailable)
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn ordinary_search_view_download_append_move_and_metadata_cannot_expose_documents() {
    let grant = MailboxHelperGrant::unsigned();
    let mailbox = "OSMAP.Documents".to_string();
    let requests = vec![
        MailboxHelperRequest::MessageList {
            canonical_username: ACCOUNT.into(),
            mailbox_name: mailbox.clone(),
            grant: grant.clone(),
        },
        MailboxHelperRequest::MessageSearch {
            canonical_username: ACCOUNT.into(),
            mailbox_name: mailbox.clone(),
            query: "synthetic".into(),
            field: MessageSearchField::All,
            grant: grant.clone(),
        },
        MailboxHelperRequest::MessageSearchBatch {
            canonical_username: ACCOUNT.into(),
            mailbox_names: vec!["INBOX".into(), mailbox.clone()],
            query: "synthetic".into(),
            field: MessageSearchField::All,
            grant: grant.clone(),
        },
        MailboxHelperRequest::MessageView {
            canonical_username: ACCOUNT.into(),
            mailbox_name: mailbox.clone(),
            uid: 7,
            grant: grant.clone(),
        },
        MailboxHelperRequest::AttachmentDownload {
            canonical_username: ACCOUNT.into(),
            mailbox_name: mailbox.clone(),
            uid: 7,
            part_path: "1".into(),
            grant: grant.clone(),
        },
        MailboxHelperRequest::MessageAppend {
            canonical_username: ACCOUNT.into(),
            mailbox_name: mailbox.clone(),
            message: b"From: alice@example.test\r\n\r\nsynthetic".to_vec(),
            destination_mailbox_guid: None,
            grant: grant.clone(),
        },
        MailboxHelperRequest::MessageMove {
            canonical_username: ACCOUNT.into(),
            source_mailbox_name: mailbox.clone(),
            destination_mailbox_name: "INBOX".into(),
            uid: 7,
            version: crate::message_metadata::MessageVersion {
                mailbox_guid: "b".repeat(32),
                message_guid: "c".repeat(32),
            },
            grant: grant.clone(),
        },
        MailboxHelperRequest::MessageMove {
            canonical_username: ACCOUNT.into(),
            source_mailbox_name: "INBOX".into(),
            destination_mailbox_name: mailbox.clone(),
            uid: 7,
            version: crate::message_metadata::MessageVersion {
                mailbox_guid: "b".repeat(32),
                message_guid: "c".repeat(32),
            },
            grant,
        },
    ];
    for request in requests {
        assert!(!mailbox_helper_protocol::ordinary_request_allowed(&request));
        assert!(parse_request(&encode_request(&request)).is_err());
    }
    let transcript = b"* PREAUTH fixture\r\n* NAMESPACE ((\"\" \".\")) NIL NIL\r\nN1 OK done\r\n* LIST () \".\" \"INBOX\"\r\n* LIST () \".\" \"OSMAP.Documents\"\r\n* LIST () \".\" \"OSMAP.DocumentsBin\"\r\nL1 OK done\r\n* BYE done\r\nZ1 OK done\r\n";
    let snapshot = crate::folder_metadata::FolderSnapshot::parse(ACCOUNT, transcript).unwrap();
    let filtered = snapshot.without_reserved_documents().unwrap();
    assert_eq!(filtered.folders().len(), 1);
    assert_eq!(filtered.folders()[0].name(), "INBOX");
    assert!(!String::from_utf8_lossy(filtered.transcript()).contains("Documents"));
}

#[test]
fn socket_round_trip_exceeds_ordinary_limit_and_runs_bin_restore() {
    socket_round_trip(2 * 1024 * 1024);
}

#[test]
fn socket_exact_ten_mib_binary_round_trip() {
    socket_round_trip(MAX_FILE_BYTES);
}

// Root runs this one finite endpoint only on Toronto in an isolated native
// fixture. The actual helper peer/grant/replay/response path is exercised;
// these synthetic bytes deliberately make no Dovecot or quota claim.
#[test]
#[ignore = "requires explicitly prepared private two-host relay fixture"]
fn native_documents_relay_endpoint() {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    struct OwnedEndpointFiles(Vec<std::path::PathBuf>);
    impl Drop for OwnedEndpointFiles {
        fn drop(&mut self) {
            for path in &self.0 {
                if let Err(error) = fs::remove_file(path) {
                    eprintln!("owned native endpoint cleanup failed: {error}");
                }
            }
        }
    }
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "native endpoint is OpenBSD-only"
    );
    let root = std::path::PathBuf::from(
        std::env::var_os("OSMAP_DOCUMENTS_NATIVE_ENDPOINT_ROOT")
            .expect("explicit private fixture root required"),
    );
    let name = root.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("osmap-s08-documents-"));
    assert!(name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    assert_eq!(root.parent(), Some(std::path::Path::new("/tmp")));
    assert_eq!(fs::canonicalize(&root).unwrap(), root);
    let metadata = fs::symlink_metadata(&root).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & 0o077, 0);
    let socket = root.join("helper.sock");
    let key = root.join("grant.key");
    let ready = root.join("helper-ready.json");
    for path in [&socket, &key, &ready] {
        assert!(!path.exists(), "fixture output must start absent");
    }
    let mut owned = OwnedEndpointFiles(Vec::new());
    let mut key_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key)
        .unwrap();
    owned.0.push(key.clone());
    // create_new makes this an actual current-process creator measurement;
    // the caller-supplied directory owner alone is not a current UID proof.
    let owner = key_file.metadata().unwrap().uid();
    assert_eq!(
        owner, 0,
        "standalone fixture SSHD uses its measured root principal"
    );
    assert_eq!(metadata.uid(), owner);
    key_file.write_all(KEY).unwrap();
    key_file.sync_all().unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    owned.0.push(socket.clone());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let backend = Fixture {
        body: Mutex::new((0..MAX_FILE_BYTES).map(|i| (i % 256) as u8).collect()),
        mailbox: Mutex::new("OSMAP.Documents".into()),
        ..Fixture::default()
    };
    let mut ready_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&ready)
        .unwrap();
    owned.0.push(ready.clone());
    serde_json::to_writer(
        &mut ready_file,
        &serde_json::json!({
            "account": ACCOUNT, "document_id": ID,
            "location": location("OSMAP.Documents"),
            "helper_socket": socket, "grant_key": key,
            "helper_uid": owner, "trusted_connector_uid": owner,
            "backend": "synthetic; not Dovecot or quota qualification"
        }),
    )
    .unwrap();
    ready_file.sync_all().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let accept_deadline = deadline - Duration::from_secs(15);
    let replay = Mutex::new(BTreeMap::new());
    for _ in 0..2 {
        let mut stream = loop {
            assert!(
                std::time::Instant::now() < accept_deadline,
                "finite native endpoint accept expired"
            );
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("private endpoint accept failed: {error}"),
            }
        };
        let trusted = MailboxHelperTrustedCallerPolicy {
            trusted_peer_uid: owner,
            grant_key: KEY.to_vec(),
        };
        authorize_helper_peer_uid(helper_stream_peer_uid(&stream).unwrap(), &trusted).unwrap();
        let bytes = read_request_bytes(&mut stream, MailboxHelperPolicy::default()).unwrap();
        assert!(matches!(
            parse(&bytes).unwrap().payload.operation,
            Operation::Read { .. }
        ));
        assert!(handle(&bytes, Some(&backend), &mut stream, KEY, &replay));
    }
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    assert!(std::time::Instant::now() < deadline);
    drop(listener);
    drop(owned);
    for path in [&socket, &key, &ready] {
        assert!(!path.exists(), "owned endpoint cleanup not confirmed");
    }
    println!("native Documents endpoint: peer verified, signed requests 2, backend reads 1, writes 0; synthetic bytes only");
}

fn socket_round_trip(file_bytes: usize) {
    let root = std::env::temp_dir().join(format!(
        "osmap-doc-helper-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let owner = fs::symlink_metadata(&root).unwrap().uid();
    let socket = root.join("helper.sock");
    let key = root.join("grant.key");
    fs::write(&key, KEY).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let backend = Arc::new(Fixture {
        ready: true,
        ..Fixture::default()
    });
    let fixture = Arc::clone(&backend);
    let server = thread::spawn(move || {
        let replay = Mutex::new(BTreeMap::new());
        for _ in 0..12 {
            let (mut stream, _) = listener.accept().unwrap();
            let trusted = MailboxHelperTrustedCallerPolicy {
                trusted_peer_uid: owner,
                grant_key: KEY.to_vec(),
            };
            authorize_helper_peer_uid(helper_stream_peer_uid(&stream).unwrap(), &trusted).unwrap();
            configure_stream_timeouts(&stream, MailboxHelperPolicy::default());
            let bytes = read_request_bytes(&mut stream, MailboxHelperPolicy::default()).unwrap();
            assert!(handle(
                &bytes,
                Some(fixture.as_ref()),
                &mut stream,
                KEY,
                &replay
            ));
        }
    });
    let client = MailboxHelperDocumentsBackend::new(&socket, &key, MailboxHelperPolicy::default())
        .with_helper_uid(owner);
    assert!(client.quota_ready(ACCOUNT).unwrap());
    assert!(client.inspect(ACCOUNT, ID).unwrap().is_empty());
    let body: Vec<u8> = (0..file_bytes).map(|index| (index % 256) as u8).collect();
    let saved = client
        .append(
            ACCOUNT,
            ID,
            "synthetic.bin",
            "application/octet-stream",
            &body,
        )
        .unwrap();
    assert_eq!(client.inspect(ACCOUNT, ID).unwrap(), vec![saved.clone()]);
    assert_eq!(client.read(ACCOUNT, ID, &saved).unwrap(), body);
    assert_eq!(
        client.read("bob@example.test", ID, &saved),
        Err(Error::NotFound)
    );
    let mut stale = saved.clone();
    stale.uid += 1;
    assert_eq!(client.read(ACCOUNT, ID, &stale), Err(Error::Stale));
    let binned = client.move_to_bin(ACCOUNT, ID, &saved).unwrap();
    assert_eq!(client.restore(ACCOUNT, ID, &binned).unwrap(), saved);
    let binned = client.move_to_bin(ACCOUNT, ID, &saved).unwrap();
    client.expunge(ACCOUNT, ID, &binned).unwrap();
    assert!(client.inspect(ACCOUNT, ID).unwrap().is_empty());
    server.join().unwrap();
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}
