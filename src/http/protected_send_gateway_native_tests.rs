// Actual authenticated helper processes and production gateway submission path.
// Loopback SMTP and a controlled Sent save process; not live Dovecot/provider QA.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TEST_NAME: &str = "http::http_gateway::http_gateway_mail::tests::protected_send_native::native_crypto_gateway_protected_send_roundtrip";
struct Scratch(PathBuf);
impl Scratch {
    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let p = self.0.join(name);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        p
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Services(Vec<Child>);
impl Drop for Services {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn helper_child(services: &mut Services, kind: &str, config: &Path, key: &Path, socket: &Path) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--ignored", "--nocapture"])
        .env("OSMAP_GATEWAY_NATIVE_SERVICE", kind)
        .env("OSMAP_GATEWAY_NATIVE_CONFIG", config)
        .env("OSMAP_GATEWAY_NATIVE_KEY", key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    services.0.push(child);
    let child = services.0.last_mut().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "fixture service exited before socket readiness"
        );
        assert!(
            Instant::now() < deadline,
            "fixture service readiness timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn native_service_child() -> bool {
    let Ok(kind) = std::env::var("OSMAP_GATEWAY_NATIVE_SERVICE") else {
        return false;
    };
    let config = PathBuf::from(std::env::var_os("OSMAP_GATEWAY_NATIVE_CONFIG").unwrap());
    let key = PathBuf::from(std::env::var_os("OSMAP_GATEWAY_NATIVE_KEY").unwrap());
    match kind.as_str() {
        "crypto" => crate::openpgp_crypto_runtime::Service::from_operator_files(&config, &key)
            .unwrap()
            .serve()
            .unwrap(),
        "inventory" => {
            crate::openpgp_inventory_runtime::Service::from_operator_files(&config, &key)
                .unwrap()
                .serve()
                .unwrap()
        }
        _ => panic!("unknown isolated fixture service"),
    }
    true
}
fn smtp_sink(
    listener: TcpListener,
    wire: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => panic!("loopback sink accept"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream.write_all(b"220 fixture ESMTP\r\n").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut data = false;
            let mut message = Vec::new();
            loop {
                let mut line = Vec::new();
                if reader.read_until(b'\n', &mut line).unwrap() == 0 {
                    break;
                }
                if data {
                    if line == b".\r\n" {
                        wire.lock().unwrap().push(std::mem::take(&mut message));
                        data = false;
                        stream.write_all(b"250 fixture queued\r\n").unwrap();
                    } else {
                        if line.starts_with(b"..") {
                            line.remove(0);
                        }
                        message.extend(line);
                    }
                    continue;
                }
                let command = String::from_utf8(line).unwrap().to_ascii_uppercase();
                if command.starts_with("EHLO ") || command.starts_with("HELO ") {
                    stream.write_all(b"250 fixture\r\n").unwrap();
                } else if command.starts_with("MAIL FROM:<ALICE@EXAMPLE.TEST>")
                    || command.starts_with("RCPT TO:<BOB@EXAMPLE.TEST>")
                {
                    stream.write_all(b"250 accepted\r\n").unwrap();
                } else if command == "DATA\r\n" {
                    data = true;
                    stream.write_all(b"354 send data\r\n").unwrap();
                } else if command == "QUIT\r\n" {
                    stream.write_all(b"221 closing\r\n").unwrap();
                    break;
                } else {
                    stream
                        .write_all(b"550 refused fixture envelope\r\n")
                        .unwrap();
                }
            }
        }
    })
}
struct SinkGuard {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for SinkGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn native_send_request<'a>(
    intent: &'a str,
    revision: u64,
    attachments: &'a [crate::send::UploadedAttachment],
) -> BrowserSendRequest<'a> {
    BrowserSendRequest {
        send_intent: intent,
        draft_id: None,
        draft_revision: None,
        recipients: "bob@example.test",
        cc_recipients: "",
        bcc_recipients: "",
        subject: "Synthetic gateway protected",
        body: "Synthetic café body\nSecond line",
        body_format: crate::compose_format::BodyFormat::Plain,
        attachments,
        reply_thread: None,
        protection: crate::send::ProtectionIntent {
            sign: true,
            encrypt: true,
            encrypt_to_self: true,
            binding_revision: Some(revision),
        },
    }
}

#[test]
#[ignore = "actual OpenBSD authenticated gateway helpers and disposable SMTP/Sent fixture"]
fn native_crypto_gateway_protected_send_roundtrip() {
    assert_eq!(std::env::consts::OS, "openbsd");
    if native_service_child() {
        return;
    }
    crate::openbsd::disable_core_dumps().unwrap();
    let path = |name: &str| {
        let p = PathBuf::from(std::env::var_os(name).expect("native gateway fixture path"));
        assert!(p.is_absolute());
        assert_eq!(fs::canonicalize(&p).unwrap(), p);
        p
    };
    let worker = path("OSMAP_CRYPTO_NATIVE_WORKER");
    let inventory_worker = path("OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER");
    let engine = path("OSMAP_CRYPTO_NATIVE_ENGINE");
    let alice = path("OSMAP_CRYPTO_NATIVE_ALICE_HOME");
    let bob = path("OSMAP_CRYPTO_NATIVE_BOB_HOME");
    let afp = std::env::var("OSMAP_CRYPTO_NATIVE_ALICE_FP").unwrap();
    let bfp = std::env::var("OSMAP_CRYPTO_NATIVE_BOB_FP").unwrap();
    let fixture = worker.parent().unwrap();
    assert!(fixture.starts_with("/tmp"));
    assert!(fixture
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    assert!(alice.starts_with(fixture) && bob.starts_with(fixture));
    assert_ne!(alice, bob);
    let root = fixture.join("gateway");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let scratch = Scratch(root);
    let mut key = [0; 32];
    getrandom::getrandom(&mut key).unwrap();
    let key_file = scratch.write("grant.key", &key, 0o600);
    let crypto_socket = scratch.0.join("c.sock");
    let inventory_socket = scratch.0.join("i.sock");
    let uid = crate::openbsd::effective_uid();
    let crypto_config=scratch.write("crypto.json",&serde_json::to_vec(&serde_json::json!({"version":1,"worker":worker,"engine":engine,"socket":crypto_socket,"trusted_web_uid":uid,"accounts":[{"account":"alice@example.test","home":alice,"signer_fingerprint":afp,"decrypt_fingerprints":[afp],"recipient_fingerprints":[afp,bfp]},{"account":"bob@example.test","home":bob,"signer_fingerprint":bfp,"decrypt_fingerprints":[bfp],"recipient_fingerprints":[afp,bfp]}]})).unwrap(),0o600);
    let inventory_config=scratch.write("inventory.json",&serde_json::to_vec(&serde_json::json!({"version":1,"worker":inventory_worker,"engine":"/usr/local/bin/gpg","socket":inventory_socket,"trusted_web_uid":uid,"accounts":[{"account":"alice@example.test","home":alice}]})).unwrap(),0o600);
    let mut services = Services(Vec::new());
    helper_child(
        &mut services,
        "crypto",
        &crypto_config,
        &key_file,
        &crypto_socket,
    );
    helper_child(
        &mut services,
        "inventory",
        &inventory_config,
        &key_file,
        &inventory_socket,
    );
    let crypto =
        crate::openpgp_crypto_runtime::Client::from_operator_files(&crypto_socket, &key_file, uid)
            .unwrap();
    let inventory = crate::openpgp_inventory_runtime::Client::from_operator_files(
        &inventory_socket,
        &key_file,
        uid,
    )
    .unwrap();
    let public = inventory.read("alice@example.test").unwrap();
    assert!(public
        .keys()
        .unwrap()
        .iter()
        .any(|k| k.primary.fingerprint == afp));
    assert!(public
        .keys()
        .unwrap()
        .iter()
        .any(|k| k.primary.fingerprint == bfp));
    let mut gateway = RuntimeBrowserGateway::for_test(&scratch.0);
    gateway.crypto_client = Some(crypto.clone());
    gateway.public_inventory_client = Some(inventory);
    let now = SystemTimeProvider.unix_timestamp();
    let store =
        crate::openpgp_bindings::BindingStore::new(gateway.settings_dir.join("openpgp-bindings"));
    let record = store
        .replace_operator(
            "alice@example.test",
            0,
            crate::openpgp_bindings::Update {
                account_binding: Some(crate::openpgp_bindings::AccountBinding {
                    primary_fingerprint: afp.clone(),
                    signing_fingerprint: Some(afp.clone()),
                    decrypt_primary_fingerprints: vec![afp.clone()],
                }),
                recipient_bindings: vec![crate::openpgp_bindings::RecipientBinding {
                    address: "bob@example.test".into(),
                    primary_fingerprint: bfp.clone(),
                    encryption: crate::openpgp_bindings::Requirement::Required,
                }],
                policy: crate::openpgp_bindings::ProtectionPolicy::default(),
            },
            &public,
            now,
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let smtp = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _sink = SinkGuard {
        stop: stop.clone(),
        thread: Some(smtp_sink(listener, smtp.clone(), stop)),
    };
    // This executable substitutes only the process transport destination. The
    // production sendmail backend still validates and submits PreparedSubmission.
    let sendmail=scratch.write("sendmail",format!("#!/usr/local/bin/python3\nimport smtplib,sys\nassert sys.argv[1:3]==['-oi','-f'] and sys.argv[4]=='--'\nwith smtplib.SMTP('127.0.0.1',{port},timeout=10) as smtp:\n    smtp.sendmail(sys.argv[3],sys.argv[5:],sys.stdin.buffer.read())\n").as_bytes(),0o700);
    let sent_path = scratch.0.join("sent.eml");
    let sent_count = scratch.0.join("sent.count");
    let save=scratch.write("doveadm-save",format!("#!/usr/local/bin/python3\nimport sys\nassert sys.argv[1:]==['-o','stats_writer_socket_path=','save','-u','alice@example.test','-m','Sent']\nwith open({:?},'wb') as out: out.write(sys.stdin.buffer.read())\nwith open({:?},'ab') as out: out.write(b'1')\n",sent_path.to_string_lossy(),sent_count.to_string_lossy()).as_bytes(),0o700);
    let submission = SubmissionService::new(crate::send::SendmailSubmissionBackend::new(
        SystemCommandExecutor,
        sendmail,
    ));
    let append = crate::mailbox::DoveadmMessageAppendBackend::new(SystemCommandExecutor, save);
    let mut session = validated_session();
    session.record.canonical_username = "alice@example.test".into();
    session.record.issued_at = now;
    session.record.expires_at = now + 3600;
    session.record.last_seen_at = now;
    let context = test_context();
    let intent = crate::send_journal::mint_intent(now).unwrap();
    let attachments = [crate::send::UploadedAttachment::new(
        ComposePolicy::default(),
        "synthetic.bin",
        "application/octet-stream",
        vec![0, 1, 255],
    )
    .unwrap()];

    let outcome = gateway.send_message_with_backends(
        &context,
        &session,
        native_send_request(&intent, record.revision, &attachments),
        &submission,
        &append,
    );
    assert!(
        matches!(
            outcome.decision,
            BrowserSendDecision::Submitted {
                sent_copy_stored: true,
                receipt_persisted: true
            }
        ),
        "production gateway protected submission must confirm both stores"
    );
    assert!(smtp.lock().unwrap().len() == 1);
    let wire = smtp.lock().unwrap()[0].clone();
    assert!(
        fs::read(&sent_path).unwrap() == wire,
        "SMTP and controlled Sent bytes must match exactly"
    );
    assert!(fs::read(&sent_count).unwrap() == b"1");
    assert!(!wire
        .windows("Synthetic café body".len())
        .any(|w| w == "Synthetic café body".as_bytes()));
    let crate::pgp_mime::PgpMimeMessage::Encrypted { ciphertext, .. } =
        crate::pgp_mime::classify(&wire, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("gateway must emit RFC3156 encrypted MIME");
    };
    let bob_plain = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![bfp.clone()],
                ciphertext: ciphertext.clone(),
            },
        )
        .unwrap()
        .unwrap();
    let self_plain = crypto
        .execute(
            "alice@example.test",
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![afp.clone()],
                ciphertext,
            },
        )
        .unwrap()
        .unwrap();
    assert!(bob_plain.content == self_plain.content);
    let crate::pgp_mime::PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = crate::pgp_mime::classify(
        &bob_plain.content,
        crate::pgp_mime::PgpMimePolicy::default(),
    )
    .unwrap()
    else {
        panic!("signed content inside encryption required");
    };
    let verified = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Verify {
                data: canonical_entity.clone(),
                signature,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        verified.signature,
        crate::openpgp_crypto::SignatureState::Valid
    );
    assert_eq!(verified.primary_fingerprint.as_deref(), Some(afp.as_str()));
    let raw = std::str::from_utf8(&canonical_entity).unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "INBOX".into(),
        uid: 1,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: canonical_entity.len() as u64,
        header_block: headers.into(),
        body_text: body.into(),
    };
    let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&message)
        .unwrap();
    assert!(
        analysis.selected_plain_text_body.as_deref() == Some("Synthetic café body\r\nSecond line"),
        "decrypted authored body must survive gateway submission"
    );
    let download = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(&message, "1.2")
    .unwrap();
    assert!(
        download.body == [0, 1, 255],
        "decrypted authored binary attachment must survive gateway submission"
    );
    let replay = gateway.send_message_with_backends(
        &context,
        &session,
        native_send_request(&intent, record.revision, &attachments),
        &submission,
        &append,
    );
    assert!(matches!(
        replay.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: true,
            receipt_persisted: true
        }
    ));
    assert!(smtp.lock().unwrap().len() == 1);
    assert!(
        fs::read(&sent_count).unwrap() == b"1",
        "journal replay must not append again"
    );
    let stale_intent = crate::send_journal::mint_intent(now).unwrap();
    let stale = gateway.send_message_with_backends(
        &context,
        &session,
        native_send_request(&stale_intent, record.revision + 1, &attachments),
        &submission,
        &append,
    );
    assert!(
        matches!(stale.decision,BrowserSendDecision::Denied {ref public_reason,..} if public_reason=="openpgp_binding_changed")
    );
    assert!(smtp.lock().unwrap().len() == 1);
    assert!(fs::read(&sent_count).unwrap() == b"1");
    assert!(
        crate::send_journal::SendJournal::new(gateway.settings_dir.join("send-journal"))
            .receipt("alice@example.test", &stale_intent, now)
            .unwrap()
            .is_none()
    );
    // Missing actual helper cannot silently fall back to a plaintext send.
    services.0[0].kill().unwrap();
    services.0[0].wait().unwrap();
    let failed_intent = crate::send_journal::mint_intent(now).unwrap();
    let unavailable = gateway.send_message_with_backends(
        &context,
        &session,
        native_send_request(&failed_intent, record.revision, &attachments),
        &submission,
        &append,
    );
    assert!(
        matches!(unavailable.decision,BrowserSendDecision::Denied {ref public_reason,..} if public_reason=="openpgp_submission_unavailable")
    );
    assert!(smtp.lock().unwrap().len() == 1);
    assert!(fs::read(&sent_count).unwrap() == b"1");
    assert!(
        crate::send_journal::SendJournal::new(gateway.settings_dir.join("send-journal"))
            .receipt("alice@example.test", &failed_intent, now)
            .unwrap()
            .is_none()
    );
    for events in [
        &outcome.audit_events,
        &replay.audit_events,
        &stale.audit_events,
        &unavailable.audit_events,
    ] {
        let rendered = format!("{events:?}");
        assert!(!rendered.contains("Synthetic café body"));
        assert!(!rendered.contains("0, 1, 255"));
    }
}
