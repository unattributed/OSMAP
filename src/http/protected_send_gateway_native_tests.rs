// Actual authenticated helper processes and production gateway submission path.
// Rust loopback SMTP and scoped real Sent save; not public/provider mail QA.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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
    if kind == "smtp-actor" {
        native_smtp_actor();
        return true;
    }
    if kind == "sent-actor" {
        native_sent_actor();
        return true;
    }
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
        "public-admin" => {
            crate::openpgp_public_admin_runtime::Service::from_operator_files(&config, &key)
                .unwrap()
                .serve()
                .unwrap()
        }
        _ => panic!("unknown isolated fixture service"),
    }
    true
}

fn actor_arguments() -> Vec<String> {
    std::env::var("OSMAP_GATEWAY_NATIVE_ARGV")
        .expect("fixed launcher argv")
        .split('\n')
        .map(str::to_owned)
        .collect()
}
fn actor_input() -> Vec<u8> {
    crate::openbsd::bounded_operator_stdin(16 * 1024, Instant::now() + Duration::from_secs(5))
        .expect("bounded synthetic transport input")
}
fn smtp_reply(reader: &mut BufReader<TcpStream>, expected: &[u8], deadline: Instant) {
    reader
        .get_ref()
        .set_read_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .expect("loopback SMTP deadline"),
        ))
        .unwrap();
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().unwrap();
        assert!(!available.is_empty(), "loopback SMTP reply ended");
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        assert!(line.len() + count <= 1024, "loopback SMTP reply limit");
        let ended = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if ended {
            break;
        }
    }
    assert!(line.starts_with(expected), "fixed loopback SMTP reply");
}
fn smtp_write(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) {
    stream
        .set_write_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .expect("loopback SMTP deadline"),
        ))
        .unwrap();
    stream.write_all(bytes).unwrap();
}
fn native_smtp_actor() {
    let arguments = actor_arguments();
    assert!(matches!(arguments.len(), 5 | 6));
    assert!(arguments[..4].iter().map(String::as_str).eq([
        "-oi",
        "-f",
        "alice@example.test",
        "--"
    ]));
    let recipients = &arguments[4..];
    assert!(recipients.iter().all(|recipient| matches!(
        recipient.as_str(),
        "alice@example.test" | "bob@example.test" | "unregistered@example.test"
    )));
    assert!(recipients.len() == 1 || recipients[0] != recipients[1]);
    let content = actor_input();
    assert!(!content.is_empty());
    let port: u16 = std::env::var("OSMAP_GATEWAY_NATIVE_PORT")
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(port, 0);
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(3),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    smtp_reply(&mut reader, b"220 ", deadline);
    smtp_write(&mut stream, b"EHLO fixture\r\n", deadline);
    smtp_reply(&mut reader, b"250 ", deadline);
    smtp_write(&mut stream, b"MAIL FROM:<alice@example.test>\r\n", deadline);
    smtp_reply(&mut reader, b"250 ", deadline);
    for recipient in recipients {
        smtp_write(
            &mut stream,
            format!("RCPT TO:<{recipient}>\r\n").as_bytes(),
            deadline,
        );
        smtp_reply(&mut reader, b"250 ", deadline);
    }
    smtp_write(&mut stream, b"DATA\r\n", deadline);
    smtp_reply(&mut reader, b"354 ", deadline);
    for line in content.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b".") {
            smtp_write(&mut stream, b".", deadline);
        }
        smtp_write(&mut stream, line, deadline);
    }
    if !content.ends_with(b"\r\n") {
        smtp_write(&mut stream, b"\r\n", deadline);
    }
    smtp_write(&mut stream, b".\r\n", deadline);
    smtp_reply(&mut reader, b"250 ", deadline);
    smtp_write(&mut stream, b"QUIT\r\n", deadline);
    smtp_reply(&mut reader, b"221 ", deadline);
}
fn native_sent_actor() {
    use crate::auth::CommandExecutor;
    assert!(actor_arguments().iter().map(String::as_str).eq([
        "-o",
        "stats_writer_socket_path=",
        "save",
        "-u",
        "alice@example.test",
        "-m",
        "Sent"
    ]));
    let path = |name| PathBuf::from(std::env::var_os(name).expect("owned Sent actor path"));
    let config = path("OSMAP_GATEWAY_NATIVE_CONFIG");
    let userdb = path("OSMAP_GATEWAY_NATIVE_USERDB");
    assert_eq!(fs::canonicalize(&config).unwrap(), config);
    let root = config.parent().unwrap();
    assert_eq!(root.parent().unwrap(), std::env::temp_dir());
    assert!(root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-protected-reader-native-"));
    assert_eq!(config.file_name().unwrap(), "dovecot.conf");
    assert_eq!(userdb, root.join("userdb"));
    let metadata = fs::symlink_metadata(&config).unwrap();
    assert!(
        metadata.is_file()
            && metadata.uid() == crate::openbsd::effective_uid()
            && metadata.mode() & 0o077 == 0
    );
    let content = actor_input();
    assert!(!content.is_empty());
    let capture = path("OSMAP_GATEWAY_NATIVE_SENT_CAPTURE");
    let counter = path("OSMAP_GATEWAY_NATIVE_SENT_COUNTER");
    let refuse = path("OSMAP_GATEWAY_NATIVE_SENT_REFUSE");
    assert_eq!(capture.parent(), counter.parent());
    assert_eq!(capture.parent(), refuse.parent());
    assert_eq!(capture.file_name().unwrap(), "sent.eml");
    assert_eq!(counter.file_name().unwrap(), "sent.count");
    assert_eq!(refuse.file_name().unwrap(), "sent-refuse");
    let capture_root = capture.parent().unwrap();
    assert_eq!(fs::canonicalize(capture_root).unwrap(), capture_root);
    assert_eq!(capture_root.file_name().unwrap(), "gateway");
    assert!(capture_root
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("osmap-crypto-fixture-"));
    let metadata = fs::symlink_metadata(capture_root).unwrap();
    assert!(
        metadata.is_dir()
            && metadata.uid() == crate::openbsd::effective_uid()
            && metadata.mode() & 0o777 == 0o700
    );
    match fs::symlink_metadata(&refuse) {
        Ok(metadata) => {
            assert!(
                metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.uid() == crate::openbsd::effective_uid()
                    && metadata.mode() & 0o777 == 0o600
            );
            eprintln!("fixture_sent_append_refused");
            std::process::exit(64);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => panic!("owned Sent refusal marker unavailable"),
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(capture)
        .unwrap();
    file.write_all(&content).unwrap();
    file.sync_all().unwrap();
    let mut count = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(counter)
        .unwrap();
    count.write_all(b"1").unwrap();
    count.sync_all().unwrap();
    let result = SystemCommandExecutor
        .run_with_stdin_bytes_timeout_and_output_limit(
            "/usr/local/bin/doveadm",
            &[
                "-c".into(),
                config.to_string_lossy().into_owned(),
                "-o".into(),
                "stats_writer_socket_path=".into(),
                "-o".into(),
                format!("auth_socket_path={}", userdb.display()),
                "save".into(),
                "-u".into(),
                "alice@example.test".into(),
                "-m".into(),
                "Sent".into(),
            ],
            &content,
            Duration::from_secs(3),
            4096,
        )
        .expect("bounded private native Sent save");
    assert_eq!(result.status_code, 0, "private native Sent save refused");
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn actor_launcher(mode: &str, settings: &[(&str, String)]) -> Vec<u8> {
    assert!(matches!(mode, "smtp-actor" | "sent-actor"));
    let mut launcher = format!("#!/bin/sh\nset -eu\nexport OSMAP_GATEWAY_NATIVE_SERVICE={}\nexport OSMAP_GATEWAY_NATIVE_ARGV=\"$(printf '%s\\n' \"$@\")\"\n", shell_quote(mode));
    for (name, value) in settings {
        assert!(
            name.starts_with("OSMAP_GATEWAY_NATIVE_")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        );
        launcher.push_str(&format!("export {name}={}\n", shell_quote(value)));
    }
    launcher.push_str(&format!(
        "exec {} --exact {} --ignored --nocapture\n",
        shell_quote(std::env::current_exe().unwrap().to_str().unwrap()),
        shell_quote(TEST_NAME)
    ));
    launcher.into_bytes()
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
                    || command.starts_with("RCPT TO:<ALICE@EXAMPLE.TEST>")
                    || command.starts_with("RCPT TO:<UNREGISTERED@EXAMPLE.TEST>")
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

fn assert_decrypted_authored_entity(entity: &[u8]) {
    let raw = std::str::from_utf8(entity).unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "INBOX".into(),
        uid: 1,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: entity.len() as u64,
        header_block: headers.into(),
        body_text: body.into(),
    };
    let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&message)
        .unwrap();
    assert_eq!(
        analysis.selected_plain_text_body.as_deref(),
        Some("Synthetic café body\r\nSecond line"),
        "decoded authored body"
    );
    let download = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(
        &message,
        &analysis
            .attachments
            .iter()
            .find(|attachment| attachment.filename.as_deref() == Some("synthetic.bin"))
            .unwrap()
            .part_path,
    )
    .unwrap();
    assert_eq!(download.body, [0, 1, 255], "decoded authored attachment");
}

fn attached_public_certificate(entity: &[u8]) -> Vec<u8> {
    let raw = std::str::from_utf8(entity).unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "Sent".into(),
        uid: 1,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: entity.len() as u64,
        header_block: headers.into(),
        body_text: body.into(),
    };
    let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&message)
        .unwrap();
    let certificates = analysis
        .attachments
        .iter()
        .filter(|attachment| attachment.filename.as_deref() == Some("openpgp-public-key.asc"))
        .collect::<Vec<_>>();
    assert_eq!(certificates.len(), 1);
    let downloaded = crate::attachment::AttachmentDownloadService::new(
        crate::attachment::AttachmentDownloadPolicy::default(),
    )
    .download_from_message(&message, &certificates[0].part_path)
    .unwrap();
    assert_eq!(downloaded.content_type, "application/pgp-keys");
    downloaded.body
}

fn assert_decrypted_route_body(entity: &[u8]) {
    let raw = std::str::from_utf8(entity).unwrap();
    let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
    let message = crate::mailbox::MessageView {
        metadata: None,
        mailbox_name: "INBOX".into(),
        uid: 1,
        flags: Vec::new(),
        date_received: String::new(),
        size_virtual: entity.len() as u64,
        header_block: headers.into(),
        body_text: body.into(),
    };
    let analysis = crate::mime::MimeAnalyzer::new(crate::mime::MimeAnalysisPolicy::default())
        .analyze_message(&message)
        .unwrap();
    assert_eq!(
        analysis.selected_plain_text_body.as_deref(),
        Some("RouteEncryptedBody")
    );
}

#[test]
fn decrypted_route_body_requires_actual_transfer_decoding() {
    let encoded = b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\nUm91dGVFbmNyeXB0ZWRCb2R5";
    assert!(!encoded
        .windows(b"RouteEncryptedBody".len())
        .any(|window| window == b"RouteEncryptedBody"));
    assert_decrypted_route_body(encoded);
}

fn native_send_request<'a>(
    intent: &'a str,
    revision: u64,
    attachments: &'a [crate::send::UploadedAttachment],
) -> BrowserSendRequest<'a> {
    BrowserSendRequest {
        sender_id: None,
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
    let admin_socket = scratch.0.join("a.sock");
    let uid = crate::openbsd::effective_uid();
    let crypto_config=scratch.write("crypto.json",&serde_json::to_vec(&serde_json::json!({"version":1,"worker":worker,"engine":engine,"socket":crypto_socket,"trusted_web_uid":uid,"accounts":[{"account":"alice@example.test","home":alice,"signer_fingerprint":afp,"decrypt_fingerprints":[afp],"recipient_fingerprints":[afp,bfp]},{"account":"bob@example.test","home":bob,"signer_fingerprint":bfp,"decrypt_fingerprints":[bfp],"recipient_fingerprints":[afp,bfp]}]})).unwrap(),0o600);
    let inventory_config=scratch.write("inventory.json",&serde_json::to_vec(&serde_json::json!({"version":1,"worker":inventory_worker,"engine":"/usr/local/bin/gpg","socket":inventory_socket,"trusted_web_uid":uid,"accounts":[{"account":"alice@example.test","home":alice}]})).unwrap(),0o600);
    let admin_state = scratch.0.join("public-admin-state");
    fs::create_dir(&admin_state).unwrap();
    fs::set_permissions(&admin_state, fs::Permissions::from_mode(0o700)).unwrap();
    let admin_config=scratch.write("public-admin.json",&serde_json::to_vec(&serde_json::json!({"version":1,"worker":inventory_worker,"engine":engine,"state_directory":admin_state,"socket":admin_socket,"trusted_web_uid":uid,"accounts":[{"account":"alice@example.test","home":alice}]})).unwrap(),0o600);
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
    helper_child(
        &mut services,
        "public-admin",
        &admin_config,
        &key_file,
        &admin_socket,
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
    let public_admin = crate::openpgp_public_admin_runtime::Client::from_operator_files(
        &admin_socket,
        &key_file,
        uid,
    )
    .unwrap();
    let snapshot = public_admin.snapshot("alice@example.test").unwrap();
    let exported = public_admin
        .export_public("alice@example.test", &snapshot.revision, &afp)
        .unwrap();
    assert_eq!(exported.primary_fingerprint, afp);
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
    gateway.public_inventory_client = Some(inventory.clone());
    gateway.public_admin_client = Some(public_admin.clone());
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
    let sendmail = scratch.write(
        "sendmail",
        &actor_launcher(
            "smtp-actor",
            &[("OSMAP_GATEWAY_NATIVE_PORT", port.to_string())],
        ),
        0o700,
    );
    let sent_path = scratch.0.join("sent.eml");
    let sent_count = scratch.0.join("sent.count");
    let sent_refuse = scratch.0.join("sent-refuse");
    let mut sent_mailbox = crate::mailbox_helper::NativeProtectedSentMailbox::new();
    let save = scratch.write(
        "doveadm-save",
        &actor_launcher(
            "sent-actor",
            &[
                (
                    "OSMAP_GATEWAY_NATIVE_CONFIG",
                    sent_mailbox.config.to_str().unwrap().into(),
                ),
                (
                    "OSMAP_GATEWAY_NATIVE_USERDB",
                    sent_mailbox.userdb.to_str().unwrap().into(),
                ),
                (
                    "OSMAP_GATEWAY_NATIVE_SENT_CAPTURE",
                    sent_path.to_str().unwrap().into(),
                ),
                (
                    "OSMAP_GATEWAY_NATIVE_SENT_COUNTER",
                    sent_count.to_str().unwrap().into(),
                ),
                (
                    "OSMAP_GATEWAY_NATIVE_SENT_REFUSE",
                    sent_refuse.to_str().unwrap().into(),
                ),
            ],
        ),
        0o700,
    );
    let submission = SubmissionService::new(crate::send::SendmailSubmissionBackend::new(
        SystemCommandExecutor,
        sendmail.clone(),
    ));
    let append =
        crate::mailbox::DoveadmMessageAppendBackend::new(SystemCommandExecutor, save.clone());
    let mut session = validated_session();
    session.record.canonical_username = "alice@example.test".into();
    session.record.session_id = "a".repeat(64);
    session.record.issued_at = now;
    session.record.expires_at = now + 3600;
    session.record.last_seen_at = now;
    assert!(RuntimeBrowserGateway::private_key_session(&session).valid(now));
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
    assert_eq!(
        attached_public_certificate(&canonical_entity),
        exported.certificate
    );
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
    .download_from_message(
        &message,
        &analysis
            .attachments
            .iter()
            .find(|attachment| attachment.filename.as_deref() == Some("synthetic.bin"))
            .unwrap()
            .part_path,
    )
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
    // An account key is sufficient for an exact self-recipient, without a
    // duplicate contact binding. The transmitted bytes must actually decrypt
    // and verify; public eligibility alone is not a delivery proof.
    let self_intent = crate::send_journal::mint_intent(now).unwrap();
    let mut self_request = native_send_request(&self_intent, record.revision, &attachments);
    self_request.recipients = "alice@example.test";
    let self_outcome =
        gateway.send_message_with_backends(&context, &session, self_request, &submission, &append);
    assert!(matches!(
        self_outcome.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: true,
            receipt_persisted: true
        }
    ));
    assert_eq!(smtp.lock().unwrap().len(), 2);
    let self_wire = smtp.lock().unwrap()[1].clone();
    assert_eq!(fs::read(&sent_path).unwrap(), self_wire);
    assert_eq!(fs::read(&sent_count).unwrap(), b"11");
    let crate::pgp_mime::PgpMimeMessage::Encrypted { ciphertext, .. } =
        crate::pgp_mime::classify(&self_wire, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("self delivery must be encrypted MIME");
    };
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
    let crate::pgp_mime::PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = crate::pgp_mime::classify(
        &self_plain.content,
        crate::pgp_mime::PgpMimePolicy::default(),
    )
    .unwrap()
    else {
        panic!("self delivery must contain signed MIME");
    };
    let verified_self = crypto
        .execute(
            "alice@example.test",
            &crate::openpgp_crypto::Operation::Verify {
                data: canonical_entity,
                signature,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        verified_self.signature,
        crate::openpgp_crypto::SignatureState::Valid
    );
    assert_eq!(
        verified_self.primary_fingerprint.as_deref(),
        Some(afp.as_str())
    );

    // A disposable Bob-signed/Alice-encrypted return is stored only in the
    // owned Alice Inbox by the Dovecot reader fixture. No provider or SMTP
    // delivery is implied by this native receive/read control.
    let return_entity = b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nReturnExactBody\r\n";
    let signed_return = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Sign {
                signer_fingerprint: bfp.clone(),
                data: return_entity.to_vec(),
            },
        )
        .unwrap()
        .unwrap();
    let digest = match signed_return.hash_algorithm {
        Some(8) => crate::pgp_mime::SignatureDigest::Sha256,
        Some(10) => crate::pgp_mime::SignatureDigest::Sha512,
        _ => panic!("unsupported disposable return signature digest"),
    };
    let signed_return = crate::pgp_mime::build_signed(
        return_entity,
        &signed_return.content,
        digest,
        "native-return-signed",
        crate::pgp_mime::PgpMimePolicy::default(),
    )
    .unwrap();
    let encrypted_return = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Encrypt {
                recipient_fingerprints: vec![afp.clone()],
                data: signed_return,
            },
        )
        .unwrap()
        .unwrap();
    let encrypted_return = crate::pgp_mime::build_encrypted(
        &encrypted_return.content,
        "native-return-encrypted",
        crate::pgp_mime::PgpMimePolicy::default(),
    )
    .unwrap();
    let mut return_wire = b"From: Bob <bob@example.test>\r\nTo: alice@example.test\r\nSubject: Synthetic encrypted return\r\nMessage-ID: <native-return@fixture.test>\r\nMIME-Version: 1.0\r\n".to_vec();
    return_wire.extend_from_slice(&encrypted_return);
    assert!(!return_wire
        .windows(b"ReturnExactBody".len())
        .any(|window| window == b"ReturnExactBody"));

    // Reuse the actual owned Dovecot reader fixture for encrypted-to-self
    // Sent and signed inbound return, including a real Locked refusal.
    sent_mailbox.prove(
        &self_wire,
        &return_wire,
        &crypto,
        &inventory,
        (&afp, &bfp),
        &alice,
    );
    assert_eq!(
        smtp.lock().unwrap().len(),
        2,
        "reader never repeats SMTP submission"
    );
    assert_eq!(fs::read(&sent_count).unwrap(), b"11");

    let required_intent = crate::send_journal::mint_intent(now).unwrap();
    let mut required_request = native_send_request(&required_intent, record.revision, &attachments);
    required_request.protection = crate::send::ProtectionIntent {
        binding_revision: Some(record.revision),
        ..Default::default()
    };
    let required_refusal = gateway.send_message_with_backends(
        &context,
        &session,
        required_request,
        &submission,
        &append,
    );
    assert!(matches!(required_refusal.decision,
        BrowserSendDecision::Denied { ref public_reason, .. }
        if public_reason == "openpgp_recipient_encryption_required"));
    assert_eq!(smtp.lock().unwrap().len(), 2);
    assert_eq!(fs::read(&sent_count).unwrap(), b"11");

    // Reuse the actual persisted-session HTTP route for signing to an address
    // with no recipient key or binding. Public export cannot unlock a signer.
    let mut route_gateway = RuntimeBrowserGateway::for_test(&scratch.0);
    route_gateway.crypto_client = Some(crypto.clone());
    route_gateway.public_inventory_client = Some(inventory.clone());
    route_gateway.public_admin_client = Some(public_admin.clone());
    route_gateway.sendmail_path = sendmail.clone();
    route_gateway.doveadm_path = save.clone();
    let issued = crate::session::SessionService::new(
        crate::session::FileSessionStore::new(scratch.0.join("sessions")),
        SystemTimeProvider,
        crate::session::SystemRandomSource,
        3600,
        1800,
    )
    .issue(
        &context,
        "alice@example.test",
        crate::auth::RequiredSecondFactor::Totp,
    )
    .unwrap();
    let app = crate::http::BrowserApp::new(crate::http::HttpPolicy::default(), route_gateway);
    let route = |method: &str, body: &str| {
        let raw = format!(
            "{method} {} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Firefox/Test\r\nOrigin: http://localhost\r\nCookie: osmap_session={}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            if method == "GET" { "/compose" } else { "/send" },
            issued.token.as_str(), body.len(),
        );
        let request = crate::http::parse_http_request(&raw, app.policy()).unwrap();
        app.handle_request(&request, "127.0.0.1")
    };
    let form_intent = |html: &str| {
        html.split("name=\"send_intent\" value=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .to_owned()
    };
    assert!(!record
        .recipient_bindings
        .iter()
        .any(|binding| binding.address == "unregistered@example.test"));
    assert!(!public.keys().unwrap().iter().any(|key| key
        .email_addresses
        .iter()
        .any(|email| email == "unregistered@example.test")));
    let signing_page = route("GET", "");
    assert_eq!(signing_page.response.status_code, 200);
    let signing_fields = format!(
        "csrf_token={}&send_intent={}&to=unregistered%40example.test&subject=SignOnly&body=SignedOnlyBody&pgp_sign=on&pgp_binding_revision={}",
        issued.record.csrf_token,
        form_intent(std::str::from_utf8(&signing_page.response.body).unwrap()),
        record.revision,
    );
    struct HeldSigningAgent {
        socket: PathBuf,
        held: PathBuf,
    }
    impl Drop for HeldSigningAgent {
        fn drop(&mut self) {
            fs::rename(&self.held, &self.socket).unwrap();
        }
    }
    let socket = alice.join("S.gpg-agent");
    let held = alice.join("S.gpg-agent.held-for-sign-only");
    assert!(!held.exists());
    fs::rename(&socket, &held).unwrap();
    let guard = HeldSigningAgent { socket, held };
    let locked_signing = route("POST", &signing_fields);
    assert_eq!(locked_signing.response.status_code, 503);
    assert!(locked_signing.audit_events.iter().any(|event| {
        event.action == "send_preparation_refused"
            && event
                .fields
                .iter()
                .any(|field| field.key == "reason" && field.value == "openpgp_key_locked")
    }));
    assert_eq!(smtp.lock().unwrap().len(), 2);
    assert_eq!(fs::read(&sent_count).unwrap(), b"11");
    drop(guard);
    let signed_only = route("POST", &signing_fields);
    assert_eq!(signed_only.response.status_code, 303);
    assert_eq!(smtp.lock().unwrap().len(), 3);
    let signed_wire = smtp.lock().unwrap()[2].clone();
    assert_eq!(fs::read(&sent_path).unwrap(), signed_wire);
    assert_eq!(fs::read(&sent_count).unwrap(), b"111");
    let crate::pgp_mime::PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = crate::pgp_mime::classify(&signed_wire, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("sign-only to an unregistered recipient must be signed, not encrypted");
    };
    assert_eq!(
        attached_public_certificate(&canonical_entity),
        exported.certificate
    );
    let verified = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Verify {
                data: canonical_entity,
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
    let stored_directory = sent_mailbox
        .config
        .parent()
        .unwrap()
        .join("alice/Maildir/.Sent");
    let normalized = std::str::from_utf8(&signed_wire)
        .unwrap()
        .replace("\r\n", "\n")
        .into_bytes();
    let stored_signed = ["cur", "new"]
        .into_iter()
        .flat_map(|part| {
            fs::read_dir(stored_directory.join(part))
                .unwrap()
                .map(|entry| fs::read(entry.unwrap().path()).unwrap())
                .collect::<Vec<_>>()
        })
        .find(|bytes| bytes == &normalized)
        .expect("real Dovecot Sent saved the signed-only message");
    let crate::pgp_mime::PgpMimeMessage::Signed {
        canonical_entity,
        signature,
        ..
    } = crate::pgp_mime::classify(&stored_signed, crate::pgp_mime::PgpMimePolicy::default())
        .unwrap()
    else {
        panic!("stored signed-only MIME");
    };
    assert_eq!(
        attached_public_certificate(&canonical_entity),
        exported.certificate
    );
    assert_eq!(
        crypto
            .execute(
                "bob@example.test",
                &crate::openpgp_crypto::Operation::Verify {
                    data: canonical_entity,
                    signature,
                }
            )
            .unwrap()
            .unwrap()
            .signature,
        crate::openpgp_crypto::SignatureState::Valid
    );
    let signing_replay = route("POST", &signing_fields);
    assert_eq!(signing_replay.response.status_code, 200);
    let replay_html = std::str::from_utf8(&signing_replay.response.body).unwrap();
    assert!(replay_html.contains("This intent already has a recorded action"));
    assert!(replay_html.contains(&format!(
        "href=\"/compose?receipt={}\"",
        form_intent(std::str::from_utf8(&signing_page.response.body).unwrap())
    )));
    assert!(!replay_html.contains("action=\"/send\""));
    assert_eq!(smtp.lock().unwrap().len(), 3);
    assert_eq!(fs::read(&sent_count).unwrap(), b"111");

    // Encryption-only uses the approved recipient public key, without any
    // sender private key. Remove only this disposable fixture's secret keys.
    let removed = Command::new("/usr/local/bin/gpg")
        .args(["--no-options", "--homedir"])
        .arg(&alice)
        .args(["--batch", "--yes", "--delete-secret-keys", &afp])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(removed.success(), "disposable sender secret-key removal");
    let encrypt_only_intent = crate::send_journal::mint_intent(now).unwrap();
    let mut encrypt_only_request =
        native_send_request(&encrypt_only_intent, record.revision, &attachments);
    encrypt_only_request.protection.sign = false;
    encrypt_only_request.protection.encrypt_to_self = false;
    let encrypt_only = gateway.send_message_with_backends(
        &context,
        &session,
        encrypt_only_request,
        &submission,
        &append,
    );
    assert!(matches!(
        encrypt_only.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: true,
            receipt_persisted: true
        }
    ));
    assert_eq!(smtp.lock().unwrap().len(), 4);
    let encrypt_only_wire = smtp.lock().unwrap()[3].clone();
    assert_eq!(fs::read(&sent_path).unwrap(), encrypt_only_wire);
    assert_eq!(fs::read(&sent_count).unwrap(), b"1111");
    let crate::pgp_mime::PgpMimeMessage::Encrypted { ciphertext, .. } = crate::pgp_mime::classify(
        &encrypt_only_wire,
        crate::pgp_mime::PgpMimePolicy::default(),
    )
    .unwrap() else {
        panic!("encryption-only delivery must be encrypted MIME");
    };
    let recipient_plain = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![bfp.clone()],
                ciphertext,
            },
        )
        .unwrap()
        .unwrap();
    assert_decrypted_authored_entity(&recipient_plain.content);
    assert!(!matches!(
        crate::pgp_mime::classify(
            &recipient_plain.content,
            crate::pgp_mime::PgpMimePolicy::default()
        )
        .unwrap(),
        crate::pgp_mime::PgpMimeMessage::Signed { .. }
    ));

    // Exercise saved-draft submission through the actual gateway/store too.
    let draft_save_intent = crate::send_journal::mint_intent(now).unwrap();
    let draft_save = gateway.save_draft_impl(
        &context,
        &session,
        BrowserDraftSaveRequest {
            sender_id: None,
            protection: encrypt_only_request.protection,
            send_intent: &draft_save_intent,
            draft_id: None,
            expected_revision: None,
            recipients: encrypt_only_request.recipients,
            cc_recipients: "",
            bcc_recipients: "",
            subject: encrypt_only_request.subject,
            body: encrypt_only_request.body,
            body_format: encrypt_only_request.body_format,
            attachments: &attachments,
            removed_attachment_indices: &[],
            source_attachments: None,
            reply_thread: None,
        },
    );
    let BrowserDraftSaveDecision::Saved { draft_id } = draft_save.decision else {
        panic!("native encryption-only draft must save");
    };
    let saved = gateway
        .build_draft_store()
        .load("alice@example.test", &draft_id, now)
        .unwrap()
        .unwrap();
    let draft_revision = saved.revision.unwrap();
    let draft_send_intent = crate::send_journal::intent_for_draft(
        "alice@example.test",
        &draft_id,
        draft_revision,
        saved.updated_at,
    )
    .unwrap();
    let draft_send = gateway.send_message_with_backends(
        &context,
        &session,
        BrowserSendRequest {
            sender_id: None,
            send_intent: &draft_send_intent,
            draft_id: Some(&draft_id),
            draft_revision: Some(draft_revision),
            attachments: &saved.request.attachments,
            ..encrypt_only_request
        },
        &submission,
        &append,
    );
    assert!(matches!(
        draft_send.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: true,
            receipt_persisted: true
        }
    ));
    assert_eq!(smtp.lock().unwrap().len(), 5);
    let draft_wire = smtp.lock().unwrap()[4].clone();
    assert_eq!(fs::read(&sent_path).unwrap(), draft_wire);
    assert_eq!(fs::read(&sent_count).unwrap(), b"11111");
    assert!(
        gateway
            .cleanup_submitted_draft_impl(
                "alice@example.test",
                &draft_id,
                draft_revision,
                &draft_send_intent,
                SystemTimeProvider.unix_timestamp()
            )
            .unwrap(),
        "receipt-qualified cleanup must remove only the submitted revision"
    );
    assert!(
        gateway
            .build_draft_store()
            .load("alice@example.test", &draft_id, now)
            .unwrap()
            .is_none(),
        "only successfully submitted exact draft is removed"
    );
    let crate::pgp_mime::PgpMimeMessage::Encrypted { ciphertext, .. } =
        crate::pgp_mime::classify(&draft_wire, crate::pgp_mime::PgpMimePolicy::default()).unwrap()
    else {
        panic!("saved-draft delivery must be encrypted MIME");
    };
    let draft_plain = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![bfp.clone()],
                ciphertext,
            },
        )
        .unwrap()
        .unwrap();
    assert_decrypted_authored_entity(&draft_plain.content);

    // Keep the same disposable native SMTP/append/helper processes and now
    // The same authenticated HTTP form path remains usable for ordinary and
    // encryption-only requests after disposable private keys are removed.
    let route_page = route("GET", "");
    assert_eq!(route_page.response.status_code, 200);
    let route_html = std::str::from_utf8(&route_page.response.body).unwrap();
    assert!(route_html.contains(&format!(
        "name=\"pgp_binding_revision\" value=\"{}\"",
        record.revision
    )));
    let plain_fields = format!(
        "csrf_token={}&send_intent={}&to=alice%40example.test&subject=RoutePlain&body=RoutePlainBody&pgp_binding_revision={}",
        issued.record.csrf_token, form_intent(route_html), record.revision,
    );
    let plain_response = route("POST", &plain_fields);
    assert_eq!(
        plain_response.response.status_code, 303,
        "{:?}",
        plain_response.audit_events
    );
    assert_eq!(smtp.lock().unwrap().len(), 6);
    let plain_wire = smtp.lock().unwrap()[5].clone();
    assert!(plain_response
        .audit_events
        .iter()
        .any(|event| event.action == "sent_copy_stored"));
    assert_eq!(fs::read(&sent_count).unwrap(), b"111111");
    let plain_sent = fs::read(&sent_path).unwrap();
    assert!(plain_sent.ends_with(b"RoutePlainBody"));
    // The owned Rust SMTP actor passes the prepared bytes unchanged. For a
    // byte message with no terminal CRLF, it adds exactly that CRLF
    // before dot termination. Sent stores the original prepared message.
    let mut smtp_normalized = plain_sent.clone();
    smtp_normalized.extend_from_slice(b"\r\n");
    assert_eq!(plain_wire, smtp_normalized);
    assert!(plain_wire
        .windows(b"RoutePlainBody".len())
        .any(|w| w == b"RoutePlainBody"));
    assert!(!plain_wire
        .windows(b"application/pgp-encrypted".len())
        .any(|w| w == b"application/pgp-encrypted"));

    let route_page = route("GET", "");
    assert_eq!(route_page.response.status_code, 200);
    let route_html = std::str::from_utf8(&route_page.response.body).unwrap();
    let blocked_fields = format!(
        "csrf_token={}&send_intent={}&to=bob%40example.test&subject=RouteBlocked&body=RouteBlockedBody&pgp_binding_revision={}",
        issued.record.csrf_token, form_intent(route_html), record.revision,
    );
    let blocked_response = route("POST", &blocked_fields);
    assert_eq!(blocked_response.response.status_code, 503);
    assert!(blocked_response
        .audit_events
        .iter()
        .any(|event| event.action == "send_preparation_refused"
            && event.fields.iter().any(|field| field.key == "reason"
                && field.value == "openpgp_recipient_encryption_required")));
    assert_eq!(smtp.lock().unwrap().len(), 6);
    assert_eq!(fs::read(&sent_count).unwrap(), b"111111");

    let route_page = route("GET", "");
    assert_eq!(route_page.response.status_code, 200);
    let route_html = std::str::from_utf8(&route_page.response.body).unwrap();
    let encrypted_fields = format!(
        "csrf_token={}&send_intent={}&to=bob%40example.test&subject=RouteEncrypted&body=RouteEncryptedBody&pgp_encrypt=on&pgp_binding_revision={}",
        issued.record.csrf_token, form_intent(route_html), record.revision,
    );
    let encrypted_response = route("POST", &encrypted_fields);
    assert_eq!(
        encrypted_response.response.status_code, 303,
        "{:?}",
        encrypted_response.audit_events
    );
    assert_eq!(smtp.lock().unwrap().len(), 7);
    let encrypted_wire = smtp.lock().unwrap()[6].clone();
    assert_eq!(fs::read(&sent_path).unwrap(), encrypted_wire);
    assert!(!encrypted_wire
        .windows(b"RouteEncryptedBody".len())
        .any(|w| w == b"RouteEncryptedBody"));
    let crate::pgp_mime::PgpMimeMessage::Encrypted { ciphertext, .. } =
        crate::pgp_mime::classify(&encrypted_wire, crate::pgp_mime::PgpMimePolicy::default())
            .unwrap()
    else {
        panic!("route delivery must be encrypted MIME");
    };
    let decrypted = crypto
        .execute(
            "bob@example.test",
            &crate::openpgp_crypto::Operation::Decrypt {
                allowed_primary_fingerprints: vec![bfp.clone()],
                ciphertext,
            },
        )
        .unwrap()
        .unwrap();
    assert_decrypted_route_body(&decrypted.content);
    assert_eq!(fs::read(&sent_count).unwrap(), b"1111111");
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
    assert!(smtp.lock().unwrap().len() == 7);
    assert!(fs::read(&sent_count).unwrap() == b"1111111");
    assert!(
        crate::send_journal::SendJournal::new(gateway.settings_dir.join("send-journal"))
            .receipt("alice@example.test", &failed_intent, now)
            .unwrap()
            .is_none()
    );
    // Optional account/self policy permits an explicit ordinary message even
    // with the private crypto helper stopped. No sign/encrypt downgrade occurs:
    // the browser request itself selects no protection.
    let ordinary_intent = crate::send_journal::mint_intent(now).unwrap();
    let mut ordinary_request = native_send_request(&ordinary_intent, record.revision, &attachments);
    ordinary_request.recipients = "alice@example.test";
    ordinary_request.protection = crate::send::ProtectionIntent {
        binding_revision: Some(record.revision),
        ..Default::default()
    };
    let ordinary = gateway.send_message_with_backends(
        &context,
        &session,
        ordinary_request,
        &submission,
        &append,
    );
    assert!(matches!(
        ordinary.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: true,
            receipt_persisted: true
        }
    ));
    assert_eq!(smtp.lock().unwrap().len(), 8);
    let ordinary_wire = smtp.lock().unwrap()[7].clone();
    assert_eq!(fs::read(&sent_path).unwrap(), ordinary_wire);
    assert_eq!(fs::read(&sent_count).unwrap(), b"11111111");
    assert!(ordinary_wire
        .windows("Synthetic café body".len())
        .any(|w| w == "Synthetic café body".as_bytes()));
    assert!(!ordinary_wire
        .windows(b"application/pgp-encrypted".len())
        .any(|w| w == b"application/pgp-encrypted"));

    // SMTP acceptance and Sent append are separate durable outcomes. A scoped
    // child refusal must not invite a second SMTP submission on intent replay.
    scratch.write("sent-refuse", b"refuse", 0o600);
    let append_failure_intent = crate::send_journal::mint_intent(now).unwrap();
    let append_failure_request = || {
        let mut request =
            native_send_request(&append_failure_intent, record.revision, &attachments);
        request.recipients = "alice@example.test";
        request.protection = crate::send::ProtectionIntent {
            binding_revision: Some(record.revision),
            ..Default::default()
        };
        request
    };
    let append_failure = gateway.send_message_with_backends(
        &context,
        &session,
        append_failure_request(),
        &submission,
        &append,
    );
    assert!(matches!(
        append_failure.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: false,
            receipt_persisted: true
        }
    ));
    assert_eq!(smtp.lock().unwrap().len(), 9);
    assert!(fs::read(&sent_count).unwrap() == b"11111111");
    assert!(fs::read(&sent_path).unwrap() == ordinary_wire);
    fs::remove_file(&sent_refuse).unwrap();
    let append_failure_replay = gateway.send_message_with_backends(
        &context,
        &session,
        append_failure_request(),
        &submission,
        &append,
    );
    assert!(matches!(
        append_failure_replay.decision,
        BrowserSendDecision::Submitted {
            sent_copy_stored: false,
            receipt_persisted: true
        }
    ));
    assert_eq!(smtp.lock().unwrap().len(), 9);
    assert!(fs::read(&sent_count).unwrap() == b"11111111");

    for events in [
        &outcome.audit_events,
        &replay.audit_events,
        &stale.audit_events,
        &unavailable.audit_events,
        &self_outcome.audit_events,
        &ordinary.audit_events,
        &required_refusal.audit_events,
        &encrypt_only.audit_events,
        &draft_send.audit_events,
        &append_failure.audit_events,
        &append_failure_replay.audit_events,
    ] {
        let rendered = format!("{events:?}");
        assert!(!rendered.contains("Synthetic café body"));
        assert!(!rendered.contains("0, 1, 255"));
    }
    sent_mailbox.finish();
}
