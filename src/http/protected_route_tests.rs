use super::*;
use crate::config::{AppConfig, OpenPgpCryptoConfig};
use crate::http::http_gateway::RuntimeBrowserGateway;
use crate::mailbox_helper::mailbox_helper_protocol::{encode_response, MailboxHelperResponse};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

const PRIVATE_MARKER: &str = "SYNTHETIC_UNVERIFIED_BODY";
const FORGED_MARKER: &[u8] = b"SYNTHETIC_FOREIGN_ATTACHMENT";

// Only these explicit fixture modes forge a gateway reply. Other fixtures use
// the existing bounded decoder and the production protection discriminator.
pub(super) fn stored_attachment_fixture(
    context: &AuthenticationContext,
    session: &ValidatedSession,
    message: &MessageView,
    part: &str,
) -> BrowserAttachmentDownloadOutcome {
    if context.user_agent == "ProtectedSource/refused" {
        return BrowserAttachmentDownloadOutcome {
            decision: BrowserAttachmentDownloadDecision::Denied {
                public_reason: "temporarily_unavailable".into(),
            },
            audit_events: vec![],
        };
    }
    let reply_mode = context
        .user_agent
        .strip_prefix("ProtectedReply/")
        .or_else(|| context.user_agent.strip_prefix("ProtectedSource/"));
    if let Some(mode) = reply_mode {
        let mut account = session.record.canonical_username.clone();
        let mut attachment = DownloadedAttachment {
            mailbox_name: message.mailbox_name.clone(),
            uid: message.uid,
            part_path: part.into(),
            filename: "synthetic.bin".into(),
            content_type: "application/octet-stream".into(),
            body: if context.user_agent.starts_with("ProtectedSource/") {
                b"SYNTHETIC_DECODED_INNER_ATTACHMENT".to_vec()
            } else {
                FORGED_MARKER.into()
            },
        };
        match mode {
            "account" => account = "other@example.test".into(),
            "mailbox" => attachment.mailbox_name = "Sent".into(),
            "uid" => attachment.uid += 1,
            "part" => attachment.part_path = "1.99".into(),
            "owned" => (),
            _ => panic!("unknown protected reply fixture mode"),
        }
        return BrowserAttachmentDownloadOutcome {
            decision: BrowserAttachmentDownloadDecision::Downloaded {
                canonical_username: account,
                attachment,
            },
            audit_events: vec![],
        };
    }
    if crate::http::http_gateway::http_gateway_protected::has_protection_envelope(message) {
        return BrowserAttachmentDownloadOutcome {
            decision: BrowserAttachmentDownloadDecision::Denied {
                public_reason: "temporarily_unavailable".into(),
            },
            audit_events: vec![],
        };
    }
    let outcome = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
        .download_for_validated_session(context, session, message, part);
    BrowserAttachmentDownloadOutcome {
        decision: match outcome.decision {
            AttachmentDownloadDecision::Downloaded {
                canonical_username,
                attachment,
                ..
            } => BrowserAttachmentDownloadDecision::Downloaded {
                canonical_username,
                attachment,
            },
            AttachmentDownloadDecision::Denied { public_reason } => {
                BrowserAttachmentDownloadDecision::Denied {
                    public_reason: public_reason.as_str().into(),
                }
            }
        },
        audit_events: vec![outcome.audit_event],
    }
}

fn content_url() -> String {
    let version = StubGateway::fixture_metadata("alice@example.com", "INBOX", 9).version;
    format!(
        "/attachment?mailbox=INBOX&uid=9&mailbox_guid={}&message_guid={}&part=1.2",
        version.mailbox_guid, version.message_guid
    )
}

#[test]
fn stored_attachment_route_rejects_foreign_reply_authority_before_returning_bytes() {
    let app = app();
    let get = |mode: &str| {
        let mut request = request(
            "GET",
            &content_url(),
            &authenticated_same_origin_headers(),
            "",
        );
        request
            .headers
            .insert("user-agent".into(), format!("ProtectedReply/{mode}"));
        app.handle_request(&request, "127.0.0.1")
    };
    let positive = get("owned");
    assert_eq!(positive.response.status_code, 200);
    assert_eq!(positive.response.body, FORGED_MARKER);
    for mode in ["account", "mailbox", "uid", "part"] {
        let refused = get(mode);
        assert_eq!(refused.response.status_code, 503, "{mode}");
        assert!(!refused
            .response
            .body
            .windows(FORGED_MARKER.len())
            .any(|bytes| bytes == FORGED_MARKER));
        assert_eq!(
            refused
                .audit_events
                .iter()
                .filter(|event| event.action == "stub_source_read")
                .count(),
            1,
            "each identity decision must use a single stored snapshot"
        );
    }
}

fn nested_message(encrypted: bool) -> MessageView {
    let nested = if encrypted {
        concat!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=inner\r\n\r\n",
            "--inner\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n",
            "--inner\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=encrypted.asc\r\n\r\n",
            "-----BEGIN PGP MESSAGE-----\r\n\r\nU1lOVEhFVElDX1VOVkVSSUZJRURfQk9EWQ==\r\n-----END PGP MESSAGE-----\r\n",
            "--inner--\r\n"
        ).to_owned()
    } else {
        format!(concat!(
            "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=inner\r\n\r\n",
            "--inner\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n",
            "--inner\r\nContent-Type: application/pgp-signature\r\nContent-Disposition: attachment; filename=signature.asc\r\n\r\n",
            "-----BEGIN PGP SIGNATURE-----\r\n\r\nZml4dHVyZQ==\r\n-----END PGP SIGNATURE-----\r\n",
            "--inner--\r\n"
        ), PRIVATE_MARKER)
    };
    MessageView {
        metadata: Some(StubGateway::fixture_metadata("alice@example.com", "INBOX", 9)),
        mailbox_name: "INBOX".into(),
        uid: 9,
        flags: vec![],
        date_received: "2026-10-01 00:00:00 +0000".into(),
        size_virtual: nested.len() as u64,
        header_block: "From: sender@example.test\r\nSubject: Synthetic nested protection\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n".into(),
        body_text: format!("--outer\r\n{nested}--outer--\r\n"),
    }
}

struct StoredHelper {
    root: PathBuf,
    gateway: RuntimeBrowserGateway,
    server: Option<thread::JoinHandle<()>>,
}

impl StoredHelper {
    fn new(message: MessageView) -> Self {
        let root = PathBuf::from("/tmp").join(format!(
            "osmap-prt-{}-{}",
            std::process::id(),
            &crate::draft::generate_draft_id().unwrap()[..12]
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("mailbox.sock");
        let key = root.join("grant.key");
        fs::write(&key, [42; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "stored message fixture was not fetched"
                        );
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("stored fixture accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert!(String::from_utf8(request).unwrap().starts_with("operation=message_view\n"), "runtime must fetch one owned stored message, never directly extract a wrapper part");
            stream
                .write_all(
                    encode_response(&MailboxHelperResponse::MessageViewOk {
                        message: Box::new(message),
                    })
                    .as_bytes(),
                )
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let config = AppConfig::from_env_map(&BTreeMap::from([
            ("OSMAP_RUN_MODE".into(), "serve".into()),
            (
                "OSMAP_STATE_ROOT".into(),
                root.join("state").to_string_lossy().into_owned(),
            ),
            (
                "OSMAP_MAILBOX_HELPER_SOCKET_PATH".into(),
                socket.to_string_lossy().into_owned(),
            ),
            (
                "OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH".into(),
                key.to_string_lossy().into_owned(),
            ),
            (
                "OSMAP_MAILBOX_HELPER_PEER_UID".into(),
                crate::openbsd::effective_uid().to_string(),
            ),
        ]))
        .unwrap();
        Self {
            root,
            gateway: RuntimeBrowserGateway::from_config(&config),
            server: Some(server),
        }
    }

    fn finish(mut self) {
        self.server.take().unwrap().join().unwrap();
    }
}

impl Drop for StoredHelper {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn context() -> AuthenticationContext {
    AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "protected-route-fixture",
        "127.0.0.1",
        "Synthetic protected route",
    )
    .unwrap()
}

#[test]
fn runtime_reader_withholds_nested_signed_and_encrypted_parts_and_automatic_quotes() {
    for encrypted in [false, true] {
        let fixture = StoredHelper::new(nested_message(encrypted));
        let outcome =
            fixture
                .gateway
                .view_message(&context(), &StubGateway::validated_session(), "INBOX", 9);
        let BrowserMessageViewDecision::Rendered { rendered, .. } = outcome.decision else {
            panic!(
                "a refusal view must preserve reader navigation: {:?}",
                outcome.audit_events
            );
        };
        assert!(matches!(
            rendered.openpgp,
            Some(crate::openpgp_reader_ui::ReaderState::Refused(_))
        ));
        assert!(!rendered.body_html.contains(PRIVATE_MARKER));
        assert!(rendered.body_text_for_compose.is_empty());
        assert!(rendered.attachments.is_empty());
        fixture.finish();
    }
}

#[test]
fn runtime_ordinary_reader_and_download_remain_available_without_crypto() {
    let mut message = nested_message(false);
    message.body_text = format!(concat!(
        "--outer\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n",
        "--outer\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=synthetic.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAH/\r\n--outer--\r\n"
    ), PRIVATE_MARKER);
    let fixture = StoredHelper::new(message.clone());
    let session = StubGateway::validated_session();
    let outcome = fixture
        .gateway
        .view_message(&context(), &session, "INBOX", 9);
    let BrowserMessageViewDecision::Rendered { rendered, .. } = outcome.decision else {
        panic!(
            "ordinary reader must remain usable without crypto: {:?}",
            outcome.audit_events
        );
    };
    assert!(rendered.openpgp.is_none());
    assert!(rendered.body_html.contains(PRIVATE_MARKER));
    assert!(rendered.body_text_for_compose.contains(PRIVATE_MARKER));
    assert_eq!(rendered.attachments.len(), 1);
    let download =
        fixture
            .gateway
            .download_stored_attachment(&context(), &session, &message, "1.2");
    let BrowserAttachmentDownloadDecision::Downloaded { attachment, .. } = download.decision else {
        panic!("ordinary attachment must remain usable without crypto");
    };
    assert_eq!(attachment.body, [0, 1, 255]);
    fixture.finish();
}

#[test]
fn runtime_nested_wrapper_parts_never_enter_ordinary_attachment_decoder() {
    let gateway_root = PathBuf::from("/tmp/osmap-unused-protected-test");
    let gateway = RuntimeBrowserGateway::for_test(&gateway_root);
    for encrypted in [false, true] {
        let message = nested_message(encrypted);
        let part = "1.1.2";
        let positive = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
            .download_from_message(&message, part)
            .unwrap();
        assert!(
            !positive.body.is_empty(),
            "fixture must expose a wrapper part through the ordinary decoder"
        );
        let outcome = gateway.download_stored_attachment(
            &context(),
            &StubGateway::validated_session(),
            &message,
            part,
        );
        assert!(matches!(
            outcome.decision,
            BrowserAttachmentDownloadDecision::Denied { .. }
        ));
    }
}

#[test]
fn runtime_legacy_protected_attachment_selectors_are_refused_after_owned_fetch() {
    for encrypted in [false, true] {
        let fixture = StoredHelper::new(nested_message(encrypted));
        let outcome = fixture.gateway.download_attachment(
            &context(),
            &StubGateway::validated_session(),
            "INBOX",
            9,
            "1.1.2",
        );
        assert_eq!(
            outcome.decision,
            BrowserAttachmentDownloadDecision::Denied {
                public_reason: "invalid_request".into()
            },
            "{:?}",
            outcome.audit_events
        );
        fixture.finish();
    }
}

#[test]
fn openpgp_only_configs_get_unix_promises_and_only_socket_grant_unveil_paths() {
    for crypto in [false, true] {
        let mut config =
            AppConfig::from_env_map(&BTreeMap::from([("OSMAP_RUN_MODE".into(), "serve".into())]))
                .unwrap();
        assert!(config.mailbox_helper_socket_path.is_none());
        let client = OpenPgpCryptoConfig {
            socket: "/var/run/osmap/synthetic.sock".into(),
            key_file: "/var/lib/osmap/web/synthetic.key".into(),
            helper_uid: 4242,
        };
        if crypto {
            config.openpgp_crypto = Some(client.clone());
        } else {
            config.openpgp_inventory = Some(client.clone());
        }
        let plan = crate::openbsd::OpenbsdConfinementPlan::from_config(&config);
        assert!(plan
            .promises_before_lock
            .split_whitespace()
            .any(|promise| promise == "unix"));
        assert!(plan
            .promises_after_lock
            .split_whitespace()
            .any(|promise| promise == "unix"));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == client.socket && rule.permissions == "rw"));
        assert!(plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path == client.key_file && rule.permissions == "r"));
        assert!(!plan
            .unveil_rules
            .iter()
            .any(|rule| rule.path.to_string_lossy().contains("private-keys-v1.d")));
    }
}

fn protected_source() -> MessageView {
    let mut message = nested_message(true);
    message.header_block = "From: sender@example.test\r\nSubject: Synthetic protected source\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=inner\r\n".into();
    message.body_text = message
        .body_text
        .split_once("\r\n\r\n")
        .unwrap()
        .1
        .strip_suffix("--outer--\r\n")
        .unwrap()
        .into();
    message
}

pub(super) fn source_fixture(
    context: &AuthenticationContext,
    session: &ValidatedSession,
    request: &MessageViewRequest,
) -> Option<crate::mailbox::MessageViewOutcome> {
    if !context.user_agent.starts_with("ProtectedSource/") {
        return None;
    }
    assert_eq!(request.mailbox_name, "INBOX");
    assert_eq!(request.uid, 9);
    Some(crate::mailbox::MessageViewOutcome {
        decision: MessageViewDecision::Retrieved {
            canonical_username: session.record.canonical_username.clone(),
            session_id: session.record.session_id.clone(),
            message: Box::new(protected_source()),
        },
        audit_event: LogEvent::new(
            LogLevel::Info,
            EventCategory::Mailbox,
            "stub_source_read",
            "synthetic protected source read",
        ),
    })
}

#[test]
fn source_copy_selects_processed_inner_attachment_instead_of_colliding_ciphertext_part() {
    let app = app();
    let message = protected_source();
    let ordinary_wrapper = AttachmentDownloadService::new(AttachmentDownloadPolicy::default())
        .download_from_message(&message, "1.2")
        .unwrap();
    assert!(ordinary_wrapper
        .body
        .starts_with(b"-----BEGIN PGP MESSAGE-----"));
    let version = message.metadata.unwrap().version;
    let form = BTreeMap::from([
        ("source_mailbox".into(), "INBOX".into()),
        ("source_uid".into(), "9".into()),
        ("source_mailbox_guid".into(), version.mailbox_guid),
        ("source_message_guid".into(), version.message_guid),
    ]);
    for mode in ["owned", "refused", "account", "mailbox", "uid", "part"] {
        let mut ctx = context();
        ctx.user_agent = format!("ProtectedSource/{mode}");
        let mut audit = Vec::new();
        let result = app.resolve_source_attachments(
            &ctx,
            &StubGateway::validated_session(),
            &form,
            &["1.2".into()],
            &mut audit,
            "send",
        );
        if mode == "owned" {
            let (_, attachments) = result
                .ok()
                .flatten()
                .expect("processed selected attachment");
            assert_eq!(attachments[0].body, b"SYNTHETIC_DECODED_INNER_ATTACHMENT");
            assert_ne!(attachments[0].body, ordinary_wrapper.body);
        } else {
            let failure = match result {
                Err(failure) => failure,
                _ => panic!("{mode} accepted"),
            };
            assert_eq!(
                failure.response().0,
                if mode == "refused" { 503 } else { 409 }
            );
        }
        assert_eq!(
            audit
                .iter()
                .filter(|event| event.action == "stub_source_read")
                .count(),
            1
        );
    }
}
