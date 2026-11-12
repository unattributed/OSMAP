//! Opt-in generated Draft location and normal Runtime private filesystem proof.
//! Synthetic issued sessions are not login or human browser acceptance.
//! No SMTP listener, system sendmail, IMAP draft mirror or private crypto.
use super::*;
use crate::draft::{DraftPolicy, DraftRecord, DraftRecordInput, DraftStore, FileDraftStore};
use crate::draft_location::{Location, Store as LocationStore};
use crate::mailbox::{
    MailboxBackend, MailboxBackendError, MailboxEntry, MessageAppendBackend, MessageAppendRequest,
    MessageFlagBackend, MessageFlagRequest, MessageFlagResult, MessageListBackend,
    MessageListRequest, MessageMoveBackend, MessageMoveRequest, MessageSearchBackend,
    MessageSearchRequest, MessageSearchResult, MessageSummary, MessageView, MessageViewBackend,
    MessageViewRequest,
};
use crate::totp::TimeProvider;
use std::os::unix::fs::symlink;
const PUBLIC_ATTACHMENT: &[u8] = b"Draft location public attachment.";
const PUBLIC_BODY: &str = "Harmless draft location body café.";

#[derive(Clone)]
struct UnavailableMail {
    reads: Arc<AtomicUsize>,
    forbidden: Arc<AtomicUsize>,
}
impl UnavailableMail {
    fn read(&self, account: &str) -> MailboxBackendError {
        assert!([ALICE, BOB].contains(&account));
        assert!(self.reads.fetch_add(1, Ordering::SeqCst) < 64);
        MailboxBackendError {
            backend: "draft-native-mail-unavailable",
            reason: "mail reads are unavailable in private draft fixture".into(),
        }
    }
    fn mutation(&self) -> MailboxBackendError {
        self.forbidden.fetch_add(1, Ordering::SeqCst);
        MailboxBackendError {
            backend: "draft-native-no-mail-mutation",
            reason: "mail mutation is outside private draft fixture".into(),
        }
    }
}
impl MailboxBackend for UnavailableMail {
    fn list_mailboxes(&self, account: &str) -> Result<Vec<MailboxEntry>, MailboxBackendError> {
        Err(self.read(account))
    }
    fn create_folder(
        &self,
        _: &crate::folder_create::CreateFolderRequest,
    ) -> crate::folder_create::Outcome {
        let _ = self.mutation();
        crate::folder_create::Outcome::Refused(crate::folder_create::Refusal::Unavailable)
    }
}
impl MessageListBackend for UnavailableMail {
    fn list_messages(
        &self,
        account: &str,
        _: &MessageListRequest,
    ) -> Result<Vec<MessageSummary>, MailboxBackendError> {
        Err(self.read(account))
    }
}
impl MessageSearchBackend for UnavailableMail {
    fn search_messages(
        &self,
        account: &str,
        _: &MessageSearchRequest,
    ) -> Result<Vec<MessageSearchResult>, MailboxBackendError> {
        Err(self.read(account))
    }
}
impl MessageViewBackend for UnavailableMail {
    fn fetch_message(
        &self,
        account: &str,
        _: &MessageViewRequest,
    ) -> Result<MessageView, MailboxBackendError> {
        Err(self.read(account))
    }
}
impl MessageAppendBackend for UnavailableMail {
    fn append_message(&self, _: &str, _: &MessageAppendRequest) -> Result<(), MailboxBackendError> {
        Err(self.mutation())
    }
}
impl MessageMoveBackend for UnavailableMail {
    fn move_message(&self, _: &str, _: &MessageMoveRequest) -> Result<(), MailboxBackendError> {
        Err(self.mutation())
    }
}
impl MessageFlagBackend for UnavailableMail {
    fn set_message_flag(
        &self,
        _: &str,
        _: &MessageFlagRequest,
    ) -> Result<MessageFlagResult, MailboxBackendError> {
        Err(self.mutation())
    }
}
fn unavailable_helper(fixture: &mut Fixture, backend: UnavailableMail) -> PathBuf {
    let socket = fixture.root.join("owned-unavailable-mail.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = fixture.stop.clone();
    fixture.threads.push(thread::spawn(move || {
        let replay = Mutex::new(BTreeMap::new());
        let deadline = Instant::now() + NATIVE_LIMIT;
        while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => panic!("owned unavailable helper listener"),
            };
            handle_helper_client(
                HelperBackends {
                    mailbox_backend: &backend,
                    message_list_backend: &backend,
                    message_search_backend: &backend,
                    message_view_backend: &backend,
                    message_move_backend: &backend,
                    message_append_backend: &backend,
                    message_flag_backend: &backend,
                },
                &Logger::new(crate::config::LogFormat::Text, LogLevel::Error),
                &mut stream,
                MailboxHelperPolicy::default(),
                MailboxHelperTrustedCallerPolicy {
                    trusted_peer_uid: test_runtime_uid(),
                    grant_key: test_helper_grant_key(),
                },
                &replay,
            );
        }
    }));
    socket
}
fn compose_fields(body: &str) -> BTreeMap<String, String> {
    let form = body
        .split_once("<form id=\"compose-form\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(form.contains("action=\"/send\"") && form.contains("enctype=\"multipart/form-data\""));
    let mut fields = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split_once('>').unwrap().0;
        let Some(name) = attribute(tag, "name") else {
            continue;
        };
        let kind = attribute(tag, "type").unwrap_or_else(|| "text".into());
        if matches!(kind.as_str(), "file" | "checkbox") {
            continue;
        }
        assert!(fields
            .insert(name, attribute(tag, "value").unwrap_or_default())
            .is_none());
    }
    let textarea = form
        .split_once("<textarea id=\"compose-body\"")
        .unwrap()
        .1
        .split_once('>')
        .unwrap()
        .1
        .split_once("</textarea>")
        .unwrap()
        .0;
    fields.insert(
        "body".into(),
        decode(textarea.strip_prefix('\n').unwrap_or(textarea)),
    );
    assert!(form.contains("name=\"body_format\"") && form.contains("value=\"plain\""));
    fields.insert("body_format".into(), "plain".into());
    assert!(fields.contains_key("csrf_token") && fields.contains_key("send_intent"));
    assert_eq!(fields.get("from").map(String::as_str), Some(ALICE));
    fields
}

fn compose_post(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    path: &str,
    fields: &BTreeMap<String, String>,
    upload: bool,
) -> HandledHttpResponse {
    assert!(["/send", "/drafts/save"].contains(&path));
    let boundary = "owned-draft-location-native-boundary";
    let mut body = Vec::new();
    for (key, value) in fields {
        assert!(!key.chars().any(char::is_control) && !key.contains('"'));
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    if upload {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"draft-location-public.txt\"\r\nContent-Type: text/plain\r\n\r\n").as_bytes());
        body.extend_from_slice(PUBLIC_ATTACHMENT);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let cookie = session
        .map(|session| format!("Cookie: osmap_session={}\r\n", session.token.as_str()))
        .unwrap_or_default();
    let mut wire = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: OSMAP/native-reader\r\nOrigin: http://localhost\r\n{cookie}Content-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend(body);
    let request = crate::http::parse_http_request_bytes(&wire, app.policy()).unwrap();
    app.handle_request(&request, "127.0.0.1")
}
fn location(response: &HandledHttpResponse) -> String {
    response
        .response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .unwrap()
        .1
        .clone()
}

fn location_fields(body: &str, selected: Location) -> BTreeMap<String, String> {
    let form = body
        .split_once("<form id=\"copies-draft-location-form\"")
        .unwrap()
        .1
        .split_once("</form>")
        .unwrap()
        .0;
    assert!(
        form.contains("method=\"post\"") && form.contains("action=\"/settings/draft-location\"")
    );
    let select = form
        .split_once("<select id=\"copies-draft-location\"")
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0;
    assert!(select.contains("name=\"location\""));
    let choices: Vec<_> = select
        .split("<option ")
        .skip(1)
        .map(|part| attribute(part.split_once('>').unwrap().0, "value").unwrap())
        .collect();
    assert_eq!(choices, vec!["default", "working"]);
    assert!(select.contains(&format!("value=\"{}\"", selected.value())));
    let mut fields = BTreeMap::new();
    for part in form.split("<input ").skip(1) {
        let tag = part.split_once('>').unwrap().0;
        if let Some(name) = attribute(tag, "name") {
            assert!(fields
                .insert(name, attribute(tag, "value").unwrap_or_default())
                .is_none());
        }
    }
    assert_eq!(fields.len(), 2);
    assert!(fields.contains_key("csrf_token") && fields.contains_key("expected_revision"));
    fields.insert("location".into(), selected.value().into());
    fields
}
fn choose(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    selected: Location,
    revision: u64,
) {
    let page = get(app, session, "/settings?section=copies");
    assert_eq!(page.response.status_code, 200);
    let fields = location_fields(text(&page), selected);
    assert_eq!(fields.get("expected_revision"), Some(&revision.to_string()));
    assert_eq!(
        http(
            app,
            Some(session),
            "POST",
            "/settings/draft-location",
            &fields
        )
        .response
        .status_code,
        303
    );
}
fn fresh(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    subject: &str,
) -> BTreeMap<String, String> {
    let page = get(app, session, "/compose");
    assert_eq!(page.response.status_code, 200);
    let mut fields = compose_fields(text(&page));
    fields.insert("to".into(), String::new());
    fields.insert("subject".into(), subject.into());
    fields.insert("body".into(), PUBLIC_BODY.into());
    fields
}
fn saved_id(response: &HandledHttpResponse) -> String {
    assert_eq!(response.response.status_code, 303);
    let href = location(response);
    assert!(href.starts_with("/draft?id="));
    href.strip_prefix("/draft?id=").unwrap().to_owned()
}
fn seed(store: &FileDraftStore, account: &str, subject: &str, now: u64) -> String {
    let id = crate::draft::generate_draft_id().unwrap();
    let draft = DraftRecord::new(
        DraftPolicy::default(),
        DraftRecordInput {
            draft_id: id.clone(),
            canonical_username: account.into(),
            now,
            recipients_text: String::new(),
            cc_text: String::new(),
            bcc_text: String::new(),
            subject: subject.into(),
            body: PUBLIC_BODY.into(),
            attachments: vec![],
            source_attachments: None,
        },
    )
    .unwrap();
    store.save(&draft, now).unwrap();
    id
}
fn tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                walk(root, &entry.path(), result);
            } else {
                assert!(metadata.is_file());
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}
fn assert_private_tree(root: &Path, uid: u32) {
    let metadata = fs::symlink_metadata(root).unwrap();
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), uid);
    assert_eq!(
        metadata.mode() & 0o777,
        if metadata.is_dir() { 0o700 } else { 0o600 }
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(root).unwrap() {
            assert_private_tree(&entry.unwrap().path(), uid);
        }
    }
}
fn duplicate_owned_directory(from: &Path, to: &Path) {
    fs::DirBuilder::new().mode(0o700).create(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        fs::set_permissions(
            to.join(entry.file_name()),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}
#[test]
#[ignore = "explicit OpenBSD generated Draft location and private storage; zero SMTP and mailbox mutation"]
fn isolated_openbsd_generated_private_draft_location_original_ids_quota_and_discard() {
    assert_eq!(
        std::env::consts::OS,
        "openbsd",
        "explicit native fixture only"
    );
    let before = standard_metadata();
    let root = PathBuf::from("/tmp").join(format!(
        "osmap-native-draft-location-{}-{}",
        std::process::id(),
        crate::draft::generate_draft_id().unwrap()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut fixture = Fixture {
        root: root.clone(),
        stop: Arc::new(AtomicBool::new(false)),
        threads: vec![],
    };
    let uid = fs::metadata(&root).unwrap().uid();
    assert_ne!(uid, 0);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("app-state"))
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let forbidden = Arc::new(AtomicUsize::new(0));
    let helper = unavailable_helper(
        &mut fixture,
        UnavailableMail {
            reads: reads.clone(),
            forbidden: forbidden.clone(),
        },
    );
    let key = root.join("fixture-grant.key");
    fs::write(&key, test_helper_grant_key()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let sendmail = root.join("owned-denied-sendmail");
    let smtp_marker = root.join("forbidden-send-invoked");
    assert!(smtp_marker
        .to_str()
        .unwrap()
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)));
    // Fixed code derives its private sibling marker from the executable argv path.
    // Fixture paths never become interpreter source or shell commands.
    fs::write(
        &sendmail,
        r#"#!/usr/local/bin/python3
import os
import sys
from pathlib import Path
executable = Path(sys.argv[0])
if not executable.is_absolute():
    raise SystemExit(72)
marker = executable.with_name("forbidden-send-invoked")
descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.close(descriptor)
raise SystemExit(71)
"#,
    )
    .unwrap();
    fs::set_permissions(&sendmail, fs::Permissions::from_mode(0o700)).unwrap();
    let config = AppConfig::from_env_map(&BTreeMap::from([
        ("OSMAP_RUN_MODE".into(), "serve".into()),
        (
            "OSMAP_STATE_DIR".into(),
            root.join("app-state").to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_SOCKET_PATH".into(),
            helper.to_string_lossy().into_owned(),
        ),
        (
            "OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH".into(),
            key.to_string_lossy().into_owned(),
        ),
        ("OSMAP_MAILBOX_HELPER_PEER_UID".into(), uid.to_string()),
        ("OSMAP_MAILBOX_WORKER_BUDGET".into(), "1".into()),
    ]))
    .unwrap();
    assert!(
        config.openpgp_crypto.is_none()
            && config.openpgp_inventory.is_none()
            && config.openpgp_public_admin.is_none()
    );
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "native-draft-location-session",
        "127.0.0.1",
        "OSMAP/native-reader",
    )
    .unwrap();
    let sessions = SessionService::new(
        FileSessionStore::new(&config.state_layout.session_dir),
        SystemTimeProvider,
        SystemRandomSource,
        180,
        180,
    );
    let alice = sessions
        .issue(&context, ALICE, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let new_app = || {
        BrowserApp::new(
            HttpPolicy::from_config(&config),
            RuntimeBrowserGateway::from_config(&config)
                .with_fixture_sendmail_path(sendmail.clone()),
        )
    };
    let app = new_app();
    let preferences = LocationStore::new(&config.state_layout.settings_dir);
    assert_eq!(
        preferences.load(ALICE).unwrap(),
        crate::draft_location::Preference::default()
    );
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::draft_location::Preference::default()
    );
    let ordinary = FileDraftStore::new(&config.state_layout.draft_dir, DraftPolicy::default());
    let working = ordinary.clone().with_new_location(Location::Working);
    let legacy = seed(
        &ordinary,
        ALICE,
        "Legacy default neighbour",
        SystemTimeProvider.unix_timestamp(),
    );
    let legacy_path = ordinary.draft_dir_for_username_and_id(ALICE, &legacy);
    let legacy_before = tree_bytes(&legacy_path);
    working.qualify_location(BOB, Location::Working).unwrap();
    let bob_id = seed(
        &working,
        BOB,
        "Bob working neighbour",
        SystemTimeProvider.unix_timestamp(),
    );
    let bob_path = working.resolved_draft_dir(BOB, &bob_id).unwrap().unwrap();
    let bob_before = tree_bytes(&bob_path);
    let unrelated = crate::settings::FileUserSettingsStore::new(&config.state_layout.settings_dir);
    crate::settings::UserSettingsStore::save(
        &unrelated,
        ALICE,
        &crate::settings::UserSettings {
            html_display_preference: crate::rendering::HtmlDisplayPreference::PreferPlainText,
            archive_mailbox_name: Some("INBOX".into()),
        },
    )
    .unwrap();
    let unrelated_path = unrelated.settings_path_for_username(ALICE);
    let unrelated_before = fs::read(&unrelated_path).unwrap();
    let initial = get(&app, &alice, "/settings?section=copies");
    assert_eq!(initial.response.status_code, 200);
    let stale_preference = location_fields(text(&initial), Location::Working);
    assert!(text(&initial).contains("value=\"default\" selected"));
    choose(&app, &alice, Location::Working, 0);
    assert_eq!(preferences.load(ALICE).unwrap().revision, 1);
    let original = fresh(&app, &alice, "Working attachment draft");
    let first = compose_post(&app, Some(&alice), "/drafts/save", &original, true);
    let working_id = saved_id(&first);
    let actual_working = ordinary
        .resolved_draft_dir(ALICE, &working_id)
        .unwrap()
        .unwrap();
    let expected_working = config
        .state_layout
        .draft_dir
        .join(".locations/working")
        .join(ordinary.owner_dir_for_username(ALICE).file_name().unwrap())
        .join(&working_id);
    assert_eq!(actual_working, expected_working);
    assert!(!ordinary
        .draft_dir_for_username_and_id(ALICE, &working_id)
        .exists());
    assert_private_tree(&actual_working, uid);
    let stored = ordinary
        .load(ALICE, &working_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(stored.request.body, PUBLIC_BODY);
    assert!(stored.request.recipients_text.is_empty());
    assert_eq!(stored.request.attachments.len(), 1);
    assert_eq!(stored.request.attachments[0].body, PUBLIC_ATTACHMENT);
    assert!(fs::read_dir(&actual_working)
        .unwrap()
        .any(|entry| fs::read(entry.unwrap().path()).unwrap() == PUBLIC_ATTACHMENT));
    drop(app);
    let restarted = new_app();
    assert_eq!(preferences.load(ALICE).unwrap().location, Location::Working);
    let resumed = get(&restarted, &alice, &format!("/draft?id={working_id}"));
    assert_eq!(resumed.response.status_code, 200);
    assert!(text(&resumed).contains("draft-location-public.txt"));
    let stale_draft = compose_fields(text(&resumed));
    assert_eq!(
        stale_draft.get("body").map(String::as_str),
        Some(PUBLIC_BODY)
    );
    assert_eq!(
        stale_draft.get("draft_revision").map(String::as_str),
        Some("1")
    );
    let reading = get(&restarted, &alice, "/settings?section=reading");
    assert_eq!(reading.response.status_code, 200);
    assert!(text(&reading).contains("Working drafts"));
    choose(&restarted, &alice, Location::Default, 1);
    let mut edited = stale_draft.clone();
    edited.insert("body".into(), "Updated public working draft.".into());
    assert_eq!(
        saved_id(&compose_post(
            &restarted,
            Some(&alice),
            "/drafts/save",
            &edited,
            false
        )),
        working_id
    );
    assert_eq!(
        ordinary.resolved_draft_dir(ALICE, &working_id).unwrap(),
        Some(actual_working.clone())
    );
    let changed = ordinary
        .load(ALICE, &working_id, SystemTimeProvider.unix_timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(changed.revision, Some(2));
    assert_eq!(changed.request.attachments[0].body, PUBLIC_ATTACHMENT);
    let default_fields = fresh(&restarted, &alice, "New default draft");
    let default_id = saved_id(&compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &default_fields,
        false,
    ));
    let default_path = ordinary.draft_dir_for_username_and_id(ALICE, &default_id);
    assert_eq!(
        ordinary.resolved_draft_dir(ALICE, &default_id).unwrap(),
        Some(default_path.clone())
    );
    let listing = get(&restarted, &alice, "/drafts");
    assert_eq!(listing.response.status_code, 200);
    for subject in [
        "Legacy default neighbour",
        "Working attachment draft",
        "New default draft",
    ] {
        assert!(text(&listing).contains(subject));
    }
    assert!(text(&listing).contains("Drafts and Working drafts"));
    assert!(!text(&listing).contains("Bob working neighbour"));
    let safe_preference = preferences.load(ALICE).unwrap();
    for (key, value, status) in [
        ("csrf_token", "bad", 403),
        ("expected_revision", "00", 400),
        ("location", "../working", 400),
        ("location", "/tmp", 400),
        ("location", "unknown", 400),
        ("account", BOB, 400),
        ("path", "/tmp", 400),
    ] {
        let mut bad = location_fields(
            text(&get(&restarted, &alice, "/settings?section=copies")),
            Location::Working,
        );
        bad.insert(key.into(), value.into());
        assert_eq!(
            http(
                &restarted,
                Some(&alice),
                "POST",
                "/settings/draft-location",
                &bad
            )
            .response
            .status_code,
            status
        );
        assert_eq!(preferences.load(ALICE).unwrap(), safe_preference);
    }
    let mut missing = stale_preference.clone();
    missing.remove("csrf_token");
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/draft-location",
            &missing
        )
        .response
        .status_code,
        403
    );
    let mut oversized = stale_preference.clone();
    oversized.insert("location".into(), "x".repeat(2049));
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/draft-location",
            &oversized
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        http(
            &restarted,
            Some(&alice),
            "POST",
            "/settings/draft-location",
            &stale_preference
        )
        .response
        .status_code,
        409
    );
    assert_eq!(
        http(
            &restarted,
            Some(&bob),
            "POST",
            "/settings/draft-location",
            &stale_preference
        )
        .response
        .status_code,
        403
    );
    assert_eq!(
        http(
            &restarted,
            None,
            "POST",
            "/settings/draft-location",
            &stale_preference
        )
        .response
        .status_code,
        303
    );
    assert_eq!(preferences.load(ALICE).unwrap(), safe_preference);
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::draft_location::Preference::default()
    );
    assert_eq!(fs::read(&unrelated_path).unwrap(), unrelated_before);
    let latest_before = tree_bytes(&actual_working);
    let mut old = stale_draft.clone();
    old.insert("body".into(), "Stale public edit refused.".into());
    let stale_saved = compose_post(&restarted, Some(&alice), "/drafts/save", &old, false);
    assert_eq!(stale_saved.response.status_code, 409);
    let retained_stale = compose_fields(text(&stale_saved));
    assert_eq!(
        retained_stale.get("body").map(String::as_str),
        Some("Stale public edit refused.")
    );
    assert_eq!(retained_stale.get("to").map(String::as_str), Some(""));
    assert_eq!(tree_bytes(&actual_working), latest_before);
    // Isolate revision CAS with a genuinely generated current, unconsumed intent.
    let current_for_cas = get(&restarted, &alice, &format!("/draft?id={working_id}"));
    assert_eq!(current_for_cas.response.status_code, 200);
    let mut stale_revision = compose_fields(text(&current_for_cas));
    assert_eq!(
        stale_revision.get("draft_revision").map(String::as_str),
        Some("2")
    );
    // Use assert! so a failed comparison never prints private intent values.
    assert!(stale_revision.get("send_intent") != old.get("send_intent"));
    stale_revision.insert("draft_revision".into(), old["draft_revision"].clone());
    assert_eq!(
        compose_post(
            &restarted,
            Some(&alice),
            "/drafts/save",
            &stale_revision,
            false
        )
        .response
        .status_code,
        409
    );
    assert_eq!(tree_bytes(&actual_working), latest_before);
    assert_ne!(
        get(&restarted, &bob, &format!("/draft?id={working_id}"))
            .response
            .status_code,
        200
    );
    choose(&restarted, &alice, Location::Working, 2);
    let working_root = config.state_layout.draft_dir.join(".locations/working");
    // Generated resumed fields retain their actual ID/revision when placement disappears.
    let before_missing = get(&restarted, &alice, &format!("/draft?id={working_id}"));
    assert_eq!(before_missing.response.status_code, 200);
    let mut existing_missing = compose_fields(text(&before_missing));
    assert_eq!(
        existing_missing.get("draft_revision").map(String::as_str),
        Some("2")
    );
    existing_missing.insert(
        "body".into(),
        "Missing placement existing edit refused.".into(),
    );
    let default_owner = ordinary.owner_dir_for_username(ALICE);
    let default_before_missing = tree_bytes(&default_owner);
    let parked_missing = root.join("owned-working-missing-parked");
    let missing_fields = fresh(&restarted, &alice, "Missing selected placement refusal");
    fs::rename(&working_root, &parked_missing).unwrap();
    let missing_copies = get(&restarted, &alice, "/settings?section=copies");
    assert_eq!(missing_copies.response.status_code, 200);
    let recovery_settings = location_fields(text(&missing_copies), Location::Working);
    assert_eq!(
        recovery_settings
            .get("expected_revision")
            .map(String::as_str),
        Some("3")
    );
    assert!(text(&missing_copies)
        .contains("<option value=\"working\" selected>Working drafts</option>"));
    assert!(text(&missing_copies).contains("Saved draft location is unavailable."));
    assert!(text(&missing_copies).contains("explicitly requalify Working drafts using this form."));
    assert!(!working_root.exists());
    let missing = compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &missing_fields,
        false,
    );
    assert_ne!(missing.response.status_code, 303);
    assert!(text(&missing).contains("Missing selected placement refusal"));
    assert!(text(&missing).contains(PUBLIC_BODY));
    assert!(!working_root.exists());
    assert_eq!(tree_bytes(&default_owner), default_before_missing);
    let missing_existing = compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &existing_missing,
        false,
    );
    assert_ne!(missing_existing.response.status_code, 303);
    assert!(!working_root.exists());
    assert_eq!(tree_bytes(&default_owner), default_before_missing);
    assert_eq!(preferences.load(ALICE).unwrap().location, Location::Working);
    fs::rename(&parked_missing, &working_root).unwrap();
    assert_eq!(tree_bytes(&actual_working), latest_before);
    assert_eq!(tree_bytes(&bob_path), bob_before);
    let parked = root.join("owned-working-parked");
    let blocked_fields = fresh(&restarted, &alice, "Unsafe placement refusal");
    fs::rename(&working_root, &parked).unwrap();
    let outside = root.join("owned-empty-outside");
    fs::DirBuilder::new().mode(0o700).create(&outside).unwrap();
    symlink(&outside, &working_root).unwrap();
    let blocked = compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &blocked_fields,
        false,
    );
    assert_ne!(blocked.response.status_code, 303);
    assert!(text(&blocked).contains("Unsafe placement refusal"));
    assert!(text(&blocked).contains(PUBLIC_BODY));
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(preferences.load(ALICE).unwrap().location, Location::Working);
    fs::remove_file(&working_root).unwrap();
    fs::rename(&parked, &working_root).unwrap();
    assert_eq!(tree_bytes(&actual_working), latest_before);
    let duplicate = ordinary.draft_dir_for_username_and_id(ALICE, &working_id);
    let duplicate_fields = fresh(&restarted, &alice, "Duplicate placement refusal");
    duplicate_owned_directory(&actual_working, &duplicate);
    let duplicate_before = tree_bytes(&duplicate);
    assert!(ordinary
        .load(ALICE, &working_id, SystemTimeProvider.unix_timestamp())
        .is_err());
    assert_ne!(get(&restarted, &alice, "/drafts").response.status_code, 200);
    let duplicate_refused = compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &duplicate_fields,
        false,
    );
    assert_ne!(duplicate_refused.response.status_code, 303);
    assert!(text(&duplicate_refused).contains("Duplicate placement refusal"));
    assert!(text(&duplicate_refused).contains(PUBLIC_BODY));
    assert_eq!(tree_bytes(&actual_working), latest_before);
    assert_eq!(tree_bytes(&duplicate), duplicate_before);
    fs::remove_dir_all(&duplicate).unwrap();
    // Real recovery is retained under a durable intent, without invoking any transport.
    let now = SystemTimeProvider.unix_timestamp();
    let journal = crate::send_journal::SendJournal::new(
        config.state_layout.settings_dir.join("send-journal"),
    );
    let recovery = crate::send_recovery::SendRecovery::new(
        config.state_layout.settings_dir.join("send-recovery"),
    );
    let intent = crate::send_journal::mint_intent(now).unwrap();
    let request = crate::send::ComposeRequest::new(
        crate::send::ComposePolicy::default(),
        ALICE,
        "Public quota recovery",
        PUBLIC_BODY,
    )
    .unwrap();
    journal
        .execute_prepared(
            ALICE,
            &intent,
            now,
            |_| Ok::<_, ()>(request.clone()),
            |prepared| {
                assert_eq!(
                    recovery
                        .capture(&journal, &ordinary, ALICE, &intent, prepared, now)
                        .unwrap(),
                    *prepared
                );
                crate::send_journal::AttemptOutcome::Unconfirmed
            },
        )
        .unwrap();
    assert_eq!(recovery.storage_usage(ALICE, now).unwrap().0, 1);
    let old_time = now - crate::draft::DEFAULT_DRAFT_MAX_AGE_SECONDS - 1;
    let expired = seed(&working, ALICE, "Expired working setup", old_time);
    let expired_path = working
        .resolved_draft_dir(ALICE, &expired)
        .unwrap()
        .unwrap();
    assert!(expired_path.exists());
    assert_eq!(ordinary.list(ALICE, now).unwrap().len(), 3);
    assert!(!expired_path.exists());
    for index in 0..46 {
        let selected = if index % 2 == 0 { &ordinary } else { &working };
        seed(
            selected,
            ALICE,
            &format!("Public quota neighbour {index:02}"),
            now,
        );
    }
    assert_eq!(ordinary.list(ALICE, now).unwrap().len(), 49);
    let full = get(&restarted, &alice, "/drafts");
    assert_eq!(full.response.status_code, 200);
    assert!(text(&full).contains("Saved drafts: 49"));
    assert!(text(&full).contains("Retained attempts: 1"));
    assert!(text(&full).contains("50 of 50 items"));
    for (revision, selected) in [(3, Location::Default), (4, Location::Working)] {
        choose(&restarted, &alice, selected, revision);
        let fields = fresh(&restarted, &alice, "Combined quota refusal");
        let refused = compose_post(&restarted, Some(&alice), "/drafts/save", &fields, false);
        assert_ne!(refused.response.status_code, 303);
        assert!(text(&refused).contains("Combined quota refusal"));
        assert!(text(&refused).contains(PUBLIC_BODY));
        assert_eq!(
            ordinary
                .list(ALICE, SystemTimeProvider.unix_timestamp())
                .unwrap()
                .len(),
            49
        );
    }
    let resume = get(&restarted, &alice, &format!("/draft?id={working_id}"));
    assert_eq!(resume.response.status_code, 200);
    let latest = compose_fields(text(&resume));
    let discard = BTreeMap::from([
        ("csrf_token".into(), latest["csrf_token"].clone()),
        ("draft_id".into(), working_id.clone()),
        ("draft_revision".into(), "1".into()),
        ("confirm".into(), "1".into()),
    ]);
    assert_ne!(
        http(&restarted, Some(&alice), "POST", "/drafts/delete", &discard)
            .response
            .status_code,
        303
    );
    assert_eq!(tree_bytes(&actual_working), latest_before);
    let mut discard = discard;
    discard.insert("draft_revision".into(), "2".into());
    assert_eq!(
        http(&restarted, Some(&alice), "POST", "/drafts/delete", &discard)
            .response
            .status_code,
        303
    );
    assert!(!actual_working.exists());
    assert_eq!(
        ordinary
            .list(ALICE, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .len(),
        48
    );
    assert_eq!(
        recovery
            .storage_usage(ALICE, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .0,
        1
    );
    let freed_fields = fresh(&restarted, &alice, "Freed combined slot working draft");
    let freed_id = saved_id(&compose_post(
        &restarted,
        Some(&alice),
        "/drafts/save",
        &freed_fields,
        false,
    ));
    let freed_path = ordinary
        .resolved_draft_dir(ALICE, &freed_id)
        .unwrap()
        .unwrap();
    assert!(freed_path.starts_with(&working_root));
    assert_eq!(
        ordinary
            .list(ALICE, SystemTimeProvider.unix_timestamp())
            .unwrap()
            .len(),
        49
    );
    choose(&restarted, &alice, Location::Default, 5);
    assert_eq!(tree_bytes(&legacy_path), legacy_before);
    assert_eq!(tree_bytes(&bob_path), bob_before);
    assert!(default_path.exists());
    assert_eq!(fs::read(&unrelated_path).unwrap(), unrelated_before);
    assert_eq!(
        preferences.load(BOB).unwrap(),
        crate::draft_location::Preference::default()
    );
    assert_private_tree(&config.state_layout.draft_dir, uid);
    assert_eq!(forbidden.load(Ordering::SeqCst), 0);
    assert!(!smtp_marker.exists());
    assert!(reads.load(Ordering::SeqCst) > 0);
    assert_eq!(standard_metadata(), before);
    fixture.finish();
    drop(fixture);
    assert!(!root.exists());
    assert_eq!(standard_metadata(), before);
    println!("native_generated_private_draft_choices=PASS unavailable_mail_does_not_disable_private_choice=PASS default_legacy_bytes_exact_owned_layout=PASS working_metadata_attachment_actual_private_files=PASS reconstructed_exact_incomplete_saved_version=PASS current_default_new_existing_working_original_ids=PASS aggregate_list_truthful_both_locations=PASS auth_csrf_foreign_invalid_stale_preference_preservation=PASS stale_draft_cas_preserves_latest_attachment=PASS missing_selected_root_no_recreate_existing_id_no_retarget=PASS unsafe_root_no_fallback_retained_authoring=PASS duplicate_ids_no_mutation_or_wrong_resume=PASS aggregate_expiry_across_locations=PASS actual_combined_recovery_quota_choice_switch_no_reset=PASS original_location_exact_revision_discard=PASS neighbour_bob_preferences_bytes_preserved=PASS finite_zero_smtp_mail_append_move_flag_crypto=PASS owned_scratch_standard_host_metadata_unchanged=PASS");
}

// Additive automatic-save interaction proof; original location case is unchanged.
#[path = "mailbox_helper_native_draft_autosave_tests.rs"]
mod draft_autosave_interaction_tests;
