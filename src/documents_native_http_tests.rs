// Real parser + Runtime gateway + authenticated helper/native Documents journey.
// Synthetic post-auth sessions qualify neither login/TOTP nor the standalone
// daemon accept loop, proxy, TLS or browser rendering.
use super::*;
use crate::auth::{AuthenticationContext, AuthenticationPolicy, RequiredSecondFactor};
use crate::config::AppConfig;
use crate::http::{BrowserApp, HandledHttpResponse, HttpPolicy, RuntimeBrowserGateway};
use crate::session::{FileSessionStore, IssuedSession, SessionService, SystemRandomSource};
use crate::totp::SystemTimeProvider;

const USER_AGENT: &str = "OSMAP/native-documents-http";
const BOB: &str = "bob@osmap-documents.invalid";

fn http(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: Option<&IssuedSession>,
    method: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    origin: &str,
) -> HandledHttpResponse {
    assert!(matches!(method, "GET" | "POST"));
    assert!(path.starts_with("/documents") && path.len() <= 256);
    assert!(body.len() <= MAX_FILE_BYTES + 4096);
    let cookie = session.map_or(String::new(), |session| {
        format!("Cookie: osmap_session={}\r\n", session.token.as_str())
    });
    let content = if method == "POST" {
        format!("Content-Type: {content_type}\r\nOrigin: {origin}\r\n")
    } else {
        assert!(body.is_empty());
        String::new()
    };
    let mut wire = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {USER_AGENT}\r\n{cookie}{content}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    let parsed = crate::http::parse_http_request_bytes(&wire, app.policy()).unwrap();
    app.handle_request(&parsed, "127.0.0.1")
}

fn html(response: &HandledHttpResponse) -> &str {
    assert_eq!(response.response.status_code, 200);
    assert!(response.response.body.len() <= 512 * 1024);
    std::str::from_utf8(&response.response.body).unwrap()
}

fn page(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    path: &str,
) -> HandledHttpResponse {
    http(app, Some(session), "GET", path, "", b"", "")
}

fn revision(response: &HandledHttpResponse) -> u64 {
    let raw = html(response)
        .split_once("name=\"revision\" value=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0;
    let revision: u64 = raw.parse().unwrap();
    assert_eq!(revision.to_string(), raw);
    revision
}

fn upload_body(csrf: &str, revision: u64, bytes: &[u8]) -> Vec<u8> {
    let mut body = format!("--document-http-fixture\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n{csrf}\r\n--document-http-fixture\r\nContent-Disposition: form-data; name=\"revision\"\r\n\r\n{revision}\r\n--document-http-fixture\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"maximum.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n--document-http-fixture--\r\n");
    body
}

fn change(
    app: &BrowserApp<RuntimeBrowserGateway>,
    session: &IssuedSession,
    route: &str,
    revision: u64,
    id: &str,
    confirm: bool,
) {
    let confirmation = if confirm { "&confirm=delete" } else { "" };
    let body = format!(
        "csrf_token={}&revision={revision}&id={id}{confirmation}",
        session.record.csrf_token
    );
    assert_eq!(
        http(
            app,
            Some(session),
            "POST",
            route,
            "application/x-www-form-urlencoded",
            body.as_bytes(),
            "http://localhost"
        )
        .response
        .status_code,
        303
    );
}

fn exact_download(response: &HandledHttpResponse, payload: &[u8]) {
    assert_eq!(response.response.status_code, 200);
    assert!(
        response.response.body == payload,
        "native HTTP download bytes differ"
    );
    for (name, value) in [
        ("Content-Type", "application/octet-stream"),
        (
            "Content-Disposition",
            "attachment; filename=\"maximum.bin\"",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("Cache-Control", "no-store"),
    ] {
        assert!(response
            .response
            .headers
            .iter()
            .any(|(key, actual)| key.eq_ignore_ascii_case(name) && actual == value));
    }
}

#[test]
#[ignore = "actual OpenBSD FFS HTTP parser/Runtime/helper/native maximum-file journey"]
fn isolated_openbsd_ffs_documents_http() {
    let whole = Instant::now();
    assert_eq!(hard_bytes(), 32 * 1024 * 1024);
    let before = standard_metadata();
    let ProductFixture {
        mut fixture,
        root,
        data,
        home,
        executor,
        userdb,
    } = product_fixture();
    let saves = executor.saves.clone();
    let native = Arc::new(
        DoveadmDocumentsBackend::new(
            executor,
            "/usr/local/bin/doveadm",
            "/usr/local/bin/doveconf",
        )
        .with_userdb_socket_path(Some(userdb)),
    );
    let initial_quota = native.quota_status(ACCOUNT).unwrap().unwrap();
    let (mut server, socket, key, exchanges) = product_documents_server(&root, native.clone());
    let config = AppConfig::from_env_map(&std::collections::BTreeMap::from([
        ("OSMAP_RUN_MODE".into(), "serve".into()),
        (
            "OSMAP_STATE_DIR".into(),
            root.join("app-state").to_string_lossy().into_owned(),
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
            QUOTA_UID.to_string(),
        ),
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
        "native-documents-http-session",
        "127.0.0.1",
        USER_AGENT,
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
        .issue(&context, ACCOUNT, RequiredSecondFactor::Totp)
        .unwrap();
    let bob = sessions
        .issue(&context, BOB, RequiredSecondFactor::Totp)
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::from_config(&config),
        RuntimeBrowserGateway::from_config(&config),
    );
    let observer = Store::new(
        config.state_layout.settings_dir.join("documents-v1"),
        native.as_ref().clone(),
    );
    assert_eq!(
        http(&app, None, "GET", "/documents", "", b"", "")
            .response
            .status_code,
        303
    );
    let initial = page(&app, &alice, "/documents");
    assert!(html(&initial).contains("Upload a file") && html(&initial).contains(ACCOUNT));
    let first_revision = revision(&initial);
    let small = upload_body(&alice.record.csrf_token, first_revision, b"not dispatched");
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/documents/upload",
            "multipart/form-data; boundary=document-http-fixture",
            &small,
            "http://foreign.example.invalid"
        )
        .response
        .status_code,
        403
    );
    let bad_csrf = upload_body("wrong", first_revision, b"not dispatched");
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/documents/upload",
            "multipart/form-data; boundary=document-http-fixture",
            &bad_csrf,
            "http://localhost"
        )
        .response
        .status_code,
        403
    );
    assert!(observer.load(ACCOUNT).unwrap().documents.is_empty());
    assert!(retained_native_snapshot(&home).is_empty());
    assert_eq!(saves.load(Ordering::SeqCst), 0);
    let payload: Vec<u8> = (0..MAX_FILE_BYTES).map(|i| (i % 256) as u8).collect();
    let upload = upload_body(&alice.record.csrf_token, first_revision, &payload);
    assert_eq!(
        http(
            &app,
            Some(&alice),
            "POST",
            "/documents/upload",
            "multipart/form-data; boundary=document-http-fixture",
            &upload,
            "http://localhost"
        )
        .response
        .status_code,
        303
    );
    let uploaded = observer.load(ACCOUNT).unwrap();
    assert_eq!(uploaded.documents.len(), 1);
    let document = &uploaded.documents[0];
    assert_eq!(document.size, MAX_FILE_BYTES as u64);
    assert_eq!(document.sha256, format!("{:x}", Sha256::digest(&payload)));
    let id = document.id.clone();
    let selected = page(&app, &alice, &format!("/documents?selected={id}"));
    assert!(
        html(&selected).contains("maximum.bin")
            && html(&selected).contains("10485760 bytes")
            && html(&selected).contains(ACCOUNT)
    );
    exact_download(
        &page(&app, &alice, &format!("/documents/download?id={id}")),
        &payload,
    );
    assert_eq!(
        page(&app, &bob, &format!("/documents/download?id={id}"))
            .response
            .status_code,
        404
    );
    assert_eq!(retained_native_snapshot(&home).len(), 1);
    assert_eq!(saves.load(Ordering::SeqCst), 1);
    assert!(native.quota_status(ACCOUNT).unwrap().unwrap().used_bytes > initial_quota.used_bytes);
    println!("native_ffs_http stage=maximum_upload_download result=PASS bytes={} sha256={:x} csrf_origin=REFUSED foreign_download=404 saves=1", MAX_FILE_BYTES, Sha256::digest(&payload));
    change(
        &app,
        &alice,
        "/documents/bin",
        revision(&selected),
        &id,
        false,
    );
    let bin = page(&app, &alice, &format!("/documents?bin=1&selected={id}"));
    assert!(html(&bin).contains("maximum.bin") && html(&bin).contains("10485760 bytes"));
    assert_eq!(
        observer
            .load(ACCOUNT)
            .unwrap()
            .storage_summary(ACCOUNT)
            .unwrap()
            .bin_bytes,
        MAX_FILE_BYTES as u64
    );
    change(
        &app,
        &alice,
        "/documents/restore",
        revision(&bin),
        &id,
        false,
    );
    exact_download(
        &page(&app, &alice, &format!("/documents/download?id={id}")),
        &payload,
    );
    let restored = page(&app, &alice, &format!("/documents?selected={id}"));
    change(
        &app,
        &alice,
        "/documents/bin",
        revision(&restored),
        &id,
        false,
    );
    let review = page(&app, &alice, &format!("/documents/delete?id={id}"));
    assert!(html(&review).contains("This cannot be undone"));
    let before_confirm = observer.load(ACCOUNT).unwrap();
    assert_eq!(before_confirm.documents[0].state, State::InBin);
    change(
        &app,
        &alice,
        "/documents/delete",
        revision(&review),
        &id,
        true,
    );
    let complete = page(&app, &alice, "/documents");
    assert!(html(&complete).contains("No documents in this view"));
    assert!(observer.load(ACCOUNT).unwrap().documents.is_empty());
    assert!(native.inspect(ACCOUNT, &id).unwrap().is_empty());
    assert!(retained_native_snapshot(&home).is_empty());
    assert_eq!(saves.load(Ordering::SeqCst), 1);
    get_quota(&data);
    for lease in [&alice, &bob] {
        sessions.revoke_by_token(&context, &lease.token).unwrap();
        assert!(sessions.validate(&context, &lease.token).is_err());
    }
    server.finish();
    assert!(exchanges.load(Ordering::SeqCst) >= 8);
    assert_eq!(before, standard_metadata());
    assert!(whole.elapsed() < NATIVE_LIMIT);
    fixture.retain_on_failure = false;
    drop(fixture);
    assert!(!root.exists());
    println!("native_ffs_http result=PASS parser_runtime_peer_dispatch_native=PASS login_totp=NOT_QUALIFIED standalone_daemon_tls_browser=NOT_QUALIFIED native_cleanup=PASS private_sessions_cleanup=PASS control_cleanup=PASS");
}
