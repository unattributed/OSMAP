use super::*;
use crate::notifications::{NotificationKind, NotificationStore};
#[test]
fn notification_native_owner_csrf_cas_and_corrupt_refusal() {
    let root = temp_dir("notification-route");
    let store = NotificationStore::new(root.join("inbox"));
    // Routes use the current request clock. Read subsequent state at the current
    // time too, even when the route crosses a wall-clock second boundary.
    let now = || crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider);
    store
        .record("alice@example.com", NotificationKind::SessionIssued, now())
        .unwrap();
    store
        .record("bob@example.com", NotificationKind::SessionIssued, now())
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            notification_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let inbox = store.load("alice@example.com", now()).unwrap();
    let id = &inbox.events[0].event_id;
    let csrf = StubGateway::validated_session().record.csrf_token;
    let body = format!(
        "csrf_token={csrf}&event_id={id}&revision={}&read=1",
        inbox.revision
    );
    let post = |body: &str| {
        app.handle_request(
            &request(
                "POST",
                "/notifications/read",
                &authenticated_same_origin_headers(),
                body,
            ),
            "127.0.0.1",
        )
    };
    assert_eq!(
        post(&body.replace(&csrf, "invalid")).response.status_code,
        403
    );
    assert_eq!(
        post(&format!("{body}&unexpected=1")).response.status_code,
        400
    );
    assert_eq!(post(&body).response.status_code, 303);
    assert!(store.load("alice@example.com", now()).unwrap().events[0].read);
    assert_eq!(post(&body).response.status_code, 409);
    let foreign = store.load("bob@example.com", now()).unwrap();
    let current = store.load("alice@example.com", now()).unwrap();
    assert_eq!(
        post(&format!(
            "csrf_token={csrf}&event_id={}&revision={}&read=1",
            foreign.events[0].event_id, current.revision
        ))
        .response
        .status_code,
        400
    );
    assert!(!store.load("bob@example.com", now()).unwrap().events[0].read);
    let path = fs::read_dir(root.join("inbox"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension().is_some_and(|v| v == "json")
                && fs::read_to_string(path).is_ok_and(|text| text.contains(id))
        })
        .unwrap();
    fs::write(&path, b"{broken").unwrap();
    assert_eq!(post(&body).response.status_code, 503);
    assert_eq!(fs::read(&path).unwrap(), b"{broken");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn notification_record_failure_keeps_successful_login_and_session_cookie() {
    let root = temp_dir("notification-auth-failure");
    let path = root.join("not-directory");
    fs::write(&path, b"synthetic refusal").unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            notification_store: Some(NotificationStore::new(&path)),
            ..StubGateway::default()
        },
    );
    let response = app.handle_request(
        &request(
            "POST",
            "/login",
            &authenticated_same_origin_headers(),
            "username=alice%40example.com&password=correct+horse+battery+staple&totp_code=123456",
        ),
        "127.0.0.1",
    );
    assert_eq!(response.response.status_code, 200);
    assert!(body_text(&response).contains("Your session is active"));
    assert!(response
        .response
        .headers
        .iter()
        .any(|(k, v)| k == "Set-Cookie" && v.contains("osmap_session=")));
    assert!(response
        .audit_events
        .iter()
        .any(|e| e.action == "notification_recording_unconfirmed"));
    assert_eq!(fs::read(path).unwrap(), b"synthetic refusal");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn notification_badge_is_request_owned_once_and_unknown_on_failure() {
    let root = temp_dir("notification-badge");
    let store = NotificationStore::new(root.join("inbox"));
    let now = crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider);
    store
        .record("alice@example.com", NotificationKind::SessionIssued, now)
        .unwrap();
    let loads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            notification_store: Some(store.clone()),
            notification_loads: loads.clone(),
            ..StubGateway::default()
        },
    );
    let get = request(
        "GET",
        "/settings?section=notifications",
        &authenticated_headers(),
        "",
    );
    get.notification_context.borrow_mut().count = Some(Some(199));
    for path in ["/settings?section=notifications", "/notifications"] {
        let mut req = get.clone();
        req.path = path.split('?').next().unwrap().into();
        loads.store(0, std::sync::atomic::Ordering::SeqCst);
        let r = app.handle_request(&req, "127.0.0.1");
        assert_eq!(r.response.status_code, 200);
        assert_eq!(
            *req.notification_context.borrow(),
            notification_badge::RenderContext::default()
        );
        assert!(body_text(&r).contains("data-unread=\"1\""));
        assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    let inbox = store.load("alice@example.com", now).unwrap();
    store
        .set_read(
            "alice@example.com",
            &inbox.events[0].event_id,
            inbox.revision,
            true,
            now,
        )
        .unwrap();
    let r = app.handle_request(&get, "127.0.0.1");
    assert!(body_text(&r).contains("data-unread=\"0\""));
    for entry in fs::read_dir(root.join("inbox")).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_some_and(|e| e == "json") {
            fs::write(p, b"{broken").unwrap();
        }
    }
    let r = app.handle_request(&get, "127.0.0.1");
    assert_eq!(r.response.status_code, 200);
    assert!(body_text(&r).contains("data-unread=\"unknown\""));
    loads.store(0, std::sync::atomic::Ordering::SeqCst);
    app.handle_request(&request("GET", "/login", &[], ""), "127.0.0.1");
    assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn notification_badge_scope_clears_entry_normal_exit_and_unwind() {
    let req = request(
        "POST",
        "/notifications/read",
        &authenticated_same_origin_headers(),
        "body retained",
    );
    let body_ptr = req.body.as_ptr();
    req.notification_context.borrow_mut().count = Some(Some(99));
    {
        let _guard = notification_badge::RenderScope::new(&req);
        assert_eq!(
            *req.notification_context.borrow(),
            notification_badge::RenderContext::default()
        );
        req.notification_context.borrow_mut().session = Some(StubGateway::validated_session());
    }
    assert_eq!(
        *req.notification_context.borrow(),
        notification_badge::RenderContext::default()
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = notification_badge::RenderScope::new(&req);
        req.notification_context.borrow_mut().session = Some(StubGateway::validated_session());
        req.notification_context.borrow_mut().count = Some(Some(7));
        panic!("synthetic response interruption");
    }));
    assert!(result.is_err());
    assert_eq!(
        *req.notification_context.borrow(),
        notification_badge::RenderContext::default()
    );
    assert_eq!(req.body.as_ptr(), body_ptr);
    assert_eq!(req.body, b"body retained");
}
