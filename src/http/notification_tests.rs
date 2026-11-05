use super::*;
use crate::notifications::{NotificationKind, NotificationStore};
#[test]
fn notification_mark_all_and_delete_are_native_owner_csrf_cas_and_hidden_category_scoped() {
    let root = temp_dir(&format!(
        "notification-manage-{}",
        crate::draft::generate_draft_id().unwrap()
    ));
    let store = NotificationStore::new(root.join("settings"));
    let now = || crate::totp::TimeProvider::unix_timestamp(&crate::totp::SystemTimeProvider);
    for kind in [NotificationKind::SessionIssued, NotificationKind::NewMail] {
        store.record("alice@example.com", kind, now()).unwrap();
    }
    store
        .record("bob@example.com", NotificationKind::SessionIssued, now())
        .unwrap();
    let prefs = crate::notification_preferences::Store::new(root.join("settings"));
    prefs
        .save_choices(
            "alice@example.com",
            0,
            crate::notification_preferences::DigestMode::Individual,
            crate::notification_preferences::Choice {
                new_mail: false,
                ..Default::default()
            },
        )
        .unwrap();
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            notification_store: Some(store.clone()),
            notification_preference_store: Some(prefs),
            browser_fixture_accounts: true,
            ..Default::default()
        },
    );
    let alice = store.load("alice@example.com", now()).unwrap();
    let bob = store.load("bob@example.com", now()).unwrap();
    let csrf = StubGateway::validated_session().record.csrf_token;
    let request_post = |path: &str, body: &str, auth: bool, foreign_origin: bool| {
        let headers = authenticated_same_origin_headers();
        let mut req = request("POST", path, if auth { &headers } else { &[] }, body);
        if foreign_origin {
            req.headers
                .insert("origin".into(), "https://foreign.invalid".into());
        }
        app.handle_request(&req, "127.0.0.1")
    };
    let body = format!("csrf_token={csrf}&revision={}", alice.revision);
    assert_eq!(
        request_post("/notifications/read-all", &body, false, false)
            .response
            .status_code,
        303
    );
    assert_eq!(
        request_post("/notifications/read-all", &body, true, true)
            .response
            .status_code,
        403
    );
    assert_eq!(
        request_post(
            "/notifications/read-all",
            &body.replace(&csrf, "invalid"),
            true,
            false
        )
        .response
        .status_code,
        403
    );
    for extra in ["&unexpected=1", "&event_id=abcd", "&revision=1"] {
        assert_eq!(
            request_post(
                "/notifications/read-all",
                &format!("{body}{extra}"),
                true,
                false
            )
            .response
            .status_code,
            400
        );
    }
    assert_eq!(
        request_post("/notifications/read-all?unexpected=1", &body, true, false)
            .response
            .status_code,
        400
    );
    assert_eq!(store.load("alice@example.com", now()).unwrap(), alice);
    let page = app.handle_request(
        &request("GET", "/notifications", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    let html = body_text(&page);
    assert!(html.contains("Mark all as read</button>"));
    assert!(html.contains("including optional notices hidden by your choices"));
    assert_eq!(html.matches("action=\"/notifications/delete\"").count(), 1);
    assert!(!html.contains("New Inbox message observed"));
    assert_eq!(
        request_post("/notifications/read-all", &body, true, false)
            .response
            .status_code,
        303
    );
    let read = store.load("alice@example.com", now()).unwrap();
    assert!(read.events.iter().all(|event| event.read));
    assert_eq!(store.load("bob@example.com", now()).unwrap(), bob);
    assert_eq!(
        request_post("/notifications/read-all", &body, true, false)
            .response
            .status_code,
        409
    );
    let page = app.handle_request(
        &request("GET", "/notifications", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert!(body_text(&page).contains("disabled>Mark all as read</button>"));
    let id = read
        .events
        .iter()
        .find(|event| event.kind == NotificationKind::SessionIssued)
        .unwrap()
        .event_id
        .clone();
    let delete = format!("csrf_token={csrf}&revision={}&event_id={id}", read.revision);
    assert_eq!(
        request_post(
            "/notifications/delete",
            &delete.replace(&csrf, "invalid"),
            true,
            false
        )
        .response
        .status_code,
        403
    );
    assert_eq!(
        request_post("/notifications/delete", &delete, true, true)
            .response
            .status_code,
        403
    );
    assert_eq!(
        request_post(
            "/notifications/delete",
            &format!("{delete}&unexpected=1"),
            true,
            false
        )
        .response
        .status_code,
        400
    );
    assert_eq!(
        request_post(
            "/notifications/delete",
            &format!(
                "csrf_token={csrf}&revision={}&event_id={}",
                read.revision, bob.events[0].event_id
            ),
            true,
            false
        )
        .response
        .status_code,
        400
    );
    assert_eq!(store.load("alice@example.com", now()).unwrap(), read);
    assert_eq!(
        request_post("/notifications/delete", &delete, true, false)
            .response
            .status_code,
        303
    );
    let deleted = store.load("alice@example.com", now()).unwrap();
    assert!(deleted.events.iter().all(|event| event.event_id != id));
    assert_eq!(deleted.events.len(), 1);
    assert_eq!(
        request_post("/notifications/delete", &delete, true, false)
            .response
            .status_code,
        409
    );
    assert_eq!(store.load("bob@example.com", now()).unwrap(), bob);
    // Both gateway implementations use the same owned native store contract.
    let runtime = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    let unchanged = runtime
        .mark_all_notifications_read(&session, deleted.revision)
        .unwrap();
    assert_eq!(unchanged, deleted);
    let empty = runtime
        .delete_notification(&session, &deleted.events[0].event_id, deleted.revision)
        .unwrap();
    assert!(empty.events.is_empty());
    let page = app.handle_request(
        &request("GET", "/notifications", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert!(body_text(&page).contains("disabled>Mark all as read</button>"));
    assert!(!body_text(&page).contains("action=\"/notifications/delete\""));
    let path = fs::read_dir(root.join("settings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| fs::read_to_string(path).is_ok_and(|text| text.contains(&id)))
        .unwrap();
    fs::write(&path, b"{broken").unwrap();
    let refused = request_post(
        "/notifications/read-all",
        &format!("csrf_token={csrf}&revision={}", empty.revision),
        true,
        false,
    );
    assert_eq!(refused.response.status_code, 503);
    assert!(body_text(&refused).contains("notification change could not be confirmed"));
    assert_eq!(fs::read(path).unwrap(), b"{broken");
    assert_eq!(store.load("bob@example.com", now()).unwrap(), bob);
    fs::remove_dir_all(root).unwrap();
}
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
