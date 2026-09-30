use super::*;
use crate::identity_preferences::{IdentityPreferences, IdentityPreferencesStore};
#[test]
fn identity_native_owner_csrf_cas_validation_and_corruption_preserve_records() {
    let root = temp_dir("identity-route");
    let store = IdentityPreferencesStore::new(root.join("identity"));
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            identity_preferences_store: Some(store.clone()),
            ..StubGateway::default()
        },
    );
    let token = StubGateway::validated_session().record.csrf_token;
    let perform = |body: &str| {
        app.handle_request(
            &request(
                "POST",
                "/settings/identity",
                &authenticated_same_origin_headers(),
                body,
            ),
            "127.0.0.1",
        )
    };
    let body=format!("csrf_token={token}&identity_revision=0&display_name=Alice+Synthetic&reply_to=reply%40example.test");
    let response = perform(&body);
    assert_eq!(response.response.status_code, 303);
    assert!(response
        .audit_events
        .iter()
        .any(|e| e.action == "identity_preferences_updated"));
    let saved = store.load("alice@example.com").unwrap();
    assert_eq!(saved.preferences.display_name(), "Alice Synthetic");
    assert_eq!(saved.preferences.reply_to(), Some("reply@example.test"));
    assert_eq!(store.load("bob@example.com").unwrap().revision, 0);
    let stale = perform(&body.replace("Alice+Synthetic", "Stale+text"));
    assert_eq!(stale.response.status_code, 409);
    assert!(body_text(&stale).contains("value=\"Stale text\""));
    assert_eq!(store.load("alice@example.com").unwrap(), saved);
    let valid = body.replace("identity_revision=0", "identity_revision=1");
    for (invalid, status) in [
        (valid.replace(&token, "wrong"), 403),
        (
            valid.replace("reply%40example.test", "bad%0ABcc%3Ax%40example.test"),
            400,
        ),
        (
            valid.replace("display_name=Alice+Synthetic", "display_name=%3Cimg%3E%0A"),
            400,
        ),
        (
            valid.replace("identity_revision=1", "identity_revision=01"),
            400,
        ),
        (format!("{valid}&canonical_username=bob%40example.com"), 400),
    ] {
        assert_eq!(perform(&invalid).response.status_code, status);
        assert_eq!(store.load("alice@example.com").unwrap(), saved);
    }
    let index = crate::private_account_file::PrivateAccountFile::new(
        root.join("identity"),
        "osmap-identity-preferences-v1",
        2048,
    );
    index
        .lock("alice@example.com")
        .unwrap()
        .write(b"corrupt")
        .unwrap();
    let result = perform(&valid);
    assert_eq!(result.response.status_code, 503);
    assert!(body_text(&result).contains("value=\"Alice Synthetic\""));
    assert!(
        body_text(&result).contains("Save identity</button>")
            && body_text(&result).contains("disabled")
    );
    assert!(result
        .audit_events
        .iter()
        .any(|e| e.action == "identity_preferences_update_failed"));
    assert_eq!(
        index.read("alice@example.com").unwrap().unwrap(),
        b"corrupt"
    );
    let overview = app.handle_request(
        &request("GET", "/settings", &authenticated_headers(), ""),
        "127.0.0.1",
    );
    assert_eq!(overview.response.status_code, 200);
    assert!(body_text(&overview).contains("Saved profile unavailable."));
    assert!(!body_text(&overview).contains("Alice Synthetic"));
    assert!(body_text(&overview).contains("href=\"/settings?section=identity\">Edit in Identity"));
    assert!(IdentityPreferences::new("", None).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identity_runtime_gateway_uses_authenticated_account_and_preserves_canonical_sender() {
    let root = temp_dir("identity-runtime");
    let gateway = RuntimeBrowserGateway::for_test(&root);
    let session = StubGateway::validated_session();
    let context = AuthenticationContext::new(
        AuthenticationPolicy::default(),
        "identity-test",
        "127.0.0.1",
        "Synthetic/Test",
    )
    .unwrap();
    let before = session.record.canonical_username.clone();
    let value = IdentityPreferences::new("Alice 🦊", Some("replies@example.test")).unwrap();
    assert_eq!(
        gateway
            .load_identity_preferences(&context, &session)
            .unwrap()
            .revision,
        0
    );
    assert_eq!(
        gateway
            .update_identity_preferences(&context, &session, 0, &value)
            .unwrap()
            .revision,
        1
    );
    assert_eq!(
        gateway
            .load_identity_preferences(&context, &session)
            .unwrap()
            .preferences,
        value
    );
    let mut bob = session.clone();
    bob.record.canonical_username = "bob@example.com".into();
    assert_eq!(
        gateway
            .load_identity_preferences(&context, &bob)
            .unwrap()
            .revision,
        0
    );
    assert_eq!(session.record.canonical_username, before);
    fs::remove_dir_all(root).unwrap();
}
