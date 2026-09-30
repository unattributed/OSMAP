use super::*;
use crate::signature::{SignatureChange as Change, SignatureSelection as Choice, SignatureStore};
#[test]
fn signature_native_cas_new_forms_and_existing_drafts_recovery_are_immutable() {
    let root = temp_dir("signature-native");
    let store = SignatureStore::new(root.join("signature"));
    let drafts = FileDraftStore::new(root.join("drafts"), DraftPolicy::default());
    let app = BrowserApp::new(
        HttpPolicy::default(),
        StubGateway {
            signature_store: Some(store.clone()),
            draft_store: Some(drafts.clone()),
            ..StubGateway::default()
        },
    );
    let account = "alice@example.com";
    let csrf = StubGateway::validated_session().record.csrf_token;
    let call = |method: &str, path: &str, body: &str| {
        let mut req = request(method, path, &authenticated_same_origin_headers(), body);
        if path == "/drafts/save" {
            add_native_compose_intent(&app, &mut req);
        }
        app.handle_request(&req, "127.0.0.1")
    };
    let form=format!("csrf_token={csrf}&signature_revision=0&selection=default&operation=definition&return_section=identity&text=Footer%20%3Cscript%3Eliteral%3C%2Fscript%3E");
    assert_eq!(
        call("POST", "/settings/signature", &form.replace(&csrf, "wrong"))
            .response
            .status_code,
        403
    );
    assert_eq!(
        call("POST", "/settings/signature", &form)
            .response
            .status_code,
        303
    );
    let stale = call("POST", "/settings/signature", &form);
    assert_eq!(stale.response.status_code, 409);
    assert!(body_text(&stale).contains("name=\"signature_revision\" value=\"0\""));
    assert!(body_text(&stale).contains("<fieldset disabled>"));
    assert!(body_text(&stale).contains("Footer &lt;script&gt;literal&lt;/script&gt;"));
    for mode in [
        "",
        "?mode=reply&mailbox=INBOX&uid=9",
        "?mode=reply-all&mailbox=INBOX&uid=9",
        "?mode=forward&mailbox=INBOX&uid=9",
    ] {
        let r = call("GET", &format!("/compose{mode}"), "");
        assert_eq!(r.response.status_code, 200);
        assert_eq!(
            body_text(&r)
                .matches("Footer &lt;script&gt;literal&lt;/script&gt;")
                .count(),
            1
        );
    }
    let saved=call("POST","/drafts/save",&format!("csrf_token={csrf}&from=alice%40example.com&to=bob%40example.com&subject=Synthetic&body=User%20entered%20only&body_format=plain"));
    assert_eq!(saved.response.status_code, 303);
    let location = location_header(&saved);
    let id = location.strip_prefix("/draft?id=").unwrap();
    let before = drafts.load(account, id, 100).unwrap().unwrap();
    assert_eq!(before.request.body, "User entered only");
    store
        .change(
            account,
            1,
            Change::Definition {
                selection: Choice::Default,
                text: "Changed footer",
            },
        )
        .unwrap();
    let resume = call("GET", &location, "");
    assert!(!body_text(&resume).contains("Changed footer"));
    assert_eq!(drafts.load(account, id, 100).unwrap().unwrap(), before);
    let compose = call("GET", "/compose", "");
    let intent = super::send_journal_routes_tests::intent(&body_text(&compose));
    let mut send=request("POST","/send",&authenticated_same_origin_headers(),&format!("csrf_token={csrf}&send_intent={intent}&to=bob%40example.com&subject=Synthetic&body=User%20entered%20only"));
    send.headers
        .insert("user-agent".into(), "OSMAP/SentCopyUnconfirmed".into());
    assert_eq!(
        app.handle_request(&send, "127.0.0.1").response.status_code,
        200
    );
    let BrowserSendRecoveryDecision::Available(snapshot) = app
        .gateway
        .read_send_recovery(&StubGateway::validated_session(), &intent)
    else {
        panic!("snapshot missing")
    };
    assert_eq!(snapshot.request.body, "User entered only");
    store
        .change(account, 2, Change::Selection(Choice::None))
        .unwrap();
    let BrowserSendRecoveryDecision::Available(after) = app
        .gateway
        .read_send_recovery(&StubGateway::validated_session(), &intent)
    else {
        panic!("snapshot missing")
    };
    assert_eq!(snapshot.request, after.request);
    let disable = format!(
        "csrf_token={csrf}&signature_revision=3&operation=selection&return_section=composition"
    );
    assert_eq!(
        call("POST", "/settings/signature", &disable)
            .response
            .status_code,
        303
    );
    assert_eq!(store.load(account).unwrap().text, "Changed footer");
    let path = fs::read_dir(root.join("signature"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    fs::write(&path, b"broken").unwrap();
    let unavailable = call("GET", "/compose?mode=reply&mailbox=INBOX&uid=9", "");
    assert_eq!(unavailable.response.status_code, 200);
    assert!(body_text(&unavailable).contains("signature is unavailable"));
    assert!(!body_text(&unavailable).contains("Changed footer"));
    assert_eq!(drafts.load(account, id, 100).unwrap().unwrap(), before);
    assert_eq!(fs::read(path).unwrap(), b"broken");
    fs::remove_dir_all(root).unwrap();
}
